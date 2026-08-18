//! The kernel materialization service.
//!
//! Owns the kernel materialization pipeline. All storage access flows
//! through an injected [`ImageStore`] port and all external source
//! acquisition flows through injected [`SourceResolver`] adapters; the
//! service never acquires a process-global implementation from inside a
//! use-case method. The public `materialize` entry point constructs the
//! default service once (default store plus default resolvers); tests inject
//! fakes.

use std::path::PathBuf;
use std::sync::Arc;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::cache_lock::acquire_build_lock;
use crate::compiler::{KernelCompiler, KernelCompilerIdentity};
use crate::{
    CustomKernelSpec, ExternalKernelPlan, KernelError, KernelPath, Link, MaterializedKernel, ops,
};
use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    digest::{LinkDigest, LinkDigestBuilder},
    materialize::{get_or_build_blueprint, materialize_layers, normalize_artifact},
    ops as core_ops,
    resolver::{ResolvedSource, ResolverSet, SourceResolverError},
    storage::{
        error::IndexError,
        file_ref::FileRef,
        link_ref::LinkRef,
        namespace::{Namespace, NamespacedLinkDigest},
    },
    store::{ImageStore, SharedStore},
    timing::{CacheOutcome, OpTimer, SourceKind},
};

/// Attach the kernel materialization category to an error report.
pub(crate) fn change_kernel<E>(error: Report<E>) -> Report<KernelError> {
    error.change_context(KernelError::Materialization)
}

/// The kernel materialization service: resolves external sources and
/// publishes validated kernel and module artifacts through an injected
/// store.
pub(crate) struct KernelService {
    store: Arc<dyn ImageStore>,
    resolvers: ResolverSet,
}

impl KernelService {
    /// Build a service over explicit dependencies.
    #[allow(dead_code)] // explicit-dependency constructor used by contract tests and future adapters
    pub(crate) fn new(store: Arc<dyn ImageStore>, resolvers: ResolverSet) -> Self {
        Self { store, resolvers }
    }

    /// Build the default service: the shared cache index (opened per
    /// operation, so the exclusive redb file lock is transient) plus the
    /// default per-kind source resolvers.
    pub(crate) fn with_defaults() -> Result<Self, Report<IndexError>> {
        Ok(Self {
            store: Arc::new(SharedStore::shared()?),
            resolvers: ResolverSet::defaults(),
        })
    }

    /// Materialize an external kernel plan. Kernel extraction and module
    /// extraction are deliberately performed here, before the result crosses
    /// into the caller, so the public materialized value is always boot-ready.
    #[cfg_attr(
        feature = "tracing",
        instrument(skip_all, fields(source = ?plan.link, has_path = plan.kernel_path.is_some()), level = "debug")
    )]
    pub(crate) async fn build_external(
        &self,
        plan: ExternalKernelPlan,
        token: &CancellationToken,
    ) -> Result<MaterializedKernel, Report<KernelError>> {
        let timer = OpTimer::start("kernel.materialize")
            .source(SourceKind::from(&plan.link))
            .namespace("kernel");
        match self.build_external_inner(plan, token).await {
            Ok(materialized) => Ok(materialized),
            Err(error) => {
                timer.fail(format!("{error:#}"));
                Err(error)
            }
        }
    }

    /// The materialization pipeline behind [`Self::build_external`], timed by
    /// the `kernel.materialize` completion timer at the wrapper and by the
    /// `kernel.resolve`/`kernel.layers`/`kernel.extract`/`kernel.modules`
    /// sub-timers.
    async fn build_external_inner(
        &self,
        plan: ExternalKernelPlan,
        token: &CancellationToken,
    ) -> Result<MaterializedKernel, Report<KernelError>> {
        let timer = OpTimer::start("kernel.resolve")
            .source(SourceKind::from(&plan.link))
            .namespace("kernel");
        let resolved = match self.resolve_source(plan.link.clone()).await {
            Ok(resolved) => resolved,
            Err(error) => {
                let error = change_kernel(error);
                timer.fail(format!("{error:#}"));
                return Err(error);
            }
        };
        // The kernel request identity combines the resolver-owned source
        // digest with the request shape (raw vs archive + normalized path).
        // Two different kernel paths in one source produce two request
        // digests; two spellings of one path produce one.
        let request_digest = kernel_request_digest(&resolved, plan.kernel_path.as_ref());

        let link = resolved.link;
        let is_image = resolved.is_image;
        let source_digest = resolved.source_digest;
        let kernel_link_ref = self
            .store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Kernel,
                link_digest: request_digest,
            })
            .map_err(change_kernel)?;
        // Modules belong to the source, not to one kernel path: two kernels
        // extracted from the same image share one module artifact.
        let modules_link_ref = self
            .store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Modules,
                link_digest: source_digest,
            })
            .map_err(change_kernel)?;

        if is_image {
            let rootfs_link_ref = self
                .store
                .reserve_link_ref(NamespacedLinkDigest {
                    namespace: Namespace::Rootfs,
                    link_digest: source_digest,
                })
                .map_err(change_kernel)?;

            let cached_kernel = self
                .store
                .read_file_ref(&kernel_link_ref)
                .map_err(change_kernel)?
                .filter(|entry| entry.artifact_type == ArtifactType::FileBzImage);
            let cached_rootfs = self
                .store
                .read_file_ref(&rootfs_link_ref)
                .map_err(change_kernel)?
                .filter(|entry| entry.artifact_type == ArtifactType::ContainerCpio);

            if let Some(kernel) = cached_kernel {
                let modules = cached_modules(self.store.as_ref(), &modules_link_ref)
                    .map_err(change_kernel)?;
                if modules.is_some() || cached_rootfs.is_none() {
                    if modules.is_some() {
                        let _ = OpTimer::start("kernel.modules").cache(CacheOutcome::Hit);
                    }
                    return Ok(MaterializedKernel {
                        kernel: kernel.path(),
                        modules,
                    });
                }
                let timer = OpTimer::start("kernel.modules").cache(CacheOutcome::Miss);
                let modules = match extract_modules_if_needed(
                    self.store.as_ref(),
                    cached_rootfs.as_ref().expect("checked above"),
                    &modules_link_ref,
                    token,
                )
                .await
                {
                    Ok(modules) => modules,
                    Err(error) => {
                        let error = change_kernel(error);
                        timer.fail(format!("{error:#}"));
                        return Err(error);
                    }
                };
                return Ok(MaterializedKernel {
                    kernel: kernel.path(),
                    modules,
                });
            }

            let rootfs = match cached_rootfs {
                Some(rootfs) => rootfs,
                None => {
                    let timer = OpTimer::start("kernel.layers")
                        .source(SourceKind::from(&link))
                        .namespace("layers");
                    // The blueprint is cached under the kernel request digest;
                    // the link snapshot is verified separately so a link
                    // cannot be swapped between reservation and use.
                    let expected_link_digest = link.digest().map_err(change_kernel)?;
                    let blueprint = match get_or_build_blueprint(
                        self.store.as_ref(),
                        &kernel_link_ref,
                        link,
                        plan.kernel_path
                            .as_ref()
                            .map(|path| PathBuf::from(path.as_str())),
                        expected_link_digest,
                    )
                    .await
                    {
                        Ok(blueprint) => blueprint,
                        Err(error) => {
                            let error = change_kernel(error);
                            timer.fail(format!("{error:#}"));
                            return Err(error);
                        }
                    };
                    let rootfs = match materialize_layers(
                        self.store.as_ref(),
                        blueprint.layers,
                        &rootfs_link_ref,
                        token,
                    )
                    .await
                    {
                        Ok(rootfs) => rootfs,
                        Err(error) => {
                            let error = change_kernel(error);
                            timer.fail(format!("{error:#}"));
                            return Err(error);
                        }
                    };
                    if let Err(error) = self.store.publish_file_ref(&rootfs_link_ref, &rootfs) {
                        let error = change_kernel(error);
                        timer.fail(format!("{error:#}"));
                        return Err(error);
                    }
                    rootfs
                }
            };

            let timer = OpTimer::start("kernel.extract").namespace("kernel");
            let extracted = extract_kernel_result(
                self.store.as_ref(),
                rootfs,
                plan.kernel_path.as_ref(),
                &kernel_link_ref,
                &modules_link_ref,
                token,
            )
            .await
            .map_err(change_kernel);
            match extracted {
                Ok(materialized) => return Ok(materialized),
                Err(error) => {
                    timer.fail(format!("{error:#}"));
                    return Err(error);
                }
            }
        }

        let mut artifact = match self
            .store
            .read_file_ref(&kernel_link_ref)
            .map_err(change_kernel)?
        {
            Some(entry) => entry,
            None => {
                let expected_link_digest = link.digest().map_err(change_kernel)?;
                let entry =
                    core_ops::load(&link, &kernel_link_ref, None, expected_link_digest, token)
                        .await
                        .map_err(change_kernel)?;
                self.store
                    .publish_file_ref(&kernel_link_ref, &entry)
                    .map_err(change_kernel)?;
                entry
            }
        };
        artifact = normalize_artifact(self.store.as_ref(), artifact, token)
            .await
            .map_err(change_kernel)?;

        if artifact.artifact_type == ArtifactType::FileBzImage {
            return Ok(MaterializedKernel {
                kernel: artifact.path(),
                modules: cached_modules(self.store.as_ref(), &modules_link_ref)
                    .map_err(change_kernel)?,
            });
        }

        // A raw source that materializes as an archive fails with a typed
        // missing-path error: raw plans carry no kernel entry path.
        if plan.kernel_path.is_none() {
            return Err(Report::new(KernelError::Materialization).attach(
                "raw kernel source materialized as an archive; no kernel entry path was requested",
            ));
        }

        let timer = OpTimer::start("kernel.extract").namespace("kernel");
        let extracted = extract_kernel_result(
            self.store.as_ref(),
            artifact,
            plan.kernel_path.as_ref(),
            &kernel_link_ref,
            &modules_link_ref,
            token,
        )
        .await
        .map_err(change_kernel);
        match extracted {
            Ok(materialized) => Ok(materialized),
            Err(error) => {
                timer.fail(format!("{error:#}"));
                Err(error)
            }
        }
    }

    /// Dispatch one facade `Link` to the resolver owning its kind and
    /// resolve it into validated content.
    async fn resolve_source(
        &self,
        source: Link,
    ) -> Result<ResolvedSource, Report<SourceResolverError>> {
        let resolver = self.resolvers.dispatch(&source);
        resolver.resolve(source).await
    }
}

/// The custom materialization path: compute the request digest, check the
/// cache, serialize identical builds, and compile only after a cache miss.
impl KernelService {
    /// Materialize a custom kernel specification through `compiler`, and
    /// report whether the returned kernel was served from the custom cache.
    /// The CLI uses the flag to report cache hits; the port keeps the plain
    /// materialized value.
    ///
    /// The custom request digest is computed before the compiler is invoked.
    /// A cached validated bzImage returns without invoking the compiler; a
    /// cache miss serializes identical requests within and across processes,
    /// re-checks the cache after acquiring the build lock, and only then
    /// calls [`KernelCompiler::compile`]. The compiler output is staged and
    /// validated through the existing artifact operations before it is
    /// published under the request digest, and an unpublished output is
    /// removed on failure.
    #[cfg_attr(
        feature = "tracing",
        instrument(skip_all, fields(version = %spec.version()), level = "debug")
    )]
    pub(crate) async fn build_custom_with_outcome(
        &self,
        spec: CustomKernelSpec,
        compiler: &dyn KernelCompiler,
        token: &CancellationToken,
    ) -> Result<(MaterializedKernel, bool), Report<KernelError>> {
        let timer = OpTimer::start("kernel.custom")
            .namespace("kernel")
            .cache(CacheOutcome::NotApplicable);
        let request_digest = custom_request_digest(&spec, compiler.identity());
        let kernel_link_ref = self
            .store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Kernel,
                link_digest: request_digest,
            })
            .map_err(change_kernel)?;

        // Fast path: a previously published validated bzImage.
        if let Some(cached) = self
            .store
            .read_file_ref(&kernel_link_ref)
            .map_err(change_kernel)?
            .filter(|entry| entry.artifact_type == ArtifactType::FileBzImage)
        {
            let _ = timer.cache(CacheOutcome::Hit);
            return Ok((
                MaterializedKernel {
                    kernel: cached.path(),
                    modules: None,
                },
                true,
            ));
        }

        // Serialize identical builds. The lock is held until publication or
        // terminal failure; a crashed process releases the OS lock when the
        // handle closes.
        let _lock = acquire_build_lock(request_digest)
            .await
            .map_err(change_kernel)?;

        // A waiting process re-checks the cache after acquiring the lock.
        if let Some(cached) = self
            .store
            .read_file_ref(&kernel_link_ref)
            .map_err(change_kernel)?
            .filter(|entry| entry.artifact_type == ArtifactType::FileBzImage)
        {
            let _ = timer.cache(CacheOutcome::Hit);
            return Ok((
                MaterializedKernel {
                    kernel: cached.path(),
                    modules: None,
                },
                true,
            ));
        }

        let compiled = compiler
            .compile(&spec)
            .await
            .map_err(|error| error.change_context(KernelError::Compilation))?;

        // Stage, validate, and publish the compiler output through the
        // existing artifact operations. `load` writes the staged file into
        // the kernel namespace and classifies its format; the bzImage
        // validation below refuses to publish anything else.
        let staged_path = compiled.path().to_path_buf();
        let link = match std::fs::metadata(&staged_path) {
            Ok(metadata) => image_core::artifact::link::ArtifactLink::Local(
                staged_path.clone(),
                metadata.len() as u128,
            ),
            Err(error) => {
                return Err(Report::new(KernelError::Compilation)
                    .attach("compiler output disappeared before staging")
                    .attach(error));
            }
        };
        let expected_link_digest = link
            .digest()
            .map_err(|error| Report::new(KernelError::Compilation).attach(error))?;
        let artifact = match core_ops::load(
            &link,
            &kernel_link_ref,
            None,
            expected_link_digest,
            token,
        )
        .await
        {
            Ok(artifact) => artifact,
            Err(error) => return Err(change_kernel(error)),
        };
        if artifact.artifact_type != ArtifactType::FileBzImage {
            return Err(Report::new(KernelError::Compilation).attach(format!(
                "compiler output materialized as {:?}, expected a raw bzImage",
                artifact.artifact_type
            )));
        }
        self.store
            .publish_file_ref(&kernel_link_ref, &artifact)
            .map_err(change_kernel)?;
        let _ = timer.cache(CacheOutcome::Miss);
        Ok((
            MaterializedKernel {
                kernel: artifact.path(),
                modules: None,
            },
            false,
        ))
    }
}

/// The custom request digest for one custom kernel specification: the
/// canonical version, the canonical source URL and expected digest, the
/// configuration mode and canonical bytes, and the canonical compiler
/// identity bytes, under the domain prefix `jyth.kernel.custom.v2`.
///
/// CPU count, memory size, temporary paths, and wall-clock time are excluded:
/// a change to any output-affecting build input must change the digest, and
/// nothing else may. A source-digest change, a source-URL change, a
/// toolchain-image digest change, a build-script change, or a Kbuild metadata
/// change each cause a cache miss.
fn custom_request_digest(spec: &CustomKernelSpec, identity: &KernelCompilerIdentity) -> LinkDigest {
    let mode = match spec.config().mode() {
        crate::KernelConfigMode::Fragment => b"fragment".as_slice(),
        crate::KernelConfigMode::Complete => b"complete".as_slice(),
    };
    let source = spec.source();
    let (algorithm, digest_bytes): (&[u8], &[u8]) = match source.digest() {
        image_core::digest::ExpectedDigest::Sha256(bytes) => (b"sha256", bytes),
        image_core::digest::ExpectedDigest::Sha512(bytes) => (b"sha512", bytes),
        image_core::digest::ExpectedDigest::Blake3(bytes) => (b"blake3", bytes),
    };
    LinkDigestBuilder::new(b"jyth.kernel.custom.v2")
        .str(b"version", spec.version().as_str())
        .str(b"source-url", source.url().as_str())
        .bytes(b"source-algorithm", algorithm)
        .bytes(b"source-digest", digest_bytes)
        .bytes(b"config-mode", mode)
        .bytes(b"config", spec.config().as_bytes())
        .bytes(b"identity", &identity.encode())
        .finish(0)
}

/// The kernel request digest for one external plan: the resolver-owned source
/// digest plus the request shape. The domain prefix `jyth.kernel.external.v1`
/// separates kernel request identities from every other digest namespace.
///
/// The encoding uses fixed-width integers and length prefixes and never
/// relies on `Debug`, JSON object order, or platform-native path encoding.
fn kernel_request_digest(
    resolved: &ResolvedSource,
    kernel_path: Option<&KernelPath>,
) -> LinkDigest {
    let builder = LinkDigestBuilder::new(b"jyth.kernel.external.v1")
        .bytes(b"source-hash", resolved.source_digest.link_hash.as_bytes())
        .u128(b"source-size", resolved.source_digest.file_size);
    let builder = match kernel_path {
        None => builder.str(b"shape", "raw"),
        Some(path) => builder.str(b"shape", "archive").str(b"path", path.as_str()),
    };
    builder.finish(resolved.source_digest.file_size)
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
async fn extract_kernel_result(
    store: &dyn ImageStore,
    source: FileRef,
    kernel_path: Option<&KernelPath>,
    kernel_ref: &LinkRef,
    modules_ref: &LinkRef,
    token: &CancellationToken,
) -> Result<MaterializedKernel, Report<KernelError>> {
    if source.artifact_type != ArtifactType::ContainerCpio {
        return Err(Report::new(KernelError::Materialization).attach(format!(
            "kernel source materialized as unsupported artifact {:?}",
            source.artifact_type
        )));
    }

    let modules = match cached_modules(store, modules_ref).map_err(change_kernel)? {
        Some(value) => {
            let _ = OpTimer::start("kernel.modules").cache(CacheOutcome::Hit);
            Some(value)
        }
        None => {
            let timer = OpTimer::start("kernel.modules").cache(CacheOutcome::Miss);
            match extract_modules_if_needed(store, &source, modules_ref, token).await {
                Ok(modules) => modules,
                Err(error) => {
                    timer.fail(format!("{error:#}"));
                    return Err(error);
                }
            }
        }
    };

    let kernel = match store
        .read_file_ref(kernel_ref)
        .map_err(change_kernel)?
        .filter(|entry| entry.artifact_type == ArtifactType::FileBzImage)
    {
        Some(value) => value,
        None => {
            // An archive plan always carries a validated KernelPath; the
            // operation boundary re-validates the canonical string.
            let requested = kernel_path
                .ok_or_else(|| {
                    Report::new(KernelError::Materialization)
                        .attach("archive extraction requires a kernel entry path")
                })?
                .as_str()
                .to_string();
            let extracted = ops::extract_kernel(&requested, &source, kernel_ref, token)
                .await
                .map_err(change_kernel)?;
            publish_transformed(store, kernel_ref, extracted).map_err(change_kernel)?
        }
    };

    Ok(MaterializedKernel {
        kernel: kernel.path(),
        modules,
    })
}

async fn extract_modules_if_needed(
    store: &dyn ImageStore,
    source: &FileRef,
    modules_ref: &LinkRef,
    token: &CancellationToken,
) -> Result<Option<FileRef>, Report<KernelError>> {
    let Some(modules) = ops::extract_modules(source, modules_ref, token)
        .await
        .map_err(change_kernel)?
    else {
        return Ok(None);
    };
    store
        .publish_file_ref(modules_ref, &modules)
        .map_err(change_kernel)?;
    Ok(Some(modules))
}

fn cached_modules(
    store: &dyn ImageStore,
    modules_ref: &LinkRef,
) -> Result<Option<FileRef>, Report<IndexError>> {
    Ok(store.read_file_ref(modules_ref)?.filter(|entry| {
        entry.artifact_type == ArtifactType::ContainerCpio
            && entry.artifact_compression == ArtifactCompression::None
    }))
}

fn publish_transformed(
    store: &dyn ImageStore,
    target: &LinkRef,
    transformed: FileRef,
) -> Result<FileRef, Report<IndexError>> {
    if store.read_file_ref(target)?.is_some() {
        store.replace_file_ref(transformed)
    } else {
        store.publish_file_ref(target, &transformed)?;
        Ok(transformed)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use image_core::{
        artifact::link::ArtifactLink,
        digest::{FileDigest, LinkDigest},
        resolver::SourceResolver,
        storage::blueprint::Blueprint,
    };

    /// In-memory `ImageStore` double: stable per-digest identities, scripted
    /// reads (consumed in order, then misses), a scriptable read failure,
    /// and a recorded publish log.
    struct FakeStore {
        link_refs: Mutex<std::collections::HashMap<NamespacedLinkDigest, LinkRef>>,
        reads: Mutex<VecDeque<Option<FileRef>>>,
        read_failure: AtomicBool,
        publishes: Mutex<Vec<(LinkRef, FileRef)>>,
    }

    impl FakeStore {
        fn new(reads: Vec<Option<FileRef>>) -> Self {
            Self {
                link_refs: Mutex::new(std::collections::HashMap::new()),
                reads: Mutex::new(reads.into()),
                read_failure: AtomicBool::new(false),
                publishes: Mutex::new(Vec::new()),
            }
        }

        fn fail_reads(&self) {
            self.read_failure.store(true, Ordering::SeqCst);
        }

        #[allow(dead_code)]
        fn published(&self) -> Vec<(LinkRef, FileRef)> {
            self.publishes.lock().expect("publishes").clone()
        }
    }

    impl ImageStore for FakeStore {
        fn reserve_link_ref(
            &self,
            link_digest: NamespacedLinkDigest,
        ) -> Result<LinkRef, Report<IndexError>> {
            Ok(*self
                .link_refs
                .lock()
                .expect("link refs")
                .entry(link_digest)
                .or_insert_with(|| LinkRef {
                    uuid: uuid::Uuid::now_v7(),
                    namespace: link_digest.namespace,
                    link_digest: link_digest.link_digest,
                }))
        }

        fn read_file_ref(
            &self,
            _link_ref: &LinkRef,
        ) -> Result<Option<FileRef>, Report<IndexError>> {
            if self.read_failure.load(Ordering::SeqCst) {
                return Err(IndexError::Transaction.report());
            }
            Ok(self.reads.lock().expect("reads").pop_front().flatten())
        }

        fn publish_file_ref(
            &self,
            link_ref: &LinkRef,
            file_ref: &FileRef,
        ) -> Result<(), Report<IndexError>> {
            self.publishes
                .lock()
                .expect("publishes")
                .push((*link_ref, file_ref.clone()));
            Ok(())
        }

        fn replace_file_ref(&self, file_ref: FileRef) -> Result<FileRef, Report<IndexError>> {
            Ok(file_ref)
        }

        fn read_blueprint(
            &self,
            _link_digest: NamespacedLinkDigest,
        ) -> Result<Option<Blueprint>, Report<IndexError>> {
            Ok(None)
        }

        fn publish_blueprint(&self, value: Blueprint) -> Result<Blueprint, Report<IndexError>> {
            Ok(value)
        }
    }

    /// A `SourceResolver` double returning one scripted outcome.
    struct ScriptedResolver {
        outcome: Mutex<Option<Result<ResolvedSource, Report<SourceResolverError>>>>,
    }

    impl ScriptedResolver {
        fn ok(link: ArtifactLink, is_image: bool) -> Self {
            Self {
                outcome: Mutex::new(Some(Ok(ResolvedSource {
                    source_digest: link.digest().expect("scripted link digest"),
                    link,
                    is_image,
                }))),
            }
        }

        fn err() -> Self {
            Self {
                outcome: Mutex::new(Some(Err(Report::new(SourceResolverError::Resolution)))),
            }
        }
    }

    impl SourceResolver for ScriptedResolver {
        fn resolve(
            &self,
            _source: Link,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>>
                    + Send
                    + '_,
            >,
        > {
            let outcome = self
                .outcome
                .lock()
                .expect("outcome")
                .take()
                .unwrap_or_else(|| {
                    Ok(ResolvedSource {
                        source_digest: LinkDigest {
                            link_hash: blake3::hash(&[]),
                            file_size: 0,
                        },
                        link: ArtifactLink::bytes(""),
                        is_image: false,
                    })
                });
            Box::pin(async move { outcome })
        }
    }

    fn kernel_file_ref() -> FileRef {
        FileRef {
            uuid: uuid::Uuid::now_v7(),
            namespace: Namespace::Kernel,
            file_digest: FileDigest {
                file_hash: blake3::hash(b"kernel"),
                file_size: 6,
            },
            artifact_type: ArtifactType::FileBzImage,
            artifact_compression: ArtifactCompression::None,
        }
    }

    fn modules_file_ref() -> FileRef {
        FileRef {
            uuid: uuid::Uuid::now_v7(),
            namespace: Namespace::Modules,
            file_digest: FileDigest {
                file_hash: blake3::hash(b"modules"),
                file_size: 7,
            },
            artifact_type: ArtifactType::ContainerCpio,
            artifact_compression: ArtifactCompression::None,
        }
    }

    /// A service over a scripted local resolver (bytes payload) and inert
    /// sibling resolvers.
    fn service_with(local: Arc<dyn SourceResolver>, store: FakeStore) -> KernelService {
        KernelService::new(
            Arc::new(store),
            ResolverSet::new(
                local,
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
            ),
        )
    }

    /// A raw plan over the given facade link.
    fn raw_plan(link: Link) -> ExternalKernelPlan {
        ExternalKernelPlan {
            link,
            kernel_path: None,
        }
    }

    /// An archive plan over the given facade link and entry path.
    fn archive_plan(link: Link, path: &str) -> ExternalKernelPlan {
        ExternalKernelPlan {
            link,
            kernel_path: Some(KernelPath::parse(path).expect("valid path")),
        }
    }

    #[tokio::test]
    async fn kernel_build_serves_cached_artifacts_through_the_injected_store() {
        let kernel = kernel_file_ref();
        let modules = modules_file_ref();
        let service = service_with(
            Arc::new(ScriptedResolver::ok(ArtifactLink::bytes("source"), false)),
            FakeStore::new(vec![Some(kernel.clone()), Some(modules.clone())]),
        );

        let built = service
            .build_external(raw_plan(Link::local("ignored")), &CancellationToken::new())
            .await
            .expect("build");
        assert_eq!(built.kernel, kernel.path());
        assert_eq!(built.modules, Some(modules));
    }

    #[tokio::test]
    async fn kernel_build_propagates_resolver_failures() {
        let service = service_with(Arc::new(ScriptedResolver::err()), FakeStore::new(vec![]));

        let err = service
            .build_external(raw_plan(Link::local("missing")), &CancellationToken::new())
            .await
            .expect_err("resolver fails");
        assert!(matches!(
            err.current_context(),
            KernelError::Materialization
        ));
        // The port error category crosses the boundary into the use-case
        // error surface.
        assert!(err.frames().any(|frame| frame.is::<SourceResolverError>()));
    }

    #[tokio::test]
    async fn kernel_build_propagates_store_failures() {
        let store = FakeStore::new(vec![]);
        store.fail_reads();
        let service = service_with(
            Arc::new(ScriptedResolver::ok(ArtifactLink::bytes("source"), false)),
            store,
        );

        let err = service
            .build_external(raw_plan(Link::local("ignored")), &CancellationToken::new())
            .await
            .expect_err("store read fails");
        assert!(matches!(
            err.current_context(),
            KernelError::Materialization
        ));
        let text = format!("{err:#}");
        assert!(text.contains("index transaction failed"), "{text}");
    }

    /// An image link must be routed to the image resolver, and the
    /// `is_image` outcome must drive the blueprint branch: the scripted
    /// (non-HTTP) source link is then rejected by the blueprint
    /// precondition, which only the image path reaches.
    #[tokio::test]
    async fn image_links_dispatch_to_the_image_resolver_and_take_the_image_path() {
        let store = FakeStore::new(vec![None, None]);
        let service = KernelService::new(
            Arc::new(store),
            ResolverSet::new(
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes("image"), true)),
            ),
        );

        let err = service
            .build_external(
                archive_plan(Link::image("example.invalid/image"), "boot/kernel"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("blueprint precondition");
        // The image path reached `ops::blueprint`, which rejects the
        // scripted non-HTTP source link with `UnsupportedArtifact`.
        let text = format!("{err:#}");
        assert!(text.contains("unsupported artifact format"), "{text}");
    }

    /// A local link must never reach the image resolver: the scripted image
    /// resolver fails, but the local source still materializes.
    #[tokio::test]
    async fn local_links_never_reach_the_image_resolver() {
        let kernel = kernel_file_ref();
        let modules = modules_file_ref();
        let service = KernelService::new(
            Arc::new(FakeStore::new(vec![
                Some(kernel.clone()),
                Some(modules.clone()),
            ])),
            ResolverSet::new(
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes("source"), false)),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
            ),
        );

        let built = service
            .build_external(raw_plan(Link::local("ignored")), &CancellationToken::new())
            .await
            .expect("local source");
        assert_eq!(built.kernel, kernel.path());
        assert_eq!(built.modules, Some(modules));
    }

    /// Request digests are path-sensitive: two paths in one source produce
    /// two identities, while normalized spellings of one path share one
    /// identity and the raw shape is distinct from any archive shape.
    #[test]
    fn request_digests_are_path_sensitive_and_normalized() {
        let source = ResolvedSource {
            source_digest: LinkDigest {
                link_hash: blake3::hash(b"source"),
                file_size: 6,
            },
            link: ArtifactLink::bytes("source"),
            is_image: false,
        };

        let raw = kernel_request_digest(&source, None);
        let path_a =
            kernel_request_digest(&source, Some(&KernelPath::parse("boot/vmlinuz").unwrap()));
        let path_b = kernel_request_digest(
            &source,
            Some(&KernelPath::parse("./boot\\vmlinuz").unwrap()),
        );
        let path_c =
            kernel_request_digest(&source, Some(&KernelPath::parse("boot/other").unwrap()));

        assert_ne!(raw, path_a, "raw and archive shapes differ");
        assert_eq!(path_a, path_b, "normalized spellings share one identity");
        assert_ne!(path_a, path_c, "different paths differ");
        assert_eq!(path_a.file_size, source.source_digest.file_size);
    }

    /// Request digests are source-sensitive: one path in two sources cannot
    /// alias one cached artifact.
    #[test]
    fn request_digests_are_source_sensitive() {
        let source_a = ResolvedSource {
            source_digest: LinkDigest {
                link_hash: blake3::hash(b"source-a"),
                file_size: 8,
            },
            link: ArtifactLink::bytes("source-a"),
            is_image: false,
        };
        let source_b = ResolvedSource {
            source_digest: LinkDigest {
                link_hash: blake3::hash(b"source-b"),
                file_size: 8,
            },
            link: ArtifactLink::bytes("source-b"),
            is_image: false,
        };

        let a = kernel_request_digest(&source_a, Some(&KernelPath::parse("boot/vmlinuz").unwrap()));
        let b = kernel_request_digest(&source_b, Some(&KernelPath::parse("boot/vmlinuz").unwrap()));
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Custom compilation: fake compiler + custom cache
    // -----------------------------------------------------------------------

    use crate::CustomKernelSpec;
    use crate::compiler::{
        CompiledKernel, KernelCompiler, KernelCompilerError, KernelCompilerIdentity,
    };
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;

    fn identity(byte: u8) -> KernelCompilerIdentity {
        let hex = format!("sha256:{}", format!("{byte:02x}").repeat(32));
        KernelCompilerIdentity::new(1, hex.clone(), hex.clone(), hex.clone(), "x86_64", "kb=1")
            .expect("identity")
    }

    /// A fake compiler: counts invocations, optionally fails, and stages a
    /// minimal bzImage (boot flag + HdrS) into a temp file on success.
    #[derive(Clone)]
    struct FakeCompiler {
        identity: KernelCompilerIdentity,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl FakeCompiler {
        fn ok() -> Self {
            Self {
                identity: identity(0x44),
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                identity: identity(0x45),
                calls: Arc::new(AtomicUsize::new(0)),
                fail: true,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl KernelCompiler for FakeCompiler {
        fn identity(&self) -> &KernelCompilerIdentity {
            &self.identity
        }

        fn compile<'a>(
            &'a self,
            _spec: &'a CustomKernelSpec,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<CompiledKernel, Report<KernelCompilerError>>>
                    + Send
                    + 'a,
            >,
        > {
            let this = self.clone();
            Box::pin(async move {
                this.calls.fetch_add(1, Ordering::SeqCst);
                if this.fail {
                    return Err(Report::new(KernelCompilerError::GuestBuild {
                        exit_status: 1,
                        stderr: "script failed".to_string(),
                    }));
                }
                let dir = tempfile::tempdir().expect("tempdir");
                let path = dir.path().join("bzImage");
                let mut bytes = vec![0u8; 0x206 + 16];
                bytes[0x1fe] = 0x55;
                bytes[0x1ff] = 0xaa;
                bytes[0x202..0x206].copy_from_slice(b"HdrS");
                std::fs::write(&path, &bytes).expect("write staged kernel");
                // Keep the tempdir alive for the service to read the staged
                // file; CompiledKernel::Drop removes the file itself.
                std::mem::forget(dir);
                CompiledKernel::new(path).map_err(|err| Report::new(err))
            })
        }
    }

    /// A caching in-memory store: reads return published entries, so a
    /// compiled artifact is visible to later requests with the same digest.
    struct CachingStore {
        link_refs: Mutex<std::collections::HashMap<NamespacedLinkDigest, LinkRef>>,
        entries: Mutex<std::collections::HashMap<NamespacedLinkDigest, FileRef>>,
    }

    impl CachingStore {
        fn new() -> Self {
            Self {
                link_refs: Mutex::new(std::collections::HashMap::new()),
                entries: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    impl ImageStore for CachingStore {
        fn reserve_link_ref(
            &self,
            link_digest: NamespacedLinkDigest,
        ) -> Result<LinkRef, Report<IndexError>> {
            Ok(*self
                .link_refs
                .lock()
                .expect("link refs")
                .entry(link_digest)
                .or_insert_with(|| LinkRef {
                    uuid: uuid::Uuid::now_v7(),
                    namespace: link_digest.namespace,
                    link_digest: link_digest.link_digest,
                }))
        }

        fn read_file_ref(&self, link_ref: &LinkRef) -> Result<Option<FileRef>, Report<IndexError>> {
            Ok(self
                .entries
                .lock()
                .expect("entries")
                .get(&NamespacedLinkDigest {
                    namespace: link_ref.namespace,
                    link_digest: link_ref.link_digest,
                })
                .cloned())
        }

        fn publish_file_ref(
            &self,
            link_ref: &LinkRef,
            file_ref: &FileRef,
        ) -> Result<(), Report<IndexError>> {
            self.entries.lock().expect("entries").insert(
                NamespacedLinkDigest {
                    namespace: link_ref.namespace,
                    link_digest: link_ref.link_digest,
                },
                file_ref.clone(),
            );
            Ok(())
        }

        fn replace_file_ref(&self, file_ref: FileRef) -> Result<FileRef, Report<IndexError>> {
            Ok(file_ref)
        }

        fn read_blueprint(
            &self,
            _link_digest: NamespacedLinkDigest,
        ) -> Result<Option<Blueprint>, Report<IndexError>> {
            Ok(None)
        }

        fn publish_blueprint(&self, value: Blueprint) -> Result<Blueprint, Report<IndexError>> {
            Ok(value)
        }
    }

    /// A custom service over the caching store with inert resolvers (custom
    /// materialization never touches external sources).
    fn custom_service(store: CachingStore) -> KernelService {
        KernelService::new(
            Arc::new(store),
            ResolverSet::new(
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
                Arc::new(ScriptedResolver::err()),
            ),
        )
    }

    fn custom_spec(version: &str) -> CustomKernelSpec {
        CustomKernelSpec::with_config(version, crate::KernelConfig::default()).expect("spec")
    }

    #[tokio::test]
    async fn fake_compiler_runs_once_for_the_first_custom_request() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();

        let (built, served_from_cache) = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect("custom build");
        assert_eq!(compiler.call_count(), 1);
        assert!(!served_from_cache, "first build is a miss");
        assert!(built.modules.is_none(), "custom builds carry no modules");
        assert!(built.kernel.exists(), "published kernel exists");
    }

    #[tokio::test]
    async fn cached_custom_request_does_not_invoke_the_compiler() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();

        let (first, first_hit) = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect("first build");
        let (second, second_hit) = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect("cached build");

        assert_eq!(compiler.call_count(), 1, "cache hit skips the compiler");
        assert!(!first_hit);
        assert!(second_hit, "the second request is served from cache");
        assert_eq!(first.kernel, second.kernel);
    }

    #[tokio::test]
    async fn a_version_change_causes_a_cache_miss() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();

        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect("first");
        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.8"), &compiler, &CancellationToken::new())
            .await
            .expect("second");
        assert_eq!(compiler.call_count(), 2, "version change misses");
    }

    /// A pinned spec whose source digest differs from the catalogued 7.1.7
    /// pin must produce a different request digest than the catalogued spec,
    /// so a source-digest change always causes a cache miss.
    fn pinned_spec_with_digest(version: &str, sha256: &str) -> CustomKernelSpec {
        let url = format!("https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-{version}.tar.xz");
        let pin = crate::KernelSourcePin::new(
            crate::KernelVersion::parse(version).expect("version"),
            image_core::http_url::HttpUrl::parse(&url).expect("url"),
            image_core::digest::ExpectedDigest::parse(&format!("sha256:{sha256}")).expect("digest"),
        )
        .expect("pin");
        CustomKernelSpec::from_pin_with_config(pin, crate::KernelConfig::default())
    }

    #[test]
    fn a_source_digest_change_changes_the_request_digest() {
        let identity = identity(0x44);
        let catalogued = custom_spec("7.1.7");
        let same_bytes = pinned_spec_with_digest(
            "7.1.7",
            "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
        );
        let different_bytes = pinned_spec_with_digest(
            "7.1.7",
            "ff01dcb449279d5b4cfccdb01fee639cf5ff1803f1749a77844dd33915422c49",
        );

        let base = custom_request_digest(&catalogued, &identity);
        let same = custom_request_digest(&same_bytes, &identity);
        let different = custom_request_digest(&different_bytes, &identity);

        // The catalogued pin and the explicit pin with identical bytes share
        // one identity (canonical URL + digest are equal).
        assert_eq!(base, same);
        // One changed source byte must change the digest.
        assert_ne!(base, different);
        assert_ne!(same, different);
    }

    #[test]
    fn a_source_url_change_changes_the_request_digest() {
        let identity = identity(0x44);
        let catalogued = custom_spec("7.1.7");
        // Rebuild the pin over a different canonical host with identical bytes.
        let pin = crate::KernelSourcePin::new(
            crate::KernelVersion::parse("7.1.7").expect("version"),
            image_core::http_url::HttpUrl::parse(
                "https://mirror.example.com/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
            )
            .expect("url"),
            image_core::digest::ExpectedDigest::parse(
                "sha256:ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
            )
            .expect("digest"),
        )
        .expect("pin");
        let moved = CustomKernelSpec::from_pin_with_config(pin, crate::KernelConfig::default());

        let base = custom_request_digest(&catalogued, &identity);
        let moved_digest = custom_request_digest(&moved, &identity);
        assert_ne!(
            base, moved_digest,
            "the source URL participates in the digest"
        );
    }

    #[tokio::test]
    async fn a_source_digest_change_causes_a_cache_miss() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();

        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect("first");
        let _ = service
            .build_custom_with_outcome(
                pinned_spec_with_digest(
                    "7.1.7",
                    "ff01dcb449279d5b4cfccdb01fee639cf5ff1803f1749a77844dd33915422c49",
                ),
                &compiler,
                &CancellationToken::new(),
            )
            .await
            .expect("second");
        assert_eq!(compiler.call_count(), 2, "source-digest change misses");
    }

    #[tokio::test]
    async fn a_configuration_byte_change_causes_a_cache_miss() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();
        let spec_a = CustomKernelSpec::with_config(
            "7.1.7",
            crate::KernelConfig::complete(b"CONFIG_A=y").expect("config"),
        )
        .expect("spec");
        let spec_b = CustomKernelSpec::with_config(
            "7.1.7",
            crate::KernelConfig::complete(b"CONFIG_B=y").expect("config"),
        )
        .expect("spec");

        let _ = service
            .build_custom_with_outcome(spec_a, &compiler, &CancellationToken::new())
            .await
            .expect("first");
        let _ = service
            .build_custom_with_outcome(spec_b, &compiler, &CancellationToken::new())
            .await
            .expect("second");
        assert_eq!(compiler.call_count(), 2, "config bytes change the digest");
    }

    #[tokio::test]
    async fn a_fragment_vs_complete_mode_change_causes_a_cache_miss() {
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::ok();
        let fragment = CustomKernelSpec::with_config(
            "7.1.7",
            crate::KernelConfig::fragment(b"CONFIG_A=y").expect("frag"),
        )
        .expect("spec");
        let complete = CustomKernelSpec::with_config(
            "7.1.7",
            crate::KernelConfig::complete(b"CONFIG_A=y").expect("complete"),
        )
        .expect("spec");

        let _ = service
            .build_custom_with_outcome(fragment, &compiler, &CancellationToken::new())
            .await
            .expect("first");
        let _ = service
            .build_custom_with_outcome(complete, &compiler, &CancellationToken::new())
            .await
            .expect("second");
        assert_eq!(compiler.call_count(), 2, "mode is part of the digest");
    }

    #[tokio::test]
    async fn a_compiler_identity_change_causes_a_cache_miss() {
        let service = custom_service(CachingStore::new());
        let compiler_a = FakeCompiler::ok();
        let mut compiler_b = FakeCompiler::ok();
        compiler_b.identity = identity(0x55);

        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler_a, &CancellationToken::new())
            .await
            .expect("first");
        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler_b, &CancellationToken::new())
            .await
            .expect("second");
        assert_eq!(compiler_a.call_count(), 1);
        assert_eq!(compiler_b.call_count(), 1, "identity change misses");
    }

    #[tokio::test]
    async fn a_failed_compiler_publishes_no_cache_entry() {
        let store = CachingStore::new();
        let service = custom_service(store);
        let compiler = FakeCompiler::failing();

        let err = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect_err("compiler fails");
        assert!(matches!(err.current_context(), KernelError::Compilation));
        assert_eq!(compiler.call_count(), 1);
        // A subsequent identical request must retry the compiler, not serve a
        // phantom cache entry.
        let service = custom_service(CachingStore::new());
        let compiler = FakeCompiler::failing();
        let _ = service
            .build_custom_with_outcome(custom_spec("7.1.7"), &compiler, &CancellationToken::new())
            .await
            .expect_err("retried");
        assert_eq!(compiler.call_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_identical_requests_publish_one_validated_artifact() {
        let service = Arc::new(custom_service(CachingStore::new()));
        let compiler = FakeCompiler::ok();
        let compiler = Arc::new(compiler);

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let service = service.clone();
            let compiler = compiler.clone();
            tasks.spawn(async move {
                service
                    .build_custom_with_outcome(
                        custom_spec("7.1.7"),
                        compiler.as_ref(),
                        &CancellationToken::new(),
                    )
                    .await
                    .expect("concurrent build")
            });
        }
        let mut kernels = Vec::new();
        let mut cache_hits = 0;
        while let Some(result) = tasks.join_next().await {
            let (materialized, served_from_cache) = result.expect("task ok");
            kernels.push(materialized.kernel);
            if served_from_cache {
                cache_hits += 1;
            }
        }
        assert_eq!(
            compiler.call_count(),
            1,
            "one compilation for identical requests"
        );
        assert_eq!(
            cache_hits, 3,
            "three waiters observe the published artifact"
        );
        assert!(
            kernels.windows(2).all(|pair| pair[0] == pair[1]),
            "one published artifact"
        );
    }
}
