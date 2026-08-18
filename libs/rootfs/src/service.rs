//! The rootfs materialization service.
//!
//! Owns the root filesystem materialization pipeline and the module merge.
//! All storage access flows through an injected [`ImageStore`] port and all
//! external source acquisition flows through injected [`SourceResolver`]
//! adapters; the service never acquires a process-global implementation from
//! inside a use-case method. The public `materialize` and `merge_modules`
//! entry points construct the default service (default store plus default
//! resolvers); tests inject fakes.

use std::path::PathBuf;
use std::sync::Arc;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{Link, RootfsError, ops};
use image_core::{
    artifact::ty::ArtifactType,
    digest::LinkDigest,
    materialize::{get_or_build_blueprint, materialize_layers, normalize_artifact},
    ops as core_ops,
    resolver::{ResolvedSource, ResolverSet, SourceResolverError},
    storage::{
        error::IndexError,
        file_ref::FileRef,
        namespace::{Namespace, NamespacedLinkDigest},
    },
    store::{ImageStore, SharedStore},
    timing::{CacheOutcome, OpTimer, SourceKind},
};

/// Attach the rootfs materialization category to an error report.
pub(crate) fn change_rootfs<E>(error: Report<E>) -> Report<RootfsError> {
    error.change_context(RootfsError::Materialization)
}

/// The rootfs materialization service: resolves external sources and
/// publishes validated CPIO artifacts through an injected store.
pub(crate) struct RootfsService {
    store: Arc<dyn ImageStore>,
    resolvers: ResolverSet,
}

impl RootfsService {
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

    /// Materialize a rootfs source into one complete uncompressed CPIO.
    #[cfg_attr(
        feature = "tracing",
        instrument(skip_all, fields(source = ?source), level = "debug")
    )]
    pub(crate) async fn build_rootfs(
        &self,
        source: Link,
        token: &CancellationToken,
    ) -> Result<FileRef, Report<RootfsError>> {
        let timer = OpTimer::start("rootfs.materialize")
            .source(SourceKind::from(&source))
            .namespace("rootfs");
        match self.build_rootfs_inner(source, token).await {
            Ok(rootfs) => Ok(rootfs),
            Err(error) => {
                timer.fail(format!("{error:#}"));
                Err(error)
            }
        }
    }

    /// The materialization pipeline behind [`Self::build_rootfs`], timed by
    /// the `rootfs.materialize` completion timer at the wrapper and by the
    /// `rootfs.resolve`/`rootfs.layers`/`rootfs.validate` sub-timers.
    async fn build_rootfs_inner(
        &self,
        source: Link,
        token: &CancellationToken,
    ) -> Result<FileRef, Report<RootfsError>> {
        let timer = OpTimer::start("rootfs.resolve")
            .source(SourceKind::from(&source))
            .namespace("rootfs");
        let resolved = match self.resolve_source(source).await {
            Ok(resolved) => resolved,
            Err(error) => {
                let error = change_rootfs(error);
                timer.fail(format!("{error:#}"));
                return Err(error);
            }
        };
        let link = resolved.link;
        let is_image = resolved.is_image;
        let source_digest = resolved.source_digest;
        let rootfs_link_ref = self
            .store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Rootfs,
                link_digest: source_digest,
            })
            .map_err(change_rootfs)?;

        if let Some(entry) = self
            .store
            .read_file_ref(&rootfs_link_ref)
            .map_err(change_rootfs)?
            .filter(|entry| entry.artifact_type == ArtifactType::ContainerCpio)
        {
            let timer = OpTimer::start("rootfs.validate").namespace("rootfs");
            if let Err(error) = ops::validate_cpio(&entry, token).await {
                let error = change_rootfs(error);
                timer.fail(format!("{error:#}"));
                return Err(error);
            }
            return Ok(entry);
        }

        let rootfs = if is_image {
            let timer = OpTimer::start("rootfs.layers")
                .source(SourceKind::from(&link))
                .namespace("layers");
            // The blueprint is cached under the source digest; the link
            // snapshot is verified separately so a link cannot be swapped
            // between reservation and use.
            let expected_link_digest = link.digest().map_err(change_rootfs)?;
            let blueprint = match get_or_build_blueprint(
                self.store.as_ref(),
                &rootfs_link_ref,
                link,
                None,
                expected_link_digest,
            )
            .await
            {
                Ok(blueprint) => blueprint,
                Err(error) => {
                    let error = change_rootfs(error);
                    timer.fail(format!("{error:#}"));
                    return Err(error);
                }
            };
            match materialize_layers(
                self.store.as_ref(),
                blueprint.layers,
                &rootfs_link_ref,
                token,
            )
            .await
            {
                Ok(rootfs) => rootfs,
                Err(error) => {
                    let error = change_rootfs(error);
                    timer.fail(format!("{error:#}"));
                    return Err(error);
                }
            }
        } else {
            let expected_link_digest = link.digest().map_err(change_rootfs)?;
            let mut artifact =
                core_ops::load(&link, &rootfs_link_ref, None, expected_link_digest, token)
                    .await
                    .map_err(change_rootfs)?;
            self.store
                .publish_file_ref(&rootfs_link_ref, &artifact)
                .map_err(change_rootfs)?;
            artifact = normalize_artifact(self.store.as_ref(), artifact, token)
                .await
                .map_err(change_rootfs)?;
            if artifact.artifact_type != ArtifactType::ContainerCpio {
                return Err(Report::new(RootfsError::Materialization).attach(format!(
                    "rootfs materialized as unsupported artifact {:?}",
                    artifact.artifact_type
                )));
            }
            let timer = OpTimer::start("rootfs.validate").namespace("rootfs");
            if let Err(error) = ops::validate_cpio(&artifact, token).await {
                let error = change_rootfs(error);
                timer.fail(format!("{error:#}"));
                return Err(error);
            }
            artifact
        };

        self.store
            .publish_file_ref(&rootfs_link_ref, &rootfs)
            .map_err(change_rootfs)?;
        Ok(rootfs)
    }

    /// Merge a cached module fragment into a derived rootfs artifact. The
    /// source rootfs link is never overwritten: two kernels may share one
    /// base rootfs but require different `/lib/modules` trees.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
    pub(crate) async fn merge_modules(
        &self,
        base: FileRef,
        modules: FileRef,
        token: &CancellationToken,
    ) -> Result<PathBuf, Report<RootfsError>> {
        let timer = OpTimer::start("rootfs.merge").namespace("rootfs");
        let mut hasher = blake3::Hasher::new();
        // The merge now resolves upper-layer paths through lower-layer
        // symlinks (for example `/lib -> /usr/lib`). Bump the derived
        // identity so an older flattened archive cannot hide the corrected
        // layout.
        hasher.update(b"image:rootfs-with-modules:v2");
        hasher.update(base.file_digest.file_hash.as_bytes());
        hasher.update(&base.file_digest.file_size.to_be_bytes());
        hasher.update(modules.file_digest.file_hash.as_bytes());
        hasher.update(&modules.file_digest.file_size.to_be_bytes());
        let derived_link = LinkDigest {
            link_hash: hasher.finalize(),
            file_size: base
                .file_digest
                .file_size
                .saturating_add(modules.file_digest.file_size),
        };
        let derived_ref = self
            .store
            .reserve_link_ref(NamespacedLinkDigest {
                namespace: Namespace::Rootfs,
                link_digest: derived_link,
            })
            .map_err(change_rootfs)?;
        if let Some(cached) = self
            .store
            .read_file_ref(&derived_ref)
            .map_err(change_rootfs)?
            .filter(|entry| entry.artifact_type == ArtifactType::ContainerCpio)
        {
            let _ = timer.cache(CacheOutcome::Hit);
            return Ok(cached.path());
        }

        let merged = match core_ops::flatten(&[base, modules], &derived_ref, token).await {
            Ok(merged) => merged,
            Err(error) => {
                let error = change_rootfs(error);
                timer.cache(CacheOutcome::Miss).fail(format!("{error:#}"));
                return Err(error);
            }
        };
        if let Err(error) = self.store.publish_file_ref(&derived_ref, &merged) {
            let error = change_rootfs(error);
            timer.cache(CacheOutcome::Miss).fail(format!("{error:#}"));
            return Err(error);
        }
        let _ = timer.cache(CacheOutcome::Miss);
        Ok(merged.path())
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use image_core::{
        artifact::link::ArtifactLink,
        digest::LinkDigest,
        resolver::SourceResolver,
        storage::{blueprint::Blueprint, link_ref::LinkRef},
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

    /// A service over a scripted local resolver (bytes payload) and inert
    /// sibling resolvers.
    fn service_with(local: Arc<dyn SourceResolver>, store: FakeStore) -> RootfsService {
        RootfsService::new(
            Arc::new(store),
            ResolverSet::new(
                local,
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
                Arc::new(ScriptedResolver::ok(ArtifactLink::bytes(""), false)),
            ),
        )
    }

    #[tokio::test]
    async fn rootfs_build_propagates_store_failures() {
        let store = FakeStore::new(vec![]);
        store.fail_reads();
        let service = service_with(
            Arc::new(ScriptedResolver::ok(ArtifactLink::bytes("rootfs"), false)),
            store,
        );

        let err = service
            .build_rootfs(Link::bytes("rootfs"), &CancellationToken::new())
            .await
            .expect_err("store read fails");
        assert!(matches!(
            err.current_context(),
            RootfsError::Materialization
        ));
        let text = format!("{err:#}");
        assert!(text.contains("index transaction failed"), "{text}");
    }
}
