//! Kernel source specification and materialization.
//!
//! # Overview
//!
//! [`Kernel`] is an opaque facade over validated kernel specifications.
//! External callers construct kernels through associated functions — never
//! through public struct fields or enum variants — and every fallible textual
//! value is validated at construction time, before any asynchronous
//! materialization begins:
//!
//! ```rust
//! use kernel::{Kernel, KernelConfig};
//!
//! static VMLINUZ: &[u8] = b"vmlinuz bytes";
//! let downloaded_bytes = bytes::Bytes::from_static(b"downloaded vmlinuz");
//!
//! let default_kernel = Kernel::default();
//!
//! let custom_kernel = Kernel::custom("7.1.7")?;
//! let configured_kernel = Kernel::custom_with_config("7.1.7", KernelConfig::default())?;
//!
//! let local_kernel = Kernel::local("./vmlinuz");
//! let remote_kernel = Kernel::http("https://example.com/vmlinuz")?;
//! let image_kernel = Kernel::image("ubuntu:24.04", "boot/vmlinuz")?;
//! let memory_kernel = Kernel::bytes(downloaded_bytes);
//! let embedded_kernel = Kernel::embedded(VMLINUZ);
//!
//! let archived_kernel = Kernel::local_archive("./kernel.cpio", "boot/vmlinuz")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Raw sources (`local`, `http`, `bytes`, `embedded`) never carry a
//! kernel-entry path; archive sources (`local_archive`, `http_archive`,
//! `bytes_archive`, `image`) always carry one validated [`KernelPath`]. The
//! opaque boundary prevents callers from pairing a raw source with an invalid
//! archive path.
//!
//! # Default and custom kernels
//!
//! [`Kernel::default()`] lowers to one pinned OCI artifact: the LinuxKit
//! `kernel` entry at an immutable manifest digest. `Kernel::custom` stores an
//! exact [`KernelVersion`] and canonical [`KernelConfig`] without starting
//! any I/O; compiling it requires a [`KernelCompiler`] adapter (see
//! [`materialize_with`]), so a plain `materialize` of a custom
//! specification returns `KernelError::CompilerUnavailable`.
//!
//! Custom compilation is a long-running, cached pre-launch operation. The
//! first supported custom-build backend is Windows/HCS; the compiler adapter
//! (`libs/jyth/src/build/kernel_compile.rs`) boots [`Kernel::default()`]
//! as its bootstrap kernel and a toolchain rootfs pinned by an immutable OCI
//! digest, so the bootstrap materialization path never recurses into the
//! compiler. Cache identity lives under `.jyth-v4` (cache generation 4):
//! kernel artifacts are keyed by source digest plus request shape, and
//! custom artifacts by the request digest derived from the canonical
//! version, configuration, and compiler identity.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: kernel.
//!
//! **Responsibility**: kernel specification and materialization.
//!
//! **Allowed dependencies**: image-core (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: VM launch, HCS state, guest commands, scheduling,
//! and boot handshake.

use std::path::PathBuf;

use bytes::Bytes;
use error_stack::Report;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use image_core::{
    Link,
    digest::ExpectedDigest,
    http_url::{HttpUrl, HttpUrlError},
    oci_reference::OciReference,
    storage::file_ref::FileRef,
};

pub(crate) mod cache_lock;
pub mod compiler;
pub(crate) mod ops;
pub(crate) mod service;
pub(crate) mod source_catalog;
pub mod spec;

pub use compiler::{CompiledKernel, KernelCompiler, KernelCompilerError, KernelCompilerIdentity};
pub use spec::config::{KernelConfig, KernelConfigError, KernelConfigMode};
pub use spec::path::{KernelPath, KernelPathError};
pub use spec::version::{KernelVersion, KernelVersionError};

use crate::service::{KernelService, change_kernel};

// ---------------------------------------------------------------------------
// Default kernel specification
// ---------------------------------------------------------------------------

/// The pinned default kernel OCI reference: LinuxKit `kernel` 6.6.13 at its
/// immutable manifest digest. Changing the default requires an explicit
/// source change, test update, and release note.
pub const DEFAULT_KERNEL_OCI_REFERENCE: &str = "registry-1.docker.io/linuxkit/kernel@sha256:cde6f94fa4b0db36db2d191e27fc65825d0c6b0006aca6956d5af5b8ad68fec0";

/// The kernel entry path inside the default LinuxKit OCI artifact.
pub const DEFAULT_KERNEL_ENTRY_PATH: &str = "kernel";

// ---------------------------------------------------------------------------
// Opaque facade
// ---------------------------------------------------------------------------

/// A validated kernel specification.
///
/// The type is opaque: the private [`KernelKind`] value is only reachable
/// through the associated constructors, so an invalid pairing of a raw source
/// with an archive path is unrepresentable.
#[derive(Debug, Clone)]
pub struct Kernel {
    kind: KernelKind,
}

/// The private kernel specification model.
#[derive(Debug, Clone)]
enum KernelKind {
    /// The single pinned default OCI artifact ([`DEFAULT_KERNEL_OCI_REFERENCE`]
    /// with the [`DEFAULT_KERNEL_ENTRY_PATH`] entry).
    Default,
    /// A custom compilation request, compiled through the [`KernelCompiler`]
    /// port by [`materialize_with`].
    Custom(CustomKernelSpec),
    /// An external raw or archive source.
    External(ExternalKernelSpec),
}

/// An external raw or archive kernel source.
#[derive(Debug, Clone)]
enum ExternalKernelSpec {
    /// A raw kernel input without a kernel-entry path.
    Raw { source: KernelSource },
    /// An archive input carrying one validated kernel-entry path.
    Archive {
        source: KernelSource,
        kernel_path: KernelPath,
    },
}

/// The validated external source behind a kernel request.
#[derive(Debug, Clone)]
enum KernelSource {
    /// A local host path (validated asynchronously by the resolver).
    Local(PathBuf),
    /// A validated HTTP(S) URL.
    Http(HttpUrl),
    /// A validated OCI image reference (always treated as an archive).
    Image(OciReference),
    /// Bytes already held by the caller.
    Bytes(Bytes),
}

impl Default for Kernel {
    /// The pinned default kernel. Performs no I/O.
    fn default() -> Self {
        Self {
            kind: KernelKind::Default,
        }
    }
}

impl Kernel {
    /// Construct a custom kernel request for an exact `version` with the
    /// canonical [`KernelConfig::default()`] fragment.
    ///
    /// The version is validated synchronously; no network or filesystem I/O
    /// starts here.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::custom("7.1.7")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn custom(version: impl AsRef<str>) -> Result<Self, KernelSpecError> {
        Ok(CustomKernelSpec::new(version)?.into())
    }

    /// Construct a custom kernel request for an exact `version` with an
    /// explicit [`KernelConfig`].
    ///
    /// ```rust
    /// use kernel::{Kernel, KernelConfig};
    /// let kernel = Kernel::custom_with_config("7.1.7", KernelConfig::default())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn custom_with_config(
        version: impl AsRef<str>,
        config: KernelConfig,
    ) -> Result<Self, KernelSpecError> {
        Ok(CustomKernelSpec::with_config(version, config)?.into())
    }

    /// Construct a custom kernel request for an exact `version` from an
    /// explicit source pin: a canonical source URL and the expected SHA-256
    /// digest of the archive. This is the escape hatch for versions absent
    /// from the embedded catalog.
    ///
    /// All three values are validated synchronously; no filesystem, network,
    /// or cache I/O starts here.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::custom_pinned(
    ///     "7.1.7",
    ///     "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
    ///     "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn custom_pinned(
        version: impl AsRef<str>,
        source_url: impl AsRef<str>,
        expected_sha256: impl AsRef<str>,
    ) -> Result<Self, KernelSpecError> {
        Self::custom_pinned_with_config(
            version,
            source_url,
            expected_sha256,
            KernelConfig::default(),
        )
    }

    /// Like [`Kernel::custom_pinned`], with an explicit [`KernelConfig`].
    ///
    /// ```rust
    /// use kernel::{Kernel, KernelConfig};
    /// let kernel = Kernel::custom_pinned_with_config(
    ///     "7.1.7",
    ///     "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
    ///     "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
    ///     KernelConfig::default(),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn custom_pinned_with_config(
        version: impl AsRef<str>,
        source_url: impl AsRef<str>,
        expected_sha256: impl AsRef<str>,
        config: KernelConfig,
    ) -> Result<Self, KernelSpecError> {
        let version = KernelVersion::parse(version.as_ref())?;
        let url = HttpUrl::parse(source_url.as_ref())?;
        if url.scheme() != "https" {
            return Err(KernelSpecError::InvalidSourceUrl(
                "pinned source URLs must use https".to_string(),
            ));
        }
        let digest = ExpectedDigest::parse(&format!("sha256:{}", expected_sha256.as_ref()))
            .map_err(|_| {
                KernelSpecError::InvalidSourceDigest(
                    "expected SHA-256 must be 64 hexadecimal characters".to_string(),
                )
            })?;
        let pin = KernelSourcePin::new(version, url, digest)?;
        Ok(Self {
            kind: KernelKind::Custom(CustomKernelSpec::from_pin_with_config(pin, config)),
        })
    }

    /// Construct a raw kernel from a local host path. Existence,
    /// permissions, and file-type checks are deferred to asynchronous
    /// materialization.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::local("./vmlinuz");
    /// ```
    pub fn local(path: impl Into<PathBuf>) -> Self {
        Self {
            kind: KernelKind::External(ExternalKernelSpec::Raw {
                source: KernelSource::Local(path.into()),
            }),
        }
    }

    /// Construct an archive kernel from a local host path and a validated
    /// kernel entry inside that archive.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::local_archive("./kernel.cpio", "boot/vmlinuz")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn local_archive(
        path: impl Into<PathBuf>,
        kernel_path: impl AsRef<str>,
    ) -> Result<Self, KernelSpecError> {
        Ok(Self {
            kind: KernelKind::External(ExternalKernelSpec::Archive {
                source: KernelSource::Local(path.into()),
                kernel_path: KernelPath::parse(kernel_path.as_ref())?,
            }),
        })
    }

    /// Construct a raw kernel from a validated HTTP(S) URL.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::http("https://example.com/vmlinuz")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn http(url: impl AsRef<str>) -> Result<Self, KernelSpecError> {
        Ok(Self {
            kind: KernelKind::External(ExternalKernelSpec::Raw {
                source: KernelSource::Http(HttpUrl::parse(url.as_ref())?),
            }),
        })
    }

    /// Construct an archive kernel from a validated HTTP(S) URL and a
    /// validated kernel entry inside that archive.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::http_archive("https://example.com/kernel.cpio", "boot/vmlinuz")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn http_archive(
        url: impl AsRef<str>,
        kernel_path: impl AsRef<str>,
    ) -> Result<Self, KernelSpecError> {
        Ok(Self {
            kind: KernelKind::External(ExternalKernelSpec::Archive {
                source: KernelSource::Http(HttpUrl::parse(url.as_ref())?),
                kernel_path: KernelPath::parse(kernel_path.as_ref())?,
            }),
        })
    }

    /// Construct an archive kernel from a validated OCI image reference and
    /// a validated kernel entry inside that image's rootfs.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::image("ubuntu:24.04", "boot/vmlinuz")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn image(
        reference: impl AsRef<str>,
        kernel_path: impl AsRef<str>,
    ) -> Result<Self, KernelSpecError> {
        Ok(Self {
            kind: KernelKind::External(ExternalKernelSpec::Archive {
                source: KernelSource::Image(OciReference::parse(reference.as_ref())?),
                kernel_path: KernelPath::parse(kernel_path.as_ref())?,
            }),
        })
    }

    /// Construct a raw kernel from bytes already held by the caller.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::bytes(vec![0x55, 0xaa]);
    /// ```
    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            kind: KernelKind::External(ExternalKernelSpec::Raw {
                source: KernelSource::Bytes(bytes.into()),
            }),
        }
    }

    /// Construct an archive kernel from bytes already held by the caller and
    /// a validated kernel entry inside that archive.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// let kernel = Kernel::bytes_archive(vec![0x30, 0x37], "boot/vmlinuz")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bytes_archive(
        bytes: impl Into<Bytes>,
        kernel_path: impl AsRef<str>,
    ) -> Result<Self, KernelSpecError> {
        Ok(Self {
            kind: KernelKind::External(ExternalKernelSpec::Archive {
                source: KernelSource::Bytes(bytes.into()),
                kernel_path: KernelPath::parse(kernel_path.as_ref())?,
            }),
        })
    }

    /// Construct a raw kernel from static bytes without copying:
    /// [`Bytes::from_static`] shares the compiled-in buffer.
    ///
    /// ```rust
    /// use kernel::Kernel;
    /// static VMLINUZ: &[u8] = b"vmlinuz bytes";
    /// let kernel = Kernel::embedded(VMLINUZ);
    /// ```
    pub fn embedded(bytes: &'static [u8]) -> Self {
        Self {
            kind: KernelKind::External(ExternalKernelSpec::Raw {
                source: KernelSource::Bytes(Bytes::from_static(bytes)),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Custom kernel specification
// ---------------------------------------------------------------------------

/// An immutable, reviewed kernel source pin: an exact version, a canonical
/// HTTPS URL, and the expected SHA-256 digest of the archive.
///
/// The pin is the content identity of a cacheable custom build: the v2 custom
/// request digest includes the source URL and digest, so a source change can
/// never alias a cached artifact compiled from different bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelSourcePin {
    version: KernelVersion,
    url: HttpUrl,
    digest: ExpectedDigest,
}

impl KernelSourcePin {
    /// Construct a pin for `version` at `url` with the expected `digest`.
    ///
    /// The digest must be a SHA-256 (64 hexadecimal characters); any other
    /// algorithm or length is rejected synchronously. Performs no filesystem,
    /// network, or cache I/O.
    pub fn new(
        version: KernelVersion,
        url: HttpUrl,
        digest: ExpectedDigest,
    ) -> Result<Self, KernelSpecError> {
        match digest {
            ExpectedDigest::Sha256(_) => {}
            _ => {
                return Err(KernelSpecError::InvalidSourceDigest(
                    "kernel source pins require a SHA-256 digest".to_string(),
                ));
            }
        }
        Ok(Self {
            version,
            url,
            digest,
        })
    }

    /// The exact kernel version.
    pub fn version(&self) -> &KernelVersion {
        &self.version
    }

    /// The canonical source URL.
    pub fn url(&self) -> &HttpUrl {
        &self.url
    }

    /// The expected SHA-256 digest of the archive bytes.
    pub fn digest(&self) -> &ExpectedDigest {
        &self.digest
    }
}

/// A custom kernel compilation request: an exact [`KernelVersion`], a
/// canonical [`KernelConfig`], and the immutable [`KernelSourcePin`] the
/// compiler must download and verify.
#[derive(Clone)]
pub struct CustomKernelSpec {
    source: KernelSourcePin,
    config: KernelConfig,
}

impl CustomKernelSpec {
    /// Construct a specification for the catalogued `version` with
    /// [`KernelConfig::default()`]. An uncatalogued version returns
    /// [`KernelSpecError::UnpinnedVersion`] before any network or cache I/O.
    pub fn new(version: impl AsRef<str>) -> Result<Self, KernelSpecError> {
        Self::with_config(version, KernelConfig::default())
    }

    /// Construct a specification for the catalogued `version` with an explicit
    /// configuration. An uncatalogued version returns
    /// [`KernelSpecError::UnpinnedVersion`] before any network or cache I/O.
    pub fn with_config(
        version: impl AsRef<str>,
        config: KernelConfig,
    ) -> Result<Self, KernelSpecError> {
        let version = KernelVersion::parse(version.as_ref())?;
        let source = source_catalog::get(&version)
            .ok_or_else(|| KernelSpecError::UnpinnedVersion(version.as_str().to_string()))?;
        Ok(Self {
            source: source.clone(),
            config,
        })
    }

    /// Construct a specification from an explicit source pin and configuration.
    pub(crate) fn from_pin_with_config(source: KernelSourcePin, config: KernelConfig) -> Self {
        Self { source, config }
    }

    /// The exact kernel version.
    pub fn version(&self) -> &KernelVersion {
        self.source.version()
    }

    /// The immutable source pin (version, URL, and expected digest).
    pub fn source(&self) -> &KernelSourcePin {
        &self.source
    }

    /// The canonical kernel configuration.
    pub fn config(&self) -> &KernelConfig {
        &self.config
    }
}

/// `Debug` redacts the configuration bytes and only reveals the version and
/// the configuration mode.
impl std::fmt::Debug for CustomKernelSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomKernelSpec")
            .field("version", self.version())
            .field("config_mode", &self.config.mode())
            .finish()
    }
}

impl From<CustomKernelSpec> for Kernel {
    fn from(spec: CustomKernelSpec) -> Self {
        Self {
            kind: KernelKind::Custom(spec),
        }
    }
}

// ---------------------------------------------------------------------------
// Construction errors
// ---------------------------------------------------------------------------

/// A validated textual kernel specification could not be constructed.
///
/// Constructors return this error before any network or filesystem operation
/// starts. Every variant names the invalid field; the nested error carries
/// the stable reason category. No variant carries configuration bytes or
/// sensitive URL components.
#[derive(Debug, Error)]
pub enum KernelSpecError {
    /// The kernel version is malformed.
    #[error("invalid kernel version: {0}")]
    InvalidVersion(#[source] KernelVersionError),
    /// The HTTP URL is malformed or rejected by the URL contract.
    #[error("invalid HTTP URL: {0}")]
    InvalidHttpUrl(#[source] HttpUrlError),
    /// The OCI reference is malformed or rejected by the reference grammar.
    #[error("invalid OCI reference: {0}")]
    InvalidOciReference(#[source] image_core::OciReferenceError),
    /// The kernel entry path is malformed or unsafe.
    #[error("invalid kernel entry path: {0}")]
    InvalidKernelPath(#[source] KernelPathError),
    /// The version is not pinned in the embedded source catalog.
    #[error("kernel version {0} is not pinned in the embedded source catalog")]
    UnpinnedVersion(String),
    /// The expected source digest is invalid (wrong algorithm or length).
    #[error("invalid kernel source digest: {0}")]
    InvalidSourceDigest(String),
    /// The source URL is rejected for a pinned or catalogued source.
    #[error("invalid kernel source URL: {0}")]
    InvalidSourceUrl(String),
    /// A catalog URL does not match its declared version.
    #[error("kernel source catalog mismatch: {0}")]
    SourceVersionMismatch(String),
    /// The embedded source catalog itself is malformed.
    #[error("invalid kernel source catalog: {0}")]
    InvalidSourceCatalog(String),
}

impl From<KernelVersionError> for KernelSpecError {
    fn from(error: KernelVersionError) -> Self {
        Self::InvalidVersion(error)
    }
}

impl From<HttpUrlError> for KernelSpecError {
    fn from(error: HttpUrlError) -> Self {
        Self::InvalidHttpUrl(error)
    }
}

impl From<image_core::OciReferenceError> for KernelSpecError {
    fn from(error: image_core::OciReferenceError) -> Self {
        Self::InvalidOciReference(error)
    }
}

impl From<KernelPathError> for KernelSpecError {
    fn from(error: KernelPathError) -> Self {
        Self::InvalidKernelPath(error)
    }
}

// ---------------------------------------------------------------------------
// Materialized kernel
// ---------------------------------------------------------------------------

/// A materialized kernel: the validated raw bzImage path and, when the
/// source carried one, the extracted loadable-module fragment.
#[derive(Debug)]
pub struct MaterializedKernel {
    /// Path of the validated raw Linux bzImage.
    pub kernel: PathBuf,
    /// Extracted module fragment (uncompressed CPIO), when the source
    /// contained a loadable module tree.
    pub modules: Option<FileRef>,
}

// ---------------------------------------------------------------------------
// Materialization errors
// ---------------------------------------------------------------------------

/// Failures returned while materializing a kernel specification.
#[derive(Debug, Error)]
pub enum KernelError {
    /// The kernel input could not be materialized: source acquisition,
    /// caching, normalization, extraction, or validation failed.
    #[error("could not materialize the kernel input")]
    Materialization,
    /// A compiled-in default or compiler identity is invalid.
    #[error("invalid built-in kernel specification")]
    InvalidBuiltInSpecification,
    /// A custom specification was passed without a compiler adapter.
    #[error("custom kernel compilation requires a compiler adapter")]
    CompilerUnavailable,
    /// A compiler adapter failed: planning, bootstrap launch, guest build,
    /// artifact transfer, validation, cleanup, or cache publication.
    #[error("custom kernel compilation failed")]
    Compilation,
}

// ---------------------------------------------------------------------------
// Materialization entry points
// ---------------------------------------------------------------------------

/// The highest kernel version in the embedded source catalog. The CLI
/// resolves its `latest` input from this reviewed catalog instead of a
/// mutable upstream version listing.
pub fn latest_catalog_version() -> Option<KernelVersion> {
    source_catalog::latest().map(|pin| pin.version().clone())
}

/// Whether `version` is pinned in the embedded source catalog.
pub fn is_catalogued(version: &KernelVersion) -> bool {
    source_catalog::get(version).is_some()
}

/// Materialize `kernel` through the default service (shared store plus
/// default source resolvers).
///
/// Supports default and external specifications. A custom specification
/// returns [`KernelError::CompilerUnavailable`] without starting any I/O;
/// compile custom kernels through [`materialize_with`].
pub async fn materialize(
    kernel: &Kernel,
    token: &CancellationToken,
) -> Result<MaterializedKernel, Report<KernelError>> {
    let service = KernelService::with_defaults().map_err(change_kernel)?;
    let plan = lower(&kernel.kind)?;
    service.build_external(plan, token).await
}

/// Materialize `kernel` through the default service with an explicit
/// compiler adapter.
///
/// Supports every specification: default and external kernels take the same
/// path as [`materialize`], and a custom specification is compiled through
/// the shared custom cache. The adapter is invoked only after a cache miss.
pub async fn materialize_with(
    kernel: &Kernel,
    compiler: &dyn KernelCompiler,
    token: &CancellationToken,
) -> Result<MaterializedKernel, Report<KernelError>> {
    let (materialized, _) = materialize_with_outcome(kernel, compiler, token).await?;
    Ok(materialized)
}

/// Like [`materialize_with`], but reports whether a custom kernel was served
/// from the cache. Default and external kernels report `false` (they never
/// use the compiler).
pub async fn materialize_with_outcome(
    kernel: &Kernel,
    compiler: &dyn KernelCompiler,
    token: &CancellationToken,
) -> Result<(MaterializedKernel, bool), Report<KernelError>> {
    let service = KernelService::with_defaults().map_err(change_kernel)?;
    match &kernel.kind {
        KernelKind::Custom(spec) => {
            service
                .build_custom_with_outcome(spec.clone(), compiler, token)
                .await
        }
        _ => {
            let plan = lower(&kernel.kind)?;
            let materialized = service.build_external(plan, token).await?;
            Ok((materialized, false))
        }
    }
}

/// The external kernel plan: one resolved source [`Link`] plus the optional
/// validated kernel entry path. A raw plan carries `None`; an archive plan
/// carries `Some(KernelPath)`. The service never infers archive intent from
/// an empty path.
#[derive(Debug, Clone)]
pub(crate) struct ExternalKernelPlan {
    pub(crate) link: Link,
    pub(crate) kernel_path: Option<KernelPath>,
}

/// Lower a public kernel kind into an [`ExternalKernelPlan`].
fn lower(kind: &KernelKind) -> Result<ExternalKernelPlan, Report<KernelError>> {
    match kind {
        KernelKind::Custom(_) => Err(Report::new(KernelError::CompilerUnavailable)),
        KernelKind::Default => {
            let reference = OciReference::parse(DEFAULT_KERNEL_OCI_REFERENCE).map_err(|error| {
                Report::new(KernelError::InvalidBuiltInSpecification).attach(error)
            })?;
            let path = KernelPath::parse(DEFAULT_KERNEL_ENTRY_PATH).map_err(|error| {
                Report::new(KernelError::InvalidBuiltInSpecification).attach(error)
            })?;
            Ok(ExternalKernelPlan {
                link: Link::image(reference.canonical()),
                kernel_path: Some(path),
            })
        }
        KernelKind::External(spec) => Ok(match spec {
            ExternalKernelSpec::Raw { source } => ExternalKernelPlan {
                link: lower_source(source),
                kernel_path: None,
            },
            ExternalKernelSpec::Archive {
                source,
                kernel_path,
            } => ExternalKernelPlan {
                link: lower_source(source),
                kernel_path: Some(kernel_path.clone()),
            },
        }),
    }
}

fn lower_source(source: &KernelSource) -> Link {
    match source {
        KernelSource::Local(path) => Link::local(path.clone()),
        KernelSource::Http(url) => Link::http(url.as_str()),
        KernelSource::Image(reference) => Link::image(reference.canonical()),
        KernelSource::Bytes(bytes) => Link::bytes(bytes.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_performs_no_io_and_lowers_to_the_pinned_reference() {
        let kernel = Kernel::default();
        let plan = lower(&kernel.kind).expect("default lowers");
        assert!(matches!(plan.link, Link::Image(_)));
        assert_eq!(
            plan.kernel_path.as_ref().expect("default path").as_str(),
            DEFAULT_KERNEL_ENTRY_PATH
        );
        assert!(DEFAULT_KERNEL_OCI_REFERENCE.contains("@sha256:"));
    }

    #[test]
    fn raw_constructors_do_not_accept_a_kernel_entry_path() {
        let local = Kernel::local("./vmlinuz");
        let http = Kernel::http("https://example.com/vmlinuz").expect("http");
        let bytes = Kernel::bytes(Bytes::from_static(b"bytes"));
        let embedded = Kernel::embedded(b"static");

        for kernel in [local, http, bytes, embedded] {
            let plan = lower(&kernel.kind).expect("raw lowers");
            assert!(plan.kernel_path.is_none(), "raw sources carry no path");
        }
    }

    #[test]
    fn archive_constructors_always_carry_a_validated_path() {
        let local = Kernel::local_archive("./kernel.cpio", "boot/vmlinuz").expect("local");
        let http =
            Kernel::http_archive("https://example.com/k.cpio", "./boot\\vmlinuz").expect("http");
        let bytes =
            Kernel::bytes_archive(Bytes::from_static(b"archive"), "boot/vmlinuz").expect("bytes");
        let image = Kernel::image("ubuntu:24.04", "boot/vmlinuz").expect("image");

        for kernel in [local, http, bytes, image] {
            let plan = lower(&kernel.kind).expect("archive lowers");
            assert_eq!(
                plan.kernel_path.as_ref().expect("path").as_str(),
                "boot/vmlinuz",
                "path normalized"
            );
        }
    }

    #[test]
    fn archive_constructors_reject_invalid_paths() {
        for bad in ["", "/abs", "..", "C:\\boot", "a//b", "a/../b"] {
            let err = Kernel::local_archive("./kernel.cpio", bad).expect_err("invalid path");
            assert!(
                matches!(err, KernelSpecError::InvalidKernelPath(_)),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn custom_constructors_validate_the_version() {
        let kernel = Kernel::custom("7.1.7").expect("valid");
        assert!(matches!(kernel.kind, KernelKind::Custom(_)));
        let err = Kernel::custom("latest").expect_err("latest rejected");
        assert!(matches!(err, KernelSpecError::InvalidVersion(_)));
        let err = Kernel::custom("7").expect_err("too few components");
        assert!(matches!(err, KernelSpecError::InvalidVersion(_)));
    }

    #[test]
    fn custom_rejects_versions_absent_from_the_embedded_catalog() {
        let err = Kernel::custom("6.6.13").expect_err("uncatalogued version");
        assert!(matches!(
            err,
            KernelSpecError::UnpinnedVersion(version) if version == "6.6.13"
        ));
        let err = CustomKernelSpec::new("6.6.13").expect_err("uncatalogued spec");
        assert!(matches!(err, KernelSpecError::UnpinnedVersion(_)));
    }

    #[test]
    fn custom_pinned_validates_all_three_values_synchronously() {
        let kernel = Kernel::custom_pinned(
            "7.1.7",
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
            "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
        )
        .expect("pinned kernel");
        let KernelKind::Custom(spec) = kernel.kind else {
            panic!("expected a custom kernel");
        };
        assert_eq!(spec.version().as_str(), "7.1.7");
        assert_eq!(spec.source().url().scheme(), "https");
        assert_eq!(spec.source().digest().digest_bytes().len(), 32);

        // A malformed digest is rejected synchronously.
        let err = Kernel::custom_pinned(
            "7.1.7",
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
            "not-a-digest",
        )
        .expect_err("bad digest");
        assert!(matches!(err, KernelSpecError::InvalidSourceDigest(_)));

        // A non-HTTPS URL is rejected synchronously.
        let err = Kernel::custom_pinned(
            "7.1.7",
            "http://example.com/linux-7.1.7.tar.xz",
            "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
        )
        .expect_err("non-https");
        assert!(matches!(err, KernelSpecError::InvalidSourceUrl(_)));

        // A malformed version is rejected synchronously.
        let err = Kernel::custom_pinned(
            "latest",
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.7.tar.xz",
            "ca8f2a6884a4d62043e9ab93ac1ab15efc2b6630fe8f768b2ef2ffdf4b5e26df",
        )
        .expect_err("bad version");
        assert!(matches!(err, KernelSpecError::InvalidVersion(_)));
    }

    #[test]
    fn custom_spec_exposes_the_immutable_source_pin() {
        let spec = CustomKernelSpec::new("7.1.7").expect("catalogued");
        assert_eq!(spec.version().as_str(), "7.1.7");
        assert_eq!(spec.source().version().as_str(), "7.1.7");
        assert!(spec.source().url().as_str().ends_with("linux-7.1.7.tar.xz"));
        assert_eq!(spec.source().digest().digest_bytes().len(), 32);
    }

    #[test]
    fn custom_uses_the_default_config_fragment() {
        let spec = CustomKernelSpec::new("7.1.7").expect("valid");
        assert_eq!(spec.version().as_str(), "7.1.7");
        assert_eq!(spec.config().mode(), KernelConfigMode::Fragment);
    }

    #[test]
    fn custom_with_config_preserves_the_explicit_config() {
        let config = KernelConfig::complete(b"CONFIG_A=y").expect("config");
        let spec = CustomKernelSpec::with_config("7.1.7", config.clone()).expect("valid");
        assert_eq!(spec.config().mode(), KernelConfigMode::Complete);
        assert_eq!(spec.config().as_bytes(), config.as_bytes());
    }

    #[test]
    fn http_constructors_validate_the_url() {
        let kernel = Kernel::http("https://example.com/vmlinuz").expect("valid");
        assert!(matches!(kernel.kind, KernelKind::External(_)));
        let err = Kernel::http("ftp://example.com/vmlinuz").expect_err("bad scheme");
        assert!(matches!(err, KernelSpecError::InvalidHttpUrl(_)));
        let err = Kernel::http("https://user:pass@example.com/vmlinuz").expect_err("credentials");
        assert!(matches!(err, KernelSpecError::InvalidHttpUrl(_)));
    }

    #[test]
    fn image_constructors_validate_the_reference_and_path() {
        let kernel = Kernel::image("ubuntu:24.04", "boot/vmlinuz").expect("valid");
        assert!(matches!(kernel.kind, KernelKind::External(_)));
        let err = Kernel::image("ftp://x/y", "boot/vmlinuz").expect_err("unsupported scheme");
        assert!(matches!(err, KernelSpecError::InvalidOciReference(_)));
    }

    #[test]
    fn debug_redacts_config_bytes_and_url_queries() {
        let spec = CustomKernelSpec::with_config("7.1.7", KernelConfig::default()).expect("spec");
        let debug = format!("{spec:?}");
        assert!(!debug.contains("CONFIG_"), "{debug}");
        assert!(debug.contains("7.1.7"), "{debug}");

        let kernel = Kernel::http("https://example.com/vmlinuz?sig=secret").expect("http");
        let debug = format!("{kernel:?}");
        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn embedded_uses_static_bytes_without_copy() {
        // `Bytes::from_static` borrows the input; the facade must not clone
        // it into a fresh allocation. The identity check proves the same
        // pointer range is referenced.
        static PAYLOAD: &[u8] = b"static kernel bytes";
        let kernel = Kernel::embedded(PAYLOAD);
        let KernelKind::External(ExternalKernelSpec::Raw {
            source: KernelSource::Bytes(bytes),
        }) = &kernel.kind
        else {
            panic!("expected raw bytes kernel");
        };
        assert_eq!(bytes.as_ref().as_ptr(), PAYLOAD.as_ptr());
        assert_eq!(bytes.len(), PAYLOAD.len());
    }

    #[test]
    fn materialize_rejects_custom_without_a_compiler() {
        let kernel = Kernel::custom("7.1.7").expect("custom");
        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(materialize(&kernel, &CancellationToken::new()))
            .expect_err("compiler unavailable");
        assert!(matches!(
            err.current_context(),
            KernelError::CompilerUnavailable
        ));
    }
}
