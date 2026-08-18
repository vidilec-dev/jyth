//! Completion-timing telemetry for the acquisition pipeline.
//!
//! [`OpTimer`] records the start time of an operation and emits ONE
//! `tracing` event on drop, so every acquisition step reports its completion
//! duration plus the attributes the caller attached (source kind, cache
//! outcome, namespace, byte count, failure summary). Events are emitted at
//! `tracing::info!` under the `jyth::timing` target: processes without a
//! subscriber only pay the dispatch check, while evidence runs (e.g. the e2e
//! kernel-builder harness with an info-level fmt subscriber) print them to
//! stderr.
//!
//! The module is deliberately NOT gated on the `profiling` feature: it is
//! always compiled so per-operation timing and cache hit/miss/invalidation
//! observability exist in every build.
//!
//! # Field conventions
//!
//! * `operation` — one of `load`, `blueprint`, `store.read`, `layer.load`,
//!   `layers.blueprint`, `layers.materialize`, `layers.normalize`,
//!   `kernel.materialize`, `kernel.resolve`, `kernel.layers`,
//!   `kernel.extract`, `kernel.modules`, `rootfs.materialize`,
//!   `rootfs.resolve`, `rootfs.layers`, `rootfs.validate`, `rootfs.merge`,
//!   or the dedicated `cache.invalidated` warning.
//! * `namespace` — `kernel` | `rootfs` | `layers` | `modules` | `blueprint`.
//! * `duration_ms` — completion duration in milliseconds (f64).

use crate::artifact::link::ArtifactLink;
use crate::link::Link;
use crate::storage::namespace::Namespace;

/// The source kind being materialized, for timing attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A local filesystem path.
    Local,
    /// Bytes already held in memory.
    Bytes,
    /// An HTTP(S) URL.
    Http,
    /// An OCI image reference.
    Oci,
}

/// What the store lookup produced for a cache read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    /// The lookup is not a cache probe (pure computation).
    NotApplicable,
    /// The cache record was present and its backing bytes valid.
    Hit,
    /// The cache record was absent or its backing bytes stale.
    Miss,
    /// A stale record was invalidated (see the `cache.invalidated` event).
    Invalidated,
    /// The probe could not decide (transient IO error); no state changed.
    Indeterminate,
}

/// Maximum length of the failure summary attached by [`OpTimer::fail`].
const MAX_ERROR_SUMMARY_CHARS: usize = 400;

/// Completion timer: records the start time and emits ONE tracing event on
/// drop. Emitted fields: `operation`, `duration_ms`, and the optional
/// `source`/`cache`/`namespace`/`bytes`/`error` attributes the caller
/// attached.
pub struct OpTimer {
    #[cfg(feature = "tracing")]
    operation: &'static str,
    #[cfg(feature = "tracing")]
    started: std::time::Instant,
    source: Option<SourceKind>,
    cache: Option<CacheOutcome>,
    namespace: Option<&'static str>,
    bytes: Option<u64>,
    error: Option<String>,
}

impl OpTimer {
    #[cfg(feature = "tracing")]
    /// Start a completion timer for `operation`.
    pub fn start(operation: &'static str) -> Self {
        Self {
            operation,
            started: std::time::Instant::now(),
            source: None,
            cache: None,
            namespace: None,
            bytes: None,
            error: None,
        }
    }
    #[cfg(not(feature = "tracing"))]
    /// Start a completion timer for `operation`.
    pub fn start(_operation: &'static str) -> Self {
        Self {
            source: None,
            cache: None,
            namespace: None,
            bytes: None,
            error: None,
        }
    }

    /// Attach the materialized source kind.
    pub fn source(mut self, source: SourceKind) -> Self {
        self.source = Some(source);
        self
    }

    /// Attach the cache-read outcome.
    pub fn cache(mut self, cache: CacheOutcome) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Attach the namespace tag (one of `kernel` | `rootfs` | `layers` |
    /// `modules` | `blueprint`).
    pub fn namespace(mut self, namespace: &'static str) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Attach the final byte count of the materialized artifact.
    pub fn bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    /// Records a failure summary (e.g. `format!("{report:#}")` truncated to
    /// ~400 chars) so the completion event reports why the operation failed.
    pub fn fail(mut self, summary: impl Into<String>) -> Self {
        let summary = summary.into();
        self.error = Some(if summary.len() > MAX_ERROR_SUMMARY_CHARS {
            summary.chars().take(MAX_ERROR_SUMMARY_CHARS).collect()
        } else {
            summary
        });
        self
    }
}

impl Drop for OpTimer {
    fn drop(&mut self) {
        #[cfg(feature = "tracing")]
        tracing::info!(
            target: "jyth::timing",
            operation = self.operation,
            duration_ms = self.started.elapsed().as_secs_f64() * 1000.0,
            source = ?self.source,
            cache = ?self.cache,
            namespace = ?self.namespace,
            bytes = ?self.bytes,
            error = ?self.error.as_deref(),
        );
    }
}

impl From<&Link> for SourceKind {
    fn from(link: &Link) -> Self {
        match link {
            Link::Local(_) => SourceKind::Local,
            Link::Bytes(_) => SourceKind::Bytes,
            Link::Http(_) => SourceKind::Http,
            Link::Image(_) => SourceKind::Oci,
        }
    }
}

impl From<&ArtifactLink> for SourceKind {
    fn from(link: &ArtifactLink) -> Self {
        match link {
            ArtifactLink::Local(..) => SourceKind::Local,
            ArtifactLink::Bytes(..) => SourceKind::Bytes,
            ArtifactLink::Http(..) => SourceKind::Http,
        }
    }
}

/// Static namespace tag for a storage [`Namespace`], used as the `namespace`
/// field of timing events.
pub fn namespace_tag(namespace: Namespace) -> &'static str {
    match namespace {
        Namespace::Kernel => "kernel",
        Namespace::Rootfs => "rootfs",
        Namespace::Layers => "layers",
        Namespace::Modules => "modules",
    }
}
