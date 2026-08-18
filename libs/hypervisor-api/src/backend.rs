//! Backend factory and instance contracts.

use std::path::PathBuf;

use uuid::Uuid;

use crate::{CloseFuture, CreateFuture, PublishFuture, StartFuture};

/// A validated host-neutral launch request handed to a [`VmFactory`].
///
/// All values are validated by `vm-model` before they reach the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLaunchSpec {
    /// Validated absolute kernel artifact path.
    pub kernel: PathBuf,
    /// Validated absolute initrd artifact path.
    pub initrd: PathBuf,
    /// Requested memory in megabytes.
    pub memory_mb: u64,
    /// Requested CPU count.
    pub vcpu_count: u32,
    /// Boot command line.
    pub cmdline: String,
    /// Optional validated NAT network.
    pub network: Option<vm_model::network::Nat>,
    /// Validated disk specifications.
    pub disks: Vec<vm_model::disk::DiskSpec>,
}

/// Capabilities a backend advertises before any instance is created.
///
/// A backend must advertise only implemented capabilities. An unavailable
/// backend returns a typed unsupported result before claiming a usable
/// instance; a backend may reject an unadvertised capability but may not
/// accept a capability and then substitute a placeholder result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Whether the backend can create and run instances on this host.
    pub available: bool,
    /// Whether NAT networking is implemented.
    pub networking: bool,
    /// Whether host-attached disks are implemented.
    pub disks: bool,
}

impl BackendCapabilities {
    /// A backend with no implemented capabilities (compile-only fallback).
    pub fn unavailable() -> Self {
        Self {
            available: false,
            networking: false,
            disks: false,
        }
    }
}

/// Typed backend information used by retry policy.
///
/// Replaces high-level matching on backend error strings: the backend
/// classifies whether a failed operation is worth retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    /// The failure is transient and the operation may be retried.
    Retryable,
    /// The failure is permanent and must not be retried.
    Permanent,
}

/// Stable categories for backend failures crossing the contract boundary.
///
/// The consuming service translates this category exactly once into its own
/// use-case error; no high-level crate parses an adapter error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorCategory {
    /// The backend is not available on this host.
    Unavailable,
    /// Capability validation failed (an unadvertised capability was
    /// requested, or the launch spec violates backend constraints).
    Capability,
    /// Creating the compute system failed.
    Create,
    /// Starting the compute system failed.
    Start,
    /// Publication failed (occurred before authenticated READY).
    Publication,
    /// Closing/cleanup failed; every incomplete cleanup action is reported.
    Close,
    /// The failure is otherwise classified as transient (see
    /// [`RetryDisposition`]).
    Transient,
}

/// A stable backend report crossing the contract boundary.
///
/// The category is the decision surface; attached text is diagnostics only
/// and must never be inspected for control flow by a high-level crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError {
    /// The stable category.
    pub category: BackendErrorCategory,
    /// Whether the operation may be retried.
    pub retry: RetryDisposition,
    /// Human-readable diagnostics (never parsed by consumers).
    pub message: String,
}

impl BackendError {
    /// Build a backend error from its stable parts.
    pub fn new(
        category: BackendErrorCategory,
        retry: RetryDisposition,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            retry,
            message: message.into(),
        }
    }

    /// A retryable failure with the given category and diagnostics.
    pub fn retryable(category: BackendErrorCategory, message: impl Into<String>) -> Self {
        Self::new(category, RetryDisposition::Retryable, message)
    }

    /// A permanent failure with the given category and diagnostics.
    pub fn permanent(category: BackendErrorCategory, message: impl Into<String>) -> Self {
        Self::new(category, RetryDisposition::Permanent, message)
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BackendError {}

/// A resource attached to a running instance, with its classified lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedResource {
    /// Absolute host-side path of the backing resource.
    pub host_path: PathBuf,
    /// Whether the resource was created by this launch.
    pub created_by_launch: bool,
}

/// The creation and capability contract (object-safe).
///
/// Creation returns one uniquely identified, owned instance, or a typed
/// failure that leaves no untracked owned resource behind.
pub trait VmFactory: Send + Sync + 'static {
    /// Advertise implemented capabilities before any instance is created.
    fn capabilities(&self) -> BackendCapabilities;

    /// Create one owned instance from a validated launch spec.
    fn create(&self, spec: VmLaunchSpec) -> CreateFuture;
}

/// The started-instance lifecycle contract (object-safe).
///
/// Operations follow the create, start, publish, close lifecycle: start
/// creates a running instance; publication follows authenticated READY;
/// consuming close completes exact cleanup. Drop retains synchronous
/// best-effort behavior for an unconsumed instance.
pub trait VmInstance: Send + Sync + 'static {
    /// The stable backend identifier for this instance.
    fn identity(&self) -> Uuid;

    /// Evidence of resources attached to this instance (empty when none).
    fn attached_resources(&self) -> &[AttachedResource];

    /// Start a created instance.
    fn start(&self) -> StartFuture;

    /// Mark the instance published only after its authenticated READY
    /// handshake succeeds.
    fn mark_published(&self) -> PublishFuture;

    /// Consume the instance and perform exact, awaited cleanup.
    ///
    /// The consuming boxed receiver guarantees successful awaited cleanup
    /// cannot be called twice.
    fn close(self: Box<Self>) -> CloseFuture;

    /// Downcast access to the concrete instance.
    ///
    /// Companion ports (e.g. a boot-control channel that must reach the
    /// backend's protected boot pipe) receive the instance as
    /// `&dyn VmInstance`; an adapter that owns the concrete type recovers
    /// it through `as_any().downcast_ref::<T>()`. Implementations return
    /// `self`.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Create the boxed future returned by [`VmFactory::create`] from an async
/// block, keeping the contract boundary explicit.
pub fn create_future<F>(future: F) -> CreateFuture
where
    F: std::future::Future<Output = Result<Box<dyn VmInstance>, BackendError>> + Send + 'static,
{
    Box::pin(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;

    struct FakeInstance {
        identity: Uuid,
    }

    impl VmInstance for FakeInstance {
        fn identity(&self) -> Uuid {
            self.identity
        }

        fn attached_resources(&self) -> &[AttachedResource] {
            &[]
        }

        fn start(&self) -> StartFuture {
            Box::pin(async { Ok(()) })
        }

        fn mark_published(&self) -> PublishFuture {
            Box::pin(async { Ok(()) })
        }

        fn close(self: Box<Self>) -> CloseFuture {
            Box::pin(async { Ok(()) })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct FakeFactory;

    impl VmFactory for FakeFactory {
        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                available: true,
                networking: true,
                disks: true,
            }
        }

        fn create(&self, _spec: VmLaunchSpec) -> CreateFuture {
            create_future(Box::pin(async {
                Ok(Box::new(FakeInstance {
                    identity: Uuid::new_v4(),
                }) as Box<dyn VmInstance>)
            }))
        }
    }

    #[test]
    fn fake_factory_returns_an_owned_instance() {
        let factory = FakeFactory;
        assert!(factory.capabilities().available);
        let spec = VmLaunchSpec {
            kernel: PathBuf::from(r"C:\run\kernel.bin"),
            initrd: PathBuf::from(r"C:\run\initrd.img"),
            memory_mb: 512,
            vcpu_count: 2,
            cmdline: "console=ttyS0".to_owned(),
            network: None,
            disks: Vec::new(),
        };
        let instance = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(factory.create(spec))
            .expect("fake creation succeeds");
        assert_ne!(instance.identity(), Uuid::nil());
        assert!(instance.attached_resources().is_empty());
    }

    #[test]
    fn fake_instance_close_is_consuming() {
        let instance = Box::new(FakeInstance {
            identity: Uuid::new_v4(),
        }) as Box<dyn VmInstance>;
        let result = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(instance.close());
        assert!(result.is_ok());
    }

    #[test]
    fn backend_error_carries_stable_category_and_retry() {
        let error = BackendError::retryable(
            BackendErrorCategory::Transient,
            "Insufficient system resources exist to complete the requested service",
        );
        assert_eq!(error.category, BackendErrorCategory::Transient);
        assert_eq!(error.retry, RetryDisposition::Retryable);
        // Consumers must be able to decide on the category alone.
        let retry = match error.retry {
            RetryDisposition::Retryable => true,
            RetryDisposition::Permanent => false,
        };
        assert!(retry);
    }

    #[test]
    fn unavailable_capabilities_are_honest() {
        let capabilities = BackendCapabilities::unavailable();
        assert!(!capabilities.available);
        assert!(!capabilities.networking);
        assert!(!capabilities.disks);
    }

    #[test]
    fn typed_future_helpers_compile_at_the_boundary() {
        // Prove the object-safe boundary is usable from a generic adapter.
        fn make_future()
        -> Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'static>>
        {
            Box::pin(async { Ok(()) })
        }
        let future = make_future();
        let result = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(future);
        assert!(result.is_ok());
    }
}
