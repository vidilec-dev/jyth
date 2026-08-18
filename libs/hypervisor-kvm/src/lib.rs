//! Experimental Linux/KVM backend (compile-only for v0.1.0).
//!
//! KVM remains experimental and is not part of the Windows/HCS v0.1.0
//! release path. The crate keeps the backend name and typed error visible
//! while routing actual launch attempts through Jyth's platform gate and
//! the honest capability advertisement of [`hypervisor_api::VmFactory`].
//!
//! The factory advertises only implemented capabilities: this backend
//! implements none on the current release, so [`KvmFactory::capabilities`]
//! reports unavailable and [`KvmFactory::create`] returns a typed
//! unsupported result before any instance could be claimed (an unavailable
//! factory must never return a fake usable instance).
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: hypervisor-kvm.
//!
//! **Responsibility**: experimental Linux/KVM backend.
//!
//! **Allowed dependencies**: hypervisor-api, vm-model (enforced by
//! `tests/architecture`).
//!
//! **Forbidden concepts**: HCS behavior, fake successful instances,
//! nil-identity placeholders, and Jyth facade types.

use std::path::Path;

use error_stack::Report;
use hypervisor_api::{
    AttachedResource, BackendCapabilities, BackendError, BackendErrorCategory, CloseFuture,
    CreateFuture, PublishFuture, RetryDisposition, StartFuture, VmFactory, VmInstance,
    VmLaunchSpec,
};
use uuid::Uuid;

/// Error context for the Linux KVM backend.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KvmError {
    /// A guest VM mutex was poisoned.
    Mutex,
    /// The guest was already running (or not running) when start/stop was called.
    InvalidState,
    /// A KVM ioctl / loader / memory operation failed.
    Io,
    /// Guest memory is too small to hold the initrd + reserved boot region.
    MemoryTooSmall,
    /// The requested operation is not implemented on the KVM backend.
    Unsupported,
}

impl std::fmt::Display for KvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            KvmError::Mutex => "a guest VM mutex was poisoned",
            KvmError::InvalidState => "guest VM is in an invalid run state for this call",
            KvmError::Io => "a KVM/ioctl/loader memory operation failed",
            KvmError::MemoryTooSmall => {
                "guest memory too small for the initrd plus the reserved boot region"
            }
            KvmError::Unsupported => "operation not supported by the KVM backend",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for KvmError {}

/// The experimental KVM factory: advertises honest capabilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmFactory;

impl VmFactory for KvmFactory {
    fn capabilities(&self) -> BackendCapabilities {
        // KVM implements no v0.1 capability on this release; an unavailable
        // factory must never claim a usable instance.
        BackendCapabilities::unavailable()
    }

    fn create(&self, _spec: VmLaunchSpec) -> CreateFuture {
        Box::pin(async {
            Err(BackendError::new(
                BackendErrorCategory::Unavailable,
                RetryDisposition::Permanent,
                "KVM is experimental and is not part of the Windows/HCS v0.1.0 launch path",
            ))
        })
    }
}

/// Compile-only KVM handle retained for the experimental platform surface.
pub struct Vm;

impl Vm {
    /// The compile-only KVM handle never attaches disks.
    pub fn attached_disks(&self) -> &[AttachedResource] {
        &[]
    }
}

impl Drop for Vm {
    fn drop(&mut self) {}
}

/// The instance contract for the compile-only handle: every operation
/// reports the typed unsupported result.
impl VmInstance for Vm {
    fn identity(&self) -> Uuid {
        Uuid::nil()
    }

    fn attached_resources(&self) -> &[AttachedResource] {
        &[]
    }

    fn start(&self) -> StartFuture {
        Box::pin(async { Err(backend_unsupported()) })
    }

    fn mark_published(&self) -> PublishFuture {
        // Publication on an unavailable handle is a no-op success so the
        // facade's publication ordering never blocks on a backend that can
        // never run; no fake running instance is ever returned (create
        // fails first).
        Box::pin(async { Ok(()) })
    }

    fn close(self: Box<Self>) -> CloseFuture {
        Box::pin(async { Ok(()) })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn backend_unsupported() -> BackendError {
    BackendError::new(
        BackendErrorCategory::Unavailable,
        RetryDisposition::Permanent,
        "operation not supported by the KVM backend",
    )
}

/// Compatibility surface mirroring the former `IVm` shape: inherent methods
/// the hypervisor facade can forward to while consumers migrate.
impl Vm {
    /// Create a compile-only handle (always reports unsupported).
    pub async fn new(
        _kernel: &Path,
        _initrd: &Path,
        _mem: u64,
        _cpu: u32,
        _cmdline: &str,
        _network: Option<&vm_model::network::Nat>,
        _disks: Option<&[vm_model::disk::DiskSpec]>,
    ) -> Result<Self, Report<KvmError>> {
        Err(Report::new(KvmError::Unsupported)
            .attach("KVM is experimental and is not part of the Windows/HCS v0.1.0 launch path"))
    }

    /// Start a created VM (always reports unsupported).
    pub async fn start(&self) -> Result<(), Report<KvmError>> {
        Err(Report::new(KvmError::Unsupported))
    }

    /// Mark the VM published (no-op on the compile-only handle).
    pub fn mark_published(&self) -> Result<(), Report<KvmError>> {
        Ok(())
    }

    /// Perform awaited cleanup (no-op on the compile-only handle).
    pub async fn close(self) -> Result<(), Report<KvmError>> {
        Ok(())
    }

    /// Return the stable backend identifier (nil on the compile-only handle).
    pub fn uuid(&self) -> Uuid {
        Uuid::nil()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_advertises_no_implemented_capabilities() {
        let factory = KvmFactory;
        let capabilities = factory.capabilities();
        assert!(!capabilities.available);
        assert!(!capabilities.networking);
        assert!(!capabilities.disks);
    }

    #[test]
    fn factory_never_returns_a_fake_usable_instance() {
        let factory = KvmFactory;
        let spec = VmLaunchSpec {
            kernel: Path::new("/kernel").to_path_buf(),
            initrd: Path::new("/initrd").to_path_buf(),
            memory_mb: 512,
            vcpu_count: 1,
            cmdline: String::new(),
            network: None,
            disks: Vec::new(),
        };
        let result = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(factory.create(spec));
        let error = result
            .map(|_| ())
            .expect_err("unavailable factory must fail");
        assert_eq!(error.category, BackendErrorCategory::Unavailable);
        assert_eq!(error.retry, RetryDisposition::Permanent);
    }

    #[test]
    fn compat_handle_reports_unsupported_creation() {
        let result = tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(Vm::new(
                Path::new("/kernel"),
                Path::new("/initrd"),
                512,
                1,
                "",
                None,
                None,
            ));
        assert!(
            matches!(result, Err(report) if *report.current_context() == KvmError::Unsupported)
        );
    }
}
