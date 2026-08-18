/// Error context for the Windows HCS (Host Compute Service) FFI boundary.
///
/// The HCS error type is owned by the `hypervisor-hcs` backend crate and
/// re-exported here for the compatibility facade.
#[cfg(target_os = "windows")]
pub use hypervisor_hcs::error::HcsError;

/// Error context for the Linux KVM backend.
///
/// The KVM error type is owned by the `hypervisor-kvm` backend crate and
/// re-exported here for the compatibility facade.
#[cfg(target_os = "linux")]
pub use hypervisor_kvm::KvmError;

/// Error returned by the compile-only fallback on hosts without a backend.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UnsupportedError;

impl std::fmt::Display for UnsupportedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host platform has no Jyth hypervisor backend")
    }
}

impl std::error::Error for UnsupportedError {}
