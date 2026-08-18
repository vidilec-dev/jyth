use error_stack::Report;
use std::path::Path;
use uuid::Uuid;

use crate::error::UnsupportedError;

/// Compile-only VM handle for hosts without a Jyth hypervisor backend.
pub struct Vm;

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
    ) -> Result<Self, Report<UnsupportedError>> {
        Err(Report::new(UnsupportedError))
    }

    /// Start a created VM (always reports unsupported).
    pub async fn start(&self) -> Result<(), Report<UnsupportedError>> {
        Err(Report::new(UnsupportedError))
    }

    /// Mark the VM published (no-op on the compile-only handle).
    pub fn mark_published(&self) -> Result<(), Report<UnsupportedError>> {
        Ok(())
    }

    /// Perform awaited cleanup (no-op on the compile-only handle).
    pub async fn close(self) -> Result<(), Report<UnsupportedError>> {
        Ok(())
    }

    /// Return the stable backend identifier (nil on the compile-only handle).
    pub fn uuid(&self) -> Uuid {
        Uuid::nil()
    }

    /// The compile-only fallback handle never attaches disks.
    pub fn attached_disks(&self) -> &[vm_model::disk::AttachedDisk] {
        &[]
    }
}

impl Drop for Vm {
    fn drop(&mut self) {}
}
