//! The immutable validated VM configuration aggregate.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::cpu::Cpu;
use crate::disk::DiskSpec;
use crate::memory::Memory;
use crate::network::Nat;

/// Why an aggregated [`VmConfig`] could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmConfigError {
    /// The requested CPU count is zero.
    CpuZero,
    /// The requested memory is zero.
    MemoryZero,
    /// Two disks normalize to the same host path.
    DuplicateDiskHostPath,
    /// Two disks share one guest mount target.
    DuplicateGuestMount,
    /// The kernel and initrd paths resolve to the same file.
    DuplicateBootArtifactPath,
    /// A boot-artifact path is not absolute.
    RelativeBootArtifactPath,
    /// A boot-artifact path is empty.
    EmptyBootArtifactPath,
}

/// An immutable, validated host-neutral VM configuration.
///
/// Construction validates every invariant that can be decided without I/O:
/// positive CPU and memory, unique normalized disk host paths, unique guest
/// mount targets, and non-empty absolute boot-artifact paths. Backend-side
/// checks (for example that a disk parent directory exists) remain in the
/// layers that may perform I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmConfig {
    cpu: Cpu,
    memory: Memory,
    network: Option<Nat>,
    disks: Vec<DiskSpec>,
    kernel: PathBuf,
    initrd: PathBuf,
}

impl VmConfig {
    /// Construct a validated VM configuration.
    pub fn new(
        cpu: Cpu,
        memory: Memory,
        network: Option<Nat>,
        disks: Vec<DiskSpec>,
        kernel: PathBuf,
        initrd: PathBuf,
    ) -> Result<Self, VmConfigError> {
        if cpu.units() == 0 {
            return Err(VmConfigError::CpuZero);
        }
        if memory.mb() == 0 {
            return Err(VmConfigError::MemoryZero);
        }
        if kernel.as_os_str().is_empty() || initrd.as_os_str().is_empty() {
            return Err(VmConfigError::EmptyBootArtifactPath);
        }
        if !kernel.is_absolute() || !initrd.is_absolute() {
            return Err(VmConfigError::RelativeBootArtifactPath);
        }
        if kernel == initrd {
            return Err(VmConfigError::DuplicateBootArtifactPath);
        }

        let mut paths = HashSet::new();
        let mut mounts = HashSet::new();
        for disk in &disks {
            if !paths.insert(disk.normalized_host_path()) {
                return Err(VmConfigError::DuplicateDiskHostPath);
            }
            if !mounts.insert(disk.guest_mount().as_str().to_owned()) {
                return Err(VmConfigError::DuplicateGuestMount);
            }
        }

        Ok(Self {
            cpu,
            memory,
            network,
            disks,
            kernel,
            initrd,
        })
    }

    /// The validated CPU request.
    pub fn cpu(&self) -> Cpu {
        self.cpu
    }

    /// The validated memory request.
    pub fn memory(&self) -> Memory {
        self.memory
    }

    /// The optional validated NAT network.
    pub fn network(&self) -> Option<&Nat> {
        self.network.as_ref()
    }

    /// The validated disk specifications.
    pub fn disks(&self) -> &[DiskSpec] {
        &self.disks
    }

    /// The validated absolute kernel path.
    pub fn kernel(&self) -> &std::path::Path {
        &self.kernel
    }

    /// The validated absolute initrd path.
    pub fn initrd(&self) -> &std::path::Path {
        &self.initrd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::{DiskRetention, ExistingDiskPolicy, GuestMount};

    fn disk(host_path: &str, mount: &str) -> DiskSpec {
        DiskSpec::new(
            host_path,
            1024,
            GuestMount::new(mount).expect("valid mount"),
            DiskRetention::Ephemeral,
            ExistingDiskPolicy::ReuseAndKeep,
        )
        .expect("valid disk")
    }

    fn config() -> Result<VmConfig, VmConfigError> {
        VmConfig::new(
            Cpu::Units(2),
            Memory::MB(512),
            Some(Nat::default()),
            vec![],
            PathBuf::from(r"C:\run\kernel.bin"),
            PathBuf::from(r"C:\run\initrd.img"),
        )
    }

    #[test]
    fn accepts_a_valid_configuration() {
        let config = config().expect("valid config");
        assert_eq!(config.cpu(), Cpu::Units(2));
        assert_eq!(config.memory(), Memory::MB(512));
        assert!(config.network().is_some());
        assert!(config.disks().is_empty());
        assert_eq!(config.kernel(), std::path::Path::new(r"C:\run\kernel.bin"));
        assert_eq!(config.initrd(), std::path::Path::new(r"C:\run\initrd.img"));
    }

    #[test]
    fn rejects_zero_cpu_and_memory() {
        assert_eq!(
            VmConfig::new(
                Cpu::Units(0),
                Memory::MB(512),
                None,
                vec![],
                PathBuf::from(r"C:\run\kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::CpuZero
        );
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(0),
                None,
                vec![],
                PathBuf::from(r"C:\run\kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::MemoryZero
        );
    }

    #[test]
    fn rejects_duplicate_normalized_disk_host_paths() {
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(512),
                None,
                vec![
                    disk(r"C:\disks\..\disks\build.vhdx", "/build"),
                    disk(r"C:\disks\build.vhdx", "/data"),
                ],
                PathBuf::from(r"C:\run\kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::DuplicateDiskHostPath
        );
    }

    #[test]
    fn rejects_duplicate_guest_mount_targets() {
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(512),
                None,
                vec![
                    disk(r"C:\disks\one.vhdx", "/data"),
                    disk(r"C:\disks\two.vhdx", "/data"),
                ],
                PathBuf::from(r"C:\run\kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::DuplicateGuestMount
        );
    }

    #[test]
    fn rejects_relative_or_empty_boot_artifact_paths() {
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(512),
                None,
                vec![],
                PathBuf::from("kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::RelativeBootArtifactPath
        );
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(512),
                None,
                vec![],
                PathBuf::new(),
                PathBuf::from(r"C:\run\initrd.img"),
            )
            .unwrap_err(),
            VmConfigError::EmptyBootArtifactPath
        );
    }

    #[test]
    fn rejects_identical_kernel_and_initrd() {
        assert_eq!(
            VmConfig::new(
                Cpu::Units(1),
                Memory::MB(512),
                None,
                vec![],
                PathBuf::from(r"C:\run\artifact.bin"),
                PathBuf::from(r"C:\run\artifact.bin"),
            )
            .unwrap_err(),
            VmConfigError::DuplicateBootArtifactPath
        );
    }
}
