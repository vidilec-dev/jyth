//! Validated guest boot-artifact paths.
//!
//! The kernel and initrd artifacts are validated at the model boundary so
//! every consumer (runtime orchestration, backends) sees the same path
//! guarantees without re-validating caller-controlled values.

use std::path::{Path, PathBuf};

/// Why [`BootArtifacts`] could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootArtifactsError {
    /// A path is empty.
    Empty,
    /// A path is not absolute.
    NotAbsolute,
    /// The kernel and initrd resolve to the same path.
    KernelEqualsInitrd,
}

/// Validated absolute kernel and initrd paths for one guest boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootArtifacts {
    kernel: PathBuf,
    initrd: PathBuf,
}

impl BootArtifacts {
    /// Validate and wrap the kernel and initrd paths.
    pub fn new(kernel: PathBuf, initrd: PathBuf) -> Result<Self, BootArtifactsError> {
        if kernel.as_os_str().is_empty() || initrd.as_os_str().is_empty() {
            return Err(BootArtifactsError::Empty);
        }
        if !kernel.is_absolute() || !initrd.is_absolute() {
            return Err(BootArtifactsError::NotAbsolute);
        }
        if kernel == initrd {
            return Err(BootArtifactsError::KernelEqualsInitrd);
        }
        Ok(Self { kernel, initrd })
    }

    /// The validated absolute kernel path.
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }

    /// The validated absolute initrd path.
    pub fn initrd(&self) -> &Path {
        &self.initrd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_absolute_paths() {
        let artifacts = BootArtifacts::new(
            PathBuf::from(r"C:\run\kernel.bin"),
            PathBuf::from(r"C:\run\initrd.img"),
        )
        .expect("valid artifacts");
        assert_eq!(artifacts.kernel(), Path::new(r"C:\run\kernel.bin"));
        assert_eq!(artifacts.initrd(), Path::new(r"C:\run\initrd.img"));
    }

    #[test]
    fn rejects_empty_paths() {
        assert_eq!(
            BootArtifacts::new(PathBuf::new(), PathBuf::from(r"C:\run\initrd.img")).unwrap_err(),
            BootArtifactsError::Empty
        );
        assert_eq!(
            BootArtifacts::new(PathBuf::from(r"C:\run\kernel.bin"), PathBuf::new()).unwrap_err(),
            BootArtifactsError::Empty
        );
    }

    #[test]
    fn rejects_relative_paths() {
        assert_eq!(
            BootArtifacts::new(
                PathBuf::from("kernel.bin"),
                PathBuf::from(r"C:\run\initrd.img")
            )
            .unwrap_err(),
            BootArtifactsError::NotAbsolute
        );
        assert_eq!(
            BootArtifacts::new(
                PathBuf::from(r"C:\run\kernel.bin"),
                PathBuf::from("initrd.img")
            )
            .unwrap_err(),
            BootArtifactsError::NotAbsolute
        );
    }

    #[test]
    fn rejects_identical_kernel_and_initrd() {
        assert_eq!(
            BootArtifacts::new(
                PathBuf::from(r"C:\run\same.bin"),
                PathBuf::from(r"C:\run\same.bin")
            )
            .unwrap_err(),
            BootArtifactsError::KernelEqualsInitrd
        );
    }
}
