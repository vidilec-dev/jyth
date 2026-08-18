//! Host-platform policy for the Jyth release boundary.
//!
//! The image crate remains host-neutral and can materialize Linux artifacts
//! independently. The Jyth facade applies the release policy before image
//! acquisition or VM construction: Windows/HCS is supported for `v0.1.0`,
//! while Linux/KVM remains experimental.

use error_stack::Report;

use crate::error::{ApiError, ApiResult};

/// Host/backend combinations recognized by Jyth's support matrix.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HostPlatform {
    /// Windows with the Host Compute Service backend.
    WindowsHcs,
    /// Linux with the experimental KVM backend.
    LinuxKvm,
    /// A host operating system without a Jyth backend.
    Other(&'static str),
}

impl HostPlatform {
    /// Detect the target host platform at compile time.
    pub const fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsHcs
        }
        #[cfg(target_os = "linux")]
        {
            Self::LinuxKvm
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Self::Other(std::env::consts::OS)
        }
    }

    /// Return the release status recorded in [`SUPPORT_MATRIX`].
    pub const fn support(self) -> PlatformSupport {
        match self {
            Self::WindowsHcs => PlatformSupport::Supported,
            Self::LinuxKvm => PlatformSupport::Experimental,
            Self::Other(_) => PlatformSupport::Unsupported,
        }
    }

    /// Return the backend name associated with this host, if any.
    pub const fn backend(self) -> &'static str {
        match self {
            Self::WindowsHcs => "HCS",
            Self::LinuxKvm => "KVM",
            Self::Other(_) => "none",
        }
    }
}

impl std::fmt::Display for HostPlatform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowsHcs => formatter.write_str("Windows/HCS"),
            Self::LinuxKvm => formatter.write_str("Linux/KVM"),
            Self::Other(os) => formatter.write_str(os),
        }
    }
}

/// Release status for a host/backend combination.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PlatformSupport {
    /// Covered by the `v0.1.0` release contract.
    Supported,
    /// Compiles and remains visible for development, but is not a release
    /// launch path.
    Experimental,
    /// No backend is available for the host.
    Unsupported,
}

impl std::fmt::Display for PlatformSupport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Supported => "supported",
            Self::Experimental => "experimental",
            Self::Unsupported => "unsupported",
        };
        formatter.write_str(label)
    }
}

/// One row in Jyth's public host/backend support matrix.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PlatformInfo {
    /// Host/backend combination described by the row.
    pub host: HostPlatform,
    /// Backend name shown to users.
    pub backend: &'static str,
    /// Release status of the combination.
    pub support: PlatformSupport,
}

/// The support matrix for the current release boundary.
pub const SUPPORT_MATRIX: &[PlatformInfo] = &[
    PlatformInfo {
        host: HostPlatform::WindowsHcs,
        backend: "HCS",
        support: PlatformSupport::Supported,
    },
    PlatformInfo {
        host: HostPlatform::LinuxKvm,
        backend: "KVM",
        support: PlatformSupport::Experimental,
    },
];

/// Fail before Jyth performs image acquisition, guest-binary compilation, or
/// VM creation unless the host is the supported Windows/HCS release target.
pub fn ensure_supported_platform() -> ApiResult<()> {
    let host = HostPlatform::current();
    if host.support() == PlatformSupport::Supported {
        return Ok(());
    }

    Err(
        Report::new(ApiError::UnsupportedPlatform { platform: host }).attach(format!(
            "Jyth v0.1.0 supports Windows/HCS; {host} ({backend}) is {support}",
            backend = host.backend(),
            support = host.support(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_platform_matches_the_compilation_target() {
        #[cfg(target_os = "windows")]
        assert_eq!(HostPlatform::current(), HostPlatform::WindowsHcs);

        #[cfg(target_os = "linux")]
        assert_eq!(HostPlatform::current(), HostPlatform::LinuxKvm);

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        assert!(matches!(HostPlatform::current(), HostPlatform::Other(_)));
    }

    #[test]
    fn support_matrix_records_windows_as_supported_and_linux_as_experimental() {
        assert_eq!(SUPPORT_MATRIX.len(), 2);
        assert_eq!(SUPPORT_MATRIX[0].host, HostPlatform::WindowsHcs);
        assert_eq!(SUPPORT_MATRIX[0].support, PlatformSupport::Supported);
        assert_eq!(SUPPORT_MATRIX[1].host, HostPlatform::LinuxKvm);
        assert_eq!(SUPPORT_MATRIX[1].support, PlatformSupport::Experimental);
    }

    #[test]
    fn only_windows_hcs_passes_the_release_gate() {
        assert_eq!(
            HostPlatform::WindowsHcs.support(),
            PlatformSupport::Supported
        );
        assert_ne!(HostPlatform::LinuxKvm.support(), PlatformSupport::Supported);
        assert_ne!(
            HostPlatform::Other("macos").support(),
            PlatformSupport::Supported
        );
    }

    #[test]
    fn unsupported_platform_error_preserves_the_typed_host() {
        #[cfg(target_os = "linux")]
        {
            let error = ensure_supported_platform().expect_err("Linux/KVM is experimental");
            assert_eq!(
                *error.current_context(),
                ApiError::UnsupportedPlatform {
                    platform: HostPlatform::LinuxKvm,
                }
            );
        }

        #[cfg(target_os = "windows")]
        ensure_supported_platform().expect("Windows/HCS is the supported release target");

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let error = ensure_supported_platform().expect_err("the host has no backend");
            assert!(matches!(
                *error.current_context(),
                ApiError::UnsupportedPlatform {
                    platform: HostPlatform::Other(_)
                }
            ));
        }
    }
}
