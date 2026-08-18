use std::fmt;

/// Error context for the guest init binary.
///
/// All variants are unit variants (no dynamic data carried in the enum itself).
/// Dynamic context (I/O error messages, module names, etc.) is attached as
/// printable frames via `error_stack::Report::attach` or `change_context`
/// at each call site, mirroring the pattern used in the host crates
/// (`protocol`, `com`, `hypervisor`, `jyth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// A mount path contained a NUL byte (converted from `NulError`).
    MountNul,
    /// A mount syscall failed (errno attached via `change_context`).
    MountInternal,
    /// An I/O error occurred (source error attached via `change_context`).
    Io,
    /// The configured NIC interface never appeared within the bounded
    /// interface deadline.
    NetworkInterfaceTimeout,
    /// A required network configuration step failed (link, address, route,
    /// DNS, or a normal boot without a configured network).
    NetworkConfig,
    /// The TCP command listener failed to bind or accept a connection.
    NetworkListener,
    /// The host backend parameter in the kernel cmdline is unsupported.
    UnsupportedHost,
    /// The `jyth.backend=` kernel cmdline parameter was not found.
    NotFoundCmdlineBackend,
    /// The kernel modules directory was not found.
    NotFoundKernelModules,
    /// A required kernel module failed to load (module name attached).
    RequiredModuleNotLoaded,
    /// The TCP command bus connection was disconnected.
    BusDisconnected,
    /// Failed to serialize an outbound `Event` frame.
    Serialize,
    /// Failed to deserialize an inbound `Command` frame.
    Deserialize,
    /// The COM1 boot or READY envelope was malformed or used an unknown
    /// version.
    BootProtocol,
    /// The command transport challenge/MAC exchange failed.
    Authentication,
    /// A peer declared a frame larger than the selected protocol bound.
    FrameTooLarge,
    /// A frame payload could not be reserved safely.
    FrameAllocation,
    /// The COM1-only bootstrap command or artifact transfer failed.
    Bootstrap,
    /// A peer closed the stream before a complete frame arrived.
    FrameTruncated,
    /// Post-authentication command/reply frame I/O exceeded the bounded
    /// frame deadline (a connected, authenticated peer stalled).
    FrameIoTimeout,
    /// Failed to spawn a guest process (process name attached).
    ProcessSpawn,
    /// A requested resource (stdin/stdout/stderr, process entry) was not found.
    ResourceNotFound,
    /// A requested disk's block device never appeared in /dev.
    DiskDeviceMissing,
    /// A created disk could not be formatted with a supported ext-family
    /// tool.
    DiskFormatFailed,
    /// A requested disk could not be mounted.
    DiskMountFailed,
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            InitError::MountNul => "mount path contained a NUL byte",
            InitError::MountInternal => "mount syscall failed",
            InitError::Io => "I/O error",
            InitError::NetworkInterfaceTimeout => {
                "the network interface did not appear within the deadline"
            }
            InitError::NetworkConfig => "network configuration failed",
            InitError::NetworkListener => "TCP command listener failed",
            InitError::UnsupportedHost => "unsupported host backend",
            InitError::NotFoundCmdlineBackend => "cmdline backend parameter not found",
            InitError::NotFoundKernelModules => "kernel modules directory not found",
            InitError::RequiredModuleNotLoaded => "a required kernel module was not loaded",
            InitError::BusDisconnected => "bus disconnected",
            InitError::Serialize => "failed to serialize event",
            InitError::Deserialize => "failed to deserialize command",
            InitError::BootProtocol => "invalid or unsupported boot protocol",
            InitError::Authentication => "command transport authentication failed",
            InitError::FrameTooLarge => "command frame exceeds its protocol limit",
            InitError::FrameAllocation => "command frame allocation failed",
            InitError::Bootstrap => "COM1 bootstrap command failed",
            InitError::FrameTruncated => "command frame was truncated",
            InitError::FrameIoTimeout => {
                "command frame I/O exceeded its deadline after authentication"
            }
            InitError::ProcessSpawn => "failed to spawn guest process",
            InitError::ResourceNotFound => "resource not found",
            InitError::DiskDeviceMissing => "a requested disk device never appeared",
            InitError::DiskFormatFailed => "a created disk could not be formatted",
            InitError::DiskMountFailed => "a requested disk could not be mounted",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for InitError {}

/// Convenience alias for `Result` with an `error_stack::Report<InitError>`.
pub type InitResult<T> = Result<T, error_stack::Report<InitError>>;
