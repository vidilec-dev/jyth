/// Top-level error context for the public `jyth` API. Every crate boundary
/// (`com`, `hypervisor`, `protocol`) reports its own `Context` type; `ApiError`
/// is the surface those are re-rooted into so callers only ever see one error
/// type, with the underlying reports preserved as attached frames.
use protocol::GuestErrorCode;

use crate::platform::HostPlatform;

/// Top-level failures returned by the public Jyth API.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The host is outside the Windows/HCS `v0.1.0` release boundary.
    UnsupportedPlatform {
        /// Platform detected by the support check.
        platform: HostPlatform,
    },
    /// A TCP command transport failure (`com::TransportError`): connect,
    /// frame read/write, or the bind got an unexpected event.
    Transport,
    /// A normal launch was requested without a validated NAT network.
    NetworkRequired,
    /// A command deadline expired while waiting in the dispatcher or while
    /// connecting to, writing to, or reading from the guest.
    RequestTimedOut,
    /// A (de)serialization failure on the wire protocol (`protocol::ProtocolError`).
    Protocol,
    /// The COM1 READY or per-connection HMAC authentication proof failed.
    Authentication,
    /// A hypervisor failure (`hypervisor::HcsError` / `KvmError`).
    Hypervisor,
    /// The guest reported a failure via `Event::Error`.
    Guest {
        /// Error code reported by the guest.
        code: GuestErrorCode,
    },
    /// The guest replied with an event that doesn't match the command sent.
    UnexpectedReply,
    /// The wait for the guest's `READY` handshake on COM1 timed out.
    ReadyTimeout,
    /// The VM could not be created / started (`create_and_start_with_retry`).
    VmCreate,
    /// A local filesystem operation (cache, initrd assembly) failed.
    Io,
    /// The COM1-only bootstrap command or artifact transfer failed.
    Bootstrap,
    /// A disk specification failed pre-launch validation (duplicate paths
    /// or mount targets, missing parent directory).
    Disk,
    /// Building the image / overlay pipeline failed.
    Build,
    /// `shutdown` failed or the command channel was already closed.
    Shutdown,
    /// `RunningProcess::close` (stop) failed or was already gone.
    ProcessClose,
    /// `RunningProcess::bind` failed to establish the stdio pipe.
    Bind,
    /// The object is in an invalid lifecycle state for the call.
    InvalidState,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ApiError::UnsupportedPlatform { platform } => {
                return write!(f, "unsupported host platform: {platform}");
            }
            ApiError::Transport => "TCP command transport error",
            ApiError::NetworkRequired => "network configuration required for a normal launch",
            ApiError::RequestTimedOut => "guest request timed out",
            ApiError::Protocol => "protocol (de)serialization error",
            ApiError::Authentication => "command transport authentication failed",
            ApiError::Hypervisor => "hypervisor error",
            ApiError::Guest { code } => return write!(f, "guest reported: {code}"),
            ApiError::UnexpectedReply => "guest reply did not match the command sent",
            ApiError::ReadyTimeout => "timed out waiting for guest READY handshake",
            ApiError::VmCreate => "failed to create or start the VM",
            ApiError::Io => "local I/O error",
            ApiError::Bootstrap => "COM1 bootstrap command or artifact transfer failed",
            ApiError::Disk => "disk specification or pre-launch validation error",
            ApiError::Build => "image build / overlay pipeline error",
            ApiError::Shutdown => "shutdown failed or channel closed",
            ApiError::ProcessClose => "process close failed or process already gone",
            ApiError::Bind => "process bind failed to establish the stdio pipe",
            ApiError::InvalidState => "object in an invalid lifecycle state for this call",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ApiError {}

/// The canonical `jyth` result type.
pub type ApiResult<T> = Result<T, error_stack::Report<ApiError>>;
