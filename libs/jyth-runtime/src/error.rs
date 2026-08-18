//! Stable error categories for the runtime orchestration boundary.
//!
//! The jyth facade maps these onto its public `ApiError` contexts exactly
//! once; no high-level crate inspects an adapter error string.

use protocol::GuestErrorCode;

/// Failures of the runtime launch, shutdown, and client services.
///
/// The variant set and display strings mirror the public Jyth `ApiError`
/// categories so the facade translation preserves the historical error
/// surface (SolidArchitecturePlan error-surface rules).
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// Boot artifact preparation or the derived run-cache failed.
    #[error("image build / overlay pipeline error")]
    Build,
    /// A TCP command transport failure or guest client creation failure.
    #[error("TCP command transport error")]
    Transport,
    /// A normal launch was requested without a validated NAT network.
    #[error("network configuration required for a normal launch")]
    NetworkRequired,
    /// A command deadline expired while waiting in the dispatcher or while
    /// connecting to, writing to, or reading from the guest.
    #[error("guest request timed out")]
    RequestTimedOut,
    /// A (de)serialization failure on the wire protocol.
    #[error("protocol (de)serialization error")]
    Protocol,
    /// The COM1 READY or per-connection HMAC authentication proof failed.
    #[error("command transport authentication failed")]
    Authentication,
    /// A hypervisor failure (backend create, start, publish, or close).
    #[error("hypervisor error")]
    Hypervisor,
    /// The guest reported a failure via `Event::Error`.
    #[error("guest reported: {code}")]
    Guest {
        /// Error code reported by the guest.
        code: GuestErrorCode,
    },
    /// The guest replied with an event that doesn't match the command sent.
    #[error("guest reply did not match the command sent")]
    UnexpectedReply,
    /// The wait for the guest's `READY` handshake on COM1 timed out.
    #[error("timed out waiting for guest READY handshake")]
    ReadyTimeout,
    /// The VM could not be created or started.
    #[error("failed to create or start the VM")]
    VmCreate,
    /// `shutdown` failed or the command channel was already closed.
    #[error("shutdown failed or channel closed")]
    Shutdown,
    /// `RunningProcess::close` (stop) failed or was already gone.
    #[error("process close failed or process already gone")]
    ProcessClose,
    /// `RunningProcess::bind` failed to establish the stdio pipe.
    #[error("process bind failed to establish the stdio pipe")]
    Bind,
    /// The object is in an invalid lifecycle state for the call.
    #[error("object in an invalid lifecycle state for this call")]
    InvalidState,
}

/// Translate one guest-client boundary error into the stable runtime
/// context, preserving the exact attachment the facade used historically.
/// This is the single runtime-side translation point for the guest command
/// boundary; the jyth facade maps the `RuntimeError` category once more into
/// its public `ApiError`.
///
/// `operation` and `endpoint` describe the call site that hit the deadline;
/// they are attached to the `RequestTimedOut` report so every facade-facing
/// timeout is complete (spec capability `error-report-completeness`).
pub fn map_client_error(
    error: guest_client::GuestClientError,
    operation: &str,
    endpoint: std::net::SocketAddr,
) -> error_stack::Report<RuntimeError> {
    use error_stack::Report;
    match error {
        guest_client::GuestClientError::Transport => Report::new(RuntimeError::Transport),
        guest_client::GuestClientError::RequestTimedOut => {
            Report::new(RuntimeError::RequestTimedOut)
                .attach(format!("operation={operation}"))
                .attach(format!("budget={:?}", guest_client::REQUEST_TIMEOUT))
                .attach(format!("endpoint={endpoint}"))
        }
        guest_client::GuestClientError::Guest { code, message } => {
            Report::new(RuntimeError::Guest { code }).attach(format!("guest error: {message}"))
        }
        guest_client::GuestClientError::UnexpectedReply => {
            Report::new(RuntimeError::UnexpectedReply)
        }
        guest_client::GuestClientError::Shutdown => Report::new(RuntimeError::Shutdown),
        guest_client::GuestClientError::InvalidState => Report::new(RuntimeError::InvalidState),
        guest_client::GuestClientError::ProcessClose => Report::new(RuntimeError::ProcessClose),
        guest_client::GuestClientError::Bind => Report::new(RuntimeError::Bind),
    }
}
