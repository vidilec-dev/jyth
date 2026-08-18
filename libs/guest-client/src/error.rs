use protocol::GuestErrorCode;

/// Stable failure categories reported by guest-client operations.
///
/// This is the error surface of the guest command boundary. The Jyth facade
/// maps every category exactly once into its public `ApiError` at the facade
/// boundary; callers inside guest-client never re-interpret these values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestClientError {
    /// The underlying transport failed while sending a command or stream
    /// bytes (connect, frame read/write, or an unexpected bind result).
    #[error("TCP command transport error")]
    Transport,
    /// A command deadline expired while waiting in the dispatcher or while
    /// connecting to, writing to, or reading from the guest.
    #[error("guest request timed out")]
    RequestTimedOut,
    /// The guest reported a failure via `Event::Error`.
    #[error("guest reported error {code}: {message}")]
    Guest {
        /// Typed error code reported by the guest.
        code: GuestErrorCode,
        /// Human-readable guest error message.
        message: String,
    },
    /// The guest replied with an event that does not match the command sent.
    #[error("guest reply did not match the command sent")]
    UnexpectedReply,
    /// The command channel is shut down or closed (dispatcher cancelled or
    /// the reply channel was dropped).
    #[error("guest command channel is shut down or closed")]
    Shutdown,
    /// The object is in an invalid lifecycle state for the call.
    #[error("process handle is closed")]
    InvalidState,
    /// A process close (stop) request failed or the process was already gone.
    #[error("process close failed")]
    ProcessClose,
    /// A process stdio bind failed to establish its stream.
    #[error("process stdio bind failed")]
    Bind,
}
