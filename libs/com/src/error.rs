//! Transport error context for the host↔guest TCP command channel.
//!
//! Every transport operation fails through an [`error_stack::Report`] rooted
//! at [`TransportError`]; [`TransportResult`] is the shared result alias. The
//! type lives in its own module so the connector, authentication, framing,
//! sync/async adapters, and RPC modules all share one error surface
//! (TcpTransportMigrationPlan WP2).

use error_stack::Report;

/// Error context for host↔guest TCP command transport (`com::TcpEndpoint`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Failed to open a TCP connection to the guest command endpoint.
    Connect,
    /// Failed to serialize a `Command` for the wire.
    Serialize,
    /// Failed to deserialize the guest's `Event` reply.
    Deserialize,
    /// Low-level frame write (length prefix + payload) failed.
    WriteFrame,
    /// Low-level frame read (length prefix + payload) failed.
    ReadFrame,
    /// The peer declared a frame larger than the selected bound or larger
    /// than the wire length type can represent.
    FrameTooLarge,
    /// The payload allocation could not be reserved without panicking.
    FrameAllocation,
    /// The peer closed the stream before a complete frame arrived.
    FrameTruncated,
    /// The capability challenge/MAC exchange failed.
    AuthenticationFailed,
    /// The peer did not reply within the configured deadline.
    TimedOut,
    /// Failed to convert a stream between blocking and async modes.
    StreamConversion,
    /// `bind`/`bind_async` got an event other than `Event::ProcessBound`.
    BindExpectedProcessBound,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            TransportError::Connect => "TCP connect failed",
            TransportError::Serialize => "failed to serialize Command",
            TransportError::Deserialize => "failed to deserialize Event",
            TransportError::WriteFrame => "failed to write frame",
            TransportError::ReadFrame => "failed to read frame",
            TransportError::FrameTooLarge => "frame exceeds the protocol limit",
            TransportError::FrameAllocation => "frame payload allocation failed",
            TransportError::FrameTruncated => "frame was truncated",
            TransportError::AuthenticationFailed => "TCP transport authentication failed",
            TransportError::TimedOut => "peer did not reply within the deadline",
            TransportError::StreamConversion => {
                "failed to convert between blocking and async stream modes"
            }
            TransportError::BindExpectedProcessBound => {
                "bind expected Event::ProcessBound but got something else"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TransportError {}

/// Result type returned by TCP transport operations.
pub type TransportResult<T> = Result<T, Report<TransportError>>;
