//! Command/event RPC over an authenticated TCP connection (TcpTransportMigrationPlan
//! WP8 com action 6).
//!
//! [`TcpEndpoint::command`] and [`TcpEndpoint::command_async`] send one `Command`
//! frame and read the correlated `Event` reply; [`TcpEndpoint::bind`] and
//! [`TcpEndpoint::bind_async`] additionally expect `Event::ProcessBound` and
//! return the bound stream. Every command frame is bounded by
//! [`MAX_COMMAND_FRAME`] and each reply read by [`REPLY_DEADLINE`]. All of
//! these operations run on streams returned by the authenticated connect
//! path ([`crate::auth`]), so no `Command`/`Event` frame is ever written or
//! decoded before authentication.

use std::time::Duration;

use error_stack::Report;
use protocol::auth::MAX_COMMAND_FRAME;
use protocol::{Command, Event};
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{AsyncStream, Stream, TcpEndpoint, TransportError, TransportResult};

/// Bounded deadline for one command or bind reply read after authentication.
/// A healthy peer replies promptly; this only guards against a guest that
/// accepts authentication but never answers. 5s is the bounded request-class
/// default (cancel-timeout-policy). Silent-peer tests pass explicit short
/// deadlines where a fast timeout matters.
const REPLY_DEADLINE: Duration = Duration::from_secs(5);

impl TcpEndpoint {
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    /// Sends one command and waits synchronously for its event reply.
    pub fn command(&self, cmd: Command) -> TransportResult<Event> {
        let mut stream = self.connect()?;

        let payload: Vec<u8> = cmd
            .try_into()
            .map_err(|e: Report<protocol::ProtocolError>| {
                e.change_context(TransportError::Serialize)
            })?;
        stream.write_frame_limited(&payload, MAX_COMMAND_FRAME)?;

        let reply_payload = stream.read_frame_with_deadline(MAX_COMMAND_FRAME, REPLY_DEADLINE)?;
        Event::try_from(reply_payload.as_slice())
            .map_err(|e| e.change_context(TransportError::Deserialize))
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    /// Sends one command and waits asynchronously for its event reply.
    pub async fn command_async(&self, cmd: Command) -> TransportResult<Event> {
        let mut stream = self.connect_async().await?;

        let payload: Vec<u8> = cmd
            .try_into()
            .map_err(|e: Report<protocol::ProtocolError>| {
                e.change_context(TransportError::Serialize)
            })?;
        stream
            .write_frame_limited(&payload, MAX_COMMAND_FRAME)
            .await?;

        let reply_payload = stream
            .read_frame_with_deadline(MAX_COMMAND_FRAME, REPLY_DEADLINE)
            .await?;
        Event::try_from(reply_payload.as_slice())
            .map_err(|e| e.change_context(TransportError::Deserialize))
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    /// Sends a binding command and returns the connected blocking stream.
    pub fn bind(&self, cmd: Command) -> TransportResult<Stream> {
        let mut stream = self.connect()?;

        let payload: Vec<u8> = cmd
            .try_into()
            .map_err(|e: Report<protocol::ProtocolError>| {
                e.change_context(TransportError::Serialize)
            })?;
        stream.write_frame_limited(&payload, MAX_COMMAND_FRAME)?;

        let event = Event::try_from(
            stream
                .read_frame_with_deadline(MAX_COMMAND_FRAME, REPLY_DEADLINE)?
                .as_slice(),
        )
        .map_err(|e| e.change_context(TransportError::Deserialize))?;
        if let Event::ProcessBound { uuid: _uuid } = event {
            #[cfg(feature = "tracing")]
            tracing::info!(uuid = ?_uuid, "[COM] Process bound");
            return Ok(stream);
        }
        Err(Report::new(TransportError::BindExpectedProcessBound)
            .attach(format!("got unexpected event {event:?} while binding")))
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    /// Sends a binding command and returns the connected async stream.
    pub async fn bind_async(&self, cmd: Command) -> TransportResult<AsyncStream> {
        let mut stream = self.connect_async().await?;

        let payload: Vec<u8> = cmd
            .try_into()
            .map_err(|e: Report<protocol::ProtocolError>| {
                e.change_context(TransportError::Serialize)
            })?;
        stream
            .write_frame_limited(&payload, MAX_COMMAND_FRAME)
            .await?;

        let event = Event::try_from(
            stream
                .read_frame_with_deadline(MAX_COMMAND_FRAME, REPLY_DEADLINE)
                .await?
                .as_slice(),
        )
        .map_err(|e| e.change_context(TransportError::Deserialize))?;
        if let Event::ProcessBound { uuid: _uuid } = event {
            #[cfg(feature = "tracing")]
            tracing::info!(uuid = ?_uuid, "[COM] Process bound");
            return Ok(stream);
        }
        Err(Report::new(TransportError::BindExpectedProcessBound)
            .attach(format!("got unexpected event {event:?} while binding")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_deadline_defaults_to_five_seconds() {
        assert_eq!(REPLY_DEADLINE, Duration::from_secs(5));
    }
}
