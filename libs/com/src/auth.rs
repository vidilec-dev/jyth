//! Mandatory host authentication exchange (TcpTransportMigrationPlan WP2).
//!
//! Every connection opened by [`crate::TcpEndpoint::connect`] and
//! [`crate::TcpEndpoint::connect_async`] must complete this challenge/MAC
//! handshake with the guest before any `Command`/`Event` frame is sent or
//! decoded: the guest sends an [`AuthChallengeV1`], the host answers with
//! [`AuthResponseV1`] derived from the session capability, and the guest
//! accepts with [`AuthAcceptedV1`]. All handshake frames are bounded by
//! [`MAX_AUTH_FRAME`]; the blocking exchange is additionally bounded by
//! [`AUTHENTICATION_DEADLINE`] socket timeouts and the async exchange by a
//! wall-clock deadline in the caller.

use error_stack::Report;
use protocol::auth::{AUTHENTICATION_DEADLINE, MAX_AUTH_FRAME, PROTOCOL_VERSION};
use protocol::{AuthAcceptedV1, AuthChallengeV1, AuthResponseV1};

use crate::{AsyncStream, Stream, TcpEndpoint, TransportError, TransportResult};

impl TcpEndpoint {
    /// Performs the challenge/MAC authentication exchange on a blocking
    /// stream. Frames are bounded by [`MAX_AUTH_FRAME`] and the whole
    /// exchange by [`AUTHENTICATION_DEADLINE`] read/write timeouts. The
    /// stream is returned only after the guest accepts the exchange, so the
    /// caller never decodes a `Command`/`Event` frame before authentication.
    pub(crate) fn authenticate_blocking(&self, mut stream: Stream) -> TransportResult<Stream> {
        stream
            .socket
            .set_read_timeout(Some(AUTHENTICATION_DEADLINE))
            .map_err(|e| Report::new(e).change_context(TransportError::AuthenticationFailed))?;
        stream
            .socket
            .set_write_timeout(Some(AUTHENTICATION_DEADLINE))
            .map_err(|e| Report::new(e).change_context(TransportError::AuthenticationFailed))?;

        let challenge_payload = stream
            .read_frame_with_limit(MAX_AUTH_FRAME)
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;
        let challenge = AuthChallengeV1::try_from(challenge_payload.as_slice())
            .map_err(|e| Report::new(TransportError::AuthenticationFailed).attach(e.to_string()))?;
        let response = AuthResponseV1::for_challenge(&self.capability, &self.vm_id, &challenge);
        let response_payload: Vec<u8> =
            response
                .try_into()
                .map_err(|e: Report<protocol::ProtocolError>| {
                    Report::new(TransportError::AuthenticationFailed).attach(e.to_string())
                })?;
        stream
            .write_frame_limited(&response_payload, MAX_AUTH_FRAME)
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;

        let accepted_payload = stream
            .read_frame_with_limit(MAX_AUTH_FRAME)
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;
        let accepted = AuthAcceptedV1::try_from(accepted_payload.as_slice())
            .map_err(|e| Report::new(TransportError::AuthenticationFailed).attach(e.to_string()))?;
        if accepted.version != PROTOCOL_VERSION {
            return Err(Report::new(TransportError::AuthenticationFailed));
        }
        stream
            .socket
            .set_read_timeout(None)
            .map_err(|e| Report::new(e).change_context(TransportError::AuthenticationFailed))?;
        stream
            .socket
            .set_write_timeout(None)
            .map_err(|e| Report::new(e).change_context(TransportError::AuthenticationFailed))?;
        Ok(stream)
    }

    /// Performs the challenge/MAC authentication exchange on an async
    /// stream. Frames are bounded by [`MAX_AUTH_FRAME`]; the caller bounds
    /// the whole exchange by a wall-clock deadline
    /// ([`crate::TcpEndpoint::connect_async`] uses
    /// [`AUTHENTICATION_DEADLINE`]). The stream is returned only after the
    /// guest accepts the exchange, so the caller never decodes a
    /// `Command`/`Event` frame before authentication.
    pub(crate) async fn authenticate_async(
        &self,
        mut stream: AsyncStream,
    ) -> TransportResult<AsyncStream> {
        let challenge_payload = stream
            .read_frame_with_limit(MAX_AUTH_FRAME)
            .await
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;
        let challenge = AuthChallengeV1::try_from(challenge_payload.as_slice())
            .map_err(|e| Report::new(TransportError::AuthenticationFailed).attach(e.to_string()))?;
        let response = AuthResponseV1::for_challenge(&self.capability, &self.vm_id, &challenge);
        let response_payload: Vec<u8> =
            response
                .try_into()
                .map_err(|e: Report<protocol::ProtocolError>| {
                    Report::new(TransportError::AuthenticationFailed).attach(e.to_string())
                })?;
        stream
            .write_frame_limited(&response_payload, MAX_AUTH_FRAME)
            .await
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;

        let accepted_payload = stream
            .read_frame_with_limit(MAX_AUTH_FRAME)
            .await
            .map_err(|e| e.change_context(TransportError::AuthenticationFailed))?;
        let accepted = AuthAcceptedV1::try_from(accepted_payload.as_slice())
            .map_err(|e| Report::new(TransportError::AuthenticationFailed).attach(e.to_string()))?;
        if accepted.version != PROTOCOL_VERSION {
            return Err(Report::new(TransportError::AuthenticationFailed));
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use crate::{AsyncStream, Stream, TcpEndpoint, TransportError};
    use protocol::auth::{
        AuthAcceptedV1, AuthChallengeV1, AuthResponseV1, MAX_AUTH_FRAME, MAX_COMMAND_FRAME,
        PROTOCOL_VERSION, SessionCapability,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

    fn endpoint(addr: SocketAddr, capability: Arc<SessionCapability>, vm_id: Uuid) -> TcpEndpoint {
        TcpEndpoint::new(addr, vm_id, capability)
    }

    #[test]
    fn blocking_tcp_authenticates_before_returning_stream() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::nil();
        let server_thread = std::thread::spawn(move || {
            let mut stream = Stream { socket: server };
            let challenge = AuthChallengeV1 {
                version: PROTOCOL_VERSION,
                challenge: [0xa5; 32],
            };
            stream
                .write_frame_limited(&challenge.to_bytes().unwrap(), MAX_AUTH_FRAME)
                .unwrap();
            let response = AuthResponseV1::try_from(
                stream
                    .read_frame_with_limit(MAX_AUTH_FRAME)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            let expected = AuthResponseV1::for_challenge(
                &SessionCapability::from_bytes([0x5a; 32]),
                &vm_id,
                &challenge,
            );
            assert_eq!(response.mac, expected.mac);
            stream
                .write_frame_limited(
                    &AuthAcceptedV1 {
                        version: PROTOCOL_VERSION,
                    }
                    .to_bytes()
                    .unwrap(),
                    MAX_AUTH_FRAME,
                )
                .unwrap();
        });

        let socket = endpoint(addr, capability, vm_id);
        let stream = socket
            .authenticate_blocking(Stream { socket: client })
            .unwrap();
        drop(stream);
        server_thread.join().unwrap();
    }

    #[test]
    fn reply_read_after_auth_times_out_against_a_silent_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::nil();
        let server_thread = std::thread::spawn(move || {
            let mut stream = Stream { socket: server };
            let challenge = AuthChallengeV1 {
                version: PROTOCOL_VERSION,
                challenge: [0xa5; 32],
            };
            stream
                .write_frame_limited(&challenge.to_bytes().unwrap(), MAX_AUTH_FRAME)
                .unwrap();
            let response = AuthResponseV1::try_from(
                stream
                    .read_frame_with_limit(MAX_AUTH_FRAME)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            let expected = AuthResponseV1::for_challenge(
                &SessionCapability::from_bytes([0x5a; 32]),
                &vm_id,
                &challenge,
            );
            assert_eq!(response.mac, expected.mac);
            stream
                .write_frame_limited(
                    &AuthAcceptedV1 {
                        version: PROTOCOL_VERSION,
                    }
                    .to_bytes()
                    .unwrap(),
                    MAX_AUTH_FRAME,
                )
                .unwrap();
            // Stay silent after accepting authentication: the host must not
            // block forever waiting for a reply frame.
            let _ = stream.read();
        });

        let socket = endpoint(addr, capability, vm_id);
        let mut stream = socket
            .authenticate_blocking(Stream { socket: client })
            .unwrap();
        let error = stream
            .read_frame_with_deadline(MAX_COMMAND_FRAME, Duration::from_millis(100))
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::TimedOut)
        ));
        drop(stream);
        server_thread.join().unwrap();
    }

    #[tokio::test]
    async fn async_reply_read_after_auth_times_out_against_a_silent_peer() {
        use tokio::net::TcpListener as AsyncTcpListener;

        let listener = AsyncTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::nil();
        let server_task = tokio::spawn(async move {
            let mut stream = AsyncStream { socket: server };
            let challenge = AuthChallengeV1 {
                version: PROTOCOL_VERSION,
                challenge: [0xa5; 32],
            };
            stream
                .write_frame_limited(&challenge.to_bytes().unwrap(), MAX_AUTH_FRAME)
                .await
                .unwrap();
            let response = AuthResponseV1::try_from(
                stream
                    .read_frame_with_limit(MAX_AUTH_FRAME)
                    .await
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
            let expected = AuthResponseV1::for_challenge(
                &SessionCapability::from_bytes([0x5a; 32]),
                &vm_id,
                &challenge,
            );
            assert_eq!(response.mac, expected.mac);
            stream
                .write_frame_limited(
                    &AuthAcceptedV1 {
                        version: PROTOCOL_VERSION,
                    }
                    .to_bytes()
                    .unwrap(),
                    MAX_AUTH_FRAME,
                )
                .await
                .unwrap();
            // Stay silent after accepting authentication until the client
            // gives up and closes the connection.
            let _ = stream.read().await;
        });

        let socket = endpoint(addr, capability, vm_id);
        let mut stream = socket
            .authenticate_async(AsyncStream { socket: client })
            .await
            .unwrap();
        let error = stream
            .read_frame_with_deadline(MAX_COMMAND_FRAME, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::TimedOut)
        ));
        drop(stream);
        server_task.await.unwrap();
    }
}
