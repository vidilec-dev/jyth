//! TCP connection creation (TcpTransportMigrationPlan WP2).
//!
//! [`TcpEndpoint`] is the endpoint handle; connecting opens a TCP stream to
//! the guest's configured command address. The caller-facing
//! [`TcpEndpoint::connect`] and [`TcpEndpoint::connect_async`] hand the
//! opened stream to the mandatory authentication exchange in [`crate::auth`]
//! before returning it, so no command frame can be written on an
//! unauthenticated connection.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use error_stack::Report;
use protocol::SessionCapability;
use protocol::auth::AUTHENTICATION_DEADLINE;
#[cfg(feature = "tracing")]
use tracing::instrument;
use uuid::Uuid;

use crate::{AsyncStream, Stream, TransportError, TransportResult};

/// The absolute deadline applied to one blocking TCP connect attempt.
/// 5s is the bounded request-class default (cancel-timeout-policy); the
/// identity and per-attempt context attachments are unchanged.
const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
/// The absolute deadline applied to one asynchronous TCP connect attempt.
const ASYNC_CONNECT_DEADLINE: Duration = AUTHENTICATION_DEADLINE;
const MAX_ASYNC_CONNECT_ATTEMPTS: usize = 3;
const ASYNC_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);

/// Identifies a guest TCP command endpoint by socket address and VM UUID.
///
/// The capability is the per-session secret the peer must prove on every
/// connection; the VM UUID binds the proof transcript to one VM identity.
#[derive(Clone)]
pub struct TcpEndpoint {
    pub(crate) address: SocketAddr,
    pub(crate) vm_id: Uuid,
    pub(crate) capability: Arc<SessionCapability>,
}

/// `Debug` includes the socket address and VM UUID for diagnostics and
/// redacts the capability material.
impl std::fmt::Debug for TcpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpEndpoint")
            .field("address", &self.address)
            .field("vm_id", &self.vm_id)
            .field("capability", &"[REDACTED]")
            .finish()
    }
}

impl TcpEndpoint {
    /// Creates an endpoint handle without opening a connection.
    pub fn new(address: SocketAddr, vm_id: Uuid, capability: Arc<SessionCapability>) -> Self {
        Self {
            address,
            vm_id,
            capability,
        }
    }

    /// Diagnostic identity attached to every `TransportError::Connect`
    /// report so a failed connect explains *which* TCP endpoint was being
    /// opened. error-stack attachments are the idiomatic place for this kind
    /// of call-site-specific context (see error-stack docs §"Building up the
    /// Report - Attachments"); putting it on the outermost report keeps a
    /// single copy regardless of which low-level step failed. The identity
    /// never includes capability material.
    pub(crate) fn identity(&self) -> String {
        format!("tcp address={} uuid={}", self.address, self.vm_id)
    }

    /// Classify a connect I/O error into a distinct attachment below the
    /// stable [`TransportError::Connect`] category.
    fn connect_error(error: std::io::Error, endpoint: &TcpEndpoint) -> Report<TransportError> {
        let kind = match error.kind() {
            std::io::ErrorKind::ConnectionRefused => "connection refused",
            std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                "host or network unreachable"
            }
            std::io::ErrorKind::TimedOut => "connect timed out",
            _ => "connect failed",
        };
        Report::new(error)
            .change_context(TransportError::Connect)
            .attach(format!("{kind} for {}", endpoint.identity()))
    }

    fn connect_inner(&self) -> TransportResult<Stream> {
        let socket = TcpStream::connect_timeout(&self.address, CONNECT_DEADLINE)
            .map_err(|e| Self::connect_error(e, self))?;
        socket
            .set_nodelay(true)
            .map_err(|e| Self::connect_error(e, self))?;
        Ok(Stream { socket })
    }

    /// Open a blocking TCP connection and authenticate it before returning.
    /// Connection failures are rooted at [`TransportError::Connect`] and
    /// authentication failures at [`TransportError::AuthenticationFailed`];
    /// both carry this `TcpEndpoint`'s address/uuid as diagnostic context.
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    pub fn connect(&self) -> TransportResult<Stream> {
        let stream = self
            .connect_inner()
            .map_err(|r| r.attach(self.identity()))?;
        self.authenticate_blocking(stream)
            .map_err(|r| r.attach(self.identity()))
    }

    async fn connect_async_inner(&self) -> TransportResult<AsyncStream> {
        let socket = tokio::net::TcpStream::connect(self.address)
            .await
            .map_err(|e| Self::connect_error(e, self))?;
        socket
            .set_nodelay(true)
            .map_err(|e| Self::connect_error(e, self))?;
        Ok(AsyncStream { socket })
    }

    async fn connect_async_bounded(&self) -> TransportResult<AsyncStream> {
        let mut last_error = None;
        for attempt in 0..MAX_ASYNC_CONNECT_ATTEMPTS {
            match tokio::time::timeout(ASYNC_CONNECT_DEADLINE, self.connect_async_inner()).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(Report::new(TransportError::Connect).attach(format!(
                        "tcp connect attempt {} exceeded {:?} for {}",
                        attempt + 1,
                        ASYNC_CONNECT_DEADLINE,
                        self.identity()
                    )));
                }
            }
            if attempt + 1 < MAX_ASYNC_CONNECT_ATTEMPTS {
                tokio::time::sleep(ASYNC_CONNECT_RETRY_DELAY).await;
            }
        }
        Err(last_error.unwrap_or_else(|| Report::new(TransportError::Connect)))
    }

    /// Async twin of [`TcpEndpoint::connect`]: open an async TCP connection,
    /// re-rooted at [`TransportError::Connect`] and stamped with this
    /// `TcpEndpoint`'s address/uuid as an attachment on failure.
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(address = %self.address, uuid = ?self.vm_id), level = "debug"))]
    pub async fn connect_async(&self) -> TransportResult<AsyncStream> {
        let stream = self
            .connect_async_bounded()
            .await
            .map_err(|r| r.attach(self.identity()))?;
        tokio::time::timeout(AUTHENTICATION_DEADLINE, self.authenticate_async(stream))
            .await
            .map_err(|_| {
                Report::new(TransportError::AuthenticationFailed)
                    .attach("authentication deadline expired")
            })?
            .map_err(|r| r.attach(self.identity()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{spawn_auth_server, spawn_silent_auth_server};
    use protocol::auth::SessionCapability;

    #[test]
    fn connect_authenticates_against_a_loopback_peer() {
        let addr = spawn_auth_server();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::nil();
        let endpoint = TcpEndpoint::new(addr, vm_id, capability);
        let stream = endpoint.connect().expect("loopback connect must succeed");
        drop(stream);
    }

    #[test]
    fn connect_classifies_connection_refused() {
        // Bind a listener, read its address, drop it: the port is closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let endpoint = TcpEndpoint::new(addr, Uuid::nil(), capability);
        let error = endpoint.connect().unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::Connect)
        ));
        assert!(
            error.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("refused"))),
            "the refused connect must carry a distinct attachment: {error:?}"
        );
        assert!(
            error.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains(&addr.to_string()))),
            "the connect report must identify the socket address: {error:?}"
        );
    }

    #[test]
    fn connect_fails_against_a_silent_peer_before_command_serialization() {
        let addr = spawn_silent_auth_server();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let endpoint = TcpEndpoint::new(addr, Uuid::nil(), capability);
        // The peer never sends a challenge: the exchange must fail within
        // the authentication deadline instead of returning an
        // unauthenticated stream.
        let error = endpoint.connect().unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_capability_never_authenticates() {
        let addr = spawn_auth_server();
        let capability = Arc::new(SessionCapability::from_bytes([0x00; 32]));
        let endpoint = TcpEndpoint::new(addr, Uuid::nil(), capability);
        let error = endpoint.connect().unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::AuthenticationFailed)
        ));
    }

    #[test]
    fn debug_redacts_the_capability_and_keeps_address_and_uuid() {
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::from_u128(0x1234);
        let endpoint = TcpEndpoint::new(
            SocketAddr::from(([10, 77, 0, 10], protocol::COMMAND_PORT)),
            vm_id,
            capability,
        );
        let debug = format!("{endpoint:?}");
        assert!(debug.contains("10.77.0.10"), "{debug}");
        assert!(debug.contains(&vm_id.to_string()), "{debug}");
        assert!(
            !debug.contains("5a5a5a") && debug.contains("REDACTED"),
            "{debug}"
        );
    }

    #[tokio::test]
    async fn connect_async_authenticates_against_a_loopback_peer() {
        let addr = spawn_auth_server();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = Uuid::nil();
        let endpoint = TcpEndpoint::new(addr, vm_id, capability);
        let stream = endpoint
            .connect_async()
            .await
            .expect("loopback async connect must succeed");
        drop(stream);
    }

    #[tokio::test]
    async fn connect_async_classifies_connection_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let endpoint = TcpEndpoint::new(addr, Uuid::nil(), capability);
        let error = endpoint.connect_async().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::Connect)
        ));
        assert!(
            error.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains(&addr.to_string()))),
            "the connect report must identify the socket address: {error:?}"
        );
    }

    #[tokio::test]
    async fn async_wrong_vm_uuid_never_authenticates() {
        // The server authenticates with VM nil; the client claims a
        // different VM identity, so the MAC never matches.
        let addr = spawn_auth_server();
        let capability = Arc::new(SessionCapability::from_bytes([0x5a; 32]));
        let endpoint = TcpEndpoint::new(addr, Uuid::from_u128(42), capability);
        let error = endpoint.connect_async().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::AuthenticationFailed)
        ));
    }

    #[test]
    fn connect_deadline_defaults_to_five_seconds() {
        assert_eq!(CONNECT_DEADLINE, Duration::from_secs(5));
    }
}
