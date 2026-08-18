//! Shared loopback test servers for the com crate's TCP transport tests.
//!
//! These helpers are compiled only under `cfg(test)` and speak the guest
//! side of the authentication exchange over a loopback `TcpListener`, so
//! blocking and async connector paths can be proven without a live VM.

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;

use protocol::auth::{
    AuthAcceptedV1, AuthChallengeV1, AuthResponseV1, MAX_AUTH_FRAME, PROTOCOL_VERSION,
    SessionCapability,
};
use uuid::Uuid;

use crate::{Stream, TransportResult};

/// The capability and VM identity the loopback auth servers expect.
pub(crate) fn server_identity() -> (Arc<SessionCapability>, Uuid) {
    (
        Arc::new(SessionCapability::from_bytes([0x5a; 32])),
        Uuid::nil(),
    )
}

/// Run the guest side of the challenge/MAC exchange on one accepted stream.
///
/// Returns `Ok(())` when the client proved the expected capability and VM
/// identity, `Err` otherwise. After the exchange — success or mismatch — the
/// function holds the connection open until the client closes it, so the
/// client's stream stays usable and the listener stays alive across async
/// connect retries.
pub(crate) fn serve_authentication(mut stream: Stream) -> TransportResult<()> {
    let (capability, vm_id) = server_identity();
    let challenge = AuthChallengeV1 {
        version: PROTOCOL_VERSION,
        challenge: [0xa5; 32],
    };
    stream.write_frame_limited(&challenge.to_bytes().unwrap(), MAX_AUTH_FRAME)?;
    let response =
        AuthResponseV1::try_from(stream.read_frame_with_limit(MAX_AUTH_FRAME)?.as_slice())
            .map_err(|_| crate::TransportError::AuthenticationFailed)?;
    let expected = AuthResponseV1::for_challenge(&capability, &vm_id, &challenge);
    let matched = response.mac == expected.mac;
    if matched {
        stream.write_frame_limited(
            &AuthAcceptedV1 {
                version: PROTOCOL_VERSION,
            }
            .to_bytes()
            .unwrap(),
            MAX_AUTH_FRAME,
        )?;
    }
    // Hold the connection open until the client closes it.
    let _ = stream.read();
    if matched {
        Ok(())
    } else {
        Err(crate::TransportError::AuthenticationFailed.into())
    }
}

/// Bind a loopback listener, accept one connection, and complete a real
/// challenge/MAC exchange on it in a background thread. Returns the address
/// the client must connect to.
pub(crate) fn spawn_auth_server() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let _ = serve_authentication(Stream { socket });
    });
    addr
}

/// Bind a loopback listener and accept one connection that never sends a
/// challenge (a silent pre-auth peer). Returns the listener address.
pub(crate) fn spawn_silent_auth_server() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(15)));
        let mut stream = Stream { socket };
        let _ = stream.read();
    });
    addr
}
