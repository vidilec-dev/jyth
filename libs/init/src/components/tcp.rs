//! Guest TCP command listener (TcpTransportMigrationPlan WP3).
//!
//! [`TcpCommandListener`] binds the configured guest IPv4 address and
//! `protocol::COMMAND_PORT` and accepts authenticated command connections.
//! Binding happens only after the NIC has been configured, so a successful
//! bind is the final proof that the configured guest address is locally
//! usable. Every accepted socket enables `TCP_NODELAY` and is placed into
//! nonblocking mode through `async_io`.

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};

use async_io::Async;
use error_stack::Report;

use crate::errors::{InitError, InitResult};

#[derive(Debug)]
pub(crate) struct TcpCommandListener {
    inner: Async<TcpListener>,
}

impl TcpCommandListener {
    /// Bind the command listener to the configured guest address and port.
    ///
    /// The listener deliberately binds the configured NIC address, never
    /// `0.0.0.0`, so accidental exposure inside the guest is reduced.
    pub(crate) fn bind(address: SocketAddrV4) -> InitResult<Self> {
        #[cfg(feature = "tracing")]
        tracing::info!(
            "[JythInit][TcpCommandListener::Bind]: Binding TCP command listener to {}",
            address
        );
        let listener = TcpListener::bind(address)
            .map_err(|e| Report::new(e).change_context(InitError::NetworkListener))?;
        let inner = Async::new(listener)
            .map_err(|e| Report::new(e).change_context(InitError::NetworkListener))?;
        Ok(Self { inner })
    }

    /// Accept one command connection, returning the nonblocking stream and
    /// the peer address. `TCP_NODELAY` is enabled before the stream is
    /// returned so command latency is never padded by Nagle's algorithm.
    pub(crate) async fn accept(&self) -> InitResult<(Async<TcpStream>, SocketAddr)> {
        let (stream, peer) = self
            .inner
            .accept()
            .await
            .map_err(|e| Report::new(e).change_context(InitError::NetworkListener))?;
        stream
            .get_ref()
            .set_nodelay(true)
            .map_err(|e| Report::new(e).change_context(InitError::NetworkListener))?;
        Ok((stream, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::AsyncWriteExt;

    /// Listener tests bind loopback port zero and accept a TCP peer.
    #[test]
    fn binds_loopback_port_zero_and_accepts_a_peer() {
        let listener =
            TcpCommandListener::bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("loopback bind must succeed");

        let address = listener.inner.get_ref().local_addr().unwrap();
        smol::block_on(async move {
            let client = std::net::TcpStream::connect(address).unwrap();
            let (server, peer) = listener.accept().await.expect("accept must succeed");
            assert_eq!(peer, address);
            assert_eq!(
                server.get_ref().local_addr().unwrap(),
                address,
                "the accepted stream must be connected to the listener address"
            );
            // The accepted socket must carry TCP_NODELAY and stay usable.
            let mut server = server;
            let mut client = Async::new(client).unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            futures_lite::AsyncReadExt::read_exact(&mut server, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf, b"ping");
            assert!(
                server.get_ref().nodelay().unwrap(),
                "accepted sockets must enable TCP_NODELAY"
            );
        });
    }

    #[test]
    fn bind_failure_is_a_typed_network_listener_error() {
        // Occupy a port, then try to bind the same port again.
        let occupied =
            TcpListener::bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = occupied.local_addr().unwrap();
        let error = TcpCommandListener::bind(SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            address.port(),
        ))
        .expect_err("a second bind on the same address must fail");
        assert!(matches!(
            error.current_context(),
            InitError::NetworkListener
        ));
    }
}
