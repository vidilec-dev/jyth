//! Local adapter newtypes around `com::TcpEndpoint` implementing the
//! guest-client ports (TcpTransportMigrationPlan WP4).
//!
//! The orphan rule forbids implementing `guest_client::CommandTransport` for
//! `com::TcpEndpoint` from outside either crate, so the jyth composition
//! root wraps the endpoint in a local newtype and hands it to the
//! guest-client dispatcher behind `Arc<dyn ...>`.

use std::future::Future;
use std::pin::Pin;

use com::TcpEndpoint;
use guest_client::{
    CommandTransport, GuestClientError, ProcessStream, StreamFuture, StreamTransport,
    TransportFuture,
};
use protocol::Command;

/// A `com::TcpEndpoint` viewed through the guest-client command and stream
/// ports.
pub(crate) struct TcpTransport(pub(crate) TcpEndpoint);

impl CommandTransport for TcpTransport {
    fn command_async(&self, cmd: Command) -> TransportFuture {
        let endpoint = self.0.clone();
        Box::pin(async move {
            endpoint
                .command_async(cmd)
                .await
                .map_err(|_| GuestClientError::Transport)
        })
    }
}

impl StreamTransport for TcpTransport {
    fn bind_async(&self, cmd: Command) -> StreamFuture {
        let endpoint = self.0.clone();
        Box::pin(async move {
            let stream = endpoint
                .bind_async(cmd)
                .await
                .map_err(|_| GuestClientError::Bind)?;
            Ok(Box::new(TcpProcessStream(stream)) as Box<dyn ProcessStream>)
        })
    }
}

/// A `com::AsyncStream` viewed through the guest-client process-stream port.
struct TcpProcessStream(com::AsyncStream);

impl ProcessStream for TcpProcessStream {
    fn read(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, GuestClientError>> + Send + '_>> {
        Box::pin(async move { self.0.read().await.map_err(|_| GuestClientError::Transport) })
    }

    fn write(
        &mut self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), GuestClientError>> + Send + '_>> {
        // Own the bytes so the returned future is not tied to the caller's
        // borrow of `data`.
        let data = data.to_vec();
        Box::pin(async move {
            self.0
                .write(&data)
                .await
                .map_err(|_| GuestClientError::Transport)
        })
    }
}
