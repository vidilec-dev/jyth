//! Tokio socket adapter for the TCP command channel (TcpTransportMigrationPlan
//! WP2).
//!
//! [`AsyncStream`] wraps the Tokio TCP stream and implements
//! [`crate::framing::AsyncFrameIo`]; all framing invariants are enforced by
//! the shared codec in `crate::framing`, and this adapter only performs the
//! socket-specific plumbing (async reads/writes, deadline timeouts).

use std::time::Duration;

use error_stack::Report;
use protocol::auth::MAX_COMMAND_FRAME;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::framing::{self, AsyncFrameIo};
use crate::{Stream, TransportError, TransportResult};

/// Tokio TCP stream for a guest command connection.
pub(crate) type AsyncSocket = tokio::net::TcpStream;

/// Tokio stream for a guest TCP command connection.
#[derive(Debug)]
pub struct AsyncStream {
    pub(crate) socket: AsyncSocket,
}

impl AsyncFrameIo for AsyncStream {
    async fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        use tokio::io::AsyncReadExt;
        self.socket
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(framing::map_async_read_error)
    }

    async fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()> {
        use tokio::io::AsyncWriteExt;
        self.socket
            .write_all(data)
            .await
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }

    async fn flush_frame(&mut self) -> TransportResult<()> {
        use tokio::io::AsyncWriteExt;
        self.socket
            .flush()
            .await
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }
}

impl AsyncStream {
    /// Converts this async stream into its blocking counterpart.
    pub fn into_sync(self) -> TransportResult<Stream> {
        self.socket
            .into_std()
            .map(|socket| Stream { socket })
            .map_err(|e| Report::new(e).change_context(TransportError::StreamConversion))
    }

    /// Writes raw bytes to the stream.
    pub async fn write(&mut self, data: &[u8]) -> TransportResult<()> {
        use tokio::io::AsyncWriteExt;
        self.socket
            .write_all(data)
            .await
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }

    /// Reads up to 4096 raw bytes from the stream.
    pub async fn read(&mut self) -> TransportResult<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0; 4096];
        let n = self
            .socket
            .read(&mut buf)
            .await
            .map_err(|e| Report::new(e).change_context(TransportError::ReadFrame))?;
        buf.truncate(n);
        Ok(buf)
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self, data), fields(len = data.len()), level = "trace"))]
    /// Writes a little-endian length-prefixed frame.
    pub async fn write_frame(&mut self, data: &[u8]) -> TransportResult<()> {
        self.write_frame_limited(data, MAX_COMMAND_FRAME).await
    }

    /// Writes a length-prefixed frame after checking its caller-selected
    /// maximum and the `u32` wire-length boundary.
    pub async fn write_frame_limited(
        &mut self,
        data: &[u8],
        maximum: usize,
    ) -> TransportResult<()> {
        framing::write_frame_limited_async(self, data, maximum).await
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "trace"))]
    /// Reads one little-endian length-prefixed frame.
    pub async fn read_frame(&mut self) -> TransportResult<Vec<u8>> {
        self.read_frame_with_limit(MAX_COMMAND_FRAME).await
    }

    /// Reads one frame, rejecting its declared length before allocation.
    pub async fn read_frame_with_limit(&mut self, maximum: usize) -> TransportResult<Vec<u8>> {
        framing::read_frame_with_limit_async(self, maximum).await
    }

    /// Reads one frame bounded by a wall-clock deadline covering the whole
    /// read. Overflow surfaces [`TransportError::TimedOut`].
    pub async fn read_frame_with_deadline(
        &mut self,
        maximum: usize,
        deadline: Duration,
    ) -> TransportResult<Vec<u8>> {
        tokio::time::timeout(deadline, self.read_frame_with_limit(maximum))
            .await
            .map_err(|_| {
                Report::new(TransportError::TimedOut)
                    .attach(format!("frame read exceeded the {deadline:?} deadline"))
            })?
    }
}

#[cfg(test)]
mod tests {
    use crate::{AsyncStream, TransportError};
    use protocol::auth::{MAX_AUTH_FRAME, MAX_COMMAND_FRAME};

    const TEST_PAYLOAD: &[u8] = b"hello-framed-world";

    #[tokio::test]
    async fn async_stream_read_write_frame_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let reader = listener.accept().await.unwrap().0;

        let mut s = AsyncStream { socket: writer };
        let mut r = AsyncStream { socket: reader };

        s.write_frame(TEST_PAYLOAD).await.unwrap();
        let got = r.read_frame().await.unwrap();
        assert_eq!(got, TEST_PAYLOAD);
    }

    #[tokio::test]
    async fn async_stream_read_frame_rejects_oversized_auth_length() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut writer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let reader = listener.accept().await.unwrap().0;

        writer
            .write_all(&u32::try_from(MAX_AUTH_FRAME + 1).unwrap().to_le_bytes())
            .await
            .unwrap();

        let mut stream = AsyncStream { socket: reader };
        let error = stream
            .read_frame_with_limit(MAX_AUTH_FRAME)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[tokio::test]
    async fn async_stream_read_frame_rejects_a_limit_above_the_library_ceiling() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _writer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let reader = listener.accept().await.unwrap().0;

        let mut stream = AsyncStream { socket: reader };
        let error = stream
            .read_frame_with_limit(MAX_COMMAND_FRAME + 1)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[tokio::test]
    async fn async_stream_read_frame_reports_a_truncated_payload() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut writer = tokio::net::TcpStream::connect(addr).await.unwrap();
        let reader = listener.accept().await.unwrap().0;

        writer.write_all(&4u32.to_le_bytes()).await.unwrap();
        writer.write_all(b"ab").await.unwrap();
        drop(writer);

        let mut stream = AsyncStream { socket: reader };
        let error = stream.read_frame_with_limit(4).await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTruncated)
        ));
    }
}
