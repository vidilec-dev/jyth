//! Blocking socket adapter for the TCP command channel
//! (TcpTransportMigrationPlan WP2).
//!
//! [`Stream`] wraps the blocking TCP socket and implements
//! [`crate::framing::SyncFrameIo`]; all framing invariants are enforced by
//! the shared codec in `crate::framing`, and this adapter only performs the
//! socket-specific plumbing (blocking mode, read timeouts).

use std::time::Duration;

use error_stack::Report;
use protocol::auth::MAX_COMMAND_FRAME;

use crate::framing::{self, SyncFrameIo};
use crate::{AsyncStream, TransportError, TransportResult};

/// Blocking TCP stream for a guest command connection.
pub(crate) type SyncSocket = std::net::TcpStream;

/// Blocking stream for a guest TCP command connection.
#[derive(Debug)]
pub struct Stream {
    pub(crate) socket: SyncSocket,
}

impl SyncFrameIo for Stream {
    fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()> {
        use std::io::Read;
        self.socket
            .set_nonblocking(false)
            .map_err(|e| Report::new(e).change_context(TransportError::ReadFrame))?;
        self.socket
            .read_exact(buf)
            .map_err(framing::map_sync_read_error)
    }

    fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()> {
        use std::io::Write;
        self.socket
            .set_nonblocking(false)
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))?;
        self.socket
            .write_all(data)
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }

    fn flush_frame(&mut self) -> TransportResult<()> {
        use std::io::Write;
        self.socket
            .flush()
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }
}

impl Stream {
    /// Converts this blocking stream into its async counterpart.
    pub fn into_async(self) -> TransportResult<AsyncStream> {
        self.socket
            .set_nonblocking(true)
            .map_err(|e| Report::new(e).change_context(TransportError::StreamConversion))?;
        let socket = tokio::net::TcpStream::from_std(self.socket)
            .map_err(|e| Report::new(e).change_context(TransportError::StreamConversion))?;
        Ok(AsyncStream { socket })
    }

    /// Writes raw bytes to the stream.
    pub fn write(&mut self, data: &[u8]) -> TransportResult<()> {
        use std::io::Write;
        self.socket
            .write_all(data)
            .map_err(|e| Report::new(e).change_context(TransportError::WriteFrame))
    }

    /// Reads up to 4096 raw bytes from the stream.
    pub fn read(&mut self) -> TransportResult<Vec<u8>> {
        use std::io::Read;
        let mut buf = vec![0; 4096];
        let n = self
            .socket
            .read(&mut buf)
            .map_err(|e| Report::new(e).change_context(TransportError::ReadFrame))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Writes a little-endian length-prefixed frame.
    pub fn write_frame(&mut self, data: &[u8]) -> TransportResult<()> {
        self.write_frame_limited(data, MAX_COMMAND_FRAME)
    }

    /// Writes a length-prefixed frame after checking its caller-selected
    /// maximum and the `u32` wire-length boundary.
    pub fn write_frame_limited(&mut self, data: &[u8], maximum: usize) -> TransportResult<()> {
        framing::write_frame_limited(self, data, maximum)
    }

    /// Reads one little-endian length-prefixed frame.
    pub fn read_frame(&mut self) -> TransportResult<Vec<u8>> {
        self.read_frame_with_limit(MAX_COMMAND_FRAME)
    }

    /// Reads one frame, rejecting its declared length before allocation.
    pub fn read_frame_with_limit(&mut self, maximum: usize) -> TransportResult<Vec<u8>> {
        framing::read_frame_with_limit(self, maximum)
    }

    /// Reads one frame bounded by a wall-clock deadline covering the whole
    /// read, then restores the caller's previous read-timeout configuration.
    /// Overflow surfaces [`TransportError::TimedOut`].
    pub fn read_frame_with_deadline(
        &mut self,
        maximum: usize,
        deadline: Duration,
    ) -> TransportResult<Vec<u8>> {
        self.socket
            .set_read_timeout(Some(deadline))
            .map_err(|e| Report::new(e).change_context(TransportError::ReadFrame))?;
        let result = self.read_frame_with_limit(maximum);
        self.socket
            .set_read_timeout(None)
            .map_err(|e| Report::new(e).change_context(TransportError::ReadFrame))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::{Stream, TransportError};
    use protocol::auth::{MAX_AUTH_FRAME, MAX_COMMAND_FRAME};
    use std::io::{Read, Write};
    use std::time::Duration;

    const TEST_PAYLOAD: &[u8] = b"hello-framed-world";

    #[test]
    fn stream_read_write_frame_roundtrip() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::net::TcpStream::connect(addr).unwrap();
        let reader = listener.accept().unwrap().0;

        let mut s = Stream { socket: writer };
        let mut r = Stream { socket: reader };

        s.write_frame(TEST_PAYLOAD).unwrap();
        let got = r.read_frame().unwrap();
        assert_eq!(got, TEST_PAYLOAD);
    }

    #[test]
    fn stream_read_frame_truncated_len_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut writer = std::net::TcpStream::connect(addr).unwrap();
        let reader = listener.accept().unwrap().0;

        writer.write_all(&[0x01, 0x02]).unwrap();
        drop(writer);

        let mut r = Stream { socket: reader };
        let err = r.read_frame().unwrap_err();
        assert!(matches!(
            err.downcast_ref(),
            Some(TransportError::FrameTruncated)
        ));
    }

    #[test]
    fn stream_read_frame_oversized_len_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut writer = std::net::TcpStream::connect(addr).unwrap();
        let reader = listener.accept().unwrap().0;

        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&u32::try_from(MAX_COMMAND_FRAME + 1).unwrap().to_le_bytes());
        writer.write_all(&buf).unwrap();

        let mut r = Stream { socket: reader };
        let err = r.read_frame().unwrap_err();
        assert!(matches!(
            err.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[test]
    fn stream_read_frame_rejects_an_auth_frame_over_its_limit() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut writer = std::net::TcpStream::connect(addr).unwrap();
        let reader = listener.accept().unwrap().0;

        writer
            .write_all(&u32::try_from(MAX_AUTH_FRAME + 1).unwrap().to_le_bytes())
            .unwrap();

        let mut stream = Stream { socket: reader };
        let error = stream.read_frame_with_limit(MAX_AUTH_FRAME).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[test]
    fn stream_read_frame_rejects_a_limit_above_the_library_ceiling_before_reading() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _writer = std::net::TcpStream::connect(addr).unwrap();
        let reader = listener.accept().unwrap().0;

        let mut stream = Stream { socket: reader };
        let error = stream
            .read_frame_with_limit(MAX_COMMAND_FRAME + 1)
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[test]
    fn stream_write_frame_rejects_payload_before_writing_any_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::net::TcpStream::connect(addr).unwrap();
        let mut reader = listener.accept().unwrap().0;

        let mut stream = Stream { socket: writer };
        let error = stream.write_frame_limited(b"12345", 4).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
        reader
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let mut byte = [0u8; 1];
        assert!(reader.read(&mut byte).is_err());
    }

    #[test]
    fn reply_read_with_deadline_times_out_against_a_silent_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let _server = listener.accept().unwrap().0;

        let mut stream = Stream { socket: client };
        let error = stream
            .read_frame_with_deadline(MAX_COMMAND_FRAME, Duration::from_millis(100))
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::TimedOut)
        ));
    }
}
