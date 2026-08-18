//! One shared frame codec for the synchronous and asynchronous TCP socket
//! adapters (TcpTransportMigrationPlan WP2).
//!
//! Every framing invariant lives here: the little-endian `u32` wire length
//! prefix, the caller-selected maximum bound, the library-wide ceiling, the
//! before-allocation rejection of oversized frames, and the read-error
//! mapping for both I/O models. The blocking [`crate::Stream`] and Tokio
//! [`crate::AsyncStream`] adapters implement [`SyncFrameIo`] and
//! [`AsyncFrameIo`] respectively and delegate all frame read/write logic to
//! this codec, so neither adapter carries its own framing.
//!
//! The sync and async codec functions share every check; only the
//! byte-level I/O (blocking socket vs. Tokio stream) differs.

use error_stack::Report;
use protocol::auth::MAX_COMMAND_FRAME;

use crate::{TransportError, TransportResult};

/// Byte-level frame I/O for the blocking adapter.
pub(crate) trait SyncFrameIo {
    /// Reads exactly `buf.len()` bytes, mapping failures through
    /// [`map_sync_read_error`].
    fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()>;
    /// Writes all of `data`.
    fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()>;
    /// Flushes buffered output.
    fn flush_frame(&mut self) -> TransportResult<()>;
}

/// Byte-level frame I/O for the Tokio adapter.
pub(crate) trait AsyncFrameIo {
    /// Reads exactly `buf.len()` bytes, mapping failures through
    /// [`map_async_read_error`].
    async fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()>;
    /// Writes all of `data`.
    async fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()>;
    /// Flushes buffered output.
    async fn flush_frame(&mut self) -> TransportResult<()>;
}

/// Validates and encodes the wire length prefix for `length` under
/// `maximum`, rejecting payloads over the bound and lengths the `u32` wire
/// type cannot represent.
fn checked_frame_len(length: usize, maximum: usize) -> TransportResult<u32> {
    validate_frame_limit(maximum)?;
    if length > maximum {
        return Err(frame_too_large(length, maximum));
    }
    u32::try_from(length).map_err(|_| frame_too_large(length, u32::MAX as usize))
}

/// Rejects a caller-selected frame limit above the library ceiling.
fn validate_frame_limit(maximum: usize) -> TransportResult<()> {
    if maximum > MAX_COMMAND_FRAME {
        return Err(Report::new(TransportError::FrameTooLarge).attach(format!(
            "requested frame limit {maximum} exceeds library maximum {MAX_COMMAND_FRAME}"
        )));
    }
    Ok(())
}

fn frame_too_large(length: usize, maximum: usize) -> Report<TransportError> {
    Report::new(TransportError::FrameTooLarge).attach(format!(
        "declared frame length {length} exceeds maximum {maximum}"
    ))
}

fn frame_allocation(length: usize) -> Report<TransportError> {
    Report::new(TransportError::FrameAllocation)
        .attach(format!("could not reserve {length} frame bytes"))
}

/// Writes one length-prefixed frame through a sync adapter, rejecting the
/// payload before any byte is written when it exceeds `maximum`.
pub(crate) fn write_frame_limited(
    io: &mut impl SyncFrameIo,
    data: &[u8],
    maximum: usize,
) -> TransportResult<()> {
    let len = checked_frame_len(data.len(), maximum)?.to_le_bytes();
    io.write_frame_bytes(&len)?;
    io.write_frame_bytes(data)?;
    io.flush_frame()
}

/// Writes one length-prefixed frame through an async adapter, rejecting the
/// payload before any byte is written when it exceeds `maximum`.
pub(crate) async fn write_frame_limited_async(
    io: &mut impl AsyncFrameIo,
    data: &[u8],
    maximum: usize,
) -> TransportResult<()> {
    let len = checked_frame_len(data.len(), maximum)?.to_le_bytes();
    io.write_frame_bytes(&len).await?;
    io.write_frame_bytes(data).await?;
    io.flush_frame().await
}

/// Reads one frame through a sync adapter, rejecting its declared length
/// before allocation.
pub(crate) fn read_frame_with_limit(
    io: &mut impl SyncFrameIo,
    maximum: usize,
) -> TransportResult<Vec<u8>> {
    validate_frame_limit(maximum)?;
    let mut len_buf = [0u8; 4];
    io.read_frame_bytes(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > maximum {
        return Err(frame_too_large(len, maximum));
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(len)
        .map_err(|_| frame_allocation(len))?;
    payload.resize(len, 0);
    io.read_frame_bytes(&mut payload)?;
    Ok(payload)
}

/// Reads one frame through an async adapter, rejecting its declared length
/// before allocation.
pub(crate) async fn read_frame_with_limit_async(
    io: &mut impl AsyncFrameIo,
    maximum: usize,
) -> TransportResult<Vec<u8>> {
    validate_frame_limit(maximum)?;
    let mut len_buf = [0u8; 4];
    io.read_frame_bytes(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > maximum {
        return Err(frame_too_large(len, maximum));
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(len)
        .map_err(|_| frame_allocation(len))?;
    payload.resize(len, 0);
    io.read_frame_bytes(&mut payload).await?;
    Ok(payload)
}

pub(crate) fn map_async_read_error(error: std::io::Error) -> Report<TransportError> {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => Report::new(TransportError::FrameTruncated),
        std::io::ErrorKind::TimedOut => Report::new(error).change_context(TransportError::TimedOut),
        _ => Report::new(error).change_context(TransportError::ReadFrame),
    }
}

pub(crate) fn map_sync_read_error(error: std::io::Error) -> Report<TransportError> {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => Report::new(TransportError::FrameTruncated),
        // A blocking read with a set timeout reports `WouldBlock` on Unix and
        // `TimedOut` on Windows when the deadline expires.
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            Report::new(error).change_context(TransportError::TimedOut)
        }
        _ => Report::new(error).change_context(TransportError::ReadFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TEST_PAYLOAD: &[u8] = b"hello-framed-world";

    /// In-memory pipe exercising the shared codec directly, without any
    /// real socket: bytes "written" become the bytes the next read consumes.
    #[derive(Default)]
    struct MemoryIo {
        written: Vec<u8>,
        read_pos: usize,
        block_on_read: bool,
    }

    impl MemoryIo {
        fn feed(&mut self, bytes: &[u8]) {
            self.written.clear();
            self.written.extend_from_slice(bytes);
            self.read_pos = 0;
        }

        fn assert_written_len(&self, len: usize) {
            assert_eq!(self.written.len(), len);
        }
    }

    /// Mirrors `read_exact`: fill `buf` completely or fail at the first
    /// short read with `UnexpectedEof`.
    fn read_exact_from(memory: &mut MemoryIo, buf: &mut [u8]) -> TransportResult<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let remaining = memory.written.len() - memory.read_pos;
            if remaining == 0 {
                return Err(map_sync_read_error(std::io::Error::from(
                    std::io::ErrorKind::UnexpectedEof,
                )));
            }
            let n = remaining.min(buf.len() - filled);
            buf[filled..filled + n]
                .copy_from_slice(&memory.written[memory.read_pos..memory.read_pos + n]);
            memory.read_pos += n;
            filled += n;
        }
        Ok(())
    }

    impl SyncFrameIo for MemoryIo {
        fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()> {
            read_exact_from(self, buf)
        }

        fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()> {
            self.written.extend_from_slice(data);
            Ok(())
        }

        fn flush_frame(&mut self) -> TransportResult<()> {
            Ok(())
        }
    }

    impl AsyncFrameIo for MemoryIo {
        async fn read_frame_bytes(&mut self, buf: &mut [u8]) -> TransportResult<()> {
            if self.block_on_read {
                std::future::pending().await
            }
            read_exact_from(self, buf)
        }

        async fn write_frame_bytes(&mut self, data: &[u8]) -> TransportResult<()> {
            self.written.extend_from_slice(data);
            Ok(())
        }

        async fn flush_frame(&mut self) -> TransportResult<()> {
            Ok(())
        }
    }

    #[test]
    fn sync_codec_round_trip() {
        let mut io = MemoryIo::default();
        write_frame_limited(&mut io, TEST_PAYLOAD, MAX_COMMAND_FRAME).unwrap();
        assert_written_round_trip(&mut io);
    }

    #[tokio::test]
    async fn async_codec_round_trip() {
        let mut io = MemoryIo::default();
        write_frame_limited_async(&mut io, TEST_PAYLOAD, MAX_COMMAND_FRAME)
            .await
            .unwrap();
        assert_written_round_trip_async(&mut io).await;
    }

    #[test]
    fn sync_codec_rejects_oversized_payload_before_writing_any_bytes() {
        let mut io = MemoryIo::default();
        let error = write_frame_limited(&mut io, b"12345", 4).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
        io.assert_written_len(0);
    }

    #[tokio::test]
    async fn async_codec_rejects_oversized_payload_before_writing_any_bytes() {
        let mut io = MemoryIo::default();
        let error = write_frame_limited_async(&mut io, b"12345", 4)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
        io.assert_written_len(0);
    }

    #[test]
    fn sync_codec_rejects_declared_length_over_maximum() {
        let mut io = MemoryIo::default();
        io.feed(&(MAX_COMMAND_FRAME as u32 + 1).to_le_bytes());
        let error = read_frame_with_limit(&mut io, MAX_COMMAND_FRAME).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[tokio::test]
    async fn async_codec_rejects_declared_length_over_maximum() {
        let mut io = MemoryIo::default();
        io.feed(&(MAX_COMMAND_FRAME as u32 + 1).to_le_bytes());
        let error = read_frame_with_limit_async(&mut io, MAX_COMMAND_FRAME)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[test]
    fn sync_codec_rejects_a_limit_above_the_library_ceiling_before_reading() {
        let mut io = MemoryIo::default();
        let error = read_frame_with_limit(&mut io, MAX_COMMAND_FRAME + 1).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[tokio::test]
    async fn async_codec_rejects_a_limit_above_the_library_ceiling_before_reading() {
        let mut io = MemoryIo::default();
        let error = read_frame_with_limit_async(&mut io, MAX_COMMAND_FRAME + 1)
            .await
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTooLarge)
        ));
    }

    #[test]
    fn sync_codec_reports_a_truncated_frame() {
        let mut io = MemoryIo::default();
        io.feed(&[0x04, 0x00, 0x00, 0x00, b'a', b'b']);
        let error = read_frame_with_limit(&mut io, 4).unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTruncated)
        ));
    }

    #[tokio::test]
    async fn async_codec_reports_a_truncated_frame() {
        let mut io = MemoryIo::default();
        io.feed(&[0x04, 0x00, 0x00, 0x00, b'a', b'b']);
        let error = read_frame_with_limit_async(&mut io, 4).await.unwrap_err();
        assert!(matches!(
            error.downcast_ref(),
            Some(TransportError::FrameTruncated)
        ));
    }

    #[tokio::test]
    async fn async_codec_deadline_times_out_against_a_silent_source() {
        let mut io = MemoryIo {
            block_on_read: true,
            ..MemoryIo::default()
        };
        let error = tokio::time::timeout(
            Duration::from_millis(100),
            read_frame_with_limit_async(&mut io, MAX_COMMAND_FRAME),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, tokio::time::error::Elapsed { .. }));
    }

    fn assert_written_round_trip(io: &mut MemoryIo) {
        let written = std::mem::take(&mut io.written);
        io.feed(&written);
        let got = read_frame_with_limit(io, MAX_COMMAND_FRAME).unwrap();
        assert_eq!(got, TEST_PAYLOAD);
    }

    async fn assert_written_round_trip_async(io: &mut MemoryIo) {
        let written = std::mem::take(&mut io.written);
        io.feed(&written);
        let got = read_frame_with_limit_async(io, MAX_COMMAND_FRAME)
            .await
            .unwrap();
        assert_eq!(got, TEST_PAYLOAD);
    }
}
