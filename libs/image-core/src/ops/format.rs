//! Artifact format detection for materialization operations.
//!
//! Each operation needs to identify an artifact's container format before it
//! can decide which transformation to apply. [`detect`] inspects the
//! smallest possible header slice and returns an [`ArtifactType`]/[
//! [`ArtifactCompression`] pair, or `None` when the bytes do not match any
//! known format, so callers translate the unknown case into an
//! [`UnsupportedArtifact`][crate::ops::error::OperationError::UnsupportedArtifact]
//! failure with the source attached as needed.

use crate::artifact::{compression::ArtifactCompression, ty::ArtifactType};
use crate::ops::error::OperationError;

/// Minimum number of bytes required for header sniffing.
///
/// The largest single fixed header is the Linux bzImage check at offset
/// `0x202 + 4`. We additionally allow TAR detection to inspect a 512-byte
/// block when present.
pub const MIN_HEADER_LEN: usize = 0x206;

/// Result of an artifact sniff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detected {
    pub artifact_type: ArtifactType,
    pub artifact_compression: ArtifactCompression,
}

/// Detect the artifact format from a leading header slice.
///
/// `bytes` may be shorter than [`MIN_HEADER_LEN`]; the function inspects only
/// the offsets that are actually present. A slice that matches no known
/// signature yields `Ok(None)`.
pub fn detect(bytes: &[u8]) -> Result<Option<Detected>, error_stack::Report<OperationError>> {
    if let Some(detected) = detect_compression(bytes) {
        return Ok(Some(detected));
    }

    if let Some(detected) = detect_container(bytes) {
        return Ok(Some(detected));
    }

    Ok(None)
}

fn detect_compression(bytes: &[u8]) -> Option<Detected> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return Some(Detected {
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::Gzip,
        });
    }
    if bytes.len() >= 4 && bytes[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        return Some(Detected {
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::Zstd,
        });
    }
    None
}

fn detect_container(bytes: &[u8]) -> Option<Detected> {
    if is_cpio_newc(bytes) {
        return Some(Detected {
            artifact_type: ArtifactType::ContainerCpio,
            artifact_compression: ArtifactCompression::None,
        });
    }

    if is_linux_bzimage(bytes) {
        return Some(Detected {
            artifact_type: ArtifactType::FileBzImage,
            artifact_compression: ArtifactCompression::None,
        });
    }

    if is_tar(bytes) {
        return Some(Detected {
            artifact_type: ArtifactType::ContainerTar,
            artifact_compression: ArtifactCompression::None,
        });
    }

    None
}

fn is_cpio_newc(bytes: &[u8]) -> bool {
    if bytes.len() < 6 {
        return false;
    }
    let magic = &bytes[..6];
    magic == b"070701" || magic == b"070702"
}

fn is_linux_bzimage(bytes: &[u8]) -> bool {
    if bytes.len() <= 0x1fe {
        return false;
    }
    if bytes[0x1fe] != 0x55 || bytes[0x1ff] != 0xaa {
        return false;
    }
    if bytes.len() < 0x206 {
        return false;
    }
    bytes[0x202..0x206] == *b"HdrS"
}

fn is_tar(bytes: &[u8]) -> bool {
    if bytes.len() < 512 {
        return false;
    }

    // A valid empty TAR is two zero blocks and has no ordinary header
    // checksum to validate.
    if bytes[..512].iter().all(|byte| *byte == 0) {
        return bytes.len() >= 1024 && bytes[..1024].iter().all(|byte| *byte == 0);
    }
    if !valid_tar_checksum(&bytes[..512]) {
        return false;
    }

    // `entries()` is lazy; advance the iterator so the archive parser must
    // validate the first header and its size fields instead of merely
    // constructing an `Archive` around arbitrary bytes.
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let Ok(mut entries) = archive.entries() else {
        return false;
    };
    match entries.next() {
        Some(Ok(_entry)) => true,
        Some(Err(_)) => false,
        None => false,
    }
}

fn valid_tar_checksum(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    let Some(stored) = parse_tar_octal(&header[148..156]) else {
        return false;
    };
    let calculated: u32 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as u32
            } else {
                *byte as u32
            }
        })
        .sum();
    stored == calculated
}

fn parse_tar_octal(bytes: &[u8]) -> Option<u32> {
    let trimmed = bytes
        .iter()
        .copied()
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if trimmed.is_empty() || trimmed.iter().any(|byte| !(*byte >= b'0' && *byte <= b'7')) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(&trimmed).ok()?, 8).ok()
}

/// Sniff and translate the unknown case into an `UnsupportedArtifact` error.
pub fn detect_or_unsupported(
    bytes: &[u8],
) -> Result<Detected, error_stack::Report<OperationError>> {
    match detect(bytes)? {
        Some(detected) => Ok(detected),
        None => Err(OperationError::UnsupportedArtifact.report()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_gzip_header() {
        let bytes = [0x1f, 0x8b, 0x08, 0x00];
        let detected = detect(&bytes).unwrap().expect("gzip detected");
        assert_eq!(detected.artifact_type, ArtifactType::Compressed);
        assert_eq!(detected.artifact_compression, ArtifactCompression::Gzip);
    }

    #[test]
    fn detects_zstd_header() {
        let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0x00];
        let detected = detect(&bytes).unwrap().expect("zstd detected");
        assert_eq!(detected.artifact_type, ArtifactType::Compressed);
        assert_eq!(detected.artifact_compression, ArtifactCompression::Zstd);
    }

    #[test]
    fn detects_cpio_newc_magic() {
        let bytes = b"070701".to_vec();
        let detected = detect(&bytes).unwrap().expect("cpio detected");
        assert_eq!(detected.artifact_type, ArtifactType::ContainerCpio);
    }

    #[test]
    fn detects_linux_bzimage_signature() {
        let mut bytes = vec![0u8; 0x206];
        bytes[0x1fe] = 0x55;
        bytes[0x1ff] = 0xaa;
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        let detected = detect(&bytes).unwrap().expect("bzImage detected");
        assert_eq!(detected.artifact_type, ArtifactType::FileBzImage);
    }

    #[test]
    fn detects_tar_ustar_magic() {
        let mut header = tar::Header::new_ustar();
        header.set_path("file").expect("path");
        header.set_size(0);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        let bytes = header.as_bytes().to_vec();
        let detected = detect(&bytes).unwrap().expect("tar detected");
        assert_eq!(detected.artifact_type, ArtifactType::ContainerTar);
    }

    #[test]
    fn rejects_tar_magic_with_an_invalid_header_checksum() {
        let mut bytes = vec![0u8; 512];
        bytes[257..263].copy_from_slice(b"ustar\0");
        bytes[148..156].copy_from_slice(b"0000000\0");
        assert!(detect(&bytes).unwrap().is_none());
    }

    #[test]
    fn detects_an_empty_tar() {
        let bytes = vec![0u8; 1024];
        let detected = detect(&bytes).unwrap().expect("empty tar detected");
        assert_eq!(detected.artifact_type, ArtifactType::ContainerTar);
    }

    #[test]
    fn unknown_bytes_yield_unsupported() {
        let bytes = [0u8; 4];
        let err = detect_or_unsupported(&bytes).expect_err("unsupported");
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported artifact format"), "{msg}");
    }
}
