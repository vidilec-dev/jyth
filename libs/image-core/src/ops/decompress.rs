//! `ops::decompress` expands a locally materialized compressed artifact.
//!
//! The function reads a [`FileRef`] whose `artifact_type` is
//! [`Compressed`][crate::artifact::ty::ArtifactType::Compressed] and whose
//! `artifact_compression` is either
//! [`Gzip`][crate::artifact::compression::ArtifactCompression::Gzip] or
//! [`Zstd`][crate::artifact::compression::ArtifactCompression::Zstd]. It
//! streams the decompressed bytes into a temporary file adjacent to the
//! original artifact, computing BLAKE3 and the total size during the same
//! pass, sniffs the leading header of the decompressed payload, and stages
//! the result for publication.
//!
//! Publication is deliberately split from decompression: the caller commits
//! the new digest to the index first, then calls
//! [`StagedDecompress::publish`] to swap the staged bytes over the original
//! path. The compressed source therefore survives until the index update
//! succeeds; a failed update leaves the on-disk bytes matching the record,
//! so a retry never re-runs decompression over already-decompressed bytes.
//!
//! All blocking work — file I/O, decompression, header sniff — runs on
//! [`tokio::task::spawn_blocking`], so the operation never blocks an async
//! worker. The original compressed bytes are preserved until every check has
//! passed, so a decoder or classification failure leaves the storage entry
//! untouched.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use crate::artifact::compression::ArtifactCompression;
use crate::artifact::ty::ArtifactType;
use crate::ops::bounded_join;
use crate::ops::error::OperationError;
use crate::ops::format::{self, MIN_HEADER_LEN};
use crate::ops::io::{self, StagedFile, TempWriter};
use crate::storage::file_ref::FileRef;

/// Absolute bound on the decompressed output of a single artifact (4 GiB).
///
/// The declared/compressed size acts as a floor: an archive larger than the
/// bound is allowed to expand at least to its own size, so a legitimate
/// large layer is never rejected solely by the absolute cap. A crafted layer
/// whose compressed size is small but expands far beyond the bound fails
/// with [`OperationError::SizeMismatch`] before the temp file grows further.
const MAX_DECOMPRESSED_BYTES: u128 = 4 * 1024 * 1024 * 1024;

/// Decompressed output staged beside the compressed source.
///
/// The compressed bytes at the artifact's canonical path remain untouched
/// until [`StagedDecompress::publish`] swaps the staged bytes into place.
/// Callers must commit [`StagedDecompress::file_ref`] to the index *before*
/// publishing, so the compressed source survives until the index update
/// succeeds.
#[derive(Debug)]
pub struct StagedDecompress {
    file_ref: FileRef,
    staged: StagedFile,
}
impl StagedDecompress {
    /// The decompressed [`FileRef`] sharing the identity of the input entry.
    ///
    /// Callers persist this record via
    /// [`file_ref::update`][crate::storage::index::file_ref::update] before
    /// calling [`Self::publish`].
    pub fn file_ref(&self) -> &FileRef {
        &self.file_ref
    }

    /// Publish the staged decompressed bytes over the artifact's canonical
    /// path, returning the final [`FileRef`].
    ///
    /// The caller MUST have committed [`Self::file_ref`] to the index first.
    /// If the swap fails after the commit, the on-disk bytes no longer match
    /// the record and the record is invalidated on the next lookup — but the
    /// compressed source was never destroyed, so a retry re-decompresses
    /// from it successfully.
    pub fn publish(self) -> Result<FileRef, Report<OperationError>> {
        self.staged
            .publish()
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        Ok(self.file_ref)
    }
}

/// Decompress a locally materialized compressed artifact.
///
/// The returned [`StagedDecompress`] shares the UUID and namespace of
/// `entry`. Its `file_digest`, `artifact_type` and `artifact_compression`
/// reflect the decompressed payload: `artifact_compression` is always
/// [`ArtifactCompression::None`], and `artifact_type` is derived from the
/// recovered header bytes — TAR, CPIO `newc` and Linux bzImage are
/// recognized; any other payload is rejected as
/// [`UnsupportedArtifact`][OperationError::UnsupportedArtifact].
///
/// The caller is expected to persist the returned [`StagedDecompress`]'s
/// `file_ref` through
/// [`file_ref::update`][crate::storage::index::file_ref::update] and then
/// call [`StagedDecompress::publish`] to complete the operation.
pub async fn decompress(
    entry: FileRef,
    token: &CancellationToken,
) -> Result<StagedDecompress, Report<OperationError>> {
    // ---- Preconditions --------------------------------------------------
    //
    // Each precondition violation produces a specific `OperationError` so the
    // caller can distinguish a missing-on-disk entry from a tampered artifact
    // or an unsupported compression variant.
    let path = entry.path();
    if !path.exists() {
        return Err(OperationError::ReadSource
            .report()
            .attach(PathLabel(path.clone()))
            .attach("input file does not exist"));
    }

    if entry.artifact_type != ArtifactType::Compressed {
        return Err(OperationError::UnsupportedArtifact
            .report()
            .attach(PathLabel(path.clone()))
            .attach(format!(
                "expected ArtifactType::Compressed, got {:?}",
                entry.artifact_type
            )));
    }

    if entry.artifact_compression == ArtifactCompression::None {
        return Err(OperationError::UnsupportedCompression
            .report()
            .attach(PathLabel(path.clone()))
            .attach("ArtifactCompression::None is not decompressible"));
    }

    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                decompress_stage(&entry)
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

/// Blocking portion of [`decompress`]. Runs on `spawn_blocking`.
fn decompress_stage(entry: &FileRef) -> Result<StagedDecompress, Report<OperationError>> {
    let path = entry.path();

    // Verify and consume the input through one stable handle. Reopening the
    // path after verification would allow a replacement between the digest
    // check and decoder input.
    let mut source = File::open(&path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(path.clone()))
            .attach(err)
    })?;
    let actual = io::compute_file_digest_from_file(&mut source, &path)
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    if actual != entry.file_digest {
        return Err(OperationError::DigestMismatch
            .report()
            .attach(PathLabel(path.clone()))
            .attach(DigestPair {
                expected: entry.file_digest,
                actual,
            }));
    }

    source
        .seek(SeekFrom::Start(0))
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;

    // Write the result to a temporary file adjacent to the original path so
    // the eventual publish can rename within the same directory. The staged
    // bytes live at a distinct path: the compressed source at `path` is
    // preserved until the caller commits the index update and publishes.
    let mut writer = TempWriter::open(&path).map_err(|err| {
        OperationError::WriteDestination
            .report()
            .attach(PathLabel(path.clone()))
            .attach(err)
    })?;

    // Decode the compressed stream straight into the staging writer so the
    // decompressed payload is never buffered in memory. The decoder reads
    // from the source file handle and the writer computes BLAKE3 + size on
    // every chunk.
    let max_bytes = MAX_DECOMPRESSED_BYTES.max(entry.file_digest.file_size);
    match entry.artifact_compression {
        ArtifactCompression::Gzip => {
            let decoder = flate2::read::MultiGzDecoder::new(&mut source);
            stream_decode(decoder, &mut writer, &path, max_bytes)?;
        }
        ArtifactCompression::Zstd => {
            let decoder = zstd::Decoder::new(&mut source).map_err(|err| {
                OperationError::ReadSource
                    .report()
                    .attach(PathLabel(path.clone()))
                    .attach(err)
            })?;
            stream_decode(decoder, &mut writer, &path, max_bytes)?;
        }
        // Already rejected by `decompress`; kept for exhaustiveness.
        ArtifactCompression::None => unreachable!("precondition enforces a compression variant"),
    }

    writer.flush().map_err(|err| {
        OperationError::WriteDestination
            .report()
            .attach(PathLabel(path.clone()))
            .attach(err)
    })?;

    // Inspect the decompressed header *before* publishing so a payload of an
    // unknown format leaves the original compressed file untouched. The temp
    // writer's file handle is positioned at end-of-file; rewind it first.
    let staged = writer
        .stage()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    let temp_path = staged.temp_path().to_path_buf();
    let header = read_temp_header(&temp_path, MIN_HEADER_LEN).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(temp_path.clone()))
            .attach(err)
    })?;

    let detected = format::detect_or_unsupported(&header)?;
    let artifact_type = match detected.artifact_type {
        ArtifactType::ContainerTar | ArtifactType::ContainerCpio | ArtifactType::FileBzImage => {
            detected.artifact_type
        }
        // A decompressed payload that is itself a compressed stream is out of
        // scope: the caller is expected to chain another `decompress` call if
        // it ever becomes necessary, and `ArtifactType::Compressed` is never
        // reported as a successful inner format here.
        other => {
            return Err(OperationError::UnsupportedArtifact
                .report()
                .attach(PathLabel(path.clone()))
                .attach(format!("unsupported inner artifact type: {other:?}")));
        }
    };

    Ok(StagedDecompress {
        file_ref: FileRef {
            uuid: entry.uuid,
            namespace: entry.namespace,
            file_digest: staged.metadata.file_digest,
            artifact_type,
            artifact_compression: ArtifactCompression::None,
        },
        staged,
    })
}

/// Stream a decoder implementing [`Read`] into a [`TempWriter`], propagating
/// decoder failures (truncated streams, invalid checksums, residual bytes
/// that are not another valid member) as `ReadSource`.
///
/// The decompressed total is bounded by `max_bytes`: exceeding the bound is
/// a [`SizeMismatch`][OperationError::SizeMismatch] reported before the temp
/// file grows further.
fn stream_decode<D: Read>(
    mut decoder: D,
    writer: &mut TempWriter,
    source_path: &Path,
    max_bytes: u128,
) -> Result<(), Report<OperationError>> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = decoder.read(&mut buffer).map_err(|err| {
            OperationError::ReadSource
                .report()
                .attach(PathLabel(source_path.to_path_buf()))
                .attach(err)
        })?;
        if read == 0 {
            break;
        }
        let total = writer.bytes_written() + read as u128;
        if total > max_bytes {
            return Err(OperationError::SizeMismatch
                .report()
                .attach(PathLabel(source_path.to_path_buf()))
                .attach(format!(
                    "decompressed output exceeds the {max_bytes}-byte bound"
                )));
        }
        writer.write_all(&buffer[..read]).map_err(|err| {
            OperationError::WriteDestination
                .report()
                .attach(PathLabel(source_path.to_path_buf()))
                .attach(err)
        })?;
    }
    Ok(())
}

/// Read up to `len` bytes from the start of the temporary file. The temp
/// writer is flushed before this is called so the bytes are on disk.
fn read_temp_header(
    temp_path: &std::path::Path,
    len: usize,
) -> Result<Vec<u8>, error_stack::Report<crate::ops::error::TempFileError>> {
    io::read_header(temp_path, len)
}

/// A `PathBuf` wrapper that prints using `Path::display`, so it can be
/// attached to a `Report<OperationError>` even though `PathBuf` itself does
/// not implement `Display`.
#[derive(Debug, Clone)]
struct PathLabel(PathBuf);

impl std::fmt::Display for PathLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// A pair of expected and actual file digests attached to a digest-mismatch
/// report so callers can inspect the divergence without parsing the report
/// text.
#[derive(Debug, Clone, Copy)]
struct DigestPair {
    expected: crate::digest::FileDigest,
    actual: crate::digest::FileDigest,
}

impl std::fmt::Display for DigestPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected size {} hash {}, got size {} hash {}",
            self.expected.file_size,
            self.expected.file_hash,
            self.actual.file_size,
            self.actual.file_hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_pair_displays_expected_and_actual() {
        let expected = crate::digest::FileDigest {
            file_hash: blake3::hash(b"a"),
            file_size: 1,
        };
        let actual = crate::digest::FileDigest {
            file_hash: blake3::hash(b"b"),
            file_size: 2,
        };
        let text = format!("{}", DigestPair { expected, actual });
        assert!(text.contains("expected size 1"), "{text}");
        assert!(text.contains("got size 2"), "{text}");
    }

    #[test]
    fn stream_decode_rejects_output_beyond_the_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("out.bin");
        let mut writer = TempWriter::open(&destination).expect("open temp writer");
        let payload = vec![b'x'; 64 * 1024 + 1];
        let compressed = gzip_once(&payload);
        let decoder = flate2::read::GzDecoder::new(compressed.as_slice());

        let err = stream_decode(decoder, &mut writer, &destination, 1024)
            .expect_err("expansion beyond the bound must fail");

        assert!(matches!(
            err.current_context(),
            OperationError::SizeMismatch
        ));
        assert!(
            writer.bytes_written() <= 64 * 1024,
            "the temp file must not grow beyond one chunk past the bound"
        );
    }

    #[test]
    fn stream_decode_accepts_output_within_the_bound() {
        let dir = tempfile::tempdir().expect("temp dir");
        let destination = dir.path().join("out.bin");
        let mut writer = TempWriter::open(&destination).expect("open temp writer");
        let payload = b"small payload".to_vec();
        let compressed = gzip_once(&payload);
        let decoder = flate2::read::GzDecoder::new(compressed.as_slice());

        stream_decode(decoder, &mut writer, &destination, 1024).expect("within the bound");
        assert_eq!(writer.bytes_written(), payload.len() as u128);
    }

    fn gzip_once(payload: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::read::GzEncoder;
        let mut encoder = GzEncoder::new(payload, Compression::default());
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut encoder, &mut out).expect("encode gzip");
        out
    }
}
