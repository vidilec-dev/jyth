//! Tests for [`crate::ops::decompress`].
//!
//! These tests cover the contract described in
//! `docs/implementation-plan/ops/03-decompress.md`: decompressing Gzip and
//! Zstandard payloads of TAR, CPIO and bzImage kinds; handling concatenated
//! Gzip members; rejecting truncated or corrupt streams; rejecting
//! `ArtifactCompression::None`; rejecting a `FileDigest` that does not match
//! the input; rejecting a payload of an unknown format; preserving the
//! compressed bytes on failure; and verifying that UUID/namespace are stable
//! and the returned digest matches the decompressed file.

use std::io::Read;
use std::path::PathBuf;

use uuid::Uuid;

use super::super::decompress as decompress_op;
use crate::artifact::{compression::ArtifactCompression, ty::ArtifactType};
use crate::digest::FileDigest;
use crate::storage::file_ref::FileRef;
use crate::storage::namespace::Namespace;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fixtures (mirror the `load` test helpers so the payloads are byte-identical
// in shape to those used by materialization).
// ---------------------------------------------------------------------------

/// A minimal valid TAR archive whose leading header contains a single small
/// entry. `format::is_tar` recognises the `ustar` magic at offset 257.
fn tar_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("entry").expect("path");
    header.set_size(3);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, std::io::Cursor::new(b"abc"))
        .expect("append");
    builder.finish().expect("finish");
    builder.into_inner().expect("into_inner")
}

/// A CPIO `newc` archive with a single small entry. The leading `070701`
/// magic is what `format::is_cpio_newc` recognises.
fn cpio_archive() -> Vec<u8> {
    use cpio::{NewcBuilder, write_cpio};
    let entry = std::io::Cursor::new(b"payload".to_vec());
    let builder = NewcBuilder::new("entry.bin")
        .ino(1)
        .mode(0o644)
        .nlink(1)
        .uid(0)
        .gid(0)
        .mtime(0)
        .dev_major(0)
        .dev_minor(0)
        .rdev_major(0)
        .rdev_minor(0);
    let inputs = vec![(builder, entry)];
    let mut output = Vec::new();
    write_cpio(inputs.into_iter(), &mut output).expect("write_cpio");
    output
}

/// A minimal bzImage with the boot flag `55 aa` at `0x1fe` and the `HdrS`
/// signature at `0x202`.
fn bzimage_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x220];
    bytes[0x1fe] = 0x55;
    bytes[0x1ff] = 0xaa;
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    bytes
}

/// Gzip-encode `payload` exactly once using `flate2::read::GzEncoder`.
fn gzip_once(payload: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::read::GzEncoder;
    let mut encoder = GzEncoder::new(payload, Compression::default());
    let mut out = Vec::new();
    encoder.read_to_end(&mut out).expect("encode gzip");
    out
}

/// Concatenate two gzip members so `MultiGzDecoder` must consume both.
fn gzip_concatenated(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = gzip_once(a);
    out.extend(gzip_once(b));
    out
}

/// Zstandard-encode `payload`.
fn zstd_bytes(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 0).expect("encode zstd")
}

/// Build a `FileRef` for the compressed bytes at `path`. The digest is the
/// actual BLAKE3 of the file on disk; `artifact_type` is `Compressed`.
fn compressed_ref(
    path: &std::path::Path,
    uuid: Uuid,
    namespace: Namespace,
    compression: ArtifactCompression,
) -> FileRef {
    let file_digest = crate::ops::io::compute_file_digest(path).expect("digest");
    FileRef {
        uuid,
        namespace,
        file_digest,
        artifact_type: ArtifactType::Compressed,
        artifact_compression: compression,
    }
}

/// Write `payload` to the on-disk destination path that the running test
/// process' `NAMESPACES` lazy cell resolves for the chosen namespace and
/// `uuid`, and return that path.
///
/// `cargo test` runs with `CARGO_MANIFEST_DIR` set, so `NAMESPACES` uses
/// `target/.jyth/<namespace>/<uuid>`. `FileRef::path()` derives from
/// `Namespace::join(uuid)`, which reads the same global lazy cell, so the
/// path the op inspects matches the bytes the test staged. Each test uses a
/// freshly generated UUID so concurrent tests never collide.
fn stage_in_global_namespace(namespace: Namespace, uuid: Uuid, payload: &[u8]) -> PathBuf {
    let path = namespace.join(uuid.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("ns dir");
    }
    std::fs::write(&path, payload).expect("write payload");
    path
}

/// Run a `decompress` call expecting success, publish the staged output and
/// return the resulting `FileRef`, panicking with the report text on failure.
async fn decompress_ok(entry: FileRef) -> FileRef {
    let staged = decompress_op::decompress(entry, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("decompress failed: {err:?}"));
    staged
        .publish()
        .unwrap_or_else(|err| panic!("publishing staged decompression failed: {err:?}"))
}

/// Run a `decompress` call expecting failure and return the report.
async fn decompress_err(entry: FileRef) -> error_stack::Report<crate::ops::error::OperationError> {
    match decompress_op::decompress(entry, &CancellationToken::new()).await {
        Ok(value) => panic!("decompress succeeded unexpectedly: {value:?}"),
        Err(err) => err,
    }
}

/// Extract the leading `OperationError` display text from a `Report`.
fn err_text(err: &error_stack::Report<crate::ops::error::OperationError>) -> String {
    format!("{err:#}")
}

/// Compute the BLAKE3 digest of an on-disk file using the same algorithm the
/// op uses, so tests can assert that the returned digest matches the
/// decompressed bytes.
fn on_disk_digest(path: &std::path::Path) -> FileDigest {
    crate::ops::io::compute_file_digest(path).expect("digest")
}

// ---------------------------------------------------------------------------
// Gzip tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decompresses_gzip_tar() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let out = decompress_ok(entry).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerTar);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);
    assert_eq!(out.uuid, uuid);
    assert_eq!(out.namespace, Namespace::Layers);
    assert!(out.path().exists());
    assert_eq!(out.file_digest, on_disk_digest(&out.path()));
    assert_eq!(out.file_digest.file_size, inner.len() as u128);
}

#[tokio::test]
async fn decompresses_gzip_cpio() {
    let inner = cpio_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let out = decompress_ok(entry).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerCpio);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);
    assert_eq!(out.file_digest, on_disk_digest(&out.path()));
}

#[tokio::test]
async fn decompresses_gzip_bzimage() {
    let inner = bzimage_bytes();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Kernel, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Kernel, ArtifactCompression::Gzip);

    let out = decompress_ok(entry).await;

    assert_eq!(out.artifact_type, ArtifactType::FileBzImage);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);
    assert_eq!(out.file_digest, on_disk_digest(&out.path()));
}

#[tokio::test]
async fn decompresses_two_concatenated_gzip_members() {
    let a = tar_archive();
    let b = cpio_archive();
    let payload = gzip_concatenated(&a, &b);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    // The first member's header determines the resulting artifact type. The
    // decoder must still consume both members without error.
    let out = decompress_ok(entry).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerTar);
    let decompressed = std::fs::read(out.path()).expect("read decompressed");
    let mut expected = a.clone();
    expected.extend_from_slice(&b);
    assert_eq!(decompressed, expected);
    assert_eq!(out.file_digest.file_size, expected.len() as u128);
}

// ---------------------------------------------------------------------------
// Zstandard tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decompresses_zstd_tar() {
    let inner = tar_archive();
    let payload = zstd_bytes(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Zstd);

    let out = decompress_ok(entry).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerTar);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);
    assert_eq!(out.uuid, uuid);
    assert_eq!(out.namespace, Namespace::Layers);
    assert_eq!(out.file_digest, on_disk_digest(&out.path()));
    assert_eq!(out.file_digest.file_size, inner.len() as u128);
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_truncated_gzip() {
    let inner = tar_archive();
    let mut payload = gzip_once(&inner);
    // Truncate the trailing bytes (the gzip CRC32 + ISIZE footer) so the
    // decoder cannot validate the stream.
    let truncated_len = payload.len().saturating_sub(8).max(1);
    payload.truncate(truncated_len);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let err = decompress_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("failed to read the source"),
        "expected ReadSource, got: {msg}"
    );
    // The original compressed bytes must survive the failure.
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn rejects_corrupt_zstd_frame() {
    let inner = tar_archive();
    let mut payload = zstd_bytes(&inner);
    // Corrupt the leading zstd magic number so the decoder cannot even
    // construct a frame reader; the first four bytes of a zstd frame are
    // `28 b5 2f fd`.
    payload[0] ^= 0xff;
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Zstd);

    let err = decompress_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("failed to read the source"),
        "expected ReadSource, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn rejects_artifact_compression_none() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    // Build a FileRef where the declared compression is `None`: this is
    // semantically not a valid input to `decompress`.
    let file_digest = crate::ops::io::compute_file_digest(&path).expect("digest");
    let entry = FileRef {
        uuid,
        namespace: Namespace::Layers,
        file_digest,
        artifact_type: ArtifactType::Compressed,
        artifact_compression: ArtifactCompression::None,
    };

    let err = decompress_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsupported compression format"),
        "expected UnsupportedCompression, got: {msg}"
    );
    // The original file remains in place because we never even opened it.
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn rejects_mismatched_file_digest() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    // Build a FileRef whose declared digest does not match the bytes on disk.
    let bogus = FileDigest {
        file_hash: blake3::hash(b"unrelated"),
        file_size: 99,
    };
    let entry = FileRef {
        uuid,
        namespace: Namespace::Layers,
        file_digest: bogus,
        artifact_type: ArtifactType::Compressed,
        artifact_compression: ArtifactCompression::Gzip,
    };

    let err = decompress_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("the materialized digest did not match the expected digest"),
        "expected DigestMismatch, got: {msg}"
    );
    // The original compressed file must be intact.
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn rejects_unknown_inner_format() {
    // A decompressed payload that matches no known signature: a few zero
    // bytes are recognized by neither `detect_compression` nor
    // `detect_container`.
    let inner = vec![0u8; 64];
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let err = decompress_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsupported artifact format"),
        "expected UnsupportedArtifact, got: {msg}"
    );
    // A failure inside classification must preserve the compressed file.
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn error_preserves_compressed_file() {
    // Use a truncated gzip stream so the decoder fails after writing some
    // bytes; the temp file must be cleaned up and the original compressed
    // stream must remain untouched.
    let inner = tar_archive();
    let mut payload = gzip_once(&inner);
    payload.truncate(payload.len().saturating_sub(8).max(1));
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let original = payload.clone();
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let _err = decompress_err(entry).await;

    // No stray temporary file for *our* entry remains inside the namespace
    // directory. Other tests running in parallel create their own temp files
    // for their own UUIDs; filter only for the temp file named after this
    // entry, which uses the pattern `.{uuid}.tmp-{random}` per `TempWriter`.
    let parent = path.parent().expect("parent");
    let stem = uuid.to_string();
    let prefix = format!(".{stem}.tmp-");
    let temps: Vec<_> = std::fs::read_dir(parent)
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect();
    assert!(temps.is_empty(), "leftover temp files for entry: {temps:?}");

    // The original compressed bytes are intact.
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, original);
}

#[tokio::test]
async fn preserves_uuid_and_namespace() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Kernel, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Kernel, ArtifactCompression::Gzip);

    let out = decompress_ok(entry).await;

    assert_eq!(out.uuid, uuid);
    assert_eq!(out.namespace, Namespace::Kernel);
    // `path()` is derived from (namespace, uuid) so it must equal the input.
    assert_eq!(out.path(), path);
}

#[tokio::test]
async fn returned_digest_matches_decompressed_file() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let out = decompress_ok(entry).await;

    let actual = on_disk_digest(&out.path());
    assert_eq!(out.file_digest, actual);
    // And the decompressed bytes match the inner payload we encoded.
    let on_disk = std::fs::read(out.path()).expect("read decompressed");
    assert_eq!(on_disk, inner);
}

#[tokio::test]
async fn compressed_source_survives_until_the_staged_output_is_published() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    // Stage the decompression without publishing: the canonical path must
    // still hold the compressed bytes so a caller can commit the index
    // update before the swap.
    let staged = decompress_op::decompress(entry, &CancellationToken::new())
        .await
        .expect("staged decompression");
    assert_eq!(staged.file_ref().uuid, uuid);
    assert_eq!(staged.file_ref().namespace, Namespace::Layers);
    let on_disk = std::fs::read(&path).expect("read canonical path");
    assert_eq!(
        on_disk, payload,
        "the compressed source must survive until the staged output is published"
    );
    let staged_siblings: Vec<_> = std::fs::read_dir(path.parent().expect("parent"))
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&format!(".{uuid}.tmp-")))
        .collect();
    assert_eq!(
        staged_siblings.len(),
        1,
        "the staged decompressed bytes must be on disk: {staged_siblings:?}"
    );

    // Publishing swaps the staged bytes over the canonical path.
    let out = staged.publish().expect("publish staged decompression");
    assert_eq!(out.path(), path);
    let on_disk = std::fs::read(&path).expect("read decompressed");
    assert_eq!(on_disk, inner);
}

#[tokio::test]
async fn dropping_the_staged_output_preserves_the_compressed_source() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);

    let staged = decompress_op::decompress(entry, &CancellationToken::new())
        .await
        .expect("staged decompression");
    let parent = path.parent().expect("parent").to_path_buf();
    drop(staged);

    let temps: Vec<_> = std::fs::read_dir(&parent)
        .expect("read dir")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&format!(".{uuid}.tmp-")))
        .collect();
    assert!(
        temps.is_empty(),
        "the staged temp must be cleaned up: {temps:?}"
    );
    let on_disk = std::fs::read(&path).expect("read original");
    assert_eq!(on_disk, payload, "the compressed source must remain intact");
}

/// A pre-cancelled token makes the blocking closure bail at entry: the
/// operation fails fast with `OperationError::Cancelled` instead of touching
/// the source (spec capability `blocking-cancellation`, cancelled-closure
/// scenario).
#[tokio::test]
async fn cancelled_token_returns_cancelled_fast() {
    let inner = tar_archive();
    let payload = gzip_once(&inner);
    let uuid = Uuid::now_v7();
    let path = stage_in_global_namespace(Namespace::Layers, uuid, &payload);
    let entry = compressed_ref(&path, uuid, Namespace::Layers, ArtifactCompression::Gzip);
    let token = CancellationToken::new();
    token.cancel();

    let err = decompress_op::decompress(entry, &token)
        .await
        .expect_err("a cancelled operation must fail");
    assert!(
        matches!(
            err.current_context(),
            crate::ops::error::OperationError::Cancelled
        ),
        "expected Cancelled, got: {err:#}"
    );
}
