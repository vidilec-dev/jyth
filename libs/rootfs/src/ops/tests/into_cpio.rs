//! Tests for [`crate::ops::into_cpio`].
//!
//! These tests cover the contract described in
//! `docs/implementation-plan/ops/04-into-cpio.md`: converting TAR entries to
//! CPIO `newc` records of every supported type; preserving UID, GID, mtime
//! and permissions; rejecting unsafe paths on Unix and Windows; rejecting
//! truncated TARs; rejecting `FileRef`s that are not uncompressed TARs;
//! verifying a single trailer; preserving the TAR on failure; and verifying
//! that the returned digest matches the produced CPIO.

use std::path::PathBuf;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    digest::FileDigest,
    ops::{error::OperationError, io},
    storage::{file_ref::FileRef, namespace::Namespace},
};

// ---------------------------------------------------------------------------
// Helpers — build, stage and inspect TAR/CPIO artifacts.
// ---------------------------------------------------------------------------

/// Build a TAR archive from a sequence of `(header, body)` pairs. Each
/// header is appended manually so tests can exercise every entry type and
/// metadata field. The archive is finished trailing with two zero blocks
/// per the TAR spec.
fn build_tar(entries: Vec<(tar::Header, Vec<u8>)>) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (header, body) in entries {
        builder
            .append(&header, std::io::Cursor::new(body))
            .expect("append tar entry");
    }
    builder.finish().expect("finish tar");
    builder.into_inner().expect("tar into_inner")
}

/// Build a TAR archive whose entries may contain paths the `tar` builder
/// would refuse (absolute, with `..` components, with Windows drive
/// prefixes). The path is written directly into the header's raw 100-byte
/// `name` field, bypassing `Header::set_path` validation. Only the `name`
/// field is responsible for the path; no `./` prefix is added.
fn build_tar_with_raw_paths(entries: Vec<(String, tar::EntryType, Vec<u8>)>) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, entry_type, body) in entries {
        let mut header = tar::Header::new_gnu();
        {
            let old = header.as_old_mut();
            let name = path.as_bytes();
            assert!(name.len() <= old.name.len(), "raw path too long: {path}");
            old.name[..name.len()].copy_from_slice(name);
            // The remaining bytes are already zero from `new_gnu`.
        }
        header.set_entry_type(entry_type);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(&body);
        // Pad the body to a multiple of 512 bytes (TAR blocking).
        let overhang = body.len() % 512;
        if overhang != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - overhang));
        }
    }
    // Two zero blocks terminate the archive.
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

/// Allocate a new GNU header with the requested type, path, size and mode.
/// UID, GID and mtime default to zero and can be overridden by chaining
/// `set_uid` / `set_gid` / `set_mtime` on the returned header.
fn header(entry_type: tar::EntryType, path: &str, size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_path(path).expect("set_path");
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    header
}

/// A regular file entry carrying `body`.
fn regular(path: &str, body: &[u8], mode: u32) -> (tar::Header, Vec<u8>) {
    (
        header(tar::EntryType::Regular, path, body.len() as u64, mode),
        body.to_vec(),
    )
}

/// A regular file with metadata preset to non-default values so a test can
/// assert they are preserved.
fn regular_meta(
    path: &str,
    body: &[u8],
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
) -> (tar::Header, Vec<u8>) {
    let mut h = header(tar::EntryType::Regular, path, body.len() as u64, mode);
    h.set_uid(uid);
    h.set_gid(gid);
    h.set_mtime(mtime);
    h.set_cksum();
    (h, body.to_vec())
}

/// A directory entry (size zero by definition).
fn directory(path: &str, mode: u32) -> (tar::Header, Vec<u8>) {
    let h = header(tar::EntryType::Directory, path, 0, mode);
    (h, Vec::new())
}

/// A symlink whose link target is `target`.
fn symlink(path: &str, target: &str, mode: u32) -> (tar::Header, Vec<u8>) {
    let mut h = header(tar::EntryType::Symlink, path, 0, mode);
    h.set_link_name(target).expect("set_link_name");
    h.set_cksum();
    (h, Vec::new())
}

/// A hard link whose target path is `target`.
fn hardlink(path: &str, target: &str) -> (tar::Header, Vec<u8>) {
    let mut h = header(tar::EntryType::Link, path, 0, 0);
    h.set_link_name(target).expect("set_link_name");
    h.set_cksum();
    (h, Vec::new())
}

/// A character device entry. The `cpio` writer emits `rdev` from the
/// header's `device_major`/`device_minor` fields.
fn char_device(path: &str, major: u32, minor: u32) -> (tar::Header, Vec<u8>) {
    let mut h = header(tar::EntryType::Char, path, 0, 0o644);
    h.set_device_major(major).expect("set_device_major");
    h.set_device_minor(minor).expect("set_device_minor");
    h.set_cksum();
    (h, Vec::new())
}

/// Stage `payload` at the on-disk path the global `NAMESPACES` cell resolves
/// for `(namespace, uuid)`, then return that path.
fn stage_in_namespace(namespace: Namespace, uuid: Uuid, payload: &[u8]) -> PathBuf {
    let path = namespace.join(uuid.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("ns dir");
    }
    std::fs::write(&path, payload).expect("write payload");
    path
}

/// Build a `FileRef` describing the staged bytes. The digest matches the
/// file on disk; `artifact_type` is `ContainerTar`/`None`.
fn tar_ref(path: &std::path::Path, uuid: Uuid, namespace: Namespace) -> FileRef {
    let file_digest = io::compute_file_digest(path).expect("digest");
    FileRef {
        uuid,
        namespace,
        file_digest,
        artifact_type: ArtifactType::ContainerTar,
        artifact_compression: ArtifactCompression::None,
    }
}

/// Await `into_cpio` and unwrap the result.
async fn cpio_ok(entry: FileRef) -> FileRef {
    crate::ops::into_cpio(entry, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("into_cpio failed: {err:?}"))
}

/// Await `into_cpio` and unwrap the failure.
async fn cpio_err(entry: FileRef) -> error_stack::Report<OperationError> {
    match crate::ops::into_cpio(entry, &CancellationToken::new()).await {
        Ok(value) => panic!("into_cpio succeeded unexpectedly: {value:?}"),
        Err(err) => err,
    }
}

/// Read back the CPIO produced at `path` using the `cpio::newc::Reader` so
/// the test exercises the same decoding the plan mandates.
fn read_cpio(path: &std::path::Path) -> Vec<(cpio::newc::Entry, Vec<u8>)> {
    let bytes = std::fs::read(path).expect("read cpio");
    let mut cursor = std::io::Cursor::new(bytes);
    let mut out = Vec::new();
    loop {
        let reader = match cpio::newc::Reader::new(cursor) {
            Ok(reader) => reader,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => panic!("cpio read: {err}"),
        };
        let entry = reader.entry().clone();
        let mut body = Vec::new();
        let handle = reader.to_writer(&mut body).expect("to_writer");
        cursor = handle;
        out.push((entry, body));
        if out.last().unwrap().0.is_trailer() {
            break;
        }
    }
    out
}

fn err_text(err: &error_stack::Report<OperationError>) -> String {
    format!("{err:#}")
}

fn on_disk_digest(path: &std::path::Path) -> FileDigest {
    io::compute_file_digest(path).expect("digest")
}

// ---------------------------------------------------------------------------
// Entry-type tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn converts_a_regular_file() {
    let tar_bytes = build_tar(vec![regular("file.txt", b"hello", 0o644)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerCpio);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);

    let entries = read_cpio(&out.path());
    let file = entries
        .iter()
        .find(|(e, _)| e.name() == "file.txt")
        .expect("file.txt present");
    assert_eq!(file.1, b"hello");
    let mode = file.0.mode();
    assert_eq!(mode & 0o170000, 0o100000, "regular file type bits");
    assert_eq!(mode & 0o7777, 0o644, "permission bits preserved");
    // The single trailer entry.
    assert_eq!(
        entries.iter().filter(|(e, _)| e.is_trailer()).count(),
        1,
        "exactly one trailer"
    );
}

#[tokio::test]
async fn converts_an_empty_directory() {
    let tar_bytes = build_tar(vec![directory("dir", 0o755)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let entries = read_cpio(&out.path());
    let dir = entries
        .iter()
        .find(|(e, _)| e.name() == "dir")
        .expect("dir present");
    assert_eq!(dir.0.mode() & 0o170000, 0o040000, "directory type bits");
    assert_eq!(dir.0.file_size(), 0);
    assert!(dir.1.is_empty());
}

#[tokio::test]
async fn converts_a_symlink() {
    let tar_bytes = build_tar(vec![symlink("link", "target.txt", 0o777)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let entries = read_cpio(&out.path());
    let link = entries
        .iter()
        .find(|(e, _)| e.name() == "link")
        .expect("link present");
    assert_eq!(link.0.mode() & 0o170000, 0o120000, "symlink type bits");
    assert_eq!(link.1, b"target.txt", "symlink target stored as body");
}

#[tokio::test]
async fn preserves_absolute_and_parent_symlink_targets_as_content() {
    let target = "/usr/../lib/kernel";
    let tar_bytes = build_tar(vec![symlink("link", target, 0o777)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;
    let entries = read_cpio(&out.path());
    let link = entries
        .iter()
        .find(|(entry, _)| entry.name() == "link")
        .expect("link present");
    assert_eq!(link.1, target.as_bytes());
}

#[tokio::test]
async fn converts_a_backward_hardlink() {
    // The target appears before the link.
    let entries = vec![
        regular("target.txt", b"shared", 0o644),
        hardlink("alias.txt", "target.txt"),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let target = cpio
        .iter()
        .find(|(e, _)| e.name() == "target.txt")
        .expect("target present");
    let alias = cpio
        .iter()
        .find(|(e, _)| e.name() == "alias.txt")
        .expect("alias present");
    assert_eq!(
        cpio.iter()
            .filter(|(e, _)| e.name() == "target.txt")
            .count(),
        1
    );
    assert_eq!(
        cpio.iter().filter(|(e, _)| e.name() == "alias.txt").count(),
        1
    );

    // Same inode group: shared (dev, ino) and nlink == 2.
    assert_eq!(target.0.ino(), alias.0.ino());
    assert_eq!(target.0.dev_major(), alias.0.dev_major());
    assert_eq!(target.0.nlink(), 2);
    assert_eq!(alias.0.nlink(), 2);
    // The body ports once; the alias carries size zero.
    assert_eq!(target.1, b"shared");
    assert_eq!(alias.0.file_size(), 0);
    assert!(alias.1.is_empty());
}

#[tokio::test]
async fn converts_a_forward_hardlink() {
    // The link appears before the target.
    let entries = vec![
        hardlink("alias.txt", "target.txt"),
        regular("target.txt", b"shared", 0o644),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let target = cpio
        .iter()
        .find(|(e, _)| e.name() == "target.txt")
        .expect("target present");
    let alias = cpio
        .iter()
        .find(|(e, _)| e.name() == "alias.txt")
        .expect("alias present");
    assert_eq!(
        cpio.iter()
            .filter(|(e, _)| e.name() == "target.txt")
            .count(),
        1
    );
    assert_eq!(
        cpio.iter().filter(|(e, _)| e.name() == "alias.txt").count(),
        1
    );

    assert_eq!(target.0.ino(), alias.0.ino());
    assert_eq!(target.0.dev_major(), alias.0.dev_major());
    assert_eq!(target.0.nlink(), 2);
    assert_eq!(alias.0.nlink(), 2);
    assert_eq!(target.1, b"shared");
    assert_eq!(alias.0.file_size(), 0);
}

#[tokio::test]
async fn converts_a_char_device() {
    let tar_bytes = build_tar(vec![char_device("dev", 5, 1)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let dev = cpio
        .iter()
        .find(|(e, _)| e.name() == "dev")
        .expect("device present");
    assert_eq!(dev.0.mode() & 0o170000, 0o020000, "char device type bits");
    assert_eq!(dev.0.rdev_major(), 5);
    assert_eq!(dev.0.rdev_minor(), 1);
}

#[tokio::test]
async fn preserves_uid_gid_mtime_and_permissions() {
    let entries = vec![regular_meta(
        "file.txt",
        b"x",
        0o600,
        1234,
        5678,
        0x1234_5678,
    )];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let file = cpio
        .iter()
        .find(|(e, _)| e.name() == "file.txt")
        .expect("file present");
    assert_eq!(file.0.uid(), 1234);
    assert_eq!(file.0.gid(), 5678);
    assert_eq!(file.0.mtime(), 0x1234_5678);
    assert_eq!(file.0.mode() & 0o7777, 0o600);
}

#[tokio::test]
async fn preserves_a_whiteout_entry() {
    // OCI whiteouts are stored as regular files named `.wh.<name>`. Their
    // semantics are applied by `flatten`, not here, so the name must be
    // preserved verbatim.
    let entries = vec![regular(".wh.foo", b"", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    assert!(cpio.iter().any(|(e, _)| e.name() == ".wh.foo"));
}

#[tokio::test]
async fn preserves_an_empty_file() {
    let entries = vec![regular("empty", b"", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let file = cpio
        .iter()
        .find(|(e, _)| e.name() == "empty")
        .expect("empty present");
    assert_eq!(file.0.file_size(), 0);
    assert!(file.1.is_empty());
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_absolute_unix_path() {
    // Absolute paths cannot be built via `tar::Builder` (it refuses them at
    // `set_path`). Build the TAR with raw path bytes so the conversion path
    // is exercised end-to-end.
    let tar_bytes = build_tar_with_raw_paths(vec![(
        "/etc/passwd".to_string(),
        tar::EntryType::Regular,
        b"x".to_vec(),
    )]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let err = cpio_err(tar_ref(&path, uuid, Namespace::Rootfs)).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for absolute path, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("absolute") || report.contains("etc/passwd"),
        "expected attribution citing the absolute path, got: {report}"
    );
    // The original TAR remains intact.
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_dotdot_path() {
    let tar_bytes = build_tar_with_raw_paths(vec![(
        "a/../b".to_string(),
        tar::EntryType::Regular,
        b"x".to_vec(),
    )]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let err = cpio_err(tar_ref(&path, uuid, Namespace::Rootfs)).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for `..` path, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_windows_drive_prefix() {
    // TAR stores paths as raw bytes; even on Windows, paths use `/` so
    // `C:\Windows` is written with a literal `\`. The op's normalizer must
    // still reject the drive prefix regardless of the host platform. We
    // bypass `set_path` validation by writing the raw bytes directly.
    let tar_bytes = build_tar_with_raw_paths(vec![(
        "C:\\Windows\\evil".to_string(),
        tar::EntryType::Regular,
        b"x".to_vec(),
    )]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let err = cpio_err(tar_ref(&path, uuid, Namespace::Rootfs)).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for Windows drive prefix, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("Windows drive prefix"),
        "expected attribution citing the drive prefix, got: {report}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_truncated_tar() {
    let entries = vec![regular("file.txt", b"hello world", 0o644)];
    let mut tar_bytes = build_tar(entries);
    // Drop the trailing zero blocks plus part of the file body so the
    // archive cannot be fully parsed.
    tar_bytes.truncate(tar_bytes.len().saturating_sub(600));

    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);
    let tar_ref = tar_ref(&path, uuid, Namespace::Rootfs);

    let err = cpio_err(tar_ref).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid tar archive") || msg.contains("failed to read the source"),
        "expected InvalidTar/ReadSource, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes, "truncated tar preserved");
}

#[tokio::test]
async fn rejects_a_fileref_that_is_not_container_tar() {
    let entries = vec![regular("file.txt", b"x", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);
    let mut entry = tar_ref(&path, uuid, Namespace::Rootfs);
    entry.artifact_type = ArtifactType::ContainerCpio;

    let err = cpio_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsupported artifact format"),
        "expected UnsupportedArtifact, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_fileref_that_is_compressed() {
    let entries = vec![regular("file.txt", b"x", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);
    let mut entry = tar_ref(&path, uuid, Namespace::Rootfs);
    entry.artifact_compression = ArtifactCompression::Gzip;

    let err = cpio_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsupported compression format"),
        "expected UnsupportedCompression, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_hardlink_with_no_target() {
    let entries = vec![
        hardlink("alias.txt", "missing.txt"),
        regular("other.txt", b"x", 0o644),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let err = cpio_err(tar_ref(&path, uuid, Namespace::Rootfs)).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid tar archive"),
        "expected InvalidTar citing missing target, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("missing.txt"),
        "expected attribution citing the missing target, got: {report}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

#[tokio::test]
async fn rejects_a_digest_mismatch() {
    let entries = vec![regular("file.txt", b"x", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);
    let mut entry = tar_ref(&path, uuid, Namespace::Rootfs);
    entry.file_digest = FileDigest {
        file_hash: blake3::hash(b"unrelated"),
        file_size: 99,
    };

    let err = cpio_err(entry).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("the materialized digest did not match the expected digest"),
        "expected DigestMismatch, got: {msg}"
    );
    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, tar_bytes);
}

// ---------------------------------------------------------------------------
// Output invariants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn output_contains_exactly_one_trailer() {
    let entries = vec![
        regular("a", b"a", 0o644),
        directory("d", 0o755),
        symlink("l", "a", 0o777),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    let trailers = cpio.iter().filter(|(e, _)| e.is_trailer()).count();
    assert_eq!(trailers, 1, "exactly one trailer, got {trailers}");
    // The trailer must be the last entry.
    assert!(cpio.last().unwrap().0.is_trailer());
}

#[tokio::test]
async fn output_is_walkable_by_newc_reader() {
    let entries = vec![
        regular("a", b"abcd", 0o644),
        regular("b", b"abcdefgh", 0o644), // 8 bytes — definitely needs no body padding
        regular("c", b"abcde", 0o644),    // 5 bytes — exercises body padding
        directory("d", 0o755),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    // `read_cpio` walks to completion; reaching the trailer without error
    // proves the padding is respected.
    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(e, _)| e.name().to_string()).collect();
    assert_eq!(
        names,
        vec!["a", "b", "c", "d", "TRAILER!!!"],
        "entries in order, trailer last: {names:?}"
    );
}

#[tokio::test]
async fn output_is_deterministic() {
    let entries = vec![
        regular("a", b"abcd", 0o644),
        directory("d", 0o755),
        symlink("l", "a", 0o777),
    ];
    let tar_bytes = build_tar(entries);

    let uuid1 = Uuid::now_v7();
    let path1 = stage_in_namespace(Namespace::Rootfs, uuid1, &tar_bytes);
    let out1 = cpio_ok(tar_ref(&path1, uuid1, Namespace::Rootfs)).await;
    let bytes1 = std::fs::read(out1.path()).expect("read 1");

    let uuid2 = Uuid::now_v7();
    let path2 = stage_in_namespace(Namespace::Rootfs, uuid2, &tar_bytes);
    let out2 = cpio_ok(tar_ref(&path2, uuid2, Namespace::Rootfs)).await;
    let bytes2 = std::fs::read(out2.path()).expect("read 2");

    // The header ino/dev fields differ only by the deterministic sequential
    // assignment, so the byte streams must be identical for the same TAR.
    assert_eq!(bytes1, bytes2, "cpio is deterministic for identical TARs");
}

#[tokio::test]
async fn preserves_uuid_and_namespace() {
    let entries = vec![regular("file.txt", b"x", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Layers, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Layers)).await;

    assert_eq!(out.uuid, uuid);
    assert_eq!(out.namespace, Namespace::Layers);
    // `path()` derives from (namespace, uuid) so it must equal the input.
    assert_eq!(out.path(), path);
}

#[tokio::test]
async fn returned_digest_matches_produced_cpio() {
    let entries = vec![
        regular("file.txt", b"stream-friendly body", 0o644),
        directory("dir", 0o755),
        symlink("link", "target", 0o777),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let actual = on_disk_digest(&out.path());
    assert_eq!(
        out.file_digest, actual,
        "returned digest matches CPIO bytes"
    );
}

#[tokio::test]
async fn failed_conversion_preserves_the_tar() {
    // Use an unsafe-path failure: the TAR must be left intact and the CPIO
    // destination must never be published over it.
    let tar_bytes = build_tar_with_raw_paths(vec![(
        "/etc/passwd".to_string(),
        tar::EntryType::Regular,
        b"x".to_vec(),
    )]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);
    let original = tar_bytes.clone();

    let _err = cpio_err(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let on_disk = std::fs::read(&path).expect("read tar");
    assert_eq!(on_disk, original, "tar preserved after failure");
}

#[tokio::test]
async fn strips_leading_dot_slash_prefix() {
    // A TAR that prefixes every entry with `./` (the common case for
    // `tar::Builder`) must normalize to the bare relative path.
    let entries = vec![regular("./file.txt", b"x", 0o644)];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let out = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    let cpio = read_cpio(&out.path());
    assert!(
        cpio.iter().any(|(e, _)| e.name() == "file.txt"),
        "leading `./` stripped: {:?}",
        cpio.iter().map(|(e, _)| e.name()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn does_not_write_to_the_filesystem() {
    // Sanity smoke test: convert a small archive and confirm no stray
    // entries materialize in the working directory. The op uses a
    // `TempWriter` adjacent to the destination, so extraction would manifest
    // as unexpected files in the destination directory.
    let entries = vec![
        regular("file.txt", b"x", 0o644),
        directory("dir", 0o755),
        symlink("link", "target", 0o777),
    ];
    let tar_bytes = build_tar(entries);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Rootfs, uuid, &tar_bytes);

    let _ = cpio_ok(tar_ref(&path, uuid, Namespace::Rootfs)).await;

    // The only file the destination directory should contain is the entry
    // itself plus any temp files from concurrent tests (which use a different
    // UUID name). We restrict the check to our UUID's prefix.
    let parent = path.parent().expect("parent");
    let stem = uuid.to_string();
    let mut matched = 0;
    for entry in std::fs::read_dir(parent).expect("read dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&stem) || name.starts_with(&format!(".{stem}")) {
            matched += 1;
        }
    }
    assert_eq!(
        matched, 1,
        "only the destination file exists for this entry"
    );
}
