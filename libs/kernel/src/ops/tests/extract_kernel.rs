//! Tests for [`crate::ops::extract_kernel`].
//!
//! These tests cover the contract described in
//! `docs/implementation-plan/ops/06-extract-kernel.md`: extracting
//! `boot/vmlinuz` from an uncompressed CPIO; normalizing `./boot/vmlinuz`
//! and `boot/vmlinuz` to the same path; rejecting basename-only searches;
//! resolving hard-link groups; reporting `KernelNotFound` for absent
//! entries; rejecting absolute or `..`-bearing request paths; rejecting
//! empty paths; rejecting bytes without the boot flag or the `HdrS`
//! signature; rejecting truncated CPIOs; preserving the source CPIO; and
//! verifying that the returned digest matches the published bzImage.

use std::io::Write;
use std::path::PathBuf;

use uuid::Uuid;

use crate::ops;
use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    digest::{FileDigest, LinkDigest},
    ops::{error::OperationError, io},
    storage::{file_ref::FileRef, link_ref::LinkRef, namespace::Namespace},
};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// CPIO + bzImage helpers
// ---------------------------------------------------------------------------

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;

/// Minimum number of bytes required for a bzImage signature check.
const MIN_BZIMAGE_LEN: usize = 0x206;

/// Build a vector of bytes that pass the bzImage signature check (boot flag
/// `55 aa` at `0x1fe`, `HdrS` magic at `0x202`). The payload is padded with
/// arbitrary deterministic bytes after the signature so the test exercises
/// the streaming copy and the digest computation.
fn bzimage_body(extra_after_signature: usize) -> Vec<u8> {
    let len = MIN_BZIMAGE_LEN + extra_after_signature;
    let mut bytes = vec![0u8; len];
    bytes[0x1fe] = 0x55;
    bytes[0x1ff] = 0xaa;
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    // Fill the post-signature region with a recognizable pattern so a test
    // can verify that the published body is intact.
    for (i, byte) in bytes.iter_mut().enumerate().skip(MIN_BZIMAGE_LEN) {
        *byte = (i as u8).wrapping_mul(0x1f);
    }
    bytes
}

/// Entry specification mirroring the one used by `flatten.rs` tests. We
/// keep a private copy so this module stays independent of the flatten
/// test helpers.
struct EntrySpec {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    dev_major: u32,
    ino: u32,
    nlink: u32,
    rdev_major: u32,
    rdev_minor: u32,
    body: Vec<u8>,
}

impl EntrySpec {
    fn regular(name: &str, body: &[u8], mode: u32) -> Self {
        Self {
            name: name.to_string(),
            mode: mode | S_IFREG,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major: 0,
            ino: 0,
            nlink: 1,
            rdev_major: 0,
            rdev_minor: 0,
            body: body.to_vec(),
        }
    }

    /// A regular file with an explicit `(dev_major, ino)` identity so two
    /// entries can form a hard-link group as recognized by the extract
    /// driver.
    fn regular_with_inode(
        name: &str,
        body: &[u8],
        mode: u32,
        dev_major: u32,
        ino: u32,
        nlink: u32,
    ) -> Self {
        Self {
            name: name.to_string(),
            mode: mode | S_IFREG,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major,
            ino,
            nlink,
            rdev_major: 0,
            rdev_minor: 0,
            body: body.to_vec(),
        }
    }

    /// A hard-link duplicate whose name shares the canonical owner's
    /// `(dev_major, ino)` identity. The duplicate carries an empty body
    /// because the canonical owner emits the bytes.
    fn hardlink_dup(name: &str, dev_major: u32, ino: u32, nlink: u32) -> Self {
        Self {
            name: name.to_string(),
            mode: 0o644 | S_IFREG,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major,
            ino,
            nlink,
            rdev_major: 0,
            rdev_minor: 0,
            body: Vec::new(),
        }
    }

    fn directory(name: &str, mode: u32) -> Self {
        Self {
            name: name.to_string(),
            mode: mode | S_IFDIR,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major: 0,
            ino: 0,
            nlink: 1,
            rdev_major: 0,
            rdev_minor: 0,
            body: Vec::new(),
        }
    }

    fn symlink(name: &str, target: &[u8], mode: u32) -> Self {
        Self {
            name: name.to_string(),
            mode: mode | S_IFLNK,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major: 0,
            ino: 0,
            nlink: 1,
            rdev_major: 0,
            rdev_minor: 0,
            body: target.to_vec(),
        }
    }

    fn char_device(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mode: 0o644 | S_IFCHR,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major: 0,
            ino: 0,
            nlink: 1,
            rdev_major: 5,
            rdev_minor: 1,
            body: Vec::new(),
        }
    }

    fn fifo(name: &str) -> Self {
        Self {
            name: name.to_string(),
            mode: 0o644 | S_IFIFO,
            uid: 0,
            gid: 0,
            mtime: 0,
            dev_major: 0,
            ino: 0,
            nlink: 1,
            rdev_major: 0,
            rdev_minor: 0,
            body: Vec::new(),
        }
    }
}

/// Encode a list of entry specs into a complete `newc` archive terminated
/// by the single `TRAILER!!!` entry. Mirrors the encoding used in
/// `flatten.rs` tests so two hard-linked entries can share `(dev_major, ino)`.
fn build_cpio(entries: &[EntrySpec]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    {
        let mut writer_ref: &mut Vec<u8> = &mut output;
        for entry in entries {
            let builder = cpio::NewcBuilder::new(&entry.name)
                .ino(entry.ino)
                .mode(entry.mode)
                .uid(entry.uid)
                .gid(entry.gid)
                .nlink(entry.nlink)
                .mtime(entry.mtime)
                .dev_major(entry.dev_major)
                .dev_minor(0)
                .rdev_major(entry.rdev_major)
                .rdev_minor(entry.rdev_minor);
            let writer = builder.write(writer_ref, entry.body.len() as u32);
            let mut writer = writer;
            writer.write_all(&entry.body).expect("write body");
            writer_ref = writer.finish().expect("finish entry padding");
        }
        cpio::newc::trailer(writer_ref).expect("trailer");
    }
    output
}

/// Hand-encode a single `newc` entry whose name is taken verbatim. Used so a
/// test can write a name that bypasses any normalization performed by the
/// CPIO encoder helpers. The body is emitted as-is, and the archive is
/// terminated with the standard `TRAILER!!!` entry.
fn build_cpio_with_raw_path(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    {
        let writer_ref: &mut Vec<u8> = &mut output;
        let builder = cpio::NewcBuilder::new(name)
            .ino(1)
            .mode(mode)
            .nlink(1)
            .uid(0)
            .gid(0)
            .mtime(0)
            .dev_major(0)
            .dev_minor(0)
            .rdev_major(0)
            .rdev_minor(0);
        let writer = builder.write(writer_ref, body.len() as u32);
        let mut writer = writer;
        writer.write_all(body).expect("write body");
        let writer_ref = writer.finish().expect("finish body padding");
        cpio::newc::trailer(writer_ref).expect("trailer");
    }
    output
}

/// Hand-encode a CPIO archive that contains exactly the trailer plus
/// additional adversarial trailing bytes after it. The `cpio::newc::trailer`
/// helper writes the trailer entry; we then append the extra bytes
/// afterwards to simulate a second trailer or trailing structural garbage.
fn build_cpio_with_trailing_bytes(entries: &[EntrySpec], trailing: &[u8]) -> Vec<u8> {
    let mut output = build_cpio(entries);
    output.extend_from_slice(trailing);
    output
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

/// Build a `FileRef` describing the staged CPIO bytes. The digest matches the
/// file on disk; `artifact_type` is `ContainerCpio` + `None`.
fn cpio_ref(path: &std::path::Path, uuid: Uuid, namespace: Namespace) -> FileRef {
    let file_digest = io::compute_file_digest(path).expect("digest");
    FileRef {
        uuid,
        namespace,
        file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    }
}

/// Build a `LinkRef` targetting the kernel namespace. The link_digest is a
/// placeholder BLAKE3 hash; the operation only consults the namespace and
/// the uuid.
fn kernel_link_ref(uuid: Uuid) -> LinkRef {
    LinkRef {
        uuid,
        namespace: Namespace::Kernel,
        link_digest: LinkDigest {
            link_hash: blake3::hash(&[]),
            file_size: 0,
        },
    }
}

/// Await `extract_kernel` and unwrap the resulting `FileRef`.
async fn extract_ok(path: &str, src: &FileRef, dst: &LinkRef) -> FileRef {
    ops::extract_kernel(path, src, dst, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("extract_kernel failed: {err:?}"))
}

/// Await `extract_kernel` and unwrap the failure.
async fn extract_err(
    path: &str,
    src: &FileRef,
    dst: &LinkRef,
) -> error_stack::Report<OperationError> {
    match ops::extract_kernel(path, src, dst, &CancellationToken::new()).await {
        Ok(value) => panic!("extract_kernel succeeded unexpectedly: {value:?}"),
        Err(err) => err,
    }
}

fn err_text(err: &error_stack::Report<OperationError>) -> String {
    format!("{err:#}")
}

fn on_disk_digest(path: &std::path::Path) -> FileDigest {
    io::compute_file_digest(path).expect("digest")
}

// ---------------------------------------------------------------------------
// Happy path: extract `boot/vmlinuz`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extracts_boot_vmlinuz_from_a_cpio() {
    let kernel = bzimage_body(64);
    let entries = vec![
        EntrySpec::directory("boot", 0o755),
        EntrySpec::regular("boot/vmlinuz", &kernel, 0o644),
        EntrySpec::regular("etc/issue", b"hello", 0o644),
    ];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let out = extract_ok("boot/vmlinuz", &src, &dst).await;

    assert_eq!(out.artifact_type, ArtifactType::FileBzImage);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);
    assert_eq!(out.namespace, Namespace::Kernel);
    assert_eq!(out.uuid, dst.uuid);

    let on_disk = std::fs::read(out.path()).expect("read kernel");
    assert_eq!(on_disk, kernel, "published bytes match the extracted body");
}

// ---------------------------------------------------------------------------
// `./boot/vmlinuz` and `boot/vmlinuz` normalize to the same entry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn normalizes_leading_dot_slash_to_the_same_entry() {
    let kernel = bzimage_body(7);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);

    // Request the prefixed form; the on-disk entry uses the bare form.
    let dst = kernel_link_ref(Uuid::now_v7());
    let out = extract_ok("./boot/vmlinuz", &src, &dst).await;

    let on_disk = std::fs::read(out.path()).expect("read kernel");
    assert_eq!(
        on_disk, kernel,
        "normalized request resolves the bare entry"
    );
}

// ---------------------------------------------------------------------------
// Reject a basename-only search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_basename_only_search() {
    let kernel = bzimage_body(7);
    // The archive contains `boot/vmlinuz`, not the bare `vmlinuz`.
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("kernel entry not found") || msg.contains("KernelNotFound"),
        "expected KernelNotFound for a basename search, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Resolve a hard-link group where the requested name is the duplicate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolves_a_hard_link_group_for_the_requested_name() {
    let kernel = bzimage_body(32);
    // Two names share the same `(dev_major, ino)`. The requested name
    // (`boot/vmlinuz`) is the size-zero duplicate; the canonical owner
    // (`lib/kernel`) carries the body.
    let entries = vec![
        EntrySpec::hardlink_dup("boot/vmlinuz", 7, 19, 2),
        EntrySpec::regular_with_inode("lib/kernel", &kernel, 0o644, 7, 19, 2),
    ];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let out = extract_ok("boot/vmlinuz", &src, &dst).await;

    let on_disk = std::fs::read(out.path()).expect("read kernel");
    assert_eq!(on_disk, kernel, "duplicate resolved to the canonical body");
}

#[tokio::test]
async fn resolves_a_hard_link_group_when_the_body_precedes_the_request() {
    let kernel = bzimage_body(33);
    // The canonical body is encountered first; the requested name is the
    // later size-zero member. Extraction must remember the body rather than
    // depending on the duplicate appearing before its target.
    let entries = vec![
        EntrySpec::regular_with_inode("lib/kernel", &kernel, 0o644, 7, 20, 2),
        EntrySpec::hardlink_dup("boot/vmlinuz", 7, 20, 2),
    ];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let out = extract_ok("boot/vmlinuz", &src, &dst).await;

    assert_eq!(std::fs::read(out.path()).expect("read kernel"), kernel);
}

// ---------------------------------------------------------------------------
// `KernelNotFound` for a path that is not present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn returns_kernel_not_found_for_an_absent_path() {
    let kernel = bzimage_body(5);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/missing", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("kernel entry not found") || msg.contains("KernelNotFound"),
        "expected KernelNotFound, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Reject an absolute request path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_absolute_request_path() {
    let kernel = bzimage_body(5);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("/boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for an absolute path, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("absolute"),
        "expected attribution citing the absolute path, got: {report}"
    );
    // Source CPIO remains intact.
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject a request path containing `..`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_dotdot_request_path() {
    let kernel = bzimage_body(5);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("a/../boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for a `..` path, got: {msg}"
    );
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject an empty request path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_empty_request_path() {
    let kernel = bzimage_body(5);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path") || msg.contains("empty"),
        "expected UnsafePath for an empty path, got: {msg}"
    );
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject a body without the boot flag
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_body_without_the_boot_flag() {
    // Same length as a valid bzImage, but with a zeroed boot flag and no
    // `HdrS` magic.
    let mut body = vec![0u8; MIN_BZIMAGE_LEN + 16];
    body[0x202..0x206].copy_from_slice(b"HdrS");
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &body, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
        "expected InvalidKernel for a missing boot flag, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("boot flag"),
        "expected attribution citing the boot flag, got: {report}"
    );
    // The destination must never have been published for a failed kernel.
    assert!(
        !dst.namespace.join(dst.uuid.to_string()).exists(),
        "destination was not published for a rejected body"
    );
    // Source CPIO remains intact.
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject a body without the `HdrS` magic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_body_without_the_hdrs_magic() {
    let mut body = vec![0u8; MIN_BZIMAGE_LEN + 16];
    body[0x1fe] = 0x55;
    body[0x1ff] = 0xaa;
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &body, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
        "expected InvalidKernel for a missing HdrS magic, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("HdrS"),
        "expected attribution citing the HdrS magic, got: {report}"
    );
    assert!(
        !dst.namespace.join(dst.uuid.to_string()).exists(),
        "destination was not published for a rejected body"
    );
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject a body too short to be a bzImage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_body_too_short_to_validate() {
    let body = vec![0u8; 0x10];
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &body, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
        "expected InvalidKernel for a short body, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("too short"),
        "expected attribution citing the short body, got: {report}"
    );
    assert!(
        !dst.namespace.join(dst.uuid.to_string()).exists(),
        "destination was not published for a short body"
    );
}

// ---------------------------------------------------------------------------
// Reject a CPIO truncated mid-entry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_truncated_cpio() {
    // Build an archive with unrelated entries and a kernel entry last; we
    // request an absent path so the walk must traverse past the unrelated
    // entries (and the truncated body) before failing. Truncating inside
    // an entry's body guarantees the walk encounters a structural error.
    let kernel = bzimage_body(64);
    let entries = vec![
        EntrySpec::regular(
            "etc/issue",
            b"hello world this is a longer payload that the truncation will land inside",
            0o644,
        ),
        EntrySpec::regular("boot/vmlinuz", &kernel, 0o644),
    ];
    let mut payload = build_cpio(&entries);
    // Truncate inside the first entry's body so the walk errors while
    // draining that entry's bytes (the CPIO reader returns `UnexpectedEof`
    // from the padding drain, which `finish_reader` surfaces as `InvalidCpio`).
    payload.truncate(110 + 12 + 8);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("absent/path", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid cpio") || msg.contains("failed to read the source"),
        "expected InvalidCpio/ReadSource for a truncated archive, got: {msg}"
    );
    // The destination remains unpublished.
    assert!(
        !dst.namespace.join(dst.uuid.to_string()).exists(),
        "destination was not published for a truncated CPIO"
    );
    // Source CPIO remains intact (the failure happens after a read error, but
    // the op never writes to the source path).
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, payload);
}

// ---------------------------------------------------------------------------
// Reject a second trailer or trailing structural bytes after the trailer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_structural_bytes_after_the_trailer() {
    let kernel = bzimage_body(32);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    // Append extra bytes after the trailer to simulate a second trailer or
    // trailing garbage.
    let payload = build_cpio_with_trailing_bytes(&entries, &[0u8; 32]);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    // The requested entry exists before the trailer, but the archive is not
    // valid until the complete stream has been checked through EOF.
    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid cpio") || msg.contains("structural bytes"),
        "{msg}"
    );
    assert!(!dst.namespace.join(dst.uuid.to_string()).exists());
}

// ---------------------------------------------------------------------------
// Source CPIO remains intact after a successful extraction
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_cpio_remains_intact_after_a_successful_extraction() {
    let kernel = bzimage_body(64);
    let entries = vec![
        EntrySpec::directory("boot", 0o755),
        EntrySpec::regular("boot/vmlinuz", &kernel, 0o644),
        EntrySpec::regular("etc/issue", b"hello", 0o644),
    ];
    let payload = build_cpio(&entries);
    let original = payload.clone();
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let _out = extract_ok("boot/vmlinuz", &src, &dst).await;

    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, original, "source CPIO is unchanged");
}

// ---------------------------------------------------------------------------
// Source CPIO remains intact after a KernelNotFound failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_cpio_remains_intact_after_a_not_found_failure() {
    let kernel = bzimage_body(16);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let original = payload.clone();
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let _err = extract_err("boot/absent", &src, &dst).await;

    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, original);
}

// ---------------------------------------------------------------------------
// Returned digest matches the published bzImage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn returned_digest_matches_the_published_bzimage() {
    let kernel = bzimage_body(300);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let out = extract_ok("boot/vmlinuz", &src, &dst).await;

    let actual = on_disk_digest(&out.path());
    assert_eq!(
        out.file_digest, actual,
        "returned digest matches published bytes"
    );
    assert_eq!(actual.file_size, kernel.len() as u128);
}

// ---------------------------------------------------------------------------
// Reject a request naming a directory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_directory_target() {
    let entries = vec![EntrySpec::directory("boot/vmlinuz", 0o755)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
        "expected InvalidKernel for a directory target, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("directory"),
        "expected attribution citing the directory type, got: {report}"
    );
}

// ---------------------------------------------------------------------------
// Reject a request naming a symlink
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_symlink_target() {
    let entries = vec![EntrySpec::symlink("boot/vmlinuz", b"../target", 0o777)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
        "expected InvalidKernel for a symlink target, got: {msg}"
    );
    let report = format!("{err:#?}");
    assert!(
        report.contains("symlink"),
        "expected attribution citing the symlink type, got: {report}"
    );
}

// ---------------------------------------------------------------------------
// Reject a request naming a device or a FIFO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_device_or_fifo_target() {
    for entry in [
        EntrySpec::char_device("boot/vmlinuz"),
        EntrySpec::fifo("boot/vmlinuz"),
    ] {
        let payload = build_cpio(&[entry]);
        let src_uuid = Uuid::now_v7();
        let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
        let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
        let dst = kernel_link_ref(Uuid::now_v7());

        let err = extract_err("boot/vmlinuz", &src, &dst).await;
        let msg = err_text(&err);
        assert!(
            msg.contains("do not satisfy the bzImage contract") || msg.contains("InvalidKernel"),
            "expected InvalidKernel for a non-regular target, got: {msg}"
        );
    }
}

// ---------------------------------------------------------------------------
// Reject requests with raw `..` segments in the CPIO entry name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_unsafe_entry_names_in_the_source_cpio() {
    // A `..`-bearing entry name in the CPIO must be rejected during the
    // walk even if the request path is benign.
    let raw = build_cpio_with_raw_path("../escape", S_IFREG | 0o644, b"hello");
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &raw);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let err = extract_err("boot/vmlinuz", &src, &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path") || msg.contains("invalid cpio"),
        "expected UnsafePath/InvalidCpio for a malicious entry name, got: {msg}"
    );
    let on_disk = std::fs::read(&src_path).expect("read source");
    assert_eq!(on_disk, raw);
}

// ---------------------------------------------------------------------------
// Path-derived equality: the published path equals `FileRef::path()` of the
// result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_published_path_is_equal_to_fileref_path() {
    let kernel = bzimage_body(7);
    let entries = vec![EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());
    let dst_uuid = dst.uuid;

    let out = extract_ok("boot/vmlinuz", &src, &dst).await;

    let expected = Namespace::Kernel.join(dst_uuid.to_string());
    assert_eq!(
        out.path(),
        expected,
        "the published path equals FileRef::path"
    );
    assert!(expected.exists(), "the published path exists on disk");
}

// ---------------------------------------------------------------------------
// Does not materialize other entries onto the host filesystem
// ---------------------------------------------------------------------------

#[tokio::test]
async fn does_not_materialize_other_entries_on_the_host() {
    let kernel = bzimage_body(8);
    let entries = vec![
        EntrySpec::directory("boot", 0o755),
        EntrySpec::regular("boot/vmlinuz", &kernel, 0o644),
        EntrySpec::regular("etc/passwd", b"root:x:0:0:root:/root:/bin/sh", 0o644),
    ];
    let payload = build_cpio(&entries);
    let src_uuid = Uuid::now_v7();
    let src_path = stage_in_namespace(Namespace::Layers, src_uuid, &payload);
    let src = cpio_ref(&src_path, src_uuid, Namespace::Layers);
    let dst = kernel_link_ref(Uuid::now_v7());

    let _out = extract_ok("boot/vmlinuz", &src, &dst).await;

    // The kernel namespace must contain the destination file. We deliberately
    // avoid scanning the whole namespace directory: concurrent tests share
    // the same on-disk kernel dir with their own UUIDs, so a global scan
    // would race. Instead we assert that no stray files matching our own
    // destination stem survive (a leftover temp file would be a bug in
    // TempWriter, which removes its temp path on drop).
    let namespaces = &image_core::storage::namespace::NAMESPACES;
    let kernel_dir = namespaces.kernel.clone();
    let stem = dst.uuid.to_string();
    let mut matched = 0;
    for entry in std::fs::read_dir(&kernel_dir).expect("read kernel dir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == stem || name.starts_with(&format!(".{stem}")) {
            matched += 1;
        }
    }
    assert_eq!(matched, 1, "only the destination file exists for our UUID");

    // The CPIO entries other than the requested kernel must never be
    // materialized onto the host. The implementation streams bodies
    // straight from the CPIO reader into the destination TempWriter; it
    // never calls `create_dir_all` or `write` for unrelated paths. The
    // strongest assertion we can make without a global filesystem sandbox
    // is that no `etc/passwd` exists relative to the working directory.
    assert!(
        !std::path::Path::new("etc/passwd").exists(),
        "the etc/passwd entry was not materialized onto the host"
    );
    assert!(
        !std::path::Path::new("boot").exists(),
        "the boot/ directory was not materialized onto the host"
    );
}

/// A pre-cancelled token makes the blocking closure bail at entry: the
/// operation fails fast with `OperationError::Cancelled` without walking the
/// CPIO (spec capability `blocking-cancellation`).
#[tokio::test]
async fn cancelled_token_returns_cancelled_fast() {
    let kernel = bzimage_body(7);
    let bytes = build_cpio(&[EntrySpec::regular("boot/vmlinuz", &kernel, 0o644)]);
    let uuid = Uuid::now_v7();
    let path = stage_in_namespace(Namespace::Kernel, uuid, &bytes);
    let src = cpio_ref(&path, uuid, Namespace::Kernel);
    let dst = kernel_link_ref(Uuid::now_v7());
    let token = CancellationToken::new();
    token.cancel();

    let err = ops::extract_kernel("boot/vmlinuz", &src, &dst, &token)
        .await
        .expect_err("a cancelled operation must fail");
    assert!(
        matches!(err.current_context(), OperationError::Cancelled),
        "expected Cancelled, got: {err:#}"
    );
}
