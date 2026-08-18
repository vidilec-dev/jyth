//! Tests for [`crate::ops::flatten`].
//!
//! These tests cover the contract described in
//! `docs/implementation-plan/ops/05-flatten.md`: combining two non-colliding
//! layers, file-overwrites from upper layers, file-vs-directory
//! substitution, directory-over-file substitution, `.wh.<name>` and opaque
//! `.wh..wh..opq` whiteouts, interleaved whiteouts/creations within a
//! single layer, whiteout markers never reaching the output, surviving
//! hard-link groups, `nlink` recalculation when an inlinked name is
//! dropped, rejecting truncated CPIOs and unsafe paths, producing a valid
//! empty archive for zero layers, deterministic output across two
//! `flatten` invocations, and leaving the source layers intact.

use std::io::Cursor;

use uuid::Uuid;

use crate::artifact::compression::ArtifactCompression;
use crate::artifact::ty::ArtifactType;
use crate::digest::FileDigest;
use crate::ops;
use crate::ops::error::OperationError;
use crate::storage::file_ref::FileRef;
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::Namespace;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Helpers — building CPIO `newc` layers out of adversarial test fixtures.
// ---------------------------------------------------------------------------

/// File-type bits used in CPIO `newc` mode words.
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// A specification for a single CPIO entry. We render it via the external
/// `cpio` crate's `NewcBuilder` so the resulting bytes are byte-identical
/// in shape to real layer artifacts.
struct EntrySpec {
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    /// Inode identity. Two surviving entries that share (dev_major, ino)
    /// form a hard-link group on emit.
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

    /// A hard-link duplicate pointing at `target`'s (dev, ino). The body is
    /// empty on the duplicate; the target carries the canonical bytes.
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

    fn whiteout(parent: &str, name: &str) -> Self {
        let full = if parent.is_empty() {
            format!(".wh.{name}")
        } else {
            format!("{parent}/.wh.{name}")
        };
        Self::regular(&full, b"", 0o644)
    }

    fn opaque_whiteout(parent: &str) -> Self {
        let full = if parent.is_empty() {
            ".wh..wh..opq".to_string()
        } else {
            format!("{parent}/.wh..wh..opq")
        };
        Self::regular(&full, b"", 0o644)
    }
}

/// Encode a list of entry specs into a complete `newc` archive terminated
/// by the single `TRAILER!!!` entry. We bypass `cpio::write_cpio` because
/// it overrides `ino` with the iteration index, which would defeat the
/// hard-link grouping tests. We keep the per-entry `dev_major`/`ino`
/// exactly as the spec requests so two hard-linked entries can share an
/// identity.
fn build_cpio(entries: &[EntrySpec]) -> Vec<u8> {
    use std::io::Write as _;
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

/// Stage a single CPIO layer on disk inside the global `Layle` namespace
/// and return its `FileRef` with a matching `FileDigest`.
///
/// The destination filename is `dst_uuid` so a unique global UUID keeps
/// fixtures mutually independent. The returned `FileRef` mirrors what
/// `into_cpio` would produce — same namespace, same UUID, with
/// `ContainerCpio` + `None`.
fn stage_layer(uuid: Uuid, payload: &[u8]) -> FileRef {
    let path = Namespace::Layers.join(uuid.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create layers dir");
    }
    std::fs::write(&path, payload).expect("write layer");
    let file_digest = crate::ops::io::compute_file_digest(&path).expect("digest");
    FileRef {
        uuid,
        namespace: Namespace::Layers,
        file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    }
}

/// Stage a single layer at `Namespace::Layers` (so a destination at
/// `Namespace::Rootfs` is distinct) and return its `FileRef`.
fn stage_layer_in_rootfs(uuid: Uuid, payload: &[u8]) -> FileRef {
    let path = Namespace::Rootfs.join(uuid.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create rootfs dir");
    }
    std::fs::write(&path, payload).expect("write layer");
    let file_digest = crate::ops::io::compute_file_digest(&path).expect("digest");
    FileRef {
        uuid,
        namespace: Namespace::Rootfs,
        file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    }
}

/// Build a `LinkRef` targetting the rootfs namespace. `flatten` requires
/// that the destination UUID and namespace match the resulting `FileRef`.
fn rootfs_link_ref(uuid: Uuid) -> LinkRef {
    // The link_digest is only used to validate the link identity itself; we
    // use a placeholder BLAKE3 hash so it does not interfere with flatten.
    LinkRef {
        uuid,
        namespace: Namespace::Rootfs,
        link_digest: crate::digest::LinkDigest {
            link_hash: blake3::hash(&[]),
            file_size: 0,
        },
    }
}

/// Await `flatten` and unwrap the result, attaching the report text to the
/// failure message when present.
async fn flatten_ok(src: &[FileRef], dst: &LinkRef) -> FileRef {
    ops::flatten(src, dst, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("flatten failed: {err:?}"))
}

/// Await `flatten` and unwrap the failure.
async fn flatten_err(src: &[FileRef], dst: &LinkRef) -> error_stack::Report<OperationError> {
    match ops::flatten(src, dst, &CancellationToken::new()).await {
        Ok(value) => panic!("flatten succeeded unexpectedly: {value:?}"),
        Err(err) => err,
    }
}

/// Read back a CPIO at `path` into a flat list of `(Entry, body)` pairs in
/// archive order. The trailer is appended last.
fn read_cpio(path: &std::path::Path) -> Vec<(cpio::newc::Entry, Vec<u8>)> {
    let bytes = std::fs::read(path).expect("read cpio");
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::new();
    loop {
        let reader = match cpio::newc::Reader::new(cursor) {
            Ok(reader) => reader,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => panic!("cpio read: {err}"),
        };
        let entry = reader.entry().clone();
        let mut body = Vec::with_capacity(entry.file_size() as usize);
        cursor = reader.to_writer(&mut body).expect("to_writer");
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
    crate::ops::io::compute_file_digest(path).expect("digest")
}

// ---------------------------------------------------------------------------
// 1) Two non-colliding layers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn combines_two_non_colliding_layers() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("a", b"AAA", 0o644)]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("b", b"BBB", 0o644)]),
    );
    let dst_uuid = Uuid::now_v7();
    let dst = rootfs_link_ref(dst_uuid);

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    assert!(cpio.iter().any(|(e, b)| e.name() == "a" && b == b"AAA"));
    assert!(cpio.iter().any(|(e, b)| e.name() == "b" && b == b"BBB"));
    assert_eq!(
        cpio.iter().filter(|(e, _)| e.is_trailer()).count(),
        1,
        "exactly one trailer"
    );
}

#[tokio::test]
async fn does_not_merge_unlinked_regular_files_with_placeholder_inodes() {
    let layer = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::regular("first", b"one", 0o644),
            EntrySpec::regular("second", b"two", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[layer], &dst).await;
    let cpio = read_cpio(&out.path());
    let first = cpio
        .iter()
        .find(|(entry, _)| entry.name() == "first")
        .unwrap();
    let second = cpio
        .iter()
        .find(|(entry, _)| entry.name() == "second")
        .unwrap();
    assert_eq!(first.1, b"one");
    assert_eq!(second.1, b"two");
    assert_ne!(
        (first.0.dev_major(), first.0.ino()),
        (second.0.dev_major(), second.0.ino())
    );
}

// ---------------------------------------------------------------------------
// 2) Upper layer substitutes a file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upper_layer_substitutes_a_file() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("file", b"old", 0o644)]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("file", b"new", 0o644)]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let file = cpio
        .iter()
        .find(|(e, _)| e.name() == "file")
        .expect("file present");
    assert_eq!(file.1, b"new", "upper layer wins");
    assert_eq!(
        cpio.iter().filter(|(e, _)| e.name() == "file").count(),
        1,
        "exactly one copy"
    );
}

// ---------------------------------------------------------------------------
// 3) File substitutes directory and descendants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_substitutes_directory_and_descendants() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::directory("dir", 0o755),
            EntrySpec::regular("dir/child", b"child", 0o644),
            EntrySpec::regular("dir/nested/grand", b"grand", 0o644),
        ]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("dir", b"now-a-file", 0o644)]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(e, _)| e.name().to_string()).collect();
    assert!(names.iter().any(|n| n == "dir"), "file present: {names:?}");
    assert!(
        cpio.iter().find(|(e, _)| e.name() == "dir").unwrap().1 == b"now-a-file",
        "dir is now a file"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("dir/")),
        "descendants removed: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// 4) Directory substitutes file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn directory_substitutes_a_file() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("entry", b"old", 0o644)]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::directory("entry", 0o755)]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let entry = cpio
        .iter()
        .find(|(e, _)| e.name() == "entry")
        .expect("entry present");
    assert_eq!(entry.0.mode() & S_IFMT, S_IFDIR, "entry is a directory");
    assert!(entry.1.is_empty(), "directory body empty");
}

#[tokio::test]
async fn resolves_upper_layer_paths_through_lower_layer_symlinks() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::symlink("lib", b"usr/lib", 0o777),
            EntrySpec::directory("usr", 0o755),
            EntrySpec::directory("usr/lib", 0o755),
        ]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::directory("lib/modules", 0o755),
            EntrySpec::regular("lib/modules/6.6.13/hv_netvsc.ko", b"module", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;
    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(entry, _)| entry.name()).collect();

    assert!(
        names.contains(&"lib"),
        "the lower symlink survives: {names:?}"
    );
    assert!(
        names.contains(&"usr/lib/modules"),
        "the upper directory follows the lower symlink: {names:?}"
    );
    assert!(
        names.contains(&"usr/lib/modules/6.6.13/hv_netvsc.ko"),
        "the upper file follows the lower symlink: {names:?}"
    );
    assert!(
        !names.contains(&"lib/modules") && !names.contains(&"lib/modules/6.6.13/hv_netvsc.ko"),
        "unresolved entries are not emitted below the symlink: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// 5) `.wh.<name>` whiteout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applies_a_named_whiteout() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::directory("dir", 0o755),
            EntrySpec::regular("dir/child", b"child", 0o644),
            EntrySpec::regular("dir/keep", b"keep", 0o644),
        ]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::whiteout("dir", "child")]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(e, _)| e.name().to_string()).collect();
    assert!(
        !names.iter().any(|n| n == "dir/child"),
        "whiteouted child removed: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "dir/keep"),
        "sibling preserved: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains(".wh.")),
        "whiteout markers not present in output: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// 6) Opaque whiteout `.wh..wh..opq`
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applies_an_opaque_whiteout() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::directory("dir", 0o755),
            EntrySpec::regular("dir/lower_a", b"a", 0o644),
            EntrySpec::regular("dir/lower_b", b"b", 0o644),
        ]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::opaque_whiteout("dir"),
            EntrySpec::regular("dir/upper", b"u", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(e, _)| e.name().to_string()).collect();
    assert!(!names.iter().any(|n| n == "dir/lower_a"), "lower_a removed");
    assert!(!names.iter().any(|n| n == "dir/lower_b"), "lower_b removed");
    assert!(
        names.iter().any(|n| n == "dir/upper"),
        "upper entry survives"
    );
    assert!(
        names.iter().any(|n| n == "dir"),
        "the directory entry survives"
    );
}

#[tokio::test]
async fn applies_an_opaque_whiteout_at_the_root() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::directory("a", 0o755),
            EntrySpec::regular("a/lower", b"lower", 0o644),
            EntrySpec::regular("root-file", b"lower", 0o644),
        ]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::opaque_whiteout(""),
            EntrySpec::regular("fresh", b"upper", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;
    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio
        .iter()
        .map(|(entry, _)| entry.name().to_string())
        .collect();
    assert!(
        !names
            .iter()
            .any(|name| name == "a" || name.starts_with("a/"))
    );
    assert!(!names.iter().any(|name| name == "root-file"));
    assert!(names.iter().any(|name| name == "fresh"));
}

// ---------------------------------------------------------------------------
// 7) A layer's whiteout does not remove an entry created by the same layer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whiteout_does_not_remove_same_layer_creation() {
    // Upper layer emits both the whiteout for `x` and `x` itself. The
    // whiteout must not preempt the creation.
    let lower = stage_layer(Uuid::now_v7(), &build_cpio(&[]));
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::whiteout("", "x"),
            EntrySpec::regular("x", b"fresh", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let x = cpio
        .iter()
        .find(|(e, _)| e.name() == "x")
        .expect("x present");
    assert_eq!(
        x.1, b"fresh",
        "fresh entry survives its own layer's whiteout"
    );
}

// ---------------------------------------------------------------------------
// 8) Whiteout markers never reach the output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn whiteout_markers_never_reach_output() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("a", b"a", 0o644)]),
    );
    let upper = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::whiteout("", "a"),
            EntrySpec::whiteout("sub", "x"),
            EntrySpec::opaque_whiteout(""),
            EntrySpec::directory("sub", 0o755),
            EntrySpec::regular("sub/y", b"y", 0o644),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let names: Vec<_> = cpio.iter().map(|(e, _)| e.name().to_string()).collect();
    assert!(
        !names.iter().any(|n| n.contains(".wh.")),
        "no whiteout markers in output: {names:?}"
    );
}

// ---------------------------------------------------------------------------
// 9) Surviving hard-link group
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preserves_a_surviving_hard_link_group() {
    // Both labels start at the lower layer and survive unchanged.
    let layer = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::regular_with_inode("target", b"shared", 0o644, 1, 7, 2),
            EntrySpec::hardlink_dup("alias", 1, 7, 2),
        ]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[layer], &dst).await;

    let cpio = read_cpio(&out.path());
    let target = cpio
        .iter()
        .find(|(e, _)| e.name() == "target")
        .expect("target present");
    let alias = cpio
        .iter()
        .find(|(e, _)| e.name() == "alias")
        .expect("alias present");
    assert_eq!(target.1, b"shared", "canonical body emitted once");
    assert!(alias.1.is_empty(), "duplicate carries size zero");
    assert_eq!(target.0.ino(), alias.0.ino(), "shared inode");
    assert_eq!(target.0.dev_major(), alias.0.dev_major(), "shared dev");
    assert_eq!(target.0.nlink(), 2, "nlink recalculated to surviving names");
    assert_eq!(alias.0.nlink(), 2, "nlink coherent across group");
}

// ---------------------------------------------------------------------------
// 10) `nlink` recalculation when a linked name is dropped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recalculates_nlink_when_a_linked_name_is_dropped() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[
            EntrySpec::regular_with_inode("a", b"data", 0o644, 1, 12, 2),
            EntrySpec::hardlink_dup("b", 1, 12, 2),
        ]),
    );
    // Upper layer whitens `b`. Only `a` survives, so `nlink` collapses to 1.
    let upper = stage_layer(Uuid::now_v7(), &build_cpio(&[EntrySpec::whiteout("", "b")]));
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[lower, upper], &dst).await;

    let cpio = read_cpio(&out.path());
    let a = cpio
        .iter()
        .find(|(e, _)| e.name() == "a")
        .expect("a present");
    assert!(cpio.iter().all(|(e, _)| e.name() != "b"), "b removed");
    assert_eq!(
        a.0.nlink(),
        1,
        "nlink recalculated to surviving count: {}",
        a.0.nlink()
    );
    assert_eq!(a.1, b"data", "body preserved");
}

// ---------------------------------------------------------------------------
// 11) Reject a truncated CPIO
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_truncated_cpio() {
    let bytes = build_cpio(&[EntrySpec::regular("file", b"hello world", 0o644)]);
    let mut truncated = bytes.clone();
    truncated.truncate(truncated.len().saturating_sub(20));
    let truncated_len = truncated.len();
    let uuid = Uuid::now_v7();
    let layer = stage_layer_in_rootfs(uuid, &truncated);
    let dst = rootfs_link_ref(Uuid::now_v7());

    let err = flatten_err(&[layer], &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid cpio `newc` archive") || msg.contains("failed to read the source"),
        "expected InvalidCpio/ReadSource for a truncated CPIO at {truncated_len} bytes: {msg}"
    );
}

#[tokio::test]
async fn rejects_bytes_after_the_cpio_trailer() {
    let mut bytes = build_cpio(&[EntrySpec::regular("file", b"body", 0o644)]);
    bytes.extend_from_slice(b"trailing-structure");
    let layer = stage_layer_in_rootfs(Uuid::now_v7(), &bytes);
    let dst = rootfs_link_ref(Uuid::now_v7());

    let err = flatten_err(&[layer], &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("invalid cpio") || msg.contains("structural bytes"),
        "{msg}"
    );
}

// ---------------------------------------------------------------------------
// 12) Reject an unsafe path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_unsafe_path() {
    // `cpio::NewcBuilder` validates names by accepting any `&str`, so a
    // hand-crafted `..` path bypasses the convenience builder. We craft
    // the bytes directly using the same writer helpers `into_cpio` uses
    // in production, but the simplest approach is to construct the
    // header bytes manually.
    let raw_layer = build_cpio_with_raw_path("../escape", S_IFREG | 0o644, b"x");
    let layer = stage_layer_in_rootfs(Uuid::now_v7(), &raw_layer);
    let dst = rootfs_link_ref(Uuid::now_v7());

    let err = flatten_err(&[layer], &dst).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("unsafe path"),
        "expected UnsafePath for `..` entry, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// 13) Zero layers — a valid CPIO with only the trailer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn produces_a_valid_empty_cpio_for_zero_layers() {
    let dst = rootfs_link_ref(Uuid::now_v7());

    let out = flatten_ok(&[], &dst).await;

    assert_eq!(out.artifact_type, ArtifactType::ContainerCpio);
    assert_eq!(out.artifact_compression, ArtifactCompression::None);

    let cpio = read_cpio(&out.path());
    // Only the trailer must be present.
    assert_eq!(cpio.len(), 1, "exactly one trailer for empty input");
    assert!(cpio[0].0.is_trailer(), "the single entry is the trailer");
}

// ---------------------------------------------------------------------------
// 14) Deterministic output: the same flatten run twice is byte-identical
// ---------------------------------------------------------------------------

#[tokio::test]
async fn flatten_is_deterministic() {
    let entries = vec![
        EntrySpec::directory("d", 0o755),
        EntrySpec::regular("a", b"AAA", 0o644),
        EntrySpec::regular("d/b", b"BBB", 0o644),
        EntrySpec::symlink("link", b"a", 0o777),
    ];
    let payload = build_cpio(&entries);

    // Two independent flatten runs must produce identical bytes.
    let dst1 = rootfs_link_ref(Uuid::now_v7());
    let dst2 = rootfs_link_ref(Uuid::now_v7());

    let l1 = stage_layer(Uuid::now_v7(), &payload);
    let out1 = flatten_ok(std::slice::from_ref(&l1), &dst1).await;
    let bytes1 = std::fs::read(out1.path()).expect("read1");

    let l2 = stage_layer(Uuid::now_v7(), &payload);
    let out2 = flatten_ok(&[l2], &dst2).await;
    let bytes2 = std::fs::read(out2.path()).expect("read2");

    assert_eq!(
        bytes1, bytes2,
        "flatten is byte-stable for identical layers"
    );
}

// ---------------------------------------------------------------------------
// 15) Source layers remain intact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_layers_remain_intact() {
    let lower_bytes = build_cpio(&[EntrySpec::regular("a", b"a", 0o644)]);
    let lower = stage_layer(Uuid::now_v7(), &lower_bytes);
    let upper_bytes = build_cpio(&[EntrySpec::regular("b", b"b", 0o644)]);
    let upper = stage_layer(Uuid::now_v7(), &upper_bytes);
    let dst = rootfs_link_ref(Uuid::now_v7());

    let _out = flatten_ok(&[lower.clone(), upper.clone()], &dst).await;

    let on_disk_lower = std::fs::read(lower.path()).expect("read lower");
    let on_disk_upper = std::fs::read(upper.path()).expect("read upper");
    assert_eq!(on_disk_lower, lower_bytes, "lower layer bytes preserved");
    assert_eq!(on_disk_upper, upper_bytes, "upper layer bytes preserved");
}

// ---------------------------------------------------------------------------
// Extra invariants: returned `FileRef` matches the produced bytes and
// preserves the destination UUID/namespace.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn returned_fileref_matches_produced_cpio_and_dst() {
    let lower = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("a", b"A", 0o644)]),
    );
    let dst_uuid = Uuid::now_v7();
    let dst = rootfs_link_ref(dst_uuid);

    let out = flatten_ok(&[lower], &dst).await;

    assert_eq!(out.uuid, dst_uuid);
    assert_eq!(out.namespace, Namespace::Rootfs);
    assert_eq!(
        out.path(),
        Namespace::Rootfs.join(dst_uuid.to_string()),
        "path derived from dst identity"
    );
    let actual = on_disk_digest(&out.path());
    assert_eq!(out.file_digest, actual, "digest matches produced CPIO");
}

// ---------------------------------------------------------------------------
// Build a CPIO `newc` archive with a raw path bypassing `NewcBuilder`'s
// path normalizer. We reuse the encoder helpers from `ops::cpio` so the
// produced bytes mirror a real adversarial input.
// ---------------------------------------------------------------------------

/// Hand-encode a single `newc` entry whose name is taken verbatim. The
/// external `cpio::NewcBuilder` accepts any `&str` for the name (it does
/// not normalize), so we use `Builder::write` plus the trailer helper to
/// produce a parseable but adversarial archive.
fn build_cpio_with_raw_path(name: &str, mode: u32, body: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
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

/// Patch the `filesize` field (offset 54..62 of the 110-byte `newc` header)
/// of the FIRST entry in `archive` to `size`, hex-encoded.
fn patch_first_newc_size(archive: &mut [u8], size: u32) {
    let hex = format!("{size:08x}");
    archive[54..62].copy_from_slice(hex.as_bytes());
}

#[tokio::test]
async fn rejects_oversized_symlink_bodies() {
    let mut layer_bytes = build_cpio(&[EntrySpec::symlink("link", b"target", 0o777)]);
    patch_first_newc_size(&mut layer_bytes, crate::ops::MAX_IN_MEMORY_ENTRY_BYTES + 1);
    let layer = stage_layer(Uuid::now_v7(), &layer_bytes);
    let dst = rootfs_link_ref(Uuid::now_v7());

    let err = flatten_err(&[layer], &dst).await;
    assert!(
        matches!(
            err.current_context(),
            crate::ops::error::OperationError::InvalidCpio
        ),
        "expected InvalidCpio, got: {err:#}"
    );
}

/// A pre-cancelled token makes the blocking closure bail at entry: the
/// operation fails fast with `OperationError::Cancelled` without touching the
/// layer bytes (spec capability `blocking-cancellation`).
#[tokio::test]
async fn cancelled_token_returns_cancelled_fast() {
    let layer = stage_layer(
        Uuid::now_v7(),
        &build_cpio(&[EntrySpec::regular("etc/hostname", b"guest", 0o100644)]),
    );
    let dst = rootfs_link_ref(Uuid::now_v7());
    let token = CancellationToken::new();
    token.cancel();

    let err = ops::flatten(&[layer], &dst, &token)
        .await
        .expect_err("a cancelled operation must fail");
    assert!(
        matches!(err.current_context(), OperationError::Cancelled),
        "expected Cancelled, got: {err:#}"
    );
}
