//! `ops::extract_kernel` copies a single `bzImage` entry out of a flattened,
//! uncompressed CPIO `newc` archive.
//!
//! The operation walks the source CPIO without materializing any other entry
//! onto the host filesystem. Regular-file bodies are streamed straight from
//! the `cpio::newc::Reader` into a
//! [`TempWriter`][image_core::ops::io::TempWriter] adjacent to the
//! destination, so resident memory stays bounded by the CPIO header and the
//! small slab of bytes used to validate the bzImage signature. Hard-link
//! groups are resolved in a single pass: when the requested path names a
//! non-canonical member (size zero), the canonical member owning the body is
//! located by matching the `(dev_major, ino)` identity, and its body is
//! streamed instead.
//!
//! See `docs/implementation-plan/ops/06-extract-kernel.md` for the full
//! contract.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use ::cpio as cpio_crate;

use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    ops::{
        bounded_join,
        cpio::normalize_path,
        error::OperationError,
        io::{self, TempWriter},
    },
    storage::{file_ref::FileRef, link_ref::LinkRef, namespace::Namespace},
};

// ---------------------------------------------------------------------------
// bzImage signature
// ---------------------------------------------------------------------------

/// Offset of the PC boot flag (`55 aa`) inside a bzImage.
const BOOT_FLAG_OFFSET: usize = 0x1fe;
/// The two byte boot flag value.
const BOOT_FLAG: [u8; 2] = [0x55, 0xaa];
/// Offset of the `HdrS` magic inside a bzImage.
const HDRS_OFFSET: usize = 0x202;
/// The four byte `HdrS` magic value.
const HDRS_MAGIC: [u8; 4] = *b"HdrS";
/// Number of bytes required to validate the bzImage signature.
const MIN_BZIMAGE_LEN: usize = HDRS_OFFSET + HDRS_MAGIC.len();

// ---------------------------------------------------------------------------
// File-type bits carried inside the CPIO `mode` field.
// ---------------------------------------------------------------------------

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Copy the `path` entry out of `src` into the destination indicated by
/// `dst`, validating that the extracted bytes satisfy the bzImage contract.
///
/// `path` is the canonical kernel-entry path produced by
/// [`KernelPath`][crate::spec::path::KernelPath]; a defensive validation
/// guard re-checks the request at the operation boundary so an internal
/// invariant violation cannot reach the CPIO walk.
///
/// See `docs/implementation-plan/ops/06-extract-kernel.md` for the full
/// contract.
pub(crate) async fn extract_kernel(
    path: &str,
    src: &FileRef,
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    // Precondition: the source must be an uncompressed CPIO.
    if src.artifact_type != ArtifactType::ContainerCpio {
        return Err(OperationError::UnsupportedArtifact.report().attach(format!(
            "expected ArtifactType::ContainerCpio, got {:?}",
            src.artifact_type
        )));
    }
    if src.artifact_compression != ArtifactCompression::None {
        return Err(OperationError::UnsupportedCompression
            .report()
            .attach(format!(
                "expected ArtifactCompression::None, got {:?}",
                src.artifact_compression
            )));
    }

    // Precondition: the destination namespace must be Kernel.
    if dst.namespace != Namespace::Kernel {
        return Err(OperationError::UnsupportedArtifact.report().attach(format!(
            "extract_kernel requires Namespace::Kernel for the destination, got {:?}",
            dst.namespace
        )));
    }

    // Precondition: `path` is relative, non-empty and free of `..` components.
    // This is the defensive guard at the operation boundary: callers hand in
    // the canonical string of a validated `KernelPath`, and the guard re-runs
    // the same normalization rules so a canonical form cannot regress.
    let requested = validate_request_path(Path::new(path))?;

    let src_clone = src.clone();
    let dst_uuid = dst.uuid;
    let dst_namespace = dst.namespace;

    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                run_blocking(&requested, &src_clone, dst_uuid, dst_namespace, &token)
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validate `path` and return its normalized CPIO name. The kernel can be
/// requested as `boot/vmlinuz` or `./boot/vmlinuz`; both must normalize to
/// the same CPIO name. Absolute paths, empty paths and `..` components are
/// rejected.
fn validate_request_path(path: &Path) -> Result<String, Report<OperationError>> {
    // Reject empty paths up front. `Path::as_os_str().is_empty()` works on
    // both Unix and Windows; the normalize_path helper would also reject
    // it, but the failure attribution is clearer when we anchor it to the
    // request.
    if path.as_os_str().is_empty() {
        return Err(OperationError::UnsafePath
            .report()
            .attach("kernel request path is empty"));
    }

    // Reject absolute paths before any normalization. The `cpio::normalize_path`
    // helper would also reject a leading separator, but we anchor the
    // attribution to the request explicitly so the failure message cites
    // the user's input rather than an internal name.
    if path.is_absolute() {
        return Err(OperationError::UnsafePath.report().attach(format!(
            "kernel request path is absolute: {}",
            path.display()
        )));
    }

    // Reject Windows drive prefixes outright. `Path` on Windows exposes a
    // prefix via `Path::components`, but cross-platform behavior is more
    // robust when we sniff the bytes of the textual representation the way
    // `normalize_path` does.
    let textual = path.to_string_lossy();
    let bytes = textual.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(OperationError::UnsafePath.report().attach(format!(
            "kernel request path contains a Windows drive prefix: {}",
            path.display()
        )));
    }

    // Re-use the CPIO normalizer so a `./` prefix and `/`-vs-`\` differences
    // are folded into a single canonical name. The normalizer also rejects
    // `..` components, empty segments and absolute Unix roots.
    normalize_path(&textual)
}

// ---------------------------------------------------------------------------
// Blocking driver
// ---------------------------------------------------------------------------

fn run_blocking(
    requested: &str,
    src: &FileRef,
    dst_uuid: uuid::Uuid,
    dst_namespace: Namespace,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    let src_path = src.path();

    // Precondition: the on-disk digest of the source CPIO must match the
    // declared `src.file_digest`. A tampered source must never produce a
    // kernel at the destination slot.
    let mut file = File::open(&src_path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(src_path.clone()))
            .attach(err)
    })?;
    let actual = io::compute_file_digest_from_file(&mut file, &src_path)
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    if actual != src.file_digest {
        return Err(OperationError::DigestMismatch
            .report()
            .attach(PathLabel(src_path.clone()))
            .attach(DigestPair {
                expected: src.file_digest,
                actual,
            }));
    }

    // Rewind the same verified handle. Keeping verification and consumption
    // on one handle closes the verify-then-reopen substitution window.
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(src_path.clone()))
            .attach(err)
    })?;
    let reader = std::io::BufReader::new(file);

    let destination = dst_namespace.join(dst_uuid.to_string());

    let outcome = walk_cpio(requested, reader, &destination, &src_path, token)?;
    match outcome {
        WalkOutcome::Published(published) => Ok(FileRef {
            uuid: dst_uuid,
            namespace: dst_namespace,
            file_digest: published.file_digest,
            artifact_type: ArtifactType::FileBzImage,
            artifact_compression: ArtifactCompression::None,
        }),
        WalkOutcome::NotFound => Err(OperationError::KernelNotFound
            .report()
            .attach(PathLabel(src_path.clone()))
            .attach(format!(
                "requested kernel entry {requested:?} not present in CPIO"
            ))),
    }
}

enum WalkOutcome {
    Published(io::PublishedFile),
    NotFound,
}

#[derive(Debug, Clone, Copy)]
struct BodyRange {
    offset: u64,
    size: u32,
}

/// Disk-backed body spool used while the complete CPIO is validated. It
/// allows a hard-link target to appear before or after the requested name
/// without retaining large regular-file bodies in memory.
struct BodySpool {
    file: File,
    path: PathBuf,
    cursor: u64,
}

impl BodySpool {
    fn open(destination: &Path) -> Result<Self, Report<OperationError>> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let stem = destination
            .file_stem()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "kernel".to_string());
        let path = parent.join(format!(".{stem}.kernel-spool-{}", uuid::Uuid::now_v7()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        Ok(Self {
            file,
            path,
            cursor: 0,
        })
    }

    fn append<R: Read + ?Sized>(
        &mut self,
        reader: &mut R,
        size: u32,
        src_path: &Path,
    ) -> Result<BodyRange, Report<OperationError>> {
        let range = BodyRange {
            offset: self.cursor,
            size,
        };
        let mut remaining = size as u64;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let want = (buffer.len() as u64).min(remaining) as usize;
            let read = reader
                .read(&mut buffer[..want])
                .map_err(|err| OperationError::ReadSource.report().attach(err))?;
            if read == 0 {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach(format!("body ended early: {remaining} bytes remaining")));
            }
            self.file
                .write_all(&buffer[..read])
                .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
            self.cursor += read as u64;
            remaining -= read as u64;
        }
        self.file
            .flush()
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        Ok(range)
    }

    fn open_reader(&self) -> Result<File, Report<OperationError>> {
        File::open(&self.path).map_err(|err| OperationError::ReadSource.report().attach(err))
    }
}

impl Drop for BodySpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// CPIO walk
// ---------------------------------------------------------------------------

/// Walk the CPIO archive behind `reader` looking for `requested`. Hard-link
/// groups are resolved in a single pass: when the requested path is observed
/// with a zero body, we record its `(dev_major, ino)` and continue scanning
/// for the canonical member that owns the body. The body is then streamed
/// straight from the CPIO into the [`TempWriter`] adjacent to `destination`.
///
/// Every header and every padding byte is validated by the `cpio::newc::Reader`
/// itself; on any structural error we surface `InvalidCpio` rather than
/// silently producing a partial kernel. A second trailer or any structural
/// bytes appearing after the first trailer are rejected.
fn walk_cpio<R: Read>(
    requested: &str,
    mut reader: R,
    destination: &Path,
    src_path: &Path,
    token: &CancellationToken,
) -> Result<WalkOutcome, Report<OperationError>> {
    let mut spool = BodySpool::open(destination)?;
    let mut bodies_by_identity: HashMap<(u32, u32), BodyRange> = HashMap::new();
    let mut requested_identity: Option<(u32, u32)> = None;
    let mut requested_body: Option<BodyRange> = None;
    let mut requested_seen = false;
    let mut requested_invalid_type: Option<&'static str> = None;

    loop {
        if token.is_cancelled() {
            return Err(OperationError::Cancelled.report());
        }
        let next = cpio_crate::newc::Reader::new(reader);
        let mut entry_reader = match next {
            Ok(reader) => reader,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach("CPIO ended before TRAILER!!!"));
            }
            Err(err) => {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach(err));
            }
        };

        let entry = entry_reader.entry().clone();

        if entry.is_trailer() {
            // Drain the trailer's body/padding (always empty) and verify no
            // further structural bytes follow.
            let mut remaining = finish_reader(entry_reader, src_path)?;
            // After the trailer, any further byte is structural garbage; a
            // second trailer or corrupted header is an InvalidCpio rather than
            // a benign trailing pad. An immediate clean EOF is fine;
            // anything else is an error.
            if has_more_bytes(&mut remaining)? {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach("structural bytes after the CPIO trailer"));
            }
            if let Some(kind) = requested_invalid_type {
                return Err(OperationError::InvalidKernel
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach(format!(
                        "requested kernel entry {requested:?} is a {kind}, not a regular file"
                    )));
            }
            return match requested_body {
                Some(body) => copy_spooled_body(&spool, body, destination, src_path)
                    .map(WalkOutcome::Published),
                None if requested_seen => Err(OperationError::InvalidKernel
                    .report()
                    .attach(PathLabel(src_path.to_path_buf()))
                    .attach("requested kernel hard-link group has no body")),
                None => Ok(WalkOutcome::NotFound),
            };
        }

        let raw_name = entry.name();
        let normalized = normalize_path(raw_name)?;

        let size = entry.file_size();
        let mode = entry.mode();
        let file_type = mode & S_IFMT;
        let dev_major = entry.dev_major();
        let ino = entry.ino();

        let matches_requested = normalized == requested;

        let identity = (dev_major, ino);
        let body = if file_type == S_IFREG && size > 0 {
            Some(spool.append(&mut entry_reader, size, src_path)?)
        } else {
            None
        };
        reader = finish_reader(entry_reader, src_path)?;

        if let Some(body) = body {
            bodies_by_identity.entry(identity).or_insert(body);
            if requested_identity == Some(identity) && requested_body.is_none() {
                requested_body = Some(body);
            }
        }
        if matches_requested {
            requested_seen = true;
            requested_identity = Some(identity);
            if file_type != S_IFREG {
                requested_invalid_type = Some(file_type_label(file_type));
            } else {
                requested_body = body.or_else(|| bodies_by_identity.get(&identity).copied());
            }
        }
    }
}

/// Copy a validated body range from the operation spool to the destination.
/// The signature is checked before publication, and the spool itself only
/// contains bytes that were read while validating every CPIO entry.
fn copy_spooled_body(
    spool: &BodySpool,
    range: BodyRange,
    destination: &Path,
    src_path: &Path,
) -> Result<io::PublishedFile, Report<OperationError>> {
    if range.size == 0 {
        return Err(OperationError::InvalidKernel
            .report()
            .attach(PathLabel(src_path.to_path_buf()))
            .attach("requested kernel entry has a zero-length body"));
    }

    let mut source = spool.open_reader()?;
    source
        .seek(SeekFrom::Start(range.offset))
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    let mut writer = TempWriter::open(destination)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    let mut header = Vec::with_capacity(MIN_BZIMAGE_LEN);
    let mut remaining = range.size as u64;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = (buffer.len() as u64).min(remaining) as usize;
        source
            .read_exact(&mut buffer[..want])
            .map_err(|err| OperationError::ReadSource.report().attach(err))?;
        let take = (MIN_BZIMAGE_LEN - header.len()).min(want);
        if take > 0 {
            header.extend_from_slice(&buffer[..take]);
        }
        writer
            .write_all(&buffer[..want])
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        remaining -= want as u64;
    }
    validate_bzimage_signature(&header, src_path)?;
    writer
        .flush()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    writer
        .publish()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))
}

/// Validate the bzImage signature of a fully-buffered prefix. The slice must
/// contain at least [`MIN_BZIMAGE_LEN`] bytes; the boot flag at `0x1fe` and
/// the `HdrS` magic at `0x202` must both match.
fn validate_bzimage_signature(bytes: &[u8], src_path: &Path) -> Result<(), Report<OperationError>> {
    if bytes.len() < MIN_BZIMAGE_LEN {
        return Err(OperationError::InvalidKernel
            .report()
            .attach(PathLabel(src_path.to_path_buf()))
            .attach(format!(
                "kernel body is too short: {} bytes (< {MIN_BZIMAGE_LEN})",
                bytes.len()
            )));
    }
    if bytes[BOOT_FLAG_OFFSET..BOOT_FLAG_OFFSET + 2] != BOOT_FLAG {
        return Err(OperationError::InvalidKernel
            .report()
            .attach(PathLabel(src_path.to_path_buf()))
            .attach("bzImage boot flag `55 aa` not present at offset 0x1fe"));
    }
    if bytes[HDRS_OFFSET..HDRS_OFFSET + 4] != HDRS_MAGIC {
        return Err(OperationError::InvalidKernel
            .report()
            .attach(PathLabel(src_path.to_path_buf()))
            .attach("bzImage `HdrS` magic not present at offset 0x202"));
    }
    Ok(())
}

/// Drain the trailing body padding of a `cpio::newc::Reader` and return the
/// underlying reader so the caller can continue scanning. Structural errors
/// surface as `InvalidCpio`.
fn finish_reader<R: Read>(
    reader: cpio_crate::newc::Reader<R>,
    src_path: &Path,
) -> Result<R, Report<OperationError>> {
    reader.finish().map_err(|err| {
        OperationError::InvalidCpio
            .report()
            .attach(PathLabel(src_path.to_path_buf()))
            .attach(err)
    })
}

/// Detect whether `reader` has any further bytes available without
/// consuming them. Used after the trailer to reject a second trailer or
/// any structural garbage. The probe reads a single byte; if it succeeds
/// we consume the byte and signal `true`. The caller has already drained
/// the trailer's body and padding, so any further byte is invalid.
fn has_more_bytes<R: Read>(reader: &mut R) -> Result<bool, Report<OperationError>> {
    let mut buf = [0u8; 1];
    match reader.read(&mut buf) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(err) => Err(OperationError::InvalidCpio.report().attach(format!(
            "error while probing for bytes after trailer: {err}"
        ))),
    }
}

/// Return a short human-readable label for a CPIO mode's file-type bits.
fn file_type_label(file_type: u32) -> &'static str {
    match file_type {
        S_IFDIR => "directory",
        S_IFLNK => "symlink",
        S_IFCHR => "character device",
        S_IFBLK => "block device",
        S_IFIFO => "fifo",
        _ => "non-regular entry",
    }
}

// ---------------------------------------------------------------------------
// Printable report attachments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PathLabel(PathBuf);

impl std::fmt::Display for PathLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[derive(Debug, Clone, Copy)]
struct DigestPair {
    expected: image_core::digest::FileDigest,
    actual: image_core::digest::FileDigest,
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
