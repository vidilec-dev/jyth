//! `ops::into_cpio` converts an uncompressed TAR artifact into a CPIO `newc`
//! archive suitable for layer flattening.
//!
//! The conversion never extracts the TAR onto the host filesystem. The
//! metadata table needed to fulfil the hard-link contract (target resolution
//! and shared device/inode assignment) is held in memory, but every regular
//! file body is streamed straight from the `tar::Entry` reader into the
//! [`TempWriter`][crate::ops::io::TempWriter], so resident memory stays
//! bounded by the metadata table.
//!
//! The `newc` writer implemented here mirrors the layout produced by the
//! [`cpio`] crate's [`cpio::NewcBuilder`] but accepts any [`Read`] for the
//! entry body, avoiding the [`Seek`] requirement that `cpio::write_cpio`
//! imposes so a multi-gigabyte regular file can be copied in constant
//! memory.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use error_stack::Report;

use crate::artifact::compression::ArtifactCompression;
use crate::artifact::ty::ArtifactType;
use crate::ops::error::OperationError;
use crate::ops::io::{self, TempWriter};
use crate::storage::file_ref::FileRef;

/// Magic number prefix for the SVR4 "new ascii" (`newc`) format.
pub const MAGIC_NEWC: &[u8] = b"070701";
/// Fixed length of a `newc` header before the variable-length name field.
pub const HEADER_LEN: usize = 110;
/// The trailer entry that terminates a `newc` archive. Output must contain
/// exactly one of these.
pub const TRAILER_NAME: &str = "TRAILER!!!";

// ---------------------------------------------------------------------------
// Intermediate representation of a single TAR entry ready to be serialized
// as a `newc` record.
// ---------------------------------------------------------------------------

/// A `newc` entry body ready to be serialized. Streaming regular files are
/// written via [`write_streaming_entry`], so this enum only needs to
/// represent bodies that fit in memory.
pub enum Body {
    /// No content is associated with this entry (directories, devices,
    /// FIFOs and the trailing hard-link duplicates that carry size zero).
    Empty,
    /// The full body already materialized in memory. Used for symlink
    /// targets, which are short by construction and must be known up-front
    /// so the `newc` size field can be filled before streaming begins.
    Owned(Vec<u8>),
}

/// The intermediate representation of a single `newc` entry as described by
/// the implementation plan. Fields are kept minimal and deterministic.
pub struct Record {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub ino: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub body: Body,
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

/// Normalize a TAR path into the relative `/`-separated form used inside the
/// CPIO archive.
///
/// Repeated leading `./` segments are stripped; a root-directory marker such
/// as `.` or `./` is canonicalized to `.`, and one trailing directory marker
/// is removed. Windows drive prefixes plus absolute Unix roots are rejected.
/// `..` components and empty segments are rejected outright — `flatten` is
/// responsible for whiteout semantics, but path traversal into the host is
/// never acceptable. `.wh.*` whiteout names are preserved verbatim because
/// `flatten` interprets their semantics.
pub fn normalize_path(raw: &str) -> Result<String, Report<OperationError>> {
    // Reject anything that, on Windows, would be interpreted with a drive
    // prefix (e.g. `C:\foo`) or a UNC root. We compare the second character
    // against `:` so the check is independent of the host platform. The plan
    // requires a Windows-specific rejection of a drive prefix.
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(OperationError::UnsafePath
            .report()
            .attach(format!("path contains a Windows drive prefix: {raw}")));
    }

    // A path is "absolute" for our purposes if, once its leading separators
    // are stripped, nothing remains, or if it begins with a separator at
    // all. Splitting on `/`/`\` lets us catch both Unix (`/foo`) and Windows
    // (`\foo`) roots without depending on the host's path parser. Reject the
    // leading-separator case explicitly so a path like `/etc/passwd` is
    // never silently interpreted as the relative `etc/passwd`.
    if raw
        .chars()
        .next()
        .map(|c| c == '/' || c == '\\')
        .unwrap_or(false)
    {
        return Err(OperationError::UnsafePath
            .report()
            .attach(format!("path is absolute: {raw}")));
    }
    let trimmed = raw;
    if trimmed.is_empty() {
        return Err(OperationError::UnsafePath
            .report()
            .attach(format!("path is empty: {raw}")));
    }

    // Strip leading `./` segments repeatedly. Many TAR writers prefix every
    // entry with `./`; keeping them would produce a non-canonical name and
    // defeat hard-link deduplication by path.
    let mut cursor = trimmed;
    while let Some(rest) = cursor
        .strip_prefix("./")
        .or_else(|| cursor.strip_prefix(".\\"))
    {
        cursor = rest;
    }

    // OCI/TAR layers commonly include an explicit root-directory entry named
    // `./`. Once its harmless leading markers are removed, retain the root as
    // the canonical relative path `.` instead of treating the empty suffix as
    // an unsafe path component.
    if cursor.is_empty() {
        return Ok(".".to_string());
    }

    // TAR directory entries conventionally carry one trailing separator
    // (`./lib/`). It is a representation marker, not an empty path segment;
    // remove exactly one so malformed doubled separators remain rejected by
    // the component walk below.
    if cursor.ends_with('/') || cursor.ends_with('\\') {
        cursor = &cursor[..cursor.len() - 1];
    }
    if cursor.is_empty() {
        return Ok(".".to_string());
    }

    // Normalize separators: any backslash is rewritten to `/` so the
    // serialized name is deterministic across operating systems.
    let normalized = cursor.replace('\\', "/");

    // Walk the components one segment at a time to reject `..`, root pivots
    // and empty segments (which on Unix would be interpreted as roots).
    let mut out = String::new();
    for segment in normalized.split('/') {
        match segment {
            "" => {
                return Err(OperationError::UnsafePath
                    .report()
                    .attach(format!("path contains an empty component: {raw}")));
            }
            ".." => {
                return Err(OperationError::UnsafePath
                    .report()
                    .attach(format!("path contains a `..` component: {raw}")));
            }
            "." => {
                // A bare `.` only survives at the very start of the path;
                // any interior `.` is a redundant component that would
                // produce a non-canonical path.
                if !out.is_empty() {
                    return Err(OperationError::UnsafePath
                        .report()
                        .attach(format!("path contains an interior `.` component: {raw}")));
                }
                out.push('.');
            }
            other => {
                if !out.is_empty() && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(other);
            }
        }
    }

    if out.is_empty() {
        return Err(OperationError::UnsafePath
            .report()
            .attach(format!("path is empty after normalization: {raw}")));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Hard-link identity
// ---------------------------------------------------------------------------

/// Identity of a hard-link group inside the CPIO. All members of a group
/// share the same (dev, ino) pair so a subsequent `flatten` pass can
/// recognize them as a single inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LinkId {
    dev: u32,
    ino: u32,
}

/// A snapshot of the metadata we need from a TAR entry without retaining
/// the body. The body is re-streamed on the second pass.
struct TarHeaderSnapshot {
    path: String,
    link_name: Option<String>,
    symlink_target: Option<Vec<u8>>,
    entry_type: tar::EntryType,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    size: u64,
    dev_major: Option<u32>,
    dev_minor: Option<u32>,
}

/// Plan describing, for every entry, the (dev, ino) identity it should use
/// and the coherent `nlink` count for its group.
struct LinkPlan {
    /// Per-entry path-to-identity assignment.
    identity: HashMap<String, LinkId>,
    /// Per-entry path-to-nlink count. Entries not part of a hardlink group
    /// default to `1` via [`LinkPlan::nlink_for`].
    nlink: HashMap<String, u32>,
    /// Forward links: target path -> list of link entries to emit once the
    /// target is reached in the streaming pass. The target carries the
    /// body; the listed links carry size zero and share the target's
    /// `LinkId`.
    pending: HashMap<String, Vec<String>>,
    /// Targets that were never observed in the snapshot list. The streaming
    /// pass turns a non-empty set into an `InvalidTar` error.
    missing: Vec<String>,
}

impl LinkPlan {
    fn identity_for(&self, path: &str) -> Option<LinkId> {
        self.identity.get(path).copied()
    }
    fn nlink_for(&self, path: &str) -> u32 {
        self.nlink.get(path).copied().unwrap_or(1)
    }
}

/// Build a `LinkPlan` from the first-pass snapshot list.
///
/// Each hardlink group is keyed on the link's target path. The target entry
/// carries the inode and the body; the link entries share its `LinkId` and
/// report the same coherent `nlink` count (target included).
fn plan_links(headers: &[TarHeaderSnapshot]) -> LinkPlan {
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for h in headers {
        if h.entry_type.is_hard_link() {
            let target = h.link_name.clone().unwrap_or_default();
            groups.entry(target).or_default().push(h.path.clone());
        }
    }

    let mut identity: HashMap<String, LinkId> = HashMap::new();
    let mut nlink: HashMap<String, u32> = HashMap::new();
    let mut pending: HashMap<String, Vec<String>> = HashMap::new();
    let mut missing: Vec<String> = Vec::new();

    let mut next_dev: u32 = 1;
    let mut next_ino: u32 = 1;

    let fresh = |next_dev: &mut u32, next_ino: &mut u32| -> LinkId {
        let id = LinkId {
            dev: *next_dev,
            ino: *next_ino,
        };
        *next_dev = next_dev.saturating_add(1);
        *next_ino = next_ino.saturating_add(1);
        id
    };

    // First, allocate identities for hardlink targets that were observed in
    // the snapshot. Each observed target plus its members share the same
    // identity and `nlink == group_size + 1`.
    let known_targets: Vec<String> = headers
        .iter()
        .filter(|h| !h.entry_type.is_hard_link())
        .map(|h| h.path.clone())
        .collect();
    for target in &known_targets {
        if let Some(members) = groups.remove(target) {
            let id = fresh(&mut next_dev, &mut next_ino);
            let group_nlink = 1 + members.len() as u32;
            identity.insert(target.clone(), id);
            nlink.insert(target.clone(), group_nlink);
            for member in &members {
                identity.insert(member.clone(), id);
                nlink.insert(member.clone(), group_nlink);
            }
            // Hard-link records are omitted from their normal TAR position
            // and emitted exactly once after the target body. This is valid
            // for both target-before-link and link-before-target archives.
            pending.insert(target.clone(), members);
        }
    }

    // Remaining groups are forward links: target appears later than the
    // links. The identity is allocated immediately so the link entries can
    // reference it, but the streaming pass defers emission of the link
    // entries until the target is reached.
    for (target, members) in groups {
        let id = fresh(&mut next_dev, &mut next_ino);
        let group_nlink = 1 + members.len() as u32;
        identity.insert(target.clone(), id);
        nlink.insert(target.clone(), group_nlink);
        for member in &members {
            identity.insert(member.clone(), id);
            nlink.insert(member.clone(), group_nlink);
        }
        // The target is not yet confirmed to exist; record it as missing.
        // The streaming pass clears it once the target is observed.
        missing.push(target.clone());
        pending.insert(target, members);
    }

    // Every entry that is not part of a hardlink group gets its own fresh
    // identity with `nlink == 1`.
    for h in headers {
        if identity.contains_key(&h.path) {
            continue;
        }
        let id = fresh(&mut next_dev, &mut next_ino);
        identity.insert(h.path.clone(), id);
    }

    LinkPlan {
        identity,
        nlink,
        pending,
        missing,
    }
}

// ---------------------------------------------------------------------------
// `newc` writer
// ---------------------------------------------------------------------------

/// Emit a single `newc` entry whose body is already materialized in
/// `record.body`. Regular files are not handled here; the caller streams
/// them through [`write_streaming_entry`] so the body never needs to satisfy
/// `'static`. All writes go through [`TempWriter::write_all`] so the
/// running BLAKE3 digest and total byte count stay accurate.
pub fn write_entry(writer: &mut TempWriter, record: &Record) -> Result<(), Report<OperationError>> {
    let file_size = match &record.body {
        Body::Empty => 0u32,
        Body::Owned(bytes) => {
            let len = bytes.len();
            if len > u32::MAX as usize {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(format!("entry body exceeds u32: {len} bytes")));
            }
            len as u32
        }
    };

    let name_len = record.name.len() + 1;
    let header = encode_header(record, file_size, name_len);
    writer
        .write_all(&header)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    match &record.body {
        Body::Empty => {}
        Body::Owned(bytes) => {
            writer
                .write_all(bytes)
                .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        }
    }

    if let Some(pad) = pad_bytes(file_size as usize) {
        writer
            .write_all(&pad)
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    }
    Ok(())
}

/// Emit a `newc` entry whose body is streamed from `reader`. The caller has
/// already validated that the body type is a regular file, so we know the
/// `record.body` was assembled with `Body::Empty` (the streaming body lives
/// outside the record). All writes go through [`TempWriter::write_all`] so
/// the running BLAKE3 digest and total byte count stay accurate.
pub fn write_streaming_entry<R: Read + ?Sized>(
    writer: &mut TempWriter,
    record: &Record,
    size: u32,
    reader: &mut R,
) -> Result<(), Report<OperationError>> {
    let name_len = record.name.len() + 1;
    let header = encode_header(record, size, name_len);
    writer
        .write_all(&header)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    copy_exactly(reader, writer, size)?;

    if let Some(pad) = pad_bytes(size as usize) {
        writer
            .write_all(&pad)
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    }
    Ok(())
}

/// Encode the 110-byte fixed header plus the NUL-terminated name plus the
/// name padding as a single contiguous slice, so callers can issue a single
/// `write_all`. The layout mirrors `cpio::newc::Builder::into_header`.
pub fn encode_header(record: &Record, file_size: u32, name_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + name_len + 4);
    out.extend_from_slice(MAGIC_NEWC);
    out.extend(hex8(record.ino));
    out.extend(hex8(record.mode));
    out.extend(hex8(record.uid));
    out.extend(hex8(record.gid));
    out.extend(hex8(record.nlink));
    out.extend(hex8(record.mtime));
    out.extend(hex8(file_size));
    out.extend(hex8(record.dev_major));
    out.extend(hex8(record.dev_minor));
    out.extend(hex8(record.rdev_major));
    out.extend(hex8(record.rdev_minor));
    out.extend(hex8(name_len as u32));
    out.extend(hex8(0)); // checksum field unused in `newc`
    out.extend_from_slice(record.name.as_bytes());
    out.push(0);
    if let Some(pad) = pad_bytes(HEADER_LEN + name_len) {
        out.extend(pad);
    }
    out
}

/// Copy exactly `size` bytes from `reader` to `writer`, signalling an error
/// if the reader ends early or yields more than the declared size. Writes
/// go through [`TempWriter::write_all`] so the running digest stays
/// accurate.
fn copy_exactly<R: Read + ?Sized>(
    reader: &mut R,
    writer: &mut TempWriter,
    size: u32,
) -> Result<(), Report<OperationError>> {
    let mut remaining = size as u64;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = (buffer.len() as u64).min(remaining) as usize;
        let read = reader
            .read(&mut buffer[..want])
            .map_err(|err| OperationError::ReadSource.report().attach(err))?;
        if read == 0 {
            return Err(OperationError::InvalidTar.report().attach(format!(
                "regular file body ended early: {remaining} bytes remaining"
            )));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Emit the single `TRAILER!!!` entry that terminates a `newc` archive.
pub fn write_trailer(writer: &mut TempWriter) -> Result<(), Report<OperationError>> {
    let record = Record {
        name: TRAILER_NAME.to_string(),
        mode: 0,
        uid: 0,
        gid: 0,
        mtime: 0,
        nlink: 1,
        dev_major: 0,
        dev_minor: 0,
        ino: 0,
        rdev_major: 0,
        rdev_minor: 0,
        body: Body::Empty,
    };
    write_entry(writer, &record)
}

/// Return the padding required to align `len` up to a multiple of four
/// bytes, or `None` if `len` is already aligned.
pub fn pad_bytes(len: usize) -> Option<Vec<u8>> {
    let overhang = len % 4;
    if overhang == 0 {
        None
    } else {
        Some(vec![0u8; 4 - overhang])
    }
}

/// Format `value` as 8 lowercase hexadecimal digits.
pub fn hex8(value: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    write!(&mut out as &mut [u8], "{:08x}", value).expect("hex fits in 8 bytes");
    out
}

// ---------------------------------------------------------------------------
// Snapshotting
// ---------------------------------------------------------------------------

fn snapshot_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
) -> Result<TarHeaderSnapshot, Report<OperationError>> {
    let header = entry.header();
    let path_bytes = entry.path_bytes();
    let raw_path = std::str::from_utf8(&path_bytes)
        .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
    let path = normalize_path(raw_path)?;

    let raw_link = entry.link_name_bytes().map(|cow| cow.into_owned());
    let (link_name, symlink_target) = if header.entry_type().is_hard_link() {
        let link_name = raw_link.as_deref().ok_or_else(|| {
            OperationError::InvalidTar
                .report()
                .attach("hard link has no target")
        })?;
        let link_name = std::str::from_utf8(link_name)
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
        (Some(normalize_path(link_name)?), None)
    } else if header.entry_type() == tar::EntryType::Symlink {
        // A symlink target is payload, not an extraction path. Preserve its
        // exact bytes, including absolute and `..`-containing targets.
        (None, raw_link)
    } else {
        (None, None)
    };

    let mode = header
        .mode()
        .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
    // `newc` stores these fields as u32. Reject values that cannot be
    // represented instead of silently changing metadata during conversion.
    let uid = header
        .uid()
        .map_err(|err| OperationError::InvalidTar.report().attach(err))
        .and_then(|value| {
            u32::try_from(value).map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach(format!("uid {value} does not fit in newc u32"))
            })
        })?;
    let gid = header
        .gid()
        .map_err(|err| OperationError::InvalidTar.report().attach(err))
        .and_then(|value| {
            u32::try_from(value).map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach(format!("gid {value} does not fit in newc u32"))
            })
        })?;
    let mtime = header
        .mtime()
        .map_err(|err| OperationError::InvalidTar.report().attach(err))
        .and_then(|value| {
            u32::try_from(value).map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach(format!("mtime {value} does not fit in newc u32"))
            })
        })?;
    let size = entry.size();
    // The GNU header stores the device-major/minor fields as blank bytes for
    // non-device entries; calling `Header::device_major` on those parses the
    // blank field and fails. Only resolve the fields for entries whose type
    // warrants it.
    let is_device = matches!(
        header.entry_type(),
        tar::EntryType::Char | tar::EntryType::Block
    );
    let dev_major = if is_device {
        header
            .device_major()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?
    } else {
        None
    };
    let dev_minor = if is_device {
        header
            .device_minor()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?
    } else {
        None
    };

    Ok(TarHeaderSnapshot {
        path,
        link_name,
        symlink_target,
        entry_type: header.entry_type(),
        mode,
        uid,
        gid,
        mtime,
        size,
        dev_major,
        dev_minor,
    })
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

/// Translate a `TarHeaderSnapshot` plus its assigned identity and `nlink`
/// into a `Record` ready for `write_entry`. The body is `Empty` for
/// hardlink duplicates, the link target bytes for symlinks, and a streaming
/// placeholder for regular files (the caller substitutes a real reader just
/// before emission).
fn build_record(
    snapshot: &TarHeaderSnapshot,
    identity: Option<LinkId>,
    nlink: u32,
) -> Result<Record, Report<OperationError>> {
    let id = identity.ok_or_else(|| {
        OperationError::InvalidTar
            .report()
            .attach(format!("entry missing planned identity: {}", snapshot.path))
    })?;

    if snapshot.entry_type.is_pax_global_extensions()
        || snapshot.entry_type.is_pax_local_extensions()
    {
        // PAX headers carry metadata about subsequent entries; they cannot
        // be represented losslessly in `newc` and are not standalone members
        // of the resulting rootfs.
        return Err(OperationError::UnsupportedArtifact.report().attach(format!(
            "unsupported TAR entry type {:?} for {}",
            snapshot.entry_type, snapshot.path
        )));
    }

    // Compose the CPIO mode word from the TAR mode's permission bits plus
    // the `newc` file-type bits matching the entry's TAR type. We strip the
    // TAR-supplied type bits and reapply the `newc` canonical type so the
    // mode word is unambiguous regardless of how the TAR was written.
    let perm_bits = snapshot.mode & 0o7777;

    let rdev = if matches!(
        snapshot.entry_type,
        tar::EntryType::Char | tar::EntryType::Block
    ) {
        device_rdev(snapshot)?
    } else {
        (0u32, 0u32)
    };

    let (mode, body) = match snapshot.entry_type {
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            if snapshot.size > u32::MAX as u64 {
                return Err(OperationError::InvalidCpio.report().attach(format!(
                    "regular file {} exceeds u32 newc size limit: {} bytes",
                    snapshot.path, snapshot.size
                )));
            }
            let mode = perm_bits | 0o100000;
            // Streaming pass substitutes a real reader before emission.
            let body = Body::Empty;
            (mode, body)
        }
        tar::EntryType::Directory => {
            let mode = perm_bits | 0o040000;
            (mode, Body::Empty)
        }
        tar::EntryType::Symlink => {
            let target = snapshot.symlink_target.clone().ok_or_else(|| {
                OperationError::InvalidTar
                    .report()
                    .attach(format!("symlink {} has no target", snapshot.path))
            })?;
            let mode = perm_bits | 0o120000;
            (mode, Body::Owned(target))
        }
        tar::EntryType::Link => {
            // Hardlink duplicates carry size zero; the target's body is
            // emitted by its own record.
            let mode = perm_bits | 0o100000;
            (mode, Body::Empty)
        }
        tar::EntryType::Char => (perm_bits | 0o020000, Body::Empty),
        tar::EntryType::Block => (perm_bits | 0o060000, Body::Empty),
        tar::EntryType::Fifo => (perm_bits | 0o010000, Body::Empty),
        other => {
            return Err(OperationError::UnsupportedArtifact.report().attach(format!(
                "unsupported TAR entry type {other:?} for {}",
                snapshot.path
            )));
        }
    };

    Ok(Record {
        name: snapshot.path.clone(),
        mode,
        uid: snapshot.uid,
        gid: snapshot.gid,
        mtime: snapshot.mtime,
        nlink,
        dev_major: id.dev,
        dev_minor: 0,
        ino: id.ino,
        rdev_major: rdev.0,
        rdev_minor: rdev.1,
        body,
    })
}

/// Resolve the (rdev_major, rdev_minor) pair for a device entry. Defaults to
/// (0, 0) if the header omitted them.
fn device_rdev(snapshot: &TarHeaderSnapshot) -> Result<(u32, u32), Report<OperationError>> {
    Ok((
        snapshot.dev_major.unwrap_or(0),
        snapshot.dev_minor.unwrap_or(0),
    ))
}

// ---------------------------------------------------------------------------
// Blocking driver
// ---------------------------------------------------------------------------

/// Convert a TAR artifact into a CPIO `newc` artifact. Refer to
/// `docs/implementation-plan/ops/04-into-cpio.md` for the full contract.
///
/// This is the blocking body invoked from `ops::into_cpio`.
pub fn convert(entry: &FileRef) -> Result<FileRef, Report<OperationError>> {
    let path = entry.path();

    // Verify and consume the TAR through one stable handle. Two independent
    // path opens would permit a replacement between the digest check and the
    // conversion passes.
    let mut source = File::open(&path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(err)
            .attach(format!("open TAR at {}", path.display()))
    })?;
    let actual = io::compute_file_digest_from_file(&mut source, &path)
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    if actual != entry.file_digest {
        return Err(OperationError::DigestMismatch
            .report()
            .attach(format!("input TAR digest mismatch at {}", path.display())));
    }

    // ---- Pass 1: collect metadata and resolve links ---------------------
    let mut headers: Vec<TarHeaderSnapshot> = Vec::new();
    {
        source
            .seek(SeekFrom::Start(0))
            .map_err(|err| OperationError::ReadSource.report().attach(err))?;
        let mut archive = tar::Archive::new(&mut source);
        let entries = archive
            .entries()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
        for entry in entries {
            let mut entry = entry.map_err(|err| OperationError::InvalidTar.report().attach(err))?;
            // Reading the PAX extensions drains an XHeader entry and advances
            // the iterator past it; we do this opportunistically so the
            // entry is consumed cleanly even though we do not propagate PAX
            // data into the CPIO.
            let _ = entry.pax_extensions();
            headers.push(snapshot_entry(&mut entry)?);
        }
    }

    let mut plan = plan_links(&headers);

    // ---- Pass 2: stream bodies and emit CPIO records -------------------
    let mut writer = TempWriter::open(&path)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    {
        source
            .seek(SeekFrom::Start(0))
            .map_err(|err| OperationError::ReadSource.report().attach(err))?;
        let mut archive = tar::Archive::new(&mut source);
        let entries = archive
            .entries()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;

        let mut header_idx = 0;
        for entry in entries {
            let mut entry = entry.map_err(|err| OperationError::InvalidTar.report().attach(err))?;
            let _ = entry.pax_extensions();

            // Re-snapshot for layout parity verification. The two reads must
            // observe the same header; a divergence indicates a concurrently
            // mutated TAR and we abort rather than produce a non-deterministic
            // CPIO.
            let live = snapshot_entry(&mut entry)?;
            let planned = headers.get(header_idx).ok_or_else(|| {
                OperationError::InvalidTar
                    .report()
                    .attach("tar entries changed between passes")
            })?;
            if planned.path != live.path || planned.entry_type != live.entry_type {
                return Err(OperationError::InvalidTar
                    .report()
                    .attach("tar contents changed between passes"));
            }
            header_idx += 1;

            if live.entry_type.is_hard_link() {
                // The hard-link member is represented by the deferred record
                // emitted when its target is serialized. Never emit the TAR
                // member here as well, or forward links appear twice.
                std::io::copy(&mut entry, &mut std::io::sink())
                    .map_err(|err| OperationError::ReadSource.report().attach(err))?;
                continue;
            }

            let identity = plan.identity_for(&live.path);
            let nlink = plan.nlink_for(&live.path);

            // Regular files stream straight from the still-live `tar::Entry`
            // reader. Other entries have an `Empty`/`Owned` body that does
            // not need a reader.
            let needs_reader = matches!(
                live.entry_type,
                tar::EntryType::Regular | tar::EntryType::Continuous
            );

            let record = build_record(&live, identity, nlink)?;
            if needs_reader {
                if live.size > u32::MAX as u64 {
                    return Err(OperationError::InvalidCpio.report().attach(format!(
                        "regular file {} exceeds u32 newc size limit: {} bytes",
                        live.path, live.size
                    )));
                }
                write_streaming_entry(&mut writer, &record, live.size as u32, &mut entry)?;
            } else {
                write_entry(&mut writer, &record)?;
            }

            // This target has arrived: clear it from the pending/missing
            // lists and emit the deferred forward links, if any.
            if let Some(deferred) = plan.pending.remove(&live.path) {
                plan.missing.retain(|m| m != &live.path);
                for link_path in deferred {
                    let identity = plan
                        .identity_for(&link_path)
                        .expect("planned link identity");
                    let nlink = plan.nlink_for(&link_path);
                    let snapshot = headers
                        .iter()
                        .find(|h| h.path == link_path)
                        .expect("planned link snapshot");
                    let record = build_record(snapshot, Some(identity), nlink)?;
                    debug_assert!(matches!(record.body, Body::Empty));
                    write_entry(&mut writer, &record)?;
                }
            }
        }

        if header_idx != headers.len() {
            return Err(OperationError::InvalidTar
                .report()
                .attach("tar entries changed between passes"));
        }
    }

    // A link still pending resolves to a target that never arrived. That is
    // a hard error per the contract.
    if !plan.pending.is_empty() || !plan.missing.is_empty() {
        let targets = plan
            .pending
            .keys()
            .chain(plan.missing.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(OperationError::InvalidTar
            .report()
            .attach(format!("hardlink target(s) not present in tar: {targets}")));
    }

    write_trailer(&mut writer)?;

    writer
        .flush()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    let published = writer
        .publish()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    Ok(FileRef {
        uuid: entry.uuid,
        namespace: entry.namespace,
        file_digest: published.file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_leading_dot_slash() {
        assert_eq!(normalize_path("./a/b").unwrap(), "a/b");
        assert_eq!(normalize_path("./././x").unwrap(), "x");
    }

    #[test]
    fn normalize_accepts_root_directory_marker() {
        assert_eq!(normalize_path(".").unwrap(), ".");
        assert_eq!(normalize_path("./").unwrap(), ".");
        assert_eq!(normalize_path("././").unwrap(), ".");
        assert_eq!(normalize_path("./lib/").unwrap(), "lib");
        assert_eq!(normalize_path("lib\\").unwrap(), "lib");
    }

    #[test]
    fn normalize_rejects_absolute_unix_paths() {
        let err = normalize_path("/etc/passwd").expect_err("absolute rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("unsafe path"), "{msg}");
    }

    #[test]
    fn normalize_rejects_dotdot() {
        let err = normalize_path("a/../b").expect_err("`..` rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("unsafe path"), "{msg}");
    }

    #[cfg(windows)]
    #[test]
    fn normalize_rejects_drive_prefix() {
        let err = normalize_path("C:\\Windows").expect_err("drive prefix rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("unsafe path"), "{msg}");
    }

    #[test]
    fn normalizes_backslashes_to_slashes() {
        assert_eq!(normalize_path("a\\b\\c").unwrap(), "a/b/c");
    }

    #[test]
    fn preserves_whiteout_names() {
        assert_eq!(normalize_path(".wh.foo").unwrap(), ".wh.foo");
        assert_eq!(normalize_path("./.wh.bar").unwrap(), ".wh.bar");
    }

    #[test]
    fn hex8_formats_lower_case() {
        assert_eq!(&hex8(0), b"00000000");
        assert_eq!(&hex8(0xdeadbeef), b"deadbeef");
    }

    #[test]
    fn pad_returns_none_for_aligned_lengths() {
        assert!(pad_bytes(4).is_none());
        assert_eq!(pad_bytes(5).unwrap().len(), 3);
    }
}
