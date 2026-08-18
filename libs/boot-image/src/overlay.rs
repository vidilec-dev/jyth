//! Overlay user-supplied entries onto a prepared image rootfs.
//!
//! The `image` crate materializes a kernel blob and a rootfs `cpio` archive.
//! This module *merges* the caller's overlay `File` and `Directory` entries
//! on top of that prepared rootfs — the same way the Linux kernel's
//! initramfs reader overlays concatenated cpio archives: a later entry
//! for a path wins over an earlier one.
//!
//! Because a given `(rootfs, entries)` tuple should be reproducible, we
//! record a *canonical* manifest (base rootfs digest + each file's
//! origin/digest/size/mode/path, plus each dir's path/mode), hash it,
//! and cache the merged result under the versioned derived cache. The
//! materialized files owned by the caller are left untouched so they can be
//! reused by other assemblies with different overlays.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::Path;

use error_stack::{Report, ResultExt};
use thiserror::Error;

use crate::cache;
use crate::{BootImageError, GuestPathReason};

// ---------------------------------------------------------------------------
// Guest paths and validated overlay entries
// ---------------------------------------------------------------------------

/// A canonical path relative to the guest filesystem root.
///
/// The host-facing builder accepts both `/etc/hostname` and
/// `etc/hostname`, but the archive and cache identity use one representation:
/// `etc/hostname`. Keeping the leading separator out of the stored value also
/// matches the names emitted by the image crate for base-rootfs entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GuestPath(String);

impl GuestPath {
    fn parse(path: &Path) -> Result<Self, BootImageError> {
        let shown = path.to_string_lossy().into_owned();
        let raw = path
            .to_str()
            .ok_or_else(|| BootImageError::InvalidGuestPath {
                path: shown.clone(),
                reason: GuestPathReason::NonRepresentable,
            })?;

        if raw.contains('\0') {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::NulByte,
            });
        }

        // A double leading separator is a UNC prefix on Windows. Drive
        // prefixes are rejected even when this code is running on another
        // host, because the target namespace is always the Linux guest.
        let normalized = raw.replace('\\', "/");
        if normalized.starts_with("//") {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::WindowsPrefix,
            });
        }
        let without_leading_separators = normalized.trim_start_matches('/');
        if without_leading_separators.is_empty() {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::EmptyTerminalName,
            });
        }

        let first_component = without_leading_separators
            .split('/')
            .find(|component| !component.is_empty() && *component != ".")
            .unwrap_or_default();
        if first_component.len() >= 2
            && first_component.as_bytes()[1] == b':'
            && first_component.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::WindowsPrefix,
            });
        }

        let raw_components: Vec<_> = without_leading_separators.split('/').collect();
        let mut components = Vec::new();
        for (index, component) in raw_components.iter().enumerate() {
            if component.is_empty() {
                return Err(BootImageError::InvalidGuestPath {
                    path: shown,
                    reason: if index + 1 == raw_components.len() {
                        GuestPathReason::EmptyTerminalName
                    } else {
                        GuestPathReason::EmptyComponent
                    },
                });
            }
            if *component == ".." {
                return Err(BootImageError::InvalidGuestPath {
                    path: shown,
                    reason: GuestPathReason::ParentTraversal,
                });
            }
            if *component != "." {
                components.push(*component);
            }
        }

        if components.is_empty() {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::EmptyTerminalName,
            });
        }

        let canonical = components.join("/");
        // `newc` stores the name length in a u32 and includes its trailing
        // NUL. The normal path limit is much smaller, but this makes the
        // representation boundary explicit and deterministic.
        if canonical.len() >= u32::MAX as usize {
            return Err(BootImageError::InvalidGuestPath {
                path: shown,
                reason: GuestPathReason::TooLong,
            });
        }

        Ok(Self(canonical))
    }

    fn display_path(&self) -> String {
        format!("/{}", self.0)
    }

    fn is_reserved(&self) -> bool {
        self.0 == "init" || self.0.starts_with("init/") || self.0 == "TRAILER!!!"
    }

    fn cpio_name(&self) -> &str {
        &self.0
    }
}

/// A user-supplied overlay entry whose content has already been resolved.
///
/// `path` is the guest path exactly as the caller stored it: leading
/// separators, backslashes, and `.`/`..` components are normalized during
/// validation. `File` entries carry their resolved content bytes (host-side
/// sources — including Rust process executables compiled by the caller —
/// are resolved BEFORE this crate sees them) and the manifest `origin`
/// string that identifies where the content came from (`bytes:<blake3>` or
/// `crate:<identity>`). The hardcoded init binary is NOT part of this list:
/// the assembly flow appends it at `/init` after validation.
#[derive(Debug, Clone)]
pub struct GuestOverlayEntry {
    /// The guest path, as supplied by the caller.
    pub path: String,
    /// The kind and resolved payload of the entry.
    pub kind: OverlayEntryKind,
}

/// The kind of one [`GuestOverlayEntry`].
#[derive(Debug, Clone)]
pub enum OverlayEntryKind {
    /// A regular file with resolved content bytes and permission bits.
    File {
        /// The resolved file content.
        content: Vec<u8>,
        /// The permission bits (only `0o777` is emitted).
        mode: u32,
        /// The manifest origin: `bytes:<blake3>` or `crate:<identity>`.
        origin: String,
    },
    /// An explicit directory entry with permission bits.
    Directory {
        /// The permission bits (only `0o777` is emitted).
        mode: u32,
    },
}

impl GuestOverlayEntry {
    /// Create a regular-file overlay entry.
    pub fn file(
        path: impl Into<String>,
        content: Vec<u8>,
        mode: u32,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            kind: OverlayEntryKind::File {
                content,
                mode,
                origin: origin.into(),
            },
        }
    }

    /// Create a directory overlay entry.
    pub fn directory(path: impl Into<String>, mode: u32) -> Self {
        Self {
            path: path.into(),
            kind: OverlayEntryKind::Directory { mode },
        }
    }
}

/// The registry kind used for duplicate/conflict detection. Kept separate
/// from the payload-carrying [`OverlayEntryKind`] so equal paths compare by
/// kind only: two files with the same path are a duplicate even when their
/// content differs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum EntryKind {
    File,
    Directory,
}

impl EntryKind {
    fn label(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
        }
    }
}

/// A materialized file whose path and content have already been validated.
/// Crate sources have been built before this value is created.
#[derive(Debug)]
pub(crate) struct ResolvedFile {
    pub(crate) path: GuestPath,
    mode: u32,
    data: Vec<u8>,
    origin: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedDir {
    path: GuestPath,
    mode: u32,
}

pub(crate) struct ValidatedOverlay {
    pub(crate) files: Vec<ResolvedFile>,
    pub(crate) dirs: Vec<ValidatedDir>,
}

fn register_overlay_path(
    entries: &mut BTreeMap<GuestPath, EntryKind>,
    path: GuestPath,
    kind: EntryKind,
) -> Result<(), BootImageError> {
    if path.is_reserved() {
        return Err(BootImageError::ReservedOverlayPath {
            path: path.display_path(),
        });
    }

    match entries.insert(path.clone(), kind) {
        None => Ok(()),
        Some(previous) if previous == kind => Err(BootImageError::DuplicateOverlayPath {
            path: path.display_path(),
        }),
        Some(previous) => Err(BootImageError::OverlayPathConflict {
            path: path.display_path(),
            conflict: format!("already registered as a {}", previous.label()),
        }),
    }
}

/// Validate every entry path, detect duplicates and conflicts, and split the
/// entries into sorted file and directory sets. Called before the init
/// binary is built or the derived cache is touched.
pub(crate) fn validate_entries(
    entries: Vec<GuestOverlayEntry>,
) -> Result<ValidatedOverlay, BootImageError> {
    let mut registry = BTreeMap::new();
    let mut files = Vec::new();
    let mut dirs = Vec::new();

    for entry in entries {
        let path = GuestPath::parse(Path::new(&entry.path))?;
        match entry.kind {
            OverlayEntryKind::File {
                content,
                mode,
                origin,
            } => {
                register_overlay_path(&mut registry, path.clone(), EntryKind::File)?;
                files.push(ResolvedFile {
                    path,
                    mode,
                    data: content,
                    origin,
                });
            }
            OverlayEntryKind::Directory { mode } => {
                register_overlay_path(&mut registry, path.clone(), EntryKind::Directory)?;
                dirs.push(ValidatedDir { path, mode });
            }
        }
    }

    // A file cannot be an ancestor of another overlay entry: that would
    // otherwise leave the guest filesystem with two incompatible results.
    for path in registry.keys() {
        let mut parent = path.0.as_str();
        while let Some(separator) = parent.rfind('/') {
            parent = &parent[..separator];
            if let Some(EntryKind::File) = registry.get(&GuestPath(parent.to_string())) {
                return Err(BootImageError::OverlayPathConflict {
                    path: path.display_path(),
                    conflict: format!("file ancestor /{parent}"),
                });
            }
        }
    }

    // These are the only sorted collections consumed by both the manifest
    // and CPIO emitter. No later stage re-sorts them independently.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    dirs.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(ValidatedOverlay { files, dirs })
}

// ---------------------------------------------------------------------------
// Manifest (canonical) — hashed to derive the cache key
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileManifest {
    /// Where the content came from: `bytes:<blake3>` or
    /// `crate:<manifest>[|bin=<name>]`.
    origin: String,
    path: String,
    mode: u32,
    digest: String,
    size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DirManifest {
    path: String,
    mode: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RootfsManifest {
    schema_version: u32,
    /// `blake3_<hex>` of the raw (pre-overlay) rootfs cpio bytes.
    base: String,
    base_size: u64,
    files: Vec<FileManifest>,
    dirs: Vec<DirManifest>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RootfsMetadata {
    pub(crate) schema_version: u32,
    pub(crate) key: String,
    pub(crate) artifact: cache::ArtifactMetadata,
}

// Inode numbers in the overlay archive are offset well above anything the
// base archive could use, so an overlay entry can never accidentally
// collide with a base inode (which would make the kernel treat it as a
// hard link to a base file with the same inode).
const ROOTFS_INODE_BASE: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// cpio emission / merge
// ---------------------------------------------------------------------------

/// Failures encountered when assembling, merging, or caching guest overlay rootfs artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OverlayError {
    /// An overlay file exceeds the maximum 32-bit size supported by the CPIO newc format.
    #[error("overlay file exceeds maximum CPIO newc size limit")]
    FileTooLarge,

    /// Emitting a CPIO entry or archive trailer failed.
    #[error("failed to emit CPIO archive")]
    CpioEmit,

    /// A CPIO archive structure is malformed or invalid.
    #[error("invalid CPIO archive from {archive}")]
    InvalidCpioArchive {
        /// Label of the archive (e.g. "base rootfs", "overlay rootfs").
        archive: &'static str,
    },

    /// Accessing the overlay cache directory failed.
    #[error("failed to access overlay cache directory")]
    DirectoryAccess,

    /// Serializing the canonical rootfs manifest to JSON failed.
    #[error("failed to serialize rootfs manifest")]
    SerializeManifest,

    /// Validating a cached rootfs artifact failed.
    #[error("failed to validate cached rootfs")]
    ValidateCache,
}

impl OverlayError {
    /// Wrap this error in an [`error_stack::Report`].
    pub fn report(self) -> Report<Self> {
        Report::new(self)
    }
}

/// Strip exactly one complete trailing cpio `TRAILER!!!` entry. Every entry,
/// payload, padding byte range, and the end of the archive is consumed before
/// the body is returned. This is intentionally strict because the result is
/// written to the derived cache and later treated as boot input.
fn strip_trailer<'a>(
    bytes: &'a [u8],
    archive: &'static str,
) -> Result<&'a [u8], Report<OverlayError>> {
    let mut remaining = bytes;
    let mut body_len = 0usize;

    loop {
        let reader = cpio::NewcReader::new(remaining).map_err(|error| {
            OverlayError::InvalidCpioArchive { archive }
                .report()
                .attach(error)
        })?;
        if reader.entry().is_trailer() {
            if reader.entry().file_size() != 0 {
                return Err(OverlayError::InvalidCpioArchive { archive }
                    .report()
                    .attach("TRAILER!!! entry has a non-zero payload"));
            }
            let tail = reader.finish().map_err(|error| {
                OverlayError::InvalidCpioArchive { archive }
                    .report()
                    .attach(error)
            })?;
            if tail.iter().any(|byte| *byte != 0) {
                return Err(OverlayError::InvalidCpioArchive { archive }
                    .report()
                    .attach("non-padding bytes after the complete TRAILER!!! entry"));
            }
            return Ok(&bytes[..body_len]);
        }

        let tail = reader.finish().map_err(|error| {
            OverlayError::InvalidCpioArchive { archive }
                .report()
                .attach(error)
        })?;
        let consumed = remaining.len() - tail.len();
        if consumed == 0 {
            return Err(OverlayError::InvalidCpioArchive { archive }
                .report()
                .attach("CPIO reader made no progress"));
        }
        body_len += consumed;
        remaining = tail;
    }
}

pub(crate) fn overlay_to_cpio(
    resolved: &[ResolvedFile],
    dirs: &[ValidatedDir],
) -> Result<Vec<u8>, Report<OverlayError>> {
    let mut out: Vec<u8> = Vec::new();
    let mut ino = ROOTFS_INODE_BASE;

    // Directories first so a later file's parent dir already exists.
    for d in dirs {
        let b = cpio::newc::Builder::new(d.path.cpio_name())
            .mode(0o040000 | (d.mode & 0o777))
            .ino(ino)
            .nlink(2);
        b.write(&mut out, 0).finish().map_err(|e| {
            OverlayError::CpioEmit
                .report()
                .attach(format!("directory: {}", d.path.display_path()))
                .attach(e)
        })?;
        ino += 1;
    }

    for file in resolved {
        let file_size = u32::try_from(file.data.len()).map_err(|_| {
            OverlayError::FileTooLarge
                .report()
                .attach(format!("file: {}", file.path.display_path()))
                .attach(format!(
                    "size: {} bytes (max: {} bytes)",
                    file.data.len(),
                    u32::MAX
                ))
        })?;
        let m = 0o100000 | (file.mode & 0o777);
        let mut writer = cpio::newc::Builder::new(file.path.cpio_name())
            .mode(m)
            .ino(ino)
            .nlink(1)
            .write(&mut out, file_size);
        writer.write_all(&file.data).map_err(|e| {
            OverlayError::CpioEmit
                .report()
                .attach(format!("file: {}", file.path.display_path()))
                .attach(e)
        })?;
        writer.finish().map_err(|e| {
            OverlayError::CpioEmit
                .report()
                .attach(format!("file: {}", file.path.display_path()))
                .attach(e)
        })?;
        ino += 1;
    }

    let out = cpio::newc::trailer(out)
        .map_err(|e| OverlayError::CpioEmit.report().attach("trailer").attach(e))?;
    Ok(out)
}

/// Merge `base` (a complete rootfs cpio) with `overlay` (a complete
/// overlay cpio) into a single archive: strip both trailers, concat the
/// bodies, emit one trailing trailer. Overlay entries that share a path
/// with a base entry win (initramfs semantics).
pub(crate) fn merge_rootfs(base: &[u8], overlay: &[u8]) -> Result<Vec<u8>, Report<OverlayError>> {
    let mut merged = strip_trailer(base, "base rootfs")?.to_vec();
    merged.extend_from_slice(strip_trailer(overlay, "overlay rootfs")?);
    let out = cpio::newc::trailer(merged)
        .map_err(|e| OverlayError::CpioEmit.report().attach("trailer").attach(e))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Rootfs cache key and validity
// ---------------------------------------------------------------------------

pub(crate) fn rootfs_dir() -> Result<std::path::PathBuf, Report<OverlayError>> {
    cache::overlay_dir().change_context(OverlayError::DirectoryAccess)
}

pub(crate) fn rootfs_manifest_key(
    base_bytes: &[u8],
    resolved: &[ResolvedFile],
    dirs: &[ValidatedDir],
) -> Result<String, Report<OverlayError>> {
    let file_manifests = resolved
        .iter()
        .map(|file| FileManifest {
            origin: file.origin.clone(),
            path: file.path.cpio_name().to_string(),
            mode: file.mode,
            digest: format!("blake3_{}", blake3::hash(&file.data).to_hex()),
            size: file.data.len() as u64,
        })
        .collect();
    let dir_manifests = dirs
        .iter()
        .map(|dir| DirManifest {
            path: dir.path.cpio_name().to_string(),
            mode: dir.mode,
        })
        .collect();
    let manifest = RootfsManifest {
        schema_version: cache::CACHE_SCHEMA_VERSION,
        base: format!("blake3_{}", blake3::hash(base_bytes).to_hex()),
        base_size: base_bytes.len() as u64,
        files: file_manifests,
        dirs: dir_manifests,
    };
    let manifest_json = serde_json::to_string(&manifest).map_err(|e| {
        OverlayError::SerializeManifest
            .report()
            .attach(e.to_string())
    })?;
    Ok(format!(
        "blake3_{}",
        blake3::hash(manifest_json.as_bytes()).to_hex()
    ))
}

/// A hardcoded initramfs stage entry: the `init` binary at `/init`
/// (executable), regardless of any user-supplied files, so it always wins
/// as pid 1.
pub(crate) fn init_overlay_file(bytes: Vec<u8>) -> ResolvedFile {
    ResolvedFile {
        path: GuestPath("init".to_string()),
        mode: 0o755,
        data: bytes,
        origin: "crate:init".to_string(),
    }
}

/// True when the cached rootfs at `path` has the expected size and its CPIO
/// structure is complete: one terminal `TRAILER!!!` entry, no non-padding
/// bytes after it.
pub(crate) fn cached_rootfs_is_valid(
    path: &std::path::Path,
    expected_size: u64,
) -> Result<bool, Report<OverlayError>> {
    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(OverlayError::ValidateCache
                .report()
                .attach(format!("cached rootfs path: {}", path.display()))
                .attach(e));
        }
    };
    if !metadata.is_file() || metadata.len() != expected_size {
        return Ok(false);
    }
    // Stream the structural validation in a single pass: one complete
    // `TRAILER!!!` entry, no non-padding bytes after it. The caller has
    // already hashed the file through `artifact_matches`, so this pass never
    // buffers the archive in memory.
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(OverlayError::ValidateCache
                .report()
                .attach(format!("cached rootfs path: {}", path.display()))
                .attach(e));
        }
    };
    let mut remaining = std::io::BufReader::new(file);
    loop {
        let reader = match cpio::NewcReader::new(remaining) {
            Ok(reader) => reader,
            Err(_) => return Ok(false),
        };
        if reader.entry().is_trailer() {
            if reader.entry().file_size() != 0 {
                return Ok(false);
            }
            let mut tail = match reader.finish() {
                Ok(tail) => tail,
                Err(_) => return Ok(false),
            };
            let mut buffer = [0u8; 64 * 1024];
            loop {
                match tail.read(&mut buffer) {
                    Ok(0) => return Ok(true),
                    Ok(read) => {
                        if buffer[..read].iter().any(|byte| *byte != 0) {
                            return Ok(false);
                        }
                    }
                    Err(_) => return Ok(false),
                }
            }
        }
        remaining = match reader.finish() {
            Ok(remaining) => remaining,
            Err(_) => return Ok(false),
        };
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(path: &str, data: &[u8]) -> ResolvedFile {
        ResolvedFile {
            path: GuestPath::parse(Path::new(path)).unwrap(),
            mode: 0o644,
            data: data.to_vec(),
            origin: format!("bytes:blake3_{}", blake3::hash(data).to_hex()),
        }
    }

    fn validated_dir(path: &str) -> ValidatedDir {
        ValidatedDir {
            path: GuestPath::parse(Path::new(path)).unwrap(),
            mode: 0o755,
        }
    }

    fn file_entry(path: &str, data: &[u8]) -> GuestOverlayEntry {
        GuestOverlayEntry::file(
            path,
            data.to_vec(),
            0o644,
            format!("bytes:blake3_{}", blake3::hash(data).to_hex()),
        )
    }

    fn dir_entry(path: &str) -> GuestOverlayEntry {
        GuestOverlayEntry::directory(path, 0o755)
    }

    /// Walk a cpio, returning `path -> bytes` for every non-trailer entry
    /// that carries data.
    fn walk_cpio(bytes: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
        let mut reader = bytes;
        while let Ok(mut r) = cpio::NewcReader::new(reader) {
            let entry = r.entry();
            let name = entry.name().to_string();
            let size = entry.file_size() as usize;
            if entry.is_trailer() {
                break;
            }
            let buf = if size > 0 {
                let mut b = vec![0u8; size];
                std::io::Read::read_exact(&mut r, &mut b).unwrap();
                b
            } else {
                Vec::new()
            };
            out.insert(name, buf);
            reader = r.finish().unwrap();
        }
        out
    }

    #[test]
    fn overlay_to_cpio_emits_files_and_dirs() {
        let dirs = vec![validated_dir("/etc")];
        let resolved = vec![resolved("/etc/motd", b"hi")];
        let cpio = overlay_to_cpio(&resolved, &dirs).unwrap();
        let entries = walk_cpio(&cpio);
        assert!(entries.contains_key("etc"), "dir etc missing");
        assert_eq!(entries.get("etc/motd").unwrap().as_slice(), b"hi");
    }

    #[test]
    fn duplicate_files_are_rejected() {
        let entries = vec![
            file_entry("/etc/hostname", b"a"),
            file_entry("etc/hostname", b"a"),
        ];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::DuplicateOverlayPath { .. })
        ));
    }

    #[test]
    fn duplicate_directories_are_rejected() {
        let entries = vec![dir_entry("/etc"), dir_entry("etc")];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::DuplicateOverlayPath { .. })
        ));
    }

    #[test]
    fn file_directory_collisions_are_rejected() {
        let entries = vec![file_entry("/etc", b"x"), dir_entry("etc")];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::OverlayPathConflict { .. })
        ));
    }

    #[test]
    fn an_explicit_directory_parent_can_contain_a_file() {
        let entries = vec![file_entry("/etc/hostname", b"x"), dir_entry("/etc")];
        assert!(validate_entries(entries).is_ok());
    }

    #[test]
    fn a_file_cannot_be_the_parent_of_another_overlay_entry() {
        let entries = vec![file_entry("/etc", b"x"), dir_entry("/etc/subdir")];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::OverlayPathConflict { .. })
        ));
    }

    #[test]
    fn reserved_init_is_rejected_for_files_and_directories() {
        let file = vec![file_entry("/init", b"x")];
        assert!(matches!(
            validate_entries(file),
            Err(BootImageError::ReservedOverlayPath { .. })
        ));

        let dir = vec![dir_entry("init")];
        assert!(matches!(
            validate_entries(dir),
            Err(BootImageError::ReservedOverlayPath { .. })
        ));

        let trailer_name = vec![file_entry("/TRAILER!!!", b"x")];
        assert!(matches!(
            validate_entries(trailer_name),
            Err(BootImageError::ReservedOverlayPath { .. })
        ));
    }

    #[test]
    fn parent_traversal_is_rejected_before_validation_can_succeed() {
        let entries = vec![file_entry("/etc/../init", b"x")];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::InvalidGuestPath {
                reason: GuestPathReason::ParentTraversal,
                ..
            })
        ));
    }

    #[test]
    fn windows_prefixes_are_rejected() {
        for path in [r"C:\Windows\system32", "/C:/Windows/system32"] {
            let entries = vec![file_entry(path, b"x")];
            assert!(matches!(
                validate_entries(entries),
                Err(BootImageError::InvalidGuestPath {
                    reason: GuestPathReason::WindowsPrefix,
                    ..
                })
            ));
        }
    }

    #[test]
    fn empty_terminal_names_are_rejected() {
        let entries = vec![file_entry("/etc/", b"x")];
        assert!(matches!(
            validate_entries(entries),
            Err(BootImageError::InvalidGuestPath {
                reason: GuestPathReason::EmptyTerminalName,
                ..
            })
        ));
    }

    #[test]
    fn opposite_insertion_orders_are_byte_and_identity_deterministic() {
        let first_entries = vec![
            file_entry("/etc/z-last", b"z"),
            file_entry("/etc/a-first", b"a"),
            dir_entry("/etc/z"),
            dir_entry("/etc/a"),
        ];
        let second_entries = vec![
            dir_entry("etc/a"),
            file_entry("etc/a-first", b"a"),
            dir_entry("/etc/z"),
            file_entry("etc/z-last", b"z"),
        ];

        let first = validate_entries(first_entries).unwrap();
        let second = validate_entries(second_entries).unwrap();
        let empty_base = overlay_to_cpio(&[], &[]).unwrap();

        assert_eq!(
            rootfs_manifest_key(&empty_base, &first.files, &first.dirs).unwrap(),
            rootfs_manifest_key(&empty_base, &second.files, &second.dirs).unwrap()
        );
        assert_eq!(
            overlay_to_cpio(&first.files, &first.dirs).unwrap(),
            overlay_to_cpio(&second.files, &second.dirs).unwrap()
        );
    }

    #[test]
    fn merge_rootfs_overrides_a_base_entry_with_a_valid_user_file() {
        let base = overlay_to_cpio(&[resolved("/etc/hostname", b"base")], &[]).unwrap();
        let overlay = overlay_to_cpio(&[resolved("etc/hostname", b"custom")], &[]).unwrap();

        let merged = merge_rootfs(&base, &overlay).unwrap();
        let entries = walk_cpio(&merged);
        assert_eq!(entries.get("etc/hostname").unwrap().as_slice(), b"custom");
    }

    #[test]
    fn merge_rootfs_preserves_base() {
        let base = overlay_to_cpio(&[resolved("/etc/hostname", b"base")], &[]).unwrap();

        let overlay = overlay_to_cpio(&[resolved("/etc/motd", b"new")], &[]).unwrap();

        let merged = merge_rootfs(&base, &overlay).unwrap();
        let entries = walk_cpio(&merged);
        assert_eq!(entries.get("etc/hostname").unwrap().as_slice(), b"base");
        assert_eq!(entries.get("etc/motd").unwrap().as_slice(), b"new");
    }

    #[test]
    fn truncated_header_is_rejected() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        assert!(strip_trailer(&archive[..100], "truncated header").is_err());
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let body_len = strip_trailer(&archive, "valid").unwrap().len();
        let mut truncated = archive[..body_len - 1].to_vec();
        truncated.extend_from_slice(&archive[body_len..]);
        assert!(strip_trailer(&truncated, "truncated payload").is_err());
    }

    #[test]
    fn missing_trailer_is_rejected() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let body = strip_trailer(&archive, "valid").unwrap();
        let other = overlay_to_cpio(&[], &[]).unwrap();
        let error = merge_rootfs(body, &other).unwrap_err();
        assert!(error.to_string().contains("base rootfs"));
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let mut corrupted = archive.clone();
        corrupted.extend_from_slice(b"garbage");
        let other = overlay_to_cpio(&[], &[]).unwrap();
        assert!(merge_rootfs(&corrupted, &other).is_err());
    }

    #[test]
    fn zero_padding_after_the_trailer_is_accepted() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let mut padded = archive.clone();
        padded.extend_from_slice(&[0; 512]);
        let other = overlay_to_cpio(&[], &[]).unwrap();
        assert!(merge_rootfs(&padded, &other).is_ok());
    }

    #[test]
    fn corrupted_cached_rootfs_is_not_valid() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let path =
            std::env::temp_dir().join(format!("jyth-corrupt-rootfs-{}", uuid::Uuid::now_v7()));
        std::fs::write(&path, &archive[..archive.len() - 1]).unwrap();
        assert!(!cached_rootfs_is_valid(&path, (archive.len() - 1) as u64).unwrap());
        let _ = std::fs::remove_file(path);
    }

    fn cached_rootfs_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("jyth-{name}-{}", uuid::Uuid::now_v7()))
    }

    #[test]
    fn complete_cached_rootfs_is_valid() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let path = cached_rootfs_path("valid-rootfs");
        std::fs::write(&path, &archive).unwrap();
        assert!(cached_rootfs_is_valid(&path, archive.len() as u64).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_rootfs_with_trailing_garbage_is_not_valid() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let mut corrupted = archive.clone();
        corrupted.extend_from_slice(b"garbage");
        let path = cached_rootfs_path("trailing-rootfs");
        std::fs::write(&path, &corrupted).unwrap();
        assert!(!cached_rootfs_is_valid(&path, corrupted.len() as u64).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_rootfs_with_zero_padding_after_the_trailer_is_valid() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let mut padded = archive.clone();
        padded.extend_from_slice(&[0; 512]);
        let path = cached_rootfs_path("padded-rootfs");
        std::fs::write(&path, &padded).unwrap();
        assert!(cached_rootfs_is_valid(&path, padded.len() as u64).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_rootfs_with_wrong_size_is_not_valid() {
        let archive = overlay_to_cpio(&[resolved("etc/file", b"body")], &[]).unwrap();
        let path = cached_rootfs_path("wrong-size-rootfs");
        std::fs::write(&path, &archive).unwrap();
        assert!(!cached_rootfs_is_valid(&path, archive.len() as u64 + 1).unwrap());
        let _ = std::fs::remove_file(path);
    }
}
