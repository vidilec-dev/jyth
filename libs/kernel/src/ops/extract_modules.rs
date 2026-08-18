//! Extract a kernel's loadable module tree into a CPIO fragment.
//!
//! LinuxKit kernel images keep the raw bzImage at `kernel` and put the
//! matching `/lib/modules` tree in a nested `kernel.tar`. Other kernel
//! archives may carry the module tree directly. This operation accepts both
//! layouts and emits a deterministic, metadata-preserving CPIO fragment that
//! the image builder can merge into the selected root filesystem.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use ::cpio as cpio_crate;

use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    ops::{
        MAX_IN_MEMORY_ENTRY_BYTES, bounded_join,
        cpio::{self, Body, Record, normalize_path},
        error::OperationError,
        io::{self, TempWriter},
    },
    storage::{file_ref::FileRef, link_ref::LinkRef, namespace::Namespace},
};

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// Extract `/lib/modules/**` from a CPIO kernel image. `Ok(None)` means the
/// source did not contain a loadable module file and no destination artifact
/// was published.
pub(crate) async fn extract_modules(
    src: &FileRef,
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<Option<FileRef>, Report<OperationError>> {
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
    if dst.namespace != Namespace::Modules {
        return Err(OperationError::UnsupportedArtifact.report().attach(format!(
            "extract_modules requires Namespace::Modules for the destination, got {:?}",
            dst.namespace
        )));
    }

    let source = src.clone();
    let destination = dst.namespace.join(dst.uuid.to_string());
    let dst_uuid = dst.uuid;
    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                run_blocking(&source, &destination, dst_uuid, &token)
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

struct ModuleEntry {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    nlink: u32,
    dev_major: u32,
    dev_minor: u32,
    ino: u32,
    rdev_major: u32,
    rdev_minor: u32,
    body: Body,
}

impl ModuleEntry {
    fn has_payload(&self) -> bool {
        !matches!(self.mode & S_IFMT, S_IFDIR) && !matches!(&self.body, Body::Empty)
    }
}

fn run_blocking(
    source: &FileRef,
    destination: &Path,
    dst_uuid: uuid::Uuid,
    token: &CancellationToken,
) -> Result<Option<FileRef>, Report<OperationError>> {
    let source_path = source.path();
    let mut file = File::open(&source_path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(source_path.clone()))
            .attach(err)
    })?;
    let actual = io::compute_file_digest_from_file(&mut file, &source_path)
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    if actual != source.file_digest {
        return Err(OperationError::DigestMismatch
            .report()
            .attach(PathLabel(source_path.clone()))
            .attach(DigestPair {
                expected: source.file_digest,
                actual,
            }));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    let entries = read_source_cpio(file, &source_path, token)?;
    if !entries.values().any(ModuleEntry::has_payload) {
        return Ok(None);
    }

    let mut writer = TempWriter::open(destination)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    for (name, entry) in entries {
        if token.is_cancelled() {
            return Err(OperationError::Cancelled.report());
        }
        let record = Record {
            name,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime: entry.mtime,
            nlink: entry.nlink.max(1),
            dev_major: entry.dev_major,
            dev_minor: entry.dev_minor,
            ino: entry.ino,
            rdev_major: entry.rdev_major,
            rdev_minor: entry.rdev_minor,
            body: entry.body,
        };
        cpio::write_entry(&mut writer, &record)?;
    }
    cpio::write_trailer(&mut writer)?;
    writer
        .flush()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    let published = writer
        .publish()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    Ok(Some(FileRef {
        uuid: dst_uuid,
        namespace: Namespace::Modules,
        file_digest: published.file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    }))
}

fn read_source_cpio(
    file: File,
    source_path: &Path,
    token: &CancellationToken,
) -> Result<BTreeMap<String, ModuleEntry>, Report<OperationError>> {
    let mut cursor = std::io::BufReader::new(file);
    let mut entries = BTreeMap::new();

    loop {
        if token.is_cancelled() {
            return Err(OperationError::Cancelled.report());
        }
        let reader = cpio_crate::newc::Reader::new(cursor).map_err(|err| {
            OperationError::InvalidCpio
                .report()
                .attach(PathLabel(source_path.to_path_buf()))
                .attach(err)
        })?;
        let mut entry_reader = reader;
        let entry = entry_reader.entry().clone();
        if entry.is_trailer() {
            let mut remaining = finish_cpio_entry(entry_reader, source_path)?;
            let mut extra = [0u8; 1];
            let read = remaining
                .read(&mut extra)
                .map_err(|err| OperationError::InvalidCpio.report().attach(err))?;
            if read != 0 {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(source_path.to_path_buf()))
                    .attach("structural bytes after the CPIO trailer"));
            }
            break;
        }

        let normalized = normalize_path(entry.name())?;
        let mode = entry.mode();
        let size = entry.file_size();
        let is_tar = is_kernel_tar(&normalized);
        let is_module = is_module_path(&normalized);
        if is_tar {
            // The nested `kernel.tar` is parsed from disk: the body is
            // spooled to a temp file instead of materialized, so a real
            // kernel image whose module bundle exceeds the in-memory bound
            // is accepted (AuditPlan B4: cap allocation, never reject valid
            // inputs — contrast the validate_cpio bug class).
            let spool = spool_cpio_body(&mut entry_reader, source_path)?;
            let path = spool.temp_path().to_path_buf();
            let file =
                File::open(&path).map_err(|err| OperationError::ReadSource.report().attach(err))?;
            extract_nested_tar(file, &mut entries)?;
            // `spool` (and its temp file) is removed on drop.
        } else if is_module {
            let body = read_cpio_body(&mut entry_reader, size, source_path)?;
            entries.insert(
                normalized,
                ModuleEntry {
                    mode,
                    uid: entry.uid(),
                    gid: entry.gid(),
                    mtime: entry.mtime(),
                    nlink: entry.nlink(),
                    dev_major: entry.dev_major(),
                    dev_minor: entry.dev_minor(),
                    ino: entry.ino(),
                    rdev_major: entry.rdev_major(),
                    rdev_minor: entry.rdev_minor(),
                    body: body_to_cpio_body(mode, body),
                },
            );
        } else {
            // The body is walked but never retained: stream it through a
            // fixed buffer instead of materializing or rejecting it. A
            // valid kernel image may contain entries far beyond the
            // in-memory bound (the raw kernel blob, firmware) that are not
            // modules.
            discard_cpio_body(&mut entry_reader, size, source_path)?;
        }
        cursor = finish_cpio_entry(entry_reader, source_path)?;
    }

    Ok(entries)
}

fn read_cpio_body<R: Read>(
    reader: &mut cpio_crate::newc::Reader<R>,
    size: u32,
    source_path: &Path,
) -> Result<Vec<u8>, Report<OperationError>> {
    // AuditPlan B4: this bound caps in-memory materialization only — the
    // body is read into a Vec below, so refusing oversized bodies up front
    // bounds host allocation. It is not a structural rejection: this path
    // is only reached for retained module entries, and real kernel modules
    // are far below 64 MiB. (Contrast the validate_cpio bug class, where
    // pure validation must stream the body instead of rejecting it.)
    if u64::from(size) > u64::from(MAX_IN_MEMORY_ENTRY_BYTES) {
        return Err(OperationError::InvalidCpio
            .report()
            .attach(PathLabel(source_path.into()))
            .attach(format!(
                "CPIO entry body of {size} bytes exceeds the in-memory bound of \
                 {} bytes",
                MAX_IN_MEMORY_ENTRY_BYTES
            )));
    }
    let mut body = Vec::with_capacity(size as usize);
    reader.read_to_end(&mut body).map_err(|err| {
        OperationError::InvalidCpio
            .report()
            .attach(PathLabel(source_path.into()))
            .attach(err)
    })?;
    if body.len() != size as usize {
        return Err(OperationError::InvalidCpio
            .report()
            .attach(PathLabel(source_path.into()))
            .attach("CPIO entry body ended before its declared size"));
    }
    Ok(body)
}

/// Stream an entry body the walk does not retain: bounded memory, no size
/// rejection (a valid kernel image may contain large non-module entries),
/// truncation still fails.
fn discard_cpio_body<R: Read>(
    reader: &mut cpio_crate::newc::Reader<R>,
    size: u32,
    source_path: &Path,
) -> Result<(), Report<OperationError>> {
    let mut buffer = [0u8; 64 * 1024];
    let mut consumed: u64 = 0;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| OperationError::InvalidCpio.report().attach(err))?;
        if read == 0 {
            break;
        }
        consumed += read as u64;
    }
    if consumed < u64::from(size) {
        return Err(OperationError::InvalidCpio
            .report()
            .attach(PathLabel(source_path.into()))
            .attach(format!(
                "CPIO entry body ended before its declared size: read {consumed} of {size} bytes"
            )));
    }
    Ok(())
}

/// Spool an entry body to a temp file adjacent to `source_path`. The
/// returned [`io::StagedFile`] removes the temp on drop. Used for the
/// nested `kernel.tar` so a large module bundle never allocates
/// proportionally in memory.
fn spool_cpio_body<R: Read>(
    reader: &mut cpio_crate::newc::Reader<R>,
    source_path: &Path,
) -> Result<io::StagedFile, Report<OperationError>> {
    let mut writer = io::TempWriter::open(source_path)
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| OperationError::InvalidCpio.report().attach(err))?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_err(|err| {
            OperationError::WriteDestination
                .report()
                .attach(PathLabel(source_path.to_path_buf()))
                .attach(err)
        })?;
    }
    writer
        .stage()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))
}

fn finish_cpio_entry<R: Read>(
    reader: cpio_crate::newc::Reader<R>,
    source_path: &Path,
) -> Result<R, Report<OperationError>> {
    reader.finish().map_err(|err| {
        OperationError::InvalidCpio
            .report()
            .attach(PathLabel(source_path.to_path_buf()))
            .attach(err)
    })
}

fn extract_nested_tar<R: Read>(
    source: R,
    entries: &mut BTreeMap<String, ModuleEntry>,
) -> Result<(), Report<OperationError>> {
    let mut archive = tar::Archive::new(source);
    let tar_entries = archive
        .entries()
        .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
    for entry in tar_entries {
        let mut entry = entry.map_err(|err| OperationError::InvalidTar.report().attach(err))?;
        let _ = entry.pax_extensions();
        let raw_path = entry.path_bytes().into_owned();
        let raw_path = std::str::from_utf8(&raw_path)
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
        let path = normalize_path(raw_path)?;
        let mode = entry
            .header()
            .mode()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;
        let uid = entry
            .header()
            .uid()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?
            .try_into()
            .map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach("tar uid exceeds newc u32")
            })?;
        let gid = entry
            .header()
            .gid()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?
            .try_into()
            .map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach("tar gid exceeds newc u32")
            })?;
        let mtime = entry
            .header()
            .mtime()
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?
            .try_into()
            .map_err(|_| {
                OperationError::InvalidCpio
                    .report()
                    .attach("tar mtime exceeds newc u32")
            })?;
        let file_type = entry.header().entry_type();
        let (dev_major, dev_minor) =
            if matches!(file_type, tar::EntryType::Char | tar::EntryType::Block) {
                (
                    entry
                        .header()
                        .device_major()
                        .map_err(|err| OperationError::InvalidTar.report().attach(err))?
                        .unwrap_or(0),
                    entry
                        .header()
                        .device_minor()
                        .map_err(|err| OperationError::InvalidTar.report().attach(err))?
                        .unwrap_or(0),
                )
            } else {
                (0, 0)
            };
        // AuditPlan B4: the nested `kernel.tar` bodies are materialized in
        // memory (they feed `extract_nested_tar`), so bound the per-entry
        // size to keep host allocation bounded. This is a deliberate
        // in-memory cap, not a structural rejection: real nested kernel.tar
        // entries are far below the 64 MiB limit.
        if entry.size() > u64::from(MAX_IN_MEMORY_ENTRY_BYTES) {
            return Err(OperationError::InvalidCpio.report().attach(format!(
                "kernel.tar entry {path} of {} bytes exceeds the in-memory bound of {} bytes",
                entry.size(),
                MAX_IN_MEMORY_ENTRY_BYTES
            )));
        }
        let mut body = Vec::new();
        entry
            .read_to_end(&mut body)
            .map_err(|err| OperationError::InvalidTar.report().attach(err))?;

        if !is_module_path(&path) {
            continue;
        }
        let file_type_bits = match file_type {
            tar::EntryType::Directory => S_IFDIR,
            tar::EntryType::Symlink => S_IFLNK,
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::Link => S_IFREG,
            tar::EntryType::Char => 0o020000,
            tar::EntryType::Block => 0o060000,
            tar::EntryType::Fifo => 0o010000,
            other => {
                return Err(OperationError::UnsupportedArtifact.report().attach(format!(
                    "unsupported nested kernel TAR entry type {other:?}"
                )));
            }
        };
        let body = if file_type == tar::EntryType::Symlink {
            Body::Owned(
                entry
                    .link_name_bytes()
                    .map(|value| value.into_owned())
                    .ok_or_else(|| {
                        OperationError::InvalidTar
                            .report()
                            .attach(format!("symlink {path} has no target"))
                    })?,
            )
        } else if file_type == tar::EntryType::Directory
            || matches!(
                file_type,
                tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo
            )
        {
            Body::Empty
        } else {
            Body::Owned(body)
        };

        entries.insert(
            path,
            ModuleEntry {
                mode: (mode & 0o7777) | file_type_bits,
                uid,
                gid,
                mtime,
                nlink: 1,
                dev_major,
                dev_minor,
                ino: 0,
                rdev_major: dev_major,
                rdev_minor: dev_minor,
                body,
            },
        );
    }
    Ok(())
}

fn body_to_cpio_body(mode: u32, body: Vec<u8>) -> Body {
    match mode & S_IFMT {
        S_IFDIR => Body::Empty,
        S_IFLNK | S_IFREG => Body::Owned(body),
        _ => Body::Empty,
    }
}

fn is_module_path(path: &str) -> bool {
    path == "lib/modules" || path.starts_with("lib/modules/")
}

fn is_kernel_tar(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("kernel.tar"))
}

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
