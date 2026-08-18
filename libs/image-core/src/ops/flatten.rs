//! `ops::flatten` overlays a sequence of OCI CPIO `newc` layers and emits a
//! single deterministic rootfs CPIO `newc` archive.
//!
//! The implementation maintains an in-memory ordered map of surviving
//! entries keyed by normalized path. Regular-file bodies are spooled to a
//! per-operation temp file so resident memory stays bounded by the metadata
//! table; the map only stores byte ranges into that spool. OCI whiteouts
//! (`.wh.<name>` and opaque `.wh..wh..opq`) are applied between layers, so a
//! whiteout never removes an entry the same layer creates. Cross-layer
//! hard-link groups are unlinked before substitutions are applied and the
//! surviving groups are rebuilt so the published archive carries a single
//! copy of each shared body and a coherent `nlink` count.
//!
//! See `docs/implementation-plan/ops/05-flatten.md` for the full contract.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use crate::artifact::compression::ArtifactCompression;
use crate::artifact::ty::ArtifactType;
use crate::ops::bounded_join;
use crate::ops::cpio::{self, Body, Record, normalize_path};

// The `cpio` external crate is referred to as `::cpio` to avoid a clash
// with the local `crate::ops::cpio` module that exposes our own writer
// helpers. The local `cpio` symbol bound above refers to that module; we
// keep the external crate qualified through the top-level alias.
use crate::ops::error::OperationError;
use crate::ops::io::{self, TempWriter};
use crate::storage::file_ref::FileRef;
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::Namespace;
use ::cpio as cpio_crate;

// ---------------------------------------------------------------------------
// Intermediate representation
// ---------------------------------------------------------------------------

/// File-type bits carried inside the CPIO `mode` field. We use these when
/// emitting records so we can route a body to the right encoder helper
/// without parsing the mode word again.
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const MAX_SYMLINK_RESOLUTION_DEPTH: usize = 40;

/// A range of bytes inside the operation spool file. Regular-file bodies are
/// stored once on disk; everything else lives in [`Metadata`].
#[derive(Debug, Clone, Copy)]
struct SpoolRange {
    offset: u64,
    size: u32,
}

/// Metadata for a survivor entry in the ordered map. The in-memory map is
/// bounded by the metadata table; only regular-file bodies live in the
/// spool, addressed by `body`.
#[derive(Debug, Clone)]
struct Metadata {
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    dev_major: u32,
    ino: u32,
    rdev_major: u32,
    rdev_minor: u32,
    /// `nlink` as declared by the source layer. Recalculated just before
    /// emission from the surviving names of the same hard-link group.
    nlink_source: u32,
    /// Index of the source layer this entry originated from. Survivors from
    /// different layers are never merged into a hard-link group even when
    /// the inherited `(dev_major, ino)` happens to collide: a hard-link
    /// group lives inside a single layer per the OCI layer model.
    source_layer: usize,
    /// Symlink target stored in memory (always short by construction) or
    /// the spool range of a regular file's body. Empty entries (dirs,
    /// devices, FIFOs, hard-link duplicates) use `Body::Spool(None)`.
    body: EntryBody,
}

/// Where the entry's body lives.
#[derive(Debug, Clone)]
enum EntryBody {
    /// No payload (directories, devices, FIFOs, hard-link duplicates that
    /// carry size zero).
    Empty,
    /// Symlink target bytes materialized in memory.
    Symlink(Vec<u8>),
    /// Regular-file body stored once in the spool.
    Spool(Option<SpoolRange>),
}

impl Metadata {
    fn is_directory(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    fn is_regular(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }

    /// Identity of the hard-link group this entry belongs to within its
    /// source layer. We include `source_layer` so two entries from
    /// different layers never accidentally form a group even when their
    /// `(dev_major, ino)` collide: a hard-link group always lives inside a
    /// single per-OCI-layer CPIO.
    fn link_key(&self) -> (usize, u32, u32) {
        (self.source_layer, self.dev_major, self.ino)
    }
}

/// A pending whiteout directive decoded from a `.wh.*` path.
enum Whiteout {
    /// Remove the named entry (and its subtree) from the accumulated state.
    Named { parent: String, name: String },
    /// Remove every entry living below `parent` from the accumulated
    /// state. Entries equal to `parent` survive.
    Opaque { parent: String },
}

/// A decoded entry from a source layer, ready to either insert into the map
/// or discard as a whiteout marker.
enum LayerEntry {
    Regular { path: String, metadata: Metadata },
    Whiteout(Whiteout),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Overlay a sequence of uncompressed CPIO `newc` layers into a single
/// deterministic rootfs CPIO written to `dst`.
///
/// See `docs/implementation-plan/ops/05-flatten.md` for the full contract.
pub async fn flatten(
    src: &[FileRef],
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    // Preconditions checked up front so a bad caller fails fast.
    if dst.namespace != Namespace::Rootfs {
        return Err(OperationError::UnsupportedArtifact
            .report()
            .attach("flatten requires Namespace::Rootfs for the destination"));
    }
    for layer in src {
        if layer.artifact_type != ArtifactType::ContainerCpio {
            return Err(OperationError::UnsupportedArtifact.report().attach(format!(
                "expected ArtifactType::ContainerCpio, got {:?}",
                layer.artifact_type
            )));
        }
        if layer.artifact_compression != ArtifactCompression::None {
            return Err(OperationError::UnsupportedCompression
                .report()
                .attach(format!(
                    "expected ArtifactCompression::None, got {:?}",
                    layer.artifact_compression
                )));
        }
    }

    let owned_src: Vec<FileRef> = src.to_vec();
    let destination: PathBuf = dst.namespace.join(dst.uuid.to_string());
    let dst_uuid = dst.uuid;
    let dst_namespace = dst.namespace;

    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                run_blocking(&owned_src, &destination, dst_uuid, dst_namespace, &token)
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

// ---------------------------------------------------------------------------
// Blocking driver
// ---------------------------------------------------------------------------

fn run_blocking(
    src: &[FileRef],
    destination: &std::path::Path,
    dst_uuid: uuid::Uuid,
    dst_namespace: Namespace,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    // Spool temp file is unique per operation, so concurrent flatten calls
    // cannot truncate or mix one another's bodies.
    let mut spool = Spool::open(destination)?;

    let res = build_state(src, &mut spool, token);
    let state = match res {
        Ok(state) => state,
        Err(err) => {
            // Spool drop removes the temp file.
            drop(spool);
            return Err(err);
        }
    };

    let published = emit(&state, destination, &spool)?;
    Ok(FileRef {
        uuid: dst_uuid,
        namespace: dst_namespace,
        file_digest: published.file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    })
}

// ---------------------------------------------------------------------------
// Spool file
// ---------------------------------------------------------------------------

/// Append-only temp file that stores regular-file bodies during the build.
/// Re-reading a body seeks the file handle back to `range.offset`.
struct Spool {
    file: File,
    path: PathBuf,
    cursor: u64,
}

impl Spool {
    fn open(destination: &std::path::Path) -> Result<Self, Report<OperationError>> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent).map_err(|err| {
            OperationError::WriteDestination
                .report()
                .attach(PathLabel(destination.to_path_buf()))
                .attach(err)
        })?;
        let stem = destination
            .file_stem()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "rootfs".to_string());
        let path = parent.join(format!(".{stem}.flatten-spool-{}", uuid::Uuid::now_v7()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|err| {
                OperationError::WriteDestination
                    .report()
                    .attach(PathLabel(path.to_path_buf()))
                    .attach(err)
            })?;
        Ok(Self {
            file,
            path,
            cursor: 0,
        })
    }

    /// Append `reader`'s `size` bytes to the spool, returning the byte
    /// range that owns the body. We do not pad between bodies: each range
    /// is exactly `size` and the emit pass seeks to each offset directly.
    fn append_body<R: Read + ?Sized>(
        &mut self,
        reader: &mut R,
        size: u32,
    ) -> Result<SpoolRange, Report<OperationError>> {
        let offset = self.cursor;
        let mut remaining = size as u64;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let want = (buffer.len() as u64).min(remaining) as usize;
            let read = reader
                .read(&mut buffer[..want])
                .map_err(|err| OperationError::ReadSource.report().attach(err))?;
            if read == 0 {
                return Err(OperationError::InvalidCpio.report().attach(format!(
                    "layer body ended early: {remaining} bytes remaining"
                )));
            }
            self.file
                .write_all(&buffer[..read])
                .map_err(|err| OperationError::WriteDestination.report().attach(err))?;
            self.cursor += read as u64;
            remaining -= read as u64;
        }
        let _ = self.file.flush();
        Ok(SpoolRange { offset, size })
    }

    /// Open a fresh read handle over the spool file. The emit pass opens
    /// one handle per regular-file group, but reusing a single seekable
    /// handle would also work.
    fn open_reader(&self) -> Result<File, Report<OperationError>> {
        let file = std::fs::File::open(&self.path)
            .map_err(|err| OperationError::ReadSource.report().attach(err))?;
        Ok(file)
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// State assembly
// ---------------------------------------------------------------------------

/// Ordered map of survivor entries keyed by normalized path. A `BTreeMap`
/// gives us directory-before-descendant ordering for free; ties above that
/// are broken by the path's natural lexicographic order.
struct State {
    entries: BTreeMap<String, Metadata>,
}

/// Decode every layer in order, applying whiteouts and substitutions to the
/// accumulated state. Checks the cancellation token per layer entry so a
/// cancelled flatten bails between entries instead of running to completion.
fn build_state(
    src: &[FileRef],
    spool: &mut Spool,
    token: &CancellationToken,
) -> Result<State, Report<OperationError>> {
    let mut entries: BTreeMap<String, Metadata> = BTreeMap::new();

    for (layer_index, layer) in src.iter().enumerate() {
        let layer_entries = read_layer(layer, spool, layer_index, token)?;

        // Two phases per layer: first apply whiteouts against the *current*
        // state (the lower layers), then insert the layer's regular entries.
        // A whiteout never removes an entry the same layer creates because
        // the creations are not yet in the map.
        let mut regulars: Vec<(String, Metadata)> = Vec::new();
        for decoded in layer_entries {
            match decoded {
                LayerEntry::Whiteout(wh) => apply_whiteout(&mut entries, &wh),
                LayerEntry::Regular { path, metadata } => regulars.push((path, metadata)),
            }
        }
        for (path, metadata) in regulars {
            let path = resolve_symlink_ancestors(&path, &entries);
            insert_and_replace(&mut entries, path, metadata);
        }
    }

    Ok(State { entries })
}

/// Walk one layer's CPIO, copying regular bodies into `spool` and returning
/// the decoded entries in their original archive order. The order matters
/// for forward hard-link resolution within the same layer.
fn read_layer(
    layer: &FileRef,
    spool: &mut Spool,
    source_layer: usize,
    token: &CancellationToken,
) -> Result<Vec<LayerEntry>, Report<OperationError>> {
    let path = layer.path();
    let mut source = File::open(&path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(PathLabel(path.clone()))
            .attach(err)
    })?;
    let actual = io::compute_file_digest_from_file(&mut source, &path)
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    if actual != layer.file_digest {
        return Err(OperationError::DigestMismatch
            .report()
            .attach(PathLabel(path.clone()))
            .attach(DigestPair {
                expected: layer.file_digest,
                actual,
            }));
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|err| OperationError::ReadSource.report().attach(err))?;
    let mut cursor = BufReader::new(source);
    let mut decoded: Vec<LayerEntry> = Vec::new();

    loop {
        if token.is_cancelled() {
            return Err(OperationError::Cancelled.report());
        }
        let reader = match cpio_crate::newc::Reader::new(cursor) {
            Ok(reader) => reader,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(format!("layer {} ended mid-header", path.display())));
            }
            Err(err) => {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(path.clone()))
                    .attach(err));
            }
        };
        let entry = reader.entry().clone();
        if entry.is_trailer() {
            // Drain the trailer and reject any bytes after the sole trailer.
            let mut remaining = reader.finish().map_err(|err| {
                OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(path.clone()))
                    .attach(err)
            })?;
            let mut extra = [0u8; 1];
            let read = remaining
                .read(&mut extra)
                .map_err(|err| OperationError::InvalidCpio.report().attach(err))?;
            if read != 0 {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(path.clone()))
                    .attach("structural bytes after the CPIO trailer"));
            }
            break;
        }

        let raw_name = entry.name();
        let normalized = normalize_path(raw_name)?;

        // Decode OCI whiteout markers. A marker lives at
        // `<parent>/.wh.<name>` and deletes `<parent>/<name>` (and its
        // subtree) from the lower-layer state. The opaque marker is
        // `<parent>/.wh..wh..opq` and removes every entry strictly below
        // `<parent>`. We split on the basename so a marker at any depth is
        // recognised, not just a top-level one.
        let basename = normalized.rsplit('/').next().unwrap_or(&normalized);
        if let Some(rest) = basename.strip_prefix(".wh.") {
            if rest == ".wh..opq" {
                let parent = parent_dir_of(&normalized);
                decoded.push(LayerEntry::Whiteout(Whiteout::Opaque { parent }));
            } else {
                let parent = parent_dir_of(&normalized);
                decoded.push(LayerEntry::Whiteout(Whiteout::Named {
                    parent,
                    name: rest.to_string(),
                }));
            }
            // Whiteout markers still own a body in the CPIO (empty by
            // convention). Drain it before continuing.
            cursor = reader.finish().map_err(|err| {
                OperationError::InvalidCpio
                    .report()
                    .attach(PathLabel(path.clone()))
                    .attach(err)
            })?;
            continue;
        }

        let (metadata, advanced) =
            decode_entry_metadata(&entry, reader, spool, &path, source_layer)?;
        cursor = advanced;
        decoded.push(LayerEntry::Regular {
            path: normalized,
            metadata,
        });
    }

    Ok(decoded)
}

/// Parent directory prefix of `path`, with no trailing slash. Returns the
/// empty string for a top-level entry.
fn parent_dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[..idx].to_string(),
        None => String::new(),
    }
}

/// Resolve symlink ancestors against the filesystem state accumulated from
/// lower layers and earlier entries in the current layer.
///
/// A CPIO layer records names as if they were extracted into the root. If a
/// lower layer contains `lib -> usr/lib`, an upper-layer entry named
/// `lib/modules/foo.ko` is therefore really created at
/// `usr/lib/modules/foo.ko`. Keeping the un-resolved name in the flattened
/// archive would cause extraction to try to create a child below a symlink
/// and lose the entry on usr-merged distributions.
fn resolve_symlink_ancestors(path: &str, entries: &BTreeMap<String, Metadata>) -> String {
    let mut resolved = path.to_string();

    for _ in 0..MAX_SYMLINK_RESOLUTION_DEPTH {
        let components: Vec<&str> = resolved.split('/').collect();
        let mut replacement = None;
        let mut prefix = String::new();

        // Only ancestors are resolved. An entry at `path` itself must still
        // replace an existing symlink at that exact path.
        for (index, component) in components.iter().enumerate().take(components.len() - 1) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);

            let Some(metadata) = entries.get(&prefix) else {
                continue;
            };
            let EntryBody::Symlink(target) = &metadata.body else {
                continue;
            };
            let Ok(target) = std::str::from_utf8(target) else {
                // A non-UTF-8 symlink cannot be represented in the CPIO
                // path model without changing its meaning. Leave the path
                // untouched and let the normal archive extraction behavior
                // apply.
                continue;
            };

            let remainder = components[index + 1..].join("/");
            let Some(next) = join_symlink_target(&prefix, target, &remainder) else {
                return resolved;
            };
            replacement = Some(next);
            break;
        }

        let Some(next) = replacement else {
            return resolved;
        };
        resolved = next;
    }

    // A symlink cycle is malformed filesystem state. Keep the last safe
    // spelling rather than looping forever or inventing a host-side path.
    resolved
}

/// Join a symlink target and the path below that symlink, applying the
/// kernel's root-relative lexical handling for `.`, `..`, and repeated `/`.
fn join_symlink_target(symlink_path: &str, target: &str, remainder: &str) -> Option<String> {
    if target.is_empty() {
        return None;
    }

    let mut components = Vec::new();
    if !target.starts_with('/')
        && let Some(parent) = symlink_path.rsplit_once('/').map(|(parent, _)| parent)
    {
        components.extend(parent.split('/'));
    }
    components.extend(target.split('/'));
    components.extend(remainder.split('/'));

    let mut normalized = Vec::new();
    for component in components {
        match component {
            "" | "." => {}
            ".." => {
                normalized.pop();
            }
            component => normalized.push(component),
        }
    }

    Some(normalized.join("/"))
}

/// Decode a regular (non-whiteout, non-trailer) entry's metadata, spooling
/// regular-file bodies into `spool`. Returns the metadata and the cursor
/// advanced past the entry body and padding.
fn decode_entry_metadata<R: Read>(
    entry: &cpio_crate::newc::Entry,
    reader: cpio_crate::newc::Reader<R>,
    spool: &mut Spool,
    layer_path: &std::path::Path,
    source_layer: usize,
) -> Result<(Metadata, R), Report<OperationError>> {
    let mode = entry.mode();
    let uid = entry.uid();
    let gid = entry.gid();
    let mtime = entry.mtime();
    let nlink_source = entry.nlink();
    let dev_major = entry.dev_major();
    let ino = entry.ino();
    let rdev_major = entry.rdev_major();
    let rdev_minor = entry.rdev_minor();

    let file_type = mode & S_IFMT;
    let (body, cursor) = if file_type == S_IFREG {
        let size = entry.file_size();
        // The `Reader::Read` impl limits reads to the remaining body
        // bytes, so reading exactly `size` bytes advances through the
        // body and `finish()` then drains the trailing body padding.
        let mut reader = reader;
        let range = spool.append_body(&mut reader, size)?;
        let cursor = finish_reader(reader, layer_path)?;
        (EntryBody::Spool(Some(range)), cursor)
    } else if file_type == S_IFLNK {
        let size = entry.file_size();
        // Symlink targets are short by construction (Linux caps them at
        // PATH_MAX, 4096 bytes — far below the bound); a target at or above
        // the in-memory bound is corrupt or malicious, never a real link.
        if u64::from(size) > u64::from(crate::ops::MAX_IN_MEMORY_ENTRY_BYTES) {
            return Err(OperationError::InvalidCpio
                .report()
                .attach(PathLabel(layer_path.to_path_buf()))
                .attach(format!(
                    "symlink body of {size} bytes exceeds the in-memory bound of {} bytes",
                    crate::ops::MAX_IN_MEMORY_ENTRY_BYTES
                )));
        }
        // Symlink targets are short; materialize into memory.
        let mut buf = vec![0u8; size as usize];
        let mut reader = reader;
        reader
            .read_exact(&mut buf)
            .map_err(|err| OperationError::InvalidCpio.report().attach(err))?;
        let cursor = finish_reader(reader, layer_path)?;
        (EntryBody::Symlink(buf), cursor)
    } else {
        // Dirs, devices, FIFOs: no body to copy. Skip the declared size and
        // any padding so the reader advances to the next entry.
        let cursor = finish_reader(reader, layer_path)?;
        (EntryBody::Empty, cursor)
    };

    Ok((
        Metadata {
            mode,
            uid,
            gid,
            mtime,
            dev_major,
            ino,
            rdev_major,
            rdev_minor,
            nlink_source,
            source_layer,
            body,
        },
        cursor,
    ))
}

/// Drain the remainder of a reader's body (if any) plus padding and return
/// the cursor advanced past the entry.
fn finish_reader<R: Read>(
    reader: cpio_crate::newc::Reader<R>,
    layer_path: &std::path::Path,
) -> Result<R, Report<OperationError>> {
    reader.finish().map_err(|err| {
        OperationError::InvalidCpio
            .report()
            .attach(err)
            .attach(PathLabel(layer_path.to_path_buf()))
    })
}

// ---------------------------------------------------------------------------
// Whiteout application
// ---------------------------------------------------------------------------

/// Remove entries from `map` according to `wh`.
fn apply_whiteout(map: &mut BTreeMap<String, Metadata>, wh: &Whiteout) {
    match wh {
        Whiteout::Named { parent, name } => {
            let target = if parent.is_empty() {
                name.to_string()
            } else {
                format!("{parent}/{name}")
            };
            remove_subtree(map, &target);
        }
        Whiteout::Opaque { parent } => {
            // Remove every entry that lives strictly below `parent`. The
            // parent directory entry itself survives.
            let prefix = if parent.is_empty() {
                String::new()
            } else {
                format!("{parent}/")
            };
            let victims: Vec<String> = map
                .keys()
                .filter(|key| prefix.is_empty() || key.starts_with(&prefix))
                .cloned()
                .collect();
            for victim in victims {
                map.remove(&victim);
            }
        }
    }
}

/// Remove `target` and every entry living below it from `map`.
fn remove_subtree(map: &mut BTreeMap<String, Metadata>, target: &str) {
    let prefix = format!("{target}/");
    let victims: Vec<String> = map
        .keys()
        .filter(|key| key.as_str() == target || key.starts_with(&prefix))
        .cloned()
        .collect();
    for victim in victims {
        map.remove(&victim);
    }
}

// ---------------------------------------------------------------------------
// Substitution
// ---------------------------------------------------------------------------

/// Insert `metadata` at `path`, applying the type-vs-type substitution
/// rules required by the plan:
///
/// - A directory replacing a non-directory removes all descendants of the
///   old path.
/// - A non-directory replacing a directory removes the whole old subtree
///   (the directory and its descendants).
/// - Same-type or file-vs-file replacements simply overwrite the entry.
fn insert_and_replace(map: &mut BTreeMap<String, Metadata>, path: String, metadata: Metadata) {
    if let Some(existing) = map.get(&path) {
        let was_dir = existing.is_directory();
        let is_dir = metadata.is_directory();
        if was_dir && !is_dir {
            // The old directory's subtree must be removed because the new
            // entry is not a directory and can no longer own descendants.
            remove_descendants(map, &path);
        } else if is_dir && !was_dir {
            // Replacing a non-directory with a directory must remove the
            // old file. The descendants logic is a no-op since nothing was
            // under the old file.
            let _ = map.remove(&path);
        }
    }
    // Unlink cross-layer hard-link groups before substitution. We do this
    // implicitly: each layer's `dev_major`/`ino` is scoped to its own
    // artifacts and the emit pass reassigns identities globally.
    map.insert(path, metadata);
}

/// Remove entries that live strictly below `path`. `path` itself survives.
fn remove_descendants(map: &mut BTreeMap<String, Metadata>, path: &str) {
    let prefix = format!("{path}/");
    let victims: Vec<String> = map
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .cloned()
        .collect();
    for victim in victims {
        map.remove(&victim);
    }
}

// ---------------------------------------------------------------------------
// Deterministic emission
// ---------------------------------------------------------------------------

/// Build the canonical emission plan from `state` and write it to
/// `destination`.
fn emit(
    state: &State,
    destination: &std::path::Path,
    spool: &Spool,
) -> Result<crate::ops::io::PublishedFile, Report<OperationError>> {
    let mut writer = TempWriter::open(destination).map_err(|err| {
        OperationError::WriteDestination
            .report()
            .attach(PathLabel(destination.to_path_buf()))
            .attach(err)
    })?;

    // Deterministic identity assignment for surviving hard-link groups.
    // Surviving entries that shared the same source-layer (dev, ino) form a
    // group; the lexicographically smallest member is the canonical body
    // carrier, and every other member emits a size-zero record that points
    // at the same canonical (dev, ino). `nlink` is recalculated from the
    // surviving names of each group.
    let plan = plan_hardlinks(state);

    // Open a single read handle over this operation's unique spool. The
    // handle/path are owned by the same `Spool` structure, so no other
    // flatten invocation can truncate the source under us.
    let mut spool_reader: Option<File> = None;

    // Iterate in BTreeMap order so parents precede descendants and ties
    // between siblings are broken lexicographically. That gives the
    // "directory before descendants" guarantee on the wire.
    for (path, metadata) in &state.entries {
        let (assignment, is_canonical_body) = plan.assignment_for(path);
        let nlink = plan.nlink_for(path);

        match &metadata.body {
            EntryBody::Empty => {
                let record = build_record(path, metadata, assignment, nlink, Body::Empty);
                cpio::write_entry(&mut writer, &record)?;
            }
            EntryBody::Symlink(bytes) => {
                if bytes.len() > u32::MAX as usize {
                    return Err(OperationError::InvalidCpio
                        .report()
                        .attach(format!("symlink {path} target exceeds u32")));
                }
                let record = build_record(path, metadata, assignment, nlink, Body::Empty);
                let mut cursor = std::io::Cursor::new(bytes.clone());
                cpio::write_streaming_entry(&mut writer, &record, bytes.len() as u32, &mut cursor)?;
            }
            EntryBody::Spool(Some(range)) if is_canonical_body => {
                // Open the spool read handle lazily so an empty output
                // never touches the spool file.
                let reader = match spool_reader.as_mut() {
                    Some(reader) => reader,
                    None => {
                        let file = spool.open_reader()?;
                        // Safe because we never reach here in a concurrency
                        // hazard with Spool's `Drop` removal.
                        spool_reader.insert(file)
                    }
                };
                use std::io::Seek;
                reader
                    .seek(std::io::SeekFrom::Start(range.offset))
                    .map_err(|err| OperationError::ReadSource.report().attach(err))?;
                let mut take = reader.take(range.size as u64);
                let record = build_record(path, metadata, assignment, nlink, Body::Empty);
                cpio::write_streaming_entry(&mut writer, &record, range.size, &mut take)?;
            }
            EntryBody::Spool(Some(_)) => {
                // Non-canonical member of a hard-link group: emit a
                // size-zero record that shares the canonical (dev, ino).
                let record = build_record(path, metadata, assignment, nlink, Body::Empty);
                cpio::write_entry(&mut writer, &record)?;
            }
            EntryBody::Spool(None) => {
                // An empty regular file carries no body.
                let record = build_record(path, metadata, assignment, nlink, Body::Empty);
                cpio::write_entry(&mut writer, &record)?;
            }
        }
    }

    cpio::write_trailer(&mut writer)?;
    writer
        .flush()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    let published = writer
        .publish()
        .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

    Ok(published)
}

/// Build a `Record` for emission. The wire-level `file_size` field is set
/// via the writer helpers' explicit `size` argument; the `Record.body`
/// here is always `Body::Empty` because we either stream the body through
/// `write_streaming_entry` or emit a size-zero entry.
fn build_record(
    path: &str,
    metadata: &Metadata,
    assignment: (u32, u32),
    nlink: u32,
    body: Body,
) -> Record {
    let (dev_major, ino) = assignment;
    Record {
        name: path.to_string(),
        mode: metadata.mode,
        uid: metadata.uid,
        gid: metadata.gid,
        mtime: metadata.mtime,
        nlink,
        dev_major,
        dev_minor: 0,
        ino,
        rdev_major: metadata.rdev_major,
        rdev_minor: metadata.rdev_minor,
        body,
    }
}

// ---------------------------------------------------------------------------
// Hard-link planning
// ---------------------------------------------------------------------------

/// The identity assigned to a surviving hard-link group during emission.
type Assignment = (u32, u32);

/// Plan that resolves hard-link groups for the emit pass.
struct HardlinkPlan {
    /// Maps a path to its assigned (dev_major, ino) identity.
    identity: BTreeMap<String, Assignment>,
    /// Tracks each group's surviving member count so `nlink` can be
    /// recalculated from the surviving names alone.
    nlink: BTreeMap<Assignment, u32>,
    /// The canonical path of each group. The member carrying the largest
    /// surviving body is preferred; ties use the lexicographically smallest
    /// path. Only the canonical member writes the body.
    canonical: BTreeMap<Assignment, String>,
}

impl HardlinkPlan {
    fn assignment_for(&self, path: &str) -> (Assignment, bool) {
        let assignment = *self.identity.get(path).expect("planned identity");
        let canonical = self
            .canonical
            .get(&assignment)
            .map(|s| s.as_str())
            .unwrap_or(path);
        let is_canonical = canonical == path;
        (assignment, is_canonical)
    }

    fn nlink_for(&self, path: &str) -> u32 {
        let assignment = *self.identity.get(path).expect("planned identity");
        *self.nlink.get(&assignment).unwrap_or(&1)
    }
}

/// Build a hard-link plan from the surviving entries. Groups are formed by
/// surviving entries that share the same source-layer `(dev_major, ino)` pair,
/// are regular files, and were declared as a hard-link group. A group with a
/// single surviving member is treated as a standalone inode; cross-layer
/// identities are always kept separate.
///
/// The plan also handles the case where `into_cpio` assigned a hard-link
/// group a single member (nlink==2 at the source) but only one name
/// survives the flatten: in that case `nlink` collapses to 1.
fn plan_hardlinks(state: &State) -> HardlinkPlan {
    // Bucket surviving entries by their inherited `(source_layer, dev_major,
    // ino)` triple. Only regular files explicitly declared with nlink>1 form
    // hard-link groups; ordinary regular files often carry placeholder zero
    // identities and must never be merged merely because those placeholders
    // collide. The `source_layer` component guarantees the "unlink hard-link
    // groups between layers" invariant: identities never cross layer
    // boundaries.
    let mut groups: BTreeMap<(usize, u32, u32), Vec<String>> = BTreeMap::new();
    for (path, metadata) in &state.entries {
        if !metadata.is_regular() || metadata.nlink_source <= 1 {
            continue;
        }
        groups
            .entry(metadata.link_key())
            .or_default()
            .push(path.clone());
    }

    let mut identity: BTreeMap<String, Assignment> = BTreeMap::new();
    let mut nlink: BTreeMap<Assignment, u32> = BTreeMap::new();
    let mut canonical: BTreeMap<Assignment, String> = BTreeMap::new();
    let mut next_dev: u32 = 1;
    let mut next_ino: u32 = 1;

    for (_source_key, mut members) in groups {
        // Sort to make the canonical representative deterministic: the
        // largest stored body is preferred, with the lexicographically
        // smallest path as a deterministic tiebreaker.
        members.sort();

        let group_size = members.len();
        let assignment = {
            let dev = next_dev;
            let ino = next_ino;
            next_dev = next_dev.saturating_add(1);
            next_ino = next_ino.saturating_add(1);
            (dev, ino)
        };

        // Pick the canonical member: the one with the largest stored body
        // (the entry that originally carried the data). The compose order
        // gives deterministic results across two runs because `members` is
        // lexicographically sorted and ties retain the first path.
        let canonical_member = members
            .iter()
            .cloned()
            .reduce(|best, current| {
                let best_size = body_size_of(state.entries.get(&best).expect("planned entry"));
                let current_size =
                    body_size_of(state.entries.get(&current).expect("planned entry"));
                if current_size > best_size {
                    current
                } else {
                    best
                }
            })
            .expect("group has at least one member");

        for member in &members {
            identity.insert(member.clone(), assignment);
        }
        nlink.insert(assignment, group_size as u32);
        canonical.insert(assignment, canonical_member);
    }

    // Entries that did not participate in a source hard-link group (including
    // ordinary regular files with nlink==1) always get their own identity.
    for path in state.entries.keys() {
        if identity.contains_key(path) {
            continue;
        }
        let dev = next_dev;
        let ino = next_ino;
        next_dev = next_dev.saturating_add(1);
        next_ino = next_ino.saturating_add(1);
        identity.insert(path.clone(), (dev, ino));
        nlink.insert((dev, ino), 1);
        // Non-regular entries are their own canonical "member".
        canonical.insert((dev, ino), path.clone());
    }

    HardlinkPlan {
        identity,
        nlink,
        canonical,
    }
}

/// Return the byte size of the entry's body, used to pick the canonical
/// member of a hard-link group.
fn body_size_of(metadata: &Metadata) -> u32 {
    match &metadata.body {
        EntryBody::Empty => 0,
        EntryBody::Symlink(bytes) => bytes.len() as u32,
        EntryBody::Spool(Some(range)) => range.size,
        EntryBody::Spool(None) => 0,
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
