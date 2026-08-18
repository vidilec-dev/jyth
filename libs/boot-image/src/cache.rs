//! Cache for derived overlays and per-run boot artifacts.
//!
//! Source/materialization storage is owned by `image-core`. This module only
//! stores artifacts derived after materialized kernel/rootfs artifacts have
//! crossed the public boundary: the merged overlay rootfs and the published
//! per-run `kernel.bin` / `initrd.img` pair. The versioned root keeps old
//! `.cache/jyth` data untouched.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CACHE_SCHEMA_VERSION: u32 = 2;
const CACHE_VERSION: &str = ".jyth-derived-v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionMetadata {
    pub algorithm: String,
    pub level: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    pub schema_version: u32,
    pub kernel: ArtifactMetadata,
    pub rootfs: ArtifactMetadata,
    pub initrd: ArtifactMetadata,
    pub uncompressed_rootfs_size: u64,
    pub compression: CompressionMetadata,
}

/// The derived-cache root. The env-var contract matches the historical Jyth
/// cache (`JYTH_CACHE_DIR`, falling back to `<manifest>/target/<version>`):
/// existing cold/warm caches stay valid across the boot-image extraction.
pub fn root() -> io::Result<PathBuf> {
    let root = if let Some(value) = std::env::var_os("JYTH_CACHE_DIR") {
        PathBuf::from(value)
    } else if let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        PathBuf::from(manifest_dir)
            .join("target")
            .join(CACHE_VERSION)
    } else {
        std::env::current_dir()?.join(CACHE_VERSION)
    };
    fs::create_dir_all(&root)?;
    Ok(root)
}

pub fn overlay_dir() -> io::Result<PathBuf> {
    let path = root()?.join("overlay");
    fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn runs_dir() -> io::Result<PathBuf> {
    let path = root()?.join("runs");
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Return the BLAKE3 identity and byte length of a file.
pub fn file_identity(path: &Path) -> io::Result<(blake3::Hash, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((hasher.finalize(), size))
}

/// Return the content identity recorded for a derived artifact.
pub fn artifact_metadata(path: &Path) -> io::Result<ArtifactMetadata> {
    let (digest, size) = file_identity(path)?;
    Ok(ArtifactMetadata {
        digest: format!("blake3_{}", digest.to_hex()),
        size,
    })
}

pub fn has_size(path: &Path, expected: u64) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.len() == expected)
        .unwrap_or(false)
}

/// Check both the size and the content digest of a derived artifact.
pub fn artifact_matches(path: &Path, expected: &ArtifactMetadata) -> io::Result<bool> {
    if !has_size(path, expected.size) {
        return Ok(false);
    }
    Ok(artifact_metadata(path)? == *expected)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    atomic_write(path, &bytes)
}

/// Publish bytes by writing a unique sibling and renaming it into place.
///
/// A concurrent builder may win the rename first. Since the destination name
/// is content-derived, an existing destination is accepted after its size
/// and digest have been checked; a stale/corrupt destination is replaced.
/// On any early failure the `.tmp-*` sibling is removed, matching
/// [`atomic_gzip`].
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let expected = blake3::hash(bytes);
    let temp = temp_path(path);
    let result = (|| {
        write_temp(&temp, bytes)?;
        publish_temp(&temp, path, expected, bytes.len() as u64)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Atomically copy a file to a derived cache path without buffering the
/// entire source in memory. On any early failure the `.tmp-*` sibling is
/// removed, matching [`atomic_gzip`].
pub fn atomic_copy(source: &Path, destination: &Path) -> io::Result<()> {
    let temp = temp_path(destination);
    let result = (|| {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let mut hasher = blake3::Hasher::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
            size += read as u64;
        }
        output.flush()?;
        output.sync_all()?;
        drop(output);
        publish_temp(&temp, destination, hasher.finalize(), size)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Stream a source file through gzip into an atomically published artifact.
///
/// The uncompressed source is read in bounded chunks. The compressed bytes are
/// written to a unique sibling, synced, hashed, and published only after the
/// complete stream succeeds. The return value is the uncompressed source size.
pub fn atomic_gzip(source: &Path, destination: &Path, level: u32) -> io::Result<u64> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = temp_path(destination);
    let result = (|| {
        let mut input = File::open(source)?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let mut encoder = GzEncoder::new(output, Compression::new(level));
        let mut source_size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            encoder.write_all(&buffer[..read])?;
            source_size += read as u64;
        }

        let mut output = encoder.finish()?;
        output.flush()?;
        output.sync_all()?;
        drop(output);

        let (digest, compressed_size) = file_identity(&temp)?;
        publish_temp(&temp, destination, digest, compressed_size)?;
        Ok(source_size)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Default initrd compression for derived runs: gzip at flate2's default
/// level (the historical Jyth run-cache behavior).
pub fn initrd_compression_metadata() -> CompressionMetadata {
    CompressionMetadata {
        algorithm: "gzip".to_string(),
        level: Compression::default().level(),
    }
}

/// Identity of one derived run directory: a content-derived key over the
/// kernel, rootfs, and compression inputs.
pub fn run_cache_id(
    kernel: &ArtifactMetadata,
    rootfs: &ArtifactMetadata,
    compression: &CompressionMetadata,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"jyth-derived-run-v2\0");
    for artifact in [kernel, rootfs] {
        hasher.update(artifact.digest.as_bytes());
        hasher.update(&artifact.size.to_le_bytes());
    }
    hasher.update(compression.algorithm.as_bytes());
    hasher.update(&compression.level.to_le_bytes());
    format!("run-{}", hasher.finalize().to_hex())
}

fn run_metadata_path(run_dir: &Path) -> PathBuf {
    run_dir.join("metadata.json")
}

/// Return the cached uncompressed rootfs size only when the metadata record
/// and every recorded artifact agree with the current inputs. Any malformed,
/// truncated, or stale cache state is a miss.
pub fn cached_run_uncompressed_size(
    run_dir: &Path,
    prepared_rootfs: &Path,
    expected_kernel: &ArtifactMetadata,
    expected_rootfs: &ArtifactMetadata,
    expected_compression: &CompressionMetadata,
) -> Option<u64> {
    let metadata: RunMetadata = read_json(&run_metadata_path(run_dir)).ok()?;
    if metadata.schema_version != CACHE_SCHEMA_VERSION
        || metadata.kernel != *expected_kernel
        || metadata.rootfs != *expected_rootfs
        || metadata.compression != *expected_compression
        || metadata.uncompressed_rootfs_size != expected_rootfs.size
    {
        return None;
    }
    if !artifact_matches(prepared_rootfs, &metadata.rootfs).ok()? {
        return None;
    }
    if !artifact_matches(&run_dir.join("kernel.bin"), &metadata.kernel).ok()? {
        return None;
    }
    if !artifact_matches(&run_dir.join("initrd.img"), &metadata.initrd).ok()? {
        return None;
    }
    Some(metadata.uncompressed_rootfs_size)
}

/// Publish the run-completion metadata record.
pub fn publish_run_metadata(
    run_dir: &Path,
    kernel: ArtifactMetadata,
    rootfs: ArtifactMetadata,
    initrd_path: &Path,
    uncompressed_rootfs_size: u64,
    compression: CompressionMetadata,
) -> io::Result<()> {
    let metadata = RunMetadata {
        schema_version: CACHE_SCHEMA_VERSION,
        kernel,
        rootfs,
        initrd: artifact_metadata(initrd_path)?,
        uncompressed_rootfs_size,
        compression,
    };
    // This is the completion sentinel: it is written after kernel.bin and
    // initrd.img have both been atomically published.
    atomic_write_json(&run_metadata_path(run_dir), &metadata)
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("cache"));
    path.with_file_name(format!(".{file_name}.tmp-{}", Uuid::now_v7()))
}

fn write_temp(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// Maximum times [`publish_temp_with`] retries a rename that contends with a
/// concurrent publisher before replacing a stale destination.
const PUBLISH_RETRY_ATTEMPTS: usize = 3;
/// Sleep between rename retries: the other writer's replace window.
const PUBLISH_RETRY_BACKOFF: Duration = Duration::from_millis(50);

fn publish_temp(
    temp: &Path,
    destination: &Path,
    expected_hash: blake3::Hash,
    expected_size: u64,
) -> io::Result<()> {
    publish_temp_with(
        temp,
        destination,
        expected_hash,
        expected_size,
        |from: &Path, to: &Path| fs::rename(from, to),
        file_matches,
    )
}

/// Publish `temp` to `destination`, tolerating a concurrent publisher.
///
/// `rename` and `matches` are injected so the failure modes are unit-testable
/// without real concurrency; [`publish_temp`] delegates with `fs::rename` and
/// [`file_matches`].
fn publish_temp_with(
    temp: &Path,
    destination: &Path,
    expected_hash: blake3::Hash,
    expected_size: u64,
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
    matches: impl Fn(&Path, blake3::Hash, u64) -> io::Result<bool>,
) -> io::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    // On Windows a concurrent publisher's replace surfaces as a sharing
    // violation (`PermissionDenied`) instead of `AlreadyExists`: writer A
    // briefly holds the destination open (replace or validation read) while
    // writer B renames. Both kinds are contention, not publication failures.
    let contended = |error: &io::Error| {
        matches!(
            error.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
        )
    };

    match rename(temp, destination) {
        Ok(()) => Ok(()),
        Err(error) if contended(&error) => {
            // A concurrent builder may have won the rename first. Since the
            // destination name is content-derived, an existing destination
            // is accepted after its size and digest have been checked. The
            // validation read itself can hit the winner's replace window
            // (PermissionDenied/AlreadyExists); that is contention too and
            // is retried inside the same loop, surfaced only after
            // `PUBLISH_RETRY_ATTEMPTS`.
            let mut accepted = false;
            for attempt in 0..=PUBLISH_RETRY_ATTEMPTS {
                if attempt > 0 {
                    std::thread::sleep(PUBLISH_RETRY_BACKOFF);
                }
                match matches(destination, expected_hash, expected_size) {
                    Ok(true) => {
                        accepted = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(error) if contended(&error) => {}
                    Err(error) => {
                        let _ = fs::remove_file(temp);
                        return Err(error);
                    }
                }
                match rename(temp, destination) {
                    Ok(()) => return Ok(()),
                    Err(error) if contended(&error) => {}
                    Err(error) => {
                        let _ = fs::remove_file(temp);
                        return Err(error);
                    }
                }
            }
            if accepted {
                let _ = fs::remove_file(temp);
                return Ok(());
            }
            // The existing file is still stale or was left by an interrupted
            // old writer. It is a derived cache artifact, so replacing it is
            // safe; the newly written sibling is still complete.
            let _ = fs::remove_file(destination);
            match rename(temp, destination) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = fs::remove_file(temp);
                    Err(error)
                }
            }
        }
        Err(error) => {
            let _ = fs::remove_file(temp);
            Err(error)
        }
    }
}

fn file_matches(path: &Path, expected_hash: blake3::Hash, expected_size: u64) -> io::Result<bool> {
    if !has_size(path, expected_size) {
        return Ok(false);
    }
    let (actual_hash, actual_size) = file_identity(path)?;
    Ok(actual_size == expected_size && actual_hash == expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("jyth-cache-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn artifact_metadata_round_trips_and_detects_truncation() {
        let dir = temp_dir();
        let path = dir.join("artifact");
        let bytes = b"complete artifact";
        atomic_write(&path, bytes).unwrap();
        let expected = artifact_metadata(&path).unwrap();
        assert!(artifact_matches(&path, &expected).unwrap());

        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(!artifact_matches(&path, &expected).unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_identical_publications_leave_one_valid_metadata_record() {
        let dir = temp_dir();
        let artifact_path = dir.join("rootfs.cpio");
        let metadata_path = dir.join("rootfs.json");
        let bytes = b"deterministic rootfs".to_vec();
        let expected = ArtifactMetadata {
            digest: format!("blake3_{}", blake3::hash(&bytes).to_hex()),
            size: bytes.len() as u64,
        };
        let metadata = RunMetadata {
            schema_version: CACHE_SCHEMA_VERSION,
            kernel: expected.clone(),
            rootfs: expected.clone(),
            initrd: expected.clone(),
            uncompressed_rootfs_size: expected.size,
            compression: CompressionMetadata {
                algorithm: "gzip".to_string(),
                level: 6,
            },
        };

        let mut workers = Vec::new();
        for _ in 0..8 {
            let artifact_path = artifact_path.clone();
            let metadata_path = metadata_path.clone();
            let bytes = bytes.clone();
            let metadata = metadata.clone();
            workers.push(std::thread::spawn(move || {
                atomic_write(&artifact_path, &bytes).unwrap();
                atomic_write_json(&metadata_path, &metadata).unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        assert!(artifact_matches(&artifact_path, &expected).unwrap());
        let actual: RunMetadata = read_json(&metadata_path).unwrap();
        assert_eq!(actual, metadata);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_accepts_a_matching_destination_after_permission_denied() {
        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").unwrap();
        fs::write(&destination, b"identical").unwrap();
        let expected = blake3::hash(b"identical");

        publish_temp_with(
            &temp,
            &destination,
            expected,
            b"identical".len() as u64,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            file_matches,
        )
        .expect("a matching destination must win");

        assert!(!temp.exists(), "the loser's temp file must be removed");
        assert_eq!(fs::read(&destination).unwrap(), b"identical");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_retries_transient_permission_denied_until_rename_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"complete").unwrap();
        fs::write(&destination, b"stale").unwrap();
        let expected = blake3::hash(b"complete");
        let attempts = AtomicUsize::new(0);
        let rename = |from: &Path, to: &Path| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "other writer is mid-replace",
                ));
            }
            fs::rename(from, to)
        };

        publish_temp_with(
            &temp,
            &destination,
            expected,
            b"complete".len() as u64,
            rename,
            file_matches,
        )
        .expect("transient contention must not fail the publish");

        assert_eq!(fs::read(&destination).unwrap(), b"complete");
        assert!(!temp.exists());
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "exactly one retry");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_surfaces_persistent_permission_denied_after_retries() {
        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"complete").unwrap();
        fs::write(&destination, b"stale").unwrap();
        let expected = blake3::hash(b"complete");

        let error = publish_temp_with(
            &temp,
            &destination,
            expected,
            b"complete".len() as u64,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            file_matches,
        )
        .expect_err("persistent contention must surface as an error");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!temp.exists(), "the temp file must be removed on failure");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_retries_a_contended_validation_read() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").unwrap();
        fs::write(&destination, b"identical").unwrap();
        let expected = blake3::hash(b"identical");
        let validation_attempts = AtomicUsize::new(0);
        let matches = |path: &Path, hash: blake3::Hash, size: u64| {
            if validation_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "winner's replace window",
                ));
            }
            file_matches(path, hash, size)
        };

        publish_temp_with(
            &temp,
            &destination,
            expected,
            b"identical".len() as u64,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            matches,
        )
        .expect("a contended validation read must retry, not abort");

        assert!(!temp.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"identical");
        assert_eq!(validation_attempts.load(Ordering::SeqCst), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_surfaces_persistent_contended_validation_reads() {
        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"complete").unwrap();
        fs::write(&destination, b"stale").unwrap();
        let expected = blake3::hash(b"complete");

        let error = publish_temp_with(
            &temp,
            &destination,
            expected,
            b"complete".len() as u64,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            |_, _, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
        )
        .expect_err("persistently contended validation reads must surface");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!temp.exists(), "the temp file must be removed on failure");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_write_removes_its_temp_sibling_on_failure() {
        let dir = temp_dir();
        let destination = dir.join("artifact");
        fs::create_dir(&destination).unwrap();

        atomic_write(&destination, b"bytes").expect_err("publishing over a directory");

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".artifact.tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp siblings must be removed: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_copy_removes_its_temp_sibling_on_failure() {
        let dir = temp_dir();
        let source = dir.join("source.bin");
        let destination = dir.join("artifact");
        fs::write(&source, b"bytes").unwrap();
        fs::create_dir(&destination).unwrap();

        atomic_copy(&source, &destination).expect_err("publishing over a directory");

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".artifact.tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp siblings must be removed: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn publish_accepts_an_already_existing_matching_destination() {
        let dir = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").unwrap();
        fs::write(&destination, b"identical").unwrap();
        let expected = blake3::hash(b"identical");

        publish_temp_with(
            &temp,
            &destination,
            expected,
            b"identical".len() as u64,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "POSIX rename semantics",
                ))
            },
            file_matches,
        )
        .expect("an already-existing matching destination must win");

        assert!(!temp.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"identical");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_gzip_streams_and_publishes_complete_artifact() {
        let dir = temp_dir();
        let source = dir.join("rootfs.cpio");
        let destination = dir.join("initrd.img");
        let source_bytes = vec![b'x'; 256 * 1024];
        fs::write(&source, &source_bytes).unwrap();

        let source_size = atomic_gzip(&source, &destination, 6).unwrap();
        assert_eq!(source_size, source_bytes.len() as u64);
        assert!(has_size(
            &destination,
            fs::metadata(&destination).unwrap().len()
        ));

        let compressed = fs::read(&destination).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut round_trip = Vec::new();
        decoder.read_to_end(&mut round_trip).unwrap();
        assert_eq!(round_trip, source_bytes);
        let temporary_artifacts = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".initrd.img.tmp-")
            })
            .count();
        assert_eq!(temporary_artifacts, 0);

        let _ = fs::remove_dir_all(dir);
    }

    fn run_cache_fixture() -> (
        PathBuf,
        ArtifactMetadata,
        ArtifactMetadata,
        CompressionMetadata,
    ) {
        let dir = std::env::temp_dir().join(format!("jyth-run-cache-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("kernel.bin"), b"kernel").unwrap();
        std::fs::write(dir.join("rootfs.cpio"), b"rootfs").unwrap();
        std::fs::write(dir.join("initrd.img"), b"compressed rootfs").unwrap();
        let kernel = artifact_metadata(&dir.join("kernel.bin")).unwrap();
        let rootfs = artifact_metadata(&dir.join("rootfs.cpio")).unwrap();
        let compression = initrd_compression_metadata();
        publish_run_metadata(
            &dir,
            kernel.clone(),
            rootfs.clone(),
            &dir.join("initrd.img"),
            rootfs.size,
            compression.clone(),
        )
        .unwrap();
        (dir, kernel, rootfs, compression)
    }

    #[test]
    fn identical_run_uses_warm_metadata_without_recompressing() {
        let (dir, kernel, rootfs, compression) = run_cache_fixture();
        let rootfs_path = dir.join("rootfs.cpio");
        let mut compressor_invocations = 0;
        if cached_run_uncompressed_size(&dir, &rootfs_path, &kernel, &rootfs, &compression)
            .is_none()
        {
            compressor_invocations += 1;
        }
        assert_eq!(compressor_invocations, 0);
        assert_eq!(
            cached_run_uncompressed_size(&dir, &rootfs_path, &kernel, &rootfs, &compression),
            Some(rootfs.size)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn changed_kernel_or_rootfs_is_a_cache_miss() {
        let (dir, kernel, rootfs, compression) = run_cache_fixture();
        let rootfs_path = dir.join("rootfs.cpio");

        std::fs::write(dir.join("kernel.bin"), b"changed kernel").unwrap();
        let changed_kernel = artifact_metadata(&dir.join("kernel.bin")).unwrap();
        assert!(
            cached_run_uncompressed_size(
                &dir,
                &rootfs_path,
                &changed_kernel,
                &rootfs,
                &compression,
            )
            .is_none()
        );

        std::fs::write(dir.join("kernel.bin"), b"kernel").unwrap();
        std::fs::write(dir.join("rootfs.cpio"), b"changed rootfs").unwrap();
        let changed_rootfs = artifact_metadata(&dir.join("rootfs.cpio")).unwrap();
        assert!(
            cached_run_uncompressed_size(
                &dir,
                &rootfs_path,
                &kernel,
                &changed_rootfs,
                &compression,
            )
            .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn truncated_initrd_and_corrupt_metadata_are_safe_misses() {
        let (dir, kernel, rootfs, compression) = run_cache_fixture();
        let rootfs_path = dir.join("rootfs.cpio");
        std::fs::write(dir.join("initrd.img"), b"compressed").unwrap();
        assert!(
            cached_run_uncompressed_size(&dir, &rootfs_path, &kernel, &rootfs, &compression)
                .is_none()
        );

        std::fs::write(run_metadata_path(&dir), b"not json").unwrap();
        assert!(
            cached_run_uncompressed_size(&dir, &rootfs_path, &kernel, &rootfs, &compression)
                .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
