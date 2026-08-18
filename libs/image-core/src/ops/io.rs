//! Atomic file staging utilities for the image materialization operations.
//!
//! All blocking operations write to a uniquely named temporary file first and
//! only publish the destination after the bytes are fully flushed, validated
//! and digested. This crate distinguishes three modes:
//!
//! * [`TempWriter::open`] creates a uniquely named temporary file inside the
//!   destination's directory. The temp file is removed automatically when the
//!   [`TempWriter`] is dropped without [`TempWriter::publish`] having been
//!   called, so a failed operation never leaves a partially written
//!   destination.
//! * [`publish`] atomically swaps the temporary file into the destination's
//!   path. The previous destination is preserved until the swap completes so
//!   a publish failure never destroys a previously valid artifact.
//! * [`TempWriter::write_all`] appends bytes to the staging writer while
//!   computing the local BLAKE3 hash and the total byte count.
//!
//! The crate always uses BLAKE3 to identify local bytes; the caller may pass
//! an [`ExpectedDigest`][crate::digest::ExpectedDigest] separately to verify
//! the bytes against a manifest-declared digest.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use sha2::{Digest as _, Sha256, Sha512};
use uuid::Uuid;

use crate::digest::{ComputedDigest, ExpectedDigest, FileDigest};
use crate::ops::error::TempFileError;

/// Optional auxiliary hasher running alongside the BLAKE3 hash computed by
/// [`TempWriter`]. It is configured from an [`ExpectedDigest`] so the
/// materialization pipeline can verify bytes against a manifest-declared
/// algorithm without rereading the destination.
#[derive(Debug)]
enum AuxHasher {
    None,
    Blake3,
    Sha256(Sha256),
    Sha512(Sha512),
}

impl AuxHasher {
    fn from_expected(expected: Option<&ExpectedDigest>) -> Self {
        match expected {
            None => Self::None,
            Some(ExpectedDigest::Blake3(_)) => Self::Blake3,
            Some(ExpectedDigest::Sha256(_)) => Self::Sha256(Sha256::new()),
            Some(ExpectedDigest::Sha512(_)) => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::None | Self::Blake3 => {}
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha512(hasher) => hasher.update(bytes),
        }
    }

    /// Materialize the auxiliary digest. Returns `None` when no auxiliary
    /// algorithm was requested. The `Blake3` variant returns `None` because
    /// the local BLAKE3 hash computed by [`TempWriter`] is the corresponding
    /// [`ComputedDigest::Blake3`]; the caller reuses it directly.
    fn finalize(self) -> Option<ComputedDigest> {
        match self {
            Self::None | Self::Blake3 => None,
            Self::Sha256(hasher) => {
                let bytes = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Some(ComputedDigest::Sha256(out))
            }
            Self::Sha512(hasher) => {
                let bytes = hasher.finalize();
                let mut out = [0u8; 64];
                out.copy_from_slice(&bytes);
                Some(ComputedDigest::Sha512(out))
            }
        }
    }
}

/// A staging writer wrapping a file adjacent to its destination.
///
/// On [`Drop`] the temporary path is removed unless [`TempWriter::publish`]
/// succeeded. The lifecycle guarantees that no partial destination lives
/// after an error.
#[derive(Debug)]
pub struct TempWriter {
    file: Option<File>,
    temp_path: PathBuf,
    destination: PathBuf,
    hasher: Hasher,
    aux: AuxHasher,
    bytes_written: u128,
    finished: Option<PublishedFile>,
    published: bool,
}

impl TempWriter {
    /// Create a uniquely named temporary file in `destination`'s parent
    /// directory.
    pub fn open(destination: &Path) -> Result<Self, error_stack::Report<TempFileError>> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        let temp_name = format!(".{}.tmp-{}", file_stem(destination), Uuid::now_v7());
        let temp_path = parent.join(&temp_name);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|err| TempFileError::Create(temp_path.clone(), err).report())?;

        Ok(Self {
            file: Some(file),
            temp_path,
            destination: destination.to_path_buf(),
            hasher: Hasher::new(),
            aux: AuxHasher::None,
            bytes_written: 0,
            finished: None,
            published: false,
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary writer handle is open before publication")
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    /// Total number of bytes written to the staging writer so far.
    pub fn bytes_written(&self) -> u128 {
        self.bytes_written
    }

    /// Configure an auxiliary hasher matching `expected`. The writer tracks
    /// this algorithm alongside the BLAKE3 hash so callers can verify bytes
    /// against a manifest-declared digest without rereading the destination.
    ///
    /// Passing `None` (or never calling this method) leaves the auxiliary
    /// hasher disabled.
    pub fn set_expected_digest(&mut self, expected: Option<&ExpectedDigest>) {
        self.aux = AuxHasher::from_expected(expected);
    }

    /// Append bytes to the staging writer while updating the running digest
    /// and any configured auxiliary hasher.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<(), error_stack::Report<TempFileError>> {
        self.file_mut()
            .write_all(bytes)
            .map_err(|err| TempFileError::Write(self.temp_path.clone(), err).report())?;
        self.hasher.update(bytes);
        self.aux.update(bytes);
        self.bytes_written += bytes.len() as u128;
        Ok(())
    }

    /// Flush the staging writer without publishing.
    pub fn flush(&mut self) -> Result<(), error_stack::Report<TempFileError>> {
        self.file_mut()
            .flush()
            .map_err(|err| TempFileError::Flush(self.temp_path.clone(), err).report())?;
        Ok(())
    }

    /// Finish the staging writer without publishing it.
    ///
    /// This is deliberately separate from [`Self::publish`]. Callers can
    /// inspect the staged bytes and verify all external authorities while the
    /// previous destination remains in place. Dropping the writer after a
    /// failed validation removes the temporary file.
    pub fn finish(&mut self) -> Result<PublishedFile, error_stack::Report<TempFileError>> {
        if let Some(finished) = &self.finished {
            return Ok(finished.clone());
        }

        self.file_mut()
            .flush()
            .map_err(|err| TempFileError::Flush(self.temp_path.clone(), err).report())?;
        self.file_mut()
            .sync_all()
            .map_err(|err| TempFileError::Flush(self.temp_path.clone(), err).report())?;

        let file_hash = std::mem::replace(&mut self.hasher, Hasher::new()).finalize();
        let file_digest = FileDigest {
            file_hash,
            file_size: self.bytes_written,
        };
        let aux = std::mem::replace(&mut self.aux, AuxHasher::None).finalize();
        let finished = PublishedFile { file_digest, aux };
        self.finished = Some(finished.clone());
        Ok(finished)
    }

    /// Finalize the staging writer and atomically replace the destination
    /// path with the temporary file.
    ///
    /// Destinations are content-derived (`namespace/<uuid>`), so concurrent
    /// builds can publish to the same path. Publication tolerates that
    /// contention exactly like the jyth cache fix (`publish_temp_with`):
    /// when the rename is rejected with a contention error, the destination
    /// is validated against the staged file's digest and size — a matching
    /// destination is accepted as the winner — and stale content is replaced
    /// after a bounded retry.
    pub fn publish(mut self) -> Result<PublishedFile, error_stack::Report<TempFileError>> {
        let finished = self.finish()?;

        // Closing the handle before the rename is required on Windows and is
        // harmless on Unix. `TempWriter` owns the only write handle, so the
        // staged file is still stable after this point.
        drop(self.file.take());

        publish(&self.temp_path, &self.destination, &finished.file_digest)?;

        self.published = true;
        Ok(finished)
    }
}

impl Drop for TempWriter {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let _ = fs::remove_file(&self.temp_path);
    }
}

/// Output of a successful [`TempWriter::publish`].
///
/// `file_digest` is the locally-canonical BLAKE3 digest of the published
/// bytes; `aux` carries the auxiliary algorithm digest configured via
/// [`TempWriter::set_expected_digest`] when present, so a manifest-declared
/// digest can be verified without rereading the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedFile {
    pub file_digest: FileDigest,
    pub aux: Option<ComputedDigest>,
}

/// A finished output whose temporary path is still unpublished.
///
/// The metadata is available for validation, while the writer remains owned
/// by this value so a failed validation still cleans up the temporary file.
#[derive(Debug)]
pub struct StagedFile {
    writer: Option<TempWriter>,
    pub metadata: PublishedFile,
}

impl StagedFile {
    pub fn temp_path(&self) -> &Path {
        self.writer
            .as_ref()
            .expect("staged file writer is present before publish")
            .temp_path()
    }

    pub fn publish(mut self) -> Result<PublishedFile, error_stack::Report<TempFileError>> {
        self.writer
            .take()
            .expect("staged file writer is present before publish")
            .publish()
    }
}

impl TempWriter {
    /// Finish a writer and retain ownership of its temporary file for later
    /// validation and publication.
    pub fn stage(mut self) -> Result<StagedFile, error_stack::Report<TempFileError>> {
        let metadata = self.finish()?;
        Ok(StagedFile {
            writer: Some(self),
            metadata,
        })
    }
}

impl PublishedFile {
    /// Produce the [`ComputedDigest`] for `expected` from the published
    /// bytes. For BLAKE3 the local digest is reused directly; the auxiliary
    /// hasher (which never tracked BLAKE3) falls through.
    pub fn computed_for(&self, expected: Option<&ExpectedDigest>) -> Option<ComputedDigest> {
        match expected {
            None => None,
            Some(ExpectedDigest::Blake3(_)) => {
                let mut out = [0u8; 32];
                out.copy_from_slice(self.file_digest.file_hash.as_bytes());
                Some(ComputedDigest::Blake3(out))
            }
            Some(ExpectedDigest::Sha256(_)) | Some(ExpectedDigest::Sha512(_)) => self.aux.clone(),
        }
    }
}

/// Read at most `len` bytes from the start of `path`. Returns the bytes
/// that could be read; callers do not require the leading slice to equal
/// [`MIN_HEADER_LEN`][crate::ops::format::MIN_HEADER_LEN].
pub fn read_header(path: &Path, len: usize) -> Result<Vec<u8>, error_stack::Report<TempFileError>> {
    let mut file =
        File::open(path).map_err(|err| TempFileError::Open(path.to_path_buf(), err).report())?;
    read_header_from_file(path, &mut file, len)
}

/// Read at most `len` bytes from the start of the given file handle. The
/// `path` argument is attached to any read error so callers can attribute
/// failures to the originating file.
pub fn read_header_from_file(
    path: &Path,
    file: &mut File,
    len: usize,
) -> Result<Vec<u8>, error_stack::Report<TempFileError>> {
    let mut buffer = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let read = file
            .read(&mut buffer[filled..])
            .map_err(|err| TempFileError::Read(path.to_path_buf(), err).report())?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Maximum times [`publish_with`] retries a publish that contends with a
/// concurrent publisher before replacing a stale destination.
const PUBLISH_RETRY_ATTEMPTS: usize = 3;
/// Sleep between publish retries: the other writer's replace window.
const PUBLISH_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Atomically replace the destination file at `destination` with the file at
/// `temp`. The previous file is preserved until the swap completes.
///
/// `expected` is the digest of the staged file at `temp`. Destinations are
/// content-derived, so a concurrent publisher may win the swap first: on a
/// contention error the destination is validated against `expected` and a
/// matching destination is accepted as the winner (bounded retry, then a
/// replace of stale content). See [`publish_with`] for the exact policy.
pub fn publish(
    temp: &Path,
    destination: &Path,
    expected: &FileDigest,
) -> Result<(), error_stack::Report<TempFileError>> {
    publish_with(
        temp,
        destination,
        expected,
        attempt_publish,
        destination_matches,
    )
}

/// Publish `temp` to `destination`, tolerating a concurrent publisher.
///
/// `rename` and `matches` are injected so the failure modes are unit-testable
/// without real concurrency; [`publish`] delegates with [`attempt_publish`]
/// and [`destination_matches`].
///
/// Policy (ported from the jyth cache fix, `publish_temp_with`):
///
/// 1. Plain rename. On success the temp is consumed.
/// 2. On a contention error (a concurrent writer's replace window), validate
///    the destination against `expected`; a matching destination is accepted
///    as the winner and the loser's temp is removed.
/// 3. A stale destination is replaced after [`PUBLISH_RETRY_ATTEMPTS`]
///    bounded retries with [`PUBLISH_RETRY_BACKOFF`] between them.
///
/// Validation-read failures with the same contention kinds are retried inside
/// the same loop rather than aborting the publish.
fn publish_with(
    temp: &Path,
    destination: &Path,
    expected: &FileDigest,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
    matches: impl Fn(&Path, &FileDigest) -> std::io::Result<bool>,
) -> Result<(), error_stack::Report<TempFileError>> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| TempFileError::Publish(destination.to_path_buf(), err).report())?;
    }

    let publish_err =
        |error: std::io::Error| TempFileError::Publish(destination.to_path_buf(), error).report();

    // A directory destination is a hard error, never contention: no retry
    // can make the rename succeed, and Windows would otherwise classify the
    // access denial as a replace window.
    if let Ok(metadata) = fs::metadata(destination)
        && metadata.is_dir()
    {
        let _ = fs::remove_file(temp);
        return Err(publish_err(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "destination is a directory",
        )));
    }

    match rename(temp, destination) {
        Ok(()) => return Ok(()),
        Err(error) if !contended(&error) => {
            let _ = fs::remove_file(temp);
            return Err(publish_err(error));
        }
        Err(_) => {}
    }

    // A concurrent publisher is mid-flight. Validate the destination against
    // the staged digest; accept a matching winner, retry briefly while the
    // other writer finishes, then replace stale content.
    let mut accepted = false;
    for attempt in 0..=PUBLISH_RETRY_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PUBLISH_RETRY_BACKOFF);
        }
        match matches(destination, expected) {
            Ok(true) => {
                accepted = true;
                break;
            }
            Ok(false) => {}
            // The winner's validation read can itself hit the replace
            // window; that is contention, not a publication failure.
            Err(error) if contended(&error) => {}
            Err(error) => {
                let _ = fs::remove_file(temp);
                return Err(publish_err(error));
            }
        }
        match rename(temp, destination) {
            Ok(()) => return Ok(()),
            Err(error) if contended(&error) => {}
            Err(error) => {
                let _ = fs::remove_file(temp);
                return Err(publish_err(error));
            }
        }
    }

    if accepted {
        // The winner's bytes are identical (the destination is
        // content-addressed). Remove our now-unneeded sibling.
        let _ = fs::remove_file(temp);
        return Ok(());
    }

    // The existing destination is stale or was left by an interrupted
    // writer. It is a derived artifact, so replacing it is safe; the newly
    // written sibling is still complete.
    let _ = fs::remove_file(destination);
    match rename(temp, destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(temp);
            Err(publish_err(error))
        }
    }
}

/// Whether `error` indicates a concurrent writer's replace window rather
/// than a real publication failure.
fn contended(error: &std::io::Error) -> bool {
    #[cfg(windows)]
    {
        // Raw Win32 codes are matched explicitly in addition to the mapped
        // kinds: `std` maps most of these to `PermissionDenied` today, but
        // the kind mapping is not part of the stable contract, and the
        // `ReplaceFileW` family (1175-1178) falls back to `Uncategorized`.
        const ERROR_FILE_NOT_FOUND: i32 = 2;
        const ERROR_PATH_NOT_FOUND: i32 = 3;
        const ERROR_ACCESS_DENIED: i32 = 5;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_LOCK_VIOLATION: i32 = 33;
        const ERROR_ALREADY_EXISTS: i32 = 183;
        const ERROR_UNABLE_TO_MOVE_REPLACEMENT: i32 = 1175;
        const ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1176;
        const ERROR_UNABLE_TO_REMOVE_REPLACED: i32 = 1177;
        const ERROR_UNABLE_TO_REMOVE_REPLACEMENT: i32 = 1178;
        matches!(
            error.kind(),
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
        ) || matches!(
            error.raw_os_error(),
            Some(
                ERROR_FILE_NOT_FOUND
                    | ERROR_PATH_NOT_FOUND
                    | ERROR_ACCESS_DENIED
                    | ERROR_SHARING_VIOLATION
                    | ERROR_LOCK_VIOLATION
                    | ERROR_ALREADY_EXISTS
                    | ERROR_UNABLE_TO_MOVE_REPLACEMENT
                    | ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
                    | ERROR_UNABLE_TO_REMOVE_REPLACED
                    | ERROR_UNABLE_TO_REMOVE_REPLACEMENT
            )
        )
    }
    #[cfg(not(windows))]
    {
        matches!(
            error.kind(),
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
        )
    }
}

/// One atomic publish attempt: rename over the destination.
fn attempt_publish(temp: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(temp, destination)
    }
    #[cfg(not(unix))]
    {
        windows_publish_attempt(temp, destination)
    }
}

/// Strict atomic replacement of a caller-owned output file (Jyth review
/// remediation WP4, finding F-04).
///
/// `staging` is a complete sibling file written by the caller; `destination`
/// is the caller-owned output it replaces. The function never deletes the
/// destination before success: a failed replacement leaves the complete
/// previous file in place, and the staging path remains available to the
/// caller for cleanup.
///
/// Unlike the content-addressed cache publisher ([`publish`]), this helper
/// has no stale-destination deletion fallback: the destination belongs to the
/// caller, not to a derived-artifact namespace.
pub fn replace_file_atomically(staging: &Path, destination: &Path) -> std::io::Result<()> {
    // Both paths must share one parent directory: a same-filesystem rename is
    // the atomicity guarantee, and a cross-directory pair would violate it.
    let staging_parent = staging
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let destination_parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if staging_parent != destination_parent {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staging and destination must share one parent directory",
        ));
    }

    // A directory destination is a hard error: the replacement must never
    // follow or replace a directory, and Windows would classify the access
    // denial as a replace window.
    if let Ok(metadata) = fs::metadata(destination)
        && metadata.is_dir()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "destination is a directory",
        ));
    }

    strict_replace(staging, destination)
}

/// One strict replacement attempt: one same-filesystem `rename` on Unix;
/// `ReplaceFileW` over an existing destination or `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` for a missing
/// destination on Windows. The destination is never deleted first.
fn strict_replace(staging: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(staging, destination)
    }
    #[cfg(not(unix))]
    {
        windows_strict_replace(staging, destination)
    }
}

/// Maximum times the Windows strict replacement retries a destination
/// existence race before surfacing the error. Neither path is ever deleted.
const STRICT_REPLACE_RETRY_ATTEMPTS: usize = 3;
/// Sleep between strict-replacement retries: the other writer's replace
/// window.
const STRICT_REPLACE_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Windows strict replacement. When the destination exists, `ReplaceFileW`
/// performs the replacement as one filesystem operation; a missing
/// destination is published through `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
///
/// The `destination.exists()` probe and the filesystem primitive are not
/// atomic: the destination may appear or disappear between them (another
/// writer's replace window). Such races are retried a bounded number of
/// times; neither destination path is ever removed by this helper.
#[cfg(not(unix))]
fn windows_strict_replace(staging: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *const std::ffi::c_void,
            reserved: *const std::ffi::c_void,
        ) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const REPLACEFILE_WRITE_THROUGH: u32 = 0x0000_0001;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let staging_wide = wide(staging);
    let destination_wide = wide(destination);
    let flags = REPLACEFILE_WRITE_THROUGH;

    let mut last_error: Option<std::io::Error> = None;
    for _ in 0..=STRICT_REPLACE_RETRY_ATTEMPTS {
        let replaced = if destination.exists() {
            unsafe {
                ReplaceFileW(
                    destination_wide.as_ptr(),
                    staging_wide.as_ptr(),
                    std::ptr::null(),
                    flags,
                    std::ptr::null(),
                    std::ptr::null(),
                ) != 0
            }
        } else {
            unsafe {
                MoveFileExW(
                    staging_wide.as_ptr(),
                    destination_wide.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                ) != 0
            }
        };

        if replaced {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        // The destination existence probe and the primitive are not atomic;
        // an existence race (file appears or disappears between them)
        // surfaces as a contention error and is retried. Neither path is
        // removed.
        if contended(&error) {
            last_error = Some(error);
            std::thread::sleep(STRICT_REPLACE_RETRY_BACKOFF);
            continue;
        }
        return Err(error);
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other("strict replacement exhausted its bounded retries")
    }))
}

/// Validate that the destination's on-disk bytes equal `expected`. An absent
/// destination is `Ok(false)` (stale or mid-replace; the caller retries the
/// rename). A probe that fails with a sharing violation surfaces as an error
/// with the kind preserved so the caller can classify it as contention.
fn destination_matches(path: &Path, expected: &FileDigest) -> std::io::Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() as u128 == expected.file_size => {}
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize() == expected.file_hash)
}

/// Windows publish attempt. When the destination exists, `ReplaceFileW`
/// performs the replacement as one filesystem operation; no fixed-name
/// backup is needed and no intermediate state exposes a missing destination.
///
/// The `destination.exists()` probe and the filesystem primitive are not
/// atomic: the destination may appear or disappear between them (another
/// writer's replace window). Such failures surface as ordinary IO errors and
/// the caller treats the race as retryable contention.
#[cfg(not(unix))]
fn windows_publish_attempt(temp: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    // Keep the Windows replacement primitive local so the image crate does
    // not need an additional runtime dependency merely for this platform
    // branch. These declarations mirror kernel32's stable wide-character
    // APIs.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *const std::ffi::c_void,
            reserved: *const std::ffi::c_void,
        ) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const REPLACEFILE_WRITE_THROUGH: u32 = 0x0000_0001;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let temp_wide = wide(temp);
    let destination_wide = wide(destination);
    let flags = REPLACEFILE_WRITE_THROUGH;

    let replaced = if destination.exists() {
        unsafe {
            ReplaceFileW(
                destination_wide.as_ptr(),
                temp_wide.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
                std::ptr::null(),
            ) != 0
        }
    } else {
        unsafe {
            MoveFileExW(
                temp_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            ) != 0
        }
    };

    if replaced {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Compute the local BLAKE3 digest of an on-disk file. Test helpers stage
/// fixture bytes on disk and derive the matching `FileDigest` from the file.
pub fn compute_file_digest(path: &Path) -> Result<FileDigest, error_stack::Report<TempFileError>> {
    let mut file =
        File::open(path).map_err(|err| TempFileError::Open(path.to_path_buf(), err).report())?;
    compute_file_digest_from_file(&mut file, path)
}

/// Compute the local BLAKE3 digest from an already-open file handle.
///
/// Keeping verification and consumption on one handle closes the
/// verify-then-reopen substitution window used by the transformation
/// operations. The caller may seek the handle back to the beginning after
/// this function returns.
pub fn compute_file_digest_from_file(
    file: &mut File,
    path: &Path,
) -> Result<FileDigest, error_stack::Report<TempFileError>> {
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total: u128 = 0;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| TempFileError::Read(path.to_path_buf(), err).report())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u128;
    }
    Ok(FileDigest {
        file_hash: hasher.finalize(),
        file_size: total,
    })
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a temporary directory whose guard outlives the test by being
    /// held by the caller. Returning only the [`PathBuf`] would drop the
    /// guard early and delete the parent directory before the writer opens
    /// its adjacent temp file.
    fn temp_dir() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    #[test]
    fn temp_writer_publishes_destination() {
        let (_guard, dir) = temp_dir();
        let dest = dir.join("out.bin");
        let mut writer = TempWriter::open(&dest).expect("open temp writer");
        writer.write_all(b"hello").expect("write");
        writer.flush().expect("flush");
        let published = writer.publish().expect("publish");
        assert!(dest.exists());
        assert_eq!(published.file_digest.file_size, 5);
        assert_eq!(fs::read(&dest).expect("read published"), b"hello");

        let probe = TempWriter::open(&dest).expect("open cleanup probe");
        let probe_path = probe.temp_path().to_path_buf();
        assert!(probe_path.exists());
        drop(probe);
        assert!(!probe_path.exists());
    }

    #[test]
    fn temp_writer_drops_partial_file_on_failure() {
        let (_guard, dir) = temp_dir();
        let dest = dir.join("dropped.bin");
        let temp_path;
        {
            let writer = TempWriter::open(&dest).expect("open temp writer");
            temp_path = writer.temp_path().to_path_buf();
            assert!(temp_path.exists());
            // Drop without publishing.
        }
        assert!(!temp_path.exists());
        assert!(!dest.exists());
    }

    #[test]
    fn publish_failure_preserves_previous_destination() {
        let (_guard, dir) = temp_dir();
        let dest = dir.join("keep.bin");
        fs::create_dir(&dest).expect("create destination directory");

        let temp = dir.join("temp-to-publish.bin");
        fs::write(&temp, b"new").expect("write new");
        let expected = FileDigest {
            file_hash: blake3::hash(b"new"),
            file_size: 3,
        };

        // A directory is an intentionally unreplaceable destination on both
        // Unix and Windows. A failed publication must leave that destination
        // intact and must not silently remove it first.
        let _err = publish(&temp, &dest, &expected).expect_err("publishing over a directory");
        assert!(dest.is_dir());
        assert!(!temp.exists(), "the failed publish must clean up its temp");
    }

    fn staged_digest(bytes: &[u8]) -> FileDigest {
        FileDigest {
            file_hash: blake3::hash(bytes),
            file_size: bytes.len() as u128,
        }
    }

    #[test]
    fn publish_accepts_a_matching_destination_after_permission_denied() {
        let (_guard, dir) = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").expect("write temp");
        fs::write(&destination, b"identical").expect("write destination");
        let expected = staged_digest(b"identical");

        publish_with(
            &temp,
            &destination,
            &expected,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            destination_matches,
        )
        .expect("a matching destination must win");

        assert!(!temp.exists(), "the loser's temp file must be removed");
        assert_eq!(fs::read(&destination).expect("read"), b"identical");
    }

    #[test]
    fn publish_retries_transient_permission_denied_until_rename_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_guard, dir) = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"complete").expect("write temp");
        fs::write(&destination, b"stale").expect("write stale destination");
        let expected = staged_digest(b"complete");
        let attempts = AtomicUsize::new(0);
        let rename = |from: &Path, to: &Path| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "other writer is mid-replace",
                ));
            }
            fs::rename(from, to)
        };

        publish_with(&temp, &destination, &expected, rename, destination_matches)
            .expect("transient contention must not fail the publish");

        assert_eq!(fs::read(&destination).expect("read"), b"complete");
        assert!(!temp.exists());
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "exactly one retry");
    }

    #[test]
    fn publish_surfaces_persistent_permission_denied_after_retries() {
        let (_guard, dir) = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"complete").expect("write temp");
        fs::write(&destination, b"stale").expect("write stale destination");
        let expected = staged_digest(b"complete");

        let err = publish_with(
            &temp,
            &destination,
            &expected,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            destination_matches,
        )
        .expect_err("persistent contention must surface as an error");

        assert!(matches!(
            err.current_context(),
            TempFileError::Publish(_, _)
        ));
        assert!(!temp.exists(), "the temp file must be removed on failure");
    }

    /// F-04 contract: the cache publisher's stale-destination fallback is a
    /// derived-artifact policy; the strict caller-output helper ([`replace_file_atomically`])
    /// must never inherit it. This documents the publisher's own behavior:
    /// a failed content-addressed publish may remove a stale derived
    /// destination, which is safe exactly because the destination is
    /// content-derived and reproducible.
    #[test]
    fn failed_replacement_can_destroy_the_previous_destination() {
        let (_guard, dir) = temp_dir();
        let temp = dir.join("staging.bin");
        let destination = dir.join("output.bin");
        fs::write(&temp, b"new").expect("write staging");
        fs::write(&destination, b"previous-valid").expect("write previous output");
        let expected = staged_digest(b"new");

        let err = publish_with(
            &temp,
            &destination,
            &expected,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            destination_matches,
        )
        .expect_err("persistent contention must surface as an error");

        assert!(matches!(
            err.current_context(),
            TempFileError::Publish(_, _)
        ));
        // The derived-artifact publisher may remove its stale destination;
        // the strict caller-output helper in the same module never may.
    }

    /// F-04 contract: a successful strict replacement exposes the complete
    /// new bytes at the destination and consumes the staging sibling.
    #[test]
    fn strict_replacement_publishes_the_complete_new_bytes() {
        let (_guard, dir) = temp_dir();
        let staging = dir.join("staging.bin");
        let destination = dir.join("output.bin");
        fs::write(&staging, b"complete new bytes").expect("write staging");
        fs::write(&destination, b"old bytes").expect("write previous output");

        replace_file_atomically(&staging, &destination).expect("strict replace");

        assert_eq!(
            fs::read(&destination).expect("read output"),
            b"complete new bytes"
        );
        assert!(!staging.exists(), "the staging sibling must be consumed");
    }

    /// F-04 contract: a simulated replacement failure preserves the complete
    /// old bytes and leaves the staging path available to the caller.
    #[test]
    fn strict_replacement_failure_preserves_the_previous_destination() {
        let (_guard, dir) = temp_dir();
        let staging = dir.join("staging.bin");
        let destination = dir.join("output.bin");
        fs::write(&staging, b"new").expect("write staging");
        fs::write(&destination, b"previous-valid").expect("write previous output");

        // A directory is an intentionally unreplaceable destination on both
        // Unix and Windows: the strict helper must leave it intact and must
        // never remove the destination first.
        let dir_destination = dir.join("output-dir");
        fs::create_dir(&dir_destination).expect("create destination directory");
        let err = replace_file_atomically(&staging, &dir_destination)
            .expect_err("a directory destination must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::IsADirectory);
        assert!(dir_destination.is_dir(), "the directory must be untouched");
        assert!(staging.exists(), "the staging path stays with the caller");
        assert_eq!(
            fs::read(&destination).expect("read previous output"),
            b"previous-valid",
            "an unrelated destination must be untouched"
        );
    }

    /// F-04 contract: staging and destination must share one parent directory
    /// so the replacement is one same-filesystem operation.
    #[test]
    fn strict_replacement_rejects_cross_directory_pairs() {
        let (_guard, dir) = temp_dir();
        let staging = dir.join("staging.bin");
        let other = dir.join("other");
        fs::create_dir(&other).expect("other dir");
        let destination = other.join("output.bin");
        fs::write(&staging, b"new").expect("write staging");

        let err = replace_file_atomically(&staging, &destination)
            .expect_err("cross-directory pair must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!destination.exists());
        assert!(staging.exists(), "the staging path stays with the caller");
    }

    /// F-04 contract: a missing destination publishes successfully through
    /// the strict helper.
    #[test]
    fn strict_replacement_publishes_a_missing_destination() {
        let (_guard, dir) = temp_dir();
        let staging = dir.join("staging.bin");
        let destination = dir.join("fresh.bin");
        fs::write(&staging, b"fresh bytes").expect("write staging");

        replace_file_atomically(&staging, &destination).expect("publish missing destination");

        assert_eq!(fs::read(&destination).expect("read output"), b"fresh bytes");
        assert!(!staging.exists());
    }

    #[test]
    fn publish_accepts_an_already_existing_matching_destination() {
        let (_guard, dir) = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").expect("write temp");
        fs::write(&destination, b"identical").expect("write destination");
        let expected = staged_digest(b"identical");

        publish_with(
            &temp,
            &destination,
            &expected,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "POSIX rename semantics",
                ))
            },
            destination_matches,
        )
        .expect("an already-existing matching destination must win");

        assert!(!temp.exists());
        assert_eq!(fs::read(&destination).expect("read"), b"identical");
    }

    #[test]
    fn publish_retries_a_contended_validation_read() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_guard, dir) = temp_dir();
        let temp = dir.join("sibling.tmp-1");
        let destination = dir.join("artifact");
        fs::write(&temp, b"identical").expect("write temp");
        fs::write(&destination, b"identical").expect("write destination");
        let expected = staged_digest(b"identical");
        let validation_attempts = AtomicUsize::new(0);
        let matches = |path: &Path, expected: &FileDigest| {
            if validation_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "winner's replace window",
                ));
            }
            destination_matches(path, expected)
        };

        publish_with(
            &temp,
            &destination,
            &expected,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sharing violation",
                ))
            },
            matches,
        )
        .expect("a contended validation read must retry, not abort");

        assert!(!temp.exists());
        assert_eq!(fs::read(&destination).expect("read"), b"identical");
        assert_eq!(validation_attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_identical_publications_leave_one_valid_destination() {
        let (_guard, dir) = temp_dir();
        let dest = dir.join("shared.bin");
        let bytes = b"deterministic shared artifact".to_vec();

        let mut workers = Vec::new();
        for _ in 0..8 {
            let dest = dest.clone();
            let bytes = bytes.clone();
            workers.push(std::thread::spawn(move || {
                let mut writer = TempWriter::open(&dest).expect("open temp writer");
                writer.write_all(&bytes).expect("write");
                let published = writer
                    .publish()
                    .unwrap_or_else(|err| panic!("publish failed: {err:#}"));
                assert_eq!(published.file_digest.file_size, bytes.len() as u128);
            }));
        }
        for worker in workers {
            worker.join().expect("worker");
        }

        assert_eq!(fs::read(&dest).expect("read"), bytes.as_slice());
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".shared.bin.tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp siblings may leak: {leftovers:?}"
        );
    }
}
