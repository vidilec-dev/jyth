#![deny(missing_docs)]
//! Shared fixtures and host-serialization helpers for the end-to-end tests.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: e2e-tests.
//!
//! **Responsibility**: define executable acceptance contracts and live-host
//! evidence (scenarios, fixtures, host serialization, adversarial clients,
//! post-run inspection, and failure evidence).
//!
//! **Forbidden concepts**: production implementation shortcuts and
//! duplicated production algorithms.

use std::ops::Deref;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use jyth::VM;
use jyth::builder::image::{Kernel, Link, Rootfs};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// OCI reference for the Alpine rootfs fixture.
pub const ALPINE_ROOTFS: &str = "alpine:3.24";

/// Error type shared by the end-to-end fixture helpers.
pub type E2eResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// How long a test binary waits for another live process to release the
/// shared host lock before refusing to run.
const HOST_LOCK_WAIT: Duration = Duration::from_secs(120);

static HCS_TEST_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();

/// Serialize live HCS tests that share one Windows host.
///
/// Two layers:
///
/// - **In-process** (fast path): a process-wide `tokio::sync::Mutex`, so the
///   tests of one binary never interleave.
/// - **Cross-process**: an exclusive OS-held lock on `%TEMP%\jyth-e2e\`
///   `jyth-e2e-host.lock` (`LockFileEx` on Windows), so the seven test
///   binaries that `cargo test -p e2e-tests` runs as separate processes
///   cannot collide on the fixed default `10.77.0.0/24` NAT subnet or the
///   host journal state. The lock is released by the OS when the holding
///   process exits or dies, so a crashed binary never wedges the suite.
///
/// The lock file is the suite's claim on the shared host resources: a lock
/// that is still held after the bounded wait (`HOST_LOCK_WAIT`) means
/// another live process is running live tests, so the guard refuses to
/// proceed with a clear error instead of colliding (HNS 0x80071392).
///
/// The lock location is deliberately NOT `JYTH_STATE_DIR`: the live binaries
/// set per-binary state dirs (`%TEMP%\jyth-e2e\<binary>`), so a lock inside
/// them would not serialize across binaries. `%TEMP%` is per-user and shared
/// by every binary of one host login, which is exactly the collision domain.
pub async fn hcs_test_guard() -> E2eResult<LiveHostGuard> {
    let in_process = HCS_TEST_LOCK
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
        .lock_owned()
        .await;
    let host = host_lock::acquire(HOST_LOCK_WAIT).await?;
    eprintln!(
        "[e2e] acquired the shared live-host lock (pid {})",
        std::process::id()
    );
    Ok(LiveHostGuard {
        _in_process: in_process,
        _host: host,
    })
}

/// The live-host serialization guard returned by [`hcs_test_guard`]: holds
/// the in-process mutex and the cross-process file lock until dropped.
pub struct LiveHostGuard {
    _in_process: OwnedMutexGuard<()>,
    _host: host_lock::HostLock,
}

/// Cross-process lock-file implementation.
///
/// Windows: `LockFileEx` over a fixed 1-byte gate region (offset 0), with a
/// PID record at a fixed offset outside the locked region so contenders can
/// still read who holds the lock. Non-Windows: `create_new` with age-based
/// stale detection (the live tests only run on Windows; this is a
/// compile-and-run honest fallback for other targets).
mod host_lock {
    use std::time::{Duration, Instant};

    /// The path every live binary contends on.
    pub(super) fn lock_path() -> std::path::PathBuf {
        std::env::temp_dir()
            .join("jyth-e2e")
            .join("jyth-e2e-host.lock")
    }

    #[cfg(target_os = "windows")]
    pub(super) async fn acquire(wait: Duration) -> Result<HostLock, String> {
        use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;

        let path = lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create e2e lock dir {}: {error}", parent.display()))?;
        }
        let mut file = open_lock_file(&path)?;
        let started = Instant::now();
        loop {
            match try_lock(&file) {
                Ok(()) => break,
                Err(error) if error == ERROR_LOCK_VIOLATION => {
                    if started.elapsed() >= wait {
                        return Err(contended_error(&path, wait));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => {
                    return Err(format!("lock {}: OS error {error}", path.display()));
                }
            }
        }
        write_holder_pid(&mut file)?;
        Ok(HostLock { file })
    }

    /// An OS-held exclusive byte-range lock on the gate region of the lock
    /// file. The OS releases the lock when the holding process exits or
    /// dies, so a crashed test binary can never wedge the suite.
    #[cfg(target_os = "windows")]
    pub(super) struct HostLock {
        file: std::fs::File,
    }

    /// The locked gate region is the first byte of the file.
    #[cfg(target_os = "windows")]
    const GATE_LEN: u32 = 1;
    /// PID record location, outside the gate region so contenders can read
    /// it while the holder's gate lock is in force.
    #[cfg(target_os = "windows")]
    const PID_OFFSET: u64 = 64;
    #[cfg(target_os = "windows")]
    const PID_LEN: usize = 64;

    /// Create (or open) the lock file and grow it to cover the gate and PID
    /// regions. No locks are held yet, so the writes cannot conflict.
    #[cfg(target_os = "windows")]
    fn open_lock_file(path: &std::path::Path) -> Result<std::fs::File, String> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, GetLastError};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_ALWAYS,
        };

        let wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(path.as_os_str())
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 path; the share
        // flags let every live binary open the same file.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!("open {}: OS error {}", path.display(), unsafe {
                GetLastError()
            }));
        }
        // SAFETY: the handle was created above and is owned exclusively.
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        if file.metadata().map_err(|error| error.to_string())?.len() < PID_OFFSET + PID_LEN as u64 {
            file.set_len(PID_OFFSET + PID_LEN as u64)
                .map_err(|error| error.to_string())?;
        }
        Ok(file)
    }

    /// One non-blocking `LockFileEx` attempt on the 1-byte gate.
    #[cfg(target_os = "windows")]
    fn try_lock(file: &std::fs::File) -> Result<(), u32> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        // SAFETY: `overlapped` is zeroed (offset 0, no event); the file
        // handle is valid for the duration of the call.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                GATE_LEN,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(unsafe { GetLastError() })
        }
    }

    /// Overwrite the PID record at [`PID_OFFSET`]. Runs after the gate lock
    /// is held; the record region is never locked, so this write cannot
    /// conflict with any other process's gate lock.
    #[cfg(target_os = "windows")]
    fn write_holder_pid(file: &mut std::fs::File) -> Result<(), String> {
        use std::io::{Seek, SeekFrom, Write};

        let record = format!("{:<width$}\n", std::process::id(), width = PID_LEN - 1);
        file.seek(SeekFrom::Start(PID_OFFSET))
            .map_err(|error| error.to_string())?;
        file.write_all(record.as_bytes())
            .map_err(|error| error.to_string())?;
        file.flush().map_err(|error| error.to_string())
    }

    /// Best-effort read of the holder's PID from the record region, which is
    /// outside the gate lock and therefore readable while the lock is held.
    #[cfg(target_os = "windows")]
    fn read_holder_pid() -> Option<u32> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(lock_path()).ok()?;
        file.seek(SeekFrom::Start(PID_OFFSET)).ok()?;
        let mut buf = [0u8; PID_LEN];
        let n = file.read(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        let digits: String = text
            .trim()
            .trim_end_matches(' ')
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }

    #[cfg(target_os = "windows")]
    fn contended_error(path: &std::path::Path, wait: Duration) -> String {
        let holder = read_holder_pid()
            .map(|pid| format!(" (pid {pid})"))
            .unwrap_or_default();
        format!(
            "another live e2e process{holder} holds the shared host lock {}; the fixed \
             default NAT subnet (10.77.0.0/24) and the host journal state would collide, \
             so this run refuses to proceed (waited {wait:?})",
            path.display()
        )
    }

    #[cfg(target_os = "windows")]
    impl Drop for HostLock {
        fn drop(&mut self) {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            use windows_sys::Win32::System::IO::OVERLAPPED;

            // SAFETY: the gate region is exactly what was locked; the
            // handle is still valid (the File closes afterwards).
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            unsafe {
                UnlockFileEx(
                    self.file.as_raw_handle() as HANDLE,
                    0,
                    GATE_LEN,
                    0,
                    &mut overlapped,
                );
            }
        }
    }

    /// `create_new` with age-based stale detection. The live tests only run
    /// on Windows; this is a compile-and-run honest fallback for other
    /// targets.
    #[cfg(not(target_os = "windows"))]
    pub(super) async fn acquire(wait: Duration) -> Result<HostLock, String> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let path = lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create e2e lock dir {}: {error}", parent.display()))?;
        }
        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(HostLock { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if is_stale(&path) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() >= wait {
                        return Err(format!(
                            "another live e2e process holds the shared host lock {}; \
                             refusing to run concurrently (waited {wait:?})",
                            path.display()
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => {
                    return Err(format!("lock {}: {error}", path.display()));
                }
            }
        }
    }

    /// A lock file left by a process that died without removing it.
    #[cfg(not(target_os = "windows"))]
    const STALE_AFTER: Duration = Duration::from_secs(10 * 60);

    #[cfg(not(target_os = "windows"))]
    pub(super) struct HostLock {
        path: std::path::PathBuf,
    }

    #[cfg(not(target_os = "windows"))]
    fn is_stale(path: &std::path::Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        let Ok(modified) = metadata.modified() else {
            return false;
        };
        std::time::SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age >= STALE_AFTER)
    }

    #[cfg(not(target_os = "windows"))]
    impl Drop for HostLock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
/// Owned VM handle that tears the guest down when dropped, so an assertion
/// panic cannot leak the compute system, HNS network, or VHDX until the next
/// run's stale-session recovery. Mirrors `ChildGuard` in
/// `runtime_isolation.rs`.
///
/// Explicit tests call [`VmGuard::shutdown`] (the ordered, awaited cleanup);
/// on panic the guard's `Drop` runs the hypervisor's synchronous journaled
/// fallback (terminate the compute system, delete the HNS network, remove
/// VHDX files) and ignores its errors.
pub struct VmGuard {
    vm: Option<VM>,
}

impl VmGuard {
    /// Wrap a launched VM.
    pub fn new(vm: VM) -> Self {
        Self { vm: Some(vm) }
    }

    /// Run the ordered, awaited shutdown now. Consumes the VM; the guard
    /// becomes inert so `Drop` is a no-op.
    pub async fn shutdown(&mut self) -> E2eResult<()> {
        if let Some(vm) = self.vm.take() {
            vm.shutdown().await?;
        }
        Ok(())
    }

    /// Take the VM out of the guard (the caller owns teardown from here).
    pub fn take(&mut self) -> Option<VM> {
        self.vm.take()
    }
}

impl Deref for VmGuard {
    type Target = VM;

    fn deref(&self) -> &Self::Target {
        self.vm
            .as_ref()
            .expect("VmGuard holds its VM until shutdown")
    }
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        drop(self.vm.take());
    }
}

/// Materialize fixture kernel/rootfs sources into concrete artifact paths,
/// mirroring the launch-side composition (kernel first, then rootfs with
/// kernel module merge). Tests need this when they require the real
/// materialized paths (e.g. child helper binaries) instead of launching a VM.
pub async fn materialize_image(
    kernel: &Kernel,
    rootfs: &Rootfs,
) -> E2eResult<(std::path::PathBuf, std::path::PathBuf)> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let kernel = ::kernel::materialize(kernel, &cancel)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("kernel materialization failed: {error:?}"))
        })?;
    let rootfs = ::rootfs::materialize(rootfs, &cancel)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("rootfs materialization failed: {error:?}"))
        })?;
    let rootfs_path = match kernel.modules {
        Some(modules) => ::rootfs::merge_modules(rootfs.file_ref, modules, &cancel)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("kernel module merge failed: {error:?}"))
            })?,
        None => rootfs.file_ref.path(),
    };
    Ok((kernel.kernel, rootfs_path))
}

/// Fixture kernel + rootfs sources for Jyth-compatible guests. The kernel is
/// the pinned [`Kernel::default()`] (one immutable OCI manifest digest, see
/// `kernel::DEFAULT_KERNEL_OCI_REFERENCE`); [`materialize_image`] turns the
/// sources into concrete artifacts when a test needs the real paths.
pub fn linuxkit_image(rootfs: impl Into<String>) -> (Kernel, Rootfs) {
    (Kernel::default(), Rootfs::new(Link::image(rootfs)))
}

/// Default Alpine fixture sources.
pub fn alpine_image() -> (Kernel, Rootfs) {
    linuxkit_image(ALPINE_ROOTFS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host lock must be exclusive (a second live acquisition is refused
    /// with a clear error), released on drop, and reacquirable afterwards.
    /// Exercises the same OS byte-range lock the live binaries contend on,
    /// without touching HCS.
    #[tokio::test]
    async fn host_lock_is_exclusive_and_reacquirable() {
        let first = host_lock::acquire(Duration::from_millis(100))
            .await
            .expect("first acquisition must succeed");
        let contended = host_lock::acquire(Duration::from_millis(300)).await;
        let message = match contended {
            Err(message) => message,
            Ok(_) => panic!("a second live acquisition must be refused"),
        };
        assert!(
            message.contains("refuses to proceed"),
            "the refusal must be a clear error: {message}"
        );
        drop(first);
        let reacquired = host_lock::acquire(Duration::from_secs(5)).await;
        assert!(
            reacquired.is_ok(),
            "the lock must be reacquirable after the holder drops it"
        );
    }
}
