//! Per-digest build locks for the custom kernel cache.
//!
//! Identical custom requests (same request digest) must serialize within and
//! across processes so one compilation publishes one validated artifact.
//!
//! The in-process path uses one asynchronous lock per request digest from a
//! registry that drops unused entries. The cross-process path opens one
//! `.jyth-v4/kernel/.locks/<digest>.lock` file and acquires the operating
//! system lock with [`std::fs::File::try_lock`], waiting asynchronously with
//! backoff so a waiting task stays cancellable. The file handle is held until
//! publication or terminal failure; a crashed compiler process releases the
//! OS lock automatically when the handle closes.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use error_stack::Report;
use thiserror::Error;

use image_core::{digest::LinkDigest, storage::namespace::NAMESPACES};

/// Failure category for build-lock acquisition.
#[derive(Debug, Error)]
pub enum BuildLockError {
    /// The lock file could not be created or opened.
    #[error("could not open the kernel build lock file")]
    Open,
    /// The operating-system lock could not be acquired.
    #[error("could not acquire the kernel build lock")]
    Acquire,
}

/// In-process per-digest async lock registry. Entries are held weakly so an
/// unused digest's entry disappears once no guard references it.
static IN_PROCESS_LOCKS: LazyLock<Mutex<HashMap<LinkDigest, Weak<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Acquire the per-digest build lock: first the in-process async lock, then
/// the cross-process file lock. The returned guard holds both until dropped,
/// after publication or terminal failure.
pub(crate) async fn acquire_build_lock(
    digest: LinkDigest,
) -> Result<BuildLockGuard, Report<BuildLockError>> {
    let in_process = acquire_in_process(digest).await;
    let file = acquire_cross_process(digest).await?;
    Ok(BuildLockGuard {
        _in_process: in_process,
        _file: file,
    })
}

/// One acquired build lock. Holding the `File` keeps the cross-process lock
/// alive; dropping the guard (and thus the handle) releases it.
pub(crate) struct BuildLockGuard {
    _in_process: tokio::sync::OwnedMutexGuard<()>,
    _file: File,
}

/// Acquire the in-process async lock for `digest`. The registry stores weak
/// entries, so an unused digest is removed automatically once its last guard
/// drops.
async fn acquire_in_process(digest: LinkDigest) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut registry = IN_PROCESS_LOCKS
            .lock()
            .expect("in-process lock registry poisoned");
        let strong = registry.get(&digest).and_then(Weak::upgrade);
        match strong {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                registry.insert(digest, Arc::downgrade(&lock));
                lock
            }
        }
    };
    lock.lock_owned().await
}

/// Acquire the cross-process lock: open `.jyth-v4/kernel/.locks/<digest>.lock`
/// and try-lock it with asynchronous backoff. The wait stays cancellable
/// because every backoff is an await point; aborting the task drops the
/// future and no handle is held until the lock is acquired.
async fn acquire_cross_process(digest: LinkDigest) -> Result<File, Report<BuildLockError>> {
    let locks_dir = NAMESPACES.kernel.join(".locks");
    std::fs::create_dir_all(&locks_dir).map_err(|_| BuildLockError::Open.report())?;
    let path: PathBuf = locks_dir.join(format!("{}.lock", hex_digest(&digest)));

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|_| BuildLockError::Open.report())?;

    let mut backoff = std::time::Duration::from_millis(50);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(2));
            }
            Err(std::fs::TryLockError::Error(_)) => return Err(BuildLockError::Acquire.report()),
        }
    }
}

/// Hex-encode a digest for the lock file name.
fn hex_digest(digest: &LinkDigest) -> String {
    digest.link_hash.to_hex().to_string()
}

impl BuildLockError {
    fn report(self) -> error_stack::Report<Self> {
        error_stack::Report::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hash;

    fn digest(byte: u8) -> LinkDigest {
        LinkDigest {
            link_hash: Hash::from_bytes([byte; 32]),
            file_size: 1,
        }
    }

    #[tokio::test]
    async fn identical_digests_share_one_in_process_lock() {
        let digest = digest(0x11);
        let first = acquire_in_process(digest).await;
        // A second acquisition for the same digest must wait; acquire it in a
        // spawned task and verify it cannot complete while the first is held.
        let task = tokio::spawn(async move {
            let _second = acquire_in_process(digest).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "second lock must wait");
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("second lock completes after release")
            .expect("task ok");
    }

    #[tokio::test]
    async fn unused_registry_entries_are_dropped() {
        let digest = digest(0x22);
        {
            let _guard = acquire_in_process(digest).await;
        }
        let registry = IN_PROCESS_LOCKS.lock().expect("registry");
        assert!(
            registry
                .get(&digest)
                .is_none_or(|weak| weak.strong_count() == 0),
            "unused digest entry is removed"
        );
    }

    #[tokio::test]
    async fn cross_process_lock_serializes_until_dropped() {
        let digest = digest(0x33);
        let first = acquire_cross_process(digest).await.expect("first lock");
        let task =
            tokio::spawn(async move { acquire_cross_process(digest).await.expect("second lock") });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "second process lock must wait");
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("second lock completes after release")
            .expect("task ok");
    }
}
