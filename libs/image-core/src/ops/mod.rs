pub mod blueprint;
pub mod cpio;
pub mod decompress;
pub mod error;
pub mod flatten;
pub mod format;
pub mod io;
pub mod load;
pub mod registry;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    artifact::{compression::ArtifactCompression, link::ArtifactLink, ty::ArtifactType},
    digest::ExpectedDigest,
    ops::error::OperationError,
    storage::{blueprint::Blueprint, file_ref::FileRef, link_ref::LinkRef},
    timing::{OpTimer, SourceKind},
};

pub use decompress::StagedDecompress;

/// Absolute bound on a single archive entry materialized in memory (64 MiB).
///
/// `newc` sizes are `u32` (up to 4 GiB per entry); a malicious or corrupt
/// layer must fail with a typed [`OperationError::InvalidCpio`] instead of
/// making the host allocate gigabytes per entry.
pub const MAX_IN_MEMORY_ENTRY_BYTES: u32 = 64 * 1024 * 1024;

/// Bounded grace given to a cancelled `spawn_blocking` worker to observe its
/// token and unwind before the join abandons the handle. Abort alone cannot
/// stop a worker thread, so the worker exits through its own
/// `is_cancelled()` checks within this window.
pub const CANCELLATION_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Await a `spawn_blocking` join, racing the operation's cancellation token
/// (spec capability `blocking-cancellation`). When the token is cancelled
/// first, the worker gets a bounded [`CANCELLATION_GRACE`] to observe it and
/// finish; beyond that the handle is abandoned (abort alone cannot stop a
/// worker thread) and `cancelled` is returned. `map_join` converts a join
/// failure into `E`.
pub async fn bounded_join<T, E>(
    handle: tokio::task::JoinHandle<T>,
    token: &CancellationToken,
    map_join: impl FnOnce(tokio::task::JoinError) -> E,
    cancelled: E,
) -> Result<T, E> {
    tokio::pin!(handle);
    tokio::select! {
        result = handle.as_mut() => result.map_err(map_join),
        _ = token.cancelled() => match tokio::time::timeout(CANCELLATION_GRACE, handle.as_mut()).await {
            Ok(result) => result.map_err(map_join),
            Err(_) => Err(cancelled),
        },
    }
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn decompress(
    entry: FileRef,
    token: &CancellationToken,
) -> Result<StagedDecompress, Report<OperationError>> {
    decompress::decompress(entry, token).await
}

/// Convert an uncompressed TAR artifact into a CPIO `newc` artifact,
/// preserving the entry types and metadata required to assemble a rootfs in
/// a later `flatten` stage. See `docs/implementation-plan/ops/04-into-cpio.md`
/// for the full contract.
#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn into_cpio(
    entry: FileRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    // Precondition: the entry must be an uncompressed TAR.
    if entry.artifact_type != ArtifactType::ContainerTar {
        return Err(OperationError::UnsupportedArtifact.report().attach(format!(
            "expected ArtifactType::ContainerTar, got {:?}",
            entry.artifact_type
        )));
    }
    if entry.artifact_compression != ArtifactCompression::None {
        return Err(OperationError::UnsupportedCompression
            .report()
            .attach(format!(
                "expected ArtifactCompression::None, got {:?}",
                entry.artifact_compression
            )));
    }

    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                cpio::convert(&entry)
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn flatten(
    src: &[FileRef],
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    flatten::flatten(src, dst, token).await
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn load(
    link: &ArtifactLink,
    link_ref: &LinkRef,
    expected_digest: Option<&ExpectedDigest>,
    expected_link_digest: crate::digest::LinkDigest,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    load::load(link, link_ref, expected_digest, expected_link_digest, token).await
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub async fn blueprint(
    link_ref: &LinkRef,
    link: ArtifactLink,
    extract: Option<PathBuf>,
    expected_link_digest: crate::digest::LinkDigest,
) -> Result<Blueprint, Report<OperationError>> {
    let timer = OpTimer::start("blueprint")
        .source(SourceKind::from(&link))
        .namespace("blueprint");
    match blueprint::blueprint(link_ref, link, extract, expected_link_digest).await {
        Ok(value) => Ok(value),
        Err(error) => {
            timer.fail(format!("{error:#}"));
            Err(error)
        }
    }
}
