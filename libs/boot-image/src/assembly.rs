//! Top-level assembly: overlay validated entries onto a prepared rootfs and
//! publish the merged, cache-derived rootfs CPIO.
//!
//! The caller must hand over *prepared* inputs: the materialized kernel
//! path, the complete base rootfs CPIO path, and overlay entries whose
//! content is already resolved to bytes. External acquisition (OCI, HTTP,
//! local, and byte sources) and host-side process executable compilation
//! happen before this crate is called.

use std::path::PathBuf;

use error_stack::{Report, ResultExt};
use tokio_util::sync::CancellationToken;

use crate::cache;
use crate::overlay::{
    ResolvedFile, RootfsMetadata, ValidatedDir, ValidatedOverlay, cached_rootfs_is_valid,
    init_overlay_file, merge_rootfs, overlay_to_cpio, rootfs_dir, rootfs_manifest_key,
    validate_entries,
};
use crate::{BootImageError, GuestOverlayEntry};

/// The prepared boot artifacts of one assembly: the kernel path (echoed
/// from the prepared input) and the merged, cached rootfs CPIO path.
pub struct PreparedBootArtifacts {
    /// The prepared kernel path.
    pub kernel: PathBuf,
    /// The merged rootfs CPIO artifact (cached under the derived cache).
    pub rootfs: PathBuf,
}

/// Prepare the kernel and rootfs boot artifacts for a launch.
///
/// All overlay entry paths are validated before the init binary is built or
/// the derived cache is touched. The hardcoded pid-1 stage (`/init`, from
/// the `init` crate) is appended after user entries so it always wins as
/// pid 1. The merged rootfs is cached under a canonical manifest key; a
/// valid cache hit returns the cached artifact without rebuilding it.
pub async fn prepare_boot_artifacts(
    kernel: PathBuf,
    rootfs: PathBuf,
    entries: Vec<GuestOverlayEntry>,
    token: &CancellationToken,
) -> Result<PreparedBootArtifacts, Report<BootImageError>> {
    // Validate every user path before building `/init` or touching the
    // derived cache.
    let ValidatedOverlay { files, dirs } = validate_entries(entries).map_err(Report::new)?;

    let mut resolved: Vec<ResolvedFile> = files;
    // Hardcoded pid-1 stage: the `init` crate is the initramfs's
    // init process. Emitted at `/init` (executable) regardless of any
    // user-supplied files, so it always wins as pid 1.
    let init_bytes = crate::init::resolve_init_binary(token)
        .await
        .map_err(|error| error.change_context(BootImageError::InitBuild))?;
    resolved.push(init_overlay_file(init_bytes));
    resolved.sort_by(|a, b| a.path.cmp(&b.path));

    prepare_inner(kernel, rootfs, resolved, dirs).await
}

async fn prepare_inner(
    kernel: PathBuf,
    base_rootfs: PathBuf,
    resolved: Vec<ResolvedFile>,
    dirs: Vec<ValidatedDir>,
) -> Result<PreparedBootArtifacts, Report<BootImageError>> {
    let base_bytes = std::fs::read(&base_rootfs)
        .change_context(BootImageError::InvalidHostPath { path: base_rootfs })?;
    // `resolved` and `dirs` were sorted by GuestPath before this function was
    // called. Both the manifest and CPIO emitter consume those same vectors.
    let key = rootfs_manifest_key(&base_bytes, &resolved, &dirs)
        .change_context(BootImageError::Overlay)?;
    let rootfs_dir = rootfs_dir().change_context(BootImageError::Cache)?;
    let out_path = rootfs_dir.join(format!("{key}.cpio"));
    let metadata_path = rootfs_dir.join(format!("{key}.json"));

    // Cache hit: the completion record and the artifact must both be valid.
    // A corrupt or incomplete record is a safe miss, never a build failure.
    if let Ok(metadata) = cache::read_json::<RootfsMetadata>(&metadata_path)
        && metadata.schema_version == cache::CACHE_SCHEMA_VERSION
        && metadata.key == key
        && cache::artifact_matches(&out_path, &metadata.artifact).unwrap_or(false)
        && cached_rootfs_is_valid(&out_path, metadata.artifact.size)
            .change_context(BootImageError::Cache)?
    {
        return Ok(PreparedBootArtifacts {
            kernel,
            rootfs: out_path,
        });
    }

    let overlay = overlay_to_cpio(&resolved, &dirs).change_context(BootImageError::Overlay)?;
    let merged = merge_rootfs(&base_bytes, &overlay).change_context(BootImageError::Overlay)?;
    cache::atomic_write(&out_path, &merged).change_context(BootImageError::Cache)?;
    let metadata = RootfsMetadata {
        schema_version: cache::CACHE_SCHEMA_VERSION,
        key,
        artifact: cache::artifact_metadata(&out_path).change_context(BootImageError::Cache)?,
    };
    // The metadata record is the completion sentinel and is published only
    // after the complete CPIO has been atomically written.
    cache::atomic_write_json(&metadata_path, &metadata).change_context(BootImageError::Cache)?;

    Ok(PreparedBootArtifacts {
        kernel,
        rootfs: out_path,
    })
}
