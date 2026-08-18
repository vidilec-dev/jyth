//! Root filesystem materialization.
//!
//! Resolves a rootfs source link (local file, in-memory bytes, HTTP
//! resource, or OCI image) into one complete, uncompressed CPIO `newc`
//! archive with exactly one `TRAILER!!!` entry, published through the
//! shared image store. OCI images have their layers materialized and
//! flattened; raw archives are validated structurally. The crate also owns
//! the module merge that folds an extracted kernel module fragment into a
//! derived rootfs artifact.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: rootfs.
//!
//! **Responsibility**: root filesystem materialization and kernel-module
//! merge.
//!
//! **Allowed dependencies**: image-core (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: VM launch, HCS state, guest commands, scheduling,
//! and boot handshake.

use std::path::PathBuf;

use error_stack::Report;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use image_core::{Link, storage::file_ref::FileRef};

pub(crate) mod ops;
pub(crate) mod service;

use crate::service::{RootfsService, change_rootfs};

/// A root filesystem source to materialize.
#[derive(Debug, Clone)]
pub struct Rootfs {
    /// The external rootfs source.
    pub source: Link,
}

impl Rootfs {
    /// Create a rootfs source.
    pub fn new(source: Link) -> Self {
        Self { source }
    }
}

/// A materialized root filesystem: one complete, uncompressed CPIO archive.
#[derive(Debug)]
pub struct MaterializedRootfs {
    /// The materialized rootfs artifact.
    pub file_ref: FileRef,
}

/// Failures returned while materializing a root filesystem.
#[derive(Debug, Error)]
pub enum RootfsError {
    /// The root filesystem input could not be materialized.
    #[error("could not materialize the root filesystem input")]
    Materialization,
}

/// Materialize `rootfs` through the default service (default store plus
/// default source resolvers).
pub async fn materialize(
    rootfs: &Rootfs,
    token: &CancellationToken,
) -> Result<MaterializedRootfs, Report<RootfsError>> {
    let service = RootfsService::with_defaults().map_err(change_rootfs)?;
    let file_ref = service.build_rootfs(rootfs.source.clone(), token).await?;
    Ok(MaterializedRootfs { file_ref })
}

/// Merge a cached module fragment into a derived rootfs artifact, returning
/// the merged rootfs path. The source rootfs link is never overwritten: two
/// kernels may share one base rootfs but require different `/lib/modules`
/// trees.
pub async fn merge_modules(
    base: FileRef,
    modules: FileRef,
    token: &CancellationToken,
) -> Result<PathBuf, Report<RootfsError>> {
    let service = RootfsService::with_defaults().map_err(change_rootfs)?;
    service.merge_modules(base, modules, token).await
}
