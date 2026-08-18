//! Thin facade over the `boot-image` crate.
//!
//! Guest boot-artifact assembly (overlay path validation, conflict
//! detection, init binary compilation, CPIO merge, and derived caching) is
//! owned by the `boot-image` crate and reached through the runtime's boot
//! artifact provider. This module performs only the host-side preparation
//! that contract requires: materializing Rust process executables to bytes
//! (`executables`), mapping the configured files and dirs into host-neutral
//! overlay entries (`entries`), and materializing the configured kernel and
//! rootfs sources into a boot-ready image before overlay assembly (internal
//! `materialize` module). Errors
//! keep the historical Jyth
//! build-stage variant set and messages so the public `ApiError::Build`
//! context is unchanged.

pub(crate) mod entries;
pub(crate) mod executables;
pub(crate) mod kernel_compile;
pub(crate) mod materialize;

use boot_image::GuestPathReason;
use error_stack::Report;
use tokio_util::sync::CancellationToken;

use crate::build::materialize::materialize_image;
use crate::builder::VmBuilder;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BuildError {
    #[error("no kernel was configured")]
    MissingKernel,
    #[error("no root filesystem was configured")]
    MissingRootfs,
    #[error("failed to materialize the VM image")]
    ImageBuild,
    #[error("failed to build the Jyth overlay")]
    Overlay,
    #[error("the launch build was cancelled")]
    Cancelled,
    #[error("invalid guest path {path:?}: {reason}")]
    InvalidGuestPath {
        path: String,
        reason: GuestPathReason,
    },
    #[error("overlay {kind} has no path")]
    MissingOverlayPath { kind: &'static str },
}

/// The validated launch inputs the runtime's boot artifact provider needs:
/// the materialized kernel/rootfs sources and the host-neutral overlay
/// entries.
pub(crate) struct BuildInput {
    pub(crate) kernel_source: std::path::PathBuf,
    pub(crate) rootfs_source: std::path::PathBuf,
    pub(crate) overlay_entries: Vec<jyth_runtime::BootOverlayEntry>,
}

pub(crate) trait Build {
    async fn build(self, token: &CancellationToken) -> Result<BuildInput, Report<BuildError>>;
}

impl Build for VmBuilder {
    async fn build(mut self, token: &CancellationToken) -> Result<BuildInput, Report<BuildError>> {
        let kernel = self
            .take_kernel()
            .ok_or_else(|| Report::new(BuildError::MissingKernel))?;
        let (kernel_source, rootfs) = match materialize_image(kernel, self.take_rootfs(), token)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                #[cfg(feature = "tracing")]
                tracing::error!(chain = %format!("{error:#}"), "VM image materialization failed");
                return Err(error.change_context(BuildError::ImageBuild));
            }
        };
        let rootfs_source = rootfs.ok_or_else(|| Report::new(BuildError::MissingRootfs))?;

        let overlay_entries =
            entries::overlay_entries(self.files_ref(), self.dirs_ref(), token).await?;

        Ok(BuildInput {
            kernel_source,
            rootfs_source,
            overlay_entries,
        })
    }
}
