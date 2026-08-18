pub(crate) mod validate_cpio;

#[cfg(test)]
mod tests;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use image_core::ops::error::OperationError;
use image_core::storage::file_ref::FileRef;

/// Convert an uncompressed TAR artifact into a CPIO `newc` artifact,
/// preserving the entry types and metadata required to assemble a rootfs in
/// a later `flatten` stage. See `docs/implementation-plan/ops/04-into-cpio.md`
/// for the full contract.
#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
#[cfg_attr(not(test), allow(dead_code))] // exercised by ops::tests::into_cpio
pub(crate) async fn into_cpio(
    entry: FileRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    image_core::ops::into_cpio(entry, token).await
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub(crate) async fn validate_cpio(
    entry: &FileRef,
    token: &CancellationToken,
) -> Result<(), Report<OperationError>> {
    validate_cpio::validate_cpio(entry, token).await
}
