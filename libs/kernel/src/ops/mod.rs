pub(crate) mod extract_kernel;
pub(crate) mod extract_modules;

#[cfg(test)]
mod tests;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use image_core::ops::error::OperationError;
use image_core::storage::{file_ref::FileRef, link_ref::LinkRef};

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub(crate) async fn extract_kernel(
    path: &str,
    src: &FileRef,
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    extract_kernel::extract_kernel(path, src, dst, token).await
}

#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
pub(crate) async fn extract_modules(
    src: &FileRef,
    dst: &LinkRef,
    token: &CancellationToken,
) -> Result<Option<FileRef>, Report<OperationError>> {
    extract_modules::extract_modules(src, dst, token).await
}
