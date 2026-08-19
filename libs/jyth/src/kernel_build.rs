//! Public custom-kernel tooling entry point.
//!
//! [`compile_kernel`] compiles a custom kernel specification through the
//! same compiler adapter and kernel cache used by
//! [`crate::builder::VmBuilder`] at launch,
//! and returns the host path of the cached bzImage. The `kernel-builder`
//! CLI calls this entry point and copies the returned cached artifact to its
//! `--output`; the entry point never launches a final target VM after the
//! custom kernel is ready.

use std::path::PathBuf;

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use kernel::{CustomKernelSpec, KernelError};

use crate::build::kernel_compile::JythKernelCompiler;
use crate::error::{ApiError, ApiResult};

/// Compile `spec` through the shared custom kernel cache and return the
/// cached bzImage path. A cache hit performs no VM launch; a miss launches
/// one bootstrap VM.
pub async fn compile_kernel(spec: CustomKernelSpec) -> ApiResult<PathBuf> {
    let (path, _) = compile_kernel_with_status(spec).await?;
    Ok(path)
}

/// Like [`compile_kernel`], but reports whether the returned bzImage was
/// served from the custom cache (the CLI reports this to the operator).
pub async fn compile_kernel_with_status(spec: CustomKernelSpec) -> ApiResult<(PathBuf, bool)> {
    let kernel = kernel::Kernel::from(spec);
    let compiler = JythKernelCompiler::new(std::env::temp_dir())
        .map_err(|error| Report::new(ApiError::Build).attach(error.to_string()))?;
    // Fresh cancellation root for this operation: the drop guard cancels it
    // when the operation ends, so a still-running blocking worker bails at
    // its next check.
    let cancel = CancellationToken::new();
    let _cancel_guard = cancel.clone().drop_guard();
    let (materialized, served_from_cache) =
        kernel::materialize_with_outcome(&kernel, &compiler, &cancel)
            .await
            .map_err(|error: Report<KernelError>| error.change_context(ApiError::Build))?;
    Ok((materialized.kernel, served_from_cache))
}
