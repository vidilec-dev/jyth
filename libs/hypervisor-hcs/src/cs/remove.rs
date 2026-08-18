use crate::error::HcsError;
use crate::{
    ext::HcsTerminateComputeSystem, operation::hcs_operation, operation::hcs_operation_sync,
};
use error_stack::Report;
#[cfg(feature = "tracing")]
use tracing::instrument;

#[cfg_attr(feature = "tracing", instrument(skip(cs), level = "debug"))]
pub(crate) async fn remove_compute_system(
    cs: crate::cs::ComputeSystem,
) -> Result<String, Report<HcsError>> {
    // HCS termination is an async lifecycle operation here. The callback-driven
    // `hcs_operation` path registers a real HCS completion callback so the
    // operation does not consume a blocking-worker thread and does not contend
    // for the 30-second `SYNC_OPERATION_TIMEOUT_MS` budget used by `Drop`.
    let handle = crate::cs::SendHandle(cs.handle);
    let doc_str = hcs_operation(move |op| unsafe {
        HcsTerminateComputeSystem(handle.as_raw(), op, std::ptr::null())
    })
    .await?;
    doc_str
        .ok_or_else(|| Report::new(HcsError::ComputeSystemTerminate))
        .map_err(|e| e.attach("HcsTerminateComputeSystem returned null"))
}

/// Synchronous variant of [`remove_compute_system`].
///
/// Drives `HcsTerminateComputeSystem` to completion on the calling thread
/// via [`hcs_operation_sync`] — no tokio runtime is involved, so this is
/// safe to call from `Drop` implementations, `spawn_blocking` workers, or
/// any other plain synchronous context (see `hcs_operation_sync` for the
/// full discussion of when this matters).
///
/// The `SendHandle` wrapper is retained for parity with the async variant
/// even though `hcs_operation_sync` does not require `F: Send`; keeping the
/// same shape makes the two functions obviously equivalent.
#[cfg_attr(feature = "tracing", instrument(skip(cs), level = "debug"))]
pub(crate) fn remove_compute_system_sync(
    cs: crate::cs::ComputeSystem,
) -> Result<String, Report<HcsError>> {
    let handle = crate::cs::SendHandle(cs.handle);
    let doc_str = hcs_operation_sync(move |op| unsafe {
        HcsTerminateComputeSystem(handle.as_raw(), op, std::ptr::null())
    })?;
    doc_str
        .ok_or_else(|| Report::new(HcsError::ComputeSystemTerminate))
        .map_err(|e| e.attach("HcsTerminateComputeSystem returned null"))
}
