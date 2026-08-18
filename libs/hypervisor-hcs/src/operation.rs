use crate::error::HcsError;
use crate::{
    core::ToOptionalString,
    ext::{
        HCS_E_OPERATION_PENDING, HCS_OPERATION, HCS_OPERATION_COMPLETION, HcsCloseOperation,
        HcsCreateOperation, HcsGetOperationResult, HcsWaitForOperationResult,
    },
};
use error_stack::Report;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
#[cfg(feature = "tracing")]
use tracing::instrument;

/// Maximum time a synchronous best-effort cleanup operation may block.
///
/// The synchronous path is used by unconditional teardown (`Drop` of `Vm`,
/// journaled fallback) so a missing HCS completion callback cannot keep the
/// host process alive forever. Async lifecycle operations (`Start`,
/// `Terminate`-via-`close`) use the callback-driven `hcs_operation` path and
/// are not subject to this floor; their synchronization is the HCS completion
/// event delivered to the registered callback.
pub(crate) const SYNC_OPERATION_TIMEOUT_MS: u32 = 30_000;

#[must_use]
pub(crate) struct HcsOperation(HCS_OPERATION);

impl HcsOperation {
    /// Create an `HCS_OPERATION` with no completion callback registered.
    ///
    /// Used by [`hcs_operation_sync`], which drives the operation to
    /// completion via [`HcsWaitForOperationResult`]. Per the HCS API
    /// contract, `NULL` is a legal value for both the context and the callback:
    /// the operation still completes internally, so the wait primitive is the
    /// point of synchronization.
    pub(crate) fn new_without_callback() -> Result<Self, Report<HcsError>> {
        match unsafe { HcsCreateOperation(std::ptr::null(), None) } {
            op if op.is_null() => Err(Report::new(HcsError::OperationCreate)),
            op => Ok(Self(op)),
        }
    }

    /// Create an `HCS_OPERATION` whose completion is signalled to `context`
    /// through `callback`. Used by [`hcs_operation`]; the context pointer is
    /// owned by the callback/future pair via `Arc::into_raw` and reclaimed by
    /// `Arc::from_raw` exactly once (see [`hcs_callback`]).
    fn new_with_callback(
        context: *const std::ffi::c_void,
        callback: HCS_OPERATION_COMPLETION,
    ) -> Result<Self, Report<HcsError>> {
        match unsafe { HcsCreateOperation(context, Some(callback)) } {
            op if op.is_null() => Err(Report::new(HcsError::OperationCreate)),
            op => Ok(Self(op)),
        }
    }

    pub(crate) fn raw(&self) -> HCS_OPERATION {
        self.0
    }
}

// SAFETY: an `HCS_OPERATION` is a Win32 HANDLE-like opaque pointer. The HCS
// API is documented as thread-safe: the same operation handle may be driven
// from any thread. The context pointer embedded inside the operation is
// caller-supplied and `Send`-safe by construction in `hcs_operation` (the
// `Arc<Mutex<Option<oneshot::Sender>>>` it carries is `Send + Sync`).
unsafe impl Send for HcsOperation {}
unsafe impl Sync for HcsOperation {}

impl Drop for HcsOperation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { HcsCloseOperation(self.0) };
        }
    }
}

/// Shared state between the async future returned by [`hcs_operation`] and
/// the HCS completion callback. The HCS contract is that the callback fires
/// *at most once*; either the callback or the future may observe the
/// completion first. Whichever fires first calls
/// `Option::take(&mut *lock).map(|s| { let _ = s.send(()); })`; the other
/// then sees `None` and no-ops. The `Arc` keeps the allocation alive until
/// *both* sides have observed the state and dropped their strong references.
///
/// This replaces the pre-`c9bd8f0` design that used
/// `ManuallyDrop<Box<oneshot::Sender>>` with ambiguous single-owner
/// semantics — the future was responsible for dropping it on cancel, but
/// HCS still held a raw pointer to it, producing a use-after-free if the
/// cancel raced with the callback. The `Arc<Mutex<Option<…>>>` formulation
/// eliminates that race: the allocation survives until both sides have
/// decremented the refcount, and `Option::take` makes first-writer-wins
/// semantics explicit.
type AsyncCallbackState = Mutex<Option<oneshot::Sender<()>>>;

/// HCS callback context pointer carried across an await boundary.
///
/// The pointee is always the `Send + Sync` [`AsyncCallbackState`] allocation
/// handed to `Arc::into_raw`; the pointer value is only ever converted back
/// through `Arc::from_raw` (see [`hcs_callback`] and [`hcs_operation`]), so
/// moving the pointer itself between threads is safe. This mirrors the
/// documented Send-safety of the HCS operation handle.
struct CallbackContext(*const std::ffi::c_void);

// SAFETY: the pointee is `Arc<AsyncCallbackState>` (`Send + Sync`), and the
// pointer is never dereferenced directly — only `Arc::from_raw` consumes it,
// which is safe from any thread.
unsafe impl Send for CallbackContext {}

/// HCS completion callback invoked once when the operation finishes (or when
/// the operation is closed by [`HcsOperation::Drop`]).
///
/// # Safety
/// `context` must be a pointer previously produced by
/// `Arc::into_raw` on an `Arc<AsyncCallbackState>`. We reclaim the strong
/// reference with `Arc::from_raw`, take the `Sender` if still present, send
/// `()` to wake the waiting future, and let the `Arc` decrement the refcount
/// at the end of the callback. HCS must not invoke this callback again after
/// it has returned for the same operation handle.
unsafe extern "system" fn hcs_callback(_operation: HCS_OPERATION, context: *mut std::ffi::c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller (`hcs_operation`) handed HCS a pointer produced by
    // `Arc::into_raw` on an `Arc<AsyncCallbackState>`. `Arc::from_raw` is the
    // inverse and reclaims exactly one strong reference.
    let state: Arc<AsyncCallbackState> =
        unsafe { Arc::from_raw(context as *const AsyncCallbackState) };
    if let Some(sender) = state.lock().ok().and_then(|mut guard| guard.take()) {
        // A closed receiver drops the message silently; the receiving future
        // observes cancellation via its `await` returning `Err`.
        let _ = sender.send(());
    }
    // Drop the `Arc`, which decrements the second strong reference. If the
    // future has already taken its clone, the allocation is freed; otherwise
    // the future's clone keeps it alive until the future itself is dropped.
    drop(state);
}

/// Run an HCS steering-API call to completion on the calling async runtime,
/// registering a real completion callback so the operation does not consume a
/// blocking-worker thread and does not contend for the 30-second
/// [`SYNC_OPERATION_TIMEOUT_MS`] budget used by `Drop`.
///
/// Returns `Ok(Option<String>)` carrying the operation's result document
/// (which may be `None` for operations that produce no document), or `Err`
/// when:
///   * `HcsCreateOperation` returned a null handle (`OperationCreate`),
///   * the steering API returned a non-zero immediate HRESULT other than
///     `HCS_E_OPERATION_PENDING` (`OperationFailed`),
///   * the future was cancelled before the callback fired
///     (`OperationCallbackMissing`), or
///   * `HcsGetOperationResult` returned a failure HRESULT
///     (`OperationResult`, with the HRESULT attached).
///
/// The `operation` closure is invoked with the raw `HCS_OPERATION` handle;
/// it must return the `HRESULT` reported by the underlying HCS call. A
/// non-zero immediate HRESULT is propagated immediately unless it equals
/// `HCS_E_OPERATION_PENDING` (`0x80370120`), which HCS uses as "the work
/// has been queued, please wait for the callback."
///
/// `F` is required to be `Send` because the closure is constructed on the
/// caller's thread and the HCS callback that may race with the future's
/// cancellation fires on an arbitrary HCS worker thread.
#[cfg_attr(feature = "tracing", instrument(skip(operation), level = "trace"))]
pub(crate) async fn hcs_operation<F>(operation: F) -> Result<Option<String>, Report<HcsError>>
where
    F: FnOnce(HCS_OPERATION) -> i32 + Send,
{
    let (tx, rx) = oneshot::channel::<()>();
    let state: Arc<AsyncCallbackState> = Arc::new(Mutex::new(Some(tx)));
    // Hand HCS one strong reference as the raw context pointer. The callback
    // reclaims it with `Arc::from_raw`. The future retains its own clone.
    let context = CallbackContext(Arc::into_raw(Arc::clone(&state)) as *const std::ffi::c_void);

    let op_guard = match HcsOperation::new_with_callback(context.0, hcs_callback) {
        Ok(guard) => guard,
        Err(error) => {
            // HCS never accepted the context pointer (the operation handle
            // is null), so the callback can never fire and nothing else will
            // reclaim the reference handed to `Arc::into_raw` above.
            drop(unsafe { Arc::from_raw(context.0 as *const AsyncCallbackState) });
            return Err(error);
        }
    };
    // The closure receives the raw `HCS_OPERATION`. The guard's `Drop` will
    // call `HcsCloseOperation` on scope exit; this is documented to cancel
    // the operation cleanly and is the standard path for both completed and
    // cancelled operations.
    let hr_immediate = operation(op_guard.raw());

    if hr_immediate != 0 && hr_immediate != HCS_E_OPERATION_PENDING {
        // The future did not race with the callback yet (the operation has
        // not been queued); recover the `Sender` so it is dropped cleanly.
        let _ = state.lock().ok().and_then(|mut guard| guard.take());
        // The steering call failed synchronously, so HCS never delivers a
        // completion callback for this operation. Close the operation first
        // (which also guarantees no callback race), then reclaim the
        // HCS-side strong reference — it would otherwise leak.
        drop(op_guard);
        drop(unsafe { Arc::from_raw(context.0 as *const AsyncCallbackState) });
        return Err(Report::new(HcsError::OperationFailed)
            .attach(format!("HRESULT 0x{:08X}", hr_immediate as u32)));
    }

    // Race the callback (`rx`) against future cancellation (`std::future`'s
    // own `Drop`). If the future is dropped here, `rx` is dropped; the
    // `state` `Arc` still has the HCS-side strong reference, the callback
    // fires when HCS completes (or never fires if `HcsCloseOperation` in
    // `HcsOperation::Drop` ran first), and the `Arc` is reclaimed cleanly.
    match rx.await {
        Ok(()) => {
            let mut result_doc: *mut u16 = std::ptr::null_mut();
            // SAFETY: `op_guard.raw()` is live until the end of this scope
            // and the operation has just completed via the callback.
            let hr = unsafe { HcsGetOperationResult(op_guard.raw(), &mut result_doc) };
            let doc_str = result_doc.to_optional_string().map_err(|error| {
                let mut report = Report::new(HcsError::OperationResult)
                    .attach(format!("HCS result document: {error}"));
                if hr != 0 {
                    report = report.attach(format!("HRESULT 0x{:08X}", hr as u32));
                }
                report
            })?;
            if hr != 0 {
                return Err(Report::new(HcsError::OperationResult)
                    .attach(format!("HRESULT 0x{:08X}", hr as u32))
                    .attach(doc_str.unwrap_or_default()));
            }
            Ok(doc_str)
        }
        Err(_) => {
            // `tx` was dropped without the callback firing first → the
            // future was cancelled while HCS still had work pending. Close
            // the operation (`HcsCloseOperation`), which is documented to
            // discard the pending operation; per the HCS contract the
            // completion callback never fires afterwards, so reclaim the
            // HCS-side strong reference here — the callback path (which
            // reclaims at `hcs_callback`) is definitively not going to run.
            // The close happens BEFORE the reclaim so the callback cannot
            // race it.
            drop(op_guard);
            drop(unsafe { Arc::from_raw(context.0 as *const AsyncCallbackState) });
            Err(Report::new(HcsError::OperationCallbackMissing)
                .attach("future was cancelled before HCS reported completion"))
        }
    }
}

/// Bounded HCS operation runner used by the synchronous fallback path
/// (`Drop` of `Vm`, journaled recovery, and any other context that cannot
/// `.await`).
///
/// Runs an HCS steering-API call to completion on the calling thread by
/// blocking on [`HcsWaitForOperationResult`] until HCS reports the operation
/// is done or the bounded synchronous fallback timeout elapses. The result
/// document, if any, is returned to the caller.
///
/// Async lifecycle operations (`Start`, async `Terminate`/`close`) register a
/// real HCS completion callback via `hcs_operation` and are not subject to
/// this floor. `Drop` and the journaled fallback keep using this synchronous
/// primitive so a dropped `Vm` cannot block forever.
///
/// Because this path needs neither a `oneshot` channel nor a tokio runtime
/// to drive a future, it is safe to invoke from any thread, including:
///
///   * a plain (non-async) caller context,
///   * inside a `tokio::task::spawn_blocking` worker without risking the
///     nested-runtime deadlock that `Runtime::block_on` would incur on a
///     tokio worker thread, and
///   * from inside a `Drop` impl, where panicking on a runtime acquisition
///     failure would abort the program.
///
/// The `operation` closure is invoked with the raw `HCS_OPERATION` handle; it
/// must return the `HRESULT` reported by the underlying HCS call (e.g.
/// `HcsTerminateComputeSystem`). A non-zero HRESULT
/// returned synchronously by the steering API is interpreted as a failure
/// and propagated immediately, with one exception:
/// `HCS_E_OPERATION_PENDING` (`0x80370120`) is treated as
/// "the work has been queued, please wait" and the function proceeds to
/// `HcsWaitForOperationResult`. (Some HCS steering APIs return this value
/// instead of `S_OK` when an operation is dispatched asynchronously.)
///
/// `F` is *not* required to be `Send` here, since nothing is moved across
/// threads — the operation is created, driven, and consumed on the calling
/// thread.
#[cfg_attr(feature = "tracing", instrument(skip(operation), level = "trace"))]
pub fn hcs_operation_sync<F>(operation: F) -> Result<Option<String>, Report<HcsError>>
where
    F: FnOnce(HCS_OPERATION) -> i32,
{
    let op_guard = HcsOperation::new_without_callback()?;

    let hr_immediate = operation(op_guard.raw());

    if hr_immediate != 0 && hr_immediate != HCS_E_OPERATION_PENDING {
        return Err(Report::new(HcsError::OperationFailed)
            .attach(format!("HRESULT 0x{:08X}", hr_immediate as u32)));
    }

    let mut result_doc: *mut u16 = std::ptr::null_mut();
    // SAFETY: `op_guard.raw()` is a live `HCS_OPERATION` created just above
    // and not yet closed (the `HcsOperation` Drop guard owns it until the
    // end of this scope). `result_doc` is a usable out-pointer. HCS either
    // writes the result document or reports that the bounded wait elapsed.
    let hr = unsafe {
        HcsWaitForOperationResult(op_guard.raw(), SYNC_OPERATION_TIMEOUT_MS, &mut result_doc)
    };

    let doc_str = result_doc.to_optional_string().map_err(|error| {
        Report::new(HcsError::OperationSyncFailed).attach(format!("HCS result document: {error}"))
    })?;

    if hr != 0 {
        if hr == HCS_E_OPERATION_PENDING {
            return Err(Report::new(HcsError::OperationSyncFailed).attach(format!(
                "HCS operation did not complete within {SYNC_OPERATION_TIMEOUT_MS} ms"
            )));
        }
        return Err(Report::new(HcsError::OperationSyncFailed).attach(format!(
            "HRESULT 0x{:08X} (detail: {})",
            hr as u32,
            doc_str.as_deref().unwrap_or("Unknown Error")
        )));
    }

    Ok(doc_str)
}

#[cfg(test)]
mod tests {
    use super::SYNC_OPERATION_TIMEOUT_MS;

    #[test]
    fn synchronous_operation_wait_is_bounded() {
        assert_eq!(SYNC_OPERATION_TIMEOUT_MS, 30_000);
        assert_ne!(SYNC_OPERATION_TIMEOUT_MS, u32::MAX);
    }
}
