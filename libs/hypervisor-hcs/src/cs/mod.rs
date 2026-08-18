use crate::core::ToWide;
use crate::error::HcsError;
use crate::ext::{GENERIC_ALL, HCS_SYSTEM, HcsCloseComputeSystem, HcsOpenComputeSystem};
use error_stack::Report;
use tokio_util::sync::CancellationToken;

pub(crate) mod create;
#[cfg(test)]
pub(crate) mod list;
pub(crate) mod remove;
pub(crate) mod start;

/// Bounded grace given to a cancelled `spawn_blocking` worker to observe its
/// token and unwind before the join abandons the handle. Abort alone cannot
/// stop a worker thread, so the worker exits through its own
/// `is_cancelled()` checks within this window.
pub(crate) const CANCELLATION_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Await a `spawn_blocking` join, racing the cancellation token (spec
/// capability `blocking-cancellation`). When the token is cancelled first,
/// the worker gets a bounded [`CANCELLATION_GRACE`] to observe it and finish;
/// beyond that the handle is abandoned (abort alone cannot stop a worker
/// thread) and `cancelled` is returned. `map_join` converts a join failure
/// into `E`.
pub(crate) async fn bounded_join<T, E>(
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

pub(crate) struct ComputeSystem {
    handle: HCS_SYSTEM,
}
impl ComputeSystem {
    pub(crate) fn from_id(id: &str) -> Result<Self, Report<HcsError>> {
        let mut sys: HCS_SYSTEM = std::ptr::null_mut();
        let wide_id = id.to_wide();
        let hr = unsafe { HcsOpenComputeSystem(wide_id.as_ptr(), GENERIC_ALL, &mut sys) };
        if hr != 0 {
            return Err(Report::new(HcsError::ComputeSystemOpen)
                .attach(format!("HRESULT 0x{:08X}", hr as u32)));
        }
        if sys.is_null() {
            return Err(Report::new(HcsError::ComputeSystemOpen)
                .attach("HcsOpenComputeSystem returned null"));
        }

        Ok(Self { handle: sys })
    }
}

impl Drop for ComputeSystem {
    fn drop(&mut self) {
        unsafe {
            HcsCloseComputeSystem(self.handle);
        }
    }
}
unsafe impl Send for ComputeSystem {}
unsafe impl Sync for ComputeSystem {}

/// `Send` wrapper around a raw HCS handle for a bounded operation running on
/// a blocking HCS operation. Raw pointers are `!Send` by default in Rust,
/// even when (like here) the HCS API is thread-safe; the newtype carries the
/// same invariant that `ComputeSystem`'s own `unsafe impl Send` already
/// establishes. Accessed only via `as_raw()` so a `move` closure necessarily
/// captures the `SendHandle` (which is `Send`), not a copy of the inner
/// `*mut c_void` (which is not).
pub(crate) struct SendHandle(pub(crate) HCS_SYSTEM);
unsafe impl Send for SendHandle {}

impl SendHandle {
    pub(crate) fn as_raw(&self) -> HCS_SYSTEM {
        self.0
    }
}
