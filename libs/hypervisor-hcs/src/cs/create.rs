use crate::cs::{ComputeSystem, bounded_join};
use crate::error::HcsError;
use crate::{
    core::ToWide,
    ext::{HCS_SYSTEM, HcsCreateComputeSystem},
    operation::hcs_operation_sync,
};
use error_stack::Report;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(crate) async fn create_compute_system(
    id: &Uuid,
    conf: &str,
    token: &CancellationToken,
) -> Result<ComputeSystem, Report<HcsError>> {
    let id = *id;
    let conf = conf.to_owned();
    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                // Entry-only check: `hcs_operation_sync` is one blocking
                // call, so mid-call cancellation is impossible; the worker
                // bails before any HCS call is made.
                if token.is_cancelled() {
                    return Err(Report::new(HcsError::OperationSyncFailed)
                        .attach("operation cancelled".to_string()));
                }
                create_compute_system_sync(&id, &conf)
            }
        }),
        token,
        |error| Report::new(HcsError::OperationSyncFailed).attach(error.to_string()),
        Report::new(HcsError::OperationSyncFailed).attach("operation cancelled".to_string()),
    )
    .await
    .and_then(|result| result)
}

fn create_compute_system_sync(id: &Uuid, conf: &str) -> Result<ComputeSystem, Report<HcsError>> {
    let mut sys: HCS_SYSTEM = std::ptr::null_mut();

    let wide_id = id.to_string().to_wide();
    let wide_conf = conf.to_wide();
    let _ = hcs_operation_sync(|op| unsafe {
        HcsCreateComputeSystem(
            wide_id.as_ptr(),
            wide_conf.as_ptr(),
            op,
            std::ptr::null(),
            &mut sys,
        )
    })
    .map_err(|e| {
        e.attach(HcsError::ComputeSystemCreate)
            .attach(format!("config: {conf}"))
    })?;
    if sys.is_null() {
        return Err(Report::new(HcsError::ComputeSystemCreate));
    }

    Ok(ComputeSystem { handle: sys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    /// A pre-cancelled token makes the blocking closure bail at entry: the
    /// operation fails fast with `OperationSyncFailed` + "operation cancelled"
    /// without calling into HCS (spec capability `blocking-cancellation`).
    #[tokio::test]
    async fn cancelled_token_returns_operation_cancelled_fast() {
        let token = CancellationToken::new();
        token.cancel();

        let result = create_compute_system(&Uuid::new_v4(), "{}", &token).await;
        assert!(result.is_err(), "a cancelled create must fail");
        let err = result.err().expect("checked above");
        assert!(
            matches!(err.current_context(), HcsError::OperationSyncFailed),
            "expected OperationSyncFailed, got: {err:#}"
        );
        assert!(err.frames().any(|f| {
            f.downcast_ref::<String>()
                .is_some_and(|s| s.contains("operation cancelled"))
        }));
    }
}
