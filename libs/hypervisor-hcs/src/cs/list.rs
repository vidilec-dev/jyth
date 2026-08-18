use crate::core::ToWide;
use crate::cs::bounded_join;
use crate::error::HcsError;
use crate::ext::HcsEnumerateComputeSystems;
use crate::operation::hcs_operation_sync;
use error_stack::Report;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Query {
    pub owners: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct ComputeSystem {
    #[serde(rename = "Id")]
    #[allow(dead_code)]
    pub(crate) id: String,
}

pub(crate) async fn list_compute_systems(
    query: &Query,
    token: &CancellationToken,
) -> Result<Vec<ComputeSystem>, Report<HcsError>> {
    let query = serde_json::to_string(query)
        .map_err(|e| Report::new(e).change_context(HcsError::Serialize))?;

    let wide_query = query.to_wide();
    let doc_str = bounded_join(
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
                hcs_operation_sync(|op| unsafe {
                    HcsEnumerateComputeSystems(wide_query.as_ptr(), op)
                })
            }
        }),
        token,
        |error| Report::new(HcsError::OperationSyncFailed).attach(error.to_string()),
        Report::new(HcsError::OperationSyncFailed).attach("operation cancelled".to_string()),
    )
    .await??;

    let entries: Vec<ComputeSystem> = serde_json::from_str(&doc_str.ok_or_else(|| {
        Report::new(HcsError::Enumeration).attach("HcsEnumerateComputeSystems returned null")
    })?)
    .map_err(|e| Report::new(e).change_context(HcsError::Deserialize))?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_list_compute_systems() {
        if crate::hyperv::ensure_hyperv_admin_membership().is_err() {
            println!("Skipping test: not running as Hyper-V admin");
            return;
        }

        let query = Query {
            owners: vec!["VMMS".to_string(), "CmService".to_string()],
        };

        let result = list_compute_systems(&query, &CancellationToken::new()).await;
        let ids = result.expect("Failed to list compute systems");
        assert!(
            !ids.is_empty(),
            "Expected at least one compute system for active owners, but got an empty list",
        );
    }

    /// A pre-cancelled token makes the blocking closure bail at entry: the
    /// operation fails fast with `OperationSyncFailed` + "operation cancelled"
    /// without calling into HCS (spec capability `blocking-cancellation`).
    #[tokio::test]
    async fn cancelled_token_returns_operation_cancelled_fast() {
        let query = Query {
            owners: vec!["VMMS".to_string()],
        };
        let token = CancellationToken::new();
        token.cancel();

        let result = list_compute_systems(&query, &token).await;
        assert!(result.is_err(), "a cancelled enumeration must fail");
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
