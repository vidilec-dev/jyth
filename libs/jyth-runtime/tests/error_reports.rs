//! Facade report-completeness tests for the runtime error boundary.
//!
//! Cancel-timeout-policy slice S2: every `RequestTimedOut` report exposed at
//! the runtime facade must carry operation, budget, and endpoint attachments
//! (spec capability `error-report-completeness`, facade scenario).

use jyth_runtime::{RuntimeError, map_client_error};

fn endpoint() -> std::net::SocketAddr {
    "127.0.0.1:8000".parse().unwrap()
}

/// A `RequestTimedOut` report at the runtime facade carries the operation
/// name, the 5s request-class budget, and the command endpoint it was
/// talking to, alongside the stable `RuntimeError` category.
#[test]
fn request_timed_out_report_carries_operation_budget_and_endpoint() {
    let report = map_client_error(
        guest_client::GuestClientError::RequestTimedOut,
        "VMShutdown",
        endpoint(),
    );

    assert!(matches!(
        report.current_context(),
        RuntimeError::RequestTimedOut
    ));
    assert!(
        report.frames().any(|f| f
            .downcast_ref::<String>()
            .is_some_and(|s| s.contains("operation=VMShutdown"))),
        "the report must carry the operation attachment: {report:?}"
    );
    assert!(
        report.frames().any(|f| f
            .downcast_ref::<String>()
            .is_some_and(|s| s.contains("budget=5s"))),
        "the report must carry the 5s budget attachment: {report:?}"
    );
    assert!(
        report.frames().any(|f| f
            .downcast_ref::<String>()
            .is_some_and(|s| s.contains("endpoint=127.0.0.1:8000"))),
        "the report must carry the endpoint attachment: {report:?}"
    );
}

/// Triangulation: a different call site (operation + endpoint) must be
/// reflected in the attachments — the values flow from the caller, not a
/// hardcoded constant.
#[test]
fn request_timed_out_report_reflects_the_calling_operation_and_endpoint() {
    let report = map_client_error(
        guest_client::GuestClientError::RequestTimedOut,
        "file_read",
        "10.0.0.5:8000".parse().unwrap(),
    );

    assert!(matches!(
        report.current_context(),
        RuntimeError::RequestTimedOut
    ));
    assert!(
        report.frames().any(|f| f
            .downcast_ref::<String>()
            .is_some_and(|s| s.contains("operation=file_read"))),
        "the report must carry the call-site operation: {report:?}"
    );
    assert!(
        report.frames().any(|f| f
            .downcast_ref::<String>()
            .is_some_and(|s| s.contains("endpoint=10.0.0.5:8000"))),
        "the report must carry the call-site endpoint: {report:?}"
    );
}
