//! Scheduler trigger/action packaging (moved from the jyth facade, WP7).
//!
//! The runtime packages the jyth-supplied scheduled processes and the
//! shutdown trigger into canonical [`scheduler::ScheduledAction`] values
//! over the shared guest client. The public `On` combinator API and its
//! trigger conversion remain in the jyth facade.

use std::sync::{Arc, Mutex};

use guest_client::PreparedProcess;
use scheduler::{ActionFuture, ActionResult, ScheduledAction};
use tokio_util::sync::CancellationToken;

use crate::client::GuestClient;
use crate::observer::{VmFinish, VmLifecycle, VmPhase};
use protocol::{Command, Event};

/// One scheduled guest process handed to the runtime: a boolean trigger and
/// the prepared guest process to run when the trigger resolves `true`.
pub struct ScheduledProcess {
    /// The trigger (converted from the public `On` by the facade).
    pub trigger: scheduler::Trigger,
    /// The prepared guest process description.
    pub process: PreparedProcess,
}

/// Package a scheduled guest process into a canonical action.
///
/// The engine invokes the action only after the trigger resolves `true`. A
/// `false` trigger publishes the dependency-cancelled process failure (the
/// E2E-observed contract) and the engine reports the task as cancelled.
///
/// The process is owned by a shared holder: the wrapped trigger consumes it
/// on a `false` resolution (dependency cancelled), and the action consumes
/// it on a `true` resolution (execution). Exactly one path runs, so the
/// holder is taken exactly once.
pub(crate) fn process_action(
    scheduled: ScheduledProcess,
    client: Arc<GuestClient>,
) -> ScheduledAction {
    let holder = Arc::new(Mutex::new(Some(scheduled.process)));
    let trigger = {
        let holder = holder.clone();
        Box::pin(async move {
            let resolved = scheduled.trigger.await;
            if !resolved
                && let Some(process) = holder.lock().expect("process holder").take()
                && let Some(lifecycle) = process.lifecycle
            {
                lifecycle.failed(guest_client::ProcessError::Cancelled {
                    cleanup_error: None,
                });
            }
            resolved
        })
    };
    let action = Box::new(move |_cancel: CancellationToken| -> ActionFuture {
        let holder = holder.clone();
        let client = client.clone();
        Box::pin(async move {
            let process = holder
                .lock()
                .expect("process holder")
                .take()
                .expect("process must be present after a true trigger");
            match client.run_direct(process).await {
                Ok(_) => ActionResult::success(),
                Err(error) => ActionResult::failure(error.to_string()),
            }
        })
    });
    ScheduledAction::new(trigger, action)
}

/// Package the shutdown condition into a canonical action that sends the
/// guest shutdown command and publishes the lifecycle finish.
pub(crate) fn shutdown_action(
    trigger: scheduler::Trigger,
    client: Arc<GuestClient>,
    observer: Option<VmLifecycle>,
) -> ScheduledAction {
    let action = Box::new(move |_cancel: CancellationToken| -> ActionFuture {
        let client = client.clone();
        Box::pin(async move {
            match client.request(Command::VMShutdown).await {
                Ok(Event::Shutdowned) => {
                    if let Some(observer) = observer {
                        observer.finished(VmFinish::Shutdown);
                    }
                    ActionResult::success()
                }
                Ok(other) => {
                    let message = format!("unexpected {} reply to VMShutdown", other.kind());
                    if let Some(observer) = observer {
                        observer.failed(VmPhase::Shutdown, message.clone());
                    }
                    ActionResult::failure(message)
                }
                Err(error) => {
                    let message = error.to_string();
                    if let Some(observer) = observer {
                        observer.failed(VmPhase::Shutdown, message.clone());
                    }
                    ActionResult::failure(message)
                }
            }
        })
    });
    ScheduledAction::new(trigger, action)
}
