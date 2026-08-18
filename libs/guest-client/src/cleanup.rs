use tokio::sync::mpsc;

use crate::transport::HostRequest;

/// Registry of background cleanup tasks, used to submit best-effort
/// `ProcessClose` requests from `RunningProcess::drop` and to join them
/// before an ordered VM shutdown consumes the dispatcher.
pub struct CleanupTasks {
    state: std::sync::Mutex<CleanupTaskState>,
}

struct CleanupTaskState {
    closed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl CleanupTasks {
    /// Create an empty cleanup registry.
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(CleanupTaskState {
                closed: false,
                tasks: Vec::new(),
            }),
        }
    }

    pub(crate) fn enqueue(&self, sender: mpsc::Sender<HostRequest>, request: HostRequest) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.closed {
                let _ = sender.try_send(request);
            }
            return;
        };

        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.tasks.retain(|task| !task.is_finished());
        if state.closed {
            return;
        }
        state.tasks.push(handle.spawn(async move {
            let _ = sender.send(request).await;
        }));
    }

    #[cfg(test)]
    pub(crate) fn spawn<F>(&self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = tokio::runtime::Handle::current();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.tasks.retain(|task| !task.is_finished());
        if !state.closed {
            state.tasks.push(handle.spawn(task));
        }
    }

    /// Mark the registry closed and await every submitted cleanup task. Used
    /// by the VM before the guest shutdown command so every tracked
    /// `ProcessClose` has reached the dispatcher.
    pub async fn close_and_join(&self) {
        let tasks = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };

        for task in tasks {
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                #[cfg(feature = "tracing")]
                tracing::warn!(error = %error, "cleanup task failed to join");
            }
        }
    }

    /// Abort every submitted cleanup task without awaiting. Drop-only path:
    /// synchronous best-effort fallback for an unconsumed VM.
    pub fn abort_all(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        for task in state.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Default for CleanupTasks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::RunningProcess;
    use crate::support::FakeStreams;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn dropped_process_cleanup_is_joined_before_registry_close_returns() {
        let cleanup_tasks = Arc::new(CleanupTasks::new());
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel(1);
        let uuid = uuid::Uuid::now_v7();

        drop(RunningProcess {
            uuid,
            cmd_tx,
            cleanup: cleanup_tasks.clone(),
            streams: Arc::new(FakeStreams::new(Vec::new())),
            closed: false,
        });

        cleanup_tasks.close_and_join().await;
        let request = cmd_rx
            .try_recv()
            .expect("drop cleanup should be submitted before join returns");
        assert!(matches!(
            request.cmd,
            protocol::Command::ProcessClose { uuid: request_uuid } if request_uuid == uuid
        ));
    }

    #[tokio::test]
    async fn drop_aborts_owned_cleanup_tasks() {
        let cleanup_tasks = Arc::new(CleanupTasks::new());
        let started = Arc::new(tokio::sync::Notify::new());
        let completed = Arc::new(AtomicBool::new(false));

        let started_task = started.clone();
        let completed_task = completed.clone();
        cleanup_tasks.spawn(async move {
            started_task.notify_one();
            std::future::pending::<()>().await;
            completed_task.store(true, Ordering::SeqCst);
        });
        started.notified().await;

        cleanup_tasks.abort_all();
        tokio::task::yield_now().await;
        assert!(!completed.load(Ordering::SeqCst));
    }
}
