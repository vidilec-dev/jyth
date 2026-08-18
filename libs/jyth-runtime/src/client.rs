//! The runtime-owned typed guest client facade.
//!
//! Wraps the guest-client `Dispatcher`, `Client`, `GuestFiles`,
//! `CleanupTasks`, and the direct-process runner behind one handle the
//! launcher, the scheduler actions, the live VM, and the facade all share.

use std::sync::{Arc, Mutex};

use guest_client::{
    CleanupTasks, GuestFiles, HostRequest, PreparedProcess, PreparedProcessBuilder, ProcessError,
    ProcessExit, StreamTransport,
};
use protocol::{Command, Event};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// One typed guest client for a live VM.
///
/// Holds the command sender, the stream transport, the retained-process
/// cleanup registry, and the dispatcher lifecycle (cancel token and joined
/// supervisor task). The scheduler actions and the live VM share the client
/// behind an `Arc`.
pub struct GuestClient {
    cmd_tx: mpsc::Sender<HostRequest>,
    files: GuestFiles,
    streams: Arc<dyn StreamTransport>,
    cleanup_tasks: Arc<CleanupTasks>,
    dispatcher_cancel: CancellationToken,
    event_loop_task: Mutex<Option<JoinHandle<()>>>,
}

impl GuestClient {
    /// Construct the client over an already-spawned dispatcher.
    pub fn new(
        cmd_tx: mpsc::Sender<HostRequest>,
        streams: Arc<dyn StreamTransport>,
        dispatcher_cancel: CancellationToken,
        event_loop_task: JoinHandle<()>,
    ) -> Self {
        Self {
            files: GuestFiles::new(cmd_tx.clone()),
            streams,
            cleanup_tasks: Arc::new(CleanupTasks::new()),
            cmd_tx,
            dispatcher_cancel,
            event_loop_task: Mutex::new(Some(event_loop_task)),
        }
    }

    /// Borrow the dispatcher command sender.
    pub fn sender(&self) -> &mpsc::Sender<HostRequest> {
        &self.cmd_tx
    }

    /// Borrow the guest stream transport.
    pub fn streams(&self) -> &Arc<dyn StreamTransport> {
        &self.streams
    }

    /// Borrow the retained-process cleanup registry.
    pub fn cleanup_tasks(&self) -> &Arc<CleanupTasks> {
        &self.cleanup_tasks
    }

    /// Borrow the guest file and directory operations.
    pub fn files(&self) -> &GuestFiles {
        &self.files
    }

    /// Send a single command and await its framed `Event` reply, bounded by
    /// the guest-client request timeout.
    pub async fn request(&self, cmd: Command) -> Result<Event, guest_client::GuestClientError> {
        guest_client::Client::request_with_sender(self.cmd_tx.clone(), cmd).await
    }

    /// Execute a prepared guest process through the direct-process runner.
    pub async fn run_direct(&self, process: PreparedProcess) -> Result<ProcessExit, ProcessError> {
        guest_client::run_direct_process(
            self.cmd_tx.clone(),
            self.streams.clone(),
            self.cleanup_tasks.clone(),
            process,
        )
        .await
    }

    /// Begin building a guest process over this client's dispatcher.
    pub fn process(&self, path: &str) -> PreparedProcessBuilder {
        PreparedProcessBuilder::new(
            path.to_string(),
            self.cmd_tx.clone(),
            self.cleanup_tasks.clone(),
            self.streams.clone(),
        )
    }

    /// Cancel the dispatcher and join its supervisor task.
    pub async fn stop_dispatcher(&self) {
        self.dispatcher_cancel.cancel();
        if let Some(task) = self
            .event_loop_task
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
            && let Err(error) = task.await
            && !error.is_cancelled()
        {
            #[cfg(feature = "tracing")]
            tracing::warn!(error = %error, "command dispatcher failed to join");
        }
    }

    /// Synchronous best-effort dispatcher shutdown for `Drop` fallback.
    pub(crate) fn abort_all(&self) {
        self.cleanup_tasks.abort_all();
        self.dispatcher_cancel.cancel();
        if let Some(task) = self
            .event_loop_task
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
        {
            // Drop cannot await the dispatcher supervisor, but aborting its
            // JoinHandle drops the dispatcher and its owned JoinSet, which
            // aborts every in-flight transport task synchronously.
            task.abort();
        }
    }
}
