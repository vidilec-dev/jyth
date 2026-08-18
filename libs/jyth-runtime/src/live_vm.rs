//! The runtime-owned live VM type (WP7, live_vm.rs).
//!
//! Owns the backend instance, the guest client, the dispatcher lifecycle,
//! the scheduler handle, the lifecycle observer, and the classified disk
//! evidence. Consuming [`shutdown`](LiveVm::shutdown) implements the ordered
//! shutdown flow; `Drop` retains the synchronous best-effort fallback.

use std::path::PathBuf;
use std::sync::Arc;

use hypervisor_api::VmInstance;
use protocol::{Command, Event, SessionCapability};
use scheduler::ScheduledAction;
use uuid::Uuid;

use crate::client::GuestClient;
use crate::error::{RuntimeError, map_client_error};
use crate::observer::{VmFinish, VmLifecycle, VmPhase};
use crate::ports::CommandEndpoint;
use error_stack::Report;
use vm_model::disk::{AttachedDisk, DiskRetention};

/// Structured disk disposition retained by a running VM. A log line alone
/// is not sufficient notification — the VM keeps every warning so callers
/// can observe lifecycle reclassifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmWarning {
    /// An existing host path converted an ephemeral request into a
    /// retained disk: the file was attached without formatting and its
    /// effective retention is [`DiskRetention::Persistent`].
    DiskReusedAsPersistent {
        /// Host path of the reused backing file.
        host_path: PathBuf,
        /// The retention the caller requested (`Ephemeral`).
        requested: DiskRetention,
        /// The retention actually applied (`Persistent`).
        effective: DiskRetention,
    },
}

/// A live connection to a booted Jyth guest.
///
/// A live VM owns the guest command dispatcher, the scheduler handle, and
/// the underlying backend instance. Dropping it performs synchronous
/// best-effort cleanup; call [`LiveVm::shutdown`] for the ordered, awaited
/// cleanup path.
pub struct LiveVm {
    instance: Option<Box<dyn VmInstance>>,
    client: Arc<GuestClient>,
    observer: Option<VmLifecycle>,
    scheduler: Option<scheduler::RunHandle>,
    attached_disks: Vec<AttachedDisk>,
    warnings: Vec<VmWarning>,
    capability: Arc<SessionCapability>,
    command_endpoint: CommandEndpoint,
}

impl Drop for LiveVm {
    fn drop(&mut self) {
        if let Some(scheduler) = &self.scheduler {
            scheduler.cancel();
        }
        self.client.abort_all();
        // If `shutdown()` already took the handle out, this is a no-op.
        // Otherwise dropping it runs the backend's synchronous journaled
        // fallback; it never spawns an asynchronous cleanup task.
        if let Some(instance) = self.instance.take() {
            drop(instance);
            if let Some(observer) = &self.observer {
                observer.finished(VmFinish::Dropped);
            }
        }
    }
}

impl LiveVm {
    /// Assemble the live VM: start the scheduler when any action was
    /// declared, retain the classified disk evidence, and keep the session
    /// capability for the facade's stream binds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        instance: Box<dyn VmInstance>,
        client: Arc<GuestClient>,
        actions: Vec<ScheduledAction>,
        observer: Option<VmLifecycle>,
        attached_disks: Vec<AttachedDisk>,
        warnings: Vec<VmWarning>,
        capability: Arc<SessionCapability>,
        command_endpoint: CommandEndpoint,
    ) -> Self {
        // Empty declarations produce no actions, so no scheduler task is
        // started at all (preserving the historical no-op behavior).
        let scheduler = if actions.is_empty() {
            None
        } else {
            Some(scheduler::Scheduler::new().start(actions))
        };
        Self {
            instance: Some(instance),
            client,
            observer,
            scheduler,
            attached_disks,
            warnings,
            capability,
            command_endpoint,
        }
    }

    /// The backing hypervisor VM identifier. Returns [`Uuid::nil`] after
    /// [`shutdown`](Self::shutdown) consumed the backend instance.
    pub fn uuid(&self) -> Uuid {
        match &self.instance {
            Some(instance) => instance.identity(),
            None => Uuid::nil(),
        }
    }

    /// The session capability used for the authenticated TCP endpoint.
    pub fn capability(&self) -> &Arc<SessionCapability> {
        &self.capability
    }

    /// The effective TCP command endpoint retained from the launch `Nat`.
    /// Facade-facing accessor: the jyth composition root builds its concrete
    /// transport endpoint from this value.
    pub fn command_endpoint(&self) -> CommandEndpoint {
        self.command_endpoint
    }

    /// Borrow the typed guest client.
    pub fn client(&self) -> &GuestClient {
        &self.client
    }

    /// The classified disposition of every attached disk: host path, guest
    /// mount, origin (created by this launch vs pre-existing), and the
    /// requested/effective retention. Empty when no disk was requested, or
    /// after [`shutdown`](Self::shutdown) consumed the backend instance.
    pub fn attached_disks(&self) -> &[AttachedDisk] {
        &self.attached_disks
    }

    /// Disk lifecycle warnings retained by this VM (see [`VmWarning`]).
    pub fn warnings(&self) -> &[VmWarning] {
        &self.warnings
    }

    /// Cancel and join every scheduler task before backend cleanup begins
    /// (target shutdown flow: the live VM stops accepting new scheduled
    /// actions, then cancels and joins existing scheduler tasks).
    async fn cancel_and_join_scheduler(&mut self) {
        if let Some(handle) = &self.scheduler {
            handle.cancel();
        }
        if let Some(handle) = self.scheduler.take() {
            handle.join().await;
        }
    }

    /// Gracefully shuts the VM down and awaits exact host-side cleanup.
    ///
    /// This method consumes the VM so a logically stopped handle cannot be
    /// reused. Guest-shutdown and host-cleanup failures are both retained in
    /// the returned report; a guest failure never prevents host cleanup.
    /// The ordering copies the historical facade behavior exactly: join the
    /// scheduler, close retained processes, request the guest shutdown
    /// command, stop the dispatcher, then consume the backend instance.
    pub async fn shutdown(mut self) -> Result<(), Report<RuntimeError>> {
        self.cancel_and_join_scheduler().await;
        // Scheduler cancellation can drop RunningProcess handles. Ensure
        // their tracked ProcessClose submissions have reached the dispatcher
        // before asking the guest to shut down.
        self.client.cleanup_tasks().close_and_join().await;

        let guest_result = match self.client.request(Command::VMShutdown).await {
            Ok(Event::Shutdowned) => Ok(()),
            Ok(other) => Err(Report::new(RuntimeError::UnexpectedReply)
                .attach(format!("unexpected {} reply to VMShutdown", other.kind()))),
            Err(error) => {
                Err(
                    map_client_error(error, "VMShutdown", self.command_endpoint().address())
                        .change_context(RuntimeError::Shutdown),
                )
            }
        };
        self.client.stop_dispatcher().await;
        let host_result = match self.instance.take() {
            Some(instance) => instance
                .close()
                .await
                .map_err(|error| Report::new(RuntimeError::Hypervisor).attach(error)),
            None => Ok(()),
        };

        self.attached_disks.clear();
        match (guest_result, host_result) {
            (Ok(()), Ok(())) => {
                if let Some(observer) = &self.observer {
                    observer.finished(VmFinish::Shutdown);
                }
                Ok(())
            }
            (Err(guest), Ok(())) => {
                let message = guest.to_string();
                if let Some(observer) = &self.observer {
                    observer.failed(VmPhase::Shutdown, message);
                }
                Err(guest.change_context(RuntimeError::Shutdown))
            }
            (Ok(()), Err(host)) => {
                let message = host.to_string();
                if let Some(observer) = &self.observer {
                    observer.failed(VmPhase::Shutdown, message);
                }
                Err(host.change_context(RuntimeError::Shutdown))
            }
            (Err(guest), Err(host)) => {
                let guest_message = guest.to_string();
                let host_message = host.to_string();
                if let Some(observer) = &self.observer {
                    observer.failed(
                        VmPhase::Shutdown,
                        format!(
                            "host cleanup failed: {host_message}; guest shutdown failed: {guest_message}"
                        ),
                    );
                }
                Err(host
                    .change_context(RuntimeError::Shutdown)
                    .attach(format!("guest shutdown also failed: {guest_message}")))
            }
        }
    }
}
