use crate::error::HcsError;
use error_stack::Report;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncBufReadExt;
use uuid::Uuid;

use sha2::Digest;

use crate::cs::remove::remove_compute_system_sync;
use crate::cs::{
    ComputeSystem, create::create_compute_system, remove::remove_compute_system,
    start::start_compute_system,
};
use crate::hyperv::ensure_hyperv_admin_membership;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

/// One logical Jyth runtime session: the explicit owner of a session
/// journal. Opening a session reconciles stale sessions once per open and
/// creates the process's current journal. The redb writer lock protects live
/// sessions, so multiple sessions may be opened concurrently (each gets its
/// own reconcile pass).
pub struct Session {
    journal: Arc<crate::journal::SessionJournal>,
}

impl Session {
    /// Open a session under an explicit state root: prepare the root, run
    /// stale-session reconciliation, then create the current session journal.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, Report<HcsError>> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|error| {
            Report::new(HcsError::Journal)
                .attach(format!("create state root {}: {error}", root.display()))
        })?;
        crate::journal::reject_reparse_components(&root)?;
        let session_id = Uuid::now_v7();
        let current_path = crate::journal::session_path(&root, session_id);
        reconcile_stale_sessions(&root, &current_path).await?;
        let journal = crate::journal::SessionJournal::create_current(root, session_id)?;
        Ok(Self { journal: Arc::new(journal) })
    }

    /// Open a session under the resolved default state root (`JYTH_STATE_DIR`
    /// override or the production `ProgramData` sessions dir).
    pub async fn open_default() -> Result<Self, Report<HcsError>> {
        let root = crate::journal::resolve_state_root()?;
        Self::open(root).await
    }

    pub(crate) fn journal(&self) -> &Arc<crate::journal::SessionJournal> {
        &self.journal
    }
}

/// Aggregated outcome of one cleanup pass, reported by the recovery summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CleanupSummary {
    /// Resources transitioned to `Removed` by a successful cleanup.
    recovered: usize,
    /// Resources already absent, transitioned to `Removed` idempotently.
    absent: usize,
    /// Genuine cleanup failures (retry-able or terminal).
    failed: usize,
    /// Resources transitioned to `Abandoned` this pass.
    abandoned: usize,
}

/// Structured record of one genuine cleanup failure. The same fields build
/// the persisted `last_error` (self-describing inventory) and the structured
/// log event.
struct CleanupFailure {
    kind: &'static str,
    operation: &'static str,
    identity: String,
    cause: String,
}

async fn reconcile_stale_sessions(
    root: &Path,
    current_path: &Path,
) -> Result<(), Report<HcsError>> {
    let mut summary = CleanupSummary::default();
    for path in crate::journal::session_paths(root)? {
        if path == current_path {
            continue;
        }
        let Some(stale) = crate::journal::SessionJournal::try_open_existing(&path)? else {
            #[cfg(feature = "tracing")]
            tracing::debug!(path = %path.display(), "[JOURNAL] session is still locked; skipping recovery");
            continue;
        };
        #[cfg(feature = "tracing")]
        tracing::debug!(path = %stale.path().display(), "[JOURNAL] recovering unlocked session");

        let records = stale.all_vms()?;
        for record in records {
            if record.is_complete() {
                stale.remove_vm(record.vm_id)?;
                continue;
            }
            let vm_id = record.vm_id;
            let outcome = cleanup_record_async_with(
                &stale,
                vm_id,
                CleanupResources::empty(),
                |id| async move { remove_compute_system_by_id(&id).await },
                |network_id, network_name, endpoint_id, endpoint_name| {
                    crate::hns::delete_exact(network_id, network_name, endpoint_id, endpoint_name)
                },
                remove_disk,
                &mut summary,
            )
            .await;
            if let Err(_error) = outcome {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    %vm_id,
                    error = %_error,
                    "[JOURNAL] record remains pending after cleanup pass"
                );
            }
        }

        let incomplete = stale
            .all_vms()?
            .into_iter()
            .any(|record| !record.is_complete());
        let retains_inventory = stale.has_abandoned()?;
        drop(stale);
        if !incomplete && !retains_inventory {
            std::fs::remove_file(&path).map_err(|error| {
                Report::new(HcsError::Journal).attach(format!(
                    "remove recovered session database {}: {error}",
                    path.display()
                ))
            })?;
        }
    }
    #[cfg(feature = "tracing")]
    tracing::info!(
        recovered = summary.recovered,
        absent = summary.absent,
        failed = summary.failed,
        abandoned = summary.abandoned,
        "[JOURNAL] stale-session recovery complete"
    );
    Ok(())
}

struct CleanupResources {
    system: Option<ComputeSystem>,
    #[cfg(target_os = "windows")]
    network: Option<crate::hns::NetworkState>,
}

impl CleanupResources {
    fn empty() -> Self {
        Self {
            system: None,
            #[cfg(target_os = "windows")]
            network: None,
        }
    }
}

/// Owns resources created while `Vm::from_conf` is still fallible. The
/// journal is authoritative once each side effect is recorded, while the
/// identity list covers the narrow window between creating a disk and
/// committing its observed identity.
struct ProvisioningGuard {
    journal: Arc<crate::journal::SessionJournal>,
    vm_id: Uuid,
    #[cfg(target_os = "windows")]
    network: Option<crate::hns::NetworkState>,
    unjournaled_disks: Vec<(PathBuf, crate::journal::FileIdentity)>,
    armed: bool,
}

impl ProvisioningGuard {
    fn new(journal: Arc<crate::journal::SessionJournal>, vm_id: Uuid) -> Self {
        Self {
            journal,
            vm_id,
            #[cfg(target_os = "windows")]
            network: None,
            unjournaled_disks: Vec::new(),
            armed: true,
        }
    }

    fn disarm(mut self) -> CleanupResources {
        self.armed = false;
        CleanupResources {
            system: None,
            #[cfg(target_os = "windows")]
            network: self.network.take(),
        }
    }
}

impl Drop for ProvisioningGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let resources = CleanupResources {
            system: None,
            #[cfg(target_os = "windows")]
            network: self.network.take(),
        };
        if let Err(_error) = cleanup_record_sync(&self.journal, self.vm_id, resources) {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                vm_id = %self.vm_id,
                error = %_error,
                "[JOURNAL] provisioning rollback incomplete"
            );
        }

        for (path, expected) in &self.unjournaled_disks {
            if !path.exists() {
                continue;
            }
            match crate::journal::file_identity(path) {
                Ok(actual) if &actual == expected => {
                    if let Err(_error) = std::fs::remove_file(path) {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            path = %path.display(),
                            error = %_error,
                            "[JOURNAL] unjournaled disk rollback failed"
                        );
                    }
                }
                Ok(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        path = %path.display(),
                        "[JOURNAL] refusing to remove replaced unjournaled disk"
                    )
                }
                Err(_error) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        path = %path.display(),
                        error = %_error,
                        "[JOURNAL] cannot verify unjournaled disk during rollback"
                    )
                }
            }
        }
    }
}
/// A Windows Hypervisor Platform VM handle and its host-side bus connection.
pub struct Vm {
    /// Identifier assigned to the HCS compute system.
    pub id: Uuid,
    system: Mutex<Option<ComputeSystem>>,
    /// Named-pipe path used by the guest-agent bus.
    pub bus_pipe_name: Option<String>,
    /// Snapshot of the COM1 bus-pipe DACL taken from the server handle at
    /// creation time. A single-instance pipe cannot be reopened for
    /// inspection once the guest worker connects, so this is the only
    /// reliable proof of the deny-by-default descriptor with the exact
    /// per-VM identity ACE. `None` only when the snapshot itself failed
    /// (the descriptor was still applied). Read by the `#[ignore]`d live
    /// test `com1_pipe_dacl_contains_vm_identity_after_launch`.
    #[allow(dead_code)] // live-test proof of the applied descriptor
    pub(crate) bus_pipe_aces: Option<Vec<crate::security::ParsedAce>>,
    /// Server endpoint used to accept the guest-agent bus connection.
    pub bus_pipe_server: std::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeServer>>,
    /// HNS network + endpoint handles created by Task I-3 when the
    /// caller asked for a NIC via [`Vm::from_conf`]'s `network` argument.
    /// `None` for the offline default. Torn down in `Drop` *after* the
    /// HCS compute system is removed (the underlying VM has to release
    /// its grip on the endpoint before `HcnDeleteEndpoint` will
    /// succeed). Best-effort delete on a network in use just logs a
    /// warning — no panic.
    #[cfg(target_os = "windows")]
    network: Mutex<Option<crate::hns::NetworkState>>,
    /// Classified disposition of every disk attached to this VM, in
    /// attachment order. Populated during materialization (before the HCS
    /// compute system exists) and exposed to callers through
    /// [`Vm::attached_disks`]; the journal record remains authoritative
    /// for cleanup.
    attached_disks: Vec<vm_model::disk::AttachedDisk>,
    journal: Arc<crate::journal::SessionJournal>,
    cleanup_completed: bool,
}
impl Drop for Vm {
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(id = ?self.id), level = "debug"))]
    fn drop(&mut self) {
        if self.cleanup_completed {
            return;
        }

        let journal = self.journal.clone();
        let vm_id = self.id;
        let resources = self.take_cleanup_resources();

        if let Err(_error) = cleanup_record_sync(&journal, vm_id, resources) {
            #[cfg(feature = "tracing")]
            tracing::warn!(vm_id = %self.id, error = %_error, "[JOURNAL] synchronous Drop cleanup incomplete");
        }
    }
}
impl Vm {
    fn take_cleanup_resources(&mut self) -> CleanupResources {
        let system = self.system.lock().ok().and_then(|mut guard| guard.take());
        #[cfg(target_os = "windows")]
        let network = self.network.lock().ok().and_then(|mut guard| guard.take());
        CleanupResources {
            system,
            #[cfg(target_os = "windows")]
            network,
        }
    }

    /// Take ownership of the pending guest-agent bus endpoint, if present.
    /// A poisoned lock (a panicked task holding it) yields `None`, matching
    /// the crate's other poison-tolerant paths.
    pub fn take_bus_pipe(&self) -> Option<tokio::net::windows::named_pipe::NamedPipeServer> {
        self.bus_pipe_server
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }

    /// The classified disposition of every attached disk, in attachment
    /// order: host path, guest mount, origin, and requested/effective
    /// retention. Empty when no disk was requested.
    pub fn attached_disks(&self) -> &[vm_model::disk::AttachedDisk] {
        &self.attached_disks
    }
}

impl Vm {
    /// Create an HCS VM within an explicit runtime session.
    pub async fn new_with_session(
        session: &Session,
        kernel: &Path,
        initrd: &Path,
        mem: u64,
        cpu: u32,
        cmdline: &str,
        network: Option<&vm_model::network::Nat>,
        disks: Option<&[vm_model::disk::DiskSpec]>,
    ) -> Result<Self, Report<HcsError>> {
        let conf = crate::conf::Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(mem)
            .vcpus(cpu)
            .parms(cmdline);

        Vm::from_conf(session, conf, network, disks).await
    }
    pub fn uuid(&self) -> Uuid {
        self.id
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(id = ?self.id), level = "debug"))]
    pub async fn start(&self) -> Result<(), Report<HcsError>> {
        // Take the system out of the mutex so we don't hold a
        // non-Send `MutexGuard` across the `.await`; put it back
        // when done. (The `stop` impl does the same, just without
        // putting it back.)
        let sys = {
            let mut guard = self
                .system
                .lock()
                .map_err(|e| Report::new(HcsError::ComputeSystemStart).attach(e.to_string()))?;
            guard.take()
        };
        let Some(sys) = sys else {
            return Err(Report::new(HcsError::ComputeSystemStart)
                .attach("VM already stopped or not initialized"));
        };
        let res = start_compute_system(&sys).await;
        // Put it back regardless; on error the caller can retry/still
        // call `stop`, which itself takes it out again.
        if let Ok(mut guard) = self.system.lock() {
            *guard = Some(sys);
        }
        res?;
        self.journal.update_vm(self.id, |record| {
            if record.phase == crate::journal::VmResourcePhase::Planned {
                record.phase = crate::journal::VmResourcePhase::Starting;
            }
        })?;
        Ok(())
    }

    pub fn mark_published(&self) -> Result<(), Report<HcsError>> {
        self.journal.update_vm(self.id, |record| {
            record.phase = crate::journal::VmResourcePhase::Published;
            record.published = true;
            record.last_error = None;
            for disk in &mut record.disks {
                disk.published = true;
                // READY is the initialization acknowledgement: the host
                // marks created disks initialized only after verifying the
                // READY proof (the builder calls mark_published after that).
                if disk.initialization_requested {
                    disk.initialization_acknowledged = true;
                }
            }
        })
    }

    pub async fn close(mut self) -> Result<(), Report<HcsError>> {
        let journal = self.journal.clone();
        let vm_id = self.id;
        let resources = self.take_cleanup_resources();
        let result = cleanup_record_async(&journal, vm_id, resources).await;
        if result.is_ok() {
            self.cleanup_completed = true;
        }
        result
    }
}

async fn cleanup_record_async(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    resources: CleanupResources,
) -> Result<(), Report<HcsError>> {
    cleanup_record_async_with(
        journal,
        vm_id,
        resources,
        |id| async move { remove_compute_system_by_id(&id).await },
        |network_id, network_name, endpoint_id, endpoint_name| {
            crate::hns::delete_exact(network_id, network_name, endpoint_id, endpoint_name)
        },
        remove_disk,
        &mut CleanupSummary::default(),
    )
    .await
}

/// Core async cleanup pass. The compute/network/disk operations are injected
/// so the failure modes are unit-testable without a live HCS host; the
/// production wrapper passes the real implementations. `summary` accumulates
/// the per-resource outcome counts for the recovery summary line.
async fn cleanup_record_async_with<ComputeHook, ComputeFut, NetworkHook, DiskHook>(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    mut resources: CleanupResources,
    remove_compute: ComputeHook,
    delete_network: NetworkHook,
    remove_disk: DiskHook,
    summary: &mut CleanupSummary,
) -> Result<(), Report<HcsError>>
where
    ComputeHook: Fn(String) -> ComputeFut,
    ComputeFut: std::future::Future<Output = Result<(), Report<HcsError>>>,
    NetworkHook: Fn(Option<&str>, &str, Option<&str>, &str) -> Result<(), Report<HcsError>>,
    DiskHook: Fn(Uuid, &crate::journal::DiskResource) -> Result<(), Report<HcsError>>,
{
    journal.update_vm(vm_id, |record| {
        record.phase = crate::journal::VmResourcePhase::CleanupPending;
        record.cleanup_attempts = record.cleanup_attempts.saturating_add(1);
        record.last_error = None;
    })?;

    let mut failures = Vec::new();
    let record = journal.vm(vm_id)?.ok_or_else(|| {
        Report::new(HcsError::Journal).attach(format!("VM resource record {vm_id} is missing"))
    })?;

    if record.compute_system.state != crate::journal::ResourceState::Removed {
        let result = match resources.system.take() {
            Some(system) => remove_compute_system(system).await.map(|_| ()),
            None => remove_compute(record.compute_system.id.clone()).await,
        };
        let identity = record.compute_system.id.clone();
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "compute_system",
            "remove",
            identity,
            |record, state| record.compute_system.state = state,
            summary,
            &mut failures,
        )?;
    }

    if let Some(network) = record.network.as_ref()
        && network.state != crate::journal::ResourceState::Removed
    {
        let result = match resources.network.take() {
            Some(state) => crate::hns::close_and_delete_result(state),
            None => delete_network(
                network.network_id.as_deref(),
                &network.network_name,
                network.endpoint_id.as_deref(),
                &network.endpoint_name,
            ),
        };
        let identity = format!("{}/{}", network.network_name, network.endpoint_name);
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "network",
            "delete",
            identity,
            |record, state| {
                if let Some(network) = &mut record.network {
                    network.state = state;
                }
            },
            summary,
            &mut failures,
        )?;
    }

    for (index, disk) in record.disks.iter().enumerate() {
        if disk.state == crate::journal::ResourceState::Removed {
            continue;
        }
        let result = remove_disk(vm_id, disk);
        // Display-only identity for the persisted last_error and the
        // operator-facing inventory; the faithful OsString form stays in
        // the journal record itself.
        let identity = disk.path.to_string_lossy().into_owned();
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "disk",
            "remove",
            identity,
            |record, state| {
                if let Some(disk) = record.disks.get_mut(index) {
                    if state == crate::journal::ResourceState::Removed {
                        // The ACE cannot exist without the file (or was
                        // revoked by the successful cleanup).
                        disk.vm_ace_added = false;
                    }
                    disk.state = state;
                }
            },
            summary,
            &mut failures,
        )?;
    }

    if failures.is_empty() {
        journal.update_vm(vm_id, |record| {
            record.phase = crate::journal::VmResourcePhase::Complete;
            record.last_error = None;
        })?;
        journal.remove_vm(vm_id)?;
        journal.remove_abandoned(vm_id)?;
        Ok(())
    } else {
        let record = journal.vm(vm_id)?.ok_or_else(|| {
            Report::new(HcsError::Journal).attach(format!("VM resource record {vm_id} is missing"))
        })?;
        if record.cleanup_attempts >= crate::journal::MAX_CLEANUP_ATTEMPTS {
            abandon_remaining(journal, vm_id, &record, &failures, summary)?;
            Ok(())
        } else {
            Err(Report::new(HcsError::Cleanup).attach(
                failures
                    .into_iter()
                    .map(|failure| failure.cause)
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }
}

fn cleanup_record_sync(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    resources: CleanupResources,
) -> Result<(), Report<HcsError>> {
    cleanup_record_sync_with(
        journal,
        vm_id,
        resources,
        remove_compute_system_by_id_sync,
        |network_id, network_name, endpoint_id, endpoint_name| {
            crate::hns::delete_exact(network_id, network_name, endpoint_id, endpoint_name)
        },
        remove_disk,
        &mut CleanupSummary::default(),
    )
}

/// Core synchronous cleanup pass; see [`cleanup_record_async_with`].
fn cleanup_record_sync_with<ComputeHook, NetworkHook, DiskHook>(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    mut resources: CleanupResources,
    remove_compute: ComputeHook,
    delete_network: NetworkHook,
    remove_disk: DiskHook,
    summary: &mut CleanupSummary,
) -> Result<(), Report<HcsError>>
where
    ComputeHook: Fn(&str) -> Result<(), Report<HcsError>>,
    NetworkHook: Fn(Option<&str>, &str, Option<&str>, &str) -> Result<(), Report<HcsError>>,
    DiskHook: Fn(Uuid, &crate::journal::DiskResource) -> Result<(), Report<HcsError>>,
{
    journal.update_vm(vm_id, |record| {
        record.phase = crate::journal::VmResourcePhase::CleanupPending;
        record.cleanup_attempts = record.cleanup_attempts.saturating_add(1);
        record.last_error = None;
    })?;

    let mut failures = Vec::new();
    let record = journal.vm(vm_id)?.ok_or_else(|| {
        Report::new(HcsError::Journal).attach(format!("VM resource record {vm_id} is missing"))
    })?;

    if record.compute_system.state != crate::journal::ResourceState::Removed {
        let result = match resources.system.take() {
            Some(system) => remove_compute_system_sync(system).map(|_| ()),
            None => remove_compute(&record.compute_system.id),
        };
        let identity = record.compute_system.id.clone();
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "compute_system",
            "remove",
            identity,
            |record, state| record.compute_system.state = state,
            summary,
            &mut failures,
        )?;
    }

    if let Some(network) = record.network.as_ref()
        && network.state != crate::journal::ResourceState::Removed
    {
        let result = match resources.network.take() {
            Some(state) => crate::hns::close_and_delete_result(state),
            None => delete_network(
                network.network_id.as_deref(),
                &network.network_name,
                network.endpoint_id.as_deref(),
                &network.endpoint_name,
            ),
        };
        let identity = format!("{}/{}", network.network_name, network.endpoint_name);
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "network",
            "delete",
            identity,
            |record, state| {
                if let Some(network) = &mut record.network {
                    network.state = state;
                }
            },
            summary,
            &mut failures,
        )?;
    }

    for (index, disk) in record.disks.iter().enumerate() {
        if disk.state == crate::journal::ResourceState::Removed {
            continue;
        }
        let result = remove_disk(vm_id, disk);
        // Display-only identity (see the async pass above).
        let identity = disk.path.to_string_lossy().into_owned();
        apply_resource_outcome(
            journal,
            vm_id,
            result,
            "disk",
            "remove",
            identity,
            |record, state| {
                if let Some(disk) = record.disks.get_mut(index) {
                    if state == crate::journal::ResourceState::Removed {
                        disk.vm_ace_added = false;
                    }
                    disk.state = state;
                }
            },
            summary,
            &mut failures,
        )?;
    }

    if failures.is_empty() {
        journal.update_vm(vm_id, |record| {
            record.phase = crate::journal::VmResourcePhase::Complete;
            record.last_error = None;
        })?;
        journal.remove_vm(vm_id)?;
        journal.remove_abandoned(vm_id)?;
        Ok(())
    } else {
        let record = journal.vm(vm_id)?.ok_or_else(|| {
            Report::new(HcsError::Journal).attach(format!("VM resource record {vm_id} is missing"))
        })?;
        if record.cleanup_attempts >= crate::journal::MAX_CLEANUP_ATTEMPTS {
            abandon_remaining(journal, vm_id, &record, &failures, summary)?;
            Ok(())
        } else {
            Err(Report::new(HcsError::Cleanup).attach(
                failures
                    .into_iter()
                    .map(|failure| failure.cause)
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }
}

/// Apply one resource-cleanup outcome to the journal. Success and an
/// already-absent resource both transition to `Removed` (idempotent
/// cleanup); only a genuine failure leaves the resource `RemovalFailed`
/// with a persisted, self-describing `last_error` and a structured event.
#[allow(clippy::too_many_arguments)] // one parameter per outcome field
fn apply_resource_outcome(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    result: Result<(), Report<HcsError>>,
    kind: &'static str,
    operation: &'static str,
    identity: String,
    transition: impl FnOnce(&mut crate::journal::VmResourceRecord, crate::journal::ResourceState),
    summary: &mut CleanupSummary,
    failures: &mut Vec<CleanupFailure>,
) -> Result<(), Report<HcsError>> {
    match result {
        Ok(()) => {
            summary.recovered += 1;
            journal.update_vm(vm_id, |record| {
                transition(record, crate::journal::ResourceState::Removed);
            })
        }
        Err(error) if resource_is_absent(&error) => {
            summary.absent += 1;
            #[cfg(feature = "tracing")]
            tracing::warn!(
                resource_kind = kind,
                resource_id = %identity,
                "[JOURNAL] stale resource already absent"
            );
            journal.update_vm(vm_id, |record| {
                transition(record, crate::journal::ResourceState::Removed);
            })
        }
        Err(error) => {
            summary.failed += 1;
            let cause = report_text(&error);
            let message = format!(
                "resource_kind={kind} operation={operation} resource_id={identity} cause={cause}"
            );
            failures.push(CleanupFailure {
                kind,
                operation,
                identity: identity.clone(),
                cause: cause.clone(),
            });
            #[cfg(feature = "tracing")]
            let attempts = journal
                .vm(vm_id)?
                .map(|record| record.cleanup_attempts)
                .unwrap_or_default();
            #[cfg(feature = "tracing")]
            tracing::error!(
                vm_id = %vm_id,
                resource_kind = kind,
                operation,
                resource_id = %identity,
                cause = %cause,
                attempt = attempts,
                total_attempts = crate::journal::MAX_CLEANUP_ATTEMPTS,
                "[JOURNAL] cleanup failed"
            );
            journal.update_vm(vm_id, |record| {
                transition(record, crate::journal::ResourceState::RemovalFailed);
                record.last_error = Some(message);
            })
        }
    }
}

/// Transition every remaining non-`Removed` resource of an exhausted record
/// to `Abandoned`, persist the abandoned inventory with each resource's
/// exact identity and last error, and emit the terminal operator-facing
/// event. Returns `Ok` because the record is now terminal for recovery.
fn abandon_remaining(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    record: &crate::journal::VmResourceRecord,
    failures: &[CleanupFailure],
    summary: &mut CleanupSummary,
) -> Result<(), Report<HcsError>> {
    let now = crate::journal::unix_time_ms();
    let existing = journal.abandoned(vm_id)?;
    let mut entries: Vec<crate::journal::AbandonedResourceEntry> =
        existing.map(|record| record.entries).unwrap_or_default();
    let mut abandoned_now = Vec::new();

    let mut consider =
        |kind: &'static str, identity: String, state: crate::journal::ResourceState| {
            if state == crate::journal::ResourceState::Removed {
                return;
            }
            let last_error = failures
            .iter()
            .find(|failure| failure.kind == kind && failure.identity == identity)
            .map(|failure| {
                format!(
                    "resource_kind={} operation={} resource_id={} cause={}",
                    failure.kind, failure.operation, failure.identity, failure.cause
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "resource_kind={kind} resource_id={identity} cause=cleanup attempts exhausted"
                )
            });
            match entries
                .iter_mut()
                .find(|entry| entry.kind == kind && entry.identity == identity)
            {
                Some(entry) => {
                    entry.last_error = last_error.clone();
                }
                None => {
                    entries.push(crate::journal::AbandonedResourceEntry {
                        kind: kind.to_string(),
                        identity: identity.clone(),
                        last_error: last_error.clone(),
                        first_abandoned_at_unix_ms: now,
                    });
                }
            }
            abandoned_now.push(crate::journal::AbandonedResourceEntry {
                kind: kind.to_string(),
                identity,
                last_error,
                first_abandoned_at_unix_ms: now,
            });
        };

    consider(
        "compute_system",
        record.compute_system.id.clone(),
        record.compute_system.state,
    );
    if let Some(network) = &record.network {
        consider(
            "network",
            format!("{}/{}", network.network_name, network.endpoint_name),
            network.state,
        );
    }
    for disk in &record.disks {
        consider("disk", disk.path.to_string_lossy().into_owned(), disk.state);
    }

    journal.put_abandoned(&crate::journal::AbandonedRecord {
        schema_version: crate::journal::SCHEMA_VERSION,
        vm_id,
        entries,
    })?;
    journal.update_vm(vm_id, |record| {
        if record.compute_system.state != crate::journal::ResourceState::Removed {
            record.compute_system.state = crate::journal::ResourceState::Abandoned;
        }
        if let Some(network) = &mut record.network
            && network.state != crate::journal::ResourceState::Removed
        {
            network.state = crate::journal::ResourceState::Abandoned;
        }
        for disk in &mut record.disks {
            if disk.state != crate::journal::ResourceState::Removed {
                disk.state = crate::journal::ResourceState::Abandoned;
            }
        }
        let identities = abandoned_now
            .iter()
            .map(|entry| {
                format!(
                    "resource_kind={} resource_id={}",
                    entry.kind, entry.identity
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        record.last_error = Some(format!(
            "abandoned after {} cleanup attempts: {identities}",
            crate::journal::MAX_CLEANUP_ATTEMPTS
        ));
    })?;
    summary.abandoned += abandoned_now.len();
    #[cfg(feature = "tracing")]
    for entry in abandoned_now {
        tracing::error!(
            vm_id = %vm_id,
            resource_kind = %entry.kind,
            resource_id = %entry.identity,
            last_error = %entry.last_error,
            "[JOURNAL] resource abandoned; query the abandoned inventory and remove deliberately"
        );
    }
    Ok(())
}

async fn remove_compute_system_by_id(id: &str) -> Result<(), Report<HcsError>> {
    match ComputeSystem::from_id(id) {
        Ok(system) => remove_compute_system(system).await.map(|_| ()),
        Err(error) if resource_is_absent(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Remove a compute system by its exact recorded ID, treating an already-
/// absent system as successful idempotent cleanup. Reused by the legacy
/// cleanup admin API (`hcs_admin::delete_legacy_compute_system`); never scans
/// prefixes or owners.
pub fn remove_compute_system_by_id_sync(id: &str) -> Result<(), Report<HcsError>> {
    match ComputeSystem::from_id(id) {
        Ok(system) => remove_compute_system_sync(system).map(|_| ()),
        Err(error) if resource_is_absent(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Clean up one journaled disk. Runs after the compute system has released
/// the VHDX, so the file is no longer open by the VM worker.
///
/// 1. Revoke the temporary per-VM ACE when Jyth added one (identified by
///    the per-VM SID derived from `vm_id`; only that ACE is removed).
/// 2. Apply the deletion predicate: a file is deleted only when its origin
///    is `CreatedByLaunch`, the current Windows file identity still matches
///    the recorded identity, and the disk is deletable (ephemeral, or
///    created by a launch that never reached publication). `PreExisting`
///    is an unconditional never-delete; a missing file is idempotent
///    success; a missing recorded identity or a changed identity refuses
///    deletion.
fn remove_disk(vm_id: Uuid, disk: &crate::journal::DiskResource) -> Result<(), Report<HcsError>> {
    if disk.state == crate::journal::ResourceState::Planned {
        return Ok(());
    }
    let path = Path::new(&disk.path);

    if disk.vm_ace_added {
        let sid = crate::security::vm_identity_sid(vm_id);
        crate::security::validate_vm_identity_sid(&sid)?;
        if path.exists() {
            revoke_vm_identity_access(path, &sid)?;
        }

        #[cfg(feature = "tracing")]
        tracing::info!(path = %path.display(), sid = %sid, "[CLEANUP] revoked temporary VM identity ACE");
    }

    if disk.origin == vm_model::disk::DiskOrigin::PreExisting {
        return Ok(());
    }
    let deletable =
        disk.effective_retention == vm_model::disk::DiskRetention::Ephemeral || !disk.published;
    if !deletable {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }
    let Some(expected) = &disk.file_identity else {
        return Err(Report::new(HcsError::Cleanup).attach(format!(
            "refusing to delete {} without a recorded file identity",
            path.display()
        )));
    };
    let current = crate::journal::file_identity(path)?;
    if &current != expected {
        return Err(Report::new(HcsError::DiskIdentityChanged).attach(format!(
            "file identity changed before deleting {}",
            path.display()
        )));
    }
    match std::fs::remove_file(path) {
        Ok(()) => {
            #[cfg(feature = "tracing")]
            tracing::info!(path = %path.display(), "[CLEANUP] removed journaled disk");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Report::new(HcsError::Cleanup)
            .attach(format!("remove journaled disk {}: {error}", path.display()))),
    }
}

/// Render a report including its printable attachments. `Report`'s `Display`
/// renders only the context chain; the HCS/HNS/disk layers attach their
/// HRESULT/OS detail text as attachments, and that detail must survive into
/// absence classification and the persisted `last_error` messages.
fn report_text(error: &Report<HcsError>) -> String {
    let mut text = error.to_string();
    for frame in error.frames() {
        if let error_stack::FrameKind::Attachment(error_stack::AttachmentKind::Printable(
            attachment,
        )) = frame.kind()
        {
            text.push_str("; ");
            text.push_str(&attachment.to_string());
        }
    }
    text
}

/// Classify a cleanup error as "the resource is already absent". The
/// classification relies ONLY on the stable HRESULT whitelist HCS/HNS/Hyper-V
/// use for "not found" (`0x80070490`) and "cannot find the file"
/// (`0x80070002`). Error TEXT is deliberately not matched: message wording
/// is localized and can change between releases, and a wording change must
/// not turn a genuine failure into an idempotent `Removed` transition that
/// deletes the journal record. Absence is never a failed transition.
fn resource_is_absent(error: &Report<HcsError>) -> bool {
    let text = report_text(error).to_ascii_lowercase();
    text.contains("0x80070490") || text.contains("0x80070002")
}

impl Vm {
    /// Create an HCS VM from a serialized configuration and optional host
    /// networking and disk resources. An empty or `None` disk list performs
    /// no disk operation and creates no directory. The VM is journaled in
    /// the explicit runtime [`Session`]'s journal.
    #[cfg_attr(
        feature = "tracing",
        instrument(skip(session, conf, network, disks), fields(id), level = "debug")
    )]
    pub async fn from_conf(
        session: &Session,
        mut conf: crate::conf::Conf,
        network: Option<&vm_model::network::Nat>,
        disks: Option<&[vm_model::disk::DiskSpec]>,
    ) -> Result<Self, Report<HcsError>> {
        let cancel_token = CancellationToken::new();
        let cancel_token_guard = cancel_token.clone().drop_guard();

        // A fresh per-attempt VM UUID from the OS CSPRNG (v4 via getrandom)
        // — plan step 1 of the secure control plane. This UUID is the HCS
        // compute-system ID and the root of every per-VM name and the
        // per-VM identity SID; nothing depends on time-ordered values.
        let id = uuid::Uuid::new_v4();
        let journal = session.journal().clone();
        ensure_hyperv_admin_membership()?;
        conf = conf.owner(&journal.owner());

        let bus_pipe_name = format!(r"\\.\pipe\jyth-{}-bus", id);
        conf = conf.add_com_port(1, &bus_pipe_name)?;

        let planned_network_id = network.map(|_| Uuid::now_v7());
        let planned_network =
            planned_network_id.map(|network_id| crate::journal::NetworkResource {
                network_name: format!("jyth-nat-{id}"),
                network_id: Some(network_id.to_string()),
                endpoint_name: format!("jyth-ep-{id}"),
                endpoint_id: None,
                state: crate::journal::ResourceState::Planned,
            });
        // Disk intent is journaled before any side effect: each requested
        // path, its SCSI slot, and its requested retention. Origin and
        // effective retention are classified during materialization (still
        // before any HCS state exists) and corrected in the journal.
        let planned_disks = plan_disk_resources(id, disks)?;
        journal.put_vm(&crate::journal::VmResourceRecord {
            schema_version: 1,
            vm_id: id,
            phase: crate::journal::VmResourcePhase::Planned,
            published: false,
            compute_system: crate::journal::ComputeResource {
                id: id.to_string(),
                state: crate::journal::ResourceState::Planned,
            },
            network: planned_network,
            disks: planned_disks,
            cleanup_attempts: 0,
            last_error: None,
        })?;
        let mut provisioning = ProvisioningGuard::new(journal.clone(), id);

        // Task I-3: when the caller asked for a NIC, create the HNS
        // network + endpoint *before* serialising the conf — the
        // endpoint id has to land in `Devices.NetworkAdapters` via
        // `Conf::add_network_adapter` so HCS resolves the NIC at
        // start. Failure here aborts before any HCS state is created,
        // so no cleanup is owed.
        //
        // HNS does NOT auto-attach endpoints at create time; HCS looks
        // up the NIC at `HcsCreateComputeSystem` time by resolving the
        // `NetworkAdapters[].EndpointId` GUID against the HNS endpoint
        // table. So we have to put the HNS-allocated endpoint GUID
        // there (NOT a pre-populated seed — HNS ignores pre-populated
        // GUIDs). `create_network_and_endpoint` queries the real
        // GUID back via `HcnQueryEndpointProperties` and returns it
        // in `state.endpoint_id_string`.
        //
        // `planned_network_id` is `Some` exactly when `network` is `Some`
        // (both derive from the caller's `network` argument), so the zip is
        // a panic-free way to destructure the pair.
        if let Some((nat, planned_network_id)) = network.zip(planned_network_id) {
            let network_journal = Arc::clone(&journal);
            let endpoint_journal = Arc::clone(&journal);
            let state = crate::hns::create_network_and_endpoint_with_callbacks(
                id,
                planned_network_id,
                nat,
                move |network_id| {
                    network_journal.update_vm(id, |record| {
                        if let Some(network) = &mut record.network {
                            network.network_id = Some(network_id.to_string());
                        }
                    })
                },
                move |endpoint_id| {
                    endpoint_journal.update_vm(id, |record| {
                        if let Some(network) = &mut record.network {
                            network.endpoint_id = Some(endpoint_id.to_string());
                            network.state = crate::journal::ResourceState::Created;
                        }
                    })
                },
            )?;
            let endpoint_id = state.endpoint_id_string.clone();
            provisioning.network = Some(state);
            conf = conf.add_network_adapter(crate::conf::NetworkAdapter {
                endpoint_id,
                mac: None,
            })?;
        }

        // Disks: when the caller asked for one or more, materialize each
        // VHDX at its exact configured host path *before* serialising the
        // conf — the host path has to land in `Devices.Scsi.N` via
        // `Conf::add_scsi_disk` so HCS attaches the file as a guest block
        // device at VM start. Each path is resolved under a per-path named
        // mutex that spans existence classification → journal update →
        // creation/validation → file-identity capture → ACL update, so two
        // processes cannot both create/own the same missing path. The
        // guest init is responsible for `mkfs` + `mount` of each device at
        // its `guest_mount`; only disks the backend created are marked for
        // guest initialization.
        //
        // The VHDX access grant targets the exact per-VM identity
        // `NT VIRTUAL MACHINE\<vm-guid>` (SID `S-1-5-83-1-<r1>-<r2>-<r3>-<r4>`
        // derived from the VM GUID), NOT the machine-wide `NT VIRTUAL
        // MACHINE\Virtual Machines` group (SID `S-1-5-83-0`): the VM
        // worker process runs under that group, and without a grant HCS
        // returns `Access is denied. (0x80070005)` when Synthetic Storage
        // tries to open the VHDX at power-on. The grant is temporary —
        // cleanup revokes exactly this ACE after the compute system
        // releases the file.
        let mut attached_disks: Vec<vm_model::disk::AttachedDisk> = Vec::new();
        if let Some(specs) = disks.filter(|disks| !disks.is_empty()) {
            let vm_sid = crate::security::vm_identity_sid(id);
            crate::security::validate_vm_identity_sid(&vm_sid)?;
            for (index, spec) in specs.iter().enumerate() {
                let planned = provisioning_planned_disk(&journal, id, index)?;
                let attached = materialize_disk(
                    &journal,
                    &mut provisioning,
                    id,
                    &vm_sid,
                    index,
                    spec,
                    &planned,
                )?;
                let (controller, lun) = scsi_slot(index)?;
                conf = conf.add_scsi_disk(crate::conf::ScsiDisk {
                    controller,
                    lun,
                    path: hcs_config_path(&attached.host_path),
                    read_only: false,
                })?;
                attached_disks.push(attached);
            }
        }

        let logs_pipe_name = format!(r"\\.\pipe\jyth-{}-logs", id);
        // Outcome of the provisioning async block: the COM1 bus-pipe DACL
        // snapshot, the transferred Tokio pipe server, and the created
        // compute system (or an error covered by the armed guard).
        type ProvisionOutcome = (
            Option<Vec<crate::security::ParsedAce>>,
            std::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeServer>>,
            ComputeSystem,
        );
        let result: Result<ProvisionOutcome, Report<HcsError>> = async {
        // From here on, every `?` failure is covered by the armed
        // `ProvisioningGuard`; on success the exact HNS handles move into
        // the returned `Vm`.
            {
                use tokio::spawn;

                conf = conf.add_com_port(0, logs_pipe_name.as_str())?;
                spawn({
                    let cancel_token = cancel_token.clone();
                    let logs_pipe_name = logs_pipe_name.clone();
                    async move {
                        let mut reader =
                            match crate::console::connect_pipe(id, &logs_pipe_name, cancel_token).await {
                                Ok(reader) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::info!(pipe = %logs_pipe_name, "[HOST] Logs pipe connected");
                                    reader
                                }
                                Err(_e) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(pipe = %logs_pipe_name, error = %_e, "[HOST] Failed to connect to logs pipe");
                                    return;
                                }
                            };
                        let mut line_bytes = Vec::new();
                        while let Ok(n) = reader.read_until(b'\n', &mut line_bytes).await {
                            if n == 0 {
                                break;
                            }
                            #[cfg(feature = "tracing")]
                            let line = String::from_utf8_lossy(&line_bytes)
                                .trim_end_matches(['\r', '\n'])
                                .to_string();
                            #[cfg(feature = "tracing")]
                            tracing::info!(%line, "[VM CONSOLE]");
                            line_bytes.clear();
                        }
                    }
                });
            }
            let conf_str = conf.json()?;
            #[cfg(feature = "tracing")]
            tracing::debug!(config = %conf_str, "HCS configuration");
            // Also eprintln it so callers without a tracing subscriber
            // (e.g. the net-probe example before RUST_LOG wiring) can
            // watch the HCS XML being assembled — invaluable when
            // debugging `HcsCreateComputeSystem` schema rejections
            // (HCS returns `0x8037010D`/`HCS_E_SYSTEM_INVALID_CONFIGURATION`
            // or `0x80370110` for adapter-block schema mismatches with
            // no detail beyond the HRESULT).
            if std::env::var("JYTH_DEBUG_HCS_CONF").is_ok() {
                eprintln!("[debug] HCS config for VM {id}:\n{conf_str}");
            }

            // The COM1 bus pipe is created with an explicit deny-by-default
            // descriptor — current logon SID, exact per-VM identity
            // `NT VIRTUAL MACHINE\<id>`, and SYSTEM — never the default
            // ACL, and FILE_FLAG_FIRST_PIPE_INSTANCE prevents namespace
            // pre-creation. `named_pipe_sddl` fails closed on any token or
            // descriptor error.
            let sddl = crate::security::named_pipe_sddl(id)?;
            let handle = crate::security::create_pipe_with_security(&bus_pipe_name, &sddl)
                .map_err(|e| Report::new(e).change_context(HcsError::ComPortSetup))?;
            // Snapshot the applied DACL from the server handle BEFORE the
            // transfer to Tokio: with `nMaxInstances=1` the pipe cannot be
            // reopened for inspection once the guest worker connects.
            // Inspection failure is a warning, not a launch failure — the
            // descriptor was already applied.
            let bus_pipe_aces = crate::security::dacl_aces_from_handle(handle.as_raw_handle())
                .map(Some)
                .unwrap_or_else(|_error| {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(%_error, "could not snapshot COM1 bus-pipe DACL");
                    None
                });
            // SAFETY: `handle` is the sole reference to a fresh overlapped
            // pipe instance; the transfer hands the closing responsibility
            // to Tokio (same pattern as `crate::console::connect_pipe`).
            let bus_pipe_server = unsafe {
                tokio::net::windows::named_pipe::NamedPipeServer::from_raw_handle(
                    handle.into_raw_handle(),
                )
            }
            .map_err(|e| Report::new(e).change_context(HcsError::ComPortSetup))?;

            let sys = create_compute_system(&id, &conf_str, &cancel_token).await?;
            journal.update_vm(id, |record| {
                record.compute_system.state = crate::journal::ResourceState::Created;
                record.phase = crate::journal::VmResourcePhase::Starting;
            })?;

            Ok((bus_pipe_aces, std::sync::Mutex::new(Some(bus_pipe_server)), sys))
        }
        .await;

        match result {
            Ok((bus_pipe_aces, bus_pipe_server, sys)) => {
                let CleanupResources { network, .. } = provisioning.disarm();
                cancel_token_guard.disarm();
                Ok(Vm {
                    id,
                    system: Mutex::new(Some(sys)),
                    bus_pipe_name: Some(bus_pipe_name),
                    bus_pipe_aces,
                    bus_pipe_server,
                    network: Mutex::new(network),
                    attached_disks,
                    journal,
                    cleanup_completed: false,
                })
            }
            Err(e) => {
                // Dropping the still-armed guard performs exact synchronous
                // rollback and leaves the journal pending if any step fails.
                Err(e)
            }
        }
    }
}

const SCSI_LUNS_PER_CONTROLLER: usize = 64;

fn scsi_slot(index: usize) -> Result<(u32, u32), Report<HcsError>> {
    let controller = u32::try_from(index / SCSI_LUNS_PER_CONTROLLER).map_err(|_| {
        Report::new(HcsError::DiskInvalidPath).attach(format!(
            "disk index {index} cannot be represented as an HCS SCSI controller"
        ))
    })?;
    let lun = u32::try_from(index % SCSI_LUNS_PER_CONTROLLER).map_err(|_| {
        Report::new(HcsError::DiskInvalidPath)
            .attach(format!("SCSI LUN for disk index {index} overflows u32"))
    })?;
    Ok((controller, lun))
}

/// Journal the intent for every requested disk: normalized absolute path,
/// SCSI slot, and requested retention. An empty or `None` list produces no
/// disk records and performs no filesystem operation.
fn plan_disk_resources(
    vm_id: Uuid,
    disks: Option<&[vm_model::disk::DiskSpec]>,
) -> Result<Vec<crate::journal::DiskResource>, Report<HcsError>> {
    let mut planned = Vec::new();
    let Some(specs) = disks.filter(|disks| !disks.is_empty()) else {
        return Ok(planned);
    };
    for (index, spec) in specs.iter().enumerate() {
        let (controller, lun) = scsi_slot(index)?;
        let path = crate::journal::normalize_absolute_path(spec.host_path())?;
        planned.push(crate::journal::DiskResource {
            // The journal persists the faithful `OsString` form so cleanup
            // targets exactly the file the VHDX creation addressed.
            path: path.into_os_string(),
            controller,
            lun,
            state: crate::journal::ResourceState::Planned,
            // Placeholders corrected during materialization: a pre-existing
            // file is reclassified to PreExisting, and effective retention
            // follows the materialization matrix.
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: spec.retention(),
            effective_retention: spec.retention(),
            file_identity: None,
            initialization_requested: false,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: false,
        });
    }
    let _ = vm_id;
    Ok(planned)
}

fn provisioning_planned_disk(
    journal: &crate::journal::SessionJournal,
    vm_id: Uuid,
    index: usize,
) -> Result<crate::journal::DiskResource, Report<HcsError>> {
    journal
        .vm(vm_id)?
        .and_then(|record| record.disks.into_iter().nth(index))
        .ok_or_else(|| {
            Report::new(HcsError::Journal)
                .attach(format!("disk plan entry {index} for VM {vm_id} is missing"))
        })
}

/// Encode a host path for the HCS configuration document. HCS reads the
/// SCSI `Path` field as a JSON string, and JSON is UTF-8 text, so a path
/// with unpaired surrogate code units cannot be expressed faithfully — the
/// explicit wide conversion below is the closest form, and such a path
/// fails to open at HCS power-on instead of addressing a different file.
/// The journal keeps the faithful `OsString` form (see
/// `crate::journal::DiskResource::path`); this conversion is only for the
/// serialized HCS schema.
fn hcs_config_path(path: &Path) -> String {
    String::from_utf16_lossy(&path.as_os_str().encode_wide().collect::<Vec<u16>>())
}

/// The materialization decision for one disk, from the plan's matrix:
///
/// | File at launch | Requested retention | Effective behavior |
/// | --- | --- | --- |
/// | Missing | Ephemeral | Create, grant VM-specific access, initialize in guest. |
/// | Missing | Persistent | Create, grant access, initialize in guest, retain after publication. |
/// | Existing | Persistent | Validate and attach, never initialize, retain. |
/// | Existing | Ephemeral + `ReuseAndKeep` | Validate and attach, never initialize, reclassify to persistent, warn. |
/// | Existing | Ephemeral + `Error` | Fail before HCS compute-system creation. |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskMaterialization {
    Create,
    Reuse,
    ReuseAndReclassify,
    RejectExisting,
}

fn classify_disk(
    exists: bool,
    retention: vm_model::disk::DiskRetention,
    on_existing: vm_model::disk::ExistingDiskPolicy,
) -> DiskMaterialization {
    if !exists {
        return DiskMaterialization::Create;
    }
    match (retention, on_existing) {
        (_, vm_model::disk::ExistingDiskPolicy::Error) => DiskMaterialization::RejectExisting,
        (
            vm_model::disk::DiskRetention::Ephemeral,
            vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
        ) => DiskMaterialization::ReuseAndReclassify,
        (
            vm_model::disk::DiskRetention::Persistent,
            vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
        ) => DiskMaterialization::Reuse,
    }
}

/// Materialize one disk under its per-path lock: existence classification →
/// journal update → creation/validation → file-identity capture → per-VM
/// ACL update. The caller attaches the returned disk to the HCS config
/// afterwards, so the identity is always journaled before attachment.
fn materialize_disk(
    journal: &crate::journal::SessionJournal,
    provisioning: &mut ProvisioningGuard,
    vm_id: Uuid,
    vm_sid: &str,
    index: usize,
    spec: &vm_model::disk::DiskSpec,
    planned: &crate::journal::DiskResource,
) -> Result<vm_model::disk::AttachedDisk, Report<HcsError>> {
    let normalized = crate::journal::normalize_absolute_path(spec.host_path())?;
    if normalized.as_os_str() != planned.path.as_os_str() {
        return Err(Report::new(HcsError::DiskInvalidPath).attach(format!(
            "planned disk path {} no longer matches the spec path {}",
            planned.path.to_string_lossy(),
            normalized.display()
        )));
    }
    // Per-path named mutex: held through classification, journal update,
    // creation/validation, identity capture, and ACL update, so two
    // processes cannot both create/own the same missing path.
    let _lock = PathLock::acquire(&normalized)?;
    crate::journal::reject_disk_reparse_points(&normalized)?;

    let Some(parent) = normalized.parent() else {
        return Err(Report::new(HcsError::DiskParentMissing)
            .attach(format!("disk path {} has no parent", normalized.display())));
    };
    if !parent.is_dir() {
        return Err(Report::new(HcsError::DiskParentMissing).attach(format!(
            "disk parent directory is missing or not a directory: {}",
            parent.display()
        )));
    }

    let retention = spec.retention();
    let mut classification = classify_disk(normalized.exists(), retention, spec.on_existing());
    if classification == DiskMaterialization::Create {
        match create_sparse_vhdx(&normalized, spec.create_size_mb().get()) {
            Ok(()) => {}
            Err(_error) if normalized.exists() => {
                // The file appeared concurrently while we held the path
                // lock (a non-cooperating creator): re-run the selected
                // existing-file policy, still under the lock.
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    path = %normalized.display(),
                    error = %_error,
                    "[DISK] path appeared during create; re-running the existing-file policy"
                );
                classification = classify_disk(true, retention, spec.on_existing());
            }
            Err(error) => {
                return Err(Report::new(HcsError::DiskCreateFailed)
                    .attach(format!("New-VHD for {}: {error}", normalized.display())));
            }
        }
    }

    let (origin, effective, initialize, warning, created) = match classification {
        DiskMaterialization::Create => (
            vm_model::disk::DiskOrigin::CreatedByLaunch,
            retention,
            true,
            None,
            true,
        ),
        DiskMaterialization::Reuse => {
            validate_existing_vhdx(&normalized)?;
            (
                vm_model::disk::DiskOrigin::PreExisting,
                vm_model::disk::DiskRetention::Persistent,
                false,
                None,
                false,
            )
        }
        DiskMaterialization::ReuseAndReclassify => {
            validate_existing_vhdx(&normalized)?;
            (
                vm_model::disk::DiskOrigin::PreExisting,
                vm_model::disk::DiskRetention::Persistent,
                false,
                Some(vm_model::disk::DiskRetention::Ephemeral),
                false,
            )
        }
        DiskMaterialization::RejectExisting => {
            return Err(Report::new(HcsError::DiskPathExists).attach(format!(
                "disk path already exists and ExistingDiskPolicy::Error was selected: {}",
                normalized.display()
            )));
        }
    };

    if warning.is_some() {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            path = %normalized.display(),
            requested = ?retention,
            effective = ?effective,
            "[DISK] existing path reused: ephemeral request reclassified as persistent"
        );
    }

    // Identity is captured after create/open and journaled BEFORE the
    // caller attaches the disk to the HCS configuration.
    let identity = crate::journal::file_identity(&normalized)?;
    if created {
        provisioning
            .unjournaled_disks
            .push((normalized.clone(), identity.clone()));
    }
    journal.update_vm(vm_id, |record| {
        if let Some(disk) = record.disks.get_mut(index) {
            disk.state = crate::journal::ResourceState::Created;
            disk.origin = origin;
            disk.effective_retention = effective;
            disk.initialization_requested = initialize;
            disk.file_identity = Some(identity.clone());
        }
    })?;

    grant_vm_identity_access(&normalized, vm_sid)?;
    journal.update_vm(vm_id, |record| {
        if let Some(disk) = record.disks.get_mut(index) {
            disk.vm_ace_added = true;
        }
    })?;

    Ok(vm_model::disk::AttachedDisk {
        host_path: normalized,
        guest_mount: spec.guest_mount().as_str().to_string(),
        origin,
        requested_retention: retention,
        effective_retention: effective,
    })
}

/// A per-path named mutex guarding one disk path across processes.
///
/// The name is `Local\jyth-disk-<sha256hex>` where `<sha256hex>` is the
/// lowercase SHA-256 of the normalized absolute path's faithful wide code
/// units. The `Local\` namespace scopes the lock to the logon session, which
/// is exactly the cross-process scope Jyth's own processes share; `Global\`
/// would require privileges and a service identity. The mutex handle is
/// created with a NULL security descriptor, so access is governed by the
/// default DACL (same-user access). The lock is released on drop.
#[derive(Debug)]
struct PathLock(*mut std::ffi::c_void);

impl PathLock {
    fn acquire(path: &Path) -> Result<Self, Report<HcsError>> {
        Self::acquire_with_timeout(path, PATH_LOCK_WAIT_MS)
    }

    fn acquire_with_timeout(path: &Path, wait_ms: u32) -> Result<Self, Report<HcsError>> {
        let name = path_lock_name(path);
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, wide.as_ptr()) };
        if handle.is_null() {
            return Err(
                Report::new(HcsError::DiskPathAlreadyClaimed).attach(format!(
                    "CreateMutexW failed for {} ({})",
                    name,
                    std::io::Error::last_os_error()
                )),
            );
        }
        // The wait is bounded: a hung or suspended holder must not block
        // every provisioning path for that disk indefinitely.
        let wait = unsafe { WaitForSingleObject(handle, wait_ms) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                CloseHandle(handle);
            }
            let reason = match wait {
                WAIT_TIMEOUT => format!("timed out after {wait_ms} ms"),
                WAIT_ABANDONED => {
                    "abandoned by a terminated owner; treated as still claimed".to_owned()
                }
                _ => format!(
                    "wait failed (result {wait}): {}",
                    std::io::Error::last_os_error()
                ),
            };
            return Err(Report::new(HcsError::DiskPathAlreadyClaimed)
                .attach(format!("could not acquire disk path lock {name}: {reason}")));
        }
        Ok(Self(handle))
    }
}

impl Drop for PathLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

/// Derive the stable per-path lock name from the path's faithful wide code
/// units: two processes must agree on the exact name, and distinct paths
/// (including surrogate-only differences) must hash distinctly.
fn path_lock_name(path: &Path) -> String {
    let mut hasher = sha2::Sha256::new();
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "Local\\jyth-disk-{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Create a sparse (dynamic) VHDX at `path` of `size_mb` megabytes on the
/// host. Invoked by [`Vm::from_conf`] once per created disk. Uses the
/// Hyper-V `New-VHD` cmdlet via `powershell.exe` (`-NoProfile` to skip the
/// user profile load — `New-VHD` is from the `Hyper-V` PowerShell module
/// which the same check that gates `ensure_hyperv_admin_membership`
/// already guarantees is available).
///
/// The path and size are passed as PROCESS ARGUMENTS, never interpolated
/// into script text, so caller-controlled values cannot alter the command.
/// The script must be a script-block invocation (`& { ... }`): Windows
/// PowerShell (5.1 and 7) only binds trailing `-Command` arguments to
/// `$args` when the command string is a script-block call — the bare
/// `New-VHD ...` form leaves `$args` empty and `New-VHD` fails with
/// "The argument is null or empty" for `-Path` (proved by the live e2e
/// disk tests).
fn create_sparse_vhdx(path: &std::path::Path, size_mb: u64) -> std::io::Result<()> {
    let size_bytes = size_mb.checked_mul(1024 * 1024).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("disk size {size_mb} MB overflows u64 bytes"),
        )
    })?;
    // The parent dir is checked by the caller before this is invoked, but
    // `New-VHD` doesn't itself create the parent; call again defensively
    // in case the caller path changes later.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // The path travels as an `OsStr` argument, never through a lossy string
    // conversion, and the invocation is bounded (a hung PowerShell cannot
    // block provisioning forever).
    let output = run_bounded(
        std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg("& { New-VHD -Path $args[0] -SizeBytes $args[1] -Dynamic | Out-Null }")
            .arg(path.as_os_str())
            .arg(size_bytes.to_string()),
        &format!("New-VHD for {}", path.display()),
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(std::io::Error::other(format!(
            "New-VHD failed (status {:?}): stderr={stderr} stdout={stdout}",
            output.status,
        )));
    }
    if !path.exists() {
        return Err(std::io::Error::other(format!(
            "New-VHD reported success but {} does not exist",
            path.display(),
        )));
    }
    Ok(())
}

/// Validate an existing file as a writable VHDX via `Get-VHD` (Hyper-V's
/// VHDX reader). An arbitrary file is never attached based on its
/// extension alone; `Get-VHD` fails on a path that is not a valid VHDX.
fn validate_existing_vhdx(path: &std::path::Path) -> Result<(), Report<HcsError>> {
    let output = run_bounded(
        std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg("& { Get-VHD -Path $args[0] | Out-Null }")
            .arg(path.as_os_str()),
        &format!("Get-VHD for {}", path.display()),
    )
    .map_err(|error| {
        Report::new(HcsError::DiskNotValidWritableVhdx).attach(format!(
            "Get-VHD invocation failed for {}: {error}",
            path.display()
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(
            Report::new(HcsError::DiskNotValidWritableVhdx).attach(format!(
                "Get-VHD rejected {} (status {:?}): stderr={stderr} stdout={stdout}",
                path.display(),
                output.status,
            )),
        );
    }
    Ok(())
}

/// Grant the exact per-VM worker identity read+write access to `path` so
/// the VM's Synthetic Storage controller can open the VHDX at power-on.
/// The SID is the per-VM `S-1-5-83-1-<r1>-<r2>-<r3>-<r4>` derived from the
/// VM GUID — not the machine-wide `NT VIRTUAL MACHINE\Virtual Machines`
/// group. The grant appends one allow ACE and is idempotent (re-adding the
/// same ACE is a no-op).
///
/// The ACE is added through the Windows security APIs with the SID used as
/// opaque bytes. `icacls /grant *<sid>` cannot be used here: the per-VM
/// identity has no account record until VMMS creates the compute system
/// (which happens after this grant), so `icacls` fails with
/// ERROR_NONE_MAPPED (1332) — "No mapping between account names and
/// security IDs was done" (proved by the live e2e disk tests).
fn grant_vm_identity_access(path: &std::path::Path, sid: &str) -> Result<(), Report<HcsError>> {
    crate::security::grant_file_identity_access(path, sid)
}

/// Remove exactly the per-VM ACE Jyth added to `path`, preserving every
/// other ACE (including ACEs added by other tools): the current DACL is
/// read live and rewritten with the `sid` ACE filtered out. A missing file
/// is an idempotent success (the ACE cannot exist without the file).
fn revoke_vm_identity_access(path: &std::path::Path, sid: &str) -> Result<(), Report<HcsError>> {
    crate::security::revoke_file_identity_access(path, sid)
}

/// Maximum wall-clock time the per-path disk mutex may be held by another
/// process before acquisition reports the path as claimed.
const PATH_LOCK_WAIT_MS: u32 = 30_000;
/// Maximum wall-clock time a provisioning helper subprocess (PowerShell,
/// icacls) may run before it is killed as hung.
pub(crate) const SUBPROCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Poll interval while waiting for a subprocess to exit.
const SUBPROCESS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x0000_0080;
const WAIT_TIMEOUT: u32 = 0x0000_0102;

/// Run `command` to completion with a bounded wait (see
/// [`SUBPROCESS_TIMEOUT`]); on timeout the child is killed and the error
/// names `operation`.
pub(crate) fn run_bounded(
    command: &mut std::process::Command,
    operation: &str,
) -> std::io::Result<std::process::Output> {
    run_bounded_with_timeout(command, operation, SUBPROCESS_TIMEOUT)
}

/// Implementation of [`run_bounded`] with an injectable timeout (the tests
/// override it with a tiny value). Stdout/stderr are piped and drained only
/// after the child has exited; a child blocked writing into a full pipe is
/// killed by the timeout rather than deadlocking the caller.
fn run_bounded_with_timeout(
    command: &mut std::process::Command,
    operation: &str,
    timeout: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("{operation} could not be started: {error}"),
            )
        })?;
    let deadline = std::time::Instant::now() + timeout;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            Ok(None) => std::thread::sleep(SUBPROCESS_POLL_INTERVAL),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("{operation} wait failed: {error}"),
                ));
            }
        }
    }
    // The child has exited (or has been killed), so `wait_with_output`
    // returns immediately and drains the pipes to EOF.
    let output = child.wait_with_output().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("{operation} output could not be read: {error}"),
        )
    })?;
    if timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("{operation} did not finish within {timeout:?} and was killed"),
        ));
    }
    Ok(output)
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn CreateMutexW(
        attributes: *mut std::ffi::c_void,
        initial_owner: i32,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut std::ffi::c_void) -> i32;
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time;

    use crate::{
        conf::Conf,
        cs::list::{Query, list_compute_systems},
    };

    use super::*;

    #[test]
    fn scsi_slots_are_deterministic_before_disk_creation() {
        assert_eq!(scsi_slot(0).expect("first SCSI slot"), (0, 0));
        assert_eq!(
            scsi_slot(63).expect("last slot on first controller"),
            (0, 63)
        );
        assert_eq!(
            scsi_slot(64).expect("first slot on second controller"),
            (1, 0)
        );
    }

    #[test]
    fn disk_cleanup_refuses_a_replaced_file() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("scratch.vhdx");
        let replacement = root.join("replacement.vhdx");
        std::fs::write(&path, b"first").expect("write first file");
        std::fs::write(&replacement, b"replacement").expect("write replacement file");
        let original_identity =
            crate::journal::file_identity(&path).expect("read original identity");
        std::fs::remove_file(&path).expect("remove original file");
        std::fs::rename(&replacement, &path).expect("replace file");

        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: vm_model::disk::DiskRetention::Ephemeral,
            effective_retention: vm_model::disk::DiskRetention::Ephemeral,
            file_identity: Some(original_identity),
            initialization_requested: true,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: false,
        };
        assert!(remove_disk(Uuid::nil(), &disk).is_err());
        assert!(path.exists(), "replacement file must not be deleted");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_cleanup_keeps_published_persistent_files() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("persistent.vhdx");
        std::fs::write(&path, b"persistent").expect("write persistent file");
        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: vm_model::disk::DiskRetention::Persistent,
            effective_retention: vm_model::disk::DiskRetention::Persistent,
            file_identity: None,
            initialization_requested: false,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: true,
        };
        remove_disk(Uuid::nil(), &disk).expect("published persistent file is retained");
        assert!(path.exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_cleanup_deletes_unpublished_persistent_created_files() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("unpublished.vhdx");
        std::fs::write(&path, b"rollback state").expect("write file");
        let identity = crate::journal::file_identity(&path).expect("read identity");
        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: vm_model::disk::DiskRetention::Persistent,
            effective_retention: vm_model::disk::DiskRetention::Persistent,
            file_identity: Some(identity),
            initialization_requested: true,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: false,
        };
        remove_disk(Uuid::nil(), &disk).expect("unpublished created persistent file is deletable");
        assert!(!path.exists(), "rollback state must be removed");
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_cleanup_never_deletes_pre_existing_files() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("existing.vhdx");
        std::fs::write(&path, b"pre-existing").expect("write file");
        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::PreExisting,
            requested_retention: vm_model::disk::DiskRetention::Ephemeral,
            effective_retention: vm_model::disk::DiskRetention::Persistent,
            file_identity: None,
            initialization_requested: false,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: true,
        };
        remove_disk(Uuid::nil(), &disk).expect("pre-existing disk is never deleted");
        assert!(path.exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_cleanup_refuses_deletion_without_a_recorded_identity() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("noidentity.vhdx");
        std::fs::write(&path, b"no identity recorded").expect("write file");
        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: vm_model::disk::DiskRetention::Ephemeral,
            effective_retention: vm_model::disk::DiskRetention::Ephemeral,
            file_identity: None,
            initialization_requested: true,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: false,
        };
        assert!(remove_disk(Uuid::nil(), &disk).is_err());
        assert!(
            path.exists(),
            "file without recorded identity must not be deleted"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_cleanup_reports_identity_change_with_a_typed_error() {
        let root = std::env::temp_dir().join(format!("jyth-disk-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let path = root.join("replaced.vhdx");
        let replacement = root.join("replacement.vhdx");
        std::fs::write(&path, b"first").expect("write first file");
        std::fs::write(&replacement, b"replacement").expect("write replacement file");
        let original_identity =
            crate::journal::file_identity(&path).expect("read original identity");
        std::fs::remove_file(&path).expect("remove original file");
        std::fs::rename(&replacement, &path).expect("replace file");
        let disk = crate::journal::DiskResource {
            path: path.as_os_str().to_os_string(),
            controller: 0,
            lun: 0,
            state: crate::journal::ResourceState::Created,
            origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
            requested_retention: vm_model::disk::DiskRetention::Ephemeral,
            effective_retention: vm_model::disk::DiskRetention::Ephemeral,
            file_identity: Some(original_identity),
            initialization_requested: true,
            initialization_acknowledged: false,
            vm_ace_added: false,
            published: false,
        };
        let error = remove_disk(Uuid::nil(), &disk).expect_err("replaced file must be refused");
        assert_eq!(*error.current_context(), HcsError::DiskIdentityChanged);
        assert!(path.exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_materialization_matrix_covers_every_classification() {
        use vm_model::disk::{DiskRetention as Retention, ExistingDiskPolicy as Policy};
        assert_eq!(
            classify_disk(false, Retention::Ephemeral, Policy::ReuseAndKeep),
            DiskMaterialization::Create
        );
        assert_eq!(
            classify_disk(false, Retention::Persistent, Policy::ReuseAndKeep),
            DiskMaterialization::Create
        );
        assert_eq!(
            classify_disk(true, Retention::Persistent, Policy::ReuseAndKeep),
            DiskMaterialization::Reuse
        );
        assert_eq!(
            classify_disk(true, Retention::Ephemeral, Policy::ReuseAndKeep),
            DiskMaterialization::ReuseAndReclassify
        );
        assert_eq!(
            classify_disk(true, Retention::Ephemeral, Policy::Error),
            DiskMaterialization::RejectExisting
        );
        assert_eq!(
            classify_disk(true, Retention::Persistent, Policy::Error),
            DiskMaterialization::RejectExisting
        );
    }

    #[test]
    fn empty_or_missing_disk_list_plans_no_disk_and_no_directory() {
        let root = std::env::temp_dir().join(format!("jyth-diskplan-{}", Uuid::now_v7()));
        let none = plan_disk_resources(Uuid::nil(), None).expect("None plans zero disks");
        assert!(none.is_empty());
        let empty = plan_disk_resources(Uuid::nil(), Some(&[])).expect("empty plans zero disks");
        assert!(empty.is_empty());
        assert!(
            !root.exists(),
            "planning a no-disk launch must not create any directory"
        );
    }

    #[test]
    fn disk_plan_records_requested_retention_and_normalized_path() {
        let root = std::env::temp_dir().join(format!("jyth-diskplan-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let target = root.join("data.vhdx");
        let spec = vm_model::disk::DiskSpec::new(
            root.join(r".\nested\..\data.vhdx"),
            4096,
            vm_model::disk::GuestMount::new("/data").expect("valid mount"),
            vm_model::disk::DiskRetention::Persistent,
            vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
        )
        .expect("valid spec");
        let planned = plan_disk_resources(Uuid::nil(), Some(&[spec])).expect("plan one disk");
        assert_eq!(planned.len(), 1);
        assert_eq!(
            planned[0].requested_retention,
            vm_model::disk::DiskRetention::Persistent
        );
        let expected =
            crate::journal::normalize_absolute_path(&target).expect("normalize expected path");
        assert_eq!(Path::new(&planned[0].path), expected);
        assert_eq!(planned[0].state, crate::journal::ResourceState::Planned);
        assert_eq!((planned[0].controller, planned[0].lun), (0, 0));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn per_path_lock_names_are_deterministic_and_distinct() {
        let first = Path::new(r"C:\disks\build.vhdx");
        let second = Path::new(r"C:\disks\build.vhdx");
        let other = Path::new(r"C:\disks\other.vhdx");
        assert_eq!(path_lock_name(first), path_lock_name(second));
        assert_ne!(path_lock_name(first), path_lock_name(other));
        assert!(path_lock_name(first).starts_with("Local\\jyth-disk-"));
        assert_eq!(path_lock_name(first).len(), "Local\\jyth-disk-".len() + 64);
    }

    #[test]
    fn path_lock_acquisition_times_out_on_a_held_lock() {
        // A mutex is recursively acquirable by its OWNING thread, so the
        // lock must be held by a different thread for the timeout to trip.
        let path = Path::new(r"C:\disks\held.vhdx");
        let name = path_lock_name(path);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
            let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 1, wide.as_ptr()) };
            assert!(!handle.is_null(), "test mutex must be created");
            let _ = acquired_tx.send(());
            let _ = release_rx.recv();
            unsafe {
                ReleaseMutex(handle);
                CloseHandle(handle);
            }
        });
        acquired_rx
            .recv()
            .expect("holder thread must acquire the test mutex");

        let result = PathLock::acquire_with_timeout(path, 100);

        let _ = release_tx.send(());
        holder.join().expect("holder thread exits");
        let error = result.expect_err("a lock held by another thread must time out");
        assert_eq!(error.current_context(), &HcsError::DiskPathAlreadyClaimed);
        let attachment = error
            .frames()
            .filter_map(|frame| match frame.kind() {
                error_stack::FrameKind::Attachment(error_stack::AttachmentKind::Printable(
                    value,
                )) => Some(value.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            attachment.contains("timed out after 100 ms"),
            "the error must name the timeout: {attachment}"
        );
    }

    #[test]
    fn absent_classification_requires_the_hresult_not_localized_text() {
        let whitelisted = Report::new(HcsError::Cleanup).attach("element not found (0x80070490)");
        assert!(resource_is_absent(&whitelisted));
        let file_whitelisted = Report::new(HcsError::Cleanup).attach("0x80070002");
        assert!(resource_is_absent(&file_whitelisted));
        let text_only = Report::new(HcsError::Cleanup).attach("the system cannot find the file");
        assert!(
            !resource_is_absent(&text_only),
            "localized error text alone must not classify absence"
        );
        let unrelated = Report::new(HcsError::Cleanup).attach("access is denied (0x80070005)");
        assert!(!resource_is_absent(&unrelated));
    }

    #[test]
    fn bounded_subprocess_kills_a_hanging_command() {
        // `Start-Sleep` is a single process: killing it closes the piped
        // stdout/stderr, so the post-kill drain terminates immediately.
        // (A shell wrapper like `cmd /C ping …` would outlive the kill as
        // a grandchild holding the pipes open.)
        let started = std::time::Instant::now();
        let result = run_bounded_with_timeout(
            std::process::Command::new("powershell.exe").args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ]),
            "injected hanging command",
            std::time::Duration::from_millis(300),
        );
        let elapsed = started.elapsed();
        let error = result.expect_err("the hanging command must be killed by the timeout");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            error.to_string().contains("injected hanging command"),
            "the timeout error must name the operation: {error}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "the wait must be bounded, took {elapsed:?}"
        );
    }

    fn cleanup_test_journal(name: &str) -> (PathBuf, crate::journal::SessionJournal) {
        let root = std::env::temp_dir().join(format!("jyth-{name}-{}", Uuid::now_v7()));
        let journal = crate::journal::SessionJournal::create_current(&root, Uuid::now_v7())
            .expect("create journal");
        (root, journal)
    }

    fn compute_record(
        vm_id: Uuid,
        state: crate::journal::ResourceState,
        id: &str,
    ) -> crate::journal::VmResourceRecord {
        crate::journal::VmResourceRecord {
            schema_version: crate::journal::SCHEMA_VERSION,
            vm_id,
            phase: crate::journal::VmResourcePhase::CleanupPending,
            published: false,
            compute_system: crate::journal::ComputeResource {
                id: id.to_string(),
                state,
            },
            network: None,
            disks: Vec::new(),
            cleanup_attempts: 0,
            last_error: None,
        }
    }

    async fn absent_compute_hook(_id: String) -> Result<(), Report<HcsError>> {
        // Real HCS absence surfaces with the whitelisted HRESULT; the
        // classification must not depend on localized text.
        Err(Report::new(HcsError::ComputeSystemOpen)
            .attach("compute system not found (HRESULT 0x80070002)"))
    }

    async fn failing_compute_hook(_id: String) -> Result<(), Report<HcsError>> {
        Err(Report::new(HcsError::ComputeSystemTerminate).attach("access is denied"))
    }

    #[tokio::test]
    async fn cleanup_of_an_already_absent_resource_transitions_to_removed() {
        let (root, journal) = cleanup_test_journal("absent");
        let vm_id = Uuid::now_v7();
        journal
            .put_vm(&compute_record(
                vm_id,
                crate::journal::ResourceState::Created,
                "missing-system",
            ))
            .expect("write record");
        let mut summary = CleanupSummary::default();

        let result = cleanup_record_async_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            absent_compute_hook,
            |_, _, _, _| unreachable!("no network planned"),
            |_, _| unreachable!("no disks planned"),
            &mut summary,
        )
        .await;

        result.expect("an already-absent resource must not fail cleanup");
        assert_eq!(
            summary,
            CleanupSummary {
                absent: 1,
                ..CleanupSummary::default()
            },
            "the pass counts one absent transition"
        );
        assert!(
            journal.vm(vm_id).expect("read record").is_none(),
            "the record completes and is removed"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn persistent_failure_abandons_the_record_after_three_attempts() {
        let (root, journal) = cleanup_test_journal("abandon");
        let vm_id = Uuid::now_v7();
        let identity = "persistent-system".to_string();
        journal
            .put_vm(&compute_record(
                vm_id,
                crate::journal::ResourceState::Created,
                &identity,
            ))
            .expect("write record");
        let mut summary = CleanupSummary::default();

        let first = cleanup_record_async_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            failing_compute_hook,
            |_, _, _, _| unreachable!("no network planned"),
            |_, _| unreachable!("no disks planned"),
            &mut summary,
        )
        .await;
        assert!(first.is_err(), "the first failed pass stays retry-able");
        let record = journal
            .vm(vm_id)
            .expect("read record")
            .expect("record exists");
        assert_eq!(record.cleanup_attempts, 1);
        assert_eq!(
            record.compute_system.state,
            crate::journal::ResourceState::RemovalFailed
        );
        assert_eq!(summary.failed, 1);

        let second = cleanup_record_async_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            failing_compute_hook,
            |_, _, _, _| unreachable!("no network planned"),
            |_, _| unreachable!("no disks planned"),
            &mut summary,
        )
        .await;
        assert!(second.is_err(), "the second failed pass stays retry-able");
        let record = journal
            .vm(vm_id)
            .expect("read record")
            .expect("record exists");
        assert_eq!(record.cleanup_attempts, 2);
        assert_eq!(summary.failed, 2);

        let third = cleanup_record_async_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            failing_compute_hook,
            |_, _, _, _| unreachable!("no network planned"),
            |_, _| unreachable!("no disks planned"),
            &mut summary,
        )
        .await;
        third.expect("exhausted attempts return success: the record is terminal");
        assert_eq!(summary.failed, 3);
        assert_eq!(summary.abandoned, 1);

        let record = journal
            .vm(vm_id)
            .expect("read record")
            .expect("record exists");
        assert_eq!(record.cleanup_attempts, 3);
        assert_eq!(
            record.compute_system.state,
            crate::journal::ResourceState::Abandoned
        );
        assert!(
            record.is_complete(),
            "an abandoned record is terminal for GC"
        );
        let last_error = record
            .last_error
            .as_deref()
            .expect("abandoned record persists last_error");
        assert!(
            last_error.contains(&identity),
            "last_error names the exact resource identity: {last_error}"
        );

        let inventory = journal
            .abandoned(vm_id)
            .expect("read inventory")
            .expect("inventory row exists");
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].kind, "compute_system");
        assert_eq!(inventory.entries[0].identity, identity);
        assert!(
            inventory.entries[0]
                .last_error
                .contains("resource_kind=compute_system"),
            "the inventory last_error is self-describing"
        );
        assert!(inventory.entries[0].last_error.contains("access is denied"));
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn session_file_is_garbage_collected_when_all_records_are_terminal() {
        let root = std::env::temp_dir().join(format!("jyth-gc-{}", Uuid::now_v7()));
        let session_id = Uuid::now_v7();
        let stale_path = crate::journal::session_path(&root, session_id);
        {
            let journal = crate::journal::SessionJournal::create_current(&root, session_id)
                .expect("create stale session");
            let vm_id = Uuid::now_v7();
            journal
                .put_vm(&compute_record(
                    vm_id,
                    crate::journal::ResourceState::Removed,
                    "cleaned-system",
                ))
                .expect("write terminal record");
        }
        assert!(stale_path.exists(), "the stale session file exists");
        let current_path = crate::journal::session_path(&root, Uuid::now_v7());

        reconcile_stale_sessions(&root, &current_path)
            .await
            .expect("reconcile succeeds");

        assert!(
            !stale_path.exists(),
            "a fully terminal session file must be garbage collected"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[tokio::test]
    async fn explicit_cleanup_attempts_abandoned_resources_and_clears_the_inventory() {
        let (root, journal) = cleanup_test_journal("explicit-abandoned");
        let vm_id = Uuid::now_v7();
        let disk_path = root.join("abandoned.vhdx");
        std::fs::write(&disk_path, b"abandoned").expect("write disk file");
        let identity = crate::journal::file_identity(&disk_path).expect("read disk identity");
        let record = crate::journal::VmResourceRecord {
            schema_version: crate::journal::SCHEMA_VERSION,
            vm_id,
            phase: crate::journal::VmResourcePhase::CleanupPending,
            published: false,
            compute_system: crate::journal::ComputeResource {
                id: vm_id.to_string(),
                state: crate::journal::ResourceState::Removed,
            },
            network: None,
            disks: vec![crate::journal::DiskResource {
                path: disk_path.as_os_str().to_os_string(),
                controller: 0,
                lun: 0,
                state: crate::journal::ResourceState::Abandoned,
                origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
                requested_retention: vm_model::disk::DiskRetention::Ephemeral,
                effective_retention: vm_model::disk::DiskRetention::Ephemeral,
                file_identity: Some(identity),
                initialization_requested: false,
                initialization_acknowledged: false,
                vm_ace_added: false,
                published: false,
            }],
            cleanup_attempts: crate::journal::MAX_CLEANUP_ATTEMPTS,
            last_error: Some("abandoned after 3 cleanup attempts".to_string()),
        };
        journal.put_vm(&record).expect("write record");
        journal
            .put_abandoned(&crate::journal::AbandonedRecord {
                schema_version: crate::journal::SCHEMA_VERSION,
                vm_id,
                entries: vec![crate::journal::AbandonedResourceEntry {
                    kind: "disk".to_string(),
                    identity: record.disks[0].path.to_string_lossy().into_owned(),
                    last_error: "resource_kind=disk operation=remove cause=access is denied"
                        .to_string(),
                    first_abandoned_at_unix_ms: crate::journal::unix_time_ms(),
                }],
            })
            .expect("write inventory row");
        let mut summary = CleanupSummary::default();

        let result = cleanup_record_async_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            |_id| async move { unreachable!("compute system already removed") },
            |_, _, _, _| unreachable!("no network planned"),
            remove_disk,
            &mut summary,
        )
        .await;

        result.expect("explicit cleanup of an abandoned resource succeeds");
        assert_eq!(
            summary,
            CleanupSummary {
                recovered: 1,
                ..CleanupSummary::default()
            }
        );
        assert!(
            !disk_path.exists(),
            "the abandoned disk file was actually removed"
        );
        assert!(
            journal.vm(vm_id).expect("read record").is_none(),
            "the record completes"
        );
        assert!(
            journal.abandoned(vm_id).expect("read inventory").is_none(),
            "successful explicit cleanup leaves the abandoned inventory"
        );
        assert!(
            !journal.has_abandoned().expect("inventory query"),
            "no abandoned inventory remains"
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn sync_cleanup_of_an_already_absent_resource_transitions_to_removed() {
        let (root, journal) = cleanup_test_journal("absent-sync");
        let vm_id = Uuid::now_v7();
        journal
            .put_vm(&compute_record(
                vm_id,
                crate::journal::ResourceState::Created,
                "missing-system",
            ))
            .expect("write record");
        let mut summary = CleanupSummary::default();

        let result = cleanup_record_sync_with(
            &journal,
            vm_id,
            CleanupResources::empty(),
            |_id| {
                // Real HCS absence surfaces with the whitelisted HRESULT;
                // the classification must not depend on localized text.
                Err(Report::new(HcsError::ComputeSystemOpen)
                    .attach("compute system does not exist (HRESULT 0x80070002)"))
            },
            |_, _, _, _| unreachable!("no network planned"),
            |_, _| unreachable!("no disks planned"),
            &mut summary,
        );

        result.expect("an already-absent resource must not fail sync cleanup");
        assert_eq!(summary.absent, 1);
        assert!(journal.vm(vm_id).expect("read record").is_none());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    /// Boots a real HCS VM (needs a Hyper-V host + admin), so it's
    /// gated behind `#[ignore]` — same gate as its sibling
    /// `from_conf_attaches_network_and_vm_boots`. Without `--ignored`
    /// `cargo test` skips it; otherwise HCS rejects the create with
    /// `HRESULT 0x80070003` (`ERROR_PATH_NOT_FOUND`) when the staged
    /// kernel/initrd referenced here aren't present at the repo root.
    #[tokio::test]
    async fn test_vm_shutdown_cleans_up_hcs_system() {
        let start = time::SystemTime::now();

        let root = std::env::temp_dir().join(format!("jyth-live-{}", Uuid::now_v7()));
        let session = Session::open(&root).await.expect("open test session");

        let kernel =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\kernel.bin");
        let initrd =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\initrd.img");

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(256)
            .vcpus(1)
            .parms("console=ttyS0");

        println!(
            "[{:?}] [TEST]: Creating VM",
            time::SystemTime::now().duration_since(start).unwrap()
        );
        // Since the runtime journal, VMs carry the per-session owner
        // `jyth/v1/<session-uuid>`, not the legacy plain `jyth` owner —
        // assert against the exact session owner of the created VM.
        let vm_registered = |owner: String, vm_id: Uuid| async move {
            let query = Query {
                owners: vec![owner],
            };
            // Fresh cancellation root per recovery probe: the enumeration
            // always runs to completion here (design D3, cs/list fresh roots).
            let systems = list_compute_systems(&query, &CancellationToken::new())
                .await
                .unwrap_or_default();
            systems.iter().any(|cs| cs.id == vm_id.to_string())
        };
        let (owner, vm_id);
        {
            let vm = Vm::from_conf(&session, conf, None, None)
                .await
                .expect("[TEST] create vm fail");
            owner = vm.journal.owner();
            vm_id = vm.id;

            println!(
                "[{:?}] [TEST]: VM created",
                time::SystemTime::now().duration_since(start).unwrap()
            );

            assert!(
                vm_registered(owner.clone(), vm_id).await,
                "VM should exist in HCS right after creation"
            );

            println!(
                "[{:?}] [TEST]: VM exists in HCS",
                time::SystemTime::now().duration_since(start).unwrap()
            );
        }
        println!(
            "[{:?}] [TEST]: VM shutdown",
            time::SystemTime::now().duration_since(start).unwrap()
        );

        // 4. Verify it's actually gone from HCS
        assert!(
            !vm_registered(owner, vm_id).await,
            "VM should not exist in HCS after shutdown"
        );
        std::fs::remove_dir_all(&root).expect("remove test root");
    }

    /// Task I-3 metric: `cargo test -p hypervisor -- --ignored
    /// net_lifecycle` exits 0. Gated by `#[ignore]` because it boots a
    /// real HCS VM (needs a Hyper-V host + admin). Asserts:
    /// 1. `from_conf(..., Some(&Nat))` succeeds — meaning HCS accepted
    ///    the config, which it would refuse (CreateComputeSystem
    ///    returns HRESULT) if the `NetworkAdapters` reference pointed at
    ///    no endpoint. So an HCS entry proves the adapter was wired.
    /// 2. HCS shows the VM after construction.
    /// 3. After the `Vm` drops, HCS shows no remaining VM *and*
    ///    `Get-HnsNetwork | Where Name -like 'jyth-nat-*'` returns
    ///    empty — i.e. our lifecycle-owned NAT network was torn down
    ///    with the VM, no orphans survive.
    #[tokio::test]
    async fn from_conf_attaches_network_and_vm_boots() {
        let root = std::env::temp_dir().join(format!("jyth-live-{}", Uuid::now_v7()));
        let session = Session::open(&root).await.expect("open test session");

        let kernel =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\kernel.bin");
        let initrd =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\initrd.img");

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(256)
            .vcpus(1)
            .parms("console=ttyS0");

        let nat = vm_model::network::Nat::default();
        let vm_registered = |owner: String, vm_id: Uuid| async move {
            let query = Query {
                owners: vec![owner],
            };
            // Fresh cancellation root per recovery probe: the enumeration
            // always runs to completion here (design D3, cs/list fresh roots).
            let systems = list_compute_systems(&query, &CancellationToken::new())
                .await
                .unwrap_or_default();
            systems.iter().any(|cs| cs.id == vm_id.to_string())
        };
        let (owner, vm_id);
        {
            let vm = Vm::from_conf(&session, conf, Some(&nat), None)
                .await
                .expect("[TEST] from_conf with network failed");
            owner = vm.journal.owner();
            vm_id = vm.id;

            // (1) HCS accepted the config — proves the NetworkAdapters
            // block was wired correctly (CreateComputeSystem rejects a
            // dangling endpoint id).
            assert!(
                vm_registered(owner.clone(), vm_id).await,
                "[TEST] VM with NIC must register in HCS"
            );
        }
        // (2) After drop: no VM, no jyth-nat-* HNS network.
        assert!(
            !vm_registered(owner, vm_id).await,
            "[TEST] VM gone from HCS after drop"
        );

        let hns_orphans = jyth_nat_network_names();
        assert!(
            hns_orphans.is_empty(),
            "[TEST] orphan jyth-nat-* HNS networks after drop: {hns_orphans:?}"
        );
        std::fs::remove_dir_all(&root).expect("remove test root");
    }

    /// Live HCS test: after `Vm::from_conf` registers a real compute
    /// system, the COM1 bus pipe must carry the deny-by-default descriptor
    /// containing the exact per-VM identity ACE (`S-1-5-83-...` derived
    /// from the VM GUID) plus SYSTEM, and no `WD`/`BA` ACE. This is the
    /// first live proof of Work package S's named-pipe descriptors: the
    /// VM worker is expected to bind COM1 under that identity.
    ///
    /// Serialization: like its siblings, run with
    /// `cargo test -p hypervisor -- --ignored --test-threads=1`. The
    /// crate has no in-crate lock guard (the e2e suite owns one), so do
    /// not run this concurrently with other live HCS tests.
    #[tokio::test]
    async fn com1_pipe_dacl_contains_vm_identity_after_launch() {
        let root = std::env::temp_dir().join(format!("jyth-live-{}", Uuid::now_v7()));
        let session = Session::open(&root).await.expect("open test session");

        let kernel =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\kernel.bin");
        let initrd =
            Path::new("C:\\home\\projects\\ayth\\jyth\\tests\\fixtures\\assets\\initrd.img");

        let conf = Conf::new()
            .kernel(kernel)
            .initrd(initrd)
            .memory(256)
            .vcpus(1)
            .parms("console=ttyS0");

        let vm = Vm::from_conf(&session, conf, None, None)
            .await
            .expect("[TEST] create vm fail");
        // The single-instance COM1 pipe is already connected by the VM
        // worker, so the DACL cannot be reopened by name — assert on the
        // snapshot taken from the server handle at creation time.
        let aces = vm
            .bus_pipe_aces
            .as_ref()
            .expect("[TEST] COM1 bus-pipe DACL snapshot exists");
        let vm_sid = crate::security::vm_identity_sid(vm.id);
        assert!(
            aces.iter().any(|ace| ace.sid == vm_sid),
            "[TEST] COM1 pipe DACL must contain the per-VM identity ACE {vm_sid}: {aces:?}"
        );
        assert!(
            aces.iter().any(|ace| ace.sid == "S-1-5-18"),
            "[TEST] COM1 pipe DACL must contain SYSTEM: {aces:?}"
        );
        assert!(
            !aces.iter().any(|ace| ace.sid == "WD" || ace.sid == "BA"),
            "[TEST] COM1 pipe DACL must not contain WD/BA ACEs: {aces:?}"
        );
        std::fs::remove_dir_all(&root).expect("remove test root");
    }

    /// Reads the host's HNS network list (via PowerShell's built-in
    /// `Get-HnsNetwork` cmdlet on Windows Server 2016+) and returns
    /// the names of every `jyth-nat-*` network present. Used by the
    /// `--ignored` net-lifecycle test to assert no orphan NAT network
    /// survives the `Vm` drop — the rollback-safety metric of
    /// Plan §I-3.
    fn jyth_nat_network_names() -> Vec<String> {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-HnsNetwork | Select-Object -ExpandProperty Name",
            ])
            .output()
            .expect("[TEST] powershell Get-HnsNetwork invocation failed");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("jyth-nat-"))
            .collect()
    }
}
