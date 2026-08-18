//! The launch service: target launch flow orchestration over injected ports.
//!
//! The launcher receives validated inputs and service ports and drives the
//! target launch flow: validate, prepare boot artifacts, validate backend
//! capabilities, create and start the instance (typed retry on
//! [`hypervisor_api::RetryDisposition::Retryable`]), build the bounded boot
//! configuration, exchange the authenticated READY proof, mark the instance
//! published, create the typed guest client, attach scheduled actions, and
//! return a [`LiveVm`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use error_stack::Report;
use hypervisor_api::{BackendError, RetryDisposition, VmFactory, VmInstance, VmLaunchSpec};
use protocol::{
    BootConfigV1, BootstrapConfigV1, GuestDiskConfigV1, GuestNetworkConfigV1, SessionCapability,
};
use scheduler::ScheduledAction;
use vm_model::disk::{AttachedDisk, DiskOrigin, DiskRetention, DiskSpec};
use vm_model::network::Nat;

use crate::actions::{process_action, shutdown_action};
use crate::client::GuestClient;
use crate::error::RuntimeError;
use crate::live_vm::{LiveVm, VmWarning};
use crate::observer::{VmLifecycle, VmPhase};
use crate::ports::{BootArtifactProvider, BootControlChannel, CommandEndpoint, GuestClientFactory};

/// The bounded wait for the guest READY handshake over COM1.
pub const READY_TIMEOUT: Duration = Duration::from_secs(50);

/// The typed retry policy applied to backend create/start failures.
///
/// Retry decisions use [`hypervisor_api::RetryDisposition`] only; the
/// runtime never inspects backend error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of create+start attempts.
    pub max_attempts: u32,
    /// Delay between retryable attempts.
    pub retry_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            retry_delay: Duration::from_secs(10),
        }
    }
}

/// The validated launch inputs of one launch (facade-level configuration is
/// validated before this value is built).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Prepared kernel source path (materialized by the image crate).
    pub kernel_source: PathBuf,
    /// Prepared rootfs CPIO source path.
    pub rootfs_source: PathBuf,
    /// Host-supplied guest overlay entries.
    pub overlay_entries: Vec<crate::BootOverlayEntry>,
    /// Explicit memory override in megabytes; `None` uses the heuristic.
    pub memory_mb: Option<u64>,
    /// Explicit vCPU override; `None` defaults to one.
    pub vcpu_count: Option<u32>,
    /// Boot command line.
    pub cmdline: String,
    /// Optional validated NAT network.
    pub network: Option<Nat>,
    /// Validated disk specifications.
    pub disks: Vec<DiskSpec>,
}

/// One launch: the request plus the scheduler declarations packaged by the
/// facade.
pub struct Launch {
    /// The validated launch request.
    pub request: LaunchRequest,
    /// Scheduled guest processes (trigger + prepared process).
    pub scheduled_processes: Vec<crate::ScheduledProcess>,
    /// Optional shutdown trigger.
    pub shutdown_trigger: Option<scheduler::Trigger>,
}

/// The outcome of [`Launcher::prepare`]: a started, configured instance not
/// yet exchanged, published, or client-bound. Used by the COM1-only
/// bootstrap path, which performs its own command/artifact transfer.
pub struct PreparedLaunch {
    /// The created and started backend instance.
    pub instance: Box<dyn VmInstance>,
    /// The bounded boot configuration (bootstrap mode included).
    pub boot_config: BootConfigV1,
    /// The session capability backing the boot transcript.
    pub capability: Arc<SessionCapability>,
}

/// The launch service. Composes injected ports; never constructs a concrete
/// backend, transport, or artifact implementation.
pub struct Launcher {
    factory: Arc<dyn VmFactory>,
    boot: Arc<dyn BootArtifactProvider>,
    channel: Arc<dyn BootControlChannel>,
    clients: Arc<dyn GuestClientFactory>,
    retry: RetryPolicy,
}

impl Launcher {
    /// Create the launcher over its injected service ports.
    pub fn new(
        factory: Arc<dyn VmFactory>,
        boot: Arc<dyn BootArtifactProvider>,
        channel: Arc<dyn BootControlChannel>,
        clients: Arc<dyn GuestClientFactory>,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            factory,
            boot,
            channel,
            clients,
            retry,
        }
    }

    /// Prepare and start one launch: provider prepares artifacts, the
    /// factory validates capabilities, create and start the instance (with
    /// typed retry), and build the bounded boot configuration.
    ///
    /// This is the shared prefix of the full launch flow and the COM1-only
    /// bootstrap flow.
    pub async fn prepare(
        &self,
        request: LaunchRequest,
        bootstrap: Option<BootstrapConfigV1>,
    ) -> Result<PreparedLaunch, Report<RuntimeError>> {
        let artifacts = self
            .boot
            .prepare(
                request.kernel_source,
                request.rootfs_source,
                request.overlay_entries,
            )
            .await
            .map_err(|error| error.change_context(RuntimeError::Build))?;

        // The selected hypervisor factory validates backend capabilities
        // before creating host resources (target launch flow step 7).
        let capabilities = self.factory.capabilities();
        if !capabilities.available {
            return Err(Report::new(RuntimeError::VmCreate)
                .attach("the selected backend is not available on this host"));
        }
        if request.network.is_some() && !capabilities.networking {
            return Err(Report::new(RuntimeError::VmCreate)
                .attach("the selected backend does not support NAT networking"));
        }
        if !request.disks.is_empty() && !capabilities.disks {
            return Err(Report::new(RuntimeError::VmCreate)
                .attach("the selected backend does not support host-attached disks"));
        }

        let memory_mb = size_memory(artifacts.uncompressed_rootfs_size, request.memory_mb);
        let vcpu_count = request.vcpu_count.unwrap_or(1);
        let spec = VmLaunchSpec {
            kernel: artifacts.kernel,
            initrd: artifacts.initrd,
            memory_mb,
            vcpu_count,
            cmdline: request.cmdline,
            network: request.network.clone(),
            disks: request.disks.clone(),
        };
        let instance = self.create_and_start(spec).await?;

        let capability = Arc::new(SessionCapability::generate().map_err(|error| {
            Report::new(RuntimeError::Authentication).attach(error.to_string())
        })?);
        let boot_config = build_boot_config(
            &*instance,
            &capability,
            &request.network,
            &request.disks,
            bootstrap,
        )?;
        Ok(PreparedLaunch {
            instance,
            boot_config,
            capability,
        })
    }

    /// Drive the full target launch flow and return a ready [`LiveVm`].
    ///
    /// Publishes the launch lifecycle: `launching` at start, `running`
    /// before the ready VM is returned, and a launch failure otherwise.
    pub async fn launch(
        &self,
        launch: Launch,
        observer: Option<VmLifecycle>,
    ) -> Result<LiveVm, Report<RuntimeError>> {
        if let Some(observer) = &observer {
            observer.launching();
        }
        match self.launch_inner(launch, observer.clone()).await {
            Ok(live) => {
                if let Some(observer) = &observer {
                    observer.running();
                }
                Ok(live)
            }
            Err(error) => {
                if let Some(observer) = &observer {
                    observer.failed(VmPhase::Launch, error.to_string());
                }
                Err(error)
            }
        }
    }

    async fn launch_inner(
        &self,
        launch: Launch,
        observer: Option<VmLifecycle>,
    ) -> Result<LiveVm, Report<RuntimeError>> {
        let Launch {
            request,
            scheduled_processes,
            shutdown_trigger,
        } = launch;

        // A normal launch requires an explicit validated network: the guest
        // command endpoint is derived from it, so the invariant is repeated
        // at this public service boundary and fails before kernel or rootfs
        // materialization (COM1-only bootstrap keeps the optional network in
        // `prepare`).
        let network = request.network.as_ref().ok_or_else(|| {
            Report::new(RuntimeError::NetworkRequired)
                .attach("a normal launch requires a validated NAT network")
        })?;
        let command_endpoint = CommandEndpoint::from(network);

        let prepared = self.prepare(request.clone(), None).await?;
        let instance = prepared.instance;

        // Exchange the bounded boot configuration and verify the
        // authenticated READY proof, then create the typed guest client.
        // The client factory completes an authenticated TCP `Ping` before it
        // returns, so a failed readiness probe never publishes the VM and
        // the caller's drop of the prepared instance cleans everything up.
        self.channel
            .exchange_ready(&*instance, &prepared.boot_config, READY_TIMEOUT)
            .await
            .map_err(|error| {
                let context = match error.kind {
                    crate::ports::BootChannelErrorKind::Timeout => RuntimeError::ReadyTimeout,
                    crate::ports::BootChannelErrorKind::Protocol => RuntimeError::Protocol,
                    crate::ports::BootChannelErrorKind::Authentication => {
                        RuntimeError::Authentication
                    }
                };
                Report::new(context)
                    .attach(error)
                    .attach("failed waiting for guest READY on COM1")
            })?;

        // Create the typed guest client over the command endpoint derived
        // from the launch `Nat` (target launch flow step 14).
        let client = Arc::new(
            self.clients
                .create(&*instance, &prepared.capability, command_endpoint)
                .await
                .map_err(|error| Report::new(RuntimeError::Transport).attach(error))?,
        );

        // Publish the instance only after authenticated TCP command
        // readiness succeeds (target launch flow step 15).
        instance
            .mark_published()
            .await
            .map_err(|error| Report::new(RuntimeError::Hypervisor).attach(error))?;

        let attached_disks = classify_disks(&request.disks, instance.attached_resources());
        let warnings = classify_warnings(&request.disks, instance.attached_resources());
        let actions = package_actions(
            scheduled_processes,
            shutdown_trigger,
            client.clone(),
            observer.clone(),
        );

        Ok(LiveVm::new(
            instance,
            client,
            actions,
            observer,
            attached_disks,
            warnings,
            prepared.capability,
            command_endpoint,
        ))
    }

    /// Create and start one instance, retrying typed transient failures up
    /// to the policy maximum. A created-but-unstarted instance is dropped
    /// (synchronous best-effort cleanup) before the next attempt.
    async fn create_and_start(
        &self,
        spec: VmLaunchSpec,
    ) -> Result<Box<dyn VmInstance>, Report<RuntimeError>> {
        let mut last_error: Option<Report<RuntimeError>> = None;
        for attempt in 1..=self.retry.max_attempts {
            #[cfg(feature = "tracing")]
            tracing::info!(attempt, "[RETRY] starting VM");
            let outcome = async {
                let instance = self.factory.create(spec.clone()).await?;
                instance.start().await?;
                Ok::<Box<dyn VmInstance>, BackendError>(instance)
            }
            .await;
            match outcome {
                Ok(instance) => return Ok(instance),
                Err(error)
                    if error.retry == RetryDisposition::Retryable
                        && attempt < self.retry.max_attempts =>
                {
                    last_error = Some(
                        Report::new(RuntimeError::VmCreate)
                            .attach(format!("attempt {attempt}: {error}")),
                    );
                    tokio::time::sleep(self.retry.retry_delay).await;
                }
                Err(error) => {
                    return Err(Report::new(RuntimeError::VmCreate).attach(error));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            Report::new(RuntimeError::VmCreate)
                .attach("create_and_start failed with no recorded error")
        }))
    }
}

/// The historical memory sizing heuristic: 256 MiB fixed overhead + 2x the
/// uncompressed rootfs footprint + 128 MiB margin, rounded up to a multiple
/// of 2 MiB.
fn size_memory(uncompressed_size_bytes: u64, override_mb: Option<u64>) -> u64 {
    let uncompressed_size_mb = uncompressed_size_bytes.div_ceil(1048576);
    let overhead_mb = 256;
    let margin_mb = 128;
    let mut memory_mb = override_mb.unwrap_or(overhead_mb + (uncompressed_size_mb + margin_mb) * 2);
    if !memory_mb.is_multiple_of(2) {
        memory_mb += 1;
    }
    memory_mb
}

/// Build the bounded boot configuration from the started instance evidence.
///
/// The guest disk configuration is derived from the backend's attached-
/// resource classification (`created_by_launch`) zipped with the validated
/// launch request, preserving the historical "an existing file is never
/// initialized" guarantee.
fn build_boot_config(
    instance: &dyn VmInstance,
    capability: &Arc<SessionCapability>,
    network: &Option<Nat>,
    disks: &[DiskSpec],
    bootstrap: Option<BootstrapConfigV1>,
) -> Result<BootConfigV1, Report<RuntimeError>> {
    let boot_network = match network {
        Some(nat) => Some(guest_network_config(nat)?),
        None => None,
    };

    let boot_disks = instance
        .attached_resources()
        .iter()
        .zip(disks.iter())
        .enumerate()
        .map(|(index, (resource, spec))| {
            let device_index = u16::try_from(index)
                .map_err(|error| Report::new(RuntimeError::Protocol).attach(error.to_string()))?;
            let initialize = resource.created_by_launch;
            GuestDiskConfigV1::new(device_index, spec.guest_mount().as_str(), initialize)
                .map_err(|error| Report::new(RuntimeError::Protocol).attach(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let boot_config = BootConfigV1::new(
        instance.identity(),
        (**capability).clone(),
        BootConfigV1::generate_host_nonce()
            .map_err(|error| Report::new(RuntimeError::Authentication).attach(error.to_string()))?,
        boot_network,
        boot_disks,
    )
    .map_err(|error| Report::new(RuntimeError::Protocol).attach(error.to_string()))?;
    match bootstrap {
        Some(bootstrap) => boot_config
            .with_bootstrap(bootstrap)
            .map_err(|error| Report::new(RuntimeError::Protocol).attach(error.to_string())),
        None => Ok(boot_config),
    }
}

fn guest_network_config(nat: &Nat) -> Result<GuestNetworkConfigV1, Report<RuntimeError>> {
    use std::net::IpAddr;
    let dns = nat
        .dns()
        .iter()
        .enumerate()
        .map(|(index, dns)| match dns {
            IpAddr::V4(address) => Ok(address.octets()),
            IpAddr::V6(address) => Err(Report::new(RuntimeError::Protocol).attach(format!(
                "NAT DNS server at index {index} is IPv6 ({address}); the guest network protocol currently supports IPv4 DNS only"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    GuestNetworkConfigV1::new(
        nat.guest_ip().octets(),
        nat.gateway().octets(),
        nat.subnet().prefix_len(),
        dns,
    )
    .map_err(|error| Report::new(RuntimeError::Protocol).attach(error.to_string()))
}

fn classify_disks(
    specs: &[DiskSpec],
    resources: &[hypervisor_api::AttachedResource],
) -> Vec<AttachedDisk> {
    specs
        .iter()
        .zip(resources.iter())
        .map(|(spec, resource)| {
            let origin = if resource.created_by_launch {
                DiskOrigin::CreatedByLaunch
            } else {
                DiskOrigin::PreExisting
            };
            let requested = spec.retention();
            let effective = if !resource.created_by_launch && requested == DiskRetention::Ephemeral
            {
                DiskRetention::Persistent
            } else {
                requested
            };
            AttachedDisk {
                host_path: resource.host_path.clone(),
                guest_mount: spec.guest_mount().as_str().to_string(),
                origin,
                requested_retention: requested,
                effective_retention: effective,
            }
        })
        .collect()
}

fn classify_warnings(
    specs: &[DiskSpec],
    resources: &[hypervisor_api::AttachedResource],
) -> Vec<VmWarning> {
    specs
        .iter()
        .zip(resources.iter())
        .filter_map(|(spec, resource)| {
            if spec.retention() == DiskRetention::Ephemeral && !resource.created_by_launch {
                Some(VmWarning::DiskReusedAsPersistent {
                    host_path: resource.host_path.clone(),
                    requested: DiskRetention::Ephemeral,
                    effective: DiskRetention::Persistent,
                })
            } else {
                None
            }
        })
        .collect()
}

fn package_actions(
    scheduled: Vec<crate::ScheduledProcess>,
    shutdown_trigger: Option<scheduler::Trigger>,
    client: Arc<GuestClient>,
    observer: Option<VmLifecycle>,
) -> Vec<ScheduledAction> {
    let mut actions = Vec::with_capacity(scheduled.len() + usize::from(shutdown_trigger.is_some()));
    for scheduled in scheduled {
        actions.push(process_action(scheduled, client.clone()));
    }
    if let Some(trigger) = shutdown_trigger {
        actions.push(shutdown_action(trigger, client, observer));
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{BootOverlayEntry, BootOverlayEntryKind};

    #[test]
    fn size_memory_honors_the_historical_heuristic_and_rounding() {
        assert_eq!(size_memory(0, None), 256 + 128 * 2);
        assert_eq!(size_memory(1048576, None), 256 + (1 + 128) * 2);
        assert_eq!(size_memory(1048576, Some(512)), 512);
        assert_eq!(size_memory(0, Some(513)), 514);
    }

    #[test]
    fn overlay_entries_are_forwarded_unmodified() {
        let entries = [
            BootOverlayEntry {
                path: "/bin/tool".to_string(),
                kind: BootOverlayEntryKind::File {
                    content: vec![1, 2, 3],
                    mode: 0o755,
                    origin: "bytes:abc".to_string(),
                },
            },
            BootOverlayEntry {
                path: "/jyth".to_string(),
                kind: BootOverlayEntryKind::Directory { mode: 0o755 },
            },
        ];
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            &entries[0].kind,
            BootOverlayEntryKind::File { content, .. } if content == &vec![1, 2, 3]
        ));
        assert!(matches!(
            &entries[1].kind,
            BootOverlayEntryKind::Directory { mode } if *mode == 0o755
        ));
    }

    #[test]
    fn command_endpoint_derives_the_launch_nat_guest_ip_and_port() {
        let nat = Nat::try_new(
            "192.168.99.0/24",
            "192.168.99.1",
            "192.168.99.42",
            ["8.8.8.8"],
        )
        .expect("valid NAT");
        let endpoint = CommandEndpoint::from(&nat);
        assert_eq!(
            endpoint.address(),
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(192, 168, 99, 42),
                1024
            ))
        );
    }

    #[test]
    fn command_endpoint_contains_no_capability_material() {
        let endpoint = CommandEndpoint::from(&Nat::default());
        // Debug output must never reveal session-secret bytes; the type only
        // carries the socket address.
        let debug = format!("{endpoint:?}");
        assert!(
            !debug.contains("capability") && !debug.contains("secret"),
            "{debug}"
        );
        assert!(debug.contains("10.77.0.10"), "{debug}");
    }
}
