//! Default adapters for the runtime service ports (SolidArchitecturePlan
//! WP7, WP9).
//!
//! The jyth facade composes the concrete infrastructure implementations as
//! local newtypes implementing the runtime-owned ports and the
//! hypervisor-api contracts:
//!
//! - [`HcsBootArtifactProvider`] wraps `boot-image` assembly and the derived
//!   run-cache orchestration;
//! - [`HcsBootControlChannel`] wraps the COM1 boot exchange (named pipes +
//!   the platform-selected `hypervisor::Vm` handle);
//! - [`HcsVmFactory`]/[`HcsInstance`] wrap `hypervisor::Vm::new_with_session`/
//!   `start`/`mark_published`/`close` into the host-neutral contracts and
//!   classify transient memory failures through
//!   [`hypervisor_api::RetryDisposition`] at this boundary (no string matching
//!   above it);
//! - [`TcpGuestClientFactory`] builds the TCP endpoint, completes the
//!   authenticated readiness probe, and constructs the guest-client
//!   dispatcher and the runtime's [`GuestClient`].
//!
//! The COM1-only bootstrap transfer ([`run_com1_bootstrap`]) also lives
//! here: it needs the concrete named pipe and the HCS handle internals, so
//! the runtime never touches them.

use std::path::PathBuf;
use std::sync::Arc;

use com::TcpEndpoint;
use error_stack::Report;
use guest_client::{CommandTransport, Dispatcher, StreamTransport};
use hypervisor::hypervisor_api::{
    AttachedResource, BackendCapabilities, BackendError, BackendErrorCategory, CloseFuture,
    CreateFuture, PublishFuture, RetryDisposition, StartFuture, VmFactory, VmInstance,
    VmLaunchSpec,
};
use jyth_runtime::{
    ArtifactError, BootArtifactProvider, BootChannelError, BootControlChannel, BootOverlayEntry,
    ClientError, GuestClient, GuestClientFactory, PreparedBootArtifacts,
};
use protocol::{
    BootConfigV1, BootstrapResultV1, COM1_READY_MAGIC, Command, MAX_AUTH_FRAME,
    MAX_BOOT_CONFIG_FRAME, MAX_BOOTSTRAP_ARTIFACT_BYTES, MAX_BOOTSTRAP_CHUNK, ReadyV1,
};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::adapters::transport::TcpTransport;
use crate::builder::BootstrapTimings;
use crate::error::{ApiError, ApiResult};

// ---------------------------------------------------------------------------
// HcsVmFactory / HcsInstance
// ---------------------------------------------------------------------------

/// The default hypervisor factory over the platform-selected
/// [`hypervisor::Vm`] (HCS on Windows; the experimental KVM handle reports
/// typed unsupported results). Owns the explicit runtime
/// [`hypervisor::Session`] every created VM is opened within; there is no
/// process-global session in the library anymore.
pub(crate) struct HcsVmFactory {
    session: Arc<hypervisor::Session>,
}

impl HcsVmFactory {
    fn new(session: Arc<hypervisor::Session>) -> Self {
        Self { session }
    }
}

/// The concrete instance returned by [`HcsVmFactory`]: the platform-selected
/// backend handle plus its classified attached-resource evidence. The handle
/// is `Arc`-owned so the object-safe contract futures (`'static`) can hold
/// it without borrowing the instance.
pub(crate) struct HcsInstance {
    pub(crate) vm: Arc<hypervisor::Vm>,
    resources: Vec<AttachedResource>,
}

impl VmFactory for HcsVmFactory {
    fn capabilities(&self) -> BackendCapabilities {
        // The supported Windows/HCS backend implements the v0.1 capability
        // set. The experimental KVM backend is rejected before any instance
        // by the platform gate and by its own unavailable advertisement.
        BackendCapabilities {
            available: true,
            networking: true,
            disks: true,
        }
    }

    fn create(&self, spec: VmLaunchSpec) -> CreateFuture {
        let session = self.session.clone();
        Box::pin(async move {
            let vm = hypervisor::Vm::new_with_session(
                &session,
                &spec.kernel,
                &spec.initrd,
                spec.memory_mb,
                spec.vcpu_count,
                &spec.cmdline,
                spec.network.as_ref(),
                (!spec.disks.is_empty()).then_some(spec.disks.as_slice()),
            )
            .await
            .map_err(|report| backend_error(BackendErrorCategory::Create, &report))?;
            let resources = attached_resources_of(&vm);
            Ok(Box::new(HcsInstance {
                vm: Arc::new(vm),
                resources,
            }) as Box<dyn VmInstance>)
        })
    }
}

impl VmInstance for HcsInstance {
    fn identity(&self) -> uuid::Uuid {
        self.vm.uuid()
    }

    fn attached_resources(&self) -> &[AttachedResource] {
        &self.resources
    }

    fn start(&self) -> StartFuture {
        let vm = self.vm.clone();
        Box::pin(async move {
            vm.start()
                .await
                .map_err(|report| backend_error(BackendErrorCategory::Start, &report))
        })
    }

    fn mark_published(&self) -> PublishFuture {
        let vm = self.vm.clone();
        Box::pin(async move {
            vm.mark_published()
                .map_err(|report| backend_error(BackendErrorCategory::Publication, &report))
        })
    }

    fn close(self: Box<Self>) -> CloseFuture {
        Box::pin(async move {
            let vm = Arc::try_unwrap(self.vm).map_err(|_| {
                BackendError::permanent(
                    BackendErrorCategory::Close,
                    "the backend instance handle is still shared",
                )
            })?;
            vm.close()
                .await
                .map_err(|report| backend_error(BackendErrorCategory::Close, &report))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The classified attached-resource evidence of the platform handle.
fn attached_resources_of(vm: &hypervisor::Vm) -> Vec<AttachedResource> {
    #[cfg(target_os = "windows")]
    {
        vm.attached_disks()
            .iter()
            .map(|disk| AttachedResource {
                host_path: disk.host_path.clone(),
                created_by_launch: disk.origin == vm_model::disk::DiskOrigin::CreatedByLaunch,
            })
            .collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        vm.attached_disks().to_vec()
    }
}

/// Build the stable backend report for a platform backend failure.
///
/// The transient-memory classification lives at this boundary: the
/// "Insufficient system resources" HCS text is matched HERE and translated
/// into [`RetryDisposition::Retryable`] once; no code above this adapter
/// inspects backend error text.
fn backend_error(
    category: BackendErrorCategory,
    report: &error_stack::Report<impl std::fmt::Display + std::fmt::Debug>,
) -> BackendError {
    let message = report.to_string();
    let retry = if is_transient_backend_text(&message) {
        RetryDisposition::Retryable
    } else {
        RetryDisposition::Permanent
    };
    BackendError::new(category, retry, message)
}

/// Returns `true` if the rendered report looks like HCS's transient
/// "Insufficient system resources exist to complete the requested service"
/// error. The match is on the documented substring so it survives small
/// wording changes in the HCS error text; the underlying reports are
/// preserved as attached frames.
fn is_transient_backend_text(message: &str) -> bool {
    message.contains("Insufficient system resources exist to complete the requested service")
        || message.contains("Insufficient system resources")
}

// ---------------------------------------------------------------------------
// HcsBootArtifactProvider
// ---------------------------------------------------------------------------

/// The default boot-artifact provider: wraps `boot-image` assembly and the
/// derived run-cache orchestration (per-run `kernel.bin` + `initrd.img`
/// publication and the uncompressed-rootfs size used by the memory
/// heuristic).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HcsBootArtifactProvider;

impl BootArtifactProvider for HcsBootArtifactProvider {
    fn prepare(
        &self,
        kernel_source: PathBuf,
        rootfs_source: PathBuf,
        overlay_entries: Vec<BootOverlayEntry>,
    ) -> jyth_runtime::ArtifactFuture {
        Box::pin(async move {
            let entries = overlay_entries
                .into_iter()
                .map(to_guest_overlay_entry)
                .collect::<Vec<_>>();
            // Cooperative-cancellation root for the boot assembly: the drop
            // guard cancels it the moment this future ends — success, error,
            // or being dropped — so a still-running init-build worker bails
            // at its entry check (abort alone cannot stop a worker thread).
            let cancel = CancellationToken::new();
            let _cancel_guard = cancel.clone().drop_guard();
            let prepared = boot_image::prepare_boot_artifacts(
                kernel_source.clone(),
                rootfs_source.clone(),
                entries,
                &cancel,
            )
            .await
            .map_err(|report| {
                report.change_context(ArtifactError::new(format!(
                    "filed on {:?}, {:?}",
                    kernel_source, rootfs_source
                )))
            })?;

            // Per-run working directory (kernel.bin + initrd.img). The
            // identity is based on file contents, not source paths,
            // so equivalent images share a run artifact while changed bytes
            // cannot reuse stale output.
            let kernel_artifact = boot_image::cache::artifact_metadata(&prepared.kernel)
                .map_err(artifact_cache_error)?;
            let rootfs_artifact = boot_image::cache::artifact_metadata(&prepared.rootfs)
                .map_err(artifact_cache_error)?;
            let compression = boot_image::cache::initrd_compression_metadata();
            let run_id =
                boot_image::cache::run_cache_id(&kernel_artifact, &rootfs_artifact, &compression);
            let run_dir = boot_image::cache::runs_dir()
                .map_err(artifact_cache_error)?
                .join(run_id);
            std::fs::create_dir_all(&run_dir).map_err(artifact_cache_error)?;

            let kernel_file_path = run_dir.join("kernel.bin");
            let initrd_path = run_dir.join("initrd.img");
            let uncompressed_size_bytes: u64;

            if let Some(cached_size) = boot_image::cache::cached_run_uncompressed_size(
                &run_dir,
                &prepared.rootfs,
                &kernel_artifact,
                &rootfs_artifact,
                &compression,
            ) {
                #[cfg(feature = "tracing")]
                tracing::info!(dir = %run_dir.display(), "[CACHE] Using existing cached kernel and initrd");
                uncompressed_size_bytes = cached_size;
            } else {
                // kernel.bin: copy the prepared raw bzImage atomically.
                boot_image::cache::atomic_copy(&prepared.kernel, &kernel_file_path)
                    .map_err(artifact_cache_error)?;

                // initrd.img: stream the prepared rootfs cpio through gzip
                // and publish the complete artifact atomically without
                // retaining the uncompressed rootfs or compressed output in
                // host memory.
                let uncompressed_size = boot_image::cache::atomic_gzip(
                    &prepared.rootfs,
                    &initrd_path,
                    compression.level,
                )
                .map_err(artifact_initrd_error)?;
                uncompressed_size_bytes = uncompressed_size;
                boot_image::cache::publish_run_metadata(
                    &run_dir,
                    kernel_artifact,
                    rootfs_artifact,
                    &initrd_path,
                    uncompressed_size_bytes,
                    compression,
                )
                .map_err(artifact_initrd_error)?;
            }

            Ok(PreparedBootArtifacts {
                kernel: kernel_file_path,
                initrd: initrd_path,
                uncompressed_rootfs_size: uncompressed_size_bytes,
            })
        })
    }
}

fn to_guest_overlay_entry(entry: BootOverlayEntry) -> boot_image::GuestOverlayEntry {
    match entry.kind {
        jyth_runtime::BootOverlayEntryKind::File {
            content,
            mode,
            origin,
        } => boot_image::GuestOverlayEntry::file(entry.path, content, mode, origin),
        jyth_runtime::BootOverlayEntryKind::Directory { mode } => {
            boot_image::GuestOverlayEntry::directory(entry.path, mode)
        }
    }
}

fn artifact_cache_error(error: impl std::fmt::Display) -> ArtifactError {
    ArtifactError::new(format!("failed to access the Jyth derived cache: {error}"))
}

fn artifact_initrd_error(error: impl std::fmt::Display) -> ArtifactError {
    ArtifactError::new(format!("failed to assemble the initrd: {error}"))
}

// ---------------------------------------------------------------------------
// HcsBootControlChannel
// ---------------------------------------------------------------------------

/// The default boot-control channel: exchanges the bounded boot
/// configuration over the protected COM1 named pipe and verifies the
/// authenticated READY proof. The concrete backend handle is recovered
/// through [`VmInstance::as_any`], keeping the port host-neutral.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HcsBootControlChannel;

impl BootControlChannel for HcsBootControlChannel {
    fn exchange_ready(
        &self,
        instance: &dyn VmInstance,
        boot_config: &BootConfigV1,
        timeout: std::time::Duration,
    ) -> jyth_runtime::ReadyFuture {
        // Extract every owned piece synchronously so the boxed future is
        // `'static`: the shared backend handle, the serialized boot frame,
        // and the session capability.
        let Some(hcs) = instance.as_any().downcast_ref::<HcsInstance>() else {
            return Box::pin(async move {
                Err(BootChannelError::protocol(
                    "the boot channel cannot access the backend instance",
                ))
            });
        };
        let vm = hcs.vm.clone();
        let boot_frame = match boot_config.to_bytes() {
            Ok(frame) if frame.len() <= MAX_BOOT_CONFIG_FRAME => frame,
            Ok(_) => {
                return Box::pin(async move {
                    Err(BootChannelError::protocol(
                        "boot configuration exceeds the COM1 frame limit",
                    ))
                });
            }
            Err(error) => {
                return Box::pin(async move { Err(BootChannelError::protocol(error.to_string())) });
            }
        };
        let capability = boot_config.capability.clone();
        Box::pin(async move {
            wait_for_ready(&vm, timeout, &boot_frame, &capability)
                .await
                .map_err(|error| {
                    let message = error.to_string();
                    match error.current_context() {
                        ApiError::ReadyTimeout => BootChannelError::timeout(message),
                        ApiError::Protocol => BootChannelError::protocol(message),
                        ApiError::Authentication => BootChannelError::authentication(message),
                        _ => BootChannelError::protocol(message),
                    }
                })
        })
    }
}

/// Sends the bounded versioned boot configuration over COM1 and waits for
/// the guest init to return an authenticated READY proof (moved from the
/// jyth crate root, WP7 action 4). The guest sends READY after applying the
/// configuration and binding the TCP command bus, so receiving it is a
/// strict guarantee that the configured guest control plane is up.
///
/// The boot frame is pre-serialized by the caller (the boot-control channel
/// adapter), so the future only borrows the frame bytes and the session
/// capability.
#[cfg_attr(
    feature = "tracing",
    instrument(skip(vm_handle), fields(timeout_ms = timeout.as_millis() as u64), level = "debug")
)]
async fn wait_for_ready(
    vm_handle: &hypervisor::Vm,
    timeout: std::time::Duration,
    boot_frame: &[u8],
    capability: &protocol::SessionCapability,
) -> ApiResult<()> {
    #[cfg(target_os = "windows")]
    {
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let endpoint = vm_handle
            .bus_pipe_name
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let pipe = vm_handle.take_bus_pipe().ok_or_else(|| {
            ready_timeout_frames(
                Report::new(ApiError::ReadyTimeout).attach("COM1 bus pipe already taken"),
                "wait_for_ready",
                timeout,
                "connect",
                timeout,
                &endpoint,
            )
        })?;
        let connect_result = tokio::time::timeout(timeout, pipe.connect()).await;
        let mut pipe = match connect_result {
            Ok(Ok(())) => pipe,
            Ok(Err(e)) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("COM1 pipe connect failed: {e}")),
                    "wait_for_ready",
                    timeout,
                    "connect",
                    timeout,
                    &endpoint,
                ));
            }
            Err(_) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("timed out connecting to COM1 pipe ({timeout:?})")),
                    "wait_for_ready",
                    timeout,
                    "connect",
                    timeout,
                    &endpoint,
                ));
            }
        };

        let start = Instant::now();
        let mut com1_ready = vec![0u8; 4 + COM1_READY_MAGIC.len()];
        let remaining = timeout.checked_sub(start.elapsed()).unwrap_or_default();
        match tokio::time::timeout(remaining, pipe.read_exact(&mut com1_ready)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("COM1 readiness marker read failed: {error}")),
                    "wait_for_ready",
                    timeout,
                    "read_ready_marker",
                    remaining,
                    &endpoint,
                ));
            }
            Err(_) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout).attach(format!(
                        "timed out waiting for guest COM1 readiness ({timeout:?})"
                    )),
                    "wait_for_ready",
                    timeout,
                    "read_ready_marker",
                    remaining,
                    &endpoint,
                ));
            }
        }
        let marker_len = u32::from_le_bytes(com1_ready[..4].try_into().unwrap()) as usize;
        if marker_len != COM1_READY_MAGIC.len() || com1_ready[4..] != *COM1_READY_MAGIC {
            return Err(
                Report::new(ApiError::Protocol).attach("guest COM1 readiness marker was invalid")
            );
        }

        let boot_len = u32::try_from(boot_frame.len()).map_err(|_| {
            Report::new(ApiError::Protocol).attach("boot frame length does not fit u32")
        })?;
        let mut boot_wire = Vec::with_capacity(4 + boot_frame.len());
        boot_wire.extend_from_slice(&boot_len.to_le_bytes());
        boot_wire.extend_from_slice(boot_frame);
        let remaining = timeout.checked_sub(start.elapsed()).unwrap_or_default();
        match tokio::time::timeout(remaining, pipe.write_all(&boot_wire)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("COM1 boot frame write failed: {error}")),
                    "wait_for_ready",
                    timeout,
                    "write_boot_config",
                    remaining,
                    &endpoint,
                ));
            }
            Err(_) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout).attach(format!(
                        "timed out sending COM1 boot configuration ({timeout:?})"
                    )),
                    "wait_for_ready",
                    timeout,
                    "write_boot_config",
                    remaining,
                    &endpoint,
                ));
            }
        }

        let mut length_bytes = [0u8; 4];
        let remaining = timeout.checked_sub(start.elapsed()).unwrap_or_default();
        match tokio::time::timeout(remaining, pipe.read_exact(&mut length_bytes)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("COM1 READY length read failed: {error}")),
                    "wait_for_ready",
                    timeout,
                    "read_ready_length",
                    remaining,
                    &endpoint,
                ));
            }
            Err(_) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("timed out waiting for guest READY ({timeout:?})")),
                    "wait_for_ready",
                    timeout,
                    "read_ready_length",
                    remaining,
                    &endpoint,
                ));
            }
        }
        let ready_len = u32::from_le_bytes(length_bytes) as usize;
        if ready_len > MAX_AUTH_FRAME {
            return Err(Report::new(ApiError::Protocol).attach(format!(
                "READY frame length {ready_len} exceeds {MAX_AUTH_FRAME}"
            )));
        }
        let mut ready_frame = Vec::new();
        ready_frame
            .try_reserve_exact(ready_len)
            .map_err(|_| Report::new(ApiError::Protocol).attach("READY frame allocation failed"))?;
        ready_frame.resize(ready_len, 0);
        let remaining = timeout.checked_sub(start.elapsed()).unwrap_or_default();
        match tokio::time::timeout(remaining, pipe.read_exact(&mut ready_frame)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("COM1 READY frame read failed: {error}")),
                    "wait_for_ready",
                    timeout,
                    "read_ready_frame",
                    remaining,
                    &endpoint,
                ));
            }
            Err(_) => {
                return Err(ready_timeout_frames(
                    Report::new(ApiError::ReadyTimeout)
                        .attach(format!("timed out waiting for guest READY ({timeout:?})")),
                    "wait_for_ready",
                    timeout,
                    "read_ready_frame",
                    remaining,
                    &endpoint,
                ));
            }
        }

        let ready = ReadyV1::try_from(ready_frame.as_slice())
            .map_err(|error| Report::new(ApiError::Protocol).attach(error.to_string()))?;
        ready
            .verify(capability, boot_frame)
            .map_err(|error| Report::new(ApiError::Authentication).attach(error.to_string()))?;
        #[cfg(feature = "tracing")]
        tracing::info!("[CONNECT] received authenticated READY from guest on COM1");
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (vm_handle, timeout, boot_frame, capability);
        Err(Report::new(ApiError::ReadyTimeout)
            .attach("wait_for_ready: COM1 READY wait not implemented on non-Windows"))
    }
}

// ---------------------------------------------------------------------------
// TcpGuestClientFactory
// ---------------------------------------------------------------------------

/// The default guest-client factory: completes one authenticated TCP `Ping`
/// against the guest command endpoint, then builds the guest-client
/// dispatcher and the runtime's typed [`GuestClient`].
///
/// The readiness probe runs before any dispatcher task is created, so a
/// failed probe leaves no partially created task behind and the runtime
/// never publishes the VM.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TcpGuestClientFactory;

impl GuestClientFactory for TcpGuestClientFactory {
    fn create(
        &self,
        instance: &dyn VmInstance,
        capability: &protocol::SessionCapability,
        command_endpoint: jyth_runtime::CommandEndpoint,
    ) -> jyth_runtime::ClientFuture {
        let uuid = instance.identity();
        let capability = Arc::new(capability.clone());
        Box::pin(async move {
            let endpoint = TcpEndpoint::new(command_endpoint.address(), uuid, capability);

            // Readiness probe: one authenticated Ping that must answer
            // Event::VMReady. Every arrow after TCP connect stays bounded by
            // the transport connect/auth deadlines and the guest-client
            // request timeout, so a silent guest cannot block launch.
            let reply = endpoint
                .command_async(Command::Ping)
                .await
                .map_err(|_error| {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        address = %command_endpoint.address(),
                        error = %_error,
                        "TCP readiness probe failed; the VM will not be published"
                    );
                    ClientError::Create
                })?;
            if reply != protocol::Event::VMReady {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    address = %command_endpoint.address(),
                    reply = reply.kind(),
                    "TCP readiness probe expected Event::VMReady; the VM will not be published"
                );
                return Err(ClientError::Create);
            }

            let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<guest_client::HostRequest>(32);
            let dispatcher_cancel = CancellationToken::new();
            let transport: Arc<dyn CommandTransport> = Arc::new(TcpTransport(endpoint.clone()));
            let dispatcher = Dispatcher::new(cmd_rx, transport, dispatcher_cancel.clone());
            let event_loop_task = tokio::spawn(dispatcher.run());
            let streams: Arc<dyn StreamTransport> = Arc::new(TcpTransport(endpoint));
            Ok(GuestClient::new(
                cmd_tx,
                streams,
                dispatcher_cancel,
                event_loop_task,
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// COM1-only bootstrap transfer
// ---------------------------------------------------------------------------

/// Run one authenticated guest command without opening the normal TCP command bus,
/// then stream its declared artifact over the already-connected COM1 pipe.
///
/// This is deliberately a separate bootstrap API. The normal launch path
/// binds the guest TCP command listener on the configured NIC address;
/// this COM1-only path is used by the internal `binaries/kernel-builder`
/// tool to produce the very first kernel image before any TCP listener or
/// network is needed.
#[cfg_attr(
    feature = "tracing",
    instrument(
        skip(vm_handle, boot_config, output),
        fields(vm_id = %vm_handle.uuid()),
        level = "debug"
    )
)]
pub(crate) async fn run_com1_bootstrap(
    vm_handle: &hypervisor::Vm,
    ready_timeout: std::time::Duration,
    boot_config: &BootConfigV1,
    output: &std::path::Path,
    transfer_timeout: std::time::Duration,
) -> ApiResult<BootstrapTimings> {
    #[cfg(target_os = "windows")]
    {
        use std::time::Instant;
        use tokio::io::AsyncWriteExt;
        #[cfg(feature = "tracing")]
        use tracing::Instrument;

        let boot_frame = boot_config
            .to_bytes()
            .map_err(|error| Report::new(ApiError::Protocol).attach(error.to_string()))?;
        if boot_frame.len() > MAX_BOOT_CONFIG_FRAME {
            return Err(Report::new(ApiError::Protocol)
                .attach("boot configuration exceeds the COM1 frame limit"));
        }

        #[cfg(feature = "tracing")]
        tracing::info!(vm_id = %vm_handle.uuid(), "[BOOTSTRAP] connecting COM1");
        let endpoint = vm_handle
            .bus_pipe_name
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let t0 = Instant::now();
        let pipe = connect_com1(vm_handle, ready_timeout).await?;
        let connect = t0.elapsed();
        let mut pipe =
            exchange_boot_and_ready(pipe, ready_timeout, boot_config, &boot_frame, &endpoint)
                .await?;
        let ready_exchange = t0.elapsed() - connect;
        #[cfg(feature = "tracing")]
        tracing::info!(
            vm_id = %vm_handle.uuid(),
            "[BOOTSTRAP] guest READY received; waiting for result"
        );
        let phase_start = Instant::now();
        #[cfg(feature = "tracing")]
        let guest_command_span =
            tracing::info_span!("bootstrap.guest_command", vm_id = %vm_handle.uuid());
        let result_frame_future = async {
            read_com1_frame(
                &mut pipe,
                remaining(transfer_timeout, phase_start),
                MAX_AUTH_FRAME,
                "bootstrap result",
                ApiError::Bootstrap,
            )
            .await
        };
        #[cfg(feature = "tracing")]
        let result_frame_future = result_frame_future.instrument(guest_command_span);

        let result_frame = result_frame_future.await?;
        let result = BootstrapResultV1::try_from(result_frame.as_slice())
            .map_err(|error| Report::new(ApiError::Protocol).attach(error.to_string()))?;
        #[cfg(feature = "tracing")]
        tracing::info!(
            vm_id = %vm_handle.uuid(),
            status = result.status,
            artifact_len = result.artifact_len,
            "[BOOTSTRAP] result received"
        );
        if result.status != BootstrapResultV1::SUCCESS {
            return Err(Report::new(ApiError::Bootstrap).attach(format!(
                "bootstrap command failed with status {} and exit code {:?}",
                result.status, result.exit_code
            )));
        }
        if result.artifact_len == 0 || result.artifact_len > MAX_BOOTSTRAP_ARTIFACT_BYTES {
            return Err(Report::new(ApiError::Protocol).attach(format!(
                "bootstrap artifact length {} is outside its bounds",
                result.artifact_len
            )));
        }
        let guest_command = phase_start.elapsed();

        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let file_name = output.file_name().ok_or_else(|| {
            Report::new(ApiError::Bootstrap).attach("bootstrap output has no file name")
        })?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| Report::new(ApiError::Io).attach(error.to_string()))?;
        let staging = parent.join(format!(
            ".{}.jyth-bootstrap-{}.part",
            file_name.to_string_lossy(),
            vm_handle.uuid()
        ));

        #[cfg(feature = "tracing")]
        let transfer_span = tracing::info_span!(
            "bootstrap.artifact_transfer",
            vm_id = %vm_handle.uuid(),
            artifact_len = result.artifact_len
        );
        let transfer_future = async {
            const TRANSFER_PROGRESS_INTERVAL_BYTES: u64 = 2 * 1024 * 1024;
            #[cfg(feature = "tracing")]
            let transfer_started = Instant::now();
            let mut artifact = tokio::fs::File::create(&staging)
                .await
                .map_err(|error| Report::new(ApiError::Io).attach(error.to_string()))?;
            let mut hasher = blake3::Hasher::new();
            let mut received = 0u64;
            let mut next_progress_log = TRANSFER_PROGRESS_INTERVAL_BYTES;
            while received < result.artifact_len {
                let frame = read_com1_frame(
                    &mut pipe,
                    remaining(transfer_timeout, phase_start),
                    MAX_BOOTSTRAP_CHUNK,
                    "bootstrap artifact chunk",
                    ApiError::Bootstrap,
                )
                .await?;
                if frame.is_empty() {
                    return Err(Report::new(ApiError::Protocol)
                        .attach("bootstrap artifact stream contained an empty chunk"));
                }
                let remaining_bytes = result.artifact_len - received;
                if u64::try_from(frame.len()).unwrap_or(u64::MAX) > remaining_bytes {
                    return Err(Report::new(ApiError::Protocol)
                        .attach("bootstrap artifact stream exceeded its declared length"));
                }
                artifact
                    .write_all(&frame)
                    .await
                    .map_err(|error| Report::new(ApiError::Io).attach(error.to_string()))?;
                hasher.update(&frame);
                received += frame.len() as u64;
                if received >= next_progress_log || received == result.artifact_len {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        bytes = received,
                        total = result.artifact_len,
                        percent = received * 100 / result.artifact_len,
                        "artifact transfer progress"
                    );
                    next_progress_log =
                        next_progress_log.saturating_add(TRANSFER_PROGRESS_INTERVAL_BYTES);
                }
            }
            artifact
                .flush()
                .await
                .map_err(|error| Report::new(ApiError::Io).attach(error.to_string()))?;
            artifact
                .sync_all()
                .await
                .map_err(|error| Report::new(ApiError::Io).attach(error.to_string()))?;
            // The staging handle must be closed before the replacement on
            // Windows; the strict helper then publishes the complete file
            // without ever deleting the previous destination first.
            drop(artifact);

            if hasher.finalize().as_bytes() != result.artifact_digest.as_slice() {
                return Err(Report::new(ApiError::Protocol)
                    .attach("bootstrap artifact digest did not match its result envelope"));
            }

            // Strict atomic replacement (F-04): the previous output remains
            // present until one atomic replacement succeeds. The helper never
            // calls remove_file(destination); on failure the staging sibling
            // is left for the caller to clean up.
            image_core::ops::io::replace_file_atomically(&staging, output).map_err(|error| {
                Report::new(ApiError::Io)
                    .attach(error.to_string())
                    .attach("operation=bootstrap_output_publish")
                    .attach(format!("destination={}", output.display()))
            })?;
            #[cfg(feature = "tracing")]
            tracing::info!(
                bytes = received,
                total = result.artifact_len,
                elapsed_ms = transfer_started.elapsed().as_millis() as u64,
                "artifact transfer complete"
            );
            Ok::<(), Report<ApiError>>(())
        };
        #[cfg(feature = "tracing")]
        let transfer_future = transfer_future.instrument(transfer_span);

        let transfer = transfer_future.await;

        if transfer.is_err() {
            let _ = tokio::fs::remove_file(&staging).await;
        }
        let artifact_transfer = phase_start.elapsed() - guest_command;
        transfer?;
        Ok(BootstrapTimings {
            connect,
            ready_exchange,
            guest_command,
            artifact_transfer,
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (
            vm_handle,
            ready_timeout,
            boot_config,
            output,
            transfer_timeout,
        );
        Err(Report::new(ApiError::Bootstrap)
            .attach("COM1 bootstrap is only implemented for the HCS Windows backend"))
    }
}

#[cfg(target_os = "windows")]
#[cfg_attr(
    feature = "tracing",
    instrument(skip_all, fields(vm_id = %vm_handle.uuid()), level = "debug")
)]
async fn connect_com1(
    vm_handle: &hypervisor::Vm,
    timeout: std::time::Duration,
) -> ApiResult<tokio::net::windows::named_pipe::NamedPipeServer> {
    let endpoint = vm_handle
        .bus_pipe_name
        .as_deref()
        .unwrap_or("unknown")
        .to_string();
    let pipe = vm_handle.take_bus_pipe().ok_or_else(|| {
        ready_timeout_frames(
            Report::new(ApiError::ReadyTimeout).attach("COM1 bus pipe already taken"),
            "connect_com1",
            timeout,
            "connect",
            timeout,
            &endpoint,
        )
    })?;
    match tokio::time::timeout(timeout, pipe.connect()).await {
        Ok(Ok(())) => Ok(pipe),
        Ok(Err(error)) => Err(ready_timeout_frames(
            Report::new(ApiError::ReadyTimeout)
                .attach(format!("COM1 pipe connect failed: {error}")),
            "connect_com1",
            timeout,
            "connect",
            timeout,
            &endpoint,
        )),
        Err(_) => Err(ready_timeout_frames(
            Report::new(ApiError::ReadyTimeout)
                .attach(format!("timed out connecting to COM1 pipe ({timeout:?})")),
            "connect_com1",
            timeout,
            "connect",
            timeout,
            &endpoint,
        )),
    }
}

#[cfg(target_os = "windows")]
#[cfg_attr(feature = "tracing", instrument(skip_all, level = "debug"))]
async fn exchange_boot_and_ready(
    mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    timeout: std::time::Duration,
    boot_config: &BootConfigV1,
    boot_frame: &[u8],
    endpoint: &str,
) -> ApiResult<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::time::Instant;

    let start = Instant::now();
    let marker = read_com1_frame(
        &mut pipe,
        remaining(timeout, start),
        MAX_AUTH_FRAME,
        "COM1 readiness marker",
        ApiError::ReadyTimeout,
    )
    .await
    .map_err(|error| {
        ready_timeout_frames(
            error,
            "exchange_boot_and_ready",
            timeout,
            "read_ready_marker",
            remaining(timeout, start),
            endpoint,
        )
    })?;
    if marker.as_slice() != COM1_READY_MAGIC {
        return Err(
            Report::new(ApiError::Protocol).attach("guest COM1 readiness marker was invalid")
        );
    }
    write_com1_frame(
        &mut pipe,
        remaining(timeout, start),
        boot_frame,
        "COM1 boot configuration",
        ApiError::ReadyTimeout,
    )
    .await
    .map_err(|error| {
        ready_timeout_frames(
            error,
            "exchange_boot_and_ready",
            timeout,
            "write_boot_config",
            remaining(timeout, start),
            endpoint,
        )
    })?;
    let ready_frame = read_com1_frame(
        &mut pipe,
        remaining(timeout, start),
        MAX_AUTH_FRAME,
        "COM1 READY frame",
        ApiError::ReadyTimeout,
    )
    .await
    .map_err(|error| {
        ready_timeout_frames(
            error,
            "exchange_boot_and_ready",
            timeout,
            "read_ready_frame",
            remaining(timeout, start),
            endpoint,
        )
    })?;
    let ready = ReadyV1::try_from(ready_frame.as_slice())
        .map_err(|error| Report::new(ApiError::Protocol).attach(error.to_string()))?;
    ready
        .verify(&boot_config.capability, boot_frame)
        .map_err(|error| Report::new(ApiError::Authentication).attach(error.to_string()))?;
    #[cfg(feature = "tracing")]
    tracing::info!("[CONNECT] received authenticated READY from guest on COM1");
    Ok(pipe)
}

#[cfg(target_os = "windows")]
async fn read_com1_frame(
    pipe: &mut tokio::net::windows::named_pipe::NamedPipeServer,
    timeout: std::time::Duration,
    maximum: usize,
    label: &str,
    error_context: ApiError,
) -> ApiResult<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut length_bytes = [0u8; 4];
    match tokio::time::timeout(timeout, pipe.read_exact(&mut length_bytes)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(
                Report::new(error_context).attach(format!("{label} length read failed: {error}"))
            );
        }
        Err(_) => {
            return Err(Report::new(error_context)
                .attach(format!("timed out reading {label} ({timeout:?})")));
        }
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length > maximum {
        return Err(Report::new(ApiError::Protocol).attach(format!(
            "{label} length {length} exceeds its {maximum}-byte limit"
        )));
    }
    let mut frame = Vec::new();
    frame.try_reserve_exact(length).map_err(|_| {
        Report::new(ApiError::Protocol).attach(format!("{label} allocation failed"))
    })?;
    frame.resize(length, 0);
    match tokio::time::timeout(timeout, pipe.read_exact(&mut frame)).await {
        Ok(Ok(_)) => Ok(frame),
        Ok(Err(error)) => {
            Err(Report::new(error_context).attach(format!("{label} read failed: {error}")))
        }
        Err(_) => {
            Err(Report::new(error_context)
                .attach(format!("timed out reading {label} ({timeout:?})")))
        }
    }
}

#[cfg(target_os = "windows")]
async fn write_com1_frame(
    pipe: &mut tokio::net::windows::named_pipe::NamedPipeServer,
    timeout: std::time::Duration,
    frame: &[u8],
    label: &str,
    error_context: ApiError,
) -> ApiResult<()> {
    use tokio::io::AsyncWriteExt;

    let length = u32::try_from(frame.len())
        .map_err(|_| Report::new(ApiError::Protocol).attach(format!("{label} is too large")))?;
    let mut wire = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&length.to_le_bytes());
    wire.extend_from_slice(frame);
    match tokio::time::timeout(timeout, async {
        pipe.write_all(&wire).await?;
        pipe.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            Err(Report::new(error_context).attach(format!("{label} write failed: {error}")))
        }
        Err(_) => {
            Err(Report::new(error_context)
                .attach(format!("timed out writing {label} ({timeout:?})")))
        }
    }
}

#[cfg(target_os = "windows")]
fn remaining(timeout: std::time::Duration, started: std::time::Instant) -> std::time::Duration {
    timeout.checked_sub(started.elapsed()).unwrap_or_default()
}

/// Complete a `ReadyTimeout` report with the operation/budget/phase frame
/// convention (spec capability `error-report-completeness`, ReadyTimeout edge
/// scenario): the calling operation, the full ready budget, the failing
/// phase, the remaining budget slice, and the COM1 endpoint it was waiting
/// on. The existing message attachment is preserved.
#[cfg(target_os = "windows")]
fn ready_timeout_frames(
    report: Report<ApiError>,
    operation: &str,
    budget: std::time::Duration,
    phase: &str,
    remaining: std::time::Duration,
    endpoint: &str,
) -> Report<ApiError> {
    report
        .attach(format!("operation={operation}"))
        .attach(format!("budget={budget:?}"))
        .attach(format!("phase={phase}"))
        .attach(format!("remaining={remaining:?}"))
        .attach(format!("endpoint={endpoint}"))
}

/// The app's explicit one-per-process runtime session. The library no longer
/// owns a process-global journal; keeping exactly one session here is the
/// app's own choice, so stale-session reconciliation still runs once per
/// process for the default launch paths.
static APP_SESSION: tokio::sync::OnceCell<Arc<hypervisor::Session>> =
    tokio::sync::OnceCell::const_new();

async fn app_session() -> ApiResult<Arc<hypervisor::Session>> {
    APP_SESSION
        .get_or_try_init(|| async {
            hypervisor::Session::open_default()
                .await
                .map(Arc::new)
                .map_err(|report| report.change_context(ApiError::Hypervisor))
        })
        .await
        .map(Arc::clone)
}

/// Compose the default adapter set and the runtime launcher used by the
/// public launch paths. The launcher owns the app's single runtime session.
pub(crate) async fn default_launcher() -> ApiResult<jyth_runtime::Launcher> {
    let session = app_session().await?;
    Ok(jyth_runtime::Launcher::new(
        Arc::new(HcsVmFactory::new(session)),
        Arc::new(HcsBootArtifactProvider),
        Arc::new(HcsBootControlChannel),
        Arc::new(TcpGuestClientFactory),
        jyth_runtime::RetryPolicy::default(),
    ))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    /// A `ReadyTimeout` report completed with the operation/budget/phase
    /// frame convention carries every frame (spec capability
    /// `error-report-completeness`, ReadyTimeout edge scenario).
    #[test]
    fn ready_timeout_frames_carry_the_full_frame_convention() {
        let report = ready_timeout_frames(
            Report::new(ApiError::ReadyTimeout).attach("timed out waiting for guest READY"),
            "wait_for_ready",
            std::time::Duration::from_secs(50),
            "read_ready_frame",
            std::time::Duration::from_millis(250),
            r"\\.\pipe\jyth-00000000-0000-0000-0000-000000000000-bus",
        );

        assert!(matches!(report.current_context(), ApiError::ReadyTimeout));
        for expected in [
            "operation=wait_for_ready",
            "budget=50s",
            "phase=read_ready_frame",
            "remaining=250ms",
            r"endpoint=\\.\pipe\jyth-00000000-0000-0000-0000-000000000000-bus",
        ] {
            assert!(
                report.frames().any(|f| f
                    .downcast_ref::<String>()
                    .is_some_and(|s| s.contains(expected))),
                "missing frame {expected}: {report:?}"
            );
        }
    }

    /// Triangulation: distinct call sites reflect their own operation, phase,
    /// remaining slice, and endpoint — the values flow from the caller, not
    /// a hardcoded constant.
    #[test]
    fn ready_timeout_frames_reflect_the_calling_operation() {
        let report = ready_timeout_frames(
            Report::new(ApiError::ReadyTimeout).attach("timed out connecting to COM1 pipe"),
            "connect_com1",
            std::time::Duration::from_secs(50),
            "connect",
            std::time::Duration::from_secs(50),
            r"\\.\pipe\jyth-11111111-1111-1111-1111-111111111111-bus",
        );
        assert!(report.frames().any(|f| {
            f.downcast_ref::<String>()
                .is_some_and(|s| s.contains("operation=connect_com1"))
        }));
        assert!(report.frames().any(|f| {
            f.downcast_ref::<String>()
                .is_some_and(|s| s.contains("phase=connect"))
        }));
        assert!(
            report
                .frames()
                .any(|f| f.downcast_ref::<String>().is_some_and(
                    |s| s.contains(r"\\.\pipe\jyth-11111111-1111-1111-1111-111111111111-bus")
                ))
        );
    }
}
