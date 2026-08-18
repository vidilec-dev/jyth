use crate::builder::image::{Kernel, Rootfs};
use protocol::BootstrapConfigV1;
use std::future::Future;
use std::path::PathBuf;

use error_stack::Report;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::builder::{
    dir::Dir,
    file::{File, FileContent},
    permissions::Permissions,
};
use crate::error::{ApiError, ApiResult};
use crate::vm::{Executable, Process, VM, VmLifecycle, VmObserver, VmPhase, map_runtime_error};

/// Directory entries injected into the guest initramfs.
pub mod dir;
/// Regular files and Rust-binary entries injected into the guest initramfs.
pub mod file;
pub use file::RustBinary;
/// Typed kernel/rootfs sources accepted by [`VmBuilder`]. Materialization
/// lives in the `kernel` and `rootfs` crates and is driven by the builder
/// at launch; Jyth exposes no explicit materialization entry point.
///
/// # Kernel API
///
/// `Kernel` is an opaque validated facade. Construct kernels with the
/// associated functions:
///
/// ```rust
/// use jyth::builder::image::{Kernel, KernelConfig};
///
/// static VMLINUZ: &[u8] = b"vmlinuz bytes";
///
/// let default_kernel = Kernel::default();
/// let custom_kernel = Kernel::custom("7.1.7")?;
/// let configured_kernel = Kernel::custom_with_config("7.1.7", KernelConfig::default())?;
/// let local_kernel = Kernel::local("./vmlinuz");
/// let remote_kernel = Kernel::http("https://example.com/vmlinuz")?;
/// let image_kernel = Kernel::image("ubuntu:24.04", "boot/vmlinuz")?;
/// let memory_kernel = Kernel::bytes(vec![0x55, 0xaa]);
/// let embedded_kernel = Kernel::embedded(VMLINUZ);
/// let archived_kernel = Kernel::local_archive("./kernel.cpio", "boot/vmlinuz")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// `Link` remains re-exported for the unchanged [`Rootfs::new`] API; kernel
/// callers use the kernel constructors instead.
pub mod image {
    pub use image_core::Link;

    pub use kernel::{
        CustomKernelSpec, Kernel, KernelConfig, KernelConfigError, KernelConfigMode,
        KernelSpecError, KernelVersion, is_catalogued, latest_catalog_version,
    };
    pub use rootfs::Rootfs;
}
/// Unix-style permission bits for injected guest files and directories.
pub mod permissions;

/// CPU allocation requested for a VM (host-neutral model value).
pub use vm_model::cpu::Cpu;
/// Memory allocation requested for a VM (host-neutral model value).
pub use vm_model::memory::Memory;

const MATERIALIZED_PROCESS_ROOT: &str = "/jyth/processes";

/// A future-based condition controlling process or shutdown scheduling.
#[derive(Debug, Clone)]
pub enum On<F = ()> {
    /// Require every nested condition to be true.
    All(Vec<On<F>>),
    /// Require every nested condition to be false.
    AllFail(Vec<On<F>>),
    /// Require at least one nested condition to be true.
    Any(Vec<On<F>>),
    /// Require at least one nested condition to be false.
    AnyFail(Vec<On<F>>),
    /// Resolve after the future completes, regardless of its output.
    Resolve(F),
    /// Resolve when the future's output reports success.
    Success(F),
    /// Resolve when the future's output reports failure.
    Fail(F),
}

/// Result semantics used by [`On::Success`] and [`On::Fail`].
///
/// This trait keeps `On` generic at the public boundary while allowing the VM
/// builder to erase the concrete future before storing heterogeneous triggers.
#[doc(hidden)]
pub trait OnOutput {
    fn is_success(&self) -> bool;
}
impl<T, E> OnOutput for Result<T, E> {
    fn is_success(&self) -> bool {
        self.is_ok()
    }
}

/// Convert the public `On` condition combinator into a boolean trigger for
/// the canonical scheduler engine.
pub fn into_trigger<F>(on: On<F>) -> scheduler::Trigger
where
    F: Future + Send + 'static,
    F::Output: OnOutput + Send + 'static,
{
    match on {
        On::Resolve(future) => Box::pin(async move {
            let _ = future.await;
            true
        }),
        On::Success(future) => Box::pin(async move { future.await.is_success() }),
        On::Fail(future) => Box::pin(async move { !future.await.is_success() }),
        On::All(conditions) => {
            all_triggers(conditions.into_iter().map(into_trigger).collect(), true)
        }
        On::AllFail(conditions) => {
            all_triggers(conditions.into_iter().map(into_trigger).collect(), false)
        }
        On::Any(conditions) => {
            any_trigger(conditions.into_iter().map(into_trigger).collect(), true)
        }
        On::AnyFail(conditions) => {
            any_trigger(conditions.into_iter().map(into_trigger).collect(), false)
        }
    }
}

fn all_triggers(triggers: Vec<scheduler::Trigger>, expected: bool) -> scheduler::Trigger {
    Box::pin(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for trigger in triggers {
            tasks.spawn(trigger);
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(value) if value == expected => {}
                Ok(_) | Err(_) => {
                    tasks.abort_all();
                    return false;
                }
            }
        }
        true
    })
}

fn any_trigger(triggers: Vec<scheduler::Trigger>, expected: bool) -> scheduler::Trigger {
    Box::pin(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for trigger in triggers {
            tasks.spawn(trigger);
        }
        while let Some(result) = tasks.join_next().await {
            if matches!(result, Ok(value) if value == expected) {
                tasks.abort_all();
                return true;
            }
        }
        false
    })
}

/// One bounded command-and-artifact exchange for the COM1-only bootstrap.
///
/// The command is executed directly by the guest init process over the
/// authenticated COM1 boot transcript. It is intentionally separate from
/// [`VmBuilder::launch`], which configures the NIC and binds the guest TCP
/// command listener; the COM1 bootstrap path does not touch the network.
#[derive(Debug, Clone)]
pub struct BootstrapSpec {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) artifact: String,
    pub(crate) output: PathBuf,
    pub(crate) timeout: std::time::Duration,
}

impl BootstrapSpec {
    /// Create a bootstrap operation.
    pub fn new(
        program: impl Into<String>,
        artifact: impl Into<String>,
        output: impl Into<PathBuf>,
    ) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            artifact: artifact.into(),
            output: output.into(),
            timeout: std::time::Duration::from_secs(30 * 60),
        }
    }

    /// Replace the direct-exec argument vector.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Set the maximum time allowed for the guest command and artifact
    /// transfer. The timer starts after the authenticated READY exchange.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn protocol_config(&self) -> ApiResult<BootstrapConfigV1> {
        BootstrapConfigV1::new(
            self.program.clone(),
            self.args.clone(),
            self.artifact.clone(),
        )
        .map_err(|error| Report::new(ApiError::Protocol).attach(error.to_string()))
    }
}

/// Wall-clock durations of the host-visible phases of a COM1 bootstrap run,
/// measured by the host between protocol boundaries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootstrapTimings {
    /// Waiting for the guest to connect the COM1 bus pipe.
    pub connect: std::time::Duration,
    /// The authenticated READY handshake (readiness marker, boot frame, proof).
    pub ready_exchange: std::time::Duration,
    /// The guest command (the kernel build) between READY and its result frame.
    pub guest_command: std::time::Duration,
    /// Streaming, digesting, and publishing the declared artifact.
    pub artifact_transfer: std::time::Duration,
}

/// Builder for a bootable Jyth VM and its initramfs overlay.
pub struct VmBuilder {
    kernel: Option<Kernel>,
    rootfs: Option<Rootfs>,
    files: Vec<File>,
    dirs: Vec<Dir>,
    cpu: Option<Cpu>,
    mem: Option<Memory>,
    /// Optional network configuration. `None` is the default and keeps
    /// the legacy no-NIC behaviour; `Some(Nat)` requests a NIC that the
    /// HCS backend turns into a lifecycle-owned HNS NAT network (Plan
    /// §I-3). The KVM backend currently rejects non-`None` with a typed
    /// `KvmError::Unsupported` (Plan §I-5).
    network: Option<vm_model::network::Nat>,
    /// Optional host-attached disks. Empty is the default and keeps the
    /// legacy behaviour (all guest writes go to the initramfs tmpfs /
    /// rootfs in guest RAM); each [`DiskSpec`] requests a VHDX-backed
    /// block device the HCS backend materializes at the exact configured
    /// host path and whose guest init formats + mounts at the specified
    /// path. The KVM backend currently rejects a non-empty list with a
    /// typed `KvmError::Unsupported` (mirroring Plan §I-5). An empty list
    /// is passed to the backend as `None` and performs no disk operation.
    disks: Vec<vm_model::disk::DiskSpec>,
    observer: Option<VmLifecycle>,
    /// Declarative processes retained until the reactive runner is attached.
    /// Rust/byte executable sources are materialized into `files` before the
    /// initramfs overlay is built and rewritten to guest `Exec` paths.
    scheduled_processes: Vec<crate::adapters::scheduler::ScheduledProcess>,
    shutdown_trigger: Option<crate::adapters::scheduler::Trigger>,
}

impl Default for VmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

struct LaunchObserverGuard {
    observer: Option<VmLifecycle>,
}

impl LaunchObserverGuard {
    fn new(observer: Option<VmLifecycle>) -> Self {
        Self { observer }
    }

    fn launching(&self) {
        if let Some(observer) = &self.observer {
            observer.launching();
        }
    }

    fn failed(&mut self, message: impl Into<std::sync::Arc<str>>) {
        if let Some(observer) = self.observer.take() {
            observer.failed(VmPhase::Launch, message);
        }
    }

    fn complete(&mut self) -> Option<VmLifecycle> {
        self.observer.take()
    }
}

impl Drop for LaunchObserverGuard {
    fn drop(&mut self) {
        self.failed("VM launch was cancelled");
    }
}
impl VmBuilder {
    /// Creates a VM builder with no kernel, rootfs, overlays, or optional resources.
    pub fn new() -> Self {
        Self {
            kernel: None,
            rootfs: None,
            files: Vec::new(),
            dirs: Vec::new(),
            cpu: None,
            mem: None,
            network: None,
            disks: Vec::new(),
            observer: None,
            scheduled_processes: Vec::new(),
            shutdown_trigger: None,
        }
    }

    /// Return a retained VM lifecycle observer together with this builder.
    /// The observer is optional: builders created with [`VmBuilder::new`] keep
    /// their existing behavior and allocation profile.
    pub fn with_observer() -> (VmObserver, Self) {
        let (observer, lifecycle) = VmLifecycle::new();
        let mut builder = Self::new();
        builder.observer = Some(lifecycle);
        (observer, builder)
    }

    /// Set the number of virtual CPUs.
    pub fn cpu(mut self, cpu: Cpu) -> Self {
        self.cpu = Some(cpu);
        self
    }

    /// Set the VM memory allocation.
    pub fn mem(mut self, mem: Memory) -> Self {
        self.mem = Some(mem);
        self
    }

    /// Set the typed kernel source; materialized at launch.
    pub fn kernel(mut self, kernel: Kernel) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Set the typed root filesystem source; materialized at launch.
    pub fn rootfs(mut self, rootfs: Rootfs) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    /// Add a regular file to the guest initramfs overlay.
    pub fn add_file(mut self, file: File) -> Self {
        self.files.push(file);
        self
    }

    /// Add a directory to the guest initramfs overlay.
    pub fn add_dir(mut self, dir: Dir) -> Self {
        self.dirs.push(dir);
        self
    }

    /// Attach a NAT network to the guest VM. The argument is
    /// `impl Into<vm_model::network::Nat>`, so `Nat::default()`,
    /// a fully-specified `Nat::try_new(...)`, or the zero-parameter
    /// shorthand `()` (which resolves to `Nat::default()`) are all
    /// accepted. This is the "easy API" called out in Plan §II-2:
    ///
    /// ```ignore
    /// // truly zero-config
    /// VmBuilder::new().kernel(kernel).rootfs(rootfs).network(()).launch().await
    /// // explicit overrides
    /// VmBuilder::new().kernel(kernel).rootfs(rootfs).network(Nat::default()).launch().await
    /// ```
    ///
    /// Required for every normal launch: the guest command endpoint is
    /// derived from this validated `Nat`, so [`VmBuilder::launch`] without
    /// `.network(...)` fails with [`ApiError::NetworkRequired`] before any
    /// kernel or rootfs materialization. The COM1-only bootstrap path
    /// ([`VmBuilder::launch_com1_bootstrap`]) intentionally keeps the
    /// optional network.
    pub fn network(mut self, n: impl Into<vm_model::network::Nat>) -> Self {
        self.network = Some(n.into());
        self
    }

    /// Attach one host-backed disk to the guest VM. The argument is a
    /// validated [`vm_model::disk::DiskSpec`] — an absolute `.vhdx`
    /// host path, a creation size, a validated guest mount target, a
    /// requested retention, and the existing-file policy. Repeatable for
    /// multiple disks; [`VmBuilder::disks`] accepts a list in one call.
    ///
    /// ```ignore
    /// // 16 GiB ephemeral disk at /build on a host temp path
    /// VmBuilder::new().kernel(kernel).rootfs(rootfs).disk(DiskSpec::new(
    ///     std::env::temp_dir().join("build.vhdx"),
    ///     16 * 1024,
    ///     GuestMount::new("/build")?,
    ///     DiskRetention::Ephemeral,
    ///     ExistingDiskPolicy::ReuseAndKeep,
    /// )?).launch().await
    /// ```
    ///
    /// The guest surfaces each disk as `/dev/sd<letter>` (in the order
    /// `disk` was called: `sda`, `sdb`, ...) and the guest init mounts
    /// each one at its `guest_mount`. Only disks the backend created are
    /// marked for guest initialization — an existing file is never
    /// formatted. An existing path under `ExistingDiskPolicy::ReuseAndKeep`
    /// is attached and retained, and an ephemeral request is visibly
    /// reclassified as persistent (see [`crate::VM::warnings`]).
    ///
    /// The host backend materializes a VHDX per disk at the exact
    /// configured host path (so the host only pays for the bytes the guest
    /// actually writes) and removes it on cleanup only when it was created
    /// by this launch and is still deletable. Currently HCS-only; the KVM
    /// backend returns a typed `KvmError::Unsupported` if any disk is
    /// requested (mirroring Plan §I-5).
    ///
    /// Off by default; existing call sites that don't call `.disk(...)`
    /// compile and behave identically to before this feature landed.
    /// Calling `add_dir` with the same path that a disk will be mounted at
    /// is unnecessary — the guest init creates the mount point directory
    /// itself.
    pub fn disk(mut self, spec: vm_model::disk::DiskSpec) -> Self {
        self.disks.push(spec);
        self
    }

    /// Attach multiple host-backed disks in one call (see
    /// [`VmBuilder::disk`]).
    pub fn disks<I>(mut self, specs: I) -> Self
    where
        I: IntoIterator<Item = vm_model::disk::DiskSpec>,
    {
        self.disks.extend(specs);
        self
    }

    /// Retain a process and start it once its condition is satisfied.
    pub fn run_on<F>(mut self, on: On<F>, process: Process) -> Self
    where
        F: Future + Send + 'static,
        F::Output: OnOutput + Send + 'static,
    {
        self.scheduled_processes
            .push(crate::adapters::scheduler::ScheduledProcess {
                trigger: into_trigger(on),
                process,
            });
        self
    }

    /// Request guest shutdown once the supplied condition is satisfied.
    pub fn shutdown_on<F>(mut self, on: On<F>) -> Self
    where
        F: Future + Send + 'static,
        F::Output: OnOutput + Send + 'static,
    {
        self.shutdown_trigger = Some(into_trigger(on));
        self
    }

    /// Accessors used by the build-module `Build` impl.
    pub(crate) fn take_kernel(&mut self) -> Option<Kernel> {
        self.kernel.take()
    }
    pub(crate) fn take_rootfs(&mut self) -> Option<Rootfs> {
        self.rootfs.take()
    }
    pub(crate) fn files_ref(&self) -> &[File] {
        &self.files
    }

    /// Whether a guest file with `path` is registered in the plan. Test-only
    /// helper used by the compiler-plan tests to verify injected files
    /// without launching HCS.
    #[cfg(test)]
    pub(crate) fn has_guest_file(&self, path: &str) -> bool {
        self.files.iter().any(|file| {
            file.path_ref()
                .is_some_and(|p| p == std::path::Path::new(path))
        })
    }
    pub(crate) fn dirs_ref(&self) -> &[Dir] {
        &self.dirs
    }
    pub(crate) fn cpu_ref(&self) -> Option<&Cpu> {
        self.cpu.as_ref()
    }
    pub(crate) fn mem_ref(&self) -> Option<&Memory> {
        self.mem.as_ref()
    }
    pub(crate) fn network_ref(&self) -> Option<&vm_model::network::Nat> {
        self.network.as_ref()
    }
    pub(crate) fn disks_ref(&self) -> &[vm_model::disk::DiskSpec] {
        &self.disks
    }

    /// Materialize host-side process executable sources into the initramfs
    /// overlay and rewrite every affected process to the resulting guest path.
    fn materialize_process_executables(&mut self) {
        let mut injections = std::collections::BTreeMap::<PathBuf, FileContent>::new();

        for scheduled in &mut self.scheduled_processes {
            let process = &mut scheduled.process;
            let executable = process.executable().clone();
            let (kind, identity, content) = match executable {
                Executable::Rust(binary) => {
                    let identity = binary.cache_identity();
                    (
                        "rust",
                        identity.as_bytes().to_vec(),
                        FileContent::Crate(binary),
                    )
                }
                Executable::Bytes(bytes) => {
                    ("bytes", bytes.to_vec(), FileContent::Bytes(bytes.to_vec()))
                }
                Executable::Shell(_) | Executable::Exec(_) => continue,
            };

            let guest_path = materialized_process_path(kind, &identity);
            injections.entry(guest_path.clone()).or_insert(content);
            process.replace_executable(Executable::Exec(guest_path));
        }

        if injections.is_empty() {
            return;
        }

        // The initramfs extractor needs explicit directory entries before the
        // files. These paths are reserved for jyth-generated executables.
        self.dirs.push(Dir::new().path("/jyth"));
        self.dirs.push(Dir::new().path(MATERIALIZED_PROCESS_ROOT));

        self.files
            .extend(injections.into_iter().map(|(path, content)| {
                File::new()
                    .path(path)
                    .content(content)
                    .permissions(Permissions::READ | Permissions::EXECUTE)
                    .user_permissions(Permissions::ALL)
            }));
    }

    /// Materialize the prepared kernel + rootfs, assemble the boot artifacts
    /// (kernel.bin, initrd.img), boot the VM via the runtime launcher, wait
    /// for the guest's READY handshake on COM1, and return a ready-to-drive
    /// `VM`.
    ///
    /// The observer is taken before any validation so a launch that was
    /// actually called never publishes the builder-drop message: an explicit
    /// pre-runtime failure publishes the complete returned diagnostic, the
    /// runtime launcher remains authoritative for runtime failures, and only
    /// a dropped in-flight future publishes the cancellation message.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn launch(mut self) -> ApiResult<VM> {
        // Taking the observer disarms `VmBuilder::drop` for this launch; the
        // guard retains a clone so its drop still publishes cancellation.
        let observer = self.observer.take();
        let mut guard = LaunchObserverGuard::new(observer.clone());
        guard.launching();
        match self.launch_inner(observer).await {
            Ok(vm) => {
                // The runtime launcher already published `Running` before
                // returning; disarming the guard prevents a late cancellation.
                guard.complete();
                Ok(vm)
            }
            Err(error) => {
                // An explicit pre-runtime failure publishes the complete
                // diagnostic once (Debug renders contexts AND attachments;
                // alternate Display drops attachments in error-stack 0.8). A
                // runtime failure has already reached a terminal state and is
                // retained by `VmLifecycle::set`.
                guard.failed(format!("{error:?}"));
                Err(error)
            }
        }
    }

    /// Boot the guest with the authenticated COM1-only bootstrap path, run
    /// the command in [`BootstrapSpec`], retrieve its artifact, and close the
    /// VM before returning. This is intended for the internal
    /// `binaries/kernel-builder` tool, which produces a kernel image before
    /// any network or TCP command listener is required.
    #[cfg_attr(feature = "tracing", instrument(skip(self, spec), level = "debug"))]
    pub async fn launch_com1_bootstrap(
        mut self,
        spec: BootstrapSpec,
    ) -> ApiResult<BootstrapTimings> {
        // Same observer ownership as `launch`: taking it first disarms the
        // builder-drop message, the guard publishes Launching, and an
        // explicit failure publishes the complete diagnostic.
        let observer = self.observer.take();
        let mut guard = LaunchObserverGuard::new(observer);
        guard.launching();

        match self.launch_com1_bootstrap_inner(spec).await {
            Ok(timings) => {
                if let Some(observer) = guard.complete() {
                    observer.running();
                    observer.finished(crate::vm::VmFinish::Shutdown);
                }
                Ok(timings)
            }
            Err(error) => {
                guard.failed(format!("{error:?}"));
                Err(error)
            }
        }
    }

    async fn launch_com1_bootstrap_inner(self, spec: BootstrapSpec) -> ApiResult<BootstrapTimings> {
        let bootstrap = spec.protocol_config()?;
        let prepared = self
            .prepare(
                "console=ttyS0,115200n8 init=/init jyth.backend=hcs-bootstrap",
                Some(bootstrap),
            )
            .await?;

        // The COM1 transfer needs the concrete platform handle; the default
        // factory composes exactly this instance type.
        let hcs = prepared
            .instance
            .as_any()
            .downcast_ref::<crate::adapters::runtime::HcsInstance>()
            .expect("the default factory returns the HCS instance");
        let transfer = crate::adapters::runtime::run_com1_bootstrap(
            &hcs.vm,
            std::time::Duration::from_secs(50),
            &prepared.boot_config,
            &spec.output,
            spec.timeout,
        )
        .await;
        let close = prepared
            .instance
            .close()
            .await
            .map_err(|error| Report::new(ApiError::Hypervisor).attach(error.to_string()));

        match (transfer, close) {
            (Ok(timings), Ok(())) => Ok(timings),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error.attach("COM1 bootstrap VM cleanup failed")),
            (Err(error), Err(close_error)) => Err(error.attach(format!(
                "COM1 bootstrap VM cleanup also failed: {close_error}"
            ))),
        }
    }

    async fn launch_inner(self, observer: Option<VmLifecycle>) -> ApiResult<VM> {
        // A normal launch requires an explicit validated network: the guest
        // command endpoint is derived from it, and the failure must surface
        // before kernel or rootfs materialization (the COM1-only bootstrap
        // path intentionally keeps the optional network).
        if self.network_ref().is_none() {
            return Err(Report::new(ApiError::NetworkRequired)
                .attach("a normal launch requires a validated NAT network"));
        }
        let launch = self
            .prepare_launch("console=ttyS0,115200n8 init=/init jyth.backend=hcs")
            .await?;
        let live = crate::adapters::runtime::default_launcher()
            .await?
            .launch(launch, observer)
            .await
            .map_err(map_runtime_error)?;
        Ok(VM::from_live(live))
    }

    /// Validate facade-level configuration, materialize process
    /// executables, resolve the prepared kernel/rootfs sources and overlay
    /// entries, and package the scheduler declarations into the runtime
    /// launch request. The runtime performs the remaining orchestration.
    async fn prepare_launch(mut self, cmdline: &str) -> ApiResult<jyth_runtime::Launch> {
        crate::ensure_supported_platform()?;
        self.materialize_process_executables();
        let scheduled_processes = std::mem::take(&mut self.scheduled_processes);
        let shutdown_trigger = self.shutdown_trigger.take();

        // Capture the requested memory/vcpu/network before `self` is
        // moved into `Build::build` (which takes ownership of the
        // receiver). `Nat` is cheap to clone for this launch handoff, so
        // cloning avoids lifetime juggling for a `&` we'd otherwise
        // need to keep alive across the async `.await` boundary.
        let memory_mb_override = self.mem_ref().map(|m| match m {
            Memory::MB(v) => *v,
        });
        let vcpus_override = self.cpu_ref().map(|c| match c {
            Cpu::Units(v) => *v,
        });
        let network = self.network_ref().cloned();
        let disks = self.disks_ref().to_vec();
        validate_disks(&disks)?;

        // Cooperative-cancellation root for the materialization pipeline
        // (kernel/rootfs ops, overlay crate builds): the drop guard cancels
        // it the moment this launch future ends — success, error, or being
        // dropped — so any still-running spawn_blocking workers observe the
        // cancellation and bail at their next `is_cancelled()` check (abort
        // alone cannot stop a worker thread).
        let cancel = CancellationToken::new();
        let _cancel_guard = cancel.clone().drop_guard();

        let build = <Self as crate::build::Build>::build(self, &cancel)
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!(chain = %format!("{e:#}"), "launch build stage failed");
                e.change_context(ApiError::Build)
            })?;

        let scheduled_processes = scheduled_processes
            .into_iter()
            .map(|scheduled| -> ApiResult<jyth_runtime::ScheduledProcess> {
                Ok(jyth_runtime::ScheduledProcess {
                    trigger: scheduled.trigger,
                    process: scheduled.process.into_prepared().map_err(|error| {
                        Report::new(ApiError::Build)
                            .attach(format!("scheduled process failed preparation: {error}"))
                    })?,
                })
            })
            .collect::<ApiResult<Vec<_>>>()?;

        Ok(jyth_runtime::Launch {
            request: jyth_runtime::LaunchRequest {
                kernel_source: build.kernel_source,
                rootfs_source: build.rootfs_source,
                overlay_entries: build.overlay_entries,
                memory_mb: memory_mb_override,
                vcpu_count: vcpus_override,
                cmdline: cmdline.to_string(),
                network,
                disks,
            },
            scheduled_processes,
            shutdown_trigger,
        })
    }

    /// Validate facade-level configuration and package the scheduler
    /// declarations; used by the COM1 bootstrap path.
    async fn prepare(
        self,
        cmdline: &str,
        bootstrap: Option<BootstrapConfigV1>,
    ) -> ApiResult<jyth_runtime::PreparedLaunch> {
        let launch = self.prepare_launch(cmdline).await?;
        let prepared = crate::adapters::runtime::default_launcher()
            .await?
            .prepare(launch.request, bootstrap)
            .await
            .map_err(map_runtime_error)?;
        Ok(prepared)
    }
}

/// Pre-build validation of the configured disks, in addition to
/// [`vm_model::disk::DiskSpec::new`]: duplicate normalized host paths
/// and duplicate guest mount targets are rejected, and each disk's parent
/// directory must exist and be a directory (v0.1 requires a writable
/// parent for the backing file).
fn validate_disks(disks: &[vm_model::disk::DiskSpec]) -> ApiResult<()> {
    let mut paths = std::collections::HashSet::new();
    let mut mounts = std::collections::HashSet::new();
    for spec in disks {
        let normalized = spec.normalized_host_path();
        if !paths.insert(normalized.clone()) {
            return Err(Report::new(ApiError::Disk).attach(format!(
                "duplicate disk host path after normalization: {}",
                normalized.display()
            )));
        }
        let parent = normalized.parent().ok_or_else(|| {
            Report::new(ApiError::Disk)
                .attach(format!("disk path has no parent: {}", normalized.display()))
        })?;
        if !parent.is_dir() {
            return Err(Report::new(ApiError::Disk).attach(format!(
                "disk parent directory is missing or not a directory: {}",
                parent.display()
            )));
        }
        let mount = spec.guest_mount().as_str();
        if !mounts.insert(mount.to_string()) {
            return Err(Report::new(ApiError::Disk)
                .attach(format!("duplicate guest mount target in one VM: {mount}")));
        }
    }
    Ok(())
}

fn materialized_process_path(kind: &str, identity: &[u8]) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind.as_bytes());
    hasher.update(&[0]);
    hasher.update(identity);
    PathBuf::from(format!(
        "{MATERIALIZED_PROCESS_ROOT}/{kind}-{}",
        hasher.finalize().to_hex()
    ))
}

impl Drop for VmBuilder {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            observer.failed(VmPhase::Launch, "builder dropped before launch was called");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::Build;
    use crate::vm::{ProcessBuilder, VmState};
    use bytes::Bytes;
    use std::net::IpAddr;
    use std::path::Path;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn launch_rejects_linux_before_image_preparation() {
        let error = match VmBuilder::new().launch().await {
            Ok(_) => panic!("Linux/KVM launch must remain outside the release boundary"),
            Err(error) => error,
        };

        assert_eq!(
            *error.current_context(),
            crate::ApiError::UnsupportedPlatform {
                platform: crate::HostPlatform::LinuxKvm,
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn launch_rejects_linux_before_image_acquisition() {
        let error = match VmBuilder::new()
            .kernel(image::Kernel::image("example.invalid/kernel", "kernel").unwrap())
            .launch()
            .await
        {
            Ok(_) => panic!("Linux/KVM image acquisition must remain outside the release boundary"),
            Err(error) => error,
        };

        assert_eq!(
            *error.current_context(),
            crate::ApiError::UnsupportedPlatform {
                platform: crate::HostPlatform::LinuxKvm,
            }
        );
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn jyth_build_splices_the_deep_acquisition_chain() {
        let cancel = CancellationToken::new();
        let error = match VmBuilder::new()
            .kernel(image::Kernel::image("127.0.0.1:1/repo:latest", "kernel").unwrap())
            .build(&cancel)
            .await
        {
            Ok(_) => panic!("an unreachable registry must fail the build"),
            Err(error) => error,
        };

        assert!(
            matches!(
                *error.current_context(),
                crate::build::BuildError::ImageBuild
            ),
            "the builder build must surface BuildError::ImageBuild"
        );
        assert!(
            error
                .frames()
                .any(|frame| frame.is::<crate::build::materialize::MaterializeError>()),
            "the splice must keep the materialize context frame"
        );
        assert!(
            error
                .frames()
                .any(|frame| frame.is::<kernel::KernelError>()),
            "the splice must reveal the kernel frame"
        );
        let display = format!("{error:#}");
        assert!(
            display.contains("could not resolve the external source"),
            "the printed chain must surface the resolver frame, got: {display}"
        );
    }

    #[tokio::test]
    async fn observed_builder_drop_is_a_retained_launch_failure() {
        let (observer, builder) = VmBuilder::with_observer();
        drop(builder);

        let state_failure = match observer.state() {
            VmState::Failed(failure) => failure,
            state => panic!("expected a retained launch failure, got {state:?}"),
        };
        let started_failure =
            tokio::time::timeout(std::time::Duration::from_secs(1), observer.started())
                .await
                .expect("dropped builder must wake started()")
                .expect_err("dropped builder must fail started()");
        let finished_failure =
            tokio::time::timeout(std::time::Duration::from_secs(1), observer.finished())
                .await
                .expect("dropped builder must wake finished()")
                .expect_err("dropped builder must fail finished()");

        assert_eq!(state_failure, started_failure);
        assert_eq!(started_failure, finished_failure);
        assert_eq!(finished_failure.phase, VmPhase::Launch);
        assert!(finished_failure.message.contains("dropped"));
    }

    #[tokio::test]
    async fn cancelled_launch_guard_retains_a_launch_failure() {
        let (observer, lifecycle) = VmLifecycle::new();
        {
            let guard = LaunchObserverGuard::new(Some(lifecycle));
            guard.launching();
        }

        assert!(matches!(
            observer.state(),
            VmState::Failed(failure) if failure.phase == VmPhase::Launch
        ));
        let failure = observer
            .finished()
            .await
            .expect_err("cancelled launch must finish the observer");
        assert_eq!(failure.message.as_ref(), "VM launch was cancelled");
    }

    /// Dropping an in-flight launch future publishes the cancellation
    /// diagnostic: the guard retains a clone until the launch reaches a
    /// terminal handoff, so a dropped future is indistinguishable from a
    /// cancelled operation. Windows-only: on Linux the platform gate fires
    /// before the first suspension point, so the launch completes instead of
    /// staying in flight.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn dropping_an_in_flight_launch_publishes_cancellation() {
        let (observer, builder) = VmBuilder::with_observer();
        let builder = builder
            .network(())
            .kernel(image::Kernel::image("127.0.0.1:1/repo:latest", "kernel").unwrap());
        // Box-owned so dropping the box drops the in-flight launch future.
        let mut future = Box::pin(builder.launch());
        // Poll once: the guard is created, Launching published, and the
        // future suspends at the first materialization await (the refused
        // registry probe is still pending).
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let polled = future.as_mut().poll(&mut context);
        assert!(!polled.is_ready(), "the launch must stay in flight");
        drop(future);

        let failure = observer
            .finished()
            .await
            .expect_err("a dropped in-flight launch must finish the observer");
        assert_eq!(failure.phase, VmPhase::Launch);
        assert_eq!(failure.message.as_ref(), "VM launch was cancelled");
    }

    /// F-03 regression: an explicit pre-runtime launch error must become the
    /// retained observer failure, with the complete returned diagnostic —
    /// never a builder-drop or cancellation message. A missing network fails
    /// before any platform gate or materialization, so this is deterministic
    /// on every host without a live backend.
    #[tokio::test]
    async fn pre_runtime_launch_error_publishes_the_returned_diagnostic() {
        let (observer, builder) = VmBuilder::with_observer();
        let error = match builder.launch().await {
            Ok(_) => panic!("a launch without a network must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error.current_context(),
            crate::ApiError::NetworkRequired
        ));

        let failure = observer
            .finished()
            .await
            .expect_err("the pre-runtime error must finish the observer");
        assert_eq!(failure.phase, VmPhase::Launch);
        assert!(
            failure.message.contains("validated NAT network"),
            "the observer must retain the returned diagnostic, got: {:?}",
            failure.message
        );
    }

    /// The builder-drop message must never appear after `launch` has started:
    /// taking the observer at launch entry disarms `VmBuilder::drop`, so the
    /// retained failure is always the returned diagnostic.
    #[tokio::test]
    async fn launch_never_publishes_the_builder_drop_message() {
        let (observer, builder) = VmBuilder::with_observer();
        if builder.launch().await.is_ok() {
            panic!("missing network must fail");
        }

        let failure = observer
            .finished()
            .await
            .expect_err("launch must finish the observer");
        assert!(
            !failure
                .message
                .contains("builder dropped before launch was called"),
            "the builder-drop message must be disarmed once launch starts, got: {:?}",
            failure.message
        );
        assert!(!failure.message.contains("VM launch was cancelled"));
    }

    /// A materialization failure (unreachable kernel registry) publishes the
    /// complete deep build chain in the observer diagnostic, mirroring the
    /// `jyth_build_splices_the_deep_acquisition_chain` error surface.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn materialization_failure_publishes_the_complete_build_chain() {
        let (observer, builder) = VmBuilder::with_observer();
        let builder = builder
            .network(())
            .kernel(image::Kernel::image("127.0.0.1:1/repo:latest", "kernel").unwrap());
        if builder.launch().await.is_ok() {
            panic!("refused registry must fail");
        }

        let failure = observer
            .finished()
            .await
            .expect_err("the materialization failure must finish the observer");
        assert_eq!(failure.phase, VmPhase::Launch);
        // The observer message carries the Build category and its direct
        // materialization cause; the deep resolver frames remain in the
        // returned report (asserted by jyth_build_splices_the_deep_...).
        assert!(
            failure
                .message
                .contains("failed to materialize the VM image"),
            "the observer must retain the build diagnostic, got: {:?}",
            failure.message
        );
        assert!(
            !failure
                .message
                .contains("builder dropped before launch was called"),
            "the builder-drop message must stay disarmed: {:?}",
            failure.message
        );
    }

    #[test]
    fn scheduled_rust_and_bytes_are_materialized_into_executable_overlay_files() {
        let rust_process = ProcessBuilder::new()
            .rust(RustBinary::new("tests/e2e/fixtures/file-check/Cargo.toml"))
            .build()
            .unwrap();
        let byte_process = ProcessBuilder::new()
            .bytes(Bytes::from_static(b"guest executable"))
            .build()
            .unwrap();

        let mut builder = VmBuilder::new()
            .run_on(
                On::Resolve(std::future::ready(Ok::<(), ()>(()))),
                rust_process,
            )
            .run_on(
                On::Resolve(std::future::ready(Ok::<(), ()>(()))),
                byte_process,
            );
        builder.materialize_process_executables();

        assert_eq!(builder.scheduled_processes.len(), 2);
        let guest_paths: Vec<PathBuf> = builder
            .scheduled_processes
            .iter()
            .map(|scheduled| match scheduled.process.executable() {
                Executable::Exec(path) => path.clone(),
                other => panic!("expected materialized Exec, got {other:?}"),
            })
            .collect();
        assert!(guest_paths.iter().all(|path| {
            path.to_string_lossy()
                .starts_with(MATERIALIZED_PROCESS_ROOT)
        }));

        assert_eq!(builder.files_ref().len(), 2);
        assert!(builder.files_ref().iter().all(|file| file.mode() == 0o755));
        assert!(builder.files_ref().iter().any(|file| {
            matches!(
                file.content_ref(),
                Some(FileContent::Crate(binary))
                    if binary.manifest_path() == Path::new("tests/e2e/fixtures/file-check/Cargo.toml")
                        && binary.binary_name().is_none()
            )
        }));
        assert!(builder.files_ref().iter().any(|file| {
            matches!(
                file.content_ref(),
                Some(FileContent::Bytes(bytes)) if bytes == b"guest executable"
            )
        }));
    }

    #[test]
    fn duplicate_byte_executables_share_one_initramfs_entry() {
        let executable = Bytes::from_static(b"same executable");
        let first = ProcessBuilder::new()
            .bytes(executable.clone())
            .build()
            .unwrap();
        let second = ProcessBuilder::new().bytes(executable).build().unwrap();
        let mut builder = VmBuilder::new()
            .run_on(On::Resolve(std::future::ready(Ok::<(), ()>(()))), first)
            .run_on(On::Resolve(std::future::ready(Ok::<(), ()>(()))), second);

        builder.materialize_process_executables();

        assert_eq!(builder.files_ref().len(), 1);
        assert_eq!(
            builder.scheduled_processes[0].process.executable(),
            builder.scheduled_processes[1].process.executable()
        );
    }

    /// Plan §II-2 metric: `Builder::network(())` (the "easy API" form)
    /// stores the config so `network_ref()` returns `Some`. Verifies
    /// both the `()`-shorthand and a real `Nat::default()` land in the
    /// same place. Does not boot a VM — the assertion is purely on the
    /// builder's own internal storage.
    #[test]
    fn builder_network_stores_config() {
        // Default-path: no `.network(...)` ⇒ `None`.
        let b = VmBuilder::new();
        assert!(b.network_ref().is_none(), "default Builder has no network");

        // Easy-API `()` shorthand ⇒ `Some(Nat::default())`.
        let b = VmBuilder::new().network(());
        let nat = b.network_ref().expect("`network(())` stored a Nat");
        assert_eq!(nat, &vm_model::network::Nat::default());

        // Explicit `Nat` ⇒ `Some(the_supplied_nat)`.
        let custom = vm_model::network::Nat::try_new(
            "192.168.99.0/24",
            "192.168.99.1",
            "192.168.99.42",
            ["9.9.9.9", "1.0.0.1"],
        )
        .expect("custom NAT is valid");
        let b = VmBuilder::new().network(custom.clone());
        let nat = b.network_ref().expect("explicit Nat stored");
        assert_eq!(nat.subnet().to_string(), "192.168.99.0/24");
        assert_eq!(nat.guest_ip().to_string(), "192.168.99.42");
        assert_eq!(
            nat.dns(),
            &[
                IpAddr::V4("9.9.9.9".parse().unwrap()),
                IpAddr::V4("1.0.0.1".parse().unwrap()),
            ]
        );

        // Last `.network(...)` wins (matches the rest of the Builder's
        // set-once setters in spirit — they overwrite when called
        // twice).
        let b = VmBuilder::new().network(()).network(custom);
        assert_eq!(
            b.network_ref().unwrap().guest_ip().to_string(),
            "192.168.99.42"
        );
    }

    /// A normal launch without a network must fail with the typed
    /// `NetworkRequired` category before any kernel/rootfs materialization.
    /// The builder is intentionally incomplete (no kernel, no rootfs): the
    /// network guard runs first, so the test proves the failure ordering
    /// without touching the host.
    #[tokio::test]
    async fn launch_without_network_fails_before_materialization() {
        let mut future = std::pin::pin!(crate::builder::VmBuilder::new().launch());
        let result = std::future::poll_fn(|cx| future.as_mut().poll(cx)).await;
        let error = match result {
            Ok(_vm) => panic!("a normal launch without a network must fail, got a VM"),
            Err(error) => error,
        };
        assert!(matches!(
            error.current_context(),
            crate::ApiError::NetworkRequired
        ));
    }

    #[test]
    fn builder_rejects_duplicate_normalized_disk_paths_and_mounts() {
        let root = std::env::temp_dir().join(format!("jyth-builder-disk-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create test root");
        let mount = vm_model::disk::GuestMount::new("/build").expect("valid mount");
        let spec = |path: &std::path::Path, mount: &str| {
            vm_model::disk::DiskSpec::new(
                path,
                1024,
                vm_model::disk::GuestMount::new(mount).expect("valid mount"),
                vm_model::disk::DiskRetention::Ephemeral,
                vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
            )
            .expect("valid spec")
        };
        // Same file via different lexical spellings must be rejected.
        let first = root.join("build.vhdx");
        let second = root.join(r".\nested\..\build.vhdx");
        let duplicate = [spec(&first, "/build"), spec(&second, "/scratch")];
        let error = validate_disks(&duplicate).expect_err("duplicate normalized paths");
        assert_eq!(*error.current_context(), crate::ApiError::Disk);
        assert!(format!("{error:?}").contains("duplicate disk host path"));

        // Distinct paths but duplicate mount targets must be rejected.
        let duplicate_mounts = [
            spec(&root.join("a.vhdx"), "/build"),
            spec(&root.join("b.vhdx"), "/build"),
        ];
        let error = validate_disks(&duplicate_mounts).expect_err("duplicate mounts");
        assert!(format!("{error:?}").contains("duplicate guest mount target"));

        // A missing parent directory must be rejected.
        let missing_parent = [spec(&root.join("missing").join("disk.vhdx"), "/build")];
        let error = validate_disks(&missing_parent).expect_err("missing parent");
        assert!(format!("{error:?}").contains("parent directory"));

        // A valid single disk passes.
        validate_disks(&[spec(&root.join("ok.vhdx"), "/build")]).expect("single valid disk passes");
        let _ = mount;
        std::fs::remove_dir_all(root).expect("remove test root");
    }
}
