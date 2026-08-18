use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cucumber::{StatsWriter, World as _, given, then, when};
use e2e_tests::{VmGuard, hcs_test_guard, materialize_image};
use jyth::builder::VmBuilder;
use jyth::builder::image::{Kernel, KernelConfig, Link, Rootfs};
use jyth::vm::{CaptureOptions, Output, ProcessBuilder};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const DEFAULT_KERNEL_VERSION: &str = "6.6.14";
/// Kernel versions the acceptance scenarios may pin. Adding a scenario with
/// a new version requires extending this list — the guard keeps the feature
/// files in lockstep with versions the microVM config fragment was validated
/// against.
const SUPPORTED_KERNEL_VERSIONS: &[&str] = &["6.6.14", "7.1.7"];
const ALPINE_ROOTFS: &str = "alpine:3.24";
const BUILD_TIMEOUT: Duration = Duration::from_secs(90 * 60);

/// `CONFIG_LOCALVERSION` suffix the config-change scenario appends to the
/// canonical fragment. The guest reports it as part of `uname -r`, so the
/// feature file's expected release is `<version>-jyth-e2e`; keep the two in
/// lockstep.
const LOCALVERSION_SUFFIX: &str = "-jyth-e2e";

#[derive(Clone, Debug)]
struct WorldError(String);

impl fmt::Display for WorldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WorldError {}

type WorldResult<T> = Result<T, WorldError>;

static RELEASE_ARTIFACT: OnceLock<Result<PathBuf, WorldError>> = OnceLock::new();

#[derive(Debug)]
struct BuildOutcome {
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    wait_error: Option<String>,
    kill_error: Option<String>,
}

impl BuildOutcome {
    fn succeeded(&self) -> bool {
        !self.timed_out
            && self.wait_error.is_none()
            && self.status.is_some_and(|status| status.success())
    }
}

#[derive(cucumber::World)]
#[world(init = Self::new)]
struct World {
    /// The release executable that a user would invoke.
    artifact: PathBuf,
    /// Evidence and output for this scenario. It is intentionally retained.
    run_dir: PathBuf,
    /// The raw bzImage emitted by the child process.
    emitted_kernel: PathBuf,
    configured_version: Option<String>,
    build: Option<BuildOutcome>,
    /// The repeated build of an already-cached specification.
    second_build: Option<BuildOutcome>,
    /// The two children of the concurrent identical-build scenario.
    concurrent_builds: Option<(BuildOutcome, BuildOutcome)>,
    /// The deliberately failing build (configuration missing a required
    /// kernel option).
    failure_build: Option<BuildOutcome>,
    /// Host config file for the local-version complete-config scenario.
    localversion_config: Option<PathBuf>,
    /// Custom-kernel cache namespace listing before/after the failing build.
    cache_before: Option<BTreeSet<PathBuf>>,
    cache_after: Option<BTreeSet<PathBuf>>,
    /// The consumer VM, wrapped in a guard so a failing step tears it down
    /// (compute system, HNS network, VHDX) instead of leaking it.
    consumer_vm: Option<VmGuard>,
    consumer_error: Option<String>,
    guest_release: Option<String>,
    /// The shared live-host lock: this harness boots live VMs, so it must
    /// serialize against the other live e2e binaries on the same host.
    _host_guard: Option<e2e_tests::LiveHostGuard>,
}

impl fmt::Debug for World {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("World")
            .field("artifact", &self.artifact)
            .field("run_dir", &self.run_dir)
            .field("emitted_kernel", &self.emitted_kernel)
            .field("configured_version", &self.configured_version)
            .field("build", &self.build)
            .field("second_build", &self.second_build)
            .field("concurrent_builds", &self.concurrent_builds)
            .field("failure_build", &self.failure_build)
            .field("localversion_config", &self.localversion_config)
            .field("consumer_vm", &self.consumer_vm.as_ref().map(|_| "running"))
            .field("consumer_error", &self.consumer_error)
            .field("guest_release", &self.guest_release)
            .finish_non_exhaustive()
    }
}

/// The single per-binary state directory. `JYTH_STATE_DIR` is read once per
/// process, so the first call is the only effective one.
fn state_dir() -> &'static Path {
    static STATE_DIR: OnceLock<PathBuf> = OnceLock::new();
    STATE_DIR.get_or_init(|| std::env::temp_dir().join("jyth-e2e").join("kernel_builder"))
}

/// Set `JYTH_STATE_DIR` for this process and return the directory. The
/// kernel-builder children inherit it, so the failed-build scenario can
/// inspect the journal (abandoned-resource inventory) of the bootstrap VMs
/// it just ran.
fn ensure_state_dir() -> &'static Path {
    let dir = state_dir();
    std::fs::create_dir_all(dir).expect("create the e2e state directory");
    unsafe { std::env::set_var("JYTH_STATE_DIR", dir) };
    dir
}

impl World {
    async fn new() -> WorldResult<Self> {
        // Every live scenario holds the shared host lock for its whole
        // duration (including the kernel build), so a concurrent live binary
        // can never collide with the consumer VM or the journal.
        let host_guard = hcs_test_guard()
            .await
            .map_err(|error| WorldError(format!("live-host lock failed: {error}")))?;

        // Per-binary state root (journal, sessions) before any VM work; the
        // CLI children inherit it through the process environment.
        ensure_state_dir();

        let run_dir = create_run_dir()?;
        let emitted_kernel = run_dir.join("bzImage");

        let artifact = match locate_release_artifact() {
            Ok(path) => path,
            Err(error) => {
                eprintln!(
                    "[kernel-builder-e2e] release artifact lookup failed; run directory retained: {}",
                    run_dir.display()
                );
                return Err(error);
            }
        };

        Ok(Self {
            artifact,
            run_dir,
            emitted_kernel,
            configured_version: None,
            build: None,
            second_build: None,
            concurrent_builds: None,
            failure_build: None,
            localversion_config: None,
            cache_before: None,
            cache_after: None,
            consumer_vm: None,
            consumer_error: None,
            guest_release: None,
            _host_guard: Some(host_guard),
        })
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn create_run_dir() -> WorldResult<PathBuf> {
    let root = workspace_root().join("target/e2e/kernel-builder");
    std::fs::create_dir_all(&root).map_err(|error| {
        WorldError(format!(
            "failed to create E2E evidence root {}: {error}",
            root.display()
        ))
    })?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let run_dir = root.join(format!("{timestamp}-{}", std::process::id()));
    std::fs::create_dir(&run_dir).map_err(|error| {
        WorldError(format!(
            "failed to create E2E run directory {}: {error}",
            run_dir.display()
        ))
    })?;
    Ok(run_dir)
}

fn locate_release_artifact() -> WorldResult<PathBuf> {
    RELEASE_ARTIFACT
        .get_or_init(|| {
            let manifest = workspace_root().join("Cargo.toml");
            let cargo = escargot::CargoBuild::new()
                .package("kernel-builder")
                .bin("kernel-builder")
                .release()
                .manifest_path(&manifest);
            #[cfg(feature = "tracing")]
            let cargo = cargo.features("tracing");
            cargo
                .run()
                .map(|run| run.path().to_owned())
                .map_err(|error| {
                    WorldError(format!(
                        "failed to build the release kernel-builder artifact from {}: {error}",
                        manifest.display()
                    ))
                })
        })
        .clone()
}

/// Relays the kernel-builder child's output to the test harness stderr, line
/// by line, so a long in-guest kernel build shows visible progress. Only
/// compiled with `feature = "live-output"`: the retained capture (used for
/// failure evidence) is collected regardless of this feature.
///
/// The relay is non-blocking by design: the read tasks `try_send` each line
/// into a bounded channel and only bump a drop counter when the consumer is
/// slow, so a slow harness pipe can never backpressure the child's stdout
/// and stall the guest's serial stream. A single relay task drains the
/// channel; its blocking affects only itself.
#[cfg(feature = "live-output")]
fn relay_chunk(
    sender: &tokio::sync::mpsc::Sender<String>,
    dropped: &std::sync::atomic::AtomicUsize,
    chunk: &[u8],
) {
    use std::sync::atomic::Ordering;

    let mut lines: Vec<&[u8]> = chunk.split(|byte| *byte == b'\n').collect();
    if chunk.ends_with(b"\n") {
        // A chunk ending in a newline leaves an empty trailing piece; the
        // next chunk starts the next line, so drop it.
        lines.pop();
    }
    for line in lines {
        let line = String::from_utf8_lossy(line).into_owned();
        if sender.try_send(line).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Drains the live relay channel to the harness stderr until every sender is
/// gone. Spawned once per `run_kernel_builder` call; its blocking stderr
/// writes affect only this task, never the child's stdout/stderr readers.
#[cfg(feature = "live-output")]
async fn relay_drain(mut receiver: tokio::sync::mpsc::Receiver<String>) {
    use std::io::Write as _;

    while let Some(line) = receiver.recv().await {
        eprintln!("[kernel-builder] {line}");
    }
    std::io::stderr().flush().ok();
}

async fn run_kernel_builder(artifact: &Path, version: &str, output: &Path) -> BuildOutcome {
    run_kernel_builder_with_config(artifact, version, None, output).await
}

/// Runs the release `kernel-builder` child with an optional complete config
/// file (`--config`) and the shared 90-minute build budget. The child's
/// stdout/stderr are captured (and relayed live under the `live-output`
/// feature); `kill_on_drop` guarantees the child cannot outlive a harness
/// panic.
async fn run_kernel_builder_with_config(
    artifact: &Path,
    version: &str,
    config: Option<&Path>,
    output: &Path,
) -> BuildOutcome {
    let mut command = Command::new(artifact);
    command.args(["--version", version]);
    if let Some(config) = config {
        command.args(["--config"]).arg(config);
    }
    command
        .args(["--output"])
        .arg(output)
        .current_dir(workspace_root())
        // Pin the CLI's cache root: image_core resolves `.jyth-v4` under
        // `CARGO_MANIFEST_DIR`, which the harness would otherwise inherit as
        // `tests/e2e`; the documented CLI cache is
        // `binaries/kernel-builder/target/.jyth-v4`, so the child gets the
        // kernel-builder manifest dir explicitly (the snapshot and reset
        // helpers target the same root).
        .env(
            "CARGO_MANIFEST_DIR",
            workspace_root().join("binaries/kernel-builder"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return BuildOutcome {
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                timed_out: false,
                wait_error: Some(format!("failed to spawn kernel-builder: {error}")),
                kill_error: None,
            };
        }
    };

    #[cfg(feature = "live-output")]
    let (relay_tx, relay_rx) = tokio::sync::mpsc::channel::<String>(256);
    #[cfg(feature = "live-output")]
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    #[cfg(feature = "live-output")]
    let relay_task = tokio::spawn(relay_drain(relay_rx));

    let mut stdout_pipe = child.stdout.take();
    #[cfg(feature = "live-output")]
    let stdout_relay_tx = relay_tx.clone();
    #[cfg(feature = "live-output")]
    let stdout_dropped = dropped.clone();
    let stdout_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        match stdout_pipe.as_mut() {
            Some(pipe) => {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            bytes.extend_from_slice(&chunk[..read]);
                            #[cfg(feature = "live-output")]
                            relay_chunk(&stdout_relay_tx, &stdout_dropped, &chunk[..read]);
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(bytes)
            }
            None => Ok(bytes),
        }
    });

    let mut stderr_pipe = child.stderr.take();
    #[cfg(feature = "live-output")]
    let stderr_relay_tx = relay_tx.clone();
    #[cfg(feature = "live-output")]
    let stderr_dropped = dropped.clone();
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        match stderr_pipe.as_mut() {
            Some(pipe) => {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            bytes.extend_from_slice(&chunk[..read]);
                            #[cfg(feature = "live-output")]
                            relay_chunk(&stderr_relay_tx, &stderr_dropped, &chunk[..read]);
                        }
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Ok(bytes)
            }
            None => Ok(bytes),
        }
    });

    let mut timed_out = false;
    let mut wait_error = None;
    let mut kill_error = None;
    let status = match tokio::time::timeout(BUILD_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => Some(status),
        Ok(Err(error)) => {
            wait_error = Some(format!("kernel-builder wait failed: {error}"));
            None
        }
        Err(_) => {
            timed_out = true;
            if let Err(error) = child.kill().await {
                kill_error = Some(format!(
                    "failed to terminate timed-out kernel-builder: {error}"
                ));
            }
            match child.wait().await {
                Ok(status) => Some(status),
                Err(error) => {
                    wait_error = Some(format!("kernel-builder wait after timeout failed: {error}"));
                    None
                }
            }
        }
    };

    let stdout = stdout_task
        .await
        .unwrap_or_else(|error| Err(format!("kernel-builder stdout reader failed: {error}")));
    let stderr = stderr_task
        .await
        .unwrap_or_else(|error| Err(format!("kernel-builder stderr reader failed: {error}")));

    #[cfg(feature = "live-output")]
    {
        drop(relay_tx);
        if let Err(error) = relay_task.await {
            eprintln!("[kernel-builder] live relay task failed: {error}");
        }
        let dropped_count = dropped.load(std::sync::atomic::Ordering::Relaxed);
        if dropped_count > 0 {
            eprintln!("[kernel-builder] relay dropped {dropped_count} lines (consumer too slow)");
        }
    }

    if let Err(error) = &stdout {
        wait_error.get_or_insert_with(|| error.clone());
    }
    if let Err(error) = &stderr {
        wait_error.get_or_insert_with(|| error.clone());
    }

    BuildOutcome {
        status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        timed_out,
        wait_error,
        kill_error,
    }
}

/// The retained child output: stdout followed by stderr, both lossy
/// UTF-8. The build step scans it for failure signatures (e.g. the
/// `0x80370110` adapter-block) while the raw bytes stay in
/// [`BuildOutcome`] for the failure evidence.
fn retained_output(outcome: &BuildOutcome) -> String {
    let mut output = String::from_utf8_lossy(&outcome.stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(&outcome.stderr));
    output
}

fn failure_evidence(world: &World) -> String {
    let mut evidence = String::new();
    evidence.push_str(&format!(
        "[kernel-builder-e2e] failure evidence\nrun directory: {}\nemitted kernel: {}\n",
        world.run_dir.display(),
        world.emitted_kernel.display()
    ));

    match &world.build {
        Some(build) => {
            evidence.push_str(&format!("kernel-builder status: {:?}\n", build.status));
            evidence.push_str(&format!("kernel-builder timed out: {}\n", build.timed_out));
            if let Some(error) = &build.wait_error {
                evidence.push_str(&format!("kernel-builder wait error: {error}\n"));
            }
            if let Some(error) = &build.kill_error {
                evidence.push_str(&format!("kernel-builder kill error: {error}\n"));
            }
            evidence.push_str(&format!(
                "kernel-builder stdout:\n{}\n",
                String::from_utf8_lossy(&build.stdout)
            ));
            evidence.push_str(&format!(
                "kernel-builder stderr:\n{}\n",
                String::from_utf8_lossy(&build.stderr)
            ));
        }
        None => evidence.push_str("kernel-builder status: not started\n"),
    }

    if let Some((a, b)) = &world.concurrent_builds {
        evidence.push_str("concurrent build A:\n");
        evidence.push_str(&format!(
            "  status: {:?} | timed out: {} | served: {} | compiled: {}\n",
            a.status,
            a.timed_out,
            String::from_utf8_lossy(&a.stdout).contains("served from the shared custom cache"),
            String::from_utf8_lossy(&a.stdout).contains("compiled from the shared custom cache"),
        ));
        evidence.push_str(&format!(
            "  stdout:\n{}\n",
            String::from_utf8_lossy(&a.stdout)
        ));
        evidence.push_str(&format!(
            "  stderr:\n{}\n",
            String::from_utf8_lossy(&a.stderr)
        ));
        evidence.push_str("concurrent build B:\n");
        evidence.push_str(&format!(
            "  status: {:?} | timed out: {} | served: {} | compiled: {}\n",
            b.status,
            b.timed_out,
            String::from_utf8_lossy(&b.stdout).contains("served from the shared custom cache"),
            String::from_utf8_lossy(&b.stdout).contains("compiled from the shared custom cache"),
        ));
        evidence.push_str(&format!(
            "  stdout:\n{}\n",
            String::from_utf8_lossy(&b.stdout)
        ));
        evidence.push_str(&format!(
            "  stderr:\n{}\n",
            String::from_utf8_lossy(&b.stderr)
        ));
    }

    let output_length = std::fs::metadata(&world.emitted_kernel)
        .map(|metadata| metadata.len().to_string())
        .unwrap_or_else(|error| format!("unavailable ({error})"));
    evidence.push_str(&format!("emitted kernel length: {output_length} bytes\n"));

    evidence.push_str(
        "kernel-builder guest stdout/stderr are relayed through the VM console and are included above\n",
    );

    if let Some(error) = &world.consumer_error {
        evidence.push_str(&format!("consumer VM/Jyth error: {error}\n"));
    }
    if let Some(release) = &world.guest_release {
        evidence.push_str(&format!("guest release observed: {release:?}\n"));
    }
    evidence
}

fn fail(world: &mut World, message: impl Into<String>) -> ! {
    let message = message.into();
    world.consumer_error.get_or_insert(message.clone());
    panic!("{message}; run directory: {}", world.run_dir.display());
}

#[given("a supported Windows Hyper-V host")]
async fn supported_windows_hyper_v_host(_world: &mut World) {
    if !cfg!(target_os = "windows") {
        panic!("kernel-builder E2E requires the documented Windows HCS/Hyper-V host");
    }
}

#[given(expr = "kernel-builder is configured to build Linux {string}")]
async fn configured_kernel_version(world: &mut World, version: String) {
    if !SUPPORTED_KERNEL_VERSIONS.contains(&version.as_str()) {
        fail(
            world,
            format!(
                "kernel-builder is not configured to build Linux {version:?}; \
                 supported versions: {}",
                SUPPORTED_KERNEL_VERSIONS.join(", ")
            ),
        );
    }
    world.configured_version = Some(version);
}

#[when("the user builds the kernel with its default configuration")]
async fn build_kernel_with_default_configuration(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    let mut outcome = run_kernel_builder(&world.artifact, &version, &world.emitted_kernel).await;

    // Code-run host remediation: the 0x80370110 adapter-block signature means
    // the HNS/HCS compute stack is degraded. With `JYTH_ADMIN_CONSENT` in the
    // launch environment the stack is restarted (UAC-elevated) and the launch
    // retried once — the code performs the cleanup, the operator consents at
    // launch; without consent the step fails loudly through `{error:#}`.
    if !outcome.succeeded() && retained_output(&outcome).contains("0x80370110") {
        match hcs_admin::restart_compute_services() {
            Ok(()) => {
                eprintln!("[e2e] compute stack restarted; retrying the kernel build once");
                let retry =
                    run_kernel_builder(&world.artifact, &version, &world.emitted_kernel).await;
                if retry.succeeded() {
                    eprintln!("[e2e] retry succeeded after compute-stack restart");
                    outcome = retry;
                } else {
                    eprintln!("[e2e] retry failed after compute-stack restart");
                }
            }
            Err(error) => eprintln!("[e2e] compute-stack restart step: {error:#}"),
        }
    }

    let succeeded = outcome.succeeded();
    world.build = Some(outcome);

    if !succeeded {
        fail(
            world,
            "kernel-builder did not exit successfully; see the retained child output",
        );
    }
}

#[when("the user starts a new Alpine guest with the resulting artifact")]
async fn start_consumer_guest(world: &mut World) {
    let Some(build) = &world.build else {
        fail(world, "the kernel-builder child did not run");
    };
    if !build.succeeded() {
        fail(
            world,
            "the emitted kernel cannot be consumed after a failed build",
        );
    }

    match std::fs::metadata(&world.emitted_kernel) {
        Ok(metadata) if metadata.len() > 0 => {}
        Ok(_) => fail(world, "kernel-builder emitted an empty kernel"),
        Err(error) => fail(
            world,
            format!(
                "kernel-builder did not emit {}: {error}",
                world.emitted_kernel.display()
            ),
        ),
    }

    launch_guest_and_probe_release(world, Kernel::local(world.emitted_kernel.clone())).await;
}

/// Boot one Alpine guest with `kernel`, run `uname -r`, and record the
/// release in [`World::guest_release`]. The VM is retained in a guard so a
/// failing step tears it down instead of leaking it.
async fn launch_guest_and_probe_release(world: &mut World, kernel: Kernel) {
    let rootfs = Rootfs::new(Link::image(ALPINE_ROOTFS));
    match materialize_image(&kernel, &rootfs).await {
        Ok(_) => {}
        Err(error) => fail(
            world,
            format!("consumer image materialization failed: {error}"),
        ),
    }

    let vm = match VmBuilder::new()
        .kernel(kernel)
        .rootfs(rootfs)
        .network(())
        .launch()
        .await
    {
        Ok(vm) => vm,
        Err(error) => fail(world, format!("consumer VM boot failed: {error}")),
    };
    world.consumer_vm = Some(VmGuard::new(vm));

    let (observer, process_builder) = ProcessBuilder::with_observer();
    let process = match process_builder
        .shell("uname -r")
        .stdout(Output::Capture(CaptureOptions::default()))
        .build()
    {
        Ok(process) => process,
        Err(error) => fail(world, format!("failed to prepare uname process: {error}")),
    };

    let exit = match world
        .consumer_vm
        .as_ref()
        .expect("consumer VM is retained before guest execution")
        .run(process)
        .await
    {
        Ok(exit) => exit,
        Err(error) => fail(world, format!("guest uname execution failed: {error}")),
    };
    let observed_exit = match observer.finished().await {
        Ok(exit) => exit,
        Err(error) => fail(world, format!("guest uname observer failed: {error}")),
    };
    if !exit.success() || !observed_exit.success() {
        fail(
            world,
            format!("guest uname exited unsuccessfully: direct={exit}, observer={observed_exit}"),
        );
    }

    let stdout = match observer.stdout().await {
        Ok(stdout) => stdout,
        Err(error) => fail(
            world,
            format!("guest uname stdout was not captured: {error}"),
        ),
    };
    world.guest_release = Some(String::from_utf8_lossy(&stdout).trim().to_owned());
}

#[then(expr = "the guest reports kernel release {string}")]
async fn guest_reports_kernel_release(world: &mut World, expected: String) {
    let actual = world
        .guest_release
        .as_deref()
        .unwrap_or("<guest release was not observed>");
    if actual != expected {
        fail(
            world,
            format!("guest reported kernel release {actual:?}, expected {expected:?}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Custom-kernel cache scenarios (KernelApiDxPlan §12.3)
// ---------------------------------------------------------------------------

/// The release CLI's own cache root: the compiled-in `CARGO_MANIFEST_DIR`
/// (`binaries/kernel-builder`) plus `target/.jyth-v4`. The failure scenario
/// snapshots the kernel namespace to prove a failed build publishes no
/// artifact.
fn cli_kernel_cache_dir() -> PathBuf {
    workspace_root().join("binaries/kernel-builder/target/.jyth-v4/kernel")
}

/// One listing of the CLI custom-kernel cache namespace, excluding the
/// `.locks` directory (a failed digest legitimately leaves its lock file).
fn snapshot_cache_entries() -> BTreeSet<PathBuf> {
    let dir = cli_kernel_cache_dir();
    let mut entries = BTreeSet::new();
    if let Ok(read) = std::fs::read_dir(&dir) {
        for entry in read.flatten() {
            if entry.file_name().to_string_lossy() == ".locks" {
                continue;
            }
            entries.insert(entry.path());
        }
    }
    entries
}

/// Delete every custom-kernel cache entry (the kernel namespace, keeping
/// `.locks`) so a suite run starts from the documented cold state. The
/// kernel-builder CLI recreates everything it needs.
fn reset_custom_kernel_cache() -> std::io::Result<Vec<PathBuf>> {
    let dir = cli_kernel_cache_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut removed = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy() == ".locks" {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_file() {
            std::fs::remove_file(&path)?;
        } else {
            std::fs::remove_dir_all(&path)?;
        }
        removed.push(path);
    }
    Ok(removed)
}

#[when("the user builds the kernel again with its default configuration")]
async fn build_kernel_again(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    let output = world.run_dir.join("bzImage-warm");
    let outcome = run_kernel_builder(&world.artifact, &version, &output).await;
    let succeeded = outcome.succeeded();
    world.second_build = Some(outcome);
    if !succeeded {
        fail(
            world,
            "the repeated kernel build did not exit successfully; see the retained child output",
        );
    }
}

#[then("the second build reports the kernel was served from cache")]
async fn second_build_served_from_cache(world: &mut World) {
    let Some(build) = &world.second_build else {
        fail(world, "the repeated kernel build did not run");
    };
    let output = retained_output(build);
    if !output.contains("served from the shared custom cache") {
        fail(
            world,
            format!("the repeated build did not report a cache hit; output:\n{output}"),
        );
    }
    if output.contains("compiled from the shared custom cache") {
        fail(
            world,
            "the repeated build reported a fresh compilation; expected a warm cache hit",
        );
    }
}

/// Every generated custom-build VHDX lives under the host temp directory with
/// the `jyth-kernel-build-<uuid>.vhdx` prefix (impl/JythReviewRemediationPlan
/// WP1). A successful or failed build must leave none behind after the
/// bootstrap VM close completes.
fn leftover_build_disks() -> Vec<std::path::PathBuf> {
    let root = std::env::temp_dir();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("jyth-kernel-build-"))
        })
        .collect()
}

#[then("no generated build VHDX remains on the host")]
async fn no_generated_build_disk_remains(world: &mut World) {
    // A successful v2 build removes its generated disk after the bootstrap VM
    // close; only a pre-existing stale disk from an interrupted legacy run
    // would remain, and the remediation plan treats that as a manual operator
    // action. Assert that THIS scenario's build left no fresh disk behind.
    let leftovers = leftover_build_disks();
    if !leftovers.is_empty() {
        fail(
            world,
            format!(
                "a successful custom build left generated build disks behind: {}",
                leftovers
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
}

#[when("the user starts an Alpine guest with the default kernel")]
async fn start_default_kernel_guest(world: &mut World) {
    launch_guest_and_probe_release(world, Kernel::default()).await;
}

#[when("two users build the kernel with the same configuration at the same time")]
async fn two_concurrent_builds(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    // Both processes race on one request digest. The persistent custom-kernel
    // cache survives across suite runs, so a plain default-config digest would
    // already be warm on a repeated run (compiled=0 served=2). A per-run
    // unique complete config keeps the digest cold every time, so the
    // cross-process build lock is genuinely exercised and exactly one process
    // compiles.
    let config = world.run_dir.join("concurrent.config");
    let mut bytes = KernelConfig::default().as_bytes().to_vec();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    bytes.extend_from_slice(format!("\nCONFIG_LOCALVERSION=\"-jyth-race-{nanos}\"\n").as_bytes());
    std::fs::write(&config, bytes).expect("write the concurrent-race config");
    let output_a = world.run_dir.join("bzImage-concurrent-a");
    let output_b = world.run_dir.join("bzImage-concurrent-b");
    // Two independent processes race on the same custom request digest; the
    // cross-process build lock must serialize them so exactly one compiles.
    let (a, b) = tokio::join!(
        run_kernel_builder_with_config(&world.artifact, &version, Some(&config), &output_a),
        run_kernel_builder_with_config(&world.artifact, &version, Some(&config), &output_b),
    );
    world.concurrent_builds = Some((a, b));
}

#[then("both builds succeed and exactly one reports a fresh compilation")]
async fn exactly_one_fresh_compilation(world: &mut World) {
    let Some((a, b)) = &world.concurrent_builds else {
        fail(world, "the concurrent kernel builds did not run");
    };
    if !a.succeeded() || !b.succeeded() {
        fail(
            world,
            "one of the concurrent kernel builds failed; see the retained child output",
        );
    }
    let compiled = [a, b]
        .iter()
        .filter(|outcome| {
            retained_output(outcome).contains("compiled from the shared custom cache")
        })
        .count();
    let served = [a, b]
        .iter()
        .filter(|outcome| retained_output(outcome).contains("served from the shared custom cache"))
        .count();
    if compiled != 1 || served != 1 {
        fail(
            world,
            format!(
                "expected exactly one fresh compilation and one cache hit; \
                 saw compiled={compiled} served={served}"
            ),
        );
    }
}

#[when("the user builds the kernel with a configuration missing a required option")]
async fn build_with_missing_required_option(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    // A complete config that explicitly disables the first required option:
    // `olddefconfig` preserves the explicit `n`, so the in-guest
    // `require_builtin_config` check fails deterministically before the
    // expensive compile.
    let config = world.run_dir.join("missing-required.config");
    std::fs::write(&config, "CONFIG_64BIT=n\n").expect("write the broken config");
    world.cache_before = Some(snapshot_cache_entries());
    let output = world.run_dir.join("bzImage-failure");
    let outcome =
        run_kernel_builder_with_config(&world.artifact, &version, Some(&config), &output).await;
    world.cache_after = Some(snapshot_cache_entries());
    world.failure_build = Some(outcome);
}

#[then("the build fails without publishing a custom kernel cache record")]
async fn failed_without_publishing(world: &mut World) {
    let Some(build) = &world.failure_build else {
        fail(world, "the failing kernel build did not run");
    };
    if build.succeeded() {
        fail(
            world,
            "the kernel build with a missing required option must fail",
        );
    }
    let output = retained_output(build);
    // The guest prints the exact missing-option message before exiting; the
    // host error chain carries the bootstrap failure either way. Accept both
    // so a console-relay truncation cannot hide a real guest failure.
    if !output.contains("required kernel option") && !output.contains("bootstrap command failed") {
        fail(
            world,
            format!("the failure output lacks the required-option evidence:\n{output}"),
        );
    }

    let before = world.cache_before.as_ref().expect("cache snapshot taken");
    let after = world.cache_after.as_ref().expect("cache snapshot taken");
    let added: Vec<_> = after.difference(before).collect();
    if !added.is_empty() {
        fail(
            world,
            format!("the failed build published unexpected cache entries: {added:?}"),
        );
    }
}

#[then("no abandoned live-host resources remain")]
async fn no_abandoned_resources(world: &mut World) {
    match hcs_admin::list_abandoned_resources() {
        Ok(inventory) if inventory.is_empty() => {}
        Ok(inventory) => fail(
            world,
            format!(
                "the failed build left {} abandoned VM(s) in the journal",
                inventory.len()
            ),
        ),
        Err(error) => fail(
            world,
            format!("abandoned-resource inspection failed: {error:?}"),
        ),
    }
    let legacy = [
        ("compute system", hcs_admin::list_legacy_compute_systems()),
        ("network", hcs_admin::list_legacy_networks()),
        ("endpoint", hcs_admin::list_legacy_endpoints()),
    ];
    for (kind, result) in legacy {
        match result {
            Ok(items) if items.is_empty() => {}
            Ok(items) => fail(
                world,
                format!(
                    "the failed build left {} legacy {kind}(s) behind",
                    items.len()
                ),
            ),
            Err(error) => fail(world, format!("legacy {kind} inspection failed: {error:?}")),
        }
    }
}

#[when("the user builds the kernel with a complete configuration declaring a local version")]
async fn build_with_localversion_config(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    // Complete configs are injected into the bootstrap guest and applied
    // through `.config` + `olddefconfig`, so this digest is genuinely new and
    // the produced kernel reports the local version suffix in `uname -r`.
    let config = world.run_dir.join("localversion.config");
    let mut bytes = KernelConfig::default().as_bytes().to_vec();
    bytes
        .extend_from_slice(format!("\nCONFIG_LOCALVERSION=\"{LOCALVERSION_SUFFIX}\"\n").as_bytes());
    std::fs::write(&config, bytes).expect("write the local-version config");
    world.localversion_config = Some(config.clone());
    let outcome = run_kernel_builder_with_config(
        &world.artifact,
        &version,
        Some(&config),
        &world.emitted_kernel,
    )
    .await;
    let succeeded = outcome.succeeded();
    world.build = Some(outcome);
    if !succeeded {
        fail(
            world,
            "the local-version kernel build did not exit successfully; see the retained child output",
        );
    }
}

#[then("the build reports a fresh compilation")]
async fn build_reports_fresh_compilation(world: &mut World) {
    let Some(build) = &world.build else {
        fail(world, "the kernel build did not run");
    };
    let output = retained_output(build);
    if !output.contains("compiled from the shared custom cache") {
        fail(
            world,
            format!("the config-change build must compile (cache miss); output:\n{output}"),
        );
    }
}

#[when("the user builds the kernel again with the same complete configuration")]
async fn rebuild_with_same_complete_config(world: &mut World) {
    let version = world
        .configured_version
        .clone()
        .unwrap_or_else(|| DEFAULT_KERNEL_VERSION.to_owned());
    let config = world
        .localversion_config
        .clone()
        .expect("the local-version config was written");
    let output = world.run_dir.join("bzImage-localversion-warm");
    let outcome =
        run_kernel_builder_with_config(&world.artifact, &version, Some(&config), &output).await;
    let succeeded = outcome.succeeded();
    world.second_build = Some(outcome);
    if !succeeded {
        fail(
            world,
            "the repeated local-version build did not exit successfully; see the retained child output",
        );
    }
}

#[tokio::main]
async fn main() {
    // Pre-flight: confirm (or remediate) Hyper-V Administrators membership
    // before any runner/world setup. Informational — on failure the run
    // continues and the runtime gate at `Vm::from_conf` remains the
    // enforcement point; the attached message tells the operator exactly
    // what happened and what to do.
    match hcs_admin::ensure_hyperv_admin_access() {
        Ok(()) => eprintln!("[e2e] Hyper-V Administrators membership confirmed"),
        Err(error) => eprintln!("[e2e] Hyper-V Administrators membership step: {error:#}"),
    }

    // Stale `jyth-nat-*` HNS networks from aborted runs break the
    // network-adapter VM create (0x80370110); clean them, with
    // launch-environment consent (`JYTH_ADMIN_CONSENT`), before launch so
    // the run starts from a clean HNS slate.
    match hcs_admin::cleanup_stale_jyth_networks() {
        Ok(hcs_admin::HnsCleanupOutcome::NoneFound) => {}
        Ok(hcs_admin::HnsCleanupOutcome::Removed { ids }) => eprintln!(
            "[e2e] removed {} stale Jyth HNS network(s): {ids:?}",
            ids.len()
        ),
        Err(error) => eprintln!("[e2e] stale Jyth HNS network cleanup step: {error:#}"),
    }

    // The feature file assumes a cold CLI custom-kernel cache: the first
    // scenario's build warms it and the warm/failure/concurrent scenarios
    // rely on that ordering. A cache left over from an earlier run breaks
    // the "fresh compilation" assertions, so wipe the kernel namespace
    // (the `.locks` directory is retained; it is recreated on demand).
    match reset_custom_kernel_cache() {
        Ok(removed) if removed.is_empty() => {}
        Ok(removed) => eprintln!(
            "[e2e] removed {} stale custom-kernel cache entrie(s) so the suite starts cold",
            removed.len()
        ),
        Err(error) => eprintln!("[e2e] custom-kernel cache reset step: {error:#}"),
    }

    #[cfg(feature = "tracing")]
    tracing::init();

    // Run every acceptance feature under `features/` (currently the pinned
    // 6.6.14 kernel and the Linux 7 scenario). Cucumber's CLI filters allow
    // targeted runs, e.g. `-- --tags @kernel-7`.
    let features = Path::new(env!("CARGO_MANIFEST_DIR")).join("features");
    let writer = World::cucumber()
        .max_concurrent_scenarios(1)
        .after(|_, _, _, finished, world| {
            let failed = matches!(
                finished,
                cucumber::event::ScenarioFinished::BeforeHookFailed(_)
                    | cucumber::event::ScenarioFinished::StepFailed(..)
            );
            Box::pin(async move {
                let Some(world) = world else {
                    return;
                };

                let shutdown_error = if let Some(mut vm) = world.consumer_vm.take() {
                    vm.shutdown().await.err().map(|error| error.to_string())
                } else {
                    None
                };
                if let Some(error) = shutdown_error {
                    world.consumer_error = Some(format!("consumer VM shutdown failed: {error}"));
                    eprintln!("{}", failure_evidence(world));
                    panic!("consumer VM shutdown failed: {error}");
                }

                if failed {
                    eprintln!("{}", failure_evidence(world));
                }
            })
        })
        .run(features)
        .await;

    if writer.execution_has_failed() {
        let mut msg = Vec::with_capacity(3);
        let failed_steps = writer.failed_steps();
        if failed_steps > 0 {
            msg.push(format!(
                "{failed_steps} step{} failed",
                if failed_steps > 1 { "s" } else { "" },
            ));
        }
        let parsing_errors = writer.parsing_errors();
        if parsing_errors > 0 {
            msg.push(format!(
                "{parsing_errors} parsing error{}",
                if parsing_errors > 1 { "s" } else { "" },
            ));
        }
        let hook_errors = writer.hook_errors();
        if hook_errors > 0 {
            msg.push(format!(
                "{hook_errors} hook error{}",
                if hook_errors > 1 { "s" } else { "" },
            ));
        }
        panic!("{}", msg.join(", "));
    }
}
