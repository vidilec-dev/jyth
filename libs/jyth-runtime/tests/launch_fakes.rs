//! Fake-adapter contract tests for the runtime launch and shutdown services.
//!
//! Every port is replaced by a test double so launch failure at every
//! boundary and the ordered shutdown flow are provable without a live host
//! (SolidArchitecturePlan verification matrix, jyth-runtime row).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use error_stack::Report;
use guest_client::{
    CommandTransport, Dispatcher, GuestClientError, PreparedProcess, StreamFuture, StreamTransport,
    TransportFuture,
};
use hypervisor_api::{
    AttachedResource, BackendCapabilities, BackendError, BackendErrorCategory, CloseFuture,
    CreateFuture, PublishFuture, StartFuture, VmFactory, VmInstance, VmLaunchSpec,
};
use jyth_runtime::{
    ArtifactError, BootArtifactProvider, BootChannelError, BootControlChannel, ClientError,
    GuestClient, GuestClientFactory, Launch, LaunchRequest, Launcher, LiveVm,
    PreparedBootArtifacts, RetryPolicy, RuntimeError, ScheduledProcess, VmFinish, VmLifecycle,
    VmState,
};
use protocol::{Command, Event, SessionCapability};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type SharedLog = Arc<Mutex<Vec<String>>>;

fn log() -> SharedLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn push(log: &SharedLog, entry: impl Into<String>) {
    log.lock().expect("test log").push(entry.into());
}

fn has(log: &SharedLog, entry: &str) -> bool {
    log.lock()
        .expect("test log")
        .iter()
        .any(|recorded| recorded == entry)
}

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FakeInstance {
    id: Uuid,
    resources: Vec<AttachedResource>,
    events: SharedLog,
    start: Result<(), BackendError>,
    publish: Result<(), BackendError>,
    close: Result<(), BackendError>,
    drops: Arc<AtomicUsize>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeInstance {
    fn ok(id: Uuid, events: SharedLog) -> Self {
        Self {
            id,
            resources: Vec::new(),
            events,
            start: Ok(()),
            publish: Ok(()),
            close: Ok(()),
            drops: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl Drop for FakeInstance {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if !self.closed.load(Ordering::SeqCst) {
            push(&self.events, "instance_dropped");
        }
    }
}

impl VmInstance for FakeInstance {
    fn identity(&self) -> Uuid {
        self.id
    }

    fn attached_resources(&self) -> &[AttachedResource] {
        &self.resources
    }

    fn start(&self) -> StartFuture {
        push(&self.events, "start");
        let result = self.start.clone();
        Box::pin(async move { result })
    }

    fn mark_published(&self) -> PublishFuture {
        push(&self.events, "published");
        let result = self.publish.clone();
        Box::pin(async move { result })
    }

    fn close(self: Box<Self>) -> CloseFuture {
        push(&self.events, "close");
        self.closed.store(true, Ordering::SeqCst);
        let result = self.close.clone();
        Box::pin(async move {
            // Hold the boxed instance until the awaited cleanup completes,
            // mirroring the production consuming-close contract.
            let _keep_alive = self;
            result
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

enum CreateOutcome {
    Instance(Box<dyn VmInstance>),
    Fail(BackendError),
}

struct FakeVmFactory {
    capabilities: Mutex<BackendCapabilities>,
    script: Arc<Mutex<VecDeque<CreateOutcome>>>,
    attempts: Arc<AtomicUsize>,
}

impl Default for FakeVmFactory {
    fn default() -> Self {
        Self {
            capabilities: Mutex::new(BackendCapabilities {
                available: true,
                networking: true,
                disks: true,
            }),
            script: Arc::new(Mutex::new(VecDeque::new())),
            attempts: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl FakeVmFactory {
    fn push(&self, outcome: CreateOutcome) {
        self.script
            .lock()
            .expect("factory script")
            .push_back(outcome);
    }
}

impl VmFactory for FakeVmFactory {
    fn capabilities(&self) -> BackendCapabilities {
        *self.capabilities.lock().expect("factory capabilities")
    }

    fn create(&self, _spec: VmLaunchSpec) -> CreateFuture {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let outcome = self
            .script
            .lock()
            .expect("factory script")
            .pop_front()
            .unwrap_or(CreateOutcome::Fail(BackendError::permanent(
                BackendErrorCategory::Create,
                "no scripted create outcome",
            )));
        Box::pin(async move {
            match outcome {
                CreateOutcome::Instance(instance) => Ok(instance),
                CreateOutcome::Fail(error) => Err(error),
            }
        })
    }
}

struct FakeBootArtifactProvider {
    result: Mutex<Result<PreparedBootArtifacts, Report<ArtifactError>>>,
    calls: Arc<AtomicUsize>,
}

impl BootArtifactProvider for FakeBootArtifactProvider {
    fn prepare(
        &self,
        kernel_source: PathBuf,
        rootfs_source: PathBuf,
        _overlay_entries: Vec<jyth_runtime::BootOverlayEntry>,
    ) -> jyth_runtime::ArtifactFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = std::mem::replace(
            &mut *self.result.lock().expect("provider result"),
            Err(Report::new(ArtifactError::new("unused"))),
        );
        Box::pin(async move {
            let _ = (kernel_source, rootfs_source);
            result
        })
    }
}

struct FakeBootControlChannel {
    result: Mutex<Result<(), BootChannelError>>,
    calls: Arc<AtomicUsize>,
    events: SharedLog,
}

impl BootControlChannel for FakeBootControlChannel {
    fn exchange_ready(
        &self,
        _instance: &dyn VmInstance,
        _boot_config: &protocol::BootConfigV1,
        _timeout: Duration,
    ) -> jyth_runtime::ReadyFuture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.result.lock().expect("channel result").clone();
        let events = self.events.clone();
        Box::pin(async move {
            push(&events, "exchange_ready");
            result
        })
    }
}

/// A scripted guest command transport recording every command it serves.
struct ScriptedTransport {
    events: SharedLog,
}

impl CommandTransport for ScriptedTransport {
    fn command_async(&self, cmd: Command) -> TransportFuture {
        let events = self.events.clone();
        Box::pin(async move {
            match cmd {
                Command::VMShutdown => {
                    push(&events, "shutdown_command");
                    Ok(Event::Shutdowned)
                }
                Command::ProcessStart { uuid, .. } => {
                    push(&events, "process_start");
                    Ok(Event::ProcessStarted { uuid })
                }
                Command::ProcessWait { uuid } => {
                    push(&events, "process_wait");
                    Ok(Event::ProcessExited {
                        uuid,
                        exit_code: Some(0),
                        signal: None,
                    })
                }
                Command::ProcessStop { uuid } => {
                    push(&events, "process_stop");
                    Ok(Event::ProcessExited {
                        uuid,
                        exit_code: Some(0),
                        signal: None,
                    })
                }
                Command::ProcessClose { uuid } => {
                    push(&events, "process_close");
                    Ok(Event::ProcessClosed { uuid })
                }
                other => {
                    let _ = other;
                    push(&events, "command_other");
                    Ok(Event::VMReady)
                }
            }
        })
    }
}

struct FakeStreams;

impl StreamTransport for FakeStreams {
    fn bind_async(&self, _cmd: Command) -> StreamFuture {
        Box::pin(async { Err(GuestClientError::Bind) })
    }
}

struct FakeGuestClientFactory {
    fail: std::sync::atomic::AtomicBool,
    transport: Arc<ScriptedTransport>,
    events: SharedLog,
}

impl GuestClientFactory for FakeGuestClientFactory {
    fn create(
        &self,
        _instance: &dyn VmInstance,
        _capability: &SessionCapability,
        command_endpoint: jyth_runtime::CommandEndpoint,
    ) -> jyth_runtime::ClientFuture {
        let fail = self.fail.load(Ordering::SeqCst);
        let transport = self.transport.clone();
        let events = self.events.clone();
        Box::pin(async move {
            push(&events, "client_factory");
            push(
                &events,
                format!("client_factory endpoint={}", command_endpoint.address()),
            );
            if fail {
                return Err(ClientError::Create);
            }
            let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(32);
            let cancel = CancellationToken::new();
            let streams: Arc<dyn StreamTransport> = Arc::new(FakeStreams);
            let dispatcher = Dispatcher::new(cmd_rx, transport, cancel.clone());
            let task = tokio::spawn(dispatcher.run());
            Ok(GuestClient::new(cmd_tx, streams, cancel, task))
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The default fake launch network: a valid NAT whose guest address the
/// command endpoint is derived from. Normal launches require it.
fn base_network() -> vm_model::network::Nat {
    vm_model::network::Nat::try_new("10.76.0.0/24", "10.76.0.1", "10.76.0.10", ["8.8.8.8"])
        .expect("the fake NAT must be valid")
}

/// The command endpoint the runtime must derive from [`base_network`].
fn expected_command_endpoint() -> jyth_runtime::CommandEndpoint {
    jyth_runtime::CommandEndpoint::from(&base_network())
}

fn base_request() -> LaunchRequest {
    LaunchRequest {
        kernel_source: PathBuf::from(r"C:\run\kernel.bin"),
        rootfs_source: PathBuf::from(r"C:\run\rootfs.cpio"),
        overlay_entries: Vec::new(),
        memory_mb: None,
        vcpu_count: None,
        cmdline: "console=ttyS0".to_string(),
        network: Some(base_network()),
        disks: Vec::new(),
    }
}

fn launch(request: LaunchRequest) -> Launch {
    Launch {
        request,
        scheduled_processes: Vec::new(),
        shutdown_trigger: None,
    }
}

struct TestLauncher {
    launcher: Launcher,
    factory: Arc<FakeVmFactory>,
    provider: Arc<FakeBootArtifactProvider>,
    channel: Arc<FakeBootControlChannel>,
    clients: Arc<FakeGuestClientFactory>,
}

fn test_launcher(events: SharedLog) -> TestLauncher {
    let factory = Arc::new(FakeVmFactory::default());
    let provider = Arc::new(FakeBootArtifactProvider {
        result: Mutex::new(Ok(PreparedBootArtifacts {
            kernel: PathBuf::from(r"C:\run\kernel.bin"),
            initrd: PathBuf::from(r"C:\run\initrd.img"),
            uncompressed_rootfs_size: 64 * 1024 * 1024,
        })),
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let channel = Arc::new(FakeBootControlChannel {
        result: Mutex::new(Ok(())),
        calls: Arc::new(AtomicUsize::new(0)),
        events: events.clone(),
    });
    let clients = Arc::new(FakeGuestClientFactory {
        fail: std::sync::atomic::AtomicBool::new(false),
        transport: Arc::new(ScriptedTransport {
            events: events.clone(),
        }),
        events: events.clone(),
    });
    let launcher = Launcher::new(
        factory.clone(),
        provider.clone(),
        channel.clone(),
        clients.clone(),
        RetryPolicy {
            max_attempts: 3,
            retry_delay: Duration::from_millis(5),
        },
    );
    TestLauncher {
        launcher,
        factory,
        provider,
        channel,
        clients,
    }
}

fn working_instance(events: SharedLog) -> Box<dyn VmInstance> {
    Box::new(FakeInstance::ok(Uuid::new_v4(), events))
}

fn expect_launch_error(
    result: Result<LiveVm, error_stack::Report<RuntimeError>>,
) -> error_stack::Report<RuntimeError> {
    match result {
        Ok(_) => panic!("expected launch to fail"),
        Err(error) => error,
    }
}

async fn wait_for(log: &SharedLog, entry: &str, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if has(log, entry) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for recorded event {entry:?} in {log:?}"));
}

// ---------------------------------------------------------------------------
// Launch failure at every boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn launch_fails_without_a_network_before_any_materialization() {
    let events = log();
    let t = test_launcher(events.clone());
    let mut request = base_request();
    request.network = None;

    let error = expect_launch_error(t.launcher.launch(launch(request), None).await);
    assert_eq!(*error.current_context(), RuntimeError::NetworkRequired);
    assert_eq!(
        t.provider.calls.load(Ordering::SeqCst),
        0,
        "the missing-network failure must precede kernel/rootfs materialization"
    );
    assert_eq!(t.factory.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn prepare_accepts_a_missing_network_for_bootstrap_preparation() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events)));
    let mut request = base_request();
    request.network = None;

    let bootstrap = protocol::BootstrapConfigV1::new("/bin/true", Vec::new(), "/out/kernel")
        .expect("valid bootstrap config");
    let prepared = t
        .launcher
        .prepare(request, Some(bootstrap))
        .await
        .expect("COM1-only bootstrap preparation must keep the optional network");
    assert!(prepared.boot_config.bootstrap.is_some());
}

#[tokio::test]
async fn launch_fails_when_the_boot_artifact_provider_fails() {
    let events = log();
    let t = test_launcher(events.clone());
    *t.provider.result.lock().unwrap() = Err(Report::new(ArtifactError::new("scripted failure")));

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::Build);
    assert_eq!(t.provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(t.factory.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn launch_fails_when_the_backend_is_unavailable() {
    let events = log();
    let t = test_launcher(events);
    *t.factory.capabilities.lock().unwrap() = BackendCapabilities::unavailable();

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::VmCreate);
    assert_eq!(t.factory.attempts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn launch_fails_when_create_fails_permanently_after_one_attempt() {
    let events = log();
    let t = test_launcher(events);
    t.factory.push(CreateOutcome::Fail(BackendError::permanent(
        BackendErrorCategory::Create,
        "permanent create failure",
    )));

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::VmCreate);
    assert_eq!(t.factory.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn launch_retries_a_retryable_create_failure_then_succeeds() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory.push(CreateOutcome::Fail(BackendError::retryable(
        BackendErrorCategory::Transient,
        "Insufficient system resources exist to complete the requested service",
    )));
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));

    let live = t
        .launcher
        .launch(launch(base_request()), None)
        .await
        .expect("retryable create failure must retry and succeed");
    assert_eq!(t.factory.attempts.load(Ordering::SeqCst), 2);
    live.shutdown().await.expect("shutdown must succeed");
}

#[tokio::test]
async fn launch_fails_when_start_fails_and_drops_the_created_instance() {
    let events = log();
    let t = test_launcher(events.clone());
    let mut instance = FakeInstance::ok(Uuid::new_v4(), events.clone());
    instance.start = Err(BackendError::permanent(
        BackendErrorCategory::Start,
        "start failed",
    ));
    let drops = instance.drops.clone();
    t.factory.push(CreateOutcome::Instance(Box::new(instance)));

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::VmCreate);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "failed instance must be dropped"
    );
}

#[tokio::test]
async fn launch_fails_when_the_ready_exchange_fails() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    *t.channel.result.lock().unwrap() = Err(BootChannelError::timeout("scripted"));

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::ReadyTimeout);
}

#[tokio::test]
async fn launch_fails_when_publication_fails() {
    let events = log();
    let t = test_launcher(events.clone());
    let mut instance = FakeInstance::ok(Uuid::new_v4(), events.clone());
    instance.publish = Err(BackendError::permanent(
        BackendErrorCategory::Publication,
        "publication failed",
    ));
    t.factory.push(CreateOutcome::Instance(Box::new(instance)));

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::Hypervisor);
}

#[tokio::test]
async fn launch_fails_when_the_client_factory_fails_and_cleans_up_the_instance() {
    let events = log();
    let t = test_launcher(events.clone());
    let instance = FakeInstance::ok(Uuid::new_v4(), events.clone());
    let drops = instance.drops.clone();
    t.factory.push(CreateOutcome::Instance(Box::new(instance)));
    t.clients.fail.store(true, Ordering::SeqCst);

    let error = expect_launch_error(t.launcher.launch(launch(base_request()), None).await);
    assert_eq!(*error.current_context(), RuntimeError::Transport);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "a failed launch must never leak the instance"
    );
}

// ---------------------------------------------------------------------------
// Successful launch ordering and observer publication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn successful_launch_publishes_running_and_follows_the_target_order() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    let (observer, lifecycle) = VmLifecycle::new();

    let live = t
        .launcher
        .launch(launch(base_request()), Some(lifecycle))
        .await
        .expect("launch must succeed");
    assert_eq!(observer.state(), VmState::Running);

    let order = events.lock().expect("test log").clone();
    let start = order
        .iter()
        .position(|e| e == "start")
        .expect("start recorded");
    let exchange = order
        .iter()
        .position(|e| e == "exchange_ready")
        .expect("exchange recorded");
    let client = order
        .iter()
        .position(|e| e == "client_factory")
        .expect("client factory recorded");
    let published = order
        .iter()
        .position(|e| e == "published")
        .expect("published recorded");
    assert!(
        start < exchange && exchange < client && client < published,
        "publication must follow client creation (TCP readiness): {order:?}"
    );

    // The client factory must receive the exact command endpoint derived
    // from the launch `Nat` (same guest IP the boot configuration carries).
    let endpoint = format!(
        "client_factory endpoint={}",
        expected_command_endpoint().address()
    );
    assert!(
        order.iter().any(|entry| entry == &endpoint),
        "client creation must receive the endpoint derived from the launch Nat; got {order:?}"
    );

    live.shutdown().await.expect("shutdown must succeed");
}

#[tokio::test]
async fn failed_launch_publishes_a_launch_failure() {
    let events = log();
    let t = test_launcher(events);
    *t.provider.result.lock().unwrap() = Err(Report::new(ArtifactError::new("scripted failure")));
    let (observer, lifecycle) = VmLifecycle::new();

    let _ = expect_launch_error(
        t.launcher
            .launch(launch(base_request()), Some(lifecycle))
            .await,
    );
    assert!(
        matches!(observer.state(), VmState::Failed(failure) if failure.phase == jyth_runtime::VmPhase::Launch)
    );
}

// ---------------------------------------------------------------------------
// Scheduler attachment and ordered shutdown
// ---------------------------------------------------------------------------

fn immediate_scheduled_process() -> ScheduledProcess {
    ScheduledProcess {
        trigger: Box::pin(async { true }),
        process: PreparedProcess {
            path: "/bin/true".to_string(),
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            timeout: None,
            stdout: guest_client::Output::Discard,
            stderr: guest_client::Output::Discard,
            lifecycle: None,
        },
    }
}

#[tokio::test]
async fn scheduled_actions_are_attached_and_run_after_launch() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    let mut launch = launch(base_request());
    launch
        .scheduled_processes
        .push(immediate_scheduled_process());

    let live = t
        .launcher
        .launch(launch, None)
        .await
        .expect("launch must succeed");
    wait_for(&events, "process_start", Duration::from_secs(5)).await;
    live.shutdown().await.expect("shutdown must succeed");
}

#[tokio::test]
async fn shutdown_orders_scheduler_join_command_dispatcher_and_backend_close() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    let (observer, lifecycle) = VmLifecycle::new();
    let live = t
        .launcher
        .launch(launch(base_request()), Some(lifecycle))
        .await
        .expect("launch must succeed");

    live.shutdown().await.expect("shutdown must succeed");

    let order = events.lock().expect("test log").clone();
    let shutdown_cmd = order
        .iter()
        .position(|e| e == "shutdown_command")
        .expect("guest shutdown command recorded");
    let close = order
        .iter()
        .position(|e| e == "close")
        .expect("backend close recorded");
    assert!(
        shutdown_cmd < close,
        "the guest shutdown command must precede backend cleanup"
    );
    assert!(
        !has(&events, "instance_dropped"),
        "consuming close must prevent the Drop fallback"
    );
    assert_eq!(observer.state(), VmState::Finished(VmFinish::Shutdown));
}

#[tokio::test]
async fn dropped_live_vm_runs_the_synchronous_fallback() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    let (observer, lifecycle) = VmLifecycle::new();
    let live = t
        .launcher
        .launch(launch(base_request()), Some(lifecycle))
        .await
        .expect("launch must succeed");

    drop(live);

    assert_eq!(observer.state(), VmState::Finished(VmFinish::Dropped));
    assert!(has(&events, "instance_dropped"));
}

#[tokio::test]
async fn shutdown_joins_scheduled_actions_before_the_guest_command() {
    let events = log();
    let t = test_launcher(events.clone());
    t.factory
        .push(CreateOutcome::Instance(working_instance(events.clone())));
    let mut launch = launch(base_request());
    launch
        .scheduled_processes
        .push(immediate_scheduled_process());
    let live = t
        .launcher
        .launch(launch, None)
        .await
        .expect("launch must succeed");
    wait_for(&events, "process_start", Duration::from_secs(5)).await;

    live.shutdown().await.expect("shutdown must succeed");

    let order = events.lock().expect("test log").clone();
    let process_start = order
        .iter()
        .position(|e| e == "process_start")
        .expect("scheduled process recorded");
    let shutdown_cmd = order
        .iter()
        .position(|e| e == "shutdown_command")
        .expect("guest shutdown command recorded");
    assert!(
        process_start < shutdown_cmd,
        "scheduled work must finish before the guest shutdown command"
    );
}

// ---------------------------------------------------------------------------
// Disk classification and warnings
// ---------------------------------------------------------------------------

fn disk_spec(
    path: &str,
    mount: &str,
    retention: vm_model::disk::DiskRetention,
) -> vm_model::disk::DiskSpec {
    vm_model::disk::DiskSpec::new(
        PathBuf::from(path),
        1024,
        vm_model::disk::GuestMount::new(mount).expect("valid mount"),
        retention,
        vm_model::disk::ExistingDiskPolicy::ReuseAndKeep,
    )
    .expect("valid disk spec")
}

#[tokio::test]
async fn attached_disks_and_warnings_follow_the_backend_classification() {
    let events = log();
    let t = test_launcher(events.clone());
    let mut instance = FakeInstance::ok(Uuid::new_v4(), events.clone());
    instance.resources = vec![
        AttachedResource {
            host_path: PathBuf::from(r"C:\disks\created.vhdx"),
            created_by_launch: true,
        },
        AttachedResource {
            host_path: PathBuf::from(r"C:\disks\existing.vhdx"),
            created_by_launch: false,
        },
    ];
    t.factory.push(CreateOutcome::Instance(Box::new(instance)));
    let mut request = base_request();
    request.disks = vec![
        disk_spec(
            r"C:\disks\created.vhdx",
            "/build",
            vm_model::disk::DiskRetention::Ephemeral,
        ),
        disk_spec(
            r"C:\disks\existing.vhdx",
            "/scratch",
            vm_model::disk::DiskRetention::Ephemeral,
        ),
    ];

    let live = t
        .launcher
        .launch(launch(request), None)
        .await
        .expect("launch must succeed");

    let attached = live.attached_disks();
    assert_eq!(attached.len(), 2);
    assert_eq!(
        attached[0].origin,
        vm_model::disk::DiskOrigin::CreatedByLaunch
    );
    assert_eq!(
        attached[0].effective_retention,
        vm_model::disk::DiskRetention::Ephemeral
    );
    assert_eq!(attached[1].origin, vm_model::disk::DiskOrigin::PreExisting);
    assert_eq!(
        attached[1].effective_retention,
        vm_model::disk::DiskRetention::Persistent,
        "an ephemeral request on an existing path must be reclassified"
    );

    assert_eq!(live.warnings().len(), 1);
    match &live.warnings()[0] {
        jyth_runtime::VmWarning::DiskReusedAsPersistent {
            host_path,
            requested,
            effective,
        } => {
            assert_eq!(host_path, &PathBuf::from(r"C:\disks\existing.vhdx"));
            assert_eq!(*requested, vm_model::disk::DiskRetention::Ephemeral);
            assert_eq!(*effective, vm_model::disk::DiskRetention::Persistent);
        }
    }
    live.shutdown().await.expect("shutdown must succeed");
}
