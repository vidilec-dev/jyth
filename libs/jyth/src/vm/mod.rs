use com::{AsyncStream, TcpEndpoint};
use error_stack::Report;
use guest_client::{DirListing, StreamTransport};
use protocol::Command;
use std::sync::Arc;

use crate::error::{ApiError, ApiResult};
#[cfg(feature = "tracing")]
use tracing::instrument;

/// Per-request timeout for the host's `Command` → guest `Event` roundtrip.
/// Covers `VM::request` (file/dir/process commands, `shutdown`) and process
/// stdio binds. Owned by the guest-client boundary; re-exported here so the
/// facade keeps its documented public path.
pub use guest_client::REQUEST_TIMEOUT;

/// Number of throwaway bytes a service used with
/// [`crate::builder::VmBuilder::launch`] must write to stdout before doing
/// anything else. Empirically, on this HCS build, the host's read of whatever
/// the guest writes on this channel never delivers any data unless the guest
/// has ALREADY written something on it first — a write from the host side
/// alone isn't enough, reading before writing isn't enough, and the write has
/// to come from the service process itself. The exact mechanism wasn't pinned
/// down; see `docs/flows/03-port-forward.decisions`. jyth's host side discards
/// exactly this many bytes before anything reaches the forwarded TCP
/// connection, so this is invisible to whoever connects to `vm.io.port`.
pub const PORT_FORWARD_PRIMING_BYTES: usize = 6;

pub(crate) use jyth_runtime::VmLifecycle;
/// VM lifecycle observer types owned by the jyth-runtime crate and
/// re-exported so the `jyth::vm` public paths compile unchanged.
pub use jyth_runtime::{VmFailure, VmFinish, VmObserver, VmPhase, VmState};

/// Structured disk disposition retained by a running VM (owned by the
/// runtime; re-exported for the public facade path).
pub use jyth_runtime::VmWarning;

mod process;
pub use process::{
    Configured, Executable, MissingExecutable, Process, ProcessBuildError, ProcessBuilder,
};

/// Guest-client process, output, and capture types owned by the guest-client
/// crate and re-exported so the `jyth::vm` public paths compile unchanged.
pub use guest_client::{
    CaptureEnd, CaptureOptions, CaptureOverflowPolicy, DEFAULT_CAPTURE_LIMIT, MAX_CAPTURE_LIMIT,
    Output, OutputStream, ProcessError, ProcessExit, ProcessObserver, ProcessState,
};

/// A live connection to a booted Jyth guest.
///
/// A compatibility wrapper around the runtime's [`jyth_runtime::LiveVm`]
/// (SolidArchitecturePlan A15): the runtime owns the backend instance, the
/// guest client, the dispatcher, the scheduler handle, and the observer;
/// this facade adds the public request/file/process surface and the
/// `com::TcpEndpoint` needed for stdio binds. Dropping it performs synchronous
/// best-effort cleanup; call [`VM::shutdown`] for the ordered, awaited
/// cleanup path.
pub struct VM {
    live: jyth_runtime::LiveVm,
    endpoint: TcpEndpoint,
}

impl VM {
    /// Wrap a runtime live VM. The facade constructs its own TCP endpoint
    /// over the same session capability and VM identity (each command and
    /// bind opens its own connection, so this is equivalent to sharing the
    /// transport's socket value).
    pub(crate) fn from_live(live: jyth_runtime::LiveVm) -> Self {
        let endpoint = TcpEndpoint::new(
            live.command_endpoint().address(),
            live.uuid(),
            (*live.capability()).clone(),
        );
        Self { live, endpoint }
    }

    /// Create a builder for a new VM.
    pub fn builder() -> crate::builder::VmBuilder {
        crate::builder::VmBuilder::new()
    }

    /// The classified disposition of every attached disk: host path, guest
    /// mount, origin (created by this launch vs pre-existing), and the
    /// requested/effective retention. Empty when no disk was requested, or
    /// after [`VM::shutdown`] consumed the backend instance.
    pub fn attached_disks(&self) -> &[vm_model::disk::AttachedDisk] {
        self.live.attached_disks()
    }

    /// Disk lifecycle warnings retained by this VM (see [`VmWarning`]).
    pub fn warnings(&self) -> &[VmWarning] {
        self.live.warnings()
    }

    /// The backing hypervisor VM identifier: the HCS compute-system ID and
    /// the VM identity used in every capability proof. Returns
    /// [`uuid::Uuid::nil`] after [`VM::shutdown`] consumed the backend
    /// instance. This is an identity accessor, not a transport address.
    pub fn uuid(&self) -> uuid::Uuid {
        self.live.uuid()
    }

    /// The effective TCP command endpoint of this VM: the configured guest
    /// IP address and command port the host connects to. The endpoint is
    /// derived from the validated launch `Nat` and never from an
    /// unauthenticated network response.
    pub fn command_endpoint(&self) -> std::net::SocketAddr {
        self.live.command_endpoint().address()
    }

    /// The per-session capability shared with this VM's guest init. It is
    /// the secret every command connection must prove; handle it with the
    /// same care as a password.
    pub fn capability(&self) -> &Arc<protocol::SessionCapability> {
        self.live.capability()
    }

    /// Read a file from the guest.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn file_read(&self, path: &str) -> ApiResult<Vec<u8>> {
        self.live
            .client()
            .files()
            .file_read(path)
            .await
            .map_err(|e| map_client_error(e, "file_read", self.command_endpoint()))
    }

    /// Write bytes to a guest file, replacing its contents.
    #[cfg_attr(feature = "tracing", instrument(skip(self, data), level = "debug"))]
    pub async fn file_write(&self, path: &str, data: impl AsRef<[u8]>) -> ApiResult<()> {
        self.live
            .client()
            .files()
            .file_write(path, data)
            .await
            .map_err(|e| map_client_error(e, "file_write", self.command_endpoint()))
    }

    /// Remove a guest file.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn file_remove(&self, path: &str) -> ApiResult<()> {
        self.live
            .client()
            .files()
            .file_remove(path)
            .await
            .map_err(|e| map_client_error(e, "file_remove", self.command_endpoint()))
    }

    /// Create a guest directory.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn dir_create(&self, path: &str) -> ApiResult<()> {
        self.live
            .client()
            .files()
            .dir_create(path)
            .await
            .map_err(|e| map_client_error(e, "dir_create", self.command_endpoint()))
    }

    /// Remove a guest directory.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn dir_remove(&self, path: &str) -> ApiResult<()> {
        self.live
            .client()
            .files()
            .dir_remove(path)
            .await
            .map_err(|e| map_client_error(e, "dir_remove", self.command_endpoint()))
    }

    /// List entries in a guest directory.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn dir_read(&self, path: &str) -> ApiResult<DirListing> {
        self.live
            .client()
            .files()
            .dir_read(path)
            .await
            .map_err(|e| map_client_error(e, "dir_read", self.command_endpoint()))
    }

    /// Execute a VM-independent process description directly on this VM.
    ///
    /// This first execution slice supports shell/guest-path executables and
    /// guest-side discard/file output. Rust and byte executables must first be
    /// materialized by `VmBuilder::run_on` during initramfs construction.
    pub async fn run(&self, process: Process) -> Result<ProcessExit, ProcessError> {
        let prepared = process.into_prepared()?;
        self.live.client().run_direct(prepared).await
    }

    /// Begin building a process to run inside the guest. Chain `arg(s)`/`cwd`
    /// and finish with [`RunningProcessBuilder::spawn`].
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub fn process(&self, path: &str) -> RunningProcessBuilder {
        let client = self.live.client();
        RunningProcessBuilder::new(
            path.to_string(),
            client.sender().clone(),
            client.streams().clone(),
            client.cleanup_tasks().clone(),
            self.endpoint.clone(),
            self.command_endpoint(),
        )
    }

    /// Convenience: spawn a process with no arguments.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn process_start(&self, path: &str) -> ApiResult<RunningProcess> {
        self.process(path).spawn().await
    }

    /// Convenience: spawn a process with arguments.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn process_start_with_args(
        &self,
        path: &str,
        args: &[&str],
    ) -> ApiResult<RunningProcess> {
        self.process(path).args(args).spawn().await
    }

    /// Gracefully shuts the VM down and awaits exact host-side cleanup.
    ///
    /// This method consumes the VM so a logically stopped handle cannot be
    /// reused. Guest-shutdown and host-cleanup failures are both retained in
    /// the returned report; a guest failure never prevents host cleanup.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn shutdown(self) -> ApiResult<()> {
        self.live.shutdown().await.map_err(map_runtime_error)
    }
}

/// Map one runtime boundary error into the stable public `ApiError` context.
/// The underlying runtime report is preserved as an attached frame.
pub(crate) fn map_runtime_error(error: Report<jyth_runtime::RuntimeError>) -> Report<ApiError> {
    let mapped = match error.current_context() {
        jyth_runtime::RuntimeError::Build => ApiError::Build,
        jyth_runtime::RuntimeError::Transport => ApiError::Transport,
        jyth_runtime::RuntimeError::NetworkRequired => ApiError::NetworkRequired,
        jyth_runtime::RuntimeError::RequestTimedOut => ApiError::RequestTimedOut,
        jyth_runtime::RuntimeError::Protocol => ApiError::Protocol,
        jyth_runtime::RuntimeError::Authentication => ApiError::Authentication,
        jyth_runtime::RuntimeError::Hypervisor => ApiError::Hypervisor,
        jyth_runtime::RuntimeError::Guest { code } => ApiError::Guest { code: *code },
        jyth_runtime::RuntimeError::UnexpectedReply => ApiError::UnexpectedReply,
        jyth_runtime::RuntimeError::ReadyTimeout => ApiError::ReadyTimeout,
        jyth_runtime::RuntimeError::VmCreate => ApiError::VmCreate,
        jyth_runtime::RuntimeError::Shutdown => ApiError::Shutdown,
        jyth_runtime::RuntimeError::ProcessClose => ApiError::ProcessClose,
        jyth_runtime::RuntimeError::Bind => ApiError::Bind,
        jyth_runtime::RuntimeError::InvalidState => ApiError::InvalidState,
    };
    error.change_context(mapped)
}

/// One complete `RequestTimedOut` report for the bounded request class: the
/// calling operation, the full [`REQUEST_TIMEOUT`] budget, and the command
/// endpoint it was waiting on (spec capability `error-report-completeness`).
/// Every facade timeout path uses this single constructor so one timeout
/// category always carries one attachment convention.
fn request_timeout_report(
    operation: &'static str,
    endpoint: std::net::SocketAddr,
) -> error_stack::Report<ApiError> {
    Report::new(ApiError::RequestTimedOut)
        .attach(format!("operation={operation}"))
        .attach(format!("budget={:?}", REQUEST_TIMEOUT))
        .attach(format!("endpoint={endpoint}"))
}

/// Map one guest-client boundary error into the stable public `ApiError`
/// context. This is the single facade translation point for the guest
/// command boundary.
///
/// `operation` and `endpoint` describe the call site that hit the deadline;
/// they are attached to the `RequestTimedOut` report so every facade-facing
/// timeout is complete (spec capability `error-report-completeness`).
fn map_client_error(
    error: guest_client::GuestClientError,
    operation: &'static str,
    endpoint: std::net::SocketAddr,
) -> Report<ApiError> {
    match error {
        guest_client::GuestClientError::Transport => Report::new(ApiError::Transport),
        guest_client::GuestClientError::RequestTimedOut => {
            request_timeout_report(operation, endpoint)
        }
        guest_client::GuestClientError::Guest { code, message } => {
            Report::new(ApiError::Guest { code }).attach(format!("guest error: {message}"))
        }
        guest_client::GuestClientError::UnexpectedReply => Report::new(ApiError::UnexpectedReply),
        guest_client::GuestClientError::Shutdown => Report::new(ApiError::Shutdown),
        guest_client::GuestClientError::InvalidState => Report::new(ApiError::InvalidState),
        guest_client::GuestClientError::ProcessClose => Report::new(ApiError::ProcessClose),
        guest_client::GuestClientError::Bind => Report::new(ApiError::Bind),
    }
}

/// Builder for a guest process with live stdio bindings. The guest-client
/// [`guest_client::PreparedProcessBuilder`] owns the spawn protocol; this
/// facade wrapper additionally retains the `com::TcpEndpoint` so the bound
/// stdio streams keep the `com::AsyncStream` public type, plus the command
/// endpoint for complete timeout reports.
pub struct RunningProcessBuilder {
    inner: guest_client::PreparedProcessBuilder,
    endpoint: TcpEndpoint,
    command_endpoint: std::net::SocketAddr,
}

impl RunningProcessBuilder {
    pub(crate) fn new(
        path: String,
        cmd_tx: tokio::sync::mpsc::Sender<guest_client::HostRequest>,
        streams: Arc<dyn StreamTransport>,
        cleanup_tasks: Arc<guest_client::CleanupTasks>,
        endpoint: TcpEndpoint,
        command_endpoint: std::net::SocketAddr,
    ) -> Self {
        Self {
            inner: guest_client::PreparedProcessBuilder::new(path, cmd_tx, cleanup_tasks, streams),
            endpoint,
            command_endpoint,
        }
    }

    /// Append one guest process argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.inner = self.inner.arg(arg);
        self
    }

    /// Append guest process arguments.
    pub fn args(mut self, args: &[&str]) -> Self {
        self.inner = self.inner.args(args);
        self
    }

    /// Add one guest process environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.env(key, value);
        self
    }

    /// Set the working directory the process runs in, inside the guest.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.inner = self.inner.cwd(cwd);
        self
    }

    /// Spawn the process in the guest. Returns a [`RunningProcess`] handle
    /// once the guest acks `ProcessStarted`.
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(path = %self.inner.path()), level = "debug"))]
    pub async fn spawn(self) -> ApiResult<RunningProcess> {
        let Self {
            inner,
            endpoint,
            command_endpoint,
        } = self;
        let inner = inner
            .spawn()
            .await
            .map_err(|e| map_client_error(e, "process_spawn", command_endpoint))?;
        Ok(RunningProcess {
            inner,
            endpoint,
            command_endpoint,
        })
    }
}

/// A handle for a process running inside a Jyth guest.
///
/// The guest-client crate owns the process lifecycle (wait, close, drop
/// cleanup); this facade wrapper adds the `com::TcpEndpoint` needed for stdio
/// binds, whose streams are the public `com::AsyncStream` type, plus the
/// command endpoint for complete timeout reports.
pub struct RunningProcess {
    inner: guest_client::RunningProcess,
    endpoint: TcpEndpoint,
    command_endpoint: std::net::SocketAddr,
}

impl RunningProcess {
    /// Wait for natural completion without stopping or consuming this handle.
    /// This deliberately has no request timeout: a guest process may validly
    /// outlive [`REQUEST_TIMEOUT`]. The dispatcher places this long-running
    /// operation on a separate permit lane, and VM shutdown cancels it before
    /// joining the dispatcher. Repeated calls replay the guest's retained
    /// terminal status.
    pub async fn wait(&mut self) -> ApiResult<ProcessExit> {
        self.inner
            .wait()
            .await
            .map_err(|e| map_client_error(e, "process_wait", self.command_endpoint))
    }

    /// Bind the process's stdio as a length-framed byte stream (the default,
    /// recommended mode): every host read/write is a self-delimiting
    /// `[u32 len][bytes]` frame, so callers never have to worry about
    /// message boundaries.
    ///
    /// The `ProcessBind` ack roundtrip is bounded by [`REQUEST_TIMEOUT`];
    /// a slow or silent guest surfaces as `ApiError::RequestTimedOut` instead
    /// of an indefinite hang.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn bind_framed(&mut self) -> ApiResult<AsyncStream> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let stream = tokio::time::timeout_at(
            deadline,
            self.endpoint.bind_async(Command::ProcessBind {
                uuid: self.inner.uuid(),
                stay_framed: true,
            }),
        )
        .await
        .map_err(|_| request_timeout_report("process_bind_framed", self.command_endpoint))?
        .map_err(|error| error.change_context(ApiError::Bind))?;
        Ok(stream)
    }

    /// Bind the process's stdio as a raw byte stream. The previous default;
    /// kept as an escape hatch for protocols that need byte-exact streams
    /// (e.g. the port-forward priming workaround). `bind` is `bind_framed`.
    ///
    /// Bounded by [`REQUEST_TIMEOUT`] just like [`bind_framed`](Self::bind_framed).
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn bind_raw(&mut self) -> ApiResult<AsyncStream> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let stream = tokio::time::timeout_at(
            deadline,
            self.endpoint.bind_async(Command::ProcessBind {
                uuid: self.inner.uuid(),
                stay_framed: false,
            }),
        )
        .await
        .map_err(|_| request_timeout_report("process_bind_raw", self.command_endpoint))?
        .map_err(|error| error.change_context(ApiError::Bind))?;
        Ok(stream)
    }

    /// Stop the process, then discard its retained exit record. Dropping an
    /// unclosed handle performs the same best-effort cleanup.
    ///
    /// Bounded by [`REQUEST_TIMEOUT`]; a silent guest surfaces as
    /// `ApiError::ProcessClose` instead of an indefinite hang.
    #[cfg_attr(feature = "tracing", instrument(skip(self), level = "debug"))]
    pub async fn close(&mut self) -> ApiResult<()> {
        self.inner
            .close()
            .await
            .map_err(|e| map_client_error(e, "process_close", self.command_endpoint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> std::net::SocketAddr {
        "127.0.0.1:8000".parse().unwrap()
    }

    /// A `RequestTimedOut` report at the jyth facade carries the operation
    /// name, the 5s request-class budget, and the command endpoint, alongside
    /// the stable public `ApiError` category.
    #[test]
    fn request_timed_out_report_carries_operation_budget_and_endpoint() {
        let report = map_client_error(
            guest_client::GuestClientError::RequestTimedOut,
            "file_read",
            endpoint(),
        );

        assert!(matches!(
            report.current_context(),
            ApiError::RequestTimedOut
        ));
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("operation=file_read"))),
            "the report must carry the operation attachment: {report:?}"
        );
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("budget=5s"))),
            "the report must carry the 5s budget attachment: {report:?}"
        );
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("endpoint=127.0.0.1:8000"))),
            "the report must carry the endpoint attachment: {report:?}"
        );
    }

    /// Triangulation: the attachments reflect the calling operation and
    /// endpoint rather than a hardcoded constant.
    #[test]
    fn request_timed_out_report_reflects_the_calling_operation_and_endpoint() {
        let report = map_client_error(
            guest_client::GuestClientError::RequestTimedOut,
            "process_wait",
            "10.0.0.5:8000".parse().unwrap(),
        );

        assert!(matches!(
            report.current_context(),
            ApiError::RequestTimedOut
        ));
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("operation=process_wait"))),
            "the report must carry the call-site operation: {report:?}"
        );
        assert!(
            report.frames().any(|f| f
                .downcast_ref::<String>()
                .is_some_and(|s| s.contains("endpoint=10.0.0.5:8000"))),
            "the report must carry the call-site endpoint: {report:?}"
        );
    }

    /// A scripted command transport that acks `ProcessStart` with the
    /// matching uuid so the facade spawn path completes without a live guest.
    struct StartAckTransport;

    impl guest_client::CommandTransport for StartAckTransport {
        fn command_async(&self, cmd: Command) -> guest_client::TransportFuture {
            Box::pin(async move {
                match cmd {
                    Command::ProcessStart { uuid, .. } => {
                        Ok(protocol::Event::ProcessStarted { uuid })
                    }
                    Command::ProcessClose { uuid } => Ok(protocol::Event::ProcessClosed { uuid }),
                    _ => Ok(protocol::Event::Shutdowned),
                }
            })
        }
    }

    /// A `StreamTransport` fake for the facade spawn path. The bind tests
    /// exercise `bind_framed`, which uses the `com::TcpEndpoint` directly and
    /// never reaches this transport, so any call is a test bug.
    struct UnusedStreams;

    impl guest_client::StreamTransport for UnusedStreams {
        fn bind_async(&self, _cmd: Command) -> guest_client::StreamFuture {
            Box::pin(async { Err(guest_client::GuestClientError::InvalidState) })
        }
    }

    /// F-05 regression: the facade `bind_framed` outer deadline constructs a
    /// bare `ApiError::RequestTimedOut` without the operation/budget/endpoint
    /// attachments every other facade timeout carries. The fake guest
    /// completes the TCP auth exchange, then never answers the bind command;
    /// the facade's outer deadline (registered before the inner reply
    /// deadline) fires first, deterministically, without a live host.
    #[tokio::test]
    async fn bind_timeout_report_carries_the_standard_attachments() {
        use protocol::auth::{AuthAcceptedV1, AuthChallengeV1, AuthResponseV1, PROTOCOL_VERSION};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        // A fake guest that authenticates over the raw wire format
        // `[u32 LE length][payload]`, then stays silent on the bind command
        // so the host stalls until the facade's outer deadline.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("silent listener");
        let address = listener.local_addr().expect("listener address");
        let capability = Arc::new(protocol::SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = uuid::Uuid::nil();
        let guest_capability = capability.clone();
        let _silent = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("bind connection");

            async fn write_frame(socket: &mut tokio::net::TcpStream, payload: &[u8]) {
                let length = u32::try_from(payload.len()).expect("frame length");
                socket.write_all(&length.to_le_bytes()).await.expect("len");
                socket.write_all(payload).await.expect("payload");
                socket.flush().await.expect("flush");
            }
            async fn read_frame(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
                let mut length_bytes = [0u8; 4];
                socket.read_exact(&mut length_bytes).await.expect("len");
                let length = u32::from_le_bytes(length_bytes) as usize;
                let mut payload = vec![0u8; length];
                socket.read_exact(&mut payload).await.expect("payload");
                payload
            }

            let challenge = AuthChallengeV1 {
                version: PROTOCOL_VERSION,
                challenge: [0xa5; 32],
            };
            write_frame(&mut socket, &challenge.to_bytes().expect("challenge")).await;
            let response = AuthResponseV1::try_from(read_frame(&mut socket).await.as_slice())
                .expect("parse response");
            let expected = AuthResponseV1::for_challenge(&guest_capability, &vm_id, &challenge);
            assert_eq!(response.mac, expected.mac, "scripted response MAC");
            // Delay the auth completion so the host's inner reply deadline
            // (5s from after auth) starts well after the facade's outer
            // deadline (5s from before auth): the outer deadline fires
            // first, deterministically, instead of racing the inner one.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            write_frame(
                &mut socket,
                &AuthAcceptedV1 {
                    version: PROTOCOL_VERSION,
                }
                .to_bytes()
                .expect("accepted"),
            )
            .await;
            // Authenticated, but the ProcessBind reply never arrives.
            let _held = socket;
            std::future::pending::<()>().await;
        });

        // Dispatcher over the scripted transport so spawn() completes.
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<guest_client::HostRequest>(8);
        let cancel = CancellationToken::new();
        let dispatcher = guest_client::Dispatcher::new(cmd_rx, Arc::new(StartAckTransport), cancel);
        let _dispatcher_task = tokio::spawn(dispatcher.run());

        let endpoint = com::TcpEndpoint::new(address, vm_id, capability);
        let process = RunningProcessBuilder::new(
            "/bin/tool".to_string(),
            cmd_tx,
            Arc::new(UnusedStreams),
            Arc::new(guest_client::CleanupTasks::new()),
            endpoint,
            address,
        )
        .spawn()
        .await
        .expect("scripted spawn must succeed");

        // Drive the bind against the silent authenticated peer: the facade's
        // outer deadline (registered before the inner reply deadline) fires
        // first, so the test deterministically exercises the bind timeout
        // report path.
        let mut process = process;
        let report = process
            .bind_framed()
            .await
            .expect_err("a silent peer must time out the bind");

        assert!(matches!(
            report.current_context(),
            ApiError::RequestTimedOut
        ));
        let endpoint_attachment = format!("endpoint={address}");
        for expected in [
            "operation=process_bind_framed",
            "budget=5s",
            endpoint_attachment.as_str(),
        ] {
            assert!(
                report.frames().any(|f| f
                    .downcast_ref::<String>()
                    .is_some_and(|s| s.contains(expected))),
                "the bind timeout report must carry {expected}: {report:?}"
            );
        }
    }

    /// Raw-bind timeouts carry the same complete attachments with their own
    /// operation name, so framed and raw modes are distinguishable in logs.
    #[tokio::test]
    async fn raw_bind_timeout_report_carries_the_standard_attachments() {
        use protocol::auth::{AuthAcceptedV1, AuthChallengeV1, AuthResponseV1, PROTOCOL_VERSION};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("silent listener");
        let address = listener.local_addr().expect("listener address");
        let capability = Arc::new(protocol::SessionCapability::from_bytes([0x5a; 32]));
        let vm_id = uuid::Uuid::nil();
        let guest_capability = capability.clone();
        let _silent = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("bind connection");

            async fn write_frame(socket: &mut tokio::net::TcpStream, payload: &[u8]) {
                let length = u32::try_from(payload.len()).expect("frame length");
                socket.write_all(&length.to_le_bytes()).await.expect("len");
                socket.write_all(payload).await.expect("payload");
                socket.flush().await.expect("flush");
            }
            async fn read_frame(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
                let mut length_bytes = [0u8; 4];
                socket.read_exact(&mut length_bytes).await.expect("len");
                let length = u32::from_le_bytes(length_bytes) as usize;
                let mut payload = vec![0u8; length];
                socket.read_exact(&mut payload).await.expect("payload");
                payload
            }

            let challenge = AuthChallengeV1 {
                version: PROTOCOL_VERSION,
                challenge: [0xa5; 32],
            };
            write_frame(&mut socket, &challenge.to_bytes().expect("challenge")).await;
            let response = AuthResponseV1::try_from(read_frame(&mut socket).await.as_slice())
                .expect("parse response");
            let expected = AuthResponseV1::for_challenge(&guest_capability, &vm_id, &challenge);
            assert_eq!(response.mac, expected.mac, "scripted response MAC");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            write_frame(
                &mut socket,
                &AuthAcceptedV1 {
                    version: PROTOCOL_VERSION,
                }
                .to_bytes()
                .expect("accepted"),
            )
            .await;
            let _held = socket;
            std::future::pending::<()>().await;
        });

        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<guest_client::HostRequest>(8);
        let cancel = CancellationToken::new();
        let dispatcher = guest_client::Dispatcher::new(cmd_rx, Arc::new(StartAckTransport), cancel);
        let _dispatcher_task = tokio::spawn(dispatcher.run());

        let endpoint = com::TcpEndpoint::new(address, vm_id, capability);
        let process = RunningProcessBuilder::new(
            "/bin/tool".to_string(),
            cmd_tx,
            Arc::new(UnusedStreams),
            Arc::new(guest_client::CleanupTasks::new()),
            endpoint,
            address,
        )
        .spawn()
        .await
        .expect("scripted spawn must succeed");

        let mut process = process;
        let report = process
            .bind_raw()
            .await
            .expect_err("a silent peer must time out the raw bind");

        assert!(matches!(
            report.current_context(),
            ApiError::RequestTimedOut
        ));
        let endpoint_attachment = format!("endpoint={address}");
        for expected in [
            "operation=process_bind_raw",
            "budget=5s",
            endpoint_attachment.as_str(),
        ] {
            assert!(
                report.frames().any(|f| f
                    .downcast_ref::<String>()
                    .is_some_and(|s| s.contains(expected))),
                "the raw bind timeout report must carry {expected}: {report:?}"
            );
        }
    }

    /// The single timeout constructor always carries the three standard
    /// attachments regardless of the calling operation.
    #[test]
    fn request_timeout_report_carries_operation_budget_and_endpoint() {
        let report = request_timeout_report("process_wait", "10.0.0.7:8000".parse().unwrap());
        assert!(matches!(
            report.current_context(),
            ApiError::RequestTimedOut
        ));
        for expected in [
            "operation=process_wait",
            "budget=5s",
            "endpoint=10.0.0.7:8000",
        ] {
            assert!(
                report.frames().any(|f| f
                    .downcast_ref::<String>()
                    .is_some_and(|s| s.contains(expected))),
                "missing {expected}: {report:?}"
            );
        }
    }
}
