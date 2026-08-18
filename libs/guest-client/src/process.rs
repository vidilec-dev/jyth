use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use protocol::{Command, Event, ProcessOutputStream, ProcessStdio};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::cleanup::CleanupTasks;
use crate::client::{REQUEST_TIMEOUT, request_expect};
use crate::error::GuestClientError;
use crate::transport::{HostRequest, ProcessStream, StreamTransport};

/// The default maximum number of bytes retained for one captured stream.
///
/// The in-memory ceiling for one stream is [`MAX_CAPTURE_LIMIT`]. Output
/// larger than that must be routed to a host file with
/// [`Output::HostFile`] instead of an in-memory capture.
pub const DEFAULT_CAPTURE_LIMIT: usize = 8 * 1024 * 1024;

/// The maximum number of bytes one captured stream may retain in memory.
///
/// A configured capture limit above this value is rejected at build time
/// by the facade's `ProcessBuilder` with its capture-limit error. Bulk output
/// larger than this maximum must use the [`Output::HostFile`] sink, which
/// streams to a host file without retaining the output in memory.
pub const MAX_CAPTURE_LIMIT: usize = 64 * 1024 * 1024;

/// Determines when a captured value has reached its logical end.
///
/// The runner continues draining the guest stream after this boundary so a
/// guest cannot block because the host stopped reading. Bytes after the
/// boundary are discarded and are not counted against the capture limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureEnd {
    /// Retain output until the guest closes the stream.
    EndOfStream,
    /// Retain the first `n` bytes, or all available bytes if the stream ends
    /// before `n` bytes arrive.
    Bytes(usize),
    /// Retain output through the first occurrence of the delimiter.
    Delimiter(Bytes),
    /// Retain output through the first newline byte.
    Line,
}

/// Selects what happens when a captured stream exceeds its byte limit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CaptureOverflowPolicy {
    /// Stop and close the guest process, returning a typed error.
    #[default]
    Stop,
    /// Retain only the first `limit` bytes and continue draining the stream.
    Truncate,
}

/// Configuration for host-side process-output capture.
///
/// The capture is bounded: at most [`MAX_CAPTURE_LIMIT`] bytes are retained
/// in memory per stream. Output beyond that must be streamed to a host file
/// with [`Output::HostFile`]; do not raise the in-memory limit for bulk
/// output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureOptions {
    limit: usize,
    overflow: CaptureOverflowPolicy,
    end: CaptureEnd,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            limit: DEFAULT_CAPTURE_LIMIT,
            overflow: CaptureOverflowPolicy::default(),
            end: CaptureEnd::EndOfStream,
        }
    }
}

impl CaptureOptions {
    /// Creates the safe default capture configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum retained byte count.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Sets the overflow behavior.
    pub fn with_overflow(mut self, overflow: CaptureOverflowPolicy) -> Self {
        self.overflow = overflow;
        self
    }

    /// Sets the logical end of the retained capture.
    pub fn until(mut self, end: CaptureEnd) -> Self {
        self.end = end;
        self
    }

    /// Return the maximum number of bytes retained for this stream.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Return the action taken when `limit` would be exceeded.
    pub fn overflow(&self) -> CaptureOverflowPolicy {
        self.overflow
    }

    /// Return the boundary at which the retained value ends.
    pub fn end(&self) -> &CaptureEnd {
        &self.end
    }
}

/// Identifies the process output stream associated with an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// Declares where one process output stream should be routed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Output {
    /// Discard the guest stream without retaining it on the host.
    Discard,
    /// Retain the guest stream according to the supplied bounded policy.
    Capture(CaptureOptions),
    /// Stream the guest output to a host file without retaining it in memory.
    ///
    /// This is the sink for bulk output: any stream expected to exceed
    /// [`MAX_CAPTURE_LIMIT`] bytes must be routed here instead of
    /// [`Output::Capture`].
    HostFile(std::path::PathBuf),
    /// Redirect the guest output to a file inside the VM.
    GuestFile(std::path::PathBuf),
}

/// Terminal status reported by a guest process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessExit {
    /// The program's normal exit code, when it exited normally.
    pub exit_code: Option<i32>,
    /// The Unix signal that terminated it, when applicable.
    pub signal: Option<i32>,
}

impl ProcessExit {
    /// Return `true` when the process exited normally with code zero.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && self.signal.is_none()
    }
}

impl std::fmt::Display for ProcessExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.exit_code, self.signal) {
            (Some(code), None) => write!(f, "exit code {code}"),
            (_, Some(signal)) => write!(f, "signal {signal}"),
            (None, None) => f.write_str("unknown exit status"),
        }
    }
}

/// The retained state of a declarative process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessState {
    /// The process has been built but not started.
    Pending,
    /// The guest has acknowledged process start.
    Starting,
    /// The process is running in the guest.
    Running,
    /// The process exited and retained its terminal status.
    Finished(ProcessExit),
    /// Preparation, execution, output routing, timeout, or cleanup failed.
    Failed(ProcessError),
}

impl ProcessState {
    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Finished(_) | Self::Failed(_))
    }
}

/// Failure of process preparation, execution, or cleanup.
///
/// Timeout and cancellation are failures rather than independent lifecycle
/// states. A non-zero/signal exit retains its exact [`ProcessExit`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessError {
    /// A Rust or byte executable was used without initramfs materialization.
    UnpreparedExecutable,
    /// The guest rejected process start.
    Spawn(Arc<str>),
    /// Waiting for the guest process failed.
    Wait(Arc<str>),
    /// Closing or cleaning up the process failed.
    Cleanup(Arc<str>),
    /// Output routing failed.
    Output {
        /// Stream whose routing failed.
        stream: OutputStream,
        /// Routing failure description.
        message: Arc<str>,
        /// Optional cleanup failure observed while recovering.
        cleanup_error: Option<Arc<str>>,
    },
    /// Captured output exceeded its configured limit.
    OutputLimitExceeded {
        /// Stream whose capture exceeded the limit.
        stream: OutputStream,
        /// Configured capture limit in bytes.
        limit: usize,
        /// Optional cleanup failure observed while recovering.
        cleanup_error: Option<Arc<str>>,
    },
    /// Host memory could not be reserved for captured output.
    OutputAllocationFailed {
        /// Stream whose capture could not grow.
        stream: OutputStream,
        /// Total retained bytes that could not be reserved.
        requested: usize,
        /// Optional cleanup failure observed while recovering.
        cleanup_error: Option<Arc<str>>,
    },
    /// The process exited with a non-success status.
    UnsuccessfulExit(ProcessExit),
    /// The process exceeded its deadline.
    TimedOut {
        /// Configured timeout duration.
        after: Duration,
        /// Optional cleanup failure observed while recovering.
        cleanup_error: Option<Arc<str>>,
    },
    /// The process was cancelled cooperatively.
    Cancelled {
        /// Optional cleanup failure observed while recovering.
        cleanup_error: Option<Arc<str>>,
    },
    /// Output was requested before the process reached a terminal state.
    OutputUnavailable,
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnpreparedExecutable => {
                f.write_str("Rust/byte executable was not prepared into the VM initramfs")
            }
            Self::Spawn(message) => write!(f, "failed to spawn process: {message}"),
            Self::Wait(message) => write!(f, "failed while waiting for process: {message}"),
            Self::Cleanup(message) => write!(f, "failed to clean up process: {message}"),
            Self::Output {
                stream,
                message,
                cleanup_error,
            } => {
                write!(f, "failed to route {}: {message}", stream.name())?;
                if let Some(error) = cleanup_error {
                    write!(f, "; cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::OutputLimitExceeded {
                stream,
                limit,
                cleanup_error,
            } => {
                write!(
                    f,
                    "{} output exceeded the capture limit of {limit} bytes",
                    stream.name()
                )?;
                if let Some(error) = cleanup_error {
                    write!(f, "; cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::OutputAllocationFailed {
                stream,
                requested,
                cleanup_error,
            } => {
                write!(
                    f,
                    "failed to reserve {requested} bytes for captured {} output",
                    stream.name()
                )?;
                if let Some(error) = cleanup_error {
                    write!(f, "; cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::UnsuccessfulExit(exit) => write!(f, "process exited unsuccessfully: {exit}"),
            Self::TimedOut {
                after,
                cleanup_error,
            } => {
                write!(f, "process timed out after {after:?}")?;
                if let Some(error) = cleanup_error {
                    write!(f, "; cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::Cancelled { cleanup_error } => {
                f.write_str("process was cancelled")?;
                if let Some(error) = cleanup_error {
                    write!(f, "; cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::OutputUnavailable => f.write_str("captured process output is not available yet"),
        }
    }
}

impl std::error::Error for ProcessError {}

impl ProcessError {
    pub(crate) fn output(stream: OutputStream, message: impl Into<Arc<str>>) -> Self {
        Self::Output {
            stream,
            message: message.into(),
            cleanup_error: None,
        }
    }

    pub(crate) fn output_limit_exceeded(stream: OutputStream, limit: usize) -> Self {
        Self::OutputLimitExceeded {
            stream,
            limit,
            cleanup_error: None,
        }
    }

    pub(crate) fn output_allocation_failed(stream: OutputStream, requested: usize) -> Self {
        Self::OutputAllocationFailed {
            stream,
            requested,
            cleanup_error: None,
        }
    }

    pub(crate) fn with_cleanup(self, cleanup_error: Option<Arc<str>>) -> Self {
        let Some(cleanup_error) = cleanup_error else {
            return self;
        };

        match self {
            Self::Output {
                stream,
                message,
                cleanup_error: previous,
            } => Self::Output {
                stream,
                message,
                cleanup_error: merge_cleanup_errors(previous, Some(cleanup_error)),
            },
            Self::OutputLimitExceeded {
                stream,
                limit,
                cleanup_error: previous,
            } => Self::OutputLimitExceeded {
                stream,
                limit,
                cleanup_error: merge_cleanup_errors(previous, Some(cleanup_error)),
            },
            Self::OutputAllocationFailed {
                stream,
                requested,
                cleanup_error: previous,
            } => Self::OutputAllocationFailed {
                stream,
                requested,
                cleanup_error: merge_cleanup_errors(previous, Some(cleanup_error)),
            },
            other => other,
        }
    }
}

fn merge_cleanup_errors(first: Option<Arc<str>>, second: Option<Arc<str>>) -> Option<Arc<str>> {
    match (first, second) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(first), Some(second)) => Some(Arc::from(format!("{first}; {second}"))),
    }
}

/// A retained, cloneable observer paired with a staged process builder.
#[derive(Clone)]
pub struct ProcessObserver {
    receiver: watch::Receiver<ProcessState>,
    cancel: CancellationToken,
    output: Arc<Mutex<CapturedOutput>>,
}

#[derive(Default)]
struct CapturedOutput {
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

impl ProcessObserver {
    /// Return the latest retained process state.
    pub fn state(&self) -> ProcessState {
        self.receiver.borrow().clone()
    }

    /// Request cooperative cancellation. The runner stops and cleans up an
    /// already-running guest process before publishing `ProcessError::Cancelled`.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Wait for the retained terminal result. The returned future owns a
    /// cloned watch receiver and can therefore be stored as `'static`.
    pub fn finished(
        &self,
    ) -> impl std::future::Future<Output = Result<ProcessExit, ProcessError>> + Send + 'static {
        let mut receiver = self.receiver.clone();
        async move {
            loop {
                match receiver.borrow_and_update().clone() {
                    ProcessState::Finished(exit) => return Ok(exit),
                    ProcessState::Failed(error) => return Err(error),
                    ProcessState::Pending | ProcessState::Starting | ProcessState::Running => {}
                }
                if receiver.changed().await.is_err() {
                    return terminal_from_closed(receiver.borrow().clone());
                }
            }
        }
    }

    /// Return captured stdout after the process reaches a terminal state.
    pub async fn stdout(&self) -> Result<Vec<u8>, ProcessError> {
        self.output
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stdout
            .clone()
            .ok_or(ProcessError::OutputUnavailable)
    }

    /// Return captured stderr after the process reaches a terminal state.
    pub async fn stderr(&self) -> Result<Vec<u8>, ProcessError> {
        self.output
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stderr
            .clone()
            .ok_or(ProcessError::OutputUnavailable)
    }
}

fn terminal_from_closed(state: ProcessState) -> Result<ProcessExit, ProcessError> {
    match state {
        ProcessState::Finished(exit) => Ok(exit),
        ProcessState::Failed(error) => Err(error),
        ProcessState::Pending | ProcessState::Starting | ProcessState::Running => {
            Err(ProcessError::Cancelled {
                cleanup_error: None,
            })
        }
    }
}

/// Producer side of a process observer, retained by the process runner.
#[derive(Clone)]
pub struct ProcessLifecycle {
    sender: watch::Sender<ProcessState>,
    cancel: CancellationToken,
    output: Arc<Mutex<CapturedOutput>>,
}

impl ProcessLifecycle {
    /// Create a lifecycle and its retained observer.
    pub fn new() -> (ProcessObserver, Self) {
        let (sender, receiver) = watch::channel(ProcessState::Pending);
        let cancel = CancellationToken::new();
        let output = Arc::new(Mutex::new(CapturedOutput::default()));
        (
            ProcessObserver {
                receiver,
                cancel: cancel.clone(),
                output: output.clone(),
            },
            Self {
                sender,
                cancel,
                output,
            },
        )
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Publish the pre-spawn starting state.
    pub fn starting(&self) {
        self.set(ProcessState::Starting);
    }

    pub(crate) fn running(&self) {
        self.set(ProcessState::Running);
    }

    pub(crate) fn finished(&self, exit: ProcessExit) {
        self.set(ProcessState::Finished(exit));
    }

    /// Publish a terminal failure.
    pub fn failed(&self, error: ProcessError) {
        self.set(ProcessState::Failed(error));
    }

    pub(crate) fn capture_stdout(&self, bytes: Vec<u8>) {
        self.output
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stdout = Some(bytes);
    }

    pub(crate) fn capture_stderr(&self, bytes: Vec<u8>) {
        self.output
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stderr = Some(bytes);
    }

    fn set(&self, next: ProcessState) {
        let _ = self.sender.send_if_modified(|current| {
            if current.is_terminal() {
                false
            } else {
                *current = next;
                true
            }
        });
    }
}

/// A prepared guest process: a validated guest program path plus its
/// environment, working directory, timeout, output routing, and lifecycle.
///
/// Prepared processes carry no host-side executable source (`Rust`/`Bytes`);
/// the facade materializes those into guest paths before construction.
pub struct PreparedProcess {
    /// Guest executable path to start.
    pub path: String,
    /// Ordered guest arguments.
    pub args: Vec<String>,
    /// Guest environment key/value pairs.
    pub envs: Vec<(String, String)>,
    /// Optional guest working directory.
    pub cwd: Option<String>,
    /// Optional execution timeout.
    pub timeout: Option<Duration>,
    /// Stdout routing policy.
    pub stdout: Output,
    /// Stderr routing policy.
    pub stderr: Output,
    /// Retained observer lifecycle, when one was requested.
    pub lifecycle: Option<ProcessLifecycle>,
}

impl std::fmt::Debug for PreparedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedProcess")
            .field("path", &self.path)
            .field("args", &self.args)
            .field("envs", &self.envs)
            .field("cwd", &self.cwd)
            .field("timeout", &self.timeout)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish_non_exhaustive()
    }
}

/// Builder for a guest process over a dispatcher and stream transport.
pub struct PreparedProcessBuilder {
    path: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    cwd: Option<String>,
    stdout: ProcessStdio,
    stderr: ProcessStdio,
    cmd_tx: mpsc::Sender<HostRequest>,
    cleanup: Arc<CleanupTasks>,
    streams: Arc<dyn StreamTransport>,
}

impl PreparedProcessBuilder {
    /// Start building a guest process at a prepared guest executable path.
    pub fn new(
        path: String,
        cmd_tx: mpsc::Sender<HostRequest>,
        cleanup: Arc<CleanupTasks>,
        streams: Arc<dyn StreamTransport>,
    ) -> Self {
        Self {
            path,
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            stdout: ProcessStdio::Pipe,
            stderr: ProcessStdio::Pipe,
            cmd_tx,
            cleanup,
            streams,
        }
    }

    /// The prepared guest executable path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Append one guest process argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append guest process arguments.
    pub fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Add one guest process environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Set the working directory the process runs in, inside the guest.
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Route stdout to the guest-side stdio mode (pipe, null, or guest file).
    pub fn stdout_mode(mut self, stdout: ProcessStdio) -> Self {
        self.stdout = stdout;
        self
    }

    /// Route stderr to the guest-side stdio mode (pipe, null, or guest file).
    pub fn stderr_mode(mut self, stderr: ProcessStdio) -> Self {
        self.stderr = stderr;
        self
    }

    /// Spawn the process in the guest. Returns a [`RunningProcess`] handle
    /// once the guest acks `ProcessStarted` with the matching uuid.
    pub async fn spawn(self) -> Result<RunningProcess, GuestClientError> {
        let uuid = uuid::Uuid::now_v7();
        let Self {
            path,
            args,
            envs,
            cwd,
            stdout,
            stderr,
            cmd_tx,
            cleanup,
            streams,
        } = self;
        match request_expect(
            &cmd_tx,
            Command::ProcessStart {
                uuid,
                path,
                args,
                envs,
                cwd,
                stdout,
                stderr,
            },
        )
        .await?
        {
            Event::ProcessStarted { uuid: reply_uuid } if reply_uuid == uuid => {
                Ok(RunningProcess {
                    uuid,
                    cmd_tx,
                    cleanup,
                    streams,
                    closed: false,
                })
            }
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }
}

/// A handle for a process running inside a guest.
pub struct RunningProcess {
    pub(crate) uuid: uuid::Uuid,
    pub(crate) cmd_tx: mpsc::Sender<HostRequest>,
    pub(crate) cleanup: Arc<CleanupTasks>,
    pub(crate) streams: Arc<dyn StreamTransport>,
    pub(crate) closed: bool,
}

impl std::fmt::Debug for RunningProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningProcess")
            .field("uuid", &self.uuid)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl RunningProcess {
    /// The guest-assigned process identifier.
    pub fn uuid(&self) -> uuid::Uuid {
        self.uuid
    }

    /// Wait for natural completion without stopping or consuming this handle.
    /// This deliberately has no request timeout: a guest process may validly
    /// outlive [`REQUEST_TIMEOUT`]. The dispatcher places this long-running
    /// operation on a separate permit lane, and VM shutdown cancels it before
    /// joining the dispatcher. Repeated calls replay the guest's retained
    /// terminal status.
    pub async fn wait(&mut self) -> Result<ProcessExit, GuestClientError> {
        if self.closed {
            return Err(GuestClientError::InvalidState);
        }
        let reply = crate::client::Client::request_without_deadline(
            self.cmd_tx.clone(),
            Command::ProcessWait { uuid: self.uuid },
        )
        .await?;
        match reply {
            Event::Error { code, msg } => Err(GuestClientError::Guest {
                code: protocol::GuestErrorCode::from_u32(code),
                message: msg,
            }),
            Event::ProcessExited {
                uuid,
                exit_code,
                signal,
            } if uuid == self.uuid => Ok(ProcessExit { exit_code, signal }),
            _ => Err(GuestClientError::UnexpectedReply),
        }
    }

    /// Bind one process output stream as a raw byte stream.
    pub(crate) async fn bind_output_raw(
        &self,
        stream: ProcessOutputStream,
    ) -> Result<Box<dyn ProcessStream>, GuestClientError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.streams.bind_async(Command::ProcessOutputBind {
                uuid: self.uuid,
                stream,
            }),
        )
        .await
        .map_err(|_| GuestClientError::RequestTimedOut)?
    }

    /// Bind the process's stdio as a length-framed byte stream (the default,
    /// recommended mode): every host read/write is a self-delimiting
    /// `[u32 len][bytes]` frame, so callers never have to worry about
    /// message boundaries.
    ///
    /// The `ProcessBind` ack roundtrip is bounded by [`REQUEST_TIMEOUT`];
    /// a slow or silent guest surfaces as a typed timeout instead of an
    /// indefinite hang.
    pub async fn bind_framed(&mut self) -> Result<Box<dyn ProcessStream>, GuestClientError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.streams.bind_async(Command::ProcessBind {
                uuid: self.uuid,
                stay_framed: true,
            }),
        )
        .await
        .map_err(|_| GuestClientError::RequestTimedOut)?
    }

    /// Bind the process's stdio as a raw byte stream. Kept as an escape
    /// hatch for protocols that need byte-exact streams (e.g. the port-
    /// forward priming workaround). `bind` is `bind_framed`.
    ///
    /// Bounded by [`REQUEST_TIMEOUT`] just like [`bind_framed`](Self::bind_framed).
    pub async fn bind_raw(&mut self) -> Result<Box<dyn ProcessStream>, GuestClientError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        tokio::time::timeout_at(
            deadline,
            self.streams.bind_async(Command::ProcessBind {
                uuid: self.uuid,
                stay_framed: false,
            }),
        )
        .await
        .map_err(|_| GuestClientError::RequestTimedOut)?
    }

    /// Stop the process, then discard its retained exit record. Dropping an
    /// unclosed handle performs the same best-effort cleanup.
    ///
    /// Bounded by [`REQUEST_TIMEOUT`]; a silent guest surfaces as
    /// `GuestClientError::ProcessClose` instead of an indefinite hang.
    pub async fn close(&mut self) -> Result<(), GuestClientError> {
        if self.closed {
            return Ok(());
        }
        match request_expect(&self.cmd_tx, Command::ProcessStop { uuid: self.uuid }).await {
            Ok(Event::ProcessExited { uuid, .. }) if uuid == self.uuid => {}
            Ok(Event::Shutdowned) => {}
            Ok(_) => return Err(GuestClientError::UnexpectedReply),
            Err(_) => return Err(GuestClientError::ProcessClose),
        }
        match request_expect(&self.cmd_tx, Command::ProcessClose { uuid: self.uuid }).await {
            Ok(Event::ProcessClosed { uuid }) if uuid == self.uuid => {
                self.closed = true;
                Ok(())
            }
            Ok(_) => Err(GuestClientError::UnexpectedReply),
            Err(_) => Err(GuestClientError::ProcessClose),
        }
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        let (tx, _rx) = oneshot::channel();
        if self.closed {
            return;
        }
        let request = HostRequest {
            cmd: Command::ProcessClose { uuid: self.uuid },
            deadline: Some(Instant::now() + REQUEST_TIMEOUT),
            reply: tx,
        };
        self.cleanup.enqueue(self.cmd_tx.clone(), request);
    }
}

/// Accumulates captured stream bytes under the configured capture policy.
pub(crate) struct CaptureAccumulator {
    options: CaptureOptions,
    stream: OutputStream,
    bytes: Vec<u8>,
    end_reached: bool,
    /// Test hook: make the next reservation fail with a typed allocation
    /// error instead of asking the allocator. Never set in production.
    #[cfg(test)]
    fail_reserves: bool,
}

impl CaptureAccumulator {
    pub(crate) fn new(options: CaptureOptions, stream: OutputStream) -> Self {
        Self {
            options,
            stream,
            bytes: Vec::new(),
            end_reached: false,
            #[cfg(test)]
            fail_reserves: false,
        }
    }

    #[cfg(test)]
    fn new_failing_reserves(options: CaptureOptions, stream: OutputStream) -> Self {
        Self {
            options,
            stream,
            bytes: Vec::new(),
            end_reached: false,
            fail_reserves: true,
        }
    }

    pub(crate) fn push(&mut self, incoming: &[u8]) -> Result<(), ProcessError> {
        if self.end_reached || incoming.is_empty() {
            return Ok(());
        }

        match self.options.end().clone() {
            CaptureEnd::EndOfStream => self.append(incoming),
            CaptureEnd::Bytes(size) => {
                let Some(remaining) = size.checked_sub(self.bytes.len()) else {
                    self.end_reached = true;
                    return Ok(());
                };
                let count = remaining.min(incoming.len());
                self.append(&incoming[..count])?;
                if self.bytes.len() >= size {
                    self.end_reached = true;
                }
                Ok(())
            }
            CaptureEnd::Delimiter(delimiter) => {
                if let Some(end) = find_delimiter_end(&self.bytes, incoming, &delimiter) {
                    let Some(count) = end.checked_sub(self.bytes.len()) else {
                        self.end_reached = true;
                        return Ok(());
                    };
                    self.append(&incoming[..count])?;
                    self.end_reached = true;
                    Ok(())
                } else {
                    self.append(incoming)
                }
            }
            CaptureEnd::Line => {
                if let Some(end) = find_delimiter_end(&self.bytes, incoming, b"\n") {
                    let Some(count) = end.checked_sub(self.bytes.len()) else {
                        self.end_reached = true;
                        return Ok(());
                    };
                    self.append(&incoming[..count])?;
                    self.end_reached = true;
                    Ok(())
                } else {
                    self.append(incoming)
                }
            }
        }
    }

    fn append(&mut self, incoming: &[u8]) -> Result<(), ProcessError> {
        let Some(remaining) = self.options.limit().checked_sub(self.bytes.len()) else {
            return Err(ProcessError::output_limit_exceeded(
                self.stream,
                self.options.limit(),
            ));
        };
        let overflowed = incoming.len() > remaining;
        if overflowed && self.options.overflow() == CaptureOverflowPolicy::Stop {
            return Err(ProcessError::output_limit_exceeded(
                self.stream,
                self.options.limit(),
            ));
        }

        let count = remaining.min(incoming.len());
        if overflowed {
            self.end_reached = true;
        }

        let Some(needed) = self.bytes.len().checked_add(count) else {
            return Err(ProcessError::output_allocation_failed(
                self.stream,
                self.options.limit(),
            ));
        };
        self.reserve(count, overflowed, needed)?;
        self.bytes.extend_from_slice(&incoming[..count]);
        Ok(())
    }

    fn reserve(
        &mut self,
        additional: usize,
        exact: bool,
        needed: usize,
    ) -> Result<(), ProcessError> {
        #[cfg(test)]
        if self.fail_reserves {
            self.fail_reserves = false;
            return Err(ProcessError::output_allocation_failed(self.stream, needed));
        }
        let result = if exact {
            self.bytes.try_reserve_exact(additional)
        } else {
            self.bytes.try_reserve(additional)
        };
        result.map_err(|_| ProcessError::output_allocation_failed(self.stream, needed))
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) fn find_delimiter_end(
    existing: &[u8],
    incoming: &[u8],
    delimiter: &[u8],
) -> Option<usize> {
    if delimiter.is_empty() {
        return None;
    }
    let total = existing.len().checked_add(incoming.len())?;
    if delimiter.len() > total {
        return None;
    }
    for start in 0..=total - delimiter.len() {
        if delimiter.iter().enumerate().all(|(offset, expected)| {
            let index = start + offset;
            let actual = if index < existing.len() {
                existing[index]
            } else {
                incoming[index - existing.len()]
            };
            actual == *expected
        }) {
            return Some(start + delimiter.len());
        }
    }
    None
}

#[cfg(test)]
mod capture_tests {
    use super::*;

    fn capture(options: CaptureOptions, pieces: &[&[u8]]) -> Result<Vec<u8>, ProcessError> {
        let mut accumulator = CaptureAccumulator::new(options, OutputStream::Stdout);
        for piece in pieces {
            accumulator.push(piece)?;
        }
        Ok(accumulator.finish())
    }

    #[test]
    fn capture_end_policies_handle_boundaries_across_reads() {
        assert_eq!(
            capture(
                CaptureOptions::new().until(CaptureEnd::Bytes(3)),
                &[b"ab", b"cdef", b"g"]
            ),
            Ok(b"abc".to_vec())
        );
        assert_eq!(
            capture(
                CaptureOptions::new()
                    .until(CaptureEnd::Delimiter(bytes::Bytes::from_static(b"--"))),
                &[b"ab-", b"-cd--ef"]
            ),
            Ok(b"ab--".to_vec())
        );
        assert_eq!(
            capture(
                CaptureOptions::new().until(CaptureEnd::Line),
                &[b"a\nb", b"\nc"]
            ),
            Ok(b"a\n".to_vec())
        );
        assert_eq!(
            capture(CaptureOptions::new(), &[b"ab", b"cd"]),
            Ok(b"abcd".to_vec())
        );
    }

    #[test]
    fn capture_limit_allows_exact_size_and_rejects_one_byte_overflow() {
        assert_eq!(
            capture(CaptureOptions::new().with_limit(3), &[b"abc"]),
            Ok(b"abc".to_vec())
        );
        assert!(matches!(
            capture(CaptureOptions::new().with_limit(3), &[b"abcd"]),
            Err(ProcessError::OutputLimitExceeded {
                stream: OutputStream::Stdout,
                limit: 3,
                cleanup_error: None,
            })
        ));
    }

    #[test]
    fn truncate_policy_never_retains_more_than_the_limit() {
        let captured = capture(
            CaptureOptions::new()
                .with_limit(3)
                .with_overflow(CaptureOverflowPolicy::Truncate),
            &[b"0123456789"],
        )
        .unwrap();
        assert_eq!(captured, b"0123"[..3]);
        assert!(captured.len() <= 3);
    }

    #[test]
    fn exact_limit_across_reads_and_one_byte_over() {
        assert_eq!(
            capture(CaptureOptions::new().with_limit(4), &[b"ab", b"cd"]),
            Ok(b"abcd".to_vec())
        );
        assert!(matches!(
            capture(CaptureOptions::new().with_limit(4), &[b"ab", b"cde"]),
            Err(ProcessError::OutputLimitExceeded {
                stream: OutputStream::Stdout,
                limit: 4,
                cleanup_error: None,
            })
        ));
    }

    #[test]
    fn byte_limit_binds_before_a_later_read_finds_the_delimiter() {
        let error = capture(
            CaptureOptions::new()
                .with_limit(5)
                .until(CaptureEnd::Delimiter(bytes::Bytes::from_static(b"END"))),
            &[b"01234", b"END"],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ProcessError::OutputLimitExceeded {
                stream: OutputStream::Stdout,
                limit: 5,
                cleanup_error: None,
            }
        ));
    }

    #[test]
    fn truncate_policy_keeps_the_prefix_when_the_delimiter_is_late() {
        let captured = capture(
            CaptureOptions::new()
                .with_limit(5)
                .with_overflow(CaptureOverflowPolicy::Truncate)
                .until(CaptureEnd::Delimiter(bytes::Bytes::from_static(b"END"))),
            &[b"01234", b"END"],
        )
        .unwrap();
        assert_eq!(captured, b"01234");
    }

    #[test]
    fn byte_end_within_the_limit_is_kept_and_over_the_limit_is_bounded() {
        assert_eq!(
            capture(
                CaptureOptions::new()
                    .with_limit(16)
                    .until(CaptureEnd::Bytes(5)),
                &[b"0123456789"]
            ),
            Ok(b"01234".to_vec())
        );
        let captured = capture(
            CaptureOptions::new()
                .with_limit(5)
                .with_overflow(CaptureOverflowPolicy::Truncate)
                .until(CaptureEnd::Bytes(10)),
            &[b"0123456789"],
        )
        .unwrap();
        assert_eq!(captured, b"01234");
    }

    #[test]
    fn capture_starts_unallocated_and_grows_progressively() {
        let options = CaptureOptions::new().with_limit(8 * 1024 * 1024);
        let mut accumulator = CaptureAccumulator::new(options, OutputStream::Stdout);
        assert_eq!(accumulator.bytes.capacity(), 0);
        accumulator.push(&vec![0; 4096]).unwrap();
        let capacity = accumulator.bytes.capacity();
        assert!(
            (4096..=8192).contains(&capacity),
            "progressive growth should track received bytes, not the configured limit"
        );
        assert_eq!(accumulator.finish().len(), 4096);
    }

    #[test]
    fn truncate_stops_growing_retained_memory_at_the_limit() {
        let options = CaptureOptions::new()
            .with_limit(4096)
            .with_overflow(CaptureOverflowPolicy::Truncate);
        let mut accumulator = CaptureAccumulator::new(options, OutputStream::Stdout);
        let piece = vec![0; 8192];
        accumulator.push(&piece).unwrap();
        assert_eq!(accumulator.bytes.len(), 4096);
        assert!(
            accumulator.bytes.capacity() <= 4096 + 64,
            "truncation must not grow retained capacity past the received data"
        );
        accumulator.push(&piece).unwrap();
        assert_eq!(accumulator.bytes.len(), 4096);
        assert_eq!(accumulator.finish(), piece[..4096]);
    }

    #[test]
    fn allocation_failure_maps_to_a_typed_output_error() {
        let options = CaptureOptions::new().with_limit(1024);
        let mut accumulator =
            CaptureAccumulator::new_failing_reserves(options, OutputStream::Stderr);
        let error = accumulator.push(b"payload").unwrap_err();
        assert_eq!(
            error,
            ProcessError::OutputAllocationFailed {
                stream: OutputStream::Stderr,
                requested: 7,
                cleanup_error: None,
            }
        );
        assert_eq!(accumulator.bytes.len(), 0);
    }

    #[test]
    fn allocation_failure_precedes_truncation_and_leaves_the_buffer_unchanged() {
        let options = CaptureOptions::new()
            .with_limit(4)
            .with_overflow(CaptureOverflowPolicy::Truncate);
        let mut accumulator =
            CaptureAccumulator::new_failing_reserves(options, OutputStream::Stdout);
        let error = accumulator.push(b"abcdef").unwrap_err();
        assert!(matches!(
            error,
            ProcessError::OutputAllocationFailed {
                stream: OutputStream::Stdout,
                requested: 4,
                cleanup_error: None,
            }
        ));
        assert_eq!(accumulator.bytes.len(), 0);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn observer_replays_a_successful_terminal_exit() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        let replay = observer.clone();
        let exit = ProcessExit {
            exit_code: Some(0),
            signal: None,
        };

        lifecycle.starting();
        lifecycle.running();
        lifecycle.finished(exit);

        assert_eq!(observer.state(), ProcessState::Finished(exit));
        assert_eq!(observer.finished().await, Ok(exit));
        assert_eq!(replay.finished().await, Ok(exit));
    }

    #[tokio::test]
    async fn observer_retains_captured_stdout_and_stderr() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        lifecycle.capture_stdout(b"out".to_vec());
        lifecycle.capture_stderr(b"err".to_vec());

        assert_eq!(observer.stdout().await, Ok(b"out".to_vec()));
        assert_eq!(observer.stderr().await, Ok(b"err".to_vec()));
    }

    #[tokio::test]
    async fn cancellation_is_retained_as_a_process_error() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        observer.cancel();
        assert!(lifecycle.cancellation_token().is_cancelled());

        let expected = ProcessError::Cancelled {
            cleanup_error: None,
        };
        lifecycle.failed(expected.clone());

        assert_eq!(observer.state(), ProcessState::Failed(expected.clone()));
        assert_eq!(observer.finished().await, Err(expected));
    }
}

#[cfg(test)]
mod process_contract_tests {
    use super::*;
    use crate::client::Client;
    use crate::support::{ScriptedTransport, start_dispatcher};
    use protocol::Command;
    use std::sync::Arc;

    fn process_echo(cmd: &Command) -> Event {
        match cmd {
            Command::ProcessStart { uuid, .. } => Event::ProcessStarted { uuid: *uuid },
            Command::ProcessWait { uuid } | Command::ProcessStop { uuid } => Event::ProcessExited {
                uuid: *uuid,
                exit_code: Some(0),
                signal: None,
            },
            Command::ProcessClose { uuid } => Event::ProcessClosed { uuid: *uuid },
            _ => Event::VMReady,
        }
    }

    fn started(
        transport: ScriptedTransport,
    ) -> (mpsc::Sender<HostRequest>, crate::support::TestDispatcher) {
        let dispatcher = start_dispatcher(Arc::new(transport));
        (dispatcher.tx(), dispatcher)
    }

    fn builder(
        tx: mpsc::Sender<HostRequest>,
        cleanup: Arc<CleanupTasks>,
        streams: Arc<dyn StreamTransport>,
    ) -> PreparedProcessBuilder {
        PreparedProcessBuilder::new("/bin/tool".to_string(), tx, cleanup, streams)
    }

    #[tokio::test]
    async fn spawn_returns_a_running_process_for_a_matching_started_reply() {
        let (tx, dispatcher) = started(ScriptedTransport::process_lifecycle());
        let cleanup = Arc::new(CleanupTasks::new());

        let mut running = builder(
            tx.clone(),
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .arg("first")
        .env("ONE", "1")
        .cwd("/work")
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");

        let exit = running.wait().await.unwrap();
        assert_eq!(
            exit,
            ProcessExit {
                exit_code: Some(0),
                signal: None,
            }
        );
        running.close().await.unwrap();
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_rejects_a_mismatched_started_uuid() {
        let (tx, dispatcher) = started(ScriptedTransport::new(vec![Event::ProcessStarted {
            uuid: uuid::Uuid::nil(),
        }]));
        let cleanup = Arc::new(CleanupTasks::new());

        let error = builder(
            tx,
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect_err("mismatched ProcessStarted uuid must fail");
        assert_eq!(error, GuestClientError::UnexpectedReply);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_maps_guest_error_replies() {
        let (tx, dispatcher) = started(ScriptedTransport::new(vec![Event::Error {
            code: 1,
            msg: "start denied".to_string(),
        }]));
        let cleanup = Arc::new(CleanupTasks::new());

        let error = builder(
            tx,
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect_err("guest error must fail spawn");
        assert_eq!(
            error,
            GuestClientError::Guest {
                code: protocol::GuestErrorCode::ProcessStart,
                message: "start denied".to_string(),
            }
        );
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn wait_rejects_a_mismatched_exited_uuid() {
        let (tx, dispatcher) = started(ScriptedTransport::scripted(vec![
            Box::new(process_echo),
            Box::new(|_| Event::ProcessExited {
                uuid: uuid::Uuid::nil(),
                exit_code: Some(0),
                signal: None,
            }),
        ]));
        let cleanup = Arc::new(CleanupTasks::new());

        let mut running = builder(
            tx,
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        let error = running
            .wait()
            .await
            .expect_err("mismatched ProcessExited uuid must fail");
        assert_eq!(error, GuestClientError::UnexpectedReply);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn wait_maps_guest_error_replies() {
        let (tx, dispatcher) = started(ScriptedTransport::scripted(vec![
            Box::new(process_echo),
            Box::new(|_| Event::Error {
                code: 9,
                msg: "wait denied".to_string(),
            }),
        ]));
        let cleanup = Arc::new(CleanupTasks::new());

        let mut running = builder(
            tx,
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        let error = running
            .wait()
            .await
            .expect_err("guest error must fail wait");
        assert_eq!(
            error,
            GuestClientError::Guest {
                code: protocol::GuestErrorCode::ProcessWait,
                message: "wait denied".to_string(),
            }
        );
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn wait_on_a_closed_handle_is_an_invalid_state() {
        let (tx, dispatcher) = started(ScriptedTransport::process_lifecycle());
        let cleanup = Arc::new(CleanupTasks::new());

        let mut running = builder(
            tx,
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        running.close().await.unwrap();

        let error = running
            .wait()
            .await
            .expect_err("waiting after close must fail");
        assert_eq!(error, GuestClientError::InvalidState);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn close_is_idempotent_and_rejects_unexpected_replies() {
        let (tx, dispatcher) = started(ScriptedTransport::process_lifecycle());
        let cleanup = Arc::new(CleanupTasks::new());

        let mut running = builder(
            tx.clone(),
            cleanup.clone(),
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        running.close().await.expect("close must succeed");
        running.close().await.expect("second close must be a no-op");
        dispatcher.shutdown().await;

        let echo = |cmd: &Command| -> Event { process_echo(cmd) };
        let (tx, dispatcher) = started(ScriptedTransport::scripted(vec![
            Box::new(echo),
            Box::new(|_| Event::VMReady),
        ]));
        let mut running = builder(
            tx,
            cleanup,
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        let error = running
            .close()
            .await
            .expect_err("unexpected ProcessStop reply must fail");
        assert_eq!(error, GuestClientError::UnexpectedReply);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn close_accepts_shutdowned_and_maps_stop_failures_to_process_close() {
        let (tx, dispatcher) = started(ScriptedTransport::scripted(vec![
            Box::new(process_echo),
            Box::new(|_| Event::Shutdowned),
            Box::new(process_echo),
        ]));
        let cleanup = Arc::new(CleanupTasks::new());
        let mut running = builder(
            tx,
            cleanup,
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        running.close().await.unwrap();
        dispatcher.shutdown().await;

        let (tx, dispatcher) = started(ScriptedTransport::scripted(vec![
            Box::new(process_echo),
            Box::new(|_| Event::Error {
                code: 2,
                msg: "stop denied".to_string(),
            }),
        ]));
        let cleanup = Arc::new(CleanupTasks::new());
        let mut running = builder(
            tx,
            cleanup,
            Arc::new(crate::support::FakeStreams::new(Vec::new())),
        )
        .spawn()
        .await
        .expect("matching ProcessStarted must spawn");
        let error = running
            .close()
            .await
            .expect_err("guest stop failure must map to ProcessClose");
        assert_eq!(error, GuestClientError::ProcessClose);
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn request_timeout_is_reported_through_the_client() {
        let (tx, dispatcher) = started(ScriptedTransport::process_lifecycle());
        let client = Client::new(tx);
        let error = Client::request_with_deadline(
            client.sender().clone(),
            Command::Ping,
            Some(Instant::now()),
        )
        .await
        .expect_err("past deadline must time out");
        assert_eq!(error, GuestClientError::RequestTimedOut);
        dispatcher.shutdown().await;
    }

    #[test]
    fn drop_enqueues_a_process_close_request() {
        let cleanup = Arc::new(CleanupTasks::new());
        let (tx, mut rx) = mpsc::channel::<HostRequest>(1);
        let uuid = uuid::Uuid::now_v7();

        drop(RunningProcess {
            uuid,
            cmd_tx: tx,
            cleanup,
            streams: Arc::new(crate::support::FakeStreams::new(Vec::new())),
            closed: false,
        });

        let request = rx.try_recv().expect("drop must enqueue cleanup");
        assert!(matches!(
            request.cmd,
            Command::ProcessClose { uuid: request_uuid } if request_uuid == uuid
        ));
    }

    #[test]
    fn closed_handle_drop_enqueues_nothing() {
        let cleanup = Arc::new(CleanupTasks::new());
        let (tx, mut rx) = mpsc::channel::<HostRequest>(1);

        drop(RunningProcess {
            uuid: uuid::Uuid::now_v7(),
            cmd_tx: tx,
            cleanup,
            streams: Arc::new(crate::support::FakeStreams::new(Vec::new())),
            closed: true,
        });

        assert!(rx.try_recv().is_err(), "closed handle must not enqueue");
    }
}
