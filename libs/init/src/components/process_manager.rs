use async_io::Async;
use error_stack::Report;
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::process::{ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
#[cfg(feature = "tracing")]
use tracing::instrument;
use uuid::Uuid;

use crate::errors::{InitError, InitResult};
use protocol::auth::MAX_COMMAND_FRAME;
use protocol::{ProcessOutputStream, ProcessStdio};
#[derive(Clone)]
pub(crate) struct ProcessManager {
    inner: Arc<Mutex<HashMap<Uuid, Process>>>,
    cancel: CancellationToken,
}

/// The terminal state of a guest process.  This is deliberately kept after
/// reaping so multiple `ProcessWait` requests can replay the same result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessExit {
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
}

#[derive(Default)]
pub(crate) struct Completion {
    result: Mutex<Option<Result<ProcessExit, String>>>,
    ready: Notify,
}

impl Completion {
    fn record(&self, result: Result<ProcessExit, String>) {
        let mut stored = self.result.lock().unwrap_or_else(|e| e.into_inner());
        if stored.is_none() {
            *stored = Some(result);
            self.ready.notify_waiters();
        }
    }

    async fn wait(&self) -> InitResult<ProcessExit> {
        loop {
            // Register first so a completion between `notified` and the lock
            // cannot be missed; `Notify` retains that permit.
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(result) = self
                .result
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                return result.map_err(|message| Report::new(InitError::Io).attach(message));
            }
            notified.await;
        }
    }

    fn is_complete(&self) -> bool {
        self.result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

fn process_stdio(mode: ProcessStdio) -> std::io::Result<Stdio> {
    match mode {
        ProcessStdio::Pipe => Ok(Stdio::piped()),
        ProcessStdio::Null => Ok(Stdio::null()),
        ProcessStdio::File(path) => OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map(Stdio::from),
    }
}

/// Relays one child output pipe into the outbound chunk channel. A full
/// bounded channel stalls the reader (backpressure) instead of buffering
/// without bound; the loop exits on EOF, read error, or a closed channel
/// (the writer task went away).
async fn relay_output<R>(mut output: R, tx: smol::channel::Sender<Vec<u8>>)
where
    R: smol::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        match output.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        }
    }
}

impl ProcessManager {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            cancel,
        }
    }
    #[cfg_attr(feature = "tracing", instrument(skip(self), fields(uuid = ?uuid), level = "debug"))]
    pub async fn spawn(
        &self,
        uuid: Uuid,
        path: String,
        args: Vec<String>,
        envs: Vec<(String, String)>,
        cwd: Option<String>,
        stdout: ProcessStdio,
        stderr: ProcessStdio,
    ) -> InitResult<()> {
        let mut cmd = Command::new(&path);
        cmd.args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        // Take `cwd` by reference rather than by value: the diagnostic
        // path below needs to stat the resolved working directory to
        // distinguish "binary missing" from "cwd missing" on ENOENT,
        // and re-borrowing after a move would fight the borrow checker.
        if let Some(ref cwd) = cwd {
            cmd.current_dir(cwd.clone());
        }

        cmd.stdin(Stdio::piped());
        let stdout_is_piped = matches!(stdout, ProcessStdio::Pipe);
        let stderr_is_piped = matches!(stderr, ProcessStdio::Pipe);
        cmd.stdout(process_stdio(stdout).map_err(|error| {
            Report::new(InitError::Io).attach(format!("configuring process stdout: {error}"))
        })?);
        cmd.stderr(process_stdio(stderr).map_err(|error| {
            Report::new(InitError::Io).attach(format!("configuring process stderr: {error}"))
        })?);

        let cancel = self.cancel.child_token();

        let (process, mut child) = match cmd.spawn() {
            Ok(mut child) => (
                Process {
                    uuid,
                    stdin: Some(child.stdin.take().ok_or_else(|| {
                        Report::new(InitError::ResourceNotFound)
                            .attach("Stdin not found".to_string())
                    })?),
                    stdout: if stdout_is_piped {
                        Some(child.stdout.take().ok_or_else(|| {
                            Report::new(InitError::ResourceNotFound)
                                .attach("Stdout not found".to_string())
                        })?)
                    } else {
                        None
                    },
                    stderr: if stderr_is_piped {
                        Some(child.stderr.take().ok_or_else(|| {
                            Report::new(InitError::ResourceNotFound)
                                .attach("Stderr not found".to_string())
                        })?)
                    } else {
                        None
                    },
                    completion: Arc::new(Completion::default()),
                    stop: cancel.clone(),
                },
                child,
            ),
            Err(e) => {
                #[cfg(feature = "tracing")]
                tracing::info!("[Bus][Process] Failed to spawn {}: {}", path, e);

                // On ENOENT, distinguish "binary path missing" from "cwd
                // missing". Rust's `Command::spawn` chains `posix_spawn`
                // (or fork+chdir+exec) and surfaces the resulting errno
                // without indicating whether the lookup that failed was
                // the executable or the working directory — both end up
                // as `ENOENT`. Probing each one separately lets the
                // host-side error chain carry an actionable hint instead
                // of the ambiguously-worded raw spawn error.
                let mut diag = format!("failed to spawn {path} ({e})");
                if e.kind() == std::io::ErrorKind::NotFound {
                    if let Some(cwd) = &cwd {
                        match std::fs::symlink_metadata(cwd) {
                            Ok(m) => diag.push_str(&format!(
                                "; cwd {} exists ({:?})",
                                cwd,
                                m.file_type(),
                            )),
                            Err(cwd_err) => diag
                                .push_str(&format!("; cwd {} does not exist: {}", cwd, cwd_err,)),
                        }
                    }
                    match std::fs::symlink_metadata(&path) {
                        Ok(m) => diag.push_str(&format!(
                            "; binary {} exists ({:?})",
                            path,
                            m.file_type(),
                        )),
                        Err(path_err) => diag
                            .push_str(&format!("; binary {} does not exist: {}", path, path_err,)),
                    }
                    // Also surface whether the binary's parent dir is
                    // there — a common cause of "binary missing" is a
                    // typo in the path (so /bin exists but /usr/local/bin
                    // doesn't, etc).
                    if let Some(parent) = std::path::Path::new(&path).parent() {
                        if !parent.as_os_str().is_empty() {
                            match std::fs::symlink_metadata(parent) {
                                Ok(_) => {}
                                Err(parent_err) => diag.push_str(&format!(
                                    "; parent dir {} does not exist: {}",
                                    parent.display(),
                                    parent_err,
                                )),
                            }
                        }
                    }
                }

                return Err(Report::new(e)
                    .change_context(InitError::ProcessSpawn)
                    .attach(diag));
            }
        };
        {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!("[Bus][Process] Poisoned lock for process {}: {}", uuid, e);
                    e.into_inner()
                }
            };
            inner.insert(uuid, process);
        }
        let completion = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner
                .get(&uuid)
                .expect("process was just inserted")
                .completion
                .clone()
        };
        // This task exclusively owns `Child`.  Stop and shutdown are tokens,
        // not raw PID signals, so a child that exits while a stop is requested
        // can never turn into a signal sent to a recycled PID.
        let stop = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner
                .get(&uuid)
                .expect("process was just inserted")
                .stop
                .clone()
        };
        let shutdown = cancel;
        smol::spawn(async move {
            let status = tokio::select! {
                status = child.status() => status,
                _ = stop.cancelled() => {
                    match child.try_status() {
                        Ok(Some(status)) => Ok(status),
                        Ok(None) => match child.kill() {
                            Ok(()) => child.status().await,
                            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => child.status().await,
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(e),
                    }
                }
                _ = shutdown.cancelled() => {
                    match child.try_status() {
                        Ok(Some(status)) => Ok(status),
                        Ok(None) => match child.kill() {
                            Ok(()) => child.status().await,
                            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => child.status().await,
                            Err(e) => Err(e),
                        },
                        Err(e) => Err(e),
                    }
                }
            };
            match status {
                Ok(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    completion.record(Ok(ProcessExit {
                        exit_code: status.code(),
                        signal: status.signal(),
                    }));
                }
                Err(e) => {
                    let message = format!("failed to wait for process {uuid}: {e}");
                    #[cfg(feature = "tracing")]
                    tracing::info!("[Bus][Process] {message}");
                    completion.record(Err(message));
                }
            }
            // The Process entry deliberately remains in the manager:
            // waiters arriving after natural completion replay this status.
        })
        .detach();
        Ok(())
    }
    pub async fn kill(&self, uuid: Uuid) -> InitResult<ProcessExit> {
        let (stop, completion) = {
            let inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!("[Bus][Process] Poisoned lock for process {}: {}", uuid, e);
                    e.into_inner()
                }
            };
            inner
                .get(&uuid)
                .ok_or_else(|| {
                    Report::new(InitError::ResourceNotFound).attach("Process not found".to_string())
                })?
                .stop_and_completion()
        };
        stop.cancel();
        let result = completion.wait().await;
        result
    }

    pub async fn wait(&self, uuid: Uuid) -> InitResult<ProcessExit> {
        let completion = self.with_process(uuid, |process| process.completion.clone())?;
        completion.wait().await
    }

    pub fn close(&self, uuid: Uuid) -> InitResult<()> {
        let process = self.remove(uuid)?;
        process.stop.cancel();
        Ok(())
    }

    fn with_process<T>(&self, uuid: Uuid, f: impl FnOnce(&Process) -> T) -> InitResult<T> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.get(&uuid).map(f).ok_or_else(|| {
            Report::new(InitError::ResourceNotFound).attach("Process not found".to_string())
        })
    }

    fn remove(&self, uuid: Uuid) -> InitResult<Process> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.remove(&uuid).ok_or_else(|| {
            Report::new(InitError::ResourceNotFound).attach("Process not found".to_string())
        })
    }

    /// Attaches `stream` as the live stdio pipe of the process identified by
    /// `uuid`. After the success ack on the control connection, the stream is
    /// no longer carrying framed commands: it becomes a raw bidirectional
    /// byte pipe owned by the child for the remainder of its lifetime (or
    /// until the host closes the connection).
    ///
    /// Layout of the relay:
    ///   - host -> child.stdin   (raw `read` on the TCP stream, `write_all` on stdin)
    ///   - child.stdout + child.stderr -> host
    ///       (two reader tasks, one serialized writer task fed by an smol
    ///        channel so writes over the TCP stream can never interleave)
    ///
    /// A dedicated reaper started by [`spawn`](Self::spawn) waits for the
    /// child independently of this relay and records its terminal status.
    ///
    /// When the host closes the TCP stream (EOF on read), `bind` ends the
    /// host->stdin relay; the child's stdin write pipe gets dropped, which
    /// is the conventional "stdin closed" signal. The two outbound reader
    /// tasks will themselves EOF their reads when the child exits in turn
    /// (or immediately if already exited).
    #[cfg_attr(feature = "tracing", instrument(skip(self, stream), fields(uuid = ?uuid, stay_framed), level = "debug"))]
    pub async fn bind(
        &self,
        uuid: Uuid,
        stream: Async<TcpStream>,
        stay_framed: bool,
    ) -> InitResult<()> {
        // Take the child's std pipes out of the stored Process entry. They
        // move into the relay tasks; the Process entry retains completion and
        // the actor's stop token so `kill` and `wait` still work against this
        // uuid while bind is live.
        // so `kill` and `wait` still work against this uuid while bind is live.
        let (stdin, stdout, stderr) = {
            let mut inner = match self.inner.lock() {
                Ok(inner) => inner,
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!("[Bus][Process] Poisoned lock for process {}: {}", uuid, e);
                    e.into_inner()
                }
            };
            let Some(process) = inner.get_mut(&uuid) else {
                #[cfg(feature = "tracing")]
                tracing::info!("[Bus][Process] bind: process {} not found", uuid);
                return Err(Report::new(InitError::ResourceNotFound)
                    .attach("Process not found".to_string()));
            };
            let stdin = process.stdin.take().ok_or_else(|| {
                Report::new(InitError::ResourceNotFound).attach("Process already bound".to_string())
            })?;
            // stdout/stderr are only allocated when the host requested
            // `ProcessStdio::Pipe`; `Null`/`File` stdio leaves them absent.
            // A missing pipe is fine — the corresponding reader task simply
            // drops its channel sender (an immediately-closed pipe) instead
            // of panicking inside a detached task and killing guest PID 1.
            let stdout = process.stdout.take();
            let stderr = process.stderr.take();
            (stdin, stdout, stderr)
        };

        // Outbound: serialize writes from stdout+stderr readers through an
        // smol channel into a single writer task. Each reader sends Vec<u8>
        // chunks; the writer drains the channel and `write_all`s onto the
        // stream. When both readers drop, the channel closes itself and the
        // writer task exits, dropping its handle on the stream's write half.
        //
        // The channel is bounded so a child producing output faster than the
        // host reads cannot grow guest memory without bound: a full channel
        // stalls the reader (backpressure) instead of buffering forever.
        const CHUNKS_CAPACITY: usize = 64;
        let (chunks_tx, chunks_rx) = smol::channel::bounded::<Vec<u8>>(CHUNKS_CAPACITY);

        // Reader: child.stdout -> channel. `None` (host chose `Null`/`File`
        // stdio) means the pipe was never allocated: drop the sender so the
        // channel closes as soon as the other reader is also done.
        let chunks_tx_out = chunks_tx.clone();
        smol::spawn(async move {
            if let Some(stdout) = stdout {
                relay_output(stdout, chunks_tx_out.clone()).await;
            }
            drop(chunks_tx_out);
        })
        .detach();

        // Reader: child.stderr -> channel
        smol::spawn(async move {
            if let Some(stderr) = stderr {
                relay_output(stderr, chunks_tx.clone()).await;
            }
            drop(chunks_tx);
        })
        .detach();

        // Writer: channel -> TCP stream. Serializes all outbound writes.
        // In framed mode each chunk is prefixed with a 4-byte little-endian
        // length so the host's frame decoder can split interleaved
        // stdout/stderr output; in raw mode the bytes are written verbatim.
        let stream = Arc::new(stream);
        let writer_stream = stream.clone();
        smol::spawn(async move {
            let rx = chunks_rx;
            while let Ok(chunk) = rx.recv().await {
                let mut s = &*writer_stream;
                if stay_framed {
                    let len = (chunk.len() as u32).to_le_bytes();
                    if s.write_all(&len).await.is_err() {
                        break;
                    }
                }
                if s.write_all(&chunk).await.is_err() {
                    break;
                }
                let _ = s.flush().await;
            }
            // Channel closed -> both child stdout and stderr EOF'd. Drop the
            // write half: the stream will still be held by the inbound relay
            // until the host EOFs; the smol Async's Drop will eventually
            // call Shutdown::Both when no references remain.
        })
        .detach();

        // Inbound: TCP stream -> child.stdin. Holds the *read* capability of the
        // stream. Runs inline in this `bind` future so the dispatcher task
        // naturally awaits its completion before returning. In framed mode the
        // host sends length-prefixed frames; in raw mode it sends a raw byte
        // stream.
        let mut stdin = stdin;
        loop {
            let chunk = {
                let mut s = &*stream;
                if stay_framed {
                    let mut len_buf = [0u8; 4];
                    match s.read_exact(&mut len_buf).await {
                        Ok(()) => {}
                        Err(_) => break,
                    }
                    let len = u32::from_le_bytes(len_buf) as usize;
                    if len > MAX_COMMAND_FRAME {
                        return Err(Report::new(InitError::FrameTooLarge).attach(format!(
                            "declared bind frame length {len} exceeds maximum {MAX_COMMAND_FRAME}"
                        )));
                    }
                    let mut payload = vec![0u8; len];
                    if s.read_exact(&mut payload).await.is_err() {
                        break;
                    }
                    payload
                } else {
                    let mut buf = [0u8; 4096];
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf[..n].to_vec(),
                    }
                }
            };
            if stdin.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = stdin.flush().await;
        }
        // Host closed the read direction (or errored). Dropping `stdin`
        // signals EOF to the child's stdin fd. The outbound relay will EOF
        // on its own when the child's stdout/stderr readers return 0 (which
        // they will, since the child has lost its input) — at which point
        // the dedicated reaper records their terminal status.
        #[cfg(feature = "tracing")]
        tracing::info!("[Bus][Process] bind: stream closed for process {}", uuid);
        Ok(())
    }

    /// Relays one child output pipe to a dedicated host connection. Unlike
    /// `bind`, this preserves stdout/stderr identity and does not attach stdin.
    pub async fn bind_output(
        &self,
        uuid: Uuid,
        output: ProcessOutputStream,
        stream: Async<TcpStream>,
    ) -> InitResult<()> {
        enum BoundOutput {
            Stdout(ChildStdout),
            Stderr(ChildStderr),
        }

        let output = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let process = inner.get_mut(&uuid).ok_or_else(|| {
                Report::new(InitError::ResourceNotFound).attach("Process not found".to_string())
            })?;
            match output {
                ProcessOutputStream::Stdout => process
                    .stdout
                    .take()
                    .map(BoundOutput::Stdout)
                    .ok_or_else(|| {
                        Report::new(InitError::ResourceNotFound)
                            .attach("Process stdout is not available".to_string())
                    })?,
                ProcessOutputStream::Stderr => process
                    .stderr
                    .take()
                    .map(BoundOutput::Stderr)
                    .ok_or_else(|| {
                        Report::new(InitError::ResourceNotFound)
                            .attach("Process stderr is not available".to_string())
                    })?,
            }
        };

        async fn relay<R>(mut output: R, stream: Async<TcpStream>) -> InitResult<()>
        where
            R: smol::io::AsyncRead + Unpin,
        {
            let mut stream = &stream;
            let mut buffer = [0u8; 4096];
            loop {
                match output.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => stream
                        .write_all(&buffer[..read])
                        .await
                        .map_err(|error| Report::new(error).change_context(InitError::Io))?,
                    Err(error) => {
                        return Err(Report::new(error).change_context(InitError::Io));
                    }
                }
            }
            stream
                .flush()
                .await
                .map_err(|error| Report::new(error).change_context(InitError::Io))
        }

        match output {
            BoundOutput::Stdout(stdout) => relay(stdout, stream).await,
            BoundOutput::Stderr(stderr) => relay(stderr, stream).await,
        }
    }
}

pub(crate) struct Process {
    pub(crate) uuid: Uuid,
    pub(crate) stdin: Option<ChildStdin>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
    pub(crate) completion: Arc<Completion>,
    pub(crate) stop: CancellationToken,
}

impl Process {
    fn stop_and_completion(&self) -> (CancellationToken, Arc<Completion>) {
        (self.stop.clone(), self.completion.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{Completion, ProcessExit, ProcessManager};
    use crate::errors::InitError;
    use async_io::Async;
    use protocol::ProcessStdio;
    use protocol::auth::MAX_COMMAND_FRAME;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    /// A connected loopback TCP pair standing in for the host command
    /// connection in relay tests.
    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn spawn_exiting_shell(pm: &ProcessManager, uuid: Uuid) {
        smol::block_on(async {
            pm.spawn(
                uuid,
                "/bin/sh".to_string(),
                vec!["-c".to_string(), "exit 0".to_string()],
                Vec::new(),
                None,
                ProcessStdio::Null,
                ProcessStdio::Null,
            )
            .await
            .unwrap();
        });
    }

    #[test]
    fn completion_replays_a_recorded_natural_exit() {
        let completion = Completion::default();
        let expected = ProcessExit {
            exit_code: Some(23),
            signal: None,
        };
        completion.record(Ok(expected));

        assert_eq!(smol::block_on(completion.wait()).unwrap(), expected);
        assert_eq!(smol::block_on(completion.wait()).unwrap(), expected);
    }

    #[test]
    fn completion_replays_a_reaper_failure() {
        let completion = Completion::default();
        completion.record(Err("reaper lost child".to_string()));

        for _ in 0..2 {
            let error = smol::block_on(completion.wait()).unwrap_err();
            assert_eq!(error.current_context(), &InitError::Io);
            assert!(error.to_string().contains("reaper lost child"));
        }
    }

    #[test]
    fn bind_tolerates_null_stdio_process() {
        // A process spawned with `ProcessStdio::Null` has no stdout/stderr
        // pipes. `bind` must treat the missing pipes as immediately-closed
        // instead of panicking inside the detached relay tasks.
        let pm = ProcessManager::new(CancellationToken::new());
        let uuid = Uuid::from_bytes([0x11; 16]);
        spawn_exiting_shell(&pm, uuid);

        smol::block_on(async {
            let (client, server) = tcp_pair();
            let stream = Async::new(server).unwrap();
            let bind = smol::spawn(async move { pm.bind(uuid, stream, false).await });
            drop(client);
            bind.await.unwrap();
        });
    }

    #[test]
    fn bind_rejects_oversized_framed_length() {
        let pm = ProcessManager::new(CancellationToken::new());
        let uuid = Uuid::from_bytes([0x11; 16]);
        spawn_exiting_shell(&pm, uuid);

        smol::block_on(async {
            let (mut client, server) = tcp_pair();
            let stream = Async::new(server).unwrap();
            let bind = smol::spawn(async move { pm.bind(uuid, stream, true).await });
            let oversized = (MAX_COMMAND_FRAME as u32 + 1).to_le_bytes();
            client.write_all(&oversized).unwrap();
            let error = bind.await.unwrap_err();
            assert_eq!(error.current_context(), &InitError::FrameTooLarge);
            assert!(error.to_string().contains("exceeds maximum"));
        });
    }
}
