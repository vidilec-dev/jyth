use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use protocol::{ProcessOutputStream, ProcessStdio};
use tokio::sync::mpsc;

use crate::cleanup::CleanupTasks;
use crate::error::GuestClientError;
use crate::process::{
    CaptureAccumulator, Output, OutputStream, PreparedProcess, PreparedProcessBuilder,
    ProcessError, ProcessExit, ProcessLifecycle, RunningProcess,
};
use crate::transport::{HostRequest, ProcessStream, StreamTransport};

/// Execute a prepared guest process to completion on this client.
///
/// The process must already carry a prepared guest program path or shell
/// command; host-side Rust/byte executable sources must be materialized into
/// guest paths before construction. Publishes the full lifecycle to the
/// process observer: starting, running, terminal exit, or failure.
pub async fn run_direct_process(
    cmd_tx: mpsc::Sender<HostRequest>,
    streams: Arc<dyn StreamTransport>,
    cleanup_tasks: Arc<CleanupTasks>,
    process: PreparedProcess,
) -> Result<ProcessExit, ProcessError> {
    let PreparedProcess {
        path,
        args,
        envs,
        cwd,
        timeout,
        stdout,
        stderr,
        lifecycle,
    } = process;

    if let Some(lifecycle) = &lifecycle {
        lifecycle.starting();
    }
    let stdout = direct_process_stdio(stdout);
    let stderr = direct_process_stdio(stderr);

    let cancellation = lifecycle
        .as_ref()
        .map(|lifecycle| lifecycle.cancellation_token())
        .unwrap_or_default();
    if cancellation.is_cancelled() {
        return fail_direct_process(
            lifecycle,
            ProcessError::Cancelled {
                cleanup_error: None,
            },
        );
    }

    let builder = args.iter().fold(
        PreparedProcessBuilder::new(path, cmd_tx, cleanup_tasks, streams),
        |builder, arg| builder.arg(arg),
    );
    let builder = envs
        .iter()
        .fold(builder, |builder, (key, value)| builder.env(key, value));
    let builder = if let Some(cwd) = cwd {
        builder.cwd(cwd)
    } else {
        builder
    }
    .stdout_mode(stdout.stdio.clone())
    .stderr_mode(stderr.stdio.clone());

    let mut running = match builder.spawn().await {
        Ok(running) => running,
        Err(error) => {
            return fail_direct_process(
                lifecycle,
                ProcessError::Spawn(Arc::from(error.to_string())),
            );
        }
    };
    if let Some(lifecycle) = &lifecycle {
        lifecycle.running();
    }
    let mut output_drains =
        match start_output_drains(&running, stdout.host_route, stderr.host_route).await {
            Ok(drains) => drains,
            Err(error) => {
                let cleanup = running.close().await.err().map(|error| error.to_string());
                return fail_direct_process(lifecycle, error.with_cleanup(cleanup.map(Arc::from)));
            }
        };
    enum Outcome {
        Wait(Result<ProcessExit, GuestClientError>),
        TimedOut(Duration),
        Cancelled,
        Output(ProcessError),
    }

    let outcome = {
        let wait = running.wait();
        tokio::pin!(wait);
        if let Some(after) = timeout {
            let timer = tokio::time::sleep(after);
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    result = &mut wait => break Outcome::Wait(result),
                    result = output_drains.next(), if output_drains.has_pending() => {
                        if let Some(Err(error)) = result {
                            break Outcome::Output(error);
                        }
                    }
                    _ = &mut timer => break Outcome::TimedOut(after),
                    _ = cancellation.cancelled() => break Outcome::Cancelled,
                }
            }
        } else {
            loop {
                tokio::select! {
                    result = &mut wait => break Outcome::Wait(result),
                    result = output_drains.next(), if output_drains.has_pending() => {
                        if let Some(Err(error)) = result {
                            break Outcome::Output(error);
                        }
                    }
                    _ = cancellation.cancelled() => break Outcome::Cancelled,
                }
            }
        }
    };
    match outcome {
        Outcome::Wait(Ok(exit)) => {
            let cleanup = running.close().await;
            let output = finish_output_drains(output_drains).await;
            let cleanup_error = cleanup.err().map(|error| error.to_string());
            if let Some(error) = cleanup_error {
                if let Err(output_error) = output {
                    return fail_direct_process(
                        lifecycle,
                        output_error.with_cleanup(Some(Arc::from(error))),
                    );
                }
                return fail_direct_process(lifecycle, ProcessError::Cleanup(Arc::from(error)));
            }
            let completed = match output {
                Ok(completed) => completed,
                Err(error) => return fail_direct_process(lifecycle, error),
            };
            if exit.success() {
                if let Some(lifecycle) = &lifecycle {
                    retain_captured_output(lifecycle, completed);
                    lifecycle.finished(exit);
                }
                Ok(exit)
            } else {
                fail_direct_process(lifecycle, ProcessError::UnsuccessfulExit(exit))
            }
        }
        Outcome::Wait(Err(error)) => {
            let wait_error = Arc::from(error.to_string());
            let cleanup = running.close().await;
            let output = finish_output_drains(output_drains).await;
            if let Err(output_error) = output {
                let cleanup_error = combine_cleanup_errors(
                    Some(format!("wait failed: {wait_error}")),
                    cleanup.err().map(|error| error.to_string()),
                );
                return fail_direct_process(lifecycle, output_error.with_cleanup(cleanup_error));
            }
            if let Err(cleanup) = cleanup {
                return fail_direct_process(
                    lifecycle,
                    ProcessError::Cleanup(Arc::from(format!(
                        "wait failed: {wait_error}; cleanup failed: {cleanup}"
                    ))),
                );
            }
            fail_direct_process(lifecycle, ProcessError::Wait(wait_error))
        }
        Outcome::TimedOut(after) => {
            let cleanup = running.close().await.err().map(|error| error.to_string());
            let output = finish_output_drains(output_drains)
                .await
                .err()
                .map(|error| error.to_string());
            let cleanup_error = combine_cleanup_errors(cleanup, output);
            fail_direct_process(
                lifecycle,
                ProcessError::TimedOut {
                    after,
                    cleanup_error,
                },
            )
        }
        Outcome::Cancelled => {
            let cleanup = running.close().await.err().map(|error| error.to_string());
            let output = finish_output_drains(output_drains)
                .await
                .err()
                .map(|error| error.to_string());
            let cleanup_error = combine_cleanup_errors(cleanup, output);
            fail_direct_process(lifecycle, ProcessError::Cancelled { cleanup_error })
        }
        Outcome::Output(error) => {
            let cleanup = running.close().await.err().map(|error| error.to_string());
            let drain_cleanup = finish_output_drains(output_drains)
                .await
                .err()
                .map(|error| error.to_string());
            let cleanup_error = combine_cleanup_errors(cleanup, drain_cleanup);
            fail_direct_process(lifecycle, error.with_cleanup(cleanup_error))
        }
    }
}

struct DirectOutput {
    stdio: ProcessStdio,
    host_route: Option<HostOutputRoute>,
}

enum HostOutputRoute {
    Capture(crate::process::CaptureOptions),
    File(PathBuf),
}

fn direct_process_stdio(output: Output) -> DirectOutput {
    match output {
        Output::Discard => DirectOutput {
            stdio: ProcessStdio::Null,
            host_route: None,
        },
        Output::GuestFile(path) => DirectOutput {
            stdio: ProcessStdio::File(path.to_string_lossy().into_owned()),
            host_route: None,
        },
        Output::Capture(options) => DirectOutput {
            stdio: ProcessStdio::Pipe,
            host_route: Some(HostOutputRoute::Capture(options)),
        },
        Output::HostFile(path) => DirectOutput {
            stdio: ProcessStdio::Pipe,
            host_route: Some(HostOutputRoute::File(path)),
        },
    }
}

struct DrainedOutput {
    stream: OutputStream,
    captured: Option<Vec<u8>>,
}

struct OutputDrains {
    tasks: tokio::task::JoinSet<Result<DrainedOutput, ProcessError>>,
    completed: Vec<DrainedOutput>,
}

impl OutputDrains {
    fn has_pending(&self) -> bool {
        !self.tasks.is_empty()
    }

    async fn next(&mut self) -> Option<Result<(), ProcessError>> {
        let result = self.tasks.join_next().await?;
        Some(match result {
            Ok(Ok(drained)) => {
                self.completed.push(drained);
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(error) => Err(ProcessError::output(
                OutputStream::Stdout,
                format!("output drain task failed: {error}"),
            )),
        })
    }
}

async fn start_output_drains(
    process: &RunningProcess,
    stdout: Option<HostOutputRoute>,
    stderr: Option<HostOutputRoute>,
) -> Result<OutputDrains, ProcessError> {
    let mut bindings = Vec::new();
    for (stream, route) in [
        (ProcessOutputStream::Stdout, stdout),
        (ProcessOutputStream::Stderr, stderr),
    ] {
        if let Some(route) = route {
            let bound = process.bind_output_raw(stream).await.map_err(|error| {
                ProcessError::output(
                    capture_stream(stream),
                    format!("failed to bind {}: {error}", output_stream_name(stream)),
                )
            })?;
            bindings.push((stream, route, bound));
        }
    }

    let process_uuid = process.uuid();
    let mut drains = OutputDrains {
        tasks: tokio::task::JoinSet::new(),
        completed: Vec::new(),
    };
    for (stream, route, bound) in bindings {
        drains.tasks.spawn(async move {
            let stream = capture_stream(stream);
            drain_host_output(bound, route, process_uuid, stream)
                .await
                .map(|captured| DrainedOutput { stream, captured })
        });
    }
    Ok(drains)
}

async fn finish_output_drains(
    mut drains: OutputDrains,
) -> Result<Vec<DrainedOutput>, ProcessError> {
    let mut first_error = None;
    while let Some(result) = drains.tasks.join_next().await {
        match result {
            Ok(Ok(drained)) => {
                drains.completed.push(drained);
            }
            Ok(Err(error)) => {
                first_error.get_or_insert(error);
            }
            Err(error) => {
                first_error.get_or_insert(ProcessError::output(
                    OutputStream::Stdout,
                    format!("output drain task failed: {error}"),
                ));
            }
        };
        if first_error.is_some() {
            drains.tasks.abort_all();
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(drains.completed)
}

fn retain_captured_output(lifecycle: &ProcessLifecycle, completed: Vec<DrainedOutput>) {
    for drained in completed {
        if let Some(bytes) = drained.captured {
            match drained.stream {
                OutputStream::Stdout => lifecycle.capture_stdout(bytes),
                OutputStream::Stderr => lifecycle.capture_stderr(bytes),
            }
        }
    }
}

async fn drain_host_output(
    mut stream: Box<dyn ProcessStream>,
    route: HostOutputRoute,
    uuid: uuid::Uuid,
    output: OutputStream,
) -> Result<Option<Vec<u8>>, ProcessError> {
    match route {
        HostOutputRoute::Capture(options) => {
            let mut capture = CaptureAccumulator::new(options, output);
            loop {
                let bytes = stream.read().await.map_err(|error| {
                    ProcessError::output(
                        output,
                        format!("failed reading {}: {error}", output.name()),
                    )
                })?;
                if bytes.is_empty() {
                    break;
                }
                capture.push(&bytes)?;
            }
            Ok(Some(capture.finish()))
        }
        HostOutputRoute::File(path) => {
            use tokio::io::AsyncWriteExt;

            let target = host_output_path(&path, uuid, output).await?;
            let mut file = tokio::fs::File::create(&target).await.map_err(|error| {
                ProcessError::output(
                    output,
                    format!(
                        "failed creating host output file {}: {error}",
                        target.display()
                    ),
                )
            })?;
            loop {
                let bytes = stream.read().await.map_err(|error| {
                    ProcessError::output(
                        output,
                        format!("failed reading {}: {error}", output.name()),
                    )
                })?;
                if bytes.is_empty() {
                    break;
                }
                file.write_all(&bytes).await.map_err(|error| {
                    ProcessError::output(
                        output,
                        format!(
                            "failed writing host output file {}: {error}",
                            target.display()
                        ),
                    )
                })?;
            }
            file.flush().await.map_err(|error| {
                ProcessError::output(
                    output,
                    format!(
                        "failed flushing host output file {}: {error}",
                        target.display()
                    ),
                )
            })?;
            Ok(None)
        }
    }
}

async fn host_output_path(
    configured: &Path,
    uuid: uuid::Uuid,
    output: OutputStream,
) -> Result<PathBuf, ProcessError> {
    let text = configured.as_os_str().to_string_lossy();
    let directory_hint = text.ends_with('/') || text.ends_with('\\');
    let is_directory = directory_hint || configured.is_dir();
    let target = if is_directory {
        tokio::fs::create_dir_all(configured)
            .await
            .map_err(|error| {
                ProcessError::output(
                    output,
                    format!(
                        "failed creating host output directory {}: {error}",
                        configured.display()
                    ),
                )
            })?;
        configured.join(format!("process-{uuid}.{}", output.name()))
    } else {
        if let Some(parent) = configured
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                ProcessError::output(
                    output,
                    format!(
                        "failed creating host output directory {}: {error}",
                        parent.display()
                    ),
                )
            })?;
        }
        configured.to_path_buf()
    };
    Ok(target)
}

fn capture_stream(stream: ProcessOutputStream) -> OutputStream {
    match stream {
        ProcessOutputStream::Stdout => OutputStream::Stdout,
        ProcessOutputStream::Stderr => OutputStream::Stderr,
    }
}

fn output_stream_name(stream: ProcessOutputStream) -> &'static str {
    match stream {
        ProcessOutputStream::Stdout => "stdout",
        ProcessOutputStream::Stderr => "stderr",
    }
}

fn combine_cleanup_errors(first: Option<String>, second: Option<String>) -> Option<Arc<str>> {
    let message = [first, second]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
    (!message.is_empty()).then(|| Arc::from(message))
}

fn fail_direct_process(
    lifecycle: Option<ProcessLifecycle>,
    error: ProcessError,
) -> Result<ProcessExit, ProcessError> {
    if let Some(lifecycle) = lifecycle {
        lifecycle.failed(error.clone());
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{CaptureEnd, CaptureOptions, Output, ProcessLifecycle, ProcessState};
    use crate::support::{FakeStreams, ScriptedTransport, start_dispatcher};
    use protocol::{Command, Event};

    async fn run_with_streams(
        process: PreparedProcess,
        transport: ScriptedTransport,
        stream_chunks: Vec<Vec<u8>>,
    ) -> (
        Result<ProcessExit, ProcessError>,
        crate::support::TestDispatcher,
    ) {
        let dispatcher = start_dispatcher(Arc::new(transport));
        let cleanup = Arc::new(CleanupTasks::new());
        let streams: Arc<dyn StreamTransport> = Arc::new(FakeStreams::new(stream_chunks));
        let result =
            crate::direct::run_direct_process(dispatcher.tx(), streams, cleanup, process).await;
        (result, dispatcher)
    }

    #[tokio::test]
    async fn direct_process_captures_output_and_publishes_a_successful_exit() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        let process = PreparedProcess {
            path: "/bin/tool".to_string(),
            args: vec!["--flag".to_string()],
            envs: vec![("ONE".to_string(), "1".to_string())],
            cwd: Some("/work".to_string()),
            timeout: None,
            stdout: Output::Capture(
                CaptureOptions::new()
                    .until(CaptureEnd::Delimiter(bytes::Bytes::from_static(b"--END"))),
            ),
            stderr: Output::Discard,
            lifecycle: Some(lifecycle),
        };

        let (exit, dispatcher) = run_with_streams(
            process,
            ScriptedTransport::process_lifecycle(),
            vec![b"hello".to_vec(), b"--END".to_vec(), b"trailing".to_vec()],
        )
        .await;
        let exit = exit.expect("direct process must exit successfully");

        assert!(exit.success());
        assert_eq!(
            observer.state(),
            ProcessState::Finished(ProcessExit {
                exit_code: Some(0),
                signal: None,
            })
        );
        assert_eq!(observer.finished().await, Ok(exit));
        assert_eq!(observer.stdout().await, Ok(b"hello--END".to_vec()));
        assert_eq!(
            observer.stderr().await,
            Err(ProcessError::OutputUnavailable)
        );
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn pre_cancelled_process_fails_before_any_transport_work() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        observer.cancel();
        let process = PreparedProcess {
            path: "/bin/tool".to_string(),
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            timeout: None,
            stdout: Output::Discard,
            stderr: Output::Discard,
            lifecycle: Some(lifecycle),
        };

        let (result, dispatcher) =
            run_with_streams(process, ScriptedTransport::process_lifecycle(), Vec::new()).await;

        let expected = ProcessError::Cancelled {
            cleanup_error: None,
        };
        assert_eq!(result, Err(expected.clone()));
        assert_eq!(observer.finished().await, Err(expected));
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn non_zero_exit_is_published_as_unsuccessful_exit() {
        let (observer, lifecycle) = ProcessLifecycle::new();
        let process = PreparedProcess {
            path: "/bin/tool".to_string(),
            args: Vec::new(),
            envs: Vec::new(),
            cwd: None,
            timeout: None,
            stdout: Output::Discard,
            stderr: Output::Discard,
            lifecycle: Some(lifecycle),
        };

        let echo_start = |cmd: &Command| -> Event {
            if let Command::ProcessStart { uuid, .. } = cmd {
                Event::ProcessStarted { uuid: *uuid }
            } else {
                Event::VMReady
            }
        };
        let exit_seven = |cmd: &Command| -> Event {
            if let Command::ProcessWait { uuid } | Command::ProcessStop { uuid } = cmd {
                Event::ProcessExited {
                    uuid: *uuid,
                    exit_code: Some(7),
                    signal: None,
                }
            } else {
                Event::VMReady
            }
        };
        let echo_close = |cmd: &Command| -> Event {
            if let Command::ProcessClose { uuid } = cmd {
                Event::ProcessClosed { uuid: *uuid }
            } else {
                Event::VMReady
            }
        };
        let transport = ScriptedTransport::scripted(vec![
            Box::new(echo_start),
            Box::new(exit_seven),
            Box::new(exit_seven),
            Box::new(echo_close),
        ]);
        let (result, dispatcher) = run_with_streams(process, transport, Vec::new()).await;

        let expected = ProcessExit {
            exit_code: Some(7),
            signal: None,
        };
        assert!(matches!(
            result,
            Err(ProcessError::UnsuccessfulExit(exit)) if exit == expected
        ));
        assert_eq!(observer.finished().await, result);
        dispatcher.shutdown().await;
    }
}
