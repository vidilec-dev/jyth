use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use guest_client::{
    CaptureEnd, MAX_CAPTURE_LIMIT, Output, PreparedProcess, ProcessError, ProcessLifecycle,
    ProcessObserver,
};

use crate::builder::file::RustBinary;

/// A VM-independent executable source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Executable {
    /// A shell program evaluated by the guest shell.
    Shell(String),
    /// An executable already available at this guest path.
    Exec(PathBuf),
    /// A Rust binary that a later build stage will compile and inject.
    Rust(RustBinary),
    /// Executable bytes that a later build stage will inject.
    Bytes(Bytes),
}

/// Immutable, VM-independent process description produced by
/// [`ProcessBuilder::build`].
pub struct Process {
    executable: Executable,
    args: Vec<String>,
    envs: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    timeout: Option<Duration>,
    stdout: Output,
    stderr: Output,
    lifecycle: Option<ProcessLifecycle>,
}

impl Process {
    /// Borrow the executable source.
    pub fn executable(&self) -> &Executable {
        &self.executable
    }

    /// Borrow the ordered guest arguments.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Borrow the guest environment variables.
    pub fn envs(&self) -> &BTreeMap<String, String> {
        &self.envs
    }

    /// Borrow the optional guest working directory.
    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    /// Return the optional execution timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Borrow the stdout routing policy.
    pub fn stdout(&self) -> &Output {
        &self.stdout
    }

    /// Borrow the stderr routing policy.
    pub fn stderr(&self) -> &Output {
        &self.stderr
    }

    /// Whether this process was built together with a [`ProcessObserver`].
    pub fn has_observer(&self) -> bool {
        self.lifecycle.is_some()
    }

    /// Replace a host-side executable source with its prepared guest path.
    /// Used by `VmBuilder` after adding Rust/byte payloads to the initramfs.
    pub(crate) fn replace_executable(&mut self, executable: Executable) {
        self.executable = executable;
    }

    /// Convert this facade process into the guest-client prepared form.
    ///
    /// Shell commands become the guest shell invocation, guest paths pass
    /// through, and unprepared Rust/byte executables fail with
    /// [`ProcessError::UnpreparedExecutable`] after publishing the terminal
    /// failure to the retained observer.
    pub(crate) fn into_prepared(self) -> Result<PreparedProcess, ProcessError> {
        let Process {
            executable,
            args,
            envs,
            cwd,
            timeout,
            stdout,
            stderr,
            lifecycle,
        } = self;
        let (path, args) = match executable {
            Executable::Shell(command) => {
                let mut shell_args = vec!["-c".to_string(), command, "jyth-shell".to_string()];
                shell_args.append(&mut args.clone());
                ("/bin/sh".to_string(), shell_args)
            }
            Executable::Exec(path) => (path.to_string_lossy().into_owned(), args),
            Executable::Rust(_) | Executable::Bytes(_) => {
                let error = ProcessError::UnpreparedExecutable;
                if let Some(lifecycle) = &lifecycle {
                    lifecycle.failed(error.clone());
                }
                return Err(error);
            }
        };
        let cwd = cwd.map(|cwd| cwd.to_string_lossy().into_owned());
        Ok(PreparedProcess {
            path,
            args,
            envs: envs.into_iter().collect(),
            cwd,
            timeout,
            stdout,
            stderr,
            lifecycle,
        })
    }

    /// Publish the dependency-cancelled process failure (used by the
    /// scheduler adapter's trigger wrapper when a condition resolves false).
    ///
    /// The runtime's packaging publishes the same failure through the
    /// prepared process lifecycle; this method retains the facade-level
    /// contract evidence for the unit tests.
    #[cfg(test)]
    pub(crate) fn dependency_cancelled(self) {
        if let Some(lifecycle) = self.lifecycle {
            lifecycle.failed(ProcessError::Cancelled {
                cleanup_error: None,
            });
        }
    }
}

impl std::fmt::Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Process")
            .field("executable", &self.executable)
            .field("args", &self.args)
            .field("envs", &self.envs)
            .field("cwd", &self.cwd)
            .field("timeout", &self.timeout)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .finish_non_exhaustive()
    }
}

/// Initial builder stage. It intentionally exposes only executable selectors.
#[doc(hidden)]
pub struct MissingExecutable;

/// Configured builder stage. It exposes process configuration and `build`.
#[doc(hidden)]
pub struct Configured;

struct Draft {
    executable: Option<Executable>,
    args: Vec<String>,
    envs: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    timeout: Option<Duration>,
    stdout: Output,
    stderr: Output,
    lifecycle: Option<ProcessLifecycle>,
}

impl Draft {
    fn new() -> Self {
        Self {
            executable: None,
            args: Vec::new(),
            envs: BTreeMap::new(),
            cwd: None,
            timeout: None,
            stdout: Output::Discard,
            stderr: Output::Discard,
            lifecycle: None,
        }
    }
}

/// A two-stage, VM-independent process builder.
///
/// The default stage has no executable and only offers executable selectors.
/// Selecting one transitions to [`Configured`], where process options and
/// [`build`](ProcessBuilder::<Configured>::build) are available.
pub struct ProcessBuilder<State = MissingExecutable> {
    draft: Draft,
    state: std::marker::PhantomData<State>,
}

impl Default for ProcessBuilder<MissingExecutable> {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessBuilder<MissingExecutable> {
    /// Create an empty process builder.
    pub fn new() -> Self {
        Self {
            draft: Draft::new(),
            state: std::marker::PhantomData,
        }
    }

    /// Creates an empty builder and its retained observer.
    ///
    /// Observer-first ordering matches `VmBuilder::with_observer()`.
    pub fn with_observer() -> (ProcessObserver, Self) {
        let (observer, lifecycle) = ProcessLifecycle::new();
        let mut builder = Self::new();
        builder.draft.lifecycle = Some(lifecycle);
        (observer, builder)
    }

    /// Select an executable source.
    pub fn process(mut self, executable: Executable) -> ProcessBuilder<Configured> {
        self.draft.executable = Some(executable);
        ProcessBuilder {
            draft: self.draft,
            state: std::marker::PhantomData,
        }
    }

    /// Run a command through the guest shell.
    pub fn shell(self, command: impl Into<String>) -> ProcessBuilder<Configured> {
        self.process(Executable::Shell(command.into()))
    }

    /// Run an executable already present at a guest path.
    pub fn exec(self, path: PathBuf) -> ProcessBuilder<Configured> {
        self.process(Executable::Exec(path))
    }

    /// Build and inject a Rust binary before running it.
    pub fn rust(self, binary: RustBinary) -> ProcessBuilder<Configured> {
        self.process(Executable::Rust(binary))
    }

    /// Inject and run literal executable bytes.
    pub fn bytes(self, bytes: Bytes) -> ProcessBuilder<Configured> {
        self.process(Executable::Bytes(bytes))
    }
}

impl ProcessBuilder<Configured> {
    /// Append one guest process argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.draft.args.push(arg.into());
        self
    }

    /// Append a sequence of guest process arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.draft
            .args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    /// Add one guest process environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.draft.envs.insert(key.into(), value.into());
        self
    }

    /// Add guest process environment variables.
    pub fn envs<I, K, V>(mut self, envs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.draft.envs.extend(
            envs.into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        self
    }

    /// Set the guest working directory.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.draft.cwd = Some(cwd.into());
        self
    }

    /// Set the process timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.draft.timeout = Some(timeout);
        self
    }

    /// Configure stdout routing.
    pub fn stdout(mut self, output: Output) -> Self {
        self.draft.stdout = output;
        self
    }

    /// Configure stderr routing.
    pub fn stderr(mut self, output: Output) -> Self {
        self.draft.stderr = output;
        self
    }

    /// Validate and produce an immutable process description.
    pub fn build(self) -> Result<Process, ProcessBuildError> {
        let executable = self
            .draft
            .executable
            .expect("configured ProcessBuilder always has an executable");
        validate_executable(&executable)?;
        validate_output(&self.draft.stdout)?;
        validate_output(&self.draft.stderr)?;
        Ok(Process {
            executable,
            args: self.draft.args,
            envs: self.draft.envs,
            cwd: self.draft.cwd,
            timeout: self.draft.timeout,
            stdout: self.draft.stdout,
            stderr: self.draft.stderr,
            lifecycle: self.draft.lifecycle,
        })
    }
}

/// Validation failures returned by [`ProcessBuilder::build`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessBuildError {
    /// An executable path or Rust manifest path was empty.
    EmptyExecutablePath,
    /// A capture limit was zero.
    EmptyCaptureLimit,
    /// A capture limit above [`MAX_CAPTURE_LIMIT`] was configured.
    CaptureLimitTooLarge {
        /// Configured capture limit in bytes.
        requested: usize,
        /// Library maximum capture limit in bytes.
        maximum: usize,
    },
    /// A byte-count capture boundary was zero.
    EmptyCaptureEndSize,
    /// A delimiter capture boundary was empty.
    EmptyCaptureDelimiter,
}

impl std::fmt::Display for ProcessBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyExecutablePath => f.write_str("executable path cannot be empty"),
            Self::EmptyCaptureLimit => f.write_str("capture limit cannot be zero"),
            Self::CaptureLimitTooLarge { requested, maximum } => write!(
                f,
                "capture limit of {requested} bytes exceeds the library maximum of {maximum} bytes"
            ),
            Self::EmptyCaptureEndSize => f.write_str("capture end byte count cannot be zero"),
            Self::EmptyCaptureDelimiter => f.write_str("capture delimiter cannot be empty"),
        }
    }
}

impl std::error::Error for ProcessBuildError {}

fn validate_executable(executable: &Executable) -> Result<(), ProcessBuildError> {
    match executable {
        Executable::Exec(path) if path.as_os_str().is_empty() => {
            Err(ProcessBuildError::EmptyExecutablePath)
        }
        Executable::Rust(binary) if binary.manifest_path().as_os_str().is_empty() => {
            Err(ProcessBuildError::EmptyExecutablePath)
        }
        _ => Ok(()),
    }
}

fn validate_output(output: &Output) -> Result<(), ProcessBuildError> {
    match output {
        Output::Capture(options) if options.limit() == 0 => {
            Err(ProcessBuildError::EmptyCaptureLimit)
        }
        Output::Capture(options) if options.limit() > MAX_CAPTURE_LIMIT => {
            Err(ProcessBuildError::CaptureLimitTooLarge {
                requested: options.limit(),
                maximum: MAX_CAPTURE_LIMIT,
            })
        }
        Output::Capture(options) if matches!(options.end(), CaptureEnd::Bytes(0)) => {
            Err(ProcessBuildError::EmptyCaptureEndSize)
        }
        Output::Capture(options) if matches!(options.end(), CaptureEnd::Delimiter(delimiter) if delimiter.is_empty()) => {
            Err(ProcessBuildError::EmptyCaptureDelimiter)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guest_client::{CaptureOptions, ProcessState};

    #[test]
    fn staged_builder_builds_a_vm_independent_process() {
        let process = ProcessBuilder::new()
            .exec(PathBuf::from("/bin/tool"))
            .args(["first", "second"])
            .env("ONE", "1")
            .envs([("TWO", "2")])
            .cwd("/work")
            .timeout(Duration::from_secs(3))
            .stdout(Output::Capture(CaptureOptions::default()))
            .stderr(Output::GuestFile(PathBuf::from("/tmp/stderr")))
            .build()
            .unwrap();

        assert_eq!(process.executable(), &Executable::Exec("/bin/tool".into()));
        assert_eq!(process.args(), ["first", "second"]);
        assert_eq!(process.envs()["ONE"], "1");
        assert_eq!(process.envs()["TWO"], "2");
        assert_eq!(process.cwd(), Some(Path::new("/work")));
        assert_eq!(process.timeout(), Some(Duration::from_secs(3)));
        assert_eq!(
            process.stdout(),
            &Output::Capture(CaptureOptions::default())
        );
        assert_eq!(
            process.stderr(),
            &Output::GuestFile(PathBuf::from("/tmp/stderr"))
        );
    }

    #[test]
    fn shorthands_select_each_executable_kind() {
        let shell = ProcessBuilder::new().shell("echo hello").build().unwrap();
        let rust = ProcessBuilder::new()
            .rust(RustBinary::new("examples/tool/Cargo.toml"))
            .build()
            .unwrap();
        let bytes = ProcessBuilder::new()
            .bytes(Bytes::from_static(b"binary"))
            .build()
            .unwrap();

        assert_eq!(shell.executable(), &Executable::Shell("echo hello".into()));
        assert_eq!(
            rust.executable(),
            &Executable::Rust(RustBinary::new("examples/tool/Cargo.toml"))
        );
        assert_eq!(
            bytes.executable(),
            &Executable::Bytes(Bytes::from_static(b"binary"))
        );
    }

    #[test]
    fn general_selector_keeps_arguments_for_every_variant() {
        let process = ProcessBuilder::new()
            .process(Executable::Shell("printf '%s' \"$1\"".into()))
            .arg("value")
            .build()
            .unwrap();

        assert_eq!(process.args(), ["value"]);
    }

    #[test]
    fn observer_is_retained_by_the_built_process() {
        let (observer, builder) = ProcessBuilder::with_observer();
        let process = builder.shell("true").build().unwrap();

        assert_eq!(observer.state(), ProcessState::Pending);
        assert!(process.has_observer());
    }

    #[tokio::test]
    async fn unsatisfied_dependency_cancels_process_before_start() {
        let (observer, builder) = ProcessBuilder::with_observer();
        let process = builder.shell("true").build().unwrap();

        process.dependency_cancelled();

        assert!(matches!(
            observer.state(),
            ProcessState::Failed(ProcessError::Cancelled {
                cleanup_error: None
            })
        ));
        assert!(matches!(
            observer.finished().await,
            Err(ProcessError::Cancelled {
                cleanup_error: None
            })
        ));
    }

    #[tokio::test]
    async fn dropped_unfinished_process_resolves_as_cancelled() {
        let (observer, builder) = ProcessBuilder::with_observer();
        let process = builder.shell("true").build().unwrap();
        drop(process);

        assert_eq!(
            observer.finished().await,
            Err(ProcessError::Cancelled {
                cleanup_error: None,
            })
        );
    }

    #[test]
    fn invalid_output_capture_is_rejected() {
        let error = ProcessBuilder::new()
            .shell("true")
            .stdout(Output::Capture(CaptureOptions::default().with_limit(0)))
            .build()
            .unwrap_err();
        assert_eq!(error, ProcessBuildError::EmptyCaptureLimit);
    }

    #[test]
    fn capture_limit_above_the_library_maximum_is_rejected_at_build_time() {
        let error = ProcessBuilder::new()
            .shell("true")
            .stdout(Output::Capture(
                CaptureOptions::default().with_limit(MAX_CAPTURE_LIMIT + 1),
            ))
            .build()
            .unwrap_err();
        assert_eq!(
            error,
            ProcessBuildError::CaptureLimitTooLarge {
                requested: MAX_CAPTURE_LIMIT + 1,
                maximum: MAX_CAPTURE_LIMIT,
            }
        );
    }

    #[test]
    fn capture_limit_at_the_library_maximum_builds() {
        let process = ProcessBuilder::new()
            .shell("true")
            .stdout(Output::Capture(
                CaptureOptions::default().with_limit(MAX_CAPTURE_LIMIT),
            ))
            .build()
            .unwrap();
        assert!(matches!(process.stdout(), &Output::Capture(_)));
    }

    #[test]
    fn capture_limit_validation_applies_to_stderr_too() {
        let error = ProcessBuilder::new()
            .shell("true")
            .stderr(Output::Capture(
                CaptureOptions::default().with_limit(MAX_CAPTURE_LIMIT + 1),
            ))
            .build()
            .unwrap_err();
        assert_eq!(
            error,
            ProcessBuildError::CaptureLimitTooLarge {
                requested: MAX_CAPTURE_LIMIT + 1,
                maximum: MAX_CAPTURE_LIMIT,
            }
        );
    }

    #[test]
    fn unprepared_executable_fails_preparation_with_a_terminal_observer_state() {
        let (observer, builder) = ProcessBuilder::with_observer();
        let process = builder
            .rust(RustBinary::new("examples/tool/Cargo.toml"))
            .build()
            .unwrap();

        let error = process.into_prepared().expect_err("Rust source must fail");
        assert_eq!(error, ProcessError::UnpreparedExecutable);
        assert!(matches!(
            observer.state(),
            ProcessState::Failed(ProcessError::UnpreparedExecutable)
        ));
    }

    #[test]
    fn shell_and_guest_path_executables_prepare_to_guest_paths() {
        let shell = ProcessBuilder::new()
            .shell("echo hello")
            .arg("world")
            .build()
            .unwrap();
        let prepared = shell.into_prepared().unwrap();
        assert_eq!(prepared.path, "/bin/sh");
        assert_eq!(prepared.args, ["-c", "echo hello", "jyth-shell", "world"]);
        assert_eq!(prepared.cwd.as_deref(), None);

        let exec = ProcessBuilder::new()
            .exec(PathBuf::from("/bin/tool"))
            .build()
            .unwrap();
        let prepared = exec.into_prepared().unwrap();
        assert_eq!(prepared.path, "/bin/tool");
    }
}
