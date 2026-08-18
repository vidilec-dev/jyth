//! Stable host/guest command and event messages.
//!
//! Messages are serialized with `rkyv` and exchanged as length-prefixed
//! frames by the `com` transport. The numeric command port and message
//! variants are part of the guest protocol contract.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: protocol.
//!
//! **Responsibility**: versioned wire values and cryptographic transcripts.
//!
//! **Allowed dependencies**: none (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: sockets, VM creation, image acquisition, disk
//! creation, and scheduler state.
#![allow(missing_docs)]
//
// rkyv generates public archived companion structs for the documented command
// and event enums. The generated fields are serialization-ABI artifacts and
// cannot receive source-level field documentation; the hand-written wire
// types below remain fully documented.

use error_stack::Report;
use rkyv::{Archive, Deserialize, Serialize};
use uuid::Uuid;

pub mod auth;

pub use auth::{
    AUTHENTICATION_DEADLINE, AuthAcceptedV1, AuthChallengeV1, AuthResponseV1, BootConfigV1,
    BootstrapConfigV1, BootstrapResultV1, COMMAND_AUTH_CONTEXT_V1, GuestDiskConfigV1,
    GuestNetworkConfigV1, MAX_AUTH_FRAME, MAX_BOOT_CONFIG_FRAME, MAX_BOOTSTRAP_ARTIFACT_BYTES,
    MAX_BOOTSTRAP_CHUNK, MAX_COMMAND_FRAME, MAX_GUEST_CONNECTIONS, PROTOCOL_VERSION, ReadyV1,
    SessionCapability,
};

/// TCP command port used by the host command dispatcher. The guest binds
/// this port on its configured NIC address; the host derives the same
/// endpoint from the validated `Nat` supplied to launch.
pub const COMMAND_PORT: u16 = 1024;

/// Length-prefixed COM1 marker sent by init after the guest has opened and
/// configured the control UART. The host waits for this marker before sending
/// the boot configuration so the first inbound frame cannot race UART setup.
pub const COM1_READY_MAGIC: &[u8] = b"JYTH/COM1/READY";

/// Error context for the rkyv-based (de)serialization of `Command` / `Event`.
///
/// Carries no dynamic data of its own — the actual rkyv error text is
/// attached as a printable frame at the call site (see `Command::try_from` /
/// `Event::try_from` below), so `ProtocolError` stays `Copy` and can be
/// returned by value without heap allocation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// `rkyv::access` failed: the archived bytes are not a valid
    /// `ArchivedCommand` / `ArchivedEvent` (wrong schema, truncated, …).
    Access,
    /// `rkyv::deserialize` failed after a successful `access`.
    Deserialize,
    /// `rkyv::to_bytes` failed (outbound serialization).
    Serialize,
    /// A versioned control-plane frame is malformed or has an unexpected
    /// length/tag.
    InvalidFrame,
    /// A control-plane frame used a protocol version this build does not
    /// understand.
    VersionMismatch,
    /// A control-plane value violates its bounded wire contract.
    InvalidValue,
    /// The operating system CSPRNG could not produce a capability or nonce.
    Randomness,
    /// A keyed proof did not verify.
    Authentication,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ProtocolError::Access => "rkyv access of archived protocol bytes failed",
            ProtocolError::Deserialize => "rkyv deserialize of protocol message failed",
            ProtocolError::Serialize => "rkyv serialize of protocol message failed",
            ProtocolError::InvalidFrame => "versioned protocol frame is malformed",
            ProtocolError::VersionMismatch => "protocol version mismatch",
            ProtocolError::InvalidValue => "versioned protocol value is invalid",
            ProtocolError::Randomness => "operating system randomness failed",
            ProtocolError::Authentication => "protocol authentication failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ProtocolError {}

/// Typed error code for `Event::Error` received from the guest.
///
/// The wire format remains `Event::Error { code: u32, msg: String }`.
/// This enum is a host-side helper to map the numeric code to a typed
/// variant for use in `ApiError::Guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestErrorCode {
    /// Guest process creation failed.
    ProcessStart,
    /// Guest process termination failed.
    ProcessStop,
    /// Guest process wait failed.
    ProcessWait,
    /// Guest process close failed.
    ProcessClose,
    /// Guest file read failed.
    FileRead,
    /// Guest file write failed.
    FileWrite,
    /// Guest file removal failed.
    FileRemove,
    /// Guest directory read failed.
    DirRead,
    /// Guest directory creation failed.
    DirCreate,
    /// Guest directory removal failed.
    DirRemove,
    /// A guest error code not known to this host build.
    Unknown(u32),
}

impl GuestErrorCode {
    /// Map the numeric code from the guest to the typed variant.
    pub fn from_u32(code: u32) -> Self {
        match code {
            1 => Self::ProcessStart,
            2 => Self::ProcessStop,
            9 => Self::ProcessWait,
            10 => Self::ProcessClose,
            3 => Self::FileRead,
            4 => Self::FileWrite,
            5 => Self::FileRemove,
            6 => Self::DirRead,
            7 => Self::DirCreate,
            8 => Self::DirRemove,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for GuestErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessStart => write!(f, "guest process start failed"),
            Self::ProcessStop => write!(f, "guest process stop failed"),
            Self::ProcessWait => write!(f, "guest process wait failed"),
            Self::ProcessClose => write!(f, "guest process close failed"),
            Self::FileRead => write!(f, "guest file read failed"),
            Self::FileWrite => write!(f, "guest file write failed"),
            Self::FileRemove => write!(f, "guest file remove failed"),
            Self::DirRead => write!(f, "guest dir read failed"),
            Self::DirCreate => write!(f, "guest dir create failed"),
            Self::DirRemove => write!(f, "guest dir remove failed"),
            Self::Unknown(code) => write!(f, "guest error (unknown code {code})"),
        }
    }
}

impl std::error::Error for GuestErrorCode {}

/// Convenience alias: a `Result` whose error is an `error_stack::Report`
/// rooted at `ProtocolError`, with the dynamic rkyv error text attached as a
/// printable frame at each call site.
pub type ProtocolResult<T> = Result<T, Report<ProtocolError>>;

/// A request sent from the host to the guest.
#[allow(missing_docs)]
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum Command {
    /// Check that the command bus is responsive.
    Ping,
    /// Request guest shutdown.
    VMShutdown,
    /// Read a guest file.
    FileRead {
        /// Guest path to read.
        path: String,
    },
    /// Write a guest file.
    FileWrite {
        /// Guest path to write.
        path: String,
        /// Bytes to write.
        data: Vec<u8>,
    },
    /// Remove a guest file.
    FileRemove {
        /// Guest path to remove.
        path: String,
    },
    /// Read a guest directory.
    DirRead {
        /// Guest directory path.
        path: String,
    },
    /// Create a guest directory.
    DirCreate {
        /// Guest directory path.
        path: String,
    },
    /// Remove a guest directory.
    DirRemove {
        /// Guest directory path.
        path: String,
    },
    /// Start a guest process with selected stdio routes.
    ProcessStart {
        /// Process identifier used by later requests.
        uuid: Uuid,
        /// Guest executable path.
        path: String,
        /// Process arguments.
        args: Vec<String>,
        /// Environment key/value pairs.
        envs: Vec<(String, String)>,
        /// Optional guest working directory.
        cwd: Option<String>,
        /// Standard-output route.
        stdout: ProcessStdio,
        /// Standard-error route.
        stderr: ProcessStdio,
    },
    /// Bind the process control stream.
    ProcessBind {
        /// Process identifier.
        uuid: Uuid,
        /// Whether control frames remain enabled after binding.
        stay_framed: bool,
    },
    /// Bind one process output stream.
    ProcessOutputBind {
        /// Process identifier.
        uuid: Uuid,
        /// Output stream to bind.
        stream: ProcessOutputStream,
    },
    /// Stop a guest process.
    ProcessStop {
        /// Process identifier.
        uuid: Uuid,
    },
    /// Wait for a guest process to finish without stopping it.
    ProcessWait {
        /// Process identifier.
        uuid: Uuid,
    },
    /// Close a completed guest process record.
    ProcessClose {
        /// Process identifier.
        uuid: Uuid,
    },
    /// Bind a guest TCP/UDP forwarding port.
    PortBind {
        /// Guest port to bind.
        port: u32,
    },
}

/// Guest-side process output routing selected before the child is spawned.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum ProcessStdio {
    /// Keep a pipe for interactive/captured execution.
    Pipe,
    /// Connect the stream to `/dev/null` without allocating a pipe.
    Null,
    /// Create or truncate a file inside the guest and redirect the stream.
    File(String),
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Copy)]
/// Identifies which process output stream is being bound.
pub enum ProcessOutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl TryFrom<&[u8]> for Command {
    type Error = Report<ProtocolError>;

    fn try_from(value: &[u8]) -> ProtocolResult<Self> {
        let archived =
            rkyv::access::<ArchivedCommand, rkyv::rancor::Error>(value).map_err(|e| {
                Report::new(ProtocolError::Access).attach(format!("rkyv access error: {e:#?}"))
            })?;
        rkyv::deserialize::<Command, rkyv::rancor::Error>(archived).map_err(|e| {
            Report::new(ProtocolError::Deserialize)
                .attach(format!("rkyv deserialize error: {e:#?}"))
        })
    }
}

impl TryInto<Vec<u8>> for Command {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(&self)
            .map_err(|e| {
                Report::new(ProtocolError::Serialize)
                    .attach(format!("rkyv serialize error: {e:#?}"))
            })?
            .into_vec())
    }
}

/// A response or asynchronous notification sent by the guest.
#[allow(missing_docs)]
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub enum Event {
    /// The guest command bus is ready.
    VMReady,
    /// A guest process started.
    ProcessStarted {
        /// Process identifier.
        uuid: Uuid,
    },
    /// A guest process exited.
    ProcessExited {
        /// Process identifier.
        uuid: Uuid,
        /// Exit code, when the process exited normally.
        exit_code: Option<i32>,
        /// Signal number, when the process was terminated by a signal.
        signal: Option<i32>,
    },
    /// A process control stream was bound.
    ProcessBound {
        /// Process identifier.
        uuid: Uuid,
    },
    /// A process record was closed.
    ProcessClosed {
        /// Process identifier.
        uuid: Uuid,
    },
    /// A guest file was read.
    FileRead {
        /// Guest path that was read.
        path: String,
        /// File bytes.
        data: Vec<u8>,
    },
    /// A guest file was written.
    FileWritten {
        /// Guest path that was written.
        path: String,
    },
    /// A guest file was removed.
    FileRemoved {
        /// Guest path that was removed.
        path: String,
    },
    /// A guest directory was listed.
    DirRead {
        /// Guest directory path.
        path: String,
        /// Directory entry names.
        entries: Vec<String>,
    },
    /// A guest directory was created.
    DirCreated {
        /// Guest directory path.
        path: String,
    },
    /// A guest directory was removed.
    DirRemoved {
        /// Guest directory path.
        path: String,
    },
    /// A port was bound in the guest.
    PortBound {
        /// Guest port.
        port: u32,
    },
    /// The guest completed shutdown.
    Shutdowned,
    /// A guest operation failed.
    Error {
        /// Numeric guest error code.
        code: u32,
        /// Human-readable guest error message.
        msg: String,
    },
}

impl TryFrom<&[u8]> for Event {
    type Error = Report<ProtocolError>;

    fn try_from(value: &[u8]) -> ProtocolResult<Self> {
        let archived = rkyv::access::<ArchivedEvent, rkyv::rancor::Error>(value).map_err(|e| {
            Report::new(ProtocolError::Access).attach(format!("rkyv access error: {e:#?}"))
        })?;
        rkyv::deserialize::<Event, rkyv::rancor::Error>(archived).map_err(|e| {
            Report::new(ProtocolError::Deserialize)
                .attach(format!("rkyv deserialize error: {e:#?}"))
        })
    }
}

impl TryInto<Vec<u8>> for Event {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        Ok(rkyv::to_bytes::<rkyv::rancor::Error>(&self)
            .map_err(|e| {
                Report::new(ProtocolError::Serialize)
                    .attach(format!("rkyv serialize error: {e:#?}"))
            })?
            .into_vec())
    }
}

impl Event {
    /// Returns a static string identifying the variant for diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::VMReady => "VMReady",
            Event::ProcessStarted { .. } => "ProcessStarted",
            Event::ProcessExited { .. } => "ProcessExited",
            Event::ProcessBound { .. } => "ProcessBound",
            Event::ProcessClosed { .. } => "ProcessClosed",
            Event::FileRead { .. } => "FileRead",
            Event::FileWritten { .. } => "FileWritten",
            Event::FileRemoved { .. } => "FileRemoved",
            Event::DirRead { .. } => "DirRead",
            Event::DirCreated { .. } => "DirCreated",
            Event::DirRemoved { .. } => "DirRemoved",
            Event::PortBound { .. } => "PortBound",
            Event::Shutdowned => "Shutdowned",
            Event::Error { .. } => "Error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Event, ProcessOutputStream, ProcessStdio, ProtocolError, ProtocolResult};
    use uuid::Uuid;

    fn roundtrip<
        T: for<'a> TryFrom<&'a [u8], Error = error_stack::Report<ProtocolError>>
            + TryInto<Vec<u8>, Error = error_stack::Report<ProtocolError>>
            + PartialEq
            + std::fmt::Debug
            + Clone,
    >(
        original: T,
    ) -> ProtocolResult<()> {
        let bytes = original.clone().try_into()?;
        let decoded = T::try_from(bytes.as_slice())?;
        assert_eq!(decoded, original);
        Ok(())
    }

    #[test]
    fn command_try_from_try_into_roundtrip() {
        let cmds = vec![
            Command::Ping,
            Command::VMShutdown,
            Command::FileRead {
                path: "/etc/passwd".into(),
            },
            Command::FileWrite {
                path: "/tmp/x".into(),
                data: b"hello".to_vec(),
            },
            Command::FileRemove {
                path: "/tmp/x".into(),
            },
            Command::DirRead {
                path: "/var".into(),
            },
            Command::DirCreate {
                path: "/var/new".into(),
            },
            Command::DirRemove {
                path: "/var/old".into(),
            },
            Command::ProcessStart {
                uuid: Uuid::nil(),
                path: "/bin/ls".into(),
                args: vec!["-la".into()],
                envs: vec![("PATH".into(), "/usr/bin".into())],
                cwd: Some("/home".into()),
                stdout: ProcessStdio::Null,
                stderr: ProcessStdio::File("/tmp/ls.stderr".into()),
            },
            Command::ProcessStop { uuid: Uuid::nil() },
            Command::ProcessWait { uuid: Uuid::nil() },
            Command::ProcessClose { uuid: Uuid::nil() },
            Command::ProcessBind {
                uuid: Uuid::nil(),
                stay_framed: true,
            },
            Command::ProcessBind {
                uuid: Uuid::nil(),
                stay_framed: false,
            },
            Command::ProcessOutputBind {
                uuid: Uuid::nil(),
                stream: ProcessOutputStream::Stdout,
            },
            Command::ProcessOutputBind {
                uuid: Uuid::nil(),
                stream: ProcessOutputStream::Stderr,
            },
            Command::PortBind { port: 8080 },
            Command::VMShutdown,
        ];
        for cmd in cmds {
            roundtrip(cmd).unwrap();
        }
    }

    #[test]
    fn event_try_from_try_into_roundtrip() {
        let evts = vec![
            Event::VMReady,
            Event::ProcessStarted { uuid: Uuid::nil() },
            Event::ProcessExited {
                uuid: Uuid::nil(),
                exit_code: Some(17),
                signal: None,
            },
            Event::ProcessBound { uuid: Uuid::nil() },
            Event::ProcessClosed { uuid: Uuid::nil() },
            Event::FileRead {
                path: "/etc/passwd".into(),
                data: b"root:x:0:0".to_vec(),
            },
            Event::FileWritten {
                path: "/tmp/x".into(),
            },
            Event::FileRemoved {
                path: "/tmp/x".into(),
            },
            Event::DirRead {
                path: "/var".into(),
                entries: vec!["a".into(), "b".into()],
            },
            Event::DirCreated {
                path: "/var/new".into(),
            },
            Event::DirRemoved {
                path: "/var/old".into(),
            },
            Event::PortBound { port: 8080 },
            Event::Shutdowned,
            Event::Error {
                code: 42,
                msg: "oops".into(),
            },
        ];
        for evt in evts {
            roundtrip(evt).unwrap();
        }
    }

    #[test]
    fn event_kind_returns_correct_str() {
        let evts = vec![
            (Event::VMReady, "VMReady"),
            (
                Event::ProcessStarted { uuid: Uuid::nil() },
                "ProcessStarted",
            ),
            (
                Event::ProcessExited {
                    uuid: Uuid::nil(),
                    exit_code: None,
                    signal: Some(9),
                },
                "ProcessExited",
            ),
            (Event::ProcessBound { uuid: Uuid::nil() }, "ProcessBound"),
            (Event::ProcessClosed { uuid: Uuid::nil() }, "ProcessClosed"),
            (
                Event::FileRead {
                    path: "/etc/passwd".into(),
                    data: b"root:x:0:0".to_vec(),
                },
                "FileRead",
            ),
            (
                Event::FileWritten {
                    path: "/tmp/x".into(),
                },
                "FileWritten",
            ),
            (
                Event::FileRemoved {
                    path: "/tmp/x".into(),
                },
                "FileRemoved",
            ),
            (
                Event::DirRead {
                    path: "/var".into(),
                    entries: vec!["a".into(), "b".into()],
                },
                "DirRead",
            ),
            (
                Event::DirCreated {
                    path: "/var/new".into(),
                },
                "DirCreated",
            ),
            (
                Event::DirRemoved {
                    path: "/var/old".into(),
                },
                "DirRemoved",
            ),
            (Event::PortBound { port: 8080 }, "PortBound"),
            (Event::Shutdowned, "Shutdowned"),
            (
                Event::Error {
                    code: 42,
                    msg: "oops".into(),
                },
                "Error",
            ),
        ];
        for (evt, expected) in evts {
            assert_eq!(evt.kind(), expected);
        }
    }

    #[test]
    fn guest_error_code_from_u32_maps_correctly() {
        use super::GuestErrorCode;
        let cases = vec![
            (1, GuestErrorCode::ProcessStart),
            (2, GuestErrorCode::ProcessStop),
            (9, GuestErrorCode::ProcessWait),
            (10, GuestErrorCode::ProcessClose),
            (3, GuestErrorCode::FileRead),
            (4, GuestErrorCode::FileWrite),
            (5, GuestErrorCode::FileRemove),
            (6, GuestErrorCode::DirRead),
            (7, GuestErrorCode::DirCreate),
            (8, GuestErrorCode::DirRemove),
            (999, GuestErrorCode::Unknown(999)),
        ];
        for (code, expected) in cases {
            assert_eq!(GuestErrorCode::from_u32(code), expected);
        }
    }

    #[test]
    fn guest_error_code_display() {
        use super::GuestErrorCode;
        assert_eq!(
            GuestErrorCode::ProcessStart.to_string(),
            "guest process start failed"
        );
        assert_eq!(
            GuestErrorCode::ProcessStop.to_string(),
            "guest process stop failed"
        );
        assert_eq!(
            GuestErrorCode::ProcessWait.to_string(),
            "guest process wait failed"
        );
        assert_eq!(
            GuestErrorCode::ProcessClose.to_string(),
            "guest process close failed"
        );
        assert_eq!(
            GuestErrorCode::FileRead.to_string(),
            "guest file read failed"
        );
        assert_eq!(
            GuestErrorCode::FileWrite.to_string(),
            "guest file write failed"
        );
        assert_eq!(
            GuestErrorCode::FileRemove.to_string(),
            "guest file remove failed"
        );
        assert_eq!(GuestErrorCode::DirRead.to_string(), "guest dir read failed");
        assert_eq!(
            GuestErrorCode::DirCreate.to_string(),
            "guest dir create failed"
        );
        assert_eq!(
            GuestErrorCode::DirRemove.to_string(),
            "guest dir remove failed"
        );
        assert_eq!(
            GuestErrorCode::Unknown(999).to_string(),
            "guest error (unknown code 999)"
        );
    }
}
