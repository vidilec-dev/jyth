//! Typed host-to-guest file and process operations over a transport contract.
//!
//! The guest-client crate owns the guest command boundary of a live VM:
//! request/reply correlation over a consumer-owned [`CommandTransport`] port,
//! typed file and directory operations, prepared guest process execution,
//! output routing and capture, process observers, and running-process
//! lifecycle (wait, close, bind, drop cleanup).
//!
//! The crate accepts only *prepared* guest executable paths or shell
//! commands. It never compiles Rust crates, never materializes executable
//! bytes into a guest filesystem, and never creates or closes a host VM; the
//! Jyth facade owns those responsibilities and maps its public process values
//! into [`PreparedProcess`] values before calling [`run_direct_process`].
//!
//! The only workspace dependency is `protocol`; concrete socket adapters
//! (e.g. `com::TcpEndpoint`) are supplied by the composition root as local
//! newtypes implementing the ports in this crate.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: guest-client.
//!
//! **Responsibility**: typed guest file and process operations over a
//! transport contract.
//!
//! **Allowed dependencies**: protocol (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: VM creation, HCS cleanup, OCI access, boot-image
//! assembly, and scheduler graph policy.

pub mod cleanup;
pub mod client;
pub mod direct;
pub mod error;
pub mod files;
pub mod process;
pub mod transport;

pub use cleanup::CleanupTasks;
pub use client::{Client, REQUEST_TIMEOUT, request_expect};
pub use direct::run_direct_process;
pub use error::GuestClientError;
pub use files::{DirListing, GuestFiles};
pub use process::{
    CaptureEnd, CaptureOptions, CaptureOverflowPolicy, DEFAULT_CAPTURE_LIMIT, MAX_CAPTURE_LIMIT,
    Output, OutputStream, PreparedProcess, PreparedProcessBuilder, ProcessError, ProcessExit,
    ProcessLifecycle, ProcessObserver, ProcessState, RunningProcess,
};
pub use transport::{
    CommandTransport, Dispatcher, HostRequest, MAX_IN_FLIGHT_HOST_REQUESTS,
    MAX_IN_FLIGHT_PROCESS_WAITS, ProcessStream, StreamFuture, StreamTransport, TransportFuture,
};

/// Shared test doubles for the fake-transport contract tests. Compiled only
/// under `cfg(test)`; production code never references it.
#[cfg(test)]
pub(crate) mod support;
