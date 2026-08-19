#![deny(missing_docs)]
//! Host-side VM application lifecycle orchestration.
//!
//! This crate owns the launch and shutdown orchestration of a Jyth VM as an
//! application service with injected ports (SolidArchitecturePlan A5, WP7):
//!
//! - [`Launcher`] drives the target launch flow: validate, prepare boot
//!   artifacts through a [`BootArtifactProvider`], validate backend
//!   capabilities, create and start the instance through
//!   [`hypervisor_api::VmFactory`], exchange the authenticated READY proof
//!   through a [`BootControlChannel`], mark the instance published, create
//!   the typed guest client through a [`GuestClientFactory`], attach
//!   scheduled actions, and return a [`LiveVm`].
//! - [`LiveVm`] owns the running instance, the guest client, the dispatcher
//!   lifecycle, the scheduler handle, and the lifecycle observers; its
//!   consuming [`shutdown`](LiveVm::shutdown) implements the ordered
//!   shutdown flow and its `Drop` fallback retains synchronous best-effort
//!   cleanup.
//!
//! The crate depends only on contracts and generic services (`vm-model`,
//! `hypervisor-api`, `scheduler`, `guest-client`, `protocol`). It never
//! imports HCS, KVM, COM, image, boot-image, or the jyth facade, never opens
//! a socket, and never inspects backend error text (retry decisions use
//! [`hypervisor_api::RetryDisposition`] only).
//!
//! Allowed dependencies: `vm-model`, `hypervisor-api`, `scheduler`,
//! `guest-client`, `protocol`.
//!
//! Forbidden dependencies: `hypervisor-hcs`, `hypervisor-kvm`,
//! `hypervisor`, `image`, `boot-image`, `com`, `jyth`.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: jyth-runtime.
//!
//! **Responsibility**: host-side VM application lifecycle orchestration.
//!
//! **Allowed dependencies**: vm-model, hypervisor-api, scheduler,
//! guest-client, protocol (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: concrete HCS calls, concrete KVM calls, redb
//! schemas, reqwest clients, and socket implementations.

mod actions;
pub mod client;
mod error;
mod launch;
mod live_vm;
mod observer;
mod ports;

pub use actions::ScheduledProcess;
pub use client::GuestClient;
pub use error::{RuntimeError, map_client_error};
pub use launch::{Launch, LaunchRequest, Launcher, PreparedLaunch, READY_TIMEOUT, RetryPolicy};
pub use live_vm::{LiveVm, VmWarning};
pub use observer::{VmFailure, VmFinish, VmLifecycle, VmObserver, VmPhase, VmState};
pub use ports::{
    ArtifactError, ArtifactFuture, BootArtifactProvider, BootChannelError, BootControlChannel,
    BootOverlayEntry, BootOverlayEntryKind, ClientError, ClientFuture, CommandEndpoint,
    GuestClientFactory, PreparedBootArtifacts, ReadyFuture,
};

/// The canonical result type of the runtime orchestration services.
pub type RuntimeResult<T> = Result<T, error_stack::Report<RuntimeError>>;
