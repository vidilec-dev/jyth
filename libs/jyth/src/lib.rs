//! Build and run Linux guest workloads through Jyth's image and VM APIs.
//!
//! The current supported release boundary is Windows with Hyper-V/HCS. Image
//! acquisition, overlay construction, guest command transport, process
//! lifecycle, and platform diagnostics are exposed through the re-exports and
//! modules below.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: the public Jyth product boundary.
//!
//! **Responsibility**: present the public API and compose default adapters —
//! public builders, compatibility wrappers, public re-exports, platform
//! policy, default service construction, and error-context translation.
//!
//! **Allowed dependencies**: vm-model, protocol, jyth-runtime, scheduler,
//! guest-client, image-core, boot-image, hypervisor, com (enforced by
//! `tests/architecture`).
//!
//! **Forbidden concepts**: scheduling algorithms (scheduler crate), HCS
//! journaling (hypervisor-hcs), image-index transactions (image-core), frame
//! codecs (protocol/com), guest process internals (guest-client), boot
//! artifact assembly (boot-image), and host lifecycle orchestration
//! (jyth-runtime). This crate contains no infrastructure transaction, no
//! scheduling algorithm, and no transport codec; it selects the platform
//! backend and composes the concrete adapters defined in
//! `crate::adapters::runtime`.

// The materialization pipeline's async state machines (kernel/rootfs ops,
// overlay crate builds, bounded joins) nest deeply enough — with the
// `profiling` `instrument` spans on top — to exceed rustc's default type
// layout recursion limit when the custom-kernel compiler chain is laid out.
#![recursion_limit = "256"]

pub(crate) mod adapters;
pub(crate) mod build;
mod error;
pub mod kernel_build;
pub mod platform;

/// Declarative VM and initramfs builder APIs.
pub mod builder;
/// VM lifecycle, guest file, and process APIs.
pub mod vm;

/// Public VM builder name used by the lifecycle-oriented API.
pub use crate::builder::{BootstrapSpec, BootstrapTimings, On, RustBinary, VmBuilder};
pub use crate::error::{ApiError, ApiResult};
pub use crate::platform::{
    HostPlatform, PlatformInfo, PlatformSupport, SUPPORT_MATRIX, ensure_supported_platform,
};
pub use crate::vm::{
    PORT_FORWARD_PRIMING_BYTES, Process, ProcessBuilder, ProcessError, ProcessExit,
    ProcessObserver, RunningProcess, RunningProcessBuilder, VM, VmFailure, VmFinish, VmObserver,
    VmPhase, VmState, VmWarning,
};
/// Public disk configuration and disposition types (host-agnostic; the
/// HCS backend materializes them).
pub use vm_model::disk::{
    AttachedDisk, DiskError, DiskOrigin, DiskRetention, DiskSpec, ExistingDiskPolicy, GuestMount,
};
/// Public validated NAT network configuration (host-agnostic).
pub use vm_model::network::Nat;

pub use com::{AsyncStream, Stream};
