//! Host-neutral VM specifications and outcomes.
//!
//! This crate owns the validated, host-agnostic values that describe a VM:
//! CPU and memory requests, NAT network configuration, disk specifications,
//! the immutable validated `VmConfig` aggregate, and validated boot-artifact
//! paths.
//!
//! The crate performs no I/O, has no Tokio dependency, and contains no
//! backend error type. Backends (HCS, KVM) and the runtime orchestration
//! crate consume these values across their own boundaries.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: vm-model.
//!
//! **Responsibility**: validated host-neutral VM specifications and outcomes.
//!
//! **Allowed dependencies**: none (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: HCS handles, KVM file descriptors, COM streams,
//! image stores, Tokio tasks, and process execution.

pub mod boot;
pub mod config;
pub mod cpu;
pub mod disk;
pub mod memory;
pub mod network;
pub mod path;

pub use boot::{BootArtifacts, BootArtifactsError};
pub use config::{VmConfig, VmConfigError};
pub use cpu::Cpu;
pub use disk::{
    AttachedDisk, DiskError, DiskOrigin, DiskRetention, DiskSpec, ExistingDiskPolicy, GuestMount,
};
pub use memory::Memory;
pub use network::{Nat, NatAddress, NatError};
pub use path::{PathError, normalize_lexically};
