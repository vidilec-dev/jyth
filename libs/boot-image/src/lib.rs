//! Deterministic guest boot-artifact assembly from prepared inputs.
//!
//! This crate owns the deterministic host-side assembly of guest boot
//! artifacts: guest overlay path validation, overlay conflict detection,
//! init binary compilation, CPIO overlay construction, derived run-cache
//! identity and metadata, and atomic kernel and initrd publication.
//!
//! It consumes only *prepared* inputs: a materialized kernel path, a
//! complete base rootfs CPIO path, and validated overlay entries with
//! resolved content bytes. External acquisition (OCI, HTTP, local, and
//! byte sources) is owned by the `image` crate; host-side process
//! executable compilation and the public builder facade are owned by
//! `jyth`; the live VM lifecycle is owned by the runtime crates.
//!
//! Allowed dependencies: `vm-model`.
//!
//! Forbidden dependencies: `jyth`, `image`, `protocol`, `hypervisor`,
//! `com`, and any OCI access, HCS creation, COM authentication, live guest
//! command, or process scheduling behavior.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: boot-image.
//!
//! **Responsibility**: deterministic guest boot-artifact assembly.
//!
//! **Allowed dependencies**: vm-model (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: OCI access, HCS creation, COM authentication,
//! live guest commands, and process scheduling.

pub mod assembly;
pub mod cache;
pub mod init;
pub mod overlay;

use std::path::PathBuf;

pub use crate::assembly::{PreparedBootArtifacts, prepare_boot_artifacts};
pub use crate::overlay::{GuestOverlayEntry, OverlayEntryKind};

/// Why a guest path could not be represented as a canonical overlay entry.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestPathReason {
    /// The path is not valid UTF-8.
    #[error("the path is not valid UTF-8")]
    NonRepresentable,
    /// The path contains a NUL byte.
    #[error("the path contains a NUL byte")]
    NulByte,
    /// The path uses a Windows prefix.
    #[error("the path uses a Windows prefix")]
    WindowsPrefix,
    /// The path contains parent traversal (`..`).
    #[error("the path contains parent traversal (`..`)")]
    ParentTraversal,
    /// The path contains an empty component.
    #[error("the path contains an empty component")]
    EmptyComponent,
    /// The path has no terminal name.
    #[error("the path has no terminal name")]
    EmptyTerminalName,
    /// The path is too long for a newc CPIO entry.
    #[error("the path is too long for a newc CPIO entry")]
    TooLong,
}

/// Failures assembling deterministic guest boot artifacts.
///
/// The variant set and messages mirror the historical Jyth build-stage
/// error contract: the `jyth` facade maps these onto its stable public
/// error contexts without losing context.
#[derive(Debug, thiserror::Error)]
pub enum BootImageError {
    /// An overlay entry path is not a valid guest path.
    #[error("invalid guest path {path:?}: {reason}")]
    InvalidGuestPath {
        /// The offending path as supplied by the caller.
        path: String,
        /// Why the path was rejected.
        reason: GuestPathReason,
    },
    /// An overlay entry path is not a valid host path.
    #[error("invalid host path {path:?}")]
    InvalidHostPath {
        /// The offending path as supplied by the caller.
        path: PathBuf,
    },

    /// The same guest path was registered twice with the same kind.
    #[error("duplicate overlay path {path:?}")]
    DuplicateOverlayPath {
        /// The duplicated guest path.
        path: String,
    },
    /// The same guest path was registered twice with conflicting kinds.
    #[error("overlay path conflict at {path:?}: {conflict}")]
    OverlayPathConflict {
        /// The conflicting guest path.
        path: String,
        /// A description of the conflict.
        conflict: String,
    },
    /// An overlay entry used a path reserved for boot-artifact machinery.
    #[error("reserved overlay path {path:?}")]
    ReservedOverlayPath {
        /// The reserved guest path.
        path: String,
    },
    /// An overlay entry carried no path.
    #[error("overlay {kind} has no path")]
    MissingOverlayPath {
        /// The kind of the entry (`file` or `directory`).
        kind: &'static str,
    },
    /// Overlay validation, CPIO assembly, or the overlay cache failed.
    #[error("failed to build the guest overlay")]
    Overlay,
    /// The derived boot cache could not be accessed.
    #[error("failed to access the derived boot cache")]
    Cache,
    /// The guest init binary could not be compiled.
    #[error("failed to build the guest init binary")]
    InitBuild,
    /// The initrd could not be assembled.
    #[error("failed to assemble the initrd")]
    Initrd,
}
