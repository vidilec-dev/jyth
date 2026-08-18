//! Host virtualization backends for Jyth.
//!
//! The Windows Hypervisor Platform backend is the supported production path
//! for the current release. The KVM backend remains experimental and the
//! unsupported backend is used on other targets so the workspace can still be
//! compiled and documented.
//!
//! This package is the default-platform selector (SolidArchitecturePlan
//! A13): the backend implementations live in the `hypervisor-hcs` and
//! `hypervisor-kvm` crates, and this package selects the platform-
//! appropriate `Vm`. The host-neutral model surfaces (`vm-model`), the
//! backend contracts (`hypervisor-api`), and the operator admin surface
//! (`hcs-admin`) are consumed from their canonical owners.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: hypervisor.
//!
//! **Responsibility**: default platform selection and compatibility
//! forwarding.
//!
//! **Allowed dependencies**: hypervisor-api, hypervisor-hcs, hypervisor-kvm
//! (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: backend implementation logic, runtime
//! orchestration, and host-neutral model definitions.

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub(crate) mod unsupported;

/// The host-neutral backend and instance contracts, forwarded for
/// compatibility (SolidArchitecturePlan A13: the platform selector exposes
/// the shared contracts its consumers compose).
pub use hypervisor_api;

/// Error types returned by virtualization backends.
pub mod error;

#[cfg(target_os = "windows")]
pub use hypervisor_hcs::{Session, Vm};
#[cfg(target_os = "linux")]
pub use hypervisor_kvm::Vm;
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub use unsupported::Vm;
