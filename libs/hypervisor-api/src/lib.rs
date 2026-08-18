//! Host-neutral backend and instance contracts (SolidArchitecturePlan A10).
//!
//! This crate owns the backend lifecycle contracts shared by runtime and
//! adapter crates:
//!
//! - [`VmFactory`] is the creation and capability contract;
//! - [`VmInstance`] is the started-instance lifecycle contract;
//! - [`BackendCapabilities`] lets a backend advertise only implemented
//!   capabilities;
//! - [`BackendError`] is the stable backend report boundary (no high-level
//!   crate may inspect backend error strings);
//! - [`RetryDisposition`] is typed backend information for retry policy.
//!
//! The crate contains no concrete backend, no I/O, and no HCS/KVM types.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: hypervisor-api.
//!
//! **Responsibility**: host-neutral backend and instance contracts.
//!
//! **Allowed dependencies**: vm-model (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: HCS APIs, KVM ioctls, PowerShell, redb schemas,
//! COM framing, and image materialization.

mod backend;

pub use backend::{
    AttachedResource, BackendCapabilities, BackendError, BackendErrorCategory, RetryDisposition,
    VmFactory, VmInstance, VmLaunchSpec, create_future,
};

/// A boxed creation future (object-safe contract boundary).
pub type CreateFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<Box<dyn VmInstance>, BackendError>>
            + Send
            + 'static,
    >,
>;

/// A boxed start future (object-safe contract boundary).
pub type StartFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'static>>;

/// A boxed publication future (object-safe contract boundary).
pub type PublishFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'static>>;

/// A boxed consuming close future (object-safe contract boundary).
pub type CloseFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BackendError>> + Send + 'static>>;
