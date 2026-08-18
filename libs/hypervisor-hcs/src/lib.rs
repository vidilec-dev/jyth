//! The Windows/HCS hypervisor backend (SolidArchitecturePlan A11).
//!
//! This crate owns the supported production backend of the Jyth runtime:
//! HCS configuration, HNS lifecycle, secured named pipes, disk
//! materialization, the durable journaled ownership record, publication,
//! recovery, and exact cleanup. It is the single owner of the provisioning
//! saga that keeps journal intent and result ordering explicit.
//!
//! The crate compiles to an empty library on non-Windows targets; the
//! backend is selected by the `hypervisor` package.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: hypervisor-hcs.
//!
//! **Responsibility**: journaled Windows/HCS VM lifecycle.
//!
//! **Allowed dependencies**: hypervisor-api, vm-model (enforced by
//! `tests/architecture`).
//!
//! **Forbidden concepts**: public Jyth builders, guest process APIs, image
//! sources, and scheduler policies.

#![cfg(target_os = "windows")]

pub mod conf;
pub mod console;
pub mod core;
pub mod cs;
pub mod error;
pub mod ext;
pub mod hns;
pub mod hyperv;
pub mod journal;
pub mod operation;
pub mod security;
pub mod vm;

pub use vm::{Session, Vm};
