//! Validated kernel specification values.
//!
//! The `kernel` crate validates every textual value at construction time,
//! before any asynchronous materialization begins:
//!
//! - [`path::KernelPath`] validates and normalizes kernel-entry paths;
//! - [`version::KernelVersion`] validates exact kernel release versions;
//! - [`config::KernelConfig`] validates and canonicalizes Kconfig fragments
//!   and complete `.config` files.

pub mod config;
pub mod path;
pub mod version;
