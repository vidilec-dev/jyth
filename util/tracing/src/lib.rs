//! Tracing facade for the Jyth workspace.
//!
//! Re-exports the [`crates.io tracing`](https://docs.rs/tracing) API surface
//! and provides [`init`] as the single workspace-wide subscriber setup: a
//! formatting subscriber filtered by `RUST_LOG` (via `EnvFilter`).
//!
//! Crates depend on this facade instead of `tracing` directly so the
//! workspace can pin one tracing/subscriber pair without repeating the
//! initialization dance in every binary.

/// Initialize the workspace tracing subscriber from `RUST_LOG`.
///
/// Installs a `fmt` subscriber whose filter is derived from the standard
/// `RUST_LOG` environment variable. Failures are ignored (`.ok()`): a
/// subscriber that is already installed — for example by a test harness or
/// an embedding process — is left untouched.
pub fn init() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
}

pub use cratesio_tracing::*;
