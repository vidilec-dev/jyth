//! Shared tests for the `rootfs` operations.
//!
//! The integration tests for each operation live in dedicated submodules so
//! they can be addressed via `cargo test -p rootfs ops::tests::<op>` (e.g.
//! `ops::tests::into_cpio`). Submodules use the in-crate helpers directly
//! because every operation's API is `pub(crate)`; shared infrastructure
//! comes from `image_core`.

mod into_cpio;
