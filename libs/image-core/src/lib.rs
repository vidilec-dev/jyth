//! Shared source-acquisition and artifact-store infrastructure for Jyth boot
//! images.
//!
//! This crate owns the pieces of the materialization pipeline that are
//! independent of any particular domain operation: the `Link` facade, the
//! source resolvers, the digest identities, the redb-backed artifact store
//! (opened per operation via the `SharedStore` adapter so the exclusive
//! index lock stays transient), and the generic
//! materialization operations (`load`, `decompress`, `flatten`, `blueprint`)
//! plus their supporting utilities (format sniffing, atomic staging IO,
//! OCI registry client, CPIO writers).
//!
//! The `image` crate builds on top of this infrastructure with the
//! kernel/rootfs domain operations and the public `Image` facade. Later
//! kernel/rootfs crates are expected to consume this crate directly.
//!
//! OCI layer digests are checked when the manifest supplies them; artifact
//! signatures are not verified by this crate.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: image-core.
//!
//! **Responsibility**: external source acquisition and artifact-store
//! infrastructure.
//!
//! **Allowed dependencies**: none (foundation crate; `kernel`, `rootfs`, and
//! `image` build on it).
//!
//! **Forbidden concepts**: VM launch, HCS state, guest commands, scheduling,
//! and boot handshake.

pub mod artifact;
pub mod digest;
pub mod http_url;
pub mod link;
pub mod materialize;
pub mod oci_reference;
pub mod ops;
pub mod resolver;
pub mod storage;
pub mod store;
pub mod timing;

pub use http_url::{HttpUrl, HttpUrlError};
pub use link::Link;
pub use oci_reference::{OciReference, OciReferenceError};
