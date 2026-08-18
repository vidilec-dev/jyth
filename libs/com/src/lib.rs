//! Host-to-guest command transport over TCP (TcpTransportMigrationPlan).
//!
//! The crate exposes blocking and Tokio-compatible streams plus framed
//! command/event helpers. Transport failures are returned as
//! [`error_stack::Report`] values rooted at [`TransportError`].
//!
//! Internal layout: `connector` creates the TCP connection to the guest
//! command endpoint, `auth` performs the mandatory challenge/MAC exchange
//! before any command decoding, `framing` is the one shared frame codec
//! used by both adapters, `sync` and `async` are the blocking and Tokio
//! socket adapters, and `rpc` provides the command/event helpers. This
//! module is only the module declarations and the public re-export surface.
//!
//! # Responsibility (SolidArchitecturePlan target catalog)
//!
//! **Owner**: com.
//!
//! **Responsibility**: authenticated host transport.
//!
//! **Allowed dependencies**: protocol (enforced by `tests/architecture`).
//!
//! **Forbidden concepts**: VM lifecycle, guest process policy, image
//! caching, HCS ownership, and scheduling.

mod r#async;
mod auth;
mod connector;
mod error;
mod framing;
mod rpc;
mod sync;
#[cfg(test)]
mod test_support;

pub use r#async::AsyncStream;
pub use connector::TcpEndpoint;
pub use error::{TransportError, TransportResult};
pub use sync::Stream;
