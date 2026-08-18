//! Consumer-owned ports of the runtime launch use case.
//!
//! The launcher depends only on these contracts; the jyth facade supplies
//! concrete adapters as local newtypes (SolidArchitecturePlan WP7, WP9).
//! Ports are object-safe, `Send + Sync`, `Arc`-stored, expose explicit
//! boxed `Send` futures, and never require `Clone` on the implementation.

use std::path::PathBuf;

use error_stack::Report;
use hypervisor_api::VmInstance;
use protocol::{BootConfigV1, SessionCapability};

use crate::client::GuestClient;

// ---------------------------------------------------------------------------
// BootArtifactProvider
// ---------------------------------------------------------------------------

/// The kind of one [`BootOverlayEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootOverlayEntryKind {
    /// A regular file with resolved content bytes and permission bits.
    File {
        /// The resolved file content.
        content: Vec<u8>,
        /// The permission bits.
        mode: u32,
        /// The manifest origin: `bytes:<blake3>` or `crate:<identity>`.
        origin: String,
    },
    /// An explicit directory entry with permission bits.
    Directory {
        /// The permission bits.
        mode: u32,
    },
}

/// One host-supplied guest overlay entry, host-neutral and byte-resolved.
///
/// This mirrors the boot-image overlay entry shape so the default adapter
/// can forward the values without loss; the runtime never imports
/// boot-image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootOverlayEntry {
    /// The guest path, as supplied by the caller.
    pub path: String,
    /// The kind and resolved payload of the entry.
    pub kind: BootOverlayEntryKind,
}

/// The prepared boot artifacts of one launch: the per-run kernel and initrd
/// paths (published under the derived run cache) and the uncompressed
/// rootfs size used by the memory sizing heuristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedBootArtifacts {
    /// The published absolute kernel artifact path.
    pub kernel: PathBuf,
    /// The published absolute initrd artifact path.
    pub initrd: PathBuf,
    /// The uncompressed size of the initramfs rootfs in bytes.
    pub uncompressed_rootfs_size: u64,
}

/// A boxed boot-artifact preparation future (object-safe contract boundary).
pub type ArtifactFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<PreparedBootArtifacts, Report<ArtifactError>>>
            + Send
            + 'static,
    >,
>;

/// Failures preparing or retrieving deterministic boot artifacts.
///
/// The category is stable (everything maps to the runtime `Build` error);
/// the message carries the diagnostic text of the assembly or cache failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("boot artifact preparation failed: {message}")]
pub struct ArtifactError {
    /// Human-readable diagnostics (never parsed by consumers).
    pub message: String,
}

impl ArtifactError {
    /// Build an artifact failure from its diagnostic text.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Prepare or retrieve deterministic boot artifacts for one launch.
///
/// Inputs are validated and immutable for the operation. Preparation returns
/// atomically published artifacts whose identity covers every effective
/// input; failure leaves no visible partial cache entry.
pub trait BootArtifactProvider: Send + Sync + 'static {
    /// Assemble and publish the per-run kernel and initrd artifacts.
    fn prepare(
        &self,
        kernel_source: PathBuf,
        rootfs_source: PathBuf,
        overlay_entries: Vec<BootOverlayEntry>,
    ) -> ArtifactFuture;
}

// ---------------------------------------------------------------------------
// BootControlChannel
// ---------------------------------------------------------------------------

/// A boxed READY exchange future (object-safe contract boundary).
pub type ReadyFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), BootChannelError>> + Send + 'static>,
>;

/// The stable category of a boot-channel failure.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BootChannelErrorKind {
    /// The exchange timed out (connect, marker, frame, or READY wait).
    Timeout,
    /// A frame or value violated the boot protocol.
    Protocol,
    /// The authenticated READY proof failed verification.
    Authentication,
}

/// Failures of the bounded boot-configuration exchange and authenticated
/// READY verification. The kind is the decision surface; the message carries
/// the exchange diagnostics (never parsed by consumers).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct BootChannelError {
    /// The stable category.
    pub kind: BootChannelErrorKind,
    /// Human-readable diagnostics (never parsed by consumers).
    pub message: String,
}

impl BootChannelError {
    /// Build a boot-channel failure from its stable parts.
    pub fn new(kind: BootChannelErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// A timed-out exchange with diagnostics.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(BootChannelErrorKind::Timeout, message)
    }

    /// A protocol violation with diagnostics.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(BootChannelErrorKind::Protocol, message)
    }

    /// A failed READY authentication with diagnostics.
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::new(BootChannelErrorKind::Authentication, message)
    }
}

/// Send the bounded versioned boot configuration over the protected boot
/// endpoint and await the authenticated READY proof.
///
/// The call returns only after bounded configuration exchange and
/// authenticated READY verification; failure does not publish the VM and
/// does not expose secret proof material. The implementation reaches the
/// concrete backend through [`hypervisor_api::VmInstance::as_any`], so the
/// runtime never imports a concrete backend or a named pipe.
pub trait BootControlChannel: Send + Sync + 'static {
    /// Exchange the boot configuration and verify the guest READY proof.
    fn exchange_ready(
        &self,
        instance: &dyn VmInstance,
        boot_config: &BootConfigV1,
        timeout: std::time::Duration,
    ) -> ReadyFuture;
}

// ---------------------------------------------------------------------------
// GuestClientFactory
// ---------------------------------------------------------------------------

/// The host-neutral command endpoint of one live VM: the TCP socket address
/// the guest binds and the host connects to for command traffic.
///
/// The endpoint is derived from the validated launch `Nat` and
/// [`protocol::COMMAND_PORT`]; it contains no capability material and is
/// never discovered from an unauthenticated network response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandEndpoint {
    address: std::net::SocketAddr,
}

impl CommandEndpoint {
    /// The effective TCP socket address of the command endpoint.
    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }
}

impl From<&vm_model::network::Nat> for CommandEndpoint {
    /// Derive the command endpoint from the validated NAT configuration.
    fn from(nat: &vm_model::network::Nat) -> Self {
        Self {
            address: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                nat.guest_ip(),
                protocol::COMMAND_PORT,
            )),
        }
    }
}

/// A boxed guest-client creation future (object-safe contract boundary).
pub type ClientFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<GuestClient, ClientError>> + Send + 'static>,
>;

/// Failures creating the typed guest client.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The guest command transport is unavailable.
    #[error("the guest command transport is unavailable")]
    Unavailable,
    /// Client construction failed after the READY exchange.
    #[error("failed to create the guest client")]
    Create,
}

/// Create one typed guest client after authenticated READY.
///
/// Creation returns one usable typed guest client for the live VM, or a
/// typed failure that leaves no dispatcher task or guest process behind and
/// causes ordered VM cleanup.
pub trait GuestClientFactory: Send + Sync + 'static {
    /// Create the guest client over the authenticated command endpoint.
    fn create(
        &self,
        instance: &dyn VmInstance,
        capability: &SessionCapability,
        command_endpoint: CommandEndpoint,
    ) -> ClientFuture;
}
