//! Versioned control-plane messages and HMAC-SHA-256 authentication.
//!
//! The command protocol continues to use rkyv for command/event payloads.
//! Boot and authentication messages use a small explicit binary encoding so
//! their bounds and transcript bytes remain stable across host and guest
//! builds. Secrets intentionally have redacted `Debug` implementations and
//! zero their owned storage when dropped.

use crate::{ProtocolError, ProtocolResult};
use error_stack::Report;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

/// Version of the boot and command authentication envelopes.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum serialized COM1 boot configuration frame.
pub const MAX_BOOT_CONFIG_FRAME: usize = 64 * 1024;
/// Maximum serialized authentication frame.
pub const MAX_AUTH_FRAME: usize = 4 * 1024;
/// Maximum serialized command/event frame.
pub const MAX_COMMAND_FRAME: usize = 16 * 1024 * 1024;
/// Maximum size of one COM1 bootstrap artifact chunk.
pub const MAX_BOOTSTRAP_CHUNK: usize = 64 * 1024;
/// Maximum artifact size accepted by the COM1 bootstrap stream.
pub const MAX_BOOTSTRAP_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
/// Maximum number of guest command connections admitted by the release
/// protocol. The guest dispatcher may apply this limit independently.
pub const MAX_GUEST_CONNECTIONS: usize = 32;
/// Authentication deadline used by the host transport and guest contract.
pub const AUTHENTICATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

const CAPABILITY_LEN: usize = 32;
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
const MAX_DNS_SERVERS: usize = 16;
const MAX_DISKS: usize = 64;
const MAX_MOUNT_PATH_BYTES: usize = 4096;
const MAX_BOOTSTRAP_ARGS: usize = 16;
const MAX_BOOTSTRAP_STRING_BYTES: usize = 4096;

const BOOT_CONFIG_TAG: u8 = 0x10;
const READY_TAG: u8 = 0x11;
const BOOTSTRAP_RESULT_TAG: u8 = 0x12;
const AUTH_CHALLENGE_TAG: u8 = 0x20;
const AUTH_RESPONSE_TAG: u8 = 0x21;
const AUTH_ACCEPTED_TAG: u8 = 0x22;

const BOOT_DOMAIN: &[u8] = b"jyth/boot-ready/v1\0";
const CHALLENGE_DOMAIN: &[u8] = b"jyth/auth-challenge/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"jyth/auth-response/v1\0";

/// Transport-neutral V1 authentication context, included in every
/// per-connection proof transcript.
///
/// The bytes are the former HvSocket command-service identifier retained
/// unchanged for this migration. They are now an opaque V1 domain separator
/// rather than a service GUID: HCS no longer interprets them. The value is
/// immutable for protocol V1; a later protocol-version plan decides whether
/// to replace it.
pub const COMMAND_AUTH_CONTEXT_V1: &[u8] = b"00000400-FACB-11E6-BD58-64006A7986D3";

/// A per-VM capability shared only by the host and the guest init process.
///
/// This type deliberately does not implement `Copy`, and its `Debug` output
/// is redacted. Use `Arc<SessionCapability>` when sharing it across host
/// transport handles instead of copying its bytes through unrelated APIs.
pub struct SessionCapability {
    bytes: [u8; CAPABILITY_LEN],
}

impl SessionCapability {
    /// Generate a capability using the operating system CSPRNG.
    pub fn generate() -> ProtocolResult<Self> {
        let mut bytes = [0u8; CAPABILITY_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|error| Report::new(ProtocolError::Randomness).attach(error.to_string()))?;
        Ok(Self { bytes })
    }

    /// Construct a capability from exactly 32 bytes received from the secure
    /// COM1 boot exchange.
    pub fn from_bytes(bytes: [u8; CAPABILITY_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the capability for a cryptographic operation or wire encoding.
    pub fn as_bytes(&self) -> &[u8; CAPABILITY_LEN] {
        &self.bytes
    }
}

impl Clone for SessionCapability {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes }
    }
}

impl std::fmt::Debug for SessionCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionCapability(REDACTED)")
    }
}

impl Drop for SessionCapability {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A validated IPv4 guest network configuration carried over COM1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestNetworkConfigV1 {
    /// IPv4 address assigned to the guest NIC.
    pub guest_ip: [u8; 4],
    /// IPv4 gateway used for the guest default route.
    pub gateway: [u8; 4],
    /// CIDR prefix length for the guest address.
    pub prefix_len: u8,
    /// IPv4 DNS servers written to the guest resolver configuration.
    pub dns: Vec<[u8; 4]>,
}

impl GuestNetworkConfigV1 {
    /// Build and validate a guest network configuration.
    pub fn new(
        guest_ip: [u8; 4],
        gateway: [u8; 4],
        prefix_len: u8,
        dns: Vec<[u8; 4]>,
    ) -> ProtocolResult<Self> {
        let config = Self {
            guest_ip,
            gateway,
            prefix_len,
            dns,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> ProtocolResult<()> {
        if !(1..=32).contains(&self.prefix_len) {
            return Err(invalid_value("IPv4 prefix length must be between 1 and 32"));
        }
        if self.guest_ip == self.gateway {
            return Err(invalid_value("guest IP and gateway must differ"));
        }
        let mask = if self.prefix_len == 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - u32::from(self.prefix_len))
        };
        if ipv4_u32(self.guest_ip) & mask != ipv4_u32(self.gateway) & mask {
            return Err(invalid_value("guest IP and gateway must share a subnet"));
        }
        if self.dns.len() > MAX_DNS_SERVERS {
            return Err(invalid_value("too many DNS servers"));
        }
        Ok(())
    }
}

/// One host-attached disk mount instruction carried over COM1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestDiskConfigV1 {
    /// Zero-based SCSI disk index; index zero maps to `/dev/sda`.
    pub device_index: u16,
    /// Absolute guest mount path.
    pub mount_path: String,
    /// Whether the guest may initialize the newly-created disk.
    pub initialize: bool,
}

impl GuestDiskConfigV1 {
    /// Construct and validate a disk mount instruction.
    pub fn new(
        device_index: u16,
        mount_path: impl Into<String>,
        initialize: bool,
    ) -> ProtocolResult<Self> {
        let config = Self {
            device_index,
            mount_path: mount_path.into(),
            initialize,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> ProtocolResult<()> {
        if self.mount_path.is_empty()
            || !self.mount_path.starts_with('/')
            || self.mount_path.as_bytes().contains(&0)
            || self.mount_path.len() > MAX_MOUNT_PATH_BYTES
        {
            return Err(invalid_value(
                "disk mount path must be a bounded absolute path",
            ));
        }
        Ok(())
    }
}

/// Command and artifact paths used by the COM1-only bootstrap mode.
///
/// The command is executed directly, never through a shell selected by the
/// protocol. Its arguments and the artifact path are carried inside the
/// authenticated boot transcript, so the guest can run a narrowly-scoped
/// bootstrap operation without opening a TCP command listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapConfigV1 {
    /// Absolute guest path of the executable to run.
    pub program: String,
    /// Arguments passed directly to `program`.
    pub args: Vec<String>,
    /// Absolute guest path of the artifact to stream after success.
    pub artifact: String,
}

impl BootstrapConfigV1 {
    /// Build and validate a COM1 bootstrap command description.
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        artifact: impl Into<String>,
    ) -> ProtocolResult<Self> {
        let config = Self {
            program: program.into(),
            args,
            artifact: artifact.into(),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> ProtocolResult<()> {
        validate_bootstrap_path(&self.program, "bootstrap program")?;
        validate_bootstrap_path(&self.artifact, "bootstrap artifact")?;
        if self.args.len() > MAX_BOOTSTRAP_ARGS {
            return Err(invalid_value("too many bootstrap arguments"));
        }
        for argument in &self.args {
            if argument.as_bytes().contains(&0) {
                return Err(invalid_value("bootstrap argument contains a NUL byte"));
            }
            if argument.len() > MAX_BOOTSTRAP_STRING_BYTES {
                return Err(invalid_value("bootstrap argument exceeds its size limit"));
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        2 + self.program.len()
            + 1
            + self
                .args
                .iter()
                .map(|argument| 2 + argument.len())
                .sum::<usize>()
            + 2
            + self.artifact.len()
    }
}

fn validate_bootstrap_path(path: &str, label: &str) -> ProtocolResult<()> {
    if path.is_empty()
        || !path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path.len() > MAX_BOOTSTRAP_STRING_BYTES
        || path.split('/').any(|component| component == "..")
    {
        return Err(invalid_value(label));
    }
    Ok(())
}

/// Result metadata sent before a COM1 bootstrap artifact stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapResultV1 {
    /// Envelope version.
    pub version: u16,
    /// `0` means success, `1` means the command failed, and `2` means the
    /// command succeeded but the artifact could not be read.
    pub status: u8,
    /// Process exit code when the command returned one.
    pub exit_code: Option<u32>,
    /// Number of artifact bytes that follow on success.
    pub artifact_len: u64,
    /// BLAKE3 digest of the artifact bytes that follow on success.
    pub artifact_digest: [u8; 32],
}

impl BootstrapResultV1 {
    /// Status indicating that the artifact stream follows.
    pub const SUCCESS: u8 = 0;
    /// Status indicating that the bootstrap command returned unsuccessfully.
    pub const COMMAND_FAILED: u8 = 1;
    /// Status indicating that the command succeeded but the artifact was not readable.
    pub const ARTIFACT_UNAVAILABLE: u8 = 2;

    /// Construct a successful result after validating the artifact bounds.
    pub fn success(artifact_len: u64, artifact_digest: [u8; 32]) -> ProtocolResult<Self> {
        let result = Self {
            version: PROTOCOL_VERSION,
            status: Self::SUCCESS,
            exit_code: Some(0),
            artifact_len,
            artifact_digest,
        };
        result.validate()?;
        Ok(result)
    }

    /// Construct a failed-command result.
    pub fn command_failed(exit_code: Option<u32>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: Self::COMMAND_FAILED,
            exit_code,
            artifact_len: 0,
            artifact_digest: [0; 32],
        }
    }

    /// Construct an artifact-read failure result.
    pub fn artifact_unavailable() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: Self::ARTIFACT_UNAVAILABLE,
            exit_code: Some(0),
            artifact_len: 0,
            artifact_digest: [0; 32],
        }
    }

    fn validate(&self) -> ProtocolResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        if !matches!(
            self.status,
            Self::SUCCESS | Self::COMMAND_FAILED | Self::ARTIFACT_UNAVAILABLE
        ) {
            return Err(invalid_value("invalid bootstrap result status"));
        }
        if self.status == Self::SUCCESS {
            if self.artifact_len == 0 || self.artifact_len > MAX_BOOTSTRAP_ARTIFACT_BYTES {
                return Err(invalid_value(
                    "bootstrap artifact size is outside its bounds",
                ));
            }
            if self.exit_code != Some(0) {
                return Err(invalid_value(
                    "successful bootstrap result has a nonzero exit code",
                ));
            }
        } else if self.artifact_len != 0 || self.artifact_digest != [0; 32] {
            return Err(invalid_value(
                "failed bootstrap result unexpectedly contains artifact metadata",
            ));
        }
        Ok(())
    }

    /// Serialize the result envelope.
    pub fn to_bytes(self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut writer = WireWriter::with_capacity(1 + 2 + 1 + 4 + 8 + 32);
        writer.push_u8(BOOTSTRAP_RESULT_TAG);
        writer.push_u16(self.version);
        writer.push_u8(self.status);
        writer.push_u32(self.exit_code.unwrap_or(u32::MAX));
        writer.push_u64(self.artifact_len);
        writer.push_bytes(&self.artifact_digest);
        writer.finish(MAX_AUTH_FRAME)
    }
}

impl TryFrom<&[u8]> for BootstrapResultV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_AUTH_FRAME {
            return Err(invalid_frame("bootstrap result exceeds its frame limit"));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != BOOTSTRAP_RESULT_TAG {
            return Err(invalid_frame("unexpected bootstrap result tag"));
        }
        let version = reader.take_u16()?;
        let status = reader.take_u8()?;
        let encoded_exit_code = reader.take_u32()?;
        let exit_code = (encoded_exit_code != u32::MAX).then_some(encoded_exit_code);
        let result = Self {
            version,
            status,
            exit_code,
            artifact_len: reader.take_u64()?,
            artifact_digest: reader.take_array::<32>()?,
        };
        reader.finish()?;
        result.validate()?;
        Ok(result)
    }
}

/// Versioned host-to-guest COM1 bootstrap message.
pub struct BootConfigV1 {
    /// Envelope version.
    pub version: u16,
    /// VM identity used by the command endpoint and all authentication proofs.
    pub vm_id: Uuid,
    /// Capability used for READY and per-connection HMAC proofs.
    pub capability: SessionCapability,
    /// Fresh host nonce included in the READY transcript.
    pub host_nonce: [u8; NONCE_LEN],
    /// Optional validated guest network configuration.
    pub network: Option<GuestNetworkConfigV1>,
    /// Ordered disk mount instructions.
    pub disks: Vec<GuestDiskConfigV1>,
    /// Optional authenticated COM1-only bootstrap command.
    pub bootstrap: Option<BootstrapConfigV1>,
}

impl std::fmt::Debug for BootConfigV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BootConfigV1")
            .field("version", &self.version)
            .field("vm_id", &self.vm_id)
            .field("capability", &"REDACTED")
            .field("host_nonce", &"REDACTED")
            .field("network", &self.network)
            .field("disks", &self.disks)
            .field("bootstrap", &self.bootstrap)
            .finish()
    }
}

impl BootConfigV1 {
    /// Construct a version-one bootstrap message and validate all fields.
    pub fn new(
        vm_id: Uuid,
        capability: SessionCapability,
        host_nonce: [u8; NONCE_LEN],
        network: Option<GuestNetworkConfigV1>,
        disks: Vec<GuestDiskConfigV1>,
    ) -> ProtocolResult<Self> {
        let config = Self {
            version: PROTOCOL_VERSION,
            vm_id,
            capability,
            host_nonce,
            network,
            disks,
            bootstrap: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Add a COM1-only bootstrap command to this boot configuration.
    pub fn with_bootstrap(mut self, bootstrap: BootstrapConfigV1) -> ProtocolResult<Self> {
        self.bootstrap = Some(bootstrap);
        self.validate()?;
        Ok(self)
    }

    /// Generate a fresh non-secret host nonce.
    pub fn generate_host_nonce() -> ProtocolResult<[u8; NONCE_LEN]> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|error| Report::new(ProtocolError::Randomness).attach(error.to_string()))?;
        Ok(nonce)
    }

    /// Serialize the bootstrap message to its bounded wire representation.
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        let encoded_len = self.encoded_len();
        if encoded_len > MAX_BOOT_CONFIG_FRAME {
            return Err(invalid_frame(
                "encoded boot configuration exceeds its frame limit",
            ));
        }
        let mut writer = WireWriter::with_capacity(encoded_len);
        writer.push_u8(BOOT_CONFIG_TAG);
        writer.push_u16(self.version);
        writer.push_bytes(self.vm_id.as_bytes());
        writer.push_bytes(self.capability.as_bytes());
        writer.push_bytes(&self.host_nonce);
        match &self.network {
            Some(network) => {
                writer.push_u8(1);
                writer.push_bytes(&network.guest_ip);
                writer.push_bytes(&network.gateway);
                writer.push_u8(network.prefix_len);
                writer.push_u8(u8::try_from(network.dns.len()).expect("DNS count is bounded"));
                for dns in &network.dns {
                    writer.push_bytes(dns);
                }
            }
            None => writer.push_u8(0),
        }
        writer.push_u16(u16::try_from(self.disks.len()).expect("disk count is bounded"));
        for disk in &self.disks {
            writer.push_u16(disk.device_index);
            writer.push_u8(u8::from(disk.initialize));
            writer.push_u16(
                u16::try_from(disk.mount_path.len()).expect("mount path is bounded below u16"),
            );
            writer.push_bytes(disk.mount_path.as_bytes());
        }
        match &self.bootstrap {
            Some(bootstrap) => {
                writer.push_u8(1);
                writer.push_string(&bootstrap.program);
                writer.push_u8(u8::try_from(bootstrap.args.len()).expect("argument count bounded"));
                for argument in &bootstrap.args {
                    writer.push_string(argument);
                }
                writer.push_string(&bootstrap.artifact);
            }
            None => writer.push_u8(0),
        }
        writer.finish(MAX_BOOT_CONFIG_FRAME)
    }

    fn encoded_len(&self) -> usize {
        let network_len = self
            .network
            .as_ref()
            .map_or(1, |network| 1 + 4 + 4 + 1 + 1 + (network.dns.len() * 4));
        1 + 2
            + 16
            + CAPABILITY_LEN
            + NONCE_LEN
            + network_len
            + 2
            + self
                .disks
                .iter()
                .map(|disk| 2 + 1 + 2 + disk.mount_path.len())
                .sum::<usize>()
            + self
                .bootstrap
                .as_ref()
                .map_or(1, BootstrapConfigV1::encoded_len)
    }

    fn validate(&self) -> ProtocolResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        if let Some(network) = &self.network {
            network.validate()?;
        }
        if self.disks.len() > MAX_DISKS {
            return Err(invalid_value("too many disk entries"));
        }
        let mut indexes = Vec::with_capacity(self.disks.len());
        let mut paths = Vec::with_capacity(self.disks.len());
        for disk in &self.disks {
            disk.validate()?;
            if indexes.contains(&disk.device_index) {
                return Err(invalid_value("duplicate disk device index"));
            }
            if paths.contains(&disk.mount_path.as_str()) {
                return Err(invalid_value("duplicate disk mount path"));
            }
            indexes.push(disk.device_index);
            paths.push(disk.mount_path.as_str());
        }
        if let Some(bootstrap) = &self.bootstrap {
            bootstrap.validate()?;
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for BootConfigV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_BOOT_CONFIG_FRAME {
            return Err(invalid_frame("boot configuration exceeds its frame limit"));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != BOOT_CONFIG_TAG {
            return Err(invalid_frame("unexpected boot configuration tag"));
        }
        let version = reader.take_u16()?;
        if version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let vm_id = Uuid::from_bytes(reader.take_array::<16>()?);
        let capability = SessionCapability::from_bytes(reader.take_array::<CAPABILITY_LEN>()?);
        let host_nonce = reader.take_array::<NONCE_LEN>()?;
        let network = match reader.take_u8()? {
            0 => None,
            1 => {
                let guest_ip = reader.take_array::<4>()?;
                let gateway = reader.take_array::<4>()?;
                let prefix_len = reader.take_u8()?;
                let dns_count = usize::from(reader.take_u8()?);
                if dns_count > MAX_DNS_SERVERS {
                    return Err(invalid_value("too many DNS servers"));
                }
                let mut dns = Vec::with_capacity(dns_count);
                for _ in 0..dns_count {
                    dns.push(reader.take_array::<4>()?);
                }
                Some(GuestNetworkConfigV1::new(
                    guest_ip, gateway, prefix_len, dns,
                )?)
            }
            _ => return Err(invalid_frame("invalid network presence flag")),
        };
        let disk_count = usize::from(reader.take_u16()?);
        if disk_count > MAX_DISKS {
            return Err(invalid_value("too many disk entries"));
        }
        let mut disks = Vec::with_capacity(disk_count);
        for _ in 0..disk_count {
            let device_index = reader.take_u16()?;
            let initialize = match reader.take_u8()? {
                0 => false,
                1 => true,
                _ => return Err(invalid_frame("invalid disk initialize flag")),
            };
            let path_len = usize::from(reader.take_u16()?);
            if path_len > MAX_MOUNT_PATH_BYTES {
                return Err(invalid_value("disk mount path exceeds its limit"));
            }
            let mount_path = String::from_utf8(reader.take(path_len)?.to_vec())
                .map_err(|_| invalid_value("disk mount path is not UTF-8"))?;
            disks.push(GuestDiskConfigV1::new(
                device_index,
                mount_path,
                initialize,
            )?);
        }
        let bootstrap = match reader.take_u8()? {
            0 => None,
            1 => {
                let program = reader.take_string(MAX_BOOTSTRAP_STRING_BYTES)?;
                let argument_count = usize::from(reader.take_u8()?);
                if argument_count > MAX_BOOTSTRAP_ARGS {
                    return Err(invalid_value("too many bootstrap arguments"));
                }
                let mut args = Vec::with_capacity(argument_count);
                for _ in 0..argument_count {
                    args.push(reader.take_string(MAX_BOOTSTRAP_STRING_BYTES)?);
                }
                let artifact = reader.take_string(MAX_BOOTSTRAP_STRING_BYTES)?;
                Some(BootstrapConfigV1::new(program, args, artifact)?)
            }
            _ => return Err(invalid_frame("invalid bootstrap presence flag")),
        };
        reader.finish()?;
        Self::new(vm_id, capability, host_nonce, network, disks)?.with_optional_bootstrap(bootstrap)
    }
}

impl BootConfigV1 {
    fn with_optional_bootstrap(
        mut self,
        bootstrap: Option<BootstrapConfigV1>,
    ) -> ProtocolResult<Self> {
        self.bootstrap = bootstrap;
        self.validate()?;
        Ok(self)
    }
}

impl TryInto<Vec<u8>> for BootConfigV1 {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        self.to_bytes()
    }
}

/// Guest-to-host proof that the boot configuration was received and applied.
pub struct ReadyV1 {
    /// Envelope version.
    pub version: u16,
    /// Guest VM identity.
    pub vm_id: Uuid,
    /// Echo of the host nonce from [`BootConfigV1`].
    pub host_nonce: [u8; NONCE_LEN],
    /// HMAC over the domain separator and exact boot transcript bytes.
    pub mac: [u8; MAC_LEN],
}

impl std::fmt::Debug for ReadyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadyV1")
            .field("version", &self.version)
            .field("vm_id", &self.vm_id)
            .field("host_nonce", &"REDACTED")
            .field("mac", &"REDACTED")
            .finish()
    }
}

impl ReadyV1 {
    /// Create a READY proof for the exact boot frame sent by the host.
    pub fn for_boot(capability: &SessionCapability, boot_frame: &[u8]) -> ProtocolResult<Self> {
        let boot = BootConfigV1::try_from(boot_frame)?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            vm_id: boot.vm_id,
            host_nonce: boot.host_nonce,
            mac: compute_ready_mac(capability, boot_frame),
        })
    }

    /// Verify the READY proof against the exact boot frame sent by the host.
    pub fn verify(&self, capability: &SessionCapability, boot_frame: &[u8]) -> ProtocolResult<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let boot = BootConfigV1::try_from(boot_frame)?;
        if self.vm_id != boot.vm_id || self.host_nonce != boot.host_nonce {
            return Err(Report::new(ProtocolError::Authentication));
        }
        let expected = compute_ready_mac(capability, boot_frame);
        if !constant_time_eq(&expected, &self.mac) {
            return Err(Report::new(ProtocolError::Authentication));
        }
        Ok(())
    }

    /// Serialize the READY proof.
    pub fn to_bytes(&self) -> ProtocolResult<Vec<u8>> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let mut writer = WireWriter::with_capacity(1 + 2 + 16 + NONCE_LEN + MAC_LEN);
        writer.push_u8(READY_TAG);
        writer.push_u16(self.version);
        writer.push_bytes(self.vm_id.as_bytes());
        writer.push_bytes(&self.host_nonce);
        writer.push_bytes(&self.mac);
        writer.finish(MAX_AUTH_FRAME)
    }
}

impl TryFrom<&[u8]> for ReadyV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_AUTH_FRAME {
            return Err(invalid_frame("READY frame exceeds its frame limit"));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != READY_TAG {
            return Err(invalid_frame("unexpected READY tag"));
        }
        let version = reader.take_u16()?;
        if version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let ready = Self {
            version,
            vm_id: Uuid::from_bytes(reader.take_array::<16>()?),
            host_nonce: reader.take_array::<NONCE_LEN>()?,
            mac: reader.take_array::<MAC_LEN>()?,
        };
        reader.finish()?;
        Ok(ready)
    }
}

impl TryInto<Vec<u8>> for ReadyV1 {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        self.to_bytes()
    }
}

/// Guest-to-host challenge for one command connection.
#[derive(Clone, Copy)]
pub struct AuthChallengeV1 {
    /// Envelope version.
    pub version: u16,
    /// Fresh challenge derived from the VM capability and connection counter.
    pub challenge: [u8; MAC_LEN],
}

impl std::fmt::Debug for AuthChallengeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthChallengeV1")
            .field("version", &self.version)
            .field("challenge", &"REDACTED")
            .finish()
    }
}

impl AuthChallengeV1 {
    /// Serialize the challenge envelope.
    pub fn to_bytes(self) -> ProtocolResult<Vec<u8>> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let mut writer = WireWriter::with_capacity(1 + 2 + MAC_LEN);
        writer.push_u8(AUTH_CHALLENGE_TAG);
        writer.push_u16(self.version);
        writer.push_bytes(&self.challenge);
        writer.finish(MAX_AUTH_FRAME)
    }
}

impl TryFrom<&[u8]> for AuthChallengeV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_AUTH_FRAME {
            return Err(invalid_frame(
                "authentication challenge exceeds its frame limit",
            ));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != AUTH_CHALLENGE_TAG {
            return Err(invalid_frame("unexpected authentication challenge tag"));
        }
        let version = reader.take_u16()?;
        if version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let challenge = reader.take_array::<MAC_LEN>()?;
        reader.finish()?;
        Ok(Self { version, challenge })
    }
}

impl TryInto<Vec<u8>> for AuthChallengeV1 {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        self.to_bytes()
    }
}

/// Host-to-guest response to one challenge.
#[derive(Clone, Copy)]
pub struct AuthResponseV1 {
    /// Envelope version.
    pub version: u16,
    /// HMAC bound to the VM, command service, protocol version, and challenge.
    pub mac: [u8; MAC_LEN],
}

impl std::fmt::Debug for AuthResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthResponseV1")
            .field("version", &self.version)
            .field("mac", &"REDACTED")
            .finish()
    }
}

impl AuthResponseV1 {
    /// Create a response for a received challenge.
    pub fn for_challenge(
        capability: &SessionCapability,
        vm_id: &Uuid,
        challenge: &AuthChallengeV1,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            mac: compute_auth_mac(
                capability,
                vm_id,
                COMMAND_AUTH_CONTEXT_V1,
                &challenge.challenge,
            ),
        }
    }

    /// Serialize the response envelope.
    pub fn to_bytes(self) -> ProtocolResult<Vec<u8>> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let mut writer = WireWriter::with_capacity(1 + 2 + MAC_LEN);
        writer.push_u8(AUTH_RESPONSE_TAG);
        writer.push_u16(self.version);
        writer.push_bytes(&self.mac);
        writer.finish(MAX_AUTH_FRAME)
    }
}

impl TryFrom<&[u8]> for AuthResponseV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_AUTH_FRAME {
            return Err(invalid_frame(
                "authentication response exceeds its frame limit",
            ));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != AUTH_RESPONSE_TAG {
            return Err(invalid_frame("unexpected authentication response tag"));
        }
        let version = reader.take_u16()?;
        if version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let mac = reader.take_array::<MAC_LEN>()?;
        reader.finish()?;
        Ok(Self { version, mac })
    }
}

impl TryInto<Vec<u8>> for AuthResponseV1 {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        self.to_bytes()
    }
}

/// Guest-to-host acknowledgement after a valid authentication response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthAcceptedV1 {
    /// Envelope version.
    pub version: u16,
}

impl AuthAcceptedV1 {
    /// Serialize the acknowledgement envelope.
    pub fn to_bytes(self) -> ProtocolResult<Vec<u8>> {
        if self.version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        let mut writer = WireWriter::with_capacity(1 + 2);
        writer.push_u8(AUTH_ACCEPTED_TAG);
        writer.push_u16(self.version);
        writer.finish(MAX_AUTH_FRAME)
    }
}

impl TryFrom<&[u8]> for AuthAcceptedV1 {
    type Error = Report<ProtocolError>;

    fn try_from(bytes: &[u8]) -> ProtocolResult<Self> {
        if bytes.len() > MAX_AUTH_FRAME {
            return Err(invalid_frame(
                "authentication acknowledgement exceeds its frame limit",
            ));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take_u8()? != AUTH_ACCEPTED_TAG {
            return Err(invalid_frame("unexpected authentication accepted tag"));
        }
        let version = reader.take_u16()?;
        if version != PROTOCOL_VERSION {
            return Err(Report::new(ProtocolError::VersionMismatch));
        }
        reader.finish()?;
        Ok(Self { version })
    }
}

impl TryInto<Vec<u8>> for AuthAcceptedV1 {
    type Error = Report<ProtocolError>;

    fn try_into(self) -> ProtocolResult<Vec<u8>> {
        self.to_bytes()
    }
}

/// Derive a unique guest challenge from the session key and monotonic
/// connection counter.
pub fn derive_auth_challenge(
    capability: &SessionCapability,
    vm_id: &Uuid,
    connection_counter: u64,
) -> [u8; MAC_LEN] {
    let counter = connection_counter.to_le_bytes();
    hmac_sha256(
        capability.as_bytes(),
        &[CHALLENGE_DOMAIN, vm_id.as_bytes(), &counter],
    )
}

/// Compute the HMAC bound to the exact VM command service and challenge.
pub fn compute_auth_mac(
    capability: &SessionCapability,
    vm_id: &Uuid,
    service_id: &[u8],
    challenge: &[u8; MAC_LEN],
) -> [u8; MAC_LEN] {
    let version = PROTOCOL_VERSION.to_le_bytes();
    let service_len = (service_id.len() as u32).to_le_bytes();
    hmac_sha256(
        capability.as_bytes(),
        &[
            RESPONSE_DOMAIN,
            &version,
            vm_id.as_bytes(),
            &service_len,
            service_id,
            challenge,
        ],
    )
}

/// Compute the HMAC over the exact boot transcript.
pub fn compute_ready_mac(capability: &SessionCapability, boot_frame: &[u8]) -> [u8; MAC_LEN] {
    hmac_sha256(capability.as_bytes(), &[BOOT_DOMAIN, boot_frame])
}

/// Compare two HMAC values without an early-exit comparison.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; MAC_LEN] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn ipv4_u32(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

fn invalid_frame(message: &str) -> Report<ProtocolError> {
    Report::new(ProtocolError::InvalidFrame).attach(message.to_owned())
}

fn invalid_value(message: &str) -> Report<ProtocolError> {
    Report::new(ProtocolError::InvalidValue).attach(message.to_owned())
}

struct WireWriter {
    bytes: Vec<u8>,
}

impl WireWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn push_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_string(&mut self, value: &str) {
        self.push_u16(u16::try_from(value.len()).expect("validated string fits u16"));
        self.push_bytes(value.as_bytes());
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn finish(self, maximum: usize) -> ProtocolResult<Vec<u8>> {
        if self.bytes.len() > maximum {
            return Err(invalid_frame("encoded frame exceeds its maximum"));
        }
        Ok(self.bytes)
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> ProtocolResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_frame("wire offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid_frame("truncated versioned frame"))?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> ProtocolResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> ProtocolResult<u16> {
        Ok(u16::from_le_bytes(self.take_array::<2>()?))
    }

    fn take_u32(&mut self) -> ProtocolResult<u32> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    fn take_u64(&mut self) -> ProtocolResult<u64> {
        Ok(u64::from_le_bytes(self.take_array::<8>()?))
    }

    fn take_string(&mut self, maximum: usize) -> ProtocolResult<String> {
        let length = usize::from(self.take_u16()?);
        if length > maximum {
            return Err(invalid_value("versioned string exceeds its size limit"));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| invalid_value("versioned string is not UTF-8"))
    }

    fn take_array<const N: usize>(&mut self) -> ProtocolResult<[u8; N]> {
        self.take(N).map(|bytes| {
            let mut result = [0u8; N];
            result.copy_from_slice(bytes);
            result
        })
    }

    fn finish(&self) -> ProtocolResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid_frame("trailing bytes in versioned frame"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> SessionCapability {
        SessionCapability::from_bytes([0x0b; CAPABILITY_LEN])
    }

    #[test]
    fn hmac_matches_rfc_4231_sha256_vector() {
        let key = [0x0b; 20];
        let expected = hex_bytes(
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7",
        );
        let got = hmac_sha256(&key, &[b"Hi There"]);
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    #[test]
    fn capability_debug_is_redacted() {
        assert!(!format!("{:?}", capability()).contains("0b0b"));
        assert_eq!(format!("{:?}", capability()), "SessionCapability(REDACTED)");
    }

    #[test]
    fn frame_limits_are_finite_and_keep_their_protocol_order() {
        assert_eq!(MAX_BOOT_CONFIG_FRAME, 64 * 1024);
        assert_eq!(MAX_AUTH_FRAME, 4 * 1024);
        assert_eq!(MAX_COMMAND_FRAME, 16 * 1024 * 1024);
        assert_eq!(MAX_GUEST_CONNECTIONS, 32);
        assert_eq!(AUTHENTICATION_DEADLINE, std::time::Duration::from_secs(5));
    }

    #[test]
    fn boot_config_roundtrips_and_redacts_secret_fields() {
        let boot = BootConfigV1::new(
            Uuid::nil(),
            capability(),
            [0x22; NONCE_LEN],
            Some(
                GuestNetworkConfigV1::new([10, 1, 0, 10], [10, 1, 0, 1], 24, vec![[1, 1, 1, 1]])
                    .unwrap(),
            ),
            vec![GuestDiskConfigV1::new(0, "/build", true).unwrap()],
        )
        .unwrap();
        let bytes = boot.to_bytes().unwrap();
        let decoded = BootConfigV1::try_from(bytes.as_slice()).unwrap();
        assert_eq!(decoded.vm_id, Uuid::nil());
        assert_eq!(decoded.network, boot.network);
        assert_eq!(decoded.disks, boot.disks);
        assert!(format!("{boot:?}").contains("REDACTED"));
        assert!(!format!("{boot:?}").contains("0b0b"));
    }

    #[test]
    fn bootstrap_config_and_result_roundtrip_with_bounds() {
        let bootstrap = BootstrapConfigV1::new(
            "/bin/sh",
            vec!["/usr/local/bin/build-kernel.sh".into(), "6.6.14".into()],
            "/build/artifacts/bzImage",
        )
        .unwrap();
        let boot = BootConfigV1::new(
            Uuid::nil(),
            capability(),
            [0x44; NONCE_LEN],
            None,
            Vec::new(),
        )
        .unwrap()
        .with_bootstrap(bootstrap.clone())
        .unwrap();
        let decoded = BootConfigV1::try_from(boot.to_bytes().unwrap().as_slice()).unwrap();
        assert_eq!(decoded.bootstrap, Some(bootstrap));

        let result = BootstrapResultV1::success(123, [0x55; 32]).unwrap();
        assert_eq!(
            BootstrapResultV1::try_from(result.to_bytes().unwrap().as_slice()).unwrap(),
            result
        );
        assert!(BootstrapResultV1::success(0, [0; 32]).is_err());
    }

    #[test]
    fn bootstrap_paths_require_absolute_non_traversing_names() {
        assert!(BootstrapConfigV1::new("sh", Vec::new(), "/artifact").is_err());
        assert!(BootstrapConfigV1::new("/bin/sh", Vec::new(), "/tmp/../artifact").is_err());
    }

    #[test]
    fn duplicate_disk_entries_are_rejected() {
        let result = BootConfigV1::new(
            Uuid::nil(),
            capability(),
            [0; NONCE_LEN],
            None,
            vec![
                GuestDiskConfigV1::new(0, "/a", true).unwrap(),
                GuestDiskConfigV1::new(0, "/b", true).unwrap(),
            ],
        );
        assert!(
            matches!(result, Err(error) if error.current_context() == &ProtocolError::InvalidValue)
        );
    }

    #[test]
    fn boot_config_rejects_an_encoded_frame_over_its_limit() {
        let disks = (0..MAX_DISKS)
            .map(|index| {
                GuestDiskConfigV1::new(
                    index as u16,
                    format!("/{index:02}{}", "x".repeat(MAX_MOUNT_PATH_BYTES - 3)),
                    false,
                )
                .unwrap()
            })
            .collect();
        let boot =
            BootConfigV1::new(Uuid::nil(), capability(), [0; NONCE_LEN], None, disks).unwrap();

        let error = boot.to_bytes().unwrap_err();
        assert_eq!(error.current_context(), &ProtocolError::InvalidFrame);
    }

    #[test]
    fn authentication_envelopes_reject_oversized_payloads_before_parsing() {
        let oversized = vec![0u8; MAX_AUTH_FRAME + 1];
        assert_eq!(
            ReadyV1::try_from(oversized.as_slice())
                .unwrap_err()
                .current_context(),
            &ProtocolError::InvalidFrame
        );
        assert_eq!(
            AuthChallengeV1::try_from(oversized.as_slice())
                .unwrap_err()
                .current_context(),
            &ProtocolError::InvalidFrame
        );
        assert_eq!(
            AuthResponseV1::try_from(oversized.as_slice())
                .unwrap_err()
                .current_context(),
            &ProtocolError::InvalidFrame
        );
        assert_eq!(
            AuthAcceptedV1::try_from(oversized.as_slice())
                .unwrap_err()
                .current_context(),
            &ProtocolError::InvalidFrame
        );
    }

    #[test]
    fn ready_proof_rejects_modified_boot_transcript() {
        let boot = BootConfigV1::new(
            Uuid::nil(),
            capability(),
            [0x33; NONCE_LEN],
            None,
            Vec::new(),
        )
        .unwrap();
        let bytes = boot.to_bytes().unwrap();
        let ready = ReadyV1::for_boot(&boot.capability, &bytes).unwrap();
        let mut modified = bytes.clone();
        modified[0] ^= 1;
        assert!(
            ReadyV1::try_from(ready.to_bytes().unwrap().as_slice())
                .unwrap()
                .verify(&boot.capability, &modified)
                .is_err()
        );
    }

    #[test]
    fn connection_challenges_and_responses_are_bound_to_vm_and_counter() {
        let key = capability();
        let vm = Uuid::nil();
        let first = derive_auth_challenge(&key, &vm, 1);
        let second = derive_auth_challenge(&key, &vm, 2);
        assert_ne!(first, second);
        let challenge = AuthChallengeV1 {
            version: PROTOCOL_VERSION,
            challenge: first,
        };
        let response = AuthResponseV1::for_challenge(&key, &vm, &challenge);
        let expected = compute_auth_mac(&key, &vm, COMMAND_AUTH_CONTEXT_V1, &first);
        assert!(constant_time_eq(&expected, &response.mac));
        let other_vm = compute_auth_mac(&key, &Uuid::from_u128(1), COMMAND_AUTH_CONTEXT_V1, &first);
        assert!(!constant_time_eq(&other_vm, &response.mac));
    }

    #[test]
    fn command_port_is_the_immutable_tcp_port_1024() {
        // The migration moved the command endpoint from an HvSocket service
        // port to a TCP port on the configured guest address; the numeric
        // value is part of the protocol contract and must not change. The
        // u16 type itself guarantees the value fits the TCP port range.
        assert_eq!(crate::COMMAND_PORT, 1024u16);
    }

    #[test]
    fn command_auth_context_is_the_immutable_v1_domain_separator() {
        // The V1 context bytes are the retained former service identifier,
        // now treated as an opaque domain separator. They are stable for
        // protocol V1; a later protocol-version plan may replace them.
        assert_eq!(
            COMMAND_AUTH_CONTEXT_V1,
            b"00000400-FACB-11E6-BD58-64006A7986D3"
        );
        let key = capability();
        let vm = Uuid::nil();
        let challenge = AuthChallengeV1 {
            version: PROTOCOL_VERSION,
            challenge: [0x5a; 32],
        };
        let response = AuthResponseV1::for_challenge(&key, &vm, &challenge);
        let expected = compute_auth_mac(&key, &vm, COMMAND_AUTH_CONTEXT_V1, &challenge.challenge);
        assert!(constant_time_eq(&expected, &response.mac));
    }

    fn hex_bytes(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .flat_map(|word| {
                word.as_bytes()
                    .chunks_exact(2)
                    .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
