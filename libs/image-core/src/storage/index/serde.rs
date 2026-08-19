//! Direct `redb::Value` implementations for the persisted domain types.
//!
//! `FileDigest`, `Entry`, and `Blueprint` are stored directly in redb tables;
//! no parallel storage DTO or extra serialization framework is used. The
//! cache is disposable and versioned as a unit, so the persisted byte layout
//! lives beside the domain type and migrates by bumping the versioned cache
//! directory plus the [`redb::TypeName`] version.
//!
//! ## Encodings
//!
//! `FileDigest`: 48 bytes
//! ```text
//! bytes 0..32  BLAKE3 file hash
//! bytes 32..48 file size as big-endian u128
//! ```
//!
//! `Entry`: 67 bytes
//! ```text
//! bytes 0..16   UUID
//! byte 16       namespace
//! bytes 17..49  BLAKE3 file hash
//! bytes 49..65  file size as big-endian u128
//! byte 65       artifact type
//! byte 66       artifact compression
//! ```
//!
//! `LinkRef`: 65 bytes
//! ```text
//! bytes 0..16   UUID
//! byte 16       namespace
//! bytes 17..49  BLAKE3 link hash
//! bytes 49..65  link carried size as big-endian u128
//! ```
//!
//! `ExpectedDigest`: variable width
//! ```text
//! byte        discriminant (1=blake3, 2=sha256, 3=sha512)
//! bytes 1..5  payload length as big-endian u32
//! payload     raw digest bytes (32 for blake3/sha256, 64 for sha512)
//! ```
//!
//! `Blueprint`: variable width
//! ```text
//! byte        format marker (0x02)
//! bytes 1..17  target UUID (16 bytes)
//! byte 17      target namespace
//! bytes 18..22 layer count as big-endian u32 (upper bound u32::MAX)
//! repeated layer encodings:
//!   bytes 0..16  layer UUID
//!   byte 16      ArtifactLink variant (1=Local, 2=Bytes, 3=Http)
//!   bytes 17..25 payload length as big-endian u64
//!   payload bytes (Local=platform-local path bytes,
//!                  Bytes=raw bytes,
//!                  Http=UTF-8 URL bytes)
//!   bytes next 16 link carried size as big-endian u128
//!   ExpectedDigest encoding
//!   bytes next 48 LinkDigest encoding
//! byte         extract presence (0=None, 1=Some)
//! if present:
//!   bytes 0..8 extract path length as big-endian u64
//!   payload bytes (platform-local path bytes)
//! ```
//!
//! ### Malformed bytes
//!
//! `redb::Value::from_bytes` is infallible and may assume its input came
//! from the matching `as_bytes`. Decoders assert their expected widths,
//! tags, lengths, counts, and complete consumption. A corrupt cache is
//! invalidated as a versioned unit; it is not migrated or partially repaired.

use std::cmp::Ordering;

use bytes::Bytes;
use redb::{Key, TypeName, Value};
use uuid::Uuid;

use crate::{
    artifact::{
        ArtifactId, compression::ArtifactCompression, link::ArtifactLink, ty::ArtifactType,
    },
    digest::{ExpectedDigest, FileDigest, LinkDigest},
    storage::{
        blueprint::{Blueprint, Layer},
        file_ref::FileRef,
        link_ref::LinkRef,
        namespace::{Namespace, NamespacedFileDigest, NamespacedLinkDigest},
    },
};

/// Versioned type-name prefix shared with `key.rs`.
const TYPE_PREFIX: &str = "image::storage";

/// Blueprint format marker. Bumping this is equivalent to a layout change
/// and requires bumping the type-name suffix and the cache directory.
const BLUEPRINT_FORMAT_MARKER: u8 = 0x02;

/// Persisted `ArtifactLink` variant discriminant.
const LINK_LOCAL: u8 = 1;
const LINK_BYTES: u8 = 2;
const LINK_HTTP: u8 = 3;

/// Upper bound for layer counts. Encoding uses a u32 so this is a documented
/// limit, not a storage constraint.
const MAX_LAYER_COUNT: u32 = 100_000;

/// Upper bound for any single variable-length payload. Encoding uses u64.
const MAX_PAYLOAD_LEN: usize = u32::MAX as usize;

// ---------------------------------------------------------------------------
// FileRef
// ---------------------------------------------------------------------------

impl FileRef {
    /// Fixed-width byte encoding (67 bytes).
    pub fn encode(&self) -> [u8; 67] {
        let mut bytes = [0u8; 67];
        bytes[0..16].copy_from_slice(self.uuid.as_bytes());
        bytes[16] = self.namespace.to_bytes();
        bytes[17..49].copy_from_slice(self.file_digest.file_hash.as_bytes());
        bytes[49..65].copy_from_slice(&self.file_digest.file_size.to_be_bytes());
        bytes[65] = self.artifact_type.to_bytes();
        bytes[66] = self.artifact_compression.to_bytes();
        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts lengths and discriminants.
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 67, "Entry value must be 67 bytes");
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[0..16]);
        let namespace = Namespace::from_bytes(bytes[16])
            .expect("Entry namespace byte is a valid Namespace discriminant");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[17..49]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[49..65]);
        let artifact_type = ArtifactType::from_bytes(bytes[65])
            .expect("Entry artifact type byte is a valid ArtifactType discriminant");
        let artifact_compression = ArtifactCompression::from_bytes(bytes[66])
            .expect("Entry artifact compression byte is a valid ArtifactCompression discriminant");
        Self {
            uuid: Uuid::from_bytes(uuid),
            namespace,
            file_digest: FileDigest {
                file_hash: blake3::Hash::from_bytes(hash),
                file_size: u128::from_be_bytes(size),
            },
            artifact_type,
            artifact_compression,
        }
    }
}

impl Value for FileRef {
    type SelfType<'a> = FileRef;
    type AsBytes<'a> = [u8; 67];

    fn fixed_width() -> Option<usize> {
        Some(67)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::FileRef/v1"))
    }
}
// ---------------------------------------------------------------------------
// Link Ref
// ---------------------------------------------------------------------------

impl LinkRef {
    /// Fixed-width byte encoding (65 bytes).
    pub fn encode(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..16].copy_from_slice(self.uuid.as_bytes());
        bytes[16] = self.namespace.to_bytes();
        bytes[17..49].copy_from_slice(self.link_digest.link_hash.as_bytes());
        bytes[49..65].copy_from_slice(&self.link_digest.file_size.to_be_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts lengths and discriminants.
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 65, "LinkRef value must be 65 bytes");
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[0..16]);
        let namespace = Namespace::from_bytes(bytes[16])
            .expect("LinkRef namespace byte is a valid Namespace discriminant");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[17..49]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[49..65]);
        Self {
            uuid: Uuid::from_bytes(uuid),
            namespace,
            link_digest: LinkDigest {
                link_hash: blake3::Hash::from_bytes(hash),
                file_size: u128::from_be_bytes(size),
            },
        }
    }
}

impl Value for LinkRef {
    type SelfType<'a> = LinkRef;
    type AsBytes<'a> = [u8; 65];

    fn fixed_width() -> Option<usize> {
        Some(65)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::LinkRef/v2"))
    }
}

// ---------------------------------------------------------------------------
// Blueprint
// ---------------------------------------------------------------------------

impl Blueprint {
    /// Variable-width byte encoding. See module docs.
    pub fn encode(&self) -> Vec<u8> {
        let layer_count =
            u32::try_from(self.layers.len()).expect("blueprint layer count fits in u32");
        assert!(
            layer_count <= MAX_LAYER_COUNT,
            "blueprint layer count overflow"
        );

        let mut bytes = Vec::with_capacity(64 + self.layers.len() * 128);
        bytes.push(BLUEPRINT_FORMAT_MARKER);
        bytes.extend_from_slice(self.target_entry_uuid.as_bytes());
        bytes.push(self.target_entry_namespace.to_bytes());
        bytes.extend_from_slice(&layer_count.to_be_bytes());

        for layer in &self.layers {
            encode_layer(&mut bytes, layer);
        }

        match &self.extract {
            None => bytes.push(0),
            Some(path) => {
                bytes.push(1);
                let path_bytes = encode_path(path);
                let len = u64::try_from(path_bytes.len()).expect("extract path length fits in u64");
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(&path_bytes);
            }
        }

        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts lengths, tags, and complete
    /// consumption.
    pub fn decode(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);
        assert_eq!(
            cursor.take_byte(),
            BLUEPRINT_FORMAT_MARKER,
            "blueprint format marker mismatch"
        );

        let target_entry_uuid = Uuid::from_bytes(cursor.take_array_16());
        let target_entry_namespace = Namespace::from_bytes(cursor.take_byte())
            .expect("blueprint target namespace byte is a valid Namespace discriminant");

        let layer_count = u32::from_be_bytes(cursor.take_array_4());
        assert!(
            layer_count <= MAX_LAYER_COUNT,
            "blueprint layer count exceeds the documented upper bound"
        );

        let mut layers = Vec::with_capacity(usize::try_from(layer_count).unwrap());
        for _ in 0..layer_count {
            layers.push(decode_layer(&mut cursor));
        }

        let extract = match cursor.take_byte() {
            0 => None,
            1 => {
                let len_bytes = cursor.take_array_8();
                let len = usize::try_from(u64::from_be_bytes(len_bytes))
                    .expect("extract path length fits in usize");
                assert!(len <= MAX_PAYLOAD_LEN, "extract path length overflow");
                let path_bytes = cursor.take_bytes(len);
                Some(decode_path(path_bytes))
            }
            other => panic!("unknown blueprint extract presence variant {other}"),
        };

        cursor.assert_consumed();
        Self {
            target_entry_uuid,
            target_entry_namespace,
            layers,
            extract,
        }
    }
}

impl Value for Blueprint {
    type SelfType<'a> = Blueprint;
    type AsBytes<'a> = Vec<u8>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::Blueprint/v3"))
    }
}

// ---------------------------------------------------------------------------
// Private layer codec
// ---------------------------------------------------------------------------

fn encode_layer(bytes: &mut Vec<u8>, layer: &Layer) {
    bytes.extend_from_slice(layer.uuid.as_bytes());
    let (variant, payload): (u8, Vec<u8>) = match &layer.link {
        ArtifactLink::Local(path, _) => (LINK_LOCAL, encode_path(path)),
        ArtifactLink::Bytes(payload, _) => (LINK_BYTES, payload.to_vec()),
        ArtifactLink::Http(url, _) => (LINK_HTTP, url.as_bytes().to_vec()),
    };
    bytes.push(variant);
    let payload_len = u64::try_from(payload.len()).expect("layer link payload length fits in u64");
    assert!(
        payload.len() <= MAX_PAYLOAD_LEN,
        "layer link payload overflow"
    );
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&payload);

    let link_size = match layer.link {
        ArtifactLink::Local(_, size)
        | ArtifactLink::Bytes(_, size)
        | ArtifactLink::Http(_, size) => size,
    };
    bytes.extend_from_slice(&link_size.to_be_bytes());

    encode_expected_digest(bytes, &layer.expected_digest);

    bytes.extend_from_slice(&layer.link_digest.encode());
}

fn decode_layer(cursor: &mut Cursor<'_>) -> Layer {
    let uuid = Uuid::from_bytes(cursor.take_array_16());
    let variant = cursor.take_byte();
    let payload_len_bytes = cursor.take_array_8();
    let payload_len = usize::try_from(u64::from_be_bytes(payload_len_bytes))
        .expect("layer link payload length fits in usize");
    assert!(
        payload_len <= MAX_PAYLOAD_LEN,
        "layer link payload overflow"
    );
    let payload = cursor.take_bytes(payload_len);

    let link_size_bytes = cursor.take_array_16();
    let link_size = u128::from_be_bytes(link_size_bytes);

    let link = match variant {
        LINK_LOCAL => ArtifactLink::Local(decode_path(payload), link_size),
        LINK_BYTES => ArtifactLink::Bytes(Bytes::copy_from_slice(payload), link_size),
        LINK_HTTP => {
            let url = std::str::from_utf8(payload)
                .expect("Http link payload is valid UTF-8")
                .to_string();
            ArtifactLink::Http(url, link_size)
        }
        other => panic!("unknown ArtifactLink variant {other}"),
    };

    let expected_digest = decode_expected_digest(cursor);

    let link_digest = LinkDigest::decode(cursor.take_bytes(48));

    Layer {
        uuid,
        link,
        expected_digest,
        link_digest,
    }
}

fn encode_expected_digest(bytes: &mut Vec<u8>, digest: &ExpectedDigest) {
    bytes.push(digest.discriminant());
    let payload = digest.digest_bytes();
    let len = u32::try_from(payload.len()).expect("expected digest length fits in u32");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
}

fn decode_expected_digest(cursor: &mut Cursor<'_>) -> ExpectedDigest {
    let discriminant = cursor.take_byte();
    let len_bytes = cursor.take_array_4();
    let len = usize::try_from(u32::from_be_bytes(len_bytes))
        .expect("expected digest length fits in usize");
    assert!(
        len == 32 || len == 64,
        "expected digest length must be 32 or 64 bytes"
    );
    let payload = cursor.take_bytes(len);
    ExpectedDigest::from_parts(discriminant, payload)
        .expect("expected digest discriminant and payload match")
}

impl LinkDigest {
    /// Fixed-width byte encoding (48 bytes).
    pub fn encode(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[0..32].copy_from_slice(self.link_hash.as_bytes());
        bytes[32..48].copy_from_slice(&self.file_size.to_be_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 48, "LinkDigest value must be 48 bytes");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[0..32]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[32..48]);
        Self {
            link_hash: blake3::Hash::from_bytes(hash),
            file_size: u128::from_be_bytes(size),
        }
    }
}

#[cfg(test)]
impl FileDigest {
    /// Fixed-width byte encoding (48 bytes). Kept for wire-format
    /// validation parity in the round-trip tests.
    pub fn encode(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[0..32].copy_from_slice(self.file_hash.as_bytes());
        bytes[32..48].copy_from_slice(&self.file_size.to_be_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 48, "FileDigest value must be 48 bytes");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[0..32]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[32..48]);
        Self {
            file_hash: blake3::Hash::from_bytes(hash),
            file_size: u128::from_be_bytes(size),
        }
    }
}

impl NamespacedLinkDigest {
    pub fn encode(&self) -> [u8; 49] {
        let mut bytes = [0u8; 49];
        bytes[0] = self.namespace.to_bytes();
        bytes[1..33].copy_from_slice(self.link_digest.link_hash.as_bytes());
        bytes[33..49].copy_from_slice(&self.link_digest.file_size.to_be_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts the input length.
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 49, "ReferenceKey value must be 49 bytes");
        let namespace = Namespace::from_bytes(bytes[0])
            .expect("ReferenceKey namespace byte is a valid Namespace discriminant");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[1..33]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[33..49]);
        Self {
            namespace,
            link_digest: LinkDigest {
                link_hash: blake3::Hash::from_bytes(hash),
                file_size: u128::from_be_bytes(size),
            },
        }
    }
}

impl Value for NamespacedLinkDigest {
    type SelfType<'a> = NamespacedLinkDigest;
    type AsBytes<'a> = [u8; 49];

    fn fixed_width() -> Option<usize> {
        Some(49)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::ReferenceKey/v1"))
    }
}

impl Key for NamespacedLinkDigest {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.cmp(data2)
    }
}

impl ArtifactId {
    pub fn new(namespace: Namespace, uuid: Uuid) -> Self {
        Self { namespace, uuid }
    }

    /// Fixed-width byte encoding (17 bytes). See module docs.
    pub fn encode(&self) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[0] = self.namespace.to_bytes();
        bytes[1..17].copy_from_slice(self.uuid.as_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts the input length and namespace
    /// discriminant.
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 17, "EntryIdentity value must be 17 bytes");
        let namespace = Namespace::from_bytes(bytes[0])
            .expect("EntryIdentity namespace byte is a valid Namespace discriminant");
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[1..17]);
        Self {
            namespace,
            uuid: Uuid::from_bytes(uuid),
        }
    }
}

impl Value for ArtifactId {
    type SelfType<'a> = ArtifactId;
    type AsBytes<'a> = [u8; 17];

    fn fixed_width() -> Option<usize> {
        Some(17)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::EntryIdentity/v1"))
    }
}

impl Key for ArtifactId {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.cmp(data2)
    }
}

impl NamespacedFileDigest {
    /// Fixed-width byte encoding (49 bytes). See module docs.
    pub fn encode(&self) -> [u8; 49] {
        let mut bytes = [0u8; 49];
        bytes[0] = self.namespace.to_bytes();
        bytes[1..33].copy_from_slice(self.file_digest.file_hash.as_bytes());
        bytes[33..49].copy_from_slice(&self.file_digest.file_size.to_be_bytes());
        bytes
    }

    /// Inverse of [`Self::encode`]. Asserts the input length and namespace
    /// discriminant.
    pub fn decode(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            49,
            "NamespacedFileDigest value must be 49 bytes"
        );
        let namespace = Namespace::from_bytes(bytes[0])
            .expect("NamespacedFileDigest namespace byte is a valid Namespace discriminant");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[1..33]);
        let mut size = [0u8; 16];
        size.copy_from_slice(&bytes[33..49]);
        Self {
            namespace,
            file_digest: FileDigest {
                file_hash: blake3::Hash::from_bytes(hash),
                file_size: u128::from_be_bytes(size),
            },
        }
    }
}

impl Value for NamespacedFileDigest {
    type SelfType<'a> = NamespacedFileDigest;
    type AsBytes<'a> = [u8; 49];

    fn fixed_width() -> Option<usize> {
        Some(49)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        Self::decode(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.encode()
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("{TYPE_PREFIX}::NamespacedFileDigest/v1"))
    }
}

impl Key for NamespacedFileDigest {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        data1.cmp(data2)
    }
}

/// Encode a `PathBuf` to the platform-local byte representation.
///
/// Cache directories are not portable across operating systems, so the
/// encoding preserves the local `OsString` form rather than a single
/// canonical Unicode encoding. On Unix this is WTF-8 bytes; on Windows it
/// is the little-endian u16 wide-char sequence.
fn encode_path(path: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut bytes = Vec::with_capacity(path.as_os_str().encode_wide().count() * 2);
        for unit in path.as_os_str().encode_wide() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }
}

/// Decode the result of [`encode_path`]. Asserts even width on Windows.
fn decode_path(bytes: &[u8]) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        std::path::PathBuf::from(OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        assert!(
            bytes.len().is_multiple_of(2),
            "platform-local path bytes must be an even-length u16 stream"
        );
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let os_string = OsString::from_wide(&units);
        std::path::PathBuf::from(os_string)
    }
}

/// Minimal cursor over the encoded byte buffer used by blueprint decoding.
///
/// Defensive helpers assert the available length at every step so decoding
/// fails loudly on truncation rather than producing a partial or different
/// domain object.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take_byte(&mut self) -> u8 {
        let byte = *self
            .bytes
            .get(self.pos)
            .expect("blueprint decoding: input truncated at a single-byte field");
        self.pos += 1;
        byte
    }

    fn take_array_4(&mut self) -> [u8; 4] {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(self.take_bytes(4));
        arr
    }

    fn take_array_8(&mut self) -> [u8; 8] {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(self.take_bytes(8));
        arr
    }

    fn take_array_16(&mut self) -> [u8; 16] {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(self.take_bytes(16));
        arr
    }

    fn take_bytes(&mut self, n: usize) -> &'a [u8] {
        let start = self.pos;
        let end = start
            .checked_add(n)
            .expect("blueprint decoding: fixed-width field overflowed usize");
        let slice = self
            .bytes
            .get(start..end)
            .expect("blueprint decoding: input truncated at a fixed-width field");
        self.pos = end;
        slice
    }

    fn assert_consumed(&self) {
        assert_eq!(
            self.pos,
            self.bytes.len(),
            "blueprint decoding: did not consume the complete encoded value"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_link_digest(size: u128) -> LinkDigest {
        LinkDigest {
            link_hash: blake3::hash(b"some-link-bytes"),
            file_size: size,
        }
    }

    fn sample_file_digest(size: u128) -> FileDigest {
        FileDigest {
            file_hash: blake3::hash(b"some-file-bytes"),
            file_size: size,
        }
    }

    fn sample_expected_digest(algorithm: &str) -> ExpectedDigest {
        match algorithm {
            "blake3" => ExpectedDigest::Blake3([1u8; 32]),
            "sha256" => ExpectedDigest::Sha256([2u8; 32]),
            "sha512" => ExpectedDigest::Sha512([3u8; 64]),
            _ => unimplemented!("unknown algorithm"),
        }
    }

    #[test]
    fn file_digest_width_is_48_bytes() {
        assert_eq!(sample_file_digest(10).encode().len(), 48);
    }

    #[test]
    fn file_digest_round_trip() {
        let original = sample_file_digest(98765);
        let encoded = original.encode();
        let decoded = FileDigest::decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn link_digest_round_trip() {
        let original = sample_link_digest(42);
        let encoded = original.encode();
        let decoded = LinkDigest::decode(&encoded);
        assert_eq!(original, decoded);
    }

    #[test]
    fn link_ref_width_is_65_bytes() {
        let link_ref = LinkRef {
            uuid: Uuid::nil(),
            namespace: Namespace::Rootfs,
            link_digest: sample_link_digest(0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128),
        };
        assert_eq!(link_ref.encode().len(), 65);
    }

    #[test]
    fn link_ref_round_trip_with_nontrivial_size() {
        let link_ref = LinkRef {
            uuid: Uuid::nil(),
            namespace: Namespace::Layers,
            link_digest: LinkDigest {
                link_hash: blake3::hash(b"a-link"),
                file_size: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128,
            },
        };
        let encoded = link_ref.encode();
        let decoded = LinkRef::decode(&encoded);
        assert_eq!(link_ref, decoded);
        assert_eq!(
            decoded.link_digest.file_size,
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128
        );
    }

    #[test]
    fn entry_width_is_67_bytes_for_each_variant() {
        for ty in [
            ArtifactType::Compressed,
            ArtifactType::ContainerTar,
            ArtifactType::ContainerCpio,
            ArtifactType::FileBzImage,
        ] {
            for compression in [
                ArtifactCompression::None,
                ArtifactCompression::Gzip,
                ArtifactCompression::Zstd,
            ] {
                let entry = FileRef {
                    uuid: Uuid::nil(),
                    namespace: Namespace::Layers,
                    file_digest: sample_file_digest(1),
                    artifact_type: ty,
                    artifact_compression: compression,
                };
                assert_eq!(entry.encode().len(), 67);
            }
        }
    }

    #[test]
    fn entry_round_trip_for_each_variant() {
        for ty in [
            ArtifactType::Compressed,
            ArtifactType::ContainerTar,
            ArtifactType::ContainerCpio,
            ArtifactType::FileBzImage,
        ] {
            for compression in [
                ArtifactCompression::None,
                ArtifactCompression::Gzip,
                ArtifactCompression::Zstd,
            ] {
                let entry = FileRef {
                    uuid: Uuid::nil(),
                    namespace: Namespace::Rootfs,
                    file_digest: sample_file_digest(2024),
                    artifact_type: ty,
                    artifact_compression: compression,
                };
                let encoded = entry.encode();
                let decoded = FileRef::decode(&encoded);
                assert_eq!(entry, decoded);
            }
        }
    }

    #[test]
    fn entry_file_size_is_big_endian() {
        let entry = FileRef {
            uuid: Uuid::nil(),
            namespace: Namespace::Kernel,
            file_digest: FileDigest {
                file_hash: blake3::hash(b"x"),
                file_size: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128,
            },
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::None,
        };
        let encoded = entry.encode();
        assert_eq!(encoded[49], 0x01);
    }

    #[test]
    fn entry_identity_from_entry_preserves_invariant() {
        let entry = FileRef {
            uuid: Uuid::nil(),
            namespace: Namespace::Kernel,
            file_digest: sample_file_digest(1),
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::None,
        };
        let identity = ArtifactId::from(&entry);
        assert_eq!(identity.namespace, entry.namespace);
        assert_eq!(identity.uuid, entry.uuid);
    }

    fn http_layer(link_size: u128) -> Layer {
        Layer {
            uuid: Uuid::nil(),
            link: ArtifactLink::Http(
                "https://registry.example/v2/foo/manifests/1".to_string(),
                link_size,
            ),
            expected_digest: sample_expected_digest("blake3"),
            link_digest: sample_link_digest(100),
        }
    }

    #[test]
    fn blueprint_round_trip_with_http_layers() {
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Rootfs,
            layers: vec![http_layer(10), http_layer(20)],
            extract: None,
        };
        let encoded = blueprint.encode();
        let decoded = Blueprint::decode(&encoded);
        assert_eq!(blueprint, decoded);
    }

    #[test]
    fn blueprint_round_trip_with_local_links() {
        let path = std::path::PathBuf::from("/some/local/path/to/artifact.tar");
        let layer = Layer {
            uuid: Uuid::nil(),
            link: ArtifactLink::Local(path.clone(), 256),
            expected_digest: sample_expected_digest("sha256"),
            link_digest: sample_link_digest(1),
        };
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Layers,
            layers: vec![layer],
            extract: Some(path.join("kernel")),
        };
        let encoded = blueprint.encode();
        let decoded = Blueprint::decode(&encoded);
        assert_eq!(blueprint, decoded);
    }

    #[test]
    fn blueprint_round_trip_with_bytes_links() {
        let layer = Layer {
            uuid: Uuid::nil(),
            link: ArtifactLink::Bytes(Bytes::from_static(&[0xa, 0xb, 0xc, 0xd]), 4),
            expected_digest: sample_expected_digest("sha256"),
            link_digest: sample_link_digest(1),
        };
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Kernel,
            layers: vec![layer],
            extract: None,
        };
        let encoded = blueprint.encode();
        let decoded = Blueprint::decode(&encoded);
        assert_eq!(blueprint, decoded);
    }

    #[test]
    fn blueprint_round_trip_with_sha512_layer_digest() {
        // Layers carry an authoritative digest from the manifest. The
        // algorithm is preserved and verified during the round trip.
        let layer = Layer {
            uuid: Uuid::nil(),
            link: ArtifactLink::Http("https://example/v2/blob".to_string(), 17),
            expected_digest: sample_expected_digest("sha512"),
            link_digest: sample_link_digest(17),
        };
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Layers,
            layers: vec![layer],
            extract: None,
        };
        let decoded = Blueprint::decode(&blueprint.encode());
        assert_eq!(blueprint, decoded);
    }

    #[test]
    fn blueprint_round_trip_for_each_expected_digest_algorithm() {
        for algorithm in ["blake3", "sha256", "sha512"] {
            let layer = Layer {
                uuid: Uuid::nil(),
                link: ArtifactLink::Http("https://example/v2/blob".to_string(), 99),
                expected_digest: sample_expected_digest(algorithm),
                link_digest: sample_link_digest(99),
            };
            let blueprint = Blueprint {
                target_entry_uuid: Uuid::nil(),
                target_entry_namespace: Namespace::Layers,
                layers: vec![layer],
                extract: None,
            };
            let encoded = blueprint.encode();
            let decoded = Blueprint::decode(&encoded);
            assert_eq!(blueprint, decoded, "round trip failed for {algorithm}");
        }
    }

    #[test]
    #[should_panic(expected = "expected digest length must be 32 or 64 bytes")]
    fn blueprint_rejects_truncated_expected_digest() {
        let mut bytes = vec![BLUEPRINT_FORMAT_MARKER];
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(Namespace::Kernel.to_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        // layer UUID
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(LINK_LOCAL);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u128.to_be_bytes());
        // ExpectedDigest with truncated payload length.
        bytes.push(2);
        bytes.extend_from_slice(&16u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&[0u8; 48]);
        bytes.push(0);
        let _ = Blueprint::decode(&bytes);
    }

    #[cfg(windows)]
    #[test]
    fn blueprint_round_trip_non_ascii_path() {
        // Reproduces a non-ASCII Windows path that does not fit into a single
        // u16 without a surrogate. The encoder stores platform-local bytes,
        // so the round trip restores the original `PathBuf` on this OS.
        let path = std::path::PathBuf::from("C:\\\\temp\\\\\u{1F600}.img");
        let layer = Layer {
            uuid: Uuid::nil(),
            link: ArtifactLink::Local(path.clone(), 0),
            expected_digest: sample_expected_digest("blake3"),
            link_digest: sample_link_digest(0),
        };
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Layers,
            layers: vec![layer],
            extract: Some(path.clone()),
        };
        let decoded = Blueprint::decode(&blueprint.encode());
        assert_eq!(blueprint, decoded);
    }

    #[test]
    #[should_panic(expected = "blueprint format marker mismatch")]
    fn blueprint_rejects_wrong_format_marker() {
        let mut bytes = vec![0x01u8];
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.push(0);
        let _ = Blueprint::decode(&bytes);
    }

    #[test]
    #[should_panic(expected = "blueprint decoding: input truncated")]
    fn blueprint_rejects_truncated_payload() {
        let mut bytes = vec![BLUEPRINT_FORMAT_MARKER];
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(Namespace::Kernel.to_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.push(LINK_LOCAL);
        // missing payload length and payload
        let _ = Blueprint::decode(&bytes);
    }

    #[test]
    #[should_panic(expected = "unknown ArtifactLink variant")]
    fn blueprint_rejects_unknown_link_variant() {
        let mut bytes = vec![BLUEPRINT_FORMAT_MARKER];
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(Namespace::Kernel.to_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        // layer UUID
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.push(0xff);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u128.to_be_bytes());
        // ExpectedDigest: discriminant + len + payload (sha256, 32 bytes)
        bytes.push(2);
        bytes.extend_from_slice(&32u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&[0u8; 48]);
        bytes.push(0);
        let _ = Blueprint::decode(&bytes);
    }

    #[test]
    #[should_panic(expected = "blueprint decoding: did not consume")]
    fn blueprint_rejects_trailing_bytes() {
        let blueprint = Blueprint {
            target_entry_uuid: Uuid::nil(),
            target_entry_namespace: Namespace::Kernel,
            layers: vec![],
            extract: None,
        };
        let mut encoded = blueprint.encode();
        encoded.push(0xff);
        let _ = Blueprint::decode(&encoded);
    }

    #[test]
    fn type_names_are_versioned() {
        assert_eq!(
            <FileRef as Value>::type_name().name(),
            "image::storage::FileRef/v1"
        );
        assert_eq!(
            <Blueprint as Value>::type_name().name(),
            "image::storage::Blueprint/v3"
        );
        assert_eq!(
            <LinkRef as Value>::type_name().name(),
            "image::storage::LinkRef/v2"
        );
    }

    #[test]
    fn value_inverse_of_from_bytes() {
        let entry = FileRef {
            uuid: Uuid::nil(),
            namespace: Namespace::Layers,
            file_digest: sample_file_digest(5),
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::Gzip,
        };
        let bytes = <FileRef as Value>::as_bytes(&entry);
        let recovered = <FileRef as Value>::from_bytes(bytes.as_ref());
        assert_eq!(entry, recovered);
    }
}
