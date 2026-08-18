use blake3::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkDigest {
    pub link_hash: Hash,
    pub file_size: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileDigest {
    pub file_hash: Hash,
    pub file_size: u128,
}

/// Canonical domain-separated [`LinkDigest`] builder.
///
/// Every identity that is derived rather than content-addressed uses an
/// explicit domain prefix and a deterministic encoding: fixed-width
/// big-endian integers and length-prefixed byte fields. The encoding never
/// relies on `Debug`, JSON object order, or platform-native path encoding, so
/// two processes on any host derive the same digest from the same logical
/// inputs.
#[derive(Debug)]
pub struct LinkDigestBuilder {
    hasher: blake3::Hasher,
}

impl LinkDigestBuilder {
    /// Start a new digest with the domain-separation prefix `domain`.
    pub fn new(domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        Self { hasher }
    }

    /// Append a length-prefixed tagged byte field.
    pub fn bytes(mut self, tag: &[u8], value: &[u8]) -> Self {
        self.hasher.update(&(tag.len() as u64).to_be_bytes());
        self.hasher.update(tag);
        self.hasher.update(&(value.len() as u64).to_be_bytes());
        self.hasher.update(value);
        self
    }

    /// Append a length-prefixed tagged string field.
    pub fn str(self, tag: &[u8], value: &str) -> Self {
        self.bytes(tag, value.as_bytes())
    }

    /// Append a fixed-width (16-byte big-endian) tagged integer field.
    pub fn u128(mut self, tag: &[u8], value: u128) -> Self {
        self.hasher.update(&(tag.len() as u64).to_be_bytes());
        self.hasher.update(tag);
        self.hasher.update(&value.to_be_bytes());
        self
    }

    /// Append a fixed-width (8-byte big-endian) tagged integer field.
    pub fn u64(mut self, tag: &[u8], value: u64) -> Self {
        self.hasher.update(&(tag.len() as u64).to_be_bytes());
        self.hasher.update(tag);
        self.hasher.update(&value.to_be_bytes());
        self
    }

    /// Finalize the digest, carrying the caller-selected size.
    pub fn finish(self, file_size: u128) -> LinkDigest {
        LinkDigest {
            link_hash: self.hasher.finalize(),
            file_size,
        }
    }
}

/// A digest declared by an external source such as an OCI manifest.
///
/// Unlike [`FileDigest`], which always identifies locally materialized bytes
/// with BLAKE3, an `ExpectedDigest` preserves the algorithm reported by the
/// source and is only used to verify the bytes that a blob delivers. It is
/// never converted into a `FileDigest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpectedDigest {
    Blake3([u8; 32]),
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

/// Parsing failure for [`ExpectedDigest::parse`].
#[derive(Debug, thiserror::Error)]
pub enum ExpectedDigestError {
    #[error("expected digest must use the `<algorithm>:<hex>` form")]
    MissingSeparator,
    #[error("unsupported digest algorithm: {0:?}")]
    UnsupportedAlgorithm(String),
    #[error("digest hex payload has an invalid length for {algorithm:?}: {length} bytes")]
    InvalidLength {
        algorithm: &'static str,
        length: usize,
    },
    #[error("digest hex payload contains a non-hexadecimal character")]
    InvalidHex,
}

impl ExpectedDigest {
    /// Parse a digest of the form `<algorithm>:<hex>`.
    ///
    /// Accepts only `sha256`, `sha512` and `blake3`. The hex payload must
    /// match the algorithm's expected byte width.
    pub fn parse(value: &str) -> Result<Self, error_stack::Report<ExpectedDigestError>> {
        let (algorithm, hex) = value
            .split_once(':')
            .ok_or_else(|| error_stack::Report::new(ExpectedDigestError::MissingSeparator))?;

        let parsed = match algorithm {
            "blake3" => {
                let bytes = decode_hex(hex, 32).map_err(|err| match err {
                    HexError::InvalidLength => ExpectedDigestError::InvalidLength {
                        algorithm: "blake3",
                        length: hex.len(),
                    }
                    .report(),
                    HexError::InvalidChar => ExpectedDigestError::InvalidHex.report(),
                })?;
                Self::Blake3(bytes)
            }
            "sha256" => {
                let bytes = decode_hex(hex, 32).map_err(|err| match err {
                    HexError::InvalidLength => ExpectedDigestError::InvalidLength {
                        algorithm: "sha256",
                        length: hex.len(),
                    }
                    .report(),
                    HexError::InvalidChar => ExpectedDigestError::InvalidHex.report(),
                })?;
                Self::Sha256(bytes)
            }
            "sha512" => {
                let bytes = decode_hex(hex, 64).map_err(|err| match err {
                    HexError::InvalidLength => ExpectedDigestError::InvalidLength {
                        algorithm: "sha512",
                        length: hex.len(),
                    }
                    .report(),
                    HexError::InvalidChar => ExpectedDigestError::InvalidHex.report(),
                })?;
                Self::Sha512(bytes)
            }
            other => {
                return Err(ExpectedDigestError::UnsupportedAlgorithm(other.to_string()).report());
            }
        };

        Ok(parsed)
    }

    /// Compare the expected digest with one computed during reading.
    pub fn verify(&self, computed: &ComputedDigest) -> bool {
        match (self, computed) {
            (Self::Blake3(expected), ComputedDigest::Blake3(actual)) => expected == actual,
            (Self::Sha256(expected), ComputedDigest::Sha256(actual)) => expected == actual,
            (Self::Sha512(expected), ComputedDigest::Sha512(actual)) => expected == actual,
            _ => false,
        }
    }

    /// Persisted discriminant for `ExpectedDigest`.
    pub fn discriminant(&self) -> u8 {
        const DISCRIMINANT_BLAKE3: u8 = 1;
        const DISCRIMINANT_SHA256: u8 = 2;
        const DISCRIMINANT_SHA512: u8 = 3;
        match self {
            Self::Blake3(_) => DISCRIMINANT_BLAKE3,
            Self::Sha256(_) => DISCRIMINANT_SHA256,
            Self::Sha512(_) => DISCRIMINANT_SHA512,
        }
    }

    /// Raw digest bytes in declared order.
    pub fn digest_bytes(&self) -> &[u8] {
        match self {
            Self::Blake3(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }

    /// Fixed byte length of the variant's digest payload.
    #[expect(dead_code, reason = "kept for wire-format and size validation")]
    pub(crate) fn byte_len(&self) -> usize {
        self.digest_bytes().len()
    }

    pub fn from_parts(discriminant: u8, bytes: &[u8]) -> Option<Self> {
        let result = match (discriminant, bytes.len()) {
            (1, 32) => Self::Blake3(bytes.try_into().unwrap()),
            (2, 32) => Self::Sha256(bytes.try_into().unwrap()),
            (3, 64) => Self::Sha512(bytes.try_into().unwrap()),
            _ => return None,
        };
        Some(result)
    }
}

/// A digest computed locally while reading or copying bytes.
///
/// Each variant corresponds to an algorithm accepted by [`ExpectedDigest`].
/// `verify` refuses to compare across algorithms so a SHA-256 expectation
/// can never be silently matched against a BLAKE3 result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputedDigest {
    Blake3([u8; 32]),
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

enum HexError {
    InvalidLength,
    InvalidChar,
}

fn decode_hex<const N: usize>(hex: &str, expected_bytes: usize) -> Result<[u8; N], HexError> {
    if hex.len() != expected_bytes * 2 {
        return Err(HexError::InvalidLength);
    }
    let mut out = [0u8; N];
    let bytes = hex.as_bytes();
    for (i, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[i * 2])?;
        let low = hex_nibble(bytes[i * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HexError::InvalidChar),
    }
}

impl ExpectedDigestError {
    fn report(self) -> error_stack::Report<ExpectedDigestError> {
        error_stack::Report::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blake3_round_trip() {
        let value = "blake3:".to_string() + &"ab".repeat(32);
        let parsed = ExpectedDigest::parse(&value).expect("valid blake3");
        assert!(matches!(parsed, ExpectedDigest::Blake3(_)));
    }

    #[test]
    fn sha256_is_distinct_from_blake3_with_same_bytes() {
        let bytes = [0u8; 32];
        let sha = ExpectedDigest::Sha256(bytes);
        let blake = ExpectedDigest::Blake3(bytes);
        assert_ne!(sha, blake);
        assert_eq!(sha.discriminant(), 2);
        assert_eq!(blake.discriminant(), 1);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let value = "md5:".to_string() + &"00".repeat(16);
        let err = ExpectedDigest::parse(&value).expect_err("unsupported algorithm");
        assert!(matches!(
            err.current_context(),
            ExpectedDigestError::UnsupportedAlgorithm(algorithm) if algorithm == "md5"
        ));
    }

    #[test]
    fn rejects_wrong_hex_length() {
        let value = "sha256:00";
        let err = ExpectedDigest::parse(value).expect_err("invalid length");
        assert!(matches!(
            err.current_context(),
            ExpectedDigestError::InvalidLength {
                algorithm: "sha256",
                length: 2
            }
        ));
    }

    #[test]
    fn rejects_non_hex_chars() {
        let value = "sha256:".to_string() + &"zz".repeat(32);
        let err = ExpectedDigest::parse(&value).expect_err("invalid hex");
        assert!(matches!(
            err.current_context(),
            ExpectedDigestError::InvalidHex
        ));
    }

    #[test]
    fn verify_compares_matching_algorithm() {
        let bytes = [0xab; 32];
        let sha_expected = ExpectedDigest::Sha256(bytes);
        let sha_computed = ComputedDigest::Sha256(bytes);
        assert!(sha_expected.verify(&sha_computed));

        let blake_computed = ComputedDigest::Blake3(bytes);
        assert!(!sha_expected.verify(&blake_computed));
    }
}
