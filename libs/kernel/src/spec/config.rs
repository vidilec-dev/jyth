//! Validated kernel build configurations.
//!
//! A `KernelConfig` distinguishes a Kconfig *fragment* (merged through
//! `KCONFIG_ALLCONFIG`/`allnoconfig`) from a *complete* `.config` file
//! (applied directly and resolved with `olddefconfig`). Construction validates
//! and canonicalizes the content:
//!
//! - empty values, NUL bytes, non-UTF-8 content, and content larger than
//!   4 MiB are rejected;
//! - CRLF line endings are normalized to LF;
//! - the final newline is normalized to exactly one LF;
//! - comments and assignment order are preserved.
//!
//! `Debug` redacts the configuration bytes, and the canonical bytes are
//! exposed to the compiler adapter and the cache-key builder.

use std::fmt;
use std::path::PathBuf;

use bytes::Bytes;

/// Whether the configuration is a Kconfig fragment or a complete `.config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelConfigMode {
    /// A Kconfig fragment merged through `KCONFIG_ALLCONFIG`/`allnoconfig`.
    Fragment,
    /// A complete `.config` applied directly and resolved with `olddefconfig`.
    Complete,
}

/// Validation failure for [`KernelConfig`].
///
/// Every variant identifies the rejected input class with a stable reason
/// category; configuration bytes never appear in diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum KernelConfigError {
    /// The configuration is empty.
    #[error("kernel configuration must not be empty")]
    Empty,
    /// The configuration contains a NUL byte.
    #[error("kernel configuration must not contain a NUL byte")]
    NulByte,
    /// The configuration is not UTF-8 text.
    #[error("kernel configuration must be UTF-8 text")]
    NonUtf8,
    /// The configuration exceeds the 4 MiB limit.
    #[error("kernel configuration must not exceed 4 MiB")]
    TooLarge,
    /// A host file could not be read.
    #[error("failed to read kernel configuration from {path}")]
    Read {
        /// The path that failed to read.
        path: PathBuf,
        /// The original I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Manual equality for tests: variants compare by category, and `Read`
/// compares by path only (the source error is not `Eq`).
impl PartialEq for KernelConfigError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (Self::NulByte, Self::NulByte) => true,
            (Self::NonUtf8, Self::NonUtf8) => true,
            (Self::TooLarge, Self::TooLarge) => true,
            (Self::Read { path: a, .. }, Self::Read { path: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl Eq for KernelConfigError {}

/// Maximum accepted configuration size.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// A validated kernel build configuration.
#[derive(Clone)]
pub struct KernelConfig {
    mode: KernelConfigMode,
    bytes: Bytes,
}

impl KernelConfig {
    /// Construct a Kconfig fragment from validated in-memory bytes.
    pub fn fragment(bytes: impl AsRef<[u8]>) -> Result<Self, KernelConfigError> {
        Ok(Self {
            mode: KernelConfigMode::Fragment,
            bytes: normalize(bytes.as_ref(), KernelConfigMode::Fragment)?,
        })
    }

    /// Construct a complete `.config` from validated in-memory bytes.
    pub fn complete(bytes: impl AsRef<[u8]>) -> Result<Self, KernelConfigError> {
        Ok(Self {
            mode: KernelConfigMode::Complete,
            bytes: normalize(bytes.as_ref(), KernelConfigMode::Complete)?,
        })
    }

    /// Read one host file as a complete `.config`.
    pub fn read_complete(path: impl AsRef<std::path::Path>) -> Result<Self, KernelConfigError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| KernelConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::complete(bytes)
    }

    /// The canonical configuration bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether this value is a fragment or a complete configuration.
    pub fn mode(&self) -> KernelConfigMode {
        self.mode
    }
}

impl Default for KernelConfig {
    /// The versioned Jyth fragment stored as a repository asset. The asset
    /// is compiled in, so construction cannot fail at runtime; a broken
    /// asset is a build-time contract violation caught by tests.
    fn default() -> Self {
        let asset = include_str!("../../assets/jyth.config");
        Self::fragment(asset).expect("compiled-in default Jyth fragment must be valid")
    }
}

/// Validate and canonicalize configuration bytes: reject empty/NUL/non-UTF-8/
/// oversized values, normalize CRLF to LF, and normalize the final newline to
/// exactly one LF while preserving comments and assignment order.
fn normalize(bytes: &[u8], _mode: KernelConfigMode) -> Result<Bytes, KernelConfigError> {
    if bytes.is_empty() {
        return Err(KernelConfigError::Empty);
    }
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(KernelConfigError::TooLarge);
    }
    if bytes.contains(&0) {
        return Err(KernelConfigError::NulByte);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| KernelConfigError::NonUtf8)?;

    // CRLF -> LF, then strip trailing newlines and re-append exactly one LF.
    let lf = text.replace("\r\n", "\n");
    let trimmed = lf.trim_end_matches('\n');
    let mut canonical = String::with_capacity(trimmed.len() + 1);
    canonical.push_str(trimmed);
    canonical.push('\n');
    Ok(Bytes::from(canonical.into_bytes()))
}

/// `Debug` redacts the configuration bytes.
impl fmt::Debug for KernelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelConfig")
            .field("mode", &self.mode)
            .field("bytes", &format!("<redacted {} bytes>", self.bytes.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_and_complete_preserve_modes() {
        let fragment = KernelConfig::fragment(b"CONFIG_FOO=y").expect("fragment");
        assert_eq!(fragment.mode(), KernelConfigMode::Fragment);
        let complete = KernelConfig::complete(b"CONFIG_FOO=y").expect("complete");
        assert_eq!(complete.mode(), KernelConfigMode::Complete);
    }

    #[test]
    fn preserves_comments_and_assignment_order() {
        let input = b"# comment\nCONFIG_A=y\n\nCONFIG_B=y\n";
        let config = KernelConfig::complete(input).expect("valid");
        let text = String::from_utf8(config.as_bytes().to_vec()).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "# comment");
        assert_eq!(lines[1], "CONFIG_A=y");
        assert_eq!(lines[3], "CONFIG_B=y");
    }

    #[test]
    fn normalizes_crlf_to_lf() {
        let config = KernelConfig::complete(b"CONFIG_A=y\r\nCONFIG_B=y\r\n").expect("valid");
        assert_eq!(config.as_bytes(), b"CONFIG_A=y\nCONFIG_B=y\n");
    }

    #[test]
    fn normalizes_the_final_newline_to_exactly_one_lf() {
        for input in [b"CONFIG_A=y".as_slice(), b"CONFIG_A=y\n\n\n".as_slice()] {
            let config = KernelConfig::complete(input).expect("valid");
            assert_eq!(config.as_bytes(), b"CONFIG_A=y\n", "{input:?}");
        }
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(
            KernelConfig::complete(b"").expect_err("empty"),
            KernelConfigError::Empty
        );
        assert_eq!(
            KernelConfig::fragment(b"").expect_err("empty"),
            KernelConfigError::Empty
        );
    }

    #[test]
    fn rejects_nul_bytes() {
        assert_eq!(
            KernelConfig::complete(b"CONFIG_A=y\0").expect_err("nul"),
            KernelConfigError::NulByte
        );
    }

    #[test]
    fn rejects_non_utf8_content() {
        assert_eq!(
            KernelConfig::complete(b"CONFIG_A=\xff").expect_err("non utf8"),
            KernelConfigError::NonUtf8
        );
    }

    #[test]
    fn rejects_content_larger_than_4_mib() {
        let mut oversized = vec![b'a'; MAX_CONFIG_BYTES + 1];
        oversized.push(b'\n');
        assert_eq!(
            KernelConfig::complete(&oversized).expect_err("too large"),
            KernelConfigError::TooLarge
        );
    }

    #[test]
    fn read_complete_surfaces_the_original_io_error() {
        let missing = std::env::temp_dir().join(format!("missing-{}.config", uuid::Uuid::now_v7()));
        let err = KernelConfig::read_complete(&missing).expect_err("missing");
        match err {
            KernelConfigError::Read { path, source } => {
                assert_eq!(path, missing);
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn read_complete_loads_a_file() {
        let mut file = tempfile::NamedTempFile::new().expect("temp");
        std::io::Write::write_all(&mut file, b"CONFIG_A=y\r\n").expect("write");
        let config = KernelConfig::read_complete(file.path()).expect("read");
        assert_eq!(config.mode(), KernelConfigMode::Complete);
        assert_eq!(config.as_bytes(), b"CONFIG_A=y\n");
    }

    #[test]
    fn default_returns_the_versioned_jyth_fragment() {
        let config = KernelConfig::default();
        assert_eq!(config.mode(), KernelConfigMode::Fragment);
        let text = String::from_utf8(config.as_bytes().to_vec()).expect("utf8");
        for required in [
            "CONFIG_BLK_DEV_INITRD=y",
            "CONFIG_HYPERV_NET=y",
            "CONFIG_HYPERV_STORAGE=y",
            "CONFIG_INET=y",
            "CONFIG_NETDEVICES=y",
            "CONFIG_EXT4_FS=y",
            "CONFIG_MODULES=n",
        ] {
            assert!(text.contains(required), "missing {required}");
        }
    }

    #[test]
    fn default_fragment_requires_no_vsock_option() {
        // The TCP transport migration removed vsock from the command path:
        // the Jyth fragment must never require a vsock or Hyper-V socket
        // configuration option.
        let config = KernelConfig::default();
        let text = String::from_utf8(config.as_bytes().to_vec()).expect("utf8");
        for forbidden in ["CONFIG_VSOCKETS", "CONFIG_HYPERV_VSOCKETS"] {
            assert!(!text.contains(forbidden), "must not require {forbidden}");
        }
    }

    #[test]
    fn debug_redacts_configuration_bytes() {
        let config = KernelConfig::complete(b"CONFIG_SECRET=y").expect("valid");
        let debug = format!("{config:?}");
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
    }

    #[test]
    fn canonical_bytes_are_stable_across_spellings() {
        let a = KernelConfig::complete(b"CONFIG_A=y\n\n").expect("a");
        let b = KernelConfig::complete(b"CONFIG_A=y").expect("b");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
