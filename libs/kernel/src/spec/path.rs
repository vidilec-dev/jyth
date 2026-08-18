//! Validated kernel-entry path values.
//!
//! A `KernelPath` is a relative CPIO or OCI-rootfs entry name. The value
//! normalizes backslashes to forward slashes, removes `.` components, and
//! rejects absolute paths, Windows drive prefixes, UNC prefixes, NUL bytes,
//! `..` components, and empty interior components at construction time.
//!
//! The canonical forward-slash string is the single identity used for
//! extraction, blueprint construction, and cache keys: `./boot\vmlinuz`,
//! `boot\vmlinuz`, and `boot/vmlinuz` all normalize to `boot/vmlinuz`.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

/// Validation failure for [`KernelPath`].
///
/// Every variant identifies the rejected input class with a stable reason
/// category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum KernelPathError {
    /// The path is empty.
    #[error("kernel entry path must not be empty")]
    Empty,
    /// The path is absolute.
    #[error("kernel entry path must be relative")]
    Absolute,
    /// The path carries a Windows drive prefix (`C:\...`).
    #[error("kernel entry path must not contain a Windows drive prefix")]
    WindowsDrivePrefix,
    /// The path carries a UNC prefix (`\\...`).
    #[error("kernel entry path must not use a UNC prefix")]
    UncPrefix,
    /// The path contains a NUL byte.
    #[error("kernel entry path must not contain a NUL byte")]
    NulByte,
    /// The path contains a `..` component.
    #[error("kernel entry path must not contain `..` components")]
    ParentComponent,
    /// The path contains an empty interior component (`//` or a trailing
    /// separator).
    #[error("kernel entry path must not contain empty components")]
    EmptyComponent,
    /// The path is not valid UTF-8.
    #[error("kernel entry path must be valid UTF-8")]
    NonUtf8,
}

/// A validated, canonical kernel entry path inside an archive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KernelPath {
    canonical: String,
}

impl KernelPath {
    /// Parse and normalize `value`.
    pub fn parse(value: &str) -> Result<Self, KernelPathError> {
        if value.is_empty() {
            return Err(KernelPathError::Empty);
        }
        if value.as_bytes().contains(&0) {
            return Err(KernelPathError::NulByte);
        }
        // Reject a Windows drive prefix (`C:\...`) by sniffing the second
        // byte, independent of the host platform.
        let bytes = value.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Err(KernelPathError::WindowsDrivePrefix);
        }
        // A leading backslash is a UNC prefix or a rooted path.
        if value.starts_with('\\') {
            return Err(KernelPathError::UncPrefix);
        }
        if value.starts_with('/') {
            return Err(KernelPathError::Absolute);
        }

        let mut components: Vec<&str> = Vec::new();
        for component in value.split(['/', '\\']) {
            match component {
                "" => return Err(KernelPathError::EmptyComponent),
                "." => {}
                ".." => return Err(KernelPathError::ParentComponent),
                other => components.push(other),
            }
        }
        if components.is_empty() {
            // The value was only `.` components (e.g. `.` or `././`), which
            // canonicalizes to nothing.
            return Err(KernelPathError::Empty);
        }

        Ok(Self {
            canonical: components.join("/"),
        })
    }

    /// The canonical forward-slash path.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl FromStr for KernelPath {
    type Err = KernelPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for KernelPath {
    type Error = KernelPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<&Path> for KernelPath {
    type Error = KernelPathError;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        let text = value.to_str().ok_or(KernelPathError::NonUtf8)?;
        Self::parse(text)
    }
}

impl AsRef<str> for KernelPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for KernelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_backslashes_and_dot_components() {
        let path = KernelPath::parse("./boot\\vmlinuz").expect("valid");
        assert_eq!(path.as_str(), "boot/vmlinuz");
        assert_eq!(path.to_string(), "boot/vmlinuz");
    }

    #[test]
    fn preserves_simple_forward_slash_paths() {
        let path = KernelPath::parse("boot/vmlinuz").expect("valid");
        assert_eq!(path.as_str(), "boot/vmlinuz");
    }

    #[test]
    fn removes_interior_dot_components() {
        let path = KernelPath::parse("boot/./vmlinuz").expect("valid");
        assert_eq!(path.as_str(), "boot/vmlinuz");
    }

    #[test]
    fn equivalent_spellings_compare_equal() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = KernelPath::parse("./boot\\vmlinuz").expect("a");
        let b = KernelPath::parse("boot/vmlinuz").expect("b");
        assert_eq!(a, b);
        let mut hasher_a = DefaultHasher::new();
        let mut hasher_b = DefaultHasher::new();
        a.hash(&mut hasher_a);
        b.hash(&mut hasher_b);
        assert_eq!(hasher_a.finish(), hasher_b.finish());
    }

    #[test]
    fn rejects_empty_paths() {
        assert_eq!(
            KernelPath::parse("").expect_err("empty"),
            KernelPathError::Empty
        );
        assert_eq!(
            KernelPath::parse(".").expect_err("dot only"),
            KernelPathError::Empty
        );
        // `./` carries a trailing empty component after the dot.
        assert_eq!(
            KernelPath::parse("./").expect_err("dot slash"),
            KernelPathError::EmptyComponent
        );
    }

    #[test]
    fn rejects_absolute_paths() {
        assert_eq!(
            KernelPath::parse("/boot/vmlinuz").expect_err("absolute"),
            KernelPathError::Absolute
        );
    }

    #[test]
    fn rejects_windows_drive_prefixes() {
        assert_eq!(
            KernelPath::parse("C:\\boot\\vmlinuz").expect_err("drive"),
            KernelPathError::WindowsDrivePrefix
        );
        assert_eq!(
            KernelPath::parse("c:/boot/vmlinuz").expect_err("drive"),
            KernelPathError::WindowsDrivePrefix
        );
    }

    #[test]
    fn rejects_unc_prefixes() {
        assert_eq!(
            KernelPath::parse("\\\\server\\share\\vmlinuz").expect_err("unc"),
            KernelPathError::UncPrefix
        );
    }

    #[test]
    fn rejects_nul_bytes() {
        assert_eq!(
            KernelPath::parse("boot/vm\0linuz").expect_err("nul"),
            KernelPathError::NulByte
        );
    }

    #[test]
    fn rejects_parent_components() {
        assert_eq!(
            KernelPath::parse("../vmlinuz").expect_err("parent"),
            KernelPathError::ParentComponent
        );
        assert_eq!(
            KernelPath::parse("boot/../vmlinuz").expect_err("parent"),
            KernelPathError::ParentComponent
        );
    }

    #[test]
    fn rejects_empty_components() {
        assert_eq!(
            KernelPath::parse("boot//vmlinuz").expect_err("double slash"),
            KernelPathError::EmptyComponent
        );
        assert_eq!(
            KernelPath::parse("boot/vmlinuz/").expect_err("trailing slash"),
            KernelPathError::EmptyComponent
        );
        assert_eq!(
            KernelPath::parse("boot\\/vmlinuz").expect_err("mixed empty"),
            KernelPathError::EmptyComponent
        );
    }

    #[test]
    fn rejects_non_utf8_paths() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(b"boot/\xffvmlinuz");
            let err = KernelPath::try_from(Path::new(raw)).expect_err("non-utf8");
            assert_eq!(err, KernelPathError::NonUtf8);
        }
        // On Windows, OsStr is always UTF-8, so the host-representation
        // rejection is unreachable; the test only runs on Unix.
    }

    #[test]
    fn from_path_accepts_utf8_relative_paths() {
        let path = KernelPath::try_from(Path::new("./boot/vmlinuz")).expect("valid");
        assert_eq!(path.as_str(), "boot/vmlinuz");
    }

    #[test]
    fn round_trips_through_display_and_fromstr() {
        let path = KernelPath::parse("boot/vmlinuz").expect("valid");
        let reparsed = path.to_string().parse::<KernelPath>().expect("round trip");
        assert_eq!(path, reparsed);
    }
}
