use std::path::{Path, PathBuf};

use super::permissions::Permissions;

/// Identifies a Rust binary that Jyth should compile and inject.
///
/// The manifest path must point directly to a `Cargo.toml` file. When a
/// package exposes more than one binary, set [`RustBinary::bin`] to select
/// the binary explicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustBinary {
    manifest_path: PathBuf,
    binary_name: Option<String>,
}

impl RustBinary {
    /// Creates a Rust-binary specification from an explicit manifest path.
    pub fn new(manifest_path: impl Into<PathBuf>) -> Self {
        Self {
            manifest_path: manifest_path.into(),
            binary_name: None,
        }
    }

    /// Selects a package binary by name.
    pub fn bin(mut self, name: impl Into<String>) -> Self {
        self.binary_name = Some(name.into());
        self
    }

    /// Returns the explicit `Cargo.toml` path.
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Returns the selected package binary, if one was specified.
    pub fn binary_name(&self) -> Option<&str> {
        self.binary_name.as_deref()
    }

    /// Returns the source identity used by derived overlay materialization.
    pub(crate) fn cache_identity(&self) -> String {
        let mut identity = self.manifest_path.to_string_lossy().into_owned();
        if let Some(binary_name) = &self.binary_name {
            identity.push_str("|bin=");
            identity.push_str(binary_name);
        }
        identity
    }
}

/// A regular file entry to create in the guest initramfs.
pub struct File {
    path: Option<PathBuf>,
    mode: u32,
    content: Option<FileContent>,
}

impl Default for File {
    fn default() -> Self {
        Self::new()
    }
}

/// Content source for an injected guest file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileContent {
    /// Literal bytes copied into the guest file.
    Bytes(Vec<u8>),
    /// A Rust binary built and copied into the guest file.
    Crate(RustBinary),
}

impl From<Vec<u8>> for FileContent {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}

impl From<&[u8]> for FileContent {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(v.to_vec())
    }
}

impl From<RustBinary> for FileContent {
    fn from(binary: RustBinary) -> Self {
        Self::Crate(binary)
    }
}

impl File {
    /// Creates an empty regular-file specification with mode `0644`.
    pub fn new() -> Self {
        Self {
            path: None,
            content: None,
            mode: 0o644,
        }
    }

    /// Sets the guest path for this file.
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the file contents.
    pub fn content(mut self, content: impl Into<FileContent>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Sets all owner, group, and other permission bits.
    pub fn permissions(mut self, perm: Permissions) -> Self {
        let p = perm.bits();
        self.mode = (self.mode & !0o777) | (p << 6) | (p << 3) | p;
        self
    }

    /// Sets the owner permission bits.
    pub fn user_permissions(mut self, perm: Permissions) -> Self {
        self.mode = (self.mode & !0o700) | (perm.bits() << 6);
        self
    }

    /// Sets the group permission bits.
    pub fn group_permissions(mut self, perm: Permissions) -> Self {
        self.mode = (self.mode & !0o070) | (perm.bits() << 3);
        self
    }

    /// Read accessors used by the build/overlay module.
    pub(crate) fn path_ref(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
    pub(crate) fn content_ref(&self) -> Option<&FileContent> {
        self.content.as_ref()
    }
    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_binary_keeps_an_explicit_manifest_and_optional_binary_name() {
        let spec = RustBinary::new("examples/tool/Cargo.toml").bin("tool");

        assert_eq!(spec.manifest_path(), Path::new("examples/tool/Cargo.toml"));
        assert_eq!(spec.binary_name(), Some("tool"));
        assert_eq!(spec.cache_identity(), "examples/tool/Cargo.toml|bin=tool");
    }
}
