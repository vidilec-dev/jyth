use std::path::PathBuf;

use super::permissions::Permissions;

/// A directory entry to create in the guest initramfs.
pub struct Dir {
    path: Option<PathBuf>,
    mode: u32,
}

impl Default for Dir {
    fn default() -> Self {
        Self::new()
    }
}

impl Dir {
    /// Creates an empty directory specification with mode `0755`.
    pub fn new() -> Self {
        Self {
            path: None,
            mode: 0o755,
        }
    }

    /// Sets the guest path for this directory.
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
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
    pub(crate) fn mode(&self) -> u32 {
        self.mode
    }
}
