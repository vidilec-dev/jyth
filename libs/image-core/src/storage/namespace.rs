use std::{
    env::current_dir,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use crate::digest::{ExpectedDigest, FileDigest, LinkDigest};

pub struct NamespaceDir {
    pub root: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub layers: PathBuf,
    pub modules: PathBuf,
}

/// Process-wide namespace directories, initialized once. Must be a
/// `static`, not a `const`: a `const` with interior mutability re-evaluates
/// the initializer at every use, which would re-create directories and
/// recompute paths on each access.
pub static NAMESPACES: LazyLock<NamespaceDir> = LazyLock::new(|| {
    let root = if let Ok(root) = std::env::var("CARGO_MANIFEST_DIR") {
        // Cache generation 4: kernel keys now include the normalized kernel
        // path and OCI keys resolve mutable tags to immutable manifest
        // digests, so the v3 codecs and keys are not compatible. A versioned
        // root prevents an older index and newer artifact paths from being
        // mixed accidentally; v3 data is left untouched for recoverability.
        PathBuf::from(root).join("target").join(".jyth-v4")
    } else {
        current_dir().unwrap().join(".jyth-v4")
    };
    let kernel = root.join("kernel");
    let rootfs = root.join("rootfs");
    let layers = root.join("layers");
    let modules = root.join("modules");
    std::fs::create_dir_all(&kernel).unwrap();
    std::fs::create_dir_all(&rootfs).unwrap();
    std::fs::create_dir_all(&layers).unwrap();
    std::fs::create_dir_all(&modules).unwrap();
    NamespaceDir {
        root,
        kernel,
        rootfs,
        layers,
        modules,
    }
});

/// Canonical namespace tags used to physically locate a cached entry.
///
/// The persisted numeric discriminants are stable identifiers written to the
/// index. Do not derive them from declaration order: reordering the variants
/// must not change the persisted value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    Kernel = 1,
    Rootfs = 2,
    Layers = 3,
    Modules = 4,
}

impl Namespace {
    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        match self {
            Namespace::Kernel => NAMESPACES.kernel.join(path),
            Namespace::Rootfs => NAMESPACES.rootfs.join(path),
            Namespace::Layers => NAMESPACES.layers.join(path),
            Namespace::Modules => NAMESPACES.modules.join(path),
        }
    }

    pub fn to_bytes(self) -> u8 {
        self as u8
    }

    pub fn from_bytes(value: u8) -> Option<Self> {
        match value {
            1 => Some(Namespace::Kernel),
            2 => Some(Namespace::Rootfs),
            3 => Some(Namespace::Layers),
            4 => Some(Namespace::Modules),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamespacedLinkDigest {
    pub namespace: Namespace,
    pub link_digest: LinkDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamespacedFileDigest {
    pub namespace: Namespace,
    pub file_digest: FileDigest,
}

/// A digest declared by an external source, namespaced to a layer set.
///
/// Used to validate bytes that a layer delivers against the manifest's
/// declared digest. A local `FileDigest` is never derived from this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[expect(
    dead_code,
    reason = "declared-digest validation seam for layer ingestion"
)]
pub(crate) struct NamespacedExpectedDigest {
    pub(crate) namespace: Namespace,
    pub(crate) expected_digest: ExpectedDigest,
}
