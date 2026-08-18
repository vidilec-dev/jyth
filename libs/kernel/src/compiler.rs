//! The custom-kernel compiler port.
//!
//! The `kernel` crate defines the compilation contract without depending on
//! Jyth or any VM type: a [`KernelCompiler`] exposes one immutable
//! [`KernelCompilerIdentity`] (available without network or filesystem I/O)
//! and compiles a [`CustomKernelSpec`] into a [`CompiledKernel`] owning one
//! unpublished staging file. The materialization service derives the custom
//! request digest from the identity and the specification, checks the cache,
//! serializes identical builds, and only then invokes the compiler.
//!
//! The port never exposes `VmBuilder`, HCS, guest-client, or protocol types;
//! the Jyth adapter implements it in `libs/jyth/src/build/kernel_compile.rs`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use error_stack::Report;
use thiserror::Error;

use crate::CustomKernelSpec;

/// Version of the binary identity encoding. Bump when the field set changes
/// so old identities can never satisfy new cache keys.
const IDENTITY_FORMAT_VERSION: u8 = 2;

/// Failures returned by a [`KernelCompiler`].
///
/// Every variant names a stable failure stage. A guest-build failure retains
/// the guest exit status and bounded stderr evidence. A cleanup failure never
/// replaces an earlier compilation failure: the adapter keeps the primary
/// failure and attaches the cleanup failure to the same report.
#[derive(Debug, Error)]
pub enum KernelCompilerError {
    /// The compiler identity is invalid.
    #[error("invalid compiler identity")]
    InvalidIdentity,
    /// Compiler planning failed before the bootstrap VM launched.
    #[error("compiler planning failed")]
    Planning,
    /// The bootstrap VM could not be launched.
    #[error("bootstrap VM launch failed")]
    BootstrapLaunch,
    /// The guest build failed. The exit status and bounded stderr evidence
    /// are retained.
    #[error("guest build failed with exit status {exit_status}")]
    GuestBuild {
        /// The guest build process exit status.
        exit_status: u32,
        /// Bounded stderr evidence from the failed guest build.
        stderr: String,
    },
    /// The built bzImage could not be transferred out of the guest.
    #[error("built kernel artifact transfer failed")]
    ArtifactTransfer,
    /// The compiled output failed validation.
    #[error("compiled kernel validation failed")]
    Validation,
    /// Allocation or validation of the generated build-disk path failed.
    #[error("build-disk allocation or validation failed")]
    BuildDisk,
    /// Cleanup of the bootstrap VM, build disk, or staging artifacts failed.
    /// Attached to the primary failure; never a replacement for it.
    #[error("compiler cleanup failed")]
    Cleanup,
    /// The validated output could not be published to the cache.
    #[error("compiled kernel cache publication failed")]
    CachePublication,
}

/// The immutable identity of one compiler recipe.
///
/// Contains every output-affecting input that is knowable without network or
/// filesystem I/O: the recipe version, the digest of the in-guest build
/// script, the bootstrap kernel and toolchain rootfs digests, the target
/// architecture, and deterministic Kbuild metadata. The value is encoded with
/// a versioned, length-prefixed binary format for the custom request digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCompilerIdentity {
    recipe_version: u32,
    script_digest: String,
    bootstrap_kernel_digest: String,
    toolchain_rootfs_digest: String,
    target_arch: String,
    kbuild_metadata: String,
}

impl KernelCompilerIdentity {
    /// Construct an identity from its immutable fields.
    ///
    /// Digest fields must use the `<algorithm>:<hex>` form with a supported
    /// algorithm (`sha256` or `sha512`) so a malformed compiled-in identity
    /// is rejected at construction rather than poisoning the cache key.
    pub fn new(
        recipe_version: u32,
        script_digest: impl Into<String>,
        bootstrap_kernel_digest: impl Into<String>,
        toolchain_rootfs_digest: impl Into<String>,
        target_arch: impl Into<String>,
        kbuild_metadata: impl Into<String>,
    ) -> Result<Self, KernelCompilerError> {
        let identity = Self {
            recipe_version,
            script_digest: script_digest.into(),
            bootstrap_kernel_digest: bootstrap_kernel_digest.into(),
            toolchain_rootfs_digest: toolchain_rootfs_digest.into(),
            target_arch: target_arch.into(),
            kbuild_metadata: kbuild_metadata.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// The compiler recipe version.
    pub fn recipe_version(&self) -> u32 {
        self.recipe_version
    }

    /// The target architecture the compiler produces.
    pub fn target_arch(&self) -> &str {
        &self.target_arch
    }

    /// Encode the identity with a versioned, length-prefixed binary format.
    ///
    /// The encoding is deterministic and platform-independent; it is hashed
    /// into the custom request digest so a change to any output-affecting
    /// identity field produces a cache miss.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(IDENTITY_FORMAT_VERSION);
        put_u32(&mut out, self.recipe_version);
        put_str(&mut out, &self.script_digest);
        put_str(&mut out, &self.bootstrap_kernel_digest);
        put_str(&mut out, &self.toolchain_rootfs_digest);
        put_str(&mut out, &self.target_arch);
        put_str(&mut out, &self.kbuild_metadata);
        out
    }

    fn validate(&self) -> Result<(), KernelCompilerError> {
        for digest in [
            &self.script_digest,
            &self.bootstrap_kernel_digest,
            &self.toolchain_rootfs_digest,
        ] {
            let Some((algorithm, hex)) = digest.split_once(':') else {
                return Err(KernelCompilerError::InvalidIdentity);
            };
            let expected_len = match algorithm {
                "sha256" => 64,
                "sha512" => 128,
                _ => return Err(KernelCompilerError::InvalidIdentity),
            };
            if hex.len() != expected_len || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(KernelCompilerError::InvalidIdentity);
            }
        }
        if self.target_arch.is_empty() {
            return Err(KernelCompilerError::InvalidIdentity);
        }
        Ok(())
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// The custom kernel compilation port.
///
/// Implementations must be `Send` and `Sync`. `identity` must be available
/// without starting any I/O, so the service can derive the request digest
/// before compilation begins. `compile` returns a boxed `Send` future so the
/// recursive bootstrap call graph stays finite at the Rust type level.
pub trait KernelCompiler: Send + Sync {
    /// The immutable recipe identity, available without I/O.
    fn identity(&self) -> &KernelCompilerIdentity;

    /// Compile `spec` into a staged bzImage.
    fn compile<'a>(
        &'a self,
        spec: &'a CustomKernelSpec,
    ) -> Pin<
        Box<dyn Future<Output = Result<CompiledKernel, Report<KernelCompilerError>>> + Send + 'a>,
    >;
}

/// A completed compiler output: one unpublished staging file.
///
/// The value does not claim the output is a valid kernel before the
/// materialization service validates it; [`Drop`] removes the staging file on
/// a best-effort basis, so an unpublished output never leaks onto the host.
#[derive(Debug)]
pub struct CompiledKernel {
    path: PathBuf,
}

impl CompiledKernel {
    /// Wrap a completed staging file. Rejects an empty path or a path that is
    /// not a regular file.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, KernelCompilerError> {
        let path = path.into();
        if path.as_os_str().is_empty() || !path.is_file() {
            return Err(KernelCompilerError::Validation);
        }
        Ok(Self { path })
    }

    /// Lend the staging path to the materialization service.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CompiledKernel {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    #[test]
    fn identity_encodes_deterministically() {
        let identity = KernelCompilerIdentity::new(
            1,
            sha256_hex(0x11),
            sha256_hex(0x22),
            sha256_hex(0x33),
            "x86_64",
            "kb=1",
        )
        .expect("valid");
        let encoded = identity.encode();
        let again = identity.encode();
        assert_eq!(encoded, again);
        // Version prefix + fields are present and deterministic.
        assert_eq!(encoded[0], IDENTITY_FORMAT_VERSION);
    }

    #[test]
    fn identity_rejects_malformed_digests() {
        let digests: Vec<String> = vec![
            "latest".to_string(),
            "md5:abcd".to_string(),
            "sha256:not-hex".to_string(),
            format!("sha256:{}", "a".repeat(63)),
        ];
        for digest in digests {
            let err = KernelCompilerIdentity::new(
                1,
                digest.clone(),
                sha256_hex(0x22),
                sha256_hex(0x33),
                "x86_64",
                "",
            )
            .expect_err("invalid digest");
            assert!(
                matches!(err, KernelCompilerError::InvalidIdentity),
                "{digest}"
            );
        }
    }

    #[test]
    fn identity_rejects_an_empty_arch() {
        let err = KernelCompilerIdentity::new(
            1,
            sha256_hex(0x11),
            sha256_hex(0x22),
            sha256_hex(0x33),
            "",
            "",
        )
        .expect_err("empty arch");
        assert!(matches!(err, KernelCompilerError::InvalidIdentity));
    }

    #[test]
    fn compiled_kernel_rejects_empty_and_missing_paths() {
        assert!(matches!(
            CompiledKernel::new(PathBuf::new()).expect_err("empty"),
            KernelCompilerError::Validation
        ));
        let missing = std::env::temp_dir().join(format!("missing-{}.bin", uuid::Uuid::now_v7()));
        assert!(matches!(
            CompiledKernel::new(missing).expect_err("missing"),
            KernelCompilerError::Validation
        ));
    }

    #[test]
    fn compiled_kernel_drop_removes_the_staging_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("staged-bzimage");
        std::fs::write(&path, b"kernel").expect("write");
        {
            let compiled = CompiledKernel::new(&path).expect("valid file");
            assert_eq!(compiled.path(), path);
        }
        assert!(!path.exists(), "drop removes the staging file");
    }
}
