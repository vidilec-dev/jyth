//! Internal kernel + rootfs materialization composition.
//!
//! Owns the launch-side materialization sequence: kernel first, then the
//! root filesystem, folding any extracted kernel module fragment into the
//! rootfs artifact. This is the only materialization path in Jyth — there is
//! no explicit public entry point; [`crate::build::Build`] drives it.

use std::path::PathBuf;

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use crate::builder::image::{Kernel, Rootfs};

/// Failures returned while materializing kernel/rootfs sources.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MaterializeError {
    /// Kernel acquisition or validation failed.
    #[error("failed to build kernel")]
    KernelBuild,
    /// Rootfs acquisition, validation, or module merge failed.
    #[error("failed to build root filesystem")]
    RootfsBuild,
}

/// Materialize a kernel source and optional rootfs source, merging any
/// extracted kernel module tree into the root filesystem. Returns
/// `(kernel_path, rootfs_path)`; the rootfs stays `None` when no rootfs
/// source was configured.
///
/// The kernel path uses [`kernel::materialize_with`] with the Jyth compiler
/// adapter, so a custom kernel specification compiles through the shared
/// cache; default and external kernels take the same external materialization
/// path and never launch a bootstrap VM.
pub(crate) async fn materialize_image(
    kernel: Kernel,
    rootfs: Option<Rootfs>,
    token: &CancellationToken,
) -> Result<(PathBuf, Option<PathBuf>), Report<MaterializeError>> {
    let compiler = crate::build::kernel_compile::JythKernelCompiler::new(std::env::temp_dir())
        .map_err(|error| Report::new(MaterializeError::KernelBuild).attach(error.to_string()))?;
    let materialized_kernel = ::kernel::materialize_with(&kernel, &compiler, token)
        .await
        .map_err(|error| error.change_context(MaterializeError::KernelBuild))?;

    let rootfs = match rootfs {
        None => None,
        Some(rootfs) => {
            let materialized = ::rootfs::materialize(&rootfs, token)
                .await
                .map_err(|error| error.change_context(MaterializeError::RootfsBuild))?;
            match materialized_kernel.modules {
                Some(modules) => Some(
                    ::rootfs::merge_modules(materialized.file_ref, modules, token)
                        .await
                        .map_err(|error| error.change_context(MaterializeError::RootfsBuild))?,
                ),
                None => Some(materialized.file_ref.path()),
            }
        }
    };

    Ok((materialized_kernel.kernel, rootfs))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use tempfile::NamedTempFile;

    use super::*;
    use crate::builder::image::{Kernel, Link, Rootfs};

    fn bzimage() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x206 + 16];
        bytes[0x1fe] = 0x55;
        bytes[0x1ff] = 0xaa;
        bytes[0x202..0x206].copy_from_slice(b"HdrS");
        bytes
    }

    fn cpio(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut writer_ref: &mut Vec<u8> = &mut output;
            for (name, mode, body) in entries {
                let builder = ::cpio::NewcBuilder::new(name)
                    .ino(1)
                    .mode(*mode)
                    .uid(0)
                    .gid(0)
                    .nlink(1)
                    .mtime(0)
                    .dev_major(0)
                    .dev_minor(0)
                    .rdev_major(0)
                    .rdev_minor(0);
                let mut entry = builder.write(writer_ref, body.len() as u32);
                entry.write_all(body).unwrap();
                writer_ref = entry.finish().unwrap();
            }
            ::cpio::newc::trailer(writer_ref).unwrap();
        }
        output
    }

    fn nested_module_tar() -> Vec<u8> {
        let mut output = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut output);
            let body = b"kernel/test.ko";
            let mut header = tar::Header::new_gnu();
            header.set_path("lib/modules/6.6.13/modules.dep").unwrap();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(body.len() as u64);
            header.set_cksum();
            archive.append(&header, &body[..]).unwrap();
            archive.finish().unwrap();
        }
        output
    }

    fn cpio_names(bytes: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut remaining = bytes;
        loop {
            let mut reader = ::cpio::newc::Reader::new(remaining).unwrap();
            let entry = reader.entry().clone();
            if entry.is_trailer() {
                break;
            }
            names.push(entry.name().to_string());
            let mut body = Vec::new();
            reader.read_to_end(&mut body).unwrap();
            remaining = reader.finish().unwrap();
        }
        names
    }

    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn materializes_a_raw_local_kernel_without_a_rootfs() {
        let _guard = TEST_LOCK.lock().await;
        let mut source = NamedTempFile::new().unwrap();
        let bytes = bzimage();
        source.write_all(&bytes).unwrap();

        let paths = materialize_image(
            Kernel::local(source.path()),
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&paths.0).unwrap(), bytes);
        assert!(paths.1.is_none());
    }

    #[tokio::test]
    async fn a_same_size_local_edit_gets_a_new_materialization() {
        let _guard = TEST_LOCK.lock().await;
        let mut source = NamedTempFile::new().unwrap();
        let first = bzimage();
        source.write_all(&first).unwrap();
        let paths_one = materialize_image(
            Kernel::local(source.path()),
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        let mut second = first.clone();
        second[0x210] ^= 0x5a;
        std::fs::write(source.path(), &second).unwrap();
        let paths_two = materialize_image(
            Kernel::local(source.path()),
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_ne!(paths_one.0, paths_two.0);
        assert_eq!(std::fs::read(&paths_two.0).unwrap(), second);
    }

    #[tokio::test]
    async fn materializes_an_exact_archive_entry_and_complete_rootfs() {
        let _guard = TEST_LOCK.lock().await;
        let mut kernel_source = NamedTempFile::new().unwrap();
        let kernel = bzimage();
        let nested_modules = nested_module_tar();
        let kernel_archive = cpio(&[
            ("boot/kernel", 0o100755, &kernel),
            ("kernel.tar", 0o100644, &nested_modules),
        ]);
        kernel_source.write_all(&kernel_archive).unwrap();

        let mut rootfs_source = NamedTempFile::new().unwrap();
        let rootfs = cpio(&[("etc/hostname", 0o100644, b"image-test")]);
        rootfs_source.write_all(&rootfs).unwrap();

        let paths = materialize_image(
            Kernel::local_archive(kernel_source.path(), "boot/kernel").unwrap(),
            Some(Rootfs::new(Link::local(rootfs_source.path()))),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&paths.0).unwrap(), kernel);
        let materialized_rootfs = paths.1.as_ref().unwrap();
        let materialized_rootfs_bytes = std::fs::read(materialized_rootfs).unwrap();
        assert!(
            cpio_names(&materialized_rootfs_bytes)
                .iter()
                .any(|name| name == "lib/modules/6.6.13/modules.dep")
        );

        let paths_again = materialize_image(
            Kernel::local_archive(kernel_source.path(), "boot/kernel").unwrap(),
            Some(Rootfs::new(Link::local(rootfs_source.path()))),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(paths_again.0, paths.0);
        assert_eq!(paths_again.1, paths.1);
    }

    #[tokio::test]
    async fn materialize_image_materializes_kernel_and_rootfs_directly() {
        let _guard = TEST_LOCK.lock().await;
        let mut kernel_source = NamedTempFile::new().unwrap();
        let kernel = bzimage();
        let nested_modules = nested_module_tar();
        let kernel_archive = cpio(&[
            ("boot/kernel", 0o100755, &kernel),
            ("kernel.tar", 0o100644, &nested_modules),
        ]);
        kernel_source.write_all(&kernel_archive).unwrap();

        let mut rootfs_source = NamedTempFile::new().unwrap();
        let rootfs = cpio(&[("etc/hostname", 0o100644, b"image-test")]);
        rootfs_source.write_all(&rootfs).unwrap();

        let paths = materialize_image(
            Kernel::local_archive(kernel_source.path(), "boot/kernel").unwrap(),
            Some(Rootfs::new(Link::local(rootfs_source.path()))),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read(&paths.0).unwrap(), kernel);
        let materialized_rootfs = paths.1.as_ref().unwrap();
        let materialized_rootfs_bytes = std::fs::read(materialized_rootfs).unwrap();
        assert!(
            cpio_names(&materialized_rootfs_bytes)
                .iter()
                .any(|name| name == "lib/modules/6.6.13/modules.dep")
        );
    }

    /// The shared store invalidates a cache record the moment its backing
    /// bytes disappear, and the next acquisition re-fetches from the source:
    /// the same content-addressed path is restored with identical bytes.
    /// Replicates the cache-refresh path deterministically, without network.
    #[tokio::test]
    async fn stale_cache_entry_is_refreshed_from_source() {
        let _guard = TEST_LOCK.lock().await;
        let mut source = NamedTempFile::new().unwrap();
        let bytes = bzimage();
        source.write_all(&bytes).unwrap();
        let source_path = source.path().to_path_buf();

        let (kernel1, _) =
            materialize_image(Kernel::local(&source_path), None, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(std::fs::read(&kernel1).unwrap(), bytes);

        std::fs::remove_file(&kernel1).unwrap();

        let (kernel2, _) =
            materialize_image(Kernel::local(&source_path), None, &CancellationToken::new())
                .await
                .unwrap();
        assert_eq!(kernel2, kernel1);
        assert_eq!(std::fs::read(&kernel2).unwrap(), bytes);
    }

    /// An unreachable registry must surface the deep acquisition chain
    /// (MaterializeError -> KernelError -> SourceResolverError ->
    /// OperationError), never a single opaque frame. The probe targets
    /// 127.0.0.1:1, so it fails fast with a refused connection and needs no
    /// DNS.
    #[tokio::test]
    async fn unreachable_registry_failure_surfaces_the_deep_chain() {
        let _guard = TEST_LOCK.lock().await;
        let error = materialize_image(
            Kernel::image("127.0.0.1:1/repo:latest", "boot/kernel").unwrap(),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect_err("a refused registry connection must fail the build");

        let frames: Vec<_> = error.frames().collect();
        assert!(
            frames.iter().any(|frame| frame.is::<MaterializeError>()),
            "the chain must carry MaterializeError"
        );
        assert!(
            frames.iter().any(|frame| frame.is::<kernel::KernelError>()),
            "the chain must carry kernel::KernelError"
        );
        assert!(
            frames
                .iter()
                .any(|frame| frame.is::<image_core::resolver::SourceResolverError>()),
            "the chain must carry image_core::resolver::SourceResolverError"
        );
        assert!(
            frames
                .iter()
                .any(|frame| frame.is::<image_core::ops::error::OperationError>()),
            "the chain must carry the ops OperationError (the registry probe failure)"
        );
        assert!(
            frames.len() >= 3,
            "the chain must be deep, got {} frames",
            frames.len()
        );
        let display = format!("{error:#}");
        assert!(
            display.contains("could not resolve the external source"),
            "the printed chain must surface the resolution failure, got: {display}"
        );
    }
}
