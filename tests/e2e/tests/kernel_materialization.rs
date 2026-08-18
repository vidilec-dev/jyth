//! Kernel materialization acceptance over the KernelApiDxPlan constructors.
//!
//! Pure materialization — no VMs are launched; `hcs_test_guard` only
//! serializes against the suite binaries that share the host and store.
//! Covers the plan's §12.2 integration surface with the new opaque facade:
//!
//! - raw local and byte-backed kernels (`Kernel::local`, `Kernel::bytes`);
//! - archive local and byte-backed kernels (`Kernel::local_archive`,
//!   `Kernel::bytes_archive`);
//! - cache-identity path sensitivity (§4.9): two kernel paths inside one
//!   archive produce two distinct identities, normalized spellings of one
//!   path share one identity, and the pinned `Kernel::default()` lowers to
//!   the immutable OCI artifact;
//! - a raw source that materializes as an archive fails with a typed error
//!   instead of extracting (WP3 acceptance).

use std::io::Write as _;

use cpio::NewcBuilder;
use e2e_tests::{E2eResult, hcs_test_guard};
use kernel::Kernel;
use kernel::KernelError;
use uuid::Uuid;

/// `S_IFREG` for `newc` entry modes (matches the kernel crate's fixtures).
const S_IFREG: u32 = 0o100000;
/// A regular file with owner read/write: `S_IFREG | 0o644`.
const MODE_REGULAR: u32 = S_IFREG | 0o644;

/// Encode a `newc` CPIO archive terminated by the standard trailer.
fn build_cpio(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    {
        let mut writer_ref: &mut Vec<u8> = &mut output;
        for (name, body) in entries {
            let builder = NewcBuilder::new(name)
                .ino(1)
                .mode(MODE_REGULAR)
                .uid(0)
                .gid(0)
                .nlink(1)
                .mtime(0)
                .dev_major(0)
                .dev_minor(0)
                .rdev_major(0)
                .rdev_minor(0);
            let mut writer = builder.write(writer_ref, body.len() as u32);
            writer.write_all(body).expect("write CPIO entry body");
            writer_ref = writer.finish().expect("finish CPIO entry padding");
        }
        cpio::newc::trailer(writer_ref).expect("write CPIO trailer");
    }
    output
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir()
        .join("jyth-e2e")
        .join("kernel-materialization")
        .join(format!("{}-{name}", Uuid::now_v7()))
}

async fn materialize(kernel: &Kernel) -> Result<kernel::MaterializedKernel, std::io::Error> {
    let cancel = tokio_util::sync::CancellationToken::new();
    ::kernel::materialize(kernel, &cancel)
        .await
        .map_err(|error| std::io::Error::other(format!("kernel materialization failed: {error:?}")))
}

#[tokio::test]
async fn kernel_materialization_matrix() -> E2eResult<()> {
    let _host_guard = hcs_test_guard().await?;
    let cancel = tokio_util::sync::CancellationToken::new();

    // Fixture: the real validated default bzImage. Everything below reuses
    // these bytes so every input is content-valid and no test manufactures
    // fake kernel payloads.
    let default = materialize(&Kernel::default()).await?;
    let bz = std::fs::read(&default.kernel)?;
    assert!(!bz.is_empty(), "default kernel artifact must not be empty");
    // The default request is cache-stable: a second request reuses one path.
    let default_again = materialize(&Kernel::default()).await?;
    assert_eq!(
        default.kernel, default_again.kernel,
        "Kernel::default() must be cache-stable"
    );

    // Raw sources: a local path and caller-held bytes materialize to the
    // identical content-valid artifact.
    let dir = temp_path("raw");
    std::fs::create_dir_all(&dir)?;
    let local_path = dir.join("vmlinuz");
    std::fs::write(&local_path, &bz)?;
    let raw_local = materialize(&Kernel::local(local_path.as_path())).await?;
    let raw_bytes = materialize(&Kernel::bytes(bz.clone())).await?;
    assert_eq!(
        std::fs::read(&raw_local.kernel)?,
        bz,
        "raw local kernel must preserve the bzImage bytes"
    );
    assert_eq!(
        std::fs::read(&raw_bytes.kernel)?,
        bz,
        "raw byte kernel must preserve the bzImage bytes"
    );

    // Archive sources: local and byte-backed CPIO archives extract the
    // validated entry.
    let single_entry = build_cpio(&[("kernel", &bz)]);
    let cpio_path = dir.join("kernel.cpio");
    std::fs::write(&cpio_path, &single_entry)?;
    let archive_local = materialize(&Kernel::local_archive(cpio_path.as_path(), "kernel")?).await?;
    let archive_bytes =
        materialize(&Kernel::bytes_archive(single_entry.clone(), "kernel")?).await?;
    assert_eq!(
        std::fs::read(&archive_local.kernel)?,
        bz,
        "local archive must extract the kernel entry"
    );
    assert_eq!(
        std::fs::read(&archive_bytes.kernel)?,
        bz,
        "byte archive must extract the kernel entry"
    );

    // Two kernel paths inside one archive produce two distinct cache
    // identities (KernelApiDxPlan §4.9); a repeated request reuses one.
    let two_entries = build_cpio(&[("kernel", &bz), ("boot/vmlinuz", &bz)]);
    let two_path = dir.join("two-path.cpio");
    std::fs::write(&two_path, &two_entries)?;
    let via_kernel = materialize(&Kernel::local_archive(two_path.as_path(), "kernel")?).await?;
    let via_boot = materialize(&Kernel::local_archive(two_path.as_path(), "boot/vmlinuz")?).await?;
    let via_boot_again =
        materialize(&Kernel::local_archive(two_path.as_path(), "boot/vmlinuz")?).await?;
    assert_ne!(
        via_kernel.kernel, via_boot.kernel,
        "two kernel paths in one source must never alias one cache identity"
    );
    assert_eq!(
        via_boot.kernel, via_boot_again.kernel,
        "the same kernel path must reuse one cache identity"
    );
    assert_eq!(
        std::fs::read(&via_boot.kernel)?,
        bz,
        "the second entry must extract to the same validated bytes"
    );

    // Normalized spellings of one path share one identity.
    let via_normalized = materialize(&Kernel::local_archive(
        two_path.as_path(),
        "./boot\\vmlinuz",
    )?)
    .await?;
    assert_eq!(
        via_normalized.kernel, via_boot.kernel,
        "normalized path spellings must share one cache identity"
    );

    // A raw source that materializes as an archive fails with a typed error
    // instead of extracting: the raw request carries no kernel entry path.
    let raw_archive = ::kernel::materialize(&Kernel::local(cpio_path.as_path()), &cancel).await;
    let error = raw_archive.expect_err("a raw CPIO source must fail materialization");
    assert!(
        matches!(error.current_context(), KernelError::Materialization),
        "the raw-archive failure must surface KernelError::Materialization: {error:?}"
    );

    Ok(())
}
