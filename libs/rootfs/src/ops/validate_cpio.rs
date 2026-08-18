//! Structural validation for a complete uncompressed CPIO `newc` archive.

use std::io::{BufReader, Read, Seek};

use error_stack::Report;
use tokio_util::sync::CancellationToken;

use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    ops::{bounded_join, error::OperationError, io},
    storage::file_ref::FileRef,
};

/// Validate that `entry` is one complete CPIO archive with exactly one
/// trailer and no structural bytes after it.
pub(crate) async fn validate_cpio(
    entry: &FileRef,
    token: &CancellationToken,
) -> Result<(), Report<OperationError>> {
    if entry.artifact_type != ArtifactType::ContainerCpio {
        return Err(OperationError::UnsupportedArtifact
            .report()
            .attach(format!("expected CPIO, got {:?}", entry.artifact_type)));
    }
    if entry.artifact_compression != ArtifactCompression::None {
        return Err(OperationError::UnsupportedCompression
            .report()
            .attach(format!(
                "expected uncompressed CPIO, got {:?}",
                entry.artifact_compression
            )));
    }

    let entry = entry.clone();
    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                validate_blocking(&entry, &token)
            }
        }),
        token,
        |error| OperationError::ReadSource.report().attach(error),
        OperationError::Cancelled.report(),
    )
    .await?
}

fn validate_blocking(
    entry: &FileRef,
    token: &CancellationToken,
) -> Result<(), Report<OperationError>> {
    let path = entry.path();
    let mut file = std::fs::File::open(&path)
        .map_err(|error| OperationError::ReadSource.report().attach(error))?;
    let actual = io::compute_file_digest_from_file(&mut file, &path)
        .map_err(|error| OperationError::ReadSource.report().attach(error))?;
    if actual != entry.file_digest {
        return Err(OperationError::DigestMismatch.report().attach(format!(
            "CPIO digest changed while validating {}",
            path.display()
        )));
    }

    file.rewind()
        .map_err(|error| OperationError::ReadSource.report().attach(error))?;
    let mut remaining = BufReader::new(file);
    loop {
        if token.is_cancelled() {
            return Err(OperationError::Cancelled.report());
        }
        let mut reader = ::cpio::newc::Reader::new(remaining)
            .map_err(|error| OperationError::InvalidCpio.report().attach(error))?;
        if reader.entry().is_trailer() {
            remaining = reader
                .finish()
                .map_err(|error| OperationError::InvalidCpio.report().attach(error))?;
            let mut extra = [0u8; 1];
            let read = remaining
                .read(&mut extra)
                .map_err(|error| OperationError::InvalidCpio.report().attach(error))?;
            if read != 0 {
                return Err(OperationError::InvalidCpio
                    .report()
                    .attach("structural bytes after CPIO trailer"));
            }
            return Ok(());
        }

        let size = u64::from(reader.entry().file_size());
        // Pure validation never uses the body bytes, so stream them through a
        // fixed buffer instead of rejecting large entries: a valid rootfs may
        // contain files beyond MAX_IN_MEMORY_ENTRY_BYTES (firmware, ICU data,
        // big binaries). That bound caps in-memory materialization only, not
        // structural validity (AuditPlan B4).
        let mut buffer = [0u8; 64 * 1024];
        let mut consumed: u64 = 0;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| OperationError::InvalidCpio.report().attach(error))?;
            if read == 0 {
                break;
            }
            consumed += read as u64;
        }
        if consumed < size {
            return Err(OperationError::InvalidCpio.report().attach(format!(
                "CPIO entry body ended before its declared size: read {consumed} of {size} bytes"
            )));
        }
        remaining = reader
            .finish()
            .map_err(|error| OperationError::InvalidCpio.report().attach(error))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image_core::storage::namespace::Namespace;
    use tokio_util::sync::CancellationToken;

    fn cpio_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut output = Vec::new();
        {
            let mut writer_ref: &mut Vec<u8> = &mut output;
            for (name, body) in entries {
                let builder = ::cpio::NewcBuilder::new(name)
                    .ino(1)
                    .mode(0o100644)
                    .uid(0)
                    .gid(0)
                    .nlink(1)
                    .mtime(0)
                    .dev_major(0)
                    .dev_minor(0)
                    .rdev_major(0)
                    .rdev_minor(0);
                let mut entry = builder.write(writer_ref, body.len() as u32);
                entry.write_all(body).expect("write CPIO body");
                writer_ref = entry.finish().expect("finish CPIO entry");
            }
            ::cpio::newc::trailer(writer_ref).expect("write CPIO trailer");
        }
        output
    }

    /// Patch the `filesize` field (offset 54..62 of the 110-byte `newc`
    /// header) of the FIRST entry in `archive` to `size`, hex-encoded.
    fn patch_first_newc_size(archive: &mut [u8], size: u32) {
        let hex = format!("{size:08x}");
        archive[54..62].copy_from_slice(hex.as_bytes());
    }

    /// A staged CPIO fixture on disk. The guard removes the staged file when
    /// dropped so tests never leak `Namespace::Layers` fixture bytes.
    struct StagedFixture {
        entry: FileRef,
        path: std::path::PathBuf,
    }

    impl Drop for StagedFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn staged_ref(bytes: &[u8]) -> StagedFixture {
        let uuid = uuid::Uuid::now_v7();
        let path = Namespace::Layers.join(uuid.to_string());
        std::fs::create_dir_all(path.parent().expect("namespace parent")).expect("ns dir");
        std::fs::write(&path, bytes).expect("stage");
        let file_digest = image_core::ops::io::compute_file_digest(&path).expect("digest");
        StagedFixture {
            entry: FileRef {
                uuid,
                namespace: Namespace::Layers,
                file_digest,
                artifact_type: ArtifactType::ContainerCpio,
                artifact_compression: ArtifactCompression::None,
            },
            path,
        }
    }

    #[tokio::test]
    async fn accepts_a_complete_archive() {
        let bytes = cpio_archive(&[("etc/hostname", b"guest")]);
        let fixture = staged_ref(&bytes);
        validate_cpio(&fixture.entry, &CancellationToken::new())
            .await
            .expect("valid archive");
    }

    #[tokio::test]
    async fn rejects_structural_bytes_after_the_trailer() {
        let mut bytes = cpio_archive(&[("etc/hostname", b"guest")]);
        bytes.extend_from_slice(b"trailing");
        let fixture = staged_ref(&bytes);
        let err = validate_cpio(&fixture.entry, &CancellationToken::new())
            .await
            .expect_err("trailing bytes");
        assert!(matches!(err.current_context(), OperationError::InvalidCpio));
    }

    #[tokio::test]
    async fn rejects_a_body_that_ends_before_its_declared_size() {
        let mut bytes = cpio_archive(&[("etc/hostname", b"guest")]);
        patch_first_newc_size(&mut bytes, image_core::ops::MAX_IN_MEMORY_ENTRY_BYTES + 1);
        let fixture = staged_ref(&bytes);
        let err = validate_cpio(&fixture.entry, &CancellationToken::new())
            .await
            .expect_err("declared size beyond the actual body");
        assert!(
            matches!(err.current_context(), OperationError::InvalidCpio),
            "expected InvalidCpio, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn accepts_an_entry_body_above_the_in_memory_bound() {
        let body = vec![0u8; image_core::ops::MAX_IN_MEMORY_ENTRY_BYTES as usize + 1];
        let bytes = cpio_archive(&[("big.bin", &body)]);
        let fixture = staged_ref(&bytes);
        validate_cpio(&fixture.entry, &CancellationToken::new())
            .await
            .expect("a body above the in-memory bound is still a valid archive");
    }

    /// A pre-cancelled token makes the blocking closure bail at entry: the
    /// operation fails fast with `OperationError::Cancelled` without scanning
    /// the archive (spec capability `blocking-cancellation`).
    #[tokio::test]
    async fn cancelled_token_returns_cancelled_fast() {
        let bytes = cpio_archive(&[("etc/hostname", b"guest")]);
        let fixture = staged_ref(&bytes);
        let token = CancellationToken::new();
        token.cancel();

        let err = validate_cpio(&fixture.entry, &token)
            .await
            .expect_err("a cancelled operation must fail");
        assert!(
            matches!(err.current_context(), OperationError::Cancelled),
            "expected Cancelled, got: {err:#}"
        );
    }
}
