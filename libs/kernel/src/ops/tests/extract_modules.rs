//! Tests for LinuxKit-style kernel module extraction.

use std::io::{Read, Write};

use uuid::Uuid;

use crate::ops;
use image_core::{
    artifact::{compression::ArtifactCompression, ty::ArtifactType},
    digest::LinkDigest,
    ops::{MAX_IN_MEMORY_ENTRY_BYTES, error::OperationError, io},
    storage::{file_ref::FileRef, link_ref::LinkRef, namespace::Namespace},
};
use tokio_util::sync::CancellationToken;

const S_IFREG: u32 = 0o100000;

fn bzimage_body() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x206 + 8];
    bytes[0x1fe] = 0x55;
    bytes[0x1ff] = 0xaa;
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    bytes
}

fn cpio_archive(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
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
            entry.write_all(body).expect("write CPIO body");
            writer_ref = entry.finish().expect("finish CPIO entry");
        }
        ::cpio::newc::trailer(writer_ref).expect("write CPIO trailer");
    }
    output
}

fn nested_kernel_tar() -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut output);
        let body = b"alias crypto_test 123";
        let mut header = tar::Header::new_gnu();
        header.set_path("lib/modules/6.6.13/modules.alias").unwrap();
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1001);
        header.set_mtime(42);
        header.set_size(body.len() as u64);
        header.set_cksum();
        archive.append(&header, &body[..]).unwrap();
        archive.finish().unwrap();
    }
    output
}

fn stage_source(bytes: &[u8]) -> (FileRef, LinkRef) {
    let source_uuid = Uuid::now_v7();
    let source_path = Namespace::Kernel.join(source_uuid.to_string());
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    std::fs::write(&source_path, bytes).unwrap();
    let file_digest = io::compute_file_digest(&source_path).unwrap();
    let source = FileRef {
        uuid: source_uuid,
        namespace: Namespace::Kernel,
        file_digest,
        artifact_type: ArtifactType::ContainerCpio,
        artifact_compression: ArtifactCompression::None,
    };
    let destination = LinkRef {
        uuid: Uuid::now_v7(),
        namespace: Namespace::Modules,
        link_digest: LinkDigest {
            link_hash: blake3::hash(b"linuxkit-test"),
            file_size: bytes.len() as u128,
        },
    };
    (source, destination)
}

fn read_cpio(bytes: &[u8]) -> std::collections::BTreeMap<String, (u32, Vec<u8>)> {
    let mut result = std::collections::BTreeMap::new();
    let mut remaining = bytes;
    loop {
        let mut reader = ::cpio::newc::Reader::new(remaining).unwrap();
        let entry = reader.entry().clone();
        if entry.is_trailer() {
            break;
        }
        let name = entry.name().to_string();
        let mode = entry.mode();
        let mut body = Vec::new();
        reader.read_to_end(&mut body).unwrap();
        remaining = reader.finish().unwrap();
        result.insert(name, (mode, body));
    }
    result
}

#[tokio::test]
async fn extracts_nested_linuxkit_modules_with_metadata() {
    let kernel = bzimage_body();
    let nested = nested_kernel_tar();
    let source_bytes = cpio_archive(&[
        ("kernel", S_IFREG | 0o755, &kernel),
        ("kernel.tar", S_IFREG | 0o644, &nested),
    ]);
    let (source, destination) = stage_source(&source_bytes);

    let modules = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .expect("module extraction should succeed")
        .expect("nested module payload should be present");
    assert_eq!(modules.namespace, Namespace::Modules);

    let bytes = std::fs::read(modules.path()).unwrap();
    let entries = read_cpio(&bytes);
    let (mode, body) = entries.get("lib/modules/6.6.13/modules.alias").unwrap();
    assert_eq!(mode & 0o7777, 0o644);
    assert_eq!(body, b"alias crypto_test 123");
}

#[tokio::test]
async fn extracts_direct_module_tree_and_returns_none_without_payload() {
    let direct = cpio_archive(&[(
        "lib/modules/6.6.13/modules.dep",
        S_IFREG | 0o600,
        b"kernel/test.ko",
    )]);
    let (source, destination) = stage_source(&direct);
    let modules = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .unwrap()
        .expect("direct module payload should be present");
    let entries = read_cpio(&std::fs::read(modules.path()).unwrap());
    assert_eq!(
        entries["lib/modules/6.6.13/modules.dep"].1,
        b"kernel/test.ko"
    );

    let directories_only = cpio_archive(&[("lib/modules/6.6.13", 0o040000 | 0o755, &[])]);
    let (source, destination) = stage_source(&directories_only);
    assert!(
        ops::extract_modules(&source, &destination, &CancellationToken::new())
            .await
            .unwrap()
            .is_none()
    );
}

/// Patch the `filesize` field (offset 54..62 of the 110-byte `newc` header)
/// of the FIRST entry in `archive` to `size`, hex-encoded.
fn patch_first_newc_size(archive: &mut [u8], size: u32) {
    let hex = format!("{size:08x}");
    archive[54..62].copy_from_slice(hex.as_bytes());
}

/// Recompute the TAR header checksum after mutating the header, so
/// `Archive::entries()` accepts the header and exposes the mutated size.
fn fix_tar_checksum(header: &mut [u8]) {
    for byte in header.iter_mut().skip(148).take(8) {
        *byte = b' ';
    }
    let sum: u32 = header.iter().map(|byte| *byte as u32).sum();
    let checksum = format!("{sum:06o}");
    header[148..154].copy_from_slice(checksum.as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

#[tokio::test]
async fn rejects_cpio_entry_bodies_above_the_in_memory_bound() {
    let mut source_bytes = cpio_archive(&[("lib/modules/x.ko", S_IFREG | 0o644, b"tiny")]);
    patch_first_newc_size(&mut source_bytes, MAX_IN_MEMORY_ENTRY_BYTES + 1);
    let (source, destination) = stage_source(&source_bytes);

    let err = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .expect_err("an oversized in-memory body must be rejected");
    assert!(
        matches!(err.current_context(), OperationError::InvalidCpio),
        "expected InvalidCpio, got: {err:#}"
    );
}

#[tokio::test]
async fn rejects_kernel_tar_entries_above_the_in_memory_bound() {
    let mut nested = nested_kernel_tar();
    // The first (and only) tar header starts at offset 0; its size field is
    // the 11-digit octal value at bytes 124..135.
    let huge = MAX_IN_MEMORY_ENTRY_BYTES as u64 + 1;
    let octal = format!("{huge:011o}");
    nested[124..135].copy_from_slice(octal.as_bytes());
    nested[135] = 0;
    fix_tar_checksum(&mut nested[..512]);

    let source_bytes = cpio_archive(&[("kernel.tar", S_IFREG | 0o644, &nested)]);
    let (source, destination) = stage_source(&source_bytes);

    let err = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .expect_err("an oversized kernel.tar entry must be rejected");
    assert!(
        matches!(err.current_context(), OperationError::InvalidCpio),
        "expected InvalidCpio, got: {err:#}"
    );
}

#[tokio::test]
async fn accepts_large_non_module_entries_in_the_source_archive() {
    // The real linuxkit kernel image contains non-module entries far above
    // the in-memory bound (the raw kernel blob, firmware). Their bodies are
    // walked but not retained, so they must be streamed, never rejected.
    let big = vec![0xabu8; MAX_IN_MEMORY_ENTRY_BYTES as usize + 1];
    let source_bytes = cpio_archive(&[
        ("etc/big.bin", S_IFREG | 0o644, &big),
        (
            "lib/modules/6.6.13/modules.dep",
            S_IFREG | 0o600,
            b"kernel/test.ko",
        ),
    ]);
    let (source, destination) = stage_source(&source_bytes);

    let modules = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .expect("large discarded entries must not fail extraction")
        .expect("module payload should be present");
    let entries = read_cpio(&std::fs::read(modules.path()).unwrap());
    assert_eq!(
        entries["lib/modules/6.6.13/modules.dep"].1,
        b"kernel/test.ko"
    );
}

#[tokio::test]
async fn accepts_a_kernel_tar_larger_than_the_in_memory_bound() {
    // A real module bundle can exceed the in-memory bound as a whole while
    // every individual entry stays small. The nested archive is spooled to
    // disk and parsed from there instead of being rejected.
    let mut nested = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut nested);
        let body = vec![0x5au8; 64 * 1024];
        for i in 0..1400u32 {
            let mut header = tar::Header::new_gnu();
            header
                .set_path(format!("lib/modules/6.6.13/module-{i}.ko"))
                .unwrap();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(body.len() as u64);
            header.set_cksum();
            archive.append(&header, &body[..]).unwrap();
        }
        archive.finish().unwrap();
    }
    assert!(
        nested.len() as u64 > MAX_IN_MEMORY_ENTRY_BYTES as u64,
        "the fixture tar must exceed the in-memory bound (got {} bytes)",
        nested.len()
    );
    let source_bytes = cpio_archive(&[("kernel.tar", S_IFREG | 0o644, &nested)]);
    let (source, destination) = stage_source(&source_bytes);

    let modules = ops::extract_modules(&source, &destination, &CancellationToken::new())
        .await
        .expect("a large nested kernel.tar must be spooled, not rejected")
        .expect("module payload should be present");
    let entries = read_cpio(&std::fs::read(modules.path()).unwrap());
    let first = &entries["lib/modules/6.6.13/module-0.ko"].1;
    let last = &entries["lib/modules/6.6.13/module-1399.ko"].1;
    assert_eq!(first.len(), 64 * 1024);
    assert_eq!(&first[..4], &[0x5a; 4]);
    assert_eq!(last.len(), 64 * 1024);
    assert_eq!(&last[..4], &[0x5a; 4]);
}

/// A pre-cancelled token makes the blocking closure bail at entry: the
/// operation fails fast with `OperationError::Cancelled` without scanning the
/// CPIO (spec capability `blocking-cancellation`).
#[tokio::test]
async fn cancelled_token_returns_cancelled_fast() {
    let kernel = bzimage_body();
    let source_bytes = cpio_archive(&[("kernel", S_IFREG | 0o755, &kernel)]);
    let (source, destination) = stage_source(&source_bytes);
    let token = CancellationToken::new();
    token.cancel();

    let err = ops::extract_modules(&source, &destination, &token)
        .await
        .expect_err("a cancelled operation must fail");
    assert!(
        matches!(err.current_context(), OperationError::Cancelled),
        "expected Cancelled, got: {err:#}"
    );
}
