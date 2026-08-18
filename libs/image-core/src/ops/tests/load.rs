//! Tests for [`crate::ops::load`].
//!
//! These tests cover the contract described in
//! `docs/implementation-plan/ops/02-load.md`: copying bytes from local paths,
//! in-memory buffers and HTTP sources; computing BLAKE3 and the optional
//! manifest-declared digest during the same pass; verifying size and digest
//! before publication; preserving the previous destination on failure; and
//! classifying the artifact from the published bytes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use bytes::Bytes;
use sha2::Digest as _;
use uuid::Uuid;

use super::super::load as load_op;
use crate::artifact::{compression::ArtifactCompression, link::ArtifactLink, ty::ArtifactType};
use crate::digest::ExpectedDigest;
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::Namespace;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A minimal valid TAR archive whose leading header contains a single small
/// entry. `format::is_tar` recognises the `ustar` magic at offset 257 and
/// `tar::Archive` parses the leading block.
fn tar_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("entry").expect("path");
    header.set_size(3);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, std::io::Cursor::new(b"abc"))
        .expect("append");
    builder.finish().expect("finish");
    builder.into_inner().expect("into_inner")
}

/// A CPIO `newc` archive with a single small entry. Uses the `cpio` crate so
/// the produced stream matches the `070701` magic that `format::is_cpio_newc`
/// recognises.
fn cpio_archive() -> Vec<u8> {
    use cpio::{NewcBuilder, write_cpio};
    let entry = std::io::Cursor::new(b"payload".to_vec());
    let builder = NewcBuilder::new("entry.bin")
        .ino(1)
        .mode(0o644)
        .nlink(1)
        .uid(0)
        .gid(0)
        .mtime(0)
        .dev_major(0)
        .dev_minor(0)
        .rdev_major(0)
        .rdev_minor(0);
    let inputs = vec![(builder, entry)];
    let mut output = Vec::new();
    write_cpio(inputs.into_iter(), &mut output).expect("write_cpio");
    output
}

/// A minimal bzImage with the boot flag `55 aa` at `0x1fe` and the `HdrS`
/// signature at `0x202`. `format::is_linux_bzimage` requires both markers.
fn bzimage_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x220];
    bytes[0x1fe] = 0x55;
    bytes[0x1ff] = 0xaa;
    bytes[0x202..0x206].copy_from_slice(b"HdrS");
    bytes
}

/// Gzip-encoded bytes containing `payload.tar`. Uses `flate2::read` so the
/// stream begins with the `1f 8b` magic that `format::detect_compression`
/// recognises.
fn gzip_bytes(payload: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::read::GzEncoder;
    let mut encoder = GzEncoder::new(payload, Compression::default());
    let mut out = Vec::new();
    encoder.read_to_end(&mut out).expect("encode gzip");
    out
}

/// Zstandard-encoded bytes containing `payload`. Uses the `zstd` crate so
/// the stream begins with the `28 b5 2f fd` magic.
fn zstd_bytes(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 0).expect("encode zstd")
}

/// Compute a SHA-256 digest of `payload` and return it as an `ExpectedDigest`.
fn sha256_expected(payload: &[u8]) -> ExpectedDigest {
    let mut sha = sha2::Sha256::new();
    sha2::Digest::update(&mut sha, payload);
    let bytes = sha2::Digest::finalize(sha);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    ExpectedDigest::Sha256(out)
}

/// Await a `load` call and unwrap its result, attaching the report text to the
/// failure message when present.
async fn load_ok(
    link: &ArtifactLink,
    link_ref: &LinkRef,
    expected: Option<&ExpectedDigest>,
) -> crate::storage::file_ref::FileRef {
    let expected_link_digest = link.digest().expect("link digest");
    load_op::load(
        link,
        link_ref,
        expected,
        expected_link_digest,
        &CancellationToken::new(),
    )
    .await
    .unwrap_or_else(|err| panic!("load failed: {err:?}"))
}

async fn load_err(
    link: &ArtifactLink,
    link_ref: &LinkRef,
    expected: Option<&ExpectedDigest>,
) -> error_stack::Report<crate::ops::error::OperationError> {
    let expected_link_digest = link.digest().expect("link digest");
    match load_op::load(
        link,
        link_ref,
        expected,
        expected_link_digest,
        &CancellationToken::new(),
    )
    .await
    {
        Ok(value) => panic!("load succeeded unexpectedly: {value:?}"),
        Err(err) => err,
    }
}

/// Extract the leading `OperationError` Display text from a `Report`. Returns
/// a stable substring that matches the `#[error(...)]` message of the
/// original variant, with attachments stripped.
fn err_text(err: &error_stack::Report<crate::ops::error::OperationError>) -> String {
    format!("{err:#}")
}

/// Build a `LinkRef` for the given link and namespace. The UUID is freshly
/// generated for each call so the destination path is unique.
fn link_ref_for(link: &ArtifactLink, namespace: Namespace) -> LinkRef {
    LinkRef {
        uuid: Uuid::now_v7(),
        namespace,
        link_digest: link.digest().expect("link digest"),
    }
}

/// Write `payload` to a temporary on-disk file and return its path.
fn write_local(payload: &[u8]) -> PathBuf {
    let dir = tempfile::tempdir().expect("temp dir").keep();
    let path = dir.join("source.bin");
    std::fs::write(&path, payload).expect("write payload");
    path
}

// ---------------------------------------------------------------------------
// Local and Bytes source tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn loads_local_tar_and_produces_container_tar() {
    let payload = tar_archive();
    let path = write_local(&payload);
    let link = ArtifactLink::local(&path).expect("local link");
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let file_ref = load_ok(&link, &link_ref, None).await;

    assert_eq!(file_ref.artifact_type, ArtifactType::ContainerTar);
    assert_eq!(file_ref.artifact_compression, ArtifactCompression::None);
    assert_eq!(file_ref.uuid, link_ref.uuid);
    assert_eq!(file_ref.namespace, link_ref.namespace);
    assert!(file_ref.path().exists());
    assert_eq!(file_ref.file_digest.file_size, payload.len() as u128);
}

#[tokio::test]
async fn loads_cpio_from_bytes_and_produces_container_cpio() {
    let payload = cpio_archive();
    let link = ArtifactLink::bytes(Bytes::copy_from_slice(&payload));
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let file_ref = load_ok(&link, &link_ref, None).await;

    assert_eq!(file_ref.artifact_type, ArtifactType::ContainerCpio);
    assert!(file_ref.path().exists());
}

#[tokio::test]
async fn loads_minimal_bzimage_and_produces_file_bzimage() {
    let payload = bzimage_bytes();
    let path = write_local(&payload);
    let link = ArtifactLink::local(&path).expect("local link");
    let link_ref = link_ref_for(&link, Namespace::Kernel);

    let file_ref = load_ok(&link, &link_ref, None).await;

    assert_eq!(file_ref.artifact_type, ArtifactType::FileBzImage);
    assert!(file_ref.path().exists());
}

#[tokio::test]
async fn loads_gzip_and_produces_compressed_gzip() {
    let payload = gzip_bytes(&tar_archive());
    let link = ArtifactLink::bytes(Bytes::copy_from_slice(&payload));
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let file_ref = load_ok(&link, &link_ref, None).await;

    assert_eq!(file_ref.artifact_type, ArtifactType::Compressed);
    assert_eq!(file_ref.artifact_compression, ArtifactCompression::Gzip);
}

#[tokio::test]
async fn loads_zstd_and_produces_compressed_zstd() {
    let payload = zstd_bytes(&tar_archive());
    let link = ArtifactLink::bytes(Bytes::copy_from_slice(&payload));
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let file_ref = load_ok(&link, &link_ref, None).await;

    assert_eq!(file_ref.artifact_type, ArtifactType::Compressed);
    assert_eq!(file_ref.artifact_compression, ArtifactCompression::Zstd);
}

#[tokio::test]
async fn rejects_declared_size_not_matching_read_size() {
    let payload = b"consistent-message";
    // Construct a `Bytes` link whose declared size disagrees with the actual
    // buffer length. `ArtifactLink::bytes` would auto-compute the size, so
    // we build the variant explicitly to express the discrepancy.
    let link = ArtifactLink::Bytes(Bytes::copy_from_slice(payload), (payload.len() + 7) as u128);
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let err = load_err(&link, &link_ref, None).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("the materialized size did not match the expected size"),
        "{msg}"
    );
}

#[tokio::test]
async fn rejects_incorrect_sha256_digest() {
    let payload = b"signed-payload";
    let path = write_local(payload);
    let link = ArtifactLink::local(&path).expect("local link");
    let link_ref = link_ref_for(&link, Namespace::Layers);

    // Build a SHA-256 expected digest for an unrelated payload.
    let bogus = ExpectedDigest::Sha256([0u8; 32]);
    let err = load_err(&link, &link_ref, Some(&bogus)).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("the materialized digest did not match the expected digest"),
        "{msg}"
    );
}

#[tokio::test]
async fn accepts_matching_sha256_digest() {
    let payload = tar_archive();
    let path = write_local(&payload);
    let link = ArtifactLink::local(&path).expect("local link");
    let link_ref = link_ref_for(&link, Namespace::Layers);
    let expected = sha256_expected(&payload);

    let file_ref = load_ok(&link, &link_ref, Some(&expected)).await;
    assert_eq!(file_ref.artifact_type, ArtifactType::ContainerTar);
}

#[tokio::test]
async fn source_local_remains_intact_after_load() {
    let payload = bzimage_bytes();
    let path = write_local(&payload);
    let link = ArtifactLink::local(&path).expect("local link");
    let link_ref = link_ref_for(&link, Namespace::Kernel);

    let _ = load_ok(&link, &link_ref, None).await;

    let on_disk = std::fs::read(&path).expect("read source");
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn failure_preserves_previous_destination() {
    let payload_a = bzimage_bytes();
    let link_a = ArtifactLink::bytes(Bytes::copy_from_slice(&payload_a));
    let link_ref_a = link_ref_for(&link_a, Namespace::Kernel);

    // Prime the destination with a valid artifact first.
    let first = load_ok(&link_a, &link_ref_a, None).await;
    let destination = first.path();
    let first_bytes = std::fs::read(&destination).expect("read first");

    // Use a different valid payload at the same logical destination. The
    // digest failure must leave payload A in place rather than publishing B
    // before validation.
    let mut payload_b = bzimage_bytes();
    payload_b[0] = 0x7f;
    let link_b = ArtifactLink::bytes(Bytes::copy_from_slice(&payload_b));
    let link_ref_b = LinkRef {
        uuid: link_ref_a.uuid,
        namespace: link_ref_a.namespace,
        link_digest: link_b.digest().expect("link digest"),
    };
    let bogus = ExpectedDigest::Sha256([0u8; 32]);
    let _err = load_err(&link_b, &link_ref_b, Some(&bogus)).await;

    let preserved = std::fs::read(&destination).expect("read preserved");
    assert_eq!(preserved, first_bytes, "previous destination was lost");
}

// ---------------------------------------------------------------------------
// HTTP source tests
// ---------------------------------------------------------------------------

/// A trivial single-shot HTTP/1.1 server running on a worker thread. It
/// accepts one connection, serves the configured response, and stops. The
/// thread is detached because each test exercises exactly one request.
struct LocalHttp {
    addr: String,
}

impl LocalHttp {
    /// Start a server that returns `status_line` and `body`. When
    /// `truncate_at` is `Some(n)`, the response is announced with a
    /// `Content-Length` of the original body length but only `n` bytes are
    /// streamed — exercising the truncated-body path.
    fn start(status_line: String, body: Vec<u8>, truncate_at: Option<usize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr").to_string();
        let body = Arc::new(body);
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = drain_request(&mut stream);
                let announced_len = match truncate_at {
                    None => body.len(),
                    Some(_) => body.len(),
                };
                let header = format!(
                    "{status_line}\r\nContent-Length: {announced_len}\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.write_all(header.as_bytes());
                let bytes_written = match truncate_at {
                    None => body.len(),
                    Some(n) => n.min(body.len()),
                };
                let _ = stream.write_all(&body[..bytes_written]);
            }
        });
        Self { addr }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }
}

fn drain_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if let Some(ix) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
            // End of headers. The tests only issue GET/HEAD with no body.
            let _ = ix;
            break;
        }
    }
    Ok(())
}

#[test]
fn blob_download_resolves_a_bearer_challenge() {
    let payload = tar_archive();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind auth server");
    let addr = listener.local_addr().expect("auth server address");
    let realm = format!("http://{addr}/token");
    let expected_body = payload.clone();
    thread::spawn(move || {
        for request_number in 0..3 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            let first_line = request.lines().next().unwrap_or_default();
            if request_number == 0 {
                assert!(first_line.contains("GET /blob"));
                let header = format!(
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"{realm}\",service=\"registry\",scope=\"repository:test:pull\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(header.as_bytes());
            } else if request_number == 1 {
                assert!(first_line.contains("GET /token"));
                let body = br#"{"token":"test-token"}"#;
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body);
            } else {
                assert!(first_line.contains("GET /blob"));
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer test-token")
                );
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    expected_body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&expected_body);
            }
        }
    });

    let link = ArtifactLink::Http(format!("http://{addr}/blob"), payload.len() as u128);
    let link_ref = link_ref_for(&link, Namespace::Layers);
    let expected = sha256_expected(&payload);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let file_ref = runtime.block_on(load_ok(&link, &link_ref, Some(&expected)));
    assert_eq!(file_ref.artifact_type, ArtifactType::ContainerTar);
}

#[tokio::test]
async fn http_accepts_successful_response_with_expected_size() {
    let payload = tar_archive();
    let server = LocalHttp::start("HTTP/1.1 200 OK".to_string(), payload.clone(), None);
    // Build a fresh HTTP link so `ArtifactLink::http` HEADs and discovers the
    // content-length. We then turn it into an `ArtifactLink` directly so the
    // declared size matches the announced body size.
    let link = ArtifactLink::Http(server.url(), payload.len() as u128);
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let file_ref = load_ok(&link, &link_ref, None).await;
    assert_eq!(file_ref.artifact_type, ArtifactType::ContainerTar);
}

#[tokio::test]
async fn http_rejects_404() {
    let server = LocalHttp::start("HTTP/1.1 404 Not Found".to_string(), Vec::new(), None);
    let link = ArtifactLink::Http(server.url(), 0);
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let err = load_err(&link, &link_ref, None).await;
    let msg = err_text(&err);
    assert!(msg.contains("HTTP response was not successful"), "{msg}");
}

#[tokio::test]
async fn http_rejects_truncated_body() {
    let payload = tar_archive();
    // Announce the full length but only send half of the bytes; the
    // materialized size must disagree with the declared size.
    let server = LocalHttp::start(
        "HTTP/1.1 200 OK".to_string(),
        payload.clone(),
        Some(payload.len() / 2),
    );
    let link = ArtifactLink::Http(server.url(), payload.len() as u128);
    let link_ref = link_ref_for(&link, Namespace::Layers);

    let err = load_err(&link, &link_ref, None).await;
    let msg = err_text(&err);
    assert!(
        msg.contains("the materialized size did not match the expected size")
            || msg.contains("HTTP transport failure"),
        "{msg}"
    );
}

/// A pre-cancelled token makes the blocking closure bail at entry: the
/// operation fails fast with `OperationError::Cancelled` without copying the
/// source (spec capability `blocking-cancellation`, cancelled-closure
/// scenario).
#[tokio::test]
async fn cancelled_token_returns_cancelled_fast() {
    let payload = tar_archive();
    let link = ArtifactLink::bytes(Bytes::copy_from_slice(&payload));
    let link_ref = link_ref_for(&link, Namespace::Layers);
    let token = CancellationToken::new();
    token.cancel();

    let err = load_op::load(
        &link,
        &link_ref,
        None,
        link.digest().expect("link digest"),
        &token,
    )
    .await
    .expect_err("a cancelled operation must fail");
    assert!(
        matches!(
            err.current_context(),
            crate::ops::error::OperationError::Cancelled
        ),
        "expected Cancelled, got: {err:#}"
    );
}
