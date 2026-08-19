//! `ops::load` materializes a source `ArtifactLink` into a verified `FileRef`.
//!
//! The function copies bytes from a local path, an in-memory buffer or an HTTP
//! URL into a destination path derived from the link reference's namespace and
//! UUID. The copy computes BLAKE3 and the auxiliary algorithm declared by the
//! optional [`ExpectedDigest`] in a single pass, validates size and digest
//! before publishing, and then sniffs the leading bytes to classify the
//! artifact's container format.
//!
//! All blocking work (file copy, HTTP body streaming, format sniff) runs on
//! [`tokio::task::spawn_blocking`]. The destination is never partially
//! published: a [`crate::ops::io::TempWriter`] atomically replaces
//! the previous file only after size and digest checks pass, preserving the
//! previous destination when a verification fails.

use std::io::Read;
use std::path::{Path, PathBuf};

use error_stack::Report;
use reqwest::header::HeaderMap;
use tokio_util::sync::CancellationToken;

use crate::artifact::link::ArtifactLink;
use crate::digest::{ExpectedDigest, LinkDigest};
use crate::ops::bounded_join;
use crate::ops::error::OperationError;
use crate::ops::format::{self, MIN_HEADER_LEN};
use crate::ops::io::{self, StagedFile, TempWriter};
use crate::storage::file_ref::FileRef;
use crate::storage::link_ref::LinkRef;
use crate::timing::{OpTimer, SourceKind, namespace_tag};

/// Maximum number of HTTP redirects followed by `load`.
const HTTP_MAX_REDIRECTS: usize = 10;

/// Materialize `link` into the directory identified by `link_ref.namespace`,
/// producing the first verified `FileRef` of a pipeline.
///
/// Consumers of a direct source (a `Link::Local`, `Link::Bytes` or
/// `Link::Http` produced outside an OCI manifest) must pass `None` for
/// `expected_digest`. Consumers of an OCI layer must pass a reference to the
/// layer's manifest-declared digest so the materialized bytes can be
/// verified against the manifest authority before publication.
///
/// `expected_link_digest` is the digest of the `link` snapshot the caller
/// holds. The artifact is cached under `link_ref.link_digest` (which may be a
/// request or source digest derived by the caller's service), so the
/// operation verifies the link snapshot against the caller's expectation
/// instead of re-deriving the cache key from the raw link.
///
/// The materialization is timed by one `load` completion event that carries
/// the source kind, the namespace, the final byte count on success, and the
/// failure summary on error.
pub async fn load(
    link: &ArtifactLink,
    link_ref: &LinkRef,
    expected_digest: Option<&ExpectedDigest>,
    expected_link_digest: LinkDigest,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    let timer = OpTimer::start("load")
        .source(SourceKind::from(link))
        .namespace(namespace_tag(link_ref.namespace));
    match load_inner(link, link_ref, expected_digest, expected_link_digest, token).await {
        Ok(file_ref) => {
            timer.bytes(file_ref.file_digest.file_size as u64);
            Ok(file_ref)
        }
        Err(error) => {
            timer.fail(format!("{error:#}"));
            Err(error)
        }
    }
}

/// The materialization pipeline behind [`load`]: the digest precondition
/// check, the blocking copy, format classification, and staging publication.
async fn load_inner(
    link: &ArtifactLink,
    link_ref: &LinkRef,
    expected_digest: Option<&ExpectedDigest>,
    expected_link_digest: LinkDigest,
    token: &CancellationToken,
) -> Result<FileRef, Report<OperationError>> {
    // Precondition: the link digest embedded in `link` must match the caller's
    // expected snapshot digest. A divergence means the caller built the
    // reference against a stale link snapshot and any size authority would
    // be ambiguous.
    let computed = link.digest().map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach("load: link.digest() failed")
            .attach(err)
    })?;
    if computed != expected_link_digest {
        return Err(OperationError::ReadSource.report());
    }

    let destination: PathBuf = link_ref.namespace.join(link_ref.uuid.to_string());
    let link = link.clone();
    let link_digest = link_ref.link_digest;
    let expected_digest = expected_digest.copied();
    let uuid = link_ref.uuid;
    let namespace = link_ref.namespace;

    bounded_join(
        tokio::task::spawn_blocking({
            let token = token.clone();
            move || {
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }
                let staged = match &link {
                    ArtifactLink::Local(path, size) => {
                        copy_local(path, *size, &link_digest, &expected_digest, &destination)?
                    }
                    ArtifactLink::Bytes(bytes, size) => {
                        copy_bytes(bytes, *size, &expected_digest, &destination)?
                    }
                    ArtifactLink::Http(url, size) => {
                        copy_http(url, *size, &link_digest, &expected_digest, &destination)?
                    }
                };

                // Re-check before the second heavy step (format sniff and
                // publication) so a cancellation during the copy still bails.
                if token.is_cancelled() {
                    return Err(OperationError::Cancelled.report());
                }

                // Format classification is part of validation and must happen while
                // the output is still staged. A failed sniff therefore cannot replace
                // a previously valid destination.
                let header = io::read_header(staged.temp_path(), MIN_HEADER_LEN)
                    .map_err(|err| OperationError::ReadSource.report().attach(err))?;
                let detected = format::detect_or_unsupported(&header)?;
                let published = staged
                    .publish()
                    .map_err(|err| OperationError::WriteDestination.report().attach(err))?;

                Ok(FileRef {
                    uuid,
                    namespace,
                    file_digest: published.file_digest,
                    artifact_type: detected.artifact_type,
                    artifact_compression: detected.artifact_compression,
                })
            }
        }),
        token,
        |err| OperationError::ReadSource.report().attach(err),
        OperationError::Cancelled.report(),
    )
    .await?
}

fn copy_local(
    path: &Path,
    declared_size: u128,
    link_digest: &LinkDigest,
    expected: &Option<ExpectedDigest>,
    destination: &Path,
) -> Result<StagedFile, Report<OperationError>> {
    let mut source = std::fs::File::open(path).map_err(|err| {
        OperationError::ReadSource
            .report()
            .attach(err)
            .attach(PathLabel::from(path))
    })?;

    // Authoritative source size: refresh metadata so a file that changed
    // between `ArtifactLink::local` and this read is detected.
    let actual_size = source
        .metadata()
        .map(|metadata| metadata.len() as u128)
        .map_err(|err| {
            OperationError::ReadSource
                .report()
                .attach(err)
                .attach(PathLabel::from(path))
        })?;
    if actual_size != declared_size && actual_size != link_digest.file_size {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(PathLabel::from(path))
            .attach(SizePair {
                expected: declared_size,
                actual: actual_size,
            }));
    }

    let staged = stream_copy(&mut source, expected, destination).map_err(|err| {
        err.change_context(OperationError::ReadSource)
            .attach(PathLabel::from(path))
    })?;

    validate_outcome(
        staged,
        declared_size,
        expected,
        SourceLabel::Path(path.to_path_buf()),
    )
}

fn copy_bytes(
    bytes: &bytes::Bytes,
    declared_size: u128,
    expected: &Option<ExpectedDigest>,
    destination: &Path,
) -> Result<StagedFile, Report<OperationError>> {
    if bytes.len() as u128 != declared_size {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(SourceLabel::Bytes(bytes.clone()))
            .attach(SizePair {
                expected: declared_size,
                actual: bytes.len() as u128,
            }));
    }

    let mut cursor = std::io::Cursor::new(bytes.clone());
    let staged = stream_copy(&mut cursor, expected, destination)
        .map_err(|err| err.change_context(OperationError::WriteDestination))?;

    validate_outcome(
        staged,
        declared_size,
        expected,
        SourceLabel::Bytes(bytes.clone()),
    )
}

fn copy_http(
    url: &str,
    declared_size: u128,
    link_digest: &LinkDigest,
    expected: &Option<ExpectedDigest>,
    destination: &Path,
) -> Result<StagedFile, Report<OperationError>> {
    // Use reqwest::blocking per the contract: the entire layer is never
    // buffered in memory; the body is streamed straight to the temp file.
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            // Reject any redirect that leaves the HTTP/HTTPS scheme. The
            // blocking client's `Attempt::previous` returns the chain of
            // already-visited URLs; cap it at `HTTP_MAX_REDIRECTS`.
            let visited = attempt.previous().len();
            let scheme = attempt.url().scheme().to_string();
            match scheme.as_str() {
                "http" | "https" => {
                    if visited >= HTTP_MAX_REDIRECTS {
                        attempt.error("too many redirects")
                    } else {
                        attempt.follow()
                    }
                }
                other => attempt.error(format!("unsupported redirect scheme: {other}")),
            }
        }))
        .build()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;

    let response =
        crate::ops::registry::blocking_get_with_challenge(&client, url, &HeaderMap::new())?;

    let status = response.status();
    if !status.is_success() {
        return Err(OperationError::HttpStatus
            .report()
            .attach(url.to_string())
            .attach(status.as_u16()));
    }

    let declared_content_length = response.content_length().map(|len| len as u128);

    // If both the link's known size and the server's declared content length
    // are non-zero and informative, they must agree.
    if let Some(content_length) = declared_content_length
        && declared_size != 0
        && content_length != 0
        && content_length != declared_size
    {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(url.to_string())
            .attach(SizePair {
                expected: declared_size,
                actual: content_length,
            }));
    }

    let staged = {
        let mut reader = response;
        stream_copy(&mut reader, expected, destination).map_err(|err| {
            err.change_context(OperationError::HttpRequest)
                .attach(url.to_string())
        })?
    };

    validate_http_outcome(
        staged,
        declared_size,
        declared_content_length,
        link_digest,
        expected,
        url,
    )
}

/// Stream any reader implementing [`Read`] into a temp file at
/// `destination` while computing BLAKE3 plus an optional auxiliary digest.
fn stream_copy<R: Read>(
    source: &mut R,
    expected: &Option<ExpectedDigest>,
    destination: &Path,
) -> Result<StagedFile, Report<crate::ops::error::TempFileError>> {
    let mut writer = TempWriter::open(destination)?;
    writer.set_expected_digest(expected.as_ref());
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).map_err(|err| {
            crate::ops::error::TempFileError::Read(writer.temp_path().to_path_buf(), err).report()
        })?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
    }
    writer.stage()
}

/// Authority to attach to size/digest-mismatch errors. Stored as a printable
/// label so a `Report<OperationError>` keeps a readable attribution.
#[derive(Debug, Clone)]
enum SourceLabel {
    Path(PathBuf),
    Bytes(bytes::Bytes),
    Http(String),
}

impl std::fmt::Display for SourceLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Bytes(bytes) => write!(f, "<{} in-memory bytes>", bytes.len()),
            Self::Http(url) => write!(f, "{url}"),
        }
    }
}

/// A path label that prints using `Path::display`, so it can be attached to a
/// `Report` even though `PathBuf` itself does not implement `Display`.
#[derive(Debug, Clone)]
struct PathLabel(PathBuf);

impl std::fmt::Display for PathLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl<'a> From<&'a Path> for PathLabel {
    fn from(path: &'a Path) -> Self {
        Self(path.to_path_buf())
    }
}

/// A pair of expected and actual sizes. Attaches to size-mismatch errors so
/// callers can inspect the divergence without parsing the report text.
#[derive(Debug, Clone, Copy)]
struct SizePair {
    expected: u128,
    actual: u128,
}

impl std::fmt::Display for SizePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected {} bytes, got {} bytes",
            self.expected, self.actual
        )
    }
}

/// Verify sizes and digests against the link size and the manifest-declared
/// digest. Failures are reported as `SizeMismatch` or `DigestMismatch`.
fn validate_outcome(
    staged: StagedFile,
    declared_size: u128,
    expected: &Option<ExpectedDigest>,
    label: SourceLabel,
) -> Result<StagedFile, Report<OperationError>> {
    let published = staged.metadata.clone();
    if declared_size != 0 && published.file_digest.file_size != declared_size {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(label)
            .attach(SizePair {
                expected: declared_size,
                actual: published.file_digest.file_size,
            }));
    }

    verify_against_expected(&published, expected, label)?;
    Ok(staged)
}

/// `validate_outcome` for HTTP sources. Mirrors the body but folds the
/// HTTP content-length (when positive) into the size check, and falls back
/// to the link-digest size when the response did not declare one.
fn validate_http_outcome(
    staged: StagedFile,
    declared_size: u128,
    http_content_length: Option<u128>,
    link_digest: &LinkDigest,
    expected: &Option<ExpectedDigest>,
    url: &str,
) -> Result<StagedFile, Report<OperationError>> {
    let published = staged.metadata.clone();
    let label = SourceLabel::Http(url.to_string());

    // The link stores a known size of zero when the server did not declare a
    // content length at HEAD time. Treat that as "size unknown" so a zero
    // declared size never matches against the final bytes count.
    let http_declared = http_content_length.filter(|len| *len > 0);
    let link_known = if link_digest.file_size > 0 {
        Some(link_digest.file_size)
    } else {
        None
    };
    let declared_known = if declared_size != 0 {
        Some(declared_size)
    } else {
        None
    };

    if let Some(content_length) = http_declared {
        if published.file_digest.file_size != content_length {
            return Err(OperationError::SizeMismatch
                .report()
                .attach(label)
                .attach(SizePair {
                    expected: content_length,
                    actual: published.file_digest.file_size,
                }));
        }
    } else if let Some(link_size) = link_known
        && published.file_digest.file_size != link_size
    {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(label.clone())
            .attach(SizePair {
                expected: link_size,
                actual: published.file_digest.file_size,
            }));
    } else if let Some(declared) = declared_known
        && published.file_digest.file_size != declared
    {
        return Err(OperationError::SizeMismatch
            .report()
            .attach(label.clone())
            .attach(SizePair {
                expected: declared,
                actual: published.file_digest.file_size,
            }));
    }

    verify_against_expected(&published, expected, label)?;
    Ok(staged)
}

fn verify_against_expected(
    published: &crate::ops::io::PublishedFile,
    expected: &Option<ExpectedDigest>,
    label: SourceLabel,
) -> Result<(), Report<OperationError>> {
    if let Some(expected) = expected {
        let computed = published.computed_for(Some(expected));
        match computed {
            Some(value) if expected.verify(&value) => {}
            other => {
                return Err(OperationError::DigestMismatch
                    .report()
                    .attach(label)
                    .attach(
                        other
                            .map(|c| format!("{c:?}"))
                            .unwrap_or_else(|| "no".into()),
                    ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_header_helper_succeeds_for_short_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("short.bin");
        std::fs::write(&path, b"abc").expect("write");
        let header = io::read_header(&path, MIN_HEADER_LEN).expect("header");
        assert_eq!(header, b"abc");
    }

    #[test]
    fn read_header_helper_reads_partial_for_short_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("tiny.bin");
        std::fs::write(&path, b"abc").expect("write");
        let header = io::read_header(&path, 512).expect("header");
        assert_eq!(header, b"abc");
    }

    #[test]
    fn size_pair_displays_expected_actual() {
        let pair = SizePair {
            expected: 4,
            actual: 8,
        };
        let text = format!("{pair}");
        assert!(text.contains("expected 4 bytes"));
        assert!(text.contains("got 8 bytes"));
    }

    #[test]
    fn source_label_path_display_uses_path_display() {
        let label = SourceLabel::Path(PathBuf::from("/tmp/x.bin"));
        assert_eq!(format!("{label}"), "/tmp/x.bin");
    }
}
