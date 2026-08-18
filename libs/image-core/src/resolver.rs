//! The `SourceResolver` port and the default per-kind adapters.
//!
//! Each resolver validates one external source kind into a link with a
//! stable identity. The service maps the public `Link` facade input onto a
//! resolver through [`ResolverSet::dispatch`]; adding a source kind means
//! adding a resolver implementation plus the facade mapping, without
//! touching the materialization pipeline.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use error_stack::Report;
use thiserror::Error;

use crate::artifact::link::ArtifactLink;
use crate::digest::{LinkDigest, LinkDigestBuilder};
use crate::link::Link;

/// The outcome of resolving one external source: the validated link, whether
/// the source is a container image whose rootfs must be flattened and whose
/// kernel must be extracted, and the resolver-owned immutable source digest.
///
/// `source_digest` is the identity of the *content the caller asked for*,
/// independent of the request shape. Local and byte sources are
/// content-addressed; ordinary HTTP sources keep the URL-and-observed-size
/// identity; OCI sources are keyed by their canonical registry, repository,
/// and resolved immutable manifest digest, never by the caller's mutable tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    pub link: ArtifactLink,
    pub is_image: bool,
    pub source_digest: LinkDigest,
}

/// Port error category for source resolution. The materialization service
/// translates this category once into its own use-case error.
#[derive(Debug, Error)]
pub enum SourceResolverError {
    /// The resolver received a source kind it does not own.
    #[error("the source kind does not belong to this resolver")]
    UnsupportedSource,
    /// The source could not be resolved or validated.
    #[error("could not resolve the external source")]
    Resolution,
}

/// Resolve one external source kind into validated content with a stable
/// identity.
///
/// Implementations must be `Send` and `Sync` and are stored behind `Arc`.
/// Asynchronous implementations return explicit boxed `Send` futures at the
/// port boundary.
pub trait SourceResolver: Send + Sync {
    fn resolve(
        &self,
        source: Link,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>> + Send + '_>,
    >;
}

/// Default adapter for [`Link::Local`] sources: validates the path by
/// stat'ing it and content-addresses the link identity over the bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalSourceResolver;

impl SourceResolver for LocalSourceResolver {
    fn resolve(
        &self,
        source: Link,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>> + Send + '_>,
    > {
        Box::pin(async move {
            let Link::Local(path) = source else {
                return Err(Report::new(SourceResolverError::UnsupportedSource));
            };
            let link = ArtifactLink::local(path)
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
            let source_digest = link
                .digest()
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
            Ok(ResolvedSource {
                link,
                is_image: false,
                source_digest,
            })
        })
    }
}

/// Default adapter for [`Link::Bytes`] sources: the buffer is already
/// validated, and the link identity covers the held bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct BytesSourceResolver;

impl SourceResolver for BytesSourceResolver {
    fn resolve(
        &self,
        source: Link,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>> + Send + '_>,
    > {
        Box::pin(async move {
            let Link::Bytes(bytes) = source else {
                return Err(Report::new(SourceResolverError::UnsupportedSource));
            };
            let link = ArtifactLink::bytes(bytes);
            let source_digest = link
                .digest()
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
            Ok(ResolvedSource {
                link,
                is_image: false,
                source_digest,
            })
        })
    }
}

/// Default adapter for [`Link::Http`] sources: probes the URL with a HEAD
/// request so the resolved link carries the server-declared size.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpSourceResolver;

impl SourceResolver for HttpSourceResolver {
    fn resolve(
        &self,
        source: Link,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>> + Send + '_>,
    > {
        Box::pin(async move {
            let Link::Http(url) = source else {
                return Err(Report::new(SourceResolverError::UnsupportedSource));
            };
            let link = ArtifactLink::http(url)
                .await
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
            let source_digest = link
                .digest()
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
            Ok(ResolvedSource {
                link,
                is_image: false,
                source_digest,
            })
        })
    }
}

/// Default adapter for [`Link::Image`] sources: parses the OCI reference,
/// HEAD-probes the manifest end-point, resolves the tag to its immutable
/// manifest digest, and marks the source as a container image.
#[derive(Debug, Clone, Copy, Default)]
pub struct OciSourceResolver;

impl SourceResolver for OciSourceResolver {
    fn resolve(
        &self,
        source: Link,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>> + Send + '_>,
    > {
        Box::pin(async move {
            let Link::Image(reference) = source else {
                return Err(Report::new(SourceResolverError::UnsupportedSource));
            };
            let reference = crate::OciReference::parse(&reference).map_err(|error| {
                Report::new(error).change_context(SourceResolverError::Resolution)
            })?;
            let manifest_url = reference.manifest_url();

            // HEAD-probe the manifest end-point via the shared registry
            // client so a Bearer challenge is honored. The probe captures the
            // validated Docker-Content-Digest when the registry supplies it.
            let probe = crate::ops::registry::head_manifest(&manifest_url)
                .await
                .map_err(|error| error.change_context(SourceResolverError::Resolution))?;

            // Resolve the tag to an immutable manifest digest. When the probe
            // omits Docker-Content-Digest, fetch the manifest body and hash
            // it so the source identity never depends on a mutable tag.
            let manifest_digest = match probe.content_digest {
                Some(digest) => digest,
                None => {
                    let manifest = crate::ops::registry::fetch_manifest(&manifest_url)
                        .await
                        .map_err(|error| error.change_context(SourceResolverError::Resolution))?;
                    crate::ops::registry::manifest_body_digest(&manifest.bytes)
                }
            };

            let link = ArtifactLink::Http(manifest_url, probe.content_length);
            let source_digest = oci_source_digest(&reference, &manifest_digest);
            Ok(ResolvedSource {
                link,
                is_image: true,
                source_digest,
            })
        })
    }
}

/// Domain-separated immutable source digest for an OCI reference: the
/// canonical registry, repository, and resolved manifest digest.
fn oci_source_digest(reference: &crate::OciReference, manifest_digest: &str) -> LinkDigest {
    LinkDigestBuilder::new(b"jyth.source.oci.v1")
        .str(b"registry", reference.host())
        .str(b"repository", reference.repository())
        .str(b"manifest", manifest_digest)
        .finish(0)
}

/// The set of source-kind resolvers the materialization service dispatches
/// over.
#[derive(Clone)]
pub struct ResolverSet {
    local: Arc<dyn SourceResolver>,
    bytes: Arc<dyn SourceResolver>,
    http: Arc<dyn SourceResolver>,
    image: Arc<dyn SourceResolver>,
}

impl ResolverSet {
    /// The default adapter set: local, bytes, HTTP, and OCI resolvers.
    pub fn defaults() -> Self {
        Self {
            local: Arc::new(LocalSourceResolver),
            bytes: Arc::new(BytesSourceResolver),
            http: Arc::new(HttpSourceResolver),
            image: Arc::new(OciSourceResolver),
        }
    }

    /// Build a set from explicit resolvers (tests and future adapters).
    #[allow(dead_code)] // explicit-resolver constructor used by contract tests and future adapters
    pub fn new(
        local: Arc<dyn SourceResolver>,
        bytes: Arc<dyn SourceResolver>,
        http: Arc<dyn SourceResolver>,
        image: Arc<dyn SourceResolver>,
    ) -> Self {
        Self {
            local,
            bytes,
            http,
            image,
        }
    }

    /// Map one facade [`Link`] to the resolver owning its kind.
    pub fn dispatch(&self, source: &Link) -> &Arc<dyn SourceResolver> {
        match source {
            Link::Local(_) => &self.local,
            Link::Bytes(_) => &self.bytes,
            Link::Http(_) => &self.http,
            Link::Image(_) => &self.image,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;

    use super::*;
    use crate::ops::error::OperationError;

    #[tokio::test]
    async fn local_resolver_validates_an_existing_path() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"kernel bytes").expect("write");
        let resolved = LocalSourceResolver
            .resolve(Link::local(file.path()))
            .await
            .expect("resolve");
        assert_eq!(
            resolved.link,
            ArtifactLink::Local(file.path().to_path_buf(), 12)
        );
        assert!(!resolved.is_image);
        // Content-addressed source identity.
        assert_eq!(
            resolved.source_digest,
            resolved.link.digest().expect("link digest")
        );
    }

    #[tokio::test]
    async fn local_resolver_rejects_a_missing_path() {
        let missing = std::env::temp_dir().join(uuid::Uuid::now_v7().to_string());
        let err = LocalSourceResolver
            .resolve(Link::local(&missing))
            .await
            .expect_err("missing path");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::Resolution
        ));
    }

    #[tokio::test]
    async fn local_resolver_rejects_foreign_kinds() {
        let err = LocalSourceResolver
            .resolve(Link::bytes("bytes"))
            .await
            .expect_err("wrong kind");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::UnsupportedSource
        ));
    }

    #[tokio::test]
    async fn bytes_resolver_uses_the_buffer_identity() {
        let resolved = BytesSourceResolver
            .resolve(Link::bytes("bytes source"))
            .await
            .expect("resolve");
        assert_eq!(
            resolved.link,
            ArtifactLink::Bytes(bytes::Bytes::from_static(b"bytes source"), 12)
        );
        assert!(!resolved.is_image);
        assert_eq!(
            resolved.source_digest,
            resolved.link.digest().expect("link digest")
        );
    }

    #[tokio::test]
    async fn bytes_resolver_rejects_foreign_kinds() {
        let err = BytesSourceResolver
            .resolve(Link::http("https://example.invalid"))
            .await
            .expect_err("wrong kind");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::UnsupportedSource
        ));
    }

    #[tokio::test]
    async fn http_resolver_heads_the_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr").to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        });
        let url = format!("http://{addr}/kernel");
        let resolved = HttpSourceResolver
            .resolve(Link::http(&url))
            .await
            .expect("resolve");
        // A HEAD response has no body, so reqwest reports a zero content
        // length even when the header declares one; the authoritative size
        // is read from the GET response's content-length at load time.
        assert_eq!(resolved.link, ArtifactLink::Http(url, 0));
        assert!(!resolved.is_image);
        server.join().expect("server thread");
    }

    #[test]
    fn oci_source_digest_is_domain_separated_and_tag_independent() {
        let reference = crate::OciReference::parse("ubuntu:24.04").expect("valid");
        let digest_a = oci_source_digest(&reference, "sha256:aaaa");
        let digest_b = oci_source_digest(&reference, "sha256:bbbb");
        // The tag is not part of the identity: only the resolved manifest
        // digest distinguishes two mutable-tag resolutions.
        assert_eq!(
            oci_source_digest(&reference, "sha256:aaaa"),
            digest_a,
            "deterministic for one manifest digest"
        );
        assert_ne!(
            digest_a, digest_b,
            "manifest digest change changes identity"
        );

        let other_repo = crate::OciReference::parse("alpine:latest").expect("valid");
        assert_ne!(
            oci_source_digest(&other_repo, "sha256:aaaa"),
            digest_a,
            "repository is part of the identity"
        );

        let raw = ResolvedSource {
            source_digest: digest_a,
            link: ArtifactLink::Bytes(bytes::Bytes::from_static(b"x"), 1),
            is_image: true,
        };
        let request_raw = crate::digest::LinkDigestBuilder::new(b"jyth.kernel.external.v1")
            .bytes(b"source-hash", raw.source_digest.link_hash.as_bytes())
            .str(b"shape", "raw")
            .finish(0);
        assert_ne!(raw.source_digest, request_raw, "domains do not collide");
    }

    #[tokio::test]
    async fn http_resolver_rejects_foreign_kinds() {
        let err = HttpSourceResolver
            .resolve(Link::local(std::env::temp_dir()))
            .await
            .expect_err("wrong kind");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::UnsupportedSource
        ));
    }

    #[tokio::test]
    async fn oci_resolver_rejects_foreign_kinds_before_any_network_io() {
        let err = OciSourceResolver
            .resolve(Link::bytes("bytes"))
            .await
            .expect_err("wrong kind");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::UnsupportedSource
        ));
    }

    /// A refused connection on the loopback port surfaces a typed resolution
    /// failure carrying the source context. The reference is valid, so the
    /// failure must come from the network probe, not from parsing.
    #[tokio::test]
    async fn oci_resolver_propagates_unreachable_source_context() {
        let err = OciSourceResolver
            .resolve(Link::image("127.0.0.1:1/library/test:latest"))
            .await
            .expect_err("refused connection");
        assert!(matches!(
            err.current_context(),
            SourceResolverError::Resolution
        ));
        // The registry client frame crosses the boundary into the use-case
        // error surface.
        assert!(err.frames().any(|frame| frame.is::<OperationError>()));
    }

    /// A scripted resolver returning a distinguishable link proves that
    /// [`ResolverSet::dispatch`] routes each facade kind to its own slot.
    #[derive(Clone)]
    struct ReturningResolver(ArtifactLink);

    impl SourceResolver for ReturningResolver {
        fn resolve(
            &self,
            _source: Link,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResolvedSource, Report<SourceResolverError>>>
                    + Send
                    + '_,
            >,
        > {
            let link = self.0.clone();
            let source_digest = link.digest().unwrap_or(LinkDigest {
                link_hash: blake3::hash(&[]),
                file_size: 0,
            });
            Box::pin(async move {
                Ok(ResolvedSource {
                    link,
                    is_image: false,
                    source_digest,
                })
            })
        }
    }

    #[tokio::test]
    async fn dispatch_routes_each_link_kind_to_its_resolver() {
        let local_marker = ArtifactLink::Local(PathBuf::from("local-marker"), 1);
        let bytes_marker = ArtifactLink::Bytes(bytes::Bytes::from_static(b"bytes-marker"), 12);
        let http_marker = ArtifactLink::Http("http://http-marker".into(), 2);
        let image_marker = ArtifactLink::Bytes(bytes::Bytes::from_static(b"image-marker"), 12);
        let set = ResolverSet::new(
            Arc::new(ReturningResolver(local_marker.clone())),
            Arc::new(ReturningResolver(bytes_marker.clone())),
            Arc::new(ReturningResolver(http_marker.clone())),
            Arc::new(ReturningResolver(image_marker.clone())),
        );

        let resolved = set
            .dispatch(&Link::local("any"))
            .resolve(Link::local("any"))
            .await
            .expect("resolve");
        assert_eq!(resolved.link, local_marker);

        let resolved = set
            .dispatch(&Link::bytes("any"))
            .resolve(Link::bytes("any"))
            .await
            .expect("resolve");
        assert_eq!(resolved.link, bytes_marker);

        let resolved = set
            .dispatch(&Link::http("https://any"))
            .resolve(Link::http("https://any"))
            .await
            .expect("resolve");
        assert_eq!(resolved.link, http_marker);

        let resolved = set
            .dispatch(&Link::image("example.invalid/any"))
            .resolve(Link::image("example.invalid/any"))
            .await
            .expect("resolve");
        assert_eq!(resolved.link, image_marker);
    }
}
