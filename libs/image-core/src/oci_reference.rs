//! A validated, canonical OCI image reference.
//!
//! `OciReference` owns the OCI reference grammar and the canonical
//! representation used for borrowed access and hashing:
//!
//! ```text
//! [host[:port]/]repository[/component...][:tag][@digest]
//! ```
//!
//! Validation happens at construction time and never performs network or
//! filesystem I/O. The value normalizes Docker Hub shorthand, resolves the
//! default tag, and rejects malformed repository components, tags, and
//! digests before any asynchronous materialization begins.
//!
//! The type replaces the historical public role of
//! [`crate::ops::registry::ImageReference`]: registry URL construction
//! consumes an `OciReference` directly instead of reparsing a raw string.

use std::fmt;
use std::str::FromStr;

/// Validation failure for [`OciReference`].
///
/// Every variant identifies the invalid field with a stable reason category;
/// messages never include credentials or query values (the grammar rejects
/// both).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OciReferenceError {
    /// The reference is empty.
    #[error("OCI reference must not be empty")]
    Empty,
    /// The reference carries an unsupported URL scheme; only `http` and
    /// `https` are accepted, and only as an explicit prefix.
    #[error("OCI reference must not include a URL scheme")]
    HasUrlScheme,
    /// An explicit scheme prefix left nothing after `://`.
    #[error("OCI reference scheme prefix must be followed by a reference")]
    InvalidReference,
    /// The digest is missing its `<algorithm>:<hex>` separator.
    #[error("OCI reference digest must use the `<algorithm>:<hex>` form")]
    InvalidDigest,
    /// The digest uses an unsupported algorithm.
    #[error("unsupported digest algorithm")]
    UnsupportedDigestAlgorithm,
    /// The digest hex payload has an invalid length or content.
    #[error("invalid digest hex payload")]
    InvalidDigestHex,
    /// The tag contains invalid characters or exceeds the length limit.
    #[error("invalid tag")]
    InvalidTag,
    /// A repository component is empty.
    #[error("repository contains an empty component")]
    EmptyRepositoryComponent,
    /// A repository component contains invalid characters or separators.
    #[error("invalid repository component characters")]
    InvalidRepositoryComponent,
    /// The manifest URL does not match the `/v2/<repository>/manifests/...`
    /// shape.
    #[error("manifest URL is not a /v2/.../manifests/... path")]
    InvalidManifestUrl,
}

/// A validated OCI image reference.
///
/// The value owns the parsed host, repository, tag, digest, and (for
/// manifest-URL-derived references) transport scheme, plus one canonical
/// reference string used for borrowed access, equality, and hashing.
#[derive(Debug, Clone)]
pub struct OciReference {
    host: String,
    repository: String,
    tag: Option<String>,
    digest: Option<String>,
    /// URL scheme used to build manifest and blob URLs. Defaults to `https`;
    /// preserved from a parsed manifest URL so a local HTTP test registry can
    /// serve blueprint requests over plain HTTP.
    scheme: String,
    /// Canonical `host/repository[:tag][@digest]` string. The tag is
    /// normalized to `latest` when neither a tag nor a digest was given, so
    /// `ubuntu` and `ubuntu:latest` compare and hash equally.
    canonical: String,
}

/// Default Docker Hub registry host used when no host is given in a
/// reference.
pub const DEFAULT_HOST: &str = "registry-1.docker.io";

/// Maximum length of a repository component.
const MAX_COMPONENT_LEN: usize = 255;
/// Maximum length of a tag.
const MAX_TAG_LEN: usize = 128;

impl OciReference {
    /// Parse `[scheme://][host[:port]/]repository[/component...][:tag][@digest]`.
    ///
    /// A leading component containing `.`, `:`, `localhost` or bracketed IPv6
    /// literals is the registry host; otherwise Docker Hub's
    /// [`DEFAULT_HOST`] is used. A single-segment Docker Hub repository gets
    /// the `library/` namespace prefix; a multi-segment repository is
    /// preserved verbatim.
    ///
    /// An explicit `http://` or `https://` scheme prefix is accepted and
    /// preserved for registry URL construction (mirroring
    /// [`Self::from_manifest_url`]); the canonical string remains scheme-less.
    pub fn parse(value: &str) -> Result<Self, OciReferenceError> {
        if value.is_empty() {
            return Err(OciReferenceError::Empty);
        }

        // Plan variation (Jyth review remediation, WP2): an explicit
        // `http://` or `https://` scheme prefix is accepted and preserved so
        // the Jyth-owned toolchain registry (a plain-HTTP LAN registry) can
        // be referenced by manifest digest. This mirrors the scheme handling
        // of `from_manifest_url`; the canonical string stays scheme-less.
        let (scheme, reference) = match value.split_once("://") {
            Some((scheme, rest)) if scheme == "http" || scheme == "https" => {
                if rest.is_empty() {
                    return Err(OciReferenceError::InvalidReference);
                }
                (Some(scheme.to_string()), rest)
            }
            Some(_) => return Err(OciReferenceError::HasUrlScheme),
            None => (None, value),
        };

        let (name, digest) = match reference.split_once('@') {
            Some((name, digest)) if !name.is_empty() && !digest.is_empty() => {
                validate_digest(digest)?;
                (name, Some(digest.to_string()))
            }
            Some(_) => return Err(OciReferenceError::InvalidDigest),
            None => (reference, None),
        };

        // A colon is a tag separator only when it appears after the final
        // slash. This preserves registry ports such as `localhost:5000`.
        let last_slash = name.rfind('/');
        let tag_separator = name
            .rfind(':')
            .filter(|index| last_slash.map(|slash| *index > slash).unwrap_or(true));
        let (repository, tag) = match tag_separator {
            Some(index) => {
                let repository = &name[..index];
                let tag = &name[index + 1..];
                if repository.is_empty() || tag.is_empty() {
                    return Err(OciReferenceError::InvalidTag);
                }
                (repository, Some(tag))
            }
            None => (name, None),
        };

        if let Some(tag) = tag {
            validate_tag(tag)?;
        }

        // The first path component is a host only when it looks like one
        // (contains `.` or `:`, is `localhost`, or is a bracketed IPv6
        // literal). Otherwise the whole string is the repository.
        let (host, repository) = match repository.split_once('/') {
            None => (DEFAULT_HOST.to_string(), repository.to_string()),
            Some((first, rest)) => {
                if looks_like_host(first) {
                    (first.to_string(), rest.to_string())
                } else {
                    (DEFAULT_HOST.to_string(), repository.to_string())
                }
            }
        };

        // Docker Hub shorthand: only a single-segment repository receives the
        // `library/` namespace prefix. A multi-segment repository such as
        // `acme/widget` is preserved without it.
        let repository = if host == DEFAULT_HOST && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };

        validate_repository(&repository)?;

        // The tag defaults to `latest` only when neither a tag nor a digest
        // was given, so `ubuntu` and `ubuntu:latest` normalize identically.
        let tag = tag.map(str::to_string).or_else(|| {
            if digest.is_none() {
                Some("latest".to_string())
            } else {
                None
            }
        });

        let canonical = build_canonical(&host, &repository, tag.as_deref(), digest.as_deref());
        Ok(Self {
            host,
            repository,
            tag,
            digest,
            scheme: scheme.unwrap_or_else(|| "https".to_string()),
            canonical,
        })
    }

    /// Recover a reference from a manifest URL of the form
    /// `[scheme://]host[:port]/v2/<repository...>/manifests/<tag-or-digest>`.
    ///
    /// The internal `http` or `https` scheme is preserved so a local test
    /// registry can serve blueprint requests over plain HTTP. The value is
    /// intended for registry URL construction; its canonical string remains
    /// scheme-less.
    pub fn from_manifest_url(url: &str) -> Result<Self, OciReferenceError> {
        let parsed = url::Url::parse(url).map_err(|_| OciReferenceError::InvalidManifestUrl)?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(OciReferenceError::InvalidManifestUrl);
        }
        let host = parsed
            .host_str()
            .ok_or(OciReferenceError::InvalidManifestUrl)?
            .to_string();
        let host = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let scheme = parsed.scheme().to_string();
        let path = parsed.path().to_string();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() < 3 || segments[0] != "v2" {
            return Err(OciReferenceError::InvalidManifestUrl);
        }
        let manifests_idx = match segments.iter().rposition(|s| *s == "manifests") {
            Some(idx) if idx > 0 && idx == segments.len() - 2 => idx,
            _ => return Err(OciReferenceError::InvalidManifestUrl),
        };
        let repository = segments[1..manifests_idx].join("/");
        validate_repository(&repository)?;
        let selector = segments[segments.len() - 1];
        let (tag, digest) = if selector.starts_with("sha256:") || selector.starts_with("sha512:") {
            validate_digest(selector)?;
            (None, Some(selector.to_string()))
        } else {
            validate_tag(selector)?;
            (Some(selector.to_string()), None)
        };

        let canonical = build_canonical(&host, &repository, tag.as_deref(), digest.as_deref());
        Ok(Self {
            host,
            repository,
            tag,
            digest,
            scheme,
            canonical,
        })
    }

    /// The registry host (`localhost:5000`, `registry-1.docker.io`, ...).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The repository path under the registry v2 namespace
    /// (`library/ubuntu`, `acme/widget`, ...).
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// The tag part of the reference; `None` when only a digest is present.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The digest pin like `sha256:abcd...`; `None` when only a tag is
    /// present.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// The URL scheme used to build manifest and blob URLs.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The canonical reference string (`host/repository[:tag][@digest]`).
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The manifest or blob selector: the digest when pinned, otherwise the
    /// tag, otherwise `latest`.
    pub fn selector(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }

    /// Build the canonical manifest URL for this reference.
    pub fn manifest_url(&self) -> String {
        format!(
            "{scheme}://{host}/v2/{repo}/manifests/{selector}",
            scheme = self.scheme,
            host = self.host,
            repo = self.repository,
            selector = self.selector(),
        )
    }

    /// Build the manifest URL when a digest is already known. Used to fetch
    /// an inner manifest referenced by digest from an OCI index.
    pub fn manifest_url_for_digest(&self, digest: &str) -> String {
        format!(
            "{scheme}://{host}/v2/{repo}/manifests/{digest}",
            scheme = self.scheme,
            host = self.host,
            repo = self.repository,
        )
    }

    /// Build the canonical blob URL for a digest.
    pub fn blob_url(&self, digest: &str) -> String {
        format!(
            "{scheme}://{host}/v2/{repo}/blobs/{digest}",
            scheme = self.scheme,
            host = self.host,
            repo = self.repository,
        )
    }
}

/// Decide whether `first` is a registry host rather than a repository
/// component: dotted names, names with ports, `localhost`, and bracketed IPv6
/// literals are hosts.
fn looks_like_host(first: &str) -> bool {
    first.contains('.')
        || first.contains(':')
        || first == "localhost"
        || (first.starts_with('[') && first.contains(']'))
}

/// Validate the `<algorithm>:<hex>` digest. Only `sha256` and `sha512` are
/// accepted, with their canonical hex lengths.
fn validate_digest(digest: &str) -> Result<(), OciReferenceError> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(OciReferenceError::InvalidDigest);
    };
    let expected_len = match algorithm {
        "sha256" => 64,
        "sha512" => 128,
        _ => return Err(OciReferenceError::UnsupportedDigestAlgorithm),
    };
    if hex.len() != expected_len || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OciReferenceError::InvalidDigestHex);
    }
    Ok(())
}

/// Validate a tag: `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`.
fn validate_tag(tag: &str) -> Result<(), OciReferenceError> {
    if tag.is_empty() || tag.len() > MAX_TAG_LEN {
        return Err(OciReferenceError::InvalidTag);
    }
    let mut chars = tag.chars();
    let first = chars.next().expect("non-empty checked above");
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(OciReferenceError::InvalidTag);
    }
    if chars.any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')) {
        return Err(OciReferenceError::InvalidTag);
    }
    Ok(())
}

/// Validate repository components: non-empty, at most 255 characters, and
/// matching the Docker component grammar
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn validate_repository(repository: &str) -> Result<(), OciReferenceError> {
    if repository.is_empty() {
        return Err(OciReferenceError::EmptyRepositoryComponent);
    }
    for component in repository.split('/') {
        if component.is_empty() {
            return Err(OciReferenceError::EmptyRepositoryComponent);
        }
        if component.len() > MAX_COMPONENT_LEN {
            return Err(OciReferenceError::InvalidRepositoryComponent);
        }
        validate_component(component)?;
    }
    Ok(())
}

/// Validate a single repository component against the Docker grammar.
fn validate_component(component: &str) -> Result<(), OciReferenceError> {
    let bytes = component.as_bytes();
    let mut index = 0;
    // `[a-z0-9]+`
    let start = index;
    while index < bytes.len()
        && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
    {
        index += 1;
    }
    if index == start {
        return Err(OciReferenceError::InvalidRepositoryComponent);
    }
    // `((\.|_|__|-+)[a-z0-9]+)*`
    while index < bytes.len() {
        match bytes[index] {
            b'.' => index += 1,
            b'_' => {
                index += 1;
                if index < bytes.len() && bytes[index] == b'_' {
                    index += 1;
                }
            }
            b'-' => {
                while index < bytes.len() && bytes[index] == b'-' {
                    index += 1;
                }
            }
            _ => return Err(OciReferenceError::InvalidRepositoryComponent),
        }
        let segment_start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
        {
            index += 1;
        }
        if index == segment_start {
            return Err(OciReferenceError::InvalidRepositoryComponent);
        }
    }
    Ok(())
}

/// Build the canonical `host/repository[:tag][@digest]` string. Both the tag
/// and the digest are preserved when both exist; URL construction prefers the
/// digest via [`OciReference::selector`].
fn build_canonical(
    host: &str,
    repository: &str,
    tag: Option<&str>,
    digest: Option<&str>,
) -> String {
    let mut canonical = format!("{host}/{repository}");
    if let Some(tag) = tag {
        canonical.push(':');
        canonical.push_str(tag);
    }
    if let Some(digest) = digest {
        canonical.push('@');
        canonical.push_str(digest);
    }
    canonical
}

impl FromStr for OciReference {
    type Err = OciReferenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for OciReference {
    type Error = OciReferenceError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for OciReference {
    fn as_ref(&self) -> &str {
        self.canonical()
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical())
    }
}

// Identity is the canonical reference string. The transport scheme is a URL
// construction detail and is excluded so equivalent spellings compare equal.
impl PartialEq for OciReference {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for OciReference {}

impl std::hash::Hash for OciReference {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_hub_single_segment_gets_library_prefix() {
        let image = OciReference::parse("ubuntu").expect("parsed");
        assert_eq!(image.host(), DEFAULT_HOST);
        assert_eq!(image.repository(), "library/ubuntu");
        assert_eq!(image.tag(), Some("latest"));
        assert_eq!(image.digest(), None);
        assert_eq!(image.selector(), "latest");
        assert_eq!(
            image.canonical(),
            "registry-1.docker.io/library/ubuntu:latest"
        );
        assert!(image.manifest_url().ends_with("/manifests/latest"));
    }

    #[test]
    fn docker_hub_multi_segment_is_preserved_without_library_prefix() {
        let image = OciReference::parse("acme/widget").expect("parsed");
        assert_eq!(image.host(), DEFAULT_HOST);
        assert_eq!(image.repository(), "acme/widget");
        assert_eq!(image.canonical(), "registry-1.docker.io/acme/widget:latest");
    }

    #[test]
    fn linuxkit_reference_is_preserved_verbatim() {
        let image =
            OciReference::parse("registry-1.docker.io/linuxkit/kernel:6.6.13").expect("parsed");
        assert_eq!(image.host(), "registry-1.docker.io");
        assert_eq!(image.repository(), "linuxkit/kernel");
        assert_eq!(image.tag(), Some("6.6.13"));
    }

    #[test]
    fn preserves_registry_port_and_digest_pin() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = OciReference::parse(&format!("localhost:5000/team/app:stable@{digest}"))
            .expect("parsed");
        assert_eq!(image.host(), "localhost:5000");
        assert_eq!(image.repository(), "team/app");
        assert_eq!(image.tag(), Some("stable"));
        assert_eq!(image.digest().unwrap(), digest);
        // The digest is preferred when both a tag and a digest exist.
        assert_eq!(image.selector(), digest);
        assert_eq!(
            image.manifest_url(),
            format!("https://localhost:5000/v2/team/app/manifests/{digest}")
        );
        assert_eq!(
            image.canonical(),
            format!("localhost:5000/team/app:stable@{digest}")
        );
    }

    #[test]
    fn preserves_bracketed_ipv6_hosts() {
        let image = OciReference::parse("[::1]:5000/team/app:latest").expect("parsed");
        assert_eq!(image.host(), "[::1]:5000");
        assert_eq!(
            image.manifest_url(),
            "https://[::1]:5000/v2/team/app/manifests/latest"
        );
    }

    #[test]
    fn normalizes_equivalent_spellings() {
        let bare = OciReference::parse("ubuntu").expect("parsed");
        let explicit = OciReference::parse("ubuntu:latest").expect("parsed");
        let full =
            OciReference::parse("registry-1.docker.io/library/ubuntu:latest").expect("parsed");
        assert_eq!(bare, explicit);
        assert_eq!(bare, full);
    }

    #[test]
    fn rejects_url_schemes() {
        assert_eq!(
            OciReference::parse("ftp://example.com/repo").expect_err("unsupported scheme"),
            OciReferenceError::HasUrlScheme
        );
        assert_eq!(
            OciReference::parse("http://").expect_err("nothing after scheme"),
            OciReferenceError::InvalidReference
        );
    }

    /// Plan variation (Jyth review remediation WP2): the Jyth toolchain
    /// registry is a plain-HTTP LAN registry, so an explicit `http://` scheme
    /// prefix is preserved for registry URL construction — mirroring
    /// `from_manifest_url` — while the canonical string stays scheme-less.
    #[test]
    fn preserves_an_explicit_http_scheme_prefix() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let reference = OciReference::parse(&format!(
            "http://ksmc-quartz.local:5000/jyth/kernel-toolchain@{digest}"
        ))
        .expect("http reference");
        assert_eq!(reference.scheme(), "http");
        assert_eq!(reference.host(), "ksmc-quartz.local:5000");
        assert_eq!(reference.repository(), "jyth/kernel-toolchain");
        assert_eq!(reference.digest().expect("digest"), digest);
        assert_eq!(
            reference.manifest_url(),
            format!("http://ksmc-quartz.local:5000/v2/jyth/kernel-toolchain/manifests/{digest}")
        );
        // The canonical reference string remains scheme-less.
        assert_eq!(
            reference.canonical(),
            format!("ksmc-quartz.local:5000/jyth/kernel-toolchain@{digest}")
        );
    }

    #[test]
    fn preserves_an_explicit_https_scheme_prefix() {
        let reference =
            OciReference::parse("https://registry.example.com/team/app:1.2.3").expect("https");
        assert_eq!(reference.scheme(), "https");
        assert_eq!(reference.host(), "registry.example.com");
        assert_eq!(
            reference.manifest_url(),
            "https://registry.example.com/v2/team/app/manifests/1.2.3"
        );
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(
            OciReference::parse("").expect_err("must fail"),
            OciReferenceError::Empty
        );
    }

    #[test]
    fn rejects_empty_repository_components() {
        for value in ["repo//component", "repo/", "/repo", "repo//"] {
            assert_eq!(
                OciReference::parse(value).expect_err("must fail"),
                OciReferenceError::EmptyRepositoryComponent,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_invalid_repository_characters() {
        for value in ["REPO/name", "repo/UPPER", "repo/na me", "repo/na+me"] {
            assert_eq!(
                OciReference::parse(value).expect_err("must fail"),
                OciReferenceError::InvalidRepositoryComponent,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_bad_tag_separators_and_length() {
        // `repo/:tag` leaves the repository as `repo/`, whose trailing empty
        // component is rejected before the tag is considered.
        assert_eq!(
            OciReference::parse("repo/:tag").expect_err("empty repo"),
            OciReferenceError::EmptyRepositoryComponent
        );
        assert_eq!(
            OciReference::parse("repo:tag!").expect_err("bad char"),
            OciReferenceError::InvalidTag
        );
        assert_eq!(
            OciReference::parse("repo:-starts-with-dash").expect_err("bad first char"),
            OciReferenceError::InvalidTag
        );
        let long_tag = format!("repo:{}", "t".repeat(129));
        assert_eq!(
            OciReference::parse(&long_tag).expect_err("too long"),
            OciReferenceError::InvalidTag
        );
    }

    #[test]
    fn rejects_wrong_digest_lengths() {
        let digests: Vec<String> = vec![
            "sha256:abcd".to_string(),
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "g".repeat(64)),
        ];
        for digest in digests {
            let value = format!("alpine@{digest}");
            assert_eq!(
                OciReference::parse(&value).expect_err("invalid digest"),
                OciReferenceError::InvalidDigestHex,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_digest_algorithms() {
        assert_eq!(
            OciReference::parse(&format!("alpine@md5:{}", "a".repeat(32))).expect_err("md5"),
            OciReferenceError::UnsupportedDigestAlgorithm
        );
    }

    #[test]
    fn from_manifest_url_preserves_http_scheme() {
        let reference = OciReference::from_manifest_url(
            "http://127.0.0.1:5000/v2/library/test/manifests/latest",
        )
        .expect("parsed");
        assert_eq!(reference.scheme(), "http");
        assert_eq!(reference.host(), "127.0.0.1:5000");
        assert_eq!(reference.repository(), "library/test");
        assert_eq!(reference.tag(), Some("latest"));
        assert_eq!(
            reference.blob_url("sha256:abcd"),
            "http://127.0.0.1:5000/v2/library/test/blobs/sha256:abcd"
        );
    }

    #[test]
    fn from_manifest_url_preserves_digest_selector() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let reference = OciReference::from_manifest_url(&format!(
            "https://example.com/v2/team/app/manifests/{digest}"
        ))
        .expect("parsed");
        assert_eq!(reference.tag(), None);
        assert_eq!(reference.digest().unwrap(), digest);
    }

    #[test]
    fn from_manifest_url_rejects_non_v2_paths() {
        for url in [
            "https://example.com/v2/x",
            "https://example.com/v2/x/manifests",
            "https://example.com/not-v2/x/manifests/latest",
            "ftp://example.com/v2/x/manifests/latest",
        ] {
            assert_eq!(
                OciReference::from_manifest_url(url).expect_err("must fail"),
                OciReferenceError::InvalidManifestUrl,
                "{url}"
            );
        }
    }

    #[test]
    fn round_trips_through_display_and_fromstr() {
        for value in [
            "ubuntu",
            "ubuntu:24.04",
            "acme/widget",
            "localhost:5000/team/app:stable",
            "registry-1.docker.io/linuxkit/kernel:6.6.13",
            &format!("alpine@sha256:{}", "a".repeat(64)),
        ] {
            let parsed = OciReference::parse(value).expect("valid");
            let reparsed = parsed
                .to_string()
                .parse::<OciReference>()
                .expect("round trip");
            assert_eq!(parsed, reparsed, "{value}");
        }
    }

    #[test]
    fn supports_bare_digest_pins() {
        let digest = format!("sha256:{}", "b".repeat(64));
        let image = OciReference::parse(&format!("ubuntu@{digest}")).expect("parsed");
        assert_eq!(image.tag(), None);
        assert_eq!(image.digest().unwrap(), digest);
        assert_eq!(
            image.canonical(),
            format!("registry-1.docker.io/library/ubuntu@{digest}")
        );
    }
}
