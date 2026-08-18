//! Shared HTTP registry client used by [`crate::ops::blueprint`] and the OCI
//! source resolver.
//!
//! The client centralizes the OCI/Docker manifest and blob requests so all
//! call sites share the same reference normalization, redirect policy and
//! Bearer-token handling. It never treats a `401` carrying a Bearer
//! `WWW-Authenticate` challenge as an unreachable reference: the challenge is
//! parsed, a token is fetched from the realm and the original request is
//! retried with the token attached — and the token is only forwarded to the
//! host that issued it.
//!
//! Reference parsing and canonicalization live in
//! [`crate::oci_reference::OciReference`]; this module consumes validated
//! references and never reparses raw strings.
//!
//! See `docs/implementation-plan/ops/07-blueprint-and-integration.md` for the
//! full contract.

use std::time::Duration;

use error_stack::Report;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use sha2::{Digest as _, Sha256, Sha512};

use crate::ops::error::OperationError;

/// The `Docker-Content-Digest` response header carried by registry manifest
/// responses. When present it is captured, validated, and verified against
/// the fetched bytes.
const DOCKER_CONTENT_DIGEST: &str = "docker-content-digest";

/// Media types accepted by the client when requesting manifests. Listed in
/// priority order; the registry is free to return any of them.
pub const MANIFEST_ACCEPT: &[&str] = &[
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Maximum number of HTTP redirects followed by the registry client. Matches
/// the cap used by `load` for blob downloads.
const HTTP_MAX_REDIRECTS: usize = 10;

/// A single shared async client. A fresh [`reqwest::Client`] carries a
/// connection pool and a redirect policy; building one per request would
/// forfeit keep-alive and risk divergent behavior between call sites.
fn shared_client() -> Result<&'static reqwest::Client, Report<OperationError>> {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
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
    });
    let client = reqwest::Client::builder()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let _ = CLIENT.set(client);
    Ok(CLIENT.get().expect("client was just set"))
}

/// A challenge parsed out of a `WWW-Authenticate: Bearer ...` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: String,
    pub scope: String,
}

impl BearerChallenge {
    /// Parse a `WWW-Authenticate` header value beginning with `Bearer`.
    pub fn parse(header: &str) -> Option<Self> {
        let trimmed = header.trim();
        let rest = trimmed.strip_prefix("Bearer")?.trim();
        let mut realm = None;
        let mut service = None;
        let mut scope = None;
        for part in rest.split(',') {
            let part = part.trim();
            let (key, value) = part.split_once('=')?;
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "realm" => realm = Some(value.to_string()),
                "service" => service = Some(value.to_string()),
                "scope" => scope = Some(value.to_string()),
                _ => {}
            }
        }
        let realm = realm?;
        let service = service?;
        let scope = scope?;
        Some(Self {
            realm,
            service,
            scope,
        })
    }

    pub fn token_url(&self) -> String {
        let mut params = Vec::new();
        params.push(format!("service={}", percent_encode(&self.service)));
        params.push(format!("scope={}", percent_encode(&self.scope)));
        let separator = if self.realm.contains('?') { '&' } else { '?' };
        format!("{}{separator}{}", self.realm, params.join("&"))
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// Fetch a Bearer token from `challenge` end-point. Anonymous tokens are
/// supported by omitting any `Authorization` header on the token request.
async fn fetch_bearer_token(
    client: &reqwest::Client,
    challenge: &BearerChallenge,
) -> Result<String, Report<OperationError>> {
    let token_url = challenge.token_url();
    let response = client
        .get(&token_url)
        .send()
        .await
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let status = response.status();
    if !status.is_success() {
        return Err(OperationError::HttpStatus
            .report()
            .attach(token_url)
            .attach(status.as_u16()));
    }
    let body: TokenResponse = response
        .json()
        .await
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    body.token.or(body.access_token).ok_or_else(|| {
        OperationError::InvalidManifest
            .report()
            .attach("token end-point returned neither `token` nor `access_token`")
    })
}

/// Perform a blocking GET with the same one-challenge Bearer flow used by the
/// async manifest client. This is used by `ops::load` because blob bodies are
/// intentionally streamed from a blocking response into the staging writer.
pub fn blocking_get_with_challenge(
    client: &reqwest::blocking::Client,
    url: &str,
    base_headers: &HeaderMap,
) -> Result<reqwest::blocking::Response, Report<OperationError>> {
    let response = client
        .get(url)
        .headers(base_headers.clone())
        .send()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .and_then(BearerChallenge::parse)
        .ok_or_else(|| {
            OperationError::HttpStatus
                .report()
                .attach(url.to_string())
                .attach(response.status().as_u16())
        })?;
    let token = fetch_bearer_token_blocking(client, &challenge)?;
    // `bearer_auth` marks Authorization as sensitive. Reqwest then removes it
    // automatically if a redirect changes host, port or scheme, so a token
    // obtained for this registry cannot leak to a redirect target.
    let request = client
        .get(url)
        .headers(base_headers.clone())
        .bearer_auth(token);
    request
        .send()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))
}

fn fetch_bearer_token_blocking(
    client: &reqwest::blocking::Client,
    challenge: &BearerChallenge,
) -> Result<String, Report<OperationError>> {
    let token_url = challenge.token_url();
    let response = client
        .get(&token_url)
        .send()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let status = response.status();
    if !status.is_success() {
        return Err(OperationError::HttpStatus
            .report()
            .attach(token_url)
            .attach(status.as_u16()));
    }
    let body: TokenResponse = response
        .json()
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    body.token.or(body.access_token).ok_or_else(|| {
        OperationError::InvalidManifest
            .report()
            .attach("token end-point returned neither `token` nor `access_token`")
    })
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

/// Result of a manifest fetch.
pub struct ManifestResponse {
    /// The raw bytes of the manifest body. The caller is responsible for
    /// parsing them per the discovered media type.
    pub bytes: Vec<u8>,
    /// The media type negotiated from the response `Content-Type`. Used to
    /// select the deserialization strategy.
    pub media_type: String,
    /// The content digest verified against the body: the digest requested in
    /// the manifest URL selector when one is present, otherwise the registry's
    /// `Docker-Content-Digest` when supplied. `None` when neither is known.
    pub content_digest: Option<String>,
}

/// Fetch a manifest at `url` honoring the Bearer challenge flow.
///
/// The client sends `Accept` headers for the OCI and Docker manifest media
/// types. A `401` with a `WWW-Authenticate: Bearer` challenge is resolved by
/// fetching a token from the challenge's realm and replaying the request with
/// the token attached. The token is never forwarded to a different host.
///
/// The returned bytes are hashed and verified against the digest requested in
/// the URL selector (a digest-pinned manifest URL) or the registry's
/// `Docker-Content-Digest` header when supplied; a mismatch is an error
/// before the caller parses the manifest.
pub async fn fetch_manifest(url: &str) -> Result<ManifestResponse, Report<OperationError>> {
    let client = shared_client()?;
    let accept = MANIFEST_ACCEPT.join(", ");
    let accept_value = HeaderValue::from_str(&accept)
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, accept_value);
    fetch_with_challenge(client, url, &headers, &Default::default(), 0, 0).await
}

/// Result of a manifest HEAD probe: the advertised content-length, the
/// negotiated media type, and the `Docker-Content-Digest` when the registry
/// supplies one. Used by the OCI source resolver to discover the canonical
/// link size and the immutable manifest identity without consuming a body.
pub struct ManifestProbe {
    pub content_length: u128,
    /// The validated `Docker-Content-Digest` header when the registry
    /// supplied it, so a digest-pinned request can fail fast on a stale tag
    /// or moved manifest.
    pub content_digest: Option<String>,
}

/// HEAD the manifest at `url` honoring the Bearer challenge flow. Used by
/// the OCI source resolver so the link inherits the same authorization and
/// redirect behavior as `blueprint`'s full GET.
pub async fn head_manifest(url: &str) -> Result<ManifestProbe, Report<OperationError>> {
    let client = shared_client()?;
    let accept = MANIFEST_ACCEPT.join(", ");
    let accept_value = HeaderValue::from_str(&accept)
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, accept_value);
    head_with_challenge(client, url, &headers, &Default::default(), 0).await
}

async fn head_with_challenge(
    client: &reqwest::Client,
    url: &str,
    base_headers: &HeaderMap,
    tokens: &TokenState,
    auth_attempt: u8,
) -> Result<ManifestProbe, Report<OperationError>> {
    let mut request = client.head(url).headers(base_headers.clone());
    if let (Some(token), Some(host)) = (&tokens.token, &tokens.host)
        && let Ok(parsed) = reqwest::Url::parse(url)
        && parsed.host_str() == Some(host.as_str())
    {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED
        && let Some(challenge_header) = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
        && let Some(challenge) = BearerChallenge::parse(challenge_header)
    {
        if auth_attempt >= 1 {
            return Err(OperationError::HttpStatus
                .report()
                .attach(url.to_string())
                .attach(status.as_u16())
                .attach("Bearer authentication retry limit exceeded"));
        }
        let token = fetch_bearer_token(client, &challenge).await?;
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()));
        let new_tokens = TokenState {
            token: Some(token),
            host,
        };
        return Box::pin(head_with_challenge(
            client,
            url,
            base_headers,
            &new_tokens,
            auth_attempt + 1,
        ))
        .await;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || !status.is_success() {
        return Err(OperationError::HttpStatus
            .report()
            .attach(url.to_string())
            .attach(status.as_u16()));
    }

    let content_length = response.content_length().unwrap_or(0) as u128;
    let content_digest = validate_content_digest_header(&response)?;
    Ok(ManifestProbe {
        content_length,
        content_digest,
    })
}

/// Capture and validate the `Docker-Content-Digest` header of a successful
/// manifest response. `None` when the registry omitted the header; a typed
/// error when the registry supplied a malformed digest.
fn validate_content_digest_header(
    response: &reqwest::Response,
) -> Result<Option<String>, Report<OperationError>> {
    let Some(value) = response
        .headers()
        .get(DOCKER_CONTENT_DIGEST)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    let parsed = crate::digest::ExpectedDigest::parse(value).map_err(|err| {
        OperationError::InvalidManifest
            .report()
            .attach("registry supplied an invalid Docker-Content-Digest header")
            .attach(err)
    })?;
    // Only sha256/sha512 digests can be verified against fetched bytes.
    match parsed {
        crate::digest::ExpectedDigest::Sha256(_) | crate::digest::ExpectedDigest::Sha512(_) => {
            Ok(Some(value.to_string()))
        }
        crate::digest::ExpectedDigest::Blake3(_) => Err(OperationError::InvalidManifest
            .report()
            .attach("registry supplied an unsupported Docker-Content-Digest algorithm")),
    }
}

/// Compute the `<algorithm>:<hex>` digest of `bytes` for a digest whose
/// algorithm is one of the supported OCI algorithms. Returns `None` for an
/// unsupported algorithm.
fn compute_digest(algorithm: &str, bytes: &[u8]) -> Option<String> {
    match algorithm {
        "sha256" => Some(format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))),
        "sha512" => Some(format!("sha512:{}", hex_lower(&Sha512::digest(bytes)))),
        _ => None,
    }
}

/// The canonical SHA-256 digest of a manifest body, used when a successful
/// response omits `Docker-Content-Digest` so the resolver can still derive
/// the immutable manifest identity.
pub fn manifest_body_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The digest requested by a manifest URL selector
/// (`.../manifests/sha256:...`), when the selector is itself a digest.
fn requested_digest_from_url(url: &str) -> Option<String> {
    let selector = url.rsplit('/').next()?;
    if selector.starts_with("sha256:") || selector.starts_with("sha512:") {
        Some(selector.to_string())
    } else {
        None
    }
}

/// Replay-aware fetch state. Tracks the host that issued any token so the
/// token is only reused on retries to that same host.
#[derive(Default)]
struct TokenState {
    token: Option<String>,
    host: Option<String>,
}

async fn fetch_with_challenge(
    client: &reqwest::Client,
    url: &str,
    base_headers: &HeaderMap,
    tokens: &TokenState,
    redirect_depth: u32,
    auth_attempt: u8,
) -> Result<ManifestResponse, Report<OperationError>> {
    if redirect_depth > HTTP_MAX_REDIRECTS as u32 {
        return Err(OperationError::HttpRequest
            .report()
            .attach("too many redirects"));
    }

    let mut request = client.get(url).headers(base_headers.clone());
    if let (Some(token), Some(host)) = (&tokens.token, &tokens.host)
        && let Ok(parsed) = reqwest::Url::parse(url)
        && parsed.host_str() == Some(host.as_str())
    {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?;
    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED
        && let Some(challenge_header) = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
        && let Some(challenge) = BearerChallenge::parse(challenge_header)
    {
        if auth_attempt >= 1 {
            return Err(OperationError::HttpStatus
                .report()
                .attach(url.to_string())
                .attach(status.as_u16())
                .attach("Bearer authentication retry limit exceeded"));
        }
        let token = fetch_bearer_token(client, &challenge).await?;
        let host = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()));
        let new_tokens = TokenState {
            token: Some(token),
            host,
        };
        return Box::pin(fetch_with_challenge(
            client,
            url,
            base_headers,
            &new_tokens,
            redirect_depth,
            auth_attempt + 1,
        ))
        .await;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || !status.is_success() {
        return Err(OperationError::HttpStatus
            .report()
            .attach(url.to_string())
            .attach(status.as_u16()));
    }

    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let content_digest = validate_content_digest_header(&response)?;

    let bytes = response
        .bytes()
        .await
        .map_err(|err| OperationError::HttpRequest.report().attach(err))?
        .to_vec();

    // A digest-pinned manifest URL must fail when the registry returns bytes
    // that do not match the requested digest. Otherwise, when the registry
    // supplies Docker-Content-Digest, the fetched bytes must match it. A
    // success response with neither selector digest nor header leaves the
    // digest to the caller.
    let expected = requested_digest_from_url(url).or(content_digest.clone());
    if let Some(expected) = expected {
        let (algorithm, _) = expected
            .split_once(':')
            .expect("digest form validated by construction");
        let computed = compute_digest(algorithm, &bytes).ok_or_else(|| {
            OperationError::InvalidManifest
                .report()
                .attach(format!("unsupported digest algorithm: {algorithm}"))
        })?;
        if computed != expected {
            return Err(OperationError::DigestMismatch
                .report()
                .attach(format!("expected {expected}, computed {computed}"))
                .attach(url.to_string()));
        }
    }

    Ok(ManifestResponse {
        bytes,
        media_type,
        content_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_challenge_fields() {
        let header = "Bearer realm=\"https://auth.example.com/token\",service=\"registry.example.com\",scope=\"repository:foo/bar:pull\"";
        let ch = BearerChallenge::parse(header).expect("parsed");
        assert_eq!(ch.realm, "https://auth.example.com/token");
        assert_eq!(ch.service, "registry.example.com");
        assert_eq!(ch.scope, "repository:foo/bar:pull");
    }

    #[test]
    fn rejects_non_bearer_scheme() {
        assert!(BearerChallenge::parse("Basic abc").is_none());
    }

    #[test]
    fn rejects_missing_fields() {
        assert!(BearerChallenge::parse("Bearer realm=\"x\"").is_none());
        assert!(BearerChallenge::parse("Bearer service=\"x\"").is_none());
        assert!(BearerChallenge::parse("Bearer scope=\"x\"").is_none());
    }

    #[test]
    fn token_url_quotes_parameters() {
        let ch = BearerChallenge {
            realm: "https://auth.example.com/token".to_string(),
            service: "reg example".to_string(),
            scope: "repository:foo bar:pull".to_string(),
        };
        let url = ch.token_url();
        assert!(url.contains("service=reg%20example"), "{url}");
        assert!(url.contains("scope=repository%3Afoo%20bar%3Apull"), "{url}");
    }

    #[test]
    fn percent_encode_passes_unreserved_unchanged() {
        assert_eq!(percent_encode("AZaz09-_."), "AZaz09-_.");
        assert_eq!(percent_encode("AB CD"), "AB%20CD");
        assert_eq!(percent_encode(":foo"), "%3Afoo");
    }

    #[test]
    fn requested_digest_from_url_recognizes_digest_selectors() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            requested_digest_from_url(&format!("https://example.com/v2/repo/manifests/{digest}")),
            Some(digest.clone())
        );
        assert_eq!(
            requested_digest_from_url("https://example.com/v2/repo/manifests/latest"),
            None
        );
        assert_eq!(
            requested_digest_from_url("https://example.com/not-a-manifest"),
            None
        );
    }

    #[test]
    fn compute_digest_matches_sha256_and_sha512() {
        let sha = compute_digest("sha256", b"hello").expect("sha256");
        assert!(sha.starts_with("sha256:"));
        assert_eq!(sha.len(), "sha256:".len() + 64);
        let sha512 = compute_digest("sha512", b"hello").expect("sha512");
        assert!(sha512.starts_with("sha512:"));
        assert_eq!(sha512.len(), "sha512:".len() + 128);
        assert!(compute_digest("md5", b"hello").is_none());
    }
}
