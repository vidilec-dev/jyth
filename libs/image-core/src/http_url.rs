//! A validated, canonical HTTP(S) source URL.
//!
//! `HttpUrl` is the validated form of every remote non-OCI source: local and
//! byte sources are content-addressed, but HTTP sources are fetched from the
//! exact URL the caller supplied, so the value must be syntactically valid
//! before it can enter any asynchronous materialization path.
//!
//! Validation happens at construction time and never performs network or
//! filesystem I/O:
//!
//! - only `http` and `https` schemes are accepted;
//! - a host is required;
//! - fragments are rejected;
//! - embedded `user:password` credentials are rejected;
//! - path and query components are preserved;
//! - the canonical serialization returned by `url::Url` is stored.
//!
//! `Debug` and every validation message redact the query component and
//! credentials, so a signed URL never leaks through diagnostics.

use std::fmt;
use std::str::FromStr;

use url::Url;

/// Validation failure for [`HttpUrl`].
///
/// Every variant names a stable reason category; none of the variants carry
/// the rejected input, so credentials or query values never leak through
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum HttpUrlError {
    /// The URL uses a scheme other than `http` or `https`.
    #[error("URL scheme must be http or https")]
    UnsupportedScheme,
    /// The URL has no host.
    #[error("URL must include a host")]
    MissingHost,
    /// The URL carries a fragment.
    #[error("URL must not include a fragment")]
    HasFragment,
    /// The URL embeds `user:password` credentials.
    #[error("URL must not embed username or password credentials")]
    HasCredentials,
    /// The value is not a syntactically valid absolute URL.
    #[error("URL is not a valid absolute URL")]
    InvalidSyntax,
}

/// A validated HTTP(S) source URL.
///
/// The value stores the canonical serialization produced by `url::Url`, so
/// equivalent spellings of one URL compare and hash equally.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl {
    url: Url,
}

impl HttpUrl {
    /// Parse and validate `value`.
    pub fn parse(value: &str) -> Result<Self, HttpUrlError> {
        let url = Url::parse(value).map_err(|_| HttpUrlError::InvalidSyntax)?;
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(HttpUrlError::UnsupportedScheme),
        }
        if url.host_str().is_none() {
            return Err(HttpUrlError::MissingHost);
        }
        if url.fragment().is_some() {
            return Err(HttpUrlError::HasFragment);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpUrlError::HasCredentials);
        }
        Ok(Self { url })
    }

    /// The canonical serialization of the URL.
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The URL scheme (`http` or `https`).
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// The URL host without any port.
    pub fn host(&self) -> &str {
        self.url.host_str().expect("host required by validation")
    }
}

impl FromStr for HttpUrl {
    type Err = HttpUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for HttpUrl {
    type Error = HttpUrlError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl AsRef<str> for HttpUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `Debug` redacts the query component so a signed URL never appears in
/// diagnostics.
impl fmt::Debug for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = &self.url;
        // `Url` exposes the query as opaque text; rebuilding it without the
        // query would require re-encoding every component. The redacted form
        // keeps scheme, host and path, and replaces the query with a marker.
        let scheme = url.scheme().to_string();
        let host = url
            .host_str()
            .map(str::to_string)
            .unwrap_or_else(|| "<no host>".to_string());
        let port = url
            .port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        let path = url.path().to_string();
        let redacted = if url.query().is_some() {
            format!("{scheme}://{host}{port}{path}?<redacted>")
        } else {
            format!("{scheme}://{host}{port}{path}")
        };
        f.debug_tuple("HttpUrl").field(&redacted).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_http_and_https_with_paths_and_queries() {
        let url = HttpUrl::parse("https://example.com/vmlinuz?token=1").expect("valid");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host(), "example.com");
        assert_eq!(url.as_str(), "https://example.com/vmlinuz?token=1");

        let url = HttpUrl::parse("http://127.0.0.1:8080/kernel").expect("valid");
        assert_eq!(url.as_str(), "http://127.0.0.1:8080/kernel");
    }

    #[test]
    fn canonicalizes_equivalent_spellings() {
        let upper = HttpUrl::parse("HTTPS://EXAMPLE.com/vmlinuz").expect("valid");
        let lower = HttpUrl::parse("https://example.com/vmlinuz").expect("valid");
        assert_eq!(upper, lower);
        assert_eq!(upper.as_str(), "https://example.com/vmlinuz");
    }

    #[test]
    fn rejects_non_http_schemes() {
        for value in ["ftp://example.com/x", "file:///etc/passwd", "docker://x/y"] {
            assert_eq!(
                HttpUrl::parse(value).expect_err("must fail"),
                HttpUrlError::UnsupportedScheme,
                "{value}"
            );
        }
    }

    #[test]
    fn rejects_urls_without_a_host() {
        // `url::Url` rejects an empty host at parse time; the defensive
        // `MissingHost` check catches any URL shape that parses without one.
        for value in ["https://", "https://?query", "http://#frag"] {
            let err = HttpUrl::parse(value).expect_err("must fail");
            assert!(
                matches!(err, HttpUrlError::InvalidSyntax | HttpUrlError::MissingHost),
                "{value}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_fragments() {
        assert_eq!(
            HttpUrl::parse("https://example.com/vmlinuz#section").expect_err("must fail"),
            HttpUrlError::HasFragment
        );
    }

    #[test]
    fn rejects_embedded_credentials() {
        assert_eq!(
            HttpUrl::parse("https://user:pass@example.com/vmlinuz").expect_err("must fail"),
            HttpUrlError::HasCredentials
        );
        assert_eq!(
            HttpUrl::parse("https://user@example.com/vmlinuz").expect_err("must fail"),
            HttpUrlError::HasCredentials
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(
            HttpUrl::parse("not a url").expect_err("must fail"),
            HttpUrlError::InvalidSyntax
        );
    }

    #[test]
    fn debug_redacts_query_but_keeps_host_and_path() {
        let url = HttpUrl::parse("https://example.com/vmlinuz?sig=secret").expect("valid");
        let debug = format!("{url:?}");
        assert!(debug.contains("example.com/vmlinuz"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn round_trips_through_display_and_fromstr() {
        let url = HttpUrl::parse("https://example.com/a/b?x=1&y=2").expect("valid");
        let reparsed = url.to_string().parse::<HttpUrl>().expect("round trip");
        assert_eq!(url, reparsed);
    }
}
