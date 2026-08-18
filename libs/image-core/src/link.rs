//! The public source-kind facade shared by every materialization entry
//! point.
//!
//! The materialization service maps a `Link` onto the resolver owning its
//! kind via [`ResolverSet::dispatch`](crate::resolver::ResolverSet::dispatch).

use std::path::PathBuf;

use bytes::Bytes;

/// A source from which an image component can be materialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// A local file path.
    Local(PathBuf),
    /// An OCI image reference in the form
    /// `[registry-host[:port]/]repository[/repository...][:tag][@digest]`.
    Image(String),
    /// Bytes already held by the caller.
    Bytes(Bytes),
    /// An HTTP or HTTPS URL.
    Http(String),
}

impl Link {
    /// Creates an in-memory byte source.
    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        Self::Bytes(bytes.into())
    }

    /// Creates a local-path source.
    pub fn local(path: impl Into<PathBuf>) -> Self {
        Self::Local(path.into())
    }

    /// Creates an OCI image-reference source.
    pub fn image(image: impl Into<String>) -> Self {
        Self::Image(image.into())
    }

    /// Creates an HTTP source.
    pub fn http(url: impl Into<String>) -> Self {
        Self::Http(url.into())
    }
}
