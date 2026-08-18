use std::io::Read;
use std::path::PathBuf;

use bytes::Bytes;
use error_stack::Report;

use crate::digest::LinkDigest;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactLinkError {
    #[error("Failed to get file metadata for {0:?}: {1}")]
    FileMetadata(PathBuf, std::io::Error),
    #[error("Failed to read {0:?}: {1}")]
    FileRead(PathBuf, std::io::Error),
    #[error("Failed to get file metadata for {0:?}")]
    UnreachableLink(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactLink {
    Local(PathBuf, u128),
    Bytes(Bytes, u128),
    Http(String, u128),
}

impl ArtifactLink {
    pub fn local(path: impl Into<PathBuf>) -> Result<Self, Report<ArtifactLinkError>> {
        let path = path.into();
        let size = std::fs::metadata(&path)
            .map(|metadata| metadata.len() as u128)
            .map_err(|error| Report::new(ArtifactLinkError::FileMetadata(path.clone(), error)))?;
        Ok(Self::Local(path, size))
    }

    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        let size = bytes.len() as u128;
        Self::Bytes(bytes, size)
    }

    pub async fn http(url: impl Into<String>) -> Result<Self, Report<ArtifactLinkError>> {
        let url = url.into();
        let response = reqwest::Client::new()
            .head(&url)
            .send()
            .await
            .map_err(|e| Report::new(ArtifactLinkError::UnreachableLink(url.clone())).attach(e))?;
        if response.status().is_success() {
            let size = response.content_length().unwrap_or(0) as u128;
            return Ok(Self::Http(url, size));
        }
        Err(Report::new(ArtifactLinkError::UnreachableLink(url)))
    }

    /// Returns a stable identifier for the source bytes and their known size.
    ///
    /// Local links are content-addressed so changing a file in place—even if
    /// its byte length stays the same—cannot reuse a stale materialization.
    /// The file is streamed through BLAKE3 in bounded chunks; a read failure
    /// is an error, never a fallback, so a link identity never flips between
    /// two keys depending on transient readability.
    pub fn digest(&self) -> Result<LinkDigest, Report<ArtifactLinkError>> {
        match self {
            Self::Local(path, size) => {
                let mut file = std::fs::File::open(path).map_err(|error| {
                    Report::new(ArtifactLinkError::FileRead(path.clone(), error))
                })?;
                let mut hasher = blake3::Hasher::new();
                let mut buffer = vec![0u8; 1024 * 1024];
                loop {
                    let read = file.read(&mut buffer).map_err(|error| {
                        Report::new(ArtifactLinkError::FileRead(path.clone(), error))
                    })?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                Ok(LinkDigest {
                    link_hash: hasher.finalize(),
                    file_size: *size,
                })
            }
            Self::Bytes(bytes, size) => Ok(LinkDigest {
                link_hash: blake3::hash(bytes),
                file_size: *size,
            }),
            Self::Http(url, size) => Ok(LinkDigest {
                link_hash: blake3::hash(url.as_bytes()),
                file_size: *size,
            }),
        }
    }
}
