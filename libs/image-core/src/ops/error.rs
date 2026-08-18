//! Taxonomy of errors raised by the image materialization operations.
//!
//! Each public operation in [`crate::ops`] returns a [`Report<OperationError>`].
//! The taxonomy distinguishes the categories listed below so callers can
//! inspect the failure location without inspecting the attached third-party
//! error. External errors are attached to the [`Report`] via
//! [`error_stack::Report::attach`].

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    #[error("failed to read the source")]
    ReadSource,
    #[error("failed to write to the destination")]
    WriteDestination,
    #[error("HTTP transport failure")]
    HttpRequest,
    #[error("HTTP response was not successful")]
    HttpStatus,
    #[error("the materialized size did not match the expected size")]
    SizeMismatch,
    #[error("the materialized digest did not match the expected digest")]
    DigestMismatch,
    #[error("unsupported compression format")]
    UnsupportedCompression,
    #[error("unsupported artifact format")]
    UnsupportedArtifact,
    #[error("invalid tar archive")]
    InvalidTar,
    #[error("invalid cpio `newc` archive")]
    InvalidCpio,
    #[error("unsafe path: absolute, empty or contains `..` components")]
    UnsafePath,
    #[error("kernel entry not found inside the artifact")]
    KernelNotFound,
    #[error("extracted bytes do not satisfy the bzImage contract")]
    InvalidKernel,
    #[error("invalid OCI or Docker manifest")]
    InvalidManifest,
    #[error("no image found for the local platform")]
    PlatformNotFound,
    #[error("operation cancelled")]
    Cancelled,
}

impl OperationError {
    pub fn report(self) -> error_stack::Report<Self> {
        error_stack::Report::new(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TempFileError {
    #[error("failed to create temporary file at {0:?}")]
    Create(PathBuf, #[source] std::io::Error),
    #[error("failed to open {0:?}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to write at {0:?}")]
    Write(PathBuf, #[source] std::io::Error),
    #[error("failed to flush at {0:?}")]
    Flush(PathBuf, #[source] std::io::Error),
    #[error("failed to read at {0:?}")]
    Read(PathBuf, #[source] std::io::Error),
    #[error("failed to publish {0:?}")]
    Publish(PathBuf, #[source] std::io::Error),
}

impl TempFileError {
    pub fn report(self) -> error_stack::Report<Self> {
        error_stack::Report::new(self)
    }
}
