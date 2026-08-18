use std::path::PathBuf;

use error_stack::Report;
use uuid::Uuid;

/// Index-layer error taxonomy.
///
/// Errors are split into distinguishable variants so that a missing key
/// (`Ok(None)` on lookups) is never confused with a storage, codec, or
/// corruption failure. The original third-party error is attached to a
/// [`Report`] rather than embedded in the enum, so callers always know which
/// category they are handling.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("failed to open the cache index")]
    Open,
    #[error("cache index schema is incompatible with this image implementation")]
    SchemaMismatch,
    #[error("index transaction failed")]
    Transaction,
    #[error("index key and record identity do not match")]
    IdentityMismatch,
    #[error("namespace boundary violation: key and identity namespaces differ")]
    NamespaceMismatch,
    #[error("entry {uuid} does not exist")]
    EntryNotFound { uuid: Uuid },
    #[error("entry artifact is missing at {path:?}")]
    ArtifactMissing { path: PathBuf },
    #[error("blueprint target does not match the current reference")]
    BlueprintTargetMismatch,
    #[error("blueprint conflict for reference key")]
    BlueprintConflict,
    #[error("no prior file ref exists for the supplied identity")]
    MissingPrevious,
    #[error("file ref identity (uuid or namespace) does not match the existing record")]
    FileRefIdentityConflict,
}

impl IndexError {
    pub fn report(self) -> Report<IndexError> {
        Report::new(self)
    }
}
