use std::path::PathBuf;

use uuid::Uuid;

use crate::{
    artifact::{ArtifactId, compression::ArtifactCompression, ty::ArtifactType},
    digest::FileDigest,
    storage::namespace::{Namespace, NamespacedFileDigest},
};

//represents an on storage entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    pub uuid: Uuid,
    pub namespace: Namespace,

    pub file_digest: FileDigest,

    pub artifact_type: ArtifactType,
    pub artifact_compression: ArtifactCompression,
}

impl FileRef {
    pub fn path(&self) -> PathBuf {
        self.namespace.join(self.uuid.to_string())
    }
}

impl From<&FileRef> for ArtifactId {
    /// Centralizes the identity invariant: an FileRef's `ArtifactId` is
    /// exactly its own UUID and namespace.
    fn from(entry: &FileRef) -> Self {
        Self::new(entry.namespace, entry.uuid)
    }
}

impl From<&FileRef> for NamespacedFileDigest {
    /// Derive the namespace-scoped digest key from an [`FileRef`]. The
    /// namespace always matches the entry's stored namespace per the
    /// digest-table invariant.
    fn from(entry: &FileRef) -> Self {
        Self {
            namespace: entry.namespace,
            file_digest: entry.file_digest,
        }
    }
}
