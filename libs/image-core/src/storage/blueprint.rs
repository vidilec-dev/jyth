use std::path::PathBuf;

use uuid::Uuid;

use crate::{
    artifact::{ArtifactId, link::ArtifactLink},
    digest::{ExpectedDigest, LinkDigest},
    storage::namespace::{Namespace, NamespacedLinkDigest},
};

// The needed resources to construct an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blueprint {
    pub target_entry_uuid: Uuid,
    pub target_entry_namespace: Namespace,

    pub layers: Vec<Layer>,
    pub extract: Option<PathBuf>,
}

impl From<&Blueprint> for ArtifactId {
    fn from(blueprint: &Blueprint) -> Self {
        Self::new(
            blueprint.target_entry_namespace,
            blueprint.target_entry_uuid,
        )
    }
}

/// A layer blueprint carries the source link, an authority for the bytes
/// that the link should deliver, and the link digest that locates the blob.
///
/// `link_digest` identifies where the blob lives and its known source size;
/// it never changes identity-speak. `expected_digest` is a digest declared
/// by an external source (such as an OCI manifest) used to verify the bytes
/// the link delivers; it preserves the declared algorithm and is never
/// converted into a local `FileDigest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub uuid: Uuid,
    pub link: ArtifactLink,
    pub expected_digest: ExpectedDigest,
    pub link_digest: LinkDigest,
}

impl From<&Layer> for ArtifactId {
    fn from(layer: &Layer) -> Self {
        Self::new(Namespace::Layers, layer.uuid)
    }
}

impl From<&Layer> for NamespacedLinkDigest {
    fn from(layer: &Layer) -> Self {
        Self {
            namespace: Namespace::Layers,
            link_digest: layer.link_digest,
        }
    }
}
