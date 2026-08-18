use uuid::Uuid;

use crate::{
    artifact::ArtifactId,
    digest::LinkDigest,
    storage::namespace::{Namespace, NamespacedLinkDigest},
};

//represents a link to an resource. not necesserly on storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRef {
    pub uuid: Uuid,
    pub namespace: Namespace,
    pub link_digest: LinkDigest,
}

impl From<&LinkRef> for ArtifactId {
    fn from(reference: &LinkRef) -> Self {
        Self::new(reference.namespace, reference.uuid)
    }
}

impl From<&LinkRef> for NamespacedLinkDigest {
    fn from(reference: &LinkRef) -> Self {
        Self {
            namespace: reference.namespace,
            link_digest: reference.link_digest,
        }
    }
}
