use uuid::Uuid;

use crate::storage::namespace::Namespace;

pub mod compression;
pub mod link;
pub mod ty;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactId {
    pub namespace: Namespace,
    pub uuid: Uuid,
}
