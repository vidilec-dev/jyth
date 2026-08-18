//! Reference lookup and creation.
//!
//! The reference table maps a [`ReferenceKey`] (source-link identity plus
//! namespace) to its matched canonical [`EntryIdentity`]. The reverse
//! mapping [`ENTRY_REFERENCES`][crate::storage::index::store::ENTRY_REFERENCES]
//! records the same relationship in the opposite direction so reference
//! rebinding can be performed atomically in both directions.
//!
//! Before materialization, the identity assigned by [`get_or_create`] is
//! provisional: entry canonicalization may replace that identity with an
//! existing entry identity later, but only within the same namespace.
//!
//! `ReferenceKey` is derived from a [`Reference`]; the index APIs accept and
//! return `Reference` directly. There is no longer a redundant paired
//! `ReferenceHandle` that could carry an inconsistent key/reference pair.

use error_stack::Report;
use redb::ReadableTable;
use uuid::Uuid;

use crate::artifact::ArtifactId;
use crate::storage::error::IndexError;
use crate::storage::index::store::{IndexStore, LINK_DIGESTS, LINK_REFS};
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::NamespacedLinkDigest;

/// Get an existing LinkRef or create one.
pub fn get_or_create(
    store: &IndexStore,
    link_digest: NamespacedLinkDigest,
) -> Result<LinkRef, Report<IndexError>> {
    let tx = store.begin_write()?;

    let mut link_digests = tx
        .open_table(LINK_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut link_refs = tx
        .open_table(LINK_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    let resolved_artifact = {
        let guard = link_digests
            .get(&link_digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    let artifact_id = match resolved_artifact {
        Some(artifact_id) => artifact_id,
        None => {
            let artifact_id = ArtifactId::new(link_digest.namespace, Uuid::now_v7());
            link_digests
                .insert(&link_digest, &artifact_id)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
            artifact_id
        }
    };

    let resolved_link_ref = {
        let guard = link_refs
            .get(&artifact_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    let link_ref = match resolved_link_ref {
        Some(link_ref) => link_ref,
        None => {
            let link_ref = LinkRef {
                uuid: artifact_id.uuid,
                namespace: link_digest.namespace,
                link_digest: link_digest.link_digest,
            };
            link_refs
                .insert(&artifact_id, &link_ref)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
            link_ref
        }
    };

    drop(link_digests);
    drop(link_refs);
    tx.commit()
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    Ok(link_ref)
}
