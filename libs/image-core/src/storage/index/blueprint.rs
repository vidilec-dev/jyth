//! Blueprint persistence.
//!
//! A blueprint is keyed by its [`ReferenceKey`][crate::storage::index::key::ReferenceKey],
//! not by provisional UUID, so it stays addressable while entry
//! canonicalization replaces the provisional identity. The blueprint's
//! target identity must equal the current `REFERENCES` value for the same
//! key when it is inserted, ensuring the blueprint target matches the
//! reference mapping used to materialize it.

use error_stack::Report;

use crate::artifact::ArtifactId;
use crate::storage::blueprint::Blueprint;
use crate::storage::error::IndexError;
use crate::storage::index::store::BLUEPRINTS;
use crate::storage::index::store::IndexStore;
use crate::storage::index::store::LINK_DIGESTS;
use crate::storage::namespace::NamespacedLinkDigest;

/// Read the blueprint for the given reference, if any.
pub fn get_by_link_digest(
    store: &IndexStore,
    link_digest: NamespacedLinkDigest,
) -> Result<Option<Blueprint>, Report<IndexError>> {
    let tx = store.begin_read()?;
    let link_digests = tx
        .open_table(LINK_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let blueprints = tx
        .open_table(BLUEPRINTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    let Some(artifact_id) = ({
        let guard = link_digests
            .get(&link_digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    }) else {
        // The link digest does not exist in the index, so there is no blueprint for it.
        drop(blueprints);
        drop(link_digests);
        drop(tx);
        return Ok(None);
    };

    let blueprint = {
        let guard = blueprints
            .get(artifact_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    drop(blueprints);
    drop(link_digests);
    drop(tx);
    Ok(blueprint)
}

/// Insert or replace a blueprint keyed by the reference's key.
pub fn upsert(store: &IndexStore, blueprint: Blueprint) -> Result<Blueprint, Report<IndexError>> {
    let tx = store.begin_write()?;
    let mut blueprints = tx
        .open_table(BLUEPRINTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    blueprints
        .insert(ArtifactId::from(&blueprint), blueprint.clone())
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    drop(blueprints);
    tx.commit()
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    Ok(blueprint)
}
