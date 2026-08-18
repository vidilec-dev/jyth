use error_stack::Report;
use redb::ReadableTable;

use crate::artifact::ArtifactId;
use crate::storage::error::IndexError;
use crate::storage::file_ref::FileRef;
use crate::storage::index::store::{FILE_DIGESTS, IndexStore};
use crate::storage::index::store::{FILE_REFS, LINK_DIGESTS, LINK_REFS};
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::{NamespacedFileDigest, NamespacedLinkDigest};

/// Read an entry by reference.
pub fn get_by_link_ref(
    store: &IndexStore,
    link_ref: &LinkRef,
) -> Result<Option<FileRef>, Report<IndexError>> {
    let artifact_id = ArtifactId::from(link_ref);

    let tx = store.begin_read()?;
    let table = tx
        .open_table(FILE_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let file_ref = {
        let guard = table
            .get(artifact_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    drop(table);
    drop(tx);
    let Some(file_ref) = file_ref else {
        return Ok(None);
    };

    match stored_file_validity(&file_ref) {
        StoredFileValidity::Valid => Ok(Some(file_ref)),
        // A cache record is only a hit while its backing bytes remain
        // present and content-addressed. Rebuild callers receive `None`, and
        // the stale logical/content mappings are removed transactionally.
        StoredFileValidity::Miss => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                target: "jyth::timing",
                operation = "cache.invalidated",
                namespace = crate::timing::namespace_tag(file_ref.namespace),
                path = %file_ref.path().display(),
                size = file_ref.file_digest.file_size as u64,
            );
            invalidate(store, &file_ref)?;
            Ok(None)
        }
        // A probe that failed with a transient IO error (e.g. a Windows
        // sharing violation while another builder replaces the file) must
        // never destroy a valid record: treat it as a miss for this lookup
        // but leave the record in place.
        StoredFileValidity::Indeterminate => Ok(None),
    }
}

/// Outcome of probing whether a stored [`FileRef`]'s backing bytes still
/// match its recorded digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredFileValidity {
    /// The backing bytes are present and content-addressed.
    Valid,
    /// Authoritative miss: absent, not a file, or size/digest mismatch. The
    /// record is stale and may be invalidated.
    Miss,
    /// The probe hit a transient IO error (e.g. a Windows sharing violation
    /// while another builder replaces the file). Indeterminate: the record
    /// must NOT be invalidated.
    Indeterminate,
}

fn stored_file_validity(file_ref: &FileRef) -> StoredFileValidity {
    let path = file_ref.path();
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StoredFileValidity::Miss;
        }
        Err(_) => return StoredFileValidity::Indeterminate,
    };
    if !metadata.file_type().is_file() || metadata.len() as u128 != file_ref.file_digest.file_size {
        return StoredFileValidity::Miss;
    }
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StoredFileValidity::Miss;
        }
        Err(_) => return StoredFileValidity::Indeterminate,
    };
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match std::io::Read::read(&mut file, &mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return StoredFileValidity::Miss;
            }
            Err(_) => return StoredFileValidity::Indeterminate,
        }
    }
    if hasher.finalize() == file_ref.file_digest.file_hash {
        StoredFileValidity::Valid
    } else {
        StoredFileValidity::Miss
    }
}

fn invalidate(store: &IndexStore, file_ref: &FileRef) -> Result<(), Report<IndexError>> {
    let id = ArtifactId::from(file_ref);
    let digest = NamespacedFileDigest::from(file_ref);
    let tx = store.begin_write()?;
    let mut refs = tx
        .open_table(FILE_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut digests = tx
        .open_table(FILE_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let _ = refs
        .remove(&id)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let owner = {
        let guard = digests
            .get(&digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    if owner == Some(id) {
        let _ = digests
            .remove(&digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
    }
    drop(digests);
    drop(refs);
    tx.commit()
        .map_err(|err| IndexError::Transaction.report().attach(err))
}

pub fn upsert(
    store: &IndexStore,
    link_ref: &LinkRef,
    file_ref: &FileRef,
) -> Result<(), Report<IndexError>> {
    // Identity invariant: the link and file ref must share UUID and
    // namespace. The link's reported source size and the locally materialized
    // file size may differ (e.g. a compressed source is decompressed before
    // storage), so the two are *not* compared.
    {
        let link_ref_id = ArtifactId::from(link_ref);
        let file_ref_id = ArtifactId::from(file_ref);

        if link_ref_id.namespace != file_ref_id.namespace || link_ref_id.uuid != file_ref_id.uuid {
            return Err(IndexError::IdentityMismatch.report());
        }
    }

    let link_digest = NamespacedLinkDigest::from(link_ref);
    let file_digest = NamespacedFileDigest::from(file_ref);

    let tx = store.begin_write()?;

    let mut link_digests = tx
        .open_table(LINK_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut file_digests = tx
        .open_table(FILE_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut link_refs = tx
        .open_table(LINK_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut file_refs = tx
        .open_table(FILE_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    let resolved_link_ref = {
        let guard = link_digests
            .get(&link_digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };
    let link_ref_id = match resolved_link_ref {
        Some(link_ref_id) => link_ref_id,
        None => {
            let link_ref_id = ArtifactId::from(link_ref);
            link_digests
                .insert(&link_digest, &link_ref_id)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
            link_ref_id
        }
    };
    // `FILE_DIGESTS` is only a content-deduplication index. It must not
    // replace the logical identity used by `FILE_REFS`: two distinct links
    // can legitimately materialize identical bytes and each link must still
    // be retrievable through its own UUID.
    let file_ref_id = ArtifactId::from(file_ref);
    let file_digest_present = {
        let guard = file_digests
            .get(&file_digest)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.is_some()
    };
    if !file_digest_present {
        file_digests
            .insert(&file_digest, &file_ref_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
    }
    let link_ref_present = {
        let guard = link_refs
            .get(&link_ref_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.is_some()
    };
    if !link_ref_present {
        link_refs
            .insert(&link_ref_id, link_ref)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
    }
    file_refs
        .insert(&file_ref_id, file_ref)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    drop(link_digests);
    drop(file_digests);
    drop(link_refs);
    drop(file_refs);
    tx.commit()
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    Ok(())
}

/// Replace the on-disk `FileRef` for an existing artifact identity.
///
/// The new `FileRef`:
///
/// * MUST share the UUID and namespace of the previous record at the same
///   identity. Otherwise the operation fails with
///   [`IndexError::FileRefIdentityConflict`].
/// * May carry a brand-new `FileDigest`; the function inserts it into
///   `FILE_DIGESTS` even if it was never seen before. This allows a
///   transformation that conserves the artifact's identity (decompression,
///   `tar`→`cpio`, flatten, extract) to publish its result.
/// * MUST have a previous record at its identity. Otherwise the operation
///   fails with [`IndexError::MissingPrevious`].
///
/// `FILE_DIGESTS` is updated atomically so that a digest no longer points to
/// a `FileRef` whose storage bytes have changed. When another `FileRef` still
/// owns the new digest, the canonical mapping is preserved; when the previous
/// `FileRef` was the canonical owner of the digest, the old key is removed
/// and the canonical mapping may be rebound to the new identity below.
pub fn update(store: &IndexStore, file_ref: FileRef) -> Result<FileRef, Report<IndexError>> {
    let file_ref_id = ArtifactId::from(&file_ref);
    let new_file_digest = NamespacedFileDigest::from(&file_ref);

    let tx = store.begin_write()?;

    let mut file_refs = tx
        .open_table(FILE_REFS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;
    let mut file_digests = tx
        .open_table(FILE_DIGESTS)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    let previous = {
        let guard = file_refs
            .get(&file_ref_id)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        guard.map(|value| value.value())
    };

    let Some(previous) = previous else {
        drop(file_digests);
        drop(file_refs);
        tx.abort()
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        return Err(IndexError::MissingPrevious.report());
    };

    if previous.uuid != file_ref.uuid || previous.namespace != file_ref.namespace {
        drop(file_digests);
        drop(file_refs);
        tx.abort()
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        return Err(IndexError::FileRefIdentityConflict.report());
    }

    let previous_digest = NamespacedFileDigest::from(&previous);

    // Insert the new digest so this FileRef is reachable by its new content
    // key, even if it has never existed in the index before.
    if previous_digest != new_file_digest {
        let existing_for_new = {
            let guard = file_digests
                .get(&new_file_digest)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
            guard.map(|value| value.value())
        };
        if existing_for_new.is_none() {
            file_digests
                .insert(&new_file_digest, &file_ref_id)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
        }

        // If the previous FileRef was the canonical owner of the previous
        // digest key, rebind or remove that key so it never points to a
        // FileRef whose storage bytes have changed.
        let owner_of_previous = {
            let guard = file_digests
                .get(&previous_digest)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
            guard.map(|value| value.value())
        };
        if owner_of_previous == Some(file_ref_id) {
            let _ = file_digests
                .remove(&previous_digest)
                .map_err(|err| IndexError::Transaction.report().attach(err))?;
        }
    }

    file_refs
        .insert(&file_ref_id, &file_ref)
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    drop(file_digests);
    drop(file_refs);
    tx.commit()
        .map_err(|err| IndexError::Transaction.report().attach(err))?;

    Ok(file_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{compression::ArtifactCompression, ty::ArtifactType};
    use crate::digest::{FileDigest, LinkDigest};
    use crate::storage::link_ref::LinkRef;
    use crate::storage::namespace::Namespace;
    use tempfile::TempDir;

    fn file_ref(uuid: uuid::Uuid, digest: FileDigest) -> FileRef {
        FileRef {
            uuid,
            namespace: Namespace::Layers,
            file_digest: digest,
            artifact_type: ArtifactType::Compressed,
            artifact_compression: ArtifactCompression::None,
        }
    }

    fn fresh_store() -> IndexStore {
        let tmp = TempDir::new().expect("temp dir");
        IndexStore::open(tmp.path()).expect("open store")
    }

    fn link_ref(uuid: uuid::Uuid, file_size: u128) -> LinkRef {
        LinkRef {
            uuid,
            namespace: Namespace::Layers,
            link_digest: LinkDigest {
                link_hash: blake3::hash(b"link-source"),
                file_size,
            },
        }
    }

    fn link_ref_with_identity(uuid: uuid::Uuid, source: &[u8], file_size: u128) -> LinkRef {
        LinkRef {
            uuid,
            namespace: Namespace::Layers,
            link_digest: LinkDigest {
                link_hash: blake3::hash(source),
                file_size,
            },
        }
    }

    fn stage_file_ref_bytes(file_ref: &FileRef, bytes: &[u8]) {
        let path = file_ref.path();
        std::fs::create_dir_all(path.parent().expect("namespace parent")).expect("namespace");
        std::fs::write(path, bytes).expect("stage file ref");
    }

    #[test]
    fn distinct_link_refs_with_identical_file_digests_are_both_retrievable() {
        let store = fresh_store();
        let bytes = b"same materialized bytes";
        let digest = FileDigest {
            file_hash: blake3::hash(bytes),
            file_size: bytes.len() as u128,
        };
        let first = file_ref(uuid::Uuid::now_v7(), digest);
        let second = file_ref(uuid::Uuid::now_v7(), digest);
        stage_file_ref_bytes(&first, bytes);
        stage_file_ref_bytes(&second, bytes);
        let first_link = link_ref_with_identity(first.uuid, b"source-one", bytes.len() as u128);
        let second_link = link_ref_with_identity(second.uuid, b"source-two", bytes.len() as u128);

        upsert(&store, &first_link, &first).expect("insert first");
        upsert(&store, &second_link, &second).expect("insert second");

        assert_eq!(
            get_by_link_ref(&store, &first_link)
                .expect("first lookup")
                .expect("first cache hit"),
            first
        );
        assert_eq!(
            get_by_link_ref(&store, &second_link)
                .expect("second lookup")
                .expect("second cache hit"),
            second
        );
    }

    #[test]
    fn cache_lookup_invalidates_missing_backing_bytes() {
        let store = fresh_store();
        let bytes = b"cache bytes";
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(bytes),
                file_size: bytes.len() as u128,
            },
        );
        let link = link_ref_with_identity(file.uuid, b"cache-source", bytes.len() as u128);
        stage_file_ref_bytes(&file, bytes);
        upsert(&store, &link, &file).expect("insert cache record");
        std::fs::remove_file(file.path()).expect("remove backing bytes");

        assert!(get_by_link_ref(&store, &link).expect("lookup").is_none());
    }

    #[test]
    fn updater_accepts_new_digest_for_existing_identity() {
        let store = fresh_store();
        let uuid = uuid::Uuid::now_v7();
        let original = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"original"),
                file_size: 8,
            },
        );
        upsert(&store, &link_ref(uuid, 8), &original).expect("insert original");

        let updated = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"updated"),
                file_size: 16,
            },
        );
        let returned = update(&store, updated).expect("update");
        assert_eq!(returned.file_digest.file_size, 16);
    }

    #[test]
    fn updater_removes_or_rebinds_previous_digest_key() {
        let store = fresh_store();
        let uuid = uuid::Uuid::now_v7();
        let first = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"first"),
                file_size: 4,
            },
        );
        upsert(&store, &link_ref(uuid, 4), &first).expect("insert first");

        let second = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"second"),
                file_size: 8,
            },
        );
        update(&store, second).expect("update");

        // The previous digest key should no longer resolve, because the
        // update was the canonical owner.
        let tx = store.begin_read().expect("read");
        let table = tx
            .open_table(FILE_DIGESTS)
            .map_err(|err| IndexError::Transaction.report().attach(err))
            .expect("table");
        let first_key = NamespacedFileDigest {
            namespace: Namespace::Layers,
            file_digest: FileDigest {
                file_hash: blake3::hash(b"first"),
                file_size: 4,
            },
        };
        let guard = table.get(&first_key).expect("lookup");
        assert!(guard.is_none());
    }

    #[test]
    fn updater_preserves_uuid_and_namespace() {
        let store = fresh_store();
        let uuid = uuid::Uuid::now_v7();
        let original = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"original"),
                file_size: 4,
            },
        );
        upsert(&store, &link_ref(uuid, 4), &original).expect("insert");

        let updated = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"updated"),
                file_size: 4,
            },
        );
        let returned = update(&store, updated).expect("update");
        assert_eq!(returned.uuid, uuid);
        assert_eq!(returned.namespace, Namespace::Layers);
    }

    #[test]
    fn updater_rejects_missing_previous() {
        let store = fresh_store();
        let uuid = uuid::Uuid::now_v7();
        let orphan = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"orphan"),
                file_size: 2,
            },
        );
        let err = update(&store, orphan).expect_err("no previous");
        assert!(matches!(err.current_context(), IndexError::MissingPrevious));
    }

    #[test]
    fn upsert_allows_link_and_file_ref_with_distinct_sizes() {
        let store = fresh_store();
        let uuid = uuid::Uuid::now_v7();
        let entry = file_ref(
            uuid,
            FileDigest {
                file_hash: blake3::hash(b"materialized"),
                file_size: 256,
            },
        );
        // Link reports a different source size (e.g. compressed). The upsert
        // must still succeed because sizes are allowed to differ.
        let link = LinkRef {
            uuid,
            namespace: Namespace::Layers,
            link_digest: LinkDigest {
                link_hash: blake3::hash(b"link-source"),
                file_size: 42,
            },
        };
        upsert(&store, &link, &entry).expect("sizes may differ");
    }

    fn validity_of_staged_file(bytes: &[u8]) -> StoredFileValidity {
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(bytes),
                file_size: bytes.len() as u128,
            },
        );
        stage_file_ref_bytes(&file, bytes);
        stored_file_validity(&file)
    }

    #[test]
    fn validity_classifies_present_matching_bytes_as_valid() {
        assert_eq!(
            validity_of_staged_file(b"cache bytes"),
            StoredFileValidity::Valid
        );
    }

    #[test]
    fn validity_classifies_absent_backing_bytes_as_miss() {
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(b"cache bytes"),
                file_size: 11,
            },
        );
        assert_eq!(stored_file_validity(&file), StoredFileValidity::Miss);
    }

    #[test]
    fn validity_classifies_size_mismatch_as_miss() {
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(b"cache bytes"),
                file_size: 99,
            },
        );
        stage_file_ref_bytes(&file, b"cache bytes");
        assert_eq!(stored_file_validity(&file), StoredFileValidity::Miss);
    }

    #[test]
    fn validity_classifies_digest_mismatch_as_miss() {
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(b"different"),
                file_size: 11,
            },
        );
        stage_file_ref_bytes(&file, b"cache bytes");
        assert_eq!(stored_file_validity(&file), StoredFileValidity::Miss);
    }

    /// An unreadable backing file is a transient probe failure (Windows
    /// sharing violation class), never an authoritative miss: the record
    /// must survive the lookup.
    #[cfg(windows)]
    #[test]
    fn sharing_violation_does_not_invalidate_the_record() {
        use std::os::windows::fs::OpenOptionsExt;
        let store = fresh_store();
        let bytes = b"cache bytes";
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(bytes),
                file_size: bytes.len() as u128,
            },
        );
        let link = link_ref_with_identity(file.uuid, b"cache-source", bytes.len() as u128);
        stage_file_ref_bytes(&file, bytes);
        upsert(&store, &link, &file).expect("insert cache record");

        // Hold the backing file through an exclusive handle (share_mode(0)):
        // the module's `File::open` now fails with a sharing violation while
        // the metadata probe still succeeds.
        let exclusive = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(file.path())
            .expect("exclusive handle");

        assert!(
            get_by_link_ref(&store, &link).expect("lookup").is_none(),
            "a contended lookup is a miss, not a hit"
        );

        let tx = store.begin_read().expect("read");
        let table = tx
            .open_table(FILE_REFS)
            .map_err(|err| IndexError::Transaction.report().attach(err))
            .expect("table");
        let guard = table
            .get(ArtifactId::from(&file))
            .map_err(|err| IndexError::Transaction.report().attach(err))
            .expect("lookup");
        assert!(
            guard.is_some(),
            "the indeterminate probe must not invalidate the record"
        );
        drop(table);
        drop(tx);
        drop(exclusive);

        assert_eq!(
            get_by_link_ref(&store, &link)
                .expect("lookup")
                .expect("cache hit after the contention clears"),
            file
        );
    }

    /// Unix equivalent of the sharing-violation test: an unreadable backing
    /// file makes the probe indeterminate without invalidating the record.
    #[cfg(unix)]
    #[test]
    fn unreadable_backing_bytes_do_not_invalidate_the_record() {
        use std::os::unix::fs::PermissionsExt;
        let store = fresh_store();
        let bytes = b"cache bytes";
        let file = file_ref(
            uuid::Uuid::now_v7(),
            FileDigest {
                file_hash: blake3::hash(bytes),
                file_size: bytes.len() as u128,
            },
        );
        let link = link_ref_with_identity(file.uuid, b"cache-source", bytes.len() as u128);
        stage_file_ref_bytes(&file, bytes);
        upsert(&store, &link, &file).expect("insert cache record");

        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o000))
            .expect("make unreadable");

        assert!(
            get_by_link_ref(&store, &link).expect("lookup").is_none(),
            "an unreadable probe is a miss, not a hit"
        );

        let tx = store.begin_read().expect("read");
        let table = tx
            .open_table(FILE_REFS)
            .map_err(|err| IndexError::Transaction.report().attach(err))
            .expect("table");
        let guard = table
            .get(ArtifactId::from(&file))
            .map_err(|err| IndexError::Transaction.report().attach(err))
            .expect("lookup");
        assert!(
            guard.is_some(),
            "the indeterminate probe must not invalidate the record"
        );
    }
}
