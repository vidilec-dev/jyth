//! The `ImageStore` port and its default redb-backed adapter.
//!
//! The materialization service depends on this contract instead of the
//! shared redb index. The default adapter wraps the existing index
//! functions so artifact serialization stays versioned and exhaustive: the
//! index schemas and their durability semantics are untouched. The shared
//! index is opened per operation (never held for the process lifetime), so
//! its exclusive redb file lock is transient.

use std::path::PathBuf;

use error_stack::Report;

use crate::storage::blueprint::Blueprint;
use crate::storage::error::IndexError;
use crate::storage::file_ref::FileRef;
use crate::storage::index::{blueprint, file_ref, link_ref, store};
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::NamespacedLinkDigest;
use crate::timing::{CacheOutcome, OpTimer, namespace_tag};

/// Repository contract for materialized image artifacts.
///
/// The port covers the operation family the materialization service needs:
///
/// * **Reserve** — assign a stable identity to a namespaced source link.
///   Reserving the same source digest twice returns the same identity.
/// * **Read** — retrieve the artifact materialized for a link. A record
///   whose backing bytes no longer match its recorded digest is invalidated
///   transactionally and reported as a miss.
/// * **Publish** — atomically record a materialized artifact (or replace an
///   artifact at an existing identity) so a concurrent reader never observes
///   a partial state.
///
/// Implementations must be `Send` and `Sync`; services hold them behind
/// `Arc` and must never require `Clone` on a concrete implementation.
pub trait ImageStore: Send + Sync {
    /// Reserve a stable identity for a namespaced source link, creating it
    /// on first use.
    fn reserve_link_ref(
        &self,
        link_digest: NamespacedLinkDigest,
    ) -> Result<LinkRef, Report<IndexError>>;

    /// Read the artifact materialized for `link_ref`, if any. A stale
    /// record (missing or mismatched backing bytes) is invalidated and
    /// reported as a miss.
    fn read_file_ref(&self, link_ref: &LinkRef) -> Result<Option<FileRef>, Report<IndexError>>;

    /// Atomically publish a materialized artifact under `link_ref`.
    fn publish_file_ref(
        &self,
        link_ref: &LinkRef,
        file_ref: &FileRef,
    ) -> Result<(), Report<IndexError>>;

    /// Atomically replace the artifact at an existing identity.
    fn replace_file_ref(&self, file_ref: FileRef) -> Result<FileRef, Report<IndexError>>;

    /// Read the blueprint cached for a link digest, if any.
    fn read_blueprint(
        &self,
        link_digest: NamespacedLinkDigest,
    ) -> Result<Option<Blueprint>, Report<IndexError>>;

    /// Atomically publish a blueprint.
    fn publish_blueprint(&self, value: Blueprint) -> Result<Blueprint, Report<IndexError>>;
}

/// Default adapter: the redb-backed index behind the [`ImageStore`]
/// contract.
///
/// A default `SharedStore` holds no open database: [`SharedStore::shared`]
/// probes the shared index for fast failure, then every operation opens the
/// database for its own duration (see [`store::with_shared_store`]). The
/// exclusive redb file lock is therefore transient, and other Jyth processes
/// can materialize against the same on-disk cache concurrently. A dedicated
/// store ([`SharedStore::open`]) keeps its explicit-root database for the
/// caller's lifetime.
#[derive(Clone)]
pub struct SharedStore {
    store: Option<store::IndexStore>,
}

impl SharedStore {
    /// Open the process-wide shared index as the default adapter.
    ///
    /// This constructor probes the shared index (a locked or broken cache
    /// still fails here with [`IndexError::Open`]) and returns an adapter
    /// that opens the database per operation at use time.
    pub fn shared() -> Result<Self, Report<IndexError>> {
        store::with_shared_store(|_| Ok(()))?;
        Ok(Self { store: None })
    }

    /// Open a dedicated index at `root` (used by tests and by future store
    /// crates).
    #[allow(dead_code)] // repository contract tests and future store crates open dedicated indexes
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, Report<IndexError>> {
        Ok(Self {
            store: Some(store::IndexStore::open(root)?),
        })
    }

    /// Run `f` against the dedicated store when one is held, or against the
    /// shared index opened per operation otherwise.
    fn with_store<T>(
        &self,
        f: impl FnOnce(&store::IndexStore) -> Result<T, Report<IndexError>>,
    ) -> Result<T, Report<IndexError>> {
        match &self.store {
            Some(store) => f(store),
            None => store::with_shared_store(f),
        }
    }
}

impl ImageStore for SharedStore {
    fn reserve_link_ref(
        &self,
        link_digest: NamespacedLinkDigest,
    ) -> Result<LinkRef, Report<IndexError>> {
        self.with_store(|store| link_ref::get_or_create(store, link_digest))
    }

    fn read_file_ref(&self, link_ref: &LinkRef) -> Result<Option<FileRef>, Report<IndexError>> {
        self.with_store(|store| {
            let timer = OpTimer::start("store.read").namespace(namespace_tag(link_ref.namespace));
            match file_ref::get_by_link_ref(store, link_ref) {
                Ok(Some(file_ref)) => {
                    timer.cache(CacheOutcome::Hit);
                    Ok(Some(file_ref))
                }
                Ok(None) => {
                    timer.cache(CacheOutcome::Miss);
                    Ok(None)
                }
                Err(error) => {
                    timer
                        .cache(CacheOutcome::Indeterminate)
                        .fail(format!("{error:#}"));
                    Err(error)
                }
            }
        })
    }

    fn publish_file_ref(
        &self,
        link_ref: &LinkRef,
        file_ref: &FileRef,
    ) -> Result<(), Report<IndexError>> {
        self.with_store(|store| file_ref::upsert(store, link_ref, file_ref))
    }

    fn replace_file_ref(&self, file_ref: FileRef) -> Result<FileRef, Report<IndexError>> {
        self.with_store(|store| file_ref::update(store, file_ref))
    }

    fn read_blueprint(
        &self,
        link_digest: NamespacedLinkDigest,
    ) -> Result<Option<Blueprint>, Report<IndexError>> {
        self.with_store(|store| blueprint::get_by_link_digest(store, link_digest))
    }

    fn publish_blueprint(&self, value: Blueprint) -> Result<Blueprint, Report<IndexError>> {
        self.with_store(|store| blueprint::upsert(store, value))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::artifact::{compression::ArtifactCompression, link::ArtifactLink, ty::ArtifactType};
    use crate::digest::{ExpectedDigest, FileDigest, LinkDigest};
    use crate::storage::namespace::Namespace;

    fn fresh_store() -> (SharedStore, TempDir) {
        let tmp = TempDir::new().expect("temp dir");
        let store = SharedStore::open(tmp.path()).expect("open store");
        (store, tmp)
    }

    fn link_digest(bytes: &[u8]) -> LinkDigest {
        LinkDigest {
            link_hash: blake3::hash(bytes),
            file_size: bytes.len() as u128,
        }
    }

    fn namespaced(digest: LinkDigest, namespace: Namespace) -> NamespacedLinkDigest {
        NamespacedLinkDigest {
            namespace,
            link_digest: digest,
        }
    }

    /// A `FileRef` sharing the reserved identity of `link_ref` (the
    /// publish invariant: UUID and namespace must match) with backing bytes
    /// staged at its content-addressed path.
    fn staged_for(link_ref: &LinkRef, bytes: &[u8]) -> FileRef {
        let file_ref = FileRef {
            uuid: link_ref.uuid,
            namespace: link_ref.namespace,
            file_digest: FileDigest {
                file_hash: blake3::hash(bytes),
                file_size: bytes.len() as u128,
            },
            artifact_type: ArtifactType::ContainerTar,
            artifact_compression: ArtifactCompression::None,
        };
        let path = file_ref.path();
        std::fs::create_dir_all(path.parent().expect("namespace parent")).expect("namespace");
        std::fs::write(&path, bytes).expect("stage backing bytes");
        file_ref
    }

    /// A `FileRef` sharing the reserved identity of `link_ref` (the

    #[test]
    fn reserve_returns_a_stable_identity_per_digest() {
        let (store, _tmp) = fresh_store();
        let key = namespaced(link_digest(b"source-one"), Namespace::Kernel);
        let first = store.reserve_link_ref(key).expect("reserve");
        let second = store.reserve_link_ref(key).expect("reserve again");
        assert_eq!(first, second);

        let other_key = namespaced(link_digest(b"source-two"), Namespace::Kernel);
        let other = store.reserve_link_ref(other_key).expect("reserve other");
        assert_ne!(first, other);
    }

    #[test]
    fn publish_then_read_round_trips() {
        let (store, _tmp) = fresh_store();
        let link_ref = store
            .reserve_link_ref(namespaced(link_digest(b"source"), Namespace::Layers))
            .expect("reserve");
        let file_ref = staged_for(&link_ref, b"artifact bytes");
        store
            .publish_file_ref(&link_ref, &file_ref)
            .expect("publish");
        assert_eq!(
            store.read_file_ref(&link_ref).expect("read"),
            Some(file_ref)
        );
    }

    #[test]
    fn read_reports_a_missing_artifact_as_none() {
        let (store, _tmp) = fresh_store();
        let link_ref = store
            .reserve_link_ref(namespaced(link_digest(b"absent"), Namespace::Kernel))
            .expect("reserve");
        assert_eq!(store.read_file_ref(&link_ref).expect("read"), None);
    }

    #[test]
    fn read_invalidates_stale_backing_bytes() {
        let (store, _tmp) = fresh_store();
        let link_ref = store
            .reserve_link_ref(namespaced(link_digest(b"source"), Namespace::Layers))
            .expect("reserve");
        let file_ref = staged_for(&link_ref, b"cache bytes");
        store
            .publish_file_ref(&link_ref, &file_ref)
            .expect("publish");
        std::fs::remove_file(file_ref.path()).expect("remove backing bytes");

        assert_eq!(store.read_file_ref(&link_ref).expect("read"), None);
    }

    #[test]
    fn replace_updates_an_existing_identity() {
        let (store, _tmp) = fresh_store();
        let link_ref = store
            .reserve_link_ref(namespaced(link_digest(b"source"), Namespace::Layers))
            .expect("reserve");
        let original = staged_for(&link_ref, b"original");
        store
            .publish_file_ref(&link_ref, &original)
            .expect("publish");

        let replacement = FileRef {
            uuid: original.uuid,
            namespace: original.namespace,
            file_digest: FileDigest {
                file_hash: blake3::hash(b"replacement"),
                file_size: 11,
            },
            artifact_type: ArtifactType::ContainerCpio,
            artifact_compression: ArtifactCompression::None,
        };
        let returned = store.replace_file_ref(replacement).expect("replace");
        assert_eq!(returned.file_digest.file_size, 11);

        // The backing bytes no longer match the new record's digest; the
        // read probes and reports a miss.
        assert_eq!(store.read_file_ref(&link_ref).expect("read"), None);
    }

    #[test]
    fn blueprint_round_trips_through_the_store() {
        let (store, _tmp) = fresh_store();
        let key = namespaced(link_digest(b"manifest source"), Namespace::Rootfs);
        let target = store.reserve_link_ref(key).expect("reserve");
        let link = ArtifactLink::bytes("layer");
        let layer = crate::storage::blueprint::Layer {
            uuid: uuid::Uuid::now_v7(),
            link: link.clone(),
            expected_digest: ExpectedDigest::parse(&format!("sha256:{}", "ab".repeat(32)))
                .expect("digest"),
            link_digest: link.digest().expect("link digest"),
        };
        let blueprint = Blueprint {
            target_entry_uuid: target.uuid,
            target_entry_namespace: target.namespace,
            layers: vec![layer],
            extract: None,
        };
        store.publish_blueprint(blueprint.clone()).expect("publish");
        let restored = store.read_blueprint(key).expect("read").expect("hit");
        assert_eq!(restored, blueprint);
    }

    #[tokio::test]
    async fn concurrent_reserves_share_one_identity() {
        let (store, _tmp) = fresh_store();
        let store = Arc::new(store);
        let key = namespaced(link_digest(b"contended"), Namespace::Kernel);

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.reserve_link_ref(key).expect("reserve")
            }));
        }
        let mut results: Vec<LinkRef> = Vec::new();
        for task in tasks {
            results.push(task.await.expect("join"));
        }
        for other in &results[1..] {
            assert_eq!(results[0], *other);
        }
    }

    #[tokio::test]
    async fn concurrent_reads_share_the_published_artifact() {
        let (store, _tmp) = fresh_store();
        let store = Arc::new(store);
        let link_ref = store
            .reserve_link_ref(namespaced(link_digest(b"shared"), Namespace::Layers))
            .expect("reserve");
        let file_ref = staged_for(&link_ref, b"published bytes");
        store
            .publish_file_ref(&link_ref, &file_ref)
            .expect("publish");

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.read_file_ref(&link_ref).expect("read")
            }));
        }
        for task in tasks {
            assert_eq!(task.await.expect("join"), Some(file_ref.clone()));
        }
    }
}
