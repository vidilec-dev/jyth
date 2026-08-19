//! `IndexStore`: the redb database owner and the table/durability helpers.
//!
//! The store owns a [`redb::Database`] handle wrapped in an `Arc` so that
//! free functions in [`super::link_ref`], [`super::file_ref`], and
//! [`super::blueprint`] can open read and write transactions against the
//! same database. The store also owns the versioned cache root so that
//! artifact-path lookups derived from a [`Namespace`](crate::storage::namespace::Namespace)
//! stay consistent with the database records even when tests use a
//! temporary directory.
//!
//! # Locking contract
//!
//! [`redb`] takes an exclusive OS-level lock on the database file for as
//! long as a [`Database`] handle is open, so no process may hold the shared
//! cache index for its lifetime: the previous `OnceLock` singleton blocked
//! every other Jyth process from materializing. All shared-index access
//! therefore goes through [`with_shared_store`], which opens the database
//! per operation and closes it (releasing the exclusive file lock) when the
//! operation returns. A process-global mutex serializes opens within one
//! process and a bounded retry absorbs brief cross-process contention, so
//! two Jyth processes can share the on-disk cache without one permanently
//! blocking the other. Dedicated indexes at an explicit root
//! ([`IndexStore::open`]) may be held for as long as their caller needs
//! them.

use std::path::PathBuf;
use std::sync::Arc;

use error_stack::Report;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::artifact::ArtifactId;
use crate::storage::blueprint::Blueprint;
use crate::storage::error::IndexError;
use crate::storage::file_ref::FileRef;
use crate::storage::link_ref::LinkRef;
use crate::storage::namespace::{NAMESPACES, NamespacedFileDigest, NamespacedLinkDigest};

pub const LINK_DIGESTS: TableDefinition<NamespacedLinkDigest, ArtifactId> =
    TableDefinition::new("link_digests");

pub const FILE_DIGESTS: TableDefinition<NamespacedFileDigest, ArtifactId> =
    TableDefinition::new("file_digests");

pub const FILE_REFS: TableDefinition<ArtifactId, FileRef> = TableDefinition::new("file_refs");

pub const LINK_REFS: TableDefinition<ArtifactId, LinkRef> = TableDefinition::new("link_refs");

pub const BLUEPRINTS: TableDefinition<ArtifactId, Blueprint> = TableDefinition::new("blueprints");

/// Schema marker kept inside the database as a second line of defence for
/// callers that open an explicitly supplied root instead of the versioned
/// default namespace. Old databases without this marker are rejected when
/// they contain records, rather than being decoded with newer codecs.
const SCHEMA: TableDefinition<&str, u32> = TableDefinition::new("image_schema");
const SCHEMA_VERSION: u32 = 3;

/// Durability setting used when committing write transactions.
///
/// Defaults to immediate because the index is the only source-to-file
/// mapping: turning a finalized artifact into an unreachable orphan after a
/// machine failure is worse than the small fsync cost.
const INDEX_DURABILITY: redb::Durability = redb::Durability::Immediate;

/// Owner of the open redb database plus the cache-versioned root.
///
/// All index mutations go through this store; cloning is cheap because the
/// database handle is shared via [`Arc`].
#[derive(Clone)]
pub struct IndexStore {
    inner: Arc<IndexStoreInner>,
}

struct IndexStoreInner {
    database: Database,
}

impl IndexStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, Report<IndexError>> {
        let index_path = root.into().join("index.redb");
        let database =
            Database::create(&index_path).map_err(|err| IndexError::Open.report().attach(err))?;

        let tx = database
            .begin_write()
            .map_err(|err| IndexError::Open.report().attach(err))?;

        let _ = tx
            .open_table(LINK_DIGESTS)
            .map_err(|err| IndexError::Open.report().attach(err))?;
        let _ = tx
            .open_table(FILE_REFS)
            .map_err(|err| IndexError::Open.report().attach(err))?;
        let _ = tx
            .open_table(FILE_DIGESTS)
            .map_err(|err| IndexError::Open.report().attach(err))?;
        let _ = tx
            .open_table(BLUEPRINTS)
            .map_err(|err| IndexError::Open.report().attach(err))?;
        let link_refs = tx
            .open_table(LINK_REFS)
            .map_err(|err| IndexError::Open.report().attach(err))?;
        let mut schema = tx
            .open_table(SCHEMA)
            .map_err(|err| IndexError::Open.report().attach(err))?;

        let recorded = schema
            .get("version")
            .map_err(|err| IndexError::Open.report().attach(err))?
            .map(|value| value.value());
        match recorded {
            Some(version) if version != SCHEMA_VERSION => {
                return Err(IndexError::SchemaMismatch.report().attach(format!(
                    "found schema version {version}, expected {SCHEMA_VERSION}"
                )));
            }
            Some(_) => {}
            None => {
                let has_records = link_digests_len(&tx)?
                    || table_len(&tx, FILE_REFS)?
                    || table_len(&tx, FILE_DIGESTS)?
                    || table_len(&tx, BLUEPRINTS)?
                    || link_refs
                        .len()
                        .map_err(|err| IndexError::Open.report().attach(err))?
                        > 0;
                if has_records {
                    return Err(IndexError::SchemaMismatch
                        .report()
                        .attach("database has records but no image schema marker"));
                }
                schema
                    .insert("version", &SCHEMA_VERSION)
                    .map_err(|err| IndexError::Open.report().attach(err))?;
            }
        }
        drop(schema);
        drop(link_refs);
        tx.commit()
            .map_err(|err| IndexError::Open.report().attach(err))?;

        Ok(Self {
            inner: Arc::new(IndexStoreInner { database }),
        })
    }

    /// Begin a write transaction configured with the store's durability.
    pub fn begin_write(&self) -> Result<redb::WriteTransaction, Report<IndexError>> {
        let mut tx = self
            .inner
            .database
            .begin_write()
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        tx.set_durability(INDEX_DURABILITY)
            .map_err(|err| IndexError::Transaction.report().attach(err))?;
        Ok(tx)
    }

    /// Begin a read transaction.
    pub fn begin_read(&self) -> Result<redb::ReadTransaction, Report<IndexError>> {
        self.inner
            .database
            .begin_read()
            .map_err(|err| IndexError::Transaction.report().attach(err))
    }
}

fn table_len<K: redb::Key + 'static, V: redb::Value + 'static>(
    tx: &redb::WriteTransaction,
    definition: TableDefinition<K, V>,
) -> Result<bool, Report<IndexError>> {
    let table = tx
        .open_table(definition)
        .map_err(|err| IndexError::Open.report().attach(err))?;
    Ok(table
        .len()
        .map_err(|err| IndexError::Open.report().attach(err))?
        > 0)
}

fn link_digests_len(tx: &redb::WriteTransaction) -> Result<bool, Report<IndexError>> {
    table_len(tx, LINK_DIGESTS)
}

/// Attempts used to open the shared index before giving up on lock
/// contention.
const SHARED_OPEN_ATTEMPTS: u32 = 10;

/// Delay between shared-index open attempts while another process holds the
/// exclusive redb file lock.
const SHARED_OPEN_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// True when `error` is an `IndexStore::open` failure caused by the
/// exclusive redb file lock being held elsewhere (same or another process).
fn is_lock_contention(error: &Report<IndexError>) -> bool {
    error.frames().any(|frame| {
        matches!(
            frame.downcast_ref::<redb::DatabaseError>(),
            Some(redb::DatabaseError::DatabaseAlreadyOpen)
        )
    })
}

/// Open the shared index, retrying a bounded number of times when another
/// process holds the exclusive file lock. Any non-contention failure is
/// returned immediately.
fn open_shared() -> Result<IndexStore, Report<IndexError>> {
    let mut attempts = 0;
    loop {
        match IndexStore::open(NAMESPACES.root.clone()) {
            Ok(store) => return Ok(store),
            Err(error) if is_lock_contention(&error) => {
                if attempts + 1 < SHARED_OPEN_ATTEMPTS {
                    attempts += 1;
                    std::thread::sleep(SHARED_OPEN_RETRY_DELAY);
                } else {
                    return Err(error.attach(format!(
                        "shared cache index is held by another process; gave up after \
                         {SHARED_OPEN_ATTEMPTS} attempts {SHARED_OPEN_RETRY_DELAY:?} apart"
                    )));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Runs `f` against a freshly-opened shared index store, closing it (and
/// releasing the exclusive redb file lock) when `f` returns. A process-global
/// mutex serializes concurrent opens within this process; a bounded retry
/// absorbs brief cross-process contention so two Jyth processes can share
/// the on-disk cache without one permanently blocking the other.
pub fn with_shared_store<T>(
    f: impl FnOnce(&IndexStore) -> Result<T, Report<IndexError>>,
) -> Result<T, Report<IndexError>> {
    use std::sync::Mutex;

    static STORE_LOCK: Mutex<()> = Mutex::new(());

    let guard = STORE_LOCK.lock().map_err(|_| {
        IndexError::Open
            .report()
            .attach("shared store mutex poisoned")
    })?;
    let store = open_shared()?;
    let result = f(&store);
    drop(store);
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::digest::LinkDigest;
    use crate::storage::index::link_ref;
    use crate::storage::namespace::Namespace;

    /// Tests that exercise the shared index root must run serialized: they
    /// hold or write the single on-disk database.
    static SHARED_ROOT_LOCK: Mutex<()> = Mutex::new(());

    fn lock_shared_root() -> MutexGuard<'static, ()> {
        SHARED_ROOT_LOCK.lock().expect("shared root lock")
    }

    #[test]
    fn shared_store_persists_across_per_operation_opens() {
        let _guard = lock_shared_root();
        let key = NamespacedLinkDigest {
            namespace: Namespace::Kernel,
            link_digest: LinkDigest {
                link_hash: blake3::hash(b"persisted across opens"),
                file_size: 22,
            },
        };

        let first =
            with_shared_store(|store| link_ref::get_or_create(store, key)).expect("first open");

        let second = with_shared_store(|store| {
            Ok(link_ref::get_or_create(store, key).expect("reserve again"))
        })
        .expect("second open");
        assert_eq!(first, second, "identity survives closing the database");
    }

    #[test]
    fn shared_open_retries_while_the_lock_is_held_and_succeeds_after_release() {
        let _guard = lock_shared_root();
        let holder = IndexStore::open(NAMESPACES.root.clone()).expect("hold the shared index");

        let started = Instant::now();
        let error = with_shared_store(|_| Ok(())).expect_err("lock is held");
        assert!(
            error
                .current_context()
                .to_string()
                .contains("failed to open"),
            "{error:#}"
        );
        // The bounded retry absorbed the contention before giving up.
        assert!(
            started.elapsed() >= SHARED_OPEN_RETRY_DELAY * (SHARED_OPEN_ATTEMPTS - 1),
            "retried for {:?}",
            started.elapsed()
        );

        drop(holder);
        with_shared_store(|store| {
            assert!(
                store.begin_read().is_ok(),
                "read transaction on a released shared index"
            );
            Ok(())
        })
        .expect("open succeeds after release");
    }

    #[test]
    fn retry_is_bounded() {
        let _guard = lock_shared_root();
        let holder = IndexStore::open(NAMESPACES.root.clone()).expect("hold the shared index");

        let started = Instant::now();
        let _ = with_shared_store(|_| Ok(()));
        drop(holder);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "retry exceeded the bounded budget: {:?}",
            started.elapsed()
        );
    }
}
