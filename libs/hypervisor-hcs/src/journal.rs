//! Durable ownership records for resources created by the Windows HCS backend.
//!
//! The image cache has a different lifetime and failure domain, so runtime
//! ownership intentionally lives in one redb database per Jyth host process.
//! The database file is also the process liveness lease: redb permits only one
//! writable opener, therefore a recovery walk skips a session whose database
//! is still open by another process.

use crate::error::HcsError;
use error_stack::Report;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use vm_model::disk::{DiskOrigin, DiskRetention};

/// Schema version of the session and record tables. Records and databases
/// carrying a different version are rejected or skipped, never migrated.
pub const SCHEMA_VERSION: u32 = 1;
const STATE_DIR_ENV: &str = "JYTH_STATE_DIR";

const SCHEMA: TableDefinition<&str, u32> = TableDefinition::new("journal_schema");
const SESSION: TableDefinition<&str, &[u8]> = TableDefinition::new("session");
const VM_RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("vm_records");
const ABANDONED: TableDefinition<&str, &[u8]> = TableDefinition::new("abandoned");

/// Automatic recovery retries a failed record at most this many times across
/// recovery runs before transitioning its remaining resources to
/// [`ResourceState::Abandoned`] for operator review.
pub(crate) const MAX_CLEANUP_ATTEMPTS: u32 = 3;

/// State of one individual external resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ResourceState {
    Planned,
    Created,
    Removed,
    RemovalFailed,
    /// Terminal: automatic recovery gave up after [`MAX_CLEANUP_ATTEMPTS`]
    /// failed passes. The record is preserved (with its last error and exact
    /// identity) in the abandoned inventory until an operator removes the
    /// resource deliberately. Explicit cleanup still attempts it and, on
    /// success, transitions it back to `Removed`.
    Abandoned,
}

/// Lifecycle phase of a journaled VM attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum VmResourcePhase {
    Planned,
    Starting,
    Published,
    CleanupPending,
    Complete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileIdentity {
    pub volume_serial: u32,
    pub file_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    pub schema_version: u32,
    pub session_id: Uuid,
    /// The exact owner string placed in HCS configuration documents. It is
    /// deterministic from the session UUID, but keeping it in the durable
    /// record makes the intent-before-side-effect boundary explicit.
    #[serde(default)]
    pub owner: String,
    pub owner_sid: String,
    pub process_id: u32,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ComputeResource {
    pub id: String,
    pub state: ResourceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NetworkResource {
    pub network_name: String,
    pub network_id: Option<String>,
    pub endpoint_name: String,
    pub endpoint_id: Option<String>,
    pub state: ResourceState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DiskResource {
    /// Absolute normalized host path of the backing file, persisted in its
    /// faithful `OsString` form (WTF-16 code units) so cleanup targets
    /// exactly the file the VHDX creation addressed — a lossy UTF-8 round
    /// trip would mangle surrogate code units and later target a different
    /// file.
    #[serde(with = "wide_path_serde")]
    pub path: OsString,
    /// Stable HCS attachment slot selected before the VHDX side effect.
    #[serde(default)]
    pub controller: u32,
    #[serde(default)]
    pub lun: u32,
    pub state: ResourceState,
    pub origin: DiskOrigin,
    pub requested_retention: DiskRetention,
    pub effective_retention: DiskRetention,
    pub file_identity: Option<FileIdentity>,
    pub initialization_requested: bool,
    pub initialization_acknowledged: bool,
    pub vm_ace_added: bool,
    pub published: bool,
}

/// Serde bridge for the journal disk path. New records serialize the
/// faithful WTF-16 code units (`encode_wide`), which round-trip every
/// path including surrogate-only ones; reads accept both the wide-unit
/// array and the legacy UTF-8 string form written by pre-hardening
/// sessions (a plain UTF-8 path is exact when it contains no unpaired
/// surrogates).
mod wide_path_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    pub fn serialize<S: Serializer>(path: &OsString, serializer: S) -> Result<S::Ok, S::Error> {
        let units: Vec<u16> = path.encode_wide().collect();
        Serialize::serialize(&units, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OsString, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Array(units) => {
                let units = units
                    .into_iter()
                    .map(|unit| unit.as_u64().map(|unit| unit as u16))
                    .collect::<Option<Vec<u16>>>()
                    .ok_or_else(|| {
                        serde::de::Error::custom("journal disk path units must be u16")
                    })?;
                Ok(OsString::from_wide(&units))
            }
            serde_json::Value::String(text) => Ok(OsString::from(text)),
            _ => Err(serde::de::Error::custom(
                "journal disk path must be a wide-unit array or a string",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VmResourceRecord {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub phase: VmResourcePhase,
    pub published: bool,
    pub compute_system: ComputeResource,
    pub network: Option<NetworkResource>,
    pub disks: Vec<DiskResource>,
    pub cleanup_attempts: u32,
    pub last_error: Option<String>,
}

impl VmResourceRecord {
    /// True when the record is terminal for recovery purposes: explicitly
    /// `Complete`, or every resource is `Removed` or `Abandoned` (both stop
    /// automatic retries; `Abandoned` resources are listed in the abandoned
    /// inventory for deliberate operator removal).
    pub(crate) fn is_complete(&self) -> bool {
        let terminal = |state: ResourceState| {
            state == ResourceState::Removed || state == ResourceState::Abandoned
        };
        self.phase == VmResourcePhase::Complete
            || (terminal(self.compute_system.state)
                && self
                    .network
                    .as_ref()
                    .is_none_or(|network| terminal(network.state))
                && self.disks.iter().all(|disk| terminal(disk.state)))
    }
}

/// One abandoned host resource, as persisted in the abandoned inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedResourceEntry {
    /// Resource kind (`compute_system`, `network`, or `disk`).
    pub kind: String,
    /// The exact resource identity (compute-system ID, `network/endpoint`
    /// names, or disk path) an operator needs to remove it deliberately.
    pub identity: String,
    /// Self-describing last error carrying `resource_kind`/`operation`/
    /// `resource_id`/`cause` context.
    pub last_error: String,
    /// Unix time (milliseconds) of the first abandonment of this entry.
    pub first_abandoned_at_unix_ms: u64,
}

/// All abandoned resources of one VM, keyed by `vm_id` in the session
/// database's `abandoned` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedRecord {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub entries: Vec<AbandonedResourceEntry>,
}

struct JournalInner {
    database: Database,
    #[cfg(feature = "tracing")]
    path: PathBuf,
    session: SessionRecord,
    write_lock: Mutex<()>,
}

/// One process-wide runtime session database.
///
/// Public so the `journal-lock-hold` test fixture can create a journal from
/// a separate process; all mutation remains crate-internal.
#[derive(Clone)]
pub struct SessionJournal {
    inner: Arc<JournalInner>,
}

impl SessionJournal {
    /// Create a fresh session database after stale sessions have been
    /// reconciled by the HCS module.
    ///
    /// Public because the `journal-lock-hold` test fixture creates a real
    /// journal from a separate process to verify cross-process writer-lock
    /// exclusivity.
    pub fn create_current(
        root: impl Into<PathBuf>,
        session_id: Uuid,
    ) -> Result<Self, Report<HcsError>> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|error| journal_report("create state root", error))?;
        reject_reparse_components(&root)?;
        let owner_sid = current_user_sid()?;
        if is_production_state_root(&root)? {
            apply_production_acl(&root, &owner_sid)?;
        }

        let path = session_path(&root, session_id);
        let database = Database::create(&path)
            .map_err(|error| journal_report("create session database", error))?;
        initialize_database(&database)?;

        let session = SessionRecord {
            schema_version: SCHEMA_VERSION,
            session_id,
            owner: owner_for(session_id),
            owner_sid,
            process_id: std::process::id(),
            created_at_unix_ms: unix_time_ms(),
        };
        let session_bytes = serde_json::to_vec(&session)
            .map_err(|error| journal_report("encode session record", error))?;
        let journal = Self {
            inner: Arc::new(JournalInner {
                database,
                #[cfg(feature = "tracing")]
                path,
                session,
                write_lock: Mutex::new(()),
            }),
        };
        journal.write(|tx| {
            let mut table = tx
                .open_table(SESSION)
                .map_err(|error| journal_report("open session table", error))?;
            table
                .insert("current", session_bytes.as_slice())
                .map_err(|error| journal_report("write session record", error))?;
            drop(table);
            Ok(())
        })?;
        Ok(journal)
    }

    /// Attempt to open a stale session. `Ok(None)` means another live Jyth
    /// process still owns the redb writer lock and must not be disturbed.
    pub(crate) fn try_open_existing(path: &Path) -> Result<Option<Self>, Report<HcsError>> {
        let database = match Database::open(path) {
            Ok(database) => database,
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => return Ok(None),
            Err(error) => {
                return Err(journal_report("open stale session database", error));
            }
        };
        let session = read_existing_session(&database, path)?;

        Ok(Some(Self {
            inner: Arc::new(JournalInner {
                database,
                #[cfg(feature = "tracing")]
                path: path.to_path_buf(),
                session,
                write_lock: Mutex::new(()),
            }),
        }))
    }

    pub(crate) fn session_id(&self) -> Uuid {
        self.inner.session.session_id
    }

    pub(crate) fn owner(&self) -> String {
        if self.inner.session.owner.is_empty() {
            owner_for(self.session_id())
        } else {
            self.inner.session.owner.clone()
        }
    }

    #[cfg(feature = "tracing")]
    pub(crate) fn path(&self) -> &Path {
        &self.inner.path
    }

    pub(crate) fn put_vm(&self, record: &VmResourceRecord) -> Result<(), Report<HcsError>> {
        validate_schema_version(record.schema_version, "VM resource record")?;
        let bytes = serde_json::to_vec(record)
            .map_err(|error| journal_report("encode VM resource record", error))?;
        let key = record.vm_id.to_string();
        self.write(|tx| {
            let mut table = tx
                .open_table(VM_RECORDS)
                .map_err(|error| journal_report("open VM records table", error))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|error| journal_report("write VM resource record", error))?;
            drop(table);
            Ok(())
        })
    }

    pub(crate) fn update_vm(
        &self,
        vm_id: Uuid,
        update: impl FnOnce(&mut VmResourceRecord),
    ) -> Result<(), Report<HcsError>> {
        let key = vm_id.to_string();
        self.write(|tx| {
            let mut table = tx
                .open_table(VM_RECORDS)
                .map_err(|error| journal_report("open VM records table", error))?;
            let current = table
                .get(key.as_str())
                .map_err(|error| journal_report("read VM resource record", error))?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| {
                    Report::new(HcsError::Journal)
                        .attach(format!("VM resource record {vm_id} is missing"))
                })?;
            let mut record: VmResourceRecord = serde_json::from_slice(&current)
                .map_err(|error| journal_report("decode VM resource record", error))?;
            validate_schema_version(record.schema_version, "VM resource record")?;
            update(&mut record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|error| journal_report("encode VM resource record", error))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|error| journal_report("write updated VM resource record", error))?;
            drop(table);
            Ok(())
        })
    }

    pub(crate) fn vm(&self, vm_id: Uuid) -> Result<Option<VmResourceRecord>, Report<HcsError>> {
        let key = vm_id.to_string();
        let tx = self
            .inner
            .database
            .begin_read()
            .map_err(|error| journal_report("begin VM record read", error))?;
        let table = tx
            .open_table(VM_RECORDS)
            .map_err(|error| journal_report("open VM records table", error))?;
        let bytes = table
            .get(key.as_str())
            .map_err(|error| journal_report("read VM resource record", error))?
            .map(|value| value.value().to_vec());
        drop(table);
        drop(tx);
        bytes
            .map(|bytes| {
                let record: VmResourceRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| journal_report("decode VM resource record", error))?;
                validate_schema_version(record.schema_version, "VM resource record")?;
                Ok(record)
            })
            .transpose()
    }

    pub(crate) fn all_vms(&self) -> Result<Vec<VmResourceRecord>, Report<HcsError>> {
        let tx = self
            .inner
            .database
            .begin_read()
            .map_err(|error| journal_report("begin VM records read", error))?;
        let table = tx
            .open_table(VM_RECORDS)
            .map_err(|error| journal_report("open VM records table", error))?;
        let mut records = Vec::new();
        for entry in table
            .iter()
            .map_err(|error| journal_report("iterate VM records", error))?
        {
            let (_key, value) =
                entry.map_err(|error| journal_report("read VM record entry", error))?;
            let record: VmResourceRecord = serde_json::from_slice(value.value())
                .map_err(|error| journal_report("decode VM record entry", error))?;
            validate_schema_version(record.schema_version, "VM resource record")?;
            records.push(record);
        }
        drop(table);
        drop(tx);
        Ok(records)
    }

    pub(crate) fn remove_vm(&self, vm_id: Uuid) -> Result<(), Report<HcsError>> {
        let key = vm_id.to_string();
        self.write(|tx| {
            let mut table = tx
                .open_table(VM_RECORDS)
                .map_err(|error| journal_report("open VM records table", error))?;
            table
                .remove(key.as_str())
                .map_err(|error| journal_report("remove VM resource record", error))?;
            drop(table);
            Ok(())
        })
    }

    /// Upsert one VM's abandoned inventory row. Entries already recorded for
    /// the same kind + identity keep their first-abandoned timestamp.
    pub(crate) fn put_abandoned(&self, record: &AbandonedRecord) -> Result<(), Report<HcsError>> {
        validate_schema_version(record.schema_version, "abandoned record")?;
        let previous = self.abandoned(record.vm_id)?;
        let mut entries = match previous {
            Some(previous) => previous.entries,
            None => Vec::new(),
        };
        for entry in &record.entries {
            match entries
                .iter_mut()
                .find(|existing| existing.kind == entry.kind && existing.identity == entry.identity)
            {
                Some(existing) => {
                    existing.last_error = entry.last_error.clone();
                }
                None => entries.push(entry.clone()),
            }
        }
        let bytes = serde_json::to_vec(&AbandonedRecord {
            schema_version: record.schema_version,
            vm_id: record.vm_id,
            entries,
        })
        .map_err(|error| journal_report("encode abandoned record", error))?;
        let key = record.vm_id.to_string();
        self.write(|tx| {
            let mut table = tx
                .open_table(ABANDONED)
                .map_err(|error| journal_report("open abandoned table", error))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|error| journal_report("write abandoned record", error))?;
            drop(table);
            Ok(())
        })
    }

    /// Read one VM's abandoned inventory row, if any. A pre-inventory
    /// schema-1 database without an `abandoned` table reads as `None`.
    pub(crate) fn abandoned(
        &self,
        vm_id: Uuid,
    ) -> Result<Option<AbandonedRecord>, Report<HcsError>> {
        let key = vm_id.to_string();
        let tx = self
            .inner
            .database
            .begin_read()
            .map_err(|error| journal_report("begin abandoned record read", error))?;
        let table = match tx.open_table(ABANDONED) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(journal_report("open abandoned table", error)),
        };
        let bytes = table
            .get(key.as_str())
            .map_err(|error| journal_report("read abandoned record", error))?
            .map(|value| value.value().to_vec());
        drop(table);
        drop(tx);
        bytes
            .map(|bytes| {
                let record: AbandonedRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| journal_report("decode abandoned record", error))?;
                validate_schema_version(record.schema_version, "abandoned record")?;
                Ok(record)
            })
            .transpose()
    }

    /// Drop one VM's abandoned inventory row (explicit cleanup succeeded).
    pub(crate) fn remove_abandoned(&self, vm_id: Uuid) -> Result<(), Report<HcsError>> {
        let key = vm_id.to_string();
        self.write(|tx| {
            let mut table = tx
                .open_table(ABANDONED)
                .map_err(|error| journal_report("open abandoned table", error))?;
            table
                .remove(key.as_str())
                .map_err(|error| journal_report("remove abandoned record", error))?;
            drop(table);
            Ok(())
        })
    }

    /// True when the session database holds at least one abandoned record.
    /// Used by recovery to retain a session file that carries inventory.
    pub(crate) fn has_abandoned(&self) -> Result<bool, Report<HcsError>> {
        let tx = self
            .inner
            .database
            .begin_read()
            .map_err(|error| journal_report("begin abandoned scan", error))?;
        let table = match tx.open_table(ABANDONED) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(error) => return Err(journal_report("open abandoned table", error)),
        };
        let empty = table
            .is_empty()
            .map_err(|error| journal_report("scan abandoned table", error))?;
        drop(table);
        drop(tx);
        Ok(!empty)
    }

    fn write<T>(
        &self,
        operation: impl FnOnce(&redb::WriteTransaction) -> Result<T, Report<HcsError>>,
    ) -> Result<T, Report<HcsError>> {
        let _guard = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut tx = self
            .inner
            .database
            .begin_write()
            .map_err(|error| journal_report("begin journal write", error))?;
        tx.set_durability(Durability::Immediate)
            .map_err(|error| journal_report("set journal durability", error))?;
        let result = operation(&tx)?;
        tx.commit()
            .map_err(|error| journal_report("commit journal write", error))?;
        Ok(result)
    }
}

pub(crate) fn session_path(root: &Path, session_id: Uuid) -> PathBuf {
    root.join(format!("{session_id}.redb"))
}

pub(crate) fn session_paths(root: &Path) -> Result<Vec<PathBuf>, Report<HcsError>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(root).map_err(|error| journal_report("enumerate session root", error))?
    {
        let entry = entry.map_err(|error| journal_report("read session directory entry", error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| journal_report("inspect session directory entry", error))?;
        let path = entry.path();
        if file_type.is_file()
            && path.extension().and_then(OsStr::to_str) == Some("redb")
            && !is_reparse_point(&path)?
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// Resolve the state root: the `JYTH_STATE_DIR` override when set, otherwise
/// the production `ProgramData\jyth\state\v1\sessions` directory. The
/// resolved root is created and reparse-guarded.
pub fn resolve_state_root() -> Result<PathBuf, Report<HcsError>> {
    if let Some(override_root) = std::env::var_os(STATE_DIR_ENV) {
        let path = absolute_path(PathBuf::from(override_root))?;
        fs::create_dir_all(&path)
            .map_err(|error| journal_report("create override state root", error))?;
        reject_reparse_components(&path)?;
        return Ok(path);
    }

    let program_data = known_program_data()?;
    reject_reparse_components(&program_data)?;
    let root = program_data
        .join("jyth")
        .join("state")
        .join("v1")
        .join("sessions");
    fs::create_dir_all(&root)
        .map_err(|error| journal_report("create production state root", error))?;
    reject_reparse_components(&root)?;
    Ok(root)
}

/// Outcome of probing one session database's writer lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLockState {
    /// Another live process holds the redb writer lock; recovery must skip it.
    Locked,
    /// The database is unlocked and readable; recovery may open and clean it.
    Recoverable,
    /// The database is unlocked but unreadable (schema mismatch, missing
    /// session record, or IO failure). Carries the rejection reason.
    Corrupt(String),
}

/// Probe whether a session database is currently locked by another process.
/// Opens the database and immediately closes it; never retains the lock.
///
/// All three outcomes are reported as `Ok`; the `Result` wrapper is kept for
/// forward compatibility with IO probing that may need to surface a failure.
pub fn probe_session_lock(path: &Path) -> Result<SessionLockState, Report<HcsError>> {
    match SessionJournal::try_open_existing(path) {
        Ok(Some(journal)) => {
            drop(journal);
            Ok(SessionLockState::Recoverable)
        }
        Ok(None) => Ok(SessionLockState::Locked),
        Err(error) => Ok(SessionLockState::Corrupt(error.to_string())),
    }
}

pub(crate) fn file_identity(path: &Path) -> Result<FileIdentity, Report<HcsError>> {
    let file = File::open(path).map_err(|error| {
        Report::new(HcsError::Cleanup)
            .attach(format!("open {} for identity: {error}", path.display()))
    })?;
    let mut info = ByHandleFileInformation::default();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(Report::new(HcsError::Cleanup).attach(format!(
            "GetFileInformationByHandle({}) failed",
            path.display()
        )));
    }
    Ok(FileIdentity {
        volume_serial: info.volume_serial_number,
        file_id: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    })
}

fn initialize_database(database: &Database) -> Result<(), Report<HcsError>> {
    let mut tx = database
        .begin_write()
        .map_err(|error| journal_report("begin schema write", error))?;
    tx.set_durability(Durability::Immediate)
        .map_err(|error| journal_report("set schema durability", error))?;
    let mut schema = tx
        .open_table(SCHEMA)
        .map_err(|error| journal_report("open journal schema", error))?;
    let recorded = schema
        .get("version")
        .map_err(|error| journal_report("read journal schema", error))?
        .map(|value| value.value());
    match recorded {
        Some(version) if version != SCHEMA_VERSION => {
            return Err(Report::new(HcsError::JournalSchemaMismatch).attach(format!(
                "found journal schema version {version}, expected {SCHEMA_VERSION}"
            )));
        }
        Some(_) => {}
        None => {
            schema
                .insert("version", &SCHEMA_VERSION)
                .map_err(|error| journal_report("write journal schema", error))?;
        }
    }
    drop(schema);
    let _ = tx
        .open_table(SESSION)
        .map_err(|error| journal_report("create session table", error))?;
    let _ = tx
        .open_table(VM_RECORDS)
        .map_err(|error| journal_report("create VM records table", error))?;
    let _ = tx
        .open_table(ABANDONED)
        .map_err(|error| journal_report("create abandoned table", error))?;
    tx.commit()
        .map_err(|error| journal_report("commit journal schema", error))
}

fn read_existing_session(
    database: &Database,
    path: &Path,
) -> Result<SessionRecord, Report<HcsError>> {
    let tx = database
        .begin_read()
        .map_err(|error| journal_report("begin session read", error))?;

    let schema_version = {
        let schema = tx
            .open_table(SCHEMA)
            .map_err(|error| journal_report("open journal schema", error))?;
        schema
            .get("version")
            .map_err(|error| journal_report("read journal schema", error))?
            .map(|value| value.value())
            .ok_or_else(|| {
                Report::new(HcsError::JournalSchemaMismatch).attach(format!(
                    "session database {} has no schema version",
                    path.display()
                ))
            })?
    };
    validate_schema_version(schema_version, "journal")?;

    let session_bytes = {
        let table = tx
            .open_table(SESSION)
            .map_err(|error| journal_report("open session table", error))?;
        table
            .get("current")
            .map_err(|error| journal_report("read session record", error))?
            .map(|value| value.value().to_vec())
    };

    {
        let _ = tx
            .open_table(VM_RECORDS)
            .map_err(|error| journal_report("open VM records table", error))?;
    }
    drop(tx);

    let session_bytes = session_bytes.ok_or_else(|| {
        Report::new(HcsError::Journal).attach(format!(
            "session database {} has no session record",
            path.display()
        ))
    })?;
    let mut session: SessionRecord = serde_json::from_slice(&session_bytes)
        .map_err(|error| journal_report("decode session record", error))?;
    validate_schema_version(session.schema_version, "session record")?;
    let expected_owner = owner_for(session.session_id);
    if session.owner.is_empty() {
        // R1-R3 records did not persist this derived value. Reconstructing it
        // is safe because the session UUID remains the durable identity used
        // by the HCS owner string.
        session.owner = expected_owner;
    } else if session.owner != expected_owner {
        return Err(Report::new(HcsError::Journal).attach(format!(
            "session owner `{}` does not match session UUID {}",
            session.owner, session.session_id
        )));
    }
    Ok(session)
}

/// Convert a path to an absolute, lexical-normalized path without requiring
/// the target to exist. Disk intent is journaled before a missing VHDX is
/// created, so `canonicalize` cannot be used here. A relative input is
/// resolved against the current directory first; the shared lexical pass
/// then rejects any `..` that would escape above the root.
pub(crate) fn normalize_absolute_path(path: &Path) -> Result<PathBuf, Report<HcsError>> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| journal_report("resolve absolute path", error))?
            .join(path)
    };
    normalize_lexically(&absolute)
}

/// Shared lexical normalizer for absolute Windows paths: collapses `.` and
/// `..` components and stops at the root. A `..` that would pop the drive
/// prefix or UNC root is an error — silently popping past the root produces
/// a drive-relative path (e.g. `C:\..\disks\x.vhdx` → `C:disks\x.vhdx`)
/// that Windows resolves against the current directory of drive C. Used by
/// the journal (`normalize_absolute_path`) and the disk backend
/// (`vm_model::disk::DiskSpec::normalized_host_path`).
///
/// The algorithm lives in `vm_model::path` (pure computation); this wrapper
/// only maps the model error into the HCS error context.
pub(crate) fn normalize_lexically(absolute: &Path) -> Result<PathBuf, Report<HcsError>> {
    vm_model::path::normalize_lexically(absolute).map_err(|error| match error {
        vm_model::path::PathError::NotAbsolute => Report::new(HcsError::DiskInvalidPath).attach(
            format!("disk path must be absolute; got `{}`", absolute.display()),
        ),
        vm_model::path::PathError::EscapesRoot => Report::new(HcsError::DiskInvalidPath).attach(
            format!("disk path `{}` escapes above the root", absolute.display()),
        ),
    })
}

fn absolute_path(path: PathBuf) -> Result<PathBuf, Report<HcsError>> {
    normalize_absolute_path(&path)
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Read-only scan of every unlocked session database under `root` for
/// abandoned records. Live sessions (writable lock held by another process)
/// and pre-inventory schema-1 databases without an `abandoned` table are
/// skipped; no database is modified. A session database that cannot be
/// opened read-only (e.g. its owning process died mid-write and the file
/// needs repair) is logged as a warning and skipped, so one damaged dead
/// session can never wedge the whole inventory. Consumed by the read-only
/// abandoned inventory admin query.
pub fn abandoned_inventory(root: &Path) -> Result<Vec<AbandonedRecord>, Report<HcsError>> {
    let mut records = Vec::new();
    for path in session_paths(root)? {
        let database = match redb::ReadOnlyDatabase::open(&path) {
            Ok(database) => database,
            Err(redb::DatabaseError::DatabaseAlreadyOpen) => continue,
            Err(_error) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    session = %path.display(),
                    error = %_error,
                    "skipping a session database that cannot be opened read-only; \
                     its owning process likely died mid-write and the file needs repair"
                );
                continue;
            }
        };
        let tx = database
            .begin_read()
            .map_err(|error| journal_report("begin abandoned inventory read", error))?;
        let table = match tx.open_table(ABANDONED) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => continue,
            Err(error) => return Err(journal_report("open abandoned table", error)),
        };
        for entry in table
            .iter()
            .map_err(|error| journal_report("iterate abandoned records", error))?
        {
            let (_key, value) =
                entry.map_err(|error| journal_report("read abandoned record entry", error))?;
            let record: AbandonedRecord = serde_json::from_slice(value.value())
                .map_err(|error| journal_report("decode abandoned record entry", error))?;
            if record.schema_version == SCHEMA_VERSION {
                records.push(record);
            }
        }
    }
    Ok(records)
}

fn owner_for(session_id: Uuid) -> String {
    format!("jyth/v1/{session_id}")
}

fn journal_report(operation: &str, error: impl std::fmt::Display) -> Report<HcsError> {
    Report::new(HcsError::Journal).attach(format!("{operation}: {error}"))
}

fn validate_schema_version(version: u32, record_kind: &str) -> Result<(), Report<HcsError>> {
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(Report::new(HcsError::JournalSchemaMismatch).attach(format!(
            "{record_kind} schema version {version} is unsupported; expected {SCHEMA_VERSION}"
        )))
    }
}

pub(crate) fn reject_reparse_components(path: &Path) -> Result<(), Report<HcsError>> {
    if let Some(component) = first_reparse_component(path)? {
        return Err(Report::new(HcsError::Journal).attach(format!(
            "production state path contains a reparse point: {}",
            component.display()
        )));
    }
    Ok(())
}

/// Reject a disk path whose own file or any existing ancestor is a reparse
/// point. Disk intent is journaled before a missing VHDX exists, so only
/// existing components are inspected (mirroring the state-root guard).
pub(crate) fn reject_disk_reparse_points(path: &Path) -> Result<(), Report<HcsError>> {
    if let Some(component) = first_reparse_component(path)? {
        return Err(
            Report::new(HcsError::DiskReparsePointRejected).attach(format!(
                "disk path traverses a reparse point: {}",
                component.display()
            )),
        );
    }
    Ok(())
}

fn first_reparse_component(path: &Path) -> Result<Option<PathBuf>, Report<HcsError>> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() && is_reparse_point(&current)? {
            return Ok(Some(current));
        }
    }
    Ok(None)
}

fn apply_production_acl(path: &Path, owner_sid: &str) -> Result<(), Report<HcsError>> {
    // icacls requires a leading `*` when a raw SID is supplied instead of
    // an account name; without it, localized hosts may interpret the SID as
    // a literal account name and reject the ACL update.
    let owner = format!("*{owner_sid}:(OI)(CI)F");
    let system = "*S-1-5-18:(OI)(CI)F";
    let administrators = "*S-1-5-32-544:(OI)(CI)F";
    let output = crate::vm::run_bounded(
        std::process::Command::new("icacls.exe")
            .arg(path.as_os_str())
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(owner)
            .arg(system)
            .arg(administrators),
        &format!("apply runtime state ACL to {}", path.display()),
    )
    .map_err(|error| journal_report("apply runtime state ACL", error))?;
    if !output.status.success() {
        return Err(journal_report(
            "apply runtime state ACL",
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

fn is_production_state_root(path: &Path) -> Result<bool, Report<HcsError>> {
    if std::env::var_os(STATE_DIR_ENV).is_some() {
        return Ok(false);
    }
    let expected = known_program_data()?
        .join("jyth")
        .join("state")
        .join("v1")
        .join("sessions");
    Ok(path == expected)
}

fn current_user_sid() -> Result<String, Report<HcsError>> {
    crate::security::current_user_sid()
}

fn known_program_data() -> Result<PathBuf, Report<HcsError>> {
    let mut path_ptr: *mut u16 = std::ptr::null_mut();
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_PROGRAM_DATA,
            0,
            std::ptr::null_mut(),
            &mut path_ptr,
        )
    };
    if hr != 0 || path_ptr.is_null() {
        return Err(Report::new(HcsError::Journal).attach(format!(
            "SHGetKnownFolderPath(FOLDERID_ProgramData) failed: HRESULT 0x{hr:08X}"
        )));
    }
    // SAFETY: `path_ptr` is the buffer returned by `SHGetKnownFolderPath`;
    // the capped scan bounds the read.
    let length = unsafe { crate::core::wide_strlen(path_ptr) }
        .map_err(|error| journal_report("ProgramData path", error))?;
    let path = OsString::from_wide(unsafe { std::slice::from_raw_parts(path_ptr, length) });
    unsafe {
        CoTaskMemFree(path_ptr as *const std::ffi::c_void);
    }
    Ok(PathBuf::from(path))
}

fn is_reparse_point(path: &Path) -> Result<bool, Report<HcsError>> {
    let wide = crate::core::wide_path(path);
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Ok(false);
    }
    Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time_low: u32,
    creation_time_high: u32,
    last_access_time_low: u32,
    last_access_time_high: u32,
    last_write_time_low: u32,
    last_write_time_high: u32,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[repr(C)]
struct WindowsGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const FOLDERID_PROGRAM_DATA: WindowsGuid = WindowsGuid {
    data1: 0x62AB5D82,
    data2: 0xFDC1,
    data3: 0x4DC3,
    data4: [0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97],
};
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileAttributesW(path: *const u16) -> u32;
    fn GetFileInformationByHandle(
        handle: *mut std::ffi::c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        folder_id: *const WindowsGuid,
        flags: u32,
        token: *mut std::ffi::c_void,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(memory: *const std::ffi::c_void);
}

use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;

#[cfg(test)]
mod tests {
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use std::sync::OnceLock;

    /// Build the standalone `journal-lock-hold` fixture with escargot and
    /// return its executable path. Built once per test process into a
    /// dedicated temp target dir: never the workspace target dir, whose
    /// build lock the outer `cargo test` already holds.
    fn lock_holder_binary() -> PathBuf {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        BINARY
            .get_or_init(|| {
                let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures/journal-lock-hold/Cargo.toml");
                let target_dir = std::env::temp_dir().join("jyth-journal-lock-hold-target");
                escargot::CargoBuild::new()
                    .bin("journal-lock-hold")
                    .manifest_path(&manifest)
                    .target_dir(&target_dir)
                    .run()
                    .expect("build journal lock fixture")
                    .path()
                    .to_path_buf()
            })
            .clone()
    }

    /// A child process holding the redb writer lock of a session journal.
    struct LockedJournalChild {
        child: Child,
    }

    impl LockedJournalChild {
        fn spawn(root: &Path, session_id: Uuid, ready: &Path) -> Self {
            let child = Command::new(lock_holder_binary())
                .arg(root)
                .arg(session_id.to_string())
                .arg(ready)
                .spawn()
                .expect("spawn journal lock child");
            Self { child }
        }

        fn wait_until_ready(&mut self, ready: &Path) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if ready.exists() {
                    return;
                }
                if let Some(status) = self.child.try_wait().expect("poll child") {
                    panic!("journal lock child exited before publishing: {status}");
                }
                assert!(
                    Instant::now() < deadline,
                    "journal lock child did not publish in time"
                );
                thread::sleep(Duration::from_millis(25));
            }
        }

        fn terminate(&mut self) {
            self.child.kill().expect("terminate journal lock child");
            self.child.wait().expect("wait for terminated child");
        }
    }

    impl Drop for LockedJournalChild {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_until<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(value) = probe() {
                return Some(value);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("jyth-{name}-{}", Uuid::now_v7()))
    }

    #[test]
    fn journal_round_trips_versioned_records() {
        let root = test_root("journal-roundtrip");
        let session =
            SessionJournal::create_current(&root, Uuid::now_v7()).expect("create journal");
        let vm_id = Uuid::now_v7();
        let network_id = Uuid::now_v7();
        let endpoint_id = Uuid::now_v7();
        let disk_path = normalize_absolute_path(Path::new(r".\planned\..\disk.vhdx"))
            .expect("normalize disk path");
        session
            .put_vm(&VmResourceRecord {
                schema_version: SCHEMA_VERSION,
                vm_id,
                phase: VmResourcePhase::Planned,
                published: false,
                compute_system: ComputeResource {
                    id: vm_id.to_string(),
                    state: ResourceState::Planned,
                },
                network: Some(NetworkResource {
                    network_name: format!("jyth-nat-{vm_id}"),
                    network_id: Some(network_id.to_string()),
                    endpoint_name: format!("jyth-ep-{vm_id}"),
                    endpoint_id: Some(endpoint_id.to_string()),
                    state: ResourceState::Created,
                }),
                disks: vec![DiskResource {
                    path: disk_path.as_os_str().to_os_string(),
                    controller: 1,
                    lun: 2,
                    state: ResourceState::Created,
                    origin: DiskOrigin::CreatedByLaunch,
                    requested_retention: DiskRetention::Ephemeral,
                    effective_retention: DiskRetention::Ephemeral,
                    file_identity: Some(FileIdentity {
                        volume_serial: 7,
                        file_id: 11,
                    }),
                    initialization_requested: true,
                    initialization_acknowledged: true,
                    vm_ace_added: true,
                    published: false,
                }],
                cleanup_attempts: 0,
                last_error: None,
            })
            .expect("write VM record");
        session
            .update_vm(vm_id, |record| {
                record.phase = VmResourcePhase::Published;
                record.published = true;
            })
            .expect("update VM record");
        let record = session
            .vm(vm_id)
            .expect("read VM record")
            .expect("record exists");
        assert_eq!(record.phase, VmResourcePhase::Published);
        assert!(record.published);
        assert_eq!(session.owner(), format!("jyth/v1/{}", session.session_id()));
        let record = session.vm(vm_id).expect("read published record").unwrap();
        let network = record.network.expect("network identity");
        assert_eq!(
            network.network_id.as_deref(),
            Some(network_id.to_string().as_str())
        );
        assert_eq!(
            network.endpoint_id.as_deref(),
            Some(endpoint_id.to_string().as_str())
        );
        assert_eq!(record.disks[0].controller, 1);
        assert_eq!(record.disks[0].lun, 2);
        assert_eq!(record.disks[0].file_identity.as_ref().unwrap().file_id, 11);
        drop(session);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn runtime_journal_is_dedicated_and_shared_by_vm_records() {
        const IMAGE_SENTINEL: TableDefinition<&str, &[u8]> = TableDefinition::new("image_sentinel");

        let root = test_root("journal-topology");
        fs::create_dir_all(&root).expect("create test root");
        let image_root = root.join("image-cache");
        fs::create_dir_all(&image_root).expect("create image root");
        let image_index_path = image_root.join("index.redb");
        let image_marker = b"image-index-marker";

        let image_database = Database::create(&image_index_path).expect("create image index");
        let mut image_write = image_database.begin_write().expect("begin image write");
        image_write
            .set_durability(Durability::Immediate)
            .expect("set image durability");
        let mut image_table = image_write
            .open_table(IMAGE_SENTINEL)
            .expect("open image table");
        image_table
            .insert("marker", image_marker.as_slice())
            .expect("write image marker");
        drop(image_table);
        image_write.commit().expect("commit image marker");
        drop(image_database);

        let session_root = root.join("sessions");
        let session =
            SessionJournal::create_current(&session_root, Uuid::now_v7()).expect("create session");
        let shared_session = session.clone();
        let first_vm = Uuid::now_v7();
        let second_vm = Uuid::now_v7();
        for (index, vm_id) in [first_vm, second_vm].into_iter().enumerate() {
            let journal = if index == 0 {
                &session
            } else {
                &shared_session
            };
            journal
                .put_vm(&VmResourceRecord {
                    schema_version: SCHEMA_VERSION,
                    vm_id,
                    phase: VmResourcePhase::Planned,
                    published: false,
                    compute_system: ComputeResource {
                        id: vm_id.to_string(),
                        state: ResourceState::Planned,
                    },
                    network: None,
                    disks: Vec::new(),
                    cleanup_attempts: 0,
                    last_error: None,
                })
                .expect("write VM record");
        }

        let session_paths = session_paths(&session_root).expect("enumerate session databases");
        assert_eq!(
            session_paths.len(),
            1,
            "one session file stores all VM records"
        );
        assert_eq!(session.all_vms().expect("read VM records").len(), 2);
        drop(shared_session);
        drop(session);

        let image_database = Database::create(&image_index_path).expect("reopen image index");
        let image_read = image_database.begin_read().expect("begin image read");
        let image_table = image_read
            .open_table(IMAGE_SENTINEL)
            .expect("open image table after journal use");
        let marker = image_table
            .get("marker")
            .expect("read image marker")
            .expect("image marker exists");
        assert_eq!(marker.value(), image_marker);
        drop(marker);
        drop(image_table);
        drop(image_read);
        drop(image_database);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn second_writer_is_treated_as_a_live_session() {
        let root = test_root("journal-lock");
        let session_id = Uuid::now_v7();
        let session = SessionJournal::create_current(&root, session_id).expect("create journal");
        let path = session_path(&root, session_id);
        assert!(
            SessionJournal::try_open_existing(&path)
                .expect("probe journal")
                .is_none()
        );
        drop(session);
        let reopened = SessionJournal::try_open_existing(&path)
            .expect("reopen journal")
            .expect("journal should be unlocked");
        drop(reopened);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn recovery_probe_does_not_create_a_missing_session_database() {
        let root = test_root("journal-missing");
        fs::create_dir_all(&root).expect("create test root");
        let path = session_path(&root, Uuid::now_v7());

        let result = SessionJournal::try_open_existing(&path);

        assert!(result.is_err(), "a missing session must not be recoverable");
        assert!(
            !path.exists(),
            "probing a stale session must never create a new database"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn schema_less_database_fails_closed_without_journal_initialization() {
        let root = test_root("journal-no-schema");
        fs::create_dir_all(&root).expect("create test root");
        let path = session_path(&root, Uuid::now_v7());
        let database = Database::create(&path).expect("create database");
        drop(database);

        let result = SessionJournal::try_open_existing(&path);

        assert!(result.is_err(), "a schema-less database must fail closed");
        let database = Database::open(&path).expect("reopen database");
        let tx = database.begin_read().expect("begin database read");
        assert!(
            tx.open_table(SCHEMA).is_err(),
            "a rejected database must not receive the journal schema table"
        );
        assert!(
            tx.open_table(SESSION).is_err(),
            "a rejected database must not receive the session table"
        );
        assert!(
            tx.open_table(VM_RECORDS).is_err(),
            "a rejected database must not receive the VM records table"
        );
        drop(tx);
        drop(database);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn writer_lock_is_exclusive_across_processes_and_released_after_termination() {
        let root = test_root("journal-process-lock");
        fs::create_dir_all(&root).expect("create test root");
        let session_id = Uuid::now_v7();
        let path = session_path(&root, session_id);
        let ready = root.join("ready");

        // A foreign process creates the journal through the public API and
        // then holds the redb writer lock on the file until terminated.
        let mut child = LockedJournalChild::spawn(&root, session_id, &ready);
        child.wait_until_ready(&ready);

        assert!(
            SessionJournal::try_open_existing(&path)
                .expect("probe child journal")
                .is_none(),
            "a live process must retain the redb writer lock"
        );

        child.terminate();

        let reopened = wait_until(Duration::from_secs(10), || {
            SessionJournal::try_open_existing(&path)
                .expect("reopen child journal after termination")
        })
        .expect("redb writer lock was not released after termination");
        drop(reopened);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn probe_reports_locked_while_held_and_recoverable_after_release() {
        let root = test_root("journal-probe-held");
        fs::create_dir_all(&root).expect("create test root");
        let session_id = Uuid::now_v7();
        let path = session_path(&root, session_id);

        let session = SessionJournal::create_current(&root, session_id).expect("create journal");
        assert_eq!(
            probe_session_lock(&path).expect("probe held journal"),
            SessionLockState::Locked,
            "redb's registry reports the in-process database as already open"
        );

        drop(session);
        assert_eq!(
            probe_session_lock(&path).expect("probe released journal"),
            SessionLockState::Recoverable,
            "dropping the journal releases the writer lock"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn probe_reports_lock_across_processes_and_after_termination() {
        let root = test_root("journal-probe-process");
        fs::create_dir_all(&root).expect("create test root");
        let session_id = Uuid::now_v7();
        let path = session_path(&root, session_id);
        let ready = root.join("ready");

        // A foreign process creates the journal through the public API and
        // then holds the redb writer lock on the file until terminated.
        let mut child = LockedJournalChild::spawn(&root, session_id, &ready);
        child.wait_until_ready(&ready);

        assert_eq!(
            probe_session_lock(&path).expect("probe child journal"),
            SessionLockState::Locked,
            "a live process must retain the redb writer lock"
        );

        child.terminate();

        let state = wait_until(Duration::from_secs(10), || {
            Some(probe_session_lock(&path).expect("probe child journal after termination"))
        })
        .expect("redb writer lock was not released after termination");
        assert_eq!(
            state,
            SessionLockState::Recoverable,
            "the released journal must be probed as recoverable"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn file_identity_changes_when_a_path_is_replaced() {
        let root = test_root("journal-identity");
        fs::create_dir_all(&root).expect("create test root");
        let path = root.join("disk.vhdx");
        let replacement = root.join("replacement.vhdx");
        fs::write(&path, b"first").expect("write first file");
        fs::write(&replacement, b"second").expect("write replacement file");
        let first = file_identity(&path).expect("first identity");
        let replacement_identity = file_identity(&replacement).expect("replacement identity");
        fs::remove_file(&path).expect("remove first file");
        fs::rename(&replacement, &path).expect("replace file");
        let second = file_identity(&path).expect("second identity");
        assert_ne!(first, replacement_identity);
        assert_eq!(second, replacement_identity);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn disk_intent_path_is_absolute_and_lexically_normalized() {
        let path = normalize_absolute_path(Path::new(r".\scratch\..\disk.vhdx"))
            .expect("normalize disk intent path");
        assert!(path.is_absolute());
        assert_eq!(path.file_name().and_then(OsStr::to_str), Some("disk.vhdx"));
        assert!(!path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }));
    }

    #[test]
    fn lexical_normalization_stops_at_the_root_and_rejects_escape() {
        // A plain absolute path normalizes to itself.
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\x.vhdx")).expect("plain path"),
            PathBuf::from(r"C:\disks\x.vhdx")
        );
        // `..` pops only real components, never the root.
        assert_eq!(
            normalize_lexically(Path::new(r"C:\disks\..\x.vhdx")).expect("pop below root"),
            PathBuf::from(r"C:\x.vhdx")
        );
        assert!(
            normalize_lexically(Path::new(r"C:\disks\..\..\..\x.vhdx")).is_err(),
            "over-root pop must be rejected, never drive-relative"
        );
        // UNC roots are preserved and protected the same way.
        assert_eq!(
            normalize_lexically(Path::new(r"\\server\share\disks\..\x.vhdx"))
                .expect("UNC normalization"),
            PathBuf::from(r"\\server\share\x.vhdx")
        );
        assert!(normalize_lexically(Path::new(r"\\server\share\..\..\x.vhdx")).is_err());
        // Relative inputs are rejected by the shared normalizer (the
        // journal wrapper absolutizes them first).
        let relative = normalize_lexically(Path::new(r"..\x.vhdx"))
            .expect_err("relative input must be rejected");
        assert_eq!(relative.current_context(), &HcsError::DiskInvalidPath);
        let attachment = relative
            .frames()
            .filter_map(|frame| match frame.kind() {
                error_stack::FrameKind::Attachment(error_stack::AttachmentKind::Printable(
                    value,
                )) => Some(value.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            attachment.contains("must be absolute"),
            "the rejection must be clear: {attachment}"
        );
    }

    #[test]
    fn journal_disk_path_round_trips_surrogate_units() {
        // The faithful wide form survives a journal encode/decode cycle:
        // 0xD800 is an unpaired surrogate that a lossy round trip would
        // replace with U+FFFD.
        let units = [
            b'C'.into(),
            0x3A,
            0x5C,
            0xD800,
            0x5C,
            b'x'.into(),
            b'.'.into(),
            b'v'.into(),
            b'h'.into(),
            b'd'.into(),
            b'x'.into(),
        ];
        let path = OsString::from_wide(&units);
        let record = VmResourceRecord {
            schema_version: SCHEMA_VERSION,
            vm_id: Uuid::now_v7(),
            phase: VmResourcePhase::Planned,
            published: false,
            compute_system: ComputeResource {
                id: Uuid::now_v7().to_string(),
                state: ResourceState::Planned,
            },
            network: None,
            disks: vec![DiskResource {
                path: path.clone(),
                controller: 0,
                lun: 0,
                state: ResourceState::Planned,
                origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
                requested_retention: vm_model::disk::DiskRetention::Ephemeral,
                effective_retention: vm_model::disk::DiskRetention::Ephemeral,
                file_identity: None,
                initialization_requested: false,
                initialization_acknowledged: false,
                vm_ace_added: false,
                published: false,
            }],
            cleanup_attempts: 0,
            last_error: None,
        };
        let encoded = serde_json::to_vec(&record).expect("encode record");
        let decoded: VmResourceRecord = serde_json::from_slice(&encoded).expect("decode record");
        assert_eq!(decoded.disks[0].path, path);

        // Legacy string-form records (written by pre-hardening sessions)
        // still decode.
        let legacy = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "vm_id": Uuid::now_v7(),
            "phase": "Planned",
            "published": false,
            "compute_system": { "id": "id", "state": "Planned" },
            "network": null,
            "disks": [{
                "path": r"C:\disks\legacy.vhdx",
                "controller": 0,
                "lun": 0,
                "state": "Planned",
                "origin": "CreatedByLaunch",
                "requested_retention": "Ephemeral",
                "effective_retention": "Ephemeral",
                "file_identity": null,
                "initialization_requested": false,
                "initialization_acknowledged": false,
                "vm_ace_added": false,
                "published": false
            }],
            "cleanup_attempts": 0,
            "last_error": null
        });
        let legacy_record: VmResourceRecord =
            serde_json::from_value(legacy).expect("legacy record decodes");
        assert_eq!(
            legacy_record.disks[0].path,
            OsString::from(r"C:\disks\legacy.vhdx")
        );
    }

    #[test]
    fn unknown_journal_schema_fails_closed() {
        let root = test_root("journal-schema");
        fs::create_dir_all(&root).expect("create test root");
        let path = root.join("unknown.redb");
        let database = Database::create(&path).expect("create database");
        let mut tx = database.begin_write().expect("begin schema write");
        tx.set_durability(Durability::Immediate)
            .expect("set schema durability");
        let mut schema = tx.open_table(SCHEMA).expect("open schema table");
        schema
            .insert("version", &99)
            .expect("write unknown version");
        drop(schema);
        tx.commit().expect("commit unknown version");
        drop(database);

        let result = SessionJournal::try_open_existing(&path);
        assert!(result.is_err(), "unknown journal schema must fail closed");
        let error = result.err().expect("schema error").to_string();
        assert!(error.contains("unsupported") || error.contains("schema"));
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn abandoned_inventory_round_trips_and_preserves_first_timestamp() {
        let root = test_root("journal-abandoned");
        let session =
            SessionJournal::create_current(&root, Uuid::now_v7()).expect("create journal");
        let vm_id = Uuid::now_v7();
        assert!(!session.has_abandoned().expect("empty inventory query"));
        let entry = || AbandonedResourceEntry {
            kind: "disk".to_owned(),
            identity: r"C:\disks\leaked.vhdx".to_owned(),
            last_error: "resource_kind=disk operation=remove cause=access is denied".to_owned(),
            first_abandoned_at_unix_ms: 1000,
        };
        session
            .put_abandoned(&AbandonedRecord {
                schema_version: SCHEMA_VERSION,
                vm_id,
                entries: vec![entry()],
            })
            .expect("write abandoned record");
        assert!(session.has_abandoned().expect("inventory query"));
        let read = session
            .abandoned(vm_id)
            .expect("read abandoned record")
            .expect("abandoned record exists");
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.entries[0].identity, r"C:\disks\leaked.vhdx");
        assert_eq!(read.entries[0].first_abandoned_at_unix_ms, 1000);

        // Re-abandoning the same resource refreshes only the last error.
        session
            .put_abandoned(&AbandonedRecord {
                schema_version: SCHEMA_VERSION,
                vm_id,
                entries: vec![AbandonedResourceEntry {
                    first_abandoned_at_unix_ms: 9999,
                    ..entry()
                }],
            })
            .expect("re-abandon");
        let read = session
            .abandoned(vm_id)
            .expect("read re-abandoned record")
            .expect("record exists");
        assert_eq!(read.entries.len(), 1, "no duplicate entry");
        assert_eq!(
            read.entries[0].first_abandoned_at_unix_ms, 1000,
            "first-abandoned timestamp is preserved"
        );

        session
            .remove_abandoned(vm_id)
            .expect("remove abandoned record");
        assert!(
            session
                .abandoned(vm_id)
                .expect("read after removal")
                .is_none()
        );
        assert!(!session.has_abandoned().expect("empty inventory query"));
        drop(session);
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn abandoned_resources_count_as_terminal_for_gc() {
        let vm_id = Uuid::now_v7();
        let base = VmResourceRecord {
            schema_version: SCHEMA_VERSION,
            vm_id,
            phase: VmResourcePhase::CleanupPending,
            published: false,
            compute_system: ComputeResource {
                id: vm_id.to_string(),
                state: ResourceState::Abandoned,
            },
            network: None,
            disks: Vec::new(),
            cleanup_attempts: 3,
            last_error: Some(
                "resource_kind=compute_system resource_id=... cause=denied".to_owned(),
            ),
        };
        assert!(base.is_complete(), "Abandoned is terminal for GC");

        let mixed = VmResourceRecord {
            disks: vec![DiskResource {
                path: OsString::from(r"C:\disks\disk.vhdx"),
                controller: 0,
                lun: 0,
                state: ResourceState::Removed,
                origin: vm_model::disk::DiskOrigin::CreatedByLaunch,
                requested_retention: vm_model::disk::DiskRetention::Ephemeral,
                effective_retention: vm_model::disk::DiskRetention::Ephemeral,
                file_identity: None,
                initialization_requested: false,
                initialization_acknowledged: false,
                vm_ace_added: false,
                published: false,
            }],
            ..base.clone()
        };
        assert!(mixed.is_complete());

        let still_failing = VmResourceRecord {
            compute_system: ComputeResource {
                id: vm_id.to_string(),
                state: ResourceState::RemovalFailed,
            },
            ..base
        };
        assert!(
            !still_failing.is_complete(),
            "RemovalFailed is not terminal"
        );
    }

    #[test]
    fn abandoned_inventory_scan_is_read_only_and_skips_live_sessions() {
        let root = test_root("journal-abandoned-scan");
        fs::create_dir_all(&root).expect("create test root");
        let stale_id = Uuid::now_v7();
        let live_id = Uuid::now_v7();
        let abandoned_vm = Uuid::now_v7();
        {
            let stale =
                SessionJournal::create_current(&root, stale_id).expect("create stale session");
            stale
                .put_abandoned(&AbandonedRecord {
                    schema_version: SCHEMA_VERSION,
                    vm_id: abandoned_vm,
                    entries: vec![AbandonedResourceEntry {
                        kind: "disk".to_owned(),
                        identity: r"C:\disks\leaked.vhdx".to_owned(),
                        last_error: "resource_kind=disk operation=remove cause=denied".to_owned(),
                        first_abandoned_at_unix_ms: 1,
                    }],
                })
                .expect("write abandoned record");
        }
        let live = SessionJournal::create_current(&root, live_id).expect("create live session");

        let records = abandoned_inventory(&root).expect("scan abandoned inventory");
        assert_eq!(records.len(), 1, "live sessions are skipped");
        assert_eq!(records[0].vm_id, abandoned_vm);
        assert_eq!(records[0].entries[0].identity, r"C:\disks\leaked.vhdx");
        drop(live);
        fs::remove_dir_all(root).expect("remove test root");
    }
}
