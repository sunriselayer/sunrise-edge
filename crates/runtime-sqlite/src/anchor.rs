//! Independent local-OS rollback anchor. This is deployment metadata, never a
//! protocol checkpoint, signature, quorum certificate, or portable import token.

mod snapshot;
pub use snapshot::{ConfiguredCheckpointAuthority, LocalSnapshotLimits, LocalStoreCheckpoint};

use crate::{native_connection::NativeConnection, native_files};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime_sql_durable::schema::{SQL_ANCHORED_SCHEMA_IDENTITY, SQL_DURABLE_SCHEMA_IDENTITY};
use rusqlite::{Connection, TransactionBehavior, params, types::ValueRef};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

const APPLICATION_ID: i64 = 0x5345_414E;
const VERSION: i64 = 1;
const MAX_OBSERVATIONS: u64 = 65_536;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_BLOB: u64 = 16 * 1024 * 1024;

// Closed typed column sets and primary-key order. Physical pages, WAL, mtime,
// indices, query plans and sqlite_schema text never enter a root.
const TABLES: &[(&str, &str)] = &[
    (
        "durable_metadata",
        "SELECT id,schema_identity,chain_id,validator_id,domain,writer_fence,mutation_sequence,source_instance_id,namespace_origin,import_binding FROM durable_metadata ORDER BY id",
    ),
    (
        "durable_import_progress",
        "SELECT id,phase,progress FROM durable_import_progress ORDER BY id",
    ),
    (
        "durable_outgoing_barrier",
        "SELECT id,barrier FROM durable_outgoing_barrier ORDER BY id",
    ),
    (
        "durable_successor_serving",
        "SELECT id,serving FROM durable_successor_serving ORDER BY id",
    ),
    (
        "durable_state",
        "SELECT key,revision,value FROM durable_state ORDER BY key",
    ),
    (
        "durable_conditional_readiness",
        "SELECT slot,status,record FROM durable_conditional_readiness ORDER BY slot",
    ),
    (
        "durable_object_heads",
        "SELECT object_id,status,head_revision,object_version,digest_algorithm,digest_bytes,owner_projection,routing_projection FROM durable_object_heads ORDER BY object_id",
    ),
    (
        "durable_object_versions",
        "SELECT object_id,object_version,digest_algorithm,digest_bytes,schema_version,type_id,created_chain_id,created_protocol_version,created_checkpoint,inline_canonical_bytes,blob_digest_algorithm,blob_digest_bytes FROM durable_object_versions ORDER BY object_id,object_version",
    ),
    (
        "durable_receipts",
        "SELECT request_id,event_digest_algorithm,event_digest_bytes,canonical_bytes FROM durable_receipts ORDER BY request_id",
    ),
    (
        "durable_outbox_messages",
        "SELECT request_id,message_index,payload_digest_algorithm,payload_digest_bytes,canonical_payload FROM durable_outbox_messages ORDER BY request_id,message_index",
    ),
    (
        "durable_outbox_delivery",
        "SELECT request_id,message_count,next_message_index,completed,available_at_unix_millis,active_lease_id,lease_expires_at_unix_millis,attempt_count FROM durable_outbox_delivery ORDER BY request_id",
    ),
    (
        "durable_outbox_attempts",
        "SELECT lease_id,request_id,message_index,lease_expires_at_unix_millis,status FROM durable_outbox_attempts ORDER BY lease_id",
    ),
];

/// Opaque failure: no missing, pending or mismatched authority is recreated.
#[derive(Debug)]
pub struct IndependentAnchorError;
impl fmt::Display for IndependentAnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("independent local anchor refused; preserve files and stop all writers")
    }
}
impl Error for IndependentAnchorError {}
impl From<rusqlite::Error> for IndependentAnchorError {
    fn from(_: rusqlite::Error) -> Self {
        Self
    }
}
impl From<io::Error> for IndependentAnchorError {
    fn from(_: io::Error) -> Self {
        Self
    }
}
impl From<crate::native_connection::NativeError> for IndependentAnchorError {
    fn from(_: crate::native_connection::NativeError) -> Self {
        Self
    }
}

/// A local publication of one acknowledged storage state. Its authority is
/// the independent pinned anchor owner; it is not a network state commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorCheckpoint {
    /// Monotonic local acknowledgement sequence, encoded as unsigned BE in SQL.
    pub sequence: u64,
    /// Complete typed logical rows, including local safety and delivery state.
    pub state_root: [u8; 32],
    /// Closed immutable body inventory retained at this acknowledgement.
    pub body_manifest_root: [u8; 32],
}

#[derive(Clone, Debug)]
struct Body {
    algorithm: i64,
    digest: [u8; 32],
    length: u64,
    content_hash: [u8; 32],
}

struct Budget {
    observations: u64,
    bytes: u64,
    deadline: Option<u64>,
}
impl Budget {
    fn new(deadline: Option<u64>) -> Self {
        Self {
            observations: 0,
            bytes: 0,
            deadline,
        }
    }
    fn charge(&mut self, bytes: usize) -> Result<(), IndependentAnchorError> {
        self.observations = self
            .observations
            .checked_add(1)
            .ok_or(IndependentAnchorError)?;
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes).map_err(|_| IndependentAnchorError)?)
            .ok_or(IndependentAnchorError)?;
        if self.observations > MAX_OBSERVATIONS || self.bytes > MAX_BYTES {
            return Err(IndependentAnchorError);
        }
        if let Some(deadline) = self.deadline {
            let now: u128 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| IndependentAnchorError)?
                .as_millis();
            if now >= u128::from(deadline) {
                return Err(IndependentAnchorError);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn physical_identity(metadata: &std::fs::Metadata) -> Result<(u64, u64), IndependentAnchorError> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), metadata.ino()))
}
#[cfg(not(unix))]
fn physical_identity(_: &std::fs::Metadata) -> Result<(u64, u64), IndependentAnchorError> {
    Err(IndependentAnchorError)
}

fn field(hash: &mut Sha256, tag: u8, bytes: &[u8]) {
    hash.update([tag]);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn state_root(
    connection: &Connection,
    budget: &mut Budget,
) -> Result<[u8; 32], IndependentAnchorError> {
    let mut hash: Sha256 = Sha256::new();
    hash.update(b"SE-LOCAL-ANCHORED-ROWS\0\x01");
    for (name, sql) in TABLES {
        field(&mut hash, 1, name.as_bytes());
        let mut statement = connection.prepare(sql)?;
        let columns: usize = statement.column_count();
        let mut rows = statement.query([])?;
        let mut count: u64 = 0;
        while let Some(row) = rows.next()? {
            budget.charge(0)?;
            count = count.checked_add(1).ok_or(IndependentAnchorError)?;
            hash.update([2]);
            hash.update((columns as u64).to_be_bytes());
            for index in 0..columns {
                match row.get_ref(index)? {
                    ValueRef::Null => field(&mut hash, 0, &[]),
                    ValueRef::Integer(value) => {
                        budget.charge(8)?;
                        field(&mut hash, 1, &value.to_be_bytes());
                    }
                    ValueRef::Text(bytes) => {
                        budget.charge(bytes.len())?;
                        field(&mut hash, 2, bytes);
                    }
                    ValueRef::Blob(bytes) => {
                        budget.charge(bytes.len())?;
                        field(&mut hash, 3, bytes);
                    }
                    ValueRef::Real(_) => return Err(IndependentAnchorError),
                }
            }
        }
        hash.update([3]);
        hash.update(count.to_be_bytes());
    }
    Ok(hash.finalize().into())
}

fn body_at(
    connection: &Connection,
    algorithm: i64,
    digest: [u8; 32],
    budget: &mut Budget,
) -> Result<Body, IndependentAnchorError> {
    // One statement both bounds and borrows the exact content. Never allocate
    // a Vec using a length from an earlier independently mutable observation.
    connection.query_row(
        "SELECT CASE WHEN typeof(content)='blob' AND length(content)<=16777216 THEN content ELSE NULL END FROM blobs WHERE digest_algorithm=?1 AND digest_bytes=?2",
        params![algorithm,digest.as_slice()],
        |row| {
            let bytes: &[u8] = row.get_ref(0)?.as_blob()?;
            let length: u64 = u64::try_from(bytes.len()).map_err(|_| rusqlite::Error::InvalidQuery)?;
            if length > MAX_BLOB { return Err(rusqlite::Error::InvalidQuery); }
            budget.charge(bytes.len()).map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(Body { algorithm,digest,length,content_hash:Sha256::digest(bytes).into() })
        },
    ).map_err(IndependentAnchorError::from)
}

fn all_bodies(
    connection: &Connection,
    budget: &mut Budget,
) -> Result<Vec<Body>, IndependentAnchorError> {
    let mut statement = connection.prepare(
        "SELECT digest_algorithm,digest_bytes FROM blobs ORDER BY digest_algorithm,digest_bytes",
    )?;
    let mut rows = statement.query([])?;
    let mut bodies: Vec<Body> = Vec::new();
    while let Some(row) = rows.next()? {
        budget.charge(40)?;
        let algorithm: i64 = row.get(0)?;
        let digest: [u8; 32] = fixed(row, 1)?;
        bodies.push(body_at(connection, algorithm, digest, budget)?);
    }
    Ok(bodies)
}

fn manifest_root(bodies: &[Body]) -> [u8; 32] {
    let mut hash: Sha256 = Sha256::new();
    hash.update(b"SE-LOCAL-IMMUTABLE-BODIES\0\x01");
    hash.update((bodies.len() as u64).to_be_bytes());
    for body in bodies {
        hash.update(body.algorithm.to_be_bytes());
        hash.update(body.digest);
        hash.update(body.length.to_be_bytes());
        hash.update(body.content_hash);
    }
    hash.finalize().into()
}

fn fixed<const N: usize>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    match row.get_ref(index)? {
        ValueRef::Blob(bytes) if bytes.len() == N => {
            bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn bodies_in(
    connection: &Connection,
    pending: bool,
    budget: &mut Budget,
) -> Result<Vec<Body>, IndependentAnchorError> {
    let mut statement = connection.prepare("SELECT algorithm,digest,length,content_hash FROM anchor_bodies WHERE pending=?1 ORDER BY algorithm,digest")?;
    let mut rows = statement.query([i64::from(pending)])?;
    let mut bodies: Vec<Body> = Vec::new();
    while let Some(row) = rows.next()? {
        budget.charge(80)?;
        let digest: [u8; 32] = fixed(row, 1)?;
        let length: [u8; 8] = fixed(row, 2)?;
        let content_hash: [u8; 32] = fixed(row, 3)?;
        bodies.push(Body {
            algorithm: row.get(0)?,
            digest,
            length: u64::from_be_bytes(length),
            content_hash,
        });
    }
    Ok(bodies)
}

fn verify_bodies(
    blobs: &Connection,
    bodies: &[Body],
    budget: &mut Budget,
) -> Result<(), IndependentAnchorError> {
    for expected in bodies {
        let actual: Body = body_at(blobs, expected.algorithm, expected.digest, budget)?;
        if actual.length != expected.length || actual.content_hash != expected.content_hash {
            return Err(IndependentAnchorError);
        }
    }
    Ok(())
}

fn replace_bodies(
    connection: &Connection,
    pending: bool,
    bodies: &[Body],
) -> Result<(), IndependentAnchorError> {
    connection.execute(
        "DELETE FROM anchor_bodies WHERE pending=?1",
        [i64::from(pending)],
    )?;
    for body in bodies {
        connection.execute("INSERT INTO anchor_bodies(pending,algorithm,digest,length,content_hash) VALUES(?1,?2,?3,?4,?5)", params![i64::from(pending), body.algorithm, body.digest.as_slice(), body.length.to_be_bytes().as_slice(), body.content_hash.as_slice()])?;
    }
    Ok(())
}

fn checkpoint(connection: &Connection) -> Result<AnchorCheckpoint, IndependentAnchorError> {
    let (sequence, state, body): ([u8; 8], [u8; 32], [u8; 32]) = connection.query_row(
        "SELECT sequence,state_root,body_root FROM anchor_head WHERE id=1",
        [],
        |row| Ok((fixed(row, 0)?, fixed(row, 1)?, fixed(row, 2)?)),
    )?;
    Ok(AnchorCheckpoint {
        sequence: u64::from_be_bytes(sequence),
        state_root: state,
        body_manifest_root: body,
    })
}

#[derive(Debug)]
struct AnchorLease {
    file: File,
    attachment: native_files::ImportFile,
}
impl AnchorLease {
    fn path(anchor: &Path) -> PathBuf {
        let mut path = anchor.as_os_str().to_os_string();
        path.push(".lease");
        PathBuf::from(path)
    }
    fn open(anchor: &Path, fresh: bool) -> Result<Self, IndependentAnchorError> {
        let path: PathBuf = Self::path(anchor);
        let mut attachment: native_files::ImportFile = if fresh {
            native_files::create_new(&path)?
        } else {
            native_files::open_existing(&path)?
        };
        // Only the separate lease inode is opened independently. Never open an
        // extra File descriptor on a SQLite main/WAL/SHM inode.
        let file: File = OpenOptions::new().read(true).write(true).open(&path)?;
        file.try_lock().map_err(|_| IndependentAnchorError)?;
        attachment.check()?;
        if physical_identity(&file.metadata()?)?
            != physical_identity(&std::fs::symlink_metadata(&path)?)?
        {
            return Err(IndependentAnchorError);
        }
        if fresh {
            attachment.sync_parent()?;
        }
        Ok(Self { file, attachment })
    }
    fn check(&self) -> Result<(), IndependentAnchorError> {
        let held: (u64, u64) = physical_identity(&self.file.metadata()?)?;
        let path = std::fs::symlink_metadata(self.attachment.path())?;
        if path.file_type().is_symlink() || !path.is_file() || physical_identity(&path)? != held {
            return Err(IndependentAnchorError);
        }
        // The held parent identities are checked by the containing SQLite
        // anchor owner, whose parent is the identical protected directory.
        Ok(())
    }
}

/// Test-only rendezvous at actual authority COMMIT, never an error injection.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnchorCommitPhase {
    Prepare,
    Finalize,
}

#[cfg(test)]
struct AnchorCommitHook {
    phase: AnchorCommitPhase,
    action: Box<dyn FnOnce() + Send>,
}

#[cfg(test)]
#[derive(Default)]
struct AnchorTestControl {
    hook: Mutex<Option<AnchorCommitHook>>,
    error: Mutex<Option<(AnchorCommitPhase, i32)>>,
}
#[cfg(test)]
impl fmt::Debug for AnchorTestControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnchorTestControl")
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
impl AnchorTestControl {
    fn boundary(&self, phase: AnchorCommitPhase) {
        let mut slot = self.hook.lock().unwrap();
        let hook: Option<AnchorCommitHook> =
            if slot.as_ref().is_some_and(|hook| hook.phase == phase) {
                slot.take()
            } else {
                None
            };
        drop(slot);
        if let Some(hook) = hook {
            (hook.action)();
        }
    }
    fn observe(&self, phase: AnchorCommitPhase, result: &rusqlite::Result<()>) {
        if let Err(rusqlite::Error::SqliteFailure(failure, _)) = result {
            *self.error.lock().unwrap() = Some((phase, failure.extended_code));
        }
    }
}

/// One lifetime OS lock and independently held database. Lock order is anchor
/// mutex, then state connection; the body inspection connection is read-only.
/// Blob puts never acquire either of these locks and cannot replace content.
#[derive(Debug)]
pub(crate) struct IndependentAnchor {
    owner: Mutex<NativeConnection>,
    lease: AnchorLease,
    blob_path: Option<PathBuf>,
    #[cfg(test)]
    test: AnchorTestControl,
}

pub(crate) struct AnchorGuard<'a> {
    owner: MutexGuard<'a, NativeConnection>,
    lease: &'a AnchorLease,
    blobs: NativeConnection,
    budget: Budget,
    #[cfg(test)]
    test: &'a AnchorTestControl,
}

fn require_separate(
    anchor: &Path,
    state: &Path,
    blobs: &Path,
) -> Result<(), IndependentAnchorError> {
    let anchor_parent: PathBuf =
        std::fs::canonicalize(anchor.parent().ok_or(IndependentAnchorError)?)?;
    for input in [state, blobs] {
        let parent: PathBuf = std::fs::canonicalize(input.parent().ok_or(IndependentAnchorError)?)?;
        if anchor_parent.starts_with(&parent) || parent.starts_with(&anchor_parent) {
            return Err(IndependentAnchorError);
        }
    }
    Ok(())
}

impl IndependentAnchor {
    pub(crate) fn open(
        anchor: &Path,
        state: &Path,
        blob_path: &Path,
    ) -> Result<Arc<Self>, IndependentAnchorError> {
        require_separate(anchor, state, blob_path)?;
        drop(crate::SqliteBlobStore::open_existing(blob_path).map_err(|_| IndependentAnchorError)?);
        Self::open_configured(anchor, Some(blob_path.to_path_buf()))
    }

    fn open_configured(
        anchor: &Path,
        blob_path: Option<PathBuf>,
    ) -> Result<Arc<Self>, IndependentAnchorError> {
        let lease: AnchorLease = AnchorLease::open(anchor, false)?;
        let mut owner: NativeConnection = NativeConnection::open_existing(anchor, true)?;
        owner.identity.check()?;
        let actual = std::fs::symlink_metadata(anchor)?;
        let (application, version): (i64, i64) = (
            owner
                .sqlite
                .pragma_query_value(None, "application_id", |row| row.get(0))?,
            owner
                .sqlite
                .pragma_query_value(None, "user_version", |row| row.get(0))?,
        );
        if application != APPLICATION_ID || version != VERSION {
            return Err(IndependentAnchorError);
        }
        let (device, inode, lease_device, lease_inode): ([u8; 8], [u8; 8], [u8; 8], [u8; 8]) =
            owner.sqlite.query_row(
                "SELECT device,inode,lease_device,lease_inode FROM anchor_head WHERE id=1",
                [],
                |row| {
                    Ok((
                        fixed(row, 0)?,
                        fixed(row, 1)?,
                        fixed(row, 2)?,
                        fixed(row, 3)?,
                    ))
                },
            )?;
        let (actual_device, actual_inode): (u64, u64) = physical_identity(&actual)?;
        if device != actual_device.to_be_bytes() || inode != actual_inode.to_be_bytes() {
            return Err(IndependentAnchorError);
        }
        let (actual_lease_device, actual_lease_inode): (u64, u64) =
            physical_identity(&lease.file.metadata()?)?;
        if lease_device != actual_lease_device.to_be_bytes()
            || lease_inode != actual_lease_inode.to_be_bytes()
        {
            return Err(IndependentAnchorError);
        }
        lease.check()?;
        Ok(Arc::new(Self {
            owner: Mutex::new(owner),
            lease,
            blob_path,
            #[cfg(test)]
            test: AnchorTestControl::default(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn on_commit(
        &self,
        phase: AnchorCommitPhase,
        action: impl FnOnce() + Send + 'static,
    ) {
        *self.test.error.lock().unwrap() = None;
        *self.test.hook.lock().unwrap() = Some(AnchorCommitHook {
            phase,
            action: Box::new(action),
        });
    }

    #[cfg(test)]
    pub(crate) fn observed_commit_error(&self) -> Option<(AnchorCommitPhase, i32)> {
        *self.test.error.lock().unwrap()
    }

    #[cfg(test)]
    pub(crate) fn test_hold_transaction<T>(&self, action: impl FnOnce() -> T) -> T {
        let mut owned = self.owner.lock().unwrap();
        let tx = owned
            .sqlite
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let result: T = action();
        tx.rollback().unwrap();
        result
    }

    pub(crate) fn lock(
        &self,
        deadline: Option<u64>,
    ) -> Result<AnchorGuard<'_>, IndependentAnchorError> {
        // The held lease is never reopened, released, or adopted after a failure.
        self.lease.check()?;
        let mut owner: MutexGuard<'_, NativeConnection> =
            self.owner.lock().map_err(|_| IndependentAnchorError)?;
        owner.identity.check()?;
        let blobs: NativeConnection = NativeConnection::open_existing(
            self.blob_path.as_deref().ok_or(IndependentAnchorError)?,
            false,
        )?;
        Ok(AnchorGuard {
            owner,
            lease: &self.lease,
            blobs,
            budget: Budget::new(deadline),
            #[cfg(test)]
            test: &self.test,
        })
    }
}

impl AnchorGuard<'_> {
    pub(crate) fn checkpoint(&self) -> Result<AnchorCheckpoint, IndependentAnchorError> {
        checkpoint(&self.owner.sqlite)
    }

    pub(crate) fn check(&mut self, state: &Connection) -> Result<(), IndependentAnchorError> {
        self.lease.check()?;
        self.owner.identity.check()?;
        self.blobs.identity.check()?;
        let pending: Option<[u8; 32]> = self.owner.sqlite.query_row(
            "SELECT pending_state_root FROM anchor_head WHERE id=1",
            [],
            |row| match row.get_ref(0)? {
                ValueRef::Null => Ok(None),
                _ => Ok(Some(fixed(row, 0)?)),
            },
        )?;
        let actual: [u8; 32] = state_root(state, &mut self.budget)?;
        if let Some(expected) = pending {
            if expected != actual {
                return Err(IndependentAnchorError);
            }
            let bodies: Vec<Body> = bodies_in(&self.owner.sqlite, true, &mut self.budget)?;
            verify_bodies(&self.blobs.sqlite, &bodies, &mut self.budget)?;
            self.finalize()?;
        }
        let expected: AnchorCheckpoint = checkpoint(&self.owner.sqlite)?;
        if expected.state_root != actual {
            return Err(IndependentAnchorError);
        }
        let bodies: Vec<Body> = bodies_in(&self.owner.sqlite, false, &mut self.budget)?;
        if manifest_root(&bodies) != expected.body_manifest_root {
            return Err(IndependentAnchorError);
        }
        verify_bodies(&self.blobs.sqlite, &bodies, &mut self.budget)?;
        self.lease.check()?;
        self.owner.identity.check()?;
        self.blobs.identity.check()?;
        Ok(())
    }

    pub(crate) fn prepare(&mut self, state: &Connection) -> Result<(), IndependentAnchorError> {
        let root: [u8; 32] = state_root(state, &mut self.budget)?;
        let old: AnchorCheckpoint = checkpoint(&self.owner.sqlite)?;
        // A callback may request COMMIT after a logical no-op. No state
        // acknowledgement is advanced and no indistinguishable Pending is
        // created; existing body staging remains outside the old manifest.
        if root == old.state_root {
            return Ok(());
        }
        let bodies: Vec<Body> = all_bodies(&self.blobs.sqlite, &mut self.budget)?;
        self.blobs.identity.check()?;
        let sequence: u64 = old.sequence.checked_add(1).ok_or(IndependentAnchorError)?;
        let tx = self
            .owner
            .sqlite
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed: usize = tx.execute("UPDATE anchor_head SET pending_state_root=?1,pending_body_root=?2,pending_sequence=?3 WHERE id=1 AND pending_state_root IS NULL", params![root.as_slice(),manifest_root(&bodies).as_slice(),sequence.to_be_bytes().as_slice()])?;
        if changed != 1 {
            return Err(IndependentAnchorError);
        }
        replace_bodies(&tx, true, &bodies)?;
        #[cfg(test)]
        self.test.boundary(AnchorCommitPhase::Prepare);
        let result: rusqlite::Result<()> = tx.commit();
        #[cfg(test)]
        self.test.observe(AnchorCommitPhase::Prepare, &result);
        result?;
        self.lease.check()?;
        self.owner.identity.check()?;
        Ok(())
    }

    pub(crate) fn finalize(&mut self) -> Result<(), IndependentAnchorError> {
        self.lease.check()?;
        self.owner.identity.check()?;
        let tx = self
            .owner
            .sqlite
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed: usize = tx.execute("UPDATE anchor_head SET state_root=pending_state_root,body_root=pending_body_root,sequence=pending_sequence,pending_state_root=NULL,pending_body_root=NULL,pending_sequence=NULL WHERE id=1 AND pending_state_root IS NOT NULL", [])?;
        if changed != 1 {
            return Err(IndependentAnchorError);
        }
        tx.execute("DELETE FROM anchor_bodies WHERE pending=0", [])?;
        tx.execute("UPDATE anchor_bodies SET pending=0 WHERE pending=1", [])?;
        #[cfg(test)]
        self.test.boundary(AnchorCommitPhase::Finalize);
        let result: rusqlite::Result<()> = tx.commit();
        #[cfg(test)]
        self.test.observe(AnchorCommitPhase::Finalize, &result);
        result?;
        self.lease.check()?;
        self.owner.identity.check()?;
        Ok(())
    }
}

/// Explicit one-way stopped-writer enrollment. The caller must already have
/// stopped all legacy writers/signers. This cannot establish historical freshness
/// retroactively. Both inputs must be initialized supported files; the anchor
/// must be new and outside both backup/state directory trees.
#[allow(clippy::too_many_arguments)]
pub fn enroll_independent_anchor(
    state: &Path,
    blobs: &Path,
    anchor: &Path,
    chain: &ChainId,
    validator: ValidatorId,
    domain: AtomicityDomainId,
    expected_initial_state_root: [u8; 32],
    expected_initial_body_manifest_root: [u8; 32],
    confirmed_stopped: bool,
) -> Result<AnchorCheckpoint, IndependentAnchorError> {
    if !confirmed_stopped {
        return Err(IndependentAnchorError);
    }
    require_separate(anchor, state, blobs)?;
    // The ordinary owners validate namespaces and both native schemas first.
    let namespace = crate::SqliteNamespace::new(chain.clone(), validator, domain);
    let source: crate::SqliteDurableStore =
        crate::SqliteDurableStore::open_historical(state, namespace)
            .map_err(|_| IndependentAnchorError)?;
    drop(source);
    let body_owner: crate::SqliteBlobStore =
        crate::SqliteBlobStore::open_existing(blobs).map_err(|_| IndependentAnchorError)?;
    drop(body_owner);
    let mut source: NativeConnection = NativeConnection::open_existing(state, true)?;
    let body_connection: NativeConnection = NativeConnection::open_existing(blobs, false)?;
    let mut budget: Budget = Budget::new(None);
    let transaction = source
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (origin,phase): (i64,Option<i64>) = transaction.query_row(
        "SELECT namespace_origin,(SELECT phase FROM durable_import_progress WHERE id=1) FROM durable_metadata WHERE id=1",[],|row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    if !matches!((origin, phase), (1, None) | (2, Some(2))) {
        return Err(IndependentAnchorError);
    }
    let initial_root: [u8; 32] = state_root(&transaction, &mut budget)?;
    let identity: Vec<u8> = transaction.query_row(
        "SELECT schema_identity FROM durable_metadata WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    if identity != SQL_DURABLE_SCHEMA_IDENTITY {
        return Err(IndependentAnchorError);
    }
    let bodies: Vec<Body> = all_bodies(&body_connection.sqlite, &mut budget)?;
    let body_root: [u8; 32] = manifest_root(&bodies);
    if initial_root != expected_initial_state_root
        || body_root != expected_initial_body_manifest_root
    {
        return Err(IndependentAnchorError);
    }
    let lease: AnchorLease = AnchorLease::open(anchor, true)?;
    let held = native_files::create_new(anchor)?;
    let mut owner: NativeConnection = NativeConnection::open_reserved(held, true, true)?;
    let attachment = std::fs::symlink_metadata(anchor)?;
    let (lease_device, lease_inode): (u64, u64) = physical_identity(&lease.file.metadata()?)?;
    owner
        .sqlite
        .pragma_update(None, "application_id", APPLICATION_ID)?;
    owner.sqlite.pragma_update(None, "user_version", VERSION)?;
    owner.sqlite.execute_batch("CREATE TABLE anchor_head(id INTEGER PRIMARY KEY CHECK(id=1),device BLOB NOT NULL CHECK(length(device)=8),inode BLOB NOT NULL CHECK(length(inode)=8),lease_device BLOB NOT NULL CHECK(length(lease_device)=8),lease_inode BLOB NOT NULL CHECK(length(lease_inode)=8),sequence BLOB NOT NULL CHECK(length(sequence)=8),state_root BLOB NOT NULL CHECK(length(state_root)=32),body_root BLOB NOT NULL CHECK(length(body_root)=32),pending_state_root BLOB NULL CHECK(pending_state_root IS NULL OR length(pending_state_root)=32),pending_body_root BLOB NULL CHECK(pending_body_root IS NULL OR length(pending_body_root)=32),pending_sequence BLOB NULL CHECK(pending_sequence IS NULL OR length(pending_sequence)=8)); CREATE TABLE anchor_bodies(pending INTEGER NOT NULL CHECK(pending IN (0,1)),algorithm INTEGER NOT NULL,digest BLOB NOT NULL CHECK(length(digest)=32),length BLOB NOT NULL CHECK(length(length)=8),content_hash BLOB NOT NULL CHECK(length(content_hash)=32),PRIMARY KEY(pending,algorithm,digest)) WITHOUT ROWID;")?;
    let (device, inode): (u64, u64) = physical_identity(&attachment)?;
    let tx = owner
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("INSERT INTO anchor_head(id,device,inode,lease_device,lease_inode,sequence,state_root,body_root) VALUES(1,?1,?2,?3,?4,?5,?6,?7)",params![device.to_be_bytes().as_slice(),inode.to_be_bytes().as_slice(),lease_device.to_be_bytes().as_slice(),lease_inode.to_be_bytes().as_slice(),0_u64.to_be_bytes().as_slice(),initial_root.as_slice(),body_root.as_slice()])?;
    replace_bodies(&tx, false, &bodies)?;
    tx.commit()?;
    owner.sync_created()?;
    transaction.execute(
        "UPDATE durable_metadata SET schema_identity=?1 WHERE id=1 AND schema_identity=?2",
        params![SQL_ANCHORED_SCHEMA_IDENTITY, SQL_DURABLE_SCHEMA_IDENTITY],
    )?;
    let new_root: [u8; 32] = state_root(&transaction, &mut budget)?;
    let tx = owner
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("UPDATE anchor_head SET pending_state_root=?1,pending_body_root=?2,pending_sequence=?3 WHERE id=1",params![new_root.as_slice(),body_root.as_slice(),1_u64.to_be_bytes().as_slice()])?;
    replace_bodies(&tx, true, &bodies)?;
    tx.commit()?;
    source.identity.check()?;
    transaction.commit()?;
    source.identity.check()?;
    let anchor_owner: IndependentAnchor = IndependentAnchor {
        owner: Mutex::new(owner),
        lease,
        blob_path: Some(blobs.to_path_buf()),
        #[cfg(test)]
        test: AnchorTestControl::default(),
    };
    let mut guard = anchor_owner.lock(None)?;
    guard.check(&source.sqlite)?;
    checkpoint(&guard.owner.sqlite)
}

/// Observes initial inputs for explicit stopped-owner enrollment pins. This is
/// read-only and does not assert that this state is current or exclude writers.
pub fn inspect_independent_anchor_inputs(
    state: &Path,
    blobs: &Path,
    chain: &ChainId,
    validator: ValidatorId,
    domain: AtomicityDomainId,
) -> Result<AnchorCheckpoint, IndependentAnchorError> {
    let namespace = crate::SqliteNamespace::new(chain.clone(), validator, domain);
    drop(
        crate::SqliteDurableStore::open_historical(state, namespace)
            .map_err(|_| IndependentAnchorError)?,
    );
    drop(crate::SqliteBlobStore::open_existing(blobs).map_err(|_| IndependentAnchorError)?);
    // The observation uses read-only connections and one deferred read
    // snapshot. It never takes the write lock, so a live writer is neither
    // blocked nor excluded for the bounded scan.
    let mut source: NativeConnection = NativeConnection::open_existing(state, false)?;
    let body_owner: NativeConnection = NativeConnection::open_existing(blobs, false)?;
    let transaction = source
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut budget: Budget = Budget::new(None);
    let state_root: [u8; 32] = state_root(&transaction, &mut budget)?;
    let bodies: Vec<Body> = all_bodies(&body_owner.sqlite, &mut budget)?;
    let result: AnchorCheckpoint = AnchorCheckpoint {
        sequence: 0,
        state_root,
        body_manifest_root: manifest_root(&bodies),
    };
    transaction.rollback()?;
    source.identity.check()?;
    Ok(result)
}
