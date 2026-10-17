//! Same-layout local snapshots. Neither these bytes nor a local acknowledgement
//! replace protocol history, genesis, successor certificates or quorum trust.
use super::*;
use crate::SqliteNamespace;
use rusqlite::backup::{Backup, StepResult};

/// Bounded native work. The caller also retains its original shared transport
/// budget; every SQLite backup step consults it without resetting its deadline.
#[derive(Clone, Copy, Debug)]
pub struct LocalSnapshotLimits {
    /// Downward-only database bound, at most32MiB per complete file.
    pub max_database_bytes: u64,
    /// Original invocation deadline, never restarted between scan phases.
    pub deadline_unix_millis: Option<u64>,
}
impl LocalSnapshotLimits {
    fn validate(self) -> Result<(), IndependentAnchorError> {
        if self.max_database_bytes == 0 || self.max_database_bytes > 32 * 1024 * 1024 {
            return Err(IndependentAnchorError);
        }
        Ok(())
    }
}

/// Complete selected-store identity and current local acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalStoreCheckpoint {
    /// Independently configured namespace, also verified in actual rows.
    pub namespace: SqliteNamespace,
    /// Original physical-store logical identity; never used to reset authority.
    pub source_instance_id: [u8; 16],
    /// Exact current sequence and complete typed state/body roots.
    pub checkpoint: AnchorCheckpoint,
}

/// Holds the EXISTING configured authority without requiring surviving source
/// volumes. Missing authority and Pending refuse; no enrollment/reset path.
#[derive(Debug)]
pub struct ConfiguredCheckpointAuthority {
    anchor: Arc<IndependentAnchor>,
    namespace: SqliteNamespace,
}
impl ConfiguredCheckpointAuthority {
    /// Opens only an existing independent authority with finite local defaults.
    pub fn open(anchor: &Path, namespace: SqliteNamespace) -> Result<Self, IndependentAnchorError> {
        Self::open_bounded(
            anchor,
            namespace,
            LocalSnapshotLimits {
                max_database_bytes: 32 * 1024 * 1024,
                deadline_unix_millis: None,
            },
            || Ok(()),
        )
    }

    /// Retains the caller's original cooperative budget during authority work.
    pub fn open_bounded(
        anchor: &Path,
        namespace: SqliteNamespace,
        limits: LocalSnapshotLimits,
        mut check_budget: impl FnMut() -> Result<(), IndependentAnchorError>,
    ) -> Result<Self, IndependentAnchorError> {
        limits.validate()?;
        check_budget()?;
        bounded_file(anchor, limits)?;
        let anchor: Arc<IndependentAnchor> = IndependentAnchor::open_configured(anchor, None)?;
        {
            let mut owner = anchor.owner.lock().map_err(|_| IndependentAnchorError)?;
            owner.identity.check()?;
            require_acknowledged(&owner.sqlite)?;
            let mut budget: Budget = Budget::new(limits.deadline_unix_millis);
            let bodies: Vec<Body> = bodies_in(&owner.sqlite, false, &mut budget)?;
            if manifest_root(&bodies) != checkpoint(&owner.sqlite)?.body_manifest_root {
                return Err(IndependentAnchorError);
            }
        }
        check_budget()?;
        Ok(Self { anchor, namespace })
    }

    /// Rechecks a fully authenticated, privately staged pair. No output owner
    /// remains open on success, so callers may hash/attach the closed files.
    pub fn verify_snapshot(
        &self,
        state: &Path,
        blobs: &Path,
        expected: &LocalStoreCheckpoint,
        limits: LocalSnapshotLimits,
        mut check_budget: impl FnMut() -> Result<(), IndependentAnchorError>,
    ) -> Result<(), IndependentAnchorError> {
        limits.validate()?;
        check_budget()?;
        require_separate(self.anchor.lease.attachment.path(), state, blobs)?;
        let mut owner = self
            .anchor
            .owner
            .lock()
            .map_err(|_| IndependentAnchorError)?;
        self.anchor.lease.check()?;
        owner.identity.check()?;
        require_acknowledged(&owner.sqlite)?;
        if self.namespace != expected.namespace || checkpoint(&owner.sqlite)? != expected.checkpoint
        {
            return Err(IndependentAnchorError);
        }
        verify_pair(state, blobs, expected, limits, &mut check_budget)?;
        check_budget()?;
        self.anchor.lease.check()?;
        owner.identity.check()?;
        if checkpoint(&owner.sqlite)? != expected.checkpoint {
            return Err(IndependentAnchorError);
        }
        Ok(())
    }
}

fn require_acknowledged(connection: &Connection) -> Result<(), IndependentAnchorError> {
    let (count, ready): (i64, i64) = connection.query_row(
        "SELECT count(*),coalesce(sum(id=1 AND pending_state_root IS NULL AND pending_body_root IS NULL AND pending_sequence IS NULL),0) FROM anchor_head", [], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    if count != 1 || ready != 1 {
        return Err(IndependentAnchorError);
    }
    Ok(())
}

fn geometry(
    connection: &Connection,
    limits: LocalSnapshotLimits,
) -> Result<(i64, i64), IndependentAnchorError> {
    let size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if !(512..=65536).contains(&size)
        || !(size as u64).is_power_of_two()
        || pages <= 0
        || u64::try_from(pages)
            .ok()
            .and_then(|n| n.checked_mul(size as u64))
            .is_none_or(|n| n > limits.max_database_bytes)
    {
        return Err(IndependentAnchorError);
    }
    Ok((size, pages))
}

// Compare every SQLite schema object, including automatically created indices.
// SQL is compared with the SAME SQLite parser's trusted current DDL output;
// alternate triggers/views/indices and extra tables cannot hide outside roots.
type SchemaRow = [Option<Vec<u8>>; 4];

fn schema_rows(
    connection: &Connection,
    budget: &mut Budget,
) -> Result<Vec<SchemaRow>, IndependentAnchorError> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name")?;
    let mut rows = statement.query([])?;
    let mut result: Vec<SchemaRow> = Vec::new();
    while let Some(row) = rows.next()? {
        if result.len() >= 64 {
            return Err(IndependentAnchorError);
        }
        let mut fields: SchemaRow = [None, None, None, None];
        for (index, field) in fields.iter_mut().enumerate() {
            match row.get_ref(index)? {
                ValueRef::Null => {}
                ValueRef::Text(bytes) if bytes.len() <= 65536 => {
                    budget.charge(bytes.len())?;
                    *field = Some(bytes.to_vec());
                }
                _ => return Err(IndependentAnchorError),
            }
        }
        result.push(fields);
    }
    Ok(result)
}

fn closed_schema(
    connection: &Connection,
    state: bool,
    budget: &mut Budget,
) -> Result<(), IndependentAnchorError> {
    let golden: Connection = Connection::open_in_memory()?;
    let (application, version): (i64, i64) = if state {
        for ddl in runtime_sql_durable::schema::TABLE_STATEMENTS {
            golden.execute_batch(ddl)?;
        }
        (0x5352_4453, 5)
    } else {
        golden.execute_batch(&crate::blob::blob_schema_ddl())?;
        (0x5352_4245, 1)
    };
    let actual_application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let actual_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if actual_application != application
        || actual_version != version
        || schema_rows(connection, budget)? != schema_rows(&golden, budget)?
    {
        return Err(IndependentAnchorError);
    }
    Ok(())
}

fn identity(
    connection: &Connection,
    namespace: &SqliteNamespace,
) -> Result<[u8; 16], IndependentAnchorError> {
    connection.query_row("SELECT schema_identity,chain_id,validator_id,domain,source_instance_id FROM durable_metadata WHERE id=1",[],|row| {
        if row.get_ref(0)?.as_blob()? != SQL_ANCHORED_SCHEMA_IDENTITY
            || row.get_ref(1)?.as_str()? != namespace.chain_id().as_str()
            || row.get_ref(2)?.as_blob()? != namespace.validator_id().as_bytes()
            || row.get_ref(3)?.as_blob()? != namespace.domain().as_bytes()
        { return Err(rusqlite::Error::InvalidQuery); }
        fixed(row,4)
    }).map_err(IndependentAnchorError::from)
}

fn bounded_file(path: &Path, limits: LocalSnapshotLimits) -> Result<(), IndependentAnchorError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > limits.max_database_bytes {
        return Err(IndependentAnchorError);
    }
    Ok(())
}

fn verify_pair(
    state: &Path,
    blobs: &Path,
    expected: &LocalStoreCheckpoint,
    limits: LocalSnapshotLimits,
    check_budget: &mut impl FnMut() -> Result<(), IndependentAnchorError>,
) -> Result<(), IndependentAnchorError> {
    for path in [state, blobs] {
        bounded_file(path, limits)?;
        native_files::require_no_sidecars(path)?;
    }
    let mut state: NativeConnection = NativeConnection::open_existing(state, false)?;
    let mut blobs: NativeConnection = NativeConnection::open_existing(blobs, false)?;
    let state_tx = state
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Deferred)?;
    let body_tx = blobs
        .sqlite
        .transaction_with_behavior(TransactionBehavior::Deferred)?;
    geometry(&state_tx, limits)?;
    geometry(&body_tx, limits)?;
    let mut budget: Budget = Budget::new(limits.deadline_unix_millis);
    closed_schema(&state_tx, true, &mut budget)?;
    closed_schema(&body_tx, false, &mut budget)?;
    check_budget()?;
    if identity(&state_tx, &expected.namespace)? != expected.source_instance_id
        || state_root(&state_tx, &mut budget)? != expected.checkpoint.state_root
        || manifest_root(&all_bodies(&body_tx, &mut budget)?)
            != expected.checkpoint.body_manifest_root
    {
        return Err(IndependentAnchorError);
    }
    // The metadata table is covered by its closed schema but body-root hashing
    // covers only immutable bodies; independently require its known identity.
    let body_identity: bool = body_tx.query_row(
        "SELECT count(*)=1 AND sum(id=1 AND schema_identity=?1)=1 FROM blob_metadata",
        [crate::SQLITE_BLOB_SCHEMA_IDENTITY],
        |row| row.get(0),
    )?;
    if !body_identity {
        return Err(IndependentAnchorError);
    }
    check_budget()?;
    body_tx.rollback()?;
    state_tx.rollback()?;
    state.identity.check()?;
    blobs.identity.check()?;
    Ok(())
}

fn copy_database(
    source: &Connection,
    destination: &Path,
    limits: LocalSnapshotLimits,
    check_budget: &mut impl FnMut() -> Result<(), IndependentAnchorError>,
) -> Result<(), IndependentAnchorError> {
    check_budget()?;
    native_files::validate_fresh(destination)?;
    let (page_size, pages): (i64, i64) = geometry(source, limits)?;
    let mut target: NativeConnection =
        NativeConnection::snapshot_destination(destination, page_size)?;
    {
        let backup: Backup<'_, '_> = Backup::new(source, &mut target.sqlite)?;
        let maximum_steps: i64 = pages.checked_add(63).ok_or(IndependentAnchorError)? / 64 + 1;
        let mut done: bool = false;
        for _ in 0..maximum_steps {
            check_budget()?;
            let result: StepResult = backup.step(64)?;
            let progress = backup.progress();
            if i64::from(progress.pagecount) > pages || progress.remaining < 0 {
                return Err(IndependentAnchorError);
            }
            match result {
                StepResult::Done => {
                    done = true;
                    break;
                }
                StepResult::More => {}
                _ => return Err(IndependentAnchorError),
            }
        }
        if !done {
            return Err(IndependentAnchorError);
        }
    }
    target.identity.check()?;
    target.sync_created()?;
    drop(target); // SQLite closes/checkpoints BEFORE any independent leaf open.
    native_files::require_no_sidecars(destination)?;
    bounded_file(destination, limits)?;
    check_budget()
}

impl AnchorGuard<'_> {
    #[cfg(test)]
    pub(crate) fn test_with_body_read<T>(&mut self, action: impl FnOnce(&mut Self) -> T) -> T {
        self.blobs.sqlite.execute_batch("BEGIN DEFERRED").unwrap();
        let result: T = action(self);
        self.blobs.sqlite.execute_batch("ROLLBACK").unwrap();
        result
    }

    pub(crate) fn snapshot(
        &mut self,
        source: &mut NativeConnection,
        namespace: &SqliteNamespace,
        state_out: &Path,
        blobs_out: &Path,
        limits: LocalSnapshotLimits,
        mut check_budget: impl FnMut() -> Result<(), IndependentAnchorError>,
    ) -> Result<LocalStoreCheckpoint, IndependentAnchorError> {
        limits.validate()?;
        require_separate(self.lease.attachment.path(), state_out, blobs_out)?;
        if state_out == blobs_out {
            return Err(IndependentAnchorError);
        }
        source.identity.check()?;
        self.blobs.identity.check()?;
        // Caller already owns anchor then source mutex. Deferred read snapshots
        // pin both complete inputs; no write transaction blocks Backup::step.
        source.sqlite.execute_batch("BEGIN DEFERRED")?;
        if let Err(error) = self.blobs.sqlite.execute_batch("BEGIN DEFERRED") {
            source.sqlite.execute_batch("ROLLBACK")?;
            return Err(error.into());
        }
        let result = (|| {
            self.check(&source.sqlite)?;
            require_acknowledged(&self.owner.sqlite)?;
            geometry(&source.sqlite, limits)?;
            geometry(&self.blobs.sqlite, limits)?;
            let mut budget: Budget = Budget::new(limits.deadline_unix_millis);
            closed_schema(&source.sqlite, true, &mut budget)?;
            closed_schema(&self.blobs.sqlite, false, &mut budget)?;
            let source_instance_id: [u8; 16] = identity(&source.sqlite, namespace)?;
            let bodies: Vec<Body> = all_bodies(&self.blobs.sqlite, &mut budget)?;
            copy_database(&source.sqlite, state_out, limits, &mut check_budget)?;
            copy_database(&self.blobs.sqlite, blobs_out, limits, &mut check_budget)?;
            let old: AnchorCheckpoint = checkpoint(&self.owner.sqlite)?;
            let body_root: [u8; 32] = manifest_root(&bodies);
            let expected = LocalStoreCheckpoint {
                namespace: namespace.clone(),
                source_instance_id,
                checkpoint: AnchorCheckpoint {
                    sequence: if body_root == old.body_manifest_root {
                        old.sequence
                    } else {
                        old.sequence.checked_add(1).ok_or(IndependentAnchorError)?
                    },
                    state_root: old.state_root,
                    body_manifest_root: body_root,
                },
            };
            verify_pair(state_out, blobs_out, &expected, limits, &mut check_budget)?;
            // All copied bodies become acknowledged in one independent commit.
            // This changes no source rows; a crash leaves either valid head.
            if body_root != old.body_manifest_root {
                let tx = self
                    .owner
                    .sqlite
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                require_acknowledged(&tx)?;
                tx.execute(
                    "UPDATE anchor_head SET sequence=?1,body_root=?2 WHERE id=1",
                    params![
                        expected.checkpoint.sequence.to_be_bytes().as_slice(),
                        body_root.as_slice()
                    ],
                )?;
                replace_bodies(&tx, false, &bodies)?;
                tx.commit()?;
            }
            self.lease.check()?;
            self.owner.identity.check()?;
            source.identity.check()?;
            self.blobs.identity.check()?;
            check_budget()?;
            Ok(expected)
        })();
        // Both rollbacks are attempted even on failure. Never clear Pending or
        // rewrite the authority to make an artifact acceptable.
        let body_end = self.blobs.sqlite.execute_batch("ROLLBACK");
        let state_end = source.sqlite.execute_batch("ROLLBACK");
        body_end?;
        state_end?;
        result
    }
}
