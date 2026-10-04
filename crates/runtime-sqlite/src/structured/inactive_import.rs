//! Native opt-in facade. Neither ordinary open nor DO/PG composition creates
//! this permanent import-only origin. This is the only native facade that
//! exposes first-successor activation and serving (DR-0189): its lifecycle
//! can reach `CompleteInactive`, so it alone satisfies
//! `SuccessorServingRepository: InactiveImportRepository`. There is no
//! ordinary promotion path; an operator reaches `Serving` only through an
//! explicit, separately reviewed `commit_successor_activation` call against
//! this exact facade.
use super::*;
use crate::native_files;
use protocol_types::Digest32;
use protocol_types::ValidatorId;
use runtime::successor_serving::{SuccessorServingObservation, SuccessorServingRepository};
use runtime::{
    ImportBatch, ImportBinding, ImportProgress, InactiveImportRepository, NamespaceLifecycle,
    ReadinessRecord, ReadinessRetentionRepository, ReadinessSlot, ReadinessSlotObservation,
};

/// Fresh or resumed installation destination, never an ordinary node store.
#[derive(Debug)]
pub struct SqliteImportTarget {
    store: SqliteDurableStore,
}

fn configure(connection: &Connection) -> Result<(), SqliteDurableStoreError> {
    connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}
impl SqliteImportTarget {
    /// Reserves a new file, initializes its own local fence and immutable
    /// binding. Existing files are never replaced, converted or reset. A
    /// failed creation preserves the file for explicit operator inspection.
    pub fn create(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
        own_writer_fence: WriterFenceGeneration,
        binding: &ImportBinding,
    ) -> Result<Self, SqliteDurableStoreError> {
        if binding.domain != namespace.domain() || &binding.context.chain_id != namespace.chain_id()
        {
            return Err(SqliteDurableStoreError::ImportBindingMismatch);
        }
        runtime::inactive_import::encode_import_binding(binding)
            .map_err(|_| SqliteDurableStoreError::InvalidPersistedMetadata)?;
        let path: &Path = path.as_ref();
        let reserved: native_files::ImportFile =
            native_files::create_new(path).map_err(SqliteDurableStoreError::File)?;
        let connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&connection)?;
        native_files::check_attached(path, &reserved).map_err(SqliteDurableStoreError::File)?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(SqliteDurableStoreError::UnsupportedJournalMode(journal));
        }
        let backend: NativeSqlBackend = NativeSqlBackend::new(connection);
        run_operator_step(&backend, |session, _| {
            session.exec(
                &format!("PRAGMA application_id = {STRUCTURED_APPLICATION_ID}"),
                &[],
            )?;
            session.exec(
                &format!("PRAGMA user_version = {STRUCTURED_SCHEMA_VERSION}"),
                &[],
            )?;
            schema::bootstrap_import_namespace(session, &namespace, own_writer_fence, binding)
        })?;
        native_files::sync_created(path, &reserved).map_err(SqliteDurableStoreError::File)?;
        Ok(Self {
            store: SqliteDurableStore {
                engine: SqlDurableEngine::new(backend, namespace),
            },
        })
    }

    /// Opens only an already initialized import destination, matching all
    /// mandatory origin/binding/progress metadata. No bootstrap or repair.
    pub fn open_existing(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
        binding: &ImportBinding,
    ) -> Result<Self, SqliteDurableStoreError> {
        let path: &Path = path.as_ref();
        let held: native_files::ImportFile =
            native_files::open_existing(path).map_err(SqliteDurableStoreError::File)?;
        let connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&connection)?;
        let application: i64 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        if application != STRUCTURED_APPLICATION_ID {
            return Err(SqliteDurableStoreError::ApplicationId(application));
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != STRUCTURED_SCHEMA_VERSION {
            return Err(SqliteDurableStoreError::SchemaVersion(version));
        }
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(SqliteDurableStoreError::UnsupportedJournalMode(journal));
        }
        let backend: NativeSqlBackend = NativeSqlBackend::new(connection);
        let metadata = run_operator_step(&backend, |session, _| {
            schema::verify_namespace(session, &namespace)
        })?;
        if metadata.lifecycle().binding() != Some(binding) {
            return Err(SqliteDurableStoreError::ImportBindingMismatch);
        }
        native_files::check_attached(path, &held).map_err(SqliteDurableStoreError::File)?;
        Ok(Self {
            store: SqliteDurableStore {
                engine: SqlDurableEngine::new(backend, namespace),
            },
        })
    }
    #[must_use]
    pub const fn namespace(&self) -> &SqliteNamespace {
        self.store.namespace()
    }
    pub fn writer_fence(&self) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        self.store.writer_fence()
    }
    /// Destination-local operator fencing only, not a copied source token.
    pub fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        self.store.advance_writer_fence(expected, next)
    }
}

impl DurableDomainStateStore for SqliteImportTarget {
    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.store.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.store.get_namespace_lifecycle(context, domain)
    }
    fn get_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::successor_serving::SuccessorServingSlot, DurableReadError> {
        self.store.get_successor_serving(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.store.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.store.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for SqliteImportTarget {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.store.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.store
            .get_object_version(context, domain, object_id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.store.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        invocation: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.store.commit_invocation(context, invocation)
    }
    fn successor_serving_repository(&self) -> Option<&dyn SuccessorServingRepository> {
        Some(self)
    }
}
impl DurableStateKeyScanner for SqliteImportTarget {
    fn scan_durable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &StateKeyScan,
    ) -> Result<StateKeyPage, DurableReadError> {
        self.store.scan_durable_keys(context, domain, scan)
    }
}
impl StructuredOutboxExclusionGuard for SqliteImportTarget {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        self.store.inspect_outbox_exclusion(context, domain)
    }
}
impl DurablePortableRepository for SqliteImportTarget {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.store.scan_portable_keys(context, domain, scan)
    }
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.store.read_portable_descriptor(context, domain, key)
    }
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.store.read_portable_chunk(context, domain, request)
    }
}
impl DurablePortableSnapshotRepository for SqliteImportTarget {
    fn begin_portable_snapshot(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.store.begin_portable_snapshot(context, domain)
    }
    fn scan_portable_keys_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.store
            .scan_portable_keys_at(context, domain, token, scan)
    }
    fn read_portable_descriptor_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.store
            .read_portable_descriptor_at(context, domain, token, key)
    }
    fn read_portable_chunk_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.store
            .read_portable_chunk_at(context, domain, token, request)
    }
    fn check_portable_outbox_empty_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.store
            .check_portable_outbox_empty_at(context, domain, token)
    }
}
impl InactiveImportRepository for SqliteImportTarget {
    fn begin_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        initial_accumulator: Digest32,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .begin_import(context, domain, binding, initial_accumulator)
    }
    fn read_import_progress(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<Option<ImportProgress>, DurableReadError> {
        self.store.engine.read_import_progress(context, domain)
    }
    fn commit_import_batch(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        batch: &ImportBatch,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .commit_import_batch(context, domain, batch)
    }
    fn finish_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        expected: &ImportProgress,
        token: &PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .finish_import(context, domain, binding, expected, token)
    }
}

impl SuccessorServingRepository for SqliteImportTarget {
    fn read_namespace_validator(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError> {
        self.store.engine.read_namespace_validator(context, domain)
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_successor_activation(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.store.engine.commit_successor_activation(
            context,
            domain,
            binding,
            progress,
            fresh_token,
            record,
            transaction,
        )
    }

    fn commit_successor_durable(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .commit_successor_durable(context, observation, transaction)
    }

    fn commit_successor_invocation(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .commit_successor_invocation(context, observation, transaction)
    }

    fn commit_successor_seal_retention(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.store
            .engine
            .commit_successor_seal_retention(context, observation, token, transaction)
    }

    fn commit_successor_seal_completion(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: runtime::SealBarrier,
    ) -> DurableCommitOutcome {
        self.store.engine.commit_successor_seal_completion(
            context,
            observation,
            token,
            transaction,
            sealed,
        )
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod successor_tests;

impl ReadinessRetentionRepository for SqliteImportTarget {
    fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError> {
        self.store.engine.read_ready_slot_at(
            operation,
            domain,
            binding,
            progress,
            fresh_token,
            slot,
        )
    }
    fn retain_ready_slot(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        expected_observation: &ReadinessSlotObservation,
        record: &ReadinessRecord,
    ) -> DurableCommitOutcome {
        self.store.engine.retain_ready_slot(
            operation,
            domain,
            binding,
            progress,
            fresh_token,
            expected_observation,
            record,
        )
    }
}
