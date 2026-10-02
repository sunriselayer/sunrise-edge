//! Exact protected lookup/CAS within the existing import authority transaction.
use super::*;
use runtime::conditional_readiness::{
    MAX_READINESS_RECORD_BYTES, decode_readiness_record, encode_readiness_record,
    encode_readiness_slot,
};
use runtime::portable::PortableSnapshotError;
use runtime::{ReadinessRecord, ReadinessSlot, ReadinessSlotObservation};

fn complete_matches(
    metadata: &NamespaceMetadata,
    domain: AtomicityDomainId,
    binding: &ImportBinding,
    progress: &ImportProgress,
) -> Result<(), PreCommitFailure> {
    if binding.domain != domain || progress.next_ordinal != binding.row_count {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    match metadata.lifecycle() {
        NamespaceLifecycle::CompleteInactive {
            binding: stored,
            progress: complete,
        } if stored == binding && complete == progress => Ok(()),
        _ => Err(PreCommitFailure::InvalidPersistedState),
    }
}

fn token_matches(
    namespace: &SqlDurableNamespace,
    metadata: &NamespaceMetadata,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
) -> Result<(), PreCommitFailure> {
    let bytes: Vec<u8> =
        portable::portable_namespace_bytes(namespace, &metadata.source_instance_id())
            .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    token
        .check(
            &bytes,
            domain,
            metadata.writer_fence(),
            metadata.mutation_sequence(),
        )
        .map_err(|_| PreCommitFailure::Changed)
}

fn observe(
    session: &mut dyn SqlSession,
    key: &[u8],
    slot: &ReadinessSlot,
    binding: &ImportBinding,
    progress: &ImportProgress,
    token: &PortableSnapshotToken,
) -> Result<ReadinessSlotObservation, PreCommitFailure> {
    // Length/type first inside the same transaction; never allocate an
    // unrestricted BLOB before deciding whether the exact record is bounded.
    let rows = session.exec(
        "SELECT status, typeof(record), length(record)
        FROM durable_conditional_readiness WHERE slot = ?1 LIMIT 2",
        &[SqlValue::Blob(key.to_vec())],
    )?;
    let Some(row) = rows
        .one()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?
    else {
        return Ok(ReadinessSlotObservation::Absent);
    };
    let status: i64 = row
        .integer(0)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let kind: &str = row
        .text(1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if status == 2 && kind == "null" && matches!(row.value(2), Some(SqlValue::Null)) {
        return Ok(ReadinessSlotObservation::Tombstoned);
    }
    let length: usize = row
        .integer(2)
        .ok()
        .and_then(|value: i64| usize::try_from(value).ok())
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    if status != 1 || kind != "blob" || length == 0 || length > MAX_READINESS_RECORD_BYTES {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let records = session.exec(
        "SELECT record FROM durable_conditional_readiness
        WHERE slot = ?1 AND typeof(record) = 'blob' AND length(record) = ?2 LIMIT 2",
        &[
            SqlValue::Blob(key.to_vec()),
            SqlValue::Integer(
                i64::try_from(length).map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            ),
        ],
    )?;
    let record_row = records
        .one()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let bytes: &[u8] = record_row
        .blob(0)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let record: ReadinessRecord =
        decode_readiness_record(bytes).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    record
        .validate_present_at(slot, binding, progress, token)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    Ok(ReadinessSlotObservation::Present(record))
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Bounded exact protected read, with the verification token checked in
    /// the same transaction as immutable origin/progress and retained bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError> {
        let key: Vec<u8> = encode_readiness_slot(slot)?;
        if !self.domain_is_bound(domain) {
            return Err(RuntimeError::AtomicityDomainMismatch.into());
        }
        run_read(&self.backend, Self::budget(operation), |session, now| {
            let metadata: NamespaceMetadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, operation, now)?;
            complete_matches(&metadata, domain, binding, progress)?;
            token_matches(&self.namespace, &metadata, domain, fresh_token)?;
            let result: ReadinessSlotObservation =
                observe(session, &key, slot, binding, progress, fresh_token)?;
            check_deadline_before_commit(session, operation)?;
            Ok(result)
        })
        .map_err(|error: PreCommitFailure| match error {
            PreCommitFailure::Changed => PortableSnapshotError::Changed,
            other => PortableSnapshotError::Read(other.into_read_error()),
        })
    }

    /// Storage-only exact insertion/comparison. No signing or ordinary write
    /// authorization is supplied by this opt-in operation.
    #[allow(clippy::too_many_arguments)]
    pub fn retain_ready_slot(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        expected_observation: &ReadinessSlotObservation,
        record: &ReadinessRecord,
    ) -> DurableCommitOutcome {
        let bytes: Vec<u8> = match encode_readiness_record(record) {
            Ok(bytes) => bytes,
            Err(_) => return DurableCommitOutcome::Rejected(conflict()),
        };
        let key: Vec<u8> = match encode_readiness_slot(&record.slot) {
            Ok(key) => key,
            Err(_) => return DurableCommitOutcome::Rejected(conflict()),
        };
        self.import_write(operation, domain, |session, metadata| {
            binding_matches(metadata, binding, domain)?;
            complete_matches(metadata, domain, binding, progress).map_err(reject)?;
            token_matches(&self.namespace, metadata, domain, fresh_token)
                .map_err(|_| conflict())?;
            if &record.binding != binding || &record.progress != progress {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            let actual: ReadinessSlotObservation =
                observe(session, &key, &record.slot, binding, progress, fresh_token)
                    .map_err(reject)?;
            if &actual != expected_observation {
                return Err(conflict());
            }
            match actual {
                ReadinessSlotObservation::Present(stored) if stored == *record => Ok(()),
                ReadinessSlotObservation::Absent if record.creation_token == *fresh_token => {
                    let rows = session
                        .exec(
                            "INSERT INTO durable_conditional_readiness
                        (slot, status, record) VALUES (?1, 1, ?2)",
                            &[SqlValue::Blob(key), SqlValue::Blob(bytes)],
                        )
                        .map_err(|error| reject(error.into()))?;
                    if rows.rows_affected() != 1 {
                        return Err(conflict());
                    }
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| reject(error.into()))?;
                    Ok(())
                }
                _ => Err(conflict()),
            }
        })
    }
}
