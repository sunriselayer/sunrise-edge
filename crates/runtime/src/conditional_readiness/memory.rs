//! Protected bytes share the existing authority/sequence lock, not business rows.
use super::*;
use crate::{
    DurableCommitRejection, DurableReadError, MemoryDurableStateStore, MemoryDurableStoreData,
    NamespaceLifecycle, memory_next_mutation_sequence, validate_memory_durable_commit_authority,
    validate_memory_durable_commit_domain, validate_memory_durable_read_authority,
    validate_memory_durable_read_domain,
};
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

fn check_binding(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    binding: &ImportBinding,
    progress: &ImportProgress,
) -> Result<(), RuntimeError> {
    encode_import_binding(binding)?;
    encode_import_progress(progress)?;
    if binding.domain != domain || progress.next_ordinal != binding.row_count {
        return Err(invalid());
    }
    match &data.lifecycle {
        NamespaceLifecycle::CompleteInactive {
            binding: stored,
            progress: complete,
        } if stored == binding && complete == progress => Ok(()),
        _ => Err(invalid()),
    }
}

fn check_token(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
) -> Result<(), PortableSnapshotError> {
    let sequence: u64 = data
        .mutation_sequences
        .get(domain.as_bytes())
        .copied()
        .unwrap_or(0);
    token.check(
        &data.portable_namespace,
        domain,
        data.active_writer_fence,
        sequence,
    )
}

fn observe(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    key: &[u8],
    slot: &ReadinessSlot,
    binding: &ImportBinding,
    progress: &ImportProgress,
    token: &PortableSnapshotToken,
) -> Result<ReadinessSlotObservation, RuntimeError> {
    match data
        .readiness_slots
        .get(&(*domain.as_bytes(), key.to_vec()))
    {
        None => Ok(ReadinessSlotObservation::Absent),
        Some(None) => Ok(ReadinessSlotObservation::Tombstoned),
        Some(Some(bytes)) => {
            let record: ReadinessRecord = decode_readiness_record(bytes)?;
            record.validate_present_at(slot, binding, progress, token)?;
            Ok(ReadinessSlotObservation::Present(record))
        }
    }
}

impl ReadinessRetentionRepository for MemoryDurableStateStore {
    fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError> {
        let key: Vec<u8> = encode_readiness_slot(slot)?;
        let data: RwLockReadGuard<'_, MemoryDurableStoreData> = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, operation)?;
        check_binding(&data, domain, binding, progress)?;
        check_token(&data, domain, fresh_token)?;
        observe(&data, domain, &key, slot, binding, progress, fresh_token)
            .map_err(|_| PortableSnapshotError::Read(DurableReadError::InvalidPersistedState))
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
        let bytes: Vec<u8> = match encode_readiness_record(record) {
            Ok(bytes) => bytes,
            Err(_) => {
                return DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict);
            }
        };
        let key: Vec<u8> = match encode_readiness_slot(&record.slot) {
            Ok(key) => key,
            Err(_) => {
                return DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict);
            }
        };
        let mut data: RwLockWriteGuard<'_, MemoryDurableStoreData> = match self.inner.write() {
            Ok(data) => data,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::UnavailableBeforeCommit,
                );
            }
        };
        let result: Result<(), DurableCommitRejection> = (|| {
            validate_memory_durable_commit_domain(&data, domain)?;
            validate_memory_durable_commit_authority(&data, operation)?;
            check_binding(&data, domain, binding, progress)
                .map_err(|_| DurableCommitRejection::ImportBindingMismatch)?;
            check_token(&data, domain, fresh_token)
                .map_err(|_| DurableCommitRejection::ImportConflict)?;
            if &record.binding != binding || &record.progress != progress {
                return Err(DurableCommitRejection::ImportBindingMismatch);
            }
            let actual: ReadinessSlotObservation = observe(
                &data,
                domain,
                &key,
                &record.slot,
                binding,
                progress,
                fresh_token,
            )
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
            if &actual != expected_observation {
                return Err(DurableCommitRejection::ImportConflict);
            }
            match actual {
                ReadinessSlotObservation::Present(stored) if stored == *record => Ok(()),
                ReadinessSlotObservation::Absent if record.creation_token == *fresh_token => {
                    let next: u64 = memory_next_mutation_sequence(&data, domain)
                        .ok_or(DurableCommitRejection::CommitSequenceOverflow)?;
                    data.readiness_slots
                        .insert((*domain.as_bytes(), key), Some(bytes));
                    data.mutation_sequences.insert(*domain.as_bytes(), next);
                    Ok(())
                }
                _ => Err(DurableCommitRejection::ImportConflict),
            }
        })();
        match result {
            Ok(()) => DurableCommitOutcome::Committed,
            Err(reason) => DurableCommitOutcome::Rejected(reason),
        }
    }
}
