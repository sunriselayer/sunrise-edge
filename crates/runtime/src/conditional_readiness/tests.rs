//! Storage fixtures only: no vote authentication or initial E bond is seeded.
use super::*;
use crate::portable::DurablePortableSnapshotRepository;
use crate::{
    DurableCommitRejection, DurableDomainStateStore, ImportBatch, ImportContext, ImportRow,
    MemoryDurableStateStore, NamespaceLifecycle, StorageCorrelationId, StorageDeadline,
};
use protocol_types::{ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, ProtocolVersion};

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn binding() -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("readiness-storage").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(2),
        },
        domain: AtomicityDomainId::new([7; 32]).unwrap(),
        genesis_digest: digest(1),
        validator_set_digest: digest(2),
        cut_digest: digest(3),
        package_digest: digest(4),
        plan_digest: digest(5),
        row_count: 1,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(7),
    }
}
fn operation(fence: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(10_000).unwrap(),
        StorageCorrelationId::new([5; 16]).unwrap(),
    )
}
fn complete() -> (
    MemoryDurableStateStore,
    ImportBinding,
    ImportProgress,
    PortableSnapshotToken,
) {
    let pin: ImportBinding = binding();
    let operation: DurableOperationContext = operation(7);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_import_target(pin.clone(), operation.writer_fence()).unwrap();
    let initial: ImportProgress = ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest(6),
    };
    assert_eq!(
        store.begin_import(&operation, pin.domain, &pin, initial.accumulator),
        DurableCommitOutcome::Committed
    );
    let batch: ImportBatch = ImportBatch::new(
        pin.clone(),
        initial,
        digest(7),
        digest(8),
        vec![ImportRow::State {
            key: b"business".to_vec(),
            value: Some(b"original".to_vec()),
        }],
    )
    .unwrap();
    assert_eq!(
        store.commit_import_batch(&operation, pin.domain, &batch),
        DurableCommitOutcome::Committed
    );
    let verified: PortableSnapshotToken = store
        .begin_portable_snapshot(&operation, pin.domain)
        .unwrap();
    assert_eq!(
        store.finish_import(&operation, pin.domain, &pin, batch.next(), &verified),
        DurableCommitOutcome::Committed
    );
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&operation, pin.domain)
        .unwrap();
    (store, pin, batch.next().clone(), token)
}
fn record(
    pin: &ImportBinding,
    progress: &ImportProgress,
    token: &PortableSnapshotToken,
    identity: u8,
) -> ReadinessRecord {
    ReadinessRecord {
        slot: ReadinessSlot {
            identity: digest(identity),
            signer: ValidatorId::new([9; 32]),
        },
        binding: pin.clone(),
        progress: progress.clone(),
        creation_token: token.clone(),
        vote_bytes: vec![0x42; 128],
    }
}

#[test]
fn readiness_storage_closed_frames_and_bounds() {
    let (_, pin, progress, token) = complete();
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let slot_bytes: Vec<u8> = encode_readiness_slot(&value.slot).unwrap();
    let expected_digest: Vec<u8> = encode_digest32(&value.slot.identity).unwrap();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64D0, 1);
    expected.field_bytes(1, expected_digest).unwrap();
    expected.field_bytes(2, [9_u8; 32].to_vec()).unwrap();
    assert_eq!(slot_bytes, expected.finish().unwrap());
    assert_eq!(decode_readiness_slot(&slot_bytes).unwrap(), value.slot);
    let token_bytes: Vec<u8> = encode_readiness_creation_token(&token).unwrap();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64D2, 1);
    expected.field_bytes(1, token.namespace().to_vec()).unwrap();
    expected
        .field_bytes(2, pin.domain.as_bytes().to_vec())
        .unwrap();
    expected.field_u64(3, 7).unwrap();
    expected.field_u64(4, token.mutation_sequence()).unwrap();
    assert_eq!(token_bytes, expected.finish().unwrap());
    assert_eq!(
        decode_readiness_creation_token(&token_bytes).unwrap(),
        token
    );
    let bytes: Vec<u8> = encode_readiness_record(&value).unwrap();
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64D1, 1);
    expected.field_bytes(1, slot_bytes).unwrap();
    expected
        .field_bytes(2, encode_import_binding(&pin).unwrap())
        .unwrap();
    expected
        .field_bytes(3, encode_import_progress(&progress).unwrap())
        .unwrap();
    expected.field_bytes(4, token_bytes).unwrap();
    expected.field_bytes(5, value.vote_bytes.clone()).unwrap();
    assert_eq!(bytes, expected.finish().unwrap());
    assert_eq!(decode_readiness_record(&bytes).unwrap(), value);
    assert!(decode_readiness_record(&bytes[..bytes.len() - 1]).is_err());
    let mut legal: ReadinessRecord = value.clone();
    legal.vote_bytes = vec![0x43; MAX_READINESS_VOTE_BYTES];
    assert!(encode_readiness_record(&legal).is_ok());
    legal.vote_bytes.push(0);
    assert!(encode_readiness_record(&legal).is_err());
    legal.vote_bytes.clear();
    assert!(encode_readiness_record(&legal).is_err());
    assert!(decode_readiness_slot(&vec![0; MAX_READINESS_SLOT_BYTES + 1]).is_err());
    assert!(decode_readiness_record(&vec![0; MAX_READINESS_RECORD_BYTES + 1]).is_err());
    let mut invalid: CanonicalStruct = CanonicalStruct::new(0x64D2, 1);
    invalid.field_bytes(1, vec![1; 257]).unwrap();
    invalid
        .field_bytes(2, pin.domain.as_bytes().to_vec())
        .unwrap();
    invalid.field_u64(3, 0).unwrap();
    invalid.field_u64(4, 1).unwrap();
    assert!(decode_readiness_creation_token(&invalid.finish().unwrap()).is_err());
    for (type_id, version, extra) in [
        (0x64D0_u16, 2_u16, false),
        (0x64D1, 1, false),
        (0x64D0, 1, true),
    ] {
        let mut invalid: CanonicalStruct = CanonicalStruct::new(type_id, version);
        invalid
            .field_bytes(1, encode_digest32(&value.slot.identity).unwrap())
            .unwrap();
        invalid
            .field_bytes(2, value.slot.signer.as_bytes().to_vec())
            .unwrap();
        if extra {
            invalid.field_u64(3, 1).unwrap();
        }
        assert!(decode_readiness_slot(&invalid.finish().unwrap()).is_err());
    }
    let mut zero_fence: CanonicalStruct = CanonicalStruct::new(0x64D2, 1);
    zero_fence
        .field_bytes(1, token.namespace().to_vec())
        .unwrap();
    zero_fence
        .field_bytes(2, pin.domain.as_bytes().to_vec())
        .unwrap();
    zero_fence.field_u64(3, 0).unwrap();
    zero_fence.field_u64(4, token.mutation_sequence()).unwrap();
    assert!(decode_readiness_creation_token(&zero_fence.finish().unwrap()).is_err());
}

#[test]
fn readiness_storage_memory_insert_advances_token_but_present_retry_is_read_only() {
    let (store, pin, progress, token) = complete();
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    assert_eq!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Absent
    );
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot),
        Err(PortableSnapshotError::Changed)
    );
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Present(value.clone()),
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    let fresh: PortableSnapshotToken = store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert_eq!(fresh.mutation_sequence(), token.mutation_sequence() + 1);
    let observed: ReadinessSlotObservation = store
        .read_ready_slot_at(&context, pin.domain, &pin, &progress, &fresh, &value.slot)
        .unwrap();
    assert_eq!(observed, ReadinessSlotObservation::Present(value.clone()));
    assert_eq!(
        store.retain_ready_slot(
            &context, pin.domain, &pin, &progress, &fresh, &observed, &value
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.begin_portable_snapshot(&context, pin.domain).unwrap(),
        fresh
    );
    store.set_active_writer_fence(WriterFenceGeneration::new(8).unwrap());
    let newer: PortableSnapshotToken = store
        .begin_portable_snapshot(&operation(8), pin.domain)
        .unwrap();
    assert_eq!(
        store
            .read_ready_slot_at(
                &operation(8),
                pin.domain,
                &pin,
                &progress,
                &newer,
                &value.slot
            )
            .unwrap(),
        observed
    );
    assert_eq!(
        store
            .get_namespace_lifecycle(&operation(8), pin.domain)
            .unwrap(),
        NamespaceLifecycle::CompleteInactive {
            binding: pin.clone(),
            progress: progress.clone()
        }
    );
    assert_eq!(
        store
            .get_versioned_durable(&operation(8), pin.domain, b"business")
            .unwrap()
            .value(),
        Some(b"original".as_slice())
    );
}

#[test]
fn readiness_storage_memory_refuses_wrong_origin_namespace_binding_fence_and_deadline() {
    let (store, pin, progress, token) = complete();
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let (other, _, _, foreign) = complete();
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &foreign, &value.slot)
            .is_err()
    );
    assert!(
        other
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    let mut wrong: ImportBinding = pin.clone();
    wrong.plan_digest = digest(11);
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &wrong, &progress, &token, &value.slot)
            .is_err()
    );
    assert!(
        store
            .read_ready_slot_at(
                &operation(6),
                pin.domain,
                &pin,
                &progress,
                &token,
                &value.slot
            )
            .is_err()
    );
    let fresh: MemoryDurableStateStore =
        MemoryDurableStateStore::new_import_target(pin.clone(), context.writer_fence()).unwrap();
    let fresh_token: PortableSnapshotToken =
        fresh.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert!(
        fresh
            .read_ready_slot_at(
                &context,
                pin.domain,
                &pin,
                &progress,
                &fresh_token,
                &value.slot
            )
            .is_err()
    );
    let ordinary: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(pin.domain, context.writer_fence());
    let ordinary_token: PortableSnapshotToken = ordinary
        .begin_portable_snapshot(&context, pin.domain)
        .unwrap();
    assert!(
        ordinary
            .read_ready_slot_at(
                &context,
                pin.domain,
                &pin,
                &progress,
                &ordinary_token,
                &value.slot
            )
            .is_err()
    );
    store.set_time(10_000);
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
}

#[test]
fn readiness_storage_memory_tombstone_corruption_and_absent_cache_recreation() {
    let (store, pin, progress, token) = complete();
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let key: Vec<u8> = encode_readiness_slot(&value.slot).unwrap();
    store
        .inner
        .write()
        .unwrap()
        .readiness_slots
        .insert((*pin.domain.as_bytes(), key.clone()), None);
    assert_eq!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Tombstoned
    );
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Tombstoned,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    store
        .inner
        .write()
        .unwrap()
        .readiness_slots
        .insert((*pin.domain.as_bytes(), key.clone()), Some(vec![0; 100]));
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    store
        .inner
        .write()
        .unwrap()
        .readiness_slots
        .remove(&(*pin.domain.as_bytes(), key.clone()));
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    store
        .inner
        .write()
        .unwrap()
        .readiness_slots
        .remove(&(*pin.domain.as_bytes(), key));
    let current: PortableSnapshotToken =
        store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &current,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    let recreated: ReadinessRecord = record(&pin, &progress, &current, 10);
    assert_eq!(recreated.vote_bytes, value.vote_bytes);
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &current,
            &ReadinessSlotObservation::Absent,
            &recreated
        ),
        DurableCommitOutcome::Committed
    );
}
