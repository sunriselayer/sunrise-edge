use super::*;
use crate::portable::DurablePortableSnapshotRepository;
use hashing::{BuiltinHashFunction, HashFunction};
use protocol_types::{HashAlgorithmId, HashPurpose};

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn binding(rows: u64) -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("inactive-import-test").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(7),
        },
        domain: AtomicityDomainId::new([7; 32]).unwrap(),
        genesis_digest: digest(1),
        validator_set_digest: digest(2),
        cut_digest: digest(3),
        package_digest: digest(4),
        plan_digest: digest(5),
        row_count: rows,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(19),
    }
}
fn operation(fence: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(10_000).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    )
}
fn initial() -> ImportProgress {
    ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest(6),
    }
}
fn state(key: &[u8], value: Option<&[u8]>) -> ImportRow {
    ImportRow::State {
        key: key.to_vec(),
        value: value.map(<[u8]>::to_vec),
    }
}
fn batch(binding: &ImportBinding, expected: &ImportProgress, rows: Vec<ImportRow>) -> ImportBatch {
    ImportBatch::new(
        binding.clone(),
        expected.clone(),
        digest(7),
        digest(8),
        rows,
    )
    .unwrap()
}
fn batch_with_digest(
    binding: &ImportBinding,
    expected: &ImportProgress,
    batch_digest_byte: u8,
    next_accumulator_byte: u8,
    rows: Vec<ImportRow>,
) -> ImportBatch {
    ImportBatch::new(
        binding.clone(),
        expected.clone(),
        digest(batch_digest_byte),
        digest(next_accumulator_byte),
        rows,
    )
    .unwrap()
}
fn ordinary_write(domain: AtomicityDomainId) -> AtomicStateTransaction {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"forbidden".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"forbidden".to_vec(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn assert_node_event_vector(bytes: &[u8], expected_hex: &str) {
    assert_eq!(expected_hex.len(), 64);
    let expected: [u8; 32] = std::array::from_fn(|offset| {
        u8::from_str_radix(&expected_hex[offset * 2..offset * 2 + 2], 16).unwrap()
    });
    let chain: ChainId = ChainId::new("cut-vector").unwrap();
    let hash: BuiltinHashFunction = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256);
    let actual: Digest32 = hash
        .hash(
            HashPurpose::NodeEvent,
            ProtocolVersion::new(1),
            &chain,
            bytes,
        )
        .unwrap();
    assert_eq!(actual.bytes(), expected);
}

#[test]
fn ordinary_write_lifecycle_refusal_has_literal_phase_precedence() {
    // Phase-only synthetic observations, not authenticated serving evidence
    // or a way to install these combinations in a live namespace.
    let pin: ImportBinding = binding(0);
    let progress: ImportProgress = initial();
    let lifecycles: [NamespaceLifecycle; 4] = [
        NamespaceLifecycle::Ordinary,
        NamespaceLifecycle::FreshImport(pin.clone()),
        NamespaceLifecycle::Importing {
            binding: pin.clone(),
            progress: progress.clone(),
        },
        NamespaceLifecycle::CompleteInactive {
            binding: pin.clone(),
            progress: progress.clone(),
        },
    ];
    let barriers: [OutgoingBarrier; 2] = [
        OutgoingBarrier::Unsealed,
        OutgoingBarrier::Sealed(SealBarrier {
            outgoing_epoch: Epoch::new(7),
            request: [0x80; 32],
            height: 1,
            block_digest: digest(10),
            target_digest: digest(11),
            transition_history: TransitionHistoryState::Virgin,
        }),
    ];
    let slots: [SuccessorServingSlot; 2] = [
        SuccessorServingSlot::Inactive,
        SuccessorServingSlot::Serving(Box::new(SuccessorServingObservation {
            record: Vec::new(),
            binding: pin,
            progress,
        })),
    ];
    // Literal independent expectations: lifecycle, barrier, slot, result.
    // 4 lifecycle variants x 2 barriers x 2 slots = 16 predicate cases.
    let cases: [(usize, usize, usize, Result<(), DurableCommitRejection>); 16] = [
        (0, 0, 0, Ok(())),
        (0, 0, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (0, 1, 0, Err(DurableCommitRejection::NamespaceSealed)),
        (0, 1, 1, Err(DurableCommitRejection::NamespaceSealed)),
        (1, 0, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (1, 0, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (1, 1, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (1, 1, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (2, 0, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (2, 0, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (2, 1, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (2, 1, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (3, 0, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (3, 0, 1, Err(DurableCommitRejection::InactiveNamespace)),
        (3, 1, 0, Err(DurableCommitRejection::InactiveNamespace)),
        (3, 1, 1, Err(DurableCommitRejection::InactiveNamespace)),
    ];
    for (lifecycle_index, barrier_index, slot_index, expected) in cases {
        let actual: Result<(), DurableCommitRejection> = validate_ordinary_write_lifecycle(
            &lifecycles[lifecycle_index],
            &barriers[barrier_index],
            &slots[slot_index],
        );
        assert_eq!(
            actual, expected,
            "lifecycle {lifecycle_index}, barrier {barrier_index}, slot {slot_index}"
        );
    }
}

#[test]
fn inactive_import_persistence_frames_match_independent_node_vectors() {
    // Synthetic storage frames, not an authenticated import plan or permit.
    // Independently pinned by scripts/business-import-vectors.mjs.
    let pin: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("cut-vector").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(2),
        },
        domain: AtomicityDomainId::new([0x11; 32]).unwrap(),
        genesis_digest: digest(0x22),
        validator_set_digest: digest(0x22),
        cut_digest: digest(0x22),
        package_digest: digest(0x22),
        plan_digest: digest(0x22),
        row_count: 3,
        blob_count: 2,
        generation_floor: ExecutionGeneration::new(7),
    };
    let binding_bytes: Vec<u8> = encode_import_binding(&pin).unwrap();
    assert_eq!(decode_import_binding(&binding_bytes).unwrap(), pin);
    assert_node_event_vector(
        &binding_bytes,
        "10d26677f6bb5df07aa0f3f69982b69abfba650c1e367ce6491e6a5cae4f0039",
    );
    let fresh: ImportProgress = ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest(0x22),
    };
    let fresh_bytes: Vec<u8> = encode_import_progress(&fresh).unwrap();
    assert_eq!(decode_import_progress(&fresh_bytes).unwrap(), fresh);
    assert_node_event_vector(
        &fresh_bytes,
        "24f8039cde4c8d125efc3e7e6d73fbbe56819a2c0d59a046ea8f57c8ee0767b9",
    );
    let applied: ImportProgress = ImportProgress {
        next_ordinal: 3,
        last_batch_digest: Some(digest(0x33)),
        accumulator: digest(0x22),
    };
    let applied_bytes: Vec<u8> = encode_import_progress(&applied).unwrap();
    assert_eq!(decode_import_progress(&applied_bytes).unwrap(), applied);
    assert_node_event_vector(
        &applied_bytes,
        "bbd5e8e8cb58b2cd745a71beb6b353f3efe0caf20ac2dbc1619f13079dbf0ec7",
    );
    assert_ne!(fresh_bytes, applied_bytes);
}

#[test]
fn inactive_import_closed_metadata_frames_and_batch_bounds() {
    let pin: ImportBinding = binding(256);
    let bytes: Vec<u8> = encode_import_binding(&pin).unwrap();
    assert_eq!(decode_import_binding(&bytes).unwrap(), pin);
    let frame = decode_canonical_frame(&bytes).unwrap();
    frame.require_type(0x64C0).unwrap();
    frame.require_version(1).unwrap();
    assert_eq!(frame.required_u64(10).unwrap(), 256);
    assert_eq!(frame.required_u64(12).unwrap(), 19);
    assert!(decode_import_binding(&bytes[..bytes.len() - 1]).is_err());
    let progress: ImportProgress = initial();
    assert_eq!(
        decode_import_progress(&encode_import_progress(&progress).unwrap()).unwrap(),
        progress
    );
    assert!(
        encode_import_progress(&ImportProgress {
            next_ordinal: 1,
            ..progress.clone()
        })
        .is_err()
    );
    assert!(
        ImportBatch::new(
            pin.clone(),
            progress.clone(),
            digest(7),
            digest(8),
            Vec::new()
        )
        .is_err()
    );
    assert!(
        ImportBatch::new(
            pin.clone(),
            progress.clone(),
            digest(7),
            digest(8),
            vec![state(b"a", None), state(b"a", None)]
        )
        .is_err()
    );
    assert!(
        ImportBatch::new(
            pin.clone(),
            progress.clone(),
            digest(7),
            digest(8),
            vec![state(b"z", None), state(b"a", None)]
        )
        .is_err()
    );
    let many: Vec<ImportRow> = (0_u16..129)
        .map(|key| state(&key.to_be_bytes(), None))
        .collect();
    assert!(ImportBatch::new(pin.clone(), progress.clone(), digest(7), digest(8), many).is_err());
    let legal: Vec<u8> = vec![0x11; MAX_STATE_VALUE_BYTES];
    assert!(
        ImportBatch::new(
            pin.clone(),
            progress.clone(),
            digest(7),
            digest(8),
            vec![state(b"a", Some(&legal))]
        )
        .is_ok()
    );
    assert!(
        ImportBatch::new(
            pin,
            progress,
            digest(7),
            digest(8),
            vec![state(b"a", Some(&legal)), state(b"b", Some(&legal))]
        )
        .is_err()
    );
}

#[test]
fn inactive_import_memory_restores_four_collections_exact_retry_and_fenced_completion() {
    let pin: ImportBinding = binding(6);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_import_target(pin.clone(), operation(7).writer_fence())
            .unwrap();
    let context: DurableOperationContext = operation(7);
    assert_eq!(
        store.get_namespace_lifecycle(&context, pin.domain).unwrap(),
        NamespaceLifecycle::FreshImport(pin.clone())
    );
    assert_eq!(
        store.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let id: ObjectId = ObjectId::new([9; 32]);
    let first: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(17).unwrap(),
        digest(10),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(11),
    );
    let last: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(19).unwrap(),
        digest(12),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(13),
    );
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([8; 32]).unwrap(),
        digest(14),
        vec![0x61; 72],
    )
    .unwrap();
    let install: ImportBatch = batch(
        &pin,
        &initial(),
        vec![
            state(b"a", Some(b"exact")),
            state(b"z", None),
            ImportRow::ObjectVersion(first.clone()),
            ImportRow::ObjectVersion(last.clone()),
            ImportRow::ObjectHead {
                object_id: id,
                head: ImportObjectHead::Tombstoned {
                    last_object_version: last.object_version(),
                },
            },
            ImportRow::Receipt(receipt.clone()),
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &install),
        DurableCommitOutcome::Committed
    );
    let token = store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &install),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.begin_portable_snapshot(&context, pin.domain).unwrap(),
        token,
        "identical retry does not reapply or advance sequence"
    );
    assert_eq!(
        store
            .get_request_receipt(&context, pin.domain, receipt.request_id())
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store
            .get_object_version(&context, pin.domain, id, first.object_version())
            .unwrap(),
        Some(first)
    );
    assert_eq!(
        store
            .get_object_version(&context, pin.domain, id, last.object_version())
            .unwrap(),
        Some(last)
    );
    assert!(matches!(
        store.get_object_head(&context, pin.domain, id).unwrap(),
        DurableObjectHead::Tombstoned {
            head_revision: ObjectHeadRevision::FIRST,
            ..
        }
    ));
    let tombstone = store
        .get_versioned_durable(&context, pin.domain, b"z")
        .unwrap();
    assert_ne!(tombstone.revision(), StateRevision::INITIAL);
    assert!(tombstone.value().is_none());
    let foreign =
        MemoryDurableStateStore::new_import_target(pin.clone(), context.writer_fence()).unwrap();
    let foreign_token = foreign
        .begin_portable_snapshot(&context, pin.domain)
        .unwrap();
    assert!(matches!(
        store.finish_import(&context, pin.domain, &pin, install.next(), &foreign_token),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        store.finish_import(&context, pin.domain, &pin, install.next(), &token),
        DurableCommitOutcome::Committed
    );
    assert!(matches!(
        store.get_namespace_lifecycle(&context, pin.domain).unwrap(),
        NamespaceLifecycle::CompleteInactive { .. }
    ));
    assert_eq!(
        store.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    store.set_active_writer_fence(operation(8).writer_fence());
    assert!(matches!(
        store.get_namespace_lifecycle(&context, pin.domain),
        Err(DurableReadError::WriterFenced { .. })
    ));
    assert!(
        store
            .get_namespace_lifecycle(&operation(8), pin.domain)
            .is_ok()
    );
}

#[test]
fn inactive_import_memory_ordinary_binding_progress_conflict_and_deadline_refuse_atomically() {
    let pin: ImportBinding = binding(3);
    let context: DurableOperationContext = operation(7);
    let ordinary: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(pin.domain, context.writer_fence());
    assert!(matches!(
        ordinary.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        ordinary
            .get_namespace_lifecycle(&context, pin.domain)
            .unwrap(),
        NamespaceLifecycle::Ordinary
    );
    assert_eq!(
        ordinary.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Committed
    );
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_import_target(pin.clone(), context.writer_fence()).unwrap();
    let mut wrong = pin.clone();
    wrong.cut_digest = digest(99);
    assert!(matches!(
        store.begin_import(&context, pin.domain, &wrong, initial().accumulator),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let first: ImportBatch = batch(&pin, &initial(), vec![state(b"a", Some(b"first"))]);
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &first),
        DurableCommitOutcome::Committed
    );
    let bad: ImportBatch = batch(
        &pin,
        first.next(),
        vec![
            state(b"a", Some(b"different")),
            state(b"b", Some(b"must-not-land")),
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &bad),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(
        store.read_import_progress(&context, pin.domain).unwrap(),
        Some(first.next().clone())
    );
    assert!(
        store
            .get_versioned_durable(&context, pin.domain, b"b")
            .unwrap()
            .value()
            .is_none()
    );
    store.set_time(10_000);
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &first),
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
}

#[test]
fn new_bound_from_import_batches_reconstructs_exact_rows_across_batches() {
    let pin: ImportBinding = binding(5);
    let id: ObjectId = ObjectId::new([21; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(3).unwrap(),
        digest(40),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        17,
        digest(41),
    );
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([44; 32]).unwrap(),
        digest(45),
        vec![0x71; 6],
    )
    .unwrap();
    let first: ImportBatch = batch(
        &pin,
        &initial(),
        vec![state(b"a", Some(b"first")), state(b"z", None)],
    );
    let second: ImportBatch = batch(
        &pin,
        first.next(),
        vec![
            ImportRow::ObjectVersion(version.clone()),
            ImportRow::ObjectHead {
                object_id: id,
                head: ImportObjectHead::Current {
                    object_version: version.object_version(),
                    digest: version.digest(),
                    owner_projection: Default::default(),
                    routing_projection: Default::default(),
                },
            },
            ImportRow::Receipt(receipt.clone()),
        ],
    );
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound_from_import_batches(
        &pin,
        WriterFenceGeneration::new(9).unwrap(),
        &[first, second],
    )
    .unwrap();
    let context: DurableOperationContext = operation(9);
    assert_eq!(
        store.get_namespace_lifecycle(&context, pin.domain).unwrap(),
        NamespaceLifecycle::Ordinary
    );
    assert_eq!(
        store.get_outgoing_barrier(&context, pin.domain).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.get_successor_serving(&context, pin.domain).unwrap(),
        SuccessorServingSlot::Inactive
    );
    assert!(store.outgoing_seal_repository().is_some());
    assert!(store.successor_serving_repository().is_none());
    assert_eq!(
        store
            .get_versioned_durable(&context, pin.domain, b"a")
            .unwrap()
            .value(),
        Some(b"first".as_slice())
    );
    let tombstone = store
        .get_versioned_durable(&context, pin.domain, b"z")
        .unwrap();
    assert!(tombstone.value().is_none());
    assert_ne!(tombstone.revision(), StateRevision::INITIAL);
    assert_eq!(
        store
            .get_object_version(&context, pin.domain, id, version.object_version())
            .unwrap(),
        Some(version.clone())
    );
    assert!(matches!(
        store.get_object_head(&context, pin.domain, id).unwrap(),
        DurableObjectHead::Current { .. }
    ));
    assert_eq!(
        store
            .get_request_receipt(&context, pin.domain, receipt.request_id())
            .unwrap(),
        Some(receipt)
    );
    let data = store.inner.read().unwrap();
    assert_eq!(data.receipts.len(), 1);
    assert!(data.outboxes.is_empty());
    assert!(data.deliveries.is_empty());
    assert!(data.successor_namespace_validator.is_none());
    assert!(data.mutation_sequences.is_empty());
    assert_eq!(
        data.state_domains[pin.domain.as_bytes()][b"a".as_slice()].revision,
        StateRevision::new(1)
    );
    assert_eq!(
        data.state_domains[pin.domain.as_bytes()][b"z".as_slice()].revision,
        StateRevision::new(1)
    );
}

#[test]
fn new_bound_from_import_batches_rejects_binding_mismatch_and_short_count() {
    let pin: ImportBinding = binding(2);
    let first: ImportBatch = batch(&pin, &initial(), vec![state(b"a", Some(b"x"))]);
    let mut wrong_binding: ImportBinding = pin.clone();
    wrong_binding.cut_digest = digest(77);
    let mismatched: ImportBatch =
        batch(&wrong_binding, first.next(), vec![state(b"b", Some(b"y"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first.clone(), mismatched],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportBindingMismatch
    );
    let second_bad_expected: ImportBatch = batch(&pin, &initial(), vec![state(b"b", Some(b"y"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first.clone(), second_bad_expected],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
}

#[test]
fn new_bound_from_import_batches_accepts_a_three_batch_chain_with_distinct_accumulators() {
    let pin: ImportBinding = binding(3);
    let first: ImportBatch =
        batch_with_digest(&pin, &initial(), 70, 80, vec![state(b"a", Some(b"1"))]);
    let second: ImportBatch =
        batch_with_digest(&pin, first.next(), 71, 81, vec![state(b"b", Some(b"2"))]);
    let third: ImportBatch =
        batch_with_digest(&pin, second.next(), 72, 82, vec![state(b"c", Some(b"3"))]);
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound_from_import_batches(
        &pin,
        WriterFenceGeneration::new(1).unwrap(),
        &[first, second, third],
    )
    .unwrap();
    let context: DurableOperationContext = operation(1);
    assert_eq!(
        store
            .get_versioned_durable(&context, pin.domain, b"a")
            .unwrap()
            .value(),
        Some(b"1".as_slice())
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, pin.domain, b"b")
            .unwrap()
            .value(),
        Some(b"2".as_slice())
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, pin.domain, b"c")
            .unwrap()
            .value(),
        Some(b"3".as_slice())
    );
}

#[test]
fn new_bound_from_import_batches_rejects_substituted_accumulator_mid_chain() {
    let pin: ImportBinding = binding(2);
    let first: ImportBatch =
        batch_with_digest(&pin, &initial(), 70, 80, vec![state(b"a", Some(b"1"))]);
    // Structurally plausible (ordinal and batch digest both correct) but the
    // accumulator is a substituted value, not the real chained next().
    let mut forged_expected: ImportProgress = first.next().clone();
    forged_expected.accumulator = digest(0xFE);
    let second: ImportBatch = batch_with_digest(
        &pin,
        &forged_expected,
        71,
        81,
        vec![state(b"b", Some(b"2"))],
    );
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first, second],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
}

#[test]
fn new_bound_from_import_batches_rejects_reversed_locator_across_batch_boundary() {
    let pin: ImportBinding = binding(2);
    let first: ImportBatch =
        batch_with_digest(&pin, &initial(), 70, 80, vec![state(b"m", Some(b"1"))]);
    // The progress chain is genuinely valid; only the row locator order
    // regresses across the batch boundary ("a" sorts before "m").
    let second: ImportBatch =
        batch_with_digest(&pin, first.next(), 71, 81, vec![state(b"a", Some(b"2"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first, second],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
}

#[test]
fn new_bound_from_import_batches_rejects_exact_duplicate_row_at_valid_next_progress() {
    let pin: ImportBinding = binding(2);
    let first: ImportBatch =
        batch_with_digest(&pin, &initial(), 70, 80, vec![state(b"a", Some(b"1"))]);
    // The progress chain is genuinely valid; the second batch repeats a
    // byte-identical row (same key, same value) from the first batch.
    let second: ImportBatch =
        batch_with_digest(&pin, first.next(), 71, 81, vec![state(b"a", Some(b"1"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first, second],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
}

#[test]
fn new_bound_from_import_batches_reuses_head_and_provenance_validation_across_batches() {
    let pin: ImportBinding = binding(2);
    let id: ObjectId = ObjectId::new([22; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(3).unwrap(),
        digest(40),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        17,
        digest(41),
    );
    let first: ImportBatch = batch(
        &pin,
        &initial(),
        vec![ImportRow::ObjectVersion(version.clone())],
    );
    let correct: ImportRow = ImportRow::ObjectHead {
        object_id: id,
        head: ImportObjectHead::Tombstoned {
            last_object_version: version.object_version(),
        },
    };
    let second: ImportBatch = batch(&pin, first.next(), vec![correct]);
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound_from_import_batches(
        &pin,
        WriterFenceGeneration::new(1).unwrap(),
        &[first.clone(), second],
    )
    .unwrap();
    assert!(matches!(
        store.get_object_head(&operation(1), pin.domain, id).unwrap(),
        DurableObjectHead::Tombstoned { last_object_version, .. } if last_object_version == version.object_version()
    ));
    let wrong: ImportBatch = batch(
        &pin,
        first.next(),
        vec![ImportRow::ObjectHead {
            object_id: id,
            head: ImportObjectHead::Tombstoned {
                last_object_version: DurableObjectVersion::new(2).unwrap(),
            },
        }],
    );
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first, wrong],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
    let mut foreign: ImportBinding = pin.clone();
    foreign.context.chain_id = ChainId::new("foreign-import-chain").unwrap();
    let bad_provenance: ImportBatch = batch(
        &foreign,
        &initial(),
        vec![ImportRow::ObjectVersion(version)],
    );
    // State rows precede versions globally, so use a receipt after the
    // foreign-provenance version to make the provenance check decisive.
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x44; 32]).unwrap(),
        digest(0x45),
        vec![1],
    )
    .unwrap();
    let final_row: ImportBatch = batch(
        &foreign,
        bad_provenance.next(),
        vec![ImportRow::Receipt(receipt)],
    );
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &foreign,
            WriterFenceGeneration::new(1).unwrap(),
            &[bad_provenance, final_row],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportBindingMismatch
    );
}

#[test]
fn new_bound_from_import_batches_rejects_reordered_duplicated_and_conflicting_batches() {
    let pin: ImportBinding = binding(2);
    let first: ImportBatch = batch(&pin, &initial(), vec![state(b"a", Some(b"x"))]);
    let second: ImportBatch = batch(&pin, first.next(), vec![state(b"b", Some(b"y"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[second.clone(), first.clone()],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first.clone(), first.clone()],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
    let conflicting: ImportBatch = batch(&pin, first.next(), vec![state(b"a", Some(b"different"))]);
    assert_eq!(
        MemoryDurableStateStore::new_bound_from_import_batches(
            &pin,
            WriterFenceGeneration::new(1).unwrap(),
            &[first, conflicting],
        )
        .unwrap_err(),
        DurableCommitRejection::ImportConflict
    );
}
