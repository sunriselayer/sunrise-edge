use super::*;
use crate::portable::DurablePortableSnapshotRepository;
use protocol_types::HashAlgorithmId;

fn domain(byte: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([byte; 32]).unwrap()
}

fn context(fence: u64, deadline: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(deadline).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    )
}

fn sample_request(byte: u8) -> [u8; 32] {
    let mut request = [byte; 32];
    request[0] |= 0x80;
    request
}

fn sample_sealed(byte: u8) -> SealBarrier {
    SealBarrier {
        outgoing_epoch: Epoch::new(1),
        request: sample_request(byte),
        height: 7,
        block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
        target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(2); 32]),
        transition_history: TransitionHistoryState::Virgin,
    }
}

#[test]
fn seal_barrier_round_trip_rejects_low_bit_and_corrupt_bytes() {
    let sealed = sample_sealed(5);
    let encoded = encode_seal_barrier(&sealed).unwrap();
    assert_eq!(decode_seal_barrier(&encoded).unwrap(), sealed);

    let mut no_high_bit = sealed;
    no_high_bit.request[0] &= 0x7F;
    assert_eq!(
        encode_seal_barrier(&no_high_bit),
        Err(RuntimeError::InvalidOutgoingBarrier)
    );

    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        decode_seal_barrier(&corrupt),
        Err(RuntimeError::InvalidOutgoingBarrier)
    );
}

fn minimal_invocation(
    domain: AtomicityDomainId,
    sealed: &SealBarrier,
) -> DurableInvocationTransaction {
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    DurableInvocationTransaction::new(domain, None, DurableObjectChanges::empty(), receipt, None)
        .unwrap()
}

#[test]
fn memory_store_starts_unsealed_and_requires_explicit_bound_domain() {
    let selected = domain(10);
    let bound =
        MemoryDurableStateStore::new_bound(selected, WriterFenceGeneration::new(1).unwrap());
    assert_eq!(
        bound.get_outgoing_barrier(&context(1, 1_000), selected),
        Ok(OutgoingBarrier::Unsealed)
    );

    let unbound = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let token = unbound
        .begin_portable_snapshot(&context(1, 1_000), selected)
        .unwrap();
    let sealed = sample_sealed(11);
    let invocation = minimal_invocation(selected, &sealed);
    assert_eq!(
        unbound.commit_seal_completion(&context(1, 1_000), &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch)
    );
}

#[test]
fn memory_seal_completion_seals_barrier_and_blocks_both_ordinary_ports() {
    let selected = domain(20);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = MemoryDurableStateStore::new_bound(selected, fence);
    let operation = context(1, 1_000);
    let token = store.begin_portable_snapshot(&operation, selected).unwrap();
    let sealed = sample_sealed(21);
    let invocation = minimal_invocation(selected, &sealed);

    assert_eq!(
        store.commit_seal_completion(&operation, &token, invocation.clone(), sealed),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.get_outgoing_barrier(&operation, selected),
        Ok(OutgoingBarrier::Sealed(sealed))
    );

    let retry_token = store.begin_portable_snapshot(&operation, selected).unwrap();
    assert_eq!(
        store.commit_seal_completion(&operation, &retry_token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );

    let ordinary_transaction = AtomicStateTransaction::new(
        selected,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"key".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"key".to_vec(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&operation, ordinary_transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );

    let other_sealed = sample_sealed(22);
    let other_invocation = minimal_invocation(selected, &other_sealed);
    assert_eq!(
        store.commit_invocation(&operation, other_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
}

#[test]
fn memory_seal_completion_rejects_stale_token_and_receipt_mismatch() {
    let selected = domain(30);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = MemoryDurableStateStore::new_bound(selected, fence);
    let operation = context(1, 1_000);
    let stale_token = store.begin_portable_snapshot(&operation, selected).unwrap();

    let unrelated = AtomicStateTransaction::new(
        selected,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"other".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"other".to_vec(), StateMutation::Put(vec![9])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&operation, unrelated),
        DurableCommitOutcome::Committed
    );

    let sealed = sample_sealed(31);
    let invocation = minimal_invocation(selected, &sealed);
    assert_eq!(
        store.commit_seal_completion(&operation, &stale_token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );

    let fresh_token = store.begin_portable_snapshot(&operation, selected).unwrap();
    let mismatched_request_id = DurableRequestId::new([0x55; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xCD; 32]);
    let mismatched_receipt =
        DurableRequestReceipt::new(mismatched_request_id, event_digest, vec![2]).unwrap();
    let mismatched_invocation = DurableInvocationTransaction::new(
        selected,
        None,
        DurableObjectChanges::empty(),
        mismatched_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_completion(&operation, &fresh_token, mismatched_invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
}

#[test]
fn memory_seal_completion_rejects_nonempty_outbox() {
    let selected = domain(40);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = MemoryDurableStateStore::new_bound(selected, fence);
    let operation = context(1, 1_000);
    let token = store.begin_portable_snapshot(&operation, selected).unwrap();

    let sealed = sample_sealed(41);
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]),
        vec![9],
    )
    .unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
    let invocation = DurableInvocationTransaction::new(
        selected,
        None,
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_completion(&operation, &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
}

#[test]
fn memory_seal_retention_commits_before_seal_and_is_blocked_after() {
    let selected = domain(50);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = MemoryDurableStateStore::new_bound(selected, fence);
    let operation = context(1, 1_000);
    let token = store.begin_portable_snapshot(&operation, selected).unwrap();
    let retention = AtomicStateTransaction::new(
        selected,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"cut".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"cut".to_vec(), StateMutation::Put(vec![3])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_retention(&operation, &token, retention),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.get_outgoing_barrier(&operation, selected),
        Ok(OutgoingBarrier::Unsealed)
    );

    let completion_token = store.begin_portable_snapshot(&operation, selected).unwrap();
    let sealed = sample_sealed(51);
    let invocation = minimal_invocation(selected, &sealed);
    assert_eq!(
        store.commit_seal_completion(&operation, &completion_token, invocation, sealed),
        DurableCommitOutcome::Committed
    );

    let after_token = store.begin_portable_snapshot(&operation, selected).unwrap();
    let retention_after_seal = AtomicStateTransaction::new(
        selected,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"cut".to_vec(), StateRevision::new(1)).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"cut".to_vec(), StateMutation::Put(vec![4])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_retention(&operation, &after_token, retention_after_seal),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
}

#[test]
fn outgoing_barrier_round_trip_rejects_phase_record_mismatch() {
    let unsealed = OutgoingBarrier::Unsealed;
    let encoded_unsealed = encode_outgoing_barrier(&unsealed).unwrap();
    assert_eq!(
        decode_outgoing_barrier(&encoded_unsealed).unwrap(),
        unsealed
    );

    let sealed = OutgoingBarrier::Sealed(sample_sealed(6));
    let encoded_sealed = encode_outgoing_barrier(&sealed).unwrap();
    assert_eq!(decode_outgoing_barrier(&encoded_sealed).unwrap(), sealed);

    let mut extra_row = encoded_unsealed.clone();
    extra_row.push(0);
    assert_eq!(
        decode_outgoing_barrier(&extra_row),
        Err(RuntimeError::InvalidOutgoingBarrier)
    );
}

#[test]
fn outgoing_barrier_unsealed_encodes_to_stable_bytes() {
    let encoded = encode_outgoing_barrier(&OutgoingBarrier::Unsealed).unwrap();
    let expected: Vec<u8> = vec![
        0x53, 0x4E, 0x52, 0x45, // magic "SNRE"
        0xD3, 0x64, // type id 0x64D3, little-endian
        0x01, 0x00, // version 1
        0x02, 0x00, // field count 2
        0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, // field 1: phase u16 = 1 (Unsealed)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // field 2: zero-length sealed record
    ];
    assert_eq!(encoded, expected);
}

#[test]
fn memory_outgoing_seal_repository_getter_requires_explicit_bound_domain() {
    let selected = domain(70);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let bound = MemoryDurableStateStore::new_bound(selected, fence);
    assert!(bound.outgoing_seal_repository().is_some());

    let unbound = MemoryDurableStateStore::new(fence);
    assert!(unbound.outgoing_seal_repository().is_none());
}

#[test]
fn outgoing_barrier_sealed_encodes_to_stable_bytes() {
    let sealed = sample_sealed(6);
    let sealed_record_bytes = encode_seal_barrier(&sealed).unwrap();
    let encoded = encode_outgoing_barrier(&OutgoingBarrier::Sealed(sealed)).unwrap();

    let mut expected: Vec<u8> = vec![
        0x53, 0x4E, 0x52, 0x45, // magic "SNRE"
        0xD3, 0x64, // type id 0x64D3, little-endian
        0x01, 0x00, // version 1
        0x02, 0x00, // field count 2
    ];
    expected.extend_from_slice(&[0x01, 0x00, 0x02, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&2u16.to_le_bytes());
    expected.extend_from_slice(&[0x02, 0x00]);
    expected.extend_from_slice(
        &u32::try_from(sealed_record_bytes.len())
            .unwrap()
            .to_le_bytes(),
    );
    expected.extend_from_slice(&sealed_record_bytes);

    assert_eq!(encoded, expected);
}

#[test]
fn seal_barrier_encodes_to_stable_bytes() {
    let sealed = sample_sealed(5);
    let encoded = encode_seal_barrier(&sealed).unwrap();

    let digest_frame = |fill: u8| -> Vec<u8> {
        let mut frame: Vec<u8> = vec![
            0x53, 0x4E, 0x52, 0x45, // magic "SNRE"
            0x03, 0x01, // type id 0x0103 (Digest32), little-endian
            0x01, 0x00, // version 1
            0x02, 0x00, // field count 2
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, // field 1: algorithm id = 1 (Sha2_256)
            0x02, 0x00, 0x20, 0x00, 0x00, 0x00, // field 2 header: 32-byte digest
        ];
        frame.extend_from_slice(&[fill; 32]);
        frame
    };
    let block_digest_frame = digest_frame(6);
    let target_digest_frame = digest_frame(7);
    let mut request = [0x05u8; 32];
    request[0] = 0x85;

    let mut expected: Vec<u8> = vec![
        0x53, 0x4E, 0x52, 0x45, // magic "SNRE"
        0xD4, 0x64, // type id 0x64D4, little-endian
        0x01, 0x00, // version 1
        0x06, 0x00, // field count 6
    ];
    expected.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&1u64.to_le_bytes());
    expected.extend_from_slice(&[0x02, 0x00, 0x20, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&request);
    expected.extend_from_slice(&[0x03, 0x00, 0x08, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&7u64.to_le_bytes());
    expected.extend_from_slice(&[0x04, 0x00, 0x38, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&block_digest_frame);
    expected.extend_from_slice(&[0x05, 0x00, 0x38, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&target_digest_frame);
    expected.extend_from_slice(&[0x06, 0x00, 0x02, 0x00, 0x00, 0x00]);
    expected.extend_from_slice(&1u16.to_le_bytes());

    assert_eq!(encoded, expected);
}

#[test]
fn memory_seal_completion_persists_legal_empty_outbox_batch() {
    let selected = domain(90);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = MemoryDurableStateStore::new_bound(selected, fence);
    let operation = context(1, 1_000);
    let token = store.begin_portable_snapshot(&operation, selected).unwrap();

    let sealed = sample_sealed(91);
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xAA; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, Vec::new()).unwrap();
    let invocation = DurableInvocationTransaction::new(
        selected,
        None,
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap();

    assert_eq!(
        store.commit_seal_completion(&operation, &token, invocation, sealed),
        DurableCommitOutcome::Committed
    );

    let data = store.inner.read().unwrap();
    let request_key = (*selected.as_bytes(), *request_id.as_bytes());
    let persisted_outbox = data
        .outboxes
        .get(&request_key)
        .expect("empty outbox batch is persisted, not silently dropped");
    assert!(persisted_outbox.messages().is_empty());
    let delivery = data
        .deliveries
        .get(&request_key)
        .expect("delivery row is persisted for the empty batch");
    assert!(delivery.completed);
}

#[test]
fn memory_claim_and_ack_reject_pending_outbox_after_seal() {
    for acknowledged_before_corruption in [false, true] {
        let selected = domain(100);
        let fence = WriterFenceGeneration::new(1).unwrap();
        let store = MemoryDurableStateStore::new_bound(selected, fence);
        let operation = context(1, 1_000);

        let pending_request_id = DurableRequestId::new([0x11; 32]).unwrap();
        let pending_event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
        let pending_receipt =
            DurableRequestReceipt::new(pending_request_id, pending_event_digest, vec![1]).unwrap();
        let message = DurableOutboxMessage::new(
            Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
            vec![9],
        )
        .unwrap();
        let pending_outbox =
            DurableOutboxBatch::new(pending_request_id, pending_event_digest, vec![message])
                .unwrap();
        let pending_invocation = DurableInvocationTransaction::new(
            selected,
            None,
            DurableObjectChanges::empty(),
            pending_receipt,
            Some(pending_outbox),
        )
        .unwrap();
        assert_eq!(
            store.commit_invocation(&operation, pending_invocation),
            DurableCommitOutcome::Committed
        );

        let claim_request = RequestOutboxClaimRequest::new(
            selected,
            OutboxRequestId::new(*pending_request_id.as_bytes()).unwrap(),
            1_000,
            DurableOutboxLeaseId::new([0x44; 32]).unwrap(),
            2_000,
        )
        .unwrap();
        assert!(matches!(
            store.claim_request_outbox(&operation, claim_request),
            DurableOutboxClaimOutcome::Claimed(_)
        ));
        let acknowledgement = DurableOutboxAcknowledgement::new(
            selected,
            OutboxRequestId::new(*pending_request_id.as_bytes()).unwrap(),
            0,
            claim_request.lease_id(),
        );
        if acknowledged_before_corruption {
            assert_eq!(
                store.acknowledge_outbox(&operation, acknowledgement),
                DurableOutboxAcknowledgementOutcome::Acknowledged
            );
        }
        let token = store.begin_portable_snapshot(&operation, selected).unwrap();
        let sealed = sample_sealed(101);
        let invocation = minimal_invocation(selected, &sealed);
        assert_eq!(
            store.commit_seal_completion(&operation, &token, invocation, sealed),
            DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
        );
        assert_eq!(
            store.begin_portable_snapshot(&operation, selected).unwrap(),
            token,
            "even fully ACKed nonempty outbox forbids Seal, without mutation"
        );

        // Deliberate at-rest corruption, not a production Seal or an authority
        // bypass: the legitimate completion above correctly rejected this state.
        store.inner.write().unwrap().outgoing_barrier = OutgoingBarrier::Sealed(sealed);
        assert_eq!(
            store.claim_request_outbox(&operation, claim_request),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::InvalidPersistedState)
        );
        assert_eq!(
            store.acknowledge_outbox(&operation, acknowledgement),
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            )
        );
    }
}
