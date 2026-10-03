use super::*;
use crate::fast_path::tests::{
    CountingSigner, RetentionReplica, full_snapshot, logical_replica, logical_replica_bound,
    seal_namespace,
};
use crate::ordered_economics::{AdmissionClosureRecord, encode_admission_closure_record};
use crate::paid_execution::tests::{context, domain, protocol, resolver};
use protocol_types::{HashAlgorithmId, SignatureSchemeId, ValidatorId};
use runtime::DurableDomainStateStore;
use std::cell::Cell;

fn identity() -> FrozenFrontierIdentity {
    FrozenFrontierIdentity {
        chain_id: ChainId::new("frontier-codec-test").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(2),
        domain: AtomicityDomainId::new([1; 32]).unwrap(),
        closure_request_id: [2; 32],
        closure_height: 7,
        entry_count: 1,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
    }
}

#[test]
fn cursor_and_final_records_are_canonical_and_bound_to_one_identity() {
    let cursor = FrontierCursor {
        identity: identity(),
        last_request_id: [4; 32],
    };
    let cursor_bytes: Vec<u8> = encode_cursor(&cursor).unwrap();
    assert_eq!(decode_cursor(&cursor_bytes).unwrap(), cursor);

    let vote = FrozenFrontierVote {
        identity: cursor.identity.clone(),
        validator: ValidatorId::new([5; 32]),
        signature_scheme: SignatureSchemeId::Ed25519,
        signature: vec![6; 64],
    };
    let final_record = FinalFrontier {
        identity: cursor.identity.clone(),
        vote,
    };
    let final_bytes: Vec<u8> = encode_final(&final_record).unwrap();
    assert_eq!(decode_final(&final_bytes).unwrap(), final_record);
    let mut corrupt: Vec<u8> = final_bytes;
    corrupt[0] ^= 1;
    assert!(decode_final(&corrupt).is_err());
}

#[test]
fn cursors_cannot_be_empty_or_conflicting() {
    let mut zero_count = identity();
    zero_count.entry_count = 0;
    assert!(
        encode_cursor(&FrontierCursor {
            identity: zero_count,
            last_request_id: [4; 32],
        })
        .is_err()
    );
    assert!(
        encode_cursor(&FrontierCursor {
            identity: identity(),
            last_request_id: [0; 32],
        })
        .is_err()
    );
    let mut final_record = FinalFrontier {
        identity: identity(),
        vote: FrozenFrontierVote {
            identity: identity(),
            validator: ValidatorId::new([5; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![6; 64],
        },
    };
    final_record.vote.identity.closure_height += 1;
    assert!(encode_final(&final_record).is_err());
}

fn stage_closure(replica: &RetentionReplica) -> Vec<u8> {
    let record: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0x55; 32],
        closed_at_block_height: 3,
    };
    let closure_key: Vec<u8> =
        admission_closure_key(protocol().chain_id(), protocol().epoch()).unwrap();
    replica.put_row(
        closure_key.clone(),
        encode_admission_closure_record(&record).unwrap(),
    );
    closure_key
}

#[test]
fn advance_frozen_frontier_stops_before_signing_once_sealed() {
    let unsealed: RetentionReplica = logical_replica();
    stage_closure(&unsealed);
    let unsealed_step: FrozenFrontierStep = advance_frozen_frontier(
        &unsealed.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &unsealed.signer,
    )
    .unwrap();
    assert!(matches!(unsealed_step, FrozenFrontierStep::Finalized(_)));

    let sealed: RetentionReplica = logical_replica_bound();
    stage_closure(&sealed);
    seal_namespace(&sealed.store, domain());
    let before: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    let signer: CountingSigner<'_> = CountingSigner {
        inner: &sealed.signer,
        calls: Cell::new(0),
    };
    let result: Result<FrozenFrontierStep, FrozenFrontierError> = advance_frozen_frontier(
        &sealed.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &signer,
    );
    assert!(
        matches!(
            &result,
            Err(FrozenFrontierError::Node(
                NodeCoreError::PersistenceInvariant(
                    "outgoing epoch is sealed; live work is forbidden"
                )
            ))
        ),
        "unexpected sealed frontier result: {result:?}"
    );
    assert_eq!(signer.calls.get(), 0);
    let final_key: Vec<u8> = key(
        protocol().chain_id(),
        protocol().epoch(),
        FRONTIER_FINAL_PREFIX,
    )
    .unwrap();
    let cursor_key: Vec<u8> = key(
        protocol().chain_id(),
        protocol().epoch(),
        FRONTIER_PROGRESS_PREFIX,
    )
    .unwrap();
    for row_key in [final_key, cursor_key] {
        assert!(
            sealed
                .store
                .get_versioned_durable(&context(), domain(), &row_key)
                .unwrap()
                .value()
                .is_none()
        );
    }
    let after: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    assert_eq!(
        before, after,
        "a sealed fresh advance must write nothing at all, not merely the named final/cursor rows"
    );
}

#[test]
fn advance_frozen_frontier_replays_the_retained_final_vote_then_stops_once_sealed() {
    let replica: RetentionReplica = logical_replica_bound();
    stage_closure(&replica);
    let first: FrozenFrontierStep = advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &replica.signer,
    )
    .unwrap();
    let vote: FrozenFrontierVote = match first {
        FrozenFrontierStep::Finalized(boxed) => *boxed,
        FrozenFrontierStep::Advanced { .. } => panic!("expected finalized"),
    };
    let replay_signer: CountingSigner<'_> = CountingSigner {
        inner: &replica.signer,
        calls: Cell::new(0),
    };
    let replayed: FrozenFrontierStep = advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &replay_signer,
    )
    .unwrap();
    match replayed {
        FrozenFrontierStep::Finalized(boxed) => assert_eq!(*boxed, vote),
        FrozenFrontierStep::Advanced { .. } => panic!("retained replay must return the same vote"),
    }
    assert_eq!(replay_signer.calls.get(), 0);
    seal_namespace(&replica.store, domain());
    let before: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&replica.store);
    let sealed_signer: CountingSigner<'_> = CountingSigner {
        inner: &replica.signer,
        calls: Cell::new(0),
    };
    let result: Result<FrozenFrontierStep, FrozenFrontierError> = advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &sealed_signer,
    );
    assert!(
        matches!(
            &result,
            Err(FrozenFrontierError::Node(
                NodeCoreError::PersistenceInvariant(
                    "outgoing epoch is sealed; live work is forbidden"
                )
            ))
        ),
        "unexpected sealed replay result: {result:?}"
    );
    assert_eq!(sealed_signer.calls.get(), 0);
    let after: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&replica.store);
    assert_eq!(
        before, after,
        "a sealed retained-replay attempt must write nothing and must not re-expose the final vote"
    );
}
