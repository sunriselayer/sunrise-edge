//! DR-0149 focused read-only preparation and independent apply evidence.
use super::tests::certified_multi_escrow_inventory::{
    Voter, apply_escrow, build_final_claim, build_split_claim, build_validator_set,
    build_zero_claim, certify, current_row, four_sorted_voters, install_all, prepare_vote,
    sign_claim, sign_leg_with_key,
};
use super::*;
use crate::paid_execution::tests::{
    FIRST_PAID_NONCE, Fixture, PaidCall, base_policy, context, domain, entry, key, memory_store,
    next_nonce, paid_call_with_access, protocol, refund_account, resolver, sender,
};
use execution::LocalWasmExecutionEngine;
use execution::local_execution::{decode_signed_local_execution, encode_signed_local_execution};
use execution::paid_execution::ReservationAccessKind;
use objects::AccessMode;
use runtime::{
    DurableDomainStateStore, DurableObjectHead, DurableRequestId, DurableRequestReceipt,
    DurableStateKeyScanner, MemoryBlobStore, MemoryDurableStateStore, StateKeyPage, StateKeyScan,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::num::NonZeroUsize;

const ESCROW: [u8; 32] = [0xB1; 32];

fn install_certified<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (Fixture, Vec<Voter>, BondResourceId) {
    let voters: Vec<Voter> = four_sorted_voters();
    let entries: Vec<crate::fast_path::FastPathValidatorEntry> =
        voters.iter().map(|voter| voter.entry.clone()).collect();
    let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(store, &entries);
    let co1: MemoryDurableStateStore = memory_store();
    let co2: MemoryDurableStateStore = memory_store();
    install_all(&co1, &entries);
    install_all(&co2, &entries);
    let signed: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &policy,
            request: ESCROW[0],
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let votes: Vec<consensus::FastVote> = vec![
        prepare_vote(store, &policy, &voters[0], &signed),
        prepare_vote(&co1, &policy, &voters[1], &signed),
        prepare_vote(&co2, &policy, &voters[2], &signed),
    ];
    apply_escrow(
        store,
        &policy,
        &signed,
        &certify(&build_validator_set(&entries), &votes),
    );
    let resource_id: BondResourceId = crate::fast_path::fee_resource_id(&policy).unwrap();
    (fixture, voters, resource_id)
}

type StateEntry = (Vec<u8>, StateRevision, Option<Vec<u8>>);

fn state_snapshot<S: DurableStateKeyScanner>(store: &S) -> Vec<StateEntry> {
    let mut result: Vec<StateEntry> = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let scan: StateKeyScan =
            StateKeyScan::new(b"se/".to_vec(), after, NonZeroUsize::new(128).unwrap()).unwrap();
        let page: StateKeyPage = store
            .scan_durable_keys(&context(), domain(), &scan)
            .unwrap();
        for key in page.keys() {
            let value: VersionedStateValue = store
                .get_versioned_durable(&context(), domain(), key)
                .unwrap();
            result.push((
                key.clone(),
                value.revision(),
                value.value().map(<[u8]>::to_vec),
            ));
        }
        after = page.continuation_cursor().map(<[u8]>::to_vec);
        if after.is_none() {
            return result;
        }
    }
}

fn request_receipt<S: StructuredDurableDomainStateStore>(
    store: &S,
    request: [u8; 32],
) -> Option<DurableRequestReceipt> {
    store
        .get_request_receipt(
            &context(),
            domain(),
            DurableRequestId::new(request).unwrap(),
        )
        .unwrap()
}

fn prepare_from_signed<S: StructuredDurableDomainStateStore>(
    store: &S,
    bytes: &[u8],
    voter: &Voter,
) -> Result<PreparedFeeClaim, FeeClaimError> {
    let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(bytes).unwrap();
    let signed_leg: Option<&[u8]> = match &signed.intent.operation {
        FeeClaimOperation::ZeroShare => None,
        FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } => {
            Some(leg)
        }
    };
    prepare_fee_claim(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &LocalWasmExecutionEngine::new(),
        FeeClaimPreparationRequest {
            escrow_request_id: signed.intent.escrow_request_id,
            request_id: signed.intent.request_id,
            validator_id: signed.intent.validator_id,
            claimant_public_key: voter.entry.public_key.as_slice().try_into().unwrap(),
            recipient: signed.intent.recipient,
            signed_leg,
        },
        12,
    )
}

fn apply<S: StructuredDurableDomainStateStore>(
    store: &S,
    bytes: &[u8],
) -> Result<NodeOutput, FeeClaimError> {
    handle_fee_claim(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &LocalWasmExecutionEngine::new(),
        bytes,
        12,
    )
}

struct ParityEvidence {
    signed: Vec<Vec<u8>>,
    outputs: Vec<NodeOutput>,
    final_row: Vec<u8>,
    payout: ObjectRef,
    nonce: u64,
}

fn exercise_preparation<S: DurableStateKeyScanner>(store: &S) -> ParityEvidence {
    let (fixture, voters, resource): (Fixture, Vec<Voter>, BondResourceId) =
        install_certified(store);
    let inspection: FeeClaimInspection = inspect_fee_claim(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        ESCROW,
        voters[0].entry.id,
        sender(),
        &base_policy(),
    )
    .unwrap();
    assert_eq!(inspection.entitlement.kind, Some(FeeClaimKind::Split));
    let view: &FeeClaimExecutionView = inspection.execution.as_ref().unwrap();
    assert_eq!(view.next_nonce, next_nonce(store));
    assert_eq!(
        view.resource.instance,
        execution::local_execution::instance_target(&resolver(), &view.instance).unwrap()
    );
    let initial_head: DurableObjectHead = store
        .get_object_head(&context(), domain(), view.fee_output.id)
        .unwrap();

    let legacy_fixture: Vec<u8> = build_split_claim(
        store,
        &fixture,
        &voters[0],
        resource,
        ESCROW,
        [0xD1; 32],
        next_nonce(store),
        0xE1,
    )
    .signed_bytes;
    let before: Vec<StateEntry> = state_snapshot(store);
    let nonce: u64 = next_nonce(store);
    let prepared: PreparedFeeClaim =
        prepare_from_signed(store, &legacy_fixture, &voters[0]).unwrap();
    assert_eq!(
        prepared.intent,
        decode_signed_fee_claim_intent(&legacy_fixture)
            .unwrap()
            .intent
    );
    let payout: ObjectRef = prepared.expected_payout.clone().unwrap();
    assert_eq!(state_snapshot(store), before);
    assert_eq!(next_nonce(store), nonce);
    assert_eq!(
        store
            .get_object_head(&context(), domain(), view.fee_output.id)
            .unwrap(),
        initial_head
    );
    assert_eq!(
        store
            .get_object_head(&context(), domain(), payout.id)
            .unwrap(),
        DurableObjectHead::Absent
    );
    assert!(request_receipt(store, [0xD1; 32]).is_none());
    let first: Vec<u8> = sign_claim(&voters[0].signing_key, prepared.intent);
    assert_eq!(first, legacy_fixture);
    let first_output: NodeOutput = apply(store, &first).unwrap();
    assert_eq!(current_row(store, ESCROW).1, prepared.next_settlement);
    assert!(prepare_from_signed(store, &first, &voters[0]).is_err());

    let final_fixture: Vec<u8> = build_final_claim(
        store,
        &fixture,
        &voters[1],
        resource,
        ESCROW,
        [0xD2; 32],
        next_nonce(store),
        0xE2,
    );
    let before: Vec<StateEntry> = state_snapshot(store);
    let final_prepared: PreparedFeeClaim =
        prepare_from_signed(store, &final_fixture, &voters[1]).unwrap();
    assert_eq!(
        final_prepared.intent,
        decode_signed_fee_claim_intent(&final_fixture)
            .unwrap()
            .intent
    );
    assert!(final_prepared.expected_payout.is_none());
    assert_eq!(state_snapshot(store), before);
    let second: Vec<u8> = sign_claim(&voters[1].signing_key, final_prepared.intent);
    let second_output: NodeOutput = apply(store, &second).unwrap();
    assert_eq!(current_row(store, ESCROW).1, final_prepared.next_settlement);

    // Zero-share inspection/preparation does not read a current escrow head
    // or nonce, even after the complete fee object has been transferred.
    let zero_view: FeeClaimInspection = inspect_fee_claim(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        ESCROW,
        voters[2].entry.id,
        [0; 32],
        &base_policy(),
    )
    .unwrap();
    assert_eq!(zero_view.entitlement.kind, Some(FeeClaimKind::ZeroShare));
    assert!(zero_view.execution.is_none());
    let zero_fixture: Vec<u8> = build_zero_claim(store, &voters[2], resource, ESCROW, [0xD3; 32]);
    let before: Vec<StateEntry> = state_snapshot(store);
    let nonce: u64 = next_nonce(store);
    let zero_prepared: PreparedFeeClaim =
        prepare_from_signed(store, &zero_fixture, &voters[2]).unwrap();
    assert_eq!(
        zero_prepared.intent,
        decode_signed_fee_claim_intent(&zero_fixture)
            .unwrap()
            .intent
    );
    assert_eq!(state_snapshot(store), before);
    assert_eq!(next_nonce(store), nonce);
    let third: Vec<u8> = sign_claim(&voters[2].signing_key, zero_prepared.intent);
    let third_output: NodeOutput = apply(store, &third).unwrap();
    assert_eq!(next_nonce(store), nonce);
    let discovery: FeeEscrowDiscoveryPage = discover_fee_escrows_page(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(discovery.escrows.len(), 1);
    assert_eq!(discovery.escrows[0].verification.verified_claims, 3);
    assert_eq!(discovery.escrows[0].verification.verified_payouts, 1);
    assert!(discovery.continuation_cursor.is_none());
    assert!(discovery.escrows[0].claimants[0].claimed);
    assert_eq!(discovery.escrows[0].claimants[0].kind, None);
    ParityEvidence {
        signed: vec![first, second, third],
        outputs: vec![first_output, second_output, third_output],
        final_row: current_row(store, ESCROW).0,
        payout,
        nonce,
    }
}

#[test]
fn generic_preparation_zero_split_final_is_read_only_and_matches_independent_apply() {
    exercise_preparation(&memory_store());
}

#[test]
fn prepared_claims_reopen_sqlite_with_exact_replay_and_signed_payout_proof() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf =
        std::env::temp_dir().join(format!("fee-preparation-{}-{unique}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        protocol().chain_id().clone(),
        four_sorted_voters()[0].entry.id,
        domain(),
    );
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let evidence: ParityEvidence = {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace.clone(), fence).unwrap();
        exercise_preparation(&store)
    };
    {
        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace, fence).unwrap();
        let before: Vec<StateEntry> = state_snapshot(&reopened);
        for (signed, output) in evidence.signed.iter().zip(&evidence.outputs) {
            assert_eq!(&apply(&reopened, signed).unwrap(), output);
        }
        assert_eq!(state_snapshot(&reopened), before);
        assert_eq!(current_row(&reopened, ESCROW).0, evidence.final_row);
        assert_eq!(next_nonce(&reopened), evidence.nonce);
        let report: FeeClaimVerificationReport = verify_fee_claim_history(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            &ESCROW,
        )
        .unwrap();
        assert_eq!(report.verified_payouts, 1);
        assert!(matches!(
            reopened
                .get_object_head(&context(), domain(), evidence.payout.id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn preparation_rejects_wrong_key_context_recipient_nonce_leg_and_authority_without_writes() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, voters, resource): (Fixture, Vec<Voter>, BondResourceId) =
        install_certified(&store);
    let fixture_bytes: Vec<u8> = build_split_claim(
        &store,
        &fixture,
        &voters[0],
        resource,
        ESCROW,
        [0xD1; 32],
        next_nonce(&store),
        0xE1,
    )
    .signed_bytes;
    let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(&fixture_bytes).unwrap();
    let FeeClaimOperation::Split { leg, .. } = &signed.intent.operation else {
        panic!("split");
    };
    let before: Vec<StateEntry> = state_snapshot(&store);
    let prepare = |public_key: [u8; 32],
                   recipient: Address,
                   context_view: &PublicationContext,
                   bytes: Option<&[u8]>| {
        prepare_fee_claim(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            context_view,
            &base_policy(),
            &LocalWasmExecutionEngine::new(),
            FeeClaimPreparationRequest {
                escrow_request_id: ESCROW,
                request_id: signed.intent.request_id,
                validator_id: voters[0].entry.id,
                claimant_public_key: public_key,
                recipient,
                signed_leg: bytes,
            },
            12,
        )
    };
    let public_key: [u8; 32] = voters[0].entry.public_key.as_slice().try_into().unwrap();
    assert!(prepare([0xA5; 32], signed.intent.recipient, &protocol(), Some(leg)).is_err());
    assert!(prepare(public_key, Address::new([0; 32]), &protocol(), Some(leg)).is_err());
    let different_valid_recipient: Address =
        Address::new(voters[3].entry.public_key.as_slice().try_into().unwrap());
    assert_ne!(different_valid_recipient, signed.intent.recipient);
    let nonce_before: u64 = next_nonce(&store);
    assert!(
        prepare(
            public_key,
            different_valid_recipient,
            &protocol(),
            Some(leg)
        )
        .is_err()
    );
    assert_eq!(state_snapshot(&store), before);
    assert_eq!(next_nonce(&store), nonce_before);
    assert!(request_receipt(&store, signed.intent.request_id).is_none());
    let future: PublicationContext = PublicationContext::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        Epoch::new(protocol().epoch().get() + 1),
    )
    .unwrap();
    assert!(prepare(public_key, signed.intent.recipient, &future, Some(leg)).is_err());
    assert!(prepare(public_key, signed.intent.recipient, &protocol(), None).is_err());
    assert!(
        prepare(
            public_key,
            signed.intent.recipient,
            &protocol(),
            Some(&leg[..10])
        )
        .is_err()
    );
    let mut stale = decode_signed_local_execution(leg).unwrap();
    stale.intent.call.nonce += 1;
    let stale_bytes: Vec<u8> =
        encode_signed_local_execution(&sign_leg_with_key(stale.intent, &key())).unwrap();
    assert!(
        prepare(
            public_key,
            signed.intent.recipient,
            &protocol(),
            Some(&stale_bytes)
        )
        .is_err()
    );
    let mut wrong_ref = decode_signed_local_execution(leg).unwrap();
    wrong_ref.intent.call.access.entries[0].object_ref.version += 1;
    let wrong_ref_bytes: Vec<u8> =
        encode_signed_local_execution(&sign_leg_with_key(wrong_ref.intent, &key())).unwrap();
    assert!(
        prepare(
            public_key,
            signed.intent.recipient,
            &protocol(),
            Some(&wrong_ref_bytes)
        )
        .is_err()
    );
    let mut wrong_target = decode_signed_local_execution(leg).unwrap();
    wrong_target.intent.call.entrypoint = "transfer".to_owned();
    let wrong_target_bytes: Vec<u8> =
        encode_signed_local_execution(&sign_leg_with_key(wrong_target.intent, &key())).unwrap();
    assert!(
        prepare(
            public_key,
            signed.intent.recipient,
            &protocol(),
            Some(&wrong_target_bytes)
        )
        .is_err()
    );
    assert_eq!(state_snapshot(&store), before);
    assert!(request_receipt(&store, signed.intent.request_id).is_none());

    // Wrong immutable defining-code authority fails certified inspection,
    // independently of the operator providing the correct historical key.
    let authority_key: Vec<u8> =
        local_instance_state::object_authority_key(signed.intent.expected_fee_output.id);
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &authority_key)
        .unwrap();
    let mut authority =
        execution::local_execution::decode_object_authority(observed.value().unwrap()).unwrap();
    authority.instance.seed[0] ^= 1;
    crate::paid_execution::tests::set_state(
        &store,
        authority_key,
        StateMutation::Put(
            execution::local_execution::encode_object_authority(&authority).unwrap(),
        ),
    );
    let tampered: Vec<StateEntry> = state_snapshot(&store);
    assert!(prepare(public_key, signed.intent.recipient, &protocol(), Some(leg)).is_err());
    assert_eq!(state_snapshot(&store), tampered);
}

#[test]
fn independent_apply_rejects_stale_prepared_generation_and_changed_payout_commitment() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, voters, resource): (Fixture, Vec<Voter>, BondResourceId) =
        install_certified(&store);
    let first: Vec<u8> = build_split_claim(
        &store,
        &fixture,
        &voters[0],
        resource,
        ESCROW,
        [0xD1; 32],
        next_nonce(&store),
        0xE1,
    )
    .signed_bytes;
    let competing: Vec<u8> = build_split_claim(
        &store,
        &fixture,
        &voters[1],
        resource,
        ESCROW,
        [0xD2; 32],
        next_nonce(&store),
        0xE2,
    )
    .signed_bytes;
    let prepared: PreparedFeeClaim = prepare_from_signed(&store, &first, &voters[0]).unwrap();
    let rival: PreparedFeeClaim = prepare_from_signed(&store, &competing, &voters[1]).unwrap();
    let mut changed: FeeClaimIntent = prepared.intent.clone();
    if let FeeClaimOperation::Split {
        expected_payout: Some(reference),
        ..
    } = &mut changed.operation
    {
        reference.version += 1;
    }
    let changed_bytes: Vec<u8> = sign_claim(&voters[0].signing_key, changed);
    let before: Vec<StateEntry> = state_snapshot(&store);
    assert!(apply(&store, &changed_bytes).is_err());
    assert_eq!(state_snapshot(&store), before);
    let original: Vec<u8> = sign_claim(&voters[0].signing_key, prepared.intent);
    apply(&store, &original).unwrap();
    let retained: Vec<StateEntry> = state_snapshot(&store);
    assert!(apply(&store, &sign_claim(&voters[1].signing_key, rival.intent)).is_err());
    assert_eq!(state_snapshot(&store), retained);
    assert!(request_receipt(&store, [0xD2; 32]).is_none());
}

#[test]
fn discovery_checks_empty_page_context_and_rejects_tombstones_and_foreign_cursor() {
    let store: MemoryDurableStateStore = memory_store();
    let voters: Vec<Voter> = four_sorted_voters();
    let entries: Vec<crate::fast_path::FastPathValidatorEntry> =
        voters.iter().map(|voter| voter.entry.clone()).collect();
    install_all(&store, &entries);
    let page = |expected: &PublicationContext, after: Option<Vec<u8>>| {
        discover_fee_escrows_page(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            expected,
            after,
            NonZeroUsize::new(1).unwrap(),
        )
    };
    assert!(page(&protocol(), None).unwrap().escrows.is_empty());
    let future: PublicationContext = PublicationContext::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        Epoch::new(protocol().epoch().get() + 1),
    )
    .unwrap();
    assert!(page(&future, None).is_err());
    assert!(page(&protocol(), Some(b"se/foreign/cursor".to_vec())).is_err());
    let key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(protocol().chain_id(), &ESCROW).unwrap();
    crate::paid_execution::tests::set_state(&store, key, StateMutation::Delete);
    assert!(page(&protocol(), None).is_err());
    let malformed_store: MemoryDurableStateStore = memory_store();
    install_all(&malformed_store, &entries);
    let mut malformed: Vec<u8> =
        local_instance_state::fastpath_settlement_key(protocol().chain_id(), &ESCROW).unwrap();
    malformed.pop();
    crate::paid_execution::tests::set_state(
        &malformed_store,
        malformed,
        StateMutation::Put(vec![0]),
    );
    assert!(
        discover_fee_escrows_page(
            &malformed_store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            None,
            NonZeroUsize::new(1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn discovery_uses_scanned_proof_and_rejects_a_far_orphan_claim_even_when_tombstoned() {
    for mutation in [StateMutation::Put(vec![0]), StateMutation::Delete] {
        let store: MemoryDurableStateStore = memory_store();
        install_certified(&store);
        let orphan_key: Vec<u8> =
            local_instance_state::fastpath_fee_claim_key(protocol().chain_id(), &ESCROW, 300)
                .unwrap();
        crate::paid_execution::tests::set_state(&store, orphan_key, mutation);
        let before: Vec<StateEntry> = state_snapshot(&store);
        assert!(
            discover_fee_escrows_page(
                &store,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                None,
                NonZeroUsize::new(1).unwrap()
            )
            .is_err()
        );
        assert_eq!(state_snapshot(&store), before);
    }
}

#[test]
fn discovery_pages_two_genuine_certified_rows_in_exact_key_order() {
    let store: MemoryDurableStateStore = memory_store();
    let co1: MemoryDurableStateStore = memory_store();
    let co2: MemoryDurableStateStore = memory_store();
    let voters: Vec<Voter> = four_sorted_voters();
    let entries: Vec<crate::fast_path::FastPathValidatorEntry> =
        voters.iter().map(|voter| voter.entry.clone()).collect();
    let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(&store, &entries);
    install_all(&co1, &entries);
    install_all(&co2, &entries);
    for (request, nonce, source) in [
        (0xB1, FIRST_PAID_NONCE, &fixture.coin),
        (0xB2, FIRST_PAID_NONCE + 1, &fixture.small),
    ] {
        let signed: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &policy,
                request,
                nonce,
                source,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(source, AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        let votes: Vec<consensus::FastVote> = vec![
            prepare_vote(&store, &policy, &voters[0], &signed),
            prepare_vote(&co1, &policy, &voters[1], &signed),
            prepare_vote(&co2, &policy, &voters[2], &signed),
        ];
        let certificate: Vec<u8> = certify(&build_validator_set(&entries), &votes);
        let output: NodeOutput = apply_escrow(&store, &policy, &signed, &certificate);
        assert_eq!(apply_escrow(&co1, &policy, &signed, &certificate), output);
        assert_eq!(apply_escrow(&co2, &policy, &signed, &certificate), output);
    }
    let before: Vec<StateEntry> = state_snapshot(&store);
    let first: FeeEscrowDiscoveryPage = discover_fee_escrows_page(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(first.escrows.len(), 1);
    assert_eq!(first.escrows[0].settlement.request_id, [0xB1; 32]);
    assert_eq!(first.escrows[0].verification.final_generation, 1);
    let cursor: Vec<u8> = first.continuation_cursor.unwrap();
    assert_eq!(
        cursor,
        local_instance_state::fastpath_settlement_key(protocol().chain_id(), &[0xB1; 32]).unwrap()
    );
    let second: FeeEscrowDiscoveryPage = discover_fee_escrows_page(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        Some(cursor),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(second.escrows.len(), 1);
    assert_eq!(second.escrows[0].settlement.request_id, [0xB2; 32]);
    assert!(second.continuation_cursor.is_none());
    assert_eq!(state_snapshot(&store), before);
}

#[test]
fn preparation_refuses_used_request_and_oversized_leg_before_any_pending_writes() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, voters, resource): (Fixture, Vec<Voter>, BondResourceId) =
        install_certified(&store);
    let signed: SignedFeeClaimIntent = decode_signed_fee_claim_intent(
        &build_split_claim(
            &store,
            &fixture,
            &voters[0],
            resource,
            ESCROW,
            [0xD1; 32],
            next_nonce(&store),
            0xE1,
        )
        .signed_bytes,
    )
    .unwrap();
    let FeeClaimOperation::Split { leg, .. } = &signed.intent.operation else {
        panic!("split");
    };
    let prepare = |request_id: [u8; 32], bytes: &[u8]| {
        prepare_fee_claim(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &LocalWasmExecutionEngine::new(),
            FeeClaimPreparationRequest {
                escrow_request_id: ESCROW,
                request_id,
                validator_id: voters[0].entry.id,
                claimant_public_key: voters[0].entry.public_key.as_slice().try_into().unwrap(),
                recipient: signed.intent.recipient,
                signed_leg: Some(bytes),
            },
            12,
        )
    };
    let before: Vec<StateEntry> = state_snapshot(&store);
    assert!(matches!(
        prepare(ESCROW, leg),
        Err(FeeClaimError::Invalid(
            "fee preparation request id already used; replay original artifact"
        ))
    ));
    let too_large: Vec<u8> =
        vec![0; execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES + 1];
    assert!(matches!(
        prepare([0xD1; 32], &too_large),
        Err(FeeClaimError::Invalid("fee preparation leg byte bound"))
    ));
    assert_eq!(state_snapshot(&store), before);
}
