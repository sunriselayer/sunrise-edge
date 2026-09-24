use super::*;
use crate::fast_path::records::{
    FastPathFeeShare, FastPathSettlementRecord, encode_fastpath_settlement_record,
};
use crate::genesis::tests::{build_fixture, chain, context, domain, protocol, resolver};
use abi::call_values::{CallValue, encode_call_value};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::VerifiedPublicationInterface;
use objects::{Address, Object, Owner, encode_object};
use protocol_types::{HashAlgorithmId, ValidatorId};
use runtime::{
    DurableObjectMutation, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersionRecord, DurableRequestId,
    DurableRequestReceipt, MemoryBlobStore, MemoryDurableStateStore, WriterFenceGeneration,
};
use validator_set::{ValidatorInfo, ValidatorSet};

fn object_ref(object: &Object) -> ObjectRef {
    let bytes: Vec<u8> = encode_object(object).unwrap();
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &bytes)
            .unwrap(),
    }
}

/// Directly installs one immutable escrow object version and its current
/// head, bypassing every execution/policy path this module does not depend
/// on: this file exercises [`verify_fee_claim_chain`] alone, against
/// hand-built durable state.
fn commit_object_version<S: StructuredDurableDomainStateStore>(
    store: &S,
    object: &Object,
    checkpoint: u64,
    receipt_seed: u8,
) -> ObjectRef {
    let reference: ObjectRef = object_ref(object);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        object.clone(),
        reference.digest,
        DurableObjectProvenance::new(chain(), protocol().protocol_version()),
        checkpoint,
    )
    .unwrap();
    let head: DurableObjectHead = store
        .get_object_head(&context(1), domain(), object.id)
        .unwrap();
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(object.owner.clone()).unwrap();
    let mutation: DurableObjectMutation = if object.version == 1 {
        DurableObjectMutation::Create {
            version,
            owner_projection,
            routing_projection: DurableObjectRoutingProjection::default(),
        }
    } else {
        DurableObjectMutation::Update {
            version,
            owner_projection,
            routing_projection: DurableObjectRoutingProjection::default(),
        }
    };
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(object.id, head)],
        vec![DurableObjectMutationEntry::new(object.id, mutation)],
    )
    .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([receipt_seed; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [receipt_seed; 32]),
        vec![receipt_seed],
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(
            &context(1),
            DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap(),
        ),
        DurableCommitOutcome::Committed
    );
    reference
}

/// Writes or overwrites one generic state key (a settlement row or a signed
/// fee-claim envelope), fencing on whatever revision is currently observed.
fn put_state<S: StructuredDurableDomainStateStore>(store: &S, key: Vec<u8>, value: Vec<u8>) {
    let revision: StateRevision = store
        .get_versioned_durable(&context(1), domain(), &key)
        .unwrap()
        .revision();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), revision).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(value)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Committed
    );
}

fn coin_data(amount: u64) -> Vec<u8> {
    encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(amount),
    )
    .unwrap()
}

/// The one knob each tamper test flips away from an otherwise fully
/// consistent, independently re-derivable two-claim chain (`Split` then
/// `FinalTransfer`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tamper {
    None,
    TrailingZero,
    MissingEnvelope,
    BadSignature,
    BadEscrowValue,
}

struct ChainFixture {
    store: MemoryDurableStateStore,
    interface: VerifiedPublicationInterface,
    escrow_resource: FeeEscrowResourceAbi,
    validator_set: ValidatorSet,
    genesis_row: FastPathSettlementRecord,
    genesis_row_bytes: Vec<u8>,
}

fn build_chain(tamper: Tamper) -> ChainFixture {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, ..) = build_fixture();

    let candidate = execution::publication::authenticate_publication_submission(
        &resolver(),
        &protocol(),
        &execution::local_execution::generic_object_result_semantics(&resolver(), &protocol())
            .unwrap(),
        manifest.publication.clone(),
    )
    .unwrap();
    let interface: VerifiedPublicationInterface =
        execution::publication::verify_publication_interface(candidate, Vec::new()).unwrap();

    let resource_id: BondResourceId = manifest.economics_policy.resources[0].resource_id;
    let escrow_resource: FeeEscrowResourceAbi = FeeEscrowResourceAbi {
        ty: manifest.objects[1].authority.ty.clone(),
        schema_version: manifest.objects[1].object.schema_version,
    };

    let validator1_key: SigningKey = SigningKey::from([0x51; 32]);
    let validator2_key: SigningKey = SigningKey::from([0x52; 32]);
    let validator1_public: [u8; 32] = VerificationKey::from(&validator1_key).into();
    let validator2_public: [u8; 32] = VerificationKey::from(&validator2_key).into();
    let validator3_key: SigningKey = SigningKey::from([0x53; 32]);
    let validator3_public: [u8; 32] = VerificationKey::from(&validator3_key).into();
    let validator1: ValidatorId = ValidatorId::new(validator1_public);
    let validator2: ValidatorId = ValidatorId::new(validator2_public);
    let validator3: ValidatorId = ValidatorId::new(validator3_public);
    let mut validators: Vec<ValidatorInfo> = vec![
        ValidatorInfo {
            id: validator1,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: validator1_public.to_vec(),
        },
        ValidatorInfo {
            id: validator2,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: validator2_public.to_vec(),
        },
    ];
    if tamper == Tamper::TrailingZero {
        validators.push(ValidatorInfo {
            id: validator3,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: validator3_public.to_vec(),
        });
    }
    let validator_set: ValidatorSet = ValidatorSet::new(protocol().epoch(), validators).unwrap();

    let escrow_request_id: [u8; 32] = [0x61; 32];
    let scope: ProtocolCustodyScope = fee_escrow_scope(&protocol(), escrow_request_id, resource_id);

    let mut escrow_v1: Object = manifest.objects[1].object.clone();
    escrow_v1.owner = Owner::ProtocolCustody(scope.clone());
    escrow_v1.data = coin_data(1_000_000);
    let escrow_v1_ref: ObjectRef = commit_object_version(&store, &escrow_v1, 1, 0x01);

    let mut shares: Vec<FastPathFeeShare> = vec![
        FastPathFeeShare {
            validator_id: validator1,
            amount: 500_000,
            claimed: false,
        },
        FastPathFeeShare {
            validator_id: validator2,
            amount: 500_000,
            claimed: false,
        },
    ];
    if tamper == Tamper::TrailingZero {
        shares.push(FastPathFeeShare {
            validator_id: validator3,
            amount: 0,
            claimed: false,
        });
    }
    shares.sort_by_key(|share| share.validator_id);

    let genesis_row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: protocol(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(escrow_v1_ref.clone()),
        fee_output_epoch: Some(protocol().epoch()),
        total_amount: Some(1_000_000),
        shares,
    };
    let genesis_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&genesis_row).unwrap();
    put_state(
        &store,
        local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap(),
        genesis_row_bytes.clone(),
    );

    // Claim 1: validator1 splits its 500_000 share to `recipient1`, the
    // escrow object retaining custody of the other unclaimed 500_000.
    let mut escrow_v2: Object = escrow_v1.clone();
    escrow_v2.version = 2;
    escrow_v2.data = coin_data(if tamper == Tamper::BadEscrowValue {
        400_000
    } else {
        500_000
    });
    let escrow_v2_ref: ObjectRef = commit_object_version(&store, &escrow_v2, 2, 0x02);

    let mut next_row: FastPathSettlementRecord = genesis_row.clone();
    next_row.generation = 2;
    next_row.fee_output = Some(escrow_v2_ref.clone());
    next_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == validator1)
        .unwrap()
        .claimed = true;
    let next_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();

    let recipient1: Address = Address::new([0x71; 32]);
    let intent1: FeeClaimIntent = FeeClaimIntent {
        context: protocol(),
        request_id: [0xA1; 32],
        escrow_request_id,
        certificate_epoch: protocol().epoch(),
        validator_id: validator1,
        resource_id,
        expected_generation: 1,
        expected_fee_output: escrow_v1_ref.clone(),
        expected_previous_row_digest: fee_claim_row_digest(
            &resolver(),
            protocol().epoch(),
            &genesis_row_bytes,
        )
        .unwrap(),
        expected_next_row_digest: fee_claim_row_digest(
            &resolver(),
            protocol().epoch(),
            &next_row_bytes,
        )
        .unwrap(),
        share_amount: 500_000,
        recipient: recipient1,
        operation: FeeClaimOperation::Split { leg: vec![0xAB] },
    };
    let digest1: Digest32 = fee_claim_intent_digest(&resolver(), &intent1).unwrap();
    let frame1: Vec<u8> = fee_claim_signing_frame(&intent1.context, digest1).unwrap();
    let mut signature1: [u8; 64] = validator1_key.sign(&frame1).into();
    if tamper == Tamper::BadSignature {
        signature1[0] ^= 1;
    }
    let signed1: SignedFeeClaimIntent = SignedFeeClaimIntent {
        intent: intent1,
        signature: signature1,
    };
    let bytes1: Vec<u8> = codec::encode_signed_fee_claim_intent(&signed1).unwrap();
    if tamper != Tamper::MissingEnvelope {
        put_state(
            &store,
            local_instance_state::fastpath_fee_claim_key(&chain(), &escrow_request_id, 2).unwrap(),
            bytes1,
        );
    }
    put_state(
        &store,
        local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap(),
        next_row_bytes.clone(),
    );

    // Claim 2: validator2 takes the final remaining 500_000 by whole-object
    // transfer, exhausting the row.
    let mut escrow_v3: Object = escrow_v2.clone();
    escrow_v3.version = 3;
    let recipient2: Address = Address::new([0x72; 32]);
    escrow_v3.owner = Owner::Address(recipient2);
    let escrow_v3_ref: ObjectRef = commit_object_version(&store, &escrow_v3, 3, 0x03);

    let mut final_row: FastPathSettlementRecord = next_row.clone();
    final_row.generation = 3;
    final_row.fee_output = Some(escrow_v3_ref.clone());
    final_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == validator2)
        .unwrap()
        .claimed = true;
    let final_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&final_row).unwrap();

    let intent2: FeeClaimIntent = FeeClaimIntent {
        context: protocol(),
        request_id: [0xA2; 32],
        escrow_request_id,
        certificate_epoch: protocol().epoch(),
        validator_id: validator2,
        resource_id,
        expected_generation: 2,
        expected_fee_output: escrow_v2_ref,
        expected_previous_row_digest: fee_claim_row_digest(
            &resolver(),
            protocol().epoch(),
            &next_row_bytes,
        )
        .unwrap(),
        expected_next_row_digest: fee_claim_row_digest(
            &resolver(),
            protocol().epoch(),
            &final_row_bytes,
        )
        .unwrap(),
        share_amount: 500_000,
        recipient: recipient2,
        operation: FeeClaimOperation::FinalTransfer { leg: vec![0xCD] },
    };
    let digest2: Digest32 = fee_claim_intent_digest(&resolver(), &intent2).unwrap();
    let frame2: Vec<u8> = fee_claim_signing_frame(&intent2.context, digest2).unwrap();
    let signature2: [u8; 64] = validator2_key.sign(&frame2).into();
    let signed2: SignedFeeClaimIntent = SignedFeeClaimIntent {
        intent: intent2,
        signature: signature2,
    };
    let bytes2: Vec<u8> = codec::encode_signed_fee_claim_intent(&signed2).unwrap();
    put_state(
        &store,
        local_instance_state::fastpath_fee_claim_key(&chain(), &escrow_request_id, 3).unwrap(),
        bytes2,
    );
    put_state(
        &store,
        local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap(),
        final_row_bytes.clone(),
    );

    if tamper == Tamper::TrailingZero {
        let mut zero_row: FastPathSettlementRecord = final_row.clone();
        zero_row.generation = 4;
        zero_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator3)
            .unwrap()
            .claimed = true;
        let zero_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&zero_row).unwrap();
        let zero_intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id: [0xA3; 32],
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id: validator3,
            resource_id,
            expected_generation: 3,
            expected_fee_output: escrow_v3_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &final_row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &zero_row_bytes,
            )
            .unwrap(),
            share_amount: 0,
            recipient: Address::new([0x73; 32]),
            operation: FeeClaimOperation::ZeroShare,
        };
        let zero_digest: Digest32 = fee_claim_intent_digest(&resolver(), &zero_intent).unwrap();
        let zero_frame: Vec<u8> =
            fee_claim_signing_frame(&zero_intent.context, zero_digest).unwrap();
        let zero_signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
            intent: zero_intent,
            signature: validator3_key.sign(&zero_frame).into(),
        };
        put_state(
            &store,
            local_instance_state::fastpath_fee_claim_key(&chain(), &escrow_request_id, 4).unwrap(),
            codec::encode_signed_fee_claim_intent(&zero_signed).unwrap(),
        );
        put_state(
            &store,
            local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap(),
            zero_row_bytes,
        );
    }

    ChainFixture {
        store,
        interface,
        escrow_resource,
        validator_set,
        genesis_row,
        genesis_row_bytes,
    }
}

fn run(fixture: &ChainFixture) -> Result<FeeClaimChainReport, FeeClaimError> {
    verify_fee_claim_chain(
        &fixture.store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &fixture.validator_set,
        &fixture.escrow_resource,
        &fixture.interface,
        &fixture.genesis_row,
        &fixture.genesis_row_bytes,
    )
}

#[test]
fn verifies_a_consistent_split_then_final_chain() {
    let fixture: ChainFixture = build_chain(Tamper::None);
    let report: FeeClaimChainReport = run(&fixture).unwrap();
    assert_eq!(
        report,
        FeeClaimChainReport {
            final_generation: 3,
            verified_claims: 2,
            verified_positive_claims: 2,
        }
    );
}

#[test]
fn verifies_zero_share_claim_after_final_transfer() {
    let fixture: ChainFixture = build_chain(Tamper::TrailingZero);
    let report: FeeClaimChainReport = run(&fixture).unwrap();
    assert_eq!(report.final_generation, 4);
    assert_eq!(report.verified_claims, 3);
    assert_eq!(report.verified_positive_claims, 2);
}

#[test]
fn rejects_a_missing_intermediate_envelope() {
    let fixture: ChainFixture = build_chain(Tamper::MissingEnvelope);
    let error: FeeClaimError = run(&fixture).unwrap_err();
    assert!(matches!(
        error,
        FeeClaimError::Invalid("fee claim chain missing or orphaned envelope")
    ));
}

#[test]
fn rejects_a_nonadjacent_orphan_envelope_after_the_installed_tail() {
    let fixture: ChainFixture = build_chain(Tamper::None);
    put_state(
        &fixture.store,
        local_instance_state::fastpath_fee_claim_key(&chain(), &fixture.genesis_row.request_id, 5)
            .unwrap(),
        vec![0xFF],
    );
    let error: FeeClaimError = run(&fixture).unwrap_err();
    assert!(matches!(
        error,
        FeeClaimError::Invalid("fee claim chain orphan envelope")
    ));
}

#[test]
fn rejects_a_tampered_validator_signature() {
    let fixture: ChainFixture = build_chain(Tamper::BadSignature);
    let error: FeeClaimError = run(&fixture).unwrap_err();
    assert!(matches!(
        error,
        FeeClaimError::Invalid("fee claim chain envelope signature")
    ));
}

#[test]
fn rejects_an_escrow_value_that_does_not_conserve_the_unclaimed_total() {
    let fixture: ChainFixture = build_chain(Tamper::BadEscrowValue);
    let error: FeeClaimError = run(&fixture).unwrap_err();
    assert!(matches!(
        error,
        FeeClaimError::Invalid(
            "fee claim chain escrow value does not conserve the unclaimed total"
        )
    ));
}

#[test]
fn rejects_a_genesis_anchor_that_is_not_generation_one() {
    let fixture: ChainFixture = build_chain(Tamper::None);
    let mut genesis_row: FastPathSettlementRecord = fixture.genesis_row.clone();
    genesis_row.generation = 2;
    let error: FeeClaimError = verify_fee_claim_chain(
        &fixture.store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &fixture.validator_set,
        &fixture.escrow_resource,
        &fixture.interface,
        &genesis_row,
        &fixture.genesis_row_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        FeeClaimError::Invalid("fee claim chain genesis generation")
    ));
}
