use super::*;
use crate::fast_path::records::encode_fastpath_settlement_record;
use crate::genesis::{
    self,
    tests::{build_fixture, custody_object_entry, manifest_with_custody, resign_manifest},
};
use abi::call_values::{CallValue, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
    derive_local_created_object_id, encode_signed_local_execution, local_execution_event_digest,
    local_execution_signing_frame,
};
use objects::{Address, ObjectId, ProtocolCustodyScope};
use protocol_types::{HashAlgorithmId, SignatureSchemeId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableObjectChanges, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersionRecord, DurableRequestId,
    DurableRequestReceipt, MemoryBlobStore, MemoryDurableStateStore, StateReadAssertion,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};

fn object_ref(object: &Object) -> ObjectRef {
    let bytes: Vec<u8> = objects::encode_object(object).unwrap();
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: genesis::tests::resolver()
            .hash_for_purpose(
                genesis::tests::protocol().epoch(),
                HashPurpose::Object,
                &bytes,
            )
            .unwrap(),
    }
}

struct ClaimEvidence {
    row_key: Vec<u8>,
    final_bytes: Vec<u8>,
    coin_id: ObjectId,
    first_signed: Vec<u8>,
    second_signed: Vec<u8>,
    first_output: NodeOutput,
    second_output: NodeOutput,
}

fn exercise_split_then_final<S: StructuredDurableDomainStateStore>(store: &S) -> ClaimEvidence {
    let (_base_manifest, _origin, instance, def_id, coin_id) = build_fixture();
    let mut manifest: genesis::GenesisManifest = manifest_with_custody(ObjectId::new([0x94; 32]));
    let second_key: SigningKey = SigningKey::from([0x99; 32]);
    let second_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&second_key).into();
    let second_validator: ValidatorId = ValidatorId::new(second_public);
    let mut second_bond: genesis::GenesisObjectEntry = custody_object_entry(
        &manifest,
        ObjectId::new([0x99; 32]),
        genesis::tests::chain(),
    );
    let Owner::ProtocolCustody(second_scope) = &mut second_bond.object.owner else {
        panic!("second bond custody owner");
    };
    second_scope.subject = second_public;
    manifest.objects.push(second_bond);
    manifest
        .validator_set
        .validators
        .push(crate::fast_path::FastPathValidatorEntry {
            id: second_validator,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: second_public.to_vec(),
        });
    manifest
        .validator_set
        .validators
        .sort_by_key(|entry| entry.id);
    resign_manifest(&mut manifest);
    genesis::install_genesis(
        store,
        &genesis::tests::context(1),
        genesis::tests::domain(),
        &genesis::tests::resolver(),
        &manifest,
        10,
    )
    .unwrap();
    let resource_id: BondResourceId = manifest.economics_policy.resources[0].resource_id;
    let escrow_request_id: [u8; 32] = [0x95; 32];
    let scope: ProtocolCustodyScope =
        fee_escrow_scope(&genesis::tests::protocol(), escrow_request_id, resource_id);
    let mut escrow: Object = manifest.objects[1].object.clone();
    escrow.version += 1;
    escrow.owner = Owner::ProtocolCustody(scope);
    let escrow_ref: ObjectRef = object_ref(&escrow);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        escrow.clone(),
        escrow_ref.digest,
        DurableObjectProvenance::new(
            genesis::tests::chain(),
            genesis::tests::protocol().protocol_version(),
        ),
        11,
    )
    .unwrap();
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            coin_id,
            store
                .get_object_head(
                    &genesis::tests::context(1),
                    genesis::tests::domain(),
                    coin_id,
                )
                .unwrap(),
        )],
        vec![DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Update {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(escrow.owner.clone())
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let setup_receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x96; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x96; 32]),
        vec![0x96],
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(
            &genesis::tests::context(1),
            DurableInvocationTransaction::new(
                genesis::tests::domain(),
                None,
                changes,
                setup_receipt,
                None,
            )
            .unwrap(),
        ),
        DurableCommitOutcome::Committed
    );

    let amount: u64 = 1_000_000;
    let share_amount: u64 = amount / 2;
    let validator_id: ValidatorId = ValidatorId::new(genesis::tests::sender());
    let row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: genesis::tests::protocol(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(escrow_ref.clone()),
        fee_output_epoch: Some(genesis::tests::protocol().epoch()),
        total_amount: Some(amount),
        shares: {
            let mut shares: Vec<FastPathFeeShare> = [validator_id, second_validator]
                .into_iter()
                .map(|validator_id| FastPathFeeShare {
                    validator_id,
                    amount: share_amount,
                    claimed: false,
                })
                .collect();
            shares.sort_by_key(|share| share.validator_id);
            shares
        },
    };
    let row_key: Vec<u8> = local_instance_state::fastpath_settlement_key(
        genesis::tests::protocol().chain_id(),
        &escrow_request_id,
    )
    .unwrap();
    let row_bytes: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
    let setup_row: AtomicStateTransaction = AtomicStateTransaction::new(
        genesis::tests::domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(row_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(row_key.clone(), StateMutation::Put(row_bytes.clone()))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&genesis::tests::context(1), setup_row),
        DurableCommitOutcome::Committed
    );

    let recipient: Address =
        Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([0x97; 32])).into());
    let request_id: [u8; 32] = [0x98; 32];
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(genesis::tests::protocol());
    let call: CallIntent = CallIntent {
        context: genesis::tests::protocol(),
        request_id,
        sender: genesis::tests::sender(),
        nonce: 0,
        code: instance.code.clone(),
        instance: execution::local_execution::instance_target(
            &genesis::tests::resolver(),
            &instance,
        )
        .unwrap(),
        entrypoint: "split".to_owned(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
        access: AccessManifest {
            entries: vec![AccessEntry {
                object_ref: escrow_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::split_arguments(share_amount, recipient.as_bytes())
            .unwrap(),
        gas_limit: 500_000,
    };
    let leg_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&genesis::tests::resolver()).unwrap(),
        call,
        authorizations: Vec::new(),
    };
    let leg_frame: Vec<u8> =
        local_execution_signing_frame(&genesis::tests::protocol(), &leg_intent).unwrap();
    let signed_leg: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        signature: genesis::tests::key().sign(&leg_frame).into(),
        intent: leg_intent,
    };
    let leg: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
    let payout_id: ObjectId = derive_local_created_object_id(
        &genesis::tests::resolver(),
        &genesis::tests::protocol(),
        &instance.context,
        &execution::local_execution::instance_target(&genesis::tests::resolver(), &instance)
            .unwrap(),
        &instance.code,
        local_execution_event_digest(&genesis::tests::resolver(), &signed_leg).unwrap(),
        0,
    )
    .unwrap();
    let payout: Object = Object {
        id: payout_id,
        version: 1,
        owner: Owner::Address(recipient),
        type_hash: escrow.type_hash,
        schema_version: escrow.schema_version,
        data: encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(share_amount),
        )
        .unwrap(),
    };
    let mut retained: Object = escrow.clone();
    retained.version += 1;
    retained.data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(share_amount),
    )
    .unwrap();
    let mut next_row: FastPathSettlementRecord = row.clone();
    next_row.generation += 1;
    next_row.fee_output = Some(object_ref(&retained));
    next_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == validator_id)
        .unwrap()
        .claimed = true;
    let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
    let resolver: HashSuiteResolver = genesis::tests::resolver();
    let intent: FeeClaimIntent = FeeClaimIntent {
        context: genesis::tests::protocol(),
        request_id,
        escrow_request_id,
        certificate_epoch: genesis::tests::protocol().epoch(),
        validator_id,
        resource_id,
        expected_generation: 1,
        expected_fee_output: escrow_ref,
        expected_previous_row_digest: fee_claim_row_digest(
            &resolver,
            genesis::tests::protocol().epoch(),
            &row_bytes,
        )
        .unwrap(),
        expected_next_row_digest: fee_claim_row_digest(
            &resolver,
            genesis::tests::protocol().epoch(),
            &next_bytes,
        )
        .unwrap(),
        share_amount,
        recipient,
        operation: FeeClaimOperation::Split {
            leg,
            expected_payout: Some(object_ref(&payout)),
        },
    };
    let intent_digest: Digest32 = fee_claim_intent_digest(&resolver, &intent).unwrap();
    let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, intent_digest).unwrap();
    let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
        signature: genesis::tests::key().sign(&frame).into(),
        intent,
    };
    let signed_bytes: Vec<u8> = codec::encode_signed_fee_claim_intent(&signed).unwrap();
    let run = |signed_bytes: &[u8]| {
        handle_fee_claim(
            store,
            &MemoryBlobStore::default(),
            &genesis::tests::context(1),
            genesis::tests::domain(),
            &resolver,
            &[],
            &genesis::tests::protocol(),
            &policy,
            &LocalWasmExecutionEngine::new(),
            signed_bytes,
            12,
        )
    };
    let mut invalid_signature: SignedFeeClaimIntent = signed.clone();
    invalid_signature.signature[0] ^= 1;
    let invalid_bytes: Vec<u8> = codec::encode_signed_fee_claim_intent(&invalid_signature).unwrap();
    assert!(run(&invalid_bytes).is_err());
    assert_eq!(
        store
            .get_versioned_durable(
                &genesis::tests::context(1),
                genesis::tests::domain(),
                &row_key
            )
            .unwrap()
            .value(),
        Some(row_bytes.as_slice())
    );
    let output: NodeOutput = run(&signed_bytes).unwrap();
    assert_eq!(run(&signed_bytes).unwrap(), output);
    assert_eq!(
        store
            .get_versioned_durable(
                &genesis::tests::context(1),
                genesis::tests::domain(),
                &row_key
            )
            .unwrap()
            .value(),
        Some(next_bytes.as_slice())
    );
    let head: DurableObjectHead = store
        .get_object_head(
            &genesis::tests::context(1),
            genesis::tests::domain(),
            coin_id,
        )
        .unwrap();
    assert!(
        matches!(head, DurableObjectHead::Current { object_version, .. } if object_version.get() == 3)
    );

    let second_recipient: Address =
        Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([0x9a; 32])).into());
    let second_request_id: [u8; 32] = [0x9b; 32];
    let second_call: CallIntent = CallIntent {
        context: genesis::tests::protocol(),
        request_id: second_request_id,
        sender: genesis::tests::sender(),
        nonce: 1,
        code: instance.code.clone(),
        instance: execution::local_execution::instance_target(&resolver, &instance).unwrap(),
        entrypoint: "transfer".to_owned(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
        access: AccessManifest {
            entries: vec![AccessEntry {
                object_ref: next_row.fee_output.clone().unwrap(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(second_recipient.as_bytes()).unwrap(),
        gas_limit: 500_000,
    };
    let second_leg_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver).unwrap(),
        call: second_call,
        authorizations: Vec::new(),
    };
    let second_leg_frame: Vec<u8> =
        local_execution_signing_frame(&genesis::tests::protocol(), &second_leg_intent).unwrap();
    let second_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: genesis::tests::key().sign(&second_leg_frame).into(),
        intent: second_leg_intent,
    })
    .unwrap();
    let mut transferred: Object = retained;
    transferred.version += 1;
    transferred.owner = Owner::Address(second_recipient);
    let mut final_row: FastPathSettlementRecord = next_row.clone();
    final_row.generation += 1;
    final_row.fee_output = Some(object_ref(&transferred));
    final_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == second_validator)
        .unwrap()
        .claimed = true;
    let final_bytes: Vec<u8> = encode_fastpath_settlement_record(&final_row).unwrap();
    let second_intent: FeeClaimIntent = FeeClaimIntent {
        context: genesis::tests::protocol(),
        request_id: second_request_id,
        escrow_request_id,
        certificate_epoch: genesis::tests::protocol().epoch(),
        validator_id: second_validator,
        resource_id,
        expected_generation: 2,
        expected_fee_output: next_row.fee_output.clone().unwrap(),
        expected_previous_row_digest: fee_claim_row_digest(
            &resolver,
            genesis::tests::protocol().epoch(),
            &next_bytes,
        )
        .unwrap(),
        expected_next_row_digest: fee_claim_row_digest(
            &resolver,
            genesis::tests::protocol().epoch(),
            &final_bytes,
        )
        .unwrap(),
        share_amount,
        recipient: second_recipient,
        operation: FeeClaimOperation::FinalTransfer { leg: second_leg },
    };
    let second_digest: Digest32 = fee_claim_intent_digest(&resolver, &second_intent).unwrap();
    let second_frame: Vec<u8> =
        fee_claim_signing_frame(&second_intent.context, second_digest).unwrap();
    let second_signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
        signature: second_key.sign(&second_frame).into(),
        intent: second_intent,
    };
    let second_bytes: Vec<u8> = codec::encode_signed_fee_claim_intent(&second_signed).unwrap();
    let final_output: NodeOutput = run(&second_bytes).unwrap();
    assert_eq!(run(&second_bytes).unwrap(), final_output);
    let mut conflicting_second: SignedFeeClaimIntent = second_signed;
    conflicting_second.signature[0] ^= 1;
    let conflicting_bytes: Vec<u8> =
        codec::encode_signed_fee_claim_intent(&conflicting_second).unwrap();
    assert!(run(&conflicting_bytes).is_err());
    assert_eq!(
        store
            .get_versioned_durable(
                &genesis::tests::context(1),
                genesis::tests::domain(),
                &row_key
            )
            .unwrap()
            .value(),
        Some(final_bytes.as_slice())
    );
    let final_head: DurableObjectHead = store
        .get_object_head(
            &genesis::tests::context(1),
            genesis::tests::domain(),
            coin_id,
        )
        .unwrap();
    assert!(
        matches!(final_head, DurableObjectHead::Current { object_version, .. } if object_version.get() == 4)
    );
    ClaimEvidence {
        row_key,
        final_bytes,
        coin_id,
        first_signed: signed_bytes,
        second_signed: second_bytes,
        first_output: output,
        second_output: final_output,
    }
}

#[test]
fn signed_split_then_final_fee_claims_use_real_wasm_and_conserve_escrow() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let _evidence: ClaimEvidence = exercise_split_then_final(&store);
}

#[test]
fn file_backed_sqlite_fee_claims_reopen_and_replay_without_reapplication() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf =
        std::env::temp_dir().join(format!("fee-claims-sqlite-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let db_path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        genesis::tests::chain(),
        ValidatorId::new([0xa1; 32]),
        genesis::tests::domain(),
    );
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let evidence: ClaimEvidence = {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        exercise_split_then_final(&store)
    };
    {
        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
        assert_eq!(
            reopened
                .get_versioned_durable(
                    &genesis::tests::context(1),
                    genesis::tests::domain(),
                    &evidence.row_key,
                )
                .unwrap()
                .value(),
            Some(evidence.final_bytes.as_slice())
        );
        let policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(genesis::tests::protocol());
        let replay = |bytes: &[u8]| {
            handle_fee_claim(
                &reopened,
                &MemoryBlobStore::default(),
                &genesis::tests::context(1),
                genesis::tests::domain(),
                &genesis::tests::resolver(),
                &[],
                &genesis::tests::protocol(),
                &policy,
                &LocalWasmExecutionEngine::new(),
                bytes,
                12,
            )
        };
        assert_eq!(
            replay(&evidence.first_signed).unwrap(),
            evidence.first_output
        );
        assert_eq!(
            replay(&evidence.second_signed).unwrap(),
            evidence.second_output
        );
        let head: DurableObjectHead = reopened
            .get_object_head(
                &genesis::tests::context(1),
                genesis::tests::domain(),
                evidence.coin_id,
            )
            .unwrap();
        assert!(
            matches!(head, DurableObjectHead::Current { object_version, .. } if object_version.get() == 4)
        );
    }
    std::fs::remove_dir_all(&directory).unwrap();
}
