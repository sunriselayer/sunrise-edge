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

/// DR-0139/DR-0140 phase 3 evidence: a real file-backed SQLite close/reopen
/// end-to-end proof that starts from genuinely certified `fast_path::prepare`
/// and `fast_path::apply` (never a directly inserted settlement row),
/// creates two distinct certified escrows, exercises split, final-transfer
/// and zero-share claims (including one signed split payout per escrow),
/// then runs a caller-driven multi-page `verify_fee_escrow_inventory_page`
/// sweep under a quiescent store and checks exact counts, payout
/// `ObjectRef`s and replay non-reapplication. A final tamper of one retained
/// claim envelope proves the whole multi-page sweep fails closed, not just
/// the tampered escrow.
mod certified_multi_escrow_inventory {
    use super::*;
    use crate::fast_path::{
        self, FastPathEd25519Verifier, FastPathValidatorEntry, install_validator_set,
    };
    use crate::paid_execution::tests::{
        CountingEngine, FIRST_PAID_NONCE, Fixture, PaidCall, base_policy, context, domain, entry,
        install, key, memory_store, next_nonce, object_reference, paid_call_with_access, protocol,
        receipt, refund_account, resolver, sender, set_state,
    };
    use bonds::BondResourceConfig;
    use consensus::{ConsensusSigner, FastCertificate, FastVote};
    use ed25519_zebra::VerificationKey;
    use execution::paid_execution::{PaidExecutionStatus, ReservationAccessKind};
    use fees::{Amount, GasSchedule};
    use protocol_types::{HashSuite, HashSuiteId, HashSuiteSchedule};
    use runtime::DurableStateKeyScanner;
    use std::num::NonZeroUsize;
    use validator_set::ValidatorInfo;

    /// One real independent Ed25519 validator: its own signing key plus the
    /// installable [`FastPathValidatorEntry`] every store's validator set
    /// carries. Distinct from `crate::fast_path::tests::TestSigner`, which is
    /// private to that sibling test module.
    struct Voter {
        entry: FastPathValidatorEntry,
        signing_key: SigningKey,
    }
    impl ConsensusSigner for Voter {
        fn validator_id(&self) -> ValidatorId {
            self.entry.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            let signature: [u8; 64] = self.signing_key.sign(framed).into();
            Ok(signature.to_vec())
        }
    }

    fn voter(seed: u8) -> Voter {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let public: [u8; 32] = VerificationKey::from(&signing_key).into();
        Voter {
            entry: FastPathValidatorEntry {
                id: ValidatorId::new(public),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public.to_vec(),
            },
            signing_key,
        }
    }

    /// Four validators sorted by [`ValidatorId`], the exact order
    /// [`fast_path::validator_fee_shares`] assigns quotient/remainder shares
    /// in: with `charged.actual == 2` (see [`cheap_policy`]) entries `0`/`1`
    /// always receive the escrow's two positive shares and `2`/`3` always
    /// receive a zero share, regardless of preparation order.
    fn four_sorted_voters() -> Vec<Voter> {
        let mut voters: Vec<Voter> = vec![voter(0xC1), voter(0xC2), voter(0xC3), voter(0xC4)];
        voters.sort_by_key(|voter| voter.entry.id);
        voters
    }

    fn build_validator_set(entries: &[FastPathValidatorEntry]) -> ValidatorSet {
        ValidatorSet::new(
            protocol().epoch(),
            entries
                .iter()
                .map(|entry| ValidatorInfo {
                    id: entry.id,
                    voting_power: entry.voting_power,
                    signature_scheme: entry.signature_scheme,
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        )
        .unwrap()
    }

    /// Keep the execution price above the calibrated minimum while yielding
    /// an exact charged amount of two for each real-WASM transfer in this
    /// fixture. The test asserts that amount for both source objects, so a
    /// future fuel-cost change fails visibly instead of silently losing the
    /// intended `[1, 1, 0, 0]` split/final/zero-share coverage.
    fn cheap_policy(base: &PaidFeePolicy) -> PaidFeePolicy {
        let mut policy: PaidFeePolicy = base.clone();
        policy.gas_schedule = GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        };
        policy.conversion_divisor = 40_000;
        policy
    }

    /// Installs the deterministic asset fixture, the four-validator set and
    /// the shared cheap fee-escrow policy on one store. Every store in this
    /// test -- the SQLite primary and every memory-backed voter -- calls
    /// this identically, exactly like `fast_path::tests`' own multi-store
    /// patterns: independent stores derive byte-identical fixture state.
    fn install_all<S: StructuredDurableDomainStateStore>(
        store: &S,
        entries: &[FastPathValidatorEntry],
    ) -> (Fixture, PaidFeePolicy) {
        let fixture: Fixture = install(store);
        install_validator_set(
            store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.to_vec(),
        )
        .unwrap();
        let policy: PaidFeePolicy = cheap_policy(&fixture.policy);
        let economics: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
            context: policy.code.context().clone(),
            resources: vec![FastPathEconomicsResourcePolicy {
                resource_id: fast_path::fee_resource_id(&policy).unwrap(),
                context: policy.code.context().clone(),
                instance: policy.instance.clone(),
                code: policy.code.clone(),
                ty: policy.asset_type.clone(),
                schema: policy.schema,
                split_entrypoint: "split".to_owned(),
                transfer_entrypoint: "transfer".to_owned(),
                bond: None,
                fee_escrow: true,
            }],
        };
        set_state(
            store,
            local_instance_state::fastpath_economics_policy_key(&economics.context).unwrap(),
            StateMutation::Put(
                crate::economics::encode_fastpath_economics_policy(&economics).unwrap(),
            ),
        );
        set_state(
            store,
            local_instance_state::paid_fee_policy_key(&protocol()).unwrap(),
            StateMutation::Put(execution::paid_execution::encode_paid_fee_policy(&policy).unwrap()),
        );
        (fixture, policy)
    }

    fn prepare_vote<S: StructuredDurableDomainStateStore>(
        store: &S,
        policy: &PaidFeePolicy,
        voter: &Voter,
        signed_bytes: &[u8],
    ) -> FastVote {
        fast_path::prepare(
            store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            policy,
            &LocalWasmExecutionEngine::new(),
            voter,
            signed_bytes,
            10,
        )
        .unwrap()
    }

    fn certify(validator_set: &ValidatorSet, votes: &[FastVote]) -> Vec<u8> {
        let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            validator_set.clone(),
        )
        .unwrap();
        let certificate: FastCertificate = certifier
            .try_form_certificate(
                votes[0].tx_hash,
                votes[0].execution_effects_hash,
                votes[0].locked_objects_digest,
                votes,
                &FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("three of four equal-power votes already form quorum");
        assert!(certificate.votes.len() >= 3);
        consensus::encode_fast_certificate(&certificate).unwrap()
    }

    fn apply_escrow<S: StructuredDurableDomainStateStore>(
        store: &S,
        policy: &PaidFeePolicy,
        signed_bytes: &[u8],
        certificate_bytes: &[u8],
    ) -> NodeOutput {
        fast_path::apply(
            store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            policy,
            &LocalWasmExecutionEngine::new(),
            signed_bytes,
            certificate_bytes,
        )
        .unwrap()
    }

    fn read_current_escrow<S: StructuredDurableDomainStateStore>(
        store: &S,
        id: ObjectId,
    ) -> Object {
        let head: DurableObjectHead = store.get_object_head(&context(), domain(), id).unwrap();
        let DurableObjectHead::Current { object_version, .. } = head else {
            panic!("escrow object must remain current");
        };
        let version_record = store
            .get_object_version(&context(), domain(), id, object_version)
            .unwrap()
            .expect("escrow object version must be retained");
        let DurableObjectPayload::Inline(inline) = version_record.payload() else {
            panic!("escrow object must be inline in this fixture");
        };
        inline.object().clone()
    }

    fn current_row<S: StructuredDurableDomainStateStore>(
        store: &S,
        escrow_request_id: [u8; 32],
    ) -> (Vec<u8>, FastPathSettlementRecord) {
        let key: Vec<u8> = local_instance_state::fastpath_settlement_key(
            protocol().chain_id(),
            &escrow_request_id,
        )
        .unwrap();
        let bytes: Vec<u8> = store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value()
            .expect("settlement row installed")
            .to_vec();
        let row: FastPathSettlementRecord = decode_fastpath_settlement_record(&bytes).unwrap();
        (bytes, row)
    }

    fn sign_claim(signing_key: &SigningKey, intent: FeeClaimIntent) -> Vec<u8> {
        let digest: Digest32 = fee_claim_intent_digest(&resolver(), &intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
            signature: signing_key.sign(&frame).into(),
            intent,
        };
        codec::encode_signed_fee_claim_intent(&signed).unwrap()
    }

    /// The claimant-signed leg is always signed by `key()` (the fixture's
    /// original escrow-creating sender), never by the claiming validator: it
    /// authorizes the `split`/`transfer` entrypoint on behalf of the sender
    /// whose paid intent created the escrow, exactly like
    /// `exercise_split_then_final` above.
    fn sign_leg(intent: LocalExecutionIntent) -> SignedLocalExecutionIntent {
        let frame: Vec<u8> = local_execution_signing_frame(&protocol(), &intent).unwrap();
        SignedLocalExecutionIntent {
            signature: key().sign(&frame).into(),
            intent,
        }
    }

    struct SplitClaim {
        signed_bytes: Vec<u8>,
        payout: Object,
    }

    #[allow(clippy::too_many_arguments)]
    fn build_split_claim<S: StructuredDurableDomainStateStore>(
        store: &S,
        fixture: &Fixture,
        validator: &Voter,
        resource_id: BondResourceId,
        escrow_request_id: [u8; 32],
        claim_request_id: [u8; 32],
        leg_nonce: u64,
        recipient_seed: u8,
    ) -> SplitClaim {
        let (row_bytes, row) = current_row(store, escrow_request_id);
        let share_amount: u64 = row
            .shares
            .iter()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .amount;
        let escrow_ref: ObjectRef = row.fee_output.clone().unwrap();
        let escrow_object: Object = read_current_escrow(store, escrow_ref.id);
        let recipient_key: SigningKey = SigningKey::from([recipient_seed; 32]);
        let recipient: Address = Address::new(VerificationKey::from(&recipient_key).into());
        let call: CallIntent = CallIntent {
            context: protocol(),
            request_id: claim_request_id,
            sender: sender(),
            nonce: leg_nonce,
            code: fixture.code.clone(),
            instance: execution::local_execution::instance_target(&resolver(), &fixture.instance)
                .unwrap(),
            entrypoint: "split".to_owned(),
            type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
            access: AccessManifest {
                entries: vec![entry(&escrow_object, AccessMode::Write)],
            },
            arguments: public_standard_asset::split_arguments(share_amount, recipient.as_bytes())
                .unwrap(),
            gas_limit: 500_000,
        };
        let signed_leg: SignedLocalExecutionIntent = sign_leg(LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: base_policy().digest(&resolver()).unwrap(),
            call,
            authorizations: Vec::new(),
        });
        let leg_bytes: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
        let payout_id: ObjectId = derive_local_created_object_id(
            &resolver(),
            &protocol(),
            &fixture.instance.context,
            &execution::local_execution::instance_target(&resolver(), &fixture.instance).unwrap(),
            &fixture.instance.code,
            local_execution_event_digest(&resolver(), &signed_leg).unwrap(),
            0,
        )
        .unwrap();
        let payout: Object = Object {
            id: payout_id,
            version: 1,
            owner: Owner::Address(recipient),
            type_hash: escrow_object.type_hash,
            schema_version: escrow_object.schema_version,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(share_amount),
            )
            .unwrap(),
        };
        let unclaimed_before: u64 = row
            .shares
            .iter()
            .filter(|share| !share.claimed && share.amount > 0)
            .map(|share| share.amount)
            .sum();
        let mut retained: Object = escrow_object.clone();
        retained.version += 1;
        retained.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(unclaimed_before - share_amount),
        )
        .unwrap();
        let mut next_row: FastPathSettlementRecord = row.clone();
        next_row.generation += 1;
        next_row.fee_output = Some(object_reference(&retained));
        next_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .claimed = true;
        let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id: claim_request_id,
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id: validator.entry.id,
            resource_id,
            expected_generation: row.generation,
            expected_fee_output: escrow_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount,
            recipient,
            operation: FeeClaimOperation::Split {
                leg: leg_bytes,
                expected_payout: Some(object_reference(&payout)),
            },
        };
        SplitClaim {
            signed_bytes: sign_claim(&validator.signing_key, intent),
            payout,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_final_claim<S: StructuredDurableDomainStateStore>(
        store: &S,
        fixture: &Fixture,
        validator: &Voter,
        resource_id: BondResourceId,
        escrow_request_id: [u8; 32],
        claim_request_id: [u8; 32],
        leg_nonce: u64,
        recipient_seed: u8,
    ) -> Vec<u8> {
        let (row_bytes, row) = current_row(store, escrow_request_id);
        let share_amount: u64 = row
            .shares
            .iter()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .amount;
        let escrow_ref: ObjectRef = row.fee_output.clone().unwrap();
        let escrow_object: Object = read_current_escrow(store, escrow_ref.id);
        let recipient_key: SigningKey = SigningKey::from([recipient_seed; 32]);
        let recipient: Address = Address::new(VerificationKey::from(&recipient_key).into());
        let call: CallIntent = CallIntent {
            context: protocol(),
            request_id: claim_request_id,
            sender: sender(),
            nonce: leg_nonce,
            code: fixture.code.clone(),
            instance: execution::local_execution::instance_target(&resolver(), &fixture.instance)
                .unwrap(),
            entrypoint: "transfer".to_owned(),
            type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
            access: AccessManifest {
                entries: vec![entry(&escrow_object, AccessMode::Write)],
            },
            arguments: public_standard_asset::transfer_arguments(recipient.as_bytes()).unwrap(),
            gas_limit: 500_000,
        };
        let signed_leg: SignedLocalExecutionIntent = sign_leg(LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: base_policy().digest(&resolver()).unwrap(),
            call,
            authorizations: Vec::new(),
        });
        let leg_bytes: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
        let mut transferred: Object = escrow_object.clone();
        transferred.version += 1;
        transferred.owner = Owner::Address(recipient);
        transferred.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(share_amount),
        )
        .unwrap();
        let mut next_row: FastPathSettlementRecord = row.clone();
        next_row.generation += 1;
        next_row.fee_output = Some(object_reference(&transferred));
        next_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .claimed = true;
        let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id: claim_request_id,
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id: validator.entry.id,
            resource_id,
            expected_generation: row.generation,
            expected_fee_output: escrow_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount,
            recipient,
            operation: FeeClaimOperation::FinalTransfer { leg: leg_bytes },
        };
        sign_claim(&validator.signing_key, intent)
    }

    fn build_zero_claim<S: StructuredDurableDomainStateStore>(
        store: &S,
        validator: &Voter,
        resource_id: BondResourceId,
        escrow_request_id: [u8; 32],
        claim_request_id: [u8; 32],
    ) -> Vec<u8> {
        let (row_bytes, row) = current_row(store, escrow_request_id);
        let escrow_ref: ObjectRef = row.fee_output.clone().unwrap();
        let mut next_row: FastPathSettlementRecord = row.clone();
        next_row.generation += 1;
        next_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .claimed = true;
        let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
        let recipient: Address = Address::new(VerificationKey::from(&validator.signing_key).into());
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id: claim_request_id,
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id: validator.entry.id,
            resource_id,
            expected_generation: row.generation,
            expected_fee_output: escrow_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                &resolver(),
                protocol().epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount: 0,
            recipient,
            operation: FeeClaimOperation::ZeroShare,
        };
        sign_claim(&validator.signing_key, intent)
    }

    fn submit_claim<S: StructuredDurableDomainStateStore>(
        store: &S,
        signed_bytes: &[u8],
    ) -> NodeOutput {
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
            signed_bytes,
            12,
        )
        .unwrap()
    }

    #[derive(Default)]
    struct SweepTotals {
        rows: u64,
        claims: u64,
        payouts: u64,
    }

    /// Pages through the complete settlement-key prefix under one quiescent
    /// fenced store, accumulating exact counts. Mirrors what an operator's
    /// "complete sweep" driver must do: stop and report `Err` the moment any
    /// page fails, never silently treat a partial prefix as the whole store.
    fn sweep_all<S: DurableStateKeyScanner>(
        store: &S,
        page_size: usize,
    ) -> Result<SweepTotals, FeeClaimError> {
        sweep_all_with_resolver(store, &resolver(), page_size)
    }

    /// Same as [`sweep_all`], but against a caller-supplied resolver: used by
    /// [`certified_claim_by_a_dropped_validator_survives_a_real_epoch_transition_and_hash_suite_rotation`]
    /// so the sweep resolves both the pre-transition and post-transition
    /// `HashSuite` from the same schedule-aware resolver object, exactly
    /// like a real node would.
    fn sweep_all_with_resolver<S: DurableStateKeyScanner>(
        store: &S,
        resolver: &HashSuiteResolver,
        page_size: usize,
    ) -> Result<SweepTotals, FeeClaimError> {
        let mut after: Option<Vec<u8>> = None;
        let mut totals: SweepTotals = SweepTotals::default();
        loop {
            let page: FeeEscrowInventoryPage = verify_fee_escrow_inventory_page(
                store,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                resolver,
                &[],
                protocol().chain_id(),
                after,
                NonZeroUsize::new(page_size).unwrap(),
            )?;
            totals.rows += page.verified_rows;
            totals.claims += page.verified_claims;
            totals.payouts += page.verified_payouts;
            match page.continuation_cursor {
                Some(cursor) => after = Some(cursor),
                None => return Ok(totals),
            }
        }
    }

    #[test]
    fn certified_two_escrow_inventory_sweep_survives_restart_and_fails_closed_on_tamper() {
        let voters: Vec<Voter> = four_sorted_voters();
        let entries: Vec<FastPathValidatorEntry> =
            voters.iter().map(|voter| voter.entry.clone()).collect();
        let validator_set: ValidatorSet = build_validator_set(&entries);

        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "fee-claims-multi-escrow-sqlite-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let db_path: std::path::PathBuf = directory.join("state.sqlite");
        let namespace: SqliteNamespace =
            SqliteNamespace::new(protocol().chain_id().clone(), entries[0].id, domain());
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();

        // Genuinely certified prepare/apply needs quorum (3 of 4): the
        // primary is the real file-backed SQLite store this test restarts,
        // and two more independent memory-backed stores supply the other
        // two real votes. The fourth validator never prepares at all --
        // only its identity/key matters, for its own later zero-share claim.
        let primary: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(&primary, &entries);
        let voter_store_1: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_1, &entries);
        let voter_store_2: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_2, &entries);
        let resource_id: BondResourceId = fast_path::fee_resource_id(&policy).unwrap();

        // ---- escrow 1: fully drained (split, final, zero, zero) ----
        let escrow1_request_id: [u8; 32] = [0xB1; 32];
        let escrow1_bytes: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &policy,
                request: 0xB1,
                nonce: FIRST_PAID_NONCE,
                source: &fixture.coin,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(&fixture.coin, AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        let votes1: Vec<FastVote> = vec![
            prepare_vote(&primary, &policy, &voters[0], &escrow1_bytes),
            prepare_vote(&voter_store_1, &policy, &voters[1], &escrow1_bytes),
            prepare_vote(&voter_store_2, &policy, &voters[2], &escrow1_bytes),
        ];
        let certificate1_bytes: Vec<u8> = certify(&validator_set, &votes1);
        let apply1_output: NodeOutput =
            apply_escrow(&primary, &policy, &escrow1_bytes, &certificate1_bytes);
        assert_eq!(receipt(&apply1_output).status, PaidExecutionStatus::Success);
        let charged1 = receipt(&apply1_output).charged.expect("escrow1 charged");
        assert_eq!(charged1.actual.get(), 2);
        // Every real validator store (not only the primary) applies the
        // certificate too, exactly like an honest validator would: only
        // `apply`, never `prepare` alone, releases a store's own nonce lock
        // and advances its sender-nonce sequence for the next request.
        assert_eq!(
            apply_escrow(&voter_store_1, &policy, &escrow1_bytes, &certificate1_bytes),
            apply1_output
        );
        assert_eq!(
            apply_escrow(&voter_store_2, &policy, &escrow1_bytes, &certificate1_bytes),
            apply1_output
        );

        // ---- escrow 2: partially claimed (split only, left open) ----
        let escrow2_request_id: [u8; 32] = [0xB2; 32];
        let escrow2_bytes: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &policy,
                request: 0xB2,
                nonce: FIRST_PAID_NONCE + 1,
                source: &fixture.small,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(&fixture.small, AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        let votes2: Vec<FastVote> = vec![
            prepare_vote(&primary, &policy, &voters[0], &escrow2_bytes),
            prepare_vote(&voter_store_1, &policy, &voters[1], &escrow2_bytes),
            prepare_vote(&voter_store_2, &policy, &voters[2], &escrow2_bytes),
        ];
        let certificate2_bytes: Vec<u8> = certify(&validator_set, &votes2);
        let apply2_output: NodeOutput =
            apply_escrow(&primary, &policy, &escrow2_bytes, &certificate2_bytes);
        assert_eq!(receipt(&apply2_output).status, PaidExecutionStatus::Success);
        let charged2 = receipt(&apply2_output).charged.expect("escrow2 charged");
        assert_eq!(charged2.actual.get(), 2);
        assert_ne!(
            charged1.fee_output.id, charged2.fee_output.id,
            "two distinct certified fee escrows"
        );

        // ---- escrow 1 claims: split, final, zero, zero ----
        let split1: SplitClaim = build_split_claim(
            &primary,
            &fixture,
            &voters[0],
            resource_id,
            escrow1_request_id,
            [0xD1; 32],
            next_nonce(&primary),
            0xE1,
        );
        let split1_output: NodeOutput = submit_claim(&primary, &split1.signed_bytes);
        assert_eq!(
            split1_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );

        let final1_bytes: Vec<u8> = build_final_claim(
            &primary,
            &fixture,
            &voters[1],
            resource_id,
            escrow1_request_id,
            [0xD2; 32],
            next_nonce(&primary),
            0xE2,
        );
        let final1_output: NodeOutput = submit_claim(&primary, &final1_bytes);
        assert_eq!(
            final1_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );

        let zero1a_bytes: Vec<u8> = build_zero_claim(
            &primary,
            &voters[2],
            resource_id,
            escrow1_request_id,
            [0xD3; 32],
        );
        let zero1a_output: NodeOutput = submit_claim(&primary, &zero1a_bytes);
        let zero1b_bytes: Vec<u8> = build_zero_claim(
            &primary,
            &voters[3],
            resource_id,
            escrow1_request_id,
            [0xD4; 32],
        );
        let zero1b_output: NodeOutput = submit_claim(&primary, &zero1b_bytes);

        // ---- escrow 2 claim: split only ----
        let split2: SplitClaim = build_split_claim(
            &primary,
            &fixture,
            &voters[0],
            resource_id,
            escrow2_request_id,
            [0xD5; 32],
            next_nonce(&primary),
            0xE3,
        );
        let split2_output: NodeOutput = submit_claim(&primary, &split2.signed_bytes);
        assert_eq!(
            split2_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );

        let (_, final_row1) = current_row(&primary, escrow1_request_id);
        assert_eq!(final_row1.generation, 5);
        assert!(final_row1.shares.iter().all(|share| share.claimed));
        let (_, open_row2) = current_row(&primary, escrow2_request_id);
        assert_eq!(open_row2.generation, 2);
        assert_eq!(
            open_row2
                .shares
                .iter()
                .filter(|share| !share.claimed)
                .count(),
            3
        );

        drop(primary);
        drop(voter_store_1);
        drop(voter_store_2);

        // ---- restart, then verify per-escrow chains and the full sweep ----
        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace, fence).unwrap();

        let report1: FeeClaimVerificationReport = verify_fee_claim_history(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            &escrow1_request_id,
        )
        .unwrap();
        assert_eq!(report1.final_generation, 5);
        assert_eq!(report1.verified_claims, 4);
        assert_eq!(report1.verified_positive_claims, 2);
        assert_eq!(report1.verified_payouts, 1);

        let report2: FeeClaimVerificationReport = verify_fee_claim_history(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            &escrow2_request_id,
        )
        .unwrap();
        assert_eq!(report2.final_generation, 2);
        assert_eq!(report2.verified_claims, 1);
        assert_eq!(report2.verified_positive_claims, 1);
        assert_eq!(report2.verified_payouts, 1);

        // Caller-driven multi-page sweep under a quiescent store (page size
        // 1, forcing one page per settlement row): proves coverage of every
        // retained escrow, not just the two explicit request ids above.
        let totals: SweepTotals = sweep_all(&reopened, 1).unwrap();
        assert_eq!(totals.rows, 2);
        assert_eq!(totals.claims, 5);
        assert_eq!(totals.payouts, 2);

        // Exact payout `ObjectRef`s: the signed split payout the verifier
        // proved is exactly the object this test itself derived and
        // committed, still current at its committed version after restart.
        for (payout, split_bytes) in [
            (&split1.payout, &split1.signed_bytes),
            (&split2.payout, &split2.signed_bytes),
        ] {
            let decoded: SignedFeeClaimIntent =
                decode_signed_fee_claim_intent(split_bytes).unwrap();
            let FeeClaimOperation::Split {
                expected_payout: Some(signed_ref),
                ..
            } = &decoded.intent.operation
            else {
                panic!("split claim must carry a signed payout ref");
            };
            assert_eq!(signed_ref, &object_reference(payout));
            assert_eq!(read_current_escrow(&reopened, payout.id), *payout);
        }

        // Replay non-reapplication: both certificate applies and every claim
        // on both escrows, all against the reopened store. Preserve the exact
        // installed row bytes and sender nonce across the whole replay set.
        let (row1_before_replay, _): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&reopened, escrow1_request_id);
        let (row2_before_replay, _): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&reopened, escrow2_request_id);
        let nonce_before_replay: u64 = next_nonce(&reopened);
        let replay_engine: CountingEngine = CountingEngine::new();
        let replayed1: NodeOutput = fast_path::apply(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &policy,
            &replay_engine,
            &escrow1_bytes,
            &certificate1_bytes,
        )
        .unwrap();
        assert_eq!(replayed1, apply1_output);
        assert_eq!(replay_engine.calls.get(), 0);
        let replayed2: NodeOutput = fast_path::apply(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &policy,
            &replay_engine,
            &escrow2_bytes,
            &certificate2_bytes,
        )
        .unwrap();
        assert_eq!(replayed2, apply2_output);
        assert_eq!(replay_engine.calls.get(), 0);
        for (signed, output) in [
            (&split1.signed_bytes, &split1_output),
            (&final1_bytes, &final1_output),
            (&zero1a_bytes, &zero1a_output),
            (&zero1b_bytes, &zero1b_output),
            (&split2.signed_bytes, &split2_output),
        ] {
            assert_eq!(submit_claim(&reopened, signed), *output);
        }
        assert_eq!(
            current_row(&reopened, escrow1_request_id).0,
            row1_before_replay
        );
        assert_eq!(
            current_row(&reopened, escrow2_request_id).0,
            row2_before_replay
        );
        assert_eq!(next_nonce(&reopened), nonce_before_replay);
        assert_eq!(
            read_current_escrow(&reopened, split1.payout.id),
            split1.payout
        );
        assert_eq!(
            read_current_escrow(&reopened, split2.payout.id),
            split2.payout
        );

        // ---- negative case: a tampered retained claim poisons the whole sweep ----
        let tampered_key: Vec<u8> = local_instance_state::fastpath_fee_claim_key(
            protocol().chain_id(),
            &escrow2_request_id,
            2,
        )
        .unwrap();
        let mut tampered_bytes: Vec<u8> = reopened
            .get_versioned_durable(&context(), domain(), &tampered_key)
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        *tampered_bytes.last_mut().unwrap() ^= 0x01;
        set_state(&reopened, tampered_key, StateMutation::Put(tampered_bytes));

        assert!(
            verify_fee_claim_history(
                &reopened,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                &escrow2_request_id,
            )
            .is_err()
        );
        // escrow1's own retained chain is untouched and still verifies alone...
        assert!(
            verify_fee_claim_history(
                &reopened,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                &escrow1_request_id,
            )
            .is_ok()
        );
        // ...but the caller-driven sweep that must cover every escrow fails
        // closed as soon as it reaches the tampered row: a page that
        // succeeded earlier never becomes a "complete inventory" claim on
        // its own.
        assert!(sweep_all(&reopened, 1).is_err());

        drop(reopened);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    // ── DR-0139/DR-0140 cross-epoch evidence: a claim by a validator the
    // *current* validator set has already dropped ──────────────────────────

    /// A minimal, structurally valid Active [`fast_path::records::FastPathBondRecord`]
    /// for one voter, set directly into durable state exactly like this
    /// module already seeds the fee policy and validator-set rows above --
    /// never through a real deposit leg or `genesis::install_genesis`. Only
    /// [`epoch_transition::derive_eligibility_reads`] (private to that
    /// module) ever reads this row, and only for its own structural/
    /// liability-floor fields; the synthetic `custody_object`/`authority` are
    /// never independently re-verified against real durable object state by
    /// any code this test exercises.
    fn synthetic_bond_record(
        fixture: &Fixture,
        policy: &PaidFeePolicy,
        resolver: &HashSuiteResolver,
        resource_id: BondResourceId,
        validator: &Voter,
        seed: u8,
    ) -> fast_path::records::FastPathBondRecord {
        let custody_object_id: ObjectId = ObjectId::new([seed; 32]);
        let digest: Digest32 = resolver
            .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &[seed])
            .unwrap();
        let authorization_key: [u8; 32] = validator
            .entry
            .public_key
            .clone()
            .try_into()
            .expect("ed25519 validator public key is 32 bytes");
        fast_path::records::FastPathBondRecord {
            context: protocol(),
            validator_id: validator.entry.id,
            resource_domain: resource_id.domain(),
            resource: *resource_id.value(),
            custody_object: ObjectRef {
                id: custody_object_id,
                version: 1,
                digest,
            },
            custody_object_epoch: protocol().epoch(),
            authority: execution::local_execution::ObjectAuthority {
                object_id: custody_object_id,
                instance_context: protocol(),
                instance: execution::local_execution::instance_target(resolver, &fixture.instance)
                    .unwrap(),
                code: fixture.code.clone(),
                ty: policy.asset_type.clone(),
            },
            amount: 1_000,
            committed_at_checkpoint: 10,
            generation: 1,
            lifecycle_epoch: protocol().epoch(),
            slashable_from_epoch: protocol().epoch(),
            required_minimum: 100,
            state: fast_path::records::FastPathBondState::Active,
            authorization_scheme: SignatureSchemeId::Ed25519,
            authorization_key,
        }
    }

    /// Enables a bond config on the fixture's one economics resource (reusing
    /// its existing fee-escrow resource id for bonds too) and seeds a
    /// synthetic Active bond for each given validator: the exact prerequisite
    /// [`epoch_transition::propose_and_vote`]'s `derive_eligibility_reads`
    /// gate requires before it will cast a vote naming that validator in an
    /// incoming set.
    fn install_bonded_validators<S: StructuredDurableDomainStateStore>(
        store: &S,
        fixture: &Fixture,
        policy: &PaidFeePolicy,
        resolver: &HashSuiteResolver,
        resource_id: BondResourceId,
        validators: &[&Voter],
    ) {
        let economics_key: Vec<u8> =
            local_instance_state::fastpath_economics_policy_key(&protocol()).unwrap();
        let economics_bytes: Vec<u8> = store
            .get_versioned_durable(&context(), domain(), &economics_key)
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        let mut economics: FastPathEconomicsPolicy =
            crate::economics::decode_fastpath_economics_policy(&economics_bytes).unwrap();
        economics.resources[0].bond = Some(BondResourceConfig {
            resource_id,
            min_bond: Amount::new(100),
            enabled: true,
            unbonding_epochs: 7,
            max_validator_exposure: None,
        });
        set_state(
            store,
            economics_key,
            StateMutation::Put(
                crate::economics::encode_fastpath_economics_policy(&economics).unwrap(),
            ),
        );

        for (index, validator) in validators.iter().enumerate() {
            let seed: u8 = 0xF0_u8.wrapping_add(u8::try_from(index).unwrap());
            let record: fast_path::records::FastPathBondRecord =
                synthetic_bond_record(fixture, policy, resolver, resource_id, validator, seed);
            let record_bytes: Vec<u8> =
                fast_path::records::encode_fastpath_bond_record(&record).unwrap();
            set_state(
                store,
                local_instance_state::fastpath_bond_record_key(
                    protocol().chain_id(),
                    &validator.entry.id,
                )
                .unwrap(),
                StateMutation::Put(record_bytes),
            );
        }
    }

    /// A real DR-0132 `e -> e+1` transition: every given voter independently
    /// derives and casts an outgoing-set vote over the same `next_validators`
    /// (which may be a strict subset of the outgoing set -- dropping a
    /// validator is exactly what
    /// [`certified_claim_by_a_dropped_validator_survives_a_real_epoch_transition_and_hash_suite_rotation`]
    /// exercises), a real quorum certificate is formed and verified, and
    /// [`epoch_transition::activate`] atomically installs it. Returns the new
    /// current epoch's [`PublicationContext`].
    fn advance_epoch<S: StructuredDurableDomainStateStore>(
        store: &S,
        resolver: &HashSuiteResolver,
        outgoing_validator_set: &ValidatorSet,
        voters: &[&Voter],
        next_validators: Vec<FastPathValidatorEntry>,
        checkpoint: u64,
    ) -> PublicationContext {
        let chain_id: ChainId = protocol().chain_id().clone();
        let votes: Vec<consensus::EpochTransitionVote> = voters
            .iter()
            .map(|voter| {
                epoch_transition::propose_and_vote(
                    store,
                    &context(),
                    domain(),
                    resolver,
                    &chain_id,
                    protocol().protocol_version(),
                    next_validators.clone(),
                    *voter,
                )
                .unwrap()
            })
            .collect();
        let certifier: consensus::EpochTransitionCertifier =
            consensus::EpochTransitionCertifier::new(
                chain_id.clone(),
                protocol().protocol_version(),
                protocol().epoch(),
                outgoing_validator_set.clone(),
            )
            .unwrap();
        let certificate: consensus::EpochTransitionCertificate = certifier
            .try_form_certificate(
                votes[0].next_epoch,
                votes[0].current_validator_set_digest,
                votes[0].next_validator_set_digest,
                votes[0].activation_digest,
                &votes,
                &FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("three of four outgoing validators exceed epoch-transition quorum");
        let certificate_bytes: Vec<u8> =
            consensus::encode_epoch_transition_certificate(&certificate).unwrap();
        let outcome: epoch_transition::EpochActivationOutcome = epoch_transition::activate(
            store,
            &context(),
            domain(),
            resolver,
            &chain_id,
            protocol().protocol_version(),
            next_validators,
            &certificate_bytes,
            checkpoint,
        )
        .unwrap();
        let record: epoch_transition::FastPathEpochTransitionRecord = match outcome {
            epoch_transition::EpochActivationOutcome::Activated(record)
            | epoch_transition::EpochActivationOutcome::AlreadyActivated(record) => record,
        };
        PublicationContext::new(chain_id, protocol().protocol_version(), record.to_epoch).unwrap()
    }

    /// Like [`build_zero_claim`], but the outer envelope's own `context` is
    /// the caller-supplied `claim_context` (the *current* committed epoch)
    /// while `certificate_epoch` still names the escrow row's own original
    /// certification epoch: exactly the shape a validator the live set has
    /// already dropped must use to claim under DR-0139/DR-0140's historical
    /// framing.
    fn build_zero_claim_at<S: StructuredDurableDomainStateStore>(
        store: &S,
        resolver: &HashSuiteResolver,
        claim_context: &PublicationContext,
        validator: &Voter,
        resource_id: BondResourceId,
        escrow_request_id: [u8; 32],
        claim_request_id: [u8; 32],
    ) -> Vec<u8> {
        let (row_bytes, row) = current_row(store, escrow_request_id);
        let escrow_ref: ObjectRef = row.fee_output.clone().unwrap();
        let mut next_row: FastPathSettlementRecord = row.clone();
        next_row.generation += 1;
        next_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .claimed = true;
        let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
        let recipient: Address = Address::new(VerificationKey::from(&validator.signing_key).into());
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: claim_context.clone(),
            request_id: claim_request_id,
            escrow_request_id,
            certificate_epoch: row.context.epoch(),
            validator_id: validator.entry.id,
            resource_id,
            expected_generation: row.generation,
            expected_fee_output: escrow_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                resolver,
                row.context.epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                resolver,
                row.context.epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount: 0,
            recipient,
            operation: FeeClaimOperation::ZeroShare,
        };
        let digest: Digest32 = fee_claim_intent_digest(resolver, &intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
            signature: validator.signing_key.sign(&frame).into(),
            intent,
        };
        codec::encode_signed_fee_claim_intent(&signed).unwrap()
    }

    fn object_reference_at(
        resolver: &HashSuiteResolver,
        epoch: Epoch,
        object: &Object,
    ) -> ObjectRef {
        let bytes: Vec<u8> = objects::encode_object(object).unwrap();
        ObjectRef {
            id: object.id,
            version: object.version,
            digest: resolver
                .hash_for_purpose(epoch, HashPurpose::Object, &bytes)
                .unwrap(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_split_claim_at<S: StructuredDurableDomainStateStore>(
        store: &S,
        resolver: &HashSuiteResolver,
        claim_context: &PublicationContext,
        fixture: &Fixture,
        validator: &Voter,
        resource_id: BondResourceId,
        escrow_request_id: [u8; 32],
        claim_request_id: [u8; 32],
        recipient_seed: u8,
    ) -> SplitClaim {
        let (row_bytes, row): (Vec<u8>, FastPathSettlementRecord) =
            current_row(store, escrow_request_id);
        let share_amount: u64 = row
            .shares
            .iter()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .amount;
        assert!(share_amount > 0);
        let escrow_ref: ObjectRef = row.fee_output.clone().unwrap();
        let escrow_object: Object = read_current_escrow(store, escrow_ref.id);
        let recipient_key: SigningKey = SigningKey::from([recipient_seed; 32]);
        let recipient: Address = Address::new(VerificationKey::from(&recipient_key).into());
        // A newly created payout gets the current suite's type identity;
        // the already-existing escrow keeps its original type hash on update.
        let claim_epoch_type_hash: Digest32 = abi::package_types::derive_scoped_type_id(
            resolver,
            claim_context.epoch(),
            &fixture.policy.asset_type,
        )
        .unwrap();
        assert_ne!(escrow_object.type_hash, claim_epoch_type_hash);
        let instance: execution::call::InstanceTarget =
            execution::local_execution::instance_target(resolver, &fixture.instance).unwrap();
        let leg_nonce: u64 = crate::query_sender_next_nonce(
            store,
            &context(),
            domain(),
            claim_context.chain_id().clone(),
            claim_context.protocol_version(),
            claim_context.epoch(),
            sender(),
        )
        .unwrap();
        let call: CallIntent = CallIntent {
            context: claim_context.clone(),
            request_id: claim_request_id,
            sender: sender(),
            nonce: leg_nonce,
            code: fixture.code.clone(),
            instance: instance.clone(),
            entrypoint: "split".to_owned(),
            type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
            access: AccessManifest {
                entries: vec![entry(&escrow_object, AccessMode::Write)],
            },
            arguments: public_standard_asset::split_arguments(share_amount, recipient.as_bytes())
                .unwrap(),
            gas_limit: 500_000,
        };
        let policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(claim_context.clone());
        let leg_intent: LocalExecutionIntent = LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: policy.digest(resolver).unwrap(),
            call,
            authorizations: Vec::new(),
        };
        let leg_frame: Vec<u8> = local_execution_signing_frame(claim_context, &leg_intent).unwrap();
        let signed_leg: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
            signature: key().sign(&leg_frame).into(),
            intent: leg_intent,
        };
        let leg_bytes: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
        let payout_id: ObjectId = derive_local_created_object_id(
            resolver,
            claim_context,
            &fixture.instance.context,
            &instance,
            &fixture.instance.code,
            local_execution_event_digest(resolver, &signed_leg).unwrap(),
            0,
        )
        .unwrap();
        let payout: Object = Object {
            id: payout_id,
            version: 1,
            owner: Owner::Address(recipient),
            type_hash: claim_epoch_type_hash,
            schema_version: escrow_object.schema_version,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(share_amount),
            )
            .unwrap(),
        };
        let unclaimed_before: u64 = row
            .shares
            .iter()
            .filter(|share| !share.claimed && share.amount > 0)
            .map(|share| share.amount)
            .sum();
        let mut retained: Object = escrow_object.clone();
        retained.version += 1;
        retained.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(unclaimed_before - share_amount),
        )
        .unwrap();
        let mut next_row: FastPathSettlementRecord = row.clone();
        next_row.generation += 1;
        next_row.fee_output = Some(object_reference_at(
            resolver,
            claim_context.epoch(),
            &retained,
        ));
        next_row.fee_output_epoch = Some(claim_context.epoch());
        next_row
            .shares
            .iter_mut()
            .find(|share| share.validator_id == validator.entry.id)
            .unwrap()
            .claimed = true;
        let next_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: claim_context.clone(),
            request_id: claim_request_id,
            escrow_request_id,
            certificate_epoch: row.context.epoch(),
            validator_id: validator.entry.id,
            resource_id,
            expected_generation: row.generation,
            expected_fee_output: escrow_ref,
            expected_previous_row_digest: fee_claim_row_digest(
                resolver,
                row.context.epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                resolver,
                row.context.epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount,
            recipient,
            operation: FeeClaimOperation::Split {
                leg: leg_bytes,
                expected_payout: Some(object_reference_at(
                    resolver,
                    claim_context.epoch(),
                    &payout,
                )),
            },
        };
        let digest: Digest32 = fee_claim_intent_digest(resolver, &intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
            signature: validator.signing_key.sign(&frame).into(),
            intent,
        };
        SplitClaim {
            signed_bytes: codec::encode_signed_fee_claim_intent(&signed).unwrap(),
            payout,
        }
    }

    /// Like [`submit_claim`], but against a caller-supplied resolver and
    /// `expected` context, so a claim can legitimately be submitted "at" a
    /// context later than the one its escrow was certified under.
    fn submit_claim_at<S: StructuredDurableDomainStateStore>(
        store: &S,
        resolver: &HashSuiteResolver,
        expected: &PublicationContext,
        signed_bytes: &[u8],
    ) -> NodeOutput {
        handle_fee_claim(
            store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            resolver,
            &[],
            expected,
            &LocalExecutionPolicy::generic_object_results(expected.clone()),
            &LocalWasmExecutionEngine::new(),
            signed_bytes,
            12,
        )
        .unwrap()
    }

    /// DR-0139/DR-0140 cross-epoch evidence: certifies one escrow at epoch
    /// `E` with a real 3-of-4 quorum, then performs a genuine DR-0132
    /// `propose_and_vote`/`activate` transition to `E + 1` that both drops
    /// one of the four certificate-epoch validators from the incoming set
    /// and rotates the active `HashSuite`. The dropped validator then
    /// submits a real signed zero-share claim whose outer envelope names the
    /// *current* `E + 1` context (fenced against the live epoch record)
    /// while its `certificate_epoch` still names `E`. After a real
    /// file-backed SQLite close/reopen, `verify_fee_claim_history` and a
    /// caller-driven inventory sweep both still accept it -- proving they
    /// resolve the claimant's signature and the row's own digest against the
    /// certificate-epoch validator set and hash suite, never the live epoch
    /// 1 set, which no longer contains this validator at all.
    #[test]
    fn certified_claim_by_a_dropped_validator_survives_a_real_epoch_transition_and_hash_suite_rotation()
     {
        let voters: Vec<Voter> = four_sorted_voters();
        let entries: Vec<FastPathValidatorEntry> =
            voters.iter().map(|voter| voter.entry.clone()).collect();
        let genesis_validator_set: ValidatorSet = build_validator_set(&entries);
        let rotation_epoch: u64 = protocol().epoch().get() + 1;
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(rotation_epoch),
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap();

        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "fee-claims-dropped-validator-sqlite-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let db_path: std::path::PathBuf = directory.join("state.sqlite");
        let namespace: SqliteNamespace =
            SqliteNamespace::new(protocol().chain_id().clone(), entries[0].id, domain());
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();

        let primary: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(&primary, &entries);
        let voter_store_1: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_1, &entries);
        let voter_store_2: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_2, &entries);
        let resource_id: BondResourceId = fast_path::fee_resource_id(&policy).unwrap();

        // ---- the escrow: certified at epoch 0 with a real 3-of-4 quorum ----
        let escrow_request_id: [u8; 32] = [0xC1; 32];
        let escrow_bytes: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &policy,
                request: 0xC1,
                nonce: FIRST_PAID_NONCE,
                source: &fixture.coin,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(&fixture.coin, AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        let votes: Vec<FastVote> = vec![
            prepare_vote(&primary, &policy, &voters[0], &escrow_bytes),
            prepare_vote(&voter_store_1, &policy, &voters[1], &escrow_bytes),
            prepare_vote(&voter_store_2, &policy, &voters[2], &escrow_bytes),
        ];
        let certificate_bytes: Vec<u8> = certify(&genesis_validator_set, &votes);
        let apply_output: NodeOutput =
            apply_escrow(&primary, &policy, &escrow_bytes, &certificate_bytes);
        assert_eq!(receipt(&apply_output).status, PaidExecutionStatus::Success);
        assert_eq!(receipt(&apply_output).charged.unwrap().actual.get(), 2);

        // ---- a real DR-0132 epoch transition 0 -> 1: drops voters[3] from
        // the incoming set and rotates the active HashSuite ----
        let retained: Vec<&Voter> = vec![&voters[0], &voters[1], &voters[2]];
        install_bonded_validators(
            &primary,
            &fixture,
            &policy,
            &resolver,
            resource_id,
            &retained,
        );
        let next_validators: Vec<FastPathValidatorEntry> =
            retained.iter().map(|voter| voter.entry.clone()).collect();
        let next_context: PublicationContext = advance_epoch(
            &primary,
            &resolver,
            &genesis_validator_set,
            &retained,
            next_validators,
            20,
        );
        assert_eq!(next_context.epoch().get(), rotation_epoch);

        // Sanity: voters[3] really is absent from the live epoch-1 set, and
        // still present in the retained epoch-0 (certificate-epoch) set.
        let epoch1_set: ValidatorSet = equivocation::load_historical_validator_set(
            &primary,
            &context(),
            domain(),
            &resolver,
            protocol().chain_id(),
            protocol().protocol_version(),
            next_context.epoch(),
        )
        .unwrap();
        assert!(epoch1_set.get(voters[3].entry.id).is_none());
        let epoch0_set: ValidatorSet = equivocation::load_historical_validator_set(
            &primary,
            &context(),
            domain(),
            &resolver,
            protocol().chain_id(),
            protocol().protocol_version(),
            protocol().epoch(),
        )
        .unwrap();
        assert!(epoch0_set.get(voters[3].entry.id).is_some());

        // ---- the dropped validator (voters[3]) submits a real signed claim
        // under the *current* epoch-1 context, naming the original epoch-0
        // certificate ----
        let claim_request_id: [u8; 32] = [0xC2; 32];
        let claim_bytes: Vec<u8> = build_zero_claim_at(
            &primary,
            &resolver,
            &next_context,
            &voters[3],
            resource_id,
            escrow_request_id,
            claim_request_id,
        );
        let claim_output: NodeOutput =
            submit_claim_at(&primary, &resolver, &next_context, &claim_bytes);
        assert_eq!(
            claim_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let (_, claimed_row): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&primary, escrow_request_id);
        assert_eq!(claimed_row.generation, 2);
        assert!(
            claimed_row
                .shares
                .iter()
                .find(|share| share.validator_id == voters[3].entry.id)
                .unwrap()
                .claimed
        );

        drop(primary);
        drop(voter_store_1);
        drop(voter_store_2);

        // ---- restart, then independently re-verify the whole chain and
        // inventory using the same schedule-aware resolver ----
        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace, fence).unwrap();

        let report: FeeClaimVerificationReport = verify_fee_claim_history(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver,
            &[],
            protocol().chain_id(),
            &escrow_request_id,
        )
        .unwrap();
        assert_eq!(report.final_generation, 2);
        assert_eq!(report.verified_claims, 1);
        assert_eq!(report.verified_positive_claims, 0);
        assert_eq!(report.verified_payouts, 0);

        let totals: SweepTotals = sweep_all_with_resolver(&reopened, &resolver, 1).unwrap();
        assert_eq!(totals.rows, 1);
        assert_eq!(totals.claims, 1);
        assert_eq!(totals.payouts, 0);

        // ---- replay non-reapplication across the restart ----
        let (row_before_replay, _): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&reopened, escrow_request_id);
        let replay_engine: CountingEngine = CountingEngine::new();
        let replayed: NodeOutput = fast_path::apply(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver,
            &[],
            &protocol(),
            &base_policy(),
            &policy,
            &replay_engine,
            &escrow_bytes,
            &certificate_bytes,
        )
        .unwrap();
        assert_eq!(replayed, apply_output);
        assert_eq!(replay_engine.calls.get(), 0);
        assert_eq!(
            submit_claim_at(&reopened, &resolver, &next_context, &claim_bytes),
            claim_output
        );
        assert_eq!(
            current_row(&reopened, escrow_request_id).0,
            row_before_replay
        );

        drop(reopened);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn certified_positive_claim_by_a_dropped_validator_survives_epoch_rotation_and_restart() {
        let voters: Vec<Voter> = four_sorted_voters();
        let entries: Vec<FastPathValidatorEntry> =
            voters.iter().map(|voter| voter.entry.clone()).collect();
        let genesis_validator_set: ValidatorSet = build_validator_set(&entries);
        let rotation_epoch: u64 = protocol().epoch().get() + 1;
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(rotation_epoch),
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap();

        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "fee-claims-positive-cross-epoch-sqlite-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let db_path: std::path::PathBuf = directory.join("state.sqlite");
        let namespace: SqliteNamespace =
            SqliteNamespace::new(protocol().chain_id().clone(), entries[0].id, domain());
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();

        let primary: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(&primary, &entries);
        let voter_store_1: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_1, &entries);
        let voter_store_2: MemoryDurableStateStore = memory_store();
        install_all(&voter_store_2, &entries);
        let resource_id: BondResourceId = fast_path::fee_resource_id(&policy).unwrap();

        // The certified fee of two is allocated [1, 1, 0, 0]. Voter 1
        // signs the certificate, owns a positive share, and is then removed
        // from the active set before claiming that share.
        let escrow_request_id: [u8; 32] = [0xC3; 32];
        let escrow_bytes: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &policy,
                request: 0xC3,
                nonce: FIRST_PAID_NONCE,
                source: &fixture.coin,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(&fixture.coin, AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        let votes: Vec<FastVote> = vec![
            prepare_vote(&primary, &policy, &voters[0], &escrow_bytes),
            prepare_vote(&voter_store_1, &policy, &voters[1], &escrow_bytes),
            prepare_vote(&voter_store_2, &policy, &voters[2], &escrow_bytes),
        ];
        let certificate_bytes: Vec<u8> = certify(&genesis_validator_set, &votes);
        let apply_output: NodeOutput =
            apply_escrow(&primary, &policy, &escrow_bytes, &certificate_bytes);
        assert_eq!(receipt(&apply_output).status, PaidExecutionStatus::Success);
        assert_eq!(receipt(&apply_output).charged.unwrap().actual.get(), 2);
        let (_, certified_row): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&primary, escrow_request_id);
        assert_eq!(certified_row.shares[1].validator_id, voters[1].entry.id);
        assert_eq!(certified_row.shares[1].amount, 1);

        // The transition is the real vote/certificate/activation path. Its
        // bond eligibility rows are synthetic fixture prerequisites, not
        // evidence of real bond deposits or production network capacity.
        let retained: Vec<&Voter> = vec![&voters[0], &voters[2], &voters[3]];
        install_bonded_validators(
            &primary,
            &fixture,
            &policy,
            &resolver,
            resource_id,
            &retained,
        );
        let next_validators: Vec<FastPathValidatorEntry> =
            retained.iter().map(|voter| voter.entry.clone()).collect();
        let next_context: PublicationContext = advance_epoch(
            &primary,
            &resolver,
            &genesis_validator_set,
            &retained,
            next_validators,
            20,
        );
        assert_eq!(next_context.epoch().get(), rotation_epoch);
        let epoch1_set: ValidatorSet = equivocation::load_historical_validator_set(
            &primary,
            &context(),
            domain(),
            &resolver,
            protocol().chain_id(),
            protocol().protocol_version(),
            next_context.epoch(),
        )
        .unwrap();
        assert!(epoch1_set.get(voters[1].entry.id).is_none());

        let claim_request_id: [u8; 32] = [0xC4; 32];
        let split: SplitClaim = build_split_claim_at(
            &primary,
            &resolver,
            &next_context,
            &fixture,
            &voters[1],
            resource_id,
            escrow_request_id,
            claim_request_id,
            0xE4,
        );
        let claim_output: NodeOutput =
            submit_claim_at(&primary, &resolver, &next_context, &split.signed_bytes);
        assert_eq!(
            claim_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let (_, claimed_row): (Vec<u8>, FastPathSettlementRecord) =
            current_row(&primary, escrow_request_id);
        assert_eq!(claimed_row.generation, 2);
        assert_eq!(claimed_row.fee_output_epoch, Some(next_context.epoch()));
        assert_eq!(read_current_escrow(&primary, split.payout.id), split.payout);

        drop(primary);
        drop(voter_store_1);
        drop(voter_store_2);

        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
        let report: FeeClaimVerificationReport = verify_fee_claim_history(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver,
            &[],
            protocol().chain_id(),
            &escrow_request_id,
        )
        .unwrap();
        assert_eq!(report.final_generation, 2);
        assert_eq!(report.verified_claims, 1);
        assert_eq!(report.verified_positive_claims, 1);
        assert_eq!(report.verified_payouts, 1);
        let totals: SweepTotals = sweep_all_with_resolver(&reopened, &resolver, 1).unwrap();
        assert_eq!(totals.rows, 1);
        assert_eq!(totals.claims, 1);
        assert_eq!(totals.payouts, 1);

        let row_before_replay: Vec<u8> = current_row(&reopened, escrow_request_id).0;
        let payout_head_before_replay: DurableObjectHead = reopened
            .get_object_head(&context(), domain(), split.payout.id)
            .unwrap();
        let payout_version_before_replay: Option<DurableObjectVersionRecord> = reopened
            .get_object_version(
                &context(),
                domain(),
                split.payout.id,
                DurableObjectVersion::new(split.payout.version).unwrap(),
            )
            .unwrap();
        let next_nonce_before_replay: u64 = crate::query_sender_next_nonce(
            &reopened,
            &context(),
            domain(),
            next_context.chain_id().clone(),
            next_context.protocol_version(),
            next_context.epoch(),
            sender(),
        )
        .unwrap();
        let replay_engine: CountingEngine = CountingEngine::new();
        let replayed: NodeOutput = fast_path::apply(
            &reopened,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver,
            &[],
            &protocol(),
            &base_policy(),
            &policy,
            &replay_engine,
            &escrow_bytes,
            &certificate_bytes,
        )
        .unwrap();
        assert_eq!(replayed, apply_output);
        assert_eq!(replay_engine.calls.get(), 0);
        assert_eq!(
            submit_claim_at(&reopened, &resolver, &next_context, &split.signed_bytes),
            claim_output
        );
        assert_eq!(
            current_row(&reopened, escrow_request_id).0,
            row_before_replay
        );
        assert_eq!(
            reopened
                .get_object_head(&context(), domain(), split.payout.id)
                .unwrap(),
            payout_head_before_replay
        );
        assert_eq!(
            reopened
                .get_object_version(
                    &context(),
                    domain(),
                    split.payout.id,
                    DurableObjectVersion::new(split.payout.version).unwrap(),
                )
                .unwrap(),
            payout_version_before_replay
        );
        assert_eq!(
            crate::query_sender_next_nonce(
                &reopened,
                &context(),
                domain(),
                next_context.chain_id().clone(),
                next_context.protocol_version(),
                next_context.epoch(),
                sender(),
            )
            .unwrap(),
            next_nonce_before_replay
        );

        drop(reopened);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
