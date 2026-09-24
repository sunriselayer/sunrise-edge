use super::*;
use crate::fast_path::{FastPathValidatorEntry, install_validator_set};
use crate::genesis::{
    self,
    tests::{
        build_fixture, chain, context, custody_object_entry, domain, key, manifest_with_custody,
        protocol, resign_manifest, resolver, sender,
    },
};
use abi::call_values::{CallValue, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
    derive_local_created_object_id, encode_signed_local_execution, instance_target,
    local_execution_event_digest, local_execution_signing_frame,
};
use objects::{Address, ObjectId, ProtocolCustodyScope};
use protocol_types::{HashAlgorithmId, SignatureSchemeId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectProvenance, DurableObjectRoutingProjection, DurableObjectVersion,
    DurableObjectVersionRecord, DurableReadError, DurableRequestId, DurableRequestReceipt,
    IndeterminateCommitReason, MemoryBlobStore, MemoryDurableStateStore, StateReadAssertion,
    VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Duplicated from `fee_claims::tests` rather than shared: that module's
/// helper is private to its own file and this crate keeps object identity
/// helpers local to whichever test module actually needs them.
fn object_ref(object: &Object) -> ObjectRef {
    let bytes: Vec<u8> = objects::encode_object(object).unwrap();
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &bytes)
            .unwrap(),
    }
}

struct ZeroClaimFixture {
    row_key: Vec<u8>,
    next_row_bytes: Vec<u8>,
    claim_key: Vec<u8>,
    request_a: [u8; 32],
    request_b: [u8; 32],
    signed_a: Vec<u8>,
    signed_b: Vec<u8>,
}

fn zero_claim_fixture<S: StructuredDurableDomainStateStore>(store: &S) -> ZeroClaimFixture {
    let positive_key: SigningKey = SigningKey::from([0xb3; 32]);
    let zero_key: SigningKey = SigningKey::from([0xb4; 32]);
    let positive_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&positive_key).into();
    let zero_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&zero_key).into();
    let zero_id: ValidatorId = ValidatorId::new(zero_public);
    let mut validators: Vec<FastPathValidatorEntry> = [positive_public, zero_public]
        .into_iter()
        .map(|public_key| FastPathValidatorEntry {
            id: ValidatorId::new(public_key),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        })
        .collect();
    validators.sort_by_key(|entry| entry.id);
    install_validator_set(
        store,
        &context(1),
        domain(),
        &resolver(),
        protocol(),
        validators,
    )
    .unwrap();

    let escrow_request_id: [u8; 32] = [0xb5; 32];
    let resource_id: BondResourceId = BondResourceId::new(7, [0xb6; 32]).unwrap();
    let fee_output: ObjectRef = ObjectRef {
        id: ObjectId::new([0xb7; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xb8; 32]),
    };
    let mut shares: Vec<FastPathFeeShare> = vec![
        FastPathFeeShare {
            validator_id: ValidatorId::new(positive_public),
            amount: 1,
            claimed: false,
        },
        FastPathFeeShare {
            validator_id: zero_id,
            amount: 0,
            claimed: false,
        },
    ];
    shares.sort_by_key(|share| share.validator_id);
    let row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: protocol(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(fee_output.clone()),
        fee_output_epoch: Some(protocol().epoch()),
        total_amount: Some(1),
        shares,
    };
    let row_key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap();
    let row_bytes: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
    let setup: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
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
        store.commit_durable(&context(1), setup),
        DurableCommitOutcome::Committed
    );

    let mut next: FastPathSettlementRecord = row.clone();
    next.generation = 2;
    next.shares
        .iter_mut()
        .find(|share| share.validator_id == zero_id)
        .unwrap()
        .claimed = true;
    let next_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&next).unwrap();
    let previous_digest: Digest32 =
        fee_claim_row_digest(&resolver(), protocol().epoch(), &row_bytes).unwrap();
    let next_digest: Digest32 =
        fee_claim_row_digest(&resolver(), protocol().epoch(), &next_row_bytes).unwrap();
    let signed = |request_id: [u8; 32]| -> Vec<u8> {
        let intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id,
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id: zero_id,
            resource_id,
            expected_generation: 1,
            expected_fee_output: fee_output.clone(),
            expected_previous_row_digest: previous_digest,
            expected_next_row_digest: next_digest,
            share_amount: 0,
            recipient: Address::new([0xb9; 32]),
            operation: FeeClaimOperation::ZeroShare,
        };
        let digest: Digest32 = fee_claim_intent_digest(&resolver(), &intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        codec::encode_signed_fee_claim_intent(&SignedFeeClaimIntent {
            signature: zero_key.sign(&frame).into(),
            intent,
        })
        .unwrap()
    };
    let request_a: [u8; 32] = [0xba; 32];
    let request_b: [u8; 32] = [0xbb; 32];
    ZeroClaimFixture {
        row_key,
        next_row_bytes,
        claim_key: local_instance_state::fastpath_fee_claim_key(&chain(), &escrow_request_id, 2)
            .unwrap(),
        request_a,
        request_b,
        signed_a: signed(request_a),
        signed_b: signed(request_b),
    }
}

fn submit_claim<S: StructuredDurableDomainStateStore>(
    store: &S,
    signed: &[u8],
) -> Result<NodeOutput, FeeClaimError> {
    handle_fee_claim(
        store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &LocalExecutionPolicy::generic_object_results(protocol()),
        &LocalWasmExecutionEngine::new(),
        signed,
        12,
    )
}

enum InterceptMode {
    CommitGate(Arc<CommitGate>),
    PersistThenAmbiguous(AtomicBool),
    RejectAmbiguously(AtomicBool),
}

/// Rendezvous after both requests have read generation 1. Timeout converts
/// pre-commit regressions into test failures instead of hanging CI forever.
struct CommitGate {
    arrived: Mutex<u8>,
    ready: Condvar,
}

impl CommitGate {
    fn wait_for_both(&self) {
        let mut arrived: std::sync::MutexGuard<'_, u8> = self.arrived.lock().unwrap();
        *arrived += 1;
        if *arrived == 2 {
            self.ready.notify_all();
            return;
        }
        let (_arrived, wait): (std::sync::MutexGuard<'_, u8>, std::sync::WaitTimeoutResult) = self
            .ready
            .wait_timeout_while(arrived, Duration::from_secs(10), |count| *count < 2)
            .unwrap();
        assert!(
            !wait.timed_out(),
            "second claim never reached the commit boundary"
        );
    }
}

struct InterceptStore<S> {
    inner: S,
    mode: InterceptMode,
}

impl<S: StructuredDurableDomainStateStore> DurableDomainStateStore for InterceptStore<S> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}

impl<S: StructuredDurableDomainStateStore> StructuredDurableDomainStateStore for InterceptStore<S> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        match &self.mode {
            InterceptMode::CommitGate(gate) => {
                gate.wait_for_both();
                self.inner.commit_invocation(context, transaction)
            }
            InterceptMode::PersistThenAmbiguous(armed) if armed.swap(false, Ordering::SeqCst) => {
                assert_eq!(
                    self.inner.commit_invocation(context, transaction),
                    DurableCommitOutcome::Committed
                );
                DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
            InterceptMode::RejectAmbiguously(armed) if armed.swap(false, Ordering::SeqCst) => {
                DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
            _ => self.inner.commit_invocation(context, transaction),
        }
    }
}

#[test]
fn fee_claim_ambiguous_commit_reconciles_both_persisted_and_uncommitted_outcomes() {
    for persisted in [true, false] {
        let inner: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let fixture: ZeroClaimFixture = zero_claim_fixture(&inner);
        let mode: InterceptMode = if persisted {
            InterceptMode::PersistThenAmbiguous(AtomicBool::new(true))
        } else {
            InterceptMode::RejectAmbiguously(AtomicBool::new(true))
        };
        let store: InterceptStore<MemoryDurableStateStore> = InterceptStore { inner, mode };
        assert!(matches!(
            submit_claim(&store, &fixture.signed_a),
            Err(FeeClaimError::Node(
                NodeCoreError::DurableCommitIndeterminate(
                    IndeterminateCommitReason::ConnectionLost
                )
            ))
        ));
        let after_first: VersionedStateValue = store
            .get_versioned_durable(&context(1), domain(), &fixture.row_key)
            .unwrap();
        let receipt_after_first: Option<DurableRequestReceipt> = store
            .get_request_receipt(
                &context(1),
                domain(),
                DurableRequestId::new(fixture.request_a).unwrap(),
            )
            .unwrap();
        assert_eq!(
            after_first.value() == Some(fixture.next_row_bytes.as_slice()),
            persisted
        );
        assert_eq!(receipt_after_first.is_some(), persisted);

        // Retry the exact signed request. A persisted commit returns its
        // recorded receipt before reading the now-advanced settlement row;
        // an uncommitted attempt safely executes once on the unchanged row.
        let replay: NodeOutput = submit_claim(&store, &fixture.signed_a).unwrap();
        assert_eq!(
            replay.responses()[0].payload(),
            Some(fixture.next_row_bytes.as_slice())
        );
        let settled: VersionedStateValue = store
            .get_versioned_durable(&context(1), domain(), &fixture.row_key)
            .unwrap();
        assert_eq!(settled.value(), Some(fixture.next_row_bytes.as_slice()));
        assert_eq!(settled.revision(), StateRevision::new(2));
        assert_eq!(
            store
                .get_versioned_durable(&context(1), domain(), &fixture.claim_key)
                .unwrap()
                .value(),
            Some(fixture.signed_a.as_slice())
        );
        assert_eq!(submit_claim(&store, &fixture.signed_a).unwrap(), replay);
        assert!(submit_claim(&store, &fixture.signed_b).is_err());
    }
}

#[test]
fn file_backed_sqlite_competing_claim_writers_commit_one_generation_once() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf =
        std::env::temp_dir().join(format!("fee-claim-race-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let db_path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace =
        SqliteNamespace::new(chain(), ValidatorId::new([0xbc; 32]), domain());
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let fixture: ZeroClaimFixture = {
        let setup: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        zero_claim_fixture(&setup)
    };
    let gate: Arc<CommitGate> = Arc::new(CommitGate {
        arrived: Mutex::new(0),
        ready: Condvar::new(),
    });
    let writer_a: InterceptStore<SqliteDurableStore> = InterceptStore {
        inner: SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap(),
        mode: InterceptMode::CommitGate(Arc::clone(&gate)),
    };
    let writer_b: InterceptStore<SqliteDurableStore> = InterceptStore {
        inner: SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap(),
        mode: InterceptMode::CommitGate(gate),
    };
    let signed_a: Vec<u8> = fixture.signed_a.clone();
    let signed_b: Vec<u8> = fixture.signed_b.clone();
    // SQLite is normally single-writer; two handles deliberately exercise
    // the durable CAS collision, not an operational HA/failover path.
    let (result_a, result_b): (
        Result<NodeOutput, FeeClaimError>,
        Result<NodeOutput, FeeClaimError>,
    ) = std::thread::scope(|scope| {
        let a = scope.spawn(move || submit_claim(&writer_a, &signed_a));
        let b = scope.spawn(move || submit_claim(&writer_b, &signed_b));
        (a.join().unwrap(), b.join().unwrap())
    });
    let a_won: bool = result_a.is_ok();
    let b_won: bool = result_b.is_ok();
    assert_ne!(a_won, b_won, "exactly one generation-1 claim must win");
    let loser: &Result<NodeOutput, FeeClaimError> = if a_won { &result_b } else { &result_a };
    assert!(
        matches!(
            loser,
            Err(FeeClaimError::Node(NodeCoreError::StateConflict))
        ),
        "the losing commit must reject its stale generation CAS assertion: {loser:?}"
    );

    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
    let row: VersionedStateValue = reopened
        .get_versioned_durable(&context(1), domain(), &fixture.row_key)
        .unwrap();
    assert_eq!(row.value(), Some(fixture.next_row_bytes.as_slice()));
    assert_eq!(row.revision(), StateRevision::new(2));
    let winning_bytes: &[u8] = if a_won {
        &fixture.signed_a
    } else {
        &fixture.signed_b
    };
    assert_eq!(
        reopened
            .get_versioned_durable(&context(1), domain(), &fixture.claim_key)
            .unwrap()
            .value(),
        Some(winning_bytes)
    );
    let receipt_a: Option<DurableRequestReceipt> = reopened
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(fixture.request_a).unwrap(),
        )
        .unwrap();
    let receipt_b: Option<DurableRequestReceipt> = reopened
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(fixture.request_b).unwrap(),
        )
        .unwrap();
    assert_eq!(receipt_a.is_some(), a_won);
    assert_eq!(receipt_b.is_some(), b_won);
    std::fs::remove_dir_all(&directory).unwrap();
}

/// Two distinct valid signed positive (object-mutating) claims from two
/// different validators, both authorized against the identical generation-1
/// settlement row and identical escrow object, both reserving the identical
/// first sender nonce -- the real-WASM analog of [`ZeroClaimFixture`]. Split
/// amounts are asymmetric (300_000 / 700_000 of a 1_000_000 escrow) so the
/// winner is independently identifiable from the retained escrow bytes, not
/// only from which share the settlement row marks claimed.
struct PositiveClaimFixture {
    row_key: Vec<u8>,
    claim_key: Vec<u8>,
    coin_id: ObjectId,
    sender: [u8; 32],
    request_a: [u8; 32],
    request_b: [u8; 32],
    signed_a: Vec<u8>,
    signed_b: Vec<u8>,
    next_bytes_a: Vec<u8>,
    next_bytes_b: Vec<u8>,
    escrow_bytes_a: Vec<u8>,
    escrow_bytes_b: Vec<u8>,
    payout_id_a: ObjectId,
    payout_id_b: ObjectId,
    payout_bytes_a: Vec<u8>,
    payout_bytes_b: Vec<u8>,
}

fn positive_claim_fixture<S: StructuredDurableDomainStateStore>(store: &S) -> PositiveClaimFixture {
    let (_base_manifest, _origin, instance, def_id, coin_id) = build_fixture();
    let mut manifest: genesis::GenesisManifest = manifest_with_custody(ObjectId::new([0xc0; 32]));
    let second_key: SigningKey = SigningKey::from([0xc1; 32]);
    let second_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&second_key).into();
    let second_validator: ValidatorId = ValidatorId::new(second_public);
    let mut second_bond: genesis::GenesisObjectEntry =
        custody_object_entry(&manifest, ObjectId::new([0xc2; 32]), chain());
    let Owner::ProtocolCustody(second_scope) = &mut second_bond.object.owner else {
        panic!("second bond custody owner");
    };
    second_scope.subject = second_public;
    manifest.objects.push(second_bond);
    manifest
        .validator_set
        .validators
        .push(FastPathValidatorEntry {
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
    genesis::install_genesis(store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    let resource_id: BondResourceId = manifest.economics_policy.resources[0].resource_id;
    let escrow_request_id: [u8; 32] = [0xc5; 32];
    let scope: ProtocolCustodyScope = fee_escrow_scope(&protocol(), escrow_request_id, resource_id);
    let mut escrow: Object = manifest.objects[1].object.clone();
    escrow.version += 1;
    escrow.owner = Owner::ProtocolCustody(scope);
    let escrow_ref: ObjectRef = object_ref(&escrow);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        escrow.clone(),
        escrow_ref.digest,
        DurableObjectProvenance::new(chain(), protocol().protocol_version()),
        11,
    )
    .unwrap();
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            coin_id,
            store
                .get_object_head(&context(1), domain(), coin_id)
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
        DurableRequestId::new([0xc6; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xc6; 32]),
        vec![0xc6],
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(
            &context(1),
            DurableInvocationTransaction::new(domain(), None, changes, setup_receipt, None)
                .unwrap(),
        ),
        DurableCommitOutcome::Committed
    );

    let total_amount: u64 = 1_000_000;
    let share_a: u64 = 300_000;
    let share_b: u64 = 700_000;
    let validator_a: ValidatorId = ValidatorId::new(sender());
    let row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: protocol(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(escrow_ref.clone()),
        fee_output_epoch: Some(protocol().epoch()),
        total_amount: Some(total_amount),
        shares: {
            let mut shares: Vec<FastPathFeeShare> = vec![
                FastPathFeeShare {
                    validator_id: validator_a,
                    amount: share_a,
                    claimed: false,
                },
                FastPathFeeShare {
                    validator_id: second_validator,
                    amount: share_b,
                    claimed: false,
                },
            ];
            shares.sort_by_key(|share| share.validator_id);
            shares
        },
    };
    let row_key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(&chain(), &escrow_request_id).unwrap();
    let row_bytes: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
    let setup_row: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
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
        store.commit_durable(&context(1), setup_row),
        DurableCommitOutcome::Committed
    );

    let resolver: HashSuiteResolver = resolver();
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(protocol());

    let build_claim = |validator_id: ValidatorId,
                       signer: &SigningKey,
                       share_amount: u64,
                       recipient: Address,
                       request_id: [u8; 32]|
     -> (Vec<u8>, Vec<u8>, Vec<u8>, ObjectId, Vec<u8>) {
        let call: CallIntent = CallIntent {
            context: protocol(),
            request_id,
            sender: sender(),
            nonce: 0,
            code: instance.code.clone(),
            instance: instance_target(&resolver, &instance).unwrap(),
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
            policy_digest: policy.digest(&resolver).unwrap(),
            call,
            authorizations: Vec::new(),
        };
        let leg_frame: Vec<u8> = local_execution_signing_frame(&protocol(), &leg_intent).unwrap();
        let signed_leg: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
            signature: key().sign(&leg_frame).into(),
            intent: leg_intent,
        };
        let leg: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
        let leg_digest: Digest32 = local_execution_event_digest(&resolver, &signed_leg).unwrap();
        let payout_id: ObjectId = derive_local_created_object_id(
            &resolver,
            &protocol(),
            &instance.context,
            &instance_target(&resolver, &instance).unwrap(),
            &instance.code,
            leg_digest,
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
        let payout_bytes: Vec<u8> = objects::encode_object(&payout).unwrap();

        let mut retained: Object = escrow.clone();
        retained.version += 1;
        retained.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(total_amount - share_amount),
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
        let escrow_bytes: Vec<u8> = objects::encode_object(&retained).unwrap();

        let intent: FeeClaimIntent = FeeClaimIntent {
            context: protocol(),
            request_id,
            escrow_request_id,
            certificate_epoch: protocol().epoch(),
            validator_id,
            resource_id,
            expected_generation: 1,
            expected_fee_output: escrow_ref.clone(),
            expected_previous_row_digest: fee_claim_row_digest(
                &resolver,
                protocol().epoch(),
                &row_bytes,
            )
            .unwrap(),
            expected_next_row_digest: fee_claim_row_digest(
                &resolver,
                protocol().epoch(),
                &next_bytes,
            )
            .unwrap(),
            share_amount,
            recipient,
            operation: FeeClaimOperation::Split { leg },
        };
        let digest: Digest32 = fee_claim_intent_digest(&resolver, &intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
            signature: signer.sign(&frame).into(),
            intent,
        };
        (
            codec::encode_signed_fee_claim_intent(&signed).unwrap(),
            next_bytes,
            escrow_bytes,
            payout_id,
            payout_bytes,
        )
    };

    let request_a: [u8; 32] = [0xc8; 32];
    let request_b: [u8; 32] = [0xc9; 32];
    let recipient_a: Address =
        Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([0xca; 32])).into());
    let recipient_b: Address =
        Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([0xcb; 32])).into());
    let (signed_a, next_bytes_a, escrow_bytes_a, payout_id_a, payout_bytes_a) =
        build_claim(validator_a, &key(), share_a, recipient_a, request_a);
    let (signed_b, next_bytes_b, escrow_bytes_b, payout_id_b, payout_bytes_b) = build_claim(
        second_validator,
        &second_key,
        share_b,
        recipient_b,
        request_b,
    );

    PositiveClaimFixture {
        row_key,
        claim_key: local_instance_state::fastpath_fee_claim_key(&chain(), &escrow_request_id, 2)
            .unwrap(),
        coin_id,
        sender: sender(),
        request_a,
        request_b,
        signed_a,
        signed_b,
        next_bytes_a,
        next_bytes_b,
        escrow_bytes_a,
        escrow_bytes_b,
        payout_id_a,
        payout_id_b,
        payout_bytes_a,
        payout_bytes_b,
    }
}

fn assert_object_bytes<S: StructuredDurableDomainStateStore>(
    store: &S,
    object_id: ObjectId,
    expected_version: u64,
    expected: &[u8],
) {
    let head: DurableObjectHead = store
        .get_object_head(&context(1), domain(), object_id)
        .unwrap();
    let DurableObjectHead::Current {
        object_version,
        digest,
        ..
    } = head
    else {
        panic!("positive claim must retain a current object");
    };
    assert_eq!(object_version.get(), expected_version);
    let record: DurableObjectVersionRecord = store
        .get_object_version(&context(1), domain(), object_id, object_version)
        .unwrap()
        .unwrap();
    assert_eq!(record.digest(), digest);
    let runtime::DurableObjectPayload::Inline(inline) = record.payload() else {
        panic!("positive claim fixture must keep the escrow inline");
    };
    assert_eq!(inline.canonical_bytes(), expected);
}

fn assert_object_absent<S: StructuredDurableDomainStateStore>(store: &S, object_id: ObjectId) {
    assert_eq!(
        store
            .get_object_head(&context(1), domain(), object_id)
            .unwrap(),
        DurableObjectHead::Absent
    );
}

/// Races two distinct valid signed positive claims (asymmetric splits of the
/// same generation-1 escrow, from two different validators) against real
/// file-backed SQLite through the identical [`CommitGate`] rendezvous the
/// zero-share race above uses. Exactly one must durably win; the loser's
/// escrow object, shared sender nonce and outer receipt must be exactly as
/// they were before the race (a stale CAS assertion, never a second partial
/// application).
#[test]
fn file_backed_sqlite_positive_claim_competing_writers_commit_one_generation_once() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "fee-claim-positive-race-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db_path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace =
        SqliteNamespace::new(chain(), ValidatorId::new([0xcc; 32]), domain());
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let fixture: PositiveClaimFixture = {
        let setup: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        positive_claim_fixture(&setup)
    };
    let gate: Arc<CommitGate> = Arc::new(CommitGate {
        arrived: Mutex::new(0),
        ready: Condvar::new(),
    });
    let writer_a: InterceptStore<SqliteDurableStore> = InterceptStore {
        inner: SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap(),
        mode: InterceptMode::CommitGate(Arc::clone(&gate)),
    };
    let writer_b: InterceptStore<SqliteDurableStore> = InterceptStore {
        inner: SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap(),
        mode: InterceptMode::CommitGate(gate),
    };
    let signed_a: Vec<u8> = fixture.signed_a.clone();
    let signed_b: Vec<u8> = fixture.signed_b.clone();
    let (result_a, result_b): (
        Result<NodeOutput, FeeClaimError>,
        Result<NodeOutput, FeeClaimError>,
    ) = std::thread::scope(|scope| {
        let a = scope.spawn(move || submit_claim(&writer_a, &signed_a));
        let b = scope.spawn(move || submit_claim(&writer_b, &signed_b));
        (a.join().unwrap(), b.join().unwrap())
    });
    let a_won: bool = result_a.is_ok();
    let b_won: bool = result_b.is_ok();
    assert_ne!(a_won, b_won, "exactly one positive claim must win");
    let loser: &Result<NodeOutput, FeeClaimError> = if a_won { &result_b } else { &result_a };
    assert!(
        matches!(
            loser,
            Err(FeeClaimError::Node(NodeCoreError::StateConflict))
        ),
        "the losing positive claim must reject its stale generation CAS assertion: {loser:?}"
    );

    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
    let winning_next_bytes: &[u8] = if a_won {
        &fixture.next_bytes_a
    } else {
        &fixture.next_bytes_b
    };
    let row: VersionedStateValue = reopened
        .get_versioned_durable(&context(1), domain(), &fixture.row_key)
        .unwrap();
    assert_eq!(row.value(), Some(winning_next_bytes));
    assert_eq!(row.revision(), StateRevision::new(2));
    let winning_signed_bytes: &[u8] = if a_won {
        &fixture.signed_a
    } else {
        &fixture.signed_b
    };
    assert_eq!(
        reopened
            .get_versioned_durable(&context(1), domain(), &fixture.claim_key)
            .unwrap()
            .value(),
        Some(winning_signed_bytes)
    );
    let receipt_a: Option<DurableRequestReceipt> = reopened
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(fixture.request_a).unwrap(),
        )
        .unwrap();
    let receipt_b: Option<DurableRequestReceipt> = reopened
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(fixture.request_b).unwrap(),
        )
        .unwrap();
    assert_eq!(receipt_a.is_some(), a_won);
    assert_eq!(receipt_b.is_some(), b_won);
    let winning_escrow_bytes: &[u8] = if a_won {
        &fixture.escrow_bytes_a
    } else {
        &fixture.escrow_bytes_b
    };
    assert_object_bytes(&reopened, fixture.coin_id, 3, winning_escrow_bytes);
    let (winning_payout_id, winning_payout_bytes, losing_payout_id): (ObjectId, &[u8], ObjectId) =
        if a_won {
            (
                fixture.payout_id_a,
                &fixture.payout_bytes_a,
                fixture.payout_id_b,
            )
        } else {
            (
                fixture.payout_id_b,
                &fixture.payout_bytes_b,
                fixture.payout_id_a,
            )
        };
    assert_ne!(winning_payout_id, losing_payout_id);
    assert_object_bytes(&reopened, winning_payout_id, 1, winning_payout_bytes);
    assert_object_absent(&reopened, losing_payout_id);
    let next_nonce: u64 = query_sender_next_nonce(
        &reopened,
        &context(1),
        domain(),
        chain(),
        protocol().protocol_version(),
        protocol().epoch(),
        fixture.sender,
    )
    .unwrap();
    assert_eq!(
        next_nonce, 1,
        "exactly one leg must have advanced the shared sender nonce"
    );
    let winning_claim: SignedFeeClaimIntent =
        decode_signed_fee_claim_intent(winning_signed_bytes).unwrap();
    let economics_key: Vec<u8> =
        local_instance_state::fastpath_economics_policy_key(&protocol()).unwrap();
    let economics_observed: VersionedStateValue = reopened
        .get_versioned_durable(&context(1), domain(), &economics_key)
        .unwrap();
    let economics: FastPathEconomicsPolicy = decode_fastpath_economics_policy(
        economics_observed
            .value()
            .expect("committed economics policy"),
    )
    .unwrap();
    verify_retained_claim_legs(
        &reopened,
        &context(1),
        domain(),
        &resolver(),
        &economics.resources[0],
        &protocol(),
        &winning_claim.intent.escrow_request_id,
        2,
    )
    .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A positive claim's ambiguous commit outcome (indeterminate after either a
/// real persisted commit or a real rejected one) must reconcile by exact
/// replay -- never a second leg execution, object mutation, nonce
/// reservation or row generation bump -- and that reconciliation must
/// survive a real close/reopen of the file-backed store, not merely an
/// in-process retry.
#[test]
fn file_backed_sqlite_positive_claim_ambiguous_commit_reconciles_and_reopens_without_reapplication()
{
    for persisted in [true, false] {
        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "fee-claim-positive-ambiguous-{persisted}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let db_path: std::path::PathBuf = directory.join("state.sqlite");
        let namespace: SqliteNamespace =
            SqliteNamespace::new(chain(), ValidatorId::new([0xcd; 32]), domain());
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let fixture: PositiveClaimFixture = {
            let setup: SqliteDurableStore =
                SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
            positive_claim_fixture(&setup)
        };
        let mode: InterceptMode = if persisted {
            InterceptMode::PersistThenAmbiguous(AtomicBool::new(true))
        } else {
            InterceptMode::RejectAmbiguously(AtomicBool::new(true))
        };
        {
            let store: InterceptStore<SqliteDurableStore> = InterceptStore {
                inner: SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap(),
                mode,
            };
            assert!(matches!(
                submit_claim(&store, &fixture.signed_a),
                Err(FeeClaimError::Node(
                    NodeCoreError::DurableCommitIndeterminate(
                        IndeterminateCommitReason::ConnectionLost
                    )
                ))
            ));
            let after_first: VersionedStateValue = store
                .get_versioned_durable(&context(1), domain(), &fixture.row_key)
                .unwrap();
            assert_eq!(
                after_first.value() == Some(fixture.next_bytes_a.as_slice()),
                persisted
            );
            let receipt_after_first: Option<DurableRequestReceipt> = store
                .get_request_receipt(
                    &context(1),
                    domain(),
                    DurableRequestId::new(fixture.request_a).unwrap(),
                )
                .unwrap();
            assert_eq!(receipt_after_first.is_some(), persisted);
            if persisted {
                assert_object_bytes(&store, fixture.payout_id_a, 1, &fixture.payout_bytes_a);
            } else {
                assert_object_absent(&store, fixture.payout_id_a);
            }
            assert_object_absent(&store, fixture.payout_id_b);
        }

        // Close and reopen a fresh handle before ever observing a successful
        // reconciliation: a persisted-but-client-unacknowledged commit and an
        // uncommitted retry must both reconcile correctly after a real
        // restart, not merely within the same open connection.
        let reopened: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        let replay: NodeOutput = submit_claim(&reopened, &fixture.signed_a).unwrap();
        assert_eq!(
            replay.responses()[0].payload(),
            Some(fixture.next_bytes_a.as_slice())
        );
        let settled: VersionedStateValue = reopened
            .get_versioned_durable(&context(1), domain(), &fixture.row_key)
            .unwrap();
        assert_eq!(settled.value(), Some(fixture.next_bytes_a.as_slice()));
        assert_eq!(settled.revision(), StateRevision::new(2));
        assert_eq!(
            reopened
                .get_versioned_durable(&context(1), domain(), &fixture.claim_key)
                .unwrap()
                .value(),
            Some(fixture.signed_a.as_slice())
        );
        assert_eq!(submit_claim(&reopened, &fixture.signed_a).unwrap(), replay);
        assert_object_bytes(&reopened, fixture.coin_id, 3, &fixture.escrow_bytes_a);
        assert_object_bytes(&reopened, fixture.payout_id_a, 1, &fixture.payout_bytes_a);
        assert_object_absent(&reopened, fixture.payout_id_b);
        let next_nonce: u64 = query_sender_next_nonce(
            &reopened,
            &context(1),
            domain(),
            chain(),
            protocol().protocol_version(),
            protocol().epoch(),
            fixture.sender,
        )
        .unwrap();
        assert_eq!(
            next_nonce, 1,
            "replaying the reconciled receipt must not reserve a second nonce"
        );
        // The competing validator's claim still expects generation 1: it
        // must now fail closed rather than silently reapplying against the
        // already-advanced row.
        let stale_error: FeeClaimError = submit_claim(&reopened, &fixture.signed_b).unwrap_err();
        assert!(matches!(
            stale_error,
            FeeClaimError::Invalid("fee claim settlement identity mismatch")
        ));
        assert_object_bytes(&reopened, fixture.payout_id_a, 1, &fixture.payout_bytes_a);
        assert_object_absent(&reopened, fixture.payout_id_b);
        drop(reopened);

        let restarted: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
        assert_eq!(
            restarted
                .get_versioned_durable(&context(1), domain(), &fixture.row_key)
                .unwrap()
                .value(),
            Some(fixture.next_bytes_a.as_slice())
        );
        assert_eq!(submit_claim(&restarted, &fixture.signed_a).unwrap(), replay);
        assert_object_bytes(&restarted, fixture.coin_id, 3, &fixture.escrow_bytes_a);
        assert_object_bytes(&restarted, fixture.payout_id_a, 1, &fixture.payout_bytes_a);
        assert_object_absent(&restarted, fixture.payout_id_b);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
