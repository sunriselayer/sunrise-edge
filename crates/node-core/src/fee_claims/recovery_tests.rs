use super::*;
use crate::fast_path::{FastPathValidatorEntry, install_validator_set};
use crate::genesis::tests::{chain, context, domain, protocol, resolver};
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use objects::{Address, ObjectId};
use protocol_types::{HashAlgorithmId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableObjectHead, DurableObjectVersion, DurableObjectVersionRecord,
    DurableReadError, DurableRequestId, DurableRequestReceipt, IndeterminateCommitReason,
    MemoryBlobStore, MemoryDurableStateStore, StateReadAssertion, VersionedStateValue,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

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

fn submit_zero<S: StructuredDurableDomainStateStore>(
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
            submit_zero(&store, &fixture.signed_a),
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
        let replay: NodeOutput = submit_zero(&store, &fixture.signed_a).unwrap();
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
        assert_eq!(submit_zero(&store, &fixture.signed_a).unwrap(), replay);
        assert!(submit_zero(&store, &fixture.signed_b).is_err());
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
        let a = scope.spawn(move || submit_zero(&writer_a, &signed_a));
        let b = scope.spawn(move || submit_zero(&writer_b, &signed_b));
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
