//! DR-0150 recovery runs the production public WASM pipeline and real Ed25519
//! certificate verification. No recovery helper receives a signing capability.
use super::*;

const REQUEST: u8 = 0x90;
const CHECKPOINT: u64 = 777;

fn call_bytes(fixture: &Fixture, trap: bool) -> Vec<u8> {
    if trap {
        trapping_mint_call(fixture, REQUEST, FIRST_PAID_NONCE)
    } else {
        transfer_with_exact_request_id(fixture, [REQUEST; 32], FIRST_PAID_NONCE)
    }
}

/// Shared by the sibling non-recovery apply tests in `super`: independently
/// prepares `bytes` on three separate fresh validator stores and aggregates
/// their votes into one certificate, without perturbing any caller's own
/// store.
pub(super) fn certificate_for(bytes: &[u8], checkpoint: u64) -> Vec<u8> {
    let (signers, entries) = four_validators();
    let mut votes: Vec<FastVote> = Vec::new();
    for signer in &signers[..3] {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        votes.push(
            prepare(
                &store,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &fixture.policy,
                &CountingEngine::new(),
                signer,
                bytes,
                checkpoint,
            )
            .unwrap(),
        );
    }
    let set: ValidatorSet = ValidatorSet::new(
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
    .unwrap();
    let certificate: FastCertificate = certifier(set)
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    consensus::encode_fast_certificate(&certificate).unwrap()
}

fn recover<S: StructuredDurableDomainStateStore, E: PaidContractEngine + ?Sized>(
    store: &S,
    fixture: &Fixture,
    engine: &E,
    bytes: &[u8],
    certificate: &[u8],
    checkpoint: u64,
) -> FastPathResult<NodeOutput> {
    apply_with_recovery(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        engine,
        bytes,
        certificate,
        checkpoint,
    )
}

fn write_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    key: Vec<u8>,
    mutation: StateMutation,
) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn assert_no_recovery_preparation<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
) {
    let chain: ChainId = protocol().chain_id().clone();
    let mut keys: Vec<Vec<u8>> = vec![
        fastpath_prepared_record_key(&chain, &[REQUEST; 32]).unwrap(),
        fastpath_nonce_lock_key(&chain, &sender(), protocol().epoch()).unwrap(),
        fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
        fastpath_lock_key(&chain, fixture.cap.id).unwrap(),
    ];
    for key in keys.drain(..) {
        let observed: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        assert_eq!(
            observed.revision(),
            StateRevision::INITIAL,
            "recovery created a row/tombstone"
        );
        assert!(observed.value().is_none());
    }
    let synthetic: [u8; 32] =
        fastpath_synthetic_prepare_request_id(&resolver(), protocol().epoch(), &[REQUEST; 32])
            .unwrap();
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(synthetic).unwrap()
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn signerless_memory_recovery_matches_prepared_apply_success_and_charged_trap() {
    for trap in [false, true] {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        let (signers, _) = install_four_validators(&store);
        let bytes: Vec<u8> = call_bytes(&fixture, trap);
        let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
        let engine: CountingEngine = CountingEngine::new();
        let recovered: NodeOutput =
            recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).unwrap();
        assert_eq!(engine.calls.get(), 1);
        assert_eq!(
            receipt(&recovered).status,
            if trap {
                PaidExecutionStatus::ApplicationFailed
            } else {
                PaidExecutionStatus::Success
            }
        );
        assert!(receipt(&recovered).charged.is_some());
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
        assert_no_recovery_preparation(&store, &fixture);

        let prepared_store: MemoryDurableStateStore = memory_store();
        let prepared_fixture: Fixture = install(&prepared_store);
        install_four_validators(&prepared_store);
        prepare(
            &prepared_store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &prepared_fixture.policy,
            &CountingEngine::new(),
            &signers[0],
            &bytes,
            CHECKPOINT,
        )
        .unwrap();
        // An existing preparation ignores the caller's replacement checkpoint.
        let prepared: NodeOutput = recover(
            &prepared_store,
            &prepared_fixture,
            &CountingEngine::new(),
            &bytes,
            &certificate,
            99999,
        )
        .unwrap();
        assert_eq!(recovered, prepared);
        let chain: ChainId = protocol().chain_id().clone();
        for key in [
            fastpath_certificate_key(&chain, &[REQUEST; 32]).unwrap(),
            fastpath_commitment_witness_key(&chain, &[REQUEST; 32]).unwrap(),
            fastpath_settlement_key(&chain, &[REQUEST; 32]).unwrap(),
        ] {
            assert_eq!(
                store
                    .get_versioned_durable(&context(), domain(), &key)
                    .unwrap()
                    .value(),
                prepared_store
                    .get_versioned_durable(&context(), domain(), &key)
                    .unwrap()
                    .value()
            );
        }
    }
}

#[test]
fn signerless_sqlite_recovery_reopens_success_and_trap_and_replays_without_execution() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "certified-recovery-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let (_, validators) = four_validators();
    for (index, trap) in [false, true].into_iter().enumerate() {
        let files: ValidatorFiles =
            ValidatorFiles::new(&directory, u8::try_from(index).unwrap(), validators[3].id);
        let (store, _blobs) = files.open();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        let bytes: Vec<u8> = call_bytes(&fixture, trap);
        let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
        let output: NodeOutput = recover(
            &store,
            &fixture,
            &CountingEngine::new(),
            &bytes,
            &certificate,
            CHECKPOINT,
        )
        .unwrap();
        assert_no_recovery_preparation(&store, &fixture);
        drop(store);
        let (reopened, _blobs) = files.open();
        let engine: CountingEngine = CountingEngine::new();
        // Receipt-first replay needs neither a valid current certificate nor checkpoint.
        assert_eq!(
            recover(&reopened, &fixture, &engine, &bytes, &[], 0).unwrap(),
            output
        );
        assert_eq!(engine.calls.get(), 0);
        assert_eq!(next_nonce(&reopened), FIRST_PAID_NONCE + 1);
        assert_no_recovery_preparation(&reopened, &fixture);
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn recovery_rejects_invalid_certificate_before_wasm_and_wrong_checkpoint_without_writes() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let mut invalid: FastCertificate = consensus::decode_fast_certificate(&certificate).unwrap();
    invalid.votes[0].signature[0] ^= 1;
    let invalid_bytes: Vec<u8> = consensus::encode_fast_certificate(&invalid).unwrap();
    let engine: CountingEngine = CountingEngine::new();
    assert!(
        recover(
            &store,
            &fixture,
            &engine,
            &bytes,
            &invalid_bytes,
            CHECKPOINT
        )
        .is_err()
    );
    assert_eq!(engine.calls.get(), 0);
    assert!(matches!(
        recover(
            &store,
            &fixture,
            &engine,
            &bytes,
            &certificate,
            CHECKPOINT + 1
        ),
        Err(FastPathError::Invalid(
            "fast-path re-derived commitment no longer matches the certificate"
        ))
    ));
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    assert_no_recovery_preparation(&store, &fixture);
}

#[test]
fn recovery_rejects_present_nonce_object_locks_and_prepared_tombstones() {
    let source: MemoryDurableStateStore = memory_store();
    let source_fixture: Fixture = install(&source);
    let bytes: Vec<u8> = call_bytes(&source_fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    // Own orphan, foreign and future lock values all reject without execution.
    for (owner, epoch) in [
        ([REQUEST; 32], Epoch::new(0)),
        ([0x91; 32], Epoch::new(0)),
        ([REQUEST; 32], Epoch::new(1)),
    ] {
        for nonce_lock in [false, true] {
            let store: MemoryDurableStateStore = memory_store();
            let fixture: Fixture = install(&store);
            install_four_validators(&store);
            let (key, value): (Vec<u8>, Vec<u8>) = if nonce_lock {
                (
                    fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch())
                        .unwrap(),
                    encode_fastpath_nonce_lock_record(&FastPathNonceLockRecord {
                        request_id: owner,
                        sender: sender(),
                        epoch,
                        nonce: FIRST_PAID_NONCE,
                    })
                    .unwrap(),
                )
            } else {
                (
                    fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap(),
                    encode_fastpath_lock_record(&FastPathLockRecord {
                        request_id: owner,
                        object: object_reference(&fixture.coin),
                        locked_epoch: epoch,
                    })
                    .unwrap(),
                )
            };
            write_state(&store, key.clone(), StateMutation::Put(value.clone()));
            let engine: CountingEngine = CountingEngine::new();
            assert!(recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).is_err());
            assert_eq!(engine.calls.get(), 0);
            assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
            assert_eq!(
                store
                    .get_versioned_durable(&context(), domain(), &key)
                    .unwrap()
                    .value(),
                Some(value.as_slice())
            );
        }
    }
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let key: Vec<u8> = fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    write_state(&store, key.clone(), StateMutation::Put(vec![0xff]));
    let engine: CountingEngine = CountingEngine::new();
    assert!(recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).is_err());
    write_state(&store, key, StateMutation::Delete);
    assert!(matches!(
        recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT),
        Err(FastPathError::Invalid(
            "certified recovery refuses a prepared-record tombstone"
        ))
    ));
    assert_eq!(engine.calls.get(), 0);
}

#[test]
fn recovery_accepts_prior_lock_tombstones_without_creating_new_lock_revisions() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let keys: Vec<Vec<u8>> = vec![
        fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap(),
        fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch()).unwrap(),
    ];
    let mut revisions: Vec<StateRevision> = Vec::new();
    for key in &keys {
        write_state(&store, key.clone(), StateMutation::Put(vec![0xff]));
        write_state(&store, key.clone(), StateMutation::Delete);
        revisions.push(
            store
                .get_versioned_durable(&context(), domain(), key)
                .unwrap()
                .revision(),
        );
    }
    recover(
        &store,
        &fixture,
        &CountingEngine::new(),
        &bytes,
        &certificate,
        CHECKPOINT,
    )
    .unwrap();
    for (key, revision) in keys.iter().zip(revisions) {
        let observed: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), key)
            .unwrap();
        assert_eq!(observed.revision(), revision);
        assert!(observed.value().is_none());
    }
}

struct PrepareDuringExecution<'a> {
    store: &'a MemoryDurableStateStore,
    fixture: &'a Fixture,
    signed_bytes: &'a [u8],
    signer: &'a TestSigner,
    inner: CountingEngine,
}
impl PaidContractEngine for PrepareDuringExecution<'_> {
    fn execute_paid(
        &self,
        request: execution::paid_execution::PaidExecutionRequest<'_>,
    ) -> Result<
        execution::paid_execution::PaidExecutionOutcome,
        execution::paid_execution::PaidExecutionError,
    > {
        let outcome: execution::paid_execution::PaidExecutionOutcome =
            self.inner.execute_paid(request)?;
        prepare(
            self.store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &self.fixture.policy,
            &CountingEngine::new(),
            self.signer,
            self.signed_bytes,
            CHECKPOINT,
        )
        .unwrap();
        Ok(outcome)
    }
}

#[test]
fn recovery_final_commit_conflicts_with_a_real_concurrent_prepare() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _) = install_four_validators(&store);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let engine: PrepareDuringExecution<'_> = PrepareDuringExecution {
        store: &store,
        fixture: &fixture,
        signed_bytes: &bytes,
        signer: &signers[3],
        inner: CountingEngine::new(),
    };
    assert!(matches!(
        recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT),
        Err(FastPathError::Node(NodeCoreError::StateConflict))
    ));
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    let key: Vec<u8> = fastpath_certificate_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value()
            .is_none()
    );
    let replay: NodeOutput = recover(
        &store,
        &fixture,
        &CountingEngine::new(),
        &bytes,
        &certificate,
        0,
    )
    .unwrap();
    assert_eq!(receipt(&replay).status, PaidExecutionStatus::Success);
}

/// Once a receipt exists, any generic-state/object read or write is a bug.
struct ReceiptOnlyStore<'a> {
    inner: &'a MemoryDurableStateStore,
}
impl DurableDomainStateStore for ReceiptOnlyStore<'_> {
    fn get_versioned_durable(
        &self,
        _: &DurableOperationContext,
        _: AtomicityDomainId,
        _: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        panic!("historical replay must not read current state");
    }
    fn commit_durable(
        &self,
        _: &DurableOperationContext,
        _: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        panic!("historical replay must not mutate state");
    }
}
impl StructuredDurableDomainStateStore for ReceiptOnlyStore<'_> {
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request)
    }
    fn commit_invocation(
        &self,
        _: &DurableOperationContext,
        _: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        panic!("historical replay must not reapply");
    }
}

#[test]
fn recovery_historical_receipt_precedes_epoch_policy_code_and_object_reads() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let output: NodeOutput = recover(
        &store,
        &fixture,
        &CountingEngine::new(),
        &bytes,
        &certificate,
        CHECKPOINT,
    )
    .unwrap();
    let key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
    write_state(&store, key, StateMutation::Put(vec![0xff]));
    let historical: ReceiptOnlyStore<'_> = ReceiptOnlyStore { inner: &store };
    let engine: CountingEngine = CountingEngine::new();
    assert_eq!(
        recover(&historical, &fixture, &engine, &bytes, &[], 0).unwrap(),
        output
    );
    assert_eq!(
        apply(
            &historical,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &engine,
            &bytes,
            &[]
        )
        .unwrap(),
        output
    );
    let conflicting: Vec<u8> =
        transfer_with_exact_request_id(&fixture, [REQUEST; 32], FIRST_PAID_NONCE + 1);
    assert!(
        recover(
            &historical,
            &fixture,
            &engine,
            &conflicting,
            &certificate,
            CHECKPOINT
        )
        .is_err()
    );
    assert_eq!(engine.calls.get(), 0);
}

#[test]
fn recovery_refuses_missing_definitions_policies_divergent_nonce_and_object_head() {
    let source: MemoryDurableStateStore = memory_store();
    let source_fixture: Fixture = install(&source);
    let bytes: Vec<u8> = call_bytes(&source_fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    for kind in 0u8..6 {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        match kind {
            0 => write_state(
                &store,
                publication::publication_record_key(&fixture.origin).unwrap(),
                StateMutation::Delete,
            ),
            1 => write_state(
                &store,
                local_instance_state::instance_record_key(
                    protocol().chain_id(),
                    &fixture.instance.creator,
                    &fixture.instance.seed,
                )
                .unwrap(),
                StateMutation::Delete,
            ),
            2 => write_state(
                &store,
                local_instance_state::execution_policy_key_for_profile(
                    base_policy().context(),
                    base_policy().profile(),
                )
                .unwrap(),
                StateMutation::Delete,
            ),
            3 => write_state(
                &store,
                local_instance_state::paid_fee_policy_key(&fixture.policy.context).unwrap(),
                StateMutation::Delete,
            ),
            4 => {
                let layout: PersistenceLayout = PersistenceLayout::new(
                    protocol().chain_id().clone(),
                    protocol().protocol_version(),
                );
                write_state(
                    &store,
                    layout.sender_nonce_key(sender(), protocol().epoch()),
                    StateMutation::Put(
                        SenderNonceRecord::new(sender(), protocol().epoch(), FIRST_PAID_NONCE + 1)
                            .encode()
                            .unwrap(),
                    ),
                );
            }
            5 => {
                install_custody_owned_version(&store, &fixture.coin);
            }
            _ => unreachable!(),
        }
        let engine: CountingEngine = CountingEngine::new();
        assert!(
            recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).is_err(),
            "prerequisite {kind} accepted"
        );
        assert_eq!(engine.calls.get(), 0);
        assert_no_recovery_preparation(&store, &fixture);
    }
}

fn signed_certificate_for_hashes(
    tx_hash: Digest32,
    commitment: Digest32,
    locks: Digest32,
) -> Vec<u8> {
    let (signers, entries) = four_validators();
    let set: ValidatorSet = ValidatorSet::new(
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
    .unwrap();
    let cert: consensus::FastPathCertifier = certifier(set);
    let votes: Vec<FastVote> = signers[..3]
        .iter()
        .map(|signer| cert.cast_vote(tx_hash, commitment, locks, signer).unwrap())
        .collect();
    let certificate: FastCertificate = cert
        .try_form_certificate(tx_hash, commitment, locks, &votes, &FastPathEd25519Verifier)
        .unwrap()
        .unwrap();
    consensus::encode_fast_certificate(&certificate).unwrap()
}

#[test]
fn recovery_verifies_exact_tx_hash_quorum_full_commitment_and_independent_lock_digest() {
    let source: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&source);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let valid: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let certificate: FastCertificate = consensus::decode_fast_certificate(&valid).unwrap();
    let different: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xff; 32]);
    let mut insufficient: FastCertificate = certificate.clone();
    insufficient.votes.pop();
    let cases: Vec<(Vec<u8>, u32)> = vec![
        (
            signed_certificate_for_hashes(
                different,
                certificate.execution_effects_hash,
                certificate.locked_objects_digest,
            ),
            0,
        ),
        (
            consensus::encode_fast_certificate(&insufficient).unwrap(),
            0,
        ),
        (
            signed_certificate_for_hashes(
                certificate.tx_hash,
                different,
                certificate.locked_objects_digest,
            ),
            1,
        ),
        (
            signed_certificate_for_hashes(
                certificate.tx_hash,
                certificate.execution_effects_hash,
                different,
            ),
            1,
        ),
    ];
    for (certificate_bytes, calls) in cases {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        let engine: CountingEngine = CountingEngine::new();
        assert!(
            recover(
                &store,
                &fixture,
                &engine,
                &bytes,
                &certificate_bytes,
                CHECKPOINT
            )
            .is_err()
        );
        assert_eq!(engine.calls.get(), calls);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
        assert_no_recovery_preparation(&store, &fixture);
    }
}

#[test]
fn recovery_strict_lock_fence_refuses_older_epoch_locks_and_changed_read_revisions() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let key: Vec<u8> = fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    write_state(
        &store,
        key.clone(),
        StateMutation::Put(
            encode_fastpath_lock_record(&FastPathLockRecord {
                request_id: [0x92; 32],
                object: object_reference(&fixture.coin),
                locked_epoch: Epoch::new(0),
            })
            .unwrap(),
        ),
    );
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(
        mutation_fence::fence_object_lock(
            &store,
            &context(),
            domain(),
            protocol().chain_id(),
            &object_reference(&fixture.coin),
            &[REQUEST; 32],
            Epoch::new(1),
            mutation_fence::LockMode::Absent,
            &mut reads
        )
        .is_err()
    );
    assert!(reads.contains_key(&key));
    // A second observation must not erase the earlier absent revision.
    let mut prior: BTreeMap<Vec<u8>, StateRevision> =
        BTreeMap::from([(key, StateRevision::INITIAL)]);
    assert!(matches!(
        merge_apply_reads(&mut prior, reads),
        Err(FastPathError::Node(NodeCoreError::StateConflict))
    ));
}

/// Inserts exactly one conflicting row immediately before the real atomic
/// store receives recovery's final transaction. Other asserted rows stay
/// unchanged, so each case independently proves its absence was fenced.
struct InsertAtCommit<'a> {
    inner: &'a MemoryDurableStateStore,
    key: Vec<u8>,
    value: Vec<u8>,
}
impl DurableDomainStateStore for InsertAtCommit<'_> {
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
impl StructuredDurableDomainStateStore for InsertAtCommit<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        write_state(
            self.inner,
            self.key.clone(),
            StateMutation::Put(self.value.clone()),
        );
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn recovery_final_cas_independently_fences_prepared_nonce_and_every_input_lock_absence() {
    let source: MemoryDurableStateStore = memory_store();
    let source_fixture: Fixture = install(&source);
    let bytes: Vec<u8> = call_bytes(&source_fixture, true);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    for kind in 0u8..4 {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        let key: Vec<u8> = match kind {
            0 => fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
            1 => fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch())
                .unwrap(),
            2 => fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap(),
            3 => fastpath_lock_key(protocol().chain_id(), fixture.cap.id).unwrap(),
            _ => unreachable!(),
        };
        let racing: InsertAtCommit<'_> = InsertAtCommit {
            inner: &store,
            key: key.clone(),
            value: vec![0xff],
        };
        let engine: CountingEngine = CountingEngine::new();
        assert!(
            matches!(
                recover(&racing, &fixture, &engine, &bytes, &certificate, CHECKPOINT),
                Err(FastPathError::Node(NodeCoreError::StateConflict))
            ),
            "unfenced row {kind}"
        );
        assert_eq!(engine.calls.get(), 1);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
        assert_eq!(
            store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap()
                .value(),
            Some([0xff].as_slice())
        );
        for record in [
            fastpath_certificate_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
            fastpath_commitment_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
            fastpath_settlement_key(protocol().chain_id(), &[REQUEST; 32]).unwrap(),
        ] {
            assert!(
                store
                    .get_versioned_durable(&context(), domain(), &record)
                    .unwrap()
                    .value()
                    .is_none()
            );
        }
    }
}

#[test]
fn recovery_never_falls_back_from_a_conflicting_well_formed_preparation() {
    let donor: MemoryDurableStateStore = memory_store();
    let donor_fixture: Fixture = install(&donor);
    let (signers, _) = install_four_validators(&donor);
    prepare_transfer(
        &donor,
        &donor_fixture,
        &signers[0],
        REQUEST + 1,
        FIRST_PAID_NONCE,
    )
    .unwrap();
    let donor_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST + 1; 32]).unwrap();
    let prepared_bytes: Vec<u8> = donor
        .get_versioned_durable(&context(), domain(), &donor_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let bytes: Vec<u8> = call_bytes(&fixture, false);
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let key: Vec<u8> = fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    write_state(
        &store,
        key.clone(),
        StateMutation::Put(prepared_bytes.clone()),
    );
    let engine: CountingEngine = CountingEngine::new();
    assert!(recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).is_err());
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value(),
        Some(prepared_bytes.as_slice())
    );
}

/// DR-0151 delivery 1: a same-epoch replica that missed prepare recovers a
/// certified paid `Publish`, atomically durably publishing its signed frame.
#[test]
fn signerless_recovery_applies_a_certified_paid_publish() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let artifact = publish_artifact(90);
    let origin = artifact.origin().clone();
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        0x91,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let certificate: Vec<u8> = certificate_for(&bytes, CHECKPOINT);
    let engine: CountingEngine = CountingEngine::new();
    let output: NodeOutput =
        recover(&store, &fixture, &engine, &bytes, &certificate, CHECKPOINT).unwrap();
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
    assert_eq!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &publication_record_key(&origin).unwrap()
            )
            .unwrap()
            .value(),
        Some(bytes.as_slice())
    );
}

fn instantiate_bytes_for(
    fixture: &Fixture,
    reference: &execution::publication::UnverifiedDependencyRef,
    seed: u8,
    source: ObjectRef,
) -> Vec<u8> {
    let record = execution::local_execution::InstanceRecord {
        seed: [seed; 32],
        code: reference.clone(),
        ..fixture.instance.clone()
    };
    let application = execution::call::CallIntent {
        context: protocol(),
        request_id: [0x93; 32],
        sender: sender(),
        nonce: FIRST_PAID_NONCE + 1,
        code: reference.clone(),
        instance: instance_target(&resolver(), &record).unwrap(),
        entrypoint: "init".into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 100_000,
    };
    sign_paid(execution::paid_execution::PaidIntent {
        context: protocol(),
        request_id: [0x93; 32],
        sender: sender(),
        nonce: FIRST_PAID_NONCE + 1,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &fixture.policy).unwrap(),
        consent: FeeSourceConsent {
            source,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: refund_account(),
        },
        application: PaidApplication::Instantiate(application),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

/// Like [`certificate_for`], but every certifying validator first recovers
/// the already-certified `publish_bytes`/`publish_certificate` pair on its
/// own store, so its nonce and durable code closure match a validator that
/// honestly applied the dependency before preparing `bytes`.
fn certificate_for_after_publish(
    publish_bytes: &[u8],
    publish_certificate: &[u8],
    bytes: &[u8],
    checkpoint: u64,
) -> Vec<u8> {
    let (signers, entries) = four_validators();
    let mut votes: Vec<FastVote> = Vec::new();
    for signer in &signers[..3] {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        install_four_validators(&store);
        recover(
            &store,
            &fixture,
            &CountingEngine::new(),
            publish_bytes,
            publish_certificate,
            checkpoint,
        )
        .unwrap();
        votes.push(
            prepare(
                &store,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &fixture.policy,
                &CountingEngine::new(),
                signer,
                bytes,
                checkpoint,
            )
            .unwrap(),
        );
    }
    let set: ValidatorSet = ValidatorSet::new(
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
    .unwrap();
    let certificate: FastCertificate = certifier(set)
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    consensus::encode_fast_certificate(&certificate).unwrap()
}

/// DR-0151 delivery 1: a same-epoch replica that missed both prepares
/// recovers a certified `Publish` and a certified `Instantiate` depending on
/// it, in their declared dependency order: the `Publish` is applied first,
/// so the `Instantiate`'s own recovery can resolve its code closure locally.
#[test]
fn signerless_recovery_applies_certified_definitions_in_dependency_order() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let artifact = publish_artifact(94);
    let reference = publish_artifact_reference(&artifact);
    let publish_bytes: Vec<u8> = paid_publish(
        &fixture,
        0x94,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let publish_certificate: Vec<u8> = certificate_for(&publish_bytes, CHECKPOINT);
    recover(
        &store,
        &fixture,
        &CountingEngine::new(),
        &publish_bytes,
        &publish_certificate,
        CHECKPOINT,
    )
    .unwrap();
    let source: ObjectRef = current_object_ref(&store, protocol().chain_id(), fixture.coin.id);
    let instantiate_bytes: Vec<u8> = instantiate_bytes_for(&fixture, &reference, 95, source);
    let instantiate_certificate: Vec<u8> = certificate_for_after_publish(
        &publish_bytes,
        &publish_certificate,
        &instantiate_bytes,
        CHECKPOINT,
    );
    let engine: CountingEngine = CountingEngine::new();
    let output: NodeOutput = recover(
        &store,
        &fixture,
        &engine,
        &instantiate_bytes,
        &instantiate_certificate,
        CHECKPOINT,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
}

/// Recovering the `Instantiate` before its `Publish` dependency has itself
/// been recovered fails closed here because both intents share `fixture`'s
/// sender: the certificate's sender-nonce sequencing (asserted before any
/// code-closure resolution) can never be satisfied out of declared order for
/// same-sender dependencies. Nonce sequencing does not police dependency
/// order in general -- a `Publish` from a different sender has an
/// independent nonce, so this same generic admission check would not catch a
/// missing cross-sender dependency; recovery order is a caller discipline
/// enforced only incidentally here, not a distinct recovery code path.
#[test]
fn signerless_recovery_of_an_instantiate_before_its_publish_dependency_fails_closed() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let artifact = publish_artifact(96);
    let reference = publish_artifact_reference(&artifact);
    let publish_bytes: Vec<u8> = paid_publish(
        &fixture,
        0x96,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let publish_certificate: Vec<u8> = certificate_for(&publish_bytes, CHECKPOINT);
    let reference_store: MemoryDurableStateStore = memory_store();
    let reference_fixture: Fixture = install(&reference_store);
    install_four_validators(&reference_store);
    recover(
        &reference_store,
        &reference_fixture,
        &CountingEngine::new(),
        &publish_bytes,
        &publish_certificate,
        CHECKPOINT,
    )
    .unwrap();
    let source: ObjectRef =
        current_object_ref(&reference_store, protocol().chain_id(), fixture.coin.id);
    let instantiate_bytes: Vec<u8> = instantiate_bytes_for(&fixture, &reference, 97, source);
    let certificate: Vec<u8> = certificate_for_after_publish(
        &publish_bytes,
        &publish_certificate,
        &instantiate_bytes,
        CHECKPOINT,
    );
    let engine: CountingEngine = CountingEngine::new();
    assert!(matches!(
        recover(
            &store,
            &fixture,
            &engine,
            &instantiate_bytes,
            &certificate,
            CHECKPOINT,
        ),
        Err(FastPathError::Admission(PaidExecutionAdmissionError::Node(
            NodeCoreError::SenderNonceMismatch { .. }
        )))
    ));
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
}

/// Deleting an already-recovered `Publish`'s durable publication record is a
/// test-only divergent prerequisite fault injection -- a peer that actually
/// applied the certificate can never lose the record it just durably wrote,
/// so this never models a genuine catch-up or import path -- not a distinct
/// recovery code path. It isolates the missing/broken-definition failure
/// from the out-of-order nonce failure above: the `Instantiate` here is
/// built with the exact nonce and fee-source prerequisites an honest
/// dependency-order recovery would leave behind, so admission gets past
/// nonce freshness and fails only when it tries to resolve the code closure.
/// A tombstoned key is not the same durable state as one genuinely never
/// written: the root-node publication load treats a revision-INITIAL
/// absence as "never published" (the ordinary missing-definition case
/// another test already covers), but a present-then-deleted key as
/// `PublicationAdmissionError::CorruptRecord` -- exactly the distinction a
/// real corrupted or rolled-back peer store would hit.
#[test]
fn signerless_recovery_of_an_instantiate_fails_closed_when_its_recovered_publish_definition_is_missing()
 {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    install_four_validators(&store);
    let artifact = publish_artifact(98);
    let reference = publish_artifact_reference(&artifact);
    let origin = artifact.origin().clone();
    let publish_bytes: Vec<u8> = paid_publish(
        &fixture,
        98,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let publish_certificate: Vec<u8> = certificate_for(&publish_bytes, CHECKPOINT);
    recover(
        &store,
        &fixture,
        &CountingEngine::new(),
        &publish_bytes,
        &publish_certificate,
        CHECKPOINT,
    )
    .unwrap();
    let source: ObjectRef = current_object_ref(&store, protocol().chain_id(), fixture.coin.id);
    let instantiate_bytes: Vec<u8> = instantiate_bytes_for(&fixture, &reference, 99, source);
    let instantiate_certificate: Vec<u8> = certificate_for_after_publish(
        &publish_bytes,
        &publish_certificate,
        &instantiate_bytes,
        CHECKPOINT,
    );
    let nonce_before: u64 = next_nonce(&store);
    let coin_bytes_before: Vec<u8> = match crate::query::query_object(
        &store,
        &context(),
        domain(),
        protocol().chain_id(),
        fixture.coin.id,
    )
    .unwrap()
    {
        crate::query::ObjectQueryResult::CurrentInline {
            canonical_object_bytes,
            ..
        } => canonical_object_bytes,
        _ => unreachable!("fee coin must be a current inline object"),
    };
    let publication_key: Vec<u8> = publication_record_key(&origin).unwrap();
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &publication_key)
        .unwrap();
    assert!(observed.value().is_some());
    let erase: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(publication_key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(publication_key.clone(), StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), erase),
        DurableCommitOutcome::Committed
    );
    let engine: CountingEngine = CountingEngine::new();
    assert!(matches!(
        recover(
            &store,
            &fixture,
            &engine,
            &instantiate_bytes,
            &instantiate_certificate,
            CHECKPOINT,
        ),
        Err(FastPathError::Admission(
            PaidExecutionAdmissionError::Publication(PublicationAdmissionError::CorruptRecord)
        ))
    ));
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(next_nonce(&store), nonce_before);
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &publication_key)
            .unwrap()
            .value()
            .is_none()
    );
    let coin_bytes_after: Vec<u8> = match crate::query::query_object(
        &store,
        &context(),
        domain(),
        protocol().chain_id(),
        fixture.coin.id,
    )
    .unwrap()
    {
        crate::query::ObjectQueryResult::CurrentInline {
            canonical_object_bytes,
            ..
        } => canonical_object_bytes,
        _ => unreachable!("fee coin must be a current inline object"),
    };
    assert_eq!(coin_bytes_after, coin_bytes_before);
    assert_eq!(
        crate::query::query_request_receipt(
            &store,
            &context(),
            domain(),
            RequestId::new([0x93; 32]).unwrap(),
        )
        .unwrap(),
        crate::query::ReceiptQueryResult::Absent {
            request_id: RequestId::new([0x93; 32]).unwrap()
        }
    );
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[0x93; 32]).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &prepared_key)
            .unwrap()
            .value()
            .is_none()
    );
}

/// The exact current [`ObjectRef`] for `id`, independently re-verified by
/// [`crate::query::query_object`]: used to build a fresh fee-source consent
/// against an object a prior certified request in the same chain already
/// mutated (its version/digest no longer match the fixture's own snapshot).
fn current_object_ref<S: StructuredDurableDomainStateStore>(
    store: &S,
    chain_id: &ChainId,
    id: ObjectId,
) -> ObjectRef {
    match crate::query::query_object(store, &context(), domain(), chain_id, id).unwrap() {
        crate::query::ObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ..
        } => ObjectRef {
            id,
            version: object_version.get(),
            digest,
        },
        _ => unreachable!("fee-source coin must be a current inline object"),
    }
}
