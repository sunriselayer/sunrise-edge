//! DR-0130 fast-path prepare/apply regressions, reusing the paid-execution
//! fixtures (`crate::paid_execution::tests`) so every scenario runs the real
//! public Standard Asset WASM through the production execution engine and a
//! real durable store, exactly like the direct-commit regressions.
use super::*;
use crate::economics::{
    FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy, encode_fastpath_economics_policy,
};
use crate::fast_path::records::FastPathBondState;
use crate::paid_execution::tests::{
    CountingEngine, FIRST_PAID_NONCE, Fixture, PaidCall, base_policy, context, domain, entry,
    install, install_logical_profile, install_with_profile, memory_store, next_nonce,
    object_reference, paid_call_with_access, paid_instantiate, paid_publish, protocol,
    publish_artifact, publish_artifact_reference, receipt, refund_account, resolver, sender,
    sign_paid, trapping_mint_call,
};
use crate::publication::PublicationAdmissionError;
use crate::publication::publication_record_key;
use abi::AccessManifest;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{InstanceRecord, instance_target};
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidResultTarget,
    ReservationAccessKind, paid_fee_policy_digest,
};
use fees::Amount;
use runtime::portable::DurablePortableSnapshotRepository;
use runtime::{
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHeadRead, DurableObjectMutation, DurableObjectMutationEntry,
    DurableObjectOwnerProjection, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersionRecord, DurableRequestId, DurableRequestReceipt, MemoryBlobStore,
    MemoryDurableStateStore, OutgoingSealRepository, SealBarrier, StorageCorrelationId,
    StorageDeadline, TransitionHistoryState, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::cell::Cell;

mod causal;
mod recovery;

/// A real (non-mocked) Ed25519 `ConsensusSigner`, mirroring
/// `consensus::fast_vote`'s own private test signer.
pub(crate) struct TestSigner {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl ConsensusSigner for TestSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

fn validator(seed: u8) -> (TestSigner, FastPathValidatorEntry) {
    let signing_key: SigningKey = SigningKey::from([seed; 32]);
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let id_bytes: [u8; 32] = verification_key.into();
    let id: ValidatorId = ValidatorId::new(id_bytes);
    let signer: TestSigner = TestSigner {
        validator_id: id,
        signing_key,
    };
    let entry: FastPathValidatorEntry = FastPathValidatorEntry {
        id,
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: id_bytes.to_vec(),
    };
    (signer, entry)
}

/// Four equal-power validators: `ValidatorSet::quorum_threshold` for four
/// validators of power one each is `4 - (4-1)/3 = 3`, so three votes form a
/// certificate and one is never enough.
pub(crate) fn four_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [101u8, 102, 103, 104] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

fn install_four_validators<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let (signers, entries) = four_validators();
    install_validator_set(
        store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries.clone(),
    )
    .unwrap();
    (signers, entries)
}

pub(crate) fn memory_store_bound() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
}

/// Raw-port Sealed barrier installation for guard unit tests: the narrow
/// `OutgoingSealRepository::commit_seal_completion` completion port, called
/// directly with a synthetic sentinel record. This is deliberately NOT an
/// independently reconstructed protocol Seal proof (no real Freeze/DrainSet
/// readiness, certificate, or ordered engine commit backs it); it exists only
/// to flip the storage-level barrier a guard test observes. Never reuse this
/// as evidence that a real Seal would authorize anything.
pub(crate) fn seal_namespace(store: &MemoryDurableStateStore, domain: AtomicityDomainId) {
    let token = store.begin_portable_snapshot(&context(), domain).unwrap();
    let mut request: [u8; 32] = [0xFE; 32];
    request[0] |= 0x80;
    let sealed: SealBarrier = SealBarrier {
        outgoing_epoch: protocol().epoch(),
        request,
        height: 1,
        block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xFC; 32]),
        target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xFD; 32]),
        transition_history: TransitionHistoryState::Virgin,
    };
    let request_id: DurableRequestId = DurableRequestId::new(sealed.request).unwrap();
    let event_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xFB; 32]);
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::empty(),
        receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_seal_completion(&context(), &token, invocation, sealed),
        DurableCommitOutcome::Committed
    );
}

pub(crate) struct CountingSigner<'a> {
    pub(crate) inner: &'a TestSigner,
    pub(crate) calls: Cell<u32>,
}
impl ConsensusSigner for CountingSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.inner.validator_id()
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        self.inner.signature_scheme()
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get() + 1);
        self.inner.sign_framed(framed)
    }
}

fn install_fee_escrow_economics<S: StructuredDurableDomainStateStore>(
    store: &S,
    fee_policy: &PaidFeePolicy,
) {
    let resource_id: BondResourceId = fee_resource_id(fee_policy).unwrap();
    let policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: fee_policy.code.context().clone(),
        resources: vec![FastPathEconomicsResourcePolicy {
            resource_id,
            context: fee_policy.code.context().clone(),
            instance: fee_policy.instance.clone(),
            code: fee_policy.code.clone(),
            ty: fee_policy.asset_type.clone(),
            schema: fee_policy.schema,
            split_entrypoint: "split".to_owned(),
            transfer_entrypoint: "transfer".to_owned(),
            bond: None,
            fee_escrow: true,
        }],
    };
    let key: Vec<u8> =
        local_instance_state::fastpath_economics_policy_key(&policy.context).unwrap();
    let bytes: Vec<u8> = encode_fastpath_economics_policy(&policy).unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn oversized_legacy_validator_set_rejects_prepare_before_locking_objects() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    let mut first_signer: Option<TestSigner> = None;
    for index in 0..=records::MAX_FASTPATH_ACTIVE_VALIDATORS {
        let mut seed: [u8; 32] = [0; 32];
        seed[28..].copy_from_slice(&u32::try_from(index + 1).unwrap().to_be_bytes());
        let key: SigningKey = SigningKey::from(seed);
        let public_key: [u8; 32] = VerificationKey::from(&key).into();
        let id: ValidatorId = ValidatorId::new(public_key);
        if first_signer.is_none() {
            first_signer = Some(TestSigner {
                validator_id: id,
                signing_key: key,
            });
        }
        entries.push(FastPathValidatorEntry {
            id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        });
    }
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries,
    )
    .unwrap();
    let signer: TestSigner = first_signer.unwrap();
    let error: FastPathError =
        prepare_transfer(&store, &fixture, &signer, 0xd1, FIRST_PAID_NONCE).unwrap_err();
    assert!(
        matches!(error, FastPathError::Invalid(message) if message == "fast-path active validator set exceeds the fee-claim capacity bound")
    );
    let object_lock_key: Vec<u8> =
        fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    let nonce_lock_key: Vec<u8> =
        fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch()).unwrap();
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[0xd1; 32]).unwrap();
    for key in [object_lock_key, nonce_lock_key, prepared_key] {
        assert!(
            store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap()
                .value()
                .is_none()
        );
    }
}

fn certifier(validator_set: ValidatorSet) -> consensus::FastPathCertifier {
    consensus::FastPathCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        validator_set,
    )
    .unwrap()
}

fn prepare_transfer<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    signer: &TestSigner,
    request: u8,
    nonce: u64,
) -> FastPathResult<FastVote> {
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture,
            policy: &fixture.policy,
            request,
            nonce,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    prepare(
        store,
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
        &bytes,
        10,
    )
}

/// Replaces one fixture object's current version with an otherwise identical
/// protocol-custody-owned version. This is test setup, not a protocol path:
/// DR-0135 deliberately exposes no post-genesis operation that can perform
/// this owner transition.
fn install_custody_owned_version<S: StructuredDurableDomainStateStore>(
    store: &S,
    object: &Object,
) -> Object {
    let mut custody_object: Object = object.clone();
    custody_object.version = custody_object.version.checked_add(1).unwrap();
    custody_object.owner = Owner::ProtocolCustody(objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::BondCollateral,
        chain_id: protocol().chain_id().clone(),
        subject: [0x78; 32],
        resource: [0x79; 32],
    });
    let canonical_bytes: Vec<u8> = objects::encode_object(&custody_object).unwrap();
    let digest: Digest32 = resolver()
        .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        custody_object.clone(),
        digest,
        DurableObjectProvenance::new(protocol().chain_id().clone(), protocol().protocol_version()),
        9,
    )
    .unwrap();
    let head: DurableObjectHeadRead = DurableObjectHeadRead::new(
        custody_object.id,
        store
            .get_object_head(&context(), domain(), custody_object.id)
            .unwrap(),
    );
    let mutation: DurableObjectMutationEntry = DurableObjectMutationEntry::new(
        custody_object.id,
        DurableObjectMutation::Update {
            version,
            owner_projection: DurableObjectOwnerProjection::from_owner(
                custody_object.owner.clone(),
            )
            .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
    );
    let changes: DurableObjectChanges =
        DurableObjectChanges::new(vec![head], vec![mutation]).unwrap();
    let request_id: DurableRequestId = DurableRequestId::new([0xE5; 32]).unwrap();
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, digest, vec![0xE5]).unwrap();
    let transaction: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&context(), transaction),
        DurableCommitOutcome::Committed
    );
    custody_object
}

/// DR-0135: FastVote preparation must reject a custody-owned lock target
/// before executing or writing a lock, prepared record, or nonce reservation.
#[test]
fn prepare_rejects_protocol_custody_owned_lock_target_before_execution() {
    let store: MemoryDurableStateStore = memory_store();
    let mut fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    fixture.coin = install_custody_owned_version(&store, &fixture.coin);
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 0xE6,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let engine: CountingEngine = CountingEngine::new();
    let result: FastPathResult<FastVote> = prepare(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &signers[0],
        &bytes,
        10,
    );
    assert!(
        matches!(
            &result,
            Err(FastPathError::Admission(error)) if matches!(error.as_ref(),
                PaidExecutionAdmissionError::Invalid(
                    "paid inputs require sender address ownership"
                )
            )
        ),
        "unexpected custody prepare result: {result:?}"
    );
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    let lock_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &lock_key)
            .unwrap()
            .value()
            .is_none()
    );
}

fn apply_transfer<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    request: u8,
    nonce: u64,
    certificate_bytes: &[u8],
) -> FastPathResult<NodeOutput> {
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture,
            policy: &fixture.policy,
            request,
            nonce,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    apply(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &bytes,
        certificate_bytes,
    )
}

/// Builds one signed `Call` with a caller-chosen exact 32-byte request id,
/// unlike `PaidCall::request: u8` (which always fills all 32 bytes with the
/// same repeated byte and so can never land inside the reserved fast-path
/// synthetic-receipt prefix).
fn transfer_with_exact_request_id(fixture: &Fixture, request_id: [u8; 32], nonce: u64) -> Vec<u8> {
    let application: CallIntent = CallIntent {
        context: protocol(),
        request_id,
        sender: sender(),
        nonce,
        code: fixture.code.clone(),
        instance: instance_target(&resolver(), &fixture.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&fixture.asset)],
        access: AccessManifest {
            entries: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    sign_paid(execution::paid_execution::PaidIntent {
        context: protocol(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &fixture.policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_reference(&fixture.coin),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: refund_account(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

#[test]
fn exact_prepare_replay_returns_the_identical_vote_without_reexecuting() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 20,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let engine: CountingEngine = CountingEngine::new();
    let first: FastVote = prepare(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 1);
    let second: FastVote = prepare(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    // Exact replay never touches the engine again.
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(first, second);
}

#[test]
fn conflicting_prepared_replay_with_different_bytes_fails_closed() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    prepare_transfer(&store, &fixture, &signers[0], 21, FIRST_PAID_NONCE).unwrap();
    // Same request id (21), different nonce/content -> different signed
    // bytes and a different digest under the same original request id.
    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &signers[0], 21, FIRST_PAID_NONCE + 1);
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "conflicting fast-path prepared record"
        ))
    ));
}

#[test]
fn an_intent_already_finalized_by_the_direct_paid_path_cannot_later_be_prepared() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let request: u8 = 34;
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );

    // Finalize the intent through the ordinary direct paid path first.
    let direct_output: NodeOutput = crate::paid_execution::handle_paid_execution(
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
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(receipt(&direct_output).status, PaidExecutionStatus::Success);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);

    // The exact same signed intent must not be preparable after the fact,
    // and this reconciliation must fail closed before any nonce, policy,
    // object or engine work -- in particular, before the engine runs at all.
    let prepare_engine: CountingEngine = CountingEngine::new();
    let result = prepare(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &prepare_engine,
        &signers[0],
        &bytes,
        10,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "paid intent already finalized outside the fast path"
        ))
    ));
    assert_eq!(prepare_engine.calls.get(), 0);
    // The rejected prepare left the nonce exactly as the direct commit set it.
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

#[test]
fn a_locked_object_blocks_a_direct_commit_and_leaves_its_tracked_state_untouched() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    prepare_transfer(&store, &fixture, &signers[0], 22, FIRST_PAID_NONCE).unwrap();

    let nonce_before: u64 = crate::query::query_sender_next_nonce(
        &store,
        &context(),
        domain(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        sender(),
    )
    .unwrap();
    assert_eq!(nonce_before, FIRST_PAID_NONCE);

    // A different, unrelated direct-commit request reusing the now-locked
    // fee-source Coin as its own fee source must fail closed.
    let direct_bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 23,
            nonce: nonce_before,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let result = crate::paid_execution::handle_paid_execution(
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
        &direct_bytes,
        10,
    );
    assert!(matches!(
        result,
        Err(PaidExecutionAdmissionError::Invalid(
            "sender nonce locked by a pending fast path"
        ))
    ));
    // The nonce must be exactly unchanged: a pre-admission rejection writes
    // nothing and consumes nothing, lock included.
    let nonce_after: u64 = crate::query::query_sender_next_nonce(
        &store,
        &context(),
        domain(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        sender(),
    )
    .unwrap();
    assert_eq!(nonce_before, nonce_after);
}

#[test]
fn independent_validators_derive_byte_identical_commitment_and_a_quorum_certificate_applies() {
    let store_a: MemoryDurableStateStore = memory_store();
    let store_b: MemoryDurableStateStore = memory_store();
    let store_c: MemoryDurableStateStore = memory_store();
    let store_d: MemoryDurableStateStore = memory_store();
    let fixture_a: Fixture = install(&store_a);
    let fixture_b: Fixture = install(&store_b);
    let fixture_c: Fixture = install(&store_c);
    let fixture_d: Fixture = install(&store_d);
    let (signers, entries) = four_validators();
    for store in [&store_a, &store_b, &store_c, &store_d] {
        install_validator_set(
            store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
    }

    let vote_a: FastVote =
        prepare_transfer(&store_a, &fixture_a, &signers[0], 24, FIRST_PAID_NONCE).unwrap();
    let vote_b: FastVote =
        prepare_transfer(&store_b, &fixture_b, &signers[1], 24, FIRST_PAID_NONCE).unwrap();
    let vote_c: FastVote =
        prepare_transfer(&store_c, &fixture_c, &signers[2], 24, FIRST_PAID_NONCE).unwrap();
    let vote_d: FastVote =
        prepare_transfer(&store_d, &fixture_d, &signers[3], 24, FIRST_PAID_NONCE).unwrap();

    // Four fully independent admissions (separate stores, separate
    // validators) derive the exact same (tx_hash, commitment) pair.
    for vote in [&vote_b, &vote_c, &vote_d] {
        assert_eq!(vote_a.tx_hash, vote.tx_hash);
        assert_eq!(vote_a.execution_effects_hash, vote.execution_effects_hash);
    }

    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let votes: Vec<FastVote> = vec![vote_a.clone(), vote_b.clone(), vote_c, vote_d.clone()];
    // Three of four is already quorum; the fourth vote is not required.
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    assert!(certificate.votes.len() >= 3);
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let alternate_votes: Vec<FastVote> = vec![vote_a.clone(), vote_b.clone(), vote_d.clone()];
    let alternate_certificate: FastCertificate = cert
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &alternate_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    assert_ne!(alternate_certificate.votes, certificate.votes);
    let alternate_certificate_bytes: Vec<u8> =
        consensus::encode_fast_certificate(&alternate_certificate).unwrap();

    let output: NodeOutput = apply_transfer(
        &store_a,
        &fixture_a,
        24,
        FIRST_PAID_NONCE,
        &certificate_bytes,
    )
    .unwrap();
    let result = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(next_nonce(&store_a), FIRST_PAID_NONCE + 1);

    let alternate_output: NodeOutput = apply_transfer(
        &store_b,
        &fixture_b,
        24,
        FIRST_PAID_NONCE,
        &alternate_certificate_bytes,
    )
    .unwrap();
    assert_eq!(
        receipt(&alternate_output).status,
        PaidExecutionStatus::Success
    );

    let settlement_bytes: Vec<u8> = store_a
        .get_versioned_durable(
            &context(),
            domain(),
            &fastpath_settlement_key(protocol().chain_id(), &[24; 32]).unwrap(),
        )
        .unwrap()
        .value()
        .expect("certificate apply must commit its escrow row")
        .to_vec();
    let settlement: FastPathSettlementRecord =
        records::decode_fastpath_settlement_record(&settlement_bytes).unwrap();
    let alternate_settlement_bytes: Vec<u8> = store_b
        .get_versioned_durable(
            &context(),
            domain(),
            &fastpath_settlement_key(protocol().chain_id(), &[24; 32]).unwrap(),
        )
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    assert_eq!(alternate_settlement_bytes, settlement_bytes);
    let charged = result.charged.expect("successful paid call is charged");
    assert_eq!(settlement.context, protocol());
    assert_eq!(settlement.generation, 1);
    assert_eq!(settlement.fee_output.as_ref(), Some(&charged.fee_output));
    assert_eq!(settlement.fee_output_epoch, Some(protocol().epoch()));
    assert_eq!(settlement.total_amount, Some(charged.actual.get()));
    assert_eq!(settlement.shares.len(), entries.len());
    assert_eq!(
        settlement
            .shares
            .iter()
            .map(|share| share.validator_id)
            .collect::<Vec<ValidatorId>>(),
        cert.validator_set()
            .validators()
            .iter()
            .map(|validator| validator.id)
            .collect::<Vec<ValidatorId>>()
    );
    assert!(settlement.shares.iter().all(|share| !share.claimed));
    assert!(
        settlement
            .shares
            .windows(2)
            .all(|pair| pair[0].validator_id < pair[1].validator_id)
    );
    assert_eq!(
        settlement
            .shares
            .iter()
            .map(|share| share.amount)
            .sum::<u64>(),
        charged.actual.get()
    );
    let quotient: u64 = charged.actual.get() / settlement.shares.len() as u64;
    let remainder: usize = (charged.actual.get() % settlement.shares.len() as u64) as usize;
    for (index, share) in settlement.shares.iter().enumerate() {
        assert_eq!(share.amount, quotient + u64::from(index < remainder));
    }

    let fee_head: DurableObjectHead = store_a
        .get_object_head(&context(), domain(), charged.fee_output.id)
        .unwrap();
    let DurableObjectHead::Current { object_version, .. } = fee_head else {
        panic!("fee escrow output must remain current after apply");
    };
    let fee_version: DurableObjectVersionRecord = store_a
        .get_object_version(&context(), domain(), charged.fee_output.id, object_version)
        .unwrap()
        .expect("fee escrow object version");
    let runtime::DurableObjectPayload::Inline(inline) = fee_version.payload() else {
        panic!("fee escrow output must be inline in the test fixture");
    };
    assert_eq!(
        inline.object().owner,
        Owner::ProtocolCustody(objects::ProtocolCustodyScope {
            purpose: objects::ProtocolCustodyPurpose::FeeEscrow,
            chain_id: protocol().chain_id().clone(),
            subject: [24; 32],
            resource: *settlement.resource_id.expect("charged resource").value(),
        })
    );
}

/// The new signed envelope must survive a real prepare/certify/apply cycle,
/// including a replica whose local CAS revision differs for the same semantic
/// state. Provenance reads fence each local commit but are not a signed
/// physical coordinate.
#[test]
fn logical_profile_validators_certify_and_apply_across_physical_revisions() {
    let store_a: MemoryDurableStateStore = memory_store();
    let store_b: MemoryDurableStateStore = memory_store();
    let store_c: MemoryDurableStateStore = memory_store();
    let profile_a: logical_generation::LogicalProfileRecord = install_logical_profile(&store_a);
    let profile_b: logical_generation::LogicalProfileRecord = install_logical_profile(&store_b);
    let profile_c: logical_generation::LogicalProfileRecord = install_logical_profile(&store_c);
    let fixture_a: Fixture = install_with_profile(&store_a, Some(&profile_a));
    let fixture_b: Fixture = install_with_profile(&store_b, Some(&profile_b));
    let fixture_c: Fixture = install_with_profile(&store_c, Some(&profile_c));
    let (signers, entries) = four_validators();
    for store in [&store_a, &store_b, &store_c] {
        install_validator_set(
            store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
    }

    // Same signed fee-policy bytes and logical provenance; only B's local
    // persistence revision changes. Such divergence is expected after import.
    let policy_key: Vec<u8> = local_instance_state::paid_fee_policy_key(&protocol()).unwrap();
    let observed = store_b
        .get_versioned_durable(&context(), domain(), &policy_key)
        .unwrap();
    let policy_bytes: Vec<u8> = observed.value().unwrap().to_vec();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(policy_key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(policy_key, StateMutation::Put(policy_bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store_b.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );

    let request: u8 = 0xd3;
    let vote_a: FastVote =
        prepare_transfer(&store_a, &fixture_a, &signers[0], request, FIRST_PAID_NONCE).unwrap();
    let vote_b: FastVote =
        prepare_transfer(&store_b, &fixture_b, &signers[1], request, FIRST_PAID_NONCE).unwrap();
    let vote_c: FastVote =
        prepare_transfer(&store_c, &fixture_c, &signers[2], request, FIRST_PAID_NONCE).unwrap();
    assert_eq!(vote_a.tx_hash, vote_b.tx_hash);
    assert_eq!(vote_a.execution_effects_hash, vote_b.execution_effects_hash);
    assert_eq!(vote_a.execution_effects_hash, vote_c.execution_effects_hash);
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set.clone());
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &[vote_a, vote_b, vote_c],
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    // DR-0154: a handoff-capable apply now requires a verified
    // `AvailabilityCertificate`. Assemble the canonical bundle purely from
    // replica A's own prepared material (no apply has happened anywhere
    // yet), then have all three replicas independently retain it and form
    // the quorum availability certificate every apply below requires.
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &store_a,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &transfer_bytes(&fixture_a, request, FIRST_PAID_NONCE),
        &certificate_bytes,
    )
    .expect("assembling a bundle from prepared-only material, before any apply");
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let availability_votes: Vec<consensus::AvailabilityVote> = [
        (&store_a, &signers[0]),
        (&store_b, &signers[1]),
        (&store_c, &signers[2]),
    ]
    .into_iter()
    .map(|(store, signer)| {
        crate::fast_path::publication::retain_publication(
            store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &bundle_bytes,
            signer,
        )
        .unwrap()
    })
    .collect();
    let availability_certifier: consensus::AvailabilityCertifier =
        consensus::AvailabilityCertifier::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            validator_set,
        )
        .unwrap();
    let availability_certificate: consensus::AvailabilityCertificate = availability_certifier
        .try_form_certificate(
            &availability_votes[0].identity,
            &availability_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power ACKs already form quorum");
    let availability_certificate_bytes: Vec<u8> =
        consensus::encode_availability_certificate(&availability_certificate).unwrap();

    for (store, fixture) in [
        (&store_a, &fixture_a),
        (&store_b, &fixture_b),
        (&store_c, &fixture_c),
    ] {
        let signed_bytes: Vec<u8> = transfer_bytes(fixture, request, FIRST_PAID_NONCE);
        let output: NodeOutput = fast_path::apply_after_publication(
            store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &CountingEngine::new(),
            &signed_bytes,
            &certificate_bytes,
            &availability_certificate_bytes,
        )
        .unwrap();
        assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
        assert_eq!(next_nonce(store), FIRST_PAID_NONCE + 1);
        let witness_key: Vec<u8> = local_instance_state::fastpath_commitment_witness_key(
            protocol().chain_id(),
            &[request; 32],
        )
        .unwrap();
        let witness = store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap();
        let witness_bytes: &[u8] = witness.value().unwrap();
        let witness_frame = decode_canonical_frame(witness_bytes).unwrap();
        assert_eq!(witness_frame.version(), 2);
        let decoded: commitment::DecodedCommitmentWitness =
            commitment::decode_witness(witness_bytes).unwrap();
        let mut downgraded: Vec<u8> = witness_bytes.to_vec();
        downgraded[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert!(commitment::decode_witness(&downgraded).is_err());
        let mut padded: Vec<u8> = witness_bytes.to_vec();
        padded.push(0);
        assert!(commitment::decode_witness(&padded).is_err());
        assert_eq!(
            decoded.paid_execution_result.status,
            PaidExecutionStatus::Success
        );
        assert_eq!(
            commitment::hash_witness_bytes(&resolver(), protocol().epoch(), witness_bytes).unwrap(),
            certificate.execution_effects_hash
        );
    }
}

/// Regression coverage for the durably bound `created_checkpoint`: `prepare`
/// admits and votes at one checkpoint, and `apply` -- which no longer
/// accepts a checkpoint argument at all -- must re-derive admission against
/// that exact stored value rather than any value visible only at apply
/// time. Before this bound the two independently, so checkpoint progress
/// between vote and apply could re-derive a different commitment for an
/// otherwise perfectly valid certificate and strand both locks (phase 1 has
/// no rollback or expiry).
#[test]
fn apply_uses_the_prepare_time_checkpoint_and_releases_both_locks() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let request: u8 = 40;
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );

    // Prepare at a checkpoint deliberately distinct from every other
    // fixture's checkpoint-10 convention in this file, so a later apply
    // that used any other checkpoint would be unmistakable in the committed
    // object version below.
    let prepare_checkpoint: u64 = 777;
    let vote: FastVote = prepare(
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
        &signers[0],
        &bytes,
        prepare_checkpoint,
    )
    .unwrap();

    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    // `apply` takes no checkpoint argument at all: this call compiling and
    // succeeding is itself part of the regression coverage that the
    // prepare-time value is the only one that can ever be used.
    let output: NodeOutput = apply(
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
        &bytes,
        &certificate_bytes,
    )
    .unwrap();
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);

    // The committed object version durably carries the exact checkpoint
    // `prepare` bound, proving `apply` re-derived admission against the
    // stored value rather than any value visible only at apply time.
    let head: DurableObjectHead = store
        .get_object_head(&context(), domain(), fixture.coin.id)
        .unwrap();
    let DurableObjectHead::Current { object_version, .. } = head else {
        panic!("coin must have a current head after a successful apply");
    };
    let version: DurableObjectVersionRecord = store
        .get_object_version(&context(), domain(), fixture.coin.id, object_version)
        .unwrap()
        .expect("committed object version must be readable");
    assert_eq!(version.created_checkpoint(), prepare_checkpoint);

    // Both exclusive locks are released by the successful apply above: the
    // fee-source Coin's nonce lock and its own per-object fast-path lock are
    // both gone, exactly as a phase-1 apply that never diverges from the
    // certified commitment must leave them.
    let chain: ChainId = protocol().chain_id().clone();
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_nonce_lock_key(&chain, &sender(), protocol().epoch()).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );
}

fn transfer_bytes_for(fixture: &Fixture, request: u8, nonce: u64) -> Vec<u8> {
    let call: PaidCall = PaidCall {
        fixture,
        policy: &fixture.policy,
        request,
        nonce,
        source: &fixture.coin,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
    };
    paid_call_with_access(call, ReservationAccessKind::Write)
}

/// DR-0187 signing-site guard: `require_ordinary_namespace` at the top of
/// `prepare` (`fast_path.rs:675`), before any lock, nonce or execution touch
/// and before the validator's own signature. An Unsealed companion proves
/// the same request is otherwise valid; `CountingEngine`/`CountingSigner`
/// prove zero execution and zero local signing, not merely a returned
/// error. The second half proves a cached exact-replay prepare (a vote
/// already cached before sealing) is also stopped at this same guard,
/// before it ever reaches the exact-replay cache branch that would
/// otherwise re-expose the cached vote.
#[test]
fn prepare_stops_before_signing_once_sealed() {
    let unsealed_store: MemoryDurableStateStore = memory_store_bound();
    let fixture: Fixture = install(&unsealed_store);
    let (signers, _entries) = install_four_validators(&unsealed_store);
    prepare_transfer(
        &unsealed_store,
        &fixture,
        &signers[0],
        0x61,
        FIRST_PAID_NONCE,
    )
    .unwrap();

    let sealed_store: MemoryDurableStateStore = memory_store_bound();
    let fixture: Fixture = install(&sealed_store);
    let (signers, _entries) = install_four_validators(&sealed_store);
    seal_namespace(&sealed_store, domain());
    let before_fresh: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed_store);
    let bytes: Vec<u8> = transfer_bytes_for(&fixture, 0x61, FIRST_PAID_NONCE);
    let engine: CountingEngine = CountingEngine::new();
    let signer: CountingSigner<'_> = CountingSigner {
        inner: &signers[0],
        calls: Cell::new(0),
    };
    let result: FastPathResult<FastVote> = prepare(
        &sealed_store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &signer,
        &bytes,
        10,
    );
    assert!(
        matches!(
            &result,
            Err(FastPathError::Node(NodeCoreError::PersistenceInvariant(
                "outgoing epoch is sealed; live work is forbidden"
            )))
        ),
        "unexpected sealed prepare result: {result:?}"
    );
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(signer.calls.get(), 0);
    let chain: ChainId = protocol().chain_id().clone();
    for key in [
        fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
        fastpath_nonce_lock_key(&chain, &sender(), protocol().epoch()).unwrap(),
        fastpath_prepared_record_key(&chain, &[0x61; 32]).unwrap(),
    ] {
        assert!(
            sealed_store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap()
                .value()
                .is_none()
        );
    }
    let after_fresh: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed_store);
    assert_eq!(
        before_fresh, after_fresh,
        "a sealed fresh prepare must write nothing at all, not merely the named lock/nonce/prepared rows"
    );

    let cached_store: MemoryDurableStateStore = memory_store_bound();
    let fixture: Fixture = install(&cached_store);
    let (signers, _entries) = install_four_validators(&cached_store);
    let cached_bytes: Vec<u8> = transfer_bytes_for(&fixture, 0x62, FIRST_PAID_NONCE);
    let first_vote: FastVote = prepare(
        &cached_store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &signers[0],
        &cached_bytes,
        10,
    )
    .unwrap();
    let unsealed_replay_engine: CountingEngine = CountingEngine::new();
    let unsealed_replay_signer: CountingSigner<'_> = CountingSigner {
        inner: &signers[0],
        calls: Cell::new(0),
    };
    let unsealed_replay_vote: FastVote = prepare(
        &cached_store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &unsealed_replay_engine,
        &unsealed_replay_signer,
        &cached_bytes,
        10,
    )
    .unwrap();
    assert_eq!(
        unsealed_replay_vote, first_vote,
        "the exact-replay cache branch must return the identical retained vote"
    );
    assert_eq!(unsealed_replay_engine.calls.get(), 0);
    assert_eq!(unsealed_replay_signer.calls.get(), 0);
    seal_namespace(&cached_store, domain());
    let before_cached: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&cached_store);
    let replay_engine: CountingEngine = CountingEngine::new();
    let replay_signer: CountingSigner<'_> = CountingSigner {
        inner: &signers[0],
        calls: Cell::new(0),
    };
    let replay_result: FastPathResult<FastVote> = prepare(
        &cached_store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &replay_engine,
        &replay_signer,
        &cached_bytes,
        10,
    );
    assert!(
        matches!(
            &replay_result,
            Err(FastPathError::Node(NodeCoreError::PersistenceInvariant(
                "outgoing epoch is sealed; live work is forbidden"
            )))
        ),
        "cached replay must stop at the barrier: {replay_result:?}"
    );
    assert_eq!(replay_engine.calls.get(), 0);
    assert_eq!(replay_signer.calls.get(), 0);
    let after_cached: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&cached_store);
    assert_eq!(
        before_cached, after_cached,
        "a sealed cached replay must write nothing and must not re-expose the retained vote"
    );
}

/// DR-0187 signing-site guard: `require_ordinary_namespace` inside
/// `apply_internal` (`fast_path.rs:1308`), reached only after the legal
/// historical-receipt reconciliation returns `None` (this request has never
/// completed) so the stop below is genuinely the barrier, not
/// `AlreadyCompleted`. An Unsealed companion applies the identical
/// certificate successfully first. The sealed twin's certificate is formed
/// before sealing (an otherwise-valid, already-quorum-certified request),
/// then applied after sealing: zero engine executions, no receipt, no
/// nonce advance and the prepared record/lock untouched, proving no partial
/// commit leaked past the guard.
#[test]
fn apply_stops_before_commit_once_sealed() {
    let unsealed_store: MemoryDurableStateStore = memory_store_bound();
    let fixture: Fixture = install(&unsealed_store);
    let (signers, entries) = install_four_validators(&unsealed_store);
    let (unsealed_bytes, unsealed_certificate): (Vec<u8>, Vec<u8>) = prepare_and_certify(
        &unsealed_store,
        &fixture,
        &signers,
        &entries,
        0x63,
        FIRST_PAID_NONCE,
    );
    let unsealed_output: NodeOutput = apply(
        &unsealed_store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &unsealed_bytes,
        &unsealed_certificate,
    )
    .unwrap();
    assert_eq!(
        receipt(&unsealed_output).status,
        PaidExecutionStatus::Success
    );

    let sealed_store: MemoryDurableStateStore = memory_store_bound();
    let fixture: Fixture = install(&sealed_store);
    let (signers, entries) = install_four_validators(&sealed_store);
    let (bytes, certificate_bytes): (Vec<u8>, Vec<u8>) = prepare_and_certify(
        &sealed_store,
        &fixture,
        &signers,
        &entries,
        0x63,
        FIRST_PAID_NONCE,
    );
    seal_namespace(&sealed_store, domain());
    let engine: CountingEngine = CountingEngine::new();
    let result: FastPathResult<NodeOutput> = apply(
        &sealed_store,
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
        &certificate_bytes,
    );
    assert!(
        matches!(
            &result,
            Err(FastPathError::Node(NodeCoreError::PersistenceInvariant(
                "outgoing epoch is sealed; live work is forbidden"
            )))
        ),
        "unexpected sealed apply result: {result:?}"
    );
    assert_eq!(engine.calls.get(), 0);
    let request_id: DurableRequestId = DurableRequestId::new([0x63; 32]).unwrap();
    assert!(
        sealed_store
            .get_request_receipt(&context(), domain(), request_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(next_nonce(&sealed_store), FIRST_PAID_NONCE);
    let chain: ChainId = protocol().chain_id().clone();
    assert!(
        sealed_store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_prepared_record_key(&chain, &[0x63; 32]).unwrap(),
            )
            .unwrap()
            .value()
            .is_some(),
        "a sealed apply must leave the local prepared record untouched"
    );
    assert!(
        sealed_store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
            )
            .unwrap()
            .value()
            .is_some(),
        "a sealed apply must never release a lock it never committed"
    );
}

fn prepare_and_certify<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    signers: &[TestSigner],
    entries: &[FastPathValidatorEntry],
    request: u8,
    nonce: u64,
) -> (Vec<u8>, Vec<u8>) {
    let bytes: Vec<u8> = transfer_bytes_for(fixture, request, nonce);
    let vote: FastVote = prepare(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    (bytes, certificate_bytes)
}

/// One validator's independent pair of file-backed SQLite stores (state and
/// blobs), reopened repeatedly across this test to prove restart-durable
/// behavior. Mirrors one real node process's persistence, not shared with
/// any other validator.
struct ValidatorFiles {
    state_path: std::path::PathBuf,
    blob_path: std::path::PathBuf,
    namespace: SqliteNamespace,
}
impl ValidatorFiles {
    fn new(directory: &std::path::Path, index: u8, validator: ValidatorId) -> Self {
        Self {
            state_path: directory.join(format!("validator-{index}-state.sqlite")),
            blob_path: directory.join(format!("validator-{index}-blobs.sqlite")),
            namespace: SqliteNamespace::new(protocol().chain_id().clone(), validator, domain()),
        }
    }
    /// Opens (or reopens, after a prior instance was dropped) this
    /// validator's own state and blob stores from disk.
    fn open(&self) -> (SqliteDurableStore, SqliteBlobStore) {
        (
            SqliteDurableStore::open(
                &self.state_path,
                self.namespace.clone(),
                WriterFenceGeneration::new(1).unwrap(),
            )
            .unwrap(),
            SqliteBlobStore::open(&self.blob_path).unwrap(),
        )
    }
}

#[test]
fn four_validator_sqlite_restart_e2e_derives_identical_votes_and_replays_prepare_and_apply_exactly()
{
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "fastpath-4validator-durable-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let request: u8 = 0x40;
    let (signers, entries) = four_validators();
    let files: Vec<ValidatorFiles> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            ValidatorFiles::new(
                &directory,
                u8::try_from(index).expect("four-validator index"),
                entry.id,
            )
        })
        .collect();

    // Prepare independently on four separate file-backed validator stores:
    // separate SQLite state/blob files, one real Ed25519 signer per
    // validator, no shared process state whatsoever.
    let mut fixtures: Vec<Fixture> = Vec::new();
    let mut votes: Vec<FastVote> = Vec::new();
    let mut signed_bytes: Option<Vec<u8>> = None;
    for (index, file) in files.iter().enumerate() {
        let (store, blob_store) = file.open();
        let fixture: Fixture = install(&store);
        install_validator_set(
            &store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
        install_fee_escrow_economics(&store, &fixture.policy);
        let bytes: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &fixture,
                policy: &fixture.policy,
                request,
                nonce: FIRST_PAID_NONCE,
                source: &fixture.coin,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
                access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        if let Some(existing) = &signed_bytes {
            // Every independent validator's own fixture install and signed
            // intent construction is fully deterministic: byte-identical
            // signed bytes, not merely an identical commitment.
            assert_eq!(existing, &bytes);
        } else {
            signed_bytes = Some(bytes.clone());
        }
        let engine: CountingEngine = CountingEngine::new();
        let vote: FastVote = prepare(
            &store,
            &blob_store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &engine,
            &signers[index],
            &bytes,
            10,
        )
        .unwrap();
        assert_eq!(engine.calls.get(), 1);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
        votes.push(vote);
        fixtures.push(fixture);
    }
    let signed_bytes: Vec<u8> = signed_bytes.unwrap();

    // Four fully independent, file-backed admissions derive the exact same
    // (tx_hash, commitment) pair.
    for vote in &votes[1..] {
        assert_eq!(votes[0].tx_hash, vote.tx_hash);
        assert_eq!(votes[0].execution_effects_hash, vote.execution_effects_hash);
    }

    // Close and reopen every validator's store; exact prepare replay returns
    // the identical byte-stable vote without touching the engine again.
    for (index, file) in files.iter().enumerate() {
        let (store, blob_store) = file.open();
        let replay_engine: CountingEngine = CountingEngine::new();
        let replayed_vote: FastVote = prepare(
            &store,
            &blob_store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixtures[index].policy,
            &replay_engine,
            &signers[index],
            &signed_bytes,
            10,
        )
        .unwrap();
        assert_eq!(replayed_vote, votes[index]);
        assert_eq!(replay_engine.calls.get(), 0);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    }

    // Three of four real, independently derived votes already form quorum.
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    assert!(certificate.votes.len() >= 3);
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    // Apply on validator 0's reopened store.
    let applied_output: NodeOutput;
    {
        let (store, blob_store) = files[0].open();
        let apply_engine: CountingEngine = CountingEngine::new();
        applied_output = apply(
            &store,
            &blob_store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixtures[0].policy,
            &apply_engine,
            &signed_bytes,
            &certificate_bytes,
        )
        .unwrap();
        assert_eq!(
            receipt(&applied_output).status,
            PaidExecutionStatus::Success
        );
        assert_eq!(apply_engine.calls.get(), 1);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
    }

    // Close and reopen validator 0's store; exact apply replay returns the
    // identical final receipt without re-executing or re-advancing the
    // nonce a second time.
    {
        let (store, blob_store) = files[0].open();
        let request_id: [u8; 32] = receipt(&applied_output).request_id;
        let witness_key: Vec<u8> =
            fastpath_commitment_witness_key(protocol().chain_id(), &request_id).unwrap();
        let witness_observed: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap();
        let witness_bytes: &[u8] = witness_observed.value().expect("reopened witness");
        let witnessed: commitment::DecodedCommitmentWitness =
            commitment::decode_witness(witness_bytes).unwrap();
        assert_eq!(witnessed.event_digest, certificate.tx_hash);
        assert_eq!(witnessed.paid_execution_result, receipt(&applied_output));
        assert_eq!(
            commitment::hash_witness_bytes(&resolver(), protocol().epoch(), witness_bytes).unwrap(),
            certificate.execution_effects_hash
        );
        let history_report: crate::fee_claims::FeeClaimVerificationReport =
            crate::fee_claims::verify_fee_claim_history(
                &store,
                &blob_store,
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                &request_id,
            )
            .unwrap();
        assert_eq!(history_report.final_generation, 1);
        assert_eq!(history_report.verified_claims, 0);
        assert_eq!(history_report.verified_positive_claims, 0);
        let inventory: crate::fee_claims::FeeEscrowInventoryPage =
            crate::fee_claims::verify_fee_escrow_inventory_page(
                &store,
                &blob_store,
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                None,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .unwrap();
        assert_eq!(inventory.verified_rows, 1);
        assert_eq!(inventory.verified_claims, 0);
        assert_eq!(inventory.continuation_cursor, None);
        let replay_engine: CountingEngine = CountingEngine::new();
        let replayed_output: NodeOutput = apply(
            &store,
            &blob_store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixtures[0].policy,
            &replay_engine,
            &signed_bytes,
            &certificate_bytes,
        )
        .unwrap();
        assert_eq!(replayed_output, applied_output);
        assert_eq!(replay_engine.calls.get(), 0);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
        // An otherwise well-formed replacement instance row with the same
        // logical creator/seed but a different signed record digest cannot
        // stand in for the fee resource's committed defining instance.
        let original_instance: &execution::local_execution::InstanceRecord = &fixtures[0].instance;
        let instance_key: Vec<u8> = crate::local_instance_state::instance_record_key(
            protocol().chain_id(),
            &original_instance.creator,
            &original_instance.seed,
        )
        .unwrap();
        let observed_instance: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &instance_key)
            .unwrap();
        let mut replaced_instance: execution::local_execution::InstanceRecord =
            original_instance.clone();
        replaced_instance.context = execution::publication::PublicationContext::new(
            original_instance.context.chain_id().clone(),
            original_instance.context.protocol_version(),
            Epoch::new(original_instance.context.epoch().get() + 1),
        )
        .unwrap();
        let replace_instance: AtomicStateTransaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(instance_key.clone(), observed_instance.revision())
                    .unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    instance_key,
                    StateMutation::Put(
                        execution::local_execution::encode_instance_record(&replaced_instance)
                            .unwrap(),
                    ),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(), replace_instance),
            DurableCommitOutcome::Committed
        );
        let instance_result: Result<
            crate::fee_claims::FeeClaimVerificationReport,
            crate::fee_claims::FeeClaimError,
        > = crate::fee_claims::verify_fee_claim_history(
            &store,
            &blob_store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            &request_id,
        );
        assert!(
            matches!(
                &instance_result,
                Err(crate::fee_claims::FeeClaimError::Invalid(
                    "fee claim resource instance mismatch"
                ))
            ),
            "{instance_result:?}"
        );
        let delete_witness: AtomicStateTransaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(witness_key.clone(), witness_observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(witness_key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(), delete_witness),
            DurableCommitOutcome::Committed
        );
        assert!(
            crate::fee_claims::verify_fee_claim_history(
                &store,
                &blob_store,
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                &request_id,
            )
            .is_err()
        );
        assert!(
            crate::fee_claims::verify_fee_escrow_inventory_page(
                &store,
                &blob_store,
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                None,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .is_err()
        );
    }

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn duplicate_and_reordered_certificates_apply_idempotently() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    // Only the first signer actually prepares, and only on this single store;
    // the other three validators cast votes for the identical header directly
    // without ever preparing against a store of their own.
    let vote_local: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], 25, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote_local.tx_hash,
                vote_local.execution_effects_hash,
                vote_local.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote_local.clone()];
    all_votes.extend(remote_votes.clone());
    let ascending: FastCertificate = cert
        .try_form_certificate(
            vote_local.tx_hash,
            vote_local.execution_effects_hash,
            vote_local.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    // A reordered (but still canonically ascending once re-verified) vote
    // arrival order produces the same certificate deterministically.
    let mut reversed_votes: Vec<FastVote> = all_votes.clone();
    reversed_votes.reverse();
    let reordered: FastCertificate = cert
        .try_form_certificate(
            vote_local.tx_hash,
            vote_local.execution_effects_hash,
            vote_local.locked_objects_digest,
            &reversed_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    assert_eq!(ascending, reordered);

    let first_bytes: Vec<u8> = consensus::encode_fast_certificate(&ascending).unwrap();
    let first_output: NodeOutput =
        apply_transfer(&store, &fixture, 25, FIRST_PAID_NONCE, &first_bytes).unwrap();

    // Re-applying the identical certificate returns the identical final
    // receipt idempotently, without re-executing (the reconcile-receipt
    // short circuit fires before any admission work).
    let second_output: NodeOutput =
        apply_transfer(&store, &fixture, 25, FIRST_PAID_NONCE, &first_bytes).unwrap();
    assert_eq!(first_output.responses(), second_output.responses());

    // A duplicate/reordered certificate for the identical header also
    // returns the identical final receipt idempotently.
    let reordered_bytes: Vec<u8> = consensus::encode_fast_certificate(&reordered).unwrap();
    let third_output: NodeOutput =
        apply_transfer(&store, &fixture, 25, FIRST_PAID_NONCE, &reordered_bytes).unwrap();
    assert_eq!(first_output.responses(), third_output.responses());
}

#[test]
fn apply_without_a_local_prepared_record_fails_closed() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = four_validators();
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries,
    )
    .unwrap();
    // Cast the required votes directly (no local prepare on `store`), form a
    // structurally valid certificate, and try to apply it.
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 26,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let (_authenticated, event_digest, _request_id) =
        crate::paid_execution::authenticate_and_identify(&resolver(), &protocol(), &bytes).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
        protocol().epoch(),
        signers
            .iter()
            .map(|signer| ValidatorInfo {
                id: signer.validator_id(),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: signer.validator_id().as_bytes().to_vec(),
            })
            .collect(),
    )
    .unwrap();
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    // Any commitment is fine: this must be rejected before the certificate
    // is even inspected, because there is no local prepared record at all.
    let votes: Vec<FastVote> = signers
        .iter()
        .map(|signer| {
            cert.cast_vote(event_digest, event_digest, event_digest, signer)
                .unwrap()
        })
        .collect();
    let certificate: FastCertificate = FastCertificate {
        chain_id: protocol().chain_id().clone(),
        protocol_version: protocol().protocol_version(),
        epoch: protocol().epoch(),
        tx_hash: event_digest,
        execution_effects_hash: event_digest,
        locked_objects_digest: event_digest,
        votes,
    };
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let result = apply_transfer(&store, &fixture, 26, FIRST_PAID_NONCE, &certificate_bytes);
    assert!(matches!(
        result,
        Err(FastPathError::Invalid("no local fast-path prepared record"))
    ));
}

/// Directly overwrites the committed `FastPathEpochRecord`, simulating a
/// Slice-2 transition this DR does not implement, so Slice 1's real,
/// enforced-from-day-one wrong-epoch/digest rejection can be exercised.
fn overwrite_epoch_record<S: StructuredDurableDomainStateStore>(
    store: &S,
    record: &local_instance_state::FastPathEpochRecord,
) {
    let key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                key,
                StateMutation::Put(
                    local_instance_state::encode_fastpath_epoch_record(record).unwrap(),
                ),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

/// DR-0131 criterion 4: a request bound to a non-current epoch is rejected
/// before any lock, execution, or mutation. Simulates the committed epoch
/// having advanced past this (now stale) prepare request.
#[test]
fn prepare_rejects_a_request_bound_to_a_non_current_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let installed: local_instance_state::FastPathEpochRecord = {
        let key: Vec<u8> =
            local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
        let bytes: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        local_instance_state::decode_fastpath_epoch_record(bytes.value().unwrap()).unwrap()
    };
    overwrite_epoch_record(
        &store,
        &local_instance_state::FastPathEpochRecord {
            current_epoch: Epoch::new(installed.current_epoch.get() + 1),
            ..installed
        },
    );
    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &signers[0], 30, FIRST_PAID_NONCE);
    assert!(matches!(
        result,
        Err(FastPathError::Node(NodeCoreError::EpochMismatch { expected, actual }))
            if expected == Epoch::new(installed.current_epoch.get() + 1) && actual == installed.current_epoch
    ));
    // No lock, nonce reservation, or prepared record was written.
    assert_eq!(
        crate::query::query_sender_next_nonce(
            &store,
            &context(),
            domain(),
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            sender(),
        )
        .unwrap(),
        FIRST_PAID_NONCE
    );
}

/// DR-0131 key transition safety proof, leg 3: apply also rejects a request
/// bound to a non-current epoch, after a valid local prepare and certificate
/// already exist -- simulating the epoch record advancing between prepare
/// and apply.
#[test]
fn apply_rejects_a_request_bound_to_a_non_current_epoch() {
    let store_a: MemoryDurableStateStore = memory_store();
    let store_b: MemoryDurableStateStore = memory_store();
    let store_c: MemoryDurableStateStore = memory_store();
    let fixture_a: Fixture = install(&store_a);
    let fixture_b: Fixture = install(&store_b);
    let fixture_c: Fixture = install(&store_c);
    let (signers, entries) = four_validators();
    for store in [&store_a, &store_b, &store_c] {
        install_validator_set(
            store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
    }
    let vote_a: FastVote =
        prepare_transfer(&store_a, &fixture_a, &signers[0], 31, FIRST_PAID_NONCE).unwrap();
    let vote_b: FastVote =
        prepare_transfer(&store_b, &fixture_b, &signers[1], 31, FIRST_PAID_NONCE).unwrap();
    let vote_c: FastVote =
        prepare_transfer(&store_c, &fixture_c, &signers[2], 31, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let votes: Vec<FastVote> = vec![vote_a.clone(), vote_b, vote_c];
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let store: MemoryDurableStateStore = store_a;
    let fixture: Fixture = fixture_a;
    let installed: local_instance_state::FastPathEpochRecord = {
        let key: Vec<u8> =
            local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
        let bytes: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        local_instance_state::decode_fastpath_epoch_record(bytes.value().unwrap()).unwrap()
    };
    overwrite_epoch_record(
        &store,
        &local_instance_state::FastPathEpochRecord {
            current_epoch: Epoch::new(installed.current_epoch.get() + 1),
            ..installed
        },
    );
    let result: FastPathResult<NodeOutput> =
        apply_transfer(&store, &fixture, 31, FIRST_PAID_NONCE, &certificate_bytes);
    assert!(matches!(
        result,
        Err(FastPathError::Node(NodeCoreError::EpochMismatch { expected, actual }))
            if expected == Epoch::new(installed.current_epoch.get() + 1) && actual == installed.current_epoch
    ));
    // The certificate never applied: the object lock is still held.
    let lock_key: Vec<u8> = fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &lock_key)
            .unwrap()
            .value()
            .is_some()
    );
}

/// DR-0131 two-tier fence model: validator-authorized prepare/apply
/// additionally fence the active per-epoch `ValidatorSet` row and verify its
/// digest matches the committed epoch record.
#[test]
fn prepare_rejects_a_validator_set_digest_mismatch_with_the_committed_epoch_record() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let installed: local_instance_state::FastPathEpochRecord = {
        let key: Vec<u8> =
            local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
        let bytes: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        local_instance_state::decode_fastpath_epoch_record(bytes.value().unwrap()).unwrap()
    };
    overwrite_epoch_record(
        &store,
        &local_instance_state::FastPathEpochRecord {
            current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x5A; 32]),
            ..installed
        },
    );
    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &signers[0], 32, FIRST_PAID_NONCE);
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "fast-path validator set digest does not match the committed epoch record"
        ))
    ));
}

/// DR-0131 criterion 5: prepare rejects a signer absent from the currently
/// committed per-epoch `ValidatorSet`. There is no separate, locally mutable
/// retirement action -- this is entirely a membership lookup against the one
/// committed set.
#[test]
fn prepare_rejects_a_signer_absent_from_the_committed_validator_set() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (_signers, _entries) = install_four_validators(&store);
    let (rogue_signer, _rogue_entry) = validator(250);
    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &rogue_signer, 33, FIRST_PAID_NONCE);
    assert!(matches!(
        result,
        Err(FastPathError::Consensus(ConsensusError::UnknownValidator(
            id
        ))) if id == rogue_signer.validator_id()
    ));
}

/// Regression for the fresh-prepare vote-verification gap identified in
/// design review: `cast_vote` only checks that `signer`'s `(validator_id,
/// scheme)` pair is a *registered* member (`ensure_registered_scheme`); it
/// never verifies the produced signature actually verifies under that
/// validator's *committed public key*. A locally misconfigured or rotated
/// signing key -- one that claims a real, registered validator identity but
/// signs with different key material -- must be rejected by `prepare`
/// itself, before any prepared record, lock, or nonce reservation commits,
/// exactly like the exact-replay branch already re-verifies its stored vote.
/// Without this, the fresh branch would durably wedge every input object
/// behind a vote that can never be certified (phase 1 has no rollback or
/// expiry).
#[test]
fn prepare_rejects_a_fresh_vote_whose_signature_does_not_match_the_registered_public_key() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (_signers, entries) = install_four_validators(&store);
    // Claims the first committed validator's exact identity and scheme, but
    // signs with an unrelated key -- a `ConsensusSigner` misconfiguration
    // `ensure_registered_scheme` alone cannot detect.
    let wrong_key_signer: TestSigner = TestSigner {
        validator_id: entries[0].id,
        signing_key: SigningKey::from([0xEE; 32]),
    };
    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &wrong_key_signer, 35, FIRST_PAID_NONCE);
    assert!(matches!(
        result,
        Err(FastPathError::Consensus(ConsensusError::InvalidSignature(
            id
        ))) if id == entries[0].id
    ));

    // Exact-vector proof of "no commit/locks": every durable key this
    // request could have written remains completely absent.
    let object_lock_key: Vec<u8> =
        fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    let nonce_lock_key: Vec<u8> =
        fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch()).unwrap();
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[35; 32]).unwrap();
    for key in [object_lock_key, nonce_lock_key, prepared_key] {
        assert!(
            store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap()
                .value()
                .is_none()
        );
    }
}

/// DR-0131 criterion 5: apply rejects a certificate whose votes are signed
/// entirely by validators absent from the committed per-epoch `ValidatorSet`
/// -- a rogue quorum that never actually authorizes anything against the
/// real installed set.
#[test]
fn apply_rejects_a_certificate_signed_by_validators_absent_from_the_committed_set() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (real_signers, _entries) = install_four_validators(&store);
    // A real local prepare, so apply reaches certificate verification.
    prepare_transfer(&store, &fixture, &real_signers[0], 34, FIRST_PAID_NONCE).unwrap();

    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 34,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let (_authenticated, event_digest, _request_id) =
        crate::paid_execution::authenticate_and_identify(&resolver(), &protocol(), &bytes).unwrap();
    let prepared: FastPathPreparedRecord = records::decode_fastpath_prepared_record(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_prepared_record_key(protocol().chain_id(), &[34; 32]).unwrap(),
            )
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();

    // A rogue four-validator set, disjoint from the real installed set
    // (distinct seeds), reaching quorum only among themselves.
    let (rogue_signers, rogue_entries): (Vec<TestSigner>, Vec<FastPathValidatorEntry>) =
        [201u8, 202, 203, 204].into_iter().map(validator).unzip();
    let rogue_set: ValidatorSet = ValidatorSet::new(
        protocol().epoch(),
        rogue_entries
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
    let rogue_certifier: consensus::FastPathCertifier = certifier(rogue_set);
    let rogue_votes: Vec<FastVote> = rogue_signers
        .iter()
        .take(3)
        .map(|signer| {
            rogue_certifier
                .cast_vote(
                    event_digest,
                    prepared.commitment,
                    prepared.commitment,
                    signer,
                )
                .unwrap()
        })
        .collect();
    let rogue_certificate: FastCertificate = rogue_certifier
        .try_form_certificate(
            event_digest,
            prepared.commitment,
            prepared.commitment,
            &rogue_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let rogue_certificate_bytes: Vec<u8> =
        consensus::encode_fast_certificate(&rogue_certificate).unwrap();

    let result: FastPathResult<NodeOutput> = apply_transfer(
        &store,
        &fixture,
        34,
        FIRST_PAID_NONCE,
        &rogue_certificate_bytes,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Consensus(ConsensusError::UnknownValidator(
            _
        )))
    ));
}

/// DR-0131 key transition safety proof: apply and a concurrent epoch-record
/// write CAS-fence the identical row, so they cannot interleave
/// inconsistently -- proven here with a stand-in racing write (Slice 1
/// itself never writes this record after genesis) rather than a real
/// Slice-2 transition.
struct EpochRacingEngine<'a, S: StructuredDurableDomainStateStore> {
    store: &'a S,
    inner: CountingEngine,
}
impl<S: StructuredDurableDomainStateStore> execution::paid_execution::PaidContractEngine
    for EpochRacingEngine<'_, S>
{
    fn execute_paid(
        &self,
        request: execution::paid_execution::PaidExecutionRequest<'_>,
    ) -> Result<
        execution::paid_execution::PaidExecutionOutcome,
        execution::paid_execution::PaidExecutionError,
    > {
        let outcome = self.inner.execute_paid(request)?;
        let installed: local_instance_state::FastPathEpochRecord = {
            let key: Vec<u8> =
                local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
            let bytes: VersionedStateValue = self
                .store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap();
            local_instance_state::decode_fastpath_epoch_record(bytes.value().unwrap()).unwrap()
        };
        overwrite_epoch_record(
            self.store,
            &local_instance_state::FastPathEpochRecord {
                previous_epoch: Some(installed.current_epoch),
                activated_at_checkpoint: installed.activated_at_checkpoint + 1,
                ..installed
            },
        );
        Ok(outcome)
    }
}

#[test]
fn a_racing_epoch_record_write_conflicts_the_apply_commit() {
    let store_a: MemoryDurableStateStore = memory_store();
    let store_b: MemoryDurableStateStore = memory_store();
    let store_c: MemoryDurableStateStore = memory_store();
    let fixture_a: Fixture = install(&store_a);
    let fixture_b: Fixture = install(&store_b);
    let fixture_c: Fixture = install(&store_c);
    let (signers, entries) = four_validators();
    for store in [&store_a, &store_b, &store_c] {
        install_validator_set(
            store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
    }
    let vote_a: FastVote =
        prepare_transfer(&store_a, &fixture_a, &signers[0], 35, FIRST_PAID_NONCE).unwrap();
    let vote_b: FastVote =
        prepare_transfer(&store_b, &fixture_b, &signers[1], 35, FIRST_PAID_NONCE).unwrap();
    let vote_c: FastVote =
        prepare_transfer(&store_c, &fixture_c, &signers[2], 35, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let votes: Vec<FastVote> = vec![vote_a.clone(), vote_b, vote_c];
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let store: MemoryDurableStateStore = store_a;
    let fixture: Fixture = fixture_a;

    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 35,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let racing: EpochRacingEngine<'_, MemoryDurableStateStore> = EpochRacingEngine {
        store: &store,
        inner: CountingEngine::new(),
    };
    let result: FastPathResult<NodeOutput> = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &racing,
        &bytes,
        &certificate_bytes,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Node(NodeCoreError::StateConflict))
    ));
    // The lock is still held: the racing commit never applied.
    let lock_key: Vec<u8> = fastpath_lock_key(protocol().chain_id(), fixture.coin.id).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &lock_key)
            .unwrap()
            .value()
            .is_some()
    );
}

#[test]
fn application_failed_fee_only_outcome_prepares_and_applies() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let bytes: Vec<u8> = trapping_mint_call(&fixture, 27, FIRST_PAID_NONCE);
    let vote: FastVote = prepare(
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
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let output: NodeOutput = apply(
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
        &bytes,
        &certificate_bytes,
    )
    .unwrap();
    let result = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::ApplicationFailed);
    assert!(result.charged.is_some());
}

#[test]
fn stale_writer_fence_rejects_apply_atomically() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], 28, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 28,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let stale_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    );
    let result = apply(
        &store,
        &MemoryBlobStore::default(),
        &stale_context,
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &bytes,
        &certificate_bytes,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Node(NodeCoreError::DurableRead(
            DurableReadError::WriterFenced { .. }
        )))
    ));

    // Atomic: the rejected attempt left the lock untouched, so the correctly
    // fenced retry still succeeds.
    let output: NodeOutput =
        apply_transfer(&store, &fixture, 28, FIRST_PAID_NONCE, &certificate_bytes).unwrap();
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
}

#[test]
fn certificate_with_wrong_commitment_for_the_correct_tx_hash_is_rejected_before_engine_execution() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let request: u8 = 32;
    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let prepare_engine: CountingEngine = CountingEngine::new();
    let vote: FastVote = prepare(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &prepare_engine,
        &signers[0],
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(prepare_engine.calls.get(), 1);
    let fee_source_head_before: DurableObjectHead = store
        .get_object_head(&context(), domain(), fixture.coin.id)
        .unwrap();

    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);

    // A real quorum certificate over the exact correct `tx_hash`, but a
    // wrong commitment: every vote is genuinely Ed25519-signed and the
    // certificate verifies structurally, it just attests to a different
    // staged commit than the one `prepare` actually locked and voted on.
    let mut wrong_commitment_bytes: [u8; 32] = vote.execution_effects_hash.bytes();
    wrong_commitment_bytes[0] ^= 0xff;
    let wrong_commitment: Digest32 =
        Digest32::new(HashAlgorithmId::Sha2_256, wrong_commitment_bytes);
    let votes: Vec<FastVote> = signers
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                wrong_commitment,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            wrong_commitment,
            vote.locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    assert!(certificate.votes.len() >= 3);
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let apply_engine: CountingEngine = CountingEngine::new();
    let result = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &apply_engine,
        &bytes,
        &certificate_bytes,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "fast-path certificate does not match the locally prepared commitment"
        ))
    ));
    // Rejected before any engine (execution) work.
    assert_eq!(apply_engine.calls.get(), 0);

    // Nonce unchanged: the rejected apply never advanced it.
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);

    // No final receipt, certificate, or settlement record was written.
    let original_request_id: [u8; 32] = [request; 32];
    let chain: ChainId = protocol().chain_id().clone();
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(original_request_id).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.coin.id)
            .unwrap(),
        fee_source_head_before
    );

    // Both exact lock rows remain, not merely the earlier nonce check that a
    // direct retry would encounter first.
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_nonce_lock_key(&chain, &sender(), protocol().epoch()).unwrap(),
            )
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
            )
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_certificate_key(&chain, &original_request_id).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_settlement_key(&chain, &original_request_id).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );

    // Locks retained: a fresh direct commit reusing the same locked
    // fee-source Coin still fails closed, exactly like a never-certified
    // prepare (phase 1 has no rollback or expiry).
    let direct_bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: request + 1,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let direct_result = crate::paid_execution::handle_paid_execution(
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
        &direct_bytes,
        10,
    );
    assert!(matches!(
        direct_result,
        Err(PaidExecutionAdmissionError::Invalid(
            "sender nonce locked by a pending fast path"
        ))
    ));
}

/// DR-0133 §2: prepare's exact-replay stored-vote check additionally
/// compares `vote.locked_objects_digest` against the digest re-derived from
/// `existing.locked_objects`; a stored vote whose `locked_objects_digest`
/// disagrees with the record it was replayed alongside must not be silently
/// returned as if consistent.
#[test]
fn fast_path_prepare_replay_rejects_a_stored_vote_whose_locked_objects_digest_disagrees_with_the_prepared_lock_set()
 {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], 60, FIRST_PAID_NONCE).unwrap();

    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let mut wrong_digest_bytes: [u8; 32] = vote.locked_objects_digest.bytes();
    wrong_digest_bytes[0] ^= 0xFF;
    let wrong_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, wrong_digest_bytes);
    let re_signed_vote: FastVote = cert
        .cast_vote(
            vote.tx_hash,
            vote.execution_effects_hash,
            wrong_digest,
            &signers[0],
        )
        .unwrap();

    // Overwrite the stored prepared record's vote bytes with the
    // re-signed-but-wrong-digest vote, keeping every other field --
    // including `locked_objects` -- exactly as prepare originally committed.
    let key: Vec<u8> = fastpath_prepared_record_key(protocol().chain_id(), &[60; 32]).unwrap();
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let existing: FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(observed.value().unwrap()).unwrap();
    let tampered: FastPathPreparedRecord = FastPathPreparedRecord {
        vote: consensus::encode_fast_vote(&re_signed_vote).unwrap(),
        ..existing
    };
    let bytes: Vec<u8> = records::encode_fastpath_prepared_record(&tampered).unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );

    let result: FastPathResult<FastVote> =
        prepare_transfer(&store, &fixture, &signers[0], 60, FIRST_PAID_NONCE);
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "fast-path prepared replay vote mismatch"
        ))
    ));
}

/// DR-0133 §2: apply's independent re-derivation additionally computes
/// `fresh_locked_objects_digest` from `admission.locked_objects` and
/// requires it equal `certificate.locked_objects_digest` -- independent of,
/// and strictly beyond, `verify_certificate`'s own per-vote consistency
/// check, which only proves the certificate's votes agree with its header,
/// never that the header agrees with a fresh, independent re-admission. A
/// quorum-carrying certificate that is internally self-consistent (every
/// vote signs the identical, but simply wrong, `locked_objects_digest`) must
/// still be rejected.
#[test]
fn fast_path_apply_rejects_a_certificate_whose_locked_objects_digest_does_not_match_the_freshly_rederived_lock_set()
 {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], 61, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);

    let mut wrong_digest_bytes: [u8; 32] = vote.locked_objects_digest.bytes();
    wrong_digest_bytes[0] ^= 0xFF;
    let wrong_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, wrong_digest_bytes);
    let votes: Vec<FastVote> = signers
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                wrong_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            wrong_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let result: FastPathResult<NodeOutput> =
        apply_transfer(&store, &fixture, 61, FIRST_PAID_NONCE, &certificate_bytes);
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "fast-path re-derived locked-object digest no longer matches the certificate"
        ))
    ));
}

/// Delegates every read/write to a real in-memory store, but reports
/// [`IndeterminateCommitReason::ConnectionLost`] on the very next
/// `commit_invocation` call *after* the underlying commit has already been
/// dispatched to and applied by the inner store -- mirroring a connection
/// loss discovered only after the backend durably committed. Follows this
/// crate's own indeterminate-commit test convention
/// (`crate::publication::tests::ObservedStore`).
struct IndeterminateOnceApplyStore {
    inner: MemoryDurableStateStore,
    inject_indeterminate: Cell<bool>,
}
impl IndeterminateOnceApplyStore {
    fn new() -> Self {
        Self {
            inner: memory_store(),
            inject_indeterminate: Cell::new(false),
        }
    }
}
impl runtime::DurableDomainStateStore for IndeterminateOnceApplyStore {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, runtime::DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
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
impl StructuredDurableDomainStateStore for IndeterminateOnceApplyStore {
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
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
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
        let outcome: DurableCommitOutcome = self.inner.commit_invocation(context, transaction);
        if self.inject_indeterminate.take() {
            assert_eq!(outcome, DurableCommitOutcome::Committed);
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        outcome
    }
}

#[test]
fn indeterminate_apply_commit_reconciles_on_exact_retry_without_reexecution_or_double_debit() {
    let store: IndeterminateOnceApplyStore = IndeterminateOnceApplyStore::new();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let request: u8 = 33;
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], request, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request,
            nonce: FIRST_PAID_NONCE,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );

    store.inject_indeterminate.set(true);
    let first_engine: CountingEngine = CountingEngine::new();
    let first_result = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &first_engine,
        &bytes,
        &certificate_bytes,
    );
    assert!(matches!(
        first_result,
        Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(_)
        ))
    ));
    // The wrapper delegated the real commit before reporting indeterminate:
    // the engine already ran exactly once for this genuinely applied commit.
    assert_eq!(first_engine.calls.get(), 1);

    // Exact retry: `reconcile_receipt` fires before any nonce, lock or
    // engine work, so this is zero re-execution and no second fee debit.
    let retry_engine: CountingEngine = CountingEngine::new();
    let second_output: NodeOutput = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &retry_engine,
        &bytes,
        &certificate_bytes,
    )
    .unwrap();
    assert_eq!(receipt(&second_output).status, PaidExecutionStatus::Success);
    assert_eq!(retry_engine.calls.get(), 0);

    // Exactly one nonce advance total, not two.
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);

    let chain: ChainId = protocol().chain_id().clone();
    let original_request_id: [u8; 32] = [request; 32];
    // The certificate and settlement records exist, written exactly once by
    // the commit the wrapper actually applied.
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_certificate_key(&chain, &original_request_id).unwrap(),
            )
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_settlement_key(&chain, &original_request_id).unwrap(),
            )
            .unwrap()
            .value()
            .is_some()
    );

    // Locks removed: neither the nonce lock nor the object lock installed at
    // prepare still exists once the reconciled commit landed.
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_nonce_lock_key(&chain, &sender(), protocol().epoch()).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &fastpath_lock_key(&chain, fixture.coin.id).unwrap(),
            )
            .unwrap()
            .value()
            .is_none()
    );
}

#[test]
fn an_uncertifiable_prepare_leaves_its_lock_permanently_held() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], 29, FIRST_PAID_NONCE).unwrap();
    // A hand-built one-of-four certificate: well below the quorum of three,
    // so `verify_certificate` must reject it and `apply` must never touch
    // the lock.
    let below_quorum: FastCertificate = FastCertificate {
        chain_id: protocol().chain_id().clone(),
        protocol_version: protocol().protocol_version(),
        epoch: protocol().epoch(),
        tx_hash: vote.tx_hash,
        execution_effects_hash: vote.execution_effects_hash,
        locked_objects_digest: vote.locked_objects_digest,
        votes: vec![vote.clone()],
    };
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&below_quorum).unwrap();
    let result = apply_transfer(&store, &fixture, 29, FIRST_PAID_NONCE, &certificate_bytes);
    assert!(result.is_err());

    // The lock is still held: a direct commit over the same fee-source Coin
    // still fails closed, with no expiry and no rollback in phase 1.
    let nonce: u64 = crate::query::query_sender_next_nonce(
        &store,
        &context(),
        domain(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        sender(),
    )
    .unwrap();
    let direct_bytes: Vec<u8> = paid_call_with_access(
        PaidCall {
            fixture: &fixture,
            policy: &fixture.policy,
            request: 30,
            nonce,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    );
    let direct_result = crate::paid_execution::handle_paid_execution(
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
        &direct_bytes,
        10,
    );
    assert!(matches!(
        direct_result,
        Err(PaidExecutionAdmissionError::Invalid(
            "sender nonce locked by a pending fast path"
        ))
    ));
}

#[test]
fn reserved_request_id_prefix_is_rejected_by_direct_commit_and_prepare() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let mut reserved_id: [u8; 32] = [0u8; 32];
    reserved_id[..local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG.len()]
        .copy_from_slice(&local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    let bytes: Vec<u8> = transfer_with_exact_request_id(&fixture, reserved_id, FIRST_PAID_NONCE);

    let direct_result = crate::paid_execution::handle_paid_execution(
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
        &bytes,
        10,
    );
    assert!(matches!(
        direct_result,
        Err(PaidExecutionAdmissionError::Invalid(
            "request id reserved for fast-path synthetic receipts"
        ))
    ));

    let prepare_result = prepare(
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
        &signers[0],
        &bytes,
        10,
    );
    assert!(matches!(
        prepare_result,
        Err(FastPathError::Admission(error)) if matches!(error.as_ref(),
            PaidExecutionAdmissionError::Invalid(
                "request id reserved for fast-path synthetic receipts"
            )
        )
    ));
}

#[test]
fn synthetic_prepare_request_id_is_deterministic_and_collision_resistant() {
    let first: [u8; 32] = local_instance_state::fastpath_synthetic_prepare_request_id(
        &resolver(),
        protocol().epoch(),
        &[1; 32],
    )
    .unwrap();
    let first_again: [u8; 32] = local_instance_state::fastpath_synthetic_prepare_request_id(
        &resolver(),
        protocol().epoch(),
        &[1; 32],
    )
    .unwrap();
    let second: [u8; 32] = local_instance_state::fastpath_synthetic_prepare_request_id(
        &resolver(),
        protocol().epoch(),
        &[2; 32],
    )
    .unwrap();
    let next_epoch: [u8; 32] = local_instance_state::fastpath_synthetic_prepare_request_id(
        &resolver(),
        Epoch::new(protocol().epoch().get() + 1),
        &[1; 32],
    )
    .unwrap();
    assert_eq!(first, first_again);
    assert_ne!(first, second);
    assert_ne!(first, next_epoch);
    assert!(local_instance_state::is_reserved_paid_request_id(&first));
    assert!(local_instance_state::is_reserved_paid_request_id(&second));
    assert!(local_instance_state::is_reserved_paid_request_id(
        &next_epoch
    ));
}

/// DR-0151 delivery 1: a real paid `Instantiate` is admitted, prepared and
/// applied through the same certified pipeline as `Call`.
#[test]
fn fast_path_prepare_and_apply_admit_a_real_paid_instantiate() {
    const CHECKPOINT: u64 = 42;
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let instantiate_bytes: Vec<u8> = {
        let new_instance_record: InstanceRecord = InstanceRecord {
            seed: [60; 32],
            ..fixture.instance.clone()
        };
        let application = execution::call::CallIntent {
            context: protocol(),
            request_id: [31; 32],
            sender: sender(),
            nonce: FIRST_PAID_NONCE,
            code: fixture.code.clone(),
            instance: instance_target(&resolver(), &new_instance_record).unwrap(),
            entrypoint: "init".into(),
            type_arguments: vec![],
            access: AccessManifest { entries: vec![] },
            arguments: public_standard_asset::no_arguments().unwrap(),
            gas_limit: 100_000,
        };
        sign_paid(execution::paid_execution::PaidIntent {
            context: protocol(),
            request_id: [31; 32],
            sender: sender(),
            nonce: FIRST_PAID_NONCE,
            fee_policy_digest: paid_fee_policy_digest(&resolver(), &fixture.policy).unwrap(),
            consent: FeeSourceConsent {
                source: object_reference(&fixture.coin),
                access: ReservationAccessKind::Write,
                max_fee: Amount::new(1_000_000),
                refund_recipient: refund_account(),
            },
            application: PaidApplication::Instantiate(application),
            gas_limit: 100_000,
            authorizations: vec![],
        })
    };
    let result = prepare(
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
        &signers[0],
        &instantiate_bytes,
        CHECKPOINT,
    );
    result.unwrap();
    // Pre-apply: preparation only authenticates, admits, locks and stages a
    // synthetic receipt. Neither the new instance record, the final receipt
    // keyed by the original request id, the sender nonce, nor the fee-source
    // object may already reflect application.
    assert!(
        local_execution::query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            sender(),
            [60; 32],
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        crate::query::query_request_receipt(
            &store,
            &context(),
            domain(),
            RequestId::new([31; 32]).unwrap(),
        )
        .unwrap(),
        crate::query::ReceiptQueryResult::Absent {
            request_id: RequestId::new([31; 32]).unwrap()
        }
    );
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    match crate::query::query_object(
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
        } => assert_eq!(
            canonical_object_bytes,
            objects::encode_object(&fixture.coin).unwrap()
        ),
        _ => unreachable!("fee coin must be a current inline object"),
    }
    let certificate: Vec<u8> = recovery::certificate_for(&instantiate_bytes, CHECKPOINT);
    let engine: CountingEngine = CountingEngine::new();
    let output: NodeOutput = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &instantiate_bytes,
        &certificate,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 1);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    let record = if let PaidResultTarget::Instance(record) = &result.target {
        record
    } else {
        unreachable!()
    };
    assert_eq!(
        local_execution::query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            sender(),
            [60; 32],
        )
        .unwrap()
        .as_ref(),
        Some(record)
    );
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
    let replay: NodeOutput = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &instantiate_bytes,
        &certificate,
    )
    .unwrap();
    assert_eq!(replay, output);
    assert_eq!(engine.calls.get(), 1);
}

/// DR-0151 delivery 1: a real paid `Publish` is admitted, prepared and
/// applied through the same certified pipeline as `Call`/`Instantiate`.
#[test]
fn fast_path_prepare_and_apply_admit_a_real_paid_publish() {
    const CHECKPOINT: u64 = 42;
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let artifact = publish_artifact(70);
    let origin = artifact.origin().clone();
    let publish_bytes: Vec<u8> = paid_publish(
        &fixture,
        70,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
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
        &signers[0],
        &publish_bytes,
        CHECKPOINT,
    )
    .unwrap();
    // Pre-apply: preparation only authenticates, admits, locks and stages a
    // synthetic receipt. Neither the publication record, the final receipt
    // keyed by the original request id, the sender nonce, nor the fee-source
    // object may already reflect application.
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &publication_record_key(&origin).unwrap()
            )
            .unwrap()
            .value()
            .is_none()
    );
    assert_eq!(
        crate::query::query_request_receipt(
            &store,
            &context(),
            domain(),
            RequestId::new([70; 32]).unwrap(),
        )
        .unwrap(),
        crate::query::ReceiptQueryResult::Absent {
            request_id: RequestId::new([70; 32]).unwrap()
        }
    );
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    match crate::query::query_object(
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
        } => assert_eq!(
            canonical_object_bytes,
            objects::encode_object(&fixture.coin).unwrap()
        ),
        _ => unreachable!("fee coin must be a current inline object"),
    }
    let certificate: Vec<u8> = recovery::certificate_for(&publish_bytes, CHECKPOINT);
    let engine: CountingEngine = CountingEngine::new();
    let output: NodeOutput = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &publish_bytes,
        &certificate,
    )
    .unwrap();
    assert_eq!(engine.calls.get(), 1);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(result.target, PaidResultTarget::Package(origin.clone()));
    assert_eq!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &publication_record_key(&origin).unwrap()
            )
            .unwrap()
            .value(),
        Some(publish_bytes.as_slice())
    );
    let replay: NodeOutput = apply(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &engine,
        &publish_bytes,
        &certificate,
    )
    .unwrap();
    assert_eq!(replay, output);
    assert_eq!(engine.calls.get(), 1);
}

/// A fresh `Instantiate` prepare colliding with an already fast-path-applied
/// instance seed fails closed before any lock or prepared record is written.
#[test]
fn fast_path_prepare_rejects_a_colliding_instantiate_seed() {
    const CHECKPOINT: u64 = 42;
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let bytes: Vec<u8> = paid_instantiate(&fixture, 61, FIRST_PAID_NONCE, 61, &fixture.coin);
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
        &signers[0],
        &bytes,
        CHECKPOINT,
    )
    .unwrap();
    let certificate: Vec<u8> = recovery::certificate_for(&bytes, CHECKPOINT);
    apply(
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
        &bytes,
        &certificate,
    )
    .unwrap();
    let colliding: Vec<u8> =
        paid_instantiate(&fixture, 62, FIRST_PAID_NONCE + 1, 61, &fixture.coin);
    let engine: CountingEngine = CountingEngine::new();
    assert!(matches!(
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
            &engine,
            &signers[1],
            &colliding,
            CHECKPOINT,
        ),
        Err(FastPathError::Admission(error)) if matches!(error.as_ref(),
            PaidExecutionAdmissionError::Invalid("instance already reserved")
        )
    ));
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[62; 32]).unwrap();
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &prepared_key)
            .unwrap()
            .value()
            .is_none()
    );
}

/// A fresh `Publish` prepare colliding with an already fast-path-applied
/// origin fails closed before any lock or prepared record is written.
#[test]
fn fast_path_prepare_rejects_a_duplicate_publish_origin() {
    const CHECKPOINT: u64 = 42;
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let artifact = publish_artifact(80);
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        80,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
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
        &signers[0],
        &bytes,
        CHECKPOINT,
    )
    .unwrap();
    let certificate: Vec<u8> = recovery::certificate_for(&bytes, CHECKPOINT);
    apply(
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
        &bytes,
        &certificate,
    )
    .unwrap();
    let duplicate_artifact = publish_artifact(80);
    let duplicate_bytes: Vec<u8> = paid_publish(
        &fixture,
        81,
        FIRST_PAID_NONCE + 1,
        duplicate_artifact,
        &fixture.coin,
        100_000,
    );
    assert!(matches!(
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
            &signers[1],
            &duplicate_bytes,
            CHECKPOINT,
        ),
        Err(FastPathError::Admission(error)) if matches!(error.as_ref(),
            PaidExecutionAdmissionError::Invalid("publication origin already exists")
        )
    ));
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

/// A `Publish` declaring a never-published dependency fails closed at
/// prepare, before any lock or prepared record is written.
#[test]
fn fast_path_prepare_rejects_a_publish_with_a_missing_dependency() {
    const CHECKPOINT: u64 = 42;
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, _entries) = install_four_validators(&store);
    let bogus_dependency = execution::publication::UnverifiedDependencyRef::new(
        abi::package_types::PackageOrigin::unverified(
            protocol().chain_id().clone(),
            sender(),
            [200; 32],
        )
        .unwrap(),
        1,
        protocol(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
    )
    .unwrap();
    let artifact = crate::paid_execution::tests::publish_artifact_with_dependencies(
        82,
        vec![bogus_dependency],
    );
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        82,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let engine: CountingEngine = CountingEngine::new();
    assert!(matches!(
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
            &engine,
            &signers[0],
            &bytes,
            CHECKPOINT,
        ),
        Err(FastPathError::Admission(error)) if matches!(error.as_ref(),
            PaidExecutionAdmissionError::Publication(PublicationAdmissionError::MissingDependency)
        )
    ));
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
}

#[test]
fn install_validator_set_is_idempotent_and_rejects_a_conflicting_reinstall() {
    let store: MemoryDurableStateStore = memory_store();
    let (_signers, entries) = four_validators();
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries.clone(),
    )
    .unwrap();
    // Byte-identical re-install is idempotent.
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries,
    )
    .unwrap();
    // A conflicting re-install (different validator set) fails closed.
    let (_other_signers, other_entries) = validator(200);
    let result = install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        vec![other_entries],
    );
    assert!(matches!(
        result,
        Err(FastPathError::Invalid(
            "fast-path validator set already installed with different bytes"
        ))
    ));
}

// ── Pinned canonical wire vectors for every DR-0130 frame this module and
// its siblings (`local_instance_state`, `records`, `commitment`) allocate,
// `0x641B` through `0x6425`. Each test below pins the exact bytes this
// crate's own encoder produces; `scripts/fast-path-vectors.mjs`
// independently reconstructs the identical bytes from scratch (it never
// invokes this Rust encoder) and checks the same literal hex. Fixed,
// non-cryptographic fill bytes are used deliberately: these vectors pin the
// *canonical framing*, not any cryptographic property (mirrors
// `consensus::fast_vote`'s own `0xD006`-`0xD008` vectors and
// `scripts/fast-vote-vectors.mjs`).

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector_object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
    }
}

fn vector_context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("dr0130-fastpath-vectors").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(9),
    )
    .unwrap()
}

#[test]
fn fastpath_lock_record_frame_0x641b_is_stable() {
    let record: FastPathLockRecord = FastPathLockRecord {
        request_id: [0x11; 32],
        object: vector_object_ref(0x22, 7, 0x33),
        locked_epoch: Epoch::new(9),
    };
    let bytes: Vec<u8> = encode_fastpath_lock_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451b6401000300010020000000111111111111111111111111111111111111111111111111111111111111111102008c000000534e5245044001000300010030000000534e524501400100010001002000000022222222222222222222222222222222222222222222222222222222222222220200080000000700000000000000030038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330300080000000900000000000000"
    );
}

#[test]
fn fastpath_nonce_lock_record_frame_0x6425_is_stable() {
    let record: FastPathNonceLockRecord = FastPathNonceLockRecord {
        request_id: [0x44; 32],
        sender: [0x55; 32],
        epoch: Epoch::new(9),
        nonce: 42,
    };
    let bytes: Vec<u8> = encode_fastpath_nonce_lock_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52452564010004000100200000004444444444444444444444444444444444444444444444444444444444444444020020000000555555555555555555555555555555555555555555555555555555555555555503000800000009000000000000000400080000002a00000000000000"
    );
}

#[test]
fn fastpath_epoch_record_genesis_frame_0x6426_is_stable() {
    let record: local_instance_state::FastPathEpochRecord =
        local_instance_state::FastPathEpochRecord {
            current_epoch: Epoch::new(9),
            current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
            previous_epoch: None,
            activated_at_checkpoint: 0x77,
        };
    let bytes: Vec<u8> = local_instance_state::encode_fastpath_epoch_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52452664010003000100080000000900000000000000020038000000534e5245030101000200010002000000010002002000000066666666666666666666666666666666666666666666666666666666666666660400080000007700000000000000"
    );
}

#[test]
fn fastpath_epoch_record_with_previous_epoch_frame_0x6426_is_stable() {
    let record: local_instance_state::FastPathEpochRecord =
        local_instance_state::FastPathEpochRecord {
            current_epoch: Epoch::new(10),
            current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]),
            previous_epoch: Some(Epoch::new(9)),
            activated_at_checkpoint: 0x99,
        };
    let bytes: Vec<u8> = local_instance_state::encode_fastpath_epoch_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52452664010004000100080000000a00000000000000020038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888803000800000009000000000000000400080000009900000000000000"
    );
}

#[test]
fn fastpath_prepared_record_frame_0x641c_is_stable() {
    let locked_objects: Vec<ObjectRef> = vec![
        vector_object_ref(0xaa, 1, 0xbb),
        vector_object_ref(0xcc, 2, 0xdd),
    ];
    let record: FastPathPreparedRecord = FastPathPreparedRecord {
        context: vector_context(),
        request_id: [0x66; 32],
        signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
        commitment: Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]),
        vote: vec![0x99; 4],
        locked_objects,
        pending_nonce: 5,
        created_checkpoint: 6,
        // Historical store: the frozen version-one bytes below must not move.
        prepared_generation: None,
    };
    let bytes: Vec<u8> = records::encode_fastpath_prepared_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451c640100080001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000006666666666666666666666666666666666666666666666666666666666666666030038000000534e524503010100020001000200000001000200200000007777777777777777777777777777777777777777777777777777777777777777040038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888805000400000099999999060038010000534e52452064010003000100040000000200000002008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd07000800000005000000000000000800080000000600000000000000"
    );

    // Extract and pin the nested `0x6420` object-ref-list frame (field 6)
    // and, inside it, one nested `ObjectRef` list item, straight out of the
    // already-pinned outer bytes above -- this is the only way to reach
    // these nested frames' exact bytes, since their encoders are private to
    // `records`.
    let outer = decode_canonical_frame(&bytes).unwrap();
    let object_ref_list_bytes: &[u8] = outer.required_field(6).unwrap();
    assert_eq!(
        hex(object_ref_list_bytes),
        "534e52452064010003000100040000000200000002008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb03008c000000534e5245044001000300010030000000534e5245014001000100010020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200080000000200000000000000030038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    );
    let object_ref_list = decode_canonical_frame(object_ref_list_bytes).unwrap();
    let first_object_ref_bytes: &[u8] = object_ref_list.required_field(2).unwrap();
    assert_eq!(
        hex(first_object_ref_bytes),
        "534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn logical_prepared_record_frame_0x641c_v2_is_stable() {
    let record: FastPathPreparedRecord = FastPathPreparedRecord {
        context: vector_context(),
        request_id: [0x66; 32],
        signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
        commitment: Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]),
        vote: vec![0x99],
        locked_objects: Vec::new(),
        pending_nonce: 5,
        created_checkpoint: 6,
        prepared_generation: Some(protocol_types::ExecutionGeneration::new(7)),
    };
    let bytes: Vec<u8> = records::encode_fastpath_prepared_record(&record).unwrap();
    assert_eq!(
        records::decode_fastpath_prepared_record(&bytes).unwrap(),
        record
    );
    assert_eq!(
        hex(&bytes),
        "534e52451c640200090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000006666666666666666666666666666666666666666666666666666666666666666030038000000534e524503010100020001000200000001000200200000007777777777777777777777777777777777777777777777777777777777777777040038000000534e52450301010002000100020000000100020020000000888888888888888888888888888888888888888888888888888888888888888805000100000099060014000000534e524520640100010001000400000000000000070008000000050000000000000008000800000006000000000000000900080000000700000000000000"
    );
}

#[test]
fn fastpath_certificate_record_frame_0x641d_is_stable() {
    let record: FastPathCertificateRecord = FastPathCertificateRecord {
        request_id: [0xee; 32],
        certificate: vec![0xff; 6],
    };
    let bytes: Vec<u8> = records::encode_fastpath_certificate_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451d6401000200010020000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee020006000000ffffffffffff"
    );
}

#[test]
fn validator_fee_rounding_assigns_zero_shares() {
    let (_signers, entries) = four_validators();
    let validator_set: ValidatorSet = ValidatorSet::new(
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
    let shares: Vec<FastPathFeeShare> = validator_fee_shares(&validator_set, 2).unwrap();
    assert_eq!(shares.len(), 4);
    assert_eq!(
        shares
            .iter()
            .map(|share| share.amount)
            .collect::<Vec<u64>>(),
        vec![1, 1, 0, 0]
    );
    assert_eq!(
        shares
            .iter()
            .map(|share| share.validator_id)
            .collect::<Vec<ValidatorId>>(),
        validator_set
            .validators()
            .iter()
            .map(|validator| validator.id)
            .collect::<Vec<ValidatorId>>()
    );
    assert!(shares.iter().all(|share| !share.claimed));
    assert!(validator_fee_shares(&validator_set, 0).is_err());
}

#[test]
fn signed_zero_fee_claim_commits_once_and_conflicting_replay_changes_nothing() {
    use crate::fee_claims::codec::{
        FeeClaimIntent, FeeClaimOperation, SignedFeeClaimIntent, encode_signed_fee_claim_intent,
    };
    use crate::fee_claims::{fee_claim_intent_digest, fee_claim_signing_frame, handle_fee_claim};

    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let mut shares: Vec<FastPathFeeShare> = entries
        .iter()
        .map(|entry| FastPathFeeShare {
            validator_id: entry.id,
            amount: u64::from(entry.id == signers[0].validator_id),
            claimed: false,
        })
        .collect();
    shares.sort_by_key(|share| share.validator_id);
    let fee_output: ObjectRef = object_reference(&fixture.coin);
    let resource_id: BondResourceId = BondResourceId::new(1, [0x71; 32]).unwrap();
    let escrow_request_id: [u8; 32] = [0xc1; 32];
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
        fastpath_settlement_key(protocol().chain_id(), &escrow_request_id).unwrap();
    let row_bytes: Vec<u8> = records::encode_fastpath_settlement_record(&row).unwrap();
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
        store.commit_durable(&context(), setup),
        DurableCommitOutcome::Committed
    );

    let zero_signer: &TestSigner = &signers[1];
    let mut next_row: FastPathSettlementRecord = row.clone();
    next_row.generation += 1;
    next_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == zero_signer.validator_id)
        .unwrap()
        .claimed = true;
    let next_bytes: Vec<u8> = records::encode_fastpath_settlement_record(&next_row).unwrap();
    let previous_digest: Digest32 = resolver()
        .hash_for_purpose(
            protocol().epoch(),
            HashPurpose::ExecutionEffects,
            &row_bytes,
        )
        .unwrap();
    let next_digest: Digest32 = resolver()
        .hash_for_purpose(
            protocol().epoch(),
            HashPurpose::ExecutionEffects,
            &next_bytes,
        )
        .unwrap();
    let intent: FeeClaimIntent = FeeClaimIntent {
        context: protocol(),
        request_id: [0xc2; 32],
        escrow_request_id,
        certificate_epoch: protocol().epoch(),
        validator_id: zero_signer.validator_id,
        resource_id,
        expected_generation: 1,
        expected_fee_output: fee_output,
        expected_previous_row_digest: previous_digest,
        expected_next_row_digest: next_digest,
        share_amount: 0,
        recipient: objects::Address::new([0xc3; 32]),
        operation: FeeClaimOperation::ZeroShare,
    };
    let digest: Digest32 = fee_claim_intent_digest(&resolver(), &intent).unwrap();
    let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
    let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
        signature: zero_signer.signing_key.sign(&frame).into(),
        intent,
    };
    let signed_bytes: Vec<u8> = encode_signed_fee_claim_intent(&signed).unwrap();
    let run = |bytes: &[u8]| {
        handle_fee_claim(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &execution::LocalWasmExecutionEngine::new(),
            bytes,
            10,
        )
    };
    let first: NodeOutput = run(&signed_bytes).unwrap();
    assert_eq!(run(&signed_bytes).unwrap(), first);
    let after: Vec<u8> = store
        .get_versioned_durable(&context(), domain(), &row_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    assert_eq!(after, next_bytes);
    let claim_key: Vec<u8> =
        local_instance_state::fastpath_fee_claim_key(protocol().chain_id(), &escrow_request_id, 2)
            .unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &claim_key)
            .unwrap()
            .value(),
        Some(signed_bytes.as_slice())
    );
    let mut conflicting: SignedFeeClaimIntent = signed;
    conflicting.signature[0] ^= 1;
    let conflicting_bytes: Vec<u8> = encode_signed_fee_claim_intent(&conflicting).unwrap();
    assert!(run(&conflicting_bytes).is_err());
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &row_key)
            .unwrap()
            .value(),
        Some(after.as_slice())
    );
}

#[test]
fn fastpath_settlement_record_charged_frame_0x641e_is_stable() {
    let record: FastPathSettlementRecord = FastPathSettlementRecord {
        context: vector_context(),
        request_id: [0x01; 32],
        generation: 1,
        resource_id: Some(BondResourceId::new(9, [0x09; 32]).unwrap()),
        fee_output: Some(vector_object_ref(0x02, 3, 0x04)),
        fee_output_epoch: Some(Epoch::new(3)),
        total_amount: Some(1),
        shares: vec![
            FastPathFeeShare {
                validator_id: ValidatorId::new([0x05; 32]),
                amount: 1,
                claimed: false,
            },
            FastPathFeeShare {
                validator_id: ValidatorId::new([0x06; 32]),
                amount: 0,
                claimed: false,
            },
        ],
    };
    let bytes: Vec<u8> = records::encode_fastpath_settlement_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451e640100080001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000001010101010101010101010101010101010101010101010101010101010101010300080000000100000000000000040038000000534e52450880010002000100020000000900020020000000090909090909090909090909090909090909090909090909090909090909090905008c000000534e5245044001000300010030000000534e524501400100010001002000000002020202020202020202020202020202020202020202020202020202020202020200080000000300000000000000030038000000534e524503010100020001000200000001000200200000000404040404040404040404040404040404040404040404040404040404040404060008000000030000000000000007000800000001000000000000000800ac000000534e524536640100030001000400000002000000020046000000534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000030046000000534e5245356401000300010020000000060606060606060606060606060606060606060606060606060606060606060602000800000000000000000000000300020000000000"
    );

    // Extract and pin the nested `0x6436` fee-share-list frame (field 8).
    let outer = decode_canonical_frame(&bytes).unwrap();
    let fee_share_list_bytes: &[u8] = outer.required_field(8).unwrap();
    assert_eq!(
        hex(fee_share_list_bytes),
        "534e524536640100030001000400000002000000020046000000534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000030046000000534e5245356401000300010020000000060606060606060606060606060606060606060606060606060606060606060602000800000000000000000000000300020000000000"
    );

    let share_list = decode_canonical_frame(fee_share_list_bytes).unwrap();
    assert_eq!(
        hex(share_list.required_field(2).unwrap()),
        "534e5245356401000300010020000000050505050505050505050505050505050505050505050505050505050505050502000800000001000000000000000300020000000000"
    );

    let mut inconsistent: FastPathSettlementRecord = record.clone();
    inconsistent.shares[0].claimed = true;
    assert!(records::encode_fastpath_settlement_record(&inconsistent).is_err());
    inconsistent.generation = 2;
    let claimed_bytes: Vec<u8> = records::encode_fastpath_settlement_record(&inconsistent).unwrap();
    assert_eq!(
        records::decode_fastpath_settlement_record(&claimed_bytes).unwrap(),
        inconsistent
    );
    let mut duplicate: FastPathSettlementRecord = record.clone();
    duplicate.shares[1].validator_id = duplicate.shares[0].validator_id;
    assert!(records::encode_fastpath_settlement_record(&duplicate).is_err());
    let mut reordered: FastPathSettlementRecord = record.clone();
    reordered.shares.swap(0, 1);
    assert!(records::encode_fastpath_settlement_record(&reordered).is_err());
    let mut inflated: FastPathSettlementRecord = record.clone();
    inflated.shares[0].amount = 2;
    assert!(records::encode_fastpath_settlement_record(&inflated).is_err());
    let mut missing_resource: FastPathSettlementRecord = record.clone();
    missing_resource.resource_id = None;
    assert!(records::encode_fastpath_settlement_record(&missing_resource).is_err());
    let mut zero_total: FastPathSettlementRecord = record.clone();
    zero_total.total_amount = Some(0);
    assert!(records::encode_fastpath_settlement_record(&zero_total).is_err());
    let mut no_shares: FastPathSettlementRecord = record.clone();
    no_shares.shares.clear();
    assert!(records::encode_fastpath_settlement_record(&no_shares).is_err());
}

#[test]
fn fastpath_settlement_record_uncharged_frame_0x641e_is_stable() {
    let record: FastPathSettlementRecord = FastPathSettlementRecord {
        context: vector_context(),
        request_id: [0x07; 32],
        generation: 0,
        resource_id: None,
        fee_output: None,
        fee_output_epoch: None,
        total_amount: None,
        shares: Vec::new(),
    };
    let bytes: Vec<u8> = records::encode_fastpath_settlement_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451e640100030001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000007070707070707070707070707070707070707070707070707070707070707070300080000000000000000000000"
    );
    let mut partial_charge: FastPathSettlementRecord = record;
    partial_charge.resource_id = Some(BondResourceId::new(9, [0x09; 32]).unwrap());
    assert!(records::encode_fastpath_settlement_record(&partial_charge).is_err());
}

#[test]
fn fastpath_bond_record_frame_0x642a_is_stable() {
    let context: PublicationContext = vector_context();
    let origin: abi::package_types::PackageOrigin = abi::package_types::PackageOrigin::unverified(
        context.chain_id().clone(),
        [0x10; 32],
        [0x11; 32],
    )
    .unwrap();
    let code: execution::publication::UnverifiedDependencyRef =
        execution::publication::UnverifiedDependencyRef::new(
            origin.clone(),
            1,
            context.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        )
        .unwrap();
    let authority: execution::local_execution::ObjectAuthority =
        execution::local_execution::ObjectAuthority {
            object_id: ObjectId::new([0x20; 32]),
            instance_context: context.clone(),
            instance: execution::call::InstanceTarget {
                creator: [0x13; 32],
                seed: [0x14; 32],
                revision: 1,
                record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x15; 32]),
            },
            code,
            ty: abi::package_types::ScopedTypeTag::new(
                origin,
                2,
                vec![abi::package_types::ScopedTypeArg::Opaque {
                    domain: 7,
                    value: [0x30; 32],
                }],
            )
            .unwrap(),
        };
    let record: FastPathBondRecord = FastPathBondRecord {
        context,
        validator_id: ValidatorId::new([0x16; 32]),
        resource_domain: 7,
        resource: [0x30; 32],
        custody_object: vector_object_ref(0x20, 1, 0x21),
        custody_object_epoch: Epoch::new(9),
        authority,
        amount: 1_000,
        committed_at_checkpoint: 0x22,
        generation: 1,
        lifecycle_epoch: Epoch::new(9),
        slashable_from_epoch: Epoch::new(9),
        required_minimum: 100,
        state: FastPathBondState::Active,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: VerificationKey::from(&SigningKey::from([0x23; 32])).into(),
    };
    let bytes: Vec<u8> = records::encode_fastpath_bond_record(&record).unwrap();
    assert_eq!(
        records::decode_fastpath_bond_record(&bytes).unwrap(),
        record
    );
    assert_eq!(
        hex(&bytes),
        "534e52452a640100100001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000016161616161616161616161616161616161616161616161616161616161616160300020000000700040020000000303030303030303030303030303030303030303030303030303030303030303005008c000000534e5245044001000300010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030038000000534e524503010100020001000200000001000200200000002121212121212121212121212121212121212121212121212121212121212121060026030000534e5245076401000500010020000000202020202020202020202020202020202020202020202020202020202020202002003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000300a2000000534e5245016401000400010020000000131313131313131313131313131313131313131313131313131313131313131302002000000014141414141414141414141414141414141414141414141414141414141414140300080000000100000000000000040038000000534e52450301010002000100020000000100020020000000151515151515151515151515151515151515151515151515151515151515151504001c010000534e524502630100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f7273020002000000010003002000000010101010101010101010101010101010101010101010101010101010101010100400200000001111111111111111111111111111111111111111111111111111111111111111020008000000010000000000000003003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000040038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120500e1000000534e524503520100040001007b000000534e52450152010004000100170000006472303133302d66617374706174682d766563746f727302000200000001000300200000001010101010101010101010101010101010101010101010101010101010101010040020000000111111111111111111111111111111111111111111111111111111111111111102000200000002000300020000000100040040000000534e5245025201000300010002000000020002000200000007000300200000003030303030303030303030303030303030303030303030303030303030303030070008000000e803000000000000080008000000220000000000000009000800000001000000000000000a000800000009000000000000000b000800000064000000000000000c0012000000534e52452d640100010001000200000001000d000200000001000e002000000074f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa90f000800000009000000000000001000080000000900000000000000"
    );

    let mut trailing: Vec<u8> = bytes.clone();
    trailing.push(0);
    assert!(records::decode_fastpath_bond_record(&trailing).is_err());

    let mut wrong_type: Vec<u8> = bytes.clone();
    wrong_type[4..6].copy_from_slice(&0x642Bu16.to_le_bytes());
    assert!(records::decode_fastpath_bond_record(&wrong_type).is_err());

    let mut zero_amount: FastPathBondRecord = record;
    zero_amount.amount = 0;
    assert!(records::encode_fastpath_bond_record(&zero_amount).is_err());

    let mut mismatched_resource: FastPathBondRecord =
        records::decode_fastpath_bond_record(&bytes).unwrap();
    mismatched_resource.resource = [0x31; 32];
    assert!(records::encode_fastpath_bond_record(&mismatched_resource).is_err());

    let mut stale_lifecycle: FastPathBondRecord =
        records::decode_fastpath_bond_record(&bytes).unwrap();
    stale_lifecycle.lifecycle_epoch = Epoch::new(8);
    assert!(records::encode_fastpath_bond_record(&stale_lifecycle).is_err());

    let mut stale_unbonding: FastPathBondRecord =
        records::decode_fastpath_bond_record(&bytes).unwrap();
    stale_unbonding.state = FastPathBondState::Unbonding {
        unlock_epoch: stale_unbonding.lifecycle_epoch,
        recipient: [0x17; 32],
    };
    assert!(records::encode_fastpath_bond_record(&stale_unbonding).is_err());
    stale_unbonding.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(stale_unbonding.lifecycle_epoch.get() + 1),
        recipient: [0x17; 32],
    };
    assert!(records::encode_fastpath_bond_record(&stale_unbonding).is_ok());
}

#[test]
fn fastpath_bond_transition_record_frame_0x6431_is_stable() {
    let transition: records::FastPathBondTransitionRecord = records::FastPathBondTransitionRecord {
        context: vector_context(),
        validator_id: ValidatorId::new([0x79; 32]),
        generation: 2,
        previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        current_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        operation: records::FastPathBondLifecycleOperation::Deposit,
        committed_at_checkpoint: 9,
        authorization: records::BondTransitionAuthorization::ValidatorEnvelope {
            signed_envelope: vec![0x13, 0x13, 0x13],
        },
        resulting_row: vec![0x14, 0x14],
    };
    let bytes: Vec<u8> = records::encode_fastpath_bond_transition_record(&transition).unwrap();
    assert_eq!(
        records::decode_fastpath_bond_transition_record(&bytes).unwrap(),
        transition
    );
    assert_eq!(
        hex(&bytes),
        "534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120600020000000100070008000000090000000000000008001b000000534e524533640100020001000200000001000200030000001313130900020000001414"
    );

    let mut trailing: Vec<u8> = bytes.clone();
    trailing.push(0);
    assert!(records::decode_fastpath_bond_transition_record(&trailing).is_err());

    let mut zero_generation: records::FastPathBondTransitionRecord =
        records::decode_fastpath_bond_transition_record(&bytes).unwrap();
    zero_generation.generation = 0;
    assert!(records::encode_fastpath_bond_transition_record(&zero_generation).is_err());
}

/// DR-0137 unit 3: frame `0x6433/v1` round-trips both closed authorization
/// tags, a `Slash` transition record embeds a `ConsumedEvidence`
/// authorization correctly, and neither tag accepts the other's fields nor
/// an unknown tag.
#[test]
fn bond_transition_authorization_frame_0x6433_round_trips_both_tags() {
    let validator_envelope = records::BondTransitionAuthorization::ValidatorEnvelope {
        signed_envelope: vec![0x21, 0x22, 0x23],
    };
    let bytes = records::encode_bond_transition_authorization(&validator_envelope).unwrap();
    assert_eq!(
        records::decode_bond_transition_authorization(&bytes).unwrap(),
        validator_envelope
    );
    assert_eq!(
        hex(&bytes),
        "534e52453364010002000100020000000100020003000000212223"
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(records::decode_bond_transition_authorization(&trailing).is_err());

    let consumed_evidence = records::BondTransitionAuthorization::ConsumedEvidence {
        evidence_bytes: vec![0x31, 0x32],
        evidence_epoch: Epoch::new(4),
        evidence_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
        forfeiture_leg: vec![0x34, 0x35, 0x36],
        previous_object: vec![0x37, 0x38],
        resulting_object: vec![0x39, 0x3a],
    };
    let bytes = records::encode_bond_transition_authorization(&consumed_evidence).unwrap();
    assert_eq!(
        records::decode_bond_transition_authorization(&bytes).unwrap(),
        consumed_evidence
    );
    assert_eq!(
        hex(&bytes),
        "534e5245336401000700010002000000020003000200000031320400080000000400000000000000050038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330600030000003435360700020000003738080002000000393a"
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(records::decode_bond_transition_authorization(&trailing).is_err());

    // A `Slash` transition record retains a `ConsumedEvidence` authorization
    // and round-trips exactly like any other operation.
    let transition = records::FastPathBondTransitionRecord {
        context: vector_context(),
        validator_id: ValidatorId::new([0x79; 32]),
        generation: 2,
        previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        current_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        operation: records::FastPathBondLifecycleOperation::Slash,
        committed_at_checkpoint: 9,
        authorization: consumed_evidence,
        resulting_row: vec![0x14, 0x14],
    };
    let bytes = records::encode_fastpath_bond_transition_record(&transition).unwrap();
    assert_eq!(
        records::decode_fastpath_bond_transition_record(&bytes).unwrap(),
        transition
    );
    assert_eq!(
        hex(&bytes),
        "534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120600020000000600070008000000090000000000000008007f000000534e5245336401000700010002000000020003000200000031320400080000000400000000000000050038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330600030000003435360700020000003738080002000000393a0900020000001414"
    );
}

#[test]
fn fastpath_bond_state_frame_0x642d_round_trips_every_closed_variant() {
    let states: Vec<FastPathBondState> = vec![
        FastPathBondState::Active,
        FastPathBondState::Unbonding {
            unlock_epoch: Epoch::new(12),
            recipient: [0x17; 32],
        },
        FastPathBondState::Jailed {
            evidence_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x18; 32]),
        },
        FastPathBondState::Exited,
    ];
    for state in states {
        let bytes: Vec<u8> = records::encode_fastpath_bond_state(&state).unwrap();
        assert_eq!(records::decode_fastpath_bond_state(&bytes).unwrap(), state);
        let mut trailing: Vec<u8> = bytes;
        trailing.push(0);
        assert!(records::decode_fastpath_bond_state(&trailing).is_err());
    }

    let active: Vec<u8> = records::encode_fastpath_bond_state(&FastPathBondState::Active).unwrap();
    assert_eq!(hex(&active), "534e52452d64010001000100020000000100");
}

/// DR-0137 unit 3: `validates_transition` is the exact, exhaustive closed
/// state machine both `bond_lifecycle`'s live admission and
/// `genesis::verify_fastpath_bond_chain`'s restart re-derivation share --
/// exactly one `(previous, resulting)` pair per operation, never more.
#[test]
fn fastpath_bond_lifecycle_operation_validates_transition_is_closed_and_exhaustive() {
    use records::{FastPathBondLifecycleOperation, FastPathBondState};

    let unlock_epoch = Epoch::new(9);
    let recipient = [0x19; 32];
    let evidence_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x1A; 32]);
    let other_evidence_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x1B; 32]);
    let states: Vec<FastPathBondState> = vec![
        FastPathBondState::Active,
        FastPathBondState::Unbonding {
            unlock_epoch,
            recipient,
        },
        FastPathBondState::Jailed { evidence_digest },
        FastPathBondState::Jailed {
            evidence_digest: other_evidence_digest,
        },
        FastPathBondState::Exited,
    ];
    let operations: [FastPathBondLifecycleOperation; 6] = [
        FastPathBondLifecycleOperation::Deposit,
        FastPathBondLifecycleOperation::Replace,
        FastPathBondLifecycleOperation::Unbond,
        FastPathBondLifecycleOperation::Withdraw,
        FastPathBondLifecycleOperation::Reactivate,
        FastPathBondLifecycleOperation::Slash,
    ];

    for operation in operations {
        let mut admitted: Vec<(FastPathBondState, FastPathBondState)> = Vec::new();
        for previous in &states {
            for resulting in &states {
                if operation.validates_transition(previous, resulting) {
                    admitted.push((previous.clone(), resulting.clone()));
                }
            }
        }
        match operation {
            FastPathBondLifecycleOperation::Deposit => {
                assert_eq!(admitted.len(), 1);
                assert!(admitted.iter().all(|(p, r)| *p == FastPathBondState::Exited
                    && matches!(r, FastPathBondState::Active)));
            }
            FastPathBondLifecycleOperation::Replace => {
                assert_eq!(admitted.len(), 1);
                assert!(
                    admitted
                        .iter()
                        .all(|(p, r)| matches!(p, FastPathBondState::Active)
                            && matches!(r, FastPathBondState::Active))
                );
            }
            FastPathBondLifecycleOperation::Unbond => {
                assert_eq!(admitted.len(), 1);
                assert!(
                    admitted
                        .iter()
                        .all(|(p, r)| matches!(p, FastPathBondState::Active)
                            && matches!(r, FastPathBondState::Unbonding { .. }))
                );
            }
            FastPathBondLifecycleOperation::Withdraw => {
                assert_eq!(admitted.len(), 1);
                assert!(
                    admitted
                        .iter()
                        .all(|(p, r)| matches!(p, FastPathBondState::Unbonding { .. })
                            && *r == FastPathBondState::Exited)
                );
            }
            FastPathBondLifecycleOperation::Reactivate => {
                // Both `Jailed` variants (differing only by evidence digest)
                // may reactivate: the digest is historical audit data, not
                // part of the state-machine shape.
                assert_eq!(admitted.len(), 2);
                assert!(
                    admitted
                        .iter()
                        .all(|(p, r)| matches!(p, FastPathBondState::Jailed { .. })
                            && matches!(r, FastPathBondState::Active))
                );
            }
            FastPathBondLifecycleOperation::Slash => {
                // `Active` and `Unbonding` may both be slashed (the bond
                // remains slashable through unbonding); either may land at
                // either `Jailed` variant depending on the consumed digest.
                assert_eq!(admitted.len(), 4);
                assert!(admitted.iter().all(|(p, r)| matches!(
                    p,
                    FastPathBondState::Active | FastPathBondState::Unbonding { .. }
                ) && matches!(
                    r,
                    FastPathBondState::Jailed { .. }
                )));
            }
        }
    }
}

#[test]
fn fastpath_validator_set_record_frame_0x641f_is_stable() {
    let validators: Vec<FastPathValidatorEntry> = vec![
        FastPathValidatorEntry {
            id: ValidatorId::new([0x11; 32]),
            voting_power: 100,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![0x22; 3],
        },
        FastPathValidatorEntry {
            id: ValidatorId::new([0x33; 32]),
            voting_power: 200,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![0x44; 3],
        },
    ];
    let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: vector_context(),
        validators,
    };
    let bytes: Vec<u8> = records::encode_fastpath_validator_set_record(&record).unwrap();
    assert_eq!(
        hex(&bytes),
        "534e52451f640100020001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200be000000534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444"
    );

    // Extract and pin the nested `0x6422` validator-entry-list frame (field
    // 2) and, inside it, one nested `0x6423` validator-entry list item.
    let outer = decode_canonical_frame(&bytes).unwrap();
    let entry_list_bytes: &[u8] = outer.required_field(2).unwrap();
    assert_eq!(
        hex(entry_list_bytes),
        "534e52452264010003000100040000000200000002004f000000534e524523640100040001002000000011111111111111111111111111111111111111111111111111111111111111110200080000006400000000000000030002000000010004000300000022222203004f000000534e52452364010004000100200000003333333333333333333333333333333333333333333333333333333333333333020008000000c8000000000000000300020000000100040003000000444444"
    );
    let entry_list = decode_canonical_frame(entry_list_bytes).unwrap();
    let first_entry_bytes: &[u8] = entry_list.required_field(2).unwrap();
    assert_eq!(
        hex(first_entry_bytes),
        "534e5245236401000400010020000000111111111111111111111111111111111111111111111111111111111111111102000800000064000000000000000300020000000100040003000000222222"
    );
}

/// One envelope input set, parameterized purely by physical coordinates.
fn envelope_with_coordinates(
    head_revision: u64,
    state_revision: u64,
    nonce_revision: u64,
    derived: Option<&logical_generation::LogicalDerivation>,
) -> Vec<u8> {
    let object_id: ObjectId = ObjectId::new([0xc0; 32]);
    let head_reads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        object_id,
        DurableObjectHead::Tombstoned {
            head_revision: runtime::ObjectHeadRevision::new(head_revision).unwrap(),
            last_object_version: DurableObjectVersion::new(4).unwrap(),
        },
    )];
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    reads.insert(vec![0xc1; 3], StateRevision::new(state_revision));
    commitment::encode_envelope(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xc2; 32]),
        &[0xc3; 4],
        &[],
        &head_reads,
        &[],
        &reads,
        &[],
        &[0xc4; 4],
        StateRevision::new(nonce_revision),
        &[0xc5; 4],
        derived,
    )
    .unwrap()
}

/// DR-0154: the handoff-capable envelope signs semantic observations and the
/// authenticated generation, and no physical persistence coordinate at all, so
/// two nodes whose local revisions differ still hash one logical transaction
/// identically. The historical envelope keeps signing exactly those
/// coordinates.
#[test]
fn the_handoff_capable_envelope_signs_no_physical_coordinate() {
    let mut observations: BTreeMap<Vec<u8>, logical_generation::ReadObservation> = BTreeMap::new();
    observations.insert(
        vec![0xc1; 3],
        logical_generation::ReadObservation {
            observed: Some(logical_generation::LogicalObservation::StateDeleted),
            generation: Some(protocol_types::ExecutionGeneration::new(4)),
        },
    );
    let derived: logical_generation::LogicalDerivation = logical_generation::LogicalDerivation {
        generation: protocol_types::ExecutionGeneration::new(5),
        reads: observations,
        inputs: BTreeMap::new(),
    };
    assert_eq!(
        envelope_with_coordinates(1, 6, 9, Some(&derived)),
        envelope_with_coordinates(77, 1234, 4321, Some(&derived))
    );
    assert_ne!(
        envelope_with_coordinates(1, 6, 9, None),
        envelope_with_coordinates(77, 1234, 4321, None)
    );
}

#[test]
fn logical_commitment_envelope_frame_0x6424_v2_is_stable() {
    let mut observations: BTreeMap<Vec<u8>, logical_generation::ReadObservation> = BTreeMap::new();
    observations.insert(
        vec![0xc1; 3],
        logical_generation::ReadObservation {
            observed: Some(logical_generation::LogicalObservation::StateDeleted),
            generation: Some(protocol_types::ExecutionGeneration::new(4)),
        },
    );
    let derived: logical_generation::LogicalDerivation = logical_generation::LogicalDerivation {
        generation: protocol_types::ExecutionGeneration::new(5),
        reads: observations,
        inputs: BTreeMap::new(),
    };
    let bytes: Vec<u8> = envelope_with_coordinates(77, 1234, 4321, Some(&derived));
    assert_eq!(
        hex(&bytes),
        format!(
            "{}{}{}",
            "534e5245246402000b00010038000000534e52450301010002000100020000000100020020000000",
            "c2".repeat(32),
            "020004000000c3c3c3c3030004000000000000000400310000000000000100000029c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00100000000000000040500040000000000000006001e000000000000010000001600000003c1c1c100000002000201000000000000000407000400000000000000080004000000c4c4c4c40a0004000000c5c5c5c50b000800000005000000000000000c000400000000000000"
        )
    );
}

#[test]
fn fastpath_commitment_envelope_frame_0x6424_is_stable() {
    // Created-authority items remain empty because their full nested
    // authority bytes are pinned by the local-execution vectors. The other
    // lists each carry a minimal item here so this vector also pins the
    // commitment layer's big-endian count/length and tagged-item framing,
    // not merely the outer canonical frame.
    let created_authorities: Vec<CreatedObjectAuthority> = Vec::new();
    let object_id: ObjectId = ObjectId::new([0xb0; 32]);
    let head_reads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        object_id,
        DurableObjectHead::Absent,
    )];
    let object_mutations: Vec<DurableObjectMutationEntry> = vec![DurableObjectMutationEntry::new(
        object_id,
        DurableObjectMutation::Delete,
    )];
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    reads.insert(vec![0xb1; 3], StateRevision::new(6));
    let state_mutations: Vec<StateMutationEntry> =
        vec![StateMutationEntry::new(vec![0xb2; 3], StateMutation::Put(vec![0xb3; 2])).unwrap()];
    let nonce_key: Vec<u8> = vec![0xa3; 4];
    let nonce_value: Vec<u8> = vec![0xa4; 4];
    let envelope: Vec<u8> = commitment::encode_envelope(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xa1; 32]),
        &[0xa2; 4],
        &created_authorities,
        &head_reads,
        &object_mutations,
        &reads,
        &state_mutations,
        &nonce_key,
        StateRevision::new(5),
        &nonce_value,
        // Historical store: no logical derivation, so these exact frozen bytes
        // must stay byte-identical under DR-0154.
        None,
    )
    .unwrap();
    assert_eq!(
        hex(&envelope),
        "534e5245246401000a00010038000000534e52450301010002000100020000000100020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1020004000000a2a2a2a2030004000000000000000400290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000500290000000000000100000021b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b000060017000000000000010000000f00000003b1b1b10000000000000006070016000000000000010000000e00000003b2b2b20100000002b3b3080004000000a3a3a3a309000800000005000000000000000a0004000000a4a4a4a4"
    );
    let digest: Digest32 = commitment::compute(
        &resolver(),
        Epoch::new(0),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xa1; 32]),
        &[0xa2; 4],
        &created_authorities,
        &head_reads,
        &object_mutations,
        &reads,
        &state_mutations,
        &nonce_key,
        StateRevision::new(5),
        &nonce_value,
        None,
    )
    .unwrap();
    assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
    assert_eq!(
        hex(&digest.bytes()),
        "daf6fb51270cf45b82aac8b91b8719f50736fefc79e3bc285d149c1d0503a904"
    );
}

// --- DR-0154 publication-retention fixtures ---------------------------------
//
// Shared with `crate::fast_path::publication::tests`. Everything here builds a
// *real* certified paid `Call`: three independent replicas prepare, a genuine
// quorum certificate forms, and (for a handoff-capable/`logical` request) the
// canonical publication bundle is assembled purely from one preparing
// replica's own durably retained prepare-side material
// (`publication::assemble_publication_bundle`) -- no replica ever applies
// first. The historical (`v1`) fixture below still applies to obtain a real
// `0x6424/v1` witness, since a physical-profile prepare retains no witness at
// all (only a handoff-capable prepare does); that asymmetry is itself the
// point of the v1 negative fixture.

use consensus::bundle::{ArtifactManifest, LOGICAL_COMMITMENT_PROFILE, PublicationBundle};
use runtime::{DurableObjectVersion, IndeterminateCommitReason};

/// One replica that may retain publications: its own store, the identical
/// installed fixture and its own registered signer.
pub(crate) struct RetentionReplica {
    pub(crate) store: MemoryDurableStateStore,
    pub(crate) fixture: Fixture,
    pub(crate) signer: TestSigner,
}

impl RetentionReplica {
    /// Prepares the shared transfer call on this replica, creating its local
    /// nonce and object locks.
    pub(crate) fn prepare_transfer(&self, request: u8, nonce: u64) -> FastPathResult<FastVote> {
        prepare_transfer(&self.store, &self.fixture, &self.signer, request, nonce)
    }

    /// Returns the current durable value of one exact key.
    pub(crate) fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.store
            .get_versioned_durable(&context(), domain(), key)
            .unwrap()
            .value()
            .map(<[u8]>::to_vec)
    }

    /// Writes one exact durable row under its observed revision. Test setup
    /// only: no protocol path writes a foreign publication row.
    pub(crate) fn put_row(&self, key: Vec<u8>, value: Vec<u8>) {
        let observed: VersionedStateValue = self
            .store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(value)).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            self.store.commit_durable(&context(), transaction),
            DurableCommitOutcome::Committed
        );
    }

    /// Returns this replica's fast-path lock rows for the fixture's fee-source
    /// object and its sender/epoch nonce lock.
    pub(crate) fn lock_rows(&self) -> Vec<Option<Vec<u8>>> {
        let object_lock: Vec<u8> =
            fastpath_lock_key(protocol().chain_id(), self.fixture.coin.id).unwrap();
        let nonce_lock: Vec<u8> =
            fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch()).unwrap();
        vec![self.row(&object_lock), self.row(&nonce_lock)]
    }

    /// Returns this replica's current head for the fixture's fee-source object.
    pub(crate) fn coin_head(&self) -> DurableObjectHead {
        self.store
            .get_object_head(&context(), domain(), self.fixture.coin.id)
            .unwrap()
    }

    /// Returns any completed-request receipt under `request_id`.
    pub(crate) fn request_receipt(&self, request_id: [u8; 32]) -> Option<DurableRequestReceipt> {
        self.store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(request_id).unwrap(),
            )
            .unwrap()
    }
}

fn retention_replica(logical: bool, signer_index: usize) -> RetentionReplica {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = if logical {
        let profile: logical_generation::LogicalProfileRecord =
            crate::paid_execution::tests::install_freeze_profile(&store);
        install_with_profile(&store, Some(&profile))
    } else {
        install(&store)
    };
    let (mut signers, entries) = four_validators();
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries,
    )
    .unwrap();
    RetentionReplica {
        store,
        fixture,
        signer: signers.swap_remove(signer_index),
    }
}

/// A handoff-capable (`0x6424/v2`) replica, signing as the one validator that
/// never participates in the quorums below, so retention is never confused
/// with this replica's own fast-path vote.
pub(crate) fn logical_replica() -> RetentionReplica {
    retention_replica(true, 3)
}

/// Same handoff-capable fixture as `logical_replica`, but its store is
/// explicitly bound to `domain()` (see `memory_store_bound`), so it carries
/// `OutgoingSealRepository`: DR-0187 grants that capability only to an
/// explicitly domain-bound store. Used by cross-module Sealed-barrier guard
/// tests that must legitimately seal this exact replica's own store.
pub(crate) fn logical_replica_bound() -> RetentionReplica {
    let store: MemoryDurableStateStore = memory_store_bound();
    let profile: logical_generation::LogicalProfileRecord =
        crate::paid_execution::tests::install_freeze_profile(&store);
    let fixture: Fixture = install_with_profile(&store, Some(&profile));
    let (mut signers, entries) = four_validators();
    install_validator_set(
        &store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries,
    )
    .unwrap();
    RetentionReplica {
        store,
        fixture,
        signer: signers.swap_remove(3),
    }
}

/// A historical physical-profile (`0x6424/v1`) replica.
pub(crate) fn physical_replica() -> RetentionReplica {
    retention_replica(false, 3)
}

/// Builds the shared transfer call's signed intent bytes.
pub(crate) fn transfer_bytes(fixture: &Fixture, request: u8, nonce: u64) -> Vec<u8> {
    paid_call_with_access(
        PaidCall {
            fixture,
            policy: &fixture.policy,
            request,
            nonce,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    )
}

/// Builds one complete, genuinely certified publication bundle for the shared
/// transfer call, using the quorum formed by `subset`'s signers.
pub(crate) fn transfer_bundle(
    logical: bool,
    request: u8,
    nonce: u64,
    subset: &[usize],
) -> (PublicationBundle, FastCertificate) {
    let replicas: Vec<RetentionReplica> = subset
        .iter()
        .map(|index| retention_replica(logical, *index))
        .collect();
    let votes: Vec<FastVote> = replicas
        .iter()
        .map(|replica| replica.prepare_transfer(request, nonce).unwrap())
        .collect();
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("quorum reached");

    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: PublicationBundle = if logical {
        // Assembled purely from the first replica's own durably retained
        // prepare-side material (its `prepare_transfer` call above already
        // durably retained the witness and every required artifact, before
        // that call's `FastVote` was ever returned): no replica applies
        // anything here.
        let assembler: &RetentionReplica = &replicas[0];
        crate::fast_path::publication::assemble_publication_bundle(
            &assembler.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &transfer_bytes(&assembler.fixture, request, nonce),
            &certificate_bytes,
        )
        .expect("assembling a bundle from prepared-only material, before any apply")
    } else {
        // A historical (`0x6424/v1`) prepare retains no prepare-side witness
        // at all, so `assemble_publication_bundle` cannot be used here: this
        // negative fixture applies once purely to obtain real `v1` witness
        // bytes to feed into a bundle that `retain_publication` must then
        // refuse on profile grounds -- proving the profile check runs before
        // any closure derivation, not that v1 publication is supported.
        let applier: &RetentionReplica = &replicas[0];
        apply_transfer(
            &applier.store,
            &applier.fixture,
            request,
            nonce,
            &certificate_bytes,
        )
        .unwrap();
        let witness_key: Vec<u8> =
            fastpath_commitment_witness_key(protocol().chain_id(), &[request; 32]).unwrap();
        let witness: Vec<u8> = applier
            .row(&witness_key)
            .expect("apply persists the commitment witness");
        PublicationBundle {
            domain: domain(),
            request_id: [request; 32],
            commitment_profile: LOGICAL_COMMITMENT_PROFILE,
            signed_intent: transfer_bytes(&applier.fixture, request, nonce),
            certificate: certificate.clone(),
            witness,
            manifest: ArtifactManifest {
                entries: Vec::new(),
            },
            contents: Vec::new(),
        }
    };

    (bundle, certificate)
}

/// The default handoff-capable bundle: the quorum formed by signers 0/1/2.
pub(crate) fn transfer_bundle_bytes(
    request: u8,
    nonce: u64,
) -> (PublicationBundle, FastCertificate) {
    transfer_bundle(true, request, nonce, &[0, 1, 2])
}

/// The same operation certified by a different, equally valid signer subset.
pub(crate) fn rebundle_with_other_subset(request: u8, nonce: u64) -> PublicationBundle {
    transfer_bundle(true, request, nonce, &[1, 2, 3]).0
}

/// A historical physical-profile bundle, used to prove a `0x6424/v1` witness
/// can never be retained as a publication.
pub(crate) fn physical_transfer_bundle_bytes(
    request: u8,
    nonce: u64,
) -> (PublicationBundle, FastCertificate) {
    transfer_bundle(false, request, nonce, &[0, 1, 2])
}

pub(crate) fn installed_validator_set() -> ValidatorSet {
    let (_signers, entries) = four_validators();
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

/// Complete structured rows, metadata and exact payloads for refusal/replay
/// comparisons. A fixture's own setup writes occur before this snapshot.
pub(crate) fn full_snapshot(
    store: &MemoryDurableStateStore,
) -> Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> {
    use runtime::portable::{
        DurableCollection, DurablePortableRepository, DurableRecordChunkOutcome,
        DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordScan,
    };
    use std::num::NonZeroUsize;
    let mut rows: Vec<(DurableRecordDescriptor, Vec<u8>)> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(128).unwrap())
                    .unwrap();
            let page = store
                .scan_portable_keys(&context(), domain(), &scan)
                .unwrap();
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor(&context(), domain(), key)
                    .unwrap()
                    .unwrap();
                let mut bytes: Vec<u8> = Vec::new();
                if descriptor.payload_length().is_some() {
                    loop {
                        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            bytes.len(),
                            NonZeroUsize::new(1024 * 1024).unwrap(),
                        )
                        .unwrap();
                        let DurableRecordChunkOutcome::Chunk(chunk) = store
                            .read_portable_chunk(&context(), domain(), &request)
                            .unwrap()
                        else {
                            panic!("snapshot changed");
                        };
                        bytes.extend_from_slice(chunk.bytes());
                        if chunk.is_last() {
                            break;
                        }
                    }
                }
                rows.push((descriptor, bytes));
            }
            after = page.continuation().cloned();
            if after.is_none() {
                break;
            }
        }
    }
    rows
}

/// Injectable connection loss, optionally after the atomic commit lands.
/// Only the selected commit kind is affected once; reads are real storage.
pub(crate) struct AmbiguousCommitStore<'a> {
    pub(crate) inner: &'a MemoryDurableStateStore,
    pub(crate) state: Cell<bool>,
    pub(crate) invocation: Cell<bool>,
    pub(crate) land_before_outcome: bool,
}

impl runtime::DurableDomainStateStore for AmbiguousCommitStore<'_> {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, runtime::DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
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
        if self.state.take() {
            if self.land_before_outcome {
                assert_eq!(
                    self.inner.commit_durable(context, transaction),
                    DurableCommitOutcome::Committed
                );
            }
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for AmbiguousCommitStore<'_> {
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
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
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
        if self.invocation.take() {
            if self.land_before_outcome {
                assert_eq!(
                    self.inner.commit_invocation(context, transaction),
                    DurableCommitOutcome::Committed
                );
            }
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        self.inner.commit_invocation(context, transaction)
    }
}

// --- DR-0154 apply-admission gate: prepare -> bundle -> ACKs -> AC -> apply -

/// Retains `bundle_bytes` on fresh replicas at `subset` (each independently
/// verifying and durably retaining the bundle -- none needs to have prepared
/// this request itself) and forms the resulting quorum
/// [`consensus::AvailabilityCertificate`].
fn availability_certificate_bytes_for(bundle_bytes: &[u8], subset: &[usize]) -> Vec<u8> {
    let votes: Vec<consensus::AvailabilityVote> = subset
        .iter()
        .map(|index| {
            let replica: RetentionReplica = retention_replica(true, *index);
            crate::fast_path::publication::retain_publication(
                &replica.store,
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                bundle_bytes,
                &replica.signer,
            )
            .unwrap()
        })
        .collect();
    let certifier: consensus::AvailabilityCertifier = consensus::AvailabilityCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        installed_validator_set(),
    )
    .unwrap();
    let certificate: consensus::AvailabilityCertificate = certifier
        .try_form_certificate(
            &votes[0].identity,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power ACKs already form quorum");
    consensus::encode_availability_certificate(&certificate).unwrap()
}

/// The complete real DR-0154 flow this slice implements: a genuine
/// handoff-capable prepare on three independent replicas, a real
/// [`FastCertificate`], a [`PublicationBundle`] assembled purely from one
/// preparing replica's own durably retained material (no replica has applied
/// anything at this point), three independent replicas retaining that bundle
/// and forming a quorum [`consensus::AvailabilityCertificate`], and only then
/// a successful apply -- both on a replica that prepared and, signerlessly,
/// on a replica that never did.
#[test]
fn real_v2_prepare_bundle_three_acks_certificate_apply_succeeds_without_prior_apply() {
    const REQUEST: u8 = 0x51;
    let replicas: Vec<RetentionReplica> =
        (0..3).map(|index| retention_replica(true, index)).collect();
    let votes: Vec<FastVote> = replicas
        .iter()
        .map(|replica| replica.prepare_transfer(REQUEST, FIRST_PAID_NONCE).unwrap())
        .collect();
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let signed_bytes: Vec<u8> = transfer_bytes(&replicas[0].fixture, REQUEST, FIRST_PAID_NONCE);

    // No replica has applied anything yet: no certificate/settlement row
    // exists on any of the three.
    let certificate_key: Vec<u8> =
        fastpath_certificate_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    for replica in &replicas {
        assert_eq!(replica.row(&certificate_key), None);
    }

    // Assemble the canonical publication bundle purely from replica 0's own
    // durably retained prepare-side material: read-only, no apply anywhere.
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &replicas[0].store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &signed_bytes,
        &certificate_bytes,
    )
    .expect("assembling a bundle from prepared-only material, before any apply");
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();

    // Three independent replicas retain the bundle and form the quorum
    // availability certificate.
    let availability_certificate_bytes: Vec<u8> =
        availability_certificate_bytes_for(&bundle_bytes, &[0, 1, 2]);

    // Apply on the replica that actually prepared.
    let output: NodeOutput = fast_path::apply_after_publication(
        &replicas[0].store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &replicas[0].fixture.policy,
        &CountingEngine::new(),
        &signed_bytes,
        &certificate_bytes,
        &availability_certificate_bytes,
    )
    .unwrap();
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);
    assert!(replicas[0].row(&certificate_key).is_some());

    // Signerless recovery succeeds identically on a fourth replica that
    // never prepared this request at all.
    let recovering: RetentionReplica = retention_replica(true, 3);
    let recovering_signed_bytes: Vec<u8> =
        transfer_bytes(&recovering.fixture, REQUEST, FIRST_PAID_NONCE);
    let recovered: NodeOutput = fast_path::apply_with_recovery_after_publication(
        &recovering.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &recovering.fixture.policy,
        &CountingEngine::new(),
        &recovering_signed_bytes,
        &certificate_bytes,
        10,
        &availability_certificate_bytes,
    )
    .unwrap();
    assert_eq!(receipt(&recovered).status, PaidExecutionStatus::Success);
}

/// A handoff-capable apply through the *legacy* `apply` entry point (which
/// never threads an availability certificate) is refused, and leaves every
/// object lock, the sender/epoch nonce lock and the fee-source object head
/// exactly as prepare left them: no certificate, settlement or commitment
/// witness row is created either.
#[test]
fn apply_without_an_availability_certificate_refuses_and_leaves_state_and_locks_unchanged() {
    const REQUEST: u8 = 0x52;
    let replicas: Vec<RetentionReplica> =
        (0..3).map(|index| retention_replica(true, index)).collect();
    let votes: Vec<FastVote> = replicas
        .iter()
        .map(|replica| replica.prepare_transfer(REQUEST, FIRST_PAID_NONCE).unwrap())
        .collect();
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let applier: &RetentionReplica = &replicas[0];
    let before_locks: Vec<Option<Vec<u8>>> = applier.lock_rows();
    let before_coin_head: DurableObjectHead = applier.coin_head();

    let result = apply_transfer(
        &applier.store,
        &applier.fixture,
        REQUEST,
        FIRST_PAID_NONCE,
        &certificate_bytes,
    );
    assert!(
        matches!(result, Err(FastPathError::Invalid(_))),
        "unexpected result: {result:?}"
    );
    assert_eq!(applier.lock_rows(), before_locks);
    assert_eq!(applier.coin_head(), before_coin_head);
    let certificate_key: Vec<u8> =
        fastpath_certificate_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    assert_eq!(applier.row(&certificate_key), None);
}

/// An availability certificate that verifies but attests a *different*
/// request id is refused just as fail-closed as no certificate at all, and
/// changes nothing.
#[test]
fn apply_after_publication_with_a_mismatched_availability_certificate_refuses_and_leaves_state_and_locks_unchanged()
 {
    const REQUEST: u8 = 0x53;
    const OTHER_REQUEST: u8 = 0x54;
    let replicas: Vec<RetentionReplica> =
        (0..3).map(|index| retention_replica(true, index)).collect();
    let votes: Vec<FastVote> = replicas
        .iter()
        .map(|replica| replica.prepare_transfer(REQUEST, FIRST_PAID_NONCE).unwrap())
        .collect();
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    // A genuine, validly signed availability certificate -- but for a
    // completely different operation on entirely independent replicas (own
    // fresh stores and sender-nonce sequences), so it shares nothing with
    // `REQUEST` except being certified under the same validator set/epoch.
    let other_replicas: Vec<RetentionReplica> =
        (0..3).map(|index| retention_replica(true, index)).collect();
    let other_votes: Vec<FastVote> = other_replicas
        .iter()
        .map(|replica| {
            replica
                .prepare_transfer(OTHER_REQUEST, FIRST_PAID_NONCE)
                .unwrap()
        })
        .collect();
    let other_certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            other_votes[0].tx_hash,
            other_votes[0].execution_effects_hash,
            other_votes[0].locked_objects_digest,
            &other_votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let other_certificate_bytes: Vec<u8> =
        consensus::encode_fast_certificate(&other_certificate).unwrap();
    let other_signed_bytes: Vec<u8> =
        transfer_bytes(&other_replicas[0].fixture, OTHER_REQUEST, FIRST_PAID_NONCE);
    let other_bundle: PublicationBundle =
        crate::fast_path::publication::assemble_publication_bundle(
            &other_replicas[0].store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &other_signed_bytes,
            &other_certificate_bytes,
        )
        .unwrap();
    let other_bundle_bytes: Vec<u8> =
        consensus::bundle::encode_publication_bundle(&other_bundle).unwrap();
    let mismatched_availability_certificate_bytes: Vec<u8> = {
        let votes: Vec<consensus::AvailabilityVote> = other_replicas
            .iter()
            .map(|replica| {
                crate::fast_path::publication::retain_publication(
                    &replica.store,
                    &context(),
                    domain(),
                    &resolver(),
                    &[],
                    &protocol(),
                    &other_bundle_bytes,
                    &replica.signer,
                )
                .unwrap()
            })
            .collect();
        let certifier: consensus::AvailabilityCertifier = consensus::AvailabilityCertifier::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            installed_validator_set(),
        )
        .unwrap();
        let certificate: consensus::AvailabilityCertificate = certifier
            .try_form_certificate(
                &votes[0].identity,
                &votes,
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
                ),
            )
            .unwrap()
            .expect("three equal-power ACKs already form quorum");
        consensus::encode_availability_certificate(&certificate).unwrap()
    };

    let applier: &RetentionReplica = &replicas[0];
    let before_locks: Vec<Option<Vec<u8>>> = applier.lock_rows();
    let before_coin_head: DurableObjectHead = applier.coin_head();
    let signed_bytes: Vec<u8> = transfer_bytes(&applier.fixture, REQUEST, FIRST_PAID_NONCE);

    let result = fast_path::apply_after_publication(
        &applier.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &applier.fixture.policy,
        &CountingEngine::new(),
        &signed_bytes,
        &certificate_bytes,
        &mismatched_availability_certificate_bytes,
    );
    assert!(
        matches!(result, Err(FastPathError::Invalid(_))),
        "unexpected result: {result:?}"
    );
    assert_eq!(applier.lock_rows(), before_locks);
    assert_eq!(applier.coin_head(), before_coin_head);
    let certificate_key: Vec<u8> =
        fastpath_certificate_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    assert_eq!(applier.row(&certificate_key), None);
}

/// Historical (`0x6424/v1`) apply behavior is byte-identical to before this
/// slice: the legacy `apply` entry point succeeds with no availability
/// certificate at all, and `apply_after_publication` behaves exactly like
/// `apply` for a v1 store (the certificate bytes are accepted but never
/// required or inspected).
#[test]
fn v1_apply_remains_unchanged_and_requires_no_availability_certificate() {
    const REQUEST: u8 = 0x55;
    let replica: RetentionReplica = retention_replica(false, 0);
    let vote_a: FastVote = replica.prepare_transfer(REQUEST, FIRST_PAID_NONCE).unwrap();
    let replica_b: RetentionReplica = retention_replica(false, 1);
    let vote_b: FastVote = replica_b
        .prepare_transfer(REQUEST, FIRST_PAID_NONCE)
        .unwrap();
    let replica_c: RetentionReplica = retention_replica(false, 2);
    let vote_c: FastVote = replica_c
        .prepare_transfer(REQUEST, FIRST_PAID_NONCE)
        .unwrap();
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &[vote_a, vote_b, vote_c],
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let output: NodeOutput = apply_transfer(
        &replica.store,
        &replica.fixture,
        REQUEST,
        FIRST_PAID_NONCE,
        &certificate_bytes,
    )
    .expect("v1 apply requires no availability certificate");
    assert_eq!(receipt(&output).status, PaidExecutionStatus::Success);

    // No prepared witness/artifact material exists for a v1 request: there
    // is nothing to assemble a publication bundle from, by design.
    let witness_key: Vec<u8> = crate::fast_path::prepared_material::fastpath_prepared_witness_key(
        protocol().chain_id(),
        &[REQUEST; 32],
    )
    .unwrap();
    assert_eq!(replica.row(&witness_key), None);
}

/// [`publication::assemble_publication_bundle`] is read-only and
/// restart-safe: it succeeds identically after closing and reopening one
/// preparing replica's real SQLite-backed store, using only durably retained
/// material -- no in-process state survives the reopen.
#[test]
fn assemble_publication_bundle_is_restart_safe_across_a_real_sqlite_reopen() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "fastpath-assemble-restart-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    const REQUEST: u8 = 0x56;
    let (signers, entries) = four_validators();
    let file: ValidatorFiles = ValidatorFiles::new(&directory, 0, entries[0].id);
    type RetainedMaterialRows = Vec<(Vec<u8>, Vec<u8>)>;
    let (fixture, original_vote_a, original_material): (Fixture, FastVote, RetainedMaterialRows) = {
        let (store, _blob_store) = file.open();
        let profile: logical_generation::LogicalProfileRecord = install_logical_profile(&store);
        let fixture: Fixture = install_with_profile(&store, Some(&profile));
        install_validator_set(
            &store,
            &context(),
            domain(),
            &resolver(),
            protocol(),
            entries.clone(),
        )
        .unwrap();
        let vote: FastVote =
            prepare_transfer(&store, &fixture, &signers[0], REQUEST, FIRST_PAID_NONCE).unwrap();
        let witness_key: Vec<u8> =
            prepared_material::fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32])
                .unwrap();
        let witness_bytes: Vec<u8> = store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value()
            .unwrap()
            .to_vec();
        let (_, required): (Digest32, publication::RequiredArtifacts) =
            publication::witness::required_artifacts(&witness_bytes).unwrap();
        let mut material: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        material.insert(witness_key, witness_bytes);
        for ((kind_tag, _identity), digest) in required.iter() {
            let key: Vec<u8> = prepared_material::fastpath_prepared_artifact_key(
                protocol().chain_id(),
                &[REQUEST; 32],
                consensus::bundle::ArtifactKind::from_u16(*kind_tag).unwrap(),
                digest,
            )
            .unwrap();
            let bytes: Vec<u8> = store
                .get_versioned_durable(&context(), domain(), &key)
                .unwrap()
                .value()
                .unwrap()
                .to_vec();
            material.insert(key, bytes);
        }
        (fixture, vote, material.into_iter().collect())
        // `store`/`_blob_store` dropped here: the SQLite connection closes.
    };

    let replica_b: RetentionReplica = retention_replica(true, 1);
    let vote_b: FastVote = replica_b
        .prepare_transfer(REQUEST, FIRST_PAID_NONCE)
        .unwrap();
    let replica_c: RetentionReplica = retention_replica(true, 2);
    let vote_c: FastVote = replica_c
        .prepare_transfer(REQUEST, FIRST_PAID_NONCE)
        .unwrap();

    // Reopen validator 0's real SQLite store from a fresh connection -- a
    // process-restart proxy -- and confirm exact prepare replay returns the
    // identical retained vote, exactly as a genuine restarted validator
    // resubmitting the same request would observe.
    let (reopened_store, reopened_blob_store) = file.open();
    let signed_bytes: Vec<u8> = transfer_bytes(&fixture, REQUEST, FIRST_PAID_NONCE);
    let replay_engine: CountingEngine = CountingEngine::new();
    let vote_a: FastVote = prepare(
        &reopened_store,
        &reopened_blob_store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &replay_engine,
        &signers[0],
        &signed_bytes,
        10,
    )
    .expect("exact prepare replay after reopen returns the retained vote");
    assert_eq!(vote_a, original_vote_a);
    assert_eq!(replay_engine.calls.get(), 0);
    for (key, original_bytes) in &original_material {
        assert_eq!(
            reopened_store
                .get_versioned_durable(&context(), domain(), key)
                .unwrap()
                .value(),
            Some(original_bytes.as_slice()),
            "exact prepare replay preserves every retained byte after restart"
        );
    }
    let certificate: FastCertificate = certifier(installed_validator_set())
        .try_form_certificate(
            vote_a.tx_hash,
            vote_a.execution_effects_hash,
            vote_a.locked_objects_digest,
            &[vote_a, vote_b, vote_c],
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap()
        .expect("three equal-power votes already form quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &reopened_store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &signed_bytes,
        &certificate_bytes,
    )
    .expect("restart-safe assembly from a fresh SQLite connection");
    assert_eq!(bundle.request_id, [REQUEST; 32]);
    assert!(
        !bundle.manifest.entries.is_empty(),
        "the real fixture transfer has a nonempty required closure"
    );
}

/// Delegates every read to a real store but reports every *state* commit as
/// indeterminate, so retention can never expose a signature for an ambiguous
/// write.
pub(crate) struct IndeterminateCommitStore {
    inner: MemoryDurableStateStore,
}

impl IndeterminateCommitStore {
    pub(crate) const fn new(inner: MemoryDurableStateStore) -> Self {
        Self { inner }
    }
}

impl runtime::DurableDomainStateStore for IndeterminateCommitStore {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, runtime::DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
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
        _context: &DurableOperationContext,
        _transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    }
}

impl StructuredDurableDomainStateStore for IndeterminateCommitStore {
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
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
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
        self.inner.commit_invocation(context, transaction)
    }
}
