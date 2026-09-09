//! Durable paid execution regressions.
//!
//! Every fee/application path below runs the real public Standard Asset WASM
//! through the production [`LocalWasmExecutionEngine`] and the real durable
//! store: there is no fake outcome, no native balance backdoor and no
//! fabricated authenticated witness anywhere in the core proofs.
//!
//! The pre-existing asset state (published code, instance, TreasuryCap and the
//! sender's Coins) is installed exactly the way DR-0124 describes a bootstrap
//! installer would: through the existing committed zero-fee surface, before
//! any paid request exists. Paid admission itself never touches that surface.
use super::*;
use abi::package_types::PackageOrigin;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
    decode_local_execution_result, encode_signed_local_execution, generic_object_result_semantics,
    local_execution_signing_frame,
};
use execution::paid_execution::{
    FeeSourceConsent, PaidExecutionResult, PaidResultTarget, SignedPaidIntent,
    decode_paid_execution_result, encode_signed_paid_intent, paid_fee_policy_digest,
    paid_intent_signing_frame,
};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
};
use fees::{Amount, GasSchedule};
use local_execution::query_local_instance;
use protocol_types::{HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId};
use public_standard_asset::{StandardAssetPackage, build_package};
use runtime::{
    DurableDomainStateStore, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::cell::Cell;

// ── trusted fixture configuration ───────────────────────────────────────

fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn treasury() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([9; 32])).into()
}
fn refund_account() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([11; 32])).into()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("paid-durable").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn protocol() -> PublicationContext {
    PublicationContext::new(
        resolver().chain_id().clone(),
        resolver().protocol_version(),
        Epoch::new(0),
    )
    .unwrap()
}
fn base_policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::generic_object_results(protocol())
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([8; 32]).unwrap()
}
fn generation(value: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(value).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    )
}
fn context() -> DurableOperationContext {
    generation(1)
}
fn object_reference(object: &Object) -> ObjectRef {
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(
                protocol().epoch(),
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}
fn entry(object: &Object, mode: AccessMode) -> AccessEntry {
    AccessEntry {
        object_ref: object_reference(object),
        mode,
    }
}
fn set_state<S: StructuredDurableDomainStateStore>(
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

/// A blob store that refuses every operation. Any path that touches it is a
/// path that performed blob I/O, which exact replay must never do.
struct DeniedBlobStore;
impl BlobStore for DeniedBlobStore {
    fn put_blob(&self, _digest: Digest32, _bytes: Vec<u8>) -> Result<(), RuntimeError> {
        Err(RuntimeError::DurableStoreUnavailable)
    }
    fn get_blob(&self, _digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        Err(RuntimeError::DurableStoreUnavailable)
    }
}

// ── zero-fee installation of the pre-existing asset state ───────────────

fn publish_package<S: StructuredDurableDomainStateStore>(
    store: &S,
    seed: u8,
    request: u8,
    nonce: u64,
) -> (PackageOrigin, UnverifiedDependencyRef) {
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [seed; 32]).unwrap();
    let package: StandardAssetPackage = build_package(&origin).unwrap();
    let semantics: Digest32 = generic_object_result_semantics(&resolver(), &protocol()).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame: Vec<u8> = publication_submission_signing_frame(
        &resolver(),
        &protocol(),
        &artifact,
        nonce,
        [request; 32],
    )
    .unwrap();
    let reference: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, protocol(), digest).unwrap();
    let policy: publication::LocalPublicationPolicy =
        publication::LocalPublicationPolicy::object_results(protocol(), semantics);
    set_state(
        store,
        publication::publication_policy_key_for_profile(&protocol(), 4).unwrap(),
        StateMutation::Put(policy.encode().unwrap()),
    );
    publication::handle_local_publication(
        store,
        &context(),
        domain(),
        &resolver(),
        &policy,
        PublicationSubmission::new(
            [request; 32],
            PublicationRequest::new(artifact, nonce, digest, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap();
    (origin, reference)
}

/// One installed zero-fee invocation. This exists only to create the
/// pre-paid asset state; paid admission never enters this surface.
#[allow(clippy::too_many_arguments)]
fn install_call<S: StructuredDurableDomainStateStore>(
    store: &S,
    record: &InstanceRecord,
    request: u8,
    nonce: u64,
    entrypoint: &str,
    type_arguments: Vec<abi::package_types::ScopedTypeArg>,
    arguments: Vec<u8>,
    access: Vec<AccessEntry>,
) -> Vec<Object> {
    let call: CallIntent = CallIntent {
        context: protocol(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        code: record.code.clone(),
        instance: instance_target(&resolver(), record).unwrap(),
        entrypoint: entrypoint.into(),
        type_arguments,
        access: abi::AccessManifest { entries: access },
        arguments,
        gas_limit: 500_000,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: if entrypoint == record.initializer {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: base_policy().digest(&resolver()).unwrap(),
        call,
    };
    let frame: Vec<u8> = local_execution_signing_frame(&protocol(), &intent).unwrap();
    let bytes: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key().sign(&frame).into(),
    })
    .unwrap();
    let output: NodeOutput = local_execution::handle_local_execution(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &base_policy(),
        &LocalWasmExecutionEngine::new(),
        &bytes,
        10,
    )
    .unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    let result = decode_local_execution_result(output.responses()[0].payload().unwrap()).unwrap();
    result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object.clone()),
            ObjectEffect::Mutated { new_object, .. } => Some(new_object.clone()),
            ObjectEffect::Deleted { .. } => None,
        })
        .collect()
}

/// Selects one produced object by its verified nominal tag, so a fixture never
/// depends on the engine's internal arena ordering.
fn pick(objects: &[Object], tag: &abi::package_types::ScopedTypeTag) -> Object {
    objects
        .iter()
        .find(|object| {
            abi::package_types::verify_scoped_type_id(
                &resolver(),
                &object.type_hash,
                protocol().epoch(),
                tag,
            )
            .unwrap()
        })
        .expect("produced object of the requested nominal type")
        .clone()
}

/// The complete installed fixture: published profile-four asset code, one
/// instance, its TreasuryCap and two sender-owned Coins.
struct Fixture {
    origin: PackageOrigin,
    code: UnverifiedDependencyRef,
    instance: InstanceRecord,
    asset: ObjectId,
    cap: Object,
    coin: Object,
    small: Object,
    policy: PaidFeePolicy,
}

fn fee_policy(
    origin: &PackageOrigin,
    instance: &InstanceRecord,
    asset: &ObjectId,
) -> PaidFeePolicy {
    PaidFeePolicy {
        context: protocol(),
        base_policy_digest: base_policy().digest(&resolver()).unwrap(),
        instance: instance_target(&resolver(), instance).unwrap(),
        code: instance.code.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(asset)],
        asset_type: public_standard_asset::coin_type_tag(origin, asset).unwrap(),
        reservation_type: public_standard_asset::reservation_type_tag(origin, asset).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: treasury(),
        gas_schedule: GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: 200_000,
        settle_allowance: 200_000,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    }
}

/// The first paid sender nonce, after the installed publication and the three
/// installed zero-fee invocations.
const FIRST_PAID_NONCE: u64 = 4;

fn install<S: StructuredDurableDomainStateStore>(store: &S) -> Fixture {
    set_state(
        store,
        execution_policy_key_for_profile(&protocol(), 4).unwrap(),
        StateMutation::Put(base_policy().encode().unwrap()),
    );
    let (origin, code) = publish_package(store, 1, 1, 0);
    let instance: InstanceRecord = InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [2; 32],
        code: code.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let initialized: Vec<Object> = install_call(
        store,
        &instance,
        2,
        1,
        "init",
        vec![],
        public_standard_asset::no_arguments().unwrap(),
        vec![],
    );
    let asset: ObjectId = pick(
        &initialized,
        &public_standard_asset::definition_type_tag(&origin).unwrap(),
    )
    .id;
    let cap_tag = public_standard_asset::treasury_cap_type_tag(&origin, &asset).unwrap();
    let coin_tag = public_standard_asset::coin_type_tag(&origin, &asset).unwrap();
    let cap: Object = pick(&initialized, &cap_tag);
    let types = vec![public_standard_asset::asset_type_argument(&asset)];
    let minted: Vec<Object> = install_call(
        store,
        &instance,
        3,
        2,
        "mint",
        types.clone(),
        public_standard_asset::mint_arguments(1_000, &sender()).unwrap(),
        vec![entry(&cap, AccessMode::Write)],
    );
    let coin: Object = pick(&minted, &coin_tag);
    let cap: Object = pick(&minted, &cap_tag);
    let minted: Vec<Object> = install_call(
        store,
        &instance,
        4,
        3,
        "mint",
        types,
        public_standard_asset::mint_arguments(400, &sender()).unwrap(),
        vec![entry(&cap, AccessMode::Write)],
    );
    let small: Object = pick(&minted, &coin_tag);
    let cap: Object = pick(&minted, &cap_tag);
    let policy: PaidFeePolicy = fee_policy(&origin, &instance, &asset);
    set_state(
        store,
        paid_fee_policy_key(&protocol()).unwrap(),
        StateMutation::Put(encode_paid_fee_policy(&policy).unwrap()),
    );
    Fixture {
        origin,
        code,
        instance,
        asset,
        cap,
        coin,
        small,
        policy,
    }
}

// ── paid request builders ───────────────────────────────────────────────

fn sign_paid(intent: PaidIntent) -> Vec<u8> {
    let frame: Vec<u8> = paid_intent_signing_frame(&protocol(), &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        intent,
        signature: key().sign(&frame).into(),
    })
    .unwrap()
}

struct PaidCall<'a> {
    fixture: &'a Fixture,
    policy: &'a PaidFeePolicy,
    request: u8,
    nonce: u64,
    source: &'a Object,
    entrypoint: &'a str,
    arguments: Vec<u8>,
    access: Vec<AccessEntry>,
}

fn paid_call(call: PaidCall<'_>) -> Vec<u8> {
    let application: CallIntent = CallIntent {
        context: protocol(),
        request_id: [call.request; 32],
        sender: sender(),
        nonce: call.nonce,
        code: call.fixture.code.clone(),
        instance: instance_target(&resolver(), &call.fixture.instance).unwrap(),
        entrypoint: call.entrypoint.into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(
            &call.fixture.asset,
        )],
        access: abi::AccessManifest {
            entries: call.access,
        },
        arguments: call.arguments,
        gas_limit: 100_000,
    };
    sign_paid(PaidIntent {
        context: protocol(),
        request_id: [call.request; 32],
        sender: sender(),
        nonce: call.nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), call.policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_reference(call.source),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: refund_account(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

/// The canonical successful path: one Coin funds both the fee reservation and
/// the application's own `transfer` of the spendable remainder.
fn transfer_call(fixture: &Fixture, request: u8, nonce: u64) -> Vec<u8> {
    paid_call(PaidCall {
        fixture,
        policy: &fixture.policy,
        request,
        nonce,
        source: &fixture.coin,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, AccessMode::Write)],
    })
}

/// `mint` with an undecodable all-zero recipient: the application writes the
/// TreasuryCap supply and only then traps at the host create boundary.
fn trapping_mint_call(fixture: &Fixture, request: u8, nonce: u64) -> Vec<u8> {
    paid_call(PaidCall {
        fixture,
        policy: &fixture.policy,
        request,
        nonce,
        source: &fixture.coin,
        entrypoint: "mint",
        arguments: public_standard_asset::mint_arguments(5, &[0u8; 32]).unwrap(),
        access: vec![entry(&fixture.cap, AccessMode::Write)],
    })
}

fn paid_instantiate(
    fixture: &Fixture,
    request: u8,
    nonce: u64,
    seed: u8,
    source: &Object,
) -> Vec<u8> {
    let record: InstanceRecord = InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [seed; 32],
        code: fixture.code.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let application: CallIntent = CallIntent {
        context: protocol(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        code: fixture.code.clone(),
        instance: instance_target(&resolver(), &record).unwrap(),
        entrypoint: "init".into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 100_000,
    };
    sign_paid(PaidIntent {
        context: protocol(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &fixture.policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_reference(source),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: refund_account(),
        },
        application: PaidApplication::Instantiate(application),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

fn publish_artifact(seed: u8) -> CodeArtifact {
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [seed; 32]).unwrap();
    let package: StandardAssetPackage = build_package(&origin).unwrap();
    CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin,
        revision: 1,
        wasm_profile: 4,
        semantics: generic_object_result_semantics(&resolver(), &protocol()).unwrap(),
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap()
}

fn paid_publish(
    fixture: &Fixture,
    request: u8,
    nonce: u64,
    artifact: CodeArtifact,
    source: &Object,
    gas_limit: u64,
) -> Vec<u8> {
    sign_paid(PaidIntent {
        context: protocol(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &fixture.policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_reference(source),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: refund_account(),
        },
        application: PaidApplication::Publish(artifact),
        gas_limit,
        authorizations: vec![],
    })
}

// ── invocation helpers ──────────────────────────────────────────────────

/// Counts engine entries, so exact replay can be proven not to reexecute.
struct CountingEngine {
    inner: LocalWasmExecutionEngine,
    calls: Cell<u32>,
}
impl CountingEngine {
    fn new() -> Self {
        Self {
            inner: LocalWasmExecutionEngine::new(),
            calls: Cell::new(0),
        }
    }
}
impl PaidContractEngine for CountingEngine {
    fn execute_paid(
        &self,
        request: PaidExecutionRequest<'_>,
    ) -> Result<PaidExecutionOutcome, PaidExecutionError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.execute_paid(request)
    }
}

fn run<S: StructuredDurableDomainStateStore>(
    store: &S,
    blob_store: &dyn BlobStore,
    operation: &DurableOperationContext,
    policy: &PaidFeePolicy,
    engine: &CountingEngine,
    bytes: &[u8],
) -> PaidResult<NodeOutput> {
    handle_paid_execution(
        store,
        blob_store,
        operation,
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        policy,
        engine,
        bytes,
        10,
    )
}

fn execute<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    engine: &CountingEngine,
    bytes: &[u8],
) -> PaidResult<NodeOutput> {
    run(
        store,
        &MemoryBlobStore::default(),
        &context(),
        &fixture.policy,
        engine,
        bytes,
    )
}

fn receipt(output: &NodeOutput) -> PaidExecutionResult {
    decode_paid_execution_result(output.responses()[0].payload().unwrap()).unwrap()
}
fn next_nonce<S: StructuredDurableDomainStateStore>(store: &S) -> u64 {
    query_sender_next_nonce(
        store,
        &context(),
        domain(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        sender(),
    )
    .unwrap()
}

/// Every durable byte one paid regression must prove unchanged.
#[derive(Debug, PartialEq, Eq)]
struct Tracked {
    states: Vec<VersionedStateValue>,
    heads: Vec<DurableObjectHead>,
    bodies: Vec<Option<DurableObjectVersionRecord>>,
    receipts: Vec<Option<DurableRequestReceipt>>,
}
fn tracked<S: StructuredDurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    fixture: &Fixture,
    extra_origin: &PackageOrigin,
) -> Tracked {
    let ids: Vec<ObjectId> = vec![fixture.coin.id, fixture.small.id, fixture.cap.id];
    let keys: Vec<Vec<u8>> = vec![
        instance_record_key(
            protocol().chain_id(),
            &fixture.instance.creator,
            &fixture.instance.seed,
        )
        .unwrap(),
        instance_record_key(protocol().chain_id(), &sender(), &[50; 32]).unwrap(),
        paid_fee_policy_key(&protocol()).unwrap(),
        execution_policy_key_for_profile(&protocol(), 4).unwrap(),
        publication::publication_record_key(&fixture.origin).unwrap(),
        publication::publication_record_key(extra_origin).unwrap(),
        PersistenceLayout::new(protocol().chain_id().clone(), protocol().protocol_version())
            .sender_nonce_key(sender(), protocol().epoch()),
    ]
    .into_iter()
    .chain(ids.iter().map(|id| object_authority_key(*id)))
    .collect();
    Tracked {
        states: keys
            .iter()
            .map(|key| {
                store
                    .get_versioned_durable(operation, domain(), key)
                    .unwrap()
            })
            .collect(),
        heads: ids
            .iter()
            .map(|id| store.get_object_head(operation, domain(), *id).unwrap())
            .collect(),
        bodies: ids
            .iter()
            .flat_map(|id| (1..=4u64).map(move |version| (*id, version)))
            .map(|(id, version)| {
                store
                    .get_object_version(
                        operation,
                        domain(),
                        id,
                        DurableObjectVersion::new(version).unwrap(),
                    )
                    .unwrap()
            })
            .collect(),
        receipts: (1..=12u8)
            .map(|request| {
                store
                    .get_request_receipt(
                        operation,
                        domain(),
                        DurableRequestId::new([request; 32]).unwrap(),
                    )
                    .unwrap()
            })
            .collect(),
    }
}

fn memory_store() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap())
}

// ── regressions ─────────────────────────────────────────────────────────

#[test]
fn successful_paid_call_charges_the_fee_and_advances_the_source_once() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let bytes: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE);
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    let charged = result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
    // The same original source funded both phases and advanced exactly once.
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.coin.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        fixture.coin.version + 1
    );
    // Both settlement outputs are durable, distinct, freshly created objects.
    let fee_head = store
        .get_object_head(&context(), domain(), charged.fee_output.id)
        .unwrap();
    assert_eq!(fee_head.object_version().unwrap().get(), 1);
    let refund_reference = charged.refund_output.as_ref().unwrap();
    assert_ne!(refund_reference.id, charged.fee_output.id);
    assert_eq!(
        store
            .get_object_head(&context(), domain(), refund_reference.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        1
    );
    // Each fresh output carries its own immutable authority row.
    for id in [charged.fee_output.id, refund_reference.id] {
        assert!(
            store
                .get_versioned_durable(&context(), domain(), &object_authority_key(id))
                .unwrap()
                .value()
                .is_some()
        );
    }
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
    assert_eq!(engine.calls.get(), 1);

    // Exact replay: no reexecution, no recharge, no reapplication, even with
    // the installed policies and the fee instance deliberately removed and
    // every blob read denied.
    for key in [
        paid_fee_policy_key(&protocol()).unwrap(),
        execution_policy_key_for_profile(&protocol(), 4).unwrap(),
        instance_record_key(
            protocol().chain_id(),
            &fixture.instance.creator,
            &fixture.instance.seed,
        )
        .unwrap(),
    ] {
        set_state(&store, key, StateMutation::Delete);
    }
    let replayed: NodeOutput = run(
        &store,
        &DeniedBlobStore,
        &context(),
        &fixture.policy,
        &engine,
        &bytes,
    )
    .unwrap();
    assert_eq!(replayed, output);
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

#[test]
fn application_trap_charges_only_the_fee_and_reverts_application_effects() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let before_cap: DurableObjectHead = store
        .get_object_head(&context(), domain(), fixture.cap.id)
        .unwrap();
    let bytes: Vec<u8> = trapping_mint_call(&fixture, 5, FIRST_PAID_NONCE);
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::ApplicationFailed);
    let charged = result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    // The application's own TreasuryCap write was discarded; only the fee
    // source and the settlement outputs changed.
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.cap.id)
            .unwrap(),
        before_cap
    );
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.coin.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        fixture.coin.version + 1
    );
    assert!(result.effects.events.is_empty());
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

#[test]
fn zero_charge_reservation_failure_commits_only_the_nonce_and_receipt() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let other: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [60; 32]).unwrap();
    let before: Tracked = tracked(&store, &context(), &fixture, &other);
    // The 400-unit Coin cannot fund the worst-case reservation, so the pinned
    // contract's `reserve` traps: zero charge, no effects.
    let bytes: Vec<u8> = paid_call(PaidCall {
        fixture: &fixture,
        policy: &fixture.policy,
        request: 5,
        nonce: FIRST_PAID_NONCE,
        source: &fixture.small,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.small, AccessMode::Write)],
    });
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::ReservationFailed);
    assert!(result.charged.is_none());
    assert!(result.effects.object_effects.is_empty());
    assert!(result.effects.events.is_empty());
    let after: Tracked = tracked(&store, &context(), &fixture, &other);
    // Only the nonce row and the new receipt differ.
    assert_eq!(after.heads, before.heads);
    assert_eq!(after.bodies, before.bodies);
    assert_eq!(after.states[..6], before.states[..6]);
    assert_eq!(after.states[7..], before.states[7..]);
    assert_ne!(after.states[6], before.states[6]);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
    // Replay still returns the same zero-charge receipt without reexecuting.
    assert_eq!(
        run(
            &store,
            &DeniedBlobStore,
            &context(),
            &fixture.policy,
            &engine,
            &bytes
        )
        .unwrap(),
        output
    );
    assert_eq!(engine.calls.get(), 1);
}

#[test]
fn paid_instantiate_writes_its_record_only_on_success() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let key: Vec<u8> = instance_record_key(protocol().chain_id(), &sender(), &[50; 32]).unwrap();
    // A zero-charge reservation failure must not reserve the instance.
    let failing: Vec<u8> = paid_instantiate(&fixture, 5, FIRST_PAID_NONCE, 50, &fixture.small);
    let output: NodeOutput = execute(&store, &fixture, &engine, &failing).unwrap();
    assert_eq!(
        receipt(&output).status,
        PaidExecutionStatus::ReservationFailed
    );
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value()
            .is_none()
    );
    // The successful invocation commits the record atomically with its fee.
    let bytes: Vec<u8> = paid_instantiate(&fixture, 6, FIRST_PAID_NONCE + 1, 50, &fixture.coin);
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    let PaidResultTarget::Instance(record) = &result.target else {
        panic!("instantiate target");
    };
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value(),
        Some(encode_instance_record(record).unwrap().as_slice())
    );
    assert_eq!(
        query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            sender(),
            [50; 32],
        )
        .unwrap()
        .as_ref(),
        Some(record)
    );
    // A second Instantiate of the same seed is rejected before execution.
    let repeat: Vec<u8> = paid_instantiate(&fixture, 7, FIRST_PAID_NONCE + 2, 50, &fixture.coin);
    assert!(matches!(
        execute(&store, &fixture, &engine, &repeat),
        Err(PaidExecutionAdmissionError::Invalid(
            "instance already reserved"
        ))
    ));
}

#[test]
fn paid_publish_stores_its_signed_frame_and_loads_as_a_verified_dependency() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let artifact: CodeArtifact = publish_artifact(20);
    let origin: PackageOrigin = artifact.origin().clone();
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        5,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        100_000,
    );
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(result.target, PaidResultTarget::Package(origin.clone()));
    // The stored record is the complete canonical signed paid frame.
    assert_eq!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &publication::publication_record_key(&origin).unwrap()
            )
            .unwrap()
            .value(),
        Some(bytes.as_slice())
    );
    // It loads as a verified dependency, with paid provenance, and the legacy
    // submission-shaped query fails closed rather than synthesizing one.
    let loaded = publication::load_verified_publication(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &origin,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        loaded.record,
        publication::VerifiedPublicationRecord::Paid {
            request_id: [5; 32]
        }
    );
    assert!(loaded.record.submission().is_none());
    assert_eq!(loaded.interface.candidate().artifact().origin(), &origin);
    assert!(matches!(
        publication::query_publication(&store, &context(), domain(), &resolver(), &origin),
        Err(PublicationAdmissionError::UnsupportedRecordProvenance)
    ));
    // The legacy publication path cannot reuse a paid origin.
    assert!(matches!(
        publication::query_publication(&store, &context(), domain(), &resolver(), &fixture.origin),
        Ok(Some(_))
    ));
}

#[test]
fn failed_paid_publish_stores_no_record_and_an_unbacked_frame_never_loads() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let artifact: CodeArtifact = publish_artifact(21);
    let origin: PackageOrigin = artifact.origin().clone();
    let key: Vec<u8> = publication::publication_record_key(&origin).unwrap();
    // A zero-charge reservation failure publishes nothing.
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        5,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.small,
        100_000,
    );
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    assert_eq!(
        receipt(&output).status,
        PaidExecutionStatus::ReservationFailed
    );
    assert!(
        store
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap()
            .value()
            .is_none()
    );
    // Planting those exact signed bytes at the immutable origin key is not
    // publication: the committed receipt for that request is not a successful
    // paid Publish, so the loader refuses to grant dependency authority.
    set_state(&store, key.clone(), StateMutation::Put(bytes));
    assert!(matches!(
        publication::load_verified_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &origin
        ),
        Err(PublicationAdmissionError::CorruptRecord)
    ));
    // A paid frame with no committed receipt at all also fails closed.
    let other: CodeArtifact = publish_artifact(22);
    let other_origin: PackageOrigin = other.origin().clone();
    let unbacked: Vec<u8> = paid_publish(
        &fixture,
        9,
        FIRST_PAID_NONCE + 5,
        other,
        &fixture.coin,
        100_000,
    );
    set_state(
        &store,
        publication::publication_record_key(&other_origin).unwrap(),
        StateMutation::Put(unbacked),
    );
    assert!(matches!(
        publication::load_verified_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &other_origin
        ),
        Err(PublicationAdmissionError::CorruptRecord)
    ));
}

#[test]
fn an_exhausted_paid_publish_charges_the_fee_and_still_stores_no_record() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let artifact: CodeArtifact = publish_artifact(26);
    let origin: PackageOrigin = artifact.origin().clone();
    // The deterministic artifact-byte/closure-node units exceed this signed
    // application limit, so the publication is suppressed and the whole limit
    // is charged.
    let bytes: Vec<u8> = paid_publish(
        &fixture,
        5,
        FIRST_PAID_NONCE,
        artifact,
        &fixture.coin,
        1_000,
    );
    let output: NodeOutput = execute(&store, &fixture, &engine, &bytes).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    let result: PaidExecutionResult = receipt(&output);
    assert_eq!(result.status, PaidExecutionStatus::ApplicationFailed);
    let charged = result.charged.as_ref().unwrap();
    assert_eq!(charged.application_gas_units, 1_000);
    assert!(charged.actual.get() > 0);
    assert!(
        store
            .get_versioned_durable(
                &context(),
                domain(),
                &publication::publication_record_key(&origin).unwrap()
            )
            .unwrap()
            .value()
            .is_none()
    );
    // The charged fee still committed against the same original source.
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.coin.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        fixture.coin.version + 1
    );
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

#[test]
fn unknown_and_malformed_stored_publication_frames_fail_closed() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [23; 32]).unwrap();
    let key: Vec<u8> = publication::publication_record_key(&origin).unwrap();
    // A canonical frame of a wholly unrelated type is not a publication.
    let unrelated: Vec<u8> = encode_paid_fee_policy(&fixture.policy).unwrap();
    for planted in [unrelated, vec![0u8; 16], vec![]] {
        set_state(&store, key.clone(), StateMutation::Put(planted));
        assert!(
            publication::load_verified_publication(
                &store,
                &context(),
                domain(),
                &resolver(),
                &[],
                &origin
            )
            .is_err()
        );
    }
}

#[test]
fn absent_or_different_installed_policies_reject_before_execution() {
    for (key, replacement) in [
        (paid_fee_policy_key(&protocol()).unwrap(), None),
        (
            execution_policy_key_for_profile(&protocol(), 4).unwrap(),
            None,
        ),
        (
            execution_policy_key_for_profile(&protocol(), 4).unwrap(),
            Some(LocalExecutionPolicy::general(protocol()).encode().unwrap()),
        ),
    ] {
        let store: MemoryDurableStateStore = memory_store();
        let fixture: Fixture = install(&store);
        let engine: CountingEngine = CountingEngine::new();
        set_state(
            &store,
            key,
            match replacement {
                Some(bytes) => StateMutation::Put(bytes),
                None => StateMutation::Delete,
            },
        );
        let bytes: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE);
        assert!(matches!(
            execute(&store, &fixture, &engine, &bytes),
            Err(PaidExecutionAdmissionError::Invalid(
                "execution policy absent or different" | "paid fee policy absent or different"
            ))
        ));
        assert_eq!(engine.calls.get(), 0);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
    }
}

#[test]
fn wrong_fee_instance_code_or_source_authority_reject_before_execution() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();

    // (a) A policy pinning an instance that was never created.
    let mut absent: PaidFeePolicy = fixture.policy.clone();
    absent.instance.seed = [77; 32];
    absent.instance.record_digest = resolver()
        .hash_for_purpose(protocol().epoch(), HashPurpose::Object, b"absent-instance")
        .unwrap();
    set_state(
        &store,
        paid_fee_policy_key(&protocol()).unwrap(),
        StateMutation::Put(encode_paid_fee_policy(&absent).unwrap()),
    );
    let bytes: Vec<u8> = paid_call(PaidCall {
        fixture: &fixture,
        policy: &absent,
        request: 5,
        nonce: FIRST_PAID_NONCE,
        source: &fixture.coin,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, AccessMode::Write)],
    });
    assert!(matches!(
        run(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            &absent,
            &engine,
            &bytes
        ),
        Err(PaidExecutionAdmissionError::Invalid("fee instance absent"))
    ));

    // (b) A policy pinning the right instance but another package's code.
    let (other_origin, other_code) = publish_package(&store, 24, 24, FIRST_PAID_NONCE);
    let mut wrong_code: PaidFeePolicy = fixture.policy.clone();
    wrong_code.code = other_code;
    wrong_code.asset_type =
        public_standard_asset::coin_type_tag(&other_origin, &fixture.asset).unwrap();
    wrong_code.reservation_type =
        public_standard_asset::reservation_type_tag(&other_origin, &fixture.asset).unwrap();
    set_state(
        &store,
        paid_fee_policy_key(&protocol()).unwrap(),
        StateMutation::Put(encode_paid_fee_policy(&wrong_code).unwrap()),
    );
    let bytes: Vec<u8> = paid_call(PaidCall {
        fixture: &fixture,
        policy: &wrong_code,
        request: 6,
        nonce: FIRST_PAID_NONCE + 1,
        source: &fixture.coin,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, AccessMode::Write)],
    });
    assert!(matches!(
        run(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            &wrong_code,
            &engine,
            &bytes
        ),
        Err(PaidExecutionAdmissionError::Invalid("pinned fee code"))
    ));

    // (c) An object of the wrong nominal type can never be a fee source.
    set_state(
        &store,
        paid_fee_policy_key(&protocol()).unwrap(),
        StateMutation::Put(encode_paid_fee_policy(&fixture.policy).unwrap()),
    );
    let bytes: Vec<u8> = paid_call(PaidCall {
        fixture: &fixture,
        policy: &fixture.policy,
        request: 7,
        nonce: FIRST_PAID_NONCE + 1,
        source: &fixture.cap,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, AccessMode::Write)],
    });
    assert!(matches!(
        execute(&store, &fixture, &engine, &bytes),
        Err(PaidExecutionAdmissionError::Invalid("fee source authority"))
    ));
    assert_eq!(engine.calls.get(), 0);
    // Only the installed publication in (b) consumed a nonce; every paid
    // rejection above committed nothing.
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 1);
}

#[test]
fn a_foreign_instance_coin_is_never_admitted_as_this_policy_s_fee_source() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    // A second instance of the very same code mints its own Coin. Equal
    // nominal shape is not equal instance authority.
    let other: InstanceRecord = InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [51; 32],
        code: fixture.code.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let initialized: Vec<Object> = install_call(
        &store,
        &other,
        8,
        FIRST_PAID_NONCE,
        "init",
        vec![],
        public_standard_asset::no_arguments().unwrap(),
        vec![],
    );
    let asset: ObjectId = pick(
        &initialized,
        &public_standard_asset::definition_type_tag(&fixture.origin).unwrap(),
    )
    .id;
    let minted: Vec<Object> = install_call(
        &store,
        &other,
        9,
        FIRST_PAID_NONCE + 1,
        "mint",
        vec![public_standard_asset::asset_type_argument(&asset)],
        public_standard_asset::mint_arguments(5_000, &sender()).unwrap(),
        vec![entry(
            &pick(
                &initialized,
                &public_standard_asset::treasury_cap_type_tag(&fixture.origin, &asset).unwrap(),
            ),
            AccessMode::Write,
        )],
    );
    let foreign: Object = pick(
        &minted,
        &public_standard_asset::coin_type_tag(&fixture.origin, &asset).unwrap(),
    );
    let bytes: Vec<u8> = paid_call(PaidCall {
        fixture: &fixture,
        policy: &fixture.policy,
        request: 10,
        nonce: FIRST_PAID_NONCE + 2,
        source: &foreign,
        entrypoint: "transfer",
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        access: vec![entry(&fixture.coin, AccessMode::Write)],
    });
    assert!(execute(&store, &fixture, &engine, &bytes).is_err());
    assert_eq!(engine.calls.get(), 0);
}

#[test]
fn request_id_reuse_changes_no_tracked_byte() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let engine: CountingEngine = CountingEngine::new();
    let other: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [60; 32]).unwrap();
    let bytes: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE);
    execute(&store, &fixture, &engine, &bytes).unwrap();
    let before: Tracked = tracked(&store, &context(), &fixture, &other);
    // Same request ID, different signed bytes: the conflicting request is
    // rejected with `RequestIdReuse` and writes nothing.
    let conflicting: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE + 1);
    assert!(matches!(
        execute(&store, &fixture, &engine, &conflicting),
        Err(PaidExecutionAdmissionError::Node(
            NodeCoreError::RequestIdReuse
        ))
    ));
    assert_eq!(tracked(&store, &context(), &fixture, &other), before);
    assert_eq!(engine.calls.get(), 1);
}

/// Commits a competing write to the installed fee policy while the engine is
/// running, proving every policy read joins the one final fenced CAS.
struct RacingEngine<'a> {
    store: &'a MemoryDurableStateStore,
    policy: PaidFeePolicy,
    inner: LocalWasmExecutionEngine,
}
impl PaidContractEngine for RacingEngine<'_> {
    fn execute_paid(
        &self,
        request: PaidExecutionRequest<'_>,
    ) -> Result<PaidExecutionOutcome, PaidExecutionError> {
        let outcome = self.inner.execute_paid(request)?;
        set_state(
            self.store,
            paid_fee_policy_key(&protocol()).unwrap(),
            StateMutation::Put(encode_paid_fee_policy(&self.policy).unwrap()),
        );
        Ok(outcome)
    }
}

#[test]
fn a_racing_policy_write_rolls_back_objects_nonce_and_receipt() {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let other: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [60; 32]).unwrap();
    let before: Tracked = tracked(&store, &context(), &fixture, &other);
    let bytes: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE);
    let racing: RacingEngine<'_> = RacingEngine {
        store: &store,
        policy: fixture.policy.clone(),
        inner: LocalWasmExecutionEngine::new(),
    };
    let result = handle_paid_execution(
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
        10,
    );
    assert!(matches!(
        result,
        Err(PaidExecutionAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));
    let after: Tracked = tracked(&store, &context(), &fixture, &other);
    assert_eq!(after.heads, before.heads);
    assert_eq!(after.bodies, before.bodies);
    assert_eq!(after.receipts, before.receipts);
    assert_eq!(next_nonce(&store), FIRST_PAID_NONCE);
}

#[test]
fn sqlite_reopen_replays_exactly_and_a_stale_writer_generation_is_fenced() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf =
        std::env::temp_dir().join(format!("paid-durable-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let state_path: std::path::PathBuf = directory.join("state.sqlite");
    let blob_path: std::path::PathBuf = directory.join("blobs.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        protocol().chain_id().clone(),
        ValidatorId::new([4; 32]),
        domain(),
    );
    let blob_store: SqliteBlobStore = SqliteBlobStore::open(&blob_path).unwrap();
    let other: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [60; 32]).unwrap();
    let fixture: Fixture;
    let call_bytes: Vec<u8>;
    let publish_bytes: Vec<u8>;
    let published: PackageOrigin;
    let call_output: NodeOutput;
    let publish_output: NodeOutput;
    let expected: Tracked;
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &state_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        fixture = install(&store);
        let engine: CountingEngine = CountingEngine::new();
        call_bytes = transfer_call(&fixture, 5, FIRST_PAID_NONCE);
        call_output = run(
            &store,
            &blob_store,
            &context(),
            &fixture.policy,
            &engine,
            &call_bytes,
        )
        .unwrap();
        assert_eq!(receipt(&call_output).status, PaidExecutionStatus::Success);
        let artifact: CodeArtifact = publish_artifact(25);
        published = artifact.origin().clone();
        publish_bytes = paid_publish(
            &fixture,
            6,
            FIRST_PAID_NONCE + 1,
            artifact,
            &fixture.small,
            100_000,
        );
        publish_output = run(
            &store,
            &blob_store,
            &context(),
            &fixture.policy,
            &engine,
            &publish_bytes,
        )
        .unwrap();
        assert_eq!(
            receipt(&publish_output).status,
            PaidExecutionStatus::ReservationFailed
        );
        assert_eq!(engine.calls.get(), 2);
        expected = tracked(&store, &context(), &fixture, &other);
        assert_eq!(next_nonce(&store), FIRST_PAID_NONCE + 2);

        // Same-boot exact replay: no reexecution, no recharge, no reapply.
        for bytes in [&call_bytes, &publish_bytes] {
            let replayed: NodeOutput = run(
                &store,
                &DeniedBlobStore,
                &context(),
                &fixture.policy,
                &engine,
                bytes,
            )
            .unwrap();
            assert_eq!(
                &replayed,
                if std::ptr::eq(bytes, &call_bytes) {
                    &call_output
                } else {
                    &publish_output
                }
            );
        }
        assert_eq!(engine.calls.get(), 2);
        // A conflicting request ID leaves every tracked byte unchanged.
        let conflicting: Vec<u8> = transfer_call(&fixture, 5, FIRST_PAID_NONCE + 2);
        assert!(matches!(
            run(
                &store,
                &blob_store,
                &context(),
                &fixture.policy,
                &engine,
                &conflicting
            ),
            Err(PaidExecutionAdmissionError::Node(
                NodeCoreError::RequestIdReuse
            ))
        ));
        assert_eq!(tracked(&store, &context(), &fixture, &other), expected);
        assert!(
            store
                .get_versioned_durable(
                    &context(),
                    domain(),
                    &publication::publication_record_key(&published).unwrap()
                )
                .unwrap()
                .value()
                .is_none()
        );
        store
            .advance_writer_fence(
                WriterFenceGeneration::new(1).unwrap(),
                WriterFenceGeneration::new(2).unwrap(),
            )
            .unwrap();
    }
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &state_path,
            namespace,
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.writer_fence().unwrap(),
            WriterFenceGeneration::new(2).unwrap()
        );
        let engine: CountingEngine = CountingEngine::new();
        // The stale generation-one writer is fenced out even for a replay.
        assert!(
            run(
                &store,
                &DeniedBlobStore,
                &context(),
                &fixture.policy,
                &engine,
                &call_bytes
            )
            .is_err()
        );
        // Post-restart exact replay under the current generation.
        for (bytes, output) in [
            (&call_bytes, &call_output),
            (&publish_bytes, &publish_output),
        ] {
            assert_eq!(
                &run(
                    &store,
                    &DeniedBlobStore,
                    &generation(2),
                    &fixture.policy,
                    &engine,
                    bytes
                )
                .unwrap(),
                output
            );
        }
        assert_eq!(engine.calls.get(), 0);
        assert_eq!(tracked(&store, &generation(2), &fixture, &other), expected);
    }
    std::fs::remove_dir_all(directory).unwrap();
}
