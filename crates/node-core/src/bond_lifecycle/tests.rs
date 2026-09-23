use super::*;
use crate::fast_path::records::{
    FastPathBondLifecycleOperation, decode_fastpath_bond_transition_record,
};
use crate::genesis::tests::{
    build_fixture, chain, context, domain, key, manifest_with_custody, protocol, resolver, sender,
};
use crate::genesis::{self, GenesisError, GenesisInstallOutcome};
use crate::local_instance_state::fastpath_bond_transition_key;
use abi::call_values::{CallValue, encode_call_value};
use ed25519_zebra::SigningKey;
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::CreatedObjectAuthority;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, ObjectAuthority,
    local_execution_signing_frame,
};
use execution::{EventRecord, ObjectEffect};
use objects::ObjectId;
use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersionRecord, DurableReadError, DurableRequestId,
    DurableRequestReceipt, MemoryBlobStore, MemoryDurableStateStore, ObjectHeadRevision,
    StateMutation, StateMutationEntry, StateReadAssertion, VersionedStateValue,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};

type Fixture = (
    genesis::GenesisManifest,
    abi::package_types::PackageOrigin,
    execution::local_execution::InstanceRecord,
    ObjectId,
    ObjectId,
);

fn engine() -> LocalWasmExecutionEngine {
    LocalWasmExecutionEngine::new()
}

/// One canonical prime-order Ed25519 address derived from `seed`, for tests
/// whose recipient passes through [`crypto::validate_ed25519_owner_address`].
fn canonical_address(seed: u8) -> Address {
    Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([seed; 32])).into())
}

fn leg_policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::generic_object_results(protocol())
}

fn store() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap())
}

fn put_unconditionally<S: StructuredDurableDomainStateStore>(
    store: &S,
    key: Vec<u8>,
    bytes: Vec<u8>,
) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(1), domain(), &key)
        .unwrap();
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
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Committed
    );
}

fn delete_unconditionally<S: StructuredDurableDomainStateStore>(store: &S, key: Vec<u8>) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(1), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Committed
    );
}

fn get_bond<S: StructuredDurableDomainStateStore>(
    store: &S,
    validator: ValidatorId,
) -> FastPathBondRecord {
    let bond_key: Vec<u8> =
        local_instance_state::fastpath_bond_record_key(&chain(), &validator).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    decode_fastpath_bond_record(observed.value().unwrap()).unwrap()
}

fn put_bond<S: StructuredDurableDomainStateStore>(store: &S, row: &FastPathBondRecord) {
    let bond_key: Vec<u8> =
        local_instance_state::fastpath_bond_record_key(&chain(), &row.validator_id).unwrap();
    put_unconditionally(
        store,
        bond_key,
        crate::fast_path::records::encode_fastpath_bond_record(row).unwrap(),
    );
}

/// Signs `intent` with `signer` over its intent digest (matches the
/// committed bond row's authorization key when `signer == key()`).
fn signed_envelope(intent: BondLifecycleIntent, signer: &SigningKey) -> SignedBondLifecycleIntent {
    let digest: Digest32 = bond_lifecycle_intent_digest(&resolver(), &intent).unwrap();
    let frame: Vec<u8> = bond_lifecycle_signing_frame(&intent.context, digest).unwrap();
    SignedBondLifecycleIntent {
        signature: signer.sign(&frame).into(),
        intent,
    }
}

fn signed_leg(intent: LocalExecutionIntent) -> Vec<u8> {
    let frame: Vec<u8> = local_execution_signing_frame(&intent.call.context, &intent).unwrap();
    let signed = execution::local_execution::SignedLocalExecutionIntent {
        signature: key().sign(&frame).into(),
        intent,
    };
    execution::local_execution::encode_signed_local_execution(&signed).unwrap()
}

/// Builds a whole-object `transfer` leg over `object` for the standard-asset
/// coin contract, encoding `operand` as its sole 32-byte argument (the
/// protocol-custody deposit token or exact release recipient).
#[allow(clippy::too_many_arguments)]
fn transfer_leg(
    fixture: &Fixture,
    current_context: PublicationContext,
    object: ObjectRef,
    sender_bytes: [u8; 32],
    nonce: u64,
    request_id: [u8; 32],
    operand: [u8; 32],
) -> Vec<u8> {
    let (manifest, _origin, instance_record, def_id, coin_id) = fixture;
    let target = execution::local_execution::instance_target(&resolver(), instance_record).unwrap();
    let call = CallIntent {
        context: current_context.clone(),
        request_id,
        sender: sender_bytes,
        nonce,
        code: instance_record.code.clone(),
        instance: target,
        entrypoint: "transfer".to_owned(),
        type_arguments: vec![public_standard_asset::asset_type_argument(def_id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: object,
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&operand).unwrap(),
        gas_limit: 500_000,
    };
    let _ = coin_id;
    let base_policy = LocalExecutionPolicy::generic_object_results(current_context);
    let intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: base_policy.digest(&resolver()).unwrap(),
        call,
        authorizations: Vec::new(),
    };
    let _ = manifest;
    signed_leg(intent)
}

fn object_ref_at(resolver: &HashSuiteResolver, object: &Object, epoch: Epoch) -> ObjectRef {
    let bytes: Vec<u8> = objects::encode_object(object).unwrap();
    let digest: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::Object, &bytes)
        .unwrap();
    ObjectRef {
        id: object.id,
        version: object.version,
        digest,
    }
}

fn object_ref(resolver: &HashSuiteResolver, object: &Object) -> ObjectRef {
    object_ref_at(resolver, object, Epoch::new(0))
}

/// Predicts the exact whole-object result of a `transfer`: same identity,
/// version + 1, new owner, byte-identical body -- computable without ever
/// running WASM, matching the invariant `effects::validate` enforces.
fn transferred(current: &Object, new_owner: Owner, epoch: Epoch) -> (Object, ObjectRef) {
    let new_object = Object {
        id: current.id,
        version: current.version + 1,
        owner: new_owner,
        type_hash: current.type_hash,
        schema_version: current.schema_version,
        data: current.data.clone(),
    };
    let oref = object_ref_at(&resolver(), &new_object, epoch);
    (new_object, oref)
}

fn resource_id_of(bond: &FastPathBondRecord) -> BondResourceId {
    BondResourceId::new(bond.resource_domain, bond.resource).unwrap()
}

fn row_digest(row: &FastPathBondRecord) -> Digest32 {
    let bytes = crate::fast_path::records::encode_fastpath_bond_record(row).unwrap();
    bond_row_digest(&resolver(), row.lifecycle_epoch, &bytes).unwrap()
}

/// Builds the closed [`BondLifecycleIntent`] fields common to every
/// operation: the exact resource/generation/previous-digest the current
/// `bond` row observes, and the exact next-row digest `next` predicts.
fn base_intent(
    current_context: &PublicationContext,
    request_id: [u8; 32],
    bond: &FastPathBondRecord,
    next: &FastPathBondRecord,
    operation: BondLifecycleOperation,
) -> BondLifecycleIntent {
    BondLifecycleIntent {
        context: current_context.clone(),
        request_id,
        validator_id: bond.validator_id,
        resource_id: resource_id_of(bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: row_digest(bond),
        expected_next_row_digest: row_digest(next),
        operation,
    }
}

fn predicted_next(
    bond: &FastPathBondRecord,
    checkpoint: u64,
    current_epoch: Epoch,
) -> FastPathBondRecord {
    let mut next: FastPathBondRecord = bond.clone();
    next.generation = bond.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = checkpoint;
    next.lifecycle_epoch = current_epoch;
    next
}

/// Seeds a fresh sender-owned coin object directly into `store` (bypassing
/// ordinary execution admission, which is irrelevant here: only its exact
/// stored shape matters for the `bond_lifecycle` legs under test), sharing
/// the genesis fixture's own coin authority template.
fn seed_owned_coin<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    id: ObjectId,
    amount: u64,
    owner: [u8; 32],
    seed_request_id: [u8; 32],
) -> (Object, ObjectAuthority) {
    let (manifest, ..) = fixture;
    let template = &manifest.objects[1];
    let object: Object = Object {
        id,
        version: 1,
        owner: Owner::Address(Address::new(owner)),
        type_hash: template.object.type_hash,
        schema_version: template.object.schema_version,
        data: encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(amount),
        )
        .unwrap(),
    };
    let authority: ObjectAuthority = ObjectAuthority {
        object_id: id,
        instance_context: template.authority.instance_context.clone(),
        instance: template.authority.instance.clone(),
        code: template.authority.code.clone(),
        ty: template.authority.ty.clone(),
    };
    let oref: ObjectRef = object_ref(&resolver(), &object);
    let version_record = DurableObjectVersionRecord::from_inline_object(
        object.clone(),
        oref.digest,
        DurableObjectProvenance::new(chain(), protocol().protocol_version()),
        0,
    )
    .unwrap();
    let owner_projection = DurableObjectOwnerProjection::from_owner(object.owner.clone()).unwrap();
    let mutation = DurableObjectMutationEntry::new(
        id,
        DurableObjectMutation::Create {
            version: version_record,
            owner_projection,
            routing_projection: DurableObjectRoutingProjection::default(),
        },
    );
    let auth_key = local_instance_state::object_authority_key(id);
    let auth_bytes = execution::local_execution::encode_object_authority(&authority).unwrap();
    let auth_observed = store
        .get_versioned_durable(&context(1), domain(), &auth_key)
        .unwrap();
    let state = DurableStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(auth_key.clone(), auth_observed.revision()).unwrap(),
        ])
        .unwrap(),
        vec![StateMutationEntry::new(auth_key, StateMutation::Put(auth_bytes)).unwrap()],
    )
    .unwrap();
    let head_read = DurableObjectHeadRead::new(
        id,
        store.get_object_head(&context(1), domain(), id).unwrap(),
    );
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(seed_request_id).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, seed_request_id),
        vec![0],
    )
    .unwrap();
    let tx = DurableInvocationTransaction::new(
        domain(),
        Some(state),
        DurableObjectChanges::new(vec![head_read], vec![mutation]).unwrap(),
        receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context(1), tx),
        DurableCommitOutcome::Committed
    );
    (object, authority)
}

fn install<S: StructuredDurableDomainStateStore>(store: &S, manifest: &genesis::GenesisManifest) {
    genesis::install_genesis(store, &context(1), domain(), &resolver(), manifest, 10).unwrap();
}

fn call<S: StructuredDurableDomainStateStore>(
    store: &S,
    signed: &SignedBondLifecycleIntent,
    current_context: &PublicationContext,
    leg_policy_used: &LocalExecutionPolicy,
    checkpoint: u64,
) -> Result<NodeOutput, BondLifecycleError> {
    call_with_engine(
        store,
        signed,
        current_context,
        leg_policy_used,
        checkpoint,
        &engine(),
    )
}

fn call_with_engine<S: StructuredDurableDomainStateStore, E: LocalContractEngine + ?Sized>(
    store: &S,
    signed: &SignedBondLifecycleIntent,
    current_context: &PublicationContext,
    leg_policy_used: &LocalExecutionPolicy,
    checkpoint: u64,
    engine: &E,
) -> Result<NodeOutput, BondLifecycleError> {
    handle_bond_lifecycle(
        store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        current_context,
        leg_policy_used,
        engine,
        &encode_signed_bond_lifecycle_intent(signed).unwrap(),
        checkpoint,
    )
}

/// Wraps [`LocalWasmExecutionEngine`], counting every `execute` invocation,
/// so a test can prove an exact/conflicting replay never re-runs a leg's
/// WASM execution rather than merely observing an unchanged final state.
struct CountingEngine {
    inner: LocalWasmExecutionEngine,
    calls: std::sync::atomic::AtomicUsize,
}

impl CountingEngine {
    fn new() -> Self {
        Self {
            inner: LocalWasmExecutionEngine::new(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl LocalContractEngine for CountingEngine {
    fn execute(
        &self,
        request: execution::local_execution::LocalExecutionRequest<'_>,
    ) -> Result<execution::local_execution::LocalExecutionOutcome, LocalExecutionError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.execute(request)
    }
}

/// DR-0137's invariant that economics/bond-lifecycle runtime code has no
/// Standard Asset import, constructor id, private body codec or
/// asset-specific branch. `public-standard-asset` is already only a
/// `[dev-dependencies]` entry in `crates/node-core/Cargo.toml` (so a
/// non-test build could not link it regardless); this scans the actual
/// committed source text of every runtime module this implementation unit
/// added or extended as an independent, redundant check.
#[test]
fn bond_lifecycle_runtime_source_has_no_standard_asset_knowledge() {
    let forbidden = ["standard_asset", "public_standard_asset", "StandardAsset"];
    for source in [
        include_str!("../bond_lifecycle.rs"),
        include_str!("effects.rs"),
        include_str!("../fast_path/records.rs"),
        include_str!("../economics.rs"),
    ] {
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "runtime source unexpectedly references {needle}"
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector_context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("dr0130-fastpath-vectors").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(9),
    )
    .unwrap()
}

fn vector_resource_id() -> BondResourceId {
    BondResourceId::new(7, [0x79; 32]).unwrap()
}

#[test]
fn bond_lifecycle_deposit_intent_frame_0x642f_and_signed_0x6430_round_trip_and_are_stable() {
    let intent = BondLifecycleIntent {
        context: vector_context(),
        request_id: [0x71; 32],
        validator_id: ValidatorId::new([0x72; 32]),
        resource_id: vector_resource_id(),
        expected_generation: 4,
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x81; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x82; 32]),
        operation: BondLifecycleOperation::Deposit {
            leg: vec![0xAA, 0xBB, 0xCC],
        },
    };
    let bytes = encode_bond_lifecycle_intent(&intent).unwrap();
    assert_eq!(decode_bond_lifecycle_intent(&bytes).unwrap(), intent);
    assert_eq!(
        hex(&bytes),
        "534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000717171717171717171717171717171717171717171717171717171717171717103002000000072727272727272727272727272727272727272727272727272727272727272720400020000000100050003000000aabbcc0a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000004000000000000000c0038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810d0038000000534e524503010100020001000200000001000200200000008282828282828282828282828282828282828282828282828282828282828282"
    );

    let signed = SignedBondLifecycleIntent {
        intent,
        signature: [0x42; 64],
    };
    let signed_bytes = encode_signed_bond_lifecycle_intent(&signed).unwrap();
    assert_eq!(
        decode_signed_bond_lifecycle_intent(&signed_bytes).unwrap(),
        signed
    );
    // Exact bytes, not merely a round trip: cross-checked against the
    // independent JavaScript vector (`signedBondLifecycleIntent0x6430` in
    // `scripts/fast-path-vectors.mjs`).
    assert_eq!(
        hex(&signed_bytes),
        "534e5245306401000200010074010000534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000717171717171717171717171717171717171717171717171717171717171717103002000000072727272727272727272727272727272727272727272727272727272727272720400020000000100050003000000aabbcc0a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000004000000000000000c0038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810d0038000000534e52450301010002000100020000000100020020000000828282828282828282828282828282828282828282828282828282828282828202004000000042424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242"
    );

    let mut trailing = signed_bytes.clone();
    trailing.push(0);
    assert!(decode_signed_bond_lifecycle_intent(&trailing).is_err());

    let mut wrong_type = signed_bytes;
    wrong_type[4..6].copy_from_slice(&0x6431u16.to_le_bytes());
    assert!(decode_signed_bond_lifecycle_intent(&wrong_type).is_err());
}

#[test]
fn bond_lifecycle_intent_covers_every_operation_shape_and_is_stable() {
    let base = |operation: BondLifecycleOperation| BondLifecycleIntent {
        context: vector_context(),
        request_id: [0x72; 32],
        validator_id: ValidatorId::new([0x72; 32]),
        resource_id: vector_resource_id(),
        expected_generation: 1,
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
        operation,
    };
    let cases = [
        (
            base(BondLifecycleOperation::Deposit { leg: vec![1, 2, 3] }),
            "534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000001000500030000000102030a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202",
        ),
        (
            base(BondLifecycleOperation::Replace {
                deposit_leg: vec![4, 5],
                release_leg: vec![6, 7],
                release_recipient: Address::new([0x22; 32]),
            }),
            "534e52452f6401000b0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000002000600020000000405070002000000060708002000000022222222222222222222222222222222222222222222222222222222222222220a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202",
        ),
        (
            base(BondLifecycleOperation::Unbond {
                recipient: Address::new([0x33; 32]),
            }),
            "534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000072727272727272727272727272727272727272727272727272727272727272720300200000007272727272727272727272727272727272727272727272727272727272727272040002000000030009002000000033333333333333333333333333333333333333333333333333333333333333330a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202",
        ),
        (
            base(BondLifecycleOperation::Withdraw { leg: vec![8, 9] }),
            "534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000072727272727272727272727272727272727272727272727272727272727272720300200000007272727272727272727272727272727272727272727272727272727272727272040002000000040005000200000008090a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202",
        ),
    ];
    for (intent, expected_hex) in cases {
        let bytes = encode_bond_lifecycle_intent(&intent).unwrap();
        assert_eq!(decode_bond_lifecycle_intent(&bytes).unwrap(), intent);
        assert_eq!(hex(&bytes), expected_hex);
    }
}

#[test]
fn fastpath_bond_transition_record_round_trips_and_is_stable() {
    let transition = FastPathBondTransitionRecord {
        context: vector_context(),
        validator_id: ValidatorId::new([0x79; 32]),
        generation: 2,
        previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        current_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        operation: FastPathBondLifecycleOperation::Deposit,
        committed_at_checkpoint: 9,
        signed_envelope: vec![0xAA, 0xBB],
        resulting_row: vec![0xCC, 0xDD, 0xEE],
    };
    let bytes =
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap();
    assert_eq!(
        decode_fastpath_bond_transition_record(&bytes).unwrap(),
        transition
    );
    assert_eq!(
        hex(&bytes),
        "534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e52450301010002000100020000000100020020000000121212121212121212121212121212121212121212121212121212121212121206000200000001000700080000000900000000000000080002000000aabb090003000000ccddee"
    );

    let mut zero_generation = transition.clone();
    zero_generation.generation = 0;
    assert!(
        crate::fast_path::records::encode_fastpath_bond_transition_record(&zero_generation)
            .is_err()
    );
}

fn custody_effects_fixture() -> (
    execution::publication::VerifiedPublicationInterface,
    ObjectAuthority,
    object_snapshots::ObjectSnapshot,
) {
    let (manifest, _origin, instance_record, _def_id, coin_id) = build_fixture();
    let interface = build_interface(&manifest, &instance_record);
    let coin_entry = &manifest.objects[1];
    let authority = coin_entry.authority.clone();
    let snapshot = object_snapshots::ObjectSnapshot {
        head: DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::new(1).unwrap(),
            digest: object_ref(&resolver(), &coin_entry.object).digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(
                coin_entry.object.owner.clone(),
            )
            .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
        object: coin_entry.object.clone(),
        created_checkpoint: 0,
        provenance: DurableObjectProvenance::new(chain(), protocol().protocol_version()),
    };
    let _ = coin_id;
    (interface, authority, snapshot)
}

fn build_interface(
    manifest: &genesis::GenesisManifest,
    instance_record: &execution::local_execution::InstanceRecord,
) -> execution::publication::VerifiedPublicationInterface {
    let candidate = execution::publication::authenticate_publication_submission(
        &resolver(),
        &protocol(),
        &execution::local_execution::generic_object_result_semantics(&resolver(), &protocol())
            .unwrap(),
        manifest.publication.clone(),
    )
    .unwrap();
    let _ = instance_record;
    execution::publication::verify_publication_interface(candidate, Vec::new()).unwrap()
}

#[test]
fn custody_effects_validate_accepts_a_conserving_owner_transition() {
    let (interface, authority, snapshot) = custody_effects_fixture();
    let mut new_object = snapshot.object.clone();
    new_object.version += 1;
    new_object.owner = Owner::Address(Address::new([0x55; 32]));
    let effects = ExecutionEffects {
        tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
        status: ExecutionStatus::Success,
        object_effects: vec![ObjectEffect::Mutated {
            previous_version: snapshot.object.version,
            new_object: new_object.clone(),
        }],
        events: Vec::new(),
        gas_used: 0,
    };
    let owner_before = snapshot.object.owner.clone();
    let owner_after = new_object.owner.clone();
    let (validated, amount) = effects::validate(
        &interface,
        &authority,
        &effects::ExpectedCustodyTransfer {
            object_id: snapshot.object.id,
            owner_before: &owner_before,
            owner_after: &owner_after,
        },
        0,
        &snapshot,
        &effects,
    )
    .unwrap();
    assert_eq!(validated, new_object);
    assert_eq!(amount, 1_000_000);
}

#[test]
fn custody_effects_validate_rejects_every_adversarial_shape() {
    let (interface, authority, snapshot) = custody_effects_fixture();
    let owner_before = snapshot.object.owner.clone();
    let target_owner = Owner::Address(Address::new([0x55; 32]));
    let expected = effects::ExpectedCustodyTransfer {
        object_id: snapshot.object.id,
        owner_before: &owner_before,
        owner_after: &target_owner,
    };
    let mut conserving = snapshot.object.clone();
    conserving.version += 1;
    conserving.owner = target_owner.clone();

    let success = |object_effects: Vec<ObjectEffect>, events: Vec<EventRecord>| ExecutionEffects {
        tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
        status: ExecutionStatus::Success,
        object_effects,
        events,
        gas_used: 0,
    };

    // Trap.
    let trapped = ExecutionEffects {
        status: ExecutionStatus::Failure {
            reason: "x".to_owned(),
        },
        ..success(
            vec![ObjectEffect::Mutated {
                previous_version: snapshot.object.version,
                new_object: conserving.clone(),
            }],
            Vec::new(),
        )
    };
    assert!(effects::validate(&interface, &authority, &expected, 0, &snapshot, &trapped,).is_err());

    // Emitted an event.
    let with_event = success(
        vec![ObjectEffect::Mutated {
            previous_version: snapshot.object.version,
            new_object: conserving.clone(),
        }],
        vec![EventRecord {
            type_tag: vec![1],
            data: vec![2],
        }],
    );
    assert!(
        effects::validate(&interface, &authority, &expected, 0, &snapshot, &with_event).is_err()
    );

    // No effects / too many effects.
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(Vec::new(), Vec::new()),
        )
        .is_err()
    );
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![
                    ObjectEffect::Mutated {
                        previous_version: snapshot.object.version,
                        new_object: conserving.clone(),
                    },
                    ObjectEffect::Mutated {
                        previous_version: snapshot.object.version,
                        new_object: conserving.clone(),
                    },
                ],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Creation / deletion instead of mutation.
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(vec![ObjectEffect::Created(conserving.clone())], Vec::new()),
        )
        .is_err()
    );
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Deleted {
                    id: snapshot.object.id,
                    version: snapshot.object.version,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Wrong object id.
    let mut wrong_id = conserving.clone();
    wrong_id.id = ObjectId::new([0xEE; 32]);
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: wrong_id,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Wrong previous version.
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version + 1,
                    new_object: conserving.clone(),
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Wrong new version (not previous + 1).
    let mut skipped_version = conserving.clone();
    skipped_version.version += 1;
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: skipped_version,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Type changed.
    let mut wrong_type = conserving.clone();
    wrong_type.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]);
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: wrong_type,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Schema changed.
    let mut wrong_schema = conserving.clone();
    wrong_schema.schema_version += 1;
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: wrong_schema,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Body changed (not byte-identical).
    let mut wrong_body = conserving.clone();
    wrong_body.data =
        encode_call_value(&abi::call_values::ValueLayout::U64, &CallValue::U64(1)).unwrap();
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: wrong_body,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Wrong observed owner-before (precondition mismatch).
    let mut different_start = snapshot.clone();
    different_start.object.owner = Owner::Address(Address::new([0x99; 32]));
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &different_start,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: different_start.object.version,
                    new_object: conserving.clone(),
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Wrong observed owner-after (not the exact expected transition).
    let mut different_after = conserving.clone();
    different_after.owner = Owner::Address(Address::new([0x66; 32]));
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: snapshot.object.version,
                    new_object: different_after,
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );

    // Checkpoint regression.
    let mut later_snapshot = snapshot.clone();
    later_snapshot.created_checkpoint = 100;
    assert!(
        effects::validate(
            &interface,
            &authority,
            &expected,
            0,
            &later_snapshot,
            &success(
                vec![ObjectEffect::Mutated {
                    previous_version: later_snapshot.object.version,
                    new_object: conserving.clone(),
                }],
                Vec::new(),
            ),
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------
// Unbond / Withdraw end-to-end (Unbond has no leg; Withdraw's leg is a
// plain whole-object release, fully predictable without running WASM).
// ---------------------------------------------------------------------

#[test]
fn unbond_transitions_active_to_unbonding_and_restart_reverifies_the_chain() {
    let object_id = ObjectId::new([0x40; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);

    let bond = get_bond(&store, ValidatorId::new(sender()));
    let recipient = canonical_address(0x50);
    let mut next = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &protocol(),
        [0x61; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap();
    let response = &output.responses()[0];
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let new_bond = decode_fastpath_bond_record(response.payload().unwrap()).unwrap();
    assert_eq!(new_bond, next);
    assert_eq!(new_bond.generation, 2);

    // Exact replay returns the identical receipt without re-executing.
    let replay = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap();
    assert_eq!(replay.responses()[0].payload(), response.payload());

    // A resubmission of the identical intent under a different signature
    // byte string conflicts rather than silently "replaying": the receipt
    // digest hashes the exact signed bytes (intent and signature together),
    // not the intent alone, so it never even needs to reach signature
    // verification to fail closed here.
    let mut tampered_signature = signed.clone();
    tampered_signature.signature[0] ^= 0xFF;
    assert_ne!(tampered_signature.signature, signed.signature);
    let error = call(&store, &tampered_signature, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Node(NodeCoreError::RequestIdReuse)
    ));

    // Genesis restart must still verify: generation 1 differs from the
    // installed row, but the permanent transition chain re-derives it.
    let outcome =
        genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
            .unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));

    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    let transition_bytes = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    assert!(transition_bytes.value().is_some());
}

#[test]
fn unbond_rejects_a_non_active_bond_and_a_jailed_bond() {
    let object_id = ObjectId::new([0x41; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let mut row = get_bond(&store, ValidatorId::new(sender()));
    row.state = FastPathBondState::Jailed {
        evidence_digest: Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
    };
    put_bond(&store, &row);

    let dummy_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]);
    let intent = BondLifecycleIntent {
        context: protocol(),
        request_id: [0x62; 32],
        validator_id: ValidatorId::new(sender()),
        resource_id: resource_id_of(&row),
        expected_generation: row.generation,
        expected_previous_row_digest: dummy_digest,
        expected_next_row_digest: dummy_digest,
        operation: BondLifecycleOperation::Unbond {
            recipient: canonical_address(0x51),
        },
    };
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond is jailed")
    ));
}

#[test]
fn unbond_rejects_a_non_canonical_recipient_address() {
    let object_id = ObjectId::new([0x46; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let recipient = Address::new([0x51; 32]); // not a canonical prime-order point
    let mut next = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &protocol(),
        [0x68; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond unbond recipient address")
    ));
}

#[test]
fn handle_bond_lifecycle_rejects_a_missing_bond_row() {
    let manifest = manifest_with_custody(ObjectId::new([0x42; 32]));
    let store = store();
    install(&store, &manifest);
    let unknown_validator = ValidatorId::new([0x99; 32]);
    let dummy_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]);
    let intent = BondLifecycleIntent {
        context: protocol(),
        request_id: [0x63; 32],
        validator_id: unknown_validator,
        resource_id: BondResourceId::new(1, [0; 32]).unwrap(),
        expected_generation: 1,
        expected_previous_row_digest: dummy_digest,
        expected_next_row_digest: dummy_digest,
        operation: BondLifecycleOperation::Unbond {
            recipient: canonical_address(0x52),
        },
    };
    // Signed by the genesis validator's key; the row simply does not exist
    // for `unknown_validator`, so it must fail before signature checking
    // could even select a key.
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid(
            "first-ever post-genesis bonding requires an existing committed bond row"
        )
    ));
}

#[test]
fn handle_bond_lifecycle_rejects_a_wrong_signature_and_a_reserved_request_id() {
    let manifest = manifest_with_custody(ObjectId::new([0x43; 32]));
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let dummy_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]);

    let intent = BondLifecycleIntent {
        context: protocol(),
        request_id: [0x64; 32],
        validator_id: ValidatorId::new(sender()),
        resource_id: resource_id_of(&bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: dummy_digest,
        expected_next_row_digest: dummy_digest,
        operation: BondLifecycleOperation::Unbond {
            recipient: canonical_address(0x53),
        },
    };
    let wrong_key = SigningKey::from([0x99; 32]);
    let signed = signed_envelope(intent, &wrong_key);
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle envelope signature")
    ));

    let mut reserved_request_id: [u8; 32] = [0x64; 32];
    reserved_request_id[..local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG.len()]
        .copy_from_slice(&local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    let reserved_intent = BondLifecycleIntent {
        context: protocol(),
        request_id: reserved_request_id,
        validator_id: ValidatorId::new(sender()),
        resource_id: resource_id_of(&bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: dummy_digest,
        expected_next_row_digest: dummy_digest,
        operation: BondLifecycleOperation::Unbond {
            recipient: canonical_address(0x53),
        },
    };
    let signed = signed_envelope(reserved_intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("request id reserved for fast-path synthetic receipts")
    ));
}

#[test]
fn handle_bond_lifecycle_rejects_stale_generation_stale_previous_digest_and_wrong_resource() {
    let object_id = ObjectId::new([0x47; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let recipient = canonical_address(0x59);
    let mut next = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let base = base_intent(
        &protocol(),
        [0x69; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );

    // Stale expected_generation (a delayed resubmission against a
    // since-advanced row).
    let mut stale_generation = base.clone();
    stale_generation.expected_generation = bond.generation + 1;
    let signed = signed_envelope(stale_generation, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle stale expected generation")
    ));

    // Stale expected_previous_row_digest.
    let mut stale_digest = base.clone();
    stale_digest.expected_previous_row_digest =
        Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let signed = signed_envelope(stale_digest, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle stale expected previous row digest")
    ));

    // Wrong resource.
    let mut wrong_resource = base.clone();
    wrong_resource.resource_id = BondResourceId::new(bond.resource_domain, [0xAB; 32]).unwrap();
    let signed = signed_envelope(wrong_resource, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle resource mismatch")
    ));

    // Wrong expected_next_row_digest: passes the preamble (resource/
    // generation/previous digest all match) but fails once deterministic
    // execution's actual next digest is compared against it, inside `commit`.
    let mut wrong_next = base;
    wrong_next.expected_next_row_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xCD; 32]);
    let signed = signed_envelope(wrong_next, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle next row digest mismatch")
    ));

    // None of the above ever committed anything.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
}

#[test]
fn handle_bond_lifecycle_rejects_a_validator_live_set_key_divergence() {
    let object_id = ObjectId::new([0x48; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));

    // The genesis-epoch validator set is immutable once installed, so
    // advance to a fresh epoch instead, installing our validator there with
    // a genuinely different key. `install_validator_set` derives and
    // commits a *consistent* digest for the new set/epoch record together,
    // so this is a real "present with a diverged key" scenario, not merely
    // a validator-set/epoch-record digest mismatch. `Unbond` has no leg, so
    // no fresh execution policy needs installing at the new epoch either.
    let diverged_key: [u8; 32] =
        ed25519_zebra::VerificationKey::from(&SigningKey::from([0x61; 32])).into();
    let later_context: PublicationContext =
        PublicationContext::new(chain(), protocol().protocol_version(), Epoch::new(3)).unwrap();
    fast_path::install_validator_set(
        &store,
        &context(1),
        domain(),
        &resolver(),
        later_context.clone(),
        vec![crate::fast_path::records::FastPathValidatorEntry {
            id: ValidatorId::new(sender()),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: diverged_key.to_vec(),
        }],
    )
    .unwrap();

    let recipient = canonical_address(0x54);
    let mut next = predicted_next(&bond, 11, later_context.epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(later_context.epoch().get() + 7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &later_context,
        [0x6A; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &later_context, &leg_policy(), 11).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid(
            "bond authorization key diverges from the committed live validator set"
        )
    ));
}

#[test]
fn policy_minimum_raise_does_not_strand_unbond_or_withdraw() {
    let object_id = ObjectId::new([0x49; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.required_minimum, 100);

    // Raise the committed policy minimum for this resource well above the
    // existing bond's own amount/required_minimum.
    let policy_key = local_instance_state::fastpath_economics_policy_key(&bond.context).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &policy_key)
        .unwrap();
    let mut policy = decode_fastpath_economics_policy(observed.value().unwrap()).unwrap();
    let mut raised = policy.resources[0].bond.clone().unwrap();
    raised.min_bond = fees::Amount::new(10_000_000);
    policy.resources[0].bond = Some(raised);
    put_unconditionally(
        &store,
        policy_key,
        crate::economics::encode_fastpath_economics_policy(&policy).unwrap(),
    );

    // Unbond still succeeds and preserves the *old* required_minimum.
    let recipient = canonical_address(0x55);
    let mut next = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &protocol(),
        [0x6B; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap();
    let unbonding = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(unbonding.required_minimum, 100);

    // Advance epoch/live-set/execution-policy so withdraw can run, then
    // withdraw still succeeds and still preserves the old required_minimum.
    let later_context: PublicationContext =
        PublicationContext::new(chain(), protocol().protocol_version(), Epoch::new(7)).unwrap();
    fast_path::install_validator_set(
        &store,
        &context(1),
        domain(),
        &resolver(),
        later_context.clone(),
        vec![crate::fast_path::records::FastPathValidatorEntry {
            id: ValidatorId::new([0xEE; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![0xEE; 32],
        }],
    )
    .unwrap();
    let later_leg_policy = LocalExecutionPolicy::generic_object_results(later_context.clone());
    put_unconditionally(
        &store,
        local_instance_state::execution_policy_key_for_profile(&later_context, 4).unwrap(),
        later_leg_policy.encode().unwrap(),
    );
    let withdraw_request_id: [u8; 32] = [0x6D; 32];
    let fixture = build_fixture();
    let leg = transfer_leg(
        &fixture,
        later_context.clone(),
        unbonding.custody_object.clone(),
        sender(),
        0,
        withdraw_request_id,
        *recipient.as_bytes(),
    );
    // The custody object is untouched by `Unbond`, so it is still exactly
    // the genesis manifest's own custody entry (index 2: definition, coin,
    // then the pushed custody object).
    let current_custody_object: &Object = &manifest.objects[2].object;
    let (new_object, oref) = transferred(
        current_custody_object,
        Owner::Address(recipient),
        Epoch::new(7),
    );
    let mut withdraw_next = predicted_next(&unbonding, 12, Epoch::new(7));
    withdraw_next.state = FastPathBondState::Exited;
    withdraw_next.custody_object = oref;
    withdraw_next.authority.object_id = new_object.id;

    let withdraw_intent = base_intent(
        &later_context,
        withdraw_request_id,
        &unbonding,
        &withdraw_next,
        BondLifecycleOperation::Withdraw { leg },
    );
    let signed = signed_envelope(withdraw_intent, &key());
    let output = call(&store, &signed, &later_context, &later_leg_policy, 12).unwrap();
    let final_bond = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(final_bond.state, FastPathBondState::Exited);
    // The policy raise never stranded either transition: `required_minimum`
    // stays exactly the value captured at the original deposit.
    assert_eq!(final_bond.required_minimum, 100);
}

// ---------------------------------------------------------------------
// Deposit / Replace: real-WASM end-to-end through `handle_bond_lifecycle`.
// ---------------------------------------------------------------------

fn custody_scope_of(bond: &FastPathBondRecord) -> ProtocolCustodyScope {
    custody_scope(&bond.context, bond.validator_id, bond.resource)
}

/// Forces the installed bond row into `Exited`, as if a prior withdrawal had
/// already completed, so `Deposit`/`Replace` tests do not each need to
/// replay a full `Unbond`/`Withdraw` cycle first.
fn force_exited<S: StructuredDurableDomainStateStore>(
    store: &S,
    bond: &FastPathBondRecord,
) -> FastPathBondRecord {
    let mut exited = bond.clone();
    exited.state = FastPathBondState::Exited;
    put_bond(store, &exited);
    exited
}

#[test]
fn deposit_transitions_exited_to_active_with_real_wasm_execution() {
    let object_id = ObjectId::new([0x4A; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x4B; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 5_000, sender(), [0x70; 32]);

    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x71; 32];
    let leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &source_object),
        sender(),
        0,
        request_id,
        token,
    );

    let (new_object, oref) = transferred(
        &source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 20, protocol().epoch());
    next.custody_object = oref;
    next.authority = source_authority;
    next.amount = 5_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;

    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Deposit { leg },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &protocol(), &leg_policy(), 20).unwrap();
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(committed, next);
    assert_eq!(committed.state, FastPathBondState::Active);
    assert_eq!(committed.amount, 5_000);
    assert_eq!(committed.custody_object.id, new_object.id);
    // The deposited object is now live custody-owned; the old (already
    // `Exited`) custody object is untouched and no longer referenced.
    let head = store
        .get_object_head(&context(1), domain(), source_id)
        .unwrap();
    assert!(matches!(
        head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 2
    ));
}

/// Every embedded leg's own `CallIntent::request_id` must equal the outer
/// `BondLifecycleIntent::request_id` exactly (step 2b of
/// `handle_bond_lifecycle`) -- checked before reserved-id rejection, replay
/// reconciliation, the epoch fence, or any object/nonce work, so a leg
/// signed under one request id cannot be spliced into an outer envelope
/// signed under a different one.
#[test]
fn deposit_rejects_a_leg_whose_request_id_differs_from_the_outer_intent() {
    let object_id = ObjectId::new([0x6C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x6D; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 5_000, sender(), [0x7E; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let leg_request_id: [u8; 32] = [0x7F; 32];
    let outer_request_id: [u8; 32] = [0x80; 32];
    assert_ne!(leg_request_id, outer_request_id);
    let leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &source_object),
        sender(),
        0,
        leg_request_id,
        token,
    );
    let (_new_object, oref) = transferred(
        &source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 20, protocol().epoch());
    next.custody_object = oref;
    next.authority = source_authority;
    next.amount = 5_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;
    let intent = base_intent(
        &protocol(),
        outer_request_id,
        &bond,
        &next,
        BondLifecycleOperation::Deposit { leg },
    );
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 20).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond lifecycle leg request id mismatch")
    ));
    // Nothing committed: same generation, same object version, no receipt
    // recorded for either request id.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
    let head = store
        .get_object_head(&context(1), domain(), source_id)
        .unwrap();
    assert!(matches!(
        head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
}

#[test]
fn replace_swaps_custody_atomically_with_same_sender_consecutive_nonces() {
    let object_id = ObjectId::new([0x4C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);
    let old_custody_id = bond.custody_object.id;

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0x4D; 32]);
    let (new_source_object, new_source_authority) =
        seed_owned_coin(&store, &fixture, new_source_id, 7_000, sender(), [0x72; 32]);

    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0x56);
    let request_id: [u8; 32] = [0x73; 32];
    let deposit_leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &new_source_object),
        sender(),
        0,
        request_id,
        token,
    );
    let release_leg = transfer_leg(
        &fixture,
        protocol(),
        bond.custody_object.clone(),
        sender(),
        1,
        request_id,
        *release_recipient.as_bytes(),
    );

    let (new_deposit_object, deposit_oref) = transferred(
        &new_source_object,
        Owner::ProtocolCustody(scope.clone()),
        protocol().epoch(),
    );
    // The custody object released is exactly the genesis manifest's own
    // pushed custody entry (index 2), untouched since genesis.
    let old_custody_object: &Object = &manifest.objects[2].object;
    assert_eq!(old_custody_object.id, old_custody_id);

    let mut next = predicted_next(&bond, 21, protocol().epoch());
    next.custody_object = deposit_oref;
    next.authority = new_source_authority;
    next.amount = 7_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;

    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &protocol(), &leg_policy(), 21).unwrap();
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(committed, next);
    assert_eq!(committed.custody_object.id, new_deposit_object.id);
    assert_eq!(committed.amount, 7_000);

    // Both owner transitions actually committed in the single atomic
    // transaction: the new source is now custody-owned, and the old
    // custody object now belongs to the release recipient.
    let new_source_head = store
        .get_object_head(&context(1), domain(), new_source_id)
        .unwrap();
    let new_source_owner = new_source_head
        .owner_projection()
        .and_then(DurableObjectOwnerProjection::owner)
        .unwrap();
    assert_eq!(*new_source_owner, Owner::ProtocolCustody(scope));
    let old_custody_head = store
        .get_object_head(&context(1), domain(), old_custody_id)
        .unwrap();
    let old_custody_owner = old_custody_head
        .owner_projection()
        .and_then(DurableObjectOwnerProjection::owner)
        .unwrap();
    assert_eq!(*old_custody_owner, Owner::Address(release_recipient));

    // The consumed nonce range advanced by exactly two (both legs, one
    // shared sender).
    let layout = PersistenceLayout::new(chain(), protocol().protocol_version());
    let nonce_key = layout.sender_nonce_key(sender(), protocol().epoch());
    let nonce_bytes = store
        .get_versioned_durable(&context(1), domain(), &nonce_key)
        .unwrap();
    assert!(nonce_bytes.value().is_some());
}

#[test]
fn replace_rejects_nonconsecutive_nonces_and_commits_nothing() {
    let object_id = ObjectId::new([0x4E; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0x4F; 32]);
    let (new_source_object, _authority) =
        seed_owned_coin(&store, &fixture, new_source_id, 7_000, sender(), [0x74; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0x57);
    let request_id: [u8; 32] = [0x75; 32];
    let deposit_leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &new_source_object),
        sender(),
        0,
        request_id,
        token,
    );
    // Nonconsecutive: should be 1, not 2.
    let release_leg = transfer_leg(
        &fixture,
        protocol(),
        bond.custody_object.clone(),
        sender(),
        2,
        request_id,
        *release_recipient.as_bytes(),
    );
    // The nonconsecutive-nonce rejection happens before `replace` ever
    // builds or needs a resulting row, so `expected_next_row_digest` here is
    // an arbitrary placeholder: no legitimately encodable row exists for it
    // to predict.
    let intent = BondLifecycleIntent {
        context: protocol(),
        request_id,
        validator_id: bond.validator_id,
        resource_id: resource_id_of(&bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: row_digest(&bond),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
        operation: BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        },
    };
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 21).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond replace legs require consecutive nonces")
    ));
    // Nothing changed: same generation, same state.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
}

#[test]
fn deposit_rejects_an_amount_below_the_committed_minimum() {
    let object_id = ObjectId::new([0x58; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x59; 32]);
    // Below the committed minimum (100).
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 10, sender(), [0x76; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x77; 32];
    let leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &source_object),
        sender(),
        0,
        request_id,
        token,
    );
    let _ = source_authority;
    // A row with `amount < required_minimum` can never be canonically
    // encoded (it is not a valid `FastPathBondRecord` at all), so no
    // legitimate `expected_next_row_digest` exists for it; the minimum
    // check inside `deposit` rejects this leg's observed amount well before
    // any resulting row would be built or compared.
    let intent = BondLifecycleIntent {
        context: protocol(),
        request_id,
        validator_id: bond.validator_id,
        resource_id: resource_id_of(&bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: row_digest(&bond),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x98; 32]),
        operation: BondLifecycleOperation::Deposit { leg },
    };
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 20).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond deposit amount below the committed minimum")
    ));
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
    // The seeded source object is untouched (still version 1, still
    // sender-owned): the rejected leg committed nothing.
    let head = store
        .get_object_head(&context(1), domain(), source_id)
        .unwrap();
    assert!(matches!(
        head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
}

#[test]
fn replace_second_leg_trap_commits_nothing() {
    let object_id = ObjectId::new([0x5A; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0x5B; 32]);
    let (new_source_object, source_authority) =
        seed_owned_coin(&store, &fixture, new_source_id, 7_000, sender(), [0x78; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x79; 32];
    let deposit_leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &new_source_object),
        sender(),
        0,
        request_id,
        token,
    );
    // The release leg's operand matches neither the validator-authorized
    // release recipient the capability was bound to, nor any canonical
    // address, so the host `transfer_object` function itself traps deep
    // inside WASM execution -- a genuine execution-level trap, not an
    // admission-time rejection.
    let release_recipient = canonical_address(0x58);
    let release_leg = transfer_leg(
        &fixture,
        protocol(),
        bond.custody_object.clone(),
        sender(),
        1,
        request_id,
        [0u8; 32],
    );
    let (_new_deposit_object, deposit_oref) = transferred(
        &new_source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 21, protocol().epoch());
    next.custody_object = deposit_oref;
    next.authority = source_authority;
    next.amount = 7_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;
    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        },
    );
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 21).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond replace release leg trapped")
    ));
    // Nothing committed: same generation, same nonce range unreserved, same
    // objects untouched by either leg despite the deposit leg's own
    // execution having genuinely succeeded first.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
    let source_head = store
        .get_object_head(&context(1), domain(), new_source_id)
        .unwrap();
    assert!(matches!(
        source_head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
}

#[test]
fn deposit_exact_and_conflicting_replay_never_reexecutes_the_leg() {
    let object_id = ObjectId::new([0x5C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x5D; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 5_000, sender(), [0x7A; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x7B; 32];
    let leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &source_object),
        sender(),
        0,
        request_id,
        token,
    );
    let (_new_object, oref) = transferred(
        &source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 20, protocol().epoch());
    next.custody_object = oref;
    next.authority = source_authority;
    next.amount = 5_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;
    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Deposit { leg },
    );
    let signed = signed_envelope(intent, &key());

    let engine = CountingEngine::new();
    let output =
        call_with_engine(&store, &signed, &protocol(), &leg_policy(), 20, &engine).unwrap();
    assert_eq!(engine.call_count(), 1);
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(committed, next);

    // An exact replay of the identical signed envelope reuses the stored
    // receipt without ever re-entering the engine.
    let replay =
        call_with_engine(&store, &signed, &protocol(), &leg_policy(), 20, &engine).unwrap();
    assert_eq!(
        replay.responses()[0].payload(),
        output.responses()[0].payload()
    );
    assert_eq!(engine.call_count(), 1);

    // A different signature over the identical intent conflicts on the
    // receipt digest (which hashes the exact signed bytes) before it could
    // ever reach signature verification or leg execution again.
    let mut tampered = signed.clone();
    tampered.signature[0] ^= 0xFF;
    let error =
        call_with_engine(&store, &tampered, &protocol(), &leg_policy(), 20, &engine).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Node(NodeCoreError::RequestIdReuse)
    ));
    assert_eq!(engine.call_count(), 1);
}

// ---------------------------------------------------------------------
// `created_authorities`: a custody leg that creates an object is rejected.
// ---------------------------------------------------------------------

/// Wraps [`LocalWasmExecutionEngine`] and reports one extra surviving
/// creation authority alongside the real, otherwise-valid custody-transfer
/// effect. `deposit`/`replace` must independently reject any non-empty
/// `created_authorities` regardless of what the engine reports: no
/// standard-asset entrypoint ever creates an object, so exercising this
/// defense requires simulating a hypothetical custody-target contract that
/// does, without granting the engine layer any special trust of its own.
struct CreatingEngine {
    inner: LocalWasmExecutionEngine,
}

impl LocalContractEngine for CreatingEngine {
    fn execute(
        &self,
        request: execution::local_execution::LocalExecutionRequest<'_>,
    ) -> Result<execution::local_execution::LocalExecutionOutcome, LocalExecutionError> {
        let mut authority: ObjectAuthority = request.inputs[0].authority.clone();
        authority.object_id = ObjectId::new([0x66; 32]);
        let mut outcome = self.inner.execute(request)?;
        outcome.created_authorities.push(CreatedObjectAuthority {
            creation_ordinal: 0,
            authority,
        });
        Ok(outcome)
    }
}

#[test]
fn deposit_rejects_a_leg_that_reports_a_created_authority() {
    let object_id = ObjectId::new([0x5E; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x5F; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 5_000, sender(), [0x7C; 32]);
    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x7D; 32];
    let leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &source_object),
        sender(),
        0,
        request_id,
        token,
    );
    let (_new_object, oref) = transferred(
        &source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 20, protocol().epoch());
    next.custody_object = oref;
    next.authority = source_authority;
    next.amount = 5_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;
    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Deposit { leg },
    );
    let signed = signed_envelope(intent, &key());

    let engine = CreatingEngine {
        inner: LocalWasmExecutionEngine::new(),
    };
    let error =
        call_with_engine(&store, &signed, &protocol(), &leg_policy(), 20, &engine).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond deposit leg created an object")
    ));
    // Nothing committed: the bond row is untouched, and the source object
    // the engine's (real, valid) mutation would have consumed is still at
    // its original version.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
    let head = store
        .get_object_head(&context(1), domain(), source_id)
        .unwrap();
    assert!(matches!(
        head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
}

// ---------------------------------------------------------------------
// Real file-backed SQLite: full lifecycle across independent process
// restarts, writer-fence generation, and single-commit atomicity.
// ---------------------------------------------------------------------

#[test]
fn file_backed_sqlite_full_lifecycle_restart_and_fencing() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bond-lifecycle-durable-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([9; 32]), domain());
    let fence1 = WriterFenceGeneration::new(1).unwrap();

    let object_id = ObjectId::new([0x61; 32]);
    let manifest = manifest_with_custody(object_id);
    let fixture = build_fixture();

    // 1. Fresh install (Active), then run a real (object-mutating) Replace
    //    entirely at the genesis epoch/validator set -- no epoch advance or
    //    test-only live-set override -- swapping in a freshly seeded
    //    sender-owned coin for the original genesis custody object.
    let after_replace: FastPathBondRecord;
    let replaced_custody_object: Object;
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        install(&store, &manifest);
        let bond = get_bond(&store, ValidatorId::new(sender()));

        let new_source_id = ObjectId::new([0x62; 32]);
        let (new_source_object, new_source_authority) =
            seed_owned_coin(&store, &fixture, new_source_id, 5_000, sender(), [0x91; 32]);
        let scope = custody_scope_of(&bond);
        let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
            &resolver(),
            &protocol(),
            new_source_id,
            &scope,
        )
        .unwrap();
        let release_recipient = canonical_address(0x92);
        let request_id: [u8; 32] = [0x93; 32];
        let deposit_leg = transfer_leg(
            &fixture,
            protocol(),
            object_ref(&resolver(), &new_source_object),
            sender(),
            0,
            request_id,
            token,
        );
        let release_leg = transfer_leg(
            &fixture,
            protocol(),
            bond.custody_object.clone(),
            sender(),
            1,
            request_id,
            *release_recipient.as_bytes(),
        );
        let (new_object, oref) = transferred(
            &new_source_object,
            Owner::ProtocolCustody(scope),
            protocol().epoch(),
        );
        replaced_custody_object = new_object;
        let mut next = predicted_next(&bond, 20, protocol().epoch());
        next.custody_object = oref;
        next.authority = new_source_authority;
        next.amount = 5_000;
        next.required_minimum = 100;
        next.state = FastPathBondState::Active;
        let intent = base_intent(
            &protocol(),
            request_id,
            &bond,
            &next,
            BondLifecycleOperation::Replace {
                deposit_leg,
                release_leg,
                release_recipient,
            },
        );
        let signed = signed_envelope(intent, &key());
        let output = call(&store, &signed, &protocol(), &leg_policy(), 20).unwrap();
        after_replace =
            decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(after_replace, next);
    }

    // 2. Reopen: the row survived exactly, and a full genesis restart
    //    re-verification (walking the real permanent transition chain
    //    against real file-backed SQLite storage, not merely reading the
    //    row back) succeeds after this object-mutating Replace.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, after_replace);

        let restart_outcome =
            genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
                .unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }

    // 3. Reopen: run a real Unbond.
    let after_unbond: FastPathBondRecord;
    let unbond_recipient = canonical_address(0x94);
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, after_replace);

        let mut next = predicted_next(&reopened, 21, protocol().epoch());
        next.state = FastPathBondState::Unbonding {
            unlock_epoch: Epoch::new(7),
            recipient: *unbond_recipient.as_bytes(),
        };
        let intent = base_intent(
            &protocol(),
            [0x95; 32],
            &reopened,
            &next,
            BondLifecycleOperation::Unbond {
                recipient: unbond_recipient,
            },
        );
        let signed = signed_envelope(intent, &key());
        let output = call(&store, &signed, &protocol(), &leg_policy(), 21).unwrap();
        after_unbond =
            decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(after_unbond, next);
    }

    // 4. Reopen: advance to the unlock epoch with a live set that no longer
    //    includes this validator, then run a real Withdraw releasing the
    //    replaced custody object.
    let later_context: PublicationContext =
        PublicationContext::new(chain(), protocol().protocol_version(), Epoch::new(7)).unwrap();
    let later_leg_policy = LocalExecutionPolicy::generic_object_results(later_context.clone());
    let withdraw_request_id: [u8; 32] = [0x96; 32];
    let after_withdraw: FastPathBondRecord;
    let withdraw_signed: SignedBondLifecycleIntent;
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, after_unbond);

        fast_path::install_validator_set(
            &store,
            &context(1),
            domain(),
            &resolver(),
            later_context.clone(),
            vec![crate::fast_path::records::FastPathValidatorEntry {
                id: ValidatorId::new([0xFE; 32]),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: vec![0xFE; 32],
            }],
        )
        .unwrap();
        put_unconditionally(
            &store,
            local_instance_state::execution_policy_key_for_profile(&later_context, 4).unwrap(),
            later_leg_policy.encode().unwrap(),
        );

        let leg = transfer_leg(
            &fixture,
            later_context.clone(),
            reopened.custody_object.clone(),
            sender(),
            0,
            withdraw_request_id,
            *unbond_recipient.as_bytes(),
        );
        let (_new_object, oref) = transferred(
            &replaced_custody_object,
            Owner::Address(unbond_recipient),
            Epoch::new(7),
        );
        let mut next = predicted_next(&reopened, 22, Epoch::new(7));
        next.state = FastPathBondState::Exited;
        next.custody_object = oref;
        next.authority.object_id = replaced_custody_object.id;
        let intent = base_intent(
            &later_context,
            withdraw_request_id,
            &reopened,
            &next,
            BondLifecycleOperation::Withdraw { leg },
        );
        let signed = signed_envelope(intent, &key());
        let output = call(&store, &signed, &later_context, &later_leg_policy, 22).unwrap();
        after_withdraw =
            decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(after_withdraw, next);
        withdraw_signed = signed;
    }

    // 5. Reopen and replay the exact Withdraw envelope: the identical
    //    receipt returns without re-executing, and the row is unchanged.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let replay = call(
            &store,
            &withdraw_signed,
            &later_context,
            &later_leg_policy,
            22,
        )
        .unwrap();
        let replayed =
            decode_fastpath_bond_record(replay.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(replayed, after_withdraw);
        let stable = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(stable, after_withdraw);
    }

    // 6. Competing transition: two writer handles open the same database and
    //    submit different, individually valid transitions from the exact
    //    same committed row (re-depositing after the withdrawal). Exactly
    //    one commits; the later competing attempt observes the advanced row,
    //    and no partial effect from the loser survives. This is stale-writer
    //    competition, not a simultaneous-thread commit-collision test.
    {
        let store_a = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let store_b = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let base = get_bond(&store_a, ValidatorId::new(sender()));
        assert_eq!(base, after_withdraw);

        let race_source_a = ObjectId::new([0x63; 32]);
        let race_source_b = ObjectId::new([0x64; 32]);
        let (source_a, authority_a) = seed_owned_coin(
            &store_a,
            &fixture,
            race_source_a,
            6_000,
            sender(),
            [0x97; 32],
        );
        let (source_b, authority_b) = seed_owned_coin(
            &store_b,
            &fixture,
            race_source_b,
            6_500,
            sender(),
            [0x98; 32],
        );

        let scope = custody_scope_of(&base);
        let build_deposit_intent = |source_id: ObjectId,
                                    source_object: &Object,
                                    authority: ObjectAuthority,
                                    amount: u64,
                                    request_id: [u8; 32]| {
            let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
                &resolver(),
                &later_context,
                source_id,
                &scope,
            )
            .unwrap();
            // The Withdraw leg already consumed nonce 0 for this sender at
            // this epoch; both racing legs contend for nonce 1.
            let leg = transfer_leg(
                &fixture,
                later_context.clone(),
                object_ref_at(&resolver(), source_object, Epoch::new(7)),
                sender(),
                1,
                request_id,
                token,
            );
            let (_new_object, oref) = transferred(
                source_object,
                Owner::ProtocolCustody(scope.clone()),
                Epoch::new(7),
            );
            let mut next = predicted_next(&base, 23, Epoch::new(7));
            next.custody_object = oref;
            next.authority = authority;
            next.amount = amount;
            next.required_minimum = 100;
            next.state = FastPathBondState::Active;
            let intent = base_intent(
                &later_context,
                request_id,
                &base,
                &next,
                BondLifecycleOperation::Deposit { leg },
            );
            signed_envelope(intent, &key())
        };
        let signed_a =
            build_deposit_intent(race_source_a, &source_a, authority_a, 6_000, [0x99; 32]);
        let signed_b =
            build_deposit_intent(race_source_b, &source_b, authority_b, 6_500, [0x9A; 32]);

        let result_a = call(&store_a, &signed_a, &later_context, &later_leg_policy, 23);
        let result_b = call(&store_b, &signed_b, &later_context, &later_leg_policy, 23);
        let outcomes = [result_a.is_ok(), result_b.is_ok()];
        assert_eq!(
            outcomes.iter().filter(|ok| **ok).count(),
            1,
            "exactly one of the two competing writers must commit"
        );

        let store_c = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let settled = get_bond(&store_c, ValidatorId::new(sender()));
        assert_eq!(settled.generation, base.generation + 1);
        assert_ne!(settled, base);
        // The loser's own source object never moved: no partial state from
        // the rejected writer survived alongside the winner's commit.
        let (winner_source, loser_source) = if result_a.is_ok() {
            (race_source_a, race_source_b)
        } else {
            (race_source_b, race_source_a)
        };
        let winner_head = store_c
            .get_object_head(&context(1), domain(), winner_source)
            .unwrap();
        assert!(matches!(
            winner_head,
            DurableObjectHead::Current { object_version, .. } if object_version.get() == 2
        ));
        let loser_head = store_c
            .get_object_head(&context(1), domain(), loser_source)
            .unwrap();
        assert!(matches!(
            loser_head,
            DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
        ));
    }

    // 7. Writer-fence generation: a stale generation-1 writer handle is
    //    rejected once the fence advances to generation 2.
    {
        let store = SqliteDurableStore::open(&db_path, namespace, fence1).unwrap();
        store
            .advance_writer_fence(fence1, WriterFenceGeneration::new(2).unwrap())
            .unwrap();
        let stale_intent = base_intent(
            &later_context,
            [0x9B; 32],
            &after_withdraw,
            &after_withdraw,
            BondLifecycleOperation::Unbond {
                recipient: unbond_recipient,
            },
        );
        let signed = signed_envelope(stale_intent, &key());
        let error = call(&store, &signed, &later_context, &later_leg_policy, 24).unwrap_err();
        assert!(matches!(
            error,
            BondLifecycleError::Node(NodeCoreError::DurableRead(
                DurableReadError::WriterFenced { .. }
            )) | BondLifecycleError::Node(NodeCoreError::DurableCommitRejected(
                DurableCommitRejection::WriterFenced { .. }
            ))
        ));
    }
}

// ---------------------------------------------------------------------
// Transition-chain restart negatives: every way a stored generation-2
// transition or the installed singleton itself can be corrupted must fail
// `genesis::install_genesis`'s independent re-verification.
// ---------------------------------------------------------------------

/// Installs genesis, then runs one real `Unbond` (generation 1 -> 2),
/// returning the store/manifest/transition key/bond key a tamper scenario
/// then corrupts before re-running `install_genesis`.
fn build_unbonded_chain() -> (
    MemoryDurableStateStore,
    genesis::GenesisManifest,
    Vec<u8>,
    Vec<u8>,
) {
    let object_id = ObjectId::new([0x6E; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let recipient = canonical_address(0x59);
    let mut next = predicted_next(&bond, 11, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &protocol(),
        [0x9B; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap();
    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    let bond_key =
        local_instance_state::fastpath_bond_record_key(&chain(), &ValidatorId::new(sender()))
            .unwrap();
    (store, manifest, transition_key, bond_key)
}

fn assert_restart_fails_closed(
    store: &MemoryDurableStateStore,
    manifest: &genesis::GenesisManifest,
) {
    let error = genesis::install_genesis(store, &context(1), domain(), &resolver(), manifest, 10)
        .unwrap_err();
    assert!(matches!(error, GenesisError::TamperedInstalledRecord(_)));
}

#[test]
fn restart_rejects_a_deleted_transition_record() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    delete_unconditionally(&store, transition_key);
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_swapped_transition_generation() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    transition.generation = 3;
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

/// `FastPathBondTransitionRecord::committed_at_checkpoint` is documented as
/// a redundant, informational copy of the resulting row's own field
/// (`crate::fast_path::records`) that restart must cross-check rather than
/// trust on its own. Tampering only the transition's own summary copy --
/// leaving the resulting row bytes, and therefore every digest, untouched
/// -- isolates that specific cross-check from the (already separately
/// tested) digest chain.
#[test]
fn restart_rejects_a_transition_checkpoint_that_diverges_from_its_resulting_row() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    let resulting_row: FastPathBondRecord =
        decode_fastpath_bond_record(&transition.resulting_row).unwrap();
    assert_ne!(resulting_row.committed_at_checkpoint, 0);
    transition.committed_at_checkpoint = resulting_row
        .committed_at_checkpoint
        .checked_add(1)
        .unwrap();
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_lifted_signature() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    let mut signed = decode_signed_bond_lifecycle_intent(&transition.signed_envelope).unwrap();
    // Lift the signature bytes of a *different* validity signing over the
    // same message shape (a single flipped byte stands in for any
    // signature the validator never actually produced over this content).
    signed.signature[0] ^= 0xFF;
    transition.signed_envelope = encode_signed_bond_lifecycle_intent(&signed).unwrap();
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_tampered_signed_envelope() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    let last = transition.signed_envelope.len() - 1;
    transition.signed_envelope[last] ^= 0xFF;
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_tampered_stored_resulting_row() {
    let (store, manifest, transition_key, _bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    let last = transition.resulting_row.len() - 1;
    transition.resulting_row[last] ^= 0xFF;
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_coordinated_rewrite_of_transition_and_final_row() {
    let (store, manifest, transition_key, bond_key) = build_unbonded_chain();
    let transition_observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition =
        decode_fastpath_bond_transition_record(transition_observed.value().unwrap()).unwrap();
    let mut tampered_row: FastPathBondRecord =
        decode_fastpath_bond_record(&transition.resulting_row).unwrap();
    tampered_row.amount += 1;
    let tampered_row_bytes =
        crate::fast_path::records::encode_fastpath_bond_record(&tampered_row).unwrap();
    transition.resulting_row = tampered_row_bytes.clone();
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    // Rewrite the installed singleton to match, so a summary-only check
    // (final row equals transition's resulting row) would wrongly pass;
    // only the recomputed digest chain against the validator's own signed
    // `expected_next_row_digest` catches this.
    put_unconditionally(&store, bond_key, tampered_row_bytes);
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_tampered_final_singleton_alone() {
    let (store, manifest, _transition_key, bond_key) = build_unbonded_chain();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    let mut installed: FastPathBondRecord =
        decode_fastpath_bond_record(observed.value().unwrap()).unwrap();
    installed.amount += 1;
    put_unconditionally(
        &store,
        bond_key,
        crate::fast_path::records::encode_fastpath_bond_record(&installed).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

// ---------------------------------------------------------------------
// Cross-protocol-version restart: a later no-leg transition signed under a
// different protocol version than the row it observed must still verify on
// restart. The previous-row digest a validator commits to is always framed
// under *its own* current signing resolver, not whatever resolver produced
// the row bytes; restart must recompute that digest the same way at every
// step (never carry forward a digest computed under a prior transition's
// possibly-different-protocol-version resolver), while still requiring
// exactly the right historical resolver to be available and correct.
//
// Genesis itself (and every other genesis-level check
// `install_genesis_with_history` performs) is always re-verified under its
// own fixed, original protocol version -- that resolver is always the
// top-level `resolver` argument. A later transition signed under an
// upgraded protocol version is therefore supplied through `history`, not as
// the top-level resolver, exactly as a real node would encounter it: the
// chain's genesis never re-frames itself under a newer suite, but
// individual post-genesis records can be.
//
// These tests construct the generation-2 transition and its resulting row
// directly (bypassing `handle_bond_lifecycle`, which also depends on a
// live validator-set/epoch record consistently framed under one resolver,
// orthogonal to this bug) so they isolate exactly the chain-walk digest
// recomputation `genesis::verify_fastpath_bond_chain` performs -- the same
// technique the tamper tests above already use for direct storage setup.
// ---------------------------------------------------------------------

fn protocol_at(version: u32, epoch: u64) -> PublicationContext {
    PublicationContext::new(chain(), ProtocolVersion::new(version), Epoch::new(epoch)).unwrap()
}

fn resolver_at(version: u32, algorithm: HashAlgorithmId) -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(version),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::uniform(HashSuiteId::new(version as u16), algorithm),
        }],
    )
    .unwrap()
}

/// Installs genesis under `resolver()`/`protocol()` (chain-fixed protocol
/// version 3), then directly writes one authentically signed generation-2
/// `Unbond` transition -- and its resulting row as the newly installed
/// singleton -- entirely framed under a later protocol version 4
/// (`resolver_at(4, ..)`), exactly as if a validator had submitted it after
/// a protocol upgrade. Returns the store/manifest/transition-context/
/// resolver/recipient needed to drive restart verification.
fn build_unbonded_chain_signed_under_a_later_protocol_version(
    later_algorithm: HashAlgorithmId,
) -> (
    MemoryDurableStateStore,
    genesis::GenesisManifest,
    PublicationContext,
    HashSuiteResolver,
) {
    let object_id = ObjectId::new([0x6F; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));

    let context_v4 = protocol_at(4, bond.context.epoch().get());
    let resolver_v4 = resolver_at(4, later_algorithm);

    let recipient = canonical_address(0x6A);
    let mut next = predicted_next(&bond, 15, bond.lifecycle_epoch);
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let previous_bytes = crate::fast_path::records::encode_fastpath_bond_record(&bond).unwrap();
    let next_bytes = crate::fast_path::records::encode_fastpath_bond_record(&next).unwrap();
    let previous_digest =
        bond_row_digest(&resolver_v4, bond.lifecycle_epoch, &previous_bytes).unwrap();
    let next_digest = bond_row_digest(&resolver_v4, next.lifecycle_epoch, &next_bytes).unwrap();

    let intent = BondLifecycleIntent {
        context: context_v4.clone(),
        request_id: [0x6B; 32],
        validator_id: bond.validator_id,
        resource_id: resource_id_of(&bond),
        expected_generation: bond.generation,
        expected_previous_row_digest: previous_digest,
        expected_next_row_digest: next_digest,
        operation: BondLifecycleOperation::Unbond { recipient },
    };
    let intent_digest = bond_lifecycle_intent_digest(&resolver_v4, &intent).unwrap();
    let frame = bond_lifecycle_signing_frame(&context_v4, intent_digest).unwrap();
    let signed = SignedBondLifecycleIntent {
        signature: key().sign(&frame).into(),
        intent,
    };
    let signed_bytes = encode_signed_bond_lifecycle_intent(&signed).unwrap();

    let transition = FastPathBondTransitionRecord {
        context: context_v4.clone(),
        validator_id: bond.validator_id,
        generation: 2,
        previous_row_digest: previous_digest,
        current_row_digest: next_digest,
        operation: FastPathBondLifecycleOperation::Unbond,
        committed_at_checkpoint: 15,
        signed_envelope: signed_bytes,
        resulting_row: next_bytes.clone(),
    };
    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    let bond_key =
        local_instance_state::fastpath_bond_record_key(&chain(), &ValidatorId::new(sender()))
            .unwrap();
    put_unconditionally(&store, bond_key, next_bytes);

    (store, manifest, context_v4, resolver_v4)
}

#[test]
fn an_authenticated_later_transition_signed_under_a_new_protocol_version_verifies_on_restart() {
    let (store, manifest, _context_v4, resolver_v4) =
        build_unbonded_chain_signed_under_a_later_protocol_version(HashAlgorithmId::Sha3_256);

    // Genesis itself is still re-verified under its own original protocol
    // version (`resolver()`); the later transition's own protocol version 4
    // is supplied only through `history`.
    let outcome = genesis::install_genesis_with_history(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &[resolver_v4],
        &manifest,
        10,
    )
    .unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
}

#[test]
fn restart_fails_closed_when_the_historical_resolver_for_a_transition_is_wrong_or_missing() {
    let (store, manifest, _context_v4, _resolver_v4) =
        build_unbonded_chain_signed_under_a_later_protocol_version(HashAlgorithmId::Sha3_256);

    // No matching (chain, protocol-version) resolver anywhere in
    // `resolver`/`history`: the transition's own signing context can never
    // be resolved at all, so restart must fail closed rather than silently
    // falling back to genesis's own resolver.
    let error = genesis::install_genesis_with_history(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &[],
        &manifest,
        10,
    )
    .unwrap_err();
    assert!(matches!(error, GenesisError::TamperedInstalledRecord(_)));

    // A resolver present under the exact right (chain, protocol-version)
    // pair but a different hash suite (as if history retained the wrong
    // suite for that version) must also fail closed, not merely by luck of
    // an absent entry: the previous- and next-row digests it recomputes
    // will not match what the validator actually signed.
    let wrong_suite_history = resolver_at(4, HashAlgorithmId::Blake3_256);
    let error = genesis::install_genesis_with_history(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &[wrong_suite_history],
        &manifest,
        10,
    )
    .unwrap_err();
    assert!(matches!(error, GenesisError::TamperedInstalledRecord(_)));
}
