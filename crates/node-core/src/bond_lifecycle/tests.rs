use super::slash;
use super::*;
use crate::equivocation;
use crate::fast_path::records::{
    FastPathBondLifecycleOperation, decode_fastpath_bond_transition_record,
};
use crate::genesis::tests::{
    build_fixture, chain, context, custody_object_entry, domain, key, manifest_with_custody,
    protocol, resign_manifest, resolver, sender,
};
use crate::genesis::{self, GenesisError, GenesisInstallOutcome};
use crate::local_instance_state::fastpath_bond_transition_key;
use abi::call_values::{CallValue, encode_call_value};
use consensus::{ConsensusSigner, FastPathCertifier};
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
    transfer_leg_with_resolver(
        &resolver(),
        fixture,
        current_context,
        object,
        sender_bytes,
        nonce,
        request_id,
        operand,
    )
}

/// Like [`transfer_leg`], but computes the leg's own self-declared
/// `policy_digest` (and the instance target digest, though that is anchored
/// at the fixture's own genesis-pinned `context` regardless) under an
/// explicit `resolver` rather than always the plain [`resolver`] test
/// fixture -- needed once a leg commits at an epoch where a rotating
/// resolver's schedule has actually diverged from the plain one.
#[allow(clippy::too_many_arguments)]
fn transfer_leg_with_resolver(
    resolver: &HashSuiteResolver,
    fixture: &Fixture,
    current_context: PublicationContext,
    object: ObjectRef,
    sender_bytes: [u8; 32],
    nonce: u64,
    request_id: [u8; 32],
    operand: [u8; 32],
) -> Vec<u8> {
    let (manifest, _origin, instance_record, def_id, coin_id) = fixture;
    let target = execution::local_execution::instance_target(resolver, instance_record).unwrap();
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
        policy_digest: base_policy.digest(resolver).unwrap(),
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
        (
            base(BondLifecycleOperation::Reactivate {
                leg: vec![10, 11, 12],
            }),
            "534e52452f640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000007272727272727272727272727272727272727272727272727272727272727272030020000000727272727272727272727272727272727272727272727272727272727272727204000200000005000500030000000a0b0c0a0038000000534e5245088001000200010002000000070002002000000079797979797979797979797979797979797979797979797979797979797979790b000800000001000000000000000c0038000000534e5245030101000200010002000000010002002000000001010101010101010101010101010101010101010101010101010101010101010d0038000000534e524503010100020001000200000001000200200000000202020202020202020202020202020202020202020202020202020202020202",
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
        authorization: BondTransitionAuthorization::ValidatorEnvelope {
            signed_envelope: vec![0xAA, 0xBB],
        },
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
        "534e524531640100090001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f727302000400000003000000030008000000090000000000000002002000000079797979797979797979797979797979797979797979797979797979797979790300080000000200000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e5245030101000200010002000000010002002000000012121212121212121212121212121212121212121212121212121212121212120600020000000100070008000000090000000000000008001a000000534e52453364010002000100020000000100020002000000aabb090003000000ccddee"
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
    withdraw_next.custody_object_epoch = withdraw_next.lifecycle_epoch;
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
    next.custody_object_epoch = next.lifecycle_epoch;
    next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
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
    next.custody_object_epoch = next.lifecycle_epoch;
    next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
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
    let (new_source_object, new_source_authority) = seed_owned_coin(
        &store,
        &fixture,
        new_source_id,
        1_200_000,
        sender(),
        [0x72; 32],
    );

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
    next.custody_object_epoch = next.lifecycle_epoch;
    next.authority = new_source_authority;
    next.amount = 1_200_000;
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
    assert_eq!(committed.amount, 1_200_000);

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

/// `Replace` must never let a validator instantly reduce its live collateral
/// below what it already posted: the new amount is required to be at least
/// the previous live bond amount, exactly like the committed maximum/minimum
/// checks alongside it. Both legs still genuinely execute through real WASM
/// (proving this is a late, not an admission-time, rejection) but the
/// rejection happens before `commit`, so nothing -- not the bond row, either
/// object, the nonce range, or a request receipt -- is left partially
/// mutated.
#[test]
fn replace_rejects_a_decreasing_amount_atomically_with_no_partial_state() {
    let object_id = ObjectId::new([0x4C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);
    assert_eq!(bond.amount, 1_000_000);

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0x4D; 32]);
    // Below the previous live bond amount (1_000_000), even though still
    // above the committed minimum (100): the decreasing-amount check alone
    // must reject this.
    let (new_source_object, new_source_authority) = seed_owned_coin(
        &store,
        &fixture,
        new_source_id,
        900_000,
        sender(),
        [0x7F; 32],
    );

    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0x59);
    let request_id: [u8; 32] = [0x80; 32];
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
    let (_new_deposit_object, deposit_oref) = transferred(
        &new_source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 21, protocol().epoch());
    next.custody_object = deposit_oref;
    next.custody_object_epoch = next.lifecycle_epoch;
    next.authority = new_source_authority;
    next.amount = 900_000;
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
        BondLifecycleError::Invalid("bond replace amount below the previous live bond amount")
    ));

    // No partial state: the bond row is byte-for-byte unchanged.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
    // Neither leg's object mutation survived, despite both legs' WASM having
    // genuinely executed: the new source is still sender-owned at version 1,
    // and the old custody object is still untouched.
    let new_source_head = store
        .get_object_head(&context(1), domain(), new_source_id)
        .unwrap();
    assert!(matches!(
        new_source_head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
    let new_source_owner = new_source_head
        .owner_projection()
        .and_then(DurableObjectOwnerProjection::owner)
        .unwrap();
    assert_eq!(*new_source_owner, Owner::Address(Address::new(sender())));
    let old_custody_head = store
        .get_object_head(&context(1), domain(), bond.custody_object.id)
        .unwrap();
    assert!(matches!(
        old_custody_head,
        DurableObjectHead::Current { object_version, .. } if object_version.get() == 1
    ));
    // No nonce range was reserved.
    let layout = PersistenceLayout::new(chain(), protocol().protocol_version());
    let nonce_key = layout.sender_nonce_key(sender(), protocol().epoch());
    let nonce_bytes = store
        .get_versioned_durable(&context(1), domain(), &nonce_key)
        .unwrap();
    assert!(nonce_bytes.value().is_none());
    // No request receipt was committed either: an exact replay of the
    // identical signed bytes re-runs from scratch and fails the same way,
    // rather than a reconciled receipt short-circuiting to any outcome.
    let replay_error = call(&store, &signed, &protocol(), &leg_policy(), 21).unwrap_err();
    assert!(matches!(
        replay_error,
        BondLifecycleError::Invalid("bond replace amount below the previous live bond amount")
    ));
}

/// The non-decreasing `Replace` floor is `>=`, not `>`: an amount exactly
/// equal to the previous live bond amount must still succeed.
#[test]
fn replace_succeeds_with_an_amount_exactly_equal_to_the_previous_live_amount() {
    let object_id = ObjectId::new([0x4C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);
    assert_eq!(bond.amount, 1_000_000);

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0x4D; 32]);
    let (new_source_object, new_source_authority) = seed_owned_coin(
        &store,
        &fixture,
        new_source_id,
        1_000_000,
        sender(),
        [0x81; 32],
    );

    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0x5A);
    let request_id: [u8; 32] = [0x82; 32];
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
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut next = predicted_next(&bond, 21, protocol().epoch());
    next.custody_object = deposit_oref;
    next.custody_object_epoch = next.lifecycle_epoch;
    next.authority = new_source_authority;
    next.amount = 1_000_000;
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
    assert_eq!(committed.amount, 1_000_000);
    assert_eq!(committed.custody_object.id, new_deposit_object.id);
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
    next.custody_object_epoch = next.lifecycle_epoch;
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
    next.custody_object_epoch = next.lifecycle_epoch;
    next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
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
    next.custody_object_epoch = next.lifecycle_epoch;
    next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
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
        let (new_source_object, new_source_authority) = seed_owned_coin(
            &store,
            &fixture,
            new_source_id,
            1_100_000,
            sender(),
            [0x91; 32],
        );
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
        next.custody_object_epoch = next.lifecycle_epoch;
        next.authority = new_source_authority;
        next.amount = 1_100_000;
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
        next.custody_object_epoch = next.lifecycle_epoch;
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
            // this epoch; both competing legs are built from nonce 1.
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
            next.custody_object_epoch = next.lifecycle_epoch;
            next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
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

/// Real file-backed SQLite coverage for the evidence-driven `Slash` path:
/// genesis install, a real class (a) evidence-driven slash, a close/reopen
/// full genesis restart re-verification, a real `Reactivate`, and one more
/// close/reopen restart re-verification -- proving the complete
/// `Active -> Jailed -> Active` chain, not merely each transition alone,
/// re-verifies from real on-disk storage across independent process-like
/// open/close cycles.
#[test]
fn file_backed_sqlite_slash_restart_and_reactivate() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bond-lifecycle-slash-durable-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([10; 32]), domain());
    let fence1 = WriterFenceGeneration::new(1).unwrap();

    let object_id = ObjectId::new([0xC0; 32]);
    let manifest = manifest_with_custody(object_id);
    let fixture = build_fixture();

    // 1. Fresh install (Active), record real class (a) evidence, and run a
    //    real evidence-driven slash.
    let jailed_bond: FastPathBondRecord;
    let conflict_digest: Digest32;
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        install(&store, &manifest);
        let bond = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(bond.state, FastPathBondState::Active);
        let (evidence, digest) = record_class_a_evidence(&store, 15);
        conflict_digest = digest;

        let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
        let request_id: [u8; 32] = [0xC1; 32];
        let (intent, ..) = build_slash_intent(
            &fixture,
            &protocol(),
            &bond,
            &custody_object,
            evidence.epoch,
            conflict_digest,
            request_id,
        );
        let intent_bytes = slash::encode_slash_intent(&intent).unwrap();
        let output = slash::handle_bond_slash(
            &store,
            &MemoryBlobStore::default(),
            &context(1),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &leg_policy(),
            &engine(),
            &intent_bytes,
            20,
        )
        .unwrap();
        jailed_bond =
            decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(
            jailed_bond.state,
            FastPathBondState::Jailed {
                evidence_digest: conflict_digest
            }
        );
        assert_eq!(jailed_bond.generation, bond.generation + 1);
    }

    // 2. Close and reopen: the jailed row survived exactly, and a full
    //    genesis restart re-verification (walking the real permanent
    //    transition chain, including the `ConsumedEvidence` authorization,
    //    against real file-backed SQLite storage) succeeds.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, jailed_bond);
        let restart_outcome =
            genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
                .unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }

    // 3. Close and reopen: run a real `Reactivate` with a fresh sender-owned
    //    coin, at the exact same committed context (reactivation needs no
    //    epoch advance).
    let reactivated_bond: FastPathBondRecord;
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, jailed_bond);

        let source_id = ObjectId::new([0xC2; 32]);
        let (source_object, source_authority) =
            seed_owned_coin(&store, &fixture, source_id, 3_000, sender(), [0xC3; 32]);
        let scope = custody_scope_of(&reopened);
        let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
            &resolver(),
            &protocol(),
            source_id,
            &scope,
        )
        .unwrap();
        let request_id: [u8; 32] = [0xC4; 32];
        let leg = transfer_leg(
            &fixture,
            protocol(),
            object_ref(&resolver(), &source_object),
            sender(),
            1,
            request_id,
            token,
        );
        let (new_object, oref) = transferred(
            &source_object,
            Owner::ProtocolCustody(scope),
            protocol().epoch(),
        );
        let mut next = predicted_next(&reopened, 25, protocol().epoch());
        next.custody_object = oref;
        next.custody_object_epoch = next.lifecycle_epoch;
        next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
        next.authority = source_authority;
        next.amount = 3_000;
        next.required_minimum = 100;
        next.state = FastPathBondState::Active;
        let intent = base_intent(
            &protocol(),
            request_id,
            &reopened,
            &next,
            BondLifecycleOperation::Reactivate { leg },
        );
        let signed = signed_envelope(intent, &key());
        let output = call(&store, &signed, &protocol(), &leg_policy(), 25).unwrap();
        reactivated_bond =
            decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
        assert_eq!(reactivated_bond, next);
        assert_eq!(reactivated_bond.state, FastPathBondState::Active);
        assert_eq!(reactivated_bond.custody_object.id, new_object.id);
    }

    // 4. Close and reopen once more: the complete chain -- genesis, the real
    //    slash, and the real reactivate -- re-verifies from disk.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        let reopened = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(reopened, reactivated_bond);
        let restart_outcome =
            genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
                .unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }
}

/// Real file-backed SQLite competing-writer coverage for `Slash` racing
/// `Replace` from the exact same committed `Active` row: two independent
/// writer handles open the same database and submit different, individually
/// valid transitions (one evidence-driven and unsigned, one a validator-
/// signed two-leg swap) from the identical committed generation. Exactly one
/// commits; the loser observes the advanced row and no partial effect from
/// it survives.
#[test]
fn file_backed_sqlite_slash_vs_replace_competing_writers_commit_exactly_once() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bond-lifecycle-slash-race-durable-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([11; 32]), domain());
    let fence1 = WriterFenceGeneration::new(1).unwrap();

    let object_id = ObjectId::new([0xD0; 32]);
    let manifest = manifest_with_custody(object_id);
    let fixture = build_fixture();
    let active_bond: FastPathBondRecord;
    let conflict_digest: Digest32;
    let evidence_epoch: Epoch;

    // 1. Fresh install (Active) and real class (a) evidence recorded against
    //    the exact same store the race below runs against.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        install(&store, &manifest);
        active_bond = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(active_bond.state, FastPathBondState::Active);
        let (evidence, digest) = record_class_a_evidence(&store, 15);
        evidence_epoch = evidence.epoch;
        conflict_digest = digest;
    }

    // 2. Two independent writer handles open the same database and each
    //    submit one individually valid transition against the identical
    //    committed `Active` row: writer A slashes it (evidence-driven,
    //    unsigned), writer B replaces it (validator-signed two-leg swap).
    //    Only one can win.
    let store_a = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let store_b = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let base_a = get_bond(&store_a, ValidatorId::new(sender()));
    let base_b = get_bond(&store_b, ValidatorId::new(sender()));
    assert_eq!(base_a, active_bond);
    assert_eq!(base_b, active_bond);

    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let slash_request_id: [u8; 32] = [0xD1; 32];
    let (slash_intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &base_a,
        &custody_object,
        evidence_epoch,
        conflict_digest,
        slash_request_id,
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();

    let new_source_id = ObjectId::new([0xD2; 32]);
    let (new_source_object, new_source_authority) = seed_owned_coin(
        &store_b,
        &fixture,
        new_source_id,
        6_000,
        sender(),
        [0xD3; 32],
    );
    let scope = custody_scope_of(&base_b);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0xD4);
    let replace_request_id: [u8; 32] = [0xD5; 32];
    let deposit_leg = transfer_leg(
        &fixture,
        protocol(),
        object_ref(&resolver(), &new_source_object),
        sender(),
        0,
        replace_request_id,
        token,
    );
    let release_leg = transfer_leg(
        &fixture,
        protocol(),
        base_b.custody_object.clone(),
        sender(),
        1,
        replace_request_id,
        *release_recipient.as_bytes(),
    );
    let (_new_deposit_object, deposit_oref) = transferred(
        &new_source_object,
        Owner::ProtocolCustody(scope),
        protocol().epoch(),
    );
    let mut replaced_next = predicted_next(&base_b, 22, protocol().epoch());
    replaced_next.custody_object = deposit_oref;
    replaced_next.custody_object_epoch = replaced_next.lifecycle_epoch;
    replaced_next.authority = new_source_authority;
    replaced_next.amount = 6_000;
    replaced_next.required_minimum = 100;
    replaced_next.state = FastPathBondState::Active;
    let replace_intent = base_intent(
        &protocol(),
        replace_request_id,
        &base_b,
        &replaced_next,
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        },
    );
    let replace_signed = signed_envelope(replace_intent, &key());

    let slash_result = slash::handle_bond_slash(
        &store_a,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &slash_intent_bytes,
        23,
    );
    let replace_result = call(&store_b, &replace_signed, &protocol(), &leg_policy(), 24);

    // Exactly one commits.
    assert_ne!(slash_result.is_ok(), replace_result.is_ok());

    let final_store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let final_bond = get_bond(&final_store, ValidatorId::new(sender()));
    match &slash_result {
        Ok(_) => {
            assert_eq!(
                final_bond.state,
                FastPathBondState::Jailed {
                    evidence_digest: conflict_digest
                }
            );
            // Full forfeiture, not a merge with the loser's proposed swap.
            assert_eq!(final_bond.amount, active_bond.amount);
            assert!(matches!(
                replace_result.unwrap_err(),
                BondLifecycleError::Node(NodeCoreError::StateConflict)
                    | BondLifecycleError::Node(NodeCoreError::DurableCommitRejected(
                        DurableCommitRejection::Conflict { .. }
                    ))
                    | BondLifecycleError::Invalid(_)
            ));
        }
        Err(_) => {
            assert_eq!(final_bond, replaced_next);
            assert!(matches!(
                slash_result.unwrap_err(),
                BondLifecycleError::Node(NodeCoreError::StateConflict)
                    | BondLifecycleError::Node(NodeCoreError::DurableCommitRejected(
                        DurableCommitRejection::Conflict { .. }
                    ))
                    | BondLifecycleError::Invalid(_)
            ));
        }
    }
    // No partial state either way: exactly one generation-2 transition
    // record exists, and the installed singleton matches it exactly.
    assert_eq!(final_bond.generation, active_bond.generation + 1);
    let restart_outcome = genesis::install_genesis(
        &final_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
}

/// Real file-backed SQLite competing-writer coverage for `Slash` racing
/// `Withdraw` from the exact same committed `Unbonding` row, at/after its own
/// unlock epoch and with the validator already absent from the committed
/// live set: two independent writer handles open the same database and
/// submit different, individually valid transitions (one evidence-driven and
/// unsigned, one a validator-signed release) from the identical committed
/// generation. `Unbonding` still carries live collateral
/// (`FastPathBondRecord::live_collateral`), so both are genuinely admissible
/// from this exact row; `handle_bond_slash` never itself consults the live
/// validator set, so the same absence that legitimizes `Withdraw` has no
/// bearing on `Slash`'s own eligibility. This test deliberately commits
/// `Withdraw` first, proving the stale `Slash` leaves no receipt, nonce
/// advance or consumed-evidence marker; the sibling Slash-vs-Replace race
/// covers the opposite, Slash-wins ordering. The resulting `Exited` state
/// re-verifies through a fresh close/reopen `install_genesis` restart.
#[test]
fn file_backed_sqlite_slash_vs_withdraw_competing_writers_commit_exactly_once() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "bond-lifecycle-slash-withdraw-race-durable-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([12; 32]), domain());
    let fence1 = WriterFenceGeneration::new(1).unwrap();

    let object_id = ObjectId::new([0xD6; 32]);
    let alternate_object_id = ObjectId::new([0xDB; 32]);
    let alternate_key: SigningKey = SigningKey::from([0xDC; 32]);
    let alternate_public_key: [u8; 32] =
        ed25519_zebra::VerificationKey::from(&alternate_key).into();
    let alternate_validator_id: ValidatorId = ValidatorId::new(alternate_public_key);
    let mut manifest = manifest_with_custody(object_id);
    // This fixture needs a one-epoch release delay so a real certificate can
    // retire the unbonding validator before Withdraw becomes valid. The
    // second validator and its own exact genesis collateral let that
    // certificate install a non-empty next set without the retiring sender.
    manifest.economics_policy.resources[0]
        .bond
        .as_mut()
        .unwrap()
        .unbonding_epochs = 1;
    manifest
        .validator_set
        .validators
        .push(crate::fast_path::records::FastPathValidatorEntry {
            id: alternate_validator_id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: alternate_public_key.to_vec(),
        });
    manifest
        .validator_set
        .validators
        .sort_by_key(|validator| validator.id);
    let mut alternate_custody = manifest.objects[2].clone();
    alternate_custody.object.id = alternate_object_id;
    alternate_custody.authority.object_id = alternate_object_id;
    let alternate_scope: &mut ProtocolCustodyScope = match &mut alternate_custody.object.owner {
        Owner::ProtocolCustody(scope) => scope,
        _ => panic!("fixture custody object must be protocol-owned"),
    };
    alternate_scope.subject = alternate_public_key;
    manifest.objects.push(alternate_custody);
    resign_manifest(&mut manifest);
    let fixture = build_fixture();
    let unbonding_bond: FastPathBondRecord;
    let conflict_digest: Digest32;
    let evidence_epoch: Epoch;
    let recipient: Address = canonical_address(0xD7);
    // Genesis is at epoch 0 and this signed fixture uses a one-epoch release
    // delay, so a real `Unbond` at genesis unlocks at exactly epoch 1.
    let later_context: PublicationContext =
        PublicationContext::new(chain(), protocol().protocol_version(), Epoch::new(1)).unwrap();
    let later_leg_policy = LocalExecutionPolicy::generic_object_results(later_context.clone());

    // 1. Fresh two-validator install. While both bonds are Active, form a
    //    real quorum certificate whose next set contains only the alternate
    //    validator. Then commit a real `Unbond` and class (a) evidence before
    //    activating that already-certified set at epoch 1. This is the
    //    certificate-wins ordering: the sender is now absent from the live
    //    set, its unlock epoch has elapsed, and the complete epoch history is
    //    restart-verifiable rather than hand-written test state.
    {
        let store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
        install(&store, &manifest);
        let active_bond = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(active_bond.state, FastPathBondState::Active);

        let next_validators = vec![crate::fast_path::records::FastPathValidatorEntry {
            id: alternate_validator_id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: alternate_public_key.to_vec(),
        }];
        let sender_vote = crate::epoch_transition::propose_and_vote(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol().protocol_version(),
            next_validators.clone(),
            &FixedKeySigner(key()),
        )
        .unwrap();
        let alternate_vote = crate::epoch_transition::propose_and_vote(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol().protocol_version(),
            next_validators.clone(),
            &FixedKeySigner(alternate_key),
        )
        .unwrap();
        let outgoing_validators: Vec<validator_set::ValidatorInfo> = manifest
            .validator_set
            .validators
            .iter()
            .map(|validator| validator_set::ValidatorInfo {
                id: validator.id,
                voting_power: validator.voting_power,
                signature_scheme: validator.signature_scheme,
                public_key: validator.public_key.clone(),
            })
            .collect();
        let outgoing_set: ValidatorSet =
            ValidatorSet::new(protocol().epoch(), outgoing_validators).unwrap();
        let certifier = consensus::EpochTransitionCertifier::new(
            chain(),
            protocol().protocol_version(),
            protocol().epoch(),
            outgoing_set,
        )
        .unwrap();
        let votes = vec![sender_vote.clone(), alternate_vote];
        let certificate = certifier
            .try_form_certificate(
                sender_vote.next_epoch,
                sender_vote.current_validator_set_digest,
                sender_vote.next_validator_set_digest,
                sender_vote.activation_digest,
                &votes,
                &fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("both equal-power validators exceed quorum");
        let certificate_bytes: Vec<u8> =
            consensus::encode_epoch_transition_certificate(&certificate).unwrap();

        let mut next = predicted_next(&active_bond, 11, protocol().epoch());
        next.state = FastPathBondState::Unbonding {
            unlock_epoch: Epoch::new(1),
            recipient: *recipient.as_bytes(),
        };
        let intent = base_intent(
            &protocol(),
            [0xD8; 32],
            &active_bond,
            &next,
            BondLifecycleOperation::Unbond { recipient },
        );
        let signed = signed_envelope(intent, &key());
        call(&store, &signed, &protocol(), &leg_policy(), 11).unwrap();
        unbonding_bond = get_bond(&store, ValidatorId::new(sender()));
        assert_eq!(
            unbonding_bond.state,
            FastPathBondState::Unbonding {
                unlock_epoch: Epoch::new(1),
                recipient: *recipient.as_bytes(),
            }
        );

        let (evidence, digest) = record_class_a_evidence(&store, 15);
        evidence_epoch = evidence.epoch;
        conflict_digest = digest;

        let activation = crate::epoch_transition::activate(
            &store,
            &context(1),
            domain(),
            &resolver(),
            &chain(),
            protocol().protocol_version(),
            next_validators,
            &certificate_bytes,
            16,
        )
        .unwrap();
        assert!(matches!(
            activation,
            crate::epoch_transition::EpochActivationOutcome::Activated { .. }
        ));
    }

    // 2. Two independent writer handles open the same database and each
    //    submit one individually valid transition against the identical
    //    committed `Unbonding` row, both committing at the epoch-1 committed
    //    current epoch: writer A slashes it (evidence-driven, unsigned;
    //    still valid since `Unbonding` retains live collateral), writer B
    //    withdraws it (validator-signed release; valid since the unlock
    //    epoch has elapsed and the validator is absent from the epoch-1 live
    //    set). Only one can win.
    let store_a = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let store_b = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let base_a = get_bond(&store_a, ValidatorId::new(sender()));
    let base_b = get_bond(&store_b, ValidatorId::new(sender()));
    assert_eq!(base_a, unbonding_bond);
    assert_eq!(base_b, unbonding_bond);

    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let slash_request_id: [u8; 32] = [0xD9; 32];
    let (slash_intent, ..) = build_slash_intent(
        &fixture,
        &later_context,
        &base_a,
        &custody_object,
        evidence_epoch,
        conflict_digest,
        slash_request_id,
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();

    let withdraw_request_id: [u8; 32] = [0xDA; 32];
    let withdraw_leg = transfer_leg(
        &fixture,
        later_context.clone(),
        base_b.custody_object.clone(),
        sender(),
        0,
        withdraw_request_id,
        *recipient.as_bytes(),
    );
    // The custody object is untouched by `Unbond`, so it is still exactly
    // the genesis manifest's own custody entry (index 2).
    let current_custody_object: &Object = &manifest.objects[2].object;
    let (_withdrawn_object, withdrawn_oref) = transferred(
        current_custody_object,
        Owner::Address(recipient),
        Epoch::new(1),
    );
    let mut withdrawn_next = predicted_next(&base_b, 24, Epoch::new(1));
    withdrawn_next.state = FastPathBondState::Exited;
    withdrawn_next.custody_object = withdrawn_oref;
    withdrawn_next.custody_object_epoch = withdrawn_next.lifecycle_epoch;
    let withdraw_intent = base_intent(
        &later_context,
        withdraw_request_id,
        &base_b,
        &withdrawn_next,
        BondLifecycleOperation::Withdraw { leg: withdraw_leg },
    );
    let withdraw_signed = signed_envelope(withdraw_intent, &key());

    // Commit Withdraw first through writer B, then submit the independently
    // prepared Slash through writer A. This ordering specifically proves the
    // release winner leaves no slash receipt or consumed-evidence marker;
    // the sibling Slash-vs-Replace test already covers the Slash-wins side.
    let withdraw_result = call(
        &store_b,
        &withdraw_signed,
        &later_context,
        &later_leg_policy,
        24,
    );
    let slash_result = slash::handle_bond_slash(
        &store_a,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &later_context,
        &later_leg_policy,
        &engine(),
        &slash_intent_bytes,
        23,
    );

    // Exactly one commits.
    assert_ne!(slash_result.is_ok(), withdraw_result.is_ok());
    assert!(withdraw_result.is_ok());
    assert!(slash_result.is_err());

    let final_store = SqliteDurableStore::open(&db_path, namespace.clone(), fence1).unwrap();
    let final_bond = get_bond(&final_store, ValidatorId::new(sender()));
    assert_eq!(final_bond, withdrawn_next);
    assert!(matches!(
        slash_result.unwrap_err(),
        BondLifecycleError::Node(NodeCoreError::StateConflict)
            | BondLifecycleError::Node(NodeCoreError::DurableCommitRejected(
                DurableCommitRejection::Conflict { .. }
            ))
            | BondLifecycleError::Invalid(_)
    ));
    // No partial state: exactly one generation-3 transition record exists,
    // and the installed singleton matches it exactly.
    assert_eq!(final_bond.generation, unbonding_bond.generation + 1);
    let withdraw_receipt: Option<DurableRequestReceipt> = final_store
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(withdraw_request_id).unwrap(),
        )
        .unwrap();
    let slash_receipt: Option<DurableRequestReceipt> = final_store
        .get_request_receipt(
            &context(1),
            domain(),
            DurableRequestId::new(slash_request_id).unwrap(),
        )
        .unwrap();
    assert!(withdraw_receipt.is_some());
    assert!(slash_receipt.is_none());
    let consumed_key: Vec<u8> = local_instance_state::fastpath_evidence_consumed_key(
        &chain(),
        evidence_epoch,
        *unbonding_bond.validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    let consumed: VersionedStateValue = final_store
        .get_versioned_durable(&context(1), domain(), &consumed_key)
        .unwrap();
    assert!(consumed.value().is_none());
    let layout = PersistenceLayout::new(chain(), protocol().protocol_version());
    let nonce_key: Vec<u8> = layout.sender_nonce_key(sender(), later_context.epoch());
    let nonce_bytes: VersionedStateValue = final_store
        .get_versioned_durable(&context(1), domain(), &nonce_key)
        .unwrap();
    let nonce: SenderNonceRecord = SenderNonceRecord::decode(nonce_bytes.value().unwrap()).unwrap();
    assert_eq!(nonce.next_nonce, 1);
    let restart_outcome = genesis::install_genesis(
        &final_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
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
    let BondTransitionAuthorization::ValidatorEnvelope { signed_envelope } =
        &transition.authorization
    else {
        panic!("expected a validator-signed envelope");
    };
    let mut signed = decode_signed_bond_lifecycle_intent(signed_envelope).unwrap();
    // Lift the signature bytes of a *different* validity signing over the
    // same message shape (a single flipped byte stands in for any
    // signature the validator never actually produced over this content).
    signed.signature[0] ^= 0xFF;
    transition.authorization = BondTransitionAuthorization::ValidatorEnvelope {
        signed_envelope: encode_signed_bond_lifecycle_intent(&signed).unwrap(),
    };
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
    let BondTransitionAuthorization::ValidatorEnvelope { signed_envelope } =
        &mut transition.authorization
    else {
        panic!("expected a validator-signed envelope");
    };
    let last = signed_envelope.len() - 1;
    signed_envelope[last] ^= 0xFF;
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
        authorization: BondTransitionAuthorization::ValidatorEnvelope {
            signed_envelope: signed_bytes,
        },
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

// ── DR-0137 implementation unit 3: evidence-driven slash and reactivate ────

/// Signs with a fixed key as the exact genesis validator (`sender()`/`key()`).
struct FixedKeySigner(SigningKey);
impl ConsensusSigner for FixedKeySigner {
    fn validator_id(&self) -> ValidatorId {
        let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&self.0).into();
        ValidatorId::new(public_key)
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.0.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

fn ev_digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

/// One-validator [`FastPathCertifier`] bound to the exact genesis validator
/// set `manifest_with_custody` installs.
fn one_validator_certifier() -> FastPathCertifier {
    let validator_set: ValidatorSet = ValidatorSet::new(
        protocol().epoch(),
        vec![validator_set::ValidatorInfo {
            id: ValidatorId::new(sender()),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: sender().to_vec(),
        }],
    )
    .unwrap();
    FastPathCertifier::new(
        chain(),
        protocol().protocol_version(),
        protocol().epoch(),
        validator_set,
    )
    .unwrap()
}

/// Records a real class (a) DR-0133 evidence row proving the genesis
/// validator equivocated, and returns the decoded evidence plus its
/// normalized-identity `conflict_digest` -- the exact selector
/// `handle_bond_slash` requires.
fn record_class_a_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    checkpoint: u64,
) -> (consensus::FastVoteEquivocationEvidence, Digest32) {
    let certifier = one_validator_certifier();
    let signer = FixedKeySigner(key());
    // Class (a): the identical `tx_hash`, a differing payload (here,
    // `execution_effects_hash`).
    let vote_a = certifier
        .cast_vote(ev_digest(0x01), ev_digest(0x02), ev_digest(0x03), &signer)
        .unwrap();
    let vote_b = certifier
        .cast_vote(ev_digest(0x01), ev_digest(0x05), ev_digest(0x03), &signer)
        .unwrap();
    let bytes_a = consensus::encode_fast_vote(&vote_a).unwrap();
    let bytes_b = consensus::encode_fast_vote(&vote_b).unwrap();
    let outcome = equivocation::submit_fast_vote_equivocation_evidence(
        store,
        &context(1),
        domain(),
        &resolver(),
        &chain(),
        protocol().protocol_version(),
        &bytes_a,
        &bytes_b,
        checkpoint,
    )
    .unwrap();
    let record = match outcome {
        equivocation::EquivocationEvidenceOutcome::Recorded(record) => record,
        equivocation::EquivocationEvidenceOutcome::AlreadyRecorded(_) => {
            panic!("expected a freshly recorded evidence row")
        }
    };
    let evidence =
        consensus::decode_fast_vote_equivocation_evidence(&record.evidence_bytes).unwrap();
    let conflict_digest = equivocation::normalized_identity_digest(
        &resolver(),
        &equivocation::DecodedEquivocationEvidence::FastVote(evidence.clone()),
    )
    .unwrap();
    (evidence, conflict_digest)
}

/// Records a real class (b) DR-0133 object-conflict evidence row proving the
/// genesis validator equivocated (two differing transactions whose locked
/// object sets share a pair), and returns its epoch plus the exact
/// normalized-identity `conflict_digest` `handle_bond_slash` requires.
fn record_class_b_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    checkpoint: u64,
) -> (Epoch, Digest32) {
    let certifier = one_validator_certifier();
    let signer = FixedKeySigner(key());
    let epoch: Epoch = protocol().epoch();
    let shared: ObjectRef = ObjectRef {
        id: ObjectId::new([0x61; 32]),
        version: 1,
        digest: ev_digest(0x62),
    };
    let mut entries_a: Vec<ObjectRef> = vec![
        shared.clone(),
        ObjectRef {
            id: ObjectId::new([0x63; 32]),
            version: 1,
            digest: ev_digest(0x64),
        },
    ];
    entries_a.sort_by_key(|entry| entry.id);
    let mut entries_b: Vec<ObjectRef> = vec![
        shared,
        ObjectRef {
            id: ObjectId::new([0x65; 32]),
            version: 1,
            digest: ev_digest(0x66),
        },
    ];
    entries_b.sort_by_key(|entry| entry.id);
    let preimage_a = consensus::LockedObjectSetPreimage {
        chain_id: chain(),
        protocol_version: protocol().protocol_version(),
        epoch,
        entries: entries_a,
    };
    let preimage_b = consensus::LockedObjectSetPreimage {
        chain_id: chain(),
        protocol_version: protocol().protocol_version(),
        epoch,
        entries: entries_b,
    };
    let preimage_bytes_a = consensus::encode_locked_object_set_preimage(&preimage_a).unwrap();
    let preimage_bytes_b = consensus::encode_locked_object_set_preimage(&preimage_b).unwrap();
    let digest_a: Digest32 = resolver()
        .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &preimage_bytes_a)
        .unwrap();
    let digest_b: Digest32 = resolver()
        .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &preimage_bytes_b)
        .unwrap();
    let vote_a = certifier
        .cast_vote(ev_digest(0x67), ev_digest(0x68), digest_a, &signer)
        .unwrap();
    let vote_b = certifier
        .cast_vote(ev_digest(0x69), ev_digest(0x6a), digest_b, &signer)
        .unwrap();
    let bytes_a = consensus::encode_fast_vote(&vote_a).unwrap();
    let bytes_b = consensus::encode_fast_vote(&vote_b).unwrap();
    let outcome = equivocation::submit_fast_vote_object_conflict_evidence(
        store,
        &context(1),
        domain(),
        &resolver(),
        &chain(),
        protocol().protocol_version(),
        &bytes_a,
        &bytes_b,
        &preimage_bytes_a,
        &preimage_bytes_b,
        checkpoint,
    )
    .unwrap();
    let record = match outcome {
        equivocation::EquivocationEvidenceOutcome::Recorded(record) => record,
        equivocation::EquivocationEvidenceOutcome::AlreadyRecorded(_) => {
            panic!("expected a freshly recorded evidence row")
        }
    };
    let evidence =
        consensus::decode_fast_vote_object_conflict_evidence(&record.evidence_bytes).unwrap();
    let conflict_digest = equivocation::normalized_identity_digest(
        &resolver(),
        &equivocation::DecodedEquivocationEvidence::ObjectConflict(evidence.clone()),
    )
    .unwrap();
    (evidence.epoch, conflict_digest)
}

/// Records a real class (c) DR-0133 epoch-transition-equivocation evidence
/// row proving the genesis validator, acting as the sole outgoing-epoch
/// signer, voted for two differing activation targets over the identical
/// `(epoch, next_epoch)` pair. Returns the outgoing epoch plus the exact
/// normalized-identity `conflict_digest` `handle_bond_slash` requires.
fn record_class_c_evidence<S: StructuredDurableDomainStateStore>(
    store: &S,
    checkpoint: u64,
) -> (Epoch, Digest32) {
    let validator_set: ValidatorSet = ValidatorSet::new(
        protocol().epoch(),
        vec![validator_set::ValidatorInfo {
            id: ValidatorId::new(sender()),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: sender().to_vec(),
        }],
    )
    .unwrap();
    let certifier = consensus::EpochTransitionCertifier::new(
        chain(),
        protocol().protocol_version(),
        protocol().epoch(),
        validator_set,
    )
    .unwrap();
    let signer = FixedKeySigner(key());
    let next_epoch = Epoch::new(protocol().epoch().get() + 1);
    let vote_a = certifier
        .cast_vote(
            next_epoch,
            ev_digest(0x71),
            ev_digest(0x72),
            ev_digest(0x73),
            &signer,
        )
        .unwrap();
    let vote_b = certifier
        .cast_vote(
            next_epoch,
            ev_digest(0x71),
            ev_digest(0x72),
            ev_digest(0x74),
            &signer,
        )
        .unwrap();
    let bytes_a = consensus::encode_epoch_transition_vote(&vote_a).unwrap();
    let bytes_b = consensus::encode_epoch_transition_vote(&vote_b).unwrap();
    let outcome = equivocation::submit_epoch_transition_equivocation_evidence(
        store,
        &context(1),
        domain(),
        &resolver(),
        &chain(),
        protocol().protocol_version(),
        &bytes_a,
        &bytes_b,
        checkpoint,
    )
    .unwrap();
    let record = match outcome {
        equivocation::EquivocationEvidenceOutcome::Recorded(record) => record,
        equivocation::EquivocationEvidenceOutcome::AlreadyRecorded(_) => {
            panic!("expected a freshly recorded evidence row")
        }
    };
    let evidence =
        consensus::decode_epoch_transition_equivocation_evidence(&record.evidence_bytes).unwrap();
    let conflict_digest = equivocation::normalized_identity_digest(
        &resolver(),
        &equivocation::DecodedEquivocationEvidence::EpochTransition(evidence.clone()),
    )
    .unwrap();
    (evidence.epoch, conflict_digest)
}

/// Builds the forfeiture leg and full [`slash::SlashIntent`] bytes moving
/// `bond`'s exact live custody object into `ForfeitedCollateral`, pinned to
/// `conflict_digest`/`evidence_epoch`, committing at `current_context`
/// (which need not equal `evidence_epoch`'s own context: a bond may be
/// slashed at a later committed epoch than the evidence it is slashed by).
/// `leg_nonce` is the forfeiture leg's own sender nonce at `current_context`
/// -- callers that already spent earlier nonces for `sender()` at that same
/// epoch (e.g. a preceding `Replace`) must pass the next unused value.
#[allow(clippy::too_many_arguments)]
fn build_slash_intent_at_nonce(
    fixture: &Fixture,
    current_context: &PublicationContext,
    bond: &FastPathBondRecord,
    custody_object: &Object,
    evidence_epoch: Epoch,
    conflict_digest: Digest32,
    request_id: [u8; 32],
    leg_nonce: u64,
) -> (slash::SlashIntent, Object, ProtocolCustodyScope) {
    let target_scope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::ForfeitedCollateral,
        chain_id: bond.context.chain_id().clone(),
        subject: *bond.validator_id.as_bytes(),
        resource: bond.resource,
    };
    let forfeit_token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        current_context,
        bond.custody_object.id,
        &target_scope,
    )
    .unwrap();
    let leg = transfer_leg(
        fixture,
        current_context.clone(),
        // Hashed at `bond`'s own recorded `custody_object_epoch`, never at
        // `current_context.epoch()`: a bond slashed at a later committing
        // epoch than the one that last actually minted its custody object
        // (e.g. after an intervening `Unbond`) must still match the durable
        // object's own pinned digest.
        object_ref_at(&resolver(), custody_object, bond.custody_object_epoch),
        sender(),
        leg_nonce,
        request_id,
        forfeit_token,
    );
    let (new_object, _oref) = transferred(
        custody_object,
        Owner::ProtocolCustody(target_scope.clone()),
        current_context.epoch(),
    );
    let intent = slash::SlashIntent {
        context: current_context.clone(),
        request_id,
        validator_id: bond.validator_id,
        resource_id: resource_id_of(bond),
        expected_generation: bond.generation,
        evidence_epoch,
        conflict_digest,
        leg,
    };
    (intent, new_object, target_scope)
}

/// [`build_slash_intent_at_nonce`] at leg nonce 0, for the (overwhelming)
/// majority of callers whose sender has not already spent an earlier nonce
/// for `current_context`'s epoch.
#[allow(clippy::too_many_arguments)]
fn build_slash_intent(
    fixture: &Fixture,
    current_context: &PublicationContext,
    bond: &FastPathBondRecord,
    custody_object: &Object,
    evidence_epoch: Epoch,
    conflict_digest: Digest32,
    request_id: [u8; 32],
) -> (slash::SlashIntent, Object, ProtocolCustodyScope) {
    build_slash_intent_at_nonce(
        fixture,
        current_context,
        bond,
        custody_object,
        evidence_epoch,
        conflict_digest,
        request_id,
        0,
    )
}

#[test]
fn slash_forfeits_the_bond_and_jails_the_validator_with_real_wasm_execution() {
    let object_id = ObjectId::new([0x92; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);

    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);

    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0x93; 32];
    let (intent, new_object, target_scope) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();

    let output = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &intent_bytes,
        20,
    )
    .unwrap();
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(
        committed.state,
        FastPathBondState::Jailed {
            evidence_digest: conflict_digest
        }
    );
    assert_eq!(committed.generation, bond.generation + 1);
    // Full forfeiture: the historical amount/minimum are preserved exactly,
    // not zeroed or reduced.
    assert_eq!(committed.amount, bond.amount);
    assert_eq!(committed.required_minimum, bond.required_minimum);
    assert_eq!(committed.custody_object.id, new_object.id);

    let head = store
        .get_object_head(&context(1), domain(), object_id)
        .unwrap();
    match head {
        DurableObjectHead::Current {
            owner_projection, ..
        } => {
            assert_eq!(
                owner_projection,
                DurableObjectOwnerProjection::from_owner(Owner::ProtocolCustody(target_scope))
                    .unwrap()
            );
        }
        _ => panic!("expected a live head at the forfeited object"),
    }

    // The evidence-consumed absence fence is now occupied.
    let consumed_key = local_instance_state::fastpath_evidence_consumed_key(
        &chain(),
        evidence.epoch,
        *bond.validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    let consumed_observed = store
        .get_versioned_durable(&context(1), domain(), &consumed_key)
        .unwrap();
    let consumed =
        slash::decode_evidence_consumption_record(consumed_observed.value().unwrap()).unwrap();
    assert_eq!(consumed.generation, committed.generation);
    assert_eq!(consumed.conflict_digest, conflict_digest);
}

/// Shared end-to-end assertion for a real evidence-driven slash, reused by
/// the class (b)/(c) tests below: one-time full forfeiture (`Jailed` state,
/// generation+1, exact historical amount/minimum preservation, the
/// forfeited object's owner projection) exactly like the class (a) test
/// above, differing only in which DR-0133 evidence family authorizes it.
/// `record_evidence` records the real evidence row against the exact same
/// store the slash itself commits against, and returns its
/// `(evidence_epoch, conflict_digest)` selector.
fn assert_slash_forfeits_and_jails(
    record_evidence: impl FnOnce(&MemoryDurableStateStore) -> (Epoch, Digest32),
) {
    let object_id = ObjectId::new([0xB0; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);
    let (evidence_epoch, conflict_digest) = record_evidence(&store);

    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0xB1; 32];
    let (intent, new_object, target_scope) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence_epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();

    let output = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &intent_bytes,
        20,
    )
    .unwrap();
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(
        committed.state,
        FastPathBondState::Jailed {
            evidence_digest: conflict_digest
        }
    );
    assert_eq!(committed.generation, bond.generation + 1);
    // Full forfeiture: the historical amount/minimum are preserved exactly,
    // not zeroed or reduced.
    assert_eq!(committed.amount, bond.amount);
    assert_eq!(committed.required_minimum, bond.required_minimum);
    assert_eq!(committed.custody_object.id, new_object.id);

    let head = store
        .get_object_head(&context(1), domain(), object_id)
        .unwrap();
    match head {
        DurableObjectHead::Current {
            owner_projection, ..
        } => {
            assert_eq!(
                owner_projection,
                DurableObjectOwnerProjection::from_owner(Owner::ProtocolCustody(target_scope))
                    .unwrap()
            );
        }
        _ => panic!("expected a live head at the forfeited object"),
    }

    // The evidence-consumed absence fence is now occupied, one-time only.
    let consumed_key = local_instance_state::fastpath_evidence_consumed_key(
        &chain(),
        evidence_epoch,
        *bond.validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    let consumed_observed = store
        .get_versioned_durable(&context(1), domain(), &consumed_key)
        .unwrap();
    let consumed =
        slash::decode_evidence_consumption_record(consumed_observed.value().unwrap()).unwrap();
    assert_eq!(consumed.generation, committed.generation);
    assert_eq!(consumed.conflict_digest, conflict_digest);
}

/// DR-0133 class (b) (`FastVoteObjectConflictEvidence`) end to end: real
/// object-conflict evidence authorizes exactly the same one-time full
/// forfeiture as class (a) does.
#[test]
fn slash_forfeits_the_bond_with_real_class_b_object_conflict_evidence() {
    assert_slash_forfeits_and_jails(|store| record_class_b_evidence(store, 15));
}

/// DR-0133 class (c) (`EpochTransitionEquivocationEvidence`) end to end:
/// real epoch-transition-equivocation evidence authorizes exactly the same
/// one-time full forfeiture as class (a) does.
#[test]
fn slash_forfeits_the_bond_with_real_class_c_epoch_transition_evidence() {
    assert_slash_forfeits_and_jails(|store| record_class_c_evidence(store, 15));
}

/// DR-0137 ("Jailing never changes current-epoch certificate verification"):
/// forming a `FastCertificate` over one fixed `(tx_hash,
/// execution_effects_hash, locked_objects_digest)` tuple from the identical
/// single vote produces byte-for-byte identical encoded certificate bytes
/// whether formed before or after a real evidence-driven slash jails that
/// same validator's bond mid-epoch. `FastPathCertifier`/`FastCertificate`
/// formation and verification read only the immutable `ValidatorSet`
/// snapshot captured at construction, never a bond row: jailing disables
/// local signing going forward and later-set eligibility, nothing already
/// (or independently still) certifiable from the unchanged outgoing set.
#[test]
fn current_epoch_certificate_verification_is_byte_for_byte_unaffected_by_a_later_slash() {
    let object_id = ObjectId::new([0xF7; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(bond.state, FastPathBondState::Active);

    let form_certificate = || {
        let certifier = one_validator_certifier();
        let signer = FixedKeySigner(key());
        let vote = certifier
            .cast_vote(ev_digest(0xC1), ev_digest(0xC2), ev_digest(0xC3), &signer)
            .unwrap();
        let certificate = certifier
            .try_form_certificate(
                ev_digest(0xC1),
                ev_digest(0xC2),
                ev_digest(0xC3),
                std::slice::from_ref(&vote),
                &fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .expect("the single equal-power validator exceeds quorum");
        certifier
            .verify_certificate(&certificate, &fast_path::FastPathEd25519Verifier)
            .unwrap();
        consensus::encode_fast_certificate(&certificate).unwrap()
    };

    // Formed once before the slash, over the bond's still-`Active` state.
    let certificate_before_slash: Vec<u8> = form_certificate();

    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let (slash_intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        [0xF8; 32],
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();
    slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &slash_intent_bytes,
        20,
    )
    .unwrap();
    let jailed_bond = get_bond(&store, ValidatorId::new(sender()));
    assert!(matches!(
        jailed_bond.state,
        FastPathBondState::Jailed { .. }
    ));

    // Formed again after the slash, over the identical fixed tuple/vote: a
    // completely independent construction that never reads `store` at all.
    let certificate_after_slash: Vec<u8> = form_certificate();

    assert_eq!(certificate_before_slash, certificate_after_slash);
}

#[test]
fn slash_exact_replay_returns_the_same_receipt_without_reexecuting_the_leg() {
    let object_id = ObjectId::new([0x94; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0x95; 32];
    let (intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();
    let counting_engine = CountingEngine::new();

    let first = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &counting_engine,
        &intent_bytes,
        20,
    )
    .unwrap();
    let calls_after_first = counting_engine
        .calls
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(calls_after_first >= 1);

    let second = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &counting_engine,
        &intent_bytes,
        20,
    )
    .unwrap();
    assert_eq!(
        counting_engine
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        calls_after_first,
        "exact replay must not re-execute the forfeiture leg"
    );
    assert_eq!(
        first.responses()[0].payload(),
        second.responses()[0].payload()
    );
}

#[test]
fn slash_fails_closed_when_the_evidence_digest_is_already_consumed() {
    let object_id = ObjectId::new([0x96; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);

    // Directly occupy the evidence-consumed absence fence, as if a prior
    // (different-request) slash had already consumed this exact evidence,
    // without actually mutating the bond row -- isolating the fence check
    // from the live-collateral/lifecycle-epoch checks a real double-slash
    // would also trip.
    let consumed_key = local_instance_state::fastpath_evidence_consumed_key(
        &chain(),
        evidence.epoch,
        *bond.validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    let marker = slash::EvidenceConsumptionRecord {
        validator_id: bond.validator_id,
        evidence_epoch: evidence.epoch,
        conflict_digest,
        generation: bond.generation + 1,
        consumed_at_checkpoint: 1,
    };
    put_unconditionally(
        &store,
        consumed_key,
        slash::encode_evidence_consumption_record(&marker).unwrap(),
    );

    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0x97; 32];
    let (intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();
    let error = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &intent_bytes,
        20,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("evidence already consumed")
    ));
    // Nothing committed: the bond row is untouched.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
}

/// Forces the installed bond row into `Jailed` with an arbitrary evidence
/// digest, as if a prior slash had already completed, so `Reactivate` tests
/// do not each need to replay a full evidence-submission-and-slash cycle
/// first.
fn force_jailed<S: StructuredDurableDomainStateStore>(
    store: &S,
    bond: &FastPathBondRecord,
) -> FastPathBondRecord {
    let mut jailed = bond.clone();
    jailed.state = FastPathBondState::Jailed {
        evidence_digest: ev_digest(0xAA),
    };
    put_bond(store, &jailed);
    jailed
}

#[test]
fn reactivate_transitions_jailed_to_active_with_real_wasm_execution() {
    let object_id = ObjectId::new([0x98; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_jailed(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0x99; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 7_000, sender(), [0x9A; 32]);

    let scope = custody_scope_of(&bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0x9B; 32];
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
    let mut next = predicted_next(&bond, 25, protocol().epoch());
    next.custody_object = oref;
    next.custody_object_epoch = next.lifecycle_epoch;
    next.slashable_from_epoch = Epoch::new(next.lifecycle_epoch.get() + 1);
    next.authority = source_authority;
    next.amount = 7_000;
    next.required_minimum = 100;
    next.state = FastPathBondState::Active;

    let intent = base_intent(
        &protocol(),
        request_id,
        &bond,
        &next,
        BondLifecycleOperation::Reactivate { leg },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &protocol(), &leg_policy(), 25).unwrap();
    let committed = decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(committed, next);
    assert_eq!(committed.state, FastPathBondState::Active);
    assert_eq!(committed.amount, 7_000);
    assert_eq!(committed.custody_object.id, new_object.id);
}

#[test]
fn every_bond_lifecycle_operation_except_reactivate_rejects_a_jailed_bond() {
    let object_id = ObjectId::new([0x9C; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = force_jailed(&store, &get_bond(&store, ValidatorId::new(sender())));

    let recipient = canonical_address(0x9D);
    let mut next = predicted_next(&bond, 30, protocol().epoch());
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &protocol(),
        [0x9E; 32],
        &bond,
        &next,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    let error = call(&store, &signed, &protocol(), &leg_policy(), 30).unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("bond is jailed")
    ));
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), bond);
}

/// A real genesis install immediately followed by one real evidence-driven
/// slash, all on `store` -- the common starting point for the restart-verify
/// `ConsumedEvidence` branch tests below.
fn build_slashed_chain() -> (MemoryDurableStateStore, genesis::GenesisManifest) {
    let object_id = ObjectId::new([0xA0; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0xA1; 32];
    let (intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();
    slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &intent_bytes,
        20,
    )
    .unwrap();
    (store, manifest)
}

#[test]
fn restart_reverifies_a_real_evidence_driven_slash_transition() {
    let (store, manifest) = build_slashed_chain();
    let outcome = genesis::install_genesis_with_history(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &[],
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
fn restart_rejects_a_tampered_consumed_evidence_marker_after_a_slash() {
    let (store, manifest) = build_slashed_chain();
    let jailed_bond = get_bond(&store, ValidatorId::new(sender()));
    let evidence_digest = match jailed_bond.state {
        FastPathBondState::Jailed { evidence_digest } => evidence_digest,
        _ => panic!("expected a jailed bond"),
    };
    let consumed_key = local_instance_state::fastpath_evidence_consumed_key(
        &chain(),
        protocol().epoch(),
        sender(),
        evidence_digest,
    )
    .unwrap();
    delete_unconditionally(&store, consumed_key);
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_tampered_evidence_bytes_inside_the_retained_transition() {
    let (store, manifest) = build_slashed_chain();
    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    match &mut transition.authorization {
        BondTransitionAuthorization::ConsumedEvidence { evidence_bytes, .. } => {
            let last = evidence_bytes.len() - 1;
            evidence_bytes[last] ^= 0xFF;
        }
        BondTransitionAuthorization::ValidatorEnvelope { .. } => {
            panic!("expected a consumed-evidence authorization")
        }
    }
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

/// Shared scaffold for the `ConsumedEvidence` per-field tamper tests below:
/// a single bit flip inside exactly one of the retained forfeiture leg,
/// previous object or resulting object, leaving every other retained byte
/// (including the installed singleton and `current_row_digest`) untouched.
fn tampered_evidence_authorization_fails_closed(
    mutate: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>),
) {
    let (store, manifest) = build_slashed_chain();
    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    match &mut transition.authorization {
        BondTransitionAuthorization::ConsumedEvidence {
            forfeiture_leg,
            previous_object,
            resulting_object,
            ..
        } => mutate(forfeiture_leg, previous_object, resulting_object),
        BondTransitionAuthorization::ValidatorEnvelope { .. } => {
            panic!("expected a consumed-evidence authorization")
        }
    }
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    assert_restart_fails_closed(&store, &manifest);
}

/// A tampered retained forfeiture leg fails the leg's own re-authenticated
/// signature (structural closure item 1: the leg is now authenticated on
/// restart, not merely ignored via `forfeiture_leg: _`).
#[test]
fn restart_rejects_a_tampered_forfeiture_leg_inside_the_retained_transition() {
    tampered_evidence_authorization_fails_closed(|leg, _, _| {
        let last = leg.len() - 1;
        leg[last] ^= 0xFF;
    });
}

/// A tampered retained previous-object body no longer hashes to the
/// (untouched) previous row's own `custody_object` digest.
#[test]
fn restart_rejects_a_tampered_previous_object_inside_the_retained_transition() {
    tampered_evidence_authorization_fails_closed(|_, previous_object, _| {
        let last = previous_object.len() - 1;
        previous_object[last] ^= 0xFF;
    });
}

/// A tampered retained resulting-object body no longer hashes to the
/// (untouched) resulting row's own `custody_object` digest.
#[test]
fn restart_rejects_a_tampered_resulting_object_inside_the_retained_transition() {
    tampered_evidence_authorization_fails_closed(|_, _, resulting_object| {
        let last = resulting_object.len() - 1;
        resulting_object[last] ^= 0xFF;
    });
}

/// Shared scaffold for the fully coordinated `ConsumedEvidence` rewrite
/// tests below: `mutate` tampers the resulting row, and both
/// `transition.current_row_digest` and the installed singleton are rewritten
/// to match -- exactly the "coordinated rewrite of resulting_row/
/// current_row_digest/final bond" this unit's restart fix closes. A
/// self-consistency check alone (current row bytes hash to
/// `current_row_digest`) would wrongly pass; only the independently
/// recomputed resulting `ObjectRef` and the previous-row-copied fields
/// (never signed by anyone for evidence-driven forfeiture) catch this.
fn coordinated_slash_row_rewrite_fails_closed(mutate: impl FnOnce(&mut FastPathBondRecord)) {
    coordinated_slash_row_rewrite_fails_closed_on(build_slashed_chain(), mutate);
}

/// Like [`coordinated_slash_row_rewrite_fails_closed`], but against an
/// arbitrary already-slashed `(store, manifest)` chain rather than always
/// [`build_slashed_chain`]'s genesis-epoch one -- used by the
/// `custody_object_epoch` variant below, which needs a slash that committed
/// strictly after `context.epoch()` for there to be any independently
/// tamperable value between it and `lifecycle_epoch` in the first place.
fn coordinated_slash_row_rewrite_fails_closed_on(
    (store, manifest): (MemoryDurableStateStore, genesis::GenesisManifest),
    mutate: impl FnOnce(&mut FastPathBondRecord),
) {
    let transition_key =
        fastpath_bond_transition_key(&chain(), &ValidatorId::new(sender()), 2).unwrap();
    let bond_key =
        local_instance_state::fastpath_bond_record_key(&chain(), &ValidatorId::new(sender()))
            .unwrap();
    let observed = store
        .get_versioned_durable(&context(1), domain(), &transition_key)
        .unwrap();
    let mut transition = decode_fastpath_bond_transition_record(observed.value().unwrap()).unwrap();
    let mut tampered_row: FastPathBondRecord =
        decode_fastpath_bond_record(&transition.resulting_row).unwrap();
    mutate(&mut tampered_row);
    let tampered_row_bytes: Vec<u8> =
        crate::fast_path::records::encode_fastpath_bond_record(&tampered_row).unwrap();
    transition.resulting_row = tampered_row_bytes.clone();
    transition.current_row_digest = bond_row_digest(
        &resolver(),
        tampered_row.lifecycle_epoch,
        &tampered_row_bytes,
    )
    .unwrap();
    put_unconditionally(
        &store,
        transition_key,
        crate::fast_path::records::encode_fastpath_bond_transition_record(&transition).unwrap(),
    );
    put_unconditionally(&store, bond_key, tampered_row_bytes);
    assert_restart_fails_closed(&store, &manifest);
}

#[test]
fn restart_rejects_a_coordinated_rewrite_of_slash_amount() {
    coordinated_slash_row_rewrite_fails_closed(|row| row.amount += 1);
}

#[test]
fn restart_rejects_a_coordinated_rewrite_of_slash_custody_object() {
    coordinated_slash_row_rewrite_fails_closed(|row| row.custody_object.version += 1);
}

#[test]
fn restart_rejects_a_coordinated_rewrite_of_slash_lifecycle_epoch() {
    coordinated_slash_row_rewrite_fails_closed(|row| {
        row.lifecycle_epoch = Epoch::new(row.lifecycle_epoch.get() + 1);
    });
}

/// `slashable_from_epoch` is preserved unchanged as audit data across a
/// `Slash`: a coordinated rewrite that bumps it (even though the row is no
/// longer live collateral) must still fail closed, since restart's
/// `ConsumedEvidence` branch cross-checks it against the previous row
/// exactly like every other copied-unchanged field.
#[test]
fn restart_rejects_a_coordinated_rewrite_of_slash_slashable_from_epoch() {
    coordinated_slash_row_rewrite_fails_closed(|row| {
        row.slashable_from_epoch = Epoch::new(row.slashable_from_epoch.get() + 1);
    });
}

// ── DR-0137 unit 3: multi-epoch liability-floor / custody-object-epoch
// end-to-end coverage ───────────────────────────────────────────────────

/// Legitimately advances the committed fast-path epoch by exactly one, via a
/// real single-validator (1-of-1 quorum) DR-0132 `propose_and_vote`/
/// `activate` cycle that re-elects the identical genesis validator (still
/// `Active`, hence eligible). Unlike `fast_path::install_validator_set` (a
/// raw epoch-record overwrite this module also uses elsewhere, for tests
/// that never restart-verify across the bump), this installs a real
/// permanent `FastPathEpochTransitionRecord` plus the real activation-set
/// rows (validator set, execution/fee/publication policy) at the new epoch,
/// so a later `genesis::install_genesis` can walk the real DR-0132 chain
/// across it and a later real leg execution finds its policy durably
/// installed. Returns the new current epoch's `PublicationContext`.
fn advance_epoch<S: StructuredDurableDomainStateStore>(
    store: &S,
    resolver: &HashSuiteResolver,
    current_epoch: Epoch,
    checkpoint: u64,
) -> PublicationContext {
    let entries = vec![crate::fast_path::records::FastPathValidatorEntry {
        id: ValidatorId::new(sender()),
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: sender().to_vec(),
    }];
    let signer = FixedKeySigner(key());
    let vote = crate::epoch_transition::propose_and_vote(
        store,
        &context(1),
        domain(),
        resolver,
        &chain(),
        protocol().protocol_version(),
        entries.clone(),
        &signer,
    )
    .unwrap();
    let outgoing_validator_set: ValidatorSet = ValidatorSet::new(
        current_epoch,
        vec![validator_set::ValidatorInfo {
            id: ValidatorId::new(sender()),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: sender().to_vec(),
        }],
    )
    .unwrap();
    let certifier = consensus::EpochTransitionCertifier::new(
        chain(),
        protocol().protocol_version(),
        current_epoch,
        outgoing_validator_set,
    )
    .unwrap();
    let certificate = certifier
        .try_form_certificate(
            vote.next_epoch,
            vote.current_validator_set_digest,
            vote.next_validator_set_digest,
            vote.activation_digest,
            std::slice::from_ref(&vote),
            &fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("the single equal-power validator exceeds quorum");
    let certificate_bytes = consensus::encode_epoch_transition_certificate(&certificate).unwrap();
    crate::epoch_transition::activate(
        store,
        &context(1),
        domain(),
        resolver,
        &chain(),
        protocol().protocol_version(),
        entries,
        &certificate_bytes,
        checkpoint,
    )
    .unwrap();
    PublicationContext::new(chain(), protocol().protocol_version(), vote.next_epoch).unwrap()
}

/// DR-0137 unit 3's core liability-floor fix, end to end: real DR-0133
/// evidence recorded at genesis epoch `E`, a real `Unbond` committing
/// strictly later at `E + 1` through a real DR-0132 epoch bump (which
/// advances `lifecycle_epoch` to `E + 1` while carrying
/// `slashable_from_epoch`/`custody_object_epoch` forward from genesis
/// unchanged), a real evidence-driven `Slash` while the bond is `Unbonding`
/// that still succeeds using the old evidence, and a full genesis restart
/// re-verification of the complete chain (genesis -> epoch bump -> Unbond ->
/// Slash). A naive `evidence_epoch >= lifecycle_epoch` gate -- the bug
/// `slashable_from_epoch` fixes -- would have rejected this exact slash,
/// since the evidence's epoch `E` is strictly less than the bond's
/// `lifecycle_epoch` of `E + 1` by the time it is slashed.
#[test]
fn slash_survives_an_intervening_unbond_using_evidence_older_than_the_unbond() {
    let object_id = ObjectId::new([0xE2; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let genesis_bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(genesis_bond.state, FastPathBondState::Active);

    // Evidence at genesis epoch `E`.
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    assert_eq!(evidence.epoch, genesis_bond.slashable_from_epoch);

    // A real DR-0132 epoch bump to `E + 1`, re-electing the identical
    // validator (still `Active`, so it remains eligible).
    let next_context = advance_epoch(&store, &resolver(), protocol().epoch(), 16);
    assert_eq!(next_context.epoch().get(), protocol().epoch().get() + 1);

    // `Unbond` commits at `E + 1`: `lifecycle_epoch` advances, but
    // `slashable_from_epoch`/`custody_object_epoch` are carried forward
    // unchanged (no leg execution at all, so no policy row is needed).
    let unbond_leg_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    let recipient = canonical_address(0xE3);
    let mut unbonding = predicted_next(&genesis_bond, 17, next_context.epoch());
    unbonding.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(next_context.epoch().get() + 7),
        recipient: *recipient.as_bytes(),
    };
    let intent = base_intent(
        &next_context,
        [0xE4; 32],
        &genesis_bond,
        &unbonding,
        BondLifecycleOperation::Unbond { recipient },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &next_context, &unbond_leg_policy, 17).unwrap();
    let unbonding_bond =
        decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(unbonding_bond, unbonding);
    assert_eq!(unbonding_bond.lifecycle_epoch, next_context.epoch());
    assert_eq!(
        unbonding_bond.slashable_from_epoch,
        genesis_bond.slashable_from_epoch
    );
    assert_eq!(
        unbonding_bond.custody_object_epoch,
        genesis_bond.custody_object_epoch
    );

    // The evidence-driven `Slash`, committing at `E + 1` too, still succeeds
    // using the evidence recorded back at genesis epoch `E`: gating on
    // `slashable_from_epoch` (unchanged since genesis), never on the
    // now-advanced `lifecycle_epoch`.
    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let (slash_intent, ..) = build_slash_intent(
        &fixture,
        &next_context,
        &unbonding_bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        [0xE5; 32],
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();
    let slash_output = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &next_context,
        &unbond_leg_policy,
        &engine(),
        &slash_intent_bytes,
        18,
    )
    .unwrap();
    let jailed =
        decode_fastpath_bond_record(slash_output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(
        jailed.state,
        FastPathBondState::Jailed {
            evidence_digest: conflict_digest
        }
    );
    assert_eq!(
        jailed.slashable_from_epoch,
        genesis_bond.slashable_from_epoch
    );
    assert_eq!(jailed.amount, genesis_bond.amount);

    // Full genesis restart re-verification of the complete chain, across the
    // real DR-0132 epoch bump.
    let outcome =
        genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
            .unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
}

/// The `Replace` sibling of
/// [`slash_survives_an_intervening_unbond_using_evidence_older_than_the_unbond`]:
/// evidence at genesis epoch `E`, a real `Replace` swapping in fresh
/// collateral one real DR-0132 epoch bump later at `E + 1` (which mints a
/// brand-new custody object -- `custody_object_epoch` *does* advance here,
/// unlike `Unbond` -- while still preserving `slashable_from_epoch`
/// unchanged: liability provenance survives a same-state collateral swap), a
/// real evidence-driven `Slash` of the *replaced* collateral using the old
/// evidence, and a full genesis restart re-verification. The `Replace` here
/// also raises the amount (1_000_000 -> 1_300_000), so this doubles as
/// coverage that a legitimate non-decreasing `Replace` still leaves the
/// *entire* new replacement amount forfeitable by pre-existing evidence --
/// not merely the smaller amount that was actually live when the evidence
/// arose.
#[test]
fn slash_survives_an_intervening_replace_using_evidence_older_than_the_replace() {
    let object_id = ObjectId::new([0xE6; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let genesis_bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(genesis_bond.state, FastPathBondState::Active);

    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    assert_eq!(evidence.epoch, genesis_bond.slashable_from_epoch);

    let next_context = advance_epoch(&store, &resolver(), protocol().epoch(), 16);

    let fixture = build_fixture();
    let new_source_id = ObjectId::new([0xE7; 32]);
    let (new_source_object, new_source_authority) = seed_owned_coin(
        &store,
        &fixture,
        new_source_id,
        1_300_000,
        sender(),
        [0xE8; 32],
    );
    let scope = custody_scope_of(&genesis_bond);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &next_context,
        new_source_id,
        &scope,
    )
    .unwrap();
    let release_recipient = canonical_address(0xE9);
    let replace_request_id: [u8; 32] = [0xEA; 32];
    let deposit_leg = transfer_leg(
        &fixture,
        next_context.clone(),
        object_ref(&resolver(), &new_source_object),
        sender(),
        0,
        replace_request_id,
        token,
    );
    let release_leg = transfer_leg(
        &fixture,
        next_context.clone(),
        genesis_bond.custody_object.clone(),
        sender(),
        1,
        replace_request_id,
        *release_recipient.as_bytes(),
    );
    let (new_custody_object, new_custody_ref) = transferred(
        &new_source_object,
        Owner::ProtocolCustody(scope.clone()),
        next_context.epoch(),
    );
    let mut replaced = predicted_next(&genesis_bond, 17, next_context.epoch());
    replaced.custody_object = new_custody_ref;
    replaced.custody_object_epoch = replaced.lifecycle_epoch;
    replaced.authority = new_source_authority;
    replaced.amount = 1_300_000;
    replaced.required_minimum = 100;
    replaced.state = FastPathBondState::Active;
    let replace_intent = base_intent(
        &next_context,
        replace_request_id,
        &genesis_bond,
        &replaced,
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            release_recipient,
        },
    );
    let signed = signed_envelope(replace_intent, &key());
    let replace_leg_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    let output = call(&store, &signed, &next_context, &replace_leg_policy, 17).unwrap();
    let replaced_bond =
        decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(replaced_bond, replaced);
    assert_eq!(
        replaced_bond.slashable_from_epoch,
        genesis_bond.slashable_from_epoch
    );
    assert_eq!(replaced_bond.lifecycle_epoch, next_context.epoch());
    assert_eq!(replaced_bond.custody_object_epoch, next_context.epoch());

    // Slash the replaced collateral using the OLD (pre-`Replace`) evidence:
    // gating on `slashable_from_epoch`, preserved unchanged across the
    // collateral swap.
    // `sender()` already spent nonces 0 and 1 on the `Replace`'s own two legs
    // at `next_context`'s epoch; the forfeiture leg is the third.
    let (slash_intent, ..) = build_slash_intent_at_nonce(
        &fixture,
        &next_context,
        &replaced_bond,
        &new_custody_object,
        evidence.epoch,
        conflict_digest,
        [0xEB; 32],
        2,
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();
    let slash_output = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &next_context,
        &replace_leg_policy,
        &engine(),
        &slash_intent_bytes,
        18,
    )
    .unwrap();
    let jailed =
        decode_fastpath_bond_record(slash_output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(
        jailed.state,
        FastPathBondState::Jailed {
            evidence_digest: conflict_digest
        }
    );
    assert_eq!(
        jailed.slashable_from_epoch,
        genesis_bond.slashable_from_epoch
    );
    assert_eq!(jailed.amount, 1_300_000);

    let outcome =
        genesis::install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10)
            .unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
}

/// A [`HashSuiteResolver`] whose schedule matches [`resolver`] exactly up to
/// `rotation_epoch` (identical `HashSuite::genesis()` from epoch 0), then
/// rotates to a distinct suite (a different id and object-digest algorithm)
/// from `rotation_epoch` onward -- for proving that restart hashes a bond's
/// previous custody object at its own recorded `custody_object_epoch`,
/// never at the transitioning epoch.
fn rotating_resolver(rotation_epoch: u64) -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(3),
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
    .unwrap()
}

/// Proves `custody_object_epoch` is actually load-bearing, not merely
/// stored: a hash-suite rotation activates exactly at the same epoch `E + 1`
/// an `Unbond` and a later evidence-driven `Slash` commit at, using evidence
/// recorded back at genesis epoch `E`. The bond row's own
/// `lifecycle_epoch`/`current_row_digest` hashing correctly moves to the new
/// suite (Sha3-256) at `E + 1`, while the *custody object*'s digest --
/// pinned to `custody_object_epoch`, which `Unbond` carries forward
/// unchanged from genesis -- must still be recomputed under the *old* suite
/// (Sha2-256) at restart, and the freshly forfeited object minted by the
/// `Slash` itself must be recomputed under the *new* suite at its own
/// committing epoch. Restart succeeding here is only possible if
/// `genesis::verify_fastpath_bond_chain` hashes each object at its own
/// recorded epoch rather than uniformly at the transitioning epoch.
#[test]
fn restart_reverifies_a_slash_across_a_hash_suite_rotation_using_custody_object_epoch() {
    let object_id = ObjectId::new([0xEC; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    let rotation_epoch: u64 = protocol().epoch().get() + 1;
    let resolver = rotating_resolver(rotation_epoch);
    genesis::install_genesis(&store, &context(1), domain(), &resolver, &manifest, 10).unwrap();
    let genesis_bond = get_bond(&store, ValidatorId::new(sender()));
    assert_eq!(genesis_bond.state, FastPathBondState::Active);

    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);

    // The epoch bump itself lands exactly on the rotation boundary: the
    // certificate/activation-set digests it forms are already hashed under
    // the new suite.
    let next_context = advance_epoch(&store, &resolver, protocol().epoch(), 16);
    assert_eq!(next_context.epoch().get(), rotation_epoch);

    let unbond_leg_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    let recipient = canonical_address(0xED);
    let mut unbonding = predicted_next(&genesis_bond, 17, next_context.epoch());
    unbonding.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(next_context.epoch().get() + 7),
        recipient: *recipient.as_bytes(),
    };
    let unbond_intent = BondLifecycleIntent {
        context: next_context.clone(),
        request_id: [0xEE; 32],
        validator_id: genesis_bond.validator_id,
        resource_id: resource_id_of(&genesis_bond),
        expected_generation: genesis_bond.generation,
        expected_previous_row_digest: bond_row_digest(
            &resolver,
            genesis_bond.lifecycle_epoch,
            &crate::fast_path::records::encode_fastpath_bond_record(&genesis_bond).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_row_digest(
            &resolver,
            unbonding.lifecycle_epoch,
            &crate::fast_path::records::encode_fastpath_bond_record(&unbonding).unwrap(),
        )
        .unwrap(),
        operation: BondLifecycleOperation::Unbond { recipient },
    };
    let intent_digest = bond_lifecycle_intent_digest(&resolver, &unbond_intent).unwrap();
    let frame = bond_lifecycle_signing_frame(&unbond_intent.context, intent_digest).unwrap();
    let signed = SignedBondLifecycleIntent {
        signature: key().sign(&frame).into(),
        intent: unbond_intent,
    };
    let output = handle_bond_lifecycle(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver,
        &[],
        &next_context,
        &unbond_leg_policy,
        &engine(),
        &encode_signed_bond_lifecycle_intent(&signed).unwrap(),
        17,
    )
    .unwrap();
    let unbonding_bond =
        decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(unbonding_bond, unbonding);
    // `custody_object_epoch` stayed at genesis epoch, strictly before the
    // rotation: the object's own durable digest is still a Sha2-256 digest.
    assert_eq!(
        unbonding_bond.custody_object_epoch,
        genesis_bond.custody_object_epoch
    );
    assert!(unbonding_bond.custody_object_epoch.get() < rotation_epoch);

    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let target_scope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::ForfeitedCollateral,
        chain_id: unbonding_bond.context.chain_id().clone(),
        subject: *unbonding_bond.validator_id.as_bytes(),
        resource: unbonding_bond.resource,
    };
    let forfeit_token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver,
        &next_context,
        unbonding_bond.custody_object.id,
        &target_scope,
    )
    .unwrap();
    let slash_request_id: [u8; 32] = [0xEF; 32];
    let leg = transfer_leg_with_resolver(
        &resolver,
        &fixture,
        next_context.clone(),
        object_ref_at(
            &resolver,
            &custody_object,
            unbonding_bond.custody_object_epoch,
        ),
        sender(),
        0,
        slash_request_id,
        forfeit_token,
    );
    let slash_intent = slash::SlashIntent {
        context: next_context.clone(),
        request_id: slash_request_id,
        validator_id: unbonding_bond.validator_id,
        resource_id: resource_id_of(&unbonding_bond),
        expected_generation: unbonding_bond.generation,
        evidence_epoch: evidence.epoch,
        conflict_digest,
        leg,
    };
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();
    let slash_output = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver,
        &[],
        &next_context,
        &unbond_leg_policy,
        &engine(),
        &slash_intent_bytes,
        18,
    )
    .unwrap();
    let jailed =
        decode_fastpath_bond_record(slash_output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(
        jailed.state,
        FastPathBondState::Jailed {
            evidence_digest: conflict_digest
        }
    );
    // The freshly forfeited object is minted at the slash's own (rotated)
    // committing epoch.
    assert_eq!(jailed.custody_object_epoch, next_context.epoch());
    assert_eq!(jailed.custody_object_epoch.get(), rotation_epoch);

    // Full genesis restart re-verification: only possible if the previous
    // custody object is independently rehashed at its own recorded
    // `custody_object_epoch` (pre-rotation, Sha2-256) rather than uniformly
    // at each transition's own committing epoch (post-rotation, Sha3-256).
    let outcome =
        genesis::install_genesis(&store, &context(1), domain(), &resolver, &manifest, 10).unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
}

/// DR-0137 unit 3: a freshly `Deposit`ed bond's liability floor
/// (`slashable_from_epoch == committing epoch + 1`) actually gates real
/// evidence-driven forfeiture, not merely a stored value: real evidence
/// dated at or before the deposit itself cannot slash it, even though it is
/// exactly the genesis validator's own equivocation evidence and would
/// freely slash the *genesis* generation of the identical bond (see
/// `slash_forfeits_the_bond_and_jails_the_validator_with_real_wasm_execution`).
/// `Reactivate` shares this exact code path
/// (`bond_lifecycle::deposit_or_reactivate`) and the identical
/// unconditional `committing epoch + 1` floor -- see
/// `reactivate_transitions_jailed_to_active_with_real_wasm_execution`, which
/// already asserts the same floor value for that path -- so this one focused
/// negative test covers both entry points rather than duplicating it.
#[test]
fn fresh_deposit_liability_floor_rejects_evidence_no_newer_than_the_deposit_itself() {
    let object_id = ObjectId::new([0xF0; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let exited = force_exited(&store, &get_bond(&store, ValidatorId::new(sender())));

    let fixture = build_fixture();
    let source_id = ObjectId::new([0xF1; 32]);
    let (source_object, source_authority) =
        seed_owned_coin(&store, &fixture, source_id, 5_000, sender(), [0xF2; 32]);
    let scope = custody_scope_of(&exited);
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &resolver(),
        &protocol(),
        source_id,
        &scope,
    )
    .unwrap();
    let request_id: [u8; 32] = [0xF3; 32];
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
    let mut deposited = predicted_next(&exited, 20, protocol().epoch());
    deposited.custody_object = oref;
    deposited.custody_object_epoch = deposited.lifecycle_epoch;
    deposited.slashable_from_epoch = Epoch::new(deposited.lifecycle_epoch.get() + 1);
    deposited.authority = source_authority;
    deposited.amount = 5_000;
    deposited.required_minimum = 100;
    deposited.state = FastPathBondState::Active;
    let intent = base_intent(
        &protocol(),
        request_id,
        &exited,
        &deposited,
        BondLifecycleOperation::Deposit { leg },
    );
    let signed = signed_envelope(intent, &key());
    let output = call(&store, &signed, &protocol(), &leg_policy(), 20).unwrap();
    let deposited_bond =
        decode_fastpath_bond_record(output.responses()[0].payload().unwrap()).unwrap();
    assert_eq!(deposited_bond, deposited);
    assert_eq!(
        deposited_bond.slashable_from_epoch,
        Epoch::new(protocol().epoch().get() + 1)
    );

    // Real evidence dated at the deposit's own committing epoch: strictly
    // older than the fresh floor.
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 21);
    assert_eq!(evidence.epoch, protocol().epoch());
    assert!(evidence.epoch.get() < deposited_bond.slashable_from_epoch.get());

    let (slash_intent, ..) = build_slash_intent(
        &fixture,
        &protocol(),
        &deposited_bond,
        &new_object,
        evidence.epoch,
        conflict_digest,
        [0xF4; 32],
    );
    let slash_intent_bytes = slash::encode_slash_intent(&slash_intent).unwrap();
    let error = slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &leg_policy(),
        &engine(),
        &slash_intent_bytes,
        22,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        BondLifecycleError::Invalid("evidence epoch predates the bond's slashable-from epoch")
    ));
    // Nothing committed: the freshly deposited bond row is untouched.
    assert_eq!(get_bond(&store, ValidatorId::new(sender())), deposited_bond);
}

/// Like [`build_slashed_chain`], but the real evidence-driven slash commits
/// one real DR-0132 epoch bump after genesis (`E + 1`) rather than at
/// genesis epoch `E` itself, using evidence recorded back at `E` -- giving
/// the resulting `Jailed` row's `lifecycle_epoch`/`custody_object_epoch`
/// (both pinned to the slash's own committing epoch, per `handle_bond_slash`)
/// room strictly above `context.epoch()` (genesis epoch `E`) to
/// independently tamper `custody_object_epoch` alone without first tripping
/// `encode_fastpath_bond_record`'s own `custody_object_epoch <=
/// lifecycle_epoch` invariant.
fn build_slashed_chain_at_the_next_epoch() -> (MemoryDurableStateStore, genesis::GenesisManifest) {
    let object_id = ObjectId::new([0xF5; 32]);
    let manifest = manifest_with_custody(object_id);
    let store = store();
    install(&store, &manifest);
    let bond = get_bond(&store, ValidatorId::new(sender()));
    let (evidence, conflict_digest) = record_class_a_evidence(&store, 15);
    let next_context = advance_epoch(&store, &resolver(), protocol().epoch(), 16);
    let fixture = build_fixture();
    let custody_object = custody_object_entry(&manifest, object_id, chain()).object;
    let request_id: [u8; 32] = [0xF6; 32];
    let (intent, ..) = build_slash_intent(
        &fixture,
        &next_context,
        &bond,
        &custody_object,
        evidence.epoch,
        conflict_digest,
        request_id,
    );
    let intent_bytes = slash::encode_slash_intent(&intent).unwrap();
    let leg_policy = LocalExecutionPolicy::generic_object_results(next_context.clone());
    slash::handle_bond_slash(
        &store,
        &MemoryBlobStore::default(),
        &context(1),
        domain(),
        &resolver(),
        &[],
        &next_context,
        &leg_policy,
        &engine(),
        &intent_bytes,
        20,
    )
    .unwrap();
    (store, manifest)
}

/// `custody_object_epoch` must equal exactly this transition's own
/// committing epoch (the forfeiture leg mints the resulting
/// `ForfeitedCollateral` object here): a coordinated rewrite that moves it
/// down within its otherwise-locally-valid `[context.epoch(),
/// lifecycle_epoch]` range -- using a slash that committed one real DR-0132
/// epoch after genesis, so that range is nonempty -- must still fail closed,
/// since restart's `ConsumedEvidence` branch requires it to equal
/// `transition.context.epoch()` exactly, not merely satisfy
/// `encode_fastpath_bond_record`'s own looser bound.
#[test]
fn restart_rejects_a_coordinated_rewrite_of_slash_custody_object_epoch() {
    coordinated_slash_row_rewrite_fails_closed_on(build_slashed_chain_at_the_next_epoch(), |row| {
        row.custody_object_epoch = Epoch::new(row.custody_object_epoch.get() - 1);
    });
}
