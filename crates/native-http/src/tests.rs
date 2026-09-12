mod local_execution_http;
use super::*;
use abi::{AccessEntry, AccessManifest};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use canonical_encoding::{CanonicalDecodingError, CanonicalStruct, decode_canonical_frame};
use crypto::{Ed25519OwnerAddressError, SignatureDomain, SignatureMessageType};
use execution::{Transaction, decode_transaction, encode_transaction, encode_transaction_signable};
use node_core::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_CHAIN_ID_BYTES, NodeDedupRecord, NodeOutboxDelivery,
    NodeOutput, NodeResponse, NodeResponseStatus, NodeStateAccess, NodeStateAccessMode,
    NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate, OutboundMessage,
    PreinstalledModuleCatalogEntry, PreinstalledModuleSemanticsEnvelope,
    TransactionalNodeTransition, encode_preinstalled_semantics_envelope,
    handle_resolved_durable_idempotent_event,
};
use objects::{
    AccessMode, Address, Object, ObjectId, ObjectRef, Owner, decode_object, encode_object,
};
use protocol_config::TransactionAuthProfile;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteId,
    HashSuiteSchedule, ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
    AtomicStateWriteSet, CompareAndSwapResult, ComposedRuntime, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectPayload,
    DurableObjectProvenance, DurableObjectRoutingProjection, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOutboxClaim, DurableReadError, DurableRequestId,
    DurableRequestReceipt, IndexedOutboxRepository, ManualClock, MemoryBlobStore,
    MemoryDurableStateStore, MemoryRuntime, MemoryScheduler, MemorySigner, MemoryStateStore,
    MemoryTransport, ObjectHeadRevision, OutboxRequestId, RequestOutboxClaimRequest, RuntimeError,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StateStore,
    StructuredDurableDomainStateStore, SystemClock, TransactionalStateStore, Transport,
    VersionedStateValue,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace, SqliteStateStore};
use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use system_modules::{
    GasModel, ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
    SystemModuleRegistry, TypeSchema, encode_system_module_manifest,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, oneshot},
};
use tower::ServiceExt;

const TEST_STATE_TYPE_ID: u16 = 0xEF11;
const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF12;
static NEXT_DATABASE_PATH: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let nonce = NEXT_DATABASE_PATH.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sunrise-edge-native-recovery-{}-{nanos}-{nonce}.db",
            std::process::id()
        ));
        Self { path }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.as_os_str().to_owned();
            path.push(suffix);
            let path = PathBuf::from(path);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}

fn canonical(type_id: u16, value: u64) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(type_id, 1);
    frame.field_u64(1, value).unwrap();
    frame.finish().unwrap()
}

fn request_id(byte: u8) -> RequestId {
    RequestId::new([byte; 32]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn config() -> NodeConfig {
    NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        b"http/node-state".to_vec(),
    )
    .unwrap()
}

fn placement(byte: u8, activation_epoch: u64) -> DomainPlacementManifest {
    DomainPlacementManifest::single_domain(
        1,
        AtomicityDomainId::new([byte; 32]).unwrap(),
        Epoch::new(activation_epoch),
    )
    .unwrap()
}

/// A committed protocol configuration whose `protocol_version` matches
/// [`config`] and whose `transaction_auth_profile` is active, used to
/// compose [`structured_durable_router`].
fn active_protocol_config(domain: AtomicityDomainId) -> ProtocolConfig {
    let mut protocol_config = ProtocolConfig::genesis();
    protocol_config.protocol_version = ProtocolVersion::new(3);
    protocol_config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, domain, Epoch::new(0)).unwrap());
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_address_is_public_key());
    protocol_config
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn sqlite_runtime<T>(
    path: &std::path::Path,
    transport: T,
    now_unix_millis: u64,
) -> ComposedRuntime<SqliteStateStore, MemoryBlobStore, MemorySigner, T, ManualClock, MemoryScheduler>
{
    ComposedRuntime::new(
        SqliteStateStore::open(path).unwrap(),
        MemoryBlobStore::default(),
        MemorySigner::new(ValidatorId::new([0x44; 32])),
        transport,
        ManualClock::new(now_unix_millis),
        MemoryScheduler::default(),
    )
}

/// A generic, non-transaction event used by direct node-core/recovery
/// fixture setup. Native HTTP rejects this family at its external boundary.
fn event(request_id: RequestId) -> NodeEvent {
    NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id,
        node_core::NodeEventKind::ReceiveVote,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap()
}

fn externally_unsupported_event_kinds() -> [NodeEventKind; 7] {
    [
        NodeEventKind::ReceiveVote,
        NodeEventKind::ReceiveCertificate,
        NodeEventKind::ReceiveConsensusMessage,
        NodeEventKind::ApplyGovernanceCertificate,
        NodeEventKind::ApplyProtocolUpgrade,
        NodeEventKind::ApplyValidatorSetChange,
        NodeEventKind::Tick,
    ]
}

fn event_with_kind(request_id: RequestId, kind: NodeEventKind, chain_id: ChainId) -> NodeEvent {
    NodeEvent::new(
        chain_id,
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id,
        kind,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap()
}

/// Builds an unsigned `SubmitTransaction` `NodeEvent` carrying `payload`
/// verbatim, for tests that construct malformed or deliberately
/// mis-signed transaction bytes.
fn submit_transaction_event(request_id: RequestId, payload: Vec<u8>) -> NodeEvent {
    NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id,
        node_core::NodeEventKind::SubmitTransaction,
        payload,
    )
    .unwrap()
}

fn raw_submit_transaction_event_bytes(request_id: RequestId, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(0xE001, 1);
    frame.field_str(1, "sunrise-test").unwrap();
    frame.field_u32(2, 3).unwrap();
    frame.field_u64(3, 7).unwrap();
    frame
        .field_bytes(4, request_id.as_bytes().to_vec())
        .unwrap();
    frame
        .field_u16(5, NodeEventKind::SubmitTransaction.as_u16())
        .unwrap();
    frame.field_bytes(6, payload).unwrap();
    frame.finish().unwrap()
}

/// A dev-only deterministic Ed25519 signing key. Test infrastructure
/// only; mirrors `node_core::transaction_auth`'s test-only signer.
fn dev_signing_key(seed: u8) -> ed25519_zebra::SigningKey {
    ed25519_zebra::SigningKey::from([seed; 32])
}

fn dev_sender_address(signing_key: &ed25519_zebra::SigningKey) -> Address {
    let verification_key = ed25519_zebra::VerificationKey::from(signing_key);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(verification_key.as_ref());
    Address::new(bytes)
}

fn transaction_module_ref() -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([0u8; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0u8; 32]),
    }
}

fn unsigned_transaction(sender: Address, chain: ChainId, epoch: Epoch, nonce: u64) -> Transaction {
    Transaction {
        chain_id: chain,
        protocol_version: ProtocolVersion::new(3),
        epoch,
        sender,
        nonce,
        access_manifest: AccessManifest::new(),
        module_ref: transaction_module_ref(),
        entrypoint: "noop".to_string(),
        args: vec![1, 2, 3],
        gas_limit: 1_000,
        fee_payment: None,
        signature: Vec::new(),
    }
}

/// The exact production transaction-v1 signature domain, matching
/// `node_core::transaction_auth::authenticate_transaction_bytes`.
fn production_transaction_domain(chain: ChainId, epoch: Epoch) -> SignatureDomain {
    SignatureDomain {
        chain_id: chain,
        protocol_version: ProtocolVersion::new(3),
        epoch,
        message_type: SignatureMessageType::new("transaction-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    }
}

fn sign_under_domain(
    signing_key: &ed25519_zebra::SigningKey,
    domain: &SignatureDomain,
    signable: &[u8],
) -> Vec<u8> {
    let framed = crypto::frame_signature_message(domain, signable).unwrap();
    let signature = signing_key.sign(&framed);
    signature.to_bytes().to_vec()
}

/// Encodes `tx` signed for the exact production domain, matching what
/// `authenticate_transaction_bytes` itself verifies.
fn signed_transaction_bytes(signing_key: &ed25519_zebra::SigningKey, tx: &Transaction) -> Vec<u8> {
    let signable = encode_transaction_signable(tx).unwrap();
    let domain = production_transaction_domain(tx.chain_id.clone(), tx.epoch);
    let mut signed = tx.clone();
    signed.signature = sign_under_domain(signing_key, &domain, &signable);
    encode_transaction(&signed).unwrap()
}

fn signed_submission_transaction_bytes(
    signing_key: &ed25519_zebra::SigningKey,
    request_id: RequestId,
    tx: &Transaction,
) -> Vec<u8> {
    let transaction_signable: Vec<u8> = encode_transaction_signable(tx).unwrap();
    let signable: Vec<u8> =
        node_core::encode_submit_transaction_signable(request_id, &transaction_signable).unwrap();
    let domain = SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        message_type: SignatureMessageType::new(node_core::SUBMIT_TRANSACTION_V1_MESSAGE_TYPE)
            .unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    let mut signed: Transaction = tx.clone();
    signed.signature = sign_under_domain(signing_key, &domain, &signable);
    encode_transaction(&signed).unwrap()
}

/// A real, deterministically Ed25519-signed `SubmitTransaction`
/// `NodeEvent` that authenticates under [`active_protocol_config`] and
/// [`config`]'s trusted chain/epoch.
fn signed_submit_transaction_event(
    signing_key: &ed25519_zebra::SigningKey,
    request_id: RequestId,
    nonce: u64,
) -> NodeEvent {
    let sender = dev_sender_address(signing_key);
    let tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        nonce,
    );
    let bytes = signed_transaction_bytes(signing_key, &tx);
    submit_transaction_event(request_id, bytes)
}

// ── preinstalled WASM native HTTP composition ───────────────────────

/// A contract that overwrites `object[0]`'s data with a fixed byte,
/// matching `execution::wasm_engine`'s stable host ABI.
fn preinstalled_write_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\CA\FE")
            (func (export "run")
              (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))))"#,
    )
    .unwrap()
}

/// A contract that always traps via `abort`.
fn preinstalled_trap_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "http-preinstalled-trap-marker")
            (func (export "run")
              (call $abort (i32.const 0) (i32.const 30))))"#,
    )
    .unwrap()
}

fn preinstalled_manifest(module_id: ModuleId, max_input_size: u64) -> SystemModuleManifest {
    SystemModuleManifest {
        module_id,
        input_schema: TypeSchema {
            descriptor: "http.preinstalled.input.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        },
        output_schema: TypeSchema {
            descriptor: "http.preinstalled.output.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        },
        max_input_size,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    }
}

/// Builds a committed [`SystemModuleRegistry`] entry and a matching
/// [`node_core::PreinstalledModuleCatalog`] entry whose commitments
/// agree, plus the `ObjectRef` a transaction must declare as
/// `module_ref` to reference it. Every digest is computed from
/// `resolver`, matching
/// `node_core::preinstalled_wasm::resolve_preinstalled_module`'s exact
/// verification rules, rather than a pasted constant.
fn preinstalled_module_fixture(
    resolver: &HashSuiteResolver,
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    max_input_size: u64,
) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
    let manifest = preinstalled_manifest(module_id, max_input_size);
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::opaque_only(
            b"http-preinstalled-semantics-v1".to_vec(),
        )
        .unwrap();
    let semantics_bytes: Vec<u8> =
        encode_preinstalled_semantics_envelope(&semantics_envelope).unwrap();
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &semantics_bytes,
        )
        .unwrap();
    let code_hash = resolver
        .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, &wasm_bytes)
        .unwrap();
    let manifest_bytes = encode_system_module_manifest(&manifest).unwrap();
    let manifest_hash = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &manifest_bytes,
        )
        .unwrap();
    let module = SystemModule {
        module_id,
        version,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Active,
    };
    let mut registry = SystemModuleRegistry::new();
    registry.add_module(module).unwrap();
    let entry = PreinstalledModuleCatalogEntry::new(
        module_id,
        version,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .unwrap();
    let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
    let module_ref = ObjectRef {
        id: ObjectId::new(*module_id.as_bytes()),
        version,
        digest: code_hash,
    };
    (registry, catalog, module_ref)
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_wasm_transaction(
    sender: Address,
    chain: ChainId,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> Transaction {
    Transaction {
        chain_id: chain,
        protocol_version: ProtocolVersion::new(3),
        epoch,
        sender,
        nonce,
        access_manifest,
        module_ref,
        entrypoint: "run".to_string(),
        args,
        gas_limit: 1_000_000,
        fee_payment: None,
        signature: Vec::new(),
    }
}

/// A real, deterministically Ed25519-signed `SubmitTransaction`
/// `NodeEvent` invoking a preinstalled module, matching
/// [`signed_submit_transaction_event`]'s signing but with a caller-chosen
/// access manifest, module reference, and args.
fn signed_preinstalled_wasm_submit_transaction_event(
    signing_key: &ed25519_zebra::SigningKey,
    request_id: RequestId,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> NodeEvent {
    signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
        signing_key,
        request_id,
        nonce,
        access_manifest,
        module_ref,
        "run",
        args,
    )
}

/// Same as [`signed_preinstalled_wasm_submit_transaction_event`], with a
/// caller-chosen entrypoint name instead of the fixed `"run"` export.
#[allow(clippy::too_many_arguments)]
fn signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
    signing_key: &ed25519_zebra::SigningKey,
    request_id: RequestId,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    entrypoint: &str,
    args: Vec<u8>,
) -> NodeEvent {
    let sender = dev_sender_address(signing_key);
    let mut tx = preinstalled_wasm_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        nonce,
        access_manifest,
        module_ref,
        args,
    );
    tx.entrypoint = entrypoint.to_string();
    let bytes = signed_transaction_bytes(signing_key, &tx);
    submit_transaction_event(request_id, bytes)
}

/// A committed protocol configuration like [`active_protocol_config`],
/// additionally carrying `registry` as the committed system-module
/// registry a preinstalled-WASM call resolves `module_ref` against.
fn preinstalled_protocol_config(
    domain: AtomicityDomainId,
    registry: SystemModuleRegistry,
) -> ProtocolConfig {
    let mut protocol_config = active_protocol_config(domain);
    protocol_config.system_modules = registry;
    protocol_config
}

/// A [`DurableOperationContext`] deadline computed from real wall-clock
/// time, required by [`SqliteDurableStore`] (unlike [`MemoryDurableStateStore`],
/// it compares the deadline against actual `SystemTime::now()`, not a
/// settable virtual clock), matching `runtime-sqlite`'s own
/// `live_context` test helper.
fn live_operation_context(
    fence: WriterFenceGeneration,
    correlation_byte: u8,
) -> DurableOperationContext {
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now + 60_000).unwrap(),
        StorageCorrelationId::new([correlation_byte; 16]).unwrap(),
    )
}

/// Directly commits one address-owned inline object version and head as
/// fixture setup, bypassing every HTTP/node-core entrypoint, exactly like
/// `node_core`'s own `commit_memory_inline_object` test helper.
fn commit_owned_object<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef
where
    S: IndexedOutboxRepository,
{
    let object_id = object.id;
    let object_version = object.version;
    let owner = object.owner.clone();
    let canonical_bytes = encode_object(&object).unwrap();
    let chain_id = ChainId::new(chain).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let provenance = DurableObjectProvenance::new(chain_id, ProtocolVersion::new(3));
    let record = DurableObjectVersionRecord::from_inline_object(
        object,
        digest,
        provenance,
        created_checkpoint,
    )
    .unwrap();
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt_request_id: RequestId = request_id(receipt_byte);
    let receipt_event_digest: Digest32 = Digest32::new(
        HashAlgorithmId::Sha2_256,
        [receipt_byte.wrapping_add(1); 32],
    );
    let receipt_response: NodeResponse =
        NodeResponse::new(receipt_request_id, NodeResponseStatus::Accepted, None).unwrap();
    let receipt_record: NodeDedupRecord = NodeDedupRecord::new(
        receipt_request_id,
        receipt_event_digest,
        vec![receipt_response],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(*receipt_request_id.as_bytes()).unwrap(),
        receipt_event_digest,
        receipt_record.encode().unwrap(),
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    );
    ObjectRef {
        id: object_id,
        version: object_version,
        digest,
    }
}

/// A [`BlobStore`] test double that counts every [`BlobStore::get_blob`]
/// call, so an end-to-end HTTP composition test can prove the exact
/// supplied blob store (not some other default) served the request.
#[derive(Clone, Default)]
struct CountingBlobStore {
    blobs: Arc<std::sync::Mutex<std::collections::BTreeMap<Digest32, Vec<u8>>>>,
    get_calls: Arc<AtomicUsize>,
}

impl CountingBlobStore {
    fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }
}

impl BlobStore for CountingBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.blobs.lock().unwrap().insert(digest, bytes);
        Ok(())
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.blobs.lock().unwrap().get(digest).cloned())
    }
}

/// Directly commits one address-owned blob-backed object version and
/// head as fixture setup, bypassing every HTTP/node-core entrypoint,
/// exactly like [`commit_owned_object`] but with the canonical body
/// stored only in `blob_store`, keyed under its own content digest.
#[allow(clippy::too_many_arguments)]
fn commit_owned_blob_object<S>(
    store: &S,
    blob_store: &CountingBlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef
where
    S: IndexedOutboxRepository,
{
    let object_id = object.id;
    let object_version = object.version;
    let owner = object.owner.clone();
    let schema_version = object.schema_version;
    let canonical_bytes = encode_object(&object).unwrap();
    let chain_id = ChainId::new(chain).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    blob_store.put_blob(digest, canonical_bytes).unwrap();
    let provenance = DurableObjectProvenance::new(chain_id, ProtocolVersion::new(3));
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::new(object_version).unwrap(),
        digest,
        schema_version,
        provenance,
        created_checkpoint,
        digest,
    );
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt_request_id: RequestId = request_id(receipt_byte);
    let receipt_event_digest: Digest32 = Digest32::new(
        HashAlgorithmId::Sha2_256,
        [receipt_byte.wrapping_add(1); 32],
    );
    let receipt_response: NodeResponse =
        NodeResponse::new(receipt_request_id, NodeResponseStatus::Accepted, None).unwrap();
    let receipt_record: NodeDedupRecord = NodeDedupRecord::new(
        receipt_request_id,
        receipt_event_digest,
        vec![receipt_response],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(*receipt_request_id.as_bytes()).unwrap(),
        receipt_event_digest,
        receipt_record.encode().unwrap(),
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    );
    ObjectRef {
        id: object_id,
        version: object_version,
        digest,
    }
}

/// Builds the preinstalled-WASM durable router with an explicit,
/// caller-supplied `BlobStore` component instead of a default
/// [`MemoryBlobStore`], so a test can prove the exact supplied store is
/// the one the composition dispatches through.
#[allow(clippy::too_many_arguments)]
fn preinstalled_app_with_blob_store<S, B, C>(
    store: Arc<S>,
    blob_store: Arc<B>,
    transport: Arc<MemoryTransport>,
    clock: Arc<C>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    catalog: Arc<PreinstalledModuleCatalog>,
    created_checkpoint: u64,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
    preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            blob_store,
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

/// Decodes a committed version's typed object regardless of whether its
/// payload is inline or blob-backed, so tests written against either
/// shape can assert on the same decoded `Object` without caring which
/// storage representation a given commit chose.
fn committed_object(version: &DurableObjectVersionRecord, blob_store: &impl BlobStore) -> Object {
    match version.payload() {
        DurableObjectPayload::Inline(inline) => inline.object().clone(),
        DurableObjectPayload::BlobReference(blob_digest) => {
            let bytes = blob_store.get_blob(blob_digest).unwrap().unwrap();
            decode_object(&bytes).unwrap()
        }
    }
}

fn owned_object(id: ObjectId, owner: Address, byte: u8) -> Object {
    Object {
        id,
        version: 1,
        owner: Owner::Address(owner),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
        schema_version: u32::from(byte),
        data: vec![byte],
    }
}

struct IncrementMachine {
    state_key: Vec<u8>,
}

impl IncrementMachine {
    fn new(state_key: &[u8]) -> Self {
        Self {
            state_key: state_key.to_vec(),
        }
    }
}

impl TransactionalNodeStateMachine for IncrementMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            self.state_key.clone(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let current = state
            .get(&self.state_key)
            .ok_or(NodeCoreError::TransitionRejected("test state missing"))?
            .value()
            .map(decode_canonical_frame)
            .transpose()?
            .map(|frame| frame.required_u64(1))
            .transpose()?
            .unwrap_or(0);
        let next = current
            .checked_add(1)
            .ok_or(NodeCoreError::TransitionRejected("test overflow"))?;
        let response = NodeResponse::new(
            event.request_id(),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
        )?;
        let outbound = NodeEvent::new(
            event.chain_id().clone(),
            event.protocol_version(),
            event.epoch(),
            request_id(0xF0),
            node_core::NodeEventKind::ReceiveVote,
            canonical(TEST_PAYLOAD_TYPE_ID, next),
        )?;
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                self.state_key.clone(),
                canonical(TEST_STATE_TYPE_ID, next),
            )?],
            NodeOutput::new(vec![response], vec![OutboundMessage::new(outbound)])?,
        )
    }
}

struct CountingMachine {
    inner: IncrementMachine,
    access_plan_calls: AtomicUsize,
    transition_calls: AtomicUsize,
}

impl CountingMachine {
    fn new(state_key: &[u8]) -> Self {
        Self {
            inner: IncrementMachine::new(state_key),
            access_plan_calls: AtomicUsize::new(0),
            transition_calls: AtomicUsize::new(0),
        }
    }
}

impl TransactionalNodeStateMachine for CountingMachine {
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        self.access_plan_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.access_plan(event)
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.transition_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.transition(state, event)
    }
}

struct BlockingMachine {
    inner: IncrementMachine,
    entered: Arc<Notify>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl TransactionalNodeStateMachine for BlockingMachine {
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        self.inner.access_plan(event)
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.entered.notify_one();
        let (released, release_signal) = self.release.as_ref();
        let mut is_released = released
            .lock()
            .map_err(|_| NodeCoreError::TransitionRejected("test release lock poisoned"))?;
        while !*is_released {
            is_released = release_signal
                .wait(is_released)
                .map_err(|_| NodeCoreError::TransitionRejected("test release lock poisoned"))?;
        }
        self.inner.transition(state, event)
    }
}

#[derive(Default)]
struct CountingStateStore {
    inner: MemoryStateStore,
    calls: AtomicUsize,
}

impl CountingStateStore {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl StateStore for CountingStateStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.put(key, value)
    }

    fn compare_and_swap(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.compare_and_swap(key, expected, new_value)
    }
}

impl TransactionalStateStore for CountingStateStore {
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_versioned(key)
    }

    fn commit_atomic(
        &self,
        write_set: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_atomic(write_set)
    }
}

impl runtime::DomainTransactionalStateStore for CountingStateStore {
    fn get_versioned_in_domain(
        &self,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_versioned_in_domain(domain, key)
    }

    fn commit_transaction(
        &self,
        transaction: AtomicStateTransaction,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.commit_transaction(transaction)
    }
}

#[derive(Default)]
struct CountingTransport {
    send_calls: AtomicUsize,
}

impl Transport for CountingTransport {
    fn send(&self, _message: Vec<u8>) -> Result<(), RuntimeError> {
        self.send_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct SequenceLeaseIds {
    next: Mutex<u64>,
}

impl OutboxLeaseIdSource for SequenceLeaseIds {
    fn next_lease_id(
        &self,
        _request_id: RequestId,
    ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError> {
        let mut next = self
            .next
            .lock()
            .map_err(|_| OutboxLeaseIdSourceError::Unavailable)?;
        *next = next
            .checked_add(1)
            .ok_or(OutboxLeaseIdSourceError::Exhausted)?;
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&next.to_le_bytes());
        OutboxLeaseId::new(bytes).map_err(|_| OutboxLeaseIdSourceError::Exhausted)
    }
}

#[derive(Default)]
struct CountingLeaseIds {
    calls: AtomicUsize,
}

impl OutboxLeaseIdSource for CountingLeaseIds {
    fn next_lease_id(
        &self,
        _request_id: RequestId,
    ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        OutboxLeaseId::new([0x73; 32]).map_err(|_| OutboxLeaseIdSourceError::Exhausted)
    }
}

struct FixedIndexedIdentity;

impl IndexedOutboxIdentitySource for FixedIndexedIdentity {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new([0x71; 32]).unwrap(),
            StorageCorrelationId::new([0x72; 16]).unwrap(),
        ))
    }
}

#[derive(Default)]
struct SequenceIndexedIdentities {
    next: Mutex<u64>,
}

impl IndexedOutboxIdentitySource for SequenceIndexedIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let mut next = self
            .next
            .lock()
            .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?;
        *next = next
            .checked_add(1)
            .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?;
        let mut lease = [0_u8; 32];
        lease[..8].copy_from_slice(&next.to_le_bytes());
        let mut correlation = [0_u8; 16];
        correlation[..8].copy_from_slice(&next.to_le_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease)
                .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?,
            StorageCorrelationId::new(correlation)
                .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?,
        ))
    }
}

#[derive(Default)]
struct CountingIndexedIdentities {
    calls: AtomicUsize,
    next: Mutex<u64>,
}

impl IndexedOutboxIdentitySource for CountingIndexedIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut next = self
            .next
            .lock()
            .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?;
        *next = next
            .checked_add(1)
            .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?;
        let mut lease = [0_u8; 32];
        lease[..8].copy_from_slice(&next.to_le_bytes());
        let mut correlation = [0_u8; 16];
        correlation[..8].copy_from_slice(&next.to_le_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease)
                .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?,
            StorageCorrelationId::new(correlation)
                .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?,
        ))
    }
}

struct CountingClock {
    now_unix_millis: u64,
    calls: AtomicUsize,
}

impl CountingClock {
    fn new(now_unix_millis: u64) -> Self {
        Self {
            now_unix_millis,
            calls: AtomicUsize::new(0),
        }
    }
}

impl Clock for CountingClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.now_unix_millis)
    }
}

/// An identity source that always fails with a fixed, chosen error, for
/// exercising the query path's `Unavailable`/`Exhausted` classification.
struct FailingIndexedIdentities {
    error: IndexedOutboxIdentitySourceError,
}

impl IndexedOutboxIdentitySource for FailingIndexedIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        Err(self.error)
    }
}

/// A clock that always fails, for exercising the query path's
/// `NodeCoreError::Runtime` classification.
struct FailingClock;

impl Clock for FailingClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        Err(RuntimeError::EmptyKey)
    }
}

#[derive(Debug)]
struct StepCancellation {
    cancel_at_call: usize,
    calls: AtomicUsize,
}

impl StepCancellation {
    fn new(cancel_at_call: usize) -> Self {
        Self {
            cancel_at_call,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl InvocationCancellation for StepCancellation {
    fn is_cancelled(&self) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.cancel_at_call
    }
}

#[derive(Debug, Default)]
struct ManualCancellation {
    cancelled: AtomicBool,
}

impl ManualCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

impl InvocationCancellation for ManualCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

struct ScriptedIndexedStore {
    claims: Mutex<VecDeque<DurableOutboxClaimOutcome>>,
    acknowledgements: Mutex<VecDeque<DurableOutboxAcknowledgementOutcome>>,
    claim_requests: Mutex<Vec<DueOutboxClaimRequest>>,
    acknowledgement_requests: Mutex<Vec<DurableOutboxAcknowledgement>>,
    storage_calls: AtomicUsize,
}

impl ScriptedIndexedStore {
    fn new(
        claims: Vec<DurableOutboxClaimOutcome>,
        acknowledgements: Vec<DurableOutboxAcknowledgementOutcome>,
    ) -> Self {
        Self {
            claims: Mutex::new(claims.into()),
            acknowledgements: Mutex::new(acknowledgements.into()),
            claim_requests: Mutex::new(Vec::new()),
            acknowledgement_requests: Mutex::new(Vec::new()),
            storage_calls: AtomicUsize::new(0),
        }
    }
}

impl StateStore for ScriptedIndexedStore {
    fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::DurableStoreUnavailable)
    }

    fn put(&self, _key: Vec<u8>, _value: Vec<u8>) -> Result<(), RuntimeError> {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::DurableStoreUnavailable)
    }

    fn compare_and_swap(
        &self,
        _key: Vec<u8>,
        _expected: Option<Vec<u8>>,
        _new_value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError> {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        Err(RuntimeError::DurableStoreUnavailable)
    }
}

impl DurableDomainStateStore for ScriptedIndexedStore {
    fn get_versioned_durable(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        Err(DurableReadError::Unavailable)
    }

    fn commit_durable(
        &self,
        _context: &DurableOperationContext,
        _transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
    }
}

impl StructuredDurableDomainStateStore for ScriptedIndexedStore {
    fn get_request_receipt(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        Err(DurableReadError::Unavailable)
    }

    fn commit_invocation(
        &self,
        _context: &DurableOperationContext,
        _transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
    }
}

impl IndexedOutboxRepository for ScriptedIndexedStore {
    fn claim_request_outbox(
        &self,
        _context: &DurableOperationContext,
        _request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        self.claims
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(DurableOutboxClaimOutcome::NoDueWork)
    }

    fn claim_due_outbox(
        &self,
        _context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        self.claim_requests.lock().unwrap().push(request);
        self.claims
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(DurableOutboxClaimOutcome::NoDueWork)
    }

    fn acknowledge_outbox(
        &self,
        _context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        self.storage_calls.fetch_add(1, Ordering::SeqCst);
        self.acknowledgement_requests
            .lock()
            .unwrap()
            .push(acknowledgement);
        self.acknowledgements
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(DurableOutboxAcknowledgementOutcome::Acknowledged)
    }
}

struct IndeterminateRequestClaimStore {
    inner: MemoryDurableStateStore,
    commit_contexts: Mutex<Vec<DurableOperationContext>>,
    claim_contexts: Mutex<Vec<DurableOperationContext>>,
    claim_requests: Mutex<Vec<RequestOutboxClaimRequest>>,
}

impl IndeterminateRequestClaimStore {
    fn new(inner: MemoryDurableStateStore) -> Self {
        Self {
            inner,
            commit_contexts: Mutex::new(Vec::new()),
            claim_contexts: Mutex::new(Vec::new()),
            claim_requests: Mutex::new(Vec::new()),
        }
    }
}

impl DurableDomainStateStore for IndeterminateRequestClaimStore {
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

impl StructuredDurableDomainStateStore for IndeterminateRequestClaimStore {
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
        self.commit_contexts.lock().unwrap().push(*context);
        self.inner.commit_invocation(context, transaction)
    }
}

impl IndexedOutboxRepository for IndeterminateRequestClaimStore {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.claim_contexts.lock().unwrap().push(*context);
        self.claim_requests.lock().unwrap().push(request);
        DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.inner.claim_due_outbox(context, request)
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        self.inner.acknowledge_outbox(context, acknowledgement)
    }
}

struct CancelOnFirstReceiptReadStore {
    inner: MemoryDurableStateStore,
    cancellation: Arc<ManualCancellation>,
    cancelled: AtomicBool,
    receipt_reads: AtomicUsize,
}

impl CancelOnFirstReceiptReadStore {
    fn new(inner: MemoryDurableStateStore, cancellation: Arc<ManualCancellation>) -> Self {
        Self {
            inner,
            cancellation,
            cancelled: AtomicBool::new(false),
            receipt_reads: AtomicUsize::new(0),
        }
    }

    fn receipt_reads(&self) -> usize {
        self.receipt_reads.load(Ordering::SeqCst)
    }
}

impl DurableDomainStateStore for CancelOnFirstReceiptReadStore {
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

impl StructuredDurableDomainStateStore for CancelOnFirstReceiptReadStore {
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.receipt_reads.fetch_add(1, Ordering::SeqCst);
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.cancellation.cancel();
        }
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

impl IndexedOutboxRepository for CancelOnFirstReceiptReadStore {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.inner.claim_request_outbox(context, request)
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.inner.claim_due_outbox(context, request)
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        self.inner.acknowledge_outbox(context, acknowledgement)
    }
}

fn indexed_runtime(
    store: ScriptedIndexedStore,
) -> ComposedRuntime<
    ScriptedIndexedStore,
    MemoryBlobStore,
    MemorySigner,
    MemoryTransport,
    ManualClock,
    MemoryScheduler,
> {
    ComposedRuntime::new(
        store,
        MemoryBlobStore::default(),
        MemorySigner::new(ValidatorId::new([0x44; 32])),
        MemoryTransport::default(),
        ManualClock::new(10_000),
        MemoryScheduler::default(),
    )
}

fn indexed_authority() -> IndexedOutboxRecoveryAuthority {
    IndexedOutboxRecoveryAuthority::new(
        AtomicityDomainId::new([0x61; 32]).unwrap(),
        WriterFenceGeneration::new(3).unwrap(),
        1_000,
        NATIVE_OUTBOX_LEASE_MILLIS,
    )
    .unwrap()
}

fn app<R>(runtime: Arc<R>, config: NodeConfig) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
{
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    router(
        runtime,
        config,
        resolver(),
        machine,
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
}

type ObservedLegacyRuntime = ComposedRuntime<
    CountingStateStore,
    CountingBlobStore,
    MemorySigner,
    CountingTransport,
    CountingClock,
    MemoryScheduler,
>;

fn observed_legacy_runtime() -> Arc<ObservedLegacyRuntime> {
    Arc::new(ComposedRuntime::new(
        CountingStateStore::default(),
        CountingBlobStore::default(),
        MemorySigner::new(ValidatorId::new([0x44; 32])),
        CountingTransport::default(),
        CountingClock::new(10_000),
        MemoryScheduler::default(),
    ))
}

fn resolved_app(
    runtime: Arc<MemoryRuntime>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
) -> Router {
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    resolved_domain_router(
        runtime,
        placement,
        config,
        resolver(),
        machine,
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
}

fn structured_request_authority() -> StructuredDurableRequestAuthority {
    StructuredDurableRequestAuthority::new(
        WriterFenceGeneration::new(3).unwrap(),
        1_000,
        NATIVE_OUTBOX_LEASE_MILLIS,
    )
    .unwrap()
}

fn structured_app<S>(
    store: Arc<S>,
    transport: Arc<MemoryTransport>,
    clock: Arc<ManualClock>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
{
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
    structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

/// Builds the read-only structured durable router with an explicit,
/// caller-supplied `BlobStore` component instead of a default
/// [`MemoryBlobStore`], so a test can prove the exact supplied store is
/// (or is not) the one the composition dispatches through.
fn structured_app_with_blob_store<S, B>(
    store: Arc<S>,
    blob_store: Arc<B>,
    transport: Arc<MemoryTransport>,
    clock: Arc<ManualClock>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
{
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
    structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            blob_store,
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

fn structured_app_with_cancellation<S>(
    store: Arc<S>,
    transport: Arc<MemoryTransport>,
    clock: Arc<ManualClock>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    cancellation: Arc<dyn InvocationCancellation>,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
{
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    structured_durable_router(
        StructuredDurableNativeComponents::with_cancellation(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
            cancellation,
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

fn observed_structured_app(
    store: Arc<CancelOnFirstReceiptReadStore>,
    transport: Arc<MemoryTransport>,
    clock: Arc<CountingClock>,
    identities: Arc<CountingIndexedIdentities>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    machine: Arc<CountingMachine>,
) -> Router {
    structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            clock,
            identities,
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

fn preinstalled_app<S, C>(
    store: Arc<S>,
    transport: Arc<MemoryTransport>,
    clock: Arc<C>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    catalog: Arc<PreinstalledModuleCatalog>,
    created_checkpoint: u64,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config.state_key()));
    preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_app_with_cancellation<S>(
    store: Arc<S>,
    transport: Arc<MemoryTransport>,
    clock: Arc<ManualClock>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    catalog: Arc<PreinstalledModuleCatalog>,
    created_checkpoint: u64,
    cancellation: Arc<dyn InvocationCancellation>,
) -> Router
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
{
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::with_cancellation(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
            cancellation,
        ),
        PreinstalledWasmComposition::new(catalog, WasmExecutionEngine, created_checkpoint),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

async fn assert_submit_rejected_before_side_effects_with_config(
    body: Vec<u8>,
    protocol_config: ProtocolConfig,
    config: NodeConfig,
    expected_status: StatusCode,
    expected_body: &'static str,
) {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let inner = MemoryDurableStateStore::new(fence);
    inner.set_time(10_000);
    let cancellation = Arc::new(ManualCancellation::default());
    let store = Arc::new(CancelOnFirstReceiptReadStore::new(
        inner,
        Arc::clone(&cancellation),
    ));
    let transport = Arc::new(MemoryTransport::default());
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(CountingMachine::new(config.state_key()));
    let app = observed_structured_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::clone(&clock),
        Arc::clone(&identities),
        protocol_config,
        config,
        Arc::clone(&machine),
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), expected_status);
    assert_eq!(
        to_bytes(response.into_body(), 256).await.unwrap(),
        expected_body
    );
    assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 0);
    assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.receipt_reads(), 0);
    assert!(!cancellation.is_cancelled());
    assert!(transport.drain_outbound().unwrap().is_empty());
}

async fn assert_submit_rejected_before_side_effects(
    body: Vec<u8>,
    protocol_config: ProtocolConfig,
    expected_status: StatusCode,
    expected_body: &'static str,
) {
    assert_submit_rejected_before_side_effects_with_config(
        body,
        protocol_config,
        config(),
        expected_status,
        expected_body,
    )
    .await;
}

#[test]
fn structured_router_rejects_diverging_or_missing_config_authority() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    let transport = Arc::new(MemoryTransport::default());
    let clock = Arc::new(ManualClock::new(10_000));
    let identities = Arc::new(SequenceIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config().state_key()));
    let domain = AtomicityDomainId::new([0x89; 32]).unwrap();
    let mut mismatched = active_protocol_config(domain);
    mismatched.protocol_version = ProtocolVersion::new(2);

    let blob_store = Arc::new(MemoryBlobStore::default());
    let mismatch = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            Arc::clone(&transport),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        mismatched,
        structured_request_authority(),
        config(),
        resolver(),
        Arc::clone(&machine),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    );
    assert!(matches!(
        mismatch,
        Err(StructuredDurableRouterError::ProtocolVersionAuthorityMismatch {
            node_config,
            protocol_config,
        }) if node_config == ProtocolVersion::new(3)
            && protocol_config == ProtocolVersion::new(2)
    ));

    let mut missing_placement = ProtocolConfig::genesis();
    missing_placement.protocol_version = ProtocolVersion::new(3);
    missing_placement.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_address_is_public_key());
    let missing = structured_durable_router(
        StructuredDurableNativeComponents::new(store, blob_store, transport, clock, identities),
        missing_placement,
        structured_request_authority(),
        config(),
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    );
    assert!(matches!(
        missing,
        Err(StructuredDurableRouterError::MissingDomainPlacement)
    ));
}

#[tokio::test]
async fn structured_route_authenticates_submit_before_commit_and_replay() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let config = config();
    let machine = Arc::new(CountingMachine::new(config.state_key()));
    let domain = AtomicityDomainId::new([0x86; 32]).unwrap();
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::clone(&transport),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        active_protocol_config(domain),
        structured_request_authority(),
        config,
        resolver(),
        Arc::clone(&machine),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();
    let signing_key = dev_signing_key(0x31);
    let event = signed_submit_transaction_event(&signing_key, request_id(0x36), 0);
    let body = event.encode().unwrap();

    let first = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    let second = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let first_status = first.status();
    let first_body = to_bytes(first.into_body(), 256).await.unwrap();
    let second_status = second.status();
    let second_body = to_bytes(second.into_body(), 256).await.unwrap();
    assert_eq!(
        first_status,
        StatusCode::OK,
        "first response body: {}",
        String::from_utf8_lossy(&first_body)
    );
    assert_eq!(
        second_status,
        StatusCode::OK,
        "second response body: {}",
        String::from_utf8_lossy(&second_body)
    );
    assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 2);
    assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 1);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 2);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 2);
    assert_eq!(transport.drain_outbound().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn structured_event_route_rejects_excess_blocking_work_without_blocking_liveness() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
    let config: NodeConfig = config();
    let entered: Arc<Notify> = Arc::new(Notify::new());
    let release: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
    let machine: Arc<BlockingMachine> = Arc::new(BlockingMachine {
        inner: IncrementMachine::new(config.state_key()),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let blocking_executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let app: Router = structured_durable_router_with_executor(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        active_protocol_config(AtomicityDomainId::new([0x8B; 32]).unwrap()),
        structured_request_authority(),
        config,
        resolver(),
        machine,
        blocking_executor,
    )
    .unwrap();
    let first_signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x36);
    let first_event: NodeEvent =
        signed_submit_transaction_event(&first_signing_key, request_id(0x37), 0);
    let second_signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x38);
    let second_event: NodeEvent =
        signed_submit_transaction_event(&second_signing_key, request_id(0x39), 0);

    let first_app: Router = app.clone();
    let first = tokio::spawn(async move {
        first_app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(first_event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    entered.notified().await;

    let liveness: Response = app
        .clone()
        .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let overloaded: Response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(second_event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let (released, release_signal) = release.as_ref();
    *released.lock().unwrap() = true;
    release_signal.notify_all();
    let first: Response = first.await.unwrap();

    assert_eq!(liveness.status(), StatusCode::NO_CONTENT);
    assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        to_bytes(overloaded.into_body(), 128).await.unwrap(),
        "blocking-capacity-exhausted"
    );
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(transport.drain_outbound().unwrap().len(), 1);
}

#[tokio::test]
async fn structured_route_maps_fresh_request_nonce_mismatch_without_transition_or_send() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let config = config();
    let machine = Arc::new(CountingMachine::new(config.state_key()));
    let domain = AtomicityDomainId::new([0x96; 32]).unwrap();
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::clone(&transport),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        active_protocol_config(domain),
        structured_request_authority(),
        config,
        resolver(),
        Arc::clone(&machine),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();
    let signing_key = dev_signing_key(0x41);
    let event = signed_submit_transaction_event(&signing_key, request_id(0x46), 1);

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "sender-nonce-mismatch"
    );
    assert_eq!(machine.access_plan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(machine.transition_calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 1);
    assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
    assert!(transport.drain_outbound().unwrap().is_empty());
}

#[tokio::test]
async fn native_error_mapping_keeps_nonce_overflow_distinct_from_conflict() {
    let sender = [0x55; 32];
    let mismatch = node_error_response(&NodeCoreError::SenderNonceMismatch {
        sender,
        expected: 3,
        actual: 2,
    });
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(mismatch.into_body(), 128).await.unwrap(),
        "sender-nonce-mismatch"
    );

    let overflow = node_error_response(&NodeCoreError::SenderNonceOverflow { sender });
    assert_eq!(overflow.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        to_bytes(overflow.into_body(), 128).await.unwrap(),
        "sender-nonce-overflow"
    );
}

#[tokio::test]
async fn native_error_mapping_classifies_fee_request_and_composition_failures() {
    let asset_id = standard_assets::AssetId::new([0x56; 32]);
    let cases: Vec<(NodeCoreError, StatusCode, &'static str)> = vec![
        (
            NodeCoreError::FeePaymentRequired,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-required",
        ),
        (
            NodeCoreError::FeePaymentNotRequired,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-not-required",
        ),
        (
            NodeCoreError::FeePaymentUnsupportedOnPath,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-unsupported-on-path",
        ),
        (
            NodeCoreError::FeePaymentRejected(fees::FeeError::UnknownAsset(asset_id)),
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-rejected",
        ),
        (
            NodeCoreError::FeePaymentRejected(fees::FeeError::ArithmeticOverflow),
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-settlement-overflow",
        ),
        (
            NodeCoreError::FeePaymentRejected(fees::FeeError::ZeroFeeUnitsPerAssetUnit),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-policy-invalid",
        ),
        (
            NodeCoreError::FeeObjectNotDeclaredWrite,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-not-declared-write",
        ),
        (
            NodeCoreError::FeeObjectNotOwnedBySender,
            StatusCode::FORBIDDEN,
            "fee-object-owner-mismatch",
        ),
        (
            NodeCoreError::FeeObjectIsTreasury,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-is-treasury",
        ),
        (
            NodeCoreError::FeeTreasuryAccessMisdeclared,
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-treasury-access-misdeclared",
        ),
        (
            NodeCoreError::FeeCompositionFailed(
                node_core::FeeCompositionError::InsufficientBalance,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-balance-insufficient",
        ),
        (
            NodeCoreError::FeeCompositionFailed(node_core::FeeCompositionError::MalformedBody),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-invalid",
        ),
        (
            NodeCoreError::FeeCompositionUnavailable,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-unavailable",
        ),
        (
            NodeCoreError::FeeCompositionNoOp,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-no-op",
        ),
        (
            NodeCoreError::FeeAmountZero,
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-settlement-zero",
        ),
        (
            NodeCoreError::UnsupportedGasScheduleShape(
                node_core::GasScheduleShapeFault::UnmeasuredCategoryPriced,
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-schedule-unsupported",
        ),
        (
            NodeCoreError::UnsupportedGasScheduleShape(
                node_core::GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice,
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-schedule-unsupported",
        ),
    ];

    for (error, expected_status, expected_code) in cases {
        let response = node_error_response(&error);
        assert_eq!(response.status(), expected_status, "error: {error:?}");
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            expected_code,
            "error: {error:?}"
        );
    }
}

#[tokio::test]
async fn native_error_mapping_covers_every_authenticated_object_dispatch_variant() {
    let object_id = ObjectId::new([0x61; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x62; 32]);
    let cases: Vec<(NodeCoreError, StatusCode, &str)> = vec![
        (
            NodeCoreError::DurableRead(DurableReadError::InvalidRequest(
                RuntimeError::UnsupportedObjectStorage,
            )),
            StatusCode::NOT_IMPLEMENTED,
            "object-storage-unsupported",
        ),
        (
            NodeCoreError::ObjectNotFound { object_id },
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-not-found",
        ),
        (
            NodeCoreError::ObjectVersionMismatch {
                object_id,
                expected: 1,
                actual: 2,
            },
            StatusCode::CONFLICT,
            "object-version-mismatch",
        ),
        (
            NodeCoreError::ObjectDigestMismatch {
                object_id,
                expected: digest,
                actual: digest,
            },
            StatusCode::CONFLICT,
            "object-digest-mismatch",
        ),
        (
            NodeCoreError::ObjectOwnerMismatch { object_id },
            StatusCode::FORBIDDEN,
            "object-owner-mismatch",
        ),
        (
            NodeCoreError::InadmissibleObjectOwnerAddress {
                object_id,
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
            },
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::InadmissibleObjectOutputOwnerAddress {
                object_id,
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectAccessModeUnsupported {
                object_id,
                mode: AccessMode::Write,
            },
            StatusCode::NOT_IMPLEMENTED,
            "object-mutating-access-unsupported",
        ),
        (
            NodeCoreError::ObjectOwnerKindUnsupported { object_id },
            StatusCode::NOT_IMPLEMENTED,
            "object-owner-kind-unsupported",
        ),
        (
            NodeCoreError::ObjectBlobMissing {
                object_id,
                blob_digest: digest,
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "object-blob-unavailable",
        ),
        (
            NodeCoreError::ObjectBlobDigestMismatch {
                object_id,
                blob_digest: digest,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectBlobPublishFailed {
                object_id,
                blob_digest: digest,
                source: RuntimeError::BlobDigestConflict { digest },
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "object-blob-publish-failed",
        ),
        (
            NodeCoreError::ObjectManifestTooLarge {
                count: 33,
                maximum: 32,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-manifest-too-large",
        ),
        (
            NodeCoreError::DuplicateObjectAccess { object_id },
            StatusCode::BAD_REQUEST,
            "object-manifest-duplicate",
        ),
        (
            NodeCoreError::InvalidObjectVersion {
                object_id,
                version: 0,
            },
            StatusCode::BAD_REQUEST,
            "object-version-invalid",
        ),
        (
            NodeCoreError::ObjectConflict { object_id },
            StatusCode::CONFLICT,
            "object-head-conflict",
        ),
        (
            NodeCoreError::ObjectRecordMissing { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectRecordMismatch { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectBodyDigestMismatch { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectProvenanceMismatch { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectDigestUnverifiable {
                object_id,
                algorithm: HashAlgorithmId::Blake3_256,
            },
            StatusCode::NOT_IMPLEMENTED,
            "object-digest-algorithm-unsupported",
        ),
        (
            NodeCoreError::ObjectBodyTooLarge {
                object_id,
                actual: 2 * 1024 * 1024,
                maximum: 1024 * 1024,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-body-too-large",
        ),
        (
            NodeCoreError::PreinstalledModuleUnknown {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-unknown",
        ),
        (
            NodeCoreError::PreinstalledModuleInactive {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-inactive",
        ),
        (
            NodeCoreError::PreinstalledModuleNotYetActive {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
                activation_epoch: Epoch::new(9),
                current_epoch: Epoch::new(7),
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-not-yet-active",
        ),
        (
            NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-reference-invalid",
        ),
        (
            NodeCoreError::PreinstalledModuleArgsTooLarge {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
                actual: 128,
                maximum: 64,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-args-too-large",
        ),
        (
            NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
                requested: 20_000_000,
                maximum: 10_000_000,
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-gas-limit-exceeded",
        ),
        (
            NodeCoreError::PreinstalledModuleZeroObjectAccess,
            StatusCode::BAD_REQUEST,
            "preinstalled-module-zero-object-access",
        ),
        (
            NodeCoreError::PreinstalledModuleNotCataloged {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        (
            NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        (
            NodeCoreError::PreinstalledModuleManifestHashMismatch {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        (
            NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
                module_id: ModuleId::new([0x63; 32]),
                version: 1,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        (
            NodeCoreError::ObjectCreatedCheckpointRegression {
                object_id,
                previous_created_checkpoint: 9,
                attempted_created_checkpoint: 5,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "object-created-checkpoint-regression",
        ),
        (
            NodeCoreError::ObjectVersionOverflow { object_id },
            StatusCode::CONFLICT,
            "object-version-overflow",
        ),
        (
            NodeCoreError::ObjectCreationUnsupported { object_id },
            StatusCode::NOT_IMPLEMENTED,
            "object-creation-unsupported",
        ),
        (
            NodeCoreError::ObjectEffectMismatch {
                object_id,
                reason: "test reason",
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-effect-mismatch",
        ),
        (
            NodeCoreError::DuplicateObjectEffect { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::TooManyObjectEffects {
                actual: 33,
                maximum: 32,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::UndeclaredObjectEffect { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ObjectMutationContextMissing { object_id },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::SystemModules(SystemModuleError::ZeroModuleVersion),
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::Execution(ExecutionError::MissingEntrypoint(
                "does-not-exist".to_string(),
            )),
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-entrypoint-unknown",
        ),
        (
            NodeCoreError::Execution(ExecutionError::ResourceLimitExceeded("input objects")),
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-resource-limit-exceeded",
        ),
        (
            NodeCoreError::Execution(ExecutionError::WasmEngine("boom".to_string())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-engine-failure",
        ),
        (
            NodeCoreError::Execution(ExecutionError::ObjectVersionOverflow(object_id)),
            StatusCode::CONFLICT,
            "object-version-overflow",
        ),
        (
            NodeCoreError::Execution(ExecutionError::HashChainMismatch),
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
    ];

    for (error, expected_status, expected_code) in cases {
        let response = node_error_response(&error);
        assert_eq!(response.status(), expected_status, "error: {error:?}");
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            expected_code,
            "error: {error:?}"
        );
    }
}

#[tokio::test]
async fn structured_route_rejects_invalid_submit_before_every_side_effect() {
    let domain = AtomicityDomainId::new([0x87; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let signing_key = dev_signing_key(0x32);
    let valid = signed_submit_transaction_event(&signing_key, request_id(0x37), 1);

    let mut invalid_signature = decode_transaction(valid.payload()).unwrap();
    invalid_signature.signature = vec![0_u8; 64];
    let invalid_signature_event = submit_transaction_event(
        request_id(0x38),
        encode_transaction(&invalid_signature).unwrap(),
    );
    assert_submit_rejected_before_side_effects(
        invalid_signature_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::UNAUTHORIZED,
        "transaction-signature-invalid",
    )
    .await;

    let mut strict_protocol_config: ProtocolConfig = protocol_config.clone();
    strict_protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let sender: Address = dev_sender_address(&signing_key);
    let strict_transaction: Transaction = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        1,
    );
    let signed_request_id: RequestId = request_id(0x47);
    let relabeled_event: NodeEvent = submit_transaction_event(
        request_id(0x48),
        signed_submission_transaction_bytes(&signing_key, signed_request_id, &strict_transaction),
    );
    assert_submit_rejected_before_side_effects(
        relabeled_event.encode().unwrap(),
        strict_protocol_config,
        StatusCode::UNAUTHORIZED,
        "transaction-signature-invalid",
    )
    .await;

    let sender = dev_sender_address(&signing_key);
    let mut wrong_chain = unsigned_transaction(
        sender,
        ChainId::new("other-chain").unwrap(),
        Epoch::new(7),
        2,
    );
    wrong_chain.signature = vec![0_u8; 64];
    let wrong_chain_event =
        submit_transaction_event(request_id(0x39), encode_transaction(&wrong_chain).unwrap());
    assert_submit_rejected_before_side_effects(
        wrong_chain_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::BAD_REQUEST,
        "transaction-context-mismatch",
    )
    .await;

    let sender = dev_sender_address(&signing_key);
    let mut wrong_version = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        3,
    );
    wrong_version.protocol_version = ProtocolVersion::new(2);
    wrong_version.signature = vec![0_u8; 64];
    let wrong_version_event = submit_transaction_event(
        request_id(0x3A),
        encode_transaction(&wrong_version).unwrap(),
    );
    assert_submit_rejected_before_side_effects(
        wrong_version_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::BAD_REQUEST,
        "transaction-context-mismatch",
    )
    .await;

    let sender = dev_sender_address(&signing_key);
    let mut wrong_epoch = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(8),
        4,
    );
    wrong_epoch.signature = vec![0_u8; 64];
    let wrong_epoch_event =
        submit_transaction_event(request_id(0x3B), encode_transaction(&wrong_epoch).unwrap());
    assert_submit_rejected_before_side_effects(
        wrong_epoch_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::BAD_REQUEST,
        "transaction-context-mismatch",
    )
    .await;

    let mut trailing_payload = valid.payload().to_vec();
    trailing_payload.push(0);
    assert_submit_rejected_before_side_effects(
        raw_submit_transaction_event_bytes(request_id(0x3C), trailing_payload),
        protocol_config.clone(),
        StatusCode::BAD_REQUEST,
        "invalid-node-event",
    )
    .await;

    let mut missing_profile = protocol_config;
    missing_profile.transaction_auth_profile = None;
    assert_submit_rejected_before_side_effects(
        valid.encode().unwrap(),
        missing_profile,
        StatusCode::SERVICE_UNAVAILABLE,
        "transaction-auth-config-unavailable",
    )
    .await;

    let premature_node_config = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(2),
        Epoch::new(7),
        b"http/node-state".to_vec(),
    )
    .unwrap();
    let mut premature_protocol_config = ProtocolConfig::genesis();
    premature_protocol_config.protocol_version = ProtocolVersion::new(2);
    premature_protocol_config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, domain, Epoch::new(0)).unwrap());
    let premature_event = NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(2),
        Epoch::new(7),
        request_id(0x3E),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap();
    assert_submit_rejected_before_side_effects_with_config(
        premature_event.encode().unwrap(),
        premature_protocol_config,
        premature_node_config,
        StatusCode::SERVICE_UNAVAILABLE,
        "transaction-auth-config-unavailable",
    )
    .await;
}

#[tokio::test]
async fn structured_route_rejects_outer_event_context_mismatch_before_every_side_effect() {
    let domain = AtomicityDomainId::new([0x8A; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);

    let wrong_chain_event = NodeEvent::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id(0x40),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap();
    assert_submit_rejected_before_side_effects(
        wrong_chain_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::CONFLICT,
        "state-or-context-conflict",
    )
    .await;

    let wrong_version_event = NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(2),
        Epoch::new(7),
        request_id(0x41),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap();
    assert_submit_rejected_before_side_effects(
        wrong_version_event.encode().unwrap(),
        protocol_config.clone(),
        StatusCode::CONFLICT,
        "state-or-context-conflict",
    )
    .await;

    let wrong_epoch_event = NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(8),
        request_id(0x42),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap();
    assert_submit_rejected_before_side_effects(
        wrong_epoch_event.encode().unwrap(),
        protocol_config,
        StatusCode::CONFLICT,
        "state-or-context-conflict",
    )
    .await;
}

#[tokio::test]
async fn structured_route_rejects_canonical_non_transaction_payload_before_every_side_effect() {
    let domain = AtomicityDomainId::new([0x8B; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let event = submit_transaction_event(request_id(0x43), canonical(TEST_PAYLOAD_TYPE_ID, 9));

    assert_submit_rejected_before_side_effects(
        event.encode().unwrap(),
        protocol_config,
        StatusCode::BAD_REQUEST,
        "invalid-transaction-bytes",
    )
    .await;
}

#[tokio::test]
async fn legacy_native_routes_reject_submit_without_machine_or_storage_work() {
    let signing_key = dev_signing_key(0x33);
    let submit = signed_submit_transaction_event(&signing_key, request_id(0x3D), 1);

    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let node_config = config();
    let legacy = app(Arc::clone(&runtime), node_config.clone());
    let response = legacy
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "submit-transaction-requires-authenticated-route"
    );
    assert_eq!(
        runtime.state_store().get(node_config.state_key()).unwrap(),
        None
    );

    let resolved_runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x45; 32])));
    let placement = placement(0x88, 7);
    let domain = placement.domain();
    let resolved = resolved_app(
        Arc::clone(&resolved_runtime),
        placement,
        node_config.clone(),
    );
    let response = resolved
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "submit-transaction-requires-authenticated-route"
    );
    assert_eq!(
        resolved_runtime
            .state_store()
            .get_versioned_in_domain(domain, node_config.state_key())
            .unwrap()
            .value(),
        None
    );
}

async fn assert_event_family_rejected(app: Router, event: NodeEvent) {
    let response: Response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "event-family-requires-authenticated-route"
    );
}

#[tokio::test]
async fn every_native_event_route_rejects_all_unauthenticated_families_before_side_effects() {
    // The four plain constructors delegate directly to their corresponding
    // `_with_executor` constructors and install the same handler state, so
    // this matrix covers both public constructor forms without duplicating
    // the 28 request/side-effect assertions.
    for (index, kind) in externally_unsupported_event_kinds().into_iter().enumerate() {
        let request_byte: u8 = u8::try_from(0x60_usize + index).unwrap();
        let event: NodeEvent = event_with_kind(
            request_id(request_byte),
            kind,
            ChainId::new("sunrise-test").unwrap(),
        );

        let legacy_runtime: Arc<ObservedLegacyRuntime> = observed_legacy_runtime();
        let legacy_machine: Arc<CountingMachine> =
            Arc::new(CountingMachine::new(config().state_key()));
        let legacy_lease_ids: Arc<CountingLeaseIds> = Arc::new(CountingLeaseIds::default());
        let legacy: Router = router(
            Arc::clone(&legacy_runtime),
            config(),
            resolver(),
            Arc::clone(&legacy_machine),
            Arc::clone(&legacy_lease_ids),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        );
        assert_event_family_rejected(legacy, event.clone()).await;
        assert_eq!(legacy_runtime.state_store().calls(), 0);
        assert_eq!(legacy_runtime.blob_store().get_calls(), 0);
        assert_eq!(legacy_runtime.clock().calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            legacy_runtime.transport().send_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(legacy_lease_ids.calls.load(Ordering::SeqCst), 0);
        assert_eq!(legacy_machine.access_plan_calls.load(Ordering::SeqCst), 0);
        assert_eq!(legacy_machine.transition_calls.load(Ordering::SeqCst), 0);

        let resolved_runtime: Arc<ObservedLegacyRuntime> = observed_legacy_runtime();
        let resolved_machine: Arc<CountingMachine> =
            Arc::new(CountingMachine::new(config().state_key()));
        let resolved_lease_ids: Arc<CountingLeaseIds> = Arc::new(CountingLeaseIds::default());
        let resolved: Router = resolved_domain_router(
            Arc::clone(&resolved_runtime),
            placement(0x88, 7),
            config(),
            resolver(),
            Arc::clone(&resolved_machine),
            Arc::clone(&resolved_lease_ids),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        );
        assert_event_family_rejected(resolved, event.clone()).await;
        assert_eq!(resolved_runtime.state_store().calls(), 0);
        assert_eq!(resolved_runtime.blob_store().get_calls(), 0);
        assert_eq!(resolved_runtime.clock().calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            resolved_runtime
                .transport()
                .send_calls
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(resolved_lease_ids.calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolved_machine.access_plan_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolved_machine.transition_calls.load(Ordering::SeqCst), 0);

        let structured_store: Arc<ScriptedIndexedStore> =
            Arc::new(ScriptedIndexedStore::new(Vec::new(), Vec::new()));
        let structured_blob_store: Arc<CountingBlobStore> = Arc::new(CountingBlobStore::default());
        let structured_transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
        let structured_clock: Arc<CountingClock> = Arc::new(CountingClock::new(10_000));
        let structured_identities: Arc<CountingIndexedIdentities> =
            Arc::new(CountingIndexedIdentities::default());
        let structured_machine: Arc<CountingMachine> =
            Arc::new(CountingMachine::new(config().state_key()));
        let structured: Router = structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&structured_store),
                Arc::clone(&structured_blob_store),
                Arc::clone(&structured_transport),
                Arc::clone(&structured_clock),
                Arc::clone(&structured_identities),
            ),
            active_protocol_config(AtomicityDomainId::new([0x89; 32]).unwrap()),
            structured_request_authority(),
            config(),
            resolver(),
            Arc::clone(&structured_machine),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();
        assert_event_family_rejected(structured, event.clone()).await;
        assert_eq!(structured_store.storage_calls.load(Ordering::SeqCst), 0);
        assert_eq!(structured_blob_store.get_calls(), 0);
        assert_eq!(structured_clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(structured_identities.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            structured_machine.access_plan_calls.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            structured_machine.transition_calls.load(Ordering::SeqCst),
            0
        );
        assert!(structured_transport.drain_outbound().unwrap().is_empty());

        let preinstalled_store: Arc<ScriptedIndexedStore> =
            Arc::new(ScriptedIndexedStore::new(Vec::new(), Vec::new()));
        let preinstalled_blob_store: Arc<CountingBlobStore> =
            Arc::new(CountingBlobStore::default());
        let preinstalled_transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
        let preinstalled_clock: Arc<CountingClock> = Arc::new(CountingClock::new(10_000));
        let preinstalled_identities: Arc<CountingIndexedIdentities> =
            Arc::new(CountingIndexedIdentities::default());
        let preinstalled_machine: Arc<CountingMachine> =
            Arc::new(CountingMachine::new(config().state_key()));
        let preinstalled: Router = preinstalled_wasm_structured_durable_router(
            StructuredDurableNativeComponents::new(
                Arc::clone(&preinstalled_store),
                Arc::clone(&preinstalled_blob_store),
                Arc::clone(&preinstalled_transport),
                Arc::clone(&preinstalled_clock),
                Arc::clone(&preinstalled_identities),
            ),
            PreinstalledWasmComposition::new(
                Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap()),
                WasmExecutionEngine,
                9,
            ),
            active_protocol_config(AtomicityDomainId::new([0x8A; 32]).unwrap()),
            structured_request_authority(),
            config(),
            resolver(),
            Arc::clone(&preinstalled_machine),
            NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
        )
        .unwrap();
        assert_event_family_rejected(preinstalled, event).await;
        assert_eq!(preinstalled_store.storage_calls.load(Ordering::SeqCst), 0);
        assert_eq!(preinstalled_blob_store.get_calls(), 0);
        assert_eq!(preinstalled_clock.calls.load(Ordering::SeqCst), 0);
        assert_eq!(preinstalled_identities.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            preinstalled_machine
                .access_plan_calls
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            preinstalled_machine.transition_calls.load(Ordering::SeqCst),
            0
        );
        assert!(preinstalled_transport.drain_outbound().unwrap().is_empty());
    }
}

struct FailOnceTransport {
    fail_next: Mutex<bool>,
    outbound: Mutex<Vec<Vec<u8>>>,
}

impl FailOnceTransport {
    fn new() -> Self {
        Self {
            fail_next: Mutex::new(true),
            outbound: Mutex::new(Vec::new()),
        }
    }
}

impl Transport for FailOnceTransport {
    fn send(&self, message: Vec<u8>) -> Result<(), RuntimeError> {
        let mut fail_next = self
            .fail_next
            .lock()
            .map_err(|_| RuntimeError::TransportUnavailable)?;
        if *fail_next {
            *fail_next = false;
            return Err(RuntimeError::TransportUnavailable);
        }
        self.outbound
            .lock()
            .map_err(|_| RuntimeError::TransportUnavailable)?
            .push(message);
        Ok(())
    }

    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let mut outbound = self
            .outbound
            .lock()
            .map_err(|_| RuntimeError::TransportUnavailable)?;
        Ok(std::mem::take(&mut *outbound))
    }
}

struct FailOnceRuntime {
    state_store: MemoryStateStore,
    blob_store: MemoryBlobStore,
    signer: MemorySigner,
    transport: FailOnceTransport,
    clock: ManualClock,
    scheduler: MemoryScheduler,
}

impl FailOnceRuntime {
    fn new() -> Self {
        Self {
            state_store: MemoryStateStore::default(),
            blob_store: MemoryBlobStore::default(),
            signer: MemorySigner::new(ValidatorId::new([0x44; 32])),
            transport: FailOnceTransport::new(),
            clock: ManualClock::new(1_000),
            scheduler: MemoryScheduler::default(),
        }
    }
}

impl Runtime for FailOnceRuntime {
    type State = MemoryStateStore;
    type Blobs = MemoryBlobStore;
    type NodeSigner = MemorySigner;
    type Network = FailOnceTransport;
    type Time = ManualClock;
    type TaskScheduler = MemoryScheduler;

    fn state_store(&self) -> &Self::State {
        &self.state_store
    }

    fn blob_store(&self) -> &Self::Blobs {
        &self.blob_store
    }

    fn signer(&self) -> &Self::NodeSigner {
        &self.signer
    }

    fn transport(&self) -> &Self::Network {
        &self.transport
    }

    fn clock(&self) -> &Self::Time {
        &self.clock
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        &self.scheduler
    }
}

#[test]
fn http_result_round_trip_is_bounded_and_stable() {
    let id = request_id(0x31);
    let response = NodeResponse::new(
        id,
        NodeResponseStatus::Accepted,
        Some(canonical(TEST_PAYLOAD_TYPE_ID, 4)),
    )
    .unwrap();
    let result = HttpNodeResult::new(id, vec![response]).unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);
    assert_eq!(
        hex(&encoded),
        "534e524501e101000300010020000000313131313131313131313131313131313131313131313131\
         31313131313131310200040000000100000003005a00000056000000534e524502e0010003000100\
         20000000313131313131313131313131313131313131313131313131313131313131313102000200\
         00000100030018000000534e524512ef010001000100080000000400000000000000"
            .replace(' ', "")
    );
}

// --- DR-0082 bounded query-result codecs -----------------------------

#[test]
fn context_query_result_round_trip_is_bounded_and_stable() {
    let result = HttpContextQueryResult::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        HashSuiteId::new(1),
        1,
        1,
        1,
        AtomicityDomainId::new([0x11; 32]).unwrap(),
        vec![0xAA, 0xBB, 0xCC],
    )
    .unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpContextQueryResult::decode(&encoded).unwrap(), result);
    let expected_hex = concat!(
        "534e524502e10100090001000c00000073756e726973652d746573740200040000000300000003000800",
        "00000700000000000000040002000000010005000200000001000600020000000100070002000000010008",
        "0020000000111111111111111111111111111111111111111111111111111111111111111109000300000",
        "0aabbcc",
    );
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn context_query_result_rejects_unexpected_field() {
    let mut frame = CanonicalStruct::new(
        CONTEXT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_str(1, "sunrise-test").unwrap();
    frame.field_u32(2, 3).unwrap();
    frame.field_u64(3, 7).unwrap();
    frame.field_u16(4, 1).unwrap();
    frame.field_u16(5, 1).unwrap();
    frame.field_u16(6, 1).unwrap();
    frame.field_u16(7, 1).unwrap();
    frame.field_bytes(8, vec![0x11; 32]).unwrap();
    frame.field_bytes(9, vec![0xAA]).unwrap();
    frame.field_u16(10, 0).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpContextQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(10)
        ))
    ));
}

#[test]
fn context_query_result_rejects_zero_ids_long_chain_id_and_empty_config_bytes() {
    fn build(
        protocol_version: u32,
        hash_suite_id: u16,
        profile: u16,
        scheme: u16,
        binding: u16,
        chain: &str,
        config_bytes: Vec<u8>,
    ) -> Result<HttpContextQueryResult, QueryResultError> {
        HttpContextQueryResult::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(protocol_version),
            Epoch::new(7),
            HashSuiteId::new(hash_suite_id),
            profile,
            scheme,
            binding,
            AtomicityDomainId::new([0x11; 32]).unwrap(),
            config_bytes,
        )
    }

    assert_eq!(
        build(0, 1, 1, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroProtocolVersion)
    );
    assert_eq!(
        build(3, 0, 1, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroHashSuiteId)
    );
    assert_eq!(
        build(3, 1, 0, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroTransactionAuthProfileId)
    );
    assert_eq!(
        build(3, 1, 1, 0, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroSignatureSchemeId)
    );
    assert_eq!(
        build(3, 1, 1, 1, 0, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroAddressBindingId)
    );
    let long_chain = "x".repeat(MAX_CHAIN_ID_BYTES + 1);
    assert_eq!(
        build(3, 1, 1, 1, 1, &long_chain, vec![0xAA]),
        Err(QueryResultError::ChainIdTooLong(MAX_CHAIN_ID_BYTES + 1))
    );
    assert_eq!(
        build(3, 1, 1, 1, 1, "sunrise-test", Vec::new()),
        Err(QueryResultError::EmptyProtocolConfigBytes)
    );
    assert!(build(3, 1, 1, 1, 1, "sunrise-test", vec![0xAA]).is_ok());
}

fn sample_inline_object_bytes(object_id: ObjectId, version: u64) -> Vec<u8> {
    let object = Object {
        id: object_id,
        version,
        owner: Owner::Address(Address::new([0x21; 32])),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
        schema_version: 1,
        data: vec![0xDD, 0xEE],
    };
    encode_object(&object).unwrap()
}

fn sample_object_query_results() -> Vec<HttpObjectQueryResult> {
    let object_id = ObjectId::new([0x20; 32]);
    vec![
        HttpObjectQueryResult::Absent { object_id },
        HttpObjectQueryResult::Tombstoned {
            object_id,
            head_revision: ObjectHeadRevision::new(2).unwrap(),
            last_object_version: DurableObjectVersion::new(1).unwrap(),
        },
        HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: ObjectHeadRevision::new(1).unwrap(),
            object_version: DurableObjectVersion::new(1).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            creating_chain_id: ChainId::new("sunrise-test").unwrap(),
            creating_protocol_version: ProtocolVersion::new(3),
            canonical_object_bytes: sample_inline_object_bytes(object_id, 1),
        },
        HttpObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: ObjectHeadRevision::new(3).unwrap(),
            object_version: DurableObjectVersion::new(2).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x23; 32]),
            blob_digest: Digest32::new(HashAlgorithmId::Sha3_256, [0x24; 32]),
        },
    ]
}

#[test]
fn object_query_result_round_trips_every_status() {
    for case in sample_object_query_results() {
        let encoded = case.encode().unwrap();
        let decoded = HttpObjectQueryResult::decode(&encoded).unwrap();
        assert_eq!(decoded, case);
        assert_eq!(decoded.object_id(), case.object_id());
    }
}

#[test]
fn unchanged_object_query_statuses_preserve_encoding_v1() {
    let cases: Vec<HttpObjectQueryResult> = sample_object_query_results();
    for index in [0_usize, 1_usize, 3_usize] {
        let encoded: Vec<u8> = cases[index].encode().unwrap();
        assert_eq!(decode_canonical_frame(&encoded).unwrap().version(), 1);
    }
}

#[test]
fn object_query_result_current_inline_v2_matches_pinned_stable_vector() {
    let result = &sample_object_query_results()[2];
    let encoded = result.encode().unwrap();

    let expected_hex = "534e524503e1020009000100020000000300020020000000202020202020202020202020202020202020202020202020202020202020202003000800000001000000000000000400080000000100000000000000050002000000010006002000000022222222222222222222222222222222222222222222222222222222222222220700ec000000534e5245054001000600010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030048000000534e52450340010002000100020000000100020030000000534e52450240010001000100200000002121212121212121212121212121212121212121212121212121212121212121040038000000534e52450301010002000100020000000100020020000000999999999999999999999999999999999999999999999999999999999999999905000400000001000000060002000000ddee0a000c00000073756e726973652d746573740b000400000003000000";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn historical_object_query_v1_vector_decodes_without_digest_context() {
    let historical_hex = "534e524503e1010007000100020000000300020020000000202020202020202020202020202020202020202020202020202020202020202003000800000001000000000000000400080000000100000000000000050002000000010006002000000022222222222222222222222222222222222222222222222222222222222222220700ec000000534e5245054001000600010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030048000000534e52450340010002000100020000000100020030000000534e52450240010001000100200000002121212121212121212121212121212121212121212121212121212121212121040038000000534e52450301010002000100020000000100020020000000999999999999999999999999999999999999999999999999999999999999999905000400000001000000060002000000ddee";
    let historical_bytes: Vec<u8> = (0..historical_hex.len())
        .step_by(2)
        .map(|index: usize| u8::from_str_radix(&historical_hex[index..index + 2], 16).unwrap())
        .collect();
    let decoded = HttpObjectQueryResult::decode(&historical_bytes).unwrap();
    assert!(matches!(
        &decoded,
        HttpObjectQueryResult::HistoricalCurrentInline { .. }
    ));
    assert_eq!(decoded.encode().unwrap(), historical_bytes);
}

#[test]
fn object_query_result_binds_the_exact_requested_selector() {
    let a = ObjectId::new([0x30; 32]);
    let b = ObjectId::new([0x31; 32]);
    let result_a = HttpObjectQueryResult::Absent { object_id: a };
    let result_b = HttpObjectQueryResult::Absent { object_id: b };

    assert_eq!(result_a.object_id(), a);
    assert_eq!(result_b.object_id(), b);
    assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
    assert_eq!(
        HttpObjectQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .object_id(),
        a
    );
    assert_ne!(
        HttpObjectQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .object_id(),
        b
    );
}

#[test]
fn object_query_result_rejects_unknown_status_id() {
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_u16(1, 99).unwrap();
    frame
        .field_bytes(2, ObjectId::new([0x01; 32]).as_bytes().to_vec())
        .unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::UnknownObjectStatus(99))
    );
}

#[test]
fn object_query_result_absent_rejects_a_field_only_valid_for_another_status() {
    let object_id = ObjectId::new([0x32; 32]);
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ObjectQueryStatus::Absent.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 1).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(3)
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_absent() {
    let object_id = ObjectId::new([0x33; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::Absent.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_tombstoned() {
    let object_id = ObjectId::new([0x34; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::Tombstoned.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 2).unwrap();
    frame.field_u64(4, 1).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_current_blob_reference() {
    let object_id = ObjectId::new([0x35; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::CurrentBlobReference.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 3).unwrap();
    frame.field_u64(4, 2).unwrap();
    frame
        .field_u16(5, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(6, vec![0x23; 32]).unwrap();
    frame
        .field_u16(8, HashAlgorithmId::Sha3_256.as_u16())
        .unwrap();
    frame.field_bytes(9, vec![0x24; 32]).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_mismatched_canonical_type_id() {
    let request_id = request_id(0x01);
    let receipt_bytes = HttpReceiptQueryResult::Absent { request_id }
        .encode()
        .unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&receipt_bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId { .. }
        ))
    ));
}

fn current_inline_object_frame(
    object_id: ObjectId,
    object_version: u64,
    canonical_object_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ObjectQueryStatus::CurrentInline.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 1).unwrap();
    frame.field_u64(4, object_version).unwrap();
    frame
        .field_u16(5, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(6, vec![0x22; 32]).unwrap();
    frame.field_bytes(7, canonical_object_bytes).unwrap();
    frame.finish().unwrap()
}

#[test]
fn object_query_result_current_inline_rejects_oversized_body() {
    let object_id = ObjectId::new([0x25; 32]);
    let bytes = current_inline_object_frame(
        object_id,
        1,
        vec![0_u8; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1],
    );

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectBodyTooLarge {
            actual: MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        })
    );
}

#[test]
fn object_query_result_current_inline_rejects_invalid_nested_object_bytes() {
    let object_id = ObjectId::new([0x26; 32]);
    let bytes = current_inline_object_frame(object_id, 1, vec![0xFF, 0x00]);

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::InvalidCanonicalObject(_))
    ));
}

#[test]
fn object_query_result_current_inline_rejects_nested_identity_mismatch() {
    let object_id = ObjectId::new([0x27; 32]);
    let other_id = ObjectId::new([0x28; 32]);
    let nested_bytes = sample_inline_object_bytes(other_id, 1);
    let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectIdentityMismatch {
            expected: object_id,
            actual: other_id,
        })
    );
}

#[test]
fn object_query_result_current_inline_rejects_nested_version_mismatch() {
    let object_id = ObjectId::new([0x29; 32]);
    let nested_bytes = sample_inline_object_bytes(object_id, 2);
    let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectVersionMismatch {
            expected: 1,
            actual: 2,
        })
    );
}

fn sample_receipt_query_results() -> Vec<HttpReceiptQueryResult> {
    let request_id = request_id(0x50);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]);
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id, event_digest, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    vec![
        HttpReceiptQueryResult::Absent { request_id },
        HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes,
        },
    ]
}

#[test]
fn receipt_query_result_round_trips_every_status() {
    for case in sample_receipt_query_results() {
        let encoded = case.encode().unwrap();
        let decoded = HttpReceiptQueryResult::decode(&encoded).unwrap();
        assert_eq!(decoded, case);
        assert_eq!(decoded.request_id(), case.request_id());
    }
}

#[test]
fn receipt_query_result_present_matches_pinned_stable_vector() {
    let result = &sample_receipt_query_results()[1];
    let encoded = result.encode().unwrap();

    let expected_hex = "534e524504e10100050001000200000002000200200000005050505050505050505050505050505050505050505050505050505050505050030002000000010004002000000055555555555555555555555555555555555555555555555555555555555555550500aa000000534e524503e0010005000100200000005050505050505050505050505050505050505050505050505050505050505050020002000000010003002000000055555555555555555555555555555555555555555555555555555555555555550400040000000100000005003c00000038000000534e524502e00100020001002000000050505050505050505050505050505050505050505050505050505050505050500200020000000100";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn receipt_query_result_binds_the_exact_requested_selector() {
    let a = request_id(0x60);
    let b = request_id(0x61);
    let result_a = HttpReceiptQueryResult::Absent { request_id: a };
    let result_b = HttpReceiptQueryResult::Absent { request_id: b };

    assert_eq!(result_a.request_id(), a);
    assert_eq!(result_b.request_id(), b);
    assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
    assert_eq!(
        HttpReceiptQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .request_id(),
        a
    );
}

#[test]
fn receipt_query_result_rejects_unknown_status_id() {
    let mut frame = CanonicalStruct::new(
        RECEIPT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_u16(1, 7).unwrap();
    frame
        .field_bytes(2, request_id(0x01).as_bytes().to_vec())
        .unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::UnknownReceiptStatus(7))
    );
}

fn present_receipt_frame(
    request_id: RequestId,
    event_digest: Digest32,
    dedup_record_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(
        RECEIPT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ReceiptQueryStatus::Present.as_u16())
        .unwrap();
    frame
        .field_bytes(2, request_id.as_bytes().to_vec())
        .unwrap();
    frame
        .field_u16(3, event_digest.algorithm().as_u16())
        .unwrap();
    frame.field_bytes(4, event_digest.bytes().to_vec()).unwrap();
    frame.field_bytes(5, dedup_record_bytes).unwrap();
    frame.finish().unwrap()
}

// `receipt_query_result_rejects_oversized_body` is not constructible as a
// unit test: `runtime::MAX_DURABLE_RECEIPT_BYTES` currently equals
// `canonical_encoding::MAX_CANONICAL_FRAME_BYTES`, so any field that large
// already fails to canonically frame (`FrameTooLarge`) before this
// decoder's own `ReceiptTooLarge` bound ever runs. The check is kept as
// defense in depth in case the two bounds diverge in the future.

#[test]
fn receipt_query_result_rejects_invalid_nested_dedup_record_bytes() {
    let request_id = request_id(0x53);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x54; 32]);
    let bytes = present_receipt_frame(request_id, event_digest, vec![0xFF, 0x00]);

    assert!(matches!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::InvalidDedupRecord(_))
    ));
}

#[test]
fn receipt_query_result_rejects_nested_request_id_mismatch() {
    let request_id_outer = request_id(0x56);
    let request_id_nested = request_id(0x57);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x58; 32]);
    let response =
        NodeResponse::new(request_id_nested, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id_nested, event_digest, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    let bytes = present_receipt_frame(request_id_outer, event_digest, dedup_record_bytes);

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::RequestIdentityMismatch {
            expected: request_id_outer,
            actual: request_id_nested,
        })
    );
}

#[test]
fn receipt_query_result_rejects_nested_event_digest_mismatch() {
    let request_id = request_id(0x59);
    let event_digest_outer = Digest32::new(HashAlgorithmId::Sha2_256, [0x5A; 32]);
    let event_digest_nested = Digest32::new(HashAlgorithmId::Sha2_256, [0x5B; 32]);
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id, event_digest_nested, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    let bytes = present_receipt_frame(request_id, event_digest_outer, dedup_record_bytes);

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::EventDigestMismatch)
    );
}

#[test]
fn next_nonce_query_result_round_trip_is_bounded_and_stable() {
    let result = HttpNextNonceQueryResult::new(Address::new([0x61; 32]), Epoch::new(7), 42);
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNextNonceQueryResult::decode(&encoded).unwrap(), result);
    let expected_hex = "534e524505e1010003000100200000006161616161616161616161616161616161616161616161616161616161616161020008000000070000000000000003000800000\
02a00000000000000";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn next_nonce_query_result_binds_the_exact_requested_sender() {
    let a = HttpNextNonceQueryResult::new(Address::new([0x70; 32]), Epoch::new(7), 1);
    let b = HttpNextNonceQueryResult::new(Address::new([0x71; 32]), Epoch::new(7), 1);

    assert_eq!(a.sender(), Address::new([0x70; 32]));
    assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    assert_eq!(
        HttpNextNonceQueryResult::decode(&a.encode().unwrap())
            .unwrap()
            .sender(),
        Address::new([0x70; 32])
    );
}

#[test]
fn next_nonce_query_result_rejects_mismatched_canonical_type_id() {
    let object_bytes = HttpObjectQueryResult::Absent {
        object_id: ObjectId::new([0x01; 32]),
    }
    .encode()
    .unwrap();

    assert!(matches!(
        HttpNextNonceQueryResult::decode(&object_bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId { .. }
        ))
    ));
}

#[test]
fn indexed_recovery_authority_bounds_operation_inside_lease() {
    let domain = AtomicityDomainId::new([0x61; 32]).unwrap();
    let fence = WriterFenceGeneration::new(3).unwrap();
    assert_eq!(
        IndexedOutboxRecoveryAuthority::new(domain, fence, 0, 30_000),
        Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
    );
    assert_eq!(
        IndexedOutboxRecoveryAuthority::new(domain, fence, 30_000, 30_000),
        Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
    );
    assert_eq!(
        IndexedOutboxRecoveryAuthority::new(
            domain,
            fence,
            1_000,
            MAX_DURABLE_OUTBOX_LEASE_MILLIS + 1,
        ),
        Err(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)
    );
    let authority = indexed_authority();
    assert_eq!(authority.domain(), domain);
    assert_eq!(authority.writer_fence(), fence);
    assert_eq!(
        StructuredDurableRequestAuthority::new(fence, 30_000, 30_000),
        Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)
    );
    assert_eq!(structured_request_authority().writer_fence(), fence);
}

#[tokio::test]
async fn indexed_recovery_reconciles_claim_and_ack_before_returning_success() {
    let request_id = request_id(0x73);
    let payload = event(request_id).encode().unwrap();
    let lease_id = DurableOutboxLeaseId::new([0x71; 32]).unwrap();
    let claim = DurableOutboxClaim::from_parts(
        OutboxRequestId::new(*request_id.as_bytes()).unwrap(),
        0,
        lease_id,
        40_000,
        payload.clone(),
    )
    .unwrap();
    let store = ScriptedIndexedStore::new(
        vec![
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
            DurableOutboxClaimOutcome::Claimed(claim),
        ],
        vec![
            DurableOutboxAcknowledgementOutcome::Indeterminate(
                IndeterminateCommitReason::ConnectionLost,
            ),
            DurableOutboxAcknowledgementOutcome::Acknowledged,
        ],
    );
    let runtime = Arc::new(indexed_runtime(store));

    let report = recover_indexed_outbox_once(
        Arc::clone(&runtime),
        indexed_authority(),
        Arc::new(FixedIndexedIdentity),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
    )
    .await
    .unwrap();

    assert_eq!(
        report.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(request_id)
    );
    assert_eq!(report.continuation_cursor(), None);
    assert_eq!(runtime.transport().drain_outbound().unwrap(), vec![payload]);
    let claim_requests = runtime.state_store().claim_requests.lock().unwrap();
    assert_eq!(claim_requests.len(), 2);
    assert_eq!(claim_requests[0], claim_requests[1]);
    drop(claim_requests);
    let acknowledgement_requests = runtime
        .state_store()
        .acknowledgement_requests
        .lock()
        .unwrap();
    assert_eq!(acknowledgement_requests.len(), 2);
    assert_eq!(acknowledgement_requests[0], acknowledgement_requests[1]);
}

#[tokio::test]
async fn indexed_recovery_never_sends_an_unreconciled_claim() {
    let store = ScriptedIndexedStore::new(
        vec![
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded),
        ],
        Vec::new(),
    );
    let runtime = Arc::new(indexed_runtime(store));

    let error = recover_indexed_outbox_once(
        Arc::clone(&runtime),
        indexed_authority(),
        Arc::new(FixedIndexedIdentity),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        IndexedOutboxRecoveryError::ClaimIndeterminate(IndeterminateCommitReason::ConnectionLost)
    ));
    assert!(runtime.transport().drain_outbound().unwrap().is_empty());
    assert!(
        runtime
            .state_store()
            .acknowledgement_requests
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn structured_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
    for cancel_at_call in 1_usize..=3_usize {
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
        let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
        let clock: Arc<ManualClock> = Arc::new(ManualClock::new(10_000));
        let config: NodeConfig = config();
        let domain: AtomicityDomainId = AtomicityDomainId::new([0x84; 32]).unwrap();
        let protocol_config: ProtocolConfig = active_protocol_config(domain);
        let cancellation: Arc<StepCancellation> = Arc::new(StepCancellation::new(cancel_at_call));
        let app: Router = structured_app_with_cancellation(
            Arc::clone(&store),
            Arc::clone(&transport),
            clock,
            protocol_config,
            config.clone(),
            cancellation.clone(),
        );
        let id: RequestId = request_id(u8::try_from(0x30_usize + cancel_at_call).unwrap());
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x34);
        let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);

        let response: Response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "invocation-cancelled-before-storage"
        );
        assert_eq!(cancellation.calls(), cancel_at_call);
        assert!(transport.drain_outbound().unwrap().is_empty());
        let verification_context: DurableOperationContext = DurableOperationContext::new(
            fence,
            StorageDeadline::new(11_000).unwrap(),
            StorageCorrelationId::new([0x41; 16]).unwrap(),
        );
        let state: VersionedStateValue = store
            .get_versioned_durable(&verification_context, domain, config.state_key())
            .unwrap();
        assert_eq!(state.revision(), runtime::StateRevision::INITIAL);
        assert_eq!(state.value(), None);
        assert_eq!(
            store
                .get_request_receipt(
                    &verification_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap(),
                )
                .unwrap(),
            None
        );
        let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
            domain,
            OutboxRequestId::new(*id.as_bytes()).unwrap(),
            10_000,
            DurableOutboxLeaseId::new([u8::try_from(0x44_usize + cancel_at_call).unwrap(); 32])
                .unwrap(),
            11_000,
        )
        .unwrap();
        assert_eq!(
            store.claim_request_outbox(&verification_context, claim_request),
            DurableOutboxClaimOutcome::NoDueWork
        );
    }
}

#[tokio::test]
async fn structured_route_ignores_cancellation_after_storage_dispatch_begins() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let inner: MemoryDurableStateStore = MemoryDurableStateStore::new(fence);
    inner.set_time(10_000);
    let cancellation: Arc<ManualCancellation> = Arc::new(ManualCancellation::default());
    let store: Arc<CancelOnFirstReceiptReadStore> = Arc::new(CancelOnFirstReceiptReadStore::new(
        inner,
        Arc::clone(&cancellation),
    ));
    let transport: Arc<MemoryTransport> = Arc::new(MemoryTransport::default());
    let config: NodeConfig = config();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x85; 32]).unwrap();
    let protocol_config: ProtocolConfig = active_protocol_config(domain);
    let id: RequestId = request_id(0x35);
    let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x35);
    let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);
    let app: Router = structured_app_with_cancellation(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        cancellation.clone(),
    );

    let response: Response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(cancellation.is_cancelled());
    assert_eq!(transport.drain_outbound().unwrap().len(), 1);
    let verification_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(11_000).unwrap(),
        StorageCorrelationId::new([0x42; 16]).unwrap(),
    );
    let claim_request: RequestOutboxClaimRequest = RequestOutboxClaimRequest::new(
        domain,
        OutboxRequestId::new(*id.as_bytes()).unwrap(),
        10_000,
        DurableOutboxLeaseId::new([0x43; 32]).unwrap(),
        11_000,
    )
    .unwrap();
    assert_eq!(
        store.claim_request_outbox(&verification_context, claim_request),
        DurableOutboxClaimOutcome::NoDueWork
    );
}

#[tokio::test]
async fn structured_route_commits_and_claims_only_the_exact_request() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let clock = Arc::new(ManualClock::new(10_000));
    let config = config();
    let placement = placement(0x81, 7);
    let domain = placement.domain();
    let machine = IncrementMachine::new(config.state_key());
    let older_request_id = request_id(0x21);
    let older_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(11_000).unwrap(),
        StorageCorrelationId::new([0x31; 16]).unwrap(),
    );
    handle_resolved_durable_idempotent_event(
        store.as_ref(),
        &older_context,
        &placement,
        &config,
        &resolver(),
        event(older_request_id),
        &machine,
    )
    .unwrap();

    let current_request_id = request_id(0x22);
    let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x22);
    let submit: NodeEvent = signed_submit_transaction_event(&signing_key, current_request_id, 0);
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::clone(&clock),
        protocol_config,
        config.clone(),
    );
    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let outbound = transport.drain_outbound().unwrap();
    assert_eq!(outbound.len(), 1);
    let delivered = NodeEvent::decode(&outbound[0]).unwrap();
    assert_eq!(
        decode_canonical_frame(delivered.payload())
            .unwrap()
            .required_u64(1),
        Ok(2)
    );

    let due_request = DueOutboxClaimRequest::new(
        domain,
        10_000,
        DurableOutboxLeaseId::new([0x91; 32]).unwrap(),
        40_000,
    )
    .unwrap();
    let due_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(11_000).unwrap(),
        StorageCorrelationId::new([0x32; 16]).unwrap(),
    );
    let current_claim_request = RequestOutboxClaimRequest::new(
        domain,
        OutboxRequestId::new(*current_request_id.as_bytes()).unwrap(),
        10_000,
        DurableOutboxLeaseId::new([0x92; 32]).unwrap(),
        40_000,
    )
    .unwrap();
    assert_eq!(
        store.claim_request_outbox(&due_context, current_claim_request),
        DurableOutboxClaimOutcome::NoDueWork
    );
    let DurableOutboxClaimOutcome::Claimed(older_claim) =
        store.claim_due_outbox(&due_context, due_request)
    else {
        panic!("older request should remain due after exact-request delivery");
    };
    assert_eq!(
        older_claim.request_id().as_bytes(),
        older_request_id.as_bytes()
    );
}

#[tokio::test]
async fn structured_route_never_sends_an_unreconciled_request_claim() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let inner = MemoryDurableStateStore::new(fence);
    inner.set_time(10_000);
    let store = Arc::new(IndeterminateRequestClaimStore::new(inner));
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let placement = placement(0x82, 7);
    let domain = placement.domain();
    let protocol_config = active_protocol_config(domain);
    let id = request_id(0x23);
    let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x23);
    let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);
    let app = structured_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "outbox-claim-indeterminate"
    );
    assert!(transport.drain_outbound().unwrap().is_empty());
    let commit_contexts = store.commit_contexts.lock().unwrap();
    let claim_contexts = store.claim_contexts.lock().unwrap();
    let claim_requests = store.claim_requests.lock().unwrap();
    assert_eq!(commit_contexts.len(), 1);
    assert_eq!(claim_contexts.len(), 2);
    assert_eq!(claim_requests.len(), 2);
    assert_eq!(commit_contexts[0], claim_contexts[0]);
    assert_eq!(claim_contexts[0], claim_contexts[1]);
    assert_eq!(claim_requests[0], claim_requests[1]);
    assert_eq!(claim_requests[0].domain(), domain);
    assert_eq!(claim_requests[0].request_id().as_bytes(), id.as_bytes());
}

#[tokio::test]
async fn structured_route_maps_writer_fencing_without_publishing_output() {
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(4).unwrap(),
    ));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(
        AtomicityDomainId::new([0x83; 32]).expect("test domain must be non-zero"),
    );
    let app = structured_app(
        store,
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x24);
    let submit: NodeEvent = signed_submit_transaction_event(&signing_key, request_id(0x24), 0);

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(submit.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "durable-storage-unavailable"
    );
    assert!(transport.drain_outbound().unwrap().is_empty());
}

// ── preinstalled-WASM structured durable route ──────────────────────

#[tokio::test]
async fn preinstalled_route_write_commits_accepted_and_advances_object_version_and_nonce_receipt() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xB1; 32]).unwrap();
    let module_id = ModuleId::new([0x70; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x51);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xB1; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xB2; 32]), sender, 0x40);
    let write_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x41,
    );
    let write_object_id = write_ref.id;
    let catalog = Arc::new(catalog);
    let blob_store = Arc::new(MemoryBlobStore::default());
    let app = preinstalled_app_with_blob_store(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        Arc::clone(&catalog),
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let id = request_id(0xB3);
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        manifest.clone(),
        module_ref.clone(),
        vec![1, 2],
    );

    let response = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpNodeResult::decode(&bytes).unwrap();
    assert_eq!(result.responses().len(), 1);
    assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);
    assert!(result.responses()[0].payload().is_some());

    let write_head = store
        .get_object_head(&setup_context, domain, write_object_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    let write_v2 = store
        .get_object_version(
            &setup_context,
            domain,
            write_object_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(
        matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
        "a body at or under the threshold must stay inline"
    );
    assert_eq!(
        committed_object(&write_v2, blob_store.as_ref()).data,
        vec![0xCA, 0xFE]
    );
    assert!(
        store
            .get_request_receipt(
                &setup_context,
                domain,
                DurableRequestId::new(*id.as_bytes()).unwrap()
            )
            .unwrap()
            .is_some()
    );

    // A fresh request at the same already-spent nonce fails with a
    // conflict, proving the nonce advanced past 0.
    let replay_nonce_event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        request_id(0xB4),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let nonce_response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(replay_nonce_event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(nonce_response.into_body(), 128).await.unwrap(),
        "sender-nonce-mismatch"
    );
}

/// End-to-end composition proof: a signed `Write` access naming a
/// blob-backed previous version is only readable at all because the
/// router dispatches through the exact `BlobStore` supplied to
/// [`StructuredDurableNativeComponents::new`], not a hidden default. The
/// counting double proves the fetch was dispatched through it, and the
/// committed new version — an ordinary small body, so it stays inline
/// rather than being republished — carries the fetched blob's own data.
#[tokio::test]
async fn preinstalled_route_reads_blob_backed_object_through_supplied_blob_store() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let blob_store = Arc::new(CountingBlobStore::default());
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xBB; 32]).unwrap();
    let module_id = ModuleId::new([0x72; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x53);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xBB; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xBC; 32]), sender, 0x40);
    let write_ref = commit_owned_blob_object(
        store.as_ref(),
        blob_store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x41,
    );
    let write_object_id = write_ref.id;
    let catalog = Arc::new(catalog);
    let app = preinstalled_app_with_blob_store(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        Arc::clone(&catalog),
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let id = request_id(0xBD);
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpNodeResult::decode(&bytes).unwrap();
    assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);

    assert_eq!(
        blob_store.get_calls(),
        1,
        "the request must dispatch through the exact supplied blob store"
    );
    let write_v2 = store
        .get_object_version(
            &setup_context,
            domain,
            write_object_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(
        matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
        "a body at or under the threshold must stay inline"
    );
    assert_eq!(
        committed_object(&write_v2, blob_store.as_ref()).data,
        vec![0xCA, 0xFE]
    );
}

#[tokio::test]
async fn preinstalled_route_exact_duplicate_does_not_reexecute_or_reapply() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xB5; 32]).unwrap();
    let module_id = ModuleId::new([0x71; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x52);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xB5; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xB6; 32]), sender, 0x42);
    let write_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x43,
    );
    let write_object_id = write_ref.id;
    let catalog = Arc::new(catalog);
    let app = preinstalled_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        request_id(0xB7),
        0,
        manifest,
        module_ref,
        vec![3, 4],
    );
    let body = event.encode().unwrap();

    let first = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_bytes = to_bytes(first.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();

    let second = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_bytes = to_bytes(second.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();

    assert_eq!(first_bytes, second_bytes);
    let write_head = store
        .get_object_head(&setup_context, domain, write_object_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
}

#[tokio::test]
async fn preinstalled_route_replay_after_sqlite_reopen_returns_persisted_result() {
    let database = TestDatabase::new();
    let fence = WriterFenceGeneration::new(3).unwrap();
    let chain = ChainId::new("sunrise-test").unwrap();
    let validator = ValidatorId::new([0x44; 32]);
    let domain = AtomicityDomainId::new([0xB8; 32]).unwrap();
    let namespace = SqliteNamespace::new(chain, validator, domain);
    let config = config();
    let module_id = ModuleId::new([0x72; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let catalog = Arc::new(catalog);
    let signing_key = dev_signing_key(0x53);
    let sender = dev_sender_address(&signing_key);
    let id = request_id(0xB9);
    let mut manifest = AccessManifest::new();

    let first_bytes = {
        let store =
            Arc::new(SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap());
        let setup_context = live_operation_context(fence, 0xB9);
        let write_object = owned_object(ObjectId::new([0xBA; 32]), sender, 0x44);
        let write_ref = commit_owned_object(
            store.as_ref(),
            &setup_context,
            domain,
            write_object,
            "sunrise-test",
            9,
            0x45,
        );
        manifest.push(AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        });
        let app = preinstalled_app(
            Arc::clone(&store),
            Arc::new(MemoryTransport::default()),
            Arc::new(SystemClock),
            protocol_config.clone(),
            config.clone(),
            Arc::clone(&catalog),
            9,
        );
        let event = signed_preinstalled_wasm_submit_transaction_event(
            &signing_key,
            id,
            0,
            manifest.clone(),
            module_ref.clone(),
            vec![5, 6],
        );
        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap()
    };

    let reopened = Arc::new(SqliteDurableStore::open(&database.path, namespace, fence).unwrap());

    // Directly prove the durable receipt survived the close/reopen,
    // independent of the exact-replay HTTP round trip below.
    let receipt_context = live_operation_context(fence, 0xBC);
    assert!(
        reopened
            .get_request_receipt(
                &receipt_context,
                domain,
                DurableRequestId::new(*id.as_bytes()).unwrap(),
            )
            .unwrap()
            .is_some()
    );

    let replay_app = preinstalled_app(
        Arc::clone(&reopened),
        Arc::new(MemoryTransport::default()),
        Arc::new(SystemClock),
        protocol_config.clone(),
        config.clone(),
        Arc::clone(&catalog),
        9,
    );
    let replay_event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        manifest.clone(),
        module_ref.clone(),
        vec![5, 6],
    );
    let replay_response = replay_app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(replay_event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay_bytes = to_bytes(replay_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(first_bytes, replay_bytes);

    let read_context = live_operation_context(fence, 0xBB);
    let write_head = reopened
        .get_object_head(&read_context, domain, ObjectId::new([0xBA; 32]))
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));

    // A fresh request ID at the already-spent nonce 0, with the same
    // module/object access, conflicts. Exact replay above reconciles
    // from the persisted receipt before ever checking the nonce, so this
    // proves the sender-nonce record itself survived reopen, not just
    // the receipt.
    let nonce_probe_app = preinstalled_app(
        reopened,
        Arc::new(MemoryTransport::default()),
        Arc::new(SystemClock),
        protocol_config,
        config,
        catalog,
        9,
    );
    let nonce_probe_event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        request_id(0xBD),
        0,
        manifest,
        module_ref,
        vec![5, 6],
    );
    let nonce_probe_response = nonce_probe_app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(nonce_probe_event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_probe_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(nonce_probe_response.into_body(), 128)
            .await
            .unwrap(),
        "sender-nonce-mismatch"
    );
}

#[tokio::test]
async fn preinstalled_route_trap_returns_rejected_and_leaves_object_unchanged() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xBC; 32]).unwrap();
    let module_id = ModuleId::new([0x73; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_trap_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x54);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xBC; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xBD; 32]), sender, 0x46);
    let write_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x47,
    );
    let write_object_id = write_ref.id;
    let catalog = Arc::new(catalog);
    let app = preinstalled_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let id = request_id(0xBE);
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        manifest.clone(),
        module_ref.clone(),
        vec![7, 8],
    );

    let response = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpNodeResult::decode(&bytes).unwrap();
    assert_eq!(result.responses().len(), 1);
    assert_eq!(result.responses()[0].status(), NodeResponseStatus::Rejected);

    let write_head = store
        .get_object_head(&setup_context, domain, write_object_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));

    // The trap still consumed the nonce: a fresh request at the same
    // nonce conflicts.
    let replay_nonce_event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        request_id(0xBF),
        0,
        manifest,
        module_ref,
        vec![7, 8],
    );
    let nonce_response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(replay_nonce_event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        to_bytes(nonce_response.into_body(), 128).await.unwrap(),
        "sender-nonce-mismatch"
    );
}

#[tokio::test]
async fn preinstalled_route_zero_object_call_rejects_before_storage_dispatch() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let inner = MemoryDurableStateStore::new(fence);
    inner.set_time(10_000);
    let cancellation = Arc::new(ManualCancellation::default());
    let store = Arc::new(CancelOnFirstReceiptReadStore::new(
        inner,
        Arc::clone(&cancellation),
    ));
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xC0; 32]).unwrap();
    let module_id = ModuleId::new([0x74; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x55);
    let catalog = Arc::new(catalog);
    let app = preinstalled_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );
    let id = request_id(0xC1);
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        AccessManifest::new(),
        module_ref,
        vec![1],
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "preinstalled-module-zero-object-access"
    );
    // `CancelOnFirstReceiptReadStore` flips this signal the moment
    // `get_request_receipt` is first dispatched, so it staying false
    // directly proves the structured durable path never reached its
    // first storage read for this rejected call.
    assert!(!cancellation.is_cancelled());
    assert_eq!(store.receipt_reads(), 0);
    let read_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xC1; 16]).unwrap(),
    );
    assert_eq!(
        store
            .inner
            .get_request_receipt(
                &read_context,
                domain,
                DurableRequestId::new(*id.as_bytes()).unwrap()
            )
            .unwrap(),
        None
    );
    assert!(transport.drain_outbound().unwrap().is_empty());
}

/// A discriminating test proving `MissingEntrypoint` (a client-chosen
/// entrypoint name absent from an otherwise valid, catalog-verified
/// module) maps to `422` and never reaches object mutation or a
/// persisted receipt, exercising `execution_error_response`'s
/// classification through the full HTTP path rather than only as a unit
/// case on `node_error_response`.
#[tokio::test]
async fn preinstalled_route_missing_entrypoint_rejects_as_client_fault_without_mutation() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD2; 32]).unwrap();
    let module_id = ModuleId::new([0x75; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x57);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD2; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xD3; 32]), sender, 0x48);
    let write_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x49,
    );
    let write_object_id = write_ref.id;
    let catalog = Arc::new(catalog);
    let app = preinstalled_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let id = request_id(0xD4);
    // `preinstalled_write_wasm_bytes` only exports `"run"`.
    let event = signed_preinstalled_wasm_submit_transaction_event_with_entrypoint(
        &signing_key,
        id,
        0,
        manifest,
        module_ref,
        "does-not-exist",
        vec![1, 2],
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "preinstalled-module-entrypoint-unknown"
    );
    assert_eq!(
        store
            .get_request_receipt(
                &setup_context,
                domain,
                DurableRequestId::new(*id.as_bytes()).unwrap()
            )
            .unwrap(),
        None
    );
    let write_head = store
        .get_object_head(&setup_context, domain, write_object_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
    assert!(transport.drain_outbound().unwrap().is_empty());
}

/// Proves the catalog/commitment-mismatch classification end to end:
/// the caller-supplied catalog entry's exact semantics-envelope bytes no
/// longer rehash to the governance-committed `semantics_hash`, which is a
/// host catalog defect, so this must be an opaque `500`, not a client
/// fault, and must never leak the internal `Display` text of the mismatch.
#[tokio::test]
async fn preinstalled_route_catalog_semantics_hash_mismatch_is_opaque_host_failure() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD5; 32]).unwrap();
    let module_id = ModuleId::new([0x76; 32]);
    let (registry, _genuine_catalog, module_ref) = preinstalled_module_fixture(
        &resolver(),
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
    );
    // Corrupt the caller-supplied catalog: same module_id/version/WASM/
    // manifest as the registry commitment, but different exact semantics
    // envelope bytes, so the catalog entry no longer rehashes to the
    // registry's committed `semantics_hash`.
    let mismatched_semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::opaque_only(
            b"http-preinstalled-semantics-mismatch".to_vec(),
        )
        .unwrap();
    let mismatched_entry = PreinstalledModuleCatalogEntry::new(
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        preinstalled_manifest(module_id, 64),
        mismatched_semantics_envelope,
    )
    .unwrap();
    let catalog = Arc::new(PreinstalledModuleCatalog::new(vec![mismatched_entry]).unwrap());
    let protocol_config = preinstalled_protocol_config(domain, registry);
    let signing_key = dev_signing_key(0x58);
    let sender = dev_sender_address(&signing_key);
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD5; 16]).unwrap(),
    );
    let write_object = owned_object(ObjectId::new([0xD6; 32]), sender, 0x4A);
    let write_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        write_object,
        "sunrise-test",
        9,
        0x4B,
    );
    let write_object_id = write_ref.id;
    let app = preinstalled_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );
    let mut manifest = AccessManifest::new();
    manifest.push(AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    });
    let id = request_id(0xD7);
    let event = signed_preinstalled_wasm_submit_transaction_event(
        &signing_key,
        id,
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );

    let response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "preinstalled-module-catalog-mismatch"
    );
    assert_eq!(
        store
            .get_request_receipt(
                &setup_context,
                domain,
                DurableRequestId::new(*id.as_bytes()).unwrap()
            )
            .unwrap(),
        None
    );
    let write_head = store
        .get_object_head(&setup_context, domain, write_object_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
    assert!(transport.drain_outbound().unwrap().is_empty());
}

#[tokio::test]
async fn structured_route_still_rejects_write_and_consume_access() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xC2; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        Arc::clone(&transport),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let signing_key = dev_signing_key(0x56);
    let sender = dev_sender_address(&signing_key);

    for (byte, mode) in [(0xC3_u8, AccessMode::Write), (0xC4_u8, AccessMode::Consume)] {
        let mut tx = unsigned_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
        );
        tx.access_manifest.push(AccessEntry {
            object_ref: ObjectRef {
                id: ObjectId::new([byte; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
            },
            mode,
        });
        let signed_bytes = signed_transaction_bytes(&signing_key, &tx);
        let event = submit_transaction_event(request_id(byte), signed_bytes);

        let response = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(event.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "object-mutating-access-unsupported"
        );
    }
}

#[tokio::test]
async fn preinstalled_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
    // Both the shared axum wrapper's own initial observation (call 1) and
    // the two checkpoints inside the shared
    // `invoke_structured_durable_event_with_execution` core (calls 2 and
    // 3, mirroring `structured_route_rejects_cancellation_at_each_pre_storage_checkpoint`)
    // must reject on this route too, proving the new thin wrapper wires
    // its own state's cancellation signal through correctly.
    for cancel_at_call in 1_usize..=3_usize {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let config = config();
        let domain = AtomicityDomainId::new([0xC5; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let cancellation: Arc<StepCancellation> = Arc::new(StepCancellation::new(cancel_at_call));
        let catalog = Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap());
        let app = preinstalled_app_with_cancellation(
            Arc::clone(&store),
            Arc::clone(&transport),
            Arc::new(ManualClock::new(10_000)),
            protocol_config,
            config.clone(),
            catalog,
            9,
            cancellation.clone(),
        );
        let id = request_id(u8::try_from(0xD0_usize + cancel_at_call).unwrap());
        let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0x5A);
        let submit: NodeEvent = signed_submit_transaction_event(&signing_key, id, 0);

        let response = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(submit.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "invocation-cancelled-before-storage"
        );
        assert_eq!(cancellation.calls(), cancel_at_call);
        assert!(transport.drain_outbound().unwrap().is_empty());
        let verification_context = DurableOperationContext::new(
            fence,
            StorageDeadline::new(11_000).unwrap(),
            StorageCorrelationId::new([0xD1; 16]).unwrap(),
        );
        assert_eq!(
            store
                .get_request_receipt(
                    &verification_context,
                    domain,
                    DurableRequestId::new(*id.as_bytes()).unwrap(),
                )
                .unwrap(),
            None
        );
    }
}

/// Proves `structured_durable_router` and `preinstalled_wasm_structured_durable_router`
/// share identical unsupported-content-type/content-encoding/body rejection
/// behavior, since both now dispatch through the one private
/// `submit_structured_durable_event_common` helper rather than duplicated
/// per-route logic.
#[tokio::test]
async fn structured_and_preinstalled_routes_share_content_type_and_body_rejection_behavior() {
    let domain = AtomicityDomainId::new([0xCA; 32]).unwrap();
    let config = config();
    let structured_store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    structured_store.set_time(10_000);
    let structured = structured_app(
        structured_store,
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        active_protocol_config(domain),
        config.clone(),
    );
    let preinstalled_store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    preinstalled_store.set_time(10_000);
    let preinstalled = preinstalled_app(
        preinstalled_store,
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        active_protocol_config(domain),
        config,
        Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap()),
        9,
    );

    for app in [structured, preinstalled] {
        let wrong_type = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(event(request_id(0xCB)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            to_bytes(wrong_type.into_body(), 128).await.unwrap(),
            "unsupported-content-type"
        );

        let unsupported_encoding = app
            .clone()
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from(event(request_id(0xCC)).encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unsupported_encoding.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            to_bytes(unsupported_encoding.into_body(), 128)
                .await
                .unwrap(),
            "unsupported-content-encoding"
        );

        let oversized_body = app
            .oneshot(
                Request::post(NODE_EVENT_PATH)
                    .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                    .body(Body::from(vec![0_u8; MAX_HTTP_EVENT_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized_body.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[tokio::test]
async fn unattended_recovery_rejects_when_shared_blocking_capacity_is_exhausted() {
    let runtime: Arc<MemoryRuntime> = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let blocking_executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let _held_permit = blocking_executor.try_acquire().unwrap();

    let result = recover_outboxes_once(
        runtime,
        config(),
        Arc::new(SequenceLeaseIds::default()),
        blocking_executor,
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .await;

    assert!(matches!(
        result,
        Err(NativeOutboxRecoveryError::CapacityExhausted)
    ));
}

#[tokio::test]
async fn unattended_recovery_drains_at_most_one_outbox_and_paginates() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let config = config();
    let machine = IncrementMachine::new(config.state_key());
    let resolver = resolver();
    let first_id = request_id(0x61);
    let second_id = request_id(0x62);
    handle_idempotent_event(
        runtime.as_ref(),
        &config,
        &resolver,
        event(first_id),
        &machine,
    )
    .unwrap();
    handle_idempotent_event(
        runtime.as_ref(),
        &config,
        &resolver,
        event(second_id),
        &machine,
    )
    .unwrap();
    assert!(runtime.transport().drain_outbound().unwrap().is_empty());

    let lease_ids = Arc::new(SequenceLeaseIds::default());
    let executor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let first = recover_outboxes_once(
        Arc::clone(&runtime),
        config.clone(),
        Arc::clone(&lease_ids),
        executor.clone(),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        first.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(first_id)
    );
    assert!(first.continuation_cursor().is_some());
    assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);

    let second = recover_outboxes_once(
        Arc::clone(&runtime),
        config.clone(),
        Arc::clone(&lease_ids),
        executor.clone(),
        first.continuation_cursor().map(<[u8]>::to_vec),
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        second.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(second_id)
    );
    assert_eq!(second.continuation_cursor(), None);
    assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);

    let completed_sweep = recover_outboxes_once(
        runtime,
        config,
        lease_ids,
        executor,
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        completed_sweep.outcome(),
        &NativeOutboxRecoveryOutcome::NoEligibleOutbox
    );
    assert_eq!(completed_sweep.continuation_cursor(), None);
}

#[tokio::test]
async fn unattended_recovery_skips_active_lease_and_retries_after_expiry() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let config = config();
    let id = request_id(0x63);
    handle_idempotent_event(
        runtime.as_ref(),
        &config,
        &resolver(),
        event(id),
        &IncrementMachine::new(config.state_key()),
    )
    .unwrap();
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    claim_next_outbox_message(
        runtime.state_store(),
        &layout,
        id,
        OutboxLeaseId::new([0xAA; 32]).unwrap(),
        0,
        NATIVE_OUTBOX_LEASE_MILLIS,
    )
    .unwrap()
    .unwrap();

    let lease_ids = Arc::new(SequenceLeaseIds::default());
    let executor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let active = recover_outboxes_once(
        Arc::clone(&runtime),
        config.clone(),
        Arc::clone(&lease_ids),
        executor.clone(),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        active.outcome(),
        &NativeOutboxRecoveryOutcome::NoEligibleOutbox
    );
    assert!(runtime.transport().drain_outbound().unwrap().is_empty());

    runtime.clock().set(NATIVE_OUTBOX_LEASE_MILLIS);
    let expired = recover_outboxes_once(
        Arc::clone(&runtime),
        config,
        lease_ids,
        executor,
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        expired.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(id)
    );
    assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
}

#[tokio::test]
async fn unattended_recovery_redelivers_send_without_ack_after_lease_expiry() {
    let runtime = Arc::new(FailOnceRuntime::new());
    let config = config();
    let id = request_id(0x64);
    handle_idempotent_event(
        runtime.as_ref(),
        &config,
        &resolver(),
        event(id),
        &IncrementMachine::new(config.state_key()),
    )
    .unwrap();
    let lease_ids = Arc::new(SequenceLeaseIds::default());
    let executor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));

    let failed = recover_outboxes_once(
        Arc::clone(&runtime),
        config.clone(),
        Arc::clone(&lease_ids),
        executor.clone(),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await;
    assert!(matches!(failed, Err(NativeOutboxRecoveryError::Send)));
    assert!(runtime.transport().drain_outbound().unwrap().is_empty());

    runtime.clock.set(31_000);
    let recovered = recover_outboxes_once(
        Arc::clone(&runtime),
        config.clone(),
        lease_ids,
        executor,
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        recovered.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(id)
    );
    assert_eq!(runtime.transport().drain_outbound().unwrap().len(), 1);
    let state = runtime
        .state_store()
        .get(config.state_key())
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_canonical_frame(&state)
            .unwrap()
            .required_u64(1)
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn unattended_recovery_fails_closed_on_mismatched_delivery_key() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let config = config();
    let recorded_id = request_id(0x71);
    handle_idempotent_event(
        runtime.as_ref(),
        &config,
        &resolver(),
        event(recorded_id),
        &IncrementMachine::new(config.state_key()),
    )
    .unwrap();
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let delivery = runtime
        .state_store()
        .get(&layout.outbox_delivery_key(*recorded_id.as_bytes()))
        .unwrap()
        .unwrap();
    runtime
        .state_store()
        .put(
            layout.outbox_delivery_key(*request_id(0x70).as_bytes()),
            delivery,
        )
        .unwrap();

    let result = recover_outboxes_once(
        runtime,
        config,
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        None,
        NonZeroUsize::new(8).unwrap(),
    )
    .await;
    assert!(matches!(result, Err(NativeOutboxRecoveryError::Node(_))));
}

#[tokio::test]
async fn sqlite_outbox_is_recovered_after_runtime_reopen_without_reapplying_state() {
    let database = TestDatabase::new();
    let config = config();
    let id = request_id(0x81);
    {
        let first_runtime = Arc::new(sqlite_runtime(
            &database.path,
            MemoryTransport::default(),
            1_000,
        ));
        handle_idempotent_event(
            first_runtime.as_ref(),
            &config,
            &resolver(),
            event(id),
            &IncrementMachine::new(config.state_key()),
        )
        .unwrap();
        assert!(
            first_runtime
                .transport()
                .drain_outbound()
                .unwrap()
                .is_empty()
        );
    }

    let reopened = Arc::new(sqlite_runtime(
        &database.path,
        MemoryTransport::default(),
        1_000,
    ));
    let recovered = recover_outboxes_once(
        Arc::clone(&reopened),
        config.clone(),
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        recovered.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(id)
    );
    assert_eq!(reopened.transport().drain_outbound().unwrap().len(), 1);
    let state = reopened
        .state_store()
        .get(config.state_key())
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_canonical_frame(&state)
            .unwrap()
            .required_u64(1)
            .unwrap(),
        1
    );
    drop(reopened);

    let completed = Arc::new(sqlite_runtime(
        &database.path,
        MemoryTransport::default(),
        1_000,
    ));
    let sweep = recover_outboxes_once(
        Arc::clone(&completed),
        config,
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        sweep.outcome(),
        &NativeOutboxRecoveryOutcome::NoEligibleOutbox
    );
    assert!(completed.transport().drain_outbound().unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_send_failure_lease_survives_reopen_and_redelivers_only_after_expiry() {
    let database = TestDatabase::new();
    let config = config();
    let id = request_id(0x82);
    {
        let failing = Arc::new(sqlite_runtime(
            &database.path,
            FailOnceTransport::new(),
            1_000,
        ));
        handle_idempotent_event(
            failing.as_ref(),
            &config,
            &resolver(),
            event(id),
            &IncrementMachine::new(config.state_key()),
        )
        .unwrap();
        let failed = recover_outboxes_once(
            Arc::clone(&failing),
            config.clone(),
            Arc::new(SequenceLeaseIds::default()),
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
            None,
            NonZeroUsize::new(4).unwrap(),
        )
        .await;
        assert!(matches!(failed, Err(NativeOutboxRecoveryError::Send)));
    }

    let before_expiry = Arc::new(sqlite_runtime(
        &database.path,
        MemoryTransport::default(),
        30_999,
    ));
    let skipped = recover_outboxes_once(
        Arc::clone(&before_expiry),
        config.clone(),
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        skipped.outcome(),
        &NativeOutboxRecoveryOutcome::NoEligibleOutbox
    );
    assert!(
        before_expiry
            .transport()
            .drain_outbound()
            .unwrap()
            .is_empty()
    );
    drop(before_expiry);

    let expired = Arc::new(sqlite_runtime(
        &database.path,
        MemoryTransport::default(),
        31_000,
    ));
    let recovered = recover_outboxes_once(
        Arc::clone(&expired),
        config.clone(),
        Arc::new(SequenceLeaseIds::default()),
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap())),
        None,
        NonZeroUsize::new(4).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        recovered.outcome(),
        &NativeOutboxRecoveryOutcome::Recovered(id)
    );
    assert_eq!(expired.transport().drain_outbound().unwrap().len(), 1);
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let delivery = expired
        .state_store()
        .get(&layout.outbox_delivery_key(*id.as_bytes()))
        .unwrap()
        .unwrap();
    let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
    assert_eq!(delivery.attempts(), 2);
    assert_eq!(delivery.lease(), None);
}

#[tokio::test]
async fn native_route_rejects_media_type_and_malformed_event() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let app = app(runtime.clone(), config());

    let wrong_type = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(event(request_id(0x42)).encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let unknown_media_version = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(
                    header::CONTENT_TYPE,
                    format!("{NODE_EVENT_MEDIA_TYPE}; version=2"),
                )
                .body(Body::from(event(request_id(0x44)).encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        unknown_media_version.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let malformed = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(vec![1, 2, 3]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(malformed.into_body(), 128).await.unwrap(),
        "invalid-node-event"
    );

    let mut unknown_kind_frame = CanonicalStruct::new(0xE001, 1);
    unknown_kind_frame.field_str(1, "sunrise-test").unwrap();
    unknown_kind_frame.field_u32(2, 3).unwrap();
    unknown_kind_frame.field_u64(3, 7).unwrap();
    unknown_kind_frame
        .field_bytes(4, request_id(0x45).as_bytes().to_vec())
        .unwrap();
    unknown_kind_frame.field_u16(5, u16::MAX).unwrap();
    unknown_kind_frame
        .field_bytes(6, canonical(TEST_PAYLOAD_TYPE_ID, 9))
        .unwrap();
    let unknown_kind = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(unknown_kind_frame.finish().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_kind.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        to_bytes(unknown_kind.into_body(), 128).await.unwrap(),
        "invalid-node-event"
    );
    assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
}

#[tokio::test]
async fn native_route_enforces_body_limit() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let app = app(runtime, config());
    let oversized = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(vec![0; MAX_HTTP_EVENT_BODY_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn test_serve_policy(
    max_connections: usize,
    header_read_timeout_millis: u64,
    body_idle_timeout_millis: u64,
    body_total_timeout_millis: u64,
) -> NativeHttpServePolicy {
    NativeHttpServePolicy::new(
        max_connections,
        header_read_timeout_millis,
        body_idle_timeout_millis,
        body_total_timeout_millis,
        1_000,
    )
    .unwrap()
}

async fn start_serve_test(
    policy: NativeHttpServePolicy,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let listener: tokio::net::TcpListener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: std::net::SocketAddr = listener.local_addr().unwrap();
    let app: Router = Router::new().route(LIVENESS_PATH, get(liveness));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = tokio::spawn(serve_with_policy(listener, app, policy, async move {
        let _received = shutdown_receiver.await;
    }));
    (address, shutdown_sender, server)
}

#[tokio::test]
async fn real_http_publication_body_cap_requires_explicit_ingress_opt_in() {
    for (enabled, length, expected) in [
        (false, MAX_HTTP_EVENT_BODY_BYTES + 1, "413"),
        (
            false,
            execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES + 1,
            "404",
        ),
        (
            true,
            execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES,
            "404",
        ),
        (
            true,
            execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES + 1,
            "413",
        ),
    ] {
        let policy = test_serve_policy(4, 2_000, 2_000, 3_000).with_local_publication(enabled);
        let (address, shutdown, server) = start_serve_test(policy).await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let header = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
            publication::PUBLICATION_PATH,
            NODE_EVENT_MEDIA_TYPE
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        // Writing may race the authoritative limit rejection; the response
        // still distinguishes rejection from dispatch to the absent route.
        let _write = stream.write_all(&vec![0_u8; length]).await;
        let response = read_to_connection_end(&mut stream).await.unwrap();
        let status = String::from_utf8_lossy(&response);
        assert!(
            status.starts_with(&format!("HTTP/1.1 {expected}")),
            "enabled={enabled}, length={length}, response={status}"
        );
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

#[test]
fn publication_router_rejects_wrong_fixed_semantics_before_storage() {
    let store = Arc::new(ScriptedIndexedStore::new(Vec::new(), Vec::new()));
    let node_config = config();
    let context = execution::publication::PublicationContext::new(
        node_config.chain_id().clone(),
        node_config.protocol_version(),
        node_config.epoch(),
    )
    .unwrap();
    let policy = node_core::publication::LocalPublicationPolicy::new(
        context,
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x33; 32]),
    );
    let result = preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(CountingClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        PreinstalledWasmComposition::new(
            Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap()),
            WasmExecutionEngine,
            9,
        )
        .with_local_publication(policy),
        active_protocol_config(AtomicityDomainId::new([0x8a; 32]).unwrap()),
        structured_request_authority(),
        node_config,
        resolver(),
        Arc::new(IncrementMachine::new(config().state_key())),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    );
    assert!(matches!(
        result,
        Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch)
    ));
    assert_eq!(store.storage_calls.load(Ordering::SeqCst), 0);
}

async fn read_to_connection_end(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let mut response: Vec<u8> = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test connection stayed open"))??;
    Ok(response)
}

#[test]
fn serve_policy_rejects_zero_oversized_and_incoherent_limits() {
    assert_eq!(
        NativeHttpServePolicy::new(0, 1, 1, 1, 1),
        Err(NativeHttpServePolicyError::InvalidConnectionLimit)
    );
    assert_eq!(
        NativeHttpServePolicy::new(MAX_NATIVE_HTTP_CONNECTIONS + 1, 1, 1, 1, 1),
        Err(NativeHttpServePolicyError::InvalidConnectionLimit)
    );
    assert_eq!(
        NativeHttpServePolicy::new(1, MAX_NATIVE_HTTP_HEADER_READ_MILLIS + 1, 1, 1, 1),
        Err(NativeHttpServePolicyError::InvalidHeaderReadTimeout)
    );
    assert_eq!(
        NativeHttpServePolicy::new(1, 1, MAX_NATIVE_HTTP_BODY_IDLE_MILLIS + 1, 1, 1),
        Err(NativeHttpServePolicyError::InvalidBodyIdleTimeout)
    );
    assert_eq!(
        NativeHttpServePolicy::new(1, 1, 1, MAX_NATIVE_HTTP_BODY_TOTAL_MILLIS + 1, 1),
        Err(NativeHttpServePolicyError::InvalidBodyTotalTimeout)
    );
    assert_eq!(
        NativeHttpServePolicy::new(1, 1, 2, 1, 1),
        Err(NativeHttpServePolicyError::BodyIdleExceedsTotal)
    );
    assert_eq!(
        NativeHttpServePolicy::new(1, 1, 1, 1, MAX_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS + 1),
        Err(NativeHttpServePolicyError::InvalidResponseTotalTimeout)
    );
}

#[test]
fn accept_error_backoff_is_bounded_non_spinning_and_monotonic() {
    let mut previous = Duration::ZERO;
    for consecutive_errors in 1..=64_u32 {
        let backoff = accept_error_backoff(consecutive_errors);
        assert!(
            backoff >= ACCEPT_ERROR_BACKOFF_FLOOR,
            "backoff must never be short enough to spin: {backoff:?}"
        );
        assert!(
            backoff <= ACCEPT_ERROR_BACKOFF_CEILING,
            "backoff must stay bounded: {backoff:?}"
        );
        assert!(
            backoff >= previous,
            "backoff must not shrink as consecutive errors accumulate"
        );
        previous = backoff;
    }
    assert_eq!(accept_error_backoff(1), ACCEPT_ERROR_BACKOFF_FLOOR);
    assert_eq!(accept_error_backoff(64), ACCEPT_ERROR_BACKOFF_CEILING);
}

#[tokio::test]
async fn io_idle_timeout_bounds_stalled_response_writes() {
    let (_reader, writer): (tokio::io::DuplexStream, tokio::io::DuplexStream) =
        tokio::io::duplex(1);
    let mut stream: IoIdleTimeoutStream<tokio::io::DuplexStream> = IoIdleTimeoutStream::new(
        writer,
        Duration::from_millis(20),
        Duration::from_millis(200),
    );

    let error: io::Error = timeout(Duration::from_secs(1), stream.write_all(b"ab"))
        .await
        .expect("write timeout fixture must finish")
        .expect_err("a peer that never reads must hit the write idle deadline");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn io_total_timeout_bounds_slow_drip_response_reads() {
    let (mut reader, writer): (tokio::io::DuplexStream, tokio::io::DuplexStream) =
        tokio::io::duplex(1);
    let reader_task: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let mut byte: [u8; 1] = [0];
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if reader.read_exact(&mut byte).await.is_err() {
                break;
            }
        }
    });
    let mut stream: IoIdleTimeoutStream<tokio::io::DuplexStream> = IoIdleTimeoutStream::new(
        writer,
        Duration::from_millis(100),
        Duration::from_millis(50),
    );

    let error: io::Error = timeout(Duration::from_secs(1), stream.write_all(&[0; 32]))
        .await
        .expect("write timeout fixture must finish")
        .expect_err("slow response progress must not extend the total deadline");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    reader_task.abort();
}

#[tokio::test]
async fn serve_bounds_slow_headers_connection_overload_and_recovers() {
    let (address, shutdown_sender, server) =
        start_serve_test(test_serve_policy(1, 100, 100, 500)).await;
    let mut slow: tokio::net::TcpStream = tokio::net::TcpStream::connect(address).await.unwrap();
    slow.write_all(b"G").await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut overloaded: tokio::net::TcpStream =
        tokio::net::TcpStream::connect(address).await.unwrap();
    let overloaded_write = overloaded
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;
    if overloaded_write.is_ok() {
        let mut byte: [u8; 1] = [0];
        let overloaded_read = timeout(Duration::from_millis(500), overloaded.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(overloaded_read, Ok(0) | Err(_)));
    }

    let slow_result = read_to_connection_end(&mut slow).await;
    assert!(
        slow_result.is_ok()
            || slow_result.is_err_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                )
            })
    );

    let mut legitimate: tokio::net::TcpStream =
        tokio::net::TcpStream::connect(address).await.unwrap();
    legitimate
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let response: Vec<u8> = read_to_connection_end(&mut legitimate).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204 No Content\r\n"));

    shutdown_sender.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_bounds_body_idle_and_total_time_without_reusing_connections() {
    let (address, shutdown_sender, server) =
        start_serve_test(test_serve_policy(2, 200, 120, 300)).await;

    let mut idle: tokio::net::TcpStream = tokio::net::TcpStream::connect(address).await.unwrap();
    idle.write_all(b"POST /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nx")
        .await
        .unwrap();
    let idle_response = read_to_connection_end(&mut idle).await;
    assert!(
        idle_response.is_ok()
            || idle_response.is_err_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                )
            })
    );

    let mut total: tokio::net::TcpStream = tokio::net::TcpStream::connect(address).await.unwrap();
    total
        .write_all(b"POST /health/live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\na")
        .await
        .unwrap();
    for byte in *b"bcd" {
        tokio::time::sleep(Duration::from_millis(80)).await;
        total.write_all(&[byte]).await.unwrap();
    }
    let total_response: Vec<u8> = read_to_connection_end(&mut total).await.unwrap();
    assert!(total_response.starts_with(b"HTTP/1.1 408 Request Timeout\r\n"));
    assert!(
        String::from_utf8_lossy(&total_response).contains("body-read-timeout"),
        "unexpected response: {}",
        String::from_utf8_lossy(&total_response)
    );

    let mut one_request: tokio::net::TcpStream =
        tokio::net::TcpStream::connect(address).await.unwrap();
    one_request
        .write_all(
            b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\nGET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await
        .unwrap();
    let response: Vec<u8> = read_to_connection_end(&mut one_request).await.unwrap();
    assert_eq!(
        response
            .windows(b"HTTP/1.1 204 No Content".len())
            .filter(|window: &&[u8]| *window == b"HTTP/1.1 204 No Content")
            .count(),
        1
    );

    shutdown_sender.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn liveness_does_not_touch_protocol_state() {
    let runtime = Arc::new(MemoryRuntime::new(ValidatorId::new([0x44; 32])));
    let response = app(runtime.clone(), config())
        .oneshot(Request::get(LIVENESS_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(runtime.state_store().get(b"http/node-state").unwrap(), None);
}

// --- DR-0082 bounded query API: router integration --------------------

fn query_object_path(object_id: ObjectId) -> String {
    format!("/v1/objects/{}", hex(object_id.as_bytes()))
}

fn query_receipt_path(id: RequestId) -> String {
    format!("/v1/receipts/{}", hex(id.as_bytes()))
}

fn query_next_nonce_path(sender: &Address) -> String {
    format!("/v1/senders/{}/next-nonce", hex(sender.as_bytes()))
}

#[tokio::test]
async fn context_route_returns_trusted_composition() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD1; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let expected_bytes = protocol_config.canonical_bytes().unwrap();
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        QUERY_RESULT_MEDIA_TYPE
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpContextQueryResult::decode(&bytes).unwrap();
    assert_eq!(result.chain_id(), &ChainId::new("sunrise-test").unwrap());
    assert_eq!(result.protocol_version(), ProtocolVersion::new(3));
    assert_eq!(result.epoch(), Epoch::new(7));
    assert_eq!(result.domain(), domain);
    assert_eq!(result.protocol_config_bytes(), expected_bytes.as_slice());
}

#[tokio::test]
async fn context_route_rejects_inactive_domain_placement_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let config = config();
    // `config()`'s epoch is 7; an activation epoch of 100 makes this
    // placement inactive at the trusted current epoch, exactly like the
    // storage-backed routes' inactive-placement rejection.
    let mut protocol_config = active_protocol_config(AtomicityDomainId::new([0xFC; 32]).unwrap());
    protocol_config.domain_placement = Some(placement(0xFC, 100));
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn object_route_returns_true_absence() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD2; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let object_id = ObjectId::new([0x01; 32]);

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::Absent { object_id }
    );
}

#[tokio::test]
async fn object_route_returns_verified_current_inline() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD3; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD3; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xD3));
    let object = owned_object(ObjectId::new([0xD4; 32]), owner, 0x40);
    let object_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x41,
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_ref.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    match HttpObjectQueryResult::decode(&bytes).unwrap() {
        HttpObjectQueryResult::CurrentInline {
            object_id,
            digest,
            canonical_object_bytes,
            ..
        } => {
            assert_eq!(object_id, object_ref.id);
            assert_eq!(digest, object_ref.digest);
            let decoded = objects::decode_object(&canonical_object_bytes).unwrap();
            assert_eq!(decoded.id, object_ref.id);
        }
        other => panic!("expected current inline object, got {other:?}"),
    }
}

#[tokio::test]
async fn object_route_returns_retained_tombstone() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD5; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD5; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xD5));
    let object = owned_object(ObjectId::new([0xD6; 32]), owner, 0x42);
    let object_id = object.id;
    commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x43,
    );
    let current_head = store
        .get_object_head(&setup_context, domain, object_id)
        .unwrap();
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(object_id, current_head)],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Delete,
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x44; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
        vec![0x46],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::Tombstoned {
            object_id,
            head_revision: ObjectHeadRevision::new(2).unwrap(),
            last_object_version: DurableObjectVersion::FIRST,
        }
    );
}

#[tokio::test]
async fn object_route_returns_current_blob_reference_without_fetching_body() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD7; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD7; 16]).unwrap(),
    );
    let object_id = ObjectId::new([0xD8; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xD9; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0xDA; 32]);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        digest,
        1,
        DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
        blob_digest,
    );
    let owner = dev_sender_address(&dev_signing_key(0xDB));
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(owner))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0xDC; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xDD; 32]),
        vec![0xDE],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let blob_store = Arc::new(CountingBlobStore::default());
    let app = structured_app_with_blob_store(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            blob_digest,
        }
    );
    assert_eq!(
        blob_store.get_calls(),
        0,
        "the query route must never fetch a blob body through the supplied blob store"
    );
}

#[tokio::test]
async fn object_route_tampered_digest_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xE1; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xE1; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xE2));
    let object_id = ObjectId::new([0xE3; 32]);
    let object = owned_object(object_id, owner, 0x50);
    let canonical_bytes = encode_object(&object).unwrap();
    let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
    let record = DurableObjectVersionRecord::from_inline_canonical_bytes(
        canonical_bytes,
        tampered_digest,
        DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
    )
    .unwrap();
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(owner))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0xE4; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xE5; 32]),
        vec![0xE6],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn object_route_writer_fence_mismatch_is_opaque_unavailable() {
    let authority_fence = WriterFenceGeneration::new(3).unwrap();
    // The store's own active fence differs from the authority's fence
    // that `structured_app` fixes via `structured_request_authority()`,
    // so the durable read proves `WriterFenced` rather than corruption.
    let store_fence = WriterFenceGeneration::new(9).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(store_fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF6; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let _ = authority_fence;

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[tokio::test]
async fn object_route_identity_unavailable_is_opaque_unavailable() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF7; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(FailingIndexedIdentities {
                error: IndexedOutboxIdentitySourceError::Unavailable,
            }),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[tokio::test]
async fn object_route_identity_exhausted_is_opaque_invalid() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF9; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(FailingIndexedIdentities {
                error: IndexedOutboxIdentitySourceError::Exhausted,
            }),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn object_route_clock_failure_is_opaque_unavailable() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xFA; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(FailingClock),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[test]
fn query_node_error_response_parts_classifies_durable_read_variants() {
    let cases: Vec<(NodeCoreError, StatusCode, &str)> = vec![
        (
            NodeCoreError::DurableRead(DurableReadError::WriterFenced {
                active_generation: WriterFenceGeneration::new(3).unwrap(),
            }),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::DeadlineExceeded),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        // `SchemaMismatch` is an explicit decision (DR-0082): it proves an
        // adapter/deployment schema disagreement, not corrupted persisted
        // bytes, so it is grouped with the other availability conditions
        // rather than with `query-state-invalid`.
        (
            NodeCoreError::DurableRead(DurableReadError::SchemaMismatch),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::InvalidPersistedState),
            StatusCode::INTERNAL_SERVER_ERROR,
            "query-state-invalid",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::InvalidRequest(
                RuntimeError::UnsupportedObjectStorage,
            )),
            StatusCode::INTERNAL_SERVER_ERROR,
            "query-state-invalid",
        ),
    ];
    for (error, expected_status, expected_code) in cases {
        let (status, code) = query_node_error_response_parts(&error);
        assert_eq!(status, expected_status, "error: {error:?}");
        assert_eq!(code, expected_code, "error: {error:?}");
    }
}

#[tokio::test]
async fn object_route_rejects_inactive_domain_placement_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let config = config();
    // `config()`'s epoch is 7; an activation epoch of 100 makes this
    // placement inactive at the trusted current epoch.
    let mut protocol_config = active_protocol_config(AtomicityDomainId::new([0xFB; 32]).unwrap());
    protocol_config.domain_placement = Some(placement(0xFB, 100));
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn receipt_route_returns_true_absence() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xE7; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let id = request_id(0x01);

    let response = app
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes).unwrap(),
        HttpReceiptQueryResult::Absent { request_id: id }
    );
}

#[tokio::test]
async fn receipt_route_corrupt_receipt_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xE9; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xE9; 16]).unwrap(),
    );
    let id = request_id(0x02);
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(*id.as_bytes()).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xEA; 32]),
        vec![0xEB, 0x00],
    )
    .unwrap();
    let invocation = DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::empty(),
        receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn receipt_and_next_nonce_routes_reflect_a_real_submission() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xE8; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let signing_key = dev_signing_key(0xE9);
    let sender = dev_sender_address(&signing_key);
    let id = request_id(0xEA);
    let event = signed_submit_transaction_event(&signing_key, id, 0);

    let submit_response = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(submit_response.status(), StatusCode::OK);

    let receipt_response = app
        .clone()
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt_response.status(), StatusCode::OK);
    let receipt_bytes = to_bytes(receipt_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    match HttpReceiptQueryResult::decode(&receipt_bytes).unwrap() {
        HttpReceiptQueryResult::Present {
            request_id,
            dedup_record_bytes,
            ..
        } => {
            assert_eq!(request_id, id);
            let record = NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
            assert_eq!(record.request_id(), id);
        }
        other => panic!("expected present receipt, got {other:?}"),
    }

    let nonce_response = app
        .oneshot(
            Request::get(query_next_nonce_path(&sender))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let nonce_bytes = to_bytes(nonce_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let nonce_result = HttpNextNonceQueryResult::decode(&nonce_bytes).unwrap();
    assert_eq!(nonce_result.sender(), sender);
    assert_eq!(nonce_result.epoch(), Epoch::new(7));
    assert_eq!(nonce_result.next_nonce(), 1);
}

#[tokio::test]
async fn next_nonce_route_true_absence_returns_zero() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xEB; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let sender = Address::new([0x01; 32]);

    let response = app
        .oneshot(
            Request::get(query_next_nonce_path(&sender))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpNextNonceQueryResult::decode(&bytes).unwrap();
    assert_eq!(result.sender(), sender);
    assert_eq!(result.next_nonce(), 0);
    assert_eq!(result.epoch(), Epoch::new(7));
}

#[tokio::test]
async fn next_nonce_route_deleted_record_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xEC; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xEC; 16]).unwrap(),
    );
    let sender = [0x02; 32];
    let key = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    )
    .sender_nonce_key(sender, Epoch::new(7));
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&setup_context, transaction),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_next_nonce_path(&Address::new(sender)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn query_routes_reject_malformed_selectors_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xED; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let malformed_paths: Vec<String> = vec![
        "/v1/objects/too-short".to_string(),
        format!("/v1/objects/{}", "A".repeat(64)),
        format!("/v1/receipts/{}", "0".repeat(64)),
        format!("/v1/receipts/{}", "g".repeat(64)),
        "/v1/senders/short/next-nonce".to_string(),
    ];
    for path in malformed_paths {
        let response = app
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path: {path}");
    }

    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn both_routers_return_identical_results_for_all_four_query_routes() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xEE; 32]).unwrap();
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let catalog = Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap());

    // Populate one verified current-inline object and one present receipt
    // so parity is checked against real content, not only absence.
    // Tombstone and blob-reference results are covered by dedicated
    // structured-router tests and need not be duplicated here.
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xEE; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xEE));
    let object = owned_object(ObjectId::new([0xEF; 32]), owner, 0x46);
    let object_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x47,
    );

    let structured = structured_app(
        Arc::clone(&store),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        protocol_config.clone(),
        config.clone(),
    );
    let preinstalled = preinstalled_app(
        Arc::clone(&store),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );

    let populated_object_path: String = query_object_path(object_ref.id);
    let populated_receipt_path: String = query_receipt_path(request_id(0x47));
    let paths: [String; 6] = [
        QUERY_CONTEXT_PATH.to_string(),
        query_object_path(ObjectId::new([0x01; 32])),
        populated_object_path.clone(),
        query_receipt_path(request_id(0x02)),
        populated_receipt_path.clone(),
        query_next_nonce_path(&Address::new([0x03; 32])),
    ];
    for path in paths {
        let structured_response = structured
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let preinstalled_response = preinstalled
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            structured_response.status(),
            preinstalled_response.status(),
            "path: {path}"
        );
        assert_eq!(
            structured_response.headers().get(header::CONTENT_TYPE),
            preinstalled_response.headers().get(header::CONTENT_TYPE),
            "path: {path}"
        );
        assert_eq!(
            structured_response.headers().get(header::CACHE_CONTROL),
            preinstalled_response.headers().get(header::CACHE_CONTROL),
            "path: {path}"
        );
        let structured_bytes = to_bytes(structured_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let preinstalled_bytes =
            to_bytes(preinstalled_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
                .await
                .unwrap();
        assert_eq!(structured_bytes, preinstalled_bytes, "path: {path}");
        if path == populated_object_path {
            assert!(matches!(
                HttpObjectQueryResult::decode(&structured_bytes).unwrap(),
                HttpObjectQueryResult::CurrentInline { .. }
            ));
        } else if path == populated_receipt_path {
            assert!(matches!(
                HttpReceiptQueryResult::decode(&structured_bytes).unwrap(),
                HttpReceiptQueryResult::Present { .. }
            ));
        }
    }
}

#[tokio::test]
async fn object_route_admission_rejects_when_blocking_capacity_exhausted() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xEF; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let blocking_executor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router_with_executor(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        blocking_executor.clone(),
    )
    .unwrap();
    let held_permit = blocking_executor.try_acquire().unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(held_permit);
}

#[tokio::test]
async fn object_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
    for cancel_at_call in 1_usize..=3_usize {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(ManualClock::new(10_000));
        let config = config();
        let domain = AtomicityDomainId::new([0xF5; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let cancellation: Arc<StepCancellation> = Arc::new(StepCancellation::new(cancel_at_call));
        let app = structured_app_with_cancellation(
            store,
            transport,
            clock,
            protocol_config,
            config,
            cancellation.clone(),
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "invocation-cancelled-before-storage"
        );
        assert_eq!(cancellation.calls(), cancel_at_call);
    }
}
