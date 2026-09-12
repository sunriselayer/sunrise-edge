mod bound_snapshots;
use super::*;
use abi::{
    AccessEntry, AccessManifest, ConstructorDeclaration, ConstructorId, EntrypointSignature,
    ParamDeclaration, TypeArity, TypeTag,
};
use ed25519_zebra::SigningKey;
use execution::{Transaction, encode_transaction, encode_transaction_signable};
use hashing::{BuiltinHashFunction, HashFunction};
use objects::{AccessMode, Address, ObjectId, ObjectRef, encode_object};
use protocol_config::TransactionAuthProfile;
use protocol_types::{HashSuite, HashSuiteId, HashSuiteSchedule, SignatureSchemeId};
use runtime::{
    DurableDomainStateStore, DurableObjectProvenance, DurableObjectRoutingProjection,
    MemoryBlobStore, MemoryDurableStateStore, MemoryRuntime, StateRevision, StateStore,
    StorageCorrelationId, StorageDeadline, TransactionalStateStore, WriterFenceGeneration,
};
use std::sync::{
    Arc, Barrier, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use system_modules::SystemModuleRegistry;

const TEST_STATE_TYPE_ID: u16 = 0xEF01;
const TEST_PAYLOAD_TYPE_ID: u16 = 0xEF02;

fn canonical(type_id: u16, value: u64) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(type_id, 1);
    frame.field_u64(1, value).unwrap();
    frame.finish().unwrap()
}

fn request(byte: u8) -> RequestId {
    RequestId::new([byte; 32]).unwrap()
}

fn domain(byte: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([byte; 32]).unwrap()
}

fn placement(byte: u8, activation_epoch: u64) -> DomainPlacementManifest {
    DomainPlacementManifest::single_domain(1, domain(byte), Epoch::new(activation_epoch)).unwrap()
}

fn durable_context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(10_000).unwrap(),
        StorageCorrelationId::new([0xA5; 16]).unwrap(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn event(chain: &str, request_id: RequestId) -> NodeEvent {
    event_value(chain, request_id, 9)
}

fn submit_event(chain: &str, request_id: RequestId) -> NodeEvent {
    NodeEvent::new(
        ChainId::new(chain).unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id,
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap()
}

fn event_value(chain: &str, request_id: RequestId, value: u64) -> NodeEvent {
    NodeEvent::new(
        ChainId::new(chain).unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request_id,
        NodeEventKind::ReceiveVote,
        canonical(TEST_PAYLOAD_TYPE_ID, value),
    )
    .unwrap()
}

fn config(chain: &str) -> NodeConfig {
    NodeConfig::new(
        ChainId::new(chain).unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        b"node/state".to_vec(),
    )
    .unwrap()
}

fn resolver(chain: &str) -> HashSuiteResolver {
    resolver_for_protocol(chain, ProtocolVersion::new(3))
}

fn resolver_for_protocol(chain: &str, protocol_version: ProtocolVersion) -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new(chain).unwrap(),
        protocol_version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

/// Same as [`resolver`], but with a second SHA3-256 hash-suite schedule
/// entry activating at `rotation_epoch`.
fn resolver_with_rotation(chain: &str, rotation_epoch: Epoch) -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new(chain).unwrap(),
        ProtocolVersion::new(3),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: rotation_epoch,
                suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
            },
        ],
    )
    .unwrap()
}

/// A committed protocol configuration whose `protocol_version` matches
/// [`config`] and whose `transaction_auth_profile` is active, used to
/// authenticate a `SubmitTransaction` event.
fn active_protocol_config(byte: u8) -> ProtocolConfig {
    let mut protocol_config = ProtocolConfig::genesis();
    protocol_config.protocol_version = ProtocolVersion::new(3);
    protocol_config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, domain(byte), Epoch::new(0)).unwrap());
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_address_is_public_key());
    protocol_config
}

/// A dev-only deterministic signer built directly on the exact-pinned
/// workspace `ed25519-zebra` `SigningKey`. Test infrastructure only,
/// mirroring `transaction_auth`'s own test-only signer.
fn dev_signing_key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn dev_sender_address(signing_key: &SigningKey) -> Address {
    let verification_key = ed25519_zebra::VerificationKey::from(signing_key);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(verification_key.as_ref());
    Address::new(bytes)
}

fn sample_object_ref(id_byte: u8) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [id_byte; 32]),
    }
}

fn test_object(id: ObjectId, version: u64, owner: Owner, byte: u8) -> Object {
    Object {
        id,
        version,
        owner,
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
        schema_version: u32::from(byte),
        data: vec![byte],
    }
}

/// Hashes `object`'s canonical bytes with the production object-digest
/// suite, returning the version record ready to commit alongside the
/// exact digest a signed [`ObjectRef`] must declare to match it.
fn hashed_object_version(
    object: Object,
    chain: &str,
    checkpoint: u64,
) -> (DurableObjectVersionRecord, Digest32) {
    hashed_object_version_with_protocol_version(object, chain, ProtocolVersion::new(3), checkpoint)
}

/// Same as [`hashed_object_version`] but with an explicit creating
/// protocol version, for exercising cross-version provenance.
fn hashed_object_version_with_protocol_version(
    object: Object,
    chain: &str,
    protocol_version: ProtocolVersion,
    checkpoint: u64,
) -> (DurableObjectVersionRecord, Digest32) {
    let canonical_bytes = encode_object(&object).unwrap();
    let chain_id = ChainId::new(chain).unwrap();
    let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &canonical_bytes,
        )
        .unwrap();
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    (
        DurableObjectVersionRecord::from_inline_object(object, digest, provenance, checkpoint)
            .unwrap(),
        digest,
    )
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

#[test]
fn inline_blob_threshold_uses_exact_canonical_length() {
    let object_id: ObjectId = ObjectId::new([0x6F; 32]);
    let owner: Owner = Owner::Address(Address::new([0x6E; 32]));
    let mut boundary_object: Object = test_object(object_id, 2, owner.clone(), 0x00);
    boundary_object.data = Vec::new();
    let empty_length: usize = encode_object(&boundary_object).unwrap().len();
    assert!(empty_length < MAX_INLINE_OBJECT_BODY_BYTES);
    boundary_object.data = vec![0x6F; MAX_INLINE_OBJECT_BODY_BYTES - empty_length];
    let boundary_bytes: Vec<u8> = encode_object(&boundary_object).unwrap();
    assert_eq!(boundary_bytes.len(), MAX_INLINE_OBJECT_BODY_BYTES);
    let (boundary_record, _): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version(boundary_object, "sunrise-test", 2);
    let mut boundary_pending: Vec<PendingBlobPublication> = Vec::new();
    let boundary_record: DurableObjectVersionRecord =
        stage_inline_version_for_blob_store(boundary_record, &mut boundary_pending);
    assert!(matches!(
        boundary_record.payload(),
        DurableObjectPayload::Inline(_)
    ));
    assert!(boundary_pending.is_empty());

    let mut over_object: Object = test_object(object_id, 2, owner, 0x00);
    over_object.data = Vec::new();
    over_object.data = vec![0x70; MAX_INLINE_OBJECT_BODY_BYTES + 1 - empty_length];
    let over_bytes: Vec<u8> = encode_object(&over_object).unwrap();
    assert_eq!(over_bytes.len(), MAX_INLINE_OBJECT_BODY_BYTES + 1);
    let (over_record, _): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version(over_object, "sunrise-test", 2);
    let mut over_pending: Vec<PendingBlobPublication> = Vec::new();
    let over_record: DurableObjectVersionRecord =
        stage_inline_version_for_blob_store(over_record, &mut over_pending);
    assert!(matches!(
        over_record.payload(),
        DurableObjectPayload::BlobReference(_)
    ));
    assert_eq!(over_pending.len(), 1);
    assert_eq!(over_pending[0].canonical_bytes, over_bytes);
}

fn manifest_with(entries: Vec<AccessEntry>) -> AccessManifest {
    let mut manifest = AccessManifest::new();
    for entry in entries {
        manifest.push(entry);
    }
    manifest
}

/// Builds an unsigned transaction with an empty object-access manifest,
/// so tests that only exercise nonce/replay/idempotency semantics are not
/// also subject to object-dispatch authorization. Tests that specifically
/// exercise object dispatch use [`unsigned_transaction_with_manifest`].
fn unsigned_transaction(sender: Address, chain: ChainId, epoch: Epoch, nonce: u64) -> Transaction {
    unsigned_transaction_with_manifest(sender, chain, epoch, nonce, AccessManifest::new())
}

fn unsigned_transaction_with_manifest(
    sender: Address,
    chain: ChainId,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
) -> Transaction {
    Transaction {
        chain_id: chain,
        protocol_version: ProtocolVersion::new(3),
        epoch,
        sender,
        nonce,
        access_manifest,
        module_ref: sample_object_ref(0xDD),
        entrypoint: "transfer".to_string(),
        args: vec![1, 2, 3, 4],
        gas_limit: 100_000,
        fee_payment: None,
        signature: Vec::new(),
    }
}

/// Builds and authenticates one `SubmitTransaction` event for `sender` at
/// `nonce` under the shared test chain/epoch/protocol-config fixtures.
fn authenticated_submission(
    chain: &str,
    request_id: RequestId,
    signing_key: &SigningKey,
    epoch: Epoch,
    nonce: u64,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> AuthenticatedSubmitTransaction {
    let sender = dev_sender_address(signing_key);
    let tx = unsigned_transaction(sender, ChainId::new(chain).unwrap(), epoch, nonce);
    authenticated_submission_from_transaction(
        chain,
        request_id,
        signing_key,
        epoch,
        tx,
        config,
        protocol_config,
    )
}

/// Same as [`authenticated_submission`], but with an explicit
/// object-access manifest, for tests that exercise object dispatch.
#[allow(clippy::too_many_arguments)]
fn authenticated_submission_with_manifest(
    chain: &str,
    request_id: RequestId,
    signing_key: &SigningKey,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> AuthenticatedSubmitTransaction {
    let sender = dev_sender_address(signing_key);
    let tx = unsigned_transaction_with_manifest(
        sender,
        ChainId::new(chain).unwrap(),
        epoch,
        nonce,
        access_manifest,
    );
    authenticated_submission_from_transaction(
        chain,
        request_id,
        signing_key,
        epoch,
        tx,
        config,
        protocol_config,
    )
}

#[allow(clippy::too_many_arguments)]
fn authenticated_submission_from_transaction(
    chain: &str,
    request_id: RequestId,
    signing_key: &SigningKey,
    epoch: Epoch,
    tx: Transaction,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> AuthenticatedSubmitTransaction {
    let payload = signed_transaction_bytes(signing_key, &tx);
    let protocol_version: ProtocolVersion = tx.protocol_version;
    let event = NodeEvent::new(
        ChainId::new(chain).unwrap(),
        protocol_version,
        epoch,
        request_id,
        NodeEventKind::SubmitTransaction,
        payload,
    )
    .unwrap();
    authenticate_submit_transaction_event(event, config, protocol_config).unwrap()
}

/// Authenticates a test transaction under profile 2's request-bound
/// signature envelope.
#[allow(clippy::too_many_arguments)]
fn authenticated_profile_2_submission_from_transaction(
    chain: &str,
    request_id: RequestId,
    signing_key: &SigningKey,
    epoch: Epoch,
    tx: Transaction,
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> AuthenticatedSubmitTransaction {
    let protocol_version: ProtocolVersion = tx.protocol_version;
    let transaction_signable: Vec<u8> = encode_transaction_signable(&tx).unwrap();
    let submission_signable: Vec<u8> =
        encode_submit_transaction_signable(request_id, &transaction_signable).unwrap();
    let domain: crypto::SignatureDomain = crypto::SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version,
        epoch: tx.epoch,
        message_type: crypto::SignatureMessageType::new(SUBMIT_TRANSACTION_V1_MESSAGE_TYPE)
            .unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    let framed: Vec<u8> = crypto::frame_signature_message(&domain, &submission_signable).unwrap();
    let signature = signing_key.sign(&framed);
    let mut signed: Transaction = tx;
    signed.signature = signature.to_bytes().to_vec();
    let payload: Vec<u8> = encode_transaction(&signed).unwrap();
    let event: NodeEvent = NodeEvent::new(
        ChainId::new(chain).unwrap(),
        protocol_version,
        epoch,
        request_id,
        NodeEventKind::SubmitTransaction,
        payload,
    )
    .unwrap();
    authenticate_submit_transaction_event(event, config, protocol_config).unwrap()
}

/// Signs `tx` under the exact production `SignatureDomain` that
/// `authenticate_transaction_bytes` itself builds (`tx.chain_id`,
/// `tx.protocol_version`, `tx.epoch`, message family `"transaction-v1"`,
/// Ed25519), matching `transaction_auth`'s own test-only signer, and
/// returns the fully encoded transaction bytes.
fn signed_transaction_bytes(signing_key: &SigningKey, tx: &Transaction) -> Vec<u8> {
    let signable = encode_transaction_signable(tx).unwrap();
    let domain = crypto::SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        message_type: crypto::SignatureMessageType::new("transaction-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    let framed = crypto::frame_signature_message(&domain, &signable).unwrap();
    let signature = signing_key.sign(&framed);
    let mut signed = tx.clone();
    signed.signature = signature.to_bytes().to_vec();
    encode_transaction(&signed).unwrap()
}

struct IncrementMachine;

impl NodeStateMachine for IncrementMachine {
    fn transition(
        &self,
        current_state: Option<&[u8]>,
        event: &NodeEvent,
    ) -> Result<NodeTransition, NodeCoreError> {
        let value = match current_state {
            Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
            None => 0,
        };
        let next = value
            .checked_add(1)
            .ok_or(NodeCoreError::TransitionRejected("test counter overflow"))?;
        let response = NodeResponse::new(
            event.request_id(),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
        )?;
        NodeTransition::new(
            canonical(TEST_STATE_TYPE_ID, next),
            NodeOutput::new(vec![response], Vec::new())?,
        )
    }
}

#[test]
fn event_round_trip_has_stable_encoding() {
    let event = submit_event("sunrise-test", request(0x11));
    let encoded = event.encode().unwrap();
    let decoded = NodeEvent::decode(&encoded).unwrap();

    assert_eq!(decoded, event);
    assert_eq!(
        hex(&encoded),
        "534e524501e00100060001000c00000073756e726973652d7465737402000400000003000000\
         03000800000007000000000000000400200000001111111111111111111111111111111111111111\
         1111111111111111111111110500020000000100060018000000534e524502ef0100010001000800\
         00000900000000000000"
            .replace(' ', "")
    );
}

#[test]
fn node_event_digest_is_stable_and_context_bound() {
    let event = submit_event("sunrise-test", request(0x12));
    let digest = event.digest(&resolver("sunrise-test")).unwrap();

    assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
    assert_eq!(
        hex(&digest.bytes()),
        "657a106559c95a487c1bf33c245d6eded71706b4d4921fd9b938552b5e1aa281"
    );
    assert!(matches!(
        event.digest(&resolver("other-chain")),
        Err(NodeCoreError::ChainMismatch { .. })
    ));
}

#[test]
fn dedup_and_outbox_records_have_stable_canonical_vectors() {
    let request_id = request(0x21);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]);
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let dedup = NodeDedupRecord::new(request_id, digest, vec![response]).unwrap();
    let dedup_bytes = dedup.encode().unwrap();
    assert_eq!(NodeDedupRecord::decode(&dedup_bytes).unwrap(), dedup);
    assert_eq!(
        hex(&dedup_bytes),
        concat!(
            "534e524503e001000500010020000000",
            "2121212121212121212121212121212121212121212121212121212121212121",
            "0200020000000100",
            "0300200000002222222222222222222222222222222222222222222222222222222222222222",
            "04000400000001000000",
            "05003c00000038000000534e524502e001000200010020000000",
            "2121212121212121212121212121212121212121212121212121212121212121",
            "0200020000000100"
        )
    );

    let outbox = NodeOutboxBatch::new(request_id, digest, Vec::new()).unwrap();
    let outbox_bytes = outbox.encode().unwrap();
    assert_eq!(NodeOutboxBatch::decode(&outbox_bytes).unwrap(), outbox);
    assert_eq!(
        hex(&outbox_bytes),
        concat!(
            "534e524504e001000500010020000000",
            "2121212121212121212121212121212121212121212121212121212121212121",
            "0200020000000100",
            "0300200000002222222222222222222222222222222222222222222222222222222222222222",
            "04000400000000000000",
            "050000000000"
        )
    );

    let delivery = NodeOutboxDelivery::pending(request_id, digest);
    let delivery_bytes = delivery.encode().unwrap();
    assert_eq!(
        NodeOutboxDelivery::decode(&delivery_bytes).unwrap(),
        delivery
    );
    assert_eq!(
        hex(&delivery_bytes),
        concat!(
            "534e524505e001000500010020000000",
            "2121212121212121212121212121212121212121212121212121212121212121",
            "0200020000000100",
            "0300200000002222222222222222222222222222222222222222222222222222222222222222",
            "04000400000000000000",
            "05000400000000000000"
        )
    );
}

#[test]
fn sender_nonce_record_has_stable_canonical_vector_and_key_cross_check() {
    let sender = [0x33; 32];
    let record = SenderNonceRecord::new(sender, Epoch::new(7), 9);
    let bytes = record.encode().unwrap();
    assert_eq!(SenderNonceRecord::decode(&bytes).unwrap(), record);
    assert_eq!(
        hex(&bytes),
        concat!(
            "534e524506e001000300010020000000",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0200080000000700000000000000",
            "0300080000000900000000000000"
        )
    );

    // The persisted key derived for this exact sender/epoch is the one a
    // reader must use to address this record.
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    assert!(
        key.starts_with(
            PersistenceLayout::new(
                ChainId::new("sunrise-test").unwrap(),
                ProtocolVersion::new(3)
            )
            .sender_nonce_prefix()
            .as_slice()
        )
    );

    let mut wrong_type = CanonicalStruct::new(0xDEAD, ENCODING_VERSION);
    wrong_type.field_bytes(1, sender.to_vec()).unwrap();
    wrong_type.field_u64(2, 7).unwrap();
    wrong_type.field_u64(3, 9).unwrap();
    assert!(matches!(
        SenderNonceRecord::decode(&wrong_type.finish().unwrap()).unwrap_err(),
        NodeCoreError::CanonicalDecoding(_)
    ));

    let mut short_sender = CanonicalStruct::new(SENDER_NONCE_RECORD_TYPE_ID, ENCODING_VERSION);
    short_sender.field_bytes(1, vec![0x01; 31]).unwrap();
    short_sender.field_u64(2, 7).unwrap();
    short_sender.field_u64(3, 9).unwrap();
    assert!(matches!(
        SenderNonceRecord::decode(&short_sender.finish().unwrap()).unwrap_err(),
        NodeCoreError::CanonicalDecoding(_)
    ));
}

#[test]
fn event_decode_rejects_unknown_kind_and_schema_fields() {
    let payload = canonical(TEST_PAYLOAD_TYPE_ID, 1);
    let mut unknown_kind = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
    unknown_kind.field_str(1, "sunrise-test").unwrap();
    unknown_kind.field_u32(2, 3).unwrap();
    unknown_kind.field_u64(3, 7).unwrap();
    unknown_kind.field_bytes(4, [0x22; 32]).unwrap();
    unknown_kind.field_u16(5, 0xFFFF).unwrap();
    unknown_kind.field_bytes(6, payload.clone()).unwrap();
    assert_eq!(
        NodeEvent::decode(&unknown_kind.finish().unwrap()).unwrap_err(),
        NodeCoreError::UnknownEventKind(0xFFFF)
    );

    let mut extra_field = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
    extra_field.field_str(1, "sunrise-test").unwrap();
    extra_field.field_u32(2, 3).unwrap();
    extra_field.field_u64(3, 7).unwrap();
    extra_field.field_bytes(4, [0x22; 32]).unwrap();
    extra_field.field_u16(5, 1).unwrap();
    extra_field.field_bytes(6, payload).unwrap();
    extra_field.field_u16(7, 0).unwrap();
    assert!(matches!(
        NodeEvent::decode(&extra_field.finish().unwrap()),
        Err(NodeCoreError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(7)
        ))
    ));
}

#[test]
fn event_requires_non_zero_request_and_canonical_payload() {
    assert_eq!(RequestId::new([0; 32]), Err(NodeCoreError::ZeroRequestId));
    assert!(matches!(
        NodeEvent::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
            request(1),
            NodeEventKind::Tick,
            vec![1, 2, 3],
        ),
        Err(NodeCoreError::CanonicalDecoding(_))
    ));
}

#[test]
fn response_round_trip_preserves_optional_payload() {
    let response = NodeResponse::new(
        request(0x21),
        NodeResponseStatus::Accepted,
        Some(canonical(TEST_PAYLOAD_TYPE_ID, 42)),
    )
    .unwrap();
    let encoded = response.encode().unwrap();

    assert_eq!(NodeResponse::decode(&encoded).unwrap(), response);
    assert_eq!(
        hex(&encoded),
        "534e524502e001000300010020000000212121212121212121212121212121212121212121212121\
         21212121212121210200020000000100030018000000534e524502ef010001000100080000002a00\
         000000000000"
            .replace(' ', "")
    );

    let empty = NodeResponse::new(request(0x22), NodeResponseStatus::Rejected, None).unwrap();
    assert_eq!(
        NodeResponse::decode(&empty.encode().unwrap()).unwrap(),
        empty
    );
}

#[test]
fn handle_event_persists_before_returning_output() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let config = config("sunrise-test");
    let event = event("sunrise-test", request(0x33));

    let output = handle_event(&runtime, &config, event, &IncrementMachine).unwrap();
    let persisted = runtime
        .state_store()
        .get(config.state_key())
        .unwrap()
        .unwrap();

    assert_eq!(
        decode_canonical_frame(&persisted).unwrap().required_u64(1),
        Ok(1)
    );
    assert_eq!(output.responses().len(), 1);
    assert!(output.outbound_messages().is_empty());
}

#[test]
fn generic_handler_rejects_submit_before_transition_or_storage() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let config = config("sunrise-test");
    let error = handle_event(
        &runtime,
        &config,
        submit_event("sunrise-test", request(0x34)),
        &IncrementMachine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::UnauthenticatedTransactionSubmission);
    assert_eq!(runtime.state_store().get(config.state_key()).unwrap(), None);
}

#[test]
fn all_eight_generic_handlers_reject_submit_before_machine_or_storage_work() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let config = config("sunrise-test");
    let resolver = resolver("sunrise-test");
    let event_domain = domain(0xD4);
    let event_placement = placement(0xD4, 7);
    let machine = CountingPlanMachine {
        access_plans: AtomicUsize::new(0),
    };

    let domain_transactional_error = handle_domain_transactional_event(
        &runtime,
        event_domain,
        &config,
        submit_event("sunrise-test", request(0xB1)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        domain_transactional_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let resolved_transactional_error = handle_resolved_transactional_event(
        &runtime,
        &event_placement,
        &config,
        submit_event("sunrise-test", request(0xB2)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        resolved_transactional_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let transactional_error = handle_transactional_event(
        &runtime,
        &config,
        submit_event("sunrise-test", request(0xB3)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        transactional_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let idempotent_error = handle_idempotent_event(
        &runtime,
        &config,
        &resolver,
        submit_event("sunrise-test", request(0xB4)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        idempotent_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let domain_idempotent_error = handle_domain_idempotent_event(
        &runtime,
        event_domain,
        &config,
        &resolver,
        submit_event("sunrise-test", request(0xB5)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        domain_idempotent_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let resolved_idempotent_error = handle_resolved_idempotent_event(
        &runtime,
        &event_placement,
        &config,
        &resolver,
        submit_event("sunrise-test", request(0xB6)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        resolved_idempotent_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let resolved_durable_idempotent_error = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &event_placement,
        &config,
        &resolver,
        submit_event("sunrise-test", request(0xB7)),
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        resolved_durable_idempotent_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );
    assert!(store.commits.lock().unwrap().is_empty());
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);

    let event_error = handle_event(
        &runtime,
        &config,
        submit_event("sunrise-test", request(0xB8)),
        &IncrementMachine,
    )
    .unwrap_err();
    assert_eq!(
        event_error,
        NodeCoreError::UnauthenticatedTransactionSubmission
    );

    assert_eq!(machine.access_plans.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.state_store().get(config.state_key()).unwrap(), None);
    assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
    assert_eq!(
        runtime.state_store().get(b"state/idempotent").unwrap(),
        None
    );
    assert!(
        runtime
            .state_store()
            .get_versioned_in_domain(event_domain, b"state/a")
            .unwrap()
            .value()
            .is_none()
    );
}

#[test]
fn authenticate_submit_transaction_event_rejects_wrong_kind() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xD5);

    let error = authenticate_submit_transaction_event(
        event("sunrise-test", request(0xA1)),
        &config,
        &protocol_config,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ExpectedSubmitTransaction);
}

#[test]
fn authenticate_submit_transaction_event_rejects_protocol_config_version_mismatch() {
    let config = config("sunrise-test");
    let mut protocol_config = active_protocol_config(0xD6);
    protocol_config.protocol_version = ProtocolVersion::new(2);

    let error = authenticate_submit_transaction_event(
        submit_event("sunrise-test", request(0xA2)),
        &config,
        &protocol_config,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ProtocolConfigVersionMismatch {
            node_config: ProtocolVersion::new(3),
            protocol_config: ProtocolVersion::new(2),
        }
    );
}

#[test]
fn authenticate_submit_transaction_event_happy_path_authenticates_transaction() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xD7);
    let signing_key = dev_signing_key(0x71);
    let sender = dev_sender_address(&signing_key);
    let tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
    );
    let payload = signed_transaction_bytes(&signing_key, &tx);
    let event = NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        request(0xA3),
        NodeEventKind::SubmitTransaction,
        payload,
    )
    .unwrap();

    let authenticated =
        authenticate_submit_transaction_event(event.clone(), &config, &protocol_config).unwrap();

    assert_eq!(authenticated.event(), &event);
    assert_eq!(authenticated.transaction().transaction().nonce, 0);

    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated,
        &machine,
    )
    .unwrap();

    assert_eq!(resolved.domain(), domain(0xD7));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    // One read for the sender-nonce record and one for the machine's
    // single declared application state key.
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 2);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let state = commits[0].state().unwrap();
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let nonce_key = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    )
    .sender_nonce_key(sender_bytes, Epoch::new(7));
    let nonce_mutation = state
        .mutations()
        .iter()
        .find(|mutation| mutation.key() == nonce_key.as_slice())
        .expect("sender nonce mutation is committed alongside app state");
    match nonce_mutation.mutation() {
        StateMutation::Put(bytes) => {
            let record = SenderNonceRecord::decode(bytes).unwrap();
            assert_eq!(record.sender, sender_bytes);
            assert_eq!(record.epoch, Epoch::new(7));
            assert_eq!(record.next_nonce, 1);
        }
        other => panic!("expected a nonce put mutation, got {other:?}"),
    }
}

fn sender_nonce_key_for(chain: &str, sender: [u8; 32], epoch: Epoch) -> Vec<u8> {
    PersistenceLayout::new(ChainId::new(chain).unwrap(), ProtocolVersion::new(3))
        .sender_nonce_key(sender, epoch)
}

#[test]
fn sender_nonce_sequential_submissions_advance_persisted_next_nonce() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE1);
    let signing_key = dev_signing_key(0x91);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let context = durable_context();
    let resolver = resolver("sunrise-test");

    let first = authenticated_submission(
        "sunrise-test",
        request(0xC0),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        first,
        &machine,
    )
    .unwrap();

    let second = authenticated_submission(
        "sunrise-test",
        request(0xC1),
        &signing_key,
        Epoch::new(7),
        1,
        &config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        second,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 2);
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&context, domain(0xE1), &nonce_key)
        .unwrap();
    let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
    assert_eq!(record.next_nonce, 2);
}

#[test]
fn sender_nonce_sequence_isolated_by_epoch() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let protocol_config = active_protocol_config(0xEE);
    let signing_key = dev_signing_key(0x9E);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let epoch_seven_config = config("sunrise-test");
    let epoch_eight_config = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(8),
        b"node/state".to_vec(),
    )
    .unwrap();
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let context = durable_context();
    let resolver = resolver("sunrise-test");

    for (request_id, epoch, config) in [
        (request(0xCE), Epoch::new(7), &epoch_seven_config),
        (request(0xCF), Epoch::new(8), &epoch_eight_config),
    ] {
        let submission = authenticated_submission(
            "sunrise-test",
            request_id,
            &signing_key,
            epoch,
            0,
            config,
            &protocol_config,
        );
        handle_authenticated_resolved_durable_submit_transaction(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &resolver,
            submission,
            &machine,
        )
        .unwrap();
    }

    for epoch in [Epoch::new(7), Epoch::new(8)] {
        let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, epoch);
        let persisted = store
            .get_versioned_durable(&context, domain(0xEE), &nonce_key)
            .unwrap();
        let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
        assert_eq!(record.epoch, epoch);
        assert_eq!(record.next_nonce, 1);
    }
}

struct ConcurrentNonceMachine {
    barrier: Arc<Barrier>,
}

impl TransactionalNodeStateMachine for ConcurrentNonceMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/concurrent-nonce".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.barrier.wait();
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

fn run_concurrent_nonce_submissions(
    store: Arc<MemoryDurableStateStore>,
    resolver: HashSuiteResolver,
    context: DurableOperationContext,
    first: AuthenticatedSubmitTransaction,
    second: AuthenticatedSubmitTransaction,
    machine: Arc<ConcurrentNonceMachine>,
) -> [Result<ResolvedNodeOutput, NodeCoreError>; 2] {
    let first_handle = {
        let store = Arc::clone(&store);
        let machine = Arc::clone(&machine);
        let resolver = resolver.clone();
        std::thread::spawn(move || {
            handle_authenticated_resolved_durable_submit_transaction(
                &MemoryBlobStore::default(),
                store.as_ref(),
                &context,
                &resolver,
                first,
                machine.as_ref(),
            )
        })
    };
    let second_handle = {
        let store = Arc::clone(&store);
        let machine = Arc::clone(&machine);
        std::thread::spawn(move || {
            handle_authenticated_resolved_durable_submit_transaction(
                &MemoryBlobStore::default(),
                store.as_ref(),
                &context,
                &resolver,
                second,
                machine.as_ref(),
            )
        })
    };

    [first_handle.join().unwrap(), second_handle.join().unwrap()]
}

fn assert_one_nonce_commit_and_one_conflict(
    results: &[Result<ResolvedNodeOutput, NodeCoreError>; 2],
) {
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(NodeCoreError::StateConflict)))
            .count(),
        1
    );
}

#[test]
fn concurrent_first_nonce_submissions_commit_at_most_once() {
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(1).unwrap(),
    ));
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xEF);
    let signing_key = dev_signing_key(0x9F);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let first = authenticated_submission(
        "sunrise-test",
        request(0xD0),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let second = authenticated_submission(
        "sunrise-test",
        request(0xD1),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let machine = Arc::new(ConcurrentNonceMachine {
        barrier: Arc::new(Barrier::new(2)),
    });
    let resolver = resolver("sunrise-test");
    let context = durable_context();

    let results = run_concurrent_nonce_submissions(
        Arc::clone(&store),
        resolver,
        context,
        first,
        second,
        machine,
    );
    assert_one_nonce_commit_and_one_conflict(&results);

    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&durable_context(), domain(0xEF), &nonce_key)
        .unwrap();
    let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
    assert_eq!(record.next_nonce, 1);
}

#[test]
fn concurrent_existing_nonce_submissions_commit_at_most_once() {
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(1).unwrap(),
    ));
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF0);
    let signing_key = dev_signing_key(0xA0);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let resolver = resolver("sunrise-test");
    let context = durable_context();

    let initial = authenticated_submission(
        "sunrise-test",
        request(0xD2),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        store.as_ref(),
        &context,
        &resolver,
        initial,
        &IdempotentMachine {
            calls: AtomicUsize::new(0),
        },
    )
    .unwrap();

    let first = authenticated_submission(
        "sunrise-test",
        request(0xD3),
        &signing_key,
        Epoch::new(7),
        1,
        &config,
        &protocol_config,
    );
    let second = authenticated_submission(
        "sunrise-test",
        request(0xD4),
        &signing_key,
        Epoch::new(7),
        1,
        &config,
        &protocol_config,
    );
    let machine = Arc::new(ConcurrentNonceMachine {
        barrier: Arc::new(Barrier::new(2)),
    });
    let results = run_concurrent_nonce_submissions(
        Arc::clone(&store),
        resolver,
        context,
        first,
        second,
        machine,
    );
    assert_one_nonce_commit_and_one_conflict(&results);

    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&durable_context(), domain(0xF0), &nonce_key)
        .unwrap();
    let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
    assert_eq!(record.next_nonce, 2);
}

#[test]
fn stale_nonce_on_fresh_request_id_rejects_before_app_state_read_transition_or_commit() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE2);
    let signing_key = dev_signing_key(0x92);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC2),
        &signing_key,
        Epoch::new(7),
        1,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::SenderNonceMismatch {
            sender: sender_bytes,
            expected: 0,
            actual: 1,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
    // Only the sender-nonce record is read before the mismatch is
    // detected; the machine's declared application state key is never
    // touched.
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_request_replay_returns_persisted_output_without_reconsuming_nonce() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE3);
    let signing_key = dev_signing_key(0x93);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let context = durable_context();
    let resolver = resolver("sunrise-test");

    let first_submission = authenticated_submission(
        "sunrise-test",
        request(0xC3),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let first = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        first_submission,
        &machine,
    )
    .unwrap();

    let replay_submission = authenticated_submission(
        "sunrise-test",
        request(0xC3),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let replay = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        replay_submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.output().responses(), replay.output().responses());

    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&context, domain(0xE3), &nonce_key)
        .unwrap();
    let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
    assert_eq!(record.next_nonce, 1);
}

#[test]
fn skipped_nonce_rejects_with_exact_expected_and_actual() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE4);
    let signing_key = dev_signing_key(0x94);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC4),
        &signing_key,
        Epoch::new(7),
        5,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::SenderNonceMismatch {
            sender: sender_bytes,
            expected: 0,
            actual: 5,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn nonce_at_u64_max_overflows_instead_of_wrapping() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE5);
    let signing_key = dev_signing_key(0x95);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let record = SenderNonceRecord::new(sender_bytes, Epoch::new(7), u64::MAX);
    store.preload(nonce_key, StateRevision::new(1), record.encode().unwrap());
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC5),
        &signing_key,
        Epoch::new(7),
        u64::MAX,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::SenderNonceOverflow {
            sender: sender_bytes,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn corrupt_nonce_record_bytes_reject_before_app_state_or_commit() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE6);
    let signing_key = dev_signing_key(0x96);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    store.preload(nonce_key, StateRevision::new(1), vec![0xFF, 0x00, 0x01]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC6),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PersistenceInvariant("invalid persisted sender nonce record")
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn nonce_tombstone_never_resets_an_accepted_epoch_to_zero() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xED);
    let signing_key = dev_signing_key(0x9D);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    store.preload_tombstone(nonce_key, StateRevision::new(2));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let submission = authenticated_submission(
        "sunrise-test",
        request(0xCD),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PersistenceInvariant(
            "persisted sender nonce record was deleted while its epoch may be accepted"
        )
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn misbound_nonce_record_sender_rejects_as_persistence_invariant() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE7);
    let signing_key = dev_signing_key(0x97);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    // A record correctly addressed by this sender/epoch's key, but whose
    // own bound fields describe a different sender: corruption or a
    // storage-layer misbinding bug, not an ordinary nonce mismatch.
    let misbound = SenderNonceRecord::new([0xAA; 32], Epoch::new(7), 0);
    store.preload(nonce_key, StateRevision::new(1), misbound.encode().unwrap());
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC7),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PersistenceInvariant(
            "persisted sender nonce record does not match its key's sender/epoch"
        )
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

struct PrefixClaimingMachine {
    key: Vec<u8>,
}

impl TransactionalNodeStateMachine for PrefixClaimingMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            self.key.clone(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                self.key.clone(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?,
        )
    }
}

#[test]
fn app_plan_key_under_sender_nonce_prefix_is_rejected_for_non_submit_event_kind() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let victim_sender = [0x77; 32];
    // A different epoch than the event's own epoch (7): the prefix
    // rejection must not depend on matching the reservation-less caller
    // to any particular sender or epoch.
    let key = sender_nonce_key_for("sunrise-test", victim_sender, Epoch::new(9));
    let machine = PrefixClaimingMachine { key };
    // `event(..)` builds a `ReceiveVote` event: a non-`SubmitTransaction`
    // family, proving the shared helper does not branch on event kind.
    let input = event("sunrise-test", request(0xC8));

    let error = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xE8, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        input,
        &machine,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::ReservedStateAccess(_)));
    assert!(store.commits.lock().unwrap().is_empty());
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);
}

#[test]
fn legacy_transactional_handlers_also_reject_sender_nonce_prefix() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let config = config("sunrise-test");
    let resolver = resolver("sunrise-test");
    let key = sender_nonce_key_for("sunrise-test", [0x78; 32], Epoch::new(9));
    let machine = PrefixClaimingMachine { key };

    let errors = [
        handle_transactional_event(
            &runtime,
            &config,
            event("sunrise-test", request(0xB0)),
            &machine,
        )
        .unwrap_err(),
        handle_idempotent_event(
            &runtime,
            &config,
            &resolver,
            event("sunrise-test", request(0xB1)),
            &machine,
        )
        .unwrap_err(),
        handle_domain_transactional_event(
            &runtime,
            domain(0xB2),
            &config,
            event("sunrise-test", request(0xB2)),
            &machine,
        )
        .unwrap_err(),
        handle_domain_idempotent_event(
            &runtime,
            domain(0xB3),
            &config,
            &resolver,
            event("sunrise-test", request(0xB3)),
            &machine,
        )
        .unwrap_err(),
    ];

    assert!(
        errors
            .iter()
            .all(|error| matches!(error, NodeCoreError::ReservedStateAccess(_)))
    );
}

struct RejectingMachine;

impl TransactionalNodeStateMachine for RejectingMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/reject".to_vec(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let response = NodeResponse::new(event.request_id(), NodeResponseStatus::Rejected, None)?;
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/reject".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 0),
            )?],
            NodeOutput::new(vec![response], Vec::new())?,
        )
    }
}

#[test]
fn committed_deterministic_rejection_still_consumes_the_nonce() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xE9);
    let signing_key = dev_signing_key(0x99);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let context = durable_context();

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xC9),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver("sunrise-test"),
        submission,
        &RejectingMachine,
    )
    .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&context, domain(0xE9), &nonce_key)
        .unwrap();
    let record = SenderNonceRecord::decode(persisted.value().unwrap()).unwrap();
    assert_eq!(record.next_nonce, 1);
}

struct ErrMachine;

impl TransactionalNodeStateMachine for ErrMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/err".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        Err(NodeCoreError::TransitionRejected("test rejection"))
    }
}

#[test]
fn transition_error_does_not_consume_the_nonce() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xEA);
    let signing_key = dev_signing_key(0x9A);
    let sender_bytes = *dev_sender_address(&signing_key).as_bytes();
    let context = durable_context();
    let resolver = resolver("sunrise-test");

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xCA),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        submission,
        &ErrMachine,
    )
    .unwrap_err();
    assert_eq!(error, NodeCoreError::TransitionRejected("test rejection"));

    let nonce_key = sender_nonce_key_for("sunrise-test", sender_bytes, Epoch::new(7));
    let persisted = store
        .get_versioned_durable(&context, domain(0xEA), &nonce_key)
        .unwrap();
    assert!(persisted.value().is_none());

    // The still-expected nonce 0 now succeeds for a fresh request.
    let retry = authenticated_submission(
        "sunrise-test",
        request(0xCB),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        retry,
        &machine,
    )
    .unwrap();
}

struct WideMachine {
    count: usize,
}

impl TransactionalNodeStateMachine for WideMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        let accesses = (0..self.count)
            .map(|index| {
                NodeStateAccess::new(
                    format!("state/wide/{index:05}").into_bytes(),
                    NodeStateAccessMode::ReadOnly,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        NodeStateAccessPlan::new(accesses)
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

#[test]
fn app_plan_at_max_atomic_state_writes_exceeds_reserved_nonce_capacity() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xEB);
    let signing_key = dev_signing_key(0x9B);
    let machine = WideMachine {
        count: MAX_ATOMIC_STATE_WRITES,
    };

    let submission = authenticated_submission(
        "sunrise-test",
        request(0xCC),
        &signing_key,
        Epoch::new(7),
        0,
        &config,
        &protocol_config,
    );
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::TooManyStateAccesses {
            count: MAX_ATOMIC_STATE_WRITES,
            maximum: MAX_ATOMIC_STATE_WRITES - 1,
        }
    );
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());

    // The identical plan is accepted by the generic durable caller, which
    // passes no reservation and therefore does not reserve nonce write
    // capacity.
    let generic_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let generic_machine = WideMachine {
        count: MAX_ATOMIC_STATE_WRITES,
    };
    let output = handle_resolved_durable_idempotent_event(
        &generic_store,
        &durable_context(),
        &placement(0xEC, 7),
        &config,
        &resolver("sunrise-test"),
        event("sunrise-test", request(0xCD)),
        &generic_machine,
    )
    .unwrap();
    assert_eq!(output.output().responses().len(), 1);
}

#[test]
fn wrong_context_is_rejected_before_transition() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_event(
        &runtime,
        &config("expected-chain"),
        event("other-chain", request(0x55)),
        &IncrementMachine,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
    assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
}

struct ConflictingMachine<'a> {
    runtime: &'a MemoryRuntime,
    state_key: Vec<u8>,
}

impl NodeStateMachine for ConflictingMachine<'_> {
    fn transition(
        &self,
        _current_state: Option<&[u8]>,
        _event: &NodeEvent,
    ) -> Result<NodeTransition, NodeCoreError> {
        self.runtime
            .state_store()
            .put(self.state_key.clone(), canonical(TEST_STATE_TYPE_ID, 99))?;
        NodeTransition::new(canonical(TEST_STATE_TYPE_ID, 1), NodeOutput::default())
    }
}

#[test]
fn compare_and_swap_conflict_discards_transition_output() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let config = config("sunrise-test");
    runtime
        .state_store()
        .put(
            config.state_key().to_vec(),
            canonical(TEST_STATE_TYPE_ID, 0),
        )
        .unwrap();
    let machine = ConflictingMachine {
        runtime: &runtime,
        state_key: config.state_key().to_vec(),
    };

    let error = handle_event(
        &runtime,
        &config,
        event("sunrise-test", request(0x66)),
        &machine,
    )
    .unwrap_err();
    let persisted = runtime
        .state_store()
        .get(config.state_key())
        .unwrap()
        .unwrap();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert_eq!(
        decode_canonical_frame(&persisted).unwrap().required_u64(1),
        Ok(99)
    );
}

struct MultiKeyMachine;

impl TransactionalNodeStateMachine for MultiKeyMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(b"state/b".to_vec(), NodeStateAccessMode::ReadWrite)?,
            NodeStateAccess::new(b"state/a".to_vec(), NodeStateAccessMode::ReadWrite)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let value = |key: &[u8]| -> Result<u64, NodeCoreError> {
            match state.get(key).and_then(VersionedStateValue::value) {
                Some(bytes) => Ok(decode_canonical_frame(bytes)?.required_u64(1)?),
                None => Ok(0),
            }
        };
        TransactionalNodeTransition::new(
            vec![
                NodeStateUpdate::put(
                    b"state/b".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, value(b"state/b")? + 2),
                )?,
                NodeStateUpdate::put(
                    b"state/a".to_vec(),
                    canonical(TEST_STATE_TYPE_ID, value(b"state/a")? + 1),
                )?,
            ],
            NodeOutput::default(),
        )
    }
}

#[test]
fn transactional_handler_commits_declared_multi_key_transition() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x67)),
        &MultiKeyMachine,
    )
    .unwrap();

    let a = runtime.state_store().get(b"state/a").unwrap().unwrap();
    let b = runtime.state_store().get(b"state/b").unwrap().unwrap();
    assert_eq!(decode_canonical_frame(&a).unwrap().required_u64(1), Ok(1));
    assert_eq!(decode_canonical_frame(&b).unwrap().required_u64(1), Ok(2));
    assert_eq!(
        runtime
            .state_store()
            .get_versioned(b"state/a")
            .unwrap()
            .revision(),
        StateRevision::new(1)
    );
}

#[test]
fn domain_transactional_handler_isolates_identical_keys() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let first_domain = domain(0xA1);
    let second_domain = domain(0xA2);
    handle_domain_transactional_event(
        &runtime,
        first_domain,
        &config("sunrise-test"),
        event("sunrise-test", request(0x81)),
        &MultiKeyMachine,
    )
    .unwrap();

    let first = runtime
        .state_store()
        .get_versioned_in_domain(first_domain, b"state/a")
        .unwrap();
    let second = runtime
        .state_store()
        .get_versioned_in_domain(second_domain, b"state/a")
        .unwrap();
    assert_eq!(
        decode_canonical_frame(first.value().unwrap())
            .unwrap()
            .required_u64(1),
        Ok(1)
    );
    assert_eq!(
        second,
        VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
    );
    assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
}

struct CountingPlanMachine {
    access_plans: AtomicUsize,
}

impl TransactionalNodeStateMachine for CountingPlanMachine {
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        self.access_plans.fetch_add(1, Ordering::SeqCst);
        MultiKeyMachine.access_plan(event)
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        MultiKeyMachine.transition(state, event)
    }
}

#[test]
fn resolved_transactional_handler_derives_the_access_plan_once() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = CountingPlanMachine {
        access_plans: AtomicUsize::new(0),
    };
    let result = handle_resolved_transactional_event(
        &runtime,
        &placement(0xA3, 7),
        &config("sunrise-test"),
        event("sunrise-test", request(0x87)),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.access_plans.load(Ordering::SeqCst), 1);
    assert_eq!(result.domain(), domain(0xA3));
    assert!(result.output().responses().is_empty());
    assert!(
        runtime
            .state_store()
            .get_versioned_in_domain(result.domain(), b"state/a")
            .unwrap()
            .value()
            .is_some()
    );
}

struct IdempotentMachine {
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for IdempotentMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/idempotent".to_vec(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let current = match state
            .get(b"state/idempotent")
            .and_then(VersionedStateValue::value)
        {
            Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
            None => 0,
        };
        let next = current + 1;
        let response = NodeResponse::new(
            event.request_id(),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
        )?;
        let outbound = OutboundMessage::new(NodeEvent::new(
            event.chain_id().clone(),
            event.protocol_version(),
            event.epoch(),
            request(0xFE),
            NodeEventKind::Tick,
            canonical(TEST_PAYLOAD_TYPE_ID, next),
        )?);
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/idempotent".to_vec(),
                canonical(TEST_STATE_TYPE_ID, next),
            )?],
            NodeOutput::new(vec![response], vec![outbound])?,
        )
    }
}

type ScriptedStateReads = BTreeMap<Vec<u8>, (StateRevision, Option<Vec<u8>>)>;

struct ScriptedDurableStore {
    receipt: Mutex<Option<DurableRequestReceipt>>,
    commits: Mutex<Vec<DurableInvocationTransaction>>,
    state_reads: AtomicUsize,
    object_head_reads: AtomicUsize,
    object_heads: Mutex<BTreeMap<ObjectId, DurableObjectHead>>,
    object_versions: Mutex<BTreeMap<(ObjectId, u64), DurableObjectVersionRecord>>,
    commit_outcome: DurableCommitOutcome,
    preloaded: Mutex<ScriptedStateReads>,
}

impl ScriptedDurableStore {
    fn new(commit_outcome: DurableCommitOutcome) -> Self {
        Self {
            receipt: Mutex::new(None),
            commits: Mutex::new(Vec::new()),
            state_reads: AtomicUsize::new(0),
            object_head_reads: AtomicUsize::new(0),
            object_heads: Mutex::new(BTreeMap::new()),
            object_versions: Mutex::new(BTreeMap::new()),
            commit_outcome,
            preloaded: Mutex::new(BTreeMap::new()),
        }
    }

    /// Scripts a fixed read response for one exact key, overriding the
    /// default absent/`INITIAL` response used by every other key.
    fn preload(&self, key: Vec<u8>, revision: StateRevision, value: Vec<u8>) {
        self.preloaded
            .lock()
            .unwrap()
            .insert(key, (revision, Some(value)));
    }

    fn preload_tombstone(&self, key: Vec<u8>, revision: StateRevision) {
        self.preloaded.lock().unwrap().insert(key, (revision, None));
    }

    fn preload_object(
        &self,
        object_id: ObjectId,
        head: DurableObjectHead,
        version: Option<DurableObjectVersionRecord>,
    ) {
        self.object_heads.lock().unwrap().insert(object_id, head);
        if let Some(version) = version {
            self.object_versions
                .lock()
                .unwrap()
                .insert((object_id, version.object_version().get()), version);
        }
    }
}

impl DurableDomainStateStore for ScriptedDurableStore {
    fn get_versioned_durable(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.state_reads.fetch_add(1, Ordering::SeqCst);
        match self.preloaded.lock().unwrap().get(key) {
            Some((revision, value)) => {
                VersionedStateValue::from_persisted_parts(*revision, value.clone())
                    .map_err(DurableReadError::InvalidRequest)
            }
            None => VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                .map_err(DurableReadError::InvalidRequest),
        }
    }

    fn commit_durable(
        &self,
        _context: &DurableOperationContext,
        _transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    }
}

impl StructuredDurableDomainStateStore for ScriptedDurableStore {
    fn get_request_receipt(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        Ok(self.receipt.lock().unwrap().clone())
    }

    fn commit_invocation(
        &self,
        _context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.commits.lock().unwrap().push(transaction);
        self.commit_outcome.clone()
    }

    fn get_object_head(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.object_head_reads.fetch_add(1, Ordering::SeqCst);
        self.object_heads
            .lock()
            .unwrap()
            .get(&object_id)
            .cloned()
            .ok_or(DurableReadError::InvalidRequest(
                RuntimeError::UnsupportedObjectStorage,
            ))
    }

    fn get_object_version(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        Ok(self
            .object_versions
            .lock()
            .unwrap()
            .get(&(object_id, object_version.get()))
            .cloned())
    }
}

fn preload_inline_object(
    store: &ScriptedDurableStore,
    chain: &str,
    object_id: ObjectId,
    owner: Owner,
    byte: u8,
) -> (ObjectRef, DurableObjectHead) {
    let object: Object = test_object(object_id, 1, owner.clone(), byte);
    let (record, digest): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version(object, chain, 1);
    let head: DurableObjectHead = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head.clone(), Some(record));
    (
        ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        head,
    )
}

/// A [`BlobStore`] test double that counts every [`BlobStore::get_blob`]
/// call and can be scripted to fail closed with a fixed [`RuntimeError`],
/// so tests can prove ordering (a blob fetch never happens before an
/// earlier fail-closed check) as well as exact digest-keyed content.
#[derive(Clone, Default)]
struct InstrumentedBlobStore {
    blobs: Arc<Mutex<BTreeMap<Digest32, Vec<u8>>>>,
    get_calls: Arc<AtomicUsize>,
    put_calls: Arc<AtomicUsize>,
    fail_with: Arc<Mutex<Option<RuntimeError>>>,
    fail_put_with: Arc<Mutex<Option<RuntimeError>>>,
}

impl InstrumentedBlobStore {
    fn insert(&self, digest: Digest32, bytes: Vec<u8>) {
        self.blobs.lock().unwrap().insert(digest, bytes);
    }

    fn fail_with(&self, error: RuntimeError) {
        *self.fail_with.lock().unwrap() = Some(error);
    }

    fn fail_put_with(&self, error: RuntimeError) {
        *self.fail_put_with.lock().unwrap() = Some(error);
    }

    fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }

    fn put_calls(&self) -> usize {
        self.put_calls.load(Ordering::SeqCst)
    }
}

impl BlobStore for InstrumentedBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.fail_put_with.lock().unwrap().clone() {
            return Err(error);
        }
        self.insert(digest, bytes);
        Ok(())
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.fail_with.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.blobs.lock().unwrap().get(digest).cloned())
    }
}

/// Preloads a blob-backed current object version: canonical bytes live
/// only in `blob_store`, keyed under the returned `blob_digest`, exactly
/// like a production content-addressed store. Both the immutable
/// version's own `digest` (checked against the head and independently
/// re-verified against the fetched bytes) and the payload's separate
/// `blob_digest` (independently verified against the same fetched bytes
/// first) are computed from the identical canonical bytes, matching the
/// non-adversarial case; individual tests overwrite one or the other to
/// exercise a specific corruption.
fn preload_blob_object(
    store: &ScriptedDurableStore,
    blob_store: &InstrumentedBlobStore,
    chain: &str,
    object_id: ObjectId,
    owner: Owner,
    byte: u8,
) -> (ObjectRef, DurableObjectHead, Digest32) {
    let object: Object = test_object(object_id, 1, owner.clone(), byte);
    let canonical_bytes: Vec<u8> = encode_object(&object).unwrap();
    let chain_id = ChainId::new(chain).unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let content_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &canonical_bytes,
        )
        .unwrap();
    blob_store.insert(content_digest, canonical_bytes);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        content_digest,
        object.schema_version,
        provenance,
        1,
        content_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: content_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head.clone(), Some(record));
    (
        ObjectRef {
            id: object_id,
            version: 1,
            digest: content_digest,
        },
        head,
        content_digest,
    )
}

fn commit_memory_inline_object(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    object_domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef {
    commit_memory_inline_object_with_protocol_version(
        store,
        context,
        object_domain,
        object,
        chain,
        ProtocolVersion::new(3),
        created_checkpoint,
        receipt_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_memory_inline_object_with_protocol_version(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    object_domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    protocol_version: ProtocolVersion,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef {
    let object_id: ObjectId = object.id;
    let object_version: u64 = object.version;
    let owner: Owner = object.owner.clone();
    let (record, digest): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version_with_protocol_version(
            object,
            chain,
            protocol_version,
            created_checkpoint,
        );
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            runtime::DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([receipt_byte; 32]).unwrap(),
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [receipt_byte.wrapping_add(1); 32],
        ),
        vec![receipt_byte.wrapping_add(2)],
    )
    .unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(object_domain, None, changes, receipt, None).unwrap();
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

struct OwnedObjectEffectMachine {
    expected_inputs: Vec<(ObjectId, AccessMode)>,
    replacement_data: Vec<u8>,
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for OwnedObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/owned-object-effects".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let actual_inputs: Vec<(ObjectId, AccessMode)> = state
            .resolved_objects()
            .iter()
            .map(|input: &ResolvedObject| (input.object.id, input.mode))
            .collect();
        assert_eq!(actual_inputs, self.expected_inputs);

        let mut effects: Vec<ObjectEffect> = Vec::new();
        for input in state.resolved_objects() {
            match input.mode {
                AccessMode::Read => {}
                AccessMode::Write => {
                    let mut new_object: Object = input.object.clone();
                    new_object.version = new_object.version.checked_add(1).unwrap();
                    new_object.data = self.replacement_data.clone();
                    effects.push(ObjectEffect::Mutated {
                        previous_version: input.object.version,
                        new_object,
                    });
                }
                AccessMode::Consume => effects.push(ObjectEffect::Deleted {
                    id: input.object.id,
                    version: input.object.version,
                }),
            }
        }
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), effects, output)
    }
}

struct UndeclaredObjectEffectMachine;

impl TransactionalNodeStateMachine for UndeclaredObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/undeclared-object-effect".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        assert!(state.resolved_objects().is_empty());
        let object_id: ObjectId = ObjectId::new([0xA1; 32]);
        let effect: ObjectEffect = ObjectEffect::Deleted {
            id: object_id,
            version: 1,
        };
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
    }
}

struct ReadObjectEffectMachine;

impl TransactionalNodeStateMachine for ReadObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/read-object-effect".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let [input]: &[ResolvedObject] = state.resolved_objects() else {
            panic!("expected one authenticated read object");
        };
        let effect: ObjectEffect = ObjectEffect::Deleted {
            id: input.object.id,
            version: input.object.version,
        };
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
    }
}

#[test]
fn authenticated_read_only_manifest_commits_sorted_exact_head_assertions() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF1);
    let signing_key = dev_signing_key(0xB1);
    let sender: Address = dev_sender_address(&signing_key);
    let higher_id: ObjectId = ObjectId::new([0x31; 32]);
    let lower_id: ObjectId = ObjectId::new([0x21; 32]);
    let (higher_ref, higher_head): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        higher_id,
        Owner::Address(sender),
        0x31,
    );
    let (lower_ref, lower_head): (ObjectRef, DurableObjectHead) =
        preload_inline_object(&store, "sunrise-test", lower_id, Owner::Immutable, 0x21);
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: higher_ref,
            mode: AccessMode::Read,
        },
        AccessEntry {
            object_ref: lower_ref,
            mode: AccessMode::Read,
        },
    ]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD1),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 2);
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert!(object_changes.mutations().is_empty());
    assert_eq!(
        object_changes.reads(),
        &[
            runtime::DurableObjectHeadRead::new(lower_id, lower_head),
            runtime::DurableObjectHeadRead::new(higher_id, higher_head),
        ]
    );
}

/// Every pure, zero-I/O rejection in [`validate_object_entries`]. The
/// duplicate-`ObjectId` branch is otherwise unreachable through
/// [`authenticated_submission_with_manifest`], since
/// [`abi::decode_access_manifest`] already rejects a duplicate id while
/// decoding the authenticated transaction, so it is exercised directly
/// against the extracted validator here.
#[test]
fn validate_object_entries_rejects_every_pure_branch() {
    fn entry(byte: u8, version: u64, mode: AccessMode) -> AccessEntry {
        AccessEntry {
            object_ref: ObjectRef {
                id: ObjectId::new([byte; 32]),
                version,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
            },
            mode,
        }
    }

    let accepted: Vec<AccessEntry> = (0..32u8)
        .map(|byte| entry(byte, 1, AccessMode::Read))
        .collect();
    let accesses = validate_object_entries(&accepted, AuthenticatedObjectPolicy::ReadOnly).unwrap();
    assert_eq!(accesses.len(), 32);
    assert!(
        accesses
            .windows(2)
            .all(|pair| pair[0].object_ref.id < pair[1].object_ref.id)
    );

    let too_many: Vec<AccessEntry> = (0..33u8)
        .map(|byte| entry(byte, 1, AccessMode::Read))
        .collect();
    assert_eq!(
        validate_object_entries(&too_many, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
        NodeCoreError::ObjectManifestTooLarge {
            count: 33,
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        }
    );

    let duplicate_id = ObjectId::new([0x09; 32]);
    let duplicate = vec![
        AccessEntry {
            object_ref: ObjectRef {
                id: duplicate_id,
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
            },
            mode: AccessMode::Read,
        },
        AccessEntry {
            object_ref: ObjectRef {
                id: duplicate_id,
                version: 2,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            mode: AccessMode::Read,
        },
    ];
    assert_eq!(
        validate_object_entries(&duplicate, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
        NodeCoreError::DuplicateObjectAccess {
            object_id: duplicate_id
        }
    );

    let zero_version_id = ObjectId::new([0x0A; 32]);
    assert_eq!(
        validate_object_entries(
            &[entry(0x0A, 0, AccessMode::Read)],
            AuthenticatedObjectPolicy::ReadOnly,
        )
        .unwrap_err(),
        NodeCoreError::InvalidObjectVersion {
            object_id: zero_version_id,
            version: 0,
        }
    );

    for mode in [AccessMode::Write, AccessMode::Consume] {
        let object_id = ObjectId::new([0x0B; 32]);
        assert_eq!(
            validate_object_entries(&[entry(0x0B, 1, mode)], AuthenticatedObjectPolicy::ReadOnly,)
                .unwrap_err(),
            NodeCoreError::ObjectAccessModeUnsupported { object_id, mode }
        );
    }

    let owned_modes = validate_object_entries(
        &[
            entry(0x0D, 1, AccessMode::Consume),
            entry(0x0C, 1, AccessMode::Write),
        ],
        AuthenticatedObjectPolicy::OwnedMutations {
            created_checkpoint: 1,
        },
    )
    .unwrap();
    assert_eq!(owned_modes.len(), 2);
    assert_eq!(owned_modes[0].object_ref.id, ObjectId::new([0x0D; 32]));
    assert_eq!(owned_modes[1].object_ref.id, ObjectId::new([0x0C; 32]));
}

/// Every storage-facing branch of `load_and_authorize_objects` that only
/// runs once the pure manifest validation above has already passed:
/// unsupported access modes, absence, tombstones, version/digest
/// disagreement with the signed reference, unsupported owner kinds,
/// unreadable blob bodies, a missing immutable version record, and every
/// distinct shape of storage corruption the corruption guard must catch
/// — including an owner projection that disagreed with the inline
/// object's owner and one that was absent entirely.
#[test]
fn authenticated_object_dispatch_fails_closed_for_every_pure_and_storage_branch() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF2);
    let signing_key = dev_signing_key(0xB2);
    let sender: Address = dev_sender_address(&signing_key);

    // `expect_zero_object_io`: true only for manifest entries rejected by
    // the pure, zero-I/O `validate_object_entries` stage, before
    // `load_and_authorize_objects` ever calls `get_object_head`.
    type DispatchCase = (
        &'static str,
        Box<dyn Fn() -> (ScriptedDurableStore, AccessManifest, NodeCoreError)>,
        bool,
    );

    fn current_head_with_owner_projection(
        head: DurableObjectHead,
        owner_projection: DurableObjectOwnerProjection,
    ) -> DurableObjectHead {
        match head {
            DurableObjectHead::Current {
                head_revision,
                object_version,
                digest,
                routing_projection,
                ..
            } => DurableObjectHead::Current {
                head_revision,
                object_version,
                digest,
                owner_projection,
                routing_projection,
            },
            other => panic!("expected current head, got {other:?}"),
        }
    }

    let cases: Vec<DispatchCase> = vec![
        (
            "write mode unsupported",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_ref = sample_object_ref(0x41);
                let object_id = object_ref.id;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Write,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectAccessModeUnsupported {
                        object_id,
                        mode: AccessMode::Write,
                    },
                )
            }),
            true,
        ),
        (
            "consume mode unsupported",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_ref = sample_object_ref(0x4A);
                let object_id = object_ref.id;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Consume,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectAccessModeUnsupported {
                        object_id,
                        mode: AccessMode::Consume,
                    },
                )
            }),
            true,
        ),
        (
            "absent object",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x42; 32]);
                store.preload_object(object_id, DurableObjectHead::Absent, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: sample_object_ref(0x42),
                    mode: AccessMode::Read,
                }]);
                (store, manifest, NodeCoreError::ObjectNotFound { object_id })
            }),
            false,
        ),
        (
            "tombstoned object",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x48; 32]);
                store.preload_object(
                    object_id,
                    DurableObjectHead::Tombstoned {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        last_object_version: DurableObjectVersion::FIRST,
                    },
                    None,
                );
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: sample_object_ref(0x48),
                    mode: AccessMode::Read,
                }]);
                (store, manifest, NodeCoreError::ObjectNotFound { object_id })
            }),
            false,
        ),
        (
            "object version mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x49; 32]);
                let (mut object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x49,
                );
                object_ref.version = 2;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectVersionMismatch {
                        object_id,
                        expected: 2,
                        actual: 1,
                    },
                )
            }),
            false,
        ),
        (
            "object digest mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4B; 32]);
                let (mut object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x4B,
                );
                let actual_digest = object_ref.digest;
                let wrong_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xFE; 32]);
                object_ref.digest = wrong_digest;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectDigestMismatch {
                        object_id,
                        expected: wrong_digest,
                        actual: actual_digest,
                    },
                )
            }),
            false,
        ),
        (
            "owner mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x43; 32]);
                let (object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(Address::new([0xEE; 32])),
                    0x43,
                );
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "shared owner rejected",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4C; 32]);
                let (object_ref, _head) =
                    preload_inline_object(&store, "sunrise-test", object_id, Owner::Shared, 0x4C);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                )
            }),
            false,
        ),
        (
            "system owner rejected",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4D; 32]);
                let (object_ref, _head) =
                    preload_inline_object(&store, "sunrise-test", object_id, Owner::System, 0x4D);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                )
            }),
            false,
        ),
        (
            "blob payload missing from blob store",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x44; 32]);
                let record_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]);
                let blob_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha3_256, [0x46; 32]);
                let blob_record: DurableObjectVersionRecord =
                    DurableObjectVersionRecord::from_blob_reference(
                        object_id,
                        DurableObjectVersion::FIRST,
                        record_digest,
                        1,
                        DurableObjectProvenance::new(
                            ChainId::new("sunrise-test").unwrap(),
                            ProtocolVersion::new(3),
                        ),
                        1,
                        blob_digest,
                    );
                let blob_head: DurableObjectHead = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest: record_digest,
                    owner_projection: DurableObjectOwnerProjection::default(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, blob_head, Some(blob_record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest: record_digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBlobMissing {
                        object_id,
                        blob_digest,
                    },
                )
            }),
            false,
        ),
        (
            "missing version record",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4E; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x4E);
                let (_, digest) = hashed_object_version(object, "sunrise-test", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMissing { object_id },
                )
            }),
            false,
        ),
        (
            "record identity disagrees with owner projection",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x47; 32]);
                let (object_ref, head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x47,
                );
                let corrupt_head = current_head_with_owner_projection(
                    head,
                    DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(
                        [0xEF; 32],
                    )))
                    .unwrap(),
                );
                store.preload_object(object_id, corrupt_head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "absent owner projection",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4F; 32]);
                let (object_ref, head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x4F,
                );
                let corrupt_head = current_head_with_owner_projection(
                    head,
                    DurableObjectOwnerProjection::default(),
                );
                store.preload_object(object_id, corrupt_head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "object body substitution",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x61; 32]);
                let genuine_object = test_object(object_id, 1, Owner::Address(sender), 0x61);
                let (_, digest) = hashed_object_version(genuine_object.clone(), "sunrise-test", 1);
                let mut substituted_object = genuine_object;
                substituted_object.data = vec![0xFF; 4];
                let provenance = DurableObjectProvenance::new(
                    ChainId::new("sunrise-test").unwrap(),
                    ProtocolVersion::new(3),
                );
                let tampered_record = DurableObjectVersionRecord::from_inline_object(
                    substituted_object,
                    digest,
                    provenance,
                    1,
                )
                .unwrap();
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(tampered_record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBodyDigestMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "object provenance chain mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x64; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x64);
                let (record, digest) = hashed_object_version(object, "sunrise-other-chain", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectProvenanceMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "unsupported digest algorithm",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x65; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x65);
                let digest = Digest32::new(HashAlgorithmId::Blake3_256, [0x66; 32]);
                let provenance = DurableObjectProvenance::new(
                    ChainId::new("sunrise-test").unwrap(),
                    ProtocolVersion::new(3),
                );
                let record =
                    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, 1)
                        .unwrap();
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectDigestUnverifiable {
                        object_id,
                        algorithm: HashAlgorithmId::Blake3_256,
                    },
                )
            }),
            false,
        ),
        (
            "object body over per-object bound",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x67; 32]);
                let mut object = test_object(object_id, 1, Owner::Address(sender), 0x67);
                object.data = Vec::new();
                let empty_length = encode_object(&object).unwrap().len();
                object.data = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1 - empty_length];
                let body_length = encode_object(&object).unwrap().len();
                let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBodyTooLarge {
                        object_id,
                        actual: body_length,
                        maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                    },
                )
            }),
            false,
        ),
    ];

    for (index, (name, build, expect_zero_object_io)) in cases.into_iter().enumerate() {
        let (store, manifest, expected_error) = build();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let request_byte = 0xD2u8.wrapping_add(u8::try_from(index).unwrap());
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated_submission_with_manifest(
                "sunrise-test",
                request(request_byte),
                &signing_key,
                Epoch::new(7),
                0,
                manifest,
                &node_config,
                &protocol_config,
            ),
            &machine,
        )
        .unwrap_err();
        assert_eq!(error, expected_error, "case: {name}");
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0, "case: {name}");
        if expect_zero_object_io {
            assert_eq!(store.state_reads.load(Ordering::SeqCst), 0, "case: {name}");
            assert_eq!(
                store.object_head_reads.load(Ordering::SeqCst),
                0,
                "case: {name}"
            );
        }
    }
}

/// A signed read-only access naming a blob-backed object is fetched from
/// the supplied `BlobStore`, independently verified, decoded, and
/// committed exactly like an inline object.
#[test]
fn authenticated_read_only_blob_reference_is_fetched_verified_and_commits() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB0);
    let signing_key = dev_signing_key(0xB0);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x70; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x70,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB0),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(blob_store.get_calls(), 1);
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert!(object_changes.mutations().is_empty());
    assert_eq!(
        object_changes.reads(),
        &[runtime::DurableObjectHeadRead::new(object_id, head)]
    );
    let _ = blob_digest;
}

/// A declared `Write` access may read a blob-backed previous version: the
/// owned-effects entrypoint fetches and verifies it exactly like the
/// read-only entrypoint. The new immutable version it commits here is an
/// ordinary small body (well under `MAX_INLINE_OBJECT_BODY_BYTES`, like
/// every devnet asset account), so it stays inline and zero blobs are
/// published for it — reading a blob-backed previous version never by
/// itself forces the next version to also be blob-backed. The
/// preinstalled-WASM entrypoint shares the identical
/// `load_and_authorize_objects` loader and is not separately exercised
/// here.
#[test]
fn authenticated_owned_write_updates_blob_backed_previous_version_stays_inline_when_small() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB1);
    let signing_key = dev_signing_key(0xB1);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x71; 32]);
    let (object_ref, _head, _blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x71,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB1),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x72],
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        blob_store.get_calls(),
        1,
        "the blob-backed previous version is still fetched"
    );
    assert_eq!(
        blob_store.put_calls(),
        0,
        "a body at or under the threshold must publish nothing"
    );
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert_eq!(object_changes.mutations().len(), 1);
    match object_changes.mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => {
            assert!(matches!(version.payload(), DurableObjectPayload::Inline(_)));
            assert_eq!(version.object_version().get(), 2);
            assert_eq!(committed_object(version, &blob_store).data, vec![0x72]);
        }
        other => panic!("expected an inline Update mutation, got {other:?}"),
    }
}

/// A new version whose canonical bytes exceed `MAX_INLINE_OBJECT_BODY_BYTES`
/// is published to the supplied `BlobStore` and stored as a
/// `BlobReference` keyed under its own object digest, unlike the small
/// body proven inline above.
#[test]
fn authenticated_owned_write_large_update_publishes_and_references_blob() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x75; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x75,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let large_body = vec![0x76; MAX_INLINE_OBJECT_BODY_BYTES + 1];
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: large_body.clone(),
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        blob_store.put_calls(),
        1,
        "a body over the threshold must publish exactly once"
    );
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert_eq!(object_changes.mutations().len(), 1);
    match object_changes.mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => {
            assert!(matches!(
                version.payload(),
                DurableObjectPayload::BlobReference(_)
            ));
            assert_eq!(version.object_version().get(), 2);
            assert_eq!(committed_object(version, &blob_store).data, large_body);
        }
        other => panic!("expected a blob-referenced Update mutation, got {other:?}"),
    }
}

/// Exact request replay returns the persisted receipt before the
/// transition, effect translation, or blob publication ever run, even for
/// an owned `Write` that would otherwise publish a new version.
#[test]
fn authenticated_owned_write_exact_replay_publishes_no_blob() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x77);
    let signing_key = dev_signing_key(0x77);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x77; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x77,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x78; MAX_INLINE_OBJECT_BODY_BYTES + 1],
        calls: AtomicUsize::new(0),
    };

    let first_blob_store = InstrumentedBlobStore::default();
    let first_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x77),
        &signing_key,
        Epoch::new(7),
        0,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &first_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        first_submission,
        2,
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first_blob_store.put_calls(), 1);

    // The scripted store's `commit_invocation` does not itself persist
    // the receipt for later `get_request_receipt` reads, unlike a real
    // durable adapter; wire the exact committed receipt through so the
    // second call is a genuine exact replay.
    let commits = store.commits.lock().unwrap();
    let committed_receipt = commits[0].receipt().clone();
    drop(commits);
    *store.receipt.lock().unwrap() = Some(committed_receipt);

    let replay_blob_store = InstrumentedBlobStore::default();
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x77),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &replay_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        999,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        replay_blob_store.put_calls(),
        0,
        "exact replay must publish no blob"
    );
    assert_eq!(
        replay_blob_store.get_calls(),
        0,
        "exact replay must return before any blob-store I/O"
    );
}

/// A `BlobStore::put_blob` failure while publishing a new version aborts
/// the request before `commit_invocation` is ever called: zero
/// state/receipt/nonce/outbox/object changes, distinct from a later
/// commit-time rejection.
#[test]
fn authenticated_owned_write_blob_publish_failure_aborts_before_commit() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    blob_store.fail_put_with(RuntimeError::DurableStoreUnavailable);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x78);
    let signing_key = dev_signing_key(0x78);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x78; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x78,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x78),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x79; MAX_INLINE_OBJECT_BODY_BYTES + 1],
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBlobPublishFailed {
            object_id: id,
            source: RuntimeError::DurableStoreUnavailable,
            ..
        } if id == object_id
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(blob_store.put_calls(), 1);
    assert!(
        store.commits.lock().unwrap().is_empty(),
        "a publish failure must never reach commit_invocation"
    );
    assert!(store.receipt.lock().unwrap().is_none());
}

/// A later `commit_invocation` rejection (e.g. a concurrent object head
/// conflict) can only ever leave an already-published blob as an
/// unreachable content-addressed orphan: the blob was published before
/// the rejected commit attempt and remains directly readable from the
/// `BlobStore`, but no head or receipt ever came to reference it.
#[test]
fn authenticated_owned_write_commit_rejection_leaves_only_an_orphan_blob() {
    let object_id = ObjectId::new([0x7A; 32]);
    let conflict = DurableCommitRejection::ObjectConflict {
        object_id,
        current: runtime::DurableObjectHeadSummary::Absent,
    };
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(conflict));
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x7A);
    let signing_key = dev_signing_key(0x7A);
    let sender: Address = dev_sender_address(&signing_key);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7A,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x7A),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let large_body = vec![0x7B; MAX_INLINE_OBJECT_BODY_BYTES + 1];
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: large_body.clone(),
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectConflict { object_id });
    // `commit_invocation` was attempted (and scripted to reject),
    // strictly after the blob was already published.
    assert_eq!(blob_store.put_calls(), 1);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let version = match commits[0].object_changes().mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => version.clone(),
        other => panic!("expected an Update mutation, got {other:?}"),
    };
    drop(commits);
    assert!(matches!(
        version.payload(),
        DurableObjectPayload::BlobReference(_)
    ));
    assert_eq!(
        committed_object(&version, &blob_store).data,
        large_body,
        "the orphaned blob remains directly readable from the BlobStore"
    );
}

/// A [`RuntimeError`] surfaced by the supplied `BlobStore` is a typed
/// runtime/storage error, not silently treated as a missing blob.
#[test]
fn authenticated_object_dispatch_blob_store_runtime_error_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    blob_store.fail_with(RuntimeError::DurableStoreUnavailable);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB2);
    let signing_key = dev_signing_key(0xB2);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x73; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x73,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB2),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::Runtime(RuntimeError::DurableStoreUnavailable)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A blob digest absent from the supplied `BlobStore` is a distinct typed
/// missing-blob error.
#[test]
fn authenticated_object_dispatch_missing_blob_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB3);
    let signing_key = dev_signing_key(0xB3);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x74; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x74,
    );
    // The record/head are preloaded, but the blob content itself is
    // never inserted into `blob_store`.
    let _ = head;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB3),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let empty_blob_store = InstrumentedBlobStore::default();

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &empty_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBlobMissing {
            object_id,
            blob_digest,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// Fetched blob bytes are bounded at the same per-object limit as an
/// inline body before either digest is verified or the body is decoded:
/// oversized bytes that are also not a valid canonical `Object` still
/// reject as `ObjectBodyTooLarge`, never a decode error, proving the
/// bound runs first.
#[test]
fn authenticated_object_dispatch_oversized_blob_rejects_before_hashing_or_decode() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB4);
    let signing_key = dev_signing_key(0xB4);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x75; 32]);
    // Deliberately malformed (not a canonical `Object` encoding) so a
    // check that ran hashing or decoding first would fail differently.
    let oversized_bytes: Vec<u8> = vec![0xAB; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1];
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x75; 32]);
    blob_store.insert(blob_digest, oversized_bytes);
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x76; 32]);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        record_digest,
        0,
        provenance,
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: record_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: record_digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB4),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        }
    );
    assert_eq!(blob_store.get_calls(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// A blob whose fetched bytes do not hash to their own claimed
/// `blob_digest` is a distinct typed corruption from
/// `ObjectBodyDigestMismatch`, and is caught before `objects::decode_object`
/// ever runs (the substituted bytes below are not a valid canonical
/// `Object` encoding either).
#[test]
fn authenticated_object_dispatch_blob_digest_mismatch_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x77; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x77,
    );
    // Substitute the stored bytes for something that does not hash to
    // the payload's own claimed `blob_digest`.
    blob_store.insert(blob_digest, vec![0xEE; 16]);
    let _ = head;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBlobDigestMismatch {
            object_id,
            blob_digest,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Fetched blob bytes that are not a valid canonical `Object` encoding,
/// but do hash to their own claimed `blob_digest`, fail closed as a
/// typed `DurableInvocation` decode error rather than panicking.
#[test]
fn authenticated_object_dispatch_malformed_blob_bytes_fail_decode() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB6);
    let signing_key = dev_signing_key(0xB6);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x78; 32]);
    let garbage: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44];
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let blob_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(HashPurpose::Object, protocol_version, &chain_id, &garbage)
        .unwrap();
    blob_store.insert(blob_digest, garbage);
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        record_digest,
        0,
        provenance,
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: record_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: record_digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB6),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert!(
        matches!(error, NodeCoreError::DurableInvocation(_)),
        "expected a typed decode error, got {error:?}"
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// A blob whose decoded object identity disagrees with the signed
/// reference is corruption distinct from a digest mismatch, exactly like
/// the existing inline record-mismatch checks.
#[test]
fn authenticated_object_dispatch_blob_identity_mismatch_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB7);
    let signing_key = dev_signing_key(0xB7);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7A; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7A,
    );
    // Overwrite the stored blob with a validly encoded but differently
    // identified object, still hashing to the same `blob_digest` value
    // is not possible; instead this proves the identity cross-check
    // fires once the (different) content is legitimately fetched and
    // decoded under its own consistent digest.
    let substituted_object =
        test_object(ObjectId::new([0x7B; 32]), 1, Owner::Address(sender), 0x7A);
    let substituted_bytes = encode_object(&substituted_object).unwrap();
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let substituted_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &substituted_bytes,
        )
        .unwrap();
    // Re-preload the head/version so the record's own `digest` and
    // `blob_digest` both consistently name the substituted content,
    // isolating the identity check from the earlier digest checks.
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        substituted_digest,
        substituted_object.schema_version,
        provenance,
        1,
        substituted_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: substituted_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    blob_store.insert(substituted_digest, substituted_bytes);
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: substituted_digest,
        },
        mode: AccessMode::Read,
    }]);
    let _ = object_ref;
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB7),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectRecordMismatch { object_id });
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Focused corruption cases exercised only after a blob is successfully
/// fetched and its own `blob_digest` independently verifies, proving each
/// later independent check still fails closed: the record's own `digest`
/// re-verified against the same fetched bytes (distinct from the earlier
/// `blob_digest` check), the decoded object's `version` disagreeing with
/// the signed reference, the decoded object's `schema_version`
/// disagreeing with the row, and an unsupported `blob_digest` algorithm.
#[test]
fn authenticated_object_dispatch_blob_specific_corruption_cases_fail_closed() {
    struct Case {
        name: &'static str,
        object: Object,
        store_blob: bool,
        blob_digest: fn(&[u8]) -> Digest32,
        /// `None` means "compute correctly from the encoded bytes".
        record_digest: Option<Digest32>,
        record_schema_version: Option<u32>,
        declared_version: u64,
        expected_error: fn(ObjectId) -> NodeCoreError,
    }

    fn correct_digest(bytes: &[u8]) -> Digest32 {
        BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                ProtocolVersion::new(3),
                &ChainId::new("sunrise-test").unwrap(),
                bytes,
            )
            .unwrap()
    }

    fn unsupported_algorithm_digest(_bytes: &[u8]) -> Digest32 {
        Digest32::new(HashAlgorithmId::Blake3_256, [0x11; 32])
    }

    let sender: Address = dev_sender_address(&dev_signing_key(0xC1));
    let cases = [
        Case {
            name: "record digest mismatch after a valid blob_digest",
            object: test_object(ObjectId::new([0x81; 32]), 1, Owner::Address(sender), 0x81),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: Some(Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32])),
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectBodyDigestMismatch { object_id },
        },
        Case {
            name: "decoded object version mismatch",
            object: test_object(ObjectId::new([0x82; 32]), 2, Owner::Address(sender), 0x82),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: None,
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectRecordMismatch { object_id },
        },
        Case {
            name: "decoded object schema mismatch",
            object: test_object(ObjectId::new([0x83; 32]), 1, Owner::Address(sender), 0x83),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: None,
            record_schema_version: Some(0xFFFF_FFFF),
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectRecordMismatch { object_id },
        },
        Case {
            name: "unsupported blob_digest algorithm fails closed",
            object: test_object(ObjectId::new([0x84; 32]), 1, Owner::Address(sender), 0x84),
            store_blob: true,
            blob_digest: unsupported_algorithm_digest,
            record_digest: None,
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectDigestUnverifiable {
                object_id,
                algorithm: HashAlgorithmId::Blake3_256,
            },
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let object_id = case.object.id;
        let encoded_bytes = encode_object(&case.object).unwrap();
        let blob_digest = (case.blob_digest)(&encoded_bytes);
        let record_digest = case
            .record_digest
            .unwrap_or_else(|| correct_digest(&encoded_bytes));
        let schema_version = case
            .record_schema_version
            .unwrap_or(case.object.schema_version);

        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob_store = InstrumentedBlobStore::default();
        if case.store_blob {
            blob_store.insert(blob_digest, encoded_bytes);
        }
        let provenance = DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::FIRST,
            record_digest,
            schema_version,
            provenance,
            1,
            blob_digest,
        );
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest: record_digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: case.declared_version,
                digest: record_digest,
            },
            mode: AccessMode::Read,
        }]);
        let signing_key = dev_signing_key(0xC1);
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xC1);
        let submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xC1u8.wrapping_add(u8::try_from(index).unwrap())),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let error = handle_authenticated_resolved_durable_submit_transaction(
            &blob_store,
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            (case.expected_error)(object_id),
            "case: {}",
            case.name
        );
        assert_eq!(
            machine.calls.load(Ordering::SeqCst),
            0,
            "case: {}",
            case.name
        );
    }
}

/// The version record's stored chain provenance is checked from the
/// record header alone, before any blob-store I/O: a cross-chain
/// blob-backed record rejects without ever calling `get_blob`.
#[test]
fn authenticated_object_dispatch_provenance_mismatch_rejects_before_blob_fetch() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB8);
    let signing_key = dev_signing_key(0xB8);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7C; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-other-chain",
        object_id,
        Owner::Address(sender),
        0x7C,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectProvenanceMismatch { object_id });
    assert_eq!(
        blob_store.get_calls(),
        0,
        "provenance mismatch must reject before any blob-store I/O"
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Exact request replay returns the persisted receipt before any
/// `BlobStore` I/O, even when the replayed request's own manifest names a
/// blob-backed object.
#[test]
fn exact_replay_returns_before_blob_store_io() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let first_blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB9);
    let signing_key = dev_signing_key(0xB9);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7D; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &first_blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7D,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let first_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &first_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        first_submission,
        &machine,
    )
    .unwrap();
    assert_eq!(first_blob_store.get_calls(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);

    // The scripted store's `commit_invocation` does not itself persist
    // the receipt for later `get_request_receipt` reads, unlike a real
    // durable adapter; wire the exact committed receipt through so the
    // second call is a genuine exact replay.
    let commits = store.commits.lock().unwrap();
    let committed_receipt = commits[0].receipt().clone();
    drop(commits);
    *store.receipt.lock().unwrap() = Some(committed_receipt);

    let replay_blob_store = InstrumentedBlobStore::default();
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &replay_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        replay_blob_store.get_calls(),
        0,
        "exact replay must return before any blob-store I/O"
    );
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 1);
}

/// The aggregate 8 MiB inline/blob body budget is shared: an inline body
/// and a blob-fetched body count against the same running total, and the
/// bound rejects before the transition runs regardless of which entry
/// pushed it over.
#[test]
fn mixed_inline_and_blob_bodies_share_the_aggregate_bound() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xBA);
    let signing_key = dev_signing_key(0xBA);
    let sender: Address = dev_sender_address(&signing_key);
    const PER_OBJECT_BYTES: usize = 300_000;
    const _: () = assert!(PER_OBJECT_BYTES < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
    // 30 objects at 300,000 bytes each is 9,000,000 bytes, safely over
    // the 8 MiB aggregate bound while each individual body stays under
    // the 1 MiB per-object bound and the 32-entry manifest bound.
    const OBJECT_COUNT: usize = 30;
    const _: () = assert!(OBJECT_COUNT <= MAX_AUTHENTICATED_OBJECT_READS);
    const _: () =
        assert!(OBJECT_COUNT * PER_OBJECT_BYTES > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES);
    let mut entries: Vec<AccessEntry> = Vec::with_capacity(OBJECT_COUNT);
    for index in 0..OBJECT_COUNT {
        let byte = u8::try_from(index).unwrap();
        let object_id = ObjectId::new([byte; 32]);
        if index % 2 == 0 {
            let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
            object.data = Vec::new();
            let empty_length = encode_object(&object).unwrap().len();
            object.data = vec![0; PER_OBJECT_BYTES - empty_length];
            let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
            let head = DurableObjectHead::Current {
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            };
            store.preload_object(object_id, head, Some(record));
            entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: object_id,
                    version: 1,
                    digest,
                },
                mode: AccessMode::Read,
            });
        } else {
            let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
            object.data = Vec::new();
            let empty_length = encode_object(&object).unwrap().len();
            object.data = vec![0; PER_OBJECT_BYTES - empty_length];
            let canonical_bytes = encode_object(&object).unwrap();
            let chain_id = ChainId::new("sunrise-test").unwrap();
            let protocol_version = ProtocolVersion::new(3);
            let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
                .hash(
                    HashPurpose::Object,
                    protocol_version,
                    &chain_id,
                    &canonical_bytes,
                )
                .unwrap();
            blob_store.insert(digest, canonical_bytes);
            let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
            let record = DurableObjectVersionRecord::from_blob_reference(
                object_id,
                DurableObjectVersion::FIRST,
                digest,
                object.schema_version,
                provenance,
                1,
                digest,
            );
            let head = DurableObjectHead::Current {
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            };
            store.preload_object(object_id, head, Some(record));
            entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: object_id,
                    version: 1,
                    digest,
                },
                mode: AccessMode::Read,
            });
        }
    }
    let manifest = manifest_with(entries);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xBA),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            ..
        }
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// An object created under a different protocol version than the current
/// event still verifies, because node-core recomputes with the record's
/// own stored provenance and never with the reader's epoch-selected hash
/// suite. This is the regression test that forbids reintroducing
/// `HashSuiteResolver`-based digest recomputation.
#[test]
fn object_created_under_an_older_protocol_version_still_verifies() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x62; 32]);
    let object = test_object(object_id, 1, Owner::Address(sender), 0x62);
    let (record, digest) = hashed_object_version_with_protocol_version(
        object,
        "sunrise-test",
        ProtocolVersion::new(2),
        1,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE1),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.commits.lock().unwrap().len(), 1);
}

/// A stored digest whose algorithm differs from the reader's active epoch
/// suite still verifies, because the algorithm comes from the
/// self-describing stored digest, not the epoch suite.
#[test]
fn object_digest_algorithm_differing_from_reader_epoch_suite_still_verifies() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF6);
    let signing_key = dev_signing_key(0xB6);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x63; 32]);
    let object = test_object(object_id, 1, Owner::Address(sender), 0x63);
    let canonical_bytes = encode_object(&object).unwrap();
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha3_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &canonical_bytes,
        )
        .unwrap();
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record =
        DurableObjectVersionRecord::from_inline_object(object, digest, provenance, 1).unwrap();
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE2),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

/// 32 entries individually under the per-object bound whose sum crosses
/// the aggregate bound are rejected without ever reaching the transition.
#[test]
fn object_bodies_over_aggregate_bound_reject_before_transition_or_commit() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xFA);
    let signing_key = dev_signing_key(0xBA);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    const PER_OBJECT_BYTES: usize = 300_000;
    const _: () = assert!(PER_OBJECT_BYTES < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
    const _: () = assert!(
        MAX_AUTHENTICATED_OBJECT_READS * PER_OBJECT_BYTES
            > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES
    );
    let mut entries: Vec<AccessEntry> = Vec::with_capacity(MAX_AUTHENTICATED_OBJECT_READS);
    for index in 0..MAX_AUTHENTICATED_OBJECT_READS {
        let byte = u8::try_from(index).unwrap();
        let object_id = ObjectId::new([byte; 32]);
        let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
        object.data = Vec::new();
        let empty_length = encode_object(&object).unwrap().len();
        object.data = vec![0; PER_OBJECT_BYTES - empty_length];
        let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        entries.push(AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            mode: AccessMode::Read,
        });
    }
    let manifest = manifest_with(entries);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE6),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            ..
        }
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn receipt_and_nonce_short_circuit_before_authenticated_object_reads() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF3);
    let signing_key = dev_signing_key(0xB3);
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: sample_object_ref(0x51),
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let stale_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let stale_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD7),
        &signing_key,
        Epoch::new(7),
        1,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    assert!(matches!(
        handle_authenticated_resolved_durable_submit_transaction(
            &MemoryBlobStore::default(),
            &stale_store,
            &durable_context(),
            &resolver("sunrise-test"),
            stale_submission,
            &machine,
        ),
        Err(NodeCoreError::SenderNonceMismatch { .. })
    ));
    assert_eq!(stale_store.object_head_reads.load(Ordering::SeqCst), 0);

    let replay_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let event_digest: Digest32 = replay_submission
        .event()
        .digest(&resolver("sunrise-test"))
        .unwrap();
    let response: NodeResponse = NodeResponse::new(
        replay_submission.event().request_id(),
        NodeResponseStatus::Accepted,
        None,
    )
    .unwrap();
    let record: NodeDedupRecord = NodeDedupRecord::new(
        replay_submission.event().request_id(),
        event_digest,
        vec![response],
    )
    .unwrap();
    replay_store.receipt.lock().unwrap().replace(
        DurableRequestReceipt::new(
            DurableRequestId::new(*replay_submission.event().request_id().as_bytes()).unwrap(),
            event_digest,
            record.encode().unwrap(),
        )
        .unwrap(),
    );
    let replay = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &replay_store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        &machine,
    )
    .unwrap();
    assert_eq!(replay.output().responses().len(), 1);
    assert_eq!(replay_store.state_reads.load(Ordering::SeqCst), 0);
    assert_eq!(replay_store.object_head_reads.load(Ordering::SeqCst), 0);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn authenticated_object_head_conflict_is_retryable_and_distinct() {
    let object_id: ObjectId = ObjectId::new([0x61; 32]);
    let conflict = DurableCommitRejection::ObjectConflict {
        object_id,
        current: runtime::DurableObjectHeadSummary::Absent,
    };
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(conflict));
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF4);
    let signing_key = dev_signing_key(0xB4);
    let sender: Address = dev_sender_address(&signing_key);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x61,
    );
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectConflict { object_id });
    assert_eq!(store.commits.lock().unwrap().len(), 1);
    assert!(store.receipt.lock().unwrap().is_none());
}

/// Commits an object directly against a real [`MemoryDurableStateStore`]
/// (bypassing node-core, which does not implement object writes), then
/// authorizes and commits a non-empty read-only manifest referencing it
/// through the full authenticated submit-transaction path.
#[test]
fn memory_store_authenticated_read_only_manifest_commits_against_real_object_store() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF7);
    let signing_key = dev_signing_key(0xC7);
    let sender: Address = dev_sender_address(&signing_key);
    let context = durable_context();
    let resolver = resolver("sunrise-test");
    let object_domain = domain(0xF7);
    let object_id = ObjectId::new([0x81; 32]);

    let object = test_object(object_id, 1, Owner::Address(sender), 0x81);
    let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
    let create_mutation = runtime::DurableObjectMutation::Create {
        version: record,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let create_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            create_mutation,
        )],
    )
    .unwrap();
    let create_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x21; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        vec![0x23],
    )
    .unwrap();
    let create_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        create_changes,
        create_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, create_invocation),
        DurableCommitOutcome::Committed
    );

    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolved.domain(), object_domain);
    assert_eq!(resolved.output().responses().len(), 1);

    let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record = SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn memory_store_authenticated_owned_write_commits_atomically_and_replays_receipt() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFA);
    let signing_key: SigningKey = dev_signing_key(0xCA);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFA);
    let read_id: ObjectId = ObjectId::new([0x84; 32]);
    let write_id: ObjectId = ObjectId::new([0x94; 32]);
    let read_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(read_id, 1, Owner::Immutable, 0x84),
        "sunrise-test",
        4,
        0x31,
    );
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x94),
        "sunrise-test",
        5,
        0x34,
    );
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: read_ref,
            mode: AccessMode::Read,
        },
    ]);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(write_id, AccessMode::Write), (read_id, AccessMode::Read)],
        replacement_data: vec![0xA4],
        calls: AtomicUsize::new(0),
    };

    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let first: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            submission,
            6,
            &machine,
        )
        .unwrap();
    let replay: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            replay_submission,
            999,
            &machine,
        )
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    let write_v2: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            write_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(write_v2.created_checkpoint(), 6);
    assert!(
        matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
        "a body at or under the threshold must stay inline"
    );
    assert_eq!(committed_object(&write_v2, &blob_store).data, vec![0xA4]);
    let read_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, read_id)
        .unwrap();
    assert_eq!(read_head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

// ── preinstalled WASM composition (Developer MVP step 3) ────────────────

/// A contract that overwrites `object[0]`'s data with a fixed byte,
/// exactly like `execution::wasm_engine`'s own `write_object_contract`
/// test fixture.
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

/// A contract that overwrites both declared objects. It is intentionally
/// metadata-blind: node-core must authorize the non-sender destination
/// from the committed semantics policy before execution.
fn preinstalled_write_two_wasm_bytes() -> Vec<u8> {
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
              (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))
              (drop (call $write_object_data (i32.const 1) (i32.const 0) (i32.const 2)))))"#,
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
            (data (i32.const 0) "contract-secret-abort-marker")
            (func (export "run")
              (call $abort (i32.const 0) (i32.const 28))))"#,
    )
    .unwrap()
}

/// A contract that succeeds without touching any resolved object, even
/// though the transaction may declare `Write`/`Consume` access.
fn preinstalled_noop_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (memory 1)
            (export "memory" (memory 0))
            (func (export "run")))"#,
    )
    .unwrap()
}

/// A contract that consumes `object[0]`.
fn preinstalled_consume_wasm_bytes() -> Vec<u8> {
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
            (func (export "run")
              (drop (call $consume_object (i32.const 0)))))"#,
    )
    .unwrap()
}

/// A contract that calls `create_object` once, matching
/// `execution::wasm_engine`'s own `create_object` test fixture layout
/// (34-byte type hash at offset 0, one data byte at offset 34).
fn preinstalled_create_wasm_bytes() -> Vec<u8> {
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
            (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF")
            (func (export "run")
              (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))))"#,
    )
    .unwrap()
}

/// A contract that creates an Address-owned object using the historical
/// universal ZIP-215 non-canonical identity encoding. Profile 1 admits
/// these owner bytes, while profile 2 must reject them before durable
/// commit. The separate Create prohibition remains in force either way.
fn preinstalled_create_with_inadmissible_owner_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "create_object" (func $create_object (param i32 i32 i32 i32 i32 i32)(result i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF")
            (data (i32.const 35) "\01")
            (data (i32.const 66) "\80")
            (func (export "run")
              (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 3) (i32.const 35)))))"#,
    )
    .unwrap()
}

fn preinstalled_manifest(
    module_id: ModuleId,
    max_input_size: u64,
) -> system_modules::SystemModuleManifest {
    system_modules::SystemModuleManifest {
        module_id,
        input_schema: system_modules::TypeSchema {
            descriptor: "counter.input.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        },
        output_schema: system_modules::TypeSchema {
            descriptor: "counter.output.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        },
        max_input_size,
        gas_model: system_modules::GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    }
}

/// Builds a committed [`SystemModuleRegistry`] entry and a matching
/// [`PreinstalledModuleCatalog`] entry whose commitments agree, plus the
/// `ObjectRef` an authenticated transaction must declare as `module_ref`
/// to reference it (see [`preinstalled_wasm::resolve_preinstalled_module`]
/// for the exact mapping).
fn preinstalled_module_fixture(
    resolver: &HashSuiteResolver,
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    max_input_size: u64,
    activation_epoch: Epoch,
    status: system_modules::ModuleStatus,
) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::opaque_only(b"test-semantics-v1".to_vec()).unwrap();
    preinstalled_module_fixture_with_envelope(
        resolver,
        module_id,
        version,
        wasm_bytes,
        max_input_size,
        activation_epoch,
        status,
        envelope,
    )
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_module_fixture_with_envelope(
    resolver: &HashSuiteResolver,
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    max_input_size: u64,
    activation_epoch: Epoch,
    status: system_modules::ModuleStatus,
    envelope: PreinstalledModuleSemanticsEnvelope,
) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
    let manifest = preinstalled_manifest(module_id, max_input_size);
    let code_hash = resolver
        .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, &wasm_bytes)
        .unwrap();
    let manifest_bytes = system_modules::encode_system_module_manifest(&manifest).unwrap();
    let manifest_hash = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &manifest_bytes,
        )
        .unwrap();
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&envelope).unwrap();
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &semantics_bytes,
        )
        .unwrap();
    let module = system_modules::SystemModule {
        module_id,
        version,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch,
        status,
    };
    let mut registry = SystemModuleRegistry::new();
    registry.add_module(module).unwrap();
    let entry =
        PreinstalledModuleCatalogEntry::new(module_id, version, wasm_bytes, manifest, envelope)
            .unwrap();
    let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
    let module_ref = ObjectRef {
        id: ObjectId::new(*module_id.as_bytes()),
        version,
        digest: code_hash,
    };
    (registry, catalog, module_ref)
}

fn preinstalled_transaction(
    sender: Address,
    chain: ChainId,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> Transaction {
    preinstalled_transaction_with_protocol_version(
        sender,
        chain,
        ProtocolVersion::new(3),
        epoch,
        nonce,
        access_manifest,
        module_ref,
        args,
    )
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_transaction_with_protocol_version(
    sender: Address,
    chain: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> Transaction {
    Transaction {
        chain_id: chain,
        protocol_version,
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

const OWNER_TRANSITION_CONSTRUCTOR_ID: u16 = 0x7A01;
const OWNER_TRANSITION_BODY_TYPE_ID: u16 = 0x7A01;
const OWNER_TRANSITION_ARGS_TYPE_ID: u16 = 0x7A02;

fn owner_transition_envelope() -> PreinstalledModuleSemanticsEnvelope {
    let constructor: ConstructorDeclaration = ConstructorDeclaration {
        id: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
        body_type_id: OWNER_TRANSITION_BODY_TYPE_ID,
        body_version: 1,
        schema_version: 1,
        arity: TypeArity::Fixed,
        projection: Vec::new(),
    };
    let signature: EntrypointSignature = EntrypointSignature::new(
        "run".to_string(),
        vec![ParamDeclaration {
            mode: AccessMode::Write,
            constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
            schema_version: 1,
        }],
    )
    .unwrap();
    let typed: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![constructor], signature).unwrap();
    let owner: PreinstalledOwnerTransitionPolicy = PreinstalledOwnerTransitionPolicy::new(
        "run".to_string(),
        0,
        OWNER_TRANSITION_ARGS_TYPE_ID,
        1,
        1,
    )
    .unwrap();
    PreinstalledModuleSemanticsEnvelope::with_typed_policies(
        b"owner-transition-test".to_vec(),
        Vec::new(),
        vec![typed],
        vec![owner],
    )
    .unwrap()
}

fn owner_transition_args(recipient: Address) -> Vec<u8> {
    let mut args: CanonicalStruct = CanonicalStruct::new(OWNER_TRANSITION_ARGS_TYPE_ID, 1);
    args.field_bytes(1, recipient.as_bytes().to_vec()).unwrap();
    args.finish().unwrap()
}

fn owner_transition_object(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    id: ObjectId,
    owner: Address,
    data: Vec<u8>,
) -> Object {
    let type_hash: Digest32 = abi::derive_type_id(
        resolver,
        epoch,
        &TypeTag {
            constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
            type_arg: None,
        },
    )
    .unwrap();
    let mut body: CanonicalStruct = CanonicalStruct::new(OWNER_TRANSITION_BODY_TYPE_ID, 1);
    body.field_bytes(1, data).unwrap();
    Object {
        id,
        version: 1,
        owner: Owner::Address(owner),
        type_hash,
        schema_version: 1,
        data: body.finish().unwrap(),
    }
}

fn zero_fee_policy() -> CommittedFeePolicy {
    let config: ProtocolConfig = ProtocolConfig::genesis();
    CommittedFeePolicy {
        gas_schedule: config.gas_schedule,
        fee_assets: config.fee_assets,
    }
}

fn submit_event_for_protocol(protocol_version: ProtocolVersion, request_byte: u8) -> NodeEvent {
    NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        request(request_byte),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap()
}

fn load_cross_owner_destination_with_policy(
    policy: Option<PreinstalledObjectAccessPolicy>,
    entrypoint: &str,
    destination_mode: AccessMode,
    destination_owner: Owner,
    source_is_sender: bool,
) -> Result<LoadedAuthenticatedObjects, NodeCoreError> {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = Address::new([0x41; 32]);
    let (source_ref, _source_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x42; 32]),
        Owner::Address(if source_is_sender {
            sender
        } else {
            Address::new([0x98; 32])
        }),
        0x30,
    );
    let (destination_ref, _destination_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x43; 32]),
        destination_owner,
        0x31,
    );
    let dispatch = AuthenticatedObjectDispatch {
        authority: sender,
        owner_address_policy: Ed25519OwnerAddressPolicy::LegacyZip215,
        accesses: vec![
            AuthenticatedObjectAccess {
                object_ref: source_ref,
                mode: AccessMode::Write,
            },
            AuthenticatedObjectAccess {
                object_ref: destination_ref,
                mode: destination_mode,
            },
        ],
    };
    let policies: Vec<PreinstalledObjectAccessPolicy> = policy.into_iter().collect();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"test".to_vec(), policies).unwrap();
    let authorization = ResolvedPreinstalledAuthorization {
        entrypoint,
        envelope: &envelope,
    };
    load_and_authorize_objects(
        &store,
        &MemoryBlobStore::default(),
        &durable_context(),
        domain(0x44),
        &ChainId::new("sunrise-test").unwrap(),
        &dispatch,
        Some(&authorization),
        None,
    )
}

#[test]
fn strict_profile_rejects_inadmissible_destination_and_treasury_owners() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = dev_sender_address(&dev_signing_key(0x41));
    let mut universal_owner_bytes: [u8; 32] = [0; 32];
    universal_owner_bytes[0] = 1;
    universal_owner_bytes[31] = 0x80;
    let universal_owner: Address = Address::new(universal_owner_bytes);
    let (source_ref, _source_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x42; 32]),
        Owner::Address(sender),
        0x30,
    );
    let destination_id: ObjectId = ObjectId::new([0x43; 32]);
    let (destination_ref, _destination_head) = preload_inline_object(
        &store,
        "sunrise-test",
        destination_id,
        Owner::Address(universal_owner),
        0x31,
    );
    let dispatch = AuthenticatedObjectDispatch {
        authority: sender,
        owner_address_policy: Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        accesses: vec![
            AuthenticatedObjectAccess {
                object_ref: source_ref,
                mode: AccessMode::Write,
            },
            AuthenticatedObjectAccess {
                object_ref: destination_ref,
                mode: AccessMode::Write,
            },
        ],
    };
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        0x31,
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"test".to_vec(), vec![policy]).unwrap();
    let authorization = ResolvedPreinstalledAuthorization {
        entrypoint: "run",
        envelope: &envelope,
    };
    for treasury_object_id in [None, Some(destination_id)] {
        assert_eq!(
            load_and_authorize_objects(
                &store,
                &MemoryBlobStore::default(),
                &durable_context(),
                domain(0x44),
                &ChainId::new("sunrise-test").unwrap(),
                &dispatch,
                Some(&authorization),
                treasury_object_id,
            ),
            Err(NodeCoreError::InadmissibleObjectOwnerAddress {
                object_id: destination_id,
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
            })
        );
    }
}

#[test]
fn typed_entrypoint_rejects_mismatch_before_wasm_execution() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x31; 32]);
    let object_id: ObjectId = ObjectId::new([0x32; 32]);
    let mut object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x33]);
    object.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]);
    let module_id: ModuleId = ModuleId::new([0x34; 32]);
    // Invalid WASM bytes make the ordering observable: reaching the
    // engine would return an execution error instead of this ABI error.
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        vec![0xFF],
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x32),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x35; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert!(matches!(
        machine.transition(&state, &submit_event_for_protocol(protocol_version, 0x36)),
        Err(NodeCoreError::TypedAbi(
            abi::AbiError::TypeIdentityMismatch { .. }
        ))
    ));
}

#[test]
fn owner_transition_v3_rejects_before_wasm_execution() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(3);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x37; 32]);
    let object: Object = owner_transition_object(
        &hash_resolver,
        Epoch::new(7),
        ObjectId::new([0x38; 32]),
        sender,
        vec![0x39],
    );
    let module_id: ModuleId = ModuleId::new([0x3A; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        vec![0xFF],
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x38),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x3B; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert_eq!(
        machine
            .transition(&state, &submit_event_for_protocol(protocol_version, 0x3C))
            .unwrap_err(),
        NodeCoreError::OwnerTransitionProtocolVersionTooLow {
            actual: protocol_version,
            minimum: ProtocolVersion::new(4),
        }
    );
}

#[test]
fn owner_transition_rejects_module_effect_for_transferred_object() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x3D; 32]);
    let object_id: ObjectId = ObjectId::new([0x3E; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x3F]);
    let module_id: ModuleId = ModuleId::new([0x40; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x3E),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x41; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert_eq!(
        machine
            .transition(&state, &submit_event_for_protocol(protocol_version, 0x42))
            .unwrap_err(),
        NodeCoreError::OwnerTransitionObjectEffectForbidden { object_id }
    );
}

#[test]
fn owner_transition_rejects_fee_payer_and_treasury_aliases() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x43; 32]);
    let object_id: ObjectId = ObjectId::new([0x44; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x45]);
    let module_id: ModuleId = ModuleId::new([0x46; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let object_ref: ObjectRef = ObjectRef {
        id: object_id,
        version: object.version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x47; 32]),
    };
    let base_transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x48; 32])),
    );
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };
    let effects = ExecutionEffects {
        tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x49; 32]),
        status: ExecutionStatus::Success,
        object_effects: Vec::new(),
        events: Vec::new(),
        gas_used: 0,
    };
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let catalog_entry: &PreinstalledModuleCatalogEntry = catalog.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();

    let mut payer_transaction: Transaction = base_transaction.clone();
    payer_transaction.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: object_ref,
    });
    let payer_machine = PreinstalledWasmMachine {
        transaction: &payer_transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    assert_eq!(
        payer_machine
            .synthesize_owner_transition(catalog_entry, &state, &effects)
            .err(),
        Some(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id })
    );

    let composer: RecordingFeeComposer = RecordingFeeComposer::new();
    let treasury_machine = PreinstalledWasmMachine {
        transaction: &base_transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: Some(PreinstalledFeeComposition::new(object_id, &composer)),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    assert_eq!(
        treasury_machine
            .synthesize_owner_transition(catalog_entry, &state, &effects)
            .err(),
        Some(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id })
    );
}

#[test]
fn owner_transition_v4_receipt_and_committed_mutation_match_exactly() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x4A);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x4A);
    protocol_config.protocol_version = protocol_version;
    let signing_key: SigningKey = dev_signing_key(0x4A);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = dev_sender_address(&dev_signing_key(0x4B));
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let module_id: ModuleId = ModuleId::new([0x4C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let object_id: ObjectId = ObjectId::new([0x4D; 32]);
    let original: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x4E, 0x4F]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        original.clone(),
        "sunrise-test",
        protocol_version,
        9,
        0x50,
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(recipient),
    );
    let request_id: RequestId = request(0x51);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request_id,
        &signing_key,
        epoch,
        transaction,
        &node_config,
        &protocol_config,
    );

    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap();
    let response: &NodeResponse = &resolved.output().responses()[0];
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let receipt_effects: ExecutionEffects =
        execution::decode_execution_effects(response.payload().unwrap()).unwrap();
    assert_eq!(receipt_effects.object_effects.len(), 1);
    let ObjectEffect::Mutated {
        previous_version,
        new_object,
    } = &receipt_effects.object_effects[0]
    else {
        panic!("owner transition receipt did not contain one mutation");
    };
    assert_eq!(*previous_version, 1);
    assert_eq!(new_object.id, object_id);
    assert_eq!(new_object.version, 2);
    assert_eq!(new_object.owner, Owner::Address(recipient));
    assert_eq!(new_object.data, original.data);
    assert_eq!(new_object.type_hash, original.type_hash);
    assert_eq!(new_object.schema_version, original.schema_version);

    let committed: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            object_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(committed_object(&committed, &blob_store), *new_object);

    let persisted_receipt: ReceiptQueryResult =
        query_request_receipt(&store, &context, object_domain, request_id).unwrap();
    let ReceiptQueryResult::Present { record, .. } = persisted_receipt else {
        panic!("accepted owner transition receipt was not persisted");
    };
    assert_eq!(record.responses()[0].payload(), response.payload());
}

/// Proves the index-space invariant documented on
/// [`PreinstalledOwnerTransitionPolicy`] and DR-0106: with a signed
/// manifest of *three* declared accesses (transferred object, a distinct
/// fee payer, and the fee treasury as the final entry) but the treasury
/// hidden from engine visibility, `transferred_access_index = 0` still
/// resolves to the intended object rather than silently drifting once a
/// third manifest entry is introduced.
#[test]
fn owner_transition_index_unaffected_by_hidden_final_treasury() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x53);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x53);
    protocol_config.protocol_version = protocol_version;
    let signing_key: SigningKey = dev_signing_key(0x53);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = dev_sender_address(&dev_signing_key(0x54));
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);

    // Two Write params, matching the two engine-visible resolved objects
    // once the treasury is hidden: index 0 is the transferred object,
    // index 1 is the distinct fee payer.
    let constructor: ConstructorDeclaration = ConstructorDeclaration {
        id: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
        body_type_id: OWNER_TRANSITION_BODY_TYPE_ID,
        body_version: 1,
        schema_version: 1,
        arity: TypeArity::Fixed,
        projection: Vec::new(),
    };
    let signature: EntrypointSignature = EntrypointSignature::new(
        "run".to_string(),
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
                schema_version: 1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
                schema_version: 1,
            },
        ],
    )
    .unwrap();
    let typed: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![constructor], signature).unwrap();
    let owner: PreinstalledOwnerTransitionPolicy = PreinstalledOwnerTransitionPolicy::new(
        "run".to_string(),
        0,
        OWNER_TRANSITION_ARGS_TYPE_ID,
        1,
        1,
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_typed_policies(
            b"owner-transition-hidden-treasury-test".to_vec(),
            Vec::new(),
            vec![typed],
            vec![owner],
        )
        .unwrap();

    let module_id: ModuleId = ModuleId::new([0x55; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        envelope,
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let object_id: ObjectId = ObjectId::new([0x56; 32]);
    let original: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x57, 0x58]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        original.clone(),
        "sunrise-test",
        protocol_version,
        9,
        0x59,
    );

    let payer_id: ObjectId = ObjectId::new([0x5A; 32]);
    let payer_object: Object =
        owner_transition_object(&hash_resolver, epoch, payer_id, sender, vec![0x5B]);
    let payer_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        protocol_version,
        9,
        0x5C,
    );

    let treasury_owner: Address = Address::new([0x5D; 32]);
    let treasury_id: ObjectId = ObjectId::new([0x5E; 32]);
    let mut treasury_object: Object =
        test_object(treasury_id, 1, Owner::Address(treasury_owner), 0x5E);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        protocol_version,
        9,
        0x5F,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest,
        module_ref,
        owner_transition_args(recipient),
    );
    transaction.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });

    let request_id: RequestId = request(0x60);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request_id,
        &signing_key,
        epoch,
        transaction,
        &node_config,
        &protocol_config,
    );

    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            Some(fee_composition),
        )
        .unwrap();

    let response: &NodeResponse = &resolved.output().responses()[0];
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let receipt_effects: ExecutionEffects =
        execution::decode_execution_effects(response.payload().unwrap()).unwrap();
    // The owner-transition target (transferred index 0) is the only
    // application effect: it is unaffected by the fee payer/treasury
    // entries appended after it in the signed manifest.
    assert_eq!(receipt_effects.object_effects.len(), 1);
    let ObjectEffect::Mutated { new_object, .. } = &receipt_effects.object_effects[0] else {
        panic!("owner transition receipt did not contain one mutation");
    };
    assert_eq!(new_object.id, object_id);
    assert_eq!(new_object.owner, Owner::Address(recipient));
    assert_eq!(new_object.data, original.data);

    // The distinct fee payer (engine-visible typed parameter 1) and the
    // hidden treasury were still separately debited/credited: the
    // hidden-from-engine treasury access did not simply vanish.
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                payer_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_some(),
        "fee payer must have been separately debited"
    );
    let committed_treasury: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&committed_treasury, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn owner_transition_inadmissible_recipient_commits_nothing() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x52);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x52);
    protocol_config.protocol_version = protocol_version;
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0x52);
    let sender: Address = dev_sender_address(&signing_key);
    let mut recipient_bytes: [u8; 32] = [0; 32];
    recipient_bytes[0] = 1;
    recipient_bytes[31] = 0x80;
    let inadmissible_recipient: Address = Address::new(recipient_bytes);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let module_id: ModuleId = ModuleId::new([0x53; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let object_id: ObjectId = ObjectId::new([0x54; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x55]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        object,
        "sunrise-test",
        protocol_version,
        9,
        0x56,
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(inadmissible_recipient),
    );
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request(0x57),
            &signing_key,
            epoch,
            transaction,
            &node_config,
            &protocol_config,
        );

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap_err();
    assert_eq!(
        error,
        NodeCoreError::InadmissibleObjectOutputOwnerAddress {
            object_id,
            source: Ed25519OwnerAddressError::NonCanonicalPoint,
        }
    );
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        query_request_receipt(&store, &context, object_domain, request(0x57)).unwrap(),
        ReceiptQueryResult::Absent {
            request_id: request(0x57)
        }
    );
}

#[test]
fn preinstalled_wasm_owned_write_commits_object_nonce_and_receipt() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFD);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0xDA);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFD);
    let module_id = ModuleId::new([0x70; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x95; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x95),
        "sunrise-test",
        9,
        0x3A,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request(0xF0),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
    let engine = WasmExecutionEngine;
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(resolved.output().responses().len(), 1);
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    assert!(resolved.output().responses()[0].payload().is_some());
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    let write_v2: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            write_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    let committed_write: Object = committed_object(&write_v2, &blob_store);
    assert_eq!(committed_write.owner, Owner::Address(sender));
    assert_eq!(committed_write.data, vec![0xCA, 0xFE]);
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn preinstalled_wasm_committed_policy_allows_exact_cross_owner_destination_write() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xD1);
    let signing_key: SigningKey = dev_signing_key(0xD1);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = Address::new([0xD2; 32]);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD1);
    let module_id: ModuleId = ModuleId::new([0xD3; 32]);
    let destination_byte: u8 = 0x21;
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [destination_byte.wrapping_add(1); 32],
        ),
        u32::from(destination_byte),
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope = PreinstalledModuleSemanticsEnvelope::new(
        b"two-object-transfer-test".to_vec(),
        vec![policy],
    )
    .unwrap();
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_two_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        envelope,
    );
    protocol_config.system_modules = registry;

    let source_id: ObjectId = ObjectId::new([0xD4; 32]);
    let destination_id: ObjectId = ObjectId::new([0xD5; 32]);
    let source_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(source_id, 1, Owner::Address(sender), 0x20),
        "sunrise-test",
        9,
        0xD4,
    );
    let destination_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(
            destination_id,
            1,
            Owner::Address(recipient),
            destination_byte,
        ),
        "sunrise-test",
        9,
        0xD5,
    );
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: source_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: destination_ref,
            mode: AccessMode::Write,
        },
    ]);
    let transaction: Transaction = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xD6),
        &signing_key,
        Epoch::new(7),
        transaction,
        &node_config,
        &protocol_config,
    );

    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for (object_id, expected_owner) in [(source_id, sender), (destination_id, recipient)] {
        let record: DurableObjectVersionRecord = store
            .get_object_version(
                &context,
                object_domain,
                object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        let object: Object = committed_object(&record, &blob_store);
        assert_eq!(object.owner, Owner::Address(expected_owner));
        assert_eq!(object.data, vec![0xCA, 0xFE]);
    }
}

#[test]
fn preinstalled_cross_owner_policy_rejects_wrong_position_entrypoint_mode_type_and_schema() {
    let expected_type: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]);
    let exact_policy = || {
        PreinstalledObjectAccessPolicy::new(
            1,
            "run".to_string(),
            AccessMode::Write,
            expected_type,
            0x31,
        )
        .unwrap()
    };

    assert!(
        load_cross_owner_destination_with_policy(
            Some(exact_policy()),
            "run",
            AccessMode::Write,
            Owner::Address(Address::new([0x99; 32])),
            true,
        )
        .is_ok()
    );

    let wrong_position: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        2,
        "run".to_string(),
        AccessMode::Write,
        expected_type,
        0x31,
    )
    .unwrap();
    let wrong_type: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]),
        0x31,
    )
    .unwrap();
    let wrong_schema: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        expected_type,
        0x32,
    )
    .unwrap();
    let cases: Vec<(Option<PreinstalledObjectAccessPolicy>, &str, AccessMode)> = vec![
        (None, "run", AccessMode::Write),
        (Some(wrong_position), "run", AccessMode::Write),
        (Some(exact_policy()), "other", AccessMode::Write),
        (Some(exact_policy()), "run", AccessMode::Consume),
        (Some(wrong_type), "run", AccessMode::Write),
        (Some(wrong_schema), "run", AccessMode::Write),
    ];
    for (policy, entrypoint, mode) in cases {
        assert!(matches!(
            load_cross_owner_destination_with_policy(
                policy,
                entrypoint,
                mode,
                Owner::Address(Address::new([0x99; 32])),
                true,
            ),
            Err(NodeCoreError::ObjectOwnerMismatch { .. })
        ));
    }
}

#[test]
fn preinstalled_cross_owner_policy_never_authorizes_non_address_owner_kinds() {
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        0x31,
    )
    .unwrap();
    for owner in [Owner::Shared, Owner::System, Owner::Immutable] {
        assert!(matches!(
            load_cross_owner_destination_with_policy(
                Some(policy.clone()),
                "run",
                AccessMode::Write,
                owner,
                true,
            ),
            Err(NodeCoreError::ObjectOwnerKindUnsupported { .. })
        ));
    }

    assert!(matches!(
        load_cross_owner_destination_with_policy(
            Some(policy),
            "run",
            AccessMode::Write,
            Owner::Address(Address::new([0x99; 32])),
            false,
        ),
        Err(NodeCoreError::ObjectOwnerMismatch { .. })
    ));
}

#[test]
fn preinstalled_wasm_exact_replay_does_not_reexecute_or_reapply() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFE);
    let signing_key: SigningKey = dev_signing_key(0xDB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFE);
    let module_id = ModuleId::new([0x71; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x96; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x96),
        "sunrise-test",
        9,
        0x3B,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xF1),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let engine = WasmExecutionEngine;

    let first =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();
    // An empty catalog and a different composition-trusted checkpoint on
    // replay prove that the persisted receipt short-circuits before module
    // resolution, object load, checkpoint validation, or execution.
    let empty_catalog: PreinstalledModuleCatalog =
        PreinstalledModuleCatalog::new(Vec::new()).unwrap();
    let replay =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &empty_catalog,
            &engine,
            replay_submission,
            999,
            None,
        )
        .unwrap();

    assert_eq!(first, replay);
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                write_id,
                DurableObjectVersion::new(3).unwrap(),
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn preinstalled_wasm_rejects_unknown_inactive_and_not_yet_active_module_before_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFF);
    let signing_key: SigningKey = dev_signing_key(0xDC);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x72; 32]);
    let engine = WasmExecutionEngine;

    // Unknown: empty registry, nonempty catalog.
    let (_, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let empty_registry = SystemModuleRegistry::new();
    let run_case = |registry: &SystemModuleRegistry,
                    catalog: &PreinstalledModuleCatalog,
                    module_ref: ObjectRef,
                    request_byte: u8|
     -> (NodeCoreError, usize) {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([request_byte; 32]),
            Owner::Address(sender),
            request_byte,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &{
                let mut committed_config: ProtocolConfig = protocol_config.clone();
                committed_config.system_modules = registry.clone();
                committed_config
            },
        );
        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
&MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();
        (error, store.commits.lock().unwrap().len())
    };

    let (error, commits) = run_case(&empty_registry, &catalog, module_ref.clone(), 0xA0);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleUnknown {
            module_id,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Pending (not yet activated / not Active): registry has the module,
    // but its status is Pending.
    let (pending_registry, _, pending_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        2,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Pending,
    );
    let pending_entry = PreinstalledModuleCatalogEntry::new(
        module_id,
        2,
        preinstalled_write_wasm_bytes(),
        preinstalled_manifest(module_id, 64),
        PreinstalledModuleSemanticsEnvelope::opaque_only(b"test-semantics-v1".to_vec()).unwrap(),
    )
    .unwrap();
    let pending_catalog = PreinstalledModuleCatalog::new(vec![pending_entry]).unwrap();
    let (error, commits) = run_case(&pending_registry, &pending_catalog, pending_ref, 0xA1);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleInactive {
            module_id,
            version: 2
        }
    );
    assert_eq!(commits, 0);

    // Active but not yet activated at the transaction's epoch (7).
    let (future_registry, future_catalog, future_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        3,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(8),
        system_modules::ModuleStatus::Active,
    );
    let (error, commits) = run_case(&future_registry, &future_catalog, future_ref, 0xA2);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleNotYetActive {
            module_id,
            version: 3,
            activation_epoch: Epoch::new(8),
            current_epoch: Epoch::new(7),
        }
    );
    assert_eq!(commits, 0);
}

#[test]
fn preinstalled_wasm_rejects_reference_digest_code_manifest_and_semantics_mismatch_before_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xF6);
    let signing_key: SigningKey = dev_signing_key(0xDD);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let engine = WasmExecutionEngine;

    let run_case = |registry: SystemModuleRegistry,
                    catalog: PreinstalledModuleCatalog,
                    module_ref: ObjectRef,
                    request_byte: u8|
     -> (NodeCoreError, usize) {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([request_byte; 32]),
            Owner::Address(sender),
            request_byte,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &{
                let mut committed_config: ProtocolConfig = protocol_config.clone();
                committed_config.system_modules = registry.clone();
                committed_config
            },
        );
        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
&MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();
        (error, store.commits.lock().unwrap().len())
    };

    // Declared `module_ref.digest` disagrees with the registry commitment.
    let module_id_a = ModuleId::new([0x73; 32]);
    let (registry_a, catalog_a, ref_a) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_a,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_ref = ref_a.clone();
    tampered_ref.digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let (error, commits) = run_case(registry_a, catalog_a, tampered_ref, 0xB0);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
            module_id: module_id_a,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Not cataloged: registry commits it, but no catalog entry exists.
    let module_id_b = ModuleId::new([0x74; 32]);
    let (registry_b, _catalog_b, ref_b) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_b,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let empty_catalog = PreinstalledModuleCatalog::new(vec![]).unwrap();
    let (error, commits) = run_case(registry_b, empty_catalog, ref_b, 0xB1);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleNotCataloged {
            module_id: module_id_b,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry code hash disagrees with the catalog's actual WASM bytes.
    let module_id_c = ModuleId::new([0x75; 32]);
    let (mut registry_c, catalog_c, mut ref_c) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_c,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_module = registry_c.get(module_id_c, 1).unwrap().clone();
    tampered_module.canonical_code_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_c = SystemModuleRegistry::new();
    registry_c.add_module(tampered_module.clone()).unwrap();
    ref_c.digest = tampered_module.canonical_code_hash;
    let (error, commits) = run_case(registry_c, catalog_c, ref_c, 0xB2);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleCodeHashMismatch {
            module_id: module_id_c,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry manifest hash disagrees with the catalog's actual manifest.
    let module_id_d = ModuleId::new([0x76; 32]);
    let (mut registry_d, catalog_d, ref_d) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_d,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_manifest_module = registry_d.get(module_id_d, 1).unwrap().clone();
    tampered_manifest_module.manifest_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_d = SystemModuleRegistry::new();
    registry_d.add_module(tampered_manifest_module).unwrap();
    let (error, commits) = run_case(registry_d, catalog_d, ref_d, 0xB3);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleManifestHashMismatch {
            module_id: module_id_d,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry semantics hash disagrees with the catalog entry.
    let module_id_e = ModuleId::new([0x77; 32]);
    let (mut registry_e, catalog_e, ref_e) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_e,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_semantics_module = registry_e.get(module_id_e, 1).unwrap().clone();
    tampered_semantics_module.semantics_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_e = SystemModuleRegistry::new();
    registry_e.add_module(tampered_semantics_module).unwrap();
    let (error, commits) = run_case(registry_e, catalog_e, ref_e, 0xB4);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
            module_id: module_id_e,
            version: 1
        }
    );
    assert_eq!(commits, 0);
}

#[test]
fn preinstalled_wasm_rejects_oversized_args_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xF8);
    let signing_key: SigningKey = dev_signing_key(0xDE);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x78; 32]);
    // max_input_size = 1, but args below are 2 bytes.
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        1,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x98; 32]),
        Owner::Address(sender),
        0x98,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleArgsTooLarge {
            module_id,
            version: 1,
            actual: 2,
            maximum: 1,
        }
    );
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_trapped_execution_commits_deterministic_rejected_receipt_without_object_mutation()
 {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xF9);
    let signing_key: SigningKey = dev_signing_key(0xDF);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xF9);
    let module_id = ModuleId::new([0x79; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_trap_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x99; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x99),
        "sunrise-test",
        9,
        0x3C,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let expected_tx_hash: Digest32 = hash_transaction(&tx, &hash_resolver).unwrap();
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xB6),
        &signing_key,
        Epoch::new(7),
        tx.clone(),
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(resolved.output().responses().len(), 1);
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payload: &[u8] = resolved.output().responses()[0].payload().unwrap();

    // The contract's own abort message must never reach the persisted
    // payload, and neither must engine-internal (`wasmi`) text: every
    // trap is normalized to one fixed, engine-independent reason before
    // encoding (see `preinstalled_wasm::normalize_trapped_preinstalled_execution`).
    let payload_text = String::from_utf8_lossy(payload);
    assert!(!payload_text.contains("contract-secret-abort-marker"));
    assert!(!payload_text.contains("wasmi"));

    // The encoded payload is stable: it is exactly the canonical
    // encoding of the normalized closed failure (fixed reason, full
    // `gas_limit` charge, empty effects/events), independent of exactly
    // where inside the contract execution trapped.
    let expected_effects = execution::ExecutionEffects {
        tx_hash: expected_tx_hash,
        status: ExecutionStatus::Failure {
            reason: "preinstalled module execution trapped".to_string(),
        },
        object_effects: Vec::new(),
        events: Vec::new(),
        gas_used: tx.gas_limit,
    };
    let expected_payload = encode_execution_effects(&expected_effects).unwrap();
    assert_eq!(payload, expected_payload.as_slice());

    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn preinstalled_wasm_zero_object_access_is_rejected_before_domain_resolution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE0);
    let signing_key: SigningKey = dev_signing_key(0xE0);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7A; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    // No access-manifest entries at all: this MVP path requires at least
    // one authenticated object.
    let manifest = manifest_with(Vec::new());
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC0),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::PreinstalledModuleZeroObjectAccess);
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_consume_commits_tombstone_end_to_end() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE2);
    let signing_key: SigningKey = dev_signing_key(0xE2);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xE2);
    let module_id = ModuleId::new([0x7C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_consume_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let consume_id: ObjectId = ObjectId::new([0x9B; 32]);
    let consume_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(consume_id, 1, Owner::Address(sender), 0x9B),
        "sunrise-test",
        9,
        0x3E,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: consume_ref,
        mode: AccessMode::Consume,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC1),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, consume_id)
        .unwrap();
    assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
}

#[test]
fn preinstalled_wasm_create_effect_is_fail_closed() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE3);
    let signing_key: SigningKey = dev_signing_key(0xE3);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7D; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_create_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC2; 32]),
        Owner::Address(sender),
        0xC2,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC2),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectCreationUnsupported { .. }
    ));
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn strict_preinstalled_output_owner_rejects_before_atomic_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xA7);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0xA7);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id: ModuleId = ModuleId::new([0xA8; 32]);
    let (registry, catalog, module_ref): (
        SystemModuleRegistry,
        PreinstalledModuleCatalog,
        ObjectRef,
    ) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_create_with_inadmissible_owner_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let input_id: ObjectId = ObjectId::new([0xA9; 32]);
    let (object_ref, original_head): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        input_id,
        Owner::Address(sender),
        0xA9,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let transaction: Transaction = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    let request_id: RequestId = request(0xAA);
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request_id,
            &signing_key,
            Epoch::new(7),
            transaction,
            &node_config,
            &protocol_config,
        );
    let context: DurableOperationContext = durable_context();

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(
        matches!(
            error,
            NodeCoreError::InadmissibleObjectOutputOwnerAddress {
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    // No invocation reached the atomic store, so nonce, receipt, and
    // outbox remain absent together rather than partially committing.
    assert!(store.commits.lock().unwrap().is_empty());
    assert!(store.receipt.lock().unwrap().is_none());
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let nonce: VersionedStateValue = store
        .get_versioned_durable(&context, domain(0xA7), nonce_key.as_slice())
        .unwrap();
    assert!(nonce.value().is_none());
    let current_head: DurableObjectHead = store
        .get_object_head(&context, domain(0xA7), input_id)
        .unwrap();
    assert_eq!(current_head, original_head);
    assert!(
        store
            .get_object_version(
                &context,
                domain(0xA7),
                input_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn preinstalled_wasm_missing_entrypoint_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE4);
    let signing_key: SigningKey = dev_signing_key(0xE4);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7E; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC3; 32]),
        Owner::Address(sender),
        0xC3,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.entrypoint = "does-not-exist".to_string();
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC4),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::Execution(ExecutionError::MissingEntrypoint(_))
    ));
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_gas_limit_exact_ceiling_succeeds_and_over_ceiling_is_rejected() {
    // Over the ceiling: rejected before the engine ever runs, no commit.
    let node_config: NodeConfig = config("sunrise-test");
    let mut over_protocol_config: ProtocolConfig = active_protocol_config(0xE5);
    let signing_key: SigningKey = dev_signing_key(0xE5);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let over_module_id = ModuleId::new([0x7F; 32]);
    let (over_registry, over_catalog, over_module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        over_module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    over_protocol_config.system_modules = over_registry;
    let over_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (over_object_ref, _) = preload_inline_object(
        &over_store,
        "sunrise-test",
        ObjectId::new([0xC5; 32]),
        Owner::Address(sender),
        0xC5,
    );
    let over_manifest = manifest_with(vec![AccessEntry {
        object_ref: over_object_ref,
        mode: AccessMode::Read,
    }]);
    let mut over_tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        over_manifest,
        over_module_ref,
        vec![1, 2],
    );
    over_tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1;
    let over_submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC6),
        &signing_key,
        Epoch::new(7),
        over_tx,
        &node_config,
        &over_protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &over_store,
            &durable_context(),
            &hash_resolver,
            &over_catalog,
            &engine,
            over_submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
            requested: MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1,
            maximum: MAX_PREINSTALLED_MODULE_GAS_LIMIT,
        }
    );
    assert_eq!(over_store.commits.lock().unwrap().len(), 0);

    // Exactly at the ceiling: accepted and committed end-to-end.
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE6);
    let context: DurableOperationContext = durable_context();
    let object_domain: AtomicityDomainId = domain(0xE6);
    let module_id = ModuleId::new([0x80; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0xC7; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0xC7),
        "sunrise-test",
        9,
        0x3F,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT;
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC7),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
}

#[test]
fn preinstalled_wasm_successful_noop_on_declared_write_is_fail_closed_non_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE7);
    let signing_key: SigningKey = dev_signing_key(0xE7);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x81; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC8; 32]),
        Owner::Address(sender),
        0xC8,
    );
    let write_object_id = object_ref.id;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC8),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    // The contract runs to completion without trapping (a genuine
    // `ExecutionStatus::Success`) but never calls `write_object_data`, so
    // it produces no effect for the declared `Write` access. This must
    // still fail closed instead of silently committing as a no-op.
    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id: write_object_id,
            reason: "write access requires exactly one mutated effect",
        }
    );
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_resolves_end_to_end_across_hash_suite_rotation() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(15),
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE8);
    let signing_key: SigningKey = dev_signing_key(0xE8);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver_with_rotation("sunrise-test", Epoch::new(10));
    let object_domain: AtomicityDomainId = domain(0xE8);
    let module_id = ModuleId::new([0x82; 32]);
    // Committed while the SHA2-256 genesis suite is active (epoch 0, see
    // `preinstalled_module_fixture`).
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0xC9; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0xC9),
        "sunrise-test",
        9,
        0x40,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    // Epoch 15 is well after the resolver's SHA3-256 rotation at epoch
    // 10, even though the module was committed under the SHA2-256
    // genesis suite; resolution must still succeed (see
    // `hashing::verify_digest`).
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(15),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC9),
        &signing_key,
        Epoch::new(15),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
}

#[test]
fn memory_store_authenticated_owned_consume_commits_tombstone_with_nonce() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFB);
    let signing_key: SigningKey = dev_signing_key(0xCB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFB);
    let object_id: ObjectId = ObjectId::new([0x85; 32]);
    let object_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(object_id, 1, Owner::Address(sender), 0x85),
        "sunrise-test",
        5,
        0x37,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Consume,
    }]);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Consume)],
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &hash_resolver,
        submission,
        6,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn authenticated_owned_write_requires_exact_effect_before_commit() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
    let signing_key: SigningKey = dev_signing_key(0xCC);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id: ObjectId = ObjectId::new([0x86; 32]);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x86,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEA),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine: IdempotentMachine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            2,
            &machine,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "write access requires exactly one mutated effect",
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert!(store.commits.lock().unwrap().is_empty());
    assert!(store.receipt.lock().unwrap().is_none());
}

#[test]
fn authenticated_read_only_object_rejects_machine_effect_before_commit() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
    let signing_key: SigningKey = dev_signing_key(0xCE);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id: ObjectId = ObjectId::new([0xA1; 32]);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0xA1,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEC),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]),
        &node_config,
        &protocol_config,
    );

    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &ReadObjectEffectMachine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "read access produced a mutation effect",
        }
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn authenticated_owned_modes_reject_immutable_object_before_transition() {
    for (mode, request_byte) in [(AccessMode::Write, 0xED_u8), (AccessMode::Consume, 0xEE_u8)] {
        let store: ScriptedDurableStore =
            ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
        let signing_key: SigningKey = dev_signing_key(0xCF);
        let object_id: ObjectId = ObjectId::new([request_byte; 32]);
        let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            object_id,
            Owner::Immutable,
            request_byte,
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry { object_ref, mode }]),
            &node_config,
            &protocol_config,
        );
        let machine: IdempotentMachine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let error: NodeCoreError =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &MemoryBlobStore::default(),
                &store,
                &durable_context(),
                &resolver("sunrise-test"),
                submission,
                2,
                &machine,
            )
            .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectOwnerKindUnsupported { object_id }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }
}

#[test]
fn authenticated_owned_write_checkpoint_regression_commits_nothing() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xF9);
    let signing_key: SigningKey = dev_signing_key(0xCD);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let object_domain: AtomicityDomainId = domain(0xF9);
    let object_id: ObjectId = ObjectId::new([0x87; 32]);
    let object_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(object_id, 1, Owner::Address(sender), 0x87),
        "sunrise-test",
        18,
        0x3A,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEF),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0xA7],
        calls: AtomicUsize::new(0),
    };

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &resolver("sunrise-test"),
            submission,
            17,
            &machine,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectCreatedCheckpointRegression {
            object_id,
            previous_created_checkpoint: 18,
            attempted_created_checkpoint: 17,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert_eq!(head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    assert!(
        store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap()
            .value()
            .is_none()
    );
}

#[test]
fn generic_durable_handler_rejects_object_effects_without_dispatch() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id: ObjectId = ObjectId::new([0xA1; 32]);

    let error: NodeCoreError = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xFD, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0xEB)),
        &UndeclaredObjectEffectMachine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::UndeclaredObjectEffect { object_id });
    assert!(store.commits.lock().unwrap().is_empty());
}

/// One machine implementation used only to inject a genuine, deterministic
/// TOCTOU race into a single-threaded owned-object Write test:
/// `transition()` runs strictly after `load_and_authorize_objects` has
/// captured its object-head snapshot and strictly before the outer
/// invocation commits. It commits a competing update, then returns its own
/// conflicting update effect against the stale verified input.
struct StaleHeadRaceMachine<'a> {
    store: &'a MemoryDurableStateStore,
    context: DurableOperationContext,
    racing_invocation: Mutex<Option<DurableInvocationTransaction>>,
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for StaleHeadRaceMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/stale-head-race".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let racing_invocation = self
            .racing_invocation
            .lock()
            .unwrap()
            .take()
            .expect("the racing invocation commits exactly once");
        assert_eq!(
            self.store
                .commit_invocation(&self.context, racing_invocation),
            DurableCommitOutcome::Committed
        );
        let [input]: &[ResolvedObject] = state.resolved_objects() else {
            panic!("expected one authenticated Write object");
        };
        assert_eq!(input.mode, AccessMode::Write);
        let mut new_object: Object = input.object.clone();
        new_object.version = new_object.version.checked_add(1).unwrap();
        new_object.data = vec![0x84];
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            vec![ObjectEffect::Mutated {
                previous_version: input.object.version,
                new_object,
            }],
            NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?,
        )
    }
}

#[test]
fn memory_store_stale_head_race_yields_object_conflict_without_consuming_nonce_then_retries() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF8);
    let signing_key = dev_signing_key(0xC8);
    let sender: Address = dev_sender_address(&signing_key);
    let context = durable_context();
    let resolver = resolver("sunrise-test");
    let object_domain = domain(0xF8);
    let object_id = ObjectId::new([0x82; 32]);

    let object_v1 = test_object(object_id, 1, Owner::Address(sender), 0x82);
    let (record_v1, digest_v1) = hashed_object_version(object_v1, "sunrise-test", 1);
    let owner_projection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap();
    let create_mutation = runtime::DurableObjectMutation::Create {
        version: record_v1,
        owner_projection: owner_projection.clone(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let create_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            create_mutation,
        )],
    )
    .unwrap();
    let create_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x24; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x25; 32]),
        vec![0x26],
    )
    .unwrap();
    let create_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        create_changes,
        create_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, create_invocation),
        DurableCommitOutcome::Committed
    );
    let head_v1 = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();

    let object_v2 = test_object(object_id, 2, Owner::Address(sender), 0x83);
    let (record_v2, digest_v2) = hashed_object_version(object_v2, "sunrise-test", 2);
    let racing_mutation = runtime::DurableObjectMutation::Update {
        version: record_v2,
        owner_projection,
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let racing_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(object_id, head_v1)],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            racing_mutation,
        )],
    )
    .unwrap();
    let racing_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x27; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x28; 32]),
        vec![0x29],
    )
    .unwrap();
    let racing_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        racing_changes,
        racing_receipt,
        None,
    )
    .unwrap();

    let racing_machine = StaleHeadRaceMachine {
        store: &store,
        context,
        racing_invocation: Mutex::new(Some(racing_invocation)),
        calls: AtomicUsize::new(0),
    };
    let stale_manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: digest_v1,
        },
        mode: AccessMode::Write,
    }]);
    let stale_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE6),
        &signing_key,
        Epoch::new(7),
        0,
        stale_manifest,
        &node_config,
        &protocol_config,
    );

    let race_error =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &resolver,
            stale_submission,
            2,
            &racing_machine,
        )
        .unwrap_err();
    assert_eq!(race_error, NodeCoreError::ObjectConflict { object_id });
    assert_eq!(racing_machine.calls.load(Ordering::SeqCst), 1);

    // The outer commit was rejected atomically, so the racing write's own
    // (state-free) invocation is the only thing that committed: the
    // sender-nonce key was never written and the same nonce is still
    // expected next.
    let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let nonce_after_conflict = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    assert!(nonce_after_conflict.value().is_none());

    let head_v2 = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert_eq!(head_v2.object_version(), DurableObjectVersion::new(2));

    let retry_manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 2,
            digest: digest_v2,
        },
        mode: AccessMode::Read,
    }]);
    let retry_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE7),
        &signing_key,
        Epoch::new(7),
        0,
        retry_manifest,
        &node_config,
        &protocol_config,
    );
    let retry_machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        retry_submission,
        &retry_machine,
    )
    .unwrap();
    assert_eq!(retry_machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolved.output().responses().len(), 1);

    let nonce_after_retry = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record = SenderNonceRecord::decode(nonce_after_retry.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn durable_idempotent_handler_builds_typed_sections_and_replays_receipt() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let input = event("sunrise-test", request(0x91));
    let resolver = resolver("sunrise-test");
    let first = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC1, 7),
        &config("sunrise-test"),
        &resolver,
        input.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(first.domain(), domain(0xC1));
    assert_eq!(first.output().outbound_messages().len(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let invocation = &commits[0];
    let state = invocation.state().unwrap();
    assert_eq!(state.domain(), domain(0xC1));
    assert_eq!(state.reads().len(), 1);
    assert_eq!(state.mutations().len(), 1);
    assert!(invocation.objects().is_empty());
    let receipt = invocation.receipt().clone();
    assert_eq!(
        NodeDedupRecord::decode(receipt.canonical_bytes())
            .unwrap()
            .responses()
            .len(),
        1
    );
    let outbox = invocation.outbox().unwrap();
    assert_eq!(outbox.messages().len(), 1);
    let outbound_event = NodeEvent::decode(outbox.messages()[0].canonical_payload()).unwrap();
    assert_eq!(
        outbox.messages()[0].payload_digest(),
        outbound_event.digest(&resolver).unwrap()
    );
    drop(commits);

    store.receipt.lock().unwrap().replace(receipt);
    let replay = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC1, 7),
        &config("sunrise-test"),
        &resolver,
        input.clone(),
        &machine,
    )
    .unwrap();
    assert_eq!(replay.output().responses(), first.output().responses());
    assert!(replay.output().outbound_messages().is_empty());
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 1);
    assert_eq!(store.commits.lock().unwrap().len(), 1);

    assert_eq!(
        handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC1, 7),
            &config("sunrise-test"),
            &resolver,
            event_value("sunrise-test", request(0x91), 10),
            &machine,
        ),
        Err(NodeCoreError::RequestIdReuse)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_idempotent_handler_conforms_against_memory_store() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let input = event("sunrise-test", request(0x93));
    let context = durable_context();
    let first = handle_resolved_durable_idempotent_event(
        &store,
        &context,
        &placement(0xC3, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        input.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_resolved_durable_idempotent_event(
        &store,
        &context,
        &placement(0xC3, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        input,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.output().responses(), replay.output().responses());
    assert!(replay.output().outbound_messages().is_empty());
    let persisted = store
        .get_versioned_durable(&context, domain(0xC3), b"state/idempotent")
        .unwrap();
    assert_eq!(persisted.revision(), StateRevision::new(1));
    assert_eq!(
        decode_canonical_frame(persisted.value().unwrap())
            .unwrap()
            .required_u64(1),
        Ok(1)
    );
}

struct ReadOnlyMachine;

impl TransactionalNodeStateMachine for ReadOnlyMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/read-only".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

#[test]
fn durable_idempotent_handler_asserts_read_only_state_and_hides_ambiguity() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Indeterminate(
        IndeterminateCommitReason::ConnectionLost,
    ));
    let result = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC2, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0x92)),
        &ReadOnlyMachine,
    );

    assert_eq!(
        result,
        Err(NodeCoreError::DurableCommitIndeterminate(
            IndeterminateCommitReason::ConnectionLost
        ))
    );
    let commits = store.commits.lock().unwrap();
    let state = commits[0].state().unwrap();
    assert_eq!(state.reads().len(), 1);
    assert!(state.mutations().is_empty());
    assert!(commits[0].outbox().is_none());
}

#[test]
fn durable_concurrent_receipt_publication_requests_reconciliation_retry() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(
        DurableCommitRejection::RequestAlreadyCommitted,
    ));
    let result = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC2, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0x93)),
        &ReadOnlyMachine,
    );

    assert_eq!(result, Err(NodeCoreError::StateConflict));
}

#[test]
fn idempotent_handler_commits_dedup_and_outbox_and_replays_response() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x6B));
    let resolver = resolver("sunrise-test");
    let first = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.responses(), replay.responses());
    assert_eq!(first.outbound_messages().len(), 1);
    assert!(replay.outbound_messages().is_empty());
    let persisted = runtime
        .state_store()
        .get(b"state/idempotent")
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_canonical_frame(&persisted).unwrap().required_u64(1),
        Ok(1)
    );

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let dedup = runtime
        .state_store()
        .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let outbox = runtime
        .state_store()
        .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let delivery = runtime
        .state_store()
        .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(
        NodeDedupRecord::decode(&dedup).unwrap().responses().len(),
        1
    );
    assert_eq!(
        NodeOutboxBatch::decode(&outbox).unwrap().messages().len(),
        1
    );
    assert_eq!(
        NodeOutboxDelivery::decode(&delivery).unwrap().next_index(),
        0
    );

    assert_eq!(
        handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver,
            event_value("sunrise-test", request(0x6B), 10),
            &machine,
        ),
        Err(NodeCoreError::RequestIdReuse)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn domain_idempotent_handler_scopes_state_receipt_and_outbox() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let first_domain = domain(0xB1);
    let second_domain = domain(0xB2);
    let event = event("sunrise-test", request(0x82));
    let resolver = resolver("sunrise-test");

    let first = handle_domain_idempotent_event(
        &runtime,
        first_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_domain_idempotent_event(
        &runtime,
        first_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    handle_domain_idempotent_event(
        &runtime,
        second_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 2);
    assert_eq!(first.responses(), replay.responses());
    assert!(replay.outbound_messages().is_empty());
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for active_domain in [first_domain, second_domain] {
        for key in [
            b"state/idempotent".to_vec(),
            layout.request_dedup_key(*event.request_id().as_bytes()),
            layout.outbox_batch_key(*event.request_id().as_bytes()),
            layout.outbox_delivery_key(*event.request_id().as_bytes()),
        ] {
            assert!(
                runtime
                    .state_store()
                    .get_versioned_in_domain(active_domain, &key)
                    .unwrap()
                    .value()
                    .is_some()
            );
            assert_eq!(runtime.state_store().get(&key).unwrap(), None);
        }
    }
}

#[test]
fn resolved_idempotent_handler_uses_committed_domain_and_returns_it() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let placement = placement(0xB4, 7);
    let event = event("sunrise-test", request(0x85));
    let resolver = resolver("sunrise-test");

    let first = handle_resolved_idempotent_event(
        &runtime,
        &placement,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_resolved_idempotent_event(
        &runtime,
        &placement,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.domain(), placement.domain());
    assert_eq!(replay.domain(), placement.domain());
    assert_eq!(first.output().responses(), replay.output().responses());
    assert_eq!(first.output().outbound_messages().len(), 1);
    assert!(replay.output().outbound_messages().is_empty());
    assert_eq!(replay.clone().into_output(), replay.output);

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    assert!(
        claim_next_outbox_message_in_domain(
            runtime.state_store(),
            first.domain(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x45; 32]).unwrap(),
            100,
            10,
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain(0xB5), b"state/idempotent")
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn resolved_handler_rejects_inactive_manifest_before_transition_or_read() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x86));
    let error = handle_resolved_idempotent_event(
        &runtime,
        &placement(0xB6, 8),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event,
        &machine,
    )
    .unwrap_err();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        error,
        NodeCoreError::ProtocolConfig(ProtocolConfigError::InactiveDomainPlacement {
            activation_epoch: Epoch::new(8),
            event_epoch: Epoch::new(7),
        })
    );
    assert_eq!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain(0xB6), b"state/idempotent")
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn outbox_lease_expiry_redelivers_and_matching_ack_advances_cursor() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x6D));
    handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &machine,
    )
    .unwrap();
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let first_lease = OutboxLeaseId::new([0x31; 32]).unwrap();
    let second_lease = OutboxLeaseId::new([0x32; 32]).unwrap();
    assert_eq!(
        OutboxLeaseId::new([0; 32]),
        Err(NodeCoreError::ZeroOutboxLeaseId)
    );
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            first_lease,
            100,
            0,
        ),
        Err(NodeCoreError::InvalidOutboxLeaseDuration(0))
    );

    let first = claim_next_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        first_lease,
        100,
        10,
    )
    .unwrap()
    .unwrap();
    assert_eq!(first.index(), 0);
    assert_eq!(first.expires_at_unix_millis(), 110);
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            second_lease,
            109,
            10,
        ),
        Err(NodeCoreError::OutboxLeaseActive {
            expires_at_unix_millis: 110,
        })
    );

    let redelivered = claim_next_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        second_lease,
        110,
        10,
    )
    .unwrap()
    .unwrap();
    assert_eq!(redelivered.index(), first.index());
    assert_eq!(redelivered.message(), first.message());
    assert_eq!(
        acknowledge_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            1,
            second_lease,
        ),
        Err(NodeCoreError::OutboxIndexMismatch)
    );
    assert_eq!(
        acknowledge_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            0,
            first_lease,
        ),
        Err(NodeCoreError::OutboxLeaseMismatch)
    );
    acknowledge_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        0,
        second_lease,
    )
    .unwrap();
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x33; 32]).unwrap(),
            121,
            10,
        )
        .unwrap(),
        None
    );

    let delivery = runtime
        .state_store()
        .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
    assert_eq!(delivery.next_index(), 1);
    assert_eq!(delivery.attempts(), 2);
    assert_eq!(delivery.lease(), None);
}

#[test]
fn domain_outbox_claim_and_ack_never_cross_domain_boundaries() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let first_domain = domain(0xC1);
    let second_domain = domain(0xC2);
    let event = event("sunrise-test", request(0x84));
    let config = config("sunrise-test");
    let resolver = resolver("sunrise-test");
    for active_domain in [first_domain, second_domain] {
        handle_domain_idempotent_event(
            &runtime,
            active_domain,
            &config,
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
    }
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let lease = OutboxLeaseId::new([0x41; 32]).unwrap();
    let claim = claim_next_outbox_message_in_domain(
        runtime.state_store(),
        first_domain,
        &layout,
        event.request_id(),
        lease,
        100,
        10,
    )
    .unwrap()
    .unwrap();
    acknowledge_outbox_message_in_domain(
        runtime.state_store(),
        first_domain,
        &layout,
        event.request_id(),
        claim.index(),
        lease,
    )
    .unwrap();

    assert_eq!(
        claim_next_outbox_message_in_domain(
            runtime.state_store(),
            first_domain,
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x42; 32]).unwrap(),
            111,
            10,
        )
        .unwrap(),
        None
    );
    let second_claim = claim_next_outbox_message_in_domain(
        runtime.state_store(),
        second_domain,
        &layout,
        event.request_id(),
        OutboxLeaseId::new([0x43; 32]).unwrap(),
        111,
        10,
    )
    .unwrap();
    assert!(second_claim.is_some());
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x44; 32]).unwrap(),
            111,
            10,
        ),
        Err(NodeCoreError::OutboxNotFound)
    );
}

#[test]
fn idempotent_conflict_does_not_publish_dedup_or_outbox_records() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let event = event("sunrise-test", request(0x6C));
    let error = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &TransactionalConflictMachine { runtime: &runtime },
    )
    .unwrap_err();
    assert_eq!(error, NodeCoreError::StateConflict);

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
}

struct InvalidAccessMachine {
    plan_mode: NodeStateAccessMode,
    update_key: &'static [u8],
}

impl TransactionalNodeStateMachine for InvalidAccessMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/a".to_vec(),
            self.plan_mode,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                self.update_key.to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn transactional_handler_rejects_undeclared_and_read_only_updates() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let undeclared = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x68)),
        &InvalidAccessMachine {
            plan_mode: NodeStateAccessMode::ReadWrite,
            update_key: b"state/b",
        },
    );
    assert_eq!(
        undeclared,
        Err(NodeCoreError::UndeclaredStateUpdate(b"state/b".to_vec()))
    );

    let read_only = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x69)),
        &InvalidAccessMachine {
            plan_mode: NodeStateAccessMode::ReadOnly,
            update_key: b"state/a",
        },
    );
    assert_eq!(
        read_only,
        Err(NodeCoreError::ReadOnlyStateUpdate(b"state/a".to_vec()))
    );
    assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
    assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
}

struct TransactionalConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
}

impl TransactionalNodeStateMachine for TransactionalConflictMachine<'_> {
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        MultiKeyMachine.access_plan(event)
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.runtime
            .state_store()
            .put(b"state/a".to_vec(), canonical(TEST_STATE_TYPE_ID, 99))?;
        MultiKeyMachine.transition(state, event)
    }
}

#[test]
fn transactional_conflict_applies_none_of_the_candidate_updates() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x6A)),
        &TransactionalConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    let a = runtime.state_store().get(b"state/a").unwrap().unwrap();
    assert_eq!(decode_canonical_frame(&a).unwrap().required_u64(1), Ok(99));
    assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
}

struct ReadDependencyConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
}

impl TransactionalNodeStateMachine for ReadDependencyConflictMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
            NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        assert_eq!(
            state
                .get(b"state/dependency")
                .and_then(VersionedStateValue::value),
            None
        );
        self.runtime.state_store().put(
            b"state/dependency".to_vec(),
            canonical(TEST_STATE_TYPE_ID, 99),
        )?;
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/result".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn transactional_handler_asserts_read_only_absence_before_commit() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x7B)),
        &ReadDependencyConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert!(
        runtime
            .state_store()
            .get(b"state/dependency")
            .unwrap()
            .is_some()
    );
    assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
}

#[test]
fn idempotent_handler_asserts_read_only_absence_before_commit() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let event = event("sunrise-test", request(0x7C));
    let error = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &ReadDependencyConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for key in [
        layout.request_dedup_key(*event.request_id().as_bytes()),
        layout.outbox_batch_key(*event.request_id().as_bytes()),
        layout.outbox_delivery_key(*event.request_id().as_bytes()),
    ] {
        assert_eq!(runtime.state_store().get(&key).unwrap(), None);
    }
}

struct DomainReadDependencyConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
    domain: AtomicityDomainId,
}

impl TransactionalNodeStateMachine for DomainReadDependencyConflictMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
            NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let dependency =
            state
                .get(b"state/dependency")
                .ok_or(NodeCoreError::PersistenceInvariant(
                    "dependency missing from snapshot",
                ))?;
        let competing = AtomicStateTransaction::new(
            self.domain,
            AtomicStateReadSet::new(vec![StateReadAssertion::new(
                b"state/dependency".to_vec(),
                dependency.revision(),
            )?])?,
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(
                b"state/dependency".to_vec(),
                StateMutation::Put(canonical(TEST_STATE_TYPE_ID, 99)),
            )?])?,
        )?;
        assert_eq!(
            self.runtime.state_store().commit_transaction(competing)?,
            AtomicStateWriteResult::Committed
        );
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/result".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn domain_idempotent_conflict_publishes_neither_result_receipt_nor_outbox() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let domain = domain(0xB3);
    let event = event("sunrise-test", request(0x83));
    let error = handle_domain_idempotent_event(
        &runtime,
        domain,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &DomainReadDependencyConflictMachine {
            runtime: &runtime,
            domain,
        },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain, b"state/dependency")
            .unwrap()
            .value()
            .is_some()
    );
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for key in [
        b"state/result".to_vec(),
        layout.request_dedup_key(*event.request_id().as_bytes()),
        layout.outbox_batch_key(*event.request_id().as_bytes()),
        layout.outbox_delivery_key(*event.request_id().as_bytes()),
    ] {
        assert_eq!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain, &key)
                .unwrap()
                .value(),
            None
        );
    }
}

#[test]
fn transactional_access_and_update_sets_are_bounded_and_unique() {
    let access = NodeStateAccess::new(b"state/a".to_vec(), NodeStateAccessMode::ReadWrite).unwrap();
    assert_eq!(
        NodeStateAccessPlan::new(vec![access.clone(), access]),
        Err(NodeCoreError::DuplicateStateAccessKey)
    );
    assert_eq!(
        NodeStateAccessPlan::new(Vec::new()),
        Err(NodeCoreError::EmptyStateAccessPlan)
    );

    let update = NodeStateUpdate::delete(b"state/a".to_vec()).unwrap();
    assert_eq!(
        TransactionalNodeTransition::new(vec![update.clone(), update], NodeOutput::default(),),
        Err(NodeCoreError::DuplicateStateUpdateKey)
    );
    assert_eq!(
        TransactionalNodeTransition::new(Vec::new(), NodeOutput::default()),
        Err(NodeCoreError::EmptyStateUpdates)
    );
    assert_eq!(
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            Vec::new(),
            NodeOutput::default(),
        ),
        Err(NodeCoreError::EmptyStateUpdates)
    );
    let effects: Vec<ObjectEffect> = (0..=MAX_AUTHENTICATED_OBJECT_READS)
        .map(|index: usize| {
            ObjectEffect::Created(test_object(
                ObjectId::new([u8::try_from(index).unwrap(); 32]),
                1,
                Owner::Immutable,
                u8::try_from(index).unwrap(),
            ))
        })
        .collect();
    assert_eq!(
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            effects,
            NodeOutput::default(),
        ),
        Err(NodeCoreError::TooManyObjectEffects {
            actual: MAX_AUTHENTICATED_OBJECT_READS + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        })
    );
}

#[test]
fn response_must_match_event_request() {
    struct WrongResponseMachine;

    impl NodeStateMachine for WrongResponseMachine {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let response = NodeResponse::new(request(0x77), NodeResponseStatus::Accepted, None)?;
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, 1),
                NodeOutput::new(vec![response], Vec::new())?,
            )
        }
    }

    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x78)),
        &WrongResponseMachine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ResponseRequestMismatch { .. }
    ));
    assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
}

#[test]
fn outbound_event_must_match_invocation_context() {
    struct CrossChainOutputMachine;

    impl NodeStateMachine for CrossChainOutputMachine {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let outbound = OutboundMessage::new(event("other-chain", request(0x79)));
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, 1),
                NodeOutput::new(Vec::new(), vec![outbound])?,
            )
        }
    }

    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x7A)),
        &CrossChainOutputMachine,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
    assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
}

// --- DR-0082 bounded Developer MVP query API -------------------------

#[test]
fn query_next_nonce_true_absence_returns_zero() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();

    let next_nonce = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF1),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        [0x11; 32],
    )
    .unwrap();

    assert_eq!(next_nonce, 0);
}

#[test]
fn query_next_nonce_returns_advanced_persisted_value() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x12; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    let record = SenderNonceRecord::new(sender, Epoch::new(7), 5);
    let transaction = AtomicStateTransaction::new(
        domain(0xF2),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(record.encode().unwrap())).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let next_nonce = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF2),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap();

    assert_eq!(next_nonce, 5);
}

#[test]
fn query_next_nonce_deleted_record_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x13; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    // A delete from true absence still installs a non-`INITIAL` revision
    // with no value: the exact "deleted while its epoch may be accepted"
    // corruption this query must fail closed on, distinct from true
    // absence (which is `INITIAL` with no value).
    let transaction = AtomicStateTransaction::new(
        domain(0xF3),
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
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let error = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF3),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_next_nonce_corrupt_record_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x14; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    let transaction = AtomicStateTransaction::new(
        domain(0xF4),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(vec![0xFF, 0x00, 0x01])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let error = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF4),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_object_true_absence() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x21; 32]);
    store.preload_object(object_id, DurableObjectHead::Absent, None);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x61), &chain_id, object_id).unwrap();

    assert_eq!(result, ObjectQueryResult::Absent { object_id });
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_retained_tombstone() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x22; 32]);
    let head = DurableObjectHead::Tombstoned {
        head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
        last_object_version: DurableObjectVersion::new(2).unwrap(),
    };
    store.preload_object(object_id, head, None);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x62), &chain_id, object_id).unwrap();

    assert_eq!(
        result,
        ObjectQueryResult::Tombstoned {
            object_id,
            head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
            last_object_version: DurableObjectVersion::new(2).unwrap(),
        }
    );
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_verified_current_inline() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x23; 32]);
    let owner = Owner::Address(Address::new([0x24; 32]));
    let (object_ref, _head) = preload_inline_object(&store, "sunrise-test", object_id, owner, 0x25);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x63), &chain_id, object_id).unwrap();

    match &result {
        ObjectQueryResult::CurrentInline {
            object_id: result_object_id,
            head_revision,
            object_version,
            digest,
            creating_chain_id,
            protocol_version,
            canonical_object_bytes,
        } => {
            assert_eq!(*result_object_id, object_id);
            assert_eq!(*head_revision, runtime::ObjectHeadRevision::FIRST);
            assert_eq!(*object_version, DurableObjectVersion::FIRST);
            assert_eq!(*digest, object_ref.digest);
            assert_eq!(creating_chain_id.as_str(), "sunrise-test");
            assert_eq!(*protocol_version, ProtocolVersion::new(3));
            let decoded = objects::decode_object(canonical_object_bytes).unwrap();
            assert_eq!(decoded.id, object_id);
            assert_eq!(decoded.version, 1);
        }
        other => panic!("expected verified current inline object, got {other:?}"),
    }
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_current_blob_reference_returns_metadata_without_fetching_body() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x26; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x27; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x28; 32]);
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
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::default(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x64), &chain_id, object_id).unwrap();

    assert_eq!(
        result,
        ObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            blob_digest,
        }
    );
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_wrong_chain_blob_reference_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x2C; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x2D; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x2E; 32]);
    // Provenance names a different chain than the trusted chain the
    // query is scoped to: this must fail closed before ever branching on
    // inline vs. blob payload, even though a blob body is never fetched.
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        digest,
        1,
        DurableObjectProvenance::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::default(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let error = query_object(&store, &context, domain(0x6D), &chain_id, object_id).unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectProvenanceMismatch { object_id: id } if id == object_id
    ));
}

#[test]
fn query_object_tampered_digest_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x29; 32]);
    let owner = Owner::Address(Address::new([0x2A; 32]));
    let object = test_object(object_id, 1, owner.clone(), 0x2B);
    let (record, _correct_digest) = hashed_object_version(object, "sunrise-test", 1);
    let inline = record.payload().inline().unwrap().clone();
    // A digest that disagrees with the actual canonical body, while head
    // and version still agree with each other, so only the independent
    // recomputation against the body itself can catch the tamper.
    let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
    let tampered_record = DurableObjectVersionRecord::from_inline_canonical_bytes(
        inline.canonical_bytes().to_vec(),
        tampered_digest,
        record.provenance().clone(),
        record.created_checkpoint(),
    )
    .unwrap();
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: tampered_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(tampered_record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let error = query_object(&store, &context, domain(0x65), &chain_id, object_id).unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyDigestMismatch { object_id: id } if id == object_id
    ));
}

#[test]
fn query_receipt_true_absence() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x31);

    let result = query_request_receipt(&store, &context, domain(0x71), req).unwrap();

    assert_eq!(result, ReceiptQueryResult::Absent { request_id: req });
    assert_eq!(result.request_id(), req);
}

#[test]
fn query_receipt_present_is_independently_reverified() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x32);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
    let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
    let dedup = NodeDedupRecord::new(req, event_digest, vec![response]).unwrap();
    let canonical_bytes = dedup.encode().unwrap();
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let receipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, canonical_bytes.clone())
            .unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let result = query_request_receipt(&store, &context, domain(0x72), req).unwrap();

    match &result {
        ReceiptQueryResult::Present {
            request_id: result_request_id,
            event_digest: got_digest,
            record,
        } => {
            assert_eq!(*result_request_id, req);
            assert_eq!(*got_digest, event_digest);
            assert_eq!(record.encode().unwrap(), canonical_bytes);
        }
        other => panic!("expected present receipt, got {other:?}"),
    }
    assert_eq!(result.request_id(), req);
}

#[test]
fn query_receipt_corrupt_bytes_fail_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x34);
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x35; 32]);
    let receipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, vec![0xEE, 0x00]).unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let error = query_request_receipt(&store, &context, domain(0x73), req).unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_receipt_outer_digest_mismatch_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x36);
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x37; 32]);
    let outer_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x38; 32]);
    let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
    let dedup = NodeDedupRecord::new(req, record_digest, vec![response]).unwrap();
    let canonical_bytes = dedup.encode().unwrap();
    let receipt =
        DurableRequestReceipt::new(durable_request_id, outer_digest, canonical_bytes).unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let error = query_request_receipt(&store, &context, domain(0x74), req).unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

// ── S3 fee lifecycle ─────────────────────────────────────────────────

fn fee_asset_id() -> standard_assets::AssetId {
    standard_assets::AssetId::new([0xF3; 32])
}

fn fee_gas_schedule() -> fees::GasSchedule {
    fees::GasSchedule {
        base_fee: 1,
        execution_price: 1,
        read_price: 0,
        write_price: 0,
        storage_price: 0,
        system_module_price: 0,
    }
}

fn fee_asset_registry() -> fees::FeeAssetRegistry {
    let mut registry = fees::FeeAssetRegistry::new();
    registry
        .add_asset(fees::FeeAsset {
            asset_id: fee_asset_id(),
            fee_units_per_asset_unit: 1,
            enabled: true,
        })
        .unwrap();
    registry
}

/// Committed protocol configuration with a non-zero fee schedule and one
/// enabled fee asset, otherwise identical to [`active_protocol_config`].
fn fee_active_protocol_config(byte: u8) -> ProtocolConfig {
    let mut protocol_config = active_protocol_config(byte);
    protocol_config.gas_schedule = fee_gas_schedule();
    protocol_config.fee_assets = fee_asset_registry();
    protocol_config
}

/// Deterministically appends a fixed debit/credit tag to each body and
/// records the exact settled amount it was asked to charge, so tests can
/// assert both the merged bytes and the amount without needing real
/// balance semantics.
#[derive(Debug)]
struct RecordingFeeComposer {
    charged_amount: Mutex<Option<u64>>,
}

impl RecordingFeeComposer {
    fn new() -> Self {
        Self {
            charged_amount: Mutex::new(None),
        }
    }
}

impl FeeEffectComposer for RecordingFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        *self.charged_amount.lock().unwrap() = Some(request.amount.get());
        let mut payer_body = request.payer_body.to_vec();
        payer_body.push(0xF0);
        let mut treasury_body = request.treasury_body.to_vec();
        treasury_body.push(0xF1);
        Ok(FeeChargeBodies {
            payer_body,
            treasury_body,
        })
    }
}

/// Returns both bodies unchanged, deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`] whenever a non-zero amount is
/// charged.
#[derive(Debug)]
struct EchoFeeComposer;

impl FeeEffectComposer for EchoFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        Ok(FeeChargeBodies {
            payer_body: request.payer_body.to_vec(),
            treasury_body: request.treasury_body.to_vec(),
        })
    }
}

/// Changes only the payer body, leaving the treasury body byte-identical
/// to its effective input — deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`]: a non-zero charge must move
/// value on both sides, not just debit the payer.
#[derive(Debug)]
struct PayerOnlyChangeFeeComposer;

impl FeeEffectComposer for PayerOnlyChangeFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let mut payer_body = request.payer_body.to_vec();
        payer_body.push(0xF2);
        Ok(FeeChargeBodies {
            payer_body,
            treasury_body: request.treasury_body.to_vec(),
        })
    }
}

/// Changes only the treasury body, leaving the payer body byte-identical
/// to its effective input — deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`]: a non-zero charge must move
/// value on both sides, not just credit the treasury.
#[derive(Debug)]
struct TreasuryOnlyChangeFeeComposer;

impl FeeEffectComposer for TreasuryOnlyChangeFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let mut treasury_body = request.treasury_body.to_vec();
        treasury_body.push(0xF3);
        Ok(FeeChargeBodies {
            payer_body: request.payer_body.to_vec(),
            treasury_body,
        })
    }
}

/// Always rejects with a fixed, caller-chosen error.
#[derive(Debug)]
struct RejectingFeeComposer(FeeCompositionError);

impl FeeEffectComposer for RejectingFeeComposer {
    fn compose_fee_charge(
        &self,
        _request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        Err(self.0.clone())
    }
}

#[test]
fn preinstalled_wasm_fee_charges_actual_gas_used_not_gas_limit() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xD0);
    let signing_key: SigningKey = dev_signing_key(0xD0);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD0);
    let module_id = ModuleId::new([0xD0; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0xD1; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xD1);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xD2,
    );
    let treasury_owner: Address = Address::new([0xD3; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xD4; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xD4);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xD5,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xD6),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let payload = resolved.output().responses()[0].payload().unwrap();
    let effects = execution::decode_execution_effects(payload).unwrap();
    assert!(effects.gas_used < 1_000_000);

    let charged = composer.charged_amount.lock().unwrap().unwrap();
    assert_eq!(charged, 1 + effects.gas_used);

    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0x10, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn preinstalled_wasm_fee_merges_into_application_mutated_payer_object() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xD7);
    let signing_key: SigningKey = dev_signing_key(0xD7);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD7);
    let module_id = ModuleId::new([0xD7; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0xD8; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xD8);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xD9,
    );
    let treasury_owner: Address = Address::new([0xDA; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xDB; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xDB);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xDC,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xDD),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );

    // Exactly one Mutated effect for the payer: version bumps by one,
    // not two, even though both the application and the fee charge
    // touched it (requirement 6).
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(2));
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0xCA, 0xFE, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn preinstalled_wasm_trapped_call_still_charges_fee_and_credits_treasury() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xDE);
    let signing_key: SigningKey = dev_signing_key(0xDE);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xDE);
    let module_id = ModuleId::new([0xDE; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_trap_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0xDF; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xDF);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xE1,
    );
    let treasury_owner: Address = Address::new([0xE2; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xE3; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xE3);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xE4,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xE5),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payload = resolved.output().responses()[0].payload().unwrap();
    let effects = execution::decode_execution_effects(payload).unwrap();
    assert!(effects.object_effects.is_empty());
    assert_eq!(effects.gas_used, 1_000_000);

    let charged = composer.charged_amount.lock().unwrap().unwrap();
    assert_eq!(charged, 1 + 1_000_000);

    // The application never ran (trap), so the committed payer body is
    // exactly its loaded data with only the fee tag appended.
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0x10, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn preinstalled_wasm_trap_with_zero_schedule_and_fee_composition_present_commits_no_mutation() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFB);
    let signing_key: SigningKey = dev_signing_key(0xFB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFB);
    let module_id = ModuleId::new([0xFB; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_trap_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let payer_id: ObjectId = ObjectId::new([0xFC; 32]);
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(payer_id, 1, Owner::Address(sender), 0xFC),
        "sunrise-test",
        9,
        0xFD,
    );
    let treasury_id: ObjectId = ObjectId::new([0xFE; 32]);

    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xFF),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(1));
}

#[test]
fn preinstalled_wasm_fee_treasury_is_hidden_from_engine_object_count() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x60);
    let signing_key: SigningKey = dev_signing_key(0x60);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0x60);
    let module_id = ModuleId::new([0x60; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_two_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0x61; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0x61);
    payer_object.data = vec![0x00, 0x00];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0x62,
    );
    let treasury_owner: Address = Address::new([0x63; 32]);
    let treasury_id: ObjectId = ObjectId::new([0x64; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0x64);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0x65,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x66),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    // The module attempts to write declared indices 0 and 1, but with
    // the treasury excluded from engine inputs the engine holds exactly
    // one object; the out-of-range write to index 1 silently no-ops (see
    // `execution::wasm_engine::write_object_data`), so only the payer
    // carries the application's write, fee-tagged on top.
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0xCA, 0xFE, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn generic_read_only_entrypoint_rejects_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE6);
    let signing_key: SigningKey = dev_signing_key(0xE6);
    let sender: Address = dev_sender_address(&signing_key);
    let mut tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: sample_object_ref(0xE7),
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xE7),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: Vec::new(),
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn generic_owned_effects_entrypoint_rejects_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE8);
    let signing_key: SigningKey = dev_signing_key(0xE8);
    let sender: Address = dev_sender_address(&signing_key);
    let mut tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: sample_object_ref(0xE9),
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xEA),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: Vec::new(),
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        9,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn preinstalled_wasm_nonzero_schedule_requires_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xEB);
    let signing_key: SigningKey = dev_signing_key(0xEB);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xEB; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xEC; 32]),
        Owner::Address(sender),
        0xEC,
    );
    let treasury_owner = Address::new([0xED; 32]);
    let treasury_id = ObjectId::new([0xEE; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xEE,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xEF),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentRequired);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A declared `fee_payment` must never be silently ignored just because
/// the committed schedule's worst-case fee at `gas_limit` happens to be
/// zero: node-core has no way to charge it and must fail closed instead
/// of admitting the transaction as though it were fee-free.
#[test]
fn preinstalled_wasm_fee_payment_declared_against_zero_worst_case_fee_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    // Deliberately not `fee_active_protocol_config`: the default,
    // genesis-derived `gas_schedule` prices every unit at zero, so the
    // committed worst-case fee at any `gas_limit` is zero.
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x64);
    let signing_key: SigningKey = dev_signing_key(0x64);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x64; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x65; 32]),
        Owner::Address(sender),
        0x65,
    );
    let treasury_id = ObjectId::new([0x66; 32]);
    // No treasury access is declared: only the `fee_payment` itself is
    // misdeclared here.
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref.clone(),
        mode: AccessMode::Write,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x67),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentNotRequired);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// No fee-charging composition is wired for this deployment (`None`
/// passed to the handler), yet the transaction declares a
/// `fee_payment`. It must never be silently ignored — that would admit
/// the transaction as fee-free while dropping the sender's declared
/// payment.
#[test]
fn preinstalled_wasm_fee_payment_declared_with_no_fee_composition_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x68);
    let signing_key: SigningKey = dev_signing_key(0x68);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x68; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x69; 32]),
        Owner::Address(sender),
        0x69,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref.clone(),
        mode: AccessMode::Write,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x6A),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// No fee-charging composition is wired, and the transaction declares no
/// `fee_payment` either, but the committed schedule's worst-case fee at
/// `gas_limit` is non-zero. Historical fee-free behavior must not
/// silently apply here: with a committed non-zero price and nothing to
/// charge it against, the deployment is misconfigured and must fail
/// closed rather than let the transaction execute for free.
#[test]
fn preinstalled_wasm_nonzero_schedule_with_no_fee_composition_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x6B);
    let signing_key: SigningKey = dev_signing_key(0x6B);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x6B; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x6C; 32]),
        Owner::Address(sender),
        0x6C,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x6D),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionUnavailable);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A committed schedule that prices a category this path never measures
/// (`read_price`, `write_price`, `storage_price`, or
/// `system_module_price`) must fail closed before the engine ever runs,
/// rather than let `fees::calculate_fee` silently multiply that price by
/// the always-zero usage this path reports and drop it from the total.
#[test]
fn preinstalled_wasm_schedule_pricing_an_unmeasured_category_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x91);
    protocol_config.gas_schedule.storage_price = 1;
    let signing_key: SigningKey = dev_signing_key(0x91);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x91; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x92; 32]),
        Owner::Address(sender),
        0x92,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x93),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::UnsupportedGasScheduleShape(GasScheduleShapeFault::UnmeasuredCategoryPriced)
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A committed schedule with a zero `base_fee` but a non-zero
/// `execution_price` lets a legitimate zero-`gas_used` success settle a
/// zero fee even though worst-case admission at `gas_limit` already
/// required a treasury `Write`. This must fail closed before the engine
/// ever runs rather than depend on whichever `gas_used` a specific
/// invocation happens to report.
#[test]
fn preinstalled_wasm_zero_base_fee_with_nonzero_execution_price_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x94);
    protocol_config.gas_schedule.base_fee = 0;
    let signing_key: SigningKey = dev_signing_key(0x94);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x94; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x95; 32]),
        Owner::Address(sender),
        0x95,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x96),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::UnsupportedGasScheduleShape(
            GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice
        )
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_not_declared_write_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x6C);
    let signing_key: SigningKey = dev_signing_key(0x6C);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x6C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x6D; 32]),
        Owner::Address(sender),
        0x6D,
    );
    let treasury_owner = Address::new([0x6E; 32]);
    let treasury_id = ObjectId::new([0x6F; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x6F,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        // Not declared anywhere in the manifest.
        fee_object: sample_object_ref(0x70),
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x71),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectNotDeclaredWrite);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_not_owned_by_sender_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x72);
    let signing_key: SigningKey = dev_signing_key(0x72);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = Address::new([0x73; 32]);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x72; 32]);
    let destination_byte: u8 = 0x22;
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [destination_byte.wrapping_add(1); 32],
        ),
        u32::from(destination_byte),
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"fee-owner-test".to_vec(), vec![policy]).unwrap();
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_two_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        envelope,
    );
    protocol_config.system_modules = registry;

    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (source_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x74; 32]),
        Owner::Address(sender),
        0x21,
    );
    let (destination_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x75; 32]),
        Owner::Address(recipient),
        destination_byte,
    );
    let treasury_owner = Address::new([0x76; 32]);
    let treasury_id = ObjectId::new([0x77; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x77,
    );

    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: source_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: destination_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        // Authorized for cross-owner Write by the committed policy, but
        // never owned by the sender: the fee lifecycle requires more
        // than mere authorization.
        fee_object: destination_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x78),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectNotOwnedBySender);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_equal_to_treasury_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x79);
    let signing_key: SigningKey = dev_signing_key(0x79);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x79; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x7A; 32]),
        Owner::Address(sender),
        0x7A,
    );
    let treasury_owner = Address::new([0x7B; 32]);
    let treasury_id = ObjectId::new([0x7C; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x7C,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref.clone(),
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: treasury_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x7D),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectIsTreasury);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_treasury_declared_at_non_final_index_is_misdeclared() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x7E);
    let signing_key: SigningKey = dev_signing_key(0x7E);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7E; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    // A sender-owned stand-in for the treasury id, so object loading
    // succeeds under the ordinary same-owner rule: this test isolates
    // manifest-structure validation from ownership authorization.
    let treasury_id = ObjectId::new([0x7F; 32]);
    let (treasury_stand_in_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(sender),
        0x7F,
    );
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x80; 32]),
        Owner::Address(sender),
        0x80,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: treasury_stand_in_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x81),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeTreasuryAccessMisdeclared);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_sender_substituted_object_as_treasury_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x82);
    let signing_key: SigningKey = dev_signing_key(0x82);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x82; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x83; 32]),
        Owner::Address(sender),
        0x83,
    );
    // Sender's own object, declared final -- an attempt to redirect the
    // fee credit to an address the sender controls. The real trusted
    // treasury id (below) never appears in this manifest at all.
    let (substituted_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x84; 32]),
        Owner::Address(sender),
        0x84,
    );
    let treasury_id = ObjectId::new([0x85; 32]);
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: substituted_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x86),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeTreasuryAccessMisdeclared);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_max_fee_below_worst_case_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x87);
    let signing_key: SigningKey = dev_signing_key(0x87);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x87; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x88; 32]),
        Owner::Address(sender),
        0x88,
    );
    let treasury_owner = Address::new([0x89; 32]);
    let treasury_id = ObjectId::new([0x8A; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x8A,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    // gas_limit is 1_000_000 (see `preinstalled_transaction`), so the
    // worst-case fee is 1 + 1_000_000 = 1_000_001; `max_fee` of 1 can
    // never cover it.
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x8B),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::FeePaymentRejected(fees::FeeError::MaxFeeExceeded { .. })
    ));
    // The engine never ran: no commit was ever attempted.
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_composer_insufficient_balance_rejects_whole_request() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x8C);
    let signing_key: SigningKey = dev_signing_key(0x8C);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x8C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x8D; 32]),
        Owner::Address(sender),
        0x8D,
    );
    let treasury_owner = Address::new([0x8E; 32]);
    let treasury_id = ObjectId::new([0x8F; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x8F,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x90),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RejectingFeeComposer(FeeCompositionError::InsufficientBalance);
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::FeeCompositionFailed(FeeCompositionError::InsufficientBalance)
    );
    // No commit at all: no nonce burn, no receipt, no object mutation.
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_composer_no_op_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x91);
    let signing_key: SigningKey = dev_signing_key(0x91);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x91; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x92; 32]),
        Owner::Address(sender),
        0x92,
    );
    let treasury_owner = Address::new([0x93; 32]);
    let treasury_id = ObjectId::new([0x94; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x94,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x95),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A composer that debits the payer but leaves the treasury body
/// byte-identical is not a valid non-zero settlement: value must move on
/// both sides, never just off the payer.
#[test]
fn preinstalled_wasm_fee_composer_payer_only_change_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xA0);
    let signing_key: SigningKey = dev_signing_key(0xA0);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xA0; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xA1; 32]),
        Owner::Address(sender),
        0xA1,
    );
    let treasury_owner = Address::new([0xA2; 32]);
    let treasury_id = ObjectId::new([0xA3; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xA3,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xA4),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = PayerOnlyChangeFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A composer that credits the treasury but leaves the payer body
/// byte-identical is not a valid non-zero settlement: value must move on
/// both sides, never just onto the treasury.
#[test]
fn preinstalled_wasm_fee_composer_treasury_only_change_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xA5);
    let signing_key: SigningKey = dev_signing_key(0xA5);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xA5; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xA6; 32]),
        Owner::Address(sender),
        0xA6,
    );
    let treasury_owner = Address::new([0xA7; 32]);
    let treasury_id = ObjectId::new([0xA8; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xA8,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xA9),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = TreasuryOnlyChangeFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// Owned fixture state for the `charge_fee` adversarial tests below.
/// `charge_fee` never reads `self.transaction`, `self.resolver`,
/// `self.catalog`, `self.engine`, or `self.fee_policy`, so their exact
/// contents are immaterial; only `payer`, `treasury`, and `fee_payment`
/// matter to the assertions.
fn charge_fee_test_state() -> (
    Transaction,
    HashSuiteResolver,
    PreinstalledModuleCatalog,
    WasmExecutionEngine,
    CommittedFeePolicy,
    Object,
    Object,
    fees::FeePayment,
) {
    let signing_key = dev_signing_key(0xB0);
    let sender = dev_sender_address(&signing_key);
    let resolver = resolver("sunrise-test");
    let catalog = PreinstalledModuleCatalog::new(Vec::new()).unwrap();
    let engine = WasmExecutionEngine;
    let fee_policy = CommittedFeePolicy {
        gas_schedule: fee_gas_schedule(),
        fee_assets: fee_asset_registry(),
    };
    let payer = test_object(ObjectId::new([0xB1; 32]), 1, Owner::Address(sender), 0xB1);
    let treasury_owner = Address::new([0xB2; 32]);
    let treasury = test_object(
        ObjectId::new([0xB3; 32]),
        1,
        Owner::Address(treasury_owner),
        0xB3,
    );
    let fee_object_ref = ObjectRef {
        id: payer.id,
        version: payer.version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB4; 32]),
    };
    let fee_payment = fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: fee_object_ref.clone(),
    };
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: fee_object_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: ObjectRef {
                id: treasury.id,
                version: treasury.version,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB5; 32]),
            },
            mode: AccessMode::Write,
        },
    ]);
    let module_ref = ObjectRef {
        id: ObjectId::new([0xB6; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB7; 32]),
    };
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    (
        tx,
        resolver,
        catalog,
        engine,
        fee_policy,
        payer,
        treasury,
        fee_payment,
    )
}

/// `charge_fee` finds at most one application effect naming the fee
/// object; two effects for the same id must be rejected as a duplicate,
/// never silently coalesced into one merged mutation. This scenario is
/// unreachable through the real WASM engine (the fee object is always a
/// single declared `Write` access, so the engine can produce at most one
/// effect for it), so `charge_fee` is exercised directly.
#[test]
fn preinstalled_wasm_charge_fee_rejects_duplicate_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };
    let mut payer_next = payer.clone();
    payer_next.version = payer.version + 1;
    payer_next.data = vec![0x01];
    let duplicate_effect = ObjectEffect::Mutated {
        previous_version: payer.version,
        new_object: payer_next,
    };

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![duplicate_effect.clone(), duplicate_effect],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::DuplicateObjectEffect {
            object_id: payer.id
        }
    );
}

/// A `Created` application effect for the fee object id is exactly what
/// `translate_authenticated_object_effects` would reject for a declared
/// `Write` access; `charge_fee` must reject it too rather than treating
/// it as "no existing effect" and silently overwriting it with a fresh
/// mutation.
#[test]
fn preinstalled_wasm_charge_fee_rejects_created_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };
    let created = test_object(payer.id, 1, payer.owner.clone(), 0xB9);

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![ObjectEffect::Created(created)],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectCreationUnsupported {
            object_id: payer.id
        }
    );
}

/// A `Deleted` application effect for the fee object id disagrees with
/// its required `Write` access exactly like
/// `translate_authenticated_object_effects` would reject it;
/// `charge_fee` must reject it too instead of masking it by filtering
/// every same-id effect out during merge and inserting a fresh mutation.
#[test]
fn preinstalled_wasm_charge_fee_rejects_deleted_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![ObjectEffect::Deleted {
                id: payer.id,
                version: payer.version,
            }],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id: payer.id,
            reason: "fee object write access requires exactly one mutated effect",
        }
    );
}

#[test]
fn preinstalled_wasm_fee_paying_exact_replay_does_not_recharge() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xF4);
    let signing_key: SigningKey = dev_signing_key(0xF4);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xF4);
    let module_id = ModuleId::new([0xF4; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0xF5; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xF5);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xF6,
    );
    let treasury_owner: Address = Address::new([0xF7; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xF8; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xF8);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xF9,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xFA),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

    let first =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            Some(fee_composition),
        )
        .unwrap();

    // An empty catalog and no fee composition at all on replay prove
    // that the persisted receipt short-circuits before module
    // resolution, fee admission, or execution -- the fee is not
    // reapplied.
    let empty_catalog: PreinstalledModuleCatalog =
        PreinstalledModuleCatalog::new(Vec::new()).unwrap();
    let replay =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &empty_catalog,
            &engine,
            replay_submission,
            999,
            None,
        )
        .unwrap();

    assert_eq!(first, replay);
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(2));
    let treasury_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, treasury_id)
        .unwrap();
    assert_eq!(treasury_head.object_version(), DurableObjectVersion::new(2));
}
