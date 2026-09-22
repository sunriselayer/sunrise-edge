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

/// DR-0131 criterion 7: the `SubmitTransaction` event family -- the one
/// shared external admission boundary for the read-only, owned-mutations,
/// and preinstalled-WASM entrypoints alike -- rejects an externally
/// supplied request id inside the reserved fast-path synthetic namespace,
/// before any inner-transaction authentication or storage work.
#[test]
fn authenticate_submit_transaction_event_rejects_reserved_request_id() {
    let config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xD9);
    let tag: [u8; 8] = local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG;
    let mut reserved_id: [u8; 32] = [0u8; 32];
    reserved_id[..tag.len()].copy_from_slice(&tag);

    let error = authenticate_submit_transaction_event(
        submit_event("sunrise-test", RequestId::new(reserved_id).unwrap()),
        &config,
        &protocol_config,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::PersistenceInvariant("request id reserved for fast-path synthetic receipts")
    ));
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
    // Sender nonce, committed epoch, fast-path nonce lock, then the machine's
    // one application state key.
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 4);
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

/// DR-0131: the established object-read-only `SubmitTransaction` entrypoint
/// still advances a sender nonce, so it must honor a fast-path prepare's
/// sender/epoch nonce lock even though it never mutates an object.
#[test]
fn authenticated_read_only_submit_honors_fastpath_nonce_lock() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE0);
    let signing_key: SigningKey = dev_signing_key(0x90);
    let sender: [u8; 32] = *dev_sender_address(&signing_key).as_bytes();
    let epoch: Epoch = Epoch::new(7);
    let chain: ChainId = ChainId::new("sunrise-test").unwrap();
    let lock_key: Vec<u8> =
        local_instance_state::fastpath_nonce_lock_key(&chain, &sender, epoch).unwrap();
    let lock: local_instance_state::FastPathNonceLockRecord =
        local_instance_state::FastPathNonceLockRecord {
            request_id: [0x33; 32],
            sender,
            epoch,
            nonce: 0,
        };
    store.preload(
        lock_key,
        StateRevision::INITIAL.checked_next().unwrap(),
        local_instance_state::encode_fastpath_nonce_lock_record(&lock).unwrap(),
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission(
        "sunrise-test",
        request(0xD9),
        &signing_key,
        epoch,
        0,
        &node_config,
        &protocol_config,
    );
    let machine: IdempotentMachine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
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
        NodeCoreError::PersistenceInvariant("sender nonce locked by a pending fast path")
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// DR-0131 criterion 4: the established object-read-only `SubmitTransaction`
/// entrypoint rejects a request bound to a non-current epoch before any
/// lock, machine execution, or mutation -- proven the same way as the
/// fast-path nonce-lock rejection above: zero machine calls and an empty
/// commit log (so no nonce advance and no state mutation survive either).
#[test]
fn authenticated_read_only_submit_rejects_a_wrong_current_epoch() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE1);
    let signing_key: SigningKey = dev_signing_key(0x91);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission(
        "sunrise-test",
        request(0xDA),
        &signing_key,
        Epoch::new(7),
        0,
        &node_config,
        &protocol_config,
    );
    let machine: IdempotentMachine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    // Overrides the store's own default (Epoch::new(7)) installed by
    // `ScriptedDurableStore::new`, simulating a Slice-2 transition this DR
    // does not implement.
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(8));

    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::EpochMismatch { expected, actual }
            if expected == Epoch::new(8) && actual == Epoch::new(7)
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

fn sender_nonce_key_for(chain: &str, sender: [u8; 32], epoch: Epoch) -> Vec<u8> {
    PersistenceLayout::new(ChainId::new(chain).unwrap(), ProtocolVersion::new(3))
        .sender_nonce_key(sender, epoch)
}

#[test]
fn sender_nonce_sequential_submissions_advance_persisted_next_nonce() {
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(domain(0xE1));
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
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(domain(0xEE));
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
        if epoch == Epoch::new(8) {
            // Model the committed lifecycle transition before submitting in
            // the new epoch; processing two independently "current" epochs
            // without advancing the singleton is no longer a valid fixture.
            commit_fastpath_epoch_record(
                &store,
                &context,
                domain(0xEE),
                "sunrise-test",
                Epoch::new(8),
            );
        }
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
    let store = Arc::new(memory_store_with_fastpath_epoch(domain(0xEF)));
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
    let store = Arc::new(memory_store_with_fastpath_epoch(domain(0xF0)));
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
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(domain(0xE3));
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
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(domain(0xE9));
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
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(domain(0xEA));
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
            maximum: MAX_ATOMIC_STATE_WRITES - RESERVED_FASTPATH_FENCE_READS,
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
