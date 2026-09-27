//! Deterministic public DEVELOPMENT fixture for the workerd SQLite-backed
//! Durable Object wasm-host test.
//!
//! Builds one real four-validator FastVote genesis (no PostgreSQL, four
//! independent in-memory stores), then drives a real sequence of paid
//! executions -- a self-transfer of the genesis fee coin, a freshly
//! published user package's publish and instantiate (whose `init` call
//! creates its own Definition/TreasuryCap, exactly like the top-level
//! create-asset verb), the full public Standard Asset verb set
//! (mint/split/merge/transfer/burn), and a genuinely charged Wasmi trap --
//! through `node_core::fast_path::prepare` (three of four
//! validators only) and `apply_with_recovery` (all four, including the
//! fourth validator that never itself prepares). Prints every canonical
//! wire artifact as JSON on stdout.
#![allow(dead_code)]

#[path = "../tests/support/genesis_fixture.rs"]
mod genesis_fixture;

use abi::AccessManifest;
use abi::package_types::{PackageOrigin, ScopedTypeTag, verify_scoped_type_id};
use canonical_encoding::encode_digest32;
use consensus::{ConsensusSigner, FastPathCertifier, FastVote, encode_fast_certificate};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    self, InstanceRecord, LocalExecutionPolicy, encode_instance_record,
};
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidIntent, ReservationAccessKind,
    decode_paid_execution_result,
};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationContext, UnverifiedDependencyRef,
};
use execution::{
    GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION, LocalWasmExecutionEngine, ObjectEffect,
};
use fees::Amount;
use genesis_fixture::FastVoteGenesisFixture;
use hashing::HashSuiteResolver;
use node_core::fast_path::{self, FastPathEd25519Verifier, FastPathError};
use node_core::local_execution::query_local_instance;
use node_core::paid_execution::PaidExecutionAdmissionError;
use node_core::paid_execution::authenticate_paid_execution;
use node_core::publication::{encode_publication_query_result, query_publication_with_history};
use node_core::{
    GenesisInstallOutcome, NodeCoreError, ObjectQueryResult, RequestId, decode_genesis_manifest,
    genesis_manifest_commitment, install_genesis, query_object, query_request_receipt,
    query_sender_next_nonce,
};
use node_wire::{
    FastVoteApplyRequest, HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult,
    HttpObjectQueryResult, http_receipt_query_result,
};
use objects::{Address, Object, ObjectId, ObjectRef};
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, TransactionAuthProfile,
    resolve_transaction_auth_profile,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, SignatureSchemeId, ValidatorId};
use public_standard_asset::{
    INITIALIZER, asset_type_argument, coin_type_tag, definition_type_tag, mint_arguments,
    no_arguments, split_arguments, transfer_arguments, treasury_cap_type_tag,
};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED;
use validator_set::{ValidatorInfo, ValidatorSet};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// Trusted per-validator adapter configuration, laid out exactly per
/// `adapters/cloudflare-workers/rust/src/config.rs`'s
/// `decode_trusted_adapter_config`: format_version:u16, hash_suite_id:u16,
/// chain_id_len:u16+chain_id, protocol_version:u32, epoch:u64, domain[32],
/// validator_id[32], validator_signing_secret[32], writer_fence:u64,
/// genesis_authority_public_key[32], digest_len:u16+digest_frame,
/// created_checkpoint:u64, operation_timeout_millis:u64,
/// fee_policy_len:u16+fee_policy_frame.
#[allow(clippy::too_many_arguments)]
fn trusted_adapter_config_bytes(
    fixture: &FastVoteGenesisFixture,
    validator_id: ValidatorId,
    validator_secret: [u8; 32],
    genesis_authority_public_key: [u8; 32],
    genesis_manifest_digest_frame: &[u8],
    fee_policy_frame: &[u8],
) -> Vec<u8> {
    let chain_id_bytes: Vec<u8> = fixture.chain_id.to_string().into_bytes();
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&1_u16.to_be_bytes()); // ADAPTER_CONFIG_FORMAT_VERSION
    bytes.extend_from_slice(&1_u16.to_be_bytes()); // HashSuite::genesis().id
    bytes.extend_from_slice(&(chain_id_bytes.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&chain_id_bytes);
    bytes.extend_from_slice(&fixture.protocol_version.get().to_be_bytes());
    bytes.extend_from_slice(&fixture.epoch.get().to_be_bytes());
    bytes.extend_from_slice(fixture.domain.as_bytes());
    bytes.extend_from_slice(validator_id.as_bytes());
    bytes.extend_from_slice(&validator_secret);
    bytes.extend_from_slice(&1_u64.to_be_bytes()); // writer_fence (checkpoint 1)
    bytes.extend_from_slice(&genesis_authority_public_key);
    bytes.extend_from_slice(&(genesis_manifest_digest_frame.len() as u16).to_be_bytes());
    bytes.extend_from_slice(genesis_manifest_digest_frame);
    bytes.extend_from_slice(&1_u64.to_be_bytes()); // created_checkpoint (genesis checkpoint)
    bytes.extend_from_slice(&20_000_u64.to_be_bytes()); // operation_timeout_millis
    bytes.extend_from_slice(&(fee_policy_frame.len() as u16).to_be_bytes());
    bytes.extend_from_slice(fee_policy_frame);
    bytes
}

struct MemorySigner<'a> {
    id: ValidatorId,
    key: &'a SigningKey,
}

impl ConsensusSigner for MemorySigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(framed).into();
        Ok(signature.to_vec())
    }
}

/// Identifies the freshly created `Definition`/`TreasuryCap` pair a
/// successful `Instantiate` left behind, excluding fee/refund outputs.
fn identify_definition_and_cap(
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    origin: &PackageOrigin,
) -> (ObjectId, ObjectId) {
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|value| value.id);
    let created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                Some(object)
            }
            _ => None,
        })
        .collect();
    let definition_tag: ScopedTypeTag = definition_type_tag(origin).unwrap();
    let definition: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| {
            verify_scoped_type_id(resolver, &object.type_hash, epoch, &definition_tag)
                .unwrap_or(false)
        })
        .expect("instantiate must create a Definition");
    let cap_tag: ScopedTypeTag = treasury_cap_type_tag(origin, &definition.id).unwrap();
    let cap: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| {
            verify_scoped_type_id(resolver, &object.type_hash, epoch, &cap_tag).unwrap_or(false)
        })
        .expect("instantiate must create a TreasuryCap");
    (definition.id, cap.id)
}

/// Identifies the single freshly created `Coin` a `mint`/`split` call left
/// behind, excluding the fee/refund settlement outputs.
fn identify_coin(
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    origin: &PackageOrigin,
    asset: ObjectId,
) -> ObjectId {
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|value| value.id);
    let coin_tag: ScopedTypeTag = coin_type_tag(origin, &asset).unwrap();
    result
        .effects
        .object_effects
        .iter()
        .find_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                verify_scoped_type_id(resolver, &object.type_hash, epoch, &coin_tag)
                    .unwrap_or(false)
                    .then_some(object.id)
            }
            _ => None,
        })
        .expect("call must create exactly one Coin")
}

fn current_ref<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    object_id: ObjectId,
) -> ObjectRef
where
    S: StructuredDurableDomainStateStore,
{
    match query_object(store, context, domain, chain_id, object_id).unwrap() {
        ObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            ..
        } => ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest,
        },
        other => panic!("expected {object_id:?} to be a current inline object, got {other:?}"),
    }
}

struct Validator {
    store: MemoryDurableStateStore,
    blobs: MemoryBlobStore,
}

struct Step {
    label: String,
    request_id_hex: String,
    sender_hex: String,
    signed_paid_intent_hex: String,
    votes_hex: [String; 3],
    certificate_hex: String,
    apply_request_hex: String,
    expected_http_node_result_hex: String,
    receipt_query_hex: String,
    next_nonce_query_hex: String,
    queried_objects: Vec<(String, String)>,
    gas_used: u64,
    reserved_fee: Option<u64>,
    actual_fee: Option<u64>,
    refund_fee: Option<u64>,
    application_gas_units: Option<u64>,
}

/// Queries the exact canonical HTTP wire encodings of the durable receipt,
/// the sender's next expected nonce, and every object in `ids`, on every
/// validator in `validators`, asserting all four agree byte-for-byte.
fn query_state_hexes(
    fixture: &FastVoteGenesisFixture,
    validators: &[Validator; 4],
    context: &DurableOperationContext,
    request_id: RequestId,
    sender: Address,
    ids: &[ObjectId],
    label: &str,
) -> (String, String, Vec<(String, String)>) {
    let mut receipt_hex: Option<String> = None;
    let mut nonce_hex: Option<String> = None;
    let mut objects_hex: Option<Vec<(String, String)>> = None;
    for backing in validators.iter() {
        let receipt =
            query_request_receipt(&backing.store, context, fixture.domain, request_id).unwrap();
        let receipt_bytes: Vec<u8> = http_receipt_query_result(receipt)
            .unwrap()
            .encode()
            .unwrap();
        let receipt_this: String = hex(&receipt_bytes);

        let next: u64 = query_sender_next_nonce(
            &backing.store,
            context,
            fixture.domain,
            fixture.chain_id.clone(),
            fixture.protocol_version,
            fixture.epoch,
            *sender.as_bytes(),
        )
        .unwrap();
        let nonce_bytes: Vec<u8> = HttpNextNonceQueryResult::new(sender, fixture.epoch, next)
            .encode()
            .unwrap();
        let nonce_this: String = hex(&nonce_bytes);

        let mut objects_this: Vec<(String, String)> = Vec::with_capacity(ids.len());
        for id in ids {
            let result: ObjectQueryResult = query_object(
                &backing.store,
                context,
                fixture.domain,
                &fixture.chain_id,
                *id,
            )
            .unwrap();
            let http_result: HttpObjectQueryResult = result.into();
            let bytes: Vec<u8> = http_result.encode().unwrap();
            objects_this.push((hex(id.as_bytes()), hex(&bytes)));
        }

        if let Some(previous) = &receipt_hex {
            assert_eq!(
                previous, &receipt_this,
                "{label}: receipt query diverged across validators"
            );
        } else {
            receipt_hex = Some(receipt_this);
        }
        if let Some(previous) = &nonce_hex {
            assert_eq!(
                previous, &nonce_this,
                "{label}: next-nonce query diverged across validators"
            );
        } else {
            nonce_hex = Some(nonce_this);
        }
        if let Some(previous) = &objects_hex {
            assert_eq!(
                previous, &objects_this,
                "{label}: object query diverged across validators"
            );
        } else {
            objects_hex = Some(objects_this);
        }
    }
    (
        receipt_hex.unwrap(),
        nonce_hex.unwrap(),
        objects_hex.unwrap(),
    )
}

/// Classifies one `fast_path::prepare` outcome into its exact HTTP-adapter
/// status (per `native_http::fastpath_error_response`/`admission_error`)
/// and a short error label, without inventing any status this codebase does
/// not itself assign.
fn classify_prepare_error(error: &FastPathError) -> (u16, String) {
    match error {
        FastPathError::Invalid("conflicting fast-path prepared record") => {
            (400, "FastPathPreparedConflict".to_owned())
        }
        FastPathError::Node(NodeCoreError::RequestIdReuse) => (409, "RequestIdReuse".to_owned()),
        FastPathError::Admission(PaidExecutionAdmissionError::Node(
            NodeCoreError::SenderNonceMismatch { .. },
        )) => (409, "SenderNonceMismatch".to_owned()),
        other => (0, format!("{other:?}")),
    }
}

/// Exercises `fast_path::prepare` for `signed_bytes` on each of the four
/// validators independently, with that validator's own real signer, and
/// returns each validator's `(status, error label, rejected)` outcome.
fn prepare_per_validator(
    fixture: &FastVoteGenesisFixture,
    validators: &[Validator; 4],
    context: &DurableOperationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    engine: &LocalWasmExecutionEngine,
    signed_bytes: &[u8],
) -> ([u16; 4], [String; 4], [bool; 4]) {
    let mut status_by_validator: [u16; 4] = [0; 4];
    let mut error_by_validator: [String; 4] = std::array::from_fn(|_| String::new());
    let mut rejected_by_validator: [bool; 4] = [false; 4];
    for (index, (validator, backing)) in
        fixture.validators.iter().zip(validators.iter()).enumerate()
    {
        let signer = MemorySigner {
            id: validator.validator_id,
            key: &validator.signing_key,
        };
        let result = fast_path::prepare(
            &backing.store,
            &backing.blobs,
            context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            base_policy,
            fee_policy,
            engine,
            &signer,
            signed_bytes,
            1,
        );
        rejected_by_validator[index] = result.is_err();
        let (status, error) = match &result {
            Err(error) => classify_prepare_error(error),
            Ok(_) => (200, "Ok".to_owned()),
        };
        status_by_validator[index] = status;
        error_by_validator[index] = error;
    }
    (
        status_by_validator,
        error_by_validator,
        rejected_by_validator,
    )
}

/// Signs, prepares on validators 0-2 only (validator 3 never calls
/// `prepare`), certifies, and applies with recovery on all four validators
/// -- asserting every validator's canonical `HttpNodeResult` wire encoding
/// is byte-identical, including the fourth, which only ever sees the
/// certificate through `apply_with_recovery`. Every DO checkpoint is the
/// fixed genesis checkpoint `1`, matching the trusted adapter config.
/// Re-applies the identical certificate a second time on all four
/// validators and re-queries every id in `queried_objects` plus the
/// request's own receipt/next-nonce, asserting the replay left every
/// queried value byte-identical to the first application.
#[allow(clippy::too_many_arguments)]
fn run_step(
    fixture: &FastVoteGenesisFixture,
    validators: &[Validator; 4],
    context: &DurableOperationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    engine: &LocalWasmExecutionEngine,
    certifier: &FastPathCertifier,
    signed_bytes: &[u8],
    label: &str,
    queried_objects: Vec<ObjectId>,
) -> (Step, PaidExecutionResult) {
    const CHECKPOINT: u64 = 1;
    let intent: PaidIntent = execution::paid_execution::decode_signed_paid_intent(signed_bytes)
        .unwrap()
        .intent;
    let request_id: RequestId = RequestId::new(intent.request_id).unwrap();
    let sender: Address = Address::new(intent.sender);

    let mut votes: Vec<FastVote> = Vec::with_capacity(3);
    for (validator, backing) in fixture.validators.iter().zip(validators.iter()).take(3) {
        let signer = MemorySigner {
            id: validator.validator_id,
            key: &validator.signing_key,
        };
        let vote = fast_path::prepare(
            &backing.store,
            &backing.blobs,
            context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            base_policy,
            fee_policy,
            engine,
            &signer,
            signed_bytes,
            CHECKPOINT,
        )
        .unwrap();
        votes.push(vote);
    }

    let target: &FastVote = &votes[0];
    let certificate = certifier
        .try_form_certificate(
            target.tx_hash,
            target.execution_effects_hash,
            target.locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("3-of-4 equal-power votes must certify");
    let certificate_bytes: Vec<u8> = encode_fast_certificate(&certificate).unwrap();
    let apply_request_bytes: Vec<u8> = FastVoteApplyRequest {
        signed_paid_intent: signed_bytes.to_vec(),
        certificate: certificate_bytes.clone(),
    }
    .encode()
    .unwrap();

    let mut http_node_result_bytes: Option<Vec<u8>> = None;
    let mut raw_result_bytes: Option<Vec<u8>> = None;
    for backing in validators.iter() {
        let output = fast_path::apply_with_recovery(
            &backing.store,
            &backing.blobs,
            context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            base_policy,
            fee_policy,
            engine,
            signed_bytes,
            &certificate_bytes,
            CHECKPOINT,
        )
        .unwrap();
        let payload: Vec<u8> = output.responses()[0].payload().unwrap().to_vec();
        let http_result: Vec<u8> = HttpNodeResult::new(request_id, output.responses().to_vec())
            .unwrap()
            .encode()
            .unwrap();
        if let Some(previous) = &http_node_result_bytes {
            assert_eq!(
                previous, &http_result,
                "{label}: validators diverged on the HttpNodeResult wire encoding"
            );
            assert_eq!(
                raw_result_bytes.as_ref().unwrap(),
                &payload,
                "{label}: validators diverged on the applied node result"
            );
        } else {
            http_node_result_bytes = Some(http_result);
            raw_result_bytes = Some(payload);
        }
    }
    let http_node_result_bytes: Vec<u8> = http_node_result_bytes.unwrap();
    let raw_result_bytes: Vec<u8> = raw_result_bytes.unwrap();
    let result: PaidExecutionResult = decode_paid_execution_result(&raw_result_bytes).unwrap();

    let (receipt_hex, nonce_hex, queried_objects_hex) = query_state_hexes(
        fixture,
        validators,
        context,
        request_id,
        sender,
        &queried_objects,
        label,
    );

    // Native exact apply replay: re-applying the identical certificate must
    // leave every queried object/receipt/nonce byte-identical.
    for backing in validators.iter() {
        let output = fast_path::apply_with_recovery(
            &backing.store,
            &backing.blobs,
            context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            base_policy,
            fee_policy,
            engine,
            signed_bytes,
            &certificate_bytes,
            CHECKPOINT,
        )
        .unwrap();
        let payload: Vec<u8> = output.responses()[0].payload().unwrap().to_vec();
        assert_eq!(
            payload, raw_result_bytes,
            "{label}: replayed apply diverged from the original result"
        );
    }
    let (replay_receipt_hex, replay_nonce_hex, replay_objects_hex) = query_state_hexes(
        fixture,
        validators,
        context,
        request_id,
        sender,
        &queried_objects,
        label,
    );
    assert_eq!(
        replay_receipt_hex, receipt_hex,
        "{label}: replay changed the queried receipt"
    );
    assert_eq!(
        replay_nonce_hex, nonce_hex,
        "{label}: replay changed the queried next-nonce"
    );
    assert_eq!(
        replay_objects_hex, queried_objects_hex,
        "{label}: replay changed a queried object"
    );

    let charged = result.charged.as_ref();
    let step = Step {
        label: label.to_owned(),
        request_id_hex: hex(&intent.request_id),
        sender_hex: hex(&intent.sender),
        signed_paid_intent_hex: hex(signed_bytes),
        votes_hex: [
            hex(&consensus::encode_fast_vote(&votes[0]).unwrap()),
            hex(&consensus::encode_fast_vote(&votes[1]).unwrap()),
            hex(&consensus::encode_fast_vote(&votes[2]).unwrap()),
        ],
        certificate_hex: hex(&certificate_bytes),
        apply_request_hex: hex(&apply_request_bytes),
        expected_http_node_result_hex: hex(&http_node_result_bytes),
        receipt_query_hex: receipt_hex,
        next_nonce_query_hex: nonce_hex,
        queried_objects: queried_objects_hex,
        gas_used: result.effects.gas_used,
        reserved_fee: charged.map(|value| value.reserved.get()),
        actual_fee: charged.map(|value| value.actual.get()),
        refund_fee: charged.map(|value| value.refund.get()),
        application_gas_units: charged.map(|value| value.application_gas_units),
    };
    (step, result)
}

fn sign(fixture: &FastVoteGenesisFixture, intent: PaidIntent) -> Vec<u8> {
    fixture.sign_intent(intent)
}

struct Negative {
    label: String,
    signed_paid_intent_hex: String,
    apply_request_hex: Option<String>,
    expected_status_by_validator: [u16; 4],
    error_by_validator: [String; 4],
    rejected_by_validator: [bool; 4],
    receipt_unchanged: bool,
    nonce_unchanged: bool,
    objects_unchanged: bool,
}

fn opt_num(value: Option<u64>) -> String {
    match value {
        Some(number) => number.to_string(),
        None => "null".to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn print_steps(
    steps: &[Step],
    genesis_manifest_hex: &str,
    adapter_configs_hex: &[String],
    context_query_hex: &str,
    paid_fee_policy_hex: &str,
    publication_query_path: &str,
    publication_query_hex: &str,
    instance_query_path: &str,
    instance_query_hex: &str,
    negatives: &[Negative],
    repin_signed_paid_intent_hex: &str,
) {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"genesis_manifest_hex\": \"{genesis_manifest_hex}\",\n"
    ));
    out.push_str("  \"trusted_adapter_config_hex\": [\n");
    for (index, config) in adapter_configs_hex.iter().enumerate() {
        let comma = if index + 1 == adapter_configs_hex.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!("    \"{config}\"{comma}\n"));
    }
    out.push_str("  ],\n");
    out.push_str("  \"steps\": [\n");
    for (index, step) in steps.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"label\": \"{}\",\n", step.label));
        out.push_str(&format!(
            "      \"request_id_hex\": \"{}\",\n",
            step.request_id_hex
        ));
        out.push_str(&format!("      \"sender_hex\": \"{}\",\n", step.sender_hex));
        out.push_str(&format!(
            "      \"signed_paid_intent_hex\": \"{}\",\n",
            step.signed_paid_intent_hex
        ));
        out.push_str("      \"votes_hex\": [\n");
        for (vote_index, vote) in step.votes_hex.iter().enumerate() {
            let comma = if vote_index + 1 == step.votes_hex.len() {
                ""
            } else {
                ","
            };
            out.push_str(&format!("        \"{vote}\"{comma}\n"));
        }
        out.push_str("      ],\n");
        out.push_str(&format!(
            "      \"certificate_hex\": \"{}\",\n",
            step.certificate_hex
        ));
        out.push_str(&format!(
            "      \"apply_request_hex\": \"{}\",\n",
            step.apply_request_hex
        ));
        out.push_str(&format!(
            "      \"expected_http_node_result_hex\": \"{}\",\n",
            step.expected_http_node_result_hex
        ));
        out.push_str(&format!(
            "      \"receipt_query_hex\": \"{}\",\n",
            step.receipt_query_hex
        ));
        out.push_str(&format!(
            "      \"next_nonce_query_hex\": \"{}\",\n",
            step.next_nonce_query_hex
        ));
        out.push_str("      \"queried_objects\": [\n");
        for (query_index, (id_hex, query_hex)) in step.queried_objects.iter().enumerate() {
            let comma = if query_index + 1 == step.queried_objects.len() {
                ""
            } else {
                ","
            };
            out.push_str(&format!(
                "        {{\"id_hex\": \"{id_hex}\", \"query_hex\": \"{query_hex}\"}}{comma}\n"
            ));
        }
        out.push_str("      ],\n");
        out.push_str(&format!("      \"gas_used\": {},\n", step.gas_used));
        out.push_str(&format!(
            "      \"reserved_fee\": {},\n",
            opt_num(step.reserved_fee)
        ));
        out.push_str(&format!(
            "      \"actual_fee\": {},\n",
            opt_num(step.actual_fee)
        ));
        out.push_str(&format!(
            "      \"refund_fee\": {},\n",
            opt_num(step.refund_fee)
        ));
        out.push_str(&format!(
            "      \"application_gas_units\": {}\n",
            opt_num(step.application_gas_units)
        ));
        let comma = if index + 1 == steps.len() { "" } else { "," };
        out.push_str(&format!("    }}{comma}\n"));
    }
    out.push_str("  ],\n");
    out.push_str(&format!(
        "  \"context_query_hex\": \"{context_query_hex}\",\n"
    ));
    out.push_str(&format!(
        "  \"paid_fee_policy_hex\": \"{paid_fee_policy_hex}\",\n"
    ));
    out.push_str(&format!(
        "  \"publication_query_path\": \"{publication_query_path}\",\n"
    ));
    out.push_str(&format!(
        "  \"publication_query_hex\": \"{publication_query_hex}\",\n"
    ));
    out.push_str(&format!(
        "  \"instance_query_path\": \"{instance_query_path}\",\n"
    ));
    out.push_str(&format!(
        "  \"instance_query_hex\": \"{instance_query_hex}\",\n"
    ));
    out.push_str(&format!(
        "  \"repin_signed_paid_intent_hex\": \"{repin_signed_paid_intent_hex}\",\n"
    ));
    out.push_str("  \"negatives\": [\n");
    for (index, negative) in negatives.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"label\": \"{}\",\n", negative.label));
        out.push_str(&format!(
            "      \"signed_paid_intent_hex\": \"{}\",\n",
            negative.signed_paid_intent_hex
        ));
        out.push_str(&format!(
            "      \"apply_request_hex\": {},\n",
            match &negative.apply_request_hex {
                Some(value) => format!("\"{value}\""),
                None => "null".to_owned(),
            }
        ));
        out.push_str("      \"expected_status_by_validator\": [\n");
        for (validator_index, status) in negative.expected_status_by_validator.iter().enumerate() {
            let comma = if validator_index + 1 == 4 { "" } else { "," };
            out.push_str(&format!("        {status}{comma}\n"));
        }
        out.push_str("      ],\n");
        out.push_str("      \"error_by_validator\": [\n");
        for (validator_index, error) in negative.error_by_validator.iter().enumerate() {
            let comma = if validator_index + 1 == 4 { "" } else { "," };
            out.push_str(&format!("        \"{error}\"{comma}\n"));
        }
        out.push_str("      ],\n");
        out.push_str("      \"rejected_by_validator\": [\n");
        for (validator_index, rejected) in negative.rejected_by_validator.iter().enumerate() {
            let comma = if validator_index + 1 == 4 { "" } else { "," };
            out.push_str(&format!("        {rejected}{comma}\n"));
        }
        out.push_str("      ],\n");
        out.push_str(&format!(
            "      \"receipt_unchanged\": {},\n",
            negative.receipt_unchanged
        ));
        out.push_str(&format!(
            "      \"nonce_unchanged\": {},\n",
            negative.nonce_unchanged
        ));
        out.push_str(&format!(
            "      \"objects_unchanged\": {}\n",
            negative.objects_unchanged
        ));
        let comma = if index + 1 == negatives.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!("    }}{comma}\n"));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    println!("{out}");
}

fn main() {
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_network_fixture("cf-do-fixture");
    let genesis: node_core::GenesisManifest =
        decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let fee_policy = genesis.fee_policy.clone();

    let context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    );
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();

    let validators: [Validator; 4] = std::array::from_fn(|_| {
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(
            fixture.domain,
            WriterFenceGeneration::new(1).unwrap(),
        );
        let blobs: MemoryBlobStore = MemoryBlobStore::default();
        Validator { store, blobs }
    });
    for validator in &validators {
        let outcome = install_genesis(
            &validator.store,
            &context,
            fixture.domain,
            &fixture.resolver,
            &genesis,
            1,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            GenesisInstallOutcome::FreshInstall { .. }
        ));
    }

    let validator_infos: Vec<ValidatorInfo> = genesis
        .validator_set
        .validators
        .iter()
        .map(|entry| ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let validator_set: ValidatorSet = ValidatorSet::new(fixture.epoch, validator_infos).unwrap();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        validator_set,
    )
    .unwrap();

    let genesis_authority_public_key: [u8; 32] =
        VerificationKey::from(&SigningKey::from(DEVNET_PAID_GENESIS_SEED)).into();
    let manifest_digest_full = genesis_manifest_commitment(&fixture.resolver, &genesis).unwrap();
    let manifest_digest_frame: Vec<u8> = encode_digest32(&manifest_digest_full).unwrap();
    let fee_policy_frame: Vec<u8> =
        execution::paid_execution::encode_paid_fee_policy(&fee_policy).unwrap();
    let adapter_configs_hex: Vec<String> = fixture
        .validators
        .iter()
        .map(|validator| {
            hex(&trusted_adapter_config_bytes(
                &fixture,
                validator.validator_id,
                validator.seed,
                genesis_authority_public_key,
                &manifest_digest_frame,
                &fee_policy_frame,
            ))
        })
        .collect();

    let mut steps: Vec<Step> = Vec::new();
    let devnet_instance_record = fixture.instance_record();
    let devnet_instance =
        local_execution::instance_target(&fixture.resolver, &devnet_instance_record).unwrap();

    // Step 1: a real sender-signed self-transfer of the genesis fee coin
    // (request_id fixture.request_id, nonce 0) -- keeps the coin under the
    // sender's own ownership for every later step, unlike
    // fixture.paid_intent_bytes (whose default recipient/refund is a
    // distinct address, used instead only for the request-id-conflict
    // negative below).
    let genesis_fee_coin_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    let genesis_call = CallIntent {
        context: fixture.context.clone(),
        request_id: fixture.request_id,
        sender: fixture.sender,
        nonce: 0,
        code: fixture.code(),
        instance: devnet_instance.clone(),
        entrypoint: "transfer".to_owned(),
        type_arguments: vec![asset_type_argument(&fixture.definition_id())],
        access: AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: genesis_fee_coin_ref.clone(),
                mode: objects::AccessMode::Write,
            }],
        },
        arguments: transfer_arguments(&fixture.sender).unwrap(),
        gas_limit: 100_000,
    };
    let genesis_intent = PaidIntent {
        context: fixture.context.clone(),
        request_id: fixture.request_id,
        sender: fixture.sender,
        nonce: 0,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
            &fixture.resolver,
            &fee_policy,
        )
        .unwrap(),
        consent: FeeSourceConsent {
            source: genesis_fee_coin_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: fixture.sender,
        },
        application: PaidApplication::Call(genesis_call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let genesis_signed = sign(&fixture, genesis_intent);
    let (step, genesis_result) = run_step(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &certifier,
        &genesis_signed,
        "genesis-transfer",
        vec![fixture.fee_coin],
    );
    assert_eq!(
        genesis_result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    steps.push(step);

    // Step 2: a genuinely fresh, user-selected package published under an
    // independent origin.
    let publish_origin_seed: [u8; 32] = [0x71; 32];
    let origin: PackageOrigin = PackageOrigin::unverified(
        fixture.chain_id.clone(),
        fixture.sender,
        publish_origin_seed,
    )
    .unwrap();
    let package = public_standard_asset::build_package(&origin).unwrap();
    let semantics =
        local_execution::generic_object_result_semantics(&fixture.resolver, &fixture.context)
            .unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: fixture.context.clone(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
        semantics,
        wasm: package.wasm.clone(),
        unverified_abi: package.encoded_abi.clone(),
        exports: package.exports.clone(),
        unverified_dependencies: Vec::new(),
    })
    .unwrap();
    let artifact_digest =
        execution::publication::artifact_commitment(&fixture.resolver, &fixture.context, &artifact)
            .unwrap();
    let code_ref: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, fixture.context.clone(), artifact_digest)
            .unwrap();

    let mut fee_coin_ref: ObjectRef = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    let mut nonce: u64 = 1;
    let publish_intent = PaidIntent {
        context: fixture.context.clone(),
        request_id: [0xD1; 32],
        sender: fixture.sender,
        nonce,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
            &fixture.resolver,
            &fee_policy,
        )
        .unwrap(),
        consent: FeeSourceConsent {
            source: fee_coin_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: fixture.sender,
        },
        application: PaidApplication::Publish(artifact),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let publish_signed = sign(&fixture, publish_intent);
    let (step, publish_result) = run_step(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &certifier,
        &publish_signed,
        "publish",
        vec![fixture.fee_coin],
    );
    assert_eq!(
        publish_result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    steps.push(step);
    nonce += 1;

    // Step 3: instantiate (init) the freshly published package.
    let instance_seed: [u8; 32] = [0x72; 32];
    let instance_record = InstanceRecord {
        context: fixture.context.clone(),
        creator: fixture.sender,
        seed: instance_seed,
        code: code_ref.clone(),
        revision: 1,
        initializer: INITIALIZER.to_owned(),
    };
    let instance = local_execution::instance_target(&fixture.resolver, &instance_record).unwrap();
    fee_coin_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    let instantiate_call = CallIntent {
        context: fixture.context.clone(),
        request_id: [0xD2; 32],
        sender: fixture.sender,
        nonce,
        code: code_ref.clone(),
        instance: instance.clone(),
        entrypoint: INITIALIZER.to_owned(),
        type_arguments: Vec::new(),
        access: AccessManifest::new(),
        arguments: no_arguments().unwrap(),
        gas_limit: 100_000,
    };
    let instantiate_intent = PaidIntent {
        context: fixture.context.clone(),
        request_id: [0xD2; 32],
        sender: fixture.sender,
        nonce,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(
            &fixture.resolver,
            &fee_policy,
        )
        .unwrap(),
        consent: FeeSourceConsent {
            source: fee_coin_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: fixture.sender,
        },
        application: PaidApplication::Instantiate(instantiate_call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let instantiate_signed = sign(&fixture, instantiate_intent);
    let (step, instantiate_result) = run_step(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &certifier,
        &instantiate_signed,
        "instantiate-create-asset",
        vec![fixture.fee_coin],
    );
    assert_eq!(
        instantiate_result.status,
        execution::paid_execution::PaidExecutionStatus::Success
    );
    let (definition, treasury_cap): (ObjectId, ObjectId) = identify_definition_and_cap(
        &instantiate_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
    );
    steps.push(step);
    nonce += 1;

    let type_args = vec![asset_type_argument(&definition)];
    let fee_policy_digest =
        execution::paid_execution::paid_fee_policy_digest(&fixture.resolver, &fee_policy).unwrap();

    macro_rules! run_call {
        ($request_id:expr, $entrypoint:expr, $access:expr, $arguments:expr, $label:expr, $queried:expr) => {{
            fee_coin_ref = current_ref(
                &validators[0].store,
                &context,
                fixture.domain,
                &fixture.chain_id,
                fixture.fee_coin,
            );
            let call = CallIntent {
                context: fixture.context.clone(),
                request_id: $request_id,
                sender: fixture.sender,
                nonce,
                code: code_ref.clone(),
                instance: instance.clone(),
                entrypoint: $entrypoint.to_owned(),
                type_arguments: type_args.clone(),
                access: $access,
                arguments: $arguments,
                gas_limit: 100_000,
            };
            let intent = PaidIntent {
                context: fixture.context.clone(),
                request_id: $request_id,
                sender: fixture.sender,
                nonce,
                fee_policy_digest,
                consent: FeeSourceConsent {
                    source: fee_coin_ref.clone(),
                    access: ReservationAccessKind::Write,
                    max_fee: Amount::new(1_000_000),
                    refund_recipient: fixture.sender,
                },
                application: PaidApplication::Call(call),
                gas_limit: 100_000,
                authorizations: Vec::new(),
            };
            let signed = sign(&fixture, intent);
            let (step, result) = run_step(
                &fixture,
                &validators,
                &context,
                &base_policy,
                &fee_policy,
                &engine,
                &certifier,
                &signed,
                $label,
                $queried,
            );
            assert_eq!(
                result.status,
                execution::paid_execution::PaidExecutionStatus::Success
            );
            steps.push(step);
            nonce += 1;
            result
        }};
    }

    // mint(cap, 500, sender) -> coinA
    let cap_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        treasury_cap,
    );
    let mint_access = AccessManifest {
        entries: vec![abi::AccessEntry {
            object_ref: cap_ref.clone(),
            mode: objects::AccessMode::Write,
        }],
    };
    let mint_result = run_call!(
        [0xD3; 32],
        "mint",
        mint_access,
        mint_arguments(500, &fixture.sender).unwrap(),
        "mint",
        vec![treasury_cap]
    );
    let coin_a: ObjectId = identify_coin(
        &mint_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
        definition,
    );

    // split(coinA, 100, sender) -> coinA mutated + coinB created
    let coin_a_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        coin_a,
    );
    let split_access = AccessManifest {
        entries: vec![abi::AccessEntry {
            object_ref: coin_a_ref.clone(),
            mode: objects::AccessMode::Write,
        }],
    };
    let split_result = run_call!(
        [0xD4; 32],
        "split",
        split_access,
        split_arguments(100, &fixture.sender).unwrap(),
        "split",
        vec![coin_a]
    );
    let coin_b: ObjectId = identify_coin(
        &split_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
        definition,
    );

    // merge(into=coinA, from=coinB)
    let coin_a_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        coin_a,
    );
    let coin_b_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        coin_b,
    );
    let merge_access = AccessManifest {
        entries: vec![
            abi::AccessEntry {
                object_ref: coin_a_ref.clone(),
                mode: objects::AccessMode::Write,
            },
            abi::AccessEntry {
                object_ref: coin_b_ref.clone(),
                mode: objects::AccessMode::Consume,
            },
        ],
    };
    run_call!(
        [0xD5; 32],
        "merge",
        merge_access,
        no_arguments().unwrap(),
        "merge",
        vec![coin_a, coin_b]
    );

    // mint(cap, 50, sender) -> coinC (kept separate, for transfer)
    let cap_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        treasury_cap,
    );
    let mint2_access = AccessManifest {
        entries: vec![abi::AccessEntry {
            object_ref: cap_ref.clone(),
            mode: objects::AccessMode::Write,
        }],
    };
    let mint2_result = run_call!(
        [0xD6; 32],
        "mint",
        mint2_access,
        mint_arguments(50, &fixture.sender).unwrap(),
        "mint-2",
        vec![treasury_cap]
    );
    let coin_c: ObjectId = identify_coin(
        &mint2_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
        definition,
    );

    // transfer(coinC, recipient)
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x81; 32])).into();
    let coin_c_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        coin_c,
    );
    let transfer_access = AccessManifest {
        entries: vec![abi::AccessEntry {
            object_ref: coin_c_ref.clone(),
            mode: objects::AccessMode::Write,
        }],
    };
    run_call!(
        [0xD7; 32],
        "transfer",
        transfer_access,
        transfer_arguments(&recipient).unwrap(),
        "transfer",
        vec![coin_c]
    );

    // burn(cap, coinA)
    let cap_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        treasury_cap,
    );
    let coin_a_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        coin_a,
    );
    let burn_access = AccessManifest {
        entries: vec![
            abi::AccessEntry {
                object_ref: cap_ref.clone(),
                mode: objects::AccessMode::Write,
            },
            abi::AccessEntry {
                object_ref: coin_a_ref.clone(),
                mode: objects::AccessMode::Consume,
            },
        ],
    };
    run_call!(
        [0xD8; 32],
        "burn",
        burn_access,
        no_arguments().unwrap(),
        "burn",
        vec![treasury_cap, coin_a]
    );

    // A genuinely charged Wasmi trap: the genesis fee coin used
    // simultaneously as the transfer's own `Write` call access and as its
    // own fee-reservation source, on the devnet's own genesis-installed
    // Standard Asset instance.
    fee_coin_ref = current_ref(
        &validators[0].store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    let trap_recipient: [u8; 32] = [0x41; 32];
    let trap_call = CallIntent {
        context: fixture.context.clone(),
        request_id: [0xD9; 32],
        sender: fixture.sender,
        nonce,
        code: fixture.code(),
        instance: devnet_instance.clone(),
        entrypoint: "transfer".to_owned(),
        type_arguments: vec![asset_type_argument(&fixture.definition_id())],
        access: AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: fee_coin_ref.clone(),
                mode: objects::AccessMode::Write,
            }],
        },
        arguments: transfer_arguments(&trap_recipient).unwrap(),
        gas_limit: 100_000,
    };
    let trap_intent = PaidIntent {
        context: fixture.context.clone(),
        request_id: [0xD9; 32],
        sender: fixture.sender,
        nonce,
        fee_policy_digest,
        consent: FeeSourceConsent {
            source: fee_coin_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: fixture.sender,
        },
        application: PaidApplication::Call(trap_call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let trap_signed = sign(&fixture, trap_intent);
    let (step, trap_result) = run_step(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &certifier,
        &trap_signed,
        "trap",
        vec![fixture.fee_coin],
    );
    assert_eq!(
        trap_result.status,
        execution::paid_execution::PaidExecutionStatus::ApplicationFailed
    );
    assert!(trap_result.charged.is_some());
    steps.push(step);
    nonce += 1;

    // Negative: a genuine signed request-id conflict at `fast_path::prepare`.
    // `fixture.request_id` was already prepared and applied (with an
    // identical committed receipt) on all four validators in step 1 (the
    // genesis-transfer). Preparing a second, differently-signed intent
    // under the same request id is exercised on each validator with its
    // own real signer: validators 0-2 (which locally prepared the original
    // vote) fail closed at `fast_path::prepare`'s own already-prepared
    // record check (`FastPathError::Invalid("conflicting fast-path
    // prepared record")`, HTTP 400); validator 3 (which never itself
    // prepared, only ever caught up via `apply_with_recovery`) instead
    // reconciles against its own committed durable receipt and fails
    // closed with `NodeCoreError::RequestIdReuse` (HTTP 409) -- both are
    // genuine outcomes of the real admission pipeline, not invented
    // per-validator behavior.
    let conflict_ids: [ObjectId; 1] = [fixture.fee_coin];
    let (conflict_receipt_before, conflict_nonce_before, conflict_objects_before) =
        query_state_hexes(
            &fixture,
            &validators,
            &context,
            RequestId::new(fixture.request_id).unwrap(),
            Address::new(fixture.sender),
            &conflict_ids,
            "request-id-conflict",
        );
    let conflicting_bytes = fixture.sign_transfer(
        fixture.request_id,
        nonce,
        VerificationKey::from(&SigningKey::from([0x91; 32])).into(),
    );
    let (conflict_status, conflict_error, conflict_rejected) = prepare_per_validator(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &conflicting_bytes,
    );
    let (conflict_receipt_after, conflict_nonce_after, conflict_objects_after) = query_state_hexes(
        &fixture,
        &validators,
        &context,
        RequestId::new(fixture.request_id).unwrap(),
        Address::new(fixture.sender),
        &conflict_ids,
        "request-id-conflict",
    );
    let conflict_negative = Negative {
        label: "request-id-conflict".to_owned(),
        signed_paid_intent_hex: hex(&conflicting_bytes),
        apply_request_hex: None,
        expected_status_by_validator: conflict_status,
        error_by_validator: conflict_error,
        rejected_by_validator: conflict_rejected,
        receipt_unchanged: conflict_receipt_before == conflict_receipt_after,
        nonce_unchanged: conflict_nonce_before == conflict_nonce_after,
        objects_unchanged: conflict_objects_before == conflict_objects_after,
    };
    assert_eq!(
        conflict_negative.expected_status_by_validator,
        [400, 400, 400, 409]
    );
    assert!(
        conflict_negative
            .rejected_by_validator
            .iter()
            .all(|value| *value)
    );
    assert!(
        conflict_negative.receipt_unchanged
            && conflict_negative.nonce_unchanged
            && conflict_negative.objects_unchanged
    );

    // Negative: the same genuine request-id conflict, but at
    // `fast_path::apply_with_recovery` -- the conflicting signed bytes
    // paired with the ORIGINAL step-1 certificate (never a fabricated
    // certificate for the conflicting bytes). `apply_internal` reconciles
    // the durable receipt before ever decoding/verifying the certificate,
    // so every validator (having already committed step 1's receipt) fails
    // closed with `NodeCoreError::RequestIdReuse` (HTTP 409), leaving
    // queried state unchanged.
    let original_certificate_bytes: Vec<u8> = unhex(&steps[0].certificate_hex);
    let apply_conflict_request_bytes: Vec<u8> = FastVoteApplyRequest {
        signed_paid_intent: conflicting_bytes.clone(),
        certificate: original_certificate_bytes.clone(),
    }
    .encode()
    .unwrap();
    let (apply_conflict_receipt_before, apply_conflict_nonce_before, apply_conflict_objects_before) =
        query_state_hexes(
            &fixture,
            &validators,
            &context,
            RequestId::new(fixture.request_id).unwrap(),
            Address::new(fixture.sender),
            &conflict_ids,
            "apply-request-id-conflict",
        );
    let mut apply_conflict_status: [u16; 4] = [0; 4];
    let mut apply_conflict_error: [String; 4] = std::array::from_fn(|_| String::new());
    let mut apply_conflict_rejected: [bool; 4] = [false; 4];
    for (index, backing) in validators.iter().enumerate() {
        let result = fast_path::apply_with_recovery(
            &backing.store,
            &backing.blobs,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            &base_policy,
            &fee_policy,
            &engine,
            &conflicting_bytes,
            &original_certificate_bytes,
            1,
        );
        apply_conflict_rejected[index] = result.is_err();
        let (status, error) = match &result {
            Err(FastPathError::Node(NodeCoreError::RequestIdReuse)) => {
                (409, "RequestIdReuse".to_owned())
            }
            Err(other) => (0, format!("{other:?}")),
            Ok(_) => (200, "Ok".to_owned()),
        };
        apply_conflict_status[index] = status;
        apply_conflict_error[index] = error;
    }
    let (apply_conflict_receipt_after, apply_conflict_nonce_after, apply_conflict_objects_after) =
        query_state_hexes(
            &fixture,
            &validators,
            &context,
            RequestId::new(fixture.request_id).unwrap(),
            Address::new(fixture.sender),
            &conflict_ids,
            "apply-request-id-conflict",
        );
    let apply_conflict_negative = Negative {
        label: "apply-request-id-conflict".to_owned(),
        signed_paid_intent_hex: hex(&conflicting_bytes),
        apply_request_hex: Some(hex(&apply_conflict_request_bytes)),
        expected_status_by_validator: apply_conflict_status,
        error_by_validator: apply_conflict_error,
        rejected_by_validator: apply_conflict_rejected,
        receipt_unchanged: apply_conflict_receipt_before == apply_conflict_receipt_after,
        nonce_unchanged: apply_conflict_nonce_before == apply_conflict_nonce_after,
        objects_unchanged: apply_conflict_objects_before == apply_conflict_objects_after,
    };
    assert_eq!(
        apply_conflict_negative.expected_status_by_validator,
        [409, 409, 409, 409]
    );
    assert!(
        apply_conflict_negative
            .rejected_by_validator
            .iter()
            .all(|value| *value)
    );
    assert!(
        apply_conflict_negative.receipt_unchanged
            && apply_conflict_negative.nonce_unchanged
            && apply_conflict_negative.objects_unchanged
    );

    // Negative: a nonce gap, exercised on each validator with its own real
    // signer. No validator has a local prepared record or a committed
    // receipt for this fresh request id, so all four independently reach
    // the same fresh-admission nonce check and fail closed with
    // `NodeCoreError::SenderNonceMismatch` (HTTP 409 on every validator).
    let gap_request_id: [u8; 32] = [0xDA; 32];
    let gap_ids: [ObjectId; 1] = [fixture.fee_coin];
    let expected_nonce = query_sender_next_nonce(
        &validators[0].store,
        &context,
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    let (gap_receipt_before, gap_nonce_before, gap_objects_before) = query_state_hexes(
        &fixture,
        &validators,
        &context,
        RequestId::new(gap_request_id).unwrap(),
        Address::new(fixture.sender),
        &gap_ids,
        "nonce-gap",
    );
    let gapped_bytes = fixture.sign_transfer(
        gap_request_id,
        expected_nonce + 10,
        VerificationKey::from(&SigningKey::from([0x92; 32])).into(),
    );
    let (gap_status, gap_error, gap_rejected) = prepare_per_validator(
        &fixture,
        &validators,
        &context,
        &base_policy,
        &fee_policy,
        &engine,
        &gapped_bytes,
    );
    let (gap_receipt_after, gap_nonce_after, gap_objects_after) = query_state_hexes(
        &fixture,
        &validators,
        &context,
        RequestId::new(gap_request_id).unwrap(),
        Address::new(fixture.sender),
        &gap_ids,
        "nonce-gap",
    );
    let gap_negative = Negative {
        label: "nonce-gap".to_owned(),
        signed_paid_intent_hex: hex(&gapped_bytes),
        apply_request_hex: None,
        expected_status_by_validator: gap_status,
        error_by_validator: gap_error,
        rejected_by_validator: gap_rejected,
        receipt_unchanged: gap_receipt_before == gap_receipt_after,
        nonce_unchanged: gap_nonce_before == gap_nonce_after,
        objects_unchanged: gap_objects_before == gap_objects_after,
    };
    assert_eq!(
        gap_negative.expected_status_by_validator,
        [409, 409, 409, 409]
    );
    assert!(
        gap_negative
            .rejected_by_validator
            .iter()
            .all(|value| *value)
    );
    assert!(
        gap_negative.receipt_unchanged
            && gap_negative.nonce_unchanged
            && gap_negative.objects_unchanged
    );

    // Golden native context query (matches
    // `fastvote_host_pg`'s own trusted composition exactly): genesis
    // `ProtocolConfig` with this fixture's protocol version, a single-domain
    // placement at rule version 1 for this fixture's domain from epoch 0,
    // and the canonical Ed25519/canonical-prime-order/address-is-public-key
    // transaction-auth profile.
    let repin_signed_paid_intent_hex: String = {
        let mut repin_intent: PaidIntent =
            execution::paid_execution::decode_signed_paid_intent(&genesis_signed)
                .unwrap()
                .intent;
        let repin_context: PublicationContext = PublicationContext::new(
            fixture.chain_id.clone(),
            fixture.protocol_version,
            Epoch::new(1),
        )
        .unwrap();
        repin_intent.context = repin_context.clone();
        match &mut repin_intent.application {
            PaidApplication::Call(call) | PaidApplication::Instantiate(call) => {
                call.context = repin_context.clone();
            }
            PaidApplication::Publish(_) => {}
        }
        let repin_signed: Vec<u8> = fixture.sign_intent(repin_intent);
        authenticate_paid_execution(&fixture.resolver, &repin_context, &repin_signed).expect(
            "genuinely epoch1-signed prepare must authenticate under its own declared epoch",
        );
        hex(&repin_signed)
    };

    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = fixture.protocol_version;
    protocol_config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, fixture.domain, Epoch::new(0)).unwrap());
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let profile = resolve_transaction_auth_profile(&protocol_config).unwrap();
    let protocol_config_bytes: Vec<u8> = protocol_config.canonical_bytes().unwrap();
    let context_query_bytes: Vec<u8> = HttpContextQueryResult::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        protocol_config.hash_suite_id,
        profile.profile_id(),
        profile.signature_scheme_id().as_u16(),
        profile.address_binding().as_u16(),
        fixture.domain,
        protocol_config_bytes,
    )
    .unwrap()
    .encode()
    .unwrap();

    // The freshly published origin's real durable publication record, and
    // the freshly instantiated application's real durable instance record
    // -- both through the shared canonical node-core read paths, not a new
    // contract operation.
    let publication_query_bytes: Vec<u8> = encode_publication_query_result(
        &query_publication_with_history(
            &validators[0].store,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &origin,
        )
        .unwrap()
        .unwrap(),
    )
    .unwrap();
    let instance_query_bytes: Vec<u8> = encode_instance_record(
        &query_local_instance(
            &validators[0].store,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.chain_id,
            fixture.sender,
            instance_seed,
        )
        .unwrap()
        .unwrap(),
    )
    .unwrap();

    print_steps(
        &steps,
        &hex(&fixture.manifest_bytes),
        &adapter_configs_hex,
        &hex(&context_query_bytes),
        &hex(&fee_policy_frame),
        &format!(
            "/v1/contracts/publications/{}/{}",
            hex(&fixture.sender),
            hex(&publish_origin_seed)
        ),
        &hex(&publication_query_bytes),
        &format!(
            "/v1/contracts/instances/{}/{}",
            hex(&fixture.sender),
            hex(&instance_seed)
        ),
        &hex(&instance_query_bytes),
        &[conflict_negative, apply_conflict_negative, gap_negative],
        &repin_signed_paid_intent_hex,
    );
}
