//! Closure regressions use a real signed logical genesis, paid WASM prepare,
//! durable prepared artifacts and its genuine FastCertificate. Corruptions
//! leave the certified witness and all supplied artifact bytes unchanged.

use super::*;
use crate::LocalSigner;
use abi::call_values::{CallValue, ValueLayout, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use consensus::bundle::{ArtifactEntry, ArtifactKind, verify_publication_bundle};
use consensus::{ConsensusSigner, FastCertificate, FastVote};
use crypto::SignatureSigner;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionStatus, PaidIntent, ReservationAccessKind,
    paid_fee_policy_digest, paid_intent_signing_frame,
};
use node_core::fast_path::publication::{
    PublicationRetentionError, assemble_publication_bundle, decode_certified_execution_witness,
};
use node_core::genesis::{GenesisManifest, genesis_manifest_signing_frame, install_genesis};
use node_core::logical_generation::CommitmentProfile;
use node_core::{NodeResponse, NodeResponseStatus, RequestId};
use node_wire::HttpNodeResult;
use objects::{AccessMode, ObjectRef};
use protocol_types::{
    ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion, SignatureSchemeId,
};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use sunrise_edge_devnet::{
    DEVNET_PAID_GENESIS_SEED, DevOwner, PaidGenesisActivationMetadata, build_paid_genesis_manifest,
};
use validator_set::{ValidatorInfo, ValidatorSet};

struct PreparedSigner {
    id: ValidatorId,
    key: SigningKey,
}

impl ConsensusSigner for PreparedSigner {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(bytes).into();
        Ok(signature.to_vec())
    }
}

pub(crate) struct MemberFixture {
    pub(crate) resolver: HashSuiteResolver,
    pub(crate) context: PublicationContext,
    pub(crate) domain: AtomicityDomainId,
    pub(crate) certifier: FastPathCertifier,
    pub(crate) bundle: PublicationBundle,
    pub(crate) signed: SignedPaidIntent,
}

pub(crate) fn member_fixture() -> MemberFixture {
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("drain-client-test").unwrap(),
        ProtocolVersion::new(4),
        Epoch::new(8),
    )
    .unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
    let payer: LocalSigner = LocalSigner::from_seed([0x31; 32]);
    let sender: [u8; 32] = *payer.address().as_bytes();
    let owner: DevOwner = DevOwner::new(sender);
    let (mut manifest, metadata): (GenesisManifest, PaidGenesisActivationMetadata) =
        build_paid_genesis_manifest(&resolver, &context, &[owner], owner).unwrap();
    manifest.commitment_profile = CommitmentProfile::LogicalGenerationV2;
    manifest.minimum_freeze_block_height = 1;
    let key: SigningKey = SigningKey::from(DEVNET_PAID_GENESIS_SEED);
    let verification: VerificationKey = (&key).into();
    let signer: PreparedSigner = PreparedSigner {
        id: ValidatorId::new(verification.into()),
        key,
    };
    manifest.signature = signer
        .key
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain, generation);
    let operation: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    );
    install_genesis(&store, &operation, domain, &resolver, &manifest, 1).unwrap();
    let object_ref = |id: objects::ObjectId| -> ObjectRef {
        let object: &objects::Object = &manifest
            .objects
            .iter()
            .find(|entry| entry.object.id == id)
            .unwrap()
            .object;
        ObjectRef {
            id,
            version: object.version,
            digest: resolver
                .hash_for_purpose(
                    context.epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(object).unwrap(),
                )
                .unwrap(),
        }
    };
    let request_id: [u8; 32] = [0x51; 32];
    let gas_limit: u64 = 500_000;
    let arguments: Vec<u8> = encode_call_value(
        &ValueLayout::Tuple(vec![ValueLayout::Bytes {
            min_len: 32,
            max_len: 32,
        }]),
        &CallValue::Tuple(vec![CallValue::Bytes(sender.to_vec())]),
    )
    .unwrap();
    let intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id,
        sender,
        nonce: 0,
        fee_policy_digest: paid_fee_policy_digest(&resolver, &manifest.fee_policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref(metadata.owner_coins[0].fee_coin),
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(100_000),
            refund_recipient: sender,
        },
        application: PaidApplication::Call(CallIntent {
            context: context.clone(),
            request_id,
            sender,
            nonce: 0,
            code: metadata.code,
            instance: metadata.instance,
            entrypoint: "transfer".to_owned(),
            type_arguments: manifest.fee_policy.type_arguments.clone(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: object_ref(metadata.owner_coins[0].spend_coin),
                    mode: AccessMode::Write,
                }],
            },
            arguments,
            gas_limit,
        }),
        gas_limit,
        authorizations: Vec::new(),
    };
    let signed: SignedPaidIntent = SignedPaidIntent {
        signature: payer
            .sign_framed(&paid_intent_signing_frame(&context, &intent).unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        intent,
    };
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).unwrap();
    let validators: Vec<ValidatorInfo> = manifest
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
    let certifier: FastPathCertifier = FastPathCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        ValidatorSet::new(context.epoch(), validators).unwrap(),
    )
    .unwrap();
    let vote: FastVote = node_core::fast_path::prepare(
        &store,
        &MemoryBlobStore::default(),
        &operation,
        domain,
        &resolver,
        &[],
        &context,
        &LocalExecutionPolicy::generic_object_results(context.clone()),
        &manifest.fee_policy,
        &LocalWasmExecutionEngine::new(),
        &signer,
        &signed_bytes,
        2,
    )
    .unwrap();
    let certificate: FastCertificate = certifier
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &[vote],
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let bundle: PublicationBundle = assemble_publication_bundle(
        &store,
        &operation,
        domain,
        &resolver,
        &[],
        &context,
        &signed_bytes,
        &consensus::encode_fast_certificate(&certificate).unwrap(),
    )
    .unwrap();
    assert!(bundle.manifest.entries.len() > 1);
    MemberFixture {
        resolver,
        context,
        domain,
        certifier,
        bundle,
        signed,
    }
}

struct ScriptedTransport {
    responses: RefCell<VecDeque<WireResponse>>,
    requests: RefCell<Vec<WireRequest>>,
}
impl Transport for ScriptedTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, crate::TransportError> {
        self.requests.borrow_mut().push(request.clone());
        Ok(self
            .responses
            .borrow_mut()
            .pop_front()
            .expect("unexpected mutation POST"))
    }
}

fn client(bundle: &PublicationBundle) -> Client<ScriptedTransport> {
    Client::new(ScriptedTransport {
        responses: RefCell::new(VecDeque::from([WireResponse {
            status: 200,
            content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
            body: encode_publication_bundle(bundle).unwrap(),
        }])),
        requests: RefCell::new(Vec::new()),
    })
}

fn certified_output(fixture: &MemberFixture) -> Vec<u8> {
    let (_, result): (protocol_types::Digest32, PaidExecutionResult) =
        decode_certified_execution_witness(&fixture.bundle.witness).unwrap();
    let request: RequestId = RequestId::new(fixture.signed.intent.request_id).unwrap();
    let status: NodeResponseStatus = if result.status == PaidExecutionStatus::Success {
        NodeResponseStatus::Accepted
    } else {
        NodeResponseStatus::Rejected
    };
    let receipt: NodeResponse = NodeResponse::new(
        request,
        status,
        Some(encode_paid_execution_result(&result).unwrap()),
    )
    .unwrap();
    HttpNodeResult::new(request, vec![receipt])
        .unwrap()
        .encode()
        .unwrap()
}

fn corrupt_closure(fixture: &MemberFixture, corruption: u8) -> PublicationBundle {
    let mut bundle: PublicationBundle = fixture.bundle.clone();
    match corruption {
        0 => {
            bundle.manifest.entries.remove(0);
            bundle.contents.remove(0);
        }
        1 => {
            bundle.manifest.entries.clear();
            bundle.contents.clear();
        }
        2 => {
            let content: Vec<u8> = b"uncertified surplus body".to_vec();
            bundle.manifest.entries.push(ArtifactEntry {
                kind: ArtifactKind::ObjectBody,
                identity: vec![0xFF; 40],
                content_digest: fixture
                    .resolver
                    .hash_for_purpose(fixture.context.epoch(), HashPurpose::Object, &content)
                    .unwrap(),
                content_length: u32::try_from(content.len()).unwrap(),
            });
            bundle.contents.push(content);
        }
        _ => unreachable!("test corruption case"),
    }
    assert_eq!(bundle.certificate, fixture.bundle.certificate);
    assert_eq!(bundle.witness, fixture.bundle.witness);
    verify_publication_bundle(
        &bundle,
        &fixture.certifier,
        &FastPathEd25519Verifier,
        &fixture.resolver,
        &[],
    )
    .unwrap();
    bundle
}

fn assert_closure_refusal(error: ClientError, corruption: u8) {
    assert!(std::error::Error::source(&error).is_some());
    match error {
        ClientError::DrainPublicationVerification(cause) if corruption < 2 => assert!(matches!(
            *cause,
            PublicationRetentionError::MissingRequiredArtifact { .. }
        )),
        ClientError::DrainPublicationVerification(cause) => assert!(matches!(
            *cause,
            PublicationRetentionError::UnrequiredArtifact { .. }
        )),
        other => panic!("unexpected refusal: {other}"),
    }
}

#[test]
fn genuine_complete_retained_member_sources_under_independent_local_pins() {
    let fixture: MemberFixture = member_fixture();
    let endpoint: Client<ScriptedTransport> = client(&fixture.bundle);
    let observed: PublicationBundle = endpoint
        .source_retained_drain_member(
            &fixture.signed,
            &fixture.certifier,
            &fixture.resolver,
            &[],
            &fixture.context,
            fixture.domain,
            None,
        )
        .unwrap();
    assert_eq!(observed, fixture.bundle);
    assert_eq!(endpoint.transport().requests.borrow().len(), 1);
}

#[test]
fn genuine_complete_member_preserves_exact_saved_original_output() {
    let fixture: MemberFixture = member_fixture();
    let original: Vec<u8> = certified_output(&fixture);
    let endpoint: Client<ScriptedTransport> = client(&fixture.bundle);
    endpoint
        .transport()
        .responses
        .borrow_mut()
        .push_back(WireResponse {
            status: 200,
            content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
            body: original.clone(),
        });
    let (_, observed): (PaidExecutionResult, Vec<u8>) = endpoint
        .apply_drain_member_output_with_saved(
            &fixture.signed,
            &fixture.certifier,
            &fixture.resolver,
            &[],
            &fixture.context,
            fixture.domain,
            Some(&original),
            None,
        )
        .unwrap();
    assert_eq!(observed, original);
    let requests = endpoint.transport().requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH);
    assert_eq!(requests[1].path, FASTVOTE_DRAIN_APPLY_PATH);
}

#[test]
fn paired_omission_empty_and_surplus_closures_stop_after_source_before_member_post() {
    let fixture: MemberFixture = member_fixture();
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&fixture.signed).unwrap();
    let original: Vec<u8> = certified_output(&fixture);
    let saved_before: Vec<u8> = original.clone();
    for corruption in 0u8..3 {
        let bundle: PublicationBundle = corrupt_closure(&fixture, corruption);
        for saved in [None, Some(original.as_slice())] {
            let endpoint: Client<ScriptedTransport> = client(&bundle);
            let error: ClientError = endpoint
                .apply_drain_member_output_with_saved(
                    &fixture.signed,
                    &fixture.certifier,
                    &fixture.resolver,
                    &[],
                    &fixture.context,
                    fixture.domain,
                    saved,
                    None,
                )
                .unwrap_err();
            assert_closure_refusal(error, corruption);
            let requests = endpoint.transport().requests.borrow();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].path, FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH);
            assert_eq!(
                encode_signed_paid_intent(&fixture.signed).unwrap(),
                signed_bytes
            );
            if let Some(bytes) = saved {
                assert_eq!(bytes, saved_before);
            }
        }
    }
}

#[test]
fn staged_import_refuses_incomplete_or_surplus_closure_before_any_post() {
    let fixture: MemberFixture = member_fixture();
    for corruption in 0u8..3 {
        let bundle: PublicationBundle = corrupt_closure(&fixture, corruption);
        // Even a descriptor that commits to the tampered manifest cannot
        // replace the witness-required closure as local verification authority.
        let identity: AvailabilityIdentity = verify_publication_bundle(
            &bundle,
            &fixture.certifier,
            &FastPathEd25519Verifier,
            &fixture.resolver,
            &[],
        )
        .unwrap()
        .identity;
        let endpoint: Client<ScriptedTransport> = client(&bundle);
        let signer: ValidatorId = fixture.certifier.validator_set().validators()[0].id;
        let error: ClientError = endpoint
            .import_staged_drain_publication(
                signer,
                &bundle,
                &identity,
                &fixture.certifier,
                &fixture.resolver,
                &[],
                None,
            )
            .unwrap_err();
        assert_closure_refusal(error, corruption);
        assert!(endpoint.transport().requests.borrow().is_empty());
    }
}

#[test]
fn foreign_certifier_context_refuses_member_and_import_without_network_mutation() {
    let fixture: MemberFixture = member_fixture();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        ChainId::new("foreign-member-committee").unwrap(),
        fixture.context.protocol_version(),
        fixture.context.epoch(),
        fixture.certifier.validator_set().clone(),
    )
    .unwrap();
    let endpoint: Client<ScriptedTransport> = client(&fixture.bundle);
    assert!(
        endpoint
            .apply_drain_member_output(
                &fixture.signed,
                &certifier,
                &fixture.resolver,
                &[],
                &fixture.context,
                fixture.domain,
                None
            )
            .is_err()
    );
    let identity: AvailabilityIdentity = verify_drain_publication_bundle(
        &fixture.resolver,
        &[],
        &fixture.context,
        fixture.domain,
        &fixture.certifier,
        &fixture.bundle,
    )
    .unwrap();
    let signer: ValidatorId = certifier.validator_set().validators()[0].id;
    assert!(
        endpoint
            .import_staged_drain_publication(
                signer,
                &fixture.bundle,
                &identity,
                &certifier,
                &fixture.resolver,
                &[],
                None
            )
            .is_err()
    );
    assert!(endpoint.transport().requests.borrow().is_empty());
}
