//! Executable evidence of the current ordering/business-execution boundary.
//! Two alternative legitimate delivery chronologies have identical certified
//! inputs/order but different original business outcomes. This is not a claim
//! of same-run signature equivocation. It preserves the counterexample, not a fix.
use super::*;
use crate::ordered_economics::reservation::OrderedNonceLockHeld;
use canonical_encoding::decode_canonical_frame;
use consensus::bundle::PublicationBundle;
use execution::call::{CallIntent, InstanceTarget};
use execution::local_execution::{InstanceRecord, instance_target};
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidFeePolicy,
    PaidIntent, ReservationAccessKind, SignedPaidIntent, encode_signed_paid_intent,
    paid_fee_policy_digest, paid_intent_signing_frame,
};
use fee_claims::{FeeClaimPreparationRequest, PreparedFeeClaim};
use objects::{AccessMode, Object, ObjectRef, Owner};
use runtime::{
    DurableObjectHead, DurableObjectPayload, DurableObjectVersion, DurableObjectVersionRecord,
};

#[path = "causal_placement/business_reconstruction.rs"]
mod business_reconstruction;

struct CausalFixture {
    network: Network,
    manifest: GenesisManifest,
    instance: InstanceRecord,
    claimant_coin: Object,
}

fn setup_causal_fixture() -> CausalFixture {
    setup_fixture_profile(crate::logical_generation::CommitmentProfile::LogicalGenerationV2)
}

fn setup_fixture_profile(profile: crate::logical_generation::CommitmentProfile) -> CausalFixture {
    let signers: Vec<TestSigner> = signers();
    let mut manifest: GenesisManifest = four_validator_manifest(&signers);
    manifest.commitment_profile = profile;
    manifest.minimum_freeze_block_height = 1;
    // An ordinary address-owned object in the signed genesis, not a patched
    // business row or a special execution privilege for Standard Asset.
    let mut claimant_entry: GenesisObjectEntry = manifest.objects[1].clone();
    claimant_entry.object.id = ObjectId::new([0x21; 32]);
    claimant_entry.object.owner = Owner::Address(Address::new(*signers[1].id.as_bytes()));
    claimant_entry.authority.object_id = claimant_entry.object.id;
    manifest.objects.push(claimant_entry.clone());
    fixture::resign_manifest(&mut manifest);
    assert_eq!(
        decode_canonical_frame(&genesis::encode_genesis_manifest(&manifest).unwrap())
            .unwrap()
            .version(),
        if profile == crate::logical_generation::CommitmentProfile::CausalAdmission {
            4
        } else {
            3
        }
    );
    let context: DurableOperationContext = fixture::context(1);
    let stores: Vec<MemoryDurableStateStore> = (0..REPLICAS)
        .map(|_| {
            let store: MemoryDurableStateStore =
                MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
            genesis::install_genesis(
                &store,
                &context,
                fixture::domain(),
                &fixture::resolver(),
                &manifest,
                10,
            )
            .unwrap();
            store
        })
        .collect();
    let bond_key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &signers[0].id).unwrap();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(
        stores[0]
            .get_versioned_durable(&context, fixture::domain(), &bond_key)
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        genesis::genesis_manifest_commitment(&fixture::resolver(), &manifest).unwrap(),
        Some(&manifest),
        validator_set(&signers),
        fixture::resolver(),
    )
    .unwrap();
    let (_, _, instance, _, _) = fixture::build_fixture();
    let network: Network = Network {
        stores,
        context,
        policy,
        leg_policy: LocalExecutionPolicy::generic_object_results(fixture::protocol()),
        engine: LocalWasmExecutionEngine::new(),
        blobs: MemoryBlobStore::default(),
        resolver: fixture::resolver(),
        history: Vec::new(),
        signers,
        bond,
    };
    network.install_ordered();
    CausalFixture {
        network,
        manifest,
        instance,
        claimant_coin: claimant_entry.object,
    }
}

fn fresh_fixture() -> CausalFixture {
    setup_fixture_profile(crate::logical_generation::CommitmentProfile::CausalAdmission)
}

fn object_ref(network: &Network, object: &Object) -> ObjectRef {
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: network
            .resolver
            .hash_for_purpose(
                fixture::protocol().epoch(),
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}

fn paid_transfer(
    fixture: &CausalFixture,
    signer_index: usize,
    coin: &Object,
    request_id: [u8; 32],
    nonce: u64,
) -> Vec<u8> {
    let network: &Network = &fixture.network;
    let signer: &TestSigner = &network.signers[signer_index];
    let sender: [u8; 32] = *signer.id.as_bytes();
    let source: ObjectRef = object_ref(network, coin);
    let call: CallIntent = CallIntent {
        context: fixture::protocol(),
        request_id,
        sender,
        nonce,
        code: fixture.instance.code.clone(),
        instance: instance_target(&network.resolver, &fixture.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&sender).unwrap(),
        gas_limit: 100_000,
    };
    let intent: PaidIntent = PaidIntent {
        context: fixture::protocol(),
        request_id,
        sender,
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&network.resolver, &fixture.manifest.fee_policy)
            .unwrap(),
        consent: FeeSourceConsent {
            source,
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: sender,
        },
        application: PaidApplication::Call(call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&fixture::protocol(), &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        signature: signer.key.sign(&frame).into(),
        intent,
    })
    .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct CertifiedPaidMaterial {
    bundle: Vec<u8>,
    certificate: Vec<u8>,
    availability_certificate: Vec<u8>,
    result: PaidExecutionResult,
}

fn certify_and_apply_paid(
    fixture: &CausalFixture,
    signed_bytes: &[u8],
    checkpoint: u64,
) -> CertifiedPaidMaterial {
    certify_paid_with_subsets(
        fixture,
        signed_bytes,
        checkpoint,
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        true,
    )
}

// Subsets contain genuine independently executed votes, not newly signed
// supplied commitments. Retention and application may legitimately carry
// different quorums for the identical certified execution subject.
fn certify_paid_with_subsets(
    fixture: &CausalFixture,
    signed_bytes: &[u8],
    checkpoint: u64,
    publication_signers: &[usize],
    execution_signers: &[usize],
    availability_signers: &[usize],
    apply: bool,
) -> CertifiedPaidMaterial {
    let network: &Network = &fixture.network;
    let fee_policy: &PaidFeePolicy = &fixture.manifest.fee_policy;
    // Every vote is independently derived through the actual paid WASM
    // execution/commitment path. No signer merely signs a supplied digest.
    let votes: Vec<consensus::FastVote> = (0..REPLICAS)
        .map(|replica| {
            crate::fast_path::prepare(
                &network.stores[replica],
                &network.blobs,
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &fixture::protocol(),
                &network.leg_policy,
                fee_policy,
                &network.engine,
                &network.signers[replica],
                signed_bytes,
                checkpoint,
            )
            .unwrap()
        })
        .collect();
    let set: ValidatorSet = validator_set(&network.signers);
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        set.clone(),
    )
    .unwrap();
    let certificate_for = |subset: &[usize]| -> consensus::FastCertificate {
        let selected: Vec<consensus::FastVote> = subset
            .iter()
            .map(|index: &usize| votes[*index].clone())
            .collect();
        certifier
            .try_form_certificate(
                votes[0].tx_hash,
                votes[0].execution_effects_hash,
                votes[0].locked_objects_digest,
                &selected,
                &crate::fast_path::FastPathEd25519Verifier,
            )
            .unwrap()
            .unwrap()
    };
    let publication_certificate: consensus::FastCertificate = certificate_for(publication_signers);
    let publication_certificate_bytes: Vec<u8> =
        consensus::encode_fast_certificate(&publication_certificate).unwrap();
    let certificate_bytes: Vec<u8> =
        consensus::encode_fast_certificate(&certificate_for(execution_signers)).unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &network.stores[0],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        signed_bytes,
        &publication_certificate_bytes,
    )
    .unwrap();
    assert_eq!(
        decode_canonical_frame(&bundle.witness).unwrap().version(),
        2
    );
    consensus::bundle::verify_publication_bundle(
        &bundle,
        &certifier,
        &crate::fast_path::FastPathEd25519Verifier,
        &network.resolver,
        &network.history,
    )
    .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let acknowledgements: Vec<consensus::AvailabilityVote> = (0..REPLICAS)
        .map(|replica| {
            crate::fast_path::publication::retain_publication(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &fixture::protocol(),
                &bundle_bytes,
                &network.signers[replica],
            )
            .unwrap()
        })
        .collect();
    let availability_certifier: consensus::AvailabilityCertifier =
        consensus::AvailabilityCertifier::new(
            fixture::chain(),
            fixture::protocol().protocol_version(),
            fixture::protocol().epoch(),
            set,
        )
        .unwrap();
    let availability: consensus::AvailabilityCertificate = availability_certifier
        .try_form_certificate(
            &acknowledgements[0].identity,
            &availability_signers
                .iter()
                .map(|index: &usize| acknowledgements[*index].clone())
                .collect::<Vec<consensus::AvailabilityVote>>(),
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let availability_bytes: Vec<u8> =
        consensus::encode_availability_certificate(&availability).unwrap();
    let (_, result): (Digest32, PaidExecutionResult) =
        crate::fast_path::publication::decode_certified_execution_witness(&bundle.witness).unwrap();
    assert_eq!(result.status, PaidExecutionStatus::Success);
    for replica in (0..REPLICAS).filter(|_| apply) {
        let output: NodeOutput = crate::fast_path::apply_after_publication(
            &network.stores[replica],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            fee_policy,
            &network.engine,
            signed_bytes,
            &certificate_bytes,
            &availability_bytes,
        )
        .unwrap();
        assert_eq!(
            execution::paid_execution::decode_paid_execution_result(
                output.responses()[0].payload().unwrap()
            )
            .unwrap(),
            result
        );
    }
    CertifiedPaidMaterial {
        bundle: bundle_bytes,
        certificate: certificate_bytes,
        availability_certificate: availability_bytes,
        result,
    }
}

fn nonce(network: &Network, replica: usize) -> u64 {
    query_sender_next_nonce(
        &network.stores[replica],
        &network.context,
        network.domain(),
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        *network.signers[1].id.as_bytes(),
    )
    .unwrap()
}

fn positive_claim(
    fixture: &CausalFixture,
    escrow_request: [u8; 32],
    request: [u8; 32],
) -> (OrderedCandidate, FastPathSettlementRecord) {
    positive_claim_for(fixture, escrow_request, request, 1, 1)
}

fn positive_claim_for(
    fixture: &CausalFixture,
    escrow_request: [u8; 32],
    request: [u8; 32],
    signer_index: usize,
    next_nonce: u64,
) -> (OrderedCandidate, FastPathSettlementRecord) {
    let network: &Network = &fixture.network;
    let signer: &TestSigner = &network.signers[signer_index];
    let recipient: Address = Address::new(*signer.id.as_bytes());
    let inspection: fee_claims::FeeClaimInspection = fee_claims::inspect_fee_claim(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        escrow_request,
        signer.id,
        *signer.id.as_bytes(),
        &network.leg_policy,
    )
    .unwrap();
    let view: &fee_claims::FeeClaimExecutionView = inspection.execution.as_ref().unwrap();
    assert_eq!(view.next_nonce, next_nonce);
    assert!(inspection.entitlement.amount > 0);
    let target: InstanceTarget = instance_target(&network.resolver, &fixture.instance).unwrap();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: network.leg_policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: fixture::protocol(),
            request_id: request,
            sender: *signer.id.as_bytes(),
            nonce: next_nonce,
            code: fixture.instance.code.clone(),
            instance: target,
            entrypoint: "split".into(),
            type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: object_ref(network, &view.fee_output),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::split_arguments(
                inspection.entitlement.amount,
                recipient.as_bytes(),
            )
            .unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&fixture::protocol(), &leg).unwrap();
    let signed_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: signer.key.sign(&frame).into(),
        intent: leg,
    })
    .unwrap();
    let prepared: PreparedFeeClaim = fee_claims::prepare_fee_claim(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &network.engine,
        FeeClaimPreparationRequest {
            escrow_request_id: escrow_request,
            request_id: request,
            validator_id: signer.id,
            claimant_public_key: *signer.id.as_bytes(),
            recipient,
            signed_leg: Some(&signed_leg),
        },
        13,
    )
    .unwrap();
    let digest: Digest32 =
        fee_claims::fee_claim_intent_digest(&network.resolver, &prepared.intent).unwrap();
    let frame: Vec<u8> = fee_claims::fee_claim_signing_frame(&fixture::protocol(), digest).unwrap();
    let signed: fee_claims::codec::SignedFeeClaimIntent = fee_claims::codec::SignedFeeClaimIntent {
        signature: signer.key.sign(&frame).into(),
        intent: prepared.intent,
    };
    (
        OrderedCandidate {
            context: fixture::protocol(),
            request_id: request,
            kind: OrderedOperationKind::FeeClaim,
            intent: fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
            created_checkpoint: 13,
        },
        prepared.next_settlement,
    )
}

fn settlement(network: &Network, replica: usize, escrow: [u8; 32]) -> FastPathSettlementRecord {
    let key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(&fixture::chain(), &escrow).unwrap();
    decode_fastpath_settlement_record(&network.value(replica, &key).unwrap()).unwrap()
}

fn history_material(network: &Network) -> OrderedHistoryHeightMaterial {
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    assert_eq!(identity.through_height, 1);
    let descriptor: OrderedHistoryHeightDescriptor = read_ordered_history_height_descriptor(
        &network.stores[0],
        &network.context,
        &network.env(),
        &identity,
        1,
    )
    .unwrap();
    let digest: Digest32 = ordered_history_descriptor_digest(&network.policy, &descriptor).unwrap();
    let components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = descriptor
        .components
        .iter()
        .map(|reference| {
            let bytes: Vec<u8> = read_ordered_history_component_chunk(
                &network.stores[0],
                &network.context,
                &network.env(),
                &identity,
                1,
                digest,
                reference.kind,
                0,
                MAX_ORDERED_HISTORY_CHUNK_BYTES as u32,
            )
            .unwrap();
            assert_eq!(u64::try_from(bytes.len()).unwrap(), reference.length);
            (reference.kind, bytes)
        })
        .collect();
    let material: OrderedHistoryHeightMaterial = OrderedHistoryHeightMaterial {
        descriptor,
        components,
    };
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity).unwrap();
    verifier.verify_next_height(&material).unwrap();
    verifier.finish().unwrap();
    material
}

#[test]
fn identical_logical_owned_material_and_ordered_proof_do_not_pin_original_nonce_refusal() {
    let before: CausalFixture = setup_causal_fixture();
    let after: CausalFixture = setup_causal_fixture();
    assert_eq!(before.manifest, after.manifest);
    assert_eq!(
        before.network.policy.anchor(),
        after.network.policy.anchor()
    );
    let escrow: [u8; 32] = [0xe1; 32];
    let independent: [u8; 32] = [0xe2; 32];
    let claim: [u8; 32] = [0xe3; 32];

    // The same certified paid operation by another sender creates the actual
    // target escrow on every replica in both chronologies.
    let c: Vec<u8> = paid_transfer(&before, 0, &before.manifest.objects[1].object, escrow, 0);
    assert_eq!(
        c,
        paid_transfer(&after, 0, &after.manifest.objects[1].object, escrow, 0)
    );
    assert_eq!(
        certify_and_apply_paid(&before, &c, 11),
        certify_and_apply_paid(&after, &c, 11)
    );
    let original: FastPathSettlementRecord = settlement(&before.network, 0, escrow);
    assert_eq!(original, settlement(&after.network, 0, escrow));
    assert_eq!(nonce(&before.network, 0), 0);

    // B: O is an independent nonce-0 paid operation with its own genesis
    // input, not the fee escrow consumed by the claim. It runs before claim.
    let o: Vec<u8> = paid_transfer(&before, 1, &before.claimant_coin, independent, 0);
    assert_eq!(
        o,
        paid_transfer(&after, 1, &after.claimant_coin, independent, 0)
    );
    let after_owned: CertifiedPaidMaterial = certify_and_apply_paid(&after, &o, 12);
    let (candidate, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&after, escrow, claim);
    authenticate_candidate(&before.network.env(), &candidate).unwrap();
    authenticate_candidate(&after.network.env(), &candidate).unwrap();

    // Both chronologies genuinely admit/sign/certify the SAME candidate and
    // its two empty followers. A has nonce 0; B has nonce 1. No proposal or
    // certificate is forged, transplanted or bypasses signing admission.
    let mut terminal: Option<QuorumCertificate> = None;
    for view in 1..=3 {
        let item: Option<&OrderedCandidate> = (view == 1).then_some(&candidate);
        let (a_outputs, a_certificate, a_proposal) = before.network.round(view, item);
        let (b_outputs, b_certificate, b_proposal) = after.network.round(view, item);
        assert_eq!(a_proposal, b_proposal);
        assert_eq!(a_certificate, b_certificate);
        if view == 3 {
            for replica in 0..REPLICAS {
                assert_eq!(a_outputs[replica].committed.len(), 1);
                assert_eq!(b_outputs[replica].committed.len(), 1);
                let a: &OrderedOutcome = &a_outputs[replica].committed[0];
                let b: &OrderedOutcome = &b_outputs[replica].committed[0];
                assert_eq!(a.candidate_digest, b.candidate_digest);
                assert_eq!(a.block_height, b.block_height);
                assert_eq!(a.block_digest, b.block_digest);
                assert_eq!(refusal_of(a), OrderedRefusal::StaleSenderNonce);
                assert_eq!(
                    b.output.responses()[0].status(),
                    NodeResponseStatus::Accepted
                );
                assert_ne!(a.output, b.output);
                assert_eq!(nonce(&before.network, replica), 0);
                assert_eq!(nonce(&after.network, replica), 2);
                assert_eq!(settlement(&before.network, replica, escrow), original);
                assert_eq!(settlement(&after.network, replica, escrow), expected);
            }
            terminal = Some(a_certificate);
        }
    }

    // A: only after the genuine no-effect refusal released its reservation,
    // O can prepare and apply. Its exact signed v2 witness, actual closure,
    // FastCertificate, availability certificate and paid result equal B's.
    let before_owned: CertifiedPaidMaterial = certify_and_apply_paid(&before, &o, 12);
    assert_eq!(before_owned, after_owned);
    for replica in 0..REPLICAS {
        assert_eq!(nonce(&before.network, replica), 1);
        assert_eq!(nonce(&after.network, replica), 2);
        assert_eq!(settlement(&before.network, replica, escrow), original);
        assert_eq!(settlement(&after.network, replica, escrow), expected);
    }
    let a_material: OrderedHistoryHeightMaterial = history_material(&before.network);
    let b_material: OrderedHistoryHeightMaterial = history_material(&after.network);
    assert_eq!(
        a_material.descriptor.identity,
        b_material.descriptor.identity
    );
    for kind in [
        OrderedHistoryComponentKind::CommitProof,
        OrderedHistoryComponentKind::Candidate,
        OrderedHistoryComponentKind::RequestHeader,
    ] {
        assert_eq!(
            a_material
                .components
                .iter()
                .find(|(k, _)| *k == kind)
                .unwrap(),
            b_material
                .components
                .iter()
                .find(|(k, _)| *k == kind)
                .unwrap()
        );
    }
    for kind in [
        OrderedHistoryComponentKind::RetainedOutcome,
        OrderedHistoryComponentKind::OriginalReceipt,
    ] {
        assert_ne!(
            a_material
                .components
                .iter()
                .find(|(k, _)| *k == kind)
                .unwrap(),
            b_material
                .components
                .iter()
                .find(|(k, _)| *k == kind)
                .unwrap()
        );
    }
    assert_ne!(a_material, b_material);

    // Later nonce availability and exact certificate replay do not revise
    // A's original refusal or charge O/claim again. B retains its success.
    let terminal: QuorumCertificate = terminal.unwrap();
    for fixture in [&before, &after] {
        let network: &Network = &fixture.network;
        for replica in 0..REPLICAS {
            let outcome: OrderedOutcome = query_ordered_outcome(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &claim,
            )
            .unwrap()
            .unwrap();
            let before_replay = network.snapshot(replica, &[escrow, independent, claim], 3);
            assert!(
                process_certificate(
                    &network.stores[replica],
                    &network.context,
                    &network.env(),
                    &terminal,
                )
                .unwrap()
                .committed
                .is_empty()
            );
            assert_eq!(
                network.snapshot(replica, &[escrow, independent, claim], 3),
                before_replay
            );
            assert_eq!(
                query_ordered_outcome(
                    &network.stores[replica],
                    &network.context,
                    &network.env(),
                    &claim
                )
                .unwrap()
                .unwrap(),
                outcome
            );
        }
    }
}

struct CountingConsensusSigner<'a> {
    signer: &'a TestSigner,
    calls: std::cell::Cell<usize>,
}

impl ConsensusSigner for CountingConsensusSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.signer.validator_id()
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        self.signer.signature_scheme()
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get().checked_add(1).unwrap());
        self.signer.sign_framed(frame)
    }
}

fn receipt(network: &Network, replica: usize, request: [u8; 32]) -> Option<DurableRequestReceipt> {
    network.stores[replica]
        .get_request_receipt(
            &network.context,
            network.domain(),
            DurableRequestId::new(request).unwrap(),
        )
        .unwrap()
}

fn recover_paid(
    fixture: &CausalFixture,
    replica: usize,
    signed: &[u8],
    material: &CertifiedPaidMaterial,
    checkpoint: u64,
) {
    let network: &Network = &fixture.network;
    crate::fast_path::publication::retain_publication(
        &network.stores[replica],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &material.bundle,
        &network.signers[replica],
    )
    .unwrap();
    let actual: NodeOutput = crate::fast_path::apply_with_recovery_after_publication(
        &network.stores[replica],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &fixture.manifest.fee_policy,
        &network.engine,
        signed,
        &material.certificate,
        checkpoint,
        &material.availability_certificate,
    )
    .unwrap();
    assert_eq!(
        execution::paid_execution::decode_paid_execution_result(
            actual.responses()[0].payload().unwrap(),
        )
        .unwrap(),
        material.result
    );
}

#[test]
fn causal_future_nonce_stops_without_signature_or_writes_then_exact_owned_recovery_admits() {
    let missing: CausalFixture = fresh_fixture();
    let ready: CausalFixture = fresh_fixture();
    let escrow: [u8; 32] = [0x61; 32];
    let independent: [u8; 32] = [0x62; 32];
    let claim: [u8; 32] = [0xe3; 32];
    let c: Vec<u8> = paid_transfer(&missing, 0, &missing.manifest.objects[1].object, escrow, 0);
    assert_eq!(
        certify_and_apply_paid(&missing, &c, 11),
        certify_and_apply_paid(&ready, &c, 11)
    );
    let o: Vec<u8> = paid_transfer(&ready, 1, &ready.claimant_coin, independent, 0);
    let producer: CertifiedPaidMaterial = certify_and_apply_paid(&ready, &o, 12);
    let (candidate, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&ready, escrow, claim);
    let network: &Network = &missing.network;
    let leader: usize = network.leader_index(1);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[leader],
        calls: std::cell::Cell::new(0),
    };
    let before = network.snapshot(leader, &[claim], 1);
    let escrow_before: FastPathSettlementRecord = settlement(network, leader, escrow);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &signer
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(network.snapshot(leader, &[claim], 1), before);
    assert!(receipt(network, leader, claim).is_none());
    assert_eq!(settlement(network, leader, escrow), escrow_before);
    assert_eq!(nonce(network, leader), 0);

    // A genuine ready leader's proposal is not a licence for a missing
    // predecessor to be converted into a locally selected stale refusal.
    let ready_leader: usize = ready.network.leader_index(1);
    let proposal: OrderedProposal = propose(
        &ready.network.stores[ready_leader],
        &ready.network.context,
        &ready.network.env(),
        Some(&candidate),
        &ready.network.signers[ready_leader],
    )
    .unwrap();
    assert!(matches!(
        process_proposal(
            &network.stores[leader],
            &network.context,
            &network.env(),
            &proposal,
            &signer
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(network.snapshot(leader, &[claim], 1), before);

    for replica in 0..REPLICAS {
        recover_paid(&missing, replica, &o, &producer, 12);
    }
    let producer_receipt: DurableRequestReceipt = receipt(network, 0, independent).unwrap();
    let mut terminal: Option<QuorumCertificate> = None;
    for view in 1..=3 {
        let (outputs, certificate, _) = network.round(view, (view == 1).then_some(&candidate));
        if view == 3 {
            assert!(
                outputs
                    .iter()
                    .all(|output| output.committed[0].output.responses()[0].status()
                        == NodeResponseStatus::Accepted)
            );
            terminal = Some(certificate);
        }
    }
    assert_eq!(nonce(network, 0), 2);
    assert_eq!(settlement(network, 0, escrow), expected);
    assert_eq!(receipt(network, 0, independent).unwrap(), producer_receipt);
    let original: DurableRequestReceipt = receipt(network, 0, claim).unwrap();
    let replay_before = network.snapshot(0, &[claim], 3);
    process_certificate(
        &network.stores[0],
        &network.context,
        &network.env(),
        &terminal.unwrap(),
    )
    .unwrap();
    assert_eq!(receipt(network, 0, claim).unwrap(), original);
    assert_eq!(network.snapshot(0, &[claim], 3), replay_before);
    assert_eq!(nonce(network, 0), 2);
}

fn current_object(network: &Network, replica: usize, id: ObjectId) -> Object {
    let head: DurableObjectHead = network.stores[replica]
        .get_object_head(&network.context, network.domain(), id)
        .unwrap();
    let version: DurableObjectVersion = head.object_version().unwrap();
    let record: DurableObjectVersionRecord = network.stores[replica]
        .get_object_version(&network.context, network.domain(), id, version)
        .unwrap()
        .unwrap();
    match record.payload() {
        DurableObjectPayload::Inline(inline) => inline.object().clone(),
        DurableObjectPayload::BlobReference(_) => panic!("genuine genesis/paid fixture is inline"),
    }
}

#[test]
fn causal_successor_applies_justified_business_prefix_before_nonce_admission() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let first_escrow: [u8; 32] = [0x64; 32];
    let second_escrow: [u8; 32] = [0x65; 32];
    let independent: [u8; 32] = [0x66; 32];
    let first_claim: [u8; 32] = [0xe4; 32];
    let second_claim: [u8; 32] = [0xe5; 32];
    let first: Vec<u8> = paid_transfer(
        &fixture,
        0,
        &fixture.manifest.objects[1].object,
        first_escrow,
        0,
    );
    certify_and_apply_paid(&fixture, &first, 11);
    let source: Object = current_object(network, 0, fixture.manifest.objects[1].object.id);
    let second: Vec<u8> = paid_transfer(&fixture, 0, &source, second_escrow, 1);
    certify_and_apply_paid(&fixture, &second, 12);
    let independent_bytes: Vec<u8> =
        paid_transfer(&fixture, 1, &fixture.claimant_coin, independent, 0);
    certify_and_apply_paid(&fixture, &independent_bytes, 12);
    let (first_candidate, _): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&fixture, first_escrow, first_claim);
    network.round(1, Some(&first_candidate));
    network.round(2, None);
    let (terminal, _) = network.certify(3, None);
    let delayed: usize = (1..REPLICAS)
        .find(|replica| *replica != network.leader_index(4))
        .unwrap();
    for replica in 0..REPLICAS {
        if replica != delayed {
            process_certificate(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &terminal,
            )
            .unwrap();
        }
    }
    assert_eq!(nonce(network, delayed), 1);
    assert_eq!(nonce(network, network.leader_index(4)), 2);
    let (next_candidate, _): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim_for(&fixture, second_escrow, second_claim, 1, 2);
    let leader: usize = network.leader_index(4);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&next_candidate),
        &network.signers[leader],
    )
    .unwrap();
    let output: OrderedEventOutput = process_proposal(
        &network.stores[delayed],
        &network.context,
        &network.env(),
        &proposal,
        &network.signers[delayed],
    )
    .unwrap();
    assert_eq!(output.committed.len(), 1);
    assert_eq!(output.committed[0].request_id, first_claim);
    assert_eq!(nonce(network, delayed), 2);
    assert!(
        output
            .messages
            .iter()
            .any(|message| matches!(message, ConsensusMessage::Vote(_)))
    );
    assert!(receipt(network, delayed, first_claim).is_some());
    assert!(receipt(network, delayed, second_claim).is_none());
}

#[test]
fn causal_different_senders_keep_prefix_derived_stale_generation_without_custody_locks() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let escrow: [u8; 32] = [0x67; 32];
    let independent: [u8; 32] = [0x68; 32];
    let first_claim: [u8; 32] = [0xe6; 32];
    let second_claim: [u8; 32] = [0xe7; 32];
    let c: Vec<u8> = paid_transfer(&fixture, 0, &fixture.manifest.objects[1].object, escrow, 0);
    certify_and_apply_paid(&fixture, &c, 11);
    let o: Vec<u8> = paid_transfer(&fixture, 1, &fixture.claimant_coin, independent, 0);
    certify_and_apply_paid(&fixture, &o, 12);
    let (first, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&fixture, escrow, first_claim);
    let (stale, _): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim_for(&fixture, escrow, second_claim, 2, 0);
    assert!(
        reservation::reservation_plan(&network.env(), &first)
            .unwrap()
            .objects
            .is_empty()
    );
    assert!(
        reservation::reservation_plan(&network.env(), &stale)
            .unwrap()
            .objects
            .is_empty()
    );
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&first));
    }
    for view in 4..=6 {
        let (outputs, _, _) = network.round(view, (view == 4).then_some(&stale));
        if view == 6 {
            for (replica, output) in outputs.iter().enumerate() {
                assert_eq!(
                    refusal_of(&output.committed[0]),
                    OrderedRefusal::StaleGeneration
                );
                assert_eq!(settlement(network, replica, escrow), expected);
                assert_eq!(
                    query_sender_next_nonce(
                        &network.stores[replica],
                        &network.context,
                        network.domain(),
                        fixture::chain(),
                        fixture::protocol().protocol_version(),
                        fixture::protocol().epoch(),
                        *network.signers[2].id.as_bytes()
                    )
                    .unwrap(),
                    0
                );
            }
        }
    }
}

#[test]
fn causal_zero_leg_ordered_request_namespace_is_closed_before_any_admission() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let recipient: Address = Address::new(*network.signers[0].id.as_bytes());
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 13, *recipient.as_bytes());
    let owned_id: [u8; 32] = [0x69; 32];
    let wrong: OrderedCandidate =
        unbond_candidate(network, &network.bond, &next, owned_id, recipient, 13);
    let leader: usize = network.leader_index(1);
    let before = network.snapshot(leader, &[owned_id], 1);
    for kind in [
        OrderedOperationKind::FeeClaim,
        OrderedOperationKind::BondLifecycle,
        OrderedOperationKind::BondSlash,
        OrderedOperationKind::Evidence,
        OrderedOperationKind::Freeze,
        OrderedOperationKind::DrainSet,
    ] {
        // The external-ID boundary precedes kind-specific decoding. Only
        // BondLifecycle below is a complete genuine candidate control.
        let mut other: OrderedCandidate = wrong.clone();
        other.kind = kind;
        assert!(matches!(
            authenticate_candidate(&network.env(), &other),
            Err(OrderedEconomicsError::Unauthenticated(_))
        ));
    }
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&wrong),
            &network.signers[leader]
        ),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
    assert_eq!(network.snapshot(leader, &[owned_id], 1), before);
    let ordered_id: [u8; 32] = [0xe9; 32];
    let valid: OrderedCandidate =
        unbond_candidate(network, &network.bond, &next, ordered_id, recipient, 13);
    authenticate_candidate(&network.env(), &valid).unwrap();
    assert!(
        reservation::reservation_plan(&network.env(), &valid)
            .unwrap()
            .is_empty()
    );
    let synthetic: [u8; 32] = reservation::ordered_admission_request_id(
        &network.resolver,
        fixture::protocol().epoch(),
        &ordered_id,
        network.policy.candidate_digest(&valid).unwrap(),
        reservation::OrderedAdmissionStage::Vote,
        1,
    )
    .unwrap();
    let synthetic_candidate: OrderedCandidate =
        unbond_candidate(network, &network.bond, &next, synthetic, recipient, 13);
    assert!(authenticate_candidate(&network.env(), &synthetic_candidate).is_err());
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&valid));
    }
    assert_eq!(network.committed_bond(0), next);
    assert!(receipt(network, 0, ordered_id).is_some());
    assert!(receipt(network, 0, owned_id).is_none());
}

fn ordered_transfer_leg(
    fixture: &CausalFixture,
    object: ObjectRef,
    request: [u8; 32],
    nonce: u64,
    operand: &[u8; 32],
) -> Vec<u8> {
    let network: &Network = &fixture.network;
    let signer: &TestSigner = &network.signers[0];
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: network.leg_policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: fixture::protocol(),
            request_id: request,
            sender: *signer.id.as_bytes(),
            nonce,
            code: fixture.instance.code.clone(),
            instance: instance_target(&network.resolver, &fixture.instance).unwrap(),
            entrypoint: "transfer".into(),
            type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: object,
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(operand).unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&fixture::protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: signer.key.sign(&frame).into(),
        intent,
    })
    .unwrap()
}

fn replacement(
    fixture: &CausalFixture,
    request: [u8; 32],
) -> (OrderedCandidate, FastPathBondRecord) {
    let network: &Network = &fixture.network;
    let previous: &FastPathBondRecord = &network.bond;
    let entry: &GenesisObjectEntry = &fixture.manifest.objects[1];
    let scope: objects::ProtocolCustodyScope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::BondCollateral,
        chain_id: fixture::chain(),
        subject: *previous.validator_id.as_bytes(),
        resource: previous.resource,
    };
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &network.resolver,
        &fixture::protocol(),
        entry.object.id,
        &scope,
    )
    .unwrap();
    let recipient: Address = Address::new(*network.signers[0].id.as_bytes());
    let deposit: Vec<u8> = ordered_transfer_leg(
        fixture,
        object_ref(network, &entry.object),
        request,
        0,
        &token,
    );
    let release: Vec<u8> = ordered_transfer_leg(
        fixture,
        previous.custody_object.clone(),
        request,
        1,
        recipient.as_bytes(),
    );
    let mut deposited: Object = entry.object.clone();
    deposited.version = deposited.version.checked_add(1).unwrap();
    deposited.owner = Owner::ProtocolCustody(scope);
    let mut next: FastPathBondRecord = previous.clone();
    next.generation = next.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = 13;
    next.lifecycle_epoch = fixture::protocol().epoch();
    next.custody_object = object_ref(network, &deposited);
    next.custody_object_epoch = fixture::protocol().epoch();
    next.authority = entry.authority.clone();
    let intent: BondLifecycleIntent = BondLifecycleIntent {
        context: fixture::protocol(),
        request_id: request,
        validator_id: previous.validator_id,
        resource_id: BondResourceId::new(previous.resource_domain, previous.resource).unwrap(),
        expected_generation: previous.generation,
        expected_previous_row_digest: bond_row_digest(
            &network.resolver,
            previous.lifecycle_epoch,
            &encode_fastpath_bond_record(previous).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_row_digest(
            &network.resolver,
            next.lifecycle_epoch,
            &encode_fastpath_bond_record(&next).unwrap(),
        )
        .unwrap(),
        operation: BondLifecycleOperation::Replace {
            deposit_leg: deposit,
            release_leg: release,
            release_recipient: recipient,
        },
    };
    (
        OrderedCandidate {
            context: fixture::protocol(),
            request_id: request,
            kind: OrderedOperationKind::BondLifecycle,
            intent: encode_signed_bond_lifecycle_intent(&sign_bond_lifecycle(
                &network.resolver,
                intent,
            ))
            .unwrap(),
            created_checkpoint: 13,
        },
        next,
    )
}

#[test]
fn causal_replace_fences_two_nonce_legs_and_exact_head_with_distinct_internal_receipts() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let request: [u8; 32] = [0xea; 32];
    let (candidate, expected): (OrderedCandidate, FastPathBondRecord) =
        replacement(&fixture, request);
    let digest: Digest32 = network.policy.candidate_digest(&candidate).unwrap();
    let plan: reservation::OrderedReservationPlan =
        reservation::reservation_plan(&network.env(), &candidate).unwrap();
    assert_eq!(
        plan.objects,
        vec![object_ref(network, &fixture.manifest.objects[1].object)]
    );
    let required: OrderedCausalRequirements =
        ordered_causal_requirements(&network.env(), &candidate).unwrap();
    let held: OrderedNonceLockHeld = required.nonce.unwrap();
    assert_eq!(held.count, 2);
    assert_eq!(required.objects, plan.objects);
    assert_eq!(required.legs.len(), 2);
    assert!(required.fee_escrow_request_id.is_none());
    let leader: usize = network.leader_index(1);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    let leader_receipt_id: [u8; 32] = reservation::ordered_admission_request_id(
        &network.resolver,
        fixture::protocol().epoch(),
        &request,
        digest,
        reservation::OrderedAdmissionStage::LeaderProposal,
        1,
    )
    .unwrap();
    let vote_receipt_id: [u8; 32] = reservation::ordered_admission_request_id(
        &network.resolver,
        fixture::protocol().epoch(),
        &request,
        digest,
        reservation::OrderedAdmissionStage::Vote,
        1,
    )
    .unwrap();
    let leader_receipt: DurableRequestReceipt =
        receipt(network, leader, leader_receipt_id).unwrap();
    assert_ne!(leader_receipt_id, vote_receipt_id);
    assert!(receipt(network, leader, request).is_none());
    let before = network.snapshot(leader, &[request], 1);
    assert_eq!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader]
        )
        .unwrap(),
        proposal
    );
    assert_eq!(network.snapshot(leader, &[request], 1), before);
    assert_eq!(
        receipt(network, leader, leader_receipt_id).unwrap(),
        leader_receipt
    );
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for replica in 0..REPLICAS {
        let output: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[replica],
        )
        .unwrap();
        let vote: ConsensusVote = output
            .messages
            .iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            })
            .unwrap();
        let original_bookkeeping: DurableRequestReceipt =
            receipt(network, replica, vote_receipt_id).unwrap();
        let before = network.snapshot(replica, &[request], 1);
        let replay: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[replica],
        )
        .unwrap();
        assert_eq!(replay.messages, output.messages);
        assert_eq!(network.snapshot(replica, &[request], 1), before);
        assert_eq!(
            receipt(network, replica, vote_receipt_id).unwrap(),
            original_bookkeeping
        );
        assert!(receipt(network, replica, request).is_none());
        votes.push(vote);
    }
    let certificate: QuorumCertificate = network
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &super::super::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .unwrap();
    for store in &network.stores {
        process_certificate(store, &network.context, &network.env(), &certificate).unwrap();
    }
    network.round(2, None);
    network.round(3, None);
    for replica in 0..REPLICAS {
        assert_eq!(network.committed_bond(replica), expected);
        assert_eq!(
            query_sender_next_nonce(
                &network.stores[replica],
                &network.context,
                network.domain(),
                fixture::chain(),
                fixture::protocol().protocol_version(),
                fixture::protocol().epoch(),
                *network.signers[0].id.as_bytes()
            )
            .unwrap(),
            2
        );
        assert!(receipt(network, replica, request).is_some());
        assert!(receipt(network, replica, vote_receipt_id).is_some());
        assert_eq!(
            current_object(network, replica, fixture.manifest.objects[1].object.id).owner,
            Owner::ProtocolCustody(objects::ProtocolCustodyScope {
                purpose: objects::ProtocolCustodyPurpose::BondCollateral,
                chain_id: fixture::chain(),
                subject: *network.bond.validator_id.as_bytes(),
                resource: network.bond.resource,
            })
        );
    }
}

#[test]
fn ordered_admission_synthetic_ids_bind_stage_view_epoch_candidate_and_not_owned_prepare() {
    let resolver: HashSuiteResolver = fixture::resolver();
    let request: [u8; 32] = [0xeb; 32];
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x71; 32]);
    let derive = |epoch, original: &[u8; 32], digest, stage, view| {
        reservation::ordered_admission_request_id(&resolver, epoch, original, digest, stage, view)
            .unwrap()
    };
    let first: [u8; 32] = derive(
        Epoch::new(0),
        &request,
        digest,
        reservation::OrderedAdmissionStage::Vote,
        1,
    );
    assert_eq!(
        first,
        [
            83, 69, 58, 70, 80, 118, 49, 58, 84, 242, 219, 245, 96, 189, 51, 121, 218, 130, 170,
            34, 22, 63, 155, 61, 217, 15, 87, 205, 91, 228, 240, 86
        ]
    );
    let ids: [[u8; 32]; 7] = [
        first,
        derive(
            Epoch::new(0),
            &request,
            digest,
            reservation::OrderedAdmissionStage::LeaderProposal,
            1,
        ),
        derive(
            Epoch::new(0),
            &request,
            digest,
            reservation::OrderedAdmissionStage::Vote,
            2,
        ),
        derive(
            Epoch::new(1),
            &request,
            digest,
            reservation::OrderedAdmissionStage::Vote,
            1,
        ),
        derive(
            Epoch::new(0),
            &[0xec; 32],
            digest,
            reservation::OrderedAdmissionStage::Vote,
            1,
        ),
        derive(
            Epoch::new(0),
            &request,
            Digest32::new(HashAlgorithmId::Sha2_256, [0x72; 32]),
            reservation::OrderedAdmissionStage::Vote,
            1,
        ),
        local_instance_state::fastpath_synthetic_prepare_request_id(
            &resolver,
            Epoch::new(0),
            &request,
        )
        .unwrap(),
    ];
    let unique: std::collections::BTreeSet<[u8; 32]> = ids.into_iter().collect();
    assert_eq!(unique.len(), ids.len());
    assert!(
        unique
            .iter()
            .all(local_instance_state::is_reserved_paid_request_id)
    );
    assert_eq!(
        first,
        derive(
            Epoch::new(0),
            &request,
            digest,
            reservation::OrderedAdmissionStage::Vote,
            1
        )
    );
}

fn replace_history_component(
    policy: &OrderedEconomicsPolicy,
    material: &mut OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
    bytes: Vec<u8>,
) {
    let reference: &mut OrderedHistoryComponentRef = material
        .descriptor
        .components
        .iter_mut()
        .find(|reference| reference.kind == kind)
        .unwrap();
    reference.length = u64::try_from(bytes.len()).unwrap();
    reference.digest = ordered_history_component_digest(policy, &bytes).unwrap();
    *material
        .components
        .iter_mut()
        .find(|(found, _)| *found == kind)
        .unwrap() = (kind, bytes);
}

#[test]
fn isolated_ordered_reconstruction_requires_actual_causal_producers_and_rejects_matching_false_companions()
 {
    let source: CausalFixture = fresh_fixture();
    let overlay: CausalFixture = fresh_fixture();
    let network: &Network = &source.network;
    let escrow: [u8; 32] = [0x6a; 32];
    let independent: [u8; 32] = [0x6b; 32];
    let claim: [u8; 32] = [0xed; 32];
    let c: Vec<u8> = paid_transfer(&source, 0, &source.manifest.objects[1].object, escrow, 0);
    let escrow_material: CertifiedPaidMaterial = certify_and_apply_paid(&source, &c, 11);
    let o: Vec<u8> = paid_transfer(&source, 1, &source.claimant_coin, independent, 0);
    let nonce_material: CertifiedPaidMaterial = certify_and_apply_paid(&source, &o, 12);
    let (candidate, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&source, escrow, claim);
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&candidate));
    }
    let material: OrderedHistoryHeightMaterial = history_material(network);
    let mut verifier: OrderedHistoryVerifier = OrderedHistoryVerifier::new(
        overlay.network.policy.clone(),
        material.descriptor.identity.clone(),
    )
    .unwrap();
    recover_paid(&overlay, 0, &c, &escrow_material, 11);
    let before = overlay.network.snapshot(0, &[claim], 3);
    assert!(matches!(
        engine::reconstruct_ordered_history_height(
            &overlay.network.stores[0],
            &overlay.network.context,
            &overlay.network.env(),
            &mut verifier,
            &material,
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(verifier.height(), 0);
    assert_eq!(overlay.network.snapshot(0, &[claim], 3), before);
    assert!(receipt(&overlay.network, 0, claim).is_none());
    recover_paid(&overlay, 0, &o, &nonce_material, 12);

    // Companions are mutually consistent and canonically linked to the
    // real signed candidate, but are deliberately a false business claim.
    // No SQL row, signature, QC, owned witness or actual effect is forged.
    let mut counterfeit: OrderedHistoryHeightMaterial = material.clone();
    let mut claimed: OrderedOutcome =
        query_ordered_outcome(&network.stores[0], &network.context, &network.env(), &claim)
            .unwrap()
            .unwrap();
    claimed.output = engine::refusal_output_for_tests(claim, OrderedRefusal::StaleSenderNonce);
    let original: DurableRequestReceipt = receipt(network, 0, claim).unwrap();
    let false_receipt: Vec<u8> = NodeDedupRecord::new(
        RequestId::new(claim).unwrap(),
        claimed.candidate_digest,
        claimed.output.responses().to_vec(),
    )
    .unwrap()
    .encode()
    .unwrap();
    replace_history_component(
        &network.policy,
        &mut counterfeit,
        OrderedHistoryComponentKind::RetainedOutcome,
        engine::encode_retained_outcome_for_tests(&claimed),
    );
    replace_history_component(
        &network.policy,
        &mut counterfeit,
        OrderedHistoryComponentKind::OriginalReceipt,
        false_receipt,
    );
    let mut structural: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), material.descriptor.identity.clone())
            .unwrap();
    structural.verify_next_height(&counterfeit).unwrap();
    structural.finish().unwrap();
    let before = overlay.network.snapshot(0, &[claim], 3);
    let escrow_before: FastPathSettlementRecord = settlement(&overlay.network, 0, escrow);
    assert!(
        engine::reconstruct_ordered_history_height(
            &overlay.network.stores[0],
            &overlay.network.context,
            &overlay.network.env(),
            &mut verifier,
            &counterfeit
        )
        .is_err()
    );
    assert_eq!(verifier.height(), 0);
    assert_eq!(overlay.network.snapshot(0, &[claim], 3), before);
    assert_eq!(settlement(&overlay.network, 0, escrow), escrow_before);
    assert_eq!(nonce(&overlay.network, 0), 1);
    assert!(receipt(&overlay.network, 0, claim).is_none());

    let derived: OrderedOutcome = engine::reconstruct_ordered_history_height(
        &overlay.network.stores[0],
        &overlay.network.context,
        &overlay.network.env(),
        &mut verifier,
        &material,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        derived,
        query_ordered_outcome(&network.stores[0], &network.context, &network.env(), &claim)
            .unwrap()
            .unwrap()
    );
    assert_eq!(receipt(&overlay.network, 0, claim).unwrap(), original);
    assert_eq!(settlement(&overlay.network, 0, escrow), expected);
    assert_eq!(nonce(&overlay.network, 0), 2);
    assert_eq!(verifier.height(), 1);
    verifier.finish().unwrap();
}

#[test]
fn causal_direct_unbond_and_local_execution_deny_fresh_but_original_ordered_receipt_replays() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let request: [u8; 32] = [0xee; 32];
    let recipient: Address = Address::new(*network.signers[0].id.as_bytes());
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 13, *recipient.as_bytes());
    let candidate: OrderedCandidate =
        unbond_candidate(network, &network.bond, &next, request, recipient, 13);
    let before = network.snapshot(0, &[request], 3);
    assert!(
        bond_lifecycle::handle_bond_lifecycle(
            &network.stores[0],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &network.engine,
            &candidate.intent,
            13
        )
        .is_err()
    );
    let direct_request: [u8; 32] = [0x6c; 32];
    let leg: Vec<u8> = ordered_transfer_leg(
        &fixture,
        object_ref(network, &fixture.manifest.objects[1].object),
        direct_request,
        0,
        recipient.as_bytes(),
    );
    assert!(
        crate::local_execution::handle_local_execution(
            &network.stores[0],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &network.leg_policy,
            &network.engine,
            &leg,
            13
        )
        .is_err()
    );
    assert_eq!(network.snapshot(0, &[request], 3), before);
    assert!(receipt(network, 0, request).is_none());
    assert!(receipt(network, 0, direct_request).is_none());
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&candidate));
    }
    let original: DurableRequestReceipt = receipt(network, 0, request).unwrap();
    let before = network.snapshot(0, &[request], 3);
    let output: NodeOutput = bond_lifecycle::handle_bond_lifecycle(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &network.engine,
        &candidate.intent,
        99,
    )
    .unwrap();
    assert_eq!(
        output,
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &request
        )
        .unwrap()
        .unwrap()
        .output
    );
    assert_eq!(receipt(network, 0, request).unwrap(), original);
    assert_eq!(network.snapshot(0, &[request], 3), before);
}

/// Delivers a genuine certified paid producer immediately before the real
/// ordered admission commit. It neither fabricates a business row nor edits
/// a certificate, and retains the admission transaction for its head-only
/// negative control below.
struct PaidHeadRaceStore<'a> {
    fixture: &'a CausalFixture,
    replica: usize,
    signed: &'a [u8],
    producer: &'a CertifiedPaidMaterial,
    raced: std::cell::Cell<bool>,
    captured: std::cell::RefCell<Option<DurableInvocationTransaction>>,
}

impl DurableDomainStateStore for PaidHeadRaceStore<'_> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.fixture.network.stores[self.replica].get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.fixture.network.stores[self.replica].commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for PaidHeadRaceStore<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.fixture.network.stores[self.replica].get_object_head(context, domain, object)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.fixture.network.stores[self.replica]
            .get_object_version(context, domain, object, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.fixture.network.stores[self.replica].get_request_receipt(context, domain, request)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        assert!(!self.raced.replace(true));
        *self.captured.borrow_mut() = Some(transaction.clone());
        recover_paid(self.fixture, self.replica, self.signed, self.producer, 11);
        self.fixture.network.stores[self.replica].commit_invocation(context, transaction)
    }
}

#[test]
fn causal_ordered_head_assertion_rejects_real_certified_paid_update_even_without_nonce_read_control()
 {
    let target: CausalFixture = fresh_fixture();
    let source: CausalFixture = fresh_fixture();
    let network: &Network = &target.network;
    let owned_request: [u8; 32] = [0x6d; 32];
    let ordered_request: [u8; 32] = [0xef; 32];
    let signed: Vec<u8> = paid_transfer(
        &source,
        0,
        &source.manifest.objects[1].object,
        owned_request,
        0,
    );
    let producer: CertifiedPaidMaterial = certify_and_apply_paid(&source, &signed, 11);
    let (candidate, _): (OrderedCandidate, FastPathBondRecord) =
        replacement(&target, ordered_request);
    let replica: usize = network.leader_index(1);
    let before = network.snapshot(replica, &[ordered_request], 1);
    let original_head: DurableObjectHead = network.stores[replica]
        .get_object_head(
            &network.context,
            network.domain(),
            target.manifest.objects[1].object.id,
        )
        .unwrap();
    let racing: PaidHeadRaceStore<'_> = PaidHeadRaceStore {
        fixture: &target,
        replica,
        signed: &signed,
        producer: &producer,
        raced: std::cell::Cell::new(false),
        captured: std::cell::RefCell::new(None),
    };
    assert!(
        propose(
            &racing,
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[replica]
        )
        .is_err()
    );
    assert!(racing.raced.get());
    assert_eq!(network.snapshot(replica, &[ordered_request], 1), before);
    assert!(receipt(network, replica, ordered_request).is_none());
    assert!(receipt(network, replica, owned_request).is_some());
    let transaction: DurableInvocationTransaction = racing.captured.borrow().clone().unwrap();
    assert!(transaction.objects().mutations().is_empty());
    assert!(transaction.outbox().is_none());
    assert_eq!(
        transaction.objects().reads(),
        &[runtime::DurableObjectHeadRead::new(
            target.manifest.objects[1].object.id,
            original_head,
        )]
    );
    assert!(
        receipt(
            network,
            replica,
            *transaction.receipt().request_id().as_bytes()
        )
        .is_none()
    );

    // Isolate the actual retained typed head assertions, removing all state
    // assertions only in this read-only negative control. A nonce CAS cannot
    // explain this rejection: the independently certified update moved the
    // genuine source head, and the backend refuses that head itself.
    let head_only: DurableInvocationTransaction = DurableInvocationTransaction::new(
        network.domain(),
        None,
        transaction.objects().clone(),
        transaction.receipt().clone(),
        None,
    )
    .unwrap();
    assert!(
        matches!(network.stores[replica].commit_invocation(&network.context, head_only),
        DurableCommitOutcome::Rejected(runtime::DurableCommitRejection::ObjectConflict { object_id, .. })
        if object_id == target.manifest.objects[1].object.id)
    );
    assert!(
        receipt(
            network,
            replica,
            *transaction.receipt().request_id().as_bytes()
        )
        .is_none()
    );
    assert_eq!(network.snapshot(replica, &[ordered_request], 1), before);
}
