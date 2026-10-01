//! Executable evidence of the current ordering/business-execution boundary.
//! Two alternative legitimate delivery chronologies have identical certified
//! inputs/order but different original business outcomes. This is not a claim
//! of same-run signature equivocation. It preserves the counterexample, not a fix.
use super::*;
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

struct CausalFixture {
    network: Network,
    manifest: GenesisManifest,
    instance: InstanceRecord,
    claimant_coin: Object,
}

fn setup_causal_fixture() -> CausalFixture {
    let signers: Vec<TestSigner> = signers();
    let mut manifest: GenesisManifest = four_validator_manifest(&signers);
    manifest.commitment_profile = crate::logical_generation::CommitmentProfile::LogicalGenerationV2;
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
        3
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
    let certificate: consensus::FastCertificate = certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &network.stores[0],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        signed_bytes,
        &certificate_bytes,
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
            &acknowledgements,
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let availability_bytes: Vec<u8> =
        consensus::encode_availability_certificate(&availability).unwrap();
    let (_, result): (Digest32, PaidExecutionResult) =
        crate::fast_path::publication::decode_certified_execution_witness(&bundle.witness).unwrap();
    assert_eq!(result.status, PaidExecutionStatus::Success);
    for replica in 0..REPLICAS {
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
    let network: &Network = &fixture.network;
    let signer: &TestSigner = &network.signers[1];
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
    assert_eq!(view.next_nonce, 1);
    assert!(inspection.entitlement.amount > 0);
    let target: InstanceTarget = instance_target(&network.resolver, &fixture.instance).unwrap();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: network.leg_policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: fixture::protocol(),
            request_id: request,
            sender: *signer.id.as_bytes(),
            nonce: 1,
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
