//! Fresh causal-profile fixtures use the real atomic signed-v4 genesis
//! installer, never a manually asserted profile or uncertified business write.
use super::*;
use crate::admission_profile::VerifiedAdmissionProfile;
use crate::genesis::{GenesisManifest, GenesisObjectEntry, install_genesis};
use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::derive_scoped_type_id;
use execution::local_execution::ObjectAuthority;
use objects::{Object, ObjectId};

fn causal_fixture<S: StructuredDurableDomainStateStore>(
    store: &S,
    installed_at: u64,
) -> (Fixture, GenesisManifest, Vec<TestSigner>) {
    let (mut manifest, origin, instance, asset, _) =
        crate::genesis::tests::build_fixture_for_context(protocol(), resolver());
    let coin: Object = manifest.objects[1].object.clone();
    let small_id: ObjectId = ObjectId::new([0x23; 32]);
    let mut small: Object = coin.clone();
    small.id = small_id;
    small.data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(100),
    )
    .unwrap();
    let mut small_authority: ObjectAuthority = manifest.objects[1].authority.clone();
    small_authority.object_id = small_id;
    manifest.objects.push(GenesisObjectEntry {
        object: small.clone(),
        authority: small_authority,
    });
    let cap_id: ObjectId = ObjectId::new([0x24; 32]);
    let cap_tag: abi::package_types::ScopedTypeTag =
        public_standard_asset::treasury_cap_type_tag(&origin, &asset).unwrap();
    let mut cap: Object = coin.clone();
    cap.id = cap_id;
    cap.type_hash = derive_scoped_type_id(&resolver(), protocol().epoch(), &cap_tag).unwrap();
    cap.data = encode_call_value(
        &public_standard_asset::treasury_cap_body_layout(),
        &CallValue::U64(1_000_100),
    )
    .unwrap();
    let mut cap_authority: ObjectAuthority = manifest.objects[1].authority.clone();
    cap_authority.object_id = cap_id;
    cap_authority.ty = cap_tag;
    manifest.objects.push(GenesisObjectEntry {
        object: cap.clone(),
        authority: cap_authority,
    });
    let (signers, mut validators): (Vec<TestSigner>, Vec<FastPathValidatorEntry>) =
        four_validators();
    validators.sort_by_key(|entry| entry.id);
    manifest.validator_set.validators = validators.clone();
    for (index, validator) in validators.iter().enumerate() {
        let id: ObjectId = ObjectId::new([0x30 + u8::try_from(index).unwrap(); 32]);
        let mut collateral: GenesisObjectEntry = crate::genesis::tests::custody_object_entry(
            &manifest,
            id,
            protocol().chain_id().clone(),
        );
        let objects::Owner::ProtocolCustody(ref mut scope) = collateral.object.owner else {
            panic!("custody template");
        };
        scope.subject = *validator.id.as_bytes();
        manifest.objects.push(collateral);
    }
    manifest.commitment_profile = logical_generation::CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    crate::genesis::tests::resign_manifest(&mut manifest);
    install_genesis(
        store,
        &context(),
        domain(),
        &resolver(),
        &manifest,
        installed_at,
    )
    .unwrap();
    let fixture: Fixture = Fixture {
        origin,
        code: instance.code.clone(),
        instance,
        asset,
        cap,
        coin,
        small,
        policy: manifest.fee_policy.clone(),
    };
    (fixture, manifest, signers)
}

struct ObservedSigner<'a> {
    inner: &'a TestSigner,
    calls: Cell<usize>,
}
impl ConsensusSigner for ObservedSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.inner.validator_id()
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        self.inner.signature_scheme()
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get() + 1);
        self.inner.sign_framed(framed)
    }
}

#[test]
fn causal_wrong_lane_prepare_direct_paid_and_recovery_refuse_without_writes_or_signatures() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, manifest, signers) = causal_fixture(&store, 10);
    let engine: CountingEngine = CountingEngine::new();
    let signer: ObservedSigner<'_> = ObservedSigner {
        inner: &signers[0],
        calls: Cell::new(0),
    };
    let before = full_snapshot(&store);
    let wrong: Vec<u8> = transfer_bytes(&fixture, 0x91, next_nonce(&store));
    let verified: VerifiedAdmissionProfile = crate::genesis::VerifiedGenesisRoot::verify_bytes(
        &resolver(),
        &crate::genesis::encode_genesis_manifest(&manifest).unwrap(),
        crate::genesis::genesis_manifest_commitment(&resolver(), &manifest)
            .unwrap()
            .bytes(),
        manifest.context(),
    )
    .unwrap()
    .admission_profile()
    .clone();
    assert!(
        crate::paid_execution::authenticate_paid_execution_with_profile(
            &resolver(),
            &protocol(),
            &verified,
            &wrong
        )
        .is_err()
    );
    assert!(
        prepare(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &engine,
            &signer,
            &wrong,
            10
        )
        .is_err()
    );
    // Even a lane-correct owned request cannot use the untracked direct writer.
    let owned: Vec<u8> = transfer_bytes(&fixture, 0x11, next_nonce(&store));
    assert!(
        crate::paid_execution::authenticate_paid_execution_with_profile(
            &resolver(),
            &protocol(),
            &verified,
            &owned
        )
        .is_ok()
    );
    assert!(
        crate::paid_execution::handle_paid_execution(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &engine,
            &owned,
            10
        )
        .is_err()
    );
    let (bundle, certificate): (PublicationBundle, FastCertificate) =
        transfer_bundle_bytes(0x91, FIRST_PAID_NONCE);
    assert!(
        apply_with_recovery(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &fixture.policy,
            &engine,
            &bundle.signed_intent,
            &consensus::encode_fast_certificate(&certificate).unwrap(),
            10
        )
        .is_err()
    );
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(full_snapshot(&store), before);
}

#[test]
fn causal_imported_owned_material_wrong_lane_refuses_pure_and_retention_without_ack() {
    let store: MemoryDurableStateStore = memory_store();
    let (_, manifest, signers) = causal_fixture(&store, 10);
    let verified: VerifiedAdmissionProfile = crate::genesis::VerifiedGenesisRoot::verify_bytes(
        &resolver(),
        &crate::genesis::encode_genesis_manifest(&manifest).unwrap(),
        crate::genesis::genesis_manifest_commitment(&resolver(), &manifest)
            .unwrap()
            .bytes(),
        manifest.context(),
    )
    .unwrap()
    .admission_profile()
    .clone();
    let (bundle, _): (PublicationBundle, FastCertificate) =
        transfer_bundle_bytes(0x92, FIRST_PAID_NONCE);
    let certifier: consensus::FastPathCertifier = certifier(installed_validator_set());
    // Legitimate legacy source proof, not malformed framing or a fake cert.
    let identity: consensus::AvailabilityIdentity =
        crate::fast_path::drain_publication::verify_drain_publication_bundle(
            &resolver(),
            &[],
            &protocol(),
            domain(),
            &certifier,
            &bundle,
        )
        .unwrap();
    assert!(
        crate::fast_path::drain_publication::verify_drain_publication_bundle_with_profile(
            &resolver(),
            &[],
            &protocol(),
            &verified,
            domain(),
            &certifier,
            &bundle
        )
        .is_err()
    );
    let before = full_snapshot(&store);
    let signer: ObservedSigner<'_> = ObservedSigner {
        inner: &signers[3],
        calls: Cell::new(0),
    };
    let bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    assert!(
        crate::fast_path::publication::retain_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &bytes,
            &signer
        )
        .is_err()
    );
    let closure: crate::ordered_economics::AdmissionClosureRecord =
        crate::ordered_economics::AdmissionClosureRecord {
            closed_epoch: protocol().epoch(),
            request_id: [0xA1; 32],
            closed_at_block_height: 1,
        };
    crate::paid_execution::tests::set_state(
        &store,
        crate::ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
            .unwrap(),
        StateMutation::Put(
            crate::ordered_economics::encode_admission_closure_record(&closure).unwrap(),
        ),
    );
    let frozen_before = full_snapshot(&store);
    assert!(
        crate::fast_path::drain_publication::retain_drain_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &identity,
            &bytes
        )
        .is_err()
    );
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(full_snapshot(&store), frozen_before);
    assert_ne!(frozen_before, before); // only the explicit Freeze test setup
}

#[test]
fn causal_real_paid_success_trap_zero_charge_publish_instantiate_and_signerless_recovery() {
    for kind in 0_u8..5 {
        let mut replicas: Vec<(MemoryDurableStateStore, Fixture, Vec<TestSigner>)> = Vec::new();
        for index in 0_u8..4 {
            let store: MemoryDurableStateStore = memory_store();
            let (fixture, _, signers) = causal_fixture(&store, 10 + u64::from(index));
            replicas.push((store, fixture, signers));
        }
        let first = &replicas[0];
        let nonce: u64 = next_nonce(&first.0);
        let request: u8 = 0x21 + kind;
        let bytes: Vec<u8> = match kind {
            0 => transfer_bytes(&first.1, request, nonce),
            1 => trapping_mint_call(&first.1, request, nonce),
            2 => paid_call_with_access(
                PaidCall {
                    fixture: &first.1,
                    policy: &first.1.policy,
                    request,
                    nonce,
                    source: &first.1.small,
                    entrypoint: "transfer",
                    arguments: public_standard_asset::transfer_arguments(&refund_account())
                        .unwrap(),
                    access: vec![entry(&first.1.small, objects::AccessMode::Write)],
                },
                ReservationAccessKind::Write,
            ),
            3 => paid_publish(
                &first.1,
                request,
                nonce,
                publish_artifact(0x61),
                &first.1.coin,
                100_000,
            ),
            _ => paid_instantiate(&first.1, request, nonce, 0x62, &first.1.coin),
        };
        let votes: Vec<FastVote> = replicas[..3]
            .iter()
            .enumerate()
            .map(|(index, replica)| {
                prepare(
                    &replica.0,
                    &MemoryBlobStore::default(),
                    &context(),
                    domain(),
                    &resolver(),
                    &[],
                    &protocol(),
                    &base_policy(),
                    &replica.1.policy,
                    &CountingEngine::new(),
                    &replica.2[index],
                    &bytes,
                    20,
                )
                .unwrap()
            })
            .collect();
        assert!(
            votes
                .iter()
                .all(|vote| vote.execution_effects_hash == votes[0].execution_effects_hash)
        );
        let certificate: FastCertificate = certifier(installed_validator_set())
            .try_form_certificate(
                votes[0].tx_hash,
                votes[0].execution_effects_hash,
                votes[0].locked_objects_digest,
                &votes,
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
                ),
            )
            .unwrap()
            .unwrap();
        let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
        let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
            &first.0,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &bytes,
            &certificate_bytes,
        )
        .unwrap();
        let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
        let acks: Vec<consensus::AvailabilityVote> = replicas[..3]
            .iter()
            .enumerate()
            .map(|(index, replica)| {
                crate::fast_path::publication::retain_publication(
                    &replica.0,
                    &context(),
                    domain(),
                    &resolver(),
                    &[],
                    &protocol(),
                    &bundle_bytes,
                    &replica.2[index],
                )
                .unwrap()
            })
            .collect();
        let availability: consensus::AvailabilityCertifier = consensus::AvailabilityCertifier::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            installed_validator_set(),
        )
        .unwrap();
        let ac: consensus::AvailabilityCertificate = availability
            .try_form_certificate(
                &acks[0].identity,
                &acks,
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
                ),
            )
            .unwrap()
            .unwrap();
        let ac_bytes: Vec<u8> = consensus::encode_availability_certificate(&ac).unwrap();
        let engine: CountingEngine = CountingEngine::new();
        let output: NodeOutput = apply_after_publication(
            &first.0,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &first.1.policy,
            &engine,
            &bytes,
            &certificate_bytes,
            &ac_bytes,
        )
        .unwrap();
        let recovered: NodeOutput = apply_with_recovery_after_publication(
            &replicas[3].0,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &replicas[3].1.policy,
            &CountingEngine::new(),
            &bytes,
            &certificate_bytes,
            20,
            &ac_bytes,
        )
        .unwrap();
        assert_eq!(output, recovered);
        let result: PaidExecutionResult = receipt(&output);
        assert_eq!(
            result.status,
            match kind {
                1 => PaidExecutionStatus::ApplicationFailed,
                2 => PaidExecutionStatus::ReservationFailed,
                _ => PaidExecutionStatus::Success,
            }
        );
        if kind == 1 {
            assert!(result.charged.as_ref().unwrap().actual.get() > 0);
        }
        if kind == 2 {
            assert!(result.charged.is_none());
            assert!(result.effects.object_effects.is_empty());
        }
        let before = full_snapshot(&first.0);
        assert_eq!(
            apply_after_publication(
                &first.0,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &first.1.policy,
                &engine,
                &bytes,
                &certificate_bytes,
                &ac_bytes
            )
            .unwrap(),
            output
        );
        assert_eq!(
            crate::paid_execution::handle_paid_execution(
                &first.0,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &first.1.policy,
                &engine,
                &bytes,
                90
            )
            .unwrap(),
            output
        );
        assert_eq!(engine.calls.get(), 1);
        assert_eq!(next_nonce(&first.0), nonce + 1);
        assert_eq!(full_snapshot(&first.0), before);
    }
}

struct NeverExecute;
impl TransactionalNodeStateMachine for NeverExecute {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"causal/direct-business".to_vec(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }
    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        panic!("a fresh untracked causal writer must never run");
    }
}

#[test]
fn causal_generic_durable_writer_denies_fresh_even_with_request_selected_foreign_epoch() {
    let store: MemoryDurableStateStore = memory_store();
    let (_, _, _) = causal_fixture(&store, 10);
    for request_epoch in [protocol().epoch(), Epoch::new(99)] {
        let before = full_snapshot(&store);
        let mut payload: CanonicalStruct = CanonicalStruct::new(0x7A01, 1);
        payload.field_u64(1, 1).unwrap();
        let event: NodeEvent = NodeEvent::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            request_epoch,
            RequestId::new([0x43; 32]).unwrap(),
            NodeEventKind::Tick,
            payload.finish().unwrap(),
        )
        .unwrap();
        let machine: NeverExecute = NeverExecute;
        let plan: NodeStateAccessPlan = machine.access_plan(&event).unwrap();
        assert!(
            crate::handle_durable_idempotent_event_with_plan(
                None,
                &store,
                &context(),
                domain(),
                &resolver(),
                event,
                &machine,
                plan,
                None,
                None,
                None,
                None
            )
            .is_err()
        );
        assert_eq!(full_snapshot(&store), before);
    }
}

#[test]
fn causal_standalone_publication_denies_fresh_but_replays_authenticated_genesis_original() {
    let store: MemoryDurableStateStore = memory_store();
    let (fixture, manifest, _) = causal_fixture(&store, 10);
    let semantics: Digest32 =
        execution::local_execution::generic_object_result_semantics(&resolver(), &protocol())
            .unwrap();
    let policy: crate::publication::LocalPublicationPolicy =
        crate::publication::LocalPublicationPolicy::object_results(protocol(), semantics);
    let artifact: execution::publication::CodeArtifact = publish_artifact(0x66);
    let request: [u8; 32] = [0x44; 32];
    let nonce: u64 = next_nonce(&store);
    let digest: Digest32 =
        execution::publication::artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let framed: Vec<u8> = execution::publication::publication_submission_signing_frame(
        &resolver(),
        &protocol(),
        &artifact,
        nonce,
        request,
    )
    .unwrap();
    let submission: execution::publication::PublicationSubmission =
        execution::publication::PublicationSubmission::new(
            request,
            execution::publication::PublicationRequest::new(
                artifact,
                nonce,
                digest,
                crate::paid_execution::tests::key().sign(&framed).into(),
            ),
        )
        .unwrap();
    let before = full_snapshot(&store);
    assert!(
        crate::publication::handle_local_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            &policy,
            submission
        )
        .is_err()
    );
    let replay: NodeOutput = crate::publication::handle_local_publication(
        &store,
        &context(),
        domain(),
        &resolver(),
        &policy,
        manifest.publication.clone(),
    )
    .unwrap();
    assert_eq!(
        replay,
        crate::publication::publication_output(&manifest.publication).unwrap()
    );
    assert_eq!(next_nonce(&store), nonce);
    assert_eq!(
        store
            .get_object_head(&context(), domain(), fixture.coin.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        1
    );
    assert_eq!(full_snapshot(&store), before);
}

#[test]
fn causal_generic_direct_gate_cannot_hide_a_pristine_lost_profile_with_foreign_request_epoch() {
    let source: MemoryDurableStateStore = memory_store();
    let (_, manifest, _) = causal_fixture(&source, 10);
    let partial: MemoryDurableStateStore = memory_store();
    for key in [
        crate::genesis::genesis_manifest_key(manifest.context()).unwrap(),
        crate::genesis::genesis_marker_key(manifest.context()).unwrap(),
        local_instance_state::fastpath_epoch_record_key(manifest.context().chain_id()).unwrap(),
    ] {
        let row: VersionedStateValue = source
            .get_versioned_durable(&context(), domain(), &key)
            .unwrap();
        crate::paid_execution::tests::set_state(
            &partial,
            key,
            StateMutation::Put(row.value().unwrap().to_vec()),
        );
    }
    let before = full_snapshot(&partial);
    let mut payload: CanonicalStruct = CanonicalStruct::new(0x7A01, 1);
    payload.field_u64(1, 1).unwrap();
    let event: NodeEvent = NodeEvent::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        Epoch::new(99),
        RequestId::new([0x45; 32]).unwrap(),
        NodeEventKind::Tick,
        payload.finish().unwrap(),
    )
    .unwrap();
    let machine: NeverExecute = NeverExecute;
    let plan: NodeStateAccessPlan = machine.access_plan(&event).unwrap();
    let error: NodeCoreError = crate::handle_durable_idempotent_event_with_plan(
        None,
        &partial,
        &context(),
        domain(),
        &resolver(),
        event,
        &machine,
        plan,
        None,
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        NodeCoreError::PersistenceInvariant(
            "installed signed genesis requires its missing profile"
        )
    ));
    assert_eq!(full_snapshot(&partial), before);
}
