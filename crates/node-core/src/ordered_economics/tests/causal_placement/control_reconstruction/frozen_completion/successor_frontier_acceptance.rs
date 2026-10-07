//! Genuine current behind-tail successor-frontier acceptance, with separate
//! complete-source audit of authenticated prior drain-publication carriers.
use super::*;
use crate::business_reconstruction::SourceBusinessSnapshot;
use crate::business_reconstruction::cut::{BusinessCutError, VerifiedBusinessCut};

struct RetainedPaidPublication {
    identity: consensus::AvailabilityIdentity,
    bundle: Vec<u8>,
}

fn signed_transfer(
    world: &SuccessorWorld,
    signer: &TestSigner,
    coin_ref: ObjectRef,
    request_id: [u8; 32],
    fee_policy: &PaidFeePolicy,
) -> Vec<u8> {
    let source: &CausalFixture = world.source();
    let network: &Network = &source.network;
    let sender: [u8; 32] = *signer.id.as_bytes();
    let next: PublicationContext = world.policy.context().clone();
    let call: CallIntent = CallIntent {
        context: next.clone(),
        request_id,
        sender,
        nonce: 0,
        code: source.instance.code.clone(),
        instance: instance_target(&network.resolver, &source.instance).unwrap(),
        entrypoint: "transfer".into(),
        type_arguments: fee_policy.type_arguments.clone(),
        arguments: public_standard_asset::transfer_arguments(&sender).unwrap(),
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: coin_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        gas_limit: 100_000,
    };
    let intent: PaidIntent = PaidIntent {
        context: next.clone(),
        request_id,
        sender,
        nonce: 0,
        fee_policy_digest: paid_fee_policy_digest(&network.resolver, fee_policy).unwrap(),
        application: PaidApplication::Call(call),
        consent: FeeSourceConsent {
            source: coin_ref,
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: sender,
        },
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&next, &intent).unwrap();
    encode_signed_paid_intent(&SignedPaidIntent {
        signature: signer.key.sign(&frame).into(),
        intent,
    })
    .unwrap()
}

fn publish_retained(
    world: &SuccessorWorld,
    sender: &TestSigner,
    coin_ref: ObjectRef,
    request_id: [u8; 32],
    fee_policy: &PaidFeePolicy,
) -> RetainedPaidPublication {
    let network: &Network = world.network();
    let signed: Vec<u8> = signed_transfer(world, sender, coin_ref, request_id, fee_policy);
    let votes: Vec<consensus::FastVote> = (0..world.members.len())
        .map(|index: usize| {
            crate::serving_authority::prepare_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &composition(world, index, fee_policy),
                &world.members[index],
                &signed,
                1,
            )
            .unwrap()
        })
        .collect();
    let set: ValidatorSet = world.policy.engine().validator_set().clone();
    let next: PublicationContext = world.policy.context().clone();
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        next.protocol_version(),
        next.epoch(),
        set,
    )
    .unwrap();
    let certificate: consensus::FastCertificate = certifier
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
        &world.targets[0].0,
        &world.operation,
        network.domain(),
        &network.resolver,
        &network.history,
        &next,
        &signed,
        &certificate_bytes,
    )
    .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let acknowledgements: Vec<consensus::AvailabilityVote> = (0..world.members.len())
        .map(|index: usize| {
            crate::serving_authority::retain_publication_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &network.resolver,
                &network.history,
                &bundle_bytes,
                &world.members[index],
            )
            .unwrap()
        })
        .collect();
    let identity: consensus::AvailabilityIdentity = acknowledgements[0].identity.clone();
    assert!(
        acknowledgements
            .iter()
            .all(|vote| vote.identity == identity)
    );
    RetainedPaidPublication {
        identity,
        bundle: bundle_bytes,
    }
}

fn commit_real_freeze(world: &SuccessorWorld, request_id: [u8; 32]) {
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let current: PublicationContext = world.policy.context().clone();
    let next: PublicationContext = PublicationContext::new(
        current.chain_id().clone(),
        current.protocol_version(),
        Epoch::new(current.epoch().get().checked_add(1).unwrap()),
    )
    .unwrap();
    let entries: Vec<FastPathValidatorEntry> = world
        .policy
        .engine()
        .validator_set()
        .validators()
        .iter()
        .map(
            |entry: &validator_set::ValidatorInfo| FastPathValidatorEntry {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            },
        )
        .collect();
    let freeze: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&FreezeIntent {
            context: current,
            request_id,
            advisory_next_set: FastPathValidatorSetRecord {
                context: next,
                validators: entries,
            },
        })
        .unwrap(),
        created_checkpoint: 1,
    };
    successor_round(world, &env, Some(&freeze));
    successor_round(world, &env, None);
    let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(world, &env, None);
    assert!(
        outputs[0]
            .committed
            .iter()
            .any(|outcome: &OrderedOutcome| outcome.request_id == request_id
                && outcome.output.responses()[0].status() == NodeResponseStatus::Accepted)
    );
}

fn write_row(world: &SuccessorWorld, key: &[u8], mutation: StateMutation) {
    let domain: AtomicityDomainId = world.network().domain();
    let warrant: crate::serving_authority::LiveWarrant<'_> = world.warrant(0);
    let observed: VersionedStateValue = world.targets[0]
        .0
        .get_versioned_durable(&world.operation, domain, key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), mutation).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        crate::serving_authority::ServingGate::Successor(&warrant).commit_durable(
            &world.targets[0].0,
            &world.operation,
            transaction
        ),
        runtime::DurableCommitOutcome::Committed
    );
}

fn source_snapshot(world: &SuccessorWorld) -> SourceBusinessSnapshot {
    crate::test_support::capture::captured_source(
        &world.targets[0].0,
        &world.targets[0].1,
        &world.operation,
        world.network().domain(),
    )
}

fn assert_logical_restore(world: &SuccessorWorld, before: &SourceBusinessSnapshot) {
    let restored: SourceBusinessSnapshot = source_snapshot(world);
    assert_eq!(
        crate::business_reconstruction::inactive_import::raw_rows(&restored, false).unwrap(),
        crate::business_reconstruction::inactive_import::raw_rows(before, false).unwrap(),
        "restore preserves every logical row without rewinding physical revisions"
    );
    assert_eq!(restored.referenced_blobs, before.referenced_blobs);
    assert_ne!(restored.token, before.token, "restore is a real new commit");
}

fn assert_refusal_unchanged(
    world: &SuccessorWorld,
    after_injection: &SourceBusinessSnapshot,
    signer: &RefusalSigner<'_>,
    signatures: usize,
) {
    assert_eq!(source_snapshot(world), *after_injection);
    assert_eq!(signer.signatures.get(), signatures);
    assert_eq!(
        world.targets[0]
            .0
            .get_outgoing_barrier(&world.operation, world.network().domain())
            .unwrap(),
        runtime::OutgoingBarrier::Unsealed
    );
}

fn altered_publication(bytes: &[u8]) -> Vec<u8> {
    let mut publication: crate::fast_path::publication::FastPathPublicationRecord =
        crate::fast_path::publication::decode_fastpath_publication_record(bytes).unwrap();
    let mut certificate: consensus::FastCertificate =
        consensus::decode_fast_certificate(&publication.certificate).unwrap();
    certificate.votes[0].signature[0] ^= 1;
    publication.certificate = consensus::encode_fast_certificate(&certificate).unwrap();
    crate::fast_path::publication::encode_fastpath_publication_record(&publication).unwrap()
}

fn next_owned_id(world: &SuccessorWorld, previous: [u8; 32]) -> [u8; 32] {
    let mut request: [u8; 32] = previous;
    let mut incremented: bool = false;
    for byte in request.iter_mut().rev() {
        if let Some(next) = byte.checked_add(1) {
            *byte = next;
            incremented = true;
            break;
        }
        *byte = 0;
    }
    assert!(
        incremented && request > previous,
        "retained key order has a successor"
    );
    crate::admission_profile::require_external_request_lane(
        world.network().root.admission_profile(),
        crate::admission_profile::ExternalRequestLane::Owned,
        &request,
    )
    .expect("the actual retained tail leaves a genuine owned-lane external ID");
    request
}

fn physical_cursor(world: &SuccessorWorld) -> frontier::FrontierCursor {
    let current: &PublicationContext = world.policy.context();
    let key: Vec<u8> =
        frontier::key(current.chain_id(), current.epoch(), b"frontier-progress/").unwrap();
    frontier::decode_cursor(world.value(0, &key).1.as_deref().unwrap()).unwrap()
}

fn page(
    world: &SuccessorWorld,
    index: usize,
    after: Option<[u8; 32]>,
) -> Result<(FrozenFrontierVote, FrozenFrontierPage), FrozenFrontierError> {
    let network: &Network = world.network();
    read_frozen_frontier_page_successor(
        &world.warrant(index),
        &world.targets[index].0,
        &world.operation,
        network.domain(),
        &network.resolver,
        &network.history,
        world.policy.context(),
        world.members[index].id,
        after,
        NonZeroUsize::new(2).unwrap(),
    )
}

fn verify_stream(
    world: &SuccessorWorld,
    vote: &FrozenFrontierVote,
    first: &FrozenFrontierPage,
    terminal: &FrozenFrontierPage,
) {
    let network: &Network = world.network();
    let current: &PublicationContext = world.policy.context();
    let certifier: consensus::FrozenFrontierCertifier = consensus::FrozenFrontierCertifier::new(
        current.chain_id().clone(),
        current.protocol_version(),
        current.epoch(),
        world.policy.engine().validator_set().clone(),
    )
    .unwrap();
    let mut verifier: consensus::FrozenFrontierPageVerifier =
        consensus::FrozenFrontierPageVerifier::new(
            &network.resolver,
            &certifier,
            vote.clone(),
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap();
    for served in [first, terminal] {
        let encoded: Vec<u8> = consensus::encode_frozen_frontier_page(served).unwrap();
        let decoded: FrozenFrontierPage = consensus::decode_frozen_frontier_page(&encoded).unwrap();
        assert_eq!(decoded, *served);
        verifier.push_page(&network.resolver, &decoded).unwrap();
    }
    assert_eq!(verifier.finish().unwrap(), *vote);
}

fn complete_current_drain(world: &SuccessorWorld, material: &[RetainedPaidPublication]) {
    let network: &Network = world.network();
    let current: PublicationContext = world.policy.context().clone();
    let maximum_steps: u64 = chain_authority(world)
        .import_binding()
        .row_count
        .checked_add(3)
        .unwrap();
    let mut selected: Vec<(FrozenFrontierVote, [FrozenFrontierPage; 2])> = Vec::new();
    for index in 0..3 {
        let mut final_vote: Option<FrozenFrontierVote> = None;
        for _ in 0..maximum_steps {
            match advance_frozen_frontier_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.operation,
                network.domain(),
                &network.resolver,
                &network.history,
                &current,
                &world.members[index],
            )
            .unwrap()
            {
                FrozenFrontierStep::Advanced { entry_count } => {
                    assert!(entry_count <= 2);
                }
                FrozenFrontierStep::Finalized(vote) => {
                    final_vote = Some(*vote);
                    break;
                }
            }
        }
        let vote: FrozenFrontierVote = final_vote.expect("bounded genuine frontier completes");
        let (served, first): (FrozenFrontierVote, FrozenFrontierPage) =
            page(world, index, None).unwrap();
        let (last_vote, terminal): (FrozenFrontierVote, FrozenFrontierPage) =
            page(world, index, Some(material[1].identity.request_id)).unwrap();
        assert_eq!(served, vote);
        assert_eq!(last_vote, vote);
        let expected_entries: Vec<consensus::AvailabilityIdentity> =
            material.iter().map(|item| item.identity.clone()).collect();
        assert_eq!(first.entries, expected_entries);
        assert!(!first.terminal && terminal.terminal && terminal.entries.is_empty());
        verify_stream(world, &vote, &first, &terminal);
        selected.push((vote, [first, terminal]));
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let votes: Vec<FrozenFrontierVote> = selected.iter().map(|(vote, _)| vote.clone()).collect();
    let mut expected_union: Option<DrainUnionIdentity> = None;
    for index in 0..world.members.len() {
        for (vote, pages) in &selected {
            for served in pages {
                ingest_drain_signer_page_successor(
                    &world.warrant(index),
                    &world.targets[index].0,
                    &world.operation,
                    network.domain(),
                    &network.resolver,
                    &current,
                    vote.validator,
                    vote.clone(),
                    served.clone(),
                )
                .unwrap();
                for entry in &served.entries {
                    let item: &RetainedPaidPublication = material
                        .iter()
                        .find(|item| item.identity == *entry)
                        .unwrap();
                    assert_eq!(
                        import_staged_drain_publication_successor(
                            &world.warrant(index),
                            &world.targets[index].0,
                            &world.operation,
                            network.domain(),
                            &network.resolver,
                            &network.history,
                            &current,
                            vote.validator,
                            &item.bundle,
                        )
                        .unwrap(),
                        *entry
                    );
                    assert_eq!(
                        confirm_drain_signer_entry_successor(
                            &world.warrant(index),
                            &world.targets[index].0,
                            &world.operation,
                            network.domain(),
                            &network.resolver,
                            &network.history,
                            &current,
                            vote.validator,
                            entry.request_id,
                        )
                        .unwrap(),
                        *entry
                    );
                }
            }
            let progress: DrainSignerProgress = read_drain_signer_progress_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.operation,
                network.domain(),
                &network.resolver,
                &current,
                vote.validator,
            )
            .unwrap();
            assert!(progress.complete && progress.staged_page.is_none());
            assert_eq!(progress.vote, *vote);
            assert_eq!(progress.confirmed_identity, vote.identity);
        }
        let mut ready: Option<DrainUnionIdentity> = None;
        for step in 1u64..=3 {
            match advance_drain_union_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.operation,
                network.domain(),
                &network.resolver,
                &network.history,
                &current,
                &votes,
            )
            .unwrap()
            {
                DrainUnionStep::Advanced { member_count } => {
                    assert!(step <= 2);
                    assert_eq!(member_count, step);
                }
                DrainUnionStep::Ready(identity) => {
                    assert_eq!(step, 3);
                    assert_eq!(identity.member_count, 2);
                    ready = Some(*identity);
                    break;
                }
            }
        }
        let ready: DrainUnionIdentity = ready.expect("two real members produce a complete union");
        assert_eq!(
            verify_drain_ready_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.operation,
                network.domain(),
                &network.resolver,
                &current,
                &votes,
            )
            .unwrap(),
            ready
        );
        if let Some(expected) = &expected_union {
            assert_eq!(&ready, expected);
        } else {
            expected_union = Some(ready);
        }
    }
    let drain_request: [u8; 32] = [0xf3; 32];
    let drain: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id: drain_request,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&DrainSetIntent {
            context: current.clone(),
            request_id: drain_request,
            selected_votes: votes,
            drain_union_identity: expected_union.unwrap(),
        })
        .unwrap(),
        created_checkpoint: 4,
    };
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    successor_round(world, &env, Some(&drain));
    successor_round(world, &env, None);
    let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(world, &env, None);
    for output in outputs {
        assert!(output.committed.iter().any(|outcome: &OrderedOutcome| {
            outcome.request_id == drain_request
                && outcome.output.responses()[0].status() == NodeResponseStatus::Accepted
        }));
    }
    let fee_key: Vec<u8> = crate::local_instance_state::paid_fee_policy_key(&current).unwrap();
    let fee_policy: PaidFeePolicy = execution::paid_execution::decode_paid_fee_policy(
        world.value(0, &fee_key).1.as_deref().unwrap(),
    )
    .unwrap();
    for index in 0..world.members.len() {
        for item in material {
            let output: NodeOutput = crate::fast_path::drain_apply::apply_drain_member_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.targets[index].1,
                &world.operation,
                network.domain(),
                &network.resolver,
                &network.history,
                &current,
                &world.next_base,
                &fee_policy,
                &network.engine,
                item.identity.request_id,
                drain.created_checkpoint,
            )
            .unwrap();
            assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
        }
    }
    for _ in 0..3 {
        successor_round(world, &env, None);
    }
}

fn source_cut(
    world: &SuccessorWorld,
    fixed: &OrderedHistoryIdentity,
    ordered: &[OrderedHistoryHeightMaterial],
) -> Result<VerifiedBusinessCut, BusinessCutError> {
    let mut plan: BusinessReconstructionPlan<'_> =
        reconstruction_plan(world.source(), &world.cut_history);
    plan.operation_context = world.operation;
    plan.ordered_history_identity = fixed;
    crate::business_reconstruction::cut::derive_successor_source_business_cut(
        plan,
        &world.warrant(0),
        &world.targets[0].0,
        &world.targets[0].1,
        ordered,
    )
}

#[test]
fn genuine_successor_frontier_authenticates_behind_tail_current_entries() {
    let world: SuccessorWorld = recurring_world();
    let network: &Network = world.network();
    let domain: AtomicityDomainId = network.domain();
    let current: PublicationContext = world.policy.context().clone();
    // The immutable origin owns these genuine imported bodies. Transfer
    // its complete referenced closure before current preparation creates
    // additional bodies in each target's independent repository.
    let imported: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
        &world.targets[0].0,
        &network.blobs,
        &world.operation,
        domain,
    );
    for (_, blobs) in &world.targets {
        for (digest, body) in &imported.referenced_blobs {
            blobs.put_blob(*digest, body.clone()).unwrap();
        }
    }
    let mut normal_prefix: Vec<u8> =
        crate::fast_path::publication::fastpath_publication_key(current.chain_id(), &[0; 32])
            .unwrap();
    normal_prefix.truncate(normal_prefix.len().checked_sub(32).unwrap());
    assert!(
        world
            .warrant(0)
            .next_prior_state_row(&normal_prefix, &normal_prefix)
            .is_none(),
        "verified replay does not import the origin's ordinary publication log"
    );
    assert!(
        !imported.records.iter().any(
            |row: &crate::business_reconstruction::SourceSnapshotRecord| matches!(row.descriptor.key(),
                runtime::portable::DurableRecordKey::State(key) if key.starts_with(&normal_prefix)
            )
        ),
        "the actual imported store has no historical normal-publication prefix"
    );
    // Replay retains the independently verified selected e0 bundles under
    // their owning epoch-scoped drain addresses. These rows are not physical
    // inputs of the ordinary publication-prefix frontier scan below.
    let historical_epoch: Epoch = network.root.genesis_context().epoch();
    assert!(historical_epoch < current.epoch());
    let mut drain_prefix: Vec<u8> = crate::fast_path::drain_publication::drain_publication_key(
        current.chain_id(),
        historical_epoch,
        &[0; 32],
    )
    .unwrap();
    drain_prefix.truncate(drain_prefix.len().checked_sub(32).unwrap());
    let prior_drain: Vec<(Vec<u8>, Vec<u8>)> = {
        let warrant: crate::serving_authority::LiveWarrant<'_> = world.warrant(0);
        let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut after: Vec<u8> = drain_prefix.clone();
        while let Some((key, bytes)) = warrant.next_prior_state_row(&drain_prefix, &after) {
            assert!(key > after.as_slice());
            after = key.to_vec();
            let bytes: &[u8] = bytes.expect("the genuine retained prior carrier is present");
            let record: crate::fast_path::publication::FastPathPublicationRecord =
                crate::fast_path::publication::decode_fastpath_publication_record(bytes).unwrap();
            assert_eq!(record.context, *network.root.genesis_context());
            assert_eq!(
                crate::fast_path::publication::encode_fastpath_publication_record(&record).unwrap(),
                bytes,
                "the genuine prior drain carrier uses its canonical owning codec"
            );
            let expected_key: Vec<u8> = crate::fast_path::drain_publication::drain_publication_key(
                current.chain_id(),
                historical_epoch,
                &record.request_id,
            )
            .unwrap();
            assert_eq!(key, expected_key.as_slice());
            assert_eq!(world.value(0, key).1.as_deref(), Some(bytes));
            rows.push((key.to_vec(), bytes.to_vec()));
        }
        rows
    };
    assert!(
        prior_drain.len() >= 2,
        "verified e0 replay retains multiple actual drain-publication carriers"
    );
    let last_prior: [u8; 32] = prior_drain.last().unwrap().0[drain_prefix.len()..]
        .try_into()
        .unwrap();
    let request_id_1: [u8; 32] = next_owned_id(&world, last_prior);
    let request_id_2: [u8; 32] = next_owned_id(&world, request_id_1);
    let fee_bytes: Vec<u8> = world
        .value(
            0,
            &crate::local_instance_state::paid_fee_policy_key(&current).unwrap(),
        )
        .1
        .unwrap();
    let fee_policy: PaidFeePolicy =
        execution::paid_execution::decode_paid_fee_policy(&fee_bytes).unwrap();
    let claimant_id: ObjectId = world.source().claimant_coin.id;
    let (_, claimant_ref): (Object, ObjectRef) = current_imported_object(&world, claimant_id);
    let b: TestSigner = TestSigner {
        id: network.signers[1].id,
        key: network.signers[1].key,
    };
    let g: TestSigner = never_member_g();
    let (_, g_ref): (Object, ObjectRef) =
        current_imported_object(&world, ObjectId::new([0x23; 32]));
    assert!(request_id_1 < request_id_2);
    let material_1: RetainedPaidPublication =
        publish_retained(&world, &b, claimant_ref, request_id_1, &fee_policy);
    let material_2: RetainedPaidPublication =
        publish_retained(&world, &g, g_ref, request_id_2, &fee_policy);
    let identities: Vec<consensus::AvailabilityIdentity> =
        vec![material_1.identity.clone(), material_2.identity.clone()];
    let material: [RetainedPaidPublication; 2] = [material_1, material_2];
    commit_real_freeze(&world, [0xf0; 32]);
    let publication_key_1: Vec<u8> =
        crate::fast_path::publication::fastpath_publication_key(current.chain_id(), &request_id_1)
            .unwrap();
    let original_bytes_1: Vec<u8> = world.value(0, &publication_key_1).1.unwrap();
    let signer: RefusalSigner<'_> = RefusalSigner {
        inner: &world.members[0],
        signatures: Cell::new(0),
    };
    let advance = |signer: &RefusalSigner<'_>| {
        advance_frozen_frontier_successor(
            &world.warrant(0),
            &world.targets[0].0,
            &world.operation,
            domain,
            &network.resolver,
            &network.history,
            &current,
            signer,
        )
    };
    let closure_key: Vec<u8> =
        freeze::admission_closure_key(current.chain_id(), current.epoch()).unwrap();
    let closure: freeze::AdmissionClosureRecord =
        freeze::decode_admission_closure_record(world.value(0, &closure_key).1.as_deref().unwrap())
            .unwrap();
    let mut expected_frontier: consensus::FrozenFrontierAccumulator =
        consensus::FrozenFrontierAccumulator::new(
            &network.resolver,
            current.chain_id().clone(),
            current.protocol_version(),
            current.epoch(),
            domain,
            closure.request_id,
            closure.closed_at_block_height,
        )
        .unwrap();
    // With the actual verified normal prefix empty, exactly two bounded
    // one-publication steps precede finalization. Each current identity is
    // folded once; no drain-family row is claimed as a physical scan input.
    assert_eq!(
        advance(&signer).unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 1 }
    );
    expected_frontier
        .push(&network.resolver, &identities[0])
        .unwrap();
    let cursor: frontier::FrontierCursor = physical_cursor(&world);
    assert!(cursor.indexed);
    assert_eq!(cursor.physical_last_request_id, request_id_1);
    assert_eq!(cursor.last_request_id, Some(request_id_1));
    assert_eq!(&cursor.identity, expected_frontier.identity());
    let physical_last: [u8; 32] = cursor.physical_last_request_id;
    assert_eq!(signer.signatures.get(), 0);
    let before_tail_fault: SourceBusinessSnapshot = source_snapshot(&world);
    write_row(&world, &publication_key_1, StateMutation::Delete);
    let injected_tail: SourceBusinessSnapshot = source_snapshot(&world);
    assert!(matches!(
        advance(&signer),
        Err(FrozenFrontierError::Invalid(
            "frontier physical cursor carrier disappeared or changed"
        ))
    ));
    assert_refusal_unchanged(&world, &injected_tail, &signer, 0);
    write_row(
        &world,
        &publication_key_1,
        StateMutation::Put(original_bytes_1.clone()),
    );
    assert_logical_restore(&world, &before_tail_fault);
    assert_eq!(
        advance(&signer).unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 2 }
    );
    expected_frontier
        .push(&network.resolver, &identities[1])
        .unwrap();
    let cursor: frontier::FrontierCursor = physical_cursor(&world);
    assert!(cursor.indexed);
    assert!(cursor.physical_last_request_id > physical_last);
    assert_eq!(cursor.physical_last_request_id, request_id_2);
    assert_eq!(cursor.last_request_id, Some(request_id_2));
    assert_eq!(&cursor.identity, expected_frontier.identity());
    assert!(request_id_1 < cursor.physical_last_request_id);
    assert_eq!(
        signer.signatures.get(),
        0,
        "bounded current progress never signs"
    );
    let final_step: FrozenFrontierStep = advance(&signer).unwrap();
    let final_vote: FrozenFrontierVote = match final_step {
        FrozenFrontierStep::Finalized(vote) => *vote,
        FrozenFrontierStep::Advanced { .. } => panic!("expected finalization"),
    };
    assert_eq!(signer.signatures.get(), 1);
    assert_eq!(final_vote.identity.entry_count, 2);
    assert_eq!(&final_vote.identity, expected_frontier.identity());
    let (vote, first_page): (FrozenFrontierVote, FrozenFrontierPage) =
        page(&world, 0, None).unwrap();
    assert_eq!(vote, final_vote);
    assert!(
        !first_page.terminal,
        "an exactly full page retains its public nonterminal encoding"
    );
    assert_eq!(first_page.entries.len(), 2);
    assert_eq!(first_page.entries, identities);
    let (terminal_vote, terminal_page): (FrozenFrontierVote, FrozenFrontierPage) =
        page(&world, 0, Some(request_id_2)).unwrap();
    assert_eq!(terminal_vote, final_vote);
    assert!(terminal_page.terminal && terminal_page.entries.is_empty());
    assert_eq!(terminal_page.after_request_id, Some(request_id_2));
    verify_stream(&world, &final_vote, &first_page, &terminal_page);
    let vote_bytes: Vec<u8> = consensus::encode_frozen_frontier_vote(&final_vote).unwrap();
    assert_eq!(
        consensus::decode_frozen_frontier_vote(&vote_bytes).unwrap(),
        final_vote
    );
    let page_bytes: Vec<u8> = consensus::encode_frozen_frontier_page(&first_page).unwrap();
    let terminal_bytes: Vec<u8> = consensus::encode_frozen_frontier_page(&terminal_page).unwrap();
    let entry_bytes: Vec<Vec<u8>> = identities
        .iter()
        .map(|identity| consensus::encode_availability_identity(identity).unwrap())
        .collect();
    for (identity, bytes) in identities.iter().zip(&entry_bytes) {
        assert_eq!(
            consensus::decode_availability_identity(bytes).unwrap(),
            *identity
        );
    }
    let before_replay: SourceBusinessSnapshot = source_snapshot(&world);
    assert_eq!(
        advance(&signer).unwrap(),
        FrozenFrontierStep::Finalized(Box::new(final_vote.clone()))
    );
    assert_eq!(
        page(&world, 0, None).unwrap(),
        (final_vote.clone(), first_page.clone())
    );
    assert_eq!(
        page(&world, 0, Some(request_id_2)).unwrap(),
        (final_vote.clone(), terminal_page.clone())
    );
    assert_refusal_unchanged(&world, &before_replay, &signer, 1);
    let index_key_1: Vec<u8> =
        frontier::entry_key(current.chain_id(), current.epoch(), &request_id_1).unwrap();
    let index_bytes_1: Vec<u8> = world.value(0, &index_key_1).1.unwrap();
    let mut altered_index: frontier::FrontierEntry =
        frontier::decode_entry(&index_bytes_1).unwrap();
    altered_index.ordinal = 2;
    for (key, original, changed) in [
        (
            &publication_key_1,
            &original_bytes_1,
            altered_publication(&original_bytes_1),
        ),
        (
            &index_key_1,
            &index_bytes_1,
            frontier::encode_entry(&altered_index).unwrap(),
        ),
    ] {
        for mutation in [StateMutation::Put(changed), StateMutation::Delete] {
            let intact: SourceBusinessSnapshot = source_snapshot(&world);
            write_row(&world, key, mutation);
            let injected: SourceBusinessSnapshot = source_snapshot(&world);
            assert!(
                page(&world, 0, None).is_err(),
                "a behind-tail current carrier or index must reverify"
            );
            assert_refusal_unchanged(&world, &injected, &signer, 1);
            write_row(&world, key, StateMutation::Put(original.clone()));
            assert_logical_restore(&world, &intact);
            assert_eq!(page(&world, 0, None).unwrap().1, first_page);
        }
    }
    complete_current_drain(&world, &material);
    let (fixed, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        current_history(&world);
    let intact: SourceBusinessSnapshot = source_snapshot(&world);
    let cut: VerifiedBusinessCut = source_cut(&world, &fixed, &ordered)
        .expect("the complete genuine DrainSet/member closure produces a valid full source cut");
    assert_eq!(&cut.identity().context, &current);
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let authority: VerifiedSuccessorAuthority = chain_authority(&world);
    let verified: VerifiedImportPlan =
        crate::business_reconstruction::inactive_import::verify_saved_business_import_chain(
            reconstruction_plan(world.source(), &world.cut_history),
            &authority,
            &fixed,
            &saved,
        )
        .expect("independent saved-cut replay validates the same genuine source closure");
    assert!(!verified.rows().is_empty());
    assert!(
        !verified.rows().iter().any(|row| matches!(row,
            runtime::inactive_import::ImportRow::State { key, .. } if key == &index_key_1
        )),
        "validated current locator metadata is excluded from logical import"
    );
    assert_refusal_unchanged(&world, &intact, &signer, 1);
    let index_key_2: Vec<u8> =
        frontier::entry_key(current.chain_id(), current.epoch(), &request_id_2).unwrap();
    let index_bytes_2: Vec<u8> = world.value(0, &index_key_2).1.unwrap();
    let mut entry_2: frontier::FrontierEntry = frontier::decode_entry(&index_bytes_2).unwrap();
    entry_2.ordinal = 1;
    for mutation in [
        StateMutation::Put(frontier::encode_entry(&entry_2).unwrap()),
        StateMutation::Delete,
    ] {
        let before: SourceBusinessSnapshot = source_snapshot(&world);
        write_row(&world, &index_key_2, mutation);
        let injected: SourceBusinessSnapshot = source_snapshot(&world);
        let error: BusinessCutError = match source_cut(&world, &fixed, &ordered) {
            Err(error) => error,
            Ok(_) => panic!("a duplicated ordinal or missing slot cannot form a full source cut"),
        };
        assert!(
            matches!(
                error,
                BusinessCutError::Reconstruction(ref cause)
                    if matches!(cause.as_ref(), crate::business_reconstruction::BusinessReconstructionError::Invalid(
                        "source local ordered key/schema/proof differs"
                    ))
            ),
            "the index corpus is rejected by its owning complete source audit: {error}"
        );
        assert_refusal_unchanged(&world, &injected, &signer, 1);
        write_row(
            &world,
            &index_key_2,
            StateMutation::Put(index_bytes_2.clone()),
        );
        assert_logical_restore(&world, &before);
        let restored: VerifiedBusinessCut = source_cut(&world, &fixed, &ordered).unwrap();
        assert_eq!(restored.identity(), cut.identity());
        assert_eq!(restored.package_identity(), cut.package_identity());
    }
    // The whole-source owner separately authenticates this actual prior e0
    // drain carrier. Its request ID precedes the chosen current IDs, but its
    // epoch-scoped key is not traversed by the frontier's physical prefix.
    let (prior_key, prior_bytes): &(Vec<u8>, Vec<u8>) = &prior_drain[0];
    let prior_id: [u8; 32] = prior_key[drain_prefix.len()..].try_into().unwrap();
    assert!(prior_id <= last_prior && last_prior < request_id_1);
    for fault in 0u8..3 {
        let before: SourceBusinessSnapshot = source_snapshot(&world);
        match fault {
            0 => write_row(
                &world,
                prior_key,
                StateMutation::Put(altered_publication(prior_bytes)),
            ),
            1 => write_row(&world, prior_key, StateMutation::Delete),
            2 => {
                let connection: rusqlite::Connection =
                    rusqlite::Connection::open(world._files.path("serving-0-state.db")).unwrap();
                let removed: usize = connection
                    .execute(
                        "DELETE FROM durable_state WHERE key = ?1",
                        rusqlite::params![prior_key],
                    )
                    .unwrap();
                assert_eq!(
                    removed, 1,
                    "the hostile backend fault physically removes exactly one retained carrier"
                );
                let remaining: i64 = connection
                    .query_row(
                        "SELECT count(*) FROM durable_state WHERE key = ?1",
                        rusqlite::params![prior_key],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(remaining, 0);
                assert_eq!(world.value(0, prior_key), (StateRevision::INITIAL, None));
            }
            _ => unreachable!(),
        }
        let injected: SourceBusinessSnapshot = source_snapshot(&world);
        assert_eq!(
            advance(&signer).unwrap(),
            FrozenFrontierStep::Finalized(Box::new(final_vote.clone()))
        );
        let (served_vote, served_page): (FrozenFrontierVote, FrozenFrontierPage) =
            page(&world, 0, None).unwrap();
        assert_eq!(
            consensus::encode_frozen_frontier_vote(&served_vote).unwrap(),
            vote_bytes
        );
        assert_eq!(
            consensus::encode_frozen_frontier_page(&served_page).unwrap(),
            page_bytes
        );
        let expected_reason: &str = if fault == 2 {
            "complete source semantic projection differs from independent reconstruction"
        } else {
            "earlier protected row differs from the verified base"
        };
        let error: BusinessCutError = match source_cut(&world, &fixed, &ordered) {
            Err(error) => error,
            Ok(_) => panic!(
                "the full source cut must refuse the altered or missing actual prior carrier"
            ),
        };
        assert!(
            matches!(
                error,
                BusinessCutError::Reconstruction(ref cause)
                    if matches!(cause.as_ref(), crate::business_reconstruction::BusinessReconstructionError::Invalid(reason)
                        if *reason == expected_reason)
            ),
            "historical source refusal has the authentic prior-row cause: {error}"
        );
        assert_refusal_unchanged(&world, &injected, &signer, 1);
        write_row(&world, prior_key, StateMutation::Put(prior_bytes.clone()));
        assert_logical_restore(&world, &before);
        let restored: VerifiedBusinessCut = source_cut(&world, &fixed, &ordered)
            .expect("each real restore again validates the complete source cut");
        assert_eq!(restored.identity(), cut.identity());
        assert_eq!(restored.package_identity(), cut.package_identity());
    }
    let old: DurableOperationContext = world.operation;
    let new: DurableOperationContext = fixture::context(90);
    let old_warrant: crate::serving_authority::LiveWarrant<'_> = world.warrant(0);
    let before_fence: SourceBusinessSnapshot = source_snapshot(&world);
    let reopened: SqliteImportTarget = SqliteImportTarget::open_existing(
        world._files.path("serving-0-state.db"),
        SqliteNamespace::new(fixture::chain(), world.members[0].id, domain),
        chain_authority(&world).import_binding(),
    )
    .unwrap();
    reopened
        .advance_writer_fence(old.writer_fence(), new.writer_fence())
        .unwrap();
    let after_fence: SourceBusinessSnapshot =
        crate::test_support::capture::captured_source(&reopened, &world.targets[0].1, &new, domain);
    crate::test_support::capture::assert_same_records_and_blobs(&after_fence, &before_fence);
    assert!(
        advance_frozen_frontier_successor(
            &old_warrant,
            &world.targets[0].0,
            &old,
            domain,
            &network.resolver,
            &network.history,
            &current,
            &signer,
        )
        .is_err(),
        "the already-issued old writer cannot replay through a fresh fence"
    );
    assert!(
        resolve_live_authority(
            &world.targets[0].0,
            &old,
            domain,
            reconstruction_plan(world.source(), &world.cut_history),
            &world.sealed_history,
            &mut world.artifacts(),
            world.public_key(0),
        )
        .is_err()
    );
    let mut artifacts: Artifacts<'_> = world.artifacts();
    let replayed: LiveAuthority<'_> = resolve_live_authority(
        &reopened,
        &new,
        domain,
        reconstruction_plan(world.source(), &world.cut_history),
        &world.sealed_history,
        &mut artifacts,
        world.public_key(0),
    )
    .unwrap();
    let LiveAuthority::Successor(replay_warrant) = replayed else {
        unreachable!()
    };
    assert_eq!(
        advance_frozen_frontier_successor(
            &replay_warrant,
            &reopened,
            &new,
            domain,
            &network.resolver,
            &network.history,
            &current,
            &signer,
        )
        .unwrap(),
        FrozenFrontierStep::Finalized(Box::new(final_vote.clone()))
    );
    let (replay_vote, replay_page): (FrozenFrontierVote, FrozenFrontierPage) =
        read_frozen_frontier_page_successor(
            &replay_warrant,
            &reopened,
            &new,
            domain,
            &network.resolver,
            &network.history,
            &current,
            world.members[0].id,
            None,
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(replay_vote, final_vote);
    assert_eq!(replay_page, first_page);
    let (replay_terminal_vote, replay_terminal): (FrozenFrontierVote, FrozenFrontierPage) =
        read_frozen_frontier_page_successor(
            &replay_warrant,
            &reopened,
            &new,
            domain,
            &network.resolver,
            &network.history,
            &current,
            world.members[0].id,
            Some(request_id_2),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(replay_terminal_vote, final_vote);
    assert_eq!(
        consensus::encode_frozen_frontier_vote(&replay_vote).unwrap(),
        vote_bytes
    );
    assert_eq!(
        consensus::encode_frozen_frontier_page(&replay_page).unwrap(),
        page_bytes
    );
    assert_eq!(
        consensus::encode_frozen_frontier_page(&replay_terminal).unwrap(),
        terminal_bytes
    );
    let replay_entries: Vec<Vec<u8>> = replay_page
        .entries
        .iter()
        .map(|identity| consensus::encode_availability_identity(identity).unwrap())
        .collect();
    assert_eq!(replay_entries, entry_bytes);
    verify_stream(&world, &replay_vote, &replay_page, &replay_terminal);
    assert_eq!(
        signer.signatures.get(),
        1,
        "reopen/refencing creates no new signature"
    );
    assert_eq!(
        crate::test_support::capture::captured_source(&reopened, &world.targets[0].1, &new, domain),
        after_fence
    );
}
