//! Real SQLite activation with a hidden committed reply and one refused read.
//! Complete equal-store observations, not a physical SQLite I/O fault claim.
use super::super::sqlite_handoff_faults::{
    HandoffFaultPlan, PendingHandoffFault, SqliteHandoffFaults,
};
use super::*;
use crate::business_reconstruction::{SourceBusinessSnapshot, SourceSnapshotRecord};
use crate::fast_path::records::{
    decode_fastpath_validator_set_record, encode_fastpath_validator_set_record,
};
use crate::local_instance_state::{
    FastPathEpochRecord, decode_fastpath_epoch_record, encode_fastpath_epoch_record,
    execution_policy_key_for_profile, fastpath_epoch_record_key, fastpath_validator_set_key,
    paid_fee_policy_key,
};
use crate::logical_generation::{
    LogicalKeySpace, LogicalObservation, LogicalProfileRecord, LogicalProvenanceRecord,
    LogicalSubject, content_digest, decode_logical_profile_record,
    decode_logical_provenance_record, encode_logical_provenance_record, logical_profile_key,
};
use crate::publication::{LocalPublicationPolicy, publication_policy_key_for_profile};
use crate::serving_authority::{SuccessorActivationError, VerifiedSuccessorAuthority};
use crate::test_support::capture::{assert_same_records_and_blobs, captured_source};
use consensus::{
    ConsensusState, decode_committed_block_proof, decode_consensus_state, encode_consensus_state,
};
use execution::paid_execution::{PaidFeePolicy, decode_paid_fee_policy, encode_paid_fee_policy};
use protocol_types::{Epoch, ExecutionGeneration};
use runtime::portable::{
    DurableCollection, DurableRecordKey, DurableRecordMetadata, PortableSnapshotToken,
};
use runtime::{
    AtomicityDomainId, DurableRequestReceipt, ImportProgress, InactiveImportRepository,
    IndeterminateCommitReason, NamespaceLifecycle, OutgoingBarrier, StateRevision,
    SuccessorServingRecord, SuccessorServingRepository, decode_successor_serving_record,
    encode_successor_serving_record,
};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

fn state_row<'a>(
    source: &'a SourceBusinessSnapshot,
    key: &[u8],
) -> Option<&'a SourceSnapshotRecord> {
    source.records.iter().find(|row: &&SourceSnapshotRecord| {
        matches!(row.descriptor.key(), DurableRecordKey::State(actual) if actual == key)
    })
}

fn state_bytes<'a>(source: &'a SourceBusinessSnapshot, key: &[u8]) -> &'a [u8] {
    state_row(source, key).unwrap().value.as_deref().unwrap()
}

fn state_revision(row: &SourceSnapshotRecord) -> StateRevision {
    let DurableRecordMetadata::State { revision, .. } = row.descriptor.metadata() else {
        panic!("state observation must retain its physical revision");
    };
    *revision
}

fn protected_state(
    target: &SqliteImportTarget,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> (
    SuccessorServingSlot,
    NamespaceLifecycle,
    Option<ImportProgress>,
    OutgoingBarrier,
) {
    (
        target.get_successor_serving(operation, domain).unwrap(),
        target.get_namespace_lifecycle(operation, domain).unwrap(),
        target.read_import_progress(operation, domain).unwrap(),
        target.get_outgoing_barrier(operation, domain).unwrap(),
    )
}

fn assert_counts(faults: &SqliteHandoffFaults<'_>, activations: usize, refused_reads: usize) {
    assert_eq!(faults.successor_activation_calls.get(), activations);
    assert_eq!(faults.reconciliation_read_failures.get(), refused_reads);
    assert_eq!(faults.outgoing_getter_calls.get(), 0);
    assert_eq!(faults.ordinary_durable_calls.get(), 0);
    assert_eq!(faults.ordinary_invocation_calls.get(), 0);
    assert_eq!(faults.successor_retention_calls.get(), 0);
    assert_eq!(faults.successor_completion_calls.get(), 0);
    assert_eq!(faults.live_race_calls.get(), 0);
    assert_eq!(faults.competing_activation_calls.get(), 0);
    assert!(faults.after_race.borrow().is_none());
    assert!(faults.after_competing_activation.borrow().is_none());
}

#[test]
fn first_successor_activation_reply_loss_on_real_sqlite() {
    let fixture: seal_signing::SealSigningFixture = seal_signing::seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (cut_history, history_before): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let cut: crate::business_reconstruction::cut::VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &network.stores[0],
        &network.blobs,
        &history_before,
    )
    .unwrap();
    assert_eq!(cut.identity(), &fixture.cut_identity);
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let plan: VerifiedImportPlan = verify_saved_business_import(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &saved,
    )
    .unwrap();
    let env_before: OrderedEconomicsEnvironment<'_> = seal_signing::env_with_seal(network);
    seal_acceptance::accept_genuine_seal(&fixture, &env_before);
    let (sealed_history, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    assert!(sealed_history.through_height > cut_history.through_height);
    let certificate: Vec<u8> = network
        .blobs
        .get_blob(&fixture.certificate_digest)
        .unwrap()
        .unwrap();
    let mut artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &certificate,
    };
    let authority: VerifiedSuccessorAuthority = verify_successor_authority(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
    )
    .unwrap();
    assert_eq!(authority.import_binding(), plan.binding());
    let expected_subject: Digest32 = authority.subject_digest();
    let expected_manifest: Digest32 = authority.manifest_digest();
    let next_context: PublicationContext = authority.policy_inputs().context().clone();
    let outgoing: Epoch = plan.binding().context.epoch;
    let next_epoch: Epoch = Epoch::new(outgoing.get().checked_add(1).unwrap());
    assert_eq!(next_context.epoch(), next_epoch);
    assert_eq!(next_context.chain_id(), &plan.binding().context.chain_id);
    assert_eq!(
        next_context.protocol_version(),
        plan.binding().context.protocol_version
    );
    assert_eq!(authority.policy_inputs().domain(), network.domain());
    assert_eq!(
        authority.policy_inputs().generation_floor(),
        plan.binding().generation_floor
    );
    let set_digest: Digest32 = authority.validator_set().digest(&network.resolver).unwrap();
    assert_eq!(fixture.subject.next_set_digest, set_digest);
    let operation: DurableOperationContext = fixture::context(41);
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    let mut targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = Vec::new();
    let mut signers: Vec<ReadinessSigningKey> = Vec::new();
    for index in 0_usize..3_usize {
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture::chain(),
            network.signers[index].id,
            network.domain(),
        );
        let target: SqliteImportTarget = SqliteImportTarget::create(
            files.path(&format!("activation-reply-state-{index}.db")),
            namespace,
            operation.writer_fence(),
            plan.binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore =
            SqliteBlobStore::open(files.path(&format!("activation-reply-body-{index}.db")))
                .unwrap();
        conditional_readiness::complete(&plan, &target, &blobs, &operation);
        signers.push(ReadinessSigningKey::new(
            network.signers[index].id,
            network.signers[index].key,
        ));
        targets.push((target, blobs));
    }
    let before: Vec<SourceBusinessSnapshot> = targets
        .iter()
        .map(|(target, blobs): &(SqliteImportTarget, SqliteBlobStore)| {
            captured_source(target, blobs, &operation, network.domain())
        })
        .collect();
    assert_same_records_and_blobs(&before[0], &before[2]);
    assert_same_records_and_blobs(&before[1], &before[2]);
    let mut pre_observations: Vec<(ImportProgress, PortableSnapshotToken)> = Vec::new();
    for (index, (target, blobs)) in targets.iter().enumerate() {
        let (progress, token): (ImportProgress, PortableSnapshotToken) =
            plan.observe_complete(target, blobs, &operation).unwrap();
        assert_eq!(&progress, plan.complete_progress());
        assert_eq!(token, before[index].token);
        assert_eq!(token.domain(), network.domain());
        assert_eq!(token.writer_fence(), operation.writer_fence());
        assert_eq!(
            protected_state(target, &operation, network.domain()),
            (
                SuccessorServingSlot::Inactive,
                NamespaceLifecycle::CompleteInactive {
                    binding: plan.binding().clone(),
                    progress: progress.clone()
                },
                Some(progress.clone()),
                OutgoingBarrier::Unsealed,
            )
        );
        let validator: ValidatorId = target
            .read_namespace_validator(&operation, network.domain())
            .unwrap();
        assert_eq!(validator, network.signers[index].id);
        let member: &ValidatorInfo = authority.validator_set().get(validator).unwrap();
        assert_eq!(member.signature_scheme, SignatureSchemeId::Ed25519);
        assert_eq!(
            member.public_key.as_slice(),
            signers[index].public_key().as_slice()
        );
        assert_eq!(signers[index].signatures_created(), 0);
        pre_observations.push((progress, token));
    }

    // F and S keep the same counted wrapper through later settlement.
    let failure: SqliteHandoffFaults<'_> = SqliteHandoffFaults::new(
        &targets[0].0,
        HandoffFaultPlan::LoseCommittedActivationReplyThenFailReconciliation,
    );
    let success: SqliteHandoffFaults<'_> = SqliteHandoffFaults::new(
        &targets[1].0,
        HandoffFaultPlan::LoseCommittedActivationReply,
    );
    assert_eq!(
        failure.pending_faults(),
        vec![
            PendingHandoffFault::ActivationCommittedReplyLossBeforeReconciliationFailure,
            PendingHandoffFault::ReconciliationBarrierReadFailure,
        ]
    );
    assert_eq!(
        success.pending_faults(),
        vec![PendingHandoffFault::ActivationCommittedReplyLoss]
    );
    assert_counts(&failure, 0, 0);
    assert_counts(&success, 0, 0);
    let failed: Result<SuccessorActivationOutcome, SuccessorActivationError> = activate_successor(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
        &failure,
        &targets[0].1,
        &operation,
        &signers[0],
        1,
    );
    assert!(matches!(
        failed,
        Err(SuccessorActivationError::Indeterminate(
            IndeterminateCommitReason::CancellationRequested,
        ))
    ));
    let succeeded: SuccessorActivationOutcome = activate_successor(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
        &success,
        &targets[1].1,
        &operation,
        &signers[1],
        1,
    )
    .unwrap();
    assert!(
        matches!(succeeded, SuccessorActivationOutcome::Activated { subject, manifest }
        if subject == expected_subject && manifest == expected_manifest)
    );
    let control: SuccessorActivationOutcome = activate_successor(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
        &targets[2].0,
        &targets[2].1,
        &operation,
        &signers[2],
        1,
    )
    .unwrap();
    assert!(
        matches!(control, SuccessorActivationOutcome::Activated { subject, manifest }
        if subject == expected_subject && manifest == expected_manifest)
    );
    assert!(failure.pending_faults().is_empty());
    assert!(success.pending_faults().is_empty());
    assert_counts(&failure, 1, 1);
    assert_counts(&success, 1, 0);
    let landed: Vec<SourceBusinessSnapshot> = targets
        .iter()
        .map(|(target, blobs): &(SqliteImportTarget, SqliteBlobStore)| {
            captured_source(target, blobs, &operation, network.domain())
        })
        .collect();
    assert_same_records_and_blobs(&landed[0], &landed[2]);
    assert_same_records_and_blobs(&landed[1], &landed[2]);

    // Independent public codecs and genuine source facts, never the challenged
    // activation mutation builder or private reconstruction bootstrap.
    let chain: &protocol_types::ChainId = next_context.chain_id();
    let new_revision: StateRevision = StateRevision::INITIAL.checked_next().unwrap();
    let mut expected_state: BTreeMap<Vec<u8>, (StateRevision, Vec<u8>)> = BTreeMap::new();
    let epoch_key: Vec<u8> = fastpath_epoch_record_key(chain).unwrap();
    let old_epoch: FastPathEpochRecord =
        decode_fastpath_epoch_record(state_bytes(&before[2], &epoch_key)).unwrap();
    assert_eq!(old_epoch.current_epoch, outgoing);
    let epoch_record: FastPathEpochRecord = FastPathEpochRecord {
        current_epoch: next_epoch,
        current_validator_set_digest: set_digest,
        previous_epoch: Some(outgoing),
        activated_at_checkpoint: sealed_history.through_height,
    };
    assert!(
        expected_state
            .insert(
                epoch_key.clone(),
                (
                    state_revision(state_row(&before[2], &epoch_key).unwrap())
                        .checked_next()
                        .unwrap(),
                    encode_fastpath_epoch_record(&epoch_record).unwrap(),
                )
            )
            .is_none()
    );
    let mut members: Vec<FastPathValidatorEntry> = network
        .signers
        .iter()
        .map(|member: &TestSigner| FastPathValidatorEntry {
            id: member.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: VerificationKey::from(&member.key).as_ref().to_vec(),
        })
        .collect();
    members.sort_by_key(|member: &FastPathValidatorEntry| member.id);
    let set_record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: next_context.clone(),
        validators: members,
    };
    let set_key: Vec<u8> = fastpath_validator_set_key(&next_context).unwrap();
    assert!(state_row(&before[2], &set_key).is_none());
    assert!(
        expected_state
            .insert(
                set_key.clone(),
                (
                    new_revision,
                    encode_fastpath_validator_set_record(&set_record).unwrap(),
                )
            )
            .is_none()
    );
    let execution: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(next_context.clone());
    let execution_key: Vec<u8> = execution_policy_key_for_profile(&next_context, 4).unwrap();
    let outgoing_context: PublicationContext =
        PublicationContext::new(chain.clone(), next_context.protocol_version(), outgoing).unwrap();
    let old_fee_key: Vec<u8> = paid_fee_policy_key(&outgoing_context).unwrap();
    let old_fee: PaidFeePolicy =
        decode_paid_fee_policy(state_bytes(&before[2], &old_fee_key)).unwrap();
    assert_eq!(old_fee.context, outgoing_context);
    let fee: PaidFeePolicy = PaidFeePolicy {
        context: next_context.clone(),
        base_policy_digest: execution.digest(&network.resolver).unwrap(),
        ..old_fee
    };
    let fee_key: Vec<u8> = paid_fee_policy_key(&next_context).unwrap();
    let publication: LocalPublicationPolicy = LocalPublicationPolicy::object_results(
        next_context.clone(),
        execution::local_execution::generic_object_result_semantics(
            &network.resolver,
            &next_context,
        )
        .unwrap(),
    );
    let publication_key: Vec<u8> = publication_policy_key_for_profile(&next_context, 4).unwrap();
    let policy_values: [(Vec<u8>, Vec<u8>); 3] = [
        (execution_key.clone(), execution.encode().unwrap()),
        (fee_key.clone(), encode_paid_fee_policy(&fee).unwrap()),
        (publication_key.clone(), publication.encode().unwrap()),
    ];
    let profile: LogicalProfileRecord = decode_logical_profile_record(state_bytes(
        &before[2],
        &logical_profile_key(chain).unwrap(),
    ))
    .unwrap();
    let key_space: LogicalKeySpace<'_> = LogicalKeySpace::new(&profile, &network.resolver);
    let old_fee_subject: LogicalSubject = LogicalSubject::StateKey(old_fee_key.clone());
    let old_fee_provenance_key: Vec<u8> = key_space.provenance_key(&old_fee_subject).unwrap();
    let old_fee_provenance: LogicalProvenanceRecord =
        decode_logical_provenance_record(state_bytes(&before[2], &old_fee_provenance_key)).unwrap();
    assert_eq!(old_fee_provenance.subject, old_fee_subject);
    assert_eq!(
        old_fee_provenance.observation,
        LogicalObservation::StatePresent {
            content_digest: content_digest(
                &network.resolver,
                old_fee_provenance.observed_epoch,
                state_bytes(&before[2], &old_fee_key)
            )
            .unwrap(),
        }
    );
    let generation: ExecutionGeneration = ExecutionGeneration::new(
        authority
            .policy_inputs()
            .generation_floor()
            .get()
            .max(old_fee_provenance.generation.get())
            .checked_add(1)
            .unwrap(),
    );
    for (key, bytes) in &policy_values {
        assert!(state_row(&before[2], key).is_none());
        assert!(
            expected_state
                .insert(key.clone(), (new_revision, bytes.clone()))
                .is_none()
        );
        let subject: LogicalSubject = LogicalSubject::StateKey(key.clone());
        let provenance_key: Vec<u8> = key_space.provenance_key(&subject).unwrap();
        assert!(state_row(&before[2], &provenance_key).is_none());
        let provenance: LogicalProvenanceRecord = LogicalProvenanceRecord {
            subject,
            observed_epoch: next_epoch,
            generation,
            observation: LogicalObservation::StatePresent {
                content_digest: content_digest(&network.resolver, next_epoch, bytes).unwrap(),
            },
        };
        let encoded: Vec<u8> = encode_logical_provenance_record(&provenance).unwrap();
        assert_eq!(
            decode_logical_provenance_record(&encoded).unwrap(),
            provenance
        );
        assert!(
            expected_state
                .insert(provenance_key, (new_revision, encoded))
                .is_none()
        );
    }
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&network.root, authority.policy_inputs()).unwrap();
    let genesis_key: Vec<u8> = engine::scoped_state_key(policy.key_scope(), chain).unwrap();
    assert!(state_row(&before[2], &genesis_key).is_none());
    let genesis: ConsensusState = policy.engine().genesis_state(1);
    assert_eq!(genesis.current_view, 1);
    assert_eq!(genesis.last_voted_view, 0);
    assert_eq!(genesis.last_voted_digest, None);
    assert_eq!(genesis.committed_height, 0);
    assert_eq!(genesis.high_qc, genesis.locked_qc);
    assert_eq!(genesis.high_qc.epoch, next_epoch);
    assert_eq!(
        genesis.high_qc.proposal_digest,
        authority.policy_inputs().anchor()
    );
    assert!(
        expected_state
            .insert(
                genesis_key.clone(),
                (new_revision, encode_consensus_state(&genesis).unwrap(),)
            )
            .is_none()
    );
    let untouched_roots: [Vec<u8>; 2] = [
        engine::scoped_applied_height_key(policy.key_scope(), chain).unwrap(),
        engine::scoped_vote_high_key(policy.key_scope(), chain).unwrap(),
    ];
    for key in &untouched_roots {
        assert!(state_row(&before[2], key).is_none());
    }

    let suffix_start: u64 = cut_history.through_height.checked_add(1).unwrap();
    for height in suffix_start..=sealed_history.through_height {
        let material: &OrderedHistoryHeightMaterial = history
            .iter()
            .find(|item: &&OrderedHistoryHeightMaterial| item.descriptor.height == height)
            .unwrap();
        let proofs: Vec<&Vec<u8>> = material
            .components
            .iter()
            .filter_map(|(kind, bytes): &(OrderedHistoryComponentKind, Vec<u8>)| {
                (*kind == OrderedHistoryComponentKind::CommitProof).then_some(bytes)
            })
            .collect();
        assert_eq!(proofs.len(), 1);
        let proof: CommittedBlockProof = decode_committed_block_proof(proofs[0]).unwrap();
        assert_eq!(proof.committed.height, height);
        assert_eq!(
            network
                .policy
                .engine()
                .proposal_digest(&proof.committed)
                .unwrap(),
            material.descriptor.block_digest
        );
        let key: Vec<u8> = engine::ordered_committed_proof_key(chain, outgoing, height).unwrap();
        assert!(state_row(&before[2], &key).is_none());
        assert!(
            expected_state
                .insert(key, (new_revision, proofs[0].clone()))
                .is_none()
        );
    }
    let terminal: &OrderedHistoryHeightMaterial = history
        .iter()
        .find(|item: &&OrderedHistoryHeightMaterial| {
            item.descriptor.height == sealed_history.through_height
        })
        .unwrap();
    let component = |kind: OrderedHistoryComponentKind| -> Vec<u8> {
        let values: Vec<&Vec<u8>> = terminal
            .components
            .iter()
            .filter_map(|(actual, bytes): &(OrderedHistoryComponentKind, Vec<u8>)| {
                (*actual == kind).then_some(bytes)
            })
            .collect();
        assert_eq!(values.len(), 1);
        values[0].clone()
    };
    let candidate_bytes: Vec<u8> = component(OrderedHistoryComponentKind::Candidate);
    let candidate: OrderedCandidate = decode_ordered_candidate(&candidate_bytes).unwrap();
    assert_eq!(candidate, fixture.candidate);
    assert_eq!(candidate.kind, OrderedOperationKind::Seal);
    let candidate_digest: Digest32 = network.policy.candidate_digest(&fixture.candidate).unwrap();
    let header_bytes: Vec<u8> = component(OrderedHistoryComponentKind::RequestHeader);
    let header: engine::RequestHeader = engine::decode_request_header(&header_bytes).unwrap();
    assert_eq!(header.candidate_digest, candidate_digest);
    assert_eq!(header.kind, OrderedOperationKind::Seal);
    assert_eq!(
        header.created_checkpoint,
        fixture.candidate.created_checkpoint
    );
    let outcome_bytes: Vec<u8> = component(OrderedHistoryComponentKind::RetainedOutcome);
    let outcome: OrderedOutcome = engine::decode_retained_outcome(&outcome_bytes).unwrap();
    assert_eq!(outcome.candidate_digest, candidate_digest);
    assert_eq!(outcome.request_id, fixture.candidate.request_id);
    assert_eq!(outcome.block_height, sealed_history.through_height);
    assert_eq!(outcome.block_digest, terminal.descriptor.block_digest);
    assert!(outcome.output.outbound_messages().is_empty());
    assert_eq!(outcome.output.responses().len(), 1);
    let response: &crate::NodeResponse = &outcome.output.responses()[0];
    assert_eq!(response.status(), crate::NodeResponseStatus::Accepted);
    assert_eq!(
        response.request_id().as_bytes(),
        &fixture.candidate.request_id
    );
    let intent: seal::SealIntent = seal::decode_seal_intent(&fixture.candidate.intent).unwrap();
    let seal_target: Digest32 = seal::seal_target_digest(
        &network.resolver,
        &fixture.candidate.context,
        intent
            .readiness_subject
            .identity(&network.resolver)
            .unwrap(),
        intent.predecessor_tag,
        intent.predecessor_digest,
    )
    .unwrap();
    assert_eq!(
        seal::decode_seal_outcome(response.payload().unwrap()).unwrap(),
        seal::SealOutcome {
            target: seal_target,
            request: fixture.candidate.request_id,
            seal_block_height: sealed_history.through_height,
            seal_block_digest: terminal.descriptor.block_digest,
        }
    );
    for (key, bytes) in [
        (
            engine::ordered_candidate_record_key(chain, candidate_digest).unwrap(),
            candidate_bytes,
        ),
        (
            engine::ordered_request_header_key(chain, &fixture.candidate.request_id).unwrap(),
            header_bytes,
        ),
        (
            engine::ordered_outcome_key(chain, &fixture.candidate.request_id).unwrap(),
            outcome_bytes,
        ),
    ] {
        assert!(state_row(&before[2], &key).is_none());
        assert!(expected_state.insert(key, (new_revision, bytes)).is_none());
    }
    let receipt_bytes: Vec<u8> = component(OrderedHistoryComponentKind::OriginalReceipt);
    let dedup: NodeDedupRecord = NodeDedupRecord::decode(&receipt_bytes).unwrap();
    assert_eq!(dedup.request_id().as_bytes(), &fixture.candidate.request_id);
    assert_eq!(dedup.responses(), outcome.output.responses());
    assert_eq!(dedup.encode().unwrap(), receipt_bytes);
    let receipt_id: runtime::DurableRequestId =
        runtime::DurableRequestId::new(fixture.candidate.request_id).unwrap();
    let original_receipt: DurableRequestReceipt = network.stores[0]
        .get_request_receipt(&network.context, network.domain(), receipt_id)
        .unwrap()
        .unwrap();
    assert_eq!(original_receipt.request_id(), receipt_id);
    assert_eq!(original_receipt.event_digest(), dedup.event_digest());
    assert_eq!(original_receipt.canonical_bytes(), receipt_bytes.as_slice());
    let receipt_descriptor: DurableRecordDescriptor = DurableRecordDescriptor::new(
        DurableRecordKey::Receipt(receipt_id),
        DurableRecordMetadata::Receipt {
            event_digest: original_receipt.event_digest(),
            length: NonZeroUsize::new(receipt_bytes.len()).unwrap(),
        },
    )
    .unwrap();
    let expected_receipt: SourceSnapshotRecord = SourceSnapshotRecord {
        descriptor: receipt_descriptor,
        value: Some(receipt_bytes),
    };

    for (index, (target, _blobs)) in targets.iter().enumerate() {
        let pre: &SourceBusinessSnapshot = &before[index];
        let post: &SourceBusinessSnapshot = &landed[index];
        let (progress, pre_token): &(ImportProgress, PortableSnapshotToken) =
            &pre_observations[index];
        assert_eq!(post.token.namespace(), pre_token.namespace());
        assert_eq!(post.token.domain(), pre_token.domain());
        assert_eq!(post.token.writer_fence(), pre_token.writer_fence());
        assert_eq!(
            post.token.mutation_sequence(),
            pre_token.mutation_sequence().checked_add(1).unwrap()
        );
        let pre_state: Vec<&SourceSnapshotRecord> = pre
            .records
            .iter()
            .filter(|row: &&SourceSnapshotRecord| {
                row.descriptor.key().collection() == DurableCollection::State
            })
            .collect();
        let post_state: Vec<&SourceSnapshotRecord> = post
            .records
            .iter()
            .filter(|row: &&SourceSnapshotRecord| {
                row.descriptor.key().collection() == DurableCollection::State
            })
            .collect();
        assert_ne!(
            pre_state, post_state,
            "actual activation changed persisted State rows"
        );
        let mut changed: BTreeSet<Vec<u8>> = BTreeSet::new();
        for row in &post_state {
            let DurableRecordKey::State(key) = row.descriptor.key() else {
                unreachable!()
            };
            if state_row(pre, key) != Some(*row) {
                assert!(changed.insert(key.clone()));
            }
        }
        let expected_keys: BTreeSet<Vec<u8>> = expected_state.keys().cloned().collect();
        assert_eq!(changed, expected_keys);
        for row in &pre_state {
            let DurableRecordKey::State(key) = row.descriptor.key() else {
                unreachable!()
            };
            let retained: &SourceSnapshotRecord = state_row(post, key).unwrap();
            if !expected_state.contains_key(key) {
                assert_eq!(retained, *row);
            }
        }
        for (key, (revision, bytes)) in &expected_state {
            let actual: &SourceSnapshotRecord = state_row(post, key).unwrap();
            let expected_descriptor: DurableRecordDescriptor = DurableRecordDescriptor::new(
                DurableRecordKey::State(key.clone()),
                DurableRecordMetadata::State {
                    revision: *revision,
                    value_length: Some(bytes.len()),
                },
            )
            .unwrap();
            assert_eq!(actual.descriptor, expected_descriptor);
            assert_eq!(actual.value.as_deref(), Some(bytes.as_slice()));
        }
        assert_eq!(
            decode_fastpath_epoch_record(state_bytes(post, &epoch_key)).unwrap(),
            epoch_record
        );
        assert_eq!(
            decode_fastpath_validator_set_record(state_bytes(post, &set_key)).unwrap(),
            set_record
        );
        assert_eq!(
            LocalExecutionPolicy::decode(state_bytes(post, &execution_key)).unwrap(),
            execution
        );
        assert_eq!(
            decode_paid_fee_policy(state_bytes(post, &fee_key)).unwrap(),
            fee
        );
        assert_eq!(
            LocalPublicationPolicy::decode(state_bytes(post, &publication_key)).unwrap(),
            publication
        );
        assert_eq!(
            decode_consensus_state(state_bytes(post, &genesis_key)).unwrap(),
            genesis
        );
        assert_eq!(state_row(post, &old_fee_key), state_row(pre, &old_fee_key));
        assert_eq!(
            state_row(post, &old_fee_provenance_key),
            state_row(pre, &old_fee_provenance_key)
        );
        for key in &untouched_roots {
            assert!(state_row(post, key).is_none());
        }
        for collection in [
            DurableCollection::ObjectHeads,
            DurableCollection::ObjectVersions,
        ] {
            let pre_rows: Vec<&SourceSnapshotRecord> = pre
                .records
                .iter()
                .filter(|row: &&SourceSnapshotRecord| {
                    row.descriptor.key().collection() == collection
                })
                .collect();
            let post_rows: Vec<&SourceSnapshotRecord> = post
                .records
                .iter()
                .filter(|row: &&SourceSnapshotRecord| {
                    row.descriptor.key().collection() == collection
                })
                .collect();
            assert_eq!(post_rows, pre_rows);
        }
        assert_eq!(post.referenced_blobs, pre.referenced_blobs);
        let pre_receipts: Vec<&SourceSnapshotRecord> = pre
            .records
            .iter()
            .filter(|row: &&SourceSnapshotRecord| {
                row.descriptor.key().collection() == DurableCollection::Receipts
            })
            .collect();
        let post_receipts: Vec<&SourceSnapshotRecord> = post
            .records
            .iter()
            .filter(|row: &&SourceSnapshotRecord| {
                row.descriptor.key().collection() == DurableCollection::Receipts
            })
            .collect();
        assert!(
            pre_receipts
                .iter()
                .all(|row: &&SourceSnapshotRecord| row.descriptor.key()
                    != expected_receipt.descriptor.key())
        );
        assert_eq!(
            post_receipts.len(),
            pre_receipts.len().checked_add(1).unwrap()
        );
        for row in pre_receipts {
            assert!(post_receipts.contains(&row));
        }
        assert!(post_receipts.contains(&&expected_receipt));
        assert_eq!(
            target
                .get_request_receipt(&operation, network.domain(), receipt_id)
                .unwrap(),
            Some(original_receipt.clone())
        );
        let protected: (
            SuccessorServingSlot,
            NamespaceLifecycle,
            Option<ImportProgress>,
            OutgoingBarrier,
        ) = protected_state(target, &operation, network.domain());
        assert_eq!(
            protected.1,
            NamespaceLifecycle::CompleteInactive {
                binding: plan.binding().clone(),
                progress: progress.clone(),
            }
        );
        assert_eq!(protected.2, Some(progress.clone()));
        assert_eq!(protected.3, OutgoingBarrier::Unsealed);
        let SuccessorServingSlot::Serving(observation) = protected.0 else {
            panic!("the real activation must install Serving");
        };
        assert_eq!(observation.binding, *plan.binding());
        assert_eq!(observation.progress, *progress);
        let expected: SuccessorServingRecord = SuccessorServingRecord {
            subject: expected_subject,
            manifest: expected_manifest,
            binding: plan.binding().clone(),
            progress: progress.clone(),
            activation_token: pre_token.clone(),
            anchor: authority.policy_inputs().anchor(),
            validator: network.signers[index].id,
            public_key: signers[index].public_key(),
        };
        assert_eq!(
            observation.record,
            encode_successor_serving_record(&expected).unwrap()
        );
        let actual: SuccessorServingRecord =
            decode_successor_serving_record(&observation.record).unwrap();
        assert_eq!(actual.subject, expected.subject);
        assert_eq!(actual.manifest, expected.manifest);
        assert_eq!(actual.binding, expected.binding);
        assert_eq!(actual.progress, expected.progress);
        assert_eq!(actual.activation_token, expected.activation_token);
        assert_eq!(actual.anchor, expected.anchor);
        assert_eq!(actual.validator, expected.validator);
        assert_eq!(actual.public_key, expected.public_key);
        assert_eq!(signers[index].signatures_created(), 0);
    }

    // Reconcile both ambiguous calls on their SAME consumed counted port.
    for (index, faults, refused_reads) in
        [(0_usize, &failure, 1_usize), (1_usize, &success, 0_usize)]
    {
        let (target, blobs): &(SqliteImportTarget, SqliteBlobStore) = &targets[index];
        let prior: SourceBusinessSnapshot =
            captured_source(target, blobs, &operation, network.domain());
        let prior_protected: (
            SuccessorServingSlot,
            NamespaceLifecycle,
            Option<ImportProgress>,
            OutgoingBarrier,
        ) = protected_state(target, &operation, network.domain());
        assert_eq!(prior, landed[index]);
        assert!(faults.pending_faults().is_empty());
        assert_counts(faults, 1, refused_reads);
        let settled: SuccessorActivationOutcome = activate_successor(
            reconstruction_plan(&fixture.source.fixture, &cut_history),
            &sealed_history,
            &mut artifacts,
            faults,
            blobs,
            &operation,
            &signers[index],
            1,
        )
        .unwrap();
        assert!(
            matches!(settled, SuccessorActivationOutcome::AlreadyActivated { subject, manifest }
            if subject == expected_subject && manifest == expected_manifest)
        );
        assert!(faults.pending_faults().is_empty());
        assert_counts(faults, 1, refused_reads);
        assert_eq!(
            captured_source(target, blobs, &operation, network.domain()),
            prior
        );
        assert_eq!(
            protected_state(target, &operation, network.domain()),
            prior_protected
        );
        assert_eq!(signers[index].signatures_created(), 0);
    }
}
