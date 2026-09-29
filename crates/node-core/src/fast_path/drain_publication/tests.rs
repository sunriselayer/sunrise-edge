use super::*;
use crate::fast_path::tests::{
    RetentionReplica, installed_validator_set, logical_replica, physical_replica,
    transfer_bundle_bytes,
};
use crate::ordered_economics::{
    AdmissionClosureRecord, FrozenFrontierStep, advance_frozen_frontier,
    encode_admission_closure_record, read_frozen_frontier_page,
};
use crate::paid_execution::tests::{FIRST_PAID_NONCE, context, domain, protocol, resolver};
use consensus::bundle::encode_publication_bundle;
use consensus::{AvailabilityVote, FrozenFrontierPage, FrozenFrontierVote};
use runtime::{DurableDomainStateStore, MemoryDurableStateStore};
use std::{cell::Cell, num::NonZeroUsize};

const REQUEST: u8 = 0xE4;

fn close(replica: &RetentionReplica) {
    let record: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0x55; 32],
        closed_at_block_height: 3,
    };
    let key: Vec<u8> =
        crate::ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
            .unwrap();
    replica.put_row(key, encode_admission_closure_record(&record).unwrap());
}

fn identity(bundle: &PublicationBundle) -> AvailabilityIdentity {
    verify_bundle(
        &resolver(),
        &[],
        &protocol(),
        domain(),
        &installed_validator_set(),
        bundle,
    )
    .unwrap()
}

fn import(
    replica: &RetentionReplica,
    bundle: &PublicationBundle,
    expected_identity: &AvailabilityIdentity,
) -> DrainResult<AvailabilityIdentity> {
    retain_drain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        expected_identity,
        &encode_publication_bundle(bundle).unwrap(),
    )
}

/// Writes the exact `drain-publication/`+`drain-publication-artifact/` rows
/// [`retain_drain_publication`] would have written, but deliberately leaves
/// the `drain-possession/` marker key completely untouched (pristine,
/// `StateRevision::INITIAL`) -- simulating a same-epoch restore that carried
/// the authenticated proof/artifact history without importing the local
/// marker.
fn stage_proof_without_marker(
    replica: &RetentionReplica,
    bundle: &PublicationBundle,
    identity: &AvailabilityIdentity,
) {
    let chain: ChainId = protocol().chain_id().clone();
    let epoch: Epoch = protocol().epoch();
    let record: FastPathPublicationRecord = FastPathPublicationRecord {
        context: protocol(),
        request_id: bundle.request_id,
        identity: encode_availability_identity(identity).unwrap(),
        signed_intent: bundle.signed_intent.clone(),
        certificate: encode_fast_certificate(&bundle.certificate).unwrap(),
        witness: bundle.witness.clone(),
        manifest: encode_artifact_manifest(&bundle.manifest).unwrap(),
    };
    for (entry, content) in bundle.manifest.entries.iter().zip(bundle.contents.iter()) {
        let key: Vec<u8> =
            drain_publication_artifact_key(&chain, epoch, &bundle.request_id, entry).unwrap();
        replica.put_row(key, content.clone());
    }
    let key: Vec<u8> = drain_publication_key(&chain, epoch, &bundle.request_id).unwrap();
    replica.put_row(key, encode_fastpath_publication_record(&record).unwrap());
}

fn closure_key() -> Vec<u8> {
    crate::ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
        .unwrap()
}

fn delete_row(replica: &RetentionReplica, key: Vec<u8>) {
    let revision: StateRevision = replica
        .store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap()
        .revision();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), revision).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        replica.store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn assert_no_import(replica: &RetentionReplica) {
    for key in [
        drain_publication_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap(),
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap(),
    ] {
        assert!(replica.row(&key).is_none());
    }
}

/// Lands a real competing state write after the importer has read its
/// profile/epoch/set/Freeze fence but immediately before its atomic commit.
/// This proves the read assertion rejects the entire import, not just the
/// metadata write that raced.
struct RacingStore<'a> {
    inner: &'a MemoryDurableStateStore,
    race_key: Vec<u8>,
    race_value: Vec<u8>,
    raced: Cell<bool>,
}

impl DurableDomainStateStore for RacingStore<'_> {
    fn get_versioned_durable(
        &self,
        operation: &DurableOperationContext,
        atomicity_domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner
            .get_versioned_durable(operation, atomicity_domain, key)
    }

    fn commit_durable(
        &self,
        operation: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.raced.replace(true) {
            let observed: VersionedStateValue = self
                .inner
                .get_versioned_durable(operation, domain(), &self.race_key)
                .unwrap();
            let foreign: AtomicStateTransaction = AtomicStateTransaction::new(
                domain(),
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(self.race_key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(
                        self.race_key.clone(),
                        StateMutation::Put(self.race_value.clone()),
                    )
                    .unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                self.inner.commit_durable(operation, foreign),
                DurableCommitOutcome::Committed
            );
        }
        self.inner.commit_durable(operation, transaction)
    }
}

impl StructuredDurableDomainStateStore for RacingStore<'_> {
    fn get_object_head(
        &self,
        operation: &DurableOperationContext,
        atomicity_domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner
            .get_object_head(operation, atomicity_domain, object_id)
    }

    fn get_object_version(
        &self,
        operation: &DurableOperationContext,
        atomicity_domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(operation, atomicity_domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        operation: &DurableOperationContext,
        atomicity_domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner
            .get_request_receipt(operation, atomicity_domain, request_id)
    }

    fn commit_invocation(
        &self,
        operation: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(operation, transaction)
    }
}

#[test]
fn post_freeze_import_keeps_full_proof_without_ack_or_application_and_replays_exactly() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let original_key: Vec<u8> = crate::fast_path::publication::fastpath_publication_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
    )
    .unwrap();
    let ack_key: Vec<u8> = crate::fast_path::publication::fastpath_availability_ack_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
    )
    .unwrap();
    let locks_before: Vec<Option<Vec<u8>>> = replica.lock_rows();
    let coin_before = replica.coin_head();
    close(&replica);
    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
    assert!(replica.row(&original_key).is_none());
    assert!(replica.row(&ack_key).is_none());
    assert_eq!(replica.lock_rows(), locks_before);
    assert_eq!(replica.coin_head(), coin_before);
    assert!(replica.request_receipt([REQUEST; 32]).is_none());
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap();
    assert_eq!(
        replica.row(&marker_key),
        Some(encode_availability_identity(&expected_identity).unwrap())
    );
    verify_drain_possession(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &expected_identity,
    )
    .unwrap();
    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
}

#[test]
fn import_requires_freeze_and_exact_frontier_identity_and_rechecks_saved_artifacts() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    assert!(import(&replica, &bundle, &expected_identity).is_err());
    close(&replica);
    let mut wrong: AvailabilityIdentity = expected_identity.clone();
    wrong.request_id[0] ^= 1;
    assert!(import(&replica, &bundle, &wrong).is_err());
    assert!(
        replica
            .row(
                &drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32])
                    .unwrap()
            )
            .is_none()
    );
    import(&replica, &bundle, &expected_identity).unwrap();
    let artifact: &ArtifactEntry = bundle.manifest.entries.first().unwrap();
    let key: Vec<u8> = drain_publication_artifact_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
        artifact,
    )
    .unwrap();
    replica.put_row(key, vec![0xAA]);
    assert!(
        verify_drain_possession(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &expected_identity,
        )
        .is_err()
    );
    assert!(import(&replica, &bundle, &expected_identity).is_err());
}

#[test]
fn import_does_not_extend_the_already_signed_local_frontier() {
    let replica: RetentionReplica = logical_replica();
    let (first, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let first_vote: AvailabilityVote = crate::fast_path::publication::retain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &encode_publication_bundle(&first).unwrap(),
        &replica.signer,
    )
    .unwrap();
    close(&replica);
    assert!(matches!(
        advance_frozen_frontier(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &replica.signer,
        )
        .unwrap(),
        FrozenFrontierStep::Advanced { .. }
    ));
    let final_vote: FrozenFrontierVote = match advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &replica.signer,
    )
    .unwrap()
    {
        FrozenFrontierStep::Finalized(vote) => *vote,
        FrozenFrontierStep::Advanced { .. } => panic!("expected final frontier"),
    };
    let before: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(before.0, final_vote);
    assert_eq!(before.1.entries, vec![first_vote.identity]);
    let (second, _certificate) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let second_identity: AvailabilityIdentity = identity(&second);
    import(&replica, &second, &second_identity).unwrap();
    let after: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        consensus::encode_frozen_frontier_vote(&after.0).unwrap(),
        consensus::encode_frozen_frontier_vote(&before.0).unwrap()
    );
    assert_eq!(
        consensus::encode_frozen_frontier_page(&after.1).unwrap(),
        consensus::encode_frozen_frontier_page(&before.1).unwrap()
    );
}

#[test]
fn import_before_local_frontier_finalization_still_cannot_enter_its_frozen_log() {
    let replica: RetentionReplica = logical_replica();
    let (own, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let own_vote: AvailabilityVote = crate::fast_path::publication::retain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &encode_publication_bundle(&own).unwrap(),
        &replica.signer,
    )
    .unwrap();
    close(&replica);
    let (foreign, _) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let foreign_identity: AvailabilityIdentity = identity(&foreign);
    import(&replica, &foreign, &foreign_identity).unwrap();
    assert!(matches!(
        advance_frozen_frontier(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &replica.signer,
        )
        .unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 1 }
    ));
    let finalized: FrozenFrontierVote = match advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &replica.signer,
    )
    .unwrap()
    {
        FrozenFrontierStep::Finalized(vote) => *vote,
        FrozenFrontierStep::Advanced { .. } => panic!("import entered own frozen log"),
    };
    let (vote, page): (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(vote, finalized);
    assert_eq!(page.entries, vec![own_vote.identity]);
    assert!(page.terminal);
}

#[test]
fn import_refuses_historical_profile_wrong_epoch_and_invalid_freeze_without_writes() {
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);

    let historical: RetentionReplica = physical_replica();
    close(&historical);
    assert!(matches!(
        import(&historical, &bundle, &expected_identity),
        Err(PublicationRetentionError::Node(
            NodeCoreError::PersistenceInvariant("historical profile has no drain publication")
        ))
    ));
    assert_no_import(&historical);

    let wrong_epoch: RetentionReplica = logical_replica();
    close(&wrong_epoch);
    let epoch_key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
    let mut epoch_record: local_instance_state::FastPathEpochRecord =
        local_instance_state::decode_fastpath_epoch_record(&wrong_epoch.row(&epoch_key).unwrap())
            .unwrap();
    epoch_record.current_epoch = Epoch::new(protocol().epoch().get() + 1);
    wrong_epoch.put_row(
        epoch_key,
        local_instance_state::encode_fastpath_epoch_record(&epoch_record).unwrap(),
    );
    assert!(matches!(
        import(&wrong_epoch, &bundle, &expected_identity),
        Err(PublicationRetentionError::Node(
            NodeCoreError::EpochMismatch { .. }
        ))
    ));
    assert_no_import(&wrong_epoch);

    for invalid in [
        AdmissionClosureRecord {
            closed_epoch: Epoch::new(protocol().epoch().get() + 1),
            request_id: [0x55; 32],
            closed_at_block_height: 3,
        },
        AdmissionClosureRecord {
            closed_epoch: protocol().epoch(),
            request_id: [0x55; 32],
            closed_at_block_height: 0,
        },
        AdmissionClosureRecord {
            closed_epoch: protocol().epoch(),
            request_id: [0; 32],
            closed_at_block_height: 3,
        },
    ] {
        let replica: RetentionReplica = logical_replica();
        replica.put_row(
            closure_key(),
            encode_admission_closure_record(&invalid).unwrap(),
        );
        assert!(matches!(
            import(&replica, &bundle, &expected_identity),
            Err(PublicationRetentionError::InconsistentRetainedRecord(
                "invalid committed Freeze"
            ))
        ));
        assert_no_import(&replica);
    }
    let tombstoned: RetentionReplica = logical_replica();
    close(&tombstoned);
    delete_row(&tombstoned, closure_key());
    assert!(matches!(
        import(&tombstoned, &bundle, &expected_identity),
        Err(PublicationRetentionError::InconsistentRetainedRecord(
            "ordered Freeze is not committed"
        ))
    ));
    assert_no_import(&tombstoned);
}

#[test]
fn same_request_conflicting_identity_and_missing_marker_refuse_without_repair() {
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let conflicting: RetentionReplica = logical_replica();
    close(&conflicting);
    import(&conflicting, &bundle, &expected_identity).unwrap();
    let publication_key: Vec<u8> =
        drain_publication_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap();
    let mut saved: FastPathPublicationRecord =
        decode_fastpath_publication_record(&conflicting.row(&publication_key).unwrap()).unwrap();
    let mut changed_identity: AvailabilityIdentity = expected_identity.clone();
    changed_identity.signed_intent_digest = bundle.certificate.execution_effects_hash;
    saved.identity = encode_availability_identity(&changed_identity).unwrap();
    conflicting.put_row(
        publication_key,
        encode_fastpath_publication_record(&saved).unwrap(),
    );
    assert!(matches!(
        import(&conflicting, &bundle, &expected_identity),
        Err(PublicationRetentionError::ConflictingRetainedIdentity)
    ));

    let replica: RetentionReplica = logical_replica();
    close(&replica);
    import(&replica, &bundle, &expected_identity).unwrap();
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap();
    delete_row(&replica, marker_key);
    // A genuinely tombstoned marker (as opposed to a pristine, never-written
    // one) must still fail closed rather than being silently rebuilt.
    assert!(matches!(
        import(&replica, &bundle, &expected_identity),
        Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain possession marker is tombstoned"
        ))
    ));
    assert!(
        verify_drain_possession(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &expected_identity,
        )
        .is_err()
    );
}

/// A same-epoch restore may carry the authenticated `drain-publication/`
/// and `drain-publication-artifact/` history while this host's own local
/// `drain-possession/` marker was never written (pristine, as opposed to
/// tombstoned). An exact retry must independently re-verify the complete
/// saved proof and every artifact against the caller's staged identity, then
/// safely rebuild the marker atomically with that re-verification.
#[test]
fn import_rebuilds_a_pristine_missing_marker_after_a_same_epoch_restore() {
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let replica: RetentionReplica = logical_replica();
    close(&replica);
    stage_proof_without_marker(&replica, &bundle, &expected_identity);
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap();
    assert!(replica.row(&marker_key).is_none());

    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
    assert_eq!(
        replica.row(&marker_key),
        Some(encode_availability_identity(&expected_identity).unwrap())
    );

    // A further exact retry now takes the ordinary already-retained path.
    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
}

#[test]
fn concurrent_artifact_rewrite_rejects_pristine_marker_rebuild() {
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let replica: RetentionReplica = logical_replica();
    close(&replica);
    stage_proof_without_marker(&replica, &bundle, &expected_identity);
    let first_artifact: &ArtifactEntry = bundle
        .manifest
        .entries
        .first()
        .expect("test bundle must carry an artifact");
    let artifact_key: Vec<u8> = drain_publication_artifact_key(
        protocol().chain_id(),
        protocol().epoch(),
        &bundle.request_id,
        first_artifact,
    )
    .unwrap();
    let marker_key: Vec<u8> = drain_possession_key(
        protocol().chain_id(),
        protocol().epoch(),
        &bundle.request_id,
    )
    .unwrap();
    let racing: RacingStore<'_> = RacingStore {
        inner: &replica.store,
        race_key: artifact_key.clone(),
        race_value: replica.row(&artifact_key).unwrap(),
        raced: Cell::new(false),
    };
    let result: DrainResult<AvailabilityIdentity> = retain_drain_publication(
        &racing,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &expected_identity,
        &encode_publication_bundle(&bundle).unwrap(),
    );
    assert!(racing.raced.get());
    assert!(matches!(
        result,
        Err(PublicationRetentionError::Node(
            NodeCoreError::DurableCommitRejected(_)
        ))
    ));
    assert!(replica.row(&marker_key).is_none());
}

#[test]
fn concurrent_profile_freeze_epoch_or_validator_row_changes_reject_the_whole_import() {
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let epoch_key: Vec<u8> =
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
    let validator_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&protocol()).unwrap();
    let profile_key: Vec<u8> =
        logical_generation::logical_profile_key(protocol().chain_id()).unwrap();
    for key in [profile_key, closure_key(), epoch_key, validator_key] {
        let replica: RetentionReplica = logical_replica();
        close(&replica);
        let original: Vec<u8> = replica.row(&key).unwrap();
        let racing: RacingStore<'_> = RacingStore {
            inner: &replica.store,
            race_key: key,
            race_value: original,
            raced: Cell::new(false),
        };
        let result: DrainResult<AvailabilityIdentity> = retain_drain_publication(
            &racing,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &expected_identity,
            &encode_publication_bundle(&bundle).unwrap(),
        );
        assert!(racing.raced.get(), "the competing write must actually land");
        assert!(matches!(
            result,
            Err(PublicationRetentionError::Node(
                NodeCoreError::DurableCommitRejected(_)
            ))
        ));
        assert_no_import(&replica);
    }
}
