//! Real signed evidence through a reader that cannot commit.

use super::*;
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{
    DurableObjectHead, DurableObjectVersion, DurableObjectVersionRecord, DurableRequestId,
    DurableRequestReceipt, NamespaceLifecycle, StructuredStateReader, VersionedStateReader,
};

struct EvidenceReader<'a> {
    store: &'a MemoryDurableStateStore,
}

impl VersionedStateReader for EvidenceReader<'_> {
    fn read_versioned_state(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.store.get_versioned_durable(operation, domain, key)
    }
}

impl StructuredStateReader for EvidenceReader<'_> {
    fn read_outgoing_barrier(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.store.get_outgoing_barrier(operation, domain)
    }

    fn read_namespace_lifecycle(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.store.get_namespace_lifecycle(operation, domain)
    }

    fn read_successor_serving(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, DurableReadError> {
        self.store.get_successor_serving(operation, domain)
    }

    fn read_object_head(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.store.get_object_head(operation, domain, object_id)
    }

    fn read_object_version(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.store
            .get_object_version(operation, domain, object_id, object_version)
    }

    fn read_request_receipt(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.store
            .get_request_receipt(operation, domain, request_id)
    }
}

#[test]
fn all_three_evidence_preparations_are_writer_free_and_direct_commits_remain_real() {
    let store: MemoryDurableStateStore = memory_store();
    let operation: DurableOperationContext = context();
    let resolver: HashSuiteResolver = resolver();
    let (signers, entries): (Vec<TestSigner>, Vec<FastPathValidatorEntry>) = four_validators();
    let fixture: GenesisFixture = build_genesis_fixture(entries.clone());
    assert!(matches!(
        install_genesis_with_history(
            &store,
            &operation,
            domain(),
            &resolver,
            &[],
            &fixture.manifest,
            1,
        )
        .unwrap(),
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    let reader: EvidenceReader<'_> = EvidenceReader { store: &store };
    let before: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain()).unwrap();
    let epoch: Epoch = Epoch::new(0);
    let fast: FastPathCertifier = fast_certifier(epoch, &entries);
    let same_a: FastVote = fast
        .cast_vote(digest(1), digest(2), digest(3), &signers[0])
        .unwrap();
    let same_b: FastVote = fast
        .cast_vote(digest(1), digest(4), digest(3), &signers[0])
        .unwrap();
    let same_a_bytes: Vec<u8> = encode_fast_vote(&same_a).unwrap();
    let same_b_bytes: Vec<u8> = encode_fast_vote(&same_b).unwrap();

    let shared: ObjectRef = object_ref(9, 1, 10);
    let preimage_a: LockedObjectSetPreimage = make_preimage(epoch, vec![shared.clone()]);
    let preimage_b: LockedObjectSetPreimage =
        make_preimage(epoch, vec![shared, object_ref(11, 1, 12)]);
    let conflict_a: FastVote = fast
        .cast_vote(
            digest(5),
            digest(6),
            compute_preimage_digest(&resolver, &preimage_a),
            &signers[0],
        )
        .unwrap();
    let conflict_b: FastVote = fast
        .cast_vote(
            digest(7),
            digest(8),
            compute_preimage_digest(&resolver, &preimage_b),
            &signers[0],
        )
        .unwrap();
    let conflict_a_bytes: Vec<u8> = encode_fast_vote(&conflict_a).unwrap();
    let conflict_b_bytes: Vec<u8> = encode_fast_vote(&conflict_b).unwrap();
    let preimage_a_bytes: Vec<u8> = encode_locked_object_set_preimage(&preimage_a).unwrap();
    let preimage_b_bytes: Vec<u8> = encode_locked_object_set_preimage(&preimage_b).unwrap();

    let transition: EpochTransitionCertifier = transition_certifier(epoch, &entries);
    let transition_a: EpochTransitionVote = transition
        .cast_vote(
            Epoch::new(1),
            digest(13),
            digest(14),
            digest(15),
            &signers[0],
        )
        .unwrap();
    let transition_b: EpochTransitionVote = transition
        .cast_vote(
            Epoch::new(1),
            digest(13),
            digest(14),
            digest(16),
            &signers[0],
        )
        .unwrap();
    let transition_a_bytes: Vec<u8> = encode_epoch_transition_vote(&transition_a).unwrap();
    let transition_b_bytes: Vec<u8> = encode_epoch_transition_vote(&transition_b).unwrap();

    let proposals: Vec<EquivocationEvidencePreparation> = vec![
        prepare_fast_vote_equivocation_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &same_a_bytes,
            &same_b_bytes,
            30,
            None,
            None,
        )
        .unwrap(),
        prepare_fast_vote_object_conflict_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &conflict_a_bytes,
            &conflict_b_bytes,
            &preimage_a_bytes,
            &preimage_b_bytes,
            30,
            None,
            None,
        )
        .unwrap(),
        prepare_epoch_transition_equivocation_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &transition_a_bytes,
            &transition_b_bytes,
            30,
            None,
            None,
        )
        .unwrap(),
    ];
    let mut proposed_records: Vec<FastPathEquivocationEvidenceRecord> = Vec::new();
    for proposal in proposals {
        let prepared: PreparedEquivocationEvidence = match proposal {
            EquivocationEvidencePreparation::New(prepared) => prepared,
            EquivocationEvidencePreparation::AlreadyRecorded(_) => panic!("fresh evidence"),
        };
        let (transaction, record): (AtomicStateTransaction, FastPathEquivocationEvidenceRecord) =
            prepared.into_parts();
        assert_eq!(transaction.domain(), domain());
        assert_eq!(transaction.mutations().len(), 1);
        assert_eq!(record.recorded_at_checkpoint, 30);
        let mutation: &StateMutationEntry = &transaction.mutations()[0];
        assert_eq!(
            mutation.mutation(),
            &StateMutation::Put(encode_fastpath_equivocation_evidence_record(&record).unwrap()),
        );
        let absent: VersionedStateValue = reader
            .read_versioned_state(&operation, domain(), mutation.key())
            .unwrap();
        assert_eq!(absent.revision(), StateRevision::INITIAL);
        assert!(absent.value().is_none());
        proposed_records.push(record);
    }
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain()).unwrap(),
        before,
    );

    // The same proposals are completed by the unchanged public direct APIs,
    // against actual storage, never an intercepted successful commit.
    let outcomes: Vec<EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord>> = vec![
        submit_fast_vote_equivocation_evidence(
            &store,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &same_a_bytes,
            &same_b_bytes,
            30,
        )
        .unwrap(),
        submit_fast_vote_object_conflict_evidence(
            &store,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &conflict_a_bytes,
            &conflict_b_bytes,
            &preimage_a_bytes,
            &preimage_b_bytes,
            30,
        )
        .unwrap(),
        submit_epoch_transition_equivocation_evidence(
            &store,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &transition_a_bytes,
            &transition_b_bytes,
            30,
        )
        .unwrap(),
    ];
    for (outcome, proposed) in outcomes.into_iter().zip(proposed_records) {
        assert_eq!(outcome, EquivocationEvidenceOutcome::Recorded(proposed));
    }
    let committed: PortableSnapshotToken =
        store.begin_portable_snapshot(&operation, domain()).unwrap();
    assert_eq!(
        committed.mutation_sequence(),
        before.mutation_sequence() + 3
    );

    let retained: Vec<EquivocationEvidencePreparation> = vec![
        prepare_fast_vote_equivocation_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &same_a_bytes,
            &same_b_bytes,
            99,
            None,
            None,
        )
        .unwrap(),
        prepare_fast_vote_object_conflict_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &conflict_a_bytes,
            &conflict_b_bytes,
            &preimage_a_bytes,
            &preimage_b_bytes,
            99,
            None,
            None,
        )
        .unwrap(),
        prepare_epoch_transition_equivocation_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &transition_a_bytes,
            &transition_b_bytes,
            99,
            None,
            None,
        )
        .unwrap(),
    ];
    for preparation in retained {
        assert!(matches!(
            preparation,
            EquivocationEvidencePreparation::AlreadyRecorded(record)
                if record.recorded_at_checkpoint == 30
        ));
    }
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain()).unwrap(),
        committed,
    );

    // New malformed proof and stale physical authority still fail without
    // effects; preparation invents neither a commit nor ambiguity result.
    let mut invalid_b: FastVote = fast
        .cast_vote(digest(21), digest(24), digest(23), &signers[0])
        .unwrap();
    invalid_b.signature[0] ^= 1;
    let invalid_a: FastVote = fast
        .cast_vote(digest(21), digest(22), digest(23), &signers[0])
        .unwrap();
    assert!(matches!(
        prepare_fast_vote_equivocation_evidence_ordered(
            &reader,
            &operation,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &encode_fast_vote(&invalid_a).unwrap(),
            &encode_fast_vote(&invalid_b).unwrap(),
            40,
            None,
            None,
        ),
        Err(EquivocationEvidenceError::Consensus(
            ConsensusError::InvalidSignature(_)
        ))
    ));
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain()).unwrap(),
        committed,
    );
    let stale: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        operation.deadline(),
        operation.correlation_id(),
    );
    assert!(matches!(
        prepare_fast_vote_equivocation_evidence_ordered(
            &reader,
            &stale,
            domain(),
            &resolver,
            &chain(),
            protocol_version(),
            &same_a_bytes,
            &same_b_bytes,
            99,
            None,
            None,
        ),
        Err(EquivocationEvidenceError::Node(NodeCoreError::DurableRead(
            DurableReadError::WriterFenced { .. }
        )))
    ));
    assert_eq!(
        store.begin_portable_snapshot(&operation, domain()).unwrap(),
        committed,
    );
}
