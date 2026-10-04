//! Genuine Original publication/index proof, poisoning and retry regressions.
use super::*;
use crate::fast_path::tests::AmbiguousCommitStore;
use runtime::outbox_guard::StructuredOutboxInventory;
use runtime::portable::{
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordDescriptor,
    DurableRecordPage,
};

fn retained() -> (RetentionReplica, consensus::AvailabilityVote) {
    let replica: RetentionReplica = logical_replica_bound();
    let (bundle, _): (
        consensus::bundle::PublicationBundle,
        consensus::FastCertificate,
    ) = crate::fast_path::tests::transfer_bundle_bytes(
        0x31,
        crate::paid_execution::tests::FIRST_PAID_NONCE,
    );
    let acknowledgement: consensus::AvailabilityVote =
        crate::fast_path::publication::retain_publication(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &consensus::bundle::encode_publication_bundle(&bundle).unwrap(),
            &replica.signer,
        )
        .unwrap();
    stage_closure(&replica);
    (replica, acknowledgement)
}

fn advance<S: DurablePortableRepository + StructuredOutboxExclusionGuard>(
    store: &S,
    signer: &CountingSigner<'_>,
) -> Result<FrozenFrontierStep, FrozenFrontierError> {
    advance_frozen_frontier(
        store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        signer,
    )
}

fn page(
    replica: &RetentionReplica,
    after: Option<[u8; 32]>,
) -> Result<(FrozenFrontierVote, FrozenFrontierPage), FrozenFrontierError> {
    read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        after,
        NonZeroUsize::MIN,
    )
}

fn replace(replica: &RetentionReplica, key: Vec<u8>, mutation: StateMutation) {
    let observed: VersionedStateValue = replica
        .store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        replica.store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn poisoned_deleted_or_foreign_index_and_changed_current_carrier_refuse_without_reader_writes() {
    let (replica, acknowledgement): (RetentionReplica, consensus::AvailabilityVote) = retained();
    let signer: CountingSigner<'_> = CountingSigner {
        inner: &replica.signer,
        calls: Cell::new(0),
    };
    assert_eq!(
        advance(&replica.store, &signer).unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 1 }
    );
    assert!(matches!(
        advance(&replica.store, &signer).unwrap(),
        FrozenFrontierStep::Finalized(_)
    ));
    assert_eq!(signer.calls.get(), 1);
    let indexed_key: Vec<u8> = entry_key(
        protocol().chain_id(),
        protocol().epoch(),
        &acknowledgement.identity.request_id,
    )
    .unwrap();
    let indexed_bytes: Vec<u8> = replica.row(&indexed_key).unwrap();
    let original: FrontierEntry = decode_entry(&indexed_bytes).unwrap();
    let mut ordinal: FrontierEntry = original.clone();
    ordinal.ordinal = 2;
    let mut foreign: FrontierEntry = original.clone();
    foreign.publication.epoch = Epoch::new(1);
    let mut request: FrontierEntry = original.clone();
    request.publication.request_id = [0x32; 32];
    let mut freeze: FrontierEntry = original.clone();
    freeze.closure_height = freeze.closure_height.checked_add(1).unwrap();
    let mut future: CanonicalStruct = CanonicalStruct::new(FRONTIER_ENTRY_TYPE, ENCODING_VERSION);
    future
        .field_bytes(1, original.closure_request_id.to_vec())
        .unwrap();
    future.field_u64(2, original.closure_height).unwrap();
    future.field_u64(3, original.ordinal).unwrap();
    future
        .field_bytes(
            4,
            encode_availability_identity(&original.publication).unwrap(),
        )
        .unwrap();
    future.field_bytes(99, vec![1]).unwrap();
    for mutation in [
        StateMutation::Delete,
        StateMutation::Put(encode_entry(&ordinal).unwrap()),
        StateMutation::Put(encode_entry(&foreign).unwrap()),
        StateMutation::Put(encode_entry(&request).unwrap()),
        StateMutation::Put(encode_entry(&freeze).unwrap()),
        StateMutation::Put(future.finish().unwrap()),
    ] {
        replace(&replica, indexed_key.clone(), mutation);
        let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
        assert!(page(&replica, None).is_err());
        assert!(page(&replica, Some(acknowledgement.identity.request_id)).is_err());
        assert_eq!(full_snapshot(&replica.store), before);
        assert_eq!(signer.calls.get(), 1);
        replace(
            &replica,
            indexed_key.clone(),
            StateMutation::Put(indexed_bytes.clone()),
        );
        assert!(page(&replica, None).is_ok());
    }
    // Current data behind the persisted physical tail is still independently
    // re-verified by the page reader, not trusted through its index identity.
    let publication_key: Vec<u8> =
        fastpath_publication_key(protocol().chain_id(), &acknowledgement.identity.request_id)
            .unwrap();
    let publication_bytes: Vec<u8> = replica.row(&publication_key).unwrap();
    replace(
        &replica,
        publication_key.clone(),
        StateMutation::Put(b"changed current carrier behind tail".to_vec()),
    );
    let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
    assert!(page(&replica, None).is_err());
    assert_eq!(full_snapshot(&replica.store), before);
    assert_eq!(signer.calls.get(), 1);
    replace(
        &replica,
        publication_key,
        StateMutation::Put(publication_bytes),
    );
    // A locally planted extra slot cannot create an accepted truncated or
    // extended stream, including the exactly-full first page's lookahead.
    let extra_key: Vec<u8> =
        entry_key(protocol().chain_id(), protocol().epoch(), &[0x32; 32]).unwrap();
    let mut extra: FrontierEntry = original;
    extra.ordinal = 2;
    extra.publication.request_id = [0x32; 32];
    replace(
        &replica,
        extra_key,
        StateMutation::Put(encode_entry(&extra).unwrap()),
    );
    let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
    assert!(matches!(
        page(&replica, None),
        Err(FrozenFrontierError::Invalid(
            "frontier index exceeds signed count"
        ))
    ));
    assert!(page(&replica, Some(acknowledgement.identity.request_id)).is_err());
    assert_eq!(full_snapshot(&replica.store), before);
    assert_eq!(signer.calls.get(), 1);
}

#[test]
fn genuine_pre_index_final_refuses_without_reinterpreting_old_progress_or_signing() {
    let (replica, _): (RetentionReplica, consensus::AvailabilityVote) = retained();
    let signer: CountingSigner<'_> = CountingSigner {
        inner: &replica.signer,
        calls: Cell::new(0),
    };
    assert!(matches!(
        advance(&replica.store, &signer).unwrap(),
        FrozenFrontierStep::Advanced { .. }
    ));
    assert!(matches!(
        advance(&replica.store, &signer).unwrap(),
        FrozenFrontierStep::Finalized(_)
    ));
    let final_key: Vec<u8> = key(
        protocol().chain_id(),
        protocol().epoch(),
        FRONTIER_FINAL_PREFIX,
    )
    .unwrap();
    let mut legacy: FinalFrontier = decode_final(&replica.row(&final_key).unwrap()).unwrap();
    legacy.indexed = false;
    replace(
        &replica,
        final_key,
        StateMutation::Put(encode_final(&legacy).unwrap()),
    );
    let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
    assert!(matches!(
        advance(&replica.store, &signer),
        Err(FrozenFrontierError::NotReady(
            "pre-index final frontier is not complete indexed material"
        ))
    ));
    assert!(matches!(
        page(&replica, None),
        Err(FrozenFrontierError::NotReady(
            "pre-index final frontier has no complete current index"
        ))
    ));
    assert_eq!(full_snapshot(&replica.store), before);
    assert_eq!(signer.calls.get(), 1);
}

#[test]
fn stale_deciding_publication_cas_cannot_land_an_index_or_cursor() {
    let (replica, acknowledgement): (RetentionReplica, consensus::AvailabilityVote) = retained();
    let publication_key: Vec<u8> =
        fastpath_publication_key(protocol().chain_id(), &acknowledgement.identity.request_id)
            .unwrap();
    let indexed_key: Vec<u8> = entry_key(
        protocol().chain_id(),
        protocol().epoch(),
        &acknowledgement.identity.request_id,
    )
    .unwrap();
    let cursor_key: Vec<u8> = key(
        protocol().chain_id(),
        protocol().epoch(),
        FRONTIER_PROGRESS_PREFIX,
    )
    .unwrap();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    for row in [&publication_key, &indexed_key, &cursor_key] {
        let observed: VersionedStateValue = replica
            .store
            .get_versioned_durable(&context(), domain(), row)
            .unwrap();
        put_read(&mut reads, row.clone(), observed.revision()).unwrap();
    }
    let publication_bytes: Vec<u8> = replica.row(&publication_key).unwrap();
    // A real concurrent backend revision wins after the deciding read. The
    // publication's authentic bytes are unchanged, so a fresh retry is legal.
    replace(
        &replica,
        publication_key,
        StateMutation::Put(publication_bytes),
    );
    let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
        &resolver(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        domain(),
        [0x55; 32],
        3,
    )
    .unwrap();
    accumulator
        .push(&resolver(), &acknowledgement.identity)
        .unwrap();
    let cursor: FrontierCursor = FrontierCursor {
        identity: accumulator.into_identity(),
        last_request_id: Some(acknowledgement.identity.request_id),
        physical_last_request_id: acknowledgement.identity.request_id,
        indexed: true,
    };
    let entry: FrontierEntry = FrontierEntry {
        closure_request_id: [0x55; 32],
        closure_height: 3,
        ordinal: 1,
        publication: acknowledgement.identity,
    };
    let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
    assert!(matches!(
        commit_rows(
            crate::serving_authority::ServingGate::Original,
            &replica.store,
            &context(),
            domain(),
            reads,
            vec![
                StateMutationEntry::new(
                    indexed_key.clone(),
                    StateMutation::Put(encode_entry(&entry).unwrap())
                )
                .unwrap(),
                StateMutationEntry::new(
                    cursor_key.clone(),
                    StateMutation::Put(encode_cursor(&cursor).unwrap())
                )
                .unwrap()
            ]
        ),
        Err(FrozenFrontierError::Node(
            NodeCoreError::DurableCommitRejected(runtime::DurableCommitRejection::Conflict { .. })
        ))
    ));
    assert!(replica.row(&indexed_key).is_none());
    assert!(replica.row(&cursor_key).is_none());
    assert_eq!(full_snapshot(&replica.store), before);
    let signer: CountingSigner<'_> = CountingSigner {
        inner: &replica.signer,
        calls: Cell::new(0),
    };
    assert_eq!(
        advance(&replica.store, &signer).unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 1 }
    );
    assert_eq!(signer.calls.get(), 0);
    assert!(replica.row(&indexed_key).is_some() && replica.row(&cursor_key).is_some());
}

// The existing fault owner delegates every real storage read and optionally
// lands its real atomic state transaction before losing the reply. These
// adapters add only bounded portable/outbox reads for this genuine owner.
impl DurablePortableRepository for AmbiguousCommitStore<'_> {
    fn scan_portable_keys(
        &self,
        operation: &DurableOperationContext,
        scope: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner.scan_portable_keys(operation, scope, scan)
    }
    fn read_portable_descriptor(
        &self,
        operation: &DurableOperationContext,
        scope: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.inner.read_portable_descriptor(operation, scope, key)
    }
    fn read_portable_chunk(
        &self,
        operation: &DurableOperationContext,
        scope: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.inner.read_portable_chunk(operation, scope, request)
    }
}

impl StructuredOutboxExclusionGuard for AmbiguousCommitStore<'_> {
    fn inspect_outbox_exclusion(
        &self,
        operation: &DurableOperationContext,
        scope: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        self.inner.inspect_outbox_exclusion(operation, scope)
    }
}

#[test]
fn ambiguous_index_cursor_commit_retries_to_the_exact_clean_vote_and_full_state() {
    let (clean, _): (RetentionReplica, consensus::AvailabilityVote) = retained();
    let clean_signer: CountingSigner<'_> = CountingSigner {
        inner: &clean.signer,
        calls: Cell::new(0),
    };
    assert!(matches!(
        advance(&clean.store, &clean_signer).unwrap(),
        FrozenFrontierStep::Advanced { entry_count: 1 }
    ));
    let expected: FrozenFrontierStep = advance(&clean.store, &clean_signer).unwrap();
    let clean_state: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&clean.store);
    for land_before_outcome in [false, true] {
        let (replica, acknowledgement): (RetentionReplica, consensus::AvailabilityVote) =
            retained();
        let signer: CountingSigner<'_> = CountingSigner {
            inner: &replica.signer,
            calls: Cell::new(0),
        };
        let fault: AmbiguousCommitStore<'_> = AmbiguousCommitStore {
            inner: &replica.store,
            state: Cell::new(true),
            invocation: Cell::new(false),
            land_before_outcome,
        };
        let before: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
        assert!(matches!(
            advance(&fault, &signer),
            Err(FrozenFrontierError::Node(
                NodeCoreError::DurableCommitIndeterminate(_)
            ))
        ));
        assert_eq!(signer.calls.get(), 0);
        let indexed_key: Vec<u8> = entry_key(
            protocol().chain_id(),
            protocol().epoch(),
            &acknowledgement.identity.request_id,
        )
        .unwrap();
        let cursor_key: Vec<u8> = key(
            protocol().chain_id(),
            protocol().epoch(),
            FRONTIER_PROGRESS_PREFIX,
        )
        .unwrap();
        assert_eq!(replica.row(&indexed_key).is_some(), land_before_outcome);
        assert_eq!(
            replica.row(&cursor_key).is_some(),
            land_before_outcome,
            "cursor and index cannot partially land"
        );
        if !land_before_outcome {
            assert_eq!(full_snapshot(&replica.store), before);
            assert_eq!(
                advance(&fault, &signer).unwrap(),
                FrozenFrontierStep::Advanced { entry_count: 1 }
            );
            assert_eq!(signer.calls.get(), 0);
        }
        assert_eq!(advance(&fault, &signer).unwrap(), expected);
        assert_eq!(signer.calls.get(), 1);
        assert_eq!(full_snapshot(&replica.store), clean_state);
        let retained: Vec<(DurableRecordDescriptor, Vec<u8>)> = full_snapshot(&replica.store);
        assert_eq!(advance(&fault, &signer).unwrap(), expected);
        assert_eq!(signer.calls.get(), 1);
        assert_eq!(full_snapshot(&replica.store), retained);
    }
}
