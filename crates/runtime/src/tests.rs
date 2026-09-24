use super::*;
use hashing::{BuiltinHashFunction, HashFunction};
use protocol_types::{HashAlgorithmId, HashPurpose};

fn key(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

fn domain(byte: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([byte; 32]).unwrap()
}

fn read(text: &str, revision: StateRevision) -> StateReadAssertion {
    StateReadAssertion::new(key(text), revision).unwrap()
}

fn mutation(text: &str, mutation: StateMutation) -> StateMutationEntry {
    StateMutationEntry::new(key(text), mutation).unwrap()
}

fn transaction(
    domain: AtomicityDomainId,
    reads: Vec<StateReadAssertion>,
    mutations: Vec<StateMutationEntry>,
) -> Result<AtomicStateTransaction, RuntimeError> {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(mutations)?,
    )
}

fn durable_context(fence: u64, deadline: u64, correlation: u8) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(deadline).unwrap(),
        StorageCorrelationId::new([correlation; 16]).unwrap(),
    )
}

fn durable_invocation(
    domain: AtomicityDomainId,
    request_byte: u8,
    expected_revision: StateRevision,
    mutation_value: Option<u8>,
    include_outbox: bool,
) -> DurableInvocationTransaction {
    let request_id = DurableRequestId::new([request_byte; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 1; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![request_byte]).unwrap();
    let mutations = mutation_value
        .map(|value| vec![mutation("state", StateMutation::Put(vec![value]))])
        .unwrap_or_default();
    let state = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![read("state", expected_revision)]).unwrap(),
        mutations,
    )
    .unwrap();
    let outbox = include_outbox.then(|| {
        let message = DurableOutboxMessage::new(
            Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 2; 32]),
            vec![request_byte + 3],
        )
        .unwrap();
        DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap()
    });
    DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt,
        outbox,
    )
    .unwrap()
}

fn test_object_version(version: u64, byte: u8) -> DurableObjectVersionRecord {
    let object: Object = Object {
        id: ObjectId::new([byte; 32]),
        version,
        owner: Owner::Address(objects::Address::new([byte.wrapping_add(1); 32])),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(2); 32]),
        schema_version: u32::from(byte),
        data: vec![byte.wrapping_add(3)],
    };
    let canonical: Vec<u8> = encode_object(&object).unwrap();
    let chain_id: ChainId = ChainId::new("sunrise-runtime-tests").unwrap();
    let protocol_version: ProtocolVersion = ProtocolVersion::new(1);
    let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(HashPurpose::Object, protocol_version, &chain_id, &canonical)
        .unwrap();
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(chain_id, protocol_version);
    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, u64::from(byte))
        .unwrap()
}

fn test_create_mutation(version: u64, byte: u8) -> DurableObjectMutation {
    DurableObjectMutation::Create {
        version: test_object_version(version, byte),
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
            objects::Address::new([byte.wrapping_add(1); 32]),
        ))
        .unwrap(),
        routing_projection: DurableObjectRoutingProjection::new(Some(vec![byte])).unwrap(),
    }
}

fn test_object_invocation(
    invocation_domain: AtomicityDomainId,
    request_byte: u8,
    objects: DurableObjectChanges,
) -> DurableInvocationTransaction {
    let request_id: DurableRequestId = DurableRequestId::new([request_byte; 32]).unwrap();
    let digest: Digest32 = Digest32::new(
        HashAlgorithmId::Sha2_256,
        [request_byte.wrapping_add(1); 32],
    );
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, digest, vec![request_byte]).unwrap();
    DurableInvocationTransaction::new(invocation_domain, None, objects, receipt, None).unwrap()
}

fn durable_outbox_invocation(
    domain: AtomicityDomainId,
    request_byte: u8,
    payloads: &[u8],
) -> DurableInvocationTransaction {
    let request_id = DurableRequestId::new([request_byte; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xD1; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![request_byte]).unwrap();
    let messages = payloads
        .iter()
        .map(|payload| {
            DurableOutboxMessage::new(
                Digest32::new(HashAlgorithmId::Sha2_256, [*payload; 32]),
                vec![*payload],
            )
            .unwrap()
        })
        .collect();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, messages).unwrap();
    let state = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
        Vec::new(),
    )
    .unwrap();
    DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap()
}

#[test]
fn compare_and_swap_writes_when_expected_matches() {
    let store = MemoryStateStore::default();
    store.put(key("k"), vec![1]).unwrap();

    let result = store
        .compare_and_swap(key("k"), Some(vec![1]), vec![2])
        .unwrap();

    assert!(result.swapped);
    assert_eq!(result.current, Some(vec![1]));
    assert_eq!(store.get(b"k").unwrap(), Some(vec![2]));
}

#[test]
fn compare_and_swap_rejects_when_expected_mismatch() {
    let store = MemoryStateStore::default();
    store.put(key("k"), vec![9]).unwrap();

    let result = store
        .compare_and_swap(key("k"), Some(vec![1]), vec![2])
        .unwrap();

    assert!(!result.swapped);
    assert_eq!(result.current, Some(vec![9]));
    assert_eq!(store.get(b"k").unwrap(), Some(vec![9]));
}

#[test]
fn domain_transaction_envelope_is_bounded_ordered_and_complete() {
    assert_eq!(
        AtomicityDomainId::new([0; 32]),
        Err(protocol_types::TypeError::ZeroAtomicityDomainId)
    );
    assert_eq!(
        StateMutationEntry::new(key("a"), StateMutation::Assert),
        Err(RuntimeError::StateAssertionAsMutation)
    );
    assert_eq!(
        AtomicStateReadSet::new(Vec::new()),
        Err(RuntimeError::EmptyReadSet)
    );
    let duplicate_read = read("same", StateRevision::INITIAL);
    assert_eq!(
        AtomicStateReadSet::new(vec![duplicate_read.clone(), duplicate_read]),
        Err(RuntimeError::DuplicateStateReadKey)
    );
    assert_eq!(
        AtomicStateMutationSet::new(Vec::new()),
        Err(RuntimeError::EmptyWriteSet)
    );
    let duplicate_mutation = mutation("same", StateMutation::Delete);
    assert_eq!(
        AtomicStateMutationSet::new(vec![duplicate_mutation.clone(), duplicate_mutation,]),
        Err(RuntimeError::DuplicateStateWriteKey)
    );
    assert_eq!(
        transaction(
            domain(1),
            vec![read("a", StateRevision::INITIAL)],
            vec![mutation("b", StateMutation::Delete)],
        ),
        Err(RuntimeError::StateMutationWithoutRead)
    );

    let transaction = transaction(
        domain(1),
        vec![
            read("z", StateRevision::INITIAL),
            read("a", StateRevision::INITIAL),
        ],
        vec![
            mutation("z", StateMutation::Put(vec![2])),
            mutation("a", StateMutation::Put(vec![1])),
        ],
    )
    .unwrap();
    assert_eq!(transaction.reads()[0].key(), b"a");
    assert_eq!(transaction.reads()[1].key(), b"z");
    assert_eq!(transaction.mutations()[0].key(), b"a");
    assert_eq!(transaction.mutations()[1].key(), b"z");
    assert_eq!(transaction.represented_bytes(), 96);
}

#[test]
fn durable_operation_context_requires_explicit_non_zero_authority_and_identity() {
    assert_eq!(WriterFenceGeneration::new(0), None);
    assert_eq!(StorageDeadline::new(0), None);
    assert_eq!(StorageCorrelationId::new([0; 16]), None);

    let fence = WriterFenceGeneration::new(7).unwrap();
    let deadline = StorageDeadline::new(1_000).unwrap();
    let correlation_id = StorageCorrelationId::new([9; 16]).unwrap();
    let context = DurableOperationContext::new(fence, deadline, correlation_id);

    assert_eq!(context.writer_fence().get(), 7);
    assert_eq!(context.writer_fence().checked_next().unwrap().get(), 8);
    assert_eq!(context.deadline().unix_millis(), 1_000);
    assert!(!context.deadline().is_expired_at(999));
    assert!(context.deadline().is_expired_at(1_000));
    assert_eq!(context.correlation_id().as_bytes(), &[9; 16]);
    assert_eq!(
        WriterFenceGeneration::new(u64::MAX).unwrap().checked_next(),
        None
    );
}

#[test]
fn durable_commit_outcome_does_not_blur_conflict_and_ambiguity() {
    assert_eq!(
        DurableCommitOutcome::from(AtomicStateWriteResult::Conflict {
            key: key("dependency"),
            current_revision: StateRevision::new(4),
        }),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: key("dependency"),
            current_revision: StateRevision::new(4),
        })
    );
    assert_ne!(
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit),
        DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
    );
    assert_ne!(
        DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: key("dependency"),
            current_revision: StateRevision::new(4),
        })
    );
}

#[test]
fn indexed_outbox_claim_contract_bounds_identity_payload_and_lease() {
    assert_eq!(
        OutboxRequestId::new([0; 32]),
        Err(IndexedOutboxContractError::ZeroRequestId)
    );
    assert_eq!(
        DurableOutboxLeaseId::new([0; 32]),
        Err(IndexedOutboxContractError::ZeroLeaseId)
    );
    let request_id = OutboxRequestId::new([3; 32]).unwrap();
    let lease_id = DurableOutboxLeaseId::new([4; 32]).unwrap();
    assert_eq!(
        DueOutboxClaimRequest::new(domain(1), 1_000, lease_id, 1_000),
        Err(IndexedOutboxContractError::InvalidLeaseWindow)
    );
    assert_eq!(
        DueOutboxClaimRequest::new(
            domain(1),
            1_000,
            lease_id,
            1_001 + MAX_DURABLE_OUTBOX_LEASE_MILLIS,
        ),
        Err(IndexedOutboxContractError::InvalidLeaseWindow)
    );
    let request = DueOutboxClaimRequest::new(domain(1), 1_000, lease_id, 2_000).unwrap();
    assert_eq!(request.domain(), domain(1));
    assert_eq!(request.now_unix_millis(), 1_000);
    assert_eq!(request.lease_id(), lease_id);
    assert_eq!(request.lease_expires_at_unix_millis(), 2_000);
    let exact =
        RequestOutboxClaimRequest::new(domain(1), request_id, 1_000, lease_id, 2_000).unwrap();
    assert_eq!(exact.domain(), domain(1));
    assert_eq!(exact.request_id(), request_id);
    assert_eq!(exact.now_unix_millis(), 1_000);
    assert_eq!(exact.lease_id(), lease_id);
    assert_eq!(exact.lease_expires_at_unix_millis(), 2_000);

    assert_eq!(
        DurableOutboxClaim::from_parts(request_id, 2, lease_id, 2_000, Vec::new()),
        Err(IndexedOutboxContractError::EmptyPayload)
    );
    let claim = DurableOutboxClaim::from_parts(request_id, 2, lease_id, 2_000, vec![8, 9]).unwrap();
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 2);
    assert_eq!(claim.lease_id(), lease_id);
    assert_eq!(claim.lease_expires_at_unix_millis(), 2_000);
    assert_eq!(claim.canonical_payload(), &[8, 9]);

    let acknowledgement = DurableOutboxAcknowledgement::new(domain(1), request_id, 2, lease_id);
    assert_eq!(acknowledgement.domain(), domain(1));
    assert_eq!(acknowledgement.request_id(), request_id);
    assert_eq!(acknowledgement.message_index(), 2);
    assert_eq!(acknowledgement.lease_id(), lease_id);
}

#[test]
fn indexed_outbox_outcomes_keep_claim_and_ack_ambiguity_explicit() {
    assert_ne!(
        DurableOutboxClaimOutcome::Rejected(
            DurableOutboxClaimRejection::DeadlineExceededBeforeCommit
        ),
        DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
    );
    assert_ne!(
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::LeaseMismatch
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    assert_ne!(
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit
        ),
        DurableOutboxAcknowledgementOutcome::Indeterminate(
            IndeterminateCommitReason::DeadlineExceeded
        )
    );
}

#[test]
fn structured_durable_state_section_supports_read_only_assertions() {
    let state = DurableStateTransaction::new(
        domain(1),
        AtomicStateReadSet::new(vec![read("dependency", StateRevision::new(7))]).unwrap(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(state.domain(), domain(1));
    assert_eq!(state.reads().len(), 1);
    assert!(state.mutations().is_empty());
    assert!(state.represented_bytes() > 0);
    assert_eq!(
        DurableStateTransaction::new(
            domain(1),
            AtomicStateReadSet::new(vec![read("dependency", StateRevision::new(7))]).unwrap(),
            vec![mutation("other", StateMutation::Delete)],
        ),
        Err(RuntimeError::StateMutationWithoutRead)
    );
}

#[test]
fn durable_object_section_is_typed_canonical_contained_and_bounded() {
    assert_eq!(DurableObjectChanges::empty().represented_bytes(), 0);
    assert_eq!(DurableObjectVersion::new(0), None);
    assert_eq!(ObjectHeadRevision::new(0), None);
    assert_eq!(DurableObjectVersion::MAX.checked_next(), None);
    assert_eq!(
        ObjectHeadRevision::new(u64::MAX).unwrap().checked_next(),
        None
    );
    assert_eq!(
        DurableObjectVersionRecord::from_inline_canonical_bytes(
            vec![0; MAX_DURABLE_INLINE_OBJECT_BYTES + 1],
            Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
            DurableObjectProvenance::new(
                ChainId::new("sunrise-runtime-tests").unwrap(),
                ProtocolVersion::new(1),
            ),
            1,
        ),
        Err(DurableInvocationError::ObjectBodyTooLarge {
            length: MAX_DURABLE_INLINE_OBJECT_BYTES + 1,
            maximum: MAX_DURABLE_INLINE_OBJECT_BYTES,
        })
    );
    assert_eq!(
        DurableObjectOwnerProjection::from_canonical_bytes(Some(vec![
            0;
            MAX_DURABLE_OBJECT_PROJECTION_BYTES
                + 1
        ])),
        Err(DurableInvocationError::ObjectOwnerProjectionTooLarge {
            length: MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1,
            maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
        })
    );
    assert_eq!(
        DurableObjectRoutingProjection::new(Some(vec![0; MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1])),
        Err(DurableInvocationError::ObjectRoutingProjectionTooLarge {
            length: MAX_DURABLE_OBJECT_PROJECTION_BYTES + 1,
            maximum: MAX_DURABLE_OBJECT_PROJECTION_BYTES,
        })
    );

    let first_id: ObjectId = ObjectId::new([0x11; 32]);
    let second_id: ObjectId = ObjectId::new([0x22; 32]);
    let blob_record: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        first_id,
        DurableObjectVersion::FIRST,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x31; 32]),
        7,
        DurableObjectProvenance::new(
            ChainId::new("sunrise-runtime-tests").unwrap(),
            ProtocolVersion::new(1),
        ),
        8,
        Digest32::new(HashAlgorithmId::Sha3_256, [0x32; 32]),
    );
    assert_eq!(
        blob_record.canonical_record_type_id(),
        u32::from(OBJECT_CANONICAL_TYPE_ID)
    );
    assert_eq!(blob_record.inline_type_hash(), None);
    assert_eq!(
        blob_record.payload().blob_digest(),
        Some(Digest32::new(HashAlgorithmId::Sha3_256, [0x32; 32]))
    );
    assert!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                first_id,
                DurableObjectMutation::Create {
                    version: blob_record,
                    owner_projection: DurableObjectOwnerProjection::default(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .is_ok()
    );
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![
            DurableObjectHeadRead::new(second_id, DurableObjectHead::Absent),
            DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
        ],
        vec![
            DurableObjectMutationEntry::new(second_id, test_create_mutation(1, 0x22)),
            DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11)),
        ],
    )
    .unwrap();
    assert_eq!(changes.reads()[0].object_id(), first_id);
    assert_eq!(changes.reads()[1].object_id(), second_id);
    assert_eq!(changes.mutations()[0].object_id(), first_id);
    assert_eq!(changes.mutations()[1].object_id(), second_id);
    assert!(changes.represented_bytes() > 2 * size_of::<u32>());

    assert_eq!(
        DurableObjectChanges::new(
            vec![
                DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
                DurableObjectHeadRead::new(first_id, DurableObjectHead::Absent),
            ],
            Vec::new(),
        ),
        Err(DurableInvocationError::DuplicateObjectReadId)
    );
    assert_eq!(
        DurableObjectChanges::new(
            Vec::new(),
            vec![DurableObjectMutationEntry::new(
                first_id,
                test_create_mutation(1, 0x11),
            )],
        ),
        Err(DurableInvocationError::ObjectMutationWithoutRead {
            object_id: first_id,
        })
    );
    assert_eq!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                first_id,
                test_create_mutation(1, 0x22),
            )],
        ),
        Err(DurableInvocationError::InvalidObjectTransition {
            object_id: first_id,
        })
    );
    assert_eq!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                first_id,
                DurableObjectMutation::Create {
                    version: test_object_version(1, 0x11),
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                        .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        ),
        Err(DurableInvocationError::InvalidObjectTransition {
            object_id: first_id,
        })
    );
    assert_eq!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Absent,
            )],
            vec![
                DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11),),
                DurableObjectMutationEntry::new(first_id, test_create_mutation(1, 0x11),),
            ],
        ),
        Err(DurableInvocationError::DuplicateObjectMutationId)
    );
    assert_eq!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Absent,
            )],
            vec![DurableObjectMutationEntry::new(
                first_id,
                test_create_mutation(2, 0x11),
            )],
        ),
        Err(DurableInvocationError::InvalidObjectTransition {
            object_id: first_id,
        })
    );

    let too_many_mutations: Vec<DurableObjectMutationEntry> = (0..=MAX_DURABLE_OBJECT_MUTATIONS)
        .map(|index: usize| {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[..size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
            DurableObjectMutationEntry::new(ObjectId::new(bytes), test_create_mutation(1, 0x33))
        })
        .collect();
    assert_eq!(
        DurableObjectChanges::new(Vec::new(), too_many_mutations),
        Err(DurableInvocationError::TooManyObjectMutations {
            count: MAX_DURABLE_OBJECT_MUTATIONS + 1,
            maximum: MAX_DURABLE_OBJECT_MUTATIONS,
        })
    );

    let too_many_reads: Vec<DurableObjectHeadRead> = (0_u16
        ..=u16::try_from(MAX_DURABLE_OBJECT_READS).unwrap())
        .map(|index: u16| {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[..2].copy_from_slice(&index.to_be_bytes());
            DurableObjectHeadRead::new(ObjectId::new(bytes), DurableObjectHead::Absent)
        })
        .collect();
    assert_eq!(
        DurableObjectChanges::new(too_many_reads, Vec::new()),
        Err(DurableInvocationError::TooManyObjectReads {
            count: MAX_DURABLE_OBJECT_READS + 1,
            maximum: MAX_DURABLE_OBJECT_READS,
        })
    );

    let empty_object: Object = Object {
        id: first_id,
        version: 2,
        owner: Owner::Shared,
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x46; 32]),
        schema_version: 1,
        data: Vec::new(),
    };
    let empty_length: usize = encode_object(&empty_object).unwrap().len();
    let mut maximum_object: Object = empty_object;
    maximum_object.data = vec![0; MAX_DURABLE_INLINE_OBJECT_BYTES - empty_length];
    let next_version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        maximum_object,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
        DurableObjectProvenance::new(
            ChainId::new("sunrise-runtime-tests").unwrap(),
            ProtocolVersion::new(1),
        ),
        4,
    )
    .unwrap();
    assert_eq!(
        next_version
            .payload()
            .inline()
            .unwrap()
            .canonical_bytes()
            .len(),
        MAX_DURABLE_INLINE_OBJECT_BYTES
    );
    assert!(
        DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                first_id,
                DurableObjectHead::Current {
                    head_revision: ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                        .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
            vec![DurableObjectMutationEntry::new(
                first_id,
                DurableObjectMutation::Update {
                    version: next_version,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Shared)
                        .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            )],
        )
        .is_ok()
    );
}

#[test]
fn durable_object_provenance_round_trips_and_grows_represented_bytes() {
    let chain_id: ChainId = ChainId::new("sunrise-runtime-tests").unwrap();
    let protocol_version: ProtocolVersion = ProtocolVersion::new(1);
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(chain_id.clone(), protocol_version);
    assert_eq!(provenance.chain_id(), &chain_id);
    assert_eq!(provenance.protocol_version(), protocol_version);

    let short_version: DurableObjectVersionRecord = test_object_version(1, 0x51);
    assert_eq!(short_version.provenance().chain_id(), &chain_id);
    assert_eq!(
        short_version.provenance().protocol_version(),
        protocol_version
    );

    fn object_with_id(byte: u8) -> Object {
        Object {
            id: ObjectId::new([byte; 32]),
            version: 1,
            owner: Owner::Address(objects::Address::new([byte.wrapping_add(1); 32])),
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(2); 32]),
            schema_version: 1,
            data: vec![byte.wrapping_add(3)],
        }
    }
    let long_chain_id: ChainId =
        ChainId::new("sunrise-runtime-tests-with-a-much-longer-chain-identifier").unwrap();
    let canonical: Vec<u8> = encode_object(&object_with_id(0x51)).unwrap();
    let long_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &long_chain_id,
            &canonical,
        )
        .unwrap();
    let long_version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        object_with_id(0x51),
        long_digest,
        DurableObjectProvenance::new(long_chain_id.clone(), protocol_version),
        1,
    )
    .unwrap();

    let short_bytes: usize = represented_object_version_bytes(0, &short_version).unwrap();
    let long_bytes: usize = represented_object_version_bytes(0, &long_version).unwrap();
    assert_eq!(
        long_bytes - short_bytes,
        long_chain_id.as_str().len() - chain_id.as_str().len()
    );

    let mut differing_provenance: DurableObjectVersionRecord = short_version.clone();
    differing_provenance.provenance = DurableObjectProvenance::new(
        ChainId::new("sunrise-runtime-tests-other").unwrap(),
        protocol_version,
    );
    assert_ne!(short_version, differing_provenance);

    let maximum_chain_id: ChainId = ChainId::new("x".repeat(128)).unwrap();
    let maximum_provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(maximum_chain_id.clone(), protocol_version);
    let bounded_canonical: Vec<u8> = encode_object(&object_with_id(0x59)).unwrap();
    let bounded_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &maximum_chain_id,
            &bounded_canonical,
        )
        .unwrap();
    let bounded_version: DurableObjectVersionRecord =
        DurableObjectVersionRecord::from_inline_object(
            object_with_id(0x59),
            bounded_digest,
            maximum_provenance,
            1,
        )
        .unwrap();
    assert!(
        represented_object_version_bytes(0, &bounded_version).unwrap()
            <= MAX_DURABLE_OBJECT_CHANGES_BYTES
    );
}

#[test]
fn memory_durable_objects_enforce_domain_fence_and_deadline() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(7).unwrap();
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(fence);
    store.set_time(100);
    let first_domain: AtomicityDomainId = domain(0x31);
    let second_domain: AtomicityDomainId = domain(0x32);
    let object_id: ObjectId = ObjectId::new([0x41; 32]);
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            test_create_mutation(1, 0x41),
        )],
    )
    .unwrap();

    let stale_context: DurableOperationContext = durable_context(6, 200, 0x41);
    assert_eq!(
        store.commit_invocation(
            &stale_context,
            test_object_invocation(first_domain, 0x41, objects.clone()),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: fence,
        })
    );
    assert_eq!(
        store.get_object_head(&stale_context, first_domain, object_id),
        Err(DurableReadError::WriterFenced {
            active_generation: fence,
        })
    );
    assert_eq!(
        store.get_object_version(
            &stale_context,
            first_domain,
            object_id,
            DurableObjectVersion::FIRST,
        ),
        Err(DurableReadError::WriterFenced {
            active_generation: fence,
        })
    );
    let expired_context: DurableOperationContext = durable_context(7, 100, 0x42);
    assert_eq!(
        store.commit_invocation(
            &expired_context,
            test_object_invocation(first_domain, 0x42, objects.clone()),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
    assert_eq!(
        store.get_object_head(&expired_context, first_domain, object_id),
        Err(DurableReadError::DeadlineExceeded)
    );
    assert_eq!(
        store.get_object_version(
            &expired_context,
            first_domain,
            object_id,
            DurableObjectVersion::FIRST,
        ),
        Err(DurableReadError::DeadlineExceeded)
    );

    let live_context: DurableOperationContext = durable_context(7, 200, 0x43);
    assert_eq!(
        store.commit_invocation(
            &live_context,
            test_object_invocation(first_domain, 0x43, objects),
        ),
        DurableCommitOutcome::Committed
    );
    assert!(matches!(
        store
            .get_object_head(&live_context, first_domain, object_id)
            .unwrap(),
        DurableObjectHead::Current { .. }
    ));
    assert_eq!(
        store
            .get_object_head(&live_context, second_domain, object_id)
            .unwrap(),
        DurableObjectHead::Absent
    );
    assert!(
        store
            .get_object_version(
                &live_context,
                first_domain,
                object_id,
                DurableObjectVersion::FIRST,
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .get_object_version(
                &live_context,
                second_domain,
                object_id,
                DurableObjectVersion::FIRST,
            )
            .unwrap(),
        None
    );
}

#[test]
fn structured_durable_invocation_keeps_receipt_and_outbox_typed() {
    let request_id = DurableRequestId::new([0x81; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x82; 32]);
    let message_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x83; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![0x84, 0x85]).unwrap();
    let message = DurableOutboxMessage::new(message_digest, vec![0x86, 0x87]).unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message.clone()]).unwrap();
    let state = DurableStateTransaction::new(
        domain(1),
        AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
        vec![mutation("state", StateMutation::Put(vec![1]))],
    )
    .unwrap();
    let invocation = DurableInvocationTransaction::new(
        domain(1),
        Some(state),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox.clone()),
    )
    .unwrap();

    assert_eq!(invocation.domain(), domain(1));
    assert_eq!(invocation.state().unwrap().mutations().len(), 1);
    assert!(invocation.objects().is_empty());
    assert_eq!(invocation.receipt(), &receipt);
    assert_eq!(invocation.outbox(), Some(&outbox));
    assert!(invocation.represented_bytes() > receipt.canonical_bytes().len());
    assert_eq!(outbox.messages()[0], message);
    assert_eq!(outbox.messages()[0].payload_digest(), message_digest);
}

#[test]
fn structured_durable_invocation_rejects_cross_section_identity_drift() {
    let request_id = DurableRequestId::new([0x91; 32]).unwrap();
    let other_request_id = DurableRequestId::new([0x92; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x93; 32]);
    let other_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x94; 32]);
    assert_eq!(
        DurableRequestReceipt::new(request_id, event_digest, Vec::new()),
        Err(DurableInvocationError::EmptyReceipt)
    );
    assert_eq!(
        DurableOutboxMessage::new(event_digest, Vec::new()),
        Err(DurableInvocationError::EmptyOutboxMessage)
    );
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let message = DurableOutboxMessage::new(event_digest, vec![2]).unwrap();
    let wrong_request =
        DurableOutboxBatch::new(other_request_id, event_digest, vec![message.clone()]).unwrap();
    assert_eq!(
        DurableInvocationTransaction::new(
            domain(1),
            None,
            DurableObjectChanges::empty(),
            receipt.clone(),
            Some(wrong_request),
        ),
        Err(DurableInvocationError::RequestIdentityMismatch)
    );
    let wrong_digest = DurableOutboxBatch::new(request_id, other_digest, vec![message]).unwrap();
    assert_eq!(
        DurableInvocationTransaction::new(
            domain(1),
            None,
            DurableObjectChanges::empty(),
            receipt.clone(),
            Some(wrong_digest),
        ),
        Err(DurableInvocationError::EventDigestMismatch)
    );
    let state = DurableStateTransaction::new(
        domain(2),
        AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        DurableInvocationTransaction::new(
            domain(1),
            Some(state),
            DurableObjectChanges::empty(),
            receipt,
            None,
        ),
        Err(DurableInvocationError::StateDomainMismatch)
    );
}

#[test]
fn memory_durable_store_commits_state_receipt_and_outbox_atomically() {
    let fence = WriterFenceGeneration::new(7).unwrap();
    let store = MemoryDurableStateStore::new(fence);
    store.set_time(100);
    let context = durable_context(7, 1_000, 1);
    let invocation = durable_invocation(domain(3), 0xA1, StateRevision::INITIAL, Some(9), true);
    let request_id = invocation.receipt().request_id();
    let receipt = invocation.receipt().clone();

    assert_eq!(
        store.commit_invocation(&context, invocation),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(3), b"state")
            .unwrap(),
        VersionedStateValue::from_persisted_parts(StateRevision::new(1), Some(vec![9])).unwrap()
    );
    assert_eq!(
        store
            .get_request_receipt(&context, domain(3), request_id)
            .unwrap(),
        Some(receipt)
    );
    let data = store.inner.read().unwrap();
    assert_eq!(data.receipts.len(), 1);
    assert_eq!(data.outboxes.len(), 1);
}

#[test]
fn memory_durable_store_conflict_publishes_no_partial_invocation() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context = durable_context(1, 1_000, 2);
    let initialize = AtomicStateTransaction::new(
        domain(4),
        AtomicStateReadSet::new(vec![read("state", StateRevision::INITIAL)]).unwrap(),
        AtomicStateMutationSet::new(vec![mutation("state", StateMutation::Put(vec![7]))]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, initialize),
        DurableCommitOutcome::Committed
    );
    let invocation = durable_invocation(domain(4), 0xB1, StateRevision::INITIAL, Some(8), true);
    let request_id = invocation.receipt().request_id();

    assert_eq!(
        store.commit_invocation(&context, invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: key("state"),
            current_revision: StateRevision::new(1),
        })
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(4), b"state")
            .unwrap()
            .value(),
        Some([7].as_slice())
    );
    assert_eq!(
        store
            .get_request_receipt(&context, domain(4), request_id)
            .unwrap(),
        None
    );
    assert!(store.inner.read().unwrap().outboxes.is_empty());
}

#[test]
fn memory_durable_store_preserves_read_only_revision_and_fails_closed_on_authority() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(5).unwrap());
    store.set_time(100);
    let context = durable_context(5, 1_000, 3);
    let read_only = durable_invocation(domain(5), 0xC1, StateRevision::INITIAL, None, false);
    assert_eq!(
        store.commit_invocation(&context, read_only),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(5), b"state")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );

    store.set_active_writer_fence(WriterFenceGeneration::new(6).unwrap());
    assert_eq!(
        store.get_versioned_durable(&context, domain(5), b"state"),
        Err(DurableReadError::WriterFenced {
            active_generation: WriterFenceGeneration::new(6).unwrap(),
        })
    );
    assert_eq!(
        store.commit_invocation(
            &context,
            durable_invocation(domain(5), 0xC2, StateRevision::INITIAL, None, false,),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: WriterFenceGeneration::new(6).unwrap(),
        })
    );

    let current_context = durable_context(6, 100, 4);
    assert_eq!(
        store.get_versioned_durable(&current_context, domain(5), b"state"),
        Err(DurableReadError::DeadlineExceeded)
    );
    assert_eq!(
        store.commit_invocation(
            &current_context,
            durable_invocation(domain(5), 0xC3, StateRevision::INITIAL, None, false,),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
}

fn put_durable(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    name: &str,
    value: u8,
) {
    let write = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![read(name, StateRevision::INITIAL)]).unwrap(),
        AtomicStateMutationSet::new(vec![mutation(name, StateMutation::Put(vec![value]))]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(context, write),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn memory_durable_state_scan_is_prefix_bounded_ordered_and_paginated() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context = durable_context(1, 1_000, 8);
    let selected_domain = domain(10);
    for (name, value) in [
        ("outbox/c", 3u8),
        ("other/a", 9),
        ("outbox/a", 1),
        ("outbox/b", 2),
    ] {
        put_durable(&store, &context, selected_domain, name, value);
    }

    let first_scan =
        StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(2).unwrap()).unwrap();
    let first = store
        .scan_durable_keys(&context, selected_domain, &first_scan)
        .unwrap();
    assert_eq!(first.keys(), &[key("outbox/a"), key("outbox/b")]);
    assert_eq!(first.continuation_cursor(), Some(b"outbox/b".as_slice()));

    let second_scan = StateKeyScan::new(
        key("outbox/"),
        first.continuation_cursor().map(<[u8]>::to_vec),
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    let second = store
        .scan_durable_keys(&context, selected_domain, &second_scan)
        .unwrap();
    assert_eq!(second.keys(), &[key("outbox/c")]);
    assert_eq!(second.continuation_cursor(), None);

    // A different bound domain never observes another domain's keys.
    let other_domain_scan =
        StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(4).unwrap()).unwrap();
    let other_domain_page = store
        .scan_durable_keys(&context, domain(11), &other_domain_scan)
        .unwrap();
    assert!(other_domain_page.keys().is_empty());
}

#[test]
fn memory_durable_state_scan_includes_tombstones_and_reports_empty_pages() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context = durable_context(1, 1_000, 9);
    let selected_domain = domain(12);
    put_durable(&store, &context, selected_domain, "key/a", 1);
    let delete = AtomicStateTransaction::new(
        selected_domain,
        AtomicStateReadSet::new(vec![read("key/a", StateRevision::new(1))]).unwrap(),
        AtomicStateMutationSet::new(vec![mutation("key/a", StateMutation::Delete)]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, delete),
        DurableCommitOutcome::Committed
    );

    let scan = StateKeyScan::new(key("key/"), None, NonZeroUsize::new(4).unwrap()).unwrap();
    let page = store
        .scan_durable_keys(&context, selected_domain, &scan)
        .unwrap();
    assert_eq!(page.keys(), &[key("key/a")]);
    assert_eq!(
        store
            .get_versioned_durable(&context, selected_domain, b"key/a")
            .unwrap()
            .value(),
        None
    );

    let empty_scan =
        StateKeyScan::new(key("missing/"), None, NonZeroUsize::new(4).unwrap()).unwrap();
    let empty_page = store
        .scan_durable_keys(&context, selected_domain, &empty_scan)
        .unwrap();
    assert!(empty_page.keys().is_empty());
    assert_eq!(empty_page.continuation_cursor(), None);
}

#[test]
fn memory_durable_state_scan_fails_closed_on_domain_fence_and_deadline() {
    let selected_domain = domain(13);
    let store =
        MemoryDurableStateStore::new_bound(selected_domain, WriterFenceGeneration::new(4).unwrap());
    store.set_time(50);
    let context = durable_context(4, 1_000, 10);
    let scan = StateKeyScan::new(key("key/"), None, NonZeroUsize::new(4).unwrap()).unwrap();

    assert_eq!(
        store.scan_durable_keys(&context, domain(14), &scan),
        Err(DurableReadError::InvalidRequest(
            RuntimeError::AtomicityDomainMismatch
        ))
    );

    store.set_active_writer_fence(WriterFenceGeneration::new(5).unwrap());
    assert_eq!(
        store.scan_durable_keys(&context, selected_domain, &scan),
        Err(DurableReadError::WriterFenced {
            active_generation: WriterFenceGeneration::new(5).unwrap(),
        })
    );

    let expired_context = durable_context(5, 10, 11);
    assert_eq!(
        store.scan_durable_keys(&expired_context, selected_domain, &scan),
        Err(DurableReadError::DeadlineExceeded)
    );
}

#[test]
fn memory_indexed_outbox_claims_stable_order_and_reconciles_same_lease() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context = durable_context(1, 1_000, 5);
    let selected_domain = domain(6);
    assert_eq!(
        store.commit_invocation(
            &context,
            durable_outbox_invocation(selected_domain, 0xB2, &[0x22]),
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.commit_invocation(
            &context,
            durable_outbox_invocation(selected_domain, 0xA2, &[0x11]),
        ),
        DurableCommitOutcome::Committed
    );

    let lease = DurableOutboxLeaseId::new([0x31; 32]).unwrap();
    let request = DueOutboxClaimRequest::new(selected_domain, 0, lease, 10).unwrap();
    let first = store.claim_due_outbox(&context, request);
    let replay = store.claim_due_outbox(&context, request);
    assert_eq!(first, replay);
    assert_eq!(
        store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(domain(8), 0, lease, 10).unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );
    let DurableOutboxClaimOutcome::Claimed(claim) = first else {
        panic!("expected a claimed outbox");
    };
    assert_eq!(
        claim.request_id(),
        OutboxRequestId::new([0xA2; 32]).unwrap()
    );
    assert_eq!(claim.canonical_payload(), &[0x11]);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                selected_domain,
                claim.request_id(),
                claim.message_index(),
                lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let next_lease = DurableOutboxLeaseId::new([0x32; 32]).unwrap();
    let next = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(selected_domain, 0, next_lease, 10).unwrap(),
    );
    let DurableOutboxClaimOutcome::Claimed(next) = next else {
        panic!("expected the next ordered outbox");
    };
    assert_eq!(next.request_id(), OutboxRequestId::new([0xB2; 32]).unwrap());
}

#[test]
fn memory_exact_request_claim_does_not_take_an_older_domain_row() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(3).unwrap());
    let context = durable_context(3, 1_000, 7);
    let selected_domain = domain(9);
    for request_byte in [0xA3, 0xB3] {
        assert_eq!(
            store.commit_invocation(
                &context,
                durable_outbox_invocation(selected_domain, request_byte, &[request_byte]),
            ),
            DurableCommitOutcome::Committed
        );
    }

    let exact_request_id = OutboxRequestId::new([0xB3; 32]).unwrap();
    let exact_lease = DurableOutboxLeaseId::new([0x51; 32]).unwrap();
    let exact_request =
        RequestOutboxClaimRequest::new(selected_domain, exact_request_id, 0, exact_lease, 10)
            .unwrap();
    let exact = store.claim_request_outbox(&context, exact_request);
    let DurableOutboxClaimOutcome::Claimed(exact) = exact else {
        panic!("expected exact request claim");
    };
    assert_eq!(exact.request_id(), exact_request_id);
    assert_eq!(exact.canonical_payload(), &[0xB3]);
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                selected_domain,
                OutboxRequestId::new([0xA3; 32]).unwrap(),
                0,
                exact_lease,
                10,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );

    let due_lease = DurableOutboxLeaseId::new([0x52; 32]).unwrap();
    let due = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(selected_domain, 0, due_lease, 10).unwrap(),
    );
    let DurableOutboxClaimOutcome::Claimed(due) = due else {
        panic!("expected remaining due claim");
    };
    assert_eq!(due.request_id(), OutboxRequestId::new([0xA3; 32]).unwrap());
}

#[test]
fn memory_indexed_outbox_retains_attempt_history_for_delayed_ack() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(2).unwrap());
    let context = durable_context(2, 1_000, 6);
    let selected_domain = domain(7);
    assert_eq!(
        store.commit_invocation(
            &context,
            durable_outbox_invocation(selected_domain, 0xD2, &[0x41, 0x42]),
        ),
        DurableCommitOutcome::Committed
    );
    let request_id = OutboxRequestId::new([0xD2; 32]).unwrap();
    let expired_lease = DurableOutboxLeaseId::new([0x41; 32]).unwrap();
    assert!(matches!(
        store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 0, expired_lease, 10).unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 10, expired_lease, 20).unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );

    let first_acknowledged_lease = DurableOutboxLeaseId::new([0x42; 32]).unwrap();
    let redelivery = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(selected_domain, 10, first_acknowledged_lease, 20).unwrap(),
    );
    let DurableOutboxClaimOutcome::Claimed(redelivery) = redelivery else {
        panic!("expected expired lease redelivery");
    };
    assert_eq!(redelivery.message_index(), 0);
    let first_ack =
        DurableOutboxAcknowledgement::new(selected_domain, request_id, 0, first_acknowledged_lease);
    assert_eq!(
        store.acknowledge_outbox(&context, first_ack),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let second_lease = DurableOutboxLeaseId::new([0x43; 32]).unwrap();
    let second = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(selected_domain, 10, second_lease, 20).unwrap(),
    );
    let DurableOutboxClaimOutcome::Claimed(second) = second else {
        panic!("expected second message");
    };
    assert_eq!(second.message_index(), 1);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(selected_domain, request_id, 1, second_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    assert_eq!(
        store.acknowledge_outbox(&context, first_ack),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    assert_eq!(
        store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(selected_domain, 10, expired_lease, 20).unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );
    let data = store.inner.read().unwrap();
    assert_eq!(data.delivery_attempts.len(), 3);
    assert!(data.deliveries.values().all(|delivery| delivery.completed));
}

#[test]
fn memory_domain_transactions_isolate_domains_and_assert_every_read() {
    let store = MemoryStateStore::default();
    let first_domain = domain(1);
    let second_domain = domain(2);

    let initialize_dependency = transaction(
        first_domain,
        vec![read("dependency", StateRevision::INITIAL)],
        vec![mutation("dependency", StateMutation::Put(vec![9]))],
    )
    .unwrap();
    assert_eq!(
        store.commit_transaction(initialize_dependency).unwrap(),
        AtomicStateWriteResult::Committed
    );

    let stale = transaction(
        first_domain,
        vec![
            read("dependency", StateRevision::INITIAL),
            read("result", StateRevision::INITIAL),
        ],
        vec![mutation("result", StateMutation::Put(vec![1]))],
    )
    .unwrap();
    assert_eq!(
        store.commit_transaction(stale).unwrap(),
        AtomicStateWriteResult::Conflict {
            key: key("dependency"),
            current_revision: StateRevision::new(1),
        }
    );
    assert_eq!(
        store
            .get_versioned_in_domain(first_domain, b"result")
            .unwrap()
            .value(),
        None
    );
    assert_eq!(
        store
            .get_versioned_in_domain(first_domain, b"dependency")
            .unwrap()
            .value(),
        Some([9].as_slice())
    );
    assert_eq!(
        store
            .get_versioned_in_domain(second_domain, b"dependency")
            .unwrap(),
        VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
    );
}

#[test]
fn state_key_scan_is_prefix_bounded_and_cursor_paginated() {
    let store = MemoryStateStore::default();
    for name in ["outbox/c", "other/a", "outbox/a", "outbox/b"] {
        store.put(key(name), vec![1]).unwrap();
    }
    let first_scan =
        StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(2).unwrap()).unwrap();
    let first = store.scan_keys(&first_scan).unwrap();
    assert_eq!(first.keys(), &[key("outbox/a"), key("outbox/b")]);
    assert_eq!(first.continuation_cursor(), Some(b"outbox/b".as_slice()));

    let second_scan = StateKeyScan::new(
        key("outbox/"),
        first.continuation_cursor().map(<[u8]>::to_vec),
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    let second = store.scan_keys(&second_scan).unwrap();
    assert_eq!(second.keys(), &[key("outbox/c")]);
    assert_eq!(second.continuation_cursor(), None);
}

#[test]
fn state_key_scan_rejects_unbounded_or_invalid_pages() {
    assert_eq!(
        StateKeyScan::new(
            key("outbox/"),
            Some(key("other/a")),
            NonZeroUsize::new(1).unwrap(),
        ),
        Err(RuntimeError::StateScanCursorOutsidePrefix)
    );
    assert_eq!(
        StateKeyScan::new(
            key("outbox/"),
            None,
            NonZeroUsize::new(MAX_STATE_SCAN_KEYS + 1).unwrap(),
        ),
        Err(RuntimeError::StateScanLimitTooLarge {
            requested: MAX_STATE_SCAN_KEYS + 1,
            maximum: MAX_STATE_SCAN_KEYS,
        })
    );

    let scan = StateKeyScan::new(key("outbox/"), None, NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(
        StateKeyPage::from_ordered_candidates(&scan, vec![key("outbox/b"), key("outbox/a")],),
        Err(RuntimeError::InvalidStateScanPage)
    );
    assert_eq!(
        StateKeyPage::from_ordered_candidates(&scan, vec![key("other/a")]),
        Err(RuntimeError::InvalidStateScanPage)
    );
}

#[test]
fn atomic_write_set_commits_multiple_keys_in_canonical_order() {
    let store = MemoryStateStore::default();
    let writes = AtomicStateWriteSet::new(vec![
        StateWrite::new(
            key("z"),
            StateRevision::INITIAL,
            StateMutation::Put(vec![2]),
        )
        .unwrap(),
        StateWrite::new(
            key("a"),
            StateRevision::INITIAL,
            StateMutation::Put(vec![1]),
        )
        .unwrap(),
    ])
    .unwrap();

    assert_eq!(writes.writes()[0].key(), b"a");
    assert_eq!(writes.writes()[1].key(), b"z");
    assert_eq!(
        store.commit_atomic(writes).unwrap(),
        AtomicStateWriteResult::Committed
    );
    assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
    assert_eq!(store.get(b"z").unwrap(), Some(vec![2]));
    assert_eq!(
        store.get_versioned(b"a").unwrap().revision(),
        StateRevision::new(1)
    );
}

#[test]
fn atomic_conflict_applies_none_of_the_write_set() {
    let store = MemoryStateStore::default();
    store.put(key("a"), vec![1]).unwrap();
    let observed_a = store.get_versioned(b"a").unwrap();
    let observed_b = store.get_versioned(b"b").unwrap();

    store.put(key("a"), vec![9]).unwrap();
    let writes = AtomicStateWriteSet::new(vec![
        StateWrite::new(key("a"), observed_a.revision(), StateMutation::Put(vec![2])).unwrap(),
        StateWrite::new(key("b"), observed_b.revision(), StateMutation::Put(vec![3])).unwrap(),
    ])
    .unwrap();

    assert_eq!(
        store.commit_atomic(writes).unwrap(),
        AtomicStateWriteResult::Conflict {
            key: key("a"),
            current_revision: StateRevision::new(2),
        }
    );
    assert_eq!(store.get(b"a").unwrap(), Some(vec![9]));
    assert_eq!(store.get(b"b").unwrap(), None);
}

#[test]
fn tombstone_revision_prevents_delete_recreate_aba() {
    let store = MemoryStateStore::default();
    store.put(key("k"), vec![1]).unwrap();
    let stale = store.get_versioned(b"k").unwrap();

    let delete = AtomicStateWriteSet::new(vec![
        StateWrite::new(key("k"), stale.revision(), StateMutation::Delete).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        store.commit_atomic(delete).unwrap(),
        AtomicStateWriteResult::Committed
    );
    let deleted = store.get_versioned(b"k").unwrap();
    assert_eq!(deleted.value(), None);
    assert_eq!(deleted.revision(), StateRevision::new(2));

    let recreate = AtomicStateWriteSet::new(vec![
        StateWrite::new(key("k"), deleted.revision(), StateMutation::Put(vec![1])).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        store.commit_atomic(recreate).unwrap(),
        AtomicStateWriteResult::Committed
    );

    let stale_write = AtomicStateWriteSet::new(vec![
        StateWrite::new(key("k"), stale.revision(), StateMutation::Put(vec![7])).unwrap(),
    ])
    .unwrap();
    assert_eq!(
        store.commit_atomic(stale_write).unwrap(),
        AtomicStateWriteResult::Conflict {
            key: key("k"),
            current_revision: StateRevision::new(3),
        }
    );
    assert_eq!(store.get(b"k").unwrap(), Some(vec![1]));
}

#[test]
fn atomic_write_set_rejects_duplicates_and_resource_excess() {
    let duplicate =
        StateWrite::new(key("same"), StateRevision::INITIAL, StateMutation::Delete).unwrap();
    assert_eq!(
        AtomicStateWriteSet::new(vec![duplicate.clone(), duplicate]),
        Err(RuntimeError::DuplicateStateWriteKey)
    );
    assert_eq!(
        AtomicStateWriteSet::new(Vec::new()),
        Err(RuntimeError::EmptyWriteSet)
    );
    assert!(matches!(
        StateWrite::new(
            vec![0; MAX_STATE_KEY_BYTES + 1],
            StateRevision::INITIAL,
            StateMutation::Delete,
        ),
        Err(RuntimeError::StateKeyTooLong { .. })
    ));
    assert!(matches!(
        StateWrite::new(
            key("large"),
            StateRevision::INITIAL,
            StateMutation::Put(vec![0; MAX_STATE_VALUE_BYTES + 1]),
        ),
        Err(RuntimeError::StateValueTooLarge { .. })
    ));
}

#[test]
fn revision_overflow_aborts_before_any_atomic_mutation() {
    let store = MemoryStateStore::default();
    {
        let mut domains = store.inner.write().unwrap();
        domains.entry(LEGACY_MEMORY_DOMAIN).or_default().insert(
            key("a"),
            StoredStateValue {
                revision: StateRevision::new(u64::MAX),
                value: Some(vec![1]),
            },
        );
    }
    let writes = AtomicStateWriteSet::new(vec![
        StateWrite::new(
            key("a"),
            StateRevision::new(u64::MAX),
            StateMutation::Put(vec![2]),
        )
        .unwrap(),
        StateWrite::new(
            key("b"),
            StateRevision::INITIAL,
            StateMutation::Put(vec![3]),
        )
        .unwrap(),
    ])
    .unwrap();

    assert_eq!(
        store.commit_atomic(writes),
        Err(RuntimeError::StateRevisionOverflow)
    );
    assert_eq!(store.get(b"a").unwrap(), Some(vec![1]));
    assert_eq!(store.get(b"b").unwrap(), None);
}

#[test]
fn atomic_assert_checks_revision_without_incrementing_it() {
    let store = MemoryStateStore::default();
    store.put(key("a"), vec![1]).unwrap();
    let observed = store.get_versioned(b"a").unwrap();
    let write_set = AtomicStateWriteSet::new(vec![
        StateWrite::new(key("a"), observed.revision(), StateMutation::Assert).unwrap(),
    ])
    .unwrap();

    assert_eq!(
        store.commit_atomic(write_set).unwrap(),
        AtomicStateWriteResult::Committed
    );
    assert_eq!(store.get_versioned(b"a").unwrap(), observed);
}

#[test]
fn scheduler_returns_only_ready_payloads() {
    let scheduler = MemoryScheduler::default();
    scheduler.schedule(20, vec![2]).unwrap();
    scheduler.schedule(10, vec![1]).unwrap();
    scheduler.schedule(30, vec![3]).unwrap();

    let first = scheduler.drain_ready(20).unwrap();
    let second = scheduler.drain_ready(25).unwrap();
    let third = scheduler.drain_ready(30).unwrap();

    assert_eq!(first.len(), 2);
    assert_eq!(first[0].payload, vec![1]);
    assert_eq!(first[1].payload, vec![2]);
    assert!(second.is_empty());
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].payload, vec![3]);
}

#[test]
fn persistence_layout_is_deterministic_and_namespaced() {
    let chain_id = ChainId::new("sunrise-devnet").unwrap();
    let layout = PersistenceLayout::new(chain_id.clone(), ProtocolVersion::new(3));

    let key1 = layout.epoch_metadata_key(Epoch::new(7));
    let key2 = layout.epoch_metadata_key(Epoch::new(7));
    assert_eq!(key1, key2);

    let key3 = layout.object_version_key([0x11; 32], 5);
    let key4 = layout.object_version_key([0x11; 32], 6);
    assert_ne!(key3, key4);

    let key5 = layout.system_module_record_key([0xAA; 32], 1);
    let key6 = layout.system_module_record_key([0xAA; 32], 2);
    assert_ne!(key5, key6);

    let other_layout = PersistenceLayout::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
    );
    assert_ne!(
        layout.protocol_config_key(),
        other_layout.protocol_config_key()
    );

    let key1_text = String::from_utf8(key1).unwrap();
    assert!(key1_text.starts_with("se/sunrise-devnet/v3/epoch/"));
    let key5_text = String::from_utf8(key5).unwrap();
    assert!(key5_text.contains("system-modules/"));

    let migration = Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0xBB; 32]);
    let migration_key = layout.migration_record_key(&migration);
    assert_ne!(migration_key, layout.protocol_upgrade_schedule_key());
    assert_ne!(
        layout.consensus_state_key(Epoch::new(7)),
        layout.consensus_state_key(Epoch::new(8))
    );
    assert_ne!(
        layout.request_dedup_key([0xCC; 32]),
        layout.outbox_batch_key([0xCC; 32])
    );
    assert_ne!(
        layout.outbox_batch_key([0xCC; 32]),
        layout.outbox_delivery_key([0xCC; 32])
    );
    assert_ne!(
        layout.request_dedup_key([0xCC; 32]),
        layout.request_dedup_key([0xCD; 32])
    );
    assert!(
        String::from_utf8(migration_key)
            .unwrap()
            .contains("protocol/migrations/sha2-256-")
    );
}

#[test]
fn sender_nonce_key_matches_exact_stable_vector() {
    let chain_id = ChainId::new("sunrise-devnet").unwrap();
    let layout = PersistenceLayout::new(chain_id, ProtocolVersion::new(3));

    let key = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
    let expected = b"se/sunrise-devnet/v3/sender-nonces/\
1111111111111111111111111111111111111111111111111111111111111111\
/00000000000000000007"
        .to_vec();
    assert_eq!(key, expected);

    let prefix = layout.sender_nonce_prefix();
    assert_eq!(prefix, b"se/sunrise-devnet/v3/sender-nonces/".to_vec());
    assert!(key.starts_with(&prefix));
}

#[test]
fn sender_nonce_key_is_deterministic_and_namespaced_per_sender_epoch_chain() {
    let chain_id = ChainId::new("sunrise-devnet").unwrap();
    let layout = PersistenceLayout::new(chain_id, ProtocolVersion::new(3));

    let key1 = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
    let key2 = layout.sender_nonce_key([0x11; 32], Epoch::new(7));
    assert_eq!(key1, key2);

    let different_sender = layout.sender_nonce_key([0x22; 32], Epoch::new(7));
    assert_ne!(key1, different_sender);

    let different_epoch = layout.sender_nonce_key([0x11; 32], Epoch::new(8));
    assert_ne!(key1, different_epoch);

    let other_layout = PersistenceLayout::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
    );
    assert_ne!(
        key1,
        other_layout.sender_nonce_key([0x11; 32], Epoch::new(7))
    );

    assert!(key1.starts_with(&layout.sender_nonce_prefix()));
    assert!(!different_sender.starts_with(&other_layout.sender_nonce_prefix()));
}

#[test]
fn memory_runtime_wires_components() {
    let runtime = MemoryRuntime::new(ValidatorId::new([0xAA; 32]));
    runtime.set_time(123);

    assert_eq!(runtime.clock().now_unix_millis().unwrap(), 123);
    assert_eq!(
        runtime.signer().validator_id(),
        ValidatorId::new([0xAA; 32])
    );

    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]);
    runtime.blob_store().put_blob(digest, vec![7, 8]).unwrap();
    assert_eq!(
        runtime.blob_store().get_blob(&digest).unwrap(),
        Some(vec![7, 8])
    );

    runtime.transport().send(vec![1, 2, 3]).unwrap();
    assert_eq!(
        runtime.transport().drain_outbound().unwrap(),
        vec![vec![1, 2, 3]]
    );
}

/// Storing byte-identical content under a digest already present is an
/// idempotent no-op success, matching a retried or duplicate publication
/// of the same immutable version.
#[test]
fn memory_blob_store_put_is_idempotent_for_identical_content() {
    let store = MemoryBlobStore::default();
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]);
    store.put_blob(digest, vec![1, 2, 3]).unwrap();
    store.put_blob(digest, vec![1, 2, 3]).unwrap();
    assert_eq!(store.get_blob(&digest).unwrap(), Some(vec![1, 2, 3]));
}

/// Storing different content under an already-present digest fails
/// closed rather than silently overwriting the existing bytes.
#[test]
fn memory_blob_store_put_rejects_conflicting_content() {
    let store = MemoryBlobStore::default();
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x03; 32]);
    store.put_blob(digest, vec![1, 2, 3]).unwrap();
    assert_eq!(
        store.put_blob(digest, vec![9, 9, 9]),
        Err(RuntimeError::BlobDigestConflict { digest })
    );
    assert_eq!(store.get_blob(&digest).unwrap(), Some(vec![1, 2, 3]));
}

/// A poisoned lock means the map's contents are no longer trustworthy:
/// both operations fail closed with a typed storage-unavailability error
/// rather than silently recovering a guard over possibly-torn state.
#[test]
fn memory_blob_store_fails_closed_on_poisoned_lock() {
    let store = Arc::new(MemoryBlobStore::default());
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x04; 32]);
    let poison_store = Arc::clone(&store);
    let result = std::thread::spawn(move || {
        let _guard = poison_store.inner.write().unwrap();
        panic!("intentionally poison the blob store lock");
    })
    .join();
    assert!(result.is_err());

    assert_eq!(
        store.put_blob(digest, vec![5, 6]),
        Err(RuntimeError::DurableStoreUnavailable)
    );
    assert_eq!(
        store.get_blob(&digest),
        Err(RuntimeError::DurableStoreUnavailable)
    );
}
