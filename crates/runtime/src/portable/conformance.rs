//! Test-only portable repository fixtures. These assertions are storage
//! conformance, NOT proof of authenticated cut completeness or activation.

use super::*;
use crate::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectRoutingProjection, DurableRequestReceipt, StateMutation, StateMutationEntry,
    StateReadAssertion,
};
use objects::{Address, Object, Owner};
use protocol_types::{ChainId, HashAlgorithmId, ProtocolVersion};

/// Verifies that every collection uses one backend-enforced source token.
/// Reuse on independently bootstrapped memory/SQLite/PostgreSQL namespaces.
pub fn verify_snapshot<S: DurablePortableSnapshotRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> PortableSnapshotToken {
    let token: PortableSnapshotToken = store.begin_portable_snapshot(context, domain).unwrap();
    store
        .check_portable_outbox_empty_at(context, domain, &token)
        .unwrap();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(2).unwrap())
                    .unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(context, domain, &token, &scan)
                .unwrap();
            assert_eq!(
                page,
                store.scan_portable_keys(context, domain, &scan).unwrap()
            );
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor_at(context, domain, &token, key)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    Some(descriptor.clone()),
                    store
                        .read_portable_descriptor(context, domain, key)
                        .unwrap()
                );
                if let Some(length) = descriptor.payload_length() {
                    // Both ends of a large legal value are guarded. Existing
                    // conformance::verify covers all intervening payloads.
                    for offset in [0, length.saturating_sub(1)] {
                        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            offset,
                            NonZeroUsize::new(256).unwrap(),
                        )
                        .unwrap();
                        assert_eq!(
                            store
                                .read_portable_chunk_at(context, domain, &token, &request)
                                .unwrap(),
                            store
                                .read_portable_chunk(context, domain, &request)
                                .unwrap()
                        );
                    }
                }
            }
            match page.continuation() {
                Some(next) => after = Some(next.clone()),
                None => break,
            }
        }
    }
    assert_eq!(
        token,
        store.begin_portable_snapshot(context, domain).unwrap()
    );
    token
}

/// A previously unseen key invalidates even reads of an unchanged row. This
/// catches omission between pages, which per-row descriptor checks cannot.
pub fn assert_snapshot_changed<S: DurablePortableSnapshotRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) {
    let token: PortableSnapshotToken = store.begin_portable_snapshot(context, domain).unwrap();
    let key: DurableRecordKey = DurableRecordKey::State(b"a-large".to_vec());
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor_at(context, domain, &token, &key)
        .unwrap()
        .unwrap();
    let chunk: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(256).unwrap()).unwrap();
    let new_key: Vec<u8> = b"z-snapshot-new".to_vec();
    let write: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(new_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(new_key, StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(context, write),
        DurableCommitOutcome::Committed
    ));
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.scan_portable_keys_at(context, domain, &token, &scan),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.read_portable_descriptor_at(context, domain, &token, &key),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.read_portable_chunk_at(context, domain, &token, &chunk),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.check_portable_outbox_empty_at(context, domain, &token),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(
        store
            .begin_portable_snapshot(context, domain)
            .unwrap()
            .mutation_sequence()
            > token.mutation_sequence()
    );
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

/// Seeds one empty isolated test namespace. Panics on contract failure.
pub fn seed<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
) {
    let state: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(
            [
                b"a-large".as_slice(),
                b"b-empty".as_slice(),
                b"c-deleted".as_slice(),
            ]
            .into_iter()
            .map(|key| StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL).unwrap())
            .collect(),
        )
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                b"a-large".to_vec(),
                StateMutation::Put(vec![0x5a; MAX_STATE_VALUE_BYTES]),
            )
            .unwrap(),
            StateMutationEntry::new(b"b-empty".to_vec(), StateMutation::Put(Vec::new())).unwrap(),
            StateMutationEntry::new(b"c-deleted".to_vec(), StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(context, state),
        DurableCommitOutcome::Committed
    ));
    let id: ObjectId = ObjectId::new([1; 32]);
    for n in 1..=10u8 {
        let object: Object = Object {
            id,
            version: u64::from(n),
            owner: Owner::Address(Address::new([7; 32])),
            type_hash: digest(0xcc),
            schema_version: 1,
            data: vec![
                n;
                if n == 1 {
                    MAX_PORTABLE_CHUNK_BYTES + 11
                } else {
                    1
                }
            ],
        };
        let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
            object,
            digest(n),
            DurableObjectProvenance::new(chain.clone(), ProtocolVersion::new(1)),
            u64::from(n),
        )
        .unwrap();
        let owner: DurableObjectOwnerProjection =
            DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new([7; 32])))
                .unwrap();
        let routing: DurableObjectRoutingProjection =
            DurableObjectRoutingProjection::new(Some(vec![n])).unwrap();
        let mutation: DurableObjectMutation = if n == 1 {
            DurableObjectMutation::Create {
                version,
                owner_projection: owner,
                routing_projection: routing,
            }
        } else {
            DurableObjectMutation::Update {
                version,
                owner_projection: owner,
                routing_projection: routing,
            }
        };
        commit_object(store, context, domain, id, n, mutation);
    }
    commit_object(
        store,
        context,
        domain,
        id,
        11,
        DurableObjectMutation::Delete,
    );
    let id: ObjectId = ObjectId::new([2; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::FIRST,
        digest(12),
        1,
        DurableObjectProvenance::new(chain.clone(), ProtocolVersion::new(1)),
        12,
        digest(0xbb),
    );
    commit_object(
        store,
        context,
        domain,
        id,
        12,
        DurableObjectMutation::Create {
            version,
            owner_projection: DurableObjectOwnerProjection::default(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
    );
}

fn commit_object<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    id: ObjectId,
    n: u8,
    mutation: DurableObjectMutation,
) {
    let head: DurableObjectHead = store.get_object_head(context, domain, id).unwrap();
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(id, head)],
        vec![DurableObjectMutationEntry::new(id, mutation)],
    )
    .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([n; 32]).unwrap(),
        digest(n),
        vec![
            n;
            if n == 1 {
                MAX_PORTABLE_CHUNK_BYTES + 13
            } else {
                1
            }
        ],
    )
    .unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain, None, objects, receipt, None).unwrap();
    assert!(matches!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    ));
}

fn keys<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    collection: DurableCollection,
) -> Vec<DurableRecordKey> {
    let mut after: Option<DurableRecordKey> = None;
    let mut keys: Vec<DurableRecordKey> = Vec::new();
    loop {
        let request: DurableRecordScan =
            DurableRecordScan::new(collection, after, NonZeroUsize::new(1).unwrap()).unwrap();
        let page: DurableRecordPage = store.scan_portable_keys(context, domain, &request).unwrap();
        keys.extend_from_slice(page.keys());
        after = page.continuation().cloned();
        if after.is_none() {
            return keys;
        }
    }
}

fn payload<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    descriptor: &DurableRecordDescriptor,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            body.len(),
            NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES).unwrap(),
        )
        .unwrap();
        let DurableRecordChunkOutcome::Chunk(chunk) = store
            .read_portable_chunk(context, domain, &request)
            .unwrap_or_else(|error| {
                panic!(
                    "chunk read {:?} {:?}: {error:?}",
                    descriptor.key(),
                    request.range()
                )
            })
        else {
            panic!("quiescent fixture descriptor changed")
        };
        assert!(chunk.bytes().len() <= MAX_PORTABLE_CHUNK_BYTES);
        assert!(chunk.is_last() || !chunk.bytes().is_empty());
        body.extend_from_slice(chunk.bytes());
        if chunk.is_last() {
            assert_eq!(Some(body.len()), descriptor.payload_length());
            return body;
        }
    }
}

/// Verifies exact metadata, all original rows/tombstones and large payloads
/// using the same contract after reopen. Panics on contract failure.
pub fn verify<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
) {
    let states: Vec<DurableRecordKey> = keys(store, context, domain, DurableCollection::State);
    assert_eq!(
        states,
        vec![
            DurableRecordKey::State(b"a-large".to_vec()),
            DurableRecordKey::State(b"b-empty".to_vec()),
            DurableRecordKey::State(b"c-deleted".to_vec())
        ]
    );
    for (index, key) in states.iter().enumerate() {
        let descriptor: DurableRecordDescriptor = store
            .read_portable_descriptor(context, domain, key)
            .unwrap()
            .unwrap();
        assert!(
            matches!(descriptor.metadata(),DurableRecordMetadata::State{revision,..} if *revision!=StateRevision::INITIAL)
        );
        match index {
            0 => {
                assert_eq!(descriptor.payload_length(), Some(MAX_STATE_VALUE_BYTES));
                assert!(
                    payload(store, context, domain, &descriptor)
                        .iter()
                        .all(|byte| *byte == 0x5a)
                );
            }
            1 => {
                assert_eq!(descriptor.payload_length(), Some(0));
                assert!(payload(store, context, domain, &descriptor).is_empty());
            }
            _ => assert_eq!(descriptor.payload_length(), None),
        }
    }
    assert_eq!(
        store
            .read_portable_descriptor(
                context,
                domain,
                &DurableRecordKey::State(b"never-existed".to_vec())
            )
            .unwrap(),
        None
    );
    let receipts: Vec<DurableRecordKey> = keys(store, context, domain, DurableCollection::Receipts);
    assert_eq!(receipts.len(), 12);
    for (index, key) in receipts.iter().enumerate() {
        let byte: u8 = u8::try_from(index + 1).unwrap();
        assert_eq!(
            *key,
            DurableRecordKey::Receipt(DurableRequestId::new([byte; 32]).unwrap())
        );
        let descriptor: DurableRecordDescriptor = store
            .read_portable_descriptor(context, domain, key)
            .unwrap()
            .unwrap();
        assert!(
            matches!(descriptor.metadata(),DurableRecordMetadata::Receipt{event_digest,..} if *event_digest==digest(byte))
        );
        let body: Vec<u8> = payload(store, context, domain, &descriptor);
        assert_eq!(
            body.len(),
            if byte == 1 {
                MAX_PORTABLE_CHUNK_BYTES + 13
            } else {
                1
            }
        );
        assert!(body.iter().all(|n| *n == byte));
    }
    let heads: Vec<DurableRecordKey> = keys(store, context, domain, DurableCollection::ObjectHeads);
    assert_eq!(
        heads,
        vec![
            DurableRecordKey::ObjectHead(ObjectId::new([1; 32])),
            DurableRecordKey::ObjectHead(ObjectId::new([2; 32]))
        ]
    );
    let deleted: DurableRecordDescriptor = store
        .read_portable_descriptor(context, domain, &heads[0])
        .unwrap()
        .unwrap();
    assert!(
        matches!(deleted.metadata(),DurableRecordMetadata::ObjectHead(DurableObjectHead::Tombstoned{last_object_version,..}) if last_object_version.get()==10)
    );
    let current: DurableRecordDescriptor = store
        .read_portable_descriptor(context, domain, &heads[1])
        .unwrap()
        .unwrap();
    assert_eq!(current.payload_length(), None);
    assert!(matches!(
        current.metadata(),
        DurableRecordMetadata::ObjectHead(DurableObjectHead::Current {
            head_revision,
            object_version,
            digest: stored,
            owner_projection,
            routing_projection,
        }) if head_revision.get() == 1
            && *object_version == DurableObjectVersion::FIRST
            && *stored == digest(12)
            && owner_projection.bytes().is_none()
            && routing_projection.bytes().is_none()
    ));
    let versions: Vec<DurableRecordKey> =
        keys(store, context, domain, DurableCollection::ObjectVersions);
    assert_eq!(versions.len(), 11);
    for (index, key) in versions.iter().enumerate() {
        let descriptor: DurableRecordDescriptor = store
            .read_portable_descriptor(context, domain, key)
            .unwrap()
            .unwrap();
        let DurableRecordMetadata::ObjectVersion {
            provenance,
            schema_version,
            created_checkpoint,
            payload: kind,
            digest: stored,
        } = descriptor.metadata()
        else {
            panic!("wrong version metadata")
        };
        assert_eq!(
            provenance,
            &DurableObjectProvenance::new(chain.clone(), ProtocolVersion::new(1))
        );
        assert_eq!(*schema_version, 1);
        if index < 10 {
            let version: u64 = u64::try_from(index + 1).unwrap();
            assert_eq!(
                *key,
                DurableRecordKey::ObjectVersion(
                    ObjectId::new([1; 32]),
                    DurableObjectVersion::new(version).unwrap()
                )
            );
            assert_eq!(*created_checkpoint, version);
            assert_eq!(*stored, digest(u8::try_from(version).unwrap()));
            let object: Object =
                objects::decode_object(&payload(store, context, domain, &descriptor)).unwrap();
            assert_eq!(object.id, ObjectId::new([1; 32]));
            assert_eq!(object.version, version);
            assert_eq!(
                object.data.len(),
                if version == 1 {
                    MAX_PORTABLE_CHUNK_BYTES + 11
                } else {
                    1
                }
            );
            assert!(object.data.iter().all(|byte| u64::from(*byte) == version));
        } else {
            assert_eq!(
                *key,
                DurableRecordKey::ObjectVersion(
                    ObjectId::new([2; 32]),
                    DurableObjectVersion::FIRST
                )
            );
            assert_eq!(*kind, DurablePayloadDescriptor::BlobReference(digest(0xbb)));
            assert_eq!(descriptor.payload_length(), None);
        }
    }
}

/// A legitimate same-length rewrite must invalidate a previously observed
/// descriptor even when the actual payload bytes are identical.
pub fn assert_changed<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) {
    let key: DurableRecordKey = DurableRecordKey::State(b"b-empty".to_vec());
    let old: DurableRecordDescriptor = store
        .read_portable_descriptor(context, domain, &key)
        .unwrap()
        .unwrap();
    let DurableRecordMetadata::State { revision, .. } = old.metadata() else {
        panic!("expected state")
    };
    let state: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"b-empty".to_vec(), *revision).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"b-empty".to_vec(), StateMutation::Put(Vec::new())).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(context, state),
        DurableCommitOutcome::Committed
    ));
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(old, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(
        store
            .read_portable_chunk(context, domain, &request)
            .unwrap(),
        DurableRecordChunkOutcome::Changed
    );
}

/// All three read methods must reject the same authority error. Capture the
/// descriptor before changing the writer or schema authority.
pub fn assert_refused<S: DurablePortableRepository>(
    store: &S,
    rejected: &DurableOperationContext,
    rejected_domain: AtomicityDomainId,
    descriptor: &DurableRecordDescriptor,
    expected: DurableReadError,
) {
    let key: &DurableRecordKey = descriptor.key();
    let chunk: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor.clone(), 0, NonZeroUsize::new(1).unwrap())
            .unwrap();
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.scan_portable_keys(rejected, rejected_domain, &scan),
        Err(expected.clone())
    );
    assert_eq!(
        store.read_portable_descriptor(rejected, rejected_domain, key),
        Err(expected.clone())
    );
    assert_eq!(
        store.read_portable_chunk(rejected, rejected_domain, &chunk),
        Err(expected)
    );
}

/// One reusable content-addressed blob fixture: a present-empty blob and one
/// present multi-chunk blob whose length exceeds [`MAX_PORTABLE_CHUNK_BYTES`].
#[derive(Clone, Debug)]
pub struct BlobFixture {
    pub empty_digest: Digest32,
    pub large_digest: Digest32,
    pub large_bytes: Vec<u8>,
}

/// Seeds one present-empty blob and one large multi-chunk blob. Panics on
/// contract failure.
pub fn seed_blob<S: PortableBlobRepository>(store: &S) -> BlobFixture {
    let empty_digest: Digest32 = digest(0xe1);
    store.put_blob(empty_digest, Vec::new()).unwrap();
    let large_digest: Digest32 = digest(0xe2);
    let large_bytes: Vec<u8> = (0..(MAX_PORTABLE_CHUNK_BYTES + 17))
        .map(|index| u8::try_from(index % 256).unwrap())
        .collect();
    store.put_blob(large_digest, large_bytes.clone()).unwrap();
    BlobFixture {
        empty_digest,
        large_digest,
        large_bytes,
    }
}

fn blob_payload<S: PortableBlobRepository>(
    store: &S,
    descriptor: &PortableBlobDescriptor,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            *descriptor,
            body.len(),
            NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES).unwrap(),
        )
        .unwrap();
        let outcome: PortableBlobChunkOutcome = store.read_portable_blob_chunk(&request).unwrap();
        let chunk: Box<PortableBlobChunk> = match outcome {
            PortableBlobChunkOutcome::Chunk(chunk) => chunk,
            PortableBlobChunkOutcome::Corrupt => {
                panic!("quiescent blob fixture descriptor changed")
            }
        };
        assert!(chunk.bytes().len() <= MAX_PORTABLE_CHUNK_BYTES);
        assert!(chunk.is_last() || !chunk.bytes().is_empty());
        body.extend_from_slice(chunk.bytes());
        if chunk.is_last() {
            assert_eq!(body.len(), descriptor.length());
            return body;
        }
    }
}

/// Verifies exact missing/present-empty/large-multi-chunk semantics using
/// the same contract, e.g. after a close/reopen. Panics on contract failure.
pub fn verify_blob<S: PortableBlobRepository>(store: &S, fixture: &BlobFixture) {
    let missing_digest: Digest32 = digest(0xef);
    assert_eq!(
        store
            .read_portable_blob_descriptor(&missing_digest)
            .unwrap(),
        None
    );

    let empty_descriptor: PortableBlobDescriptor = store
        .read_portable_blob_descriptor(&fixture.empty_digest)
        .unwrap()
        .unwrap();
    assert_eq!(empty_descriptor.length(), 0);
    assert_eq!(blob_payload(store, &empty_descriptor), Vec::<u8>::new());

    let large_descriptor: PortableBlobDescriptor = store
        .read_portable_blob_descriptor(&fixture.large_digest)
        .unwrap()
        .unwrap();
    assert_eq!(large_descriptor.length(), fixture.large_bytes.len());
    assert_eq!(blob_payload(store, &large_descriptor), fixture.large_bytes);
}

/// A descriptor whose claimed length disagrees with the true stored content
/// must never yield stitched bytes. Panics on contract failure.
pub fn assert_blob_chunk_corrupt<S: PortableBlobRepository>(store: &S, fixture: &BlobFixture) {
    let wrong: PortableBlobDescriptor =
        PortableBlobDescriptor::new(fixture.large_digest, fixture.large_bytes.len() + 1);
    let request: PortableBlobChunkRequest =
        PortableBlobChunkRequest::new(wrong, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(
        store.read_portable_blob_chunk(&request).unwrap(),
        PortableBlobChunkOutcome::Corrupt
    );
    for missing_length in [0usize, 1usize] {
        let missing: PortableBlobDescriptor =
            PortableBlobDescriptor::new(digest(0xef), missing_length);
        let request: PortableBlobChunkRequest =
            PortableBlobChunkRequest::new(missing, 0, NonZeroUsize::new(1).unwrap()).unwrap();
        assert_eq!(
            store.read_portable_blob_chunk(&request).unwrap(),
            PortableBlobChunkOutcome::Corrupt
        );
    }
}
