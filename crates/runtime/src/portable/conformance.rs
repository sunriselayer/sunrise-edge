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
