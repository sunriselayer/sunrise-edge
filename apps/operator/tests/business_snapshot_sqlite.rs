//! Direct production capture over real embedded SQLite, not D1/DO certification.
//! Only the adversarial wrapper injects writes; capture has no writable seam.

use hashing::{BuiltinHashFunction, HashFunction};
use node_core::business_reconstruction::{SourceBusinessSnapshot, SourceSnapshotRecord};
use node_core::{NodeDedupRecord, NodeResponse, NodeResponseStatus, RequestId};
use objects::{Address, Object, ObjectId, Owner};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, HashPurpose, ProtocolVersion,
    ValidatorId,
};
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurablePortableSnapshotRepository,
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordDescriptor,
    DurableRecordKey, DurableRecordPage, DurableRecordScan, MAX_PORTABLE_CHUNK_BYTES,
    PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobDescriptor,
    PortableBlobRepository, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, BlobStore,
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableOutboxBatch, DurableOutboxMessage, DurableReadError,
    DurableRequestId, DurableRequestReceipt, DurableStateTransaction, RuntimeError, StateMutation,
    StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    num::NonZeroUsize,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

const COLLECTIONS: [DurableCollection; 4] = [
    DurableCollection::State,
    DurableCollection::Receipts,
    DurableCollection::ObjectHeads,
    DurableCollection::ObjectVersions,
];

struct OwnedDirectory(PathBuf);
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn operation(fence: WriterFenceGeneration) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    )
}

fn digest(chain: &ChainId, purpose: HashPurpose, bytes: &[u8]) -> Digest32 {
    BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(purpose, ProtocolVersion::new(1), chain, bytes)
        .unwrap()
}

fn receipt(chain: &ChainId, id: u8, payload: Vec<u8>) -> DurableRequestReceipt {
    let request: RequestId = RequestId::new([id; 32]).unwrap();
    let event: Digest32 = digest(chain, HashPurpose::NodeEvent, &[id]);
    let response: NodeResponse =
        NodeResponse::new(request, NodeResponseStatus::Accepted, Some(payload)).unwrap();
    let bytes: Vec<u8> = NodeDedupRecord::new(request, event, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    DurableRequestReceipt::new(DurableRequestId::new([id; 32]).unwrap(), event, bytes).unwrap()
}

struct Fixture {
    store: SqliteDurableStore,
    blobs: SqliteBlobStore,
    namespace: SqliteNamespace,
    blob_bytes: BTreeMap<Digest32, Vec<u8>>,
    referenced: Digest32,
    directory: OwnedDirectory,
}

impl Fixture {
    fn new() -> Self {
        let unique: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: OwnedDirectory = OwnedDirectory(std::env::temp_dir().join(format!(
            "business-snapshot-sqlite-{}-{unique}",
            std::process::id()
        )));
        fs::create_dir(&directory.0).unwrap();
        let namespace: SqliteNamespace = SqliteNamespace::new(
            ChainId::new("business-snapshot-sqlite").unwrap(),
            ValidatorId::new([0x62; 32]),
            AtomicityDomainId::new([0x63; 32]).unwrap(),
        );
        let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: SqliteDurableStore =
            SqliteDurableStore::open(directory.0.join("state.sqlite"), namespace.clone(), first)
                .unwrap();
        let blobs: SqliteBlobStore =
            SqliteBlobStore::open(directory.0.join("blobs.sqlite")).unwrap();
        let context: DurableOperationContext = operation(first);
        let mut blob_bytes: BTreeMap<Digest32, Vec<u8>> = BTreeMap::new();
        let mut referenced: Option<Digest32> = None;
        for id in 1..=2u8 {
            let object: Object = Object {
                id: ObjectId::new([id; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0x80 + id; 32])),
                type_hash: digest(
                    namespace.chain_id(),
                    HashPurpose::Object,
                    b"test-object-type",
                ),
                schema_version: 1,
                data: vec![
                    id;
                    if id == 1 {
                        node_core::MAX_INLINE_OBJECT_BODY_BYTES + 11
                    } else {
                        1
                    }
                ],
            };
            let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
            assert!(bytes.len() <= node_core::MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
            let object_digest: Digest32 = digest(namespace.chain_id(), HashPurpose::Object, &bytes);
            let provenance: DurableObjectProvenance =
                DurableObjectProvenance::new(namespace.chain_id().clone(), ProtocolVersion::new(1));
            let version: DurableObjectVersionRecord = if id == 1 {
                // A real content-addressed canonical object body, written before its reference.
                blobs.put_blob(object_digest, bytes.clone()).unwrap();
                blob_bytes.insert(object_digest, bytes);
                referenced = Some(object_digest);
                DurableObjectVersionRecord::from_blob_reference(
                    object.id,
                    DurableObjectVersion::FIRST,
                    object_digest,
                    object.schema_version,
                    provenance,
                    11,
                    object_digest,
                )
            } else {
                DurableObjectVersionRecord::from_inline_object(
                    object.clone(),
                    object_digest,
                    provenance,
                    12,
                )
                .unwrap()
            };
            let changes: DurableObjectChanges = DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    object.id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    object.id,
                    DurableObjectMutation::Create {
                        version,
                        owner_projection: DurableObjectOwnerProjection::from_owner(object.owner)
                            .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            )
            .unwrap();
            let state: Option<DurableStateTransaction> = (id == 1).then(|| {
                // State values are opaque to storage, but even the large test value
                // is a decodable canonical record rather than decoder-error bait.
                let large: Vec<u8> = receipt(
                    namespace.chain_id(),
                    0x21,
                    vec![0x31; MAX_PORTABLE_CHUNK_BYTES + 9],
                )
                .canonical_bytes()
                .to_vec();
                assert!(large.len() > MAX_PORTABLE_CHUNK_BYTES);
                NodeDedupRecord::decode(&large).unwrap();
                DurableStateTransaction::new(
                    namespace.domain(),
                    AtomicStateReadSet::new(
                        [
                            b"a-large".as_slice(),
                            b"b-empty".as_slice(),
                            b"c-deleted".as_slice(),
                        ]
                        .into_iter()
                        .map(|key| {
                            StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL).unwrap()
                        })
                        .collect(),
                    )
                    .unwrap(),
                    vec![
                        StateMutationEntry::new(b"a-large".to_vec(), StateMutation::Put(large))
                            .unwrap(),
                        StateMutationEntry::new(
                            b"b-empty".to_vec(),
                            StateMutation::Put(Vec::new()),
                        )
                        .unwrap(),
                        StateMutationEntry::new(b"c-deleted".to_vec(), StateMutation::Delete)
                            .unwrap(),
                    ],
                )
                .unwrap()
            });
            let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
                namespace.domain(),
                state,
                changes,
                receipt(namespace.chain_id(), id, vec![id]),
                None,
            )
            .unwrap();
            assert_eq!(
                store.commit_invocation(&context, invocation),
                DurableCommitOutcome::Committed
            );
        }
        let garbage: Vec<u8> = b"unreferenced immutable blob".to_vec();
        let garbage_digest: Digest32 = digest(namespace.chain_id(), HashPurpose::Object, &garbage);
        blobs.put_blob(garbage_digest, garbage.clone()).unwrap();
        blob_bytes.insert(garbage_digest, garbage);
        Self {
            store,
            blobs,
            namespace,
            blob_bytes,
            referenced: referenced.unwrap(),
            directory,
        }
    }
}

// Independent bounded point/page reads also work with a nonempty outbox.
// This records what the injector wrote, so refusal cannot conceal capture writes.
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    token: PortableSnapshotToken,
    rows: Vec<SourceSnapshotRecord>,
    blobs: BTreeMap<Digest32, Vec<u8>>,
    outbox: Result<(), PortableSnapshotError>,
}

fn observe(fixture: &Fixture) -> Observation {
    let context: DurableOperationContext = operation(fixture.store.writer_fence().unwrap());
    let domain: AtomicityDomainId = fixture.namespace.domain();
    let token: PortableSnapshotToken = fixture
        .store
        .begin_portable_snapshot(&context, domain)
        .unwrap();
    let mut rows: Vec<SourceSnapshotRecord> = Vec::new();
    for collection in COLLECTIONS {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let page: DurableRecordPage = fixture
                .store
                .scan_portable_keys(
                    &context,
                    domain,
                    &DurableRecordScan::new(collection, after, NonZeroUsize::new(2).unwrap())
                        .unwrap(),
                )
                .unwrap();
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = fixture
                    .store
                    .read_portable_descriptor(&context, domain, key)
                    .unwrap()
                    .unwrap();
                let value: Option<Vec<u8>> = descriptor.payload_length().map(|length| {
                    let mut value: Vec<u8> = Vec::new();
                    while value.len() < length {
                        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            value.len(),
                            NonZeroUsize::new(4096).unwrap(),
                        )
                        .unwrap();
                        let DurableRecordChunkOutcome::Chunk(chunk) = fixture
                            .store
                            .read_portable_chunk(&context, domain, &request)
                            .unwrap()
                        else {
                            panic!("quiet fixture row changed");
                        };
                        assert_eq!(chunk.bytes().len(), request.range().len());
                        value.extend_from_slice(chunk.bytes());
                    }
                    value
                });
                rows.push(SourceSnapshotRecord { descriptor, value });
                assert!(rows.len() <= 16, "this fixture has at most ten rows");
            }
            after = page.continuation().cloned();
            if after.is_none() {
                break;
            }
        }
    }
    let blobs: BTreeMap<Digest32, Vec<u8>> = fixture
        .blob_bytes
        .keys()
        .map(|digest| (*digest, fixture.blobs.get_blob(digest).unwrap().unwrap()))
        .collect();
    Observation {
        token: token.clone(),
        rows,
        blobs,
        outbox: fixture
            .store
            .check_portable_outbox_empty_at(&context, domain, &token),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Injection {
    None,
    TokenChange,
    Outbox,
    WriterFence,
}

struct ObservedSource<'a> {
    fixture: &'a Fixture,
    injection: Injection,
    injected: Cell<bool>,
    checks: Cell<usize>,
    pages: Cell<usize>,
    after_injection: RefCell<Option<Observation>>,
}

impl<'a> ObservedSource<'a> {
    fn new(fixture: &'a Fixture, injection: Injection) -> Self {
        Self {
            fixture,
            injection,
            injected: Cell::new(false),
            checks: Cell::new(0),
            pages: Cell::new(0),
            after_injection: RefCell::new(None),
        }
    }
    fn inject(&self) {
        assert!(!self.injected.replace(true));
        let fixture: &Fixture = self.fixture;
        let context: DurableOperationContext = operation(fixture.store.writer_fence().unwrap());
        match self.injection {
            Injection::None => panic!("no writer is configured"),
            Injection::TokenChange => {
                let key: Vec<u8> = b"b-empty".to_vec();
                let before: VersionedStateValue = fixture
                    .store
                    .get_versioned_durable(&context, fixture.namespace.domain(), &key)
                    .unwrap();
                let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
                    fixture.namespace.domain(),
                    AtomicStateReadSet::new(vec![
                        StateReadAssertion::new(key.clone(), before.revision()).unwrap(),
                    ])
                    .unwrap(),
                    AtomicStateMutationSet::new(vec![
                        StateMutationEntry::new(
                            key,
                            StateMutation::Put(
                                receipt(fixture.namespace.chain_id(), 0x23, vec![0x23])
                                    .canonical_bytes()
                                    .to_vec(),
                            ),
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    fixture.store.commit_durable(&context, transaction),
                    DurableCommitOutcome::Committed
                );
            }
            Injection::Outbox => {
                let receipt: DurableRequestReceipt =
                    receipt(fixture.namespace.chain_id(), 0x22, vec![0x22]);
                let message_bytes: Vec<u8> = receipt.canonical_bytes().to_vec();
                let message: DurableOutboxMessage = DurableOutboxMessage::new(
                    digest(
                        fixture.namespace.chain_id(),
                        HashPurpose::NodeEvent,
                        &message_bytes,
                    ),
                    message_bytes,
                )
                .unwrap();
                let outbox: DurableOutboxBatch = DurableOutboxBatch::new(
                    receipt.request_id(),
                    receipt.event_digest(),
                    vec![message],
                )
                .unwrap();
                let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
                    fixture.namespace.domain(),
                    None,
                    DurableObjectChanges::empty(),
                    receipt,
                    Some(outbox),
                )
                .unwrap();
                assert_eq!(
                    fixture.store.commit_invocation(&context, invocation),
                    DurableCommitOutcome::Committed
                );
            }
            Injection::WriterFence => {
                let next: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
                assert_eq!(
                    fixture
                        .store
                        .advance_writer_fence(context.writer_fence(), next)
                        .unwrap(),
                    next
                );
            }
        }
        self.after_injection.replace(Some(observe(fixture)));
    }
}

// Production capture may read, never call any durable or blob write seam.
impl DurableDomainStateStore for ObservedSource<'_> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.fixture
            .store
            .get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        _: &DurableOperationContext,
        _: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        panic!("capture attempted a state write");
    }
}
impl StructuredDurableDomainStateStore for ObservedSource<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.fixture.store.get_object_head(context, domain, id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.fixture
            .store
            .get_object_version(context, domain, id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.fixture.store.get_request_receipt(context, domain, id)
    }
    fn commit_invocation(
        &self,
        _: &DurableOperationContext,
        _: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        panic!("capture attempted an invocation write");
    }
}
impl DurablePortableRepository for ObservedSource<'_> {
    fn scan_portable_keys(
        &self,
        _: &DurableOperationContext,
        _: AtomicityDomainId,
        _: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        panic!("capture used an unguarded scan");
    }
    fn read_portable_descriptor(
        &self,
        _: &DurableOperationContext,
        _: AtomicityDomainId,
        _: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        panic!("capture used an unguarded descriptor");
    }
    fn read_portable_chunk(
        &self,
        _: &DurableOperationContext,
        _: AtomicityDomainId,
        _: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        panic!("capture used an unguarded chunk");
    }
}
impl DurablePortableSnapshotRepository for ObservedSource<'_> {
    fn begin_portable_snapshot(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.fixture.store.begin_portable_snapshot(context, domain)
    }
    fn scan_portable_keys_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        assert_eq!(scan.limit().get(), 1);
        self.pages.set(self.pages.get() + 1);
        self.fixture
            .store
            .scan_portable_keys_at(context, domain, token, scan)
    }
    fn read_portable_descriptor_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        if self.injection == Injection::WriterFence
            && !self.injected.get()
            && key.collection() == DurableCollection::ObjectVersions
        {
            self.inject();
        }
        self.fixture
            .store
            .read_portable_descriptor_at(context, domain, token, key)
    }
    fn read_portable_chunk_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        assert!(request.range().len() <= MAX_PORTABLE_CHUNK_BYTES);
        if self.injection == Injection::TokenChange && !self.injected.get() && request.offset() > 0
        {
            self.inject();
        }
        self.fixture
            .store
            .read_portable_chunk_at(context, domain, token, request)
    }
    fn check_portable_outbox_empty_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.checks.set(self.checks.get() + 1);
        if self.injection == Injection::Outbox && self.checks.get() == 2 {
            self.inject();
        }
        self.fixture
            .store
            .check_portable_outbox_empty_at(context, domain, token)
    }
}

struct ObservedBlobs<'a> {
    store: &'a SqliteBlobStore,
    chunks: Cell<usize>,
}
impl BlobStore for ObservedBlobs<'_> {
    fn put_blob(&self, _: Digest32, _: Vec<u8>) -> Result<(), RuntimeError> {
        panic!("capture attempted a blob write");
    }
    fn get_blob(&self, _: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        panic!("capture used an unbounded blob read");
    }
}
impl PortableBlobRepository for ObservedBlobs<'_> {
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<PortableBlobDescriptor>, RuntimeError> {
        self.store.read_portable_blob_descriptor(digest)
    }
    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError> {
        assert!(request.range().len() <= MAX_PORTABLE_CHUNK_BYTES);
        self.chunks.set(self.chunks.get() + 1);
        self.store.read_portable_blob_chunk(request)
    }
}

#[test]
fn production_capture_reads_all_four_sqlite_collections_and_exact_referenced_blob_closure() {
    let fixture: Fixture = Fixture::new();
    let before: Observation = observe(&fixture);
    let source: ObservedSource<'_> = ObservedSource::new(&fixture, Injection::None);
    let blobs: ObservedBlobs<'_> = ObservedBlobs {
        store: &fixture.blobs,
        chunks: Cell::new(0),
    };
    let snapshot: SourceBusinessSnapshot = capture_source_business_snapshot(
        &source,
        &blobs,
        &operation(before.token.writer_fence()),
        fixture.namespace.domain(),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    snapshot.validate().unwrap();
    assert_eq!(snapshot.token, before.token);
    assert_eq!(snapshot.records, before.rows);
    for (collection, count) in COLLECTIONS.into_iter().zip([3usize, 2, 2, 2]) {
        assert_eq!(
            snapshot
                .records
                .iter()
                .filter(|row| row.descriptor.key().collection() == collection)
                .count(),
            count
        );
    }
    assert_eq!(
        snapshot.referenced_blobs,
        BTreeMap::from([(
            fixture.referenced,
            fixture.blob_bytes[&fixture.referenced].clone()
        )])
    );
    assert_eq!(
        objects::decode_object(&snapshot.referenced_blobs[&fixture.referenced])
            .unwrap()
            .id,
        ObjectId::new([1; 32])
    );
    assert_eq!(
        digest(
            fixture.namespace.chain_id(),
            HashPurpose::Object,
            &snapshot.referenced_blobs[&fixture.referenced]
        ),
        fixture.referenced
    );
    assert!(source.pages.get() >= snapshot.records.len());
    assert_eq!(source.checks.get(), 2);
    assert_eq!(blobs.chunks.get(), 1);
    assert_eq!(
        observe(&fixture),
        before,
        "production capture never changes rows, blobs, fence or token"
    );

    let empty: SqliteBlobStore =
        SqliteBlobStore::open(fixture.directory.0.join("missing-blobs.sqlite")).unwrap();
    let error = capture_source_business_snapshot(
        &source,
        &empty,
        &operation(before.token.writer_fence()),
        fixture.namespace.domain(),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("referenced blob is missing"));
    assert_eq!(
        observe(&fixture),
        before,
        "missing closure is refusal, not source repair"
    );
}

#[test]
fn production_capture_refuses_mid_capture_token_outbox_and_writer_fence_changes() {
    for injection in [
        Injection::TokenChange,
        Injection::Outbox,
        Injection::WriterFence,
    ] {
        let fixture: Fixture = Fixture::new();
        let before: Observation = observe(&fixture);
        let source: ObservedSource<'_> = ObservedSource::new(&fixture, injection);
        let error = capture_source_business_snapshot(
            &source,
            &fixture.blobs,
            &operation(before.token.writer_fence()),
            fixture.namespace.domain(),
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap_err();
        assert!(
            source.injected.get(),
            "{injection:?} must really occur after capture begins"
        );
        let refusal: &PortableSnapshotError = error
            .downcast_ref::<PortableSnapshotError>()
            .expect("real SQLite guarded-read refusal, not a decoding failure");
        match injection {
            Injection::TokenChange | Injection::Outbox => {
                assert_eq!(refusal, &PortableSnapshotError::Changed)
            }
            Injection::WriterFence => assert_eq!(
                refusal,
                &PortableSnapshotError::Read(DurableReadError::WriterFenced {
                    active_generation: WriterFenceGeneration::new(2).unwrap()
                })
            ),
            Injection::None => unreachable!(),
        }
        assert_ne!(source.after_injection.borrow().as_ref().unwrap(), &before);
        assert_eq!(
            &observe(&fixture),
            source.after_injection.borrow().as_ref().unwrap(),
            "capture may not add a write after the deliberately injected {injection:?}"
        );
        if injection == Injection::Outbox {
            let error = capture_source_business_snapshot(
                &fixture.store,
                &fixture.blobs,
                &operation(fixture.store.writer_fence().unwrap()),
                fixture.namespace.domain(),
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<PortableSnapshotError>(),
                Some(&PortableSnapshotError::NonemptyOutbox)
            );
            assert_eq!(
                &observe(&fixture),
                source.after_injection.borrow().as_ref().unwrap()
            );
        }
    }
}
