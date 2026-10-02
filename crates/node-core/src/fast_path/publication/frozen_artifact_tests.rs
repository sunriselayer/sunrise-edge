//! Frontier-only bounded artifact reads; ordinary retention remains unchanged.

use super::*;
use crate::fast_path::tests::{RetentionReplica, logical_replica, transfer_bundle_bytes};
use crate::ordered_economics::{
    AdmissionClosureRecord, FrozenFrontierStep, advance_frozen_frontier,
    encode_admission_closure_record, read_frozen_frontier_page,
};
use crate::paid_execution::tests::{
    FIRST_PAID_NONCE, context, domain, memory_store, protocol, resolver,
};
use protocol_types::HashPurpose;
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};
use runtime::portable::{DurableRecordPage, DurableRecordScan};
use runtime::{
    DurableDomainStateStore, DurableInvocationTransaction, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableRequestId, DurableRequestReceipt, MemoryDurableStateStore,
};
use std::cell::{Cell, RefCell};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    MissingDescriptor,
    Tombstone,
    WrongKey,
    WrongCollection,
    WrongLength,
    WrongRevision,
    MalformedMetadata,
    ChangedAtSecondChunk,
    WrongChunkRequest,
    ZeroProgress,
    ShortChunk,
    ExtraChunk,
}

/// Any whole-value artifact read fails, including one accidentally introduced
/// in future frontier validation. All successful bodies must use real portable
/// descriptors and real range reads, not an emulated whole-value fallback.
struct ArtifactReadStore<'a> {
    inner: &'a MemoryDurableStateStore,
    artifact_prefix: Vec<u8>,
    fault: Fault,
    whole_artifact_reads: Cell<usize>,
    descriptor_reads: Cell<usize>,
    chunk_requests: RefCell<Vec<DurableRecordChunkRequest>>,
    commits: Cell<usize>,
}

impl<'a> ArtifactReadStore<'a> {
    fn new(inner: &'a MemoryDurableStateStore, fault: Fault) -> Self {
        let mut artifact_prefix: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
        artifact_prefix.extend_from_slice(b"publication-artifact/");
        Self {
            inner,
            artifact_prefix,
            fault,
            whole_artifact_reads: Cell::new(0),
            descriptor_reads: Cell::new(0),
            chunk_requests: RefCell::new(Vec::new()),
            commits: Cell::new(0),
        }
    }

    fn artifact(&self, key: &DurableRecordKey) -> bool {
        matches!(key, DurableRecordKey::State(bytes) if bytes.starts_with(&self.artifact_prefix))
    }
}

impl DurableDomainStateStore for ArtifactReadStore<'_> {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        if key.starts_with(&self.artifact_prefix) {
            self.whole_artifact_reads
                .set(self.whole_artifact_reads.get().checked_add(1).unwrap());
            return Err(DurableReadError::InvalidPersistedState);
        }
        self.inner.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.commits.set(self.commits.get().checked_add(1).unwrap());
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for ArtifactReadStore<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.commits.set(self.commits.get().checked_add(1).unwrap());
        self.inner.commit_invocation(context, transaction)
    }
}

impl StructuredOutboxExclusionGuard for ArtifactReadStore<'_> {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        self.inner.inspect_outbox_exclusion(context, domain)
    }
}

impl DurablePortableRepository for ArtifactReadStore<'_> {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner.scan_portable_keys(context, domain, scan)
    }

    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        if !self.artifact(key) {
            return self.inner.read_portable_descriptor(context, domain, key);
        }
        self.descriptor_reads
            .set(self.descriptor_reads.get().checked_add(1).unwrap());
        if self.fault == Fault::MissingDescriptor {
            return Ok(None);
        }
        if self.fault == Fault::MalformedMetadata {
            return Err(DurableReadError::InvalidPersistedState);
        }
        let original: DurableRecordDescriptor = self
            .inner
            .read_portable_descriptor(context, domain, key)?
            .unwrap();
        let (revision, length): (StateRevision, usize) = match original.metadata() {
            DurableRecordMetadata::State {
                revision,
                value_length: Some(length),
            } => (*revision, *length),
            _ => panic!("test setup must contain a present artifact"),
        };
        let mut changed_key: DurableRecordKey = key.clone();
        let changed_metadata: DurableRecordMetadata = match self.fault {
            Fault::Tombstone => DurableRecordMetadata::State {
                revision,
                value_length: None,
            },
            Fault::WrongKey => {
                let DurableRecordKey::State(bytes) = &mut changed_key else {
                    panic!("test artifact key must be State")
                };
                bytes.push(0xFF);
                original.metadata().clone()
            }
            Fault::WrongCollection => {
                changed_key = DurableRecordKey::Receipt(DurableRequestId::new([0xCA; 32]).unwrap());
                DurableRecordMetadata::Receipt {
                    event_digest: resolver()
                        .hash_for_purpose(
                            protocol().epoch(),
                            HashPurpose::ExecutionEffects,
                            b"receipt",
                        )
                        .unwrap(),
                    length: NonZeroUsize::new(1).unwrap(),
                }
            }
            Fault::WrongLength => DurableRecordMetadata::State {
                revision,
                value_length: Some(length.checked_add(1).unwrap()),
            },
            Fault::WrongRevision => DurableRecordMetadata::State {
                revision: revision.checked_next().unwrap(),
                value_length: Some(length),
            },
            _ => return Ok(Some(original)),
        };
        Ok(Some(
            DurableRecordDescriptor::new(changed_key, changed_metadata).unwrap(),
        ))
    }

    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        if !self.artifact(request.descriptor().key()) {
            return self.inner.read_portable_chunk(context, domain, request);
        }
        self.chunk_requests.borrow_mut().push(request.clone());
        let call: usize = self.chunk_requests.borrow().len();
        if self.fault == Fault::ChangedAtSecondChunk && call == 2 {
            return Ok(DurableRecordChunkOutcome::Changed);
        }
        let chunk: Box<DurableRecordChunk> =
            match self.inner.read_portable_chunk(context, domain, request)? {
                DurableRecordChunkOutcome::Chunk(chunk) => chunk,
                changed @ DurableRecordChunkOutcome::Changed => return Ok(changed),
            };
        let mut bytes: Vec<u8> = chunk.bytes().to_vec();
        let mut response_request: DurableRecordChunkRequest = request.clone();
        match self.fault {
            Fault::WrongChunkRequest => {
                response_request = DurableRecordChunkRequest::new(
                    request.descriptor().clone(),
                    request.offset(),
                    NonZeroUsize::new(1).unwrap(),
                )
                .unwrap();
                bytes.truncate(response_request.range().len());
            }
            Fault::ZeroProgress => {
                let revision: StateRevision = match request.descriptor().metadata() {
                    DurableRecordMetadata::State { revision, .. } => *revision,
                    _ => panic!("test artifact metadata must be State"),
                };
                let empty: DurableRecordDescriptor = DurableRecordDescriptor::new(
                    request.descriptor().key().clone(),
                    DurableRecordMetadata::State {
                        revision,
                        value_length: Some(0),
                    },
                )
                .unwrap();
                response_request =
                    DurableRecordChunkRequest::new(empty, 0, NonZeroUsize::new(1).unwrap())
                        .unwrap();
                bytes.clear();
            }
            Fault::ShortChunk => {
                bytes.pop();
            }
            Fault::ExtraChunk => bytes.push(0xFF),
            _ => return Ok(DurableRecordChunkOutcome::Chunk(chunk)),
        }
        DurableRecordChunk::new(response_request, bytes)
            .map(|altered| DurableRecordChunkOutcome::Chunk(Box::new(altered)))
            .map_err(DurableReadError::InvalidRequest)
    }
}

fn artifact_entry(content: &[u8]) -> ArtifactEntry {
    ArtifactEntry {
        kind: ArtifactKind::StateValue,
        identity: b"chunk-regression-state-value".to_vec(),
        content_digest: resolver()
            .hash_for_purpose(protocol().epoch(), HashPurpose::ExecutionEffects, content)
            .unwrap(),
        content_length: u32::try_from(content.len()).unwrap(),
    }
}

fn install_artifact(store: &MemoryDurableStateStore, entry: &ArtifactEntry, bytes: &[u8]) {
    let key: Vec<u8> = artifact_key(protocol().chain_id(), &[0xC1; 32], entry).unwrap();
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(bytes.to_vec())).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn descriptors(
    store: &ArtifactReadStore<'_>,
    manifest: &ArtifactManifest,
) -> RetentionResult<Vec<DurableRecordDescriptor>> {
    frozen_artifact_descriptors(
        store,
        &context(),
        domain(),
        protocol().chain_id(),
        &[0xC1; 32],
        manifest,
    )
}

fn install_closure(replica: &RetentionReplica) {
    let closure: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0xC2; 32],
        closed_at_block_height: 4,
    };
    let key: Vec<u8> = crate::ordered_economics::engine::admission_closure_key_for_tests(
        protocol().chain_id(),
        protocol().epoch(),
    );
    replica.put_row(key, encode_admission_closure_record(&closure).unwrap());
}

#[test]
fn a_real_certified_frontier_advance_and_page_never_read_whole_artifacts() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _): (PublicationBundle, _) = transfer_bundle_bytes(0xC3, FIRST_PAID_NONCE);
    let ack: AvailabilityVote = retain_publication(
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
    install_closure(&replica);
    let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&replica.store, Fault::None);
    let step = || {
        advance_frozen_frontier(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &replica.signer,
        )
        .unwrap()
    };
    assert_eq!(step(), FrozenFrontierStep::Advanced { entry_count: 1 });
    let final_vote: Box<consensus::FrozenFrontierVote> = match step() {
        FrozenFrontierStep::Finalized(vote) => vote,
        _ => panic!("one complete retained publication must finalize"),
    };
    let (vote, page): (consensus::FrozenFrontierVote, consensus::FrozenFrontierPage) =
        read_frozen_frontier_page(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            replica.signer.validator_id(),
            None,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
    assert_eq!(vote, *final_vote);
    assert_eq!(page.entries, vec![ack.identity.clone()]);
    assert!(page.terminal);
    consensus::verify_frozen_frontier(&resolver(), &vote.identity, &[ack.identity]).unwrap();
    assert!(store.descriptor_reads.get() >= bundle.manifest.entries.len().checked_mul(2).unwrap());
    assert!(!store.chunk_requests.borrow().is_empty());
    assert_eq!(store.whole_artifact_reads.get(), 0);
    for request in store.chunk_requests.borrow().iter() {
        assert!(request.range().len() <= MAX_PORTABLE_CHUNK_BYTES);
    }
}

#[test]
fn a_legal_large_artifact_is_read_in_exact_descriptor_pinned_chunks() {
    let inner: MemoryDurableStateStore = memory_store();
    let length: usize = MAX_PORTABLE_CHUNK_BYTES.checked_add(17).unwrap();
    let bytes: Vec<u8> = (0..length)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![artifact_entry(&bytes)],
    };
    install_artifact(&inner, &manifest.entries[0], &bytes);
    let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&inner, Fault::None);
    let resolved: Vec<DurableRecordDescriptor> = descriptors(&store, &manifest).unwrap();
    let reconstructed: Vec<u8> =
        read_frozen_artifact(&store, &context(), domain(), &resolved[0]).unwrap();
    assert_eq!(reconstructed, bytes);
    assert_eq!(store.whole_artifact_reads.get(), 0);
    assert_eq!(store.commits.get(), 0);
    let requests = store.chunk_requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].range(), 0..MAX_PORTABLE_CHUNK_BYTES);
    assert_eq!(requests[1].range(), MAX_PORTABLE_CHUNK_BYTES..length);
    for request in requests.iter() {
        assert_eq!(request.descriptor(), &resolved[0]);
        assert!(request.range().len() <= MAX_PORTABLE_CHUNK_BYTES);
    }
}

#[test]
fn declared_empty_content_requires_one_exact_terminal_empty_read() {
    let inner: MemoryDurableStateStore = memory_store();
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![artifact_entry(&[])],
    };
    install_artifact(&inner, &manifest.entries[0], &[]);
    let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&inner, Fault::None);
    let resolved: Vec<DurableRecordDescriptor> = descriptors(&store, &manifest).unwrap();
    assert!(
        read_frozen_artifact(&store, &context(), domain(), &resolved[0])
            .unwrap()
            .is_empty()
    );
    let requests = store.chunk_requests.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].range(), 0..0);
    assert_eq!(requests[0].descriptor(), &resolved[0]);
    assert_eq!(store.whole_artifact_reads.get(), 0);
}

#[test]
fn malformed_or_missing_artifact_metadata_cannot_allocate_or_read_bodies() {
    let inner: MemoryDurableStateStore = memory_store();
    let bytes: Vec<u8> = vec![0xCC; 32];
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![artifact_entry(&bytes)],
    };
    install_artifact(&inner, &manifest.entries[0], &bytes);
    for fault in [
        Fault::MissingDescriptor,
        Fault::Tombstone,
        Fault::WrongKey,
        Fault::WrongCollection,
        Fault::WrongLength,
        Fault::MalformedMetadata,
    ] {
        let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&inner, fault);
        assert!(
            descriptors(&store, &manifest).is_err(),
            "accepted {fault:?}"
        );
        assert!(store.chunk_requests.borrow().is_empty());
        assert_eq!(store.whole_artifact_reads.get(), 0);
        assert_eq!(store.commits.get(), 0);
    }
}

#[test]
fn changed_revisions_and_mismatched_or_zero_short_extra_chunks_fail_closed() {
    let inner: MemoryDurableStateStore = memory_store();
    let length: usize = MAX_PORTABLE_CHUNK_BYTES.checked_add(17).unwrap();
    let bytes: Vec<u8> = vec![0xCD; length];
    let manifest: ArtifactManifest = ArtifactManifest {
        entries: vec![artifact_entry(&bytes)],
    };
    install_artifact(&inner, &manifest.entries[0], &bytes);
    for fault in [
        Fault::WrongRevision,
        Fault::ChangedAtSecondChunk,
        Fault::WrongChunkRequest,
        Fault::ZeroProgress,
        Fault::ShortChunk,
        Fault::ExtraChunk,
    ] {
        let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&inner, fault);
        let resolved: Vec<DurableRecordDescriptor> = descriptors(&store, &manifest).unwrap();
        assert!(
            read_frozen_artifact(&store, &context(), domain(), &resolved[0]).is_err(),
            "accepted {fault:?}"
        );
        if fault == Fault::ChangedAtSecondChunk {
            assert_eq!(store.chunk_requests.borrow().len(), 2);
        }
        assert_eq!(store.whole_artifact_reads.get(), 0);
        assert_eq!(store.commits.get(), 0);
    }
}

#[test]
fn artifact_count_and_complete_declared_budget_are_rejected_before_storage_reads() {
    let inner: MemoryDurableStateStore = memory_store();
    let entry: ArtifactEntry = artifact_entry(b"small");
    let over_count: ArtifactManifest = ArtifactManifest {
        entries: vec![entry.clone(); MAX_RETAINED_ARTIFACTS.checked_add(1).unwrap()],
    };
    let mut maximum: ArtifactEntry = entry;
    maximum.content_length = u32::try_from(MAX_ENCODED_BUNDLE_BYTES).unwrap();
    let mut extra: ArtifactEntry = maximum.clone();
    extra.content_length = 1;
    extra.identity.push(1);
    let over_budget: ArtifactManifest = ArtifactManifest {
        entries: vec![maximum, extra],
    };
    for manifest in [over_count, over_budget] {
        let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&inner, Fault::None);
        assert!(descriptors(&store, &manifest).is_err());
        assert_eq!(store.descriptor_reads.get(), 0);
        assert!(store.chunk_requests.borrow().is_empty());
        assert_eq!(store.whole_artifact_reads.get(), 0);
    }
}

#[test]
fn descriptor_or_chunk_faults_cannot_advance_or_sign_a_real_frontier() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _): (PublicationBundle, _) = transfer_bundle_bytes(0xC4, FIRST_PAID_NONCE);
    retain_publication(
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
    install_closure(&replica);
    for fault in [
        Fault::MissingDescriptor,
        Fault::Tombstone,
        Fault::WrongKey,
        Fault::WrongCollection,
        Fault::WrongLength,
        Fault::WrongRevision,
        Fault::MalformedMetadata,
        Fault::WrongChunkRequest,
        Fault::ZeroProgress,
        Fault::ShortChunk,
        Fault::ExtraChunk,
    ] {
        let store: ArtifactReadStore<'_> = ArtifactReadStore::new(&replica.store, fault);
        assert!(
            advance_frozen_frontier(
                &store,
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &replica.signer,
            )
            .is_err(),
            "advanced with {fault:?}"
        );
        assert_eq!(store.commits.get(), 0, "persisted progress with {fault:?}");
        assert_eq!(store.whole_artifact_reads.get(), 0);
    }
}
