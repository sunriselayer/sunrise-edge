//! Counts calls at the actual runtime boundaries used by the production router.
#![allow(dead_code)]
use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
};
use objects::ObjectId;
use protocol_types::{AtomicityDomainId, Digest32};
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};
use runtime::portable::{
    DurablePortableRepository, DurableRecordChunkOutcome, DurableRecordChunkRequest,
    DurableRecordDescriptor, DurableRecordKey, DurableRecordPage, DurableRecordScan,
};
use runtime::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
pub struct IoCounters {
    pub identities: Arc<AtomicUsize>,
    pub clock: Arc<AtomicUsize>,
    pub reads: Arc<AtomicUsize>,
    pub writes: Arc<AtomicUsize>,
    pub blobs: Arc<AtomicUsize>,
}
impl IoCounters {
    pub fn reset(&self) {
        for counter in [
            &self.identities,
            &self.clock,
            &self.reads,
            &self.writes,
            &self.blobs,
        ] {
            counter.store(0, Ordering::SeqCst);
        }
    }
    pub fn snapshot(&self) -> [usize; 5] {
        [
            &self.identities,
            &self.clock,
            &self.reads,
            &self.writes,
            &self.blobs,
        ]
        .map(|counter| counter.load(Ordering::SeqCst))
    }
}

pub struct Observed<T> {
    pub inner: Arc<T>,
    pub counters: IoCounters,
}
impl<T> Observed<T> {
    pub fn new(inner: Arc<T>, counters: &IoCounters) -> Self {
        Self {
            inner,
            counters: counters.clone(),
        }
    }
    fn read(&self) {
        self.counters.reads.fetch_add(1, Ordering::SeqCst);
    }
    fn write(&self) {
        self.counters.writes.fetch_add(1, Ordering::SeqCst);
    }
}
impl<T: Clock> Clock for Observed<T> {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        self.counters.clock.fetch_add(1, Ordering::SeqCst);
        self.inner.now_unix_millis()
    }
}
impl<T: IndexedOutboxIdentitySource> IndexedOutboxIdentitySource for Observed<T> {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        self.counters.identities.fetch_add(1, Ordering::SeqCst);
        self.inner.next_attempt_identity()
    }
}
impl<T: BlobStore> BlobStore for Observed<T> {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.counters.blobs.fetch_add(1, Ordering::SeqCst);
        self.inner.put_blob(digest, bytes)
    }
    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.counters.blobs.fetch_add(1, Ordering::SeqCst);
        self.inner.get_blob(digest)
    }
}
impl<T: DurableDomainStateStore> DurableDomainStateStore for Observed<T> {
    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.read();
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.read();
        self.inner.get_namespace_lifecycle(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.read();
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.write();
        self.inner.commit_durable(context, transaction)
    }
}
impl<T: StructuredDurableDomainStateStore> StructuredDurableDomainStateStore for Observed<T> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.read();
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.read();
        self.inner
            .get_object_version(context, domain, object_id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.read();
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.write();
        self.inner.commit_invocation(context, transaction)
    }
}
impl<T: DurablePortableRepository> DurablePortableRepository for Observed<T> {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.read();
        self.inner.scan_portable_keys(context, domain, scan)
    }
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.read();
        self.inner.read_portable_descriptor(context, domain, key)
    }
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.read();
        self.inner.read_portable_chunk(context, domain, request)
    }
}
impl<T: StructuredOutboxExclusionGuard> StructuredOutboxExclusionGuard for Observed<T> {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        self.read();
        self.inner.inspect_outbox_exclusion(context, domain)
    }
}
impl<T: IndexedOutboxRepository> IndexedOutboxRepository for Observed<T> {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.write();
        self.inner.claim_request_outbox(context, request)
    }
    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.write();
        self.inner.claim_due_outbox(context, request)
    }
    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        self.write();
        self.inner.acknowledge_outbox(context, acknowledgement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::portable::DurableCollection;
    use std::num::NonZeroUsize;

    fn fixture() -> (
        Observed<MemoryDurableStateStore>,
        DurableOperationContext,
        AtomicityDomainId,
        DurableRecordKey,
    ) {
        let domain: AtomicityDomainId = AtomicityDomainId::new([0x42; 32]).unwrap();
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
        let context: DurableOperationContext = DurableOperationContext::new(
            fence,
            StorageDeadline::new(10_000).unwrap(),
            StorageCorrelationId::new([0x43; 16]).unwrap(),
        );
        let inner: Arc<MemoryDurableStateStore> =
            Arc::new(MemoryDurableStateStore::new_bound(domain, fence));
        let key: Vec<u8> = b"observed-portable-fixture".to_vec();
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key.clone(), StateMutation::Put(b"body".to_vec())).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            inner.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );
        (
            Observed::new(inner, &IoCounters::default()),
            context,
            domain,
            DurableRecordKey::State(key),
        )
    }

    #[test]
    fn portable_and_outbox_operations_delegate_and_count_one_read_each() {
        let (observed, context, domain, key) = fixture();
        let scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            None,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        let page: DurableRecordPage = observed
            .scan_portable_keys(&context, domain, &scan)
            .unwrap();
        assert_eq!(page.keys(), std::slice::from_ref(&key));
        let descriptor: DurableRecordDescriptor = observed
            .read_portable_descriptor(&context, domain, &key)
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.key(), &key);
        assert_eq!(descriptor.payload_length(), Some(4));
        let request: DurableRecordChunkRequest =
            DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(2).unwrap()).unwrap();
        let DurableRecordChunkOutcome::Chunk(chunk) = observed
            .read_portable_chunk(&context, domain, &request)
            .unwrap()
        else {
            panic!("unchanged fixture descriptor must yield a chunk")
        };
        assert_eq!(chunk.request(), &request);
        assert_eq!(chunk.bytes(), b"bo");
        assert!(!chunk.is_last());
        let inventory: StructuredOutboxInventory =
            observed.inspect_outbox_exclusion(&context, domain).unwrap();
        assert_eq!(
            inventory,
            observed
                .inner
                .inspect_outbox_exclusion(&context, domain)
                .unwrap()
        );
        assert!(!inventory.blocks_exclusion());
        assert_eq!(observed.counters.snapshot(), [0, 0, 4, 0, 0]);
    }

    #[test]
    fn rejected_portable_and_outbox_reads_preserve_backend_fence_and_domain_errors() {
        let (observed, context, domain, key) = fixture();
        let descriptor: DurableRecordDescriptor = observed
            .inner
            .read_portable_descriptor(&context, domain, &key)
            .unwrap()
            .unwrap();
        let request: DurableRecordChunkRequest =
            DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(2).unwrap()).unwrap();
        let scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            None,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        let fenced: DurableOperationContext = DurableOperationContext::new(
            WriterFenceGeneration::new(2).unwrap(),
            context.deadline(),
            context.correlation_id(),
        );
        let foreign: AtomicityDomainId = AtomicityDomainId::new([0x44; 32]).unwrap();
        for (authority, requested_domain) in [(fenced, domain), (context, foreign)] {
            assert_eq!(
                observed
                    .scan_portable_keys(&authority, requested_domain, &scan)
                    .unwrap_err(),
                observed
                    .inner
                    .scan_portable_keys(&authority, requested_domain, &scan)
                    .unwrap_err(),
            );
            assert_eq!(
                observed
                    .read_portable_descriptor(&authority, requested_domain, &key)
                    .unwrap_err(),
                observed
                    .inner
                    .read_portable_descriptor(&authority, requested_domain, &key)
                    .unwrap_err(),
            );
            assert_eq!(
                observed
                    .read_portable_chunk(&authority, requested_domain, &request)
                    .unwrap_err(),
                observed
                    .inner
                    .read_portable_chunk(&authority, requested_domain, &request)
                    .unwrap_err(),
            );
            assert_eq!(
                observed
                    .inspect_outbox_exclusion(&authority, requested_domain)
                    .unwrap_err(),
                observed
                    .inner
                    .inspect_outbox_exclusion(&authority, requested_domain)
                    .unwrap_err(),
            );
        }
        assert_eq!(observed.counters.snapshot(), [0, 0, 8, 0, 0]);
    }

    #[test]
    fn changed_descriptor_outcome_is_forwarded_and_counted_as_a_read() {
        let (observed, context, domain, key) = fixture();
        let descriptor: DurableRecordDescriptor = observed
            .inner
            .read_portable_descriptor(&context, domain, &key)
            .unwrap()
            .unwrap();
        let revision: StateRevision = match descriptor.metadata() {
            runtime::portable::DurableRecordMetadata::State { revision, .. } => *revision,
            _ => panic!("fixture descriptor must be State"),
        };
        let DurableRecordKey::State(state_key) = &key else {
            panic!("fixture key must be State")
        };
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(state_key.clone(), revision).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(state_key.clone(), StateMutation::Put(b"edit".to_vec()))
                    .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            observed.inner.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );
        let request: DurableRecordChunkRequest =
            DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(2).unwrap()).unwrap();
        assert_eq!(
            observed
                .read_portable_chunk(&context, domain, &request)
                .unwrap(),
            DurableRecordChunkOutcome::Changed,
        );
        assert_eq!(observed.counters.snapshot(), [0, 0, 1, 0, 0]);
    }
}
