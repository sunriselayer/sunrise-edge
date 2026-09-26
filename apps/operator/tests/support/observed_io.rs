//! Counts calls at the actual runtime boundaries used by the production router.
#![allow(dead_code)]
use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
};
use objects::ObjectId;
use protocol_types::{AtomicityDomainId, Digest32};
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
