//! Same-owning-memory-store forwarding and counted faults at the real Seal
//! retention/completion ports. Every race writes through the ordinary fenced
//! CAS port before the challenged Seal transaction, never through raw state.
use super::*;
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableBlobChunk, PortableBlobChunkOutcome, PortableBlobChunkRequest,
    PortableBlobDescriptor, PortableBlobRepository, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    DurableInvocationTransaction, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableReadError, NamespaceLifecycle, OutgoingBarrier,
    OutgoingSealRepository, RuntimeError, SealBarrier, StructuredDurableDomainStateStore,
    VersionedStateValue,
};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealRace {
    RetentionSequence,
    RetentionInventory,
    CompletionSequence,
    CompletionInventory,
}

pub(super) const PHANTOM_KEY: &[u8] = b"test/seal-phantom-inventory";
pub(super) const PHANTOM_VALUE: &[u8] = b"a concurrent ordinary writer inserted this row";

pub(super) struct SealFaultStore<'a> {
    pub(super) inner: &'a MemoryDurableStateStore,
    blobs: &'a MemoryBlobStore,
    domain: AtomicityDomainId,
    request: [u8; 32],
    capability: bool,
    race: Option<SealRace>,
    barrier_completion: Option<(
        usize,
        &'a OrderedEconomicsEnvironment<'a>,
        &'a consensus::QuorumCertificate,
    )>,
    pub(super) getter_calls: Cell<usize>,
    pub(super) retention_calls: Cell<usize>,
    pub(super) completion_calls: Cell<usize>,
    pub(super) race_calls: Cell<usize>,
    pub(super) barrier_calls: Cell<usize>,
    pub(super) barrier_completion_calls: Cell<usize>,
    pub(super) after_race: RefCell<Option<SourceBusinessSnapshot>>,
    pub(super) after_seal_completion: RefCell<Option<SourceBusinessSnapshot>>,
    pub(super) after_barrier_completion: RefCell<Option<SourceBusinessSnapshot>>,
}

impl<'a> SealFaultStore<'a> {
    pub(super) fn new(
        network: &'a Network,
        replica: usize,
        request: [u8; 32],
        capability: bool,
        race: Option<SealRace>,
    ) -> Self {
        Self {
            inner: &network.stores[replica],
            blobs: &network.blobs,
            domain: network.domain(),
            request,
            capability,
            race,
            barrier_completion: None,
            getter_calls: Cell::new(0),
            retention_calls: Cell::new(0),
            completion_calls: Cell::new(0),
            race_calls: Cell::new(0),
            barrier_calls: Cell::new(0),
            barrier_completion_calls: Cell::new(0),
            after_race: RefCell::new(None),
            after_seal_completion: RefCell::new(None),
            after_barrier_completion: RefCell::new(None),
        }
    }

    pub(super) fn complete_seal_after_barrier_observation(
        &mut self,
        read_number: usize,
        env: &'a OrderedEconomicsEnvironment<'a>,
        certificate: &'a consensus::QuorumCertificate,
    ) {
        self.barrier_completion = Some((read_number, env, certificate));
    }

    fn apply_race(&self, context: &DurableOperationContext, completion: bool) {
        let Some(race) = self.race else {
            return;
        };
        let at_completion: bool = matches!(
            race,
            SealRace::CompletionSequence | SealRace::CompletionInventory
        );
        if at_completion != completion {
            return;
        }
        assert_eq!(
            self.race_calls.get(),
            0,
            "the planned fault is consumed once"
        );
        let inventory: bool = matches!(
            race,
            SealRace::RetentionInventory | SealRace::CompletionInventory
        );
        let key: Vec<u8> = if inventory {
            PHANTOM_KEY.to_vec()
        } else {
            engine::ordered_vote_record_key_for_tests(&fixture::chain(), 2)
        };
        let observed: VersionedStateValue = self
            .inner
            .get_versioned_durable(context, self.domain, &key)
            .unwrap();
        let value: Vec<u8> = if inventory {
            assert_eq!(observed.revision(), StateRevision::INITIAL);
            assert!(observed.value().is_none());
            PHANTOM_VALUE.to_vec()
        } else {
            // The exact real retained vote is rewritten byte-identically by a
            // concurrent ordinary writer. It changes sequence/revision only;
            // it is not in the Seal transaction's ordinary deciding read set.
            observed.value().unwrap().to_vec()
        };
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            self.domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(value)).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            self.inner.commit_durable(context, transaction),
            DurableCommitOutcome::Committed
        );
        self.race_calls.set(1);
        let expected: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
            self.inner,
            self.blobs,
            context,
            self.domain,
        );
        *self.after_race.borrow_mut() = Some(expected);
    }
}

impl DurableDomainStateStore for SealFaultStore<'_> {
    fn get_namespace_lifecycle(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(c, d)
    }
    fn get_outgoing_barrier(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        let observed: OutgoingBarrier = self.inner.get_outgoing_barrier(c, d)?;
        let count: usize = self.barrier_calls.get().checked_add(1).unwrap();
        self.barrier_calls.set(count);
        if let Some((read_number, env, certificate)) = self.barrier_completion
            && count == read_number
        {
            assert!(!observed.is_sealed());
            assert_eq!(self.barrier_completion_calls.get(), 0);
            // A concurrent, otherwise ordinary core invocation consumes
            // the real QC and completes the original Seal in this exact
            // store after this read's Unsealed observation. The caller
            // must freshly guard a retained response before exposing it.
            let completed: OrderedEventOutput =
                process_certificate(self.inner, c, env, certificate).unwrap();
            assert_eq!(completed.committed.len(), 1);
            assert_eq!(completed.committed[0].request_id, self.request);
            assert!(self.inner.get_outgoing_barrier(c, d)?.is_sealed());
            self.barrier_completion_calls.set(1);
            *self.after_barrier_completion.borrow_mut() = Some(
                crate::test_support::capture::captured_source(self.inner, self.blobs, c, d),
            );
        }
        Ok(observed)
    }
    fn get_versioned_durable(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        k: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(c, d, k)
    }
    fn commit_durable(
        &self,
        c: &DurableOperationContext,
        tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(c, tx)
    }
}

impl StructuredDurableDomainStateStore for SealFaultStore<'_> {
    fn get_object_head(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(c, d, o)
    }
    fn get_object_version(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: ObjectId,
        v: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner.get_object_version(c, d, o, v)
    }
    fn get_request_receipt(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        r: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(c, d, r)
    }
    fn commit_invocation(
        &self,
        c: &DurableOperationContext,
        tx: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(c, tx)
    }
    fn outgoing_seal_repository(&self) -> Option<&dyn OutgoingSealRepository> {
        self.getter_calls
            .set(self.getter_calls.get().checked_add(1).unwrap());
        if self.capability { Some(self) } else { None }
    }
}

impl DurablePortableRepository for SealFaultStore<'_> {
    fn scan_portable_keys(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner.scan_portable_keys(c, d, scan)
    }
    fn read_portable_descriptor(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        k: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.inner.read_portable_descriptor(c, d, k)
    }
    fn read_portable_chunk(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        r: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.inner.read_portable_chunk(c, d, r)
    }
}

impl DurablePortableSnapshotRepository for SealFaultStore<'_> {
    fn begin_portable_snapshot(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.inner.begin_portable_snapshot(c, d)
    }
    fn scan_portable_keys_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        s: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.inner.scan_portable_keys_at(c, d, t, s)
    }
    fn read_portable_descriptor_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        k: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.inner.read_portable_descriptor_at(c, d, t, k)
    }
    fn read_portable_chunk_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        r: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.inner.read_portable_chunk_at(c, d, t, r)
    }
    fn check_portable_outbox_empty_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.inner.check_portable_outbox_empty_at(c, d, t)
    }
}

impl OutgoingSealRepository for SealFaultStore<'_> {
    fn commit_seal_retention(
        &self,
        c: &DurableOperationContext,
        t: &PortableSnapshotToken,
        tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.retention_calls
            .set(self.retention_calls.get().checked_add(1).unwrap());
        self.apply_race(c, false);
        self.inner.commit_seal_retention(c, t, tx)
    }
    fn commit_seal_completion(
        &self,
        c: &DurableOperationContext,
        t: &PortableSnapshotToken,
        tx: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        assert_eq!(sealed.request, self.request);
        assert_eq!(tx.receipt().request_id().as_bytes(), &self.request);
        self.completion_calls
            .set(self.completion_calls.get().checked_add(1).unwrap());
        self.apply_race(c, true);
        let outcome: DurableCommitOutcome = self.inner.commit_seal_completion(c, t, tx, sealed);
        if outcome == DurableCommitOutcome::Committed {
            *self.after_seal_completion.borrow_mut() =
                Some(crate::test_support::capture::captured_source(
                    self.inner,
                    self.blobs,
                    c,
                    self.domain,
                ));
        }
        outcome
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CertificateFault {
    Absent,
    WrongLength,
    WrongDigest,
}

pub(super) struct SealBlobFault<'a> {
    inner: &'a MemoryBlobStore,
    digest: Digest32,
    fault: CertificateFault,
    pub(super) descriptor_calls: Cell<usize>,
    pub(super) chunk_calls: Cell<usize>,
}

impl<'a> SealBlobFault<'a> {
    pub(super) fn new(
        inner: &'a MemoryBlobStore,
        digest: Digest32,
        fault: CertificateFault,
    ) -> Self {
        Self {
            inner,
            digest,
            fault,
            descriptor_calls: Cell::new(0),
            chunk_calls: Cell::new(0),
        }
    }
}

impl runtime::BlobStore for SealBlobFault<'_> {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.inner.put_blob(digest, bytes)
    }
    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.inner.get_blob(digest)
    }
}

impl PortableBlobRepository for SealBlobFault<'_> {
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<PortableBlobDescriptor>, RuntimeError> {
        let descriptor: Option<PortableBlobDescriptor> =
            self.inner.read_portable_blob_descriptor(digest)?;
        if *digest != self.digest {
            return Ok(descriptor);
        }
        self.descriptor_calls
            .set(self.descriptor_calls.get().checked_add(1).unwrap());
        assert!(
            descriptor.is_some(),
            "the fault masks genuine staged material"
        );
        match self.fault {
            CertificateFault::Absent => Ok(None),
            CertificateFault::WrongLength => Ok(descriptor.map(|value| {
                PortableBlobDescriptor::new(value.digest(), value.length().checked_add(1).unwrap())
            })),
            CertificateFault::WrongDigest => Ok(descriptor),
        }
    }
    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError> {
        let outcome: PortableBlobChunkOutcome = self.inner.read_portable_blob_chunk(request)?;
        if request.descriptor().digest() != self.digest {
            return Ok(outcome);
        }
        self.chunk_calls
            .set(self.chunk_calls.get().checked_add(1).unwrap());
        assert_eq!(self.fault, CertificateFault::WrongDigest);
        let PortableBlobChunkOutcome::Chunk(chunk) = outcome else {
            panic!("the real staged certificate has an exact readable range");
        };
        let mut bytes: Vec<u8> = chunk.bytes().to_vec();
        bytes[0] ^= 1;
        Ok(PortableBlobChunkOutcome::Chunk(Box::new(
            PortableBlobChunk::new(request.clone(), bytes)?,
        )))
    }
}
