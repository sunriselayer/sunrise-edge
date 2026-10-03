//! Read-only observations for verification that does not own persistence.

use crate::{
    AtomicityDomainId, DurableDomainStateStore, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    DurableRequestReceipt, NamespaceLifecycle, ObjectId, OutgoingBarrier,
    StructuredDurableDomainStateStore, SuccessorServingSlot, VersionedStateValue,
};

/// Reads a value and its exact revision without granting a commit capability.
///
/// A reader may be a live durable store or an already captured, independently
/// checked set of rows. This interface alone proves neither snapshot continuity
/// nor namespace, membership or serving authority. Live-store reads retain the
/// underlying adapter's domain, writer-fence and deadline checks. Consumers
/// still verify the returned material under their own protocol contract.
///
/// Verification must not require a writable store just to inspect backing rows.
///
/// A consumer bounded by this trait cannot acquire write capability:
///
/// ```compile_fail
/// use runtime::{DurableDomainStateStore, VersionedStateReader};
/// fn requires_writer<S: DurableDomainStateStore>(_: &S) {}
/// fn cannot_promote<S: VersionedStateReader>(reader: &S) {
///     requires_writer(reader);
/// }
/// ```
pub trait VersionedStateReader {
    /// Reads one observation using the caller's explicit context and domain.
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError>;
}

// Forward existing durable adapters without inventing another provider API or
// retaining fake commit methods on captured views. The distinct method name
// avoids overlap with the underlying store's broader trait. Nothing implements
// DurableDomainStateStore in the opposite direction.
impl<S: DurableDomainStateStore + ?Sized> VersionedStateReader for S {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.get_versioned_durable(context, domain, key)
    }
}

/// Structured observations for business preparation, without persistence.
///
/// Every method is required: neither an ordinary origin nor an absent receipt
/// may be fabricated by a default. The observations alone prove no stable
/// snapshot, authenticated history, current serving or signing authority.
/// The owning admission and final commit still check those distinct contracts.
/// Existing stores forward the same domain, fence, deadline and schema checks.
///
/// A reader cannot be used where actual persistence is required:
///
/// ```compile_fail
/// use runtime::{StructuredDurableDomainStateStore, StructuredStateReader};
/// fn requires_writer<S: StructuredDurableDomainStateStore>(_: &S) {}
/// fn cannot_promote<S: StructuredStateReader>(reader: &S) {
///     requires_writer(reader);
/// }
/// ```
pub trait StructuredStateReader: VersionedStateReader {
    /// Observes physical namespace origin; this is not serving authority.
    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError>;

    /// Reads one exact object-head observation without changing its version.
    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError>;

    /// Reads a retained immutable object version; bodies keep their own port.
    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError>;

    /// Reads the exact original receipt for owner-specific reconciliation.
    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError>;

    /// Observes the protected outgoing barrier through this same reader.
    /// Unsealed is never membership or serving permission.
    fn read_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError>;

    /// Observes the protected successor-serving slot through this same
    /// reader. Inactive is never serving permission, and Serving never
    /// reverts to Inactive.
    fn read_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<SuccessorServingSlot, DurableReadError>;
}

impl<S: StructuredDurableDomainStateStore + ?Sized> StructuredStateReader for S {
    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.get_namespace_lifecycle(context, domain)
    }

    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.get_object_head(context, domain, object_id)
    }

    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.get_object_version(context, domain, object_id, object_version)
    }

    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.get_request_receipt(context, domain, request_id)
    }

    fn read_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        self.get_outgoing_barrier(context, domain)
    }

    fn read_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<SuccessorServingSlot, DurableReadError> {
        self.get_successor_serving(context, domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
        MemoryDurableStateStore, RuntimeError, StateMutation, StateMutationEntry,
        StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };

    fn domain(byte: u8) -> AtomicityDomainId {
        AtomicityDomainId::new([byte; 32]).unwrap()
    }

    fn context(fence: u64, deadline: u64) -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(fence).unwrap(),
            StorageDeadline::new(deadline).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        )
    }

    fn mutate(
        store: &MemoryDurableStateStore,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        expected: StateRevision,
        mutation: StateMutation,
    ) {
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(b"key".to_vec(), expected).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(b"key".to_vec(), mutation).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(context, transaction),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn reader_bridge_preserves_absent_present_and_tombstone_observations() {
        let domain: AtomicityDomainId = domain(1);
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(domain, WriterFenceGeneration::new(1).unwrap());
        let context: DurableOperationContext = context(1, 1_000);
        let reader: &dyn VersionedStateReader = &store;
        let absent: VersionedStateValue = reader
            .read_versioned_state(&context, domain, b"key")
            .unwrap();
        assert_eq!(absent.revision(), StateRevision::INITIAL);
        assert_eq!(absent.value(), None);

        mutate(
            &store,
            &context,
            domain,
            absent.revision(),
            StateMutation::Put(vec![7]),
        );
        let present: VersionedStateValue = reader
            .read_versioned_state(&context, domain, b"key")
            .unwrap();
        assert_eq!(present.revision(), StateRevision::new(1));
        assert_eq!(present.value(), Some([7].as_slice()));

        mutate(
            &store,
            &context,
            domain,
            present.revision(),
            StateMutation::Delete,
        );
        let tombstone: VersionedStateValue = reader
            .read_versioned_state(&context, domain, b"key")
            .unwrap();
        assert_eq!(tombstone.revision(), StateRevision::new(2));
        assert_eq!(tombstone.value(), None);
    }

    #[test]
    fn reader_bridge_preserves_domain_fence_deadline_and_key_refusals() {
        let selected: AtomicityDomainId = domain(2);
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(selected, WriterFenceGeneration::new(4).unwrap());
        store.set_time(50);
        let reader: &dyn VersionedStateReader = &store;
        let operation: DurableOperationContext = context(4, 1_000);
        assert_eq!(
            reader.read_versioned_state(&operation, domain(3), b"key"),
            Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch
            )),
        );
        assert_eq!(
            reader.read_versioned_state(&operation, selected, b""),
            Err(DurableReadError::InvalidRequest(RuntimeError::EmptyKey)),
        );
        store.set_active_writer_fence(WriterFenceGeneration::new(5).unwrap());
        assert_eq!(
            reader.read_versioned_state(&operation, selected, b"key"),
            Err(DurableReadError::WriterFenced {
                active_generation: WriterFenceGeneration::new(5).unwrap(),
            }),
        );
        assert_eq!(
            reader.read_versioned_state(&context(5, 50), selected, b"key"),
            Err(DurableReadError::DeadlineExceeded),
        );
    }

    #[test]
    fn structured_reader_forwards_absence_origin_and_all_operation_refusals() {
        let domain: AtomicityDomainId = domain(7);
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(domain, WriterFenceGeneration::new(4).unwrap());
        store.set_time(50);
        let reader: &dyn StructuredStateReader = &store;
        let operation: DurableOperationContext = context(4, 1_000);
        let object: ObjectId = ObjectId::new([8; 32]);
        let request: DurableRequestId = DurableRequestId::new([9; 32]).unwrap();
        assert_eq!(
            reader.read_namespace_lifecycle(&operation, domain),
            Ok(NamespaceLifecycle::Ordinary)
        );
        assert_eq!(
            reader.read_object_head(&operation, domain, object),
            Ok(DurableObjectHead::Absent)
        );
        assert_eq!(
            reader.read_object_version(&operation, domain, object, DurableObjectVersion::FIRST),
            Ok(None)
        );
        assert_eq!(
            reader.read_request_receipt(&operation, domain, request),
            Ok(None)
        );

        let wrong_domain: AtomicityDomainId = AtomicityDomainId::new([10; 32]).unwrap();
        let expected: DurableReadError =
            DurableReadError::InvalidRequest(RuntimeError::AtomicityDomainMismatch);
        assert_eq!(
            reader.read_namespace_lifecycle(&operation, wrong_domain),
            Err(expected.clone())
        );
        assert_eq!(
            reader.read_object_head(&operation, wrong_domain, object),
            Err(expected.clone())
        );
        assert_eq!(
            reader.read_object_version(
                &operation,
                wrong_domain,
                object,
                DurableObjectVersion::FIRST
            ),
            Err(expected.clone())
        );
        assert_eq!(
            reader.read_request_receipt(&operation, wrong_domain, request),
            Err(expected)
        );

        for (operation, expected) in [
            (
                context(3, 1_000),
                DurableReadError::WriterFenced {
                    active_generation: WriterFenceGeneration::new(4).unwrap(),
                },
            ),
            (context(4, 50), DurableReadError::DeadlineExceeded),
        ] {
            assert_eq!(
                reader.read_namespace_lifecycle(&operation, domain),
                Err(expected.clone())
            );
            assert_eq!(
                reader.read_object_head(&operation, domain, object),
                Err(expected.clone())
            );
            assert_eq!(
                reader.read_object_version(&operation, domain, object, DurableObjectVersion::FIRST),
                Err(expected.clone())
            );
            assert_eq!(
                reader.read_request_receipt(&operation, domain, request),
                Err(expected)
            );
        }
    }
}
