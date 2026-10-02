//! Read-only observations for verification that does not own persistence.

use crate::{
    AtomicityDomainId, DurableDomainStateStore, DurableOperationContext, DurableReadError,
    VersionedStateValue,
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
}
