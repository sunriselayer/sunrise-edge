//! Explicit local publication policy bootstrap; no contract execution or fees.

use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::publication::{
    LocalPublicationPolicy, local_publication_profile_semantics, publication_policy_key,
};
use protocol_types::{AtomicityDomainId, Epoch};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableOperationContext, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision,
};

/// Startup failures retain storage rejection and uncertainty for operator reconciliation.
#[derive(Debug)]
pub enum LocalPublicationBootError {
    /// Publication context validation failed.
    Context(execution::publication::PublicationError),
    /// Policy construction failed.
    Policy(node_core::publication::PublicationAdmissionError),
    /// A fenced policy read failed.
    Read(runtime::DurableReadError),
    /// The atomic transaction was invalid.
    Runtime(runtime::RuntimeError),
    /// Stored policy disagrees with the trusted boot profile.
    Mismatch,
    /// A deleted policy cannot be recreated implicitly.
    Tombstoned,
    /// Storage authoritatively rejected the write.
    Rejected(runtime::DurableCommitRejection),
    /// Storage could not determine whether the write committed.
    Indeterminate(runtime::IndeterminateCommitReason),
}
impl std::fmt::Display for LocalPublicationBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local publication policy bootstrap failed: {self:?}")
    }
}
impl std::error::Error for LocalPublicationBootError {}
impl From<execution::publication::PublicationError> for LocalPublicationBootError {
    fn from(value: execution::publication::PublicationError) -> Self {
        Self::Context(value)
    }
}
impl From<node_core::publication::PublicationAdmissionError> for LocalPublicationBootError {
    fn from(value: node_core::publication::PublicationAdmissionError) -> Self {
        Self::Policy(value)
    }
}
impl From<runtime::DurableReadError> for LocalPublicationBootError {
    fn from(value: runtime::DurableReadError) -> Self {
        Self::Read(value)
    }
}
impl From<runtime::RuntimeError> for LocalPublicationBootError {
    fn from(value: runtime::RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Verifies an existing exact policy or atomically seeds its absent key.
/// A mismatched policy or uncertain commit is a startup failure.
pub fn seed_local_publication_policy<S: DurableDomainStateStore + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<LocalPublicationPolicy, LocalPublicationBootError> {
    let context: PublicationContext = PublicationContext::new(
        resolver.chain_id().clone(),
        resolver.protocol_version(),
        epoch,
    )?;
    let semantics = local_publication_profile_semantics(resolver, &context)?;
    let policy: LocalPublicationPolicy = LocalPublicationPolicy::new(context, semantics);
    let key: Vec<u8> = publication_policy_key(policy.context())?;
    let bytes: Vec<u8> = policy.encode()?;
    let observed = store.get_versioned_durable(operation, domain, &key)?;
    if let Some(existing) = observed.value() {
        if existing != bytes {
            return Err(LocalPublicationBootError::Mismatch);
        }
        return Ok(policy);
    }
    if observed.revision() != StateRevision::INITIAL {
        return Err(LocalPublicationBootError::Tombstoned);
    }
    let reads: AtomicStateReadSet = AtomicStateReadSet::new(vec![StateReadAssertion::new(
        key.clone(),
        observed.revision(),
    )?])?;
    let mutations: AtomicStateMutationSet =
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key.clone(),
            StateMutation::Put(bytes.clone()),
        )?])?;
    let transaction: AtomicStateTransaction =
        AtomicStateTransaction::new(domain, reads, mutations)?;
    match store.commit_durable(operation, transaction) {
        DurableCommitOutcome::Committed => {}
        DurableCommitOutcome::Rejected(reason) => {
            return Err(LocalPublicationBootError::Rejected(reason));
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            return Err(LocalPublicationBootError::Indeterminate(reason));
        }
    }
    if store
        .get_versioned_durable(operation, domain, &key)?
        .value()
        != Some(bytes.as_slice())
    {
        return Err(LocalPublicationBootError::Mismatch);
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use runtime::{
        MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
    };

    #[test]
    fn bootstrap_preserves_exact_policy_and_rejects_tombstone_mismatch_and_stale_fence() {
        let domain = AtomicityDomainId::new([3; 32]).unwrap();
        let fence = WriterFenceGeneration::new(2).unwrap();
        let store = MemoryDurableStateStore::new_bound(domain, fence);
        let resolver = HashSuiteResolver::new(
            ChainId::new("boot-publication").unwrap(),
            ProtocolVersion::new(6),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let operation = DurableOperationContext::new(
            fence,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([5; 16]).unwrap(),
        );
        let policy =
            seed_local_publication_policy(&store, &operation, domain, &resolver, Epoch::new(0))
                .unwrap();
        let key = publication_policy_key(policy.context()).unwrap();
        let before = store
            .get_versioned_durable(&operation, domain, &key)
            .unwrap();
        assert_eq!(
            seed_local_publication_policy(&store, &operation, domain, &resolver, Epoch::new(0))
                .unwrap()
                .encode()
                .unwrap(),
            policy.encode().unwrap()
        );
        assert_eq!(
            store
                .get_versioned_durable(&operation, domain, &key)
                .unwrap(),
            before
        );
        let stale = DurableOperationContext::new(
            WriterFenceGeneration::new(1).unwrap(),
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([6; 16]).unwrap(),
        );
        assert!(matches!(
            seed_local_publication_policy(&store, &stale, domain, &resolver, Epoch::new(0)),
            Err(LocalPublicationBootError::Read(_))
        ));
        for mutation in [StateMutation::Put(vec![1]), StateMutation::Delete] {
            let read = store
                .get_versioned_durable(&operation, domain, &key)
                .unwrap();
            let transaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), read.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(key.clone(), mutation).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                store.commit_durable(&operation, transaction),
                DurableCommitOutcome::Committed
            );
            let before = store
                .get_versioned_durable(&operation, domain, &key)
                .unwrap();
            assert!(matches!(
                seed_local_publication_policy(&store, &operation, domain, &resolver, Epoch::new(0)),
                Err(LocalPublicationBootError::Mismatch | LocalPublicationBootError::Tombstoned)
            ));
            assert_eq!(
                store
                    .get_versioned_durable(&operation, domain, &key)
                    .unwrap(),
                before
            );
        }
    }
}
