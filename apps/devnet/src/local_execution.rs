//! Explicit atomic bootstrap of typed publication and local zero-fee execution.

use execution::local_execution::{LocalExecutionError, LocalExecutionPolicy};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::local_instance_state::execution_policy_key;
use node_core::publication::{
    LocalPublicationPolicy, local_executable_publication_semantics,
    publication_policy_key_for_profile,
};
use protocol_types::{AtomicityDomainId, Epoch};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableOperationContext, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision, VersionedStateValue,
};

/// Boot must fail closed rather than partly activating executable authority.
#[derive(Debug)]
pub enum LocalExecutionBootError {
    /// Existing publication/context/storage error.
    Publication(crate::publication::LocalPublicationBootError),
    /// Invalid closed execution policy.
    Execution(LocalExecutionError),
    /// Invalid reserved state key.
    State(node_core::NodeCoreError),
}
impl std::fmt::Display for LocalExecutionBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local execution bootstrap failed: {self:?}")
    }
}
impl std::error::Error for LocalExecutionBootError {}
impl From<crate::publication::LocalPublicationBootError> for LocalExecutionBootError {
    fn from(value: crate::publication::LocalPublicationBootError) -> Self {
        Self::Publication(value)
    }
}

/// Seeds both exact policies in one fenced write; live mismatches and tombstones
/// reject before any write. Existing matching rows remain immutable.
pub fn seed_local_execution_policies<S: DurableDomainStateStore + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<(LocalPublicationPolicy, LocalExecutionPolicy), LocalExecutionBootError> {
    use crate::publication::LocalPublicationBootError as E;
    let context: PublicationContext = PublicationContext::new(
        resolver.chain_id().clone(),
        resolver.protocol_version(),
        epoch,
    )
    .map_err(E::from)?;
    let semantics = local_executable_publication_semantics(resolver, &context).map_err(E::from)?;
    let publication: LocalPublicationPolicy =
        LocalPublicationPolicy::executable(context.clone(), semantics);
    let execution: LocalExecutionPolicy = LocalExecutionPolicy::new(context);
    let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            publication_policy_key_for_profile(publication.context(), 2).map_err(E::from)?,
            publication.encode().map_err(E::from)?,
        ),
        (
            execution_policy_key(execution.context()).map_err(LocalExecutionBootError::State)?,
            execution
                .encode()
                .map_err(LocalExecutionBootError::Execution)?,
        ),
    ];
    let mut reads: Vec<StateReadAssertion> = Vec::with_capacity(entries.len());
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    for (key, bytes) in &entries {
        let observed: VersionedStateValue = store
            .get_versioned_durable(operation, domain, key)
            .map_err(E::from)?;
        reads.push(StateReadAssertion::new(key.clone(), observed.revision()).map_err(E::from)?);
        if let Some(existing) = observed.value() {
            if existing != bytes {
                return Err(E::Mismatch.into());
            }
        } else {
            if observed.revision() != StateRevision::INITIAL {
                return Err(E::Tombstoned.into());
            }
            mutations.push(
                StateMutationEntry::new(key.clone(), StateMutation::Put(bytes.clone()))
                    .map_err(E::from)?,
            );
        }
    }
    if !mutations.is_empty() {
        let tx: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(reads).map_err(E::from)?,
            AtomicStateMutationSet::new(mutations).map_err(E::from)?,
        )
        .map_err(E::from)?;
        match store.commit_durable(operation, tx) {
            DurableCommitOutcome::Committed => {}
            DurableCommitOutcome::Rejected(reason) => return Err(E::Rejected(reason).into()),
            DurableCommitOutcome::Indeterminate(reason) => {
                return Err(E::Indeterminate(reason).into());
            }
        }
    }
    for (key, bytes) in entries {
        if store
            .get_versioned_durable(operation, domain, &key)
            .map_err(E::from)?
            .value()
            != Some(bytes.as_slice())
        {
            return Err(E::Mismatch.into());
        }
    }
    Ok((publication, execution))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use runtime::{
        MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
    };

    #[test]
    fn policies_seed_atomically_and_reject_partial_tombstone_and_stale_fence() {
        let domain: AtomicityDomainId = AtomicityDomainId::new([4; 32]).unwrap();
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
        let operation: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([2; 16]).unwrap(),
        );
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            ChainId::new("execution-boot").unwrap(),
            ProtocolVersion::new(3),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain, generation);
        let pair =
            seed_local_execution_policies(&store, &operation, domain, &resolver, Epoch::new(0))
                .unwrap();
        assert_eq!(
            pair,
            seed_local_execution_policies(&store, &operation, domain, &resolver, Epoch::new(0))
                .unwrap()
        );
        let stale: DurableOperationContext = DurableOperationContext::new(
            WriterFenceGeneration::new(1).unwrap(),
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([3; 16]).unwrap(),
        );
        assert!(
            seed_local_execution_policies(&store, &stale, domain, &resolver, Epoch::new(0))
                .is_err()
        );
        let broken: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(domain, generation);
        let key: Vec<u8> = execution_policy_key(pair.1.context()).unwrap();
        let tx: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            broken.commit_durable(&operation, tx),
            DurableCommitOutcome::Committed
        );
        assert!(matches!(
            seed_local_execution_policies(&broken, &operation, domain, &resolver, Epoch::new(0)),
            Err(LocalExecutionBootError::Publication(
                crate::publication::LocalPublicationBootError::Tombstoned
            ))
        ));
        let publication_key: Vec<u8> =
            publication_policy_key_for_profile(pair.0.context(), 2).unwrap();
        let observed: VersionedStateValue = broken
            .get_versioned_durable(&operation, domain, &publication_key)
            .unwrap();
        assert!(observed.value().is_none());
        assert_eq!(observed.revision(), StateRevision::INITIAL);
    }
}
