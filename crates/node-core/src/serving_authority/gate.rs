//! DR-0189 private trusted namespace authority of one invocation.
//!
//! The existing functional handlers take this gate instead of calling the
//! ordinary namespace guards, generation floor and generic commit ports
//! directly. `Original` delegates to exactly those unchanged guards and
//! ports, so every ordinary entry point is byte- and behavior-equivalent.
//! `Successor` exists only while a freshly resolved [`LiveWarrant`] is
//! borrowed: it binds writes to the issuing store, derives above the
//! verified cut floor, folds the deciding warrant CAS reads into every
//! transaction and commits only through the protected successor ports. No
//! guard is relaxed globally and no Ordinary facade exists.

use super::*;
use crate::logical_generation::{GenerationScope, LogicalProfileRecord};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableInvocationTransaction, DurableStateTransaction,
    StateReadAssertion, StructuredDurableDomainStateStore, StructuredStateReader,
    SuccessorServingRepository,
};

/// The one authority an invocation of a shared handler acts under.
#[derive(Clone, Copy)]
pub(crate) enum ServingGate<'w> {
    /// The ordinary original namespace and its unchanged guards.
    Original,
    /// A verified, installed first successor for this invocation only.
    Successor(&'w LiveWarrant<'w>),
}

impl<'w> ServingGate<'w> {
    /// Live mutation and signing admission.
    pub(crate) fn require_live<S: DurableDomainStateStore>(
        self,
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        match self {
            Self::Original => crate::mutation_fence::require_ordinary_namespace(store, context, domain),
            Self::Successor(warrant) => warrant.require_issuer(store, context, domain),
        }
    }

    /// Signerless reconciliation admission (origin only for the original).
    pub(crate) fn require_origin<S: DurableDomainStateStore>(
        self,
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        match self {
            Self::Original => {
                crate::mutation_fence::require_origin_ordinary_namespace(store, context, domain)
            }
            Self::Successor(warrant) => warrant.require_issuer(store, context, domain),
        }
    }

    /// Writer-free preparation admission through a reader or recording view.
    pub(crate) fn require_reader<R: StructuredStateReader + ?Sized>(
        self,
        reader: &R,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        match self {
            Self::Original => {
                crate::mutation_fence::require_ordinary_reader_namespace(reader, context, domain)
            }
            Self::Successor(warrant) => warrant.require_reader(reader, context, domain),
        }
    }

    /// The local consensus signer must be the fresh physical namespace
    /// member of a successor. The original keeps its existing checks.
    pub(crate) fn require_local_signer<S: StructuredDurableDomainStateStore + ?Sized>(
        self,
        store: &S,
        signer: protocol_types::ValidatorId,
    ) -> Result<(), NodeCoreError> {
        match self {
            Self::Original => Ok(()),
            Self::Successor(warrant) => warrant.successor_repository(store, signer).map(|_| ()),
        }
    }

    /// The generation floor of this invocation: the profile genesis floor
    /// for the original, the verified cut binding floor for a successor.
    pub(crate) fn generation_scope(self, profile: &LogicalProfileRecord) -> GenerationScope {
        match self {
            Self::Original => GenerationScope::from_profile(profile),
            Self::Successor(warrant) => GenerationScope::for_live(warrant),
        }
    }

    /// The successor port of the issuing store, refused for any other store.
    fn port<'s, S: StructuredDurableDomainStateStore + ?Sized>(
        warrant: &LiveWarrant<'_>,
        store: &'s S,
        context: &DurableOperationContext,
    ) -> Result<&'s dyn SuccessorServingRepository, NodeCoreError> {
        warrant.require_issuer(store, context, warrant.policy_inputs().domain())?;
        store
            .successor_serving_repository()
            .ok_or(NodeCoreError::PersistenceInvariant(
                "store exposes no successor serving repository",
            ))
    }

    /// Metadata commit: the unchanged generic port for the original, the
    /// protected successor port with folded deciding reads otherwise. A
    /// refusal before dispatch is a definite no-write rejection.
    pub(crate) fn commit_durable<S: StructuredDurableDomainStateStore + ?Sized>(
        self,
        store: &S,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        match self {
            Self::Original => store.commit_durable(context, transaction),
            Self::Successor(warrant) => {
                let prepared: Result<(&dyn SuccessorServingRepository, AtomicStateTransaction), NodeCoreError> =
                    Self::port(warrant, store, context).and_then(|port| {
                    fold_atomic(warrant.reads(), transaction).map(|folded| (port, folded))
                });
                match prepared {
                    Ok((port, folded)) => {
                        port.commit_successor_durable(context, warrant.serving_observation(), folded)
                    }
                    Err(_) => refused(),
                }
            }
        }
    }

    /// Invocation commit, as [`Self::commit_durable`].
    pub(crate) fn commit_invocation<S: StructuredDurableDomainStateStore + ?Sized>(
        self,
        store: &S,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        match self {
            Self::Original => store.commit_invocation(context, transaction),
            Self::Successor(warrant) => {
                let prepared: Result<(&dyn SuccessorServingRepository, DurableInvocationTransaction), NodeCoreError> =
                    Self::port(warrant, store, context).and_then(|port| {
                    fold_invocation(warrant.reads(), transaction).map(|folded| (port, folded))
                });
                match prepared {
                    Ok((port, folded)) => port.commit_successor_invocation(
                        context,
                        warrant.serving_observation(),
                        folded,
                    ),
                    Err(_) => refused(),
                }
            }
        }
    }
}

fn refused() -> DurableCommitOutcome {
    DurableCommitOutcome::Rejected(runtime::DurableCommitRejection::InactiveNamespace)
}

fn merge_reads(
    existing: &[StateReadAssertion],
    warrant: &BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Vec<StateReadAssertion>, NodeCoreError> {
    let mut merged: BTreeMap<Vec<u8>, StateRevision> = existing
        .iter()
        .map(|read: &StateReadAssertion| (read.key().to_vec(), read.expected_revision()))
        .collect();
    for (key, revision) in warrant {
        if let Some(previous) = merged.insert(key.clone(), *revision)
            && previous != *revision
        {
            return Err(NodeCoreError::StateConflict);
        }
    }
    merged
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()
        .map_err(NodeCoreError::from)
}

fn fold_atomic(
    warrant: &BTreeMap<Vec<u8>, StateRevision>,
    transaction: AtomicStateTransaction,
) -> Result<AtomicStateTransaction, NodeCoreError> {
    let reads: Vec<StateReadAssertion> = merge_reads(transaction.reads(), warrant)?;
    Ok(AtomicStateTransaction::new(
        transaction.domain(),
        AtomicStateReadSet::new(reads)?,
        AtomicStateMutationSet::new(transaction.mutations().to_vec())?,
    )?)
}

fn fold_invocation(
    warrant: &BTreeMap<Vec<u8>, StateRevision>,
    transaction: DurableInvocationTransaction,
) -> Result<DurableInvocationTransaction, NodeCoreError> {
    let domain: AtomicityDomainId = transaction.domain();
    let (existing, mutations): (Vec<StateReadAssertion>, Vec<runtime::StateMutationEntry>) =
        match transaction.state() {
            Some(state) => (state.reads().to_vec(), state.mutations().to_vec()),
            None => (Vec::new(), Vec::new()),
        };
    let state: DurableStateTransaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(merge_reads(&existing, warrant)?)?,
        mutations,
    )?;
    Ok(DurableInvocationTransaction::new(
        domain,
        Some(state),
        transaction.objects(),
        transaction.receipt().clone(),
        transaction.outbox().cloned(),
    )?)
}
