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
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableInvocationTransaction, DurableStateTransaction,
    OutgoingSealRepository, SealBarrier, StateReadAssertion, StructuredDurableDomainStateStore,
    StructuredStateReader, SuccessorServingRepository,
};

/// The one authority an invocation of a shared handler acts under.
#[derive(Clone, Copy)]
pub(crate) enum ServingGate<'w> {
    /// The ordinary original namespace and its unchanged guards.
    Original,
    /// A verified, installed first successor for this invocation only.
    Successor(&'w LiveWarrant<'w>),
    /// A private reconstruction call on its exact in-memory issuer. It can
    /// replay certified effects but can never sign or Seal.
    Replay(&'w crate::business_reconstruction::ReplayScope<'w>),
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
            Self::Original => {
                crate::mutation_fence::require_ordinary_namespace(store, context, domain)
            }
            Self::Successor(warrant) => warrant.require_live(store, context, domain),
            Self::Replay(scope) => scope.require_issuer(store, context, domain),
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
            Self::Replay(scope) => scope.require_issuer(store, context, domain),
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
            Self::Replay(scope) => scope.require_issuer(reader, context, domain),
        }
    }

    /// Retained material only, not a cached live signature response. An
    /// Original origin remains readable after Seal, preserving its existing
    /// library contract. A successor still needs the exact fresh Unsealed
    /// reader observation, and Replay remains confined to its private issuer.
    pub(crate) fn require_material_reader<R: StructuredStateReader + ?Sized>(
        self,
        reader: &R,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        match self {
            Self::Original => crate::mutation_fence::require_origin_ordinary_reader_namespace(
                reader, context, domain,
            ),
            Self::Successor(warrant) => warrant.require_reader(reader, context, domain),
            Self::Replay(scope) => scope.require_issuer(reader, context, domain),
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
            Self::Replay(_) => Err(NodeCoreError::PersistenceInvariant(
                "private replay never signs",
            )),
        }
    }

    /// The generation floor of this invocation: the profile genesis floor
    /// for the original, the verified cut binding floor for a successor.
    pub(crate) fn generation_scope(self, profile: &LogicalProfileRecord) -> GenerationScope {
        match self {
            Self::Original => GenerationScope::from_profile(profile),
            Self::Successor(warrant) => GenerationScope::for_live(warrant),
            Self::Replay(scope) => GenerationScope::for_replay(scope.floor()),
        }
    }

    /// The verified outgoing committee digest when `certificate_epoch` is
    /// exactly the predecessor epoch of a successor warrant. The original
    /// namespace keeps its legacy transition-chain anchor and returns `None`.
    pub(crate) fn predecessor_certificate_anchor(
        self,
        certificate_epoch: protocol_types::Epoch,
    ) -> Option<Digest32> {
        match self {
            Self::Original => None,
            Self::Successor(warrant) => warrant.predecessor_certificate_anchor(certificate_epoch),
            Self::Replay(scope) => scope.predecessor_certificate_anchor(certificate_epoch),
        }
    }

    /// Only exact independently verified prior rows may be carried rather
    /// than interpreted by the current epoch's frontier. No decoded epoch
    /// or incoming row manufactures this provenance.
    pub(crate) fn prior_state_row(self, key: &[u8]) -> Option<&'w [u8]> {
        match self {
            Self::Original => None,
            Self::Successor(warrant) => warrant.prior_state_row(key),
            Self::Replay(scope) => scope.prior_state_row(key),
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
            Self::Replay(scope) => {
                if scope
                    .require_issuer(store, context, transaction.domain())
                    .is_err()
                {
                    return refused();
                }
                store.commit_durable(context, transaction)
            }
            Self::Successor(warrant) => {
                let prepared: Result<
                    (&dyn SuccessorServingRepository, AtomicStateTransaction),
                    NodeCoreError,
                > = Self::port(warrant, store, context).and_then(|port| {
                    fold_atomic(warrant.reads(), transaction).map(|folded| (port, folded))
                });
                match prepared {
                    Ok((port, folded)) => port.commit_successor_durable(
                        context,
                        warrant.serving_observation(),
                        folded,
                    ),
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
            Self::Replay(scope) => {
                if scope
                    .require_issuer(store, context, transaction.domain())
                    .is_err()
                {
                    return refused();
                }
                store.commit_invocation(context, transaction)
            }
            Self::Successor(warrant) => {
                let prepared: Result<
                    (
                        &dyn SuccessorServingRepository,
                        DurableInvocationTransaction,
                    ),
                    NodeCoreError,
                > = Self::port(warrant, store, context).and_then(|port| {
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

    /// DR-0191 Section 8: the one Seal port of this invocation. `Original`
    /// is exactly the store's own `OutgoingSealRepository`; `Successor` is
    /// the issuing store's own successor repository, after the issuer check.
    /// Port availability is never verified serving or Seal authority.
    pub(crate) fn seal_port<'s, S: StructuredDurableDomainStateStore + ?Sized>(
        self,
        store: &'s S,
    ) -> Result<SealPort<'s>, NodeCoreError>
    where
        'w: 's,
    {
        match self {
            Self::Original => store
                .outgoing_seal_repository()
                .map(SealPort::Original)
                .ok_or(NodeCoreError::PersistenceInvariant(
                    "store exposes no outgoing Seal repository",
                )),
            Self::Successor(warrant) => {
                let port: &'s dyn SuccessorServingRepository =
                    Self::port(warrant, store, warrant.context())?;
                Ok(SealPort::Successor { port, warrant })
            }
            Self::Replay(_) => Err(NodeCoreError::PersistenceInvariant(
                "private replay cannot retain or complete Seal",
            )),
        }
    }

    /// Next exact independently verified prior State key, not merely the
    /// next key physically present now. Frontier traversal merges this with
    /// its bounded physical scan so disappearance cannot shorten history.
    pub(crate) fn next_prior_state_row(
        self,
        prefix: &[u8],
        after: &[u8],
    ) -> Option<(&'w [u8], Option<&'w [u8]>)> {
        match self {
            Self::Original => None,
            Self::Successor(warrant) => warrant.next_prior_state_row(prefix, after),
            Self::Replay(scope) => scope.next_prior_state_row(prefix, after),
        }
    }
}

/// DR-0191 Section 8: the one issuer-bound Seal capability every engine and
/// completion Seal consumer resolves through `ServingGate::seal_port`.
/// Never constructed elsewhere; no public flag selects a variant.
#[derive(Clone, Copy)]
pub(crate) enum SealPort<'s> {
    /// The ordinary original namespace and its unchanged Seal repository.
    Original(&'s dyn OutgoingSealRepository),
    /// A freshly warranted successor and its own store's successor port.
    Successor {
        /// The issuing store's successor port.
        port: &'s dyn SuccessorServingRepository,
        /// The fresh warrant whose deciding reads every commit folds.
        warrant: &'s LiveWarrant<'s>,
    },
}

impl<'s> SealPort<'s> {
    pub(crate) fn reconstruction_base<'c>(
        self,
        root: &'c crate::genesis::VerifiedGenesisRoot,
    ) -> Result<ReconstructionBase<'c>, SuccessorActivationError>
    where
        's: 'c,
    {
        match self {
            Self::Original(_) => Ok(ReconstructionBase::genesis(root)),
            Self::Successor { warrant, .. } => warrant.reconstruction_base(root),
        }
    }
    /// The same store as a structured reader for state and history reads.
    pub(crate) fn reader(self) -> &'s dyn StructuredDurableDomainStateStore {
        match self {
            Self::Original(repository) => repository,
            Self::Successor { port, .. } => port,
        }
    }

    /// The same store as the portable snapshot reader whose token every
    /// Seal commit checks. Core never constructs a token itself.
    pub(crate) fn snapshots(self) -> &'s dyn DurablePortableSnapshotRepository {
        match self {
            Self::Original(repository) => repository,
            Self::Successor { port, .. } => port,
        }
    }

    /// Token-checked retention while the barrier is Unsealed.
    pub(crate) fn commit_retention(
        self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        match self {
            Self::Original(repository) => {
                repository.commit_seal_retention(context, token, transaction)
            }
            Self::Successor { port, warrant } => {
                if context != warrant.context() {
                    return refused();
                }
                match fold_atomic(warrant.reads(), transaction) {
                    Ok(folded) => port.commit_successor_seal_retention(
                        context,
                        warrant.serving_observation(),
                        token,
                        folded,
                    ),
                    Err(_) => refused(),
                }
            }
        }
    }

    /// The Seal invocation and the permanent Sealed barrier, atomically.
    /// A successor additionally requires `sealed` to close exactly its own
    /// warranted epoch before dispatch.
    pub(crate) fn commit_completion(
        self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        match self {
            Self::Original(repository) => {
                repository.commit_seal_completion(context, token, transaction, sealed)
            }
            Self::Successor { port, warrant } => {
                if context != warrant.context()
                    || sealed.outgoing_epoch != warrant.policy_inputs().context().epoch()
                {
                    return refused();
                }
                match fold_invocation(warrant.reads(), transaction) {
                    Ok(folded) => port.commit_successor_seal_completion(
                        context,
                        warrant.serving_observation(),
                        token,
                        folded,
                        sealed,
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

#[cfg(test)]
mod architecture {
    use std::path::{Path, PathBuf};

    fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "tests") {
                    sources(&path, found);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
            {
                found.push(path);
            }
        }
    }

    /// DR-0191 Section 3/8: every non-test core Seal consumer resolves
    /// through `ServingGate::seal_port`; no other owner calls the store
    /// getter directly.
    #[test]
    fn only_the_gate_reads_the_outgoing_seal_getter() {
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files: Vec<PathBuf> = Vec::new();
        sources(&root, &mut files);
        let offenders: Vec<PathBuf> = files
            .into_iter()
            .filter(|path: &PathBuf| !path.ends_with("serving_authority/gate.rs"))
            .filter(|path: &PathBuf| {
                std::fs::read_to_string(path)
                    .unwrap()
                    .contains(".outgoing_seal_repository()")
            })
            .collect();
        assert!(offenders.is_empty(), "direct Seal getter: {offenders:?}");
    }

    /// The historical material exception never enters preparation,
    /// admission, advancement, signing or a writer. Exact public original
    /// and successor readers compose the same two private material owners.
    #[test]
    fn material_reader_gate_is_used_only_by_the_two_retained_material_owners() {
        const CALL: &str = ".require_material_reader(";
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let owners: [(&str, &str); 2] = [
            (
                "ordered_economics/frontier.rs",
                "fn read_frozen_frontier_page_gated",
            ),
            (
                "ordered_economics/drain_union.rs",
                "fn read_drain_signer_progress_gated",
            ),
        ];
        let mut files: Vec<PathBuf> = Vec::new();
        sources(&root, &mut files);
        for path in files {
            if path.ends_with("serving_authority/gate.rs") {
                continue;
            }
            let contents: String = std::fs::read_to_string(&path).unwrap();
            match owners
                .iter()
                .find(|(owner, _): &&(&str, &str)| path.ends_with(owner))
            {
                None => assert!(
                    !contents.contains(CALL),
                    "material gate outside an owner: {path:?}"
                ),
                Some((_, owner)) => {
                    let start: usize = contents.find(owner).unwrap();
                    let body: &str = contents[start..].split("\n}").next().unwrap();
                    assert_eq!(
                        contents.matches(CALL).count(),
                        1,
                        "unexpected material gate count: {path:?}"
                    );
                    assert_eq!(
                        body.matches(CALL).count(),
                        1,
                        "material gate outside its exact reader: {path:?}"
                    );
                }
            }
        }
    }
}
