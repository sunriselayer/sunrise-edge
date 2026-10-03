//! DR-0189 Section 8: per-invocation serving authority. Every successor
//! request reruns the full source-free evidence and the destination
//! comparisons; nothing is cached across requests.

use super::closure::{
    SuccessorRows, derive_successor_rows, require_installed_closure, require_installed_record,
    require_local_member,
};
use super::*;
use crate::genesis::VerifiedGenesisRoot;
use protocol_types::ValidatorId;
use runtime::inactive_import::NamespaceLifecycle;
use runtime::{
    OutgoingBarrier, StructuredDurableDomainStateStore, SuccessorServingRepository,
    SuccessorServingSlot,
};

/// The one authority a live invocation may act under.
pub enum LiveAuthority<'inv> {
    /// An ordinary original namespace: existing behavior and gates apply
    /// unchanged.
    OriginalGenesis,
    /// A verified, installed first successor for this invocation only.
    Successor(Box<LiveWarrant<'inv>>),
}

/// Resolves the authority of one invocation.
///
/// An `Ordinary`, unsealed namespace with an Inactive slot is the original
/// genesis authority. A `CompleteInactive`, unsealed namespace with a Serving
/// slot is a successor only after the full evidence rerun, exact record
/// comparison, a fresh namespace-validator and local-key check, the deciding
/// e+1 CAS reads and the fenced immutable Seal closure comparison. Anything
/// else refuses; Ordinary with Serving is corruption. A store without the
/// successor repository cannot serve a successor.
pub fn resolve_live_authority<'inv, S: StructuredDurableDomainStateStore>(
    store: &'inv S,
    context: &'inv DurableOperationContext,
    domain: AtomicityDomainId,
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
    signer_public_key: [u8; 32],
) -> Result<LiveAuthority<'inv>, ServingAuthorityError> {
    let lifecycle: NamespaceLifecycle = store.get_namespace_lifecycle(context, domain)?;
    let barrier: OutgoingBarrier = store.get_outgoing_barrier(context, domain)?;
    let slot: SuccessorServingSlot = store.get_successor_serving(context, domain)?;
    match (lifecycle, barrier, slot) {
        (
            NamespaceLifecycle::Ordinary,
            OutgoingBarrier::Unsealed,
            SuccessorServingSlot::Inactive,
        ) => Ok(LiveAuthority::OriginalGenesis),
        (NamespaceLifecycle::Ordinary, _, SuccessorServingSlot::Serving(_)) => Err(
            ServingAuthorityError::Refused("ordinary namespace carries a serving record"),
        ),
        (
            NamespaceLifecycle::CompleteInactive { binding, progress },
            OutgoingBarrier::Unsealed,
            SuccessorServingSlot::Serving(observation),
        ) => {
            if observation.binding != binding || observation.progress != progress {
                return Err(ServingAuthorityError::Refused(
                    "serving observation differs from the namespace origin",
                ));
            }
            let root: &VerifiedGenesisRoot = plan.genesis_root;
            let warrant: LiveWarrant<'inv> = successor_warrant(
                store,
                context,
                domain,
                root,
                verify::verify_successor_activation(plan, manifest_identity, artifacts)?,
                *observation,
                signer_public_key,
            )?;
            Ok(LiveAuthority::Successor(Box::new(warrant)))
        }
        _ => Err(ServingAuthorityError::Refused(
            "namespace is neither an ordinary original nor a serving successor",
        )),
    }
}

fn successor_warrant<'inv, S: StructuredDurableDomainStateStore>(
    store: &'inv S,
    context: &'inv DurableOperationContext,
    domain: AtomicityDomainId,
    root: &VerifiedGenesisRoot,
    evidence: VerifiedSuccessorActivation,
    observation: SuccessorServingObservation,
    signer_public_key: [u8; 32],
) -> Result<LiveWarrant<'inv>, ServingAuthorityError> {
    if evidence.policy_inputs.domain != domain {
        return Err(ServingAuthorityError::Refused(
            "verified successor domain differs from the invocation domain",
        ));
    }
    let repository: &dyn SuccessorServingRepository =
        store
            .successor_serving_repository()
            .ok_or(ServingAuthorityError::Refused(
                "store exposes no successor serving repository",
            ))?;
    let namespace_validator: ValidatorId = repository.read_namespace_validator(context, domain)?;
    require_local_member(&evidence, namespace_validator, signer_public_key)?;
    require_installed_record(
        &evidence,
        &observation,
        namespace_validator,
        signer_public_key,
    )?;
    let rows: SuccessorRows = derive_successor_rows(store, context, root, &evidence)?;
    let reads: BTreeMap<Vec<u8>, StateRevision> =
        require_installed_closure(store, context, &evidence, &rows)?;
    Ok(LiveWarrant {
        evidence,
        issuer: store,
        context,
        observation,
        reads,
    })
}

impl LiveWarrant<'_> {
    /// The verified outgoing committee digest for the exact predecessor
    /// epoch, else `None`.
    pub(crate) fn predecessor_certificate_anchor(
        &self,
        certificate_epoch: protocol_types::Epoch,
    ) -> Option<Digest32> {
        (certificate_epoch == self.evidence.outgoing_context.epoch())
            .then_some(self.evidence.policy_inputs.predecessor_set_digest)
    }

    /// Writer-side issuer binding: the store must be the exact object that
    /// issued this warrant, under the same operation context and verified
    /// domain. Address identity is checked privately; nothing public can
    /// assert it.
    /// An offset-zero wrapper may share this address; this is an invocation
    /// identity check, not the final persistence authority. Protected ports
    /// still compare the actual namespace, observation and deciding CAS
    /// under their lock before any successor write.
    pub(crate) fn require_issuer<S: ?Sized>(
        &self,
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        if !std::ptr::addr_eq(
            store as *const S,
            self.issuer as *const dyn runtime::StructuredStateReader,
        ) || context != self.context
            || domain != self.evidence.policy_inputs.domain
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "successor invocation is not bound to the warrant issuer",
            ));
        }
        Ok(())
    }

    /// Reader-side binding for writer-free preparation, which may observe the
    /// issuer through a recording view: the reader must report the exact
    /// protected Serving observation, its unchanged origin and Unsealed.
    pub(crate) fn require_reader<R: runtime::StructuredStateReader + ?Sized>(
        &self,
        reader: &R,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), NodeCoreError> {
        if context != self.context || domain != self.evidence.policy_inputs.domain {
            return Err(NodeCoreError::PersistenceInvariant(
                "successor preparation is not bound to the warrant scope",
            ));
        }
        let serving: bool = matches!(
            reader.read_successor_serving(context, domain)?,
            SuccessorServingSlot::Serving(observation)
                if observation.record == self.observation.record
                    && observation.binding == self.observation.binding
                    && observation.progress == self.observation.progress
        );
        let origin: bool = matches!(
            reader.read_namespace_lifecycle(context, domain)?,
            NamespaceLifecycle::CompleteInactive { binding, progress }
                if binding == self.observation.binding && progress == self.observation.progress
        );
        let unsealed: bool =
            reader.read_outgoing_barrier(context, domain)? == OutgoingBarrier::Unsealed;
        if !serving || !origin || !unsealed {
            return Err(NodeCoreError::PersistenceInvariant(
                "successor preparation reader differs from the warrant observation",
            ));
        }
        Ok(())
    }

    /// The protected successor commit port of `store`, after a fresh
    /// warrant-only check that the physical namespace validator is exactly
    /// the local consensus signer and a verified successor member. The local
    /// member is read fresh here, never cached on the warrant.
    pub(crate) fn successor_repository<'s, S: StructuredDurableDomainStateStore + ?Sized>(
        &self,
        store: &'s S,
        signer: ValidatorId,
    ) -> Result<&'s dyn SuccessorServingRepository, NodeCoreError> {
        self.require_issuer(store, self.context, self.evidence.policy_inputs.domain)?;
        let repository: &'s dyn SuccessorServingRepository = store
            .successor_serving_repository()
            .ok_or(
            NodeCoreError::PersistenceInvariant("store exposes no successor serving repository"),
        )?;
        let namespace_validator: ValidatorId = repository
            .read_namespace_validator(self.context, self.evidence.policy_inputs.domain)?;
        if namespace_validator != signer
            || self
                .evidence
                .policy_inputs
                .validator_set
                .get(namespace_validator)
                .is_none()
        {
            return Err(NodeCoreError::PersistenceInvariant(
                "local signer is not the namespace successor member",
            ));
        }
        Ok(repository)
    }
}
