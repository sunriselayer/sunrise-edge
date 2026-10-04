//! DR-0189 first-successor target-local activation and authenticated
//! serving authority.
//!
//! Three opaque roles are kept strictly apart. Source-free evidence
//! (`VerifiedSuccessorActivation`) is produced only by the one private
//! verifier from the original pinned genesis, the outgoing committee, the
//! authenticated ordered history through the committed terminal Seal, the
//! readiness certificate it names and plan-derived next-set eligibility. An
//! `ActivationWarrant` adds the destination facts needed to install the
//! successor before Serving. A [`LiveWarrant`] is built only from an
//! installed Serving slot plus a fresh full rerun of the evidence. Every
//! field is private to this module and its children: no decoded row, flag or
//! equality report constructs any of them, and none has `Default`, `Clone`
//! or serialization.
//!
//! Nothing here creates a new outgoing signature. Evidence is re-verified in
//! full on every invocation that needs it (activation, reconciliation,
//! startup and every live request) with no cache or memo. Cost is linear in
//! saved-cut re-execution plus the ordered history through the Seal.

use crate::NodeCoreError;
use crate::business_reconstruction::BusinessReconstructionPlan;
use crate::business_reconstruction::cut::SavedBusinessCut;
use crate::business_reconstruction::inactive_import::{BusinessImportError, VerifiedImportPlan};
use crate::epoch_transition::NextSetEligibilityError;
use crate::fast_path::records::FastPathValidatorEntry;
use crate::ordered_economics::{
    OrderedEconomicsError, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
};
use canonical_encoding::{CanonicalDecodingError, CanonicalEncodingError};
use consensus::readiness::ReadinessError;
use execution::publication::PublicationContext;
use protocol_types::{Digest32, ExecutionGeneration};
use runtime::{
    AtomicityDomainId, DurableCommitRejection, DurableOperationContext, DurableReadError,
    IndeterminateCommitReason, RuntimeError, StateRevision, SuccessorServingObservation,
};
use std::collections::BTreeMap;
use std::{error::Error, fmt};
use validator_set::ValidatorSet;

mod activation;
mod base;
mod chain;
mod closure;
mod entry;
mod frames;
mod gate;
mod live;
mod verify;

pub(crate) use base::ReconstructionBase;
pub(crate) use gate::{SealPort, ServingGate};

#[cfg(test)]
pub(crate) mod tests;

pub use activation::{SuccessorActivationOutcome, activate_successor, activate_successor_chain};
pub(crate) use chain::{
    CommitteeProvenance, OwnerProvenance, VerifiedCommitteeHistory, VerifiedOwnerRegistry,
};
pub use chain::{SuccessorChainArtifacts, SuccessorChainBudget, SuccessorLinkPins};
pub use entry::{
    SuccessorFastVoteComposition, SuccessorFeeClaimInspection, apply_successor,
    inspect_fee_claim_successor, prepare_fee_claim_successor, prepare_successor,
    query_request_receipt_successor, retain_publication_successor,
};
pub use frames::{
    MAX_SUCCESSOR_ACTIVATION_MANIFEST_BYTES, MAX_SUCCESSOR_ACTIVATION_SUBJECT_BYTES,
    SUCCESSOR_ACTIVATION_MANIFEST_TYPE, SUCCESSOR_ACTIVATION_SUBJECT_TYPE,
    SuccessorActivationManifest, SuccessorActivationSubject, decode_successor_activation_manifest,
    decode_successor_activation_subject, encode_successor_activation_manifest,
    encode_successor_activation_subject, successor_activation_manifest_digest,
    successor_activation_subject_digest,
};
pub use live::{LiveAuthority, resolve_live_authority, resolve_live_authority_chain};

/// Untrusted transport of the existing saved-cut, history-export and
/// readiness-certificate artifacts. Every returned value is a claim: the
/// verifier knows every reference independently (its own height counter,
/// descriptor component references, the recomputed package digest and the
/// SealIntent certificate length and digest). Missing or corrupt artifacts
/// stop, never skip, and a directory listing is never authority.
pub trait SuccessorArtifactSource {
    /// Whole saved cut, as the existing saved-cut archive reader assembles it.
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError>;
    /// Height `1..=identity.through_height` of one fixed history export.
    fn history_height(
        &mut self,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError>;
    /// Exactly `length` bytes, `length <= 1 MiB`, else refuse.
    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError>;
}

/// Closed artifact transport failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessorArtifactError {
    /// The named artifact does not exist.
    Missing,
    /// The artifact exceeds its owning bound.
    Oversized,
    /// The artifact bytes do not decode under their owning codec.
    Malformed,
    /// The artifact could not be read.
    Io,
}

impl fmt::Display for SuccessorArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "successor artifact is missing",
            Self::Oversized => "successor artifact exceeds its bound",
            Self::Malformed => "successor artifact is malformed",
            Self::Io => "successor artifact could not be read",
        })
    }
}

impl Error for SuccessorArtifactError {}

/// Closed refusal of successor verification or activation. Every variant
/// proves no destination write occurred, except [`Self::Indeterminate`],
/// which preserves the existing reply-loss boundary.
#[derive(Debug)]
pub enum SuccessorActivationError {
    /// An artifact could not be supplied.
    Artifact(SuccessorArtifactError),
    /// Saved-cut re-execution or inactive-target comparison refused.
    Import(Box<BusinessImportError>),
    /// Ordered history, Seal or policy authentication refused.
    Ordered(Box<OrderedEconomicsError>),
    /// Readiness certificate or subject verification refused.
    Readiness(ReadinessError),
    /// A certified successor member is not eligible under the plan state.
    Ineligible,
    /// A plan eligibility prerequisite is absent or inconsistent.
    EligibilityPrerequisite,
    /// Storage, key derivation or canonical encoding failure.
    Node(Box<NodeCoreError>),
    /// A closed successor invariant failed.
    Invalid(&'static str),
    /// The destination composition cannot install or serve a successor.
    Unsupported(&'static str),
    /// The complete activation transaction exceeds an existing bound. Refused
    /// whole before any port call; never a partial install.
    ActivationTooLarge,
    /// The destination proved the activation was not committed.
    Rejected(DurableCommitRejection),
    /// The destination could not prove whether activation committed, and a
    /// fresh slot read did not show this exact record.
    Indeterminate(IndeterminateCommitReason),
    /// DR-0191: more link pins than the configured local budget. Refused
    /// before any artifact access; never truncated.
    ChainBudgetExceeded {
        /// Supplied link pin count.
        links: usize,
        /// Configured maximum link count.
        budget: u32,
    },
}

impl fmt::Display for SuccessorActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => error.fmt(f),
            Self::Import(error) => error.fmt(f),
            Self::Ordered(error) => error.fmt(f),
            Self::Readiness(error) => error.fmt(f),
            Self::Ineligible => f.write_str("certified successor member is not eligible"),
            Self::EligibilityPrerequisite => {
                f.write_str("successor eligibility prerequisite is absent or inconsistent")
            }
            Self::Node(error) => error.fmt(f),
            Self::Invalid(message) | Self::Unsupported(message) => f.write_str(message),
            Self::ActivationTooLarge => {
                f.write_str("successor activation transaction exceeds an existing bound")
            }
            Self::Rejected(reason) => write!(f, "successor activation refused: {reason:?}"),
            Self::Indeterminate(reason) => {
                write!(f, "successor activation remains indeterminate: {reason:?}")
            }
            Self::ChainBudgetExceeded { links, budget } => write!(
                f,
                "successor chain of {links} links exceeds the configured budget {budget}"
            ),
        }
    }
}

impl Error for SuccessorActivationError {}

impl From<SuccessorArtifactError> for SuccessorActivationError {
    fn from(error: SuccessorArtifactError) -> Self {
        Self::Artifact(error)
    }
}
impl From<BusinessImportError> for SuccessorActivationError {
    fn from(error: BusinessImportError) -> Self {
        Self::Import(Box::new(error))
    }
}
impl From<OrderedEconomicsError> for SuccessorActivationError {
    fn from(error: OrderedEconomicsError) -> Self {
        Self::Ordered(Box::new(error))
    }
}
impl From<ReadinessError> for SuccessorActivationError {
    fn from(error: ReadinessError) -> Self {
        Self::Readiness(error)
    }
}
impl From<NodeCoreError> for SuccessorActivationError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(Box::new(error))
    }
}
impl From<DurableReadError> for SuccessorActivationError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(Box::new(NodeCoreError::from(error)))
    }
}
impl From<RuntimeError> for SuccessorActivationError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(Box::new(NodeCoreError::from(error)))
    }
}
impl From<CanonicalEncodingError> for SuccessorActivationError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(Box::new(NodeCoreError::CanonicalEncoding(error)))
    }
}
impl From<CanonicalDecodingError> for SuccessorActivationError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(Box::new(NodeCoreError::CanonicalDecoding(error)))
    }
}
impl From<NextSetEligibilityError> for SuccessorActivationError {
    fn from(error: NextSetEligibilityError) -> Self {
        match error {
            NextSetEligibilityError::Ineligible => Self::Ineligible,
            NextSetEligibilityError::Prerequisite => Self::EligibilityPrerequisite,
            NextSetEligibilityError::Node(error) => Self::Node(Box::new(error)),
        }
    }
}

/// Closed refusal of per-invocation serving authority.
#[derive(Debug)]
pub enum ServingAuthorityError {
    /// The full source-free evidence rerun refused.
    Evidence(Box<SuccessorActivationError>),
    /// Storage, fencing or encoding failure.
    Node(Box<NodeCoreError>),
    /// Inactive, importing, sealed, corrupt, unsupported or mismatched
    /// destination state. Never a fallback to another authority.
    Refused(&'static str),
}

impl fmt::Display for ServingAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => error.fmt(f),
            Self::Node(error) => error.fmt(f),
            Self::Refused(message) => f.write_str(message),
        }
    }
}

impl Error for ServingAuthorityError {}

impl From<SuccessorActivationError> for ServingAuthorityError {
    fn from(error: SuccessorActivationError) -> Self {
        Self::Evidence(Box::new(error))
    }
}
impl From<NodeCoreError> for ServingAuthorityError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(Box::new(error))
    }
}
impl From<DurableReadError> for ServingAuthorityError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(Box::new(NodeCoreError::from(error)))
    }
}

/// Source-free verified e+1 policy facts, shared read-only by the evidence
/// wrapper and both warrants. There is no public or crate constructor, no
/// `Default` and no serialization. It never carries a local validator id or
/// key: the destination member is a separate warrant-only fact.
#[derive(Debug)]
pub struct SuccessorPolicyInputs {
    context: PublicationContext,
    domain: AtomicityDomainId,
    subject_digest: Digest32,
    genesis_digest: Digest32,
    validator_set: ValidatorSet,
    anchor: Digest32,
    generation_floor: ExecutionGeneration,
    /// Verified outgoing (epoch e) committee digest bound by the cut and the
    /// terminal Seal. It anchors historical certificate-epoch claims only.
    predecessor_set_digest: Digest32,
}

impl SuccessorPolicyInputs {
    /// Verified successor publication context at e+1.
    #[must_use]
    pub const fn context(&self) -> &PublicationContext {
        &self.context
    }
    /// Verified plan atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }
    /// Verified 0xD054 subject digest, v3 anchor field 10.
    #[must_use]
    pub const fn subject_digest(&self) -> Digest32 {
        self.subject_digest
    }
    /// Original pinned genesis digest, unchanged.
    #[must_use]
    pub const fn genesis_digest(&self) -> Digest32 {
        self.genesis_digest
    }
    /// Checked-eligible certified e+1 validator set.
    #[must_use]
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }
    /// Verified v3 successor consensus anchor.
    #[must_use]
    pub const fn anchor(&self) -> Digest32 {
        self.anchor
    }
    /// Verified cut binding generation floor.
    #[must_use]
    pub const fn generation_floor(&self) -> ExecutionGeneration {
        self.generation_floor
    }
    /// Verified outgoing epoch-e committee digest, the only predecessor
    /// certificate scope a successor accepts for imported claims.
    #[must_use]
    pub const fn predecessor_set_digest(&self) -> Digest32 {
        self.predecessor_set_digest
    }
}

/// Exact verified Seal closure bytes from the terminal history height.
struct SealClosure {
    candidate_digest: Digest32,
    request_id: [u8; 32],
    candidate: Vec<u8>,
    header: Vec<u8>,
    outcome: Vec<u8>,
    receipt: Vec<u8>,
    receipt_event_digest: Digest32,
}

/// Module-private source-free evidence. It contains no destination fact.
/// Only the proof QC subset may differ between independently activated
/// hosts, so each host installs the proof bytes its own run verified.
struct VerifiedSuccessorActivation {
    subject: SuccessorActivationSubject,
    subject_digest: Digest32,
    manifest_digest: Digest32,
    import: VerifiedImportPlan,
    next_members: Vec<FastPathValidatorEntry>,
    policy_inputs: SuccessorPolicyInputs,
    outgoing_context: PublicationContext,
    /// Exact verified commit-proof bytes for heights T+1 through h.
    suffix_proofs: Vec<(u64, Vec<u8>)>,
    seal: SealClosure,
}

/// Public read-only wrapper over the private verified chain evidence. Its
/// only constructors are [`verify_successor_authority`] and
/// [`verify_successor_chain_authority`]; it has no `Clone`, `Default` or
/// serialization. Accessors report the last (current) link.
pub struct VerifiedSuccessorAuthority(chain::VerifiedSuccessorChain);

impl VerifiedSuccessorAuthority {
    /// Verified 0xD054 subject digest.
    #[must_use]
    pub const fn subject_digest(&self) -> Digest32 {
        self.0.current().subject_digest
    }
    /// Verified 0xD055 manifest digest of this verification run.
    #[must_use]
    pub const fn manifest_digest(&self) -> Digest32 {
        self.0.current().manifest_digest
    }
    /// Exact last-link inactive import identity, independently verified by
    /// this chain. Read-only transport continuity, never writer authority.
    #[must_use]
    pub const fn import_binding(&self) -> &runtime::ImportBinding {
        self.0.current().import.binding()
    }
    /// Checked-eligible certified e+1 validator set.
    #[must_use]
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.0.current().policy_inputs.validator_set
    }
    /// Verified source-free e+1 policy inputs.
    #[must_use]
    pub const fn policy_inputs(&self) -> &SuccessorPolicyInputs {
        &self.0.current().policy_inputs
    }
    /// Number of verified links, at least one.
    #[must_use]
    pub const fn link_count(&self) -> u32 {
        self.0.link_count()
    }
    /// Verified committee history e_0 through the current epoch.
    pub(crate) fn committees(&self) -> &chain::VerifiedCommitteeHistory {
        self.0.committees()
    }
    /// Verified genesis and registered owner registry.
    pub(crate) fn owners(&self) -> &chain::VerifiedOwnerRegistry {
        self.0.owners()
    }
    /// DR-0191: the current epoch's ordered policy derived privately from
    /// this verified chain (verified predecessor committee, historical
    /// certificate scopes, signed genesis registration economics and the
    /// verified owner registry). `root` must be this chain's own genesis.
    pub fn ordered_policy(
        &self,
        root: &crate::genesis::VerifiedGenesisRoot,
    ) -> Result<crate::ordered_economics::OrderedEconomicsPolicy, SuccessorActivationError> {
        self.0.current_policy(root)
    }

    pub(crate) fn reconstruction_base<'c>(
        &'c self,
        root: &'c crate::genesis::VerifiedGenesisRoot,
    ) -> Result<ReconstructionBase<'c>, SuccessorActivationError> {
        self.0.reconstruction_base(root)
    }

    pub(crate) fn reconstruction_inputs(
        &self,
        plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<ReconstructionInputs, SuccessorActivationError> {
        ReconstructionInputs::new(&self.0, plan)
    }
}

/// Owned per-call policies derived only from verified chain evidence.
pub(crate) struct ReconstructionInputs {
    ordered: crate::ordered_economics::OrderedEconomicsPolicy,
    leg: execution::local_execution::LocalExecutionPolicy,
    paid: execution::local_execution::LocalExecutionPolicy,
}

impl ReconstructionInputs {
    fn new(
        chain: &chain::VerifiedSuccessorChain,
        plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<Self, SuccessorActivationError> {
        if chain.current().policy_inputs.domain != plan.domain {
            return Err(SuccessorActivationError::Invalid(
                "reconstruction plan domain differs from verified chain",
            ));
        }
        let ordered = chain.current_policy(plan.genesis_root)?;
        let leg = execution::local_execution::LocalExecutionPolicy::generic_object_results(
            ordered.context().clone(),
        );
        let paid = execution::local_execution::LocalExecutionPolicy::generic_object_results(
            ordered.context().clone(),
        );
        Ok(Self { ordered, leg, paid })
    }

    pub(crate) fn plan<'q, 'p: 'q>(
        &'q self,
        source: BusinessReconstructionPlan<'p>,
        identity: &'q OrderedHistoryIdentity,
    ) -> BusinessReconstructionPlan<'q> {
        BusinessReconstructionPlan {
            genesis_root: source.genesis_root,
            operation_context: source.operation_context,
            domain: source.domain,
            resolver_history: source.resolver_history,
            ordered_policy: &self.ordered,
            ordered_history_identity: identity,
            ordered_leg_policy: &self.leg,
            ordered_engine: source.ordered_engine,
            paid_base_policy: &self.paid,
            paid_engine: source.paid_engine,
        }
    }
}

/// The one public cross-crate entry: a thin wrapper over the single private
/// source-free verifier, with no duplicated verification logic and no
/// destination store, signing key or live-authority input. It is the chain
/// owner with budget 1.
pub fn verify_successor_authority(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    chain::verify_single_link(plan, manifest_identity, artifacts).map(VerifiedSuccessorAuthority)
}

/// DR-0191 Section 7: the complete pinned ordered chain from the original
/// genesis, each link through the same private verifier. `links.len()` is
/// checked against `budget` before any artifact access.
pub fn verify_successor_chain_authority(
    plan: BusinessReconstructionPlan<'_>,
    links: &[SuccessorLinkPins],
    budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    chain::verify_chain(plan, links, budget, artifacts).map(VerifiedSuccessorAuthority)
}

/// Built only inside [`activate_successor`] while the destination slot is
/// Inactive: the evidence plus a full complete-inventory comparison, the
/// physical namespace validator and the local key. It carries no serving
/// observation, because none exists yet.
struct ActivationWarrant {
    chain: chain::VerifiedSuccessorChain,
    progress: runtime::ImportProgress,
    token: runtime::portable::PortableSnapshotToken,
    namespace_validator: protocol_types::ValidatorId,
    public_key: [u8; 32],
}

/// Per-invocation successor serving authority, built only by
/// [`resolve_live_authority`] from an installed Serving slot plus a fresh
/// full evidence rerun. It is tied to the invocation borrow, never stored
/// past the call, and every successor commit rechecks its exact protected
/// observation in the backend lock.
pub struct LiveWarrant<'inv> {
    chain: chain::VerifiedSuccessorChain,
    /// The exact store borrow that issued this warrant. Every successor
    /// write path requires the store it is handed to be this same object;
    /// there is no public identity flag.
    issuer: &'inv dyn runtime::StructuredStateReader,
    context: &'inv DurableOperationContext,
    observation: SuccessorServingObservation,
    reads: BTreeMap<Vec<u8>, StateRevision>,
}

impl<'inv> LiveWarrant<'inv> {
    /// Verified source-free e+1 policy inputs (context, domain, set, anchor,
    /// subject and floor). Never a local member or key.
    #[must_use]
    pub const fn policy_inputs(&self) -> &SuccessorPolicyInputs {
        &self.chain.current().policy_inputs
    }

    /// The exact raw protected observation every successor commit port
    /// rechecks byte-for-byte inside its lock. Raw continuity, not authority.
    pub(crate) const fn serving_observation(&self) -> &SuccessorServingObservation {
        &self.observation
    }

    /// Deciding CAS reads every successor commit must fold: the installed
    /// e+1 set and three policy rows, the carried-forward epoch-e fee policy
    /// and the exact successor epoch record.
    pub(crate) const fn reads(&self) -> &BTreeMap<Vec<u8>, StateRevision> {
        &self.reads
    }

    /// The invocation context this warrant was resolved under.
    pub(crate) const fn context(&self) -> &'inv DurableOperationContext {
        self.context
    }

    /// Number of fully reverified links in this invocation.
    pub const fn link_count(&self) -> u32 {
        self.chain.link_count()
    }

    pub(crate) fn reconstruction_base<'c>(
        &'c self,
        root: &'c crate::genesis::VerifiedGenesisRoot,
    ) -> Result<ReconstructionBase<'c>, SuccessorActivationError> {
        self.chain.reconstruction_base(root)
    }

    pub fn ordered_policy(
        &self,
        root: &crate::genesis::VerifiedGenesisRoot,
    ) -> Result<crate::ordered_economics::OrderedEconomicsPolicy, SuccessorActivationError> {
        self.chain.current_policy(root)
    }

    pub(crate) fn reconstruction_inputs(
        &self,
        plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<ReconstructionInputs, SuccessorActivationError> {
        ReconstructionInputs::new(&self.chain, plan)
    }

    pub(crate) fn prior_state_row(&self, key: &[u8]) -> Option<&[u8]> {
        self.chain.current().import.rows().iter().find_map(
            |row: &runtime::inactive_import::ImportRow| match row {
                runtime::inactive_import::ImportRow::State {
                    key: found,
                    value: Some(bytes),
                } if found == key => Some(bytes.as_slice()),
                _ => None,
            },
        )
    }
}
