//! Thin SDK wrapper over the node-core first-successor evidence verifier
//! (DR-0189 Section 3.2, Section 9). This is the one entry point
//! `clients/rust` uses to reach it, since the module-private verifier
//! lives in a different module that this crate cannot name directly.

use consensus::FastPathCertifier;
use execution::publication::PublicationContext;
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    OrderedEconomicsError, OrderedEconomicsPolicy, OrderedHistoryIdentity,
};
use node_core::serving_authority::{
    SuccessorActivationError, SuccessorArtifactSource, VerifiedSuccessorAuthority,
    verify_successor_authority,
};
use std::{error::Error, fmt};

/// Verifies full source-free successor evidence and returns opaque,
/// read-only authority over it. Takes no destination store, lifecycle,
/// token or local key; authenticates the e+1 committee and v3 anchor
/// directly rather than trusting a destination claim.
pub fn load_successor_authority(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    verify_successor_authority(plan, manifest_identity, artifacts)
}

/// Source-free e+1 workflow composition for successor clients. The ordered
/// policy feeds the existing ordered submission workflow, the certifier the
/// existing FastVote quorum and apply workflow, and the expected context is
/// checked before any signature is created. Nothing here comes from an
/// endpoint response or a caller epoch flag.
pub struct SuccessorWorkflowAuthority {
    authority: VerifiedSuccessorAuthority,
    ordered_policy: OrderedEconomicsPolicy,
    certifier: FastPathCertifier,
}

/// Refusal to compose successor workflows.
#[derive(Debug)]
pub enum SuccessorWorkflowError {
    /// The source-free successor evidence refused.
    Authority(SuccessorActivationError),
    /// The successor ordered policy refused the verified inputs.
    Policy(OrderedEconomicsError),
    /// The verified e+1 committee cannot form a FastVote certifier.
    Certifier(String),
    /// A context to be signed is not exactly the verified e+1 context.
    ContextMismatch,
}

impl fmt::Display for SuccessorWorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(f, "successor authority refused: {error}"),
            Self::Policy(error) => write!(f, "successor ordered policy refused: {error}"),
            Self::Certifier(reason) => write!(f, "successor certifier refused: {reason}"),
            Self::ContextMismatch => {
                f.write_str("signing context is not the verified successor e+1 context")
            }
        }
    }
}

impl Error for SuccessorWorkflowError {}

/// Verifies the full successor evidence and composes the e+1 ordered policy
/// and FastVote certifier from it, with the original genesis root of the
/// same plan. No destination store, key or claim participates.
pub fn load_successor_workflow(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> {
    let root: &VerifiedGenesisRoot = plan.genesis_root;
    let authority: VerifiedSuccessorAuthority =
        load_successor_authority(plan, manifest_identity, artifacts)
            .map_err(SuccessorWorkflowError::Authority)?;
    let ordered_policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(root, authority.policy_inputs())
            .map_err(SuccessorWorkflowError::Policy)?;
    let context: &PublicationContext = authority.policy_inputs().context();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        authority.validator_set().clone(),
    )
    .map_err(|error| SuccessorWorkflowError::Certifier(error.to_string()))?;
    Ok(SuccessorWorkflowAuthority {
        authority,
        ordered_policy,
        certifier,
    })
}

impl SuccessorWorkflowAuthority {
    /// The verified e+1 publication context every new intent must declare.
    #[must_use]
    pub fn expected_context(&self) -> &PublicationContext {
        self.authority.policy_inputs().context()
    }

    /// The successor ordered policy (v3 anchor, e+1 committee and scope).
    #[must_use]
    pub fn ordered_policy(&self) -> &OrderedEconomicsPolicy {
        &self.ordered_policy
    }

    /// The FastVote certifier over the verified e+1 committee.
    #[must_use]
    pub fn fastvote_certifier(&self) -> &FastPathCertifier {
        &self.certifier
    }

    /// The underlying read-only verified authority.
    #[must_use]
    pub fn authority(&self) -> &VerifiedSuccessorAuthority {
        &self.authority
    }

    /// Run before creating any signature for a successor request.
    pub fn require_signing_context(
        &self,
        declared: &PublicationContext,
    ) -> Result<(), SuccessorWorkflowError> {
        if declared != self.expected_context() {
            return Err(SuccessorWorkflowError::ContextMismatch);
        }
        Ok(())
    }
}
