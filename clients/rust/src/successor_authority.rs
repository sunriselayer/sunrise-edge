//! Thin SDK wrapper over the node-core bounded successor-chain verifier
//! (DR-0191 Sections 2 and 9). This is the one entry point
//! `clients/rust` uses to reach it, since the module-private verifier
//! lives in a different module that this crate cannot name directly.

use crate::load_verified_genesis_root;
pub use crate::successor_artifacts::SuccessorLinkArchiveDirectories as SuccessorArtifactDirectories;
use crate::successor_artifacts::{SuccessorChainArtifactFiles, require_successor_chain_budget};
use consensus::FastPathCertifier;
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::admission_profile::VerifiedAdmissionProfile;
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    OrderedEconomicsError, OrderedEconomicsPolicy, OrderedHistoryIdentity,
};
use node_core::serving_authority::{
    SuccessorActivationError, SuccessorArtifactSource, SuccessorChainArtifacts,
    SuccessorChainBudget, SuccessorLinkPins, VerifiedSuccessorAuthority,
    verify_successor_authority, verify_successor_chain_authority,
};
use protocol_types::AtomicityDomainId;
use runtime::{
    DurableOperationContext, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use std::num::NonZeroU32;
use std::path::Path;
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

/// Verifies every pinned link from the original genesis through the current
/// successor. The local budget is checked by core before any artifact call.
pub fn load_successor_chain_authority(
    plan: BusinessReconstructionPlan<'_>,
    links: &[SuccessorLinkPins],
    budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    verify_successor_chain_authority(plan, links, budget, artifacts)
}

/// Source-free e+1 workflow composition for successor clients. The ordered
/// policy feeds the existing ordered submission workflow, the certifier the
/// existing FastVote quorum and apply workflow, and the expected context is
/// checked before any signature is created. Nothing here comes from an
/// endpoint response or a caller epoch flag.
pub struct SuccessorWorkflowAuthority {
    root: VerifiedGenesisRoot,
    authority: VerifiedSuccessorAuthority,
    ordered_policy: OrderedEconomicsPolicy,
    certifier: FastPathCertifier,
    admission_profile: VerifiedAdmissionProfile,
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
    /// A local pin, archive or artifact could not be loaded.
    Load(String),
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
            Self::Load(reason) => write!(f, "successor artifacts refused: {reason}"),
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
    compose_successor_workflow(root, authority)
}

/// Composes the current policy and signing context from the opaque verified
/// chain, preserving original admission and economics and all owner/history
/// provenance. No caller-supplied current epoch or policy participates.
pub fn load_successor_chain_workflow(
    plan: BusinessReconstructionPlan<'_>,
    links: &[SuccessorLinkPins],
    budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts,
) -> Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> {
    let root: &VerifiedGenesisRoot = plan.genesis_root;
    let authority: VerifiedSuccessorAuthority =
        load_successor_chain_authority(plan, links, budget, artifacts)
            .map_err(SuccessorWorkflowError::Authority)?;
    compose_successor_workflow(root, authority)
}

fn compose_successor_workflow(
    root: &VerifiedGenesisRoot,
    authority: VerifiedSuccessorAuthority,
) -> Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> {
    let admission_profile: VerifiedAdmissionProfile = root.admission_profile().clone();
    let ordered_policy: OrderedEconomicsPolicy = authority
        .ordered_policy(root)
        .map_err(SuccessorWorkflowError::Authority)?;
    let context: &PublicationContext = authority.policy_inputs().context();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        authority.validator_set().clone(),
    )
    .map_err(|error| SuccessorWorkflowError::Certifier(error.to_string()))?;
    Ok(SuccessorWorkflowAuthority {
        root: root.clone(),
        authority,
        ordered_policy,
        certifier,
        admission_profile,
    })
}

impl SuccessorWorkflowAuthority {
    /// The independently pinned original root retained by this composition.
    #[must_use]
    pub fn genesis_root(&self) -> &VerifiedGenesisRoot {
        &self.root
    }
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

    /// The original signed admission profile, unchanged at e+1, which still
    /// governs request lanes and the publication gate.
    #[must_use]
    pub fn admission_profile(&self) -> &VerifiedAdmissionProfile {
        &self.admission_profile
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

/// Loads the original pinned genesis (manifest, digest, schedule, context)
/// and domain, composes the private reconstruction plan exactly as the
/// operator does, and runs [load_successor_workflow] over held read-only
/// artifact directories. No destination store, key or endpoint claim is
/// consulted; an ordinary-genesis fallback does not exist here.
pub fn load_successor_workflow_from_directories(
    genesis_manifest: &Path,
    resolver: &HashSuiteResolver,
    expected_genesis_digest: [u8; 32],
    genesis_context: &PublicationContext,
    domain: AtomicityDomainId,
    directories: &SuccessorArtifactDirectories<'_>,
) -> Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> {
    load_successor_chain_workflow_from_directories(
        genesis_manifest,
        resolver,
        expected_genesis_digest,
        genesis_context,
        domain,
        std::slice::from_ref(directories),
        SuccessorChainBudget::new(NonZeroU32::MIN),
    )
}

/// Loads an ordered chain of the existing archive directory roles. The
/// explicit budget and nonempty count are checked before any genesis or
/// artifact I/O. Each link is verified with core's privately derived policy.
#[allow(clippy::too_many_arguments)]
pub fn load_successor_chain_workflow_from_directories(
    genesis_manifest: &Path,
    resolver: &HashSuiteResolver,
    expected_genesis_digest: [u8; 32],
    genesis_context: &PublicationContext,
    domain: AtomicityDomainId,
    directories: &[SuccessorArtifactDirectories<'_>],
    budget: SuccessorChainBudget,
) -> Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> {
    require_successor_chain_budget(directories.len(), budget)
        .map_err(SuccessorWorkflowError::Authority)?;
    let load = |reason: &str, error: &dyn fmt::Display| {
        SuccessorWorkflowError::Load(format!("{reason}: {error}"))
    };
    let root: VerifiedGenesisRoot = load_verified_genesis_root(
        genesis_manifest,
        resolver,
        expected_genesis_digest,
        genesis_context,
    )
    .map_err(|error| load("pinned genesis", &error))?;
    if !root.admission_profile().is_causal() {
        return Err(SuccessorWorkflowError::Load(
            "successor requires a signed causal-admission genesis".into(),
        ));
    }
    let genesis_policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, domain)
            .map_err(SuccessorWorkflowError::Policy)?;
    let mut artifacts: SuccessorChainArtifactFiles =
        SuccessorChainArtifactFiles::open(directories, budget)
            .map_err(SuccessorWorkflowError::Authority)?;
    let links: Vec<SuccessorLinkPins> = artifacts.pins();
    let identity: &OrderedHistoryIdentity = &links
        .first()
        .ok_or_else(|| SuccessorWorkflowError::Load("successor chain is empty".into()))?
        .cut_identity;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(genesis_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
        genesis_root: &root,
        operation_context: private_reconstruction_operation()?,
        domain,
        resolver_history: &[],
        ordered_policy: &genesis_policy,
        ordered_history_identity: identity,
        ordered_leg_policy: &base_policy,
        ordered_engine: &engine,
        paid_base_policy: &base_policy,
        paid_engine: &engine,
    };
    load_successor_chain_workflow(plan, &links, budget, &mut artifacts)
}

/// Exists only for private source-free reconstruction, never authority
/// over a destination store.
fn private_reconstruction_operation() -> Result<DurableOperationContext, SuccessorWorkflowError> {
    let now: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| SuccessorWorkflowError::Load("system clock unavailable".into()))?;
    let invalid = || SuccessorWorkflowError::Load("private reconstruction context invalid".into());
    Ok(DurableOperationContext::new(
        WriterFenceGeneration::new(1).ok_or_else(invalid)?,
        now.checked_add(3_600_000)
            .and_then(StorageDeadline::new)
            .ok_or_else(invalid)?,
        StorageCorrelationId::new([0xB9; 16]).ok_or_else(invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion};

    #[test]
    fn directory_chain_budget_refuses_before_genesis_or_artifact_io() {
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("successor-sdk-budget").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            context.chain_id().clone(),
            context.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let missing: &Path = Path::new("/nonexistent/successor-sdk-budget-before-genesis");
        let directories: Vec<SuccessorArtifactDirectories<'_>> = (0..2)
            .map(|_| SuccessorArtifactDirectories {
                plan_history: missing,
                cut: missing,
                manifest_history: missing,
                certificate: missing,
            })
            .collect();
        let result: Result<SuccessorWorkflowAuthority, SuccessorWorkflowError> =
            load_successor_chain_workflow_from_directories(
                missing,
                &resolver,
                [0; 32],
                &context,
                AtomicityDomainId::new([1; 32]).unwrap(),
                &directories,
                SuccessorChainBudget::new(NonZeroU32::MIN),
            );
        assert!(matches!(
            result,
            Err(SuccessorWorkflowError::Authority(
                SuccessorActivationError::ChainBudgetExceeded {
                    links: 2,
                    budget: 1
                }
            ))
        ));
        assert!(!missing.exists());
    }
}
