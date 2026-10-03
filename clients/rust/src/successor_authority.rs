//! Thin SDK wrapper over the node-core first-successor evidence verifier
//! (DR-0189 Section 3.2, Section 9). This is the one entry point
//! `clients/rust` uses to reach it, since the module-private verifier
//! lives in a different module that this crate cannot name directly.

use crate::immutable_archive::ImmutableArchiveReader;
use crate::load_verified_genesis_root;
use crate::ordered_history_archive::{
    read_regular_archive_file, read_verified_ordered_history_archive,
};
use crate::successor_artifacts::SuccessorArtifactFiles;
use consensus::FastPathCertifier;
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::admission_profile::VerifiedAdmissionProfile;
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedEconomicsError, OrderedEconomicsPolicy,
    OrderedHistoryHeightMaterial, OrderedHistoryIdentity, decode_ordered_history_identity,
};
use node_core::serving_authority::{
    SuccessorActivationError, SuccessorArtifactSource, VerifiedSuccessorAuthority,
    verify_successor_authority,
};
use protocol_types::AtomicityDomainId;
use runtime::{
    DurableOperationContext, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
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

/// Source-free e+1 workflow composition for successor clients. The ordered
/// policy feeds the existing ordered submission workflow, the certifier the
/// existing FastVote quorum and apply workflow, and the expected context is
/// checked before any signature is created. Nothing here comes from an
/// endpoint response or a caller epoch flag.
pub struct SuccessorWorkflowAuthority {
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
    let admission_profile: VerifiedAdmissionProfile = root.admission_profile().clone();
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
        admission_profile,
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

/// The four existing read-only artifact transports a successor client
/// verifies: the ordered history through T feeding the plan, the saved
/// pre-Seal cut, the full history_export through the Seal height h and the
/// retained readiness certificate directory.
pub struct SuccessorArtifactDirectories<'p> {
    pub plan_history: &'p Path,
    pub cut: &'p Path,
    pub manifest_history: &'p Path,
    pub certificate: &'p Path,
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
    let (identity, _ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        read_verified_ordered_history_archive(&genesis_policy, directories.plan_history)
            .map_err(|error| load("plan ordered history", &error))?;
    let cut: ImmutableArchiveReader = ImmutableArchiveReader::open(directories.cut)
        .map_err(|error| load("saved cut directory", &error))?;
    let manifest_history: ImmutableArchiveReader =
        ImmutableArchiveReader::open(directories.manifest_history)
            .map_err(|error| load("manifest history directory", &error))?;
    let certificate: ImmutableArchiveReader = ImmutableArchiveReader::open(directories.certificate)
        .map_err(|error| load("certificate directory", &error))?;
    let identity_bytes: Vec<u8> = read_regular_archive_file(
        manifest_history.root(),
        Path::new("identity.bin"),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )
    .map_err(|error| load("manifest identity", &error))?;
    // Untrusted transport claim; the core verifier re-derives it.
    let manifest_identity: OrderedHistoryIdentity =
        decode_ordered_history_identity(&identity_bytes)
            .map_err(|error| load("manifest identity", &error))?;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(genesis_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let plan = |operation: DurableOperationContext| BusinessReconstructionPlan {
        genesis_root: &root,
        operation_context: operation,
        domain,
        resolver_history: &[],
        ordered_policy: &genesis_policy,
        ordered_history_identity: &identity,
        ordered_leg_policy: &base_policy,
        ordered_engine: &engine,
        paid_base_policy: &base_policy,
        paid_engine: &engine,
    };
    let mut artifacts: SuccessorArtifactFiles<'_> = SuccessorArtifactFiles::new(
        plan(private_reconstruction_operation()?),
        cut,
        manifest_history,
        certificate,
    );
    load_successor_workflow(
        plan(private_reconstruction_operation()?),
        &manifest_identity,
        &mut artifacts,
    )
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
