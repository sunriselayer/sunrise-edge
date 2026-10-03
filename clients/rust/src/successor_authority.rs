//! Thin SDK wrapper over the node-core first-successor evidence verifier
//! (DR-0189 Section 3.2, Section 9). This is the one entry point
//! `clients/rust` uses to reach it, since the module-private verifier
//! lives in a different module that this crate cannot name directly.

use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::ordered_economics::OrderedHistoryIdentity;
use node_core::serving_authority::{
    SuccessorActivationError, SuccessorArtifactSource, VerifiedSuccessorAuthority,
    verify_successor_authority,
};

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
