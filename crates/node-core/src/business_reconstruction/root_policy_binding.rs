//! One immutable root/policy relation for private reconstruction consumers.
//!
//! The separate stages let each owner retain its companion checks and exact
//! diagnostic precedence. Success is only configuration agreement, never a
//! serving, completed-cut, readiness, Seal or activation capability.

use crate::genesis::VerifiedGenesisRoot;
use crate::ordered_economics::{OrderedEconomicsPolicy, ordered_economics_authority_anchor};
use protocol_types::Digest32;
use runtime::AtomicityDomainId;

#[derive(Debug)]
pub(super) struct ConfigurationMismatch;

/// Checks the still-independent immutable policy/domain inputs against one
/// authenticated causal root. Equality includes the complete resolver schedule
/// and original committee, even when an active suite or anchor already agrees.
pub(super) fn require_configuration(
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    domain: AtomicityDomainId,
) -> Result<(), ConfigurationMismatch> {
    if !root.admission_profile().is_causal()
        || policy.context() != root.manifest().context()
        || policy.domain() != domain
        || policy.genesis_digest() != root.digest()
        || policy.resolver().schedules() != root.genesis_resolver().schedules()
        || policy.engine().validator_set() != root.genesis_committee()
    {
        return Err(ConfigurationMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub(super) enum RootAnchorBindingError {
    Derivation,
    Mismatch,
}

/// Re-derives the canonical anchor from the exact authenticated root, including
/// its signed Freeze height. A historical policy with copied digest/domain/
/// committee bytes, or its internally consistent history, cannot replace it.
pub(super) fn require_root_anchor(
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    domain: AtomicityDomainId,
) -> Result<(), RootAnchorBindingError> {
    let expected_anchor: Digest32 = ordered_economics_authority_anchor(
        root.genesis_resolver(),
        root.manifest().context(),
        domain,
        root.digest(),
        root.manifest().minimum_freeze_block_height,
        root.genesis_committee(),
    )
    .map_err(|_| RootAnchorBindingError::Derivation)?;
    if policy.anchor() != expected_anchor {
        return Err(RootAnchorBindingError::Mismatch);
    }
    Ok(())
}
