//! Signed-genesis external-request lanes and fresh direct-writer boundary.
//!
//! The profile tag alone is descriptive, not authority. Pure authentication
//! accepts only [`VerifiedAdmissionProfile`], constructed by verifying a locally
//! pinned signed genesis. Mutating paths additionally fence that installed
//! binding. These configuration CAS reads are not business witness operands:
//! local install-marker checkpoints must never change a certified commitment.
use std::collections::BTreeMap;

use execution::publication::PublicationContext;
use protocol_types::{Digest32, HashPurpose};
use runtime::{
    AtomicityDomainId, DurableOperationContext, StateRevision, VersionedStateReader,
    VersionedStateValue,
};

use crate::NodeCoreError;
#[cfg(test)]
use crate::genesis::genesis_manifest_commitment;
use crate::genesis::{
    GenesisInstallMarker, GenesisManifest, decode_genesis_install_marker, decode_genesis_manifest,
    genesis_manifest_key, genesis_marker_key,
};
use crate::logical_generation::{
    CommitmentProfile, InstalledCommitmentProfile, LogicalProfileRecord, fence_commitment_profile,
    logical_profile_key,
};
#[cfg(test)]
use hashing::HashSuiteResolver;

#[cfg(test)]
mod tests;

/// Disjoint original external request identities in the fresh causal profile.
/// Internal synthetic prepare identities remain excluded in both lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalRequestLane {
    /// Standalone owned paid intent: the most significant bit is zero.
    Owned,
    /// Ordered candidate, including embedded legs: the bit is one.
    Ordered,
}

/// A privately constructed signed-genesis profile, rooted in a local digest pin.
///
/// This is not an execution certificate or bootstrap-effects proof. Its context
/// is the original genesis context, not a caller-selected current epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdmissionProfile {
    profile: CommitmentProfile,
    context: PublicationContext,
    genesis_digest: Digest32,
    genesis_authority: [u8; 32],
    minimum_freeze_block_height: u64,
}

impl VerifiedAdmissionProfile {
    /// Root-only crate-private verified construction (DR-0182). The only
    /// public path to a [`VerifiedAdmissionProfile`] is
    /// [`crate::genesis::VerifiedGenesisRoot::verify_bytes`], which performs
    /// the pin/context/resolver/round-trip/authority checks this type used to
    /// duplicate as an independent public authenticator.
    pub(crate) fn from_verified_manifest(manifest: &GenesisManifest, digest: Digest32) -> Self {
        Self {
            profile: manifest.commitment_profile,
            context: manifest.context().clone(),
            genesis_digest: digest,
            genesis_authority: manifest.genesis_authority,
            minimum_freeze_block_height: manifest.minimum_freeze_block_height,
        }
    }

    fn from_verified_record(record: &LogicalProfileRecord) -> Self {
        Self {
            profile: record.profile,
            context: record.context.clone(),
            genesis_digest: record.manifest_digest,
            genesis_authority: record.genesis_authority,
            minimum_freeze_block_height: record.minimum_freeze_block_height,
        }
    }

    /// Returns the authenticated descriptive profile, not mutation authority.
    #[must_use]
    pub const fn commitment_profile(&self) -> CommitmentProfile {
        self.profile
    }

    /// Returns the original locally pinned genesis context.
    #[must_use]
    pub const fn context(&self) -> &PublicationContext {
        &self.context
    }

    /// Returns the exact signed manifest digest this profile was verified from.
    #[must_use]
    pub const fn genesis_digest(&self) -> Digest32 {
        self.genesis_digest
    }

    /// Whether the authenticated genesis explicitly selects causal admission.
    #[must_use]
    pub const fn is_causal(&self) -> bool {
        matches!(self.profile, CommitmentProfile::CausalAdmission)
    }
}

/// Pure bounded lane validation under authenticated genesis authority.
/// Historical profiles retain their old ID interpretation; synthetic IDs
/// remain invalid even when the namespace bit matches the requested lane.
pub fn require_external_request_lane(
    profile: &VerifiedAdmissionProfile,
    lane: ExternalRequestLane,
    request_id: &[u8; 32],
) -> Result<(), NodeCoreError> {
    crate::local_instance_state::reject_reserved_request_id(request_id).map_err(invalid)?;
    if request_id == &[0; 32] {
        return Err(invalid("zero external request id"));
    }
    if profile.is_causal()
        && ((request_id[0] & 0x80 != 0) != matches!(lane, ExternalRequestLane::Ordered))
    {
        return Err(invalid(
            "external request id is in the wrong admission lane",
        ));
    }
    Ok(())
}

/// Fences the installed profile and rejects wrong-lane fresh admission.
/// `expected` is trusted composition, never decoded request context. A present
/// profile supplies its original genesis root independently of the live epoch.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fence_installed_external_request_lane<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    request_id: &[u8; 32],
    lane: ExternalRequestLane,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    if let Some(profile) = resolve_installed(store, context, domain, expected, reads)? {
        require_external_request_lane(&profile, lane, request_id)?;
    } else {
        crate::local_instance_state::reject_reserved_request_id(request_id).map_err(invalid)?;
    }
    Ok(())
}

/// Reconciles a private locally pinned profile with its installed association.
/// Call before nonce/object work and merge `reads` into the admission's CAS.
pub(crate) fn fence_verified_admission_profile<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &VerifiedAdmissionProfile,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let installed: InstalledCommitmentProfile =
        fence_commitment_profile(store, context, domain, expected.context().chain_id(), reads)?;
    if match installed.logical() {
        Some(record) => VerifiedAdmissionProfile::from_verified_record(record) != *expected,
        None => expected.profile.is_logical(),
    } {
        return Err(invalid(
            "installed admission profile differs from pinned genesis",
        ));
    }
    // Legacy logical test fixtures can intentionally omit their signed
    // manifest. A caller carrying a real genesis pin never gets that exception.
    fence_manifest_and_marker(store, context, domain, expected, reads)
}

/// Refuses fresh untracked/direct business writers in the causal profile.
/// Exact completed receipt reconciliation must precede this check. No caller
/// boolean, decoded certificate or stored tag supplies a certified bypass.
pub(crate) fn require_historical_direct_writer<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    if resolve_installed(store, context, domain, expected, reads)?
        .is_some_and(|profile| profile.is_causal())
    {
        return Err(invalid(
            "causal admission requires a certified business path",
        ));
    }
    Ok(())
}

fn resolve_installed<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<Option<VerifiedAdmissionProfile>, NodeCoreError> {
    // Even a pristine slot is an admission dependency: a concurrent fresh
    // v4 install must reject this legacy writer's final CAS, not let it
    // execute under one interpretation and commit under another.
    let profile_key: Vec<u8> = logical_profile_key(expected.chain_id())?;
    fence_read(store, context, domain, profile_key, reads)?;
    let installed: InstalledCommitmentProfile =
        fence_commitment_profile(store, context, domain, expected.chain_id(), reads)?;
    if let Some(record) = installed.logical() {
        if record.context.protocol_version() != expected.protocol_version() {
            return Err(invalid("installed admission profile protocol differs"));
        }
        let verified: VerifiedAdmissionProfile =
            VerifiedAdmissionProfile::from_verified_record(record);
        if verified.is_causal() {
            fence_verified_admission_profile(store, context, domain, &verified, reads)?;
        } else {
            // The old v1 logical fixture exception permits an absent manifest
            // at the record's own root. It must not let a forged/downshifted
            // row redirect this composition away from an installed v4 root.
            refuse_conflicting_composition_root(store, context, domain, expected, record, reads)?;
        }
        return Ok(Some(verified));
    }
    // A pristine missing profile is not by itself proof of a historical
    // store. Consult the trusted root's immutable manifest and marker too.
    let manifest_key: Vec<u8> =
        genesis_manifest_key(expected).map_err(|_| invalid("admission profile genesis key"))?;
    let marker_key: Vec<u8> =
        genesis_marker_key(expected).map_err(|_| invalid("admission profile marker key"))?;
    let manifest_row: VersionedStateValue =
        fence_read(store, context, domain, manifest_key, reads)?;
    let marker_row: VersionedStateValue = fence_read(store, context, domain, marker_key, reads)?;
    if manifest_row.value().is_none()
        && marker_row.value().is_none()
        && manifest_row.revision() == StateRevision::INITIAL
        && marker_row.revision() == StateRevision::INITIAL
    {
        // Preserve the historical interpretation. Absence CAS remains only
        // local admission configuration, never a signed witness operand.
        return Ok(None);
    }
    let manifest: GenesisManifest = decode_genesis_manifest(
        manifest_row
            .value()
            .ok_or(invalid("installed admission genesis is missing"))?,
    )
    .map_err(|_| invalid("installed admission genesis is malformed"))?;
    if manifest.context() != expected
        || manifest.commitment_profile != CommitmentProfile::PhysicalCheckpointV1
    {
        return Err(invalid(
            "installed signed genesis requires its missing profile",
        ));
    }
    verify_signature(&manifest)?;
    let marker: GenesisInstallMarker = decode_genesis_install_marker(
        marker_row
            .value()
            .ok_or(invalid("installed admission marker is missing"))?,
    )
    .map_err(|_| invalid("installed admission marker is malformed"))?;
    let verified: VerifiedAdmissionProfile =
        VerifiedAdmissionProfile::from_verified_manifest(&manifest, marker.manifest_digest);
    verify_marker_and_manifest(
        &verified,
        &manifest,
        &marker,
        manifest_row.value().unwrap_or_default(),
    )?;
    // Historical signed binding bytes and witness read operands are frozen;
    // the independent configuration reads still join the local commit CAS.
    Ok(Some(verified))
}

fn refuse_conflicting_composition_root<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    record: &LogicalProfileRecord,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let manifest_key: Vec<u8> =
        genesis_manifest_key(expected).map_err(|_| invalid("admission profile genesis key"))?;
    let marker_key: Vec<u8> =
        genesis_marker_key(expected).map_err(|_| invalid("admission profile marker key"))?;
    let manifest_row: VersionedStateValue =
        fence_read(store, context, domain, manifest_key, reads)?;
    let marker_row: VersionedStateValue = fence_read(store, context, domain, marker_key, reads)?;
    if record.context != *expected {
        let original_manifest_key: Vec<u8> = genesis_manifest_key(&record.context)
            .map_err(|_| invalid("admission profile genesis key"))?;
        let original_marker_key: Vec<u8> = genesis_marker_key(&record.context)
            .map_err(|_| invalid("admission profile marker key"))?;
        fence_read(store, context, domain, original_manifest_key, reads)?;
        fence_read(store, context, domain, original_marker_key, reads)?;
    }
    if let Some(bytes) = manifest_row.value() {
        let manifest: GenesisManifest = decode_genesis_manifest(bytes)
            .map_err(|_| invalid("installed admission genesis is malformed"))?;
        if manifest.context() != expected
            || manifest.commitment_profile != record.profile
            || manifest.minimum_freeze_block_height != record.minimum_freeze_block_height
            || manifest.genesis_authority != record.genesis_authority
            || manifest.context() != &record.context
            || !hashing::verify_digest(
                &record.manifest_digest,
                HashPurpose::ProtocolConfig,
                expected.protocol_version(),
                expected.chain_id(),
                bytes,
            )?
        {
            return Err(invalid(
                "installed admission profile redirects the trusted genesis root",
            ));
        }
    } else if marker_row.value().is_some()
        || marker_row.revision() != StateRevision::INITIAL
        || manifest_row.revision() != StateRevision::INITIAL
    {
        return Err(invalid("installed admission genesis is missing"));
    }
    Ok(())
}

fn fence_manifest_and_marker<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &VerifiedAdmissionProfile,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let manifest_key: Vec<u8> = genesis_manifest_key(expected.context())
        .map_err(|_| invalid("admission profile genesis key"))?;
    let marker_key: Vec<u8> = genesis_marker_key(expected.context())
        .map_err(|_| invalid("admission profile marker key"))?;
    let manifest_row: VersionedStateValue =
        fence_read(store, context, domain, manifest_key, reads)?;
    let marker_row: VersionedStateValue = fence_read(store, context, domain, marker_key, reads)?;
    let bytes: &[u8] = manifest_row
        .value()
        .ok_or(invalid("installed admission genesis is missing"))?;
    let manifest: GenesisManifest = decode_genesis_manifest(bytes)
        .map_err(|_| invalid("installed admission genesis is malformed"))?;
    let marker: GenesisInstallMarker = decode_genesis_install_marker(
        marker_row
            .value()
            .ok_or(invalid("installed admission marker is missing"))?,
    )
    .map_err(|_| invalid("installed admission marker is malformed"))?;
    verify_marker_and_manifest(expected, &manifest, &marker, bytes)?;
    verify_signature(&manifest)?;
    // Historical genesis has no logical row, but a token-pinned composition
    // still fences its absence without altering any signed business operand.
    if !expected.profile.is_logical() {
        let key: Vec<u8> = logical_profile_key(expected.context().chain_id())?;
        let row: VersionedStateValue = fence_read(store, context, domain, key, reads)?;
        if row.value().is_some() || row.revision() != StateRevision::INITIAL {
            return Err(invalid("historical admission profile is not pristine"));
        }
    }
    Ok(())
}

fn verify_marker_and_manifest(
    expected: &VerifiedAdmissionProfile,
    manifest: &GenesisManifest,
    marker: &GenesisInstallMarker,
    bytes: &[u8],
) -> Result<(), NodeCoreError> {
    if VerifiedAdmissionProfile::from_verified_manifest(manifest, expected.genesis_digest)
        != *expected
        || marker.context != expected.context
        || marker.manifest_digest != expected.genesis_digest
        || marker.genesis_authority != expected.genesis_authority
        || !hashing::verify_digest(
            &expected.genesis_digest,
            HashPurpose::ProtocolConfig,
            expected.context.protocol_version(),
            expected.context.chain_id(),
            bytes,
        )?
    {
        return Err(invalid("installed admission genesis association differs"));
    }
    Ok(())
}

/// Shares the installer/root's own strict nonzero canonical prime-order
/// Ed25519 authority and signature check (DR-0182), so this installed-profile
/// verifier can never accept a weaker authority shape than either.
fn verify_signature(manifest: &GenesisManifest) -> Result<(), NodeCoreError> {
    crate::genesis::verify_manifest_authority(manifest)
        .map_err(|_| invalid("admission genesis authority or signature is invalid"))
}

fn fence_read<S: VersionedStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: Vec<u8>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<VersionedStateValue, NodeCoreError> {
    let seen: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
    if let Some(previous) = reads.insert(key, seen.revision())
        && previous != seen.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(seen)
}

const fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}
