//! Explicit, untrusted DrainSet proof closure for private reconstruction.
//!
//! Source signer-entry rows supply claims, never trusted progress. Every
//! selected stream starts from its seed and reproduces its original signed
//! terminal vote. Only existing ingestion/import/confirmation/union handlers
//! create private readiness; source ready/progress/possession rows are not
//! copied. Retaining proof never applies an owned business operation.

use super::{
    BusinessReconstructionOverlay, BusinessReconstructionPlan, OwnedPublicationMaterial,
    ReconstructionEd25519Verifier, SourceBusinessSnapshot, SourceSnapshotRecord,
    VerifiedPublicationSemantic,
};
use crate::NodeCoreError;
use crate::admission_profile::{ExternalRequestLane, require_external_request_lane};
use crate::ordered_economics::{
    DrainSetIntent, DrainSignerError, DrainUnionStep, OrderedCandidate,
    OrderedEconomicsEnvironment, OrderedEconomicsError, OrderedHistoryComponentKind,
    OrderedHistoryHeightMaterial, OrderedHistoryVerifier, OrderedOperationKind,
    advance_drain_union, confirm_drain_signer_entry, decode_drain_set_intent,
    decode_ordered_candidate, drain_signer_entry_key, import_staged_drain_publication,
    ingest_drain_signer_page, staged_drain_signer_identity,
};
use consensus::bundle::{PublicationBundleError, encode_publication_bundle};
use consensus::{
    AvailabilityIdentity, FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierPageVerifier,
    FrozenFrontierVote, MAX_DRAIN_UNION_SIGNERS, MAX_FROZEN_FRONTIER_PAGE_ENTRIES,
    decode_availability_identity, encode_frozen_frontier_page,
};
use protocol_types::{Digest32, HashPurpose, ValidatorId};
use runtime::portable::DurableRecordKey;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    fmt,
};

/// One exact selected signer's untrusted bounded consecutive page stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSetSignerFrontierMaterial {
    /// Must match one validator in the original candidate's exact selection.
    pub signer: ValidatorId,
    /// Individual pages have the existing entry/byte bounds. The full stream
    /// has linear history cost, not a new aggregate frame or history ceiling.
    pub pages: Vec<FrozenFrontierPage>,
}

/// Transport material only, never a verified readiness/application capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSetControlMaterial {
    /// Digest of the exact authenticated original ordered candidate.
    pub candidate_digest: Digest32,
    /// Must equal the candidate's original ascending signed vote selection.
    pub selected_votes: Vec<FrozenFrontierVote>,
    /// Exactly one stream per selected vote, in the same validator order.
    pub signer_frontiers: Vec<DrainSetSignerFrontierMaterial>,
}

/// A bounded control-closure failure. Causes contain no artifact/request body.
#[derive(Debug)]
pub enum DrainSetControlProofError {
    /// Malformed, foreign, conflicting, or unbound control material.
    Invalid(&'static str),
    /// Independently required control closure is unavailable.
    Incomplete(&'static str),
    /// Owning schema or trusted-profile validation failed.
    Node(Box<NodeCoreError>),
    /// The exact locally pinned genesis commitment could not be recomputed.
    Genesis(Box<crate::GenesisError>),
    /// A selected stream failed its real signature/terminal verification.
    Frontier(Box<consensus::FrontierError>),
    /// An ordinary private drain handler refused or could not commit.
    Drain(Box<DrainSignerError>),
    /// Authenticated ordered history or owning preflight refused.
    Ordered(Box<OrderedEconomicsError>),
    /// An individual complete publication bundle violates its existing bound.
    Bundle(Box<PublicationBundleError>),
}

impl fmt::Display for DrainSetControlProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "control proof refused: {reason}"),
            Self::Incomplete(reason) => write!(formatter, "control proof incomplete: {reason}"),
            Self::Node(error) => error.fmt(formatter),
            Self::Genesis(error) => error.fmt(formatter),
            Self::Frontier(error) => error.fmt(formatter),
            Self::Drain(error) => error.fmt(formatter),
            Self::Ordered(error) => error.fmt(formatter),
            Self::Bundle(error) => error.fmt(formatter),
        }
    }
}

impl Error for DrainSetControlProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Node(error) => Some(error.as_ref()),
            Self::Genesis(error) => Some(error.as_ref()),
            Self::Frontier(error) => Some(error.as_ref()),
            Self::Drain(error) => Some(error.as_ref()),
            Self::Ordered(error) => Some(error.as_ref()),
            Self::Bundle(error) => Some(error.as_ref()),
            Self::Invalid(_) | Self::Incomplete(_) => None,
        }
    }
}

impl From<NodeCoreError> for DrainSetControlProofError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(Box::new(error))
    }
}
impl From<crate::GenesisError> for DrainSetControlProofError {
    fn from(error: crate::GenesisError) -> Self {
        Self::Genesis(Box::new(error))
    }
}
impl From<consensus::FrontierError> for DrainSetControlProofError {
    fn from(error: consensus::FrontierError) -> Self {
        Self::Frontier(Box::new(error))
    }
}
impl From<consensus::ConsensusError> for DrainSetControlProofError {
    fn from(error: consensus::ConsensusError) -> Self {
        Self::Frontier(Box::new(consensus::FrontierError::from(error)))
    }
}
impl From<DrainSignerError> for DrainSetControlProofError {
    fn from(error: DrainSignerError) -> Self {
        Self::Drain(Box::new(error))
    }
}
impl From<OrderedEconomicsError> for DrainSetControlProofError {
    fn from(error: OrderedEconomicsError) -> Self {
        Self::Ordered(Box::new(error))
    }
}
impl From<PublicationBundleError> for DrainSetControlProofError {
    fn from(error: PublicationBundleError) -> Self {
        Self::Bundle(Box::new(error))
    }
}

type ControlResult<T> = Result<T, DrainSetControlProofError>;
type CandidateCatalogue = BTreeMap<Digest32, OrderedCandidate>;

fn candidate_digest(
    plan: &BusinessReconstructionPlan<'_>,
    candidate: &OrderedCandidate,
) -> ControlResult<Digest32> {
    let bytes: Vec<u8> = crate::ordered_economics::encode_ordered_candidate(candidate)?;
    Ok(plan
        .resolver
        .hash_for_purpose(candidate.context.epoch(), HashPurpose::NodeEvent, &bytes)
        .map_err(NodeCoreError::from)?)
}

fn require_plan_binding(plan: &BusinessReconstructionPlan<'_>) -> ControlResult<()> {
    if !plan.admission_profile.is_causal()
        || plan.admission_profile.context() != plan.genesis.context()
        || plan.admission_profile.genesis_digest() != plan.pinned_genesis_digest
        || plan.ordered_policy.genesis_digest() != plan.pinned_genesis_digest
        || plan.ordered_policy.context() != plan.genesis.context()
        || plan.ordered_policy.domain() != plan.domain
        || crate::genesis_manifest_commitment(plan.resolver, plan.genesis)?
            != plan.pinned_genesis_digest
    {
        return Err(DrainSetControlProofError::Invalid(
            "control plan differs from locally pinned causal genesis",
        ));
    }
    Ok(())
}

fn component(
    material: &OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
) -> ControlResult<&[u8]> {
    material
        .components
        .iter()
        .find(|(found, _)| *found == kind)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or(DrainSetControlProofError::Incomplete(
            "control original ordered component is missing",
        ))
}

/// Authentication covers order/candidate only. Original result companions do
/// not decide whether control closure is collected or independently required.
fn authenticated_control_candidates(
    plan: &BusinessReconstructionPlan<'_>,
    ordered: &[OrderedHistoryHeightMaterial],
) -> ControlResult<CandidateCatalogue> {
    require_plan_binding(plan)?;
    let mut verifier: OrderedHistoryVerifier = OrderedHistoryVerifier::new(
        plan.ordered_policy.clone(),
        plan.ordered_history_identity.clone(),
    )?;
    let mut candidates: CandidateCatalogue = BTreeMap::new();
    for material in ordered {
        let block: consensus::CommittedBlock = verifier.verify_next_height(material)?;
        let Some(digest) = block.transactions.first().copied() else {
            continue;
        };
        let candidate: OrderedCandidate =
            decode_ordered_candidate(component(material, OrderedHistoryComponentKind::Candidate)?)?;
        if candidate.kind != OrderedOperationKind::DrainSet {
            continue;
        }
        if candidate_digest(plan, &candidate)? != digest {
            return Err(DrainSetControlProofError::Invalid(
                "control original candidate digest differs from proof",
            ));
        }
        match candidates.entry(digest) {
            Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            Entry::Occupied(entry) if entry.get() == &candidate => {}
            Entry::Occupied(_) => {
                return Err(DrainSetControlProofError::Invalid(
                    "control recommit differs from its exact original candidate",
                ));
            }
        }
    }
    verifier.finish()?;
    Ok(candidates)
}

fn pages_from_entries(entries: &[AvailabilityIdentity]) -> ControlResult<Vec<FrozenFrontierPage>> {
    if entries.is_empty() {
        return Ok(vec![FrozenFrontierPage {
            after_request_id: None,
            entries: Vec::new(),
            terminal: true,
        }]);
    }
    let mut pages: Vec<FrozenFrontierPage> = Vec::new();
    let mut after_request_id: Option<[u8; 32]> = None;
    let mut consumed: usize = 0;
    for chunk in entries.chunks(MAX_FROZEN_FRONTIER_PAGE_ENTRIES) {
        consumed = consumed
            .checked_add(chunk.len())
            .ok_or(DrainSetControlProofError::Invalid(
                "control page count overflow",
            ))?;
        let page: FrozenFrontierPage = FrozenFrontierPage {
            after_request_id,
            entries: chunk.to_vec(),
            terminal: consumed == entries.len(),
        };
        // Retain both owning byte and entry bounds before any page is stored.
        encode_frozen_frontier_page(&page)?;
        after_request_id = chunk.last().map(|entry| entry.request_id);
        pages.push(page);
    }
    Ok(pages)
}

/// Reconstructs explicit proof inputs from the captured source only. Source
/// ready/progress/possession rows and running digests are never read here.
/// Canonical entry claims are authenticated by complete original vote streams,
/// not by their presence in storage. Full bundle closure is verified separately
/// by the owned assembler and again by ordinary private drain import.
pub fn drain_control_material_from_source_snapshot(
    snapshot: &SourceBusinessSnapshot,
    plan: &BusinessReconstructionPlan<'_>,
    ordered: &[OrderedHistoryHeightMaterial],
) -> ControlResult<Vec<DrainSetControlMaterial>> {
    snapshot.validate().map_err(|_| {
        DrainSetControlProofError::Invalid("control source snapshot descriptor/value shape")
    })?;
    if snapshot.token.domain() != plan.domain {
        return Err(DrainSetControlProofError::Invalid(
            "control source domain differs",
        ));
    }
    let candidates: CandidateCatalogue = authenticated_control_candidates(plan, ordered)?;
    let state: BTreeMap<Vec<u8>, &SourceSnapshotRecord> = snapshot
        .records
        .iter()
        .filter_map(|record| match record.descriptor.key() {
            DurableRecordKey::State(key) => Some((key.clone(), record)),
            _ => None,
        })
        .collect();
    let mut controls: Vec<DrainSetControlMaterial> = Vec::new();
    for candidate in candidates.values() {
        // The source may legitimately have refused before checking readiness
        // (NoFreeze, a foreign selection, or an exact completed replay). Only
        // complete authenticated streams are optional proof inputs. Absence
        // here grants no authority: private owning preflight later requires
        // every needed stream, and semantic comparison still checks source
        // rows rather than blessing malformed/unrecognized control records.
        if let Ok(control) = available_control_from_source_rows(&state, plan, candidate) {
            controls.push(control);
        }
    }
    Ok(controls)
}

fn available_control_from_source_rows(
    state: &BTreeMap<Vec<u8>, &SourceSnapshotRecord>,
    plan: &BusinessReconstructionPlan<'_>,
    candidate: &OrderedCandidate,
) -> ControlResult<DrainSetControlMaterial> {
    let intent: DrainSetIntent = decode_drain_set_intent(&candidate.intent)?;
    let mut frontiers: Vec<DrainSetSignerFrontierMaterial> =
        Vec::with_capacity(intent.selected_votes.len());
    for vote in &intent.selected_votes {
        let mut prefix: Vec<u8> = drain_signer_entry_key(
            plan.genesis.context().chain_id(),
            plan.genesis.context().epoch(),
            vote.validator,
            &[1; 32],
        )?;
        prefix.truncate(
            prefix
                .len()
                .checked_sub(32)
                .ok_or(DrainSetControlProofError::Invalid(
                    "control signer-entry prefix underflow",
                ))?,
        );
        let mut entries: Vec<AvailabilityIdentity> = Vec::new();
        for (key, record) in state.range(prefix.clone()..) {
            if !key.starts_with(&prefix) {
                break;
            }
            let bytes: &[u8] =
                record
                    .value
                    .as_deref()
                    .ok_or(DrainSetControlProofError::Incomplete(
                        "selected signer entry is tombstoned",
                    ))?;
            let identity: AvailabilityIdentity = decode_availability_identity(bytes)?;
            if drain_signer_entry_key(
                plan.genesis.context().chain_id(),
                plan.genesis.context().epoch(),
                vote.validator,
                &identity.request_id,
            )?
            .as_slice()
                != key.as_slice()
            {
                return Err(DrainSetControlProofError::Invalid(
                    "selected signer-entry key differs from identity",
                ));
            }
            entries.push(identity);
        }
        frontiers.push(DrainSetSignerFrontierMaterial {
            signer: vote.validator,
            pages: pages_from_entries(&entries)?,
        });
    }
    let control: DrainSetControlMaterial = DrainSetControlMaterial {
        candidate_digest: candidate_digest(plan, candidate)?,
        selected_votes: intent.selected_votes,
        signer_frontiers: frontiers,
    };
    validate_bound_control(plan, candidate, &control)?;
    Ok(control)
}

fn validate_bound_control(
    plan: &BusinessReconstructionPlan<'_>,
    candidate: &OrderedCandidate,
    control: &DrainSetControlMaterial,
) -> ControlResult<()> {
    plan.ordered_policy.authenticate_candidate(candidate)?;
    if candidate.kind != OrderedOperationKind::DrainSet
        || candidate_digest(plan, candidate)? != control.candidate_digest
    {
        return Err(DrainSetControlProofError::Invalid(
            "control candidate binding differs",
        ));
    }
    let intent: DrainSetIntent = decode_drain_set_intent(&candidate.intent)?;
    if intent.selected_votes != control.selected_votes
        || control.selected_votes.is_empty()
        || control.selected_votes.len() > MAX_DRAIN_UNION_SIGNERS
        || control.signer_frontiers.len() != control.selected_votes.len()
    {
        return Err(DrainSetControlProofError::Invalid(
            "control material differs from exact original selection",
        ));
    }
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        plan.genesis.context().chain_id().clone(),
        plan.genesis.context().protocol_version(),
        plan.genesis.context().epoch(),
        plan.ordered_policy.engine().validator_set().clone(),
    )?;
    let mut members: BTreeMap<[u8; 32], AvailabilityIdentity> = BTreeMap::new();
    for (vote, frontier) in control.selected_votes.iter().zip(&control.signer_frontiers) {
        if vote.validator != frontier.signer {
            return Err(DrainSetControlProofError::Invalid(
                "control signer order differs",
            ));
        }
        let mut verifier: FrozenFrontierPageVerifier = FrozenFrontierPageVerifier::new(
            plan.resolver,
            &certifier,
            vote.clone(),
            &ReconstructionEd25519Verifier,
        )?;
        for page in &frontier.pages {
            encode_frozen_frontier_page(page)?;
            verifier.push_page(plan.resolver, page)?;
            for identity in &page.entries {
                require_external_request_lane(
                    plan.admission_profile,
                    ExternalRequestLane::Owned,
                    &identity.request_id,
                )?;
                if let Some(previous) = members.insert(identity.request_id, identity.clone())
                    && previous != *identity
                {
                    return Err(DrainSetControlProofError::Invalid(
                        "selected signers disagree on one publication identity",
                    ));
                }
            }
        }
        if verifier.finish()? != *vote {
            return Err(DrainSetControlProofError::Invalid(
                "control signed terminal differs",
            ));
        }
    }
    Ok(())
}

/// Validates every optional supplied control selection against its exact
/// authenticated original history. Missing selections remain absent until the
/// owning independently replayed preflight proves their closure is needed.
/// A valid bound but unnecessary selection is not execution authority and does
/// not change deterministic pre-readiness refusal/recommit precedence.
pub(super) fn validate_control_inputs(
    plan: &BusinessReconstructionPlan<'_>,
    ordered: &[OrderedHistoryHeightMaterial],
    controls: &[DrainSetControlMaterial],
) -> ControlResult<()> {
    let candidates: CandidateCatalogue = authenticated_control_candidates(plan, ordered)?;
    let mut unique: BTreeSet<Digest32> = BTreeSet::new();
    for control in controls {
        if !unique.insert(control.candidate_digest) {
            return Err(DrainSetControlProofError::Invalid(
                "duplicate control original selection",
            ));
        }
        let candidate: &OrderedCandidate =
            candidates
                .get(&control.candidate_digest)
                .ok_or(DrainSetControlProofError::Invalid(
                    "control selection is outside authenticated history",
                ))?;
        validate_bound_control(plan, candidate, control)?;
    }
    Ok(())
}

/// Derives readiness solely in the isolated genesis/replay-owned store. The
/// verified catalogue came from the owning full publication verifier, but
/// every retained bundle is independently checked again by the ordinary drain
/// handlers. No source-store handle, signer, application flag or ready row is
/// accepted by this function.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn prepare_drain_control(
    overlay: &BusinessReconstructionOverlay<'_>,
    candidate: &OrderedCandidate,
    block_height: u64,
    controls: &[DrainSetControlMaterial],
    owned: &[OwnedPublicationMaterial],
    catalog: &[VerifiedPublicationSemantic],
    consumed: &mut BTreeSet<Digest32>,
) -> ControlResult<()> {
    if candidate.kind != OrderedOperationKind::DrainSet {
        return Ok(());
    }
    let plan: &BusinessReconstructionPlan<'_> = &overlay.plan;
    let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: plan.ordered_policy,
        resolver: plan.resolver,
        history: plan.resolver_history,
        leg_policy: plan.ordered_leg_policy,
        engine: plan.ordered_engine,
        blobs: &overlay.blobs,
    };
    if !crate::ordered_economics::engine::reconstruction_drain_readiness_needed(
        &overlay.store,
        &plan.operation_context,
        &environment,
        candidate,
        block_height,
    )? {
        return Ok(());
    }
    let digest: Digest32 = candidate_digest(plan, candidate)?;
    if consumed.contains(&digest) {
        return Err(DrainSetControlProofError::Invalid(
            "previously derived private control readiness was lost",
        ));
    }
    let control: &DrainSetControlMaterial = controls
        .iter()
        .find(|control| control.candidate_digest == digest)
        .ok_or(DrainSetControlProofError::Incomplete(
            "independently required DrainSet control closure is missing",
        ))?;
    validate_bound_control(plan, candidate, control)?;
    if catalog.len() != owned.len() {
        return Err(DrainSetControlProofError::Invalid(
            "publication catalogue position differs",
        ));
    }
    let members: BTreeMap<[u8; 32], usize> = catalog
        .iter()
        .enumerate()
        .map(|(index, member)| (member.identity.request_id, index))
        .collect();
    let mut unique_members: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (vote, frontier) in control.selected_votes.iter().zip(&control.signer_frontiers) {
        for page in &frontier.pages {
            ingest_drain_signer_page(
                &overlay.store,
                &plan.operation_context,
                plan.domain,
                plan.resolver,
                plan.genesis.context(),
                frontier.signer,
                vote.clone(),
                page.clone(),
            )?;
            for entry in &page.entries {
                let staged: AvailabilityIdentity = staged_drain_signer_identity(
                    &overlay.store,
                    &plan.operation_context,
                    plan.domain,
                    plan.genesis.context(),
                    frontier.signer,
                )?;
                if staged != *entry {
                    return Err(DrainSetControlProofError::Invalid(
                        "private staged identity differs",
                    ));
                }
                let index: usize = *members.get(&staged.request_id).ok_or(
                    DrainSetControlProofError::Incomplete("selected full publication is missing"),
                )?;
                if catalog[index].identity != staged {
                    return Err(DrainSetControlProofError::Invalid(
                        "selected full publication identity conflicts with catalogue",
                    ));
                }
                let bundle: Vec<u8> = encode_publication_bundle(&owned[index].bundle)?;
                let imported: AvailabilityIdentity = import_staged_drain_publication(
                    &overlay.store,
                    &plan.operation_context,
                    plan.domain,
                    plan.resolver,
                    plan.resolver_history,
                    plan.genesis.context(),
                    frontier.signer,
                    &bundle,
                )?;
                if imported != staged {
                    return Err(DrainSetControlProofError::Invalid(
                        "private imported identity differs",
                    ));
                }
                let confirmed: AvailabilityIdentity = confirm_drain_signer_entry(
                    &overlay.store,
                    &plan.operation_context,
                    plan.domain,
                    plan.resolver,
                    plan.resolver_history,
                    plan.genesis.context(),
                    frontier.signer,
                    staged.request_id,
                )?;
                if confirmed != staged {
                    return Err(DrainSetControlProofError::Invalid(
                        "private confirmed identity differs",
                    ));
                }
                unique_members.insert(staged.request_id);
            }
        }
    }
    let mut expected_count: u64 = 0;
    for _ in 0..=unique_members.len() {
        match advance_drain_union(
            &overlay.store,
            &plan.operation_context,
            plan.domain,
            plan.resolver,
            plan.resolver_history,
            plan.genesis.context(),
            &control.selected_votes,
        )? {
            DrainUnionStep::Advanced { member_count } => {
                expected_count =
                    expected_count
                        .checked_add(1)
                        .ok_or(DrainSetControlProofError::Invalid(
                            "control union count overflow",
                        ))?;
                if member_count != expected_count {
                    return Err(DrainSetControlProofError::Invalid(
                        "private union progress differs",
                    ));
                }
            }
            DrainUnionStep::Ready(identity) => {
                if identity.member_count
                    != u64::try_from(unique_members.len()).map_err(|_| {
                        DrainSetControlProofError::Invalid("control unique count overflow")
                    })?
                {
                    return Err(DrainSetControlProofError::Invalid(
                        "private ready union differs from authenticated stream count",
                    ));
                }
                // The candidate may legitimately claim a wrong union and be
                // refused. Readiness is derived from actual selected streams;
                // the ordinary owning handler, not this scheduler, compares
                // the candidate claim and produces its original response.
                consumed.insert(digest);
                return Ok(());
            }
        }
    }
    Err(DrainSetControlProofError::Incomplete(
        "private union did not reach exact terminal",
    ))
}

#[cfg(test)]
mod tests {
    use super::pages_from_entries;
    use consensus::{
        AvailabilityIdentity, FrozenFrontierPage, MAX_FROZEN_FRONTIER_PAGE_BYTES,
        MAX_FROZEN_FRONTIER_PAGE_ENTRIES, decode_frozen_frontier_page, encode_frozen_frontier_page,
    };
    use protocol_types::{
        AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion,
    };

    // Codec/partition fixture only: these claims provide no signature, source
    // completeness, retained bundle, or independent execution authority.
    fn identity(index: u64) -> AvailabilityIdentity {
        let mut request_id: [u8; 32] = [0; 32];
        request_id[24..].copy_from_slice(&index.to_be_bytes());
        let digest: Digest32 = Digest32::new(HashAlgorithmId::Blake3_256, [0x91; 32]);
        AvailabilityIdentity {
            chain_id: ChainId::new("bounded-control-pages").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(3),
            domain: AtomicityDomainId::new([0x92; 32]).unwrap(),
            request_id,
            signed_intent_digest: digest,
            execution_commitment: digest,
            semantic_artifacts_digest: digest,
        }
    }

    #[test]
    fn source_entry_partition_is_bounded_consecutive_and_has_one_exact_terminal() {
        let length: usize = 2 * MAX_FROZEN_FRONTIER_PAGE_ENTRIES + 1;
        let entries: Vec<AvailabilityIdentity> =
            (1..=u64::try_from(length).unwrap()).map(identity).collect();
        let pages: Vec<FrozenFrontierPage> = pages_from_entries(&entries).unwrap();
        assert_eq!(pages.len(), 3);
        let mut previous: Option<[u8; 32]> = None;
        let mut restored: Vec<AvailabilityIdentity> = Vec::new();
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(page.after_request_id, previous);
            assert!(page.entries.len() <= MAX_FROZEN_FRONTIER_PAGE_ENTRIES);
            assert_eq!(page.terminal, index + 1 == pages.len());
            let bytes: Vec<u8> = encode_frozen_frontier_page(page).unwrap();
            assert!(bytes.len() <= MAX_FROZEN_FRONTIER_PAGE_BYTES);
            assert_eq!(decode_frozen_frontier_page(&bytes).unwrap(), *page);
            previous = page.entries.last().map(|entry| entry.request_id);
            restored.extend_from_slice(&page.entries);
        }
        assert_eq!(restored, entries);
    }

    #[test]
    fn empty_source_frontier_still_requires_one_seed_terminal_page() {
        let pages: Vec<FrozenFrontierPage> = pages_from_entries(&[]).unwrap();
        assert_eq!(
            pages,
            vec![FrozenFrontierPage {
                after_request_id: None,
                entries: Vec::new(),
                terminal: true,
            }]
        );
        let bytes: Vec<u8> = encode_frozen_frontier_page(&pages[0]).unwrap();
        assert_eq!(decode_frozen_frontier_page(&bytes).unwrap(), pages[0]);
    }
}
