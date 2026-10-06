//! DR-0153: node-core side of ordered network economics.
//!
//! This module owns the `node_core::ordered_economics` contract's data types
//! and canonical wire codecs, the canonical domain-separated authority
//! anchor, the pure candidate-authentication check (real outer/leg/evidence
//! signature verification, not merely a structural decode), the typed
//! semantic-refusal preflight, the same-key FastVote reservations one
//! admitted candidate's own address-owned inputs need, the durable
//! leader-proposal and local-vote identity records, writer-free owning business
//! preparation and the bounded physical observation scope, and the
//! `propose`/`process_proposal`/`process_certificate`/`observe_proposal`/
//! `query_status`/`process_tick` orchestrator.
//!
//! It composes `crates/consensus` (`ChainedHotStuff::{propose, on_event,
//! on_observer_event, verify_proposal, verify_vote, verify_certificate,
//! certificate_from_votes, validate_state}` plus
//! `consensus::{decode_proposal, decode_vote, decode_quorum_certificate,
//! encode_consensus_state, decode_consensus_state}`); it does not vendor,
//! duplicate or replace any of that engine's logic.
//!
//! ## Failure discipline
//!
//! DR-0153 draws a hard line between a *deterministic retained rejection*
//! and a *stop*. [`OrderedEconomicsError`] encodes that line in its type:
//!
//! * [`OrderedEconomicsError::Unauthenticated`] -- decided with zero storage
//!   reads, so it is deterministic for every replica: retained rejection.
//! * [`OrderedEconomicsError::Refused`] -- a [`OrderedRefusal`] decided
//!   against a *healthy, present, decodable* committed row by
//!   [`preflight`]: retained rejection, no value or nonce movement.
//! * [`OrderedEconomicsError::RequestHeaderConflict`] -- a boundary conflict
//!   raised before any consensus metadata or business receipt is written.
//! * [`OrderedEconomicsError::Prerequisite`] and
//!   [`OrderedEconomicsError::Node`] -- unknown, missing, corrupt, fenced or
//!   ambiguous: stop local apply, never advance the applied prefix.
//!
//! There is deliberately no `Invalid(&'static str)` bucket that a handler's
//! own free-form invariant string can fall into and become a committed
//! rejection. Every existing handler failure this module does not itself
//! positively classify defaults to a stop.
//!
//! ## Epoch-handoff integration status
//!
//! A signed-genesis minimum height and a committed-eligibility check now
//! warrant `Freeze` before proposal/vote and at ordered execution; successful
//! `Freeze` closes admission for ordinary and ordered business mutations and
//! fresh publication-retention ACKs. This is still only one part of
//! DR-0154. DR-0168 adds bounded complete-frontier proof retention and the
//! ordinary shared-chain `DrainSet`, plus explicit certified member apply.
//! `Seal`, verified next-set readiness and activation, and retirement of
//! the older standalone epoch-transition route must still be
//! integrated before this path can be enabled as a complete handoff.
use super::*;
use runtime::StructuredStateReader;

pub(crate) mod audit_projection;
mod candidate;
mod completion;
mod drain_set;
mod drain_union;
mod durable_keys;
pub(crate) mod engine;
mod evidence_submission;
mod freeze;
mod frontier;
mod identity;
mod observed_read;
pub mod ordered_history;
mod policy;
mod preflight;
mod reservation;
mod seal;

pub use candidate::{
    MAX_ORDERED_CANDIDATE_INTENT_BYTES, OrderedCandidate, OrderedOperationKind,
    decode_ordered_candidate, encode_ordered_candidate,
};
pub(crate) use drain_set::drain_set_record_key;
pub use drain_set::{
    DrainSetIntent, DrainSetRecord, decode_drain_set_intent, decode_drain_set_record,
    encode_drain_set_intent, encode_drain_set_record,
};
pub use drain_union::{
    DrainSignerError, DrainSignerProgress, DrainUnionStep, MAX_DRAIN_SIGNER_PAGE_ENTRIES,
    MAX_DRAIN_UNION_SIGNERS, advance_drain_union, confirm_drain_signer_entry,
    drain_signer_entry_key, drain_signer_progress_key, drain_union_progress_key,
    drain_union_ready_key, import_staged_drain_publication, ingest_drain_signer_page,
    read_drain_signer_progress, staged_drain_signer_identity, verify_drain_ready,
    verify_drain_ready_into,
};
pub(crate) use drain_union::{
    advance_drain_union_gated, confirm_drain_signer_entry_gated,
    import_staged_drain_publication_gated, ingest_drain_signer_page_gated,
};
pub use drain_union::{
    advance_drain_union_successor, confirm_drain_signer_entry_successor,
    import_staged_drain_publication_successor, ingest_drain_signer_page_successor,
    read_drain_signer_progress_successor, staged_drain_signer_identity_successor,
    verify_drain_ready_successor,
};
pub use engine::{
    OrderedEventOutput, OrderedOutcome, OrderedProposal, OrderedStatus,
    decode_ordered_event_output, decode_ordered_outcome, decode_ordered_proposal,
    decode_ordered_refusal_payload, decode_ordered_status, encode_ordered_event_output,
    encode_ordered_outcome, encode_ordered_proposal, encode_ordered_refusal_payload,
    encode_ordered_status, install_ordered_genesis, observe_proposal, observe_proposal_successor,
    process_certificate, process_certificate_successor, process_proposal,
    process_proposal_successor, process_tick, process_tick_successor, propose, propose_successor,
    query_ordered_outcome, query_status, query_status_successor,
};
pub use evidence_submission::{
    MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES, OrderedEvidenceSubmission,
    decode_ordered_evidence_submission, encode_ordered_evidence_submission,
};
pub(crate) use freeze::admission_closure_key;
pub(crate) use freeze::fence_admission_open;
pub use freeze::{
    AdmissionClosureRecord, FreezeIntent, decode_admission_closure_record, decode_freeze_intent,
    encode_admission_closure_record, encode_freeze_intent,
};
pub use frontier::{
    FrozenFrontierError, FrozenFrontierStep, advance_frozen_frontier, read_frozen_frontier_page,
};
pub use frontier::{advance_frozen_frontier_successor, read_frozen_frontier_page_successor};
pub(crate) use ordered_history::verified_committed_block;
pub use ordered_history::{
    MAX_ORDERED_HISTORY_CHUNK_BYTES, MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    OrderedHistoryComponentKind, OrderedHistoryComponentRef, OrderedHistoryHeightDescriptor,
    OrderedHistoryHeightMaterial, OrderedHistoryIdentity, OrderedHistorySummary,
    OrderedHistoryVerifier, VerifiedOrderedHistory, decode_ordered_history_height_descriptor,
    decode_ordered_history_identity, decode_ordered_history_summary,
    encode_ordered_history_height_descriptor, encode_ordered_history_identity,
    encode_ordered_history_summary, ordered_history_component_digest,
    ordered_history_descriptor_digest, query_ordered_history_summary,
    read_ordered_history_component_chunk, read_ordered_history_height_descriptor,
};
pub use policy::{
    ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, OrderedEconomicsEnvironment, OrderedEconomicsPolicy,
    OrderedSealComposition, authenticate_candidate, ordered_economics_authority_anchor,
};
pub(crate) use policy::{OrderedKeyScope, ordered_economics_successor_anchor};
pub(crate) use reservation::{
    OrderedCausalRequirements, OrderedLegAdmission, ordered_causal_requirements,
};
pub use seal::{
    MAX_SEAL_CUT_IDENTITY_BYTES, MAX_SEAL_INTENT_BYTES, MAX_SEAL_OUTCOME_BYTES,
    SEAL_PREDECESSOR_TAG_GENESIS, SEAL_PREDECESSOR_TAG_SUCCESSOR, SealIntent, SealOutcome,
    decode_seal_intent, decode_seal_outcome, encode_seal_intent, encode_seal_outcome,
    seal_certificate_digest, seal_request_id, seal_target_digest,
};
pub(crate) use seal::{decode_seal_cut_identity, seal_cut_identity_digest, seal_next_members};

/// Maximum address-owned object inputs one admitted candidate may reserve.
/// DR-0153's closed profile only ever reserves a bond deposit leg's single
/// sender-owned source object (one per leg, at most two legs in `Replace`),
/// so this is a fail-closed bound, not a capacity target.
pub(crate) const MAX_ORDERED_RESERVED_OBJECTS: usize = 2;

/// One typed semantic refusal: a deterministic business outcome decided
/// against a healthy, present, decodable committed row.
///
/// Every variant is re-evaluable by any replica from the same committed
/// state, moves no value, advances no sender nonce, and releases only the
/// refused candidate's own reservations. Nothing that depends on a row being
/// *absent*, tombstoned, undecodable or fenced is representable here: those
/// are [`OrderedEconomicsError::Prerequisite`] stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedRefusal {
    /// The signed `expected_generation` does not equal the healthy committed
    /// row's own generation (the ordinary stale-resubmission case).
    StaleGeneration,
    /// The signed `expected_previous_row_digest` does not equal the healthy
    /// committed row's own recomputed digest.
    StalePreviousRow,
    /// A signed identity field (resource, escrow request, certificate epoch,
    /// fee output) disagrees with the healthy committed row.
    SignedRowMismatch,
    /// The healthy committed row's own state does not permit this operation.
    IneligibleState,
    /// A signed leg's nonce is not that sender's next nonce for this epoch.
    StaleSenderNonce,
    /// The claimed fee share is absent, already claimed, or a different
    /// amount than the row records.
    ShareUnavailable,
    /// This request id already carries a committed receipt over different
    /// canonical bytes (it was spent through another path).
    RequestCommittedElsewhere,
    /// DR-0154: a business candidate (every kind other than
    /// [`OrderedOperationKind::Freeze`]) committed after admission was
    /// already closed by an earlier committed `Freeze`. The deterministic,
    /// authenticated no-effect closed-epoch refusal: no value or nonce
    /// movement, and the original retained outcome (if any) is untouched.
    ClosedEpoch,
    /// DR-0154: a second `Freeze` candidate committed after admission was
    /// already closed by an earlier one. There is no unfreeze in this
    /// profile, so a later `Freeze` is refused rather than re-applied.
    AlreadyFrozen,
    /// The committed Freeze candidate appeared below the signed genesis
    /// minimum ordered proposal height.
    PrematureFreeze,
    /// The advisory next set was structurally valid, but a healthy committed
    /// bond or resource policy no longer makes one of its members eligible.
    IneligibleNextSet,
    /// DrainSet committed while the authorized epoch was still open.
    NoFreeze,
    /// This epoch already has an immutable committed DrainSet.
    AlreadyDrained,
    /// The declared selection differs from the committed Freeze or verified union.
    ForeignDrainSet,
    /// A healthy immutable signed registration already roots this identity.
    AlreadyRegistered,
    /// A healthy admitted initial collateral leg trapped.
    RegistrationTrapped,
    /// Initial collateral execution produced forbidden effects.
    RegistrationEffects,
    /// Initial collateral amount is not a positive conserved u64.
    RegistrationAmount,
    /// Initial collateral policy is disabled or its minimum is not met.
    RegistrationMinimum,
    /// Initial collateral exceeds the committed maximum exposure.
    RegistrationExposure,
}

impl OrderedRefusal {
    /// Stable wire tag for [`engine`]'s retained outcome payload.
    pub(crate) const fn to_wire(self) -> u16 {
        match self {
            Self::StaleGeneration => 1,
            Self::StalePreviousRow => 2,
            Self::SignedRowMismatch => 3,
            Self::IneligibleState => 4,
            Self::StaleSenderNonce => 5,
            Self::ShareUnavailable => 6,
            Self::RequestCommittedElsewhere => 7,
            Self::ClosedEpoch => 8,
            Self::AlreadyFrozen => 9,
            Self::PrematureFreeze => 10,
            Self::IneligibleNextSet => 11,
            Self::NoFreeze => 12,
            Self::AlreadyDrained => 13,
            Self::ForeignDrainSet => 14,
            Self::AlreadyRegistered => 15,
            Self::RegistrationTrapped => 16,
            Self::RegistrationEffects => 17,
            Self::RegistrationAmount => 18,
            Self::RegistrationMinimum => 19,
            Self::RegistrationExposure => 20,
        }
    }

    pub(crate) fn from_wire(value: u16) -> Result<Self, NodeCoreError> {
        match value {
            1 => Ok(Self::StaleGeneration),
            2 => Ok(Self::StalePreviousRow),
            3 => Ok(Self::SignedRowMismatch),
            4 => Ok(Self::IneligibleState),
            5 => Ok(Self::StaleSenderNonce),
            6 => Ok(Self::ShareUnavailable),
            7 => Ok(Self::RequestCommittedElsewhere),
            8 => Ok(Self::ClosedEpoch),
            9 => Ok(Self::AlreadyFrozen),
            10 => Ok(Self::PrematureFreeze),
            11 => Ok(Self::IneligibleNextSet),
            12 => Ok(Self::NoFreeze),
            13 => Ok(Self::AlreadyDrained),
            14 => Ok(Self::ForeignDrainSet),
            15 => Ok(Self::AlreadyRegistered),
            16 => Ok(Self::RegistrationTrapped),
            17 => Ok(Self::RegistrationEffects),
            18 => Ok(Self::RegistrationAmount),
            19 => Ok(Self::RegistrationMinimum),
            20 => Ok(Self::RegistrationExposure),
            _ => Err(NodeCoreError::PersistenceInvariant(
                "unknown ordered refusal tag",
            )),
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::StaleGeneration => "ordered candidate names a superseded row generation",
            Self::StalePreviousRow => "ordered candidate names a superseded previous row digest",
            Self::SignedRowMismatch => {
                "ordered candidate identity disagrees with the committed row"
            }
            Self::IneligibleState => "committed row state does not permit this ordered operation",
            Self::StaleSenderNonce => "ordered candidate leg nonce is not the sender's next nonce",
            Self::ShareUnavailable => "claimed fee share is unavailable on the committed row",
            Self::RequestCommittedElsewhere => {
                "request id already carries a different committed receipt"
            }
            Self::ClosedEpoch => {
                "ordered candidate committed after admission was closed by a freeze"
            }
            Self::AlreadyFrozen => "admission is already closed by an earlier committed freeze",
            Self::PrematureFreeze => "freeze precedes the signed epoch-end minimum height",
            Self::IneligibleNextSet => "freeze advisory next set is no longer eligible",
            Self::NoFreeze => "drain set committed before any freeze was committed",
            Self::AlreadyDrained => "drain set already committed for this epoch",
            Self::ForeignDrainSet => {
                "drain set union identity disagrees with the local ready union"
            }
            Self::AlreadyRegistered => "validator already has a verified initial registration",
            Self::RegistrationTrapped => "initial collateral leg trapped",
            Self::RegistrationEffects => "initial collateral leg produced forbidden effects",
            Self::RegistrationAmount => "initial collateral amount is not positive and conserved",
            Self::RegistrationMinimum => "initial collateral minimum or enabled policy is not met",
            Self::RegistrationExposure => "initial collateral exceeds committed maximum exposure",
        }
    }
}

impl fmt::Display for OrderedRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Failures specific to ordered-economics candidate handling.
#[derive(Debug)]
pub enum OrderedEconomicsError {
    /// Storage, encoding, fencing or other node-core boundary failure. Per
    /// DR-0153 this must stop local apply and require reconciliation; it is
    /// never treated as, or recorded as, a semantic rejection.
    Node(NodeCoreError),
    /// The pinned profile itself is not a coherent authority anchor (context,
    /// validator set, resolver and consensus parameters must agree). Raised
    /// only while constructing [`OrderedEconomicsPolicy`].
    Policy(&'static str),
    /// Pure authentication failed: the candidate's own canonical bytes,
    /// declared identity, outer signature, an embedded leg's signature, or
    /// its evidence proof. Decided with zero storage reads, so every replica
    /// reaches the same answer -- a deterministic retained rejection.
    Unauthenticated(&'static str),
    /// The candidate's request id is already bound to a different candidate
    /// digest, kind or creation checkpoint. A boundary conflict, raised
    /// before any consensus metadata or business receipt is written, never a
    /// committed semantic rejection.
    RequestHeaderConflict,
    /// A typed business refusal decided against the healthy committed state.
    /// A deterministic retained rejection with no value or nonce movement.
    Refused(OrderedRefusal),
    /// A prerequisite this candidate depends on is absent, tombstoned,
    /// undecodable, fenced or otherwise unknown. Stop: declared catch-up or
    /// recovery is required, and the applied prefix must not advance.
    Prerequisite(&'static str),
    /// This request id already has a **completed** ordered outcome, retained
    /// durably by the invocation that executed it.
    ///
    /// Neither a rejection nor a stop: it is the successful idempotent answer.
    /// It carries the exact original [`OrderedOutcome`] so a caller returns
    /// that instead of placing the candidate a second time, re-executing it,
    /// or re-acquiring the reservations the original invocation already
    /// released. A retained request *header* alone is never completion.
    AlreadyCompleted(Box<OrderedOutcome>),
    /// DR-0189: a first-successor (epoch-scoped) policy never authenticates,
    /// signs, votes for or applies an epoch-handoff control candidate
    /// (`Freeze`, `DrainSet`, `Seal`) or initial `BondRegistration`, and
    /// never installs a fresh ordered genesis. Recurring handoff is
    /// separately reviewed future work. Candidates are refused as the first
    /// check of the one shared pure authentication chokepoint, before any
    /// context, lane or kind-specific authentication. It is a permanent
    /// caller-facing refusal rather than a retained rejection or a storage
    /// stop.
    UnsupportedSuccessorControl,
}

impl OrderedEconomicsError {
    /// Whether this failure is a deterministic, retained semantic outcome the
    /// ordered path may record and advance its applied prefix past.
    #[must_use]
    pub const fn is_semantic_rejection(&self) -> bool {
        matches!(self, Self::Unauthenticated(_) | Self::Refused(_))
    }

    /// Whether this failure must stop local apply and require reconciliation
    /// or declared catch-up instead of advancing the applied prefix.
    #[must_use]
    pub const fn requires_reconciliation(&self) -> bool {
        matches!(self, Self::Node(_) | Self::Prerequisite(_))
    }

    /// The exact retained outcome when this request already completed, else
    /// `None`. The one accessor a network surface needs to turn an idempotent
    /// resubmission into the original answer.
    #[must_use]
    pub fn completed_outcome(&self) -> Option<&OrderedOutcome> {
        match self {
            Self::AlreadyCompleted(outcome) => Some(outcome),
            _ => None,
        }
    }
}

impl fmt::Display for OrderedEconomicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Policy(message)
            | Self::Unauthenticated(message)
            | Self::Prerequisite(message) => f.write_str(message),
            Self::RequestHeaderConflict => {
                f.write_str("ordered candidate request id reused with a different header")
            }
            Self::Refused(refusal) => refusal.fmt(f),
            Self::AlreadyCompleted(_) => {
                f.write_str("ordered candidate request id already completed")
            }
            Self::UnsupportedSuccessorControl => f.write_str(
                "epoch-handoff control or initial registration is unsupported at a first successor",
            ),
        }
    }
}

impl Error for OrderedEconomicsError {}

impl From<crate::EnvelopeError> for OrderedEconomicsError {
    fn from(value: crate::EnvelopeError) -> Self {
        <Self as From<NodeCoreError>>::from(NodeCoreError::from(value))
    }
}

impl From<NodeCoreError> for OrderedEconomicsError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}

impl From<CanonicalEncodingError> for OrderedEconomicsError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalEncoding(value))
    }
}

impl From<CanonicalDecodingError> for OrderedEconomicsError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(value))
    }
}

impl From<RuntimeError> for OrderedEconomicsError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(NodeCoreError::from(value))
    }
}

impl From<DurableReadError> for OrderedEconomicsError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(NodeCoreError::from(value))
    }
}

impl From<HashingError> for OrderedEconomicsError {
    fn from(value: HashingError) -> Self {
        Self::Node(NodeCoreError::Hashing(value))
    }
}

impl From<DurableInvocationError> for OrderedEconomicsError {
    fn from(value: DurableInvocationError) -> Self {
        Self::Node(NodeCoreError::from(value))
    }
}

/// Every existing-handler failure this module cannot positively classify as a
/// deterministic business outcome stops local apply. Exactly one leaf case is
/// promoted to a typed refusal: [`NodeCoreError::RequestIdReuse`], which
/// `durable_reconciliation::reconcile_receipt` raises only when this exact
/// request id already carries a committed receipt over *different* canonical
/// bytes. That is permanently true for every replica from the same committed
/// receipt, so it is a retained rejection rather than a stop.
///
/// Nothing else is enumerated. A missing fee-preparation output, an
/// unavailable custody row, a wrong or absent installed policy, an orphaned
/// history walk and every other `Invalid(&'static str)` an existing handler
/// may raise all fall through to [`OrderedEconomicsError::Prerequisite`] --
/// which is why [`preflight`] must decide the genuine stale/user-invalid
/// refusals *before* the handler ever runs.
const HANDLER_STOP: &str = "ordered candidate execution requires reconciliation";

fn node_failure(error: &NodeCoreError) -> OrderedEconomicsError {
    if matches!(error, NodeCoreError::RequestIdReuse) {
        return OrderedEconomicsError::Refused(OrderedRefusal::RequestCommittedElsewhere);
    }
    OrderedEconomicsError::Prerequisite(HANDLER_STOP)
}

fn admission_failure(
    error: &local_execution::LocalExecutionAdmissionError,
) -> OrderedEconomicsError {
    match error {
        local_execution::LocalExecutionAdmissionError::Node(inner) => node_failure(inner),
        _ => OrderedEconomicsError::Prerequisite(HANDLER_STOP),
    }
}

pub(crate) fn fee_claim_failure(error: &fee_claims::FeeClaimError) -> OrderedEconomicsError {
    match error {
        fee_claims::FeeClaimError::Node(inner) => node_failure(inner),
        fee_claims::FeeClaimError::Admission(inner) => admission_failure(inner),
        fee_claims::FeeClaimError::Equivocation(inner) => equivocation_failure(inner),
        _ => OrderedEconomicsError::Prerequisite(HANDLER_STOP),
    }
}

pub(crate) fn bond_lifecycle_failure(
    error: &bond_lifecycle::BondLifecycleError,
) -> OrderedEconomicsError {
    match error {
        bond_lifecycle::BondLifecycleError::Node(inner) => node_failure(inner),
        bond_lifecycle::BondLifecycleError::Admission(inner) => admission_failure(inner),
        _ => OrderedEconomicsError::Prerequisite(HANDLER_STOP),
    }
}

pub(crate) fn bond_registration_failure(
    error: &bond_lifecycle::registration::BondRegistrationError,
) -> OrderedEconomicsError {
    use bond_lifecycle::registration::{BondRegistrationError, BondRegistrationRefusal};
    match error {
        BondRegistrationError::Refused(refusal) => OrderedEconomicsError::Refused(match refusal {
            BondRegistrationRefusal::AlreadyRegistered => OrderedRefusal::AlreadyRegistered,
            BondRegistrationRefusal::Trapped => OrderedRefusal::RegistrationTrapped,
            BondRegistrationRefusal::ForbiddenEffects => OrderedRefusal::RegistrationEffects,
            BondRegistrationRefusal::InvalidAmount => OrderedRefusal::RegistrationAmount,
            BondRegistrationRefusal::BelowMinimum => OrderedRefusal::RegistrationMinimum,
            BondRegistrationRefusal::AboveMaximum => OrderedRefusal::RegistrationExposure,
            BondRegistrationRefusal::InitialRowMismatch => OrderedRefusal::SignedRowMismatch,
        }),
        BondRegistrationError::Node(inner) => node_failure(inner),
        BondRegistrationError::Admission(inner) => admission_failure(inner),
        _ => OrderedEconomicsError::Prerequisite(HANDLER_STOP),
    }
}

pub(crate) fn equivocation_failure(
    error: &equivocation::EquivocationEvidenceError,
) -> OrderedEconomicsError {
    match error {
        equivocation::EquivocationEvidenceError::Node(inner) => node_failure(inner),
        _ => OrderedEconomicsError::Prerequisite(HANDLER_STOP),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::causal_placement::registration::{
    RegisteredCutFixture, registered_cut_fixture,
};
