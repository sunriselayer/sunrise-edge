//! DR-0153: node-core side of ordered network economics.
//!
//! This module owns the `node_core::ordered_economics` contract's data types
//! and canonical wire codecs, the canonical domain-separated authority
//! anchor, the pure candidate-authentication check (real outer/leg/evidence
//! signature verification, not merely a structural decode), the typed
//! semantic-refusal preflight, the same-key FastVote reservations one
//! admitted candidate's own address-owned inputs need, the durable
//! leader-proposal and local-vote identity records, the private staging-store
//! adapter that captures an existing economics handler's transaction without
//! publishing it, and the
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
//! fresh publication-retention ACKs. `DrainSet` is now integrated as a
//! second closed-admission control command ([`drain_set`]): before honest
//! proposal/vote it locally re-verifies exact drain-union readiness via
//! [`drain_union::verify_drain_ready_into`] and folds every resulting
//! revision assertion into the same durable commit as the signed
//! proposal/vote; at committed execution it re-verifies readiness through the
//! staging store and installs the one-per-epoch immutable
//! [`drain_set::DrainSetRecord`]. This is still only one part of DR-0154.
//! `Seal`, verified next-set readiness and activation, and retirement of the
//! older standalone epoch-transition route must be integrated before this
//! path can be enabled as a complete handoff.
use super::*;

mod candidate;
mod drain_set;
mod drain_union;
pub(crate) mod engine;
mod evidence_submission;
mod freeze;
mod frontier;
mod identity;
mod policy;
mod preflight;
mod reservation;
mod staging;

pub use candidate::{
    MAX_ORDERED_CANDIDATE_INTENT_BYTES, OrderedCandidate, OrderedOperationKind,
    decode_ordered_candidate, encode_ordered_candidate,
};
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
pub use engine::{
    OrderedEventOutput, OrderedOutcome, OrderedProposal, OrderedStatus,
    decode_ordered_event_output, decode_ordered_outcome, decode_ordered_proposal,
    decode_ordered_refusal_payload, decode_ordered_status, encode_ordered_event_output,
    encode_ordered_outcome, encode_ordered_proposal, encode_ordered_refusal_payload,
    encode_ordered_status, install_ordered_genesis, observe_proposal, process_certificate,
    process_proposal, process_tick, propose, query_ordered_outcome, query_status,
};
pub use evidence_submission::{
    MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES, OrderedEvidenceSubmission,
    decode_ordered_evidence_submission, encode_ordered_evidence_submission,
};
pub use freeze::{
    AdmissionClosureRecord, FreezeIntent, decode_admission_closure_record, decode_freeze_intent,
    encode_admission_closure_record, encode_freeze_intent,
};
pub(crate) use freeze::{admission_closure_key, fence_admission_open};
pub use frontier::{
    FrozenFrontierError, FrozenFrontierStep, advance_frozen_frontier, read_frozen_frontier_page,
};
pub use policy::{
    ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, OrderedEconomicsEnvironment, OrderedEconomicsPolicy,
    authenticate_candidate, ordered_economics_authority_anchor,
};
pub(crate) use reservation::OrderedLegAdmission;
pub(crate) use staging::StagingStore;

/// Maximum address-owned object inputs one admitted candidate may reserve.
/// DR-0153's closed profile only ever reserves a bond deposit leg's single
/// sender-owned source object (one per leg, at most two legs in `Replace`),
/// so this is a fail-closed bound, not a capacity target.
pub(crate) const MAX_ORDERED_RESERVED_OBJECTS: usize = 2;

/// One typed semantic refusal: a deterministic business outcome decided
/// against a healthy, present, decodable committed row.
///
/// Business variants are re-evaluable by any replica from the same committed
/// state. `ForeignDrainSet` additionally requires the same locally retained
/// DrainSet-ready selection; a replica still importing that selection stops
/// before deciding the refusal. Every variant moves no value, advances no
/// sender nonce, and releases only the refused candidate's own reservations.
/// Tombstoned, undecodable or fenced prerequisites are stops, not refusals;
/// `NoFreeze` is the explicitly modeled initially absent closure exception.
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
    /// [`OrderedOperationKind::Freeze`] and [`OrderedOperationKind::DrainSet`]) committed after admission was
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
    /// DR-0154/DR-0157: a `DrainSet` candidate committed before any `Freeze`
    /// was committed for this epoch. Symmetric with [`Self::ClosedEpoch`]:
    /// every replica decides this identically from the same absent closure
    /// row.
    NoFreeze,
    /// DR-0154/DR-0157: a second `DrainSet` candidate committed after this
    /// epoch's one-per-epoch immutable [`super::drain_set::DrainSetRecord`]
    /// was already installed. There is no re-selection in this profile.
    AlreadyDrained,
    /// DR-0154/DR-0157: the committed `DrainSet` candidate's declared
    /// [`consensus::DrainUnionIdentity`] disagrees with this replica's own
    /// independently reconstructed, quorum-verified local ready union for the
    /// exact same selected-signer roster and committed Freeze.
    ForeignDrainSet,
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
        }
    }
}

impl Error for OrderedEconomicsError {}

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
