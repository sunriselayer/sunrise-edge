//! DR-0153 orchestrator: `install_ordered_genesis`, `propose`,
//! `process_proposal`, `process_certificate`, `observe_proposal`,
//! `query_status` and `process_tick`, wired against the real
//! `consensus::ChainedHotStuff` durable API.
//!
//! Every entry point follows the same fixed order, which is the contract:
//!
//! 1. **pure authentication** of the candidate's outer envelope, every
//!    embedded leg and any evidence proof -- before any clock or storage
//!    read;
//! 2. **request-header reconciliation** -- a request id already bound to
//!    different bytes/kind/checkpoint is a boundary conflict raised before
//!    any consensus metadata or business receipt is written;
//! 3. **local protocol identity** -- the exact leader proposal or vote for
//!    this view is reconciled against its immutable durable record, and a
//!    conflicting one fails closed before any signature is exposed;
//! 4. **owned reservations** -- precisely the candidate's own address-owned
//!    inputs and sender-nonce range, under the same FastVote lock keys;
//! 5. **one engine event** through the real `ChainedHotStuff`;
//! 6. **one atomic commit** merging the existing owner's prepared
//!    transaction (with its original receipt), the consensus state, the
//!    order/candidate/identity records and the precise lock release.
//!
//! A byte-identical replay of an already-applied event writes nothing at all:
//! no row is rewritten, no revision incremented, no nonce re-reserved.
use super::completion::{
    AssembledOriginalCompletion, ConfirmedOriginalCompletion, PreparedOriginalCompletion,
};
use super::identity::{LocalVoteReconciliation, RetainedIdentity};
use super::observed_read::ObservedBusinessReadView;
use super::policy::{AuthenticatedOrderedOperation, Ed25519ConsensusVerifier};
use super::reservation::{OrderedReservationPlan, PendingWrite};
use super::seal;
use super::*;
use crate::admission_profile::{
    fence_verified_admission_profile, require_historical_direct_writer,
};
use crate::business_reconstruction::BusinessReconstructionPlan;
use crate::operation_preparation::{
    InvocationPreparation, PreparedBusinessInvocation, PreparedStateOperation,
};
use canonical_encoding::{decode_digest32, encode_chain_id, encode_digest32};
use consensus::{
    CommittedBlock, ConsensusEngine, ConsensusEvent, ConsensusMessage, ConsensusOutput,
    ConsensusProposal, ConsensusSigner, ConsensusState, QuorumCertificate, decode_consensus_state,
    decode_proposal, decode_quorum_certificate, encode_consensus_state, encode_proposal,
    encode_quorum_certificate,
};
use runtime::portable::PortableSnapshotToken;
use runtime::{
    DurableCommitOutcome, DurableDomainStateStore, DurableObjectHeadRead, OutgoingSealRepository,
    SealBarrier, StateAssemblyError, StateObservationSet, StateTransactionBuilder,
    StructuredDurableDomainStateStore, StructuredStateReader, TransitionHistoryState,
    VersionedStateReader,
};

/// Reserved under [`crate::local_instance_state::INSTANCE_STATE_PREFIX`], so
/// every existing enforcement point that already calls
/// `local_instance_state::is_reserved` covers these rows for free: no
/// contract and no generic transactional plan may read or write ordered
/// consensus state, candidate bytes, local signing identity or reservations.
pub(crate) const ORDERED_ECONOMICS_STATE_PREFIX: &[u8] = b"se/instances/v1/ordered-economics/";

const ORDERED_PROPOSAL_TYPE: u16 = 0x6442;
const ORDERED_STATUS_TYPE: u16 = 0x6443;
const ORDERED_OUTCOME_TYPE: u16 = 0x6444;
const ORDERED_EVENT_OUTPUT_TYPE: u16 = 0x6445;
const APPLIED_HEIGHT_RECORD_TYPE: u16 = 0x6446;
const REQUEST_HEADER_RECORD_TYPE: u16 = 0x6447;
const NODE_OUTPUT_RECORD_TYPE: u16 = 0x6448;
const ORDERED_REFUSAL_PAYLOAD_TYPE: u16 = 0x644E;
const ORDERED_OUTCOME_RECORD_TYPE: u16 = 0x644F;
const ENCODING_VERSION: u16 = 1;

/// One consensus message per outbound slot; bounded generously above anything
/// one three-chain window's `on_event` call legitimately emits (at most one
/// vote plus one certificate).
const MAX_ORDERED_EVENT_MESSAGES: usize = 8;
/// DR-0153 §"One atomic business/order commit": at most one newly committed
/// business operation per durable invocation.
const MAX_ORDERED_EVENT_COMMITTED: usize = 1;
/// Hard bound on the certified-ancestor walk one vote-readiness check
/// performs. `ChainedHotStuff::prune_state` retains only a couple of
/// committed heights, so a legitimate walk terminates in a few steps.
const MAX_VOTE_ANCESTOR_WALK: usize = 64;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

fn stop(message: &'static str) -> OrderedEconomicsError {
    OrderedEconomicsError::Prerequisite(message)
}

/// Distinguishes a genuinely virgin row from a deleted one.
///
/// [`VersionedStateValue::value`] returning `None` at
/// [`StateRevision::INITIAL`] means the row was never written. The same `None`
/// at any later revision means it was written and then deleted: a tombstone.
///
/// The two must never be conflated here. Treating a tombstone as virgin absence
/// would let this module recreate an immutable request header or candidate
/// record, reset the applied-height marker back to genesis, or report an
/// already-completed request as never seen -- each of which silently rewrites a
/// non-initial revision and, for the applied-height marker, would re-execute a
/// committed economic prefix. A deleted row is persisted corruption: stop and
/// require reconciliation.
fn require_virgin_absence(
    observed: &VersionedStateValue,
    message: &'static str,
) -> Result<(), OrderedEconomicsError> {
    if observed.value().is_none() && observed.revision() != StateRevision::INITIAL {
        return Err(stop(message));
    }
    Ok(())
}

fn consensus_to_node(_error: consensus::ConsensusError) -> OrderedEconomicsError {
    OrderedEconomicsError::Prerequisite("ordered economics consensus transition failed closed")
}

fn consensus_message_wire_tag(message: &ConsensusMessage) -> u16 {
    match message {
        ConsensusMessage::Proposal(_) => 1,
        ConsensusMessage::Vote(_) => 2,
        ConsensusMessage::Certificate(_) => 3,
    }
}

fn encode_consensus_message(message: &ConsensusMessage) -> Result<Vec<u8>, NodeCoreError> {
    match message {
        ConsensusMessage::Proposal(proposal) => {
            encode_proposal(proposal).map_err(|_| invalid("ordered event proposal message"))
        }
        ConsensusMessage::Vote(vote) => {
            consensus::encode_vote(vote).map_err(|_| invalid("ordered event vote message"))
        }
        ConsensusMessage::Certificate(certificate) => encode_quorum_certificate(certificate)
            .map_err(|_| invalid("ordered event certificate message")),
    }
}

fn decode_consensus_message(tag: u16, bytes: &[u8]) -> Result<ConsensusMessage, NodeCoreError> {
    match tag {
        1 => Ok(ConsensusMessage::Proposal(
            decode_proposal(bytes).map_err(|_| invalid("ordered event proposal message"))?,
        )),
        2 => Ok(ConsensusMessage::Vote(
            consensus::decode_vote(bytes).map_err(|_| invalid("ordered event vote message"))?,
        )),
        3 => Ok(ConsensusMessage::Certificate(
            decode_quorum_certificate(bytes)
                .map_err(|_| invalid("ordered event certificate message"))?,
        )),
        _ => Err(invalid("unknown ordered event message tag")),
    }
}

/// One candidate proposed under DR-0153's closed three-chain profile, paired
/// with the exact signed [`ConsensusProposal`] that carries it (or an empty
/// window).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedProposal {
    /// The signed consensus proposal.
    pub proposal: ConsensusProposal,
    /// The one candidate this proposal's transaction digest names, if any.
    pub candidate: Option<OrderedCandidate>,
}

/// Encodes frame `0x6442/v1`.
pub fn encode_ordered_proposal(value: &OrderedProposal) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(ORDERED_PROPOSAL_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_proposal(&value.proposal).map_err(|_| invalid("ordered proposal message"))?,
    )?;
    if let Some(candidate) = &value.candidate {
        frame.field_bytes(2, encode_ordered_candidate(candidate)?)?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6442/v1`.
pub fn decode_ordered_proposal(bytes: &[u8]) -> Result<OrderedProposal, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_PROPOSAL_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    if frame.field(2).is_some() {
        frame.require_only_fields(&[1, 2])?;
    } else {
        frame.require_only_fields(&[1])?;
    }
    let proposal: ConsensusProposal = decode_proposal(frame.required_field(1)?)
        .map_err(|_| invalid("ordered proposal message"))?;
    let candidate = match frame.field(2) {
        Some(bytes) => Some(decode_ordered_candidate(bytes)?),
        None => None,
    };
    let value = OrderedProposal {
        proposal,
        candidate,
    };
    if encode_ordered_proposal(&value)? != bytes {
        return Err(invalid("noncanonical ordered proposal"));
    }
    Ok(value)
}

/// One committed ordered-economics outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedOutcome {
    /// Digest of the exact committed candidate bytes.
    pub candidate_digest: Digest32,
    /// The candidate's own replay identity.
    pub request_id: [u8; 32],
    /// Height at which this outcome committed.
    pub block_height: u64,
    /// Digest of the committing proposal.
    pub block_digest: Digest32,
    /// The exact deterministic node output this outcome produced. A refused
    /// candidate's response payload is the canonical `0x644E/v1` typed
    /// [`OrderedRefusal`] frame, so the refusal reason is itself part of the
    /// retained, comparable outcome.
    pub output: NodeOutput,
}

/// Encodes frame `0x644E/v1`: the deterministic payload a refused ordered
/// candidate's `Rejected` response carries.
///
/// Public so a surface, SDK or E2E comparison can read the typed refusal
/// reason straight out of a retained [`OrderedOutcome`] instead of matching
/// on a free-form string.
pub fn encode_ordered_refusal_payload(refusal: OrderedRefusal) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(ORDERED_REFUSAL_PAYLOAD_TYPE, ENCODING_VERSION);
    frame.field_u16(1, refusal.to_wire())?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644E/v1`.
pub fn decode_ordered_refusal_payload(bytes: &[u8]) -> Result<OrderedRefusal, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_REFUSAL_PAYLOAD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    OrderedRefusal::from_wire(frame.required_u16(1)?)
}

/// Every ordered-economics `NodeOutput` this delivery produces carries zero
/// outbound messages (mirroring each existing owning preparation):
/// only `responses` needs a durable wire form.
fn encode_node_output(output: &NodeOutput) -> Result<Vec<u8>, NodeCoreError> {
    if !output.outbound_messages().is_empty() {
        return Err(invalid("ordered outcome output carries outbound messages"));
    }
    let responses = output.responses();
    if responses.len() > MAX_NODE_OUTPUT_ITEMS {
        return Err(NodeCoreError::TooManyOutputItems {
            collection: "responses",
            count: responses.len(),
        });
    }
    let mut frame = CanonicalStruct::new(NODE_OUTPUT_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u32(
        1,
        u32::try_from(responses.len()).map_err(|_| invalid("ordered outcome responses"))?,
    )?;
    for (index, response) in responses.iter().enumerate() {
        let field = u16::try_from(index + 2).map_err(|_| invalid("ordered outcome responses"))?;
        frame.field_bytes(field, response.encode()?)?;
    }
    Ok(frame.finish()?)
}

fn decode_node_output(bytes: &[u8]) -> Result<NodeOutput, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(NODE_OUTPUT_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let response_count = frame.required_u32(1)? as usize;
    if response_count > MAX_NODE_OUTPUT_ITEMS {
        return Err(NodeCoreError::TooManyOutputItems {
            collection: "responses",
            count: response_count,
        });
    }
    let mut fields: Vec<u16> = Vec::with_capacity(response_count + 1);
    fields.push(1);
    let mut responses = Vec::with_capacity(response_count);
    for index in 0..response_count {
        let field = u16::try_from(index + 2).map_err(|_| invalid("ordered outcome responses"))?;
        fields.push(field);
        responses.push(NodeResponse::decode(frame.required_field(field)?)?);
    }
    frame.require_only_fields(&fields)?;
    let output = NodeOutput::new(responses, Vec::new())?;
    if encode_node_output(&output)? != bytes {
        return Err(invalid("noncanonical ordered outcome output"));
    }
    Ok(output)
}

/// Encodes frame `0x6444/v1`.
pub fn encode_ordered_outcome(value: &OrderedOutcome) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(ORDERED_OUTCOME_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&value.candidate_digest)?)?;
    frame.field_bytes(2, value.request_id.to_vec())?;
    frame.field_u64(3, value.block_height)?;
    frame.field_bytes(4, encode_digest32(&value.block_digest)?)?;
    frame.field_bytes(5, encode_node_output(&value.output)?)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6444/v1`.
pub fn decode_ordered_outcome(bytes: &[u8]) -> Result<OrderedOutcome, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_OUTCOME_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("ordered outcome request id length"))?;
    let value = OrderedOutcome {
        candidate_digest: decode_digest32(frame.required_field(1)?)?,
        request_id,
        block_height: frame.required_u64(3)?,
        block_digest: decode_digest32(frame.required_field(4)?)?,
        output: decode_node_output(frame.required_field(5)?)?,
    };
    if encode_ordered_outcome(&value)? != bytes {
        return Err(invalid("noncanonical ordered outcome"));
    }
    Ok(value)
}

/// One deterministic consensus transition's outbound messages plus any newly
/// committed ordered-economics outcomes, bounded to at most one committed
/// outcome per invocation.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OrderedEventOutput {
    /// Messages safe to hand to an untrusted transport.
    pub messages: Vec<ConsensusMessage>,
    /// Newly committed ordered-economics outcomes (at most one).
    pub committed: Vec<OrderedOutcome>,
}

/// Encodes frame `0x6445/v1`.
pub fn encode_ordered_event_output(value: &OrderedEventOutput) -> Result<Vec<u8>, NodeCoreError> {
    if value.messages.len() > MAX_ORDERED_EVENT_MESSAGES {
        return Err(invalid("ordered event output messages"));
    }
    if value.committed.len() > MAX_ORDERED_EVENT_COMMITTED {
        return Err(invalid("ordered event output committed"));
    }
    let mut frame = CanonicalStruct::new(ORDERED_EVENT_OUTPUT_TYPE, ENCODING_VERSION);
    frame.field_u32(
        1,
        u32::try_from(value.messages.len())
            .map_err(|_| invalid("ordered event output messages"))?,
    )?;
    for (index, message) in value.messages.iter().enumerate() {
        let tag_field =
            u16::try_from(2 * index + 2).map_err(|_| invalid("ordered event output messages"))?;
        let body_field = tag_field
            .checked_add(1)
            .ok_or(invalid("ordered event output messages"))?;
        frame.field_u16(tag_field, consensus_message_wire_tag(message))?;
        frame.field_bytes(body_field, encode_consensus_message(message)?)?;
    }
    let committed_count_field = u16::try_from(2 * value.messages.len() + 2)
        .map_err(|_| invalid("ordered event output committed"))?;
    frame.field_u32(
        committed_count_field,
        u32::try_from(value.committed.len())
            .map_err(|_| invalid("ordered event output committed"))?,
    )?;
    for (index, outcome) in value.committed.iter().enumerate() {
        let field = u16::try_from(2 * value.messages.len() + 3 + index)
            .map_err(|_| invalid("ordered event output committed"))?;
        frame.field_bytes(field, encode_ordered_outcome(outcome)?)?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6445/v1`.
pub fn decode_ordered_event_output(bytes: &[u8]) -> Result<OrderedEventOutput, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_EVENT_OUTPUT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let message_count = frame.required_u32(1)? as usize;
    if message_count > MAX_ORDERED_EVENT_MESSAGES {
        return Err(invalid("ordered event output messages"));
    }
    let mut messages = Vec::with_capacity(message_count);
    for index in 0..message_count {
        let tag_field =
            u16::try_from(2 * index + 2).map_err(|_| invalid("ordered event output messages"))?;
        let body_field = tag_field
            .checked_add(1)
            .ok_or(invalid("ordered event output messages"))?;
        let tag = frame.required_u16(tag_field)?;
        messages.push(decode_consensus_message(
            tag,
            frame.required_field(body_field)?,
        )?);
    }
    let committed_count_field = u16::try_from(2 * message_count + 2)
        .map_err(|_| invalid("ordered event output committed"))?;
    let committed_count = frame.required_u32(committed_count_field)? as usize;
    if committed_count > MAX_ORDERED_EVENT_COMMITTED {
        return Err(invalid("ordered event output committed"));
    }
    let mut committed = Vec::with_capacity(committed_count);
    for index in 0..committed_count {
        let field = u16::try_from(2 * message_count + 3 + index)
            .map_err(|_| invalid("ordered event output committed"))?;
        committed.push(decode_ordered_outcome(frame.required_field(field)?)?);
    }
    let value = OrderedEventOutput {
        messages,
        committed,
    };
    if encode_ordered_event_output(&value)? != bytes {
        return Err(invalid("noncanonical ordered event output"));
    }
    Ok(value)
}

/// Bounded status snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedStatus {
    /// View currently eligible for proposal processing.
    pub current_view: u64,
    /// Highest known quorum certificate.
    pub high_qc: QuorumCertificate,
    /// Highest committed height.
    pub committed_height: u64,
}

/// Encodes frame `0x6443/v1`.
pub fn encode_ordered_status(value: &OrderedStatus) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(ORDERED_STATUS_TYPE, ENCODING_VERSION);
    frame.field_u64(1, value.current_view)?;
    frame.field_bytes(
        2,
        encode_quorum_certificate(&value.high_qc).map_err(|_| invalid("ordered status high qc"))?,
    )?;
    frame.field_u64(3, value.committed_height)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6443/v1`.
pub fn decode_ordered_status(bytes: &[u8]) -> Result<OrderedStatus, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_STATUS_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let value = OrderedStatus {
        current_view: frame.required_u64(1)?,
        high_qc: decode_quorum_certificate(frame.required_field(2)?)
            .map_err(|_| invalid("ordered status high qc"))?,
        committed_height: frame.required_u64(3)?,
    };
    if encode_ordered_status(&value)? != bytes {
        return Err(invalid("noncanonical ordered status"));
    }
    Ok(value)
}

// --- durable storage keys -------------------------------------------------

fn prefixed_key(infix: &[u8], chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(infix);
    key.extend(encode_chain_id(chain)?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn ordered_state_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"state/", chain)
}

pub(crate) fn ordered_applied_height_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"applied-height/", chain)
}

/// Immutable per-height proof key. This new family does not alter any
/// existing candidate, publication, ACK or artifact key.
pub(crate) fn ordered_committed_proof_key(
    chain: &ChainId,
    epoch: Epoch,
    height: u64,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"committed-proof/", chain)?;
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(&height.to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(crate) fn ordered_candidate_record_key(
    chain: &ChainId,
    digest: Digest32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"candidate/", chain)?;
    key.extend_from_slice(&digest.bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(crate) fn ordered_request_header_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"header/", chain)?;
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Key of one retained, completed ordered outcome, in the same reserved
/// namespace as every other row here.
pub(crate) fn ordered_outcome_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"outcome/", chain)?;
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Encodes frame `0x644F/v1`: the durable row identity wrapping one exact
/// canonical [`OrderedOutcome`] frame.
///
/// The row frame is deliberately distinct from the `0x6444` transport frame it
/// carries, so a stored row can never be mistaken for a message and a message
/// can never be mistaken for proof of completion.
fn encode_retained_outcome(outcome: &OrderedOutcome) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(ORDERED_OUTCOME_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_ordered_outcome(outcome)?)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644F/v1`.
pub(super) fn decode_retained_outcome(bytes: &[u8]) -> Result<OrderedOutcome, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_OUTCOME_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let outcome = decode_ordered_outcome(frame.required_field(1)?)?;
    if encode_retained_outcome(&outcome)? != bytes {
        return Err(invalid("noncanonical retained ordered outcome"));
    }
    Ok(outcome)
}

/// One outcome-row observation: the retained outcome when this replica already
/// completed the request, plus the key and CAS revision it was read at so the
/// caller can assert either its exact content or its exact absence.
struct OutcomeRow {
    retained: Option<OrderedOutcome>,
    key: Vec<u8>,
    revision: StateRevision,
}

/// Cross-checks one retained outcome against both durable records the very same
/// invocation committed alongside it: the immutable request header, and the
/// request receipt.
///
/// The outcome row is only ever written in one atomic invocation together with
/// a header binding this request id to the candidate digest, and a receipt for
/// the same request id. So a retained outcome whose header is missing or names a
/// different candidate digest, or which has no receipt, or whose responses
/// disagree with that receipt, is persisted inconsistency rather than an answer.
/// Each case fails closed as a stop: a completion result is only ever the exact
/// original responses that were really committed, never a fabricated or
/// partially recovered one, and never an orphan row on its own authority.
///
/// Which digest the receipt records is deliberately *not* constrained. An
/// accepted handler keeps its original intent receipt digest while a refusal or
/// a retained-evidence acceptance uses the candidate digest, and both are
/// correct. What must agree is the request identity, the exact responses, the
/// header's candidate digest, and the receipt's own two copies of its event
/// digest -- the outer [`DurableRequestReceipt::event_digest`] and the one
/// inside its [`NodeDedupRecord`] projection.
fn require_consistent_completion<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    request_id: &[u8; 32],
    outcome: &OrderedOutcome,
) -> Result<(), OrderedEconomicsError> {
    if &outcome.request_id != request_id {
        return Err(stop(
            "retained ordered outcome is keyed by another request id",
        ));
    }
    // The immutable header that the completing invocation wrote must still bind
    // this request id to exactly the candidate the outcome names.
    let header_key: Vec<u8> =
        ordered_request_header_key(env.policy.context().chain_id(), request_id)?;
    let observed_header: VersionedStateValue =
        store.read_versioned_state(context, env.policy.domain(), &header_key)?;
    let header_bytes: &[u8] = observed_header.value().ok_or(stop(
        "retained ordered outcome has no immutable request header",
    ))?;
    let header: RequestHeader = decode_request_header(header_bytes)?;
    if header.candidate_digest != outcome.candidate_digest {
        return Err(stop(
            "retained ordered outcome disagrees with its immutable request header",
        ));
    }
    let durable_id: DurableRequestId = DurableRequestId::new(*request_id)
        .map_err(|_| invalid("invalid durable request identity"))?;
    let receipt: DurableRequestReceipt = store
        .read_request_receipt(context, env.policy.domain(), durable_id)?
        .ok_or(stop(
            "retained ordered outcome has no committed request receipt",
        ))?;
    if receipt.request_id() != durable_id {
        return Err(stop(
            "durable receipt lookup returned another request for a retained outcome",
        ));
    }
    let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes())
        .map_err(|_| stop("retained ordered outcome receipt does not decode"))?;
    if record.request_id().as_bytes() != request_id
        || record.event_digest() != receipt.event_digest()
        || record.responses() != outcome.output.responses()
    {
        return Err(stop(
            "retained ordered outcome disagrees with its own committed receipt",
        ));
    }
    Ok(())
}

/// Reads the outcome row for `request_id`, cross-checked against its own
/// immutable request header and committed receipt. Bounded point reads only;
/// never writes.
///
/// A deleted outcome row is not "not completed": it is corruption, and reporting
/// virgin absence for it would let a finished request be placed and executed a
/// second time.
fn read_outcome_row<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    request_id: &[u8; 32],
) -> Result<OutcomeRow, OrderedEconomicsError> {
    let key: Vec<u8> = ordered_outcome_key(env.policy.context().chain_id(), request_id)?;
    let observed: VersionedStateValue =
        store.read_versioned_state(context, env.policy.domain(), &key)?;
    require_virgin_absence(&observed, "ordered outcome row was deleted")?;
    let retained = match observed.value() {
        None => None,
        Some(bytes) => {
            let outcome: OrderedOutcome = decode_retained_outcome(bytes)?;
            require_consistent_completion(store, context, env, request_id, &outcome)?;
            Some(outcome)
        }
    };
    Ok(OutcomeRow {
        retained,
        key,
        revision: observed.revision(),
    })
}

/// Bounded read-only lookup of the exact outcome this replica retained for one
/// request id, or `None` when it has not completed that request.
///
/// Performs at most three bounded point reads and no scan: the outcome row, and
/// -- only when that row exists -- the immutable request header and the request
/// receipt it must agree with. It signs nothing, reserves nothing, writes
/// nothing, and never reads a module, object or sender nonce, so a network
/// surface may expose it directly.
///
/// `Ok(None)` means this replica has not completed that request. It is not proof
/// of absence network-wide: this replica may simply be behind. A *deleted*
/// outcome row is never reported as `None`; like any other inconsistency
/// between the row, its header and its receipt it fails closed as
/// [`OrderedEconomicsError::Prerequisite`].
pub fn query_ordered_outcome<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    request_id: &[u8; 32],
) -> Result<Option<OrderedOutcome>, OrderedEconomicsError> {
    Ok(read_outcome_row(store, context, env, request_id)?.retained)
}

fn encode_applied_height(height: u64) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(APPLIED_HEIGHT_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, height)?;
    Ok(frame.finish()?)
}

fn decode_applied_height(bytes: &[u8]) -> Result<u64, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(APPLIED_HEIGHT_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    Ok(frame.required_u64(1)?)
}

/// Permanent, first-writer-wins binding of one request id to the exact
/// candidate digest/kind/checkpoint it was first admitted with. A later
/// candidate reusing the same request id under different bytes, kind or
/// checkpoint fails closed here, before any fresh proposal/vote metadata
/// write (DR-0153's header-reuse rule).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequestHeader {
    pub(super) candidate_digest: Digest32,
    pub(super) kind: OrderedOperationKind,
    pub(super) created_checkpoint: u64,
}

pub(super) fn encode_request_header(header: &RequestHeader) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(REQUEST_HEADER_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&header.candidate_digest)?)?;
    frame.field_u16(2, header.kind.to_wire())?;
    frame.field_u64(3, header.created_checkpoint)?;
    Ok(frame.finish()?)
}

pub(super) fn decode_request_header(bytes: &[u8]) -> Result<RequestHeader, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(REQUEST_HEADER_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    Ok(RequestHeader {
        candidate_digest: decode_digest32(frame.required_field(1)?)?,
        kind: OrderedOperationKind::from_wire(frame.required_u16(2)?)?,
        created_checkpoint: frame.required_u64(3)?,
    })
}

/// Digest binding one candidate's exact canonical bytes at its own context's
/// epoch, used both as its wire-transaction digest and as its permanent
/// request-header binding.
pub(super) fn candidate_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    candidate_bytes: &[u8],
) -> Result<Digest32, OrderedEconomicsError> {
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, candidate_bytes)?)
}

// --- merged single-commit accumulator -------------------------------------

/// Accumulates every read assertion and mutation one invocation will commit,
/// deduplicating by key so the merged transaction is valid
/// ([`AtomicStateReadSet`] rejects duplicate keys) and so two contributors
/// cannot silently disagree about the same row.
pub(super) struct MergedWrites {
    state: StateTransactionBuilder,
}

/// A same-sized capacity probe, never a cryptographic signature and never
/// exposed or committed. Actual signing starts only after complete bounded
/// invocation construction has succeeded.
struct CapacityProbeSigner<'a, C: ConsensusSigner>(&'a C);

impl<C: ConsensusSigner> ConsensusSigner for CapacityProbeSigner<'_, C> {
    fn validator_id(&self) -> protocol_types::ValidatorId {
        self.0.validator_id()
    }
    fn signature_scheme(&self) -> protocol_types::SignatureSchemeId {
        self.0.signature_scheme()
    }
    fn sign_framed(&self, _framed: &[u8]) -> Result<Vec<u8>, String> {
        Ok(vec![0; 64])
    }
}

fn admission_transaction(
    env: &OrderedEconomicsEnvironment<'_>,
    admitted: &AdmittedCandidate,
    stage: reservation::OrderedAdmissionStage,
    view: u64,
    writes: MergedWrites,
) -> Result<DurableInvocationTransaction, OrderedEconomicsError> {
    let synthetic: [u8; 32] = reservation::ordered_admission_request_id(
        env.resolver(),
        env.policy.context().epoch(),
        &admitted.request_id,
        admitted.digest,
        stage,
        view,
    )?;
    let output: NodeOutput = NodeOutput::new(Vec::new(), Vec::new())?;
    let receipt: DurableRequestReceipt = build_receipt(synthetic, admitted.digest, &output)?;
    Ok(DurableInvocationTransaction::new(
        env.policy.domain(),
        Some(writes.into_state_transaction(env.policy.domain())?),
        DurableObjectChanges::new(admitted.head_reads.clone(), Vec::new())?,
        receipt,
        None,
    )?)
}

fn require_admission_receipt<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    stage: reservation::OrderedAdmissionStage,
    view: u64,
) -> Result<(), OrderedEconomicsError> {
    if !env.policy.is_causal()
        || reservation::reservation_plan(env, candidate)?
            .objects
            .is_empty()
    {
        return Ok(());
    }
    let digest: Digest32 = env.policy.candidate_digest(candidate)?;
    let synthetic: [u8; 32] = reservation::ordered_admission_request_id(
        env.resolver(),
        env.policy.context().epoch(),
        &candidate.request_id,
        digest,
        stage,
        view,
    )?;
    let receipt: DurableRequestReceipt = store
        .read_request_receipt(
            context,
            env.policy.domain(),
            DurableRequestId::new(synthetic)
                .map_err(|_| invalid("ordered admission receipt identity"))?,
        )?
        .ok_or(stop(
            "retained signing identity lacks ordered admission receipt",
        ))?;
    let expected: DurableRequestReceipt =
        build_receipt(synthetic, digest, &NodeOutput::new(Vec::new(), Vec::new())?)?;
    if receipt != expected {
        return Err(stop("retained ordered admission receipt differs"));
    }
    Ok(())
}

impl MergedWrites {
    pub(super) fn new(domain: AtomicityDomainId) -> Self {
        Self {
            state: StateTransactionBuilder::new(domain),
        }
    }

    pub(super) fn read(
        &mut self,
        key: Vec<u8>,
        revision: StateRevision,
    ) -> Result<(), OrderedEconomicsError> {
        self.state
            .observe(StateReadAssertion::new(key, revision)?)
            .map_err(state_assembly_error)
    }

    pub(super) fn mutate(
        &mut self,
        key: Vec<u8>,
        revision: StateRevision,
        mutation: StateMutation,
    ) -> Result<(), OrderedEconomicsError> {
        self.read(key.clone(), revision)?;
        self.record_mutation(key, mutation)
    }

    fn record_mutation(
        &mut self,
        key: Vec<u8>,
        mutation: StateMutation,
    ) -> Result<(), OrderedEconomicsError> {
        self.state
            .coalesce_mutation_exact(StateMutationEntry::new(key, mutation)?)
            .map_err(state_assembly_error)
    }

    fn apply(&mut self, write: PendingWrite) -> Result<(), OrderedEconomicsError> {
        let (key, revision, mutation) = write;
        self.mutate(key, revision, mutation)
    }

    pub(super) fn merge_handler_state(
        &mut self,
        state: &DurableStateTransaction,
    ) -> Result<(), OrderedEconomicsError> {
        self.state
            .merge_state_exact(state)
            .map_err(state_assembly_error)
    }

    pub(super) fn merge_observations(
        &mut self,
        observations: &StateObservationSet,
    ) -> Result<(), OrderedEconomicsError> {
        self.state
            .merge_observations(observations)
            .map_err(state_assembly_error)
    }

    fn is_unchanged(&self) -> bool {
        self.state.is_unchanged()
    }

    pub(super) fn into_state_transaction(
        self,
        domain: AtomicityDomainId,
    ) -> Result<DurableStateTransaction, OrderedEconomicsError> {
        if self.state.domain() != domain {
            return Err(RuntimeError::AtomicityDomainMismatch.into());
        }
        Ok(self.state.finish_invocation_state()?)
    }

    fn into_atomic_transaction(
        self,
        domain: AtomicityDomainId,
    ) -> Result<AtomicStateTransaction, OrderedEconomicsError> {
        if self.state.domain() != domain {
            return Err(RuntimeError::AtomicityDomainMismatch.into());
        }
        Ok(self.state.finish_metadata()?)
    }
}

pub(super) fn state_assembly_error(error: StateAssemblyError) -> OrderedEconomicsError {
    match error {
        StateAssemblyError::ConflictingObservation { .. } => NodeCoreError::StateConflict.into(),
        StateAssemblyError::ConflictingMutation { .. } => {
            stop("ordered economics invocation produced two different mutations for one row")
        }
        StateAssemblyError::Runtime(error) => error.into(),
    }
}

pub(super) fn commit_outcome_error(outcome: DurableCommitOutcome) -> OrderedEconomicsError {
    match outcome {
        DurableCommitOutcome::Committed => {
            stop("unreachable committed outcome treated as a failure")
        }
        DurableCommitOutcome::Rejected(reason) => {
            OrderedEconomicsError::Node(NodeCoreError::DurableCommitRejected(reason))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            OrderedEconomicsError::Node(NodeCoreError::DurableCommitIndeterminate(reason))
        }
    }
}

// --- durable state load/install --------------------------------------------

struct LoadedState {
    state: ConsensusState,
    revision: StateRevision,
    key: Vec<u8>,
}

/// Loads and re-verifies the durable [`ConsensusState`]. Fails closed if it
/// was never installed or fails
/// [`consensus::ChainedHotStuff::validate_state`] -- the restart-safety guard
/// every orchestrator entry point runs before applying a new event.
fn load_state<S: StructuredStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<LoadedState, OrderedEconomicsError> {
    let key = ordered_state_key(env.policy.context().chain_id())?;
    let observed = store.read_versioned_state(context, env.policy.domain(), &key)?;
    let bytes = observed
        .value()
        .ok_or(stop("ordered economics consensus state is not installed"))?;
    let state = decode_consensus_state(bytes)
        .map_err(|_| stop("ordered economics consensus state does not decode"))?;
    env.policy
        .engine()
        .validate_state(&state, &Ed25519ConsensusVerifier)
        .map_err(|_| stop("ordered economics consensus state failed re-verification"))?;
    Ok(LoadedState {
        state,
        revision: observed.revision(),
        key,
    })
}

/// Installs the genesis [`ConsensusState`] exactly once, from the caller's own
/// trusted local clock.
///
/// `now_unix_millis` initializes the pacemaker's first view deadline. It must
/// come from the operator's verified trusted clock *before it starts
/// listening* -- never a remote peer, a candidate payload or a
/// [`DurableOperationContext`] deadline. There is deliberately no
/// `SystemTime` call inside this deterministic protocol core.
///
/// Idempotent and non-destructive across restart:
///
/// * a retained state row is **re-verified and kept**, never overwritten, so a
///   restart cannot roll the pacemaker, high/locked certificates or last-vote
///   safety information back to genesis;
/// * a *tombstoned* row (absent at a non-initial revision) is persisted
///   corruption and stops -- it is never treated as a fresh genesis reset.
pub fn install_ordered_genesis<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    now_unix_millis: u64,
) -> Result<(), OrderedEconomicsError> {
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let key = ordered_state_key(env.policy.context().chain_id())?;
    let domain = env.policy.domain();
    let observed = store.read_versioned_state(context, domain, &key)?;
    if let Some(bytes) = observed.value() {
        // Verified existing: re-verify and keep exactly what is stored.
        let state = decode_consensus_state(bytes)
            .map_err(|_| stop("retained ordered consensus state does not decode"))?;
        env.policy
            .engine()
            .validate_state(&state, &Ed25519ConsensusVerifier)
            .map_err(|_| stop("retained ordered consensus state failed re-verification"))?;
        return Ok(());
    }
    if observed.revision() != StateRevision::INITIAL {
        return Err(stop(
            "ordered consensus state row was deleted; refusing to reset it to genesis",
        ));
    }
    let state = env.policy.engine().genesis_state(now_unix_millis);
    let bytes = encode_consensus_state(&state)
        .map_err(|_| stop("ordered genesis consensus state does not encode"))?;
    let mut writes = MergedWrites::new(domain);
    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut profile_reads)?;
    for (key, revision) in profile_reads {
        writes.read(key, revision)?;
    }
    writes.mutate(key, observed.revision(), StateMutation::Put(bytes))?;
    match store.commit_durable(context, writes.into_atomic_transaction(domain)?) {
        DurableCommitOutcome::Committed => Ok(()),
        outcome => Err(commit_outcome_error(outcome)),
    }
}

/// Reads the highest committed height whose economic effects (if any) are
/// already durably applied. Absent means genesis, matching
/// [`ConsensusState::committed_height`]'s own zero start.
pub(super) fn load_applied_height<S: StructuredStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<(u64, Vec<u8>, StateRevision), OrderedEconomicsError> {
    let key = ordered_applied_height_key(env.policy.context().chain_id())?;
    let observed = store.read_versioned_state(context, env.policy.domain(), &key)?;
    // Virgin absence is genuinely expected here and only here: before the first
    // committed height there is no marker, which is exactly height zero. A
    // deleted marker is not height zero -- silently reading it as zero would
    // re-execute an already applied economic prefix.
    require_virgin_absence(&observed, "ordered applied-height marker was deleted")?;
    let height = match observed.value() {
        Some(bytes) => decode_applied_height(bytes)?,
        None => 0,
    };
    Ok((height, key, observed.revision()))
}

/// Deterministic rejection output: a closed `Rejected` response carrying the
/// typed refusal, keyed to the candidate's own request id. No application or
/// custody movement, no sender-nonce advancement.
fn refusal_output(
    request_id: [u8; 32],
    refusal: OrderedRefusal,
) -> Result<NodeOutput, NodeCoreError> {
    let response = NodeResponse::new(
        RequestId::new(request_id)?,
        NodeResponseStatus::Rejected,
        Some(encode_ordered_refusal_payload(refusal)?),
    )?;
    NodeOutput::new(vec![response], Vec::new())
}

/// Disposition of one attempted candidate execution.
pub(super) enum LegOutcome {
    /// The owner prepared its exact original invocation without committing it.
    PreparedInvocation(Box<PreparedBusinessInvocation>),
    /// A pure metadata proposal. The completion owner supplies its outer receipt.
    PreparedState(PreparedStateOperation),
    /// One narrowly enumerated legitimate outcome in which the existing handler
    /// accepts *without* preparing any transaction: the normalized evidence
    /// identity this candidate carries is already durably recorded, so the
    /// permanent one-time row is correct as it stands and re-writing it would
    /// be wrong.
    ///
    /// This is not a blanket licence for any handler that returns `Ok` with
    /// no proposed mutation. It is produced only by
    /// [`execute_evidence_candidate`] on
    /// [`equivocation::EquivocationEvidencePreparation::AlreadyRecorded`], and the
    /// result contains no business mutation.
    AcceptedRetainedEvidence(NodeOutput),
    /// A deterministic, retained refusal: no value or nonce movement.
    Refused(NodeOutput),
    /// DR-0187 Seal acceptance: the real independent private business
    /// closure (`business_reconstruction::cut::verify_live_seal_closure`)
    /// has already run and matched, producing a genuine receipt-only
    /// output and the token/barrier the actual `OutgoingSealRepository`
    /// completion port must retain atomically with it. Produced only by
    /// [`execute_seal_candidate`]; never a metadata-only convenience result.
    AcceptedSeal {
        output: NodeOutput,
        retention: SealRetention,
    },
    /// Infrastructural failure or unknown prerequisite: local apply must stop
    /// and require reconciliation.
    Stop(OrderedEconomicsError),
}

/// The real token-covered source capture and the exact sealed-record fields
/// one successful DR-0187 acceptance must retain atomically with the
/// ordinary original receipt via `OutgoingSealRepository::commit_seal_completion`.
pub(super) struct SealRetention {
    pub(super) token: PortableSnapshotToken,
    pub(super) barrier: SealBarrier,
}

fn refused(request_id: [u8; 32], refusal: OrderedRefusal) -> LegOutcome {
    match refusal_output(request_id, refusal) {
        Ok(output) => LegOutcome::Refused(output),
        Err(error) => LegOutcome::Stop(OrderedEconomicsError::Node(error)),
    }
}

/// Converts one execution-path error into a disposition, honouring the module
/// contract: only a pure authentication failure or a typed refusal is a
/// retained rejection; everything else stops.
pub(super) fn disposition(request_id: [u8; 32], error: OrderedEconomicsError) -> LegOutcome {
    match error {
        OrderedEconomicsError::Refused(refusal) => refused(request_id, refusal),
        // A candidate that fails *pure* authentication at execution time was
        // committed by a byzantine leader without ever passing admission.
        // The failure is storage-independent, so every replica reaches it:
        // record it as a refusal that moves nothing.
        OrderedEconomicsError::Unauthenticated(_) => {
            refused(request_id, OrderedRefusal::SignedRowMismatch)
        }
        other => LegOutcome::Stop(other),
    }
}

/// Evaluates one committed candidate through writer-free owning preparations.
///
/// The caller supplies evidence of pure authentication. Then the typed
/// [`super::preflight`] checks the healthy committed state before the exact
/// owning preparation its `kind` already uses, with the
/// private admitted-candidate capability that authorizes exactly this
/// request's own retained reservations.
///
/// Every state read -- the preflight's included -- goes through the observed
/// reader, so the exact rows whose healthy revisions decided the answer are recorded and
/// become CAS assertions in the one final commit. A refusal derived from a row
/// that has since moved is then rejected atomically instead of being retained
/// against state that no longer justifies it.
pub(super) fn execute_candidate<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    operation: &AuthenticatedOrderedOperation<'_>,
    admission: Option<&OrderedLegAdmission<'_>>,
    committed: &CommittedOrderedOperation<'_>,
    seal_repository: Option<&dyn OutgoingSealRepository>,
) -> LegOutcome {
    let candidate: &OrderedCandidate = operation.candidate();
    let block_height: u64 = committed.height();
    let block_digest: Digest32 = committed.block_digest();
    if candidate.kind == OrderedOperationKind::Seal
        && (env.seal.is_none() || seal_repository.is_none())
    {
        return LegOutcome::Stop(stop(
            "ordered Seal completion requires the live composition and same-store capability",
        ));
    }
    if let Err(error) = preflight::preflight(store, context, env, candidate, block_height) {
        // A Seal warrant is a local prerequisite for its independently
        // verified closure, not a healthy-state business refusal. Keep the
        // applied prefix and original receipt absent until it can be proved.
        if candidate.kind == OrderedOperationKind::Seal {
            return LegOutcome::Stop(error);
        }
        return disposition(candidate.request_id, error);
    }
    let domain = env.policy.domain();
    match candidate.kind {
        OrderedOperationKind::FeeClaim => dispatch_invocation(
            fee_claims::prepare_fee_claim_ordered(
                store,
                env.blobs,
                context,
                domain,
                env.resolver(),
                env.history,
                env.policy.context(),
                env.leg_policy,
                env.engine,
                &candidate.intent,
                candidate.created_checkpoint,
                admission,
            ),
            candidate.request_id,
            fee_claim_failure,
        ),
        OrderedOperationKind::BondLifecycle => dispatch_invocation(
            bond_lifecycle::prepare_bond_lifecycle_ordered(
                store,
                env.blobs,
                context,
                domain,
                env.resolver(),
                env.history,
                env.policy.context(),
                env.leg_policy,
                env.engine,
                &candidate.intent,
                candidate.created_checkpoint,
                admission,
            ),
            candidate.request_id,
            bond_lifecycle_failure,
        ),
        OrderedOperationKind::BondRegistration => dispatch_invocation(
            bond_lifecycle::registration::prepare_bond_registration_ordered(
                store, context, env, candidate, admission,
            ),
            candidate.request_id,
            bond_registration_failure,
        ),
        OrderedOperationKind::BondSlash => dispatch_invocation(
            bond_lifecycle::slash::prepare_bond_slash_ordered(
                store,
                env.blobs,
                context,
                domain,
                env.resolver(),
                env.history,
                env.policy.context(),
                env.leg_policy,
                env.engine,
                &candidate.intent,
                candidate.created_checkpoint,
                admission,
            ),
            candidate.request_id,
            bond_lifecycle_failure,
        ),
        OrderedOperationKind::Evidence => {
            execute_evidence_candidate(store, context, domain, env, candidate, admission)
        }
        OrderedOperationKind::Freeze => dispatch_state(
            freeze::prepare_freeze_ordered(
                store,
                context,
                domain,
                env.policy.context().chain_id(),
                candidate,
                block_height,
            ),
            candidate.request_id,
            node_failure,
        ),
        OrderedOperationKind::DrainSet => dispatch_state(
            drain_set::prepare_drain_set_ordered(
                store,
                context,
                domain,
                env.policy.context().chain_id(),
                candidate,
                block_height,
            ),
            candidate.request_id,
            node_failure,
        ),
        // DR-0187: the real acceptance-only business closure. A warranted
        // candidate (preflight, above) is necessary but never sufficient by
        // itself: `execute_seal_candidate` additionally requires the live
        // `env.seal` composition and the store's own `OutgoingSealRepository`
        // capability, and only ever produces `AcceptedSeal` after the real
        // independent `verify_live_seal_closure` comparison has matched.
        OrderedOperationKind::Seal => execute_seal_candidate(
            context,
            env,
            candidate,
            block_height,
            block_digest,
            seal_repository,
        ),
    }
}

/// DR-0187 Seal dispatch. Pure fields (target/request/output) are
/// derivable from the already pure-authenticated candidate alone, but
/// producing [`LegOutcome::AcceptedSeal`] additionally requires the live
/// `env.seal` composition and the stores own [`OutgoingSealRepository`]
/// capability, and only after the real independent
/// `business_reconstruction::cut::verify_live_seal_closure` comparison has
/// matched. Neither a missing composition nor a missing capability ever
/// falls back to a receipt-only acceptance: this first-epoch feature never
/// needs to replay an accepted Seal through historical reconstruction, so
/// both Stop rather than fabricate a success this validator has not
/// actually, independently verified.
fn execute_seal_candidate(
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    block_height: u64,
    block_digest: Digest32,
    seal_repository: Option<&dyn OutgoingSealRepository>,
) -> LegOutcome {
    let intent = match seal::decode_seal_intent(&candidate.intent) {
        Ok(intent) => intent,
        Err(_) => {
            return LegOutcome::Stop(stop("seal acceptance candidate intent does not decode"));
        }
    };
    let cut_identity = match seal::decode_seal_cut_identity(&intent) {
        Ok(identity) => identity,
        Err(_) => {
            return LegOutcome::Stop(stop(
                "seal acceptance candidate cut identity does not decode",
            ));
        }
    };
    let subject_identity: Digest32 = match intent.readiness_subject.identity(env.resolver()) {
        Ok(digest) => digest,
        Err(_) => {
            return LegOutcome::Stop(stop("seal acceptance readiness subject configuration"));
        }
    };
    let target: Digest32 = match seal::seal_target_digest(
        env.resolver(),
        &candidate.context,
        subject_identity,
        intent.predecessor_tag,
        intent.predecessor_digest,
    ) {
        Ok(target) => target,
        Err(error) => return LegOutcome::Stop(error.into()),
    };
    let outcome_frame: SealOutcome = SealOutcome {
        target,
        request: candidate.request_id,
        seal_block_height: block_height,
        seal_block_digest: block_digest,
    };
    let payload: Vec<u8> = match seal::encode_seal_outcome(&outcome_frame) {
        Ok(bytes) => bytes,
        Err(error) => return LegOutcome::Stop(error.into()),
    };
    let request_id: RequestId = match RequestId::new(candidate.request_id) {
        Ok(id) => id,
        Err(error) => return LegOutcome::Stop(error.into()),
    };
    let response: NodeResponse =
        match NodeResponse::new(request_id, NodeResponseStatus::Accepted, Some(payload)) {
            Ok(response) => response,
            Err(error) => return LegOutcome::Stop(error.into()),
        };
    let output: NodeOutput = match NodeOutput::new(vec![response], Vec::new()) {
        Ok(output) => output,
        Err(error) => return LegOutcome::Stop(error.into()),
    };
    // DR-0187: "None or missing SAMESTORE capability is Unsupported Stop";
    // public cut/saved/import/readiness keep their own unrelated 3-empty
    // terminal and never need to re-execute an accepted Seal, so there is
    // deliberately no reduced/receipt-only branch below this point.
    let Some(composition) = env.seal.as_ref() else {
        return LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
            "ordered Seal acceptance requires a live Seal composition; this environment carries none",
        ));
    };
    let Some(repository) = seal_repository else {
        return LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
            "ordered Seal acceptance requires the stores OutgoingSealRepository capability",
        ));
    };
    // DR-0187: the business-reconstruction target is the actual CURRENT
    // prior tip h-1, never the candidates own possibly-stale declared
    // checkpoint -- empty progress may have extended it since signing.
    let Some(current_height) = block_height.checked_sub(1) else {
        return LegOutcome::Stop(stop("seal acceptance height underflow"));
    };
    let prior_state: LoadedState = match load_state(repository, context, env) {
        Ok(loaded) => loaded,
        Err(error) => return LegOutcome::Stop(error),
    };
    let (applied_height, _, _) = match load_applied_height(repository, context, env) {
        Ok(applied) => applied,
        Err(error) => return LegOutcome::Stop(error),
    };
    if applied_height != current_height || prior_state.state.committed_height != current_height {
        return LegOutcome::Stop(stop(
            "ordered Seal acceptance requires the actual applied and committed prior tip h-1; declared recovery required",
        ));
    }
    let certificate: consensus::readiness::ReadinessCertificate =
        match seal::load_verified_seal_certificate(env, candidate) {
            Ok(certificate) => certificate,
            Err(error) => return LegOutcome::Stop(error),
        };
    let next_members: Vec<crate::fast_path::records::FastPathValidatorEntry> =
        seal::seal_next_members(&certificate);
    let current_identity: OrderedHistoryIdentity = match super::ordered_history::identity_at_height(
        repository,
        context,
        env,
        current_height,
    ) {
        Ok(identity) => identity,
        Err(error) => return LegOutcome::Stop(error),
    };
    let ordered_material: Vec<OrderedHistoryHeightMaterial> =
        match super::ordered_history::assemble_verified_material(
            repository,
            context,
            env,
            &current_identity,
        ) {
            Ok(material) => material,
            Err(error) => return LegOutcome::Stop(error),
        };
    // The intents own anchor must land on the real authenticated chain at
    // exactly its declared checkpoint, and every height strictly after it
    // through the current prior tip must be empty progress: an intent
    // cannot silently repin to a different branch or skip a nonempty one.
    if cut_identity.ordered_history.through_height > current_height {
        return LegOutcome::Stop(stop(
            "seal acceptance candidate checkpoint lies beyond the current prior tip",
        ));
    }
    for material in &ordered_material {
        if material.descriptor.height == cut_identity.ordered_history.through_height {
            if material.descriptor.view != cut_identity.ordered_history.through_view
                || material.descriptor.block_digest != cut_identity.ordered_history.through_digest
            {
                return LegOutcome::Stop(stop(
                    "seal acceptance candidate anchor disagrees with the authenticated archive",
                ));
            }
        } else if material.descriptor.height > cut_identity.ordered_history.through_height
            && (material.descriptor.components.len() != 1
                || material.descriptor.components[0].kind
                    != OrderedHistoryComponentKind::CommitProof)
        {
            return LegOutcome::Stop(stop(
                "seal acceptance candidate post-anchor committed height is not empty",
            ));
        }
    }
    let plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
        genesis_root: composition.genesis_root,
        operation_context: *context,
        domain: env.policy.domain(),
        resolver_history: env.history,
        ordered_policy: env.policy,
        ordered_history_identity: &current_identity,
        ordered_leg_policy: env.leg_policy,
        ordered_engine: env.engine,
        paid_base_policy: composition.paid_base_policy,
        paid_engine: composition.paid_engine,
    };
    let verified = match crate::business_reconstruction::cut::verify_live_seal_closure(
        plan,
        repository,
        composition.blobs,
        &ordered_material,
        candidate,
        block_digest,
        &next_members,
    ) {
        Ok(verified) => verified,
        Err(_) => {
            return LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
                "ordered Seal acceptance independent business closure failed",
            ));
        }
    };
    // DR-0187: the verified cut must equal the candidates ENTIRE own
    // declared intent cut except the independently authenticated empty
    // history extension this block just proved.
    let mut expected_identity = cut_identity.clone();
    expected_identity.ordered_history = verified.identity().ordered_history.clone();
    if &expected_identity != verified.identity() {
        return LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
            "ordered Seal acceptance verified business cut differs from the candidates own intent",
        ));
    }
    let Some(token) = verified.source_token().cloned() else {
        return LegOutcome::Stop(stop(
            "ordered Seal acceptance business closure produced no source token",
        ));
    };
    let barrier: SealBarrier = SealBarrier {
        outgoing_epoch: env.policy.context().epoch(),
        request: candidate.request_id,
        height: block_height,
        block_digest,
        target_digest: target,
        transition_history: TransitionHistoryState::Virgin,
    };
    LegOutcome::AcceptedSeal {
        output,
        retention: SealRetention { token, barrier },
    }
}

/// DR-0187 pre-vote/leader signing retention: ordinary cut derivation's
/// unchanged terminal three-empty, over the
/// CURRENT committed prefix, through the same SAMESTORE capability. Compares
/// the result against the candidates own declared intent cut on every
/// field except the independently authenticated empty history extension,
/// exactly like acceptance, then returns the fresh token this one signing
/// attempt retains. A missing composition/capability or a disagreeing
/// reconstruction stops rather than signing on an unverified claim.
fn require_seal_signing_retention<S: StructuredDurableDomainStateStore + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    loaded: &LoadedState,
    selected: &QuorumCertificate,
    observations: &mut StateObservationSet,
) -> Result<PortableSnapshotToken, OrderedEconomicsError> {
    let current_height: u64 = loaded.state.committed_height;
    let (applied_height, applied_key, applied_revision) = load_applied_height(store, context, env)?;
    if applied_height != current_height {
        return Err(stop(
            "ordered Seal signing requires the applied prefix to match the committed height",
        ));
    }
    observations
        .observe(StateReadAssertion::new(
            loaded.key.clone(),
            loaded.revision,
        )?)
        .map_err(state_assembly_error)?;
    observations
        .observe(StateReadAssertion::new(applied_key, applied_revision)?)
        .map_err(state_assembly_error)?;
    let composition = env
        .seal
        .as_ref()
        .ok_or(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing requires a live Seal composition",
        ))?;
    let repository: &dyn OutgoingSealRepository =
        store
            .outgoing_seal_repository()
            .ok_or(OrderedEconomicsError::Prerequisite(
                "ordered Seal signing requires the stores OutgoingSealRepository capability",
            ))?;
    let intent = seal::decode_seal_intent(&candidate.intent)
        .map_err(|_| stop("seal signing candidate intent does not decode"))?;
    let cut_identity = seal::decode_seal_cut_identity(&intent)
        .map_err(|_| stop("seal signing candidate cut identity does not decode"))?;
    let certificate: consensus::readiness::ReadinessCertificate =
        seal::load_verified_seal_certificate(env, candidate)?;
    let next_members: Vec<crate::fast_path::records::FastPathValidatorEntry> =
        seal::seal_next_members(&certificate);
    if cut_identity.ordered_history.through_height > current_height {
        return Err(stop(
            "seal signing candidate checkpoint lies beyond the current prior tip",
        ));
    }
    let current_identity: OrderedHistoryIdentity =
        super::ordered_history::identity_at_height(repository, context, env, current_height)?;
    let ordered_material: Vec<OrderedHistoryHeightMaterial> =
        super::ordered_history::assemble_verified_material(
            repository,
            context,
            env,
            &current_identity,
        )?;
    let boundary: &OrderedHistoryHeightDescriptor = &ordered_material
        .last()
        .ok_or(stop(
            "Seal signing lacks the independently verified committed boundary",
        ))?
        .descriptor;
    require_seal_selected_ancestry(env.policy, &loaded.state, selected, boundary)?;
    for material in &ordered_material {
        if material.descriptor.height == cut_identity.ordered_history.through_height {
            if material.descriptor.view != cut_identity.ordered_history.through_view
                || material.descriptor.block_digest != cut_identity.ordered_history.through_digest
            {
                return Err(stop(
                    "seal signing candidate anchor disagrees with the authenticated archive",
                ));
            }
        } else if material.descriptor.height > cut_identity.ordered_history.through_height
            && (material.descriptor.components.len() != 1
                || material.descriptor.components[0].kind
                    != OrderedHistoryComponentKind::CommitProof)
        {
            return Err(stop(
                "seal signing candidate post-anchor committed height is not empty",
            ));
        }
    }
    let plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
        genesis_root: composition.genesis_root,
        operation_context: *context,
        domain: env.policy.domain(),
        resolver_history: env.history,
        ordered_policy: env.policy,
        ordered_history_identity: &current_identity,
        ordered_leg_policy: env.leg_policy,
        ordered_engine: env.engine,
        paid_base_policy: composition.paid_base_policy,
        paid_engine: composition.paid_engine,
    };
    let verified =
        crate::business_reconstruction::cut::derive_source_business_cut_for_seal_signing(
            plan,
            repository,
            composition.blobs,
            &ordered_material,
            &next_members,
        )
        .map_err(|_| {
            OrderedEconomicsError::Prerequisite(
                "ordered Seal signing independent business reconstruction failed",
            )
        })?;
    let mut expected_identity = cut_identity.clone();
    expected_identity.ordered_history = verified.identity().ordered_history.clone();
    if &expected_identity != verified.identity() {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing verified business cut differs from the candidates own intent",
        ));
    }
    verified.source_token().cloned().ok_or(stop(
        "ordered Seal signing business reconstruction produced no source token",
    ))
}

/// Only the selected justification must be empty above the independently
/// verified committed boundary. `load_state` already re-verifies every cached
/// proposal's context, membership, leadership, QC and signature; this bounded
/// walk additionally requires direct heights, monotonic views and the exact
/// boundary digest/view. Unrelated superseded forks remain ordinary consensus
/// state and do not acquire a second global business-free condition.
fn require_seal_selected_ancestry(
    policy: &OrderedEconomicsPolicy,
    state: &ConsensusState,
    selected: &QuorumCertificate,
    boundary: &OrderedHistoryHeightDescriptor,
) -> Result<(), OrderedEconomicsError> {
    if boundary.height != state.committed_height {
        return Err(stop(
            "Seal committed boundary differs from the loaded state; catch-up required",
        ));
    }
    let mut cursor: &QuorumCertificate = selected;
    for walked in 0..=MAX_VOTE_ANCESTOR_WALK {
        if cursor.height == boundary.height {
            if cursor.proposal_digest != boundary.block_digest || cursor.view != boundary.view {
                return Err(stop(
                    "Seal selected branch forks at the committed boundary; catch-up required",
                ));
            }
            return Ok(());
        }
        if cursor.height < boundary.height {
            return Err(stop(
                "Seal selected branch skips the committed boundary; catch-up required",
            ));
        }
        if walked == MAX_VOTE_ANCESTOR_WALK {
            return Err(stop(
                "Seal selected-ancestor walk exceeded its bound; catch-up required",
            ));
        }
        let ancestor: &ConsensusProposal = state.known_proposal(&cursor.proposal_digest).ok_or(
            stop("Seal selected ancestor is missing; declared catch-up required"),
        )?;
        if ancestor.height != cursor.height
            || ancestor.view != cursor.view
            || policy
                .engine()
                .proposal_digest(ancestor)
                .map_err(consensus_to_node)?
                != cursor.proposal_digest
            || ancestor.justify.height.checked_add(1) != Some(ancestor.height)
            || ancestor.justify.view >= ancestor.view
        {
            return Err(stop(
                "Seal selected ancestry has inconsistent direct links; catch-up required",
            ));
        }
        require_profile_shape(ancestor).map_err(|_| {
            stop("Seal selected ancestor violates the ordered profile; catch-up required")
        })?;
        if !ancestor.transactions.is_empty() {
            return Err(stop(
                "Seal selected ancestor carries a candidate; declared catch-up required",
            ));
        }
        cursor = &ancestor.justify;
    }
    Err(stop(
        "Seal selected-ancestor walk exceeded its bound; catch-up required",
    ))
}

#[cfg(test)]
#[path = "tests/seal_selected_ancestry.rs"]
mod seal_selected_ancestry_tests;

#[cfg(test)]
#[path = "tests/seal_acceptance_dispatch.rs"]
pub(super) mod seal_acceptance_dispatch_tests;

fn dispatch_invocation<E>(
    result: Result<InvocationPreparation, E>,
    request_id: [u8; 32],
    classify: fn(&E) -> OrderedEconomicsError,
) -> LegOutcome {
    match result {
        Ok(InvocationPreparation::Prepared(prepared)) => LegOutcome::PreparedInvocation(prepared),
        Ok(InvocationPreparation::Retained(_)) => LegOutcome::Stop(stop(
            "fresh ordered preparation unexpectedly reconciled a retained original",
        )),
        Err(error) => disposition(request_id, classify(&error)),
    }
}

fn dispatch_state(
    result: Result<PreparedStateOperation, NodeCoreError>,
    request_id: [u8; 32],
    classify: fn(&NodeCoreError) -> OrderedEconomicsError,
) -> LegOutcome {
    match result {
        Ok(prepared) => LegOutcome::PreparedState(prepared),
        Err(error) => disposition(request_id, classify(&error)),
    }
}

fn execute_evidence_candidate<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    admission: Option<&OrderedLegAdmission<'_>>,
) -> LegOutcome {
    let submission =
        match evidence_submission::decode_ordered_evidence_submission(&candidate.intent) {
            Ok(submission) => submission,
            Err(_) => return refused(candidate.request_id, OrderedRefusal::SignedRowMismatch),
        };
    let chain = env.policy.context().chain_id().clone();
    let protocol_version = env.policy.context().protocol_version();
    let checkpoint = submission.checkpoint();
    let outcome = match &submission {
        evidence_submission::OrderedEvidenceSubmission::FastVote {
            statement_a,
            statement_b,
            ..
        } => equivocation::prepare_fast_vote_equivocation_evidence_ordered(
            store,
            context,
            domain,
            env.resolver(),
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            checkpoint,
            Some(env.policy.context()),
            admission,
        ),
        evidence_submission::OrderedEvidenceSubmission::ObjectConflict {
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            ..
        } => equivocation::prepare_fast_vote_object_conflict_evidence_ordered(
            store,
            context,
            domain,
            env.resolver(),
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            checkpoint,
            Some(env.policy.context()),
            admission,
        ),
        evidence_submission::OrderedEvidenceSubmission::EpochTransition {
            statement_a,
            statement_b,
            ..
        } => equivocation::prepare_epoch_transition_equivocation_evidence_ordered(
            store,
            context,
            domain,
            env.resolver(),
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            checkpoint,
            Some(env.policy.context()),
            admission,
        ),
    };
    match outcome {
        Ok(recorded) => {
            let (record, prepared): (
                equivocation::FastPathEquivocationEvidenceRecord,
                Option<AtomicStateTransaction>,
            ) = match recorded {
                equivocation::EquivocationEvidencePreparation::New(prepared) => {
                    let (transaction, record) = prepared.into_parts();
                    (record, Some(transaction))
                }
                equivocation::EquivocationEvidencePreparation::AlreadyRecorded(record) => {
                    (record, None)
                }
            };
            let build = || -> Result<NodeOutput, NodeCoreError> {
                let payload = equivocation::encode_fastpath_equivocation_evidence_record(&record)?;
                let response = NodeResponse::new(
                    RequestId::new(candidate.request_id)?,
                    NodeResponseStatus::Accepted,
                    Some(payload),
                )?;
                NodeOutput::new(vec![response], Vec::new())
            };
            match build() {
                // A fresh request id resubmitting an identical, already
                // recorded normalized evidence is a legitimate accepted
                // outcome, not a wedge: the permanent one-time row already
                // holds exactly the right bytes, so this invocation commits
                // only its own new outer receipt and order rows, with the
                // observed evidence row asserted by CAS.
                Ok(output) => match prepared {
                    Some(transaction) => {
                        LegOutcome::PreparedState(PreparedStateOperation::new(transaction, output))
                    }
                    None => LegOutcome::AcceptedRetainedEvidence(output),
                },
                Err(error) => LegOutcome::Stop(OrderedEconomicsError::Node(error)),
            }
        }
        Err(error) => disposition(candidate.request_id, equivocation_failure(&error)),
    }
}

// --- request-header/candidate-record reconciliation -----------------------

/// Identity/order evidence issued only at the two owning verified-commit
/// boundaries below. A certificate does not authenticate business execution.
/// Neither callers nor decoded source companions can construct this type.
pub(super) struct CommittedOrderedOperation<'a> {
    candidate: &'a OrderedCandidate,
    block: &'a CommittedBlock,
    digest: Digest32,
}

impl<'a> CommittedOrderedOperation<'a> {
    /// The caller has already verified the full committed proof and its
    /// contiguous prefix. This binds the exact canonical original material to
    /// that verified block, without claiming that its semantics are accepted.
    fn bind_verified(
        env: &OrderedEconomicsEnvironment<'_>,
        candidate: &'a OrderedCandidate,
        block: &'a CommittedBlock,
    ) -> Result<Self, OrderedEconomicsError> {
        let bytes: Vec<u8> = encode_ordered_candidate(candidate)?;
        let digest: Digest32 = candidate_digest(env.resolver(), candidate.context.epoch(), &bytes)?;
        if block.transactions.as_slice() != [digest] {
            return Err(stop(
                "committed operation differs from exact original material",
            ));
        }
        Ok(Self {
            candidate,
            block,
            digest,
        })
    }

    pub(super) const fn candidate(&self) -> &'a OrderedCandidate {
        self.candidate
    }

    pub(super) const fn digest(&self) -> Digest32 {
        self.digest
    }

    pub(super) const fn height(&self) -> u64 {
        self.block.height
    }

    pub(super) const fn block_digest(&self) -> Digest32 {
        self.block.digest
    }
}

/// The execution mode is an explicit private warrant, not a boolean or a
/// public permission flag. Live/recovery uses only this original's retained
/// reservation; isolated replay is issued only after contiguous proof and
/// causal prerequisite verification. Both preserve owning lock checks.
pub(super) struct ExecutionWarrant<'a> {
    kind: ExecutionWarrantKind<'a>,
}

enum ExecutionWarrantKind<'a> {
    Reserved(OrderedLegAdmission<'a>),
    CertifiedPrivateReplay(OrderedLegAdmission<'a>),
}

impl<'a> ExecutionWarrant<'a> {
    pub(super) fn admission(
        &self,
        request_id: [u8; 32],
    ) -> Result<&OrderedLegAdmission<'a>, OrderedEconomicsError> {
        let admission: &OrderedLegAdmission<'a> = match &self.kind {
            ExecutionWarrantKind::Reserved(admission)
            | ExecutionWarrantKind::CertifiedPrivateReplay(admission) => admission,
        };
        if admission.request_id != request_id {
            return Err(stop(
                "ordered execution warrant names another original request",
            ));
        }
        Ok(admission)
    }
}

/// Private isolated reconstruction only. The contiguous pinned proof stream
/// authenticates the original candidate/order, not its source outcome. Every
/// causal dependency is checked before early semantic refusals, existing
/// handlers independently derive effects/receipt, and source companions are
/// compared before committing anything. A concrete memory store cannot grant
/// a live provider application or incoming-validator serving capability.
pub(crate) fn reconstruct_ordered_history_height(
    store: &runtime::MemoryDurableStateStore,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    verifier: &mut OrderedHistoryVerifier,
    material: &OrderedHistoryHeightMaterial,
) -> Result<Option<OrderedOutcome>, OrderedEconomicsError> {
    if !env.policy.is_causal() {
        return Err(stop(
            "business reconstruction requires pinned causal genesis",
        ));
    }
    verifier.require_pinned_policy(env.policy)?;
    let mut next: OrderedHistoryVerifier = verifier.clone();
    let block: CommittedBlock = next.verify_next_height(material)?;
    let component = |kind: OrderedHistoryComponentKind| -> Result<&[u8], OrderedEconomicsError> {
        material
            .components
            .iter()
            .find(|(found, _)| *found == kind)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or(stop("ordered reconstruction component missing"))
    };
    let mut writes: MergedWrites = MergedWrites::new(env.policy.domain());
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut reads)?;
    let (applied, applied_key, applied_revision) = load_applied_height(store, context, env)?;
    if applied != verifier.height() {
        return Err(stop("ordered reconstruction local prefix differs"));
    }
    let archive_key: Vec<u8> = ordered_committed_proof_key(
        env.policy.context().chain_id(),
        env.policy.context().epoch(),
        block.height,
    )?;
    let archive: VersionedStateValue =
        store.read_versioned_state(context, env.policy.domain(), &archive_key)?;
    if archive.value().is_some() || archive.revision() != StateRevision::INITIAL {
        return Err(stop(
            "ordered reconstruction height already archived or deleted",
        ));
    }
    writes.mutate(
        archive_key,
        archive.revision(),
        StateMutation::Put(component(OrderedHistoryComponentKind::CommitProof)?.to_vec()),
    )?;
    writes.mutate(
        applied_key,
        applied_revision,
        StateMutation::Put(encode_applied_height(block.height)?),
    )?;
    let mut completed: Option<OrderedOutcome> = None;
    let mut prepared: Option<PreparedOriginalCompletion> = None;
    let mut admission_heads: Vec<DurableObjectHeadRead> = Vec::new();
    if !block.transactions.is_empty() {
        let candidate: OrderedCandidate =
            decode_ordered_candidate(component(OrderedHistoryComponentKind::Candidate)?)?;
        let source_outcome: &[u8] = component(OrderedHistoryComponentKind::RetainedOutcome)?;
        let source_receipt: &[u8] = component(OrderedHistoryComponentKind::OriginalReceipt)?;
        match admit_candidate(
            store,
            context,
            env,
            &candidate,
            AdmissionPurpose::ReconcileOnly,
        )? {
            Admission::Completed(retained) => {
                let receipt: DurableRequestReceipt = store
                    .read_request_receipt(
                        context,
                        env.policy.domain(),
                        DurableRequestId::new(candidate.request_id)
                            .map_err(|_| invalid("ordered reconstruction request id"))?,
                    )?
                    .ok_or(stop("ordered reconstruction original receipt missing"))?;
                if encode_retained_outcome(&retained)?.as_slice() != source_outcome {
                    return Err(stop(
                        "ordered reconstructed recommit original outcome differs",
                    ));
                }
                if receipt.canonical_bytes() != source_receipt {
                    return Err(stop(
                        "ordered reconstructed recommit original receipt differs",
                    ));
                }
                completed = Some(*retained);
            }
            Admission::Fresh(admitted) => {
                for (key, revision) in admitted.reads {
                    writes.read(key, revision)?;
                }
                for write in admitted.writes {
                    writes.apply(write)?;
                }
                let plan: OrderedReservationPlan = reservation::reservation_plan(env, &candidate)?;
                reservation::verify_causal_prerequisites(
                    store,
                    context,
                    env,
                    &candidate,
                    &plan,
                    &mut reads,
                    &mut admission_heads,
                )?;
                // No live prepare is installed in this isolated overlay.
                // The proof-backed capability authorizes dispatch, while all
                // actual locks still use ordinary absence/Fresh semantics.
                let warrant: ExecutionWarrant<'_> = ExecutionWarrant {
                    kind: ExecutionWarrantKind::CertifiedPrivateReplay(OrderedLegAdmission {
                        request_id: candidate.request_id,
                        objects: &[],
                        nonce: None,
                    }),
                };
                let operation: CommittedOrderedOperation<'_> =
                    CommittedOrderedOperation::bind_verified(env, &candidate, &block)?;
                let actual: PreparedOriginalCompletion = completion::prepare_original_completion(
                    store, context, env, &operation, &warrant, None,
                )?;
                if encode_retained_outcome(actual.outcome())?.as_slice() != source_outcome {
                    return Err(stop(
                        "ordered original outcome differs from independent business execution",
                    ));
                }
                if actual.receipt().canonical_bytes() != source_receipt {
                    return Err(stop(
                        "ordered original receipt differs from independent business execution",
                    ));
                }
                let row: OutcomeRow = read_outcome_row(store, context, env, &candidate.request_id)?;
                writes.mutate(
                    row.key,
                    row.revision,
                    StateMutation::Put(encode_retained_outcome(actual.outcome())?),
                )?;
                prepared = Some(actual);
            }
        }
    }
    for (key, revision) in reads {
        writes.read(key, revision)?;
    }
    match prepared {
        Some(prepared) => {
            let confirmed: ConfirmedOriginalCompletion = prepared.confirm(
                store,
                context,
                env.policy.domain(),
                writes,
                &admission_heads,
            )?;
            completed = Some(confirmed.into_outcome());
        }
        None => {
            let outcome: DurableCommitOutcome = store.commit_durable(
                context,
                writes.into_atomic_transaction(env.policy.domain())?,
            );
            if !matches!(outcome, DurableCommitOutcome::Committed) {
                return Err(commit_outcome_error(outcome));
            }
        }
    }
    *verifier = next;
    Ok(completed)
}

/// Everything one newly admitted candidate contributes to the single commit.
#[derive(Clone)]
struct AdmittedCandidate {
    digest: Digest32,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    writes: Vec<PendingWrite>,
    head_reads: Vec<DurableObjectHeadRead>,
    request_id: [u8; 32],
}

/// Read-only facts about an unfinished request, not admission or signing
/// authority. The owning admission phase must fence its policy and consume
/// these exact observations before any proposed writes can be committed.
struct UncompletedCandidateBinding {
    bytes: Vec<u8>,
    digest: Digest32,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    writes: Vec<PendingWrite>,
}

enum CandidateReconciliation {
    Uncompleted(UncompletedCandidateBinding),
    Completed(Box<OrderedOutcome>),
}

/// Pinned pure policy and installed durable authority must describe the same
/// profile. Manifest-free legacy policies cannot mutate a causal store.
fn fence_policy<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), OrderedEconomicsError> {
    match env.policy.admission_profile() {
        Some(profile) if profile.is_causal() => {
            fence_verified_admission_profile(store, context, env.policy.domain(), profile, reads)?
        }
        _ => require_historical_direct_writer(
            store,
            context,
            env.policy.domain(),
            env.policy.context(),
            reads,
        )?,
    }
    Ok(())
}

/// What reconciling one candidate against retained order state concluded.
enum Admission {
    /// Not yet completed: place it, with these writes.
    Fresh(AdmittedCandidate),
    /// Already completed, carrying the exact retained outcome.
    ///
    /// A signing caller must not place it a second time. The signerless
    /// observer may still record the consensus proposal that names it -- see
    /// [`observe_proposal`] -- because declared recovery has to be able to
    /// replay authentic artifacts in dependency order even when a later one
    /// re-places an operation this replica already finished.
    Completed(Box<OrderedOutcome>),
}

/// Closed coordinator purposes. Reconciliation records verified material but
/// grants no signing/reservation permission; fresh signing additionally fences
/// the exact causal inputs and acquires only this request's reservations.
enum AdmissionPurpose {
    ReconcileOnly,
    FreshSigning,
}

/// Checks the immutable request binding and original completion using bounded
/// point reads only. In particular, an unfinished request does not consult the
/// installed profile, candidate carrier, reservations, modules, objects or
/// nonces. Signing roots must check their namespace authority before entering
/// the separate admission phase. A retained header alone is not completion.
fn reconcile_candidate<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<CandidateReconciliation, OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let bytes: Vec<u8> = encode_ordered_candidate(candidate)?;
    let digest: Digest32 = candidate_digest(env.resolver(), candidate.context.epoch(), &bytes)?;
    let mut writes: Vec<PendingWrite> = Vec::new();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();

    // 1. Header reuse is a conflict before all other metadata.
    let header_key: Vec<u8> = ordered_request_header_key(chain, &candidate.request_id)?;
    let observed_header: VersionedStateValue =
        store.read_versioned_state(context, domain, &header_key)?;
    reads.insert(header_key.clone(), observed_header.revision());
    // A deleted header must never be recreated: it is the immutable binding
    // every later replay and every completion cross-check depends on.
    require_virgin_absence(&observed_header, "ordered request header row was deleted")?;
    match observed_header.value() {
        None => {
            let header: RequestHeader = RequestHeader {
                candidate_digest: digest,
                kind: candidate.kind,
                created_checkpoint: candidate.created_checkpoint,
            };
            writes.push((
                header_key,
                observed_header.revision(),
                StateMutation::Put(encode_request_header(&header)?),
            ));
        }
        Some(existing_bytes) => {
            let existing: RequestHeader = decode_request_header(existing_bytes)?;
            if existing.candidate_digest != digest
                || existing.kind != candidate.kind
                || existing.created_checkpoint != candidate.created_checkpoint
            {
                return Err(OrderedEconomicsError::RequestHeaderConflict);
            }
        }
    }

    // 2. Already completed? Answer from the retained outcome instead of
    //    creating a duplicate placement or re-acquiring released locks. This
    //    precedes every reservation and every business read below.
    let outcome_row: OutcomeRow = read_outcome_row(store, context, env, &candidate.request_id)?;
    if let Some(retained) = outcome_row.retained {
        if retained.candidate_digest != digest {
            // The header already rules this out; keep the boundary conflict
            // authoritative rather than answering with a foreign outcome.
            return Err(OrderedEconomicsError::RequestHeaderConflict);
        }
        // The outcome row is only ever written by the invocation that read the
        // committed candidate bytes, so their row already exists and matches
        // this digest; there is nothing left to place.
        return Ok(CandidateReconciliation::Completed(Box::new(retained)));
    }
    reads.insert(outcome_row.key, outcome_row.revision);
    Ok(CandidateReconciliation::Uncompleted(
        UncompletedCandidateBinding {
            bytes,
            digest,
            reads,
            writes,
        },
    ))
}

/// Prepares exact candidate retention and, only for authorized fresh signing,
/// this candidate's own reservations. Original completion returns before any
/// admission preparation. The captured header/outcome observations remain
/// part of the actual atomic admission, not permission to bypass its guards.
fn admit_candidate<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    purpose: AdmissionPurpose,
) -> Result<Admission, OrderedEconomicsError> {
    let binding: UncompletedCandidateBinding =
        match reconcile_candidate(store, context, env, candidate)? {
            CandidateReconciliation::Uncompleted(binding) => binding,
            CandidateReconciliation::Completed(outcome) => {
                return Ok(Admission::Completed(outcome));
            }
        };
    let UncompletedCandidateBinding {
        bytes,
        digest,
        mut reads,
        mut writes,
    } = binding;
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let mut head_reads: Vec<DurableObjectHeadRead> = Vec::new();
    fence_policy(store, context, env, &mut reads)?;

    // 3. Exact candidate bytes, content-addressed and immutable.
    let candidate_key = ordered_candidate_record_key(chain, digest)?;
    let observed_candidate = store.read_versioned_state(context, domain, &candidate_key)?;
    reads.insert(candidate_key.clone(), observed_candidate.revision());
    // Likewise immutable: a deleted candidate record is corruption, not room to
    // write the same content-addressed bytes again.
    require_virgin_absence(
        &observed_candidate,
        "ordered candidate record row was deleted",
    )?;
    match observed_candidate.value() {
        None => writes.push((
            candidate_key,
            observed_candidate.revision(),
            StateMutation::Put(bytes),
        )),
        Some(existing) if existing == bytes.as_slice() => {}
        Some(_) => return Err(stop("ordered candidate digest collision")),
    }

    // 4. Precisely this candidate's own address-owned reservations.
    if matches!(purpose, AdmissionPurpose::FreshSigning) {
        let plan: OrderedReservationPlan = reservation::reservation_plan(env, candidate)?;
        if env.policy.is_causal() {
            reservation::verify_causal_prerequisites(
                store,
                context,
                env,
                candidate,
                &plan,
                &mut reads,
                &mut head_reads,
            )?;
        }
        writes.extend(reservation::acquire_reservations(
            store, context, env, candidate, &plan, &mut reads,
        )?);
    }
    Ok(Admission::Fresh(AdmittedCandidate {
        digest,
        reads,
        writes,
        head_reads,
        request_id: candidate.request_id,
    }))
}

/// Read-only normal-admission barrier query over the isolated reconstruction
/// store. It uses the owning completed-first admission and complete preflight
/// at the certified block height, never an untrusted source outcome. A refused
/// or completed Freeze must not move later Owned replay targets. The caller
/// still executes the ordinary owner after resolving authenticated dependency
/// closure; this boolean grants no application or closure-bypass capability.
pub(crate) fn reconstruction_freeze_barrier_needed(
    store: &runtime::MemoryDurableStateStore,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    block_height: u64,
) -> Result<bool, OrderedEconomicsError> {
    if candidate.kind != OrderedOperationKind::Freeze {
        return Ok(false);
    }
    if !env.policy.is_causal() {
        return Err(stop(
            "business reconstruction requires pinned causal genesis",
        ));
    }
    if let Admission::Completed(_) = admit_candidate(
        store,
        context,
        env,
        candidate,
        AdmissionPurpose::ReconcileOnly,
    )? {
        return Ok(false);
    }
    match preflight::preflight(store, context, env, candidate, block_height) {
        Ok(()) => Ok(true),
        Err(OrderedEconomicsError::Refused(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Read-only scheduling query over the isolated reconstruction store. Exact
/// completed reconciliation precedes every fresh prerequisite, just as in the
/// owning execution path. The shared owning prefix preserves live authority,
/// NoFreeze, AlreadyDrained and foreign-selection refusal precedence. Only a
/// typed missing readiness dependency requests external proof material; an
/// already independently derived ready union is reused even when a candidate
/// claims a different union. The normal owner still decides and records the
/// complete business/control response. This boolean grants no capability.
pub(crate) fn reconstruction_drain_readiness_needed(
    store: &runtime::MemoryDurableStateStore,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    _block_height: u64,
) -> Result<bool, OrderedEconomicsError> {
    if candidate.kind != OrderedOperationKind::DrainSet {
        return Ok(false);
    }
    if !env.policy.is_causal() {
        return Err(stop(
            "control reconstruction requires pinned causal genesis",
        ));
    }
    env.policy.authenticate_candidate(candidate)?;
    if let Admission::Completed(_) = admit_candidate(
        store,
        context,
        env,
        candidate,
        AdmissionPurpose::ReconcileOnly,
    )? {
        return Ok(false);
    }
    preflight::require_live_authority(store, context, env)?;
    match preflight::require_admission_open(store, context, env, candidate) {
        Ok(()) => {}
        Err(OrderedEconomicsError::Refused(_)) => return Ok(false),
        Err(error) => return Err(error),
    }
    let intent: drain_set::DrainSetIntent =
        match drain_set::preflight_drain_set_prefix(store, context, env, candidate) {
            Ok(intent) => intent,
            Err(OrderedEconomicsError::Refused(_)) => return Ok(false),
            Err(error) => return Err(error),
        };
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    match drain_union::verify_drain_ready_into(
        store,
        context,
        env.policy.domain(),
        env.resolver(),
        env.policy.context(),
        &intent.selected_votes,
        &mut reads,
    ) {
        Ok(_) => Ok(false),
        Err(drain_union::DrainSignerError::NotReady(_)) => Ok(true),
        Err(error) => Err(drain_set::classify_readiness_error(error)),
    }
}

/// Reconciles one candidate for a **signing** caller: a completed request is
/// answered with its exact retained outcome instead of being placed again,
/// re-executed, or having its already-released reservations re-acquired.
fn admit_candidate_for_signer<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    proposal_height: u64,
) -> Result<AdmittedCandidate, OrderedEconomicsError> {
    let observed: ObservedBusinessReadView<'_, S> =
        ObservedBusinessReadView::new(store, env.policy.domain());
    let result: Result<AdmittedCandidate, OrderedEconomicsError> =
        admit_candidate_for_signer_observed(&observed, context, env, candidate, proposal_height);
    let (observations, mut admitted): (StateObservationSet, AdmittedCandidate) =
        observed.finish_with(result)?;
    // Every successful fresh attempt read the one-per-epoch DrainSet row, so
    // this successful scope is nonempty. The extra closure is physical CAS,
    // never a business logical dependency map or a signing witness operand.
    for read in observations.into_read_set()?.reads() {
        if admitted
            .reads
            .insert(read.key().to_vec(), read.expected_revision())
            .is_some_and(|previous| previous != read.expected_revision())
        {
            return Err(NodeCoreError::StateConflict.into());
        }
    }
    Ok(admitted)
}

fn admit_candidate_for_signer_observed<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    proposal_height: u64,
) -> Result<AdmittedCandidate, OrderedEconomicsError> {
    // Post-DrainSet liveness gate, strictly stronger than (and checked before)
    // the Freeze-only gate below: once a healthy accepted `DrainSet` has
    // committed for this chain/epoch, an honest leader/replica never again
    // places or votes for fresh business, Freeze or DrainSet candidates.
    // Only Seal can continue to its own fully warranted signing preflight,
    // unlike the business-only exemption
    // below. This reuses the exact durable one-per-epoch `DrainSetRecord` a
    // committed, accepted `DrainSet` installs; a *refused* `DrainSet` installs
    // nothing, so it never trips this gate. Assert the observed row revision
    // with either the proposal or vote commit: unlike the business-only
    // Freeze gate, this also protects control proposals that do not run an
    // authoritative closed-epoch preflight before signing.
    let drain_key: Vec<u8> = drain_set::drain_set_record_key(
        env.policy.context().chain_id(),
        env.policy.context().epoch(),
    )?;
    let (drain_record, drain_revision): (Option<drain_set::DrainSetRecord>, StateRevision) =
        drain_set::read_drain_set_record_with_revision(
            store,
            context,
            env.policy.domain(),
            env.policy.context().chain_id(),
            env.policy.context().epoch(),
        )?;
    if drain_record.is_some() {
        // The closure forbids a new candidate signature, not exact replay of
        // an outcome already committed before it. Preserve the original
        // request-header conflict precedence, then let the bounded read-only
        // outcome query verify its immutable header and receipt. None of
        // these reads touches local readiness, reservations or fresh rows.
        let bytes: Vec<u8> = encode_ordered_candidate(candidate)?;
        let digest: Digest32 = candidate_digest(env.resolver(), candidate.context.epoch(), &bytes)?;
        let header_key: Vec<u8> =
            ordered_request_header_key(env.policy.context().chain_id(), &candidate.request_id)?;
        let header_row: VersionedStateValue =
            store.read_versioned_state(context, env.policy.domain(), &header_key)?;
        require_virgin_absence(&header_row, "ordered request header row was deleted")?;
        if let Some(existing_bytes) = header_row.value() {
            let existing: RequestHeader = decode_request_header(existing_bytes)?;
            if existing.candidate_digest != digest
                || existing.kind != candidate.kind
                || existing.created_checkpoint != candidate.created_checkpoint
            {
                return Err(OrderedEconomicsError::RequestHeaderConflict);
            }
        }
        if let Some(outcome) = query_ordered_outcome(store, context, env, &candidate.request_id)? {
            if outcome.candidate_digest != digest {
                return Err(OrderedEconomicsError::RequestHeaderConflict);
            }
            return Err(OrderedEconomicsError::AlreadyCompleted(Box::new(outcome)));
        }
        if candidate.kind != OrderedOperationKind::Seal {
            return Err(OrderedEconomicsError::Refused(
                OrderedRefusal::AlreadyDrained,
            ));
        }
    }
    // DR-0154 liveness gate, additive to (not a substitute for) `preflight`'s
    // own authoritative closed-epoch refusal at commit time: an honest
    // leader/replica never even places or votes for a *fresh* business
    // candidate once a `Freeze` has committed, "Stop new ... construction of
    // fresh economic candidates" / "an honest replica emits no fresh vote for
    // a proposal whose own payload carries business." A `Freeze` candidate
    // itself is exempt -- a second one is still admissible here and resolves
    // to `AlreadyFrozen` at preflight. This check is deliberately confined to
    // this signer-only entry point (`propose`/`process_proposal`), never
    // `observe_proposal`'s reconciliation-only admission call:
    // declared, signerless recovery must still be able to record and replay
    // an authentic pre-freeze business proposal's bytes during catch-up, so
    // its own already-justified inherited suffix can reach the deterministic
    // closed-epoch refusal at commit time instead of never being recorded at
    // all. Closure and warrant observations join the same CAS batch as the
    // signing identity: a concurrent Freeze cannot expose a fresh vote.
    match admit_candidate(
        store,
        context,
        env,
        candidate,
        AdmissionPurpose::FreshSigning,
    )? {
        Admission::Fresh(mut admitted) => {
            admitted.reads.insert(drain_key, drain_revision);
            if !matches!(
                candidate.kind,
                OrderedOperationKind::Freeze
                    | OrderedOperationKind::DrainSet
                    | OrderedOperationKind::Seal
            ) && freeze::read_authorized_closure(store, context, env)?.is_some()
            {
                return Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch));
            }
            if candidate.kind == OrderedOperationKind::Freeze {
                freeze::require_freeze_warrant(store, context, env, candidate, proposal_height)?;
            }
            if candidate.kind == OrderedOperationKind::DrainSet {
                drain_set::require_drain_set_readiness(
                    store,
                    context,
                    env,
                    candidate,
                    &mut admitted.reads,
                )?;
            }
            if candidate.kind == OrderedOperationKind::Seal {
                preflight::preflight(store, context, env, candidate, proposal_height)?;
            }
            Ok(admitted)
        }
        Admission::Completed(outcome) => Err(OrderedEconomicsError::AlreadyCompleted(outcome)),
    }
}

/// Builds one durable receipt (`NodeDedupRecord`-backed) keyed by
/// `request_id`, replaying `output`'s responses idempotently. Used for a
/// retained refusal and an accepted control/evidence preparation, which
/// otherwise has no request-id receipt of its own.
pub(super) fn build_receipt(
    request_id: [u8; 32],
    event_digest: Digest32,
    output: &NodeOutput,
) -> Result<DurableRequestReceipt, NodeCoreError> {
    let typed_request_id = RequestId::new(request_id)?;
    let dedup = NodeDedupRecord::new(typed_request_id, event_digest, output.responses().to_vec())?;
    DurableRequestReceipt::new(
        DurableRequestId::new(request_id)
            .map_err(|_| invalid("invalid durable request identity"))?,
        event_digest,
        dedup.encode()?,
    )
    .map_err(NodeCoreError::from)
}

/// Merges every read and mutation this invocation produced with the event
/// application's outcome, executes at most one newly committed candidate, and
/// commits exactly once: through `commit_invocation` when a business
/// operation executed (merged with the handler's **own original** receipt and
/// object changes), through plain `commit_durable` when only infrastructure
/// state changed, and not at all when nothing changed -- so a byte-identical
/// exact replay never rewrites a row or increments a revision.
#[allow(clippy::too_many_arguments)]
fn finalize_event<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    loaded: &LoadedState,
    consensus_output: ConsensusOutput,
    admitted: Option<AdmittedCandidate>,
    vote: Option<(LocalVoteReconciliation, Option<consensus::ConsensusVote>)>,
) -> Result<OrderedEventOutput, OrderedEconomicsError> {
    prepare_event(
        store,
        context,
        env,
        loaded,
        consensus_output,
        admitted,
        vote,
    )?
    .confirm(store, context)
}

/// An unpublished result and its one explicit completion kind, produced by
/// the handler's actual read-only observation preparation. A capacity probe
/// only builds and drops this proposal; it never simulates confirmation.
struct PreparedEventCompletion {
    result: OrderedEventOutput,
    completion: PreparedEventWrite,
}

enum PreparedEventWrite {
    Unchanged,
    Metadata(AtomicStateTransaction),
    Admission(DurableInvocationTransaction),
    Original(AssembledOriginalCompletion),
}

impl PreparedEventCompletion {
    fn confirm<S: StructuredDurableDomainStateStore>(
        mut self,
        store: &S,
        context: &DurableOperationContext,
    ) -> Result<OrderedEventOutput, OrderedEconomicsError> {
        let outcome: DurableCommitOutcome = match self.completion {
            PreparedEventWrite::Unchanged => return Ok(self.result),
            PreparedEventWrite::Metadata(transaction) => store.commit_durable(context, transaction),
            PreparedEventWrite::Admission(transaction) => {
                store.commit_invocation(context, transaction)
            }
            PreparedEventWrite::Original(prepared) => {
                let confirmed: ConfirmedOriginalCompletion = prepared.confirm(store, context)?;
                self.result.committed = vec![confirmed.into_outcome()];
                return Ok(self.result);
            }
        };
        match outcome {
            DurableCommitOutcome::Committed => Ok(self.result),
            outcome => Err(commit_outcome_error(outcome)),
        }
    }
    fn confirm_seal_retention(
        self,
        repository: &dyn OutgoingSealRepository,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        observations: &StateObservationSet,
    ) -> Result<OrderedEventOutput, OrderedEconomicsError> {
        match self.completion {
            PreparedEventWrite::Metadata(transaction) => {
                let domain: AtomicityDomainId = transaction.domain();
                let mut writes: MergedWrites = MergedWrites::new(domain);
                writes.merge_handler_state(&DurableStateTransaction::from(transaction))?;
                writes.merge_observations(observations)?;
                match repository.commit_seal_retention(
                    context,
                    token,
                    writes.into_atomic_transaction(domain)?,
                ) {
                    DurableCommitOutcome::Committed => Ok(self.result),
                    outcome => Err(commit_outcome_error(outcome)),
                }
            }
            PreparedEventWrite::Unchanged
            | PreparedEventWrite::Admission(_)
            | PreparedEventWrite::Original(_) => Err(stop(
                "ordered Seal signing retention requires a pure metadata completion",
            )),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_event<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    loaded: &LoadedState,
    consensus_output: ConsensusOutput,
    admitted: Option<AdmittedCandidate>,
    vote: Option<(LocalVoteReconciliation, Option<consensus::ConsensusVote>)>,
) -> Result<PreparedEventCompletion, OrderedEconomicsError> {
    let domain = env.policy.domain();
    let chain = env.policy.context().chain_id().clone();
    let (applied_height, applied_height_key, applied_height_revision) =
        load_applied_height(store, context, env)?;
    if applied_height > loaded.state.committed_height {
        return Err(stop(
            "ordered applied height exceeds the committed height; state is inconsistent",
        ));
    }

    let next_state = consensus_output.state;
    let economic_blocks: Vec<&CommittedBlock> = consensus_output
        .committed_blocks
        .iter()
        .filter(|block| !block.transactions.is_empty())
        .collect();
    if economic_blocks.len() > MAX_ORDERED_EVENT_COMMITTED {
        return Err(stop(
            "ordered economics cannot execute more than one newly committed candidate per invocation",
        ));
    }
    if !economic_blocks.is_empty()
        && admitted
            .as_ref()
            .is_some_and(|item| !item.head_reads.is_empty())
    {
        return Err(stop(
            "causal business predecessor must commit before head-reading fresh signing",
        ));
    }

    let mut writes = MergedWrites::new(domain);
    let mut policy_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut policy_reads)?;
    for (key, revision) in policy_reads {
        writes.read(key, revision)?;
    }
    writes.read(loaded.key.clone(), loaded.revision)?;
    writes.read(applied_height_key.clone(), applied_height_revision)?;

    // Capture/archive every committed height, including empty and replay
    // windows, in the same CAS as the original receipt and application effects.
    // Older missing archives do not alter historical ordering admission.
    // Export refuses them; no proof is fabricated or silently backfilled.
    if consensus_output.committed_proofs.len() != consensus_output.committed_blocks.len() {
        return Err(stop("ordered consensus omitted a committed proof"));
    }
    let mut prior_height: u64 = loaded.state.committed_height;
    let mut prior_digest: Option<Digest32> = None;
    let mut prior_view: Option<u64> = None;
    for (block, proof) in consensus_output
        .committed_blocks
        .iter()
        .zip(consensus_output.committed_proofs.iter())
    {
        let verified: CommittedBlock =
            super::ordered_history::verified_committed_block(env.policy, proof)?;
        if verified != *block
            || block.height
                != prior_height
                    .checked_add(1)
                    .ok_or(stop("ordered committed proof height overflow"))?
        {
            return Err(stop("ordered committed proof is not contiguous"));
        }
        if prior_digest.is_none() {
            if prior_height == 0 {
                prior_digest = Some(env.policy.anchor());
                prior_view = Some(0);
            } else {
                let digest: Digest32 = proof.committed.justify.proposal_digest;
                let previous: &ConsensusProposal = loaded
                    .state
                    .known_proposal(&digest)
                    .ok_or(stop("ordered committed predecessor is unavailable"))?;
                if previous.height != prior_height || !loaded.state.contains_committed(&digest) {
                    return Err(stop(
                        "ordered committed predecessor disagrees with local prefix",
                    ));
                }
                prior_digest = Some(digest);
                prior_view = Some(previous.view);
            }
        }
        if proof.committed.justify.height != prior_height
            || Some(proof.committed.justify.proposal_digest) != prior_digest
            || Some(proof.committed.justify.view) != prior_view
        {
            return Err(stop("ordered committed proof does not extend predecessor"));
        }
        let key: Vec<u8> =
            ordered_committed_proof_key(&chain, env.policy.context().epoch(), block.height)?;
        let observed: VersionedStateValue = store.read_versioned_state(context, domain, &key)?;
        if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
            return Err(stop(
                "ordered committed proof height already exists or was deleted",
            ));
        }
        let bytes: Vec<u8> = consensus::encode_committed_block_proof(proof)
            .map_err(|_| stop("ordered committed proof does not encode within capacity"))?;
        writes.mutate(key, observed.revision(), StateMutation::Put(bytes))?;
        prior_height = block.height;
        prior_digest = Some(block.digest);
        prior_view = Some(block.view);
    }

    let next_state_bytes = encode_consensus_state(&next_state)
        .map_err(|_| stop("ordered consensus state does not encode"))?;
    let stored_state_bytes = encode_consensus_state(&loaded.state)
        .map_err(|_| stop("ordered consensus state does not encode"))?;
    if next_state_bytes != stored_state_bytes {
        writes.record_mutation(loaded.key.clone(), StateMutation::Put(next_state_bytes))?;
    }

    if let Some(admitted) = &admitted {
        for (key, revision) in &admitted.reads {
            writes.read(key.clone(), *revision)?;
        }
        for write in &admitted.writes {
            writes.apply(write.clone())?;
        }
    }

    if let Some((reconciliation, produced)) = &vote {
        if let (RetainedIdentity::Absent, Some(produced_vote)) =
            (&reconciliation.retained, produced)
        {
            let record = identity::LocalVoteRecord {
                view: produced_vote.view,
                proposal_digest: produced_vote.proposal_digest,
                vote: consensus::encode_vote(produced_vote)
                    .map_err(|_| stop("ordered vote does not encode"))?,
            };
            writes.mutate(
                reconciliation.record_key.clone(),
                reconciliation.record_revision,
                StateMutation::Put(identity::encode_local_vote_record(&record)?),
            )?;
            if produced_vote.view > reconciliation.high_water {
                writes.mutate(
                    reconciliation.high_key.clone(),
                    reconciliation.high_revision,
                    StateMutation::Put(identity::encode_vote_high_water(produced_vote.view)?),
                )?;
            } else {
                writes.read(
                    reconciliation.high_key.clone(),
                    reconciliation.high_revision,
                )?;
            }
        } else {
            // Exact replay, or no vote produced: assert both rows unchanged
            // so an old proposal replayed after pruning cannot rewrite them.
            writes.read(
                reconciliation.record_key.clone(),
                reconciliation.record_revision,
            )?;
            writes.read(
                reconciliation.high_key.clone(),
                reconciliation.high_revision,
            )?;
        }
    }

    let mut new_applied_height = applied_height;
    let batch_applied_height: u64 = consensus_output
        .committed_blocks
        .last()
        .map_or(applied_height, |block| block.height);
    let mut prepared: Option<PreparedOriginalCompletion> = None;
    let mut execution_admission_heads: Vec<DurableObjectHeadRead> = Vec::new();

    if let Some(block) = economic_blocks.first().copied() {
        if applied_height != loaded.state.committed_height {
            return Err(stop(
                "ordered economics unapplied committed prefix; declared catch-up required",
            ));
        }
        let digest = block.transactions[0];
        let candidate_key = ordered_candidate_record_key(&chain, digest)?;
        let observed_candidate = store.read_versioned_state(context, domain, &candidate_key)?;
        let Some(candidate_bytes) = observed_candidate.value().map(<[u8]>::to_vec) else {
            return Err(stop(
                "ordered economics missing committed candidate bytes; declared catch-up required",
            ));
        };
        writes.read(candidate_key, observed_candidate.revision())?;
        let candidate = decode_ordered_candidate(&candidate_bytes)?;
        if env.policy.is_causal() {
            authenticate_candidate(env, &candidate)?;
            if env.policy.candidate_digest(&candidate)? != digest {
                return Err(stop("causal committed candidate digest differs"));
            }
        }
        // An already-completed candidate can legitimately reappear in a later
        // economic window (a replaying or byzantine leader places it again).
        // Answer with its EXACT retained outcome: re-execute nothing, write no
        // receipt, touch no lock, and rewrite no revision. Only the
        // applied-height marker advances, because the block really did commit.
        //
        // This returns before the reservation rows are read and before any
        // handler runs, so a completed candidate costs no module, object or
        // sender-nonce lookup at all.
        let outcome_row: OutcomeRow = read_outcome_row(store, context, env, &candidate.request_id)?;
        if let Some(retained) = outcome_row.retained {
            if retained.candidate_digest != digest {
                return Err(stop(
                    "retained ordered outcome disagrees with the committed candidate digest",
                ));
            }
            writes.read(outcome_row.key, outcome_row.revision)?;
            if batch_applied_height != applied_height {
                writes.record_mutation(
                    applied_height_key,
                    StateMutation::Put(encode_applied_height(batch_applied_height)?),
                )?;
            }
            let output = OrderedEventOutput {
                messages: consensus_output.outbound_messages,
                committed: vec![retained],
            };
            materialize_event_output(&output)?;
            let completion: PreparedEventWrite = if writes.is_unchanged() {
                PreparedEventWrite::Unchanged
            } else {
                PreparedEventWrite::Metadata(writes.into_atomic_transaction(domain)?)
            };
            return Ok(PreparedEventCompletion {
                result: output,
                completion,
            });
        }
        if env.policy.is_causal() {
            let plan: OrderedReservationPlan = reservation::reservation_plan(env, &candidate)?;
            let mut prerequisite_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
            reservation::verify_causal_prerequisites(
                store,
                context,
                env,
                &candidate,
                &plan,
                &mut prerequisite_reads,
                &mut execution_admission_heads,
            )?;
            for (key, revision) in prerequisite_reads {
                writes.read(key, revision)?;
            }
        }
        // Only this exact request's own retained reservations may be reused.
        let retained = reservation::load_reservation(store, context, env, &candidate.request_id)?;
        let empty_plan: OrderedReservationPlan = OrderedReservationPlan::default();
        let plan: &OrderedReservationPlan =
            retained.as_ref().map_or(&empty_plan, |(plan, _, _)| plan);
        let warrant: ExecutionWarrant<'_> = ExecutionWarrant {
            kind: ExecutionWarrantKind::Reserved(OrderedLegAdmission {
                request_id: candidate.request_id,
                objects: plan.objects.as_slice(),
                nonce: plan.nonce,
            }),
        };
        let operation: CommittedOrderedOperation<'_> =
            CommittedOrderedOperation::bind_verified(env, &candidate, block)?;
        let actual: PreparedOriginalCompletion = completion::prepare_original_completion(
            store,
            context,
            env,
            &operation,
            &warrant,
            store.outgoing_seal_repository(),
        )?;
        // Successful preparation includes acceptance or a typed no-effect
        // refusal. A stop returns above and releases no reservation.
        let release: Vec<PendingWrite> = match &retained {
            None => Vec::new(),
            Some((plan, record_key, record_revision)) => reservation::release_reservations(
                store,
                context,
                env,
                plan,
                record_key.clone(),
                *record_revision,
            )?,
        };
        // Retain the exact completed outcome atomically with the original
        // receipt and order rows, so an exact proposal/certificate replay or an
        // interrupted client resume can be answered from it without re-placing
        // or re-executing anything.
        writes.mutate(
            outcome_row.key,
            outcome_row.revision,
            StateMutation::Put(encode_retained_outcome(actual.outcome())?),
        )?;
        prepared = Some(actual);
        for write in release {
            writes.apply(write)?;
        }
        // Exactly one economic block was fully processed; every other
        // newly committed block has been verified empty. Mark its followers
        // applied in this same archive/effects CAS, never after a stop.
        new_applied_height = batch_applied_height;
    } else if let Some(block) = consensus_output
        .committed_blocks
        .iter()
        .max_by_key(|block| block.height)
    {
        // Empty windows carry no economic effect, so their heights may be
        // marked applied directly.
        new_applied_height = block.height;
    }

    if new_applied_height != applied_height {
        writes.record_mutation(
            applied_height_key,
            StateMutation::Put(encode_applied_height(new_applied_height)?),
        )?;
    }

    let result: OrderedEventOutput = OrderedEventOutput {
        messages: consensus_output.outbound_messages,
        committed: prepared
            .as_ref()
            .map(|item| item.outcome().clone())
            .into_iter()
            .collect(),
    };
    // Prove the answer is canonically representable while failing is still
    // free: never commit state whose own committed response cannot be encoded.
    materialize_event_output(&result)?;
    let completion: PreparedEventWrite = if let Some(prepared) = prepared {
        PreparedEventWrite::Original(prepared.assemble(
            domain,
            writes,
            &execution_admission_heads,
        )?)
    } else if admitted
        .as_ref()
        .is_some_and(|item| !item.head_reads.is_empty())
    {
        let item: &AdmittedCandidate = admitted.as_ref().ok_or(stop("missing causal admission"))?;
        let view: u64 = vote
            .as_ref()
            .and_then(|(_, produced)| produced.as_ref())
            .map(|produced| produced.view)
            .ok_or(stop("head-reading admission produced no vote"))?;
        let transaction: DurableInvocationTransaction = admission_transaction(
            env,
            item,
            reservation::OrderedAdmissionStage::Vote,
            view,
            writes,
        )?;
        PreparedEventWrite::Admission(transaction)
    } else if !writes.is_unchanged() {
        PreparedEventWrite::Metadata(writes.into_atomic_transaction(domain)?)
    } else {
        PreparedEventWrite::Unchanged
    };
    Ok(PreparedEventCompletion { result, completion })
}

/// Height-`%3==1` windows may carry one candidate; every other height must
/// stay empty (DR-0153's closed three-chain scheduling profile).
fn transactions_for(
    state: &ConsensusState,
    digest: Option<Digest32>,
) -> Result<Vec<Digest32>, OrderedEconomicsError> {
    let next_height = state
        .high_qc
        .height
        .checked_add(1)
        .ok_or(stop("ordered economics height overflow"))?;
    match (next_height % 3 == 1, digest) {
        (true, Some(digest)) => Ok(vec![digest]),
        (_, None) => Ok(Vec::new()),
        (false, Some(_)) => Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate proposed at a non-economic height",
        )),
    }
}

/// Requires the closed profile's transaction shape: zero digests, or exactly
/// one at an economic-bearing height.
pub(super) fn require_profile_shape(
    proposal: &ConsensusProposal,
) -> Result<(), OrderedEconomicsError> {
    let economic_height: bool = proposal.height % 3 == 1;
    match (proposal.transactions.len(), economic_height) {
        (0, _) | (1, true) => Ok(()),
        _ => Err(OrderedEconomicsError::Unauthenticated(
            "ordered proposal violates the closed three-chain scheduling profile",
        )),
    }
}

/// Refuses to sign a vote until this replica's economic prefix is genuinely
/// ready for the branch being voted on.
///
/// A cryptographically valid justify certificate with unknown parent content
/// is *not* local execution readiness. This requires:
///
/// * every already-committed height's economic effect to be durably applied
///   (`applied_height == committed_height`), and
/// * every certified ancestor above the committed height to be known locally
///   **with its candidate bytes present**.
///
/// Either gap stops with a declared-catch-up prerequisite instead of voting.
/// `observe_proposal` deliberately does not run this: recovery is how the gap
/// is closed, and it signs nothing.
fn require_vote_readiness<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    state: &ConsensusState,
    proposal: &ConsensusProposal,
) -> Result<(), OrderedEconomicsError> {
    let (applied_height, _, _) = load_applied_height(store, context, env)?;
    if applied_height != state.committed_height {
        return Err(stop(
            "ordered applied prefix lags the committed height; declared catch-up required",
        ));
    }
    let chain = env.policy.context().chain_id();
    let domain = env.policy.domain();
    let mut cursor: Digest32 = proposal.justify.proposal_digest;
    let mut justify_view: u64 = proposal.justify.view;
    for _ in 0..MAX_VOTE_ANCESTOR_WALK {
        if justify_view == 0 {
            // The genesis anchor: nothing above the committed height remains.
            return Ok(());
        }
        let Some(ancestor) = state.known_proposal(&cursor) else {
            return Err(stop(
                "ordered proposal's certified ancestor payload is unknown locally; declared catch-up required",
            ));
        };
        if ancestor.height <= state.committed_height {
            return Ok(());
        }
        for digest in &ancestor.transactions {
            let key = ordered_candidate_record_key(chain, *digest)?;
            if store
                .read_versioned_state(context, domain, &key)?
                .value()
                .is_none()
            {
                return Err(stop(
                    "ordered proposal's certified ancestor is missing its candidate bytes; declared catch-up required",
                ));
            }
        }
        cursor = ancestor.justify.proposal_digest;
        justify_view = ancestor.justify.view;
    }
    Err(stop("ordered certified-ancestor walk exceeded its bound"))
}

/// Builds and signs a proposal for the current view, exactly as
/// [`consensus::ChainedHotStuff::propose`] does, optionally carrying one
/// candidate at an economic-bearing height.
///
/// The exact signed leader-proposal identity is durably recorded, keyed by
/// view and leader, **before** the signed proposal is returned. Presenting a
/// *different* candidate for a view this leader already signed fails closed
/// rather than producing a second, conflicting signed proposal: an honest
/// leader does not equivocate because its caller changed its mind. Presenting
/// the same work again replays the exact retained proposal and writes nothing.
///
/// The candidate's own address-owned inputs and sender-nonce range are
/// reserved in the same commit, under the same durable FastVote lock keys.
pub fn propose<S, C>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: Option<&OrderedCandidate>,
    signer: &C,
) -> Result<OrderedProposal, OrderedEconomicsError>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    // 1. Pure authentication, before any storage read.
    if let Some(candidate) = candidate {
        authenticate_candidate(env, candidate)?;
    }
    if env.policy.is_causal() {
        return propose_causal(store, context, env, candidate, signer);
    }
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let loaded = load_state(store, context, env)?;
    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut profile_reads)?;
    let proposal_height: u64 = loaded
        .state
        .high_qc
        .height
        .checked_add(1)
        .ok_or(stop("ordered economics height overflow"))?;
    // 2. Header conflict, before any other metadata, and the candidate's own
    //    reservations.
    let admitted = match candidate {
        Some(candidate) => Some(admit_candidate_for_signer(
            store,
            context,
            env,
            candidate,
            proposal_height,
        )?),
        None => None,
    };
    let transactions = transactions_for(&loaded.state, admitted.as_ref().map(|a| a.digest))?;
    let proposal = env
        .policy
        .engine()
        .propose(&loaded.state, transactions, signer)
        .map_err(consensus_to_node)?;
    let digest = env
        .policy
        .engine()
        .proposal_digest(&proposal)
        .map_err(consensus_to_node)?;

    // 3. Exact leader identity, keyed by epoch/view/leader, CAS-recorded
    //    before the signature is exposed.
    let (key, revision, retained) = identity::reconcile_leader_proposal(
        store,
        context,
        env,
        proposal.view,
        signer.validator_id(),
        digest,
    )?;
    if let RetainedIdentity::Exact(retained_proposal) = retained {
        // Exact repeated output: nothing is rewritten, no revision bumped.
        return Ok(OrderedProposal {
            proposal: retained_proposal,
            candidate: candidate.cloned(),
        });
    }

    let record = identity::LeaderProposalRecord {
        view: proposal.view,
        leader: proposal.leader,
        proposal_digest: digest,
        proposal: encode_proposal(&proposal)
            .map_err(|_| stop("ordered proposal does not encode"))?,
    };
    let mut writes = MergedWrites::new(env.policy.domain());
    for (key, revision) in profile_reads {
        writes.read(key, revision)?;
    }
    writes.mutate(
        key,
        revision,
        StateMutation::Put(identity::encode_leader_proposal_record(&record)?),
    )?;
    if let Some(admitted) = &admitted {
        for (key, revision) in &admitted.reads {
            writes.read(key.clone(), *revision)?;
        }
        for write in &admitted.writes {
            writes.apply(write.clone())?;
        }
    }
    // `propose` applies no consensus event, so it commits only the leader
    // identity, candidate/header bookkeeping and reservations -- atomically.
    if let outcome @ (DurableCommitOutcome::Rejected(_) | DurableCommitOutcome::Indeterminate(_)) =
        store.commit_durable(
            context,
            writes.into_atomic_transaction(env.policy.domain())?,
        )
    {
        return Err(commit_outcome_error(outcome));
    }
    Ok(OrderedProposal {
        proposal,
        candidate: candidate.cloned(),
    })
}

#[allow(clippy::too_many_arguments)]
fn causal_leader_writes<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    loaded: &LoadedState,
    proposal: &ConsensusProposal,
    digest: Digest32,
    identity_key: &[u8],
    revision: StateRevision,
    admitted: Option<&AdmittedCandidate>,
) -> Result<MergedWrites, OrderedEconomicsError> {
    let record: identity::LeaderProposalRecord = identity::LeaderProposalRecord {
        view: proposal.view,
        leader: proposal.leader,
        proposal_digest: digest,
        proposal: encode_proposal(proposal)
            .map_err(|_| stop("ordered proposal does not encode"))?,
    };
    let mut writes: MergedWrites = MergedWrites::new(env.policy.domain());
    writes.read(loaded.key.clone(), loaded.revision)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut reads)?;
    for (key, revision) in reads {
        writes.read(key, revision)?;
    }
    writes.mutate(
        identity_key.to_vec(),
        revision,
        StateMutation::Put(identity::encode_leader_proposal_record(&record)?),
    )?;
    if let Some(admitted) = admitted {
        for (key, revision) in &admitted.reads {
            writes.read(key.clone(), *revision)?;
        }
        for write in &admitted.writes {
            writes.apply(write.clone())?;
        }
    }
    Ok(writes)
}

/// DR-0187: Seal signing requires the live OutgoingSealRepository SAMESTORE
/// capability and composition before any proposal or vote is produced for
/// it, not only at eventual acceptance. Every other candidate kind is
/// unaffected. A missing capability stops; it never silently falls back to
/// ordinary signing or a fabricated refusal.
fn require_seal_signing_capability<S: StructuredDurableDomainStateStore>(
    store: &S,
    candidate: Option<&OrderedCandidate>,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<(), OrderedEconomicsError> {
    let is_seal: bool =
        candidate.is_some_and(|candidate| candidate.kind == OrderedOperationKind::Seal);
    let capable: bool = env.seal.is_some() && store.outgoing_seal_repository().is_some();
    if is_seal && !capable {
        return Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing requires the live Seal composition and OutgoingSealRepository capability",
        ));
    }
    Ok(())
}

fn propose_causal<S, C>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: Option<&OrderedCandidate>,
    signer: &C,
) -> Result<OrderedProposal, OrderedEconomicsError>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    let preliminary: Option<Digest32> = match candidate {
        Some(candidate) => match reconcile_candidate(store, context, env, candidate)? {
            CandidateReconciliation::Uncompleted(binding) => Some(binding.digest),
            CandidateReconciliation::Completed(outcome) => {
                return Err(OrderedEconomicsError::AlreadyCompleted(outcome));
            }
        },
        None => None,
    };
    require_seal_signing_capability(store, candidate, env)?;
    crate::mutation_fence::require_origin_ordinary_namespace(store, context, env.policy.domain())?;
    let mut loaded: LoadedState = load_state(store, context, env)?;
    // The current high QC can itself finish the justified prefix. A capacity
    // preview and a retained leader signature must not bypass that completion.
    let prefix: ConsensusOutput = env
        .policy
        .engine()
        .on_observer_event(
            &loaded.state,
            ConsensusEvent::Certificate(loaded.state.high_qc.clone()),
            &Ed25519ConsensusVerifier,
        )
        .map_err(consensus_to_node)?;
    if !prefix.committed_blocks.is_empty() {
        finalize_event(store, context, env, &loaded, prefix, None, None)?;
        loaded = load_state(store, context, env)?;
    }
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let transactions: Vec<Digest32> = transactions_for(&loaded.state, preliminary)?;
    let probe: CapacityProbeSigner<'_, C> = CapacityProbeSigner(signer);
    let preview: ConsensusProposal = env
        .policy
        .engine()
        .propose(&loaded.state, transactions.clone(), &probe)
        .map_err(consensus_to_node)?;
    let digest: Digest32 = env
        .policy
        .engine()
        .proposal_digest(&preview)
        .map_err(consensus_to_node)?;
    let (key, revision, retained) =
        identity::reconcile_unsigned_leader_proposal(store, context, env, &preview)?;
    if let RetainedIdentity::Exact(retained) = retained {
        if let Some(candidate) = candidate {
            require_admission_receipt(
                store,
                context,
                env,
                candidate,
                reservation::OrderedAdmissionStage::LeaderProposal,
                retained.view,
            )?;
        }
        crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
        return Ok(OrderedProposal {
            proposal: retained,
            candidate: candidate.cloned(),
        });
    }
    let admitted: Option<AdmittedCandidate> = candidate
        .map(|candidate| admit_candidate_for_signer(store, context, env, candidate, preview.height))
        .transpose()?;
    let probe_writes: MergedWrites = causal_leader_writes(
        store,
        context,
        env,
        &loaded,
        &preview,
        digest,
        &key,
        revision,
        admitted.as_ref(),
    )?;
    if let Some(item) = admitted.as_ref().filter(|item| !item.head_reads.is_empty()) {
        drop(admission_transaction(
            env,
            item,
            reservation::OrderedAdmissionStage::LeaderProposal,
            preview.view,
            probe_writes,
        )?);
    } else {
        drop(probe_writes.into_atomic_transaction(env.policy.domain())?);
    }
    let mut seal_signing_observations: StateObservationSet =
        StateObservationSet::new(env.policy.domain());
    let seal_signing_token: Option<PortableSnapshotToken> =
        match candidate.filter(|item| item.kind == OrderedOperationKind::Seal) {
            Some(fresh_candidate) => {
                if admitted
                    .as_ref()
                    .is_some_and(|item| !item.head_reads.is_empty())
                {
                    return Err(stop(
                        "ordered Seal signing admission unexpectedly produced object reads",
                    ));
                }
                Some(require_seal_signing_retention(
                    store,
                    context,
                    env,
                    fresh_candidate,
                    &loaded,
                    &loaded.state.high_qc,
                    &mut seal_signing_observations,
                )?)
            }
            None => None,
        };
    let proposal: ConsensusProposal = env
        .policy
        .engine()
        .propose(&loaded.state, transactions, signer)
        .map_err(consensus_to_node)?;
    let mut comparable: ConsensusProposal = proposal.clone();
    comparable.signature = preview.signature.clone();
    if comparable != preview || proposal.signature.len() != preview.signature.len() {
        return Err(stop("ordered proposal differs from capacity probe"));
    }
    let digest: Digest32 = env
        .policy
        .engine()
        .proposal_digest(&proposal)
        .map_err(consensus_to_node)?;
    env.policy
        .engine()
        .verify_proposal(&proposal, &Ed25519ConsensusVerifier)
        .map_err(consensus_to_node)?;
    let mut writes: MergedWrites = causal_leader_writes(
        store,
        context,
        env,
        &loaded,
        &proposal,
        digest,
        &key,
        revision,
        admitted.as_ref(),
    )?;
    let outcome: DurableCommitOutcome = if let Some(token) = seal_signing_token.as_ref() {
        if admitted
            .as_ref()
            .is_some_and(|item| !item.head_reads.is_empty())
        {
            return Err(stop(
                "ordered Seal retention cannot contain object admission",
            ));
        }
        writes.merge_observations(&seal_signing_observations)?;
        let repository: &dyn OutgoingSealRepository = store.outgoing_seal_repository().ok_or(
            stop("ordered Seal signing capability vanished before commit"),
        )?;
        repository.commit_seal_retention(
            context,
            token,
            writes.into_atomic_transaction(env.policy.domain())?,
        )
    } else if let Some(item) = admitted.as_ref().filter(|item| !item.head_reads.is_empty()) {
        store.commit_invocation(
            context,
            admission_transaction(
                env,
                item,
                reservation::OrderedAdmissionStage::LeaderProposal,
                proposal.view,
                writes,
            )?,
        )
    } else {
        store.commit_durable(
            context,
            writes.into_atomic_transaction(env.policy.domain())?,
        )
    };
    if !matches!(outcome, DurableCommitOutcome::Committed) {
        return Err(commit_outcome_error(outcome));
    }
    Ok(OrderedProposal {
        proposal,
        candidate: candidate.cloned(),
    })
}

/// Applies one leader proposal, voting when safe: the local validator's only
/// path to sign a new [`consensus::ConsensusVote`].
pub fn process_proposal<S, C>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    proposal: &OrderedProposal,
    signer: &C,
) -> Result<OrderedEventOutput, OrderedEconomicsError>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    // 1. Pure authentication of every signed input, before clock or storage.
    require_profile_shape(&proposal.proposal)?;
    env.policy
        .engine()
        .verify_proposal(&proposal.proposal, &Ed25519ConsensusVerifier)
        .map_err(|_| {
            OrderedEconomicsError::Unauthenticated("ordered proposal failed verification")
        })?;
    if let Some(candidate) = &proposal.candidate {
        authenticate_candidate(env, candidate)?;
    }
    if env.policy.is_causal() {
        // Completed originals reconcile before live capabilities, blobs or
        // signing authority. Their exact immutable replay performs no write.
        if let Some(candidate) = &proposal.candidate {
            let expected: [Digest32; 1] = [env.policy.candidate_digest(candidate)?];
            if proposal.proposal.transactions.as_slice() != expected.as_slice() {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "causal proposal candidate digest differs",
                ));
            }
            match reconcile_candidate(store, context, env, candidate)? {
                CandidateReconciliation::Uncompleted(_) => {}
                CandidateReconciliation::Completed(outcome) => {
                    return Err(OrderedEconomicsError::AlreadyCompleted(outcome));
                }
            }
        } else if !proposal.proposal.transactions.is_empty() {
            return Err(stop("causal proposal lacks delivered candidate bytes"));
        }
    }
    require_seal_signing_capability(store, proposal.candidate.as_ref(), env)?;
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let mut loaded = load_state(store, context, env)?;
    let digest = env
        .policy
        .engine()
        .proposal_digest(&proposal.proposal)
        .map_err(consensus_to_node)?;

    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut profile_reads)?;
    let mut prefix_committed: Vec<OrderedOutcome> = Vec::new();
    if env.policy.is_causal() {
        require_vote_readiness(store, context, env, &loaded.state, &proposal.proposal)?;
        // Preserve the existing future-view/branch admission checks before
        // using the independently authenticated certificate for progress.
        env.policy
            .engine()
            .on_observer_event(
                &loaded.state,
                ConsensusEvent::Proposal(proposal.proposal.clone()),
                &Ed25519ConsensusVerifier,
            )
            .map_err(consensus_to_node)?;
        let prefix: ConsensusOutput = env
            .policy
            .engine()
            .on_observer_event(
                &loaded.state,
                ConsensusEvent::Certificate(proposal.proposal.justify.clone()),
                &Ed25519ConsensusVerifier,
            )
            .map_err(consensus_to_node)?;
        if !prefix.committed_blocks.is_empty() {
            let mut commits_control: bool = false;
            for block in &prefix.committed_blocks {
                for candidate_digest in &block.transactions {
                    let key: Vec<u8> = ordered_candidate_record_key(
                        env.policy.context().chain_id(),
                        *candidate_digest,
                    )?;
                    let row: VersionedStateValue =
                        store.read_versioned_state(context, env.policy.domain(), &key)?;
                    let candidate: OrderedCandidate = decode_ordered_candidate(
                        row.value()
                            .ok_or(stop("causal prefix lacks committed candidate material"))?,
                    )?;
                    commits_control |= matches!(
                        candidate.kind,
                        OrderedOperationKind::Freeze
                            | OrderedOperationKind::DrainSet
                            | OrderedOperationKind::Seal
                    );
                }
            }
            let observed: OrderedEventOutput =
                finalize_event(store, context, env, &loaded, prefix, None, None)?;
            prefix_committed = observed.committed;
            // Committing either control ends fresh candidate signing. The
            // prefix is genuine progress, not a locally invented refusal.
            if proposal.candidate.is_some() && commits_control {
                return Ok(OrderedEventOutput {
                    messages: Vec::new(),
                    committed: prefix_committed,
                });
            }
            loaded = load_state(store, context, env)?;
        }
    }
    // A retained vote is still this validator's own live signature. Process
    // justified progress first, then reobserve the outgoing barrier before
    // considering either a retained response or a fresh vote.
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let retained: LocalVoteReconciliation =
        identity::reconcile_local_vote(store, context, env, proposal.proposal.view, digest)?;
    if let RetainedIdentity::Exact(vote) = retained.retained {
        if vote.validator != signer.validator_id() {
            return Err(stop("retained ordered vote signer differs"));
        }
        env.policy
            .engine()
            .verify_vote(&vote, &Ed25519ConsensusVerifier)
            .map_err(consensus_to_node)?;
        if let Some(candidate) = &proposal.candidate {
            let candidate_digest: Digest32 = env.policy.candidate_digest(candidate)?;
            let expected: [Digest32; 1] = [candidate_digest];
            if proposal.proposal.transactions.as_slice() != expected.as_slice() {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "replayed candidate differs from retained proposal",
                ));
            }
            require_admission_receipt(
                store,
                context,
                env,
                candidate,
                reservation::OrderedAdmissionStage::Vote,
                vote.view,
            )?;
        } else if !proposal.proposal.transactions.is_empty() {
            return Err(stop("replayed business proposal lacks candidate bytes"));
        }
        crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
        return Ok(OrderedEventOutput {
            messages: vec![ConsensusMessage::Vote(vote)],
            committed: prefix_committed,
        });
    }
    let admitted = match &proposal.candidate {
        Some(candidate) => {
            let admitted = admit_candidate_for_signer(
                store,
                context,
                env,
                candidate,
                proposal.proposal.height,
            )?;
            if !proposal.proposal.transactions.contains(&admitted.digest) {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "ordered proposal candidate does not match its own transaction digest",
                ));
            }
            Some(admitted)
        }
        None => {
            if !proposal.proposal.transactions.is_empty() {
                // The leader named a candidate this replica does not have.
                // Voting on it would commit content we cannot execute.
                return Err(stop(
                    "ordered proposal names a candidate whose bytes were not delivered",
                ));
            }
            None
        }
    };

    // A verified justification may commit Freeze or DrainSet in this event.
    // Process that observation without exposing a vote for its own fresh
    // payload. The persisted prefix and inherited consensus locks remain intact.
    if proposal.candidate.as_ref().is_some() {
        let preview: ConsensusOutput = env
            .policy
            .engine()
            .on_observer_event(
                &loaded.state,
                ConsensusEvent::Proposal(proposal.proposal.clone()),
                &Ed25519ConsensusVerifier,
            )
            .map_err(consensus_to_node)?;
        if preview
            .committed_blocks
            .iter()
            .filter(|block| !block.transactions.is_empty())
            .count()
            > MAX_ORDERED_EVENT_COMMITTED
        {
            return Err(stop("Freeze preview exceeds committed candidate bound"));
        }
        let mut commits_freeze: bool = false;
        let mut commits_drain_set: bool = false;
        let mut commits_seal: bool = false;
        for block in &preview.committed_blocks {
            if block.transactions.len() > 1 {
                return Err(stop("Freeze preview violates the candidate profile"));
            }
            for committed_digest in &block.transactions {
                let key: Vec<u8> = ordered_candidate_record_key(
                    env.policy.context().chain_id(),
                    *committed_digest,
                )?;
                let row: VersionedStateValue =
                    store.read_versioned_state(context, env.policy.domain(), &key)?;
                let bytes: &[u8] = row
                    .value()
                    .ok_or_else(|| stop("Freeze preview lacks committed candidate"))?;
                let committed: OrderedCandidate = decode_ordered_candidate(bytes)?;
                if committed.context != *env.policy.context()
                    || candidate_digest(env.resolver(), committed.context.epoch(), bytes)?
                        != *committed_digest
                {
                    return Err(stop("Freeze preview candidate context or digest differs"));
                }
                authenticate_candidate(env, &committed)
                    .map_err(|_| stop("Freeze preview candidate authentication failed"))?;
                commits_freeze |= committed.kind == OrderedOperationKind::Freeze;
                commits_drain_set |= committed.kind == OrderedOperationKind::DrainSet;
                commits_seal |= committed.kind == OrderedOperationKind::Seal;
            }
        }
        if commits_freeze || commits_drain_set || commits_seal {
            let observed: OrderedEventOutput = observe_proposal(store, context, env, proposal)?;
            if commits_freeze
                && freeze::read_admission_closure(
                    store,
                    context,
                    env.policy.domain(),
                    env.policy.context().chain_id(),
                    env.policy.context().epoch(),
                )?
                .is_none()
            {
                return Err(stop("Freeze preview changed before observation; retry"));
            }
            if observed
                .messages
                .iter()
                .any(|message| matches!(message, ConsensusMessage::Vote(_)))
            {
                return Err(stop("Freeze observation unexpectedly produced a vote"));
            }
            return Ok(observed);
        }
    }

    // 3. Vote readiness, then the immutable local vote identity.
    require_vote_readiness(store, context, env, &loaded.state, &proposal.proposal)?;
    let reconciliation: LocalVoteReconciliation =
        identity::reconcile_local_vote(store, context, env, proposal.proposal.view, digest)?;

    if env.policy.is_causal() {
        let probe: CapacityProbeSigner<'_, C> = CapacityProbeSigner(signer);
        let preview: ConsensusOutput = env
            .policy
            .engine()
            .on_event(
                &loaded.state,
                ConsensusEvent::Proposal(proposal.proposal.clone()),
                &probe,
                &Ed25519ConsensusVerifier,
            )
            .map_err(consensus_to_node)?;
        if preview
            .committed_blocks
            .iter()
            .any(|block| !block.transactions.is_empty())
        {
            return Err(stop(
                "causal justified business prefix must be processed before signing",
            ));
        }
        let produced: Option<consensus::ConsensusVote> =
            preview
                .outbound_messages
                .iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote.clone()),
                    _ => None,
                });
        let probe_reconciliation: LocalVoteReconciliation =
            identity::reconcile_local_vote(store, context, env, proposal.proposal.view, digest)?;
        let prepared: PreparedEventCompletion = prepare_event(
            store,
            context,
            env,
            &loaded,
            preview,
            admitted.clone(),
            Some((probe_reconciliation, produced)),
        )?;
        drop(prepared);
    }
    let mut seal_signing_observations: StateObservationSet =
        StateObservationSet::new(env.policy.domain());
    let seal_signing_token: Option<PortableSnapshotToken> = match proposal
        .candidate
        .as_ref()
        .filter(|item| item.kind == OrderedOperationKind::Seal)
    {
        Some(seal_candidate) => {
            if admitted
                .as_ref()
                .is_some_and(|item| !item.head_reads.is_empty())
            {
                return Err(stop(
                    "ordered Seal vote admission unexpectedly produced object reads",
                ));
            }
            Some(require_seal_signing_retention(
                store,
                context,
                env,
                seal_candidate,
                &loaded,
                &proposal.proposal.justify,
                &mut seal_signing_observations,
            )?)
        }
        None => None,
    };

    // 4. One engine event.
    let output = env
        .policy
        .engine()
        .on_event(
            &loaded.state,
            ConsensusEvent::Proposal(proposal.proposal.clone()),
            signer,
            &Ed25519ConsensusVerifier,
        )
        .map_err(consensus_to_node)?;
    let produced: Option<consensus::ConsensusVote> =
        output
            .outbound_messages
            .iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            });
    let mut result = match seal_signing_token {
        Some(token) => {
            let repository: &dyn OutgoingSealRepository = store.outgoing_seal_repository().ok_or(
                stop("ordered Seal signing capability vanished before commit"),
            )?;
            prepare_event(
                store,
                context,
                env,
                &loaded,
                output,
                admitted,
                Some((reconciliation, produced)),
            )?
            .confirm_seal_retention(
                repository,
                context,
                &token,
                &seal_signing_observations,
            )?
        }
        None => finalize_event(
            store,
            context,
            env,
            &loaded,
            output,
            admitted,
            Some((reconciliation, produced)),
        )?,
    };
    prefix_committed.append(&mut result.committed);
    result.committed = prefix_committed;
    // Exact repeated output: an already-recorded vote is re-emitted from its
    // retained bytes, since the engine itself stays silent on a replay.
    if !result
        .messages
        .iter()
        .any(|message| matches!(message, ConsensusMessage::Vote(_)))
    {
        let replay: LocalVoteReconciliation =
            identity::reconcile_local_vote(store, context, env, proposal.proposal.view, digest)?;
        if let RetainedIdentity::Exact(vote) = replay.retained {
            crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
            result.messages.insert(0, ConsensusMessage::Vote(vote));
        }
    }
    Ok(result)
}

/// Applies one quorum certificate. Uses the signerless observer transition --
/// applying an already-signed certificate never requires this replica to vote
/// or hold a local identity.
pub fn process_certificate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    certificate: &QuorumCertificate,
) -> Result<OrderedEventOutput, OrderedEconomicsError> {
    env.policy
        .engine()
        .verify_certificate(certificate, &Ed25519ConsensusVerifier)
        .map_err(|_| {
            OrderedEconomicsError::Unauthenticated("ordered certificate failed verification")
        })?;
    crate::mutation_fence::require_origin_ordinary_namespace(store, context, env.policy.domain())?;
    let loaded = load_state(store, context, env)?;
    let output = env
        .policy
        .engine()
        .on_observer_event(
            &loaded.state,
            ConsensusEvent::Certificate(certificate.clone()),
            &Ed25519ConsensusVerifier,
        )
        .map_err(consensus_to_node)?;
    finalize_event(store, context, env, &loaded, output, None, None)
}

/// Signerless authenticated replay/recovery of one observed proposal: never
/// signs a vote, never manufactures a reservation.
pub fn observe_proposal<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    proposal: &OrderedProposal,
) -> Result<OrderedEventOutput, OrderedEconomicsError> {
    require_profile_shape(&proposal.proposal)?;
    env.policy
        .engine()
        .verify_proposal(&proposal.proposal, &Ed25519ConsensusVerifier)
        .map_err(|_| {
            OrderedEconomicsError::Unauthenticated("ordered proposal failed verification")
        })?;
    if let Some(candidate) = &proposal.candidate {
        authenticate_candidate(env, candidate)?;
    }
    crate::mutation_fence::require_origin_ordinary_namespace(store, context, env.policy.domain())?;
    let loaded = load_state(store, context, env)?;
    let admitted = match &proposal.candidate {
        Some(candidate) => {
            // Declared recovery records the exact candidate bytes it was
            // given, and reserves nothing at all.
            //
            // A request this replica already completed is *not* refused here:
            // declared recovery must be able to replay authentic artifacts in
            // dependency order even when a later proposal re-places an
            // operation that already finished. Recovery signs nothing and
            // reserves nothing, so recording the proposal creates no duplicate
            // placement; the retained outcome still answers the execution.
            let admitted = match admit_candidate(
                store,
                context,
                env,
                candidate,
                AdmissionPurpose::ReconcileOnly,
            )? {
                Admission::Fresh(admitted) => admitted,
                Admission::Completed(_) => AdmittedCandidate {
                    digest: env.policy.candidate_digest(candidate)?,
                    reads: BTreeMap::new(),
                    writes: Vec::new(),
                    head_reads: Vec::new(),
                    request_id: candidate.request_id,
                },
            };
            if !proposal.proposal.transactions.contains(&admitted.digest) {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "ordered proposal candidate does not match its own transaction digest",
                ));
            }
            Some(admitted)
        }
        None => None,
    };
    let output = env
        .policy
        .engine()
        .on_observer_event(
            &loaded.state,
            ConsensusEvent::Proposal(proposal.proposal.clone()),
            &Ed25519ConsensusVerifier,
        )
        .map_err(consensus_to_node)?;
    finalize_event(store, context, env, &loaded, output, admitted, None)
}

/// Bounded read-only status snapshot.
pub fn query_status<S: StructuredDurableDomainStateStore + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<OrderedStatus, OrderedEconomicsError> {
    let loaded = load_state(store, context, env)?;
    Ok(OrderedStatus {
        current_view: loaded.state.current_view,
        high_qc: loaded.state.high_qc.clone(),
        committed_height: loaded.state.committed_height,
    })
}

/// Trusted-clock-only pacemaker route.
///
/// `now_unix_millis` must come from the caller's own trusted local clock --
/// never a remote peer, a candidate payload, or a
/// [`DurableOperationContext`] deadline. It carries no economic content and
/// never commits a business operation; it only lets the local view advance
/// once the configured timeout has elapsed, exactly like the underlying
/// engine's own `Tick` handling. A tick can authorize no proposal, quorum or
/// mutation.
pub fn process_tick<S, C>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    now_unix_millis: u64,
    signer: &C,
) -> Result<OrderedEventOutput, OrderedEconomicsError>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    crate::mutation_fence::require_ordinary_namespace(store, context, env.policy.domain())?;
    let loaded = load_state(store, context, env)?;
    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_policy(store, context, env, &mut profile_reads)?;
    let output = env
        .policy
        .engine()
        .on_event(
            &loaded.state,
            ConsensusEvent::Tick { now_unix_millis },
            signer,
            &Ed25519ConsensusVerifier,
        )
        .map_err(consensus_to_node)?;
    finalize_event(store, context, env, &loaded, output, None, None)
}

#[cfg(test)]
pub(crate) fn ordered_state_key_for_tests(chain: &ChainId) -> Vec<u8> {
    ordered_state_key(chain).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_applied_height_key_for_tests(chain: &ChainId) -> Vec<u8> {
    ordered_applied_height_key(chain).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_request_header_key_for_tests(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Vec<u8> {
    ordered_request_header_key(chain, request_id).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_candidate_record_key_for_tests(chain: &ChainId, digest: Digest32) -> Vec<u8> {
    ordered_candidate_record_key(chain, digest).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_leader_record_key_for_tests(chain: &ChainId, view: u64) -> Vec<u8> {
    identity::ordered_leader_record_key(chain, view).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_vote_record_key_for_tests(chain: &ChainId, view: u64) -> Vec<u8> {
    identity::ordered_vote_record_key(chain, view).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_vote_high_key_for_tests(chain: &ChainId) -> Vec<u8> {
    identity::ordered_vote_high_key(chain).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_reservation_key_for_tests(chain: &ChainId, request_id: &[u8; 32]) -> Vec<u8> {
    reservation::ordered_reservation_key(chain, request_id).unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_outcome_key_for_tests(chain: &ChainId, request_id: &[u8; 32]) -> Vec<u8> {
    ordered_outcome_key(chain, request_id).unwrap()
}

#[cfg(test)]
pub(crate) fn admission_closure_key_for_tests(chain: &ChainId, epoch: Epoch) -> Vec<u8> {
    freeze::admission_closure_key(chain, epoch).unwrap()
}

#[cfg(test)]
pub(crate) fn encode_retained_outcome_for_tests(outcome: &OrderedOutcome) -> Vec<u8> {
    encode_retained_outcome(outcome).unwrap()
}

#[cfg(test)]
pub(crate) fn refusal_output_for_tests(
    request_id: [u8; 32],
    refusal: OrderedRefusal,
) -> NodeOutput {
    refusal_output(request_id, refusal).unwrap()
}

/// Builds one request-header row for a corruption regression: a header whose
/// candidate digest deliberately disagrees with a retained outcome.
#[cfg(test)]
pub(crate) fn encode_request_header_for_tests(
    candidate_digest: Digest32,
    kind: OrderedOperationKind,
    created_checkpoint: u64,
) -> Vec<u8> {
    encode_request_header(&RequestHeader {
        candidate_digest,
        kind,
        created_checkpoint,
    })
    .unwrap()
}

#[cfg(test)]
pub(crate) fn ordered_candidate_digest_for_tests(
    resolver: &HashSuiteResolver,
    candidate: &OrderedCandidate,
) -> Digest32 {
    let bytes = encode_ordered_candidate(candidate).unwrap();
    candidate_digest(resolver, candidate.context.epoch(), &bytes).unwrap()
}
/// Materializes the canonical `0x6445` form of one event output **before** its
/// invocation commits.
///
/// The closed profile caps (at most [`MAX_ORDERED_EVENT_MESSAGES`] messages, at
/// most [`MAX_ORDERED_EVENT_COMMITTED`] committed outcomes, and every bound the
/// nested response/outcome frames enforce) are therefore proven satisfiable
/// while failing is still free. Discovering them afterwards would leave a
/// committed business effect whose own result could not be encoded, and the
/// only remaining options would be to lie about the outcome or to truncate it
/// arbitrarily. Neither is acceptable, so the check happens first.
fn materialize_event_output(output: &OrderedEventOutput) -> Result<(), OrderedEconomicsError> {
    encode_ordered_event_output(output)
        .map(|_| ())
        .map_err(|_| stop("ordered event output exceeds the closed profile canonical bounds"))
}
