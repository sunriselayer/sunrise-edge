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
//! 6. **one atomic commit** merging the existing handler's own captured
//!    transaction (with its original receipt), the consensus state, the
//!    order/candidate/identity records and the precise lock release.
//!
//! A byte-identical replay of an already-applied event writes nothing at all:
//! no row is rewritten, no revision incremented, no nonce re-reserved.
use super::identity::{LocalVoteReconciliation, RetainedIdentity};
use super::policy::Ed25519ConsensusVerifier;
use super::reservation::{OrderedReservationPlan, PendingWrite};
use super::*;
use canonical_encoding::{decode_digest32, encode_chain_id, encode_digest32};
use consensus::{
    CommittedBlock, ConsensusEngine, ConsensusEvent, ConsensusMessage, ConsensusOutput,
    ConsensusProposal, ConsensusSigner, ConsensusState, QuorumCertificate, decode_consensus_state,
    decode_proposal, decode_quorum_certificate, encode_consensus_state, encode_proposal,
    encode_quorum_certificate,
};
use runtime::DurableCommitOutcome;

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
/// candidate, business or control, per durable invocation.
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
/// outbound messages (mirroring every existing handler this module stages):
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

pub(super) fn ordered_state_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"state/", chain)
}

pub(super) fn ordered_applied_height_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"applied-height/", chain)
}

/// Replica-local, CAS-fenced cut-stability barrier. A future pre-Seal cut may
/// only start scanning after this row has been installed from the verified
/// business-free suffix and completed drain. It is not portable authority.
pub(crate) fn business_free_barrier_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"business-free-barrier/", chain)?;
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(super) fn ordered_candidate_record_key(
    chain: &ChainId,
    digest: Digest32,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = prefixed_key(b"candidate/", chain)?;
    key.extend_from_slice(&digest.bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn ordered_request_header_key(
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
fn ordered_outcome_key(chain: &ChainId, request_id: &[u8; 32]) -> Result<Vec<u8>, NodeCoreError> {
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
fn decode_retained_outcome(bytes: &[u8]) -> Result<OrderedOutcome, NodeCoreError> {
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
fn require_consistent_completion<S: StructuredDurableDomainStateStore>(
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
        store.get_versioned_durable(context, env.policy.domain(), &header_key)?;
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
        .get_request_receipt(context, env.policy.domain(), durable_id)?
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
fn read_outcome_row<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    request_id: &[u8; 32],
) -> Result<OutcomeRow, OrderedEconomicsError> {
    let key: Vec<u8> = ordered_outcome_key(env.policy.context().chain_id(), request_id)?;
    let observed: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), &key)?;
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
pub fn query_ordered_outcome<S: StructuredDurableDomainStateStore>(
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

pub(super) fn decode_applied_height(bytes: &[u8]) -> Result<u64, NodeCoreError> {
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
struct RequestHeader {
    candidate_digest: Digest32,
    kind: OrderedOperationKind,
    created_checkpoint: u64,
}

fn encode_request_header(header: &RequestHeader) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(REQUEST_HEADER_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&header.candidate_digest)?)?;
    frame.field_u16(2, header.kind.to_wire())?;
    frame.field_u64(3, header.created_checkpoint)?;
    Ok(frame.finish()?)
}

fn decode_request_header(bytes: &[u8]) -> Result<RequestHeader, NodeCoreError> {
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
#[derive(Default)]
struct MergedWrites {
    reads: BTreeMap<Vec<u8>, StateRevision>,
    mutations: BTreeMap<Vec<u8>, StateMutation>,
}

impl MergedWrites {
    fn read(&mut self, key: Vec<u8>, revision: StateRevision) -> Result<(), OrderedEconomicsError> {
        match self.reads.insert(key, revision) {
            Some(previous) if previous != revision => {
                Err(OrderedEconomicsError::Node(NodeCoreError::StateConflict))
            }
            _ => Ok(()),
        }
    }

    fn mutate(
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
        match self.mutations.insert(key, mutation.clone()) {
            Some(previous) if previous != mutation => Err(stop(
                "ordered economics invocation produced two different mutations for one row",
            )),
            _ => Ok(()),
        }
    }

    fn apply(&mut self, write: PendingWrite) -> Result<(), OrderedEconomicsError> {
        let (key, revision, mutation) = write;
        self.mutate(key, revision, mutation)
    }

    fn merge_handler_state(
        &mut self,
        state: &DurableStateTransaction,
    ) -> Result<(), OrderedEconomicsError> {
        for assertion in state.reads() {
            self.read(assertion.key().to_vec(), assertion.expected_revision())?;
        }
        for entry in state.mutations() {
            self.record_mutation(entry.key().to_vec(), entry.mutation().clone())?;
        }
        Ok(())
    }

    fn is_unchanged(&self) -> bool {
        self.mutations.is_empty()
    }

    fn into_state_transaction(
        self,
        domain: AtomicityDomainId,
    ) -> Result<DurableStateTransaction, OrderedEconomicsError> {
        let assertions: Vec<StateReadAssertion> = self
            .reads
            .into_iter()
            .map(|(key, revision)| StateReadAssertion::new(key, revision))
            .collect::<Result<_, RuntimeError>>()?;
        let mutations: Vec<StateMutationEntry> = self
            .mutations
            .into_iter()
            .map(|(key, mutation)| StateMutationEntry::new(key, mutation))
            .collect::<Result<_, RuntimeError>>()?;
        Ok(DurableStateTransaction::new(
            domain,
            AtomicStateReadSet::new(assertions)?,
            mutations,
        )?)
    }

    fn into_atomic_transaction(
        self,
        domain: AtomicityDomainId,
    ) -> Result<AtomicStateTransaction, OrderedEconomicsError> {
        let assertions: Vec<StateReadAssertion> = self
            .reads
            .into_iter()
            .map(|(key, revision)| StateReadAssertion::new(key, revision))
            .collect::<Result<_, RuntimeError>>()?;
        let mutations: Vec<StateMutationEntry> = self
            .mutations
            .into_iter()
            .map(|(key, mutation)| StateMutationEntry::new(key, mutation))
            .collect::<Result<_, RuntimeError>>()?;
        Ok(AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(assertions)?,
            AtomicStateMutationSet::new(mutations)?,
        )?)
    }
}

fn commit_outcome_error(outcome: DurableCommitOutcome) -> OrderedEconomicsError {
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
fn load_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<LoadedState, OrderedEconomicsError> {
    let key = ordered_state_key(env.policy.context().chain_id())?;
    let observed = store.get_versioned_durable(context, env.policy.domain(), &key)?;
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
    let key = ordered_state_key(env.policy.context().chain_id())?;
    let domain = env.policy.domain();
    let observed = store.get_versioned_durable(context, domain, &key)?;
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
    let mut writes = MergedWrites::default();
    writes.mutate(key, observed.revision(), StateMutation::Put(bytes))?;
    match store.commit_durable(context, writes.into_atomic_transaction(domain)?) {
        DurableCommitOutcome::Committed => Ok(()),
        outcome => Err(commit_outcome_error(outcome)),
    }
}

/// Reads the highest committed height whose economic effects (if any) are
/// already durably applied. Absent means genesis, matching
/// [`ConsensusState::committed_height`]'s own zero start.
fn load_applied_height<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<(u64, Vec<u8>, StateRevision), OrderedEconomicsError> {
    let key = ordered_applied_height_key(env.policy.context().chain_id())?;
    let observed = store.get_versioned_durable(context, env.policy.domain(), &key)?;
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
enum LegOutcome {
    /// The staged handler committed a business transaction, captured by
    /// [`StagingStore`] and not yet published.
    Accepted(NodeOutput),
    /// One narrowly enumerated legitimate outcome in which the existing handler
    /// accepts *without* staging any transaction: the normalized evidence
    /// identity this candidate carries is already durably recorded, so the
    /// permanent one-time row is correct as it stands and re-writing it would
    /// be wrong.
    ///
    /// This is not a blanket licence for any handler that returns `Ok` with
    /// nothing staged. It is produced only by
    /// [`execute_evidence_candidate`] on
    /// [`equivocation::EquivocationEvidenceOutcome::AlreadyRecorded`], and the
    /// caller still requires the staging adapter to have captured nothing.
    AcceptedRetainedEvidence(NodeOutput),
    /// A deterministic, retained refusal: no value or nonce movement.
    Refused(NodeOutput),
    /// Infrastructural failure or unknown prerequisite: local apply must stop
    /// and require reconciliation.
    Stop(OrderedEconomicsError),
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
fn disposition(request_id: [u8; 32], error: OrderedEconomicsError) -> LegOutcome {
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

/// Executes one committed candidate against `staging` (never the real store
/// directly).
///
/// Order: pure re-authentication, then the typed
/// [`super::preflight`] against the healthy committed state, then the exact
/// existing handler its `kind` already uses -- unmodified, except for the
/// private admitted-candidate capability that authorizes exactly this
/// request's own retained reservations.
///
/// Every storage read -- the preflight's included -- goes through `staging`, so
/// the exact rows whose healthy revisions decided the answer are recorded and
/// become CAS assertions in the one final commit. A refusal derived from a row
/// that has since moved is then rejected atomically instead of being retained
/// against state that no longer justifies it.
fn execute_candidate<S: StructuredDurableDomainStateStore>(
    staging: &StagingStore<'_, S>,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    admission: Option<&OrderedLegAdmission<'_>>,
    block_height: u64,
) -> LegOutcome {
    if let Err(error) = authenticate_candidate(env, candidate) {
        return disposition(candidate.request_id, error);
    }
    if let Err(error) = preflight::preflight(staging, context, env, candidate, block_height) {
        return disposition(candidate.request_id, error);
    }
    let domain = env.policy.domain();
    match candidate.kind {
        OrderedOperationKind::FeeClaim => dispatch(
            fee_claims::handle_fee_claim_ordered(
                staging,
                env.blobs,
                context,
                domain,
                env.resolver,
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
        OrderedOperationKind::BondLifecycle => dispatch(
            bond_lifecycle::handle_bond_lifecycle_ordered(
                staging,
                env.blobs,
                context,
                domain,
                env.resolver,
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
        OrderedOperationKind::BondSlash => dispatch(
            bond_lifecycle::slash::handle_bond_slash_ordered(
                staging,
                env.blobs,
                context,
                domain,
                env.resolver,
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
            execute_evidence_candidate(staging, context, domain, env, candidate)
        }
        OrderedOperationKind::Freeze => dispatch(
            freeze::handle_freeze_ordered(
                staging,
                context,
                domain,
                env.policy.context().chain_id(),
                candidate,
                block_height,
            ),
            candidate.request_id,
            node_failure,
        ),
        OrderedOperationKind::DrainSet => dispatch(
            drain_set::handle_drain_set_ordered(
                staging,
                context,
                domain,
                env.policy.context().chain_id(),
                candidate,
                block_height,
            ),
            candidate.request_id,
            node_failure,
        ),
    }
}

fn dispatch<E>(
    result: Result<NodeOutput, E>,
    request_id: [u8; 32],
    classify: fn(&E) -> OrderedEconomicsError,
) -> LegOutcome {
    match result {
        Ok(output) => LegOutcome::Accepted(output),
        Err(error) => disposition(request_id, classify(&error)),
    }
}

fn execute_evidence_candidate<S: StructuredDurableDomainStateStore>(
    staging: &StagingStore<'_, S>,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
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
        } => equivocation::submit_fast_vote_equivocation_evidence(
            staging,
            context,
            domain,
            env.resolver,
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            checkpoint,
        ),
        evidence_submission::OrderedEvidenceSubmission::ObjectConflict {
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            ..
        } => equivocation::submit_fast_vote_object_conflict_evidence(
            staging,
            context,
            domain,
            env.resolver,
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            checkpoint,
        ),
        evidence_submission::OrderedEvidenceSubmission::EpochTransition {
            statement_a,
            statement_b,
            ..
        } => equivocation::submit_epoch_transition_equivocation_evidence(
            staging,
            context,
            domain,
            env.resolver,
            &chain,
            protocol_version,
            statement_a,
            statement_b,
            checkpoint,
        ),
    };
    match outcome {
        Ok(recorded) => {
            let (record, already_recorded) = match recorded {
                equivocation::EquivocationEvidenceOutcome::Recorded(record) => (record, false),
                equivocation::EquivocationEvidenceOutcome::AlreadyRecorded(record) => {
                    (record, true)
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
                Ok(output) if already_recorded => LegOutcome::AcceptedRetainedEvidence(output),
                Ok(output) => LegOutcome::Accepted(output),
                Err(error) => LegOutcome::Stop(OrderedEconomicsError::Node(error)),
            }
        }
        Err(error) => disposition(candidate.request_id, equivocation_failure(&error)),
    }
}

// --- request-header/candidate-record reconciliation -----------------------

/// Everything one newly admitted candidate contributes to the single commit.
struct AdmittedCandidate {
    digest: Digest32,
    writes: Vec<PendingWrite>,
    /// Pure CAS read assertions with no accompanying mutation, folded into
    /// the same commit as `writes`. DR-0157's pre-vote DrainSet readiness
    /// re-verification ([`admit_candidate_for_signer`]) is the only current
    /// contributor: every row
    /// [`drain_set::require_drain_set_readiness`]/[`drain_union::verify_drain_ready_into`]
    /// observed must be asserted in the *same* durable commit that records
    /// the signed proposal/vote, so a local ready marker or any of its
    /// Freeze/epoch/set prerequisites moving afterward rejects that commit
    /// instead of silently exposing a signature over stale readiness.
    reads: BTreeMap<Vec<u8>, StateRevision>,
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

/// Reconciles one candidate a caller wants to newly place into the shared
/// order: reads (never writes) the permanent request-header row, failing
/// closed on any header-reuse conflict **before** the caller applies any
/// consensus event, then the candidate-bytes row, then -- only when
/// `reserve` -- this candidate's own address-owned reservations.
///
/// `reserve` is `false` for the signerless observer path: declared recovery
/// signs nothing and reserves nothing.
///
/// A request id that already carries a retained **completed** outcome short
/// circuits here, before any reservation, preflight, module, object or nonce
/// I/O: the candidate is answered from its retained outcome rather than placed
/// a second time. A retained header alone is not completion.
fn admit_candidate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    reserve: bool,
) -> Result<Admission, OrderedEconomicsError> {
    let chain = env.policy.context().chain_id();
    let domain = env.policy.domain();
    let bytes = encode_ordered_candidate(candidate)?;
    let digest = candidate_digest(env.resolver, candidate.context.epoch(), &bytes)?;
    let mut writes: Vec<PendingWrite> = Vec::new();

    // 1. Header reuse is a conflict before all other metadata.
    let header_key = ordered_request_header_key(chain, &candidate.request_id)?;
    let observed_header = store.get_versioned_durable(context, domain, &header_key)?;
    // A deleted header must never be recreated: it is the immutable binding
    // every later replay and every completion cross-check depends on.
    require_virgin_absence(&observed_header, "ordered request header row was deleted")?;
    match observed_header.value() {
        None => {
            let header = RequestHeader {
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
            let existing = decode_request_header(existing_bytes)?;
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
        return Ok(Admission::Completed(Box::new(retained)));
    }

    // A fresh candidate would write an immutable header/candidate row even
    // before it commits an economic receipt. Both are cut-classified history,
    // so the post-drain barrier must fence placement as well as execution.
    // Keep the original header-conflict and exact-completion reconciliation
    // before this check. The read assertion follows the candidate into the
    // same proposal/vote/observer commit, closing the installation race.
    let barrier_key: Vec<u8> = business_free_barrier_key(chain, env.policy.context().epoch())?;
    let barrier_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &barrier_key)?;
    if barrier_row.value().is_some() {
        return Err(stop(
            "ordered candidate arrived after the cut-stability barrier",
        ));
    }
    require_virgin_absence(&barrier_row, "ordered cut-stability barrier was deleted")?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    reads.insert(barrier_key, barrier_row.revision());

    // 3. Exact candidate bytes, content-addressed and immutable.
    let candidate_key = ordered_candidate_record_key(chain, digest)?;
    let observed_candidate = store.get_versioned_durable(context, domain, &candidate_key)?;
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
    if reserve {
        let plan: OrderedReservationPlan = reservation::reservation_plan(env, candidate)?;
        writes.extend(reservation::acquire_reservations(
            store, context, env, candidate, &plan,
        )?);
    }
    Ok(Admission::Fresh(AdmittedCandidate {
        digest,
        writes,
        reads,
    }))
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
    // DR-0154/DR-0157 liveness gate, additive to (not a substitute for)
    // `preflight`'s own authoritative closed-epoch refusal at commit time: an
    // honest leader/replica never even places or votes for a *fresh* business
    // candidate once a `Freeze` has committed, "Stop new ... construction of
    // fresh economic candidates" / "an honest replica emits no fresh vote for
    // a proposal whose own payload carries business." `Freeze` and `DrainSet`
    // are both exempt from this business-only gate: a second `Freeze` is
    // still admissible here and resolves to `AlreadyFrozen` at preflight, and
    // `DrainSet` is admissible here *only* once `Freeze` has committed --
    // exactly the positive `{Freeze, DrainSet}` allowlist
    // `preflight::require_admission_open` enforces authoritatively. This
    // check is deliberately confined to this signer-only entry point
    // (`propose`/`process_proposal`), never `observe_proposal`'s plain
    // `admit_candidate(..., reserve: false)` call: declared, signerless
    // recovery must still be able to record and replay an authentic
    // pre-freeze business proposal's bytes during catch-up, so its own
    // already-justified inherited suffix can reach the deterministic
    // closed-epoch refusal at commit time instead of never being recorded at
    // all. This check is not itself CAS-fenced (a race is caught at commit
    // time by `preflight`'s own staged read), so a caller does not need this
    // exact row's revision recorded to get a safe answer.
    if !matches!(
        candidate.kind,
        OrderedOperationKind::Freeze | OrderedOperationKind::DrainSet
    ) && freeze::read_admission_closure(
        store,
        context,
        env.policy.domain(),
        env.policy.context().chain_id(),
        env.policy.context().epoch(),
    )?
    .is_some()
    {
        return Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch));
    }
    match admit_candidate(store, context, env, candidate, true)? {
        Admission::Fresh(mut admitted) => {
            if candidate.kind == OrderedOperationKind::Freeze {
                freeze::require_freeze_warrant(store, context, env, candidate, proposal_height)?;
            }
            // DR-0157: before this replica ever exposes a leader proposal or
            // a vote for a `DrainSet` candidate, it must re-verify its own
            // exact local readiness for the candidate's declared selection
            // and union identity. Every row this reads is folded into
            // `admitted.reads`, which `propose`/`finalize_event` then commit
            // atomically with the signed proposal/vote record itself -- a
            // race that moves the local ready marker or any of its
            // Freeze/epoch/set prerequisites between this check and that
            // commit is rejected by CAS rather than silently exposing a
            // signature over stale readiness. Missing local readiness
            // surfaces as `OrderedEconomicsError::Prerequisite`, stopping
            // this proposal/vote attempt entirely -- never a committed
            // refusal.
            if candidate.kind == OrderedOperationKind::DrainSet {
                drain_set::require_drain_set_readiness(
                    store,
                    context,
                    env,
                    candidate,
                    &mut admitted.reads,
                )?;
            }
            Ok(admitted)
        }
        Admission::Completed(outcome) => Err(OrderedEconomicsError::AlreadyCompleted(outcome)),
    }
}

/// Builds one durable receipt (`NodeDedupRecord`-backed) keyed by
/// `request_id`, replaying `output`'s responses idempotently. Used for a
/// retained refusal, and for an accepted outcome whose handler committed
/// through plain `commit_durable` (evidence submission), which otherwise has
/// no request-id receipt of its own.
fn build_receipt(
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

/// Read the local cut fence and return its revision for the caller's atomic
/// commit. This is used by `finalize_event` for every newly committed
/// candidate, including Freeze/DrainSet control receipts and outcomes.
pub(super) fn fence_cut_for_committed_candidate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    epoch: Epoch,
) -> Result<(Vec<u8>, StateRevision), OrderedEconomicsError> {
    let key: Vec<u8> = business_free_barrier_key(chain, epoch)?;
    let row: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if row.value().is_some() {
        return Err(stop(
            "ordered candidate committed after the cut-stability barrier",
        ));
    }
    require_virgin_absence(&row, "ordered cut-stability barrier was deleted")?;
    Ok((key, row.revision()))
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
    let candidate_blocks: Vec<&CommittedBlock> = consensus_output
        .committed_blocks
        .iter()
        .filter(|block| !block.transactions.is_empty())
        .collect();
    if candidate_blocks.len() > MAX_ORDERED_EVENT_COMMITTED {
        return Err(stop(
            "ordered economics cannot execute more than one newly committed candidate per invocation",
        ));
    }

    let mut writes = MergedWrites::default();
    writes.read(loaded.key.clone(), loaded.revision)?;
    writes.read(applied_height_key.clone(), applied_height_revision)?;

    // The post-drain barrier is a writer fence, not just a point-in-time
    // suffix predicate. A late inherited business candidate may create a
    // closed-epoch refusal; a control candidate also creates an outcome and
    // receipt. Both must have entered the applied prefix before the barrier.
    // A concurrent install rejects this commit by CAS. Empty consensus
    // progress remains legal.
    if !candidate_blocks.is_empty() {
        let (barrier_key, barrier_revision): (Vec<u8>, StateRevision) =
            fence_cut_for_committed_candidate(
                store,
                context,
                domain,
                &chain,
                env.policy.context().epoch(),
            )?;
        writes.read(barrier_key, barrier_revision)?;
    }

    let next_state_bytes = encode_consensus_state(&next_state)
        .map_err(|_| stop("ordered consensus state does not encode"))?;
    let stored_state_bytes = encode_consensus_state(&loaded.state)
        .map_err(|_| stop("ordered consensus state does not encode"))?;
    if next_state_bytes != stored_state_bytes {
        writes.record_mutation(loaded.key.clone(), StateMutation::Put(next_state_bytes))?;
    }

    if let Some(admitted) = &admitted {
        for write in &admitted.writes {
            writes.apply(write.clone())?;
        }
        for (key, revision) in &admitted.reads {
            writes.read(key.clone(), *revision)?;
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
    let mut committed_outcome: Option<OrderedOutcome> = None;
    let mut business: Option<DurableInvocationTransaction> = None;

    if let Some(block) = candidate_blocks.first().copied() {
        if applied_height != loaded.state.committed_height {
            return Err(stop(
                "ordered economics unapplied committed prefix; declared catch-up required",
            ));
        }
        let digest = block.transactions[0];
        let candidate_key = ordered_candidate_record_key(&chain, digest)?;
        let observed_candidate = store.get_versioned_durable(context, domain, &candidate_key)?;
        let Some(candidate_bytes) = observed_candidate.value().map(<[u8]>::to_vec) else {
            return Err(stop(
                "ordered economics missing committed candidate bytes; declared catch-up required",
            ));
        };
        writes.read(candidate_key, observed_candidate.revision())?;
        let candidate = decode_ordered_candidate(&candidate_bytes)?;
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
            if block.height != applied_height {
                writes.record_mutation(
                    applied_height_key,
                    StateMutation::Put(encode_applied_height(block.height)?),
                )?;
            }
            let output = OrderedEventOutput {
                messages: consensus_output.outbound_messages,
                committed: vec![retained],
            };
            materialize_event_output(&output)?;
            if !writes.is_unchanged() {
                let transaction = writes.into_atomic_transaction(domain)?;
                if let outcome @ (DurableCommitOutcome::Rejected(_)
                | DurableCommitOutcome::Indeterminate(_)) =
                    store.commit_durable(context, transaction)
                {
                    return Err(commit_outcome_error(outcome));
                }
            }
            return Ok(output);
        }
        // Only this exact request's own retained reservations may be reused.
        let retained = reservation::load_reservation(store, context, env, &candidate.request_id)?;
        let admission = retained.as_ref().map(|(plan, _, _)| OrderedLegAdmission {
            request_id: candidate.request_id,
            objects: plan.objects.as_slice(),
            nonce: plan.nonce,
        });
        let staging: StagingStore<'_, S> = StagingStore::new(store);
        let outcome = execute_candidate(
            &staging,
            context,
            env,
            &candidate,
            admission.as_ref(),
            block.height,
        );
        // One durable invocation observes one stable snapshot, so two different
        // revisions for one key can only be concurrent interference. Never
        // retain a decision derived from two disagreeing views of a row.
        if staging.had_inconsistent_read() {
            return Err(stop(
                "ordered candidate execution observed one row at two revisions",
            ));
        }
        // Both acceptance and refusal release exactly this candidate's own
        // reservations; a stop releases nothing.
        let release: Vec<PendingWrite> = match (&outcome, &retained) {
            (LegOutcome::Stop(_), _) | (_, None) => Vec::new(),
            (_, Some((plan, record_key, record_revision))) => reservation::release_reservations(
                store,
                context,
                env,
                plan,
                record_key.clone(),
                *record_revision,
            )?,
        };
        // Every row the preflight and the staged handler actually read becomes
        // a CAS assertion in the one final commit -- including, on a refusal,
        // the escrow/bond/nonce/authority rows whose healthy revisions decided
        // it. Object heads, versions and provenance stay handler-owned.
        if !matches!(outcome, LegOutcome::Stop(_)) {
            for (key, revision) in staging.observed_reads() {
                writes.read(key, revision)?;
            }
        }
        match outcome {
            LegOutcome::Stop(error) => return Err(error),
            LegOutcome::Accepted(output) => {
                let captured = match (staging.take_invocation(), staging.take_durable()) {
                    // The existing handler's single typed receipt, object
                    // changes and outbox are carried through untouched.
                    (Some(invocation), None) => invocation,
                    (None, Some(plain)) => {
                        // Evidence submission commits through plain
                        // `commit_durable` (content-addressed idempotency,
                        // not a request-id receipt): wrap it in our own outer
                        // receipt so `OrderedOutcome` stays uniform.
                        let receipt = build_receipt(candidate.request_id, digest, &output)?;
                        DurableInvocationTransaction::new(
                            domain,
                            Some(DurableStateTransaction::from(plain)),
                            DurableObjectChanges::empty(),
                            receipt,
                            None,
                        )?
                    }
                    (None, None) => {
                        return Err(stop(
                            "ordered economics accepted candidate produced no staged transaction",
                        ));
                    }
                    (Some(_), Some(_)) => {
                        return Err(stop(
                            "ordered economics candidate staged through two commit paths at once",
                        ));
                    }
                };
                committed_outcome = Some(OrderedOutcome {
                    candidate_digest: digest,
                    request_id: candidate.request_id,
                    block_height: block.height,
                    block_digest: block.digest,
                    output,
                });
                business = Some(captured);
            }
            LegOutcome::AcceptedRetainedEvidence(output) => {
                // Narrowly enumerated read-only acceptance: the permanent
                // one-time evidence row already holds exactly these bytes. The
                // handler must genuinely have staged nothing -- anything else
                // would mean it intended a write this branch would silently
                // drop.
                if staging.take_invocation().is_some() || staging.take_durable().is_some() {
                    return Err(stop(
                        "ordered evidence reported an already-recorded row yet staged a write",
                    ));
                }
                let receipt = build_receipt(candidate.request_id, digest, &output)?;
                business = Some(DurableInvocationTransaction::new(
                    domain,
                    None,
                    DurableObjectChanges::empty(),
                    receipt,
                    None,
                )?);
                committed_outcome = Some(OrderedOutcome {
                    candidate_digest: digest,
                    request_id: candidate.request_id,
                    block_height: block.height,
                    block_digest: block.digest,
                    output,
                });
            }
            LegOutcome::Refused(output) => {
                let receipt = build_receipt(candidate.request_id, digest, &output)?;
                business = Some(DurableInvocationTransaction::new(
                    domain,
                    None,
                    DurableObjectChanges::empty(),
                    receipt,
                    None,
                )?);
                committed_outcome = Some(OrderedOutcome {
                    candidate_digest: digest,
                    request_id: candidate.request_id,
                    block_height: block.height,
                    block_digest: block.digest,
                    output,
                });
            }
        }
        // Retain the exact completed outcome atomically with the original
        // receipt and order rows, so an exact proposal/certificate replay or an
        // interrupted client resume can be answered from it without re-placing
        // or re-executing anything.
        if let Some(outcome) = &committed_outcome {
            writes.mutate(
                outcome_row.key,
                outcome_row.revision,
                StateMutation::Put(encode_retained_outcome(outcome)?),
            )?;
        }
        for write in release {
            writes.apply(write)?;
        }
        new_applied_height = block.height;
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

    let result = OrderedEventOutput {
        messages: consensus_output.outbound_messages,
        committed: committed_outcome.into_iter().collect(),
    };
    // Prove the answer is canonically representable while failing is still
    // free: never commit state whose own committed response cannot be encoded.
    materialize_event_output(&result)?;
    if let Some(business) = business {
        if let Some(handler_state) = business.state() {
            writes.merge_handler_state(handler_state)?;
        }
        let transaction = DurableInvocationTransaction::new(
            domain,
            Some(writes.into_state_transaction(domain)?),
            business.objects(),
            business.receipt().clone(),
            business.outbox().cloned(),
        )?;
        if let outcome @ (DurableCommitOutcome::Rejected(_)
        | DurableCommitOutcome::Indeterminate(_)) = store.commit_invocation(context, transaction)
        {
            return Err(commit_outcome_error(outcome));
        }
    } else if !writes.is_unchanged() {
        let transaction = writes.into_atomic_transaction(domain)?;
        if let outcome @ (DurableCommitOutcome::Rejected(_)
        | DurableCommitOutcome::Indeterminate(_)) = store.commit_durable(context, transaction)
        {
            return Err(commit_outcome_error(outcome));
        }
    }

    Ok(result)
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
                .get_versioned_durable(context, domain, &key)?
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
    let loaded = load_state(store, context, env)?;
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
    let mut writes = MergedWrites::default();
    writes.mutate(
        key,
        revision,
        StateMutation::Put(identity::encode_leader_proposal_record(&record)?),
    )?;
    if let Some(admitted) = &admitted {
        for write in &admitted.writes {
            writes.apply(write.clone())?;
        }
        for (key, revision) in &admitted.reads {
            writes.read(key.clone(), *revision)?;
        }
    }
    // `propose` applies no consensus event, so it commits only the leader
    // identity, candidate/header bookkeeping, reservations and any DrainSet
    // readiness read assertions -- atomically.
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
    let loaded = load_state(store, context, env)?;
    let digest = env
        .policy
        .engine()
        .proposal_digest(&proposal.proposal)
        .map_err(consensus_to_node)?;

    // 2. Header conflict before any consensus metadata, then reservations.
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

    // A proposal can commit the Freeze carried by its justification before
    // the engine produces its own vote. Looking only at the closure row here
    // would see the pre-event state and could sign a fresh business proposal
    // in the same event that closes admission. After preserving the normal
    // header/admission error precedence, preview the signerless event. If it
    // commits Freeze, persist that authenticated observation without signing
    // this proposal. Ordinary proposals below retain one atomic signer event.
    if proposal.candidate.as_ref().is_some_and(|candidate| {
        !matches!(
            candidate.kind,
            OrderedOperationKind::Freeze | OrderedOperationKind::DrainSet
        )
    }) {
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
            return Err(stop(
                "ordered Freeze preview exceeds the committed candidate bound",
            ));
        }
        let mut commits_freeze: bool = false;
        for block in &preview.committed_blocks {
            if block.transactions.len() > 1 {
                return Err(stop(
                    "ordered Freeze preview violates the candidate profile",
                ));
            }
            for committed_digest in &block.transactions {
                let candidate_key: Vec<u8> = ordered_candidate_record_key(
                    env.policy.context().chain_id(),
                    *committed_digest,
                )?;
                let row: VersionedStateValue =
                    store.get_versioned_durable(context, env.policy.domain(), &candidate_key)?;
                let candidate_bytes: &[u8] = row.value().ok_or_else(|| {
                    stop("ordered Freeze preview lacks committed candidate bytes")
                })?;
                let committed: OrderedCandidate = decode_ordered_candidate(candidate_bytes)?;
                if committed.context != *env.policy.context()
                    || candidate_digest(env.resolver, committed.context.epoch(), candidate_bytes)?
                        != *committed_digest
                {
                    return Err(stop(
                        "ordered Freeze preview candidate context or digest mismatch",
                    ));
                }
                authenticate_candidate(env, &committed)
                    .map_err(|_| stop("ordered Freeze preview candidate failed authentication"))?;
                if committed.kind == OrderedOperationKind::Freeze {
                    commits_freeze = true;
                }
            }
        }
        if commits_freeze {
            let observed: OrderedEventOutput = observe_proposal(store, context, env, proposal)?;
            if freeze::read_admission_closure(
                store,
                context,
                env.policy.domain(),
                env.policy.context().chain_id(),
                env.policy.context().epoch(),
            )?
            .is_none()
            {
                return Err(stop(
                    "ordered Freeze preview changed before observation; retry",
                ));
            }
            if observed
                .messages
                .iter()
                .any(|message| matches!(message, ConsensusMessage::Vote(_)))
            {
                return Err(stop(
                    "signerless Freeze observation unexpectedly produced a vote",
                ));
            }
            return Ok(observed);
        }
    }

    // 3. Vote readiness, then the immutable local vote identity.
    require_vote_readiness(store, context, env, &loaded.state, &proposal.proposal)?;
    let reconciliation: LocalVoteReconciliation =
        identity::reconcile_local_vote(store, context, env, proposal.proposal.view, digest)?;

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
    let mut result = finalize_event(
        store,
        context,
        env,
        &loaded,
        output,
        admitted,
        Some((reconciliation, produced)),
    )?;
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
            let admitted = match admit_candidate(store, context, env, candidate, false)? {
                Admission::Fresh(admitted) => admitted,
                Admission::Completed(_) => AdmittedCandidate {
                    digest: env.policy.candidate_digest(candidate)?,
                    writes: Vec::new(),
                    reads: BTreeMap::new(),
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
pub fn query_status<S: StructuredDurableDomainStateStore>(
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
    let loaded = load_state(store, context, env)?;
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
