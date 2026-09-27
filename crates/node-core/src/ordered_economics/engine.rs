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

fn ordered_state_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"state/", chain)
}

fn ordered_applied_height_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    prefixed_key(b"applied-height/", chain)
}

fn ordered_candidate_record_key(
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
fn execute_candidate<S: StructuredDurableDomainStateStore>(
    staging: &StagingStore<'_, S>,
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    admission: Option<&OrderedLegAdmission<'_>>,
) -> LegOutcome {
    if let Err(error) = authenticate_candidate(env, candidate) {
        return disposition(candidate.request_id, error);
    }
    if let Err(error) = preflight::preflight(store, context, env, candidate) {
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
            let record = match recorded {
                equivocation::EquivocationEvidenceOutcome::Recorded(record)
                | equivocation::EquivocationEvidenceOutcome::AlreadyRecorded(record) => record,
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
}

/// Reconciles one candidate a caller wants to newly place into the shared
/// order: reads (never writes) the permanent request-header row, failing
/// closed on any header-reuse conflict **before** the caller applies any
/// consensus event, then the candidate-bytes row, then -- only when
/// `reserve` -- this candidate's own address-owned reservations.
///
/// `reserve` is `false` for the signerless observer path: declared recovery
/// signs nothing and reserves nothing.
fn admit_candidate<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    reserve: bool,
) -> Result<AdmittedCandidate, OrderedEconomicsError> {
    let chain = env.policy.context().chain_id();
    let domain = env.policy.domain();
    let bytes = encode_ordered_candidate(candidate)?;
    let digest = candidate_digest(env.resolver, candidate.context.epoch(), &bytes)?;
    let mut writes: Vec<PendingWrite> = Vec::new();

    // 1. Header reuse is a conflict before all other metadata.
    let header_key = ordered_request_header_key(chain, &candidate.request_id)?;
    let observed_header = store.get_versioned_durable(context, domain, &header_key)?;
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

    // 2. Exact candidate bytes, content-addressed and immutable.
    let candidate_key = ordered_candidate_record_key(chain, digest)?;
    let observed_candidate = store.get_versioned_durable(context, domain, &candidate_key)?;
    match observed_candidate.value() {
        None => writes.push((
            candidate_key,
            observed_candidate.revision(),
            StateMutation::Put(bytes),
        )),
        Some(existing) if existing == bytes.as_slice() => {}
        Some(_) => return Err(stop("ordered candidate digest collision")),
    }

    // 3. Precisely this candidate's own address-owned reservations.
    if reserve {
        let plan: OrderedReservationPlan = reservation::reservation_plan(env, candidate)?;
        writes.extend(reservation::acquire_reservations(
            store, context, env, candidate, &plan,
        )?);
    }
    Ok(AdmittedCandidate { digest, writes })
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

    let mut writes = MergedWrites::default();
    writes.read(loaded.key.clone(), loaded.revision)?;
    writes.read(applied_height_key.clone(), applied_height_revision)?;

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

    if let Some(block) = economic_blocks.first().copied() {
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
            store,
            context,
            env,
            &candidate,
            admission.as_ref(),
        );
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

    let messages = consensus_output.outbound_messages;
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

    Ok(OrderedEventOutput {
        messages,
        committed: committed_outcome.into_iter().collect(),
    })
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
fn require_profile_shape(proposal: &ConsensusProposal) -> Result<(), OrderedEconomicsError> {
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
    // 2. Header conflict, before any other metadata, and the candidate's own
    //    reservations.
    let admitted = match candidate {
        Some(candidate) => Some(admit_candidate(store, context, env, candidate, true)?),
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
            let admitted = admit_candidate(store, context, env, candidate, true)?;
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
            let admitted = admit_candidate(store, context, env, candidate, false)?;
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
pub(crate) fn ordered_candidate_digest_for_tests(
    resolver: &HashSuiteResolver,
    candidate: &OrderedCandidate,
) -> Digest32 {
    let bytes = encode_ordered_candidate(candidate).unwrap();
    candidate_digest(resolver, candidate.context.epoch(), &bytes).unwrap()
}
