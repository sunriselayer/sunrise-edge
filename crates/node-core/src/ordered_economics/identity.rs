//! Durable local protocol identity DR-0153 requires node-core to own:
//! the exact leader proposal this replica signed for a view, and the exact
//! vote it signed for a view.
//!
//! `consensus::ChainedHotStuff::validate_state` is explicit that it cannot
//! recover the local `last_voted_view`/`last_voted_digest` binding after a
//! restart, because `prune_state` may already have dropped the proposal that
//! binding referred to, and that "reconstructing that specific still-safe-to-
//! vote invariant after a restart [...] belongs in the caller that owns local
//! identity (e.g. `node-core`)". These rows are that caller's answer.
//!
//! Both records are **immutable and first-writer-wins**: once a view is
//! bound to a digest it is never rewritten, so restart, log pruning and an
//! exact replay of an old proposal can neither lose the binding nor bump its
//! revision. A second, *different* proposal or vote in the same view fails
//! closed before any signature is exposed -- an honest leader/voter is never
//! made to equivocate by a caller handing it conflicting work.
use super::*;
use canonical_encoding::{decode_digest32, encode_chain_id, encode_digest32};
use consensus::{ConsensusProposal, ConsensusVote, decode_proposal, decode_vote, encode_proposal};
use protocol_types::ValidatorId;

const ORDERED_LEADER_RECORD_TYPE: u16 = 0x644B;
const ORDERED_VOTE_RECORD_TYPE: u16 = 0x644C;
const ORDERED_VOTE_HIGH_RECORD_TYPE: u16 = 0x644D;
const ENCODING_VERSION: u16 = 1;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

fn view_key(chain: &ChainId, infix: &[u8], view: u64) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(infix);
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&view.to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

pub(crate) fn ordered_leader_record_key(
    chain: &ChainId,
    view: u64,
) -> Result<Vec<u8>, NodeCoreError> {
    view_key(chain, b"leader-proposal/", view)
}

pub(crate) fn ordered_vote_record_key(
    chain: &ChainId,
    view: u64,
) -> Result<Vec<u8>, NodeCoreError> {
    view_key(chain, b"vote/", view)
}

pub(crate) fn ordered_vote_high_key(chain: &ChainId) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"vote-high/");
    key.extend(encode_chain_id(chain)?);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// The exact signed leader proposal this replica produced for one view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeaderProposalRecord {
    pub(crate) view: u64,
    pub(crate) leader: ValidatorId,
    pub(crate) proposal_digest: Digest32,
    /// Exact canonical `ConsensusProposal` bytes, signature included.
    pub(crate) proposal: Vec<u8>,
}

/// Encodes frame `0x644B/v1`.
pub(crate) fn encode_leader_proposal_record(
    record: &LeaderProposalRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_LEADER_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.view)?;
    frame.field_bytes(2, record.leader.as_bytes().to_vec())?;
    frame.field_bytes(3, encode_digest32(&record.proposal_digest)?)?;
    frame.field_bytes(4, record.proposal.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644B/v1`, re-decoding the retained proposal so a
/// corrupt row can never be replayed as an authentic signed proposal.
pub(crate) fn decode_leader_proposal_record(
    bytes: &[u8],
) -> Result<(LeaderProposalRecord, ConsensusProposal), NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_LEADER_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let leader_bytes: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("ordered leader record leader length"))?;
    let record: LeaderProposalRecord = LeaderProposalRecord {
        view: frame.required_u64(1)?,
        leader: ValidatorId::new(leader_bytes),
        proposal_digest: decode_digest32(frame.required_field(3)?)?,
        proposal: frame.required_field(4)?.to_vec(),
    };
    let proposal: ConsensusProposal =
        decode_proposal(&record.proposal).map_err(|_| invalid("ordered leader record proposal"))?;
    if proposal.view != record.view
        || proposal.leader != record.leader
        || encode_proposal(&proposal).map_err(|_| invalid("ordered leader record proposal"))?
            != record.proposal
    {
        return Err(invalid("ordered leader record disagrees with its proposal"));
    }
    if encode_leader_proposal_record(&record)? != bytes {
        return Err(invalid("noncanonical ordered leader record"));
    }
    Ok((record, proposal))
}

/// The exact signed vote this replica produced for one view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalVoteRecord {
    pub(crate) view: u64,
    pub(crate) proposal_digest: Digest32,
    /// Exact canonical `ConsensusVote` bytes, signature included.
    pub(crate) vote: Vec<u8>,
}

/// Encodes frame `0x644C/v1`.
pub(crate) fn encode_local_vote_record(record: &LocalVoteRecord) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_VOTE_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.view)?;
    frame.field_bytes(2, encode_digest32(&record.proposal_digest)?)?;
    frame.field_bytes(3, record.vote.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644C/v1`, re-decoding the retained vote.
pub(crate) fn decode_local_vote_record(
    bytes: &[u8],
) -> Result<(LocalVoteRecord, ConsensusVote), NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_VOTE_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let record: LocalVoteRecord = LocalVoteRecord {
        view: frame.required_u64(1)?,
        proposal_digest: decode_digest32(frame.required_field(2)?)?,
        vote: frame.required_field(3)?.to_vec(),
    };
    let vote: ConsensusVote =
        decode_vote(&record.vote).map_err(|_| invalid("ordered vote record vote"))?;
    if vote.view != record.view || vote.proposal_digest != record.proposal_digest {
        return Err(invalid("ordered vote record disagrees with its vote"));
    }
    if encode_local_vote_record(&record)? != bytes {
        return Err(invalid("noncanonical ordered vote record"));
    }
    Ok((record, vote))
}

/// Encodes frame `0x644D/v1`: the highest view this replica has ever voted
/// in, kept outside the prunable `ConsensusState` so a restart can never
/// re-vote a lower view.
pub(crate) fn encode_vote_high_water(view: u64) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_VOTE_HIGH_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, view)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x644D/v1`.
pub(crate) fn decode_vote_high_water(bytes: &[u8]) -> Result<u64, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_VOTE_HIGH_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    Ok(frame.required_u64(1)?)
}

/// What a retained identity row says about the work a caller is presenting.
pub(crate) enum RetainedIdentity<T> {
    /// Nothing recorded for this view yet.
    Absent,
    /// This exact work is already recorded: replay it, write nothing.
    Exact(T),
}

/// Reads the retained leader-proposal record for `view` and decides whether
/// `digest` may be signed into it.
///
/// Returns [`RetainedIdentity::Exact`] with the retained proposal when this
/// exact proposal was already recorded (an idempotent re-propose), and fails
/// closed when a *different* proposal is already recorded for the same view:
/// an honest leader does not equivocate because its caller changed the
/// candidate.
pub(crate) fn reconcile_leader_proposal<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    leader: ValidatorId,
    digest: Digest32,
) -> Result<(Vec<u8>, StateRevision, RetainedIdentity<ConsensusProposal>), OrderedEconomicsError> {
    let key: Vec<u8> = ordered_leader_record_key(env.policy.context().chain_id(), view)?;
    let observed: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), &key)?;
    match observed.value() {
        None => Ok((key, observed.revision(), RetainedIdentity::Absent)),
        Some(bytes) => {
            let (record, proposal) = decode_leader_proposal_record(bytes)?;
            if record.view != view || record.leader != leader {
                return Err(OrderedEconomicsError::Prerequisite(
                    "retained ordered leader record belongs to another view or leader",
                ));
            }
            if record.proposal_digest != digest {
                return Err(OrderedEconomicsError::Prerequisite(
                    "this leader already signed a different proposal in this view",
                ));
            }
            Ok((key, observed.revision(), RetainedIdentity::Exact(proposal)))
        }
    }
}

/// The existing proposal digest includes its signature. A capacity probe
/// cannot predict that digest without calling the real signer. Reconcile all
/// unsigned fields instead, then independently re-verify the retained signed
/// proposal and its stored digest. No wire/preimage/layout changes are made.
pub(crate) fn reconcile_unsigned_leader_proposal<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    unsigned: &ConsensusProposal,
) -> Result<(Vec<u8>, StateRevision, RetainedIdentity<ConsensusProposal>), OrderedEconomicsError> {
    let key: Vec<u8> = ordered_leader_record_key(env.policy.context().chain_id(), unsigned.view)?;
    let observed: VersionedStateValue =
        store.get_versioned_durable(context, env.policy.domain(), &key)?;
    match observed.value() {
        None if observed.revision() == StateRevision::INITIAL => {
            Ok((key, observed.revision(), RetainedIdentity::Absent))
        }
        None => Err(invalid("retained causal ordered leader identity was deleted").into()),
        Some(bytes) => {
            let (record, retained): (LeaderProposalRecord, ConsensusProposal) =
                decode_leader_proposal_record(bytes)?;
            let mut comparable: ConsensusProposal = unsigned.clone();
            comparable.signature = retained.signature.clone();
            if comparable != retained {
                return Err(OrderedEconomicsError::Prerequisite(
                    "this leader already signed a different proposal in this view",
                ));
            }
            env.policy
                .engine()
                .verify_proposal(&retained, &super::policy::Ed25519ConsensusVerifier)
                .map_err(|_| invalid("retained causal leader proposal signature differs"))?;
            if env
                .policy
                .engine()
                .proposal_digest(&retained)
                .map_err(|_| invalid("retained causal leader digest"))?
                != record.proposal_digest
            {
                return Err(invalid("retained causal leader identity digest differs").into());
            }
            Ok((key, observed.revision(), RetainedIdentity::Exact(retained)))
        }
    }
}

/// Reads the retained local vote record for `view` plus the durable
/// highest-voted-view watermark, and decides whether this replica may vote
/// for `digest` in `view`.
///
/// Fails closed when a different digest is already recorded for the view, or
/// when `view` is below the durable watermark: both would be equivocation or
/// a vote-order regression that the prunable `ConsensusState` alone cannot
/// rule out after a restart.
pub(crate) fn reconcile_local_vote<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    digest: Digest32,
) -> Result<LocalVoteReconciliation, OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let domain: AtomicityDomainId = env.policy.domain();
    let record_key: Vec<u8> = ordered_vote_record_key(chain, view)?;
    let observed: VersionedStateValue =
        store.get_versioned_durable(context, domain, &record_key)?;
    let high_key: Vec<u8> = ordered_vote_high_key(chain)?;
    let observed_high: VersionedStateValue =
        store.get_versioned_durable(context, domain, &high_key)?;
    let high_water: u64 = match observed_high.value() {
        Some(bytes) => decode_vote_high_water(bytes)?,
        None => 0,
    };
    let retained: RetainedIdentity<ConsensusVote> = match observed.value() {
        None => {
            if view < high_water {
                return Err(OrderedEconomicsError::Prerequisite(
                    "ordered vote view is below this replica's durable vote watermark",
                ));
            }
            RetainedIdentity::Absent
        }
        Some(bytes) => {
            let (record, vote) = decode_local_vote_record(bytes)?;
            if record.view != view {
                return Err(OrderedEconomicsError::Prerequisite(
                    "retained ordered vote record belongs to another view",
                ));
            }
            if record.proposal_digest != digest {
                return Err(OrderedEconomicsError::Prerequisite(
                    "this replica already voted for a different proposal in this view",
                ));
            }
            RetainedIdentity::Exact(vote)
        }
    };
    Ok(LocalVoteReconciliation {
        record_key,
        record_revision: observed.revision(),
        high_key,
        high_revision: observed_high.revision(),
        high_water,
        retained,
    })
}

/// Everything one vote decision needs to fold into the single atomic commit.
pub(crate) struct LocalVoteReconciliation {
    pub(crate) record_key: Vec<u8>,
    pub(crate) record_revision: StateRevision,
    pub(crate) high_key: Vec<u8>,
    pub(crate) high_revision: StateRevision,
    pub(crate) high_water: u64,
    pub(crate) retained: RetainedIdentity<ConsensusVote>,
}
