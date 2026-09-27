//! Durable persistence support for [`crate::ChainedHotStuff`]: bounded
//! strict canonical decoders for the existing message frames, the
//! persisted-[`ConsensusState`] canonical codec (frame `0xD010`, nested
//! collection frames `0xD011`-`0xD016`), minimal quorum aggregation from
//! already-signed votes, a signerless authenticated-observer transition,
//! and re-verification of a decoded state before reuse.
//!
//! Every decoder here rejects an oversized outer input, an unbounded
//! declared collection count, or an inconsistent cross-field key *before*
//! doing any signature or hashing work, and every encoder enforces the same
//! bounds so a round trip can never silently grow past them.

use crate::{
    CERTIFICATE_TYPE_ID, ChainedHotStuff, CommittedBlock, ConsensusError, ConsensusEvent,
    ConsensusOutput, ConsensusProposal, ConsensusState, ConsensusVerifier, ConsensusVote,
    ENCODING_VERSION, MAX_BLOCK_TRANSACTIONS_LIMIT, PROPOSAL_TYPE_ID, QuorumCertificate,
    VOTE_PAYLOAD_TYPE_ID, VOTE_TYPE_ID, encode_proposal, encode_quorum_certificate, encode_vote,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, decode_canonical_frame, decode_digest32,
    encode_digest32,
};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion, SignatureSchemeId, ValidatorId};
use std::collections::{BTreeMap, BTreeSet};

const CONSENSUS_STATE_TYPE_ID: u16 = 0xD010;
const KNOWN_PROPOSALS_LIST_TYPE_ID: u16 = 0xD011;
const CERTIFICATES_LIST_TYPE_ID: u16 = 0xD012;
const PENDING_VOTES_LIST_TYPE_ID: u16 = 0xD013;
const PENDING_VOTE_GROUP_TYPE_ID: u16 = 0xD014;
const OBSERVED_VOTES_LIST_TYPE_ID: u16 = 0xD015;
const COMMITTED_LIST_TYPE_ID: u16 = 0xD016;

/// Bound on votes accepted while strictly decoding one [`QuorumCertificate`]
/// (mirrors `fast_vote::MAX_FAST_CERTIFICATE_VOTES` and
/// `validator_set::MAX_VALIDATORS`; certificates here are not
/// validator-set-bounded at decode time since decoders are free functions
/// with no engine context).
const MAX_CERTIFICATE_VOTES: usize = 10_000;
/// Bounds on the persisted [`ConsensusState`] canonical wire frame
/// (`0xD010`-`0xD016`), chosen generously relative to what
/// [`ChainedHotStuff::prune_state`] ever actually retains
/// (`RETAIN_COMMITTED_HEIGHTS` = 2, `MAX_FUTURE_VIEW_GAP` = 64) so that
/// legitimate pruned states never approach the bound while corrupted or
/// adversarial input is still rejected before unbounded allocation.
const MAX_STATE_KNOWN_PROPOSALS: usize = 4_096;
const MAX_STATE_CERTIFICATES: usize = 4_096;
const MAX_STATE_PENDING_VOTE_GROUPS: usize = 4_096;
const MAX_STATE_VOTES_PER_GROUP: usize = 10_000;
const MAX_STATE_OBSERVED_VOTES: usize = 8_192;
const MAX_STATE_COMMITTED: usize = 4_096;

/// Explicit per-type outer-byte-length caps checked *before*
/// [`decode_canonical_frame`] is ever invoked, in addition to (and tighter
/// than) `canonical_encoding::MAX_CANONICAL_FRAME_BYTES` (32 MiB). A vote
/// never legitimately needs more than a few KiB; a certificate or proposal
/// never legitimately needs more than a few MiB even at
/// [`MAX_CERTIFICATE_VOTES`]/[`MAX_BLOCK_TRANSACTIONS_LIMIT`]. Because every
/// nested frame (`known_proposals`, `certificates`, ...) is always a
/// byte-for-byte substring of its parent frame, bounding the outer
/// [`ConsensusState`] frame this way transitively bounds everything nested
/// inside it; the per-message caps below only matter when
/// [`decode_vote`]/[`decode_proposal`]/[`decode_quorum_certificate`] are
/// called standalone (outside a `ConsensusState`).
const MAX_ENCODED_VOTE_BYTES: usize = 8 * 1024;
const MAX_ENCODED_CERTIFICATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENCODED_PROPOSAL_BYTES: usize = 10 * 1024 * 1024;
const MAX_ENCODED_CONSENSUS_STATE_BYTES: usize = 16 * 1024 * 1024;
/// Bound on the `votes` slice a caller may pass to
/// [`ChainedHotStuff::certificate_from_votes`], checked before any
/// signature verification. Double [`MAX_CERTIFICATE_VOTES`] to tolerate
/// redundant/duplicate submissions from independent observers while still
/// rejecting an unbounded caller-supplied slice up front.
const MAX_CERTIFICATE_FROM_VOTES_INPUT: usize = 2 * MAX_CERTIFICATE_VOTES;

fn ensure_encoded_bound(
    kind: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), ConsensusError> {
    if actual > max {
        return Err(ConsensusError::EncodedFrameTooLarge { kind, actual, max });
    }
    Ok(())
}

/// Decodes and strictly re-validates one canonical [`ConsensusVote`].
///
/// Requires the input to fit [`MAX_ENCODED_VOTE_BYTES`] before any parsing,
/// the vote type id/encoding version, exactly fields 1-2 in the outer frame
/// and 1-8 in the nested payload frame, a non-zero view/height, a
/// non-empty bounded signature, and byte-exact re-encoding of the decoded
/// value. It does not verify the signature; callers must still call
/// [`ChainedHotStuff::verify_vote`].
pub fn decode_vote(input: &[u8]) -> Result<ConsensusVote, ConsensusError> {
    ensure_encoded_bound("vote", input.len(), MAX_ENCODED_VOTE_BYTES)?;
    let outer = decode_canonical_frame(input)?;
    outer.require_type(VOTE_TYPE_ID)?;
    outer.require_version(ENCODING_VERSION)?;
    outer.require_only_fields(&[1, 2])?;
    let payload_bytes = outer.required_field(1)?;
    let signature = outer.required_field(2)?.to_vec();

    let payload = decode_canonical_frame(payload_bytes)?;
    payload.require_type(VOTE_PAYLOAD_TYPE_ID)?;
    payload.require_version(ENCODING_VERSION)?;
    payload.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;

    let chain_id =
        ChainId::new(payload.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(payload.required_u32(2)?);
    let epoch = Epoch::new(payload.required_u64(3)?);
    let view = payload.required_u64(4)?;
    let height = payload.required_u64(5)?;
    let proposal_digest = decode_digest32(payload.required_field(6)?)?;
    let validator_field = payload.required_field(7)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 7,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let signature_scheme = SignatureSchemeId::try_from(payload.required_u16(8)?)
        .map_err(ConsensusError::ProtocolType)?;
    if view == 0 || height == 0 {
        return Err(ConsensusError::ZeroViewOrHeight);
    }

    let vote = ConsensusVote {
        chain_id,
        protocol_version,
        epoch,
        view,
        height,
        proposal_digest,
        validator: ValidatorId::new(validator_bytes),
        signature_scheme,
        signature,
    };
    if encode_vote(&vote)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(vote)
}

/// Decodes and strictly re-validates one canonical [`QuorumCertificate`].
///
/// Requires the input to fit [`MAX_ENCODED_CERTIFICATE_BYTES`] before any
/// parsing, the certificate type id/encoding version, an exact declared
/// vote count bounded by [`MAX_CERTIFICATE_VOTES`] (checked before any
/// nested vote is decoded), every nested [`ConsensusVote`] to decode under
/// [`decode_vote`] and match this certificate's view/height/digest,
/// strictly ascending validator order, a consistent genesis anchor (view,
/// height, and vote count all zero together, or none of them), and
/// byte-exact re-encoding of the decoded value. It does not verify
/// signatures, quorum power, or the genesis block digest against a
/// specific chain; callers must still call
/// [`ChainedHotStuff::verify_certificate`].
pub fn decode_quorum_certificate(input: &[u8]) -> Result<QuorumCertificate, ConsensusError> {
    ensure_encoded_bound(
        "quorum_certificate",
        input.len(),
        MAX_ENCODED_CERTIFICATE_BYTES,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(CERTIFICATE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;

    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let view = frame.required_u64(4)?;
    let height = frame.required_u64(5)?;
    let proposal_digest = decode_digest32(frame.required_field(6)?)?;
    let count = usize::try_from(frame.required_u32(7)?)
        .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
    if count > MAX_CERTIFICATE_VOTES {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    if (view == 0 || height == 0) && !(view == 0 && height == 0 && count == 0) {
        return Err(ConsensusError::InvalidGenesisCertificate);
    }
    let expected_field_count = count
        .checked_add(7)
        .ok_or(ConsensusError::NonCanonicalCertificateVotes)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    let mut votes = Vec::with_capacity(count);
    let mut previous: Option<ValidatorId> = None;
    for index in 0..count {
        let field =
            u16::try_from(index + 8).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        let vote = decode_vote(frame.required_field(field)?)?;
        if vote.view != view || vote.height != height || vote.proposal_digest != proposal_digest {
            return Err(ConsensusError::CertificateVoteMismatch);
        }
        if previous.is_some_and(|validator| validator >= vote.validator) {
            return Err(ConsensusError::NonCanonicalCertificateVotes);
        }
        previous = Some(vote.validator);
        votes.push(vote);
    }

    let certificate = QuorumCertificate {
        chain_id,
        protocol_version,
        epoch,
        view,
        height,
        proposal_digest,
        votes,
    };
    if encode_quorum_certificate(&certificate)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(certificate)
}

/// Decodes and strictly re-validates one canonical [`ConsensusProposal`].
///
/// Requires the input to fit [`MAX_ENCODED_PROPOSAL_BYTES`] before any
/// parsing, the proposal type id/encoding version (`v2` outer over `v1`
/// payload, matching [`encode_proposal`]), a bounded declared transaction
/// count, a nested `justify` certificate that decodes under
/// [`decode_quorum_certificate`], a non-zero view/height, a non-empty
/// bounded signature, and byte-exact re-encoding of the decoded value. It
/// does not verify signatures, leader eligibility, or justify-certificate
/// quorum; callers must still call [`ChainedHotStuff::verify_proposal`].
pub fn decode_proposal(input: &[u8]) -> Result<ConsensusProposal, ConsensusError> {
    ensure_encoded_bound("proposal", input.len(), MAX_ENCODED_PROPOSAL_BYTES)?;
    let outer = decode_canonical_frame(input)?;
    outer.require_type(PROPOSAL_TYPE_ID)?;
    outer.require_version(ENCODING_VERSION + 1)?;
    outer.require_only_fields(&[1, 2])?;
    let payload_bytes = outer.required_field(1)?;
    let signature = outer.required_field(2)?.to_vec();

    let payload = decode_canonical_frame(payload_bytes)?;
    payload.require_type(PROPOSAL_TYPE_ID)?;
    payload.require_version(ENCODING_VERSION)?;

    let chain_id =
        ChainId::new(payload.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(payload.required_u32(2)?);
    let epoch = Epoch::new(payload.required_u64(3)?);
    let view = payload.required_u64(4)?;
    let height = payload.required_u64(5)?;
    let leader_field = payload.required_field(6)?;
    let leader_bytes: [u8; 32] = leader_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 6,
            expected: 32,
            actual: leader_field.len(),
        })
    })?;
    let justify = decode_quorum_certificate(payload.required_field(7)?)?;
    let tx_count = usize::try_from(payload.required_u32(8)?)
        .map_err(|_| ConsensusError::TooManyTransactions(usize::MAX))?;
    let max_transactions = usize::try_from(MAX_BLOCK_TRANSACTIONS_LIMIT)
        .map_err(|_| ConsensusError::ArithmeticOverflow)?;
    if tx_count > max_transactions {
        return Err(ConsensusError::TooManyTransactions(tx_count));
    }
    let signature_scheme = SignatureSchemeId::try_from(payload.required_u16(9)?)
        .map_err(ConsensusError::ProtocolType)?;
    let expected_field_count = tx_count
        .checked_add(9)
        .ok_or(ConsensusError::TooManyTransactions(tx_count))?;
    if payload.field_count() != expected_field_count {
        return Err(ConsensusError::TooManyTransactions(tx_count));
    }
    let mut transactions = Vec::with_capacity(tx_count);
    for index in 0..tx_count {
        let field =
            u16::try_from(index + 10).map_err(|_| ConsensusError::TooManyTransactions(tx_count))?;
        transactions.push(decode_digest32(payload.required_field(field)?)?);
    }
    if view == 0 || height == 0 {
        return Err(ConsensusError::ZeroViewOrHeight);
    }

    let proposal = ConsensusProposal {
        chain_id,
        protocol_version,
        epoch,
        view,
        height,
        leader: ValidatorId::new(leader_bytes),
        justify,
        transactions,
        signature_scheme,
        signature,
    };
    if encode_proposal(&proposal)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalCertificateVotes);
    }
    Ok(proposal)
}

fn encode_known_proposals(
    map: &BTreeMap<Digest32, ConsensusProposal>,
) -> Result<Vec<u8>, ConsensusError> {
    if map.len() > MAX_STATE_KNOWN_PROPOSALS {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "known_proposals",
            actual: map.len(),
            max: MAX_STATE_KNOWN_PROPOSALS,
        });
    }
    let mut canonical = CanonicalStruct::new(KNOWN_PROPOSALS_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(map.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, (digest, proposal)) in map.iter().enumerate() {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let proposal_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(digest_field, encode_digest32(digest)?)?;
        canonical.field_bytes(proposal_field, encode_proposal(proposal)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_known_proposals(
    input: &[u8],
) -> Result<BTreeMap<Digest32, ConsensusProposal>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(KNOWN_PROPOSALS_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "known_proposals",
            actual: usize::MAX,
            max: MAX_STATE_KNOWN_PROPOSALS,
        }
    })?;
    if count > MAX_STATE_KNOWN_PROPOSALS {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "known_proposals",
            actual: count,
            max: MAX_STATE_KNOWN_PROPOSALS,
        });
    }
    let expected_field_count = count
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "known_proposals field count",
        ));
    }
    let mut map = BTreeMap::new();
    let mut previous: Option<Digest32> = None;
    for index in 0..count {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let proposal_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let digest = decode_digest32(frame.required_field(digest_field)?)?;
        if previous.is_some_and(|value| value >= digest) {
            return Err(ConsensusError::InconsistentPersistedState(
                "known_proposals order",
            ));
        }
        previous = Some(digest);
        let proposal = decode_proposal(frame.required_field(proposal_field)?)?;
        map.insert(digest, proposal);
    }
    if encode_known_proposals(&map)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "known_proposals re-encode",
        ));
    }
    Ok(map)
}

fn encode_certificates_map(
    map: &BTreeMap<Digest32, QuorumCertificate>,
) -> Result<Vec<u8>, ConsensusError> {
    if map.len() > MAX_STATE_CERTIFICATES {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "certificates",
            actual: map.len(),
            max: MAX_STATE_CERTIFICATES,
        });
    }
    let mut canonical = CanonicalStruct::new(CERTIFICATES_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(map.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, (digest, certificate)) in map.iter().enumerate() {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let certificate_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(digest_field, encode_digest32(digest)?)?;
        canonical.field_bytes(certificate_field, encode_quorum_certificate(certificate)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_certificates_map(
    input: &[u8],
) -> Result<BTreeMap<Digest32, QuorumCertificate>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(CERTIFICATES_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "certificates",
            actual: usize::MAX,
            max: MAX_STATE_CERTIFICATES,
        }
    })?;
    if count > MAX_STATE_CERTIFICATES {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "certificates",
            actual: count,
            max: MAX_STATE_CERTIFICATES,
        });
    }
    let expected_field_count = count
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "certificates field count",
        ));
    }
    let mut map = BTreeMap::new();
    let mut previous: Option<Digest32> = None;
    for index in 0..count {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let certificate_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let digest = decode_digest32(frame.required_field(digest_field)?)?;
        if previous.is_some_and(|value| value >= digest) {
            return Err(ConsensusError::InconsistentPersistedState(
                "certificates order",
            ));
        }
        previous = Some(digest);
        let certificate = decode_quorum_certificate(frame.required_field(certificate_field)?)?;
        if certificate.proposal_digest != digest {
            return Err(ConsensusError::InconsistentPersistedState(
                "certificate keyed by wrong digest",
            ));
        }
        map.insert(digest, certificate);
    }
    if encode_certificates_map(&map)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "certificates re-encode",
        ));
    }
    Ok(map)
}

fn encode_pending_vote_group(
    votes: &BTreeMap<ValidatorId, ConsensusVote>,
) -> Result<Vec<u8>, ConsensusError> {
    if votes.len() > MAX_STATE_VOTES_PER_GROUP {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "pending_votes group",
            actual: votes.len(),
            max: MAX_STATE_VOTES_PER_GROUP,
        });
    }
    let mut canonical = CanonicalStruct::new(PENDING_VOTE_GROUP_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(votes.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, vote) in votes.values().enumerate() {
        let field = u16::try_from(index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(field, encode_vote(vote)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_pending_vote_group(
    input: &[u8],
) -> Result<BTreeMap<ValidatorId, ConsensusVote>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PENDING_VOTE_GROUP_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "pending_votes group",
            actual: usize::MAX,
            max: MAX_STATE_VOTES_PER_GROUP,
        }
    })?;
    if count > MAX_STATE_VOTES_PER_GROUP {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "pending_votes group",
            actual: count,
            max: MAX_STATE_VOTES_PER_GROUP,
        });
    }
    let expected_field_count = count
        .checked_add(1)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "pending_votes group field count",
        ));
    }
    let mut votes = BTreeMap::new();
    let mut previous: Option<ValidatorId> = None;
    for index in 0..count {
        let field = u16::try_from(index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let vote = decode_vote(frame.required_field(field)?)?;
        if previous.is_some_and(|validator| validator >= vote.validator) {
            return Err(ConsensusError::InconsistentPersistedState(
                "pending_votes group order",
            ));
        }
        previous = Some(vote.validator);
        votes.insert(vote.validator, vote);
    }
    if encode_pending_vote_group(&votes)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "pending_votes group re-encode",
        ));
    }
    Ok(votes)
}

fn encode_pending_votes(
    map: &BTreeMap<Digest32, BTreeMap<ValidatorId, ConsensusVote>>,
) -> Result<Vec<u8>, ConsensusError> {
    if map.len() > MAX_STATE_PENDING_VOTE_GROUPS {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "pending_votes",
            actual: map.len(),
            max: MAX_STATE_PENDING_VOTE_GROUPS,
        });
    }
    let mut canonical = CanonicalStruct::new(PENDING_VOTES_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(map.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, (digest, votes)) in map.iter().enumerate() {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let group_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(digest_field, encode_digest32(digest)?)?;
        canonical.field_bytes(group_field, encode_pending_vote_group(votes)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_pending_votes(
    input: &[u8],
) -> Result<BTreeMap<Digest32, BTreeMap<ValidatorId, ConsensusVote>>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PENDING_VOTES_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "pending_votes",
            actual: usize::MAX,
            max: MAX_STATE_PENDING_VOTE_GROUPS,
        }
    })?;
    if count > MAX_STATE_PENDING_VOTE_GROUPS {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "pending_votes",
            actual: count,
            max: MAX_STATE_PENDING_VOTE_GROUPS,
        });
    }
    let expected_field_count = count
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "pending_votes field count",
        ));
    }
    let mut map = BTreeMap::new();
    let mut previous: Option<Digest32> = None;
    for index in 0..count {
        let digest_field =
            u16::try_from(2 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let group_field = digest_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let digest = decode_digest32(frame.required_field(digest_field)?)?;
        if previous.is_some_and(|value| value >= digest) {
            return Err(ConsensusError::InconsistentPersistedState(
                "pending_votes order",
            ));
        }
        previous = Some(digest);
        let votes = decode_pending_vote_group(frame.required_field(group_field)?)?;
        for vote in votes.values() {
            if vote.proposal_digest != digest {
                return Err(ConsensusError::InconsistentPersistedState(
                    "pending vote keyed by wrong digest",
                ));
            }
        }
        map.insert(digest, votes);
    }
    if encode_pending_votes(&map)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "pending_votes re-encode",
        ));
    }
    Ok(map)
}

fn encode_observed_votes(
    map: &BTreeMap<(ValidatorId, u64), Digest32>,
) -> Result<Vec<u8>, ConsensusError> {
    if map.len() > MAX_STATE_OBSERVED_VOTES {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "observed_votes",
            actual: map.len(),
            max: MAX_STATE_OBSERVED_VOTES,
        });
    }
    let mut canonical = CanonicalStruct::new(OBSERVED_VOTES_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(map.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, ((validator, view), digest)) in map.iter().enumerate() {
        let validator_field =
            u16::try_from(3 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let view_field = validator_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let digest_field = validator_field
            .checked_add(2)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(validator_field, *validator.as_bytes())?;
        canonical.field_u64(view_field, *view)?;
        canonical.field_bytes(digest_field, encode_digest32(digest)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_observed_votes(
    input: &[u8],
) -> Result<BTreeMap<(ValidatorId, u64), Digest32>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(OBSERVED_VOTES_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "observed_votes",
            actual: usize::MAX,
            max: MAX_STATE_OBSERVED_VOTES,
        }
    })?;
    if count > MAX_STATE_OBSERVED_VOTES {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "observed_votes",
            actual: count,
            max: MAX_STATE_OBSERVED_VOTES,
        });
    }
    let expected_field_count = count
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "observed_votes field count",
        ));
    }
    let mut map = BTreeMap::new();
    let mut previous: Option<(ValidatorId, u64)> = None;
    for index in 0..count {
        let validator_field =
            u16::try_from(3 * index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let view_field = validator_field
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let digest_field = validator_field
            .checked_add(2)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let validator_bytes: [u8; 32] =
            frame
                .required_field(validator_field)?
                .try_into()
                .map_err(|_| {
                    ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
                        field_id: validator_field,
                        expected: 32,
                        actual: frame.required_field(validator_field).map_or(0, <[u8]>::len),
                    })
                })?;
        let validator = ValidatorId::new(validator_bytes);
        let view = frame.required_u64(view_field)?;
        let key = (validator, view);
        if previous.is_some_and(|value| value >= key) {
            return Err(ConsensusError::InconsistentPersistedState(
                "observed_votes order",
            ));
        }
        previous = Some(key);
        let digest = decode_digest32(frame.required_field(digest_field)?)?;
        map.insert(key, digest);
    }
    if encode_observed_votes(&map)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "observed_votes re-encode",
        ));
    }
    Ok(map)
}

fn encode_committed(set: &BTreeSet<Digest32>) -> Result<Vec<u8>, ConsensusError> {
    if set.len() > MAX_STATE_COMMITTED {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "committed",
            actual: set.len(),
            max: MAX_STATE_COMMITTED,
        });
    }
    let mut canonical = CanonicalStruct::new(COMMITTED_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(set.len()).map_err(|_| ConsensusError::ArithmeticOverflow)?,
    )?;
    for (index, digest) in set.iter().enumerate() {
        let field = u16::try_from(index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        canonical.field_bytes(field, encode_digest32(digest)?)?;
    }
    Ok(canonical.finish()?)
}

fn decode_committed(input: &[u8]) -> Result<BTreeSet<Digest32>, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(COMMITTED_LIST_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let count = usize::try_from(frame.required_u32(1)?).map_err(|_| {
        ConsensusError::StateCollectionTooLarge {
            field: "committed",
            actual: usize::MAX,
            max: MAX_STATE_COMMITTED,
        }
    })?;
    if count > MAX_STATE_COMMITTED {
        return Err(ConsensusError::StateCollectionTooLarge {
            field: "committed",
            actual: count,
            max: MAX_STATE_COMMITTED,
        });
    }
    let expected_field_count = count
        .checked_add(1)
        .ok_or(ConsensusError::ArithmeticOverflow)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::InconsistentPersistedState(
            "committed field count",
        ));
    }
    let mut set = BTreeSet::new();
    let mut previous: Option<Digest32> = None;
    for index in 0..count {
        let field = u16::try_from(index + 2).map_err(|_| ConsensusError::ArithmeticOverflow)?;
        let digest = decode_digest32(frame.required_field(field)?)?;
        if previous.is_some_and(|value| value >= digest) {
            return Err(ConsensusError::InconsistentPersistedState(
                "committed order",
            ));
        }
        previous = Some(digest);
        set.insert(digest);
    }
    if encode_committed(&set)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "committed re-encode",
        ));
    }
    Ok(set)
}

/// Encodes the complete persisted [`ConsensusState`] (frame `0xD010/v1`,
/// with nested collection frames `0xD011`-`0xD016`), preserving every
/// private field and deterministic map/set order.
pub fn encode_consensus_state(state: &ConsensusState) -> Result<Vec<u8>, ConsensusError> {
    if (state.last_voted_view == 0) != state.last_voted_digest.is_none() {
        return Err(ConsensusError::InconsistentPersistedState(
            "last_voted_view/last_voted_digest",
        ));
    }
    let mut canonical = CanonicalStruct::new(CONSENSUS_STATE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, state.current_view)?;
    canonical.field_u64(2, state.view_deadline_unix_millis)?;
    canonical.field_u64(3, state.last_voted_view)?;
    if let Some(digest) = state.last_voted_digest {
        canonical.field_bytes(4, encode_digest32(&digest)?)?;
    }
    canonical.field_bytes(5, encode_quorum_certificate(&state.high_qc)?)?;
    canonical.field_bytes(6, encode_quorum_certificate(&state.locked_qc)?)?;
    canonical.field_u64(7, state.committed_height)?;
    canonical.field_bytes(8, encode_known_proposals(&state.known_proposals)?)?;
    canonical.field_bytes(9, encode_certificates_map(&state.certificates)?)?;
    canonical.field_bytes(10, encode_pending_votes(&state.pending_votes)?)?;
    canonical.field_bytes(11, encode_observed_votes(&state.observed_votes)?)?;
    canonical.field_bytes(12, encode_committed(&state.committed)?)?;
    let bytes = canonical.finish()?;
    ensure_encoded_bound(
        "consensus_state",
        bytes.len(),
        MAX_ENCODED_CONSENSUS_STATE_BYTES,
    )?;
    Ok(bytes)
}

/// Decodes and strictly re-validates one canonical persisted
/// [`ConsensusState`].
///
/// Requires the input to fit [`MAX_ENCODED_CONSENSUS_STATE_BYTES`] before
/// any parsing. Beyond the shared canonical-frame guarantees (strict field
/// order, no duplicates, no unknown fields, bounded frame size), this
/// enforces: `last_voted_view == 0` iff `last_voted_digest` is absent;
/// `current_view` non-zero; `high_qc.view < current_view`;
/// `last_voted_view < current_view` when non-zero; `locked_qc.view <=
/// high_qc.view`; `committed_height <= high_qc.height`; every nested
/// collection decodes under its own bounded strict decoder with canonical
/// map/set order and cross-field key consistency (a certificate/proposal
/// keyed by its own digest, a pending vote keyed by the proposal digest it
/// targets); every `committed` digest is present in `known_proposals`; and
/// byte-exact re-encoding of the decoded value. It does not verify any
/// signature or re-derive proposal digests via a hash resolver; callers
/// must still call [`ChainedHotStuff::validate_state`] before reusing a
/// decoded state to drive further transitions.
pub fn decode_consensus_state(input: &[u8]) -> Result<ConsensusState, ConsensusError> {
    ensure_encoded_bound(
        "consensus_state",
        input.len(),
        MAX_ENCODED_CONSENSUS_STATE_BYTES,
    )?;
    let frame = decode_canonical_frame(input)?;
    frame.require_type(CONSENSUS_STATE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;

    let current_view = frame.required_u64(1)?;
    let view_deadline_unix_millis = frame.required_u64(2)?;
    let last_voted_view = frame.required_u64(3)?;
    let last_voted_digest = match frame.field(4) {
        Some(bytes) => Some(decode_digest32(bytes)?),
        None => None,
    };
    if (last_voted_view == 0) != last_voted_digest.is_none() {
        return Err(ConsensusError::InconsistentPersistedState(
            "last_voted_view/last_voted_digest",
        ));
    }
    if current_view == 0 {
        return Err(ConsensusError::InconsistentPersistedState(
            "current_view zero",
        ));
    }
    let high_qc = decode_quorum_certificate(frame.required_field(5)?)?;
    let locked_qc = decode_quorum_certificate(frame.required_field(6)?)?;
    if high_qc.view >= current_view {
        return Err(ConsensusError::InconsistentPersistedState(
            "high_qc view not below current_view",
        ));
    }
    if last_voted_view != 0 && last_voted_view >= current_view {
        return Err(ConsensusError::InconsistentPersistedState(
            "last_voted_view not below current_view",
        ));
    }
    if locked_qc.view > high_qc.view {
        return Err(ConsensusError::InconsistentPersistedState(
            "locked_qc exceeds high_qc",
        ));
    }
    let committed_height = frame.required_u64(7)?;
    if committed_height > high_qc.height {
        return Err(ConsensusError::InconsistentPersistedState(
            "committed_height exceeds high_qc height",
        ));
    }
    let known_proposals = decode_known_proposals(frame.required_field(8)?)?;
    let certificates = decode_certificates_map(frame.required_field(9)?)?;
    let pending_votes = decode_pending_votes(frame.required_field(10)?)?;
    let observed_votes = decode_observed_votes(frame.required_field(11)?)?;
    let committed = decode_committed(frame.required_field(12)?)?;
    for digest in &committed {
        if !known_proposals.contains_key(digest) {
            return Err(ConsensusError::InconsistentPersistedState(
                "committed digest missing from known_proposals",
            ));
        }
    }

    let state = ConsensusState {
        current_view,
        view_deadline_unix_millis,
        last_voted_view,
        last_voted_digest,
        high_qc,
        locked_qc,
        committed_height,
        known_proposals,
        certificates,
        pending_votes,
        observed_votes,
        committed,
    };
    if encode_consensus_state(&state)?.as_slice() != input {
        return Err(ConsensusError::InconsistentPersistedState(
            "consensus_state re-encode",
        ));
    }
    Ok(state)
}

impl ChainedHotStuff {
    /// Verifies a proposal's context, leader eligibility, justify
    /// certificate, and signature without mutating or requiring any state.
    pub fn verify_proposal<V: ConsensusVerifier>(
        &self,
        proposal: &ConsensusProposal,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.validate_proposal(proposal, verifier)
    }

    /// Verifies a vote's context, registered scheme, and signature without
    /// mutating or requiring any state.
    pub fn verify_vote<V: ConsensusVerifier>(
        &self,
        vote: &ConsensusVote,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.validate_vote(vote, verifier)
    }

    /// Deterministically aggregates a minimal quorum certificate from
    /// already-signed votes for one proposal, or `Ok(None)` if the given
    /// votes do not reach quorum.
    ///
    /// Rejects an oversized `votes` slice (see
    /// [`MAX_CERTIFICATE_FROM_VOTES_INPUT`]) before any per-vote work, then
    /// verifies the proposal itself (context, leader, justify, signature),
    /// then every candidate vote's context, registered scheme, and
    /// signature, and that each vote actually targets this proposal's
    /// digest/view/height. Votes are deduplicated by validator (a repeated
    /// byte-identical vote is accepted idempotently; a repeated vote that
    /// differs is rejected as non-canonical, since this method does not
    /// build equivocation evidence). The certificate accumulates votes in
    /// ascending [`ValidatorId`] order -- the same canonical order
    /// [`encode_quorum_certificate`] requires -- stopping as soon as the
    /// validator set's quorum threshold is met, so two callers given the
    /// same vote set always produce byte-identical certificates regardless
    /// of the order votes were collected in.
    pub fn certificate_from_votes<V: ConsensusVerifier>(
        &self,
        proposal: &ConsensusProposal,
        votes: &[ConsensusVote],
        verifier: &V,
    ) -> Result<Option<QuorumCertificate>, ConsensusError> {
        if votes.len() > MAX_CERTIFICATE_FROM_VOTES_INPUT {
            return Err(ConsensusError::StateCollectionTooLarge {
                field: "certificate_from_votes input",
                actual: votes.len(),
                max: MAX_CERTIFICATE_FROM_VOTES_INPUT,
            });
        }
        self.validate_proposal(proposal, verifier)?;
        let digest = self.proposal_digest(proposal)?;
        let mut unique: BTreeMap<ValidatorId, ConsensusVote> = BTreeMap::new();
        for vote in votes {
            if vote.proposal_digest != digest
                || vote.view != proposal.view
                || vote.height != proposal.height
            {
                return Err(ConsensusError::CertificateVoteMismatch);
            }
            self.validate_vote(vote, verifier)?;
            if let Some(existing) = unique.get(&vote.validator) {
                if existing != vote {
                    return Err(ConsensusError::NonCanonicalCertificateVotes);
                }
                continue;
            }
            unique.insert(vote.validator, vote.clone());
        }
        let required = self.validator_set.quorum_threshold();
        let mut power = 0u64;
        let mut selected = Vec::new();
        for (validator, vote) in &unique {
            let info = self
                .validator_set
                .get(*validator)
                .ok_or(ConsensusError::UnknownValidator(*validator))?;
            power = power
                .checked_add(info.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
            selected.push(vote.clone());
            if power >= required {
                break;
            }
        }
        if power < required {
            return Ok(None);
        }
        Ok(Some(QuorumCertificate {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            view: proposal.view,
            height: proposal.height,
            proposal_digest: digest,
            votes: selected,
        }))
    }

    fn process_observed_proposal<V: ConsensusVerifier>(
        &self,
        state: &mut ConsensusState,
        proposal: ConsensusProposal,
        verifier: &V,
        committed: &mut Vec<CommittedBlock>,
    ) -> Result<(), ConsensusError> {
        self.validate_proposal(&proposal, verifier)?;
        // The observer path treats its input as untrusted authenticated
        // history (not yet-trusted local processing), so unlike the local
        // voting path it bounds the future-view gap here too, even though
        // this method never votes or advances a timeout.
        self.ensure_bounded_future_view(state.current_view, proposal.view)?;
        let digest = self.proposal_digest(&proposal)?;
        state
            .known_proposals
            .entry(digest)
            .or_insert_with(|| proposal.clone());
        self.apply_certificate(state, proposal.justify.clone(), verifier, committed)?;
        if let Some(certificate) = state.certificates.get(&digest).cloned() {
            self.apply_certificate(state, certificate, verifier, committed)?;
        }
        Ok(())
    }

    /// Applies one authenticated proposal, vote, or certificate observed
    /// from an untrusted transport but already carrying valid signatures
    /// (e.g. replaying another validator's certified history), without the
    /// local validator signing anything.
    ///
    /// This never appends to `last_voted_view`/`last_voted_digest` and
    /// never emits a [`crate::ConsensusMessage::Vote`]: a [`ConsensusEvent::Proposal`]
    /// only records the proposal and applies its justify/known certificate,
    /// exactly like the existing-certificate fast path in
    /// `process_proposal`, preserving the same lock/high-QC/commit/prune
    /// semantics as [`crate::ConsensusEngine::on_event`], and additionally
    /// bounds the proposal's future-view gap (the authenticated event
    /// stream is still untrusted transport, not yet-trusted local state). A
    /// [`ConsensusEvent::Vote`] is aggregated exactly as in `on_event`
    /// (useful for building a certificate from independently observed
    /// votes); a [`ConsensusEvent::Certificate`]'s vote list is bounded and
    /// every signature re-verified by [`Self::verify_certificate`] before
    /// being applied. A [`ConsensusEvent::Tick`] carries no authenticated
    /// content and is always rejected with
    /// [`ConsensusError::UntrustedObserverTick`] -- this method can never
    /// manufacture a vote or a view advance from an unauthenticated clock.
    pub fn on_observer_event<V: ConsensusVerifier>(
        &self,
        state: &ConsensusState,
        event: ConsensusEvent,
        verifier: &V,
    ) -> Result<ConsensusOutput, ConsensusError> {
        let mut next = state.clone();
        let mut outbound = Vec::new();
        let mut committed = Vec::new();
        match event {
            ConsensusEvent::Proposal(proposal) => {
                self.process_observed_proposal(&mut next, proposal, verifier, &mut committed)?;
            }
            ConsensusEvent::Vote(vote) => {
                self.process_vote(&mut next, vote, verifier, &mut outbound, &mut committed)?;
            }
            ConsensusEvent::Certificate(certificate) => {
                self.apply_certificate(&mut next, certificate, verifier, &mut committed)?;
            }
            ConsensusEvent::Tick { .. } => return Err(ConsensusError::UntrustedObserverTick),
        }
        self.prune_state(&mut next);
        Ok(ConsensusOutput {
            state: next,
            outbound_messages: outbound,
            committed_blocks: committed,
            view_advanced: false,
        })
    }

    /// Re-verifies a decoded, persisted [`ConsensusState`] against this
    /// engine's context, validator set, and hash resolver before it is
    /// reused to drive further transitions.
    ///
    /// Checks the local last-voted/high-QC/locked-QC/committed-height
    /// invariants [`decode_consensus_state`] already enforces structurally,
    /// then re-verifies every embedded signature: `high_qc`, `locked_qc`,
    /// every entry in the certificate and known-proposal caches (each
    /// keyed by its own digest, and, where both a certificate and its
    /// proposal are retained, agreeing on view/height), every pending vote
    /// (keyed by the proposal digest it targets, inner map keyed by the
    /// vote's own validator, and cross-checked against `observed_votes`
    /// where an entry for that `(validator, view)` is still retained), and
    /// that every observed-vote validator is a member of the active
    /// validator set. `high_qc`/`locked_qc` must either be the exact
    /// genesis anchor or exactly match the retained entry in `certificates`
    /// keyed by their own digest.
    ///
    /// This is deliberately more expensive than `on_event`'s per-message
    /// verification and is meant to be run once, after loading state from
    /// durable storage or across a process restart, not on every
    /// transition.
    ///
    /// Limitation: this cannot recover a *local* binding between
    /// `last_voted_view`/`last_voted_digest` and this validator's own entry
    /// in `observed_votes`, because [`ChainedHotStuff::prune_state`] may
    /// have already dropped the old vote/proposal it referred to (pruning
    /// only ever retains `high_qc`/`locked_qc` unconditionally, not an
    /// arbitrary last-voted digest). Reconstructing that specific
    /// still-safe-to-vote invariant after a restart, if ever needed,
    /// belongs in the caller that owns local identity (e.g. `node-core`),
    /// not in this crate.
    pub fn validate_state<V: ConsensusVerifier>(
        &self,
        state: &ConsensusState,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        if (state.last_voted_view == 0) != state.last_voted_digest.is_none() {
            return Err(ConsensusError::InconsistentPersistedState(
                "last_voted_view/last_voted_digest",
            ));
        }
        if state.current_view == 0 {
            return Err(ConsensusError::InconsistentPersistedState(
                "current_view zero",
            ));
        }
        if state.high_qc.view >= state.current_view {
            return Err(ConsensusError::InconsistentPersistedState(
                "high_qc view not below current_view",
            ));
        }
        if state.last_voted_view != 0 && state.last_voted_view >= state.current_view {
            return Err(ConsensusError::InconsistentPersistedState(
                "last_voted_view not below current_view",
            ));
        }
        if state.locked_qc.view > state.high_qc.view {
            return Err(ConsensusError::InconsistentPersistedState(
                "locked_qc exceeds high_qc",
            ));
        }
        if state.committed_height > state.high_qc.height {
            return Err(ConsensusError::InconsistentPersistedState(
                "committed_height exceeds high_qc height",
            ));
        }
        self.verify_certificate(&state.high_qc, verifier)?;
        self.verify_certificate(&state.locked_qc, verifier)?;
        if state.high_qc.view != 0
            && state.certificates.get(&state.high_qc.proposal_digest) != Some(&state.high_qc)
        {
            return Err(ConsensusError::InconsistentPersistedState(
                "high_qc not retained in certificates",
            ));
        }
        if state.locked_qc.view != 0
            && state.certificates.get(&state.locked_qc.proposal_digest) != Some(&state.locked_qc)
        {
            return Err(ConsensusError::InconsistentPersistedState(
                "locked_qc not retained in certificates",
            ));
        }
        for (digest, certificate) in &state.certificates {
            if certificate.proposal_digest != *digest {
                return Err(ConsensusError::InconsistentPersistedState(
                    "certificate keyed by wrong digest",
                ));
            }
            self.verify_certificate(certificate, verifier)?;
            if let Some(proposal) = state.known_proposals.get(digest)
                && (proposal.view != certificate.view || proposal.height != certificate.height)
            {
                return Err(ConsensusError::InconsistentPersistedState(
                    "known proposal view/height disagrees with its certificate",
                ));
            }
        }
        for (digest, proposal) in &state.known_proposals {
            if self.proposal_digest(proposal)? != *digest {
                return Err(ConsensusError::InconsistentPersistedState(
                    "known_proposals keyed by wrong digest",
                ));
            }
            self.validate_proposal(proposal, verifier)?;
        }
        for (digest, votes) in &state.pending_votes {
            for (validator, vote) in votes {
                if vote.proposal_digest != *digest {
                    return Err(ConsensusError::InconsistentPersistedState(
                        "pending vote keyed by wrong digest",
                    ));
                }
                if vote.validator != *validator {
                    return Err(ConsensusError::InconsistentPersistedState(
                        "pending vote keyed by wrong validator",
                    ));
                }
                self.validate_vote(vote, verifier)?;
                // A pruned observed_votes entry for this (validator, view)
                // is not an error: prune_state's group-representative
                // retention criterion is coarser than a per-vote one, so a
                // legitimately retained pending vote can outlive its own
                // observed_votes entry. When one is still present, though,
                // it must agree.
                if let Some(observed) = state.observed_votes.get(&(vote.validator, vote.view))
                    && *observed != vote.proposal_digest
                {
                    return Err(ConsensusError::InconsistentPersistedState(
                        "pending vote disagrees with observed_votes",
                    ));
                }
            }
        }
        for (validator, _) in state.observed_votes.keys() {
            self.validator_set
                .get(*validator)
                .ok_or(ConsensusError::UnknownValidator(*validator))?;
        }
        for digest in &state.committed {
            if !state.known_proposals.contains_key(digest) {
                return Err(ConsensusError::InconsistentPersistedState(
                    "committed digest missing from known_proposals",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
