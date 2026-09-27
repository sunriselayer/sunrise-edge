//! `OrderedOperationKind::Evidence` candidates carry a submission envelope,
//! not an already-built evidence record: `equivocation::submit_*` (the
//! existing DR-0133 handlers) build and verify the evidence themselves from
//! two raw signed statements, and commit through a content-addressed
//! absence fence rather than the request-id receipt every other kind uses.
//! This module owns that envelope's canonical frame (`0x6449/v1`) and the
//! pure build step both [`super::policy::authenticate_candidate`] and
//! [`super::engine`]'s execution dispatch share.
use super::*;
use consensus::{
    EpochTransitionEquivocationEvidence, FastVote, FastVoteEquivocationEvidence,
    FastVoteObjectConflictEvidence, LockedObjectSetPreimage,
    build_epoch_transition_equivocation_evidence, build_fast_vote_equivocation_evidence,
    build_fast_vote_object_conflict_evidence, decode_epoch_transition_vote, decode_fast_vote,
    decode_locked_object_set_preimage,
};
use protocol_types::{ChainId, ProtocolVersion};

const EVIDENCE_SUBMISSION_TYPE: u16 = 0x6449;
const ENCODING_VERSION: u16 = 1;
const FAMILY_FAST_VOTE: u16 = 1;
const FAMILY_OBJECT_CONFLICT: u16 = 2;
const FAMILY_EPOCH_TRANSITION: u16 = 3;

/// Maximum canonical bytes of one evidence submission envelope.
///
/// The envelope is only ever carried as an [`OrderedCandidate`] intent, so this
/// is exactly that bound and can reject nothing a candidate could legitimately
/// hold. Because every decoded part is a borrowed slice of the whole frame,
/// enforcing it at the decoder entry bounds every subsequent copy -- the point
/// being that an untrusted frame cannot make this decoder allocate megabytes of
/// statements and only afterwards be told the envelope was oversized.
pub const MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES: usize = MAX_ORDERED_CANDIDATE_INTENT_BYTES;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// Raw signed statements (plus, for the object-conflict family, their
/// locked-object preimages) an [`OrderedCandidate`] of kind
/// [`OrderedOperationKind::Evidence`] carries. Mirrors exactly what
/// `equivocation::submit_*` itself takes, so execution never re-derives or
/// second-guesses what authentication already built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedEvidenceSubmission {
    FastVote {
        statement_a: Vec<u8>,
        statement_b: Vec<u8>,
        checkpoint: u64,
    },
    ObjectConflict {
        statement_a: Vec<u8>,
        statement_b: Vec<u8>,
        preimage_a: Vec<u8>,
        preimage_b: Vec<u8>,
        checkpoint: u64,
    },
    EpochTransition {
        statement_a: Vec<u8>,
        statement_b: Vec<u8>,
        checkpoint: u64,
    },
}

impl OrderedEvidenceSubmission {
    pub(crate) fn checkpoint(&self) -> u64 {
        match self {
            Self::FastVote { checkpoint, .. }
            | Self::ObjectConflict { checkpoint, .. }
            | Self::EpochTransition { checkpoint, .. } => *checkpoint,
        }
    }
}

/// Encodes frame `0x6449/v1`.
pub fn encode_ordered_evidence_submission(
    value: &OrderedEvidenceSubmission,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame = CanonicalStruct::new(EVIDENCE_SUBMISSION_TYPE, ENCODING_VERSION);
    match value {
        OrderedEvidenceSubmission::FastVote {
            statement_a,
            statement_b,
            checkpoint,
        } => {
            frame.field_u16(1, FAMILY_FAST_VOTE)?;
            frame.field_bytes(2, statement_a.clone())?;
            frame.field_bytes(3, statement_b.clone())?;
            frame.field_u64(4, *checkpoint)?;
        }
        OrderedEvidenceSubmission::ObjectConflict {
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            checkpoint,
        } => {
            frame.field_u16(1, FAMILY_OBJECT_CONFLICT)?;
            frame.field_bytes(2, statement_a.clone())?;
            frame.field_bytes(3, statement_b.clone())?;
            frame.field_u64(4, *checkpoint)?;
            frame.field_bytes(5, preimage_a.clone())?;
            frame.field_bytes(6, preimage_b.clone())?;
        }
        OrderedEvidenceSubmission::EpochTransition {
            statement_a,
            statement_b,
            checkpoint,
        } => {
            frame.field_u16(1, FAMILY_EPOCH_TRANSITION)?;
            frame.field_bytes(2, statement_a.clone())?;
            frame.field_bytes(3, statement_b.clone())?;
            frame.field_u64(4, *checkpoint)?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES {
        return Err(invalid("ordered evidence submission bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes frame `0x6449/v1`.
pub fn decode_ordered_evidence_submission(
    bytes: &[u8],
) -> Result<OrderedEvidenceSubmission, NodeCoreError> {
    if bytes.len() > MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES {
        return Err(invalid("ordered evidence submission bytes"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(EVIDENCE_SUBMISSION_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let family = frame.required_u16(1)?;
    let value = match family {
        FAMILY_FAST_VOTE => {
            frame.require_only_fields(&[1, 2, 3, 4])?;
            OrderedEvidenceSubmission::FastVote {
                statement_a: frame.required_field(2)?.to_vec(),
                statement_b: frame.required_field(3)?.to_vec(),
                checkpoint: frame.required_u64(4)?,
            }
        }
        FAMILY_OBJECT_CONFLICT => {
            frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
            OrderedEvidenceSubmission::ObjectConflict {
                statement_a: frame.required_field(2)?.to_vec(),
                statement_b: frame.required_field(3)?.to_vec(),
                checkpoint: frame.required_u64(4)?,
                preimage_a: frame.required_field(5)?.to_vec(),
                preimage_b: frame.required_field(6)?.to_vec(),
            }
        }
        FAMILY_EPOCH_TRANSITION => {
            frame.require_only_fields(&[1, 2, 3, 4])?;
            OrderedEvidenceSubmission::EpochTransition {
                statement_a: frame.required_field(2)?.to_vec(),
                statement_b: frame.required_field(3)?.to_vec(),
                checkpoint: frame.required_u64(4)?,
            }
        }
        other => return Err(invalid_family(other)),
    };
    if encode_ordered_evidence_submission(&value)? != bytes {
        return Err(invalid("noncanonical ordered evidence submission"));
    }
    Ok(value)
}

fn invalid_family(_family: u16) -> NodeCoreError {
    invalid("unknown ordered evidence submission family")
}

/// Purely builds (never persists or looks up) the complete cryptographic
/// evidence this submission names, ready for
/// [`equivocation::DecodedEquivocationEvidence`]-shaped verification.
pub(crate) fn build_decoded_evidence(
    submission: &OrderedEvidenceSubmission,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
) -> Result<equivocation::DecodedEquivocationEvidence, OrderedEconomicsError> {
    let bad = |_| OrderedEconomicsError::Unauthenticated("invalid evidence candidate statement");
    match submission {
        OrderedEvidenceSubmission::FastVote {
            statement_a,
            statement_b,
            ..
        } => {
            let a: FastVote = decode_fast_vote(statement_a).map_err(bad)?;
            let b: FastVote = decode_fast_vote(statement_b).map_err(bad)?;
            if &a.chain_id != chain || a.protocol_version != protocol_version {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "evidence candidate statement chain/protocol mismatch",
                ));
            }
            let evidence: FastVoteEquivocationEvidence =
                build_fast_vote_equivocation_evidence(&a, &b).map_err(bad)?;
            Ok(equivocation::DecodedEquivocationEvidence::FastVote(
                evidence,
            ))
        }
        OrderedEvidenceSubmission::ObjectConflict {
            statement_a,
            statement_b,
            preimage_a,
            preimage_b,
            ..
        } => {
            let a: FastVote = decode_fast_vote(statement_a).map_err(bad)?;
            let b: FastVote = decode_fast_vote(statement_b).map_err(bad)?;
            let a_preimage: LockedObjectSetPreimage =
                decode_locked_object_set_preimage(preimage_a).map_err(bad)?;
            let b_preimage: LockedObjectSetPreimage =
                decode_locked_object_set_preimage(preimage_b).map_err(bad)?;
            if &a.chain_id != chain || a.protocol_version != protocol_version {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "evidence candidate statement chain/protocol mismatch",
                ));
            }
            let evidence: FastVoteObjectConflictEvidence =
                build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage)
                    .map_err(bad)?;
            Ok(equivocation::DecodedEquivocationEvidence::ObjectConflict(
                evidence,
            ))
        }
        OrderedEvidenceSubmission::EpochTransition {
            statement_a,
            statement_b,
            ..
        } => {
            let a = decode_epoch_transition_vote(statement_a).map_err(bad)?;
            let b = decode_epoch_transition_vote(statement_b).map_err(bad)?;
            if a.chain_id != *chain || a.protocol_version != protocol_version {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "evidence candidate statement chain/protocol mismatch",
                ));
            }
            let evidence: EpochTransitionEquivocationEvidence =
                build_epoch_transition_equivocation_evidence(&a, &b).map_err(bad)?;
            Ok(equivocation::DecodedEquivocationEvidence::EpochTransition(
                evidence,
            ))
        }
    }
}
