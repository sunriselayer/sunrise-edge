//! `OrderedCandidate`: the exact operation envelope proposed under DR-0153's
//! closed three-chain scheduling profile. This frame carries no consensus
//! bookkeeping of its own -- only the exact existing canonical intent bytes
//! (or evidence's canonical outer frame) an existing handler already
//! decodes, plus the identity/context needed to place it in the shared
//! order.
use super::*;
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};

const ORDERED_CANDIDATE_TYPE: u16 = 0x6440;
const ENCODING_VERSION: u16 = 1;

/// Maximum canonical bytes of one candidate's embedded intent/evidence
/// envelope. Bounded generously above the largest existing signed envelope
/// this crate already accepts (a multi-leg bond-lifecycle intent), since an
/// ordered candidate carries exactly one existing envelope unmodified.
pub const MAX_ORDERED_CANDIDATE_INTENT_BYTES: usize = 512 * 1024;

/// The one existing economics state machine an [`OrderedCandidate`] invokes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedOperationKind {
    /// `fees::SignedFeeClaimIntent` (existing `crate::fee_claims`).
    FeeClaim,
    /// `crate::bond_lifecycle::SignedBondLifecycleIntent`.
    BondLifecycle,
    /// `crate::bond_lifecycle::slash::SlashIntent` (unsigned, evidence-authorized).
    BondSlash,
    /// One of the three DR-0133 equivocation-evidence families
    /// (`crate::equivocation`).
    Evidence,
    /// DR-0154: the closed-admission control command (`super::freeze`).
    /// Unlike every other kind, its `intent` carries no signature.
    Freeze,
}

impl OrderedOperationKind {
    pub(crate) fn to_wire(self) -> u16 {
        match self {
            Self::FeeClaim => 1,
            Self::BondLifecycle => 2,
            Self::BondSlash => 3,
            Self::Evidence => 4,
            Self::Freeze => 5,
        }
    }

    pub(crate) fn from_wire(value: u16) -> Result<Self, NodeCoreError> {
        match value {
            1 => Ok(Self::FeeClaim),
            2 => Ok(Self::BondLifecycle),
            3 => Ok(Self::BondSlash),
            4 => Ok(Self::Evidence),
            5 => Ok(Self::Freeze),
            other => Err(NodeCoreError::PersistenceInvariant(ordered_kind_message(
                other,
            ))),
        }
    }
}

fn ordered_kind_message(_value: u16) -> &'static str {
    "unknown ordered operation kind"
}

/// One candidate ordered economics operation, exactly as specified by the
/// `node_core::ordered_economics` contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedCandidate {
    /// Chain/protocol/epoch replay boundary.
    pub context: PublicationContext,
    /// Exact replay identity; must equal the signed outer request id and
    /// every embedded leg's own request id (checked by
    /// [`super::authenticate_candidate`], not by this codec).
    pub request_id: [u8; 32],
    /// Which existing state machine this candidate invokes.
    pub kind: OrderedOperationKind,
    /// Exact existing canonical envelope bytes (signed intent, or the
    /// evidence's canonical outer frame for [`OrderedOperationKind::Evidence`]).
    pub intent: Vec<u8>,
    /// Committed execution input recorded at candidate creation. Not proof
    /// that any checkpoint or state root was published.
    pub created_checkpoint: u64,
}

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// Encodes frame `0x6440/v1`.
pub fn encode_ordered_candidate(candidate: &OrderedCandidate) -> Result<Vec<u8>, NodeCoreError> {
    if candidate.request_id == [0u8; 32] {
        return Err(invalid("ordered candidate request id must not be zero"));
    }
    if candidate.intent.is_empty() || candidate.intent.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("ordered candidate intent length"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(ORDERED_CANDIDATE_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&candidate.context)
            .map_err(|_| invalid("invalid ordered candidate context"))?,
    )?;
    frame.field_bytes(2, candidate.request_id.to_vec())?;
    frame.field_u16(3, candidate.kind.to_wire())?;
    frame.field_bytes(4, candidate.intent.clone())?;
    frame.field_u64(5, candidate.created_checkpoint)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6440/v1`.
pub fn decode_ordered_candidate(bytes: &[u8]) -> Result<OrderedCandidate, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ORDERED_CANDIDATE_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let request_id_bytes: &[u8] = frame.required_field(2)?;
    let request_id: [u8; 32] = request_id_bytes
        .try_into()
        .map_err(|_| invalid("ordered candidate request id length"))?;
    // Bound the borrowed field before it is copied: an untrusted frame must
    // not be able to make this decoder allocate an oversized intent and only
    // then be told it was too large.
    let intent_bytes: &[u8] = frame.required_field(4)?;
    if intent_bytes.is_empty() || intent_bytes.len() > MAX_ORDERED_CANDIDATE_INTENT_BYTES {
        return Err(invalid("ordered candidate intent length"));
    }
    let intent: Vec<u8> = intent_bytes.to_vec();
    let candidate: OrderedCandidate = OrderedCandidate {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("ordered candidate context"))?,
        request_id,
        kind: OrderedOperationKind::from_wire(frame.required_u16(3)?)?,
        intent,
        created_checkpoint: frame.required_u64(5)?,
    };
    if candidate.request_id == [0u8; 32] || encode_ordered_candidate(&candidate)? != bytes {
        return Err(invalid("noncanonical ordered candidate"));
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, ProtocolVersion};

    fn context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("ordered-economics-tests").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap()
    }

    #[test]
    fn ordered_candidate_round_trips_for_every_kind() {
        for kind in [
            OrderedOperationKind::FeeClaim,
            OrderedOperationKind::BondLifecycle,
            OrderedOperationKind::BondSlash,
            OrderedOperationKind::Evidence,
            OrderedOperationKind::Freeze,
        ] {
            let candidate: OrderedCandidate = OrderedCandidate {
                context: context(),
                request_id: [7; 32],
                kind,
                intent: vec![1, 2, 3, 4],
                created_checkpoint: 42,
            };
            let bytes: Vec<u8> = encode_ordered_candidate(&candidate).unwrap();
            let decoded: OrderedCandidate = decode_ordered_candidate(&bytes).unwrap();
            assert_eq!(decoded, candidate);
        }
    }

    #[test]
    fn ordered_candidate_rejects_zero_request_id_and_empty_intent() {
        let mut candidate: OrderedCandidate = OrderedCandidate {
            context: context(),
            request_id: [0; 32],
            kind: OrderedOperationKind::FeeClaim,
            intent: vec![1],
            created_checkpoint: 1,
        };
        assert!(encode_ordered_candidate(&candidate).is_err());
        candidate.request_id = [9; 32];
        candidate.intent.clear();
        assert!(encode_ordered_candidate(&candidate).is_err());
    }

    #[test]
    fn ordered_operation_kind_from_wire_rejects_unknown_tag() {
        assert!(OrderedOperationKind::from_wire(0).is_err());
        assert!(OrderedOperationKind::from_wire(6).is_err());
    }

    #[test]
    fn ordered_candidate_decode_rejects_wrong_frame_type() {
        let other_frame: Vec<u8> = {
            let mut frame: CanonicalStruct = CanonicalStruct::new(0x1234, ENCODING_VERSION);
            frame.field_bytes(1, vec![1, 2, 3]).unwrap();
            frame.finish().unwrap()
        };
        assert!(decode_ordered_candidate(&other_frame).is_err());
    }
}
