//! Bounded transport locators for post-Freeze frontier possession (DR-0157)
//! and bounded read-only durable drain signer progress (DR-0158).
//!
//! These frames select one operation on the host's own pinned outgoing epoch.
//! They are never authority: signed votes, pages and the selection are
//! independently verified by node-core against the installed set and Freeze.
//! The full publication import route accepts the existing canonical bundle
//! frame directly, avoiding an outer frame that would shrink its 32 MiB bound.
//!
//! [`DrainSignerProgressResponse`] is a bounded scheduling hint only: its
//! nested vote, running identity and staged page are exact canonical
//! protocol bytes, independently decoded and re-verified by the caller
//! against its own local pin. It is never handoff authority, creates no ACK,
//! signature or application effect, and is not a ready/`DrainSet` claim.

use crate::fastvote_frontier::{MAX_FRONTIER_PAGE_BYTES, MAX_FRONTIER_VOTE_BYTES};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use consensus::{FrozenFrontierVote, decode_frozen_frontier_vote, encode_frozen_frontier_vote};
use node_core::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS;
use protocol_types::{Epoch, ValidatorId};
use std::error::Error;
use std::fmt;

pub const FASTVOTE_DRAIN_SIGNER_PAGE_PATH: &str = "/v1/fastvote/drain/signer-page";
pub const FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH: &str = "/v1/fastvote/drain/member-confirm";
pub const FASTVOTE_DRAIN_UNION_ADVANCE_PATH: &str = "/v1/fastvote/drain/union-advance";
/// The `validator_id` path segment is only a locator. The complete canonical
/// bundle body is checked against the locally staged, page-verified identity.
pub const FASTVOTE_DRAIN_IMPORT_PATH: &str = "/v1/fastvote/drain/import/{validator_id}";
/// Certified-only, read-only. Never mutates, signs, ACKs, or claims
/// readiness; see [`DrainSignerProgressResponse`].
pub const FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH: &str = "/v1/fastvote/drain/signer-progress";

pub const DRAIN_SIGNER_PAGE_REQUEST_TYPE_ID: u16 = 0xE10A;
pub const DRAIN_MEMBER_CONFIRM_REQUEST_TYPE_ID: u16 = 0xE10B;
pub const DRAIN_UNION_ADVANCE_REQUEST_TYPE_ID: u16 = 0xE10C;
pub const DRAIN_SIGNER_PROGRESS_REQUEST_TYPE_ID: u16 = 0xE10D;
pub const DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID: u16 = 0xE10E;
const VERSION: u16 = 1;

pub const MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES: usize =
    MAX_FRONTIER_VOTE_BYTES + MAX_FRONTIER_PAGE_BYTES + 128;
pub const MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES: usize = 160;
pub const MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES: usize =
    MAX_FASTPATH_ACTIVE_VALIDATORS * (MAX_FRONTIER_VOTE_BYTES + 8) + 128;
pub const MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES: usize = 128;
/// Matches the private `consensus::availability::frontier::MAX_FRONTIER_IDENTITY_BYTES`
/// bound on one encoded [`consensus::FrozenFrontierIdentity`].
const MAX_DRAIN_SIGNER_PROGRESS_IDENTITY_BYTES: usize = 2 * 1024;
/// Matches `consensus::availability::frontier`'s own 128-byte chain-id bound.
const MAX_DRAIN_SIGNER_PROGRESS_CHAIN_ID_BYTES: usize = 128;
pub const MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES: usize = MAX_DRAIN_SIGNER_PROGRESS_CHAIN_ID_BYTES
    + MAX_FRONTIER_VOTE_BYTES
    + MAX_DRAIN_SIGNER_PROGRESS_IDENTITY_BYTES
    + MAX_FRONTIER_PAGE_BYTES + 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainWireError {
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Invalid(&'static str),
}

impl fmt::Display for DrainWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl Error for DrainWireError {}

impl From<CanonicalEncodingError> for DrainWireError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Encoding(value)
    }
}

impl From<CanonicalDecodingError> for DrainWireError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Decoding(value)
    }
}

/// One untrusted signed vote and consecutive frontier page for the local
/// outgoing epoch. A vote is not accepted merely because this frame decodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSignerPageRequest {
    pub epoch: Epoch,
    pub vote: Vec<u8>,
    pub page: Vec<u8>,
}

impl DrainSignerPageRequest {
    fn validate(&self) -> Result<(), DrainWireError> {
        if self.vote.is_empty() || self.vote.len() > MAX_FRONTIER_VOTE_BYTES {
            return Err(DrainWireError::Invalid("drain frontier vote bound"));
        }
        if self.page.is_empty() || self.page.len() > MAX_FRONTIER_PAGE_BYTES {
            return Err(DrainWireError::Invalid("drain frontier page bound"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DrainWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PAGE_REQUEST_TYPE_ID, VERSION);
        frame.field_u64(1, self.epoch.get())?;
        frame.field_bytes(2, self.vote.clone())?;
        frame.field_bytes(3, self.page.clone())?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DrainWireError> {
        if bytes.len() > MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES {
            return Err(DrainWireError::Invalid("drain signer page request bound"));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(DRAIN_SIGNER_PAGE_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            vote: frame.required_field(2)?.to_vec(),
            page: frame.required_field(3)?.to_vec(),
        };
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(DrainWireError::Invalid(
                "noncanonical drain signer page request",
            ));
        }
        Ok(request)
    }
}

/// Confirms only the current staged member of this signer. The request ID is
/// a stale-driver guard, not an identity supplied to core as authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainMemberConfirmRequest {
    pub epoch: Epoch,
    pub validator: ValidatorId,
    pub request_id: [u8; 32],
}

impl DrainMemberConfirmRequest {
    fn validate(&self) -> Result<(), DrainWireError> {
        if self.request_id == [0; 32] {
            return Err(DrainWireError::Invalid("zero drain member request id"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DrainWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_MEMBER_CONFIRM_REQUEST_TYPE_ID, VERSION);
        frame.field_u64(1, self.epoch.get())?;
        frame.field_bytes(2, self.validator.as_bytes().to_vec())?;
        frame.field_bytes(3, self.request_id.to_vec())?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DrainWireError> {
        if bytes.len() > MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES {
            return Err(DrainWireError::Invalid(
                "drain member confirm request bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(DRAIN_MEMBER_CONFIRM_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let validator_bytes: [u8; 32] = frame
            .required_field(2)?
            .try_into()
            .map_err(|_| DrainWireError::Invalid("drain validator length"))?;
        let request_id: [u8; 32] = frame
            .required_field(3)?
            .try_into()
            .map_err(|_| DrainWireError::Invalid("drain member request id length"))?;
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            validator: ValidatorId::new(validator_bytes),
            request_id,
        };
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(DrainWireError::Invalid(
                "noncanonical drain member confirm request",
            ));
        }
        Ok(request)
    }
}

/// Requests one bounded merge step for a canonical quorum selection. The
/// nested selection is decoded and verified against the local Freeze in core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainUnionAdvanceRequest {
    pub epoch: Epoch,
    pub votes: Vec<FrozenFrontierVote>,
}

impl DrainUnionAdvanceRequest {
    fn validate(&self) -> Result<(), DrainWireError> {
        if self.votes.is_empty() || self.votes.len() > MAX_FASTPATH_ACTIVE_VALIDATORS {
            return Err(DrainWireError::Invalid("drain union vote count"));
        }
        for pair in self.votes.windows(2) {
            if pair[0].validator >= pair[1].validator {
                return Err(DrainWireError::Invalid("drain union vote order"));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DrainWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_UNION_ADVANCE_REQUEST_TYPE_ID, VERSION);
        frame.field_u64(1, self.epoch.get())?;
        let count: u16 = u16::try_from(self.votes.len())
            .map_err(|_| DrainWireError::Invalid("drain union vote count"))?;
        frame.field_u16(2, count)?;
        for (index, vote) in self.votes.iter().enumerate() {
            let field: u16 = u16::try_from(index + 3)
                .map_err(|_| DrainWireError::Invalid("drain union vote field"))?;
            let encoded: Vec<u8> = encode_frozen_frontier_vote(vote)
                .map_err(|_| DrainWireError::Invalid("drain union vote encoding"))?;
            frame.field_bytes(field, encoded)?;
        }
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DrainWireError> {
        if bytes.len() > MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES {
            return Err(DrainWireError::Invalid("drain union request bound"));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(DRAIN_UNION_ADVANCE_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        let count: usize = usize::from(frame.required_u16(2)?);
        if count == 0 || count > MAX_FASTPATH_ACTIVE_VALIDATORS || frame.field_count() != count + 2
        {
            return Err(DrainWireError::Invalid("drain union vote count"));
        }
        let mut votes: Vec<FrozenFrontierVote> = Vec::with_capacity(count);
        for index in 0..count {
            let field: u16 = u16::try_from(index + 3)
                .map_err(|_| DrainWireError::Invalid("drain union vote field"))?;
            votes.push(
                decode_frozen_frontier_vote(frame.required_field(field)?)
                    .map_err(|_| DrainWireError::Invalid("invalid drain union vote"))?,
            );
        }
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            votes,
        };
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(DrainWireError::Invalid("noncanonical drain union request"));
        }
        Ok(request)
    }
}

/// A bounded read-only request for one signer's durable drain progress at an
/// exact epoch (DR-0158). Never mutates, signs, ACKs, or claims readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainSignerProgressRequest {
    pub epoch: Epoch,
    pub signer: ValidatorId,
}

impl DrainSignerProgressRequest {
    pub fn encode(&self) -> Result<Vec<u8>, DrainWireError> {
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PROGRESS_REQUEST_TYPE_ID, VERSION);
        frame.field_u64(1, self.epoch.get())?;
        frame.field_bytes(2, self.signer.as_bytes().to_vec())?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DrainWireError> {
        if bytes.len() > MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES {
            return Err(DrainWireError::Invalid(
                "drain signer progress request bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(DRAIN_SIGNER_PROGRESS_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2])?;
        let signer_bytes: [u8; 32] = frame
            .required_field(2)?
            .try_into()
            .map_err(|_| DrainWireError::Invalid("drain signer progress validator length"))?;
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            signer: ValidatorId::new(signer_bytes),
        };
        if request.encode()?.as_slice() != bytes {
            return Err(DrainWireError::Invalid(
                "noncanonical drain signer progress request",
            ));
        }
        Ok(request)
    }
}

/// Bounded read-only signer-progress snapshot (DR-0158): the chain, epoch
/// and signer are repeated in the clear so a caller can fence its own local
/// pin before decoding any nested field; the signed vote, running
/// [`consensus::FrozenFrontierIdentity`], optional cursor, optional exact
/// staged page and complete flag are exact canonical protocol bytes, never
/// independently trusted by this decoder. This is a scheduling hint, never
/// authority: it creates no ACK, signature or application effect, and is not
/// a ready/`DrainSet` claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSignerProgressResponse {
    pub chain_id: String,
    pub epoch: Epoch,
    pub signer: ValidatorId,
    pub vote: Vec<u8>,
    pub confirmed_identity: Vec<u8>,
    pub cursor: Option<[u8; 32]>,
    pub staged_page: Option<Vec<u8>>,
    pub complete: bool,
}

impl DrainSignerProgressResponse {
    fn validate(&self) -> Result<(), DrainWireError> {
        if self.chain_id.is_empty()
            || self.chain_id.len() > MAX_DRAIN_SIGNER_PROGRESS_CHAIN_ID_BYTES
        {
            return Err(DrainWireError::Invalid(
                "drain signer progress chain id bound",
            ));
        }
        if self.vote.is_empty() || self.vote.len() > MAX_FRONTIER_VOTE_BYTES {
            return Err(DrainWireError::Invalid("drain signer progress vote bound"));
        }
        if self.confirmed_identity.is_empty()
            || self.confirmed_identity.len() > MAX_DRAIN_SIGNER_PROGRESS_IDENTITY_BYTES
        {
            return Err(DrainWireError::Invalid(
                "drain signer progress identity bound",
            ));
        }
        if self.cursor == Some([0; 32]) {
            return Err(DrainWireError::Invalid("zero drain signer progress cursor"));
        }
        if let Some(page) = &self.staged_page
            && (page.is_empty() || page.len() > MAX_FRONTIER_PAGE_BYTES)
        {
            return Err(DrainWireError::Invalid("drain signer progress page bound"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DrainWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID, VERSION);
        frame.field_str(1, &self.chain_id)?;
        frame.field_u64(2, self.epoch.get())?;
        frame.field_bytes(3, self.signer.as_bytes().to_vec())?;
        frame.field_bytes(4, self.vote.clone())?;
        frame.field_bytes(5, self.confirmed_identity.clone())?;
        frame.field_bytes(6, self.cursor.map_or_else(Vec::new, |value| value.to_vec()))?;
        frame.field_bytes(7, self.staged_page.clone().unwrap_or_default())?;
        frame.field_u16(8, u16::from(self.complete))?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DrainWireError> {
        if bytes.len() > MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES {
            return Err(DrainWireError::Invalid(
                "drain signer progress response bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
        let chain_str: &str = frame.required_str(1)?;
        if chain_str.is_empty() || chain_str.len() > MAX_DRAIN_SIGNER_PROGRESS_CHAIN_ID_BYTES {
            return Err(DrainWireError::Invalid(
                "drain signer progress chain id bound",
            ));
        }
        let signer_bytes: [u8; 32] = frame
            .required_field(3)?
            .try_into()
            .map_err(|_| DrainWireError::Invalid("drain signer progress validator length"))?;
        let cursor: Option<[u8; 32]> = match frame.required_field(6)? {
            [] => None,
            value => Some(
                value
                    .try_into()
                    .map_err(|_| DrainWireError::Invalid("drain signer progress cursor length"))?,
            ),
        };
        let staged_page: Option<Vec<u8>> = match frame.required_field(7)? {
            [] => None,
            value => Some(value.to_vec()),
        };
        let complete: bool = match frame.required_u16(8)? {
            0 => false,
            1 => true,
            _ => {
                return Err(DrainWireError::Invalid(
                    "drain signer progress complete flag",
                ));
            }
        };
        let response: Self = Self {
            chain_id: chain_str.to_owned(),
            epoch: Epoch::new(frame.required_u64(2)?),
            signer: ValidatorId::new(signer_bytes),
            vote: frame.required_field(4)?.to_vec(),
            confirmed_identity: frame.required_field(5)?.to_vec(),
            cursor,
            staged_page,
            complete,
        };
        response.validate()?;
        if response.encode()?.as_slice() != bytes {
            return Err(DrainWireError::Invalid(
                "noncanonical drain signer progress response",
            ));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::FrozenFrontierIdentity;
    use protocol_types::{
        AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ProtocolVersion, SignatureSchemeId,
    };

    fn vote(validator_byte: u8) -> FrozenFrontierVote {
        FrozenFrontierVote {
            identity: FrozenFrontierIdentity {
                chain_id: ChainId::new("drain-wire-test").unwrap(),
                protocol_version: ProtocolVersion::new(1),
                epoch: Epoch::new(7),
                domain: AtomicityDomainId::new([0x44; 32]).unwrap(),
                closure_request_id: [0x55; 32],
                closure_height: 9,
                entry_count: 0,
                entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
            },
            validator: ValidatorId::new([validator_byte; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![0x77; 64],
        }
    }

    #[test]
    fn signer_page_has_stable_bytes_and_refuses_noncanonical_inputs() {
        let request: DrainSignerPageRequest = DrainSignerPageRequest {
            epoch: Epoch::new(7),
            vote: vec![0xaa],
            page: vec![0xbb, 0xcc],
        };
        let encoded: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            encoded
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e52450ae1010003000100080000000700000000000000020001000000aa030002000000bbcc"
        );
        assert_eq!(
            DrainSignerPageRequest::decode(&encoded),
            Ok(request.clone())
        );
        assert!(
            DrainSignerPageRequest {
                vote: Vec::new(),
                ..request.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainSignerPageRequest {
                page: Vec::new(),
                ..request
            }
            .encode()
            .is_err()
        );
        let mut wrong_type: Vec<u8> = encoded.clone();
        wrong_type[4] ^= 1;
        assert!(DrainSignerPageRequest::decode(&wrong_type).is_err());
        assert!(
            DrainSignerPageRequest::decode(&vec![0; MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn member_confirm_round_trips_and_rejects_zero_and_wrong_lengths() {
        let request: DrainMemberConfirmRequest = DrainMemberConfirmRequest {
            epoch: Epoch::new(7),
            validator: ValidatorId::new([0x11; 32]),
            request_id: [0x22; 32],
        };
        let bytes: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            concat!(
                "534e52450be1010003000100080000000700000000000000",
                "02002000000011111111111111111111111111111111",
                "11111111111111111111111111111111",
                "03002000000022222222222222222222222222222222",
                "22222222222222222222222222222222"
            )
        );
        assert_eq!(DrainMemberConfirmRequest::decode(&bytes), Ok(request));
        assert!(
            DrainMemberConfirmRequest {
                request_id: [0; 32],
                ..request
            }
            .encode()
            .is_err()
        );
        let mut wrong_length: CanonicalStruct =
            CanonicalStruct::new(DRAIN_MEMBER_CONFIRM_REQUEST_TYPE_ID, VERSION);
        wrong_length.field_u64(1, 7).unwrap();
        wrong_length.field_bytes(2, vec![0x11; 31]).unwrap();
        wrong_length.field_bytes(3, vec![0x22; 32]).unwrap();
        assert!(DrainMemberConfirmRequest::decode(&wrong_length.finish().unwrap()).is_err());
    }

    #[test]
    fn union_request_has_stable_bytes_and_refuses_empty_or_unordered_votes() {
        let request: DrainUnionAdvanceRequest = DrainUnionAdvanceRequest {
            epoch: Epoch::new(7),
            votes: vec![vote(1), vote(2)],
        };
        let bytes: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e52450ce10100040001000800000007000000000000000200020000000200030061010000534e524537d0010004000100dd000000534e524536d00100080001000f000000647261696e2d776972652d746573740200040000000100000003000800000007000000000000000400200000004444444444444444444444444444444444444444444444444444444444444444050020000000555555555555555555555555555555555555555555555555555555555555555506000800000009000000000000000700080000000000000000000000080038000000534e5245030101000200010002000000010002002000000066666666666666666666666666666666666666666666666666666666666666660200200000000101010101010101010101010101010101010101010101010101010101010101030002000000010004004000000077777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777040061010000534e524537d0010004000100dd000000534e524536d00100080001000f000000647261696e2d776972652d746573740200040000000100000003000800000007000000000000000400200000004444444444444444444444444444444444444444444444444444444444444444050020000000555555555555555555555555555555555555555555555555555555555555555506000800000009000000000000000700080000000000000000000000080038000000534e5245030101000200010002000000010002002000000066666666666666666666666666666666666666666666666666666666666666660200200000000202020202020202020202020202020202020202020202020202020202020202030002000000010004004000000077777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
        );
        assert_eq!(
            DrainUnionAdvanceRequest::decode(&bytes),
            Ok(request.clone())
        );
        assert!(
            DrainUnionAdvanceRequest {
                votes: Vec::new(),
                ..request.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainUnionAdvanceRequest {
                votes: vec![request.votes[1].clone(), request.votes[0].clone()],
                ..request
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn signer_progress_request_has_stable_bytes_and_refuses_noncanonical_inputs() {
        let request: DrainSignerProgressRequest = DrainSignerProgressRequest {
            epoch: Epoch::new(7),
            signer: ValidatorId::new([0x11; 32]),
        };
        let encoded: Vec<u8> = request.encode().unwrap();

        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"SNRE");
        expected.extend_from_slice(&DRAIN_SIGNER_PROGRESS_REQUEST_TYPE_ID.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&8u32.to_le_bytes());
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&32u32.to_le_bytes());
        expected.extend_from_slice(&[0x11u8; 32]);
        assert_eq!(encoded, expected);

        assert_eq!(
            DrainSignerProgressRequest::decode(&encoded).unwrap(),
            request
        );

        let mut wrong_type: Vec<u8> = encoded.clone();
        wrong_type[4] ^= 1;
        assert!(DrainSignerProgressRequest::decode(&wrong_type).is_err());
        assert!(
            DrainSignerProgressRequest::decode(&[0u8; MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES + 1])
                .is_err()
        );

        // A truncated validator id is rejected before any semantic check.
        let mut short_signer: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PROGRESS_REQUEST_TYPE_ID, VERSION);
        short_signer.field_u64(1, 7).unwrap();
        short_signer.field_bytes(2, vec![0x11; 31]).unwrap();
        assert!(DrainSignerProgressRequest::decode(&short_signer.finish().unwrap()).is_err());
    }

    /// Stable `0xE10E/v1` [`DrainSignerProgressResponse`] vector (DR-0158).
    /// The chain/epoch/signer are repeated in the clear; the nested vote,
    /// running identity and staged page are opaque bounded bytes this
    /// decoder never interprets.
    #[test]
    fn signer_progress_response_has_stable_bytes_and_refuses_invalid_fields() {
        let response: DrainSignerProgressResponse = DrainSignerProgressResponse {
            chain_id: "sr".to_owned(),
            epoch: Epoch::new(7),
            signer: ValidatorId::new([0x11; 32]),
            vote: vec![0xaa, 0xbb],
            confirmed_identity: vec![0xcc],
            cursor: Some([0x22; 32]),
            staged_page: Some(vec![0xdd, 0xee]),
            complete: true,
        };
        let encoded: Vec<u8> = response.encode().unwrap();

        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"SNRE");
        expected.extend_from_slice(&DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&8u16.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(b"sr");
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&8u32.to_le_bytes());
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&3u16.to_le_bytes());
        expected.extend_from_slice(&32u32.to_le_bytes());
        expected.extend_from_slice(&[0x11u8; 32]);
        expected.extend_from_slice(&4u16.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0xaa, 0xbb]);
        expected.extend_from_slice(&5u16.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0xcc]);
        expected.extend_from_slice(&6u16.to_le_bytes());
        expected.extend_from_slice(&32u32.to_le_bytes());
        expected.extend_from_slice(&[0x22u8; 32]);
        expected.extend_from_slice(&7u16.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0xdd, 0xee]);
        expected.extend_from_slice(&8u16.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        assert_eq!(encoded, expected);
        assert_eq!(
            DrainSignerProgressResponse::decode(&encoded).unwrap(),
            response
        );

        // The pristine/no-cursor/no-staged-page/incomplete shape round-trips
        // to a genuinely different encoding, never silently coerced to the
        // staged shape above.
        let pristine: DrainSignerProgressResponse = DrainSignerProgressResponse {
            cursor: None,
            staged_page: None,
            complete: false,
            ..response.clone()
        };
        let pristine_encoded: Vec<u8> = pristine.encode().unwrap();
        assert_eq!(
            DrainSignerProgressResponse::decode(&pristine_encoded).unwrap(),
            pristine
        );
        assert_ne!(pristine_encoded, encoded);

        assert!(
            DrainSignerProgressResponse {
                chain_id: String::new(),
                ..response.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainSignerProgressResponse {
                vote: Vec::new(),
                ..response.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainSignerProgressResponse {
                confirmed_identity: Vec::new(),
                ..response.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainSignerProgressResponse {
                cursor: Some([0; 32]),
                ..response.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            DrainSignerProgressResponse {
                staged_page: Some(Vec::new()),
                ..response.clone()
            }
            .encode()
            .is_err()
        );

        let mut wrong_type: Vec<u8> = encoded.clone();
        wrong_type[4] ^= 1;
        assert!(DrainSignerProgressResponse::decode(&wrong_type).is_err());
        assert!(
            DrainSignerProgressResponse::decode(&vec![
                0u8;
                MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES + 1
            ])
            .is_err()
        );

        // A malformed response: an out-of-range complete flag is never
        // silently coerced to a boolean.
        let mut malformed_complete: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID, VERSION);
        malformed_complete.field_str(1, "sr").unwrap();
        malformed_complete.field_u64(2, 7).unwrap();
        malformed_complete.field_bytes(3, vec![0x11; 32]).unwrap();
        malformed_complete.field_bytes(4, vec![0xaa, 0xbb]).unwrap();
        malformed_complete.field_bytes(5, vec![0xcc]).unwrap();
        malformed_complete.field_bytes(6, Vec::new()).unwrap();
        malformed_complete.field_bytes(7, Vec::new()).unwrap();
        malformed_complete.field_u16(8, 2).unwrap();
        assert!(
            DrainSignerProgressResponse::decode(&malformed_complete.finish().unwrap()).is_err()
        );

        // A malformed context: a truncated signer field is rejected before
        // any nested vote/page is even inspected.
        let mut short_signer: CanonicalStruct =
            CanonicalStruct::new(DRAIN_SIGNER_PROGRESS_RESPONSE_TYPE_ID, VERSION);
        short_signer.field_str(1, "sr").unwrap();
        short_signer.field_u64(2, 7).unwrap();
        short_signer.field_bytes(3, vec![0x11; 31]).unwrap();
        short_signer.field_bytes(4, vec![0xaa, 0xbb]).unwrap();
        short_signer.field_bytes(5, vec![0xcc]).unwrap();
        short_signer.field_bytes(6, Vec::new()).unwrap();
        short_signer.field_bytes(7, Vec::new()).unwrap();
        short_signer.field_u16(8, 0).unwrap();
        assert!(DrainSignerProgressResponse::decode(&short_signer.finish().unwrap()).is_err());
    }
}
