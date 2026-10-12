//! Bounded canonical transport for a signed frozen-frontier page.
//!
//! The response is only an envelope. Its nested vote and page must be decoded
//! and verified by `consensus::FrozenFrontierPageVerifier`; transport and a
//! valid page frame are never handoff authority.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use protocol_types::Epoch;
use std::error::Error;
use std::fmt;

pub const FASTVOTE_FROZEN_FRONTIER_PAGE_PATH: &str = "/v1/fastvote/frontier/page";
/// One bounded CAS-fenced local frontier step after committed Freeze. A
/// confirmed final step returns the already retained canonical frontier vote.
pub const FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH: &str = "/v1/fastvote/frontier/advance";
pub const FROZEN_FRONTIER_PAGE_REQUEST_TYPE_ID: u16 = 0xE107;
pub const FROZEN_FRONTIER_PAGE_RESPONSE_TYPE_ID: u16 = 0xE108;
const VERSION: u16 = 1;
const _: () = assert!(consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES <= u16::MAX as usize);
pub const MAX_FRONTIER_PAGE_LIMIT: u16 = consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES as u16;
pub const MAX_FRONTIER_PAGE_REQUEST_BYTES: usize = 128;
pub const MAX_FRONTIER_VOTE_BYTES: usize = consensus::MAX_FROZEN_FRONTIER_VOTE_BYTES;
pub const MAX_FRONTIER_PAGE_BYTES: usize = consensus::MAX_FROZEN_FRONTIER_PAGE_BYTES;
pub const MAX_FRONTIER_PAGE_RESPONSE_BYTES: usize =
    MAX_FRONTIER_VOTE_BYTES + MAX_FRONTIER_PAGE_BYTES + 64;

/// A bounded request to continue an exact epoch's immutable local frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenFrontierPageRequest {
    pub epoch: Epoch,
    pub after_request_id: Option<[u8; 32]>,
    pub limit: u16,
}

/// Exact canonical nested signed vote and page bytes, neither independently
/// trusted by the transport decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenFrontierPageResponse {
    pub vote: Vec<u8>,
    pub page: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrozenFrontierWireError {
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Invalid(&'static str),
}

impl fmt::Display for FrozenFrontierWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl Error for FrozenFrontierWireError {}

impl From<CanonicalEncodingError> for FrozenFrontierWireError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Encoding(value)
    }
}

impl From<CanonicalDecodingError> for FrozenFrontierWireError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Decoding(value)
    }
}

impl FrozenFrontierPageRequest {
    fn validate(&self) -> Result<(), FrozenFrontierWireError> {
        if self.limit == 0 || self.limit > MAX_FRONTIER_PAGE_LIMIT {
            return Err(FrozenFrontierWireError::Invalid("frontier page limit"));
        }
        if self.after_request_id == Some([0; 32]) {
            return Err(FrozenFrontierWireError::Invalid("zero frontier cursor"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrozenFrontierWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(FROZEN_FRONTIER_PAGE_REQUEST_TYPE_ID, VERSION);
        frame.field_u64(1, self.epoch.get())?;
        frame.field_bytes(
            2,
            self.after_request_id
                .map_or_else(Vec::new, |value| value.to_vec()),
        )?;
        frame.field_u16(3, self.limit)?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrozenFrontierWireError> {
        if bytes.len() > MAX_FRONTIER_PAGE_REQUEST_BYTES {
            return Err(FrozenFrontierWireError::Invalid("frontier request bound"));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(FROZEN_FRONTIER_PAGE_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let after_request_id: Option<[u8; 32]> = match frame.required_field(2)? {
            [] => None,
            value => Some(
                value
                    .try_into()
                    .map_err(|_| FrozenFrontierWireError::Invalid("frontier cursor length"))?,
            ),
        };
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            after_request_id,
            limit: frame.required_u16(3)?,
        };
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(FrozenFrontierWireError::Invalid(
                "noncanonical frontier request",
            ));
        }
        Ok(request)
    }
}

impl FrozenFrontierPageResponse {
    fn validate(&self) -> Result<(), FrozenFrontierWireError> {
        if self.vote.is_empty() || self.vote.len() > MAX_FRONTIER_VOTE_BYTES {
            return Err(FrozenFrontierWireError::Invalid("frontier vote bound"));
        }
        if self.page.is_empty() || self.page.len() > MAX_FRONTIER_PAGE_BYTES {
            return Err(FrozenFrontierWireError::Invalid("frontier page bound"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrozenFrontierWireError> {
        self.validate()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(FROZEN_FRONTIER_PAGE_RESPONSE_TYPE_ID, VERSION);
        frame.field_bytes(1, self.vote.clone())?;
        frame.field_bytes(2, self.page.clone())?;
        Ok(frame.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrozenFrontierWireError> {
        if bytes.len() > MAX_FRONTIER_PAGE_RESPONSE_BYTES {
            return Err(FrozenFrontierWireError::Invalid("frontier response bound"));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(FROZEN_FRONTIER_PAGE_RESPONSE_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2])?;
        let response: Self = Self {
            vote: frame.required_field(1)?.to_vec(),
            page: frame.required_field(2)?.to_vec(),
        };
        response.validate()?;
        if response.encode()?.as_slice() != bytes {
            return Err(FrozenFrontierWireError::Invalid(
                "noncanonical frontier response",
            ));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vector_and_bounds() {
        let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(8),
            after_request_id: None,
            limit: 2,
        };
        let encoded: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            encoded
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e524507e10100030001000800000008000000000000000200000000000300020000000200"
        );
        assert_eq!(
            FrozenFrontierPageRequest::decode(&encoded).unwrap(),
            request
        );
        assert!(
            FrozenFrontierPageRequest {
                limit: 0,
                ..request.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            FrozenFrontierPageRequest {
                limit: 129,
                ..request.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            FrozenFrontierPageRequest {
                after_request_id: Some([0; 32]),
                ..request
            }
            .encode()
            .is_err()
        );
        let mut wrong_type: Vec<u8> = encoded.clone();
        wrong_type[4] ^= 1;
        assert!(FrozenFrontierPageRequest::decode(&wrong_type).is_err());
        assert!(
            FrozenFrontierPageRequest::decode(&[0; MAX_FRONTIER_PAGE_REQUEST_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn response_vector_and_bounds() {
        let response: FrozenFrontierPageResponse = FrozenFrontierPageResponse {
            vote: vec![0xaa, 0xbb],
            page: vec![0x11],
        };
        let encoded: Vec<u8> = response.encode().unwrap();
        assert_eq!(
            encoded
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e524508e101000200010002000000aabb02000100000011"
        );
        assert_eq!(
            FrozenFrontierPageResponse::decode(&encoded).unwrap(),
            response
        );
        assert!(
            FrozenFrontierPageResponse {
                vote: Vec::new(),
                ..response.clone()
            }
            .encode()
            .is_err()
        );
        assert!(
            FrozenFrontierPageResponse {
                page: Vec::new(),
                ..response
            }
            .encode()
            .is_err()
        );
        assert!(
            FrozenFrontierPageResponse::decode(&[0; MAX_FRONTIER_PAGE_RESPONSE_BYTES + 1]).is_err()
        );
    }

    #[test]
    fn frontier_wire_caps_match_literals_and_owner() {
        let vote_cap: usize = 8_192;
        let page_cap: usize = 524_288;
        let entry_cap: u16 = 128;
        let request_cap: usize = 128;
        let response_cap: usize = 532_544;
        assert_eq!(MAX_FRONTIER_VOTE_BYTES, vote_cap);
        assert_eq!(MAX_FRONTIER_PAGE_BYTES, page_cap);
        assert_eq!(MAX_FRONTIER_PAGE_LIMIT, entry_cap);
        assert_eq!(MAX_FRONTIER_PAGE_REQUEST_BYTES, request_cap);
        assert_eq!(MAX_FRONTIER_PAGE_RESPONSE_BYTES, response_cap);
        assert_eq!(
            MAX_FRONTIER_VOTE_BYTES,
            consensus::MAX_FROZEN_FRONTIER_VOTE_BYTES
        );
        assert_eq!(
            MAX_FRONTIER_PAGE_BYTES,
            consensus::MAX_FROZEN_FRONTIER_PAGE_BYTES
        );
        assert_eq!(
            usize::from(MAX_FRONTIER_PAGE_LIMIT),
            consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES
        );
        assert_eq!(
            MAX_FRONTIER_PAGE_RESPONSE_BYTES,
            MAX_FRONTIER_VOTE_BYTES + MAX_FRONTIER_PAGE_BYTES + 64
        );
    }

    #[test]
    fn frontier_request_literal_limit_boundary() {
        let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(8),
            after_request_id: None,
            limit: 128,
        };
        let encoded: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            FrozenFrontierPageRequest::decode(&encoded).unwrap(),
            request
        );
        let excessive_limit: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            epoch: Epoch::new(8),
            after_request_id: None,
            limit: 129,
        };
        assert_eq!(
            excessive_limit.encode(),
            Err(FrozenFrontierWireError::Invalid("frontier page limit"))
        );

        // This complete literal frame has an otherwise valid empty cursor.
        let mut limit_frame: CanonicalStruct = CanonicalStruct::new(0xE107, 1);
        limit_frame.field_u64(1, 8).unwrap();
        limit_frame.field_bytes(2, Vec::<u8>::new()).unwrap();
        limit_frame.field_u16(3, 129).unwrap();
        let excessive_limit_bytes: Vec<u8> = limit_frame.finish().unwrap();
        assert_eq!(
            FrozenFrontierPageRequest::decode(&excessive_limit_bytes),
            Err(FrozenFrontierWireError::Invalid("frontier page limit"))
        );

        let excessive: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
            after_request_id: Some([0u8; 32]),
            limit: 129,
            ..request
        };
        assert_eq!(
            excessive.encode(),
            Err(FrozenFrontierWireError::Invalid("frontier page limit"))
        );

        // Type/version/fields and the 32-byte cursor length are valid. Only
        // after those checks does limit refusal precede zero-cursor refusal.
        let mut frame: CanonicalStruct = CanonicalStruct::new(0xE107, 1);
        frame.field_u64(1, 8).unwrap();
        frame.field_bytes(2, vec![0u8; 32]).unwrap();
        frame.field_u16(3, 129).unwrap();
        let excessive_bytes: Vec<u8> = frame.finish().unwrap();
        assert_eq!(
            FrozenFrontierPageRequest::decode(&excessive_bytes),
            Err(FrozenFrontierWireError::Invalid("frontier page limit"))
        );
    }

    #[test]
    fn frontier_request_literal_outer_boundary() {
        let at_cap: Vec<u8> = vec![0u8; 128];
        assert!(matches!(
            FrozenFrontierPageRequest::decode(&at_cap),
            Err(FrozenFrontierWireError::Decoding(_))
        ));
        let above_cap: Vec<u8> = vec![0u8; 129];
        assert_eq!(
            FrozenFrontierPageRequest::decode(&above_cap),
            Err(FrozenFrontierWireError::Invalid("frontier request bound"))
        );
    }

    #[test]
    fn frontier_response_literal_component_boundaries() {
        // These are opaque wire-envelope fixtures, not valid consensus
        // votes/pages or authenticated frontier capacity evidence.
        let response: FrozenFrontierPageResponse = FrozenFrontierPageResponse {
            vote: vec![0u8; 8_192],
            page: vec![0u8; 524_288],
        };
        let encoded: Vec<u8> = response.encode().unwrap();
        assert_eq!(encoded.len(), 532_502);
        assert_eq!(
            FrozenFrontierPageResponse::decode(&encoded).unwrap(),
            response
        );

        let frame_bytes: fn(&[u8], &[u8]) -> Vec<u8> = |vote: &[u8], page: &[u8]| -> Vec<u8> {
            let mut frame: CanonicalStruct = CanonicalStruct::new(0xE108, 1);
            frame.field_bytes(1, vote.to_vec()).unwrap();
            frame.field_bytes(2, page.to_vec()).unwrap();
            frame.finish().unwrap()
        };
        let cases: [(usize, usize, &'static str, usize); 3] = [
            (8_193, 524_288, "frontier vote bound", 532_503),
            (8_192, 524_289, "frontier page bound", 532_503),
            (8_193, 524_289, "frontier vote bound", 532_504),
        ];
        for (vote_length, page_length, reason, encoded_length) in cases {
            let excessive: FrozenFrontierPageResponse = FrozenFrontierPageResponse {
                vote: vec![0u8; vote_length],
                page: vec![0u8; page_length],
            };
            assert_eq!(
                excessive.encode(),
                Err(FrozenFrontierWireError::Invalid(reason))
            );
            let excessive_bytes: Vec<u8> = frame_bytes(&excessive.vote, &excessive.page);
            assert_eq!(excessive_bytes.len(), encoded_length);
            assert!(excessive_bytes.len() < 532_544);
            assert_eq!(
                FrozenFrontierPageResponse::decode(&excessive_bytes),
                Err(FrozenFrontierWireError::Invalid(reason))
            );
        }
    }

    #[test]
    fn frontier_response_literal_outer_boundary() {
        let at_cap: Vec<u8> = vec![0u8; 532_544];
        assert!(matches!(
            FrozenFrontierPageResponse::decode(&at_cap),
            Err(FrozenFrontierWireError::Decoding(_))
        ));
        let above_cap: Vec<u8> = vec![0u8; 532_545];
        assert_eq!(
            FrozenFrontierPageResponse::decode(&above_cap),
            Err(FrozenFrontierWireError::Invalid("frontier response bound"))
        );
    }
}
