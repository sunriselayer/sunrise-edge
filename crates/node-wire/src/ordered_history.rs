//! Bounded transport for DR-0169 ordered history. Payload descriptors and
//! summaries retain the core codecs; this module frames only request shapes
//! and chunk responses.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_CHUNK_BYTES, MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    OrderedHistoryComponentKind, OrderedHistoryIdentity, decode_ordered_history_identity,
    encode_ordered_history_identity,
};
use protocol_types::Digest32;
use std::{error::Error, fmt};

pub const ORDERED_HISTORY_SUMMARY_PATH: &str = "/v1/ordered-economics/history/summary";
pub const ORDERED_HISTORY_HEIGHT_PATH: &str = "/v1/ordered-economics/history/height";
pub const ORDERED_HISTORY_COMPONENT_PATH: &str = "/v1/ordered-economics/history/component";
pub const ORDERED_HISTORY_HEIGHT_REQUEST_TYPE_ID: u16 = 0xE110;
pub const ORDERED_HISTORY_COMPONENT_REQUEST_TYPE_ID: u16 = 0xE111;
pub const ORDERED_HISTORY_CHUNK_RESPONSE_TYPE_ID: u16 = 0xE112;
pub const MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES: usize =
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES + 64;
pub const MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES: usize =
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES + 128;
pub const MAX_ORDERED_HISTORY_CHUNK_RESPONSE_BYTES: usize = MAX_ORDERED_HISTORY_CHUNK_BYTES + 64;
const VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedHistoryWireError {
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Invalid(&'static str),
}

impl fmt::Display for OrderedHistoryWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}
impl Error for OrderedHistoryWireError {}
impl From<CanonicalEncodingError> for OrderedHistoryWireError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Encoding(value)
    }
}
impl From<CanonicalDecodingError> for OrderedHistoryWireError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Decoding(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryHeightRequest {
    pub identity: OrderedHistoryIdentity,
    pub height: u64,
}

impl OrderedHistoryHeightRequest {
    fn validate(&self) -> Result<(), OrderedHistoryWireError> {
        if self.height == 0 || self.height > self.identity.through_height {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history height outside fixed target",
            ));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, OrderedHistoryWireError> {
        self.validate()?;
        let mut frame = CanonicalStruct::new(ORDERED_HISTORY_HEIGHT_REQUEST_TYPE_ID, VERSION);
        frame.field_bytes(
            1,
            encode_ordered_history_identity(&self.identity)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid history identity"))?,
        )?;
        frame.field_u64(2, self.height)?;
        Ok(frame.finish()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, OrderedHistoryWireError> {
        if bytes.len() > MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history height request bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(ORDERED_HISTORY_HEIGHT_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2])?;
        let value = Self {
            identity: decode_ordered_history_identity(frame.required_field(1)?)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid history identity"))?,
            height: frame.required_u64(2)?,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(OrderedHistoryWireError::Invalid(
                "noncanonical ordered history height request",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryComponentRequest {
    pub identity: OrderedHistoryIdentity,
    pub height: u64,
    pub descriptor_digest: Digest32,
    pub kind: OrderedHistoryComponentKind,
    pub offset: u64,
    pub limit: u32,
}
impl OrderedHistoryComponentRequest {
    fn validate(&self) -> Result<(), OrderedHistoryWireError> {
        if self.height == 0 || self.height > self.identity.through_height {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history height outside fixed target",
            ));
        }
        if self.limit == 0 || self.limit as usize > MAX_ORDERED_HISTORY_CHUNK_BYTES {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history chunk limit",
            ));
        }
        if self.offset >= self.kind.max_bytes() as u64 {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history chunk offset",
            ));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, OrderedHistoryWireError> {
        self.validate()?;
        let mut frame = CanonicalStruct::new(ORDERED_HISTORY_COMPONENT_REQUEST_TYPE_ID, VERSION);
        frame.field_bytes(
            1,
            encode_ordered_history_identity(&self.identity)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid history identity"))?,
        )?;
        frame.field_u64(2, self.height)?;
        frame.field_bytes(
            3,
            canonical_encoding::encode_digest32(&self.descriptor_digest)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid descriptor digest"))?,
        )?;
        frame.field_u16(4, self.kind as u16)?;
        frame.field_u64(5, self.offset)?;
        frame.field_u32(6, self.limit)?;
        Ok(frame.finish()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, OrderedHistoryWireError> {
        if bytes.len() > MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history component request bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(ORDERED_HISTORY_COMPONENT_REQUEST_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
        let value = Self {
            identity: decode_ordered_history_identity(frame.required_field(1)?)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid history identity"))?,
            height: frame.required_u64(2)?,
            descriptor_digest: canonical_encoding::decode_digest32(frame.required_field(3)?)
                .map_err(|_| OrderedHistoryWireError::Invalid("invalid descriptor digest"))?,
            kind: OrderedHistoryComponentKind::from_wire(frame.required_u16(4)?)
                .map_err(|_| OrderedHistoryWireError::Invalid("unknown history component kind"))?,
            offset: frame.required_u64(5)?,
            limit: frame.required_u32(6)?,
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(OrderedHistoryWireError::Invalid(
                "noncanonical ordered history component request",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryChunkResponse {
    pub offset: u64,
    pub total_length: u64,
    pub chunk_bytes: Vec<u8>,
}
impl OrderedHistoryChunkResponse {
    fn validate(&self) -> Result<(), OrderedHistoryWireError> {
        if self.total_length == 0
            || self.offset >= self.total_length
            || self.chunk_bytes.is_empty()
            || self.chunk_bytes.len() > MAX_ORDERED_HISTORY_CHUNK_BYTES
            || self.chunk_bytes.len() as u64 > self.total_length - self.offset
        {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history chunk response bounds",
            ));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, OrderedHistoryWireError> {
        self.validate()?;
        let mut frame = CanonicalStruct::new(ORDERED_HISTORY_CHUNK_RESPONSE_TYPE_ID, VERSION);
        frame.field_u64(1, self.offset)?;
        frame.field_u64(2, self.total_length)?;
        frame.field_bytes(3, self.chunk_bytes.clone())?;
        Ok(frame.finish()?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, OrderedHistoryWireError> {
        if bytes.len() > MAX_ORDERED_HISTORY_CHUNK_RESPONSE_BYTES {
            return Err(OrderedHistoryWireError::Invalid(
                "ordered history chunk response bound",
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(ORDERED_HISTORY_CHUNK_RESPONSE_TYPE_ID)?;
        frame.require_version(VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let value = Self {
            offset: frame.required_u64(1)?,
            total_length: frame.required_u64(2)?,
            chunk_bytes: frame.required_field(3)?.to_vec(),
        };
        value.validate()?;
        if value.encode()?.as_slice() != bytes {
            return Err(OrderedHistoryWireError::Invalid(
                "noncanonical ordered history chunk response",
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, ProtocolVersion};

    fn identity() -> OrderedHistoryIdentity {
        OrderedHistoryIdentity {
            context: execution::publication::PublicationContext::new(
                ChainId::new("history-wire-test").unwrap(),
                ProtocolVersion::new(4),
                Epoch::new(9),
            )
            .unwrap(),
            domain: AtomicityDomainId::new([1; 32]).unwrap(),
            genesis_digest: Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
            anchor: Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
            through_height: 5,
            through_view: 8,
            through_digest: Digest32::new(HashAlgorithmId::Sha2_256, [4; 32]),
        }
    }

    #[test]
    fn height_and_component_requests_are_closed_and_round_trip() {
        let height = OrderedHistoryHeightRequest {
            identity: identity(),
            height: 3,
        };
        let height_bytes = height.encode().unwrap();
        assert_eq!(
            OrderedHistoryHeightRequest::decode(&height_bytes).unwrap(),
            height
        );
        let component = OrderedHistoryComponentRequest {
            identity: identity(),
            height: 3,
            descriptor_digest: Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
            kind: OrderedHistoryComponentKind::CommitProof,
            offset: 64,
            limit: 1024,
        };
        let component_bytes = component.encode().unwrap();
        assert_eq!(
            OrderedHistoryComponentRequest::decode(&component_bytes).unwrap(),
            component
        );
        assert!(
            OrderedHistoryHeightRequest {
                height: 6,
                ..height
            }
            .encode()
            .is_err()
        );
        assert!(
            OrderedHistoryComponentRequest {
                limit: 0,
                ..component
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn chunk_response_binds_requested_range_and_is_canonical() {
        let response = OrderedHistoryChunkResponse {
            offset: 1024,
            total_length: 2048,
            chunk_bytes: vec![7; 1024],
        };
        let bytes = response.encode().unwrap();
        assert_eq!(
            OrderedHistoryChunkResponse::decode(&bytes).unwrap(),
            response
        );
        assert!(
            OrderedHistoryChunkResponse {
                offset: 2048,
                ..response
            }
            .encode()
            .is_err()
        );
    }
}
