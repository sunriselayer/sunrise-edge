//! Bounded canonical transport for the retained-but-not-prepared publication
//! source route (DR-0154).
//!
//! The request carries only what a replica needs to look up its own already
//! durably retained record: the pinned active epoch and the signed-frontier
//! request id. It is never itself authority -- the server independently
//! reconstructs and re-verifies the complete retained
//! `consensus::bundle::PublicationBundle` before returning it, and a caller
//! must independently re-verify that returned bundle (including its signed
//! intent and certificate) against its own locally pinned context and
//! validator set before trusting it. The response body is the existing
//! canonical `0xD035` bundle frame verbatim, exactly as
//! [`crate::FASTVOTE_PUBLICATION_SOURCE_PATH`] already returns for the
//! prepared-side source route: no new envelope type is introduced for it.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use protocol_types::Epoch;
use std::error::Error;
use std::fmt;

/// A prepared-or-not replica returns the exact verified retained full
/// publication bundle for a genuine signed-frontier request id and the
/// caller's pinned active epoch. Its request body is
/// [`RetainedPublicationSourceRequest`]; its response body is the existing
/// canonical `consensus::bundle::PublicationBundle` frame, not a new
/// envelope.
pub const FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH: &str =
    "/v1/fastvote/publications/retained-source";
pub const RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID: u16 = 0xE109;
const ENCODING_VERSION: u16 = 1;

/// The whole frame is checked before canonical decoding or allocation.
pub const MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES: usize = 128;

/// A bounded, strictly canonical request for one replica's retained
/// publication bundle at one pinned active epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedPublicationSourceRequest {
    /// The caller's locally pinned active epoch. The server refuses a
    /// request naming any other epoch rather than silently repinning it.
    pub epoch: Epoch,
    /// The exact request id one already independently verified
    /// signed-frontier entry names.
    pub request_id: [u8; 32],
}

/// Size, bound or canonical framing error for
/// [`RetainedPublicationSourceRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedPublicationSourceRequestError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// The whole request exceeded its bound.
    RequestTooLarge(usize),
    /// The request id was the reserved all-zero value.
    ZeroRequestId,
    /// The request id field was not exactly 32 bytes.
    InvalidRequestIdLength(usize),
    /// A decoded frame was not its unique canonical re-encoding.
    NonCanonicalEncoding,
}

impl fmt::Display for RetainedPublicationSourceRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::RequestTooLarge(length) => write!(
                f,
                "retained publication source request is {length} bytes, maximum is {MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES}"
            ),
            Self::ZeroRequestId => f.write_str("retained publication source request id is zero"),
            Self::InvalidRequestIdLength(length) => write!(
                f,
                "retained publication source request id is {length} bytes, must be 32"
            ),
            Self::NonCanonicalEncoding => {
                f.write_str("retained publication source request is non-canonical")
            }
        }
    }
}

impl Error for RetainedPublicationSourceRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::RequestTooLarge(_)
            | Self::ZeroRequestId
            | Self::InvalidRequestIdLength(_)
            | Self::NonCanonicalEncoding => None,
        }
    }
}

impl From<CanonicalEncodingError> for RetainedPublicationSourceRequestError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for RetainedPublicationSourceRequestError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl RetainedPublicationSourceRequest {
    fn validate(&self) -> Result<(), RetainedPublicationSourceRequestError> {
        if self.request_id == [0; 32] {
            return Err(RetainedPublicationSourceRequestError::ZeroRequestId);
        }
        Ok(())
    }

    /// Encodes this request as `0xE109/v1`.
    pub fn encode(&self) -> Result<Vec<u8>, RetainedPublicationSourceRequestError> {
        self.validate()?;
        let mut frame: CanonicalStruct = CanonicalStruct::new(
            RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID,
            ENCODING_VERSION,
        );
        frame.field_u64(1, self.epoch.get())?;
        frame.field_bytes(2, self.request_id.to_vec())?;
        Ok(frame.finish()?)
    }

    /// Strictly decodes `0xE109/v1`, bounding bytes before parsing.
    pub fn decode(bytes: &[u8]) -> Result<Self, RetainedPublicationSourceRequestError> {
        if bytes.len() > MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES {
            return Err(RetainedPublicationSourceRequestError::RequestTooLarge(
                bytes.len(),
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2])?;
        let request_field: &[u8] = frame.required_field(2)?;
        let request_id: [u8; 32] = request_field.try_into().map_err(|_| {
            RetainedPublicationSourceRequestError::InvalidRequestIdLength(request_field.len())
        })?;
        let request: Self = Self {
            epoch: Epoch::new(frame.required_u64(1)?),
            request_id,
        };
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(RetainedPublicationSourceRequestError::NonCanonicalEncoding);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RetainedPublicationSourceRequest {
        RetainedPublicationSourceRequest {
            epoch: Epoch::new(7),
            request_id: [0x42; 32],
        }
    }

    #[test]
    fn round_trip_and_independent_stable_vector() {
        let request: RetainedPublicationSourceRequest = sample();
        let encoded: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            encoded
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e524509e10100020001000800000007000000000000000200200000004242424242424242424242424242424242424242424242424242424242424242"
        );
        assert_eq!(
            RetainedPublicationSourceRequest::decode(&encoded),
            Ok(request)
        );
    }

    #[test]
    fn parent_independent_locator_vector_and_closed_fields() {
        let request: RetainedPublicationSourceRequest = RetainedPublicationSourceRequest {
            epoch: Epoch::new(8),
            request_id: [7; 32],
        };
        let bytes: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e524509e10100020001000800000008000000000000000200200000000707070707070707070707070707070707070707070707070707070707070707"
        );
        assert_eq!(
            RetainedPublicationSourceRequest::decode(&bytes).unwrap(),
            request
        );
        let mut unknown: CanonicalStruct =
            CanonicalStruct::new(RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID, 1);
        unknown.field_u64(1, 8).unwrap();
        unknown.field_bytes(2, vec![7; 32]).unwrap();
        unknown.field_u16(3, 1).unwrap();
        assert!(RetainedPublicationSourceRequest::decode(&unknown.finish().unwrap()).is_err());
    }

    #[test]
    fn refuses_zero_request_id() {
        let request: RetainedPublicationSourceRequest = RetainedPublicationSourceRequest {
            request_id: [0; 32],
            ..sample()
        };
        assert_eq!(
            request.encode(),
            Err(RetainedPublicationSourceRequestError::ZeroRequestId)
        );
    }

    #[test]
    fn refuses_oversized_request() {
        let oversized: Vec<u8> = vec![0; MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES + 1];
        assert!(matches!(
            RetainedPublicationSourceRequest::decode(&oversized),
            Err(RetainedPublicationSourceRequestError::RequestTooLarge(_))
        ));
    }

    #[test]
    fn refuses_wrong_type_version_missing_or_unknown_field() {
        let mut bytes: Vec<u8> = sample().encode().unwrap();
        bytes[4] ^= 0xff;
        assert!(RetainedPublicationSourceRequest::decode(&bytes).is_err());
        bytes = sample().encode().unwrap();
        bytes[6] ^= 0xff;
        assert!(RetainedPublicationSourceRequest::decode(&bytes).is_err());

        let mut missing: CanonicalStruct = CanonicalStruct::new(
            RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID,
            ENCODING_VERSION,
        );
        missing.field_u64(1, 7).unwrap();
        assert!(matches!(
            RetainedPublicationSourceRequest::decode(&missing.finish().unwrap()),
            Err(RetainedPublicationSourceRequestError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(2)
            ))
        ));

        let mut unknown: CanonicalStruct = CanonicalStruct::new(
            RETAINED_PUBLICATION_SOURCE_REQUEST_TYPE_ID,
            ENCODING_VERSION,
        );
        unknown.field_u64(1, 7).unwrap();
        unknown.field_bytes(2, vec![0x42; 32]).unwrap();
        unknown.field_bytes(3, vec![0x01]).unwrap();
        assert!(matches!(
            RetainedPublicationSourceRequest::decode(&unknown.finish().unwrap()),
            Err(RetainedPublicationSourceRequestError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }
}
