//! Canonical transport for a publication-gated FastVote application.
//!
//! This is a new route and frame, not a reinterpretation of historical
//! [`crate::FastVoteApplyRequest`] `0x6439/v1`. The server must select the
//! publication requirement from its signed genesis profile, never from this
//! request's choice of route or frame.

use crate::{MAX_FASTVOTE_CERTIFICATE_BYTES, MAX_SIGNED_PAID_INTENT_BYTES};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use std::error::Error;

/// Canonical request type for a FastVote application carrying quorum-retention
/// authority. Allocated from the HTTP-wire `0xE1xx` namespace.
pub const FASTVOTE_PUBLISHED_APPLY_REQUEST_TYPE_ID: u16 = 0xE106;
const ENCODING_VERSION: u16 = 1;

/// A prepared replica returns the full publication bundle for a genuine
/// certificate on this certified-only route. Its body is the existing
/// [`crate::FastVoteApplyRequest`] frame, not an unframed certificate.
pub const FASTVOTE_PUBLICATION_SOURCE_PATH: &str = "/v1/fastvote/publications/source";
/// A replica verifies and durably retains one bundle before exposing its ACK.
/// Its body is a canonical `consensus::bundle::PublicationBundle` frame.
pub const FASTVOTE_PUBLICATION_RETAIN_PATH: &str = "/v1/fastvote/publications/retain";
/// A replica applies only with a verified quorum availability certificate.
pub const FASTVOTE_PUBLISHED_APPLY_PATH: &str = "/v1/fastvote/publications/apply";

/// The active FastVote validator set is bounded at 256 members; the existing
/// 4 KiB per-vote transport ceiling also bounds a serialized availability
/// certificate, including its header and canonical framing.
pub const MAX_FASTVOTE_AVAILABILITY_CERTIFICATE_BYTES: usize = MAX_FASTVOTE_CERTIFICATE_BYTES;
/// The whole frame is checked before canonical decoding or allocation.
pub const MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES: usize = MAX_SIGNED_PAID_INTENT_BYTES
    + MAX_FASTVOTE_CERTIFICATE_BYTES
    + MAX_FASTVOTE_AVAILABILITY_CERTIFICATE_BYTES
    + 1024;

/// A publication-gated apply carries its original signed intent, one genuine
/// FastCertificate and the distinct quorum-retention proof. These byte strings
/// are independently authenticated by the server; framing is not authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastVotePublishedApplyRequest {
    /// Exact canonical `SignedPaidIntent` bytes.
    pub signed_paid_intent: Vec<u8>,
    /// Exact canonical `FastCertificate` bytes.
    pub certificate: Vec<u8>,
    /// Exact canonical `AvailabilityCertificate` bytes.
    pub availability_certificate: Vec<u8>,
}

/// Size or canonical framing error for [`FastVotePublishedApplyRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastVotePublishedApplyRequestError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// Signed intent exceeded its bound.
    SignedPaidIntentTooLarge(usize),
    /// FastCertificate exceeded its bound.
    CertificateTooLarge(usize),
    /// AvailabilityCertificate exceeded its bound.
    AvailabilityCertificateTooLarge(usize),
    /// Whole request exceeded its bound.
    RequestTooLarge(usize),
    /// A decoded frame was not its unique canonical re-encoding.
    NonCanonicalEncoding,
}

impl fmt::Display for FastVotePublishedApplyRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::SignedPaidIntentTooLarge(length) => {
                write!(
                    f,
                    "signed paid intent is {length} bytes, maximum is {MAX_SIGNED_PAID_INTENT_BYTES}"
                )
            }
            Self::CertificateTooLarge(length) => {
                write!(
                    f,
                    "FastCertificate is {length} bytes, maximum is {MAX_FASTVOTE_CERTIFICATE_BYTES}"
                )
            }
            Self::AvailabilityCertificateTooLarge(length) => write!(
                f,
                "AvailabilityCertificate is {length} bytes, maximum is {MAX_FASTVOTE_AVAILABILITY_CERTIFICATE_BYTES}"
            ),
            Self::RequestTooLarge(length) => write!(
                f,
                "published apply request is {length} bytes, maximum is {MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES}"
            ),
            Self::NonCanonicalEncoding => f.write_str("published apply request is non-canonical"),
        }
    }
}

impl Error for FastVotePublishedApplyRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::SignedPaidIntentTooLarge(_)
            | Self::CertificateTooLarge(_)
            | Self::AvailabilityCertificateTooLarge(_)
            | Self::RequestTooLarge(_)
            | Self::NonCanonicalEncoding => None,
        }
    }
}

impl From<CanonicalEncodingError> for FastVotePublishedApplyRequestError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for FastVotePublishedApplyRequestError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl FastVotePublishedApplyRequest {
    fn check_bounds(&self) -> Result<(), FastVotePublishedApplyRequestError> {
        if self.signed_paid_intent.len() > MAX_SIGNED_PAID_INTENT_BYTES {
            return Err(
                FastVotePublishedApplyRequestError::SignedPaidIntentTooLarge(
                    self.signed_paid_intent.len(),
                ),
            );
        }
        if self.certificate.len() > MAX_FASTVOTE_CERTIFICATE_BYTES {
            return Err(FastVotePublishedApplyRequestError::CertificateTooLarge(
                self.certificate.len(),
            ));
        }
        if self.availability_certificate.len() > MAX_FASTVOTE_AVAILABILITY_CERTIFICATE_BYTES {
            return Err(
                FastVotePublishedApplyRequestError::AvailabilityCertificateTooLarge(
                    self.availability_certificate.len(),
                ),
            );
        }
        Ok(())
    }

    /// Encodes the three exact byte strings as `0xE106/v1`.
    pub fn encode(&self) -> Result<Vec<u8>, FastVotePublishedApplyRequestError> {
        self.check_bounds()?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(FASTVOTE_PUBLISHED_APPLY_REQUEST_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.signed_paid_intent.clone())?;
        frame.field_bytes(2, self.certificate.clone())?;
        frame.field_bytes(3, self.availability_certificate.clone())?;
        Ok(frame.finish()?)
    }

    /// Strictly decodes `0xE106/v1`, bounding bytes before parsing.
    pub fn decode(bytes: &[u8]) -> Result<Self, FastVotePublishedApplyRequestError> {
        if bytes.len() > MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES {
            return Err(FastVotePublishedApplyRequestError::RequestTooLarge(
                bytes.len(),
            ));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(FASTVOTE_PUBLISHED_APPLY_REQUEST_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;
        let request: Self = Self {
            signed_paid_intent: frame.required_field(1)?.to_vec(),
            certificate: frame.required_field(2)?.to_vec(),
            availability_certificate: frame.required_field(3)?.to_vec(),
        };
        request.check_bounds()?;
        if request.encode()?.as_slice() != bytes {
            return Err(FastVotePublishedApplyRequestError::NonCanonicalEncoding);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FastVotePublishedApplyRequest {
        FastVotePublishedApplyRequest {
            signed_paid_intent: vec![0x11; 3],
            certificate: vec![0x22; 2],
            availability_certificate: vec![0x33; 4],
        }
    }

    #[test]
    fn round_trip_and_independent_stable_vector() {
        let request: FastVotePublishedApplyRequest = sample();
        let encoded: Vec<u8> = request.encode().unwrap();
        assert_eq!(
            encoded
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "534e524506e101000300010003000000111111020002000000222203000400000033333333"
        );
        assert_eq!(FastVotePublishedApplyRequest::decode(&encoded), Ok(request));
    }

    #[test]
    fn refuses_each_over_bound_field_and_whole_frame() {
        let mut request: FastVotePublishedApplyRequest = sample();
        request.signed_paid_intent = vec![0; MAX_SIGNED_PAID_INTENT_BYTES + 1];
        assert!(matches!(
            request.encode(),
            Err(FastVotePublishedApplyRequestError::SignedPaidIntentTooLarge(_))
        ));
        request = sample();
        request.certificate = vec![0; MAX_FASTVOTE_CERTIFICATE_BYTES + 1];
        assert!(matches!(
            request.encode(),
            Err(FastVotePublishedApplyRequestError::CertificateTooLarge(_))
        ));
        request = sample();
        request.availability_certificate = vec![0; MAX_FASTVOTE_AVAILABILITY_CERTIFICATE_BYTES + 1];
        assert!(matches!(
            request.encode(),
            Err(FastVotePublishedApplyRequestError::AvailabilityCertificateTooLarge(_))
        ));
        let oversized: Vec<u8> = vec![0; MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES + 1];
        assert!(matches!(
            FastVotePublishedApplyRequest::decode(&oversized),
            Err(FastVotePublishedApplyRequestError::RequestTooLarge(_))
        ));
    }

    #[test]
    fn refuses_wrong_type_version_missing_or_unknown_field() {
        let mut bytes: Vec<u8> = sample().encode().unwrap();
        bytes[4] ^= 0xff;
        assert!(FastVotePublishedApplyRequest::decode(&bytes).is_err());
        bytes = sample().encode().unwrap();
        bytes[6] ^= 0xff;
        assert!(FastVotePublishedApplyRequest::decode(&bytes).is_err());

        let mut missing: CanonicalStruct =
            CanonicalStruct::new(FASTVOTE_PUBLISHED_APPLY_REQUEST_TYPE_ID, ENCODING_VERSION);
        missing.field_bytes(1, vec![0x11]).unwrap();
        missing.field_bytes(2, vec![0x22]).unwrap();
        assert!(matches!(
            FastVotePublishedApplyRequest::decode(&missing.finish().unwrap()),
            Err(FastVotePublishedApplyRequestError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(3)
            ))
        ));

        let mut unknown: CanonicalStruct =
            CanonicalStruct::new(FASTVOTE_PUBLISHED_APPLY_REQUEST_TYPE_ID, ENCODING_VERSION);
        unknown.field_bytes(1, vec![0x11]).unwrap();
        unknown.field_bytes(2, vec![0x22]).unwrap();
        unknown.field_bytes(3, vec![0x33]).unwrap();
        unknown.field_bytes(4, vec![0x44]).unwrap();
        assert!(matches!(
            FastVotePublishedApplyRequest::decode(&unknown.finish().unwrap()),
            Err(FastVotePublishedApplyRequestError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(4)
            ))
        ));
    }
}
