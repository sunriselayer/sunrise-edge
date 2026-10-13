//! Adapter-local, versioned, length-framed request/response codec between
//! the publication CLI client and the custody `serve` process.
//!
//! This is not a protocol wire format: it changes no canonical bytes, digest,
//! or signature payload. It carries only the untrusted inputs to
//! [`sunrise_edge_client::PreparedPublication::prepare`] (canonical artifact
//! bytes, nonce, request id) one way, and a raw 64-byte Ed25519 signature or
//! a closed, redacted refusal status the other way. It never carries a
//! caller-supplied signable frame: custody always rebuilds the frame itself
//! under its own pinned configuration (see `super::server`).

use std::fmt;

use sunrise_edge_client::{EnvelopeError, RequestId};

/// The one currently supported envelope version.
pub const CUSTODY_WIRE_VERSION: u8 = 1;
/// The one currently supported request message kind: sign a publication.
pub const CUSTODY_SIGN_PUBLICATION_MESSAGE: u8 = 1;
/// Exact Ed25519 signature length.
pub const CUSTODY_SIGNATURE_BYTES: usize = 64;

/// Reuses the existing protocol-level bound on one encoded `CodeArtifact`
/// rather than inventing a second, independently maintained ceiling.
pub const MAX_CUSTODY_ARTIFACT_BYTES: usize =
    sunrise_edge_client::publication::MAX_PUBLICATION_BYTES;
/// Fixed request header: version(1) + message type(1) + nonce(8) +
/// request_id(32) + artifact_len(4).
pub const CUSTODY_REQUEST_HEADER_BYTES: usize = 1 + 1 + 8 + 32 + 4;
/// Maximum accepted total encoded request frame size, checked before any
/// artifact decode is attempted.
pub const MAX_CUSTODY_REQUEST_FRAME_BYTES: usize =
    CUSTODY_REQUEST_HEADER_BYTES + MAX_CUSTODY_ARTIFACT_BYTES;
/// Maximum accepted total encoded response frame size (version + status +
/// an optional signature).
pub const MAX_CUSTODY_RESPONSE_FRAME_BYTES: usize = 1 + 1 + CUSTODY_SIGNATURE_BYTES;
/// Outer transport length-prefix width, in bytes.
pub const CUSTODY_LENGTH_PREFIX_BYTES: usize = 4;

/// Fail-closed codec errors. None of these ever includes raw wire bytes.
#[derive(Debug)]
pub enum CustodyWireError {
    /// The frame was shorter than its fixed header.
    Truncated,
    /// The frame declared a version this codec does not implement.
    UnsupportedVersion(u8),
    /// The frame declared a message type this codec does not implement.
    UnsupportedMessageType(u8),
    /// The frame declared a response status this codec does not recognize.
    UnsupportedStatus(u8),
    /// The declared artifact or signature length exceeded its bound.
    ArtifactTooLarge { actual: usize, maximum: usize },
    /// The outer transport length prefix exceeded its bound.
    FrameTooLarge { actual: usize, maximum: usize },
    /// The frame's actual length did not match its declared inner length.
    LengthMismatch { declared: usize, actual: usize },
    /// The request id was zero or otherwise rejected.
    RequestId(EnvelopeError),
}

impl fmt::Display for CustodyWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("custody wire frame is shorter than its fixed header"),
            Self::UnsupportedVersion(version) => {
                write!(f, "custody wire version {version} is not supported")
            }
            Self::UnsupportedMessageType(kind) => {
                write!(f, "custody wire message type {kind} is not supported")
            }
            Self::UnsupportedStatus(status) => {
                write!(f, "custody wire response status {status} is not recognized")
            }
            Self::ArtifactTooLarge { actual, maximum } => write!(
                f,
                "custody wire payload length {actual} exceeds the maximum {maximum}"
            ),
            Self::FrameTooLarge { actual, maximum } => write!(
                f,
                "custody wire frame length {actual} exceeds the maximum {maximum}"
            ),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "custody wire frame declared length {declared} but actual remaining length is {actual}"
            ),
            Self::RequestId(error) => write!(f, "custody wire request id rejected: {error}"),
        }
    }
}

impl std::error::Error for CustodyWireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequestId(error) => Some(error),
            _ => None,
        }
    }
}

/// The untrusted inputs to `PreparedPublication::prepare` custody receives;
/// never a caller-supplied signable frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignPublicationRequest {
    pub nonce: u64,
    pub request_id: RequestId,
    pub artifact_bytes: Vec<u8>,
}

/// Encodes a [`SignPublicationRequest`] to its exact bounded, versioned,
/// length-framed inner bytes (without the outer transport length prefix).
pub fn encode_request(request: &SignPublicationRequest) -> Result<Vec<u8>, CustodyWireError> {
    if request.artifact_bytes.len() > MAX_CUSTODY_ARTIFACT_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: request.artifact_bytes.len(),
            maximum: MAX_CUSTODY_ARTIFACT_BYTES,
        });
    }
    let artifact_len = u32::try_from(request.artifact_bytes.len()).map_err(|_| {
        CustodyWireError::ArtifactTooLarge {
            actual: request.artifact_bytes.len(),
            maximum: MAX_CUSTODY_ARTIFACT_BYTES,
        }
    })?;
    let mut out = Vec::with_capacity(CUSTODY_REQUEST_HEADER_BYTES + request.artifact_bytes.len());
    out.push(CUSTODY_WIRE_VERSION);
    out.push(CUSTODY_SIGN_PUBLICATION_MESSAGE);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&artifact_len.to_be_bytes());
    out.extend_from_slice(&request.artifact_bytes);
    Ok(out)
}

/// Decodes and strictly bounds one [`SignPublicationRequest`]; rejects
/// unknown version/message type and any trailing or short bytes.
pub fn decode_request(bytes: &[u8]) -> Result<SignPublicationRequest, CustodyWireError> {
    if bytes.len() > MAX_CUSTODY_REQUEST_FRAME_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_CUSTODY_REQUEST_FRAME_BYTES,
        });
    }
    if bytes.len() < CUSTODY_REQUEST_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    if bytes[0] != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    if bytes[1] != CUSTODY_SIGN_PUBLICATION_MESSAGE {
        return Err(CustodyWireError::UnsupportedMessageType(bytes[1]));
    }
    let nonce = u64::from_be_bytes(bytes[2..10].try_into().expect("exact 8-byte slice"));
    let mut request_id_bytes = [0_u8; 32];
    request_id_bytes.copy_from_slice(&bytes[10..42]);
    let request_id = RequestId::new(request_id_bytes).map_err(CustodyWireError::RequestId)?;
    let artifact_len =
        u32::from_be_bytes(bytes[42..46].try_into().expect("exact 4-byte slice")) as usize;
    if artifact_len > MAX_CUSTODY_ARTIFACT_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: artifact_len,
            maximum: MAX_CUSTODY_ARTIFACT_BYTES,
        });
    }
    let expected_total = CUSTODY_REQUEST_HEADER_BYTES
        .checked_add(artifact_len)
        .ok_or(CustodyWireError::ArtifactTooLarge {
            actual: artifact_len,
            maximum: MAX_CUSTODY_ARTIFACT_BYTES,
        })?;
    if bytes.len() != expected_total {
        return Err(CustodyWireError::LengthMismatch {
            declared: artifact_len,
            actual: bytes.len().saturating_sub(CUSTODY_REQUEST_HEADER_BYTES),
        });
    }
    let artifact_bytes = bytes[CUSTODY_REQUEST_HEADER_BYTES..].to_vec();
    Ok(SignPublicationRequest {
        nonce,
        request_id,
        artifact_bytes,
    })
}

/// A closed, redacted response status. The server never sends free-form
/// error text; a caller maps this single byte to a typed, actionable error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyResponseStatus {
    /// The request was signed; a 64-byte signature follows.
    Signed = 0,
    /// The request declared an unsupported envelope version.
    UnsupportedVersion = 1,
    /// The request declared an unsupported message type.
    UnsupportedMessageType = 2,
    /// The request was structurally malformed or exceeded a bound.
    Malformed = 3,
    /// The decoded artifact's publisher did not match the configured key.
    PublisherMismatch = 4,
    /// No valid, unexpired, exactly matching approval record exists.
    NoApproval = 5,
    /// An unexpected internal failure occurred; no detail is disclosed.
    Internal = 6,
}

impl CustodyResponseStatus {
    const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Signed),
            1 => Some(Self::UnsupportedVersion),
            2 => Some(Self::UnsupportedMessageType),
            3 => Some(Self::Malformed),
            4 => Some(Self::PublisherMismatch),
            5 => Some(Self::NoApproval),
            6 => Some(Self::Internal),
            _ => None,
        }
    }
}

impl fmt::Display for CustodyResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Signed => "signed",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedMessageType => "unsupported_message_type",
            Self::Malformed => "malformed",
            Self::PublisherMismatch => "publisher_mismatch",
            Self::NoApproval => "no_approval",
            Self::Internal => "internal",
        };
        f.write_str(text)
    }
}

/// One complete custody response: either a signature, or a closed refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyResponse {
    Signed {
        signature: [u8; CUSTODY_SIGNATURE_BYTES],
    },
    Refused {
        status: CustodyResponseStatus,
    },
}

/// Encodes a [`CustodyResponse`] to its exact bounded bytes.
#[must_use]
pub fn encode_response(response: &CustodyResponse) -> Vec<u8> {
    match response {
        CustodyResponse::Signed { signature } => {
            let mut out = Vec::with_capacity(2 + CUSTODY_SIGNATURE_BYTES);
            out.push(CUSTODY_WIRE_VERSION);
            out.push(CustodyResponseStatus::Signed as u8);
            out.extend_from_slice(signature);
            out
        }
        CustodyResponse::Refused { status } => vec![CUSTODY_WIRE_VERSION, *status as u8],
    }
}

/// Decodes and strictly bounds one [`CustodyResponse`]; rejects unknown
/// version/status and any trailing or short bytes.
pub fn decode_response(bytes: &[u8]) -> Result<CustodyResponse, CustodyWireError> {
    if bytes.len() > MAX_CUSTODY_RESPONSE_FRAME_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_CUSTODY_RESPONSE_FRAME_BYTES,
        });
    }
    if bytes.len() < 2 {
        return Err(CustodyWireError::Truncated);
    }
    if bytes[0] != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    let status = CustodyResponseStatus::from_u8(bytes[1])
        .ok_or(CustodyWireError::UnsupportedStatus(bytes[1]))?;
    match status {
        CustodyResponseStatus::Signed => {
            if bytes.len() != 2 + CUSTODY_SIGNATURE_BYTES {
                return Err(CustodyWireError::LengthMismatch {
                    declared: CUSTODY_SIGNATURE_BYTES,
                    actual: bytes.len().saturating_sub(2),
                });
            }
            let mut signature = [0_u8; CUSTODY_SIGNATURE_BYTES];
            signature.copy_from_slice(&bytes[2..]);
            Ok(CustodyResponse::Signed { signature })
        }
        other => {
            if bytes.len() != 2 {
                return Err(CustodyWireError::LengthMismatch {
                    declared: 0,
                    actual: bytes.len().saturating_sub(2),
                });
            }
            Ok(CustodyResponse::Refused { status: other })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    /// Stable encoding vector: a fixed, pinned-byte request. A change to
    /// this byte layout is an adapter wire-format break.
    #[test]
    fn request_encoding_is_stable() {
        let request = SignPublicationRequest {
            nonce: 0x0102_0304_0506_0708,
            request_id: request_id(0xAB),
            artifact_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = encode_request(&request).unwrap();
        let mut expected = vec![CUSTODY_WIRE_VERSION, CUSTODY_SIGN_PUBLICATION_MESSAGE];
        expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
        expected.extend_from_slice(&[0xAB; 32]);
        expected.extend_from_slice(&4_u32.to_be_bytes());
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(encoded, expected);
        assert_eq!(decode_request(&encoded).unwrap(), request);
    }

    #[test]
    fn request_round_trips_with_an_empty_artifact_is_rejected_by_the_artifact_layer_not_the_wire() {
        // The wire layer itself allows a zero-length artifact (CodeArtifact's
        // own decoder is what rejects an empty wasm/abi); this proves the
        // wire codec does not duplicate that policy.
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: Vec::new(),
        };
        let encoded = encode_request(&request).unwrap();
        assert_eq!(decode_request(&encoded).unwrap(), request);
    }

    #[test]
    fn decode_request_rejects_an_unsupported_version() {
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: vec![1, 2, 3],
        };
        let mut encoded = encode_request(&request).unwrap();
        encoded[0] = 2;
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn decode_request_rejects_an_unsupported_message_type() {
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: vec![1, 2, 3],
        };
        let mut encoded = encode_request(&request).unwrap();
        encoded[1] = 9;
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::UnsupportedMessageType(9))
        ));
    }

    #[test]
    fn decode_request_rejects_truncated_bytes() {
        assert!(matches!(
            decode_request(&[1, 1, 0, 0]),
            Err(CustodyWireError::Truncated)
        ));
    }

    #[test]
    fn decode_request_rejects_trailing_bytes() {
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: vec![1, 2, 3],
        };
        let mut encoded = encode_request(&request).unwrap();
        encoded.push(0xFF);
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_request_rejects_a_declared_length_longer_than_actual_bytes() {
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: vec![1, 2, 3],
        };
        let mut encoded = encode_request(&request).unwrap();
        let declared_len_offset = CUSTODY_REQUEST_HEADER_BYTES - 4;
        encoded[declared_len_offset..CUSTODY_REQUEST_HEADER_BYTES]
            .copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_request_rejects_a_zero_request_id() {
        let request = SignPublicationRequest {
            nonce: 0,
            request_id: request_id(1),
            artifact_bytes: vec![1, 2, 3],
        };
        let mut encoded = encode_request(&request).unwrap();
        encoded[10..42].copy_from_slice(&[0_u8; 32]);
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::RequestId(_))
        ));
    }

    #[test]
    fn decode_request_rejects_an_artifact_length_over_the_bound() {
        let mut encoded = vec![CUSTODY_WIRE_VERSION, CUSTODY_SIGN_PUBLICATION_MESSAGE];
        encoded.extend_from_slice(&0_u64.to_be_bytes());
        encoded.extend_from_slice(&[1_u8; 32]);
        encoded.extend_from_slice(&(MAX_CUSTODY_ARTIFACT_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode_request(&encoded),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }

    /// Stable encoding vector for a signed response.
    #[test]
    fn signed_response_encoding_is_stable() {
        let signature = [0x42_u8; CUSTODY_SIGNATURE_BYTES];
        let response = CustodyResponse::Signed { signature };
        let encoded = encode_response(&response);
        let mut expected = vec![CUSTODY_WIRE_VERSION, 0];
        expected.extend_from_slice(&signature);
        assert_eq!(encoded, expected);
        assert_eq!(decode_response(&encoded).unwrap(), response);
    }

    #[test]
    fn refused_response_round_trips_for_every_status() {
        for status in [
            CustodyResponseStatus::UnsupportedVersion,
            CustodyResponseStatus::UnsupportedMessageType,
            CustodyResponseStatus::Malformed,
            CustodyResponseStatus::PublisherMismatch,
            CustodyResponseStatus::NoApproval,
            CustodyResponseStatus::Internal,
        ] {
            let response = CustodyResponse::Refused { status };
            let encoded = encode_response(&response);
            assert_eq!(encoded.len(), 2);
            assert_eq!(decode_response(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn decode_response_rejects_trailing_bytes_after_a_refusal() {
        let mut encoded = encode_response(&CustodyResponse::Refused {
            status: CustodyResponseStatus::NoApproval,
        });
        encoded.push(0);
        assert!(matches!(
            decode_response(&encoded),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_response_rejects_a_short_signature() {
        let mut encoded = encode_response(&CustodyResponse::Signed {
            signature: [0x11; CUSTODY_SIGNATURE_BYTES],
        });
        encoded.truncate(encoded.len() - 1);
        assert!(matches!(
            decode_response(&encoded),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_response_rejects_an_unknown_status() {
        let encoded = vec![CUSTODY_WIRE_VERSION, 0xFF];
        assert!(matches!(
            decode_response(&encoded),
            Err(CustodyWireError::UnsupportedStatus(0xFF))
        ));
    }
}
