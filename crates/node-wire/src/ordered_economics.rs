//! DR-0153 ordered network economics HTTP transport frames.
//!
//! This module owns only the HTTP-layer envelope for the opt-in ordered
//! economics network surface (`native-http::ordered_economics`,
//! `sunrise-edge-client::ordered_economics_client`). Every message body that
//! is already exactly one `node_core::ordered_economics` canonical value
//! (`OrderedProposal`, `QuorumCertificate`, `OrderedEventOutput`,
//! `OrderedStatus`) is transported as that value's own canonical bytes,
//! unwrapped, under a dedicated media type -- reusing the core codec rather
//! than duplicating its schema. [`OrderedProposeRequest`] is the one new
//! frame this module defines, because "an optional candidate" is an
//! HTTP-request shape, not itself a `node_core::ordered_economics` type.
//!
//! `node_core::ordered_economics` allocated `0x6442..=0x6448` for its own
//! canonical types (`OrderedProposal`/`OrderedStatus`/`OrderedOutcome`/
//! `OrderedEventOutput`/two internal record types/`NodeOutput`), confirmed
//! by reading `crates/node-core/src/ordered_economics/engine.rs` in the
//! parallel core worktree. [`ORDERED_PROPOSE_REQUEST_TYPE_ID`] at `0x6460`
//! stays clear of that range.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use std::error::Error;

/// Canonical type identifier for [`OrderedProposeRequest`].
pub const ORDERED_PROPOSE_REQUEST_TYPE_ID: u16 = 0x6460;
const ORDERED_PROPOSE_REQUEST_ENCODING_VERSION: u16 = 1;

/// Opt-in route: leader-only. Body is an [`OrderedProposeRequest`]; response
/// is the raw canonical `OrderedProposal` bytes.
pub const ORDERED_ECONOMICS_PROPOSE_PATH: &str = "/v1/ordered-economics/propose";
/// Opt-in route: every validator. Body is the raw canonical `OrderedProposal`
/// bytes; response is the raw canonical `OrderedEventOutput` bytes (may embed
/// this replica's vote message).
pub const ORDERED_ECONOMICS_PROPOSAL_PATH: &str = "/v1/ordered-economics/proposal";
/// Opt-in route: every validator. Body is the raw canonical `QuorumCertificate`
/// bytes; response is the raw canonical `OrderedEventOutput` bytes.
pub const ORDERED_ECONOMICS_CERTIFICATE_PATH: &str = "/v1/ordered-economics/certificate";
/// Opt-in, signerless recovery/replay route. Body is the raw canonical
/// `OrderedProposal` bytes; response is the raw canonical `OrderedEventOutput`
/// bytes. Never votes, never mutates a reservation.
pub const ORDERED_ECONOMICS_OBSERVE_PATH: &str = "/v1/ordered-economics/observe";
/// Opt-in bounded read route. No body; response is the raw canonical
/// `OrderedStatus` bytes.
pub const ORDERED_ECONOMICS_STATUS_PATH: &str = "/v1/ordered-economics/status";
/// Opt-in, empty-body, trusted-local-clock-only pacemaker route. Never
/// accepts a caller-supplied timestamp; the host's own `Clock` is the sole
/// time authority. Wraps `node_core::ordered_economics::process_tick`.
/// Response is the raw canonical `OrderedEventOutput` bytes.
pub const ORDERED_ECONOMICS_TICK_PATH: &str = "/v1/ordered-economics/tick";

/// Media type for a raw canonical `OrderedProposal`.
pub const ORDERED_PROPOSAL_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.ordered-proposal";
/// Media type for a raw canonical `QuorumCertificate`.
pub const ORDERED_CERTIFICATE_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.ordered-certificate";
/// Media type for a raw canonical `OrderedEventOutput`.
pub const ORDERED_EVENT_OUTPUT_MEDIA_TYPE: &str =
    "application/vnd.sunrise-edge.ordered-event-output";
/// Media type for a raw canonical `OrderedStatus`.
pub const ORDERED_STATUS_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.ordered-status";
/// Media type for [`OrderedProposeRequest`].
pub const ORDERED_PROPOSE_REQUEST_MEDIA_TYPE: &str =
    "application/vnd.sunrise-edge.ordered-propose-request";

/// Bound on one encoded `OrderedCandidate`: real core cap is
/// `node_core::ordered_economics::MAX_ORDERED_CANDIDATE_INTENT_BYTES` (`512
/// * 1024`, confirmed in `crates/node-core/src/ordered_economics/candidate.rs`)
/// on `intent` alone, plus this frame's own context/kind/request-id/
/// checkpoint overhead.
pub const MAX_ORDERED_CANDIDATE_BYTES: usize = 512 * 1024 + 4096;
/// Bound on one complete encoded [`OrderedProposeRequest`].
pub const MAX_ORDERED_PROPOSE_REQUEST_BYTES: usize = MAX_ORDERED_CANDIDATE_BYTES + 1024;
/// Bound on one encoded `OrderedProposal`: real core cap on the embedded
/// `consensus::ConsensusProposal` is `consensus::durable::MAX_ENCODED_PROPOSAL_BYTES`
/// (`10 * 1024 * 1024`, confirmed in `crates/consensus/src/durable.rs`),
/// plus at most one `OrderedCandidate` and frame overhead.
pub const MAX_ORDERED_PROPOSAL_BYTES: usize = 10 * 1024 * 1024 + MAX_ORDERED_CANDIDATE_BYTES + 4096;
/// Bound on one encoded `QuorumCertificate`: real core cap is
/// `consensus::durable::MAX_ENCODED_CERTIFICATE_BYTES` (`8 * 1024 * 1024`,
/// confirmed in `crates/consensus/src/durable.rs`).
pub const MAX_ORDERED_CERTIFICATE_BYTES: usize = 8 * 1024 * 1024;
/// Bound on one encoded `OrderedEventOutput`: real core caps its `messages`
/// at `MAX_ORDERED_EVENT_MESSAGES` (8, confirmed in
/// `crates/node-core/src/ordered_economics/engine.rs`), each up to one full
/// `ConsensusProposal`/`QuorumCertificate`, plus at most
/// `MAX_ORDERED_EVENT_COMMITTED` (1) committed `OrderedOutcome`.
pub const MAX_ORDERED_EVENT_OUTPUT_BYTES: usize =
    8 * (10 * 1024 * 1024) + MAX_ORDERED_CANDIDATE_BYTES + 1024 * 1024;
/// Bound on one encoded `OrderedStatus` (fixed-size view/height plus one QC).
pub const MAX_ORDERED_STATUS_BYTES: usize = MAX_ORDERED_CERTIFICATE_BYTES + 256;

/// Errors from encoding or decoding an [`OrderedProposeRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderedProposeRequestError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// `candidate` exceeded [`MAX_ORDERED_CANDIDATE_BYTES`].
    CandidateTooLarge(usize),
    /// The decoded value's own re-encoding did not match the input bytes.
    NonCanonicalEncoding,
    /// The complete encoded request exceeded [`MAX_ORDERED_PROPOSE_REQUEST_BYTES`].
    RequestTooLarge(usize),
}

impl fmt::Display for OrderedProposeRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::CandidateTooLarge(length) => write!(
                f,
                "ordered propose request candidate is {length} bytes, maximum is {MAX_ORDERED_CANDIDATE_BYTES}"
            ),
            Self::NonCanonicalEncoding => {
                f.write_str("ordered propose request bytes are not the canonical encoding")
            }
            Self::RequestTooLarge(length) => write!(
                f,
                "ordered propose request is {length} bytes, maximum is {MAX_ORDERED_PROPOSE_REQUEST_BYTES}"
            ),
        }
    }
}

impl Error for OrderedProposeRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::CandidateTooLarge(_) | Self::NonCanonicalEncoding | Self::RequestTooLarge(_) => {
                None
            }
        }
    }
}

impl From<CanonicalEncodingError> for OrderedProposeRequestError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for OrderedProposeRequestError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

/// `POST /v1/ordered-economics/propose` request body: an optional exact
/// canonical `OrderedCandidate` for the current leader to propose. `None`
/// requests an empty proposal (a bare descendant heartbeat at a non-`1 mod
/// 3` height, or a deliberately empty `1 mod 3` height). This type never
/// re-derives or reinterprets the candidate bytes; the leader's own
/// `node_core::ordered_economics::propose` re-authenticates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedProposeRequest {
    /// Exact canonical `OrderedCandidate` bytes, or `None` for an empty
    /// proposal request.
    pub candidate: Option<Vec<u8>>,
}

impl OrderedProposeRequest {
    fn check_bounds(&self) -> Result<(), OrderedProposeRequestError> {
        if let Some(candidate) = &self.candidate
            && candidate.len() > MAX_ORDERED_CANDIDATE_BYTES
        {
            return Err(OrderedProposeRequestError::CandidateTooLarge(
                candidate.len(),
            ));
        }
        Ok(())
    }

    /// Encodes canonical frame `0x6460/v1`.
    pub fn encode(&self) -> Result<Vec<u8>, OrderedProposeRequestError> {
        self.check_bounds()?;
        let mut frame = CanonicalStruct::new(
            ORDERED_PROPOSE_REQUEST_TYPE_ID,
            ORDERED_PROPOSE_REQUEST_ENCODING_VERSION,
        );
        if let Some(candidate) = &self.candidate {
            frame.field_bytes(1, candidate.clone())?;
        }
        Ok(frame.finish()?)
    }

    /// Strictly decodes canonical frame `0x6460/v1`, rejecting an oversized
    /// input before decoding and re-checking bounds again after.
    pub fn decode(bytes: &[u8]) -> Result<Self, OrderedProposeRequestError> {
        if bytes.len() > MAX_ORDERED_PROPOSE_REQUEST_BYTES {
            return Err(OrderedProposeRequestError::RequestTooLarge(bytes.len()));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(ORDERED_PROPOSE_REQUEST_TYPE_ID)?;
        frame.require_version(ORDERED_PROPOSE_REQUEST_ENCODING_VERSION)?;
        frame.require_only_fields(&[1])?;
        let request = Self {
            candidate: frame.field(1).map(|bytes| bytes.to_vec()),
        };
        request.check_bounds()?;
        if request.encode()?.as_slice() != bytes {
            return Err(OrderedProposeRequestError::NonCanonicalEncoding);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_with_candidate() -> OrderedProposeRequest {
        OrderedProposeRequest {
            candidate: Some(vec![0xCD; 48]),
        }
    }

    #[test]
    fn round_trips_with_a_candidate() {
        let request = sample_with_candidate();
        let bytes = request.encode().unwrap();
        assert_eq!(OrderedProposeRequest::decode(&bytes).unwrap(), request);
    }

    #[test]
    fn round_trips_without_a_candidate_as_an_empty_proposal_request() {
        let request = OrderedProposeRequest { candidate: None };
        let bytes = request.encode().unwrap();
        assert_eq!(OrderedProposeRequest::decode(&bytes).unwrap(), request);
        assert!(
            OrderedProposeRequest::decode(&bytes)
                .unwrap()
                .candidate
                .is_none()
        );
    }

    #[test]
    fn rejects_an_oversized_candidate_on_encode() {
        let request = OrderedProposeRequest {
            candidate: Some(vec![0u8; MAX_ORDERED_CANDIDATE_BYTES + 1]),
        };
        let length = request.candidate.as_ref().unwrap().len();
        assert_eq!(
            request.encode(),
            Err(OrderedProposeRequestError::CandidateTooLarge(length))
        );
    }

    #[test]
    fn rejects_an_oversized_encoded_request_on_decode_before_parsing() {
        let oversized = vec![0u8; MAX_ORDERED_PROPOSE_REQUEST_BYTES + 1];
        let length = oversized.len();
        assert_eq!(
            OrderedProposeRequest::decode(&oversized),
            Err(OrderedProposeRequestError::RequestTooLarge(length))
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_the_canonical_re_encoding() {
        // A frame with an extra unknown field must fail closed, matching
        // `FastVoteApplyRequest`'s non-canonical-encoding precedent.
        let mut frame = CanonicalStruct::new(
            ORDERED_PROPOSE_REQUEST_TYPE_ID,
            ORDERED_PROPOSE_REQUEST_ENCODING_VERSION,
        );
        frame.field_bytes(1, vec![1, 2, 3]).unwrap();
        frame.field_bytes(2, vec![9]).unwrap();
        let bytes = frame.finish().unwrap();
        assert!(matches!(
            OrderedProposeRequest::decode(&bytes),
            Err(OrderedProposeRequestError::CanonicalDecoding(_))
        ));
    }
}
