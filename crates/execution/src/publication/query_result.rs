//! Structural provenance-query transport data, not verified durable publication.

use super::{
    PublicationError, PublicationSubmission, decode_publication_submission,
    encode_publication_submission,
};
use crate::paid_execution::{
    MAX_SIGNED_PAID_INTENT_BYTES, PaidExecutionError, SignedPaidIntent, decode_signed_paid_intent,
    encode_signed_paid_intent,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use std::fmt;

/// Canonical frame type of an encoded [`PublicationQueryResult`] (DR-0126).
pub const PUBLICATION_QUERY_RESULT_FRAME_TYPE: u16 = 0x6418;
const PUBLICATION_QUERY_RESULT_VERSION_1: u16 = 1;
const PUBLICATION_QUERY_PROVENANCE_LEGACY: u16 = 1;
const PUBLICATION_QUERY_PROVENANCE_PAID: u16 = 2;

/// Maximum encoded query frame, including the larger complete paid payload.
/// Checked before outer decoding and again after encoding.
pub const MAX_PUBLICATION_QUERY_RESULT_BYTES: usize = MAX_SIGNED_PAID_INTENT_BYTES + 256;

/// Untrusted transport data carrying one complete original signed frame.
///
/// No legacy signature is fabricated for a paid payload. Construction or
/// decoding establishes neither authentication nor a successful Publish receipt,
/// dependency closure, resolver, installed state or durable admission. A paid
/// payload need not even be a Publish application; callers retain that check.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PublicationQueryResult {
    /// Complete legacy `PublicationSubmission` frame `0x6308`.
    Legacy(PublicationSubmission),
    /// Complete `SignedPaidIntent` frame `0x6413`, still unverified.
    Paid(SignedPaidIntent),
}

/// Failures of the bounded structural query codec, not core admission errors.
#[derive(Debug)]
pub enum PublicationQueryResultError {
    /// Outer canonical framing or nested legacy publication encoding/decoding.
    Publication(PublicationError),
    /// Nested paid intent encoding/decoding or structural validation.
    Paid(PaidExecutionError),
    /// The complete query frame exceeds its existing resource bound.
    Limit,
    /// Unknown provenance or a noncanonical re-encoding of the decoded result.
    CorruptRecord,
}

impl fmt::Display for PublicationQueryResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publication(error) => error.fmt(f),
            Self::Paid(error) => error.fmt(f),
            Self::Limit => f.write_str("publication resource bound exceeded"),
            Self::CorruptRecord => f.write_str("invalid canonical durable publication record"),
        }
    }
}

// Preserve the original codec error's flat source boundary (DR-0217).
impl std::error::Error for PublicationQueryResultError {}

impl From<PublicationError> for PublicationQueryResultError {
    fn from(error: PublicationError) -> Self {
        Self::Publication(error)
    }
}

impl From<PaidExecutionError> for PublicationQueryResultError {
    fn from(error: PaidExecutionError) -> Self {
        Self::Paid(error)
    }
}

impl From<CanonicalEncodingError> for PublicationQueryResultError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Publication(PublicationError::Encoding(error))
    }
}

impl From<CanonicalDecodingError> for PublicationQueryResultError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Publication(PublicationError::Decoding(error))
    }
}

/// Encodes Frame `0x6418/v1` without granting publication authority.
pub fn encode_publication_query_result(
    result: &PublicationQueryResult,
) -> Result<Vec<u8>, PublicationQueryResultError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        PUBLICATION_QUERY_RESULT_FRAME_TYPE,
        PUBLICATION_QUERY_RESULT_VERSION_1,
    );
    match result {
        PublicationQueryResult::Legacy(submission) => {
            frame.field_u16(1, PUBLICATION_QUERY_PROVENANCE_LEGACY)?;
            frame.field_bytes(2, encode_publication_submission(submission)?)?;
        }
        PublicationQueryResult::Paid(signed) => {
            frame.field_u16(1, PUBLICATION_QUERY_PROVENANCE_PAID)?;
            frame.field_bytes(3, encode_signed_paid_intent(signed)?)?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_PUBLICATION_QUERY_RESULT_BYTES {
        return Err(PublicationQueryResultError::Limit);
    }
    Ok(bytes)
}

/// Strictly decodes Frame `0x6418/v1` as bounded, untrusted transport data.
pub fn decode_publication_query_result(
    bytes: &[u8],
) -> Result<PublicationQueryResult, PublicationQueryResultError> {
    if bytes.len() > MAX_PUBLICATION_QUERY_RESULT_BYTES {
        return Err(PublicationQueryResultError::Limit);
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(PUBLICATION_QUERY_RESULT_FRAME_TYPE)?;
    frame.require_version(PUBLICATION_QUERY_RESULT_VERSION_1)?;
    let result: PublicationQueryResult = match frame.required_u16(1)? {
        PUBLICATION_QUERY_PROVENANCE_LEGACY => {
            frame.require_only_fields(&[1, 2])?;
            PublicationQueryResult::Legacy(decode_publication_submission(frame.required_field(2)?)?)
        }
        PUBLICATION_QUERY_PROVENANCE_PAID => {
            frame.require_only_fields(&[1, 3])?;
            PublicationQueryResult::Paid(decode_signed_paid_intent(frame.required_field(3)?)?)
        }
        _ => return Err(PublicationQueryResultError::CorruptRecord),
    };
    if encode_publication_query_result(&result)? != bytes {
        return Err(PublicationQueryResultError::CorruptRecord);
    }
    Ok(result)
}
