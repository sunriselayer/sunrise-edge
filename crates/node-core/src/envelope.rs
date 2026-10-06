//! Pure canonical node envelopes and list framing (DR-0201).
//! Syntactic validity grants neither execution nor signing authority.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion, TypeError};
use std::error::Error;

pub(crate) const NODE_EVENT_TYPE_ID: u16 = 0xE001;
pub(crate) const NODE_RESPONSE_TYPE_ID: u16 = 0xE002;
pub(crate) const NODE_DEDUP_RECORD_TYPE_ID: u16 = 0xE003;
const ENCODING_VERSION: u16 = 1;

/// Maximum UTF-8 byte length of a chain identifier accepted at node ingress.
pub const MAX_CHAIN_ID_BYTES: usize = 128;
/// Maximum canonical payload length carried by one node event or response.
pub const MAX_NODE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical state value replaced by one node-core invocation.
pub const MAX_NODE_STATE_BYTES: usize = 32 * 1024 * 1024;
/// Maximum responses or outbound messages produced by one invocation.
pub const MAX_NODE_OUTPUT_ITEMS: usize = 1_024;
/// Maximum aggregate payload bytes returned by one invocation.
pub const MAX_NODE_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

/// Closed construction, framing and bounds failures; never execution authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    CanonicalEncoding(CanonicalEncodingError),
    CanonicalDecoding(CanonicalDecodingError),
    InvalidChainId(TypeError),
    InvalidHashAlgorithm(TypeError),
    InvalidDigestLength(usize),
    ChainIdTooLong(usize),
    ZeroRequestId,
    InvalidRequestIdLength(usize),
    UnknownEventKind(u16),
    UnknownResponseStatus(u16),
    PayloadTooLarge(usize),
    StateTooLarge(usize),
    TooManyOutputItems {
        collection: &'static str,
        count: usize,
    },
    OutputTooLarge(usize),
    ResponseRequestMismatch {
        expected: RequestId,
        actual: RequestId,
    },
    NestedItemLengthOverflow(usize),
    TrailingNestedListBytes(usize),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::InvalidChainId(error) => write!(f, "invalid chain id: {error}"),
            Self::InvalidHashAlgorithm(error) => write!(f, "invalid hash algorithm: {error}"),
            Self::InvalidDigestLength(length) => write!(f, "digest is {length} bytes, expected 32"),
            Self::ChainIdTooLong(length) => write!(
                f,
                "chain id is {length} bytes, maximum is {MAX_CHAIN_ID_BYTES}"
            ),
            Self::ZeroRequestId => f.write_str("request id must not be all zeroes"),
            Self::InvalidRequestIdLength(length) => {
                write!(f, "request id is {length} bytes, expected 32")
            }
            Self::UnknownEventKind(kind) => write!(f, "unknown node event kind: {kind:#06x}"),
            Self::UnknownResponseStatus(status) => {
                write!(f, "unknown node response status: {status:#06x}")
            }
            Self::PayloadTooLarge(length) => write!(
                f,
                "node payload is {length} bytes, maximum is {MAX_NODE_PAYLOAD_BYTES}"
            ),
            Self::StateTooLarge(length) => write!(
                f,
                "node state is {length} bytes, maximum is {MAX_NODE_STATE_BYTES}"
            ),
            Self::TooManyOutputItems { collection, count } => write!(
                f,
                "node output has {count} {collection}, maximum is {MAX_NODE_OUTPUT_ITEMS}"
            ),
            Self::OutputTooLarge(length) => write!(
                f,
                "node output is {length} bytes, maximum is {MAX_NODE_OUTPUT_BYTES}"
            ),
            Self::ResponseRequestMismatch { expected, actual } => write!(
                f,
                "response request id mismatch: expected {expected}, got {actual}"
            ),
            Self::NestedItemLengthOverflow(length) => write!(
                f,
                "nested canonical item length cannot be represented: {length}"
            ),
            Self::TrailingNestedListBytes(length) => {
                write!(f, "nested canonical list has {length} trailing bytes")
            }
        }
    }
}

impl Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::InvalidChainId(error) | Self::InvalidHashAlgorithm(error) => Some(error),
            _ => None,
        }
    }
}
impl From<CanonicalEncodingError> for EnvelopeError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}
impl From<CanonicalDecodingError> for EnvelopeError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

/// Distinguishes list framing from a nested item's framing, preserving each
/// consumer's original refusal vocabulary without importing orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedListDecodeError {
    /// The list count exceeds the defining node-output bound.
    TooManyItems(usize),
    /// A little-endian item length is not representable on this target.
    LengthOverflow(usize),
    /// Advancing the list offset overflowed the target address space.
    OffsetOverflow,
    /// The list ended before its declared item or length prefix.
    Truncated {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    /// All declared items decoded but unconsumed bytes remain.
    TrailingBytes(usize),
    /// List framing succeeded but a nested envelope did not decode.
    Item(EnvelopeError),
}

impl fmt::Display for NestedListDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyItems(count) => write!(f, "nested list has too many items: {count}"),
            Self::LengthOverflow(length) => write!(f, "nested item length overflows: {length}"),
            Self::OffsetOverflow => f.write_str("nested list offset overflows"),
            Self::Truncated {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "nested list truncated at {offset}: needed {needed}, remaining {remaining}"
            ),
            Self::TrailingBytes(length) => write!(f, "nested list has {length} trailing bytes"),
            Self::Item(error) => write!(f, "nested envelope failed: {error}"),
        }
    }
}

impl Error for NestedListDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Item(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NestedListDecodeError> for EnvelopeError {
    fn from(value: NestedListDecodeError) -> Self {
        match value {
            NestedListDecodeError::TooManyItems(count) => Self::TooManyOutputItems {
                collection: "nested items",
                count,
            },
            NestedListDecodeError::LengthOverflow(length) => Self::NestedItemLengthOverflow(length),
            NestedListDecodeError::OffsetOverflow => Self::NestedItemLengthOverflow(usize::MAX),
            NestedListDecodeError::Truncated {
                offset,
                needed,
                remaining,
            } => Self::CanonicalDecoding(CanonicalDecodingError::Truncated {
                offset,
                needed,
                remaining,
            }),
            NestedListDecodeError::TrailingBytes(length) => Self::TrailingNestedListBytes(length),
            NestedListDecodeError::Item(error) => error,
        }
    }
}

/// Stable, caller-supplied idempotency identifier for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 32]);

impl RequestId {
    /// Creates a non-zero request identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, EnvelopeError> {
        if bytes == [0; 32] {
            return Err(EnvelopeError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed node event families routed to application-specific schema decoders.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeEventKind {
    /// Client transaction submission.
    SubmitTransaction = 0x0001,
    /// Validator vote delivery.
    ReceiveVote = 0x0002,
    /// Certificate delivery.
    ReceiveCertificate = 0x0003,
    /// Shared-object consensus message delivery.
    ReceiveConsensusMessage = 0x0004,
    /// Governance certificate application.
    ApplyGovernanceCertificate = 0x0005,
    /// Protocol-upgrade certificate application.
    ApplyProtocolUpgrade = 0x0006,
    /// Validator-set change certificate application.
    ApplyValidatorSetChange = 0x0007,
    /// Untrusted liveness tick delivery.
    Tick = 0x0008,
}

impl NodeEventKind {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeEventKind {
    type Error = EnvelopeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SubmitTransaction),
            0x0002 => Ok(Self::ReceiveVote),
            0x0003 => Ok(Self::ReceiveCertificate),
            0x0004 => Ok(Self::ReceiveConsensusMessage),
            0x0005 => Ok(Self::ApplyGovernanceCertificate),
            0x0006 => Ok(Self::ApplyProtocolUpgrade),
            0x0007 => Ok(Self::ApplyValidatorSetChange),
            0x0008 => Ok(Self::Tick),
            other => Err(EnvelopeError::UnknownEventKind(other)),
        }
    }
}

/// One replay-bounded, canonical input to the node state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEvent {
    pub(super) chain_id: ChainId,
    pub(super) protocol_version: ProtocolVersion,
    pub(super) epoch: Epoch,
    pub(super) request_id: RequestId,
    pub(super) kind: NodeEventKind,
    pub(super) payload: Vec<u8>,
}

impl NodeEvent {
    /// Creates a validated event around one canonical application payload.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        request_id: RequestId,
        kind: NodeEventKind,
        payload: Vec<u8>,
    ) -> Result<Self, EnvelopeError> {
        validate_chain_id(&chain_id)?;
        validate_payload(&payload)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            request_id,
            kind,
            payload,
        })
    }

    /// Returns the replay-protected chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the replay-protected protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the replay-protected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the event family.
    #[must_use]
    pub const fn kind(&self) -> NodeEventKind {
        self.kind
    }

    /// Returns the canonical application payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the event into its stable canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(NODE_EVENT_TYPE_ID, ENCODING_VERSION);
        frame.field_str(1, self.chain_id.as_str())?;
        frame.field_u32(2, self.protocol_version.get())?;
        frame.field_u64(3, self.epoch.get())?;
        frame.field_bytes(4, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(5, self.kind.as_u16())?;
        frame.field_bytes(6, self.payload.clone())?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates exactly one canonical event frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_EVENT_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;

        let chain_id: ChainId = ChainId::new(frame.required_str(1)?.to_owned())
            .map_err(EnvelopeError::InvalidChainId)?;
        let request_bytes: &[u8] = frame.required_field(4)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| EnvelopeError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            chain_id,
            ProtocolVersion::new(frame.required_u32(2)?),
            Epoch::new(frame.required_u64(3)?),
            RequestId::new(request_array)?,
            NodeEventKind::try_from(frame.required_u16(5)?)?,
            frame.required_field(6)?.to_vec(),
        )
    }
}

/// Stable status returned to the request adapter.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeResponseStatus {
    /// The event was accepted and persisted.
    Accepted = 0x0001,
    /// The authenticated event was deterministically rejected by application logic.
    Rejected = 0x0002,
}

impl NodeResponseStatus {
    /// Returns the stable wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for NodeResponseStatus {
    type Error = EnvelopeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Accepted),
            0x0002 => Ok(Self::Rejected),
            other => Err(EnvelopeError::UnknownResponseStatus(other)),
        }
    }
}

/// Adapter-neutral response produced by a successful state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeResponse {
    pub(super) request_id: RequestId,
    pub(super) status: NodeResponseStatus,
    pub(super) payload: Option<Vec<u8>>,
}

impl NodeResponse {
    /// Creates a bounded response. A present payload must be a canonical frame.
    pub fn new(
        request_id: RequestId,
        status: NodeResponseStatus,
        payload: Option<Vec<u8>>,
    ) -> Result<Self, EnvelopeError> {
        if let Some(bytes) = &payload {
            validate_payload(bytes)?;
        }
        Ok(Self {
            request_id,
            status,
            payload,
        })
    }

    /// Returns the matching request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> NodeResponseStatus {
        self.status
    }

    /// Returns the optional canonical response payload.
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Encodes this response into its adapter-neutral canonical wire form.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(NODE_RESPONSE_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.status.as_u16())?;
        if let Some(payload) = &self.payload {
            frame.field_bytes(3, payload.clone())?;
        }
        Ok(frame.finish()?)
    }

    /// Decodes one adapter-neutral canonical response.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_RESPONSE_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3])?;

        let request_bytes: &[u8] = frame.required_field(1)?;
        let request_array: [u8; 32] = request_bytes
            .try_into()
            .map_err(|_| EnvelopeError::InvalidRequestIdLength(request_bytes.len()))?;
        Self::new(
            RequestId::new(request_array)?,
            NodeResponseStatus::try_from(frame.required_u16(2)?)?,
            frame.field(3).map(<[u8]>::to_vec),
        )
    }
}

/// Canonical completed-request record used for persisted idempotency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDedupRecord {
    pub(super) request_id: RequestId,
    pub(super) event_digest: Digest32,
    pub(super) responses: Vec<NodeResponse>,
}

impl NodeDedupRecord {
    /// Creates a completed request record with replayable adapter responses.
    pub fn new(
        request_id: RequestId,
        event_digest: Digest32,
        responses: Vec<NodeResponse>,
    ) -> Result<Self, EnvelopeError> {
        validate_response_count(responses.len())?;
        validate_output_bytes(
            responses
                .iter()
                .filter_map(NodeResponse::payload)
                .map(<[u8]>::len),
        )?;
        for response in &responses {
            if response.request_id() != request_id {
                return Err(EnvelopeError::ResponseRequestMismatch {
                    expected: request_id,
                    actual: response.request_id(),
                });
            }
        }
        Ok(Self {
            request_id,
            event_digest,
            responses,
        })
    }

    /// Returns the stable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the digest of the complete canonical input event.
    #[must_use]
    pub const fn event_digest(&self) -> Digest32 {
        self.event_digest
    }

    /// Returns the responses replayed for a matching duplicate request.
    #[must_use]
    pub fn responses(&self) -> &[NodeResponse] {
        &self.responses
    }

    /// Encodes the completed request record canonically.
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let response_list: Vec<u8> =
            encode_response_list(&self.responses, Some(MAX_NODE_STATE_BYTES))?;
        let response_count: u32 =
            u32::try_from(self.responses.len()).map_err(|_| EnvelopeError::TooManyOutputItems {
                collection: "dedup responses",
                count: self.responses.len(),
            })?;
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
        frame.field_bytes(1, self.request_id.as_bytes().to_vec())?;
        frame.field_u16(2, self.event_digest.algorithm().as_u16())?;
        frame.field_bytes(3, self.event_digest.bytes())?;
        frame.field_u32(4, response_count)?;
        frame.field_bytes(5, response_list)?;
        Ok(frame.finish()?)
    }

    /// Decodes and validates one completed request record.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
        frame.require_type(NODE_DEDUP_RECORD_TYPE_ID)?;
        frame.require_version(ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5])?;

        let request_id: RequestId = decode_request_id(frame.required_field(1)?)?;
        let event_digest: Digest32 =
            decode_digest(frame.required_u16(2)?, frame.required_field(3)?)?;
        let count: usize = bounded_nested_count(frame.required_u32(4)?, "dedup responses")?;
        let responses: Vec<NodeResponse> = decode_response_list(frame.required_field(5)?, count)?;
        Self::new(request_id, event_digest, responses)
    }
}

pub(crate) fn validate_chain_id(chain_id: &ChainId) -> Result<(), EnvelopeError> {
    let length: usize = chain_id.as_str().len();
    if length > MAX_CHAIN_ID_BYTES {
        return Err(EnvelopeError::ChainIdTooLong(length));
    }
    Ok(())
}

fn validate_payload(payload: &[u8]) -> Result<(), EnvelopeError> {
    if payload.len() > MAX_NODE_PAYLOAD_BYTES {
        return Err(EnvelopeError::PayloadTooLarge(payload.len()));
    }
    decode_canonical_frame(payload)?;
    Ok(())
}

pub(crate) fn decode_request_id(bytes: &[u8]) -> Result<RequestId, EnvelopeError> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnvelopeError::InvalidRequestIdLength(bytes.len()))?;
    RequestId::new(array)
}

pub(crate) fn decode_digest(algorithm: u16, bytes: &[u8]) -> Result<Digest32, EnvelopeError> {
    let algorithm: HashAlgorithmId =
        HashAlgorithmId::try_from(algorithm).map_err(EnvelopeError::InvalidHashAlgorithm)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnvelopeError::InvalidDigestLength(bytes.len()))?;
    Ok(Digest32::new(algorithm, bytes))
}

pub(crate) fn bounded_nested_count(
    count: u32,
    collection: &'static str,
) -> Result<usize, EnvelopeError> {
    let count: usize = usize::try_from(count).map_err(|_| EnvelopeError::TooManyOutputItems {
        collection,
        count: usize::MAX,
    })?;
    validate_item_count(count, collection)?;
    Ok(count)
}

/// Validates the defining response count without adding an aggregate budget.
pub fn validate_response_count(count: usize) -> Result<(), EnvelopeError> {
    validate_item_count(count, "responses")
}

pub(crate) fn validate_item_count(
    count: usize,
    collection: &'static str,
) -> Result<(), EnvelopeError> {
    if count > MAX_NODE_OUTPUT_ITEMS {
        return Err(EnvelopeError::TooManyOutputItems { collection, count });
    }
    Ok(())
}

pub(crate) fn validate_output_bytes<I>(mut lengths: I) -> Result<(), EnvelopeError>
where
    I: Iterator<Item = usize>,
{
    let total: usize = lengths
        .try_fold(0_usize, usize::checked_add)
        .ok_or(EnvelopeError::OutputTooLarge(usize::MAX))?;
    if total > MAX_NODE_OUTPUT_BYTES {
        return Err(EnvelopeError::OutputTooLarge(total));
    }
    Ok(())
}

/// Encodes the single defining response-list representation. An aggregate
/// limit belongs to the record owner; HTTP passes None and keeps its frame bound.
pub fn encode_response_list(
    responses: &[NodeResponse],
    maximum: Option<usize>,
) -> Result<Vec<u8>, EnvelopeError> {
    validate_response_count(responses.len())?;
    let items: Vec<Vec<u8>> = responses
        .iter()
        .map(NodeResponse::encode)
        .collect::<Result<Vec<Vec<u8>>, EnvelopeError>>()?;
    encode_nested_items(items, maximum)
}

pub(crate) fn encode_nested_items(
    items: Vec<Vec<u8>>,
    maximum: Option<usize>,
) -> Result<Vec<u8>, EnvelopeError> {
    let capacity: Option<usize> = items
        .iter()
        .try_fold(0_usize, |total: usize, item: &Vec<u8>| {
            total.checked_add(4)?.checked_add(item.len())
        });
    let capacity: usize = capacity.ok_or(match maximum {
        Some(_) => EnvelopeError::StateTooLarge(usize::MAX),
        None => EnvelopeError::NestedItemLengthOverflow(usize::MAX),
    })?;
    if maximum.is_some_and(|limit: usize| capacity > limit) {
        return Err(EnvelopeError::StateTooLarge(capacity));
    }
    let mut encoded: Vec<u8> = Vec::with_capacity(capacity);
    for item in items {
        let length: u32 = u32::try_from(item.len())
            .map_err(|_| EnvelopeError::NestedItemLengthOverflow(item.len()))?;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(&item);
    }
    Ok(encoded)
}

/// Decodes all items before the owning result checks request binding.
pub fn decode_response_list(
    bytes: &[u8],
    count: usize,
) -> Result<Vec<NodeResponse>, NestedListDecodeError> {
    decode_nested_items(bytes, count, NodeResponse::decode)
}

pub(crate) fn decode_nested_items<T, F>(
    bytes: &[u8],
    count: usize,
    mut decode: F,
) -> Result<Vec<T>, NestedListDecodeError>
where
    F: FnMut(&[u8]) -> Result<T, EnvelopeError>,
{
    if count > MAX_NODE_OUTPUT_ITEMS {
        return Err(NestedListDecodeError::TooManyItems(count));
    }
    let mut offset: usize = 0;
    let mut items: Vec<T> = Vec::with_capacity(count);
    for _ in 0..count {
        let length_bytes: &[u8] = take_nested_bytes(bytes, &mut offset, 4)?;
        let length: usize = usize::try_from(u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]))
        .map_err(|_| NestedListDecodeError::LengthOverflow(usize::MAX))?;
        let value: T = decode(take_nested_bytes(bytes, &mut offset, length)?)
            .map_err(NestedListDecodeError::Item)?;
        items.push(value);
    }
    if offset != bytes.len() {
        return Err(NestedListDecodeError::TrailingBytes(bytes.len() - offset));
    }
    Ok(items)
}

fn take_nested_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], NestedListDecodeError> {
    let end: usize = offset
        .checked_add(length)
        .ok_or(NestedListDecodeError::OffsetOverflow)?;
    let value: &[u8] = bytes
        .get(*offset..end)
        .ok_or(NestedListDecodeError::Truncated {
            offset: *offset,
            needed: length,
            remaining: bytes.len().saturating_sub(*offset),
        })?;
    *offset = end;
    Ok(value)
}
