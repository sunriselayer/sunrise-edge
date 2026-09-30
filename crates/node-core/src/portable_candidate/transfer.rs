//! `PortableCandidateTransferItem` (frame `0x6492`): the one bounded unit one
//! [`super::driver::advance_portable_candidate_transfer`] call emits. A row
//! whose payload exceeds [`runtime::portable::MAX_PORTABLE_CHUNK_BYTES`]
//! spans multiple consecutive items sharing the same `collection`/`row_index`
//! and strictly increasing `chunk_offset`, terminated by `chunk_is_last`.
//! Each collection's final row is followed by exactly one
//! [`PortableCandidateBoundary::CollectionEnd`] item carrying that
//! collection's exact emitted row count; there is no separate whole-cut cap.
use super::*;

const PORTABLE_CANDIDATE_TRANSFER_ITEM_TYPE: u16 = 0x6492;
const ENCODING_VERSION: u16 = 1;
/// Generous headroom over one payload chunk for the key/descriptor/header
/// overhead; not a claim that every field independently reaches this bound.
pub const MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES: usize =
    MAX_PORTABLE_CHUNK_BYTES + 64 * 1024;

/// Canonical, collection-typed encoding of one [`DurableRecordKey`]. `State`
/// keys are already bounded and canonical by `validate_state_key`; the other
/// three collections use a fixed-width natural key with no ambiguity.
pub(crate) fn encode_durable_record_key(key: &DurableRecordKey) -> Vec<u8> {
    match key {
        DurableRecordKey::State(bytes) => bytes.clone(),
        DurableRecordKey::Receipt(id) => id.as_bytes().to_vec(),
        DurableRecordKey::ObjectHead(id) => id.as_bytes().to_vec(),
        DurableRecordKey::ObjectVersion(id, version) => {
            let mut bytes: Vec<u8> = id.as_bytes().to_vec();
            bytes.extend_from_slice(&version.get().to_be_bytes());
            bytes
        }
    }
}

pub(crate) fn decode_durable_record_key(
    collection: DurableCollection,
    bytes: &[u8],
) -> Result<DurableRecordKey, PortableCandidateError> {
    let key: DurableRecordKey = match collection {
        DurableCollection::State => DurableRecordKey::State(bytes.to_vec()),
        DurableCollection::Receipts => {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| PortableCandidateError::Invalid("invalid receipt key length"))?;
            DurableRecordKey::Receipt(
                DurableRequestId::new(array)
                    .map_err(|_| PortableCandidateError::Invalid("invalid receipt request id"))?,
            )
        }
        DurableCollection::ObjectHeads => {
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| PortableCandidateError::Invalid("invalid object head key length"))?;
            DurableRecordKey::ObjectHead(ObjectId::new(array))
        }
        DurableCollection::ObjectVersions => {
            if bytes.len() != 40 {
                return Err(PortableCandidateError::Invalid(
                    "invalid object version key length",
                ));
            }
            let mut id_bytes: [u8; 32] = [0; 32];
            id_bytes.copy_from_slice(&bytes[..32]);
            let mut version_bytes: [u8; 8] = [0; 8];
            version_bytes.copy_from_slice(&bytes[32..]);
            let version: DurableObjectVersion =
                DurableObjectVersion::new(u64::from_be_bytes(version_bytes)).ok_or(
                    PortableCandidateError::Invalid("zero object version in transfer key"),
                )?;
            DurableRecordKey::ObjectVersion(ObjectId::new(id_bytes), version)
        }
    };
    key.validate()?;
    if encode_durable_record_key(&key) != bytes {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate record key",
        ));
    }
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateRowTransfer {
    pub key: DurableRecordKey,
    pub descriptor: PortableCandidateDescriptor,
    pub chunk_offset: u64,
    pub chunk_bytes: Vec<u8>,
    pub chunk_is_last: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableCandidateBoundary {
    Row(PortableCandidateRowTransfer),
    /// Terminal marker for one collection; `row_count` is that collection's
    /// exact total emitted row count, independent of `PortableCandidateManifest`.
    CollectionEnd {
        row_count: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateTransferItem {
    /// Binds every item to one [`super::PortableCandidateIdentity`] root.
    pub identity_digest: Digest32,
    pub collection: DurableCollection,
    /// Zero-based, strictly increasing within `collection`.
    pub row_index: u64,
    pub boundary: PortableCandidateBoundary,
}

pub fn encode_portable_candidate_transfer_item(
    item: &PortableCandidateTransferItem,
) -> Result<Vec<u8>, PortableCandidateError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_TRANSFER_ITEM_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        canonical_encoding::encode_digest32(&item.identity_digest)?,
    )?;
    frame.field_u16(2, collection_tag(item.collection))?;
    frame.field_u64(3, item.row_index)?;
    match &item.boundary {
        PortableCandidateBoundary::Row(row) => {
            row.key.validate()?;
            let kind_matches: bool = matches!(
                (&row.descriptor, item.collection),
                (
                    PortableCandidateDescriptor::State { .. },
                    DurableCollection::State
                ) | (
                    PortableCandidateDescriptor::Receipt { .. },
                    DurableCollection::Receipts
                ) | (
                    PortableCandidateDescriptor::ObjectHead(_),
                    DurableCollection::ObjectHeads
                ) | (
                    PortableCandidateDescriptor::ObjectVersion { .. },
                    DurableCollection::ObjectVersions
                )
            );
            if row.key.collection() != item.collection || !kind_matches {
                return Err(PortableCandidateError::Invalid(
                    "transfer key/descriptor/collection mismatch",
                ));
            }
            frame.field_u16(4, 1)?;
            frame.field_bytes(5, encode_durable_record_key(&row.key))?;
            frame.field_bytes(6, encode_portable_candidate_descriptor(&row.descriptor)?)?;
            frame.field_u64(7, row.chunk_offset)?;
            if row.chunk_bytes.len() > MAX_PORTABLE_CHUNK_BYTES {
                return Err(PortableCandidateError::Invalid(
                    "candidate row chunk exceeds the fixed chunk bound",
                ));
            }
            frame.field_bytes(8, row.chunk_bytes.clone())?;
            frame.field_u16(9, u16::from(row.chunk_is_last))?;
        }
        PortableCandidateBoundary::CollectionEnd { row_count } => {
            frame.field_u16(4, 2)?;
            frame.field_u64(10, *row_count)?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate transfer item frame too large",
        ));
    }
    Ok(bytes)
}

pub fn decode_portable_candidate_transfer_item(
    input: &[u8],
) -> Result<PortableCandidateTransferItem, PortableCandidateError> {
    if input.len() > MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate transfer item frame too large",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PORTABLE_CANDIDATE_TRANSFER_ITEM_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let identity_digest: Digest32 = canonical_encoding::decode_digest32(frame.required_field(1)?)?;
    let collection: DurableCollection = collection_from_tag(frame.required_u16(2)?)?;
    let row_index: u64 = frame.required_u64(3)?;
    let kind: u16 = frame.required_u16(4)?;
    let boundary: PortableCandidateBoundary = match kind {
        1 => {
            frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
            let key: DurableRecordKey =
                decode_durable_record_key(collection, frame.required_field(5)?)?;
            let descriptor: PortableCandidateDescriptor =
                decode_portable_candidate_descriptor(frame.required_field(6)?)?;
            let chunk_offset: u64 = frame.required_u64(7)?;
            let chunk_bytes: Vec<u8> = frame.required_field(8)?.to_vec();
            if chunk_bytes.len() > MAX_PORTABLE_CHUNK_BYTES {
                return Err(PortableCandidateError::Invalid(
                    "candidate row chunk exceeds the fixed chunk bound",
                ));
            }
            let chunk_is_last: bool = frame.required_u16(9)? != 0;
            PortableCandidateBoundary::Row(PortableCandidateRowTransfer {
                key,
                descriptor,
                chunk_offset,
                chunk_bytes,
                chunk_is_last,
            })
        }
        2 => {
            frame.require_only_fields(&[1, 2, 3, 4, 10])?;
            PortableCandidateBoundary::CollectionEnd {
                row_count: frame.required_u64(10)?,
            }
        }
        _ => {
            return Err(PortableCandidateError::Invalid(
                "unknown candidate transfer boundary kind",
            ));
        }
    };
    let item = PortableCandidateTransferItem {
        identity_digest,
        collection,
        row_index,
        boundary,
    };
    if encode_portable_candidate_transfer_item(&item)? != input {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate transfer item",
        ));
    }
    Ok(item)
}
