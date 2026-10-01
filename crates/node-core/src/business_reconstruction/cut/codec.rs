//! Swept new DR-0175 namespace 0x64B0..0x64BA. No historical frame changes.
use super::*;
use crate::ordered_economics::{decode_ordered_history_identity, encode_ordered_history_identity};
use canonical_encoding::{CanonicalFrame, decode_canonical_frame};
use execution::publication::{decode_publication_context, encode_publication_context};

const VERSION: u16 = 1;

fn bounded(bytes: &[u8], maximum: usize) -> Result<(), BusinessCutError> {
    if bytes.len() > maximum {
        return Err(invalid("business cut frame byte capacity"));
    }
    Ok(())
}
fn frame<'a>(
    bytes: &'a [u8],
    tag: u16,
    fields: &[u16],
    maximum: usize,
) -> Result<CanonicalFrame<'a>, BusinessCutError> {
    bounded(bytes, maximum)?;
    let value: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    value.require_type(tag)?;
    value.require_version(VERSION)?;
    value.require_only_fields(fields)?;
    Ok(value)
}
fn same(bytes: &[u8], encoded: Vec<u8>) -> Result<(), BusinessCutError> {
    if bytes != encoded {
        return Err(invalid("noncanonical business cut frame"));
    }
    Ok(())
}
pub(super) fn boolean(frame: &CanonicalFrame<'_>, field: u16) -> Result<bool, BusinessCutError> {
    match frame.required_u16(field)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("business cut boolean tag")),
    }
}
pub(super) fn encode_root(value: &BusinessCutCollectionRoot) -> Result<Vec<u8>, BusinessCutError> {
    let mut value_frame: CanonicalStruct = CanonicalStruct::new(0x64B1, VERSION);
    value_frame.field_u16(1, value.collection as u16)?;
    value_frame.field_u64(2, value.count)?;
    value_frame.field_bytes(3, encode_digest32(&value.root)?)?;
    Ok(value_frame.finish()?)
}
fn decode_root(bytes: &[u8]) -> Result<BusinessCutCollectionRoot, BusinessCutError> {
    let value = frame(bytes, 0x64B1, &[1, 2, 3], MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
    let result: BusinessCutCollectionRoot = BusinessCutCollectionRoot {
        collection: BusinessCutCollection::from_wire(value.required_u16(1)?)?,
        count: value.required_u64(2)?,
        root: decode_digest32(value.required_field(3)?)?,
    };
    same(bytes, encode_root(&result)?)?;
    Ok(result)
}
fn identity_shape(value: &BusinessCutIdentity) -> Result<(), BusinessCutError> {
    if value.ordered_history.context != value.context
        || value.ordered_history.domain != value.domain
        || value.ordered_history.genesis_digest != value.genesis_digest
        || value.drain_union.chain_id != *value.context.chain_id()
        || value.drain_union.protocol_version != value.context.protocol_version()
        || value.drain_union.epoch != value.context.epoch()
        || value.drain_union.domain != value.domain
        || value.drain_block_height == 0
        || value.drain_block_height >= value.ordered_history.through_height
        || value.drain_union.closure_height >= value.drain_block_height
        || value.drain_request_id == [0; 32]
        || value.drain_request_id[0] & 0x80 == 0
        || value.artifacts.collection != BusinessCutCollection::Artifacts
    {
        return Err(invalid("business cut identity context/control shape"));
    }
    for (index, root) in value.business.iter().enumerate() {
        if root.collection != BUSINESS_CUT_STREAMS[index] {
            return Err(invalid("business cut root order"));
        }
    }
    Ok(())
}
pub fn encode_business_cut_identity(
    value: &BusinessCutIdentity,
) -> Result<Vec<u8>, BusinessCutError> {
    identity_shape(value)?;
    let mut result: CanonicalStruct = CanonicalStruct::new(0x64B0, VERSION);
    result.field_bytes(
        1,
        encode_publication_context(&value.context).map_err(|_| invalid("cut context encoding"))?,
    )?;
    result.field_bytes(2, value.domain.as_bytes().to_vec())?;
    result.field_bytes(3, encode_digest32(&value.genesis_digest)?)?;
    result.field_bytes(4, encode_digest32(&value.validator_set_digest)?)?;
    result.field_bytes(
        5,
        encode_ordered_history_identity(&value.ordered_history)
            .map_err(|_| invalid("cut history encoding"))?,
    )?;
    result.field_bytes(6, value.drain_request_id.to_vec())?;
    result.field_u64(7, value.drain_block_height)?;
    result.field_bytes(8, encode_digest32(&value.drain_candidate_digest)?)?;
    result.field_bytes(
        9,
        consensus::encode_drain_union_identity(&value.drain_union)
            .map_err(|_| invalid("cut union encoding"))?,
    )?;
    result.field_u64(10, value.generation_floor.get())?;
    for (index, root) in value.business.iter().enumerate() {
        result.field_bytes(
            u16::try_from(index + 11).map_err(|_| invalid("cut root field"))?,
            encode_root(root)?,
        )?;
    }
    result.field_bytes(15, encode_root(&value.artifacts)?)?;
    let bytes: Vec<u8> = result.finish()?;
    bounded(&bytes, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
    Ok(bytes)
}
pub fn decode_business_cut_identity(bytes: &[u8]) -> Result<BusinessCutIdentity, BusinessCutError> {
    let value = frame(
        bytes,
        0x64B0,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
    )?;
    let domain: [u8; 32] = value
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("cut domain length"))?;
    let request: [u8; 32] = value
        .required_field(6)?
        .try_into()
        .map_err(|_| invalid("cut request length"))?;
    let result: BusinessCutIdentity = BusinessCutIdentity {
        context: decode_publication_context(value.required_field(1)?)
            .map_err(|_| invalid("cut context schema"))?,
        domain: AtomicityDomainId::new(domain).map_err(|_| invalid("cut invalid domain"))?,
        genesis_digest: decode_digest32(value.required_field(3)?)?,
        validator_set_digest: decode_digest32(value.required_field(4)?)?,
        ordered_history: decode_ordered_history_identity(value.required_field(5)?)
            .map_err(|_| invalid("cut history schema"))?,
        drain_request_id: request,
        drain_block_height: value.required_u64(7)?,
        drain_candidate_digest: decode_digest32(value.required_field(8)?)?,
        drain_union: consensus::decode_drain_union_identity(value.required_field(9)?)
            .map_err(|_| invalid("cut union schema"))?,
        generation_floor: ExecutionGeneration::new(value.required_u64(10)?),
        business: [
            decode_root(value.required_field(11)?)?,
            decode_root(value.required_field(12)?)?,
            decode_root(value.required_field(13)?)?,
            decode_root(value.required_field(14)?)?,
        ],
        artifacts: decode_root(value.required_field(15)?)?,
    };
    same(bytes, encode_business_cut_identity(&result)?)?;
    Ok(result)
}
pub fn encode_business_cut_package(
    value: &BusinessCutPackageIdentity,
) -> Result<Vec<u8>, BusinessCutError> {
    let mut total: u64 = 0;
    for (index, root) in value.streams.iter().enumerate() {
        if root.collection != BUSINESS_CUT_STREAMS[index] {
            return Err(invalid("cut package stream order"));
        }
        total = total
            .checked_add(root.count)
            .ok_or(invalid("cut package count overflow"))?;
    }
    if total != value.component_count {
        return Err(invalid("cut package count differs"));
    }
    let mut result: CanonicalStruct = CanonicalStruct::new(0x64B2, VERSION);
    result.field_bytes(1, encode_digest32(&value.cut_digest)?)?;
    result.field_u64(2, value.component_count)?;
    result.field_bytes(3, encode_digest32(&value.accumulator)?)?;
    for (index, root) in value.streams.iter().enumerate() {
        result.field_bytes(
            u16::try_from(index + 4).map_err(|_| invalid("cut package field"))?,
            encode_root(root)?,
        )?;
    }
    let bytes: Vec<u8> = result.finish()?;
    bounded(&bytes, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
    Ok(bytes)
}
pub fn decode_business_cut_package(
    bytes: &[u8],
) -> Result<BusinessCutPackageIdentity, BusinessCutError> {
    let value = frame(
        bytes,
        0x64B2,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
    )?;
    let result: BusinessCutPackageIdentity = BusinessCutPackageIdentity {
        cut_digest: decode_digest32(value.required_field(1)?)?,
        component_count: value.required_u64(2)?,
        accumulator: decode_digest32(value.required_field(3)?)?,
        streams: [
            decode_root(value.required_field(4)?)?,
            decode_root(value.required_field(5)?)?,
            decode_root(value.required_field(6)?)?,
            decode_root(value.required_field(7)?)?,
            decode_root(value.required_field(8)?)?,
            decode_root(value.required_field(9)?)?,
            decode_root(value.required_field(10)?)?,
        ],
    };
    same(bytes, encode_business_cut_package(&result)?)?;
    Ok(result)
}

/// Closed metadata schema. Decoding does not authenticate its observations.
pub(super) fn metadata_tag(bytes: &[u8]) -> Result<u16, BusinessCutError> {
    bounded(bytes, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
    let value: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    value.require_type(0x64B9)?;
    value.require_version(VERSION)?;
    let tag: u16 = value.required_u16(1)?;
    match tag {
        1 => {
            value.require_only_fields(&[1, 2])?;
            boolean(&value, 2)?;
        }
        2 => {
            value.require_only_fields(&[1, 2])?;
            decode_digest32(value.required_field(2)?)?;
        }
        3 => {
            value.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
            let live: bool = boolean(&value, 2)?;
            if value.required_u64(3)? == 0 {
                return Err(invalid("cut object head version"));
            }
            if live {
                decode_digest32(value.required_field(4)?)?;
            } else if !value.required_field(4)?.is_empty() {
                return Err(invalid("tombstone head digest"));
            }
            for (flag, body) in [(5, 6), (7, 8)] {
                let present: bool = boolean(&value, flag)?;
                if (!present && !value.required_field(body)?.is_empty())
                    || (!live && present)
                    || value.required_field(body)?.len()
                        > runtime::MAX_DURABLE_OBJECT_PROJECTION_BYTES
                {
                    return Err(invalid("cut head projection shape"));
                }
            }
        }
        4 => {
            value.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
            decode_digest32(value.required_field(2)?)?;
            if value.required_u32(3)? == 0 {
                return Err(invalid("cut object schema"));
            }
            let encoded: &[u8] = value.required_field(4)?;
            let chain_frame = frame(encoded, 0x0105, &[1], MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
            let chain: protocol_types::ChainId = protocol_types::ChainId::new(
                std::str::from_utf8(chain_frame.required_field(1)?)
                    .map_err(|_| invalid("cut provenance chain UTF8"))?,
            )
            .map_err(|_| invalid("cut provenance chain identity"))?;
            if canonical_encoding::encode_chain_id(&chain)? != encoded {
                return Err(invalid("noncanonical cut provenance chain"));
            }
            value.required_u32(5)?;
            match value.required_u16(6)? {
                1 if value.required_field(7)?.is_empty() => {}
                2 => {
                    decode_digest32(value.required_field(7)?)?;
                }
                _ => return Err(invalid("cut object payload descriptor")),
            }
        }
        5 => {
            value.require_only_fields(&[1, 2, 3])?;
            consensus::bundle::ArtifactKind::from_u16(value.required_u16(2)?)
                .map_err(|_| invalid("cut artifact kind"))?;
            decode_digest32(value.required_field(3)?)?;
        }
        6 => {
            value.require_only_fields(&[1, 2])?;
            proof::ProofKind::from_wire(value.required_u16(2)?)?;
        }
        _ => return Err(invalid("unknown cut component metadata")),
    }
    Ok(tag)
}
fn descriptor_shape(value: &BusinessCutComponentDescriptor) -> Result<(), BusinessCutError> {
    let tag: u16 = metadata_tag(&value.metadata)?;
    let key_ok: bool = match value.collection {
        BusinessCutCollection::State => {
            tag == 1 && !value.key.is_empty() && value.key.len() <= runtime::MAX_STATE_KEY_BYTES
        }
        BusinessCutCollection::Receipts => tag == 2 && value.key.len() == 32,
        BusinessCutCollection::ObjectHeads => {
            tag == 3 && value.key.len() == 32 && value.length == 0
        }
        BusinessCutCollection::ObjectVersions => tag == 4 && value.key.len() == 40,
        BusinessCutCollection::AuthorityCompanions => match value.key.split_first() {
            Some((1, tail)) => {
                tag == 1 && !tail.is_empty() && tail.len() <= runtime::MAX_STATE_KEY_BYTES
            }
            Some((2, tail)) => tag == 2 && tail.len() == 32,
            _ => false,
        },
        BusinessCutCollection::Artifacts => {
            if tag != 5 {
                false
            } else {
                let metadata: CanonicalFrame<'_> = decode_canonical_frame(&value.metadata)?;
                let kind: consensus::bundle::ArtifactKind =
                    consensus::bundle::ArtifactKind::from_u16(metadata.required_u16(2)?)
                        .map_err(|_| invalid("cut artifact kind"))?;
                let digest: Digest32 = decode_digest32(metadata.required_field(3)?)?;
                let mut expected: Vec<u8> = kind.as_u16().to_be_bytes().to_vec();
                expected.extend(encode_digest32(&digest)?);
                value.key == expected
            }
        }
        BusinessCutCollection::Proofs => {
            tag == 6 && proof::validate_key(&value.key, &value.metadata).is_ok()
        }
    };
    if !key_ok || value.length > body_bound(value)? as u64 {
        return Err(invalid("cut component key/length/schema"));
    }
    if tag == 1 {
        let metadata: CanonicalFrame<'_> = decode_canonical_frame(&value.metadata)?;
        if !boolean(&metadata, 2)? && value.length != 0 {
            return Err(invalid("tombstone component body"));
        }
    }
    Ok(())
}
pub(super) fn body_bound(
    value: &BusinessCutComponentDescriptor,
) -> Result<usize, BusinessCutError> {
    let tag: u16 = metadata_tag(&value.metadata)?;
    Ok(match tag {
        1 => runtime::MAX_STATE_VALUE_BYTES,
        2 => runtime::MAX_DURABLE_RECEIPT_BYTES,
        3 => 0,
        4 => runtime::MAX_DURABLE_INLINE_OBJECT_BYTES,
        5 => consensus::bundle::MAX_ARTIFACT_CONTENT_BYTES,
        6 => {
            let metadata = decode_canonical_frame(&value.metadata)?;
            let kind = proof::ProofKind::from_wire(metadata.required_u16(2)?)?;
            if kind == proof::ProofKind::HistoryComponent {
                let tag: [u8; 2] = value
                    .key
                    .get(9..11)
                    .ok_or(invalid("cut history component key length"))?
                    .try_into()
                    .map_err(|_| invalid("cut history component kind length"))?;
                crate::ordered_economics::OrderedHistoryComponentKind::from_wire(
                    u16::from_be_bytes(tag),
                )
                .map_err(|_| invalid("cut history component kind"))?
                .max_bytes()
            } else {
                kind.max_bytes()
            }
        }
        _ => return Err(invalid("cut body kind")),
    })
}
pub fn encode_business_cut_descriptor(
    value: &BusinessCutComponentDescriptor,
) -> Result<Vec<u8>, BusinessCutError> {
    descriptor_shape(value)?;
    let mut result: CanonicalStruct = CanonicalStruct::new(0x64B3, VERSION);
    result.field_u16(1, value.collection as u16)?;
    result.field_bytes(2, value.key.clone())?;
    result.field_bytes(3, value.metadata.clone())?;
    result.field_u64(4, value.length)?;
    result.field_bytes(5, encode_digest32(&value.digest)?)?;
    let bytes: Vec<u8> = result.finish()?;
    bounded(&bytes, MAX_BUSINESS_CUT_DESCRIPTOR_BYTES)?;
    Ok(bytes)
}
pub fn decode_business_cut_descriptor(
    bytes: &[u8],
) -> Result<BusinessCutComponentDescriptor, BusinessCutError> {
    let value = frame(
        bytes,
        0x64B3,
        &[1, 2, 3, 4, 5],
        MAX_BUSINESS_CUT_DESCRIPTOR_BYTES,
    )?;
    let result: BusinessCutComponentDescriptor = BusinessCutComponentDescriptor {
        collection: BusinessCutCollection::from_wire(value.required_u16(1)?)?,
        key: value.required_field(2)?.to_vec(),
        metadata: value.required_field(3)?.to_vec(),
        length: value.required_u64(4)?,
        digest: decode_digest32(value.required_field(5)?)?,
    };
    same(bytes, encode_business_cut_descriptor(&result)?)?;
    Ok(result)
}
pub fn encode_business_cut_page(value: &BusinessCutPage) -> Result<Vec<u8>, BusinessCutError> {
    if value.descriptors.len() > MAX_BUSINESS_CUT_PAGE_ENTRIES
        || (!value.terminal && value.descriptors.is_empty())
        || value.after_key.as_ref().is_some_and(Vec::is_empty)
    {
        return Err(invalid("cut page shape"));
    }
    let mut previous: Option<&[u8]> = value.after_key.as_deref();
    let mut result: CanonicalStruct = CanonicalStruct::new(0x64B4, VERSION);
    result.field_bytes(1, encode_digest32(&value.cut_digest)?)?;
    result.field_bytes(2, encode_digest32(&value.package_digest)?)?;
    result.field_u16(3, value.collection as u16)?;
    result.field_bytes(4, value.after_key.clone().unwrap_or_default())?;
    result.field_bytes(5, encode_digest32(&value.previous_accumulator)?)?;
    result.field_bytes(6, encode_digest32(&value.accumulator)?)?;
    result.field_u16(7, u16::from(value.terminal))?;
    result.field_u16(
        8,
        u16::try_from(value.descriptors.len()).map_err(|_| invalid("cut page count"))?,
    )?;
    for (index, descriptor) in value.descriptors.iter().enumerate() {
        if descriptor.collection != value.collection
            || previous.is_some_and(|key| descriptor.key.as_slice() <= key)
        {
            return Err(invalid("cut page collection/key order"));
        }
        result.field_bytes(
            u16::try_from(index + 9).map_err(|_| invalid("cut page field"))?,
            encode_business_cut_descriptor(descriptor)?,
        )?;
        previous = Some(&descriptor.key);
    }
    let bytes: Vec<u8> = result.finish()?;
    bounded(&bytes, MAX_BUSINESS_CUT_PAGE_BYTES)?;
    Ok(bytes)
}
pub fn decode_business_cut_page(bytes: &[u8]) -> Result<BusinessCutPage, BusinessCutError> {
    bounded(bytes, MAX_BUSINESS_CUT_PAGE_BYTES)?;
    let value: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    value.require_type(0x64B4)?;
    value.require_version(VERSION)?;
    let count: usize = usize::from(value.required_u16(8)?);
    if count > MAX_BUSINESS_CUT_PAGE_ENTRIES {
        return Err(invalid("cut page count capacity"));
    }
    let fields: Vec<u16> =
        (1..=u16::try_from(8 + count).map_err(|_| invalid("cut page fields"))?).collect();
    value.require_only_fields(&fields)?;
    let mut descriptors: Vec<BusinessCutComponentDescriptor> = Vec::with_capacity(count);
    for index in 0..count {
        descriptors.push(decode_business_cut_descriptor(value.required_field(
            u16::try_from(9 + index).map_err(|_| invalid("cut page field"))?,
        )?)?);
    }
    let cursor: &[u8] = value.required_field(4)?;
    let result: BusinessCutPage = BusinessCutPage {
        cut_digest: decode_digest32(value.required_field(1)?)?,
        package_digest: decode_digest32(value.required_field(2)?)?,
        collection: BusinessCutCollection::from_wire(value.required_u16(3)?)?,
        after_key: if cursor.is_empty() {
            None
        } else {
            Some(cursor.to_vec())
        },
        previous_accumulator: decode_digest32(value.required_field(5)?)?,
        accumulator: decode_digest32(value.required_field(6)?)?,
        terminal: boolean(&value, 7)?,
        descriptors,
    };
    same(bytes, encode_business_cut_page(&result)?)?;
    Ok(result)
}
pub fn encode_business_cut_chunk(value: &BusinessCutChunk) -> Result<Vec<u8>, BusinessCutError> {
    if value.bytes.len() > MAX_BUSINESS_CUT_CHUNK_BYTES
        || value.total_length != value.descriptor.length
        || value
            .offset
            .checked_add(value.bytes.len() as u64)
            .is_none_or(|end| end > value.total_length)
        || (value.bytes.is_empty() && value.total_length != 0)
    {
        return Err(invalid("cut chunk range/byte capacity"));
    }
    let mut result: CanonicalStruct = CanonicalStruct::new(0x64B5, VERSION);
    result.field_bytes(1, encode_digest32(&value.cut_digest)?)?;
    result.field_bytes(2, encode_digest32(&value.package_digest)?)?;
    result.field_bytes(3, encode_business_cut_descriptor(&value.descriptor)?)?;
    result.field_u64(4, value.offset)?;
    result.field_u64(5, value.total_length)?;
    result.field_bytes(6, value.bytes.clone())?;
    Ok(result.finish()?)
}
pub fn decode_business_cut_chunk(bytes: &[u8]) -> Result<BusinessCutChunk, BusinessCutError> {
    let value = frame(
        bytes,
        0x64B5,
        &[1, 2, 3, 4, 5, 6],
        MAX_BUSINESS_CUT_CHUNK_BYTES + MAX_BUSINESS_CUT_DESCRIPTOR_BYTES + 1024,
    )?;
    let result: BusinessCutChunk = BusinessCutChunk {
        cut_digest: decode_digest32(value.required_field(1)?)?,
        package_digest: decode_digest32(value.required_field(2)?)?,
        descriptor: decode_business_cut_descriptor(value.required_field(3)?)?,
        offset: value.required_u64(4)?,
        total_length: value.required_u64(5)?,
        bytes: value.required_field(6)?.to_vec(),
    };
    same(bytes, encode_business_cut_chunk(&result)?)?;
    Ok(result)
}
