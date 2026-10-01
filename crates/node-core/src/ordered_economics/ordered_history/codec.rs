//! New DR-0169 frames only. Existing proofs, candidates, receipts and keys keep
//! their original codecs. No all-components content superframe is defined.
use super::*;
use canonical_encoding::decode_canonical_frame;

const IDENTITY_TYPE: u16 = 0x6490;
const COMPONENT_TYPE: u16 = 0x6491;
const DESCRIPTOR_TYPE: u16 = 0x6492;
const SUMMARY_TYPE: u16 = 0x6493;
const VERSION: u16 = 1;

fn require_small(bytes: &[u8]) -> Result<(), OrderedEconomicsError> {
    if bytes.len() > MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES {
        return Err(invalid("ordered history descriptor byte capacity"));
    }
    Ok(())
}

pub fn encode_ordered_history_identity(
    value: &OrderedHistoryIdentity,
) -> Result<Vec<u8>, OrderedEconomicsError> {
    if (value.through_height == 0
        && (value.through_view != 0 || value.through_digest != value.anchor))
        || (value.through_height != 0 && value.through_view == 0)
    {
        return Err(invalid("ordered history identity target shape"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(IDENTITY_TYPE, VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&value.context)
            .map_err(|_| invalid("ordered history context encoding"))?,
    )?;
    frame.field_bytes(2, value.domain.as_bytes().to_vec())?;
    frame.field_bytes(3, encode_digest32(&value.genesis_digest)?)?;
    frame.field_bytes(4, encode_digest32(&value.anchor)?)?;
    frame.field_u64(5, value.through_height)?;
    frame.field_u64(6, value.through_view)?;
    frame.field_bytes(7, encode_digest32(&value.through_digest)?)?;
    Ok(frame.finish()?)
}

pub fn decode_ordered_history_identity(
    bytes: &[u8],
) -> Result<OrderedHistoryIdentity, OrderedEconomicsError> {
    require_small(bytes)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(IDENTITY_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
    let domain: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("ordered history domain length"))?;
    let value: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("ordered history context decoding"))?,
        domain: AtomicityDomainId::new(domain)
            .map_err(|_| invalid("ordered history invalid domain"))?,
        genesis_digest: decode_digest32(frame.required_field(3)?)?,
        anchor: decode_digest32(frame.required_field(4)?)?,
        through_height: frame.required_u64(5)?,
        through_view: frame.required_u64(6)?,
        through_digest: decode_digest32(frame.required_field(7)?)?,
    };
    if encode_ordered_history_identity(&value)?.as_slice() != bytes {
        return Err(invalid("noncanonical ordered history identity"));
    }
    Ok(value)
}

fn encode_component(value: &OrderedHistoryComponentRef) -> Result<Vec<u8>, OrderedEconomicsError> {
    if value.length == 0 || value.length > value.kind.max_bytes() as u64 {
        return Err(invalid("ordered history component length"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(COMPONENT_TYPE, VERSION);
    frame.field_u16(1, value.kind as u16)?;
    frame.field_u64(2, value.length)?;
    frame.field_bytes(3, encode_digest32(&value.digest)?)?;
    Ok(frame.finish()?)
}

fn decode_component(bytes: &[u8]) -> Result<OrderedHistoryComponentRef, OrderedEconomicsError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(COMPONENT_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let value: OrderedHistoryComponentRef = OrderedHistoryComponentRef {
        kind: OrderedHistoryComponentKind::from_wire(frame.required_u16(1)?)?,
        length: frame.required_u64(2)?,
        digest: decode_digest32(frame.required_field(3)?)?,
    };
    if encode_component(&value)?.as_slice() != bytes {
        return Err(invalid("noncanonical ordered history component"));
    }
    Ok(value)
}

pub fn encode_ordered_history_height_descriptor(
    value: &OrderedHistoryHeightDescriptor,
) -> Result<Vec<u8>, OrderedEconomicsError> {
    value.validate_shape()?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(DESCRIPTOR_TYPE, VERSION);
    frame.field_bytes(1, encode_ordered_history_identity(&value.identity)?)?;
    frame.field_u64(2, value.height)?;
    frame.field_u64(3, value.view)?;
    frame.field_bytes(4, encode_digest32(&value.block_digest)?)?;
    frame.field_u16(
        5,
        u16::try_from(value.components.len())
            .map_err(|_| invalid("ordered history component count"))?,
    )?;
    for (index, value) in value.components.iter().enumerate() {
        let field: u16 =
            u16::try_from(index + 6).map_err(|_| invalid("ordered history component field"))?;
        frame.field_bytes(field, encode_component(value)?)?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    require_small(&bytes)?;
    Ok(bytes)
}

pub fn decode_ordered_history_height_descriptor(
    bytes: &[u8],
) -> Result<OrderedHistoryHeightDescriptor, OrderedEconomicsError> {
    require_small(bytes)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(DESCRIPTOR_TYPE)?;
    frame.require_version(VERSION)?;
    let count: usize = usize::from(frame.required_u16(5)?);
    if count == 0 || count > MAX_ORDERED_HISTORY_COMPONENTS {
        return Err(invalid("ordered history component count"));
    }
    let fields: Vec<u16> = (1..=u16::try_from(5 + count)
        .map_err(|_| invalid("ordered history component field"))?)
        .collect();
    frame.require_only_fields(&fields)?;
    let mut components: Vec<OrderedHistoryComponentRef> = Vec::with_capacity(count);
    for index in 0..count {
        let field: u16 =
            u16::try_from(index + 6).map_err(|_| invalid("ordered history component field"))?;
        components.push(decode_component(frame.required_field(field)?)?);
    }
    let value: OrderedHistoryHeightDescriptor = OrderedHistoryHeightDescriptor {
        identity: decode_ordered_history_identity(frame.required_field(1)?)?,
        height: frame.required_u64(2)?,
        view: frame.required_u64(3)?,
        block_digest: decode_digest32(frame.required_field(4)?)?,
        components,
    };
    if encode_ordered_history_height_descriptor(&value)?.as_slice() != bytes {
        return Err(invalid("noncanonical ordered history descriptor"));
    }
    Ok(value)
}

pub fn encode_ordered_history_summary(
    value: &OrderedHistorySummary,
) -> Result<Vec<u8>, OrderedEconomicsError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(SUMMARY_TYPE, VERSION);
    frame.field_bytes(1, encode_ordered_history_identity(&value.identity)?)?;
    Ok(frame.finish()?)
}

pub fn decode_ordered_history_summary(
    bytes: &[u8],
) -> Result<OrderedHistorySummary, OrderedEconomicsError> {
    require_small(bytes)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SUMMARY_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1])?;
    let value: OrderedHistorySummary = OrderedHistorySummary {
        identity: decode_ordered_history_identity(frame.required_field(1)?)?,
    };
    if encode_ordered_history_summary(&value)?.as_slice() != bytes {
        return Err(invalid("noncanonical ordered history summary"));
    }
    Ok(value)
}
