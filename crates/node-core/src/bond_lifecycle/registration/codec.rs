//! Closed bounded DR-0179 frames. Decoding alone grants no authority.
use super::*;
use execution::publication::{decode_publication_context, encode_publication_context};

const INTENT_TYPE: u16 = 0x64E0;
const SIGNED_TYPE: u16 = 0x64E1;
const ANCHOR_TYPE: u16 = 0x64E2;
const VERSION: u16 = 1;

fn valid_context(context: &PublicationContext) -> Result<(), BondRegistrationError> {
    if context.chain_id().as_str().len() > 128 || context.protocol_version().get() == 0 {
        return Err(BondRegistrationError::Invalid("registration context bound"));
    }
    Ok(())
}

fn valid_intent(intent: &BondRegistrationIntent) -> Result<(), BondRegistrationError> {
    valid_context(&intent.context)?;
    valid_context(&intent.resource_context)?;
    if intent.request_id == [0; 32]
        || intent.leg.is_empty()
        || intent.leg.len() > MAX_LOCAL_EXECUTION_INTENT_BYTES
        || intent.authorization_scheme != SignatureSchemeId::Ed25519
    {
        return Err(BondRegistrationError::Invalid(
            "registration intent shape or bound",
        ));
    }
    local_instance_state::reject_reserved_request_id(&intent.request_id)
        .map_err(BondRegistrationError::Invalid)?;
    Ok(())
}

/// Encode exactly `0x64E0/v1`, preserving the embedded signed leg bytes.
pub fn encode_bond_registration_intent(
    intent: &BondRegistrationIntent,
) -> Result<Vec<u8>, BondRegistrationError> {
    valid_intent(intent)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(INTENT_TYPE, VERSION);
    frame.field_bytes(1, encode_publication_context(&intent.context)?)?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(3, intent.validator_id.as_bytes().to_vec())?;
    frame.field_u16(4, intent.authorization_scheme.as_u16())?;
    frame.field_bytes(5, intent.authorization_key.to_vec())?;
    frame.field_bytes(6, encode_publication_context(&intent.resource_context)?)?;
    frame.field_bytes(
        7,
        bonds::encode_bond_resource_id(intent.resource)
            .map_err(|_| BondRegistrationError::Invalid("registration resource encoding"))?,
    )?;
    frame.field_bytes(8, intent.leg.clone())?;
    frame.field_bytes(9, encode_digest32(&intent.expected_initial_row_digest)?)?;
    frame.field_bytes(10, encode_digest32(&intent.pinned_genesis_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_REGISTRATION_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration intent byte bound",
        ));
    }
    Ok(bytes)
}

/// Strict bounded decode, closed fields and byte-exact canonical recoding.
pub fn decode_bond_registration_intent(
    bytes: &[u8],
) -> Result<BondRegistrationIntent, BondRegistrationError> {
    if bytes.len() > MAX_BOND_REGISTRATION_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration intent byte bound",
        ));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(INTENT_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let leg: &[u8] = frame.required_field(8)?;
    if leg.is_empty() || leg.len() > MAX_LOCAL_EXECUTION_INTENT_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration leg byte bound",
        ));
    }
    // Each fixed-width field is checked before the bounded leg is copied.
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| BondRegistrationError::Invalid("registration request length"))?;
    let id: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| BondRegistrationError::Invalid("registration validator length"))?;
    let key: [u8; 32] = frame
        .required_field(5)?
        .try_into()
        .map_err(|_| BondRegistrationError::Invalid("registration key length"))?;
    if frame.required_u16(4)? != SignatureSchemeId::Ed25519.as_u16() {
        return Err(BondRegistrationError::Invalid(
            "registration signature scheme",
        ));
    }
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)?;
    let resource_context: PublicationContext =
        decode_publication_context(frame.required_field(6)?)?;
    valid_context(&context)?;
    valid_context(&resource_context)?;
    let intent: BondRegistrationIntent = BondRegistrationIntent {
        context,
        request_id,
        validator_id: ValidatorId::new(id),
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: key,
        resource_context,
        resource: bonds::decode_bond_resource_id(frame.required_field(7)?)
            .map_err(|_| BondRegistrationError::Invalid("registration resource decoding"))?,
        leg: leg.to_vec(),
        expected_initial_row_digest: decode_digest32(frame.required_field(9)?)?,
        pinned_genesis_digest: decode_digest32(frame.required_field(10)?)?,
    };
    if encode_bond_registration_intent(&intent)? != bytes {
        return Err(BondRegistrationError::Invalid(
            "noncanonical registration intent",
        ));
    }
    Ok(intent)
}

/// Encode exact signed envelope `0x64E1/v1`.
pub fn encode_signed_bond_registration_intent(
    signed: &SignedBondRegistrationIntent,
) -> Result<Vec<u8>, BondRegistrationError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(SIGNED_TYPE, VERSION);
    frame.field_bytes(1, encode_bond_registration_intent(&signed.intent)?)?;
    frame.field_bytes(2, signed.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_REGISTRATION_BYTES {
        return Err(BondRegistrationError::Invalid(
            "signed registration byte bound",
        ));
    }
    Ok(bytes)
}

/// Strict bounded decode of exact signed envelope; no execution authority.
pub fn decode_signed_bond_registration_intent(
    bytes: &[u8],
) -> Result<SignedBondRegistrationIntent, BondRegistrationError> {
    if bytes.len() > MAX_BOND_REGISTRATION_BYTES {
        return Err(BondRegistrationError::Invalid(
            "signed registration byte bound",
        ));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SIGNED_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let signature: [u8; 64] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| BondRegistrationError::Invalid("registration signature length"))?;
    let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent {
        intent: decode_bond_registration_intent(frame.required_field(1)?)?,
        signature,
    };
    if encode_signed_bond_registration_intent(&signed)? != bytes {
        return Err(BondRegistrationError::Invalid(
            "noncanonical signed registration",
        ));
    }
    Ok(signed)
}

/// Encode immutable anchor `0x64E2/v1`; linkage/signatures checked by owner.
pub fn encode_bond_registration_anchor(
    anchor: &BondRegistrationAnchor,
) -> Result<Vec<u8>, BondRegistrationError> {
    valid_context(&anchor.context)?;
    if anchor.signed_registration.is_empty()
        || anchor.signed_registration.len() > MAX_BOND_REGISTRATION_BYTES
        || anchor.resulting_row.is_empty()
        || anchor.resulting_row.len() > MAX_BOND_REGISTRATION_ROW_BYTES
    {
        return Err(BondRegistrationError::Invalid(
            "registration anchor component bound",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(ANCHOR_TYPE, VERSION);
    frame.field_bytes(1, encode_publication_context(&anchor.context)?)?;
    frame.field_bytes(2, anchor.validator_id.as_bytes().to_vec())?;
    frame.field_bytes(3, anchor.signed_registration.clone())?;
    frame.field_bytes(4, anchor.resulting_row.clone())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_BOND_REGISTRATION_ANCHOR_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration anchor byte bound",
        ));
    }
    Ok(bytes)
}

/// Strict bounded anchor decoder, preserving original signed/hash-linked bytes.
pub fn decode_bond_registration_anchor(
    bytes: &[u8],
) -> Result<BondRegistrationAnchor, BondRegistrationError> {
    if bytes.len() > MAX_BOND_REGISTRATION_ANCHOR_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration anchor byte bound",
        ));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ANCHOR_TYPE)?;
    frame.require_version(VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let envelope: &[u8] = frame.required_field(3)?;
    let row: &[u8] = frame.required_field(4)?;
    if envelope.is_empty()
        || envelope.len() > MAX_BOND_REGISTRATION_BYTES
        || row.is_empty()
        || row.len() > MAX_BOND_REGISTRATION_ROW_BYTES
    {
        return Err(BondRegistrationError::Invalid(
            "registration anchor component bound",
        ));
    }
    let id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| BondRegistrationError::Invalid("registration anchor validator length"))?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)?;
    valid_context(&context)?;
    let anchor: BondRegistrationAnchor = BondRegistrationAnchor {
        context,
        validator_id: ValidatorId::new(id),
        signed_registration: envelope.to_vec(),
        resulting_row: row.to_vec(),
    };
    if encode_bond_registration_anchor(&anchor)? != bytes {
        return Err(BondRegistrationError::Invalid(
            "noncanonical registration anchor",
        ));
    }
    Ok(anchor)
}
