use super::*;

fn claims() -> SignedBondRegistrationIntent {
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("registration-vector").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(2),
    )
    .unwrap();
    let digest: Digest32 = Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x22; 32]);
    SignedBondRegistrationIntent {
        intent: BondRegistrationIntent {
            context: context.clone(),
            request_id: [0x81; 32],
            validator_id: ValidatorId::new([0x33; 32]),
            authorization_scheme: SignatureSchemeId::Ed25519,
            authorization_key: [0x33; 32],
            resource_context: context,
            resource: BondResourceId::new(7, [0x55; 32]).unwrap(),
            leg: b"leg".to_vec(),
            expected_initial_row_digest: digest,
            pinned_genesis_digest: digest,
        },
        signature: [0x44; 64],
    }
}

#[test]
fn bond_registration_closed_frames_have_stable_layout_and_bounds() {
    let signed: SignedBondRegistrationIntent = claims();
    let intent = &signed.intent;
    let mut expected: CanonicalStruct = CanonicalStruct::new(0x64E0, 1);
    expected
        .field_bytes(
            1,
            execution::publication::encode_publication_context(&intent.context).unwrap(),
        )
        .unwrap();
    expected.field_bytes(2, vec![0x81; 32]).unwrap();
    expected.field_bytes(3, vec![0x33; 32]).unwrap();
    expected.field_u16(4, 1).unwrap();
    expected.field_bytes(5, vec![0x33; 32]).unwrap();
    expected
        .field_bytes(
            6,
            execution::publication::encode_publication_context(&intent.context).unwrap(),
        )
        .unwrap();
    expected
        .field_bytes(7, bonds::encode_bond_resource_id(intent.resource).unwrap())
        .unwrap();
    expected.field_bytes(8, b"leg".to_vec()).unwrap();
    expected
        .field_bytes(
            9,
            encode_digest32(&intent.expected_initial_row_digest).unwrap(),
        )
        .unwrap();
    expected
        .field_bytes(10, encode_digest32(&intent.pinned_genesis_digest).unwrap())
        .unwrap();
    let intent_bytes: Vec<u8> = expected.finish().unwrap();
    assert_eq!(
        encode_bond_registration_intent(intent).unwrap(),
        intent_bytes
    );
    let mut outer: CanonicalStruct = CanonicalStruct::new(0x64E1, 1);
    outer.field_bytes(1, intent_bytes).unwrap();
    outer.field_bytes(2, vec![0x44; 64]).unwrap();
    let signed_bytes: Vec<u8> = outer.finish().unwrap();
    assert_eq!(
        encode_signed_bond_registration_intent(&signed).unwrap(),
        signed_bytes
    );
    assert_eq!(
        decode_signed_bond_registration_intent(&signed_bytes).unwrap(),
        signed
    );
    let anchor: BondRegistrationAnchor = BondRegistrationAnchor {
        context: intent.context.clone(),
        validator_id: intent.validator_id,
        signed_registration: signed_bytes.clone(),
        resulting_row: b"row".to_vec(),
    };
    let mut expected_anchor: CanonicalStruct = CanonicalStruct::new(0x64E2, 1);
    expected_anchor
        .field_bytes(
            1,
            execution::publication::encode_publication_context(&intent.context).unwrap(),
        )
        .unwrap();
    expected_anchor.field_bytes(2, vec![0x33; 32]).unwrap();
    expected_anchor
        .field_bytes(3, signed_bytes.clone())
        .unwrap();
    expected_anchor.field_bytes(4, b"row".to_vec()).unwrap();
    let anchor_bytes: Vec<u8> = expected_anchor.finish().unwrap();
    assert_eq!(
        encode_bond_registration_anchor(&anchor).unwrap(),
        anchor_bytes
    );
    assert_eq!(
        decode_bond_registration_anchor(&anchor_bytes).unwrap(),
        anchor
    );
    for (bytes, decode) in [(
        encode_bond_registration_intent(intent).unwrap(),
        decode_bond_registration_intent
            as fn(&[u8]) -> Result<BondRegistrationIntent, BondRegistrationError>,
    )] {
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut bad: Vec<u8> = bytes.clone();
        bad[0] ^= 1;
        assert!(decode(&bad).is_err());
        bad = bytes;
        bad[3] = 2;
        assert!(decode(&bad).is_err());
    }
    assert!(
        decode_signed_bond_registration_intent(&signed_bytes[..signed_bytes.len() - 1]).is_err()
    );
    assert!(decode_bond_registration_anchor(&anchor_bytes[..anchor_bytes.len() - 1]).is_err());
    let mut oversized = anchor;
    oversized.resulting_row = vec![0; MAX_BOND_REGISTRATION_ROW_BYTES + 1];
    assert!(encode_bond_registration_anchor(&oversized).is_err());
    let mut oversized = signed;
    oversized.intent.leg = vec![0; MAX_LOCAL_EXECUTION_INTENT_BYTES + 1];
    assert!(encode_signed_bond_registration_intent(&oversized).is_err());
}

#[test]
fn bond_registration_signature_payload_is_self_describing_not_legacy() {
    let signed = claims();
    let digest = signed.intent.expected_initial_row_digest;
    let bytes = bond_registration_signing_frame(&signed.intent.context, digest).unwrap();
    let frame = decode_canonical_frame(&bytes).unwrap();
    frame.require_type(0x2001).unwrap();
    assert_eq!(
        frame.required_field(6).unwrap(),
        encode_digest32(&digest).unwrap()
    );
    assert_ne!(
        bytes,
        bond_lifecycle_signing_frame(&signed.intent.context, digest).unwrap()
    );
}
