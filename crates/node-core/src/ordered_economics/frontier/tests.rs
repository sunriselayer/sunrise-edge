use super::*;
use protocol_types::{HashAlgorithmId, SignatureSchemeId, ValidatorId};

fn identity() -> FrozenFrontierIdentity {
    FrozenFrontierIdentity {
        chain_id: ChainId::new("frontier-codec-test").unwrap(),
        protocol_version: ProtocolVersion::new(3),
        epoch: Epoch::new(2),
        domain: AtomicityDomainId::new([1; 32]).unwrap(),
        closure_request_id: [2; 32],
        closure_height: 7,
        entry_count: 1,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
    }
}

#[test]
fn cursor_and_final_records_are_canonical_and_bound_to_one_identity() {
    let cursor = FrontierCursor {
        identity: identity(),
        last_request_id: [4; 32],
    };
    let cursor_bytes: Vec<u8> = encode_cursor(&cursor).unwrap();
    assert_eq!(decode_cursor(&cursor_bytes).unwrap(), cursor);

    let vote = FrozenFrontierVote {
        identity: cursor.identity.clone(),
        validator: ValidatorId::new([5; 32]),
        signature_scheme: SignatureSchemeId::Ed25519,
        signature: vec![6; 64],
    };
    let final_record = FinalFrontier {
        identity: cursor.identity.clone(),
        vote,
    };
    let final_bytes: Vec<u8> = encode_final(&final_record).unwrap();
    assert_eq!(decode_final(&final_bytes).unwrap(), final_record);
    let mut corrupt: Vec<u8> = final_bytes;
    corrupt[0] ^= 1;
    assert!(decode_final(&corrupt).is_err());
}

#[test]
fn cursors_cannot_be_empty_or_conflicting() {
    let mut zero_count = identity();
    zero_count.entry_count = 0;
    assert!(
        encode_cursor(&FrontierCursor {
            identity: zero_count,
            last_request_id: [4; 32],
        })
        .is_err()
    );
    assert!(
        encode_cursor(&FrontierCursor {
            identity: identity(),
            last_request_id: [0; 32],
        })
        .is_err()
    );
    let mut final_record = FinalFrontier {
        identity: identity(),
        vote: FrozenFrontierVote {
            identity: identity(),
            validator: ValidatorId::new([5; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![6; 64],
        },
    };
    final_record.vote.identity.closure_height += 1;
    assert!(encode_final(&final_record).is_err());
}
