use crate::{ConsensusVerifier, Ed25519ConsensusVerifier, UnsupportedSignatureSchemeResponse};
use crypto::{SignatureDomain, SignatureMessageType, frame_signature_message};
use ed25519_zebra::{SigningKey, VerificationKey};
use protocol_types::{ChainId, Epoch, ProtocolVersion, SignatureSchemeId, ValidatorId};

struct VerificationCase<'a> {
    label: &'static str,
    public_key: &'a [u8],
    framed: &'a [u8],
    signature: &'a [u8],
    expected: Result<bool, String>,
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let domain: SignatureDomain = SignatureDomain {
        chain_id: ChainId::new("consensus-verifier-test-chain").unwrap(),
        protocol_version: ProtocolVersion::new(7),
        epoch: Epoch::new(42),
        message_type: SignatureMessageType::new("fast-path-vote-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    frame_signature_message(&domain, payload).unwrap()
}

#[test]
fn ed25519_outcome_matrix_is_identical_for_both_refusal_responses() {
    let key: SigningKey = SigningKey::from([0x31; 32]);
    let other_key: SigningKey = SigningKey::from([0x32; 32]);
    let public_key: Vec<u8> = VerificationKey::from(&key).as_ref().to_vec();
    let other_public_key: Vec<u8> = VerificationKey::from(&other_key).as_ref().to_vec();
    let framed: Vec<u8> = frame(b"exact consensus payload");
    let wrong_frame: Vec<u8> = frame(b"different consensus payload");
    let signature: [u8; 64] = key.sign(&framed).to_bytes();
    let other_signature: [u8; 64] = other_key.sign(&framed).to_bytes();
    let short_key: [u8; 31] = [0x11; 31];
    let long_key: [u8; 33] = [0x11; 33];
    // Reuse the pinned crypto module's malformed Edwards25519 point fixture.
    let mut malformed_key: [u8; 32] = [0xff; 32];
    malformed_key[31] = 0x00;
    let long_signature: [u8; 65] = [0; 65];
    let invalid_signature: [u8; 64] = [0xff; 64];
    let cases: [VerificationCase<'_>; 11] = [
        VerificationCase {
            label: "authentic signature",
            public_key: &public_key,
            framed: &framed,
            signature: &signature,
            expected: Ok(true),
        },
        VerificationCase {
            label: "different valid key",
            public_key: &other_public_key,
            framed: &framed,
            signature: &signature,
            expected: Ok(false),
        },
        VerificationCase {
            label: "different exact frame",
            public_key: &public_key,
            framed: &wrong_frame,
            signature: &signature,
            expected: Ok(false),
        },
        VerificationCase {
            label: "signature from a different valid key",
            public_key: &public_key,
            framed: &framed,
            signature: &other_signature,
            expected: Ok(false),
        },
        VerificationCase {
            label: "short key",
            public_key: &short_key,
            framed: &framed,
            signature: &signature,
            expected: Err("verification key has an invalid length: 31 bytes".to_string()),
        },
        VerificationCase {
            label: "long key",
            public_key: &long_key,
            framed: &framed,
            signature: &signature,
            expected: Err("verification key has an invalid length: 33 bytes".to_string()),
        },
        VerificationCase {
            label: "malformed curve point",
            public_key: &malformed_key,
            framed: &framed,
            signature: &signature,
            expected: Err("verification key is not a valid curve point encoding".to_string()),
        },
        VerificationCase {
            label: "short signature",
            public_key: &public_key,
            framed: &framed,
            signature: &signature[..63],
            expected: Err("signature has an invalid length: 63 bytes".to_string()),
        },
        VerificationCase {
            label: "long signature",
            public_key: &public_key,
            framed: &framed,
            signature: &long_signature,
            expected: Err("signature has an invalid length: 65 bytes".to_string()),
        },
        VerificationCase {
            label: "key error precedes signature error",
            public_key: &short_key,
            framed: &framed,
            signature: &signature[..63],
            expected: Err("verification key has an invalid length: 31 bytes".to_string()),
        },
        VerificationCase {
            label: "invalid exact-length signature",
            public_key: &public_key,
            framed: &framed,
            signature: &invalid_signature,
            expected: Ok(false),
        },
    ];
    let responses: [UnsupportedSignatureSchemeResponse; 2] = [
        UnsupportedSignatureSchemeResponse::InvalidSignature,
        UnsupportedSignatureSchemeResponse::FastPathProfileError,
    ];
    for response in responses {
        let verifier: Ed25519ConsensusVerifier = Ed25519ConsensusVerifier::new(response);
        for case in &cases {
            let actual: Result<bool, String> = verifier.verify_framed(
                ValidatorId::new([0x41; 32]),
                SignatureSchemeId::Ed25519,
                case.public_key,
                case.framed,
                case.signature,
            );
            assert_eq!(actual, case.expected, "{} with {response:?}", case.label);
        }
    }
}

#[test]
fn unsupported_scheme_preserves_both_responses_before_key_or_signature_decoding() {
    let cases: [(UnsupportedSignatureSchemeResponse, Result<bool, String>); 2] = [
        (
            UnsupportedSignatureSchemeResponse::InvalidSignature,
            Ok(false),
        ),
        (
            UnsupportedSignatureSchemeResponse::FastPathProfileError,
            Err("fast-path phase 1 supports only Ed25519".to_string()),
        ),
    ];
    for (response, expected) in cases {
        let verifier: Ed25519ConsensusVerifier = Ed25519ConsensusVerifier::new(response);
        assert_eq!(
            verifier.verify_framed(
                ValidatorId::new([0x41; 32]),
                SignatureSchemeId::Secp256k1,
                &[],
                b"unchanged supplied frame",
                &[],
            ),
            expected,
        );
    }
}
