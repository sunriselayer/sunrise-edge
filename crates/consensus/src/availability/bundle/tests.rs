//! Focused positive, adversarial and stable-vector tests for the `0xD033`/
//! `0xD034`/`0xD035` publication bundle family.

use super::*;
use crate::test_support::{TestCrypto, validator};
use crate::{FastVote, encode_fast_certificate};
use protocol_types::{
    ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use validator_set::ValidatorSet;

const CHAIN: &str = "dr0154-bundle";
const PROTOCOL: u32 = 3;
const EPOCH: u64 = 9;

fn chain_id() -> ChainId {
    ChainId::new(CHAIN).expect("valid chain id")
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain_id(),
        ProtocolVersion::new(PROTOCOL),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .expect("valid resolver")
}

fn certifier() -> FastPathCertifier {
    let set = ValidatorSet::new(Epoch::new(EPOCH), (1..=4).map(validator).collect())
        .expect("valid validator set");
    FastPathCertifier::new(
        chain_id(),
        ProtocolVersion::new(PROTOCOL),
        Epoch::new(EPOCH),
        set,
    )
    .expect("valid certifier")
}

fn crypto(byte: u8) -> TestCrypto {
    TestCrypto {
        validator: ValidatorId::new([byte; 32]),
    }
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

/// The artifact contents this fixture's manifest declares: one state value
/// and one object body, deliberately of different kinds so the per-kind hash
/// purpose is actually exercised.
fn contents() -> Vec<Vec<u8>> {
    vec![b"state-value-bytes".to_vec(), b"object-body-bytes".to_vec()]
}

fn witness_bytes() -> Vec<u8> {
    b"0x6424/v2 logical commitment witness bytes".to_vec()
}

fn signed_intent() -> Vec<u8> {
    b"original signed intent bytes".to_vec()
}

fn manifest(resolver: &HashSuiteResolver) -> ArtifactManifest {
    let epoch = Epoch::new(EPOCH);
    let values = contents();
    let mut object_identity: Vec<u8> = vec![0x33; 32];
    object_identity.extend_from_slice(&7u64.to_be_bytes());
    let entries = vec![
        ArtifactEntry {
            kind: ArtifactKind::StateValue,
            identity: b"se/state/key".to_vec(),
            content_digest: resolver
                .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &values[0])
                .expect("hash"),
            content_length: u32::try_from(values[0].len()).expect("bounded"),
        },
        ArtifactEntry {
            kind: ArtifactKind::ObjectBody,
            identity: object_identity,
            content_digest: resolver
                .hash_for_purpose(epoch, HashPurpose::Object, &values[1])
                .expect("hash"),
            content_length: u32::try_from(values[1].len()).expect("bounded"),
        },
    ];
    ArtifactManifest { entries }
}

/// Builds a quorum [`FastCertificate`] over the witness's real digest from
/// the given signer bytes, so the certificate genuinely attests to the exact
/// witness these bundles carry.
fn certificate(signers: &[u8]) -> FastCertificate {
    let certifier = certifier();
    let resolver = resolver();
    let tx_hash = digest(0xAA);
    let execution_effects_hash = resolver
        .hash_for_purpose(
            Epoch::new(EPOCH),
            HashPurpose::ExecutionEffects,
            &witness_bytes(),
        )
        .expect("hash");
    let locked = digest(0xCC);
    let votes: Vec<FastVote> = signers
        .iter()
        .map(|byte| {
            certifier
                .cast_vote(tx_hash, execution_effects_hash, locked, &crypto(*byte))
                .expect("vote")
        })
        .collect();
    certifier
        .try_form_certificate(tx_hash, execution_effects_hash, locked, &votes, &crypto(1))
        .expect("formation")
        .expect("quorum reached")
}

fn bundle_with(signers: &[u8]) -> PublicationBundle {
    let resolver = resolver();
    PublicationBundle {
        domain: AtomicityDomainId::new([0x44; 32]).expect("nonzero domain"),
        request_id: [0x55; 32],
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: signed_intent(),
        certificate: certificate(signers),
        witness: witness_bytes(),
        manifest: manifest(&resolver),
        contents: contents(),
    }
}

fn bundle() -> PublicationBundle {
    bundle_with(&[1, 2, 3])
}

fn verify(bundle: &PublicationBundle) -> Result<VerifiedPublicationBundle, PublicationBundleError> {
    verify_publication_bundle(bundle, &certifier(), &crypto(1), &resolver())
}

#[test]
fn verify_publication_bundle_accepts_a_complete_verified_bundle() {
    let verified = verify(&bundle()).expect("bundle verifies");
    assert_eq!(verified.identity.chain_id, chain_id());
    assert_eq!(verified.identity.epoch, Epoch::new(EPOCH));
    assert_eq!(verified.identity.request_id, [0x55; 32]);
    assert_eq!(verified.identity.signed_intent_digest, digest(0xAA));
    assert_eq!(
        verified.identity.semantic_artifacts_digest,
        verified.manifest_digest
    );
}

#[test]
fn equivalent_certificate_signer_subsets_derive_one_logical_identity() {
    let first = bundle_with(&[1, 2, 3]);
    let second = bundle_with(&[2, 3, 4]);
    assert_ne!(
        encode_fast_certificate(&first.certificate).expect("encode"),
        encode_fast_certificate(&second.certificate).expect("encode"),
        "the fixture must really carry two different valid signer subsets"
    );
    assert_ne!(
        encode_publication_bundle(&first).expect("encode"),
        encode_publication_bundle(&second).expect("encode"),
        "different proof bytes must stay distinguishable for audit"
    );
    let first_identity = verify(&first).expect("verifies").identity;
    let second_identity = verify(&second).expect("verifies").identity;
    assert_eq!(
        first_identity, second_identity,
        "equivalent valid signer subsets denote one operation"
    );
    assert_eq!(
        crate::encode_availability_identity(&first_identity).expect("encode"),
        crate::encode_availability_identity(&second_identity).expect("encode")
    );
}

#[test]
fn verify_publication_bundle_rejects_a_witness_the_quorum_did_not_attest() {
    let mut bundle = bundle();
    bundle.witness.push(0x00);
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::WitnessCommitmentMismatch)
    );
}

#[test]
fn verify_publication_bundle_rejects_substituted_artifact_content() {
    let mut bundle = bundle();
    bundle.contents[0] = b"state-value-forge".to_vec();
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::ArtifactContentDigestMismatch { index: 0 })
    );
}

#[test]
fn verify_publication_bundle_rejects_content_verified_under_the_wrong_hash_purpose() {
    // The object body's bytes are correct, but declared under the state-value
    // kind, whose digest is produced in a different existing hash domain.
    let mut bundle = bundle();
    bundle.manifest.entries[1].kind = ArtifactKind::StateValue;
    bundle.manifest.entries.swap(0, 1);
    bundle.contents.swap(0, 1);
    let error = verify(&bundle).expect_err("kind substitution must be refused");
    assert!(
        matches!(
            error,
            PublicationBundleError::ArtifactContentDigestMismatch { .. }
                | PublicationBundleError::NonCanonicalManifestOrder
        ),
        "unexpected error {error:?}"
    );
}

#[test]
fn verify_publication_bundle_rejects_a_declared_length_that_disagrees_with_the_bytes() {
    let mut bundle = bundle();
    bundle.manifest.entries[0].content_length += 1;
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::ArtifactLengthMismatch {
            index: 0,
            declared: bundle.manifest.entries[0].content_length,
            actual: bundle.contents[0].len(),
        })
    );
}

#[test]
fn verify_publication_bundle_rejects_a_missing_artifact_content() {
    let mut bundle = bundle();
    bundle.contents.pop();
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::ContentCountMismatch {
            entries: 2,
            contents: 1,
        })
    );
}

#[test]
fn verify_publication_bundle_rejects_a_duplicated_manifest_entry() {
    let mut bundle = bundle();
    bundle.manifest.entries[1] = bundle.manifest.entries[0].clone();
    bundle.contents[1] = bundle.contents[0].clone();
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::NonCanonicalManifestOrder)
    );
}

#[test]
fn verify_publication_bundle_rejects_a_misordered_manifest() {
    let mut bundle = bundle();
    bundle.manifest.entries.swap(0, 1);
    bundle.contents.swap(0, 1);
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::NonCanonicalManifestOrder)
    );
}

#[test]
fn verify_publication_bundle_rejects_a_historical_v1_commitment_profile() {
    let mut bundle = bundle();
    bundle.commitment_profile = 1;
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::UnsupportedCommitmentProfile {
            expected: LOGICAL_COMMITMENT_PROFILE,
            actual: 1,
        })
    );
}

#[test]
fn verify_publication_bundle_rejects_a_certificate_without_quorum() {
    let mut bundle = bundle();
    bundle.certificate.votes.truncate(1);
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::Consensus(
            ConsensusError::InsufficientQuorum {
                actual: 1,
                required: 3,
            }
        ))
    );
}

#[test]
fn verify_publication_bundle_rejects_a_forged_certificate_signature() {
    let mut bundle = bundle();
    bundle.certificate.votes[0].signature[0] ^= 0xFF;
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::Consensus(
            ConsensusError::InvalidSignature(ValidatorId::new([1; 32]))
        ))
    );
}

#[test]
fn verify_publication_bundle_rejects_a_certificate_from_another_epoch() {
    let mut bundle = bundle();
    bundle.certificate.epoch = Epoch::new(EPOCH + 1);
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::Consensus(
            ConsensusError::ContextMismatch
        ))
    );
}

#[test]
fn verify_publication_bundle_rejects_a_resolver_bound_to_another_chain() {
    let foreign = HashSuiteResolver::new(
        ChainId::new("dr0154-other").expect("valid chain id"),
        ProtocolVersion::new(PROTOCOL),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .expect("valid resolver");
    assert_eq!(
        verify_publication_bundle(&bundle(), &certifier(), &crypto(1), &foreign),
        Err(PublicationBundleError::Consensus(
            ConsensusError::HashChainMismatch
        ))
    );
}

#[test]
fn verify_publication_bundle_rejects_an_all_zero_request_id() {
    let mut bundle = bundle();
    bundle.request_id = [0u8; 32];
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::Consensus(
            ConsensusError::ZeroAvailabilityRequestId
        ))
    );
}

#[test]
fn verify_publication_bundle_rejects_an_empty_signed_intent() {
    let mut bundle = bundle();
    bundle.signed_intent.clear();
    assert_eq!(
        verify(&bundle),
        Err(PublicationBundleError::InvalidSignedIntentLength {
            actual: 0,
            max: MAX_SIGNED_INTENT_BYTES,
        })
    );
}

#[test]
fn artifact_kind_rejects_an_unknown_discriminant() {
    assert_eq!(
        ArtifactKind::from_u16(3),
        Err(PublicationBundleError::UnknownArtifactKind(3))
    );
    assert_eq!(
        ArtifactKind::from_u16(0),
        Err(PublicationBundleError::UnknownArtifactKind(0))
    );
}

#[test]
fn publication_bundle_encode_decode_round_trips() {
    let bundle = bundle();
    let bytes = encode_publication_bundle(&bundle).expect("encode");
    assert_eq!(decode_publication_bundle(&bytes), Ok(bundle));
}

#[test]
fn artifact_manifest_encode_decode_round_trips() {
    let manifest = manifest(&resolver());
    let bytes = encode_artifact_manifest(&manifest).expect("encode");
    assert_eq!(decode_artifact_manifest(&bytes), Ok(manifest));
}

#[test]
fn decode_publication_bundle_rejects_garbage_bytes() {
    assert!(decode_publication_bundle(&[0u8; 4]).is_err());
}

#[test]
fn decode_artifact_manifest_rejects_a_declared_count_over_the_bound() {
    let mut frame = CanonicalStruct::new(ARTIFACT_MANIFEST_TYPE_ID, ENCODING_VERSION);
    frame
        .field_u32(
            1,
            u32::try_from(MAX_ARTIFACT_MANIFEST_ENTRIES + 1).expect("bounded"),
        )
        .expect("field");
    let bytes = frame.finish().expect("finish");
    assert_eq!(
        decode_artifact_manifest(&bytes),
        Err(PublicationBundleError::ManifestTooLarge {
            actual: MAX_ARTIFACT_MANIFEST_ENTRIES + 1,
            max: MAX_ARTIFACT_MANIFEST_ENTRIES,
        })
    );
}

#[test]
fn decode_artifact_manifest_rejects_a_count_that_disagrees_with_the_fields_present() {
    let manifest = manifest(&resolver());
    let mut frame = CanonicalStruct::new(ARTIFACT_MANIFEST_TYPE_ID, ENCODING_VERSION);
    frame
        .field_u32(
            1,
            u32::try_from(manifest.entries.len()).expect("bounded") + 1,
        )
        .expect("field");
    for (index, entry) in manifest.entries.iter().enumerate() {
        frame
            .field_bytes(
                u16::try_from(index + 2).expect("bounded"),
                encode_artifact_entry(entry).expect("encode"),
            )
            .expect("field");
    }
    let bytes = frame.finish().expect("finish");
    assert_eq!(
        decode_artifact_manifest(&bytes),
        Err(PublicationBundleError::NonCanonicalManifestOrder)
    );
}

#[test]
fn decode_publication_bundle_rejects_a_content_count_that_disagrees_with_the_manifest() {
    let bundle = bundle();
    let mut frame = CanonicalStruct::new(PUBLICATION_BUNDLE_TYPE_ID, ENCODING_VERSION);
    frame
        .field_bytes(1, bundle.domain.as_bytes().to_vec())
        .expect("field");
    frame
        .field_bytes(2, bundle.request_id.to_vec())
        .expect("field");
    frame
        .field_u16(3, LOGICAL_COMMITMENT_PROFILE)
        .expect("field");
    frame
        .field_bytes(4, bundle.signed_intent.clone())
        .expect("field");
    frame
        .field_bytes(
            5,
            encode_fast_certificate(&bundle.certificate).expect("encode"),
        )
        .expect("field");
    frame.field_bytes(6, bundle.witness.clone()).expect("field");
    frame
        .field_bytes(
            7,
            encode_artifact_manifest(&bundle.manifest).expect("encode"),
        )
        .expect("field");
    frame.field_u32(8, 1).expect("field");
    frame
        .field_bytes(9, bundle.contents[0].clone())
        .expect("field");
    let bytes = frame.finish().expect("finish");
    assert_eq!(
        decode_publication_bundle(&bytes),
        Err(PublicationBundleError::ContentCountMismatch {
            entries: 2,
            contents: 1,
        })
    );
}

#[test]
fn decode_publication_bundle_rejects_a_historical_v1_commitment_profile() {
    let bundle = bundle();
    let mut bytes = encode_publication_bundle(&bundle).expect("encode");
    // Field 3 is the profile; locate its two-byte little-endian payload
    // rather than hand-rebuilding the whole frame.
    let needle: Vec<u8> = vec![3, 0, 2, 0, 0, 0, 2, 0];
    let position = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .expect("profile field present");
    bytes[position + needle.len() - 2] = 1;
    assert_eq!(
        decode_publication_bundle(&bytes),
        Err(PublicationBundleError::UnsupportedCommitmentProfile {
            expected: LOGICAL_COMMITMENT_PROFILE,
            actual: 1,
        })
    );
}

/// Decodes a literal lowercase hex string into bytes, used only to hold the
/// pinned vectors below as plain data -- never to derive expected bytes from
/// this module's own encoders or type-id constants. See
/// `scripts/availability-vectors.mjs` for the independent, non-Rust
/// reconstruction these literals are cross-checked against.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex literal");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex digit pair"))
        .collect()
}

/// Renders produced bytes as lowercase hex so a vector regression reports the
/// exact differing literal rather than a wall of decimal.
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// A fixed-byte entry/manifest/bundle fixture with no hashing or signing, so
/// the pinned vectors below depend only on the canonical framing.
fn vector_entry(
    kind: ArtifactKind,
    identity: &[u8],
    digest_byte: u8,
    length: u32,
) -> ArtifactEntry {
    ArtifactEntry {
        kind,
        identity: identity.to_vec(),
        content_digest: digest(digest_byte),
        content_length: length,
    }
}

fn vector_manifest() -> ArtifactManifest {
    ArtifactManifest {
        entries: vec![
            vector_entry(ArtifactKind::StateValue, b"key", 0xaa, 3),
            vector_entry(ArtifactKind::ObjectBody, b"obj", 0xbb, 4),
        ],
    }
}

/// A fixed-byte bundle with a literal certificate and literal signature, so
/// the pinned vector below depends only on the canonical framing and never on
/// a signing key, a hash suite or this crate's own constants.
fn vector_bundle() -> PublicationBundle {
    let vote = FastVote {
        chain_id: ChainId::new("dr0154-vectors").expect("valid chain id"),
        protocol_version: ProtocolVersion::new(PROTOCOL),
        epoch: Epoch::new(EPOCH),
        tx_hash: digest(0x11),
        execution_effects_hash: digest(0x22),
        validator: ValidatorId::new([0x01; 32]),
        signature_scheme: protocol_types::SignatureSchemeId::Ed25519,
        locked_objects_digest: digest(0x33),
        signature: vec![0x5A; 64],
    };
    PublicationBundle {
        domain: AtomicityDomainId::new([0x44; 32]).expect("nonzero domain"),
        request_id: [0x55; 32],
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: b"intent".to_vec(),
        certificate: FastCertificate {
            chain_id: ChainId::new("dr0154-vectors").expect("valid chain id"),
            protocol_version: ProtocolVersion::new(PROTOCOL),
            epoch: Epoch::new(EPOCH),
            tx_hash: digest(0x11),
            execution_effects_hash: digest(0x22),
            locked_objects_digest: digest(0x33),
            votes: vec![vote],
        },
        witness: b"witness".to_vec(),
        manifest: vector_manifest(),
        contents: vec![b"key".to_vec(), b"obj!".to_vec()],
    }
}

#[test]
fn artifact_entry_encoding_vector_0xd033_is_stable() {
    let bytes =
        encode_artifact_entry(&vector_entry(ArtifactKind::StateValue, b"key", 0xaa, 3)).unwrap();
    // Independent literal vector: reconstructed by
    // `scripts/availability-vectors.mjs` (Node, no Rust encoder involved).
    assert_eq!(bytes_to_hex(&bytes), ENTRY_VECTOR_0XD033);
    assert_eq!(bytes, hex_to_bytes(ENTRY_VECTOR_0XD033));
}

#[test]
fn artifact_manifest_encoding_vector_0xd034_is_stable() {
    let bytes = encode_artifact_manifest(&vector_manifest()).unwrap();
    // Independent literal vector: reconstructed by
    // `scripts/availability-vectors.mjs` (Node, no Rust encoder involved).
    assert_eq!(bytes_to_hex(&bytes), MANIFEST_VECTOR_0XD034);
    assert_eq!(bytes, hex_to_bytes(MANIFEST_VECTOR_0XD034));
}

#[test]
fn publication_bundle_encoding_vector_0xd035_is_stable() {
    let bytes = encode_publication_bundle(&vector_bundle()).unwrap();
    // Independent literal vector: reconstructed by
    // `scripts/availability-vectors.mjs` (Node, no Rust encoder involved).
    assert_eq!(bytes_to_hex(&bytes), BUNDLE_VECTOR_0XD035);
    assert_eq!(bytes, hex_to_bytes(BUNDLE_VECTOR_0XD035));
}

const ENTRY_VECTOR_0XD033: &str = "534e524533d00100040001000200000001000200030000006b6579030038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04000400000003000000";

const MANIFEST_VECTOR_0XD034: &str = "534e524534d00100030001000400000002000000020063000000534e524533d00100040001000200000001000200030000006b6579030038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04000400000003000000030063000000534e524533d00100040001000200000002000200030000006f626a030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb04000400000004000000";

const BUNDLE_VECTOR_0XD035: &str = "534e524535d001000a00010020000000444444444444444444444444444444444444444444444444444444444444444402002000000055555555555555555555555555555555555555555555555555555555555555550300020000000200040006000000696e74656e74050074020000534e524508d00100080001000e0000006472303135342d766563746f7273020004000000030000000300080000000900000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e524503010100020001000200000001000200200000002222222222222222222222222222222222222222222222222222222222222222060038000000534e52450301010002000100020000000100020020000000333333333333333333333333333333333333333333333333333333333333333307000400000001000000080074010000534e524507d00100020001001e010000534e524506d00100080001000e0000006472303135342d766563746f7273020004000000030000000300080000000900000000000000040038000000534e524503010100020001000200000001000200200000001111111111111111111111111111111111111111111111111111111111111111050038000000534e52450301010002000100020000000100020020000000222222222222222222222222222222222222222222222222222222222222222206002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100080038000000534e5245030101000200010002000000010002002000000033333333333333333333333333333333333333333333333333333333333333330200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0600070000007769746e6573730700e6000000534e524534d00100030001000400000002000000020063000000534e524533d00100040001000200000001000200030000006b6579030038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04000400000003000000030063000000534e524533d00100040001000200000002000200030000006f626a030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb04000400000004000000080004000000020000000900030000006b65790a00040000006f626a21";
