use super::*;
use crate::genesis::tests::{
    build_bonded_fixture, causal_bonded_manifest, chain, freeze_bonded_manifest,
    logical_bonded_manifest, resign_manifest, resolver,
};
use crate::genesis::{GenesisCommitteeError, encode_genesis_manifest, genesis_manifest_commitment};
use execution::publication::PublicationContext;
use protocol_types::{Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion, SignatureSchemeId};

/// Universal ZIP-215 noncanonical, small-order owner vector (see
/// `crypto::owner_address`'s own copy): the canonical identity re-encoded
/// with the non-canonical high sign bit set, so it is classified
/// noncanonical before its small order is even considered.
const NONCANONICAL_AUTHORITY: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
];

fn pin(manifest: &GenesisManifest) -> [u8; 32] {
    genesis_manifest_commitment(&resolver(), manifest)
        .unwrap()
        .bytes()
}

fn pin_with(resolver: &HashSuiteResolver, manifest: &GenesisManifest) -> [u8; 32] {
    genesis_manifest_commitment(resolver, manifest)
        .unwrap()
        .bytes()
}

fn fixtures() -> Vec<(&'static str, GenesisManifest)> {
    vec![
        ("v1", build_bonded_fixture().0),
        ("v2", logical_bonded_manifest()),
        ("v3", freeze_bonded_manifest()),
        ("v4", causal_bonded_manifest()),
    ]
}

#[test]
fn verify_bytes_authenticates_every_profile_and_matches_its_manifest() {
    for (name, manifest) in fixtures() {
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        let digest: [u8; 32] = pin(&manifest);
        let root: VerifiedGenesisRoot =
            VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
                .unwrap_or_else(|error| panic!("{name} root verification failed: {error}"));
        assert_eq!(root.manifest(), &manifest, "{name} manifest mismatch");
        assert_eq!(root.digest().bytes(), digest, "{name} digest mismatch");
        assert_eq!(
            root.genesis_context(),
            manifest.context(),
            "{name} context mismatch"
        );
        assert_eq!(
            root.genesis_resolver().chain_id(),
            resolver().chain_id(),
            "{name} resolver chain mismatch"
        );
        assert_eq!(
            root.admission_profile().commitment_profile(),
            manifest.commitment_profile,
            "{name} profile mismatch"
        );
        assert_eq!(
            root.genesis_committee().validators().len(),
            manifest.validator_set.validators.len(),
            "{name} committee size mismatch"
        );
    }
}

#[test]
fn wrong_pin_fails_with_commitment_mismatch_even_with_a_corrupted_signature() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    // Mutate before encoding: the bytes actually tested below must carry the
    // corrupted signature, not a stale pre-mutation snapshot.
    manifest.signature[0] ^= 0xFF;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let wrong_pin: [u8; 32] = pin(&freeze_bonded_manifest());
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, wrong_pin, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::CommitmentMismatch));
}

#[test]
fn wrong_context_fails_before_signature_is_even_checked() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    // Mutate before encoding/pinning: both the tested bytes and the matching
    // pin must reflect the corrupted signature, so commitment passes and
    // only the context check is actually exercised.
    manifest.signature[0] ^= 0xFF;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let wrong_context: PublicationContext =
        PublicationContext::new(chain(), ProtocolVersion::new(3), Epoch::new(99)).unwrap();
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, &wrong_context).unwrap_err();
    assert!(matches!(error, GenesisRootError::ContextMismatch));
}

#[test]
fn resolver_chain_mismatch_fails_with_context_mismatch() {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let other_chain_resolver: HashSuiteResolver = HashSuiteResolver::new(
        protocol_types::ChainId::new("genesis-test-other-chain").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    // Self-consistent wrong pin: what `verify_bytes` will itself compute
    // using this same wrong-chain resolver, isolating the resolver/context
    // check from the commitment check.
    let digest: [u8; 32] = pin_with(&other_chain_resolver, &manifest);
    let error: GenesisRootError = VerifiedGenesisRoot::verify_bytes(
        &other_chain_resolver,
        &bytes,
        digest,
        manifest.context(),
    )
    .unwrap_err();
    assert!(matches!(error, GenesisRootError::ContextMismatch));
}

#[test]
fn truncated_bytes_fail_to_decode() {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let mut bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    bytes.pop();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::Decode(_)));
}

#[test]
fn trailing_noncanonical_bytes_fail_to_decode() {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let mut bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    bytes.push(0);
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::Decode(_)));
}

#[test]
fn zero_authority_fails_with_invalid_signature() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    manifest.genesis_authority = [0; 32];
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::InvalidSignature));
}

#[test]
fn noncanonical_authority_fails_with_invalid_signature() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    manifest.genesis_authority = NONCANONICAL_AUTHORITY;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::InvalidSignature));
}

#[test]
fn bad_signature_fails_with_invalid_signature() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    manifest.signature[0] ^= 0xFF;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::InvalidSignature));
}

#[test]
fn wrong_family_signature_fails_with_invalid_signature() {
    // A valid v2 (handoff-capable, non-Freeze) signature never authorizes a
    // v4 (causal) manifest, even though both share the same other fields.
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    let other: GenesisManifest = logical_bonded_manifest();
    manifest.signature = other.signature;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(error, GenesisRootError::InvalidSignature));
}

#[test]
fn non_ed25519_committee_member_fails_with_invalid_committee() {
    let mut manifest: GenesisManifest = causal_bonded_manifest();
    manifest.validator_set.validators[0].signature_scheme = SignatureSchemeId::Secp256k1;
    // Resign so the authority/signature check (step 6) genuinely passes,
    // isolating the committee check (step 7) from the signature-precedence
    // case covered separately below.
    resign_manifest(&mut manifest);
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(
        error,
        GenesisRootError::InvalidCommittee(GenesisCommitteeError::UnsupportedSignatureScheme)
    ));
}

#[test]
fn oversized_committee_fails_with_invalid_committee() {
    use crate::fast_path::FastPathValidatorEntry;
    use crate::fast_path::records::MAX_FASTPATH_ACTIVE_VALIDATORS;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use protocol_types::ValidatorId;

    let mut manifest: GenesisManifest = causal_bonded_manifest();
    let mut validators: Vec<FastPathValidatorEntry> = Vec::new();
    for index in 0..=MAX_FASTPATH_ACTIVE_VALIDATORS {
        let mut seed: [u8; 32] = [0; 32];
        seed[28..].copy_from_slice(&u32::try_from(index + 1).unwrap().to_be_bytes());
        let key: SigningKey = SigningKey::from(seed);
        let public_key: [u8; 32] = VerificationKey::from(&key).into();
        validators.push(FastPathValidatorEntry {
            id: ValidatorId::new(public_key),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        });
    }
    validators.sort_by_key(|validator| validator.id);
    manifest.validator_set.validators = validators;
    resign_manifest(&mut manifest);
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let error: GenesisRootError =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
            .unwrap_err();
    assert!(matches!(
        error,
        GenesisRootError::InvalidCommittee(GenesisCommitteeError::CapacityExceeded)
    ));
}

#[test]
fn multidefect_precedence_commitment_before_context_before_signature_before_committee() {
    // Wrong pin + wrong context + bad signature: commitment wins.
    {
        let mut manifest: GenesisManifest = causal_bonded_manifest();
        manifest.signature[0] ^= 0xFF;
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        let wrong_context: PublicationContext =
            PublicationContext::new(chain(), ProtocolVersion::new(3), Epoch::new(99)).unwrap();
        let wrong_pin: [u8; 32] = pin(&freeze_bonded_manifest());
        let error: GenesisRootError =
            VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, wrong_pin, &wrong_context)
                .unwrap_err();
        assert!(matches!(error, GenesisRootError::CommitmentMismatch));
    }
    // Correct pin, wrong context + bad signature: context wins.
    {
        let mut manifest: GenesisManifest = causal_bonded_manifest();
        manifest.signature[0] ^= 0xFF;
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        let digest: [u8; 32] = pin(&manifest);
        let wrong_context: PublicationContext =
            PublicationContext::new(chain(), ProtocolVersion::new(3), Epoch::new(99)).unwrap();
        let error: GenesisRootError =
            VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, &wrong_context)
                .unwrap_err();
        assert!(matches!(error, GenesisRootError::ContextMismatch));
    }
    // Correct pin/context, bad signature + bad committee: signature wins.
    {
        let mut manifest: GenesisManifest = causal_bonded_manifest();
        manifest.validator_set.validators[0].signature_scheme = SignatureSchemeId::Secp256k1;
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        let digest: [u8; 32] = pin(&manifest);
        let error: GenesisRootError =
            VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
                .unwrap_err();
        assert!(matches!(error, GenesisRootError::InvalidSignature));
    }
}

#[test]
fn root_rebuilds_with_an_extended_trusted_schedule_and_the_unchanged_original_pin() {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = pin(&manifest);
    let base_root: VerifiedGenesisRoot =
        VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context()).unwrap();

    // A trusted later hash-suite activation, far beyond the genesis epoch,
    // does not change the genesis-epoch suite that produced `digest`.
    let extended_resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(3),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(1_000_000),
                suite: HashSuite::genesis(),
            },
        ],
    )
    .unwrap();
    let extended_root: VerifiedGenesisRoot =
        VerifiedGenesisRoot::verify_bytes(&extended_resolver, &bytes, digest, manifest.context())
            .unwrap();
    assert_eq!(base_root.digest(), extended_root.digest());
    assert_eq!(extended_root.digest().bytes(), digest);
    assert_eq!(
        extended_root.genesis_resolver().schedules().len(),
        2,
        "the rebuilt root carries its own extended schedule, not a second genesis"
    );
}

#[test]
fn historical_manifest_with_zero_freeze_height_cannot_be_mistaken_for_a_causal_root() {
    // A historical (v1/v2) manifest's own root is never causal and never
    // authorizes Freeze, independent of what any other store's policy
    // separately believes about an unrelated archive.
    for manifest in [build_bonded_fixture().0, logical_bonded_manifest()] {
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        let digest: [u8; 32] = pin(&manifest);
        let root: VerifiedGenesisRoot =
            VerifiedGenesisRoot::verify_bytes(&resolver(), &bytes, digest, manifest.context())
                .unwrap();
        assert!(!root.admission_profile().is_causal());
        assert_eq!(root.manifest().minimum_freeze_block_height, 0);
    }
}
