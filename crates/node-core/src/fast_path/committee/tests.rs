use super::*;
use crate::fast_path::records::{
    FastPathValidatorEntry, MAX_FASTPATH_ACTIVE_VALIDATORS, encode_fastpath_validator_set_record,
};
use crate::fast_path::{FastPathError, decode_validator_set_row};
use crate::{NodeCoreError, genesis};
use ed25519_zebra::{SigningKey, VerificationKey};
use protocol_types::{ChainId, Epoch, ProtocolVersion};

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("committee-validation-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
    )
    .unwrap()
}

fn member(index: u32, power: u64) -> FastPathValidatorEntry {
    let mut seed: [u8; 32] = [0; 32];
    seed[28..].copy_from_slice(&index.to_be_bytes());
    let key: SigningKey = SigningKey::from(seed);
    let public_key: [u8; 32] = VerificationKey::from(&key).into();
    FastPathValidatorEntry {
        id: ValidatorId::new(public_key),
        voting_power: power,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: public_key.to_vec(),
    }
}

fn record(members: Vec<FastPathValidatorEntry>) -> FastPathValidatorSetRecord {
    FastPathValidatorSetRecord {
        context: context(),
        validators: members,
    }
}

#[test]
fn committee_validation_preserves_canonical_membership_and_weighted_power() {
    let first: FastPathValidatorEntry = member(1, 1);
    let second: FastPathValidatorEntry = member(2, 3);
    let mut entries: Vec<FastPathValidatorEntry> = vec![first.clone(), second.clone()];
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.id));
    let source: FastPathValidatorSetRecord = record(entries);
    let original: FastPathValidatorSetRecord = source.clone();
    let set: ValidatorSet = validate_fastvote_validator_set_record(&source, &context()).unwrap();
    assert_eq!(source, original);
    assert_eq!(set.epoch(), Epoch::new(7));
    assert_eq!(set.total_voting_power(), 4);
    assert_eq!(set.quorum_threshold(), 3);
    assert_eq!(set.validators().len(), 2);
    assert!(set.validators()[0].id < set.validators()[1].id);
    assert_eq!(set.get(first.id).unwrap().voting_power, 1);
    assert_eq!(set.get(second.id).unwrap().public_key, second.public_key);
    assert!(set.get(member(3, 1).id).is_none());
    let bytes: Vec<u8> = encode_fastpath_validator_set_record(&source).unwrap();
    assert_eq!(decode_validator_set_row(&bytes, &context()).unwrap(), set);
    assert_eq!(
        encode_fastpath_validator_set_record(&source).unwrap(),
        bytes
    );
}

#[test]
fn committee_validation_context_precedes_scheme_and_set_defects() {
    let mut unsupported: FastPathValidatorEntry = member(1, 0);
    unsupported.signature_scheme = SignatureSchemeId::Secp256k1;
    unsupported.public_key.clear();
    let source: FastPathValidatorSetRecord = record(vec![unsupported]);
    let contexts: [PublicationContext; 3] = [
        PublicationContext::new(
            ChainId::new("other-committee-chain").unwrap(),
            context().protocol_version(),
            context().epoch(),
        )
        .unwrap(),
        PublicationContext::new(
            context().chain_id().clone(),
            ProtocolVersion::new(4),
            context().epoch(),
        )
        .unwrap(),
        PublicationContext::new(
            context().chain_id().clone(),
            context().protocol_version(),
            Epoch::new(8),
        )
        .unwrap(),
    ];
    let bytes: Vec<u8> = encode_fastpath_validator_set_record(&source).unwrap();
    for expected in contexts {
        assert_eq!(
            validate_fastvote_validator_set_record(&source, &expected),
            Err(FastVoteCommitteeError::ContextMismatch)
        );
        assert!(matches!(
            decode_validator_set_row(&bytes, &expected),
            Err(FastPathError::Invalid(
                "fast-path validator set context mismatch"
            ))
        ));
    }
    // Even an earlier Ed25519 member's invalid power cannot obscure a later
    // unsupported scheme: all schemes precede the generic set validation.
    let zero: FastPathValidatorEntry = member(2, 0);
    let mut unsupported: FastPathValidatorEntry = member(3, 1);
    unsupported.signature_scheme = SignatureSchemeId::Secp256k1;
    let id: ValidatorId = unsupported.id;
    let source: FastPathValidatorSetRecord = record(vec![zero, unsupported]);
    assert_eq!(
        validate_fastvote_validator_set_record(&source, &context()),
        Err(FastVoteCommitteeError::UnsupportedSignatureScheme {
            validator_id: id,
            scheme: SignatureSchemeId::Secp256k1,
        })
    );
    assert!(matches!(
        decode_validator_set_row(
            &encode_fastpath_validator_set_record(&source).unwrap(),
            &context()
        ),
        Err(FastPathError::Invalid(
            "fast-path validator set supports only Ed25519"
        ))
    ));
}

#[test]
fn committee_validation_retains_generic_empty_power_and_key_errors() {
    assert_eq!(
        validate_fastvote_validator_set_record(&record(Vec::new()), &context()),
        Err(FastVoteCommitteeError::InvalidSet(ValidatorSetError::Empty))
    );
    let zero: FastPathValidatorEntry = member(1, 0);
    assert_eq!(
        validate_fastvote_validator_set_record(&record(vec![zero.clone()]), &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::ZeroVotingPower(zero.id)
        ))
    );
    let mut empty: FastPathValidatorEntry = member(2, 1);
    empty.public_key.clear();
    assert_eq!(
        validate_fastvote_validator_set_record(&record(vec![empty.clone()]), &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::EmptyPublicKey(empty.id)
        ))
    );
    let mut oversized: FastPathValidatorEntry = member(3, 1);
    oversized.public_key.resize(513, 0x42);
    assert_eq!(
        validate_fastvote_validator_set_record(&record(vec![oversized.clone()]), &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::PublicKeyTooLarge {
                validator: oversized.id,
                length: 513,
            }
        ))
    );
    // Preserve the generic 10,000-member cap and its precedence over the
    // deliberately repeated identity/key in this excess-count record.
    let excess: FastPathValidatorSetRecord = record(vec![member(4, 1); 10_001]);
    assert_eq!(
        validate_fastvote_validator_set_record(&excess, &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::TooManyValidators(10_001)
        ))
    );
    let overflow: FastPathValidatorSetRecord = record(vec![member(1, u64::MAX), member(2, 1)]);
    assert_eq!(
        validate_fastvote_validator_set_record(&overflow, &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::VotingPowerOverflow
        ))
    );
    let zero_bytes: Vec<u8> = encode_fastpath_validator_set_record(&record(vec![zero])).unwrap();
    assert!(matches!(
        decode_validator_set_row(&zero_bytes, &context()),
        Err(FastPathError::Node(NodeCoreError::PersistenceInvariant(
            "fast-path validator zero voting power"
        )))
    ));
}

#[test]
fn committee_validation_retains_duplicate_identity_and_shared_key_errors() {
    let first: FastPathValidatorEntry = member(1, 1);
    let mut duplicate: FastPathValidatorEntry = member(2, 1);
    duplicate.id = first.id;
    assert_eq!(
        validate_fastvote_validator_set_record(&record(vec![first.clone(), duplicate]), &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::DuplicateValidator(first.id)
        ))
    );
    let mut second: FastPathValidatorEntry = member(2, 1);
    second.public_key = first.public_key.clone();
    let later: ValidatorId = first.id.max(second.id);
    assert_eq!(
        validate_fastvote_validator_set_record(&record(vec![first, second]), &context()),
        Err(FastVoteCommitteeError::InvalidSet(
            ValidatorSetError::DuplicatePublicKey(later)
        ))
    );
}

#[test]
fn committee_validation_does_not_add_key_policy_or_genesis_capacity() {
    // A structural set has never established cryptographic key admissibility.
    // Preserve ValidatorSet's own opaque nonempty-key rule; real signature
    // verification and stricter readiness-key policy stay with their owners.
    let mut opaque: FastPathValidatorEntry = member(1, 1);
    opaque.public_key = vec![0x42];
    assert!(validate_fastvote_validator_set_record(&record(vec![opaque]), &context()).is_ok());
    let entries: Vec<FastPathValidatorEntry> = (0..=MAX_FASTPATH_ACTIVE_VALIDATORS)
        .map(|index: usize| member(u32::try_from(index + 1).unwrap(), 1))
        .collect();
    let source: FastPathValidatorSetRecord = record(entries);
    let set: ValidatorSet = validate_fastvote_validator_set_record(&source, &context()).unwrap();
    assert_eq!(set.validators().len(), MAX_FASTPATH_ACTIVE_VALIDATORS + 1);
    assert_eq!(
        decode_validator_set_row(
            &encode_fastpath_validator_set_record(&source).unwrap(),
            &context()
        )
        .unwrap(),
        set
    );
}

#[test]
fn committee_validation_genesis_preserves_context_capacity_member_precedence() {
    let (mut manifest, _, _, _, _) = genesis::tests::build_fixture();
    let mut defective: FastPathValidatorEntry = member(1, 0);
    defective.signature_scheme = SignatureSchemeId::Secp256k1;
    manifest.validator_set.validators = vec![defective; MAX_FASTPATH_ACTIVE_VALIDATORS + 1];
    let correct_context: PublicationContext = manifest.validator_set.context.clone();
    manifest.validator_set.context = context();
    assert!(matches!(
        genesis::convert_genesis_committee(&manifest),
        Err(genesis::GenesisCommitteeError::ContextMismatch)
    ));
    manifest.validator_set.context = correct_context;
    assert!(matches!(
        genesis::convert_genesis_committee(&manifest),
        Err(genesis::GenesisCommitteeError::CapacityExceeded)
    ));
    manifest.validator_set.validators.truncate(1);
    assert!(matches!(
        genesis::convert_genesis_committee(&manifest),
        Err(genesis::GenesisCommitteeError::UnsupportedSignatureScheme)
    ));
    manifest.validator_set.validators[0].signature_scheme = SignatureSchemeId::Ed25519;
    assert!(matches!(
        genesis::convert_genesis_committee(&manifest),
        Err(genesis::GenesisCommitteeError::InvalidSet(
            ValidatorSetError::ZeroVotingPower(_)
        ))
    ));
}
