use super::*;
use ed25519_zebra::{SigningKey, VerificationKey};
use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule};
use validator_set::ValidatorInfo;

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("readiness-test").unwrap(),
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn keys() -> Vec<SigningKey> {
    (1..=4)
        .map(|seed: u8| SigningKey::from([seed; 32]))
        .collect()
}
fn set(keys: &[SigningKey]) -> ValidatorSet {
    let weights: [u64; 4] = [4, 3, 2, 1];
    let members: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| ValidatorInfo {
            id: ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]),
            voting_power: weights[index],
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: VerificationKey::from(key).as_ref().to_vec(),
        })
        .collect();
    ValidatorSet::new(Epoch::new(1), members).unwrap()
}
fn subject(resolver: &HashSuiteResolver, set: &ValidatorSet) -> ReadinessSubject {
    let digest = |byte: u8| Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]);
    ReadinessSubject {
        chain_id: resolver.chain_id().clone(),
        protocol_version: resolver.protocol_version(),
        epoch: Epoch::new(0),
        genesis_digest: digest(1),
        domain: AtomicityDomainId::new([2; 32]).unwrap(),
        outgoing_set_digest: digest(3),
        cut_digest: digest(4),
        next_epoch: Epoch::new(1),
        next_set_digest: set.digest(resolver).unwrap(),
        schedule_digest: readiness_schedule_digest(resolver, Epoch::new(0)).unwrap(),
    }
}
fn vote(subject: &ReadinessSubject, keys: &[SigningKey], index: usize) -> ReadinessVote {
    let signer: ValidatorId = ValidatorId::new([u8::try_from(index + 1).unwrap(); 32]);
    let signature: [u8; 64] = keys[index]
        .sign(&readiness_signing_frame(subject, signer).unwrap())
        .into();
    ReadinessVote {
        subject: subject.clone(),
        signer,
        scheme: SignatureSchemeId::Ed25519,
        signature,
    }
}

#[test]
fn readiness_real_keys_closed_roundtrip_and_distinct_weighted_quorum() {
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    let subject: ReadinessSubject = subject(&resolver, &set);
    let owner: ReadinessCertifier<'_> = ReadinessCertifier::new(&resolver, &subject, &set).unwrap();
    let a: ReadinessVote = vote(&subject, &keys, 0);
    let b: ReadinessVote = vote(&subject, &keys, 1);
    assert_eq!(
        decode_readiness_subject(&encode_readiness_subject(&subject).unwrap()).unwrap(),
        subject
    );
    assert_eq!(
        decode_readiness_vote(&encode_readiness_vote(&a).unwrap()).unwrap(),
        a
    );
    let forward: ReadinessCertificate = owner.form_certificate(&[a.clone(), b.clone()]).unwrap();
    let reverse: ReadinessCertificate = owner.form_certificate(&[b, a.clone()]).unwrap();
    assert_eq!(forward, reverse);
    let bytes: Vec<u8> = encode_readiness_certificate(&forward).unwrap();
    let decoded: ReadinessCertificate = decode_readiness_certificate(&bytes).unwrap();
    owner.verify_certificate(&decoded).unwrap();
    assert!(owner.form_certificate(&[a.clone(), a]).is_err());
    assert!(
        owner
            .form_certificate(&[
                vote(&subject, &keys, 1),
                vote(&subject, &keys, 2),
                vote(&subject, &keys, 3)
            ])
            .is_err()
    );
}

#[test]
fn readiness_complete_schedule_binding_rejects_even_noncertificate_future_difference() {
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    let subject: ReadinessSubject = subject(&resolver, &set);
    let mut future: HashSuite = HashSuite::genesis();
    future.id = HashSuiteId::new(2);
    future.object_digest = HashAlgorithmId::Sha3_256;
    let other: HashSuiteResolver = HashSuiteResolver::new(
        resolver.chain_id().clone(),
        resolver.protocol_version(),
        vec![
            resolver.schedules()[0].clone(),
            HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: future,
            },
        ],
    )
    .unwrap();
    assert_eq!(set.digest(&other).unwrap(), subject.next_set_digest);
    assert_ne!(
        readiness_schedule_digest(&other, subject.epoch).unwrap(),
        subject.schedule_digest
    );
    assert!(ReadinessCertifier::new(&other, &subject, &set).is_err());
    let mut zero: HashSuite = HashSuite::genesis();
    zero.id = HashSuiteId::new(0);
    let malformed: HashSuiteResolver = HashSuiteResolver::new(
        resolver.chain_id().clone(),
        resolver.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: zero,
        }],
    )
    .unwrap();
    assert!(readiness_schedule_digest(&malformed, subject.epoch).is_err());
}

#[test]
fn readiness_incoming_set_hashes_at_incoming_epoch() {
    let base: HashSuiteResolver = resolver();
    let mut future: HashSuite = HashSuite::genesis();
    future.id = HashSuiteId::new(2);
    future.certificate_hash = HashAlgorithmId::Sha3_256;
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        base.chain_id().clone(),
        base.protocol_version(),
        vec![
            base.schedules()[0].clone(),
            HashSuiteSchedule {
                activation_epoch: Epoch::new(1),
                suite: future,
            },
        ],
    )
    .unwrap();
    let set: ValidatorSet = set(&keys());
    let subject: ReadinessSubject = subject(&resolver, &set);
    assert_eq!(
        subject.next_set_digest.algorithm(),
        HashAlgorithmId::Sha3_256
    );
    assert_eq!(
        subject.identity(&resolver).unwrap().algorithm(),
        HashAlgorithmId::Sha2_256
    );
    ReadinessCertifier::new(&resolver, &subject, &set).unwrap();
    let mut bad: ReadinessSubject = subject.clone();
    bad.next_set_digest = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::ValidatorSet,
            &encode_validator_set(&set).unwrap(),
        )
        .unwrap();
    assert!(ReadinessCertifier::new(&resolver, &bad, &set).is_err());
}

#[test]
fn readiness_rejects_all_weak_keys_without_changing_zip215_verification() {
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    for weak in [
        [0; 32],
        {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[0] = 1;
            bytes
        },
        {
            let mut bytes: [u8; 32] = [0; 32];
            bytes[0] = 1;
            bytes[31] = 128;
            bytes
        },
    ] {
        let mut members: Vec<ValidatorInfo> = set.validators().to_vec();
        members[3].public_key = weak.to_vec();
        let weak_set: ValidatorSet = ValidatorSet::new(set.epoch(), members).unwrap();
        assert!(validate_readiness_set(&weak_set).is_err());
    }
    let mut members: Vec<ValidatorInfo> = set.validators().to_vec();
    members[3].signature_scheme = SignatureSchemeId::Secp256k1;
    assert!(validate_readiness_set(&ValidatorSet::new(set.epoch(), members).unwrap()).is_err());
}

#[test]
fn readiness_signature_binds_signer_subject_and_purpose() {
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    let subject: ReadinessSubject = subject(&resolver, &set);
    let owner: ReadinessCertifier<'_> = ReadinessCertifier::new(&resolver, &subject, &set).unwrap();
    let good: ReadinessVote = vote(&subject, &keys, 0);
    let mut bad: ReadinessVote = good.clone();
    bad.signer = set.validators()[1].id;
    assert!(owner.verify_vote(&bad).is_err());
    bad = good.clone();
    bad.subject.cut_digest = Digest32::new(HashAlgorithmId::Sha2_256, [99; 32]);
    assert!(owner.verify_vote(&bad).is_err());
    let foreign: SignatureDomain = SignatureDomain {
        chain_id: subject.chain_id.clone(),
        protocol_version: subject.protocol_version,
        epoch: subject.epoch,
        message_type: SignatureMessageType::new("fast-path-availability-v1").unwrap(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    bad = good.clone();
    bad.signature = keys[0]
        .sign(
            &frame_signature_message(
                &foreign,
                &encode_readiness_payload(&subject, good.signer, good.scheme).unwrap(),
            )
            .unwrap(),
        )
        .into();
    assert!(owner.verify_vote(&bad).is_err());
}

#[test]
fn readiness_bounds_closed_fields_and_adjacent_epoch() {
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    let subject: ReadinessSubject = subject(&resolver, &set);
    let mut bad: ReadinessSubject = subject.clone();
    bad.epoch = Epoch::new(u64::MAX);
    bad.next_epoch = Epoch::new(0);
    assert!(encode_readiness_subject(&bad).is_err());
    let good: ReadinessVote = vote(&subject, &keys, 0);
    let mut frame: CanonicalStruct = CanonicalStruct::new(VOTE, 1);
    frame
        .field_bytes(
            1,
            encode_readiness_payload(&subject, good.signer, good.scheme).unwrap(),
        )
        .unwrap();
    frame.field_bytes(2, good.signature).unwrap();
    frame.field_u16(3, 1).unwrap();
    assert!(decode_readiness_vote(&frame.finish().unwrap()).is_err());
    assert!(decode_readiness_vote(&vec![0; MAX_READINESS_VOTE_BYTES + 1]).is_err());
    assert!(decode_readiness_certificate(&vec![0; MAX_READINESS_CERTIFICATE_BYTES + 1]).is_err());
    let mut certificate: CanonicalStruct = CanonicalStruct::new(CERTIFICATE, 1);
    certificate
        .field_bytes(1, encode_readiness_subject(&subject).unwrap())
        .unwrap();
    certificate
        .field_bytes(2, encode_validator_set(&set).unwrap())
        .unwrap();
    certificate.field_u16(3, 257).unwrap();
    assert!(decode_readiness_certificate(&certificate.finish().unwrap()).is_err());
}

#[test]
fn readiness_corrected_subject_is_nonexclusive_but_never_interchangeable() {
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let old: ValidatorSet = set(&keys);
    let mut members: Vec<ValidatorInfo> = old.validators().to_vec();
    members[0].voting_power = 5;
    let corrected: ValidatorSet = ValidatorSet::new(old.epoch(), members).unwrap();
    let first: ReadinessSubject = subject(&resolver, &old);
    let second: ReadinessSubject = subject(&resolver, &corrected);
    assert_ne!(
        first.identity(&resolver).unwrap(),
        second.identity(&resolver).unwrap()
    );
    let second_owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(&resolver, &second, &corrected).unwrap();
    second_owner
        .form_certificate(&[vote(&second, &keys, 0), vote(&second, &keys, 1)])
        .unwrap();
    assert!(second_owner.verify_vote(&vote(&first, &keys, 0)).is_err());
}

#[test]
fn readiness_independent_node_frames_hashes_and_actual_signature_are_stable() {
    // scripts/conditional-readiness-vectors.mjs independently constructs every
    // frame and signs with Node/OpenSSL, never invoking these Rust encoders.
    let resolver: HashSuiteResolver = resolver();
    let keys: Vec<SigningKey> = keys();
    let set: ValidatorSet = set(&keys);
    let subject: ReadinessSubject = subject(&resolver, &set);
    let a: ReadinessVote = vote(&subject, &keys, 0);
    let owner: ReadinessCertifier<'_> = ReadinessCertifier::new(&resolver, &subject, &set).unwrap();
    let certificate: ReadinessCertificate = owner
        .form_certificate(&[a.clone(), vote(&subject, &keys, 1)])
        .unwrap();
    let schedule: HashSuiteScheduleConfig =
        HashSuiteScheduleConfig::new(resolver.schedules().to_vec()).unwrap();
    let vectors: Vec<(Vec<u8>, usize, &str)> = vec![
        (
            encode_validator_set(&set).unwrap(),
            518,
            "0e90e92d746595038b79b9014de8003604214eb8f391bb47bb34d150ca1b3255",
        ),
        (
            encode_hash_suite_schedule(&schedule).unwrap(),
            136,
            "0a1acc2fce007f2eede28425ab7cfe1814effc36c3409c51509a7460b0ead1b5",
        ),
        (
            encode_readiness_subject(&subject).unwrap(),
            432,
            "8982f691753399ceba797b16f5ab61cc908860288f849e4e864afaabd6c51673",
        ),
        (
            encode_readiness_payload(&subject, a.signer, a.scheme).unwrap(),
            494,
            "d273b0602f3a75d2850ca242d926d593ac1c508557224549873ffa37accb4403",
        ),
        (
            readiness_signing_frame(&subject, a.signer).unwrap(),
            592,
            "e662a49c2442d69fe0a1f86bbbfb47fab4259493d3e2b156bbab877e1511c290",
        ),
        (
            encode_readiness_vote(&a).unwrap(),
            580,
            "d19fa1243f0c31ec85f4b7b9bec85bec6119d1db46fe8144c61632b2da3ebf96",
        ),
        (
            encode_readiness_certificate(&certificate).unwrap(),
            2152,
            "04988eaa27cef657ccec52fdbeef8f17c5bc96c6aa6f3d33ea132ee6a53c08e8",
        ),
    ];
    for (bytes, length, expected) in vectors {
        assert_eq!(bytes.len(), length);
        let digest: Digest32 = resolver
            .hash_for_purpose(subject.epoch, HashPurpose::NodeEvent, &bytes)
            .unwrap();
        let hex: String = digest
            .bytes()
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, expected);
    }
    let signature: String = a
        .signature
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        signature,
        "939052d6dcc41cd4a7cb424f471ac38ce8ed54964f2bb2a4d2e18d20df5b45fa6db0388cdaad4ea67f3dd889f620abff0cc5cbda3c43fdf6c031106850821305"
    );
}
