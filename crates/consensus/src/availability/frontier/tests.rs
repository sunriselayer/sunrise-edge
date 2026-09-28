use super::*;
use crate::test_support::{TestCrypto, validator};
use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteSchedule};
use validator_set::ValidatorInfo;

fn fixture() -> (
    HashSuiteResolver,
    FrozenFrontierCertifier,
    Vec<TestCrypto>,
    AtomicityDomainId,
) {
    let chain_id: ChainId = ChainId::new("frontier-test").unwrap();
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(8);
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let members: Vec<ValidatorInfo> = (1..=4).map(validator).collect();
    let set: ValidatorSet = ValidatorSet::new(epoch, members).unwrap();
    let certifier: FrozenFrontierCertifier =
        FrozenFrontierCertifier::new(chain_id, protocol_version, epoch, set).unwrap();
    let signers: Vec<TestCrypto> = (1..=4)
        .map(|byte| TestCrypto {
            validator: ValidatorId::new([byte; 32]),
        })
        .collect();
    let domain: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
    (resolver, certifier, signers, domain)
}

fn operation(request_byte: u8, domain: AtomicityDomainId) -> AvailabilityIdentity {
    AvailabilityIdentity {
        chain_id: ChainId::new("frontier-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain,
        request_id: [request_byte; 32],
        signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte; 32]),
        execution_commitment: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 1; 32]),
        semantic_artifacts_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 2; 32]),
    }
}

fn empty(resolver: &HashSuiteResolver, domain: AtomicityDomainId) -> FrozenFrontierAccumulator {
    FrozenFrontierAccumulator::new(
        resolver,
        ChainId::new("frontier-test").unwrap(),
        ProtocolVersion::new(4),
        Epoch::new(8),
        domain,
        [7; 32],
        11,
    )
    .unwrap()
}

#[test]
fn frontier_accumulates_in_pages_and_verifies_exact_order() {
    let (resolver, _certifier, _signers, domain) = fixture();
    let entries: Vec<AvailabilityIdentity> = vec![operation(1, domain), operation(2, domain)];
    let mut first: FrozenFrontierAccumulator = empty(&resolver, domain);
    first.push(&resolver, &entries[0]).unwrap();
    let intermediate: FrozenFrontierAccumulator = first.clone();
    first.push(&resolver, &entries[1]).unwrap();
    let mut direct: FrozenFrontierAccumulator = empty(&resolver, domain);
    for entry in &entries {
        direct.push(&resolver, entry).unwrap();
    }
    assert_eq!(first, direct);
    assert_eq!(intermediate.identity().entry_count, 1);
    assert_eq!(first.identity().entry_count, 2);
    verify_frozen_frontier(&resolver, first.identity(), &entries).unwrap();
    assert!(verify_frozen_frontier(&resolver, first.identity(), &entries[..1]).is_err());
    assert!(verify_frozen_frontier(&resolver, first.identity(), entries.iter().rev()).is_err());

    let bytes: Vec<u8> = encode_frozen_frontier_identity(first.identity()).unwrap();
    assert_eq!(
        decode_frozen_frontier_identity(&bytes).unwrap(),
        *first.identity()
    );
}

#[test]
fn frontier_rejects_duplicates_foreign_context_and_changed_closure() {
    let (resolver, _certifier, _signers, domain) = fixture();
    let first: AvailabilityIdentity = operation(1, domain);
    let mut accumulator: FrozenFrontierAccumulator = empty(&resolver, domain);
    accumulator.push(&resolver, &first).unwrap();
    assert!(accumulator.push(&resolver, &first).is_err());
    assert!(accumulator.push(&resolver, &operation(0, domain)).is_err());
    let foreign_domain: AtomicityDomainId = AtomicityDomainId::new([10; 32]).unwrap();
    assert!(
        accumulator
            .push(&resolver, &operation(2, foreign_domain))
            .is_err()
    );
    let original: FrozenFrontierIdentity = accumulator.identity().clone();
    let changed = FrozenFrontierIdentity {
        closure_height: original.closure_height + 1,
        ..original.clone()
    };
    assert_ne!(
        encode_frozen_frontier_identity(&changed).unwrap(),
        encode_frozen_frontier_identity(&original).unwrap()
    );
    assert!(verify_frozen_frontier(&resolver, &changed, [&first]).is_err());
}

#[test]
fn frontier_vote_uses_distinct_context_and_registered_key() {
    let (resolver, certifier, signers, domain) = fixture();
    let mut accumulator: FrozenFrontierAccumulator = empty(&resolver, domain);
    accumulator.push(&resolver, &operation(1, domain)).unwrap();
    let identity: FrozenFrontierIdentity = accumulator.into_identity();
    let vote: FrozenFrontierVote = certifier.cast_vote(identity.clone(), &signers[0]).unwrap();
    certifier.verify_vote(&vote, &signers[0]).unwrap();
    let bytes: Vec<u8> = encode_frozen_frontier_vote(&vote).unwrap();
    assert_eq!(decode_frozen_frontier_vote(&bytes).unwrap(), vote);

    let mut forged: FrozenFrontierVote = vote.clone();
    forged.identity.closure_request_id = [8; 32];
    assert!(certifier.verify_vote(&forged, &signers[0]).is_err());
    let mut foreign: FrozenFrontierVote = vote.clone();
    foreign.validator = ValidatorId::new([99; 32]);
    assert!(certifier.verify_vote(&foreign, &signers[0]).is_err());
    let wrong_epoch = FrozenFrontierIdentity {
        epoch: Epoch::new(9),
        ..identity
    };
    assert!(certifier.cast_vote(wrong_epoch, &signers[0]).is_err());
}

#[test]
fn frontier_decode_rejects_type_mutation_and_excess() {
    let (resolver, _certifier, _signers, domain) = fixture();
    let identity: FrozenFrontierIdentity = empty(&resolver, domain).into_identity();
    let bytes: Vec<u8> = encode_frozen_frontier_identity(&identity).unwrap();
    let mut wrong_type: Vec<u8> = bytes.clone();
    wrong_type[0] ^= 1;
    assert!(decode_frozen_frontier_identity(&wrong_type).is_err());
    assert!(decode_frozen_frontier_identity(&vec![0; MAX_FRONTIER_IDENTITY_BYTES + 1]).is_err());
}

#[test]
fn signed_frontier_pages_require_exact_contiguous_terminal_reconstruction() {
    let (resolver, certifier, signers, domain) = fixture();
    let entries: Vec<AvailabilityIdentity> = vec![operation(1, domain), operation(2, domain)];
    let mut accumulator: FrozenFrontierAccumulator = empty(&resolver, domain);
    for entry in &entries {
        accumulator.push(&resolver, entry).unwrap();
    }
    let vote: FrozenFrontierVote = certifier
        .cast_vote(accumulator.into_identity(), &signers[0])
        .unwrap();
    let first: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: None,
        entries: vec![entries[0].clone()],
        terminal: false,
    };
    let second: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: Some(entries[0].request_id),
        entries: vec![entries[1].clone()],
        terminal: true,
    };
    for page in [&first, &second] {
        let bytes: Vec<u8> = encode_frozen_frontier_page(page).unwrap();
        assert_eq!(decode_frozen_frontier_page(&bytes).unwrap(), *page);
    }
    let mut verifier: FrozenFrontierPageVerifier =
        FrozenFrontierPageVerifier::new(&resolver, &certifier, vote.clone(), &signers[0]).unwrap();
    assert!(verifier.push_page(&resolver, &second).is_err());
    verifier.push_page(&resolver, &first).unwrap();
    assert!(verifier.push_page(&resolver, &first).is_err());
    assert!(
        FrozenFrontierPageVerifier::new(&resolver, &certifier, vote.clone(), &signers[0])
            .unwrap()
            .finish()
            .is_err()
    );
    let omitted_last: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: first.after_request_id,
        entries: first.entries.clone(),
        terminal: true,
    };
    let mut omission_verifier: FrozenFrontierPageVerifier =
        FrozenFrontierPageVerifier::new(&resolver, &certifier, vote.clone(), &signers[0]).unwrap();
    assert!(
        omission_verifier
            .push_page(&resolver, &omitted_last)
            .is_err()
    );
    let duplicate: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: Some(entries[0].request_id),
        entries: vec![entries[0].clone()],
        terminal: true,
    };
    assert!(encode_frozen_frontier_page(&duplicate).is_err());
    verifier.push_page(&resolver, &second).unwrap();
    assert_eq!(verifier.finish().unwrap(), vote);
}

#[test]
fn empty_frontier_page_vector_and_bounds_are_stable() {
    let (resolver, certifier, signers, domain) = fixture();
    let vote: FrozenFrontierVote = certifier
        .cast_vote(empty(&resolver, domain).into_identity(), &signers[0])
        .unwrap();
    let page: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: None,
        entries: Vec::new(),
        terminal: true,
    };
    let encoded: Vec<u8> = encode_frozen_frontier_page(&page).unwrap();
    assert_eq!(
        hex(&encoded),
        "534e524539d00100030001000000000002000200000001000300020000000000"
    );
    assert_eq!(decode_frozen_frontier_page(&encoded).unwrap(), page);
    let mut verifier: FrozenFrontierPageVerifier =
        FrozenFrontierPageVerifier::new(&resolver, &certifier, vote.clone(), &signers[0]).unwrap();
    verifier.push_page(&resolver, &page).unwrap();
    assert_eq!(verifier.finish().unwrap(), vote);

    let mut wrong_type: Vec<u8> = encoded.clone();
    wrong_type[4] ^= 1;
    assert!(decode_frozen_frontier_page(&wrong_type).is_err());
    let mut wrong_flag: Vec<u8> = encoded.clone();
    wrong_flag[22] = 2;
    assert!(decode_frozen_frontier_page(&wrong_flag).is_err());
    assert!(decode_frozen_frontier_page(&vec![0; MAX_FRONTIER_PAGE_BYTES + 1]).is_err());
    let too_large: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: None,
        entries: vec![operation(1, domain); MAX_FROZEN_FRONTIER_PAGE_ENTRIES + 1],
        terminal: true,
    };
    assert!(encode_frozen_frontier_page(&too_large).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn frozen_frontier_identity_and_vote_vectors_are_stable() {
    let (resolver, _certifier, _signers, domain) = fixture();
    let identity: FrozenFrontierIdentity = FrozenFrontierIdentity {
        entry_count: 2,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        ..empty(&resolver, domain).into_identity()
    };
    let vote: FrozenFrontierVote = FrozenFrontierVote {
        identity: identity.clone(),
        validator: ValidatorId::new([1; 32]),
        signature_scheme: SignatureSchemeId::Ed25519,
        signature: vec![0x5a; 64],
    };
    assert_eq!(
        hex(&encode_frozen_frontier_identity(&identity).unwrap()),
        "534e524536d00100080001000d00000066726f6e746965722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000200000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        hex(&encode_frozen_frontier_vote(&vote).unwrap()),
        "534e524537d0010004000100db000000534e524536d00100080001000d00000066726f6e746965722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000200000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
}

#[test]
fn frozen_frontier_accumulator_seed_and_step_hashes_are_stable() {
    let (resolver, _certifier, _signers, domain) = fixture();
    let mut accumulator: FrozenFrontierAccumulator = empty(&resolver, domain);
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "0b1c6153949437a5f2617e05a8849b8ae988778ac6e5aaf0ee17897b4212b7cc"
    );
    accumulator.push(&resolver, &operation(1, domain)).unwrap();
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "eb08a9f7032f18bdb7d9c8cd898b46761189faa0da5f741e13ab4cd651114897"
    );
    accumulator.push(&resolver, &operation(2, domain)).unwrap();
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "a7983d9b7dd79253338a97f1a629ea5795db854f6ba32f84cb9d2cff88dd3a41"
    );
}
