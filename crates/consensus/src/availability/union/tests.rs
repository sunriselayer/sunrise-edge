use super::*;
use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteSchedule};

fn fixture() -> (
    HashSuiteResolver,
    AtomicityDomainId,
    Vec<(ValidatorId, FrozenFrontierIdentity)>,
) {
    let chain_id: ChainId = ChainId::new("union-test").unwrap();
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id,
        protocol_version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
    let selected: Vec<(ValidatorId, FrozenFrontierIdentity)> = (1..=3)
        .map(|byte| (ValidatorId::new([byte; 32]), frontier_identity(byte)))
        .collect();
    (resolver, domain, selected)
}

fn frontier_identity(byte: u8) -> FrozenFrontierIdentity {
    FrozenFrontierIdentity {
        chain_id: ChainId::new("union-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain: AtomicityDomainId::new([9; 32]).unwrap(),
        closure_request_id: [7; 32],
        closure_height: 11,
        entry_count: u64::from(byte),
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
    }
}

fn member(request_byte: u8, domain: AtomicityDomainId) -> AvailabilityIdentity {
    AvailabilityIdentity {
        chain_id: ChainId::new("union-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain,
        request_id: [request_byte; 32],
        signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte; 32]),
        execution_commitment: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 1; 32]),
        semantic_artifacts_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 2; 32]),
    }
}

fn empty(
    resolver: &HashSuiteResolver,
    domain: AtomicityDomainId,
    selected: &[(ValidatorId, FrozenFrontierIdentity)],
) -> DrainUnionAccumulator {
    DrainUnionAccumulator::new(
        resolver,
        ChainId::new("union-test").unwrap(),
        ProtocolVersion::new(4),
        Epoch::new(8),
        domain,
        [7; 32],
        11,
        selected,
    )
    .unwrap()
}

#[test]
fn union_accumulates_members_and_resumes_exact_progress() {
    let (resolver, domain, selected) = fixture();
    let entries: Vec<AvailabilityIdentity> = vec![member(1, domain), member(2, domain)];
    let mut accumulator: DrainUnionAccumulator = empty(&resolver, domain, &selected);
    accumulator.push_member(&resolver, &entries[0]).unwrap();
    let intermediate: DrainUnionIdentity = accumulator.identity().clone();
    accumulator.push_member(&resolver, &entries[1]).unwrap();
    assert_eq!(intermediate.member_count, 1);
    assert_eq!(accumulator.identity().member_count, 2);
    assert_eq!(accumulator.identity().signer_count, 3);

    let mut continued: DrainUnionAccumulator = DrainUnionAccumulator::resume(
        &resolver,
        intermediate,
        Some(entries[0].request_id),
        &selected,
    )
    .unwrap();
    continued.push_member(&resolver, &entries[1]).unwrap();
    assert_eq!(continued, accumulator);

    let bytes: Vec<u8> = encode_drain_union_identity(accumulator.identity()).unwrap();
    assert_eq!(
        decode_drain_union_identity(&bytes).unwrap(),
        *accumulator.identity()
    );
}

#[test]
fn union_rejects_duplicates_reordering_foreign_context_and_wrong_roster() {
    let (resolver, domain, selected) = fixture();
    let first: AvailabilityIdentity = member(1, domain);
    let mut accumulator: DrainUnionAccumulator = empty(&resolver, domain, &selected);
    accumulator.push_member(&resolver, &first).unwrap();
    assert!(accumulator.push_member(&resolver, &first).is_err());
    assert!(
        accumulator
            .push_member(&resolver, &member(0, domain))
            .is_err()
    );
    let foreign_domain: AtomicityDomainId = AtomicityDomainId::new([10; 32]).unwrap();
    assert!(
        accumulator
            .push_member(&resolver, &member(2, foreign_domain))
            .is_err()
    );

    assert!(
        DrainUnionAccumulator::new(
            &resolver,
            ChainId::new("union-test").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(8),
            domain,
            [7; 32],
            11,
            &[],
        )
        .is_err()
    );
    let unordered: Vec<(ValidatorId, FrozenFrontierIdentity)> =
        vec![selected[1].clone(), selected[0].clone()];
    assert!(
        DrainUnionAccumulator::new(
            &resolver,
            ChainId::new("union-test").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(8),
            domain,
            [7; 32],
            11,
            &unordered,
        )
        .is_err()
    );
    let duplicate: Vec<(ValidatorId, FrozenFrontierIdentity)> =
        vec![selected[0].clone(), selected[0].clone()];
    assert!(
        DrainUnionAccumulator::new(
            &resolver,
            ChainId::new("union-test").unwrap(),
            ProtocolVersion::new(4),
            Epoch::new(8),
            domain,
            [7; 32],
            11,
            &duplicate,
        )
        .is_err()
    );

    let seed: DrainUnionIdentity = empty(&resolver, domain, &selected).into_identity();
    assert!(DrainUnionAccumulator::resume(&resolver, seed.clone(), None, &selected[..2]).is_err());
    // Same validator IDs, but a different signer's frontier identity: the
    // seed digest folds identities too, so this must not collide with the
    // real selection's seed.
    let mut relabeled: Vec<(ValidatorId, FrozenFrontierIdentity)> = selected.clone();
    relabeled[0].1.entry_count += 1;
    assert!(DrainUnionAccumulator::resume(&resolver, seed.clone(), None, &relabeled).is_err());
    let mut changed: DrainUnionIdentity = seed.clone();
    changed.closure_height += 1;
    assert!(DrainUnionAccumulator::resume(&resolver, changed, None, &selected).is_err());
}

#[test]
fn union_decode_rejects_type_mutation_and_excess() {
    let (resolver, domain, selected) = fixture();
    let identity: DrainUnionIdentity = empty(&resolver, domain, &selected).into_identity();
    let bytes: Vec<u8> = encode_drain_union_identity(&identity).unwrap();
    let mut wrong_type: Vec<u8> = bytes.clone();
    wrong_type[0] ^= 1;
    assert!(decode_drain_union_identity(&wrong_type).is_err());
    assert!(decode_drain_union_identity(&vec![0; MAX_DRAIN_UNION_IDENTITY_BYTES + 1]).is_err());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn drain_union_identity_vector_is_stable() {
    let (resolver, domain, selected) = fixture();
    let identity: DrainUnionIdentity = DrainUnionIdentity {
        member_count: 2,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        ..empty(&resolver, domain, &selected).into_identity()
    };
    assert_eq!(
        hex(&encode_drain_union_identity(&identity).unwrap()),
        "534e52453bd00100090001000a000000756e696f6e2d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b0000000000000007000800000003000000000000000800080000000200000000000000090038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
}

#[test]
fn drain_union_accumulator_seed_and_step_hashes_are_stable() {
    let (resolver, domain, selected) = fixture();
    let mut accumulator: DrainUnionAccumulator = empty(&resolver, domain, &selected);
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "6aca76c445901bd421f3729a4b9b7521a2bfeebaaf516bc39e37b0d01dc1cc74"
    );
    accumulator
        .push_member(&resolver, &member(1, domain))
        .unwrap();
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "b9f65d85f09dac71212187851b395f33d3dc9328d7f1167bd924b561bff7b862"
    );
    accumulator
        .push_member(&resolver, &member(2, domain))
        .unwrap();
    assert_eq!(
        hex(&accumulator.identity().entries_digest.bytes()),
        "f20fbe0bfee0e665a8d9ea44ac506350f1d81be7b188f3a0c5e16e0edd3d5c87"
    );
}
