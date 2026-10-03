//! DR-0187 pure Seal authentication coverage (`authenticate_seal` in
//! `super::policy`): everything here is decided from the candidate's own
//! canonical bytes plus the pinned policy, with zero storage reads. Every
//! candidate below is genuinely encoded and internally self-consistent
//! except the one field each negative test tampers, so the asserted
//! rejection is demonstrably that check, not an earlier structural failure.
use super::*;
use crate::business_reconstruction::cut::{
    BusinessCutCollection, BusinessCutCollectionRoot, BusinessCutIdentity,
    encode_business_cut_identity,
};
use crate::genesis::tests as fixture;
use consensus::DrainUnionIdentity;
use consensus::readiness::{ReadinessSubject, readiness_schedule_digest};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, ExecutionGeneration, HashAlgorithmId};

fn policy_with_profile(
    profile: crate::logical_generation::CommitmentProfile,
) -> OrderedEconomicsPolicy {
    let (mut manifest, _, _, _, _) = fixture::build_fixture();
    manifest.commitment_profile = profile;
    manifest.minimum_freeze_block_height = 1;
    fixture::resign_manifest(&mut manifest);
    let resolver: HashSuiteResolver = fixture::resolver();
    let digest: Digest32 =
        crate::genesis::genesis_manifest_commitment(&resolver, &manifest).unwrap();
    let root: crate::genesis::VerifiedGenesisRoot =
        crate::genesis::VerifiedGenesisRoot::verify_bytes(
            &resolver,
            &crate::genesis::encode_genesis_manifest(&manifest).unwrap(),
            digest.bytes(),
            manifest.context(),
        )
        .unwrap();
    OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap()
}

fn causal_policy() -> OrderedEconomicsPolicy {
    policy_with_profile(crate::logical_generation::CommitmentProfile::CausalAdmission)
}

fn filler_root(seed: u8, collection: BusinessCutCollection) -> BusinessCutCollectionRoot {
    BusinessCutCollectionRoot {
        collection,
        count: 0,
        root: Digest32::new(HashAlgorithmId::Blake3_256, [seed; 32]),
    }
}

/// A structurally valid `BusinessCutIdentity` whose context/domain/genesis
/// match `policy` exactly (what pure authentication actually checks); every
/// other field is a fixed filler value, since this layer never verifies
/// business/drain content -- only `super::business_reconstruction::cut`'s
/// own private reconstruction does.
fn cut_identity_for(policy: &OrderedEconomicsPolicy, through_height: u64) -> BusinessCutIdentity {
    BusinessCutIdentity {
        context: policy.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        validator_set_digest: Digest32::new(HashAlgorithmId::Blake3_256, [2; 32]),
        ordered_history: OrderedHistoryIdentity {
            context: policy.context().clone(),
            domain: policy.domain(),
            genesis_digest: policy.genesis_digest(),
            anchor: policy.anchor(),
            through_height,
            through_view: through_height,
            through_digest: Digest32::new(HashAlgorithmId::Blake3_256, [4; 32]),
        },
        drain_request_id: [0x85; 32],
        drain_block_height: through_height.checked_sub(2).unwrap(),
        drain_candidate_digest: Digest32::new(HashAlgorithmId::Blake3_256, [6; 32]),
        drain_union: DrainUnionIdentity {
            chain_id: policy.context().chain_id().clone(),
            protocol_version: policy.context().protocol_version(),
            epoch: policy.context().epoch(),
            domain: policy.domain(),
            closure_request_id: [7; 32],
            closure_height: through_height.checked_sub(4).unwrap(),
            signer_count: 1,
            member_count: 1,
            entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [8; 32]),
        },
        generation_floor: ExecutionGeneration::new(1),
        business: [
            filler_root(9, BusinessCutCollection::State),
            filler_root(10, BusinessCutCollection::Receipts),
            filler_root(11, BusinessCutCollection::ObjectHeads),
            filler_root(12, BusinessCutCollection::ObjectVersions),
        ],
        artifacts: filler_root(13, BusinessCutCollection::Artifacts),
    }
}

fn readiness_subject_for(
    policy: &OrderedEconomicsPolicy,
    cut_digest: Digest32,
) -> ReadinessSubject {
    let resolver: &HashSuiteResolver = policy.resolver();
    ReadinessSubject {
        chain_id: policy.context().chain_id().clone(),
        protocol_version: policy.context().protocol_version(),
        epoch: policy.context().epoch(),
        genesis_digest: policy.genesis_digest(),
        domain: policy.domain(),
        outgoing_set_digest: policy.engine().validator_set().digest(resolver).unwrap(),
        cut_digest,
        next_epoch: Epoch::new(policy.context().epoch().get().checked_add(1).unwrap()),
        next_set_digest: Digest32::new(HashAlgorithmId::Blake3_256, [20; 32]),
        schedule_digest: readiness_schedule_digest(resolver, policy.context().epoch()).unwrap(),
    }
}

fn candidate_for(
    policy: &OrderedEconomicsPolicy,
    cut_identity: &BusinessCutIdentity,
    subject: &ReadinessSubject,
    created_checkpoint: u64,
) -> OrderedCandidate {
    let resolver: &HashSuiteResolver = policy.resolver();
    let subject_identity: Digest32 = subject.identity(resolver).unwrap();
    let target: Digest32 = seal_target_digest(
        resolver,
        policy.context(),
        subject_identity,
        SEAL_PREDECESSOR_TAG_GENESIS,
        policy.genesis_digest(),
    )
    .unwrap();
    let certificate_digest: Digest32 = Digest32::new(HashAlgorithmId::Blake3_256, [30; 32]);
    let request_id: [u8; 32] =
        seal_request_id(resolver, policy.context(), target, certificate_digest).unwrap();
    let intent: SealIntent = SealIntent {
        readiness_subject: subject.clone(),
        cut_identity_bytes: encode_business_cut_identity(cut_identity).unwrap(),
        predecessor_tag: SEAL_PREDECESSOR_TAG_GENESIS,
        predecessor_digest: policy.genesis_digest(),
        certificate_digest,
        certificate_length: 64,
    };
    OrderedCandidate {
        context: policy.context().clone(),
        request_id,
        kind: OrderedOperationKind::Seal,
        intent: encode_seal_intent(&intent).unwrap(),
        created_checkpoint,
    }
}

struct GenuineSeal {
    policy: OrderedEconomicsPolicy,
    candidate: OrderedCandidate,
}

/// One canonical-only, internally consistent Seal candidate: decoding its own
/// intent, re-deriving the readiness subject identity/target/request and
/// comparing every pinned-profile field all agree. Every negative test below
/// starts here and tampers exactly one thing. This fixture has no independently
/// verified business cut or readiness certificate and proves only pure auth.
fn genuine_seal(policy: OrderedEconomicsPolicy, through_height: u64) -> GenuineSeal {
    let cut_identity: BusinessCutIdentity = cut_identity_for(&policy, through_height);
    let cut_digest: Digest32 =
        crate::ordered_economics::seal::seal_cut_identity_digest(policy.resolver(), &cut_identity)
            .unwrap();
    let subject: ReadinessSubject = readiness_subject_for(&policy, cut_digest);
    let candidate: OrderedCandidate =
        candidate_for(&policy, &cut_identity, &subject, through_height);
    GenuineSeal { policy, candidate }
}

#[test]
fn canonical_only_causal_seal_fixture_passes_pure_authentication() {
    let genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    assert!(
        genuine
            .policy
            .authenticate_candidate(&genuine.candidate)
            .is_ok()
    );
}

#[test]
fn seal_is_rejected_outside_the_causal_admission_profile() {
    let profile = crate::logical_generation::CommitmentProfile::LogicalGenerationV2;
    let genuine: GenuineSeal = genuine_seal(policy_with_profile(profile), 7);
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal is not authorized outside the causal admission profile"
        ))
    ));
}

#[test]
fn seal_rejects_a_readiness_subject_that_does_not_match_the_pinned_profile() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    let mut intent: SealIntent = decode_seal_intent(&genuine.candidate.intent).unwrap();
    intent.readiness_subject.domain = AtomicityDomainId::new([0xEE; 32]).unwrap();
    assert_ne!(intent.readiness_subject.domain, genuine.policy.domain());
    genuine.candidate.intent = encode_seal_intent(&intent).unwrap();
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject does not match the pinned profile"
        ))
    ));
}

#[test]
fn seal_rejects_a_readiness_subject_outgoing_set_digest_that_differs() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    let mut intent: SealIntent = decode_seal_intent(&genuine.candidate.intent).unwrap();
    intent.readiness_subject.outgoing_set_digest =
        Digest32::new(HashAlgorithmId::Blake3_256, [0xCD; 32]);
    genuine.candidate.intent = encode_seal_intent(&intent).unwrap();
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject outgoing set digest differs"
        ))
    ));
}

#[test]
fn seal_rejects_a_readiness_subject_cut_digest_that_differs_from_the_cut_identity() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    let mut intent: SealIntent = decode_seal_intent(&genuine.candidate.intent).unwrap();
    intent.readiness_subject.cut_digest = Digest32::new(HashAlgorithmId::Blake3_256, [0xEF; 32]);
    genuine.candidate.intent = encode_seal_intent(&intent).unwrap();
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject cut digest differs from the candidate own cut identity"
        ))
    ));
}

#[test]
fn seal_rejects_a_request_id_that_does_not_match_its_own_derivation() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    genuine.candidate.request_id[0] ^= 0x01;
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal candidate request id does not match its own derivation"
        ))
    ));
}

#[test]
fn seal_rejects_a_cut_identity_that_does_not_match_the_pinned_profile() {
    let policy: OrderedEconomicsPolicy = causal_policy();
    let mut cut_identity: BusinessCutIdentity = cut_identity_for(&policy, 7);
    cut_identity.domain = AtomicityDomainId::new([0xEE; 32]).unwrap();
    cut_identity.ordered_history.domain = cut_identity.domain;
    cut_identity.drain_union.domain = cut_identity.domain;
    assert_ne!(cut_identity.domain, policy.domain());
    let cut_digest: Digest32 =
        crate::ordered_economics::seal::seal_cut_identity_digest(policy.resolver(), &cut_identity)
            .unwrap();
    let subject: ReadinessSubject = readiness_subject_for(&policy, cut_digest);
    let candidate: OrderedCandidate = candidate_for(&policy, &cut_identity, &subject, 7);
    let result = policy.authenticate_candidate(&candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal candidate cut identity does not match the pinned profile"
        ))
    ));
}

#[test]
fn seal_rejects_a_created_checkpoint_that_is_not_the_cut_history_height() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    genuine.candidate.created_checkpoint = 6;
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal created checkpoint is not the cut history height"
        ))
    ));
}

#[test]
fn seal_rejects_a_predecessor_digest_that_is_not_the_pinned_genesis() {
    let mut genuine: GenuineSeal = genuine_seal(causal_policy(), 7);
    let mut intent: SealIntent = decode_seal_intent(&genuine.candidate.intent).unwrap();
    intent.predecessor_digest = Digest32::new(HashAlgorithmId::Blake3_256, [0xAB; 32]);
    genuine.candidate.intent = encode_seal_intent(&intent).unwrap();
    let result = genuine.policy.authenticate_candidate(&genuine.candidate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Unauthenticated(
            "seal predecessor digest is not the pinned genesis"
        ))
    ));
}
