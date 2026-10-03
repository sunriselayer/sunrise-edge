//! DR-0189 focused coverage of the successor policy constructor, the v3
//! anchor, the single control chokepoint, the epoch-scoped safety keys and
//! the 0xD054/0xD055 frames. The policy inputs below are built directly by
//! this child module only: production code has no raw constructor.

use super::*;
use crate::genesis::VerifiedGenesisRoot;
use crate::genesis::tests as fixture;
use crate::logical_generation::{CommitmentProfile, OrderedRowClass, classify_ordered_row};
use crate::ordered_economics::engine::{
    is_successor_scoped_ordered_key, ordered_applied_height_key, scoped_applied_height_key,
    scoped_state_key, scoped_vote_high_key,
};
use crate::ordered_economics::{
    ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, OrderedCandidate, OrderedEconomicsPolicy,
    OrderedOperationKind, ordered_economics_authority_anchor, ordered_economics_successor_anchor,
};
use canonical_encoding::{CanonicalStruct, encode_chain_id, encode_digest32};
use consensus::ConsensusParameters;
use execution::publication::encode_publication_context;
use protocol_types::{Epoch, HashAlgorithmId, HashPurpose};

const SUCCESSOR_FLOOR: u64 = 10;

/// The original causal genesis root with a positive signed Freeze height.
pub(crate) fn causal_root() -> VerifiedGenesisRoot {
    let (mut manifest, _, _, _, _) = fixture::build_fixture();
    manifest.commitment_profile = CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 7;
    fixture::resign_manifest(&mut manifest);
    let resolver: hashing::HashSuiteResolver = fixture::resolver();
    let digest: Digest32 =
        crate::genesis::genesis_manifest_commitment(&resolver, &manifest).unwrap();
    VerifiedGenesisRoot::verify_bytes(
        &resolver,
        &crate::genesis::encode_genesis_manifest(&manifest).unwrap(),
        digest.bytes(),
        manifest.context(),
    )
    .unwrap()
}

fn successor_context(root: &VerifiedGenesisRoot) -> PublicationContext {
    let original: &PublicationContext = root.genesis_context();
    PublicationContext::new(
        original.chain_id().clone(),
        original.protocol_version(),
        Epoch::new(original.epoch().get().checked_add(1).unwrap()),
    )
    .unwrap()
}

fn successor_set(root: &VerifiedGenesisRoot) -> ValidatorSet {
    ValidatorSet::new(
        successor_context(root).epoch(),
        root.genesis_committee().validators().to_vec(),
    )
    .unwrap()
}

fn subject_digest(seed: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Blake3_256, [seed; 32])
}

/// Verified-shape successor inputs over the original root and its committee
/// re-epoched to e+1, with the honest v3 anchor.
pub(crate) fn successor_inputs(root: &VerifiedGenesisRoot, subject: Digest32) -> SuccessorPolicyInputs {
    let context: PublicationContext = successor_context(root);
    let validator_set: ValidatorSet = successor_set(root);
    let anchor: Digest32 = ordered_economics_successor_anchor(
        root.genesis_resolver(),
        &context,
        fixture::domain(),
        root.digest(),
        root.manifest().minimum_freeze_block_height,
        &validator_set,
        subject,
    )
    .unwrap();
    SuccessorPolicyInputs {
        context,
        domain: fixture::domain(),
        subject_digest: subject,
        genesis_digest: root.digest(),
        validator_set,
        anchor,
        generation_floor: ExecutionGeneration::new(SUCCESSOR_FLOOR),
    }
}

fn control_candidate(kind: OrderedOperationKind, context: PublicationContext) -> OrderedCandidate {
    OrderedCandidate {
        context,
        request_id: [0x91; 32],
        kind,
        intent: vec![0xEE],
        created_checkpoint: 1,
    }
}

#[test]
fn successor_policy_retains_causal_profile_and_signed_freeze_height() {
    let root: VerifiedGenesisRoot = causal_root();
    let inputs: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&root, &inputs).unwrap();
    assert!(policy.admission_profile() == Some(root.admission_profile()));
    assert!(policy.is_causal());
    assert_eq!(policy.minimum_freeze_block_height(), 7);
    assert!(policy.registration_economics().is_none());
    assert!(policy.key_scope().is_successor());
    assert_eq!(policy.context(), inputs.context());
    assert_eq!(policy.domain(), inputs.domain());
    assert_eq!(policy.genesis_digest(), root.digest());
    assert_eq!(policy.anchor(), inputs.anchor());
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap();
    assert!(!original.key_scope().is_successor());
    assert_ne!(original.anchor(), policy.anchor());
}

#[test]
fn successor_policy_refuses_any_input_not_bound_to_the_verified_anchor() {
    let root: VerifiedGenesisRoot = causal_root();
    let mut wrong_anchor: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    wrong_anchor.anchor = subject_digest(4);
    assert!(matches!(
        OrderedEconomicsPolicy::from_successor(&root, &wrong_anchor),
        Err(OrderedEconomicsError::Policy(_))
    ));
    let mut wrong_subject: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    wrong_subject.subject_digest = subject_digest(5);
    assert!(matches!(
        OrderedEconomicsPolicy::from_successor(&root, &wrong_subject),
        Err(OrderedEconomicsError::Policy(_))
    ));
    let mut wrong_genesis: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    wrong_genesis.genesis_digest = subject_digest(6);
    assert!(matches!(
        OrderedEconomicsPolicy::from_successor(&root, &wrong_genesis),
        Err(OrderedEconomicsError::Policy(_))
    ));
    let mut wrong_domain: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    wrong_domain.domain = AtomicityDomainId::new([2; 32]).unwrap();
    assert!(matches!(
        OrderedEconomicsPolicy::from_successor(&root, &wrong_domain),
        Err(OrderedEconomicsError::Policy(_))
    ));
}

#[test]
fn v3_anchor_is_the_v2_preimage_plus_the_subject_at_the_successor_context() {
    let root: VerifiedGenesisRoot = causal_root();
    let resolver: &hashing::HashSuiteResolver = root.genesis_resolver();
    let context: PublicationContext = successor_context(&root);
    let set: ValidatorSet = successor_set(&root);
    let subject: Digest32 = subject_digest(3);
    let parameters: ConsensusParameters = ConsensusParameters::genesis();
    let mut frame: CanonicalStruct = CanonicalStruct::new(ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, 3);
    frame
        .field_bytes(1, b"se/ordered-economics/anchor/v3-successor".to_vec())
        .unwrap();
    frame
        .field_bytes(2, encode_publication_context(&context).unwrap())
        .unwrap();
    frame
        .field_bytes(3, fixture::domain().as_bytes().to_vec())
        .unwrap();
    frame.field_bytes(4, encode_digest32(&root.digest()).unwrap()).unwrap();
    frame
        .field_bytes(5, encode_digest32(&set.digest(resolver).unwrap()).unwrap())
        .unwrap();
    frame.field_u16(6, parameters.protocol.as_u16()).unwrap();
    frame.field_u32(7, parameters.max_block_transactions).unwrap();
    frame.field_u64(8, parameters.view_timeout_millis).unwrap();
    frame.field_u64(9, 7).unwrap();
    frame.field_bytes(10, encode_digest32(&subject).unwrap()).unwrap();
    let expected: Digest32 = resolver
        .hash_for_purpose(
            context.epoch(),
            HashPurpose::ProtocolConfig,
            &frame.finish().unwrap(),
        )
        .unwrap();
    let v3: Digest32 = ordered_economics_successor_anchor(
        resolver,
        &context,
        fixture::domain(),
        root.digest(),
        7,
        &set,
        subject,
    )
    .unwrap();
    assert_eq!(v3, expected);
    let v2: Digest32 = ordered_economics_authority_anchor(
        resolver,
        &context,
        fixture::domain(),
        root.digest(),
        7,
        &set,
    )
    .unwrap();
    assert_ne!(v2, v3);
    let other_subject: Digest32 = ordered_economics_successor_anchor(
        resolver,
        &context,
        fixture::domain(),
        root.digest(),
        7,
        &set,
        subject_digest(4),
    )
    .unwrap();
    assert_ne!(other_subject, v3);
    assert!(matches!(
        ordered_economics_successor_anchor(
            resolver,
            &context,
            fixture::domain(),
            root.digest(),
            0,
            &set,
            subject,
        ),
        Err(OrderedEconomicsError::Policy(_))
    ));
}

#[test]
fn successor_chokepoint_refuses_every_unsupported_control_before_any_other_check() {
    let root: VerifiedGenesisRoot = causal_root();
    let inputs: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    let successor: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&root, &inputs).unwrap();
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap();
    for kind in [
        OrderedOperationKind::Freeze,
        OrderedOperationKind::DrainSet,
        OrderedOperationKind::Seal,
        OrderedOperationKind::BondRegistration,
    ] {
        // A foreign context and a malformed intent would each fail later
        // checks: only the first check can return the typed refusal.
        let foreign: OrderedCandidate = control_candidate(kind, root.genesis_context().clone());
        assert!(matches!(
            successor.authenticate_candidate(&foreign),
            Err(OrderedEconomicsError::UnsupportedSuccessorControl)
        ));
        let local: OrderedCandidate = control_candidate(kind, inputs.context().clone());
        assert!(matches!(
            successor.authenticate_candidate(&local),
            Err(OrderedEconomicsError::UnsupportedSuccessorControl)
        ));
        // The chain-scoped original policy keeps its historical refusal.
        assert!(matches!(
            original.authenticate_candidate(&foreign),
            Err(OrderedEconomicsError::Unauthenticated(_))
        ));
    }
    for kind in [
        OrderedOperationKind::FeeClaim,
        OrderedOperationKind::BondLifecycle,
        OrderedOperationKind::BondSlash,
        OrderedOperationKind::Evidence,
    ] {
        let local: OrderedCandidate = control_candidate(kind, inputs.context().clone());
        assert!(matches!(
            successor.authenticate_candidate(&local),
            Err(OrderedEconomicsError::Unauthenticated(_))
        ));
    }
}

#[test]
fn successor_singleton_roots_are_epoch_scoped_controls_and_chain_keys_are_unchanged() {
    let root: VerifiedGenesisRoot = causal_root();
    let inputs: SuccessorPolicyInputs = successor_inputs(&root, subject_digest(3));
    let successor: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&root, &inputs).unwrap();
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap();
    let chain: &protocol_types::ChainId = inputs.context().chain_id();
    let mut scope: Vec<u8> = Vec::new();
    scope.extend_from_slice(&inputs.context().protocol_version().get().to_be_bytes());
    scope.extend_from_slice(&inputs.context().epoch().get().to_be_bytes());
    scope.extend(encode_digest32(&inputs.anchor()).unwrap());
    for (infix, actual) in [
        (
            b"state/".as_slice(),
            scoped_state_key(successor.key_scope(), chain).unwrap(),
        ),
        (
            b"applied-height/".as_slice(),
            scoped_applied_height_key(successor.key_scope(), chain).unwrap(),
        ),
        (
            b"vote-high/".as_slice(),
            scoped_vote_high_key(successor.key_scope(), chain).unwrap(),
        ),
    ] {
        let mut expected: Vec<u8> = b"se/instances/v1/ordered-economics/epoch-".to_vec();
        expected.extend_from_slice(infix);
        expected.extend(encode_chain_id(chain).unwrap());
        expected.extend_from_slice(&scope);
        assert_eq!(actual, expected);
        assert_eq!(
            classify_ordered_row(&actual),
            Some(OrderedRowClass::ConsensusControl)
        );
        assert!(is_successor_scoped_ordered_key(&actual));
    }
    let chain_applied: Vec<u8> = ordered_applied_height_key(chain).unwrap();
    assert_eq!(
        scoped_applied_height_key(original.key_scope(), chain).unwrap(),
        chain_applied
    );
    assert!(!is_successor_scoped_ordered_key(&chain_applied));
    assert_ne!(
        scoped_state_key(successor.key_scope(), chain).unwrap(),
        scoped_state_key(original.key_scope(), chain).unwrap()
    );
}

fn sample_subject(root: &VerifiedGenesisRoot) -> SuccessorActivationSubject {
    let original: &PublicationContext = root.genesis_context();
    let mut seal_request: [u8; 32] = [0x21; 32];
    seal_request[0] |= 0x80;
    SuccessorActivationSubject {
        chain_id: original.chain_id().clone(),
        protocol_version: original.protocol_version(),
        outgoing_epoch: original.epoch(),
        genesis_digest: root.digest(),
        domain: fixture::domain(),
        seal_target: subject_digest(31),
        seal_request,
        seal_height: 12,
        seal_block_digest: subject_digest(32),
        successor_epoch: successor_context(root).epoch(),
        successor_set_digest: subject_digest(33),
        schedule_digest: subject_digest(34),
        cut_digest: subject_digest(35),
    }
}

fn sample_manifest(root: &VerifiedGenesisRoot) -> SuccessorActivationManifest {
    let subject: SuccessorActivationSubject = sample_subject(root);
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(root, fixture::domain()).unwrap();
    SuccessorActivationManifest {
        history: OrderedHistoryIdentity {
            context: root.genesis_context().clone(),
            domain: fixture::domain(),
            genesis_digest: root.digest(),
            anchor: original.anchor(),
            through_height: subject.seal_height,
            through_view: 15,
            through_digest: subject.seal_block_digest,
        },
        subject,
        certificate_digest: subject_digest(41),
        certificate_length: 900,
        seal_proof_digest: subject_digest(42),
        seal_proof_length: 700,
        package_digest: subject_digest(43),
        plan_digest: subject_digest(44),
    }
}

#[test]
fn successor_frames_round_trip_exactly_and_refuse_trailing_or_foreign_bytes() {
    let root: VerifiedGenesisRoot = causal_root();
    let subject: SuccessorActivationSubject = sample_subject(&root);
    let subject_bytes: Vec<u8> = encode_successor_activation_subject(&subject).unwrap();
    assert!(subject_bytes.len() <= MAX_SUCCESSOR_ACTIVATION_SUBJECT_BYTES);
    assert_eq!(
        decode_successor_activation_subject(&subject_bytes).unwrap(),
        subject
    );
    let manifest: SuccessorActivationManifest = sample_manifest(&root);
    let manifest_bytes: Vec<u8> = encode_successor_activation_manifest(&manifest).unwrap();
    assert!(manifest_bytes.len() <= MAX_SUCCESSOR_ACTIVATION_MANIFEST_BYTES);
    assert_eq!(
        decode_successor_activation_manifest(&manifest_bytes).unwrap(),
        manifest
    );
    let mut trailing: Vec<u8> = subject_bytes.clone();
    trailing.push(0);
    assert!(decode_successor_activation_subject(&trailing).is_err());
    assert!(decode_successor_activation_manifest(&subject_bytes).is_err());
    assert!(decode_successor_activation_subject(&manifest_bytes).is_err());
    let resolver: &hashing::HashSuiteResolver = root.genesis_resolver();
    assert_ne!(
        successor_activation_subject_digest(resolver, &subject).unwrap(),
        successor_activation_manifest_digest(resolver, &manifest).unwrap()
    );
    let mut other: SuccessorActivationSubject = subject.clone();
    other.cut_digest = subject_digest(36);
    assert_ne!(
        successor_activation_subject_digest(resolver, &subject).unwrap(),
        successor_activation_subject_digest(resolver, &other).unwrap()
    );
}

#[test]
fn successor_subject_refuses_non_adjacent_epoch_unsealed_request_and_zero_height() {
    let root: VerifiedGenesisRoot = causal_root();
    let mut skipped: SuccessorActivationSubject = sample_subject(&root);
    skipped.successor_epoch = Epoch::new(skipped.outgoing_epoch.get().checked_add(2).unwrap());
    assert!(encode_successor_activation_subject(&skipped).is_err());
    let mut unsealed: SuccessorActivationSubject = sample_subject(&root);
    unsealed.seal_request[0] &= 0x7F;
    assert!(encode_successor_activation_subject(&unsealed).is_err());
    let mut genesis_height: SuccessorActivationSubject = sample_subject(&root);
    genesis_height.seal_height = 0;
    assert!(encode_successor_activation_subject(&genesis_height).is_err());
}

#[test]
fn successor_manifest_refuses_history_not_ending_at_the_seal_and_bad_lengths() {
    let root: VerifiedGenesisRoot = causal_root();
    let mut short: SuccessorActivationManifest = sample_manifest(&root);
    short.history.through_height = short.subject.seal_height - 1;
    assert!(encode_successor_activation_manifest(&short).is_err());
    let mut other_block: SuccessorActivationManifest = sample_manifest(&root);
    other_block.history.through_digest = subject_digest(50);
    assert!(encode_successor_activation_manifest(&other_block).is_err());
    let mut successor_epoch: SuccessorActivationManifest = sample_manifest(&root);
    successor_epoch.history.context = successor_context(&root);
    assert!(encode_successor_activation_manifest(&successor_epoch).is_err());
    let mut no_certificate: SuccessorActivationManifest = sample_manifest(&root);
    no_certificate.certificate_length = 0;
    assert!(encode_successor_activation_manifest(&no_certificate).is_err());
    let mut oversized: SuccessorActivationManifest = sample_manifest(&root);
    oversized.certificate_length = 1024 * 1024 + 1;
    assert!(encode_successor_activation_manifest(&oversized).is_err());
    let mut no_proof: SuccessorActivationManifest = sample_manifest(&root);
    no_proof.seal_proof_length = 0;
    assert!(encode_successor_activation_manifest(&no_proof).is_err());
}
