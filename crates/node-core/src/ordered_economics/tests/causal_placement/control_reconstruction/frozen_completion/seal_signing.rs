//! DR-0187 real leader signing-site coverage: `propose()` is the actual
//! signing site where `require_seal_signing_capability`/
//! `require_seal_signing_retention` run before any Seal signature is
//! exposed. Every candidate below references the real post-drain business
//! cut and a genuinely quorum-signed `ReadinessCertificate`; only one field
//! is tampered per negative test, so the rejection is demonstrably that
//! field, not an earlier structural failure.
use super::seal_faults::SealFaultStore;
use super::*;
use crate::business_reconstruction::cut::{
    BusinessCutIdentity, VerifiedBusinessCut, business_cut_identity_digest,
    derive_source_business_cut, encode_business_cut_identity,
};
use consensus::readiness::{
    ReadinessCertifier, ReadinessSubject, ReadinessVote, encode_readiness_certificate,
    readiness_schedule_digest, readiness_signing_frame,
};
use protocol_types::{ExecutionGeneration, SignatureSchemeId};
use runtime::BlobStore;
use validator_set::{ValidatorInfo, ValidatorSet};

pub(super) fn env_with_seal(network: &Network) -> OrderedEconomicsEnvironment<'_> {
    OrderedEconomicsEnvironment {
        seal: Some(OrderedSealComposition {
            genesis_root: &network.root,
            paid_base_policy: &network.leg_policy,
            paid_engine: &network.engine,
            blobs: &network.blobs,
        }),
        policy: &network.policy,
        history: &network.history,
        leg_policy: &network.leg_policy,
        engine: &network.engine,
        blobs: &network.blobs,
    }
}

pub(super) struct SealSigningFixture {
    pub(super) source: FrozenCompletionSource,
    pub(super) cut_identity: BusinessCutIdentity,
    pub(super) subject: ReadinessSubject,
    pub(super) next_set: ValidatorSet,
    pub(super) certificate_digest: Digest32,
    pub(super) certificate_length: u32,
    pub(super) candidate: OrderedCandidate,
    pub(super) view: u64,
}

/// Rebuilds a fully consistent Seal candidate from `cut_identity` and
/// `created_checkpoint`: the subject's own `cut_digest` and the derived
/// target/request always track `cut_identity`, exactly like an honest
/// proposer would compute them. Every negative test tampers `cut_identity`
/// (or `created_checkpoint`) before calling this, never the derivation
/// itself, so a mismatch is caught by the real check under test rather than
/// by an inconsistent candidate.
pub(super) fn candidate_for_cut(
    network: &Network,
    cut_identity: &BusinessCutIdentity,
    base_subject: &ReadinessSubject,
    next_set: &ValidatorSet,
    created_checkpoint: u64,
) -> OrderedCandidate {
    let resolver: &HashSuiteResolver = &network.resolver;
    let mut subject: ReadinessSubject = base_subject.clone();
    subject.cut_digest = business_cut_identity_digest(resolver, cut_identity).unwrap();
    let (certificate_digest, certificate_length): (Digest32, u32) =
        stage_certificate(network, &subject, next_set);
    let subject_identity: Digest32 = subject.identity(resolver).unwrap();
    let target: Digest32 = seal_target_digest(
        resolver,
        network.policy.context(),
        subject_identity,
        SEAL_PREDECESSOR_TAG_GENESIS,
        network.policy.genesis_digest(),
    )
    .unwrap();
    let request_id: [u8; 32] = seal_request_id(
        resolver,
        network.policy.context(),
        target,
        certificate_digest,
    )
    .unwrap();
    let intent: SealIntent = SealIntent {
        readiness_subject: subject,
        cut_identity_bytes: encode_business_cut_identity(cut_identity).unwrap(),
        predecessor_tag: SEAL_PREDECESSOR_TAG_GENESIS,
        predecessor_digest: network.policy.genesis_digest(),
        certificate_digest,
        certificate_length,
    };
    OrderedCandidate {
        context: network.policy.context().clone(),
        request_id,
        kind: OrderedOperationKind::Seal,
        intent: encode_seal_intent(&intent).unwrap(),
        created_checkpoint,
    }
}

/// Independently signs the exact subject for every variant. A changed cut
/// must not merely point at the original subject's certificate and stop at
/// the warrant check before reaching the comparison the test intends.
pub(super) fn stage_certificate(
    network: &Network,
    subject: &ReadinessSubject,
    next_set: &ValidatorSet,
) -> (Digest32, u32) {
    let votes: Vec<ReadinessVote> = network
        .signers
        .iter()
        .map(|signer: &TestSigner| {
            let frame: Vec<u8> = readiness_signing_frame(subject, signer.id).unwrap();
            let signature: [u8; 64] = signer.key.sign(&frame).into();
            ReadinessVote {
                subject: subject.clone(),
                signer: signer.id,
                scheme: SignatureSchemeId::Ed25519,
                signature,
            }
        })
        .collect();
    let certifier: ReadinessCertifier<'_> =
        ReadinessCertifier::new(&network.resolver, subject, next_set).unwrap();
    let certificate: consensus::readiness::ReadinessCertificate =
        certifier.form_certificate(&votes).unwrap();
    certifier.verify_certificate(&certificate).unwrap();
    let bytes: Vec<u8> = encode_readiness_certificate(&certificate).unwrap();
    let digest: Digest32 =
        seal_certificate_digest(&network.resolver, subject.epoch, &bytes).unwrap();
    let length: u32 = u32::try_from(bytes.len()).unwrap();
    network.blobs.put_blob(digest, bytes).unwrap();
    (digest, length)
}

pub(super) fn agreed_status(network: &Network) -> OrderedStatus {
    let status: OrderedStatus =
        query_status(&network.stores[0], &network.context, &network.env()).unwrap();
    for replica in 1..REPLICAS {
        let other: OrderedStatus =
            query_status(&network.stores[replica], &network.context, &network.env()).unwrap();
        assert_eq!(other, status, "authenticated replica statuses agree");
    }
    status
}

/// One genuine pre-Seal fixture: real Freeze/Drain/empty-terminal history,
/// the real derived post-drain business cut and a real 4-of-4 quorum
/// `ReadinessCertificate` over the same outgoing validator set reused as its
/// own successor, staged through the real blob owner. Every test below
/// starts here and tampers exactly one thing before calling `propose`.
pub(super) fn seal_signing_fixture() -> SealSigningFixture {
    let source: FrozenCompletionSource = super::preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let finished: OrderedStatus = agreed_status(network);
    assert_eq!(finished.committed_height, 7);
    assert_eq!(finished.high_qc.height, 9);
    assert_eq!(finished.current_view, 10);
    // Query the authenticated pending height, and perform only real EMPTY
    // rounds if a future fixture needs alignment. Views and heights are not
    // interchangeable, and no raw state or lock repair is performed.
    for _ in 0..2 {
        let status: OrderedStatus = agreed_status(network);
        if status.high_qc.height.checked_add(1).unwrap() % 3 == 1 {
            break;
        }
        network.round(status.current_view, None);
    }
    let status: OrderedStatus = agreed_status(network);
    assert_eq!(status.high_qc.height.checked_add(1).unwrap() % 3, 1);
    let (identity, history) = complete_history(network);
    let cut: VerifiedBusinessCut = derive_source_business_cut(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    let cut_identity: BusinessCutIdentity = cut.identity().clone();
    let epoch: Epoch = network.policy.context().epoch();
    let next_epoch: Epoch = Epoch::new(epoch.get().checked_add(1).unwrap());
    let next_validators: Vec<ValidatorInfo> = network
        .signers
        .iter()
        .map(|signer: &TestSigner| {
            let public_key: [u8; 32] = VerificationKey::from(&signer.key).into();
            let bond_key: Vec<u8> =
                fastpath_bond_record_key(network.policy.context().chain_id(), &signer.id).unwrap();
            let bond: FastPathBondRecord =
                decode_fastpath_bond_record(&network.value(0, &bond_key).unwrap()).unwrap();
            assert_eq!(bond.authorization_key.as_slice(), public_key.as_slice());
            ValidatorInfo {
                id: signer.id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key.to_vec(),
            }
        })
        .collect();
    let next_set: ValidatorSet = ValidatorSet::new(next_epoch, next_validators).unwrap();
    let cut_digest: Digest32 =
        business_cut_identity_digest(&network.resolver, &cut_identity).unwrap();
    let subject: ReadinessSubject = ReadinessSubject {
        chain_id: network.policy.context().chain_id().clone(),
        protocol_version: network.policy.context().protocol_version(),
        epoch,
        genesis_digest: network.policy.genesis_digest(),
        domain: network.domain(),
        outgoing_set_digest: network
            .policy
            .engine()
            .validator_set()
            .digest(&network.resolver)
            .unwrap(),
        cut_digest,
        next_epoch,
        next_set_digest: next_set.digest(&network.resolver).unwrap(),
        schedule_digest: readiness_schedule_digest(&network.resolver, epoch).unwrap(),
    };
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &subject,
        &next_set,
        identity.through_height,
    );
    let intent: SealIntent = decode_seal_intent(&candidate.intent).unwrap();
    let certificate: consensus::readiness::ReadinessCertificate =
        seal::load_verified_seal_certificate(&env_with_seal(network), &candidate).unwrap();
    crate::epoch_transition::check_next_set_eligibility(
        &network.stores[0],
        &network.context,
        network.domain(),
        network.policy.context().chain_id(),
        epoch,
        &seal::seal_next_members(&certificate),
    )
    .unwrap();
    let view: u64 = status.current_view;
    SealSigningFixture {
        source,
        cut_identity,
        subject,
        next_set,
        certificate_digest: intent.certificate_digest,
        certificate_length: intent.certificate_length,
        candidate,
        view,
    }
}

#[test]
fn seal_leader_signing_accepts_a_genuine_retention_candidate() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        Some(&fixture.candidate),
        &network.signers[leader],
    );
    assert!(result.is_ok());
}

#[test]
fn seal_leader_signing_rejects_a_checkpoint_beyond_the_current_prior_tip() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let mut cut_identity: BusinessCutIdentity = fixture.cut_identity.clone();
    cut_identity.ordered_history.through_height = cut_identity
        .ordered_history
        .through_height
        .checked_add(1)
        .unwrap();
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &fixture.subject,
        &fixture.next_set,
        cut_identity.ordered_history.through_height,
    );
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "seal signing candidate checkpoint lies beyond the current prior tip"
        ))
    ));
}

#[test]
fn seal_leader_signing_requires_the_stores_capability() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let source: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
        &network.stores[leader],
        &network.blobs,
        &network.context,
        network.domain(),
    );
    let status: OrderedStatus =
        query_status(&network.stores[leader], &network.context, &env).unwrap();
    let barrier: runtime::OutgoingBarrier = network.stores[leader]
        .get_outgoing_barrier(&network.context, network.domain())
        .unwrap();
    let store: SealFaultStore<'_> =
        SealFaultStore::new(network, leader, fixture.candidate.request_id, false, None);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[leader],
        calls: Cell::new(0),
    };
    let result = propose(
        &store,
        &network.context,
        &env,
        Some(&fixture.candidate),
        &signer,
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing requires the live Seal composition and OutgoingSealRepository capability"
        ))
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(
        store.getter_calls.get(),
        1,
        "the exact owning store getter returns None"
    );
    assert_eq!(store.retention_calls.get(), 0);
    assert_eq!(store.completion_calls.get(), 0);
    assert_eq!(
        crate::test_support::capture::captured_source(
            &network.stores[leader],
            &network.blobs,
            &network.context,
            network.domain(),
        ),
        source
    );
    assert_eq!(
        query_status(&network.stores[leader], &network.context, &env).unwrap(),
        status
    );
    assert_eq!(
        network.stores[leader]
            .get_outgoing_barrier(&network.context, network.domain())
            .unwrap(),
        barrier
    );
}

#[test]
fn seal_leader_signing_requires_a_live_composition() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let leader: usize = network.leader_index(fixture.view);
    let result = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&fixture.candidate),
        &network.signers[leader],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing requires the live Seal composition and OutgoingSealRepository capability"
        ))
    ));
}

#[test]
fn seal_leader_signing_rejects_a_business_cut_mismatch() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let mut cut_identity: BusinessCutIdentity = fixture.cut_identity.clone();
    cut_identity.generation_floor = ExecutionGeneration::new(u64::MAX);
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &fixture.subject,
        &fixture.next_set,
        cut_identity.ordered_history.through_height,
    );
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal signing verified business cut differs from the candidates own intent"
        ))
    ));
}

#[test]
fn seal_leader_signing_rejects_a_post_anchor_nonempty_committed_height() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let second_freeze: OrderedCandidate = freeze_candidate([0xD7; 32]);
    let status: OrderedStatus = agreed_status(network);
    // Honest admission after Drain refuses every fresh non-Seal candidate.
    // A real consensus-owner adversarial carrier is instead authenticated and
    // recorded by the ordinary signerless observer. Live admission's
    // AlreadyDrained differs from execution of that peer-certified Freeze:
    // its own controller retains AlreadyFrozen at a nonempty committed height.
    super::seal_acceptance::certify_adversarial_candidate(
        network,
        &second_freeze,
        status.current_view,
    );
    network.round(status.current_view.checked_add(1).unwrap(), None);
    let (completed, _, _) = network.round(status.current_view.checked_add(2).unwrap(), None);
    for replica in 0..REPLICAS {
        assert_eq!(
            completed[replica].committed[0].request_id,
            second_freeze.request_id
        );
        assert_eq!(completed[replica].committed[0].block_height, 10);
        assert_eq!(
            refusal_of(&completed[replica].committed[0]),
            OrderedRefusal::AlreadyFrozen
        );
    }
    let progressed: OrderedStatus = agreed_status(network);
    assert_eq!(progressed.committed_height, 10);
    let (_, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let material: &OrderedHistoryHeightMaterial = history
        .iter()
        .find(|material| material.descriptor.height == 10)
        .unwrap();
    let proof_bytes: &[u8] = &material
        .components
        .iter()
        .find(|(kind, _)| *kind == OrderedHistoryComponentKind::CommitProof)
        .unwrap()
        .1;
    let proof: consensus::CommittedBlockProof =
        consensus::decode_committed_block_proof(proof_bytes).unwrap();
    let block: consensus::CommittedBlock =
        ordered_history::verified_committed_block(&network.policy, &proof).unwrap();
    assert_eq!(
        block.transactions,
        vec![network.policy.candidate_digest(&second_freeze).unwrap()]
    );
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(progressed.current_view);
    let before: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
        &network.stores[leader],
        &network.blobs,
        &network.context,
        network.domain(),
    );
    let barrier: runtime::OutgoingBarrier = network.stores[leader]
        .get_outgoing_barrier(&network.context, network.domain())
        .unwrap();
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[leader],
        calls: Cell::new(0),
    };
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        Some(&fixture.candidate),
        &signer,
    );
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Prerequisite(
                "seal signing candidate post-anchor committed height is not empty"
            ))
        ),
        "unexpected signing result: {result:?}"
    );
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(
        crate::test_support::capture::captured_source(
            &network.stores[leader],
            &network.blobs,
            &network.context,
            network.domain(),
        ),
        before
    );
    assert_eq!(
        query_status(&network.stores[leader], &network.context, &env).unwrap(),
        progressed
    );
    assert_eq!(
        network.stores[leader]
            .get_outgoing_barrier(&network.context, network.domain())
            .unwrap(),
        barrier
    );
    assert!(receipt(network, leader, fixture.candidate.request_id).is_none());
}

#[test]
fn seal_leader_signing_rejects_an_anchor_that_disagrees_with_the_archive() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let mut cut_identity: BusinessCutIdentity = fixture.cut_identity.clone();
    cut_identity.ordered_history.through_view = cut_identity
        .ordered_history
        .through_view
        .checked_add(1)
        .unwrap();
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &fixture.subject,
        &fixture.next_set,
        cut_identity.ordered_history.through_height,
    );
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "seal signing candidate anchor disagrees with the authenticated archive"
        ))
    ));
}
