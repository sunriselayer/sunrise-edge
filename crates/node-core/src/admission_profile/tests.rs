use super::*;
use crate::genesis::tests::{
    causal_bonded_manifest, context, domain, expected_profile_row, freeze_bonded_manifest,
    logical_bonded_manifest, put_state, resolver,
};
use crate::genesis::{GenesisInstallOutcome, install_genesis};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, MemoryDurableStateStore, StateMutation, StateMutationEntry,
    StateReadAssertion, WriterFenceGeneration,
};

fn installed() -> (
    MemoryDurableStateStore,
    GenesisManifest,
    VerifiedAdmissionProfile,
) {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    assert!(matches!(
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap(),
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    let pin: Digest32 = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    let verified: VerifiedAdmissionProfile =
        VerifiedAdmissionProfile::from_pinned_genesis(&resolver(), &manifest, pin).unwrap();
    (store, manifest, verified)
}

#[test]
fn lane_bit_is_fresh_signed_authority_and_synthetic_namespace_still_refuses() {
    let (_, manifest, verified) = installed();
    let owned: [u8; 32] = [1; 32];
    let ordered: [u8; 32] = [0x81; 32];
    assert!(require_external_request_lane(&verified, ExternalRequestLane::Owned, &owned).is_ok());
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Ordered, &ordered).is_ok()
    );
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Owned, &ordered).is_err()
    );
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Ordered, &owned).is_err()
    );
    let mut synthetic: [u8; 32] = [1; 32];
    synthetic[..8].copy_from_slice(&crate::local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    assert_eq!(synthetic[0] & 0x80, 0);
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Owned, &synthetic).is_err()
    );
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Ordered, &synthetic).is_err()
    );
    assert!(
        require_external_request_lane(&verified, ExternalRequestLane::Owned, &[0; 32]).is_err()
    );
    for historical in [logical_bonded_manifest(), freeze_bonded_manifest()] {
        let old: VerifiedAdmissionProfile = VerifiedAdmissionProfile::from_pinned_genesis(
            &resolver(),
            &historical,
            genesis_manifest_commitment(&resolver(), &historical).unwrap(),
        )
        .unwrap();
        assert!(!old.is_causal());
        assert!(require_external_request_lane(&old, ExternalRequestLane::Owned, &ordered).is_ok());
        assert!(require_external_request_lane(&old, ExternalRequestLane::Ordered, &owned).is_ok());
    }
    assert_eq!(verified.context(), manifest.context());
}

#[test]
fn profile_token_rejects_foreign_pin_bad_signature_and_relabeling() {
    let (_, mut manifest, verified) = installed();
    let historical: GenesisManifest = freeze_bonded_manifest();
    assert!(
        VerifiedAdmissionProfile::from_pinned_genesis(
            &resolver(),
            &manifest,
            genesis_manifest_commitment(&resolver(), &historical).unwrap()
        )
        .is_err()
    );
    manifest.signature = historical.signature;
    let bad_pin: Digest32 = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    assert!(
        VerifiedAdmissionProfile::from_pinned_genesis(&resolver(), &manifest, bad_pin).is_err()
    );
    manifest.commitment_profile = CommitmentProfile::LogicalGenerationV2;
    assert!(
        VerifiedAdmissionProfile::from_pinned_genesis(
            &resolver(),
            &manifest,
            verified.genesis_digest()
        )
        .is_err()
    );
}

#[test]
fn installed_causal_profile_fences_exact_root_rows_and_denies_direct_fresh_writers() {
    let (store, manifest, verified) = installed();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_verified_admission_profile(&store, &context(1), domain(), &verified, &mut reads).unwrap();
    assert_eq!(reads.len(), 3);
    assert!(reads.contains_key(&logical_profile_key(manifest.context().chain_id()).unwrap()));
    assert!(reads.contains_key(&genesis_manifest_key(manifest.context()).unwrap()));
    assert!(reads.contains_key(&genesis_marker_key(manifest.context()).unwrap()));
    let before: VersionedStateValue = store
        .get_versioned_durable(
            &context(1),
            domain(),
            &logical_profile_key(manifest.context().chain_id()).unwrap(),
        )
        .unwrap();
    assert!(
        fence_installed_external_request_lane(
            &store,
            &context(1),
            domain(),
            manifest.context(),
            &[0x81; 32],
            ExternalRequestLane::Owned,
            &mut reads
        )
        .is_err()
    );
    assert!(
        require_historical_direct_writer(
            &store,
            &context(1),
            domain(),
            manifest.context(),
            &mut reads
        )
        .is_err()
    );
    assert_eq!(
        store
            .get_versioned_durable(
                &context(1),
                domain(),
                &logical_profile_key(manifest.context().chain_id()).unwrap()
            )
            .unwrap(),
        before
    );
}

#[test]
fn missing_pristine_profile_never_hides_installed_v4_genesis_or_marker() {
    let (_, manifest, verified) = installed();
    for material in [0_u8, 1, 2] {
        let partial: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        if material != 1 {
            put_state(
                &partial,
                &genesis_manifest_key(manifest.context()).unwrap(),
                encode_genesis_manifest(&manifest).unwrap(),
            );
        }
        if material != 0 {
            let marker: GenesisInstallMarker = GenesisInstallMarker {
                context: manifest.context().clone(),
                manifest_digest: verified.genesis_digest(),
                genesis_authority: manifest.genesis_authority,
                installed_at_checkpoint: 10,
            };
            put_state(
                &partial,
                &genesis_marker_key(manifest.context()).unwrap(),
                crate::genesis::encode_genesis_install_marker(&marker).unwrap(),
            );
        }
        assert!(
            require_historical_direct_writer(
                &partial,
                &context(1),
                domain(),
                verified.context(),
                &mut BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            fence_installed_external_request_lane(
                &partial,
                &context(1),
                domain(),
                verified.context(),
                &[1; 32],
                ExternalRequestLane::Owned,
                &mut BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            fence_verified_admission_profile(
                &partial,
                &context(1),
                domain(),
                &verified,
                &mut BTreeMap::new()
            )
            .is_err()
        );
    }
}

#[test]
fn v4_downshifted_fake_missing_manifest_or_marker_refuses_on_admission_and_reopen() {
    for corruption in [0_u8, 1, 2, 3, 4] {
        let (store, manifest, verified) = installed();
        let profile_key: Vec<u8> = logical_profile_key(verified.context().chain_id()).unwrap();
        let key: Vec<u8> = match corruption {
            2 => genesis_manifest_key(verified.context()).unwrap(),
            3 => genesis_marker_key(verified.context()).unwrap(),
            _ => profile_key.clone(),
        };
        let mutation: StateMutation = match corruption {
            0 => StateMutation::Put(expected_profile_row(&freeze_bonded_manifest())),
            1 => StateMutation::Put(vec![1, 2, 3]),
            _ => StateMutation::Delete,
        };
        let seen: VersionedStateValue = store
            .get_versioned_durable(&context(1), domain(), &key)
            .unwrap();
        let tx: AtomicStateTransaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), seen.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(1), tx),
            DurableCommitOutcome::Committed
        );
        assert!(
            fence_verified_admission_profile(
                &store,
                &context(1),
                domain(),
                &verified,
                &mut BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            fence_installed_external_request_lane(
                &store,
                &context(1),
                domain(),
                verified.context(),
                &[1; 32],
                ExternalRequestLane::Owned,
                &mut BTreeMap::new()
            )
            .is_err()
        );
        assert!(
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).is_err()
        );
    }
}

#[test]
fn changing_an_observed_genesis_marker_is_a_real_cas_conflict() {
    let (store, manifest, verified) = installed();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    fence_verified_admission_profile(&store, &context(1), domain(), &verified, &mut reads).unwrap();
    let key: Vec<u8> = genesis_marker_key(manifest.context()).unwrap();
    let marker: GenesisInstallMarker = GenesisInstallMarker {
        context: manifest.context().clone(),
        manifest_digest: verified.genesis_digest(),
        genesis_authority: manifest.genesis_authority,
        installed_at_checkpoint: 99,
    };
    put_state(
        &store,
        &key,
        crate::genesis::encode_genesis_install_marker(&marker).unwrap(),
    );
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision).unwrap())
        .collect();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(assertions).unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"test/causal-cas".to_vec(), StateMutation::Put(vec![1]))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Rejected(_)
    ));
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), b"test/causal-cas")
            .unwrap()
            .value()
            .is_none()
    );
}
