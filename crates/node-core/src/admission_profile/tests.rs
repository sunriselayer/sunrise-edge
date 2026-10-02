use super::*;
use crate::genesis::tests::{
    causal_bonded_manifest, context, domain, expected_profile_row, freeze_bonded_manifest,
    logical_bonded_manifest, put_state, resolver,
};
use crate::genesis::{
    GenesisInstallOutcome, VerifiedGenesisRoot, encode_genesis_manifest, install_genesis,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, MemoryDurableStateStore, StateMutation, StateMutationEntry,
    StateReadAssertion, WriterFenceGeneration,
};

/// Test-only replacement for the removed public `from_pinned_genesis`
/// authenticator: builds the one immutable root and returns its profile.
fn verified_profile(
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    pinned_digest: Digest32,
) -> Result<VerifiedAdmissionProfile, crate::genesis::GenesisRootError> {
    let bytes: Vec<u8> = encode_genesis_manifest(manifest)
        .map_err(|error| crate::genesis::GenesisRootError::Decode(Box::new(error)))?;
    Ok(VerifiedGenesisRoot::verify_bytes(
        resolver,
        &bytes,
        pinned_digest.bytes(),
        manifest.context(),
    )?
    .admission_profile()
    .clone())
}

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
    let verified: VerifiedAdmissionProfile = verified_profile(&resolver(), &manifest, pin).unwrap();
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
        let old: VerifiedAdmissionProfile = verified_profile(
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
        verified_profile(
            &resolver(),
            &manifest,
            genesis_manifest_commitment(&resolver(), &historical).unwrap()
        )
        .is_err()
    );
    manifest.signature = historical.signature;
    let bad_pin: Digest32 = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    assert!(verified_profile(&resolver(), &manifest, bad_pin).is_err());
    manifest.commitment_profile = CommitmentProfile::LogicalGenerationV2;
    assert!(verified_profile(&resolver(), &manifest, verified.genesis_digest()).is_err());
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
    for corruption in [0_u8, 1, 2, 3, 4, 5] {
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
            5 => {
                let mut redirect: LogicalProfileRecord =
                    crate::logical_generation::decode_logical_profile_record(
                        &expected_profile_row(&manifest),
                    )
                    .unwrap();
                redirect.profile = CommitmentProfile::LogicalGenerationV2;
                redirect.minimum_freeze_block_height = 0;
                redirect.context = PublicationContext::new(
                    verified.context().chain_id().clone(),
                    verified.context().protocol_version(),
                    protocol_types::Epoch::new(99),
                )
                .unwrap();
                StateMutation::Put(
                    crate::logical_generation::encode_logical_profile_record(&redirect).unwrap(),
                )
            }
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
    reads.insert(b"test/causal-cas".to_vec(), StateRevision::INITIAL);
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

#[test]
fn captured_pristine_profile_and_roots_cannot_race_a_genuine_v4_install() {
    let manifest: GenesisManifest = causal_bonded_manifest();
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    require_historical_direct_writer(
        &store,
        &context(1),
        domain(),
        manifest.context(),
        &mut reads,
    )
    .unwrap();
    assert_eq!(reads.len(), 3);
    assert!(
        reads
            .values()
            .all(|revision| *revision == StateRevision::INITIAL)
    );
    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let key: Vec<u8> = b"test/untracked-install-race".to_vec();
    reads.insert(key.clone(), StateRevision::INITIAL);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision).unwrap())
        .collect();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(assertions).unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(&context(1), transaction),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        store
            .get_versioned_durable(&context(1), domain(), &key)
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}
