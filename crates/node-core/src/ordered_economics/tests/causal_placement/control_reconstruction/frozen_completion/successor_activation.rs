//! Genuine source-free terminal-Seal verification and SQLite activation.
//! This re-epochs the same eligible committee; ABCE replacement and shipped
//! host/CLI acceptance are distinct coverage, not claimed by these tests.

use super::*;
use crate::business_reconstruction::cut::{SavedBusinessCut, derive_source_business_cut};
use crate::business_reconstruction::inactive_import::verify_saved_business_import;
use crate::conditional_readiness::{
    ConditionalReadinessError, ReadinessSigningKey, retain_conditional_readiness,
};
use crate::serving_authority::{
    LiveAuthority, SuccessorActivationOutcome, SuccessorArtifactError, SuccessorArtifactSource,
    activate_successor, resolve_live_authority, verify_successor_authority,
};
use runtime::{BlobStore, SuccessorServingSlot};
use runtime_sqlite::SqliteImportTarget;

struct Artifacts<'a> {
    saved: &'a SavedBusinessCut,
    history: &'a [OrderedHistoryHeightMaterial],
    certificate: &'a [u8],
}

impl SuccessorArtifactSource for Artifacts<'_> {
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        Ok(self.saved.clone())
    }
    fn history_height(
        &mut self,
        _identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.history
            .iter()
            .find(|item: &&OrderedHistoryHeightMaterial| item.descriptor.height == height)
            .cloned()
            .ok_or(SuccessorArtifactError::Missing)
    }
    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError> {
        if self.certificate.len() != length as usize {
            return Err(SuccessorArtifactError::Malformed);
        }
        Ok(self.certificate.to_vec())
    }
}

#[test]
fn genuine_terminal_seal_activates_separate_sqlite_targets_and_reconciles_advanced_state() {
    let fixture: seal_signing::SealSigningFixture = seal_signing::seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (cut_history, history_before) = complete_history(network);
    let cut = derive_source_business_cut(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &network.stores[0],
        &network.blobs,
        &history_before,
    )
    .unwrap();
    assert_eq!(cut.identity(), &fixture.cut_identity);
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let plan = verify_saved_business_import(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &saved,
    )
    .unwrap();
    let env_before: OrderedEconomicsEnvironment<'_> = seal_signing::env_with_seal(network);
    seal_acceptance::accept_genuine_seal(&fixture, &env_before);
    let (sealed_history, history) = complete_history(network);
    assert!(sealed_history.through_height > cut_history.through_height);
    let certificate: Vec<u8> = network
        .blobs
        .get_blob(&fixture.certificate_digest)
        .unwrap()
        .unwrap();
    let mut artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &certificate,
    };
    let authority = verify_successor_authority(
        reconstruction_plan(&fixture.source.fixture, &cut_history),
        &sealed_history,
        &mut artifacts,
    )
    .expect("genuinely accepted terminal Seal authenticates the successor");
    let mut corrupt_certificate: Vec<u8> = certificate.clone();
    let last: usize = corrupt_certificate.len() - 1;
    corrupt_certificate[last] ^= 1;
    let mut corrupt_artifacts: Artifacts<'_> = Artifacts {
        saved: &saved,
        history: &history,
        certificate: &corrupt_certificate,
    };
    assert!(
        matches!(
            verify_successor_authority(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut corrupt_artifacts,
            ),
            Err(crate::serving_authority::SuccessorActivationError::Invalid(
                "readiness certificate digest differs from the Seal"
            ))
        ),
        "certificate transport cannot substitute same-length bytes"
    );
    let next_context: PublicationContext = authority.policy_inputs().context().clone();
    let expected_subject: Digest32 = authority.subject_digest();
    let expected_manifest: Digest32 = authority.manifest_digest();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_successor(&network.root, authority.policy_inputs()).unwrap();
    let next_base: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(next_context);
    let env_next: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &policy,
        history: &network.history,
        leg_policy: &next_base,
        engine: &network.engine,
        blobs: &network.blobs,
        seal: None,
    };
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    for index in 0..REPLICAS {
        let state = files.path(&format!("successor-state-{index}.db"));
        let body = files.path(&format!("successor-body-{index}.db"));
        let operation: DurableOperationContext = fixture::context(41);
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture::chain(),
            network.signers[index].id,
            network.domain(),
        );
        let target: SqliteImportTarget = SqliteImportTarget::create(
            &state,
            namespace.clone(),
            operation.writer_fence(),
            plan.binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open(&body).unwrap();
        conditional_readiness::complete(&plan, &target, &blobs, &operation);
        let signer: ReadinessSigningKey =
            ReadinessSigningKey::new(network.signers[index].id, network.signers[index].key);
        if index == 0 {
            let wrong_key: ReadinessSigningKey =
                ReadinessSigningKey::new(signer.validator_id(), SigningKey::from([0xED; 32]));
            assert!(
                activate_successor(
                    reconstruction_plan(&fixture.source.fixture, &cut_history),
                    &sealed_history,
                    &mut artifacts,
                    &target,
                    &blobs,
                    &operation,
                    &wrong_key,
                    1,
                )
                .is_err()
            );
            assert_eq!(wrong_key.signatures_created(), 0);
            assert_eq!(
                target
                    .get_successor_serving(&operation, network.domain())
                    .unwrap(),
                SuccessorServingSlot::Inactive
            );
        }
        let activated = activate_successor(
            reconstruction_plan(&fixture.source.fixture, &cut_history),
            &sealed_history,
            &mut artifacts,
            &target,
            &blobs,
            &operation,
            &signer,
            1,
        )
        .expect("real complete import activates atomically");
        assert!(
            matches!(activated, SuccessorActivationOutcome::Activated { subject, manifest }
            if subject == expected_subject && manifest == expected_manifest)
        );
        assert_eq!(signer.signatures_created(), 0, "activation signs nothing");
        assert!(matches!(
            target
                .get_successor_serving(&operation, network.domain())
                .unwrap(),
            SuccessorServingSlot::Serving(_)
        ));
        let members: Vec<FastPathValidatorEntry> = network
            .signers
            .iter()
            .map(|member: &TestSigner| FastPathValidatorEntry {
                id: member.id,
                voting_power: 1,
                signature_scheme: protocol_types::SignatureSchemeId::Ed25519,
                public_key: VerificationKey::from(&member.key).as_ref().to_vec(),
            })
            .collect();
        assert!(matches!(
            retain_conditional_readiness(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &signer,
            ),
            Err(ConditionalReadinessError::UnsupportedSuccessorControl)
        ));
        assert_eq!(
            signer.signatures_created(),
            0,
            "Serving refuses readiness before signing"
        );
        let live = resolve_live_authority(
            &target,
            &operation,
            network.domain(),
            reconstruction_plan(&fixture.source.fixture, &cut_history),
            &sealed_history,
            &mut artifacts,
            signer.public_key(),
        )
        .unwrap();
        let warrant = match live {
            LiveAuthority::Successor(warrant) => warrant,
            LiveAuthority::OriginalGenesis => panic!("import target is not an original namespace"),
        };
        let foreign_handle: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace.clone(), plan.binding()).unwrap();
        assert!(
            process_tick_successor(
                &warrant,
                &foreign_handle,
                &env_next,
                20_001,
                &network.signers[index]
            )
            .is_err(),
            "a copied observation is not its warrant issuer"
        );
        process_tick_successor(
            &warrant,
            &target,
            &env_next,
            20_001,
            &network.signers[index],
        )
        .unwrap();
        drop(warrant);
        let advanced: OrderedStatus = query_status(&target, &operation, &env_next).unwrap();
        assert!(advanced.current_view > 1);
        assert!(matches!(
            activate_successor(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut artifacts,
                &target,
                &blobs,
                &operation,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(
            query_status(&target, &operation, &env_next).unwrap(),
            advanced
        );
        drop(foreign_handle);
        drop(target);
        let reopened_operation: DurableOperationContext = fixture::context(42);
        let reopened: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace, plan.binding()).unwrap();
        reopened
            .advance_writer_fence(operation.writer_fence(), reopened_operation.writer_fence())
            .unwrap();
        assert!(matches!(
            activate_successor(
                reconstruction_plan(&fixture.source.fixture, &cut_history),
                &sealed_history,
                &mut artifacts,
                &reopened,
                &blobs,
                &reopened_operation,
                &signer,
                1,
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(
            query_status(&reopened, &reopened_operation, &env_next).unwrap(),
            advanced
        );
        assert_eq!(signer.signatures_created(), 0);
    }
}
