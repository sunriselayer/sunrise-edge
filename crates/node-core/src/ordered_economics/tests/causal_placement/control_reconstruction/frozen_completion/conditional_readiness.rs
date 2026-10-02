//! Readiness from genuine owning executions, never seeded rows or signatures.
use super::*;
use crate::business_reconstruction::cut::{SavedBusinessCut, derive_source_business_cut};
use crate::business_reconstruction::inactive_import::{
    BusinessImportAdvance, VerifiedImportPlan, verify_saved_business_import,
};
use crate::conditional_readiness::{ReadinessSigningKey, retain_conditional_readiness};
use consensus::readiness::{ReadinessCertifier, ReadinessVote, encode_readiness_vote};
use runtime::portable::{PortableSnapshotError, PortableSnapshotToken};
use runtime::{
    ImportBinding, ImportProgress, ReadinessRecord, ReadinessRetentionRepository, ReadinessSlot,
    ReadinessSlotObservation,
};
use runtime_sqlite::SqliteImportTarget;
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let time: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf =
            std::env::temp_dir().join(format!("sunrise-ready-{}-{time}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn next_members(network: &Network) -> Vec<FastPathValidatorEntry> {
    network
        .signers
        .iter()
        .map(|signer: &TestSigner| FastPathValidatorEntry {
            id: signer.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: ed25519_zebra::VerificationKey::from(&signer.key)
                .as_ref()
                .to_vec(),
        })
        .collect()
}

fn complete(
    plan: &VerifiedImportPlan,
    target: &SqliteImportTarget,
    blobs: &SqliteBlobStore,
    operation: &DurableOperationContext,
) {
    loop {
        match plan
            .advance(target, blobs, operation, NonZeroUsize::MIN)
            .unwrap()
        {
            BusinessImportAdvance::Partial { new_batches, .. } => assert_eq!(new_batches, 1),
            BusinessImportAdvance::CompleteInactive { new_batches, .. } => {
                assert!(new_batches <= 1);
                return;
            }
        }
    }
}

/// The existing forwarding adapter really uses SQLite. Only the response is
/// hidden; an unlanded write never calls the underlying retention operation.
impl ReadinessRetentionRepository for inactive_business_import_faults::ReplyLoss<'_> {
    fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError> {
        let observed: ReadinessSlotObservation = self
            .inner
            .read_ready_slot_at(operation, domain, binding, progress, token, slot)?;
        if self.fence_finish.replace(false) {
            let next: runtime::WriterFenceGeneration =
                runtime::WriterFenceGeneration::new(operation.writer_fence().get() + 1).unwrap();
            self.inner
                .advance_writer_fence(operation.writer_fence(), next)
                .unwrap();
        }
        Ok(observed)
    }
    fn retain_ready_slot(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        token: &PortableSnapshotToken,
        observed: &ReadinessSlotObservation,
        record: &ReadinessRecord,
    ) -> DurableCommitOutcome {
        if self.abort_batch.replace(false) {
            return DurableCommitOutcome::Indeterminate(
                runtime::IndeterminateCommitReason::ConnectionLost,
            );
        }
        let actual: DurableCommitOutcome = self.inner.retain_ready_slot(
            operation, domain, binding, progress, token, observed, record,
        );
        if actual == DurableCommitOutcome::Committed && self.hide_stages.get() & 8 != 0 {
            self.hide_stages.set(self.hide_stages.get() & !8);
            DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost)
        } else {
            actual
        }
    }
}

fn loss(
    target: &SqliteImportTarget,
    hide: bool,
    abort: bool,
    fence: bool,
) -> inactive_business_import_faults::ReplyLoss<'_> {
    inactive_business_import_faults::ReplyLoss {
        inner: target,
        hide_stages: Cell::new(if hide { 8 } else { 0 }),
        abort_batch: Cell::new(abort),
        fence_finish: Cell::new(fence),
    }
}

#[test]
fn conditional_readiness_genuine_sqlite_all_members_restart_quorum_corrected_set_and_ambiguity() {
    let source: FrozenCompletionSource = preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history) = complete_history(network);
    let cut = derive_source_business_cut(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let verified: VerifiedImportPlan =
        verify_saved_business_import(reconstruction_plan(&source.fixture, &identity), &saved)
            .unwrap();
    assert!(verified.binding().row_count > runtime::inactive_import::MAX_IMPORT_BATCH_ROWS as u64);
    let members: Vec<FastPathValidatorEntry> = next_members(network);
    let proposal: OrderedProposal = inactive_business_import::proof_proposal(&history);
    let files: Files = Files::new();
    let mut votes: Vec<ReadinessVote> = Vec::new();
    for index in 0..REPLICAS {
        let state: PathBuf = files.path(&format!("state-{index}.db"));
        let body: PathBuf = files.path(&format!("body-{index}.db"));
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture::chain(),
            network.signers[index].id,
            network.domain(),
        );
        let operation: DurableOperationContext = fixture::context(41);
        let target: SqliteImportTarget = SqliteImportTarget::create(
            &state,
            namespace.clone(),
            operation.writer_fence(),
            verified.binding(),
        )
        .unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open(&body).unwrap();
        let signer: ReadinessSigningKey = ReadinessSigningKey::new(
            network.signers[index].id,
            network.signers[index].key.clone(),
        );
        assert!(
            retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &signer
            )
            .is_err()
        );
        assert_eq!(
            signer.signatures_created(),
            0,
            "FreshImport is not complete"
        );
        assert!(matches!(
            verified
                .advance(&target, &blobs, &operation, NonZeroUsize::MIN)
                .unwrap(),
            BusinessImportAdvance::Partial { .. }
        ));
        assert!(
            retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &signer
            )
            .is_err()
        );
        assert_eq!(signer.signatures_created(), 0, "Importing is not complete");
        complete(&verified, &target, &blobs, &operation);
        let wrong: ReadinessSigningKey =
            ReadinessSigningKey::new(network.signers[index].id, SigningKey::from([0xED; 32]));
        assert!(
            retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &wrong
            )
            .is_err()
        );
        assert_eq!(
            wrong.signatures_created(),
            0,
            "a supplied ID cannot assert its signing key"
        );
        let vote: ReadinessVote = if index == 0 {
            retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &loss(&target, true, false, false),
                &blobs,
                &operation,
                &members,
                &signer,
            )
            .unwrap()
        } else {
            retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &signer,
            )
            .unwrap()
        };
        assert_eq!(signer.signatures_created(), 1);
        let replay: ReadinessVote = retain_conditional_readiness(
            reconstruction_plan(&source.fixture, &identity),
            &saved,
            &target,
            &blobs,
            &operation,
            &members,
            &signer,
        )
        .unwrap();
        assert_eq!(
            encode_readiness_vote(&vote).unwrap(),
            encode_readiness_vote(&replay).unwrap()
        );
        assert_eq!(
            signer.signatures_created(),
            1,
            "present slot returns original signature"
        );
        inactive_business_import::assert_live_routes_denied(
            &target, &operation, &source, &proposal,
        );
        drop(target);
        drop(blobs);
        let target: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace, verified.binding()).unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&body).unwrap();
        let restarted: ReadinessSigningKey = ReadinessSigningKey::new(
            network.signers[index].id,
            network.signers[index].key.clone(),
        );
        let replay: ReadinessVote = retain_conditional_readiness(
            reconstruction_plan(&source.fixture, &identity),
            &saved,
            &target,
            &blobs,
            &operation,
            &members,
            &restarted,
        )
        .unwrap();
        assert_eq!(vote, replay);
        assert_eq!(restarted.signatures_created(), 0, "restart does not resign");
        inactive_business_import::assert_live_routes_denied(
            &target, &operation, &source, &proposal,
        );
        assert!(
            SqliteDurableStore::open(
                &state,
                SqliteNamespace::new(
                    fixture::chain(),
                    network.signers[index].id,
                    network.domain()
                ),
                operation.writer_fence()
            )
            .is_err()
        );
        if index == 0 {
            let connection: rusqlite::Connection = rusqlite::Connection::open(&state).unwrap();
            let (raw_key, raw_value): (Vec<u8>, Vec<u8>) = connection.query_row(
                "SELECT key, value FROM durable_state WHERE value IS NOT NULL ORDER BY key LIMIT 1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            connection
                .execute(
                    "UPDATE durable_state SET value = ?1 WHERE key = ?2",
                    rusqlite::params![b"corrupt-complete-inventory".as_slice(), raw_key],
                )
                .unwrap();
            let mut uncached: Vec<FastPathValidatorEntry> = members.clone();
            uncached[0].voting_power = 7;
            for candidate in [&members, &uncached] {
                assert!(
                    retain_conditional_readiness(
                        reconstruction_plan(&source.fixture, &identity),
                        &saved,
                        &target,
                        &blobs,
                        &operation,
                        candidate,
                        &restarted,
                    )
                    .is_err()
                );
                assert_eq!(
                    restarted.signatures_created(),
                    0,
                    "a complete flag or cached signature cannot hide corrupted full inventory"
                );
            }
            connection
                .execute(
                    "UPDATE durable_state SET value = ?1 WHERE key = ?2",
                    rusqlite::params![raw_value, raw_key],
                )
                .unwrap();
            let slot: ReadinessSlot = ReadinessSlot {
                identity: vote.subject.identity(&network.resolver).unwrap(),
                signer: vote.signer,
            };
            let slot_bytes: Vec<u8> =
                runtime::conditional_readiness::encode_readiness_slot(&slot).unwrap();
            let original_record: Vec<u8> = connection
                .query_row(
                    "SELECT record FROM durable_conditional_readiness WHERE slot = ?1",
                    rusqlite::params![slot_bytes],
                    |row| row.get(0),
                )
                .unwrap();
            let mut corrupt_record: ReadinessRecord =
                runtime::conditional_readiness::decode_readiness_record(&original_record).unwrap();
            *corrupt_record.vote_bytes.last_mut().unwrap() ^= 1;
            connection
                .execute(
                    "UPDATE durable_conditional_readiness SET record = ?1 WHERE slot = ?2",
                    rusqlite::params![
                        runtime::conditional_readiness::encode_readiness_record(&corrupt_record)
                            .unwrap(),
                        slot_bytes
                    ],
                )
                .unwrap();
            assert!(
                retain_conditional_readiness(
                    reconstruction_plan(&source.fixture, &identity),
                    &saved,
                    &target,
                    &blobs,
                    &operation,
                    &members,
                    &restarted,
                )
                .is_err()
            );
            assert_eq!(
                restarted.signatures_created(),
                0,
                "corrupt cached signatures are not repaired"
            );
            // Explicit storage-fault injection, not a production deletion API.
            // An absent cache must obtain new current-token retention after full
            // verification; it cannot assert the original creation observation.
            connection
                .execute(
                    "DELETE FROM durable_conditional_readiness WHERE slot = ?1",
                    rusqlite::params![slot_bytes],
                )
                .unwrap();
            let recreated: ReadinessSigningKey = ReadinessSigningKey::new(
                network.signers[index].id,
                network.signers[index].key.clone(),
            );
            assert_eq!(
                retain_conditional_readiness(
                    reconstruction_plan(&source.fixture, &identity),
                    &saved,
                    &target,
                    &blobs,
                    &operation,
                    &members,
                    &recreated,
                )
                .unwrap(),
                vote
            );
            assert_eq!(recreated.signatures_created(), 1);
            let recreated_bytes: Vec<u8> = connection
                .query_row(
                    "SELECT record FROM durable_conditional_readiness WHERE slot = ?1",
                    rusqlite::params![slot_bytes],
                    |row| row.get(0),
                )
                .unwrap();
            let recreated_record: ReadinessRecord =
                runtime::conditional_readiness::decode_readiness_record(&recreated_bytes).unwrap();
            assert_ne!(
                recreated_record.creation_token,
                runtime::conditional_readiness::decode_readiness_record(&original_record)
                    .unwrap()
                    .creation_token
            );
            assert_eq!(
                recreated_record.vote_bytes,
                encode_readiness_vote(&vote).unwrap()
            );
            drop(connection);
            let alternate: SavedBusinessCut =
                preseal_cut::alternate_retained_certificate(saved.clone(), &network.resolver);
            let alternate_plan: VerifiedImportPlan = verify_saved_business_import(
                reconstruction_plan(&source.fixture, &identity),
                &alternate,
            )
            .unwrap();
            assert_eq!(
                alternate_plan.binding().cut_digest,
                verified.binding().cut_digest
            );
            assert_ne!(
                alternate_plan.binding().package_digest,
                verified.binding().package_digest
            );
            assert_ne!(
                alternate_plan.binding().plan_digest,
                verified.binding().plan_digest
            );
            // An existing target cannot silently change its private package.
            assert!(
                retain_conditional_readiness(
                    reconstruction_plan(&source.fixture, &identity),
                    &alternate,
                    &target,
                    &blobs,
                    &operation,
                    &members,
                    &restarted,
                )
                .is_err()
            );
            assert_eq!(restarted.signatures_created(), 0);
            let alternate_target: SqliteImportTarget = SqliteImportTarget::create(
                files.path("alternate-state.db"),
                SqliteNamespace::new(
                    fixture::chain(),
                    network.signers[index].id,
                    network.domain(),
                ),
                operation.writer_fence(),
                alternate_plan.binding(),
            )
            .unwrap();
            let alternate_bodies: SqliteBlobStore =
                SqliteBlobStore::open(files.path("alternate-body.db")).unwrap();
            complete(
                &alternate_plan,
                &alternate_target,
                &alternate_bodies,
                &operation,
            );
            let alternate_signer: ReadinessSigningKey = ReadinessSigningKey::new(
                network.signers[index].id,
                network.signers[index].key.clone(),
            );
            let alternate_vote: ReadinessVote = retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &alternate,
                &alternate_target,
                &alternate_bodies,
                &operation,
                &members,
                &alternate_signer,
            )
            .unwrap();
            assert_eq!(alternate_signer.signatures_created(), 1);
            assert_eq!(
                alternate_vote, vote,
                "genuine equivalent quorum carriers change private transfer binding, not public readiness"
            );
            let mut corrected: Vec<FastPathValidatorEntry> = members.clone();
            corrected[0].voting_power = 2;
            let failure = retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &loss(&target, false, true, false),
                &blobs,
                &operation,
                &corrected,
                &restarted,
            )
            .unwrap_err();
            assert!(matches!(
                failure,
                crate::conditional_readiness::ConditionalReadinessError::Indeterminate(_)
            ));
            assert_eq!(
                restarted.signatures_created(),
                1,
                "unexported computed signature is not retained"
            );
            let second: ReadinessVote = retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &corrected,
                &restarted,
            )
            .unwrap();
            assert_ne!(
                vote.subject, second.subject,
                "corrected sets are nonexclusive before Seal"
            );
            let original: ReadinessVote = retain_conditional_readiness(
                reconstruction_plan(&source.fixture, &identity),
                &saved,
                &target,
                &blobs,
                &operation,
                &members,
                &restarted,
            )
            .unwrap();
            assert_eq!(original, vote);
            assert_eq!(
                restarted.signatures_created(),
                2,
                "exact original retry still does not resign"
            );
            let mut another: Vec<FastPathValidatorEntry> = members.clone();
            another[0].voting_power = 3;
            let fenced: ReadinessSigningKey = ReadinessSigningKey::new(
                network.signers[index].id,
                network.signers[index].key.clone(),
            );
            assert!(
                retain_conditional_readiness(
                    reconstruction_plan(&source.fixture, &identity),
                    &saved,
                    &loss(&target, false, false, true),
                    &blobs,
                    &operation,
                    &another,
                    &fenced
                )
                .is_err()
            );
            assert_eq!(
                fenced.signatures_created(),
                0,
                "changed writer before signing is refused"
            );
        }
        votes.push(vote);
    }
    let set: ValidatorSet = ValidatorSet::new(
        votes[0].subject.next_epoch,
        members
            .iter()
            .map(
                |member: &FastPathValidatorEntry| validator_set::ValidatorInfo {
                    id: member.id,
                    voting_power: member.voting_power,
                    signature_scheme: member.signature_scheme,
                    public_key: member.public_key.clone(),
                },
            )
            .collect(),
    )
    .unwrap();
    let owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(&network.resolver, &votes[0].subject, &set).unwrap();
    assert!(owner.form_certificate(&votes[..2]).is_err());
    let certificate = owner.form_certificate(&votes[..3]).unwrap();
    owner.verify_certificate(&certificate).unwrap();
    assert!(
        owner
            .form_certificate(&[votes[0].clone(), votes[0].clone(), votes[1].clone()])
            .is_err()
    );
    assert_eq!(
        snapshot(network),
        before,
        "readiness cannot change the outgoing source"
    );
}

#[test]
fn conditional_readiness_real_initial_e_four_separate_imports_and_restarted_weighted_certificate() {
    let source: crate::ordered_economics::RegisteredCutFixture =
        crate::ordered_economics::registered_cut_fixture();
    let operation: DurableOperationContext = fixture::context(41);
    let verified: VerifiedImportPlan =
        verify_saved_business_import(source.plan(operation), source.saved()).unwrap();
    assert!(verified.binding().row_count > runtime::inactive_import::MAX_IMPORT_BATCH_ROWS as u64);
    let files: Files = Files::new();
    let members: &[FastPathValidatorEntry] = &source.next_set().validators;
    let mut votes: Vec<ReadinessVote> = Vec::new();
    let mut incoming_count: usize = 0;
    for (index, member) in members.iter().enumerate() {
        let state: PathBuf = files.path(&format!("abce-state-{index}.db"));
        let body: PathBuf = files.path(&format!("abce-body-{index}.db"));
        let namespace: SqliteNamespace = SqliteNamespace::new(
            source.manifest().context().chain_id().clone(),
            member.id,
            source.policy().domain(),
        );
        let target: SqliteImportTarget = SqliteImportTarget::create(
            &state,
            namespace.clone(),
            operation.writer_fence(),
            verified.binding(),
        )
        .unwrap();
        let bodies: SqliteBlobStore = SqliteBlobStore::open(&body).unwrap();
        complete(&verified, &target, &bodies, &operation);
        let signer: ReadinessSigningKey =
            ReadinessSigningKey::new(member.id, source.signing_key(member.id).clone());
        let vote: ReadinessVote = retain_conditional_readiness(
            source.plan(operation),
            source.saved(),
            &target,
            &bodies,
            &operation,
            members,
            &signer,
        )
        .unwrap();
        assert_eq!(signer.signatures_created(), 1);
        assert_eq!(vote.signer, member.id);
        assert_eq!(signer.public_key().as_slice(), member.public_key.as_slice());
        drop(target);
        drop(bodies);
        let target: SqliteImportTarget =
            SqliteImportTarget::open_existing(&state, namespace, verified.binding()).unwrap();
        let bodies: SqliteBlobStore = SqliteBlobStore::open_existing(&body).unwrap();
        let restarted: ReadinessSigningKey =
            ReadinessSigningKey::new(member.id, source.signing_key(member.id).clone());
        assert_eq!(
            retain_conditional_readiness(
                source.plan(operation),
                source.saved(),
                &target,
                &bodies,
                &operation,
                members,
                &restarted
            )
            .unwrap(),
            vote
        );
        assert_eq!(restarted.signatures_created(), 0);
        if source
            .policy()
            .engine()
            .validator_set()
            .get(member.id)
            .is_none()
        {
            incoming_count += 1;
            let foreign_key: SigningKey = SigningKey::from([0xEE; 32]);
            let foreign_id: ValidatorId =
                ValidatorId::new(ed25519_zebra::VerificationKey::from(&foreign_key).into());
            let foreign: Vec<FastPathValidatorEntry> = vec![FastPathValidatorEntry {
                id: foreign_id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: foreign_id.as_bytes().to_vec(),
            }];
            let unbonded: ReadinessSigningKey = ReadinessSigningKey::new(foreign_id, foreign_key);
            assert!(
                retain_conditional_readiness(
                    source.plan(operation),
                    source.saved(),
                    &target,
                    &bodies,
                    &operation,
                    &foreign,
                    &unbonded
                )
                .is_err()
            );
            assert_eq!(
                unbonded.signatures_created(),
                0,
                "a real key without an actual registered bond is not ready"
            );
            target
                .advance_writer_fence(
                    operation.writer_fence(),
                    fixture::context(42).writer_fence(),
                )
                .unwrap();
            assert!(
                retain_conditional_readiness(
                    source.plan(operation),
                    source.saved(),
                    &target,
                    &bodies,
                    &operation,
                    members,
                    &restarted
                )
                .is_err()
            );
            assert_eq!(
                restarted.signatures_created(),
                0,
                "stale incoming writer cannot replay or sign"
            );
            let current: DurableOperationContext = fixture::context(42);
            assert_eq!(
                retain_conditional_readiness(
                    source.plan(current),
                    source.saved(),
                    &target,
                    &bodies,
                    &current,
                    members,
                    &restarted
                )
                .unwrap(),
                vote
            );
            assert_eq!(
                restarted.signatures_created(),
                0,
                "current fenced retry returns original bytes"
            );
        }
        votes.push(vote);
    }
    assert_eq!(
        incoming_count, 1,
        "real E is not a genesis or outgoing committee member"
    );
    let set: ValidatorSet = ValidatorSet::new(
        source.next_set().context.epoch(),
        members
            .iter()
            .map(
                |member: &FastPathValidatorEntry| validator_set::ValidatorInfo {
                    id: member.id,
                    voting_power: member.voting_power,
                    signature_scheme: member.signature_scheme,
                    public_key: member.public_key.clone(),
                },
            )
            .collect(),
    )
    .unwrap();
    let owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(source.resolver(), &votes[0].subject, &set).unwrap();
    assert!(owner.form_certificate(&votes[..2]).is_err());
    owner
        .verify_certificate(&owner.form_certificate(&votes[..3]).unwrap())
        .unwrap();
    assert!(
        owner
            .form_certificate(&[votes[0].clone(), votes[0].clone(), votes[1].clone()])
            .is_err()
    );
}
