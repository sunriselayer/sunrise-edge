//! Genuine source -> saved proofs -> independently reexecuted raw plan ->
//! inactive SQLite restore. Only deliberate corruption controls copy local
//! signature caches; no positive receipt, certificate or business row is seeded.
use super::super::super::business_reconstruction::captured_source;
use super::*;
use crate::business_reconstruction::cut::{SavedBusinessCut, derive_source_business_cut};
use crate::business_reconstruction::inactive_import::{
    BusinessImportAdvance, VerifiedImportPlan, verify_saved_business_import,
};
use runtime::inactive_import::{InactiveImportRepository, NamespaceLifecycle};
use runtime_sqlite::SqliteImportTarget;
use std::{
    num::NonZeroUsize,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-genuine-inactive-{}-{nanos}",
            std::process::id()
        ));
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

fn namespace(network: &Network) -> SqliteNamespace {
    SqliteNamespace::new(fixture::chain(), network.signers[0].id, network.domain())
}
fn begin_before_restart(
    plan: &VerifiedImportPlan,
    target: &SqliteImportTarget,
    operation: &DurableOperationContext,
    network: &Network,
) {
    // Exact documented C8 initial progress, not a completion/raw-row permit.
    let mut frame: canonical_encoding::CanonicalStruct =
        canonical_encoding::CanonicalStruct::new(0x64C8, 1);
    frame
        .field_bytes(
            1,
            canonical_encoding::encode_digest32(&plan.binding().plan_digest).unwrap(),
        )
        .unwrap();
    frame.field_bytes(2, Vec::new()).unwrap();
    frame.field_u64(3, 0).unwrap();
    let accumulator: Digest32 = network
        .resolver
        .hash_for_purpose(
            fixture::protocol().epoch(),
            protocol_types::HashPurpose::NodeEvent,
            &frame.finish().unwrap(),
        )
        .unwrap();
    assert_eq!(
        target.begin_import(operation, network.domain(), plan.binding(), accumulator),
        DurableCommitOutcome::Committed
    );
}

fn complete(
    plan: &VerifiedImportPlan,
    target: &SqliteImportTarget,
    blobs: &SqliteBlobStore,
    operation: &DurableOperationContext,
) -> runtime::ImportProgress {
    loop {
        match plan
            .advance(target, blobs, operation, NonZeroUsize::MIN)
            .unwrap()
        {
            BusinessImportAdvance::Partial { new_batches, .. } => assert_eq!(new_batches, 1),
            BusinessImportAdvance::CompleteInactive {
                progress,
                new_batches,
            } => {
                assert!(new_batches <= 1);
                return progress;
            }
        }
    }
}

pub(super) fn proof_proposal(history: &[OrderedHistoryHeightMaterial]) -> OrderedProposal {
    let material: &OrderedHistoryHeightMaterial = &history[0];
    let proof: CommittedBlockProof = consensus::decode_committed_block_proof(
        &material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::CommitProof)
            .unwrap()
            .1,
    )
    .unwrap();
    let candidate: OrderedCandidate = decode_ordered_candidate(
        &material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
            .unwrap()
            .1,
    )
    .unwrap();
    OrderedProposal {
        proposal: proof.committed,
        candidate: Some(candidate),
    }
}

/// Typed early-origin errors, not merely an unrelated missing-state error.
fn denied(error: impl std::fmt::Display) {
    assert!(
        error.to_string().contains("inactive import"),
        "unexpected refusal: {error}"
    );
}

pub(super) fn assert_live_routes_denied<S>(
    store: &S,
    operation: &DurableOperationContext,
    source: &FrozenCompletionSource,
    proposal: &OrderedProposal,
) where
    S: runtime::StructuredDurableDomainStateStore
        + runtime::portable::DurablePortableRepository
        + runtime::outbox_guard::StructuredOutboxExclusionGuard,
{
    let network: &Network = &source.fixture.network;
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[0],
        calls: Cell::new(0),
    };
    let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&source.paid.bundle).unwrap();
    denied(
        crate::fast_path::prepare(
            store,
            &network.blobs,
            operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &observed,
            &signer,
            &bundle.signed_intent,
            99,
        )
        .unwrap_err(),
    );
    denied(
        crate::fast_path::publication::retain_publication(
            store,
            operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &source.paid.bundle,
            &signer,
        )
        .unwrap_err(),
    );
    denied(
        crate::ordered_economics::frontier::advance_frozen_frontier(
            store,
            operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &signer,
        )
        .unwrap_err(),
    );
    denied(propose(store, operation, &network.env(), None, &signer).unwrap_err());
    denied(process_proposal(store, operation, &network.env(), proposal, &signer).unwrap_err());
    denied(observe_proposal(store, operation, &network.env(), proposal).unwrap_err());
    denied(
        process_certificate(store, operation, &network.env(), &proposal.proposal.justify)
            .unwrap_err(),
    );
    denied(process_tick(store, operation, &network.env(), u64::MAX, &signer).unwrap_err());
    denied(
        crate::epoch_transition::propose_and_vote(
            store,
            operation,
            network.domain(),
            &network.resolver,
            &fixture::chain(),
            fixture::protocol().protocol_version(),
            Vec::new(),
            &signer,
        )
        .unwrap_err(),
    );
    denied(
        genesis::install_genesis(
            store,
            operation,
            network.domain(),
            &network.resolver,
            &source.fixture.manifest,
            99,
        )
        .unwrap_err(),
    );
    assert_eq!(
        observed.calls.get(),
        0,
        "no admission path executes a paid engine"
    );
    assert_eq!(
        signer.calls.get(),
        0,
        "no fresh or cached protocol response reaches a signer"
    );
}

fn original_replays(
    target: &SqliteImportTarget,
    blobs: &SqliteBlobStore,
    operation: &DurableOperationContext,
    source: &FrozenCompletionSource,
) {
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot =
        captured_source(target, blobs, operation, network.domain());
    let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&source.paid.bundle).unwrap();
    let expected: NodeDedupRecord =
        NodeDedupRecord::decode(receipt(network, 0, PAID_REQUEST).unwrap().canonical_bytes())
            .unwrap();
    let replay: NodeOutput = crate::fast_path::apply(
        target,
        blobs,
        operation,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &source.fixture.manifest.fee_policy,
        &observed,
        &bundle.signed_intent,
        &source.paid.certificate,
    )
    .unwrap();
    assert_eq!(replay.responses(), expected.responses());
    for request in [PAID_REQUEST, UNAPPLIED_REQUEST] {
        let expected: NodeDedupRecord =
            NodeDedupRecord::decode(receipt(network, 0, request).unwrap().canonical_bytes())
                .unwrap();
        let replay: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
            target,
            blobs,
            operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &observed,
            request,
            999,
        )
        .unwrap();
        assert_eq!(replay.responses(), expected.responses());
    }
    assert_eq!(
        observed.calls.get(),
        0,
        "original replay consumes exact receipts, never reexecutes or charges twice"
    );
    assert_eq!(
        captured_source(target, blobs, operation, network.domain()),
        before,
        "all rows/revisions/token and referenced bodies remain unchanged"
    );
}

fn verified_drain_retainer<S: DurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    network: &Network,
    record: &crate::fast_path::publication::FastPathPublicationRecord,
) -> (PublicationBundle, consensus::AvailabilityIdentity) {
    let manifest = consensus::bundle::decode_artifact_manifest(&record.manifest).unwrap();
    let contents: Vec<Vec<u8>> = manifest
        .entries
        .iter()
        .map(|entry| {
            let key: Vec<u8> = crate::fast_path::drain_publication::drain_publication_artifact_key(
                &fixture::chain(),
                fixture::protocol().epoch(),
                &record.request_id,
                entry,
            )
            .unwrap();
            store
                .get_versioned_durable(operation, network.domain(), &key)
                .unwrap()
                .value()
                .expect("actual complete retained artifact closure")
                .to_vec()
        })
        .collect();
    let bundle: PublicationBundle = PublicationBundle {
        domain: network.domain(),
        request_id: record.request_id,
        commitment_profile: consensus::bundle::LOGICAL_COMMITMENT_PROFILE,
        signed_intent: record.signed_intent.clone(),
        certificate: consensus::decode_fast_certificate(&record.certificate).unwrap(),
        witness: record.witness.clone(),
        manifest,
        contents,
    };
    let certifier: FastPathCertifier = FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        validator_set(&network.signers),
    )
    .unwrap();
    let identity: consensus::AvailabilityIdentity =
        crate::fast_path::drain_publication::verify_drain_publication_bundle_with_profile(
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            network.policy.admission_profile().unwrap(),
            network.domain(),
            &certifier,
            &bundle,
        )
        .unwrap();
    assert!(
        consensus::encode_availability_identity(&identity).unwrap() == record.identity,
        "full retained bundle must derive its exact owning availability identity"
    );
    (bundle, identity)
}

fn assert_private_drain_retainer<S: DurableDomainStateStore>(
    target: &S,
    operation: &DurableOperationContext,
    network: &Network,
    installed: &[u8],
    original: &[u8],
    request: [u8; 32],
) {
    let actual =
        crate::fast_path::publication::decode_fastpath_publication_record(installed).unwrap();
    let source =
        crate::fast_path::publication::decode_fastpath_publication_record(original).unwrap();
    assert_eq!(actual.context, source.context, "retainer context");
    assert_eq!(actual.request_id, request, "retainer natural key");
    assert_eq!(
        actual.request_id, source.request_id,
        "retainer original request"
    );
    assert!(
        actual.identity == source.identity,
        "retainer exact identity bytes"
    );
    assert!(
        actual.signed_intent == source.signed_intent,
        "retainer exact original signed intent bytes"
    );
    assert!(
        actual.witness == source.witness,
        "retainer exact certified logical witness, no checkpoint rewriting"
    );
    assert!(
        actual.manifest == source.manifest,
        "retainer exact closed artifact manifest"
    );
    let (applied, applied_identity) = verified_drain_retainer(target, operation, network, &actual);
    let (retained, retained_identity) =
        verified_drain_retainer(&network.stores[0], &network.context, network, &source);
    assert_eq!(applied_identity, retained_identity);
    assert!(
        applied.contents == retained.contents,
        "actual source/target artifact closure remains byte-exact"
    );
    let mut subject: FastCertificate = retained.certificate.clone();
    subject.votes = applied.certificate.votes.clone();
    assert!(
        subject == applied.certificate,
        "same chain/protocol/epoch/tx/effects/locked-object subjects; only a fully verified vote subset differs"
    );
    assert!(
        retained.certificate.votes != applied.certificate.votes,
        "this genuine fixture exercises distinct certifying quorums, not fabricated signatures"
    );
}

#[test]
fn inactive_business_import_genuine_sqlite_reopen_exact_replay_and_all_phase_guard_counters() {
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
    let plan: VerifiedImportPlan =
        verify_saved_business_import(reconstruction_plan(&source.fixture, &identity), &saved)
            .unwrap();
    assert!(
        plan.binding().row_count > runtime::inactive_import::MAX_IMPORT_BATCH_ROWS as u64,
        "real Publish/Instantiate/Call producers must force more than one row batch"
    );
    assert_eq!(
        snapshot(network),
        before,
        "factory cannot change the source"
    );
    let proposal: OrderedProposal = proof_proposal(&history);
    let control_signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[0],
        calls: Cell::new(0),
    };
    let control_engine: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    let original_bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&source.paid.bundle).unwrap();
    let frozen_prepare = crate::fast_path::prepare(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &source.fixture.manifest.fee_policy,
        &control_engine,
        &control_signer,
        &original_bundle.signed_intent,
        99,
    )
    .unwrap_err();
    assert!(
        matches!(
            frozen_prepare,
            crate::fast_path::FastPathError::Node(NodeCoreError::PersistenceInvariant(
                "admission closed by a committed ordered-economics epoch freeze"
            ))
        ),
        "ordinary frozen admission must preserve its owning Freeze refusal, not the import-origin guard: {frozen_prepare}"
    );
    crate::ordered_economics::frontier::advance_frozen_frontier(
        &network.stores[0],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &control_signer,
    )
    .unwrap();
    process_proposal(
        &network.stores[0],
        &network.context,
        &network.env(),
        &proposal,
        &control_signer,
    )
    .unwrap();
    assert_eq!(
        control_signer.calls.get(),
        0,
        "ordinary positive controls actually expose existing retained signatures without resigning"
    );
    assert_eq!(control_engine.calls.get(), 0);
    let files: Files = Files::new();
    let operation: DurableOperationContext = fixture::context(41);
    let target_path: PathBuf = files.path("destination.db");
    let target: SqliteImportTarget = SqliteImportTarget::create(
        &target_path,
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open(files.path("bodies.db")).unwrap();
    assert!(matches!(
        target
            .get_namespace_lifecycle(&operation, network.domain())
            .unwrap(),
        NamespaceLifecycle::FreshImport(_)
    ));
    assert_live_routes_denied(&target, &operation, &source, &proposal);
    assert!(
        SqliteDurableStore::open(&target_path, namespace(network), operation.writer_fence())
            .is_err()
    );
    begin_before_restart(&plan, &target, &operation, network);
    assert_live_routes_denied(&target, &operation, &source, &proposal);
    drop(target);
    let mut target: SqliteImportTarget =
        SqliteImportTarget::open_existing(&target_path, namespace(network), plan.binding())
            .unwrap();
    let first: BusinessImportAdvance = plan
        .advance(&target, &blobs, &operation, NonZeroUsize::MIN)
        .unwrap();
    assert!(
        matches!(first, BusinessImportAdvance::Partial { .. }),
        "this genuine fixture must actually interrupt before completion"
    );
    assert!(match first {
        BusinessImportAdvance::Partial { new_batches, .. }
        | BusinessImportAdvance::CompleteInactive { new_batches, .. } => new_batches == 1,
    });
    drop(target);
    target = SqliteImportTarget::open_existing(&target_path, namespace(network), plan.binding())
        .unwrap();
    let progress: runtime::ImportProgress = complete(&plan, &target, &blobs, &operation);
    assert_eq!(progress.next_ordinal, plan.binding().row_count);
    assert_live_routes_denied(&target, &operation, &source, &proposal);
    assert!(
        SqliteDurableStore::open(&target_path, namespace(network), operation.writer_fence())
            .is_err()
    );
    let restored: SourceBusinessSnapshot =
        captured_source(&target, &blobs, &operation, network.domain());
    let versions: Vec<&SourceSnapshotRecord> = restored
        .records
        .iter()
        .filter(|row| matches!(row.descriptor.key(), DurableRecordKey::ObjectVersion(..)))
        .collect();
    assert!(!versions.is_empty());
    for row in versions {
        let original: &SourceSnapshotRecord = before
            .records
            .iter()
            .find(|old| old.descriptor.key() == row.descriptor.key())
            .unwrap();
        let mut metadata = original.descriptor.metadata().clone();
        if let runtime::portable::DurableRecordMetadata::ObjectVersion {
            created_checkpoint, ..
        } = &mut metadata
        {
            *created_checkpoint = 0;
        } else {
            unreachable!();
        }
        assert_eq!(
            row.descriptor.metadata(),
            &metadata,
            "only physical runtime creation checkpoint is rebased, not version/digest/provenance"
        );
        assert_eq!(
            row.value, original.value,
            "immutable canonical object bytes are unchanged"
        );
    }
    for request in [
        PAID_REQUEST,
        UNAPPLIED_REQUEST,
        FREEZE_REQUEST,
        DRAIN_REQUEST,
    ] {
        assert_eq!(
            target
                .get_request_receipt(
                    &operation,
                    network.domain(),
                    DurableRequestId::new(request).unwrap()
                )
                .unwrap(),
            receipt(network, 0, request)
        );
    }
    for request in [PAID_REQUEST, UNAPPLIED_REQUEST] {
        let key: Vec<u8> = fastpath_certificate_key(&fixture::chain(), &request).unwrap();
        assert_eq!(
            target
                .get_versioned_durable(&operation, network.domain(), &key)
                .unwrap()
                .value(),
            network.value(0, &key).as_deref(),
            "restore actual independently verified application carrier B, not replay subset A"
        );
    }
    // Preserve exact independently authenticated logical provenance and every
    // signed/hash-linked business checkpoint rather than normalizing all State.
    for row in &restored.records {
        if let DurableRecordKey::State(key) = row.descriptor.key()
            && key != &genesis::genesis_marker_key(&fixture::protocol()).unwrap()
            && let Some(old) = before
                .records
                .iter()
                .find(|old| old.descriptor.key() == row.descriptor.key())
        {
            if let Some(request) = [PAID_REQUEST, UNAPPLIED_REQUEST]
                .into_iter()
                .find(|request| {
                    key == &crate::fast_path::drain_publication::drain_publication_key(
                        &fixture::chain(),
                        fixture::protocol().epoch(),
                        request,
                    )
                    .unwrap()
                })
            {
                // Exact owner-validated private retainer A, not a rewrite of
                // source retainer B. Actual applied carrier B remains separately
                // byte-exact above. Never exempt any familiar namespace prefix.
                assert_private_drain_retainer(
                    &target,
                    &operation,
                    network,
                    row.value.as_deref().unwrap(),
                    old.value.as_deref().unwrap(),
                    request,
                );
                continue;
            }
            if key
                == &crate::local_instance_state::fastpath_epoch_record_key(&fixture::chain())
                    .unwrap()
            {
                let mut original = crate::local_instance_state::decode_fastpath_epoch_record(
                    old.value.as_deref().unwrap(),
                )
                .unwrap();
                assert!(original.previous_epoch.is_none());
                original.activated_at_checkpoint = 0;
                assert_eq!(
                    row.value.as_deref().unwrap(),
                    crate::local_instance_state::encode_fastpath_epoch_record(&original).unwrap()
                );
                continue; // Only the initial local epoch installation coordinate.
            }
            let marker_key: Vec<u8> = genesis::genesis_marker_key(&fixture::protocol()).unwrap();
            if crate::logical_generation::is_logical_provenance_key(key)
                && !crate::logical_generation::is_logical_profile_key(key)
            {
                let original = crate::logical_generation::decode_logical_provenance_record(
                    old.value.as_deref().unwrap(),
                )
                .unwrap();
                if original.subject
                    == crate::logical_generation::LogicalSubject::StateKey(marker_key)
                {
                    let installed = crate::logical_generation::decode_logical_provenance_record(
                        row.value.as_deref().unwrap(),
                    )
                    .unwrap();
                    assert_eq!(installed.subject, original.subject);
                    assert_eq!(installed.generation, original.generation);
                    assert_eq!(installed.observed_epoch, original.observed_epoch);
                    continue; // Only genesis marker's local-coordinate digest differs.
                }
            }
            assert_eq!(
                row.value, old.value,
                "restored original business State must be exact: {key:?}"
            );
        }
    }
    original_replays(&target, &blobs, &operation, &source);
    assert!(matches!(
        plan.advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .unwrap(),
        BusinessImportAdvance::CompleteInactive { new_batches: 0, .. }
    ));
    // Genuine retained signature caches are excluded from the plan, but even
    // storage corruption introducing them cannot expose a live cached result.
    let cache_keys: Vec<Vec<u8>> = vec![
        crate::local_instance_state::fastpath_prepared_record_key(&fixture::chain(), &PAID_REQUEST)
            .unwrap(),
        crate::ordered_economics::identity::ordered_vote_record_key(&fixture::chain(), 1).unwrap(),
        crate::ordered_economics::frontier::key(
            &fixture::chain(),
            fixture::protocol().epoch(),
            b"frontier/",
        )
        .unwrap(),
    ];
    let sql: rusqlite::Connection = rusqlite::Connection::open(&target_path).unwrap();
    for key in cache_keys {
        let bytes: Vec<u8> = network
            .value(0, &key)
            .expect("genuine source local signing cache");
        sql.execute(
            "INSERT INTO durable_state (key,revision,value) VALUES (?1,?2,?3)",
            rusqlite::params![key, 1u64.to_be_bytes().as_slice(), bytes],
        )
        .unwrap();
    }
    drop(sql);
    assert_live_routes_denied(&target, &operation, &source, &proposal);
    assert!(
        plan.advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .is_err(),
        "completion reenumeration refuses surplus cached safety rows"
    );
    let rival: SqliteImportTarget =
        SqliteImportTarget::open_existing(&target_path, namespace(network), plan.binding())
            .unwrap();
    rival
        .advance_writer_fence(
            operation.writer_fence(),
            WriterFenceGeneration::new(42).unwrap(),
        )
        .unwrap();
    assert!(
        plan.advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .is_err()
    );
    let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    assert!(
        crate::fast_path::drain_apply::apply_drain_member(
            &target,
            &blobs,
            &operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &observed,
            PAID_REQUEST,
            99
        )
        .is_err()
    );
    assert_eq!(observed.calls.get(), 0);
    assert_eq!(snapshot(network), before);

    let mut wrong_floor = plan.binding().clone();
    wrong_floor.generation_floor = protocol_types::ExecutionGeneration::new(
        wrong_floor.generation_floor.get().checked_add(1).unwrap(),
    );
    let foreign: SqliteImportTarget = SqliteImportTarget::create(
        files.path("wrong-floor.db"),
        namespace(network),
        operation.writer_fence(),
        &wrong_floor,
    )
    .unwrap();
    assert!(
        plan.advance(&foreign, &blobs, &operation, NonZeroUsize::MIN)
            .is_err(),
        "a local stored floor cannot authorize a different pinned raw plan"
    );
    let corrupt_cursor_path: PathBuf = files.path("wrong-progress.db");
    let corrupt_cursor: SqliteImportTarget = SqliteImportTarget::create(
        &corrupt_cursor_path,
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    begin_before_restart(&plan, &corrupt_cursor, &operation, network);
    let mut altered: runtime::ImportProgress = corrupt_cursor
        .read_import_progress(&operation, network.domain())
        .unwrap()
        .unwrap();
    altered.accumulator = plan.binding().cut_digest;
    let cursor_sql: rusqlite::Connection =
        rusqlite::Connection::open(&corrupt_cursor_path).unwrap();
    cursor_sql
        .execute(
            "UPDATE durable_import_progress SET progress = ?1 WHERE id = 1",
            rusqlite::params![runtime::inactive_import::encode_import_progress(&altered).unwrap()],
        )
        .unwrap();
    assert!(
        plan.advance(&corrupt_cursor, &blobs, &operation, NonZeroUsize::MIN)
            .is_err(),
        "canonical but wrong progress cannot silently resume"
    );
    assert_live_routes_denied(&corrupt_cursor, &operation, &source, &proposal);
    drop(cursor_sql);
    let corrupt_rows_path: PathBuf = files.path("wrong-prefix.db");
    let corrupt_rows: SqliteImportTarget = SqliteImportTarget::create(
        &corrupt_rows_path,
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let first = plan
        .advance(&corrupt_rows, &blobs, &operation, NonZeroUsize::MIN)
        .unwrap();
    let row_sql: rusqlite::Connection = rusqlite::Connection::open(&corrupt_rows_path).unwrap();
    row_sql.execute("UPDATE durable_state SET value = ?1 WHERE key = (SELECT key FROM durable_state WHERE value IS NOT NULL ORDER BY key LIMIT 1)", rusqlite::params![b"corrupted-prior-prefix".as_slice()]).unwrap();
    let corrupt_before: SourceBusinessSnapshot =
        captured_source(&corrupt_rows, &blobs, &operation, network.domain());
    let progress_before = corrupt_rows
        .read_import_progress(&operation, network.domain())
        .unwrap();
    assert!(
        plan.advance(
            &corrupt_rows,
            &blobs,
            &operation,
            NonZeroUsize::new(128).unwrap()
        )
        .is_err(),
        "complete raw inventory revalidation rejects corrupt prior rows, even when their cursor matches"
    );
    assert_eq!(
        captured_source(&corrupt_rows, &blobs, &operation, network.domain()),
        corrupt_before,
        "a corrupt matching prefix refuses before writing any later batch or body"
    );
    assert_eq!(
        corrupt_rows
            .read_import_progress(&operation, network.domain())
            .unwrap(),
        progress_before
    );
    if !first.is_complete() {
        assert!(
            matches!(
                corrupt_rows
                    .get_namespace_lifecycle(&operation, network.domain())
                    .unwrap(),
                NamespaceLifecycle::Importing { .. }
            ),
            "a corrupt incomplete target cannot mark completion"
        );
    }
    assert_live_routes_denied(&corrupt_rows, &operation, &source, &proposal);
    drop(row_sql);

    // Real begin, batch and finish commits with their acknowledgements lost:
    // core reconciles exact fresh progress+inventory rather than rerunning.
    let uncertain: SqliteImportTarget = SqliteImportTarget::create(
        files.path("reply-loss.db"),
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let lost: super::inactive_business_import_faults::ReplyLoss<'_> =
        super::inactive_business_import_faults::ReplyLoss {
            inner: &uncertain,
            hide_stages: Cell::new(7),
            abort_batch: Cell::new(false),
            fence_finish: Cell::new(false),
        };
    loop {
        if plan
            .advance(&lost, &blobs, &operation, NonZeroUsize::MIN)
            .unwrap()
            .is_complete()
        {
            break;
        }
    }
    assert_eq!(
        lost.hide_stages.get(),
        0,
        "all three actual committed replies were hidden"
    );
    original_replays(&uncertain, &blobs, &operation, &source);
    let aborted: SqliteImportTarget = SqliteImportTarget::create(
        files.path("no-batch-reply.db"),
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let stopped: super::inactive_business_import_faults::ReplyLoss<'_> =
        super::inactive_business_import_faults::ReplyLoss {
            inner: &aborted,
            hide_stages: Cell::new(0),
            abort_batch: Cell::new(true),
            fence_finish: Cell::new(false),
        };
    assert!(matches!(
        plan.advance(&stopped, &blobs, &operation, NonZeroUsize::MIN),
        Err(crate::business_reconstruction::inactive_import::BusinessImportError::Indeterminate(_))
    ));
    assert_eq!(
        aborted
            .read_import_progress(&operation, network.domain())
            .unwrap()
            .unwrap()
            .next_ordinal,
        0,
        "an uncertain unchanged cursor stops before any blind advance"
    );
    complete(&plan, &aborted, &blobs, &operation);
    let raced: SqliteImportTarget = SqliteImportTarget::create(
        files.path("finish-race.db"),
        namespace(network),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let race: super::inactive_business_import_faults::ReplyLoss<'_> =
        super::inactive_business_import_faults::ReplyLoss {
            inner: &raced,
            hide_stages: Cell::new(0),
            abort_batch: Cell::new(false),
            fence_finish: Cell::new(true),
        };
    loop {
        match plan.advance(&race, &blobs, &operation, NonZeroUsize::MIN) {
            Ok(BusinessImportAdvance::Partial { .. }) => {}
            Err(_) => break,
            Ok(BusinessImportAdvance::CompleteInactive { .. }) => {
                panic!("a raced writer fence cannot mark completion")
            }
        }
    }
    assert!(matches!(
        raced
            .get_namespace_lifecycle(&fixture::context(42), network.domain())
            .unwrap(),
        NamespaceLifecycle::Importing { .. }
    ));
}
