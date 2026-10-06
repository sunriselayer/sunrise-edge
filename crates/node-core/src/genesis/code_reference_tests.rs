//! DR-0198 baseline probe. Production remains unchanged in this commit.
//! Signed nested/outer data and all dependent instance bindings are genuine;
//! neither fresh nor retained stores are populated by raw test rows.

use super::*;
use crate::business_reconstruction::{
    BusinessReconstructionError, BusinessReconstructionOverlay, BusinessReconstructionPlan,
    BusinessReconstructionReport, SourceBusinessSnapshot,
};
use crate::ordered_economics::{OrderedEconomicsPolicy, OrderedHistoryIdentity};
use crate::test_support::capture::{assert_same_records_and_blobs, captured_source};
use execution::LocalWasmExecutionEngine;
use execution::local_execution::{instance_target, local_execution_signing_frame};
use execution::publication::UnverifiedDependencyRef;
use protocol_types::ProtocolVersion;
use runtime::{MemoryBlobStore, MemoryDurableStateStore};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{fs, io::Write, path::PathBuf};

fn root(manifest: &GenesisManifest) -> VerifiedGenesisRoot {
    let bytes: Vec<u8> = encode_genesis_manifest(manifest).unwrap();
    let digest: Digest32 = genesis_manifest_commitment(&tests::resolver(), manifest).unwrap();
    VerifiedGenesisRoot::verify_bytes(
        &tests::resolver(),
        &bytes,
        digest.bytes(),
        manifest.context(),
    )
    .unwrap()
}

/// Return coherently rebound data; signing is deliberately a separate step.
fn with_reference_context(revision: u64, code_context: PublicationContext) -> GenesisManifest {
    let mut manifest: GenesisManifest = tests::causal_bonded_manifest();
    let original: &UnverifiedDependencyRef = &manifest.initialization.intent.call.code;
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        original.origin().clone(),
        revision,
        code_context,
        *original.artifact_digest(),
    )
    .unwrap();
    let record: InstanceRecord = InstanceRecord {
        context: manifest.context().clone(),
        creator: manifest.initialization.intent.call.instance.creator,
        seed: manifest.initialization.intent.call.instance.seed,
        code: code.clone(),
        revision: 1,
        initializer: manifest.initialization.intent.call.entrypoint.clone(),
    };
    let target: execution::call::InstanceTarget =
        instance_target(&tests::resolver(), &record).unwrap();
    manifest.initialization.intent.call.code = code.clone();
    manifest.initialization.intent.call.instance = target.clone();
    manifest.fee_policy.code = code.clone();
    manifest.fee_policy.instance = target.clone();
    for resource in &mut manifest.economics_policy.resources {
        resource.code = code.clone();
        resource.instance = target.clone();
        resource.context = code.context().clone();
    }
    for entry in &mut manifest.objects {
        entry.authority.code = code.clone();
        entry.authority.instance = target.clone();
    }
    manifest
}

fn revision_manifest() -> GenesisManifest {
    let mut manifest: GenesisManifest = with_reference_context(2, tests::protocol());
    let frame: Vec<u8> =
        local_execution_signing_frame(manifest.context(), &manifest.initialization.intent).unwrap();
    manifest.initialization.signature = tests::key().sign(&frame).into();
    tests::resign_manifest(&mut manifest);
    manifest
}

fn private_reconstruction(
    root: &VerifiedGenesisRoot,
) -> Result<BusinessReconstructionReport, BusinessReconstructionError> {
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(root, tests::domain()).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: root.genesis_context().clone(),
        domain: tests::domain(),
        genesis_digest: root.digest(),
        anchor: policy.anchor(),
        through_height: 0,
        through_view: 0,
        through_digest: policy.anchor(),
    };
    let leg: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(root.genesis_context().clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
        genesis_root: root,
        operation_context: tests::context(1),
        domain: tests::domain(),
        resolver_history: &[],
        ordered_policy: &policy,
        ordered_history_identity: &identity,
        ordered_leg_policy: &leg,
        ordered_engine: &engine,
        paid_base_policy: &leg,
        paid_engine: &engine,
    };
    let mut overlay: BusinessReconstructionOverlay<'_> = BusinessReconstructionOverlay::new(plan)?;
    overlay.reconstruct(&[], &[])
}

#[test]
fn revision_reference_old_owner_accepts_fresh_and_exact_retained_genesis() {
    let manifest: GenesisManifest = revision_manifest();
    let verified: VerifiedGenesisRoot = root(&manifest);
    assert_eq!(manifest.publication.request().artifact().revision(), 1);
    assert_eq!(manifest.initialization.intent.call.code.revision(), 2);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(tests::domain(), tests::context(1).writer_fence());
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    assert!(matches!(
        install_genesis_with_history(
            &store,
            &tests::context(1),
            tests::domain(),
            verified.genesis_resolver(),
            &[],
            verified.manifest(),
            0
        )
        .unwrap(),
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    let before: SourceBusinessSnapshot =
        captured_source(&store, &blobs, &tests::context(1), tests::domain());
    assert!(!before.records.is_empty());
    assert!(matches!(
        install_genesis_with_history(
            &store,
            &tests::context(1),
            tests::domain(),
            verified.genesis_resolver(),
            &[],
            verified.manifest(),
            0
        )
        .unwrap(),
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
    let after: SourceBusinessSnapshot =
        captured_source(&store, &blobs, &tests::context(1), tests::domain());
    assert_same_records_and_blobs(&after, &before);
    assert_eq!(after.token, before.token);
    let report: BusinessReconstructionReport = private_reconstruction(&verified).unwrap();
    assert_eq!(report.genesis_digest, verified.digest());
    assert_eq!(report.ordered_height, 0);
    assert_eq!(report.owned_originals_replayed, 0);
    assert_same_records_and_blobs(
        &captured_source(&store, &blobs, &tests::context(1), tests::domain()),
        &before,
    );
}

#[test]
fn reference_context_only_is_already_refused_by_the_existing_economics_owner() {
    let code_context: PublicationContext = PublicationContext::new(
        tests::chain(),
        ProtocolVersion::new(4),
        tests::protocol().epoch(),
    )
    .unwrap();
    let manifest: GenesisManifest = with_reference_context(1, code_context);
    // Each resource follows its own code context; the unchanged outer policy
    // still pins the real original context. This is the existing refusal,
    // before the nested/outer manifest can even be validly encoded and signed.
    assert!(matches!(
        encode_genesis_manifest(&manifest),
        Err(GenesisError::NodeCore(NodeCoreError::PersistenceInvariant(
            "economics resource context mismatch"
        )))
    ));
}

#[test]
fn valid_original_profiles_still_install_and_reconcile_without_reapplication() {
    for manifest in [
        tests::build_bonded_fixture().0,
        tests::logical_bonded_manifest(),
        tests::freeze_bonded_manifest(),
        tests::causal_bonded_manifest(),
    ] {
        let verified: VerifiedGenesisRoot = root(&manifest);
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(tests::domain(), tests::context(1).writer_fence());
        let blobs: MemoryBlobStore = MemoryBlobStore::default();
        assert!(matches!(
            install_genesis(
                &store,
                &tests::context(1),
                tests::domain(),
                verified.genesis_resolver(),
                verified.manifest(),
                0
            )
            .unwrap(),
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        let before: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert!(matches!(
            install_genesis(
                &store,
                &tests::context(1),
                tests::domain(),
                verified.genesis_resolver(),
                verified.manifest(),
                0
            )
            .unwrap(),
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
        let after: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert_same_records_and_blobs(&after, &before);
        assert_eq!(after.token, before.token);
        if manifest.commitment_profile == CommitmentProfile::CausalAdmission {
            assert_eq!(
                private_reconstruction(&verified).unwrap().genesis_digest,
                verified.digest()
            );
        }
    }
}

fn export_file(path: PathBuf, bytes: &[u8]) {
    let mut file: fs::File = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "explicit offline old-owner fixture export; run only this unchanged baseline commit"]
fn revision_reference_export_genuine_old_owner_sqlite() {
    let directory: PathBuf = PathBuf::from(
        std::env::var_os("SUNRISE_GENESIS_REFERENCE_BASELINE_DIR")
            .expect("explicit empty local export directory required"),
    );
    assert!(directory.is_absolute() && directory.is_dir());
    assert!(fs::read_dir(&directory).unwrap().next().is_none());
    let manifest: GenesisManifest = revision_manifest();
    let verified: VerifiedGenesisRoot = root(&manifest);
    let namespace: SqliteNamespace = SqliteNamespace::new(
        tests::chain(),
        ValidatorId::new(tests::sender()),
        tests::domain(),
    );
    let state_path: PathBuf = directory.join("state.sqlite");
    assert!(!state_path.exists());
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &state_path,
            namespace.clone(),
            tests::context(1).writer_fence(),
        )
        .unwrap();
        assert!(matches!(
            install_genesis_with_history(
                &store,
                &tests::context(1),
                tests::domain(),
                verified.genesis_resolver(),
                &[],
                verified.manifest(),
                0
            )
            .unwrap(),
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        assert_eq!(
            store.writer_fence().unwrap(),
            tests::context(1).writer_fence()
        );
    }
    // Closing and reopening exercise real persistence, not a synthetic marker.
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_path, namespace).unwrap();
        let blobs: MemoryBlobStore = MemoryBlobStore::default();
        let before: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert!(!before.records.is_empty());
        assert!(matches!(
            install_genesis_with_history(
                &store,
                &tests::context(1),
                tests::domain(),
                verified.genesis_resolver(),
                &[],
                verified.manifest(),
                0
            )
            .unwrap(),
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
        let after: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert_same_records_and_blobs(&after, &before);
        assert_eq!(after.token, before.token);
        println!(
            "old_owner_sqlite=true records={} writer_generation={} mutation_sequence={} digest={}",
            before.records.len(),
            before.token.writer_fence().get(),
            before.token.mutation_sequence(),
            verified.digest()
        );
    }
    export_file(
        directory.join("manifest.bin"),
        &encode_genesis_manifest(verified.manifest()).unwrap(),
    );
    export_file(directory.join("digest.bin"), &verified.digest().bytes());
    assert_eq!(
        private_reconstruction(&verified).unwrap().genesis_digest,
        verified.digest()
    );
}
