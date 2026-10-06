//! DR-0198 exact published-code binding, following actual old-owner acceptance.
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
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

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
fn revision_reference_is_refused_before_any_fresh_memory_business_writes() {
    let manifest: GenesisManifest = revision_manifest();
    let verified: VerifiedGenesisRoot = root(&manifest);
    assert_eq!(manifest.publication.request().artifact().revision(), 1);
    assert_eq!(manifest.initialization.intent.call.code.revision(), 2);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(tests::domain(), tests::context(1).writer_fence());
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let before: SourceBusinessSnapshot =
        captured_source(&store, &blobs, &tests::context(1), tests::domain());
    assert!(before.records.is_empty());
    assert!(matches!(
        install_genesis_with_history(
            &store,
            &tests::context(1),
            tests::domain(),
            verified.genesis_resolver(),
            &[],
            verified.manifest(),
            0
        ),
        Err(GenesisError::Invalid(
            "initialization code reference mismatch"
        ))
    ));
    let after: SourceBusinessSnapshot =
        captured_source(&store, &blobs, &tests::context(1), tests::domain());
    assert_same_records_and_blobs(&after, &before);
    assert_eq!(after.token, before.token);
    assert!(matches!(
        private_reconstruction(&verified),
        Err(BusinessReconstructionError::Invalid(
            "private signed-genesis installation failed"
        ))
    ));
    assert_same_records_and_blobs(
        &captured_source(&store, &blobs, &tests::context(1), tests::domain()),
        &before,
    );
}

struct FreshDirectory(PathBuf);

impl FreshDirectory {
    fn new() -> Self {
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-genesis-reference-refusal-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for FreshDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn revision_reference_fresh_sqlite_refusal_survives_close_reopen_without_mutation() {
    let directory: FreshDirectory = FreshDirectory::new();
    let path: PathBuf = directory.0.join("state.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        tests::chain(),
        ValidatorId::new(tests::sender()),
        tests::domain(),
    );
    let verified: VerifiedGenesisRoot = root(&revision_manifest());
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let before: SourceBusinessSnapshot;
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace.clone(), tests::context(1).writer_fence())
                .unwrap();
        before = captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert!(before.records.is_empty());
        assert!(matches!(
            install_genesis_with_history(
                &store,
                &tests::context(1),
                tests::domain(),
                verified.genesis_resolver(),
                &[],
                verified.manifest(),
                0
            ),
            Err(GenesisError::Invalid(
                "initialization code reference mismatch"
            ))
        ));
        let after: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(1), tests::domain());
        assert_same_records_and_blobs(&after, &before);
        assert_eq!(after.token, before.token);
        assert_eq!(
            store.writer_fence().unwrap(),
            tests::context(1).writer_fence()
        );
    }
    let reopened: SqliteDurableStore = SqliteDurableStore::open_existing(&path, namespace).unwrap();
    let persisted: SourceBusinessSnapshot =
        captured_source(&reopened, &blobs, &tests::context(1), tests::domain());
    assert_same_records_and_blobs(&persisted, &before);
    assert_eq!(persisted.token, before.token);
    assert_eq!(
        reopened.writer_fence().unwrap(),
        tests::context(1).writer_fence()
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

#[test]
#[ignore = "requires genuine SQLite exported by unchanged old owner at 8c91a680; never seeds current-state rows"]
fn revision_reference_retained_old_owner_sqlite_is_refused_without_repair() {
    let directory: PathBuf = PathBuf::from(
        std::env::var_os("SUNRISE_GENESIS_REFERENCE_BASELINE_DIR")
            .expect("explicit genuine old-owner export directory required"),
    );
    assert!(directory.is_absolute() && directory.is_dir());
    let manifest: GenesisManifest = revision_manifest();
    let expected: VerifiedGenesisRoot = root(&manifest);
    let bytes: Vec<u8> = fs::read(directory.join("manifest.bin")).unwrap();
    assert_eq!(bytes, encode_genesis_manifest(&manifest).unwrap());
    assert_eq!(
        fs::read(directory.join("digest.bin")).unwrap(),
        expected.digest().bytes()
    );
    let verified: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &tests::resolver(),
        &bytes,
        expected.digest().bytes(),
        &tests::protocol(),
    )
    .unwrap();
    let namespace: SqliteNamespace = SqliteNamespace::new(
        tests::chain(),
        ValidatorId::new(tests::sender()),
        tests::domain(),
    );
    let state_path: PathBuf = directory.join("state.sqlite");
    assert!(
        state_path.is_file(),
        "missing baseline must fail, not bootstrap"
    );
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let before: SourceBusinessSnapshot;
    // The current owner can only open the already-installed baseline. Its
    // explicit restart fence is claimed before observing the no-write refusal.
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_path, namespace.clone()).unwrap();
        assert_eq!(
            store.writer_fence().unwrap(),
            tests::context(1).writer_fence()
        );
        store
            .advance_writer_fence(
                tests::context(1).writer_fence(),
                tests::context(2).writer_fence(),
            )
            .unwrap();
        before = captured_source(&store, &blobs, &tests::context(2), tests::domain());
        assert!(!before.records.is_empty());
        assert!(matches!(
            install_genesis_with_history(
                &store,
                &tests::context(2),
                tests::domain(),
                verified.genesis_resolver(),
                &[],
                verified.manifest(),
                0
            ),
            Err(GenesisError::Invalid(
                "initialization code reference mismatch"
            ))
        ));
        let after: SourceBusinessSnapshot =
            captured_source(&store, &blobs, &tests::context(2), tests::domain());
        assert_same_records_and_blobs(&after, &before);
        assert_eq!(after.token, before.token);
        println!(
            "retained_refusal=true records={} writer_generation={} mutation_sequence={} digest={}",
            before.records.len(),
            before.token.writer_fence().get(),
            before.token.mutation_sequence(),
            verified.digest()
        );
    }
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_path, namespace).unwrap();
    assert_eq!(
        reopened.writer_fence().unwrap(),
        tests::context(2).writer_fence()
    );
    let persisted: SourceBusinessSnapshot =
        captured_source(&reopened, &blobs, &tests::context(2), tests::domain());
    assert_same_records_and_blobs(&persisted, &before);
    assert_eq!(persisted.token, before.token);
    assert!(matches!(
        private_reconstruction(&verified),
        Err(BusinessReconstructionError::Invalid(
            "private signed-genesis installation failed"
        ))
    ));
    let after_private: SourceBusinessSnapshot =
        captured_source(&reopened, &blobs, &tests::context(2), tests::domain());
    assert_same_records_and_blobs(&after_private, &before);
    assert_eq!(after_private.token, before.token);
}
