//! Genuine saved cut -> independent raw plan -> file-backed inactive restore.
//! Exact original registration replay is inspection, not fresh authority.
use super::super::business_reconstruction::captured_source;
use super::*;
use crate::business_reconstruction::inactive_import::{BusinessImportAdvance, VerifiedImportPlan};
use execution::local_execution::{
    LocalContractEngine, LocalExecutionError, LocalExecutionOutcome, LocalExecutionRequest,
};
use runtime::inactive_import::NamespaceLifecycle;
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{
    cell::Cell,
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
            "sunrise-registration-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct ObservedEngine<'a> {
    inner: &'a dyn LocalContractEngine,
    calls: Cell<usize>,
}
impl LocalContractEngine for ObservedEngine<'_> {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        self.calls.set(self.calls.get().checked_add(1).unwrap());
        self.inner.execute(request)
    }
}

pub(super) fn assert_registration_restart_replay_and_fence(
    source: &RegisteredCutFixture,
    plan: &VerifiedImportPlan,
) {
    let network: &Network = &source.source.network;
    let files: Files = Files::new();
    let path: PathBuf = files.path("inactive.db");
    let namespace: SqliteNamespace =
        SqliteNamespace::new(fixture::chain(), network.signers[0].id, network.domain());
    let operation: DurableOperationContext = fixture::context(41);
    let target: SqliteImportTarget = SqliteImportTarget::create(
        &path,
        namespace.clone(),
        operation.writer_fence(),
        plan.binding(),
    )
    .unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open(files.path("bodies.db")).unwrap();
    let first: BusinessImportAdvance = plan
        .advance(&target, &blobs, &operation, NonZeroUsize::MIN)
        .unwrap();
    assert!(
        matches!(first, BusinessImportAdvance::Partial { new_batches: 1, .. }),
        "the real >128-row plan must actually stop before completion"
    );
    drop(target);
    let target: SqliteImportTarget =
        SqliteImportTarget::open_existing(&path, namespace.clone(), plan.binding()).unwrap();
    loop {
        match plan
            .advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .unwrap()
        {
            BusinessImportAdvance::Partial { new_batches, .. } => assert_eq!(new_batches, 1),
            BusinessImportAdvance::CompleteInactive {
                progress,
                new_batches,
            } => {
                assert_eq!(progress.next_ordinal, plan.binding().row_count);
                assert!(new_batches <= 1);
                break;
            }
        }
    }
    drop(target);
    let target: SqliteImportTarget =
        SqliteImportTarget::open_existing(&path, namespace.clone(), plan.binding()).unwrap();
    assert!(matches!(
        target
            .get_namespace_lifecycle(&operation, network.domain())
            .unwrap(),
        NamespaceLifecycle::CompleteInactive { .. }
    ));
    assert!(matches!(
        plan.advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .unwrap(),
        BusinessImportAdvance::CompleteInactive { new_batches: 0, .. }
    ));
    let bond_key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &e_id()).unwrap();
    let anchor_key: Vec<u8> = bond_registration_anchor_key(&fixture::chain(), &e_id()).unwrap();
    let funded: Object = funded_object(&source.source);
    let nonce_key: Vec<u8> =
        runtime::PersistenceLayout::new(fixture::chain(), fixture::protocol().protocol_version())
            .sender_nonce_key(*e_id().as_bytes(), fixture::protocol().epoch());
    for key in [
        bond_key.clone(),
        anchor_key.clone(),
        nonce_key,
        crate::local_instance_state::object_authority_key(funded.id),
    ] {
        let installed = target
            .get_versioned_durable(&operation, network.domain(), &key)
            .unwrap();
        let original = network.stores[0]
            .get_versioned_durable(&network.context, network.domain(), &key)
            .unwrap();
        assert_eq!(
            installed.value(),
            original.value(),
            "registration/raw operand differs for exact key {key:?}"
        );
    }
    let installed_bond = verify_registered_bond_chain(
        &target,
        &operation,
        network.domain(),
        &network.resolver,
        &network.history,
        &source.source.manifest,
        network.policy.genesis_digest(),
        e_id(),
    )
    .unwrap();
    assert_eq!(
        installed_bond.committed_at_checkpoint, CHECKPOINT,
        "signed/hash-linked registration checkpoint is not physically rebased"
    );
    let head = target
        .get_object_head(&operation, network.domain(), funded.id)
        .unwrap();
    let version = target
        .get_object_version(
            &operation,
            network.domain(),
            funded.id,
            head.object_version().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        version.created_checkpoint(),
        0,
        "only destination-local physical object coordinate is rebased"
    );
    let original_head = network.stores[0]
        .get_object_head(&network.context, network.domain(), funded.id)
        .unwrap();
    let original_version = network.stores[0]
        .get_object_version(
            &network.context,
            network.domain(),
            funded.id,
            original_head.object_version().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(head.object_version(), original_head.object_version());
    assert_eq!(head.digest(), original_head.digest());
    assert_eq!(head.owner_projection(), original_head.owner_projection());
    assert_eq!(
        head.routing_projection(),
        original_head.routing_projection()
    );
    assert_eq!(version.payload(), original_version.payload());
    assert_eq!(version.digest(), original_version.digest());
    assert_eq!(version.schema_version(), original_version.schema_version());
    assert_eq!(version.provenance(), original_version.provenance());
    assert_eq!(original_version.created_checkpoint(), CHECKPOINT);
    let source_snapshot = snapshot(network);
    // Bond history is authenticated by its owning generation and signed
    // registration anchor, not invented generic StateKey provenance. Both
    // signed/raw rows were compared byte-exactly above.
    assert_eq!(
        crate::logical_generation::classify_fastpath_row(&bond_key),
        Some(crate::logical_generation::FastpathRowClass::AuthenticatedHistory)
    );
    let required: Vec<crate::logical_generation::LogicalSubject> = vec![
        crate::logical_generation::LogicalSubject::Object(funded.id),
        crate::logical_generation::LogicalSubject::StateKey(anchor_key),
        crate::logical_generation::LogicalSubject::SenderNonce {
            sender: *e_id().as_bytes(),
            epoch: fixture::protocol().epoch(),
        },
    ];
    let mut compared: usize = 0;
    for record in &source_snapshot.records {
        let runtime::portable::DurableRecordKey::State(key) = record.descriptor.key() else {
            continue;
        };
        if !crate::logical_generation::is_logical_provenance_key(key)
            || crate::logical_generation::is_logical_profile_key(key)
        {
            continue;
        }
        let provenance = crate::logical_generation::decode_logical_provenance_record(
            record.value.as_deref().unwrap(),
        )
        .unwrap();
        if required.contains(&provenance.subject) {
            let installed = target
                .get_versioned_durable(&operation, network.domain(), key)
                .unwrap();
            assert_eq!(
                installed.value(),
                record.value.as_deref(),
                "authenticated registration logical provenance remains byte-exact"
            );
            compared = compared.checked_add(1).unwrap();
        }
    }
    assert_eq!(compared, required.len());
    let original_receipt: DurableRequestReceipt = receipt(network, 0, REGISTER).unwrap();
    assert_eq!(
        original_receipt.event_digest(),
        crate::bond_lifecycle::registration::bond_registration_receipt_digest(
            &network.resolver,
            &fixture::protocol(),
            &source.registration.intent
        )
        .unwrap()
    );
    assert_eq!(
        target
            .get_request_receipt(
                &operation,
                network.domain(),
                DurableRequestId::new(REGISTER).unwrap()
            )
            .unwrap()
            .unwrap(),
        original_receipt
    );
    let before = captured_source(&target, &blobs, &operation, network.domain());
    let observed: ObservedEngine<'_> = ObservedEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &network.policy,
        resolver: &network.resolver,
        history: &network.history,
        leg_policy: &network.leg_policy,
        engine: &observed,
        blobs: &blobs,
    };
    let expected: NodeDedupRecord =
        NodeDedupRecord::decode(original_receipt.canonical_bytes()).unwrap();
    let replay: NodeOutput = crate::bond_lifecycle::registration::handle_bond_registration_ordered(
        &target,
        &operation,
        &env,
        &source.registration,
        None,
    )
    .unwrap();
    assert_eq!(replay.responses(), expected.responses());
    assert_eq!(
        query_ordered_outcome(&target, &operation, &env, &REGISTER)
            .unwrap()
            .unwrap()
            .output
            .responses(),
        expected.responses()
    );
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[0],
        calls: Cell::new(0),
    };
    assert!(matches!(
        propose(&target, &operation, &env, None, &signer),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::InactiveImportNamespace
        ))
    ));
    assert_eq!(observed.calls.get(), 0);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(
        captured_source(&target, &blobs, &operation, network.domain()),
        before,
        "reopened original replay performs no object/nonce/bond/anchor/receipt or token mutation"
    );
    let rival: SqliteImportTarget =
        SqliteImportTarget::open_existing(&path, namespace, plan.binding()).unwrap();
    rival
        .advance_writer_fence(
            operation.writer_fence(),
            WriterFenceGeneration::new(42).unwrap(),
        )
        .unwrap();
    let fresh: DurableOperationContext = fixture::context(42);
    let after_fence = captured_source(&rival, &blobs, &fresh, network.domain());
    assert!(
        crate::bond_lifecycle::registration::handle_bond_registration_ordered(
            &target,
            &operation,
            &env,
            &source.registration,
            None
        )
        .is_err()
    );
    assert!(
        plan.advance(&target, &blobs, &operation, NonZeroUsize::MIN)
            .is_err()
    );
    assert_eq!(observed.calls.get(), 0);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(
        captured_source(&rival, &blobs, &fresh, network.domain()),
        after_fence
    );
}
