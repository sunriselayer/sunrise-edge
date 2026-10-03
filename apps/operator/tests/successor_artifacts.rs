//! Genuine on-disk regression coverage for the successor artifact
//! transport adapter (DR-0189 Section 3.1), reusing the existing causal
//! genesis fixture and a real [`VerifiedGenesisRoot::verify_bytes`] root.
//! These prove transport bound and local-attachment behavior only -- never
//! committed-proof, Seal or consensus verification, which stays with the
//! one node-core source-free verifier this adapter feeds.
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;
mod support {
    pub use super::genesis_fixture;
}
#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;

use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedHistoryComponentKind, OrderedHistoryComponentRef,
    OrderedHistoryHeightDescriptor, OrderedHistoryIdentity,
    encode_ordered_history_height_descriptor, ordered_history_component_digest,
};
use runtime::{DurableOperationContext, StorageCorrelationId, StorageDeadline, WriterFenceGeneration};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use sunrise_edge_operator::{immutable_archive::ImmutableArchive, successor_artifacts::SuccessorArtifactFiles};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-successor-artifacts-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

fn private_operation() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX / 2).unwrap(),
        StorageCorrelationId::new([0xC7; 16]).unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn open_certificate_fixture<'a>(
    root: &'a VerifiedGenesisRoot,
    domain: protocol_types::AtomicityDomainId,
    policy: &'a OrderedEconomicsPolicy,
    identity: &'a OrderedHistoryIdentity,
    base_policy: &'a LocalExecutionPolicy,
    engine: &'a LocalWasmExecutionEngine,
    cut_dir: &Path,
    history_dir: &Path,
    certificate_dir: &Path,
) -> SuccessorArtifactFiles<'a> {
    SuccessorArtifactFiles::new(
        BusinessReconstructionPlan {
            genesis_root: root,
            operation_context: private_operation(),
            domain,
            resolver_history: &[],
            ordered_policy: policy,
            ordered_history_identity: identity,
            ordered_leg_policy: base_policy,
            ordered_engine: engine,
            paid_base_policy: base_policy,
            paid_engine: engine,
        },
        ImmutableArchive::open_read_only(cut_dir).unwrap(),
        ImmutableArchive::open_read_only(history_dir).unwrap(),
        ImmutableArchive::open_read_only(certificate_dir).unwrap(),
    )
}


#[test]
fn successor_artifact_files_enforces_exact_certificate_length_transport() {
    let fixture = causal_genesis_fixture::build("successor-artifact-certificate");
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.network.resolver,
        &fixture.network.manifest_bytes,
        fixture.network.manifest_digest,
        &fixture.network.context,
    )
    .unwrap();
    let domain = fixture.network.domain;
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_genesis_root(&root, domain).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: fixture.network.context.clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: 0,
        through_view: 0,
        through_digest: policy.anchor(),
    };
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.network.context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();

    let cut_dir: TempDir = TempDir::new("cut");
    let history_dir: TempDir = TempDir::new("history");
    let certificate_dir: TempDir = TempDir::new("certificate");
    let certificate_bytes: [u8; 10] = [0xCC; 10];
    std::fs::write(certificate_dir.0.join("certificate.bin"), certificate_bytes).unwrap();

    let mut open = || {
        open_certificate_fixture(
            &root,
            domain,
            &policy,
            &identity,
            &base_policy,
            &engine,
            &cut_dir.0,
            &history_dir.0,
            &certificate_dir.0,
        )
    };

    // Exact length: the only legitimate request.
    assert_eq!(
        open().readiness_certificate(10).unwrap(),
        certificate_bytes.to_vec()
    );
    // Short: a claimed length below the real file size must refuse, never
    // silently return a truncated prefix.
    assert!(open().readiness_certificate(9).is_err());
    // Long: a claimed length above the real file size must refuse, never
    // silently return the shorter real bytes as if they matched.
    assert!(open().readiness_certificate(11).is_err());
    // Oversized: above the owning 1 MiB transport bound entirely.
    assert!(open().readiness_certificate(1024 * 1024 + 1).is_err());
    // Missing: no certificate file at all.
    std::fs::remove_file(certificate_dir.0.join("certificate.bin")).unwrap();
    assert!(open().readiness_certificate(10).is_err());
}

#[test]
fn successor_artifact_files_detects_replaced_or_symlinked_history_directory() {
    let fixture = causal_genesis_fixture::build("successor-artifact-history-swap");
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.network.resolver,
        &fixture.network.manifest_bytes,
        fixture.network.manifest_digest,
        &fixture.network.context,
    )
    .unwrap();
    let domain = fixture.network.domain;
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_genesis_root(&root, domain).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: fixture.network.context.clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: 1,
        through_view: 1,
        through_digest: policy.anchor(),
    };
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.network.context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let plan = BusinessReconstructionPlan {
        genesis_root: &root,
        operation_context: private_operation(),
        domain,
        resolver_history: &[],
        ordered_policy: &policy,
        ordered_history_identity: &identity,
        ordered_leg_policy: &base_policy,
        ordered_engine: &engine,
        paid_base_policy: &base_policy,
        paid_engine: &engine,
    };

    let cut_dir: TempDir = TempDir::new("cut");
    let certificate_dir: TempDir = TempDir::new("certificate");
    let history_path: PathBuf = std::env::temp_dir().join(format!(
        "sunrise-successor-artifacts-history-swap-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&history_path).unwrap();
    let component_bytes: Vec<u8> = vec![0xAB; 24];
    let digest = ordered_history_component_digest(&policy, &component_bytes).unwrap();
    let descriptor = OrderedHistoryHeightDescriptor {
        identity: identity.clone(),
        height: 1,
        view: 1,
        block_digest: identity.through_digest,
        components: vec![OrderedHistoryComponentRef {
            kind: OrderedHistoryComponentKind::CommitProof,
            length: component_bytes.len() as u64,
            digest,
        }],
    };
    std::fs::write(history_path.join("chunk-size.bin"), 1024_u32.to_be_bytes()).unwrap();
    let height_dir: PathBuf = history_path.join(format!("height-{:020}", 1));
    std::fs::create_dir(&height_dir).unwrap();
    std::fs::write(
        height_dir.join("descriptor.bin"),
        encode_ordered_history_height_descriptor(&descriptor).unwrap(),
    )
    .unwrap();
    let component_dir: PathBuf =
        height_dir.join(format!("component-{:02}", OrderedHistoryComponentKind::CommitProof as u16));
    std::fs::create_dir(&component_dir).unwrap();
    std::fs::write(
        component_dir.join(format!("chunk-{:020}.bin", 0)),
        &component_bytes,
    )
    .unwrap();

    let history_archive: ImmutableArchive = ImmutableArchive::open_read_only(&history_path).unwrap();
    let mut artifacts = SuccessorArtifactFiles::new(
        plan,
        ImmutableArchive::open_read_only(&cut_dir.0).unwrap(),
        history_archive,
        ImmutableArchive::open_read_only(&certificate_dir.0).unwrap(),
    );
    assert_eq!(
        artifacts.history_height(&identity, 1).unwrap().components,
        vec![(OrderedHistoryComponentKind::CommitProof, component_bytes)]
    );

    // Detach: remove the directory the held handle was opened against and
    // replace it with a fresh, differently-identified directory at the
    // same path. The held handle must refuse, never silently read the
    // substitute inode under the original pathname.
    std::fs::remove_dir_all(&history_path).unwrap();
    std::fs::create_dir(&history_path).unwrap();
    assert!(artifacts.history_height(&identity, 1).is_err());

    #[cfg(unix)]
    {
        // Replace again with a symlink to an unrelated real directory.
        std::fs::remove_dir_all(&history_path).unwrap();
        let elsewhere: TempDir = TempDir::new("history-elsewhere");
        std::os::unix::fs::symlink(&elsewhere.0, &history_path).unwrap();
        assert!(artifacts.history_height(&identity, 1).is_err());
        std::fs::remove_file(&history_path).unwrap();
        std::fs::create_dir(&history_path).unwrap();
    }
    let _ignored = std::fs::remove_dir_all(&history_path);
}
