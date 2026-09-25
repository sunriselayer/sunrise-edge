//! Operator command smoke evidence against actual file-backed SQLite files.
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableOperationContext, DurableReadError, StateMutation,
    StateMutationEntry, StateReadAssertion, StorageCorrelationId, StorageDeadline,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_devnet::{DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-fee-inventory-{}-{nanos}",
            std::process::id(),
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn command(directory: &TestDirectory) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_fee_escrow_inventory"));
    command.args([
        "--data-dir",
        directory.0.to_str().unwrap(),
        "--chain-id",
        "inventory-test",
        "--validator-id",
        &"11".repeat(32),
        "--domain",
        &"22".repeat(32),
        "--protocol-version",
        "3",
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--page-size",
        "1",
        "--timeout-seconds",
        "60",
    ]);
    command
}

fn namespace() -> SqliteNamespace {
    SqliteNamespace::new(
        ChainId::new("inventory-test").unwrap(),
        ValidatorId::new([0x11; 32]),
        AtomicityDomainId::new([0x22; 32]).unwrap(),
    )
}

#[test]
fn offline_sweep_does_not_bootstrap_or_claim_without_confirmation() {
    let directory: TestDirectory = TestDirectory::new();
    let missing: Output = command(&directory)
        .arg("--confirm-offline-fence-advance")
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(!directory.0.join(DEVNET_DATABASE_FILE).exists());
    assert!(!directory.0.join(DEVNET_BLOB_DATABASE_FILE).exists());

    let structured: SqliteDurableStore = SqliteDurableStore::open(
        directory.0.join(DEVNET_DATABASE_FILE),
        namespace(),
        WriterFenceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let blobs: SqliteBlobStore =
        SqliteBlobStore::open(directory.0.join(DEVNET_BLOB_DATABASE_FILE)).unwrap();
    drop(blobs);
    let unconfirmed: Output = command(&directory).output().unwrap();
    assert!(!unconfirmed.status.success());
    assert_eq!(structured.writer_fence().unwrap().get(), 1);

    let good: Output = command(&directory)
        .arg("--confirm-offline-fence-advance")
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert_eq!(structured.writer_fence().unwrap().get(), 2);
    let stdout: String = String::from_utf8(good.stdout).unwrap();
    assert!(stdout.contains("complete=true"));
    assert!(stdout.contains("verified_rows=0"));
    assert!(stdout.contains("writer_generation=2"));
    assert!(stdout.contains(&format!("data_dir={}", directory.0.display())));
    assert!(stdout.contains(&format!("validator_id={}", "11".repeat(32))));
    assert!(stdout.contains(&format!("domain={}", "22".repeat(32))));
    let old_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    );
    assert!(matches!(
        structured.get_versioned_durable(
            &old_context, AtomicityDomainId::new([0x22; 32]).unwrap(), b"any-key",
        ),
        Err(DurableReadError::WriterFenced { active_generation })
            if active_generation.get() == 2
    ));

    let again: Output = command(&directory)
        .arg("--confirm-offline-fence-advance")
        .output()
        .unwrap();
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert_eq!(structured.writer_fence().unwrap().get(), 3);

    let active_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(3).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    );
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x22; 32]).unwrap();
    let key: Vec<u8> = node_core::local_instance_state::fastpath_settlement_key(
        &ChainId::new("inventory-test").unwrap(),
        &[0x61; 32],
    )
    .unwrap();
    let observed = structured
        .get_versioned_durable(&active_context, domain, &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(vec![0xFF])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        structured.commit_durable(&active_context, transaction),
        DurableCommitOutcome::Committed
    );
    let corrupt: Output = command(&directory)
        .arg("--confirm-offline-fence-advance")
        .output()
        .unwrap();
    assert!(!corrupt.status.success());
    assert!(
        corrupt.stdout.is_empty(),
        "no partial complete result is permitted"
    );
    assert_eq!(structured.writer_fence().unwrap().get(), 4);
}
