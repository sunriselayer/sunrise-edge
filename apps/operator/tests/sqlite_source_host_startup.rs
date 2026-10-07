//! The compiled serving host must refuse, not initialize or repair, ordered
//! consensus state. Other committed genesis/business rows remain byte-exact.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[allow(dead_code)]
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use fixture::Fixture;
use node_core::business_reconstruction::{SourceBusinessSnapshot, SourceSnapshotRecord};
use node_core::ordered_economics::{OrderedEconomicsEnvironment, install_ordered_genesis};
use runtime::portable::DurableRecordKey;
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, Clock,
    DurableCommitOutcome, DurableDomainStateStore, DurableOperationContext, StateMutation,
    StateMutationEntry, StateReadAssertion, StorageCorrelationId, StorageDeadline, SystemClock,
    VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

struct PendingChild(Option<Child>);
impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

fn refused_process(args: &[OsString]) -> Output {
    let child: Child = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pending: PendingChild = PendingChild(Some(child));
    let deadline: Instant = Instant::now() + Duration::from_secs(20);
    loop {
        if pending.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return pending.0.take().unwrap().wait_with_output().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "host listened instead of refusing invalid startup state"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn args(fixture: &Fixture, state: &Path, key: &Path, genesis: &Path) -> Vec<OsString> {
    vec![
        "--chain-id".into(),
        fixture.network.chain_id.as_str().into(),
        "--validator-id".into(),
        hex(fixture.network.validators[0].validator_id.as_bytes()).into(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()).into(),
        "--protocol-version".into(),
        fixture.network.protocol_version.get().to_string().into(),
        "--epoch".into(),
        fixture.network.epoch.get().to_string().into(),
        "--suite".into(),
        "0:1:1:1:1:1:1:1".into(),
        "--genesis-manifest".into(),
        genesis.as_os_str().into(),
        "--expected-genesis-digest".into(),
        hex(&fixture.network.manifest_digest).into(),
        "--signing-key-file".into(),
        key.as_os_str().into(),
        "--state-db".into(),
        state.as_os_str().into(),
        "--blob-db".into(),
        fixture.directory.0.join("blobs.sqlite").into(),
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--created-checkpoint".into(),
        "1000".into(),
        "--timeout-seconds".into(),
        "30".into(),
        "--max-concurrent".into(),
        "4".into(),
        "--confirm-offline-fence-advance".into(),
    ]
}

fn snapshot(
    fixture: &Fixture,
    store: &SqliteDurableStore,
    context: &DurableOperationContext,
) -> SourceBusinessSnapshot {
    capture_source_business_snapshot(
        store,
        &fixture.blobs,
        context,
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap()
}

#[test]
fn compiled_source_host_refuses_missing_deleted_and_malformed_ordered_state_without_repair() {
    for case in ["missing", "deleted", "malformed"] {
        let fixture: Fixture = Fixture::new();
        let state: PathBuf = fixture.directory.0.join("startup-state.sqlite");
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &state,
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                fixture.network.validators[0].validator_id,
                fixture.network.domain,
            ),
            generation,
        )
        .unwrap();
        node_core::genesis::install_genesis(
            &store,
            &fixture.operation,
            fixture.network.domain,
            &fixture.network.resolver,
            fixture.root.manifest(),
            10,
        )
        .unwrap();
        if case != "missing" {
            let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
                policy: &fixture.policy,
                history: &[],
                leg_policy: &fixture.local_policy,
                engine: &fixture.engine,
                blobs: &fixture.blobs,
                seal: None,
            };
            install_ordered_genesis(&store, &fixture.operation, &env, 1_700_000_000_000).unwrap();
            let installed: SourceBusinessSnapshot = snapshot(&fixture, &store, &fixture.operation);
            let matches: Vec<&SourceSnapshotRecord> = installed
                .records
                .iter()
                .filter(|record: &&SourceSnapshotRecord| {
                    matches!(record.descriptor.key(), DurableRecordKey::State(_))
                        && record.value.as_deref().is_some_and(|bytes: &[u8]| {
                            consensus::decode_consensus_state(bytes).is_ok()
                        })
                })
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "the fixture identifies exactly one actual consensus row"
            );
            let key: Vec<u8> = match matches[0].descriptor.key() {
                DurableRecordKey::State(key) => key.clone(),
                _ => unreachable!(),
            };
            let observed: VersionedStateValue = store
                .get_versioned_durable(&fixture.operation, fixture.network.domain, &key)
                .unwrap();
            let mutation: StateMutation = if case == "deleted" {
                StateMutation::Delete
            } else {
                StateMutation::Put(vec![0])
            };
            let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
                fixture.network.domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                store.commit_durable(&fixture.operation, transaction),
                DurableCommitOutcome::Committed
            );
        }
        let before: SourceBusinessSnapshot = snapshot(&fixture, &store, &fixture.operation);
        let key: PathBuf = fixture.directory.0.join("startup.key");
        std::fs::write(&key, fixture.network.validators[0].seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let genesis: PathBuf = fixture.directory.0.join("startup-genesis.bin");
        std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
        let output: Output = refused_process(&args(&fixture, &state, &key, &genesis));
        assert!(!output.status.success(), "{case} was accepted");
        let diagnostic: String = String::from_utf8(output.stderr).unwrap();
        assert!(
            diagnostic.contains("existing ordered economics state is not valid"),
            "{case}: {diagnostic}"
        );
        assert!(
            output.stdout.is_empty(),
            "refusal must not advertise a listener"
        );
        let current: WriterFenceGeneration = store.writer_fence().unwrap();
        assert_eq!(
            current,
            generation.checked_next().unwrap(),
            "one explicit offline fence claim precedes this deciding refusal"
        );
        let context: DurableOperationContext = DurableOperationContext::new(
            current,
            StorageDeadline::new(
                SystemClock
                    .now_unix_millis()
                    .unwrap()
                    .checked_add(60_000)
                    .unwrap(),
            )
            .unwrap(),
            StorageCorrelationId::new([0x77; 16]).unwrap(),
        );
        let after: SourceBusinessSnapshot = snapshot(&fixture, &store, &context);
        assert_eq!(
            before.records, after.records,
            "{case}: no row initialized, reset or repaired"
        );
        assert_eq!(before.referenced_blobs, after.referenced_blobs);
        assert_eq!(before.token.namespace(), after.token.namespace());
        assert_eq!(
            before.token.mutation_sequence(),
            after.token.mutation_sequence()
        );
        assert_eq!(after.token.writer_fence(), current);
    }
}

#[test]
#[cfg(unix)]
fn compiled_tls_configuration_refuses_before_existing_fence_or_durable_io() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let fixture: Fixture = Fixture::new();
    let state: PathBuf = fixture.directory.0.join("tls-startup-state.sqlite");
    let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: SqliteDurableStore = SqliteDurableStore::open(
        &state,
        SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            fixture.network.validators[0].validator_id,
            fixture.network.domain,
        ),
        generation,
    )
    .unwrap();
    node_core::genesis::install_genesis(
        &store,
        &fixture.operation,
        fixture.network.domain,
        &fixture.network.resolver,
        fixture.root.manifest(),
        10,
    )
    .unwrap();
    let before: SourceBusinessSnapshot = snapshot(&fixture, &store, &fixture.operation);
    let protocol_key: PathBuf = fixture.directory.0.join("tls-protocol.key");
    fs::write(&protocol_key, fixture.network.validators[0].seed).unwrap();
    fs::set_permissions(&protocol_key, fs::Permissions::from_mode(0o600)).unwrap();
    let genesis: PathBuf = fixture.directory.0.join("tls-genesis.bin");
    fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let leaf: rcgen::CertifiedKey<rcgen::KeyPair> =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert: PathBuf = fixture.directory.0.join("tls-leaf.der");
    fs::write(&cert, leaf.cert.der()).unwrap();
    let key: PathBuf = fixture.directory.0.join("tls-key.der");
    fs::write(&key, leaf.signing_key.serialize_der()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let malformed: PathBuf = fixture.directory.0.join("tls-malformed");
    fs::write(&malformed, b"private-byte-sentinel").unwrap();
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600)).unwrap();
    let empty: PathBuf = fixture.directory.0.join("tls-empty");
    fs::write(&empty, b"").unwrap();
    let oversized: PathBuf = fixture.directory.0.join("tls-oversized");
    fs::write(&oversized, vec![0; 16 * 1024 + 1]).unwrap();
    let alias: PathBuf = fixture.directory.0.join("tls-alias");
    symlink(&key, &alias).unwrap();
    let directory: PathBuf = fixture.directory.0.join("tls-directory");
    fs::create_dir(&directory).unwrap();
    let other: rcgen::CertifiedKey<rcgen::KeyPair> =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mismatch: PathBuf = fixture.directory.0.join("tls-mismatch.der");
    fs::write(&mismatch, other.signing_key.serialize_der()).unwrap();
    fs::set_permissions(&mismatch, fs::Permissions::from_mode(0o600)).unwrap();
    let insecure: PathBuf = fixture.directory.0.join("tls-insecure.der");
    fs::write(&insecure, leaf.signing_key.serialize_der()).unwrap();
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o644)).unwrap();
    let missing: PathBuf = fixture.directory.0.join("tls-missing");
    let pair = |cert: &Path, key: &Path| -> Vec<OsString> {
        vec![
            "--tls-cert-der-file".into(),
            cert.into(),
            "--tls-key-pkcs8-der-file".into(),
            key.into(),
        ]
    };
    let mut cases: Vec<Vec<OsString>> = vec![
        vec!["--tls-cert-der-file".into(), cert.clone().into()],
        vec!["--tls-key-pkcs8-der-file".into(), key.clone().into()],
        vec!["--tls-unknown".into(), key.clone().into()],
    ];
    for invalid in [&malformed, &empty, &oversized, &missing, &directory] {
        cases.push(pair(invalid, &key));
    }
    for invalid in [
        &malformed, &empty, &missing, &alias, &directory, &mismatch, &insecure,
    ] {
        cases.push(pair(&cert, invalid));
    }
    let mut duplicate: Vec<OsString> = pair(&cert, &key);
    duplicate.extend(["--tls-key-pkcs8-der-file".into(), key.clone().into()]);
    cases.push(duplicate);
    let mut count: Vec<OsString> = vec!["--tls-key-pkcs8-der-file".into(), key.clone().into()];
    for _ in 0..5 {
        count.extend(["--tls-cert-der-file".into(), cert.clone().into()]);
    }
    cases.push(count);
    let names: std::collections::BTreeSet<OsString> = fs::read_dir(&fixture.directory.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    for tail in cases {
        // A nonexistent manifest makes loader-before-genesis refusal observable,
        // while the existing committed state/fence still proves no durable change.
        let mut values: Vec<OsString> = args(&fixture, &state, &protocol_key, &missing);
        values.extend(tail);
        let output: Output = refused_process(&values);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let message: String = String::from_utf8(output.stderr).unwrap();
        assert!(
            message.contains("Native TLS") || message.contains("--tls-unknown"),
            "{message}"
        );
        assert!(!message.contains("private-byte-sentinel"));
        assert_eq!(
            store.writer_fence().unwrap(),
            generation,
            "TLS refuses before fencing"
        );
        assert_eq!(snapshot(&fixture, &store, &fixture.operation), before);
        let after_names: std::collections::BTreeSet<OsString> = fs::read_dir(&fixture.directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after_names, names, "no new durable files or repair");
    }
}
