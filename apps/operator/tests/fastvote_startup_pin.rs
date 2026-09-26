//! The exact production startup helper against an installed file-backed store.
mod support;
use node_core::local_instance_state::{
    FastPathEpochRecord, decode_fastpath_epoch_record, fastpath_epoch_record_key,
};
use protocol_types::{Digest32, Epoch, HashAlgorithmId};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_operator::common::{LiveFastVotePinError, require_live_fastvote_pin};

struct TestDatabase(PathBuf);
impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn startup_rejects_advanced_epoch_and_mismatched_set_before_serving() {
    let unique: String = format!(
        "startup-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture = support::genesis_fixture::build_network_fixture(&unique);
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let path: PathBuf = std::env::temp_dir().join(format!("sunrise-{unique}.sqlite3"));
    let _owned = TestDatabase(path.clone());
    let generation = WriterFenceGeneration::new(1).unwrap();
    let store = SqliteDurableStore::open(
        &path,
        SqliteNamespace::new(
            fixture.chain_id.clone(),
            fixture.validators[0].validator_id,
            fixture.domain,
        ),
        generation,
    )
    .unwrap();
    let operation = DurableOperationContext::new(
        generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    );
    node_core::install_genesis_with_history(
        &store,
        &operation,
        fixture.domain,
        &fixture.resolver,
        &[],
        &manifest,
        1,
    )
    .unwrap();
    require_live_fastvote_pin(
        &store,
        &operation,
        fixture.domain,
        &fixture.context,
        &manifest.validator_set,
        &fixture.resolver,
    )
    .unwrap();
    let key = fastpath_epoch_record_key(&fixture.chain_id).unwrap();
    let observed = store
        .get_versioned_durable(&operation, fixture.domain, &key)
        .unwrap();
    let original: FastPathEpochRecord =
        decode_fastpath_epoch_record(observed.value().unwrap()).unwrap();
    let mut advanced = original.clone();
    advanced.current_epoch = Epoch::new(1);
    support::durable_state::set_epoch(
        &store,
        &operation,
        fixture.domain,
        &fixture.chain_id,
        &advanced,
    );
    let error = require_live_fastvote_pin(
        &store,
        &operation,
        fixture.domain,
        &fixture.context,
        &manifest.validator_set,
        &fixture.resolver,
    )
    .unwrap_err();
    assert!(matches!(error, LiveFastVotePinError::EpochMismatch { .. }));
    assert!(error.to_string().contains("fastvote-epoch-repin-required"));
    let mut mismatched = original.clone();
    mismatched.current_validator_set_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
    support::durable_state::set_epoch(
        &store,
        &operation,
        fixture.domain,
        &fixture.chain_id,
        &mismatched,
    );
    let error = require_live_fastvote_pin(
        &store,
        &operation,
        fixture.domain,
        &fixture.context,
        &manifest.validator_set,
        &fixture.resolver,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LiveFastVotePinError::ValidatorSetDigestMismatch
    ));
    assert!(error.to_string().contains("out-of-band re-pin"));
    support::durable_state::set_epoch(
        &store,
        &operation,
        fixture.domain,
        &fixture.chain_id,
        &original,
    );
    require_live_fastvote_pin(
        &store,
        &operation,
        fixture.domain,
        &fixture.context,
        &manifest.validator_set,
        &fixture.resolver,
    )
    .unwrap();
}
