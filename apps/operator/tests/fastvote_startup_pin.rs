//! The exact production startup helper against an installed file-backed store.
mod support;
use execution::publication::PublicationContext;
use node_core::fast_path::records::{
    FastPathValidatorSetRecord, decode_fastpath_validator_set_record,
    encode_fastpath_validator_set_record,
};
use node_core::local_instance_state::{
    FastPathEpochRecord, decode_fastpath_epoch_record, fastpath_epoch_record_key,
    fastpath_validator_set_key,
};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, HashAlgorithmId, SignatureSchemeId};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, DurableReadError, StorageCorrelationId,
    StorageDeadline, VersionedStateReader, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    cell::Cell,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_operator::common::{LiveFastVotePinError, require_live_fastvote_pin};
use validator_set::{ValidatorInfo, ValidatorSet};

// This wrapper has only a read port. It cannot claim a writer or acknowledge
// a synthetic commit, and counts the real durable read it delegates.
struct CountingReader<'a, S: VersionedStateReader + ?Sized> {
    store: &'a S,
    reads: Cell<usize>,
}

impl<S: VersionedStateReader + ?Sized> VersionedStateReader for CountingReader<'_, S> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.reads.set(self.reads.get() + 1);
        self.store.read_versioned_state(context, domain, key)
    }
}

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

#[test]
fn startup_rejects_unsupported_configured_scheme_even_with_matching_installed_digest() {
    let unique: String = format!(
        "startup-scheme-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: support::genesis_fixture::FastVoteGenesisFixture =
        support::genesis_fixture::build_network_fixture(&unique);
    let manifest: node_core::GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let path: PathBuf = std::env::temp_dir().join(format!("sunrise-{unique}.sqlite3"));
    let _owned: TestDatabase = TestDatabase(path.clone());
    let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.chain_id.clone(),
        fixture.validators[0].validator_id,
        fixture.domain,
    );
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&path, namespace.clone(), generation).unwrap();
    let operation: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([2; 16]).unwrap(),
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
    let reader: CountingReader<'_, SqliteDurableStore> = CountingReader {
        store: &store,
        reads: Cell::new(0),
    };
    require_live_fastvote_pin(
        &reader,
        &operation,
        fixture.domain,
        &fixture.context,
        &manifest.validator_set,
        &fixture.resolver,
    )
    .unwrap();
    assert_eq!(reader.reads.get(), 1);

    // Deliberately corrupt installed durable rows through a test-only write.
    // This is a negative fixture, not an unsupported activation producer.
    let set_key: Vec<u8> = fastpath_validator_set_key(&fixture.context).unwrap();
    let original_set: VersionedStateValue = store
        .get_versioned_durable(&operation, fixture.domain, &set_key)
        .unwrap();
    let mut unsupported: FastPathValidatorSetRecord =
        decode_fastpath_validator_set_record(original_set.value().unwrap()).unwrap();
    unsupported.validators[0].signature_scheme = SignatureSchemeId::Secp256k1;
    let unsupported_id: protocol_types::ValidatorId = unsupported.validators[0].id;
    // Independently compute the structurally valid generic digest. The
    // production FastVote validator must refuse despite exact live pinning.
    let members: Vec<ValidatorInfo> = unsupported
        .validators
        .iter()
        .map(
            |entry: &node_core::fast_path::records::FastPathValidatorEntry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            },
        )
        .collect();
    let generic_set: ValidatorSet = ValidatorSet::new(fixture.epoch, members).unwrap();
    let unsupported_digest: Digest32 = generic_set.digest(&fixture.resolver).unwrap();
    let epoch_key: Vec<u8> = fastpath_epoch_record_key(&fixture.chain_id).unwrap();
    let original_epoch: VersionedStateValue = store
        .get_versioned_durable(&operation, fixture.domain, &epoch_key)
        .unwrap();
    let mut live: FastPathEpochRecord =
        decode_fastpath_epoch_record(original_epoch.value().unwrap()).unwrap();
    live.current_validator_set_digest = unsupported_digest;
    support::durable_state::replace(
        &store,
        &operation,
        fixture.domain,
        set_key.clone(),
        encode_fastpath_validator_set_record(&unsupported).unwrap(),
    );
    support::durable_state::set_epoch(&store, &operation, fixture.domain, &fixture.chain_id, &live);

    let loaded: VersionedStateValue = store
        .get_versioned_durable(&operation, fixture.domain, &set_key)
        .unwrap();
    let loaded_set: FastPathValidatorSetRecord =
        decode_fastpath_validator_set_record(loaded.value().unwrap()).unwrap();
    let installed: VersionedStateValue = store
        .get_versioned_durable(&operation, fixture.domain, &epoch_key)
        .unwrap();
    assert_eq!(
        decode_fastpath_epoch_record(installed.value().unwrap())
            .unwrap()
            .current_validator_set_digest,
        unsupported_digest
    );
    let before: PortableSnapshotToken = store
        .begin_portable_snapshot(&operation, fixture.domain)
        .unwrap();
    reader.reads.set(0);
    let wrong_context: PublicationContext = PublicationContext::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        Epoch::new(fixture.epoch.get() + 1),
    )
    .unwrap();
    assert!(matches!(
        require_live_fastvote_pin(
            &reader,
            &operation,
            fixture.domain,
            &wrong_context,
            &loaded_set,
            &fixture.resolver,
        ),
        Err(LiveFastVotePinError::ValidatorSetContextMismatch)
    ));
    assert_eq!(reader.reads.get(), 0);
    assert!(matches!(
        require_live_fastvote_pin(
            &reader,
            &operation,
            fixture.domain,
            &fixture.context,
            &loaded_set,
            &fixture.resolver,
        ),
        Err(LiveFastVotePinError::UnsupportedSignatureScheme {
            validator_id,
            scheme: SignatureSchemeId::Secp256k1,
        }) if validator_id == unsupported_id
    ));
    assert_eq!(reader.reads.get(), 0);
    assert_eq!(store.writer_fence().unwrap(), generation);
    assert_eq!(
        store
            .begin_portable_snapshot(&operation, fixture.domain)
            .unwrap(),
        before
    );
    drop(store);

    // Closing and reopening must not repair the unsupported configuration or
    // advance a writer fence on behalf of this read-only startup helper.
    let reopened: SqliteDurableStore = SqliteDurableStore::open_existing(&path, namespace).unwrap();
    assert_eq!(reopened.writer_fence().unwrap(), generation);
    let reopened_row: VersionedStateValue = reopened
        .get_versioned_durable(&operation, fixture.domain, &set_key)
        .unwrap();
    assert_eq!(reopened_row, loaded);
    let reopened_set: FastPathValidatorSetRecord =
        decode_fastpath_validator_set_record(reopened_row.value().unwrap()).unwrap();
    assert!(matches!(
        require_live_fastvote_pin(
            &reopened,
            &operation,
            fixture.domain,
            &fixture.context,
            &reopened_set,
            &fixture.resolver,
        ),
        Err(LiveFastVotePinError::UnsupportedSignatureScheme { .. })
    ));
    assert_eq!(
        reopened
            .begin_portable_snapshot(&operation, fixture.domain)
            .unwrap(),
        before
    );
}
