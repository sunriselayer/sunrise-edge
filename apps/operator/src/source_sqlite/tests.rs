use super::*;
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let sequence: u64 = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "cut-existing-sqlite-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn missing_source_files_are_not_created_and_restart_does_not_advance_fence() {
    let directory: Directory = Directory::new();
    let state: PathBuf = directory.0.join("state.sqlite");
    let blobs: PathBuf = directory.0.join("blobs.sqlite");
    let chain: ChainId = ChainId::new("cut-existing-sqlite").unwrap();
    let validator: ValidatorId = ValidatorId::new([0x82; 32]);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x83; 32]).unwrap();
    assert!(
        ExistingSqliteSource::open(&state, &blobs, chain.clone(), validator, domain, 30).is_err()
    );
    assert!(!state.exists());
    assert!(!blobs.exists());
    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let owner: SqliteDurableStore = SqliteDurableStore::open(&state, namespace, first).unwrap();
    let blob_owner: SqliteBlobStore = SqliteBlobStore::open(&blobs).unwrap();
    drop(blob_owner);
    drop(owner);
    let source: ExistingSqliteSource =
        ExistingSqliteSource::open(&state, &blobs, chain.clone(), validator, domain, 30).unwrap();
    let token: PortableSnapshotToken = source
        .durable
        .begin_portable_snapshot(&source.operation, domain)
        .unwrap();
    assert_eq!(source.durable.writer_fence().unwrap(), first);
    drop(source);
    let reopened: ExistingSqliteSource =
        ExistingSqliteSource::open(&state, &blobs, chain.clone(), validator, domain, 30).unwrap();
    assert_eq!(
        reopened
            .durable
            .begin_portable_snapshot(&reopened.operation, domain)
            .unwrap(),
        token
    );
    let second: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    reopened
        .durable
        .advance_writer_fence(first, second)
        .unwrap();
    assert!(
        reopened
            .durable
            .check_portable_outbox_empty_at(&reopened.operation, domain, &token)
            .is_err()
    );
    drop(reopened);
    let current: ExistingSqliteSource =
        ExistingSqliteSource::open(&state, &blobs, chain, validator, domain, 30).unwrap();
    assert_eq!(current.durable.writer_fence().unwrap(), second);
    let current_token: PortableSnapshotToken = current
        .durable
        .begin_portable_snapshot(&current.operation, domain)
        .unwrap();
    assert_eq!(current_token.writer_fence(), second);
    assert_ne!(current_token, token);
}
