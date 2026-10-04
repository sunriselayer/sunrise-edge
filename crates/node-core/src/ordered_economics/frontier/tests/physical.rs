//! Scan-mechanics regressions, not fabricated consensus/business proofs.
//! Inert raw State values below are never admitted as publications, folded
//! into a logical frontier, signed, or installed as a verified chain. The
//! genuine Original/current-index and two-link Successor fixtures separately
//! exercise the complete authenticated owner. Here the same private read-only
//! merge is stressed beyond the 4,096 deciding-CAS read-set cap on real SQLite.
use super::*;
use runtime::{StorageCorrelationId, StorageDeadline, WriterFenceGeneration};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::ops::Bound::{Excluded, Unbounded};

struct ScanFiles {
    directory: std::path::PathBuf,
    namespace: SqliteNamespace,
}

impl ScanFiles {
    fn new() -> Self {
        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
            "frontier-physical-scan-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            directory,
            namespace: SqliteNamespace::new(
                protocol().chain_id().clone(),
                ValidatorId::new([0x96; 32]),
                domain(),
            ),
        }
    }
    fn open(&self) -> SqliteDurableStore {
        SqliteDurableStore::open(
            self.directory.join("state.sqlite"),
            self.namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for ScanFiles {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn request(index: u64) -> [u8; 32] {
    let mut request: [u8; 32] = [0x11; 32];
    request[24..].copy_from_slice(&index.to_be_bytes());
    request
}

fn put<S: DurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    key: Vec<u8>,
    mutation: StateMutation,
) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(operation, domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(operation, transaction),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn more_than_4096_prior_rows_have_bounded_cas_reads_and_monotonic_sqlite_resume() {
    const HISTORICAL: u64 = 4097;
    for limit in [NonZeroUsize::MIN, NonZeroUsize::new(128).unwrap()] {
        for has_current in [false, true] {
            let files: ScanFiles = ScanFiles::new();
            let mut store: SqliteDurableStore = files.open();
            let mut operation: DurableOperationContext = context();
            let prefix: Vec<u8> = publication_prefix(protocol().chain_id()).unwrap();
            let mut prior: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
            for index in 1..=HISTORICAL {
                let key: Vec<u8> =
                    fastpath_publication_key(protocol().chain_id(), &request(index)).unwrap();
                let bytes: Vec<u8> = index.to_be_bytes().to_vec();
                put(
                    &store,
                    &operation,
                    key.clone(),
                    StateMutation::Put(bytes.clone()),
                );
                prior.insert(key, bytes);
            }
            let current_key: Vec<u8> =
                fastpath_publication_key(protocol().chain_id(), &request(HISTORICAL + 1)).unwrap();
            if has_current {
                put(
                    &store,
                    &operation,
                    current_key.clone(),
                    StateMutation::Put(b"inert current selector; never authenticated".to_vec()),
                );
            }
            let next_prior = |after: &[u8]| {
                prior
                    .range((Excluded(after.to_vec()), Unbounded))
                    .next()
                    .map(|(key, bytes): (&Vec<u8>, &Vec<u8>)| {
                        (key.as_slice(), Some(bytes.as_slice()))
                    })
            };
            let seed: FrozenFrontierIdentity = FrozenFrontierAccumulator::new(
                &resolver(),
                protocol().chain_id().clone(),
                protocol().protocol_version(),
                protocol().epoch(),
                domain(),
                [0x55; 32],
                3,
            )
            .unwrap()
            .into_identity();
            let cursor_key: Vec<u8> = key(
                protocol().chain_id(),
                protocol().epoch(),
                FRONTIER_PROGRESS_PREFIX,
            )
            .unwrap();
            let mut after: Vec<u8> = prefix.clone();
            let mut physical_count: u64 = 0;
            let mut calls: u64 = 0;
            loop {
                calls = calls.checked_add(1).unwrap();
                let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
                let cursor_row: VersionedStateValue = store
                    .get_versioned_durable(&operation, domain(), &cursor_key)
                    .unwrap();
                put_read(&mut reads, cursor_key.clone(), cursor_row.revision()).unwrap();
                let page: PhysicalPublicationPage = physical_publication_page(
                    &store,
                    &operation,
                    domain(),
                    &prefix,
                    after.clone(),
                    limit,
                    &mut reads,
                    &next_prior,
                )
                .unwrap();
                assert!(
                    reads.len() <= limit.get() + 1,
                    "historical rows must consume the same physical bound as current rows"
                );
                AtomicStateReadSet::new(
                    reads
                        .iter()
                        .map(|(key, revision): (&Vec<u8>, &StateRevision)| {
                            StateReadAssertion::new(key.clone(), *revision).unwrap()
                        })
                        .collect::<Vec<StateReadAssertion>>(),
                )
                .unwrap();
                if let Some(current) = page.current_keys.first() {
                    assert!(has_current);
                    assert_eq!(current, &current_key);
                    assert_eq!(page.current_keys.len(), 1);
                    assert_eq!(
                        physical_count,
                        HISTORICAL - (HISTORICAL % u64::try_from(limit.get()).unwrap())
                    );
                    break; // Never pass the inert current bytes to a full verifier.
                }
                if let Some(last) = page.last_request_id {
                    let next_after: Vec<u8> =
                        fastpath_publication_key(protocol().chain_id(), &last).unwrap();
                    assert!(next_after > after);
                    physical_count = u64::from_be_bytes(last[24..].try_into().unwrap());
                    let cursor: FrontierCursor = FrontierCursor {
                        identity: seed.clone(),
                        last_request_id: None,
                        physical_last_request_id: last,
                        indexed: true,
                    };
                    FrozenFrontierAccumulator::resume(
                        &resolver(),
                        cursor.identity.clone(),
                        cursor.last_request_id,
                    )
                    .unwrap();
                    commit_rows(
                        crate::serving_authority::ServingGate::Original,
                        &store,
                        &operation,
                        domain(),
                        reads,
                        vec![
                            StateMutationEntry::new(
                                cursor_key.clone(),
                                StateMutation::Put(encode_cursor(&cursor).unwrap()),
                            )
                            .unwrap(),
                        ],
                    )
                    .unwrap();
                    after = next_after;
                    let retained: Vec<u8> = store
                        .get_versioned_durable(&operation, domain(), &cursor_key)
                        .unwrap()
                        .value()
                        .unwrap()
                        .to_vec();
                    assert_eq!(decode_cursor(&retained).unwrap().identity, seed);
                    // Reopen and an actual operator refence keep confirmed
                    // progress durable. This is not an ambiguous-reply test.
                    if calls == 2 {
                        drop(store);
                        store = files.open();
                        assert_eq!(
                            store
                                .get_versioned_durable(&operation, domain(), &cursor_key)
                                .unwrap()
                                .value(),
                            Some(retained.as_slice())
                        );
                        store
                            .advance_writer_fence(
                                WriterFenceGeneration::new(1).unwrap(),
                                WriterFenceGeneration::new(2).unwrap(),
                            )
                            .unwrap();
                        assert!(
                            store
                                .get_versioned_durable(&operation, domain(), &cursor_key)
                                .is_err()
                        );
                        operation = DurableOperationContext::new(
                            WriterFenceGeneration::new(2).unwrap(),
                            StorageDeadline::new(u64::MAX).unwrap(),
                            StorageCorrelationId::new([0x97; 16]).unwrap(),
                        );
                        assert_eq!(
                            store
                                .get_versioned_durable(&operation, domain(), &cursor_key)
                                .unwrap()
                                .value(),
                            Some(retained.as_slice())
                        );
                    }
                } else {
                    assert!(page.terminal && !has_current);
                    assert_eq!(physical_count, HISTORICAL);
                    break;
                }
                assert!(
                    calls <= HISTORICAL + 1,
                    "a persisted physical tail must prevent unbounded rescan"
                );
            }
            assert!(calls <= HISTORICAL + 1);
        }
    }
}

#[test]
fn missing_altered_or_tombstoned_upcoming_prior_row_refuses_the_bounded_merge() {
    for mutation in [
        None,
        Some(StateMutation::Put(b"altered".to_vec())),
        Some(StateMutation::Delete),
    ] {
        let store: runtime::MemoryDurableStateStore = crate::paid_execution::tests::memory_store();
        let prefix: Vec<u8> = publication_prefix(protocol().chain_id()).unwrap();
        let prior_key: Vec<u8> =
            fastpath_publication_key(protocol().chain_id(), &request(1)).unwrap();
        if let Some(mutation) = mutation {
            put(
                &store,
                &context(),
                prior_key.clone(),
                StateMutation::Put(b"exact old bytes".to_vec()),
            );
            put(&store, &context(), prior_key.clone(), mutation);
        }
        let next_prior = |after: &[u8]| {
            if after < prior_key.as_slice() {
                Some((prior_key.as_slice(), Some(&b"exact old bytes"[..])))
            } else {
                None
            }
        };
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            physical_publication_page(
                &store,
                &context(),
                domain(),
                &prefix,
                prefix.clone(),
                NonZeroUsize::MIN,
                &mut reads,
                &next_prior
            ),
            Err(FrozenFrontierError::Invalid(
                "prior frozen publication is missing or altered"
            ))
        ));
        assert_eq!(reads.len(), 1);
    }
}
