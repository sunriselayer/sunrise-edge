//! Live PostgreSQL conformance for [`runtime_postgres::PostgresBlobStore`].
//!
//! Skips (with a diagnostic on stderr) unless [`support::LIVE_POSTGRES_URL_ENV`]
//! is configured, exactly like the other live tests in this crate.

use postgres::{Client, Config, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{BlobStore, MAX_STATE_VALUE_BYTES, RuntimeError, WriterFenceGeneration};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, POSTGRES_SCHEMA_IDENTITY, PostgresBlobStore,
    PostgresBlobStoreError, PostgresNamespace, PostgresPoolConfig, PostgresSchemaError,
    apply_initial_schema, bootstrap_namespace, build_postgres_pool,
};
use std::{
    num::NonZeroU32,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

mod support;

const TEST_DATABASE: &str = "sunrise_edge_test";

type TestPostgresManager = PostgresConnectionManager<NoTls>;
type BlobRaceResult = (Vec<u8>, Result<(), RuntimeError>);

/// A failing assertion must not leave the shared live-test database with a
/// forged migration identity or missing table. Declared after the shared
/// cross-process lock so this runs before that lock is released on unwind.
struct RestoreTestSchemaOnDrop {
    url: String,
}

impl Drop for RestoreTestSchemaOnDrop {
    fn drop(&mut self) {
        if let Ok(mut client) = Client::connect(&self.url, NoTls)
            && client
                .batch_execute("DROP SCHEMA IF EXISTS sunrise_edge CASCADE")
                .is_ok()
        {
            let _ = apply_initial_schema(&mut client);
        }
    }
}

fn test_pool(url: &str) -> Pool<TestPostgresManager> {
    let config: Config = url.parse().unwrap();
    build_postgres_pool(
        config,
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(8).unwrap(),
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn postgres_blob_store_conformance() {
    let Some(raw_url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL blob store conformance: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = raw_url.to_string_lossy().into_owned();
    // Acquired before any live database work: this test destructively resets
    // and reuses the shared `sunrise_edge_test` database, exactly like
    // `postgres_schema_and_durable_store_conformance`, so at most one live
    // test in this crate's family touches it at a time.
    let _live_test_lock = support::LiveTestLock::acquire();

    let mut admin: Client = Client::connect(&url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, TEST_DATABASE,
        "refusing to reset a non-test database"
    );
    let _restore_schema: RestoreTestSchemaOnDrop = RestoreTestSchemaOnDrop { url: url.clone() };
    admin
        .batch_execute("DROP SCHEMA IF EXISTS sunrise_edge CASCADE")
        .unwrap();

    let namespace_a = PostgresNamespace::new(
        &ChainId::new("blob-conformance-a").unwrap(),
        ValidatorId::new([0xA1; 32]),
        AtomicityDomainId::new([0xA2; 32]).unwrap(),
    )
    .unwrap();
    let namespace_b = PostgresNamespace::new(
        &ChainId::new("blob-conformance-b").unwrap(),
        ValidatorId::new([0xB1; 32]),
        AtomicityDomainId::new([0xB2; 32]).unwrap(),
    )
    .unwrap();

    let pool: Pool<TestPostgresManager> = test_pool(&url);

    // --- Schema rejection: no migration applied yet ------------------------
    assert!(matches!(
        PostgresBlobStore::new(pool.clone(), namespace_a.clone()),
        Err(PostgresBlobStoreError::Schema(
            PostgresSchemaError::SchemaNotApplied
        ))
    ));

    apply_initial_schema(&mut admin).unwrap();

    // --- Schema rejection: schema applied, namespace not yet bootstrapped --
    assert!(matches!(
        PostgresBlobStore::new(pool.clone(), namespace_a.clone()),
        Err(PostgresBlobStoreError::Schema(
            PostgresSchemaError::NamespaceMetadataMismatch
        ))
    ));

    bootstrap_namespace(
        &mut admin,
        &namespace_a,
        POSTGRES_SCHEMA_GENERATION,
        WriterFenceGeneration::new(1).unwrap(),
    )
    .unwrap();
    bootstrap_namespace(
        &mut admin,
        &namespace_b,
        POSTGRES_SCHEMA_GENERATION,
        WriterFenceGeneration::new(1).unwrap(),
    )
    .unwrap();

    let store_a: PostgresBlobStore<TestPostgresManager> =
        PostgresBlobStore::new(pool.clone(), namespace_a.clone()).unwrap();
    let store_b: PostgresBlobStore<TestPostgresManager> =
        PostgresBlobStore::new(pool.clone(), namespace_b.clone()).unwrap();

    // The store was constructed while namespace C still existed. Its next
    // put must fail immediately if that exact metadata row disappears.
    let namespace_c: PostgresNamespace = PostgresNamespace::new(
        &ChainId::new("blob-conformance-c").unwrap(),
        ValidatorId::new([0xC1; 32]),
        AtomicityDomainId::new([0xC2; 32]).unwrap(),
    )
    .unwrap();
    bootstrap_namespace(
        &mut admin,
        &namespace_c,
        POSTGRES_SCHEMA_GENERATION,
        WriterFenceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let store_c: PostgresBlobStore<TestPostgresManager> =
        PostgresBlobStore::new(pool.clone(), namespace_c.clone()).unwrap();
    assert_eq!(
        admin
            .execute(
                "DELETE FROM sunrise_edge.storage_metadata
         WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
                &[
                    &namespace_c.chain_id_bytes(),
                    &&namespace_c.validator_id().as_bytes()[..],
                    &&namespace_c.domain().as_bytes()[..]
                ],
            )
            .unwrap(),
        1
    );
    let orphan_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xC3; 32]);
    assert!(matches!(
        store_c.put_blob(orphan_digest, b"orphan".to_vec()),
        Err(RuntimeError::DurableStoreUnavailable)
    ));

    // --- put/get roundtrip ---------------------------------------------------
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x10; 32]);
    let bytes: Vec<u8> = b"blob-payload-one".to_vec();
    store_a.put_blob(digest, bytes.clone()).unwrap();
    assert_eq!(store_a.get_blob(&digest).unwrap(), Some(bytes.clone()));

    // --- byte-identical idempotence ------------------------------------------
    store_a.put_blob(digest, bytes.clone()).unwrap();
    assert_eq!(store_a.get_blob(&digest).unwrap(), Some(bytes.clone()));

    // --- conflicting content under the same digest fails closed -------------
    let conflicting: Vec<u8> = b"different-payload".to_vec();
    let conflict_error: RuntimeError = store_a.put_blob(digest, conflicting).unwrap_err();
    assert!(matches!(
        conflict_error,
        RuntimeError::BlobDigestConflict { digest: conflict_digest } if conflict_digest == digest
    ));
    // the existing bytes were left untouched by the rejected put
    assert_eq!(store_a.get_blob(&digest).unwrap(), Some(bytes.clone()));

    // --- missing digest -------------------------------------------------------
    let missing_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x20; 32]);
    assert_eq!(store_a.get_blob(&missing_digest).unwrap(), None);

    // --- cross-namespace isolation --------------------------------------------
    assert_eq!(store_b.get_blob(&digest).unwrap(), None);
    let namespace_b_bytes: Vec<u8> = b"namespace-b-payload".to_vec();
    store_b.put_blob(digest, namespace_b_bytes.clone()).unwrap();
    assert_eq!(
        store_b.get_blob(&digest).unwrap(),
        Some(namespace_b_bytes.clone())
    );
    assert_eq!(store_a.get_blob(&digest).unwrap(), Some(bytes.clone()));

    // --- the SQL and Rust byte bounds agree at the exact live boundary -----
    let boundary_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x31; 32]);
    let boundary: Vec<u8> = vec![0x5A_u8; MAX_STATE_VALUE_BYTES];
    store_a.put_blob(boundary_digest, boundary.clone()).unwrap();
    assert_eq!(store_a.get_blob(&boundary_digest).unwrap(), Some(boundary));

    // --- oversized blob rejected before ever reaching the database ----------
    let oversized: Vec<u8> = vec![0_u8; MAX_STATE_VALUE_BYTES + 1];
    let oversized_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x30; 32]);
    assert!(matches!(
        store_a.put_blob(oversized_digest, oversized),
        Err(RuntimeError::BlobTooLarge { length, maximum })
            if length == MAX_STATE_VALUE_BYTES + 1 && maximum == MAX_STATE_VALUE_BYTES
    ));
    assert_eq!(store_a.get_blob(&oversized_digest).unwrap(), None);

    // --- concurrent conflicting inserts: exactly one byte value wins ------
    let race_digest = Digest32::new(HashAlgorithmId::Blake3_256, [0x40; 32]);
    let first_race_bytes: Vec<u8> = b"race-content-A".to_vec();
    let second_race_bytes: Vec<u8> = b"race-content-B".to_vec();
    let race_store: Arc<PostgresBlobStore<TestPostgresManager>> =
        Arc::new(PostgresBlobStore::new(pool.clone(), namespace_a.clone()).unwrap());
    let start: Arc<Barrier> = Arc::new(Barrier::new(8));
    let handles: Vec<thread::JoinHandle<BlobRaceResult>> = (0..8)
        .map(|index: usize| {
            let store: Arc<PostgresBlobStore<TestPostgresManager>> = Arc::clone(&race_store);
            let barrier: Arc<Barrier> = Arc::clone(&start);
            let bytes: Vec<u8> = if index < 4 {
                first_race_bytes.clone()
            } else {
                second_race_bytes.clone()
            };
            thread::spawn(move || {
                barrier.wait();
                let outcome: Result<(), RuntimeError> = store.put_blob(race_digest, bytes.clone());
                (bytes, outcome)
            })
        })
        .collect();
    let mut successes: Vec<Vec<u8>> = Vec::new();
    let mut conflicts: usize = 0;
    for handle in handles {
        let (bytes, outcome): (Vec<u8>, Result<(), RuntimeError>) = handle.join().unwrap();
        match outcome {
            Ok(()) => successes.push(bytes),
            Err(RuntimeError::BlobDigestConflict { digest }) if digest == race_digest => {
                conflicts += 1;
            }
            other => panic!("unexpected concurrent blob outcome: {other:?}"),
        }
    }
    assert!(!successes.is_empty());
    assert!(conflicts > 0);
    let persisted_race_bytes: Vec<u8> = store_a.get_blob(&race_digest).unwrap().unwrap();
    assert!(persisted_race_bytes == first_race_bytes || persisted_race_bytes == second_race_bytes);
    assert!(
        successes
            .iter()
            .all(|bytes: &Vec<u8>| *bytes == persisted_race_bytes)
    );

    // --- schema rejection: an installed identity other than the exact
    // supported one fails closed, never silently accepted ---------------------
    let bogus_identity: [u8; 32] = *b"sunrise-edge/postgres/schema/v9\0";
    let updated: u64 = admin
        .execute(
            "UPDATE sunrise_edge.schema_migrations SET schema_identity = $1 WHERE migration_id = 1",
            &[&&bogus_identity[..]],
        )
        .unwrap();
    assert_eq!(updated, 1);
    assert!(matches!(
        PostgresBlobStore::new(pool.clone(), namespace_a.clone()),
        Err(PostgresBlobStoreError::Schema(
            PostgresSchemaError::SchemaMismatch
        ))
    ));
    let restored: u64 = admin
        .execute(
            "UPDATE sunrise_edge.schema_migrations SET schema_identity = $1 WHERE migration_id = 1",
            &[&&POSTGRES_SCHEMA_IDENTITY[..]],
        )
        .unwrap();
    assert_eq!(restored, 1);

    // --- close/reopen: a fresh pool and store still see committed data ------
    drop(store_a);
    drop(store_b);
    drop(race_store);
    drop(pool);
    let reopened_pool: Pool<TestPostgresManager> = test_pool(&url);
    let reopened_store: PostgresBlobStore<TestPostgresManager> =
        PostgresBlobStore::new(reopened_pool.clone(), namespace_a.clone()).unwrap();
    assert_eq!(reopened_store.get_blob(&digest).unwrap(), Some(bytes));
    assert_eq!(
        reopened_store.get_blob(&race_digest).unwrap(),
        Some(persisted_race_bytes)
    );
    assert_eq!(reopened_store.namespace(), &namespace_a);

    // A partial/tampered installation is rejected at construction, before
    // the operator CLI would promote any writer fence.
    admin
        .batch_execute("DROP TABLE sunrise_edge.blobs")
        .unwrap();
    assert!(matches!(
        PostgresBlobStore::new(reopened_pool, namespace_a),
        Err(PostgresBlobStoreError::Schema(
            PostgresSchemaError::Database(_)
        ))
    ));
    // The scope guard restores the shared test schema on success and unwind.
}
