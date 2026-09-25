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
use std::{num::NonZeroU32, sync::Arc, thread, time::Duration};

mod support;

const TEST_DATABASE: &str = "sunrise_edge_test";

type TestPostgresManager = PostgresConnectionManager<NoTls>;

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

    // --- oversized blob rejected before ever reaching the database ----------
    let oversized: Vec<u8> = vec![0_u8; MAX_STATE_VALUE_BYTES + 1];
    let oversized_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x30; 32]);
    assert!(matches!(
        store_a.put_blob(oversized_digest, oversized),
        Err(RuntimeError::StateValueTooLarge { length, maximum })
            if length == MAX_STATE_VALUE_BYTES + 1 && maximum == MAX_STATE_VALUE_BYTES
    ));
    assert_eq!(store_a.get_blob(&oversized_digest).unwrap(), None);

    // --- concurrent insert race: every thread races the same digest ---------
    let race_digest = Digest32::new(HashAlgorithmId::Blake3_256, [0x40; 32]);
    let race_bytes: Vec<u8> = b"race-payload".to_vec();
    let race_store: Arc<PostgresBlobStore<TestPostgresManager>> =
        Arc::new(PostgresBlobStore::new(pool.clone(), namespace_a.clone()).unwrap());
    let handles: Vec<thread::JoinHandle<Result<(), RuntimeError>>> = (0..8)
        .map(|_| {
            let store = Arc::clone(&race_store);
            let bytes = race_bytes.clone();
            thread::spawn(move || store.put_blob(race_digest, bytes))
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    assert_eq!(
        store_a.get_blob(&race_digest).unwrap(),
        Some(race_bytes.clone())
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
        Some(race_bytes)
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
    // Do not leave the shared live-test database with a deliberately missing
    // table for the next independent test binary.
    admin
        .batch_execute("DROP SCHEMA sunrise_edge CASCADE")
        .unwrap();
    apply_initial_schema(&mut admin).unwrap();
}
