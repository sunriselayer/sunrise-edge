//! Live PostgreSQL regression for numeric object-version ordering.
//!
//! Skips (with a diagnostic on stderr) unless [`support::LIVE_POSTGRES_URL_ENV`]
//! is configured, exactly like the other live tests in this crate.
//!
//! `sunrise_edge.object_versions.object_version` is `NUMERIC(20, 0)`. Reading
//! it back as `object_version::TEXT` and then sorting by the bare identifier
//! `object_version DESC` binds to that `TEXT` output column, not the
//! underlying numeric column, so history containing both one- and two-digit
//! versions sorts lexicographically (`'9'` outranks `'10'`). This exercises
//! both the unlocked read path (`get_object_head`) and the locked
//! pre-commit read-assertion path (`validate_object_reads`, invoked from
//! `commit_invocation`) across the exact 9->10 and 99->100 rollovers.

use objects::{Address, Object, Owner, encode_object};
use postgres::{Client, NoTls};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ProtocolVersion, ValidatorId,
};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableReadError, DurableRequestId, DurableRequestReceipt, ObjectId,
    StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
    WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, apply_initial_schema, bootstrap_namespace, build_postgres_pool,
};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

const TEST_DATABASE: &str = "sunrise_edge_test";
/// Exercises the double-digit rollover (9->10) and continues one commit past
/// the triple-digit rollover (99->100->101), so the locked pre-commit path
/// also observes a triple-digit `object_version` crossover, without an
/// unbounded loop.
const HIGHEST_OBJECT_VERSION: u64 = 101;
/// A historical version below [`HIGHEST_OBJECT_VERSION`] that a corrupted
/// head is forged to reference; must remain far enough below the highest
/// version that the two can never coincide.
const STALE_FORGED_HEAD_VERSION: u64 = 99;

type TestPostgresManager = PostgresConnectionManager<NoTls>;

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
    let config: postgres::Config = url.parse().unwrap();
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

fn live_context(fence: WriterFenceGeneration, correlation_byte: u8) -> DurableOperationContext {
    let now_millis: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now_millis + 60_000).unwrap(),
        StorageCorrelationId::new([correlation_byte; 16]).unwrap(),
    )
}

fn object_projections(byte: u8) -> (DurableObjectOwnerProjection, DurableObjectRoutingProjection) {
    let owner: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new([byte; 32]))).unwrap();
    let routing: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(Some(vec![byte.wrapping_add(1)])).unwrap();
    (owner, routing)
}

fn object_version_record(
    chain_id: &ChainId,
    object_id: ObjectId,
    version: u64,
    owner_byte: u8,
) -> DurableObjectVersionRecord {
    let object: Object = Object {
        id: object_id,
        version,
        owner: Owner::Address(Address::new([owner_byte; 32])),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x9A; 32]),
        schema_version: 1,
        data: vec![owner_byte],
    };
    // The store persists the supplied digest verbatim; it does not recompute
    // it, so any well-formed `Digest32` is sufficient for this regression.
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, {
        let mut bytes: [u8; 32] = [0x5C; 32];
        bytes[..8].copy_from_slice(&version.to_be_bytes());
        bytes
    });
    let _ = encode_object(&object).unwrap();
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(chain_id.clone(), ProtocolVersion::new(1));
    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, version).unwrap()
}

/// `request_index` uniquely identifies this invocation's receipt and outbox
/// digests; each call site passes a distinct value.
fn commit_object_mutation(
    store: &PostgresDurableStore<TestPostgresManager>,
    context: &DurableOperationContext,
    object_change: (
        AtomicityDomainId,
        ObjectId,
        DurableObjectHead,
        DurableObjectMutation,
    ),
    request_index: u16,
) -> DurableCommitOutcome {
    let (domain, object_id, expected_head, mutation) = object_change;
    let [request_byte_high, request_byte_low]: [u8; 2] = request_index.to_be_bytes();
    let mut request_id_bytes: [u8; 32] = [request_byte_low; 32];
    request_id_bytes[0] = request_byte_high;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(request_id_bytes).unwrap(),
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [request_byte_low.wrapping_add(1); 32],
        ),
        vec![request_byte_low],
    )
    .unwrap();
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(object_id, expected_head)],
        vec![DurableObjectMutationEntry::new(object_id, mutation)],
    )
    .unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    store.commit_invocation(context, invocation)
}

#[test]
fn postgres_object_version_numeric_ordering_survives_double_and_triple_digit_rollover() {
    let Some(raw_url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL object-version ordering regression: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = raw_url.to_string_lossy().into_owned();
    // Acquired before any live database work: this test destructively resets
    // and reuses the shared `sunrise_edge_test` database, exactly like
    // `postgres_blob_store_conformance` and
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
    apply_initial_schema(&mut admin).unwrap();

    let chain_id: ChainId = ChainId::new("object-version-order").unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain_id,
        ValidatorId::new([0xD1; 32]),
        AtomicityDomainId::new([0xD2; 32]).unwrap(),
    )
    .unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();

    let pool: Pool<TestPostgresManager> = test_pool(&url);
    let store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );
    let domain: AtomicityDomainId = namespace.domain();
    let context: DurableOperationContext = live_context(fence, 0x61);
    let object_id: ObjectId = ObjectId::new([0x77; 32]);
    let (owner_projection, routing_projection) = object_projections(0x11);

    assert_eq!(
        store.get_object_head(&context, domain, object_id).unwrap(),
        DurableObjectHead::Absent
    );

    // --- version 1: create from Absent ---------------------------------
    let create_version: DurableObjectVersionRecord =
        object_version_record(&chain_id, object_id, 1, 0x11);
    let create_outcome: DurableCommitOutcome = commit_object_mutation(
        &store,
        &context,
        (
            domain,
            object_id,
            DurableObjectHead::Absent,
            DurableObjectMutation::Create {
                version: create_version,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            },
        ),
        1,
    );
    assert_eq!(create_outcome, DurableCommitOutcome::Committed);

    let mut head: DurableObjectHead = store.get_object_head(&context, domain, object_id).unwrap();
    assert_eq!(
        head.object_version(),
        Some(DurableObjectVersion::new(1).unwrap())
    );

    // --- versions 2..=HIGHEST_OBJECT_VERSION: sequential updates --------
    //
    // Each update's precommit read assertion is validated through the
    // locked path (`validate_object_reads`, `lock = true`); the head read
    // that follows exercises the unlocked path (`get_object_head`,
    // `lock = false`). Both call `load_last_object_version_metadata`, so
    // this single ascending sequence exercises the fixed `ORDER BY` in
    // both variants across the 9->10 and 99->100 numeric-vs-lexicographic
    // boundaries.
    for version in 2..=HIGHEST_OBJECT_VERSION {
        let version_record: DurableObjectVersionRecord =
            object_version_record(&chain_id, object_id, version, 0x11);
        let outcome: DurableCommitOutcome = commit_object_mutation(
            &store,
            &context,
            (
                domain,
                object_id,
                head.clone(),
                DurableObjectMutation::Update {
                    version: version_record,
                    owner_projection: owner_projection.clone(),
                    routing_projection: routing_projection.clone(),
                },
            ),
            u16::try_from(version).unwrap(),
        );
        assert_eq!(
            outcome,
            DurableCommitOutcome::Committed,
            "commit to object_version {version} was rejected; \
             the locked read-assertion path likely mis-ordered numeric history"
        );

        head = store.get_object_head(&context, domain, object_id).unwrap();
        assert_eq!(
            head.object_version(),
            Some(DurableObjectVersion::new(version).unwrap()),
            "unlocked head read returned the wrong object_version at {version}; \
             the numeric ORDER BY likely fell back to lexicographic TEXT order"
        );
    }

    // --- close/reopen: a fresh pool and store still see the correct,
    // fully-rolled-over head -------------------------------------------
    drop(store);
    drop(pool);
    let reopened_pool: Pool<TestPostgresManager> = test_pool(&url);
    let reopened_store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        reopened_pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );
    let reopened_head: DurableObjectHead = reopened_store
        .get_object_head(&context, domain, object_id)
        .unwrap();
    assert_eq!(
        reopened_head.object_version(),
        Some(DurableObjectVersion::new(HIGHEST_OBJECT_VERSION).unwrap())
    );
    // Captured before corruption: the exact authentic head a well-behaved
    // caller would still be holding when the row underneath it is corrupted.
    let authentic_head: DurableObjectHead = reopened_head;

    // --- fail-closed: a genuine head/history disagreement is still
    // rejected, not silently accepted by the corrected ordering.
    //
    // The forged `current_version` must reference a row that still exists in
    // `object_versions` with a matching digest, or the deferred foreign key
    // from `object_heads` to `object_versions` rejects the corruption itself
    // before either read path is ever exercised. Pointing the head back at
    // `STALE_FORGED_HEAD_VERSION` (an earlier, real, digest-matched version)
    // keeps the row foreign-key-valid while disagreeing with the true latest
    // persisted history at `HIGHEST_OBJECT_VERSION`.
    let corrupted: u64 = admin
        .execute(
            "UPDATE sunrise_edge.object_heads AS h
             SET current_version = v.object_version,
                 digest_algorithm_id = v.digest_algorithm_id,
                 digest_bytes = v.digest_bytes
             FROM sunrise_edge.object_versions AS v
             WHERE h.chain_id_bytes = $1
               AND h.validator_id = $2
               AND h.atomicity_domain_id = $3
               AND h.object_id = $4
               AND v.chain_id_bytes = h.chain_id_bytes
               AND v.validator_id = h.validator_id
               AND v.atomicity_domain_id = h.atomicity_domain_id
               AND v.object_id = h.object_id
               AND v.object_version = $5",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&object_id.as_bytes()[..],
                &STALE_FORGED_HEAD_VERSION.to_string(),
            ],
        )
        .unwrap();
    assert_eq!(corrupted, 1);

    // Unlocked read path (`get_object_head`, `lock = false`): the correctly
    // ordered latest history (`HIGHEST_OBJECT_VERSION`) no longer matches the
    // forged head (`STALE_FORGED_HEAD_VERSION`).
    let corrupted_read = reopened_store.get_object_head(&context, domain, object_id);
    assert_eq!(corrupted_read, Err(DurableReadError::InvalidPersistedState));

    // Locked mutation path (`validate_object_reads`, `lock = true`, invoked
    // from `commit_invocation`): a caller still holding the last authentic
    // head it observed must be rejected, not allowed to commit a new version
    // on top of a corrupted, disagreeing head.
    let next_version: DurableObjectVersionRecord =
        object_version_record(&chain_id, object_id, HIGHEST_OBJECT_VERSION + 1, 0x11);
    let corrupted_commit: DurableCommitOutcome = commit_object_mutation(
        &reopened_store,
        &context,
        (
            domain,
            object_id,
            authentic_head,
            DurableObjectMutation::Update {
                version: next_version,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            },
        ),
        u16::try_from(HIGHEST_OBJECT_VERSION + 1).unwrap(),
    );
    assert_eq!(
        corrupted_commit,
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    // No new version was actually committed alongside the rejection.
    assert_eq!(
        reopened_store
            .get_object_version(
                &context,
                domain,
                object_id,
                DurableObjectVersion::new(HIGHEST_OBJECT_VERSION + 1).unwrap(),
            )
            .unwrap(),
        None
    );
}
