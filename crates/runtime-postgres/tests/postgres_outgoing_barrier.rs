//! Live protected namespace-slot correctness: oversized/missing rows
//! fail closed, and a Sealed row with a nonempty outbox rejects cached
//! claim/ACK replay from the same metadata-locked transaction.

use postgres::NoTls;
use protocol_types::{AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::outgoing_seal::{OutgoingBarrier, SealBarrier, TransitionHistoryState};
use runtime::{
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableOperationContext, DurableOutboxAcknowledgement,
    DurableOutboxAcknowledgementOutcome, DurableOutboxAcknowledgementRejection, DurableOutboxBatch,
    DurableOutboxClaimOutcome, DurableOutboxClaimRejection, DurableOutboxLeaseId,
    DurableOutboxMessage, DurableReadError, DurableRequestId, DurableRequestReceipt,
    IndexedOutboxRepository, RequestOutboxClaimRequest, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, apply_initial_schema, bootstrap_namespace, build_postgres_pool,
};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "postgres_outgoing_barrier/successor_serving.rs"]
mod successor_serving;
mod support;

type Manager = PostgresConnectionManager<NoTls>;

fn pool(url: &str) -> Pool<Manager> {
    build_postgres_pool(
        url.parse().unwrap(),
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(2).unwrap(),
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap()
}

fn store(pool: Pool<Manager>, namespace: PostgresNamespace) -> PostgresDurableStore<Manager> {
    PostgresDurableStore::new(
        pool,
        namespace,
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    )
}

fn context(fence: WriterFenceGeneration) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now.checked_add(120_000).unwrap()).unwrap(),
        StorageCorrelationId::new([0x7a; 16]).unwrap(),
    )
}

fn fresh_namespace(prefix: &str, validator_byte: u8, domain_byte: u8) -> PostgresNamespace {
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let chain: ChainId = ChainId::new(format!("{prefix}-{}-{nanos}", std::process::id())).unwrap();
    PostgresNamespace::new(
        &chain,
        ValidatorId::new([validator_byte; 32]),
        AtomicityDomainId::new([domain_byte; 32]).unwrap(),
    )
    .unwrap()
}

fn connect_admin(url: &str) -> postgres::Client {
    let mut admin: postgres::Client = postgres::Client::connect(url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, "sunrise_edge_test",
        "refusing to write a non-test database"
    );
    apply_initial_schema(&mut admin).unwrap();
    admin
}

#[test]
fn postgres_outgoing_barrier_oversized_write_is_rejected_and_malformed_row_fails_closed() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = connect_admin(&url);
    let namespace = fresh_namespace("barrier-oversized", 0xc1, 0xc2);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    let oversized: Vec<u8> = vec![0u8; 2048];
    let before: Vec<u8> = runtime::encode_outgoing_barrier(&OutgoingBarrier::Unsealed).unwrap();
    let error = admin
        .execute(
            "UPDATE sunrise_edge.outgoing_barrier SET barrier = $1
             WHERE chain_id_bytes = $2 AND validator_id = $3 AND atomicity_domain_id = $4",
            &[
                &oversized,
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap_err();
    assert_eq!(
        error.code(),
        Some(&postgres::error::SqlState::CHECK_VIOLATION)
    );
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    assert_eq!(
        current.get_outgoing_barrier(&context(fence), namespace.domain()),
        Ok(OutgoingBarrier::Unsealed)
    );
    let stored: Vec<u8> = admin.query_one(
        "SELECT barrier FROM sunrise_edge.outgoing_barrier WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
        &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..]],
    ).unwrap().get(0);
    assert_eq!(stored, before);
    // Disposable namespace at-rest corruption within SQL's size bound. Do
    // not weaken the shared table's constraint just to simulate this input.
    admin.execute(
        "UPDATE sunrise_edge.outgoing_barrier SET barrier = $1 WHERE chain_id_bytes = $2 AND validator_id = $3 AND atomicity_domain_id = $4",
        &[&vec![0u8; 16], &namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..]],
    ).unwrap();
    let result = current.get_outgoing_barrier(&context(fence), namespace.domain());
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn postgres_outgoing_barrier_missing_row_fails_closed() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = connect_admin(&url);
    let namespace = fresh_namespace("barrier-missing", 0xc3, 0xc4);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    admin
        .execute(
            "DELETE FROM sunrise_edge.outgoing_barrier
             WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let result = current.get_outgoing_barrier(&context(fence), namespace.domain());
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn postgres_sealed_row_rejects_cached_claim_and_ack_replay() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = connect_admin(&url);
    for acknowledged_before_corruption in [false, true] {
        let namespace = fresh_namespace("barrier-sealed-claim", 0xc5, 0xc6);
        let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
        let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
        let domain = namespace.domain();
        let operation = context(fence);

        let request_id = DurableRequestId::new([0x51; 32]).unwrap();
        let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x52; 32]);
        let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
        let message = DurableOutboxMessage::new(
            Digest32::new(HashAlgorithmId::Sha2_256, [0x53; 32]),
            vec![9],
        )
        .unwrap();
        let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
        let invocation = DurableInvocationTransaction::new(
            domain,
            None,
            DurableObjectChanges::empty(),
            receipt,
            Some(outbox),
        )
        .unwrap();
        assert_eq!(
            current.commit_invocation(&operation, invocation),
            DurableCommitOutcome::Committed
        );

        let lease_id = DurableOutboxLeaseId::new([0x54; 32]).unwrap();
        let claim_request =
            RequestOutboxClaimRequest::new(domain, request_id, 1_000, lease_id, 2_000).unwrap();
        let claimed = current.claim_request_outbox(&operation, claim_request);
        assert!(matches!(claimed, DurableOutboxClaimOutcome::Claimed(_)));
        let acknowledgement = DurableOutboxAcknowledgement::new(domain, request_id, 0, lease_id);
        if acknowledged_before_corruption {
            assert_eq!(
                current.acknowledge_outbox(&operation, acknowledgement),
                DurableOutboxAcknowledgementOutcome::Acknowledged
            );
        }

        let sealed = SealBarrier {
            outgoing_epoch: Epoch::new(1),
            request: {
                let mut r = [0x55u8; 32];
                r[0] |= 0x80;
                r
            },
            height: 1,
            block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x56; 32]),
            target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x57; 32]),
            transition_history: TransitionHistoryState::Virgin,
        };
        let sealed_bytes =
            runtime::outgoing_seal::encode_outgoing_barrier(&OutgoingBarrier::Sealed(sealed))
                .unwrap();
        admin
            .execute(
                "UPDATE sunrise_edge.outgoing_barrier SET barrier = $1
             WHERE chain_id_bytes = $2 AND validator_id = $3 AND atomicity_domain_id = $4",
                &[
                    &sealed_bytes,
                    &namespace.chain_id_bytes(),
                    &&namespace.validator_id().as_bytes()[..],
                    &&namespace.domain().as_bytes()[..],
                ],
            )
            .unwrap();

        let replay_claim_request =
            RequestOutboxClaimRequest::new(domain, request_id, 1_500, lease_id, 2_000).unwrap();
        let replay = current.claim_request_outbox(&operation, replay_claim_request);
        assert_eq!(
            replay,
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::InvalidPersistedState)
        );

        let acknowledgement = DurableOutboxAcknowledgement::new(domain, request_id, 0, lease_id);
        let ack_outcome = current.acknowledge_outbox(&operation, acknowledgement);
        assert_eq!(
            ack_outcome,
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            )
        );
    }
}
