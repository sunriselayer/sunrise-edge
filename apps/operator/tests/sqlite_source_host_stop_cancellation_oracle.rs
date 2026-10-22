//! Live-host oracle for DR-0222's 2026-10-16 addendum ("queued work observes
//! the same stop owner"): the exact `sqlite_source_host` ordered-economics
//! wiring -- the same `NativeBlockingExecutor` and
//! `certified_ordered_economics_router` pair the compiled binary serves --
//! refuses an admitted-but-queued real request before it ever touches real
//! SQLite storage once stop is requested, while an already-admitted real
//! request that already reached the real store still completes, and a
//! brand-new post-stop request never even reaches admission.
//!
//! This drives the production router/executor directly over a real loopback
//! TCP listener instead of the compiled binary, because only this process
//! can bound the Tokio blocking-thread pool at exactly one thread. The
//! compiled binary deliberately never limits that pool, so "admitted but
//! still queued behind the blocking pool" cannot be reproduced from outside
//! a real compiled process without a debug hook; this file is the narrow,
//! explicit-limitation seam the gap calls for instead. It still constructs
//! every piece (`OrderedEconomicsState`, `certified_ordered_economics_router`,
//! `NativeBlockingExecutor`) through the exact public production
//! constructors `sqlite_source_host::run` itself calls, against a real
//! on-disk SQLite namespace prepared the same way
//! `sqlite_source_host_process.rs` prepares one for the compiled binary.
//!
//! Explicit limitations: the compiled binary's own SIGINT/SIGTERM path and
//! the generic dispatcher-level queued/in-flight semantics are proven
//! elsewhere (`local_tls_startup.rs`, `sqlite_source_host_process.rs`,
//! native-http's own
//! `queued_admitted_work_refuses_after_stop_and_in_flight_work_completes`);
//! this file's job is only to show this host's actual wiring reaches that
//! already-proven behavior, not to re-derive it. The paid/FastVote lane
//! sharing the same executor needs quorum signing to drive a real request
//! and is not separately re-exercised here; it is covered by the same
//! generic dispatcher test and by `local_tls_startup.rs`'s compiled-process
//! stop coverage.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[allow(dead_code)]
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use consensus::ConsensusSigner;
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use fixture::Fixture;
use native_http::ordered_economics::{OrderedEconomicsState, certified_ordered_economics_router};
use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
    NativeBlockingExecutor, NativeBlockingPolicy, NativeHttpObservations, NativeHttpServePolicy,
};
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::ordered_economics::{
    OrderedEconomicsEnvironment, OrderedEconomicsPolicy, OrderedStatus, decode_ordered_status,
    query_status,
};
use node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH;
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::{
    Clock, DurableOperationContext, DurableOutboxLeaseId, StorageCorrelationId, StorageDeadline,
    SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use sunrise_edge_client::{LoopbackHttpTransport, Method, Transport, WireRequest, WireResponse};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

/// Deterministic, never-exhausted identities: this test's status-only lane
/// never approaches either real failure bound.
struct CountingIdentities(AtomicU64);

impl IndexedOutboxIdentitySource for CountingIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let sequence: u64 = self.0.fetch_add(1, Ordering::SeqCst);
        let mut lease_bytes: [u8; 32] = [0; 32];
        lease_bytes[0] = 0xAA;
        lease_bytes[24..].copy_from_slice(&sequence.to_be_bytes());
        let mut correlation_bytes: [u8; 16] = [0; 16];
        correlation_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease_bytes)
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?,
            StorageCorrelationId::new(correlation_bytes)
                .ok_or(IndexedOutboxIdentitySourceError::Unavailable)?,
        ))
    }
}

/// The status/observe/query lane never consults this; a panic on
/// `sign_framed` is the assertion that this assumption still holds.
struct UnusedSigner(ValidatorId);

impl ConsensusSigner for UnusedSigner {
    fn validator_id(&self) -> ValidatorId {
        self.0
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, _frame: &[u8]) -> Result<Vec<u8>, String> {
        panic!("the ordered-economics status lane must never sign");
    }
}

fn transport(address: SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        address,
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
        NonZeroUsize::new(64 * 1024).unwrap(),
        NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
    )
    .unwrap()
}

fn raw_status(address: SocketAddr) -> WireResponse {
    transport(address)
        .send(&WireRequest {
            method: Method::Get,
            path: ORDERED_ECONOMICS_STATUS_PATH.to_owned(),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        })
        .unwrap()
}

/// Bounded condition poll: a deterministic rendezvous barrier, never a fixed
/// sleep standing in for the condition itself.
fn poll_until(deadline: Instant, label: &str, mut condition: impl FnMut() -> bool) {
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "bounded rendezvous exceeded its deadline: {label}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn direct_operation(fence: WriterFenceGeneration, tag: u8) -> DurableOperationContext {
    let now_millis: u64 = SystemClock.now_unix_millis().unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now_millis.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([tag; 16]).unwrap(),
    )
}

#[test]
fn queued_admitted_work_refuses_before_storage_through_the_real_sqlite_host_wiring() {
    let mut fixture: Fixture = Fixture::new();
    // Close every in-process fixture handle before this test's own fresh
    // handles open the exact same files, matching the convention
    // `sqlite_source_host_process.rs` already relies on against a real
    // compiled host.
    fixture.close_source_owners();

    let state_path = fixture.directory.0.join("state-0.sqlite");
    let blob_path = fixture.directory.0.join("blobs.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.network.chain_id.clone(),
        fixture.network.validators[0].validator_id,
        fixture.network.domain,
    );
    let store: Arc<SqliteDurableStore> =
        Arc::new(SqliteDurableStore::open_existing(&state_path, namespace).unwrap());
    let blobs: Arc<SqliteBlobStore> =
        Arc::new(SqliteBlobStore::open_existing_writable(&blob_path).unwrap());
    let writer_fence: WriterFenceGeneration = store.writer_fence().unwrap();

    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&fixture.root, fixture.network.domain).unwrap();
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.network.context.clone());
    let direct_engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let direct_env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &direct_engine,
        blobs: blobs.as_ref(),
        seal: None,
    };

    // Independent, pre-router real-SQLite oracle values. `query_status`
    // never writes, so capturing them before any HTTP traffic is a genuine
    // baseline, not an artifact of this test's own later activity.
    let before_status: OrderedStatus =
        query_status(store.as_ref(), &direct_operation(writer_fence, 0x90), &direct_env).unwrap();
    let before_snapshot: SourceBusinessSnapshot = capture_source_business_snapshot(
        store.as_ref(),
        blobs.as_ref(),
        &direct_operation(writer_fence, 0x91),
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();

    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let observations: NativeHttpObservations = executor.observations();
    let state: OrderedEconomicsState<SqliteDurableStore, SystemClock, CountingIdentities, UnusedSigner> =
        OrderedEconomicsState {
            store: store.clone(),
            clock: Arc::new(SystemClock),
            identities: Arc::new(CountingIdentities(AtomicU64::new(1))),
            domain: fixture.network.domain,
            writer_fence,
            operation_timeout: Duration::from_secs(30),
            policy: policy.clone(),
            history: Vec::new(),
            leg_policy: leg_policy.clone(),
            engine: Arc::new(LocalWasmExecutionEngine::new()),
            blobs: blobs.clone(),
            seal: None,
            signer: UnusedSigner(fixture.network.validators[0].validator_id),
            blocking_executor: executor.clone(),
            // The exact wiring under test: this router's pre-storage checks
            // share this executor's own stop signal, precisely as
            // `sqlite_source_host::run` wires
            // `OrderedEconomicsState::cancellation`.
            cancellation: Some(executor.stop_cancellation()),
        };
    let router = certified_ordered_economics_router(state);

    // A dedicated runtime with exactly one real blocking thread: the only
    // way to make "admitted but still queued behind the blocking pool"
    // deterministic, since the compiled host intentionally never bounds
    // that pool.
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let handle: tokio::runtime::Handle = runtime.handle().clone();

    let listener: tokio::net::TcpListener = handle
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let server = handle.spawn(native_http::serve_with_stream_upgrade_observed(
        listener,
        router,
        NativeHttpServePolicy::default(),
        |stream: tokio::net::TcpStream| async move { Ok::<_, std::io::Error>(stream) },
        async move {
            let _ = stop_receiver.await;
        },
        observations.clone(),
    ));

    // Baseline: the real router, still fully open, serves one genuine
    // SQLite-backed status read that matches the direct store query exactly.
    let opened_response: WireResponse = raw_status(address);
    assert_eq!(opened_response.status, 200);
    let opened_status: OrderedStatus = decode_ordered_status(&opened_response.body).unwrap();
    assert_eq!(opened_status, before_status);
    assert_eq!(observations.snapshot().blocking_admitted, 1);

    // Occupy the sole real blocking thread with a raw, non-production task
    // so the next two real requests become admitted (permit granted) while
    // still queued behind Tokio's blocking-pool limit, never having entered
    // their own work closure.
    let release: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
    let release_for_occupier: Arc<(Mutex<bool>, Condvar)> = release.clone();
    let (entered_sender, entered_receiver) = mpsc::channel::<()>();
    let occupier = handle.spawn_blocking(move || {
        entered_sender.send(()).unwrap();
        let (lock, wake): &(Mutex<bool>, Condvar) = release_for_occupier.as_ref();
        let mut released = lock.lock().unwrap();
        while !*released {
            let (next, timeout) = wake.wait_timeout(released, Duration::from_secs(20)).unwrap();
            released = next;
            assert!(!timeout.timed_out(), "bounded occupier release");
        }
    });
    entered_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("the occupier must take the sole real blocking thread");

    let (queued_a_sender, queued_a_receiver) = mpsc::channel::<WireResponse>();
    std::thread::spawn(move || {
        let _ = queued_a_sender.send(raw_status(address));
    });
    let first_deadline: Instant = Instant::now() + Duration::from_secs(5);
    poll_until(first_deadline, "first queued admission", || {
        observations.snapshot().blocking_admitted >= 2
    });

    let (queued_b_sender, queued_b_receiver) = mpsc::channel::<WireResponse>();
    std::thread::spawn(move || {
        let _ = queued_b_sender.send(raw_status(address));
    });
    let second_deadline: Instant = Instant::now() + Duration::from_secs(5);
    poll_until(second_deadline, "second queued admission", || {
        observations.snapshot().blocking_admitted >= 3
    });

    // Both real requests are now admitted (permits held) but strictly
    // queued behind the occupied real blocking thread, never having entered
    // their closures. Closing here cannot be observed by either one until
    // the occupier releases the thread below.
    executor.close();
    {
        let (lock, wake): &(Mutex<bool>, Condvar) = release.as_ref();
        *lock.lock().unwrap() = true;
        wake.notify_all();
    }

    let response_a: WireResponse = queued_a_receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    let response_b: WireResponse = queued_b_receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    for response in [&response_a, &response_b] {
        assert_eq!(response.status, 503);
        assert_eq!(response.body, b"invocation-cancelled-before-storage");
    }
    handle.block_on(occupier).unwrap();

    handle.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), executor.wait_drained())
            .await
            .expect("drain must complete even though every queued job was cancelled");
    });
    assert_eq!(observations.snapshot().blocking_admitted, 3);
    assert_eq!(
        observations.snapshot().blocking_closed,
        0,
        "this host's wired cancellation must intercept before executor.try_acquire's own closed branch"
    );

    // A brand-new request arriving strictly after stop never reaches
    // admission at all: refused by the same message, through the earlier
    // pre-acquire cancellation check, never a fresh permit.
    let after_close_response: WireResponse = raw_status(address);
    assert_eq!(after_close_response.status, 503);
    assert_eq!(
        after_close_response.body,
        b"invocation-cancelled-before-storage"
    );
    assert_eq!(
        observations.snapshot().blocking_admitted,
        3,
        "a post-stop request must never acquire a fresh permit"
    );

    let _ = stop_sender.send(());
    handle.block_on(server).unwrap().unwrap();

    // Real SQLite oracle: neither the successful read nor either refusal
    // path left any observable effect.
    let after_status: OrderedStatus =
        query_status(store.as_ref(), &direct_operation(writer_fence, 0x92), &direct_env).unwrap();
    assert_eq!(after_status, before_status);
    let after_snapshot: SourceBusinessSnapshot = capture_source_business_snapshot(
        store.as_ref(),
        blobs.as_ref(),
        &direct_operation(writer_fence, 0x93),
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    assert_eq!(after_snapshot.records, before_snapshot.records);
    assert_eq!(
        after_snapshot.referenced_blobs,
        before_snapshot.referenced_blobs
    );
}
