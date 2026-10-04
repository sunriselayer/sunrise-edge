//! Route-level regression for resolve_query_protocol_config: the host
//! /v1/context route must select the active hash suite fresh from the
//! trusted resolver at the authoritative committed epoch on every request,
//! never a value fixed once at router construction. See
//! docs/architecture/first-successor-serving.md and TODO.md's host query
//! limitation note.
use super::*;
use protocol_upgrades::HashSuiteScheduleConfig;

fn rotating_resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(5),
                suite: HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Sha3_256),
            },
        ],
    )
    .unwrap()
}

/// The same full schedule rotating_resolver pins, represented the way a
/// host builder must represent it in the advertised ProtocolConfig: the
/// fixed genesis entry plus one appended future suite.
fn rotating_protocol_config(domain: AtomicityDomainId) -> ProtocolConfig {
    let mut protocol_config: ProtocolConfig = active_protocol_config(domain);
    protocol_config
        .hash_suite_schedule
        .schedule(
            HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Sha3_256),
            Epoch::new(5),
            Epoch::new(0),
        )
        .unwrap();
    protocol_config
}

fn rotating_app(
    store: Arc<MemoryDurableStateStore>,
    clock: Arc<ManualClock>,
    domain: AtomicityDomainId,
) -> Router {
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            clock,
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        rotating_protocol_config(domain),
        structured_request_authority(),
        config(),
        rotating_resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

async fn fetch_context(app: &Router) -> HttpContextQueryResult {
    let response: Response = app
        .clone()
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes: Bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    HttpContextQueryResult::decode(&bytes).unwrap()
}

/// Independently rebuilt expectation, never reused from the code under
/// test: the exact schedule rotating_resolver pins, with only
/// hash_suite_id varying between the two boundary sides.
fn expected_config_bytes(domain: AtomicityDomainId, hash_suite_id: HashSuiteId) -> Vec<u8> {
    let mut config: ProtocolConfig = rotating_protocol_config(domain);
    config.hash_suite_id = hash_suite_id;
    config.canonical_bytes().unwrap()
}

#[tokio::test]
async fn context_route_tracks_a_scheduled_non_default_suite_across_a_live_epoch_advance() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD2; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD2; 16]).unwrap(),
    );
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(3),
        None,
    );
    let app: Router = rotating_app(
        Arc::clone(&store),
        Arc::new(ManualClock::new(10_000)),
        domain,
    );

    let before: HttpContextQueryResult = fetch_context(&app).await;
    assert_eq!(before.epoch(), Epoch::new(3));
    assert_eq!(before.hash_suite_id(), HashSuiteId::new(1));
    assert_eq!(
        before.protocol_config_bytes(),
        expected_config_bytes(domain, HashSuiteId::new(1)).as_slice()
    );

    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(10),
        Some(Epoch::new(3)),
    );
    let after: HttpContextQueryResult = fetch_context(&app).await;
    assert_eq!(after.epoch(), Epoch::new(10));
    assert_eq!(after.hash_suite_id(), HashSuiteId::new(9));
    assert_eq!(
        after.protocol_config_bytes(),
        expected_config_bytes(domain, HashSuiteId::new(9)).as_slice()
    );
}

#[tokio::test]
async fn context_route_resolves_the_exact_scheduled_activation_boundary() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD3; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD3; 16]).unwrap(),
    );
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(4),
        None,
    );
    let app: Router = rotating_app(
        Arc::clone(&store),
        Arc::new(ManualClock::new(10_000)),
        domain,
    );
    let just_before: HttpContextQueryResult = fetch_context(&app).await;
    assert_eq!(just_before.hash_suite_id(), HashSuiteId::new(1));

    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(5),
        Some(Epoch::new(4)),
    );
    let at_boundary: HttpContextQueryResult = fetch_context(&app).await;
    assert_eq!(at_boundary.hash_suite_id(), HashSuiteId::new(9));
    assert_ne!(
        just_before.protocol_config_bytes(),
        at_boundary.protocol_config_bytes()
    );
}

#[tokio::test]
async fn context_route_fails_closed_when_the_resolved_suite_is_not_in_the_advertised_schedule() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD4; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD4; 16]).unwrap(),
    );
    // Committed epoch 10 is past the resolver own epoch-5 rotation to suite
    // id 9, but the advertised protocol_config below never learned that
    // later entry -- an inconsistent host composition that must refuse,
    // never silently default to its stale id-1 schedule.
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(10),
        None,
    );
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    let app: Router = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        active_protocol_config(domain),
        structured_request_authority(),
        config(),
        rotating_resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response: Response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The schedule-mismatch check (fewer entries than resolver.schedules())
    // now refuses before config.validate() would even run, so this is the
    // same PersistenceInvariant classification as the mismatch tests below,
    // not the ProtocolConfigError unavailable classification validate()
    // alone would have produced.
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Both public router constructors already force base.protocol_version to
/// equal the caller/resolver at construction time (see
/// validate_structured_durable_router_authority and
/// successor::tests::router_refuses_a_protocol_config_that_differs_from_the_pinned_resolver),
/// so this mismatch is unreachable through an actual HTTP route; this
/// calls the exact shared function both routes use for their own
/// self-sufficient check instead of re-deriving it.
#[test]
fn resolve_query_protocol_config_fails_closed_on_a_base_version_resolver_caller_mismatch() {
    let resolver: HashSuiteResolver = rotating_resolver();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD9; 32]).unwrap();
    let mut base: ProtocolConfig = rotating_protocol_config(domain);
    base.protocol_version = ProtocolVersion::new(2);
    let caller_chain_id: ChainId = ChainId::new("sunrise-test").unwrap();
    let result: Result<ProtocolConfig, NodeCoreError> = resolve_query_protocol_config(
        &resolver,
        &caller_chain_id,
        ProtocolVersion::new(3),
        Epoch::new(3),
        &base,
    );
    assert!(matches!(
        result,
        Err(NodeCoreError::PersistenceInvariant(_))
    ));
}

/// The advertised protocol_config below claims protocol_version 2 while
/// both the resolver and the caller's own NodeConfig agree on version 3.
/// structured_durable_router's own construction-time check
/// (validate_structured_durable_router_authority) already refuses this
/// composition before any route is ever mounted, so this proves that exact
/// typed construction refusal rather than unwrapping into an unreachable
/// HTTP call.
#[test]
fn router_construction_fails_closed_when_the_advertised_protocol_version_disagrees_with_the_caller_and_resolver()
 {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD8; 32]).unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(domain);
    protocol_config.protocol_version = ProtocolVersion::new(2);
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    let result: Result<Router, StructuredDurableRouterError> = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config(),
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    );
    assert_eq!(
        result.err(),
        Some(
            StructuredDurableRouterError::ProtocolVersionAuthorityMismatch {
                node_config: ProtocolVersion::new(3),
                protocol_config: ProtocolVersion::new(2),
            }
        )
    );
}

/// A real, non-default suite activating at epoch zero itself (not a later
/// rotation), exercised end to end through the actual HTTP route and
/// decoded response frame, with every expectation rebuilt independently of
/// resolve_query_protocol_config.
fn genesis_suite(id: u16) -> HashSuite {
    HashSuite::uniform(HashSuiteId::new(id), HashAlgorithmId::Sha3_256)
}

#[tokio::test]
async fn context_route_reports_a_non_default_epoch_zero_suite() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD5; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD5; 16]).unwrap(),
    );
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(0),
        None,
    );
    let suite: HashSuite = genesis_suite(42);
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: suite.clone(),
        }],
    )
    .unwrap();
    let schedule: HashSuiteScheduleConfig = HashSuiteScheduleConfig::new(vec![HashSuiteSchedule {
        activation_epoch: Epoch::new(0),
        suite: suite.clone(),
    }])
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(domain);
    protocol_config.hash_suite_id = suite.id;
    protocol_config.hash_suite_schedule = schedule;
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    let app: Router = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config.clone(),
        structured_request_authority(),
        config(),
        resolver,
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let result: HttpContextQueryResult = fetch_context(&app).await;
    assert_eq!(result.epoch(), Epoch::new(0));
    assert_eq!(result.hash_suite_id(), HashSuiteId::new(42));
    let mut expected: ProtocolConfig = protocol_config;
    expected.hash_suite_id = HashSuiteId::new(42);
    assert_eq!(
        result.protocol_config_bytes(),
        expected.canonical_bytes().unwrap().as_slice()
    );
}

/// resolver's real epoch-5 suite uses Sha3_256 for id 9; the advertised
/// schedule below instead claims Sha2_256 for that same id. config.validate
/// alone would accept this (the id is present), so this proves
/// resolve_query_protocol_config's own full-schedule comparison, not that
/// looser check.
#[tokio::test]
async fn context_route_fails_closed_on_a_same_id_different_algorithm_schedule_mismatch() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD6; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD6; 16]).unwrap(),
    );
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(5),
        None,
    );
    let mut protocol_config: ProtocolConfig = active_protocol_config(domain);
    protocol_config
        .hash_suite_schedule
        .schedule(
            HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Sha2_256),
            Epoch::new(5),
            Epoch::new(0),
        )
        .unwrap();
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    let app: Router = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config(),
        rotating_resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response: Response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// resolver's real rotation activates id 9 at epoch 5; the advertised
/// schedule below activates the identical id/algorithm suite at epoch 6
/// instead -- a genuinely different committed activation boundary.
#[tokio::test]
async fn context_route_fails_closed_on_a_same_id_different_activation_epoch_mismatch() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD7; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD7; 16]).unwrap(),
    );
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(6),
        None,
    );
    let mut protocol_config: ProtocolConfig = active_protocol_config(domain);
    protocol_config
        .hash_suite_schedule
        .schedule(
            HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Sha3_256),
            Epoch::new(6),
            Epoch::new(0),
        )
        .unwrap();
    let machine: Arc<IncrementMachine> = Arc::new(IncrementMachine::new(config().state_key()));
    let app: Router = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config(),
        rotating_resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response: Response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
