//! DR-0148 certified-only FastVote router: exhaustive route-shape checks.
//!
//! These tests never exercise a real WASM admission outcome (see
//! `node_core::fast_path::tests` and `apps/operator/tests` for that); they
//! prove the *route table itself*: every direct/legacy mutating path is
//! completely unmounted (a genuine 404, not an internally-gated 200/4xx),
//! every required bounded read route and the current FastVote routes are mounted,
//! and construction rejects a FastVote composition whose policy context
//! disagrees with the native ingress context.
use super::*;
use crate::fastvote::{DisabledNodeStateMachine, certified_fastvote_router};
use crate::paid_execution::PAID_FEE_POLICY_PATH;
use consensus::ConsensusSigner;
use execution::call::InstanceTarget;
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidFeePolicy};
use execution::publication::{PublicationContext, UnverifiedDependencyRef};
use fees::GasSchedule;
use protocol_types::{SignatureSchemeId, ValidatorId};

#[path = "certified_relay_contract.rs"]
mod certified_relay_contract;

#[test]
fn frozen_frontier_wire_and_consensus_page_bounds_match() {
    assert_eq!(
        node_wire::MAX_FRONTIER_PAGE_BYTES,
        consensus::MAX_FROZEN_FRONTIER_PAGE_BYTES
    );
    assert_eq!(
        usize::from(node_wire::MAX_FRONTIER_PAGE_LIMIT),
        consensus::MAX_FROZEN_FRONTIER_PAGE_ENTRIES
    );
}

#[test]
fn frontier_errors_separate_prerequisites_cursors_and_durable_corruption() {
    use node_core::ordered_economics::FrozenFrontierError;

    assert_eq!(
        crate::fastvote::frontier_error_response(&FrozenFrontierError::NotReady("freeze pending"))
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        crate::fastvote::frontier_error_response(&FrozenFrontierError::InvalidCursor(
            "unknown cursor"
        ))
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        crate::fastvote::frontier_error_response(&FrozenFrontierError::Invalid("tombstoned"))
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

fn context() -> PublicationContext {
    PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        config().epoch(),
    )
    .unwrap()
}

pub(super) fn fastvote_fee_policy() -> PaidFeePolicy {
    let publisher: [u8; 32] = [0x51; 32];
    let origin: abi::package_types::PackageOrigin = abi::package_types::PackageOrigin::unverified(
        config().chain_id().clone(),
        publisher,
        [0x52; 32],
    )
    .unwrap();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        origin.clone(),
        1,
        context(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x53; 32]),
    )
    .unwrap();
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    PaidFeePolicy {
        context: context(),
        base_policy_digest: base_policy.digest(&resolver()).unwrap(),
        instance: InstanceTarget {
            creator: publisher,
            seed: [0x54; 32],
            revision: 1,
            record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
        },
        code,
        reserve_entrypoint: "reserve".to_owned(),
        reserve_all_entrypoint: "reserve_all".to_owned(),
        settle_entrypoint: "settle".to_owned(),
        type_arguments: Vec::new(),
        asset_type: abi::package_types::ScopedTypeTag::new(origin.clone(), 2, Vec::new()).unwrap(),
        reservation_type: abi::package_types::ScopedTypeTag::new(origin, 4, Vec::new()).unwrap(),
        schema: 1,
        fee_recipient: publisher,
        gas_schedule: GasSchedule {
            base_fee: 10,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1,
        reserve_allowance: MIN_RESERVE_ALLOWANCE,
        settle_allowance: MIN_SETTLE_ALLOWANCE,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    }
}

/// A real (non-mocked) Ed25519 signer, mirroring every other real-signer test
/// double already used across this workspace's fast-vote test suites.
struct TestSigner {
    validator_id: ValidatorId,
    signing_key: ed25519_zebra::SigningKey,
}

impl ConsensusSigner for TestSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

fn test_signer() -> TestSigner {
    let signing_key = ed25519_zebra::SigningKey::from([0x61; 32]);
    let verification_key: ed25519_zebra::VerificationKey = (&signing_key).into();
    let id_bytes: [u8; 32] = verification_key.into();
    TestSigner {
        validator_id: ValidatorId::new(id_bytes),
        signing_key,
    }
}

fn certified_router() -> Router {
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    certified_router_with_store(store, Arc::new(test_signer()))
}

fn certified_router_with_store(
    store: Arc<MemoryDurableStateStore>,
    signer: Arc<dyn ConsensusSigner + Send + Sync>,
) -> Router {
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x8A; 32]).unwrap();
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let execution = PaidExecutionComposition::new(base_policy, fastvote_fee_policy());
    let fastvote = FastVoteComposition::new(execution, signer, 1);
    certified_fastvote_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        fastvote,
        active_protocol_config(domain),
        structured_request_authority(),
        config(),
        resolver(),
        Vec::new(),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}

struct ObservedSigner {
    signer: TestSigner,
    calls: Arc<AtomicUsize>,
}

impl ConsensusSigner for ObservedSigner {
    fn validator_id(&self) -> ValidatorId {
        self.signer.validator_id()
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        self.signer.signature_scheme()
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.signer.sign_framed(framed)
    }
}

#[tokio::test]
async fn live_cached_protocol_responses_refuse_every_import_origin_without_signing() {
    use protocol_types::ExecutionGeneration;
    use runtime::{
        DurableCommitOutcome, ImportBinding, ImportContext, InactiveImportRepository,
        portable::DurablePortableSnapshotRepository,
    };

    let domain: AtomicityDomainId = AtomicityDomainId::new([0x8A; 32]).unwrap();
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x71; 32]);
    // These are storage-only claims, deliberately not a verified core plan.
    // They must never become a live protocol-output capability in any phase.
    let binding: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: config().chain_id().clone(),
            protocol_version: config().protocol_version(),
            epoch: config().epoch(),
        },
        domain,
        genesis_digest: digest,
        validator_set_digest: digest,
        cut_digest: digest,
        package_digest: digest,
        plan_digest: digest,
        row_count: 0,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(19),
    };
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let operation: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(10_000).unwrap(),
        StorageCorrelationId::new([0x72; 16]).unwrap(),
    );
    for phase in 0..3 {
        let store: Arc<MemoryDurableStateStore> =
            Arc::new(MemoryDurableStateStore::new_import_target(binding.clone(), fence).unwrap());
        if phase > 0 {
            assert_eq!(
                store.begin_import(&operation, domain, &binding, digest),
                DurableCommitOutcome::Committed
            );
        }
        if phase > 1 {
            let progress = store
                .read_import_progress(&operation, domain)
                .unwrap()
                .unwrap();
            let token = store.begin_portable_snapshot(&operation, domain).unwrap();
            assert_eq!(
                store.finish_import(&operation, domain, &binding, &progress, &token),
                DurableCommitOutcome::Committed
            );
        }
        let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let signer: Arc<dyn ConsensusSigner + Send + Sync> = Arc::new(ObservedSigner {
            signer: test_signer(),
            calls: calls.clone(),
        });
        let app: Router = certified_router_with_store(store, signer);
        let frontier: Vec<u8> = node_wire::FrozenFrontierPageRequest {
            epoch: config().epoch(),
            after_request_id: None,
            limit: 1,
        }
        .encode()
        .unwrap();
        let drain: Vec<u8> = node_wire::DrainSignerProgressRequest {
            epoch: config().epoch(),
            signer: test_signer().validator_id(),
        }
        .encode()
        .unwrap();
        for (path, bytes) in [
            (FASTVOTE_FROZEN_FRONTIER_PAGE_PATH, frontier),
            (node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH, drain),
        ] {
            let response: Response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(Body::from(bytes))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CONFLICT,
                "phase={phase}, route={path}"
            );
            let body: Bytes = to_bytes(response.into_body(), 1024).await.unwrap();
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains("inactive-import-namespace")
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0, "phase={phase}");
    }
}

async fn dispatch(app: &Router, method: &str, path: &str, body: Vec<u8>) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The explicit, shared list of every direct/legacy mutating path this
/// router must never mount, checked exhaustively against a genuine 404
/// (route not found), not an internally-gated 4xx/200 the handler itself
/// could return if it were reachable.
const DENIED_MUTATING_PATHS: &[&str] = crate::fastvote::CERTIFIED_FASTVOTE_EXCLUDED_MUTATION_PATHS;

#[tokio::test]
async fn certified_router_omits_every_direct_or_legacy_mutating_route() {
    let app = certified_router();
    for path in DENIED_MUTATING_PATHS {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            let status = dispatch(&app, method, path, vec![0xAA]).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "expected {method} {path} to be completely unmounted, got {status}"
            );
        }
    }
}

#[tokio::test]
async fn certified_router_still_serves_liveness_and_bounded_reads() {
    let app = certified_router();
    assert_eq!(
        dispatch(&app, "GET", LIVENESS_PATH, Vec::new()).await,
        StatusCode::NO_CONTENT
    );
    // A read route being *mounted* is proven by a non-404 status; the exact
    // success/failure shape of the query itself is covered by the existing
    // `local_execution_http`/main `tests` suites for the shared handlers.
    assert_ne!(
        dispatch(&app, "GET", QUERY_CONTEXT_PATH, Vec::new()).await,
        StatusCode::NOT_FOUND
    );
    assert_ne!(
        dispatch(&app, "GET", PAID_FEE_POLICY_PATH, Vec::new()).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn certified_router_mounts_fastvote_and_publication_retention_routes() {
    let app = certified_router();
    // Malformed bodies still prove the route exists: a 4xx response from the
    // handler, never the router's own 404.
    assert_ne!(
        dispatch(&app, "POST", FASTVOTE_PREPARE_PATH, vec![0xAA]).await,
        StatusCode::NOT_FOUND
    );
    assert_ne!(
        dispatch(&app, "POST", FASTVOTE_CERTIFICATES_PATH, vec![0xAA]).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        dispatch(&app, "POST", FASTVOTE_PUBLICATION_RETAIN_PATH, vec![0xAA]).await,
        StatusCode::BAD_REQUEST,
        "malformed publication must be rejected by its mounted handler"
    );
    assert_eq!(
        dispatch(&app, "GET", FASTVOTE_PUBLICATION_RETAIN_PATH, Vec::new()).await,
        StatusCode::METHOD_NOT_ALLOWED
    );
    for path in [
        FASTVOTE_PUBLICATION_SOURCE_PATH,
        FASTVOTE_PUBLISHED_APPLY_PATH,
        FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
        node_wire::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
        node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
        node_wire::FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
        node_wire::FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
        node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
        node_wire::FASTVOTE_DRAIN_APPLY_PATH,
        "/v1/fastvote/drain/import/0101010101010101010101010101010101010101010101010101010101010101",
    ] {
        assert_eq!(
            dispatch(&app, "POST", path, vec![0xAA]).await,
            StatusCode::BAD_REQUEST,
            "malformed request must reach the mounted {path} handler"
        );
        assert_eq!(
            dispatch(&app, "GET", path, Vec::new()).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    assert_ne!(
        dispatch(
            &app,
            "POST",
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            Vec::new()
        )
        .await,
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        dispatch(
            &app,
            "POST",
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            vec![0xAA]
        )
        .await,
        StatusCode::BAD_REQUEST,
    );
    let stale_request: node_wire::FrozenFrontierPageRequest =
        node_wire::FrozenFrontierPageRequest {
            epoch: Epoch::new(config().epoch().get() + 1),
            after_request_id: None,
            limit: 1,
        };
    assert_eq!(
        dispatch(
            &app,
            "POST",
            FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
            stale_request.encode().unwrap()
        )
        .await,
        StatusCode::CONFLICT,
    );
    assert_eq!(
        dispatch(
            &app,
            "GET",
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            Vec::new()
        )
        .await,
        StatusCode::METHOD_NOT_ALLOWED,
    );
}

#[test]
fn certified_router_construction_rejects_a_mismatched_fee_policy_context() {
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x8B; 32]).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let mut mismatched_policy: PaidFeePolicy = fastvote_fee_policy();
    // A fee policy whose committed context does not match the native
    // ingress context (chain/protocol/epoch from `config()`).
    mismatched_policy.context = PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        Epoch::new(config().epoch().get() + 1),
    )
    .unwrap();
    let execution = PaidExecutionComposition::new(base_policy, mismatched_policy);
    let fastvote = FastVoteComposition::new(execution, Arc::new(test_signer()), 1);
    let error = certified_fastvote_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        fastvote,
        active_protocol_config(domain),
        structured_request_authority(),
        config(),
        resolver(),
        Vec::new(),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap_err();
    assert_eq!(
        error,
        StructuredDurableRouterError::FastVotePolicyContextMismatch
    );
}

#[test]
fn disabled_node_state_machine_never_authorizes_a_transition() {
    let machine = DisabledNodeStateMachine;
    let payload: Vec<u8> = CanonicalStruct::new(0xEF10, 1).finish().unwrap();
    let event = NodeEvent::new(
        config().chain_id().clone(),
        config().protocol_version(),
        config().epoch(),
        RequestId::new([0x01; 32]).unwrap(),
        NodeEventKind::SubmitTransaction,
        payload,
    )
    .unwrap();
    assert!(matches!(
        machine.access_plan(&event),
        Err(NodeCoreError::PersistenceInvariant(_))
    ));
}
