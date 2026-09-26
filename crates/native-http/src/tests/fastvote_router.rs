//! DR-0148 certified-only FastVote router: exhaustive route-shape checks.
//!
//! These tests never exercise a real WASM admission outcome (see
//! `node_core::fast_path::tests` and `apps/operator/tests` for that); they
//! prove the *route table itself*: every direct/legacy mutating path is
//! completely unmounted (a genuine 404, not an internally-gated 200/4xx),
//! every required bounded read route and both FastVote routes are mounted,
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

fn context() -> PublicationContext {
    PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        config().epoch(),
    )
    .unwrap()
}

fn fastvote_fee_policy() -> PaidFeePolicy {
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
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x8A; 32]).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let execution = PaidExecutionComposition::new(base_policy, fastvote_fee_policy());
    let fastvote = FastVoteComposition::new(execution, Arc::new(test_signer()), 1);
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
async fn certified_router_mounts_both_fastvote_routes() {
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
