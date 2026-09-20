use std::cell::RefCell;
use std::collections::VecDeque;

use execution::call::InstanceTarget;
use execution::local_execution::{LOCAL_EXECUTION_TRAP_REASON, LocalExecutionPolicy};
use execution::paid_execution::*;
use execution::publication::{ArtifactParts, CodeArtifact, PublicationContext};
use fees::{Amount, GasSchedule};
use sunrise_edge_client::*;

struct FakeTransport {
    responses: RefCell<VecDeque<WireResponse>>,
    requests: RefCell<Vec<WireRequest>>,
}
impl Transport for FakeTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        Ok(self.responses.borrow_mut().pop_front().unwrap())
    }
}
fn response(media_type: &str, body: Vec<u8>) -> WireResponse {
    WireResponse {
        status: 200,
        content_type: Some(media_type.to_owned()),
        body,
    }
}
fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        ChainId::new("paid-client-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([1; 32]).unwrap(),
    )
    .unwrap()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        expected().chain_id().clone(),
        expected().protocol_version(),
        expected().epoch(),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    local_publication_resolver(&expected()).unwrap()
}
fn signer() -> LocalSigner {
    LocalSigner::from_seed([7; 32])
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn origin() -> PackageOrigin {
    PackageOrigin::unverified(
        expected().chain_id().clone(),
        *signer().address().as_bytes(),
        [20; 32],
    )
    .unwrap()
}
fn code() -> UnverifiedDependencyRef {
    UnverifiedDependencyRef::new(origin(), 1, context(), digest(0x88)).unwrap()
}
fn fee_policy() -> PaidFeePolicy {
    let base = LocalExecutionPolicy::generic_object_results(context());
    PaidFeePolicy {
        context: context(),
        base_policy_digest: base.digest(&resolver()).unwrap(),
        instance: InstanceTarget {
            creator: *signer().address().as_bytes(),
            seed: [9; 32],
            revision: 1,
            record_digest: digest(9),
        },
        code: code(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![],
        asset_type: package_types::ScopedTypeTag::new(origin(), 2, vec![]).unwrap(),
        reservation_type: package_types::ScopedTypeTag::new(origin(), 4, vec![]).unwrap(),
        schema: 1,
        fee_recipient: *signer().address().as_bytes(),
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
fn artifact() -> CodeArtifact {
    CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: PackageOrigin::unverified(
            expected().chain_id().clone(),
            *signer().address().as_bytes(),
            [42; 32],
        )
        .unwrap(),
        revision: 1,
        wasm_profile: 4,
        semantics: digest(0x77),
        wasm: vec![0, 97, 115, 109],
        unverified_abi: vec![1, 2, 3],
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap()
}
fn consent() -> FeeSourceConsent {
    FeeSourceConsent {
        source: ObjectRef {
            id: ObjectId::new([0x30; 32]),
            version: 1,
            digest: digest(0x30),
        },
        access: ReservationAccessKind::Write,
        max_fee: Amount::new(1_000_000),
        refund_recipient: *signer().address().as_bytes(),
    }
}
fn context_result() -> Vec<u8> {
    HttpContextQueryResult::new(
        expected().chain_id().clone(),
        expected().protocol_version(),
        expected().epoch(),
        expected().hash_suite_id(),
        2,
        1,
        2,
        expected().domain(),
        vec![1],
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[test]
fn policy_query_checks_context_and_returns_exact_canonical_policy() {
    let policy: PaidFeePolicy = fee_policy();
    let client = Client::new(FakeTransport {
        responses: RefCell::new(VecDeque::from([
            response(QUERY_RESULT_MEDIA_TYPE, context_result()),
            response(
                QUERY_RESULT_MEDIA_TYPE,
                encode_paid_fee_policy(&policy).unwrap(),
            ),
        ])),
        requests: RefCell::new(Vec::new()),
    });
    assert_eq!(
        client
            .query_paid_fee_policy(&resolver(), &expected())
            .unwrap(),
        policy
    );
    assert_eq!(
        client.transport().requests.borrow()[1].path,
        PAID_FEE_POLICY_PATH
    );
}

#[test]
fn builder_binds_policy_quote_sender_and_signature() {
    let signed: SignedPaidIntent = build_signed_paid_execution(
        &signer(),
        &resolver(),
        &expected(),
        &fee_policy(),
        consent(),
        PaidApplication::Publish(artifact()),
        RequestId::new([3; 32]).unwrap(),
        4,
        100_000,
        vec![],
    )
    .unwrap();
    assert!(
        authenticate_paid_intent(
            &resolver(),
            &context(),
            &encode_signed_paid_intent(&signed).unwrap()
        )
        .is_ok()
    );
    assert_eq!(
        signed.intent.fee_policy_digest,
        paid_fee_policy_digest(&resolver(), &fee_policy()).unwrap()
    );
}

#[test]
fn submit_rejects_outer_status_or_target_mismatch() {
    let signed: SignedPaidIntent = build_signed_paid_execution(
        &signer(),
        &resolver(),
        &expected(),
        &fee_policy(),
        consent(),
        PaidApplication::Publish(artifact()),
        RequestId::new([3; 32]).unwrap(),
        4,
        100_000,
        vec![],
    )
    .unwrap();
    let result = PaidExecutionResult {
        request_id: signed.intent.request_id,
        kind: PaidResultKind::Publish,
        target: PaidResultTarget::Package(artifact().origin().clone()),
        status: PaidExecutionStatus::HostRejected,
        effects: ExecutionEffects {
            tx_hash: digest(0x55),
            status: ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.into(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 7,
        },
        charged: None,
    };
    let request_id: RequestId = RequestId::new(signed.intent.request_id).unwrap();
    let ack = NodeResponse::new(
        request_id,
        NodeResponseStatus::Accepted,
        Some(encode_paid_execution_result(&result).unwrap()),
    )
    .unwrap();
    let outer: Vec<u8> = HttpNodeResult::new(request_id, vec![ack])
        .unwrap()
        .encode()
        .unwrap();
    let client = Client::new(FakeTransport {
        responses: RefCell::new(VecDeque::from([response(NODE_RESULT_MEDIA_TYPE, outer)])),
        requests: RefCell::new(Vec::new()),
    });
    assert!(matches!(
        client.submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));
}
