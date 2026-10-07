use std::cell::RefCell;
use std::collections::VecDeque;

use execution::call::{CallIntent, InstanceTarget};
use execution::local_execution::{
    InstanceRecord, LOCAL_EXECUTION_TRAP_REASON, LocalExecutionPolicy, instance_target,
};
use execution::paid_execution::*;
use execution::publication::{ArtifactParts, CodeArtifact, PublicationContext};
use fees::{Amount, GasSchedule};
use sunrise_edge_client::*;

#[path = "support/acknowledgement.rs"]
mod acknowledgement;

#[path = "support/external_signer.rs"]
mod external_signer;

#[test]
fn prepared_paid_families_preserve_independent_original_bytes() {
    use crypto::SignatureSigner;
    use external_signer::{Behavior, TestSigner};
    let request_id: RequestId = RequestId::new([0x42; 32]).unwrap();
    let nonce: u64 = 4;
    let gas_limit: u64 = 100_000;
    let call: CallIntent = instantiate_call(*request_id.as_bytes(), nonce, gas_limit);
    for application in [
        PaidApplication::Call(call.clone()),
        PaidApplication::Instantiate(call),
        PaidApplication::Publish(artifact()),
    ] {
        let intent: PaidIntent = PaidIntent {
            context: context(),
            request_id: *request_id.as_bytes(),
            sender: *signer().address().as_bytes(),
            nonce,
            fee_policy_digest: paid_fee_policy_digest(&resolver(), &fee_policy()).unwrap(),
            consent: consent(),
            application: application.clone(),
            gas_limit,
            authorizations: vec![],
        };
        // Original raw construction is independent of every new SDK owner/wrapper.
        let frame: Vec<u8> = paid_intent_signing_frame(&context(), &intent).unwrap();
        let signature: [u8; 64] = signer().sign_framed(&frame).unwrap().try_into().unwrap();
        let original: Vec<u8> =
            encode_signed_paid_intent(&SignedPaidIntent { intent, signature }).unwrap();
        let external: TestSigner = TestSigner::new([7; 32], Behavior::Valid);
        let prepared = PreparedPaidExecution::prepare(
            signer().address(),
            &resolver(),
            &expected(),
            &fee_policy(),
            consent(),
            application.clone(),
            request_id,
            nonce,
            gas_limit,
            vec![],
        )
        .unwrap();
        assert_eq!(prepared.signable_frame(), frame);
        assert_eq!(prepared.fee_policy(), &fee_policy());
        let actual = prepared.sign_and_finalize_external(&external).unwrap();
        assert_eq!(encode_signed_paid_intent(&actual).unwrap(), original);
        assert_eq!(external.calls(), 1);
        let development = build_signed_paid_execution(
            &signer(),
            &resolver(),
            &expected(),
            &fee_policy(),
            consent(),
            application,
            request_id,
            nonce,
            gas_limit,
            vec![],
        )
        .unwrap();
        assert_eq!(encode_signed_paid_intent(&development).unwrap(), original);
    }
}

fn prepared_publish_with(
    policy: &PaidFeePolicy,
    consent: FeeSourceConsent,
    nonce: u64,
) -> Result<PreparedPaidExecution, Box<ClientError>> {
    PreparedPaidExecution::prepare(
        signer().address(),
        &resolver(),
        &expected(),
        policy,
        consent,
        PaidApplication::Publish(artifact()),
        RequestId::new([0x42; 32]).unwrap(),
        nonce,
        100_000,
        vec![],
    )
    .map_err(Box::new)
}

#[test]
fn prepared_paid_refuses_external_failures_and_changed_preimage() {
    use crypto::SignatureSigner;
    use external_signer::{Behavior, REFUSALS, TestSigner, expected_calls};
    for behavior in REFUSALS {
        let external = TestSigner::new([7; 32], behavior);
        let error = prepared_publish_with(&fee_policy(), consent(), 4)
            .unwrap()
            .sign_and_finalize_external(&external)
            .unwrap_err();
        assert!(!error.to_string().contains("secret-provider-failure-marker"));
        assert!(!format!("{error:?}").contains("secret-provider-failure-marker"));
        assert_eq!(external.calls(), expected_calls(behavior));
        // A local provider failure is never reported as a node acknowledgement mismatch.
        match behavior {
            Behavior::Short => assert!(matches!(
                error,
                ClientError::Crypto(crypto::CryptoError::InvalidSignatureLength(63))
            )),
            Behavior::Long => assert!(matches!(
                error,
                ClientError::Crypto(crypto::CryptoError::InvalidSignatureLength(65))
            )),
            _ => assert!(!matches!(
                error,
                ClientError::PaidExecutionAcknowledgementMismatch
            )),
        }
    }
    let original = prepared_publish_with(&fee_policy(), consent(), 4).unwrap();
    let signature: Vec<u8> = signer().sign_framed(original.signable_frame()).unwrap();
    let changed = prepared_publish_with(&fee_policy(), consent(), 5).unwrap();
    assert!(matches!(
        changed.finalize(signature),
        Err(ClientError::PaidExecution(
            PaidExecutionError::InvalidSignature
        ))
    ));
}

#[test]
fn prepared_paid_preserves_presign_refusals_and_postsign_quote_order() {
    use external_signer::{Behavior, TestSigner};
    let mut foreign_policy = fee_policy();
    foreign_policy.context = PublicationContext::new(
        expected().chain_id().clone(),
        expected().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let external: TestSigner = TestSigner::new([7; 32], Behavior::Valid);
    let foreign: Result<SignedPaidIntent, ClientError> =
        match prepared_publish_with(&foreign_policy, consent(), 4) {
            Ok(prepared) => prepared.sign_and_finalize_external(&external),
            Err(error) => Err(*error),
        };
    assert!(matches!(
        foreign,
        Err(ClientError::PaidExecution(
            PaidExecutionError::ContextMismatch
        ))
    ));
    assert_eq!(external.calls(), 0);
    // A structurally malformed fee policy is an original pre-sign refusal.
    let mut invalid_policy = fee_policy();
    invalid_policy.conversion_divisor = 0;
    let invalid: Result<SignedPaidIntent, ClientError> =
        match prepared_publish_with(&invalid_policy, consent(), 4) {
            Ok(prepared) => prepared.sign_and_finalize_external(&external),
            Err(error) => Err(*error),
        };
    assert!(invalid.is_err());
    assert_eq!(external.calls(), 0);
    // The original builder quoted only after signing/authentication. Preserve
    // that behavior for a structurally valid base pin or insufficient max_fee.
    for case in 0..2 {
        let mut policy = fee_policy();
        let mut source = consent();
        if case == 0 {
            policy.base_policy_digest = digest(0x12);
        } else {
            source.max_fee = Amount::new(1);
        }
        let external: TestSigner = TestSigner::new([7; 32], Behavior::Valid);
        let prepared = prepared_publish_with(&policy, source, 4).unwrap();
        assert!(prepared.sign_and_finalize_external(&external).is_err());
        assert_eq!(external.calls(), 1);
    }
}

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

fn instantiate_record() -> InstanceRecord {
    InstanceRecord {
        context: context(),
        creator: *signer().address().as_bytes(),
        seed: [0x62; 32],
        code: code(),
        revision: 1,
        initializer: "init".to_owned(),
    }
}
fn instantiate_call(request_id: [u8; 32], nonce: u64, gas_limit: u64) -> CallIntent {
    CallIntent {
        context: context(),
        request_id,
        sender: *signer().address().as_bytes(),
        nonce,
        code: code(),
        instance: instance_target(&resolver(), &instantiate_record()).unwrap(),
        entrypoint: "init".to_owned(),
        type_arguments: vec![],
        access: AccessManifest::new(),
        arguments: vec![],
        gas_limit,
    }
}
/// Builds the exact wire bytes for one acknowledged [`PaidExecutionResult`],
/// reused by every `submit_paid_execution` test so each only states the
/// `PaidExecutionResult` it wants acknowledged, not the outer
/// `NodeResponse`/`HttpNodeResult` wrapping boilerplate.
fn ack_response_bytes(result: &PaidExecutionResult, ack_status: NodeResponseStatus) -> Vec<u8> {
    let request_id: RequestId = RequestId::new(result.request_id).unwrap();
    let ack = NodeResponse::new(
        request_id,
        ack_status,
        Some(encode_paid_execution_result(result).unwrap()),
    )
    .unwrap();
    HttpNodeResult::new(request_id, vec![ack])
        .unwrap()
        .encode()
        .unwrap()
}
fn ack_client(
    result: &PaidExecutionResult,
    ack_status: NodeResponseStatus,
) -> Client<FakeTransport> {
    Client::new(FakeTransport {
        responses: RefCell::new(VecDeque::from([response(
            NODE_RESULT_MEDIA_TYPE,
            ack_response_bytes(result, ack_status),
        )])),
        requests: RefCell::new(Vec::new()),
    })
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
    let client: Client<FakeTransport> = ack_client(&result, NodeResponseStatus::Accepted);
    assert!(matches!(
        client.submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));
}

#[test]
fn submit_paid_execution_accepts_exact_publish_success_and_rejects_wrong_kind_or_origin() {
    let signed: SignedPaidIntent = build_signed_paid_execution(
        &signer(),
        &resolver(),
        &expected(),
        &fee_policy(),
        consent(),
        PaidApplication::Publish(artifact()),
        RequestId::new([6; 32]).unwrap(),
        5,
        100_000,
        vec![],
    )
    .unwrap();
    let success = PaidExecutionResult {
        request_id: signed.intent.request_id,
        kind: PaidResultKind::Publish,
        target: PaidResultTarget::Package(artifact().origin().clone()),
        status: PaidExecutionStatus::Success,
        effects: ExecutionEffects {
            tx_hash: digest(0x56),
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 5,
        },
        charged: Some(PaidChargedOutcome {
            reserved: Amount::new(10),
            actual: Amount::new(10),
            refund: Amount::new(0),
            fee_output: consent().source.clone(),
            refund_output: None,
            reservation: ObjectId::new([0x40; 32]),
            application_gas_units: 5,
        }),
    };
    assert_eq!(
        ack_client(&success, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver())
            .unwrap(),
        success
    );

    let id: RequestId = RequestId::new(signed.intent.request_id).unwrap();
    let payload: Vec<u8> = encode_paid_execution_result(&success).unwrap();
    for shape in acknowledgement::ACK_SHAPES {
        let client: Client<FakeTransport> = Client::new(FakeTransport {
            responses: RefCell::new(VecDeque::from([response(
                NODE_RESULT_MEDIA_TYPE,
                acknowledgement::acknowledgement_bytes(
                    id,
                    NodeResponseStatus::Accepted,
                    &payload,
                    shape,
                ),
            )])),
            requests: RefCell::new(Vec::new()),
        });
        let outcome: Result<PaidExecutionResult, ClientError> =
            client.submit_paid_execution(&signed, &resolver());
        match shape {
            acknowledgement::AckShape::Exact => assert_eq!(outcome.unwrap(), success),
            acknowledgement::AckShape::OuterMismatch => assert!(
                matches!(outcome, Err(ClientError::SubmitResponseRequestIdMismatch { expected, actual }) if expected == id && actual == RequestId::new([0xFA; 32]).unwrap())
            ),
            acknowledgement::AckShape::NestedMismatch => assert!(
                matches!(outcome, Err(ClientError::Contract(node_wire::HttpContractError::RequestMismatch { expected, actual })) if expected == id && actual == RequestId::new([0xFA; 32]).unwrap())
            ),
            _ => assert!(
                matches!(
                    outcome,
                    Err(ClientError::PaidExecutionAcknowledgementMismatch)
                ),
                "shape: {shape:?}"
            ),
        }
    }

    // Wrong kind: an otherwise wire-valid Instantiate/Instance
    // acknowledgement returned for a signed Publish intent.
    let mut wrong_kind: PaidExecutionResult = success.clone();
    wrong_kind.kind = PaidResultKind::Instantiate;
    wrong_kind.target = PaidResultTarget::Instance(instantiate_record());
    assert!(matches!(
        ack_client(&wrong_kind, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));

    // Wrong origin: a Publish acknowledgement naming a different package
    // than the exact artifact this intent signed.
    let mut wrong_origin: PaidExecutionResult = success.clone();
    wrong_origin.target = PaidResultTarget::Package(
        PackageOrigin::unverified(
            expected().chain_id().clone(),
            *signer().address().as_bytes(),
            [77; 32],
        )
        .unwrap(),
    );
    assert!(matches!(
        ack_client(&wrong_origin, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));
}

#[test]
fn submit_paid_execution_accepts_exact_instantiate_success_and_rejects_wrong_kind_or_instance() {
    let signed: SignedPaidIntent = build_signed_paid_execution(
        &signer(),
        &resolver(),
        &expected(),
        &fee_policy(),
        consent(),
        PaidApplication::Instantiate(instantiate_call([7; 32], 6, 100_000)),
        RequestId::new([7; 32]).unwrap(),
        6,
        100_000,
        vec![],
    )
    .unwrap();
    let success = PaidExecutionResult {
        request_id: signed.intent.request_id,
        kind: PaidResultKind::Instantiate,
        target: PaidResultTarget::Instance(instantiate_record()),
        status: PaidExecutionStatus::Success,
        effects: ExecutionEffects {
            tx_hash: digest(0x57),
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 5,
        },
        charged: Some(PaidChargedOutcome {
            reserved: Amount::new(10),
            actual: Amount::new(10),
            refund: Amount::new(0),
            fee_output: consent().source.clone(),
            refund_output: None,
            reservation: ObjectId::new([0x41; 32]),
            application_gas_units: 5,
        }),
    };
    assert_eq!(
        ack_client(&success, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver())
            .unwrap(),
        success
    );

    // Wrong kind: a Call-shaped acknowledgement (still validly paired with
    // an Instance target) returned for a signed Instantiate intent.
    let mut wrong_kind: PaidExecutionResult = success.clone();
    wrong_kind.kind = PaidResultKind::Call;
    assert!(matches!(
        ack_client(&wrong_kind, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));

    // Wrong instance: the acknowledged instance record derives a different
    // InstanceTarget than the exact call this intent signed.
    let mut wrong_instance: PaidExecutionResult = success.clone();
    let mut record: InstanceRecord = instantiate_record();
    record.seed = [0x99; 32];
    wrong_instance.target = PaidResultTarget::Instance(record);
    assert!(matches!(
        ack_client(&wrong_instance, NodeResponseStatus::Accepted)
            .submit_paid_execution(&signed, &resolver()),
        Err(ClientError::PaidExecutionAcknowledgementMismatch)
    ));
}
