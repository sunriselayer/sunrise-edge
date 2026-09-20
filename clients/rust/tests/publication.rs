use crypto::SignatureSigner;
use execution::call::InstanceTarget;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind, SignedPaidIntent,
    paid_intent_signing_frame,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use sunrise_edge_client::publication::{PublicationRequest, encode_publication_submission};
use sunrise_edge_client::*;

/// Wraps a legacy submission exactly as the server now serves it under
/// DR-0126's provenance-aware `PublicationQueryResult` framing.
fn legacy_query_body(submission: &PublicationSubmission) -> Vec<u8> {
    encode_publication_query_result(&PublicationQueryResult::Legacy(submission.clone())).unwrap()
}

/// Wraps a signed paid intent exactly as the server now serves it under
/// DR-0126's provenance-aware `PublicationQueryResult` framing.
fn paid_query_body(signed: &SignedPaidIntent) -> Vec<u8> {
    encode_publication_query_result(&PublicationQueryResult::Paid(signed.clone())).unwrap()
}

fn paid_signer() -> LocalSigner {
    LocalSigner::from_seed([7; 32])
}

fn paid_consent() -> FeeSourceConsent {
    FeeSourceConsent {
        source: ObjectRef {
            id: ObjectId::new([0x30; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x30; 32]),
        },
        access: ReservationAccessKind::Write,
        max_fee: Amount::new(1_000_000),
        refund_recipient: *paid_signer().address().as_bytes(),
    }
}

/// Signs a `PaidApplication::Publish` intent over the given artifact.
fn sign_paid_publish(request_id: [u8; 32], artifact: CodeArtifact) -> SignedPaidIntent {
    sign_paid_intent(PaidIntent {
        context: artifact.context().clone(),
        request_id,
        sender: *paid_signer().address().as_bytes(),
        nonce: 4,
        fee_policy_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
        consent: paid_consent(),
        application: PaidApplication::Publish(artifact),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

/// Signs a `PaidApplication::Call` intent, used only to prove a non-Publish
/// paid application kind is rejected by publication query authentication.
fn sign_paid_call(request_id: [u8; 32]) -> SignedPaidIntent {
    let call = execution::call::CallIntent {
        context: expected_context(),
        request_id,
        sender: *paid_signer().address().as_bytes(),
        nonce: 4,
        code: UnverifiedDependencyRef::new(
            PackageOrigin::unverified(
                expected().chain_id().clone(),
                *paid_signer().address().as_bytes(),
                [9; 32],
            )
            .unwrap(),
            1,
            expected_context(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
        )
        .unwrap(),
        instance: InstanceTarget {
            creator: *paid_signer().address().as_bytes(),
            seed: [1; 32],
            revision: 1,
            record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
        },
        entrypoint: "run".into(),
        type_arguments: vec![],
        access: AccessManifest::default(),
        arguments: vec![],
        gas_limit: 100_000,
    };
    sign_paid_intent(PaidIntent {
        context: expected_context(),
        request_id,
        sender: *paid_signer().address().as_bytes(),
        nonce: 4,
        fee_policy_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
        consent: paid_consent(),
        application: PaidApplication::Call(call),
        gas_limit: 100_000,
        authorizations: vec![],
    })
}

fn sign_paid_intent(intent: PaidIntent) -> SignedPaidIntent {
    let frame: Vec<u8> = paid_intent_signing_frame(&intent.context.clone(), &intent).unwrap();
    let signature_bytes: Vec<u8> = paid_signer().sign_framed(&frame).unwrap();
    let signature: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
    SignedPaidIntent { intent, signature }
}

fn expected_context() -> PublicationContext {
    let expected: ExpectedProtocolContext = expected();
    PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .unwrap()
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

fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        ChainId::new("test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([1; 32]).unwrap(),
    )
    .unwrap()
}
fn artifact(signer: &LocalSigner, seed: u8) -> CodeArtifact {
    let expected: ExpectedProtocolContext = expected();
    let wasm_hex: &str = "0061736d0100000001040160000003020100050401010102071002066d656d6f727902000372756e00000a040102000b";
    let wasm: Vec<u8> = (0..wasm_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&wasm_hex[i..i + 2], 16).unwrap())
        .collect();
    CodeArtifact::new(ArtifactParts {
        context: PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap(),
        origin: PackageOrigin::unverified(
            expected.chain_id().clone(),
            *signer.address().as_bytes(),
            [seed; 32],
        )
        .unwrap(),
        revision: 1,
        wasm_profile: 1,
        semantics: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
        wasm,
        unverified_abi: b"opaque-abi".to_vec(),
        exports: vec!["run".to_owned()],
        unverified_dependencies: vec![],
    })
    .unwrap()
}
fn signed(seed: u8) -> PublicationSubmission {
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    build_signed_publication(
        &signer,
        &local_publication_resolver(&expected()).unwrap(),
        &expected(),
        artifact(&signer, seed),
        3,
        RequestId::new([3; 32]).unwrap(),
    )
    .unwrap()
}
fn response(status: u16, media_type: &str, body: Vec<u8>) -> WireResponse {
    WireResponse {
        status,
        content_type: Some(media_type.to_owned()),
        body,
    }
}
fn client(response: WireResponse) -> Client<FakeTransport> {
    let expected: ExpectedProtocolContext = expected();
    let context: HttpContextQueryResult = HttpContextQueryResult::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        expected.hash_suite_id(),
        2,
        1,
        2,
        expected.domain(),
        vec![1],
    )
    .unwrap();
    Client::new(FakeTransport {
        responses: RefCell::new(VecDeque::from([
            self::response(200, QUERY_RESULT_MEDIA_TYPE, context.encode().unwrap()),
            response,
        ])),
        requests: RefCell::new(Vec::new()),
    })
}
#[allow(clippy::result_large_err)]
fn query(
    client: &Client<FakeTransport>,
    origin: &PackageOrigin,
) -> Result<Option<PublicationQueryResult>, ClientError> {
    client.query_publication(
        origin,
        &local_publication_resolver(&expected()).unwrap(),
        &expected(),
        &Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
    )
}

#[test]
fn verifies_signature_and_exact_selector_after_independent_context_check() {
    let submission: PublicationSubmission = signed(2);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        legacy_query_body(&submission),
    ));
    assert_eq!(
        query(&client, submission.request().artifact().origin()).unwrap(),
        Some(PublicationQueryResult::Legacy(submission))
    );
    let requests = client.transport().requests.borrow();
    assert_eq!(requests[0].path, "/v1/context");
    assert!(requests[1].path.ends_with(&"02".repeat(32)));
}

#[test]
fn rejects_another_validly_signed_origin() {
    let requested: PublicationSubmission = signed(2);
    let other: PublicationSubmission = signed(4);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        legacy_query_body(&other),
    ));
    assert!(matches!(
        query(&client, requested.request().artifact().origin()),
        Err(ClientError::PublicationQuerySelectorMismatch)
    ));
}

#[test]
fn rejects_tampered_request_id_signature_and_digest() {
    let original: PublicationSubmission = signed(2);
    let request: &PublicationRequest = original.request();
    let variants: Vec<PublicationSubmission> = vec![
        PublicationSubmission::new([4; 32], request.clone()).unwrap(),
        PublicationSubmission::new(
            *original.request_id(),
            PublicationRequest::new(
                request.artifact().clone(),
                request.nonce(),
                *request.artifact_digest(),
                [0; 64],
            ),
        )
        .unwrap(),
        PublicationSubmission::new(
            *original.request_id(),
            PublicationRequest::new(
                request.artifact().clone(),
                request.nonce(),
                Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
                *request.signature(),
            ),
        )
        .unwrap(),
    ];
    for submission in variants {
        let client: Client<FakeTransport> = client(response(
            200,
            QUERY_RESULT_MEDIA_TYPE,
            legacy_query_body(&submission),
        ));
        assert!(matches!(
            query(&client, original.request().artifact().origin()),
            Err(ClientError::Publication(_))
        ));
    }
}

#[test]
fn rejects_wrong_semantics_and_original_context() {
    let submission: PublicationSubmission = signed(2);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        legacy_query_body(&submission),
    ));
    assert!(matches!(
        client.query_publication(
            submission.request().artifact().origin(),
            &local_publication_resolver(&expected()).unwrap(),
            &expected(),
            &Digest32::new(HashAlgorithmId::Sha2_256, [9; 32])
        ),
        Err(ClientError::Publication(_))
    ));
    let other: ExpectedProtocolContext = ExpectedProtocolContext::new(
        ChainId::new("other").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([1; 32]).unwrap(),
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    assert!(
        build_signed_publication(
            &signer,
            &local_publication_resolver(&other).unwrap(),
            &other,
            artifact(&signer, 2),
            0,
            RequestId::new([1; 32]).unwrap()
        )
        .is_err()
    );
}

#[test]
fn absence_and_wrong_content_type_remain_distinct() {
    let submission: PublicationSubmission = signed(2);
    let absent: Client<FakeTransport> = client(response(404, "text/plain", vec![]));
    assert!(
        query(&absent, submission.request().artifact().origin())
            .unwrap()
            .is_none()
    );
    let invalid: Client<FakeTransport> =
        client(response(200, "text/plain", legacy_query_body(&submission)));
    assert!(matches!(
        query(&invalid, submission.request().artifact().origin()),
        Err(ClientError::UnexpectedContentType { .. })
    ));
}

#[test]
fn submit_sends_exact_frame_and_rejects_swapped_receipt_identity() {
    let submission: PublicationSubmission = signed(2);
    for request_id in [[3; 32], [9; 32]] {
        let id: RequestId = RequestId::new(request_id).unwrap();
        let result: HttpNodeResult = HttpNodeResult::new(
            id,
            vec![
                NodeResponse::new(
                    id,
                    NodeResponseStatus::Accepted,
                    Some(reference_bytes(&submission)),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let client: Client<FakeTransport> = Client::new(FakeTransport {
            responses: RefCell::new(VecDeque::from([response(
                200,
                NODE_RESULT_MEDIA_TYPE,
                result.encode().unwrap(),
            )])),
            requests: RefCell::new(Vec::new()),
        });
        let returned: Result<HttpNodeResult, ClientError> = client.submit_publication(&submission);
        if request_id == [3; 32] {
            assert_eq!(returned.unwrap(), result);
        } else {
            assert!(matches!(
                returned,
                Err(ClientError::SubmitResponseRequestIdMismatch { .. })
            ));
        }
        let requests = client.transport().requests.borrow();
        assert_eq!(requests[0].path, "/v1/contracts/publications");
        assert_eq!(
            requests[0].body,
            encode_publication_submission(&submission).unwrap()
        );
    }
}

fn reference_bytes(submission: &PublicationSubmission) -> Vec<u8> {
    let request: &PublicationRequest = submission.request();
    let artifact: &CodeArtifact = request.artifact();
    let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *request.artifact_digest(),
    )
    .unwrap();
    publication::encode_dependency_ref(&reference).unwrap()
}

#[test]
fn submit_rejects_missing_rejected_extra_or_wrong_reference_acknowledgements() {
    let submission: PublicationSubmission = signed(2);
    let id: RequestId = RequestId::new(*submission.request_id()).unwrap();
    let accepted: NodeResponse = NodeResponse::new(
        id,
        NodeResponseStatus::Accepted,
        Some(reference_bytes(&submission)),
    )
    .unwrap();
    let cases: Vec<Vec<NodeResponse>> = vec![
        vec![],
        vec![accepted.clone(), accepted],
        vec![
            NodeResponse::new(
                id,
                NodeResponseStatus::Rejected,
                Some(reference_bytes(&submission)),
            )
            .unwrap(),
        ],
        vec![NodeResponse::new(id, NodeResponseStatus::Accepted, None).unwrap()],
        vec![
            NodeResponse::new(
                id,
                NodeResponseStatus::Accepted,
                Some(reference_bytes(&signed(4))),
            )
            .unwrap(),
        ],
    ];
    for responses in cases {
        let result: HttpNodeResult = HttpNodeResult::new(id, responses).unwrap();
        let client: Client<FakeTransport> = Client::new(FakeTransport {
            responses: RefCell::new(VecDeque::from([response(
                200,
                NODE_RESULT_MEDIA_TYPE,
                result.encode().unwrap(),
            )])),
            requests: RefCell::new(Vec::new()),
        });
        assert!(matches!(
            client.submit_publication(&submission),
            Err(ClientError::PublicationSubmitAcknowledgementMismatch)
        ));
    }
}

#[test]
fn historical_query_uses_original_trust_after_active_context_verification() {
    let submission: PublicationSubmission = signed(2);
    let original: ExpectedProtocolContext = expected();
    let active: ExpectedProtocolContext = ExpectedProtocolContext::new(
        original.chain_id().clone(),
        original.protocol_version(),
        Epoch::new(1),
        original.hash_suite_id(),
        2,
        1,
        2,
        original.domain(),
    )
    .unwrap();
    let context: HttpContextQueryResult = HttpContextQueryResult::new(
        active.chain_id().clone(),
        active.protocol_version(),
        active.epoch(),
        active.hash_suite_id(),
        2,
        1,
        2,
        active.domain(),
        vec![1],
    )
    .unwrap();
    let client: Client<FakeTransport> = Client::new(FakeTransport {
        responses: RefCell::new(VecDeque::from([
            response(200, QUERY_RESULT_MEDIA_TYPE, context.encode().unwrap()),
            response(200, QUERY_RESULT_MEDIA_TYPE, legacy_query_body(&submission)),
        ])),
        requests: RefCell::new(Vec::new()),
    });
    let original_context: PublicationContext = PublicationContext::new(
        original.chain_id().clone(),
        original.protocol_version(),
        original.epoch(),
    )
    .unwrap();
    assert_eq!(
        client
            .query_publication_in_context(
                submission.request().artifact().origin(),
                &local_publication_resolver(&original).unwrap(),
                &active,
                &original_context,
                submission.request().artifact().semantics()
            )
            .unwrap(),
        Some(PublicationQueryResult::Legacy(submission))
    );
}

#[test]
fn wrong_remote_context_stops_before_publication_fetch() {
    let submission: PublicationSubmission = signed(2);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        legacy_query_body(&submission),
    ));
    let original: ExpectedProtocolContext = expected();
    let active: ExpectedProtocolContext = ExpectedProtocolContext::new(
        original.chain_id().clone(),
        original.protocol_version(),
        Epoch::new(1),
        original.hash_suite_id(),
        2,
        1,
        2,
        original.domain(),
    )
    .unwrap();
    assert!(matches!(
        client.query_publication(
            submission.request().artifact().origin(),
            &local_publication_resolver(&active).unwrap(),
            &active,
            submission.request().artifact().semantics()
        ),
        Err(ClientError::ProtocolContextMismatch(_))
    ));
    assert_eq!(client.transport().requests.borrow().len(), 1);
}

/// DR-0126: a paid Publish record is queryable only after the client
/// independently re-authenticates its exact stored `SignedPaidIntent` under
/// the explicitly supplied original resolver/context. No `PublicationSubmission`
/// exists for it and none is fabricated.
#[test]
fn a_paid_record_is_queryable_after_independent_reauthentication() {
    let signer: LocalSigner = paid_signer();
    let signed: SignedPaidIntent = sign_paid_publish([11; 32], artifact(&signer, 2));
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    let origin = artifact(&signer, 2).origin().clone();
    assert_eq!(
        query(&client, &origin).unwrap(),
        Some(PublicationQueryResult::Paid(signed))
    );
}

#[test]
fn a_paid_record_with_the_wrong_origin_is_rejected() {
    let signer: LocalSigner = paid_signer();
    let signed: SignedPaidIntent = sign_paid_publish([11; 32], artifact(&signer, 2));
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    // Query a different seed's origin than the one actually signed.
    let other_origin = artifact(&signer, 4).origin().clone();
    assert!(matches!(
        query(&client, &other_origin),
        Err(ClientError::PublicationQuerySelectorMismatch)
    ));
}

#[test]
fn a_paid_record_with_a_tampered_signature_is_rejected() {
    let signer: LocalSigner = paid_signer();
    let mut signed: SignedPaidIntent = sign_paid_publish([11; 32], artifact(&signer, 2));
    signed.signature[0] ^= 0xff;
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    let origin = artifact(&signer, 2).origin().clone();
    assert!(matches!(
        query(&client, &origin),
        Err(ClientError::PublicationQueryPaidAuthentication(_))
    ));
}

#[test]
fn a_paid_record_whose_intent_context_differs_from_the_supplied_original_context_is_rejected() {
    // A genuinely self-consistent signed intent (artifact context == intent
    // context, matching the actual signature), queried with a caller-supplied
    // original context/resolver at a different protocol version. This passes
    // `query_publication_with_semantics`'s own chain/epoch trust preconditions
    // but must fail `authenticate_paid_intent`'s internal context check.
    let signer: LocalSigner = paid_signer();
    let artifact_value: CodeArtifact = artifact(&signer, 2);
    let origin: PackageOrigin = artifact_value.origin().clone();
    let signed: SignedPaidIntent = sign_paid_publish([11; 32], artifact_value);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    let wrong_context: PublicationContext = PublicationContext::new(
        expected().chain_id().clone(),
        ProtocolVersion::new(2),
        expected().epoch(),
    )
    .unwrap();
    let wrong_resolver: HashSuiteResolver = HashSuiteResolver::new(
        expected().chain_id().clone(),
        ProtocolVersion::new(2),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    assert!(matches!(
        client.query_publication_in_context(
            &origin,
            &wrong_resolver,
            &expected(),
            &wrong_context,
            &Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
        ),
        Err(ClientError::PublicationQueryPaidAuthentication(_))
    ));
}

#[test]
fn a_paid_record_with_a_non_publish_application_is_rejected() {
    let signed: SignedPaidIntent = sign_paid_call([12; 32]);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    assert!(matches!(
        query(
            &client,
            &PackageOrigin::unverified(
                expected().chain_id().clone(),
                *paid_signer().address().as_bytes(),
                [9; 32]
            )
            .unwrap()
        ),
        Err(ClientError::PublicationQueryPaidApplicationKindMismatch)
    ));
}

#[test]
fn a_paid_record_with_the_wrong_semantics_is_rejected() {
    let signer: LocalSigner = paid_signer();
    let mut wrong_semantics_artifact: CodeArtifact = artifact(&signer, 2);
    wrong_semantics_artifact = CodeArtifact::new(execution::publication::ArtifactParts {
        context: wrong_semantics_artifact.context().clone(),
        origin: wrong_semantics_artifact.origin().clone(),
        revision: wrong_semantics_artifact.revision(),
        wasm_profile: wrong_semantics_artifact.wasm_profile(),
        semantics: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        wasm: wrong_semantics_artifact.wasm().to_vec(),
        unverified_abi: wrong_semantics_artifact.unverified_abi().to_vec(),
        exports: wrong_semantics_artifact.exports().to_vec(),
        unverified_dependencies: wrong_semantics_artifact.unverified_dependencies().to_vec(),
    })
    .unwrap();
    let signed: SignedPaidIntent = sign_paid_publish([11; 32], wrong_semantics_artifact);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        paid_query_body(&signed),
    ));
    let origin = artifact(&signer, 2).origin().clone();
    assert!(matches!(
        query(&client, &origin),
        Err(ClientError::Publication(_))
    ));
}

#[test]
fn malformed_oversized_and_trailing_query_frames_are_rejected() {
    let signer: LocalSigner = paid_signer();
    let origin = artifact(&signer, 2).origin().clone();

    // Malformed: not a canonical frame at all.
    let malformed: Client<FakeTransport> =
        client(response(200, QUERY_RESULT_MEDIA_TYPE, vec![0xff; 32]));
    assert!(matches!(
        query(&malformed, &origin),
        Err(ClientError::PublicationQueryResult(_))
    ));

    // Oversized: exceeds `MAX_PUBLICATION_QUERY_RESULT_BYTES` before any
    // frame decoding is attempted.
    let oversized: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        vec![0u8; node_core::publication::MAX_PUBLICATION_QUERY_RESULT_BYTES + 1],
    ));
    assert!(matches!(
        query(&oversized, &origin),
        Err(ClientError::PublicationQueryResult(_))
    ));

    // Trailing bytes appended after an otherwise well-formed frame.
    let signed: SignedPaidIntent = sign_paid_publish([11; 32], artifact(&signer, 2));
    let mut trailing: Vec<u8> = paid_query_body(&signed);
    trailing.push(0);
    let trailing_client: Client<FakeTransport> =
        client(response(200, QUERY_RESULT_MEDIA_TYPE, trailing));
    assert!(matches!(
        query(&trailing_client, &origin),
        Err(ClientError::PublicationQueryResult(_))
    ));
}
