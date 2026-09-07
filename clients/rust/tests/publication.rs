use std::cell::RefCell;
use std::collections::VecDeque;
use sunrise_edge_client::publication::{PublicationRequest, encode_publication_submission};
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
) -> Result<Option<PublicationSubmission>, ClientError> {
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
        encode_publication_submission(&submission).unwrap(),
    ));
    assert_eq!(
        query(&client, submission.request().artifact().origin()).unwrap(),
        Some(submission)
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
        encode_publication_submission(&other).unwrap(),
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
            encode_publication_submission(&submission).unwrap(),
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
        encode_publication_submission(&submission).unwrap(),
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
    let invalid: Client<FakeTransport> = client(response(
        200,
        "text/plain",
        encode_publication_submission(&submission).unwrap(),
    ));
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
            response(
                200,
                QUERY_RESULT_MEDIA_TYPE,
                encode_publication_submission(&submission).unwrap(),
            ),
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
        Some(submission)
    );
}

#[test]
fn wrong_remote_context_stops_before_publication_fetch() {
    let submission: PublicationSubmission = signed(2);
    let client: Client<FakeTransport> = client(response(
        200,
        QUERY_RESULT_MEDIA_TYPE,
        encode_publication_submission(&submission).unwrap(),
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
