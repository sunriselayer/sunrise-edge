use super::*;
use consensus::{ConsensusSigner, FrozenFrontierAccumulator};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::PublicationContext;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    SignatureSchemeId,
};
use std::{
    io,
    pin::Pin,
    sync::atomic::AtomicUsize,
    task::{Context, Poll},
};
use validator_set::{ValidatorInfo, ValidatorSet};

struct Signer {
    key: SigningKey,
    validator: ValidatorId,
}
impl ConsensusSigner for Signer {
    fn validator_id(&self) -> ValidatorId {
        self.validator
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.key.sign(bytes).to_bytes().to_vec())
    }
}
fn fixture() -> (Frontend, Signer) {
    let key: SigningKey = SigningKey::from([0x61; 32]);
    let public: [u8; 32] = VerificationKey::from(&key).into();
    let validator: ValidatorId = ValidatorId::new(public);
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
    )
    .unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        context.chain_id().clone(),
        context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let set: ValidatorSet = ValidatorSet::new(
        context.epoch(),
        vec![ValidatorInfo {
            id: validator,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public.to_vec(),
        }],
    )
    .unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x8a; 32]).unwrap();
    let mut query_config: protocol_config::ProtocolConfig =
        protocol_config::ProtocolConfig::genesis();
    query_config.protocol_version = context.protocol_version();
    query_config.transaction_auth_profile =
        Some(protocol_config::TransactionAuthProfile::ed25519_address_is_public_key());
    query_config.domain_placement = Some(
        protocol_config::DomainPlacementManifest::single_domain(1, domain, Epoch::new(0)).unwrap(),
    );
    let fast: FastPathCertifier = FastPathCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        set.clone(),
    )
    .unwrap();
    let availability: AvailabilityCertifier = AvailabilityCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        set.clone(),
    )
    .unwrap();
    let frontier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        set,
    )
    .unwrap();
    let executor: crate::NativeBlockingExecutor = crate::NativeBlockingExecutor::new(
        crate::NativeBlockingPolicy::new(std::num::NonZeroUsize::new(2).unwrap()),
    );
    (
        Frontend {
            socket: PathBuf::from("/nonexistent/certified-custody-test.sock"),
            worker_uid: 0,
            identity: Identity::new(validator, domain, [0x42; 32]),
            context,
            resolver,
            query_config,
            fast,
            availability,
            frontier,
            timeout: Duration::from_secs(2),
            end: Instant::now().checked_add(Duration::from_secs(10)).unwrap(),
            remaining: AtomicU64::new(512),
            executor,
        },
        Signer { key, validator },
    )
}
fn input(route: Route) -> Input {
    Input {
        route,
        selectors: vec![[1; 32]; route.spec().keys.len()],
        content_type: vec![NODE_EVENT_MEDIA_TYPE.as_bytes().to_vec()],
        encoding: Vec::new(),
        body: Vec::new(),
    }
}
fn output(body: Vec<u8>) -> Output {
    Output {
        status: 200,
        headers: vec![
            (
                b"content-type".to_vec(),
                NODE_RESULT_MEDIA_TYPE.as_bytes().to_vec(),
            ),
            (b"cache-control".to_vec(), b"no-store".to_vec()),
        ],
        body,
    }
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

#[test]
fn independent_literal_contract_matches_all_twenty_one_routes_and_liveness() {
    let rows: Vec<&str> = include_str!("../../../../adapters/shared/certified-route-contract.tsv")
        .lines()
        .filter(|line: &&str| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), 21);
    assert_eq!(Route::ALL.len(), 22);
    for row in rows {
        let fields: Vec<&str> = row.split('\t').collect();
        let route: Route = Route::ALL
            .into_iter()
            .find(|route: &Route| route.spec().path == fields[1])
            .unwrap();
        let spec: Spec = route.spec();
        assert_eq!(route.method().as_str(), fields[0]);
        assert_eq!(spec.request, fields[2].parse::<usize>().unwrap());
        assert_eq!(spec.response, fields[3].parse::<usize>().unwrap());
        assert_eq!(
            route.empty_success(),
            matches!(fields[4], "empty" | "result-or-empty")
        );
    }
    assert_eq!(Route::Live.spec().path, LIVENESS_PATH);
    assert_eq!(Route::Live.spec().request, 0);
    assert_eq!(Route::Live.spec().response, 0);
}
#[test]
fn private_codec_has_stable_vector_and_refuses_profiles_trailing_unknown_and_lengths() {
    let mut request: Input = input(Route::FrontierAdvance);
    request.content_type.clear();
    let bytes: Vec<u8> = request.encode().unwrap();
    assert_eq!(
        bytes,
        [b"SCFV\0\0\0\x01".as_slice(), &[8, 0, 0, 0, 0, 0, 0]].concat()
    );
    assert_eq!(Input::decode(&bytes).unwrap(), request);
    for route in Route::ALL {
        let request: Input = input(route);
        assert_eq!(Input::decode(&request.encode().unwrap()).unwrap(), request);
    }
    let mut changed: Vec<u8> = bytes.clone();
    changed.push(0);
    assert!(Input::decode(&changed).is_err());
    for offset in 0..PROFILE.len() {
        let mut changed: Vec<u8> = bytes.clone();
        changed[offset] ^= 1;
        assert!(Input::decode(&changed).is_err());
    }
    let mut changed: Vec<u8> = bytes.clone();
    changed[8] = 255;
    assert!(Input::decode(&changed).is_err());
    assert!(Input::decode(&[2, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    let mut too_large: Input = input(Route::FrontierAdvance);
    too_large.body = vec![0, 1];
    assert!(too_large.encode().is_err());
    let mut repeated: Input = input(Route::Retain);
    repeated.encoding = vec![b"identity".to_vec(), b"gzip".to_vec()];
    assert_eq!(
        Input::decode(&repeated.encode().unwrap()).unwrap(),
        repeated
    );
    repeated.content_type = vec![vec![0; MAX_HEADER + 1]];
    assert!(repeated.encode().is_err());
    let response: Output = output(vec![1, 2, 3]);
    assert_eq!(
        Output::decode(&response.encode().unwrap()).unwrap(),
        response
    );
    let mut wrong: Vec<u8> = response.encode().unwrap();
    wrong[0] = 2;
    assert!(Output::decode(&wrong).is_err());
}
#[test]
fn whole_publication_limit_is_admitted_and_one_extra_byte_is_refused() {
    let mut request: Input = input(Route::Retain);
    request.body = vec![0x41; consensus::bundle::MAX_ENCODED_BUNDLE_BYTES];
    let encoded: Vec<u8> = request.encode().unwrap();
    assert_eq!(
        Input::decode(&encoded).unwrap().body.len(),
        32 * 1024 * 1024
    );
    request.body.push(0);
    assert!(request.encode().is_err());
}
#[test]
fn independently_signed_frontier_output_rejects_changed_signature_endpoint_context_and_route() {
    let (frontend, signer): (Frontend, Signer) = fixture();
    let accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
        &frontend.resolver,
        frontend.context.chain_id().clone(),
        frontend.context.protocol_version(),
        frontend.context.epoch(),
        frontend.identity.domain,
        [0x21; 32],
        1,
    )
    .unwrap();
    let vote: consensus::FrozenFrontierVote = frontend
        .frontier
        .cast_vote(accumulator.identity().clone(), &signer)
        .unwrap();
    let request: Input = input(Route::FrontierAdvance);
    let mut response: Output = output(consensus::encode_frozen_frontier_vote(&vote).unwrap());
    frontend.verify(&request, &response).unwrap();
    let mut wrong: consensus::FrozenFrontierVote = vote.clone();
    wrong.signature[0] ^= 1;
    response.body = consensus::encode_frozen_frontier_vote(&wrong).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
    wrong = vote.clone();
    wrong.validator = ValidatorId::new([0x33; 32]);
    response.body = consensus::encode_frozen_frontier_vote(&wrong).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
    wrong = vote.clone();
    wrong.identity.domain = AtomicityDomainId::new([0x34; 32]).unwrap();
    response.body = consensus::encode_frozen_frontier_vote(&wrong).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
    response.body = consensus::encode_frozen_frontier_vote(&vote).unwrap();
    assert!(frontend.verify(&input(Route::Prepare), &response).is_err());
    response.headers[0].1 = b"text/plain".to_vec();
    assert!(frontend.verify(&request, &response).is_err());
}

struct PanicIfPolled;
impl hyper::body::Body for PanicIfPolled {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        panic!("ignored certified GET body must not be polled")
    }
}
struct ErrorIfPolled;
impl hyper::body::Body for ErrorIfPolled {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        Poll::Ready(Some(Err(io::Error::other("fixture body error"))))
    }
}
async fn image(response: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, MAX_CANONICAL_FRAME_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
}
fn request(path: &str, media: &str, encoding: &[&str], body: Body) -> Request<Body> {
    let mut request: Request<Body> = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, media)
        .body(body)
        .unwrap();
    for value in encoding {
        request.headers_mut().append(
            header::CONTENT_ENCODING,
            HeaderValue::from_str(value).unwrap(),
        );
    }
    request
}

#[tokio::test]
async fn actual_router_http_preflight_parity_precedes_worker_admission() {
    let (frontend, _): (Frontend, Signer) = fixture();
    let frontend: Arc<Frontend> = Arc::new(frontend);
    let direct: Router = crate::tests::certified_custody_test_router();
    let proxy: Router = frontend_router(frontend.clone());
    for route in Route::ALL
        .into_iter()
        .filter(|route: &Route| route.method() == Method::POST)
    {
        let path: String = route.path(&vec![[1; 32]; route.spec().keys.len()]).unwrap();
        for media in [NODE_EVENT_MEDIA_TYPE, "text/plain"] {
            for encoding in [
                vec![],
                vec!["identity"],
                vec!["gzip"],
                vec!["identity", "gzip"],
                vec!["identity", "identity"],
            ] {
                let body_len: usize = route.spec().request + 1;
                for body_kind in 0..3 {
                    let make = || match body_kind {
                        0 => Body::empty(),
                        1 => Body::from(vec![0; body_len]),
                        _ => Body::new(ErrorIfPolled),
                    };
                    let before: u64 = frontend.remaining.load(Ordering::Relaxed);
                    // Valid empty bodies and supported headers proceed into the real
                    // worker in the separate round-trip control, not this no-socket case.
                    if media == NODE_EVENT_MEDIA_TYPE
                        && encoding.iter().all(|value: &&str| *value == "identity")
                        && encoding.len() <= 1
                        && body_kind == 0
                    {
                        continue;
                    }
                    let expected = image(
                        direct
                            .clone()
                            .oneshot(request(&path, media, &encoding, make()))
                            .await
                            .unwrap(),
                    )
                    .await;
                    let actual = image(
                        proxy
                            .clone()
                            .oneshot(request(&path, media, &encoding, make()))
                            .await
                            .unwrap(),
                    )
                    .await;
                    assert_eq!(
                        actual, expected,
                        "{path} {media} {encoding:?} body={body_kind}"
                    );
                    assert_eq!(frontend.remaining.load(Ordering::Relaxed), before);
                }
            }
        }
    }
}

struct SocketFixture {
    directory: PathBuf,
    path: PathBuf,
}
impl SocketFixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "certified-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path: PathBuf = directory.join("worker.sock");
        Self { directory, path }
    }
}
impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.path);
        let _removed = std::fs::remove_dir(&self.directory);
    }
}
async fn own_uid() -> u32 {
    let (first, _second): (UnixStream, UnixStream) = UnixStream::pair().unwrap();
    first.peer_cred().unwrap().uid()
}

#[tokio::test]
async fn all_actual_router_routes_round_trip_and_ignored_get_bodies_and_methods_match() {
    let fixture: SocketFixture = SocketFixture::new();
    let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
    let (frontend, _): (Frontend, Signer) = self::fixture();
    let uid: u32 = own_uid().await;
    let identity: Identity = frontend.identity;
    let end: Instant = frontend.end;
    let mut frontend: Frontend = frontend;
    frontend.socket = fixture.path.clone();
    frontend.worker_uid = uid;
    let frontend: Arc<Frontend> = Arc::new(frontend);
    let proxy: Router = frontend_router(frontend.clone());
    let direct: Router = crate::tests::certified_custody_test_router();
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let server = serve_worker(
        listener,
        direct.clone(),
        identity,
        uid,
        512,
        512,
        Duration::from_secs(2),
        end,
        async {
            let _done = receiver.await;
        },
    );
    let client = async {
        for route in Route::ALL {
            let path: String = route.path(&vec![[1; 32]; route.spec().keys.len()]).unwrap();
            let path: String = format!("{path}?ignored=true");
            for method in [
                route.method(),
                if route.method() == Method::GET {
                    Method::HEAD
                } else {
                    Method::GET
                },
            ] {
                let make = || {
                    Request::builder()
                        .method(method.clone())
                        .uri(&path)
                        .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                        .body(if route.method() == Method::GET {
                            Body::new(PanicIfPolled)
                        } else {
                            Body::from(vec![0xaa])
                        })
                        .unwrap()
                };
                let expected = image(direct.clone().oneshot(make()).await.unwrap()).await;
                let actual = image(proxy.clone().oneshot(make()).await.unwrap()).await;
                assert_eq!(actual, expected, "{method} {path}");
            }
        }
        for path in [
            "/v1/objects/not-hex",
            "/v1/objects/%FF",
            "/v1/receipts/0000000000000000000000000000000000000000000000000000000000000000",
            "/v1/contracts/publications/not-hex/also-not-hex",
            "/v1/contracts/instances/%FF/abc",
        ] {
            let make = || {
                Request::builder()
                    .uri(path)
                    .body(Body::new(PanicIfPolled))
                    .unwrap()
            };
            let before: u64 = frontend.remaining.load(Ordering::Relaxed);
            assert_eq!(
                image(proxy.clone().oneshot(make()).await.unwrap()).await,
                image(direct.clone().oneshot(make()).await.unwrap()).await,
                "{path}"
            );
            assert_eq!(before, frontend.remaining.load(Ordering::Relaxed));
        }
        sender.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let (result, ()) = tokio::join!(server, client);
        result.unwrap();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn liveness_is_local_and_worker_downtime_has_no_fallback() {
    let (frontend, _): (Frontend, Signer) = fixture();
    let frontend: Arc<Frontend> = Arc::new(frontend);
    let router: Router = frontend_router(frontend.clone());
    let before: u64 = frontend.remaining.load(Ordering::Relaxed);
    let response: Response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(LIVENESS_PATH)
                .body(Body::new(PanicIfPolled))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(frontend.remaining.load(Ordering::Relaxed), before);
    let response: Response = router
        .oneshot(
            Request::builder()
                .uri(QUERY_CONTEXT_PATH)
                .body(Body::new(PanicIfPolled))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(frontend.remaining.load(Ordering::Relaxed), before - 1);
}

fn signed_call(frontend: &Frontend) -> execution::paid_execution::SignedPaidIntent {
    use execution::paid_execution::{
        FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind, SignedPaidIntent,
    };
    let key: SigningKey = SigningKey::from([0x72; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    let context: PublicationContext = frontend.context.clone();
    let request_id: [u8; 32] = [0x73; 32];
    let intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id,
        sender,
        nonce: 1,
        fee_policy_digest: digest(0x11),
        consent: FeeSourceConsent {
            source: objects::ObjectRef {
                id: objects::ObjectId::new([0x22; 32]),
                version: 1,
                digest: digest(0x33),
            },
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1),
            refund_recipient: sender,
        },
        application: PaidApplication::Call(execution::call::CallIntent {
            context: context.clone(),
            request_id,
            sender,
            nonce: 1,
            code: execution::publication::UnverifiedDependencyRef::new(
                abi::package_types::PackageOrigin::unverified(
                    context.chain_id().clone(),
                    sender,
                    [0x44; 32],
                )
                .unwrap(),
                1,
                context.clone(),
                digest(0x45),
            )
            .unwrap(),
            instance: execution::call::InstanceTarget {
                creator: sender,
                seed: [0x46; 32],
                revision: 1,
                record_digest: digest(0x47),
            },
            entrypoint: "transfer".into(),
            type_arguments: Vec::new(),
            access: abi::AccessManifest::new(),
            arguments: Vec::new(),
            gas_limit: 1,
        }),
        gas_limit: 1,
        authorizations: Vec::new(),
    };
    let bytes: Vec<u8> =
        execution::paid_execution::paid_intent_signing_frame(&context, &intent).unwrap();
    SignedPaidIntent {
        intent,
        signature: key.sign(&bytes).into(),
    }
}
#[test]
fn real_fastvote_output_binds_exact_authenticated_intent_and_registered_endpoint() {
    let (frontend, signer): (Frontend, Signer) = fixture();
    let signed: execution::paid_execution::SignedPaidIntent = signed_call(&frontend);
    let mut request: Input = input(Route::Prepare);
    request.body = execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let tx: Digest32 =
        execution::paid_execution::paid_invocation_digest(&frontend.resolver, &signed).unwrap();
    let vote: consensus::FastVote = frontend
        .fast
        .cast_vote(tx, digest(0x75), digest(0x76), &signer)
        .unwrap();
    let mut response: Output = output(consensus::encode_fast_vote(&vote).unwrap());
    frontend.verify(&request, &response).unwrap();
    let wrong_tx: consensus::FastVote = frontend
        .fast
        .cast_vote(digest(0x74), digest(0x75), digest(0x76), &signer)
        .unwrap();
    response.body = consensus::encode_fast_vote(&wrong_tx).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
    let mut wrong: consensus::FastVote = vote.clone();
    wrong.signature[0] ^= 1;
    response.body = consensus::encode_fast_vote(&wrong).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
    response.body = consensus::encode_fast_vote(&vote).unwrap();
    let mut wrong: execution::paid_execution::SignedPaidIntent = signed;
    wrong.signature[0] ^= 1;
    request.body = execution::paid_execution::encode_signed_paid_intent(&wrong).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
}
#[test]
fn real_availability_ack_binds_complete_request_identity_and_endpoint_without_claiming_storage() {
    // This is an independently signed stateless response-binding fixture.
    // Its witness is not a claim of core closure, retention or commit success.
    use consensus::bundle::{ArtifactEntry, ArtifactKind, ArtifactManifest, PublicationBundle};
    let (frontend, signer): (Frontend, Signer) = fixture();
    let signed: execution::paid_execution::SignedPaidIntent = signed_call(&frontend);
    let signed_intent: Vec<u8> =
        execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
    let witness: Vec<u8> = b"unit witness; core closure is not asserted".to_vec();
    let content: Vec<u8> = b"complete unit artifact bytes".to_vec();
    let hash = |bytes: &[u8]| {
        frontend
            .resolver
            .hash_for_purpose(
                frontend.context.epoch(),
                protocol_types::HashPurpose::ExecutionEffects,
                bytes,
            )
            .unwrap()
    };
    let tx: Digest32 =
        execution::paid_execution::paid_invocation_digest(&frontend.resolver, &signed).unwrap();
    let vote: consensus::FastVote = frontend
        .fast
        .cast_vote(tx, hash(&witness), digest(0x76), &signer)
        .unwrap();
    let certificate: consensus::FastCertificate = frontend
        .fast
        .try_form_certificate(
            tx,
            hash(&witness),
            digest(0x76),
            &[vote],
            &Frontend::verifier(),
        )
        .unwrap()
        .unwrap();
    let bundle: PublicationBundle = PublicationBundle {
        domain: frontend.identity.domain,
        request_id: signed.intent.request_id,
        commitment_profile: consensus::bundle::LOGICAL_COMMITMENT_PROFILE,
        signed_intent,
        certificate,
        witness,
        manifest: ArtifactManifest {
            entries: vec![ArtifactEntry {
                kind: ArtifactKind::StateValue,
                identity: b"unit-key".to_vec(),
                content_digest: hash(&content),
                content_length: u32::try_from(content.len()).unwrap(),
            }],
        },
        contents: vec![content],
    };
    let identity: consensus::AvailabilityIdentity = consensus::bundle::verify_publication_bundle(
        &bundle,
        &frontend.fast,
        &Frontend::verifier(),
        &frontend.resolver,
        &[],
    )
    .unwrap()
    .identity;
    let ack: consensus::AvailabilityVote = frontend
        .availability
        .cast_vote(identity.clone(), &signer)
        .unwrap();
    let mut request: Input = input(Route::Retain);
    request.body = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let response: Output = output(consensus::encode_availability_vote(&ack).unwrap());
    frontend.verify(&request, &response).unwrap();
    let mut changed: consensus::AvailabilityVote = ack.clone();
    changed.signature[0] ^= 1;
    assert!(
        frontend
            .verify(
                &request,
                &output(consensus::encode_availability_vote(&changed).unwrap())
            )
            .is_err()
    );
    let mut changed: consensus::AvailabilityVote = ack.clone();
    changed.validator = ValidatorId::new([0x19; 32]);
    assert!(
        frontend
            .verify(
                &request,
                &output(consensus::encode_availability_vote(&changed).unwrap())
            )
            .is_err()
    );
    let mut changed: consensus::AvailabilityIdentity = identity;
    changed.semantic_artifacts_digest = digest(0x15);
    let changed: consensus::AvailabilityVote =
        frontend.availability.cast_vote(changed, &signer).unwrap();
    assert!(
        frontend
            .verify(
                &request,
                &output(consensus::encode_availability_vote(&changed).unwrap())
            )
            .is_err()
    );
    let mut changed: PublicationBundle = bundle;
    changed.contents[0][0] ^= 1;
    request.body = consensus::bundle::encode_publication_bundle(&changed).unwrap();
    assert!(frontend.verify(&request, &response).is_err());
}
#[tokio::test]
async fn exact_peer_uid_is_checked_before_request_prefix_or_dispatch() {
    let fixture: SocketFixture = SocketFixture::new();
    let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
    let uid: u32 = own_uid().await;
    let wrong_uid: u32 = uid.checked_add(1).unwrap();
    let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let counted: Arc<AtomicUsize> = calls.clone();
    let app: Router = Router::new().fallback(move || {
        let calls: Arc<AtomicUsize> = counted.clone();
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            StatusCode::OK
        }
    });
    let (frontend, _): (Frontend, Signer) = self::fixture();
    let end: Instant = Instant::now()
        .checked_add(Duration::from_millis(100))
        .unwrap();
    let server = serve_worker(
        listener,
        app,
        frontend.identity,
        wrong_uid,
        1,
        1,
        Duration::from_millis(20),
        end,
        tokio::time::sleep_until(end),
    );
    let client = async {
        let mut stream: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
        let mut byte: [u8; 1] = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        let (result, ()) = tokio::join!(server, client);
        result.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn frontend_authenticates_worker_before_writing_any_frame() {
    let fixture: SocketFixture = SocketFixture::new();
    let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
    let (mut frontend, _): (Frontend, Signer) = self::fixture();
    frontend.socket = fixture.path.clone();
    frontend.worker_uid = own_uid().await.checked_add(1).unwrap();
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte: [u8; 1] = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    };
    let client = async {
        assert!(frontend.exchange(&input(Route::Context)).await.is_err());
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

/// Consumes the pre-existing genuine ordered Freeze/frontier fixture, preserving
/// its original authority/signature oracles. This is transport coverage only.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assert_confirmed_round_trip(
    app: Router,
    root: &node_core::genesis::VerifiedGenesisRoot,
    validator: ValidatorId,
    domain: AtomicityDomainId,
    resolver: HashSuiteResolver,
    query_config: protocol_config::ProtocolConfig,
    cases: Vec<(&'static str, Vec<u8>, Vec<u8>)>,
) {
    let fixture: SocketFixture = SocketFixture::new();
    let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
    let uid: u32 = own_uid().await;
    let end: Instant = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
    let executor: crate::NativeBlockingExecutor = crate::NativeBlockingExecutor::new(
        crate::NativeBlockingPolicy::new(std::num::NonZeroUsize::new(1).unwrap()),
    );
    let frontend: Arc<Frontend> = Arc::new(
        Frontend::new(
            fixture.path.clone(),
            uid,
            validator,
            domain,
            root,
            resolver,
            query_config,
            Duration::from_secs(2),
            end,
            16,
            executor,
        )
        .unwrap(),
    );
    let identity: Identity = frontend.identity;
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = serve_worker(
        listener,
        app,
        identity,
        uid,
        16,
        16,
        Duration::from_secs(2),
        end,
        async {
            let _done = receiver.await;
        },
    );
    let client = async {
        frontend.preflight().await.unwrap();
        let proxy: Router = frontend_router(frontend);
        for (path, body, expected) in cases {
            let response: Response = proxy
                .clone()
                .oneshot(request(path, NODE_EVENT_MEDIA_TYPE, &[], Body::from(body)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                NODE_RESULT_MEDIA_TYPE
            );
            assert_eq!(
                to_bytes(response.into_body(), MAX_CANONICAL_FRAME_BYTES)
                    .await
                    .unwrap()
                    .as_ref(),
                expected.as_slice(),
                "{path}"
            );
        }
        sender.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let (result, ()) = tokio::join!(worker, client);
        result.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_profile_and_stalled_prefix_never_dispatch_to_the_owner() {
    for stalled in [false, true] {
        let fixture: SocketFixture = SocketFixture::new();
        let listener: UnixListener = UnixListener::bind(&fixture.path).unwrap();
        let uid: u32 = own_uid().await;
        let (frontend, _): (Frontend, Signer) = self::fixture();
        let end: Instant = Instant::now()
            .checked_add(Duration::from_millis(100))
            .unwrap();
        let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let counted: Arc<AtomicUsize> = calls.clone();
        let app: Router = Router::new().fallback(move || {
            let calls: Arc<AtomicUsize> = counted.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                StatusCode::OK
            }
        });
        let worker = serve_worker(
            listener,
            app,
            frontend.identity,
            uid,
            1,
            1,
            Duration::from_millis(20),
            end,
            tokio::time::sleep_until(end),
        );
        let client = async {
            let mut stream: UnixStream = UnixStream::connect(&fixture.path).await.unwrap();
            if !stalled {
                let old: Vec<u8> = vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
                stream
                    .write_u32(u32::try_from(old.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&old).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            let mut byte: [u8; 1] = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            let (result, ()) = tokio::join!(worker, client);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn historical_apply_keeps_exact_paid_binding_and_charged_failure_status() {
    use execution::paid_execution::{
        PaidApplication, PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus,
        PaidResultKind, PaidResultTarget, SignedPaidIntent,
    };
    for status in [
        PaidExecutionStatus::Success,
        PaidExecutionStatus::ApplicationFailed,
    ] {
        let (mut frontend, signer): (Frontend, Signer) = fixture();
        let mut signed: SignedPaidIntent = signed_call(&frontend);
        let mut call: execution::call::CallIntent = match &signed.intent.application {
            PaidApplication::Call(value) => value.clone(),
            _ => unreachable!(),
        };
        let record: execution::local_execution::InstanceRecord =
            execution::local_execution::InstanceRecord {
                context: call.context.clone(),
                creator: call.sender,
                seed: [0x46; 32],
                code: call.code.clone(),
                revision: 1,
                initializer: "init".into(),
            };
        call.instance =
            execution::local_execution::instance_target(&frontend.resolver, &record).unwrap();
        signed.intent.application = PaidApplication::Call(call);
        signed.signature = SigningKey::from([0x72; 32])
            .sign(
                &execution::paid_execution::paid_intent_signing_frame(
                    &signed.intent.context,
                    &signed.intent,
                )
                .unwrap(),
            )
            .into();
        let tx: Digest32 =
            execution::paid_execution::paid_invocation_digest(&frontend.resolver, &signed).unwrap();
        let vote: consensus::FastVote = frontend
            .fast
            .cast_vote(tx, digest(0x75), digest(0x76), &signer)
            .unwrap();
        let certificate: consensus::FastCertificate = frontend
            .fast
            .try_form_certificate(
                tx,
                digest(0x75),
                digest(0x76),
                &[vote],
                &Frontend::verifier(),
            )
            .unwrap()
            .unwrap();
        let signed_bytes: Vec<u8> =
            execution::paid_execution::encode_signed_paid_intent(&signed).unwrap();
        let mut request: Input = input(Route::Apply);
        request.body = FastVoteApplyRequest {
            signed_paid_intent: signed_bytes,
            certificate,
        }
        .encode()
        .unwrap();
        let result: PaidExecutionResult = PaidExecutionResult {
            request_id: signed.intent.request_id,
            kind: PaidResultKind::Call,
            target: PaidResultTarget::Instance(record),
            status,
            effects: execution::ExecutionEffects {
                tx_hash: tx,
                status: if status == PaidExecutionStatus::Success {
                    execution::ExecutionStatus::Success
                } else {
                    execution::ExecutionStatus::Failure {
                        reason: execution::local_execution::LOCAL_EXECUTION_TRAP_REASON.into(),
                    }
                },
                object_effects: Vec::new(),
                events: Vec::new(),
                gas_used: 1,
            },
            charged: Some(PaidChargedOutcome {
                reserved: fees::Amount::new(1),
                actual: fees::Amount::new(1),
                refund: fees::Amount::new(0),
                fee_output: signed.intent.consent.source.clone(),
                refund_output: None,
                reservation: objects::ObjectId::new([0x49; 32]),
                application_gas_units: 1,
            }),
        };
        let request_id: node_core::RequestId =
            node_core::RequestId::new(signed.intent.request_id).unwrap();
        let expected: node_core::NodeResponseStatus = if status == PaidExecutionStatus::Success {
            node_core::NodeResponseStatus::Accepted
        } else {
            node_core::NodeResponseStatus::Rejected
        };
        let encode = |result: &PaidExecutionResult, ack_status: node_core::NodeResponseStatus| {
            HttpNodeResult::new(
                request_id,
                vec![
                    node_core::NodeResponse::new(
                        request_id,
                        ack_status,
                        Some(
                            execution::paid_execution::encode_paid_execution_result(result)
                                .unwrap(),
                        ),
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
            .encode()
            .unwrap()
        };
        let response: Output = output(encode(&result, expected));
        frontend.verify(&request, &response).unwrap();
        frontend.context = PublicationContext::new(
            frontend.context.chain_id().clone(),
            frontend.context.protocol_version(),
            Epoch::new(frontend.context.epoch().get() + 1),
        )
        .unwrap();
        frontend.verify(&request, &response).unwrap();
        let mut changed: PaidExecutionResult = result.clone();
        changed.effects.tx_hash = digest(0x77);
        assert!(
            frontend
                .verify(&request, &output(encode(&changed, expected)))
                .is_err()
        );
        let wrong: node_core::NodeResponseStatus =
            if expected == node_core::NodeResponseStatus::Accepted {
                node_core::NodeResponseStatus::Rejected
            } else {
                node_core::NodeResponseStatus::Accepted
            };
        assert!(
            frontend
                .verify(&request, &output(encode(&result, wrong)))
                .is_err()
        );
        let mut changed: PaidExecutionResult = result;
        if let PaidResultTarget::Instance(record) = &mut changed.target {
            record.seed = [0x48; 32];
        }
        assert!(
            frontend
                .verify(&request, &output(encode(&changed, expected)))
                .is_err()
        );
    }
}
