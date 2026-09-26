//! Regressions exercise the production Client methods and mutation flow.
use super::*;
use crate::net::BudgetedTransport;
use crate::test_support::{FakeTransport, query_ok};
use crypto::SignatureSigner;
use std::cell::RefCell;
use sunrise_edge_client::*;

struct Fixture {
    directory: PathBuf,
    expected: ExpectedProtocolContext,
    resolver: HashSuiteResolver,
    manifest: node_core::genesis::GenesisManifest,
    signer: LocalSigner,
    signed: SignedPaidIntent,
    certifier: FastPathCertifier,
    record: local_execution::InstanceRecord,
}

impl Fixture {
    fn new() -> Self {
        let directory: PathBuf = super::tests::temp_path("boundaries");
        std::fs::create_dir(&directory).unwrap();
        let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
            ChainId::new("cli-network-boundaries").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(0),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
        )
        .unwrap();
        let resolver: HashSuiteResolver = local_publication_resolver(&expected).unwrap();
        let context: PublicationContext = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap();
        let signer: LocalSigner = LocalSigner::from_seed([0x21; 32]);
        let owner = sunrise_edge_devnet::DevOwner::new(*signer.address().as_bytes());
        let (manifest, metadata) =
            sunrise_edge_devnet::build_paid_genesis_manifest(&resolver, &context, &[owner], owner)
                .unwrap();
        let record: local_execution::InstanceRecord = local_execution::InstanceRecord {
            context: context.clone(),
            creator: metadata.instance.creator,
            seed: metadata.instance.seed,
            code: metadata.code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        };
        let request_id: [u8; 32] = [0x41; 32];
        let source: ObjectRef = ObjectRef {
            id: metadata.owner_coins[0].fee_coin,
            version: 1,
            digest: digest(0x42),
        };
        let intent: PaidIntent = PaidIntent {
            context: context.clone(),
            request_id,
            sender: *signer.address().as_bytes(),
            nonce: 0,
            fee_policy_digest: paid_fee_policy_digest(&resolver, &manifest.fee_policy).unwrap(),
            consent: FeeSourceConsent {
                source,
                access: ReservationAccessKind::Write,
                max_fee: Amount::new(100000),
                refund_recipient: *signer.address().as_bytes(),
            },
            application: PaidApplication::Call(call::CallIntent {
                context: context.clone(),
                request_id,
                sender: *signer.address().as_bytes(),
                nonce: 0,
                code: metadata.code,
                instance: metadata.instance,
                entrypoint: "transfer".to_owned(),
                type_arguments: Vec::new(),
                access: AccessManifest::new(),
                arguments: Vec::new(),
                gas_limit: 10000,
            }),
            gas_limit: 10000,
            authorizations: Vec::new(),
        };
        let signature: [u8; 64] = signer
            .sign_framed(
                &execution::paid_execution::paid_intent_signing_frame(&context, &intent).unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let signed: SignedPaidIntent = SignedPaidIntent { intent, signature };
        let authority: [u8; 32] = manifest.genesis_authority;
        let certifier: FastPathCertifier = FastPathCertifier::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            ValidatorSet::new(
                context.epoch(),
                vec![ValidatorInfo {
                    id: ValidatorId::new(authority),
                    voting_power: 1,
                    signature_scheme: SignatureSchemeId::Ed25519,
                    public_key: authority.to_vec(),
                }],
            )
            .unwrap(),
        )
        .unwrap();
        Self {
            directory,
            expected,
            resolver,
            manifest,
            signer,
            signed,
            certifier,
            record,
        }
    }
    fn path(&self, name: &str) -> String {
        self.directory.join(name).to_str().unwrap().to_owned()
    }
    fn parsed(&self, extra: &[(&'static str, &str)]) -> ParsedArgs {
        let mut specs = network_flag_specs();
        specs.extend([
            scalar("--submission"),
            scalar("--certificate"),
            scalar("--result-out"),
        ]);
        let args: Vec<OsString> = extra
            .iter()
            .flat_map(|(key, value)| [OsString::from(*key), OsString::from(*value)])
            .collect();
        parse_flags(args, &specs).unwrap()
    }
    fn context_body(&self) -> Vec<u8> {
        HttpContextQueryResult::new(
            self.expected.chain_id().clone(),
            self.expected.protocol_version(),
            self.expected.epoch(),
            self.expected.hash_suite_id(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
            vec![1],
        )
        .unwrap()
        .encode()
        .unwrap()
    }
    fn result(&self, status: PaidExecutionStatus) -> PaidExecutionResult {
        PaidExecutionResult {
            request_id: self.signed.intent.request_id,
            kind: PaidResultKind::Call,
            target: PaidResultTarget::Instance(self.record.clone()),
            status,
            effects: ExecutionEffects {
                tx_hash: execution::paid_execution::paid_invocation_digest(
                    &self.resolver,
                    &self.signed,
                )
                .unwrap(),
                status: if status == PaidExecutionStatus::Success {
                    ExecutionStatus::Success
                } else {
                    ExecutionStatus::Failure {
                        reason: local_execution::LOCAL_EXECUTION_TRAP_REASON.to_owned(),
                    }
                },
                object_effects: Vec::new(),
                events: Vec::new(),
                gas_used: 1,
            },
            charged: Some(PaidChargedOutcome {
                reserved: Amount::new(1),
                actual: Amount::new(1),
                refund: Amount::new(0),
                fee_output: self.signed.intent.consent.source.clone(),
                refund_output: None,
                reservation: ObjectId::new([0x49; 32]),
                application_gas_units: 1,
            }),
        }
    }
    fn endpoint(&self, result: &PaidExecutionResult) -> FastVoteEndpoint<FakeTransport> {
        let validator = VoteSigner(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let vote: FastVote = self
            .certifier
            .cast_vote(
                result.effects.tx_hash,
                digest(0x51),
                digest(0x52),
                &validator,
            )
            .unwrap();
        let request_id: RequestId = RequestId::new(self.signed.intent.request_id).unwrap();
        let ack: NodeResponse = NodeResponse::new(
            request_id,
            if result.status == PaidExecutionStatus::Success {
                NodeResponseStatus::Accepted
            } else {
                NodeResponseStatus::Rejected
            },
            Some(encode_paid_execution_result(result).unwrap()),
        )
        .unwrap();
        let responses = vec![
            Ok(WireResponse {
                status: 200,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body: encode_fast_vote(&vote).unwrap(),
            }),
            Ok(WireResponse {
                status: 200,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body: HttpNodeResult::new(request_id, vec![ack])
                    .unwrap()
                    .encode()
                    .unwrap(),
            }),
        ];
        FastVoteEndpoint {
            validator_id: validator.validator_id(),
            endpoint_label: "peer".to_owned(),
            client: Client::new(FakeTransport::new(responses)),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn budget() -> OperationBudget {
    OperationBudget {
        deadline: Instant::now().checked_add(Duration::from_secs(2)).unwrap(),
        per_request_cap: Duration::from_secs(1),
    }
}
struct VoteSigner(LocalSigner);
use consensus::ConsensusSigner;
impl ConsensusSigner for VoteSigner {
    fn validator_id(&self) -> ValidatorId {
        ValidatorId::new(*self.0.address().as_bytes())
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.0
            .sign_framed(framed)
            .map_err(|error| error.to_string())
    }
}

#[test]
fn production_queries_all_receive_one_shared_deadline_without_renewal() {
    let fixture: Fixture = Fixture::new();
    let source: ObjectId = fixture.signed.intent.consent.source.id;
    let object = fixture
        .manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == source)
        .unwrap()
        .object
        .clone();
    let canonical: Vec<u8> = objects::encode_object(&object).unwrap();
    let object_digest: Digest32 = fixture
        .resolver
        .hash_for_purpose(
            fixture.expected.epoch(),
            protocol_types::HashPurpose::Object,
            &canonical,
        )
        .unwrap();
    let object_result = HttpObjectQueryResult::CurrentInline {
        object_id: source,
        head_revision: runtime::ObjectHeadRevision::new(1).unwrap(),
        object_version: runtime::DurableObjectVersion::new(1).unwrap(),
        digest: object_digest,
        creating_chain_id: fixture.expected.chain_id().clone(),
        creating_protocol_version: fixture.expected.protocol_version(),
        canonical_object_bytes: canonical,
    };
    let transport: FakeTransport = FakeTransport::new(vec![
        query_ok(fixture.context_body()),
        query_ok(encode_paid_fee_policy(&fixture.manifest.fee_policy).unwrap()),
        query_ok(object_result.encode().unwrap()),
        query_ok(object_result.encode().unwrap()),
        query_ok(
            HttpNextNonceQueryResult::new(fixture.signer.address(), fixture.expected.epoch(), 0)
                .encode()
                .unwrap(),
        ),
        query_ok(fixture.context_body()),
        query_ok(
            encode_publication_query_result(&PublicationQueryResult::Legacy(
                fixture.manifest.publication.clone(),
            ))
            .unwrap(),
        ),
        query_ok(fixture.context_body()),
        query_ok(local_execution::encode_instance_record(&fixture.record).unwrap()),
    ]);
    // Put the shared deadline inside the request cap: every read must see
    // precisely this instant, even after preparation consumes some time.
    let shared: OperationBudget = OperationBudget {
        deadline: Instant::now().checked_add(Duration::from_secs(1)).unwrap(),
        per_request_cap: Duration::from_secs(2),
    };
    let client: Client<BudgetedTransport<'_, FakeTransport>> = Client::new(BudgetedTransport {
        inner: &transport,
        budget: Some(shared),
    });
    let policy: PaidFeePolicy = client
        .query_paid_fee_policy(&fixture.resolver, &fixture.expected)
        .unwrap();
    client.query_object(source).unwrap();
    let consent: FeeSourceConsent = FeeSourceConsent {
        source: ObjectRef {
            digest: object_digest,
            ..fixture.signed.intent.consent.source
        },
        ..fixture.signed.intent.consent.clone()
    };
    client
        .validate_paid_fee_source(
            &fixture.signer,
            &fixture.resolver,
            &fixture.expected,
            &policy,
            &consent,
        )
        .unwrap();
    client.query_next_nonce(fixture.signer.address()).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    client
        .query_paid_executable_interface(&fixture.record.code, &fixture.resolver, &fixture.expected)
        .unwrap();
    client
        .query_instance(
            fixture.record.creator,
            fixture.record.seed,
            &fixture.resolver,
            &fixture.expected,
        )
        .unwrap();
    let requests: Vec<WireRequest> = transport.requests();
    assert_eq!(requests.len(), 9);
    for request in requests {
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.deadline, Some(shared.deadline));
    }
}

#[test]
fn selected_peer_is_the_actual_preparation_transport_and_cap_is_applied() {
    let fixture: Fixture = Fixture::new();
    let endpoints: Vec<FastVoteEndpoint<FakeTransport>> = ["unused", "chosen"]
        .into_iter()
        .map(|label| FastVoteEndpoint {
            validator_id: ValidatorId::new([1; 32]),
            endpoint_label: label.to_owned(),
            client: Client::new(FakeTransport::new(vec![query_ok(fixture.context_body())])),
        })
        .collect();
    let selected: &Client<FakeTransport> =
        selected_preparation_client(&endpoints, "chosen").unwrap();
    let shared: OperationBudget = budget();
    let before: Instant = Instant::now();
    Client::new(BudgetedTransport {
        inner: selected.transport(),
        budget: Some(shared),
    })
    .query_context()
    .unwrap();
    assert!(endpoints[0].client.transport().requests().is_empty());
    let seen: Instant = endpoints[1].client.transport().requests()[0]
        .deadline
        .unwrap();
    assert!(seen <= shared.deadline);
    assert!(seen >= before.checked_add(shared.per_request_cap).unwrap());
    assert!(seen <= Instant::now().checked_add(shared.per_request_cap).unwrap());
    assert!(selected_preparation_client(&endpoints, "unrelated").is_err());
}

#[test]
fn elapsed_budget_refuses_before_first_production_query() {
    let transport: FakeTransport = FakeTransport::new(Vec::new());
    let shared: OperationBudget = OperationBudget {
        deadline: Instant::now(),
        per_request_cap: Duration::from_millis(20),
    };
    assert!(
        Client::new(BudgetedTransport {
            inner: &transport,
            budget: Some(shared)
        })
        .query_object(ObjectId::new([1; 32]))
        .is_err()
    );
    assert!(transport.requests().is_empty());
    assert!(shared.ensure_live().is_err());
}

struct SlowRead {
    calls: RefCell<Vec<WireRequest>>,
}
impl Transport for SlowRead {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        self.calls.borrow_mut().push(request.clone());
        std::thread::sleep(
            request
                .deadline
                .unwrap()
                .saturating_duration_since(Instant::now()),
        );
        Ok(WireResponse {
            status: 200,
            content_type: Some(QUERY_RESULT_MEDIA_TYPE.to_owned()),
            body: Vec::new(),
        })
    }
}
#[test]
fn slow_preparation_exhausts_budget_and_forbids_next_query_or_signing() {
    let fixture: Fixture = Fixture::new();
    let transport: SlowRead = SlowRead {
        calls: RefCell::new(Vec::new()),
    };
    let shared: OperationBudget = OperationBudget {
        deadline: Instant::now()
            .checked_add(Duration::from_millis(20))
            .unwrap(),
        per_request_cap: Duration::from_millis(30),
    };
    let client: Client<BudgetedTransport<'_, SlowRead>> = Client::new(BudgetedTransport {
        inner: &transport,
        budget: Some(shared),
    });
    assert!(
        client
            .query_paid_fee_policy(&fixture.resolver, &fixture.expected)
            .is_err()
    );
    assert!(client.query_next_nonce(fixture.signer.address()).is_err());
    assert!(
        shared.ensure_live().is_err(),
        "the production pre-signing guard must reject"
    );
    let requests = transport.calls.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].deadline, Some(shared.deadline));
    assert_eq!(requests[0].method, Method::Get);
}

#[cfg(unix)]
#[test]
fn paid_command_slow_http_preparation_uses_deadline_before_any_post_or_signing() {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    let fixture: Fixture = Fixture::new();
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint: String = listener.local_addr().unwrap().to_string();
    let context: Vec<u8> = fixture.context_body();
    let server = std::thread::spawn(move || {
        let accept_deadline: Instant = Instant::now().checked_add(Duration::from_secs(3)).unwrap();
        let mut stream: TcpStream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < accept_deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("test read peer did not receive preparation: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header: Vec<u8> = Vec::new();
        let mut byte: [u8; 1] = [0];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let response: String = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {QUERY_RESULT_MEDIA_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            context.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&context);
        String::from_utf8(header).unwrap()
    });
    let config: String = fixture.path("network");
    let manifest: String = fixture.path("manifest");
    let seed: String = fixture.path("seed");
    std::fs::write(
        &config,
        format!(
            "{} {endpoint} - -\n",
            encode_hex(&fixture.manifest.genesis_authority)
        ),
    )
    .unwrap();
    std::fs::write(
        &manifest,
        node_core::genesis::encode_genesis_manifest(&fixture.manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(&seed, "21".repeat(32)).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    let commitment: String = encode_hex(
        &node_core::genesis::genesis_manifest_commitment(&fixture.resolver, &fixture.manifest)
            .unwrap()
            .bytes(),
    );
    let intent: String = fixture.path("intent");
    let certificate: String = fixture.path("certificate");
    let error: String = super::super::paid_execution::run(
        "paid-call",
        [
            "--endpoint",
            &endpoint,
            "--seed-file",
            &seed,
            "--fastvote-network",
            &config,
            "--fastvote-genesis-manifest",
            &manifest,
            "--fastvote-expected-genesis-digest",
            &commitment,
            "--fastvote-signed-intent-out",
            &intent,
            "--fastvote-certificate-out",
            &certificate,
            "--fastvote-deadline-seconds",
            "1",
            "--fastvote-per-request-cap-seconds",
            "1",
            "--expected-chain-id",
            "cli-network-boundaries",
            "--expected-protocol-version",
            "3",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            &encode_hex(&[0x44; 32]),
        ]
        .into_iter()
        .map(OsString::from),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("deadline"),
        "the real preparation exchange must expire: {error}"
    );
    let received: String = server.join().unwrap();
    assert!(received.starts_with("GET /v1/context HTTP/1.1\r\n"));
    assert!(!Path::new(&intent).exists());
    assert!(!Path::new(&certificate).exists());
}

#[test]
fn network_submission_persists_exact_success_and_charged_trap_results() {
    for status in [
        PaidExecutionStatus::Success,
        PaidExecutionStatus::ApplicationFailed,
    ] {
        let fixture: Fixture = Fixture::new();
        let result: PaidExecutionResult = fixture.result(status);
        let endpoints = vec![fixture.endpoint(&result)];
        let intent = fixture.path("intent");
        let certificate = fixture.path("certificate");
        let output = fixture.path("result");
        let parsed: ParsedArgs = fixture.parsed(&[
            ("--fastvote-signed-intent-out", &intent),
            ("--fastvote-certificate-out", &certificate),
            ("--result-out", &output),
        ]);
        let shared: OperationBudget = OperationBudget {
            deadline: Instant::now().checked_add(Duration::from_secs(1)).unwrap(),
            per_request_cap: Duration::from_secs(2),
        };
        assert_eq!(
            run_network_submit(
                &parsed,
                &endpoints,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed,
                shared
            )
            .unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(&output).unwrap(),
            encode_paid_execution_result(&result).unwrap()
        );
        assert_eq!(
            std::fs::read(&intent).unwrap(),
            encode_signed_paid_intent(&fixture.signed).unwrap()
        );
        let cert: FastCertificate =
            decode_fast_certificate(&std::fs::read(&certificate).unwrap()).unwrap();
        assert_eq!(cert.tx_hash, result.effects.tx_hash);
        let requests = endpoints[0].client.transport().requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, FASTVOTE_PREPARE_PATH);
        assert_eq!(requests[1].path, FASTVOTE_CERTIFICATES_PATH);
        for request in requests {
            assert_eq!(request.deadline, Some(shared.deadline));
        }
    }
}

#[test]
fn all_network_outputs_reserve_before_any_post_existing_unwritable_or_alias() {
    let fixture: Fixture = Fixture::new();
    for failed in ["intent", "certificate", "result", "missing/result", "alias"] {
        let intent = fixture.path(&format!("{failed}-intent").replace('/', "-"));
        let certificate = fixture.path(&format!("{failed}-certificate").replace('/', "-"));
        let output = if failed == "missing/result" {
            fixture.path(failed)
        } else if failed == "alias" {
            format!(
                "{}/./{}",
                fixture.directory.display(),
                Path::new(&intent).file_name().unwrap().to_str().unwrap()
            )
        } else {
            fixture.path(&format!("{failed}-result"))
        };
        let existing = match failed {
            "intent" => Some(&intent),
            "certificate" => Some(&certificate),
            "result" => Some(&output),
            _ => None,
        };
        if let Some(path) = existing {
            std::fs::write(path, b"recovery").unwrap();
        }
        let endpoints = vec![fixture.endpoint(&fixture.result(PaidExecutionStatus::Success))];
        let parsed = fixture.parsed(&[
            ("--fastvote-signed-intent-out", &intent),
            ("--fastvote-certificate-out", &certificate),
            ("--result-out", &output),
        ]);
        assert!(
            run_network_submit(
                &parsed,
                &endpoints,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed,
                budget()
            )
            .is_err()
        );
        assert!(
            endpoints[0].client.transport().requests().is_empty(),
            "{failed} must refuse before prepare"
        );
        if let Some(path) = existing {
            assert_eq!(std::fs::read(path).unwrap(), b"recovery");
        }
    }
}

#[test]
fn replay_reserves_result_before_prepare_or_apply_and_detects_input_aliases() {
    let fixture = Fixture::new();
    let submission = fixture.path("submission");
    std::fs::write(
        &submission,
        encode_signed_paid_intent(&fixture.signed).unwrap(),
    )
    .unwrap();
    let result = fixture.result(PaidExecutionStatus::Success);
    let endpoint = fixture.endpoint(&result);
    let (cert, _) = collect_fastvote_certificate(
        std::slice::from_ref(&endpoint),
        &fixture.certifier,
        &fixture.resolver,
        &fixture.signed,
        budget().deadline,
        Duration::from_secs(1),
    )
    .unwrap();
    let cert_path = fixture.path("saved-cert");
    std::fs::write(&cert_path, encode_fast_certificate(&cert).unwrap()).unwrap();
    for supplied in [false, true] {
        for alias in [false, true] {
            let endpoints = vec![fixture.endpoint(&result)];
            let output = if alias {
                submission.clone()
            } else {
                fixture.path(&format!("result-{supplied}"))
            };
            if !alias {
                std::fs::write(&output, b"preserve").unwrap();
            }
            let cert_out = fixture.path(&format!("cert-{supplied}-{alias}"));
            let mut flags = vec![
                ("--submission", submission.as_str()),
                ("--result-out", output.as_str()),
            ];
            if supplied {
                flags.push(("--certificate", cert_path.as_str()));
            } else {
                flags.push(("--fastvote-certificate-out", cert_out.as_str()));
            }
            let parsed = fixture.parsed(&flags);
            assert!(
                replay_loaded(
                    &parsed,
                    &endpoints,
                    &fixture.certifier,
                    &fixture.resolver,
                    &fixture.signed,
                    supplied.then_some(&cert),
                    budget()
                )
                .is_err()
            );
            assert!(endpoints[0].client.transport().requests().is_empty());
        }
    }
}

#[test]
fn replay_explicit_missing_empty_truncated_corrupt_artifacts_fail_locally() {
    let fixture = Fixture::new();
    let submission = fixture.path("submission");
    let certificate = fixture.path("certificate");
    let valid: Vec<u8> = encode_signed_paid_intent(&fixture.signed).unwrap();
    std::fs::write(&submission, &valid).unwrap();
    let endpoint = fixture.endpoint(&fixture.result(PaidExecutionStatus::Success));
    let (cert, _) = collect_fastvote_certificate(
        std::slice::from_ref(&endpoint),
        &fixture.certifier,
        &fixture.resolver,
        &fixture.signed,
        budget().deadline,
        Duration::from_secs(1),
    )
    .unwrap();
    let certificate_bytes: Vec<u8> = encode_fast_certificate(&cert).unwrap();
    let mut corrupt_certificate: Vec<u8> = certificate_bytes.clone();
    corrupt_certificate[0] ^= 0xff;
    // No config/genesis flags: decoding the explicitly supplied artifact
    // must fail first, rather than silently switching to certificate collection.
    for bytes in [
        None,
        Some(Vec::new()),
        Some(certificate_bytes[..certificate_bytes.len() - 1].to_vec()),
        Some(corrupt_certificate),
    ] {
        if let Some(bytes) = bytes {
            std::fs::write(&certificate, bytes).unwrap();
        }
        let error = run_replay(
            ["--submission", &submission, "--certificate", &certificate]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(
            !error.contains("--expected-chain-id"),
            "must fail on the supplied certificate: {error}"
        );
    }
    for bytes in [
        Vec::new(),
        valid[..valid.len() - 1].to_vec(),
        vec![0xff; 80],
    ] {
        std::fs::write(&submission, bytes).unwrap();
        let error = run_replay(
            ["--submission", &submission]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(
            !error.contains("--expected-chain-id"),
            "must fail on submission before loading context: {error}"
        );
    }
}

#[test]
fn retained_output_handles_refuse_replaced_paths_and_preserve_recovery_bytes() {
    let fixture = Fixture::new();
    let output = fixture.path("result");
    let old = fixture.path("old");
    let mut artifacts = reserve_artifacts(&[(&output, "result")], &[]).unwrap();
    artifacts[0].persist(b"recovery").unwrap();
    std::fs::rename(&output, &old).unwrap();
    std::fs::write(&output, b"replacement").unwrap();
    assert!(artifacts[0].persist(b"new").is_err());
    assert_eq!(std::fs::read(&old).unwrap(), b"recovery");
    assert_eq!(std::fs::read(&output).unwrap(), b"replacement");
}

#[cfg(unix)]
#[test]
fn directory_sync_failure_is_a_hard_error_and_preserves_written_recovery_bytes() {
    let fixture: Fixture = Fixture::new();
    let output: String = fixture.path("recovery");
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    // This kernel handle supports writes but rejects fsync. Exercise the
    // exact production persistence helper, with a real failed syscall.
    let unsupported_directory: File = File::open("/dev/null").unwrap();
    assert!(persist_handles(&mut file, &unsupported_directory, b"exact recovery bytes").is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"exact recovery bytes");
}

#[test]
fn reservation_failure_keeps_prior_reserved_files_and_never_posts() {
    let fixture: Fixture = Fixture::new();
    let intent: String = fixture.path("intent");
    let certificate: String = fixture.path("certificate");
    let output: String = fixture.path("existing-result");
    std::fs::write(&output, b"prior recovery").unwrap();
    let parsed = fixture.parsed(&[
        ("--fastvote-signed-intent-out", &intent),
        ("--fastvote-certificate-out", &certificate),
        ("--result-out", &output),
    ]);
    let endpoints = vec![fixture.endpoint(&fixture.result(PaidExecutionStatus::Success))];
    assert!(
        run_network_submit(
            &parsed,
            &endpoints,
            &fixture.certifier,
            &fixture.resolver,
            &fixture.signed,
            budget()
        )
        .is_err()
    );
    assert!(endpoints[0].client.transport().requests().is_empty());
    assert_eq!(std::fs::read(&intent).unwrap(), b"");
    assert_eq!(std::fs::read(&certificate).unwrap(), b"");
    assert_eq!(std::fs::read(&output).unwrap(), b"prior recovery");
}

#[test]
fn result_failure_after_ack_names_exact_replay_and_preserves_saved_artifacts() {
    let fixture = Fixture::new();
    let output = fixture.path("result");
    let recovery = fixture.path("held-result");
    let mut artifact = reserve_artifacts(&[(&output, "result")], &[])
        .unwrap()
        .remove(0);
    std::fs::rename(&output, &recovery).unwrap();
    std::fs::write(&output, b"replacement").unwrap();
    let result: PaidExecutionResult = fixture.result(PaidExecutionStatus::ApplicationFailed);
    let error: String = persist_result(Some(&mut artifact), &result, &fixture.signed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("validated paid outcome received"));
    assert!(error.contains("recover the exact result bytes"));
    assert!(error.contains("nonce=0"));
    assert!(error.contains("do not retry with a fresh nonce"));
    assert_eq!(std::fs::read(&output).unwrap(), b"replacement");
    assert!(Path::new(&recovery).exists());
}

#[test]
fn invalid_network_budgets_and_flags_fail_before_missing_seed_or_artifacts() {
    for (flag, value) in [
        ("--fastvote-deadline-seconds", "0"),
        ("--fastvote-deadline-seconds", "18446744073709551615"),
        ("--fastvote-deadline-seconds", "3601"),
        ("--fastvote-per-request-cap-seconds", "0"),
        ("--fastvote-per-request-cap-seconds", "301"),
        ("--fastvote-per-request-cap-seconds", "18446744073709551615"),
        ("--fastvote-per-request-cap-seconds", "61"),
    ] {
        let error = super::super::paid_execution::run(
            "paid-call",
            [
                "--fastvote-network",
                "/missing-config",
                "--seed-file",
                "/missing-seed",
                flag,
                value,
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("positive") || error.contains("at most"),
            "{error}"
        );
        let replay_error = run_replay(
            [flag, value, "--submission", "/missing-artifact"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(
            replay_error.contains("positive") || replay_error.contains("at most"),
            "{replay_error}"
        );
    }
    for flag in [
        "--fastvote-deadline-seconds",
        "--fastvote-per-request-cap-seconds",
    ] {
        let error = run_replay(
            [
                flag,
                "18446744073709551616",
                "--submission",
                "/missing-artifact",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(flag),
            "integer overflow must fail during flag parsing: {error}"
        );
    }
    for (flag, value, reason) in [
        ("--tls-server-name", "peer.example", "global TLS"),
        ("--tls-ca-cert-der-file", "/missing-ca", "global TLS"),
        ("--submission-out", "/output", "--submission-out"),
    ] {
        let error = super::super::paid_execution::run(
            "paid-call",
            [
                "--fastvote-network",
                "/missing-config",
                "--seed-file",
                "/missing-seed",
                flag,
                value,
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(reason), "{error}");
    }
}

#[cfg(unix)]
#[test]
fn unwritable_and_symlink_aliased_outputs_refuse_before_prepare() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    let protected = fixture.path("protected");
    std::fs::create_dir(&protected).unwrap();
    std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o500)).unwrap();
    let link = fixture.path("link");
    symlink(&fixture.directory, &link).unwrap();
    for aliased in [false, true] {
        let intent = fixture.path(&format!("intent-{aliased}"));
        let certificate = fixture.path(&format!("cert-{aliased}"));
        let output = if aliased {
            format!("{link}/intent-{aliased}")
        } else {
            format!("{protected}/result")
        };
        let parsed = fixture.parsed(&[
            ("--fastvote-signed-intent-out", &intent),
            ("--fastvote-certificate-out", &certificate),
            ("--result-out", &output),
        ]);
        let endpoints = vec![fixture.endpoint(&fixture.result(PaidExecutionStatus::Success))];
        assert!(
            run_network_submit(
                &parsed,
                &endpoints,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed,
                budget()
            )
            .is_err()
        );
        assert!(endpoints[0].client.transport().requests().is_empty());
        assert!(!Path::new(&output).exists());
    }
    std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn replay_collect_and_saved_certificate_modes_persist_success_and_trap_bytes() {
    for status in [
        PaidExecutionStatus::Success,
        PaidExecutionStatus::ApplicationFailed,
    ] {
        let fixture = Fixture::new();
        let result = fixture.result(status);
        let submission = fixture.path("submission");
        std::fs::write(
            &submission,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let certificate = fixture.path("certificate");
        let collected_result = fixture.path("collected-result");
        let endpoints = vec![fixture.endpoint(&result)];
        let parsed = fixture.parsed(&[
            ("--submission", &submission),
            ("--fastvote-certificate-out", &certificate),
            ("--result-out", &collected_result),
        ]);
        assert_eq!(
            replay_loaded(
                &parsed,
                &endpoints,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed,
                None,
                budget()
            )
            .unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(&collected_result).unwrap(),
            encode_paid_execution_result(&result).unwrap()
        );
        let endpoints = vec![fixture.endpoint(&result)];
        let (cert, _) = collect_fastvote_certificate(
            &endpoints,
            &fixture.certifier,
            &fixture.resolver,
            &fixture.signed,
            budget().deadline,
            Duration::from_secs(1),
        )
        .unwrap();
        let saved_result = fixture.path("saved-result");
        let parsed = fixture.parsed(&[
            ("--submission", &submission),
            ("--certificate", &certificate),
            ("--result-out", &saved_result),
        ]);
        assert_eq!(
            replay_loaded(
                &parsed,
                &endpoints,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed,
                Some(&cert),
                budget()
            )
            .unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(&saved_result).unwrap(),
            encode_paid_execution_result(&result).unwrap()
        );
        assert_eq!(
            endpoints[0]
                .client
                .transport()
                .requests()
                .last()
                .unwrap()
                .path,
            FASTVOTE_CERTIFICATES_PATH
        );
    }
}

#[test]
fn replay_irrelevant_or_ambiguous_outputs_reject_before_any_artifact_read() {
    let error = run_replay(
        [
            "--submission",
            "/missing-input",
            "--fastvote-signed-intent-out",
            "/unused-output",
        ]
        .into_iter()
        .map(OsString::from),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("unsupported for replay"));
    let error = run_replay(
        [
            "--submission",
            "/missing-input",
            "--certificate",
            "/missing-cert",
            "--fastvote-certificate-out",
            "/unused-output",
        ]
        .into_iter()
        .map(OsString::from),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("unsupported when replay supplies --certificate"));
}

#[test]
fn remote_cohort_with_unrelated_loopback_read_peer_refuses_before_seed_read() {
    let fixture = Fixture::new();
    let config = fixture.path("network");
    std::fs::write(
        &config,
        format!(
            "{} 203.0.113.1:9443 peer.example /missing-ca\n",
            encode_hex(&fixture.manifest.genesis_authority)
        ),
    )
    .unwrap();
    let error = super::super::paid_execution::run(
        "paid-call",
        [
            "--fastvote-network",
            &config,
            "--endpoint",
            "127.0.0.1:9001",
            "--seed-file",
            "/deliberately-missing-seed",
            "--expected-chain-id",
            "cli-network-boundaries",
            "--expected-protocol-version",
            "3",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            &encode_hex(&[0x44; 32]),
            "--fastvote-signed-intent-out",
            &fixture.path("intent"),
            "--fastvote-certificate-out",
            &fixture.path("cert"),
        ]
        .into_iter()
        .map(OsString::from),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("exact endpoint_label"), "{error}");
}
