//! Ordered, bounded exact-artifact replay (DR-0150). This does not establish
//! complete state, global finality, or an atomic batch. Every pair authenticates
//! before outputs are reserved, and every output reserves before any POST.
use super::*;
use sunrise_edge_client::{
    FastPathEd25519Verifier, HashSuiteResolver, PaidApplication, PublicationContext,
    authenticate_paid_intent, paid_invocation_digest,
};

const MAX_ENTRIES: usize = 16;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 4096;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

const HELP: &str = "contract fastvote-catch-up --manifest FILE --result-dir EXISTING_DIRECTORY
  --expected-chain-id CHAIN --expected-protocol-version VERSION --expected-epoch EPOCH
  --expected-hash-suite-id SUITE --expected-domain DOMAIN_HEX
  --fastvote-network CONFIG --fastvote-genesis-manifest FILE
  --fastvote-expected-genesis-digest DIGEST_HEX
  [--fastvote-deadline-seconds SECONDS] [--fastvote-per-request-cap-seconds SECONDS]
Manifest: UTF-8, one signed-intent-path certificate-path pair per line, in dependency order.
Blank lines and full-line # comments are ignored. Paths containing whitespace are unsupported.
Relative paths resolve against the manifest's canonical parent directory. Certificates are mandatory.
Limits: 16 pairs, 4096 bytes/line, 65536 manifest bytes, 16777216 combined artifact bytes.
Results: entry-0001-validator-<validator-id>.result and entry-0001.report (one-based indices).
All files must be fresh. A charged application trap is a committed outcome and allows the next entry.
A failed peer or differing acknowledgement stops subsequent entries; a prefix may already have committed.
Retry identical saved artifacts to fresh result files. HTTP acknowledgements do not prove global finality
or complete replica state. No signing, new nonce, voting, implicit certificates, or reordering occurs.";

pub(in crate::commands) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let specs: Vec<crate::args::FlagSpec> = [
        "--manifest",
        "--result-dir",
        "--expected-chain-id",
        "--expected-protocol-version",
        "--expected-epoch",
        "--expected-hash-suite-id",
        "--expected-domain",
        "--fastvote-network",
        "--fastvote-genesis-manifest",
        "--fastvote-expected-genesis-digest",
        "--fastvote-deadline-seconds",
        "--fastvote-per-request-cap-seconds",
    ]
    .into_iter()
    .map(scalar)
    .collect();
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    // One deadline includes all disk/config/authentication work, without renewal.
    let budget: OperationBudget = parse_deadline(&parsed)?;
    let expected = crate::commands::standard_asset::parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let (endpoints, certifier) = load_endpoints_and_certifier(&parsed, &resolver, &context)?;
    let batch: Batch = load_batch(
        parsed.require("--manifest")?,
        &resolver,
        &context,
        &certifier,
    )?;
    apply_batch(
        &batch,
        parsed.require("--result-dir")?,
        &endpoints,
        &certifier,
        &resolver,
        budget,
    )
}

struct Entry {
    signed: SignedPaidIntent,
    certificate: FastCertificate,
}
struct Batch {
    entries: Vec<Entry>,
    // Keep original input and parent handles held through the whole batch.
    inputs: Vec<ReservedArtifact>,
    original_bytes: Vec<Vec<u8>>,
}

impl Batch {
    fn ensure_inputs_unchanged(&self) -> Result<(), CliError> {
        use std::io::{Seek, SeekFrom};
        for (input, original) in self.inputs.iter().zip(&self.original_bytes) {
            input.ensure_attached()?;
            let mut file: File = input.file.try_clone().map_err(failure)?;
            file.seek(SeekFrom::Start(0)).map_err(failure)?;
            let limit: u64 = u64::try_from(original.len())
                .map_err(failure)?
                .checked_add(1)
                .ok_or_else(|| invalid("input length overflow"))?;
            let mut observed: Vec<u8> = Vec::new();
            Read::by_ref(&mut file)
                .take(limit)
                .read_to_end(&mut observed)
                .map_err(failure)?;
            if observed != *original {
                return Err(invalid(format!(
                    "saved {} input changed at {:?}; preserve the original exact artifact bytes",
                    input.kind, input.path
                )));
            }
            input.file.sync_all().map_err(failure)?;
            input.parent.sync_all().map_err(failure)?;
        }
        Ok(())
    }
}

fn add_input_bytes(current: usize, intent: usize, certificate: usize) -> Result<usize, CliError> {
    let combined: usize = current
        .checked_add(intent)
        .and_then(|value| value.checked_add(certificate))
        .ok_or_else(|| invalid("catch-up aggregate artifact length overflow"))?;
    if combined > MAX_ARTIFACT_BYTES {
        return Err(invalid("catch-up artifacts exceed 16777216 combined bytes"));
    }
    Ok(combined)
}

fn retained_input(
    path: &Path,
    maximum: usize,
    kind: &'static str,
) -> Result<(ReservedArtifact, Vec<u8>), CliError> {
    let path: PathBuf = path.canonicalize().map_err(failure)?;
    let mut file: File = File::open(&path).map_err(failure)?;
    if !file.metadata().map_err(failure)?.is_file() {
        return Err(invalid(format!(
            "{kind} input must be a regular file: {path:?}"
        )));
    }
    let parent: File = File::open(
        path.parent()
            .ok_or_else(|| invalid("input parent missing"))?,
    )
    .map_err(failure)?;
    let limit: u64 = u64::try_from(maximum)
        .map_err(failure)?
        .checked_add(1)
        .ok_or_else(|| invalid("input length bound overflow"))?;
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid(format!(
            "{kind} input exceeds the maximum accepted size: {path:?}"
        )));
    }
    let input: ReservedArtifact = ReservedArtifact {
        path,
        file,
        parent,
        kind,
    };
    input.ensure_attached()?;
    // Fail before POST if this filesystem cannot synchronize retained artifacts.
    input.file.sync_all().map_err(failure)?;
    input.parent.sync_all().map_err(failure)?;
    Ok((input, bytes))
}

fn load_batch(
    path: &str,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    certifier: &FastPathCertifier,
) -> Result<Batch, CliError> {
    let (manifest, bytes): (ReservedArtifact, Vec<u8>) =
        retained_input(Path::new(path), MAX_MANIFEST_BYTES, "manifest")?;
    let parent: PathBuf = manifest
        .path
        .parent()
        .ok_or_else(|| invalid("manifest parent missing"))?
        .to_owned();
    let text: &str =
        std::str::from_utf8(&bytes).map_err(|_| invalid("catch-up manifest must be UTF-8"))?;
    let mut inputs: Vec<ReservedArtifact> = vec![manifest];
    let mut original_bytes: Vec<Vec<u8>> = vec![bytes.clone()];
    let mut entries: Vec<Entry> = Vec::new();
    let mut request_ids: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut aggregate: usize = 0;
    for (line_index, raw_line) in text.lines().enumerate() {
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(invalid("catch-up manifest line exceeds 4096 bytes"));
        }
        let line: &str = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if entries.len() >= MAX_ENTRIES {
            return Err(invalid("catch-up manifest exceeds 16 pairs"));
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [signed_path, certificate_path] = fields.as_slice() else {
            return Err(invalid(format!(
                "catch-up manifest line {} needs exactly two paths; whitespace in paths is unsupported",
                line_index + 1
            )));
        };
        let (intent_input, signed_bytes) = retained_input(
            &parent.join(signed_path),
            sunrise_edge_client::MAX_SIGNED_PAID_INTENT_BYTES.min(
                MAX_ARTIFACT_BYTES
                    .checked_sub(aggregate)
                    .ok_or_else(|| invalid("aggregate input bound exceeded"))?,
            ),
            "signed-intent",
        )?;
        let (certificate_input, certificate_bytes) = retained_input(
            &parent.join(certificate_path),
            sunrise_edge_client::MAX_FASTVOTE_CERTIFICATE_BYTES.min(
                MAX_ARTIFACT_BYTES
                    .checked_sub(aggregate)
                    .and_then(|remaining| remaining.checked_sub(signed_bytes.len()))
                    .ok_or_else(|| invalid("aggregate input bound exceeded"))?,
            ),
            "certificate",
        )?;
        aggregate = add_input_bytes(aggregate, signed_bytes.len(), certificate_bytes.len())?;
        // Actual production authentication, independently pinned context, exact bytes.
        authenticate_paid_intent(resolver, context, &signed_bytes).map_err(failure)?;
        let signed: SignedPaidIntent = decode_signed_paid_intent(&signed_bytes).map_err(failure)?;
        if !matches!(signed.intent.application, PaidApplication::Call(_)) {
            return Err(invalid("catch-up supports only certified Call intents"));
        }
        if !request_ids.insert(signed.intent.request_id) {
            return Err(invalid("catch-up manifest contains duplicate request ids"));
        }
        let certificate: FastCertificate =
            decode_fast_certificate(&certificate_bytes).map_err(failure)?;
        certifier
            .verify_certificate(&certificate, &FastPathEd25519Verifier)
            .map_err(failure)?;
        if certificate.tx_hash != paid_invocation_digest(resolver, &signed).map_err(failure)? {
            return Err(invalid(
                "catch-up certificate does not certify the exact signed intent",
            ));
        }
        // The existing SDK apply path re-encodes these canonical frames. Refuse
        // any representation that would alter the original saved bytes.
        if encode_signed_paid_intent(&signed).map_err(failure)? != signed_bytes
            || encode_fast_certificate(&certificate).map_err(failure)? != certificate_bytes
        {
            return Err(invalid(
                "catch-up artifact is not the exact canonical encoding",
            ));
        }
        inputs.extend([intent_input, certificate_input]);
        original_bytes.extend([signed_bytes, certificate_bytes]);
        entries.push(Entry {
            signed,
            certificate,
        });
    }
    if entries.is_empty() {
        return Err(invalid("catch-up manifest needs at least one pair"));
    }
    Ok(Batch {
        entries,
        inputs,
        original_bytes,
    })
}

fn apply_batch<T: Transport>(
    batch: &Batch,
    directory: &str,
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    budget: OperationBudget,
) -> Result<(), CliError> {
    budget.ensure_live()?;
    batch.ensure_inputs_unchanged()?;
    validate_fastvote_endpoints(endpoints, certifier).map_err(failure)?;
    let directory: PathBuf = Path::new(directory).canonicalize().map_err(failure)?;
    if !directory.is_dir() {
        return Err(invalid("--result-dir must be an existing directory"));
    }
    let mut output_names: Vec<(String, &'static str)> = Vec::new();
    for index in 1..=batch.entries.len() {
        for endpoint in endpoints {
            output_names.push((
                directory
                    .join(format!(
                        "entry-{index:04}-validator-{}.result",
                        endpoint.validator_id
                    ))
                    .to_str()
                    .ok_or_else(|| invalid("result path must be UTF-8"))?
                    .to_owned(),
                "result",
            ));
        }
        output_names.push((
            directory
                .join(format!("entry-{index:04}.report"))
                .to_str()
                .ok_or_else(|| invalid("result path must be UTF-8"))?
                .to_owned(),
            "report",
        ));
    }
    let outputs: Vec<(&str, &'static str)> = output_names
        .iter()
        .map(|(path, kind)| (path.as_str(), *kind))
        .collect();
    let input_paths: Vec<&str> = batch
        .inputs
        .iter()
        .map(|input| {
            input
                .path
                .to_str()
                .ok_or_else(|| invalid("input path must be UTF-8"))
        })
        .collect::<Result<Vec<&str>, CliError>>()?;
    let mut artifacts: Vec<ReservedArtifact> = reserve_artifacts(&outputs, &input_paths)?;
    let stride: usize = endpoints
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid("result count overflow"))?;
    for artifact in batch.inputs.iter().chain(&artifacts) {
        artifact.ensure_attached()?;
    }
    for (offset, entry) in batch.entries.iter().enumerate() {
        batch
            .ensure_inputs_unchanged()
            .map_err(|error| stopped(offset, &error))?;
        budget
            .ensure_live()
            .map_err(|error| stopped(offset, &error))?;
        for artifact in batch.inputs.iter().chain(&artifacts) {
            artifact
                .ensure_attached()
                .map_err(|error| stopped(offset, &error))?;
        }
        let index: usize = offset + 1;
        println!(
            "catch_up_entry={index} request_id={} nonce={}",
            encode_hex(&entry.signed.intent.request_id),
            entry.signed.intent.nonce
        );
        let attempts = apply_fastvote_to_all(
            endpoints,
            certifier,
            &entry.signed,
            resolver,
            &entry.certificate,
            budget.deadline,
            budget.per_request_cap,
        )
        .map_err(|error| stopped(offset, &error))?;
        let mut report: String = format!(
            "entry={index}\nrequest_id={}\nnonce={}\nacknowledgements=unsigned_not_global_finality\n",
            encode_hex(&entry.signed.intent.request_id),
            entry.signed.intent.nonce
        );
        let mut all_received: bool = true;
        let mut first_bytes: Option<Vec<u8>> = None;
        for (peer_index, attempt) in attempts.iter().enumerate() {
            match &attempt.result {
                Ok(result) => {
                    let bytes: Vec<u8> = sunrise_edge_client::encode_paid_execution_result(result)
                        .map_err(failure)?;
                    if let Some(first) = &first_bytes {
                        all_received &= first == &bytes;
                    } else {
                        first_bytes = Some(bytes.clone());
                    }
                    all_received &= matches!(
                        result.status,
                        PaidExecutionStatus::Success | PaidExecutionStatus::ApplicationFailed
                    ) && result.charged.is_some();
                    let artifact_index: usize = offset
                        .checked_mul(stride)
                        .and_then(|value| value.checked_add(peer_index))
                        .ok_or_else(|| invalid("result index overflow"))?;
                    artifacts[artifact_index]
                        .persist(&bytes)
                        .map_err(|error| stopped(offset, &error))?;
                    report.push_str(&format!(
                        "validator={} status=received paid_status={:?}\n",
                        attempt.validator_id, result.status
                    ));
                }
                Err(error) => {
                    all_received = false;
                    let (reason, _) = crate::output::bounded_sanitized_line(&error.to_string());
                    report.push_str(&format!(
                        "validator={} status=failed reason={reason}\n",
                        attempt.validator_id
                    ));
                    print_repin_diagnostic(error);
                }
            }
        }
        report.push_str(&format!(
            "all_configured_acknowledgements_received_and_equal={all_received}\n"
        ));
        artifacts[offset * stride + endpoints.len()]
            .persist(report.as_bytes())
            .map_err(|error| stopped(offset, &error))?;
        print_apply_attempts(&attempts);
        if !all_received {
            return Err(stopped(
                offset,
                &"one or more peers failed, returned a rejected outcome, or returned differing acknowledgements",
            ));
        }
    }
    println!(
        "catch_up_entries_acknowledged={} scope=declared_requests_only",
        batch.entries.len()
    );
    Ok(())
}

fn stopped(offset: usize, reason: &dyn std::fmt::Display) -> CliError {
    invalid(format!(
        "catch-up stopped at entry {}: {reason}; a prefix or this entry may already have committed; subsequent entries were not sent; preserve per-peer outputs and replay identical saved artifacts to fresh result files, never a new nonce",
        offset + 1
    ))
}

#[cfg(test)]
mod tests {
    use super::super::boundary_tests::Fixture;
    use super::*;
    use crate::test_support::FakeTransport;
    use consensus::ConsensusSigner;
    use crypto::SignatureSigner;
    use sunrise_edge_client::*;

    struct Voter(LocalSigner);
    impl ConsensusSigner for Voter {
        fn validator_id(&self) -> ValidatorId {
            ValidatorId::new(*self.0.address().as_bytes())
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
            self.0.sign_framed(bytes).map_err(|error| error.to_string())
        }
    }
    fn cert(fixture: &Fixture, signed: &SignedPaidIntent) -> FastCertificate {
        let voter: Voter = Voter(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let vote: FastVote = fixture
            .certifier
            .cast_vote(
                paid_invocation_digest(&fixture.resolver, signed).unwrap(),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x51; 32]),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x52; 32]),
                &voter,
            )
            .unwrap();
        let mut votes: Vec<FastVote> = vec![vote.clone()];
        let second: Voter = Voter(LocalSigner::from_seed([0x77; 32]));
        if fixture
            .certifier
            .validator_set()
            .get(second.validator_id())
            .is_some()
        {
            votes.push(
                fixture
                    .certifier
                    .cast_vote(
                        vote.tx_hash,
                        vote.execution_effects_hash,
                        vote.locked_objects_digest,
                        &second,
                    )
                    .unwrap(),
            );
        }
        fixture
            .certifier
            .try_form_certificate(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                &votes,
                &FastPathEd25519Verifier,
            )
            .unwrap()
            .unwrap()
    }
    fn context(fixture: &Fixture) -> PublicationContext {
        PublicationContext::new(
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
            fixture.expected.epoch(),
        )
        .unwrap()
    }
    fn save(fixture: &Fixture, name: &str, signed: &SignedPaidIntent) -> String {
        std::fs::write(
            fixture.path(&format!("{name}.intent")),
            encode_signed_paid_intent(signed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            fixture.path(&format!("{name}.cert")),
            encode_fast_certificate(&cert(fixture, signed)).unwrap(),
        )
        .unwrap();
        format!("{name}.intent {name}.cert\n")
    }
    fn load(fixture: &Fixture, text: &str) -> Result<Batch, CliError> {
        std::fs::write(fixture.path("batch"), text).unwrap();
        load_batch(
            &fixture.path("batch"),
            &fixture.resolver,
            &context(fixture),
            &fixture.certifier,
        )
    }
    fn second(fixture: &Fixture) -> SignedPaidIntent {
        let mut signed: SignedPaidIntent = fixture.signed.clone();
        signed.intent.request_id = [0x62; 32];
        signed.intent.nonce = 1;
        if let PaidApplication::Call(call) = &mut signed.intent.application {
            call.request_id = signed.intent.request_id;
            call.nonce = 1;
        }
        let signer: LocalSigner = LocalSigner::from_seed([0x21; 32]);
        signed.signature = signer
            .sign_framed(
                &execution::paid_execution::paid_intent_signing_frame(
                    &signed.intent.context,
                    &signed.intent,
                )
                .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        signed
    }
    fn response(result: &PaidExecutionResult) -> Result<WireResponse, TransportError> {
        let id: RequestId = RequestId::new(result.request_id).unwrap();
        Ok(WireResponse {
            status: 200,
            content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
            body: HttpNodeResult::new(
                id,
                vec![
                    NodeResponse::new(
                        id,
                        if result.status == PaidExecutionStatus::Success {
                            NodeResponseStatus::Accepted
                        } else {
                            NodeResponseStatus::Rejected
                        },
                        Some(encode_paid_execution_result(result).unwrap()),
                    )
                    .unwrap(),
                ],
            )
            .unwrap()
            .encode()
            .unwrap(),
        })
    }
    fn endpoint(
        _fixture: &Fixture,
        responses: Vec<Result<WireResponse, TransportError>>,
    ) -> FastVoteEndpoint<FakeTransport> {
        FastVoteEndpoint {
            validator_id: ValidatorId::new(
                *LocalSigner::from_seed(sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED)
                    .address()
                    .as_bytes(),
            ),
            endpoint_label: "peer".to_owned(),
            client: Client::new(FakeTransport::new(responses)),
        }
    }
    fn budget() -> OperationBudget {
        OperationBudget {
            deadline: Instant::now().checked_add(Duration::from_secs(5)).unwrap(),
            per_request_cap: Duration::from_secs(1),
        }
    }

    #[test]
    fn catch_up_all_pairs_authenticate_before_any_network_or_output_reservation() {
        let fixture: Fixture = Fixture::new();
        let text: String =
            save(&fixture, "first", &fixture.signed) + &save(&fixture, "last", &second(&fixture));
        let mut bytes: Vec<u8> = std::fs::read(fixture.path("last.intent")).unwrap();
        let last: usize = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(fixture.path("last.intent"), bytes).unwrap();
        assert!(load(&fixture, &text).is_err());
        assert!(!std::path::Path::new(&fixture.path("entry-0001.report")).exists());
        // Valid certificate for an unrelated signed intent also rejects offline.
        std::fs::write(
            fixture.path("last.intent"),
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        assert!(load(&fixture, "last.intent last.cert\n").is_err());
    }

    #[test]
    fn catch_up_manifest_grammar_context_duplicates_and_bounds_fail_closed() {
        let fixture: Fixture = Fixture::new();
        let line: String = save(&fixture, "first", &fixture.signed);
        assert!(load(&fixture, "").is_err());
        assert!(load(&fixture, "one two three\n").is_err());
        assert!(load(&fixture, &("#".to_owned() + &"x".repeat(MAX_LINE_BYTES))).is_err());
        assert!(
            load(&fixture, &line.repeat(2))
                .unwrap_err_string()
                .contains("duplicate")
        );
        assert!(load(&fixture, &"x".repeat(MAX_MANIFEST_BYTES + 1)).is_err());
        std::fs::write(fixture.path("batch"), &line).unwrap();
        let wrong: PublicationContext = PublicationContext::new(
            context(&fixture).chain_id().clone(),
            context(&fixture).protocol_version(),
            Epoch::new(1),
        )
        .unwrap();
        assert!(
            load_batch(
                &fixture.path("batch"),
                &fixture.resolver,
                &wrong,
                &fixture.certifier
            )
            .is_err()
        );
        let mut manifest_text: String = String::new();
        for index in 0..=MAX_ENTRIES {
            let mut intent: SignedPaidIntent = second(&fixture);
            intent.intent.request_id = [u8::try_from(index + 100).unwrap(); 32];
            if let PaidApplication::Call(call) = &mut intent.intent.application {
                call.request_id = intent.intent.request_id;
            }
            intent.signature = LocalSigner::from_seed([0x21; 32])
                .sign_framed(
                    &execution::paid_execution::paid_intent_signing_frame(
                        &intent.intent.context,
                        &intent.intent,
                    )
                    .unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap();
            manifest_text.push_str(&save(&fixture, &format!("entry{index}"), &intent));
        }
        assert!(
            load(&fixture, &manifest_text)
                .unwrap_err_string()
                .contains("16 pairs")
        );
    }

    trait ErrorString {
        fn unwrap_err_string(self) -> String;
    }
    impl<T> ErrorString for Result<T, CliError> {
        fn unwrap_err_string(self) -> String {
            self.err().unwrap().to_string()
        }
    }

    #[test]
    fn catch_up_committed_trap_continues_order_and_saves_exact_per_peer_results() {
        let mut fixture: Fixture = Fixture::new();
        let first: SignedPaidIntent = fixture.signed.clone();
        let next: SignedPaidIntent = second(&fixture);
        let batch: Batch = load(
            &fixture,
            &(save(&fixture, "first", &first) + &save(&fixture, "next", &next)),
        )
        .unwrap();
        let trap: PaidExecutionResult = fixture.result(PaidExecutionStatus::ApplicationFailed);
        fixture.signed = next;
        let success: PaidExecutionResult = fixture.result(PaidExecutionStatus::Success);
        let peers = vec![endpoint(
            &fixture,
            vec![response(&trap), response(&success)],
        )];
        apply_batch(
            &batch,
            fixture.directory.to_str().unwrap(),
            &peers,
            &fixture.certifier,
            &fixture.resolver,
            budget(),
        )
        .unwrap();
        assert_eq!(peers[0].client.transport().requests().len(), 2);
        for (index, expected) in [(1, trap), (2, success)] {
            let path: String = fixture.path(&format!(
                "entry-{index:04}-validator-{}.result",
                peers[0].validator_id
            ));
            assert_eq!(
                std::fs::read(path).unwrap(),
                encode_paid_execution_result(&expected).unwrap()
            );
            assert!(
                std::fs::read_to_string(fixture.path(&format!("entry-{index:04}.report")))
                    .unwrap()
                    .contains("all_configured_acknowledgements_received_and_equal=true")
            );
        }
    }

    #[test]
    fn catch_up_existing_aliased_missing_outputs_and_elapsed_budget_make_zero_posts() {
        let fixture: Fixture = Fixture::new();
        let batch: Batch = load(&fixture, &save(&fixture, "first", &fixture.signed)).unwrap();
        let peers = vec![endpoint(&fixture, Vec::new())];
        let result: String = fixture.path(&format!(
            "entry-0001-validator-{}.result",
            peers[0].validator_id
        ));
        std::fs::hard_link(fixture.path("first.intent"), &result).unwrap();
        assert!(
            apply_batch(
                &batch,
                fixture.directory.to_str().unwrap(),
                &peers,
                &fixture.certifier,
                &fixture.resolver,
                budget()
            )
            .is_err()
        );
        assert!(peers[0].client.transport().requests().is_empty());
        std::fs::remove_file(result).unwrap();
        assert!(
            apply_batch(
                &batch,
                &fixture.path("missing"),
                &peers,
                &fixture.certifier,
                &fixture.resolver,
                budget()
            )
            .is_err()
        );
        let elapsed: OperationBudget = OperationBudget {
            deadline: Instant::now(),
            per_request_cap: Duration::from_secs(1),
        };
        assert!(
            apply_batch(
                &batch,
                fixture.directory.to_str().unwrap(),
                &peers,
                &fixture.certifier,
                &fixture.resolver,
                elapsed
            )
            .is_err()
        );
        assert!(peers[0].client.transport().requests().is_empty());
    }

    #[test]
    fn catch_up_transport_failure_stops_dependent_suffix_and_persists_report() {
        let fixture: Fixture = Fixture::new();
        let batch: Batch = load(
            &fixture,
            &(save(&fixture, "first", &fixture.signed)
                + &save(&fixture, "next", &second(&fixture))),
        )
        .unwrap();
        let peers = vec![endpoint(
            &fixture,
            vec![Err(TransportError::RequestDeadlineExceeded)],
        )];
        let error: String = apply_batch(
            &batch,
            fixture.directory.to_str().unwrap(),
            &peers,
            &fixture.certifier,
            &fixture.resolver,
            budget(),
        )
        .unwrap_err_string();
        assert!(error.contains("prefix") && error.contains("fresh result"));
        assert_eq!(peers[0].client.transport().requests().len(), 1);
        assert!(
            std::fs::read_to_string(fixture.path("entry-0001.report"))
                .unwrap()
                .contains("status=failed")
        );
        assert!(
            std::fs::read(fixture.path("entry-0002.report"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn catch_up_unknown_flags_and_invalid_deadlines_reject_before_inputs() {
        for extra in [
            ["--seed-file", "missing"],
            ["--submission", "missing"],
            ["--fastvote-deadline-seconds", "0"],
            ["--fastvote-deadline-seconds", "18446744073709551615"],
        ] {
            assert!(run(extra.into_iter().map(OsString::from)).is_err());
        }
        run([OsString::from("--help")]).unwrap();
    }

    #[test]
    fn catch_up_aggregate_bytes_and_retained_in_place_input_changes_reject() {
        assert_eq!(
            add_input_bytes(MAX_ARTIFACT_BYTES - 3, 1, 2).unwrap(),
            MAX_ARTIFACT_BYTES
        );
        assert!(add_input_bytes(MAX_ARTIFACT_BYTES - 3, 1, 3).is_err());
        assert!(add_input_bytes(usize::MAX, 1, 0).is_err());
        let fixture: Fixture = Fixture::new();
        let batch: Batch = load(&fixture, &save(&fixture, "first", &fixture.signed)).unwrap();
        std::fs::write(fixture.path("first.intent"), b"changed in place").unwrap();
        let peers = vec![endpoint(&fixture, Vec::new())];
        assert!(
            apply_batch(
                &batch,
                fixture.directory.to_str().unwrap(),
                &peers,
                &fixture.certifier,
                &fixture.resolver,
                budget()
            )
            .is_err()
        );
        assert!(peers[0].client.transport().requests().is_empty());
        assert!(!Path::new(&fixture.path("entry-0001.report")).exists());
    }

    #[test]
    fn catch_up_authenticated_quorum_instantiate_is_rejected_offline() {
        let fixture: Fixture = Fixture::new();
        let mut signed: SignedPaidIntent = fixture.signed.clone();
        let PaidApplication::Call(mut call) = signed.intent.application else {
            panic!("fixture is a call");
        };
        call.instance.creator = signed.intent.sender;
        signed.intent.application = PaidApplication::Instantiate(call);
        signed.signature = LocalSigner::from_seed([0x21; 32])
            .sign_framed(
                &execution::paid_execution::paid_intent_signing_frame(
                    &signed.intent.context,
                    &signed.intent,
                )
                .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let text: String = save(&fixture, "instantiate", &signed);
        assert!(
            load(&fixture, &text)
                .unwrap_err_string()
                .contains("only certified Call")
        );
    }

    #[test]
    fn catch_up_differing_peer_results_are_all_retained_and_stop_suffix() {
        let mut fixture: Fixture = Fixture::new();
        let original: ValidatorInfo = fixture.certifier.validator_set().validators()[0].clone();
        let peer: LocalSigner = LocalSigner::from_seed([0x77; 32]);
        let peer_id: ValidatorId = ValidatorId::new(*peer.address().as_bytes());
        fixture.certifier = FastPathCertifier::new(
            context(&fixture).chain_id().clone(),
            context(&fixture).protocol_version(),
            context(&fixture).epoch(),
            ValidatorSet::new(
                context(&fixture).epoch(),
                vec![
                    original,
                    ValidatorInfo {
                        id: peer_id,
                        voting_power: 1,
                        signature_scheme: SignatureSchemeId::Ed25519,
                        public_key: peer.address().as_bytes().to_vec(),
                    },
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let batch: Batch = load(
            &fixture,
            &(save(&fixture, "first", &fixture.signed)
                + &save(&fixture, "next", &second(&fixture))),
        )
        .unwrap();
        let success: PaidExecutionResult = fixture.result(PaidExecutionStatus::Success);
        let trap: PaidExecutionResult = fixture.result(PaidExecutionStatus::ApplicationFailed);
        let first_peer = endpoint(&fixture, vec![response(&success)]);
        let mut second_peer = endpoint(&fixture, vec![response(&trap)]);
        second_peer.validator_id = peer_id;
        second_peer.endpoint_label = "second-peer".to_owned();
        let peers = vec![first_peer, second_peer];
        assert!(
            apply_batch(
                &batch,
                fixture.directory.to_str().unwrap(),
                &peers,
                &fixture.certifier,
                &fixture.resolver,
                budget()
            )
            .is_err()
        );
        for (endpoint, result) in peers.iter().zip([success, trap]) {
            assert_eq!(endpoint.client.transport().requests().len(), 1);
            assert_eq!(
                std::fs::read(fixture.path(&format!(
                    "entry-0001-validator-{}.result",
                    endpoint.validator_id
                )))
                .unwrap(),
                encode_paid_execution_result(&result).unwrap()
            );
        }
        assert!(
            std::fs::read_to_string(fixture.path("entry-0001.report"))
                .unwrap()
                .contains("all_configured_acknowledgements_received_and_equal=false")
        );
    }
}
