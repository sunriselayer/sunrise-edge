//! Explicit certified member apply/replay. The request carries only a
//! locator; the host re-verifies committed membership and retained proof.
//! No causal ordering, missing dependency synthesis or complete-drain claim.

use super::*;
use sunrise_edge_client::{HashSuiteResolver, PublicationContext, validate_drain_member_output};

const HELP: &str = "contract fastvote-drain-member
  --validator-id VALIDATOR_ID_HEX --signed-intent FILE --out-result FILE
  --fastvote-network CONFIG --fastvote-genesis-manifest FILE
  --fastvote-expected-genesis-digest DIGEST_HEX
  --expected-chain-id CHAIN --expected-protocol-version VERSION --expected-epoch EPOCH
  --expected-hash-suite-id SUITE --expected-domain DOMAIN_HEX
  [--fastvote-deadline-seconds SECONDS] [--fastvote-per-request-cap-seconds SECONDS]
Applies or replays exactly one original signed member using the target's committed DrainSet
and retained full certificate. Missing causal prerequisites stop the operation. The exact full
original NodeOutput HTTP envelope is saved once. An existing output is authenticated before
POST, then must agree byte-for-byte with the replay; it is never overwritten. A charged trap
is a valid saved result, not permission to re-sign or charge again. Fresh output is staged
privately and published only when complete; retry identical signed bytes after a failed
attempt. No complete-drain claim.";

/// Fresh results are written to a private sibling, never an empty final-path
/// reservation. Only complete authenticated bytes are atomically linked into
/// place without replacement. A crash before publication can leave an orphan
/// sibling, but retries never read it as saved authority.
struct MemberOutput {
    artifact: ReservedArtifact,
    destination: Option<PathBuf>,
}

impl MemberOutput {
    fn pending(out_path: &str) -> Result<Self, CliError> {
        let destination: PathBuf = artifact_path(out_path)?;
        let parent_path: &Path = destination
            .parent()
            .ok_or_else(|| invalid("member output parent missing"))?;
        let parent: File = File::open(parent_path).map_err(failure)?;
        // Fail unsupported directory synchronization before any member POST.
        parent.sync_all().map_err(failure)?;
        let timestamp: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(failure)?
            .as_nanos();
        for attempt in 0u8..16 {
            let path: PathBuf = parent_path.join(format!(
                ".sunrise-drain-member-{}-{timestamp}-{attempt}.pending",
                std::process::id()
            ));
            // The caller may itself have chosen a staging-shaped output name.
            if path == destination {
                continue;
            }
            let file: File = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(failure(error)),
            };
            let output: Self = Self {
                artifact: ReservedArtifact {
                    path,
                    file,
                    parent,
                    kind: "drain-member-result",
                },
                destination: Some(destination),
            };
            output.artifact.parent.sync_all().map_err(failure)?;
            output.artifact.ensure_attached()?;
            return Ok(output);
        }
        Err(invalid("unable to reserve a private member output sibling"))
    }

    fn publish(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        let destination: &PathBuf = self
            .destination
            .as_ref()
            .ok_or_else(|| invalid("saved member output cannot be published again"))?;
        self.artifact.persist(bytes)?;
        self.artifact.ensure_exact_input(bytes)?;
        let mut published: ReservedArtifact = ReservedArtifact {
            path: destination.clone(),
            file: self.artifact.file.try_clone().map_err(failure)?,
            parent: self.artifact.parent.try_clone().map_err(failure)?,
            kind: "drain-member-result",
        };
        // Same-directory hard linking publishes the complete inode atomically
        // and refuses every existing destination, including symlinks. Rename
        // would overwrite a concurrent writer and is deliberately not used.
        std::fs::hard_link(self.artifact.path(), destination).map_err(|source| {
            invalid(format!(
                "failed to publish member output at {destination:?} without replacement: {source}; retry identical saved signed bytes, never a fresh nonce"
            ))
        })?;
        published.ensure_exact_input(bytes)?;
        // If a later sync/recheck fails, leave the complete final file intact
        // for exact replay. Cleanup below only ever concerns the private sibling.
        Ok(())
    }
}

impl Drop for MemberOutput {
    fn drop(&mut self) {
        // Unix inode checks let us clean up only our still-attached sibling.
        // On other platforms, retaining an ignored orphan is safer than
        // deleting a path whose identity cannot be established by this helper.
        #[cfg(unix)]
        if self.destination.is_some() && self.artifact.ensure_attached().is_ok() {
            let _ = std::fs::remove_file(self.artifact.path());
            let _ = self.artifact.parent.sync_all();
        }
    }
}

pub(in crate::commands) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let specs: Vec<crate::args::FlagSpec> = [
        "--validator-id",
        "--signed-intent",
        "--out-result",
        "--fastvote-network",
        "--fastvote-genesis-manifest",
        "--fastvote-expected-genesis-digest",
        "--expected-chain-id",
        "--expected-protocol-version",
        "--expected-epoch",
        "--expected-hash-suite-id",
        "--expected-domain",
        "--fastvote-deadline-seconds",
        "--fastvote-per-request-cap-seconds",
    ]
    .into_iter()
    .map(scalar)
    .collect();
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let budget: OperationBudget = parse_deadline(&parsed)?;
    let validator: ValidatorId = ValidatorId::new(decode_hex_32(
        "--validator-id",
        parsed.require("--validator-id")?,
    )?);
    let expected: sunrise_edge_client::ExpectedProtocolContext =
        super::super::standard_asset::parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let (endpoints, certifier, _minimum): (
        Vec<FastVoteEndpoint<CliTransport>>,
        FastPathCertifier,
        u64,
    ) = load_drain_endpoints_and_certifier(&parsed, &resolver, &context)?;
    let target: &Client<CliTransport> = endpoints
        .iter()
        .find(|peer| peer.validator_id == validator)
        .map(|peer| &peer.client)
        .ok_or_else(|| invalid("--validator-id is absent from --fastvote-network"))?;
    execute(
        target,
        &certifier,
        &resolver,
        &context,
        expected.domain(),
        parsed.require("--signed-intent")?,
        parsed.require("--out-result")?,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute<T: Transport>(
    target: &Client<T>,
    certifier: &FastPathCertifier,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
    signed_path: &str,
    out_path: &str,
    budget: OperationBudget,
) -> Result<(), CliError> {
    let (mut input, signed_bytes): (ReservedArtifact, Vec<u8>) = super::catch_up::retained_input(
        Path::new(signed_path),
        sunrise_edge_client::MAX_SIGNED_PAID_INTENT_BYTES,
        "signed-intent",
    )?;
    let signed: SignedPaidIntent = decode_signed_paid_intent(&signed_bytes).map_err(failure)?;
    sunrise_edge_client::authenticate_paid_intent(resolver, context, &signed_bytes)
        .map_err(failure)?;
    // Existing output is not a success hint. Fully authenticate it locally
    // before any POST and hold its exact bytes/handles until replay ends.
    let (mut output, saved): (MemberOutput, Option<Vec<u8>>) =
        match std::fs::symlink_metadata(out_path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(invalid(
                        "saved member output must be a regular file, not a symlink",
                    ));
                }
                let (output, bytes): (ReservedArtifact, Vec<u8>) = super::catch_up::retained_input(
                    Path::new(out_path),
                    MAX_ENCODED_BUNDLE_BYTES,
                    "drain-member-result",
                )?;
                validate_drain_member_output(&signed, resolver, context, &bytes)
                    .map_err(failure)?;
                (
                    MemberOutput {
                        artifact: output,
                        destination: None,
                    },
                    Some(bytes),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (MemberOutput::pending(out_path)?, None)
            }
            Err(error) => return Err(failure(error)),
        };
    input.ensure_exact_input(&signed_bytes)?;
    if let Some(bytes) = &saved {
        output.artifact.ensure_exact_input(bytes)?;
    } else {
        output.artifact.ensure_attached()?;
    }
    let client: Client<crate::net::BudgetedTransport<'_, T>> =
        Client::new(crate::net::BudgetedTransport {
            inner: target.transport(),
            budget: Some(budget),
        });
    let (result, bytes): (PaidExecutionResult, Vec<u8>) = client
        .apply_drain_member_output_with_saved(
            &signed,
            certifier,
            resolver,
            &[],
            context,
            domain,
            saved.as_deref(),
            Some(budget.deadline),
        )
        .map_err(failure)?;
    input.ensure_exact_input(&signed_bytes)?;
    if let Some(original) = saved {
        output.artifact.ensure_exact_input(&original)?;
        if bytes != original {
            return Err(invalid(
                "member replay differs from saved original NodeOutput; output not overwritten",
            ));
        }
    } else {
        output.publish(&bytes)?;
    }
    println!("drain_member_applied=true");
    println!("request_id={}", encode_hex(&signed.intent.request_id));
    println!("status={:?}", result.status);
    println!("out_result={out_path}");
    println!("complete_drain_claim=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::boundary_tests::Fixture;
    use super::*;
    use crate::test_support::FakeTransport;
    use consensus::ConsensusSigner;
    use consensus::bundle::{
        ArtifactManifest, LOGICAL_COMMITMENT_PROFILE, PublicationBundle, encode_publication_bundle,
    };
    use crypto::SignatureSigner;
    use sunrise_edge_client::{
        CanonicalStruct, Digest32, HttpNodeResult, LocalSigner, NODE_RESULT_MEDIA_TYPE,
        NodeResponse, NodeResponseStatus, RequestId, SignatureSchemeId, TransportError,
        WireRequest, WireResponse, encode_paid_execution_result,
    };

    struct VoteSigner(LocalSigner);
    impl ConsensusSigner for VoteSigner {
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

    fn retained_bundle(fixture: &Fixture, status: PaidExecutionStatus) -> Vec<u8> {
        let tx_hash: Digest32 =
            sunrise_edge_client::paid_invocation_digest(&fixture.resolver, &fixture.signed)
                .unwrap();
        let mut digest: CanonicalStruct = CanonicalStruct::new(0x0103, 1);
        digest.field_u16(1, tx_hash.algorithm().as_u16()).unwrap();
        digest.field_bytes(2, tx_hash.bytes().to_vec()).unwrap();
        let mut witness: CanonicalStruct = CanonicalStruct::new(0x6424, 2);
        witness.field_bytes(1, digest.finish().unwrap()).unwrap();
        witness
            .field_bytes(
                2,
                encode_paid_execution_result(&fixture.result(status)).unwrap(),
            )
            .unwrap();
        // Synthetic response-binding fixture, not an admission witness: its
        // replay closure is explicitly empty under the strict list schema.
        // Genuine required-artifact omissions are covered by SDK/core tests.
        for field in [3u16, 4, 5, 6, 7, 12] {
            witness
                .field_bytes(field, 0u32.to_be_bytes().to_vec())
                .unwrap();
        }
        let nonce_key: Vec<u8> = runtime::PersistenceLayout::new(
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        )
        .sender_nonce_key(fixture.signed.intent.sender, fixture.expected.epoch());
        witness.field_bytes(8, nonce_key).unwrap();
        // The strict decoder validates every operand, including the existing
        // canonical sender/epoch/next-nonce record, even for this transport-only
        // fixture. Empty nonce bytes are not an absent nonce observation.
        let mut nonce: CanonicalStruct = CanonicalStruct::new(0xE006, 1);
        nonce
            .field_bytes(1, fixture.signed.intent.sender.to_vec())
            .unwrap();
        nonce.field_u64(2, fixture.expected.epoch().get()).unwrap();
        nonce
            .field_u64(3, fixture.signed.intent.nonce.checked_add(1).unwrap())
            .unwrap();
        witness.field_bytes(10, nonce.finish().unwrap()).unwrap();
        witness.field_u64(11, 1).unwrap();
        let bytes: Vec<u8> = witness.finish().unwrap();
        let effect_hash: Digest32 = fixture
            .resolver
            .hash_for_purpose(
                fixture.expected.epoch(),
                protocol_types::HashPurpose::ExecutionEffects,
                &bytes,
            )
            .unwrap();
        let lock_hash: Digest32 =
            Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x52; 32]);
        let signer: VoteSigner = VoteSigner(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let vote = fixture
            .certifier
            .cast_vote(tx_hash, effect_hash, lock_hash, &signer)
            .unwrap();
        let certificate = fixture
            .certifier
            .try_form_certificate(
                tx_hash,
                effect_hash,
                lock_hash,
                &[vote],
                &sunrise_edge_client::FastPathEd25519Verifier,
            )
            .unwrap()
            .unwrap();
        encode_publication_bundle(&PublicationBundle {
            domain: fixture.expected.domain(),
            request_id: fixture.signed.intent.request_id,
            commitment_profile: LOGICAL_COMMITMENT_PROFILE,
            signed_intent: encode_signed_paid_intent(&fixture.signed).unwrap(),
            certificate,
            witness: bytes,
            manifest: ArtifactManifest {
                entries: Vec::new(),
            },
            contents: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn retained_response_fixture_satisfies_the_strict_operand_schema() {
        let fixture: Fixture = Fixture::new();
        for status in [
            PaidExecutionStatus::Success,
            PaidExecutionStatus::ApplicationFailed,
        ] {
            let bundle: PublicationBundle =
                consensus::bundle::decode_publication_bundle(&retained_bundle(&fixture, status))
                    .unwrap();
            let identity: consensus::AvailabilityIdentity =
                node_core::fast_path::drain_publication::verify_drain_publication_bundle(
                    &fixture.resolver,
                    &[],
                    &fixture.signed.intent.context,
                    fixture.expected.domain(),
                    &fixture.certifier,
                    &bundle,
                )
                .unwrap();
            assert_eq!(identity.request_id, fixture.signed.intent.request_id);
        }
    }

    fn budget() -> OperationBudget {
        OperationBudget {
            deadline: Instant::now().checked_add(Duration::from_secs(2)).unwrap(),
            per_request_cap: Duration::from_secs(1),
        }
    }

    fn response(fixture: &Fixture, status: PaidExecutionStatus) -> Vec<u8> {
        let request: RequestId = RequestId::new(fixture.signed.intent.request_id).unwrap();
        let ack: NodeResponse = NodeResponse::new(
            request,
            if status == PaidExecutionStatus::Success {
                NodeResponseStatus::Accepted
            } else {
                NodeResponseStatus::Rejected
            },
            Some(encode_paid_execution_result(&fixture.result(status)).unwrap()),
        )
        .unwrap();
        HttpNodeResult::new(request, vec![ack])
            .unwrap()
            .encode()
            .unwrap()
    }

    fn endpoint(
        fixture: &Fixture,
        status: PaidExecutionStatus,
        bytes: Vec<u8>,
    ) -> Client<FakeTransport> {
        let responses: Vec<Result<WireResponse, TransportError>> =
            [retained_bundle(fixture, status), bytes]
                .into_iter()
                .map(|body| Ok(wire(body)))
                .collect();
        Client::new(FakeTransport::new(responses))
    }

    fn wire(body: Vec<u8>) -> WireResponse {
        WireResponse {
            status: 200,
            content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
            body,
        }
    }

    fn execute_fixture<T: Transport>(
        fixture: &Fixture,
        target: &Client<T>,
        signed_path: &str,
        out_path: &str,
    ) -> Result<(), CliError> {
        execute(
            target,
            &fixture.certifier,
            &fixture.resolver,
            &fixture.signed.intent.context,
            fixture.expected.domain(),
            signed_path,
            out_path,
            budget(),
        )
    }

    fn assert_absent(path: &str) {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(unix)]
    fn assert_no_pending(fixture: &Fixture) {
        for entry in std::fs::read_dir(&fixture.directory).unwrap() {
            let name: OsString = entry.unwrap().file_name();
            assert!(!name.to_string_lossy().starts_with(".sunrise-drain-member-"));
        }
    }

    #[test]
    fn member_command_help_and_bad_flags_do_not_open_files() {
        run([OsString::from("--help")]).unwrap();
        assert!(run(Vec::<OsString>::new()).is_err());
        assert!(
            run(["--validator-id", "invalid"]
                .into_iter()
                .map(OsString::from))
            .is_err()
        );
        assert!(
            run(["--tls-server-name", "unsafe"]
                .into_iter()
                .map(OsString::from))
            .is_err()
        );
    }

    #[test]
    fn exact_saved_original_output_is_preserved_on_process_style_replay() {
        for status in [
            PaidExecutionStatus::Success,
            PaidExecutionStatus::ApplicationFailed,
        ] {
            let fixture: Fixture = Fixture::new();
            let signed_path: String = fixture.path("member.signed");
            let out_path: String = fixture.path("member.result");
            let signed: Vec<u8> = encode_signed_paid_intent(&fixture.signed).unwrap();
            std::fs::write(&signed_path, &signed).unwrap();
            let body: Vec<u8> = response(&fixture, status);
            let first: Client<FakeTransport> = endpoint(&fixture, status, body.clone());
            execute(
                &first,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed.intent.context,
                fixture.expected.domain(),
                &signed_path,
                &out_path,
                budget(),
            )
            .unwrap();
            assert_eq!(std::fs::read(&out_path).unwrap(), body);
            let resumed: Client<FakeTransport> = endpoint(&fixture, status, body.clone());
            execute(
                &resumed,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed.intent.context,
                fixture.expected.domain(),
                &signed_path,
                &out_path,
                budget(),
            )
            .unwrap();
            assert_eq!(std::fs::read(&out_path).unwrap(), body);
            assert_eq!(std::fs::read(&signed_path).unwrap(), signed);
            assert_eq!(resumed.transport().requests().len(), 2);
            let requests = resumed.transport().requests();
            assert_eq!(
                requests[0].path,
                sunrise_edge_client::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH
            );
            let request = &requests[1];
            assert_eq!(request.path, sunrise_edge_client::FASTVOTE_DRAIN_APPLY_PATH);
            assert_eq!(
                sunrise_edge_client::DrainMemberApplyRequest::decode(&request.body)
                    .unwrap()
                    .member_request_id,
                fixture.signed.intent.request_id
            );
        }
    }

    #[test]
    fn malformed_or_different_saved_output_fails_before_post_without_overwrite() {
        for bytes in [b"".as_slice(), b"partial".as_slice()] {
            let fixture: Fixture = Fixture::new();
            let signed_path: String = fixture.path("member.signed");
            let out_path: String = fixture.path("member.result");
            std::fs::write(
                &signed_path,
                encode_signed_paid_intent(&fixture.signed).unwrap(),
            )
            .unwrap();
            std::fs::write(&out_path, bytes).unwrap();
            let target: Client<FakeTransport> = Client::new(FakeTransport::new(Vec::new()));
            assert!(execute_fixture(&fixture, &target, &signed_path, &out_path).is_err());
            assert!(target.transport().requests().is_empty());
            assert_eq!(std::fs::read(&out_path).unwrap(), bytes);
            #[cfg(unix)]
            assert_no_pending(&fixture);
        }
    }

    #[test]
    fn saved_uncertified_result_is_rejected_before_member_post() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let wrong: Vec<u8> = response(&fixture, PaidExecutionStatus::ApplicationFailed);
        std::fs::write(&out_path, &wrong).unwrap();
        let target = endpoint(
            &fixture,
            PaidExecutionStatus::Success,
            response(&fixture, PaidExecutionStatus::Success),
        );
        assert!(
            execute(
                &target,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed.intent.context,
                fixture.expected.domain(),
                &signed_path,
                &out_path,
                budget()
            )
            .is_err()
        );
        assert_eq!(target.transport().requests().len(), 1);
        assert_eq!(
            target.transport().requests()[0].path,
            sunrise_edge_client::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH
        );
        assert_eq!(std::fs::read(&out_path).unwrap(), wrong);
    }

    #[test]
    fn differently_signed_intent_with_same_request_id_never_reaches_member_apply() {
        let fixture: Fixture = Fixture::new();
        let mut different: SignedPaidIntent = fixture.signed.clone();
        different.intent.gas_limit = 9999;
        if let PaidApplication::Call(call) = &mut different.intent.application {
            call.gas_limit = 9999;
        }
        let signer: LocalSigner = LocalSigner::from_seed([0x21; 32]);
        different.signature = signer
            .sign_framed(
                &execution::paid_execution::paid_intent_signing_frame(
                    &different.intent.context,
                    &different.intent,
                )
                .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let signed_path: String = fixture.path("different-signed");
        let out_path: String = fixture.path("output");
        let input: Vec<u8> = encode_signed_paid_intent(&different).unwrap();
        std::fs::write(&signed_path, &input).unwrap();
        let target = endpoint(
            &fixture,
            PaidExecutionStatus::Success,
            response(&fixture, PaidExecutionStatus::Success),
        );
        assert!(
            execute(
                &target,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed.intent.context,
                fixture.expected.domain(),
                &signed_path,
                &out_path,
                budget()
            )
            .is_err()
        );
        let requests = target.transport().requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            sunrise_edge_client::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH
        );
        assert_eq!(std::fs::read(&signed_path).unwrap(), input);
        assert_absent(&out_path);
        #[cfg(unix)]
        assert_no_pending(&fixture);
    }

    #[test]
    fn validly_bound_but_uncertified_apply_response_is_not_saved() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let target = endpoint(
            &fixture,
            PaidExecutionStatus::Success,
            response(&fixture, PaidExecutionStatus::ApplicationFailed),
        );
        assert!(
            execute(
                &target,
                &fixture.certifier,
                &fixture.resolver,
                &fixture.signed.intent.context,
                fixture.expected.domain(),
                &signed_path,
                &out_path,
                budget()
            )
            .is_err()
        );
        assert_eq!(target.transport().requests().len(), 2);
        assert_absent(&out_path);
        #[cfg(unix)]
        assert_no_pending(&fixture);
        let original: Vec<u8> = response(&fixture, PaidExecutionStatus::Success);
        let resumed: Client<FakeTransport> =
            endpoint(&fixture, PaidExecutionStatus::Success, original.clone());
        execute_fixture(&fixture, &resumed, &signed_path, &out_path).unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), original);
    }

    #[test]
    fn not_ready_transport_and_uncertified_errors_allow_fresh_same_path_retry() {
        for status in [
            PaidExecutionStatus::Success,
            PaidExecutionStatus::ApplicationFailed,
        ] {
            let fixture: Fixture = Fixture::new();
            let signed_path: String = fixture.path("signed");
            let signed: Vec<u8> = encode_signed_paid_intent(&fixture.signed).unwrap();
            std::fs::write(&signed_path, &signed).unwrap();
            let bundle: Vec<u8> = retained_bundle(&fixture, status);
            let original: Vec<u8> = response(&fixture, status);
            let not_ready = || -> Result<WireResponse, TransportError> {
                Ok(WireResponse {
                    status: 409,
                    content_type: Some("text/plain".to_owned()),
                    body: b"drain-proof-not-retained".to_vec(),
                })
            };
            let cases: Vec<(Vec<Result<WireResponse, TransportError>>, usize)> = vec![
                (vec![not_ready()], 1),
                (vec![Err(TransportError::RequestDeadlineExceeded)], 1),
                (vec![Ok(wire(b"uncertified source".to_vec()))], 1),
                (vec![Ok(wire(bundle.clone())), not_ready()], 2),
                (
                    vec![
                        Ok(wire(bundle.clone())),
                        Err(TransportError::RequestDeadlineExceeded),
                    ],
                    2,
                ),
                (
                    vec![Ok(wire(bundle)), Ok(wire(b"partial result".to_vec()))],
                    2,
                ),
            ];
            for (index, (responses, request_count)) in cases.into_iter().enumerate() {
                let out_path: String = fixture.path(&format!("output-{index}"));
                let failed: Client<FakeTransport> = Client::new(FakeTransport::new(responses));
                assert!(execute_fixture(&fixture, &failed, &signed_path, &out_path).is_err());
                assert_eq!(failed.transport().requests().len(), request_count);
                assert_absent(&out_path);
                #[cfg(unix)]
                assert_no_pending(&fixture);
                let resumed: Client<FakeTransport> = endpoint(&fixture, status, original.clone());
                execute_fixture(&fixture, &resumed, &signed_path, &out_path).unwrap();
                assert_eq!(resumed.transport().requests().len(), 2);
                assert_eq!(std::fs::read(&out_path).unwrap(), original);
                assert_eq!(std::fs::read(&signed_path).unwrap(), signed);
                #[cfg(unix)]
                assert_no_pending(&fixture);
            }
        }
    }

    #[test]
    fn crash_orphan_empty_partial_or_complete_staging_never_becomes_authority() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let original: Vec<u8> = response(&fixture, PaidExecutionStatus::Success);
        for (index, bytes) in [Vec::new(), b"partial".to_vec(), original.clone()]
            .into_iter()
            .enumerate()
        {
            let out_path: String = fixture.path(&format!("output-{index}"));
            let mut interrupted: MemberOutput = MemberOutput::pending(&out_path).unwrap();
            let orphan: PathBuf = interrupted.artifact.path().to_owned();
            interrupted.artifact.file.write_all(&bytes).unwrap();
            interrupted.artifact.file.sync_all().unwrap();
            // Model process death: close handles without running sibling cleanup.
            interrupted.destination = None;
            drop(interrupted);
            assert_absent(&out_path);
            let resumed: Client<FakeTransport> =
                endpoint(&fixture, PaidExecutionStatus::Success, original.clone());
            execute_fixture(&fixture, &resumed, &signed_path, &out_path).unwrap();
            assert_eq!(resumed.transport().requests().len(), 2);
            assert_eq!(std::fs::read(&out_path).unwrap(), original);
            assert_eq!(std::fs::read(&orphan).unwrap(), bytes);
        }
    }

    struct ConcurrentOutputTransport {
        inner: FakeTransport,
        destination: PathBuf,
        retain_original_at: Option<PathBuf>,
        competing_bytes: Vec<u8>,
    }

    impl Transport for ConcurrentOutputTransport {
        fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
            if request.path == sunrise_edge_client::FASTVOTE_DRAIN_APPLY_PATH {
                if let Some(retained) = &self.retain_original_at {
                    std::fs::rename(&self.destination, retained).unwrap();
                }
                let mut competing: File = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&self.destination)
                    .unwrap();
                competing.write_all(&self.competing_bytes).unwrap();
                competing.sync_all().unwrap();
            }
            self.inner.send(request)
        }
    }

    #[test]
    fn concurrent_final_path_creation_is_never_overwritten_or_removed() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let original: Vec<u8> = response(&fixture, PaidExecutionStatus::Success);
        let competing: Vec<u8> = b"another writer's incomplete file".to_vec();
        let target: Client<ConcurrentOutputTransport> = Client::new(ConcurrentOutputTransport {
            inner: FakeTransport::new(vec![
                Ok(wire(retained_bundle(
                    &fixture,
                    PaidExecutionStatus::Success,
                ))),
                Ok(wire(original)),
            ]),
            destination: PathBuf::from(&out_path),
            retain_original_at: None,
            competing_bytes: competing.clone(),
        });
        assert!(execute_fixture(&fixture, &target, &signed_path, &out_path).is_err());
        assert_eq!(target.transport().inner.requests().len(), 2);
        assert_eq!(std::fs::read(&out_path).unwrap(), competing);
        #[cfg(unix)]
        assert_no_pending(&fixture);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_saved_output_replacement_preserves_both_inodes() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        let retained_path: String = fixture.path("retained-original");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let original: Vec<u8> = response(&fixture, PaidExecutionStatus::Success);
        std::fs::write(&out_path, &original).unwrap();
        let competing: Vec<u8> = b"replacement inode".to_vec();
        let target: Client<ConcurrentOutputTransport> = Client::new(ConcurrentOutputTransport {
            inner: FakeTransport::new(vec![
                Ok(wire(retained_bundle(
                    &fixture,
                    PaidExecutionStatus::Success,
                ))),
                Ok(wire(original.clone())),
            ]),
            destination: PathBuf::from(&out_path),
            retain_original_at: Some(PathBuf::from(&retained_path)),
            competing_bytes: competing.clone(),
        });
        assert!(execute_fixture(&fixture, &target, &signed_path, &out_path).is_err());
        assert_eq!(target.transport().inner.requests().len(), 2);
        assert_eq!(std::fs::read(&out_path).unwrap(), competing);
        assert_eq!(std::fs::read(&retained_path).unwrap(), original);
        assert_no_pending(&fixture);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_does_not_remove_a_replaced_staging_path() {
        let fixture: Fixture = Fixture::new();
        let out_path: String = fixture.path("output");
        let pending: MemberOutput = MemberOutput::pending(&out_path).unwrap();
        let stage: PathBuf = pending.artifact.path().to_owned();
        let original: PathBuf = fixture.directory.join("retained-stage");
        std::fs::rename(&stage, &original).unwrap();
        std::fs::write(&stage, b"other inode").unwrap();
        drop(pending);
        assert_eq!(std::fs::read(&stage).unwrap(), b"other inode");
        assert_eq!(std::fs::read(&original).unwrap(), Vec::<u8>::new());
        assert_absent(&out_path);
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_output_is_preserved_and_rejected_before_requests() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        let signed: Vec<u8> = encode_signed_paid_intent(&fixture.signed).unwrap();
        std::fs::write(&signed_path, &signed).unwrap();
        std::os::unix::fs::symlink(&signed_path, &out_path).unwrap();
        let target: Client<FakeTransport> = Client::new(FakeTransport::new(Vec::new()));
        assert!(execute_fixture(&fixture, &target, &signed_path, &out_path).is_err());
        assert!(target.transport().requests().is_empty());
        assert_eq!(
            std::fs::read_link(&out_path).unwrap(),
            PathBuf::from(&signed_path)
        );
        assert_eq!(std::fs::read(&signed_path).unwrap(), signed);
        assert_no_pending(&fixture);
    }

    #[test]
    fn failed_attempts_leave_no_output_so_the_identical_rerun_saves_the_original() {
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("signed");
        let out_path: String = fixture.path("output");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        let offline: Client<FakeTransport> = Client::new(FakeTransport::new(Vec::new()));
        let not_ready: Client<FakeTransport> = Client::new(FakeTransport::new(vec![
            Ok(WireResponse {
                status: 200,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body: retained_bundle(&fixture, PaidExecutionStatus::Success),
            }),
            Ok(WireResponse {
                status: 409,
                content_type: Some("text/plain; charset=utf-8".to_owned()),
                body: b"drain-member-not-ready".to_vec(),
            }),
        ]));
        let uncertified: Client<FakeTransport> = endpoint(
            &fixture,
            PaidExecutionStatus::Success,
            response(&fixture, PaidExecutionStatus::ApplicationFailed),
        );
        for failed in [&offline, &not_ready, &uncertified] {
            assert!(
                execute(
                    failed,
                    &fixture.certifier,
                    &fixture.resolver,
                    &fixture.signed.intent.context,
                    fixture.expected.domain(),
                    &signed_path,
                    &out_path,
                    budget()
                )
                .is_err()
            );
            assert!(!Path::new(&out_path).exists());
        }
        assert_eq!(not_ready.transport().requests().len(), 2);
        let body: Vec<u8> = response(&fixture, PaidExecutionStatus::Success);
        let target: Client<FakeTransport> =
            endpoint(&fixture, PaidExecutionStatus::Success, body.clone());
        execute(
            &target,
            &fixture.certifier,
            &fixture.resolver,
            &fixture.signed.intent.context,
            fixture.expected.domain(),
            &signed_path,
            &out_path,
            budget(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), body);
        assert_eq!(target.transport().requests().len(), 2);
    }
}
