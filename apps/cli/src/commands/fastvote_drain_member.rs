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
is a valid saved result, not permission to re-sign or charge again. No complete-drain claim.";

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
    let (mut output, saved): (ReservedArtifact, Option<Vec<u8>>) =
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
                (output, Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut reserved: Vec<ReservedArtifact> =
                    reserve_artifacts(&[(out_path, "drain-member-result")], &[signed_path])?;
                (
                    reserved
                        .pop()
                        .ok_or_else(|| invalid("member output reservation missing"))?,
                    None,
                )
            }
            Err(error) => return Err(failure(error)),
        };
    input.ensure_exact_input(&signed_bytes)?;
    if let Some(bytes) = &saved {
        output.ensure_exact_input(bytes)?;
    } else {
        output.ensure_attached()?;
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
        output.ensure_exact_input(&original)?;
        if bytes != original {
            return Err(invalid(
                "member replay differs from saved original NodeOutput; output not overwritten",
            ));
        }
    } else {
        output.persist(&bytes)?;
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
        NodeResponse, NodeResponseStatus, RequestId, SignatureSchemeId, WireResponse,
        encode_paid_execution_result,
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
        for field in [3u16, 4, 5, 6, 7, 8, 10] {
            witness.field_bytes(field, Vec::new()).unwrap();
        }
        witness.field_u64(11, 1).unwrap();
        witness.field_bytes(12, Vec::new()).unwrap();
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
        let responses = [retained_bundle(fixture, status), bytes]
            .into_iter()
            .map(|body| {
                Ok(WireResponse {
                    status: 200,
                    content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                    body,
                })
            })
            .collect();
        Client::new(FakeTransport::new(responses))
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
        let fixture: Fixture = Fixture::new();
        let signed_path: String = fixture.path("member.signed");
        let out_path: String = fixture.path("member.result");
        std::fs::write(
            &signed_path,
            encode_signed_paid_intent(&fixture.signed).unwrap(),
        )
        .unwrap();
        std::fs::write(&out_path, b"partial").unwrap();
        let target: Client<FakeTransport> = Client::new(FakeTransport::new(Vec::new()));
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
        assert!(target.transport().requests().is_empty());
        assert_eq!(std::fs::read(&out_path).unwrap(), b"partial");
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
        assert_eq!(std::fs::read(&out_path).unwrap(), Vec::<u8>::new());
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
        assert_eq!(std::fs::read(&out_path).unwrap(), Vec::<u8>::new());
    }
}
