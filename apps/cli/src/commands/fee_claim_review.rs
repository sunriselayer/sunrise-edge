//! Offline review and development signing of saved canonical fee-claim inputs.
//! This is a content-inspection surface, never protected approval or row authority.

use std::{error::Error, ffi::OsString, path::Path};

use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion};
use sunrise_edge_client::{
    FeeClaimIntent, FeeClaimPrepareRequest, FeeClaimReview, HashSuiteResolver, HashSuiteSchedule,
    MAX_FEE_CLAIM_INTENT_BYTES, MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES, PreparedFeeClaim,
    PublicationContext, SuccessorWorkflowAuthority,
};

use super::network_artifacts::{ReservedArtifact, artifact_path, read_bounded, reserve_artifacts};
use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::parse_u64,
};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Mutually exclusive prepare modes. Selecting review never reads a seed or
/// falls back to signing when any export argument is missing.
pub(super) enum PrepareMode<'a> {
    Development,
    Review {
        public_key: [u8; 32],
        request_out: &'a str,
        intent_out: &'a str,
    },
}

pub(super) fn prepare_mode(parsed: &ParsedArgs) -> Result<PrepareMode<'_>, CliError> {
    let review: bool = [
        "--claimant-public-key",
        "--review-request-out",
        "--review-intent-out",
    ]
    .iter()
    .any(|flag: &&str| parsed.get(flag).is_some());
    if !review {
        // Missing development flags fail before policy, output or key I/O.
        parsed.require("--claimant-seed-file")?;
        parsed.require("--created-checkpoint")?;
        parsed.require("--out")?;
        return Ok(PrepareMode::Development);
    }
    if ["--claimant-seed-file", "--created-checkpoint", "--out"]
        .iter()
        .any(|flag: &&str| parsed.get(flag).is_some())
    {
        return Err(invalid(
            "fee-claim review exports cannot be mixed with development signing flags",
        ));
    }
    let public_key: [u8; 32] = decode_hex_32(
        "--claimant-public-key",
        parsed.require("--claimant-public-key")?,
    )?;
    let request_out: &str = parsed.require("--review-request-out")?;
    let intent_out: &str = parsed.require("--review-intent-out")?;
    // Resolve aliases before a peer call; the private writer still performs
    // its own strict permission/ownership and exclusive-publication checks.
    if artifact_path(request_out)? == artifact_path(intent_out)? {
        return Err(invalid(
            "fee-claim request and intent export paths must differ",
        ));
    }
    crate::custody::check_review_preimage_destination(Path::new(request_out))?;
    crate::custody::check_review_preimage_destination(Path::new(intent_out))?;
    Ok(PrepareMode::Review {
        public_key,
        request_out,
        intent_out,
    })
}

pub(super) fn export_review(
    prepared: &PreparedFeeClaim<'_>,
    request_out: &str,
    intent_out: &str,
) -> Result<(), CliError> {
    let review: FeeClaimReview = FeeClaimReview::build(prepared).map_err(failure)?;
    let request: Vec<u8> = prepared.request().encode().map_err(failure)?;
    let intent: Vec<u8> =
        sunrise_edge_client::encode_fee_claim_intent(prepared.intent()).map_err(failure)?;
    crate::custody::write_review_preimage(Path::new(request_out), &request)?;
    crate::custody::write_review_preimage(Path::new(intent_out), &intent).map_err(|error| {
        failure(std::io::Error::other(format!(
            "request review preimage was published; intent export failed: {error}; retain the request and choose a new complete pair"
        )))
    })?;
    print!("{}", review.render_text());
    println!(
        "review_request_bytes={} review_intent_bytes={} signed=false",
        request.len(),
        intent.len()
    );
    Ok(())
}

fn flag_specs(sign: bool) -> Vec<FlagSpec> {
    let mut flags: Vec<FlagSpec> = vec![
        scalar("--request"),
        scalar("--intent"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--domain"),
        scalar("--ordered-genesis-manifest"),
        scalar("--ordered-expected-genesis-digest"),
    ];
    flags.extend(super::successor_pins::successor_flag_specs(false));
    if sign {
        flags.extend([
            scalar("--claimant-seed-file"),
            scalar("--created-checkpoint"),
            scalar("--out"),
        ]);
    }
    flags
}

fn load_workflow(
    parsed: &ParsedArgs,
    schedules: Vec<HashSuiteSchedule>,
) -> Result<SuccessorWorkflowAuthority, CliError> {
    let chain: ChainId = ChainId::new(parsed.require("--expected-chain-id")?).map_err(failure)?;
    let protocol: ProtocolVersion = ProtocolVersion::new(crate::parse::parse_u32(
        "--expected-protocol-version",
        parsed.require("--expected-protocol-version")?,
    )?);
    let epoch: Epoch = Epoch::new(parse_u64(
        "--expected-epoch",
        parsed.require("--expected-epoch")?,
    )?);
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol, epoch).map_err(failure)?;
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(decode_hex_32("--domain", parsed.require("--domain")?)?)
            .map_err(failure)?;
    let digest: [u8; 32] = decode_hex_32(
        "--ordered-expected-genesis-digest",
        parsed.require("--ordered-expected-genesis-digest")?,
    )?;
    let resolver: HashSuiteResolver = if schedules.is_empty() {
        super::ordered_economics_network::genesis_hash_suite_resolver(chain, protocol)?
    } else {
        HashSuiteResolver::new(chain, protocol, schedules).map_err(failure)?
    };
    super::successor_pins::load_successor_pins(
        parsed,
        parsed.require("--ordered-genesis-manifest")?,
        digest,
        &resolver,
        &context,
        Some(domain),
    )?
    .ok_or_else(|| invalid("fee-claim review/sign requires the --successor-* artifact flags"))
}

fn decode_saved(
    request: &[u8],
    intent: &[u8],
) -> Result<(FeeClaimPrepareRequest, FeeClaimIntent), CliError> {
    let request_frame: FeeClaimPrepareRequest =
        FeeClaimPrepareRequest::decode(request).map_err(failure)?;
    let intent_frame: FeeClaimIntent =
        sunrise_edge_client::decode_fee_claim_intent(intent).map_err(failure)?;
    if request_frame.encode().map_err(failure)? != request
        || sunrise_edge_client::encode_fee_claim_intent(&intent_frame).map_err(failure)? != intent
    {
        return Err(invalid(
            "fee-claim saved inputs must be exact canonical bytes",
        ));
    }
    Ok((request_frame, intent_frame))
}

pub(super) fn run<I: IntoIterator<Item = OsString>>(args: I, sign: bool) -> Result<(), CliError> {
    let (parsed, schedules) = super::hash_suite_pins::parse_pinned_flags(args, &flag_specs(sign))?;
    if !super::successor_pins::successor_requested(&parsed) {
        return Err(invalid(
            "fee-claim review/sign requires the --successor-* artifact flags",
        ));
    }
    let request_path: &str = parsed.require("--request")?;
    let intent_path: &str = parsed.require("--intent")?;
    let checkpoint: Option<u64> = if sign {
        parsed.require("--claimant-seed-file")?;
        parsed.require("--out")?;
        Some(parse_u64(
            "--created-checkpoint",
            parsed.require("--created-checkpoint")?,
        )?)
    } else {
        None
    };
    let workflow: SuccessorWorkflowAuthority = load_workflow(&parsed, schedules)?;
    let request_bytes: Vec<u8> = read_bounded(request_path, MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES)?;
    let intent_bytes: Vec<u8> = read_bounded(intent_path, MAX_FEE_CLAIM_INTENT_BYTES)?;
    let (request, intent): (FeeClaimPrepareRequest, FeeClaimIntent) =
        decode_saved(&request_bytes, &intent_bytes)?;
    let prepared: PreparedFeeClaim<'_> =
        PreparedFeeClaim::prepare(&workflow, &request, intent).map_err(failure)?;
    // Refuse unreadable/malformed/unbounded review before any seed is loaded.
    let review: FeeClaimReview = FeeClaimReview::build(&prepared).map_err(failure)?;
    let Some(checkpoint) = checkpoint else {
        print!("{}", review.render_text());
        return Ok(());
    };
    let out: &str = parsed.require("--out")?;
    let seed: [u8; 32] =
        crate::seed::load_dev_seed(Path::new(parsed.require("--claimant-seed-file")?))
            .map_err(failure)?;
    let signer: sunrise_edge_client::LocalSigner =
        sunrise_edge_client::LocalSigner::from_seed(seed);
    let signed: Vec<u8> = prepared.sign_and_finalize_with(&signer).map_err(failure)?;
    let encoded: Vec<u8> =
        sunrise_edge_client::fee_claim_candidate(&workflow, request.request_id, signed, checkpoint)
            .map_err(failure)?;
    let candidate = sunrise_edge_client::ordered_economics_core::decode_ordered_candidate(&encoded)
        .map_err(failure)?;
    sunrise_edge_client::ordered_economics_client::authenticate_ordered_candidate(
        workflow.ordered_policy(),
        &candidate,
    )
    .map_err(failure)?;
    let mut reservations: Vec<ReservedArtifact> = reserve_artifacts(
        &[(out, "ordered-economics-candidate")],
        &[
            request_path,
            intent_path,
            parsed.require("--ordered-genesis-manifest")?,
            parsed.require("--claimant-seed-file")?,
        ],
    )?;
    let mut artifact: ReservedArtifact = reservations
        .pop()
        .ok_or_else(|| invalid("missing fee-claim output reservation"))?;
    artifact.persist(&encoded)?;
    println!(
        "fee_claim_candidate_bytes={} out={out} epoch={}",
        encoded.len(),
        workflow.expected_context().epoch().get()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_flags;

    fn prepare_flags(values: &[&str]) -> ParsedArgs {
        let specs: Vec<FlagSpec> = [
            "--claimant-public-key",
            "--review-request-out",
            "--review-intent-out",
            "--claimant-seed-file",
            "--created-checkpoint",
            "--out",
        ]
        .into_iter()
        .map(scalar)
        .collect();
        parse_flags(values.iter().map(OsString::from), &specs).unwrap()
    }

    #[test]
    fn review_selection_never_falls_back_to_seed_io() {
        let mixed: ParsedArgs = prepare_flags(&[
            "--claimant-public-key",
            "bad",
            "--claimant-seed-file",
            "/missing/key",
        ]);
        assert!(
            prepare_mode(&mixed)
                .err()
                .unwrap()
                .to_string()
                .contains("cannot be mixed")
        );
        for missing in [
            vec![],
            vec!["--review-request-out", "/missing/request"],
            vec!["--claimant-public-key", "bad"],
        ] {
            assert!(prepare_mode(&prepare_flags(&missing)).is_err());
        }
    }

    #[test]
    fn offline_review_cannot_accept_network_or_seed_flags() {
        for flag in [
            "--ordered-network",
            "--prepare-peer",
            "--claimant-seed-file",
        ] {
            assert!(run([OsString::from(flag), OsString::from("/missing")], false).is_err());
        }
        assert!(
            run(Vec::<OsString>::new(), false)
                .unwrap_err()
                .to_string()
                .contains("--successor-*")
        );
    }

    fn sample_saved() -> (Vec<u8>, Vec<u8>) {
        use sunrise_edge_client::{
            Address, Digest32, HashAlgorithmId, ObjectId, ObjectRef, ValidatorId,
        };
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("fee-review-structural-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(1),
        )
        .unwrap();
        let request: FeeClaimPrepareRequest = FeeClaimPrepareRequest {
            context: context.clone(),
            request_id: [1; 32],
            escrow_request_id: [2; 32],
            validator_id: ValidatorId::new([3; 32]),
            claimant_public_key: [4; 32],
            recipient: Address::new([5; 32]),
            signed_leg: None,
        };
        let intent: FeeClaimIntent = FeeClaimIntent {
            context,
            request_id: [1; 32],
            escrow_request_id: [2; 32],
            certificate_epoch: Epoch::new(0),
            validator_id: request.validator_id,
            resource_id: sunrise_edge_client::bond_registration::BondResourceId::new(1, [6; 32])
                .unwrap(),
            expected_generation: 7,
            expected_fee_output: ObjectRef {
                id: ObjectId::new([8; 32]),
                version: 9,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [10; 32]),
            },
            expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
            expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
            share_amount: 0,
            recipient: request.recipient,
            operation: sunrise_edge_client::FeeClaimOperation::ZeroShare,
        };
        (
            request.encode().unwrap(),
            sunrise_edge_client::encode_fee_claim_intent(&intent).unwrap(),
        )
    }

    #[test]
    fn saved_decoder_preserves_canonical_bytes_and_refuses_trailing_or_malformed_frames() {
        // Structural only: no verified committee or authority is manufactured.
        let (request, intent): (Vec<u8>, Vec<u8>) = sample_saved();
        let (decoded_request, decoded_intent): (FeeClaimPrepareRequest, FeeClaimIntent) =
            decode_saved(&request, &intent).unwrap();
        assert_eq!(decoded_request.encode().unwrap(), request);
        assert_eq!(
            sunrise_edge_client::encode_fee_claim_intent(&decoded_intent).unwrap(),
            intent
        );
        let mut trailing_request: Vec<u8> = request.clone();
        trailing_request.push(0);
        let mut trailing_intent: Vec<u8> = intent.clone();
        trailing_intent.push(0);
        assert!(decode_saved(&trailing_request, &intent).is_err());
        assert!(decode_saved(&request, &trailing_intent).is_err());
        assert!(decode_saved(&vec![0; MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES + 1], &intent).is_err());
        assert!(decode_saved(&request, &vec![0; MAX_FEE_CLAIM_INTENT_BYTES + 1]).is_err());
    }

    #[test]
    fn malformed_saved_frames_refuse_before_any_signer() {
        assert!(decode_saved(&[], &[]).is_err());
        assert!(decode_saved(&[0; 32], &[0; 32]).is_err());
    }
}
