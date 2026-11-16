//! Explicit offline protected ZeroShare fee-claim custody commands
//! (DR-0257); no peer supplies trust pins. The only consumer that actually
//! produces a submittable candidate is the existing `economics
//! fee-claim-sign` with its custody signer flags
//! (`apps/cli/src/commands/fee_claim_review.rs`); this module owns only
//! `approve-fee-claim` and `serve-fee-claim`.

use std::{
    ffi::OsString,
    io::IsTerminal,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use sunrise_edge_client::{
    ExpectedProtocolContext, FeeClaimIntent, FeeClaimPrepareRequest, HashSuiteResolver,
    HashSuiteSchedule, MAX_FEE_CLAIM_INTENT_BYTES, MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
    PublicationContext, SuccessorWorkflowAuthority,
};

use crate::{
    args::{ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
};

use super::{
    approvals::{self, ApprovalRecord},
    config::CustodyConfig,
    error::CustodyError,
    fee_claim_zero::{FeeClaimZeroTrust, PreparedFeeClaimZero},
    fsperm::read_private_file,
};

const CONFIG: &str = "--config";
const GENESIS: &str = "--genesis-manifest-file";
const GENESIS_DIGEST: &str = "--genesis-digest";
const REQUEST: &str = "--request";
const INTENT: &str = "--intent";
const APPROVALS: &str = "--approvals-dir";

fn fail(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    fail(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn trust_specs() -> Vec<crate::args::FlagSpec> {
    let mut specs: Vec<crate::args::FlagSpec> =
        vec![scalar(CONFIG), scalar(GENESIS), scalar(GENESIS_DIGEST)];
    specs.extend(crate::commands::successor_pins::successor_flag_specs(false));
    specs
}

fn load_trust(
    parsed: &ParsedArgs,
    schedules: Vec<HashSuiteSchedule>,
    config: &CustodyConfig,
) -> Result<FeeClaimZeroTrust, CliError> {
    let expected: ExpectedProtocolContext = config.expected_context()?;
    let resolver: HashSuiteResolver =
        crate::commands::hash_suite_pins::publication_resolver(&expected, schedules)?;
    let signing_context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(fail)?;
    let digest: [u8; 32] = decode_hex_32(GENESIS_DIGEST, parsed.require(GENESIS_DIGEST)?)?;
    let workflow: SuccessorWorkflowAuthority =
        crate::commands::successor_pins::load_successor_pins(
            parsed,
            parsed.require(GENESIS)?,
            digest,
            &resolver,
            &signing_context,
            Some(expected.domain()),
        )?
        .ok_or_else(|| invalid("fee-claim custody requires the --successor-* artifact flags"))?;
    Ok(FeeClaimZeroTrust::new(config.clone(), workflow))
}

fn read_request(parsed: &ParsedArgs) -> Result<FeeClaimPrepareRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
    )?;
    let decoded: FeeClaimPrepareRequest = FeeClaimPrepareRequest::decode(&bytes).map_err(fail)?;
    if decoded.encode().map_err(fail)? != bytes {
        return Err(invalid(
            "--request is not the exact canonical FeeClaimPrepareRequest encoding",
        ));
    }
    Ok(decoded)
}

fn read_intent(parsed: &ParsedArgs) -> Result<FeeClaimIntent, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(INTENT)?),
        0o600,
        0o700,
        MAX_FEE_CLAIM_INTENT_BYTES,
    )?;
    let decoded: FeeClaimIntent =
        sunrise_edge_client::decode_fee_claim_intent(&bytes).map_err(fail)?;
    if sunrise_edge_client::encode_fee_claim_intent(&decoded).map_err(fail)? != bytes {
        return Err(invalid(
            "--intent is not the exact canonical FeeClaimIntent encoding",
        ));
    }
    Ok(decoded)
}

fn confirmation_line(review: &sunrise_edge_client::FeeClaimReview, not_after: u64) -> String {
    format!(
        "APPROVE-FEE-CLAIM-ZERO claimant={} validator_id={} certificate_epoch={} context_chain_id={} context_protocol_version={} context_epoch={} request_id={} escrow_request_id={} resource_domain={:#06x} resource_value={} expected_generation={} expected_fee_output_id={} expected_fee_output_version={} expected_fee_output_digest={} expected_previous_row_digest={} expected_next_row_digest={} share_amount=0 recipient={} intent_digest={} not_after={not_after}",
        review.claimant_hex(),
        review.validator_id_hex(),
        review.certificate_epoch(),
        review.chain_id(),
        review.protocol_version(),
        review.epoch(),
        review.request_id_hex(),
        review.escrow_request_id_hex(),
        review.resource_domain(),
        review.resource_value_hex(),
        review.expected_generation(),
        review.expected_fee_output().id_hex(),
        review.expected_fee_output().version(),
        review.expected_fee_output().digest_hex(),
        review.expected_previous_row_digest_hex(),
        review.expected_next_row_digest_hex(),
        review.recipient_hex(),
        review.intent_digest_hex(),
    )
}

pub(super) fn approve_fee_claim<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs: Vec<crate::args::FlagSpec> = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(INTENT),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let (parsed, schedules) = crate::commands::hash_suite_pins::parse_pinned_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let request: FeeClaimPrepareRequest = read_request(&parsed)?;
    let intent: FeeClaimIntent = read_intent(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    let request_id = sunrise_edge_client::RequestId::new(intent.request_id)
        .map_err(|_| CliError::from(CustodyError::ZeroRequestId))?;
    if super::revoke::is_revoked(approvals, &request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let trust: FeeClaimZeroTrust = load_trust(&parsed, schedules, &config)?;
    let prepared: PreparedFeeClaimZero<'_> = trust.prepare_zero_share(&request, intent)?;

    let expires: u64 = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    let not_after: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs()
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    let confirmation: String = confirmation_line(&prepared.review, not_after);

    if super::revoke::is_revoked(approvals, &request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    print!("{}", prepared.render_text());
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(1024)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }

    let record = ApprovalRecord {
        publisher: config.publisher(),
        not_after_unix_seconds: not_after,
        frame: prepared.prepared.signable_frame().to_vec(),
    };
    approvals::write_approval(approvals, &request_id, &record)?;
    println!("approved_fee_claim_zero=true\nrequest_id={request_id}\nnot_after={not_after}");
    Ok(())
}

pub(super) fn serve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs: Vec<crate::args::FlagSpec> = trust_specs();
    for flag in [
        "--key-file",
        "--socket",
        APPROVALS,
        "--max-connections",
        "--max-requests",
        "--total-deadline-secs",
    ] {
        specs.push(scalar(flag));
    }
    let (parsed, schedules) = crate::commands::hash_suite_pins::parse_pinned_flags(args, &specs)?;
    let bounds = super::server::ServeBounds::new(
        parse_u32("--max-connections", parsed.require("--max-connections")?)?,
        parse_u32("--max-requests", parsed.require("--max-requests")?)?,
        parse_u32(
            "--total-deadline-secs",
            parsed.require("--total-deadline-secs")?,
        )?,
    )?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: FeeClaimZeroTrust = load_trust(&parsed, schedules, &config)?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary = super::server::run_fee_claim_zero(
        config,
        signer,
        Path::new(parsed.require("--socket")?),
        Path::new(parsed.require(APPROVALS)?),
        bounds,
        trust,
    )?;
    println!(
        "connections_accepted={}\nrequests_handled={}\nrequests_signed={}\nrequests_refused={}",
        summary.connections_accepted,
        summary.requests_handled,
        summary.requests_signed,
        summary.requests_refused
    );
    Ok(())
}
