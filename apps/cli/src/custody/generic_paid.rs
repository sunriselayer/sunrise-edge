//! Endpoint-checked, operation-specific generic paid approval and protected signing.
//! The signer never accepts a caller-supplied signing frame. Both invocations
//! rebuild it from an exact canonical paid intent, custody's own context and
//! fee-policy pin, and a fresh current fee-source query through the configured
//! endpoint before an approval or signature can be produced.

use std::{
    ffi::OsString,
    io::IsTerminal,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use execution::paid_execution::{
    MAX_PAID_FEE_POLICY_BYTES, MAX_PAID_INTENT_BYTES, decode_paid_intent, encode_paid_intent,
};
use sunrise_edge_client::{
    Client, ExpectedProtocolContext, HashSuiteResolver, LocalSigner, PaidExecutionReview,
    PreparedPaidExecution, RequestId, Transport, decode_paid_fee_policy, encode_paid_fee_policy,
    encode_signed_paid_intent,
};

use crate::{
    args::{ParsedArgs, scalar},
    error::CliError,
    net::{connect_paid_execution, tls_flag_specs},
    parse::parse_u64,
};

use super::{
    approvals::{self, ApprovalRecord},
    config::CustodyConfig,
    error::CustodyError,
    fsperm::read_private_file,
};

const CONFIG: &str = "--config";
const POLICY: &str = "--policy-file";
const REQUEST: &str = "--request-file";
const APPROVALS: &str = "--approvals-dir";
const ENDPOINT: &str = "--endpoint";

fn fail(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    fail(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn specs() -> Vec<crate::args::FlagSpec> {
    let mut out = vec![
        scalar(CONFIG),
        scalar(POLICY),
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar(ENDPOINT),
    ];
    out.extend(tls_flag_specs());
    out
}

fn read_pins(parsed: &ParsedArgs) -> Result<(CustodyConfig, Vec<u8>, Vec<u8>), CliError> {
    let config = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let policy = read_private_file(
        Path::new(parsed.require(POLICY)?),
        0o600,
        0o700,
        MAX_PAID_FEE_POLICY_BYTES,
    )?;
    let request = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        MAX_PAID_INTENT_BYTES,
    )?;
    Ok((config, policy, request))
}

/// Rebuild one paid owner under custody's pinned context and fee policy.
/// The node is consulted under the configured transport/context for current
/// policy and fee-source bytes; its response cannot replace either local pin.
pub(super) fn prepare<T: Transport>(
    client: &Client<T>,
    config: &CustodyConfig,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    policy_bytes: &[u8],
    request_bytes: &[u8],
) -> Result<(PreparedPaidExecution, PaidExecutionReview, RequestId), CliError> {
    let policy = decode_paid_fee_policy(policy_bytes).map_err(fail)?;
    if encode_paid_fee_policy(&policy).map_err(fail)? != policy_bytes {
        return Err(invalid("pinned paid policy is not canonical"));
    }
    let intent = decode_paid_intent(request_bytes).map_err(fail)?;
    if encode_paid_intent(&intent).map_err(fail)? != request_bytes {
        return Err(invalid("paid request is not canonical"));
    }
    if intent.sender != *config.publisher().as_bytes() {
        return Err(invalid("paid sender differs from custody publisher"));
    }
    let installed = client.query_paid_fee_policy(resolver, expected)?;
    if installed != policy {
        return Err(invalid("installed paid policy differs from custody pin"));
    }
    client.validate_paid_fee_source_for_owner(
        config.publisher(),
        resolver,
        expected,
        &policy,
        &intent.consent,
    )?;
    let request_id = RequestId::new(intent.request_id).map_err(fail)?;
    let prepared = PreparedPaidExecution::prepare(
        config.publisher(),
        resolver,
        expected,
        &policy,
        intent.consent,
        intent.application,
        request_id,
        intent.nonce,
        intent.gas_limit,
        intent.authorizations,
    )?;
    let review = PaidExecutionReview::build(&prepared).map_err(fail)?;
    if review.intent_bytes() != request_bytes || review.policy_bytes() != policy_bytes {
        return Err(invalid("paid request differs from custody reconstruction"));
    }
    Ok((prepared, review, request_id))
}

fn load_context(
    parsed: &ParsedArgs,
    schedules: Vec<sunrise_edge_client::HashSuiteSchedule>,
    config: &CustodyConfig,
) -> Result<(ExpectedProtocolContext, HashSuiteResolver), CliError> {
    let expected = config.expected_context()?;
    let resolver = crate::commands::hash_suite_pins::publication_resolver(&expected, schedules)?;
    // The admin chooses the transport; the node cannot supply replay pins.
    let _ = parsed.require(ENDPOINT)?;
    Ok((expected, resolver))
}

pub(super) fn approve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags = specs();
    flags.push(scalar("--expires-in-seconds"));
    let (parsed, schedules) = crate::commands::hash_suite_pins::parse_pinned_flags(args, &flags)?;
    let (config, policy_bytes, request_bytes) = read_pins(&parsed)?;
    let (expected, resolver) = load_context(&parsed, schedules, &config)?;
    let client = connect_paid_execution(parsed.require(ENDPOINT)?, &parsed)?;
    let (prepared, review, request_id) = prepare(
        &client,
        &config,
        &resolver,
        &expected,
        &policy_bytes,
        &request_bytes,
    )?;
    let approvals = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    let expires = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    let not_after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs()
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    let confirmation = format!(
        "APPROVE-PAID sender={} request_id={} nonce={} policy={} fee_source={} max_fee={} not_after={not_after}",
        config.publisher(),
        request_id,
        prepared.intent().nonce,
        prepared.intent().fee_policy_digest,
        prepared.intent().consent.source.id,
        prepared.intent().consent.max_fee.get(),
    );
    print!("{}", review.text());
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(2048)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    if super::revoke::is_revoked(approvals, &request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    approvals::write_approval(
        approvals,
        &request_id,
        &ApprovalRecord {
            publisher: config.publisher(),
            not_after_unix_seconds: not_after,
            frame: prepared.signable_frame().to_vec(),
        },
    )?;
    println!("approved_paid=true\nrequest_id={request_id}\nnot_after={not_after}");
    Ok(())
}

/// Checks the exact persisted approval and revocation before signing the
/// independently rebuilt owner. Used only by the custody UID command.
pub(super) fn sign_approved(
    signer: &LocalSigner,
    config: &CustodyConfig,
    approvals_dir: &Path,
    request_id: &RequestId,
    prepared: PreparedPaidExecution,
) -> Result<sunrise_edge_client::SignedPaidIntent, CliError> {
    if signer.address() != config.publisher() {
        return Err(CustodyError::KeyFileAddressMismatch.into());
    }
    let approval = approvals::read_approval(approvals_dir, request_id)?
        .ok_or_else(|| invalid("no approval for paid request"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs();
    let revoked = super::revoke::is_revoked(approvals_dir, request_id)?;
    if !approval_matches(
        &approval,
        config.publisher(),
        prepared.signable_frame(),
        now,
        revoked,
    ) {
        return Err(invalid(
            "paid approval is expired, revoked, or differs from the request",
        ));
    }
    prepared
        .sign_and_finalize_with(signer)
        .map_err(CliError::from)
}

fn approval_matches(
    approval: &ApprovalRecord,
    publisher: sunrise_edge_client::Address,
    exact_frame: &[u8],
    now: u64,
    revoked: bool,
) -> bool {
    !revoked
        && !approvals::is_expired(approval, now)
        && approval.publisher == publisher
        && approval.frame == exact_frame
}

pub(super) fn sign<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags = specs();
    flags.extend([scalar("--key-file"), scalar("--out")]);
    let (parsed, schedules) = crate::commands::hash_suite_pins::parse_pinned_flags(args, &flags)?;
    let output = Path::new(parsed.require("--out")?);
    super::check_review_preimage_destination(output)?;
    let (config, policy_bytes, request_bytes) = read_pins(&parsed)?;
    let (expected, resolver) = load_context(&parsed, schedules, &config)?;
    let client = connect_paid_execution(parsed.require(ENDPOINT)?, &parsed)?;
    let (prepared, _review, request_id) = prepare(
        &client,
        &config,
        &resolver,
        &expected,
        &policy_bytes,
        &request_bytes,
    )?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let signed = sign_approved(
        &signer,
        &config,
        Path::new(parsed.require(APPROVALS)?),
        &request_id,
        prepared,
    )?;
    let bytes = encode_signed_paid_intent(&signed).map_err(fail)?;
    super::write_review_preimage(output, &bytes)?;
    println!("signed_paid_exported=true\nrequest_id={request_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunrise_edge_client::Address;

    #[test]
    fn paid_approval_requires_same_publisher_whole_frame_and_live_record() {
        let publisher = Address::new([7; 32]);
        let approval = ApprovalRecord {
            publisher,
            not_after_unix_seconds: 100,
            frame: vec![1, 2, 3],
        };
        assert!(approval_matches(
            &approval,
            publisher,
            &[1, 2, 3],
            99,
            false
        ));
        assert!(!approval_matches(
            &approval,
            publisher,
            &[1, 2, 3],
            100,
            false
        ));
        assert!(!approval_matches(
            &approval,
            publisher,
            &[1, 2, 3],
            99,
            true
        ));
        assert!(!approval_matches(
            &approval,
            publisher,
            &[1, 2, 4],
            99,
            false
        ));
        assert!(!approval_matches(
            &approval,
            Address::new([8; 32]),
            &[1, 2, 3],
            99,
            false
        ));
    }
}
