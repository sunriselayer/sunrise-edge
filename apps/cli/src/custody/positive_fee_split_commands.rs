//! Explicit positive Split consumers. Trust is local; no live request can approve itself.
use super::positive_fee_split::{self as policy, PositiveFeeSplitTrust};
use super::positive_fee_split_wire::{self as wire, LegRequest, Phase, Request};
use super::{config::CustodyConfig, error::CustodyError, fsperm::read_private_file};
use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
    positive_fee_claim_split::{HistoricalClaimantPin, PositiveSplitTerms, RetainedFeeObject},
};
use std::{ffi::OsString, io::IsTerminal, path::Path};
use sunrise_edge_client::{
    Address, Epoch, HashSuiteSchedule, ObjectRef, PublicationContext, RequestId,
    SuccessorWorkflowAuthority, ValidatorId,
};

fn trust_flags() -> Vec<FlagSpec> {
    let mut flags: Vec<FlagSpec> = vec![
        scalar("--config"),
        scalar("--genesis-manifest-file"),
        scalar("--genesis-digest"),
        scalar("--certificate-epoch"),
        scalar("--validator-id"),
    ];
    flags.extend(crate::commands::successor_pins::successor_flag_specs(false));
    flags
}

fn parse<I: IntoIterator<Item = OsString>>(
    args: I,
    flags: &[FlagSpec],
) -> Result<(ParsedArgs, Vec<HashSuiteSchedule>), CliError> {
    crate::commands::hash_suite_pins::parse_pinned_flags(args, flags)
}

fn load_trust(
    parsed: &ParsedArgs,
    schedules: Vec<HashSuiteSchedule>,
    config: &CustodyConfig,
) -> Result<PositiveFeeSplitTrust, CliError> {
    let expected: sunrise_edge_client::ExpectedProtocolContext = config.expected_context()?;
    let resolver: sunrise_edge_client::HashSuiteResolver =
        crate::commands::hash_suite_pins::publication_resolver(&expected, schedules)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(policy::rejected)?;
    let workflow: SuccessorWorkflowAuthority =
        crate::commands::successor_pins::load_successor_pins(
            parsed,
            parsed.require("--genesis-manifest-file")?,
            decode_hex_32("--genesis-digest", parsed.require("--genesis-digest")?)?,
            &resolver,
            &context,
            Some(expected.domain()),
        )?
        .ok_or(CustodyError::PositiveSplitRejected)?;
    let pin: HistoricalClaimantPin = HistoricalClaimantPin {
        certificate_epoch: Epoch::new(parse_u64(
            "--certificate-epoch",
            parsed.require("--certificate-epoch")?,
        )?),
        validator: ValidatorId::new(decode_hex_32(
            "--validator-id",
            parsed.require("--validator-id")?,
        )?),
        public_key: config.publisher(),
    };
    PositiveFeeSplitTrust::new(config, workflow, pin).map_err(Into::into)
}

fn read(path: &str, maximum: usize) -> Result<Vec<u8>, CustodyError> {
    read_private_file(Path::new(path), 0o600, 0o700, maximum)
}

fn read_request(parsed: &ParsedArgs, phase: Phase) -> Result<Request, CliError> {
    let bytes: Vec<u8> = read(parsed.require("--request")?, wire::MAX_REQUEST_BYTES)?;
    let request: Request = wire::decode(&bytes).map_err(CustodyError::Wire)?;
    if request.phase() != phase {
        return Err(CustodyError::PositiveSplitRejected.into());
    }
    Ok(request)
}

fn display(content: &super::positive_fee_split_approvals::Content) -> Result<(), CustodyError> {
    print!(
        "phase={:?}\n{}{}",
        content.phase,
        std::str::from_utf8(&content.trust).map_err(policy::rejected)?,
        std::str::from_utf8(&content.meaning).map_err(policy::rejected)?
    );
    Ok(())
}

pub(super) fn prepare_leg<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags: Vec<FlagSpec> = trust_flags();
    for name in [
        "--fee-object",
        "--fee-ref",
        "--fee-object-hash-epoch",
        "--escrow-request-id",
        "--request-id",
        "--amount",
        "--recipient",
        "--nonce",
        "--gas-limit",
        "--out",
    ] {
        flags.push(scalar(name));
    }
    let (parsed, schedules) = parse(args, &flags)?;
    let output: &Path = Path::new(parsed.require("--out")?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    let trust: PositiveFeeSplitTrust = load_trust(&parsed, schedules, &config)?;
    let reference_bytes: Vec<u8> = read(parsed.require("--fee-ref")?, 1024)?;
    let reference: ObjectRef =
        sunrise_edge_client::decode_object_ref(&reference_bytes).map_err(policy::rejected)?;
    if sunrise_edge_client::encode_object_ref(&reference).map_err(policy::rejected)?
        != reference_bytes
    {
        return Err(CustodyError::PositiveSplitRejected.into());
    }
    let request: Request = Request::Leg(LegRequest {
        terms: PositiveSplitTerms {
            escrow_request_id: decode_hex_32(
                "--escrow-request-id",
                parsed.require("--escrow-request-id")?,
            )?,
            request_id: decode_hex_32("--request-id", parsed.require("--request-id")?)?,
            amount: parse_u64("--amount", parsed.require("--amount")?)?,
            recipient: Address::new(decode_hex_32(
                "--recipient",
                parsed.require("--recipient")?,
            )?),
            nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
            gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
        },
        object: RetainedFeeObject {
            canonical_bytes: read(
                parsed.require("--fee-object")?,
                sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            )?,
            reference,
            hash_epoch: Epoch::new(parse_u64(
                "--fee-object-hash-epoch",
                parsed.require("--fee-object-hash-epoch")?,
            )?),
        },
    });
    let prepared: policy::Prepared<'_> = trust.prepare(&request)?;
    display(&prepared.content)?;
    super::write_review_preimage(output, &wire::encode(&request).map_err(CustodyError::Wire)?)?;
    Ok(())
}

pub(super) fn prepare_claim<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags: Vec<FlagSpec> = trust_flags();
    for name in [
        "--request",
        "--signed-leg",
        "--host-request",
        "--host-intent",
        "--out",
    ] {
        flags.push(scalar(name));
    }
    let (parsed, schedules) = parse(args, &flags)?;
    let output: &Path = Path::new(parsed.require("--out")?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    let trust: PositiveFeeSplitTrust = load_trust(&parsed, schedules, &config)?;
    let Request::Leg(leg) = read_request(&parsed, Phase::Leg)? else {
        return Err(CustodyError::PositiveSplitRejected.into());
    };
    let request: Request = Request::Claim {
        leg,
        signed_leg: read(
            parsed.require("--signed-leg")?,
            sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES,
        )?,
        request: read(
            parsed.require("--host-request")?,
            sunrise_edge_client::MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
        )?,
        intent: read(
            parsed.require("--host-intent")?,
            sunrise_edge_client::MAX_FEE_CLAIM_INTENT_BYTES,
        )?,
    };
    let prepared: policy::Prepared<'_> = trust.prepare(&request)?;
    display(&prepared.content)?;
    super::write_review_preimage(output, &wire::encode(&request).map_err(CustodyError::Wire)?)?;
    Ok(())
}

pub(super) fn approve<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: Phase,
) -> Result<(), CliError> {
    let mut flags: Vec<FlagSpec> = trust_flags();
    flags.extend([
        scalar("--request"),
        scalar("--approvals-dir"),
        scalar("--expires-in-seconds"),
    ]);
    let (parsed, schedules) = parse(args, &flags)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    let trust: PositiveFeeSplitTrust = load_trust(&parsed, schedules, &config)?;
    let request: Request = read_request(&parsed, phase)?;
    let prepared: policy::Prepared<'_> = trust.prepare(&request)?;
    let dir: &Path = Path::new(parsed.require("--approvals-dir")?);
    if super::revoke::is_revoked(dir, &prepared.content.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    prepared.authorize_leg(dir, policy::now()?)?;
    let ttl: u64 = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    let not_after: u64 = policy::now()?
        .checked_add(ttl)
        .filter(|_| ttl > 0)
        .ok_or(CustodyError::ExpiryOverflow)?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    display(&prepared.content)?;
    let confirmation: String = format!(
        "APPROVE-POSITIVE-FEE-SPLIT phase={phase:?} request={} claimant={} not_after={not_after}",
        prepared.content.request_id, prepared.content.claimant
    );
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(1024)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    if policy::now()? >= not_after {
        return Err(CustodyError::ApprovalMalformed.into());
    }
    prepared.authorize_leg(dir, policy::now()?)?;
    super::positive_fee_split_approvals::write(dir, &prepared.content, not_after)?;
    Ok(())
}

pub(super) fn sign<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: Phase,
) -> Result<(), CliError> {
    let mut flags: Vec<FlagSpec> = trust_flags();
    flags.extend([scalar("--request"), scalar("--out")]);
    if phase == Phase::Claim {
        flags.push(scalar("--created-checkpoint"));
    }
    flags.extend(crate::signer::signer_flag_specs());
    let (parsed, schedules) = parse(args, &flags)?;
    let crate::signer::SignerSelection::Custody {
        socket,
        custody_uid,
        expected_public_key,
    } = crate::signer::parse_signer_selection(&parsed)?
    else {
        return Err(CustodyError::PositiveSplitRejected.into());
    };
    let checkpoint: Option<u64> = if phase == Phase::Claim {
        Some(parse_u64(
            "--created-checkpoint",
            parsed.require("--created-checkpoint")?,
        )?)
    } else {
        None
    };
    let output: &Path = Path::new(parsed.require("--out")?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(CustodyError::KeyFileAddressMismatch.into());
    }
    let trust: PositiveFeeSplitTrust = load_trust(&parsed, schedules, &config)?;
    let request: Request = read_request(&parsed, phase)?;
    let id: RequestId = RequestId::new(request.leg().terms.request_id).map_err(policy::rejected)?;
    let prepared: policy::Prepared<'_> = trust.prepare(&request)?;
    let target: super::client::CustodyTarget = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let signature: [u8; 64] =
        super::client::request_positive_fee_split_signature(&target, &request)?;
    let signed: Vec<u8> = prepared.finalize(signature.to_vec())?;
    let bytes: Vec<u8> = if let Some(checkpoint) = checkpoint {
        trust.candidate(id, signed, checkpoint)?
    } else {
        signed
    };
    super::write_review_preimage(output, &bytes)?;
    Ok(())
}

pub(super) fn serve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags: Vec<FlagSpec> = trust_flags();
    for name in [
        "--key-file",
        "--socket",
        "--approvals-dir",
        "--max-connections",
        "--max-requests",
        "--total-deadline-secs",
    ] {
        flags.push(scalar(name));
    }
    let (parsed, schedules) = parse(args, &flags)?;
    let bounds: super::server::ServeBounds = super::server::ServeBounds::new(
        parse_u32("--max-connections", parsed.require("--max-connections")?)?,
        parse_u32("--max-requests", parsed.require("--max-requests")?)?,
        parse_u32(
            "--total-deadline-secs",
            parsed.require("--total-deadline-secs")?,
        )?,
    )?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    let trust: PositiveFeeSplitTrust = load_trust(&parsed, schedules, &config)?;
    // Trust and historical identity are verified before any private key is loaded.
    let signer: sunrise_edge_client::LocalSigner =
        super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary: super::server::ServeSummary = super::server::run_positive_fee_split(
        config,
        signer,
        Path::new(parsed.require("--socket")?),
        Path::new(parsed.require("--approvals-dir")?),
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

/// The selected ignored probe reuses exactly the production local pin loader.
#[cfg(test)]
pub(super) fn fixture_trust(args: Vec<OsString>, expected_config: &Path) -> PositiveFeeSplitTrust {
    let (parsed, schedules): (ParsedArgs, Vec<HashSuiteSchedule>) =
        parse(args, &trust_flags()).unwrap();
    assert_eq!(
        Path::new(parsed.require("--config").unwrap()),
        expected_config
    );
    let config: CustodyConfig = CustodyConfig::load(expected_config).unwrap();
    load_trust(&parsed, schedules, &config).unwrap()
}
