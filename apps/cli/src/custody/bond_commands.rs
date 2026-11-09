//! Explicit original-genesis bond review, two-principal approval, protected
//! inner/outer signing, and bounded service entry points. These commands
//! never execute a transfer or claim current chain state.

use std::{ffi::OsString, io::IsTerminal, path::Path};

use protocol_types::HashPurpose;
use sunrise_edge_client::{RequestId, bond_registration::MAX_LOCAL_EXECUTION_INTENT_BYTES};

use super::{
    bond_config::{BondConfig, BondRole},
    bond_inner::BondInnerRequest,
    bond_policy::BondTrust,
    bond_service,
    bond_wire::{self, BondPhase, BondRequest, BrokerMessage},
    error::CustodyError,
    fsperm, keyfile,
    server::ServeBounds,
};
use crate::{
    args::{FlagSpec, ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
};

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

const CONFIG: &str = "--config";
const MANIFEST: &str = "--genesis-manifest";
const REQUEST: &str = "--request";
const OUT: &str = "--out";
const SOCKET: &str = "--socket";
const BROKER_SOCKET: &str = "--broker-socket";
const INNER_WORKER_SOCKET: &str = "--inner-worker-socket";
const OUTER_WORKER_SOCKET: &str = "--outer-worker-socket";
const APPROVALS_DIR: &str = "--approvals-dir";
const KEY_FILE: &str = "--key-file";

fn load(parsed: &ParsedArgs) -> Result<BondTrust, CliError> {
    let config = BondConfig::load(Path::new(parsed.require(CONFIG)?)).map_err(failure)?;
    BondTrust::load(config, Path::new(parsed.require(MANIFEST)?))
}

fn check_role(config: &BondConfig, role: BondRole) -> Result<(), CliError> {
    let uid = fsperm::current_effective_uid().map_err(failure)?;
    config.check_role_uid(role, uid).map_err(failure)
}

fn read_private(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    fsperm::read_private_file(Path::new(path), 0o600, 0o700, maximum).map_err(failure)
}

fn read_request(parsed: &ParsedArgs) -> Result<BondRequest, CliError> {
    let bytes = read_private(parsed.require(REQUEST)?, bond_wire::MAX_REQUEST_BYTES)?;
    bond_wire::decode_request(&bytes).map_err(failure)
}

fn common() -> Vec<FlagSpec> {
    vec![scalar(CONFIG), scalar(MANIFEST)]
}

pub(super) fn prepare_inner<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags = common();
    flags.extend([
        scalar("--source-coin"),
        scalar("--nonce"),
        scalar("--request-id"),
        scalar("--gas-limit"),
        scalar(OUT),
    ]);
    let parsed = parse_flags(args, &flags)?;
    let output = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output).map_err(failure)?;
    let trust = load(&parsed)?;
    check_role(trust.config(), BondRole::Cli)?;
    let request = BondRequest::Inner(BondInnerRequest {
        source_coin_bytes: read_private(
            parsed.require("--source-coin")?,
            sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        )?,
        validator_key: trust.config().validator_key(),
        resource: trust.config().resource(),
        nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
        request_id: RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)
        .map_err(failure)?,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
    });
    let prepared = trust.prepare(&request)?;
    print!("{}", prepared.review);
    super::write_review_preimage(
        output,
        &bond_wire::encode_request(&request).map_err(failure)?,
    )
    .map_err(failure)?;
    println!("prepared_bond_inner_request=true");
    Ok(())
}

pub(super) fn prepare_outer<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags = common();
    flags.extend([
        scalar("--inner-request"),
        scalar("--signed-leg"),
        scalar("--predicted-row"),
        scalar("--request-id"),
        scalar(OUT),
    ]);
    let parsed = parse_flags(args, &flags)?;
    let output = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output).map_err(failure)?;
    let trust = load(&parsed)?;
    check_role(trust.config(), BondRole::Cli)?;
    let inner = bond_wire::decode_request(&read_private(
        parsed.require("--inner-request")?,
        bond_wire::MAX_REQUEST_BYTES,
    )?)
    .map_err(failure)?;
    let BondRequest::Inner(inner) = inner else {
        return Err(invalid(
            "outer preparation needs a typed inner bond request",
        ));
    };
    let request = BondRequest::Outer {
        inner,
        signed_leg: read_private(
            parsed.require("--signed-leg")?,
            MAX_LOCAL_EXECUTION_INTENT_BYTES,
        )?,
        row: read_private(
            parsed.require("--predicted-row")?,
            sunrise_edge_client::bond_registration::MAX_BOND_REGISTRATION_ROW_BYTES,
        )?,
        outer_request_id: RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)
        .map_err(failure)?,
    };
    let prepared = trust.prepare(&request)?;
    print!("{}", prepared.review);
    super::write_review_preimage(
        output,
        &bond_wire::encode_request(&request).map_err(failure)?,
    )
    .map_err(failure)?;
    println!("prepared_bond_outer_request=true");
    Ok(())
}

pub(super) fn approve<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: BondPhase,
) -> Result<(), CliError> {
    let mut flags = common();
    flags.extend([
        scalar(REQUEST),
        scalar(BROKER_SOCKET),
        scalar("--not-after-unix-seconds"),
    ]);
    let parsed = parse_flags(args, &flags)?;
    let trust = load(&parsed)?;
    let role = match phase {
        BondPhase::Inner => BondRole::InnerApprover,
        BondPhase::Outer => BondRole::OuterApprover,
    };
    check_role(trust.config(), role)?;
    let request = read_request(&parsed)?;
    if request.phase() != phase {
        return Err(invalid("bond approval phase differs from the request"));
    }
    let prepared = trust.prepare(&request)?;
    let not_after = parse_u64(
        "--not-after-unix-seconds",
        parsed.require("--not-after-unix-seconds")?,
    )?;
    if super::positive_fee_split::now().map_err(failure)? >= not_after {
        return Err(invalid("bond approval expiry must be in the future"));
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(failure(CustodyError::ApproveRequiresTerminal));
    }
    print!("{}", prepared.review);
    let resolver = trust.config().resolver().map_err(failure)?;
    let digest = resolver
        .hash_for_purpose(
            sunrise_edge_client::Epoch::new(0),
            HashPurpose::Transaction,
            &prepared.content.frame,
        )
        .map_err(failure)?;
    let confirmation = format!(
        "APPROVE-ORIGINAL-BOND phase={phase:?} request={} key={} frame_digest={} not_after={not_after}",
        prepared.content.request_id, prepared.content.expected_key, digest,
    );
    println!("Type exactly to approve:\n{confirmation}");
    let typed = super::approve::read_bounded_confirmation_line(1024).map_err(failure)?;
    if typed != confirmation {
        return Err(failure(CustodyError::ApprovalConfirmationMismatch));
    }
    bond_service::request_broker(
        Path::new(parsed.require(BROKER_SOCKET)?),
        trust.config(),
        &BrokerMessage::Approve {
            request,
            not_after,
            config: trust.config().raw_bytes().to_vec(),
        },
    )?;
    println!("bond_phase_approved=true");
    Ok(())
}

pub(super) fn revoke<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: BondPhase,
) -> Result<(), CliError> {
    let parsed = parse_flags(
        args,
        &[
            scalar(CONFIG),
            scalar(BROKER_SOCKET),
            scalar("--request-id"),
        ],
    )?;
    let config = BondConfig::load(Path::new(parsed.require(CONFIG)?)).map_err(failure)?;
    check_role(
        &config,
        match phase {
            BondPhase::Inner => BondRole::InnerApprover,
            BondPhase::Outer => BondRole::OuterApprover,
        },
    )?;
    let request_id = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)
    .map_err(failure)?;
    bond_service::request_broker(
        Path::new(parsed.require(BROKER_SOCKET)?),
        &config,
        &BrokerMessage::Revoke { phase, request_id },
    )?;
    println!("bond_phase_revoked=true");
    Ok(())
}

pub(super) fn sign<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: BondPhase,
) -> Result<(), CliError> {
    let mut flags = common();
    flags.extend([scalar(REQUEST), scalar(BROKER_SOCKET), scalar(OUT)]);
    let parsed = parse_flags(args, &flags)?;
    let output = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output).map_err(failure)?;
    let trust = load(&parsed)?;
    check_role(trust.config(), BondRole::Cli)?;
    let request = read_request(&parsed)?;
    if request.phase() != phase {
        return Err(invalid("bond signing phase differs from the request"));
    }
    let prepared = trust.prepare(&request)?;
    let signature = bond_service::request_signature_from_broker(
        Path::new(parsed.require(BROKER_SOCKET)?),
        trust.config(),
        &request,
    )?;
    let signed = prepared.finalize(signature.to_vec())?;
    super::write_review_preimage(output, &signed).map_err(failure)?;
    println!("bond_phase_signed={phase:?}");
    println!("executed=false");
    println!("signed_bytes={}", signed.len());
    Ok(())
}

fn bounds(parsed: &ParsedArgs) -> Result<ServeBounds, CliError> {
    ServeBounds::new(
        parse_u32("--max-connections", parsed.require("--max-connections")?)?,
        parse_u32("--max-requests", parsed.require("--max-requests")?)?,
        parse_u32(
            "--total-deadline-secs",
            parsed.require("--total-deadline-secs")?,
        )?,
    )
    .map_err(failure)
}

fn serve_flags() -> Vec<FlagSpec> {
    let mut flags = common();
    flags.extend([
        scalar(SOCKET),
        scalar("--max-connections"),
        scalar("--max-requests"),
        scalar("--total-deadline-secs"),
    ]);
    flags
}

pub(super) fn serve_broker<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut flags = serve_flags();
    flags.extend([
        scalar(APPROVALS_DIR),
        scalar(INNER_WORKER_SOCKET),
        scalar(OUTER_WORKER_SOCKET),
    ]);
    let parsed = parse_flags(args, &flags)?;
    let bounds = bounds(&parsed)?;
    let trust = load(&parsed)?;
    let summary = bond_service::serve_broker(
        &trust,
        Path::new(parsed.require(SOCKET)?),
        Path::new(parsed.require(APPROVALS_DIR)?),
        Path::new(parsed.require(INNER_WORKER_SOCKET)?),
        Path::new(parsed.require(OUTER_WORKER_SOCKET)?),
        bounds,
    )?;
    println!("connections_accepted={}", summary.connections_accepted);
    println!("requests_handled={}", summary.requests_handled);
    println!("requests_refused={}", summary.requests_refused);
    Ok(())
}

pub(super) fn serve_worker<I: IntoIterator<Item = OsString>>(
    args: I,
    phase: BondPhase,
) -> Result<(), CliError> {
    let mut flags = serve_flags();
    flags.push(scalar(KEY_FILE));
    let parsed = parse_flags(args, &flags)?;
    let bounds = bounds(&parsed)?;
    let trust = load(&parsed)?;
    let signer = keyfile::load_signer(Path::new(parsed.require(KEY_FILE)?)).map_err(failure)?;
    let summary = bond_service::serve_worker(
        &trust,
        phase,
        &signer,
        Path::new(parsed.require(SOCKET)?),
        bounds,
    )?;
    println!("connections_accepted={}", summary.connections_accepted);
    println!("requests_handled={}", summary.requests_handled);
    println!("requests_signed={}", summary.requests_signed);
    println!("requests_refused={}", summary.requests_refused);
    Ok(())
}
