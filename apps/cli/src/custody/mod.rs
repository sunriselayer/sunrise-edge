//! Publication-only, protected local OS custody (DR-0238; see
//! `docs/architecture/local-publication-custody.md`).
//!
//! Trusted local OS/root, key held in a separate process under a distinct
//! UID. One publication family only: no generic `ExternalSigner`, no
//! automatic/consensus/genesis signing route, and no network-facing HTTP
//! endpoint. At-rest encryption and compromised-root resistance are
//! explicitly NOT claimed by this first OS-permission model.
//!
//! - `custody keygen` generates custody's own private key file.
//! - `custody approve` is the only writer of approval records, and the only
//!   human-review entry point.
//! - `custody serve` is a bounded-lifetime, one-request-at-a-time signer
//!   that only ever reads the approval store.
//!
//! The publication CLI client leg lives in [`client`] and is consumed by
//! `commands/publication.rs` through [`SignerSelection::Custody`]
//! (`crate::signer`); it is not a generic frame-signing route.

mod approvals;
mod approve;
pub(crate) mod client;
mod config;
pub(crate) mod error;
mod fsperm;
mod keyfile;
mod keygen;
mod selfuid;
mod server;
pub(crate) mod wire;

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::args::{ArgsError, ParsedArgs, parse_flags, scalar};
use crate::error::CliError;
use crate::parse::parse_u32;

pub(crate) use client::{CustodyTarget, request_signature};
pub(crate) use error::CustodyError;

const CONFIG: &str = "--config";
const KEY_FILE: &str = "--key-file";
const SOCKET: &str = "--socket";
const APPROVALS_DIR: &str = "--approvals-dir";
const MAX_CONNECTIONS: &str = "--max-connections";
const MAX_REQUESTS: &str = "--max-requests";
const TOTAL_DEADLINE_SECS: &str = "--total-deadline-secs";

pub(crate) fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let action: OsString = args.next().ok_or(CliError::MissingCustodyAction)?;
    let action: &str = action.to_str().ok_or(ArgsError::NonUtf8Token)?;
    match action {
        "keygen" => keygen::run(args),
        "approve" => approve::run(args),
        "serve" => run_serve(args),
        other => Err(CliError::UnknownCustodyAction(other.to_string())),
    }
}

fn run_serve<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let specs = vec![
        scalar(CONFIG),
        scalar(KEY_FILE),
        scalar(SOCKET),
        scalar(APPROVALS_DIR),
        scalar(MAX_CONNECTIONS),
        scalar(MAX_REQUESTS),
        scalar(TOTAL_DEADLINE_SECS),
    ];
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config = config::CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let signer = keyfile::load_signer(Path::new(parsed.require(KEY_FILE)?))?;
    let socket_path = Path::new(parsed.require(SOCKET)?);
    let approvals_dir = Path::new(parsed.require(APPROVALS_DIR)?);
    let bounds = server::ServeBounds {
        max_connections: parse_u32(MAX_CONNECTIONS, parsed.require(MAX_CONNECTIONS)?)?,
        max_requests: parse_u32(MAX_REQUESTS, parsed.require(MAX_REQUESTS)?)?,
        total_deadline: Duration::from_secs(
            parse_u32(TOTAL_DEADLINE_SECS, parsed.require(TOTAL_DEADLINE_SECS)?)?.into(),
        ),
    };
    let summary = server::run(config, signer, socket_path, approvals_dir, bounds)?;
    println!("connections_accepted={}", summary.connections_accepted);
    println!("requests_handled={}", summary.requests_handled);
    println!("requests_signed={}", summary.requests_signed);
    println!("requests_refused={}", summary.requests_refused);
    Ok(())
}
