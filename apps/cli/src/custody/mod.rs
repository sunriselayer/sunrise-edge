//! Operation-specific protected local OS custody (DR-0238/0246/0249; see
//! `docs/architecture/local-publication-custody.md`).
//!
//! Trusted local OS/root, key held in a separate process under a distinct
//! UID. Separate publication, genesis Standard Asset transfer, genesis
//! Standard Asset split/merge, and genesis Standard Asset mint/burn
//! invocations: no generic `ExternalSigner`, no automatic/consensus/genesis-
//! authority signing route, and no network-facing HTTP endpoint. At-rest
//! encryption and compromised-root resistance are explicitly NOT claimed by
//! this first OS-permission model.
//!
//! - `custody keygen` generates custody's own private key file.
//! - `custody approve`, `approve-transfer`, `approve-split`, `approve-merge`,
//!   `approve-mint` and `approve-burn` independently review their own
//!   operation family before writing whole-frame approval records.
//! - `custody revoke` durably cancels a request ID without erasing its approval.
//! - `custody serve` is a bounded-lifetime, one-request-at-a-time signer
//!   that only ever reads the approval store.
//! - `custody serve-transfer` uses the same owner with a transfer-only policy.
//! - `custody serve-split-merge` uses the same owner with the DR-0249
//!   split/merge policy, under one closed kind-3 decoder.
//! - `custody serve-mint-burn` uses the same owner with the DR-0253
//!   mint/burn policy, under one closed kind-4 decoder.
//! - `custody prepare-transfer`/`prepare-split`/`prepare-merge`/
//!   `prepare-mint`/`prepare-burn` export preimages without approval;
//!   `sign-transfer`/`sign-split`/`sign-merge`/`sign-mint`/`sign-burn`
//!   finalize an offline, protected paid intent.
//!
//! The publication CLI client leg lives in [`client`] and is consumed by
//! `commands/publication.rs` through [`SignerSelection::Custody`]
//! (`crate::signer`); it is not a generic frame-signing route.

mod approvals;
mod approve;
mod asset_commands;
#[cfg(test)]
mod asset_fixture;
mod asset_mint_burn;
mod asset_mint_burn_commands;
#[cfg(test)]
mod asset_mint_burn_fixture;
#[cfg(test)]
mod asset_mint_burn_tests;
mod asset_mint_burn_wire;
mod asset_split_merge;
mod asset_split_merge_commands;
#[cfg(test)]
mod asset_split_merge_fixture;
#[cfg(test)]
mod asset_split_merge_tests;
mod asset_split_merge_wire;
mod asset_transfer;
#[cfg(test)]
mod asset_transfer_tests;
mod asset_trust;
mod asset_wire;
pub(crate) mod client;
mod config;
pub(crate) mod error;
mod fsperm;
mod keyfile;
mod keygen;
mod revoke;
mod selfuid;
mod server;
pub(crate) mod wire;

use std::ffi::OsString;
use std::path::Path;

use crate::args::{ArgsError, ParsedArgs, parse_flags, scalar};
use crate::error::CliError;
use crate::parse::parse_u32;

pub(crate) use asset_mint_burn::{AssetBurnRequest, AssetMintRequest};
pub(crate) use asset_split_merge::{AssetMergeRequest, AssetSplitRequest};
pub(crate) use asset_transfer::AssetTransferRequest;
pub(crate) use client::{CustodyTarget, request_signature};
pub(crate) use error::CustodyError;

const CONFIG: &str = "--config";
const KEY_FILE: &str = "--key-file";
const SOCKET: &str = "--socket";
const APPROVALS_DIR: &str = "--approvals-dir";
const MAX_CONNECTIONS: &str = "--max-connections";
const MAX_REQUESTS: &str = "--max-requests";
const TOTAL_DEADLINE_SECS: &str = "--total-deadline-secs";

/// Emits an explicitly requested canonical review preimage without overwrite.
/// This creates no approval and shares the custody filesystem policy.
pub(crate) fn write_review_preimage(path: &Path, bytes: &[u8]) -> Result<(), CustodyError> {
    fsperm::write_private_file(path, 0o700, 0o600, bytes, false)
}

/// Read-only preflight for a fresh review export. The exclusive writer repeats
/// the policy at publication; this check is not a reservation or authority.
pub(crate) fn check_review_preimage_destination(path: &Path) -> Result<(), CustodyError> {
    // The writer's own parent resolution: a bare file name is refused here
    // too, rather than passing against the current directory.
    fsperm::require_private_dir(fsperm::parent_of(path)?, 0o700)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(CustodyError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "review preimage destination already exists",
            ),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CustodyError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let action: OsString = args.next().ok_or(CliError::MissingCustodyAction)?;
    let action: &str = action.to_str().ok_or(ArgsError::NonUtf8Token)?;
    match action {
        "keygen" => keygen::run(args),
        "prepare-transfer" => asset_commands::prepare(args),
        "approve" => approve::run(args),
        "revoke" => revoke::run(args),
        "serve" => run_serve(args),
        "approve-transfer" => asset_commands::approve(args),
        "serve-transfer" => asset_commands::serve(args),
        "sign-transfer" => asset_commands::sign(args),
        "prepare-split" => asset_split_merge_commands::prepare_split(args),
        "approve-split" => asset_split_merge_commands::approve_split(args),
        "sign-split" => asset_split_merge_commands::sign_split(args),
        "prepare-merge" => asset_split_merge_commands::prepare_merge(args),
        "approve-merge" => asset_split_merge_commands::approve_merge(args),
        "sign-merge" => asset_split_merge_commands::sign_merge(args),
        "serve-split-merge" => asset_split_merge_commands::serve(args),
        "prepare-mint" => asset_mint_burn_commands::prepare_mint(args),
        "approve-mint" => asset_mint_burn_commands::approve_mint(args),
        "sign-mint" => asset_mint_burn_commands::sign_mint(args),
        "prepare-burn" => asset_mint_burn_commands::prepare_burn(args),
        "approve-burn" => asset_mint_burn_commands::approve_burn(args),
        "sign-burn" => asset_mint_burn_commands::sign_burn(args),
        "serve-mint-burn" => asset_mint_burn_commands::serve(args),
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
    // Pure argument validation first, before any config/key file I/O.
    let bounds = server::ServeBounds::new(
        parse_u32(MAX_CONNECTIONS, parsed.require(MAX_CONNECTIONS)?)?,
        parse_u32(MAX_REQUESTS, parsed.require(MAX_REQUESTS)?)?,
        parse_u32(TOTAL_DEADLINE_SECS, parsed.require(TOTAL_DEADLINE_SECS)?)?,
    )?;
    let config = config::CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let signer = keyfile::load_signer(Path::new(parsed.require(KEY_FILE)?))?;
    let socket_path = Path::new(parsed.require(SOCKET)?);
    let approvals_dir = Path::new(parsed.require(APPROVALS_DIR)?);
    let summary = server::run(config, signer, socket_path, approvals_dir, bounds)?;
    println!("connections_accepted={}", summary.connections_accepted);
    println!("requests_handled={}", summary.requests_handled);
    println!("requests_signed={}", summary.requests_signed);
    println!("requests_refused={}", summary.requests_refused);
    Ok(())
}

#[cfg(test)]
mod review_destination_tests {
    use super::fsperm::test_support::TempDir;
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn fresh_review_export_preflight_refuses_existing_symlink_and_open_parent() {
        let directory: TempDir = TempDir::new(0o700);
        let fresh = directory.child("fresh-review");
        check_review_preimage_destination(&fresh).unwrap();
        assert!(!fresh.exists(), "preflight must not reserve or publish");
        std::fs::write(&fresh, b"retained").unwrap();
        assert!(check_review_preimage_destination(&fresh).is_err());
        assert_eq!(std::fs::read(&fresh).unwrap(), b"retained");
        let alias = directory.child("alias-review");
        symlink(directory.child("absent"), &alias).unwrap();
        assert!(check_review_preimage_destination(&alias).is_err());
        std::fs::set_permissions(
            directory.child(".").as_path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(check_review_preimage_destination(&directory.child("another-review")).is_err());
    }

    /// A bare file name has no explicit parent, so the writer refuses it. The
    /// preflight refuses it identically, before any I/O and whatever the
    /// current directory is, instead of passing and failing after a peer call.
    #[test]
    fn review_export_preflight_refuses_a_bare_file_name_like_the_writer() {
        let bare: &Path = Path::new("bare-review");
        assert!(matches!(
            check_review_preimage_destination(bare),
            Err(CustodyError::NotADirectory(_))
        ));
        assert!(matches!(
            write_review_preimage(bare, b"unused"),
            Err(CustodyError::NotADirectory(_))
        ));
    }
}
