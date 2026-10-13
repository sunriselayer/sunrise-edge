//! `custody approve`: the one human-approval entry point.
//!
//! Requires an independently supplied, already-canonical approved artifact
//! file pinned by the custody administrator (never a live caller request),
//! rebuilds the exact publication under custody's own pinned configuration,
//! renders every material field through the existing bounded
//! `PublicationReview` renderer on a real terminal, and requires the
//! operator to type back an exact confirmation line bound to the displayed
//! publisher, artifact digest, nonce, request id, and expiry — not merely a
//! digest prefix. The written approval record binds the *whole* exact
//! signable frame, not only its digest.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sunrise_edge_client::{PreparedPublication, PublicationReview, RequestId};

use crate::args::{ParsedArgs, parse_flags, scalar};
use crate::error::CliError;
use crate::hex::decode_hex_32;
use crate::parse::parse_u64;

use super::approvals::{self, ApprovalRecord};
use super::config::CustodyConfig;
use super::error::CustodyError;
use super::fsperm::read_private_file;
use super::wire::MAX_CUSTODY_ARTIFACT_BYTES;

const CONFIG: &str = "--config";
const APPROVALS_DIR: &str = "--approvals-dir";
const APPROVED_ARTIFACT: &str = "--approved-artifact";
const NONCE: &str = "--nonce";
const REQUEST_ID: &str = "--request-id";
const EXPIRES_IN_SECONDS: &str = "--expires-in-seconds";

/// Required exact mode for the independently pinned `--approved-artifact`
/// preimage file: the same `0600` under `0700` policy as the config and key
/// files, since this file is just as security-sensitive as those (it is the
/// one input the human review and the written approval record trust).
const APPROVED_ARTIFACT_FILE_MODE: u32 = 0o600;
const APPROVED_ARTIFACT_DIR_MODE: u32 = 0o700;

/// Maximum accepted bytes for one typed confirmation line.
const MAX_CONFIRMATION_LINE_BYTES: usize = 1024;

pub(super) fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let specs = vec![
        scalar(CONFIG),
        scalar(APPROVALS_DIR),
        scalar(APPROVED_ARTIFACT),
        scalar(NONCE),
        scalar(REQUEST_ID),
        scalar(EXPIRES_IN_SECONDS),
    ];
    let parsed: ParsedArgs = parse_flags(args, &specs)?;

    let config = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let expected = config.expected_context()?;
    let resolver = sunrise_edge_client::local_publication_resolver(&expected)?;

    let artifact_bytes = read_private_file(
        Path::new(parsed.require(APPROVED_ARTIFACT)?),
        APPROVED_ARTIFACT_FILE_MODE,
        APPROVED_ARTIFACT_DIR_MODE,
        MAX_CUSTODY_ARTIFACT_BYTES,
    )?;
    let artifact = sunrise_edge_client::publication::decode_code_artifact(&artifact_bytes)
        .map_err(|error| CliError::from(CustodyError::Publication(Box::new(error))))?;
    // The preimage must be exactly the canonical encoding of what it
    // decodes to, not merely something that decodes successfully: a
    // decodable-but-non-canonical preimage could let an administrator
    // believe they approved one exact byte sequence while actually
    // approving whatever canonical bytes `encode_code_artifact` produces
    // for the decoded value, which could legitimately differ.
    let reencoded_artifact_bytes =
        sunrise_edge_client::publication::encode_code_artifact(&artifact)
            .map_err(|error| CliError::from(CustodyError::Publication(Box::new(error))))?;
    if reencoded_artifact_bytes != artifact_bytes {
        return Err(CustodyError::ApprovedPreimageNotCanonical.into());
    }
    let nonce = parse_u64(NONCE, parsed.require(NONCE)?)?;
    let request_id = RequestId::new(decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?)?;

    let prepared = PreparedPublication::prepare(
        config.publisher(),
        &resolver,
        &expected,
        artifact,
        nonce,
        request_id,
    )?;
    let review = PublicationReview::build(&prepared)
        .map_err(|error| CliError::from(CustodyError::Publication(Box::new(error))))?;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }

    // The full bounded renderer, every material field, not a digest prefix.
    print!("{}", review.render());

    let expires_in_seconds = parse_u64(EXPIRES_IN_SECONDS, parsed.require(EXPIRES_IN_SECONDS)?)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs();
    let not_after = now
        .checked_add(expires_in_seconds)
        .ok_or(CustodyError::ExpiryOverflow)?;

    let expected_confirmation = format!(
        "APPROVE publisher={} digest={} nonce={} request_id={} not_after={not_after}",
        review.publisher_hex(),
        review.artifact_digest_hex(),
        review.nonce(),
        review.request_id_hex(),
    );
    println!("Type exactly to approve:");
    println!("{expected_confirmation}");
    let typed = read_bounded_confirmation_line(MAX_CONFIRMATION_LINE_BYTES)?;
    if typed != expected_confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }

    let record = ApprovalRecord {
        publisher: config.publisher(),
        not_after_unix_seconds: not_after,
        frame: prepared.signable_frame().to_vec(),
    };
    approvals::write_approval(
        Path::new(parsed.require(APPROVALS_DIR)?),
        &request_id,
        &record,
    )?;

    println!("approved=true");
    println!("request_id={request_id}");
    println!("not_after={not_after}");
    Ok(())
}

/// Reads one line from stdin, bounded to `max_bytes`. Refuses only when that
/// byte bound is exceeded before a newline or end-of-input appears; reaching
/// end-of-input with no trailing newline is *not* itself refused here — the
/// accumulated bytes are returned as-is, and the caller's exact-match
/// confirmation comparison is what rejects an incomplete or wrong line, not
/// a special case for an absent trailing newline.
///
/// This still blocks indefinitely in wall-clock time waiting for the
/// operator to type something: giving a blocking stdin read a time bound
/// without a background thread is not possible with only `std`, and this
/// slice adds no new thread/spawn or dependency to do it. `custody approve`
/// is an attended, interactive operation; its only bound here is on bytes,
/// not time.
fn read_bounded_confirmation_line(max_bytes: usize) -> Result<String, CustodyError> {
    use std::io::Read;
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut buffer: Vec<u8> = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if buffer.len() >= max_bytes {
            return Err(CustodyError::ApprovalConfirmationMismatch);
        }
        let read = handle
            .read(&mut byte)
            .map_err(|_| CustodyError::ApprovalConfirmationMismatch)?;
        if read == 0 || byte[0] == b'\n' {
            break;
        }
        buffer.push(byte[0]);
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    String::from_utf8(buffer).map_err(|_| CustodyError::ApprovalConfirmationMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::fsperm::test_support::TempDir;
    use sunrise_edge_client::{ArtifactParts, CodeArtifact, PackageOrigin, PublicationContext};

    fn write_config(dir: &TempDir, publisher_hex: &str) -> std::path::PathBuf {
        let path = dir.child("config");
        let text = format!(
            "chain_id=sunrise-local-devnet\nprotocol_version=3\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={publisher_hex}\noperator_uid=4242\n",
            "55".repeat(32),
        );
        crate::custody::fsperm::test_support::write_mode_file(
            &path,
            crate::custody::config::CONFIG_FILE_MODE,
            text.as_bytes(),
        );
        path
    }

    fn write_artifact(dir: &TempDir, config: &CustodyConfig) -> std::path::PathBuf {
        let expected = config.expected_context().unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let context = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap();
        let origin = PackageOrigin::unverified(
            expected.chain_id().clone(),
            *config.publisher().as_bytes(),
            [1; 32],
        )
        .unwrap();
        let semantics =
            sunrise_edge_client::local_publication_profile_semantics(&resolver, &context).unwrap();
        let artifact = CodeArtifact::new(ArtifactParts {
            context,
            origin,
            revision: 1,
            wasm_profile: sunrise_edge_client::CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
            semantics,
            wasm: crate::test_support::publication_wasm(),
            unverified_abi: b"fixture-abi-v1".to_vec(),
            exports: vec!["run".to_string()],
            unverified_dependencies: Vec::new(),
        })
        .unwrap();
        let bytes = sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap();
        let path = dir.child("artifact");
        crate::custody::fsperm::test_support::write_mode_file(&path, 0o600, &bytes);
        path
    }

    /// `cargo test`'s stdin/stdout are never a real TTY, so this proves
    /// `approve` reaches and enforces the terminal requirement rather than
    /// approving non-interactively, for an otherwise completely valid
    /// config/artifact/nonce/request-id/expiry input.
    #[test]
    fn approve_refuses_without_a_real_terminal() {
        let config_dir = TempDir::new(0o700);
        let approvals_dir = TempDir::new(super::super::approvals::APPROVALS_DIR_MODE);
        let signer = sunrise_edge_client::LocalSigner::from_seed([0xE1; 32]);
        let publisher_hex = crate::hex::encode_hex(signer.address().as_bytes());
        let config_path = write_config(&config_dir, &publisher_hex);
        let config = CustodyConfig::load(&config_path).unwrap();
        let artifact_path = write_artifact(&config_dir, &config);

        let args: Vec<OsString> = vec![
            OsString::from(CONFIG),
            OsString::from(config_path.to_str().unwrap()),
            OsString::from(APPROVALS_DIR),
            OsString::from(approvals_dir.0.to_str().unwrap()),
            OsString::from(APPROVED_ARTIFACT),
            OsString::from(artifact_path.to_str().unwrap()),
            OsString::from(NONCE),
            OsString::from("1"),
            OsString::from(REQUEST_ID),
            OsString::from("aa".repeat(32)),
            OsString::from(EXPIRES_IN_SECONDS),
            OsString::from("60"),
        ];
        let error = run(args).unwrap_err();
        assert!(matches!(
            error,
            CliError::Custody(inner) if matches!(*inner, CustodyError::ApproveRequiresTerminal)
        ));
    }
}
