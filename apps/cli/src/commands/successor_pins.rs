//! Shared first-successor client pins (DR-0189 Sections 9 and 12).
//!
//! A successor workflow is selected only by explicit local artifact flags,
//! never by an endpoint response or an epoch hint. When selected, the SDK
//! verifies the complete source-free evidence from the original pinned
//! genesis, schedule and domain plus the four retained artifact
//! directories, and the caller-declared signing context must equal the
//! verified e+1 context before anything is signed. Partial flag sets refuse;
//! there is no ordinary-genesis fallback once any successor flag appears.

use std::path::Path;

use protocol_types::{AtomicityDomainId, Epoch};
use sunrise_edge_client::{
    HashSuiteResolver, PublicationContext, SuccessorArtifactDirectories,
    SuccessorWorkflowAuthority, load_successor_workflow_from_directories,
};

use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::parse_u64,
};

const GENESIS_EPOCH: &str = "--successor-genesis-epoch";
const DOMAIN: &str = "--successor-domain";
const PLAN_HISTORY: &str = "--successor-plan-history-dir";
const CUT: &str = "--successor-cut-dir";
const MANIFEST_HISTORY: &str = "--successor-manifest-history-dir";
const CERTIFICATE: &str = "--successor-certificate-dir";

fn invalid(message: impl Into<String>) -> CliError {
    CliError::LocalExecution(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    )))
}

/// Successor flags. A command with its own pinned --domain passes false.
pub(super) fn successor_flag_specs(with_domain: bool) -> Vec<FlagSpec> {
    let mut flags: Vec<FlagSpec> = vec![
        scalar(GENESIS_EPOCH),
        scalar(PLAN_HISTORY),
        scalar(CUT),
        scalar(MANIFEST_HISTORY),
        scalar(CERTIFICATE),
    ];
    if with_domain {
        flags.push(scalar(DOMAIN));
    }
    flags
}

/// Whether any successor flag is present. Commands that support no
/// successor action refuse explicitly when this is true.
pub(super) fn successor_requested(parsed: &ParsedArgs) -> bool {
    [
        GENESIS_EPOCH,
        DOMAIN,
        PLAN_HISTORY,
        CUT,
        MANIFEST_HISTORY,
        CERTIFICATE,
    ]
    .iter()
    .any(|flag: &&str| parsed.get(flag).is_some())
}

/// Loads the verified successor workflow when successor flags are present
/// and requires signing_context to be exactly its verified e+1 context.
/// domain is the command own pinned domain, or None to read the successor
/// domain flag.
pub(super) fn load_successor_pins(
    parsed: &ParsedArgs,
    genesis_manifest: &str,
    expected_genesis_digest: [u8; 32],
    resolver: &HashSuiteResolver,
    signing_context: &PublicationContext,
    domain: Option<AtomicityDomainId>,
) -> Result<Option<SuccessorWorkflowAuthority>, CliError> {
    if !successor_requested(parsed) {
        return Ok(None);
    }
    let genesis_epoch: Epoch =
        Epoch::new(parse_u64(GENESIS_EPOCH, parsed.require(GENESIS_EPOCH)?)?);
    let domain: AtomicityDomainId = match domain {
        Some(domain) => domain,
        None => AtomicityDomainId::new(decode_hex_32(DOMAIN, parsed.require(DOMAIN)?)?)
            .map_err(|_| invalid("--successor-domain must be nonzero"))?,
    };
    let genesis_context: PublicationContext = PublicationContext::new(
        signing_context.chain_id().clone(),
        signing_context.protocol_version(),
        genesis_epoch,
    )
    .map_err(|_| invalid("successor genesis context is invalid"))?;
    let directories: SuccessorArtifactDirectories<'_> = SuccessorArtifactDirectories {
        plan_history: Path::new(parsed.require(PLAN_HISTORY)?),
        cut: Path::new(parsed.require(CUT)?),
        manifest_history: Path::new(parsed.require(MANIFEST_HISTORY)?),
        certificate: Path::new(parsed.require(CERTIFICATE)?),
    };
    let workflow: SuccessorWorkflowAuthority = load_successor_workflow_from_directories(
        Path::new(genesis_manifest),
        resolver,
        expected_genesis_digest,
        &genesis_context,
        domain,
        &directories,
    )
    .map_err(|error| CliError::LocalExecution(Box::new(error)))?;
    workflow
        .require_signing_context(signing_context)
        .map_err(|_| {
            invalid(
                "declared --expected-* context is not the independently verified successor e+1 context",
            )
        })?;
    Ok(Some(workflow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use sunrise_edge_client::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn pins() -> (HashSuiteResolver, PublicationContext) {
        let chain: ChainId = ChainId::new("successor-cli-test").unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain, ProtocolVersion::new(1), Epoch::new(1)).unwrap();
        (resolver, context)
    }

    #[test]
    fn absent_successor_flags_select_no_successor_and_do_no_io() {
        let parsed: ParsedArgs =
            crate::args::parse_flags(arguments(&[]), &successor_flag_specs(true)).unwrap();
        let (resolver, context) = pins();
        assert!(!successor_requested(&parsed));
        assert!(
            load_successor_pins(
                &parsed,
                "/nonexistent/genesis",
                [0; 32],
                &resolver,
                &context,
                None
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn partial_successor_flags_refuse_without_ordinary_fallback() {
        let parsed: ParsedArgs = crate::args::parse_flags(
            arguments(&["--successor-cut-dir", "/nonexistent/cut"]),
            &successor_flag_specs(true),
        )
        .unwrap();
        let (resolver, context) = pins();
        assert!(successor_requested(&parsed));
        assert!(
            load_successor_pins(
                &parsed,
                "/nonexistent/genesis",
                [0; 32],
                &resolver,
                &context,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn unsupported_successor_controls_refuse_explicitly_before_io() {
        let freeze: String = super::super::ordered_economics_network::run(arguments(&[
            "ordered-freeze-build",
            "--successor-cut-dir",
            "/nonexistent/cut",
        ]))
        .unwrap_err()
        .to_string();
        assert!(freeze.contains("successor-control-unsupported"), "{freeze}");
        let claim: String = super::super::ordered_economics_network::run(arguments(&[
            "fee-claim-prepare",
            "--out",
            "/nonexistent/out",
        ]))
        .unwrap_err()
        .to_string();
        assert!(
            claim.contains("requires the --successor-* artifact flags"),
            "{claim}"
        );
    }
}
