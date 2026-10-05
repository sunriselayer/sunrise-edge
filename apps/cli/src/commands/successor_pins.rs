//! Shared ordered successor-chain client pins (DR-0191 Sections 9 and 12).
//!
//! A successor workflow is selected only by explicit local artifact flags,
//! never by an endpoint response or an epoch hint. When selected, the SDK
//! verifies the complete source-free evidence from the original pinned
//! genesis, schedule and domain plus the four retained artifact
//! directories, and the caller-declared signing context must equal the
//! verified e+1 context before anything is signed. Partial flag sets refuse;
//! there is no ordinary-genesis fallback once any successor flag appears.

use std::{num::NonZeroU32, path::Path};

use protocol_types::{AtomicityDomainId, Epoch};
use sunrise_edge_client::{
    HashSuiteResolver, PublicationContext, SuccessorArtifactDirectories, SuccessorChainBudget,
    SuccessorWorkflowAuthority, load_successor_chain_workflow_from_directories,
};

use crate::{
    args::{FlagSpec, ParsedArgs, repeated, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
};

const GENESIS_EPOCH: &str = "--successor-genesis-epoch";
const DOMAIN: &str = "--successor-domain";
const PLAN_HISTORY: &str = "--successor-plan-history-dir";
const CUT: &str = "--successor-cut-dir";
const MANIFEST_HISTORY: &str = "--successor-manifest-history-dir";
const CERTIFICATE: &str = "--successor-certificate-dir";
const MAX_LINKS: &str = "--successor-max-links";

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
        scalar(MAX_LINKS),
        repeated(PLAN_HISTORY),
        repeated(CUT),
        repeated(MANIFEST_HISTORY),
        repeated(CERTIFICATE),
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
        MAX_LINKS,
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
    let budget: SuccessorChainBudget = successor_budget(parsed)?;
    let plan_histories: &[String] = parsed.many(PLAN_HISTORY);
    let cuts: &[String] = parsed.many(CUT);
    let manifest_histories: &[String] = parsed.many(MANIFEST_HISTORY);
    let certificates: &[String] = parsed.many(CERTIFICATE);
    let directories: Vec<SuccessorArtifactDirectories<'_>> = plan_histories
        .iter()
        .zip(cuts)
        .zip(manifest_histories)
        .zip(certificates)
        .map(
            |(((history, cut), manifest), certificate)| SuccessorArtifactDirectories {
                plan_history: Path::new(history),
                cut: Path::new(cut),
                manifest_history: Path::new(manifest),
                certificate: Path::new(certificate),
            },
        )
        .collect();
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
    let workflow: SuccessorWorkflowAuthority = load_successor_chain_workflow_from_directories(
        Path::new(genesis_manifest),
        resolver,
        expected_genesis_digest,
        &genesis_context,
        domain,
        &directories,
        budget,
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

/// Argument-only all-or-none/count/budget checks. Commands call this before
/// reading signed intent files, keys, genesis or output inventories.
pub(super) fn successor_budget(parsed: &ParsedArgs) -> Result<SuccessorChainBudget, CliError> {
    let max_links: NonZeroU32 = NonZeroU32::new(parse_u32(MAX_LINKS, parsed.require(MAX_LINKS)?)?)
        .ok_or_else(|| invalid("--successor-max-links must be nonzero"))?;
    let budget: SuccessorChainBudget = SuccessorChainBudget::new(max_links);
    let count: usize = parsed.many(PLAN_HISTORY).len();
    if count == 0
        || [CUT, MANIFEST_HISTORY, CERTIFICATE]
            .iter()
            .any(|flag: &&str| parsed.many(flag).len() != count)
    {
        return Err(invalid(
            "successor archive directory flags must be repeated as complete ordered link sets with equal nonzero counts",
        ));
    }
    sunrise_edge_client::successor_artifacts::require_successor_chain_budget(count, budget)
        .map_err(|error| CliError::LocalExecution(Box::new(error)))?;
    Ok(budget)
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
    fn repeated_pins_require_equal_counts_and_explicit_budget_before_io() {
        let complete: [&str; 12] = [
            GENESIS_EPOCH,
            "0",
            MAX_LINKS,
            "1",
            PLAN_HISTORY,
            "/nonexistent/h0",
            CUT,
            "/nonexistent/c0",
            MANIFEST_HISTORY,
            "/nonexistent/m0",
            CERTIFICATE,
            "/nonexistent/r0",
        ];
        let mut values: Vec<OsString> = arguments(&complete);
        values.extend(arguments(&[
            PLAN_HISTORY,
            "/nonexistent/h1",
            CUT,
            "/nonexistent/c1",
            MANIFEST_HISTORY,
            "/nonexistent/m1",
            CERTIFICATE,
            "/nonexistent/r1",
        ]));
        let parsed: ParsedArgs =
            crate::args::parse_flags(values, &successor_flag_specs(true)).unwrap();
        let error: String = successor_budget(&parsed).unwrap_err().to_string();
        assert!(
            error.contains("2 links exceeds the configured budget 1"),
            "{error}"
        );
        let parsed: ParsedArgs = crate::args::parse_flags(
            arguments(&[
                MAX_LINKS,
                "2",
                PLAN_HISTORY,
                "/nonexistent/h0",
                CUT,
                "/nonexistent/c0",
            ]),
            &successor_flag_specs(true),
        )
        .unwrap();
        assert!(
            successor_budget(&parsed)
                .unwrap_err()
                .to_string()
                .contains("equal nonzero counts")
        );
        let parsed: ParsedArgs =
            crate::args::parse_flags(arguments(&[MAX_LINKS, "0"]), &successor_flag_specs(true))
                .unwrap();
        assert!(
            successor_budget(&parsed)
                .unwrap_err()
                .to_string()
                .contains("must be nonzero")
        );
        let parsed: ParsedArgs = crate::args::parse_flags(
            arguments(&[PLAN_HISTORY, "/nonexistent/h0"]),
            &successor_flag_specs(true),
        )
        .unwrap();
        assert!(successor_budget(&parsed).is_err());
    }

    #[test]
    fn successor_controls_require_budget_before_io() {
        let freeze: String = super::super::ordered_economics_network::run(arguments(&[
            "ordered-freeze-build",
            "--successor-cut-dir",
            "/nonexistent/cut",
        ]))
        .unwrap_err()
        .to_string();
        assert!(freeze.contains("--successor-max-links"), "{freeze}");
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
