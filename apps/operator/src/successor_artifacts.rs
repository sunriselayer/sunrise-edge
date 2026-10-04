//! Successor artifact transport adapter (DR-0189 Section 3.1, Section 12).
//! Owned by the SDK so the operator and successor CLI workflows share one
//! transport; re-exported here for existing operator paths.

pub use sunrise_edge_client::successor_artifacts::{
    MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES, SuccessorArtifactFiles, SuccessorChainArtifactFiles,
    SuccessorLinkArchiveDirectories, bounded_certificate_length, require_successor_chain_budget,
};

use crate::common::FlagSet;
use node_core::serving_authority::SuccessorChainBudget;
use std::{
    error::Error,
    num::NonZeroU32,
    path::{Path, PathBuf},
};

pub(crate) const CHAIN_FLAGS: &[&str] = &[
    "--successor-max-links",
    "--successor-plan-history-dir",
    "--successor-cut-dir",
    "--successor-manifest-history-dir",
    "--successor-certificate-dir",
];

/// Argument-only chain pins. The four path lists are paired in their own
/// occurrence order and must be all present with equal counts. No directory
/// listing, remote response or automatic epoch hint creates a link.
pub(crate) struct SuccessorChainInputs {
    links: Vec<(PathBuf, PathBuf, PathBuf, PathBuf)>,
    pub(crate) budget: SuccessorChainBudget,
}

impl SuccessorChainInputs {
    pub(crate) fn parse_required(flags: &mut FlagSet) -> Result<Self, Box<dyn Error>> {
        Self::parse_roles(
            flags,
            [
                "--ordered-history-dir",
                "--cut-dir",
                "--manifest-history-dir",
                "--certificate-dir",
            ],
        )
    }

    pub(crate) fn parse_optional(flags: &mut FlagSet) -> Result<Option<Self>, Box<dyn Error>> {
        let maximum: Option<String> = flags.optional_one("--successor-max-links")?;
        let histories: Vec<String> = flags.many("--successor-plan-history-dir");
        let cuts: Vec<String> = flags.many("--successor-cut-dir");
        let manifests: Vec<String> = flags.many("--successor-manifest-history-dir");
        let certificates: Vec<String> = flags.many("--successor-certificate-dir");
        if maximum.is_none()
            && histories.is_empty()
            && cuts.is_empty()
            && manifests.is_empty()
            && certificates.is_empty()
        {
            return Ok(None);
        }
        Self::from_values(
            maximum.ok_or("missing required --successor-max-links")?,
            histories,
            cuts,
            manifests,
            certificates,
        )
        .map(Some)
    }

    fn parse_roles(flags: &mut FlagSet, names: [&str; 4]) -> Result<Self, Box<dyn Error>> {
        let maximum: String = flags.one("--successor-max-links")?;
        let histories: Vec<String> = flags.many(names[0]);
        let cuts: Vec<String> = flags.many(names[1]);
        let manifests: Vec<String> = flags.many(names[2]);
        let certificates: Vec<String> = flags.many(names[3]);
        Self::from_values(maximum, histories, cuts, manifests, certificates)
    }

    fn from_values(
        maximum: String,
        histories: Vec<String>,
        cuts: Vec<String>,
        manifests: Vec<String>,
        certificates: Vec<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let maximum: NonZeroU32 = NonZeroU32::new(maximum.parse::<u32>()?)
            .ok_or("--successor-max-links must be nonzero")?;
        let budget: SuccessorChainBudget = SuccessorChainBudget::new(maximum);
        let count: usize = histories.len();
        if count == 0
            || cuts.len() != count
            || manifests.len() != count
            || certificates.len() != count
        {
            return Err("successor archive directory flags require complete ordered link sets with equal nonzero counts".into());
        }
        require_successor_chain_budget(count, budget)?;
        let links: Vec<(PathBuf, PathBuf, PathBuf, PathBuf)> = histories
            .into_iter()
            .zip(cuts)
            .zip(manifests)
            .zip(certificates)
            .map(|(((history, cut), manifest), certificate)| {
                (
                    history.into(),
                    cut.into(),
                    manifest.into(),
                    certificate.into(),
                )
            })
            .collect();
        Ok(Self { links, budget })
    }

    pub(crate) fn first_history(&self) -> &Path {
        &self.links[0].0
    }

    pub(crate) fn open(&self) -> Result<SuccessorChainArtifactFiles, Box<dyn Error>> {
        let directories: Vec<SuccessorLinkArchiveDirectories<'_>> = self
            .links
            .iter()
            .map(
                |(history, cut, manifest, certificate)| SuccessorLinkArchiveDirectories {
                    plan_history: history,
                    cut,
                    manifest_history: manifest,
                    certificate,
                },
            )
            .collect();
        Ok(SuccessorChainArtifactFiles::open(
            &directories,
            self.budget,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn repeated_directory_counts_and_budget_refuse_before_io() {
        let flags: &[&str] = &[
            "--successor-max-links",
            "--ordered-history-dir",
            "--cut-dir",
            "--manifest-history-dir",
            "--certificate-dir",
        ];
        let mut values: Vec<OsString> = vec!["--successor-max-links".into(), "1".into()];
        for _ in 0..2 {
            for flag in &flags[1..] {
                values.push((*flag).into());
                values.push("/nonexistent/chain-budget-before-io".into());
            }
        }
        let mut parsed: FlagSet = FlagSet::parse(values, flags, &[]).unwrap();
        let error: String = SuccessorChainInputs::parse_required(&mut parsed)
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("2 links exceeds the configured budget 1"),
            "{error}"
        );
        let mut parsed: FlagSet = FlagSet::parse(
            [
                "--successor-max-links",
                "2",
                "--cut-dir",
                "/nonexistent/cut",
            ]
            .map(OsString::from),
            flags,
            &[],
        )
        .unwrap();
        assert!(
            SuccessorChainInputs::parse_required(&mut parsed)
                .err()
                .unwrap()
                .to_string()
                .contains("equal nonzero counts")
        );
    }

    #[test]
    fn real_reconstruction_commands_check_chain_budget_before_any_pin_io() {
        let arguments = |mode: &str| -> Vec<OsString> {
            let mut values: Vec<OsString> = [mode, "--successor-max-links", "1"]
                .map(OsString::from)
                .to_vec();
            for _ in 0..2 {
                for flag in &CHAIN_FLAGS[1..] {
                    values.push((*flag).into());
                    values.push("/nonexistent/operator-chain-budget-before-genesis".into());
                }
            }
            values
        };
        let errors: Vec<String> = vec![
            crate::business_cut::run(arguments("export-sqlite"))
                .unwrap_err()
                .to_string(),
            crate::business_import::run(arguments("create-sqlite"))
                .unwrap_err()
                .to_string(),
            crate::conditional_readiness::run(arguments("vote-sqlite"))
                .unwrap_err()
                .to_string(),
            crate::ordered_seal::run(arguments("prepare-sqlite"))
                .unwrap_err()
                .to_string(),
        ];
        for error in errors {
            assert!(
                error.contains("2 links exceeds the configured budget 1"),
                "{error}"
            );
        }
    }
}
