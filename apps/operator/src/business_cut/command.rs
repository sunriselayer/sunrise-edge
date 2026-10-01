//! Callable local SQLite pre-Seal candidate export and database-free verification.
#![forbid(unsafe_code)]

use crate::{
    business_cut::{CutArchiveLimits, export_source_business_cut, verify_business_cut_archive},
    business_pins::{BusinessPinInputs, BusinessPins, bounded, hex, private_operation},
    common::{FlagSet, parse_hex_32},
    immutable_archive::ImmutableArchive,
    source_sqlite::ExistingSqliteSource,
};
use node_core::business_reconstruction::BusinessReconstructionPlan;
use protocol_types::ValidatorId;
use runtime::DurableOperationContext;
use std::{error::Error, ffi::OsString, path::PathBuf};

const FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--out-dir",
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--timeout-seconds",
    "--page-size",
    "--chunk-size",
    "--max-new-work",
];
const HELP: &str = "Pre-Seal business candidate only; no import, readiness, Seal or activation.\nModes: export-sqlite | verify-saved.\nBoth require: --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir --out-dir (existing directory).\nExport additionally requires: --state-db --blob-db --validator-id. Optional export bounds: --page-size 1..128 (128), --chunk-size 1..1048576 (1048576), --max-new-work 1..4096 (4096), --timeout-seconds 1..3600 (300).\nExport opens existing initialized SQLite files only, never creates or advances a fence. Changed source/token or saved bytes refuse. Resume uses the same pins, source, directory and transfer sizing. Saved verification reconstructs all original proofs without opening the source DB and grants no serving/signing authority.";

struct ExportInputs {
    state: PathBuf,
    blobs: PathBuf,
    validator: ValidatorId,
    timeout: u64,
    limits: CutArchiveLimits,
}

/// Runs the same pinned local composition as the `business_cut` executable.
/// Verification has no database, signing, transport or installation authority.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() {
        return Err(HELP.into());
    }
    let mode: OsString = values.remove(0);
    let exporting: bool = match mode.to_str() {
        Some("export-sqlite") => true,
        Some("verify-saved") => false,
        _ => return Err("unknown business cut mode; use --help".into()),
    };
    let mut flags: FlagSet = FlagSet::parse(values, FLAGS, &[])?;
    let pin_inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let output: PathBuf = flags.one("--out-dir")?.into();
    let export_inputs: Option<ExportInputs> = if exporting {
        let state: PathBuf = flags.one("--state-db")?.into();
        let blobs: PathBuf = flags.one("--blob-db")?.into();
        let validator: ValidatorId = ValidatorId::new(parse_hex_32(
            &flags.one("--validator-id")?,
            "--validator-id",
        )?);
        let timeout: u64 = bounded(
            &flags
                .optional_one("--timeout-seconds")?
                .unwrap_or_else(|| "300".into()),
            1,
            3600,
        )?;
        let page: usize = usize::try_from(bounded(
            &flags
                .optional_one("--page-size")?
                .unwrap_or_else(|| "128".into()),
            1,
            128,
        )?)?;
        let chunk: usize = usize::try_from(bounded(
            &flags
                .optional_one("--chunk-size")?
                .unwrap_or_else(|| "1048576".into()),
            1,
            1_048_576,
        )?)?;
        let new_work: usize = usize::try_from(bounded(
            &flags
                .optional_one("--max-new-work")?
                .unwrap_or_else(|| "4096".into()),
            1,
            4096,
        )?)?;
        Some(ExportInputs {
            state,
            blobs,
            validator,
            timeout,
            limits: CutArchiveLimits::new(page, chunk, new_work)?,
        })
    } else {
        None
    };
    // Mode-irrelevant source, TLS and signing inputs are never silently ignored.
    flags.finish()?;
    let pins: BusinessPins = pin_inputs.load()?;
    let archive: ImmutableArchive = if exporting {
        ImmutableArchive::open(&output)?
    } else {
        ImmutableArchive::open_read_only(&output)?
    };
    let source: Option<ExistingSqliteSource> = if let Some(inputs) = &export_inputs {
        if pins.policy.registered_validator(inputs.validator).is_none() {
            return Err("source validator is absent from pinned genesis".into());
        }
        Some(ExistingSqliteSource::open(
            &inputs.state,
            &inputs.blobs,
            pins.context.chain_id().clone(),
            inputs.validator,
            pins.domain,
            inputs.timeout,
        )?)
    } else {
        None
    };
    let operation: DurableOperationContext = match &source {
        Some(source) => source.operation,
        None => private_operation()?,
    };
    let plan: BusinessReconstructionPlan<'_> = pins.plan(operation);
    if let (Some(source), Some(inputs)) = (&source, export_inputs) {
        let progress = export_source_business_cut(
            plan,
            &source.durable,
            &source.blobs,
            &pins.ordered,
            &archive,
            inputs.limits,
        )?;
        println!(
            "business_cut={} cut={} package={} newly_saved_files={} meaning=pre-seal-candidate-not-import-readiness-seal-or-activation",
            if progress.complete {
                "complete"
            } else {
                "partial"
            },
            hex(&progress.cut_digest.bytes()),
            hex(&progress.package_digest.bytes()),
            progress.newly_saved_files
        );
    } else {
        let verified = verify_business_cut_archive(plan, &archive)?;
        println!(
            "business_cut=independently-verified cut={} package={} meaning=pre-seal-candidate-not-import-readiness-seal-or-activation",
            hex(&verified.cut_digest().bytes()),
            hex(&verified.package_digest().bytes())
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn help_and_unknown_mode_are_bounded_without_source_io() {
        assert!(run([OsString::from("--help")]).is_ok());
        assert!(run([OsString::from("force-import")]).is_err());
        assert!(run([]).is_err());
    }
}
