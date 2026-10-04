//! Callable local SQLite pre-Seal candidate export and database-free verification.
#![forbid(unsafe_code)]

use crate::{
    business_cut::{
        CutArchiveLimits, export_source_business_cut, export_successor_source_business_cut,
        read_business_cut_archive, verify_business_cut_archive,
    },
    business_pins::{BusinessPinInputs, BusinessPins, bounded, hex, operation, private_operation},
    common::{FlagSet, load_signing_key_file, parse_hex_32},
    immutable_archive::ImmutableArchive,
    source_sqlite::ExistingSqliteSource,
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainArtifactFiles, SuccessorChainInputs},
};
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::business_reconstruction::cut::SavedBusinessCut;
use node_core::business_reconstruction::inactive_import::{
    VerifiedImportPlan, verify_saved_business_import_chain,
};
use node_core::serving_authority::{
    LiveAuthority, SuccessorLinkPins, resolve_live_authority_chain,
};
use protocol_types::ValidatorId;
use runtime::DurableOperationContext;
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
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
    "--signer-key-file",
];
const HELP: &str = "Pre-Seal business candidate only; no import, readiness, Seal or activation.\nModes: export-sqlite | verify-saved.\nBoth require: --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir --out-dir (existing directory).\nExport additionally requires: --state-db --blob-db --validator-id. Optional export bounds: --page-size 1..128 (128), --chunk-size 1..1048576 (1048576), --max-new-work 1..4096 (4096), --timeout-seconds 1..3600 (300).\nExport opens existing initialized SQLite files only, never creates or advances a fence. Changed source/token or saved bytes refuse. Resume uses the same pins, source, directory and transfer sizing. Saved verification reconstructs all original proofs without opening the source DB and grants no serving/signing authority.";

struct ExportInputs {
    state: PathBuf,
    blobs: PathBuf,
    validator: ValidatorId,
    timeout: u64,
    limits: CutArchiveLimits,
    signer_key_file: Option<PathBuf>,
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
    let mut accepted: Vec<&'static str> = FLAGS.to_vec();
    accepted.extend_from_slice(CHAIN_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let chain_inputs: Option<SuccessorChainInputs> =
        SuccessorChainInputs::parse_optional(&mut flags)?;
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
            signer_key_file: if chain_inputs.is_some() {
                Some(flags.one("--signer-key-file")?.into())
            } else {
                None
            },
        })
    } else {
        None
    };
    // Mode-irrelevant source, TLS and signing inputs are never silently ignored.
    flags.finish()?;
    if let Some(inputs) = &export_inputs {
        if inputs.state == inputs.blobs {
            return Err("state and blob database paths must be distinct".into());
        }
    }
    let mut chain_artifacts: Option<SuccessorChainArtifactFiles> = chain_inputs
        .as_ref()
        .map(SuccessorChainInputs::open)
        .transpose()?;
    if let Some(artifacts) = &chain_artifacts {
        artifacts.require_output_outside(&output.join("complete"))?;
        if let Some(inputs) = &export_inputs {
            for path in [&inputs.state, &inputs.blobs] {
                artifacts.require_output_outside(path)?;
            }
        }
    }
    let pins: BusinessPins = match (&chain_inputs, &mut chain_artifacts) {
        (Some(chain), Some(artifacts)) => {
            pin_inputs.load_with_successor(artifacts, chain.budget)?
        }
        (None, None) => pin_inputs.load()?,
        _ => return Err("successor predecessor artifacts are incomplete".into()),
    };
    let archive: ImmutableArchive = if exporting {
        ImmutableArchive::open(&output)?
    } else {
        ImmutableArchive::open_read_only(&output)?
    };
    if let Some(authority) = pins.successor_authority() {
        if let Some(inputs) = export_inputs {
            if pins.policy.registered_validator(inputs.validator).is_none() {
                return Err("source validator is absent from verified current committee".into());
            }
            let key_path: PathBuf = inputs
                .signer_key_file
                .ok_or("successor source requires --signer-key-file")?;
            let key: ed25519_zebra::SigningKey = load_signing_key_file(&key_path)?;
            let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
            let source: SqliteImportTarget = SqliteImportTarget::open_existing(
                &inputs.state,
                SqliteNamespace::new(
                    pins.context.chain_id().clone(),
                    inputs.validator,
                    pins.domain,
                ),
                authority.import_binding(),
            )?;
            let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&inputs.blobs)?;
            let context: DurableOperationContext =
                operation(source.writer_fence()?, inputs.timeout, [0xBC; 16])?;
            let artifacts: &mut SuccessorChainArtifactFiles = chain_artifacts
                .as_mut()
                .ok_or("successor artifacts unavailable")?;
            let links: Vec<SuccessorLinkPins> = artifacts.pins();
            let chain: &SuccessorChainInputs =
                chain_inputs.as_ref().ok_or("successor pins unavailable")?;
            let warrant = match resolve_live_authority_chain(
                &source,
                &context,
                pins.domain,
                pins.chain_plan(private_operation()?),
                &links,
                chain.budget,
                artifacts,
                public_key,
            )? {
                LiveAuthority::Successor(warrant) => warrant,
                LiveAuthority::OriginalGenesis => {
                    return Err("successor cut source is an ordinary namespace".into());
                }
            };
            artifacts.require_output_outside(&output.join("complete"))?;
            let progress = export_successor_source_business_cut(
                pins.plan(context),
                &warrant,
                &source,
                &blobs,
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
            let saved: SavedBusinessCut =
                read_business_cut_archive(&pins.plan(private_operation()?), &archive)?;
            let verified: VerifiedImportPlan = verify_saved_business_import_chain(
                pins.plan(private_operation()?),
                authority,
                pins.cut_identity(),
                &saved,
            )?;
            println!(
                "business_cut=independently-verified cut={} package={} meaning=pre-seal-candidate-not-import-readiness-seal-or-activation",
                hex(&verified.binding().cut_digest.bytes()),
                hex(&verified.binding().package_digest.bytes())
            );
        }
        return Ok(());
    }
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
