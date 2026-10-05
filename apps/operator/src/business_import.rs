//! Callable verified installation. The command leaves an inactive import;
//! later activation belongs to the separate successor activation owner.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{BusinessPinInputs, BusinessPins, bounded, hex, operation, private_operation},
    common::{FlagSet, parse_hex_32},
    immutable_archive::ImmutableArchive,
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainArtifactFiles, SuccessorChainInputs},
};
use node_core::business_reconstruction::{
    BusinessReconstructionPlan,
    cut::SavedBusinessCut,
    inactive_import::{
        BusinessImportAdvance, VerifiedImportPlan, verify_saved_business_import,
        verify_saved_business_import_chain,
    },
};
use protocol_types::ValidatorId;
use runtime::{DurableOperationContext, WriterFenceGeneration};
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{error::Error, ffi::OsString, num::NonZeroUsize, path::PathBuf};

const FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--cut-dir",
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--timeout-seconds",
    "--max-new-batches",
];
const HELP: &str = "Verified business installation only; leaves a CompleteInactive import and never performs readiness, Seal, activation or signing.\nModes: create-sqlite | resume-sqlite.\nRequire local pins: --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir.\nRequire: --cut-dir (complete saved cut), --state-db, --blob-db, --validator-id (destination-local namespace, not membership authority).\nOptional: --timeout-seconds 1..3600 (300), --max-new-batches 1..4096 (4096), and a successor chain (all five or none): --successor-max-links once plus one or more equal-count repeated --successor-plan-history-dir --successor-cut-dir --successor-manifest-history-dir --successor-certificate-dir links, up to that budget, pinning the saved cut's successor authority; no signer key is accepted here.\nCreation requires two fresh database paths outside the pinned cut and ordered-history archives; resumption opens existing verified import-origin state and writable blob schemas only. No normal bootstrap, source writer copying, repair, reset, private key or network endpoint. Every invocation independently reexecutes saved proofs and verifies the complete destination before CompleteInactive. Missing, corrupt, foreign or ordinary targets refuse.";

/// Runs the same strictly pinned composition as the `business_import` binary.
/// Destination file I/O starts only after independent raw-plan verification.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() {
        return Err(HELP.into());
    }
    let creating: bool = match values.remove(0).to_str() {
        Some("create-sqlite") => true,
        Some("resume-sqlite") => false,
        _ => return Err("unknown business import mode; use --help".into()),
    };
    let mut accepted: Vec<&'static str> = FLAGS.to_vec();
    accepted.extend_from_slice(CHAIN_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let chain_inputs: Option<SuccessorChainInputs> =
        SuccessorChainInputs::parse_optional(&mut flags)?;
    let pin_inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let state_file: PathBuf = flags.one("--state-db")?.into();
    let blob_file: PathBuf = flags.one("--blob-db")?.into();
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
    let maximum_batches: NonZeroUsize = NonZeroUsize::new(usize::try_from(bounded(
        &flags
            .optional_one("--max-new-batches")?
            .unwrap_or_else(|| "4096".into()),
        1,
        4096,
    )?)?)
    .ok_or("zero new-batch limit")?;
    flags.finish()?;
    if state_file == blob_file {
        return Err("state and blob database paths must be distinct".into());
    }
    let mut chain_artifacts: Option<SuccessorChainArtifactFiles> = chain_inputs
        .as_ref()
        .map(SuccessorChainInputs::open)
        .transpose()?;
    if let Some(artifacts) = &chain_artifacts {
        for path in [&state_file, &blob_file] {
            artifacts.require_output_outside(path)?;
        }
    }
    let history_archive: ImmutableArchive =
        ImmutableArchive::open_read_only(pin_inputs.history_root())?;
    let archive: ImmutableArchive = ImmutableArchive::open_read_only(&cut_directory)?;
    for path in [&state_file, &blob_file] {
        archive.require_output_outside(path)?;
        history_archive.require_output_outside(path)?;
    }
    let pins: BusinessPins = match (&chain_inputs, &mut chain_artifacts) {
        (Some(chain), Some(artifacts)) => {
            pin_inputs.load_with_successor(artifacts, chain.budget)?
        }
        (None, None) => pin_inputs.load()?,
        _ => return Err("successor predecessor artifacts are incomplete".into()),
    };
    let private: BusinessReconstructionPlan<'_> = pins.plan(private_operation()?);
    let saved: SavedBusinessCut = read_business_cut_archive(&private, &archive)?;
    let verified: VerifiedImportPlan = match pins.successor_authority() {
        Some(authority) => {
            verify_saved_business_import_chain(private, authority, pins.cut_identity(), &saved)?
        }
        None => verify_saved_business_import(private, &saved)?,
    };
    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), validator, pins.domain);
    // Recheck the held input identities after reconstruction, before any
    // destination creation/open. Native target owners separately pin files
    // and ancestors; this is not a cross-file atomicity guarantee.
    for path in [&state_file, &blob_file] {
        archive.require_output_outside(path)?;
        history_archive.require_output_outside(path)?;
        if let Some(artifacts) = &chain_artifacts {
            artifacts.require_output_outside(path)?;
        }
    }
    let (target, blobs): (SqliteImportTarget, SqliteBlobStore) = if creating {
        // Neither a preexisting ordinary state file nor a preexisting body file
        // may be silently appropriated, bootstrapped or repaired.
        for path in [&state_file, &blob_file] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => return Err("create-sqlite requires absent target database paths".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let fresh: WriterFenceGeneration =
            WriterFenceGeneration::new(1).ok_or("zero destination fence")?;
        let target: SqliteImportTarget =
            SqliteImportTarget::create(&state_file, namespace, fresh, verified.binding())?;
        let blobs: SqliteBlobStore = SqliteBlobStore::create_new(&blob_file)?;
        (target, blobs)
    } else {
        (
            SqliteImportTarget::open_existing(&state_file, namespace, verified.binding())?,
            SqliteBlobStore::open_existing_writable(&blob_file)?,
        )
    };
    let current: WriterFenceGeneration = target.writer_fence()?;
    let destination: DurableOperationContext = operation(current, timeout, [0xBA; 16])?;
    match verified.advance(&target, &blobs, &destination, maximum_batches)? {
        BusinessImportAdvance::Partial {
            progress,
            new_batches,
        } => println!(
            "business_import=partial cut={} package={} plan={} next_ordinal={} new_batches={} meaning=permanently-inactive-no-admission-or-signing",
            hex(&verified.binding().cut_digest.bytes()),
            hex(&verified.binding().package_digest.bytes()),
            hex(&verified.binding().plan_digest.bytes()),
            progress.next_ordinal,
            new_batches,
        ),
        BusinessImportAdvance::CompleteInactive {
            progress,
            new_batches,
        } => println!(
            "business_import=complete-inactive cut={} package={} plan={} next_ordinal={} new_batches={} meaning=permanently-inactive-not-readiness-seal-or-activation",
            hex(&verified.binding().cut_digest.bytes()),
            hex(&verified.binding().package_digest.bytes()),
            hex(&verified.binding().plan_digest.bytes()),
            progress.next_ordinal,
            new_batches,
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn help_and_nonexistent_authority_modes_do_not_touch_a_destination() {
        assert!(run([OsString::from("--help")]).is_ok());
        for mode in [
            "force-import",
            "activate",
            "ordinary",
            "reset",
            "create-sqlite",
        ] {
            assert!(run([OsString::from(mode)]).is_err());
        }
        assert!(run([]).is_err());
    }
}
