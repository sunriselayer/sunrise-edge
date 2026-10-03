//! First-successor target-local activation (DR-0189 Section 6, Section 12).
//! This command has no listener, serving route or retry beyond node-core's
//! own atomic activation/reconciliation; it runs `activate_successor` exactly
//! once per invocation and prints the verified subject and manifest digests.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{BusinessPinInputs, bounded, hex, operation, private_operation},
    common::{FlagSet, load_signing_key_file, parse_hex_32},
    immutable_archive::ImmutableArchive,
    successor_artifacts::SuccessorArtifactFiles,
};
use node_core::business_reconstruction::{
    cut::SavedBusinessCut,
    inactive_import::{VerifiedImportPlan, verify_saved_business_import},
};
use node_core::conditional_readiness::ReadinessSigningKey;
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedHistoryIdentity, decode_ordered_history_identity,
};
use node_core::serving_authority::{
    SuccessorActivationOutcome, activate_successor,
};
use protocol_types::ValidatorId;
use runtime::{Clock, SystemClock};
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{error::Error, ffi::OsString, path::PathBuf};
use sunrise_edge_client::ordered_history_archive::read_regular_archive_file;

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
    "--manifest-history-dir",
    "--certificate-dir",
    "--target-state-db",
    "--target-blob-db",
    "--validator-id",
    "--signer-key-file",
    "--timeout-seconds",
];
const HELP: &str = "First-successor activation only: activate. No listener, serving route or signing authorization shortcut.\nRequire local --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir (through T, feeding the plan) --cut-dir (saved pre-Seal business cut) --manifest-history-dir (full history_export through the committed Seal height h) --certificate-dir (retained certificate.bin) --target-state-db --target-blob-db --validator-id --signer-key-file.\nEvery invocation independently re-verifies the complete source-free evidence chain before any destination write; a previous successful run is never trusted. Optional --timeout-seconds 1..3600 (300).";

/// Runs the same pinned local activation as the compiled binary.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() || values.remove(0) != "activate" {
        return Err(HELP.into());
    }
    let mut flags: FlagSet = FlagSet::parse(values, FLAGS, &[])?;
    let inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let manifest_history_directory: PathBuf = flags.one("--manifest-history-dir")?.into();
    let certificate_directory: PathBuf = flags.one("--certificate-dir")?.into();
    let state_path: PathBuf = flags.one("--target-state-db")?.into();
    let blob_path: PathBuf = flags.one("--target-blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let key_path: PathBuf = flags.one("--signer-key-file")?.into();
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        3600,
    )?;
    flags.finish()?;
    if state_path == blob_path {
        return Err("target state and blob database paths must be distinct".into());
    }

    let cut_archive: ImmutableArchive = ImmutableArchive::open_read_only(&cut_directory)?;
    let manifest_history: ImmutableArchive = ImmutableArchive::open_read_only(&manifest_history_directory)?;
    let certificate_archive: ImmutableArchive = ImmutableArchive::open_read_only(&certificate_directory)?;
    for archive in [&cut_archive, &manifest_history, &certificate_archive] {
        for path in [&state_path, &blob_path] {
            archive.require_output_outside(path)?;
        }
    }

    let pins = inputs.load()?;
    let manifest_identity_bytes: Vec<u8> = read_regular_archive_file(
        &manifest_history_directory,
        std::path::Path::new("identity.bin"),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    // This claimed through-h target is untrusted transport: node-core
    // independently validates it against the pinned genesis/domain/anchor
    // and re-derives it from the replayed history before any write.
    let manifest_identity: OrderedHistoryIdentity =
        decode_ordered_history_identity(&manifest_identity_bytes)?;

    let saved: SavedBusinessCut =
        read_business_cut_archive(&pins.plan(private_operation()?), &cut_archive)?;
    let verified: VerifiedImportPlan =
        verify_saved_business_import(pins.plan(private_operation()?), &saved)
            .map_err(|error| format!("successor activation saved-cut reconstruction failed: {error:?}"))?;

    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), validator, pins.domain);
    let target: SqliteImportTarget =
        SqliteImportTarget::open_existing(&state_path, namespace, verified.binding())?;
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_path)?;

    let key_path: PathBuf = if key_path.is_absolute() {
        key_path
    } else {
        std::env::current_dir()?.join(key_path)
    };
    let key_directory: ImmutableArchive = ImmutableArchive::open_read_only(
        key_path.parent().ok_or("signer key has no parent directory")?,
    )?;
    let key: ed25519_zebra::SigningKey = load_signing_key_file(&key_path)?;
    let key_name: &str = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("signer key filename is not a normal UTF-8 component")?;
    let mut checked_key: Vec<u8> = key_directory.read(key_name, 32)?;
    let matches: bool = checked_key.as_slice() == key.as_ref();
    checked_key.fill(0);
    if !matches {
        return Err("signer key changed while loading".into());
    }
    let signer: ReadinessSigningKey = ReadinessSigningKey::new(validator, key);

    let destination_operation = operation(target.writer_fence()?, timeout, [0xC0; 16])?;
    let now_unix_millis: u64 = SystemClock.now_unix_millis()?;
    // Recheck held archive identities after reconstruction and signer-key
    // loading, immediately before the one call that can perform a
    // destination write, matching the existing re-check pattern.
    for archive in [&cut_archive, &manifest_history, &certificate_archive] {
        for path in [&state_path, &blob_path] {
            archive.require_output_outside(path)?;
        }
    }
    key_directory.ensure_attached()?;
    let mut artifacts: SuccessorArtifactFiles<'_> = SuccessorArtifactFiles::new(
        pins.plan(private_operation()?),
        cut_archive,
        manifest_history_directory,
        certificate_archive,
    );
    drop(manifest_history);

    let outcome: SuccessorActivationOutcome = activate_successor(
        pins.plan(private_operation()?),
        &manifest_identity,
        &mut artifacts,
        &target,
        &blobs,
        &destination_operation,
        &signer,
        now_unix_millis,
    )?;
    match outcome {
        SuccessorActivationOutcome::Activated { subject, manifest } => println!(
            "successor_activation=activated subject={} manifest={} meaning=destination-slot-now-serving",
            hex(&subject.bytes()),
            hex(&manifest.bytes()),
        ),
        SuccessorActivationOutcome::AlreadyActivated { subject, manifest } => println!(
            "successor_activation=already-activated subject={} manifest={} meaning=exact-prior-activation-reconciled",
            hex(&subject.bytes()),
            hex(&manifest.bytes()),
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_authority_modes_and_missing_inputs_without_io() {
        assert!(run([OsString::from("--help")]).is_ok());
        assert!(run([]).is_err());
        for mode in ["serve", "force", "activate"] {
            assert!(run([OsString::from(mode)]).is_err());
        }
    }
}
