//! Prepare a proof-checked Seal candidate and stage its immutable certificate.
//! Selection still requires ordinary outgoing ordered consensus. This command
//! produces no signatures and has no raw Seal-completion port, activation or
//! serving authority. Successor preparation uses a key only to pin public identity.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{BusinessPinInputs, bounded, hex, operation, private_operation},
    common::{FlagSet, load_signing_key_file, parse_hex_32, read_bounded_file},
    immutable_archive::ImmutableArchive,
    source_sqlite::ExistingSqliteSource,
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainArtifactFiles, SuccessorChainInputs},
};
use consensus::readiness::{
    MAX_READINESS_CERTIFICATE_BYTES, ReadinessCertificate, ReadinessCertifier, ReadinessSubject,
    decode_readiness_certificate,
};
use node_core::serving_authority::{
    LiveAuthority, SuccessorLinkPins, resolve_live_authority_chain,
};
use node_core::{
    business_reconstruction::{
        cut::{SavedBusinessCut, encode_business_cut_identity},
        inactive_import::{
            VerifiedImportPlan, verify_saved_business_import, verify_saved_business_import_chain,
        },
    },
    conditional_readiness::readiness_subject_for_candidate,
    ordered_economics::{
        OrderedCandidate, OrderedOperationKind, SEAL_PREDECESSOR_TAG_GENESIS,
        SEAL_PREDECESSOR_TAG_SUCCESSOR, SealIntent, encode_ordered_candidate, encode_seal_intent,
        seal_certificate_digest, seal_request_id, seal_target_digest,
    },
    require_ordinary_namespace,
};
use protocol_types::{Digest32, ValidatorId};
use runtime::{BlobStore, DurableOperationContext};
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
    "--cut-dir",
    "--certificate",
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--out-dir",
    "--timeout-seconds",
    "--signer-key-file",
];
const HELP: &str = "Prepare only: prepare-sqlite. Stages the exact readiness certificate in an existing local blob store and writes candidate.bin for the ordinary economics network-submit command. No consensus selection, Seal completion, activation or serving is performed here; this command produces no signature, and a successor --signer-key-file, when required, only pins a public identity.\nRequire local --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir --cut-dir --certificate --state-db --blob-db --validator-id --out-dir. Optional successor chain (all five or none): --successor-max-links once plus one or more equal-count repeated --successor-plan-history-dir --successor-cut-dir --successor-manifest-history-dir --successor-certificate-dir links, up to that budget, then --signer-key-file is also required.\nThe complete local hash schedule is a separate authority pin, not authenticated merely by genesis. The saved cut is independently reconstructed; the certificate must have its exact subject and genuine weighted successor quorum. Each outgoing validator independently checks current cut, eligibility and selected ancestry before signing. Without the successor chain flags the existing source must be Ordinary and Unsealed; with them it must instead be the verified live Successor the chain names. This command neither bootstraps nor advances a writer fence. Output is immutable and permits only exact retries. Optional --timeout-seconds 1..3600 (300).";

/// Runs the same explicitly pinned, unsigned preparation as the executable.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() || values.remove(0) != "prepare-sqlite" {
        return Err(HELP.into());
    }
    let mut accepted: Vec<&'static str> = FLAGS.to_vec();
    accepted.extend_from_slice(CHAIN_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let chain_inputs: Option<SuccessorChainInputs> =
        SuccessorChainInputs::parse_optional(&mut flags)?;
    let inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let certificate_path: PathBuf = flags.one("--certificate")?.into();
    let state_path: PathBuf = flags.one("--state-db")?.into();
    let blob_path: PathBuf = flags.one("--blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let output_directory: PathBuf = flags.one("--out-dir")?.into();
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        3600,
    )?;
    let signer_path: Option<PathBuf> = if chain_inputs.is_some() {
        Some(flags.one("--signer-key-file")?.into())
    } else {
        None
    };
    flags.finish()?;
    if state_path == blob_path {
        return Err("state and blob database paths must be distinct".into());
    }

    let mut chain_artifacts: Option<SuccessorChainArtifactFiles> = chain_inputs
        .as_ref()
        .map(SuccessorChainInputs::open)
        .transpose()?;
    if let Some(artifacts) = &chain_artifacts {
        for path in [
            &state_path,
            &blob_path,
            &output_directory.join("candidate.bin"),
        ] {
            artifacts.require_output_outside(path)?;
        }
    }
    let history: ImmutableArchive = ImmutableArchive::open_read_only(inputs.history_root())?;
    let cut_archive: ImmutableArchive = ImmutableArchive::open_read_only(&cut_directory)?;
    for archive in [&history, &cut_archive] {
        for path in [
            &state_path,
            &blob_path,
            &output_directory.join("candidate.bin"),
        ] {
            archive.require_output_outside(path)?;
        }
    }
    let certificate_bytes: Vec<u8> = read_bounded_file(
        &certificate_path,
        MAX_READINESS_CERTIFICATE_BYTES,
        "readiness certificate",
    )?;
    let certificate: ReadinessCertificate = decode_readiness_certificate(&certificate_bytes)?;
    let pins = match (&chain_inputs, &mut chain_artifacts) {
        (Some(chain), Some(artifacts)) => inputs.load_with_successor(artifacts, chain.budget)?,
        (None, None) => inputs.load()?,
        _ => return Err("successor predecessor artifacts are incomplete".into()),
    };
    if pins.policy.registered_validator(validator).is_none() {
        return Err("source validator is absent from verified outgoing committee".into());
    }
    let saved: SavedBusinessCut =
        read_business_cut_archive(&pins.plan(private_operation()?), &cut_archive)?;
    let verified: VerifiedImportPlan = match pins.successor_authority() {
        Some(authority) => verify_saved_business_import_chain(
            pins.plan(private_operation()?),
            authority,
            pins.cut_identity(),
            &saved,
        )?,
        None => verify_saved_business_import(pins.plan(private_operation()?), &saved)?,
    };
    let expected: ReadinessSubject = readiness_subject_for_candidate(
        verified.binding(),
        pins.resolver(),
        &certificate.next_set,
    )?;
    let certifier: ReadinessCertifier<'_> =
        ReadinessCertifier::new(pins.resolver(), &expected, &certificate.next_set)?;
    certifier.verify_certificate(&certificate)?;
    let certificate_digest: Digest32 =
        seal_certificate_digest(pins.resolver(), pins.context.epoch(), &certificate_bytes)?;
    let (predecessor_tag, predecessor_digest): (u16, Digest32) = match pins.successor_authority() {
        Some(authority) => (SEAL_PREDECESSOR_TAG_SUCCESSOR, authority.subject_digest()),
        None => (
            SEAL_PREDECESSOR_TAG_GENESIS,
            verified.binding().genesis_digest,
        ),
    };
    let target: Digest32 = seal_target_digest(
        pins.resolver(),
        &pins.context,
        expected.identity(pins.resolver())?,
        predecessor_tag,
        predecessor_digest,
    )?;
    let intent: SealIntent = SealIntent {
        readiness_subject: expected,
        cut_identity_bytes: encode_business_cut_identity(&saved.identity)?,
        predecessor_tag,
        predecessor_digest,
        certificate_digest,
        certificate_length: u32::try_from(certificate_bytes.len())?,
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: pins.context.clone(),
        kind: OrderedOperationKind::Seal,
        request_id: seal_request_id(pins.resolver(), &pins.context, target, certificate_digest)?,
        created_checkpoint: saved.identity.ordered_history.through_height,
        intent: encode_seal_intent(&intent)?,
    };
    let candidate_bytes: Vec<u8> = encode_ordered_candidate(&candidate)?;
    let source: Option<ExistingSqliteSource> = if pins.successor_authority().is_none() {
        Some(ExistingSqliteSource::open(
            &state_path,
            &blob_path,
            pins.context.chain_id().clone(),
            validator,
            pins.domain,
            timeout,
        )?)
    } else {
        None
    };
    let successor_source: Option<(SqliteImportTarget, DurableOperationContext, [u8; 32])> =
        if let Some(authority) = pins.successor_authority() {
            let key: ed25519_zebra::SigningKey = load_signing_key_file(
                signer_path
                    .as_ref()
                    .ok_or("successor Seal source requires --signer-key-file")?,
            )?;
            let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
            let target: SqliteImportTarget = SqliteImportTarget::open_existing(
                &state_path,
                SqliteNamespace::new(pins.context.chain_id().clone(), validator, pins.domain),
                authority.import_binding(),
            )?;
            let context: DurableOperationContext =
                operation(target.writer_fence()?, timeout, [0xBD; 16])?;
            Some((target, context, public_key))
        } else {
            None
        };
    let mut recheck_source = || -> Result<(), Box<dyn Error>> {
        match (&source, &successor_source) {
            (Some(source), None) => {
                require_ordinary_namespace(&source.durable, &source.operation, pins.domain)
                    .map_err(|error| format!("Seal outgoing-source guard failed: {error:?}"))?;
            }
            (None, Some((target, context, public_key))) => {
                let artifacts: &mut SuccessorChainArtifactFiles = chain_artifacts
                    .as_mut()
                    .ok_or("successor artifacts unavailable")?;
                let links: Vec<SuccessorLinkPins> = artifacts.pins();
                let chain: &SuccessorChainInputs =
                    chain_inputs.as_ref().ok_or("successor pins unavailable")?;
                match resolve_live_authority_chain(
                    target,
                    context,
                    pins.domain,
                    pins.chain_plan(private_operation()?),
                    &links,
                    chain.budget,
                    artifacts,
                    *public_key,
                )? {
                    LiveAuthority::Successor(_) => {}
                    LiveAuthority::OriginalGenesis => {
                        return Err("successor Seal source is an ordinary namespace".into());
                    }
                }
                for path in [
                    &state_path,
                    &blob_path,
                    &output_directory.join("candidate.bin"),
                ] {
                    artifacts.require_output_outside(path)?;
                }
            }
            _ => return Err("Seal source composition is incomplete".into()),
        }
        Ok(())
    };
    recheck_source()?;
    for archive in [&history, &cut_archive] {
        for path in [
            &state_path,
            &blob_path,
            &output_directory.join("candidate.bin"),
        ] {
            archive.require_output_outside(path)?;
        }
    }
    let output: ImmutableArchive = ImmutableArchive::open(&output_directory)?;
    if output.names()?.iter().any(|name| name != "candidate.bin") {
        return Err("output directory contains another artifact role".into());
    }
    // Immutable bytes can be left unreachable after a lost reply or a changed
    // barrier. They never select a target or grant permission to sign it.
    // Keep the historical source reader read-only. Immutable staging uses
    // its separately named existing-file writer, never blob bootstrap.
    let staging: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&blob_path)?;
    staging.put_blob(certificate_digest, certificate_bytes)?;
    recheck_source()?;
    output.publish("candidate.bin", &candidate_bytes)?;
    println!(
        "ordered_seal=prepared target={} request={} meaning=unsigned-not-selected-not-serving",
        hex(&target.bytes()),
        hex(&candidate.request_id),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_authority_modes_and_missing_inputs_without_io() {
        assert!(run([OsString::from("--help")]).is_ok());
        assert!(run([]).is_err());
        for mode in ["force", "seal", "activate", "serve", "prepare-sqlite"] {
            assert!(run([OsString::from(mode)]).is_err());
        }
    }
}
