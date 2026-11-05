//! Local conditional readiness over a genuinely verified inactive SQLite target.
//! No listener, bootstrap, fence advance, Seal or activation is exposed.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{BusinessPinInputs, BusinessPins, bounded, hex, operation, private_operation},
    common::{FlagSet, load_signing_key_file, parse_hex_32, read_bounded_file},
    immutable_archive::ImmutableArchive,
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainArtifactFiles, SuccessorChainInputs},
};
use consensus::readiness::{
    MAX_READINESS_MEMBERS, MAX_READINESS_SET_BYTES, MAX_READINESS_VOTE_BYTES, ReadinessCertifier,
    ReadinessSubject, ReadinessVote, decode_readiness_set, decode_readiness_vote,
    encode_readiness_certificate, encode_readiness_vote,
};
use node_core::{
    business_reconstruction::{
        cut::SavedBusinessCut,
        inactive_import::{
            VerifiedImportPlan, verify_saved_business_import, verify_saved_business_import_chain,
        },
    },
    conditional_readiness::{
        ReadinessSigningKey, readiness_subject_for_candidate, retain_conditional_readiness,
        retain_conditional_readiness_chain,
    },
    fast_path::records::FastPathValidatorEntry,
};
use protocol_types::ValidatorId;
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{
    error::Error,
    ffi::OsString,
    path::{Path, PathBuf},
};
use validator_set::ValidatorSet;

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
    "--next-set",
    "--out-dir",
    crate::local_anchor::FLAG,
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--signer-key-file",
    "--timeout-seconds",
    "--vote",
];
const HELP: &str = "Conditional readiness only: vote-sqlite | certificate | vote-worker | vote-frontend. No Seal, activation, serving or ordinary signatures.\nRequire local --chain-id --protocol-version --epoch --domain --suite --genesis-manifest --expected-genesis-digest --ordered-history-dir --cut-dir --next-set (canonical ValidatorSet at adjacent epoch) --out-dir (existing separate directory). Optional successor chain (all five or none, either mode): --successor-max-links once plus one or more equal-count repeated --successor-plan-history-dir --successor-cut-dir --successor-manifest-history-dir --successor-certificate-dir links, up to that budget, pinning the saved cut's successor authority.\nvote-sqlite also requires --state-db --blob-db --validator-id --signer-key-file (the vote signer in either case); opens only the exact completed inactive import and does not advance its writer fence. certificate requires 1..256 --vote files and no signing key/store.\nOptional --timeout-seconds 1..3600 (300). Outputs are immutable vote.bin or certificate.bin, exact retries only. Complete local hash schedule is a separate configuration pin, not authenticated merely by genesis. Each vote invocation freshly reconstructs and compares the complete target; certificate assembly independently reconstructs the cut and verifies genuine distinct weighted successor signatures.\nvote-worker and vote-frontend each require --config pointing to a private role-specific local config file; only vote-frontend publishes vote.bin.";

struct VoteContext<'a> {
    pins: &'a BusinessPins,
    verified: &'a VerifiedImportPlan,
    saved: &'a SavedBusinessCut,
    next_set: &'a ValidatorSet,
    history: &'a ImmutableArchive,
    cut: &'a ImmutableArchive,
    prior_output: Option<(&'a ImmutableArchive, &'a str)>,
    anchor: Option<&'a Path>,
    timeout: u64,
}

pub(crate) struct PreparedVote {
    pub(crate) chain_artifacts: Option<SuccessorChainArtifactFiles>,
    pub(crate) history: ImmutableArchive,
    pub(crate) cut: ImmutableArchive,
    pub(crate) next_set: ValidatorSet,
    pub(crate) pins: BusinessPins,
    pub(crate) saved: SavedBusinessCut,
    pub(crate) verified: VerifiedImportPlan,
    pub(crate) subject: ReadinessSubject,
}

impl PreparedVote {
    pub(crate) fn produce_worker_vote(
        &self,
        inputs: (PathBuf, PathBuf, ValidatorId, PathBuf),
        anchor: Option<&Path>,
        timeout: u64,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let owner: ReadinessCertifier<'_> =
            ReadinessCertifier::new(self.pins.resolver(), &self.subject, &self.next_set)?;
        produce_vote(
            VoteContext {
                pins: &self.pins,
                verified: &self.verified,
                saved: &self.saved,
                next_set: &self.next_set,
                history: &self.history,
                cut: &self.cut,
                prior_output: None,
                anchor,
                timeout,
            },
            &owner,
            inputs,
        )
    }

    pub(crate) fn verify_worker_vote(
        &self,
        bytes: &[u8],
        validator: ValidatorId,
    ) -> Result<(), Box<dyn Error>> {
        let vote: ReadinessVote = decode_readiness_vote(bytes)?;
        if vote.signer != validator {
            return Err("readiness worker vote signer mismatch".into());
        }
        let owner: ReadinessCertifier<'_> =
            ReadinessCertifier::new(self.pins.resolver(), &self.subject, &self.next_set)?;
        owner.verify_vote(&vote)?;
        Ok(())
    }
}

/// Runs the same pinned offline composition as the compiled binary.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() {
        return Err(HELP.into());
    }
    let voting: bool = match values.remove(0).to_str() {
        Some("vote-sqlite") => true,
        Some("certificate") => false,
        Some("vote-worker") => {
            #[cfg(target_os = "linux")]
            return crate::conditional_readiness_custody::run(true, values);
            #[cfg(not(target_os = "linux"))]
            return Err("readiness custody requires Linux".into());
        }
        Some("vote-frontend") => {
            #[cfg(target_os = "linux")]
            return crate::conditional_readiness_custody::run(false, values);
            #[cfg(not(target_os = "linux"))]
            return Err("readiness custody requires Linux".into());
        }
        _ => return Err("unknown conditional readiness mode; use --help".into()),
    };
    let mut accepted: Vec<&'static str> = FLAGS.to_vec();
    accepted.extend_from_slice(CHAIN_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let anchor: Option<PathBuf> = crate::local_anchor::parse(&mut flags)?;
    let chain_inputs: Option<SuccessorChainInputs> =
        SuccessorChainInputs::parse_optional(&mut flags)?;
    let inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let next_path: PathBuf = flags.one("--next-set")?.into();
    let output_directory: PathBuf = flags.one("--out-dir")?.into();
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        3600,
    )?;
    let target_inputs: Option<(PathBuf, PathBuf, ValidatorId, PathBuf)> = if voting {
        Some((
            flags.one("--state-db")?.into(),
            flags.one("--blob-db")?.into(),
            ValidatorId::new(parse_hex_32(
                &flags.one("--validator-id")?,
                "--validator-id",
            )?),
            flags.one("--signer-key-file")?.into(),
        ))
    } else {
        None
    };
    let vote_paths: Vec<String> = if voting {
        Vec::new()
    } else {
        flags.many("--vote")
    };
    flags.finish()?;
    if !voting && anchor.is_some() {
        return Err("certificate mode has no local anchor/store".into());
    }
    if !voting && !(1..=MAX_READINESS_MEMBERS).contains(&vote_paths.len()) {
        return Err("certificate requires one to 256 bounded vote files".into());
    }
    let filename: &str = if voting {
        "vote.bin"
    } else {
        "certificate.bin"
    };
    let output_path: PathBuf = output_directory.join(filename);
    let target_paths: Option<(&Path, &Path)> = target_inputs
        .as_ref()
        .map(|(state, blobs, _, _)| (state.as_path(), blobs.as_path()));
    let prepared: PreparedVote = load_vote_public(
        chain_inputs,
        inputs,
        &cut_directory,
        &next_path,
        Some(&output_path),
        target_paths,
    )?;
    let PreparedVote {
        chain_artifacts,
        history,
        cut,
        next_set,
        pins,
        saved,
        verified,
        subject,
    } = prepared;
    let owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(pins.resolver(), &subject, &next_set)?;
    // Recheck held archive identities after reconstruction, before any writes.
    for source in [&history, &cut] {
        source.require_output_outside(&output_directory.join(filename))?;
    }
    if let Some(artifacts) = &chain_artifacts {
        artifacts.require_output_outside(&output_directory.join(filename))?;
    }
    let output: ImmutableArchive = ImmutableArchive::open(&output_directory)?;
    let names = output.names()?;
    if names.iter().any(|name| name != filename) {
        return Err("output directory contains another artifact role".into());
    }
    let bytes: Vec<u8> = if let Some(inputs) = target_inputs {
        produce_vote(
            VoteContext {
                pins: &pins,
                verified: &verified,
                saved: &saved,
                next_set: &next_set,
                history: &history,
                cut: &cut,
                prior_output: Some((&output, filename)),
                anchor: anchor.as_deref(),
                timeout,
            },
            &owner,
            inputs,
        )?
    } else {
        let mut votes: Vec<ReadinessVote> = Vec::with_capacity(vote_paths.len());
        for path in vote_paths {
            votes.push(decode_readiness_vote(&read_bounded_file(
                &PathBuf::from(path),
                MAX_READINESS_VOTE_BYTES,
                "vote",
            )?)?);
        }
        encode_readiness_certificate(&owner.form_certificate(&votes)?)?
    };
    output.publish(filename, &bytes)?;
    println!(
        "conditional_readiness={} cut={} next_epoch={} meaning=not-seal-activation-or-serving",
        if voting {
            "retained-vote"
        } else {
            "verified-certificate"
        },
        hex(&subject.cut_digest.bytes()),
        subject.next_epoch.get()
    );
    Ok(())
}

pub(crate) fn load_vote_public(
    chain_inputs: Option<SuccessorChainInputs>,
    inputs: BusinessPinInputs,
    cut_directory: &Path,
    next_path: &Path,
    output_path: Option<&Path>,
    target_paths: Option<(&Path, &Path)>,
) -> Result<PreparedVote, Box<dyn Error>> {
    let mut chain_artifacts: Option<SuccessorChainArtifactFiles> = chain_inputs
        .as_ref()
        .map(SuccessorChainInputs::open)
        .transpose()?;
    if let Some(artifacts) = &chain_artifacts {
        if let Some(path) = output_path {
            artifacts.require_output_outside(path)?;
        }
        if let Some((state, blobs)) = target_paths {
            for path in [state, blobs] {
                artifacts.require_output_outside(path)?;
            }
        }
    }
    let history: ImmutableArchive = ImmutableArchive::open_read_only(inputs.history_root())?;
    let cut: ImmutableArchive = ImmutableArchive::open_read_only(cut_directory)?;
    if let Some(path) = output_path {
        for source in [&history, &cut] {
            source.require_output_outside(path)?;
        }
    }
    if let Some((state, blobs)) = target_paths {
        if state == blobs {
            return Err("state and blob paths must be distinct".into());
        }
        for path in [state, blobs] {
            history.require_output_outside(path)?;
            cut.require_output_outside(path)?;
        }
    }
    let next_set: ValidatorSet = decode_readiness_set(&read_bounded_file(
        next_path,
        MAX_READINESS_SET_BYTES,
        "next set",
    )?)?;
    let pins: BusinessPins = match (&chain_inputs, &mut chain_artifacts) {
        (Some(chain), Some(artifacts)) => inputs.load_with_successor(artifacts, chain.budget)?,
        (None, None) => inputs.load()?,
        _ => return Err("successor predecessor artifacts are incomplete".into()),
    };
    let private = pins.plan(private_operation()?);
    let saved: SavedBusinessCut = read_business_cut_archive(&private, &cut)?;
    let verified: VerifiedImportPlan = match pins.successor_authority() {
        Some(authority) => {
            verify_saved_business_import_chain(private, authority, pins.cut_identity(), &saved)?
        }
        None => verify_saved_business_import(private, &saved)?,
    };
    let subject: ReadinessSubject =
        readiness_subject_for_candidate(verified.binding(), pins.resolver(), &next_set)?;
    Ok(PreparedVote {
        chain_artifacts,
        history,
        cut,
        next_set,
        pins,
        saved,
        verified,
        subject,
    })
}

fn produce_vote(
    context: VoteContext<'_>,
    owner: &ReadinessCertifier<'_>,
    inputs: (PathBuf, PathBuf, ValidatorId, PathBuf),
) -> Result<Vec<u8>, Box<dyn Error>> {
    let VoteContext {
        pins,
        verified,
        saved,
        next_set,
        history,
        cut,
        prior_output,
        anchor,
        timeout,
    } = context;
    let (state, blobs, validator, key_path): (PathBuf, PathBuf, ValidatorId, PathBuf) = inputs;
    for path in [&state, &blobs] {
        history.require_output_outside(path)?;
        cut.require_output_outside(path)?;
    }
    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), validator, pins.domain);
    let target: SqliteImportTarget =
        crate::local_anchor::open_import(&state, &blobs, anchor, namespace, verified.binding())?;
    let bodies: SqliteBlobStore = SqliteBlobStore::open_existing(&blobs)?;
    let key_path: PathBuf = if key_path.is_absolute() {
        key_path
    } else {
        std::env::current_dir()?.join(key_path)
    };
    let key_directory: ImmutableArchive = ImmutableArchive::open_read_only(
        key_path
            .parent()
            .ok_or("signer key has no parent directory")?,
    )?;
    let key: ed25519_zebra::SigningKey = load_signing_key_file(&key_path)?;
    let key_name: &str = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("signer key filename is not a normal UTF-8 component")?;
    // Reuse held-parent/leaf artifact checks without widening historical
    // key consumers. These bytes are never logged or written as artifacts.
    let mut checked_key: Vec<u8> = key_directory.read(key_name, 32)?;
    let matches: bool = checked_key.as_slice() == key.as_ref();
    checked_key.fill(0);
    if !matches {
        return Err("signer key changed while loading".into());
    }
    let signer: ReadinessSigningKey = ReadinessSigningKey::new(validator, key);
    if let Some((output, filename)) = prior_output
        && output.contains(filename)?
    {
        let previous: ReadinessVote =
            decode_readiness_vote(&output.read(filename, MAX_READINESS_VOTE_BYTES)?)?;
        if previous.signer != validator {
            return Err("saved vote signer mismatch".into());
        }
        owner.verify_vote(&previous)?;
    }
    let members: Vec<FastPathValidatorEntry> = next_set
        .validators()
        .iter()
        .map(|member| FastPathValidatorEntry {
            id: member.id,
            voting_power: member.voting_power,
            signature_scheme: member.signature_scheme,
            public_key: member.public_key.clone(),
        })
        .collect();
    let operation: runtime::DurableOperationContext =
        operation(target.writer_fence()?, timeout, [0xBB; 16])?;
    key_directory.ensure_attached()?;
    let vote: ReadinessVote = match pins.successor_authority() {
        Some(authority) => retain_conditional_readiness_chain(
            pins.plan(private_operation()?),
            authority,
            pins.cut_identity(),
            saved,
            &target,
            &bodies,
            &operation,
            &members,
            &signer,
        )?,
        None => retain_conditional_readiness(
            pins.plan(private_operation()?),
            saved,
            &target,
            &bodies,
            &operation,
            &members,
            &signer,
        )?,
    };
    Ok(encode_readiness_vote(&vote)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_refuses_authority_modes_without_io() {
        assert!(run([OsString::from("--help")]).is_ok());
        for mode in [
            "activate",
            "seal",
            "ordinary",
            "force",
            "vote-sqlite",
            "certificate",
        ] {
            assert!(run([OsString::from(mode)]).is_err());
        }
        assert!(run([]).is_err());
    }
}
