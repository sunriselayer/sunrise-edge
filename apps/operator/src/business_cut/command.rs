//! Callable local SQLite pre-Seal candidate export and database-free verification.
#![forbid(unsafe_code)]

use crate::{
    business_cut::{CutArchiveLimits, export_source_business_cut, verify_business_cut_archive},
    common::{FlagSet, load_trusted_genesis_manifest, parse_hash_suite, parse_hex_32},
    immutable_archive::ImmutableArchive,
    source_sqlite::ExistingSqliteSource,
};
use execution::{
    LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy,
    publication::PublicationContext,
};
use hashing::HashSuiteResolver;
use node_core::admission_profile::VerifiedAdmissionProfile;
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
};
use node_core::{GenesisManifest, genesis_manifest_commitment};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use std::{error::Error, ffi::OsString, path::PathBuf};
use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;
use validator_set::{ValidatorInfo, ValidatorSet};

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

fn bounded(value: &str, minimum: u64, maximum: u64) -> Result<u64, Box<dyn Error>> {
    let parsed: u64 = value.parse()?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err("integer outside operator bound".into());
    }
    Ok(parsed)
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn offline_operation() -> Result<DurableOperationContext, Box<dyn Error>> {
    // This fence exists only in the private reconstruction memory store.
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).ok_or("zero private fence")?;
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(3_600_000)
        .ok_or("private deadline overflow")?;
    Ok(DurableOperationContext::new(
        fence,
        StorageDeadline::new(deadline).ok_or("invalid private deadline")?,
        StorageCorrelationId::new([0xB9; 16]).ok_or("invalid private correlation")?,
    ))
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
    let chain: ChainId = ChainId::new(flags.one("--chain-id")?)?;
    let protocol: ProtocolVersion = ProtocolVersion::new(u32::try_from(bounded(
        &flags.one("--protocol-version")?,
        1,
        u64::from(u32::MAX),
    )?)?);
    let epoch: Epoch = Epoch::new(bounded(&flags.one("--epoch")?, 0, u64::MAX)?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)?;
    let suite_inputs: Vec<String> = flags.many("--suite");
    if suite_inputs.is_empty() || suite_inputs.len() > 64 {
        return Err("one to 64 explicit suite entries required".into());
    }
    let schedule: Vec<HashSuiteSchedule> = suite_inputs
        .iter()
        .map(|value: &String| parse_hash_suite(value))
        .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
    let resolver: HashSuiteResolver = HashSuiteResolver::new(chain.clone(), protocol, schedule)?;
    let context: PublicationContext = PublicationContext::new(chain.clone(), protocol, epoch)?;
    let genesis_file: PathBuf = flags.one("--genesis-manifest")?.into();
    let genesis_pin: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let history_root: PathBuf = flags.one("--ordered-history-dir")?.into();
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
    let manifest: GenesisManifest =
        load_trusted_genesis_manifest(&genesis_file, &resolver, genesis_pin, &context)?;
    let digest = genesis_manifest_commitment(&resolver, &manifest)?;
    let profile: VerifiedAdmissionProfile =
        VerifiedAdmissionProfile::from_pinned_genesis(&resolver, &manifest, digest)?;
    if !profile.is_causal() {
        return Err("business cut requires signed causal-admission genesis".into());
    }
    let validators: Vec<ValidatorInfo> = manifest
        .validator_set
        .validators
        .iter()
        .map(|member| ValidatorInfo {
            id: member.id,
            voting_power: member.voting_power,
            signature_scheme: member.signature_scheme,
            public_key: member.public_key.clone(),
        })
        .collect();
    let set: ValidatorSet = ValidatorSet::new(epoch, validators)?;
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        context.clone(),
        domain,
        digest,
        Some(&manifest),
        set,
        resolver.clone(),
    )?;
    let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        read_verified_ordered_history_archive(&policy, &history_root)?;
    let archive: ImmutableArchive = if exporting {
        ImmutableArchive::open(&output)?
    } else {
        ImmutableArchive::open_read_only(&output)?
    };
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context);
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let source: Option<ExistingSqliteSource> = if let Some(inputs) = &export_inputs {
        if policy.registered_validator(inputs.validator).is_none() {
            return Err("source validator is absent from pinned genesis".into());
        }
        Some(ExistingSqliteSource::open(
            &inputs.state,
            &inputs.blobs,
            chain,
            inputs.validator,
            domain,
            inputs.timeout,
        )?)
    } else {
        None
    };
    let operation: DurableOperationContext = match &source {
        Some(source) => source.operation,
        None => offline_operation()?,
    };
    let plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
        admission_profile: &profile,
        genesis: &manifest,
        pinned_genesis_digest: digest,
        operation_context: operation,
        domain,
        resolver: &resolver,
        resolver_history: &[],
        ordered_policy: &policy,
        ordered_history_identity: &identity,
        ordered_leg_policy: &base_policy,
        ordered_engine: &engine,
        paid_base_policy: &base_policy,
        paid_engine: &engine,
    };
    if let (Some(source), Some(inputs)) = (&source, export_inputs) {
        let progress = export_source_business_cut(
            plan,
            &source.durable,
            &source.blobs,
            &ordered,
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
