//! Read-only real PostgreSQL business reconstruction under locally pinned
//! signed genesis and a complete, independently reverified ordered archive.
#![forbid(unsafe_code)]

use execution::{
    LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy,
    publication::PublicationContext,
};
use hashing::HashSuiteResolver;
use node_core::admission_profile::VerifiedAdmissionProfile;
use node_core::business_reconstruction::{
    BusinessReconstructionOverlay, BusinessReconstructionPlan, DrainSetControlMaterial,
    OwnedPublicationMaterial, drain_control_material_from_source_snapshot,
    owned_material_from_source_snapshot,
};
use node_core::ordered_economics::{OrderedEconomicsPolicy, encode_ordered_history_identity};
use node_core::{GenesisManifest, genesis_manifest_commitment};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion, ValidatorId};
use runtime::portable::DurablePortableSnapshotRepository;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
    inspect_namespace,
};
use std::{
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Write,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
};
use sunrise_edge_client::ordered_history_archive::{
    read_regular_archive_file, read_verified_ordered_history_archive,
};
use sunrise_edge_operator::{
    business_snapshot::capture_source_business_snapshot,
    common::{
        FlagSet, connect_pool, load_trusted_genesis_manifest, parse_hash_suite, parse_hex_32,
    },
};
use validator_set::{ValidatorInfo, ValidatorSet};

const FLAGS: &[&str] = &[
    "--tls-root-der",
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--validator-id",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--out-dir",
    "--page-size",
    "--timeout-seconds",
    "--max-new-publications",
    "--max-new-control-pages",
];
const HELP: &str = "Read-only business audit (fixed local snapshot; not freshness, cut/import, readiness or Seal).\nRequired: --tls-root-der --chain-id --protocol-version --epoch --validator-id --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir --out-dir.\nOptional: --page-size 1..128, --timeout-seconds 1..3600, --max-new-publications 1..4096, --max-new-control-pages 1..4096.\nConnection: SUNRISE_EDGE_OPERATOR_POSTGRES_DSN environment variable. No writer fence is advanced. Every control stream is reverified from its seed on resume. A changed saved source token refuses continuation; use a new output directory for a new observation.";

fn bounded(value: &str, min: u64, max: u64) -> Result<u64, Box<dyn Error>> {
    let parsed: u64 = value.parse()?;
    if !(min..=max).contains(&parsed) {
        return Err("integer outside the allowed operator bound".into());
    }
    Ok(parsed)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Publishes a completely synced immutable file, never a partially written
/// destination that a later resume could mistake for completed material.
fn persist_exact(root: &Path, name: &str, bytes: &[u8]) -> Result<bool, Box<dyn Error>> {
    let target: PathBuf = root.join(name);
    if target.exists() {
        if read_regular_archive_file(root, Path::new(name), bytes.len())? != bytes {
            return Err("saved audit artifact differs from the fixed observation".into());
        }
        return Ok(false);
    }
    let temporary: PathBuf = root.join(format!(
        ".audit-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    // A create_new collision is not ours to clean up. Acquire ownership before
    // entering the cleanup scope, including on a failed publication attempt.
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result: Result<(), Box<dyn Error>> = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, &target)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    let _ignored = std::fs::remove_file(&temporary);
    result?;
    Ok(true)
}

/// Saves bounded individual control pages under the already persisted genesis,
/// ordered target, and source token. This is an immutable cache, not a trusted
/// verifier cursor: the source assembler reverified all streams from their
/// seeds before reaching this function, on every invocation.
fn cache_control_pages(
    output: &Path,
    controls: &[DrainSetControlMaterial],
    maximum_new: u64,
) -> Result<bool, Box<dyn Error>> {
    let mut new_count: u64 = 0;
    for control in controls {
        let candidate: String = hex(&control.candidate_digest.bytes());
        for (vote, frontier) in control.selected_votes.iter().zip(&control.signer_frontiers) {
            let prefix: String = format!("control-{candidate}-{}", hex(vote.validator.as_bytes()));
            let vote_bytes: Vec<u8> = consensus::encode_frozen_frontier_vote(vote)?;
            persist_exact(output, &format!("{prefix}.vote"), &vote_bytes)?;
            for (index, page) in frontier.pages.iter().enumerate() {
                let number: u64 = u64::try_from(index)?;
                let name: String = format!("{prefix}-page-{number:020}.bin");
                let bytes: Vec<u8> = consensus::encode_frozen_frontier_page(page)?;
                let new: bool = !output.join(&name).exists();
                if new && new_count >= maximum_new {
                    println!(
                        "audit=partial cached_control_pages={new_count} note=no-semantic-equality-claim"
                    );
                    return Ok(false);
                }
                persist_exact(output, &name, &bytes)?;
                if new {
                    new_count = new_count
                        .checked_add(1)
                        .ok_or("control cache counter overflow")?;
                }
            }
        }
    }
    Ok(true)
}

fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let mut flags: FlagSet = FlagSet::parse(values, FLAGS, &[])?;
    let ca: PathBuf = flags.one("--tls-root-der")?.into();
    let chain: ChainId = ChainId::new(flags.one("--chain-id")?)?;
    let protocol: ProtocolVersion = ProtocolVersion::new(u32::try_from(bounded(
        &flags.one("--protocol-version")?,
        1,
        u64::from(u32::MAX),
    )?)?);
    let epoch: Epoch = Epoch::new(bounded(&flags.one("--epoch")?, 0, u64::MAX)?);
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)?;
    let suite_inputs: Vec<String> = flags.many("--suite");
    if suite_inputs.is_empty() || suite_inputs.len() > 64 {
        return Err("one to 64 explicit --suite entries required".into());
    }
    let schedule: Vec<protocol_types::HashSuiteSchedule> = suite_inputs
        .iter()
        .map(|value| parse_hash_suite(value))
        .collect::<Result<_, _>>()?;
    let resolver: HashSuiteResolver = HashSuiteResolver::new(chain.clone(), protocol, schedule)?;
    let expected: PublicationContext = PublicationContext::new(chain.clone(), protocol, epoch)?;
    let manifest_file: PathBuf = flags.one("--genesis-manifest")?.into();
    let pin: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let manifest: GenesisManifest =
        load_trusted_genesis_manifest(&manifest_file, &resolver, pin, &expected)?;
    let genesis_digest = genesis_manifest_commitment(&resolver, &manifest)?;
    let profile: VerifiedAdmissionProfile =
        VerifiedAdmissionProfile::from_pinned_genesis(&resolver, &manifest, genesis_digest)?;
    if !profile.is_causal() {
        return Err("business reconstruction requires signed causal-admission genesis".into());
    }
    let history_root: PathBuf = flags.one("--ordered-history-dir")?.into();
    let output: PathBuf = flags.one("--out-dir")?.into();
    let page: NonZeroUsize = NonZeroUsize::new(usize::try_from(bounded(
        &flags
            .optional_one("--page-size")?
            .unwrap_or_else(|| "128".into()),
        1,
        128,
    )?)?)
    .ok_or("zero page size")?;
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        3600,
    )?;
    let maximum_new: u64 = bounded(
        &flags
            .optional_one("--max-new-publications")?
            .unwrap_or_else(|| "4096".into()),
        1,
        4096,
    )?;
    let maximum_new_control_pages: u64 = bounded(
        &flags
            .optional_one("--max-new-control-pages")?
            .unwrap_or_else(|| "4096".into()),
        1,
        4096,
    )?;
    flags.finish()?;
    let members: Vec<ValidatorInfo> = manifest
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
    let set: ValidatorSet = ValidatorSet::new(epoch, members)?;
    if set.get(validator).is_none() {
        return Err("namespace validator absent from pinned genesis".into());
    }
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        expected.clone(),
        domain,
        genesis_digest,
        Some(&manifest),
        set,
        resolver.clone(),
    )?;
    let (identity, ordered) = read_verified_ordered_history_archive(&policy, &history_root)?;
    let pool = connect_pool(&ca, NonZeroU32::new(4).ok_or("zero pool")?)?;
    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let writer = {
        let mut connection = pool.get()?;
        inspect_namespace(&mut *connection, &namespace)?
            .ok_or("existing source namespace required")?
            .writer_fence()
    };
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(timeout.checked_mul(1000).ok_or("timeout overflow")?)
        .ok_or("deadline overflow")?;
    let operation: DurableOperationContext = DurableOperationContext::new(
        writer,
        StorageDeadline::new(deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new([0xB7; 16]).ok_or("invalid correlation")?,
    );
    let source = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retries")?)?,
    );
    let blobs = PostgresBlobStore::new(pool, namespace)?;
    let snapshot = capture_source_business_snapshot(&source, &blobs, &operation, domain, page)?;
    std::fs::create_dir_all(&output)?;
    let output: PathBuf = output.canonicalize()?;
    let mut source_pin: Vec<u8> = b"sunrise-business-audit-snapshot-v1\0".to_vec();
    source_pin.extend_from_slice(&pin);
    source_pin.extend_from_slice(domain.as_bytes());
    source_pin.extend_from_slice(&u16::try_from(snapshot.token.namespace().len())?.to_be_bytes());
    source_pin.extend_from_slice(snapshot.token.namespace());
    source_pin.extend_from_slice(&snapshot.token.writer_fence().get().to_be_bytes());
    source_pin.extend_from_slice(&snapshot.token.mutation_sequence().to_be_bytes());
    persist_exact(&output, "source-token.bin", &source_pin)?;
    persist_exact(
        &output,
        "ordered-identity.bin",
        &encode_ordered_history_identity(&identity)?,
    )?;
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(expected);
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let plan = BusinessReconstructionPlan {
        admission_profile: &profile,
        genesis: &manifest,
        pinned_genesis_digest: genesis_digest,
        operation_context: operation.clone(),
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
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&snapshot, &plan)?;
    let mut new_count: u64 = 0;
    for material in &owned {
        let name = format!("owned-{}", hex(&material.bundle.request_id));
        let bundle = consensus::bundle::encode_publication_bundle(&material.bundle)?;
        let new: bool = !output.join(format!("{name}.bundle")).exists();
        if new && new_count >= maximum_new {
            println!(
                "audit=partial cached_publications={} total_publications={} note=no-semantic-equality-claim",
                new_count,
                owned.len()
            );
            return Ok(());
        }
        persist_exact(&output, &format!("{name}.bundle"), &bundle)?;
        persist_exact(
            &output,
            &format!("{name}.availability"),
            material.availability_certificate.as_deref().unwrap_or(&[]),
        )?;
        persist_exact(
            &output,
            &format!("{name}.application"),
            &[u8::from(material.source_application_present)],
        )?;
        persist_exact(
            &output,
            &format!("{name}.checkpoint"),
            &material.recovery_created_checkpoint.to_be_bytes(),
        )?;
        if new {
            new_count = new_count.checked_add(1).ok_or("cache counter overflow")?;
        }
    }
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&snapshot, &plan, &ordered)?;
    if !cache_control_pages(&output, &controls, maximum_new_control_pages)? {
        return Ok(());
    }
    let mut overlay = BusinessReconstructionOverlay::new(plan)?;
    let _execution = overlay.reconstruct_with_control_material(&owned, &ordered, &controls)?;
    let _comparison = overlay.compare_source(&snapshot)?;
    source.check_portable_outbox_empty_at(&operation, domain, &snapshot.token)?;
    let report = format!(
        "audit=semantic-equal\ngenesis={}\nordered_height={}\nordered_digest={}\nowned_publications={}\ncontrol_selections={}\nsource_records={}\nsource_sequence={}\nsource_writer={}\nmeaning=fixed-source-snapshot-only-not-network-freshness-cut-import-readiness-seal-or-activation\n",
        hex(&pin),
        identity.through_height,
        hex(&identity.through_digest.bytes()),
        owned.len(),
        controls.len(),
        snapshot.records.len(),
        snapshot.token.mutation_sequence(),
        snapshot.token.writer_fence().get()
    );
    persist_exact(&output, "complete", report.as_bytes())?;
    print!("{report}");
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("business-audit refused: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NEXT_TEMP, persist_exact};
    use std::{path::PathBuf, sync::atomic::Ordering, time::SystemTime};

    struct AuditDirectory(PathBuf);

    impl AuditDirectory {
        fn new() -> Self {
            let stamp: u128 = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let path: PathBuf = std::env::temp_dir().join(format!(
                "sunrise-business-audit-files-{}-{stamp}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("new test-owned directory");
            Self(path)
        }
    }

    impl Drop for AuditDirectory {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn immutable_files_preserve_existing_targets_and_unowned_temp_collisions() {
        let root: AuditDirectory = AuditDirectory::new();
        let collision: PathBuf = root.0.join(format!(
            ".audit-{}-{}.tmp",
            std::process::id(),
            NEXT_TEMP.load(Ordering::Relaxed)
        ));
        std::fs::write(&collision, b"not owned by this invocation").unwrap();
        assert!(persist_exact(&root.0, "material.bin", b"original").is_err());
        assert_eq!(
            std::fs::read(&collision).unwrap(),
            b"not owned by this invocation"
        );
        assert!(!root.0.join("material.bin").exists());
        assert!(persist_exact(&root.0, "material.bin", b"original").unwrap());
        assert!(!persist_exact(&root.0, "material.bin", b"original").unwrap());
        assert!(persist_exact(&root.0, "material.bin", b"changed").is_err());
        assert_eq!(
            std::fs::read(root.0.join("material.bin")).unwrap(),
            b"original"
        );
    }
}
