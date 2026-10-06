//! Fresh original-genesis SQLite preparation and advisory public-key preflight.
//! Neither mode signs, loads a seed, starts a listener or repairs an existing
//! namespace. Existing core installers and host checks retain protocol authority.
#![forbid(unsafe_code)]

use crate::common::{FlagSet, parse_hash_suite, parse_hex_32};
use crate::sqlite_genesis_checks::{
    OriginalHostPins, read_original_host_state, read_stable_advisory, verify_original_signer,
};
use execution::paid_execution::PaidFeePolicy;
use execution::publication::PublicationContext;
use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{OrderedEconomicsEnvironment, OrderedEconomicsPolicy};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    error::Error,
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
};
use sunrise_edge_client::load_verified_genesis_root;

const PREPARE_VALUE_FLAGS: &[&str] = &[
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--state-db",
    "--blob-db",
    "--created-checkpoint",
];
const PREFLIGHT_VALUE_FLAGS: &[&str] = &[
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--state-db",
    "--blob-db",
    "--validator-public-key",
];
const OPERATION_MILLIS: u64 = 60_000;

struct OriginalOptions {
    chain: ChainId,
    validator: ValidatorId,
    domain: AtomicityDomainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    resolver: HashSuiteResolver,
    expected_context: PublicationContext,
    manifest_path: PathBuf,
    expected_digest: [u8; 32],
    state_db: PathBuf,
    blob_db: PathBuf,
}

impl OriginalOptions {
    fn parse(flags: &mut FlagSet) -> Result<Self, Box<dyn Error>> {
        let chain: ChainId =
            ChainId::new(flags.one("--chain-id")?).map_err(|_| "invalid --chain-id")?;
        let validator: ValidatorId = ValidatorId::new(parse_hex_32(
            &flags.one("--validator-id")?,
            "--validator-id",
        )?);
        let domain: AtomicityDomainId =
            AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)
                .map_err(|_| "zero --domain")?;
        let protocol_raw: u32 = flags
            .one("--protocol-version")?
            .parse()
            .map_err(|_| "invalid --protocol-version")?;
        if protocol_raw == 0 {
            return Err("zero --protocol-version".into());
        }
        let protocol_version: ProtocolVersion = ProtocolVersion::new(protocol_raw);
        let epoch: Epoch = Epoch::new(
            flags
                .one("--epoch")?
                .parse()
                .map_err(|_| "invalid --epoch")?,
        );
        let suite_inputs: Vec<String> = flags.many("--suite");
        if suite_inputs.is_empty() || suite_inputs.len() > 64 {
            return Err("one to 64 explicit --suite entries required".into());
        }
        let schedule: Vec<HashSuiteSchedule> = suite_inputs
            .iter()
            .map(|value: &String| parse_hash_suite(value))
            .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
        let resolver: HashSuiteResolver =
            HashSuiteResolver::new(chain.clone(), protocol_version, schedule)?;
        let expected_context: PublicationContext =
            PublicationContext::new(chain.clone(), protocol_version, epoch)?;
        Ok(Self {
            chain,
            validator,
            domain,
            protocol_version,
            epoch,
            resolver,
            expected_context,
            manifest_path: PathBuf::from(flags.one("--genesis-manifest")?),
            expected_digest: parse_hex_32(
                &flags.one("--expected-genesis-digest")?,
                "--expected-genesis-digest",
            )?,
            state_db: PathBuf::from(flags.one("--state-db")?),
            blob_db: PathBuf::from(flags.one("--blob-db")?),
        })
    }

    fn namespace(&self) -> SqliteNamespace {
        SqliteNamespace::new(self.chain.clone(), self.validator, self.domain)
    }
}

enum Mode {
    Prepare(u64),
    Preflight([u8; 32]),
}

pub fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut tokens = tokens.into_iter();
    let mode: OsString = tokens
        .next()
        .ok_or("missing subcommand: expected prepare or preflight")?;
    let value_flags: &[&str] = match mode.to_str() {
        Some("prepare") => PREPARE_VALUE_FLAGS,
        Some("preflight") => PREFLIGHT_VALUE_FLAGS,
        Some(_) => {
            return Err("unknown sqlite-genesis subcommand; expected prepare or preflight".into());
        }
        None => return Err("non-UTF8 subcommand".into()),
    };
    let mut flags: FlagSet = FlagSet::parse(tokens, value_flags, &[])?;
    let options: OriginalOptions = OriginalOptions::parse(&mut flags)?;
    let command: Mode = if mode == "prepare" {
        Mode::Prepare(
            flags
                .one("--created-checkpoint")?
                .parse()
                .map_err(|_| "invalid --created-checkpoint")?,
        )
    } else {
        Mode::Preflight(parse_hex_32(
            &flags.one("--validator-public-key")?,
            "--validator-public-key",
        )?)
    };
    flags.finish()?;
    let root: VerifiedGenesisRoot = load_verified_genesis_root(
        &options.manifest_path,
        &options.resolver,
        options.expected_digest,
        &options.expected_context,
    )?;
    if !root.admission_profile().is_causal() {
        return Err("sqlite-genesis requires a causal-admission genesis".into());
    }
    // Unsupported policy refuses before either destination is reserved.
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, options.domain)?;
    match command {
        Mode::Prepare(checkpoint) => prepare(&options, &root, &policy, checkpoint),
        Mode::Preflight(public_key) => preflight(&options, &root, &policy, &public_key),
    }
}

fn operation(
    fence: WriterFenceGeneration,
    correlation: u8,
) -> Result<DurableOperationContext, Box<dyn Error>> {
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(OPERATION_MILLIS)
        .ok_or("local SQLite operation deadline overflow")?;
    Ok(DurableOperationContext::new(
        fence,
        StorageDeadline::new(deadline).ok_or("invalid local SQLite deadline")?,
        StorageCorrelationId::new([correlation; 16])
            .ok_or("invalid local SQLite correlation id")?,
    ))
}

fn prepare(
    options: &OriginalOptions,
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    checkpoint: u64,
) -> Result<(), Box<dyn Error>> {
    if root.genesis_committee().get(options.validator).is_none() {
        return Err(
            "--validator-id is not a member of the original signed genesis committee".into(),
        );
    }
    let (state_db, blob_db): (PathBuf, PathBuf) =
        require_fresh_destination_set(&options.state_db, &options.blob_db)?;
    let fence: WriterFenceGeneration =
        WriterFenceGeneration::new(1).ok_or("zero initial writer fence")?;
    let context: DurableOperationContext = operation(fence, 0x47)?;
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(state_db, options.namespace(), fence)?;
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(blob_db)?;
    node_core::genesis::install_genesis(
        &store,
        &context,
        options.domain,
        &options.resolver,
        root.manifest(),
        checkpoint,
    )?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(options.expected_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
        seal: None,
    };
    node_core::ordered_economics::install_ordered_genesis(
        &store,
        &context,
        &environment,
        SystemClock.now_unix_millis()?,
    )?;
    store.sync_created()?;
    blobs.sync_created()?;
    println!(
        "complete=true mode=prepare chain_id={} validator_id={} domain={} protocol_version={} epoch={} writer_fence={}",
        options.chain,
        options.validator,
        options.domain,
        options.protocol_version.get(),
        options.epoch.get(),
        fence.get()
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn require_fresh_destination_set(
    state_db: &Path,
    blob_db: &Path,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    // Check both complete prospective paths before creating either resource.
    let state_main: PathBuf = runtime_sqlite::validate_fresh_sqlite_destination(state_db)?;
    let blob_main: PathBuf = runtime_sqlite::validate_fresh_sqlite_destination(blob_db)?;
    let mut candidates: Vec<PathBuf> = vec![state_main.clone(), blob_main.clone()];
    for main in [&state_main, &blob_main] {
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = main.as_os_str().to_owned();
            sidecar.push(suffix);
            candidates.push(PathBuf::from(sidecar));
        }
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[index + 1..].contains(candidate) {
            return Err(
                "a fresh destination or its -wal/-shm/-journal sidecar aliases another destination"
                    .into(),
            );
        }
    }
    Ok((state_main, blob_main))
}

fn preflight(
    options: &OriginalOptions,
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    public_key: &[u8; 32],
) -> Result<(), Box<dyn Error>> {
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&options.state_db, options.namespace())?;
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&options.blob_db)?;
    let fence: WriterFenceGeneration = store.writer_fence()?;
    let context: DurableOperationContext = operation(fence, 0x50)?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(options.expected_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
        seal: None,
    };
    let pins: OriginalHostPins<'_> = OriginalHostPins {
        domain: options.domain,
        expected_context: &options.expected_context,
        root,
        resolver: &options.resolver,
    };
    read_stable_advisory(&store, &context, options.domain, || {
        let (_fee, record): (PaidFeePolicy, FastPathValidatorSetRecord) =
            read_original_host_state(&store, &context, &pins)?;
        verify_original_signer(&record, root, options.validator, public_key)?;
        node_core::ordered_economics::query_status(&store, &context, &environment)?;
        Ok(())
    })?;
    println!(
        "complete=true mode=preflight advisory=true chain_id={} validator_id={} domain={} protocol_version={} epoch={} writer_fence={}",
        options.chain,
        options.validator,
        options.domain,
        options.protocol_version.get(),
        options.epoch.get(),
        fence.get()
    );
    std::io::stdout().flush()?;
    Ok(())
}
