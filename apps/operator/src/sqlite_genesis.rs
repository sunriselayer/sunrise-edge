//! DR-0195 local SQLite signed-original-genesis preparation and advisory
//! preflight. `prepare` consumes one already signed genesis manifest into
//! fresh independent local SQLite namespaces, strictly reusing the existing
//! core installers (`node_core::genesis::install_genesis`,
//! `node_core::ordered_economics::install_ordered_genesis`). `preflight` is
//! a read-only, non-mutating, non-authoritative diagnostic reusing the
//! exact original-host pin checks in `sqlite_genesis_checks`. Neither mode
//! constructs or signs a genesis manifest, reads a private signing seed,
//! opens a listener, or advances a writer fence beyond preparation's own
//! initial bootstrap.
#![forbid(unsafe_code)]

use crate::common::{FlagSet, parse_hash_suite, parse_hex_32};
use crate::sqlite_genesis_checks::{
    OriginalHostPins, read_original_host_state, read_stable_advisory, verify_original_signer,
};
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
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
use std::{error::Error, ffi::OsString, path::Path, path::PathBuf};
use sunrise_edge_client::load_verified_genesis_root;

const SUITE_COUNT_MESSAGE: &str = "one to 64 explicit --suite entries required";
const ZERO_PROTOCOL_VERSION: &str = "zero --protocol-version";
const CHECKPOINT_MESSAGE: &str = "invalid --created-checkpoint";
const PREPARE_REQUIRES_CAUSAL: &str =
    "sqlite-genesis prepare requires a causal-admission genesis to install a fresh namespace";
const NOT_COMMITTEE_MEMBER: &str =
    "--validator-id is not a member of the original signed genesis committee";
const ZERO_WRITER_FENCE: &str = "zero initial writer fence";
const DEADLINE_OVERFLOW: &str = "preparation deadline overflow";
const INVALID_DEADLINE: &str = "invalid preparation deadline";
const INVALID_CORRELATION: &str = "invalid preparation correlation id";
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];
const DESTINATION_ALIAS: &str =
    "a fresh destination or its -wal/-shm/-journal sidecar aliases another destination";
const PREFLIGHT_REQUIRES_CAUSAL: &str =
    "sqlite-genesis preflight requires a causal-admission genesis";

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

fn run_prepare(tokens: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(tokens, PREPARE_VALUE_FLAGS, &[])?;
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
        return Err(ZERO_PROTOCOL_VERSION.into());
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
        return Err(SUITE_COUNT_MESSAGE.into());
    }
    let schedule: Vec<HashSuiteSchedule> = suite_inputs
        .iter()
        .map(|value: &String| parse_hash_suite(value))
        .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
    let manifest_path: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
    let expected_digest: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let state_db: PathBuf = PathBuf::from(flags.one("--state-db")?);
    let blob_db: PathBuf = PathBuf::from(flags.one("--blob-db")?);
    let created_checkpoint: u64 = flags
        .one("--created-checkpoint")?
        .parse()
        .map_err(|_| CHECKPOINT_MESSAGE)?;
    flags.finish()?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(chain.clone(), protocol_version, schedule)?;
    let expected_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, epoch)?;
    let root: VerifiedGenesisRoot = load_verified_genesis_root(
        &manifest_path,
        &resolver,
        expected_digest,
        &expected_context,
    )?;
    if !root.admission_profile().is_causal() {
        return Err(PREPARE_REQUIRES_CAUSAL.into());
    }
    if root.genesis_committee().get(validator).is_none() {
        return Err(NOT_COMMITTEE_MEMBER.into());
    }
    // Pure policy composition must refuse unsupported input before either
    // destination is reserved. Installation failures later preserve partial
    // files and never report success or attempt automatic repair.
    let ordered_policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, domain)?;
    let (state_db, blob_db): (PathBuf, PathBuf) =
        require_fresh_destination_set(&state_db, &blob_db)?;
    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let initial_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(1).ok_or(ZERO_WRITER_FENCE)?;
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&state_db, namespace, initial_fence)?;
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(&blob_db)?;
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(60_000)
        .ok_or(DEADLINE_OVERFLOW)?;
    let operation: DurableOperationContext = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(deadline).ok_or(INVALID_DEADLINE)?,
        StorageCorrelationId::new([0x47; 16]).ok_or(INVALID_CORRELATION)?,
    );
    node_core::genesis::install_genesis(
        &store,
        &operation,
        domain,
        &resolver,
        root.manifest(),
        created_checkpoint,
    )?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &ordered_policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
        seal: None,
    };
    let now_unix_millis: u64 = SystemClock.now_unix_millis()?;
    node_core::ordered_economics::install_ordered_genesis(
        &store,
        &operation,
        &env,
        now_unix_millis,
    )?;
    store.sync_created()?;
    blobs.sync_created()?;
    println!(
        "complete=true mode=prepare chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_fence={}",
        protocol_version.get(),
        epoch.get(),
        initial_fence.get(),
    );
    use std::io::Write;
    std::io::stdout().flush()?;
    Ok(())
}

fn require_fresh_destination_set(
    state_db: &Path,
    blob_db: &Path,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    // Both prospective parents, main files and sidecars are checked before
    // creation of either file. Only NotFound proves a prospective leaf absent.
    let state_main: PathBuf = runtime_sqlite::validate_fresh_sqlite_destination(state_db)?;
    let blob_main: PathBuf = runtime_sqlite::validate_fresh_sqlite_destination(blob_db)?;
    let mut candidates: Vec<PathBuf> = vec![state_main.clone(), blob_main.clone()];
    for main in [&state_main, &blob_main] {
        for suffix in SIDECAR_SUFFIXES {
            let mut sidecar = main.as_os_str().to_owned();
            sidecar.push(suffix);
            candidates.push(PathBuf::from(sidecar));
        }
    }
    for i in 0..candidates.len() {
        for j in (i + 1)..candidates.len() {
            if candidates[i] == candidates[j] {
                return Err(DESTINATION_ALIAS.into());
            }
        }
    }
    Ok((state_main, blob_main))
}

pub fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut tokens = tokens.into_iter();
    let mode: OsString = tokens
        .next()
        .ok_or("missing subcommand: expected prepare or preflight")?;
    match mode.to_str() {
        Some("prepare") => run_prepare(tokens),
        Some("preflight") => run_preflight(tokens),
        Some(_) => Err("unknown sqlite-genesis subcommand; expected prepare or preflight".into()),
        None => Err("non-UTF8 subcommand".into()),
    }
}

/// Read-only, non-mutating, non-authoritative diagnostic: observes an
/// already prepared, ordinary, unsealed original-epoch namespace and
/// reports whether it agrees with the locally pinned genesis, causal
/// profile, committed fee policy, committee, explicit public key and
/// ordered status. Never opens a listener, advances a fence, or signs.
fn run_preflight(tokens: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(tokens, PREFLIGHT_VALUE_FLAGS, &[])?;
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
        return Err(ZERO_PROTOCOL_VERSION.into());
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
        return Err(SUITE_COUNT_MESSAGE.into());
    }
    let schedule: Vec<HashSuiteSchedule> = suite_inputs
        .iter()
        .map(|value: &String| parse_hash_suite(value))
        .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
    let manifest_path: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
    let expected_digest: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let state_db: PathBuf = PathBuf::from(flags.one("--state-db")?);
    let blob_db: PathBuf = PathBuf::from(flags.one("--blob-db")?);
    let public_key: [u8; 32] = parse_hex_32(
        &flags.one("--validator-public-key")?,
        "--validator-public-key",
    )?;
    flags.finish()?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(chain.clone(), protocol_version, schedule)?;
    let expected_context: PublicationContext =
        PublicationContext::new(chain.clone(), protocol_version, epoch)?;
    let root: VerifiedGenesisRoot = load_verified_genesis_root(
        &manifest_path,
        &resolver,
        expected_digest,
        &expected_context,
    )?;
    if !root.admission_profile().is_causal() {
        return Err(PREFLIGHT_REQUIRES_CAUSAL.into());
    }
    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let store: SqliteDurableStore = SqliteDurableStore::open_existing(&state_db, namespace)?;
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db)?;
    let observed_fence: WriterFenceGeneration = store.writer_fence()?;
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(60_000)
        .ok_or(DEADLINE_OVERFLOW)?;
    let operation: DurableOperationContext = DurableOperationContext::new(
        observed_fence,
        StorageDeadline::new(deadline).ok_or(INVALID_DEADLINE)?,
        StorageCorrelationId::new([0x50; 16]).ok_or(INVALID_CORRELATION)?,
    );
    let ordered_policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, domain)?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &ordered_policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: &blobs,
        seal: None,
    };
    let pins: OriginalHostPins<'_> = OriginalHostPins {
        domain,
        expected_context: &expected_context,
        root: &root,
        resolver: &resolver,
    };
    read_stable_advisory(&store, &operation, domain, || {
        let (_, record) = read_original_host_state(&store, &operation, &pins)?;
        verify_original_signer(&record, &root, validator, &public_key)?;
        node_core::ordered_economics::query_status(&store, &operation, &env)?;
        Ok(())
    })?;
    println!(
        "complete=true mode=preflight advisory=true chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_fence={}",
        protocol_version.get(),
        epoch.get(),
        observed_fence.get(),
    );
    use std::io::Write;
    std::io::stdout().flush()?;
    Ok(())
}
