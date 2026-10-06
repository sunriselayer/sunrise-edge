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
const PARENT_TRAVERSAL: &str = "fresh destination cannot traverse parent components";
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];
const DESTINATION_ALIAS: &str =
    "a fresh destination or its -wal/-shm/-journal sidecar aliases another destination";
const DESTINATION_EXISTS: &str = "a fresh destination, or its -wal/-shm/-journal sidecar, already exists; preparation is fresh-only";
const PREFLIGHT_REQUIRES_CAUSAL: &str =
    "sqlite-genesis preflight requires a causal-admission genesis";
const TOKEN_CHANGED: &str =
    "source changed during preflight; refusing to report an advisory success";

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
    require_fresh_destination_set(&state_db, &blob_db)?;
    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let initial_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(1).ok_or(ZERO_WRITER_FENCE)?;
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&state_db, namespace, initial_fence)?;
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new(&blob_db)?;
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
    let now_unix_millis: u64 = SystemClock.now_unix_millis()?;
    node_core::ordered_economics::install_ordered_genesis(
        &store,
        &operation,
        &env,
        now_unix_millis,
    )?;
    runtime_sqlite::sync_freshly_created_destination(&state_db)?;
    runtime_sqlite::sync_freshly_created_destination(&blob_db)?;
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

/// Normalizes a destination path without touching the filesystem: resolves
/// against the current directory if relative, strips `.` components, and
/// refuses `..` traversal. Does not require the path to exist.
fn normalize_fresh_path(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let absolute: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result: PathBuf = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => return Err(PARENT_TRAVERSAL.into()),
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    Ok(result)
}

fn require_fresh_destination_set(state_db: &Path, blob_db: &Path) -> Result<(), Box<dyn Error>> {
    let state_main: PathBuf = normalize_fresh_path(state_db)?;
    let blob_main: PathBuf = normalize_fresh_path(blob_db)?;
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
    for candidate in &candidates {
        if std::fs::symlink_metadata(candidate).is_ok() {
            return Err(DESTINATION_EXISTS.into());
        }
    }
    Ok(())
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
    node_core::require_ordinary_namespace(&store, &operation, domain)?;
    use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
    let token_before: PortableSnapshotToken = store.begin_portable_snapshot(&operation, domain)?;
    crate::sqlite_genesis_checks::verify_original_host_pins(
        &store,
        &operation,
        domain,
        &expected_context,
        &root,
        &resolver,
        validator,
        &public_key,
    )?;
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
    node_core::ordered_economics::query_status(&store, &operation, &env)?;
    let token_after: PortableSnapshotToken = store.begin_portable_snapshot(&operation, domain)?;
    if token_before != token_after {
        return Err(TOKEN_CHANGED.into());
    }
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
