//! Certified-only FastVote PostgreSQL hosting operator (DR-0148).
//!
//! Serves `native_http::certified_fastvote_router` -- the certified-only
//! FastVote HTTP surface that structurally excludes every direct/legacy
//! mutating route -- bound to loopback only, backed by one already
//! bootstrapped PostgreSQL namespace. This binary never installs genesis,
//! never advances or changes the committed validator set or fee policy, and
//! never exposes a lifecycle/activation route: it only opens an existing
//! namespace, verifies the local operator's own trusted composition against
//! what is already durably committed there, and serves bounded reads plus
//! the two FastVote routes until shut down.
//!
//! Shares `fastvote_pg`'s own conventions and several small helpers
//! (bounded flag parsing, the TOCTOU-safe local signing-key file loader, the
//! TLS-only PostgreSQL connection builder, and the bounded SDK verified
//! genesis root loader) rather than reimplementing them; this binary adds
//! no new trust model beyond what that CLI's own doc comments already
//! establish.
//!
//! Trust boundaries:
//!
//! * `--genesis-manifest`/`--expected-genesis-digest` are the same offline,
//!   locally trusted pin `fastvote_pg` uses: the manifest file is trusted
//!   only after its commitment digest, embedded context, and authority
//!   signature all match exactly.
//! * This binary never calls `install_genesis_with_history`. It only reads
//!   the already-committed genesis marker, fee policy, and validator-set
//!   record and requires them to match the trusted manifest exactly
//!   (`require_committed_genesis_fee_policy`/`require_registered_signer`),
//!   failing closed before opening any listener if the namespace was never
//!   bootstrapped or was bootstrapped from a different manifest.
//! * `--confirm-offline-fence-advance` is required, exactly like
//!   `fastvote_pg`'s own mutating subcommands: starting this host claims
//!   (advances) the namespace's writer-fence generation exactly once, so
//!   the operator must stop any other writer against this namespace first.
//!   The claimed generation is fixed for this process's entire lifetime and
//!   is the one every served HTTP request's `DurableOperationContext` uses;
//!   it is never reclaimed or advanced again while serving.
//! * `--listen` must be a loopback address. This binary never terminates
//!   TLS itself: reaching it from anywhere other than loopback requires an
//!   externally configured TLS-terminating proxy the operator controls, and
//!   that proxy is not part of this protocol's trust boundary.
//! * `--enable-ordered-economics` additionally requires the already-loaded,
//!   already-live-pinned committed validator-set record to exactly equal
//!   the trusted root's own signed genesis committee/context
//!   (`require_committed_record_matches_root_committee`), before claiming
//!   the writer-fence generation. `require_live_fastvote_pin` alone only
//!   proves the record matches the live epoch digest, not that it still
//!   agrees with the independently pinned signed genesis the ordered engine
//!   derives its policy from.
#![forbid(unsafe_code)]

use sunrise_edge_operator::common::{
    FlagSet, connect_pool, load_signing_key_file, parse_hex_32, require_live_fastvote_pin,
};
use sunrise_edge_operator::host_protocol_context::host_query_protocol_config;
use sunrise_edge_operator::host_runtime::{
    FileEd25519Signer, NoOutboundTransport, SequentialIdentitySource, fast_path_committee_matches,
    require_committed_genesis_fee_policy, require_registered_signer,
};

use consensus::ConsensusSigner;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::PaidFeePolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use native_http::ordered_economics::{OrderedEconomicsState, certified_ordered_economics_router};
use native_http::{
    FastVoteComposition, NativeBlockingExecutor, NativeBlockingPolicy, PaidExecutionComposition,
    StructuredDurableNativeComponents, StructuredDurableRequestAuthority,
    certified_fastvote_router_with_executor,
};
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::decode_fastpath_validator_set_record;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::OrderedEconomicsPolicy;
use node_core::{NodeConfig, local_instance_state};
use postgres_rustls::MakeTlsConnector;
use protocol_config::ProtocolConfig;
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule,
    ProtocolVersion, ValidatorId,
};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    SystemClock, WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
    advance_writer_fence, inspect_namespace,
};
use std::{
    error::Error, ffi::OsString, num::NonZeroU32, num::NonZeroUsize, path::PathBuf,
    process::ExitCode, sync::Arc, time::Duration,
};
use sunrise_edge_client::load_verified_genesis_root;

fn parse_chain(value: String) -> Result<ChainId, String> {
    ChainId::new(value).map_err(|_| "invalid --chain-id".to_string())
}

fn parse_validator(value: &str) -> Result<ValidatorId, String> {
    Ok(ValidatorId::new(parse_hex_32(value, "--validator-id")?))
}

fn parse_domain(value: &str) -> Result<AtomicityDomainId, String> {
    AtomicityDomainId::new(parse_hex_32(value, "--domain")?).map_err(|_| "zero --domain".into())
}

fn parse_protocol_version(value: &str) -> Result<ProtocolVersion, String> {
    let version: u32 = value.parse().map_err(|_| "invalid --protocol-version")?;
    if version == 0 {
        return Err("zero --protocol-version".into());
    }
    Ok(ProtocolVersion::new(version))
}

fn parse_epoch(value: &str) -> Result<Epoch, String> {
    let epoch: u64 = value.parse().map_err(|_| "invalid --epoch")?;
    Ok(Epoch::new(epoch))
}

fn parse_u64_bounded(value: &str, field: &str, min: u64, max: u64) -> Result<u64, String> {
    let parsed: u64 = value.parse().map_err(|_| format!("invalid {field}"))?;
    if !(min..=max).contains(&parsed) {
        return Err(format!("{field} must be {min}..={max}"));
    }
    Ok(parsed)
}

fn parse_suite(value: &str) -> Result<HashSuiteSchedule, String> {
    let fields: Vec<&str> = value.split(':').collect();
    if fields.len() != 8 {
        return Err(
            "--suite needs epoch:id:transaction:object:effects:code:config:certificate (decimal wire ids)"
                .into(),
        );
    }
    let epoch: u64 = fields[0].parse().map_err(|_| "invalid suite epoch")?;
    let id: u16 = fields[1].parse().map_err(|_| "invalid suite id")?;
    if id == 0 {
        return Err("zero suite id".into());
    }
    let algorithm = |index: usize| -> Result<HashAlgorithmId, String> {
        let number: u16 = fields[index]
            .parse()
            .map_err(|_| "invalid hash algorithm id")?;
        match HashAlgorithmId::try_from(number) {
            Ok(HashAlgorithmId::Sha2_256) => Ok(HashAlgorithmId::Sha2_256),
            Ok(HashAlgorithmId::Sha3_256) => Ok(HashAlgorithmId::Sha3_256),
            _ => Err("unsupported hash algorithm id".into()),
        }
    };
    Ok(HashSuiteSchedule {
        activation_epoch: Epoch::new(epoch),
        suite: HashSuite {
            id: HashSuiteId::new(id),
            transaction_hash: algorithm(2)?,
            object_digest: algorithm(3)?,
            effects_hash: algorithm(4)?,
            code_hash: algorithm(5)?,
            config_hash: algorithm(6)?,
            certificate_hash: algorithm(7)?,
        },
    })
}

fn parse_schedule(values: &[String]) -> Result<Vec<HashSuiteSchedule>, String> {
    if values.is_empty() {
        return Err("at least one --suite is required".into());
    }
    if values.len() > 64 {
        return Err("too many --suite entries (maximum 64)".into());
    }
    values.iter().map(|value| parse_suite(value)).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

// ---------------------------------------------------------------------
// Genesis manifest trust: identical to `fastvote_pg`'s own loader.
// ---------------------------------------------------------------------

/// Required only when `--enable-ordered-economics` is set, before claiming
/// the writer-fence generation or exposing any listener.
///
/// This is not a new serving/activation token, and the root is not
/// installed-row evidence: `require_live_fastvote_pin` already requires the
/// actually committed record to match the live epoch digest, but a
/// coherently altered record paired with a matching altered live digest
/// would still pass that check while disagreeing with the independently
/// pinned signed genesis. Exact equality against `root.manifest()`'s own
/// signed committee/context closes that gap for the one opt-in path
/// (`OrderedEconomicsPolicy::from_genesis_root`) that no longer performs its
/// own internal comparison against a caller-supplied validator set.
fn require_committed_record_matches_root_committee(
    record: &FastPathValidatorSetRecord,
    root_committee: &FastPathValidatorSetRecord,
) -> Result<(), String> {
    if !fast_path_committee_matches(record, root_committee) {
        return Err(
            "committed fast-path validator set does not match the trusted verified root's original signed committee/context; refusing to enable the opt-in ordered-economics path"
                .into(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------
// PostgreSQL connection wiring: identical to `fastvote_pg`'s own
// TLS-validated DSN pattern.
// ---------------------------------------------------------------------

/// Claims a fresh writer generation exactly once, at startup. Unlike
/// `fastvote_pg`'s per-operation claim/reconcile pair, this host keeps the
/// claimed generation fixed for its entire serving lifetime: every request
/// this process later serves uses this exact generation via
/// `StructuredDurableRequestAuthority`, and a durable commit made under a
/// since-superseded generation fails closed at the storage layer rather than
/// silently reclaiming a fresh one mid-request.
fn claim_fresh_writer_fence_once(
    pool: &Pool<PostgresConnectionManager<MakeTlsConnector>>,
    namespace: &PostgresNamespace,
    timeout_seconds: u64,
    expected_previous: WriterFenceGeneration,
) -> Result<(DurableOperationContext, WriterFenceGeneration), Box<dyn Error>> {
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable")?;
    let previous: WriterFenceGeneration = inspect_namespace(&mut *connection, namespace)?
        .ok_or("PostgreSQL namespace not bootstrapped; run fastvote_pg namespace-init/install-genesis first")?
        .writer_fence();
    if previous != expected_previous {
        return Err(
            "writer fence changed during startup validation; stop competing writers and restart"
                .into(),
        );
    }
    let generation: WriterFenceGeneration =
        previous.checked_next().ok_or("writer fence exhausted")?;
    let now: u64 = SystemClock.now_unix_millis()?;
    let deadline: u64 = now
        .checked_add(
            timeout_seconds
                .checked_mul(1000)
                .ok_or("timeout overflow")?,
        )
        .ok_or("deadline overflow")?;
    advance_writer_fence(&mut connection, namespace, previous, generation)?;
    drop(connection);
    let mut correlation: [u8; 16] = [0; 16];
    correlation[..8].copy_from_slice(&generation.get().to_be_bytes());
    correlation[8..].copy_from_slice(&now.to_be_bytes());
    let context: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new(correlation).ok_or("invalid correlation id")?,
    );
    Ok((context, generation))
}

const VALUE_FLAGS: &[&str] = &[
    "--tls-root-der",
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--signing-key-file",
    "--listen",
    "--created-checkpoint",
    "--timeout-seconds",
    "--max-connections",
    "--max-concurrent",
];
const BOOL_FLAGS: &[&str] = &[
    "--confirm-offline-fence-advance",
    // DR-0153 opt-in only. Off by default: this binary otherwise serves
    // exactly its existing certified FastVote surface, unchanged.
    "--enable-ordered-economics",
];

fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(tokens, VALUE_FLAGS, BOOL_FLAGS)?;
    let confirmed: bool = flags.bool("--confirm-offline-fence-advance");
    let ordered_economics_enabled: bool = flags.bool("--enable-ordered-economics");
    let ca_der: PathBuf = PathBuf::from(flags.one("--tls-root-der")?);
    let chain: ChainId = parse_chain(flags.one("--chain-id")?)?;
    let validator: ValidatorId = parse_validator(&flags.one("--validator-id")?)?;
    let domain: AtomicityDomainId = parse_domain(&flags.one("--domain")?)?;
    let protocol_version: ProtocolVersion =
        parse_protocol_version(&flags.one("--protocol-version")?)?;
    let epoch: Epoch = parse_epoch(&flags.one("--epoch")?)?;
    let schedule: Vec<HashSuiteSchedule> = parse_schedule(&flags.many("--suite"))?;
    let manifest_path: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
    let expected_digest: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let signing_key_path: PathBuf = PathBuf::from(flags.one("--signing-key-file")?);
    let listen: String = flags.one("--listen")?;
    let created_checkpoint: u64 = parse_u64_bounded(
        &flags.one("--created-checkpoint")?,
        "--created-checkpoint",
        0,
        u64::MAX,
    )?;
    let timeout_seconds: u64 =
        parse_u64_bounded(&flags.one("--timeout-seconds")?, "--timeout-seconds", 1, 30)?;
    let max_connections: u32 = u32::try_from(parse_u64_bounded(
        &flags.one("--max-connections")?,
        "--max-connections",
        1,
        64,
    )?)
    .unwrap_or(1);
    let max_concurrent: usize = usize::try_from(parse_u64_bounded(
        &flags.one("--max-concurrent")?,
        "--max-concurrent",
        1,
        256,
    )?)
    .unwrap_or(1);
    flags.finish()?;
    if !confirmed {
        return Err(
            "requires --confirm-offline-fence-advance: stop every other writer against this namespace first; this host claims the writer fence exactly once at startup and holds it for its entire serving lifetime"
                .into(),
        );
    }

    let listen_addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| "invalid --listen socket address")?;
    if !listen_addr.ip().is_loopback() {
        return Err(
            "--listen must be a loopback address; this binary never terminates TLS itself, so non-loopback access requires an externally configured TLS-terminating proxy"
                .into(),
        );
    }

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

    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> = connect_pool(
        &ca_der,
        NonZeroU32::new(max_connections).ok_or("zero pool size")?,
    )?;
    // Inspect and validate under the installed writer generation before any
    // disruptive fence advance. A concurrent change fails closed at claim.
    let previous: WriterFenceGeneration = {
        let mut connection = pool
            .get()
            .map_err(|_| "PostgreSQL TLS connection unavailable")?;
        inspect_namespace(&mut *connection, &namespace)?
            .ok_or("PostgreSQL namespace not bootstrapped")?
            .writer_fence()
    };
    let startup_deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(
            timeout_seconds
                .checked_mul(1000)
                .ok_or("timeout overflow")?,
        )
        .ok_or("deadline overflow")?;
    let context: DurableOperationContext = DurableOperationContext::new(
        previous,
        StorageDeadline::new(startup_deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new([0x53; 16]).ok_or("invalid correlation id")?,
    );
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    let blob_store: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone())?;

    // Live admission is separate from permanent origin and from the signed
    // committee pin. Refuse a closed outgoing namespace before claiming a
    // new writer generation; the actual backend also fences every write.
    node_core::require_ordinary_namespace(&store, &context, domain)?;
    let fee_policy: PaidFeePolicy =
        require_committed_genesis_fee_policy(&store, &context, domain, &expected_context, &root)?;

    let validator_set_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&expected_context)?;
    let observed = store
        .get_versioned_durable(&context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;
    require_live_fastvote_pin(
        &store,
        &context,
        domain,
        &expected_context,
        &record,
        &resolver,
    )?;

    let signing_key: SigningKey =
        load_signing_key_file(&signing_key_path).map_err(|error| error.to_string())?;
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let derived_public_key: [u8; 32] = verification_key.into();
    require_registered_signer(&record, validator, &derived_public_key)?;
    if ordered_economics_enabled {
        require_committed_record_matches_root_committee(&record, &root.manifest().validator_set)?;
    }
    let (serving_context, generation) =
        claim_fresh_writer_fence_once(&pool, &namespace, timeout_seconds, previous)?;
    // Recheck under the generation this host will actually serve with.
    node_core::require_ordinary_namespace(&store, &serving_context, domain)?;
    require_live_fastvote_pin(
        &store,
        &serving_context,
        domain,
        &expected_context,
        &record,
        &resolver,
    )?;

    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());
    let ordered_leg_policy: LocalExecutionPolicy = base_policy.clone();
    let execution: PaidExecutionComposition =
        PaidExecutionComposition::new(base_policy, fee_policy);
    let file_signer: FileEd25519Signer = FileEd25519Signer::new(validator, signing_key);
    let ordered_signer: FileEd25519Signer = file_signer.clone();
    let signer: Arc<dyn ConsensusSigner + Send + Sync> = Arc::new(file_signer);
    let fastvote: FastVoteComposition =
        FastVoteComposition::new(execution, signer, created_checkpoint);

    // Advertised over the read-only query route only; never authority. See
    // host_protocol_context for why this must come from the resolver this
    // host actually trusts, not a genesis default. Matches the ordinary
    // CLI fixed expected transaction-auth profile
    // (apps/cli/src/commands/standard_asset.rs::parse_expected_context) and
    // devnet own genesis convention (apps/devnet/src/genesis.rs).
    let protocol_config: ProtocolConfig = host_query_protocol_config(&resolver, domain, epoch)
        .map_err(|error| format!("fastvote host query protocol configuration: {error}"))?;
    let node_config: NodeConfig = NodeConfig::new(
        chain.clone(),
        protocol_version,
        epoch,
        b"fastvote-host-pg/node-state".to_vec(),
    )?;
    let lease_millis: u64 = timeout_seconds
        .checked_mul(1000)
        .and_then(|value| value.checked_mul(4))
        .ok_or("timeout overflow")?;
    let authority: StructuredDurableRequestAuthority = StructuredDurableRequestAuthority::new(
        generation,
        timeout_seconds.saturating_mul(1000),
        lease_millis,
    )?;

    let store_arc = Arc::new(store);
    let blob_arc = Arc::new(blob_store);
    let clock_arc = Arc::new(SystemClock);
    let identities_arc = Arc::new(SequentialIdentitySource::new(generation));
    // One shared blocking-admission budget for both the certified FastVote
    // router and the opt-in ordered-economics router: their synchronous
    // store/core work draws from the same bounded concurrency pool, never
    // two independent, uncoordinated limits.
    let blocking_executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
        NativeBlockingPolicy::new(NonZeroUsize::new(max_concurrent).ok_or("zero concurrency")?),
    );
    let components = StructuredDurableNativeComponents::new(
        store_arc.clone(),
        blob_arc.clone(),
        Arc::new(NoOutboundTransport),
        clock_arc.clone(),
        identities_arc.clone(),
    );
    // DR-0153 opt-in composition: never mounted unless
    // `--enable-ordered-economics` is explicitly set. Reuses this same
    // process's already-verified genesis validator set, domain, resolver,
    // store, blob store, clock, and identity source unchanged -- no second
    // trust decision, no daemon-correctness guarantee beyond what
    // `certified_fastvote_router` itself already provides.
    let ordered_economics_router = if ordered_economics_enabled {
        let ordered_policy = OrderedEconomicsPolicy::from_genesis_root(&root, domain)
            .map_err(|error| format!("failed to compose ordered economics policy: {error}"))?;
        let genesis_engine = execution::LocalWasmExecutionEngine::new();
        let ordered_env = node_core::ordered_economics::OrderedEconomicsEnvironment {
            policy: &ordered_policy,
            history: &[],
            leg_policy: &ordered_leg_policy,
            engine: &genesis_engine,
            blobs: blob_arc.as_ref(),
            seal: None,
        };
        // The production installer verifies retained state without rewriting
        // it, and distinguishes never-written absence from a tombstone.
        // Corruption/fencing/unavailability must abort startup, never reset.
        node_core::ordered_economics::install_ordered_genesis(
            store_arc.as_ref(),
            &serving_context,
            &ordered_env,
            SystemClock.now_unix_millis()?,
        )
        .map_err(|error| format!("failed to install ordered economics genesis: {error}"))?;
        let ordered_state = OrderedEconomicsState {
            store: store_arc.clone(),
            clock: clock_arc.clone(),
            identities: identities_arc.clone(),
            domain,
            writer_fence: generation,
            operation_timeout: Duration::from_secs(timeout_seconds),
            policy: ordered_policy,
            history: Vec::new(),
            leg_policy: ordered_leg_policy,
            engine: Arc::new(execution::LocalWasmExecutionEngine::new()),
            blobs: blob_arc.clone(),
            seal: None,
            signer: ordered_signer,
            blocking_executor: blocking_executor.clone(),
            cancellation: None,
        };
        Some(certified_ordered_economics_router(ordered_state))
    } else {
        None
    };
    let router = certified_fastvote_router_with_executor(
        components,
        fastvote,
        protocol_config,
        authority,
        node_config,
        resolver,
        Vec::new(),
        blocking_executor,
    )
    .map_err(|error| format!("failed to compose certified FastVote router: {error}"))?;
    let router = match ordered_economics_router {
        Some(ordered) => router.merge(ordered),
        None => router,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        // Printed only after a successful bind, using the actual bound
        // address (never the caller's possibly-unresolved `:0` port
        // request), and explicitly flushed: a caller driving this process
        // as a subprocess (for example a test harness) must be able to
        // parse the real listening port from stdout before dialing it.
        let bound_addr = listener.local_addr()?;
        println!(
            "complete=true mode=serving chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_generation={} listen={bound_addr} manifest_digest={}",
            protocol_version.get(),
            epoch.get(),
            generation.get(),
            to_hex(&expected_digest),
        );
        use std::io::Write;
        std::io::stdout().flush()?;
        native_http::serve(listener, router, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })?;
    Ok(())
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use node_core::fast_path::records::FastPathValidatorEntry;
    use protocol_types::SignatureSchemeId;

    fn signer_entry(seed: u8) -> FastPathValidatorEntry {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let verification_key: VerificationKey = VerificationKey::from(&signing_key);
        let public_key: [u8; 32] = verification_key.into();
        FastPathValidatorEntry {
            id: ValidatorId::new(public_key),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        }
    }

    fn dummy_context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("fastvote-host-pg-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap()
    }

    #[test]
    fn committed_record_matching_the_root_committee_is_accepted() {
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![signer_entry(1), signer_entry(2)],
        };
        let root_committee: FastPathValidatorSetRecord = record.clone();
        assert!(require_committed_record_matches_root_committee(&record, &root_committee).is_ok());
    }

    #[test]
    fn committed_record_with_a_foreign_committee_is_rejected() {
        let root_committee: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![signer_entry(1), signer_entry(2)],
        };
        // Internally coherent -- same context, same validator count -- but a
        // genuinely different committee, not a tampered/truncated byte
        // string, proving the check is a real committee comparison.
        let foreign_record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![signer_entry(1), signer_entry(99)],
        };
        assert!(
            require_committed_record_matches_root_committee(&foreign_record, &root_committee)
                .is_err()
        );
    }

    #[test]
    fn committed_record_with_a_foreign_context_is_rejected_even_with_the_same_committee() {
        let root_committee: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![signer_entry(1)],
        };
        // Same signed validators, different chain/protocol/epoch: a record
        // that a live-epoch-digest check against the wrong namespace could
        // still consider internally coherent. This is not the same as a
        // bare `assert_ne!` between two vectors -- it drives the actual
        // production check end to end.
        let other_context: PublicationContext = PublicationContext::new(
            ChainId::new("fastvote-host-pg-test-other").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap();
        let foreign_record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: other_context,
            validators: root_committee.validators.clone(),
        };
        assert!(
            require_committed_record_matches_root_committee(&foreign_record, &root_committee)
                .is_err()
        );
    }
}
