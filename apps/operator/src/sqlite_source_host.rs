//! Loopback-only original-genesis SQLite host with the ordered Seal
//! composition connected: certified paid/ordered/FastVote dispatch over one
//! already bootstrapped local SQLite namespace. Never bootstraps, resets or
//! re-genesises a namespace; only reopens an already ordinary, unsealed
//! file and claims its writer fence exactly once for this process's serving
//! lifetime. Unlike fastvote_host_pg (seal None), this host always wires
//! OrderedSealHostComposition, so it additionally requires a causal-
//! admission genesis before claiming that fence.
#![forbid(unsafe_code)]

use crate::common::{
    FlagSet, load_signing_key_file, parse_hash_suite, parse_hex_32, require_live_fastvote_pin,
};
use crate::host_protocol_context::host_query_protocol_config;
use crate::host_runtime::{
    FileEd25519Signer, NoOutboundTransport, SequentialIdentitySource, fast_path_committee_matches,
    require_committed_genesis_fee_policy, require_registered_signer,
};
use consensus::ConsensusSigner;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::PaidFeePolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use native_http::ordered_economics::{
    OrderedEconomicsState, OrderedSealHostComposition, certified_ordered_economics_router,
};
use native_http::{
    FastVoteComposition, NativeBlockingExecutor, NativeBlockingPolicy, PaidExecutionComposition,
    StructuredDurableNativeComponents, StructuredDurableRequestAuthority,
    certified_fastvote_router_with_executor,
};
use node_core::NodeConfig;
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::decode_fastpath_validator_set_record;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::OrderedEconomicsPolicy;
use protocol_config::ProtocolConfig;
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    SystemClock, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    error::Error, ffi::OsString, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration,
};
use sunrise_edge_client::load_verified_genesis_root;

fn require_committed_record_matches_root_committee(
    record: &FastPathValidatorSetRecord,
    root_committee: &FastPathValidatorSetRecord,
) -> Result<(), String> {
    if !fast_path_committee_matches(record, root_committee) {
        return Err(
            "committed fast-path validator set does not match the trusted verified root's original signed committee/context; refusing to bind the ordered Seal composition"
            .into(),
        );
    }
    Ok(())
}

const VALUE_FLAGS: &[&str] = &[
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--signing-key-file",
    "--state-db",
    "--blob-db",
    "--listen",
    "--created-checkpoint",
    "--timeout-seconds",
    "--max-concurrent",
];
const BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];
const MAX_HOST_TIMEOUT_SECONDS: u64 = native_http::MAX_INDEXED_OUTBOX_OPERATION_MILLIS / 1000;

/// Parses closed argv (no fallbacks), fails closed on any refusal below
/// before advancing the writer fence, then serves the certified paid/
/// ordered/FastVote dispatcher with the ordered Seal composition bound.
/// All fee/validator-set/signer/committee pins are decided once, strictly
/// after the single fence claim, under the context this host actually
/// serves with; the Tokio HTTP loop below is transport only.
pub fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(tokens, VALUE_FLAGS, BOOL_FLAGS)?;
    let confirmed: bool = flags.bool("--confirm-offline-fence-advance");
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
    let manifest_path: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
    let expected_digest: [u8; 32] = parse_hex_32(
        &flags.one("--expected-genesis-digest")?,
        "--expected-genesis-digest",
    )?;
    let signing_key_path: PathBuf = PathBuf::from(flags.one("--signing-key-file")?);
    let state_db: PathBuf = PathBuf::from(flags.one("--state-db")?);
    let blob_db: PathBuf = PathBuf::from(flags.one("--blob-db")?);
    let listen: String = flags.one("--listen")?;
    let created_checkpoint: u64 = flags
        .one("--created-checkpoint")?
        .parse()
        .map_err(|_| "invalid --created-checkpoint")?;
    let timeout_seconds: u64 = flags
        .one("--timeout-seconds")?
        .parse()
        .map_err(|_| "invalid --timeout-seconds")?;
    if !(1..=MAX_HOST_TIMEOUT_SECONDS).contains(&timeout_seconds) {
        return Err(format!("--timeout-seconds must be 1..={MAX_HOST_TIMEOUT_SECONDS}").into());
    }
    let max_concurrent: usize = flags
        .one("--max-concurrent")?
        .parse()
        .map_err(|_| "invalid --max-concurrent")?;
    if !(1..=256).contains(&max_concurrent) {
        return Err("--max-concurrent must be 1..=256".into());
    }
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
        return Err("--listen must be a loopback address".into());
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
    if !root.admission_profile().is_causal() {
        return Err(
            "sqlite-source-host requires a causal-admission genesis to bind the ordered Seal composition"
                .into(),
        );
    }

    let namespace: SqliteNamespace = SqliteNamespace::new(chain.clone(), validator, domain);
    let store: SqliteDurableStore = SqliteDurableStore::open_existing(&state_db, namespace)?;
    let previous: WriterFenceGeneration = store.writer_fence()?;
    let timeout_millis: u64 = timeout_seconds
        .checked_mul(1000)
        .ok_or("timeout overflow")?;
    let startup_deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(timeout_millis)
        .ok_or("deadline overflow")?;
    let startup_context: DurableOperationContext = DurableOperationContext::new(
        previous,
        StorageDeadline::new(startup_deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new([0x53; 16]).ok_or("invalid correlation id")?,
    );
    // Only a go/no-go gate before claiming the fence; every pin this host
    // actually serves with is decided below, strictly after the claim,
    // under serving_context, so a writer that changed them between this
    // inspection and the claim cannot leave a stale decision in effect.
    node_core::require_ordinary_namespace(&store, &startup_context, domain)?;

    let generation: WriterFenceGeneration =
        previous.checked_next().ok_or("writer fence exhausted")?;
    store.advance_writer_fence(previous, generation)?;
    let lease_millis: u64 = timeout_millis.checked_mul(4).ok_or("timeout overflow")?;
    let serving_deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(timeout_millis)
        .ok_or("deadline overflow")?;
    let mut serving_correlation: [u8; 16] = [0; 16];
    serving_correlation[..8].copy_from_slice(&generation.get().to_be_bytes());
    let serving_context: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(serving_deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new(serving_correlation).ok_or("invalid correlation id")?,
    );
    node_core::require_ordinary_namespace(&store, &serving_context, domain)?;
    let fee_policy: PaidFeePolicy = require_committed_genesis_fee_policy(
        &store,
        &serving_context,
        domain,
        &expected_context,
        &root,
    )?;

    let validator_set_key: Vec<u8> =
        node_core::local_instance_state::fastpath_validator_set_key(&expected_context)?;
    let observed: VersionedStateValue = store
        .get_versioned_durable(&serving_context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;
    require_live_fastvote_pin(
        &store,
        &serving_context,
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
    require_committed_record_matches_root_committee(&record, &root.manifest().validator_set)?;

    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&blob_db)?;

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

    // Advertised over the read-only query route only; never authority.
    // See host_protocol_context for why this must come from the resolver
    // this host actually trusts, not a genesis default.
    let protocol_config: ProtocolConfig = host_query_protocol_config(&resolver, domain, epoch)
        .map_err(|error| format!("sqlite source host query protocol configuration: {error}"))?;
    let node_config: NodeConfig = NodeConfig::new(
        chain.clone(),
        protocol_version,
        epoch,
        b"sqlite-source-host/node-state".to_vec(),
    )?;
    let authority: StructuredDurableRequestAuthority =
        StructuredDurableRequestAuthority::new(generation, timeout_millis, lease_millis)?;

    let store_arc: Arc<SqliteDurableStore> = Arc::new(store);
    let blob_arc: Arc<SqliteBlobStore> = Arc::new(blobs);
    let clock_arc: Arc<SystemClock> = Arc::new(SystemClock);
    let identities_arc: Arc<SequentialIdentitySource> =
        Arc::new(SequentialIdentitySource::new(generation));
    let blocking_executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
        NativeBlockingPolicy::new(NonZeroUsize::new(max_concurrent).ok_or("zero concurrency")?),
    );
    let components: StructuredDurableNativeComponents<
        SqliteDurableStore,
        SqliteBlobStore,
        NoOutboundTransport,
        SystemClock,
        SequentialIdentitySource,
    > = StructuredDurableNativeComponents::new(
        store_arc.clone(),
        blob_arc.clone(),
        Arc::new(NoOutboundTransport),
        clock_arc.clone(),
        identities_arc.clone(),
    );

    let ordered_policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, domain)
            .map_err(|error| format!("failed to compose ordered economics policy: {error}"))?;
    let genesis_engine: execution::LocalWasmExecutionEngine =
        execution::LocalWasmExecutionEngine::new();
    let ordered_env: node_core::ordered_economics::OrderedEconomicsEnvironment<'_> =
        node_core::ordered_economics::OrderedEconomicsEnvironment {
            policy: &ordered_policy,
            history: &[],
            leg_policy: &ordered_leg_policy,
            engine: &genesis_engine,
            blobs: blob_arc.as_ref(),
            seal: None,
        };
    // This serving composition must never initialize a missing consensus
    // row. Bootstrap is a separate operation; status reads re-verify the
    // installed state and refuse missing, deleted or malformed rows.
    node_core::ordered_economics::query_status(store_arc.as_ref(), &serving_context, &ordered_env)
        .map_err(|error| format!("existing ordered economics state is not valid: {error}"))?;

    let seal = OrderedSealHostComposition {
        genesis_root: root.clone(),
        paid_base_policy: ordered_leg_policy.clone(),
        paid_engine: Arc::new(execution::LocalWasmExecutionEngine::new()),
        blobs: blob_arc.clone(),
    };
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
        seal: Some(seal),
        signer: ordered_signer,
        blocking_executor: blocking_executor.clone(),
        cancellation: None,
    };
    let ordered_router = certified_ordered_economics_router(ordered_state);

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
    .map_err(|error| format!("failed to compose certified FastVote router: {error}"))?
    .merge(ordered_router);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let bound_addr = listener.local_addr()?;
        println!(
            "complete=true mode=serving chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_generation={} listen={bound_addr}",
            protocol_version.get(),
            epoch.get(),
            generation.get(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use node_core::fast_path::records::FastPathValidatorEntry;
    use protocol_types::SignatureSchemeId;

    fn args_with(listen: &str, confirmed: bool) -> Vec<OsString> {
        let validator_id = "00".repeat(32);
        let domain = format!("{}01", "00".repeat(31));
        let digest = "00".repeat(32);
        let mut values: Vec<OsString> = [
            "--chain-id",
            "test-chain",
            "--validator-id",
            validator_id.as_str(),
            "--domain",
            domain.as_str(),
            "--protocol-version",
            "1",
            "--epoch",
            "0",
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--genesis-manifest",
            "/nonexistent/genesis.manifest",
            "--expected-genesis-digest",
            digest.as_str(),
            "--signing-key-file",
            "/nonexistent/key",
            "--state-db",
            "/nonexistent/state.sqlite",
            "--blob-db",
            "/nonexistent/blob.sqlite",
            "--listen",
            listen,
            "--created-checkpoint",
            "0",
            "--timeout-seconds",
            "30",
            "--max-concurrent",
            "4",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if confirmed {
            values.push(OsString::from("--confirm-offline-fence-advance"));
        }
        values
    }

    #[test]
    fn unknown_flag_is_rejected_before_any_io() {
        let error = run(vec![OsString::from("--bogus")]).unwrap_err();
        assert!(error.to_string().contains("unknown flag"));
    }

    #[test]
    fn missing_confirm_flag_refuses_before_any_file_access() {
        let error = run(args_with("127.0.0.1:0", false)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--confirm-offline-fence-advance")
        );
    }

    #[test]
    fn non_loopback_listen_is_refused_before_genesis_load() {
        let error = run(args_with("0.0.0.0:0", true)).unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }

    #[test]
    fn timeout_outside_native_authority_bounds_refuses_before_any_io() {
        for seconds in [0, MAX_HOST_TIMEOUT_SECONDS + 1, u64::MAX] {
            let mut args: Vec<OsString> = args_with("127.0.0.1:0", true);
            let index: usize = args
                .iter()
                .position(|value: &OsString| value == "--timeout-seconds")
                .unwrap();
            args[index + 1] = seconds.to_string().into();
            let diagnostic: String = run(args).unwrap_err().to_string();
            assert!(
                diagnostic.contains("--timeout-seconds must be"),
                "invalid timeout must refuse before nonexistent genesis/store/key IO: {diagnostic}"
            );
        }
    }

    fn test_context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("sqlite-source-host-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap()
    }

    fn entry(seed: u8) -> FastPathValidatorEntry {
        FastPathValidatorEntry {
            id: ValidatorId::new([seed; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![seed; 32],
        }
    }

    #[test]
    fn registered_signer_rejects_mismatched_public_key() {
        let record = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(7)],
        };
        let mismatched_key = [1u8; 32];
        assert!(
            require_registered_signer(&record, ValidatorId::new([7; 32]), &mismatched_key).is_err()
        );
    }

    #[test]
    fn registered_signer_rejects_an_unknown_validator() {
        let record = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(7)],
        };
        let key = [7u8; 32];
        assert!(require_registered_signer(&record, ValidatorId::new([9; 32]), &key).is_err());
    }

    #[test]
    fn committed_record_matching_the_root_committee_is_accepted() {
        let record = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(2)],
        };
        let root_committee = record.clone();
        assert!(require_committed_record_matches_root_committee(&record, &root_committee).is_ok());
    }

    #[test]
    fn committed_record_with_a_foreign_committee_is_rejected() {
        let root_committee = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(2)],
        };
        let foreign_record = FastPathValidatorSetRecord {
            context: test_context(),
            validators: vec![entry(1), entry(99)],
        };
        assert!(
            require_committed_record_matches_root_committee(&foreign_record, &root_committee)
                .is_err()
        );
    }
}
