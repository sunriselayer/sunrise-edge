//! Post-Seal material-only history process. Uses the existing historical
//! SQLite open and writer fence without advancing it. No protocol signing key
//! is read; optional TLS loads only its independent transport key.

use super::*;
use native_http::successor::{
    SuccessorHistoricalComposition, SuccessorHistoricalPolicySource, successor_history_router,
};
use node_core::ordered_economics::OrderedEconomicsPolicy;
use runtime::{DurableDomainStateStore, NamespaceLifecycle};
use runtime_sqlite::SqliteDurableStore;

struct HistoricalPolicy {
    pins: BusinessPins,
    links: Vec<SuccessorLinkPins>,
    budget: SuccessorChainBudget,
    artifacts: Mutex<SuccessorChainArtifactFiles>,
    epoch: Epoch,
    validator: ValidatorId,
}

impl SuccessorHistoricalPolicySource<SqliteDurableStore> for HistoricalPolicy {
    fn ordered_policy(
        &self,
        store: &SqliteDurableStore,
        context: &DurableOperationContext,
    ) -> Result<OrderedEconomicsPolicy, ServingAuthorityError> {
        let mut artifacts = self
            .artifacts
            .lock()
            .map_err(|_| ServingAuthorityError::Refused("successor history archives poisoned"))?;
        let plan_operation: DurableOperationContext = private_operation().map_err(|_| {
            ServingAuthorityError::Refused("history reconstruction context unavailable")
        })?;
        let authority: VerifiedSuccessorAuthority = verify_successor_chain_authority(
            self.pins.plan(plan_operation),
            &self.links,
            self.budget,
            &mut *artifacts,
        )?;
        let policy: OrderedEconomicsPolicy = authority.ordered_policy(self.pins.root())?;
        if policy.context().epoch() != self.epoch
            || policy.domain() != self.pins.domain
            || store.namespace().chain_id() != policy.context().chain_id()
            || store.namespace().domain() != self.pins.domain
            || store.namespace().validator_id() != self.validator
            || !authority
                .validator_set()
                .validators()
                .iter()
                .any(|member| member.id == self.validator)
        {
            return Err(ServingAuthorityError::Refused(
                "historical current namespace pins differ from verified chain",
            ));
        }
        match store.get_namespace_lifecycle(context, self.pins.domain)? {
            NamespaceLifecycle::CompleteInactive { binding, progress }
                if binding == *authority.import_binding()
                    && progress.next_ordinal == binding.row_count
                    && binding.context.epoch.get().checked_add(1) == Some(self.epoch.get()) => {}
            _ => {
                return Err(ServingAuthorityError::Refused(
                    "historical namespace is not the exact completed import",
                ));
            }
        }
        match store.get_outgoing_barrier(context, self.pins.domain)? {
            runtime::OutgoingBarrier::Sealed(sealed) if sealed.outgoing_epoch == self.epoch => {}
            _ => {
                return Err(ServingAuthorityError::Refused(
                    "historical namespace has not sealed its current epoch",
                ));
            }
        }
        Ok(policy)
    }
}

pub(super) fn run(values: Vec<OsString>) -> Result<(), Box<dyn Error>> {
    let mut accepted: Vec<&'static str> = FLAGS
        .iter()
        .copied()
        .filter(|flag| !["--signer-key-file", "--created-checkpoint"].contains(flag))
        .collect();
    accepted.push("--historical-epoch");
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let listen: SocketAddr = require_loopback_listen(&flags.one("--listen")?)?;
    let chain: SuccessorChainInputs = SuccessorChainInputs::parse_required(&mut flags)?;
    let inputs: BusinessPinInputs =
        BusinessPinInputs::parse_with_history(&mut flags, chain.first_history().to_path_buf())?;
    let state_path: PathBuf = flags.one("--target-state-db")?.into();
    let blob_path: PathBuf = flags.one("--target-blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let epoch: Epoch = Epoch::new(bounded(&flags.one("--historical-epoch")?, 0, u64::MAX)?);
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "30".into()),
        1,
        3600,
    )?;
    let maximum: usize = usize::try_from(bounded(
        &flags
            .optional_one("--max-concurrent")?
            .unwrap_or_else(|| "16".into()),
        1,
        256,
    )?)?;
    let tls_inputs: NativeTlsInputs = NativeTlsInputs::parse(&mut flags)?;
    flags.finish()?;
    if state_path == blob_path {
        return Err("target state and blob paths must be distinct".into());
    }
    let tls: Option<tokio_rustls::TlsAcceptor> = tls_inputs.load()?;
    let artifacts: SuccessorChainArtifactFiles = chain.open()?;
    for path in [&state_path, &blob_path] {
        artifacts.require_output_outside(path)?;
    }
    let pins: BusinessPins = inputs.load()?;
    let links: Vec<SuccessorLinkPins> = artifacts.pins();
    let domain: AtomicityDomainId = pins.domain;
    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), validator, domain);
    let store: Arc<SqliteDurableStore> =
        Arc::new(SqliteDurableStore::open_historical(&state_path, namespace)?);
    let generation: WriterFenceGeneration = store.writer_fence()?;
    let policy_source: Arc<HistoricalPolicy> = Arc::new(HistoricalPolicy {
        pins,
        links,
        budget: chain.budget,
        artifacts: Mutex::new(artifacts),
        epoch,
        validator,
    });
    let startup: DurableOperationContext = operation(generation, timeout, [0x5F; 16])?;
    // A full startup check is not memoized. Native rechecks every link,
    // lifecycle/binding, member pins and terminal Seal per request.
    policy_source.ordered_policy(store.as_ref(), &startup)?;
    let blobs: Arc<SqliteBlobStore> = Arc::new(SqliteBlobStore::open_existing(&blob_path)?);
    let composition: SuccessorHistoricalComposition<SqliteDurableStore> =
        SuccessorHistoricalComposition {
            store,
            policy_source,
            blobs,
            clock: Arc::new(SystemClock),
            identities: Arc::new(GenerationIdentities {
                generation,
                sequence: AtomicU64::new(1),
            }),
            writer_fence: generation,
            operation_timeout: Duration::from_secs(timeout),
            domain,
            blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
                NonZeroUsize::new(maximum).ok_or("zero --max-concurrent")?,
            )),
        };
    let blocking_executor: NativeBlockingExecutor = composition.blocking_executor.clone();
    let router = successor_history_router(composition)?;
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut stop = crate::native_operations::StopOwner::install()?;
        let listener: tokio::net::TcpListener = bind_successor_loopback(listen).await?;
        let bound: SocketAddr = listener.local_addr()?;
        if !stop.stop_before_readiness() {
        println!("complete=true mode=successor-history-material-only domain={domain} epoch={} validator_id={validator} writer_generation={} listen={bound}", epoch.get(), generation.get());
        std::io::Write::flush(&mut std::io::stdout())?;
        }
        crate::native_operations::serve(blocking_executor, stop, move |shutdown, observations| async move {
        match tls {
            None => native_http::serve_with_stream_upgrade_observed(
                listener, router, native_http::NativeHttpServePolicy::default(),
                |stream: tokio::net::TcpStream| async move { Ok::<_, std::io::Error>(stream) },
                shutdown, observations).await,
            Some(acceptor) => native_http::serve_with_stream_upgrade_observed(
                listener,
                router,
                native_http::NativeHttpServePolicy::default(),
                move |stream: tokio::net::TcpStream| native_tls::accept(acceptor.clone(), stream),
                shutdown,
                observations,
            )
            .await,
        }
        }).await
    })?;
    Ok(())
}
