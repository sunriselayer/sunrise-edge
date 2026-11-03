//! Optional distinct-UID successor custody profile. Both roles load their
//! own configuration; the frontend never opens a key or target store.
use super::*;
use crate::local_custody_transport as local;
use native_http::successor_custody::{self, Frontend, Identity};
use std::{
    io::{self, Write},
    time::Duration,
};
use tokio::time::{Instant, sleep_until};

fn refused() -> io::Error {
    io::Error::other("protected successor host refused")
}

pub(super) struct WorkerParams {
    socket: PathBuf,
    frontend_uid: u32,
    max_connections: u64,
    max_requests: u64,
    total: Duration,
}
impl WorkerParams {
    pub(super) fn parse(flags: &mut FlagSet) -> Result<Self, Box<dyn Error>> {
        let socket: PathBuf = flags.one("--socket")?.into();
        local::absolute(&socket, refused)?;
        if socket.as_os_str().len() > 100 {
            return Err(refused().into());
        }
        local::owned(socket.parent().ok_or_else(refused)?, 0o750, true, refused)?;
        if std::fs::symlink_metadata(&socket).is_ok() {
            return Err(refused().into());
        }
        let frontend_uid: u32 = flags.one("--frontend-uid")?.parse()?;
        if frontend_uid == local::own_uid(refused)? {
            return Err(refused().into());
        }
        let max_connections: u64 = bounded(&flags.one("--max-connections")?, 2, 8192)?;
        let max_requests: u64 = bounded(&flags.one("--max-requests")?, 1, 4096)?;
        if max_connections <= max_requests {
            return Err(refused().into());
        }
        let total: Duration =
            Duration::from_secs(bounded(&flags.one("--total-deadline-seconds")?, 1, 3600)?);
        Ok(Self {
            socket,
            frontend_uid,
            max_connections,
            max_requests,
            total,
        })
    }
}

pub(super) fn serve_worker(
    host: SuccessorHostInputs,
    params: WorkerParams,
) -> Result<(), Box<dyn Error>> {
    let timeout: Duration = Duration::from_secs(host.timeout);
    let prepared: PreparedHost = prepare(host)?;
    let identity: Identity = Identity::new(
        prepared.validator,
        prepared.domain,
        parse_hex_32(&prepared.genesis_digest, "genesis-digest")?,
        prepared.subject_digest,
    );
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut stop = crate::native_operations::StopOwner::install(prepared.local_observations)?;
        let (owner, listener) = local::SocketOwner::bind(&params.socket, refused)?;
        let end: Instant = Instant::now().checked_add(params.total).ok_or_else(refused)?;
        if !stop.stop_before_readiness() {
            println!("complete=true mode=successor-protected-worker transport=unix epoch={} validator_id={} writer_generation={}", prepared.epoch.get(), prepared.validator, prepared.generation.get());
            io::stdout().flush()?;
            stop.readiness_announced();
        }
        let observations = prepared.executor.observations();
        let closing = prepared.executor.clone();
        let shutdown = async move {
            tokio::select! {biased; _=stop.wait(observations)=>{}, ()=sleep_until(end)=>{}}
            closing.close();
        };
        let result = successor_custody::serve_worker(listener, prepared.router, prepared.executor.clone(), identity, params.frontend_uid, params.max_connections, params.max_requests, timeout, end, shutdown).await;
        prepared.executor.close();
        prepared.executor.wait_drained().await;
        let removed = owner.close();
        result?;
        removed
    })?;
    Ok(())
}

const FRONTEND_FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--cut-dir",
    "--manifest-history-dir",
    "--certificate-dir",
    "--successor-max-links",
    "--validator-id",
    "--socket",
    "--worker-uid",
    "--listen",
    "--timeout-seconds",
    "--max-concurrent",
    "--max-requests",
    "--total-deadline-seconds",
    native_tls::CERT_FLAG,
    native_tls::KEY_FLAG,
];

pub(super) fn run_frontend(values: Vec<OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(values, FRONTEND_FLAGS, &[])?;
    let listen: SocketAddr = require_loopback_listen(&flags.one("--listen")?)?;
    let chain: SuccessorChainInputs = SuccessorChainInputs::parse_required(&mut flags)?;
    let inputs: BusinessPinInputs =
        BusinessPinInputs::parse_with_history(&mut flags, chain.first_history().to_path_buf())?;
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let socket: PathBuf = flags.one("--socket")?.into();
    local::absolute(&socket, refused)?;
    if socket.as_os_str().len() > 100 {
        return Err(refused().into());
    }
    let worker_uid: u32 = flags.one("--worker-uid")?.parse()?;
    if worker_uid == local::own_uid(refused)? {
        return Err(refused().into());
    }
    let timeout: Duration = Duration::from_secs(bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "30".into()),
        1,
        3600,
    )?);
    let concurrent: usize = usize::try_from(bounded(
        &flags
            .optional_one("--max-concurrent")?
            .unwrap_or_else(|| "16".into()),
        1,
        256,
    )?)?;
    let max_requests: u64 = bounded(&flags.one("--max-requests")?, 1, 4096)?;
    let total: Duration =
        Duration::from_secs(bounded(&flags.one("--total-deadline-seconds")?, 1, 3600)?);
    let tls_inputs: NativeTlsInputs = NativeTlsInputs::parse(&mut flags)?;
    flags.finish()?;
    let tls: Option<tokio_rustls::TlsAcceptor> = tls_inputs.load()?;
    // Independent frontend-owned read-only artifact verification. The worker
    // cannot choose a committee, epoch or subject through a reply.
    let mut artifacts: SuccessorChainArtifactFiles = chain.open()?;
    let pins: BusinessPins = inputs.load()?;
    let links: Vec<SuccessorLinkPins> = artifacts.pins();
    let verified: VerifiedSuccessorAuthority = verify_successor_chain_authority(
        pins.plan(private_operation()?),
        &links,
        chain.budget,
        &mut artifacts,
    )?;
    let resolver: HashSuiteResolver = pins.resolver().clone();
    let domain: AtomicityDomainId = pins.domain;
    let root: &VerifiedGenesisRoot = pins.root();
    let serving_epoch: Epoch = verified.policy_inputs().context().epoch();
    let query_config: ProtocolConfig =
        host_query_protocol_config(&resolver, domain, serving_epoch).map_err(|_| refused())?;
    let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(NativeBlockingPolicy::new(
        NonZeroUsize::new(concurrent).ok_or_else(refused)?,
    ));
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut stop = crate::native_operations::StopOwner::install(crate::native_operations::PreparedLocalObservations::connect(None)?)?;
        let end: Instant = Instant::now().checked_add(total).ok_or_else(refused)?;
        let frontend: Arc<Frontend> = Arc::new(Frontend::new(socket, worker_uid, validator, root, &verified, resolver, query_config, timeout, end, max_requests)?);
        frontend.preflight().await?;
        let router = successor_custody::frontend_router(frontend);
        let listener: tokio::net::TcpListener = native_http::successor::bind_successor_loopback(listen).await?;
        let bound: SocketAddr = listener.local_addr()?;
        if !stop.stop_before_readiness() {
            println!("complete=true mode=successor-protected-frontend transport=http epoch={} validator_id={} listen={bound}", verified.policy_inputs().context().epoch().get(), validator);
            io::stdout().flush()?;
            stop.readiness_announced();
        }
        let observations = executor.observations();
        let closing = executor.clone();
        let shutdown = async move {
            tokio::select! {biased; _=stop.wait(observations)=>{}, ()=sleep_until(end)=>{}}
            closing.close();
        };
        let policy = native_http::NativeHttpServePolicy::default().with_certified_publication(true);
        let result = match tls {
            None => native_http::serve_with_stream_upgrade_observed(listener, router, policy, |stream: tokio::net::TcpStream| async move { Ok::<_, io::Error>(stream) }, shutdown, executor.observations()).await,
            Some(acceptor) => native_http::serve_with_stream_upgrade_observed(listener, router, policy, move |stream: tokio::net::TcpStream| native_tls::accept(acceptor.clone(), stream), shutdown, executor.observations()).await,
        };
        executor.close();
        executor.wait_drained().await;
        result
    })?;
    Ok(())
}
