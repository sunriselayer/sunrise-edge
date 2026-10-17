use crate::{
    common::{FlagSet, parse_hash_suite, parse_hex_32},
    native_operations::{PreparedLocalObservations, StopOwner},
    native_tls::{self, NativeTlsInputs},
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use native_http::ordered_custody::{
    Application, Frontend, Identity, frontend_router, serve_worker,
};
use native_http::{NativeBlockingExecutor, NativeBlockingPolicy, NativeHttpObservations};
use node_core::ordered_economics::OrderedEconomicsPolicy;
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fs::{self, File, Metadata},
    future::Future,
    io::{self, Read, Write},
    net::SocketAddr,
    num::NonZeroUsize,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UnixListener,
    time::{Instant, sleep_until},
};

const MAX_CONFIG: u64 = 16 * 1024;
const MAX_SECONDS: u64 = 3600;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn refused() -> io::Error {
    io::Error::other("original ordered custody refused")
}

fn own_uid() -> io::Result<u32> {
    let file: File = File::open("/proc/self/status")?;
    let mut bytes: String = String::new();
    file.take(8192).read_to_string(&mut bytes)?;
    bytes
        .lines()
        .find_map(|line: &str| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok()
        })
        .ok_or_else(refused)
}
fn absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part: Component<'_>| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(refused());
    }
    Ok(())
}
fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn owned(path: &Path, mode: u32, directory: bool) -> io::Result<Metadata> {
    absolute(path)?;
    let metadata: Metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != own_uid()?
        || metadata.permissions().mode() & 0o7777 != mode
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(refused());
    }
    Ok(metadata)
}
fn private_file(path: &Path) -> io::Result<Metadata> {
    owned(path.parent().ok_or_else(refused)?, 0o700, true)?;
    owned(path, 0o600, false)
}
fn config_file(path: &Path) -> io::Result<String> {
    let before: Metadata = private_file(path)?;
    if before.len() > MAX_CONFIG {
        return Err(refused());
    }
    let file: File = File::open(path)?;
    let opened: Metadata = file.metadata()?;
    if identity(&before) != identity(&opened)
        || opened.uid() != own_uid()?
        || opened.permissions().mode() & 0o7777 != 0o600
        || !opened.is_file()
    {
        return Err(refused());
    }
    let mut bytes: String = String::new();
    file.take(MAX_CONFIG + 1).read_to_string(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG
        || identity(&fs::symlink_metadata(path)?) != identity(&before)
    {
        return Err(refused());
    }
    Ok(bytes)
}
struct Config {
    values: BTreeMap<String, Vec<String>>,
}
impl Config {
    fn parse(input: &str, worker: bool) -> io::Result<Self> {
        Self::parse_profile(input, worker, false)
    }
    fn parse_profile(input: &str, worker: bool, certified: bool) -> io::Result<Self> {
        let common: &[&str] = &[
            "chain-id",
            "validator-id",
            "domain",
            "protocol-version",
            "epoch",
            "suite",
            "genesis-manifest",
            "expected-genesis-digest",
            "timeout-seconds",
            "max-concurrent",
            "socket",
            "max-requests",
            "total-deadline-seconds",
        ];
        let extra: &[&str] = if worker {
            &[
                "signing-key-file",
                "state-db",
                "blob-db",
                "independent-anchor-db",
                "frontend-uid",
                "max-connections",
                "confirm-offline-fence-advance",
            ]
        } else {
            &[
                "worker-uid",
                "listen",
                "tls-cert-der-file",
                "tls-key-pkcs8-der-file",
            ]
        };
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in input.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value): (&str, &str) = line.split_once('=').ok_or_else(refused)?;
            if !(common.contains(&key)
                || extra.contains(&key)
                || certified && worker && key == "created-checkpoint")
                || value.is_empty()
                || value.trim() != value
                || value.len() > 4096
            {
                return Err(refused());
            }
            let repeated: bool = matches!(key, "suite" | "tls-cert-der-file");
            let entries: &mut Vec<String> = values.entry(key.into()).or_default();
            if (!repeated && !entries.is_empty()) || entries.len() >= 64 {
                return Err(refused());
            }
            entries.push(value.into());
        }
        Ok(Self { values })
    }
    fn take(&mut self, key: &str) -> io::Result<String> {
        let mut entries: Vec<String> = self.values.remove(key).ok_or_else(refused)?;
        if entries.len() != 1 {
            return Err(refused());
        }
        entries.pop().ok_or_else(refused)
    }
    fn number(&mut self, key: &str, max: u64) -> io::Result<u64> {
        let value: u64 = self.take(key)?.parse().map_err(|_| refused())?;
        if value == 0 || value > max {
            return Err(refused());
        }
        Ok(value)
    }
    fn args(self) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();
        for (key, entries) in self.values {
            for value in entries {
                args.push(format!("--{key}").into());
                args.push(value.into());
            }
        }
        args
    }
}

pub(crate) struct Worker {
    certified: bool,
    socket: PathBuf,
    frontend_uid: u32,
    max_connections: u64,
    max_requests: u64,
    timeout: Duration,
    total: Duration,
}
impl Worker {
    fn from_config(config: &mut Config, certified: bool) -> Result<Self> {
        let socket: PathBuf = config.take("socket")?.into();
        absolute(&socket)?;
        if socket.as_os_str().len() > 100 {
            return Err(refused().into());
        }
        owned(socket.parent().ok_or_else(refused)?, 0o750, true)?;
        if fs::symlink_metadata(&socket).is_ok() {
            return Err(refused().into());
        }
        let frontend_uid: u32 = config.take("frontend-uid")?.parse()?;
        if frontend_uid == own_uid()? {
            return Err(refused().into());
        }
        let max_connections: u64 = config.number("max-connections", 4096)?;
        let max_requests: u64 = config.number("max-requests", 4096)?;
        let total: Duration =
            Duration::from_secs(config.number("total-deadline-seconds", MAX_SECONDS)?);
        let timeout_seconds: u64 = config
            .values
            .get("timeout-seconds")
            .and_then(|items: &Vec<String>| items.first())
            .ok_or_else(refused)?
            .parse()?;
        if !(1..=30).contains(&timeout_seconds) {
            return Err(refused().into());
        }
        let timeout: Duration = Duration::from_secs(timeout_seconds);
        for key in [
            "signing-key-file",
            "state-db",
            "blob-db",
            "independent-anchor-db",
        ] {
            let path: PathBuf = config
                .values
                .get(key)
                .and_then(|items: &Vec<String>| items.first())
                .ok_or_else(refused)?
                .into();
            private_file(&path)?;
        }
        if config.take("confirm-offline-fence-advance")? != "true" {
            return Err(refused().into());
        }
        if certified {
            // Explicit trusted local checkpoint, including zero. Parse now;
            // leave the value for the single original startup owner to consume.
            let checkpoint: &str = config
                .values
                .get("created-checkpoint")
                .and_then(|values: &Vec<String>| values.first())
                .ok_or_else(refused)?;
            let _: u64 = checkpoint.parse()?;
        }
        Ok(Self {
            certified,
            socket,
            frontend_uid,
            max_connections,
            max_requests,
            timeout,
            total,
        })
    }
    pub(crate) fn is_certified(&self) -> bool {
        self.certified
    }
    pub(crate) fn serve(
        self,
        app: Application,
        executor: NativeBlockingExecutor,
        identity: Identity,
    ) -> Result<()> {
        self.serve_inner(app, executor, OwnerIdentity::Ordered(identity))
    }
    pub(crate) fn serve_certified(
        self,
        app: Application,
        executor: NativeBlockingExecutor,
        identity: native_http::certified_custody::Identity,
    ) -> Result<()> {
        self.serve_inner(app, executor, OwnerIdentity::Certified(identity))
    }
    fn serve_inner(
        self,
        app: Application,
        executor: NativeBlockingExecutor,
        identity: OwnerIdentity,
    ) -> Result<()> {
        let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let (first, _second): (tokio::net::UnixStream, tokio::net::UnixStream) =
                tokio::net::UnixStream::pair()?;
            if first.peer_cred()?.uid() == self.frontend_uid {
                return Err(refused());
            }
            let mut stop: StopOwner = StopOwner::install(
                PreparedLocalObservations::connect(None).map_err(|_| refused())?,
            )?;
            let (owner, listener): (SocketOwner, UnixListener) = SocketOwner::bind(&self.socket)?;
            let end: Instant = Instant::now().checked_add(self.total).ok_or_else(refused)?;
            if !stop.stop_before_readiness() {
                if self.certified {
                    println!("complete=true mode=certified-worker transport=unix authority=original-certified-fastvote");
                } else {
                    println!("complete=true mode=protocol-worker transport=unix authority=original-ordered");
                }
                io::stdout().flush()?;
                stop.readiness_announced();
            }
            let served: io::Result<()> =
                bounded_lifecycle(executor, stop, end, move |shutdown, _observations| {
                    async move {
                        match identity {
                            OwnerIdentity::Ordered(identity) => serve_worker(listener, app, identity, self.frontend_uid, self.max_connections, self.max_requests, self.timeout, end, shutdown).await,
                            OwnerIdentity::Certified(identity) => native_http::certified_custody::serve_worker(listener, app, identity, self.frontend_uid, self.max_connections, self.max_requests, self.timeout, end, shutdown).await,
                        }
                    }
                })
                .await;
            let removed: io::Result<()> = owner.close();
            served?;
            removed
        })?;
        Ok(())
    }
}

enum OwnerIdentity {
    Ordered(Identity),
    Certified(native_http::certified_custody::Identity),
}

struct SocketOwner {
    path: PathBuf,
    inode: (u64, u64),
}
impl SocketOwner {
    fn bind(path: &Path) -> io::Result<(Self, UnixListener)> {
        owned(path.parent().ok_or_else(refused)?, 0o750, true)?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(refused()),
        }
        let listener: std::os::unix::net::UnixListener =
            std::os::unix::net::UnixListener::bind(path)?;
        let metadata: Metadata = fs::symlink_metadata(path)?;
        let owner: Self = Self {
            path: path.into(),
            inode: identity(&metadata),
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        let after: Metadata = fs::symlink_metadata(path)?;
        if !after.file_type().is_socket()
            || after.uid() != own_uid()?
            || identity(&after) != owner.inode
        {
            return Err(refused());
        }
        listener.set_nonblocking(true)?;
        Ok((owner, UnixListener::from_std(listener)?))
    }
    fn remove(&self) -> io::Result<()> {
        let after: Metadata = fs::symlink_metadata(&self.path)?;
        if identity(&after) != self.inode || !after.file_type().is_socket() {
            return Err(refused());
        }
        fs::remove_file(&self.path)
    }
    fn close(self) -> io::Result<()> {
        self.remove()
    }
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        let _removed: io::Result<()> = self.remove();
    }
}

type Shutdown = Pin<Box<dyn Future<Output = ()> + Send>>;
async fn bounded_lifecycle<R, F>(
    executor: NativeBlockingExecutor,
    stop: StopOwner,
    end: Instant,
    run: R,
) -> io::Result<()>
where
    R: FnOnce(Shutdown, NativeHttpObservations) -> F,
    F: Future<Output = io::Result<()>>,
{
    let observations: NativeHttpObservations = executor.observations();
    let stopping: NativeBlockingExecutor = executor.clone();
    let stopping_observations: NativeHttpObservations = observations.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel::<io::Result<()>>();
    let shutdown: Shutdown = Box::pin(async move {
        let result: io::Result<()> = tokio::select! {
            biased; result=stop.wait(stopping_observations)=>result.map(|_reason|()),
            ()=sleep_until(end)=>Ok(()),
        };
        stopping.close();
        let _sent = sender.send(result);
    });
    let served: io::Result<()> = run(shutdown, observations).await;
    executor.close();
    executor.wait_drained().await;
    let stopped: io::Result<()> = receiver.await.unwrap_or_else(|_| Err(refused()));
    served?;
    stopped?;
    eprintln!("protocol_custody complete=true admission=closed work=drained");
    Ok(())
}

pub(super) fn run(worker: bool, tokens: Vec<OsString>) -> Result<()> {
    run_profile(worker, tokens, false)
}
pub(super) fn run_certified(worker: bool, tokens: Vec<OsString>) -> Result<()> {
    run_profile(worker, tokens, true)
}
fn run_profile(worker: bool, tokens: Vec<OsString>, certified: bool) -> Result<()> {
    let mut flags: FlagSet = FlagSet::parse(tokens, &["--config"], &[])?;
    let path: PathBuf = flags.one("--config")?.into();
    flags.finish()?;
    let input: String = config_file(&path)?;
    let mut config: Config = if certified {
        Config::parse_profile(&input, worker, true)?
    } else {
        Config::parse(&input, worker)?
    };
    if worker {
        let launch: Worker = Worker::from_config(&mut config, certified)?;
        let mut args: Vec<OsString> = config.args();
        args.push("--confirm-offline-fence-advance".into());
        crate::sqlite_source_host::run_worker(args, launch)
    } else {
        frontend(config, certified)
    }
}

fn frontend(mut config: Config, certified: bool) -> Result<()> {
    let socket: PathBuf = config.take("socket")?.into();
    absolute(&socket)?;
    let worker_uid: u32 = config.take("worker-uid")?.parse()?;
    if worker_uid == own_uid()? {
        return Err(refused().into());
    }
    let max_requests: u64 = config.number("max-requests", 4096)?;
    let total: Duration =
        Duration::from_secs(config.number("total-deadline-seconds", MAX_SECONDS)?);
    let timeout: Duration = Duration::from_secs(config.number("timeout-seconds", 30)?);
    let concurrent: usize = usize::try_from(config.number("max-concurrent", 256)?)?;
    let listen: SocketAddr = config.take("listen")?.parse()?;
    if !listen.ip().is_loopback() {
        return Err(refused().into());
    }
    let chain: ChainId = ChainId::new(config.take("chain-id")?)?;
    let validator: ValidatorId =
        ValidatorId::new(parse_hex_32(&config.take("validator-id")?, "validator-id")?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&config.take("domain")?, "domain")?)?;
    let raw: u32 = config.take("protocol-version")?.parse()?;
    if raw == 0 {
        return Err(refused().into());
    }
    let version: ProtocolVersion = ProtocolVersion::new(raw);
    let epoch: Epoch = Epoch::new(config.take("epoch")?.parse()?);
    let suites: Vec<String> = config.values.remove("suite").ok_or_else(refused)?;
    if suites.is_empty() || suites.len() > 64 {
        return Err(refused().into());
    }
    let schedule: Vec<HashSuiteSchedule> = suites
        .iter()
        .map(|value: &String| parse_hash_suite(value))
        .collect::<std::result::Result<Vec<HashSuiteSchedule>, String>>()?;
    let manifest: PathBuf = config.take("genesis-manifest")?.into();
    absolute(&manifest)?;
    let digest: [u8; 32] = parse_hex_32(
        &config.take("expected-genesis-digest")?,
        "expected-genesis-digest",
    )?;
    let mut tls_flags: FlagSet = FlagSet::parse(
        config.args(),
        &[native_tls::CERT_FLAG, native_tls::KEY_FLAG],
        &[],
    )?;
    let tls_inputs: NativeTlsInputs = NativeTlsInputs::parse(&mut tls_flags)?;
    tls_flags.finish()?;
    let tls: Option<tokio_rustls::TlsAcceptor> = tls_inputs.load()?;
    let resolver: HashSuiteResolver = HashSuiteResolver::new(chain.clone(), version, schedule)?;
    let context: PublicationContext = PublicationContext::new(chain, version, epoch)?;
    let root: node_core::genesis::VerifiedGenesisRoot =
        sunrise_edge_client::load_verified_genesis_root(&manifest, &resolver, digest, &context)?;
    if !root.admission_profile().is_causal() {
        return Err(refused().into());
    }
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_genesis_root(&root, domain)?;
    if policy.engine().validator_set().get(validator).is_none() {
        return Err(refused().into());
    }
    let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(NativeBlockingPolicy::new(
        NonZeroUsize::new(concurrent).ok_or_else(refused)?,
    ));
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut stop: StopOwner =
            StopOwner::install(PreparedLocalObservations::connect(None).map_err(|_| refused())?)?;
        let end: Instant = Instant::now().checked_add(total).ok_or_else(refused)?;
        let app: Application = if certified {
            let query_config: protocol_config::ProtocolConfig = crate::host_protocol_context::host_query_protocol_config(&resolver, domain, epoch)?;
            let target: Arc<native_http::certified_custody::Frontend> = Arc::new(native_http::certified_custody::Frontend::new(socket, worker_uid, validator, domain, &root, resolver, query_config, timeout, end, max_requests, executor.clone())?);
            target.preflight().await?;
            native_http::certified_custody::frontend_router(target)
        } else {
            let target: Arc<Frontend> = Arc::new(Frontend::new(socket, worker_uid, validator, policy, timeout, end, max_requests, executor.clone()));
            target.preflight().await?;
            frontend_router(target)
        };
        let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind(listen).await?;
        let address: SocketAddr = listener.local_addr()?;
        if !stop.stop_before_readiness() {
            if certified {
                println!("complete=true mode=certified-frontend transport=http authority=none listen={address}");
            } else {
                println!("complete=true mode=protocol-frontend transport=http authority=none listen={address}");
            }
            io::stdout().flush()?;
            stop.readiness_announced();
        }
        bounded_lifecycle(
            executor,
            stop,
            end,
            move |shutdown, observations| async move {
                let policy: native_http::NativeHttpServePolicy =
                    native_http::NativeHttpServePolicy::new(
                        concurrent,
                        native_http::DEFAULT_NATIVE_HTTP_HEADER_READ_MILLIS,
                        native_http::DEFAULT_NATIVE_HTTP_BODY_IDLE_MILLIS,
                        native_http::DEFAULT_NATIVE_HTTP_BODY_TOTAL_MILLIS,
                        native_http::DEFAULT_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS,
                    )
                    .map_err(|_| refused())?
                    .with_certified_publication(true);
                match tls {
                    None => native_http::serve_with_stream_upgrade_observed(
                        listener,
                        app,
                        policy,
                        |stream: tokio::net::TcpStream| async move { Ok::<_, io::Error>(stream) },
                        shutdown,
                        observations,
                    )
                    .await,
                    Some(acceptor) => {
                        native_http::serve_with_stream_upgrade_observed(
                            listener,
                            app,
                            policy,
                            move |stream: tokio::net::TcpStream| {
                                native_tls::accept(acceptor.clone(), stream)
                            },
                            shutdown,
                            observations,
                        )
                        .await
                    }
                }
            },
        )
        .await
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_is_role_closed_and_rejects_duplicate_or_path_authority_keys() {
        for input in [
            "state-db=/tmp/state\n",
            "signing-key-file=/tmp/key\n",
            "trusted=true\n",
            "worker-uid=1\nworker-uid=2\n",
            "worker-uid= 1\n",
        ] {
            assert!(Config::parse(input, false).is_err());
        }
        assert!(Config::parse("worker-uid=1\n", true).is_err());
        assert!(Config::parse("frontend-uid=1\n", false).is_err());
    }
    #[test]
    fn certified_checkpoint_is_only_an_explicit_new_worker_input() {
        assert!(Config::parse("created-checkpoint=0\n", true).is_err());
        assert!(Config::parse_profile("created-checkpoint=0\n", false, true).is_err());
        assert!(Config::parse_profile("created-checkpoint=0\n", true, true).is_ok());
        assert!(
            Config::parse_profile("created-checkpoint=1\ncreated-checkpoint=2\n", true, true)
                .is_err()
        );
        for key in ["trusted", "factory", "sign-frame", "protocol-profile"] {
            assert!(Config::parse_profile(&format!("{key}=yes\n"), true, true).is_err());
        }
        assert!(Config::parse_profile("signing-key-file=/tmp/key\n", false, true).is_err());
        assert!(Config::parse_profile("worker-uid=1\n", true, true).is_err());
    }
    #[test]
    fn paths_are_local_absolute_without_parent_traversal() {
        for path in ["relative/key", "/tmp/../key"] {
            assert!(absolute(Path::new(path)).is_err());
        }
        assert!(absolute(Path::new("/tmp/owned/key")).is_ok());
    }
    #[test]
    fn private_config_refuses_symlinks_shared_modes_and_wrong_parent_mode() {
        let nonce: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "ordered-private-config-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path: PathBuf = directory.join("config");
        fs::write(&path, b"worker-uid=1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(config_file(&path).unwrap(), "worker-uid=1\n");
        let link: PathBuf = directory.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(config_file(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(config_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(config_file(&path).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }
}
