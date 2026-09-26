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
//! TLS-only PostgreSQL connection builder, and the trusted genesis-manifest
//! loader) rather than reimplementing them; this binary adds no new trust
//! model beyond what that CLI's own doc comments already establish.
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
#![forbid(unsafe_code)]

use consensus::ConsensusSigner;
use crypto::{Ed25519Verifier, SignatureVerifier};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{PaidFeePolicy, decode_paid_fee_policy};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use native_http::{
    FastVoteComposition, NativeBlockingPolicy, PaidExecutionComposition,
    StructuredDurableNativeComponents, StructuredDurableRequestAuthority,
    certified_fastvote_router,
};
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::{FastPathValidatorEntry, decode_fastpath_validator_set_record};
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::{
    GenesisManifest, MAX_GENESIS_MANIFEST_BYTES, NodeConfig, decode_genesis_install_marker,
    decode_genesis_manifest, genesis_manifest_commitment, genesis_marker_key, local_instance_state,
};
use postgres::{
    Config,
    config::{Host, SslMode},
};
use postgres_rustls::{MakeTlsConnector, tokio_rustls::TlsConnector};
use protocol_config::{DomainPlacementManifest, ProtocolConfig, TransactionAuthProfile};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule,
    ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, DurableOutboxLeaseId, RuntimeError,
    StorageCorrelationId, StorageDeadline, SystemClock, Transport, WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, advance_writer_fence, build_postgres_pool, inspect_namespace,
};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::Read,
    num::NonZeroU32,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Never accepted on argv; supplied through the operator environment,
/// exactly like `fastvote_pg`.
const POSTGRES_DSN_ENV: &str = "SUNRISE_EDGE_OPERATOR_POSTGRES_DSN";
/// Exact raw Ed25519 seed length the local key file must contain.
const SIGNING_KEY_FILE_BYTES: usize = 32;

// ---------------------------------------------------------------------
// Bounded flag parsing (identical shape to `fastvote_pg`'s own parser).
// ---------------------------------------------------------------------

struct FlagSet {
    values: BTreeMap<String, Vec<String>>,
    bools: BTreeSet<String>,
}

impl FlagSet {
    fn parse(
        tokens: impl IntoIterator<Item = OsString>,
        value_flags: &[&'static str],
        bool_flags: &[&'static str],
    ) -> Result<Self, String> {
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut bools: BTreeSet<String> = BTreeSet::new();
        let mut iterator = tokens.into_iter();
        while let Some(flag) = iterator.next() {
            let flag: String = flag
                .into_string()
                .map_err(|_| "non-UTF8 flag".to_string())?;
            if bool_flags.contains(&flag.as_str()) {
                if !bools.insert(flag.clone()) {
                    return Err(format!("duplicate {flag}"));
                }
                continue;
            }
            if !value_flags.contains(&flag.as_str()) {
                return Err(format!("unknown flag {flag}"));
            }
            let value: String = iterator
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?
                .into_string()
                .map_err(|_| format!("non-UTF8 value for {flag}"))?;
            values.entry(flag).or_default().push(value);
        }
        Ok(Self { values, bools })
    }

    fn one(&mut self, flag: &str) -> Result<String, String> {
        let mut values: Vec<String> = self.values.remove(flag).unwrap_or_default();
        match values.len() {
            1 => Ok(values.remove(0)),
            0 => Err(format!("missing required {flag}")),
            _ => Err(format!("{flag} must be supplied exactly once")),
        }
    }

    fn many(&mut self, flag: &str) -> Vec<String> {
        self.values.remove(flag).unwrap_or_default()
    }

    fn bool(&mut self, flag: &str) -> bool {
        self.bools.remove(flag)
    }

    fn finish(self) -> Result<(), String> {
        if let Some(flag) = self.values.keys().next() {
            return Err(format!(
                "{flag} was supplied but is not used by this binary"
            ));
        }
        if let Some(flag) = self.bools.iter().next() {
            return Err(format!(
                "{flag} was supplied but is not used by this binary"
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Shared scalar parsing (identical to `fastvote_pg`'s own conventions).
// ---------------------------------------------------------------------

fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be 64 hex digits"));
    }
    let mut bytes: [u8; 32] = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{field} contains invalid hex"))?;
    }
    Ok(bytes)
}

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

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    field: &'static str,
) -> Result<Vec<u8>, String> {
    let mut file: fs::File =
        fs::File::open(path).map_err(|error| format!("failed to open {field}: {error}"))?;
    let limit: u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut buffer: Vec<u8> = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| format!("failed to read {field}: {error}"))?;
    if buffer.len() > max_bytes {
        return Err(format!(
            "{field} exceeds the maximum accepted size of {max_bytes} bytes"
        ));
    }
    Ok(buffer)
}

// ---------------------------------------------------------------------
// Local Ed25519 signing key: local 0600 regular file only, raw 32-byte
// seed, never argv/env. Identical TOCTOU-closing shape to `fastvote_pg`.
// ---------------------------------------------------------------------

#[derive(Debug)]
enum SigningKeyFileError {
    Io(std::io::Error),
    Symlink,
    NotRegularFile,
    #[cfg(not(unix))]
    UnsupportedPlatform,
    InsecurePermissions {
        mode: u32,
    },
    PathReplacedDuringOpen,
    WrongLength {
        actual: usize,
    },
}

impl fmt::Display for SigningKeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read signing key file: {error}"),
            Self::Symlink => f.write_str("signing key file must not be a symlink"),
            Self::NotRegularFile => f.write_str("signing key file must be a regular file"),
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => {
                f.write_str("signing key file permissions cannot be verified on this platform")
            }
            Self::InsecurePermissions { mode } => write!(
                f,
                "signing key file must grant no group/other permission bits, got mode {mode:03o}"
            ),
            Self::PathReplacedDuringOpen => f.write_str(
                "signing key file path was replaced between validation and opening; refusing to read it",
            ),
            Self::WrongLength { actual } => write!(
                f,
                "signing key file must contain exactly {SIGNING_KEY_FILE_BYTES} raw bytes, got {actual}"
            ),
        }
    }
}

impl Error for SigningKeyFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(unix)]
fn check_unix_permissions(metadata: &fs::Metadata) -> Result<(), SigningKeyFileError> {
    use std::os::unix::fs::PermissionsExt;
    let mode: u32 = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SigningKeyFileError::InsecurePermissions { mode });
    }
    Ok(())
}

#[cfg(not(unix))]
const fn check_unix_permissions(_metadata: &fs::Metadata) -> Result<(), SigningKeyFileError> {
    Err(SigningKeyFileError::UnsupportedPlatform)
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn load_signing_key_file(path: &Path) -> Result<SigningKey, SigningKeyFileError> {
    let pre_open_metadata: fs::Metadata =
        fs::symlink_metadata(path).map_err(SigningKeyFileError::Io)?;
    if pre_open_metadata.file_type().is_symlink() {
        return Err(SigningKeyFileError::Symlink);
    }
    if !pre_open_metadata.is_file() {
        return Err(SigningKeyFileError::NotRegularFile);
    }
    check_unix_permissions(&pre_open_metadata)?;
    #[cfg(unix)]
    let pre_open_identity: FileIdentity = FileIdentity::from_metadata(&pre_open_metadata);

    let mut file: fs::File = fs::File::open(path).map_err(SigningKeyFileError::Io)?;
    let opened_metadata: fs::Metadata = file.metadata().map_err(SigningKeyFileError::Io)?;
    if !opened_metadata.is_file() {
        return Err(SigningKeyFileError::NotRegularFile);
    }
    check_unix_permissions(&opened_metadata)?;
    #[cfg(unix)]
    {
        let opened_identity: FileIdentity = FileIdentity::from_metadata(&opened_metadata);
        if opened_identity != pre_open_identity {
            return Err(SigningKeyFileError::PathReplacedDuringOpen);
        }
    }

    let mut buffer: Vec<u8> = Vec::with_capacity(SIGNING_KEY_FILE_BYTES + 1);
    file.by_ref()
        .take(u64::try_from(SIGNING_KEY_FILE_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut buffer)
        .map_err(SigningKeyFileError::Io)?;
    if buffer.len() != SIGNING_KEY_FILE_BYTES {
        return Err(SigningKeyFileError::WrongLength {
            actual: buffer.len(),
        });
    }
    let mut seed: [u8; 32] = [0; 32];
    seed.copy_from_slice(&buffer);
    Ok(SigningKey::from(seed))
}

/// A real (non-mocked) `ConsensusSigner` backed by a locally loaded Ed25519
/// signing key. Never logs or exposes the key material.
struct FileEd25519Signer {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl ConsensusSigner for FileEd25519Signer {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

// ---------------------------------------------------------------------
// Genesis manifest trust: identical to `fastvote_pg`'s own loader.
// ---------------------------------------------------------------------

fn load_trusted_genesis_manifest(
    path: &Path,
    resolver: &HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<GenesisManifest, String> {
    let bytes: Vec<u8> = read_bounded_file(path, MAX_GENESIS_MANIFEST_BYTES, "genesis manifest")?;
    let manifest: GenesisManifest = decode_genesis_manifest(&bytes)
        .map_err(|error| format!("invalid genesis manifest: {error}"))?;
    let digest = genesis_manifest_commitment(resolver, &manifest)
        .map_err(|error| format!("failed to compute genesis manifest commitment: {error}"))?;
    if digest.bytes() != expected_digest {
        return Err(
            "genesis manifest commitment does not match the operator-trusted expected genesis digest"
                .into(),
        );
    }
    if manifest.context() != expected_context {
        return Err(
            "genesis manifest context does not match the operator-trusted expected chain/protocol/epoch"
                .into(),
        );
    }
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)
            .map_err(|error| format!("invalid genesis authority key: {error}"))?;
    let signing_frame: Vec<u8> = genesis_manifest_signing_frame(&manifest)
        .map_err(|error| format!("invalid genesis signing frame: {error}"))?;
    if !verifier
        .verify_framed(&signing_frame, &manifest.signature)
        .map_err(|error| format!("invalid genesis signature: {error}"))?
    {
        return Err("invalid genesis authority signature".into());
    }
    Ok(manifest)
}

/// Reads the already-committed genesis marker and fee policy and requires
/// them to match the trusted manifest exactly. Never installs anything.
fn require_committed_genesis_fee_policy(
    store: &PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>>,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected_context: &PublicationContext,
    expected_digest: [u8; 32],
    manifest: &GenesisManifest,
) -> Result<PaidFeePolicy, Box<dyn Error>> {
    let marker_key: Vec<u8> = genesis_marker_key(expected_context)?;
    let marker_value = store
        .get_versioned_durable(context, domain, &marker_key)
        .map_err(|error| format!("failed to read committed genesis marker: {error:?}"))?;
    let marker_bytes: &[u8] = marker_value
        .value()
        .ok_or("no committed genesis install marker for expected context; this namespace was never bootstrapped")?;
    let marker = decode_genesis_install_marker(marker_bytes)?;
    if marker.context != *expected_context
        || marker.manifest_digest.bytes() != expected_digest
        || marker.genesis_authority != manifest.genesis_authority
    {
        return Err("committed genesis marker differs from the trusted manifest".into());
    }
    let policy_key: Vec<u8> = local_instance_state::paid_fee_policy_key(expected_context)?;
    let policy_value = store
        .get_versioned_durable(context, domain, &policy_key)
        .map_err(|error| format!("failed to read committed fee policy: {error:?}"))?;
    let policy_bytes: &[u8] = policy_value
        .value()
        .ok_or("no committed paid fee policy for expected context")?;
    let policy: PaidFeePolicy = decode_paid_fee_policy(policy_bytes)?;
    if policy != manifest.fee_policy {
        return Err("committed fee policy differs from the trusted genesis manifest".into());
    }
    Ok(policy)
}

fn require_registered_signer<'a>(
    record: &'a FastPathValidatorSetRecord,
    validator_id: ValidatorId,
    public_key: &[u8; 32],
) -> Result<&'a FastPathValidatorEntry, String> {
    let entry: &FastPathValidatorEntry = record
        .validators
        .iter()
        .find(|candidate| candidate.id == validator_id)
        .ok_or(
            "configured --validator-id is not a member of the committed current validator set",
        )?;
    if entry.signature_scheme != SignatureSchemeId::Ed25519 || entry.public_key != public_key {
        return Err(
            "local signing key does not match the committed validator's registered public key"
                .into(),
        );
    }
    Ok(entry)
}

// ---------------------------------------------------------------------
// PostgreSQL connection wiring: identical to `fastvote_pg`'s own
// TLS-validated DSN pattern.
// ---------------------------------------------------------------------

fn require_tls_tcp_host(config: &mut Config) -> Result<(), &'static str> {
    if !matches!(config.get_hosts(), [Host::Tcp(_)]) {
        return Err("PostgreSQL connection requires exactly one TCP host for TLS identity");
    }
    config.ssl_mode(SslMode::Require);
    Ok(())
}

fn connect_pool(
    ca_der: &Path,
    max_connections: NonZeroU32,
) -> Result<Pool<PostgresConnectionManager<MakeTlsConnector>>, Box<dyn Error>> {
    let dsn: String = std::env::var(POSTGRES_DSN_ENV)
        .map_err(|_| format!("{POSTGRES_DSN_ENV} must be set in the operator environment"))?;
    let mut config: Config =
        Config::from_str(&dsn).map_err(|_| "invalid PostgreSQL connection configuration")?;
    require_tls_tcp_host(&mut config)?;

    let certificate: Vec<u8> = fs::read(ca_der)?;
    let mut roots: RootCertStore = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate))
        .map_err(|_| "invalid DER TLS root certificate")?;
    let tls_config: ClientConfig =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "unsupported TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let tls: MakeTlsConnector = MakeTlsConnector::new(TlsConnector::from(Arc::new(tls_config)));
    let pool_config: PostgresPoolConfig = PostgresPoolConfig::new(
        max_connections,
        Duration::from_secs(10),
        Duration::from_secs(30),
        Duration::from_secs(300),
    )?;
    Ok(build_postgres_pool(config, tls, pool_config)
        .map_err(|_| "PostgreSQL TLS connection or pool initialization failed")?)
}

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
) -> Result<(DurableOperationContext, WriterFenceGeneration), Box<dyn Error>> {
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable")?;
    let previous: WriterFenceGeneration = inspect_namespace(&mut *connection, namespace)?
        .ok_or("PostgreSQL namespace not bootstrapped; run fastvote_pg namespace-init/install-genesis first")?
        .writer_fence();
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

// ---------------------------------------------------------------------
// Minimal real `Transport`/`IndexedOutboxIdentitySource` for a
// certified-only host: no route this router ever mounts sends outbound
// transport messages or claims an outbox lease, so these exist only to
// satisfy the shared component types' generic bounds.
// ---------------------------------------------------------------------

/// A `Transport` that accepts nothing to send and never claims to have
/// delivered anything. Correct because the certified-only FastVote router
/// never mounts a route that calls `Transport::send`.
struct NoOutboundTransport;
impl Transport for NoOutboundTransport {
    fn send(&self, _message: Vec<u8>) -> Result<(), RuntimeError> {
        Err(RuntimeError::TransportUnavailable)
    }
    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        Ok(Vec::new())
    }
}

/// Restart-safe-within-one-process attempt identities: unique for the
/// lifetime of one claimed writer generation, which is exactly this
/// process's own serving lifetime (a fresh process claims a fresh
/// generation, so identities never repeat across restarts either).
struct SequentialIdentitySource {
    generation: WriterFenceGeneration,
    sequence: AtomicU64,
}
impl SequentialIdentitySource {
    const fn new(generation: WriterFenceGeneration) -> Self {
        Self {
            generation,
            sequence: AtomicU64::new(1),
        }
    }
}
impl native_http::IndexedOutboxIdentitySource for SequentialIdentitySource {
    fn next_attempt_identity(
        &self,
    ) -> Result<
        native_http::IndexedOutboxAttemptIdentity,
        native_http::IndexedOutboxIdentitySourceError,
    > {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        if sequence == 0 {
            return Err(native_http::IndexedOutboxIdentitySourceError::Exhausted);
        }
        let mut lease_bytes: [u8; 32] = [0; 32];
        lease_bytes[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        lease_bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
        let lease_id = DurableOutboxLeaseId::new(lease_bytes)
            .map_err(|_| native_http::IndexedOutboxIdentitySourceError::Unavailable)?;
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        correlation[8..].copy_from_slice(&sequence.to_be_bytes());
        let correlation_id = StorageCorrelationId::new(correlation)
            .ok_or(native_http::IndexedOutboxIdentitySourceError::Unavailable)?;
        Ok(native_http::IndexedOutboxAttemptIdentity::new(
            lease_id,
            correlation_id,
        ))
    }
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
const BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];

fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(tokens, VALUE_FLAGS, BOOL_FLAGS)?;
    let confirmed: bool = flags.bool("--confirm-offline-fence-advance");
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
    let manifest: GenesisManifest = load_trusted_genesis_manifest(
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
    let (context, generation) = claim_fresh_writer_fence_once(&pool, &namespace, timeout_seconds)?;
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    let blob_store: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone())?;

    let fee_policy: PaidFeePolicy = require_committed_genesis_fee_policy(
        &store,
        &context,
        domain,
        &expected_context,
        expected_digest,
        &manifest,
    )?;

    let validator_set_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&expected_context)?;
    let observed = store
        .get_versioned_durable(&context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;

    let signing_key: SigningKey =
        load_signing_key_file(&signing_key_path).map_err(|error| error.to_string())?;
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let derived_public_key: [u8; 32] = verification_key.into();
    require_registered_signer(&record, validator, &derived_public_key)?;

    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());
    let execution: PaidExecutionComposition =
        PaidExecutionComposition::new(base_policy, fee_policy);
    let signer: Arc<dyn ConsensusSigner + Send + Sync> = Arc::new(FileEd25519Signer {
        validator_id: validator,
        signing_key,
    });
    let fastvote: FastVoteComposition =
        FastVoteComposition::new(execution, signer, created_checkpoint);

    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = protocol_version;
    protocol_config.domain_placement = Some(DomainPlacementManifest::single_domain(
        1,
        domain,
        Epoch::new(0),
    )?);
    // Matches the ordinary CLI's fixed expected transaction-auth profile
    // (apps/cli/src/commands/standard_asset.rs::parse_expected_context) and
    // devnet's own genesis convention (apps/devnet/src/genesis.rs).
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
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

    let components = StructuredDurableNativeComponents::new(
        Arc::new(store),
        Arc::new(blob_store),
        Arc::new(NoOutboundTransport),
        Arc::new(SystemClock),
        Arc::new(SequentialIdentitySource::new(generation)),
    );
    let router = certified_fastvote_router(
        components,
        fastvote,
        protocol_config,
        authority,
        node_config,
        resolver,
        Vec::new(),
        NativeBlockingPolicy::new(NonZeroUsize::new(max_concurrent).ok_or("zero concurrency")?),
    )
    .map_err(|error| format!("failed to compose certified FastVote router: {error}"))?;

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
