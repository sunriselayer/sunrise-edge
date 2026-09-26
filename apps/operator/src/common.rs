//! Narrow shared operator input, key, genesis, and PostgreSQL TLS boundaries.
#![forbid(unsafe_code)]
use crypto::{Ed25519Verifier, SignatureVerifier};
use ed25519_zebra::SigningKey;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::genesis::genesis_manifest_signing_frame;
use node_core::{
    GenesisManifest, MAX_GENESIS_MANIFEST_BYTES, decode_genesis_manifest,
    genesis_manifest_commitment,
};
use postgres::{
    Config,
    config::{Host, SslMode},
};
use postgres_rustls::{MakeTlsConnector, tokio_rustls::TlsConnector};
use protocol_types::Digest32;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime_postgres::{PostgresPoolConfig, build_postgres_pool};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::Read,
    num::NonZeroU32,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
const POSTGRES_DSN_ENV: &str = "SUNRISE_EDGE_OPERATOR_POSTGRES_DSN";
const SIGNING_KEY_FILE_BYTES: usize = 32;

/// Fail-closed startup pin failures; no failure changes installed state.
#[derive(Debug)]
pub enum LiveFastVotePinError {
    ValidatorSetContextMismatch,
    MissingLiveEpoch,
    EpochMismatch {
        configured: protocol_types::Epoch,
        live: protocol_types::Epoch,
    },
    ValidatorSetDigestMismatch,
    InvalidValidatorSet(validator_set::ValidatorSetError),
    InvalidEpochRecord(Box<node_core::NodeCoreError>),
    Read(runtime::DurableReadError),
}

impl fmt::Display for LiveFastVotePinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidatorSetContextMismatch => formatter.write_str("fastvote-epoch-repin-required: loaded validator set differs from configured context; perform an out-of-band re-pin"),
            Self::MissingLiveEpoch => formatter.write_str("fastvote-epoch-repin-required: no installed live epoch; perform an out-of-band re-pin"),
            Self::EpochMismatch { configured, live } => write!(formatter, "fastvote-epoch-repin-required: configured epoch {} differs from installed live epoch {}; perform an out-of-band re-pin before restarting", configured.get(), live.get()),
            Self::ValidatorSetDigestMismatch => formatter.write_str("fastvote-epoch-repin-required: installed live validator-set digest differs from the configured set; perform an out-of-band re-pin before restarting"),
            Self::InvalidValidatorSet(error) => write!(formatter, "invalid configured validator set: {error}"),
            Self::InvalidEpochRecord(error) => write!(formatter, "invalid installed live epoch record: {error}"),
            Self::Read(error) => write!(formatter, "failed to read installed live FastVote epoch: {error:?}"),
        }
    }
}
impl Error for LiveFastVotePinError {}

/// Validates an installed live epoch against the fixed host composition.
/// Call before claiming a new writer fence or opening a listener.
pub fn require_live_fastvote_pin<S: runtime::DurableDomainStateStore>(
    store: &S,
    operation: &runtime::DurableOperationContext,
    domain: protocol_types::AtomicityDomainId,
    expected: &PublicationContext,
    record: &node_core::fast_path::FastPathValidatorSetRecord,
    resolver: &HashSuiteResolver,
) -> Result<(), LiveFastVotePinError> {
    use node_core::local_instance_state::{
        decode_fastpath_epoch_record, fastpath_epoch_record_key,
    };
    use validator_set::{ValidatorInfo, ValidatorSet};
    if record.context != *expected {
        return Err(LiveFastVotePinError::ValidatorSetContextMismatch);
    }
    let validators: Vec<ValidatorInfo> = record
        .validators
        .iter()
        .map(|entry| ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let set: ValidatorSet = ValidatorSet::new(expected.epoch(), validators)
        .map_err(LiveFastVotePinError::InvalidValidatorSet)?;
    let digest: Digest32 = set
        .digest(resolver)
        .map_err(LiveFastVotePinError::InvalidValidatorSet)?;
    let key: Vec<u8> = fastpath_epoch_record_key(expected.chain_id())
        .map_err(|error| LiveFastVotePinError::InvalidEpochRecord(Box::new(error)))?;
    let observed: runtime::VersionedStateValue = store
        .get_versioned_durable(operation, domain, &key)
        .map_err(LiveFastVotePinError::Read)?;
    let bytes: &[u8] = observed
        .value()
        .ok_or(LiveFastVotePinError::MissingLiveEpoch)?;
    let live: node_core::local_instance_state::FastPathEpochRecord =
        decode_fastpath_epoch_record(bytes)
            .map_err(|error| LiveFastVotePinError::InvalidEpochRecord(Box::new(error)))?;
    if live.current_epoch != expected.epoch() {
        return Err(LiveFastVotePinError::EpochMismatch {
            configured: expected.epoch(),
            live: live.current_epoch,
        });
    }
    if live.current_validator_set_digest != digest {
        return Err(LiveFastVotePinError::ValidatorSetDigestMismatch);
    }
    Ok(())
}
pub struct FlagSet {
    values: BTreeMap<String, Vec<String>>,
    bools: BTreeSet<String>,
}

impl FlagSet {
    pub fn parse(
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

    /// Removes and returns exactly one value for `flag`.
    pub fn one(&mut self, flag: &str) -> Result<String, String> {
        let mut values: Vec<String> = self.values.remove(flag).unwrap_or_default();
        match values.len() {
            1 => Ok(values.remove(0)),
            0 => Err(format!("missing required {flag}")),
            _ => Err(format!("{flag} must be supplied exactly once")),
        }
    }

    /// Removes and returns zero or one value for `flag`.
    pub fn optional_one(&mut self, flag: &str) -> Result<Option<String>, String> {
        let mut values: Vec<String> = self.values.remove(flag).unwrap_or_default();
        match values.len() {
            0 => Ok(None),
            1 => Ok(Some(values.remove(0))),
            _ => Err(format!("{flag} must be supplied at most once")),
        }
    }

    /// Removes and returns every value for `flag`, in argument order.
    pub fn many(&mut self, flag: &str) -> Vec<String> {
        self.values.remove(flag).unwrap_or_default()
    }

    pub fn bool(&mut self, flag: &str) -> bool {
        self.bools.remove(flag)
    }

    /// Fails closed if any supplied flag was never consumed by the caller
    /// (for example a `--genesis-manifest` supplied alongside
    /// `--validator-set-source committed`, which never reads it): a silently
    /// ignored operator flag is exactly the kind of mistake this bounded
    /// parser exists to catch.
    pub fn finish(self) -> Result<(), String> {
        if let Some(flag) = self.values.keys().next() {
            return Err(format!(
                "{flag} was supplied but is not used by this subcommand/mode"
            ));
        }
        if let Some(flag) = self.bools.iter().next() {
            return Err(format!(
                "{flag} was supplied but is not used by this subcommand/mode"
            ));
        }
        Ok(())
    }
}

pub fn parse_hex_32(value: &str, field: &str) -> Result<[u8; 32], String> {
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

pub fn read_bounded_file(
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

#[derive(Debug)]
pub enum SigningKeyFileError {
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

/// Loads and strictly validates a raw 32-byte Ed25519 seed from `path`.
pub fn load_signing_key_file(path: &Path) -> Result<SigningKey, SigningKeyFileError> {
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

pub fn load_trusted_genesis_manifest(
    path: &Path,
    resolver: &HashSuiteResolver,
    expected_digest: [u8; 32],
    expected_context: &PublicationContext,
) -> Result<GenesisManifest, String> {
    let bytes: Vec<u8> = read_bounded_file(path, MAX_GENESIS_MANIFEST_BYTES, "genesis manifest")?;
    let manifest: GenesisManifest = decode_genesis_manifest(&bytes)
        .map_err(|error| format!("invalid genesis manifest: {error}"))?;
    let digest: Digest32 = genesis_manifest_commitment(resolver, &manifest)
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

pub fn require_tls_tcp_host(config: &mut Config) -> Result<(), &'static str> {
    if !matches!(config.get_hosts(), [Host::Tcp(_)]) {
        return Err("PostgreSQL connection requires exactly one TCP host for TLS identity");
    }
    config.ssl_mode(SslMode::Require);
    Ok(())
}

pub fn connect_pool(
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
