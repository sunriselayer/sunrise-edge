//! Operator-only PostgreSQL FastVote CLI (DR-0126/DR-0129/DR-0130).
//!
//! One bounded-subcommand binary driving the closed, genesis-epoch-only
//! FastVote workflow against one validator's PostgreSQL namespace:
//! `namespace-init`, `install-genesis`, `prepare-vote`,
//! `assemble-certificate`, `apply-certificate`. Never serves requests, never
//! opens a public network listener, and never accepts a signing key on
//! argv/env (the DSN is read from `SUNRISE_EDGE_OPERATOR_POSTGRES_DSN`,
//! matching `fee_escrow_inventory_pg`; the signing key comes only from a
//! local 0600 regular file).
//!
//! Every input (genesis manifest bytes, signed paid-intent bytes, votes, a
//! certificate) is exactly the bytes an existing protocol codec already
//! accepts. This binary invents no new canonical frame and exposes no HTTP
//! route: it is a thin, explicitly bounded wiring of
//! `node_core::genesis::install_genesis_with_history`,
//! `node_core::fast_path::{prepare, apply}` and
//! `consensus::FastPathCertifier` against `runtime_postgres`.
//!
//! Trust model: every mutating subcommand takes the operator's own
//! separately trusted `--chain-id`, `--validator-id`, `--domain`,
//! `--protocol-version`, `--epoch` and `--suite` (hash schedule) flags, plus
//! (where a genesis manifest is consumed) `--expected-genesis-digest`. The
//! genesis manifest file is only ever trusted after its
//! `genesis_manifest_commitment` under the operator-supplied resolver
//! matches that expected digest exactly, its authority signature verifies,
//! and its embedded context equals the operator-supplied expected context;
//! these checks fail closed on any mismatch, before any signature is
//! produced or durable state is touched. `prepare-vote` additionally derives
//! the local signing key's public key and requires it to match the committed
//! registration looked up by the operator-configured `--validator-id`,
//! before ever calling
//! `consensus::FastPathCertifier::cast_vote`.
//!
//! Phase 1 scope: genesis-epoch-only, exactly like
//! `node_core::fast_path` itself. There is no epoch-transition subcommand
//! here; an operator-supplied `--epoch` that does not equal the trusted
//! genesis manifest's own context epoch is rejected before any network or
//! disk I/O beyond reading the manifest file.
#![forbid(unsafe_code)]

use sunrise_edge_operator::common::{
    FlagSet, connect_pool, load_signing_key_file, load_trusted_genesis_manifest, parse_hex_32,
    read_bounded_file,
};
#[cfg(test)]
use sunrise_edge_operator::common::{SigningKeyFileError, require_tls_tcp_host};

use consensus::{
    ConsensusSigner, FastCertificate, FastPathCertifier, FastVote, decode_fast_certificate,
    decode_fast_vote, encode_fast_certificate, encode_fast_vote,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{
    MAX_SIGNED_PAID_INTENT_BYTES, PaidFeePolicy, decode_paid_fee_policy,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::fast_path::records::{
    FastPathValidatorEntry, MAX_FASTPATH_ACTIVE_VALIDATORS, decode_fastpath_validator_set_record,
};
use node_core::fast_path::{self, FastPathEd25519Verifier, FastPathValidatorSetRecord};
use node_core::local_instance_state;
use node_core::{
    GenesisInstallOutcome, GenesisManifest, decode_genesis_install_marker, genesis_marker_key,
    install_genesis_with_history,
};
use postgres::Client;
#[cfg(test)]
use postgres::{Config, config::SslMode};
use postgres_rustls::MakeTlsConnector;
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule,
    ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    SystemClock, WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
    advance_writer_fence, apply_initial_schema, bootstrap_namespace, inspect_namespace,
};
#[cfg(test)]
use std::str::FromStr;
use std::{
    error::Error,
    ffi::OsString,
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::ExitCode,
};
use validator_set::{ValidatorInfo, ValidatorSet};

/// Generous bound on one encoded `FastVote` file (canonical frame overhead
/// plus an ordinary chain id, several 32-byte digests and a 64-byte
/// signature comfortably fits in low hundreds of bytes).
const MAX_VOTE_FILE_BYTES: usize = 4096;
/// Bound on one encoded `FastCertificate` file: at most
/// `MAX_FASTPATH_ACTIVE_VALIDATORS` votes, each individually bounded by
/// [`MAX_VOTE_FILE_BYTES`], plus header overhead.
const MAX_CERTIFICATE_FILE_BYTES: usize = MAX_FASTPATH_ACTIVE_VALIDATORS * MAX_VOTE_FILE_BYTES;
/// Bound on the number of `--vote` files `assemble-certificate` accepts.
const MAX_VOTE_INPUTS: usize = MAX_FASTPATH_ACTIVE_VALIDATORS;

// ---------------------------------------------------------------------
// Shared scalar parsing (mirrors `fee_escrow_inventory_pg`'s conventions).
// ---------------------------------------------------------------------

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
        return Err("--suite needs epoch:id:transaction:object:effects:code:config:certificate (decimal wire ids)".into());
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
// Bounded file I/O.
// ---------------------------------------------------------------------

fn write_output_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options: fs::OpenOptions = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file: fs::File = options
        .open(path)
        .map_err(|error| format!("failed to create new {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", path.display()))
}

// ---------------------------------------------------------------------
// Local Ed25519 signing key: local 0600 regular file only, raw 32-byte
// seed, never argv/env. Mirrors `apps/cli/src/seed.rs`'s TOCTOU-closing
// pattern, adapted for a raw binary key file instead of hex text.
// ---------------------------------------------------------------------

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
// Genesis manifest trust: bytes are only ever used after their
// `genesis_manifest_commitment` under the operator's own resolver matches
// an independently supplied expected digest, and the manifest's embedded
// context matches the operator's independently supplied expected context.
// ---------------------------------------------------------------------

/// The local validator must have installed the exact signed manifest and its
/// committed fee policy must still equal the policy proposed to FastVote.
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
        .ok_or("no committed genesis install marker for expected context")?;
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

// ---------------------------------------------------------------------
// Validator-set conversion: maps the durable/manifest record shape onto
// `validator_set::ValidatorSet`, exactly like `node_core::fast_path`'s own
// (crate-private) conversion, rejecting a non-Ed25519 member and a context
// mismatch.
// ---------------------------------------------------------------------

fn validator_set_from_record(
    record: &FastPathValidatorSetRecord,
    expected_context: &PublicationContext,
) -> Result<ValidatorSet, String> {
    if &record.context != expected_context {
        return Err("fast-path validator set record context mismatch".into());
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(record.validators.len());
    for validator in &record.validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err("fast-path phase 1 supports only Ed25519 validators".into());
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    ValidatorSet::new(expected_context.epoch(), info).map_err(|error| error.to_string())
}

/// Requires that `validator_id`/`public_key` are a registered Ed25519
/// member of `record`, before any vote is cast.
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
// PostgreSQL connection wiring, shared by every DB-touching subcommand.
// Mirrors `fee_escrow_inventory_pg`'s TLS-validated DSN pattern exactly.
// ---------------------------------------------------------------------

/// Claims a fresh writer generation for one disruptive operator command,
/// exactly like `fee_escrow_inventory_pg`: reads the current generation,
/// advances it by exactly one, and returns the context every durable call
/// in this process must use.
fn claim_fresh_writer_fence(
    pool: &Pool<PostgresConnectionManager<MakeTlsConnector>>,
    namespace: &PostgresNamespace,
    timeout_seconds: u64,
) -> Result<(DurableOperationContext, WriterFenceGeneration), Box<dyn Error>> {
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable")?;
    let previous: WriterFenceGeneration = inspect_namespace(&mut *connection, namespace)?
        .ok_or("PostgreSQL namespace not bootstrapped")?
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

/// Reconciles that the claimed writer fence is still active and the
/// deadline has not expired, exactly like `fee_escrow_inventory_pg`.
fn reconcile_writer_fence(
    pool: &Pool<PostgresConnectionManager<MakeTlsConnector>>,
    namespace: &PostgresNamespace,
    context: &DurableOperationContext,
) -> Result<(), Box<dyn Error>> {
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable after commit")?;
    let current: WriterFenceGeneration = inspect_namespace(&mut *connection, namespace)?
        .ok_or("PostgreSQL namespace missing after commit")?
        .writer_fence();
    if current != context.writer_fence() {
        return Err("writer fence changed during the operation; discard the result".into());
    }
    if SystemClock.now_unix_millis()? >= context.deadline().unix_millis() {
        return Err("operation deadline expired before completion".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Common resolver/expected-context construction, shared by every
// subcommand that touches the fast-path protocol.
// ---------------------------------------------------------------------

fn build_resolver(
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    schedule: Vec<HashSuiteSchedule>,
) -> Result<HashSuiteResolver, Box<dyn Error>> {
    Ok(HashSuiteResolver::new(
        chain.clone(),
        protocol_version,
        schedule,
    )?)
}

fn build_expected_context(
    chain: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
) -> Result<PublicationContext, Box<dyn Error>> {
    Ok(PublicationContext::new(chain, protocol_version, epoch)?)
}

// ---------------------------------------------------------------------
// namespace-init
// ---------------------------------------------------------------------

const NAMESPACE_INIT_VALUE_FLAGS: &[&str] =
    &["--tls-root-der", "--chain-id", "--validator-id", "--domain"];
const NAMESPACE_INIT_BOOL_FLAGS: &[&str] = &["--confirm-namespace-bootstrap"];

fn run_namespace_init(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        tokens,
        NAMESPACE_INIT_VALUE_FLAGS,
        NAMESPACE_INIT_BOOL_FLAGS,
    )?;
    let confirmed: bool = flags.bool("--confirm-namespace-bootstrap");
    let ca_der: PathBuf = PathBuf::from(flags.one("--tls-root-der")?);
    let chain: ChainId = parse_chain(flags.one("--chain-id")?)?;
    let validator: ValidatorId = parse_validator(&flags.one("--validator-id")?)?;
    let domain: AtomicityDomainId = parse_domain(&flags.one("--domain")?)?;
    flags.finish()?;
    if !confirmed {
        return Err("requires --confirm-namespace-bootstrap".into());
    }

    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> =
        connect_pool(&ca_der, NonZeroU32::new(1).ok_or("zero pool size")?)?;
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable")?;
    let client: &mut Client = &mut connection;
    apply_initial_schema(client)?;
    let writer_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(1).ok_or("zero initial writer fence")?;
    let metadata = bootstrap_namespace(
        client,
        &namespace,
        runtime_postgres::POSTGRES_SCHEMA_GENERATION,
        writer_fence,
    )?;
    println!(
        "complete=true chain_id={chain} validator_id={validator} domain={domain} schema_generation={} writer_fence={}",
        metadata.schema_generation().get(),
        metadata.writer_fence().get(),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// install-genesis
// ---------------------------------------------------------------------

const INSTALL_GENESIS_VALUE_FLAGS: &[&str] = &[
    "--tls-root-der",
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--checkpoint",
    "--timeout-seconds",
];
const INSTALL_GENESIS_BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];

fn run_install_genesis(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        tokens,
        INSTALL_GENESIS_VALUE_FLAGS,
        INSTALL_GENESIS_BOOL_FLAGS,
    )?;
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
    let checkpoint: u64 =
        parse_u64_bounded(&flags.one("--checkpoint")?, "--checkpoint", 0, u64::MAX)?;
    let timeout_seconds: u64 = parse_u64_bounded(
        &flags.one("--timeout-seconds")?,
        "--timeout-seconds",
        1,
        3600,
    )?;
    flags.finish()?;
    if !confirmed {
        return Err(
            "requires --confirm-offline-fence-advance: stop the validator first; this command advances its writer fence and the validator must restart"
                .into(),
        );
    }

    let resolver: HashSuiteResolver = build_resolver(&chain, protocol_version, schedule)?;
    let expected_context: PublicationContext =
        build_expected_context(chain.clone(), protocol_version, epoch)?;
    let manifest: GenesisManifest = load_trusted_genesis_manifest(
        &manifest_path,
        &resolver,
        expected_digest,
        &expected_context,
    )?;

    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> =
        connect_pool(&ca_der, NonZeroU32::new(2).ok_or("zero pool size")?)?;
    let (context, generation) = claim_fresh_writer_fence(&pool, &namespace, timeout_seconds)?;
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);

    let outcome: GenesisInstallOutcome = install_genesis_with_history(
        &store,
        &context,
        domain,
        &resolver,
        &[],
        &manifest,
        checkpoint,
    )?;
    reconcile_writer_fence(&pool, &namespace, &context)?;

    let (label, marker, digest) = match &outcome {
        GenesisInstallOutcome::FreshInstall {
            marker,
            manifest_digest,
        } => ("fresh_install", marker, manifest_digest),
        GenesisInstallOutcome::VerifiedExisting {
            marker,
            manifest_digest,
        } => ("verified_existing", marker, manifest_digest),
    };
    println!(
        "complete=true outcome={label} chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_generation={} manifest_digest={} installed_at_checkpoint={}",
        protocol_version.get(),
        epoch.get(),
        generation.get(),
        to_hex(&digest.bytes()),
        marker.installed_at_checkpoint,
    );
    Ok(())
}

// ---------------------------------------------------------------------
// prepare-vote
// ---------------------------------------------------------------------

const PREPARE_VOTE_VALUE_FLAGS: &[&str] = &[
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
    "--paid-intent",
    "--created-checkpoint",
    "--vote-output",
    "--timeout-seconds",
];
const PREPARE_VOTE_BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];

fn run_prepare_vote(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet =
        FlagSet::parse(tokens, PREPARE_VOTE_VALUE_FLAGS, PREPARE_VOTE_BOOL_FLAGS)?;
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
    let paid_intent_path: PathBuf = PathBuf::from(flags.one("--paid-intent")?);
    let created_checkpoint: u64 = parse_u64_bounded(
        &flags.one("--created-checkpoint")?,
        "--created-checkpoint",
        0,
        u64::MAX,
    )?;
    let vote_output: PathBuf = PathBuf::from(flags.one("--vote-output")?);
    let timeout_seconds: u64 = parse_u64_bounded(
        &flags.one("--timeout-seconds")?,
        "--timeout-seconds",
        1,
        3600,
    )?;
    flags.finish()?;
    if !confirmed {
        return Err(
            "requires --confirm-offline-fence-advance: stop the validator first; this command advances its writer fence and the validator must restart"
                .into(),
        );
    }

    let resolver: HashSuiteResolver = build_resolver(&chain, protocol_version, schedule)?;
    let expected_context: PublicationContext =
        build_expected_context(chain.clone(), protocol_version, epoch)?;
    let manifest: GenesisManifest = load_trusted_genesis_manifest(
        &manifest_path,
        &resolver,
        expected_digest,
        &expected_context,
    )?;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());

    let signing_key: SigningKey =
        load_signing_key_file(&signing_key_path).map_err(|error| error.to_string())?;
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let derived_public_key: [u8; 32] = verification_key.into();
    let paid_intent_bytes: Vec<u8> = read_bounded_file(
        &paid_intent_path,
        MAX_SIGNED_PAID_INTENT_BYTES,
        "paid intent",
    )?;

    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> =
        connect_pool(&ca_der, NonZeroU32::new(4).ok_or("zero pool size")?)?;
    let blobs: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone())?;
    let (context, generation) = claim_fresh_writer_fence(&pool, &namespace, timeout_seconds)?;
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    let fee_policy: PaidFeePolicy = require_committed_genesis_fee_policy(
        &store,
        &context,
        domain,
        &expected_context,
        expected_digest,
        &manifest,
    )?;

    // DR-0130's own committed validator set is the consensus authority
    // `FastPathCertifier` (inside `fast_path::prepare`) actually certifies
    // against. This independent pre-check is defense in depth: it fails
    // closed, before ever calling into the signing pipeline, on a local key
    // that does not match this operator's own committed registration.
    let validator_set_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&expected_context)?;
    let observed = store
        .get_versioned_durable(&context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;
    require_registered_signer(&record, validator, &derived_public_key)?;

    let engine = execution::LocalWasmExecutionEngine::new();
    let signer: FileEd25519Signer = FileEd25519Signer {
        validator_id: validator,
        signing_key,
    };
    let vote: FastVote = fast_path::prepare(
        &store,
        &blobs,
        &context,
        domain,
        &resolver,
        &[],
        &expected_context,
        &base_policy,
        &fee_policy,
        &engine,
        &signer,
        &paid_intent_bytes,
        created_checkpoint,
    )?;
    reconcile_writer_fence(&pool, &namespace, &context)?;

    let vote_bytes: Vec<u8> = encode_fast_vote(&vote)?;
    write_output_file(&vote_output, &vote_bytes)?;
    println!(
        "complete=true chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_generation={} tx_hash={} execution_effects_hash={} locked_objects_digest={} vote_output={}",
        protocol_version.get(),
        epoch.get(),
        generation.get(),
        to_hex(&vote.tx_hash.bytes()),
        to_hex(&vote.execution_effects_hash.bytes()),
        to_hex(&vote.locked_objects_digest.bytes()),
        vote_output.display(),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// assemble-certificate
// ---------------------------------------------------------------------

const ASSEMBLE_CERTIFICATE_VALUE_FLAGS: &[&str] = &[
    "--validator-set-source",
    "--tls-root-der",
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--vote",
    "--certificate-output",
    "--timeout-seconds",
];
const ASSEMBLE_CERTIFICATE_BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];

enum ValidatorSetSource {
    GenesisManifest,
    Committed,
}

fn parse_validator_set_source(value: &str) -> Result<ValidatorSetSource, String> {
    match value {
        "genesis-manifest" => Ok(ValidatorSetSource::GenesisManifest),
        "committed" => Ok(ValidatorSetSource::Committed),
        _ => Err("--validator-set-source must be genesis-manifest or committed".into()),
    }
}

fn run_assemble_certificate(
    tokens: impl IntoIterator<Item = OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        tokens,
        ASSEMBLE_CERTIFICATE_VALUE_FLAGS,
        ASSEMBLE_CERTIFICATE_BOOL_FLAGS,
    )?;
    let source: ValidatorSetSource =
        parse_validator_set_source(&flags.one("--validator-set-source")?)?;
    let chain: ChainId = parse_chain(flags.one("--chain-id")?)?;
    let protocol_version: ProtocolVersion =
        parse_protocol_version(&flags.one("--protocol-version")?)?;
    let epoch: Epoch = parse_epoch(&flags.one("--epoch")?)?;
    let schedule: Vec<HashSuiteSchedule> = parse_schedule(&flags.many("--suite"))?;
    let vote_paths: Vec<String> = flags.many("--vote");
    if vote_paths.is_empty() {
        return Err("at least one --vote is required".into());
    }
    if vote_paths.len() > MAX_VOTE_INPUTS {
        return Err(format!("too many --vote inputs (maximum {MAX_VOTE_INPUTS})").into());
    }
    let certificate_output: PathBuf = PathBuf::from(flags.one("--certificate-output")?);
    let resolver: HashSuiteResolver = build_resolver(&chain, protocol_version, schedule)?;
    let expected_context: PublicationContext =
        build_expected_context(chain.clone(), protocol_version, epoch)?;

    let validator_set: ValidatorSet = match source {
        ValidatorSetSource::GenesisManifest => {
            let manifest_path: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
            let expected_digest: [u8; 32] = parse_hex_32(
                &flags.one("--expected-genesis-digest")?,
                "--expected-genesis-digest",
            )?;
            flags.finish()?;
            let manifest: GenesisManifest = load_trusted_genesis_manifest(
                &manifest_path,
                &resolver,
                expected_digest,
                &expected_context,
            )?;
            validator_set_from_record(&manifest.validator_set, &expected_context)?
        }
        ValidatorSetSource::Committed => {
            let confirmed: bool = flags.bool("--confirm-offline-fence-advance");
            let ca_der: PathBuf = PathBuf::from(flags.one("--tls-root-der")?);
            let validator: ValidatorId = parse_validator(&flags.one("--validator-id")?)?;
            let domain: AtomicityDomainId = parse_domain(&flags.one("--domain")?)?;
            let timeout_seconds: u64 = parse_u64_bounded(
                &flags
                    .optional_one("--timeout-seconds")?
                    .unwrap_or_else(|| "60".to_string()),
                "--timeout-seconds",
                1,
                3600,
            )?;
            flags.finish()?;
            if !confirmed {
                return Err(
                    "requires --confirm-offline-fence-advance: committed-set assembly advances the namespace's writer fence"
                        .into(),
                );
            }
            let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
            let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> =
                connect_pool(&ca_der, NonZeroU32::new(2).ok_or("zero pool size")?)?;
            let (context, _generation) =
                claim_fresh_writer_fence(&pool, &namespace, timeout_seconds)?;
            let policy: PostgresTransactionPolicy =
                PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
            let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
                PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
            let validator_set_key: Vec<u8> =
                local_instance_state::fastpath_validator_set_key(&expected_context)?;
            let observed = store
                .get_versioned_durable(&context, domain, &validator_set_key)
                .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
            let record_bytes: &[u8] = observed
                .value()
                .ok_or("no committed fast-path validator set for the expected genesis context")?;
            let record: FastPathValidatorSetRecord =
                decode_fastpath_validator_set_record(record_bytes)?;
            let validator_set: ValidatorSet =
                validator_set_from_record(&record, &expected_context)?;
            reconcile_writer_fence(&pool, &namespace, &context)?;
            validator_set
        }
    };
    let certifier: FastPathCertifier =
        FastPathCertifier::new(chain.clone(), protocol_version, epoch, validator_set)?;

    let mut votes: Vec<FastVote> = Vec::with_capacity(vote_paths.len());
    for vote_path in &vote_paths {
        let bytes: Vec<u8> = read_bounded_file(Path::new(vote_path), MAX_VOTE_FILE_BYTES, "vote")?;
        votes.push(decode_fast_vote(&bytes)?);
    }
    // The certified target is taken from the first supplied vote; any other
    // vote whose header disagrees is excluded by `try_form_certificate`'s
    // own documented policy rather than causing this call to fail, exactly
    // like every other caller of that library function.
    let target: &FastVote = &votes[0];
    let (tx_hash, execution_effects_hash, locked_objects_digest) = (
        target.tx_hash,
        target.execution_effects_hash,
        target.locked_objects_digest,
    );

    let certificate: FastCertificate = certifier
        .try_form_certificate(
            tx_hash,
            execution_effects_hash,
            locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )?
        .ok_or("insufficient quorum: no certificate formed, nothing written")?;
    let certificate_bytes: Vec<u8> = encode_fast_certificate(&certificate)?;
    if certificate_bytes.len() > MAX_CERTIFICATE_FILE_BYTES {
        return Err("assembled certificate exceeds the bounded output size".into());
    }
    write_output_file(&certificate_output, &certificate_bytes)?;
    println!(
        "complete=true chain_id={chain} protocol_version={} epoch={} tx_hash={} execution_effects_hash={} locked_objects_digest={} votes_supplied={} votes_in_certificate={} certificate_output={}",
        protocol_version.get(),
        epoch.get(),
        to_hex(&tx_hash.bytes()),
        to_hex(&execution_effects_hash.bytes()),
        to_hex(&locked_objects_digest.bytes()),
        votes.len(),
        certificate.votes.len(),
        certificate_output.display(),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// apply-certificate
// ---------------------------------------------------------------------

const APPLY_CERTIFICATE_VALUE_FLAGS: &[&str] = &[
    "--tls-root-der",
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--paid-intent",
    "--certificate",
    "--response-output",
    "--created-checkpoint",
    "--timeout-seconds",
];
const APPLY_CERTIFICATE_BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];

fn run_apply_certificate(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        tokens,
        APPLY_CERTIFICATE_VALUE_FLAGS,
        APPLY_CERTIFICATE_BOOL_FLAGS,
    )?;
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
    let paid_intent_path: PathBuf = PathBuf::from(flags.one("--paid-intent")?);
    let certificate_path: PathBuf = PathBuf::from(flags.one("--certificate")?);
    let response_output: Option<PathBuf> =
        flags.optional_one("--response-output")?.map(PathBuf::from);
    let recovery_created_checkpoint: Option<u64> = flags
        .optional_one("--created-checkpoint")?
        .map(|value| parse_u64_bounded(&value, "--created-checkpoint", 0, u64::MAX))
        .transpose()?;
    let timeout_seconds: u64 = parse_u64_bounded(
        &flags.one("--timeout-seconds")?,
        "--timeout-seconds",
        1,
        3600,
    )?;
    flags.finish()?;
    if !confirmed {
        return Err(
            "requires --confirm-offline-fence-advance: stop the validator first; this command advances its writer fence and the validator must restart"
                .into(),
        );
    }

    let resolver: HashSuiteResolver = build_resolver(&chain, protocol_version, schedule)?;
    let expected_context: PublicationContext =
        build_expected_context(chain.clone(), protocol_version, epoch)?;
    let manifest: GenesisManifest = load_trusted_genesis_manifest(
        &manifest_path,
        &resolver,
        expected_digest,
        &expected_context,
    )?;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(expected_context.clone());

    let paid_intent_bytes: Vec<u8> = read_bounded_file(
        &paid_intent_path,
        MAX_SIGNED_PAID_INTENT_BYTES,
        "paid intent",
    )?;
    let certificate_bytes: Vec<u8> =
        read_bounded_file(&certificate_path, MAX_CERTIFICATE_FILE_BYTES, "certificate")?;
    // Strict codec round-trip before any durable work: catches a truncated
    // or malformed certificate file with a clear error up front.
    let _: FastCertificate = decode_fast_certificate(&certificate_bytes)?;

    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain)?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> =
        connect_pool(&ca_der, NonZeroU32::new(4).ok_or("zero pool size")?)?;
    let blobs: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone())?;
    let (context, generation) = claim_fresh_writer_fence(&pool, &namespace, timeout_seconds)?;
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    let fee_policy: PaidFeePolicy = require_committed_genesis_fee_policy(
        &store,
        &context,
        domain,
        &expected_context,
        expected_digest,
        &manifest,
    )?;
    let engine = execution::LocalWasmExecutionEngine::new();

    let output = if let Some(checkpoint) = recovery_created_checkpoint {
        fast_path::apply_with_recovery(
            &store,
            &blobs,
            &context,
            domain,
            &resolver,
            &[],
            &expected_context,
            &base_policy,
            &fee_policy,
            &engine,
            &paid_intent_bytes,
            &certificate_bytes,
            checkpoint,
        )?
    } else {
        fast_path::apply(
            &store,
            &blobs,
            &context,
            domain,
            &resolver,
            &[],
            &expected_context,
            &base_policy,
            &fee_policy,
            &engine,
            &paid_intent_bytes,
            &certificate_bytes,
        )?
    };
    reconcile_writer_fence(&pool, &namespace, &context)?;

    if let Some(path) = response_output.as_deref() {
        if output.responses().len() != 1 {
            return Err("expected exactly one canonical response from apply-certificate".into());
        }
        let bytes: Vec<u8> = output.responses()[0].encode()?;
        write_output_file(path, &bytes)?;
    }

    println!(
        "complete=true chain_id={chain} validator_id={validator} domain={domain} protocol_version={} epoch={} writer_generation={} responses={} outbound_messages={}",
        protocol_version.get(),
        epoch.get(),
        generation.get(),
        output.responses().len(),
        output.outbound_messages().len(),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let _binary: Option<OsString> = args.next();
    let subcommand: Option<OsString> = args.next();
    match subcommand.as_deref().and_then(|value| value.to_str()) {
        Some("namespace-init") => run_namespace_init(args),
        Some("install-genesis") => run_install_genesis(args),
        Some("prepare-vote") => run_prepare_vote(args),
        Some("assemble-certificate") => run_assemble_certificate(args),
        Some("apply-certificate") => run_apply_certificate(args),
        _ => Err(
            "usage: fastvote_pg <namespace-init|install-genesis|prepare-vote|assemble-certificate|apply-certificate> [flags]"
                .into(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fastvote_pg failed (no complete result): {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TempFile(PathBuf);

    impl TempFile {
        fn new(contents: &[u8]) -> Self {
            let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
            let path: PathBuf = std::env::temp_dir().join(format!(
                "sunrise-edge-operator-fastvote-pg-test-{}-{sequence}",
                std::process::id()
            ));
            fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn with_mode(contents: &[u8], mode: u32) -> Self {
            let file: Self = Self::new(contents);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file.0, fs::Permissions::from_mode(mode)).unwrap();
            }
            file
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ignored = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn flag_set_rejects_unknown_flags_and_duplicates() {
        let tokens: Vec<OsString> = vec![OsString::from("--unknown"), OsString::from("value")];
        assert!(FlagSet::parse(tokens, &["--known"], &[]).is_err());

        let tokens: Vec<OsString> = vec![
            OsString::from("--known"),
            OsString::from("a"),
            OsString::from("--known"),
            OsString::from("b"),
        ];
        let mut flags: FlagSet = FlagSet::parse(tokens, &["--known"], &[]).unwrap();
        assert!(flags.one("--known").is_err());

        let tokens: Vec<OsString> = vec![OsString::from("--flag"), OsString::from("--flag")];
        assert!(FlagSet::parse(tokens, &[], &["--flag"]).is_err());
    }

    #[test]
    fn apply_recovery_checkpoint_is_optional_and_duplicates_are_rejected() {
        let mut legacy: FlagSet = FlagSet::parse(
            Vec::<OsString>::new(),
            APPLY_CERTIFICATE_VALUE_FLAGS,
            APPLY_CERTIFICATE_BOOL_FLAGS,
        )
        .unwrap();
        assert_eq!(legacy.optional_one("--created-checkpoint").unwrap(), None);
        for checkpoint in ["0", "777", "18446744073709551615"] {
            let mut flags: FlagSet = FlagSet::parse(
                [
                    OsString::from("--created-checkpoint"),
                    OsString::from(checkpoint),
                ],
                APPLY_CERTIFICATE_VALUE_FLAGS,
                APPLY_CERTIFICATE_BOOL_FLAGS,
            )
            .unwrap();
            let value: String = flags.optional_one("--created-checkpoint").unwrap().unwrap();
            assert_eq!(
                parse_u64_bounded(&value, "--created-checkpoint", 0, u64::MAX).unwrap(),
                checkpoint.parse::<u64>().unwrap()
            );
        }
        let mut duplicates: FlagSet = FlagSet::parse(
            ["--created-checkpoint", "7", "--created-checkpoint", "8"].map(OsString::from),
            APPLY_CERTIFICATE_VALUE_FLAGS,
            APPLY_CERTIFICATE_BOOL_FLAGS,
        )
        .unwrap();
        assert!(duplicates.optional_one("--created-checkpoint").is_err());
        assert!(parse_u64_bounded("invalid", "--created-checkpoint", 0, u64::MAX).is_err());
    }

    #[test]
    fn flag_set_many_preserves_order_and_bool_defaults_false() {
        let tokens: Vec<OsString> = vec![
            OsString::from("--vote"),
            OsString::from("a"),
            OsString::from("--vote"),
            OsString::from("b"),
        ];
        let mut flags: FlagSet = FlagSet::parse(tokens, &["--vote"], &["--confirm"]).unwrap();
        assert_eq!(flags.many("--vote"), vec!["a".to_string(), "b".to_string()]);
        assert!(!flags.bool("--confirm"));
    }

    #[test]
    fn flag_set_finish_rejects_an_unconsumed_value_or_bool_flag() {
        let tokens: Vec<OsString> = vec![OsString::from("--unused"), OsString::from("value")];
        let flags: FlagSet = FlagSet::parse(tokens, &["--unused"], &[]).unwrap();
        assert!(flags.finish().is_err());

        let tokens: Vec<OsString> = vec![OsString::from("--flag")];
        let flags: FlagSet = FlagSet::parse(tokens, &[], &["--flag"]).unwrap();
        assert!(flags.finish().is_err());

        let flags: FlagSet =
            FlagSet::parse(Vec::<OsString>::new(), &["--unused"], &["--flag"]).unwrap();
        assert!(flags.finish().is_ok());
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length_and_non_hex() {
        assert!(parse_hex_32("11".repeat(31).as_str(), "field").is_err());
        assert!(parse_hex_32(&"zz".repeat(32), "field").is_err());
        assert!(parse_hex_32(&"11".repeat(32), "field").is_ok());
    }

    #[test]
    fn parse_protocol_version_rejects_zero() {
        assert!(parse_protocol_version("0").is_err());
        assert!(parse_protocol_version("1").is_ok());
    }

    #[test]
    fn parse_suite_requires_exactly_eight_fields_and_nonzero_id() {
        assert!(parse_suite("0:1:1:1:1:1:1:1").is_ok());
        assert!(parse_suite("0:0:1:1:1:1:1:1").is_err());
        assert!(parse_suite("0:1:1:1:1:1:1").is_err());
    }

    #[test]
    fn parse_schedule_requires_at_least_one_suite() {
        assert!(parse_schedule(&[]).is_err());
        assert!(parse_schedule(&["0:1:1:1:1:1:1:1".to_string()]).is_ok());
    }

    #[test]
    fn require_tls_tcp_host_rejects_non_tcp_and_forces_require() {
        let mut missing: Config = Config::from_str("user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut missing).is_err());
        let mut unix_socket: Config = Config::from_str("host=/tmp user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut unix_socket).is_err());
        let mut multiple: Config = Config::from_str("host=a,b user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut multiple).is_err());
        let mut disabled: Config =
            Config::from_str("host=localhost user=test dbname=test sslmode=disable").unwrap();
        require_tls_tcp_host(&mut disabled).unwrap();
        assert_eq!(disabled.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn read_bounded_file_rejects_oversized_input() {
        let file: TempFile = TempFile::new(&[0u8; 16]);
        assert!(read_bounded_file(&file.0, 15, "field").is_err());
        assert!(read_bounded_file(&file.0, 16, "field").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn load_signing_key_file_rejects_group_readable_permissions() {
        let file: TempFile = TempFile::with_mode(&[7u8; 32], 0o640);
        let error: SigningKeyFileError = load_signing_key_file(&file.0).unwrap_err();
        assert!(matches!(
            error,
            SigningKeyFileError::InsecurePermissions { .. }
        ));
    }

    #[test]
    fn load_signing_key_file_rejects_wrong_length() {
        let file: TempFile = TempFile::with_mode(&[7u8; 31], 0o600);
        let error: SigningKeyFileError = load_signing_key_file(&file.0).unwrap_err();
        assert!(matches!(
            error,
            SigningKeyFileError::WrongLength { actual: 31 }
        ));

        let file: TempFile = TempFile::with_mode(&[7u8; 33], 0o600);
        let error: SigningKeyFileError = load_signing_key_file(&file.0).unwrap_err();
        assert!(matches!(
            error,
            SigningKeyFileError::WrongLength { actual: 33 }
        ));
    }

    #[test]
    fn load_signing_key_file_accepts_a_well_formed_key() {
        let file: TempFile = TempFile::with_mode(&[7u8; 32], 0o600);
        let key: SigningKey = load_signing_key_file(&file.0).unwrap();
        assert_eq!(key, SigningKey::from([7u8; 32]));
    }

    #[cfg(unix)]
    #[test]
    fn load_signing_key_file_rejects_a_symlink() {
        use std::os::unix::fs::symlink;
        let target: TempFile = TempFile::with_mode(&[7u8; 32], 0o600);
        let link_path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-operator-fastvote-pg-test-link-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        symlink(&target.0, &link_path).unwrap();
        let error: SigningKeyFileError = load_signing_key_file(&link_path).unwrap_err();
        assert!(matches!(error, SigningKeyFileError::Symlink));
        let _ignored = fs::remove_file(&link_path);
    }

    fn signer_entry(seed: u8) -> (SigningKey, FastPathValidatorEntry) {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let verification_key: VerificationKey = VerificationKey::from(&signing_key);
        let public_key: [u8; 32] = verification_key.into();
        let id: ValidatorId = ValidatorId::new(public_key);
        (
            signing_key,
            FastPathValidatorEntry {
                id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key.to_vec(),
            },
        )
    }

    fn dummy_context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("fastvote-pg-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap()
    }

    #[test]
    fn validator_set_from_record_rejects_context_mismatch() {
        let (_, entry) = signer_entry(1);
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![entry],
        };
        let other_context: PublicationContext = PublicationContext::new(
            ChainId::new("different-chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap();
        assert!(validator_set_from_record(&record, &other_context).is_err());
        assert!(validator_set_from_record(&record, &dummy_context()).is_ok());
    }

    #[test]
    fn require_registered_signer_rejects_unknown_validator_and_key_mismatch() {
        let (_, entry) = signer_entry(1);
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![entry.clone()],
        };
        let (_, other_entry) = signer_entry(2);
        assert!(require_registered_signer(&record, other_entry.id, &[2u8; 32]).is_err());

        let wrong_key: [u8; 32] = [0x99; 32];
        assert!(require_registered_signer(&record, entry.id, &wrong_key).is_err());

        let correct_key: [u8; 32] = entry.public_key.clone().try_into().unwrap();
        assert!(require_registered_signer(&record, entry.id, &correct_key).is_ok());
    }

    #[test]
    fn registered_signer_accepts_an_id_distinct_from_its_public_key() {
        let (_, mut entry) = signer_entry(3);
        let public_key: [u8; 32] = entry.public_key.clone().try_into().unwrap();
        let distinct_id: ValidatorId = ValidatorId::new([0xa5; 32]);
        assert_ne!(distinct_id, ValidatorId::new(public_key));
        entry.id = distinct_id;
        let record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
            context: dummy_context(),
            validators: vec![entry],
        };
        assert!(require_registered_signer(&record, distinct_id, &public_key).is_ok());
    }

    #[test]
    fn offline_certificate_assembly_rejects_unused_timeout_before_file_io() {
        let tokens: Vec<OsString> = [
            "--validator-set-source",
            "genesis-manifest",
            "--chain-id",
            "fastvote-pg-test",
            "--protocol-version",
            "1",
            "--epoch",
            "0",
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--vote",
            "/nonexistent/vote.bin",
            "--certificate-output",
            "/nonexistent/certificate.bin",
            "--genesis-manifest",
            "/nonexistent/manifest.bin",
            "--expected-genesis-digest",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--timeout-seconds",
            "60",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let error: Box<dyn Error> = run_assemble_certificate(tokens).unwrap_err();
        assert!(error.to_string().contains("--timeout-seconds was supplied"));
    }

    #[test]
    fn load_trusted_genesis_manifest_rejects_a_bad_digest_before_decoding_succeeds() {
        // A truncated/garbage manifest file must fail closed at decode, not
        // at the digest comparison (there is nothing to compute a digest
        // over), proving decode happens first and no digest is silently
        // treated as matching.
        let file: TempFile = TempFile::new(b"not a canonical genesis manifest frame");
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            ChainId::new("fastvote-pg-test").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite {
                    id: HashSuiteId::new(1),
                    transaction_hash: HashAlgorithmId::Sha2_256,
                    object_digest: HashAlgorithmId::Sha2_256,
                    effects_hash: HashAlgorithmId::Sha2_256,
                    code_hash: HashAlgorithmId::Sha2_256,
                    config_hash: HashAlgorithmId::Sha2_256,
                    certificate_hash: HashAlgorithmId::Sha2_256,
                },
            }],
        )
        .unwrap();
        let error: String =
            load_trusted_genesis_manifest(&file.0, &resolver, [0u8; 32], &dummy_context())
                .unwrap_err();
        assert!(error.contains("invalid genesis manifest"));
    }

    #[test]
    fn parse_validator_set_source_rejects_unknown_value() {
        assert!(parse_validator_set_source("offline").is_err());
        assert!(parse_validator_set_source("genesis-manifest").is_ok());
        assert!(parse_validator_set_source("committed").is_ok());
    }

    #[test]
    fn to_hex_round_trips_known_bytes() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x0a]), "00ff0a");
    }
}
