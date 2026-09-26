//! Offline fee-claim commands. No listener, bootstrap or epoch activation.
//!
//! A writer fence is advanced only after all inputs and fresh output handles
//! have passed local validation. Every claim artifact is exact canonical
//! signed bytes; applying that artifact never loads a key or replaces a nonce.

use crate::common::{
    FlagSet, connect_pool, load_signing_key_file, load_trusted_genesis_manifest, parse_hex_32,
    require_live_fastvote_pin,
};
use abi::call_values::{CallValue, ValueLayout, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::{GenesisManifest, decode_genesis_install_marker, genesis_marker_key};
use objects::{AccessMode, Address};
use postgres_rustls::MakeTlsConnector;
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
    error::Error,
    ffi::OsString,
    fs,
    io::{Read, Write},
    num::NonZeroU32,
    path::{Path, PathBuf},
};

type OperatorResult<T> = Result<T, Box<dyn Error>>;
type OperatorPool = Pool<PostgresConnectionManager<MakeTlsConnector>>;
type OperatorStore = PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>>;

const COMMON_FLAGS: &[&str] = &[
    "--tls-root-der",
    "--chain-id",
    "--validator-id",
    "--domain",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--timeout-seconds",
    "--out",
];
const CONFIRM: &str = "--confirm-offline-fence-advance";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandKind {
    List,
    Inspect,
    Prepare,
    Apply,
}

struct CommonArgs {
    ca: PathBuf,
    chain: ChainId,
    namespace_validator: ValidatorId,
    domain: AtomicityDomainId,
    protocol: ProtocolVersion,
    epoch: Epoch,
    schedule: Vec<HashSuiteSchedule>,
    manifest: PathBuf,
    manifest_digest: [u8; 32],
    timeout_seconds: u64,
    output: PathBuf,
}

enum OperationArgs {
    List {
        page_size: usize,
        after: Option<Vec<u8>>,
    },
    Inspect {
        escrow: [u8; 32],
    },
    Prepare {
        escrow: [u8; 32],
        claimant: ValidatorId,
        request: [u8; 32],
        recipient: [u8; 32],
        key: PathBuf,
        gas: u64,
        checkpoint: u64,
    },
    Apply {
        claim: PathBuf,
        checkpoint: u64,
    },
}

fn bounded_u64(value: &str, flag: &str, minimum: u64, maximum: u64) -> OperatorResult<u64> {
    let parsed: u64 = value.parse().map_err(|_| format!("invalid {flag}"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("{flag} outside {minimum}..={maximum}").into());
    }
    Ok(parsed)
}

fn parse_suite(value: &str) -> OperatorResult<HashSuiteSchedule> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 8 {
        return Err(
            "--suite requires epoch:suite:transaction:object:effects:code:config:certificate"
                .into(),
        );
    }
    let activation_epoch: Epoch = Epoch::new(bounded_u64(parts[0], "--suite epoch", 0, u64::MAX)?);
    let suite_id: u16 =
        u16::try_from(bounded_u64(parts[1], "--suite id", 1, u64::from(u16::MAX))?)?;
    let mut algorithms: Vec<HashAlgorithmId> = Vec::with_capacity(6);
    for part in &parts[2..] {
        let algorithm: HashAlgorithmId = match *part {
            "1" => HashAlgorithmId::Sha2_256,
            "2" => HashAlgorithmId::Sha3_256,
            _ => return Err("unsupported --suite algorithm".into()),
        };
        algorithms.push(algorithm);
    }
    Ok(HashSuiteSchedule {
        activation_epoch,
        suite: HashSuite {
            id: HashSuiteId::new(suite_id),
            transaction_hash: algorithms[0],
            object_digest: algorithms[1],
            effects_hash: algorithms[2],
            code_hash: algorithms[3],
            config_hash: algorithms[4],
            certificate_hash: algorithms[5],
        },
    })
}

fn decode_hex(value: &str, maximum: usize) -> OperatorResult<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() / 2 > maximum
        || !value.bytes().all(|byte: u8| byte.is_ascii_hexdigit())
    {
        return Err("invalid bounded hex cursor".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| {
            let text: &str = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut output: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_args(
    tokens: impl IntoIterator<Item = OsString>,
) -> OperatorResult<(CommandKind, CommonArgs, OperationArgs)> {
    let mut iterator = tokens.into_iter();
    let command: OsString = iterator
        .next()
        .ok_or("requires escrow-list, escrow-inspect, claim-prepare or claim-apply")?;
    let kind: CommandKind = match command.to_str() {
        Some("escrow-list") => CommandKind::List,
        Some("escrow-inspect") => CommandKind::Inspect,
        Some("claim-prepare") => CommandKind::Prepare,
        Some("claim-apply") => CommandKind::Apply,
        _ => return Err("unknown economics command".into()),
    };
    let mut flags: Vec<&'static str> = COMMON_FLAGS.to_vec();
    match kind {
        CommandKind::List => flags.extend(["--page-size", "--after"]),
        CommandKind::Inspect => flags.push("--escrow-request-id"),
        CommandKind::Prepare => flags.extend([
            "--escrow-request-id",
            "--claimant-validator-id",
            "--request-id",
            "--recipient",
            "--signing-key-file",
            "--gas-limit",
            "--checkpoint",
        ]),
        CommandKind::Apply => flags.extend(["--claim", "--checkpoint"]),
    }
    let mut parsed: FlagSet = FlagSet::parse(iterator, &flags, &[CONFIRM])?;
    if !parsed.bool(CONFIRM) {
        return Err("requires --confirm-offline-fence-advance: stop the validator and exclude other writers; restart afterward".into());
    }
    let schedule: Vec<HashSuiteSchedule> = parsed
        .many("--suite")
        .iter()
        .map(|value: &String| parse_suite(value))
        .collect::<OperatorResult<_>>()?;
    if schedule.is_empty() || schedule.len() > 64 {
        return Err("requires 1..=64 --suite entries".into());
    }
    let common: CommonArgs = CommonArgs {
        ca: parsed.one("--tls-root-der")?.into(),
        chain: ChainId::new(parsed.one("--chain-id")?)?,
        namespace_validator: ValidatorId::new(parse_hex_32(
            &parsed.one("--validator-id")?,
            "--validator-id",
        )?),
        domain: AtomicityDomainId::new(parse_hex_32(&parsed.one("--domain")?, "--domain")?)?,
        protocol: ProtocolVersion::new(u32::try_from(bounded_u64(
            &parsed.one("--protocol-version")?,
            "--protocol-version",
            1,
            u64::from(u32::MAX),
        )?)?),
        epoch: Epoch::new(bounded_u64(
            &parsed.one("--epoch")?,
            "--epoch",
            0,
            u64::MAX,
        )?),
        schedule,
        manifest: parsed.one("--genesis-manifest")?.into(),
        manifest_digest: parse_hex_32(
            &parsed.one("--expected-genesis-digest")?,
            "--expected-genesis-digest",
        )?,
        timeout_seconds: bounded_u64(
            &parsed.one("--timeout-seconds")?,
            "--timeout-seconds",
            1,
            3600,
        )?,
        output: parsed.one("--out")?.into(),
    };
    let operation: OperationArgs = match kind {
        CommandKind::List => OperationArgs::List {
            page_size: usize::try_from(bounded_u64(
                &parsed.one("--page-size")?,
                "--page-size",
                1,
                32,
            )?)?,
            after: parsed
                .optional_one("--after")?
                .as_deref()
                .map(|value: &str| decode_hex(value, 512))
                .transpose()?,
        },
        CommandKind::Inspect => OperationArgs::Inspect {
            escrow: parse_hex_32(&parsed.one("--escrow-request-id")?, "--escrow-request-id")?,
        },
        CommandKind::Prepare => OperationArgs::Prepare {
            escrow: parse_hex_32(&parsed.one("--escrow-request-id")?, "--escrow-request-id")?,
            claimant: ValidatorId::new(parse_hex_32(
                &parsed.one("--claimant-validator-id")?,
                "--claimant-validator-id",
            )?),
            request: parse_hex_32(&parsed.one("--request-id")?, "--request-id")?,
            recipient: parse_hex_32(&parsed.one("--recipient")?, "--recipient")?,
            key: parsed.one("--signing-key-file")?.into(),
            gas: bounded_u64(
                &parsed.one("--gas-limit")?,
                "--gas-limit",
                1,
                execution::local_execution::MAX_LOCAL_EXECUTION_GAS,
            )?,
            checkpoint: bounded_u64(&parsed.one("--checkpoint")?, "--checkpoint", 0, u64::MAX)?,
        },
        CommandKind::Apply => OperationArgs::Apply {
            claim: parsed.one("--claim")?.into(),
            checkpoint: bounded_u64(&parsed.one("--checkpoint")?, "--checkpoint", 0, u64::MAX)?,
        },
    };
    parsed.finish()?;
    match &operation {
        OperationArgs::Inspect { escrow } => {
            let _: node_core::RequestId = node_core::RequestId::new(*escrow)?;
        }
        OperationArgs::Prepare {
            escrow,
            request,
            recipient,
            ..
        } => {
            let _: node_core::RequestId = node_core::RequestId::new(*escrow)?;
            node_core::local_instance_state::reject_reserved_request_id(request)?;
            crypto::validate_ed25519_owner_address(
                recipient,
                crypto::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            )?;
        }
        _ => {}
    }
    Ok((kind, common, operation))
}

/// Retain both handles: replacing a path after preflight must not redirect
/// the artifact or its parent-directory synchronization.
struct ReservedOutput {
    file: fs::File,
    parent: fs::File,
}

impl ReservedOutput {
    fn reserve(path: &Path) -> OperatorResult<Self> {
        let parent_path: &Path = path
            .parent()
            .filter(|parent: &&Path| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent: fs::File = fs::File::open(parent_path)?;
        if !parent.metadata()?.is_dir() {
            return Err("output parent is not a directory".into());
        }
        let mut options: fs::OpenOptions = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file: fs::File = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let before: fs::Metadata = parent.metadata()?;
            let after: fs::Metadata = fs::metadata(parent_path)?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                return Err("output parent changed during reservation".into());
            }
        }
        file.sync_all()?;
        parent.sync_all()?;
        Ok(Self { file, parent })
    }

    fn persist(&mut self, bytes: &[u8]) -> OperatorResult<()> {
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }
}

struct Session {
    pool: OperatorPool,
    store: OperatorStore,
    blobs: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>>,
    namespace: PostgresNamespace,
    context: DurableOperationContext,
    resolver: HashSuiteResolver,
    expected: PublicationContext,
    domain: AtomicityDomainId,
}

fn operation_context(
    generation: WriterFenceGeneration,
    deadline: u64,
    correlation: u64,
) -> OperatorResult<DurableOperationContext> {
    let mut bytes: [u8; 16] = [0; 16];
    bytes[..8].copy_from_slice(&generation.get().to_be_bytes());
    bytes[8..].copy_from_slice(&correlation.to_be_bytes());
    Ok(DurableOperationContext::new(
        generation,
        StorageDeadline::new(deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new(bytes).ok_or("invalid correlation")?,
    ))
}

fn require_installed_manifest(
    store: &OperatorStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    digest: [u8; 32],
) -> OperatorResult<()> {
    let key: Vec<u8> = genesis_marker_key(manifest.context())?;
    let observed: runtime::VersionedStateValue = store
        .get_versioned_durable(context, domain, &key)
        .map_err(node_core::NodeCoreError::from)?;
    let marker: node_core::GenesisInstallMarker =
        decode_genesis_install_marker(observed.value().ok_or("no installed genesis marker")?)?;
    if &marker.context != manifest.context()
        || marker.manifest_digest.bytes() != digest
        || marker.genesis_authority != manifest.genesis_authority
    {
        return Err("installed genesis differs from independently pinned manifest".into());
    }
    let fee_key: Vec<u8> =
        node_core::local_instance_state::paid_fee_policy_key(manifest.context())?;
    let fee: runtime::VersionedStateValue = store
        .get_versioned_durable(context, domain, &fee_key)
        .map_err(node_core::NodeCoreError::from)?;
    if execution::paid_execution::decode_paid_fee_policy(
        fee.value().ok_or("missing installed fee policy")?,
    )? != manifest.fee_policy
    {
        return Err("installed fee policy differs from pinned genesis".into());
    }
    let economics_key: Vec<u8> = node_core::local_instance_state::fastpath_economics_policy_key(
        &manifest.economics_policy.context,
    )?;
    let economics: runtime::VersionedStateValue = store
        .get_versioned_durable(context, domain, &economics_key)
        .map_err(node_core::NodeCoreError::from)?;
    if node_core::economics::decode_fastpath_economics_policy(
        economics
            .value()
            .ok_or("missing installed economics policy")?,
    )? != manifest.economics_policy
    {
        return Err("installed economics policy differs from pinned genesis".into());
    }
    require_live_fastvote_pin(
        store,
        context,
        domain,
        manifest.context(),
        &manifest.validator_set,
        resolver,
    )?;
    Ok(())
}

impl Session {
    fn open(
        args: &CommonArgs,
        resolver: HashSuiteResolver,
        expected: PublicationContext,
        manifest: GenesisManifest,
        deadline: u64,
    ) -> OperatorResult<Self> {
        if manifest
            .validator_set
            .validators
            .iter()
            .all(|entry| entry.id != args.namespace_validator)
        {
            return Err("namespace validator absent from pinned genesis".into());
        }
        let pool: OperatorPool = connect_pool(&args.ca, NonZeroU32::new(2).ok_or("zero pool")?)?;
        let namespace: PostgresNamespace =
            PostgresNamespace::new(&args.chain, args.namespace_validator, args.domain)?;
        let policy: PostgresTransactionPolicy =
            PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retries")?)?;
        let store: OperatorStore =
            PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
        let blobs: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
            PostgresBlobStore::new(pool.clone(), namespace.clone())?;
        let mut connection = pool
            .get()
            .map_err(|_| "PostgreSQL TLS connection unavailable")?;
        let previous: WriterFenceGeneration = inspect_namespace(&mut *connection, &namespace)?
            .ok_or("namespace not installed; no bootstrap performed")?
            .writer_fence();
        let now: u64 = SystemClock.now_unix_millis()?;
        let before: DurableOperationContext = operation_context(previous, deadline, now)?;
        require_installed_manifest(
            &store,
            &before,
            args.domain,
            &resolver,
            &manifest,
            args.manifest_digest,
        )?;
        if SystemClock.now_unix_millis()? >= deadline {
            return Err("deadline expired before writer fence advance".into());
        }
        let generation: WriterFenceGeneration =
            previous.checked_next().ok_or("writer fence exhausted")?;
        advance_writer_fence(&mut connection, &namespace, previous, generation)?;
        drop(connection);
        let context: DurableOperationContext = operation_context(generation, deadline, now)?;
        require_installed_manifest(
            &store,
            &context,
            args.domain,
            &resolver,
            &manifest,
            args.manifest_digest,
        )?;
        Ok(Self {
            pool,
            store,
            blobs,
            namespace,
            context,
            resolver,
            expected,
            domain: args.domain,
        })
    }

    fn verify_finish(&self) -> OperatorResult<()> {
        let mut connection = self
            .pool
            .get()
            .map_err(|_| "PostgreSQL TLS connection unavailable after operation")?;
        let current: WriterFenceGeneration = inspect_namespace(&mut *connection, &self.namespace)?
            .ok_or("namespace disappeared")?
            .writer_fence();
        if current != self.context.writer_fence() {
            return Err(
                "writer fence changed; result incomplete, replay original claim with fresh output"
                    .into(),
            );
        }
        if SystemClock.now_unix_millis()? >= self.context.deadline().unix_millis() {
            return Err("operation deadline expired; result incomplete, replay original claim with fresh output".into());
        }
        Ok(())
    }
}

fn encode_claim_arguments(
    layout: &ValueLayout,
    split: bool,
    amount: u64,
    recipient: [u8; 32],
) -> OperatorResult<Vec<u8>> {
    let address: ValueLayout = ValueLayout::Bytes {
        min_len: 32,
        max_len: 32,
    };
    let expected: ValueLayout = ValueLayout::Tuple(if split {
        vec![ValueLayout::U64, address]
    } else {
        vec![address]
    });
    if *layout != expected {
        return Err("unsupported fee resource argument layout; requires public (u64,bytes32) split or (bytes32) transfer profile".into());
    }
    let fields: Vec<CallValue> = if split {
        vec![CallValue::U64(amount), CallValue::Bytes(recipient.to_vec())]
    } else {
        vec![CallValue::Bytes(recipient.to_vec())]
    };
    Ok(encode_call_value(layout, &CallValue::Tuple(fields))?)
}

/// Runs exactly one explicitly selected maintenance action.
pub fn run(tokens: impl IntoIterator<Item = OsString>) -> OperatorResult<()> {
    let started: u64 = SystemClock.now_unix_millis()?;
    let (_kind, args, operation): (CommandKind, CommonArgs, OperationArgs) = parse_args(tokens)?;
    let deadline: u64 = started
        .checked_add(
            args.timeout_seconds
                .checked_mul(1000)
                .ok_or("timeout overflow")?,
        )
        .ok_or("deadline overflow")?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(args.chain.clone(), args.protocol, args.schedule.clone())?;
    let expected: PublicationContext =
        PublicationContext::new(args.chain.clone(), args.protocol, args.epoch)?;
    let manifest: GenesisManifest =
        load_trusted_genesis_manifest(&args.manifest, &resolver, args.manifest_digest, &expected)?;
    let signing_key: Option<SigningKey> = match &operation {
        OperationArgs::Prepare { key, .. } => Some(load_signing_key_file(key)?),
        _ => None,
    };
    let claim_bytes: Option<Vec<u8>> = match &operation {
        OperationArgs::Apply { claim, .. } => {
            let bytes: Vec<u8> = read_synced_claim(claim)?;
            let signed: node_core::fee_claims::codec::SignedFeeClaimIntent =
                node_core::fee_claims::codec::decode_signed_fee_claim_intent(&bytes)?;
            if signed.intent.context != expected {
                return Err("saved claim context differs from independently pinned context".into());
            }
            let entry: &node_core::fast_path::records::FastPathValidatorEntry = manifest
                .validator_set
                .validators
                .iter()
                .find(|entry| entry.id == signed.intent.validator_id)
                .ok_or("saved claim validator absent from pinned historical set")?;
            if entry.signature_scheme != protocol_types::SignatureSchemeId::Ed25519 {
                return Err("unsupported historical claimant signature scheme".into());
            }
            let verifier: crypto::Ed25519Verifier =
                crypto::Ed25519Verifier::from_verifying_key_bytes(&entry.public_key)?;
            let digest: protocol_types::Digest32 =
                node_core::fee_claims::fee_claim_intent_digest(&resolver, &signed.intent)?;
            let frame: Vec<u8> =
                node_core::fee_claims::fee_claim_signing_frame(&signed.intent.context, digest)?;
            use crypto::SignatureVerifier;
            if !verifier.verify_framed(&frame, &signed.signature)? {
                return Err("saved claim signature invalid".into());
            }
            Some(bytes)
        }
        _ => None,
    };
    if let (OperationArgs::Prepare { claimant, .. }, Some(key)) = (&operation, &signing_key) {
        let public: [u8; 32] = VerificationKey::from(key).into();
        let entry: &node_core::fast_path::records::FastPathValidatorEntry = manifest
            .validator_set
            .validators
            .iter()
            .find(|entry| entry.id == *claimant)
            .ok_or("claimant absent from pinned genesis set")?;
        if entry.signature_scheme != protocol_types::SignatureSchemeId::Ed25519
            || entry.public_key.as_slice() != public
        {
            return Err("claimant key differs from pinned historical registration".into());
        }
    }
    // A create_new reservation precedes the disruptive fence and all business
    // mutations. Failure intentionally leaves an empty/partial investigation artifact.
    let mut output: ReservedOutput = ReservedOutput::reserve(&args.output)?;
    let session: Session = Session::open(&args, resolver, expected, manifest, deadline)?;
    execute(
        &session,
        &operation,
        signing_key.as_ref(),
        claim_bytes.as_deref(),
        &mut output,
    )?;
    session.verify_finish()?;
    println!(
        "complete=true backend=postgres scope=single_namespace chain_id={} validator_id={} domain={} writer_generation={} output={}",
        args.chain,
        args.namespace_validator,
        args.domain,
        session.context.writer_fence().get(),
        args.output.display()
    );
    Ok(())
}

fn read_synced_claim(path: &Path) -> OperatorResult<Vec<u8>> {
    let parent_path: &Path = path
        .parent()
        .filter(|parent: &&Path| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent: fs::File = fs::File::open(parent_path)?;
    let mut file: fs::File = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("claim artifact must be a regular file".into());
    }
    let maximum: usize = node_core::fee_claims::codec::MAX_FEE_CLAIM_INTENT_BYTES + 1024;
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(
            u64::try_from(maximum)?
                .checked_add(1)
                .ok_or("artifact bound overflow")?,
        )
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("empty or oversized signed claim artifact".into());
    }
    file.sync_all()?;
    parent.sync_all()?;
    Ok(bytes)
}

fn inspection_report(
    session: &Session,
    inspected: &node_core::fee_claims::FeeEscrowInspection,
) -> OperatorResult<String> {
    let row = &inspected.settlement;
    let digest: protocol_types::Digest32 = node_core::fee_claims::fee_claim_row_digest(
        &session.resolver,
        row.context.epoch(),
        &inspected.canonical_settlement,
    )?;
    let mut report: String = format!(
        "report=unsigned_verified_local_metadata escrow_request_id={} certificate_epoch={} generation={} row_digest={} verified_claims={} verified_payouts={} canonical_settlement={}\n",
        hex(&row.request_id),
        row.context.epoch().get(),
        row.generation,
        digest,
        inspected.verification.verified_claims,
        inspected.verification.verified_payouts,
        hex(&inspected.canonical_settlement)
    );
    if let Some(resource) = row.resource_id {
        report.push_str(&format!(
            "resource_id={resource:?} total_amount={} fee_output={:?}\n",
            row.total_amount.unwrap_or(0),
            row.fee_output
        ));
    }
    for entitlement in &inspected.claimants {
        report.push_str(&format!(
            "claimant_validator_id={} amount={} claimed={} kind={:?} authorization_key={}\n",
            entitlement.validator_id,
            entitlement.amount,
            entitlement.claimed,
            entitlement.kind,
            hex(&entitlement.authorization_key)
        ));
    }
    Ok(report)
}

fn execute(
    session: &Session,
    operation: &OperationArgs,
    key: Option<&SigningKey>,
    claim: Option<&[u8]>,
    output: &mut ReservedOutput,
) -> OperatorResult<()> {
    use node_core::fee_claims::{self, FeeClaimKind};
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(session.expected.clone());
    let engine: execution::LocalWasmExecutionEngine = execution::LocalWasmExecutionEngine::new();
    match operation {
        OperationArgs::List { page_size, after } => {
            let page: fee_claims::FeeEscrowDiscoveryPage = fee_claims::discover_fee_escrows_page(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                after.clone(),
                std::num::NonZeroUsize::new(*page_size).ok_or("zero page size")?,
            )?;
            let mut report: String = format!(
                "report=unsigned_verified_local_metadata coverage=present_keys page_rows={} continuation_cursor={}\n",
                page.escrows.len(),
                page.continuation_cursor
                    .as_deref()
                    .map(hex)
                    .unwrap_or_else(|| "none".into())
            );
            for escrow in &page.escrows {
                report.push_str(&inspection_report(session, escrow)?);
            }
            session.verify_finish()?;
            output.persist(report.as_bytes())?;
        }
        OperationArgs::Inspect { escrow } => {
            let inspected: fee_claims::FeeEscrowInspection = fee_claims::inspect_fee_escrow(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                *escrow,
            )?;
            session.verify_finish()?;
            output.persist(inspection_report(session, &inspected)?.as_bytes())?;
        }
        OperationArgs::Prepare {
            escrow,
            claimant,
            request,
            recipient,
            gas,
            checkpoint,
            ..
        } => {
            let key: &SigningKey = key.ok_or("missing claimant signing key")?;
            let public: [u8; 32] = VerificationKey::from(key).into();
            let inspected: fee_claims::FeeClaimInspection = fee_claims::inspect_fee_claim(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                *escrow,
                *claimant,
                public,
                &policy,
            )?;
            if inspected.entitlement.authorization_key != public {
                return Err("claimant key differs from certified historical registration".into());
            }
            let kind: FeeClaimKind = inspected.entitlement.kind.ok_or("share already claimed")?;
            let signed_leg: Option<Vec<u8>> = if kind == FeeClaimKind::ZeroShare {
                None
            } else {
                let execution: &fee_claims::FeeClaimExecutionView = inspected
                    .execution
                    .as_ref()
                    .ok_or("positive claim missing public execution view")?;
                if *checkpoint < execution.minimum_checkpoint {
                    return Err("--checkpoint predates the certified escrow object version".into());
                }
                let split: bool = kind == FeeClaimKind::Split;
                let entrypoint: String = if split {
                    execution.resource.split_entrypoint.clone()
                } else {
                    execution.resource.transfer_entrypoint.clone()
                };
                let layout: &ValueLayout = execution
                    .interface
                    .argument_layout(&entrypoint)
                    .ok_or("missing pinned public claim argument layout")?;
                let arguments: Vec<u8> = encode_claim_arguments(
                    layout,
                    split,
                    inspected.entitlement.amount,
                    *recipient,
                )?;
                let call: CallIntent = CallIntent {
                    context: session.expected.clone(),
                    request_id: *request,
                    sender: public,
                    nonce: execution.next_nonce,
                    code: execution.resource.code.clone(),
                    instance: execution.resource.instance.clone(),
                    entrypoint,
                    type_arguments: execution.resource.ty.args().to_vec(),
                    access: AccessManifest {
                        entries: vec![AccessEntry {
                            object_ref: inspected
                                .escrow
                                .settlement
                                .fee_output
                                .clone()
                                .ok_or("missing escrow output")?,
                            mode: AccessMode::Write,
                        }],
                    },
                    arguments,
                    gas_limit: *gas,
                };
                let intent: LocalExecutionIntent = LocalExecutionIntent {
                    mode: LocalExecutionMode::Call,
                    policy_digest: execution.policy.digest(&session.resolver)?,
                    call,
                    authorizations: Vec::new(),
                };
                let frame: Vec<u8> = local_execution_signing_frame(&session.expected, &intent)?;
                let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
                    intent,
                    signature: key.sign(&frame).into(),
                };
                Some(encode_signed_local_execution(&signed)?)
            };
            let prepared: fee_claims::PreparedFeeClaim = fee_claims::prepare_fee_claim(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                &policy,
                &engine,
                fee_claims::FeeClaimPreparationRequest {
                    escrow_request_id: *escrow,
                    request_id: *request,
                    validator_id: *claimant,
                    claimant_public_key: public,
                    recipient: Address::new(*recipient),
                    signed_leg: signed_leg.as_deref(),
                },
                *checkpoint,
            )?;
            let digest: protocol_types::Digest32 =
                fee_claims::fee_claim_intent_digest(&session.resolver, &prepared.intent)?;
            let frame: Vec<u8> =
                fee_claims::fee_claim_signing_frame(&prepared.intent.context, digest)?;
            let signed: fee_claims::codec::SignedFeeClaimIntent =
                fee_claims::codec::SignedFeeClaimIntent {
                    intent: prepared.intent,
                    signature: key.sign(&frame).into(),
                };
            let bytes: Vec<u8> = fee_claims::codec::encode_signed_fee_claim_intent(&signed)?;
            session.verify_finish()?;
            output.persist(&bytes)?;
            println!(
                "action=prepared request_id={} escrow_request_id={} claimant_validator_id={} amount={} kind={kind:?} payout={:?} reservation=false",
                hex(request),
                hex(escrow),
                claimant,
                signed.intent.share_amount,
                prepared.expected_payout
            );
        }
        OperationArgs::Apply { checkpoint, .. } => {
            let bytes: &[u8] = claim.ok_or("missing exact signed claim artifact")?;
            let signed: fee_claims::codec::SignedFeeClaimIntent =
                fee_claims::codec::decode_signed_fee_claim_intent(bytes)?;
            // The input's containing directory was synchronized by prepare. Apply
            // never re-signs or changes these bytes; core receipt reconciliation
            // returns an older claim receipt even after later row generations.
            let applied: node_core::NodeOutput = fee_claims::handle_fee_claim(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                &policy,
                &engine,
                bytes,
                *checkpoint,
            )?;
            let [response] = applied.responses() else {
                return Err("claim must return one exact receipt".into());
            };
            if response.request_id().as_bytes() != &signed.intent.request_id
                || response.status() != node_core::NodeResponseStatus::Accepted
            {
                return Err("claim receipt selector or status mismatch".into());
            }
            let payload: &[u8] = response
                .payload()
                .ok_or("missing claim receipt settlement")?;
            if fee_claims::fee_claim_row_digest(
                &session.resolver,
                signed.intent.certificate_epoch,
                payload,
            )? != signed.intent.expected_next_row_digest
            {
                return Err("claim receipt is not bound to signed next-row digest".into());
            }
            let receipt_row: node_core::fast_path::records::FastPathSettlementRecord =
                node_core::fast_path::records::decode_fastpath_settlement_record(payload)?;
            if receipt_row.request_id != signed.intent.escrow_request_id
                || receipt_row.generation
                    != signed
                        .intent
                        .expected_generation
                        .checked_add(1)
                        .ok_or("claim generation overflow")?
            {
                return Err("claim receipt escrow or generation mismatch".into());
            }
            let verified: fee_claims::FeeEscrowInspection = fee_claims::inspect_fee_escrow(
                &session.store,
                &session.blobs,
                &session.context,
                session.domain,
                &session.resolver,
                &[],
                &session.expected,
                signed.intent.escrow_request_id,
            )?;
            if !verified.claimants.iter().any(|entitlement| {
                entitlement.validator_id == signed.intent.validator_id && entitlement.claimed
            }) {
                return Err("retained history does not finalize claimant".into());
            }
            let retained_key: Vec<u8> = node_core::local_instance_state::fastpath_fee_claim_key(
                session.expected.chain_id(),
                &signed.intent.escrow_request_id,
                receipt_row.generation,
            )?;
            let retained: runtime::VersionedStateValue = session
                .store
                .get_versioned_durable(&session.context, session.domain, &retained_key)
                .map_err(node_core::NodeCoreError::from)?;
            if retained.value() != Some(bytes) {
                return Err("retained generation claim differs from saved exact bytes".into());
            }
            let receipt: node_core::ReceiptQueryResult = node_core::query_request_receipt(
                &session.store,
                &session.context,
                session.domain,
                response.request_id(),
            )?;
            let node_core::ReceiptQueryResult::Present {
                event_digest,
                record,
                ..
            } = receipt
            else {
                return Err("claim receipt missing after apply/replay".into());
            };
            if event_digest
                != session.resolver.hash_for_purpose(
                    signed.intent.context.epoch(),
                    protocol_types::HashPurpose::NodeEvent,
                    bytes,
                )?
                || record.responses() != applied.responses()
            {
                return Err(
                    "persisted receipt differs from exact signed claim or returned receipt".into(),
                );
            }
            session.verify_finish()?;
            output.persist(&response.encode()?)?;
            println!(
                "action=applied_or_replayed request_id={} escrow_request_id={} claimant_validator_id={} amount={} receipt_generation={} current_generation={} verified_claims={} verified_payouts={} payout={:?}",
                hex(&signed.intent.request_id),
                hex(&signed.intent.escrow_request_id),
                signed.intent.validator_id,
                signed.intent.share_amount,
                receipt_row.generation,
                verified.settlement.generation,
                verified.verification.verified_claims,
                verified.verification.verified_payouts,
                match &signed.intent.operation {
                    fee_claims::codec::FeeClaimOperation::Split {
                        expected_payout, ..
                    } => expected_payout.clone(),
                    fee_claims::codec::FeeClaimOperation::FinalTransfer { .. } =>
                        receipt_row.fee_output,
                    fee_claims::codec::FeeClaimOperation::ZeroShare => None,
                }
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(label: &str) -> PathBuf {
        let stamp: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("economics-{label}-{}-{stamp}", std::process::id()))
    }

    fn prepare_arguments(
        output: &Path,
        gas: &str,
        request: [u8; 32],
        recipient: [u8; 32],
    ) -> Vec<OsString> {
        let values: Vec<String> = vec![
            "claim-prepare".into(),
            CONFIRM.into(),
            "--tls-root-der".into(),
            "missing-ca".into(),
            "--chain-id".into(),
            "offline-test".into(),
            "--validator-id".into(),
            hex(&[0x11; 32]),
            "--domain".into(),
            hex(&[0x33; 32]),
            "--protocol-version".into(),
            "3".into(),
            "--epoch".into(),
            "0".into(),
            "--suite".into(),
            "0:1:1:1:1:1:1:1".into(),
            "--genesis-manifest".into(),
            "missing-manifest".into(),
            "--expected-genesis-digest".into(),
            hex(&[0x44; 32]),
            "--timeout-seconds".into(),
            "60".into(),
            "--out".into(),
            output.to_str().unwrap().into(),
            "--escrow-request-id".into(),
            hex(&[0x55; 32]),
            "--claimant-validator-id".into(),
            hex(&[0x22; 32]),
            "--request-id".into(),
            hex(&request),
            "--recipient".into(),
            hex(&recipient),
            "--signing-key-file".into(),
            "missing-key".into(),
            "--gas-limit".into(),
            gas.into(),
            "--checkpoint".into(),
            "1".into(),
        ];
        values.into_iter().map(OsString::from).collect()
    }

    #[test]
    fn namespace_and_claimant_are_separate_and_duplicate_scalars_fail() {
        let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x31; 32])).into();
        let target: PathBuf = path("parsed");
        let arguments: Vec<OsString> = prepare_arguments(&target, "500000", [0x66; 32], recipient);
        let (_, common, operation) = parse_args(arguments.clone()).unwrap();
        let OperationArgs::Prepare { claimant, .. } = operation else {
            panic!("prepare required");
        };
        assert_eq!(common.namespace_validator, ValidatorId::new([0x11; 32]));
        assert_eq!(claimant, ValidatorId::new([0x22; 32]));
        let mut duplicate: Vec<OsString> = arguments;
        duplicate.extend([
            OsString::from("--recipient"),
            OsString::from(hex(&recipient)),
        ]);
        assert!(parse_args(duplicate).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn excessive_gas_invalid_address_and_zero_request_fail_before_io_or_output() {
        let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x31; 32])).into();
        let target: PathBuf = path("invalid");
        let excessive: String = execution::local_execution::MAX_LOCAL_EXECUTION_GAS
            .checked_add(1)
            .unwrap()
            .to_string();
        for arguments in [
            prepare_arguments(&target, &excessive, [0x66; 32], recipient),
            prepare_arguments(&target, "500000", [0; 32], recipient),
            prepare_arguments(&target, "500000", [0x66; 32], [0; 32]),
        ] {
            assert!(run(arguments).is_err());
            assert!(!target.exists());
        }
    }

    #[test]
    fn existing_output_is_preserved_and_fresh_output_is_synced() {
        let target: PathBuf = path("output");
        fs::write(&target, b"existing").unwrap();
        assert!(ReservedOutput::reserve(&target).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"existing");
        fs::remove_file(&target).unwrap();
        let mut output: ReservedOutput = ReservedOutput::reserve(&target).unwrap();
        output.persist(b"canonical bytes").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"canonical bytes");
        drop(output);
        fs::remove_file(&target).unwrap();
    }

    #[test]
    fn missing_confirmation_and_unknown_command_fail_before_io() {
        assert!(
            run([OsString::from("escrow-list")])
                .unwrap_err()
                .to_string()
                .contains(CONFIRM)
        );
        assert!(run([OsString::from("claim-replay")]).is_err());
        assert!(
            parse_args([
                OsString::from("claim-apply"),
                OsString::from("--signing-key-file"),
                OsString::from("key")
            ])
            .is_err()
        );
    }

    #[test]
    fn unknown_layout_and_malformed_cursors_fail_closed() {
        assert!(
            encode_claim_arguments(
                &ValueLayout::Tuple(vec![ValueLayout::U64]),
                false,
                1,
                [7; 32]
            )
            .is_err()
        );
        assert!(decode_hex("abc", 10).is_err());
        assert!(decode_hex("zz", 10).is_err());
        assert!(decode_hex("00ff", 1).is_err());
        assert_eq!(decode_hex("00ff", 2).unwrap(), vec![0, 255]);
    }
}
