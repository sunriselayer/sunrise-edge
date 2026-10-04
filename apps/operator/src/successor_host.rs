//! First-successor loopback serving host (DR-0189 Sections 8 and 12).
//!
//! Serves native_http::successor::successor_router for one activated SQLite
//! import target. Startup pins the original genesis, schedule and domain,
//! re-verifies the saved cut to recover the immutable import binding, opens
//! the exact target, claims its writer fence once and requires one fresh
//! successor resolution before listening. That startup resolution is a gate
//! only: every request resolves again through resolve_live_authority over
//! the retained artifact directories, and nothing is cached. The listener
//! binds only 127.0.0.1 or ::1; any other address is refused while parsing,
//! before any file, store or socket I/O.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{BusinessPinInputs, BusinessPins, bounded, hex, operation, private_operation},
    common::{FlagSet, load_signing_key_file, parse_hex_32},
    host_protocol_context::host_query_protocol_config,
    host_runtime::FileEd25519Signer,
    immutable_archive::ImmutableArchiveReader,
    successor_artifacts::SuccessorArtifactFiles,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use hashing::HashSuiteResolver;
use native_http::successor::{
    SuccessorAuthoritySource, SuccessorHostComposition, bind_successor_loopback,
    require_loopback_listen, successor_router,
};
use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
    NativeBlockingExecutor, NativeBlockingPolicy,
};
use node_core::business_reconstruction::{
    cut::SavedBusinessCut,
    inactive_import::{VerifiedImportPlan, verify_saved_business_import},
};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedHistoryIdentity, decode_ordered_history_identity,
};
use node_core::serving_authority::{LiveAuthority, ServingAuthorityError, resolve_live_authority};
use protocol_config::ProtocolConfig;
use protocol_types::{AtomicityDomainId, Epoch, ValidatorId};
use runtime::{
    DurableOperationContext, DurableOutboxLeaseId, StorageCorrelationId, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{
    error::Error,
    ffi::OsString,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use sunrise_edge_client::ordered_history_archive::read_regular_archive_file;

const FLAGS: &[&str] = &[
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
    "--target-state-db",
    "--target-blob-db",
    "--validator-id",
    "--signer-key-file",
    "--listen",
    "--created-checkpoint",
    "--timeout-seconds",
    "--max-concurrent",
];
const BOOL_FLAGS: &[&str] = &["--confirm-offline-fence-advance"];
const HELP: &str = "First-successor loopback host only: serve. Never activates, imports, installs genesis or signs a readiness, Freeze, DrainSet or Seal control.\nRequire the same original pins as successor_activation (--chain-id --protocol-version --epoch --domain --suite --genesis-manifest --expected-genesis-digest --ordered-history-dir --cut-dir --manifest-history-dir --certificate-dir --target-state-db --target-blob-db --validator-id --signer-key-file) plus --listen 127.0.0.1:port or [::1]:port, --created-checkpoint and --confirm-offline-fence-advance (this host claims the target writer fence once and holds it).\nEvery request re-verifies the complete source-free evidence and the installed Serving record before any signing, exposure, read or commit. Optional --timeout-seconds 1..3600 (30), --max-concurrent 1..256 (16).";

/// Correlation identities unique within the one writer generation this
/// process claimed; a restart claims a new generation.
///
/// Intentionally distinct from host_runtime's shared SequentialIdentitySource:
/// that type reserves sequence `0` as a permanent exhaustion sentinel, while
/// this type has no sentinel and exhausts only at the natural `u64::MAX`
/// overflow boundary. That is a real behavioral difference, not incidental
/// duplication, so this identity source is deliberately left unshared.
struct GenerationIdentities {
    generation: WriterFenceGeneration,
    sequence: AtomicU64,
}

impl IndexedOutboxIdentitySource for GenerationIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let sequence: u64 = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current: u64| {
                current.checked_add(1)
            })
            .map_err(|_| IndexedOutboxIdentitySourceError::Exhausted)?;
        let mut lease: [u8; 32] = [0; 32];
        lease[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        lease[8..16].copy_from_slice(&sequence.to_be_bytes());
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&self.generation.get().to_be_bytes());
        correlation[8..].copy_from_slice(&sequence.to_be_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease)
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?,
            StorageCorrelationId::new(correlation)
                .ok_or(IndexedOutboxIdentitySourceError::Unavailable)?,
        ))
    }
}

type ArtifactDirectories = (
    ImmutableArchiveReader,
    ImmutableArchiveReader,
    ImmutableArchiveReader,
);

/// Owns the original pins, the through-h manifest identity claim, the held
/// artifact directories and the local signer public key. It stores no
/// verified evidence or decision: each call reruns resolve_live_authority.
struct HostAuthority {
    pins: BusinessPins,
    manifest_identity: OrderedHistoryIdentity,
    directories: Mutex<Option<ArtifactDirectories>>,
    signer_public_key: [u8; 32],
}

impl SuccessorAuthoritySource<SqliteImportTarget> for HostAuthority {
    fn genesis_root(&self) -> &VerifiedGenesisRoot {
        self.pins.root()
    }

    fn resolve<'inv>(
        &self,
        store: &'inv SqliteImportTarget,
        context: &'inv DurableOperationContext,
    ) -> Result<LiveAuthority<'inv>, ServingAuthorityError> {
        let unavailable =
            |_| ServingAuthorityError::Refused("private reconstruction context unavailable");
        let artifact_operation: DurableOperationContext =
            private_operation().map_err(unavailable)?;
        let plan_operation: DurableOperationContext = private_operation().map_err(unavailable)?;
        // One held directory set: resolutions over it are serialized, and a
        // panic mid-resolution leaves the host refusing, never guessing.
        let mut held = self.directories.lock().map_err(|_| {
            ServingAuthorityError::Refused("successor artifact directories poisoned")
        })?;
        let (cut, history, certificate): ArtifactDirectories = held.take().ok_or(
            ServingAuthorityError::Refused("successor artifact directories unavailable"),
        )?;
        let mut artifacts: SuccessorArtifactFiles<'_> = SuccessorArtifactFiles::new(
            self.pins.plan(artifact_operation),
            cut,
            history,
            certificate,
        );
        let resolved: Result<LiveAuthority<'inv>, ServingAuthorityError> = resolve_live_authority(
            store,
            context,
            self.pins.domain,
            self.pins.plan(plan_operation),
            &self.manifest_identity,
            &mut artifacts,
            self.signer_public_key,
        );
        *held = Some(artifacts.into_directories());
        resolved
    }
}

fn absolute(path: PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Runs the same pinned loopback host as the compiled binary.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() || values.remove(0) != "serve" {
        return Err(HELP.into());
    }
    let mut flags: FlagSet = FlagSet::parse(values, FLAGS, BOOL_FLAGS)?;
    let confirmed: bool = flags.bool("--confirm-offline-fence-advance");
    // Loopback is decided first, before any other flag can cause I/O.
    let listen: SocketAddr = require_loopback_listen(&flags.one("--listen")?)?;
    if !confirmed {
        return Err("requires --confirm-offline-fence-advance: stop every other writer of this target first; this host claims its writer fence once and holds it while serving".into());
    }
    let inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let manifest_history_directory: PathBuf = flags.one("--manifest-history-dir")?.into();
    let certificate_directory: PathBuf = flags.one("--certificate-dir")?.into();
    let state_path: PathBuf = flags.one("--target-state-db")?.into();
    let blob_path: PathBuf = flags.one("--target-blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let key_path: PathBuf = flags.one("--signer-key-file")?.into();
    let created_checkpoint: u64 = bounded(&flags.one("--created-checkpoint")?, 0, u64::MAX)?;
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "30".into()),
        1,
        3600,
    )?;
    let max_concurrent: u64 = bounded(
        &flags
            .optional_one("--max-concurrent")?
            .unwrap_or_else(|| "16".into()),
        1,
        256,
    )?;
    flags.finish()?;
    if state_path == blob_path {
        return Err("target state and blob database paths must be distinct".into());
    }
    serve(SuccessorHostInputs {
        listen,
        inputs,
        cut_directory,
        manifest_history_directory,
        certificate_directory,
        state_path,
        blob_path,
        validator,
        key_path: absolute(key_path)?,
        created_checkpoint,
        timeout,
        max_concurrent: usize::try_from(max_concurrent)?,
    })
}

struct SuccessorHostInputs {
    listen: SocketAddr,
    inputs: BusinessPinInputs,
    cut_directory: PathBuf,
    manifest_history_directory: PathBuf,
    certificate_directory: PathBuf,
    state_path: PathBuf,
    blob_path: PathBuf,
    validator: ValidatorId,
    key_path: PathBuf,
    created_checkpoint: u64,
    timeout: u64,
    max_concurrent: usize,
}

fn serve(host: SuccessorHostInputs) -> Result<(), Box<dyn Error>> {
    let cut_archive: ImmutableArchiveReader = ImmutableArchiveReader::open(&host.cut_directory)?;
    let manifest_history: ImmutableArchiveReader =
        ImmutableArchiveReader::open(&host.manifest_history_directory)?;
    let certificate_archive: ImmutableArchiveReader =
        ImmutableArchiveReader::open(&host.certificate_directory)?;
    for archive in [&cut_archive, &manifest_history, &certificate_archive] {
        for path in [&host.state_path, &host.blob_path] {
            archive.require_output_outside(path)?;
        }
    }
    let pins: BusinessPins = host.inputs.load()?;
    let manifest_identity_bytes: Vec<u8> = read_regular_archive_file(
        manifest_history.root(),
        Path::new("identity.bin"),
        MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
    )?;
    // Untrusted transport claim; every resolution re-derives and checks it.
    let manifest_identity: OrderedHistoryIdentity =
        decode_ordered_history_identity(&manifest_identity_bytes)?;
    // The saved cut is re-verified only to recover the immutable binding the
    // target must match when opened; it grants no authority.
    let saved: SavedBusinessCut =
        read_business_cut_archive(&pins.plan(private_operation()?), &cut_archive)?;
    let verified: VerifiedImportPlan =
        verify_saved_business_import(pins.plan(private_operation()?), &saved).map_err(|error| {
            format!("successor host saved-cut reconstruction failed: {error:?}")
        })?;

    let signing_key: SigningKey = load_signing_key_file(&host.key_path)?;
    let signer_public_key: [u8; 32] = VerificationKey::from(&signing_key).into();
    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), host.validator, pins.domain);
    let target: SqliteImportTarget =
        SqliteImportTarget::open_existing(&host.state_path, namespace, verified.binding())?;
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing_writable(&host.blob_path)?;
    let previous: WriterFenceGeneration = target.writer_fence()?;
    let generation: WriterFenceGeneration = previous
        .checked_next()
        .ok_or("target writer fence exhausted")?;
    target.advance_writer_fence(previous, generation)?;

    let resolver: HashSuiteResolver = pins.resolver().clone();
    let domain: AtomicityDomainId = pins.domain;
    let validator: ValidatorId = host.validator;
    let genesis_digest: String = hex(&pins.root().digest().bytes());
    let authority: Arc<HostAuthority> = Arc::new(HostAuthority {
        pins,
        manifest_identity,
        directories: Mutex::new(Some((cut_archive, manifest_history, certificate_archive))),
        signer_public_key,
    });
    let target: Arc<SqliteImportTarget> = Arc::new(target);
    // Startup gate under the claimed generation, not a cached decision.
    let startup: DurableOperationContext = operation(generation, host.timeout, [0x5E; 16])?;
    // The verified e+1 successor context from the genuine resolution this
    // startup gate already performs, never the original pins.context
    // (which is the predecessor genesis publication context, not the
    // epoch this host actually serves).
    let serving_epoch: Epoch = match authority.resolve(target.as_ref(), &startup)? {
        LiveAuthority::Successor(warrant) => warrant.policy_inputs().context().epoch(),
        LiveAuthority::OriginalGenesis => {
            return Err("target is an ordinary original namespace; successor_host serves only an activated successor".into());
        }
    };

    // Advertised over the read-only query route only; never authority. See
    // host_protocol_context for why this must come from the resolver this
    // host actually trusts, not a genesis default.
    let protocol_config: ProtocolConfig =
        host_query_protocol_config(&resolver, domain, serving_epoch)
            .map_err(|error| format!("successor host query protocol configuration: {error}"))?;
    let composition: SuccessorHostComposition<SqliteImportTarget> = SuccessorHostComposition {
        store: target,
        blobs: Arc::new(blobs),
        authority,
        signer: Arc::new(FileEd25519Signer::new(validator, signing_key)),
        clock: Arc::new(SystemClock),
        identities: Arc::new(GenerationIdentities {
            generation,
            sequence: AtomicU64::new(1),
        }),
        resolver,
        history: Vec::new(),
        engine: Arc::new(execution::LocalWasmExecutionEngine::new()),
        protocol_config,
        writer_fence: generation,
        operation_timeout: Duration::from_secs(host.timeout),
        created_checkpoint: host.created_checkpoint,
        blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
            NonZeroUsize::new(host.max_concurrent).ok_or("zero --max-concurrent")?,
        )),
    };
    let router = successor_router(composition)?;
    let listen: SocketAddr = host.listen;
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener: tokio::net::TcpListener = bind_successor_loopback(listen).await?;
        let bound: SocketAddr = listener.local_addr()?;
        // Printed only after the bind, with the actual port, and flushed so
        // a supervising harness can parse it before dialing.
        println!(
            "complete=true mode=successor-serving domain={domain} validator_id={} writer_generation={} listen={bound} genesis_digest={genesis_digest}",
            validator,
            generation.get(),
        );
        std::io::Write::flush(&mut std::io::stdout())?;
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

    fn arguments(listen: &str, confirm: bool) -> Vec<OsString> {
        let mut values: Vec<String> = vec!["serve".into()];
        let missing: &str = "/nonexistent/successor-host-test";
        for (flag, value) in [
            ("--chain-id", "successor-host-test"),
            ("--protocol-version", "1"),
            ("--epoch", "0"),
            ("--domain", &"11".repeat(32)),
            ("--suite", "0:1:1:1:1:1:1:1"),
            ("--genesis-manifest", missing),
            ("--expected-genesis-digest", &"22".repeat(32)),
            ("--ordered-history-dir", missing),
            ("--cut-dir", missing),
            ("--manifest-history-dir", missing),
            ("--certificate-dir", missing),
            ("--target-state-db", "/nonexistent/state.db"),
            ("--target-blob-db", "/nonexistent/blob.db"),
            ("--validator-id", &"33".repeat(32)),
            ("--signer-key-file", missing),
            ("--listen", listen),
            ("--created-checkpoint", "1"),
        ] {
            values.push(flag.into());
            values.push(value.into());
        }
        if confirm {
            values.push("--confirm-offline-fence-advance".into());
        }
        values.into_iter().map(OsString::from).collect()
    }

    #[test]
    fn parser_refuses_modes_and_missing_inputs_without_io() {
        assert!(run([OsString::from("--help")]).is_ok());
        assert!(run([]).is_err());
        for mode in ["activate", "force", "serve"] {
            assert!(run([OsString::from(mode)]).is_err());
        }
    }

    #[test]
    fn nonloopback_listen_is_refused_before_any_file_store_or_socket_io() {
        for listen in [
            "0.0.0.0:7000",
            "127.0.0.2:7000",
            "[::]:7000",
            "192.0.2.1:7000",
        ] {
            let error: String = run(arguments(listen, true)).unwrap_err().to_string();
            assert_eq!(
                error, "successor host listens only on 127.0.0.1 or ::1",
                "{listen}"
            );
        }
        let error: String = run(arguments("localhost:7000", true))
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "listen address must be a numeric ip:port socket address"
        );
    }

    #[test]
    fn fence_confirmation_is_required_before_any_io() {
        let error: String = run(arguments("127.0.0.1:0", false))
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("requires --confirm-offline-fence-advance"),
            "{error}"
        );
    }

    #[test]
    fn missing_artifact_directories_fail_closed_before_store_open() {
        // Loopback and confirmation pass; the first I/O is the read-only
        // artifact directory open, which refuses before any target write.
        assert!(run(arguments("[::1]:0", true)).is_err());
        assert!(!Path::new("/nonexistent/state.db").exists());
    }
}
