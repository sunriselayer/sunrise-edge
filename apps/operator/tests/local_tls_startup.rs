//! DR-0199/0216: actual original startup and stopped rotation through local TLS.
//!
//! Real compiled author -> secret-free inspector -> four fresh SQLite
//! preparations and preflights -> four compiled serving hosts, each behind its
//! own bounded loopback TLS terminator with an independent CA and DNS name ->
//! one separately compiled CLI certified transfer, exact replay in the same
//! boot and after reopening every host, and pin/TLS/cohort/request-ID refusals.
//! The terminator forwards exact HTTP bytes; every protocol result comes from
//! an actual host. All keys and CAs are disposable fixture material.
//! DR-0219 separately runs the same complete business oracles against direct
//! production-host termination and its actual 2 -> 3 -> 4 stopped fences.

#[path = "support/compiled_cli_process.rs"]
mod compiled_cli_process;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "support/https_relay.rs"]
mod https_relay;
#[path = "support/offline_genesis_fixture.rs"]
mod offline_genesis_fixture;

use compiled_cli_process::edge_cli_command;
use compiled_source_host_process::{ChildGuard, spawn_bounded_output, spawn_bounded_status_line};
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, FastCertificate,
    decode_availability_certificate, decode_fast_certificate, encode_availability_certificate,
    encode_fast_certificate,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::ObjectEffect;
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{
    AuthenticatedPaidIntent, PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus,
    PaidResultKind, SignedPaidIntent, authenticate_paid_intent, decode_paid_execution_result,
    decode_signed_paid_intent, encode_paid_execution_result, encode_signed_paid_intent,
    paid_intent_signing_frame, paid_invocation_digest, quote_paid_intent,
};
use fees::Amount;
use fees::reservation::{Admission, Settlement};
use https_relay::{
    FixtureCa, FixtureLeaf, HttpsRelay, PeerClose, authenticated_leaf, fixture_server_name,
};
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::{NodeDedupRecord, NodeResponseStatus};
use objects::{Address, Object, ObjectId, Owner, ProtocolCustodyPurpose, encode_object};
use offline_genesis_fixture::{Fixture, field, hex, replace, success};
use protocol_types::{AtomicityDomainId, Digest32, ValidatorId};
use public_standard_asset::coin_amount;
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, Clock,
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore, DurableOperationContext,
    DurableReadError, StateMutation, StateMutationEntry, StateReadAssertion, StorageCorrelationId,
    StorageDeadline, SystemClock, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{ErrorKind, Write},
    net::{SocketAddr, TcpListener},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::Ordering,
    time::Duration,
};
use sunrise_edge_client::{
    Client, ClientError, HttpNextNonceQueryResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    RemoteTlsHttpTransport, RequestId, TransportError, TrustedFastVoteGenesis,
    load_trusted_fastvote_genesis_with_profile,
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;
use sunrise_edge_operator::common::parse_hex_32;

const VALIDATORS: usize = 4;
const SUITE: &str = "0:1:1:1:1:1:1:1";
/// Explicitly configured logical domain shared by all four replicas.
const DOMAIN: [u8; 32] = [0x61; 32];
const OWNER_SEED: [u8; 32] = [0x56; 32];
const RECIPIENT_SEED: [u8; 32] = [0x57; 32];
const APP_COIN: [u8; 32] = [0x21; 32];
const FEE_COIN: [u8; 32] = [0x22; 32];
/// Fixture allocation of the application Coin; a transfer preserves it.
const APP_COIN_AMOUNT: u64 = 1_000_000;
const MAX_FEE: u64 = 1_000_000;
/// High bit clear: the owned causal-admission lane.
const TRANSFER_REQUEST: [u8; 32] = [0x2a; 32];
const PROCESS_DEADLINE: Duration = Duration::from_secs(60);
const CLI_DEADLINE: Duration = Duration::from_secs(90);
const INSPECTION_END: &str = "complete=true mode=inspect evidence=none";
const COMMITMENT_MISMATCH: &str =
    "genesis manifest commitment does not match the locally trusted expected digest";
const MIXED_COHORT: &str =
    "network config cannot mix loopback-plaintext and remote-TLS peers in one cohort";
const TLS_PEER_REFUSAL: &str = "transport error: TLS protocol error: invalid peer certificate: ";
const TLS_HANDSHAKE_CLOSED: &str =
    "transport error: connection closed before the TLS handshake completed";
const INSUFFICIENT_QUORUM: &str =
    "insufficient FastVote quorum: no candidate execution outcome reached quorum voting power";
const PREPARE_REFUSED: &str = "status=failed reason=unexpected HTTP status 400: fastvote-rejected";

/// Authored, inspected and prepared once; every later process reopens these
/// exact files.
struct Network {
    fixture: Fixture,
    genesis: PathBuf,
    digest: [u8; 32],
    domain: AtomicityDomainId,
    signing_keys: Vec<PathBuf>,
    owner_seed: PathBuf,
    tls_dir: PathBuf,
    artifacts_dir: PathBuf,
}

impl Network {
    fn state_db(&self, index: usize) -> PathBuf {
        self.fixture.directory.join(format!("state-{index}.sqlite"))
    }

    fn blob_db(&self, index: usize) -> PathBuf {
        self.fixture.directory.join(format!("blob-{index}.sqlite"))
    }

    fn namespace(&self, index: usize) -> SqliteNamespace {
        SqliteNamespace::new(
            self.fixture.context.chain_id().clone(),
            ValidatorId::new(self.fixture.validators[index]),
            self.domain,
        )
    }

    fn root(&self) -> VerifiedGenesisRoot {
        VerifiedGenesisRoot::verify_bytes(
            &self.fixture.resolver,
            &fs::read(&self.genesis).unwrap(),
            self.digest,
            &self.fixture.context,
        )
        .unwrap()
    }

    fn trusted(&self) -> TrustedFastVoteGenesis {
        load_trusted_fastvote_genesis_with_profile(
            &self.genesis,
            &self.fixture.resolver,
            self.digest,
            &self.fixture.context,
        )
        .unwrap()
    }

    fn genesis_object(&self, id: ObjectId) -> Object {
        self.root()
            .manifest()
            .objects
            .iter()
            .find(|entry| entry.object.id == id)
            .map(|entry| entry.object.clone())
            .expect("authored fixture object")
    }
}

fn write_private_new(path: &Path, bytes: &[u8]) {
    let mut options: fs::OpenOptions = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file: fs::File = options
        .open(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn assert_absent(path: &Path, label: &str) {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("{label}: cannot inspect {}: {error}", path.display()),
        Ok(_) => panic!("{label}: unexpected artifact {}", path.display()),
    }
}

fn assert_reserved_empty(path: &Path, label: &str) {
    let bytes: Vec<u8> = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "{label}: reserved artifact {} unreadable: {error}",
            path.display()
        )
    });
    assert!(
        bytes.is_empty(),
        "{label}: refusal wrote bytes into {}",
        path.display()
    );
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn inspect(fixture: &Fixture, genesis: &Path, digest: [u8; 32]) {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_genesis_inspect"));
    command.arg("inspect");
    for (flag, value) in [
        ("--chain-id", fixture.context.chain_id().as_str().to_owned()),
        (
            "--protocol-version",
            fixture.context.protocol_version().get().to_string(),
        ),
        ("--epoch", fixture.context.epoch().get().to_string()),
        ("--suite", SUITE.to_owned()),
        ("--expected-genesis-authority", hex(&fixture.authority)),
        ("--expected-manifest-digest", hex(&digest)),
        ("--validation-domain", hex(&[0x41; 32])),
        ("--validation-checkpoint", "10".to_owned()),
        ("--timeout-seconds", "30".to_owned()),
    ] {
        command.arg(flag).arg(value);
    }
    command.arg("--genesis-manifest").arg(genesis);
    let output: Output = spawn_bounded_output(command, PROCESS_DEADLINE);
    assert!(output.status.success(), "{}", lossy(&output.stderr));
    let summary: String = String::from_utf8(output.stdout).unwrap();
    // Multiline public diagnostics, then exactly one closing marker line.
    assert!(
        summary.ends_with(&format!("\n{INSPECTION_END}\n")),
        "{summary}"
    );
    assert_eq!(summary.matches("complete=true").count(), 1);
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for line in summary
        .lines()
        .filter(|line: &&str| *line != INSPECTION_END)
    {
        let (key, value): (&str, &str) = line.split_once('=').unwrap();
        assert!(
            values.insert(key, value).is_none(),
            "duplicate inspection field {key}"
        );
    }
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &fs::read(genesis).unwrap(),
        digest,
        &fixture.context,
    )
    .unwrap();
    assert_eq!(root.digest().bytes(), digest);
    assert_eq!(values["manifest_digest"], root.digest().to_string());
    assert_eq!(values["genesis_authority"], hex(&fixture.authority));
    assert_eq!(
        values["expected_chain_id"],
        fixture.context.chain_id().as_str()
    );
    assert_eq!(
        values["expected_protocol_version"],
        fixture.context.protocol_version().get().to_string()
    );
    assert_eq!(
        values["expected_epoch"],
        fixture.context.epoch().get().to_string()
    );
    assert_eq!(values["commitment_profile"], "causal_admission");
    assert_eq!(values["committee_member_count"], VALIDATORS.to_string());
    let committee: BTreeSet<String> = (0..VALIDATORS)
        .map(|index: usize| {
            values[format!("committee_member_{index}_public_key").as_str()].to_owned()
        })
        .collect();
    let expected: BTreeSet<String> = fixture
        .validators
        .iter()
        .map(|key: &[u8; 32]| hex(key))
        .collect();
    assert_eq!(committee, expected);
}

fn author_inspect_and_prepare() -> Network {
    let fixture: Fixture = Fixture::new();
    let line: String = success(fixture.author(&fixture.args));
    assert_eq!(field(&line, "genesis_authority="), hex(&fixture.authority));
    let digest: [u8; 32] = parse_hex_32(field(&line, "manifest_digest="), "digest").unwrap();
    let genesis: PathBuf = fixture.directory.join("genesis.bin");
    // Secret-free inspection precedes any preparation or serving host.
    inspect(&fixture, &genesis, digest);
    let domain: AtomicityDomainId = AtomicityDomainId::new(DOMAIN).unwrap();
    let mut signing_keys: Vec<PathBuf> = Vec::with_capacity(VALIDATORS);
    for (validator, public_key) in fixture.validators.iter().enumerate() {
        let pins: Vec<OsString> = fixture.root_pins(&genesis, digest, validator, domain);
        let mut prepare: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
        prepare
            .arg("prepare")
            .args(&pins)
            .args(["--created-checkpoint", "10"]);
        let prepared: String = success(spawn_bounded_output(prepare, PROCESS_DEADLINE));
        assert!(prepared.contains("mode=prepare"), "{prepared}");
        assert_eq!(field(&prepared, "writer_fence="), "1");
        let mut preflight: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
        preflight
            .arg("preflight")
            .args(&pins)
            .arg("--validator-public-key")
            .arg(hex(public_key));
        let advisory: String = success(spawn_bounded_output(preflight, PROCESS_DEADLINE));
        assert!(
            advisory.contains("complete=true mode=preflight advisory=true"),
            "{advisory}"
        );
        let seed: [u8; 32] = [0x51u8
            .checked_add(u8::try_from(validator).unwrap())
            .unwrap(); 32];
        let derived: [u8; 32] = VerificationKey::from(&SigningKey::from(seed)).into();
        assert_eq!(
            &derived, public_key,
            "each process owns its own registered key"
        );
        let key_file: PathBuf = fixture.directory.join(format!("validator-{validator}.key"));
        write_private_new(&key_file, &seed);
        signing_keys.push(key_file);
    }
    let owner: [u8; 32] = VerificationKey::from(&SigningKey::from(OWNER_SEED)).into();
    assert_eq!(owner, fixture.owner);
    let owner_seed: PathBuf = fixture.directory.join("owner.seed");
    write_private_new(&owner_seed, hex(&OWNER_SEED).as_bytes());
    let tls_dir: PathBuf = fixture.directory.join("tls");
    fs::create_dir(&tls_dir).unwrap();
    let artifacts_dir: PathBuf = fixture.directory.join("artifacts");
    fs::create_dir(&artifacts_dir).unwrap();
    Network {
        fixture,
        genesis,
        digest,
        domain,
        signing_keys,
        owner_seed,
        tls_dir,
        artifacts_dir,
    }
}

/// One actual compiled host; explicit quiet SIGINT is the stop success oracle.
/// The guard kills and reaps only if an earlier test failure unwinds.
struct Host {
    guard: ChildGuard,
    address: SocketAddr,
}

/// Direct production-host endpoint, never a relay or a fake protocol adapter.
struct DirectPeer {
    address: SocketAddr,
    ca: FixtureCa,
    leaf: FixtureLeaf,
    ca_file: PathBuf,
    cert_file: PathBuf,
    key_file: PathBuf,
}
impl TlsPeer for DirectPeer {
    fn client(&self) -> Client<RemoteTlsHttpTransport> {
        endpoint_client(self.address, &self.leaf.server_name, &self.ca.der)
    }
}
impl DirectPeer {
    fn renew(&mut self, directory: &Path, label: &str) {
        let leaf: FixtureLeaf = self.ca.issue_leaf(&self.leaf.server_name);
        assert_ne!(leaf.der, self.leaf.der);
        assert_ne!(leaf.public_key_der, self.leaf.public_key_der);
        self.cert_file = directory.join(format!("{label}.der"));
        self.key_file = directory.join(format!("{label}.key"));
        write_private_new(&self.cert_file, &leaf.der);
        write_private_new(&self.key_file, &leaf.key_pkcs8_der);
        self.leaf = leaf;
    }
    fn received(&self) -> Vec<u8> {
        let received: Vec<u8> =
            authenticated_leaf(self.address, &self.leaf.server_name, &self.ca.der);
        assert_eq!(
            received, self.leaf.der,
            "actual authenticated direct-host leaf"
        );
        received
    }
    fn context(&self, root: &Path) -> Output {
        run_cli(vec![
            "context".into(),
            "--endpoint".into(),
            self.address.to_string().into(),
            "--tls-server-name".into(),
            self.leaf.server_name.clone().into(),
            "--tls-ca-cert-der-file".into(),
            root.as_os_str().to_owned(),
        ])
    }
}
fn direct_peers(network: &Network) -> Vec<DirectPeer> {
    (0..VALIDATORS)
        .map(|index: usize| {
            let name: String = fixture_server_name();
            let ca: FixtureCa = FixtureCa::new(&format!("{name}-direct-issuer-a"));
            let leaf: FixtureLeaf = ca.issue_leaf(&name);
            let ca_file: PathBuf = network.tls_dir.join(format!("direct-{index}-ca.der"));
            let cert_file: PathBuf = network.tls_dir.join(format!("direct-{index}-leaf.der"));
            let key_file: PathBuf = network.tls_dir.join(format!("direct-{index}-key.der"));
            write_private_new(&ca_file, &ca.der);
            write_private_new(&cert_file, &leaf.der);
            write_private_new(&key_file, &leaf.key_pkcs8_der);
            DirectPeer {
                address: "127.0.0.1:0".parse().unwrap(),
                ca,
                leaf,
                ca_file,
                cert_file,
                key_file,
            }
        })
        .collect()
}
fn start_direct_hosts(network: &Network, peers: &mut [DirectPeer], generation: u64) -> Vec<Host> {
    assert_eq!(peers.len(), VALIDATORS);
    peers
        .iter_mut()
        .enumerate()
        .map(|(index, peer): (usize, &mut DirectPeer)| {
            let requested: SocketAddr = peer.address;
            let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
            command
                .args(network.fixture.root_pins(
                    &network.genesis,
                    network.digest,
                    index,
                    network.domain,
                ))
                .arg("--signing-key-file")
                .arg(&network.signing_keys[index])
                .args([
                    "--created-checkpoint",
                    "10",
                    "--timeout-seconds",
                    "30",
                    "--max-concurrent",
                    "4",
                    "--confirm-offline-fence-advance",
                    "--listen",
                ])
                .arg(requested.to_string())
                .arg("--tls-cert-der-file")
                .arg(&peer.cert_file)
                .arg("--tls-key-pkcs8-der-file")
                .arg(&peer.key_file)
                .stderr(Stdio::piped());
            let (guard, line): (ChildGuard, String) =
                spawn_bounded_status_line(command, PROCESS_DEADLINE);
            assert!(line.contains("complete=true mode=serving"), "{line}");
            assert_eq!(field(&line, "writer_generation="), generation.to_string());
            let address: SocketAddr = field(&line, "listen=").parse().unwrap();
            if requested.port() != 0 {
                assert_eq!(address, requested, "no alternate port fallback");
            }
            peer.address = address;
            Host { guard, address }
        })
        .collect()
}
fn direct_lines(network: &Network, peers: &[DirectPeer]) -> Vec<String> {
    peers
        .iter()
        .enumerate()
        .map(|(index, peer): (usize, &DirectPeer)| {
            peer_line(
                network,
                index,
                peer.address,
                &peer.leaf.server_name,
                &peer.ca_file,
            )
        })
        .collect()
}
fn direct_contexts(peers: &[DirectPeer]) -> Vec<(Vec<u8>, Vec<u8>)> {
    peers
        .iter()
        .map(|peer: &DirectPeer| {
            let sdk: Vec<u8> = peer.client().query_context().unwrap().encode().unwrap();
            let output: Output = peer.context(&peer.ca_file);
            assert!(output.status.success(), "{}", lossy(&output.stderr));
            assert!(output.stderr.is_empty() && !output.stdout.is_empty());
            (sdk, output.stdout)
        })
        .collect()
}

fn start_hosts(network: &Network, generation: u64) -> Vec<Host> {
    (0..VALIDATORS)
        .map(|validator: usize| {
            let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
            command
                .args(network.fixture.root_pins(
                    &network.genesis,
                    network.digest,
                    validator,
                    network.domain,
                ))
                .arg("--signing-key-file")
                .arg(&network.signing_keys[validator])
                .args([
                    "--listen",
                    "127.0.0.1:0",
                    "--created-checkpoint",
                    "10",
                    "--timeout-seconds",
                    "30",
                    "--max-concurrent",
                    "4",
                    "--confirm-offline-fence-advance",
                ]);
            let (guard, line): (ChildGuard, String) =
                spawn_bounded_status_line(command, PROCESS_DEADLINE);
            assert!(
                line.contains("complete=true mode=serving"),
                "validator {validator}: {line:?}"
            );
            assert_eq!(
                field(&line, "writer_generation="),
                generation.to_string(),
                "validator {validator} must claim exactly the next writer fence"
            );
            let address: SocketAddr = field(&line, "listen=").parse().unwrap();
            assert!(address.ip().is_loopback());
            Host { guard, address }
        })
        .collect()
}

/// One bounded terminator per actual host plus its independently configured
/// CA file.
struct Tls {
    relays: Vec<HttpsRelay>,
    ca_files: Vec<PathBuf>,
    cas: Vec<FixtureCa>,
    leaves: Vec<FixtureLeaf>,
}

fn start_tls(hosts: &[Host], directory: &Path) -> Tls {
    let mut relays: Vec<HttpsRelay> = Vec::with_capacity(VALIDATORS);
    let mut cas: Vec<FixtureCa> = Vec::with_capacity(VALIDATORS);
    let mut leaves: Vec<FixtureLeaf> = Vec::with_capacity(VALIDATORS);
    for host in hosts {
        let server_name: String = fixture_server_name();
        let ca: FixtureCa = FixtureCa::new(&format!("{server_name}-issuer-a"));
        let leaf: FixtureLeaf = ca.issue_leaf(&server_name);
        relays.push(HttpsRelay::bind(host.address, &leaf));
        cas.push(ca);
        leaves.push(leaf);
    }
    let ca_files: Vec<PathBuf> = relays
        .iter()
        .enumerate()
        .map(|(index, relay): (usize, &HttpsRelay)| {
            let path: PathBuf = directory.join(format!("validator-{index}-ca.der"));
            write_private_new(&path, &relay.ca_der);
            path
        })
        .collect();
    let distinct_cas: BTreeSet<Vec<u8>> = ca_files
        .iter()
        .map(|path: &PathBuf| fs::read(path).unwrap())
        .collect();
    let distinct_names: BTreeSet<&str> = relays
        .iter()
        .map(|relay: &HttpsRelay| relay.server_name.as_str())
        .collect();
    assert_eq!(distinct_cas.len(), VALIDATORS, "trust files must differ");
    assert_eq!(
        distinct_names.len(),
        VALIDATORS,
        "leaf DNS names must differ"
    );
    Tls {
        relays,
        ca_files,
        cas,
        leaves,
    }
}

fn peer_line(
    network: &Network,
    index: usize,
    endpoint: SocketAddr,
    server_name: &str,
    ca: &Path,
) -> String {
    format!(
        "{} {endpoint} {server_name} {}\n",
        hex(&network.fixture.validators[index]),
        ca.to_str().unwrap()
    )
}

fn tls_lines(network: &Network, tls: &Tls) -> Vec<String> {
    tls.relays
        .iter()
        .zip(&tls.ca_files)
        .enumerate()
        .map(|(index, (relay, ca)): (usize, (&HttpsRelay, &PathBuf))| {
            peer_line(network, index, relay.addr, &relay.server_name, ca)
        })
        .collect()
}

fn write_config(path: &Path, lines: &[String]) -> PathBuf {
    write_private_new(path, lines.concat().as_bytes());
    path.to_path_buf()
}

fn forwarded_posts(relays: &[HttpsRelay]) -> Vec<usize> {
    relays
        .iter()
        .map(|relay: &HttpsRelay| relay.counters.posts.load(Ordering::SeqCst))
        .collect()
}

fn assert_all_forwarded(before: &[usize], relays: &[HttpsRelay], label: &str) {
    assert_eq!(before.len(), VALIDATORS);
    assert_eq!(relays.len(), VALIDATORS);
    for (index, (old, new)) in before.iter().zip(forwarded_posts(relays)).enumerate() {
        assert!(
            new > *old,
            "{label}: relay {index} forwarded no POST to its actual host"
        );
    }
}

fn served_leaves(tls: &Tls) -> Vec<Vec<u8>> {
    assert_eq!(tls.relays.len(), VALIDATORS);
    assert_eq!(tls.leaves.len(), VALIDATORS);
    tls.relays
        .iter()
        .zip(&tls.leaves)
        .map(|(relay, expected): (&HttpsRelay, &FixtureLeaf)| {
            let received: Vec<u8> =
                authenticated_leaf(relay.addr, &relay.server_name, &relay.ca_der);
            assert_eq!(
                received, expected.der,
                "actual authenticated received leaf DER"
            );
            assert!(relay.counters.accepted.load(Ordering::SeqCst) > 0);
            received
        })
        .collect()
}

fn cli_context(relay: &HttpsRelay, ca: &Path) -> Output {
    run_cli(vec![
        "context".into(),
        "--endpoint".into(),
        relay.addr.to_string().into(),
        "--tls-server-name".into(),
        relay.server_name.clone().into(),
        "--tls-ca-cert-der-file".into(),
        ca.as_os_str().to_owned(),
    ])
}

/// SDK canonical context and deterministic compiled CLI context, for every peer.
fn contexts(tls: &Tls) -> Vec<(Vec<u8>, Vec<u8>)> {
    tls.relays
        .iter()
        .zip(&tls.ca_files)
        .map(|(relay, ca): (&HttpsRelay, &PathBuf)| {
            let sdk: Vec<u8> = relay_client(relay)
                .query_context()
                .unwrap()
                .encode()
                .unwrap();
            let output: Output = cli_context(relay, ca);
            assert!(
                output.status.success(),
                "compiled context: {}",
                lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
            assert!(!output.stdout.is_empty());
            (sdk, output.stdout)
        })
        .collect()
}

fn assert_context_refused(output: Output, diagnostic: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr: String = lossy(&output.stderr);
    assert!(
        stderr.starts_with("error=") && stderr.contains(diagnostic),
        "{stderr}"
    );
}

fn relay_client(relay: &HttpsRelay) -> Client<RemoteTlsHttpTransport> {
    endpoint_client(relay.addr, &relay.server_name, &relay.ca_der)
}

fn endpoint_client(address: SocketAddr, name: &str, ca: &[u8]) -> Client<RemoteTlsHttpTransport> {
    Client::new(
        RemoteTlsHttpTransport::new(
            address,
            name,
            ca,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(5),
            NonZeroUsize::new(64 * 1024).unwrap(),
            NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    )
}

/// Exact create-new destinations of one CLI invocation.
struct Outputs {
    intent: PathBuf,
    certificate: PathBuf,
    availability: PathBuf,
    result: PathBuf,
}

impl Outputs {
    fn new(directory: &Path, label: &str) -> Self {
        Self {
            intent: directory.join(format!("{label}.intent")),
            certificate: directory.join(format!("{label}.cert")),
            availability: directory.join(format!("{label}.avail")),
            result: directory.join(format!("{label}.result")),
        }
    }

    fn assert_absent(&self, label: &str) {
        for path in [
            &self.intent,
            &self.certificate,
            &self.availability,
            &self.result,
        ] {
            assert_absent(path, label);
        }
    }
}

/// Exact bytes the ordinary CLI artifact owner persisted.
#[derive(Debug, PartialEq, Eq)]
struct Saved {
    intent: Vec<u8>,
    certificate: Vec<u8>,
    availability: Vec<u8>,
    result: Vec<u8>,
}

impl Saved {
    fn read(outputs: &Outputs) -> Self {
        let saved: Saved = Self {
            intent: fs::read(&outputs.intent).unwrap(),
            certificate: fs::read(&outputs.certificate).unwrap(),
            availability: fs::read(&outputs.availability).unwrap(),
            result: fs::read(&outputs.result).unwrap(),
        };
        assert!(!saved.intent.is_empty() && !saved.certificate.is_empty());
        assert!(!saved.availability.is_empty() && !saved.result.is_empty());
        saved
    }
}

fn context_flags(network: &Network) -> Vec<(&'static str, String)> {
    vec![
        (
            "--expected-chain-id",
            network.fixture.context.chain_id().as_str().to_owned(),
        ),
        (
            "--expected-protocol-version",
            network.fixture.context.protocol_version().get().to_string(),
        ),
        (
            "--expected-epoch",
            network.fixture.context.epoch().get().to_string(),
        ),
        ("--expected-hash-suite-id", "1".to_owned()),
        ("--expected-domain", hex(network.domain.as_bytes())),
        ("--fastvote-expected-genesis-digest", hex(&network.digest)),
        ("--fastvote-deadline-seconds", "30".to_owned()),
        ("--fastvote-per-request-cap-seconds", "10".to_owned()),
    ]
}

fn push_flags(args: &mut Vec<OsString>, values: Vec<(&'static str, String)>) {
    for (flag, value) in values {
        args.push(flag.into());
        args.push(value.into());
    }
}

fn push_paths(args: &mut Vec<OsString>, paths: &[(&'static str, &Path)]) {
    for (flag, path) in paths {
        args.push((*flag).into());
        args.push(path.as_os_str().to_owned());
    }
}

fn transfer_args(
    network: &Network,
    config: &Path,
    endpoint: SocketAddr,
    seed: &Path,
    request: [u8; 32],
    nonce: u64,
    outputs: &Outputs,
) -> Vec<OsString> {
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from(RECIPIENT_SEED)).into();
    let mut args: Vec<OsString> = vec!["transfer".into()];
    push_flags(&mut args, context_flags(network));
    push_flags(
        &mut args,
        vec![
            ("--endpoint", endpoint.to_string()),
            ("--fee-source", hex(&FEE_COIN)),
            ("--max-fee", MAX_FEE.to_string()),
            ("--gas-limit", "200000".to_owned()),
            ("--request-id", hex(&request)),
            ("--nonce", nonce.to_string()),
            ("--coin", hex(&APP_COIN)),
            ("--recipient", hex(&recipient)),
        ],
    );
    push_paths(
        &mut args,
        &[
            ("--seed-file", seed),
            ("--fastvote-network", config),
            ("--fastvote-genesis-manifest", &network.genesis),
            ("--fastvote-signed-intent-out", &outputs.intent),
            ("--fastvote-certificate-out", &outputs.certificate),
            (
                "--fastvote-availability-certificate-out",
                &outputs.availability,
            ),
            ("--result-out", &outputs.result),
        ],
    );
    args
}

/// `saved` replays exact saved certificates; `None` makes the real CLI
/// collect them from the saved intent into reserved `outputs` destinations.
fn replay_args(
    network: &Network,
    config: &Path,
    submission: &Path,
    saved: Option<&Outputs>,
    outputs: &Outputs,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["contract".into(), "fastvote-replay".into()];
    push_flags(&mut args, context_flags(network));
    push_paths(
        &mut args,
        &[
            ("--fastvote-network", config),
            ("--fastvote-genesis-manifest", &network.genesis),
            ("--submission", submission),
            ("--result-out", &outputs.result),
        ],
    );
    match saved {
        Some(saved) => push_paths(
            &mut args,
            &[
                ("--certificate", &saved.certificate),
                ("--availability-certificate", &saved.availability),
            ],
        ),
        None => push_paths(
            &mut args,
            &[
                ("--fastvote-certificate-out", &outputs.certificate),
                (
                    "--fastvote-availability-certificate-out",
                    &outputs.availability,
                ),
            ],
        ),
    }
    args
}

fn run_cli(args: Vec<OsString>) -> Output {
    spawn_bounded_output(edge_cli_command(args), CLI_DEADLINE)
}

fn operation(fence: WriterFenceGeneration, tag: u8) -> DurableOperationContext {
    let now: u64 = SystemClock.now_unix_millis().unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([tag; 16]).unwrap(),
    )
}

fn open_store(network: &Network, index: usize) -> SqliteDurableStore {
    SqliteDurableStore::open_existing(network.state_db(index), network.namespace(index)).unwrap()
}

/// Complete business collections and referenced blobs of one namespace,
/// read through a fresh handle at the currently active fence.
fn snapshot(network: &Network, index: usize) -> SourceBusinessSnapshot {
    let store: SqliteDurableStore = open_store(network, index);
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(network.blob_db(index)).unwrap();
    let fence: WriterFenceGeneration = store.writer_fence().unwrap();
    let captured: SourceBusinessSnapshot = capture_source_business_snapshot(
        &store,
        &blobs,
        &operation(fence, 0x70),
        network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    assert_eq!(captured.token.writer_fence(), fence);
    captured
}

fn snapshots(network: &Network) -> Vec<SourceBusinessSnapshot> {
    (0..VALIDATORS)
        .map(|index: usize| snapshot(network, index))
        .collect()
}

fn assert_unchanged(
    before: &[SourceBusinessSnapshot],
    after: &[SourceBusinessSnapshot],
    label: &str,
) {
    assert_eq!(before.len(), VALIDATORS);
    assert_eq!(after.len(), VALIDATORS);
    for (index, (old, new)) in before.iter().zip(after).enumerate() {
        assert_eq!(
            old.records, new.records,
            "{label}: namespace {index} records"
        );
        assert_eq!(
            old.referenced_blobs, new.referenced_blobs,
            "{label}: namespace {index} referenced blobs"
        );
        assert_eq!(
            old.token.mutation_sequence(),
            new.token.mutation_sequence(),
            "{label}: namespace {index} mutation sequence"
        );
        assert_eq!(old.token, new.token, "{label}: namespace {index} token");
    }
}

/// Reopening advances each physical fence exactly once and nothing else.
/// Different replicas' physical tokens are never compared with each other.
fn assert_reopened(
    before: &[SourceBusinessSnapshot],
    after: &[SourceBusinessSnapshot],
    from: u64,
    to: u64,
) {
    assert_eq!(before.len(), VALIDATORS);
    assert_eq!(after.len(), VALIDATORS);
    for (index, (old, new)) in before.iter().zip(after).enumerate() {
        assert_eq!(
            old.records, new.records,
            "reopen: namespace {index} records"
        );
        assert_eq!(
            old.referenced_blobs, new.referenced_blobs,
            "reopen: namespace {index} blobs"
        );
        assert_eq!(old.token.namespace(), new.token.namespace());
        assert_eq!(old.token.domain(), new.token.domain());
        assert_eq!(
            old.token.mutation_sequence(),
            new.token.mutation_sequence(),
            "reopen: namespace {index} mutation sequence"
        );
        assert_eq!(old.token.writer_fence().get(), from);
        assert_eq!(new.token.writer_fence().get(), to);
    }
}

/// A real store handle and generation-2 capability, held open across the
/// restart rather than reconstructed after it.
struct StaleCapability {
    store: SqliteDurableStore,
    fence: WriterFenceGeneration,
    key: Vec<u8>,
    marker: VersionedStateValue,
    transaction: AtomicStateTransaction,
}

impl StaleCapability {
    fn hold(network: &Network, index: usize) -> Self {
        let store: SqliteDurableStore = open_store(network, index);
        let fence: WriterFenceGeneration = store.writer_fence().unwrap();
        assert_eq!(fence.get(), 2);
        let key: Vec<u8> = node_core::genesis_marker_key(&network.fixture.context).unwrap();
        let current: VersionedStateValue = store
            .get_versioned_durable(&operation(fence, 0x71), network.domain, &key)
            .unwrap();
        assert!(
            current.value().is_some(),
            "the held capability reads before restart"
        );
        // Assemble before restart from a genuine present key/revision/value.
        // This nonempty valid CAS/Put would rewrite the same marker bytes;
        // neither an invalid envelope nor an expired deadline is a substitute.
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            network.domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), current.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    key.clone(),
                    StateMutation::Put(current.value().unwrap().to_vec()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        Self {
            store,
            fence,
            key,
            marker: current,
            transaction,
        }
    }

    fn assert_fenced(&self, domain: AtomicityDomainId, active: u64) {
        // A fresh bounded deadline: only the fence, never elapsed time, refuses.
        match self
            .store
            .get_versioned_durable(&operation(self.fence, 0x72), domain, &self.key)
        {
            Err(DurableReadError::WriterFenced { active_generation }) => {
                assert_eq!(active_generation.get(), active);
            }
            Err(_) => panic!("stale capability refused for a reason other than its fence"),
            Ok(_) => panic!(
                "stale generation-{} capability still reads after restart",
                self.fence.get()
            ),
        }
        let active_fence: WriterFenceGeneration = self.store.writer_fence().unwrap();
        assert_eq!(active_fence.get(), active);
        let current: VersionedStateValue = self
            .store
            .get_versioned_durable(&operation(active_fence, 0x73), domain, &self.key)
            .unwrap();
        assert_eq!(
            current, self.marker,
            "captured CAS remains valid under the active fence"
        );
        match self
            .store
            .commit_durable(&operation(self.fence, 0x74), self.transaction.clone())
        {
            DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
                active_generation,
            }) => {
                assert_eq!(active_generation.get(), active);
            }
            other => panic!("valid stale commit must be writer-fenced, got {other:?}"),
        }
        let after: VersionedStateValue = self
            .store
            .get_versioned_durable(&operation(active_fence, 0x75), domain, &self.key)
            .unwrap();
        assert_eq!(
            after, self.marker,
            "stale commit changed no marker revision/value"
        );
    }
}

/// Exact canonical query bytes, identical from all four actual TLS clients.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    objects: BTreeMap<ObjectId, Vec<u8>>,
    receipt: Vec<u8>,
    next_nonce: Vec<u8>,
}

trait TlsPeer {
    fn client(&self) -> Client<RemoteTlsHttpTransport>;
}
impl TlsPeer for HttpsRelay {
    fn client(&self) -> Client<RemoteTlsHttpTransport> {
        relay_client(self)
    }
}

fn observe<P: TlsPeer>(
    relays: &[P],
    objects: &[ObjectId],
    request: RequestId,
    sender: Address,
) -> Observation {
    let observed: Vec<Observation> = relays
        .iter()
        .map(|relay: &P| {
            let client: Client<RemoteTlsHttpTransport> = relay.client();
            Observation {
                objects: objects
                    .iter()
                    .map(|id: &ObjectId| (*id, client.query_object(*id).unwrap().encode().unwrap()))
                    .collect(),
                receipt: client.query_receipt(request).unwrap().encode().unwrap(),
                next_nonce: client.query_next_nonce(sender).unwrap().encode().unwrap(),
            }
        })
        .collect();
    for (index, replica) in observed.iter().enumerate().skip(1) {
        assert_eq!(
            replica, &observed[0],
            "replica {index} canonical application outputs diverge"
        );
    }
    observed[0].clone()
}

fn current_inline(bytes: &[u8]) -> (u64, Digest32, Vec<u8>) {
    match HttpObjectQueryResult::decode(bytes).unwrap() {
        HttpObjectQueryResult::CurrentInline {
            object_version,
            digest,
            canonical_object_bytes,
            ..
        } => (object_version.get(), digest, canonical_object_bytes),
        other => panic!("expected a current inline object, got {other:?}"),
    }
}

fn effect_id(effect: &ObjectEffect) -> ObjectId {
    match effect {
        ObjectEffect::Created(object) => object.id,
        ObjectEffect::Mutated { new_object, .. } => new_object.id,
        ObjectEffect::Deleted { id, .. } => *id,
    }
}

fn effects_for(result: &PaidExecutionResult, id: ObjectId) -> Vec<&ObjectEffect> {
    result
        .effects
        .object_effects
        .iter()
        .filter(|effect: &&ObjectEffect| effect_id(effect) == id)
        .collect()
}

fn created(result: &PaidExecutionResult, id: ObjectId) -> &Object {
    match effects_for(result, id).as_slice() {
        [ObjectEffect::Created(object)] => object,
        other => panic!("{id} must be exactly one fresh creation, got {other:?}"),
    }
}

fn verify_initial(network: &Network, initial: &Observation, sender: Address) -> u64 {
    for (id, bytes) in &initial.objects {
        let original: Object = network.genesis_object(*id);
        let (version, _digest, canonical): (u64, Digest32, Vec<u8>) = current_inline(bytes);
        assert_eq!(version, original.version);
        assert_eq!(canonical, encode_object(&original).unwrap());
    }
    assert!(matches!(
        HttpReceiptQueryResult::decode(&initial.receipt).unwrap(),
        HttpReceiptQueryResult::Absent { .. }
    ));
    let nonce: HttpNextNonceQueryResult =
        HttpNextNonceQueryResult::decode(&initial.next_nonce).unwrap();
    assert_eq!(nonce.sender(), sender);
    assert_eq!(nonce.epoch(), network.fixture.context.epoch());
    assert_eq!(
        nonce.next_nonce(),
        0,
        "the fixture owner signed nothing in the authored genesis"
    );
    nonce.next_nonce()
}

/// Tests one precise trust refusal without measuring in-memory signatures:
/// no forwarded POST or artifact, and every complete namespace unchanged.
fn refused(
    network: &Network,
    relays: &[HttpsRelay],
    label: &str,
    args: Vec<OsString>,
    outputs: &Outputs,
    expected: &[&str],
) -> String {
    let before: Vec<SourceBusinessSnapshot> = snapshots(network);
    let posts: Vec<usize> = forwarded_posts(relays);
    let output: Output = run_cli(args);
    let stderr: String = lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "{label}: refusal exited successfully"
    );
    assert!(
        output.stdout.is_empty(),
        "{label}: refusal advertised progress: {}",
        lossy(&output.stdout)
    );
    assert!(stderr.starts_with("error="), "{label}: {stderr}");
    for diagnostic in expected {
        assert!(
            stderr.contains(diagnostic),
            "{label}: expected {diagnostic:?} in {stderr}"
        );
    }
    assert_eq!(
        forwarded_posts(relays),
        posts,
        "{label}: refusal forwarded a POST"
    );
    outputs.assert_absent(label);
    assert_unchanged(&before, &snapshots(network), label);
    stderr
}

fn refuse_bad_pins_and_cohorts(
    network: &Network,
    hosts: &[Host],
    tls: &Tls,
    config: &Path,
    nonce: u64,
) {
    // Local signed-genesis/context pins and cohort purity precede signer
    // loading, so these three deliberately have no signer key at all.
    let absent_seed: PathBuf = network.tls_dir.join("absent-owner.seed");
    assert_absent(&absent_seed, "absent signer seed");
    let lines: Vec<String> = tls_lines(network, tls);
    let selected: SocketAddr = tls.relays[0].addr;

    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "wrong-digest");
    let mut args: Vec<OsString> = transfer_args(
        network,
        config,
        selected,
        &absent_seed,
        [0x01; 32],
        nonce,
        &outputs,
    );
    replace(
        &mut args,
        "--fastvote-expected-genesis-digest",
        hex(&[0x99; 32]).into(),
    );
    refused(
        network,
        &tls.relays,
        "wrong original digest",
        args,
        &outputs,
        &[COMMITMENT_MISMATCH],
    );

    // The local protocol version keys the commitment hash itself, so the
    // pinned original digest no longer matches.
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "wrong-protocol");
    let mut args: Vec<OsString> = transfer_args(
        network,
        config,
        selected,
        &absent_seed,
        [0x02; 32],
        nonce,
        &outputs,
    );
    let wrong_protocol: u32 = network
        .fixture
        .context
        .protocol_version()
        .get()
        .checked_add(1)
        .unwrap();
    replace(
        &mut args,
        "--expected-protocol-version",
        wrong_protocol.to_string().into(),
    );
    refused(
        network,
        &tls.relays,
        "wrong local protocol pin",
        args,
        &outputs,
        &[COMMITMENT_MISMATCH],
    );

    let mut mixed: Vec<String> = lines.clone();
    mixed[0] = format!(
        "{} {} - -\n",
        hex(&network.fixture.validators[0]),
        hosts[0].address
    );
    let mixed_config: PathBuf = write_config(&network.tls_dir.join("mixed.conf"), &mixed);
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "mixed-cohort");
    let args: Vec<OsString> = transfer_args(
        network,
        &mixed_config,
        tls.relays[1].addr,
        &absent_seed,
        [0x03; 32],
        nonce,
        &outputs,
    );
    refused(
        network,
        &tls.relays,
        "mixed plaintext/TLS cohort",
        args,
        &outputs,
        &[MIXED_COHORT],
    );

    // Remote trust and context checks follow signer loading, so these use the
    // valid protected seed and select the affected peer as --endpoint.
    let mut wrong_ca: Vec<String> = lines.clone();
    wrong_ca[0] = peer_line(
        network,
        0,
        selected,
        &tls.relays[0].server_name,
        &tls.ca_files[1],
    );
    let wrong_ca_config: PathBuf = write_config(&network.tls_dir.join("wrong-ca.conf"), &wrong_ca);
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "wrong-ca");
    let args: Vec<OsString> = transfer_args(
        network,
        &wrong_ca_config,
        selected,
        &network.owner_seed,
        [0x04; 32],
        nonce,
        &outputs,
    );
    let unknown_issuer: String = format!("{TLS_PEER_REFUSAL}UnknownIssuer");
    refused(
        network,
        &tls.relays,
        "selected peer wrong CA",
        args,
        &outputs,
        &[unknown_issuer.as_str()],
    );

    let mut wrong_dns: Vec<String> = lines.clone();
    wrong_dns[0] = peer_line(
        network,
        0,
        selected,
        "unconfigured-peer.sunrise-edge.invalid",
        &tls.ca_files[0],
    );
    let wrong_dns_config: PathBuf =
        write_config(&network.tls_dir.join("wrong-dns.conf"), &wrong_dns);
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "wrong-dns");
    let args: Vec<OsString> = transfer_args(
        network,
        &wrong_dns_config,
        selected,
        &network.owner_seed,
        [0x05; 32],
        nonce,
        &outputs,
    );
    let stderr: String = refused(
        network,
        &tls.relays,
        "selected peer wrong DNS name",
        args,
        &outputs,
        &[TLS_PEER_REFUSAL],
    );
    assert!(
        stderr.contains("not valid for name") || stderr.contains("NotValidForName"),
        "{stderr}"
    );

    let foreign: [u8; 32] = [0x62; 32];
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "wrong-remote-domain");
    let mut args: Vec<OsString> = transfer_args(
        network,
        config,
        selected,
        &network.owner_seed,
        [0x06; 32],
        nonce,
        &outputs,
    );
    replace(&mut args, "--expected-domain", hex(&foreign).into());
    let mismatch: String = format!(
        "remote /v1/context domain {} disagrees with locally expected domain {}",
        hex(&DOMAIN),
        hex(&foreign)
    );
    refused(
        network,
        &tls.relays,
        "remote domain pin mismatch",
        args,
        &outputs,
        &[mismatch.as_str()],
    );
}

fn assert_ordered(stdout: &str, markers: &[&str]) {
    let mut cursor: usize = 0;
    for marker in markers {
        let position: usize = stdout[cursor..]
            .find(marker)
            .map(|offset: usize| cursor.checked_add(offset).unwrap())
            .unwrap_or_else(|| panic!("missing {marker:?} after byte {cursor}: {stdout}"));
        cursor = position.checked_add(marker.len()).unwrap();
    }
}

/// The saved intent, verified and decoded artifacts bound to it.
struct Committed {
    signed: SignedPaidIntent,
    result: PaidExecutionResult,
    tx_hash: Digest32,
}

fn verify_saved_artifacts(network: &Network, saved: &Saved, nonce: u64) -> Committed {
    let signed: SignedPaidIntent = decode_signed_paid_intent(&saved.intent).unwrap();
    assert_eq!(encode_signed_paid_intent(&signed).unwrap(), saved.intent);
    if let Err(error) = authenticate_paid_intent(
        &network.fixture.resolver,
        &network.fixture.context,
        &saved.intent,
    ) {
        panic!("saved intent fails genuine authentication: {error:?}");
    }
    assert_eq!(signed.intent.context, network.fixture.context);
    assert_eq!(signed.intent.request_id, TRANSFER_REQUEST);
    assert_eq!(signed.intent.sender, network.fixture.owner);
    assert_eq!(signed.intent.nonce, nonce);
    assert_eq!(signed.intent.consent.source.id, ObjectId::new(FEE_COIN));
    assert_eq!(signed.intent.consent.max_fee, Amount::new(MAX_FEE));
    assert_eq!(
        signed.intent.consent.refund_recipient,
        network.fixture.owner
    );
    let tx_hash: Digest32 = paid_invocation_digest(&network.fixture.resolver, &signed).unwrap();

    let certificate: FastCertificate = decode_fast_certificate(&saved.certificate).unwrap();
    assert_eq!(
        encode_fast_certificate(&certificate).unwrap(),
        saved.certificate
    );
    let trusted: TrustedFastVoteGenesis = network.trusted();
    assert!(trusted.commitment_profile().is_logical());
    trusted
        .certifier()
        .verify_certificate(
            &certificate,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap();
    assert_eq!(&certificate.chain_id, network.fixture.context.chain_id());
    assert_eq!(
        certificate.protocol_version,
        network.fixture.context.protocol_version()
    );
    assert_eq!(certificate.epoch, network.fixture.context.epoch());
    assert_eq!(certificate.tx_hash, tx_hash);

    let availability: AvailabilityCertificate =
        decode_availability_certificate(&saved.availability).unwrap();
    assert_eq!(
        encode_availability_certificate(&availability).unwrap(),
        saved.availability
    );
    let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        network.fixture.context.chain_id().clone(),
        network.fixture.context.protocol_version(),
        network.fixture.context.epoch(),
        trusted.certifier().validator_set().clone(),
    )
    .unwrap();
    availability_certifier
        .verify_certificate(
            &availability,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        )
        .unwrap();
    assert_eq!(availability.identity.domain, network.domain);
    assert_eq!(availability.identity.request_id, signed.intent.request_id);
    assert_eq!(availability.identity.signed_intent_digest, tx_hash);
    assert_eq!(
        availability.identity.execution_commitment,
        certificate.execution_effects_hash
    );

    let result: PaidExecutionResult = decode_paid_execution_result(&saved.result).unwrap();
    assert_eq!(encode_paid_execution_result(&result).unwrap(), saved.result);
    assert_eq!(result.request_id, signed.intent.request_id);
    assert_eq!(result.kind, PaidResultKind::Call);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(result.effects.tx_hash, tx_hash);
    Committed {
        signed,
        result,
        tx_hash,
    }
}

fn observed_ids(result: &PaidExecutionResult) -> Vec<ObjectId> {
    let charged: &PaidChargedOutcome = result.charged.as_ref().expect("Success is charged");
    let mut ids: Vec<ObjectId> = vec![
        ObjectId::new(APP_COIN),
        ObjectId::new(FEE_COIN),
        charged.fee_output.id,
        charged.reservation,
    ];
    if let Some(refund) = &charged.refund_output {
        ids.push(refund.id);
    }
    ids
}

fn verify_committed_state(
    network: &Network,
    committed: &Committed,
    saved: &Saved,
    observation: &Observation,
) {
    let result: &PaidExecutionResult = &committed.result;
    let consent = &committed.signed.intent.consent;
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from(RECIPIENT_SEED)).into();

    // Ordinary application Coin: same amount, asset and type; new owner.
    let app_id: ObjectId = ObjectId::new(APP_COIN);
    let app_original: Object = network.genesis_object(app_id);
    assert_eq!(
        app_original.owner,
        Owner::Address(Address::new(network.fixture.owner))
    );
    assert_eq!(coin_amount(&app_original.data).unwrap(), APP_COIN_AMOUNT);
    let app_effects: Vec<&ObjectEffect> = effects_for(result, app_id);
    let [
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        },
    ] = app_effects.as_slice()
    else {
        panic!("application Coin must be mutated exactly once: {app_effects:?}");
    };
    assert_eq!(*previous_version, app_original.version);
    assert_eq!(new_object.owner, Owner::Address(Address::new(recipient)));
    assert_eq!(new_object.type_hash, app_original.type_hash);
    assert_eq!(new_object.schema_version, app_original.schema_version);
    assert_eq!(new_object.data, app_original.data);
    assert_eq!(coin_amount(&new_object.data).unwrap(), APP_COIN_AMOUNT);
    let (version, _digest, canonical): (u64, Digest32, Vec<u8>) =
        current_inline(&observation.objects[&app_id]);
    assert_eq!(version, new_object.version);
    assert_eq!(canonical, encode_object(new_object).unwrap());

    // Fee source: exactly the reservation footprint; no invented balance.
    let fee_id: ObjectId = ObjectId::new(FEE_COIN);
    let fee_original: Object = network.genesis_object(fee_id);
    assert_eq!(consent.source.version, fee_original.version);
    match effects_for(result, fee_id).as_slice() {
        [
            ObjectEffect::Mutated {
                previous_version,
                new_object,
            },
        ] => {
            assert_eq!(*previous_version, consent.source.version);
            assert_eq!(new_object.type_hash, fee_original.type_hash);
            let (version, _digest, canonical): (u64, Digest32, Vec<u8>) =
                current_inline(&observation.objects[&fee_id]);
            assert_eq!(version, new_object.version);
            assert_eq!(canonical, encode_object(new_object).unwrap());
        }
        [ObjectEffect::Deleted { version, .. }] => {
            assert_eq!(*version, consent.source.version);
            match HttpObjectQueryResult::decode(&observation.objects[&fee_id]).unwrap() {
                HttpObjectQueryResult::Tombstoned {
                    last_object_version,
                    ..
                } => assert_eq!(last_object_version.get(), *version),
                other => panic!("deleted fee source must be tombstoned: {other:?}"),
            }
        }
        other => panic!("fee source needs exactly one reservation footprint: {other:?}"),
    }

    // Generic paid settlement: fresh fee output and optional fresh refund.
    let charged: &PaidChargedOutcome = result.charged.as_ref().expect("Success is charged");
    let authenticated: AuthenticatedPaidIntent = authenticate_paid_intent(
        &network.fixture.resolver,
        &network.fixture.context,
        &saved.intent,
    )
    .unwrap();
    let root: VerifiedGenesisRoot = network.root();
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(network.fixture.context.clone());
    let admission: Admission = quote_paid_intent(
        &authenticated,
        &network.fixture.resolver,
        &base_policy,
        &root.manifest().fee_policy,
    )
    .unwrap();
    let settlement: Settlement = admission.settle(charged.application_gas_units).unwrap();
    assert_eq!(charged.reserved, admission.reserved());
    assert_eq!(charged.actual, settlement.actual);
    assert_eq!(charged.refund, settlement.refund);
    assert!(charged.actual.get() > 0);
    assert!(charged.reserved.get() <= consent.max_fee.get());
    assert_eq!(
        charged.actual.get().checked_add(charged.refund.get()),
        Some(charged.reserved.get())
    );
    let fee_output: &Object = created(result, charged.fee_output.id);
    assert_eq!(fee_output.version, charged.fee_output.version);
    assert_eq!(fee_output.type_hash, app_original.type_hash);
    assert_eq!(fee_output.schema_version, app_original.schema_version);
    assert_eq!(coin_amount(&fee_output.data).unwrap(), charged.actual.get());
    assert!(matches!(
        &fee_output.owner,
        Owner::ProtocolCustody(scope)
            if scope.purpose == ProtocolCustodyPurpose::FeeEscrow
                && &scope.chain_id == network.fixture.context.chain_id()
    ));
    let (version, digest, canonical): (u64, Digest32, Vec<u8>) =
        current_inline(&observation.objects[&charged.fee_output.id]);
    assert_eq!(
        (version, digest),
        (charged.fee_output.version, charged.fee_output.digest)
    );
    assert_eq!(canonical, encode_object(fee_output).unwrap());
    match &charged.refund_output {
        Some(refund_ref) => {
            assert!(charged.refund.get() > 0);
            assert_ne!(refund_ref.id, charged.fee_output.id);
            let refund: &Object = created(result, refund_ref.id);
            assert_eq!(
                refund.owner,
                Owner::Address(Address::new(consent.refund_recipient))
            );
            assert_eq!(refund.type_hash, app_original.type_hash);
            assert_eq!(refund.schema_version, app_original.schema_version);
            assert_eq!(coin_amount(&refund.data).unwrap(), charged.refund.get());
            let (version, digest, canonical): (u64, Digest32, Vec<u8>) =
                current_inline(&observation.objects[&refund_ref.id]);
            assert_eq!((version, digest), (refund_ref.version, refund_ref.digest));
            assert_eq!(canonical, encode_object(refund).unwrap());
        }
        None => assert_eq!(charged.refund.get(), 0),
    }
    assert!(
        matches!(
            HttpObjectQueryResult::decode(&observation.objects[&charged.reservation]).unwrap(),
            HttpObjectQueryResult::Absent { .. } | HttpObjectQueryResult::Tombstoned { .. }
        ),
        "consumed reservation must not survive"
    );

    // Durable receipt binds the exact canonical paid result to the request.
    let request: RequestId = RequestId::new(TRANSFER_REQUEST).unwrap();
    match HttpReceiptQueryResult::decode(&observation.receipt).unwrap() {
        HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes,
        } => {
            assert_eq!(request_id, request);
            assert_eq!(event_digest, committed.tx_hash);
            let record: NodeDedupRecord = NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
            assert_eq!(record.encode().unwrap(), dedup_record_bytes);
            assert_eq!(record.request_id(), request);
            assert_eq!(record.event_digest(), committed.tx_hash);
            let [response] = record.responses() else {
                panic!("receipt must replay exactly one response");
            };
            assert_eq!(response.request_id(), request);
            assert_eq!(response.status(), NodeResponseStatus::Accepted);
            assert_eq!(response.payload(), Some(saved.result.as_slice()));
        }
        other => panic!("committed receipt missing: {other:?}"),
    }
    let nonce: HttpNextNonceQueryResult =
        HttpNextNonceQueryResult::decode(&observation.next_nonce).unwrap();
    assert_eq!(nonce.sender(), Address::new(network.fixture.owner));
    assert_eq!(nonce.epoch(), network.fixture.context.epoch());
    assert_eq!(
        nonce.next_nonce(),
        committed.signed.intent.nonce.checked_add(1).unwrap()
    );
}

fn assert_exact_replay(output: &Output, replay: &Outputs, saved: &Saved, label: &str) {
    let stdout: String = lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{label}: stdout={stdout} stderr={}",
        lossy(&output.stderr)
    );
    assert_ordered(
        &stdout,
        &[
            &format!("request_id={}", hex(&TRANSFER_REQUEST)),
            "fastvote_replay_mode=saved_certificate",
            "fastvote_replay_availability_mode=saved_certificate",
            "paid_status=Success",
        ],
    );
    assert_eq!(
        stdout
            .matches("status=received paid_status=Success")
            .count(),
        VALIDATORS,
        "{label}: every actual host returns its stored result"
    );
    assert_eq!(fs::read(&replay.result).unwrap(), saved.result, "{label}");
    for path in [&replay.intent, &replay.certificate, &replay.availability] {
        assert_absent(path, label);
    }
}

/// Everything the original commitment left behind, compared exactly.
fn assert_original_intact<P: TlsPeer>(
    network: &Network,
    relays: &[P],
    first: &Outputs,
    saved: &Saved,
    before: &[SourceBusinessSnapshot],
    expected: &Observation,
    label: &str,
) {
    assert_eq!(&Saved::read(first), saved, "{label}: saved artifacts");
    assert_unchanged(before, &snapshots(network), label);
    let ids: Vec<ObjectId> = expected.objects.keys().copied().collect();
    let observed: Observation = observe(
        relays,
        &ids,
        RequestId::new(TRANSFER_REQUEST).unwrap(),
        Address::new(network.fixture.owner),
    );
    assert_eq!(&observed, expected, "{label}: canonical query bytes");
}

fn refuse_peer_close(network: &Network, host: &Host, tls: &mut Tls, config: &Path, nonce: u64) {
    let endpoint: SocketAddr = tls.relays[0].addr;
    let name: String = tls.relays[0].server_name.clone();
    let listener: TcpListener = tls.relays.remove(0).stop();
    let close: PeerClose = PeerClose::start(listener, &name);
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "peer-close");
    let args: Vec<OsString> = transfer_args(
        network,
        config,
        endpoint,
        &network.owner_seed,
        [0x07; 32],
        nonce,
        &outputs,
    );
    // The selected endpoint is the finite worker, not any of the three live
    // relays. Its successful join additionally proves exactly one parsed SNI
    // ClientHello and zero handshake/HTTP/POST progress without any backend.
    refused(
        network,
        &tls.relays,
        "selected peer pre-handshake close",
        args,
        &outputs,
        &[TLS_HANDSHAKE_CLOSED],
    );
    let listener: TcpListener = close.finish();
    assert_eq!(listener.local_addr().unwrap(), endpoint);
    // No host stops or fence advances during this transport-only refusal.
    tls.relays
        .insert(0, HttpsRelay::start(listener, host.address, &tls.leaves[0]));
}

fn cutover_peer_zero(
    network: &Network,
    host: &Host,
    tls: &mut Tls,
    config: &Path,
    nonce: u64,
) -> PathBuf {
    let old_client: Client<RemoteTlsHttpTransport> = relay_client(&tls.relays[0]);
    let old_sdk_context: Vec<u8> = old_client.query_context().unwrap().encode().unwrap();
    let old_cli_context: Output = cli_context(&tls.relays[0], &tls.ca_files[0]);
    assert!(
        old_cli_context.status.success(),
        "{}",
        lossy(&old_cli_context.stderr)
    );
    let endpoint: SocketAddr = tls.relays[0].addr;
    let name: String = tls.relays[0].server_name.clone();
    let old_ca_file: PathBuf = tls.ca_files[0].clone();
    let old_ca_bytes: Vec<u8> = fs::read(&old_ca_file).unwrap();
    let old_config_bytes: Vec<u8> = fs::read(config).unwrap();
    let old_lines: Vec<String> = tls_lines(network, tls);
    let old_leaf: Vec<u8> = tls.leaves[0].der.clone();
    let ca: FixtureCa = FixtureCa::new(&format!("{name}-issuer-b"));
    assert_ne!(
        ca.subject, tls.cas[0].subject,
        "B_0 must have a distinct issuer DN"
    );
    assert_ne!(ca.der, tls.cas[0].der);
    let leaf: FixtureLeaf = ca.issue_leaf(&name);
    assert_ne!(leaf.der, old_leaf);
    assert_ne!(leaf.public_key_der, tls.leaves[0].public_key_der);
    let listener: TcpListener = tls.relays.remove(0).stop();
    tls.relays
        .insert(0, HttpsRelay::start(listener, host.address, &leaf));
    assert_eq!(tls.relays[0].addr, endpoint);
    assert_eq!(tls.relays[0].server_name, name);
    tls.cas[0] = ca;
    tls.leaves[0] = leaf;

    // The original config and immutable A_0 trust file still point at this
    // exact endpoint/DNS; no backend restart, root repair or protocol re-pin.
    let before: Vec<SourceBusinessSnapshot> = snapshots(network);
    let posts: Vec<usize> = forwarded_posts(&tls.relays);
    let accepted_before: usize = tls.relays[0].counters.accepted.load(Ordering::SeqCst);
    match old_client.query_context() {
        Err(ClientError::Transport(TransportError::TlsProtocol(
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        ))) => {}
        other => panic!("held A_0 SDK trust must refuse B_0 with UnknownIssuer: {other:?}"),
    }
    let accepted_sdk: usize = tls.relays[0].counters.accepted.load(Ordering::SeqCst);
    assert!(
        accepted_sdk > accepted_before,
        "held old SDK made no connection"
    );
    let unknown_issuer: String = format!("{TLS_PEER_REFUSAL}UnknownIssuer");
    assert_context_refused(cli_context(&tls.relays[0], &old_ca_file), &unknown_issuer);
    let accepted_context: usize = tls.relays[0].counters.accepted.load(Ordering::SeqCst);
    assert!(
        accepted_context > accepted_sdk,
        "fresh old-trust CLI made no connection"
    );
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "old-ca-after-cutover");
    let args: Vec<OsString> = transfer_args(
        network,
        config,
        endpoint,
        &network.owner_seed,
        [0x08; 32],
        nonce,
        &outputs,
    );
    refused(
        network,
        &tls.relays,
        "selected peer old CA after cutover",
        args,
        &outputs,
        &[unknown_issuer.as_str()],
    );
    assert!(tls.relays[0].counters.accepted.load(Ordering::SeqCst) > accepted_context);
    assert_eq!(tls.relays[0].counters.requests.load(Ordering::SeqCst), 0);
    assert_eq!(forwarded_posts(&tls.relays), posts);
    assert_unchanged(&before, &snapshots(network), "old trust refusals");
    assert_eq!(fs::read(&old_ca_file).unwrap(), old_ca_bytes);
    assert_eq!(fs::read(config).unwrap(), old_config_bytes);

    // Explicit new trust is a new immutable file/config, never an overwrite.
    let ca_file: PathBuf = network.tls_dir.join("validator-0-ca-b.der");
    write_private_new(&ca_file, &tls.cas[0].der);
    tls.ca_files[0] = ca_file;
    let mut expected_lines: Vec<String> = old_lines.clone();
    expected_lines[0] = peer_line(network, 0, endpoint, &name, &tls.ca_files[0]);
    let new_lines: Vec<String> = tls_lines(network, tls);
    assert_eq!(
        new_lines, expected_lines,
        "only peer-0 CA-file field may change"
    );
    let old_fields: Vec<&str> = old_lines[0].split_whitespace().collect();
    let new_fields: Vec<&str> = new_lines[0].split_whitespace().collect();
    assert_eq!(old_fields.len(), 4);
    assert_eq!(new_fields.len(), 4);
    assert_eq!(&old_fields[..3], &new_fields[..3]);
    assert_ne!(old_fields[3], new_fields[3]);
    let config: PathBuf = write_config(&network.tls_dir.join("network-ca-b.conf"), &new_lines);
    let received: Vec<u8> = authenticated_leaf(endpoint, &name, &tls.cas[0].der);
    assert_eq!(received, tls.leaves[0].der);
    assert_ne!(received, old_leaf);
    let new_sdk_context: Vec<u8> = relay_client(&tls.relays[0])
        .query_context()
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(new_sdk_context, old_sdk_context);
    let new_cli_context: Output = cli_context(&tls.relays[0], &tls.ca_files[0]);
    assert!(
        new_cli_context.status.success(),
        "{}",
        lossy(&new_cli_context.stderr)
    );
    assert_eq!(new_cli_context.stdout, old_cli_context.stdout);
    assert_unchanged(&before, &snapshots(network), "explicit new trust context");
    config
}

#[test]
fn actual_local_tls_startup_certifies_a_cli_transfer_refuses_bad_pins_and_replays_across_restart() {
    let network: Network = author_inspect_and_prepare();
    let hosts: Vec<Host> = start_hosts(&network, 2);
    let tls: Tls = start_tls(&hosts, &network.tls_dir);
    let config: PathBuf = write_config(
        &network.tls_dir.join("network.conf"),
        &tls_lines(&network, &tls),
    );
    let initial_leaves: Vec<Vec<u8>> = served_leaves(&tls);
    let initial_contexts: Vec<(Vec<u8>, Vec<u8>)> = contexts(&tls);
    let original_lines: Vec<String> = tls_lines(&network, &tls);
    let original_inputs: Vec<(PathBuf, Vec<u8>)> = std::iter::once(network.genesis.clone())
        .chain(network.signing_keys.iter().cloned())
        .chain(std::iter::once(network.owner_seed.clone()))
        .chain(tls.ca_files.iter().cloned())
        .chain(std::iter::once(config.clone()))
        .map(|path: PathBuf| {
            let bytes: Vec<u8> = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    let sender: Address = Address::new(network.fixture.owner);
    let request: RequestId = RequestId::new(TRANSFER_REQUEST).unwrap();
    let genesis_ids: [ObjectId; 2] = [ObjectId::new(APP_COIN), ObjectId::new(FEE_COIN)];
    let initial: Observation = observe(&tls.relays, &genesis_ids, request, sender);
    let nonce: u64 = verify_initial(&network, &initial, sender);

    refuse_bad_pins_and_cohorts(&network, &hosts, &tls, &config, nonce);
    assert_eq!(
        observe(&tls.relays, &genesis_ids, request, sender),
        initial,
        "refusals changed no coin, receipt or nonce"
    );

    // One ordinary certified transfer through all four actual TLS peers.
    let first: Outputs = Outputs::new(&network.artifacts_dir, "transfer");
    let posts: Vec<usize> = forwarded_posts(&tls.relays);
    let output: Output = run_cli(transfer_args(
        &network,
        &config,
        tls.relays[0].addr,
        &network.owner_seed,
        TRANSFER_REQUEST,
        nonce,
        &first,
    ));
    let stdout: String = lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout={stdout} stderr={}",
        lossy(&output.stderr)
    );
    // Synced intent before prepare, certificate before publication, and the
    // causal publication/availability step before any apply.
    assert_ordered(
        &stdout,
        &[
            "fastvote_signed_intent_out=",
            "fastvote_certificate_formed=true",
            "fastvote_certificate_out=",
            "fastvote_publication_source=",
            "fastvote_availability_certificate_out=",
            "apply validator=",
        ],
    );
    assert_eq!(
        stdout
            .matches("status=received paid_status=Success")
            .count(),
        VALIDATORS
    );
    assert_all_forwarded(&posts, &tls.relays, "ordinary transfer");
    let saved: Saved = Saved::read(&first);
    let committed: Committed = verify_saved_artifacts(&network, &saved, nonce);
    let ids: Vec<ObjectId> = observed_ids(&committed.result);
    let committed_view: Observation = observe(&tls.relays, &ids, request, sender);
    verify_committed_state(&network, &committed, &saved, &committed_view);

    // Exact saved intent/certificate/availability replay in the same boot.
    let before_replay: Vec<SourceBusinessSnapshot> = snapshots(&network);
    let posts: Vec<usize> = forwarded_posts(&tls.relays);
    let same_boot: Outputs = Outputs::new(&network.artifacts_dir, "same-boot-replay");
    let output: Output = run_cli(replay_args(
        &network,
        &config,
        &first.intent,
        Some(&first),
        &same_boot,
    ));
    assert_exact_replay(&output, &same_boot, &saved, "same-boot replay");
    assert_all_forwarded(&posts, &tls.relays, "same-boot replay");
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &before_replay,
        &committed_view,
        "same-boot replay",
    );

    // Issue fresh leaves under retained authorities, then quietly stop/join
    // every relay and SIGINT/reap each exact owned host. Keep every listener,
    // client endpoint, DNS, immutable CA file and original config unchanged.
    let stale: Vec<StaleCapability> = (0..VALIDATORS)
        .map(|index: usize| StaleCapability::hold(&network, index))
        .collect();
    let before_restart: Vec<SourceBusinessSnapshot> = snapshots(&network);
    let new_leaves: Vec<FixtureLeaf> = tls
        .cas
        .iter()
        .zip(&tls.leaves)
        .map(|(ca, old): (&FixtureCa, &FixtureLeaf)| {
            let leaf: FixtureLeaf = ca.issue_leaf(&old.server_name);
            assert_eq!(leaf.ca_der, old.ca_der);
            assert_eq!(leaf.ca_der, ca.der);
            assert_eq!(leaf.server_name, old.server_name);
            assert_ne!(leaf.der, old.der);
            assert_ne!(leaf.public_key_der, old.public_key_der);
            leaf
        })
        .collect();
    let Tls {
        relays,
        ca_files,
        cas,
        leaves: old_leaves,
    } = tls;
    let listeners: Vec<TcpListener> = relays.into_iter().map(HttpsRelay::stop).collect();
    for host in hosts {
        host.guard.stop_orderly(PROCESS_DEADLINE);
    }
    let hosts: Vec<Host> = start_hosts(&network, 3);
    for capability in &stale {
        capability.assert_fenced(network.domain, 3);
    }
    let reopened: Vec<SourceBusinessSnapshot> = snapshots(&network);
    assert_reopened(&before_restart, &reopened, 2, 3);
    let relays: Vec<HttpsRelay> = listeners
        .into_iter()
        .zip(&hosts)
        .zip(&new_leaves)
        .map(
            |((listener, host), leaf): ((TcpListener, &Host), &FixtureLeaf)| {
                HttpsRelay::start(listener, host.address, leaf)
            },
        )
        .collect();
    let mut tls: Tls = Tls {
        relays,
        ca_files,
        cas,
        leaves: new_leaves,
    };
    assert_eq!(tls_lines(&network, &tls), original_lines);
    let received: Vec<Vec<u8>> = served_leaves(&tls);
    for (index, leaf) in received.iter().enumerate() {
        assert_ne!(leaf, &initial_leaves[index]);
        assert_ne!(leaf, &old_leaves[index].der);
    }
    for (path, bytes) in &original_inputs {
        assert!(
            &fs::read(path).unwrap() == bytes,
            "same-CA restart changed a pinned input: {}",
            path.display()
        );
    }
    assert_eq!(contexts(&tls), initial_contexts);
    assert_eq!(observe(&tls.relays, &ids, request, sender), committed_view);
    let after_restart: Outputs = Outputs::new(&network.artifacts_dir, "restart-replay");
    let posts: Vec<usize> = forwarded_posts(&tls.relays);
    let output: Output = run_cli(replay_args(
        &network,
        &config,
        &first.intent,
        Some(&first),
        &after_restart,
    ));
    assert_exact_replay(&output, &after_restart, &saved, "restart replay");
    assert_all_forwarded(&posts, &tls.relays, "same-CA leaf rotation replay");
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &reopened,
        &committed_view,
        "restart replay",
    );

    // Finite TLS peer failure, then a separate explicit CA trust migration.
    // These restart no SQLite host and therefore must retain generation 3.
    let before_transport: Vec<SourceBusinessSnapshot> = snapshots(&network);
    refuse_peer_close(&network, &hosts[0], &mut tls, &config, nonce);
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &before_transport,
        &committed_view,
        "finite peer close",
    );
    let config: PathBuf = cutover_peer_zero(&network, &hosts[0], &mut tls, &config, nonce);
    assert_eq!(contexts(&tls), initial_contexts);
    let _received: Vec<Vec<u8>> = served_leaves(&tls);
    let ca_replay: Outputs = Outputs::new(&network.artifacts_dir, "ca-cutover-replay");
    let posts: Vec<usize> = forwarded_posts(&tls.relays);
    let output: Output = run_cli(replay_args(
        &network,
        &config,
        &first.intent,
        Some(&first),
        &ca_replay,
    ));
    assert_exact_replay(&output, &ca_replay, &saved, "explicit CA cutover replay");
    assert_all_forwarded(&posts, &tls.relays, "explicit CA cutover replay");
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &before_transport,
        &committed_view,
        "explicit CA cutover replay",
    );

    // Authenticated new TLS still cannot replace an independent domain pin.
    let foreign: [u8; 32] = [0x62; 32];
    let domain_refusal: Outputs = Outputs::new(&network.artifacts_dir, "new-ca-wrong-domain");
    let mut args: Vec<OsString> = transfer_args(
        &network,
        &config,
        tls.relays[0].addr,
        &network.owner_seed,
        [0x09; 32],
        nonce,
        &domain_refusal,
    );
    replace(&mut args, "--expected-domain", hex(&foreign).into());
    let mismatch: String = format!(
        "remote /v1/context domain {} disagrees with locally expected domain {}",
        hex(&DOMAIN),
        hex(&foreign),
    );
    let requests: usize = tls.relays[0].counters.requests.load(Ordering::SeqCst);
    refused(
        &network,
        &tls.relays,
        "new CA remote domain pin mismatch",
        args,
        &domain_refusal,
        &[mismatch.as_str()],
    );
    assert!(
        tls.relays[0].counters.requests.load(Ordering::SeqCst) > requests,
        "domain refusal must follow actual authenticated HTTP context"
    );
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &before_transport,
        &committed_view,
        "new CA remote domain refusal",
    );

    // A genuinely different signed intent reusing the committed request ID.
    let mut conflicting: SignedPaidIntent = decode_signed_paid_intent(&saved.intent).unwrap();
    conflicting.intent.consent.max_fee = Amount::new(
        conflicting
            .intent
            .consent
            .max_fee
            .get()
            .checked_add(1)
            .unwrap(),
    );
    let frame: Vec<u8> =
        paid_intent_signing_frame(&network.fixture.context, &conflicting.intent).unwrap();
    conflicting.signature = SigningKey::from(OWNER_SEED).sign(&frame).into();
    let conflicting_bytes: Vec<u8> = encode_signed_paid_intent(&conflicting).unwrap();
    assert_ne!(conflicting_bytes, saved.intent);
    assert_eq!(conflicting.intent.request_id, TRANSFER_REQUEST);
    assert_eq!(conflicting.intent.nonce, nonce);
    if let Err(error) = authenticate_paid_intent(
        &network.fixture.resolver,
        &network.fixture.context,
        &conflicting_bytes,
    ) {
        panic!("conflicting intent must be genuinely signed: {error:?}");
    }
    let before_conflict: Vec<SourceBusinessSnapshot> = snapshots(&network);
    for (index, relay) in tls.relays.iter().enumerate() {
        match relay_client(relay).prepare_fastvote(&conflicting_bytes, None) {
            Err(ClientError::UnexpectedStatus { status, body }) => {
                assert_eq!(status, 400, "validator {index}");
                assert_eq!(body, "fastvote-rejected", "validator {index}");
            }
            Err(other) => panic!("validator {index}: expected fastvote-rejected, got {other}"),
            Ok(_) => panic!("validator {index} voted for a conflicting request-ID reuse"),
        }
        assert_original_intact(
            &network,
            &tls.relays,
            &first,
            &saved,
            &before_conflict,
            &committed_view,
            &format!("conflicting SDK prepare at validator {index}"),
        );
    }

    let conflicting_path: PathBuf = network.artifacts_dir.join("conflicting-submission.intent");
    write_private_new(&conflicting_path, &conflicting_bytes);
    let conflict: Outputs = Outputs::new(&network.artifacts_dir, "conflicting-replay");
    let output: Output = run_cli(replay_args(
        &network,
        &config,
        &conflicting_path,
        None,
        &conflict,
    ));
    let stdout: String = lossy(&output.stdout);
    let stderr: String = lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "conflicting replay succeeded: {stdout}"
    );
    assert!(
        stdout.contains("fastvote_replay_mode=prepare_from_saved_intent"),
        "{stdout}"
    );
    assert_eq!(
        stdout.matches(PREPARE_REFUSED).count(),
        VALIDATORS,
        "{stdout}"
    );
    assert!(stderr.contains(INSUFFICIENT_QUORUM), "{stderr}");
    for path in [
        &conflict.certificate,
        &conflict.availability,
        &conflict.result,
    ] {
        assert_reserved_empty(path, "conflicting replay");
    }
    assert_absent(&conflict.intent, "conflicting replay");
    assert_original_intact(
        &network,
        &tls.relays,
        &first,
        &saved,
        &before_conflict,
        &committed_view,
        "conflicting CLI replay",
    );
    for (path, bytes) in original_inputs {
        assert!(
            fs::read(&path).unwrap() == bytes,
            "original pinned input changed: {}",
            path.display()
        );
    }
    for relay in tls.relays {
        let _listener: TcpListener = relay.stop();
    }
    for host in hosts {
        host.guard.stop_orderly(PROCESS_DEADLINE);
    }
}

fn direct_refused(
    network: &Network,
    peers: &[DirectPeer],
    args: Vec<OsString>,
    outputs: &Outputs,
    expected: &Observation,
    diagnostic: &str,
) {
    let before: Vec<SourceBusinessSnapshot> = snapshots(network);
    let output: Output = run_cli(args);
    assert!(!output.status.success(), "{}", lossy(&output.stdout));
    assert!(
        lossy(&output.stderr).contains(diagnostic),
        "{}",
        lossy(&output.stderr)
    );
    outputs.assert_absent("direct TLS pre-signing refusal");
    assert_unchanged(&before, &snapshots(network), "direct TLS refusal");
    let ids: Vec<ObjectId> = expected.objects.keys().copied().collect();
    assert_eq!(
        observe(
            peers,
            &ids,
            RequestId::new(TRANSFER_REQUEST).unwrap(),
            Address::new(network.fixture.owner)
        ),
        *expected
    );
}

/// Send a genuinely authenticated saved apply, discard its confirmation, and
/// reconcile the already committed receipt. This is transport/reconciliation
/// evidence, not proof that a fresh mutation starts after disconnect.
fn discard_saved_confirmation(peer: &DirectPeer, saved: &Saved) {
    let mut roots: rustls::RootCertStore = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(peer.ca.der.clone()))
        .unwrap();
    let mut config: rustls::ClientConfig = rustls::ClientConfig::builder_with_provider(
        std::sync::Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    let mut connection: rustls::ClientConnection = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        rustls::pki_types::ServerName::try_from(peer.leaf.server_name.clone()).unwrap(),
    )
    .unwrap();
    let mut socket: std::net::TcpStream =
        std::net::TcpStream::connect_timeout(&peer.address, Duration::from_secs(5)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).unwrap();
    }
    assert_eq!(
        connection.peer_certificates().unwrap()[0].as_ref(),
        peer.leaf.der
    );
    let body: Vec<u8> = node_wire::FastVoteApplyRequest {
        signed_paid_intent: saved.intent.clone(),
        certificate: saved.certificate.clone(),
    }
    .encode()
    .unwrap();
    let headers: String = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        node_wire::FASTVOTE_CERTIFICATES_PATH,
        peer.leaf.server_name,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        body.len(),
    );
    let mut stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> =
        rustls::StreamOwned::new(connection, socket);
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    stream.flush().unwrap();
    drop(stream); // No response read and no invented rejection/rollback.
}

fn assert_native_termination_summary(stderr: &[u8], reason: &str) {
    assert!(stderr.len() <= 2 * 1024, "one bounded termination record");
    let text: &str = std::str::from_utf8(stderr).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.ends_with('\n'));
    let mut fields = text.split_whitespace();
    assert_eq!(fields.next(), Some("native_operations"));
    let pairs: Vec<(&str, &str)> = fields.map(|field: &str| field.split_once('=').unwrap()).collect();
    let names: [&str; 17] = ["schema", "stop", "connections_admitted", "connections_refused",
        "accept_failures", "upgrade_failures", "upgrade_timeouts", "requests_dispatched",
        "requests_refused", "input_timeouts", "output_timeouts", "connection_failures",
        "connection_task_failures", "blocking_admitted", "blocking_overloaded", "blocking_closed", "blocking_panics"];
    assert_eq!(pairs.iter().map(|(name, _)| *name).collect::<Vec<&str>>(), names);
    assert_eq!(pairs[0].1, "1");
    assert_eq!(pairs[1].1, reason);
    let counts: Vec<u64> = pairs[2..].iter().map(|(_, value)| value.parse::<u64>().unwrap()).collect();
    assert!(counts[0] > 0, "actual connections must have been admitted");
    assert!(counts[5] > 0, "actual requests must have been dispatched");
    assert!(counts[11] > 0, "actual synchronous operations must have been admitted");
    assert_eq!(counts[14], 0, "ordinary successful fixture has no blocking unwind");
}

#[test]
fn actual_direct_tls_hosts_preserve_paid_state_replay_and_explicit_stopped_trust_rotation() {
    let network: Network = author_inspect_and_prepare();
    let mut peers: Vec<DirectPeer> = direct_peers(&network);
    let hosts: Vec<Host> = start_direct_hosts(&network, &mut peers, 2);
    let lines: Vec<String> = direct_lines(&network, &peers);
    let config: PathBuf = write_config(&network.tls_dir.join("direct-network.conf"), &lines);
    let received: Vec<Vec<u8>> = peers.iter().map(DirectPeer::received).collect();
    let contexts: Vec<(Vec<u8>, Vec<u8>)> = direct_contexts(&peers);
    let original_inputs: Vec<(PathBuf, Vec<u8>)> = std::iter::once(network.genesis.clone())
        .chain(network.signing_keys.iter().cloned())
        .chain(std::iter::once(network.owner_seed.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.ca_file.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.cert_file.clone()))
        .chain(peers.iter().map(|peer: &DirectPeer| peer.key_file.clone()))
        .chain(std::iter::once(config.clone()))
        .map(|path: PathBuf| {
            let bytes: Vec<u8> = fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    let sender: Address = Address::new(network.fixture.owner);
    let request: RequestId = RequestId::new(TRANSFER_REQUEST).unwrap();
    let initial: Observation = observe(
        &peers,
        &[ObjectId::new(APP_COIN), ObjectId::new(FEE_COIN)],
        request,
        sender,
    );
    let nonce: u64 = verify_initial(&network, &initial, sender);
    for (label, name, ca) in [
        (
            "wrong-ca",
            peers[0].leaf.server_name.as_str(),
            peers[1].ca_file.as_path(),
        ),
        (
            "wrong-dns",
            "wrong-direct.fixture.invalid",
            peers[0].ca_file.as_path(),
        ),
    ] {
        let mut wrong: Vec<String> = lines.clone();
        wrong[0] = peer_line(&network, 0, peers[0].address, name, ca);
        let wrong_config: PathBuf = write_config(
            &network.tls_dir.join(format!("direct-{label}.conf")),
            &wrong,
        );
        let outputs: Outputs = Outputs::new(&network.artifacts_dir, label);
        direct_refused(
            &network,
            &peers,
            transfer_args(
                &network,
                &wrong_config,
                peers[0].address,
                &network.owner_seed,
                [0x08; 32],
                nonce,
                &outputs,
            ),
            &outputs,
            &initial,
            TLS_PEER_REFUSAL,
        );
    }
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "direct-wrong-domain");
    let mut args: Vec<OsString> = transfer_args(
        &network,
        &config,
        peers[0].address,
        &network.owner_seed,
        [0x09; 32],
        nonce,
        &outputs,
    );
    replace(&mut args, "--expected-domain", hex(&[0x62; 32]).into());
    let mismatch: String = format!(
        "remote /v1/context domain {} disagrees with locally expected domain {}",
        hex(&DOMAIN),
        hex(&[0x62; 32])
    );
    direct_refused(&network, &peers, args, &outputs, &initial, &mismatch);

    let first: Outputs = Outputs::new(&network.artifacts_dir, "direct-transfer");
    let output: Output = run_cli(transfer_args(
        &network,
        &config,
        peers[0].address,
        &network.owner_seed,
        TRANSFER_REQUEST,
        nonce,
        &first,
    ));
    let stdout: String = lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout={stdout} stderr={}",
        lossy(&output.stderr)
    );
    assert_ordered(
        &stdout,
        &[
            "fastvote_signed_intent_out=",
            "fastvote_certificate_formed=true",
            "fastvote_certificate_out=",
            "fastvote_publication_source=",
            "fastvote_availability_certificate_out=",
            "apply validator=",
        ],
    );
    assert_eq!(
        stdout
            .matches("status=received paid_status=Success")
            .count(),
        VALIDATORS
    );
    let saved: Saved = Saved::read(&first);
    let committed: Committed = verify_saved_artifacts(&network, &saved, nonce);
    let ids: Vec<ObjectId> = observed_ids(&committed.result);
    let committed_view: Observation = observe(&peers, &ids, request, sender);
    verify_committed_state(&network, &committed, &saved, &committed_view);
    let before: Vec<SourceBusinessSnapshot> = snapshots(&network);
    let replay: Outputs = Outputs::new(&network.artifacts_dir, "direct-same-boot");
    assert_exact_replay(
        &run_cli(replay_args(
            &network,
            &config,
            &first.intent,
            Some(&first),
            &replay,
        )),
        &replay,
        &saved,
        "direct same-boot replay",
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &before,
        &committed_view,
        "direct same boot",
    );

    // Same-CA leaf/key rollover: exact same endpoints, DNS, roots and protocol
    // files, fresh authenticated DER/SPKI, and real live fence 2 -> 3.
    let stale: Vec<StaleCapability> = (0..VALIDATORS)
        .map(|index: usize| StaleCapability::hold(&network, index))
        .collect();
    for (index, peer) in peers.iter_mut().enumerate() {
        peer.renew(&network.tls_dir, &format!("direct-same-ca-{index}"));
    }
    for host in hosts {
        let stderr: Vec<u8> = host.guard.stop_orderly_terminate(PROCESS_DEADLINE);
        assert_native_termination_summary(&stderr, "sigterm");
    }
    let hosts: Vec<Host> = start_direct_hosts(&network, &mut peers, 3);
    for capability in &stale {
        capability.assert_fenced(network.domain, 3);
    }
    let reopened: Vec<SourceBusinessSnapshot> = snapshots(&network);
    assert_reopened(&before, &reopened, 2, 3);
    assert_eq!(direct_lines(&network, &peers), lines);
    for (index, peer) in peers.iter().enumerate() {
        assert_ne!(peer.received(), received[index]);
    }
    assert_eq!(direct_contexts(&peers), contexts);
    let replay: Outputs = Outputs::new(&network.artifacts_dir, "direct-same-ca-replay");
    assert_exact_replay(
        &run_cli(replay_args(
            &network,
            &config,
            &first.intent,
            Some(&first),
            &replay,
        )),
        &replay,
        &saved,
        "direct same-CA restart replay",
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened,
        &committed_view,
        "direct same CA",
    );

    // Separate unrelated-CA stopped restart. Only peer 0 changes trust; all
    // four live hosts reopen exactly once, with explicit fence 3 -> 4.
    let old_client: Client<RemoteTlsHttpTransport> = peers[0].client();
    assert_eq!(
        old_client.query_context().unwrap().encode().unwrap(),
        contexts[0].0
    );
    let old_root: PathBuf = peers[0].ca_file.clone();
    let old_root_bytes: Vec<u8> = fs::read(&old_root).unwrap();
    let ca: FixtureCa = FixtureCa::new(&format!("{}-direct-issuer-b", peers[0].leaf.server_name));
    assert_ne!(ca.subject, peers[0].ca.subject);
    assert_ne!(ca.der, peers[0].ca.der);
    peers[0].ca = ca;
    peers[0].renew(&network.tls_dir, "direct-ca-b");
    for host in hosts {
        let stderr: Vec<u8> = host.guard.stop_orderly_interrupt_observed(PROCESS_DEADLINE);
        assert_native_termination_summary(&stderr, "sigint");
    }
    let hosts: Vec<Host> = start_direct_hosts(&network, &mut peers, 4);
    let reopened_again: Vec<SourceBusinessSnapshot> = snapshots(&network);
    assert_reopened(&reopened, &reopened_again, 3, 4);
    match old_client.query_context() {
        Err(ClientError::Transport(TransportError::TlsProtocol(
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        ))) => {}
        other => panic!("held old direct trust must refuse exact UnknownIssuer: {other:?}"),
    }
    let unknown: String = format!("{TLS_PEER_REFUSAL}UnknownIssuer");
    assert_context_refused(peers[0].context(&old_root), &unknown);
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "direct-old-ca-transfer");
    direct_refused(
        &network,
        &peers,
        transfer_args(
            &network,
            &config,
            peers[0].address,
            &network.owner_seed,
            [0x08; 32],
            nonce,
            &outputs,
        ),
        &outputs,
        &committed_view,
        &unknown,
    );
    assert_eq!(fs::read(&old_root).unwrap(), old_root_bytes);
    peers[0].ca_file = network.tls_dir.join("direct-ca-b-root.der");
    write_private_new(&peers[0].ca_file, &peers[0].ca.der);
    let new_lines: Vec<String> = direct_lines(&network, &peers);
    assert_eq!(&new_lines[1..], &lines[1..]);
    let old_fields: Vec<&str> = lines[0].split_whitespace().collect();
    let new_fields: Vec<&str> = new_lines[0].split_whitespace().collect();
    assert_eq!(&old_fields[..3], &new_fields[..3]);
    assert_ne!(old_fields[3], new_fields[3]);
    let new_config: PathBuf = write_config(
        &network.tls_dir.join("direct-ca-b-network.conf"),
        &new_lines,
    );
    assert_eq!(direct_contexts(&peers), contexts);
    for peer in &peers {
        let _received: Vec<u8> = peer.received();
    }
    let replay: Outputs = Outputs::new(&network.artifacts_dir, "direct-ca-b-replay");
    assert_exact_replay(
        &run_cli(replay_args(
            &network,
            &new_config,
            &first.intent,
            Some(&first),
            &replay,
        )),
        &replay,
        &saved,
        "direct new-CA restart replay",
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened_again,
        &committed_view,
        "direct new CA",
    );
    let outputs: Outputs = Outputs::new(&network.artifacts_dir, "direct-new-ca-wrong-domain");
    let mut args: Vec<OsString> = transfer_args(
        &network,
        &new_config,
        peers[0].address,
        &network.owner_seed,
        [0x09; 32],
        nonce,
        &outputs,
    );
    replace(&mut args, "--expected-domain", hex(&[0x62; 32]).into());
    direct_refused(&network, &peers, args, &outputs, &committed_view, &mismatch);

    discard_saved_confirmation(&peers[0], &saved);
    let replay: Outputs = Outputs::new(&network.artifacts_dir, "direct-lost-confirmation-replay");
    assert_exact_replay(
        &run_cli(replay_args(
            &network,
            &new_config,
            &first.intent,
            Some(&first),
            &replay,
        )),
        &replay,
        &saved,
        "direct saved-result reconciliation",
    );
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened_again,
        &committed_view,
        "discarded saved confirmation",
    );

    let mut conflicting: SignedPaidIntent = decode_signed_paid_intent(&saved.intent).unwrap();
    conflicting.intent.consent.max_fee = Amount::new(
        conflicting
            .intent
            .consent
            .max_fee
            .get()
            .checked_add(1)
            .unwrap(),
    );
    let frame: Vec<u8> =
        paid_intent_signing_frame(&network.fixture.context, &conflicting.intent).unwrap();
    conflicting.signature = SigningKey::from(OWNER_SEED).sign(&frame).into();
    let conflicting_bytes: Vec<u8> = encode_signed_paid_intent(&conflicting).unwrap();
    assert_ne!(conflicting_bytes, saved.intent);
    assert_eq!(conflicting.intent.request_id, TRANSFER_REQUEST);
    assert_eq!(conflicting.intent.nonce, nonce);
    assert!(
        authenticate_paid_intent(
            &network.fixture.resolver,
            &network.fixture.context,
            &conflicting_bytes
        )
        .is_ok()
    );
    for (index, peer) in peers.iter().enumerate() {
        match peer.client().prepare_fastvote(&conflicting_bytes, None) {
            Err(ClientError::UnexpectedStatus { status, body }) => {
                assert_eq!(status, 400, "direct validator {index}");
                assert_eq!(body, "fastvote-rejected");
            }
            other => panic!("direct conflicting authenticated request must refuse: {other:?}"),
        }
        assert_original_intact(
            &network,
            &peers,
            &first,
            &saved,
            &reopened_again,
            &committed_view,
            "direct SDK conflict",
        );
    }
    let conflict_path: PathBuf = network.artifacts_dir.join("direct-conflicting.intent");
    write_private_new(&conflict_path, &conflicting_bytes);
    let conflict: Outputs = Outputs::new(&network.artifacts_dir, "direct-conflicting-replay");
    let output: Output = run_cli(replay_args(
        &network,
        &new_config,
        &conflict_path,
        None,
        &conflict,
    ));
    assert!(!output.status.success());
    assert!(lossy(&output.stdout).contains("fastvote_replay_mode=prepare_from_saved_intent"));
    assert_eq!(
        lossy(&output.stdout).matches(PREPARE_REFUSED).count(),
        VALIDATORS
    );
    assert!(lossy(&output.stderr).contains(INSUFFICIENT_QUORUM));
    for path in [
        &conflict.certificate,
        &conflict.availability,
        &conflict.result,
    ] {
        assert_reserved_empty(path, "direct conflict");
    }
    assert_absent(&conflict.intent, "direct conflict");
    assert_original_intact(
        &network,
        &peers,
        &first,
        &saved,
        &reopened_again,
        &committed_view,
        "direct CLI conflict",
    );
    for (path, bytes) in original_inputs {
        assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
    }
    for host in hosts {
        let stderr: Vec<u8> = host.guard.stop_orderly_interrupt_observed(PROCESS_DEADLINE);
        assert_native_termination_summary(&stderr, "sigint");
    }
}
