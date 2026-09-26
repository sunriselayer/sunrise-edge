//! Live, multi-process PostgreSQL E2E for `fastvote_host_pg` driven by the
//! actual, compiled Rust CLI (DR-0148).
//!
//! Skips (with a diagnostic on stderr) unless `SUNRISE_EDGE_TEST_POSTGRES_URL`
//! is configured, exactly like every other live PostgreSQL test in this
//! repository. Bootstraps four independent PostgreSQL namespaces with the
//! real, compiled `fastvote_pg namespace-init`/`install-genesis` subcommands
//! (this binary never installs genesis itself), starts four real
//! `fastvote_host_pg` subprocesses -- one per validator, each opening only
//! its own already-bootstrapped namespace -- and drives them with
//! `sunrise_edge_cli::run` (the exact same entrypoint the shipped
//! `sunrise-edge-cli` binary's `main` calls): `contract paid-call
//! --fastvote-network` builds and signs a real ordinary paid `Call` through
//! the existing generic path, forms a real quorum certificate from the four
//! real running hosts, and applies it. `contract fastvote-replay` then
//! exercises exact-artifact replay from the files that first call was
//! required to persist before its mutating POSTs.

mod support;

use abi::{
    AccessEntry, AccessManifest, encode_access_manifest,
    package_types::encode_scoped_type_arguments,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use objects::AccessMode;
use postgres::Config;
use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    process::{Child, Command, Stdio},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{Client, LoopbackHttpTransport};
use support::cli::{
    CHECKPOINT, CliContext, DSN_ENV, admin_pool, current_fee_coin_ref, install_genesis,
    namespace_init, proxied_dsn, single_tcp_backend_addr, snapshot, to_hex, write_signing_key_file,
};
use support::genesis_fixture::{self, FastVoteGenesisFixture, SUITE_FLAG};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A `fastvote_host_pg` subprocess this test owns: killed on drop so a
/// failing assertion never leaks a background PostgreSQL-connected process.
struct HostProcess {
    child: Child,
    addr: SocketAddr,
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_new(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

fn temp_file(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(name)
}

/// Spawns one real `fastvote_host_pg` subprocess against `dsn`, waits for its
/// `complete=true ... listen=<addr>` status line, and returns the process
/// (kept alive) plus the real bound loopback address.
#[allow(clippy::too_many_arguments)]
fn spawn_host(
    ca_path: &std::path::Path,
    dsn: &str,
    chain_id: &str,
    validator_hex: &str,
    domain_hex: &str,
    manifest_path: &std::path::Path,
    digest_hex: &str,
    signing_key_path: &std::path::Path,
    listen_addr: &str,
) -> HostProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastvote_host_pg"));
    command
        .env(DSN_ENV, dsn)
        .args([
            "--tls-root-der",
            ca_path.to_str().unwrap(),
            "--chain-id",
            chain_id,
            "--validator-id",
            validator_hex,
            "--domain",
            domain_hex,
            "--protocol-version",
            "3",
            "--epoch",
            "0",
            "--suite",
            SUITE_FLAG,
            "--genesis-manifest",
            manifest_path.to_str().unwrap(),
            "--expected-genesis-digest",
            digest_hex,
            "--signing-key-file",
            signing_key_path.to_str().unwrap(),
            "--listen",
            listen_addr,
            "--created-checkpoint",
            CHECKPOINT,
            "--timeout-seconds",
            "20",
            "--max-connections",
            "4",
            "--max-concurrent",
            "4",
            "--confirm-offline-fence-advance",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap_or_else(|error| {
        panic!("failed to spawn fastvote_host_pg: {error}");
    });
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        line.clear();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 {
            let stderr = {
                let mut buffer = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut buffer);
                }
                buffer
            };
            let status = child.try_wait().ok().flatten();
            panic!(
                "fastvote_host_pg exited before printing its status line (status={status:?}): {stderr}"
            );
        }
        if line.starts_with("complete=true") {
            break;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for fastvote_host_pg to report its listen address");
        }
    }
    let addr: SocketAddr = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("listen="))
        .unwrap_or_else(|| panic!("fastvote_host_pg status line lacked listen=: {line}"))
        .parse()
        .unwrap_or_else(|error| panic!("invalid listen address in {line:?}: {error}"));
    // Detach the piped stdout reader thread implicitly: further output is
    // simply never read, which is fine for a bounded test process.
    std::mem::forget(reader);
    HostProcess { child, addr }
}

fn write_network_config(
    path: &std::path::Path,
    fixture: &FastVoteGenesisFixture,
    hosts: &[HostProcess],
) {
    let mut text = String::new();
    for (validator, host) in fixture.validators.iter().zip(hosts) {
        text.push_str(&format!("{} {} - -\n", validator.validator_id, host.addr));
    }
    fs::write(path, text).unwrap();
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn fastvote_host_pg_cli_multivalidator_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!(
            "skipping live PostgreSQL fastvote_host_pg CLI multi-validator E2E: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let _live_test_lock = support::LiveTestLock::acquire();

    let original_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr =
        single_tcp_backend_addr(&original_config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let dsn: String = proxied_dsn(&original_config, proxy.local_addr().port());

    let unique: String = format!(
        "hostcli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_network_fixture(&unique);

    let data_dir = std::env::temp_dir().join(format!("sunrise-fastvote-host-cli-e2e-{unique}"));
    fs::create_dir(&data_dir).unwrap();
    let _owned = TempDir(data_dir.clone());

    let ca_path = temp_file(&data_dir, "ca.der");
    write_new(&ca_path, &ca_der);
    let manifest_path = temp_file(&data_dir, "genesis-manifest");
    write_new(&manifest_path, &fixture.manifest_bytes);
    let digest_hex = to_hex(&fixture.manifest_digest);
    let domain_hex = format!("{}", fixture.domain);
    let chain_id = format!("{}", fixture.chain_id);

    let cli_context = CliContext {
        protocol_version: fixture.protocol_version,
        ca_path: &ca_path,
        dsn: &dsn,
        chain_id: chain_id.clone(),
        manifest_path: &manifest_path,
        digest_hex: digest_hex.clone(),
    };

    // ---- bootstrap four independent namespaces with the real fastvote_pg CLI ----
    let validator_hex: Vec<String> = fixture
        .validators
        .iter()
        .map(|validator| format!("{}", validator.validator_id))
        .collect();
    let key_paths: Vec<PathBuf> = fixture
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let (path, guard) = write_signing_key_file(&validator.seed);
            let dest = temp_file(&data_dir, &format!("signing-key-{index}"));
            fs::copy(&path, &dest).unwrap();
            drop(guard);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).unwrap();
            }
            dest
        })
        .collect();
    for validator_id_hex in &validator_hex {
        namespace_init(&cli_context, validator_id_hex, &domain_hex);
        install_genesis(&cli_context, validator_id_hex, &domain_hex, true);
    }

    // ---- start four real fastvote_host_pg hosts ----
    let mut hosts: Vec<HostProcess> = fixture
        .validators
        .iter()
        .zip(&validator_hex)
        .zip(&key_paths)
        .map(|((_validator, validator_hex), key_path)| {
            spawn_host(
                &ca_path,
                &dsn,
                &chain_id,
                validator_hex,
                &domain_hex,
                &manifest_path,
                &digest_hex,
                key_path,
                "127.0.0.1:0",
            )
        })
        .collect();

    let network_config_path = temp_file(&data_dir, "fastvote-network.conf");
    write_network_config(&network_config_path, &fixture, &hosts);

    // ---- real CLI call-building inputs ----
    let seed_path = temp_file(&data_dir, "sender.seed");
    write_new(&seed_path, "21".repeat(32).as_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let instance_record = fixture.instance_record();
    let instance_ref_path = temp_file(&data_dir, "instance-ref");
    write_new(
        &instance_ref_path,
        &sunrise_edge_client::local_execution::encode_instance_record(&instance_record).unwrap(),
    );
    // Rebuilt fresh before every mutating call: an owned object's
    // version/digest advances on every settlement (including a
    // discarded-effects `ApplicationFailed` charge), so a stale genesis-time
    // `ObjectRef` only works for the very first call against it.
    let write_access_path = |name: &str, object_ref: objects::ObjectRef| -> PathBuf {
        let path = temp_file(&data_dir, name);
        write_new(
            &path,
            &encode_access_manifest(&AccessManifest {
                entries: vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Write,
                }],
            })
            .unwrap(),
        );
        path
    };
    let access_path = write_access_path("access", fixture.fee_coin_ref());
    let type_args_path = temp_file(&data_dir, "type-args");
    write_new(
        &type_args_path,
        &encode_scoped_type_arguments(
            &fixture.chain_id,
            &[public_standard_asset::asset_type_argument(
                &fixture.definition_id(),
            )],
        )
        .unwrap(),
    );
    // Must be a genuine canonical prime-order Ed25519 public key: the
    // `transfer` entrypoint's owner-address validation
    // (`validate_ed25519_owner_address`) fails closed on arbitrary byte
    // patterns, independent of the active transaction-auth profile.
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x71; 32])).into();
    let args_path = temp_file(&data_dir, "args");
    write_new(
        &args_path,
        &public_standard_asset::transfer_arguments(&recipient).unwrap(),
    );
    // Deliberately not a valid curve point: exercises the charged-trap path
    // (`transfer_object`'s owner-address validation rejects it, but fee
    // reservation/settlement still commit a real charge and receipt).
    let invalid_recipient: [u8; 32] = [0x41; 32];
    let invalid_args_path = temp_file(&data_dir, "args-invalid-recipient");
    write_new(
        &invalid_args_path,
        &public_standard_asset::transfer_arguments(&invalid_recipient).unwrap(),
    );

    let base_flags = |request_id_hex: &str,
                      nonce: Option<u64>,
                      args_path: &std::path::Path,
                      access_path: &std::path::Path|
     -> Vec<OsString> {
        let mut flags: Vec<OsString> = [
            "contract",
            "paid-call",
            "--endpoint",
            &format!("{}", hosts[0].addr),
            "--expected-chain-id",
            &chain_id,
            "--expected-protocol-version",
            "3",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            &domain_hex,
            "--seed-file",
            seed_path.to_str().unwrap(),
            "--fee-source",
            &to_hex(fixture.fee_coin.as_bytes()),
            "--fee-access",
            "write",
            "--max-fee",
            "1000000",
            "--gas-limit",
            "100000",
            "--request-id",
            request_id_hex,
            "--instance-ref",
            instance_ref_path.to_str().unwrap(),
            "--entrypoint",
            "transfer",
            "--access",
            access_path.to_str().unwrap(),
            "--args",
            args_path.to_str().unwrap(),
            "--type-args",
            type_args_path.to_str().unwrap(),
            "--fastvote-network",
            network_config_path.to_str().unwrap(),
            "--fastvote-genesis-manifest",
            manifest_path.to_str().unwrap(),
            "--fastvote-expected-genesis-digest",
            &digest_hex,
            "--fastvote-deadline-seconds",
            "30",
            "--fastvote-per-request-cap-seconds",
            "10",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if let Some(nonce) = nonce {
            flags.push(OsString::from("--nonce"));
            flags.push(OsString::from(nonce.to_string()));
        }
        flags
    };

    // ---- charged trap first: a deterministically rejected application
    // still commits a real fee charge and receipt (HTTP 200 committed
    // Rejected, not a network failure). Must run before any transfer that
    // would move the fee coin's ownership away from the sender.
    let namespace0 = runtime_postgres::PostgresNamespace::new(
        &fixture.chain_id,
        fixture.validators[0].validator_id,
        fixture.domain,
    )
    .unwrap();
    let admin = admin_pool(&original_config);

    let trap_request_id: [u8; 32] = [0xD8; 32];
    let trap_signed_intent_out = temp_file(&data_dir, "signed-intent-trap");
    let trap_certificate_out = temp_file(&data_dir, "certificate-trap");
    let trap_result_out = temp_file(&data_dir, "result-trap");
    let mut trap_flags = base_flags(
        &to_hex(&trap_request_id),
        Some(0),
        &invalid_args_path,
        &access_path,
    );
    trap_flags.push(OsString::from("--fastvote-signed-intent-out"));
    trap_flags.push(OsString::from(trap_signed_intent_out.to_str().unwrap()));
    trap_flags.push(OsString::from("--fastvote-certificate-out"));
    trap_flags.push(OsString::from(trap_certificate_out.to_str().unwrap()));
    trap_flags.push(OsString::from("--result-out"));
    trap_flags.push(OsString::from(trap_result_out.to_str().unwrap()));
    let trap_outcome = sunrise_edge_cli::run(trap_flags);
    assert!(
        trap_outcome.is_err(),
        "a charged application trap must be reported as rejected, never as a fresh-retryable \
         success: {trap_outcome:?}"
    );
    assert!(
        trap_signed_intent_out.exists(),
        "the signed intent must still be durably persisted before the trap was even known"
    );
    assert!(
        trap_certificate_out.exists(),
        "the real quorum certificate must still be persisted for a charged trap"
    );
    let trap_result_bytes: Vec<u8> = fs::read(&trap_result_out).unwrap();
    let trap_result =
        sunrise_edge_client::decode_paid_execution_result(&trap_result_bytes).unwrap();
    assert_eq!(
        trap_result.status,
        sunrise_edge_client::PaidExecutionStatus::ApplicationFailed
    );
    assert!(trap_result.charged.is_some());
    let after_trap = snapshot(&admin, &namespace0, &fixture);
    assert_eq!(
        after_trap.next_nonce, 1,
        "a charged trap still consumes the sender's nonce exactly once"
    );
    // The subsequent positive-path call below independently proves the trap
    // discarded its effects (never moved the fee coin's ownership): it
    // reuses the exact same fee coin as its own `--fee-source`/`--access`,
    // which would fail closed with `PaidFeeSourceInvalid` were the sender no
    // longer its owner.

    // ---- positive path: a real CLI-built, CLI-signed paid Call over the
    // real four-host network ----
    let signed_intent_out = temp_file(&data_dir, "signed-intent-1");
    let certificate_out = temp_file(&data_dir, "certificate-1");
    let result_out = temp_file(&data_dir, "result-1");
    let fresh_access_path_1 = write_access_path(
        "access-2",
        current_fee_coin_ref(&admin, &namespace0, &fixture),
    );
    let mut flags = base_flags(
        &to_hex(&fixture.request_id),
        Some(1),
        &args_path,
        &fresh_access_path_1,
    );
    flags.push(OsString::from("--fastvote-signed-intent-out"));
    flags.push(OsString::from(signed_intent_out.to_str().unwrap()));
    flags.push(OsString::from("--fastvote-certificate-out"));
    flags.push(OsString::from(certificate_out.to_str().unwrap()));
    flags.push(OsString::from("--result-out"));
    flags.push(OsString::from(result_out.to_str().unwrap()));

    let outcome = sunrise_edge_cli::run(flags);
    assert!(
        outcome.is_ok(),
        "expected the real CLI paid-call to succeed over the real 4-host network: {outcome:?}"
    );
    assert!(
        signed_intent_out.exists(),
        "signed-intent artifact must be persisted"
    );
    assert!(
        certificate_out.exists(),
        "certificate artifact must be persisted"
    );
    let result_bytes: Vec<u8> = fs::read(&result_out).unwrap();
    assert_eq!(
        sunrise_edge_client::decode_paid_execution_result(&result_bytes)
            .unwrap()
            .status,
        sunrise_edge_client::PaidExecutionStatus::Success
    );

    // ---- exact replay: fastvote-replay from the saved artifacts must
    // return the identical committed result, not re-execute or reject as a
    // fresh request ----
    let replay_result_out = temp_file(&data_dir, "result-replay");
    let replay_flags: Vec<OsString> = [
        "contract",
        "fastvote-replay",
        "--expected-chain-id",
        &chain_id,
        "--expected-protocol-version",
        "3",
        "--expected-epoch",
        "0",
        "--expected-hash-suite-id",
        "1",
        "--expected-domain",
        &domain_hex,
        "--fastvote-network",
        network_config_path.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &digest_hex,
        "--fastvote-deadline-seconds",
        "30",
        "--fastvote-per-request-cap-seconds",
        "10",
        "--submission",
        signed_intent_out.to_str().unwrap(),
        "--certificate",
        certificate_out.to_str().unwrap(),
        "--result-out",
        replay_result_out.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let replay_outcome = sunrise_edge_cli::run(replay_flags);
    assert!(
        replay_outcome.is_ok(),
        "expected exact replay from saved artifacts to succeed: {replay_outcome:?}"
    );
    assert_eq!(fs::read(&replay_result_out).unwrap(), result_bytes);

    // ---- request-id reuse conflict: a second, different call reusing the
    // exact same request id must be rejected, and durable state must remain
    // exactly what the first successful call left ----
    let before_conflict = snapshot(&admin, &namespace0, &fixture);

    let fresh_access_path_2 = write_access_path(
        "access-3",
        current_fee_coin_ref(&admin, &namespace0, &fixture),
    );
    let mut conflicting = base_flags(
        &to_hex(&fixture.request_id),
        Some(2),
        &args_path,
        &fresh_access_path_2,
    );
    conflicting.push(OsString::from("--fastvote-signed-intent-out"));
    conflicting.push(OsString::from(
        temp_file(&data_dir, "signed-intent-conflict")
            .to_str()
            .unwrap(),
    ));
    conflicting.push(OsString::from("--fastvote-certificate-out"));
    conflicting.push(OsString::from(
        temp_file(&data_dir, "certificate-conflict")
            .to_str()
            .unwrap(),
    ));
    let conflict_outcome = sunrise_edge_cli::run(conflicting);
    assert!(
        conflict_outcome.is_err(),
        "expected a conflicting request-id reuse to be rejected, not silently accepted"
    );
    assert_eq!(
        snapshot(&admin, &namespace0, &fixture),
        before_conflict,
        "a rejected conflicting request-id reuse must leave the certificate record, fee-coin \
         object and sender nonce exactly as the first successful call left them"
    );

    // ---- trap replay: replaying the exact charged-trap certificate must
    // return the identical committed trap outcome, never re-execute ----
    let trap_replay_result_out = temp_file(&data_dir, "result-trap-replay");
    let trap_replay_flags: Vec<OsString> = [
        "contract",
        "fastvote-replay",
        "--expected-chain-id",
        &chain_id,
        "--expected-protocol-version",
        "3",
        "--expected-epoch",
        "0",
        "--expected-hash-suite-id",
        "1",
        "--expected-domain",
        &domain_hex,
        "--fastvote-network",
        network_config_path.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &digest_hex,
        "--fastvote-deadline-seconds",
        "30",
        "--fastvote-per-request-cap-seconds",
        "10",
        "--submission",
        trap_signed_intent_out.to_str().unwrap(),
        "--certificate",
        trap_certificate_out.to_str().unwrap(),
        "--result-out",
        trap_replay_result_out.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let before_trap_replay = snapshot(&admin, &namespace0, &fixture);
    let trap_replay_outcome = sunrise_edge_cli::run(trap_replay_flags);
    assert!(
        trap_replay_outcome.is_err(),
        "replaying an exact charged-trap certificate must report the same committed rejection, \
         never a fresh retry"
    );
    assert_eq!(
        fs::read(&trap_replay_result_out).unwrap(),
        trap_result_bytes
    );
    assert_eq!(
        snapshot(&admin, &namespace0, &fixture),
        before_trap_replay,
        "replaying an already-committed charged-trap certificate must never re-execute or \
         mutate durable state a second time"
    );

    // ---- stale writer fence: a rival process claiming a fresh fence over
    // the exact same namespace leaves the original host's connection stale,
    // and it must fail closed rather than serve or mutate anything further ----
    let rival_request_id: [u8; 32] = [0xE5; 32];
    let rival_signed_bytes: Vec<u8> = fixture.sign_transfer(rival_request_id, 3, recipient);
    let stale_host_addr = hosts[0].addr;
    let rival = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[0],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_paths[0],
        "127.0.0.1:0",
    );
    assert_ne!(
        rival.addr, stale_host_addr,
        "the rival must be a genuinely separate live process, not the original"
    );
    let stale_client: Client<LoopbackHttpTransport> = Client::new(
        LoopbackHttpTransport::new(
            stale_host_addr,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            NonZeroUsize::new(64 * 1024).unwrap(),
            NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let stale_result = stale_client.prepare_fastvote(&rival_signed_bytes, None);
    assert!(
        stale_result.is_err(),
        "a prepare request against a fenced-out stale host must fail closed, not succeed: \
         {stale_result:?}"
    );
    drop(rival);

    // ---- real close/reopen: killing and restarting the same validator's
    // host process against its already-populated namespace must never
    // install a second genesis, and exact replay of both the already-
    // committed success and charged-trap certificates must return their
    // identical durable outcomes, proving persistence survives the restart
    // and neither replay re-executes ----
    hosts[0].child.kill().unwrap();
    hosts[0].child.wait().unwrap();
    let reopened = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[0],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_paths[0],
        &stale_host_addr.to_string(),
    );
    assert_eq!(
        reopened.addr, stale_host_addr,
        "reopening must rebind the exact same address the network config already points at"
    );
    hosts[0] = reopened;

    let before_reopen_replay = snapshot(&admin, &namespace0, &fixture);
    let reopened_success_replay_flags: Vec<OsString> = [
        "contract",
        "fastvote-replay",
        "--expected-chain-id",
        &chain_id,
        "--expected-protocol-version",
        "3",
        "--expected-epoch",
        "0",
        "--expected-hash-suite-id",
        "1",
        "--expected-domain",
        &domain_hex,
        "--fastvote-network",
        network_config_path.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &digest_hex,
        "--fastvote-deadline-seconds",
        "30",
        "--fastvote-per-request-cap-seconds",
        "10",
        "--submission",
        signed_intent_out.to_str().unwrap(),
        "--certificate",
        certificate_out.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let reopened_success_replay_outcome = sunrise_edge_cli::run(reopened_success_replay_flags);
    assert!(
        reopened_success_replay_outcome.is_ok(),
        "exact replay of the already-committed success certificate must still succeed after a \
         real close/reopen of the validator's host process: {reopened_success_replay_outcome:?}"
    );
    assert_eq!(
        snapshot(&admin, &namespace0, &fixture),
        before_reopen_replay,
        "replaying an already-committed success certificate after a real close/reopen must \
         never mutate durable state a second time"
    );

    let reopened_trap_replay_flags: Vec<OsString> = [
        "contract",
        "fastvote-replay",
        "--expected-chain-id",
        &chain_id,
        "--expected-protocol-version",
        "3",
        "--expected-epoch",
        "0",
        "--expected-hash-suite-id",
        "1",
        "--expected-domain",
        &domain_hex,
        "--fastvote-network",
        network_config_path.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &digest_hex,
        "--fastvote-deadline-seconds",
        "30",
        "--fastvote-per-request-cap-seconds",
        "10",
        "--submission",
        trap_signed_intent_out.to_str().unwrap(),
        "--certificate",
        trap_certificate_out.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let reopened_trap_replay_outcome = sunrise_edge_cli::run(reopened_trap_replay_flags);
    assert!(
        reopened_trap_replay_outcome.is_err(),
        "exact replay of the already-committed charged-trap certificate must still report the \
         same rejection after a real close/reopen: {reopened_trap_replay_outcome:?}"
    );
    assert_eq!(
        snapshot(&admin, &namespace0, &fixture),
        before_reopen_replay,
        "replaying an already-committed charged-trap certificate after a real close/reopen must \
         never mutate durable state a second time"
    );

    drop(hosts);
}
