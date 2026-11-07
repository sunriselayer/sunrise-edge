//! Real offline author -> fresh SQLite prepare -> public preflight -> serving.
//! Every key here is disposable test material; no prepared target is seeded.

#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;

use compiled_source_host_process::{spawn_bounded_output, spawn_bounded_status_line};
use ed25519_zebra::SigningKey;
use node_core::genesis::{
    GenesisManifest, VerifiedGenesisRoot, decode_genesis_manifest, genesis_manifest_commitment,
};
use objects::{ObjectId, Owner};
use protocol_types::{AtomicityDomainId, HashSuiteId, ValidatorId};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    process::{Command, Output},
    time::Duration,
};
use sunrise_edge_client::{Client, ExpectedProtocolContext, LoopbackHttpTransport};
use sunrise_edge_operator::common::parse_hex_32;

#[path = "support/offline_genesis_fixture.rs"]
mod offline_genesis_fixture;
use offline_genesis_fixture::{Fixture, field, hex, refused, replace, success};

fn install_four_validator_pairs(fixture: &Fixture, path: &std::path::Path, digest: [u8; 32]) {
    for validator in 0usize..4 {
        let domain: AtomicityDomainId =
            AtomicityDomainId::new([0x61 + u8::try_from(validator).unwrap(); 32]).unwrap();
        let pins: Vec<OsString> = fixture.root_pins(path, digest, validator, domain);
        let mut prepare: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
        prepare
            .arg("prepare")
            .args(&pins)
            .args(["--created-checkpoint", "10"]);
        success(spawn_bounded_output(prepare, Duration::from_secs(30)));
        let mut preflight: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
        preflight.arg("preflight").args(&pins).args([
            "--validator-public-key",
            &hex(&fixture.validators[validator]),
        ]);
        let advisory: String = success(spawn_bounded_output(preflight, Duration::from_secs(30)));
        assert!(advisory.contains("advisory=true"));
        let state: PathBuf = fixture.directory.join(format!("state-{validator}.sqlite"));
        let store: SqliteDurableStore = SqliteDurableStore::open_existing(
            &state,
            SqliteNamespace::new(
                fixture.context.chain_id().clone(),
                ValidatorId::new(fixture.validators[validator]),
                domain,
            ),
        )
        .unwrap();
        assert_eq!(store.writer_fence().unwrap().get(), 1);
    }
}

#[test]
fn real_author_is_deterministic_and_installs_four_independent_validator_pairs() {
    let fixture: Fixture = Fixture::new();
    let line: String = success(fixture.author(&fixture.args));
    assert_eq!(field(&line, "genesis_authority="), hex(&fixture.authority));
    let digest: [u8; 32] = parse_hex_32(field(&line, "manifest_digest="), "digest").unwrap();
    let path: PathBuf = fixture.directory.join("genesis.bin");
    let bytes: Vec<u8> = fs::read(&path).unwrap();
    let manifest: GenesisManifest = decode_genesis_manifest(&bytes).unwrap();
    let root: VerifiedGenesisRoot =
        VerifiedGenesisRoot::verify_bytes(&fixture.resolver, &bytes, digest, &fixture.context)
            .unwrap();
    assert!(root.admission_profile().is_causal());
    assert_eq!(manifest.genesis_authority, fixture.authority);
    assert_eq!(manifest.validator_set.validators.len(), 4);
    assert_eq!(manifest.objects.len(), 8);
    assert_eq!(
        public_standard_asset::treasury_supply(&manifest.objects[1].object.data).unwrap(),
        3_004_000
    );
    assert_eq!(
        manifest.objects[1].object.owner,
        Owner::Address(objects::Address::new(fixture.owner))
    );
    assert_eq!(manifest.fee_policy.fee_recipient, fixture.owner);
    assert_eq!(
        manifest.fee_policy.calls,
        execution::paid_execution::PHASE_CALLS
    );
    assert_eq!(
        manifest.fee_policy.handles,
        u32::try_from(execution::paid_execution::PHASE_HANDLES).unwrap()
    );
    assert_eq!(
        manifest.fee_policy.creations,
        execution::paid_execution::PHASE_CREATIONS
    );
    assert_eq!(
        manifest.fee_policy.events,
        u32::try_from(execution::paid_execution::PHASE_EVENTS).unwrap()
    );
    assert_eq!(
        manifest.fee_policy.memory_bytes,
        u64::try_from(execution::paid_execution::PHASE_MEMORY_BYTES).unwrap()
    );
    assert_eq!(
        manifest.fee_policy.output_bytes,
        u64::try_from(execution::paid_execution::PHASE_OUTPUT_BYTES).unwrap()
    );
    let later: PathBuf = fixture.directory.join("later.bin");
    let mut second: Vec<OsString> = fixture.args.clone();
    replace(&mut second, "--output", later.clone().into_os_string());
    replace(&mut second, "--validation-domain", hex(&[0x42; 32]).into());
    replace(&mut second, "--validation-checkpoint", "999".into());
    std::thread::sleep(Duration::from_millis(2));
    let second_line: String = success(fixture.author(&second));
    assert_eq!(second_line, line);
    assert_eq!(
        fs::read(later).unwrap(),
        bytes,
        "discarded validation coordinates and clock cannot change manifest bytes"
    );
    install_four_validator_pairs(&fixture, &path, digest);
    let key: PathBuf = fixture.directory.join("validator.key");
    fs::write(&key, [0x51; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x61; 32]).unwrap();
    let pins: Vec<OsString> = fixture.root_pins(&path, digest, 0, domain);
    let mut generations: Vec<u64> = Vec::new();
    for _ in 0..2 {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
        command
            .args(&pins)
            .arg("--signing-key-file")
            .arg(&key)
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
        let startup_byte_cap: std::num::NonZeroUsize =
            compiled_source_host_process::compiled_host_startup_line_limit(
                fixture.context.chain_id().as_str(),
            );
        let (mut host, status) =
            spawn_bounded_status_line(command, Duration::from_secs(20), startup_byte_cap);
        let address: SocketAddr = field(&status, "listen=").parse().unwrap();
        generations.push(field(&status, "writer_generation=").parse().unwrap());
        let transport: LoopbackHttpTransport = LoopbackHttpTransport::new(
            address,
            Duration::from_secs(3),
            Duration::from_secs(3),
            Duration::from_secs(3),
            NonZeroUsize::new(8192).unwrap(),
            NonZeroUsize::new(1_048_576).unwrap(),
        )
        .unwrap();
        let client: Client<LoopbackHttpTransport> = Client::new(transport);
        let local: protocol_config::ProtocolConfig =
            sunrise_edge_operator::host_protocol_context::host_query_protocol_config(
                &fixture.resolver,
                domain,
                fixture.context.epoch(),
            )
            .unwrap();
        let auth: &protocol_config::TransactionAuthProfile =
            local.transaction_auth_profile.as_ref().unwrap();
        let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
            fixture.context.chain_id().clone(),
            fixture.context.protocol_version(),
            fixture.context.epoch(),
            HashSuiteId::new(1),
            auth.profile_id(),
            auth.signature_scheme_id().as_u16(),
            auth.address_binding().as_u16(),
            domain,
        )
        .unwrap();
        client.query_verified_context(&expected).unwrap();
        let object: node_wire::HttpObjectQueryResult =
            client.query_object(ObjectId::new([1; 32])).unwrap();
        assert!(matches!(
            object,
            node_wire::HttpObjectQueryResult::CurrentInline { .. }
        ));
        host.child_mut().kill().unwrap();
        host.child_mut().wait().unwrap();
    }
    assert_eq!(generations, vec![2, 3]);
}

/// Run only in the bounded root-inside-container multi-UID fixture. The
/// ordinary author and all four original installer pairs remain the oracle.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires disposable root-inside-container UID fixture"]
fn protected_author_reviews_three_exact_frames_and_installs_four_validator_pairs() {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
        process::{Child, ExitStatus, Stdio},
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const WORKER_UID: u32 = 10_001;
    const REVIEWER_UID: u32 = 10_002;
    assert!(std::env::var_os("SUNRISE_GENESIS_MULTIUID_FIXTURE").is_some());
    assert!(std::path::Path::new("/.dockerenv").exists());
    assert_eq!(
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line: &str| line.strip_prefix("Uid:")?.split_whitespace().nth(1))
            .unwrap(),
        "0"
    );
    let fixture: Fixture = Fixture::new();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    let binary: PathBuf = fixture.directory.join("standard_asset_genesis");
    fs::copy(env!("CARGO_BIN_EXE_standard_asset_genesis"), &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let worker_dir: PathBuf = fixture.directory.join("protected-worker");
    let socket_dir: PathBuf = fixture.directory.join("protected-socket");
    fs::create_dir(&worker_dir).unwrap();
    fs::create_dir(&socket_dir).unwrap();
    fs::set_permissions(&worker_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o750)).unwrap();
    let chown = |path: &std::path::Path| {
        let output: Output = Command::new("chown")
            .arg(format!("{WORKER_UID}:0"))
            .arg(path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    chown(&worker_dir);
    chown(&socket_dir);
    let key: PathBuf = worker_dir.join("genesis.key");
    fs::copy(fixture.directory.join("authority.key"), &key).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    chown(&key);
    let output_path: PathBuf = worker_dir.join("genesis.bin");
    let socket: PathBuf = socket_dir.join("genesis.sock");
    let state: PathBuf = worker_dir.join("approval.state");
    let config_path: PathBuf = worker_dir.join("config");
    let mut args: Vec<OsString> = fixture.args.clone();
    replace(
        &mut args,
        "--genesis-key-file",
        key.clone().into_os_string(),
    );
    replace(&mut args, "--output", output_path.clone().into_os_string());
    let mut contents: String = String::new();
    for pair in args[1..].chunks_exact(2) {
        contents.push_str(pair[0].to_str().unwrap());
        contents.push('=');
        contents.push_str(pair[1].to_str().unwrap());
        contents.push('\n');
    }
    fs::write(&config_path, &contents).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    chown(&config_path);
    let expiry: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1800;

    let spawn_worker = |phase: &str, state: &std::path::Path, expires: u64| -> Child {
        let mut command: Command = Command::new(&binary);
        command
            .args(["protected-worker", phase])
            .arg(&config_path)
            .arg(&socket)
            .arg(state)
            .arg(REVIEWER_UID.to_string())
            .arg(expires.to_string())
            .uid(WORKER_UID)
            .gid(0)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child: Child = command.spawn().unwrap();
        let end: Instant = Instant::now() + Duration::from_secs(10);
        while !socket.exists()
            || fs::symlink_metadata(&socket)
                .map(|metadata: fs::Metadata| metadata.permissions().mode() & 0o7777 != 0o660)
                .unwrap_or(true)
        {
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker exited before socket bind"
            );
            assert!(Instant::now() < end, "worker did not bind in time");
            std::thread::sleep(Duration::from_millis(20));
        }
        child
    };
    let wait = |child: &mut Child| -> ExitStatus {
        let end: Instant = Instant::now() + Duration::from_secs(40);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= end {
                child.kill().unwrap();
                let _ = child.wait();
                panic!("bounded protected child did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let review = |phase: &str, respond: bool| -> String {
        let mut command: Command = Command::new(&binary);
        command
            .args(["protected-review", phase])
            .arg(&socket)
            .arg(WORKER_UID.to_string())
            .arg(hex(&fixture.authority))
            .uid(REVIEWER_UID)
            .gid(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child: Child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines: BufReader<_> = BufReader::new(stdout);
        let mut captured: String = String::new();
        let digest: String = loop {
            let mut line: String = String::new();
            let count: usize = lines.read_line(&mut line).unwrap();
            assert!(count > 0, "reviewer exited before digest");
            assert!(
                captured.len() + line.len() < 12_000_000,
                "review output bound"
            );
            captured.push_str(&line);
            if let Some(value) = line.strip_prefix("review_digest=") {
                break value.trim().to_owned();
            }
        };
        let mut stdin: std::process::ChildStdin = child.stdin.take().unwrap();
        if respond {
            stdin
                .write_all(
                    format!(
                        "{} {digest}\n",
                        if phase == "revoke" {
                            "revoke"
                        } else {
                            "approve"
                        }
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        drop(stdin);
        lines.read_to_string(&mut captured).unwrap();
        assert_eq!(wait(&mut child).success(), respond, "reviewer outcome");
        assert_eq!(captured.contains("approval_sent=true"), respond);
        captured
    };

    // A root peer can reach the socket path through group 0 but is not the
    // trusted reviewer UID. The one-shot worker must close without state.
    let mut unauthorized_worker: Child = spawn_worker("nested", &state, expiry);
    let mut unauthorized: std::os::unix::net::UnixStream =
        std::os::unix::net::UnixStream::connect(&socket).unwrap();
    unauthorized
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut byte: [u8; 1] = [0];
    assert_eq!(unauthorized.read(&mut byte).unwrap(), 0);
    assert!(!wait(&mut unauthorized_worker).success());
    assert!(!state.exists());

    // The real reviewer can inspect the exact nested candidate and then close
    // stdin without approval. EOF must leave no retained approval or output.
    let mut disconnected_nested: Child = spawn_worker("nested", &state, expiry);
    let disconnected_nested_text: String = review("nested", false);
    assert!(disconnected_nested_text.contains("publication_signing_frame="));
    assert!(!wait(&mut disconnected_nested).success());
    assert!(!state.exists());
    assert!(!output_path.exists());

    let mut nested_worker: Child = spawn_worker("nested", &state, expiry);
    let socket_metadata: fs::Metadata = fs::symlink_metadata(&socket).unwrap();
    assert_eq!(socket_metadata.uid(), WORKER_UID);
    assert_eq!(socket_metadata.permissions().mode() & 0o7777, 0o660);
    assert_eq!(
        fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o7777,
        0o750
    );
    let private_key_probe: Output = Command::new("test")
        .arg("-r")
        .arg(&key)
        .uid(REVIEWER_UID)
        .gid(0)
        .output()
        .unwrap();
    assert!(
        !private_key_probe.status.success(),
        "reviewer could read protected key"
    );
    let nested_text: String = review("nested", true);
    assert!(nested_text.contains("publication_signing_frame="));
    assert!(nested_text.contains("initialization_signing_frame="));
    assert!(nested_text.contains("fee_policy_frame="));
    assert!(nested_text.contains("economics_policy_frame="));
    assert!(nested_text.contains("hash_schedule_0=0:1:1:1:1:1:1:1"));
    assert!(wait(&mut nested_worker).success());
    assert!(state.exists());
    assert!(!output_path.exists());
    let mut changed_reviewer: Command = Command::new(&binary);
    changed_reviewer
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg((REVIEWER_UID + 1).to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(
        changed_reviewer,
        Duration::from_secs(30),
    ));

    let validators_path: PathBuf = fixture.directory.join("validators.txt");
    let original_validators: Vec<u8> = fs::read(&validators_path).unwrap();
    fs::write(
        &validators_path,
        String::from_utf8(original_validators.clone())
            .unwrap()
            .replace(" 1 1000 ", " 2 1000 "),
    )
    .unwrap();
    let mut changed_worker: Command = Command::new(&binary);
    changed_worker
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(
        changed_worker,
        Duration::from_secs(30),
    ));
    fs::write(&validators_path, original_validators).unwrap();
    let allocations_path: PathBuf = fixture.directory.join("allocations.txt");
    let original_allocations: Vec<u8> = fs::read(&allocations_path).unwrap();
    fs::write(
        &allocations_path,
        String::from_utf8(original_allocations.clone())
            .unwrap()
            .replace("1000000", "1000001"),
    )
    .unwrap();
    let mut changed_nested: Command = Command::new(&binary);
    changed_nested
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(
        changed_nested,
        Duration::from_secs(30),
    ));
    fs::write(&allocations_path, original_allocations).unwrap();
    let changed_config: String = contents.replace(
        &format!("--origin-seed={}\n", hex(&[0x31; 32])),
        &format!("--origin-seed={}\n", hex(&[0x35; 32])),
    );
    assert_ne!(changed_config, contents);
    fs::write(&config_path, changed_config).unwrap();
    let mut changed_frame: Command = Command::new(&binary);
    changed_frame
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(changed_frame, Duration::from_secs(30)));
    fs::write(&config_path, &contents).unwrap();
    let original_state: Vec<u8> = fs::read(&state).unwrap();
    let mut expired_state: Vec<u8> = original_state.clone();
    expired_state[69..77].copy_from_slice(&(expiry - 1900).to_be_bytes());
    fs::write(&state, expired_state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    let mut expired_worker: Command = Command::new(&binary);
    expired_worker
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(
        expired_worker,
        Duration::from_secs(30),
    ));
    fs::write(&state, original_state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    let original_key: Vec<u8> = fs::read(&key).unwrap();
    fs::write(&key, [0x77; 32]).unwrap();
    let mut wrong_key: Command = Command::new(&binary);
    wrong_key
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(wrong_key, Duration::from_secs(30)));
    fs::write(&key, original_key).unwrap();

    // A disconnected outer review cannot publish a partially signed manifest
    // or consume the retained nested approval, even after the protected key
    // has been opened for the two independently reviewed inner frames.
    let retained_approval: Vec<u8> = fs::read(&state).unwrap();
    let mut disconnected_manifest: Child = spawn_worker("manifest", &state, 0);
    let disconnected_manifest_text: String = review("manifest", false);
    assert!(disconnected_manifest_text.contains("manifest_signing_frame="));
    assert!(!wait(&mut disconnected_manifest).success());
    assert_eq!(fs::read(&state).unwrap(), retained_approval);
    assert!(!output_path.exists());
    println!("genesis_protected_review_disconnects=both_refused");

    let mut manifest_worker: Child = spawn_worker("manifest", &state, 0);
    let manifest_text: String = review("manifest", true);
    assert!(manifest_text.contains("manifest_signing_frame="));
    assert!(wait(&mut manifest_worker).success());
    let protected_bytes: Vec<u8> = fs::read(&output_path).unwrap();
    let manifest: GenesisManifest = decode_genesis_manifest(&protected_bytes).unwrap();
    let digest: [u8; 32] = genesis_manifest_commitment(&fixture.resolver, &manifest)
        .unwrap()
        .bytes();
    VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &protected_bytes,
        digest,
        &fixture.context,
    )
    .unwrap();
    let ordinary_path: PathBuf = fixture.directory.join("ordinary.bin");
    let mut ordinary_args: Vec<OsString> = fixture.args.clone();
    replace(
        &mut ordinary_args,
        "--output",
        ordinary_path.clone().into_os_string(),
    );
    success(fixture.author(&ordinary_args));
    assert_eq!(protected_bytes, fs::read(&ordinary_path).unwrap());
    install_four_validator_pairs(&fixture, &output_path, digest);
    // The persisted review cannot be replayed into an existing output.
    let mut replay: Command = Command::new(&binary);
    replay
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(replay, Duration::from_secs(30)));

    let revoked_state: PathBuf = worker_dir.join("revoked.state");
    let mut revoked_nested: Child = spawn_worker("nested", &revoked_state, expiry);
    review("nested", true);
    assert!(wait(&mut revoked_nested).success());
    let mut revoke_worker: Child = spawn_worker("revoke", &revoked_state, 0);
    review("revoke", true);
    assert!(wait(&mut revoke_worker).success());
    assert!(worker_dir.join("revoked.state.revoked").exists());
    let mut revoked_manifest: Command = Command::new(&binary);
    revoked_manifest
        .args(["protected-worker", "manifest"])
        .arg(&config_path)
        .arg(&socket)
        .arg(&revoked_state)
        .arg(REVIEWER_UID.to_string())
        .arg("0")
        .uid(WORKER_UID)
        .gid(0);
    refused(spawn_bounded_output(
        revoked_manifest,
        Duration::from_secs(30),
    ));
}

#[test]
fn real_author_refuses_bad_configuration_key_and_existing_output_without_mutation() {
    let fixture: Fixture = Fixture::new();
    for (flag, replacement) in [
        ("--minimum-freeze-block-height", "0".to_owned()),
        ("--conversion-divisor", "0".to_owned()),
        ("--read-price", "1".to_owned()),
        ("--reserve-allowance", "1".to_owned()),
        ("--publish-artifact-byte-price", "0".to_owned()),
        ("--unbonding-epochs", "0".to_owned()),
        ("--max-validator-exposure", "99".to_owned()),
        ("--timeout-seconds", "0".to_owned()),
        ("--expected-genesis-authority", hex(&fixture.owner)),
    ] {
        let mut args: Vec<OsString> = fixture.args.clone();
        replace(&mut args, flag, replacement.into());
        refused(fixture.author(&args));
        assert!(
            !fixture.directory.join("genesis.bin").exists(),
            "{flag} created output"
        );
    }
    success(fixture.author(&fixture.args));
    let before: Vec<u8> = fs::read(fixture.directory.join("genesis.bin")).unwrap();
    refused(fixture.author(&fixture.args));
    assert_eq!(
        fs::read(fixture.directory.join("genesis.bin")).unwrap(),
        before
    );
    for input in ["authority.key", "validators.txt", "allocations.txt"] {
        let path: PathBuf = fixture.directory.join(input);
        let before: Vec<u8> = fs::read(&path).unwrap();
        let mut args: Vec<OsString> = fixture.args.clone();
        replace(&mut args, "--output", path.clone().into_os_string());
        refused(fixture.author(&args));
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn valid_outer_signature_does_not_make_a_bad_nested_publication_installable() {
    let fixture: Fixture = Fixture::new();
    success(fixture.author(&fixture.args));
    let bytes: Vec<u8> = fs::read(fixture.directory.join("genesis.bin")).unwrap();
    let mut manifest: GenesisManifest = decode_genesis_manifest(&bytes).unwrap();
    let request: &execution::publication::PublicationRequest = manifest.publication.request();
    let corrupted: execution::publication::PublicationRequest =
        execution::publication::PublicationRequest::new(
            request.artifact().clone(),
            request.nonce(),
            *request.artifact_digest(),
            [0; 64],
        );
    manifest.publication = execution::publication::PublicationSubmission::new(
        *manifest.publication.request_id(),
        corrupted,
    )
    .unwrap();
    manifest.signature = SigningKey::from([0x55; 32])
        .sign(&node_core::genesis::genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let altered: Vec<u8> = node_core::genesis::encode_genesis_manifest(&manifest).unwrap();
    let digest: [u8; 32] = genesis_manifest_commitment(&fixture.resolver, &manifest)
        .unwrap()
        .bytes();
    VerifiedGenesisRoot::verify_bytes(&fixture.resolver, &altered, digest, &fixture.context)
        .unwrap();
    let path: PathBuf = fixture.directory.join("bad-nested.bin");
    fs::write(&path, altered).unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x71; 32]).unwrap();
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
    command
        .arg("prepare")
        .args(fixture.root_pins(&path, digest, 0, domain))
        .args(["--created-checkpoint", "10"]);
    let output: Output = spawn_bounded_output(command, Duration::from_secs(30));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid publication signature"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    refused(output);
}

#[test]
fn real_author_refuses_duplicate_cross_object_and_bond_violations() {
    let fixture: Fixture = Fixture::new();
    let row =
        |id: [u8; 32], key: [u8; 32], power: u64, bond: u64, collateral: [u8; 32]| -> String {
            format!(
                "{} {} {power} {bond} {}\n",
                hex(&id),
                hex(&key),
                hex(&collateral)
            )
        };
    let variants: Vec<(&str, String)> = vec![
        (
            "duplicate validator ID",
            row([0x10; 32], fixture.validators[0], 1, 100, [0x81; 32])
                + row([0x10; 32], fixture.validators[1], 1, 100, [0x82; 32]).as_str(),
        ),
        (
            "registered public key",
            row([0x10; 32], fixture.validators[0], 1, 100, [0x81; 32])
                + row([0x11; 32], fixture.validators[0], 1, 100, [0x82; 32]).as_str(),
        ),
        (
            "object ID",
            row([0x10; 32], fixture.validators[0], 1, 100, [1; 32]),
        ),
        (
            "eligible bounded bond",
            row([0x10; 32], fixture.validators[0], 1, 0, [0x81; 32]),
        ),
        (
            "eligible bounded bond",
            row([0x10; 32], fixture.validators[0], 1, 50, [0x81; 32]),
        ),
        (
            "positive power",
            row([0x10; 32], fixture.validators[0], 0, 100, [0x81; 32]),
        ),
    ];
    let validators_file: PathBuf = fixture.directory.join("validators.txt");
    for (expected, content) in variants {
        fs::write(&validators_file, &content).unwrap();
        let output: Output = fixture.author(&fixture.args);
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        refused(output);
        assert!(!fixture.directory.join("genesis.bin").exists());
        assert_eq!(fs::read(&validators_file).unwrap(), content.into_bytes());
    }
}

#[test]
fn real_author_refuses_malformed_oversized_and_overflowing_tables() {
    let fixture: Fixture = Fixture::new();
    let validators_file: PathBuf = fixture.directory.join("validators.txt");

    let malformed: String = format!(
        "{} {} 1 100\n",
        hex(&fixture.validators[0]),
        hex(&fixture.validators[0])
    );
    fs::write(&validators_file, &malformed).unwrap();
    refused(fixture.author(&fixture.args));
    assert!(!fixture.directory.join("genesis.bin").exists());
    assert_eq!(fs::read(&validators_file).unwrap(), malformed.into_bytes());

    let oversized: Vec<u8> = vec![b'x'; 16 * 1024 + 1];
    fs::write(&validators_file, &oversized).unwrap();
    refused(fixture.author(&fixture.args));
    assert!(!fixture.directory.join("genesis.bin").exists());
    assert_eq!(fs::read(&validators_file).unwrap(), oversized);

    let overflow: String = format!(
        "{} {} 1 {} {}\n{} {} 1 100 {}\n",
        hex(&fixture.validators[0]),
        hex(&fixture.validators[0]),
        u64::MAX,
        hex(&[0x81; 32]),
        hex(&fixture.validators[1]),
        hex(&fixture.validators[1]),
        hex(&[0x82; 32])
    );
    fs::write(&validators_file, &overflow).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            fixture.directory.join("authority.key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    let output: Output = fixture.author(&fixture.args);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("supply overflow"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    refused(output);
    assert!(!fixture.directory.join("genesis.bin").exists());
    assert_eq!(fs::read(&validators_file).unwrap(), overflow.into_bytes());
}

#[test]
fn real_author_refuses_invalid_or_excess_allocation_objects() {
    let fixture: Fixture = Fixture::new();
    let allocations: PathBuf = fixture.directory.join("allocations.txt");
    let excess: String = (0xa0u8..0xbb)
        .map(|id: u8| format!("{} 1 {}\n", hex(&fixture.owner), hex(&[id; 32])))
        .collect();
    for (expected, content) in [
        ("allocation row", format!("{} 1\n", hex(&fixture.owner))),
        (
            "positive amount",
            format!("{} 0 {}\n", hex(&fixture.owner), hex(&[0x21; 32])),
        ),
        (
            "distinct Coin ID",
            format!("{} 1 {}\n", hex(&fixture.owner), hex(&[0x11; 32])),
        ),
        ("too many genesis objects", excess),
    ] {
        fs::write(&allocations, &content).unwrap();
        let output: Output = fixture.author(&fixture.args);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        refused(output);
        assert!(!fixture.directory.join("genesis.bin").exists());
        assert_eq!(fs::read(&allocations).unwrap(), content.into_bytes());
    }
}

#[test]
#[cfg(unix)]
fn real_author_refuses_unsafe_output_locations_and_protected_key_defects() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture: Fixture = Fixture::new();

    let real_parent: PathBuf = fixture.directory.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let link_parent: PathBuf = fixture.directory.join("link-parent");
    symlink(&real_parent, &link_parent).unwrap();
    let via_symlink: PathBuf = link_parent.join("genesis.bin");
    let mut args: Vec<OsString> = fixture.args.clone();
    replace(&mut args, "--output", via_symlink.clone().into_os_string());
    refused(fixture.author(&args));
    assert!(!via_symlink.exists());
    assert!(!real_parent.join("genesis.bin").exists());

    let symlink_target: PathBuf = fixture.directory.join("symlink-target.bin");
    let symlinked_output: PathBuf = fixture.directory.join("symlinked-output.bin");
    symlink(&symlink_target, &symlinked_output).unwrap();
    let mut args: Vec<OsString> = fixture.args.clone();
    replace(
        &mut args,
        "--output",
        symlinked_output.clone().into_os_string(),
    );
    refused(fixture.author(&args));
    assert!(!symlink_target.exists());

    let key_file: PathBuf = fixture.directory.join("authority.key");
    let authority_seed: [u8; 32] = [0x55; 32];
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
    refused(fixture.author(&fixture.args));
    assert!(!fixture.directory.join("genesis.bin").exists());
    assert_eq!(fs::read(&key_file).unwrap(), authority_seed);

    fs::write(&key_file, [0x55; 31]).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    refused(fixture.author(&fixture.args));
    assert!(!fixture.directory.join("genesis.bin").exists());
    assert_eq!(fs::read(&key_file).unwrap(), [0x55; 31]);

    fs::remove_file(&key_file).unwrap();
    let real_key: PathBuf = fixture.directory.join("real.key");
    fs::write(&real_key, authority_seed).unwrap();
    fs::set_permissions(&real_key, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&real_key, &key_file).unwrap();
    refused(fixture.author(&fixture.args));
    assert!(!fixture.directory.join("genesis.bin").exists());
}
