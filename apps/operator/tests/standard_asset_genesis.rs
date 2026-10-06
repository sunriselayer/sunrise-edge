//! Real offline author -> fresh SQLite prepare -> public preflight -> serving.
//! Every key here is disposable test material; no prepared target is seeded.

#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;

use compiled_source_host_process::{spawn_bounded_output, spawn_bounded_status_line};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::genesis::{
    GenesisManifest, VerifiedGenesisRoot, decode_genesis_manifest, genesis_manifest_commitment,
};
use objects::{ObjectId, Owner};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteId, ProtocolVersion, ValidatorId,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{Client, ExpectedProtocolContext, LoopbackHttpTransport};
use sunrise_edge_operator::common::{parse_hash_suite, parse_hex_32};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<String>()
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_ascii_whitespace()
        .find_map(|value: &str| value.strip_prefix(name))
        .unwrap()
}

fn replace(args: &mut [OsString], flag: &str, value: OsString) {
    let index: usize = args.iter().position(|arg: &OsString| arg == flag).unwrap();
    args[index + 1] = value;
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let line: String = String::from_utf8(output.stdout).unwrap();
    assert_eq!(line.lines().count(), 1);
    assert!(line.starts_with("complete=true "));
    line
}

fn refused(output: Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal advertised success");
}

struct Fixture {
    directory: PathBuf,
    args: Vec<OsString>,
    resolver: HashSuiteResolver,
    context: PublicationContext,
    authority: [u8; 32],
    owner: [u8; 32],
    validators: Vec<[u8; 32]>,
}

impl Fixture {
    fn new() -> Self {
        let nonce: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-offline-author-{}-{nanos}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let key_file: PathBuf = directory.join("authority.key");
        let authority_seed: [u8; 32] = [0x55; 32];
        fs::write(&key_file, authority_seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let authority: [u8; 32] = VerificationKey::from(&SigningKey::from(authority_seed)).into();
        let owner: [u8; 32] = VerificationKey::from(&SigningKey::from([0x56; 32])).into();
        let validators: Vec<[u8; 32]> = (0x51u8..=0x54)
            .map(|seed: u8| {
                let public_key: [u8; 32] =
                    VerificationKey::from(&SigningKey::from([seed; 32])).into();
                public_key
            })
            .collect();
        let validator_table: String = validators
            .iter()
            .enumerate()
            .map(|(index, key): (usize, &[u8; 32])| {
                let byte: u8 = u8::try_from(index).unwrap() + 0x11;
                format!("{} {} 1 1000 {}\n", hex(key), hex(key), hex(&[byte; 32]))
            })
            .collect();
        let validators_file: PathBuf = directory.join("validators.txt");
        fs::write(&validators_file, validator_table).unwrap();
        let allocations_file: PathBuf = directory.join("allocations.txt");
        fs::write(
            &allocations_file,
            format!(
                "{} 1000000 {}\n{} 2000000 {}\n",
                hex(&owner),
                hex(&[0x21; 32]),
                hex(&owner),
                hex(&[0x22; 32])
            ),
        )
        .unwrap();
        let chain: ChainId = ChainId::new(format!("offline-author-{nonce}")).unwrap();
        let context: PublicationContext =
            PublicationContext::new(chain.clone(), ProtocolVersion::new(7), Epoch::new(0)).unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            chain.clone(),
            context.protocol_version(),
            vec![parse_hash_suite("0:1:1:1:1:1:1:1").unwrap()],
        )
        .unwrap();
        let mut args: Vec<OsString> = vec!["author".into()];
        for (flag, value) in [
            ("--chain-id", chain.as_str().to_owned()),
            ("--protocol-version", "7".to_owned()),
            ("--epoch", "0".to_owned()),
            ("--suite", "0:1:1:1:1:1:1:1".to_owned()),
            ("--minimum-freeze-block-height", "1".to_owned()),
            ("--expected-genesis-authority", hex(&authority)),
            ("--origin-seed", hex(&[0x31; 32])),
            ("--instance-seed", hex(&[0x32; 32])),
            ("--publication-request-id", hex(&[0x33; 32])),
            ("--initialization-request-id", hex(&[0x34; 32])),
            ("--definition-id", hex(&[1; 32])),
            ("--treasury-cap-id", hex(&[2; 32])),
            ("--mint-authority", hex(&owner)),
            ("--fee-recipient", hex(&owner)),
            ("--initialization-gas-limit", "500000".to_owned()),
            ("--base-fee", "10".to_owned()),
            ("--execution-price", "1".to_owned()),
            ("--read-price", "0".to_owned()),
            ("--write-price", "0".to_owned()),
            ("--storage-price", "0".to_owned()),
            ("--system-module-price", "0".to_owned()),
            ("--conversion-divisor", "1000".to_owned()),
            (
                "--reserve-allowance",
                execution::paid_execution::MIN_RESERVE_ALLOWANCE.to_string(),
            ),
            (
                "--settle-allowance",
                execution::paid_execution::MIN_SETTLE_ALLOWANCE.to_string(),
            ),
            ("--publish-artifact-byte-price", "1".to_owned()),
            ("--publish-closure-node-price", "1".to_owned()),
            ("--min-bond", "100".to_owned()),
            ("--unbonding-epochs", "7".to_owned()),
            ("--max-validator-exposure", "none".to_owned()),
            ("--validation-domain", hex(&[0x41; 32])),
            ("--validation-checkpoint", "10".to_owned()),
            ("--timeout-seconds", "30".to_owned()),
        ] {
            args.push(flag.into());
            args.push(value.into());
        }
        for (flag, value) in [
            ("--genesis-key-file", key_file),
            ("--validators-file", validators_file),
            ("--allocations-file", allocations_file),
            ("--output", directory.join("genesis.bin")),
        ] {
            args.push(flag.into());
            args.push(value.into_os_string());
        }
        Self {
            directory,
            args,
            resolver,
            context,
            authority,
            owner,
            validators,
        }
    }

    fn author(&self, args: &[OsString]) -> Output {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_standard_asset_genesis"));
        command.args(args);
        spawn_bounded_output(command, Duration::from_secs(30))
    }

    fn root_pins(
        &self,
        manifest: &Path,
        digest: [u8; 32],
        validator: usize,
        domain: AtomicityDomainId,
    ) -> Vec<OsString> {
        vec![
            "--chain-id".into(),
            self.context.chain_id().as_str().into(),
            "--protocol-version".into(),
            self.context.protocol_version().get().to_string().into(),
            "--epoch".into(),
            self.context.epoch().get().to_string().into(),
            "--suite".into(),
            "0:1:1:1:1:1:1:1".into(),
            "--validator-id".into(),
            hex(&self.validators[validator]).into(),
            "--domain".into(),
            hex(domain.as_bytes()).into(),
            "--genesis-manifest".into(),
            manifest.as_os_str().into(),
            "--expected-genesis-digest".into(),
            hex(&digest).into(),
            "--state-db".into(),
            self.directory
                .join(format!("state-{validator}.sqlite"))
                .into(),
            "--blob-db".into(),
            self.directory
                .join(format!("blob-{validator}.sqlite"))
                .into(),
        ]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
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
    for validator in 0usize..4 {
        let domain: AtomicityDomainId =
            AtomicityDomainId::new([0x61 + u8::try_from(validator).unwrap(); 32]).unwrap();
        let pins: Vec<OsString> = fixture.root_pins(&path, digest, validator, domain);
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
        let (mut host, status) = spawn_bounded_status_line(command, Duration::from_secs(20));
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
