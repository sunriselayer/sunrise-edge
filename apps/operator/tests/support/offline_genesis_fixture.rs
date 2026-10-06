//! Disposable signed offline-genesis inputs shared by real author and inspector
//! processes. No raw database rows or production authority are manufactured.
#![allow(dead_code)]

use crate::compiled_source_host_process::spawn_bounded_output;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_operator::common::parse_hash_suite;

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<String>()
}

pub fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_ascii_whitespace()
        .find_map(|value: &str| value.strip_prefix(name))
        .unwrap()
}

pub fn replace(args: &mut [OsString], flag: &str, value: OsString) {
    let index: usize = args.iter().position(|arg: &OsString| arg == flag).unwrap();
    args[index + 1] = value;
}

pub fn success(output: Output) -> String {
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

pub fn refused(output: Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "refusal advertised success");
}

pub struct Fixture {
    pub directory: PathBuf,
    pub args: Vec<OsString>,
    pub resolver: HashSuiteResolver,
    pub context: PublicationContext,
    pub authority: [u8; 32],
    pub owner: [u8; 32],
    pub validators: Vec<[u8; 32]>,
}

impl Fixture {
    pub fn new() -> Self {
        Self::create(None)
    }

    pub fn with_chain(chain: &str) -> Self {
        Self::create(Some(chain))
    }

    fn create(chain_text: Option<&str>) -> Self {
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
        let chain: ChainId = ChainId::new(
            chain_text.map_or_else(|| format!("offline-author-{nonce}"), str::to_owned),
        )
        .unwrap();
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

    pub fn author(&self, args: &[OsString]) -> Output {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_standard_asset_genesis"));
        command.args(args);
        spawn_bounded_output(command, Duration::from_secs(30))
    }

    pub fn root_pins(
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
