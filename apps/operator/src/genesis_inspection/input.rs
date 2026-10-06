//! Closed public configuration for the offline original-genesis inspection
//! command. Parsing resolves every flag explicitly; it accepts no secret,
//! private key, provider, database, listener or environment-supplied trust.

use crate::common::{FlagSet, parse_hash_suite, parse_hex_32};
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion};
use std::{error::Error, ffi::OsString, path::PathBuf};

const FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--expected-genesis-authority",
    "--expected-manifest-digest",
    "--genesis-manifest",
    "--validation-domain",
    "--validation-checkpoint",
    "--timeout-seconds",
];

pub(super) struct Config {
    pub resolver: HashSuiteResolver,
    pub context: PublicationContext,
    pub authority: [u8; 32],
    pub expected_digest: [u8; 32],
    pub manifest: PathBuf,
    pub validation_domain: AtomicityDomainId,
    pub validation_checkpoint: u64,
    pub timeout_millis: u64,
}

fn decimal(value: &str, field: &str) -> Result<u64, Box<dyn Error>> {
    let number: u64 = value.parse().map_err(|_| format!("invalid {field}"))?;
    if number.to_string() != value {
        return Err(format!("{field} must be canonical unsigned decimal").into());
    }
    Ok(number)
}

fn number(flags: &mut FlagSet, field: &str) -> Result<u64, Box<dyn Error>> {
    decimal(&flags.one(field)?, field)
}

fn positive(flags: &mut FlagSet, field: &str) -> Result<u64, Box<dyn Error>> {
    let value: u64 = number(flags, field)?;
    if value == 0 {
        return Err(format!("{field} must be positive").into());
    }
    Ok(value)
}

fn public_key(value: [u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
    validate_ed25519_owner_address(&value, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)?;
    Ok(value)
}

/// Requires exactly eight colon-separated columns, each canonical unsigned
/// decimal, before handing the unchanged string to the existing shared
/// `parse_hash_suite`. This never alters that resolver's own behavior.
fn parse_suite(value: &str) -> Result<HashSuiteSchedule, Box<dyn Error>> {
    let fields: Vec<&str> = value.split(':').collect();
    if fields.len() != 8 {
        return Err(
            "--suite needs epoch:id:transaction:object:effects:code:config:certificate".into(),
        );
    }
    for (index, field) in fields.iter().enumerate() {
        decimal(field, &format!("--suite column {index}"))?;
    }
    Ok(parse_hash_suite(value)?)
}

impl Config {
    pub(super) fn parse(tokens: impl Iterator<Item = OsString>) -> Result<Self, Box<dyn Error>> {
        let mut flags: FlagSet = FlagSet::parse(tokens, FLAGS, &[])?;
        let chain: ChainId =
            ChainId::new(flags.one("--chain-id")?).map_err(|_| "invalid --chain-id")?;
        let protocol: u32 = u32::try_from(positive(&mut flags, "--protocol-version")?)
            .map_err(|_| "protocol version exceeds u32")?;
        let version: ProtocolVersion = ProtocolVersion::new(protocol);
        let epoch: Epoch = Epoch::new(number(&mut flags, "--epoch")?);
        let suites: Vec<String> = flags.many("--suite");
        if suites.is_empty() || suites.len() > 64 {
            return Err("one to 64 explicit --suite entries required".into());
        }
        let schedule: Vec<HashSuiteSchedule> = suites
            .iter()
            .map(|value: &String| parse_suite(value))
            .collect::<Result<Vec<HashSuiteSchedule>, Box<dyn Error>>>()?;
        let resolver: HashSuiteResolver = HashSuiteResolver::new(chain.clone(), version, schedule)?;
        let context: PublicationContext = PublicationContext::new(chain, version, epoch)?;
        let authority: [u8; 32] = public_key(parse_hex_32(
            &flags.one("--expected-genesis-authority")?,
            "--expected-genesis-authority",
        )?)?;
        let expected_digest: [u8; 32] = parse_hex_32(
            &flags.one("--expected-manifest-digest")?,
            "--expected-manifest-digest",
        )?;
        let manifest: PathBuf = PathBuf::from(flags.one("--genesis-manifest")?);
        let validation_domain: AtomicityDomainId = AtomicityDomainId::new(parse_hex_32(
            &flags.one("--validation-domain")?,
            "--validation-domain",
        )?)
        .map_err(|_| "zero validation domain")?;
        let validation_checkpoint: u64 = number(&mut flags, "--validation-checkpoint")?;
        let timeout_seconds: u64 = positive(&mut flags, "--timeout-seconds")?;
        let timeout_millis: u64 = timeout_seconds
            .checked_mul(1000)
            .ok_or("timeout overflow")?;
        if timeout_millis > native_http::MAX_INDEXED_OUTBOX_OPERATION_MILLIS {
            return Err("timeout exceeds the operator storage-operation bound".into());
        }
        let config: Self = Self {
            resolver,
            context,
            authority,
            expected_digest,
            manifest,
            validation_domain,
            validation_checkpoint,
            timeout_millis,
        };
        flags.finish()?;
        Ok(config)
    }
}
