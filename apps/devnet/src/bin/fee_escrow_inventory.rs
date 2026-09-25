//! Offline, operator-confirmed FastVote fee-escrow inventory for one local
//! SQLite validator namespace. Never serves requests or seeds a database.
#![forbid(unsafe_code)]

use hashing::HashSuiteResolver;
use node_core::fee_claims::{FeeEscrowInventorySweep, verify_fee_escrow_inventory_all};
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule,
    ProtocolVersion, ValidatorId,
};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{error::Error, ffi::OsString, num::NonZeroUsize, path::PathBuf, process::ExitCode};
use sunrise_edge_devnet::{DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE};

struct Args {
    data_dir: PathBuf,
    chain: ChainId,
    validator: ValidatorId,
    domain: AtomicityDomainId,
    protocol_version: ProtocolVersion,
    schedule: Vec<HashSuiteSchedule>,
    page_size: NonZeroUsize,
    timeout_seconds: u64,
}

fn required(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("missing {flag}"))
}

fn set_once(slot: &mut Option<String>, flag: &str, value: String) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn parse_hex_32(value: &str, flag: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
        return Err(format!("{flag} must be 64 hex digits"));
    }
    let mut bytes: [u8; 32] = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{flag} contains invalid hex"))?;
    }
    Ok(bytes)
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
    let suite: HashSuite = HashSuite {
        id: HashSuiteId::new(id),
        transaction_hash: algorithm(2)?,
        object_digest: algorithm(3)?,
        effects_hash: algorithm(4)?,
        code_hash: algorithm(5)?,
        config_hash: algorithm(6)?,
        certificate_hash: algorithm(7)?,
    };
    Ok(HashSuiteSchedule {
        activation_epoch: Epoch::new(epoch),
        suite,
    })
}

fn parse_args(values: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut data_dir: Option<String> = None;
    let mut chain: Option<String> = None;
    let mut validator: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut protocol_version: Option<String> = None;
    let mut page_size: Option<String> = None;
    let mut timeout_seconds: Option<String> = None;
    let mut schedule: Vec<HashSuiteSchedule> = Vec::new();
    let mut confirmed: bool = false;
    let mut iterator = values.into_iter();
    while let Some(flag) = iterator.next() {
        let flag: String = flag.into_string().map_err(|_| "non-UTF8 flag")?;
        if flag == "--confirm-offline-fence-advance" {
            if confirmed {
                return Err("duplicate confirmation".into());
            }
            confirmed = true;
            continue;
        }
        let value: String = iterator
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?
            .into_string()
            .map_err(|_| format!("non-UTF8 value for {flag}"))?;
        match flag.as_str() {
            "--data-dir" => set_once(&mut data_dir, &flag, value)?,
            "--chain-id" => set_once(&mut chain, &flag, value)?,
            "--validator-id" => set_once(&mut validator, &flag, value)?,
            "--domain" => set_once(&mut domain, &flag, value)?,
            "--protocol-version" => set_once(&mut protocol_version, &flag, value)?,
            "--page-size" => set_once(&mut page_size, &flag, value)?,
            "--timeout-seconds" => set_once(&mut timeout_seconds, &flag, value)?,
            "--suite" => {
                if schedule.len() >= 64 {
                    return Err("too many suite entries (maximum 64)".into());
                }
                schedule.push(parse_suite(&value)?);
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if !confirmed {
        return Err("requires --confirm-offline-fence-advance: stop the node first; this command advances its writer fence and a running node must restart".into());
    }
    let data_dir: PathBuf = PathBuf::from(required(data_dir, "--data-dir")?);
    let chain: ChainId =
        ChainId::new(required(chain, "--chain-id")?).map_err(|_| "invalid chain id")?;
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &required(validator, "--validator-id")?,
        "--validator-id",
    )?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&required(domain, "--domain")?, "--domain")?)
            .map_err(|_| "zero atomicity domain")?;
    let protocol_version: u32 = required(protocol_version, "--protocol-version")?
        .parse()
        .map_err(|_| "invalid protocol version")?;
    if protocol_version == 0 {
        return Err("zero protocol version".into());
    }
    let page_size: usize = required(page_size, "--page-size")?
        .parse()
        .map_err(|_| "invalid page size")?;
    if !(1..=1024).contains(&page_size) {
        return Err("page size must be 1..=1024".into());
    }
    let timeout_seconds: u64 = required(timeout_seconds, "--timeout-seconds")?
        .parse()
        .map_err(|_| "invalid timeout")?;
    if !(1..=3600).contains(&timeout_seconds) {
        return Err("timeout seconds must be 1..=3600".into());
    }
    if schedule.is_empty() {
        return Err("at least one --suite is required".into());
    }
    Ok(Args {
        data_dir,
        chain,
        validator,
        domain,
        protocol_version: ProtocolVersion::new(protocol_version),
        schedule,
        page_size: NonZeroUsize::new(page_size).ok_or("zero page size")?,
        timeout_seconds,
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Args = parse_args(std::env::args_os().skip(1))?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(args.chain.clone(), args.protocol_version, args.schedule)?;
    let namespace: SqliteNamespace =
        SqliteNamespace::new(args.chain.clone(), args.validator, args.domain);
    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(args.data_dir.join(DEVNET_DATABASE_FILE), namespace)?;
    let blobs: SqliteBlobStore =
        SqliteBlobStore::open_existing(args.data_dir.join(DEVNET_BLOB_DATABASE_FILE))?;
    let now: u64 = SystemClock.now_unix_millis()?;
    let deadline: u64 = now
        .checked_add(
            args.timeout_seconds
                .checked_mul(1000)
                .ok_or("timeout overflow")?,
        )
        .ok_or("deadline overflow")?;
    let previous: WriterFenceGeneration = store.writer_fence()?;
    let generation: WriterFenceGeneration =
        previous.checked_next().ok_or("writer fence exhausted")?;
    store.advance_writer_fence(previous, generation)?;
    let mut correlation: [u8; 16] = [0; 16];
    correlation[..8].copy_from_slice(&generation.get().to_be_bytes());
    correlation[8..].copy_from_slice(&now.to_be_bytes());
    let context: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new(correlation).ok_or("invalid correlation id")?,
    );
    let result: FeeEscrowInventorySweep = verify_fee_escrow_inventory_all(
        &store,
        &blobs,
        &context,
        args.domain,
        &resolver,
        &[],
        &args.chain,
        args.page_size,
    )?;
    let current: WriterFenceGeneration = store.writer_fence()?;
    if current != generation {
        return Err("writer fence changed during inventory; discard the sweep".into());
    }
    if SystemClock.now_unix_millis()? >= deadline {
        return Err("inventory deadline expired before completion".into());
    }
    println!(
        "complete=true data_dir={} chain_id={} validator_id={} domain={} protocol_version={} writer_generation={} pages={} verified_rows={} verified_claims={} verified_payouts={}",
        args.data_dir.display(),
        args.chain,
        args.validator,
        args.domain,
        args.protocol_version.get(),
        generation.get(),
        result.pages,
        result.verified_rows,
        result.verified_claims,
        result.verified_payouts
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fee-escrow-inventory failed (no complete result): {error}");
            let mut source: Option<&(dyn Error + 'static)> = error.source();
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Vec<OsString> {
        [
            "--data-dir",
            "/missing",
            "--chain-id",
            "test",
            "--validator-id",
            &"11".repeat(32),
            "--domain",
            &"22".repeat(32),
            "--protocol-version",
            "3",
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--page-size",
            "2",
            "--timeout-seconds",
            "60",
            "--confirm-offline-fence-advance",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn requires_explicit_fence_advance_acknowledgement() {
        let mut values: Vec<OsString> = args();
        values.pop();
        assert!(parse_args(values).is_err());
        assert!(parse_args(args()).is_ok());
    }

    #[test]
    fn rejects_invalid_or_unbounded_schedule_and_page() {
        let mut values: Vec<OsString> = args();
        let position: usize = values
            .iter()
            .position(|value| value == "0:1:1:1:1:1:1:1")
            .unwrap();
        values[position] = OsString::from("0:1:3:1:1:1:1:1");
        assert!(parse_args(values).is_err());
        let mut values: Vec<OsString> = args();
        let position: usize = values
            .iter()
            .position(|value| value == &OsString::from("11".repeat(32)))
            .unwrap();
        values[position] = OsString::from("+1".repeat(32));
        assert!(parse_args(values).is_err());
        let mut values: Vec<OsString> = args();
        let position: usize = values.iter().position(|value| value == "2").unwrap();
        values[position] = OsString::from("1025");
        assert!(parse_args(values).is_err());
    }
}
