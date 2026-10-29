//! Offline, operator-confirmed FastVote fee-escrow inventory for one existing
//! PostgreSQL validator namespace. Never serves requests or seeds a database.
#![forbid(unsafe_code)]

use hashing::HashSuiteResolver;
use node_core::fee_claims::{FeeEscrowInventorySweep, verify_fee_escrow_inventory_all};
use postgres_rustls::MakeTlsConnector;
use protocol_types::{AtomicityDomainId, ChainId, HashSuiteSchedule, ProtocolVersion, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
    advance_writer_fence, inspect_namespace,
};
use std::{
    env,
    error::Error,
    ffi::OsString,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    process::ExitCode,
};

use sunrise_edge_operator::common::{
    connect_pool, parse_decimal_hash_suite as parse_suite, parse_hex_32,
};

struct Args {
    ca_der: PathBuf,
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

fn parse_args(values: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
    let mut ca_der: Option<String> = None;
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
            "--tls-root-der" => set_once(&mut ca_der, &flag, value)?,
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
        return Err("requires --confirm-offline-fence-advance: stop the validator first; this command advances its writer fence and the validator must restart".into());
    }
    let chain: ChainId =
        ChainId::new(required(chain, "--chain-id")?).map_err(|_| "invalid chain id")?;
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &required(validator, "--validator-id")?,
        "--validator-id",
    )?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&required(domain, "--domain")?, "--domain")?)
            .map_err(|_| "zero atomicity domain")?;
    let version: u32 = required(protocol_version, "--protocol-version")?
        .parse()
        .map_err(|_| "invalid protocol version")?;
    if version == 0 {
        return Err("zero protocol version".into());
    }
    let page: usize = required(page_size, "--page-size")?
        .parse()
        .map_err(|_| "invalid page size")?;
    if !(1..=1024).contains(&page) {
        return Err("page size must be 1..=1024".into());
    }
    let timeout: u64 = required(timeout_seconds, "--timeout-seconds")?
        .parse()
        .map_err(|_| "invalid timeout")?;
    if !(1..=3600).contains(&timeout) {
        return Err("timeout seconds must be 1..=3600".into());
    }
    if schedule.is_empty() {
        return Err("at least one --suite is required".into());
    }
    Ok(Args {
        ca_der: PathBuf::from(required(ca_der, "--tls-root-der")?),
        chain,
        validator,
        domain,
        protocol_version: ProtocolVersion::new(version),
        schedule,
        page_size: NonZeroUsize::new(page).ok_or("zero page size")?,
        timeout_seconds: timeout,
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Args = parse_args(env::args_os().skip(1))?;
    let pool: Pool<PostgresConnectionManager<MakeTlsConnector>> = connect_pool(
        &args.ca_der,
        // One structured scan and one blob read may overlap; leave room for
        // the final metadata check without waiting on a two-slot pool.
        NonZeroU32::new(4).ok_or("zero pool size")?,
    )?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(args.chain.clone(), args.protocol_version, args.schedule)?;
    let namespace: PostgresNamespace =
        PostgresNamespace::new(&args.chain, args.validator, args.domain)?;
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(3).ok_or("zero retry count")?)?;
    let store: PostgresDurableStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
    // Validate the blob schema and exact namespace before the disruptive
    // writer-fence advance, as the local SQLite operator does.
    let blobs: PostgresBlobStore<PostgresConnectionManager<MakeTlsConnector>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone())?;
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable")?;
    let previous: WriterFenceGeneration = inspect_namespace(&mut *connection, &namespace)?
        .ok_or("PostgreSQL namespace not bootstrapped")?
        .writer_fence();
    let generation: WriterFenceGeneration =
        previous.checked_next().ok_or("writer fence exhausted")?;
    let now: u64 = SystemClock.now_unix_millis()?;
    let deadline: u64 = now
        .checked_add(
            args.timeout_seconds
                .checked_mul(1000)
                .ok_or("timeout overflow")?,
        )
        .ok_or("deadline overflow")?;
    advance_writer_fence(&mut connection, &namespace, previous, generation)?;
    drop(connection);
    let mut correlation: [u8; 16] = [0; 16];
    correlation[..8].copy_from_slice(&generation.get().to_be_bytes());
    correlation[8..].copy_from_slice(&now.to_be_bytes());
    let context: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(deadline).ok_or("invalid deadline")?,
        StorageCorrelationId::new(correlation).ok_or("invalid correlation id")?,
    );
    // There is no authorized protocol-version activation path yet. The
    // command has no trusted historical-version resolver and must fail
    // closed rather than guessing one from retained database bytes.
    let historical_protocol_resolvers: [HashSuiteResolver; 0] = [];
    let result: FeeEscrowInventorySweep = verify_fee_escrow_inventory_all(
        &store,
        &blobs,
        &context,
        args.domain,
        &resolver,
        &historical_protocol_resolvers,
        &args.chain,
        args.page_size,
    )?;
    let mut connection = pool
        .get()
        .map_err(|_| "PostgreSQL TLS connection unavailable after sweep")?;
    let current: WriterFenceGeneration = inspect_namespace(&mut *connection, &namespace)?
        .ok_or("PostgreSQL namespace missing after sweep")?
        .writer_fence();
    if current != generation {
        return Err("writer fence changed during inventory; discard the sweep".into());
    }
    if SystemClock.now_unix_millis()? >= deadline {
        return Err("inventory deadline expired before completion".into());
    }
    println!(
        "complete=true backend=postgres chain_id={} validator_id={} domain={} protocol_version={} writer_generation={} pages={} verified_rows={} verified_claims={} verified_payouts={}",
        args.chain,
        args.validator,
        args.domain,
        args.protocol_version.get(),
        generation.get(),
        result.pages,
        result.verified_rows,
        result.verified_claims,
        result.verified_payouts,
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PostgreSQL fee-escrow inventory failed (no complete result): {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postgres::{Config, config::SslMode};
    use std::str::FromStr;
    use sunrise_edge_operator::common::require_tls_tcp_host;

    fn valid_args() -> Vec<OsString> {
        [
            "--tls-root-der",
            "/missing/root.der",
            "--chain-id",
            "paid-durable",
            "--validator-id",
            &"11".repeat(32),
            "--domain",
            &"08".repeat(32),
            "--protocol-version",
            "3",
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--page-size",
            "1",
            "--timeout-seconds",
            "60",
            "--confirm-offline-fence-advance",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn requires_offline_confirmation_and_closed_bounds() {
        let mut values: Vec<OsString> = valid_args();
        values.pop();
        assert!(parse_args(values).is_err());
        assert!(parse_args(valid_args()).is_ok());
        let mut values: Vec<OsString> = valid_args();
        let page: usize = values.iter().position(|value| value == "1").unwrap();
        values[page] = OsString::from("1025");
        assert!(parse_args(values).is_err());
    }

    #[test]
    fn inventory_argv_preserves_hex_forms_and_refusal_order() {
        let mixed: &str = "aBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaBaB";
        let mut values: Vec<OsString> = valid_args();
        for flag in ["--validator-id", "--domain"] {
            let index: usize = values
                .iter()
                .position(|value: &OsString| value == flag)
                .unwrap();
            values[index + 1] = OsString::from(mixed);
        }
        let args: Args = parse_args(values).unwrap();
        assert_eq!(args.validator.as_bytes(), &[0xab; 32]);
        assert_eq!(args.domain.as_bytes(), &[0xab; 32]);

        let mut values: Vec<OsString> = valid_args();
        for flag in ["--validator-id", "--domain"] {
            let index: usize = values
                .iter()
                .position(|value: &OsString| value == flag)
                .unwrap();
            values[index + 1] = OsString::from("bad");
        }
        assert_eq!(
            parse_args(values).err().unwrap(),
            "--validator-id must be 64 hex digits"
        );

        let mut values: Vec<OsString> = valid_args();
        let index: usize = values
            .iter()
            .position(|value: &OsString| value == "--domain")
            .unwrap();
        values[index + 1] =
            OsString::from("0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(parse_args(values).err().unwrap(), "zero atomicity domain");
    }

    #[test]
    fn tls_requires_one_tcp_host_and_never_allows_plaintext_fallback() {
        let mut missing: Config = Config::from_str("user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut missing).is_err());
        let mut unix: Config = Config::from_str("host=/tmp user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut unix).is_err());
        let mut multiple: Config = Config::from_str("host=a,b user=test dbname=test").unwrap();
        assert!(require_tls_tcp_host(&mut multiple).is_err());
        let mut disabled: Config =
            Config::from_str("host=localhost user=test dbname=test sslmode=disable").unwrap();
        require_tls_tcp_host(&mut disabled).unwrap();
        assert_eq!(disabled.get_ssl_mode(), SslMode::Require);
    }
}
