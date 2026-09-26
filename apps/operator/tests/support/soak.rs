//! Strict parser and fixture-context validator for the DR-0146 certified
//! load/recovery soak workload's `handoff.kv` file.
//!
//! The recovery reader never treats the handoff file as authoritative for
//! correctness: every field is parsed under an exact bounded grammar (no
//! duplicate, missing or unknown keys; no partial/oversized/non-printable
//! values) and then independently cross-checked against the fixed fixture
//! protocol context and the derived-count invariants (`expected_claims ==
//! 4 * expected_rows`, `expected_payouts == expected_rows`) before any
//! caller may act on it. The caller must separately re-verify the
//! `writer_generation` field against the live, currently persisted
//! PostgreSQL namespace fence -- this module has no access to the database
//! and cannot do that itself.
#![allow(dead_code)]

use std::{collections::BTreeMap, fs, path::Path};

/// Environment variable naming the fresh temporary directory the soak
/// driver (`scripts/check-postgres-soak.sh`) owns for the whole run. The
/// workload publishes `HANDOFF_FILE_NAME` into it only after completing its
/// full lifecycle and restart checks; the recovery reader only ever reads.
pub const SOAK_DIR_ENV: &str = "SUNRISE_EDGE_SOAK_DIR";

/// Bounded count of real `fee_escrow_inventory_pg` invocations the recovery
/// reader performs, one namespace writer-fence generation apart.
pub const RECOVERY_CYCLES_ENV: &str = "SUNRISE_EDGE_SOAK_RECOVERY_CYCLES";
pub const RECOVERY_CYCLES_MIN: u32 = 1;
pub const RECOVERY_CYCLES_MAX: u32 = 32;

/// Explicit disposable-test confirmation the manual runner requires; never
/// implied by a live database URL alone.
pub const CONFIRM_DISPOSABLE_ENV: &str = "SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE";

pub const HANDOFF_FILE_NAME: &str = "handoff.kv";
const MAX_HANDOFF_BYTES: u64 = 4096;
const MAX_VALUE_LEN: usize = 256;

/// The fixed DR-0143/DR-0146 fixture protocol context every handoff must
/// name exactly: chain `paid-durable`, all-`0x08` atomicity domain, protocol
/// version 3, epoch 0, and the genesis (`sha2-256` everywhere) hash suite.
pub const FIXTURE_CHAIN_ID: &str = "paid-durable";
pub const FIXTURE_DOMAIN_HEX: &str =
    "0808080808080808080808080808080808080808080808080808080808080808";
pub const FIXTURE_PROTOCOL_VERSION: u32 = 3;
pub const FIXTURE_EPOCH: u64 = 0;
pub const FIXTURE_SUITE: &str = "0:1:1:1:1:1:1:1";

const REQUIRED_KEYS: [&str; 12] = [
    "schema_version",
    "validator_id",
    "chain_id",
    "domain",
    "protocol_version",
    "epoch",
    "suite",
    "expected_rows",
    "expected_claims",
    "expected_payouts",
    "writer_generation",
    "workload_elapsed_ms",
];

/// One parsed, structurally valid `handoff.kv`. Structural validity alone
/// grants no authority: callers must additionally call
/// [`validate_against_fixture`] and independently confirm `writer_generation`
/// against the live database before treating any field as trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    pub validator_id: String,
    pub chain_id: String,
    pub domain: String,
    pub protocol_version: u32,
    pub epoch: u64,
    pub suite: String,
    pub expected_rows: u32,
    pub expected_claims: u32,
    pub expected_payouts: u32,
    pub writer_generation: u64,
    pub workload_elapsed_ms: u64,
}

fn parse_decimal<T: std::str::FromStr>(value: &str, field: &str) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "{field} must be a plain decimal integer, got {value:?}"
        ));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(format!(
            "{field} has a non-canonical leading zero: {value:?}"
        ));
    }
    value
        .parse::<T>()
        .map_err(|_| format!("{field} value out of range: {value:?}"))
}

fn require_lowercase_hex64(value: &str, field: &str) -> Result<(), String> {
    let is_hex = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !is_hex {
        return Err(format!(
            "{field} must be exactly 64 lowercase hex digits, got {value:?}"
        ));
    }
    Ok(())
}

fn require_suite_shape(value: &str, field: &str) -> Result<(), String> {
    let fields: Vec<&str> = value.split(':').collect();
    if fields.len() != 8 {
        return Err(format!(
            "{field} must have exactly 8 colon-separated decimal fields, got {value:?}"
        ));
    }
    for entry in &fields {
        let _: u64 = parse_decimal(entry, field)?;
    }
    if fields[1] == "0" {
        return Err(format!("{field} has a zero suite id"));
    }
    Ok(())
}

/// Parses `content` under an exact bounded grammar: newline-terminated
/// `key=value` lines, no blank lines, no duplicate/missing/unknown keys,
/// ASCII-graphic values bounded to [`MAX_VALUE_LEN`] bytes. Never panics on
/// malformed input.
pub fn parse_handoff(content: &str) -> Result<Handoff, String> {
    if content.is_empty() {
        return Err("handoff is empty".to_owned());
    }
    let mut lines: Vec<&str> = content.split('\n').collect();
    let Some(trailer) = lines.pop() else {
        return Err("handoff has no content".to_owned());
    };
    if !trailer.is_empty() {
        return Err("handoff must be newline-terminated with no trailing partial line".to_owned());
    }
    if lines.is_empty() {
        return Err("handoff has no fields".to_owned());
    }

    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in &lines {
        if line.is_empty() {
            return Err("handoff contains a blank line".to_owned());
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("handoff line is missing '=': {line:?}"));
        };
        if key.is_empty() || value.is_empty() {
            return Err(format!("handoff line has an empty key or value: {line:?}"));
        }
        if !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit())
        {
            return Err(format!("handoff key has unexpected characters: {key:?}"));
        }
        if value.len() > MAX_VALUE_LEN || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(format!(
                "handoff value for {key:?} is oversized or non-printable"
            ));
        }
        if fields.insert(key, value).is_some() {
            return Err(format!("duplicate handoff key {key:?}"));
        }
    }
    if fields.len() != REQUIRED_KEYS.len() {
        return Err(format!(
            "handoff must have exactly {} keys, found {}",
            REQUIRED_KEYS.len(),
            fields.len()
        ));
    }
    for key in REQUIRED_KEYS {
        if !fields.contains_key(key) {
            return Err(format!("handoff is missing required key {key:?}"));
        }
    }

    let schema_version: u32 = parse_decimal(fields["schema_version"], "schema_version")?;
    if schema_version != 1 {
        return Err(format!(
            "unsupported handoff schema_version {schema_version}"
        ));
    }
    let validator_id: &str = fields["validator_id"];
    require_lowercase_hex64(validator_id, "validator_id")?;
    let chain_id: &str = fields["chain_id"];
    if chain_id.is_empty() || chain_id.len() > 128 {
        return Err(format!(
            "chain_id has an invalid bounded length: {chain_id:?}"
        ));
    }
    let domain: &str = fields["domain"];
    require_lowercase_hex64(domain, "domain")?;
    let protocol_version: u32 = parse_decimal(fields["protocol_version"], "protocol_version")?;
    if protocol_version == 0 {
        return Err("protocol_version must be nonzero".to_owned());
    }
    let epoch: u64 = parse_decimal(fields["epoch"], "epoch")?;
    let suite: &str = fields["suite"];
    require_suite_shape(suite, "suite")?;
    let expected_rows: u32 = parse_decimal(fields["expected_rows"], "expected_rows")?;
    if !(1..=4096).contains(&expected_rows) {
        return Err(format!(
            "expected_rows {expected_rows} is out of bounds [1, 4096]"
        ));
    }
    let expected_claims: u32 = parse_decimal(fields["expected_claims"], "expected_claims")?;
    let expected_payouts: u32 = parse_decimal(fields["expected_payouts"], "expected_payouts")?;
    let writer_generation: u64 = parse_decimal(fields["writer_generation"], "writer_generation")?;
    if writer_generation == 0 {
        return Err("writer_generation must be nonzero".to_owned());
    }
    let workload_elapsed_ms: u64 =
        parse_decimal(fields["workload_elapsed_ms"], "workload_elapsed_ms")?;

    Ok(Handoff {
        validator_id: validator_id.to_owned(),
        chain_id: chain_id.to_owned(),
        domain: domain.to_owned(),
        protocol_version,
        epoch,
        suite: suite.to_owned(),
        expected_rows,
        expected_claims,
        expected_payouts,
        writer_generation,
        workload_elapsed_ms,
    })
}

/// Cross-checks a structurally parsed [`Handoff`] against the fixed fixture
/// protocol context and the derived-count invariants. This never trusts the
/// handoff's own claims about the context it ran under; every field is
/// compared to the constant expected value.
pub fn validate_against_fixture(handoff: &Handoff) -> Result<(), String> {
    if handoff.chain_id != FIXTURE_CHAIN_ID {
        return Err(format!(
            "handoff chain_id {:?} does not match the fixture chain {FIXTURE_CHAIN_ID:?}",
            handoff.chain_id
        ));
    }
    if handoff.domain != FIXTURE_DOMAIN_HEX {
        return Err(format!(
            "handoff domain {:?} does not match the fixture domain {FIXTURE_DOMAIN_HEX:?}",
            handoff.domain
        ));
    }
    if handoff.protocol_version != FIXTURE_PROTOCOL_VERSION {
        return Err(format!(
            "handoff protocol_version {} does not match the fixture protocol_version {FIXTURE_PROTOCOL_VERSION}",
            handoff.protocol_version
        ));
    }
    if handoff.epoch != FIXTURE_EPOCH {
        return Err(format!(
            "handoff epoch {} does not match the fixture epoch {FIXTURE_EPOCH}",
            handoff.epoch
        ));
    }
    if handoff.suite != FIXTURE_SUITE {
        return Err(format!(
            "handoff suite {:?} does not match the fixture suite {FIXTURE_SUITE:?}",
            handoff.suite
        ));
    }
    let expected_claims: u32 = handoff
        .expected_rows
        .checked_mul(4)
        .ok_or("expected_rows overflows the 4x claims invariant")?;
    if handoff.expected_claims != expected_claims {
        return Err(format!(
            "handoff expected_claims {} does not equal 4 * expected_rows ({expected_claims})",
            handoff.expected_claims
        ));
    }
    if handoff.expected_payouts != handoff.expected_rows {
        return Err(format!(
            "handoff expected_payouts {} does not equal expected_rows {}",
            handoff.expected_payouts, handoff.expected_rows
        ));
    }
    Ok(())
}

/// Reads, parses and fixture-validates `dir`'s `handoff.kv`. Refuses a
/// missing file, a symlink (never follows one), an empty or oversized file,
/// or content failing either [`parse_handoff`] or [`validate_against_fixture`].
/// Still grants no authority over the live database: the caller must
/// separately cross-check `writer_generation` against the currently
/// persisted namespace fence before proceeding.
pub fn read_and_validate_handoff(dir: &Path) -> Result<Handoff, String> {
    let path = dir.join(HANDOFF_FILE_NAME);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("handoff.kv missing at {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "handoff.kv at {} is not a plain regular file (symlink or other)",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_HANDOFF_BYTES {
        return Err(format!(
            "handoff.kv at {} has a disallowed size {} bytes",
            path.display(),
            metadata.len()
        ));
    }
    let content: String =
        fs::read_to_string(&path).map_err(|error| format!("failed reading handoff.kv: {error}"))?;
    let handoff: Handoff = parse_handoff(&content)?;
    validate_against_fixture(&handoff)?;
    Ok(handoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    /// Deletes its temp directory recursively on drop, best-effort.
    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fresh_dir(label: &str) -> TempDirGuard {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-soak-handoff-file-test-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&path).unwrap();
        TempDirGuard(path)
    }

    fn valid_handoff_bytes() -> Vec<u8> {
        format!(
            "schema_version=1\n\
             validator_id={}\n\
             chain_id={FIXTURE_CHAIN_ID}\n\
             domain={FIXTURE_DOMAIN_HEX}\n\
             protocol_version={FIXTURE_PROTOCOL_VERSION}\n\
             epoch={FIXTURE_EPOCH}\n\
             suite={FIXTURE_SUITE}\n\
             expected_rows=8\n\
             expected_claims=32\n\
             expected_payouts=8\n\
             writer_generation=2\n\
             workload_elapsed_ms=1\n",
            "11".repeat(32),
        )
        .into_bytes()
    }

    #[test]
    fn valid_handoff_file_reads_successfully() {
        let dir: TempDirGuard = fresh_dir("valid");
        fs::write(dir.0.join(HANDOFF_FILE_NAME), valid_handoff_bytes()).unwrap();
        assert!(read_and_validate_handoff(&dir.0).is_ok());
    }

    #[test]
    fn missing_handoff_file_is_rejected() {
        let dir: TempDirGuard = fresh_dir("missing");
        assert!(read_and_validate_handoff(&dir.0).is_err());
    }

    #[test]
    fn empty_handoff_file_is_rejected() {
        let dir: TempDirGuard = fresh_dir("empty");
        fs::write(dir.0.join(HANDOFF_FILE_NAME), b"").unwrap();
        assert!(read_and_validate_handoff(&dir.0).is_err());
    }

    #[test]
    fn oversized_handoff_file_is_rejected() {
        let dir: TempDirGuard = fresh_dir("oversized");
        let oversized: Vec<u8> = vec![b'a'; usize::try_from(MAX_HANDOFF_BYTES).unwrap() + 1];
        fs::write(dir.0.join(HANDOFF_FILE_NAME), oversized).unwrap();
        assert!(read_and_validate_handoff(&dir.0).is_err());
    }

    #[test]
    fn nonregular_handoff_path_is_rejected() {
        let dir: TempDirGuard = fresh_dir("nonregular");
        fs::create_dir(dir.0.join(HANDOFF_FILE_NAME)).unwrap();
        assert!(read_and_validate_handoff(&dir.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_handoff_path_is_never_followed() {
        let dir: TempDirGuard = fresh_dir("symlink");
        let real_target: PathBuf = dir.0.join("real-handoff.kv");
        fs::write(&real_target, valid_handoff_bytes()).unwrap();
        let link_path: PathBuf = dir.0.join(HANDOFF_FILE_NAME);
        std::os::unix::fs::symlink(&real_target, &link_path).unwrap();
        assert!(
            read_and_validate_handoff(&dir.0).is_err(),
            "a symlink at handoff.kv must never be followed, even to an otherwise-valid target"
        );
    }
}
