//! Explicit native storage profile selection; no protocol authority is inferred.
use crate::common::{FlagSet, parse_hex_32};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::ImportBinding;
use runtime_sqlite::{SqliteDurableStore, SqliteImportTarget, SqliteNamespace};
use std::{
    error::Error,
    ffi::OsString,
    path::{Path, PathBuf},
};

pub(crate) const FLAG: &str = "--independent-anchor-db";

pub(crate) fn parse(flags: &mut FlagSet) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let path: Option<PathBuf> = flags.optional_one(FLAG)?.map(PathBuf::from);
    if path.as_ref().is_some_and(|value| !value.is_absolute()) {
        return Err(
            "--independent-anchor-db requires an absolute independent authority path".into(),
        );
    }
    Ok(path)
}

pub(crate) fn open_original(
    state: &Path,
    blobs: &Path,
    anchor: Option<&Path>,
    namespace: SqliteNamespace,
) -> Result<SqliteDurableStore, Box<dyn Error>> {
    match anchor {
        Some(anchor) => Ok(SqliteDurableStore::open_anchored(
            state, blobs, anchor, namespace,
        )?),
        None => Ok(SqliteDurableStore::open_existing(state, namespace)?),
    }
}

pub(crate) fn open_import(
    state: &Path,
    blobs: &Path,
    anchor: Option<&Path>,
    namespace: SqliteNamespace,
    binding: &ImportBinding,
) -> Result<SqliteImportTarget, Box<dyn Error>> {
    match anchor {
        Some(anchor) => Ok(SqliteImportTarget::open_anchored(
            state, blobs, anchor, namespace, binding,
        )?),
        None => Ok(SqliteImportTarget::open_existing(
            state, namespace, binding,
        )?),
    }
}

/// Existing sqlite_source_host executable, separate stopped-owner mode. No new
/// executable is added to the closed release target registry.
pub(crate) fn enroll(
    inspect: bool,
    values: impl IntoIterator<Item = OsString>,
) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        values,
        &[
            "--chain-id",
            "--validator-id",
            "--domain",
            "--state-db",
            "--blob-db",
            FLAG,
            "--expected-initial-state-root",
            "--expected-initial-body-manifest-root",
        ],
        &["--confirm-writers-and-signers-stopped"],
    )?;
    let confirmed: bool = flags.bool("--confirm-writers-and-signers-stopped");
    let chain: ChainId = ChainId::new(flags.one("--chain-id")?)?;
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)?;
    let state: PathBuf = flags.one("--state-db")?.into();
    let blobs: PathBuf = flags.one("--blob-db")?.into();
    let checkpoint = if inspect {
        if parse(&mut flags)?.is_some() {
            return Err("anchor-inspect observes inputs without an anchor authority".into());
        }
        flags.finish()?;
        runtime_sqlite::inspect_independent_anchor_inputs(
            &state, &blobs, &chain, validator, domain,
        )?
    } else {
        let anchor: PathBuf = parse(&mut flags)?.ok_or("explicit independent anchor required")?;
        let expected_state: [u8; 32] = parse_hex_32(
            &flags.one("--expected-initial-state-root")?,
            "--expected-initial-state-root",
        )?;
        let expected_bodies: [u8; 32] = parse_hex_32(
            &flags.one("--expected-initial-body-manifest-root")?,
            "--expected-initial-body-manifest-root",
        )?;
        flags.finish()?;
        runtime_sqlite::enroll_independent_anchor(
            &state,
            &blobs,
            &anchor,
            &chain,
            validator,
            domain,
            expected_state,
            expected_bodies,
            confirmed,
        )?
    };
    println!(
        "complete=true meaning={} sequence={} state_root={} body_manifest_root={}",
        if inspect {
            "initial-input-observation-not-currentness"
        } else {
            "stopped-owner-enrollment"
        },
        checkpoint.sequence,
        crate::business_pins::hex(&checkpoint.state_root),
        crate::business_pins::hex(&checkpoint.body_manifest_root)
    );
    Ok(())
}

/// Offline publication from the one enrolled namespace owner. Holding another
/// live writer's lease is a refusal; this never guesses currentness from files.
pub(crate) fn checkpoint(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut flags: FlagSet = FlagSet::parse(
        values,
        &[
            "--chain-id",
            "--validator-id",
            "--domain",
            "--state-db",
            "--blob-db",
            FLAG,
        ],
        &[],
    )?;
    let chain: ChainId = ChainId::new(flags.one("--chain-id")?)?;
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)?;
    let state: PathBuf = flags.one("--state-db")?.into();
    let blobs: PathBuf = flags.one("--blob-db")?.into();
    let anchor: PathBuf = parse(&mut flags)?.ok_or("explicit independent anchor required")?;
    flags.finish()?;
    let owner: SqliteDurableStore = SqliteDurableStore::open_historical_anchored(
        &state,
        &blobs,
        &anchor,
        SqliteNamespace::new(chain, validator, domain),
    )?;
    let checkpoint = owner.independent_anchor_checkpoint()?;
    println!(
        "complete=true meaning=independent-local-acknowledgement-not-quorum-state-root sequence={} state_root={} body_manifest_root={}",
        checkpoint.sequence,
        crate::business_pins::hex(&checkpoint.state_root),
        crate::business_pins::hex(&checkpoint.body_manifest_root)
    );
    Ok(())
}
