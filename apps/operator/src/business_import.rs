//! Callable verified installation. The command leaves an inactive import;
//! later activation belongs to the separate successor activation owner.
#![forbid(unsafe_code)]

use crate::{
    business_cut::read_business_cut_archive,
    business_pins::{
        BusinessPinInputs, BusinessPins, HistoryFloor, bounded, hex, operation, private_operation,
    },
    common::{FlagSet, parse_hex_32},
    immutable_archive::ImmutableArchive,
    successor_artifacts::{CHAIN_FLAGS, SuccessorChainArtifactFiles, SuccessorChainInputs},
};
use node_core::business_reconstruction::{
    BusinessReconstructionPlan,
    cut::SavedBusinessCut,
    inactive_import::{
        BusinessImportAdvance, VerifiedImportPlan, verify_saved_business_import,
        verify_saved_business_import_chain,
    },
};
use protocol_types::ValidatorId;
use runtime::{DurableOperationContext, ImportBinding, WriterFenceGeneration};
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget, SqliteNamespace};
use std::{error::Error, ffi::OsString, num::NonZeroUsize, path::PathBuf};

const FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--domain",
    "--suite",
    "--genesis-manifest",
    "--expected-genesis-digest",
    "--ordered-history-dir",
    "--cut-dir",
    crate::local_anchor::FLAG,
    "--state-db",
    "--blob-db",
    "--validator-id",
    "--timeout-seconds",
    "--max-new-batches",
    "--history-floor-epoch",
    "--history-floor-height",
    "--history-floor-digest",
    "--expected-cut-digest",
    "--expected-package-digest",
    "--expected-plan-digest",
];
const HELP: &str = "Verified business installation only; leaves a CompleteInactive import and never performs readiness, Seal, activation or signing.\nModes: create-sqlite | resume-sqlite.\nRequire local pins: --chain-id --protocol-version --epoch --domain --suite epoch:id:tx:object:effects:code:config:certificate --genesis-manifest --expected-genesis-digest --ordered-history-dir.\nRequire: --cut-dir (complete saved cut), --state-db, --blob-db, --validator-id (destination-local namespace, not membership authority).\nOptional: --timeout-seconds 1..3600 (300), --max-new-batches 1..4096 (4096), and a successor chain (all five or none): --successor-max-links once plus one or more equal-count repeated --successor-plan-history-dir --successor-cut-dir --successor-manifest-history-dir --successor-certificate-dir links, up to that budget, pinning the saved cut's successor authority; no signer key is accepted here.\nOptional, all three or none: --history-floor-epoch --history-floor-height --history-floor-digest, an operator-retained ordered-history position from an earlier independent verification. Refuses unless the verified current epoch matches exactly and the authenticated ordered history at that height has exactly that block digest; refusal-only, never checkpoint, state-root, latest-state, readiness or activation authority, and never read from the cut, history archive or successor artifacts being restored.\nOptional, all three or none: --expected-cut-digest --expected-package-digest --expected-plan-digest, operator-retained closure-identity pins from an earlier independent run or verification. Compared against the independently reverified cut/package/plan identity immediately after reconstruction and before any destination is created or opened. Refusal-only, never checkpoint, state-root, latest-state or activation authority, and never read from the cut, history archive or successor artifacts being restored.\nCreation requires two fresh database paths outside the pinned cut and ordered-history archives; resumption opens existing verified import-origin state and writable blob schemas only. No normal bootstrap, source writer copying, repair, reset, private key or network endpoint. Every invocation independently reexecutes saved proofs and verifies the complete destination before CompleteInactive. Missing, corrupt, foreign or ordinary targets refuse.";

/// Operator-retained closure-identity pins from an earlier independent run or
/// verification, kept outside the cut/history/successor artifacts being
/// restored. All three or none; refusal-only, never checkpoint, state-root,
/// latest-state, readiness or activation authority.
struct ClosureIdentityPins {
    cut_digest: [u8; 32],
    package_digest: [u8; 32],
    plan_digest: [u8; 32],
}

impl ClosureIdentityPins {
    /// All three flags or none. Parsing performs no file I/O.
    fn parse_optional(flags: &mut FlagSet) -> Result<Option<Self>, Box<dyn Error>> {
        let cut: Option<String> = flags.optional_one("--expected-cut-digest")?;
        let package: Option<String> = flags.optional_one("--expected-package-digest")?;
        let plan: Option<String> = flags.optional_one("--expected-plan-digest")?;
        match (cut, package, plan) {
            (None, None, None) => Ok(None),
            (Some(cut), Some(package), Some(plan)) => Ok(Some(Self {
                cut_digest: parse_hex_32(&cut, "--expected-cut-digest")?,
                package_digest: parse_hex_32(&package, "--expected-package-digest")?,
                plan_digest: parse_hex_32(&plan, "--expected-plan-digest")?,
            })),
            _ => Err(
                "--expected-cut-digest, --expected-package-digest and --expected-plan-digest must be supplied together or not at all"
                    .into(),
            ),
        }
    }

    /// Must be called after independent saved-proof verification, before any
    /// destination database is opened or created. Grants no new authority:
    /// success only permits the original independent verification to stand.
    fn require(&self, binding: &ImportBinding) -> Result<(), Box<dyn Error>> {
        if binding.cut_digest.bytes() != self.cut_digest
            || binding.package_digest.bytes() != self.package_digest
            || binding.plan_digest.bytes() != self.plan_digest
        {
            return Err(
                "verified closure identity does not match the independently retained cut/package/plan digest pins"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Runs the same strictly pinned composition as the `business_import` binary.
/// Destination file I/O starts only after independent raw-plan verification.
pub fn run(values: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut values: Vec<OsString> = values.into_iter().collect();
    if values.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    if values.is_empty() {
        return Err(HELP.into());
    }
    let creating: bool = match values.remove(0).to_str() {
        Some("create-sqlite") => true,
        Some("resume-sqlite") => false,
        _ => return Err("unknown business import mode; use --help".into()),
    };
    let mut accepted: Vec<&'static str> = FLAGS.to_vec();
    accepted.extend_from_slice(CHAIN_FLAGS);
    let mut flags: FlagSet = FlagSet::parse(values, &accepted, &[])?;
    let anchor: Option<PathBuf> = crate::local_anchor::parse(&mut flags)?;
    let chain_inputs: Option<SuccessorChainInputs> =
        SuccessorChainInputs::parse_optional(&mut flags)?;
    let pin_inputs: BusinessPinInputs = BusinessPinInputs::parse(&mut flags)?;
    let cut_directory: PathBuf = flags.one("--cut-dir")?.into();
    let state_file: PathBuf = flags.one("--state-db")?.into();
    let blob_file: PathBuf = flags.one("--blob-db")?.into();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(
        &flags.one("--validator-id")?,
        "--validator-id",
    )?);
    let timeout: u64 = bounded(
        &flags
            .optional_one("--timeout-seconds")?
            .unwrap_or_else(|| "300".into()),
        1,
        3600,
    )?;
    let maximum_batches: NonZeroUsize = NonZeroUsize::new(usize::try_from(bounded(
        &flags
            .optional_one("--max-new-batches")?
            .unwrap_or_else(|| "4096".into()),
        1,
        4096,
    )?)?)
    .ok_or("zero new-batch limit")?;
    let history_floor: Option<HistoryFloor> = HistoryFloor::parse_optional(&mut flags)?;
    let closure_pins: Option<ClosureIdentityPins> =
        ClosureIdentityPins::parse_optional(&mut flags)?;
    flags.finish()?;
    if creating && anchor.is_some() {
        return Err(
            "enroll an independently verified complete target separately after import".into(),
        );
    }
    if state_file == blob_file {
        return Err("state and blob database paths must be distinct".into());
    }
    let mut chain_artifacts: Option<SuccessorChainArtifactFiles> = chain_inputs
        .as_ref()
        .map(SuccessorChainInputs::open)
        .transpose()?;
    if let Some(artifacts) = &chain_artifacts {
        for path in [&state_file, &blob_file] {
            artifacts.require_output_outside(path)?;
        }
    }
    let history_archive: ImmutableArchive =
        ImmutableArchive::open_read_only(pin_inputs.history_root())?;
    let archive: ImmutableArchive = ImmutableArchive::open_read_only(&cut_directory)?;
    for path in [&state_file, &blob_file] {
        archive.require_output_outside(path)?;
        history_archive.require_output_outside(path)?;
    }
    let pins: BusinessPins = match (&chain_inputs, &mut chain_artifacts) {
        (Some(chain), Some(artifacts)) => {
            pin_inputs.load_with_successor(artifacts, chain.budget)?
        }
        (None, None) => pin_inputs.load()?,
        _ => return Err("successor predecessor artifacts are incomplete".into()),
    };
    // Compares only the history this load already authenticated; no
    // destination database has been opened or created. Earlier read-only
    // archive containment checks only inspect ancestor directories.
    if let Some(floor) = &history_floor {
        pins.require_history_floor(floor)?;
    }
    let private: BusinessReconstructionPlan<'_> = pins.plan(private_operation()?);
    let saved: SavedBusinessCut = read_business_cut_archive(&private, &archive)?;
    let verified: VerifiedImportPlan = match pins.successor_authority() {
        Some(authority) => {
            verify_saved_business_import_chain(private, authority, pins.cut_identity(), &saved)?
        }
        None => verify_saved_business_import(private, &saved)?,
    };
    // Compares only the independently reverified closure identity; no
    // destination database has been opened or created yet.
    if let Some(expected) = &closure_pins {
        expected.require(verified.binding())?;
    }
    let namespace: SqliteNamespace =
        SqliteNamespace::new(pins.context.chain_id().clone(), validator, pins.domain);
    // Recheck the held input identities after reconstruction, before any
    // destination creation/open. Native target owners separately pin files
    // and ancestors; this is not a cross-file atomicity guarantee.
    for path in [&state_file, &blob_file] {
        archive.require_output_outside(path)?;
        history_archive.require_output_outside(path)?;
        if let Some(artifacts) = &chain_artifacts {
            artifacts.require_output_outside(path)?;
        }
    }
    let (target, blobs): (SqliteImportTarget, SqliteBlobStore) = if creating {
        // Neither a preexisting ordinary state file nor a preexisting body file
        // may be silently appropriated, bootstrapped or repaired.
        for path in [&state_file, &blob_file] {
            match std::fs::symlink_metadata(path) {
                Ok(_) => return Err("create-sqlite requires absent target database paths".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let fresh: WriterFenceGeneration =
            WriterFenceGeneration::new(1).ok_or("zero destination fence")?;
        let target: SqliteImportTarget =
            SqliteImportTarget::create(&state_file, namespace, fresh, verified.binding())?;
        let blobs: SqliteBlobStore = SqliteBlobStore::create_new(&blob_file)?;
        (target, blobs)
    } else {
        (
            crate::local_anchor::open_import(
                &state_file,
                &blob_file,
                anchor.as_deref(),
                namespace,
                verified.binding(),
            )?,
            SqliteBlobStore::open_existing_writable(&blob_file)?,
        )
    };
    let current: WriterFenceGeneration = target.writer_fence()?;
    let destination: DurableOperationContext = operation(current, timeout, [0xBA; 16])?;
    match verified.advance(&target, &blobs, &destination, maximum_batches)? {
        BusinessImportAdvance::Partial {
            progress,
            new_batches,
        } => println!(
            "business_import=partial cut={} package={} plan={} next_ordinal={} new_batches={} meaning=permanently-inactive-no-admission-or-signing",
            hex(&verified.binding().cut_digest.bytes()),
            hex(&verified.binding().package_digest.bytes()),
            hex(&verified.binding().plan_digest.bytes()),
            progress.next_ordinal,
            new_batches,
        ),
        BusinessImportAdvance::CompleteInactive {
            progress,
            new_batches,
        } => println!(
            "business_import=complete-inactive cut={} package={} plan={} next_ordinal={} new_batches={} meaning=permanently-inactive-not-readiness-seal-or-activation",
            hex(&verified.binding().cut_digest.bytes()),
            hex(&verified.binding().package_digest.bytes()),
            hex(&verified.binding().plan_digest.bytes()),
            progress.next_ordinal,
            new_batches,
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn help_and_nonexistent_authority_modes_do_not_touch_a_destination() {
        assert!(run([OsString::from("--help")]).is_ok());
        for mode in [
            "force-import",
            "activate",
            "ordinary",
            "reset",
            "create-sqlite",
        ] {
            assert!(run([OsString::from(mode)]).is_err());
        }
        assert!(run([]).is_err());
    }
}

#[cfg(test)]
mod closure_identity_pin_tests {
    use super::*;
    use protocol_types::{
        AtomicityDomainId, ChainId, Digest32, Epoch, ExecutionGeneration, HashAlgorithmId,
        ProtocolVersion,
    };
    use runtime::ImportContext;

    fn flags(pairs: &[(&str, &str)]) -> FlagSet {
        let tokens: Vec<OsString> = pairs
            .iter()
            .flat_map(|(flag, value)| [OsString::from(*flag), OsString::from(*value)])
            .collect();
        FlagSet::parse(
            tokens,
            &[
                "--expected-cut-digest",
                "--expected-package-digest",
                "--expected-plan-digest",
            ],
            &[],
        )
        .unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn test_binding() -> ImportBinding {
        ImportBinding {
            context: ImportContext {
                chain_id: ChainId::new("closure-pin-test-chain").unwrap(),
                protocol_version: ProtocolVersion::new(1),
                epoch: Epoch::new(1),
            },
            domain: AtomicityDomainId::new([0x02; 32]).unwrap(),
            genesis_digest: digest(0x01),
            validator_set_digest: digest(0x02),
            cut_digest: digest(0x10),
            package_digest: digest(0x11),
            plan_digest: digest(0x12),
            row_count: 0,
            blob_count: 0,
            generation_floor: ExecutionGeneration::new(0),
        }
    }

    #[test]
    fn parse_missing_all_three_is_none() {
        let mut set: FlagSet = flags(&[]);
        assert!(
            ClosureIdentityPins::parse_optional(&mut set)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parse_partial_subsets_refuse() {
        let cut: String = "10".repeat(32);
        let package: String = "11".repeat(32);
        let plan: String = "12".repeat(32);
        let subsets: Vec<Vec<(&str, &str)>> = vec![
            vec![("--expected-cut-digest", cut.as_str())],
            vec![("--expected-package-digest", package.as_str())],
            vec![("--expected-plan-digest", plan.as_str())],
            vec![
                ("--expected-cut-digest", cut.as_str()),
                ("--expected-package-digest", package.as_str()),
            ],
            vec![
                ("--expected-cut-digest", cut.as_str()),
                ("--expected-plan-digest", plan.as_str()),
            ],
            vec![
                ("--expected-package-digest", package.as_str()),
                ("--expected-plan-digest", plan.as_str()),
            ],
        ];
        for pairs in subsets {
            let mut set: FlagSet = flags(&pairs);
            assert!(ClosureIdentityPins::parse_optional(&mut set).is_err());
        }
    }

    #[test]
    fn parse_malformed_hex_refuses() {
        let package: String = "11".repeat(32);
        let plan: String = "12".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--expected-cut-digest", "not-hex"),
            ("--expected-package-digest", package.as_str()),
            ("--expected-plan-digest", plan.as_str()),
        ]);
        assert!(ClosureIdentityPins::parse_optional(&mut set).is_err());
    }

    #[test]
    fn parse_valid_accepts_all_three() {
        let cut: String = "10".repeat(32);
        let package: String = "11".repeat(32);
        let plan: String = "12".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--expected-cut-digest", cut.as_str()),
            ("--expected-package-digest", package.as_str()),
            ("--expected-plan-digest", plan.as_str()),
        ]);
        let pins: ClosureIdentityPins = ClosureIdentityPins::parse_optional(&mut set)
            .unwrap()
            .unwrap();
        assert_eq!(pins.cut_digest, [0x10; 32]);
        assert_eq!(pins.package_digest, [0x11; 32]);
        assert_eq!(pins.plan_digest, [0x12; 32]);
    }

    #[test]
    fn require_accepts_exact_binding() {
        let binding: ImportBinding = test_binding();
        let pins: ClosureIdentityPins = ClosureIdentityPins {
            cut_digest: binding.cut_digest.bytes(),
            package_digest: binding.package_digest.bytes(),
            plan_digest: binding.plan_digest.bytes(),
        };
        assert!(pins.require(&binding).is_ok());
    }

    #[test]
    fn require_refuses_each_single_field_mismatch() {
        let binding: ImportBinding = test_binding();
        let base: ClosureIdentityPins = ClosureIdentityPins {
            cut_digest: binding.cut_digest.bytes(),
            package_digest: binding.package_digest.bytes(),
            plan_digest: binding.plan_digest.bytes(),
        };
        let mut wrong_cut: ClosureIdentityPins = ClosureIdentityPins {
            cut_digest: base.cut_digest,
            package_digest: base.package_digest,
            plan_digest: base.plan_digest,
        };
        wrong_cut.cut_digest[31] ^= 1;
        assert!(wrong_cut.require(&binding).is_err());
        let mut wrong_package: ClosureIdentityPins = ClosureIdentityPins {
            cut_digest: base.cut_digest,
            package_digest: base.package_digest,
            plan_digest: base.plan_digest,
        };
        wrong_package.package_digest[31] ^= 1;
        assert!(wrong_package.require(&binding).is_err());
        let mut wrong_plan: ClosureIdentityPins = ClosureIdentityPins {
            cut_digest: base.cut_digest,
            package_digest: base.package_digest,
            plan_digest: base.plan_digest,
        };
        wrong_plan.plan_digest[31] ^= 1;
        assert!(wrong_plan.require(&binding).is_err());
        assert!(base.require(&binding).is_ok());
    }
}
