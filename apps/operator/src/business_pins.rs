//! Locally configured authority shared by business cut and inactive import.
//! Parsing performs no file I/O; callers reject unused flags before loading.
#![forbid(unsafe_code)]

use crate::common::{FlagSet, parse_hash_suite, parse_hex_32};
use crate::successor_artifacts::SuccessorChainArtifactFiles;
use execution::{
    LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy,
    publication::PublicationContext,
};
use hashing::HashSuiteResolver;
use node_core::business_reconstruction::BusinessReconstructionPlan;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
};
#[cfg(test)]
use node_core::ordered_economics::OrderedHistoryHeightDescriptor;
use node_core::serving_authority::{
    SuccessorChainBudget, SuccessorLinkPins, VerifiedSuccessorAuthority,
    verify_successor_chain_authority,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use std::io::Read;
use std::{
    error::Error,
    path::{Path, PathBuf},
};
use sunrise_edge_client::immutable_archive::{
    ArchiveReadBudget, AttachedFilePolicy, AttachedRegularFile, ImmutableArchiveReader,
};
use sunrise_edge_client::load_verified_genesis_root;
use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;
use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive_bounded;

pub(crate) fn bounded(value: &str, minimum: u64, maximum: u64) -> Result<u64, Box<dyn Error>> {
    let parsed: u64 = value.parse()?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err("integer outside operator bound".into());
    }
    Ok(parsed)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

pub(crate) struct BusinessPinInputs {
    context: PublicationContext,
    domain: AtomicityDomainId,
    resolver: HashSuiteResolver,
    genesis_file: PathBuf,
    genesis_pin: [u8; 32],
    history_root: PathBuf,
}

impl BusinessPinInputs {
    pub(crate) fn history_root(&self) -> &Path {
        &self.history_root
    }

    pub(crate) fn genesis_file(&self) -> &Path {
        &self.genesis_file
    }

    /// Relocates only transport paths; none of the independently parsed trust
    /// fields are derived from a recovery manifest.
    pub(crate) fn with_saved_paths(mut self, genesis: PathBuf, history: PathBuf) -> Self {
        self.genesis_file = genesis;
        self.history_root = history;
        self
    }

    /// Open-saved has no source-path flags. It supplies generated local paths
    /// to exactly the same public trust parser used by the existing commands.
    pub(crate) fn parse_saved(
        flags: &mut FlagSet,
        genesis: PathBuf,
        history: PathBuf,
    ) -> Result<Self, Box<dyn Error>> {
        Self::parse_inputs(flags, Some(genesis), history)
    }

    pub(crate) fn parse(flags: &mut FlagSet) -> Result<Self, Box<dyn Error>> {
        let history_root: PathBuf = flags.one("--ordered-history-dir")?.into();
        Self::parse_with_history(flags, history_root)
    }

    /// The recurring activation and host parsers consume an ordered list of
    /// archive roles before this original-genesis pin parser. Parsing never
    /// opens a file or adopts a peer's epoch or suite.
    pub(crate) fn parse_with_history(
        flags: &mut FlagSet,
        history_root: PathBuf,
    ) -> Result<Self, Box<dyn Error>> {
        Self::parse_inputs(flags, None, history_root)
    }

    fn parse_inputs(
        flags: &mut FlagSet,
        saved_genesis: Option<PathBuf>,
        history_root: PathBuf,
    ) -> Result<Self, Box<dyn Error>> {
        let chain: ChainId = ChainId::new(flags.one("--chain-id")?)?;
        let protocol: ProtocolVersion = ProtocolVersion::new(u32::try_from(bounded(
            &flags.one("--protocol-version")?,
            1,
            u64::from(u32::MAX),
        )?)?);
        let epoch: Epoch = Epoch::new(bounded(&flags.one("--epoch")?, 0, u64::MAX)?);
        let domain: AtomicityDomainId =
            AtomicityDomainId::new(parse_hex_32(&flags.one("--domain")?, "--domain")?)?;
        let suite_inputs: Vec<String> = flags.many("--suite");
        if suite_inputs.is_empty() || suite_inputs.len() > 64 {
            return Err("one to 64 explicit suite entries required".into());
        }
        let schedule: Vec<HashSuiteSchedule> = suite_inputs
            .iter()
            .map(|value: &String| parse_hash_suite(value))
            .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
        let resolver: HashSuiteResolver =
            HashSuiteResolver::new(chain.clone(), protocol, schedule)?;
        Ok(Self {
            context: PublicationContext::new(chain, protocol, epoch)?,
            domain,
            resolver,
            genesis_file: match saved_genesis {
                Some(path) => path,
                None => flags.one("--genesis-manifest")?.into(),
            },
            genesis_pin: parse_hex_32(
                &flags.one("--expected-genesis-digest")?,
                "--expected-genesis-digest",
            )?,
            history_root,
        })
    }

    pub(crate) fn load(self) -> Result<BusinessPins, Box<dyn Error>> {
        self.load_mode(None)
    }

    pub(crate) fn load_bounded(
        self,
        budget: &ArchiveReadBudget,
    ) -> Result<BusinessPins, Box<dyn Error>> {
        self.load_mode(Some(budget))
    }

    fn load_root(
        &self,
        budget: Option<&ArchiveReadBudget>,
    ) -> Result<VerifiedGenesisRoot, Box<dyn Error>> {
        match budget {
            None => Ok(load_verified_genesis_root(
                &self.genesis_file,
                &self.resolver,
                self.genesis_pin,
                &self.context,
            )?),
            Some(budget) => {
                budget.check()?;
                let maximum: u64 = u64::try_from(node_core::MAX_GENESIS_MANIFEST_BYTES)?;
                let mut file: AttachedRegularFile = AttachedRegularFile::open(
                    &self.genesis_file,
                    maximum,
                    budget,
                    AttachedFilePolicy::public(),
                )?;
                budget.check_component_bytes(
                    file.stamp().length,
                    node_core::MAX_GENESIS_MANIFEST_BYTES,
                )?;
                let mut bytes: Vec<u8> = Vec::new();
                file.read_to_end(&mut bytes)?;
                file.ensure_attached()?;
                let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
                    &self.resolver,
                    &bytes,
                    self.genesis_pin,
                    &self.context,
                )?;
                budget.check()?;
                Ok(root)
            }
        }
    }

    fn read_history(
        &self,
        policy: &OrderedEconomicsPolicy,
        budget: Option<&ArchiveReadBudget>,
    ) -> Result<(OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>), Box<dyn Error>> {
        match budget {
            None => read_verified_ordered_history_archive(policy, &self.history_root),
            Some(budget) => {
                let archive: ImmutableArchiveReader =
                    ImmutableArchiveReader::open_bounded(&self.history_root, budget)?;
                read_verified_ordered_history_archive_bounded(policy, &archive)
            }
        }
    }

    fn load_mode(self, budget: Option<&ArchiveReadBudget>) -> Result<BusinessPins, Box<dyn Error>> {
        let root: VerifiedGenesisRoot = self.load_root(budget)?;
        if !root.admission_profile().is_causal() {
            return Err("business reconstruction requires signed causal-admission genesis".into());
        }
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, self.domain)?;
        let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            self.read_history(&policy, budget)?;
        Ok(BusinessPins {
            context: self.context.clone(),
            domain: self.domain,
            root,
            policy,
            identity,
            ordered,
            base_policy: LocalExecutionPolicy::generic_object_results(self.context),
            engine: LocalWasmExecutionEngine::new(),
            authority: None,
            original: None,
        })
    }

    /// Keeps the original pinned root and derives the current reconstruction
    /// policy exclusively from the full verified predecessor chain. The
    /// independent --ordered-history-dir here is the current epoch's cut
    /// history; the repeated predecessor archives retain their original roles.
    pub(crate) fn load_with_successor(
        self,
        artifacts: &mut SuccessorChainArtifactFiles,
        budget: SuccessorChainBudget,
    ) -> Result<BusinessPins, Box<dyn Error>> {
        self.load_successor_mode(artifacts, budget, None)
    }

    pub(crate) fn load_with_successor_bounded(
        self,
        artifacts: &mut SuccessorChainArtifactFiles,
        chain_budget: SuccessorChainBudget,
        read_budget: &ArchiveReadBudget,
    ) -> Result<BusinessPins, Box<dyn Error>> {
        self.load_successor_mode(artifacts, chain_budget, Some(read_budget))
    }

    fn load_successor_mode(
        self,
        artifacts: &mut SuccessorChainArtifactFiles,
        budget: SuccessorChainBudget,
        read_budget: Option<&ArchiveReadBudget>,
    ) -> Result<BusinessPins, Box<dyn Error>> {
        let root: VerifiedGenesisRoot = self.load_root(read_budget)?;
        if !root.admission_profile().is_causal() {
            return Err("business reconstruction requires signed causal-admission genesis".into());
        }
        let original_policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, self.domain)?;
        let links: Vec<SuccessorLinkPins> = match read_budget {
            Some(_) => artifacts.pins_bounded()?,
            None => artifacts.pins(),
        };
        let original_identity: OrderedHistoryIdentity = links
            .first()
            .ok_or("successor chain is empty")?
            .cut_identity
            .clone();
        let original_base: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(self.context.clone());
        let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
        let authority: VerifiedSuccessorAuthority = verify_successor_chain_authority(
            BusinessReconstructionPlan {
                genesis_root: &root,
                operation_context: private_operation()?,
                domain: self.domain,
                resolver_history: &[],
                ordered_policy: &original_policy,
                ordered_history_identity: &original_identity,
                ordered_leg_policy: &original_base,
                ordered_engine: &engine,
                paid_base_policy: &original_base,
                paid_engine: &engine,
            },
            &links,
            budget,
            artifacts,
        )?;
        let policy: OrderedEconomicsPolicy = authority.ordered_policy(&root)?;
        let context: PublicationContext = policy.context().clone();
        let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            self.read_history(&policy, read_budget)?;
        Ok(BusinessPins {
            context: context.clone(),
            domain: self.domain,
            root,
            policy,
            identity,
            ordered,
            base_policy: LocalExecutionPolicy::generic_object_results(context),
            engine,
            authority: Some(authority),
            original: Some(OriginalReconstructionPins {
                policy: original_policy,
                identity: original_identity,
                base_policy: original_base,
            }),
        })
    }
}

struct OriginalReconstructionPins {
    policy: OrderedEconomicsPolicy,
    identity: OrderedHistoryIdentity,
    base_policy: LocalExecutionPolicy,
}

pub(crate) struct BusinessPins {
    pub(crate) context: PublicationContext,
    pub(crate) domain: AtomicityDomainId,
    root: VerifiedGenesisRoot,
    pub(crate) policy: OrderedEconomicsPolicy,
    identity: OrderedHistoryIdentity,
    pub(crate) ordered: Vec<OrderedHistoryHeightMaterial>,
    base_policy: LocalExecutionPolicy,
    engine: LocalWasmExecutionEngine,
    authority: Option<VerifiedSuccessorAuthority>,
    original: Option<OriginalReconstructionPins>,
}

/// Operator-retained ordered-history position from an earlier independent
/// verification (for example an earlier `history_export` run against a
/// different validator). Refusal-only: never checkpoint, state-root, latest
/// state, readiness, Seal or activation authority. All three fields are
/// parsed from argv alone and never from a saved cut, history archive,
/// successor artifact or any other recovery manifest.
pub(crate) struct HistoryFloor {
    epoch: Epoch,
    height: u64,
    block_digest: [u8; 32],
}

impl HistoryFloor {
    /// All three flags or none. Parsing performs no file I/O.
    pub(crate) fn parse_optional(flags: &mut FlagSet) -> Result<Option<Self>, Box<dyn Error>> {
        let epoch: Option<String> = flags.optional_one("--history-floor-epoch")?;
        let height: Option<String> = flags.optional_one("--history-floor-height")?;
        let digest: Option<String> = flags.optional_one("--history-floor-digest")?;
        match (epoch, height, digest) {
            (None, None, None) => Ok(None),
            (Some(epoch), Some(height), Some(digest)) => Ok(Some(Self {
                epoch: Epoch::new(bounded(&epoch, 0, u64::MAX)?),
                height: bounded(&height, 1, u64::MAX)?,
                block_digest: parse_hex_32(&digest, "--history-floor-digest")?,
            })),
            _ => Err(
                "--history-floor-epoch, --history-floor-height and --history-floor-digest must be supplied together or not at all"
                    .into(),
            ),
        }
    }
}

/// Refuses unless `floor` names an already-authenticated ancestor on
/// `identity`'s direct-parent chain within `context`'s exact epoch. Compares
/// only material `OrderedHistoryVerifier` has already authenticated; it
/// never selects between same-height forks by height or view, and it can
/// never grant checkpoint, state-root or whole-store rollback authority.
fn check_history_floor(
    context: &PublicationContext,
    identity: &OrderedHistoryIdentity,
    ordered: &[OrderedHistoryHeightMaterial],
    floor: &HistoryFloor,
) -> Result<(), Box<dyn Error>> {
    if floor.epoch != context.epoch() {
        return Err(
            "history floor epoch differs from the verified current epoch; cross-epoch floors are unsupported"
                .into(),
        );
    }
    if floor.height > identity.through_height {
        return Err("restored ordered history is below the independent history floor".into());
    }
    let zero_based: u64 = floor
        .height
        .checked_sub(1)
        .ok_or("zero history floor height")?;
    let index: usize = usize::try_from(zero_based)?;
    let material: &OrderedHistoryHeightMaterial = ordered
        .get(index)
        .filter(|material| material.descriptor.height == floor.height)
        .ok_or("restored ordered history is missing the independent history floor height")?;
    if material.descriptor.block_digest.bytes() != floor.block_digest {
        return Err(
            "restored ordered history does not extend the independent history floor block".into(),
        );
    }
    Ok(())
}

impl BusinessPins {
    /// Must be called after `load`/`load_with_successor`, before any
    /// destination path is touched. A missing floor never refuses; this is
    /// purely an additional refusal gate, not a new source of authority.
    pub(crate) fn require_history_floor(
        &self,
        floor: &HistoryFloor,
    ) -> Result<(), Box<dyn Error>> {
        check_history_floor(&self.context, &self.identity, &self.ordered, floor)
    }

    pub(crate) fn successor_authority(&self) -> Option<&VerifiedSuccessorAuthority> {
        self.authority.as_ref()
    }

    pub(crate) fn cut_identity(&self) -> &OrderedHistoryIdentity {
        &self.identity
    }

    /// The original first-link plan used by a fresh live chain resolution.
    /// Later policies still come from core, never from this saved plan.
    pub(crate) fn chain_plan(
        &self,
        operation: DurableOperationContext,
    ) -> BusinessReconstructionPlan<'_> {
        match &self.original {
            Some(original) => BusinessReconstructionPlan {
                genesis_root: &self.root,
                operation_context: operation,
                domain: self.domain,
                resolver_history: &[],
                ordered_policy: &original.policy,
                ordered_history_identity: &original.identity,
                ordered_leg_policy: &original.base_policy,
                ordered_engine: &self.engine,
                paid_base_policy: &original.base_policy,
                paid_engine: &self.engine,
            },
            None => self.plan(operation),
        }
    }
    pub(crate) fn resolver(&self) -> &HashSuiteResolver {
        self.root.genesis_resolver()
    }

    /// The original pinned verified genesis root, never a replacement.
    pub(crate) fn root(&self) -> &VerifiedGenesisRoot {
        &self.root
    }

    pub(crate) fn plan(
        &self,
        operation: DurableOperationContext,
    ) -> BusinessReconstructionPlan<'_> {
        BusinessReconstructionPlan {
            genesis_root: &self.root,
            operation_context: operation,
            domain: self.domain,
            resolver_history: &[],
            ordered_policy: &self.policy,
            ordered_history_identity: &self.identity,
            ordered_leg_policy: &self.base_policy,
            ordered_engine: &self.engine,
            paid_base_policy: &self.base_policy,
            paid_engine: &self.engine,
        }
    }
}

pub(crate) fn operation(
    fence: WriterFenceGeneration,
    timeout: u64,
    correlation: [u8; 16],
) -> Result<DurableOperationContext, Box<dyn Error>> {
    if !(1..=3600).contains(&timeout) {
        return Err("timeout must be 1..3600 seconds".into());
    }
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(
            timeout
                .checked_mul(1000)
                .ok_or("operation timeout overflow")?,
        )
        .ok_or("operation deadline overflow")?;
    Ok(DurableOperationContext::new(
        fence,
        StorageDeadline::new(deadline).ok_or("invalid operation deadline")?,
        StorageCorrelationId::new(correlation).ok_or("invalid operation correlation")?,
    ))
}

pub(crate) fn private_operation() -> Result<DurableOperationContext, Box<dyn Error>> {
    // Exists only in private reconstruction, not authority over a destination.
    operation(
        WriterFenceGeneration::new(1).ok_or("zero private fence")?,
        3600,
        [0xB9; 16],
    )
}

#[cfg(test)]
mod history_floor_tests {
    use super::*;
    use protocol_types::{Digest32, HashAlgorithmId};
    use std::ffi::OsString;

    fn flags(pairs: &[(&str, &str)]) -> FlagSet {
        let tokens: Vec<OsString> = pairs
            .iter()
            .flat_map(|(flag, value)| [OsString::from(*flag), OsString::from(*value)])
            .collect();
        FlagSet::parse(
            tokens,
            &[
                "--history-floor-epoch",
                "--history-floor-height",
                "--history-floor-digest",
            ],
            &[],
        )
        .unwrap()
    }

    fn test_digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn test_context(epoch: u64) -> PublicationContext {
        PublicationContext::new(
            ChainId::new("history-floor-test-chain").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(epoch),
        )
        .unwrap()
    }

    fn test_identity(
        context: PublicationContext,
        through_height: u64,
        through_digest: Digest32,
    ) -> OrderedHistoryIdentity {
        OrderedHistoryIdentity {
            context,
            domain: AtomicityDomainId::new([0x02; 32]).unwrap(),
            genesis_digest: test_digest(0x03),
            anchor: test_digest(0x01),
            through_height,
            through_view: through_height,
            through_digest,
        }
    }

    fn test_anchor_identity(context: PublicationContext) -> OrderedHistoryIdentity {
        let anchor: Digest32 = test_digest(0x01);
        OrderedHistoryIdentity {
            context,
            domain: AtomicityDomainId::new([0x02; 32]).unwrap(),
            genesis_digest: test_digest(0x03),
            anchor,
            through_height: 0,
            through_view: 0,
            through_digest: anchor,
        }
    }

    fn test_materials(
        identity: &OrderedHistoryIdentity,
        digests: &[Digest32],
    ) -> Vec<OrderedHistoryHeightMaterial> {
        digests
            .iter()
            .enumerate()
            .map(|(index, digest)| {
                let height: u64 = u64::try_from(index + 1).unwrap();
                OrderedHistoryHeightMaterial {
                    descriptor: OrderedHistoryHeightDescriptor {
                        identity: identity.clone(),
                        height,
                        view: height,
                        block_digest: *digest,
                        components: Vec::new(),
                    },
                    components: Vec::new(),
                }
            })
            .collect()
    }

    #[test]
    fn history_floor_parse_missing_all_three_is_none() {
        let mut set: FlagSet = flags(&[]);
        assert!(HistoryFloor::parse_optional(&mut set).unwrap().is_none());
    }

    #[test]
    fn history_floor_parse_partial_subsets_refuse() {
        let digest: String = "11".repeat(32);
        let subsets: Vec<Vec<(&str, &str)>> = vec![
            vec![("--history-floor-epoch", "1")],
            vec![("--history-floor-height", "1")],
            vec![("--history-floor-digest", digest.as_str())],
            vec![
                ("--history-floor-epoch", "1"),
                ("--history-floor-height", "1"),
            ],
            vec![
                ("--history-floor-epoch", "1"),
                ("--history-floor-digest", digest.as_str()),
            ],
            vec![
                ("--history-floor-height", "1"),
                ("--history-floor-digest", digest.as_str()),
            ],
        ];
        for pairs in subsets {
            let mut set: FlagSet = flags(&pairs);
            assert!(HistoryFloor::parse_optional(&mut set).is_err());
        }
    }

    #[test]
    fn history_floor_parse_zero_height_refuses() {
        let digest: String = "22".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--history-floor-epoch", "1"),
            ("--history-floor-height", "0"),
            ("--history-floor-digest", &digest),
        ]);
        assert!(HistoryFloor::parse_optional(&mut set).is_err());
    }

    #[test]
    fn history_floor_parse_height_overflow_refuses() {
        let digest: String = "33".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--history-floor-epoch", "1"),
            ("--history-floor-height", "99999999999999999999"),
            ("--history-floor-digest", &digest),
        ]);
        assert!(HistoryFloor::parse_optional(&mut set).is_err());
    }

    #[test]
    fn history_floor_parse_epoch_overflow_refuses() {
        let digest: String = "44".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--history-floor-epoch", "99999999999999999999"),
            ("--history-floor-height", "1"),
            ("--history-floor-digest", &digest),
        ]);
        assert!(HistoryFloor::parse_optional(&mut set).is_err());
    }

    #[test]
    fn history_floor_parse_malformed_digest_refuses() {
        let mut set: FlagSet = flags(&[
            ("--history-floor-epoch", "1"),
            ("--history-floor-height", "1"),
            ("--history-floor-digest", "not-hex"),
        ]);
        assert!(HistoryFloor::parse_optional(&mut set).is_err());
    }

    #[test]
    fn history_floor_parse_valid_accepts() {
        let digest: String = "55".repeat(32);
        let mut set: FlagSet = flags(&[
            ("--history-floor-epoch", "7"),
            ("--history-floor-height", "3"),
            ("--history-floor-digest", &digest),
        ]);
        let floor: HistoryFloor = HistoryFloor::parse_optional(&mut set).unwrap().unwrap();
        assert_eq!(floor.epoch, Epoch::new(7));
        assert_eq!(floor.height, 3);
    }

    #[test]
    fn history_floor_accepts_exact_target_and_interior_ancestor() {
        let context: PublicationContext = test_context(1);
        let digests: Vec<Digest32> = (1..=3).map(test_digest).collect();
        let identity: OrderedHistoryIdentity = test_identity(context.clone(), 3, digests[2]);
        let ordered: Vec<OrderedHistoryHeightMaterial> = test_materials(&identity, &digests);
        let tip: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(1),
            height: 3,
            block_digest: digests[2].bytes(),
        };
        assert!(check_history_floor(&context, &identity, &ordered, &tip).is_ok());
        let interior: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(1),
            height: 1,
            block_digest: digests[0].bytes(),
        };
        assert!(check_history_floor(&context, &identity, &ordered, &interior).is_ok());
    }

    #[test]
    fn history_floor_refuses_height_above_target() {
        let context: PublicationContext = test_context(1);
        let digests: Vec<Digest32> = (1..=2).map(test_digest).collect();
        let identity: OrderedHistoryIdentity = test_identity(context.clone(), 2, digests[1]);
        let ordered: Vec<OrderedHistoryHeightMaterial> = test_materials(&identity, &digests);
        let rollback: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(1),
            height: 3,
            block_digest: test_digest(0x09).bytes(),
        };
        let error: Box<dyn Error> =
            check_history_floor(&context, &identity, &ordered, &rollback).unwrap_err();
        assert!(error.to_string().contains("below the independent history floor"));
    }

    #[test]
    fn history_floor_refuses_same_height_digest_fork() {
        let context: PublicationContext = test_context(1);
        let digests: Vec<Digest32> = (1..=2).map(test_digest).collect();
        let identity: OrderedHistoryIdentity = test_identity(context.clone(), 2, digests[1]);
        let ordered: Vec<OrderedHistoryHeightMaterial> = test_materials(&identity, &digests);
        let fork: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(1),
            height: 2,
            block_digest: test_digest(0xAA).bytes(),
        };
        let error: Box<dyn Error> =
            check_history_floor(&context, &identity, &ordered, &fork).unwrap_err();
        assert!(error.to_string().contains("does not extend"));
    }

    #[test]
    fn history_floor_refuses_other_epoch_both_directions() {
        let context: PublicationContext = test_context(1);
        let digests: Vec<Digest32> = (1..=2).map(test_digest).collect();
        let identity: OrderedHistoryIdentity = test_identity(context.clone(), 2, digests[1]);
        let ordered: Vec<OrderedHistoryHeightMaterial> = test_materials(&identity, &digests);
        let older: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(0),
            height: 1,
            block_digest: digests[0].bytes(),
        };
        assert!(check_history_floor(&context, &identity, &ordered, &older).is_err());
        let newer: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(2),
            height: 1,
            block_digest: digests[0].bytes(),
        };
        assert!(check_history_floor(&context, &identity, &ordered, &newer).is_err());
    }

    #[test]
    fn history_floor_refuses_zero_height_and_empty_target() {
        let context: PublicationContext = test_context(1);
        let identity: OrderedHistoryIdentity = test_anchor_identity(context.clone());
        let ordered: Vec<OrderedHistoryHeightMaterial> = Vec::new();
        let floor: HistoryFloor = HistoryFloor {
            epoch: Epoch::new(1),
            height: 1,
            block_digest: test_digest(0x01).bytes(),
        };
        assert!(check_history_floor(&context, &identity, &ordered, &floor).is_err());
    }
}
