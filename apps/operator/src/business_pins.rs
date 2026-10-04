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
use node_core::serving_authority::{
    SuccessorChainBudget, SuccessorLinkPins, VerifiedSuccessorAuthority,
    verify_successor_chain_authority,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use std::{
    error::Error,
    path::{Path, PathBuf},
};
use sunrise_edge_client::load_verified_genesis_root;
use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;

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
            genesis_file: flags.one("--genesis-manifest")?.into(),
            genesis_pin: parse_hex_32(
                &flags.one("--expected-genesis-digest")?,
                "--expected-genesis-digest",
            )?,
            history_root,
        })
    }

    pub(crate) fn load(self) -> Result<BusinessPins, Box<dyn Error>> {
        let root: VerifiedGenesisRoot = load_verified_genesis_root(
            &self.genesis_file,
            &self.resolver,
            self.genesis_pin,
            &self.context,
        )?;
        if !root.admission_profile().is_causal() {
            return Err("business reconstruction requires signed causal-admission genesis".into());
        }
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, self.domain)?;
        let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            read_verified_ordered_history_archive(&policy, &self.history_root)?;
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
        let root: VerifiedGenesisRoot = load_verified_genesis_root(
            &self.genesis_file,
            &self.resolver,
            self.genesis_pin,
            &self.context,
        )?;
        if !root.admission_profile().is_causal() {
            return Err("business reconstruction requires signed causal-admission genesis".into());
        }
        let original_policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, self.domain)?;
        let links: Vec<SuccessorLinkPins> = artifacts.pins();
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
            read_verified_ordered_history_archive(&policy, &self.history_root)?;
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

impl BusinessPins {
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
