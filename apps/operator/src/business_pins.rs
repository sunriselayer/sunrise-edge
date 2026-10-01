//! Locally configured authority shared by business cut and inactive import.
//! Parsing performs no file I/O; callers reject unused flags before loading.
#![forbid(unsafe_code)]

use crate::common::{FlagSet, load_trusted_genesis_manifest, parse_hash_suite, parse_hex_32};
use execution::{
    LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy,
    publication::PublicationContext,
};
use hashing::HashSuiteResolver;
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
};
use node_core::{
    GenesisManifest, admission_profile::VerifiedAdmissionProfile,
    business_reconstruction::BusinessReconstructionPlan, genesis_manifest_commitment,
};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashSuiteSchedule, ProtocolVersion,
};
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use std::{
    error::Error,
    path::{Path, PathBuf},
};
use sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive;
use validator_set::{ValidatorInfo, ValidatorSet};

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
            history_root: flags.one("--ordered-history-dir")?.into(),
        })
    }

    pub(crate) fn load(self) -> Result<BusinessPins, Box<dyn Error>> {
        let manifest: GenesisManifest = load_trusted_genesis_manifest(
            &self.genesis_file,
            &self.resolver,
            self.genesis_pin,
            &self.context,
        )?;
        let digest: Digest32 = genesis_manifest_commitment(&self.resolver, &manifest)?;
        let profile: VerifiedAdmissionProfile =
            VerifiedAdmissionProfile::from_pinned_genesis(&self.resolver, &manifest, digest)?;
        if !profile.is_causal() {
            return Err("business reconstruction requires signed causal-admission genesis".into());
        }
        let validators: Vec<ValidatorInfo> = manifest
            .validator_set
            .validators
            .iter()
            .map(|member| ValidatorInfo {
                id: member.id,
                voting_power: member.voting_power,
                signature_scheme: member.signature_scheme,
                public_key: member.public_key.clone(),
            })
            .collect();
        let set: ValidatorSet = ValidatorSet::new(self.context.epoch(), validators)?;
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
            self.context.clone(),
            self.domain,
            digest,
            Some(&manifest),
            set,
            self.resolver.clone(),
        )?;
        let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            read_verified_ordered_history_archive(&policy, &self.history_root)?;
        Ok(BusinessPins {
            context: self.context.clone(),
            domain: self.domain,
            resolver: self.resolver,
            manifest,
            digest,
            profile,
            policy,
            identity,
            ordered,
            base_policy: LocalExecutionPolicy::generic_object_results(self.context),
            engine: LocalWasmExecutionEngine::new(),
        })
    }
}

pub(crate) struct BusinessPins {
    pub(crate) context: PublicationContext,
    pub(crate) domain: AtomicityDomainId,
    pub(crate) resolver: HashSuiteResolver,
    manifest: GenesisManifest,
    digest: Digest32,
    profile: VerifiedAdmissionProfile,
    pub(crate) policy: OrderedEconomicsPolicy,
    identity: OrderedHistoryIdentity,
    pub(crate) ordered: Vec<OrderedHistoryHeightMaterial>,
    base_policy: LocalExecutionPolicy,
    engine: LocalWasmExecutionEngine,
}

impl BusinessPins {
    pub(crate) fn plan(
        &self,
        operation: DurableOperationContext,
    ) -> BusinessReconstructionPlan<'_> {
        BusinessReconstructionPlan {
            admission_profile: &self.profile,
            genesis: &self.manifest,
            pinned_genesis_digest: self.digest,
            operation_context: operation,
            domain: self.domain,
            resolver: &self.resolver,
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
