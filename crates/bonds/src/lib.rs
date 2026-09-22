#![forbid(unsafe_code)]

//! Resource-generic bond policy, slashable bond objects, and validator
//! admission primitives.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32, encode_epoch,
};
use core::fmt;
use fees::Amount;
use protocol_types::{Digest32, Epoch};
use runtime::ValidatorId;
use std::error::Error;

const VALIDATOR_ADMISSION_POLICY_TYPE_ID: u16 = 0x8001;
const BOND_RESOURCE_CONFIG_TYPE_ID: u16 = 0x8002;
const BOND_RESOURCE_REGISTRY_TYPE_ID: u16 = 0x8003;
const BOND_OBJECT_TYPE_ID: u16 = 0x8004;
const SLASHING_REASON_TYPE_ID: u16 = 0x8005;
const SLASHING_EVIDENCE_TYPE_ID: u16 = 0x8006;
const VALIDATOR_ADMISSION_TYPE_ID: u16 = 0x8007;
const BOND_RESOURCE_ID_TYPE_ID: u16 = 0x8008;
const EPOCH_TYPE_ID: u16 = 0x0107;
const ENCODING_VERSION: u16 = 1;
const MAX_REGISTRY_RESOURCES: usize = u16::MAX as usize - 1;

/// Errors returned by bond helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondError {
    /// Bond resource minima must be explicitly non-zero.
    ZeroMinBond,
    /// Resource domains must be explicitly non-zero.
    ZeroResourceDomain,
    /// Unbonding periods must be explicitly non-zero.
    ZeroUnbondingEpochs,
    /// The maximum exposure must not be less than the minimum bond.
    ExposureBelowMinBond {
        /// The configured minimum bond.
        min_bond: Amount,
        /// The configured maximum exposure.
        max_validator_exposure: Amount,
    },
    /// The registry contains more entries than can be canonically encoded.
    RegistryTooLarge(usize),
    /// The registry already contains the resource.
    DuplicateResource(BondResourceId),
    /// The registry does not contain the resource.
    UnknownResource(BondResourceId),
    /// The bond resource is disabled.
    ResourceDisabled(BondResourceId),
    /// A bond was evaluated against a policy for another resource.
    ResourceConfigMismatch {
        /// Resource carried by the bond.
        bond_resource_id: BondResourceId,
        /// Resource named by the supplied policy.
        config_resource_id: BondResourceId,
    },
    /// The bond amount is below the configured minimum.
    BondBelowMinimum {
        /// The validator's bond amount.
        amount: Amount,
        /// The configured minimum.
        min_bond: Amount,
    },
    /// The bond amount exceeds the configured exposure cap.
    BondAboveExposure {
        /// The validator's bond amount.
        amount: Amount,
        /// The configured maximum.
        max_validator_exposure: Amount,
    },
    /// The bond already has an unlock epoch.
    AlreadyUnbonding,
    /// The unlock epoch calculation overflowed.
    UnlockEpochOverflow,
    /// The evidence payload did not contain two distinct signed statements.
    IdenticalEvidenceDigests,
    /// Governance approval is required for admission.
    MissingGovernanceApproval,
    /// A valid slashable bond is required for admission.
    MissingBond,
    /// A governance approval was issued for a different validator.
    ApprovalValidatorMismatch,
    /// An attached bond belongs to a different validator.
    BondValidatorMismatch,
    /// A bond cannot satisfy admission before its bonded epoch.
    BondNotYetActive {
        /// Epoch being evaluated.
        epoch: Epoch,
        /// Epoch when the bond becomes active.
        bonded_epoch: Epoch,
    },
    /// The bond is no longer active at the requested epoch.
    BondNotActive {
        /// Epoch being evaluated.
        epoch: Epoch,
        /// First epoch when the bond is no longer slashable.
        unlock_epoch: Epoch,
    },
    /// A canonical boolean was neither zero nor one.
    InvalidBoolean(u8),
    /// A validator-admission policy tag was unknown.
    UnknownValidatorAdmissionPolicy(u16),
    /// A slashing-reason tag was unknown.
    UnknownSlashingReason(u16),
    /// A registry's declared count did not match its fields.
    RegistryCountMismatch {
        /// Count declared in field 1.
        declared: usize,
        /// Number of resource fields present.
        actual: usize,
    },
    /// A decoded value did not re-encode byte-for-byte.
    NonCanonicalEncoding(&'static str),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
}

impl fmt::Display for BondError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMinBond => write!(f, "minimum bond must be non-zero"),
            Self::ZeroResourceDomain => write!(f, "bond resource domain must be non-zero"),
            Self::ZeroUnbondingEpochs => write!(f, "unbonding epochs must be non-zero"),
            Self::ExposureBelowMinBond {
                min_bond,
                max_validator_exposure,
            } => write!(
                f,
                "max validator exposure {max_validator_exposure} is below minimum bond {min_bond}"
            ),
            Self::RegistryTooLarge(count) => write!(
                f,
                "bond-resource registry has {count} entries, exceeds canonical limit"
            ),
            Self::DuplicateResource(resource_id) => {
                write!(f, "duplicate bond resource: {resource_id}")
            }
            Self::UnknownResource(resource_id) => write!(f, "unknown bond resource: {resource_id}"),
            Self::ResourceDisabled(resource_id) => {
                write!(f, "bond resource is disabled: {resource_id}")
            }
            Self::ResourceConfigMismatch {
                bond_resource_id,
                config_resource_id,
            } => write!(
                f,
                "bond resource {bond_resource_id} does not match policy resource {config_resource_id}"
            ),
            Self::BondBelowMinimum { amount, min_bond } => {
                write!(f, "bond amount {amount} is below minimum bond {min_bond}")
            }
            Self::BondAboveExposure {
                amount,
                max_validator_exposure,
            } => write!(
                f,
                "bond amount {amount} exceeds max validator exposure {max_validator_exposure}"
            ),
            Self::AlreadyUnbonding => write!(f, "bond is already unbonding"),
            Self::UnlockEpochOverflow => write!(f, "bond unlock epoch overflowed"),
            Self::IdenticalEvidenceDigests => {
                write!(
                    f,
                    "slashing evidence must contain two distinct statement digests"
                )
            }
            Self::MissingGovernanceApproval => {
                write!(f, "governance approval is required for validator admission")
            }
            Self::MissingBond => write!(f, "validator admission requires a valid bond"),
            Self::ApprovalValidatorMismatch => {
                write!(f, "governance approval belongs to a different validator")
            }
            Self::BondValidatorMismatch => {
                write!(f, "bond belongs to a different validator")
            }
            Self::BondNotYetActive {
                epoch,
                bonded_epoch,
            } => write!(
                f,
                "bond is not active at epoch {}; bonded epoch is {}",
                epoch.get(),
                bonded_epoch.get()
            ),
            Self::BondNotActive {
                epoch,
                unlock_epoch,
            } => write!(
                f,
                "bond is no longer active at epoch {}; unlock epoch is {}",
                epoch.get(),
                unlock_epoch.get()
            ),
            Self::InvalidBoolean(value) => {
                write!(f, "invalid canonical boolean value: {value}")
            }
            Self::UnknownValidatorAdmissionPolicy(value) => {
                write!(f, "unknown validator-admission policy: {value:#06x}")
            }
            Self::UnknownSlashingReason(value) => {
                write!(f, "unknown slashing reason: {value:#06x}")
            }
            Self::RegistryCountMismatch { declared, actual } => write!(
                f,
                "bond-resource registry declares {declared} entries but carries {actual}"
            ),
            Self::NonCanonicalEncoding(kind) => {
                write!(f, "decoded {kind} does not re-encode to its input bytes")
            }
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::CanonicalDecoding(error) => error.fmt(f),
        }
    }
}

impl Error for BondError {}

impl From<CanonicalEncodingError> for BondError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for BondError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

/// Validator admission policy for a protocol epoch.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValidatorAdmissionPolicy {
    /// The genesis validator set is hard-coded and permissioned.
    GenesisPermissioned = 0x0001,
    /// New validators require explicit governance approval only.
    GovernancePermissioned = 0x0002,
    /// New validators require both governance approval and a slashable bond.
    BondAndGovernance = 0x0003,
    /// New validators require a valid slashable bond only.
    BondRequired = 0x0004,
}

impl ValidatorAdmissionPolicy {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns whether the policy requires governance approval.
    #[must_use]
    pub const fn requires_governance_approval(self) -> bool {
        matches!(
            self,
            Self::GenesisPermissioned | Self::GovernancePermissioned | Self::BondAndGovernance
        )
    }

    /// Returns whether the policy requires a valid slashable bond.
    #[must_use]
    pub const fn requires_bond(self) -> bool {
        matches!(self, Self::BondAndGovernance | Self::BondRequired)
    }
}

/// Opaque resource identity accepted by the bond policy.
///
/// The domain is a non-zero nominal-type domain. The value is deliberately
/// uninterpreted by this crate, so callers may bind bonds to resources
/// defined by any authenticated public contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BondResourceId {
    domain: u16,
    value: [u8; 32],
}

impl BondResourceId {
    /// Creates an opaque resource identity in a non-zero domain.
    pub const fn new(domain: u16, value: [u8; 32]) -> Result<Self, BondError> {
        if domain == 0 {
            return Err(BondError::ZeroResourceDomain);
        }
        Ok(Self { domain, value })
    }

    /// Returns the non-zero nominal-type domain.
    #[must_use]
    pub const fn domain(self) -> u16 {
        self.domain
    }

    /// Returns the opaque resource value.
    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.value
    }
}

impl fmt::Display for BondResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}:", self.domain)?;
        for byte in self.value {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Deterministic bond-resource policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondResourceConfig {
    /// Opaque resource identifier.
    pub resource_id: BondResourceId,
    /// Minimum slashable amount required for validator eligibility.
    pub min_bond: Amount,
    /// Whether the resource may currently be used for validator bonds.
    pub enabled: bool,
    /// Number of epochs a bond stays slashable after unbond is requested.
    pub unbonding_epochs: u64,
    /// Optional maximum slashable exposure accepted from one validator.
    pub max_validator_exposure: Option<Amount>,
}

impl BondResourceConfig {
    /// Validates the bond-resource policy.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.min_bond.get() == 0 {
            return Err(BondError::ZeroMinBond);
        }
        if self.unbonding_epochs == 0 {
            return Err(BondError::ZeroUnbondingEpochs);
        }
        if let Some(max_validator_exposure) = self.max_validator_exposure
            && max_validator_exposure < self.min_bond
        {
            return Err(BondError::ExposureBelowMinBond {
                min_bond: self.min_bond,
                max_validator_exposure,
            });
        }
        Ok(())
    }
}

/// Registry of approved bond resources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BondResourceRegistry {
    resources: Vec<BondResourceConfig>,
}

impl BondResourceRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resources: Vec::new(),
        }
    }

    /// Returns the registered resources in canonical order.
    #[must_use]
    pub fn resources(&self) -> &[BondResourceConfig] {
        &self.resources
    }

    /// Returns the number of registered resources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Validates the registry.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.resources.len() > MAX_REGISTRY_RESOURCES {
            return Err(BondError::RegistryTooLarge(self.resources.len()));
        }

        let mut previous: Option<BondResourceId> = None;
        for resource in &self.resources {
            resource.validate()?;
            if let Some(resource_id) = previous {
                if resource_id == resource.resource_id {
                    return Err(BondError::DuplicateResource(resource.resource_id));
                }
                if resource_id > resource.resource_id {
                    return Err(BondError::NonCanonicalEncoding("bond resource registry"));
                }
            }
            previous = Some(resource.resource_id);
        }
        Ok(())
    }

    /// Returns one registered resource.
    #[must_use]
    pub fn get(&self, resource_id: BondResourceId) -> Option<&BondResourceConfig> {
        self.resources
            .binary_search_by_key(&resource_id, |resource| resource.resource_id)
            .ok()
            .map(|index: usize| &self.resources[index])
    }

    /// Registers a new bond resource.
    pub fn add_resource(&mut self, resource: BondResourceConfig) -> Result<(), BondError> {
        resource.validate()?;
        match self
            .resources
            .binary_search_by_key(&resource.resource_id, |entry| entry.resource_id)
        {
            Ok(_) => Err(BondError::DuplicateResource(resource.resource_id)),
            Err(index) => {
                self.resources.insert(index, resource);
                Ok(())
            }
        }
    }

    /// Disables an existing bond resource.
    pub fn disable_resource(&mut self, resource_id: BondResourceId) -> Result<(), BondError> {
        let index = self
            .resources
            .binary_search_by_key(&resource_id, |entry| entry.resource_id)
            .map_err(|_| BondError::UnknownResource(resource_id))?;
        self.resources[index].enabled = false;
        Ok(())
    }

    /// Replaces the policy for an existing bond resource.
    pub fn update_resource(&mut self, resource: BondResourceConfig) -> Result<(), BondError> {
        resource.validate()?;
        let index = self
            .resources
            .binary_search_by_key(&resource.resource_id, |entry| entry.resource_id)
            .map_err(|_| BondError::UnknownResource(resource.resource_id))?;
        self.resources[index] = resource;
        Ok(())
    }
}

/// Slashable validator collateral.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondObject {
    /// Validator that controls this bond.
    pub validator_id: ValidatorId,
    /// Opaque resource used as collateral.
    pub resource_id: BondResourceId,
    /// Slashable amount.
    pub amount: Amount,
    /// Epoch when the bond became active.
    pub bonded_epoch: Epoch,
    /// First epoch when the bond may be withdrawn, if unbonding has started.
    pub unlock_epoch: Option<Epoch>,
}

impl BondObject {
    /// Validates the bond against one resource policy.
    pub fn validate_against(&self, config: &BondResourceConfig) -> Result<(), BondError> {
        config.validate()?;
        if self.resource_id != config.resource_id {
            return Err(BondError::ResourceConfigMismatch {
                bond_resource_id: self.resource_id,
                config_resource_id: config.resource_id,
            });
        }
        if !config.enabled {
            return Err(BondError::ResourceDisabled(config.resource_id));
        }
        if self.amount < config.min_bond {
            return Err(BondError::BondBelowMinimum {
                amount: self.amount,
                min_bond: config.min_bond,
            });
        }
        if let Some(max_validator_exposure) = config.max_validator_exposure
            && self.amount > max_validator_exposure
        {
            return Err(BondError::BondAboveExposure {
                amount: self.amount,
                max_validator_exposure,
            });
        }
        Ok(())
    }

    /// Returns whether the bond is still slashable at `epoch`.
    #[must_use]
    pub fn is_active_at(&self, epoch: Epoch) -> bool {
        match self.unlock_epoch {
            Some(unlock_epoch) => epoch.get() < unlock_epoch.get(),
            None => true,
        }
    }

    /// Starts unbonding using the configured delay for the bond resource.
    pub fn request_unbond(
        &mut self,
        registry: &BondResourceRegistry,
        epoch: Epoch,
    ) -> Result<(), BondError> {
        if self.unlock_epoch.is_some() {
            return Err(BondError::AlreadyUnbonding);
        }
        let config = registry
            .get(self.resource_id)
            .ok_or(BondError::UnknownResource(self.resource_id))?;
        let unlock_epoch = epoch
            .get()
            .checked_add(config.unbonding_epochs)
            .ok_or(BondError::UnlockEpochOverflow)?;
        self.unlock_epoch = Some(Epoch::new(unlock_epoch));
        Ok(())
    }
}

/// Cryptographically provable slashable offense categories.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlashingReason {
    /// Conflicting vote on the same object version or fast-path decision.
    ConflictingObjectVote = 0x0001,
    /// Consensus-layer equivocation.
    ConsensusEquivocation = 0x0002,
    /// Conflicting finalized statements.
    ConflictingFinalizedStatement = 0x0003,
    /// Any other provable double-signing offense.
    DoubleSigning = 0x0004,
}

impl SlashingReason {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// One slashable proof with two conflicting signed statements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvidence {
    /// Offending validator.
    pub validator_id: ValidatorId,
    /// Epoch in which the offense occurred.
    pub epoch: Epoch,
    /// Categorical slash reason.
    pub reason: SlashingReason,
    /// Digest of the first signed statement.
    pub left_statement: Digest32,
    /// Digest of the conflicting signed statement.
    pub right_statement: Digest32,
}

impl SlashingEvidence {
    /// Validates local evidence invariants.
    pub fn validate(&self) -> Result<(), BondError> {
        if self.left_statement == self.right_statement {
            return Err(BondError::IdenticalEvidenceDigests);
        }
        Ok(())
    }
}

/// Authenticated governance approval accepted by validator admission.
pub trait ValidatorAdmissionApproval {
    /// Returns the validator approved by governance.
    fn approved_validator_id(&self) -> ValidatorId;
}

/// Admission record evaluated against an epoch's externally supplied policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorAdmission {
    /// Validator being considered for admission.
    pub validator_id: ValidatorId,
    /// Optional slashable bond carried by the validator.
    pub bond: Option<BondObject>,
}

impl ValidatorAdmission {
    /// Validates the admission request under authenticated epoch context.
    pub fn validate(
        &self,
        registry: &BondResourceRegistry,
        active_policy: ValidatorAdmissionPolicy,
        approval: Option<&dyn ValidatorAdmissionApproval>,
        epoch: Epoch,
    ) -> Result<(), BondError> {
        if active_policy.requires_governance_approval() {
            let approval = approval.ok_or(BondError::MissingGovernanceApproval)?;
            if approval.approved_validator_id() != self.validator_id {
                return Err(BondError::ApprovalValidatorMismatch);
            }
        }

        if let Some(bond) = &self.bond {
            if bond.validator_id != self.validator_id {
                return Err(BondError::BondValidatorMismatch);
            }
            if bond.bonded_epoch > epoch {
                return Err(BondError::BondNotYetActive {
                    epoch,
                    bonded_epoch: bond.bonded_epoch,
                });
            }
            validate_bond_for_epoch(bond, registry, epoch)?;
        } else if active_policy.requires_bond() {
            return Err(BondError::MissingBond);
        }

        Ok(())
    }
}

fn validate_bond_for_epoch(
    bond: &BondObject,
    registry: &BondResourceRegistry,
    epoch: Epoch,
) -> Result<(), BondError> {
    let config = registry
        .get(bond.resource_id)
        .ok_or(BondError::UnknownResource(bond.resource_id))?;
    bond.validate_against(config)?;
    if !bond.is_active_at(epoch) {
        return Err(BondError::BondNotActive {
            epoch,
            unlock_epoch: bond
                .unlock_epoch
                .expect("inactive bonds always have an unlock epoch"),
        });
    }
    Ok(())
}

/// Encodes a validator admission policy.
pub fn encode_validator_admission_policy(
    policy: ValidatorAdmissionPolicy,
) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_ADMISSION_POLICY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, policy.as_u16())?;
    Ok(canonical.finish()?)
}

/// Strictly decodes a validator admission policy.
pub fn decode_validator_admission_policy(
    input: &[u8],
) -> Result<ValidatorAdmissionPolicy, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(VALIDATOR_ADMISSION_POLICY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let tag: u16 = frame.required_u16(1)?;
    let policy: ValidatorAdmissionPolicy = match tag {
        0x0001 => ValidatorAdmissionPolicy::GenesisPermissioned,
        0x0002 => ValidatorAdmissionPolicy::GovernancePermissioned,
        0x0003 => ValidatorAdmissionPolicy::BondAndGovernance,
        0x0004 => ValidatorAdmissionPolicy::BondRequired,
        _ => return Err(BondError::UnknownValidatorAdmissionPolicy(tag)),
    };
    require_exact_reencoding(
        input,
        encode_validator_admission_policy(policy)?,
        "validator admission policy",
    )?;
    Ok(policy)
}

/// Encodes an opaque bond resource identity.
pub fn encode_bond_resource_id(resource_id: BondResourceId) -> Result<Vec<u8>, BondError> {
    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(BOND_RESOURCE_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, resource_id.domain())?;
    canonical.field_bytes(2, resource_id.value())?;
    Ok(canonical.finish()?)
}

/// Strictly decodes an opaque bond resource identity.
pub fn decode_bond_resource_id(input: &[u8]) -> Result<BondResourceId, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(BOND_RESOURCE_ID_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let value: [u8; 32] = decode_fixed_field::<32>(&frame, 2)?;
    let resource_id: BondResourceId = BondResourceId::new(frame.required_u16(1)?, value)?;
    require_exact_reencoding(
        input,
        encode_bond_resource_id(resource_id)?,
        "bond resource id",
    )?;
    Ok(resource_id)
}

/// Encodes one bond resource policy.
pub fn encode_bond_resource_config(config: &BondResourceConfig) -> Result<Vec<u8>, BondError> {
    config.validate()?;

    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(BOND_RESOURCE_CONFIG_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_bond_resource_id(config.resource_id)?)?;
    canonical.field_u64(2, config.min_bond.get())?;
    canonical.field_bytes(3, [u8::from(config.enabled)])?;
    canonical.field_u64(4, config.unbonding_epochs)?;
    if let Some(max_validator_exposure) = config.max_validator_exposure {
        canonical.field_u64(5, max_validator_exposure.get())?;
    }
    Ok(canonical.finish()?)
}

/// Strictly decodes one bond resource policy.
pub fn decode_bond_resource_config(input: &[u8]) -> Result<BondResourceConfig, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(BOND_RESOURCE_CONFIG_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let config: BondResourceConfig = BondResourceConfig {
        resource_id: decode_bond_resource_id(frame.required_field(1)?)?,
        min_bond: Amount::new(frame.required_u64(2)?),
        enabled: decode_boolean_field(&frame, 3)?,
        unbonding_epochs: frame.required_u64(4)?,
        max_validator_exposure: decode_optional_u64_field(&frame, 5)?.map(Amount::new),
    };
    config.validate()?;
    require_exact_reencoding(
        input,
        encode_bond_resource_config(&config)?,
        "bond resource config",
    )?;
    Ok(config)
}

/// Encodes the bond resource registry.
pub fn encode_bond_resource_registry(
    registry: &BondResourceRegistry,
) -> Result<Vec<u8>, BondError> {
    registry.validate()?;

    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(BOND_RESOURCE_REGISTRY_TYPE_ID, ENCODING_VERSION);
    canonical.field_u32(
        1,
        u32::try_from(registry.resources.len())
            .map_err(|_| BondError::RegistryTooLarge(registry.resources.len()))?,
    )?;
    for (index, resource) in registry.resources.iter().enumerate() {
        let field_id: u16 = u16::try_from(index + 2)
            .map_err(|_| BondError::RegistryTooLarge(registry.resources.len()))?;
        canonical.field_bytes(field_id, encode_bond_resource_config(resource)?)?;
    }
    Ok(canonical.finish()?)
}

/// Strictly decodes a bond resource registry in canonical resource order.
pub fn decode_bond_resource_registry(input: &[u8]) -> Result<BondResourceRegistry, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(BOND_RESOURCE_REGISTRY_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let declared: usize = usize::try_from(frame.required_u32(1)?)
        .map_err(|_| BondError::RegistryTooLarge(usize::MAX))?;
    if declared > MAX_REGISTRY_RESOURCES {
        return Err(BondError::RegistryTooLarge(declared));
    }
    let actual: usize = frame.field_count().saturating_sub(1);
    if actual != declared {
        return Err(BondError::RegistryCountMismatch { declared, actual });
    }
    let mut resources: Vec<BondResourceConfig> = Vec::with_capacity(declared);
    let mut previous: Option<BondResourceId> = None;
    for index in 0..declared {
        let field_id: u16 =
            u16::try_from(index + 2).map_err(|_| BondError::RegistryTooLarge(declared))?;
        let resource: BondResourceConfig =
            decode_bond_resource_config(frame.required_field(field_id)?)?;
        if let Some(resource_id) = previous {
            if resource_id == resource.resource_id {
                return Err(BondError::DuplicateResource(resource.resource_id));
            }
            if resource_id > resource.resource_id {
                return Err(BondError::NonCanonicalEncoding("bond resource registry"));
            }
        }
        previous = Some(resource.resource_id);
        resources.push(resource);
    }
    let registry: BondResourceRegistry = BondResourceRegistry { resources };
    registry.validate()?;
    require_exact_reencoding(
        input,
        encode_bond_resource_registry(&registry)?,
        "bond resource registry",
    )?;
    Ok(registry)
}

/// Encodes one bond object.
pub fn encode_bond_object(bond: &BondObject) -> Result<Vec<u8>, BondError> {
    let mut canonical: CanonicalStruct =
        CanonicalStruct::new(BOND_OBJECT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, bond.validator_id.as_bytes())?;
    canonical.field_bytes(2, encode_bond_resource_id(bond.resource_id)?)?;
    canonical.field_u64(3, bond.amount.get())?;
    canonical.field_bytes(4, encode_epoch(bond.bonded_epoch)?)?;
    if let Some(unlock_epoch) = bond.unlock_epoch {
        canonical.field_bytes(5, encode_epoch(unlock_epoch)?)?;
    }
    Ok(canonical.finish()?)
}

/// Strictly decodes one bond object.
pub fn decode_bond_object(input: &[u8]) -> Result<BondObject, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(BOND_OBJECT_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let bond: BondObject = BondObject {
        validator_id: decode_validator_id_field(&frame, 1)?,
        resource_id: decode_bond_resource_id(frame.required_field(2)?)?,
        amount: Amount::new(frame.required_u64(3)?),
        bonded_epoch: decode_epoch_exact(frame.required_field(4)?)?,
        unlock_epoch: frame.field(5).map(decode_epoch_exact).transpose()?,
    };
    require_exact_reencoding(input, encode_bond_object(&bond)?, "bond object")?;
    Ok(bond)
}

/// Encodes a slashing reason.
pub fn encode_slashing_reason(reason: SlashingReason) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(SLASHING_REASON_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, reason.as_u16())?;
    Ok(canonical.finish()?)
}

/// Strictly decodes a slashing reason.
pub fn decode_slashing_reason(input: &[u8]) -> Result<SlashingReason, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(SLASHING_REASON_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let tag: u16 = frame.required_u16(1)?;
    let reason: SlashingReason = match tag {
        0x0001 => SlashingReason::ConflictingObjectVote,
        0x0002 => SlashingReason::ConsensusEquivocation,
        0x0003 => SlashingReason::ConflictingFinalizedStatement,
        0x0004 => SlashingReason::DoubleSigning,
        _ => return Err(BondError::UnknownSlashingReason(tag)),
    };
    require_exact_reencoding(input, encode_slashing_reason(reason)?, "slashing reason")?;
    Ok(reason)
}

/// Encodes slashable evidence.
pub fn encode_slashing_evidence(evidence: &SlashingEvidence) -> Result<Vec<u8>, BondError> {
    evidence.validate()?;

    let mut canonical = CanonicalStruct::new(SLASHING_EVIDENCE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, evidence.validator_id.as_bytes())?;
    canonical.field_bytes(2, encode_epoch(evidence.epoch)?)?;
    canonical.field_bytes(3, encode_slashing_reason(evidence.reason)?)?;
    canonical.field_bytes(4, encode_digest32(&evidence.left_statement)?)?;
    canonical.field_bytes(5, encode_digest32(&evidence.right_statement)?)?;
    Ok(canonical.finish()?)
}

/// Strictly decodes slashable evidence.
pub fn decode_slashing_evidence(input: &[u8]) -> Result<SlashingEvidence, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(SLASHING_EVIDENCE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let evidence: SlashingEvidence = SlashingEvidence {
        validator_id: decode_validator_id_field(&frame, 1)?,
        epoch: decode_epoch_exact(frame.required_field(2)?)?,
        reason: decode_slashing_reason(frame.required_field(3)?)?,
        left_statement: decode_digest32(frame.required_field(4)?)?,
        right_statement: decode_digest32(frame.required_field(5)?)?,
    };
    evidence.validate()?;
    require_exact_reencoding(
        input,
        encode_slashing_evidence(&evidence)?,
        "slashing evidence",
    )?;
    Ok(evidence)
}

/// Encodes one validator admission record.
pub fn encode_validator_admission(admission: &ValidatorAdmission) -> Result<Vec<u8>, BondError> {
    let mut canonical = CanonicalStruct::new(VALIDATOR_ADMISSION_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, admission.validator_id.as_bytes())?;
    if let Some(bond) = &admission.bond {
        // Fields 2 and 3 belonged to the removed caller-asserted policy and
        // approval boolean. Keep field 4 stable for persisted admission blobs.
        canonical.field_bytes(4, encode_bond_object(bond)?)?;
    }
    Ok(canonical.finish()?)
}

/// Strictly decodes one validator admission record.
pub fn decode_validator_admission(input: &[u8]) -> Result<ValidatorAdmission, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(VALIDATOR_ADMISSION_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 4])?;
    let admission: ValidatorAdmission = ValidatorAdmission {
        validator_id: decode_validator_id_field(&frame, 1)?,
        bond: frame.field(4).map(decode_bond_object).transpose()?,
    };
    require_exact_reencoding(
        input,
        encode_validator_admission(&admission)?,
        "validator admission",
    )?;
    Ok(admission)
}

fn decode_fixed_field<const N: usize>(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<[u8; N], BondError> {
    let bytes: &[u8] = frame.required_field(field_id)?;
    bytes
        .try_into()
        .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
            field_id,
            expected: N,
            actual: bytes.len(),
        })
        .map_err(BondError::from)
}

fn decode_validator_id_field(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<ValidatorId, BondError> {
    Ok(ValidatorId::new(decode_fixed_field::<32>(frame, field_id)?))
}

fn decode_boolean_field(frame: &CanonicalFrame<'_>, field_id: u16) -> Result<bool, BondError> {
    let bytes: [u8; 1] = decode_fixed_field::<1>(frame, field_id)?;
    match bytes[0] {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(BondError::InvalidBoolean(value)),
    }
}

fn decode_optional_u64_field(
    frame: &CanonicalFrame<'_>,
    field_id: u16,
) -> Result<Option<u64>, BondError> {
    let Some(bytes) = frame.field(field_id) else {
        return Ok(None);
    };
    let value: [u8; 8] = bytes.try_into().map_err(|_| {
        BondError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id,
            expected: 8,
            actual: bytes.len(),
        })
    })?;
    Ok(Some(u64::from_le_bytes(value)))
}

fn decode_epoch_exact(input: &[u8]) -> Result<Epoch, BondError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(EPOCH_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let epoch: Epoch = Epoch::new(frame.required_u64(1)?);
    require_exact_reencoding(input, encode_epoch(epoch)?, "epoch")?;
    Ok(epoch)
}

fn require_exact_reencoding(
    input: &[u8],
    encoded: Vec<u8>,
    kind: &'static str,
) -> Result<(), BondError> {
    if encoded.as_slice() != input {
        return Err(BondError::NonCanonicalEncoding(kind));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect()
    }

    fn resource(byte: u8) -> BondResourceId {
        BondResourceId::new(u16::from(byte) + 1, [byte; 32]).unwrap()
    }

    fn validator(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn sample_resource_config(byte: u8) -> BondResourceConfig {
        BondResourceConfig {
            resource_id: resource(byte),
            min_bond: Amount::new(100),
            enabled: true,
            unbonding_epochs: 7,
            max_validator_exposure: Some(Amount::new(500)),
        }
    }

    fn sample_bond() -> BondObject {
        BondObject {
            validator_id: validator(0x44),
            resource_id: resource(0x33),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(3),
            unlock_epoch: Some(Epoch::new(10)),
        }
    }

    fn sample_evidence() -> SlashingEvidence {
        SlashingEvidence {
            validator_id: validator(0x55),
            epoch: Epoch::new(9),
            reason: SlashingReason::DoubleSigning,
            left_statement: digest(0xAA),
            right_statement: digest(0xBB),
        }
    }

    #[test]
    fn registry_keeps_resources_sorted() {
        let mut registry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0xBB)).unwrap();
        registry.add_resource(sample_resource_config(0xAA)).unwrap();

        assert_eq!(registry.resources()[0].resource_id, resource(0xAA));
        assert_eq!(registry.resources()[1].resource_id, resource(0xBB));
    }

    #[test]
    fn registry_validation_distinguishes_duplicates_from_noncanonical_order() {
        let duplicate_id: BondResourceId = resource(0xAA);
        let duplicate: BondResourceRegistry = BondResourceRegistry {
            resources: vec![sample_resource_config(0xAA), sample_resource_config(0xAA)],
        };
        assert_eq!(
            duplicate.validate(),
            Err(BondError::DuplicateResource(duplicate_id))
        );

        let reversed: BondResourceRegistry = BondResourceRegistry {
            resources: vec![sample_resource_config(0xBB), sample_resource_config(0xAA)],
        };
        assert_eq!(
            reversed.validate(),
            Err(BondError::NonCanonicalEncoding("bond resource registry"))
        );
    }

    #[test]
    fn request_unbond_sets_unlock_epoch_from_resource_config() {
        let mut registry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0x11)).unwrap();

        let mut bond = BondObject {
            validator_id: validator(0x22),
            resource_id: resource(0x11),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(10),
            unlock_epoch: None,
        };

        bond.request_unbond(&registry, Epoch::new(40)).unwrap();

        assert_eq!(bond.unlock_epoch, Some(Epoch::new(47)));
        assert!(bond.is_active_at(Epoch::new(46)));
        assert!(!bond.is_active_at(Epoch::new(47)));
    }

    #[test]
    fn request_unbond_allows_withdrawal_after_policy_tightens() {
        let mut registry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0x12)).unwrap();

        let mut bond = BondObject {
            validator_id: validator(0x23),
            resource_id: resource(0x12),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(10),
            unlock_epoch: None,
        };

        let mut stricter_policy = sample_resource_config(0x12);
        stricter_policy.enabled = false;
        stricter_policy.min_bond = Amount::new(200);
        registry.update_resource(stricter_policy).unwrap();
        let updated_policy = registry.get(resource(0x12)).unwrap();

        assert!(!updated_policy.enabled);
        assert_eq!(updated_policy.min_bond, Amount::new(200));
        assert_eq!(
            bond.validate_against(updated_policy),
            Err(BondError::ResourceDisabled(resource(0x12)))
        );

        bond.request_unbond(&registry, Epoch::new(40)).unwrap();

        assert_eq!(bond.unlock_epoch, Some(Epoch::new(47)));
    }

    #[test]
    fn bond_validation_rejects_a_policy_for_another_resource() {
        let bond: BondObject = sample_bond();
        let config: BondResourceConfig = sample_resource_config(0x34);

        assert_eq!(
            bond.validate_against(&config),
            Err(BondError::ResourceConfigMismatch {
                bond_resource_id: resource(0x33),
                config_resource_id: resource(0x34),
            })
        );
    }

    #[test]
    fn validator_admission_enforces_bond_and_governance_policy() {
        struct Approval(ValidatorId);
        impl ValidatorAdmissionApproval for Approval {
            fn approved_validator_id(&self) -> ValidatorId {
                self.0
            }
        }

        let mut registry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0x33)).unwrap();

        let bond = BondObject {
            validator_id: validator(0x44),
            resource_id: resource(0x33),
            amount: Amount::new(150),
            bonded_epoch: Epoch::new(3),
            unlock_epoch: None,
        };

        let missing_governance = ValidatorAdmission {
            validator_id: validator(0x44),
            bond: Some(bond.clone()),
        };
        assert_eq!(
            missing_governance.validate(
                &registry,
                ValidatorAdmissionPolicy::BondAndGovernance,
                None,
                Epoch::new(5)
            ),
            Err(BondError::MissingGovernanceApproval)
        );

        let valid = ValidatorAdmission {
            validator_id: validator(0x44),
            bond: Some(bond),
        };
        let approval = Approval(validator(0x44));
        assert_eq!(
            valid.validate(
                &registry,
                ValidatorAdmissionPolicy::BondAndGovernance,
                Some(&approval),
                Epoch::new(5)
            ),
            Ok(())
        );
    }

    #[test]
    fn validator_admission_rejects_another_validators_bond() {
        let mut registry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0x33)).unwrap();
        let admission = ValidatorAdmission {
            validator_id: validator(0x44),
            bond: Some(BondObject {
                validator_id: validator(0x45),
                resource_id: resource(0x33),
                amount: Amount::new(150),
                bonded_epoch: Epoch::new(3),
                unlock_epoch: None,
            }),
        };
        assert_eq!(
            admission.validate(
                &registry,
                ValidatorAdmissionPolicy::BondRequired,
                None,
                Epoch::new(5)
            ),
            Err(BondError::BondValidatorMismatch)
        );
    }

    #[test]
    fn slashing_evidence_requires_distinct_statement_digests() {
        let evidence = SlashingEvidence {
            validator_id: validator(0x55),
            epoch: Epoch::new(9),
            reason: SlashingReason::DoubleSigning,
            left_statement: digest(0xAA),
            right_statement: digest(0xAA),
        };

        assert_eq!(
            evidence.validate(),
            Err(BondError::IdenticalEvidenceDigests)
        );
    }

    #[test]
    fn bond_registry_encoding_changes_when_resource_is_added() {
        let registry = BondResourceRegistry::new();
        let empty = encode_bond_resource_registry(&registry).unwrap();

        let mut populated = BondResourceRegistry::new();
        populated
            .add_resource(sample_resource_config(0x77))
            .unwrap();
        let with_resource = encode_bond_resource_registry(&populated).unwrap();

        assert_ne!(empty, with_resource);
    }

    #[test]
    fn bond_resource_id_has_stable_type_id_and_round_trips() {
        let resource_id: BondResourceId = BondResourceId::new(7, [0x30; 32]).unwrap();
        let encoded: Vec<u8> = encode_bond_resource_id(resource_id).unwrap();

        assert_eq!(&encoded[4..6], &BOND_RESOURCE_ID_TYPE_ID.to_le_bytes());
        assert_eq!(
            hex(&encoded),
            concat!(
                "534e5245088001000200",
                "0100020000000700",
                "020020000000",
                "3030303030303030303030303030303030303030303030303030303030303030"
            )
        );
        assert_eq!(decode_bond_resource_id(&encoded), Ok(resource_id));
        assert_eq!(
            BondResourceId::new(0, [0x30; 32]),
            Err(BondError::ZeroResourceDomain)
        );
    }

    #[test]
    fn resource_config_and_registry_strict_decoders_round_trip() {
        let mut registry: BondResourceRegistry = BondResourceRegistry::new();
        registry.add_resource(sample_resource_config(0x10)).unwrap();
        let mut uncapped: BondResourceConfig = sample_resource_config(0x20);
        uncapped.enabled = false;
        uncapped.max_validator_exposure = None;
        registry.add_resource(uncapped.clone()).unwrap();

        let config_bytes: Vec<u8> = encode_bond_resource_config(&uncapped).unwrap();
        let registry_bytes: Vec<u8> = encode_bond_resource_registry(&registry).unwrap();

        assert_eq!(decode_bond_resource_config(&config_bytes), Ok(uncapped));
        assert_eq!(decode_bond_resource_registry(&registry_bytes), Ok(registry));
    }

    #[test]
    fn bond_object_and_admission_strict_decoders_round_trip() {
        let bond: BondObject = sample_bond();
        let admission: ValidatorAdmission = ValidatorAdmission {
            validator_id: bond.validator_id,
            bond: Some(bond.clone()),
        };
        let bond_bytes: Vec<u8> = encode_bond_object(&bond).unwrap();
        let admission_bytes: Vec<u8> = encode_validator_admission(&admission).unwrap();

        assert_eq!(decode_bond_object(&bond_bytes), Ok(bond));
        assert_eq!(decode_validator_admission(&admission_bytes), Ok(admission));

        let no_bond: ValidatorAdmission = ValidatorAdmission {
            validator_id: validator(0x66),
            bond: None,
        };
        let no_bond_bytes: Vec<u8> = encode_validator_admission(&no_bond).unwrap();
        assert_eq!(decode_validator_admission(&no_bond_bytes), Ok(no_bond));
    }

    #[test]
    fn policy_reason_and_evidence_strict_decoders_round_trip() {
        let policies: [ValidatorAdmissionPolicy; 4] = [
            ValidatorAdmissionPolicy::GenesisPermissioned,
            ValidatorAdmissionPolicy::GovernancePermissioned,
            ValidatorAdmissionPolicy::BondAndGovernance,
            ValidatorAdmissionPolicy::BondRequired,
        ];
        for policy in policies {
            let encoded: Vec<u8> = encode_validator_admission_policy(policy).unwrap();
            assert_eq!(decode_validator_admission_policy(&encoded), Ok(policy));
        }

        let reasons: [SlashingReason; 4] = [
            SlashingReason::ConflictingObjectVote,
            SlashingReason::ConsensusEquivocation,
            SlashingReason::ConflictingFinalizedStatement,
            SlashingReason::DoubleSigning,
        ];
        for reason in reasons {
            let encoded: Vec<u8> = encode_slashing_reason(reason).unwrap();
            assert_eq!(decode_slashing_reason(&encoded), Ok(reason));
        }

        let evidence: SlashingEvidence = sample_evidence();
        let encoded: Vec<u8> = encode_slashing_evidence(&evidence).unwrap();
        assert_eq!(decode_slashing_evidence(&encoded), Ok(evidence));
    }

    #[test]
    fn decoders_reject_zero_domain_unknown_tags_and_invalid_boolean() {
        let mut zero_resource: CanonicalStruct =
            CanonicalStruct::new(BOND_RESOURCE_ID_TYPE_ID, ENCODING_VERSION);
        zero_resource.field_u16(1, 0).unwrap();
        zero_resource.field_bytes(2, [0x30; 32]).unwrap();
        assert_eq!(
            decode_bond_resource_id(&zero_resource.finish().unwrap()),
            Err(BondError::ZeroResourceDomain)
        );

        let mut unknown_policy: CanonicalStruct =
            CanonicalStruct::new(VALIDATOR_ADMISSION_POLICY_TYPE_ID, ENCODING_VERSION);
        unknown_policy.field_u16(1, 0xFFFF).unwrap();
        assert_eq!(
            decode_validator_admission_policy(&unknown_policy.finish().unwrap()),
            Err(BondError::UnknownValidatorAdmissionPolicy(0xFFFF))
        );

        let mut unknown_reason: CanonicalStruct =
            CanonicalStruct::new(SLASHING_REASON_TYPE_ID, ENCODING_VERSION);
        unknown_reason.field_u16(1, 0xFFFF).unwrap();
        assert_eq!(
            decode_slashing_reason(&unknown_reason.finish().unwrap()),
            Err(BondError::UnknownSlashingReason(0xFFFF))
        );

        let config: BondResourceConfig = sample_resource_config(0x20);
        let mut invalid_boolean: CanonicalStruct =
            CanonicalStruct::new(BOND_RESOURCE_CONFIG_TYPE_ID, ENCODING_VERSION);
        invalid_boolean
            .field_bytes(1, encode_bond_resource_id(config.resource_id).unwrap())
            .unwrap();
        invalid_boolean.field_u64(2, config.min_bond.get()).unwrap();
        invalid_boolean.field_bytes(3, [2]).unwrap();
        invalid_boolean
            .field_u64(4, config.unbonding_epochs)
            .unwrap();
        invalid_boolean
            .field_u64(5, config.max_validator_exposure.unwrap().get())
            .unwrap();
        assert_eq!(
            decode_bond_resource_config(&invalid_boolean.finish().unwrap()),
            Err(BondError::InvalidBoolean(2))
        );
    }

    #[test]
    fn registry_decoder_rejects_count_mismatch_and_noncanonical_order() {
        let low: BondResourceConfig = sample_resource_config(0x10);
        let high: BondResourceConfig = sample_resource_config(0x20);

        let mut count_mismatch: CanonicalStruct =
            CanonicalStruct::new(BOND_RESOURCE_REGISTRY_TYPE_ID, ENCODING_VERSION);
        count_mismatch.field_u32(1, 1).unwrap();
        assert_eq!(
            decode_bond_resource_registry(&count_mismatch.finish().unwrap()),
            Err(BondError::RegistryCountMismatch {
                declared: 1,
                actual: 0,
            })
        );

        let mut reversed: CanonicalStruct =
            CanonicalStruct::new(BOND_RESOURCE_REGISTRY_TYPE_ID, ENCODING_VERSION);
        reversed.field_u32(1, 2).unwrap();
        reversed
            .field_bytes(2, encode_bond_resource_config(&high).unwrap())
            .unwrap();
        reversed
            .field_bytes(3, encode_bond_resource_config(&low).unwrap())
            .unwrap();
        assert_eq!(
            decode_bond_resource_registry(&reversed.finish().unwrap()),
            Err(BondError::NonCanonicalEncoding("bond resource registry"))
        );

        let mut duplicated: CanonicalStruct =
            CanonicalStruct::new(BOND_RESOURCE_REGISTRY_TYPE_ID, ENCODING_VERSION);
        duplicated.field_u32(1, 2).unwrap();
        duplicated
            .field_bytes(2, encode_bond_resource_config(&low).unwrap())
            .unwrap();
        duplicated
            .field_bytes(3, encode_bond_resource_config(&low).unwrap())
            .unwrap();
        assert_eq!(
            decode_bond_resource_registry(&duplicated.finish().unwrap()),
            Err(BondError::DuplicateResource(low.resource_id))
        );
    }

    #[test]
    fn evidence_and_admission_decoders_reject_invalid_records() {
        let evidence: SlashingEvidence = sample_evidence();
        let mut identical: CanonicalStruct =
            CanonicalStruct::new(SLASHING_EVIDENCE_TYPE_ID, ENCODING_VERSION);
        identical
            .field_bytes(1, evidence.validator_id.as_bytes())
            .unwrap();
        identical
            .field_bytes(2, encode_epoch(evidence.epoch).unwrap())
            .unwrap();
        identical
            .field_bytes(3, encode_slashing_reason(evidence.reason).unwrap())
            .unwrap();
        identical
            .field_bytes(4, encode_digest32(&evidence.left_statement).unwrap())
            .unwrap();
        identical
            .field_bytes(5, encode_digest32(&evidence.left_statement).unwrap())
            .unwrap();
        assert_eq!(
            decode_slashing_evidence(&identical.finish().unwrap()),
            Err(BondError::IdenticalEvidenceDigests)
        );

        let admission: ValidatorAdmission = ValidatorAdmission {
            validator_id: validator(0x44),
            bond: None,
        };
        let mut legacy_fields: CanonicalStruct =
            CanonicalStruct::new(VALIDATOR_ADMISSION_TYPE_ID, ENCODING_VERSION);
        legacy_fields
            .field_bytes(1, admission.validator_id.as_bytes())
            .unwrap();
        legacy_fields.field_bytes(2, [1]).unwrap();
        assert_eq!(
            decode_validator_admission(&legacy_fields.finish().unwrap()),
            Err(BondError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(2)
            ))
        );
    }
}
