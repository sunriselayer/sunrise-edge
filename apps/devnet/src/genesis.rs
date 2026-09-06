//! Committed protocol configuration for the local-only developer network.

use crate::standard_asset::derive_devnet_asset_id;
use fees::{FeeAsset, GasSchedule};
use hashing::{HashSuiteResolver, HashingError};
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, ProtocolConfigError, TransactionAuthProfile,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion};
use standard_assets::{AssetId, StandardAssetError};
use std::{error::Error, fmt};

/// Flat base cost charged on every fee-metered devnet transaction.
///
/// Non-zero so a declared treasury access always corresponds to a non-zero
/// settled fee: `settle_fee_payment` never has to reject a positive
/// `worst_case_fee_units()` as accidentally zero-amount.
const DEVNET_BASE_FEE: u64 = 1;
/// Fee-unit price per execution unit (`gas_used`).
///
/// Every other `GasSchedule` price stays `0`: nothing measures reads,
/// writes, storage, or system-module usage yet, so pricing them would imply
/// a charge nobody computes.
const DEVNET_EXECUTION_PRICE: u64 = 1;
/// One devnet fee unit equals one unit of the devnet's one derived
/// [`standard_assets::AssetId`] (see [`derive_devnet_asset_id`]).
const DEVNET_FEE_UNITS_PER_ASSET_UNIT: u64 = 1;

/// Protocol version used by the local developer network.
///
/// Bumped from 3 to 4 by this slice: `node_core::MIN_OWNER_TRANSITION_PROTOCOL_VERSION`
/// gates every committed [`node_core::PreinstalledOwnerTransitionPolicy`] on
/// `protocol_version >= 4`, and the Standard Asset v1 whole-coin transfer
/// module this devnet installs uses exactly that policy (see DR-0107).
pub const DEVNET_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(4);

/// The single logical atomicity domain used by the local developer network.
///
/// This value must remain aligned with the namespace opened by `boot`.
pub const DEVNET_DOMAIN_BYTES: [u8; 32] = [0x44; 32];

const DEVNET_DOMAIN_PLACEMENT_RULE_VERSION: u32 = 1;

/// One validated devnet protocol configuration and the resolver derived from
/// that exact configuration's committed hash-suite schedule.
#[derive(Clone, Debug)]
pub struct DevnetProtocolContext {
    chain_id: ChainId,
    epoch: Epoch,
    domain: AtomicityDomainId,
    protocol_config: ProtocolConfig,
    resolver: HashSuiteResolver,
    asset_id: AssetId,
}

impl DevnetProtocolContext {
    /// Returns the chain identifier bound into every devnet hash frame.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the configured devnet epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the devnet's sole logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the committed protocol configuration.
    #[must_use]
    pub const fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the resolver derived from `protocol_config`.
    #[must_use]
    pub const fn resolver(&self) -> &HashSuiteResolver {
        &self.resolver
    }

    /// Returns the devnet's one derived Standard Asset v1 [`AssetId`] (see
    /// [`crate::standard_asset::derive_devnet_asset_id`]).
    #[must_use]
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
        AssetId,
    ) {
        (
            self.chain_id,
            self.epoch,
            self.domain,
            self.protocol_config,
            self.resolver,
            self.asset_id,
        )
    }
}

/// Builds protocol version 4 configuration for one local developer network.
///
/// The configuration uses one fixed non-zero domain, the committed Ed25519
/// address-is-public-key authentication profile, and the genesis hash-suite
/// schedule. The resolver is built first, from the config's own
/// chain/protocol-version/hash-suite-schedule alone (before `fee_assets` is
/// populated), so the devnet's one Standard Asset v1 [`AssetId`] can be
/// derived through it via [`derive_devnet_asset_id`] — never a hardcoded
/// literal (see DR-0107, F6). Its committed `gas_schedule` charges
/// [`DEVNET_BASE_FEE`] plus [`DEVNET_EXECUTION_PRICE`] per `gas_used` unit,
/// and its `fee_assets` registry enables exactly the derived `AssetId` at
/// [`DEVNET_FEE_UNITS_PER_ASSET_UNIT`] fee unit per asset unit: the devnet
/// uses one ordinary Standard Asset v1 asset for both transfers and fees,
/// never a privileged native coin or a separate fee-only asset.
pub fn build_devnet_protocol_context(
    chain_id: ChainId,
    epoch: Epoch,
) -> Result<DevnetProtocolContext, DevnetGenesisError> {
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetGenesisError::InvalidStaticDomain)?;
    let domain_placement: DomainPlacementManifest = DomainPlacementManifest::single_domain(
        DEVNET_DOMAIN_PLACEMENT_RULE_VERSION,
        domain,
        Epoch::new(0),
    )
    .map_err(DevnetGenesisError::ProtocolConfig)?;

    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = DEVNET_PROTOCOL_VERSION;
    protocol_config.domain_placement = Some(domain_placement);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    protocol_config.gas_schedule = GasSchedule {
        base_fee: DEVNET_BASE_FEE,
        execution_price: DEVNET_EXECUTION_PRICE,
        read_price: 0,
        write_price: 0,
        storage_price: 0,
        system_module_price: 0,
    };

    // The resolver is built from the config's chain/version/schedule alone,
    // strictly before `fee_assets` is populated: the derived `AssetId` must
    // never depend on itself being already registered.
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_config.protocol_version,
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetGenesisError::Hashing)?;
    resolver
        .suite_for_epoch(epoch)
        .map_err(DevnetGenesisError::Hashing)?;

    let asset_id: AssetId =
        derive_devnet_asset_id(&resolver, epoch).map_err(DevnetGenesisError::StandardAsset)?;

    protocol_config
        .fee_assets
        .add_asset(FeeAsset {
            asset_id,
            fee_units_per_asset_unit: DEVNET_FEE_UNITS_PER_ASSET_UNIT,
            enabled: true,
        })
        .map_err(DevnetGenesisError::Fees)?;
    protocol_config
        .validate()
        .map_err(DevnetGenesisError::ProtocolConfig)?;

    Ok(DevnetProtocolContext {
        chain_id,
        epoch,
        domain,
        protocol_config,
        resolver,
        asset_id,
    })
}

/// Failures while constructing committed devnet protocol configuration.
#[derive(Debug)]
pub enum DevnetGenesisError {
    /// The compile-time domain constant unexpectedly violated its non-zero
    /// invariant.
    InvalidStaticDomain,
    /// Protocol configuration validation failed closed.
    ProtocolConfig(ProtocolConfigError),
    /// The committed hash-suite schedule could not build or resolve.
    Hashing(HashingError),
    /// The devnet's one Standard Asset v1 `AssetId` failed to derive.
    StandardAsset(StandardAssetError),
    /// The committed fee-asset registry failed to register the devnet asset.
    Fees(fees::FeeError),
}

impl fmt::Display for DevnetGenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStaticDomain => {
                formatter.write_str("devnet's static atomicity domain is invalid")
            }
            Self::ProtocolConfig(error) => {
                write!(
                    formatter,
                    "devnet protocol configuration is invalid: {error}"
                )
            }
            Self::Hashing(error) => {
                write!(
                    formatter,
                    "devnet hash-suite configuration is invalid: {error}"
                )
            }
            Self::StandardAsset(error) => {
                write!(formatter, "devnet asset id derivation failed: {error}")
            }
            Self::Fees(error) => {
                write!(
                    formatter,
                    "devnet fee-asset configuration is invalid: {error}"
                )
            }
        }
    }
}

impl Error for DevnetGenesisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidStaticDomain => None,
            Self::ProtocolConfig(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::StandardAsset(error) => Some(error),
            Self::Fees(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_config::{
        AddressBinding, ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
    };
    use protocol_types::{HashPurpose, SignatureSchemeId};

    fn test_chain() -> ChainId {
        ChainId::new("sunrise-devnet-test").unwrap()
    }

    #[test]
    fn config_and_resolver_share_chain_version_and_schedule() {
        let epoch: Epoch = Epoch::new(17);
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), epoch).unwrap();
        let config: &ProtocolConfig = context.protocol_config();

        assert_eq!(config.protocol_version, DEVNET_PROTOCOL_VERSION);
        assert_eq!(
            context.resolver().protocol_version(),
            config.protocol_version
        );
        assert_eq!(context.resolver().chain_id(), context.chain_id());
        assert_eq!(
            context.resolver().suite_for_epoch(epoch).unwrap(),
            config.hash_suite_schedule.active_at(epoch).unwrap()
        );
        assert_eq!(
            config
                .domain_placement
                .as_ref()
                .unwrap()
                .resolve_domain(epoch, 1),
            Ok(context.domain())
        );

        let first: protocol_types::Digest32 = context
            .resolver()
            .hash_for_purpose(epoch, HashPurpose::ProtocolConfig, b"alignment")
            .unwrap();
        let derived: HashSuiteResolver = HashSuiteResolver::new(
            context.chain_id().clone(),
            config.protocol_version,
            config.hash_suite_schedule.entries().to_vec(),
        )
        .unwrap();
        assert_eq!(
            derived
                .hash_for_purpose(epoch, HashPurpose::ProtocolConfig, b"alignment")
                .unwrap(),
            first
        );
    }

    #[test]
    fn devnet_has_strict_ed25519_owner_auth_and_one_enabled_fee_asset() {
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(0)).unwrap();
        let config: &ProtocolConfig = context.protocol_config();
        let profile = config.transaction_auth_profile.as_ref().unwrap();

        assert_eq!(config.fee_assets.len(), 1);
        let fee_asset = config.fee_assets.get(context.asset_id()).unwrap();
        assert!(fee_asset.enabled);
        assert_eq!(
            fee_asset.fee_units_per_asset_unit,
            DEVNET_FEE_UNITS_PER_ASSET_UNIT
        );
        assert_eq!(config.gas_schedule.base_fee, DEVNET_BASE_FEE);
        assert_eq!(config.gas_schedule.execution_price, DEVNET_EXECUTION_PRICE);
        assert_eq!(config.gas_schedule.read_price, 0);
        assert_eq!(config.gas_schedule.write_price, 0);
        assert_eq!(config.gas_schedule.storage_price, 0);
        assert_eq!(config.gas_schedule.system_module_price, 0);
        assert_eq!(
            profile.profile_id(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID
        );
        assert_eq!(profile.signature_scheme_id(), SignatureSchemeId::Ed25519);
        assert_eq!(
            profile.address_binding(),
            AddressBinding::CanonicalPrimeOrderAddressIsPublicKey
        );
        assert_eq!(config.validate(), Ok(()));
    }

    /// Pins F2/DR-0107's load-bearing coupling: the fee-payer `Coin<A>`
    /// `Write` access has an effect only because the devnet's settled fee is
    /// always non-zero. A future accidental reduction of `DEVNET_BASE_FEE` to
    /// `0` (with `execution_price` also `0`) would make a worst-case-free
    /// call's fee `Write` access have no possible effect and fail with a
    /// generic `ObjectEffectMismatch`, so this asserts the committed schedule
    /// stays non-zero.
    #[test]
    fn devnet_gas_schedule_base_fee_is_nonzero() {
        assert_ne!(DEVNET_BASE_FEE, 0);
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(0)).unwrap();
        assert_ne!(context.protocol_config().gas_schedule.base_fee, 0);
    }

    /// F7/DR-0107: this activation slice does not reconcile
    /// `objects::apply_lazy_migration`'s raw `Digest32` comparison; that
    /// remains defensible only because the devnet never enables
    /// `FeatureFlag::LazyObjectMigration`, so no committed migration
    /// descriptor can ever be consulted for a Standard Asset v1 object.
    #[test]
    fn devnet_never_enables_lazy_object_migration() {
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(0)).unwrap();
        assert!(
            !context
                .protocol_config()
                .feature_flags
                .contains(protocol_upgrades::FeatureFlag::LazyObjectMigration)
        );
    }

    #[test]
    fn devnet_asset_id_is_derived_not_hardcoded() {
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(11)).unwrap();
        let expected =
            crate::standard_asset::derive_devnet_asset_id(context.resolver(), context.epoch())
                .unwrap();
        assert_eq!(context.asset_id(), expected);

        let other_epoch_context: DevnetProtocolContext =
            build_devnet_protocol_context(test_chain(), Epoch::new(12)).unwrap();
        assert_ne!(context.asset_id(), other_epoch_context.asset_id());
    }
}
