//! Closed, signed public paid-contract genesis for the local developer network.
//!
//! This module alone knows that the genesis package is Standard Asset. Node
//! core receives only bounded canonical manifest entries and never decodes an
//! amount or supply field.

use abi::{
    AccessManifest,
    call_values::{CallValue, encode_call_value},
    package_types::{PackageOrigin, ScopedTypeArg, derive_scoped_type_id},
};
use bonds::{BondResourceConfig, BondResourceId};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::{
    call::{CallIntent, InstanceTarget},
    local_execution::{
        InstanceRecord, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
        ObjectAuthority, SignedLocalExecutionIntent, generic_object_result_semantics,
        instance_target, local_execution_signing_frame,
    },
    paid_execution::{MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidFeePolicy},
    publication::{
        ArtifactParts, CodeArtifact, PublicationContext, PublicationRequest, PublicationSubmission,
        UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
    },
};
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use node_core::economics::{FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy};
use node_core::fast_path::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use node_core::genesis::{
    GenesisError, GenesisInstallOutcome, GenesisManifest, GenesisObjectEntry,
    genesis_manifest_commitment, genesis_manifest_signing_frame, install_genesis,
};
use objects::{Address, Object, ObjectId, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::{Digest32, Epoch, HashPurpose, SignatureSchemeId, ValidatorId};
use public_standard_asset::{
    SCHEMA_VERSION, asset_type_argument, build_package, coin_amount, coin_body_layout,
    coin_type_tag, definition_body_layout, definition_type_tag, no_arguments, reservation_type_tag,
    treasury_cap_body_layout, treasury_cap_type_tag, treasury_supply,
};
use runtime::{AtomicityDomainId, DurableOperationContext, StructuredDurableDomainStateStore};
use std::{error::Error, fmt};

use crate::config::DevOwner;

/// Development-only seed for the fixed genesis authority. This is public test
/// material, never a production or operator secret.
pub const DEVNET_PAID_GENESIS_SEED: [u8; 32] = [0x47; 32];
/// Initial balance of each configured development owner's public fee-source
/// Coin.
pub const DEVNET_PAID_FEE_COIN_BALANCE: u64 = 10_000_000;
/// Initial balance of each configured development owner's public spend-source
/// Coin, distinct from [`DEVNET_PAID_FEE_COIN_BALANCE`].
pub const DEVNET_PAID_SPEND_COIN_BALANCE: u64 = 10_000_000;
/// DR-0136: every genesis validator has exactly one genesis bond record.
/// This is the sole FastVote validator's initial `BondCollateral` amount,
/// well above the devnet economics policy's own `min_bond`.
const DEVNET_GENESIS_BOND_AMOUNT: u64 = 1_000_000;
const GENESIS_CHECKPOINT: u64 = 1;
const APPLICATION_GAS_LIMIT: u64 = 500_000;

/// The two initial public `Coin<A>` objects seeded for one configured
/// development owner.
#[derive(Clone, Copy, Debug)]
pub struct PaidOwnerCoins {
    pub owner: DevOwner,
    pub fee_coin: ObjectId,
    pub spend_coin: ObjectId,
}

/// Bounded activation metadata a devnet boot needs to report and to serve
/// `mint`/`burn` without the public genesis signing key.
#[derive(Clone, Debug)]
pub struct PaidGenesisActivationMetadata {
    /// The first configured development owner, which owns the installed
    /// `TreasuryCap<A>` and is therefore the fixed local-devnet mint
    /// authority. The genesis authority itself owns no Coin or TreasuryCap.
    pub mint_authority: DevOwner,
    pub definition_id: ObjectId,
    pub treasury_cap_id: ObjectId,
    pub instance: InstanceTarget,
    pub code: UnverifiedDependencyRef,
    pub owner_coins: Vec<PaidOwnerCoins>,
}

/// Fully verified output used to compose the paid native HTTP route.
#[derive(Clone, Debug)]
pub struct PaidContractActivation {
    pub base_policy: LocalExecutionPolicy,
    pub fee_policy: PaidFeePolicy,
    pub metadata: PaidGenesisActivationMetadata,
    pub manifest_digest: Digest32,
    pub outcome: GenesisInstallOutcome,
}

/// Failures while constructing or installing the trusted devnet manifest.
#[derive(Debug)]
pub enum PaidContractGenesisError {
    Invalid(&'static str),
    Abi(abi::call_values::ValueError),
    Package(public_standard_asset::StandardAssetError),
    Publication(execution::publication::PublicationError),
    Local(execution::local_execution::LocalExecutionError),
    Paid(execution::paid_execution::PaidExecutionError),
    Hashing(hashing::HashingError),
    PackageType(abi::package_types::PackageTypeError),
    Crypto(crypto::CryptoError),
    Genesis(Box<GenesisError>),
}

impl fmt::Display for PaidContractGenesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid paid genesis: {message}"),
            Self::Abi(error) => error.fmt(formatter),
            Self::Package(error) => error.fmt(formatter),
            Self::Publication(error) => error.fmt(formatter),
            Self::Local(error) => error.fmt(formatter),
            Self::Paid(error) => error.fmt(formatter),
            Self::Hashing(error) => error.fmt(formatter),
            Self::PackageType(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
            Self::Genesis(error) => error.fmt(formatter),
        }
    }
}

impl Error for PaidContractGenesisError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PaidContractGenesisError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
from_error!(abi::call_values::ValueError, Abi);
from_error!(public_standard_asset::StandardAssetError, Package);
from_error!(execution::publication::PublicationError, Publication);
from_error!(execution::local_execution::LocalExecutionError, Local);
from_error!(execution::paid_execution::PaidExecutionError, Paid);
from_error!(hashing::HashingError, Hashing);
from_error!(abi::package_types::PackageTypeError, PackageType);
from_error!(crypto::CryptoError, Crypto);
impl From<GenesisError> for PaidContractGenesisError {
    fn from(value: GenesisError) -> Self {
        Self::Genesis(Box::new(value))
    }
}

fn genesis_key() -> SigningKey {
    SigningKey::from(DEVNET_PAID_GENESIS_SEED)
}

/// Fixed public genesis authority corresponding to
/// [`DEVNET_PAID_GENESIS_SEED`].
#[must_use]
pub fn paid_genesis_authority() -> [u8; 32] {
    VerificationKey::from(&genesis_key()).into()
}

fn derived_bytes(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    label: &[u8],
) -> Result<[u8; 32], PaidContractGenesisError> {
    Ok(resolver
        .hash_for_purpose(epoch, HashPurpose::ProtocolConfig, label)?
        .bytes())
}

fn derived_object_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    label: &[u8],
) -> Result<ObjectId, PaidContractGenesisError> {
    Ok(ObjectId::new(
        resolver
            .hash_for_purpose(epoch, HashPurpose::Object, label)?
            .bytes(),
    ))
}

fn derived_owner_coin_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    prefix: &[u8],
    owner_index: u64,
    owner: DevOwner,
) -> Result<ObjectId, PaidContractGenesisError> {
    let mut label: Vec<u8> = prefix.to_vec();
    label.extend_from_slice(&owner_index.to_le_bytes());
    label.extend_from_slice(owner.as_bytes());
    derived_object_id(resolver, epoch, &label)
}

fn authority(
    object_id: ObjectId,
    context: &PublicationContext,
    instance: &execution::call::InstanceTarget,
    code: &UnverifiedDependencyRef,
    ty: abi::package_types::ScopedTypeTag,
) -> ObjectAuthority {
    ObjectAuthority {
        object_id,
        instance_context: context.clone(),
        instance: instance.clone(),
        code: code.clone(),
        ty,
    }
}

/// Builds the exact signed manifest. This pure builder is separately testable;
/// only [`install_paid_contracts`] performs durable I/O.
pub fn build_paid_genesis_manifest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    dev_owners: &[DevOwner],
    fee_recipient: DevOwner,
) -> Result<(GenesisManifest, PaidGenesisActivationMetadata), PaidContractGenesisError> {
    if dev_owners.is_empty() {
        return Err(PaidContractGenesisError::Invalid("no development owners"));
    }
    let mint_authority: DevOwner = dev_owners[0];
    let genesis_authority: [u8; 32] = paid_genesis_authority();
    let origin_seed: [u8; 32] = derived_bytes(
        resolver,
        context.epoch(),
        b"sunrise.devnet.public-standard-asset.origin.v1",
    )?;
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), genesis_authority, origin_seed)?;
    let package: public_standard_asset::StandardAssetPackage = build_package(&origin)?;
    let semantics: Digest32 = generic_object_result_semantics(resolver, context)?;
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: public_standard_asset::REQUIRED_WASM_PROFILE,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: Vec::new(),
    })?;
    let artifact_digest: Digest32 = artifact_commitment(resolver, context, &artifact)?;
    let publication_request_id: [u8; 32] = derived_bytes(
        resolver,
        context.epoch(),
        b"sunrise.devnet.public-standard-asset.publication-request.v1",
    )?;
    let publication_frame: Vec<u8> = publication_submission_signing_frame(
        resolver,
        context,
        &artifact,
        0,
        publication_request_id,
    )?;
    let publication_signature: [u8; 64] = genesis_key().sign(&publication_frame).into();
    let publication: PublicationSubmission = PublicationSubmission::new(
        publication_request_id,
        PublicationRequest::new(artifact, 0, artifact_digest, publication_signature),
    )?;
    let code: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), artifact_digest)?;

    let instance_record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: genesis_authority,
        seed: derived_bytes(
            resolver,
            context.epoch(),
            b"sunrise.devnet.public-standard-asset.instance.v1",
        )?,
        code: code.clone(),
        revision: 1,
        initializer: public_standard_asset::INITIALIZER.to_owned(),
    };
    let instance: execution::call::InstanceTarget = instance_target(resolver, &instance_record)?;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let base_policy_digest: Digest32 = base_policy.digest(resolver)?;
    let init_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Instantiate,
        policy_digest: base_policy_digest,
        call: CallIntent {
            context: context.clone(),
            request_id: derived_bytes(
                resolver,
                context.epoch(),
                b"sunrise.devnet.public-standard-asset.initialization-request.v1",
            )?,
            sender: genesis_authority,
            nonce: 0,
            code: code.clone(),
            instance: instance.clone(),
            entrypoint: public_standard_asset::INITIALIZER.to_owned(),
            type_arguments: Vec::new(),
            access: AccessManifest::new(),
            arguments: no_arguments()?,
            gas_limit: APPLICATION_GAS_LIMIT,
        },
        authorizations: Vec::new(),
    };
    let init_frame: Vec<u8> = local_execution_signing_frame(context, &init_intent)?;
    let init_signature: [u8; 64] = genesis_key().sign(&init_frame).into();
    let initialization: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent: init_intent,
        signature: init_signature,
    };

    let definition_id: ObjectId = derived_object_id(
        resolver,
        context.epoch(),
        b"sunrise.devnet.public-standard-asset.definition.v1",
    )?;
    let treasury_cap_id: ObjectId = derived_object_id(
        resolver,
        context.epoch(),
        b"sunrise.devnet.public-standard-asset.treasury-cap.v1",
    )?;
    let definition_tag = definition_type_tag(&origin)?;
    let treasury_tag = treasury_cap_type_tag(&origin, &definition_id)?;
    let coin_tag = coin_type_tag(&origin, &definition_id)?;
    let (resource_domain, resource): (u16, [u8; 32]) = match coin_tag.args() {
        [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => {
            return Err(PaidContractGenesisError::Invalid(
                "devnet coin type must carry one opaque resource",
            ));
        }
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource)
        .map_err(|_| PaidContractGenesisError::Invalid("invalid devnet bond resource"))?;
    let owner_count: u64 = u64::try_from(dev_owners.len())
        .map_err(|_| PaidContractGenesisError::Invalid("development owner count overflow"))?;
    let per_owner_balance: u64 = DEVNET_PAID_FEE_COIN_BALANCE
        .checked_add(DEVNET_PAID_SPEND_COIN_BALANCE)
        .ok_or(PaidContractGenesisError::Invalid(
            "per-owner initial balance overflow",
        ))?;
    let total_supply: u64 = per_owner_balance
        .checked_mul(owner_count)
        .and_then(|supply| supply.checked_add(DEVNET_GENESIS_BOND_AMOUNT))
        .ok_or(PaidContractGenesisError::Invalid("initial supply overflow"))?;
    let mut objects: Vec<GenesisObjectEntry> = Vec::with_capacity(dev_owners.len() * 2 + 2);
    let definition: Object = Object {
        id: definition_id,
        version: 1,
        owner: Owner::Address(Address::new(genesis_authority)),
        type_hash: derive_scoped_type_id(resolver, context.epoch(), &definition_tag)?,
        schema_version: SCHEMA_VERSION,
        data: encode_call_value(&definition_body_layout(), &CallValue::Tuple(Vec::new()))?,
    };
    objects.push(GenesisObjectEntry {
        authority: authority(definition.id, context, &instance, &code, definition_tag),
        object: definition,
    });
    // The mint authority, never the genesis authority, owns the TreasuryCap:
    // the genesis authority must own no Coin or TreasuryCap.
    let treasury: Object = Object {
        id: treasury_cap_id,
        version: 1,
        owner: Owner::Address(Address::new(*mint_authority.as_bytes())),
        type_hash: derive_scoped_type_id(resolver, context.epoch(), &treasury_tag)?,
        schema_version: SCHEMA_VERSION,
        data: encode_call_value(&treasury_cap_body_layout(), &CallValue::U64(total_supply))?,
    };
    objects.push(GenesisObjectEntry {
        authority: authority(treasury.id, context, &instance, &code, treasury_tag),
        object: treasury.clone(),
    });

    let mut owner_coins: Vec<PaidOwnerCoins> = Vec::with_capacity(dev_owners.len());
    for (index, owner) in dev_owners.iter().copied().enumerate() {
        let owner_index: u64 = u64::try_from(index)
            .map_err(|_| PaidContractGenesisError::Invalid("owner index overflow"))?;
        let fee_coin_id: ObjectId = derived_owner_coin_id(
            resolver,
            context.epoch(),
            b"sunrise.devnet.public-standard-asset.fee-coin.v1/",
            owner_index,
            owner,
        )?;
        let spend_coin_id: ObjectId = derived_owner_coin_id(
            resolver,
            context.epoch(),
            b"sunrise.devnet.public-standard-asset.spend-coin.v1/",
            owner_index,
            owner,
        )?;
        for (coin_id, balance) in [
            (fee_coin_id, DEVNET_PAID_FEE_COIN_BALANCE),
            (spend_coin_id, DEVNET_PAID_SPEND_COIN_BALANCE),
        ] {
            let coin: Object = Object {
                id: coin_id,
                version: 1,
                owner: Owner::Address(Address::new(*owner.as_bytes())),
                type_hash: derive_scoped_type_id(resolver, context.epoch(), &coin_tag)?,
                schema_version: SCHEMA_VERSION,
                data: encode_call_value(&coin_body_layout(), &CallValue::U64(balance))?,
            };
            objects.push(GenesisObjectEntry {
                authority: authority(coin.id, context, &instance, &code, coin_tag.clone()),
                object: coin,
            });
        }
        owner_coins.push(PaidOwnerCoins {
            owner,
            fee_coin: fee_coin_id,
            spend_coin: spend_coin_id,
        });
    }

    // DR-0136: every genesis validator has exactly one genesis bond record.
    // The sole FastVote validator (the genesis authority) is bonded here,
    // in the same custody scope/resource the economics policy below pins.
    let bond_object_id: ObjectId = derived_object_id(
        resolver,
        context.epoch(),
        b"sunrise.devnet.public-standard-asset.genesis-bond.v1",
    )?;
    let bond_scope: ProtocolCustodyScope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: context.chain_id().clone(),
        subject: genesis_authority,
        resource,
    };
    let bond_object: Object = Object {
        id: bond_object_id,
        version: 1,
        owner: Owner::ProtocolCustody(bond_scope),
        type_hash: derive_scoped_type_id(resolver, context.epoch(), &coin_tag)?,
        schema_version: SCHEMA_VERSION,
        data: encode_call_value(
            &coin_body_layout(),
            &CallValue::U64(DEVNET_GENESIS_BOND_AMOUNT),
        )?,
    };
    objects.push(GenesisObjectEntry {
        authority: authority(bond_object.id, context, &instance, &code, coin_tag.clone()),
        object: bond_object,
    });

    // Fail-closed supply consistency: the generic installer intentionally
    // knows nothing about asset supply, so this builder alone asserts the
    // exact seeded Coin total (including the genesis bond, minted here
    // exactly like every other Coin-shaped object) matches the TreasuryCap
    // body it just encoded.
    let mut seeded_supply: u64 = 0;
    for entry in &objects[2..] {
        let amount: u64 = coin_amount(&entry.object.data)?;
        seeded_supply = seeded_supply
            .checked_add(amount)
            .ok_or(PaidContractGenesisError::Invalid("seeded supply overflow"))?;
    }
    let committed_supply: u64 = treasury_supply(&treasury.data)?;
    if seeded_supply != total_supply || committed_supply != total_supply {
        return Err(PaidContractGenesisError::Invalid(
            "seeded coin supply is inconsistent with the TreasuryCap total supply",
        ));
    }
    let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: context.clone(),
        resources: vec![FastPathEconomicsResourcePolicy {
            resource_id,
            context: context.clone(),
            instance: instance.clone(),
            code: code.clone(),
            ty: coin_tag.clone(),
            schema: SCHEMA_VERSION,
            split_entrypoint: "split".to_owned(),
            transfer_entrypoint: "transfer".to_owned(),
            bond: Some(BondResourceConfig {
                resource_id,
                min_bond: Amount::new(1),
                enabled: true,
                unbonding_epochs: 7,
                max_validator_exposure: None,
            }),
            fee_escrow: true,
        }],
    };

    let metadata: PaidGenesisActivationMetadata = PaidGenesisActivationMetadata {
        mint_authority,
        definition_id,
        treasury_cap_id,
        instance: instance.clone(),
        code: code.clone(),
        owner_coins,
    };
    let fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: context.clone(),
        base_policy_digest,
        instance: instance.clone(),
        code: code.clone(),
        reserve_entrypoint: "reserve".to_owned(),
        reserve_all_entrypoint: "reserve_all".to_owned(),
        settle_entrypoint: "settle".to_owned(),
        type_arguments: vec![asset_type_argument(&definition_id)],
        asset_type: coin_tag,
        reservation_type: reservation_type_tag(&origin, &definition_id)?,
        schema: SCHEMA_VERSION,
        fee_recipient: *fee_recipient.as_bytes(),
        gas_schedule: GasSchedule {
            base_fee: 10,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: MIN_RESERVE_ALLOWANCE,
        settle_allowance: MIN_SETTLE_ALLOWANCE,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    };
    let mut manifest: GenesisManifest = GenesisManifest {
        genesis_authority,
        publication,
        initialization,
        fee_policy,
        economics_policy,
        objects,
        validator_set: FastPathValidatorSetRecord {
            context: context.clone(),
            validators: vec![FastPathValidatorEntry {
                id: ValidatorId::new(genesis_authority),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: genesis_authority.to_vec(),
            }],
        },
        signature: [0; 64],
    };
    manifest.signature = genesis_key()
        .sign(&genesis_manifest_signing_frame(&manifest)?)
        .into();
    Ok((manifest, metadata))
}

/// Builds and atomically installs, or verify-only checks, the paid genesis.
#[allow(clippy::too_many_arguments)]
pub fn install_paid_contracts<S: StructuredDurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    dev_owners: &[DevOwner],
    fee_recipient: DevOwner,
) -> Result<PaidContractActivation, PaidContractGenesisError> {
    let (manifest, metadata): (GenesisManifest, PaidGenesisActivationMetadata) =
        build_paid_genesis_manifest(resolver, context, dev_owners, fee_recipient)?;
    let manifest_digest: Digest32 = genesis_manifest_commitment(resolver, &manifest)?;
    let outcome: GenesisInstallOutcome = install_genesis(
        store,
        operation,
        domain,
        resolver,
        &manifest,
        GENESIS_CHECKPOINT,
    )?;
    Ok(PaidContractActivation {
        base_policy: LocalExecutionPolicy::generic_object_results(context.clone()),
        fee_policy: manifest.fee_policy,
        metadata,
        manifest_digest,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{DEVNET_DOMAIN_BYTES, build_devnet_protocol_context};
    use protocol_types::{ChainId, Epoch};
    use runtime::{
        MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
    };

    fn owner(seed: u8) -> DevOwner {
        let key: SigningKey = SigningKey::from([seed; 32]);
        DevOwner::new(VerificationKey::from(&key).into())
    }

    fn operation() -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(1).unwrap(),
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([0x51; 16]).unwrap(),
        )
    }

    #[test]
    fn manifest_is_supply_consistent_and_installs_once_then_verifies() {
        let protocol = build_devnet_protocol_context(
            ChainId::new("paid-genesis-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.protocol_config().protocol_version,
            protocol.epoch(),
        )
        .unwrap();
        let owners: Vec<DevOwner> = vec![owner(1), owner(2)];
        let (manifest, metadata) =
            build_paid_genesis_manifest(protocol.resolver(), &context, &owners, owner(3)).unwrap();
        assert_eq!(metadata.owner_coins.len(), owners.len());
        assert_eq!(metadata.mint_authority, owners[0]);
        let expected_total_supply: u64 =
            (DEVNET_PAID_FEE_COIN_BALANCE + DEVNET_PAID_SPEND_COIN_BALANCE) * 2
                + DEVNET_GENESIS_BOND_AMOUNT;
        assert_eq!(
            public_standard_asset::treasury_supply(&manifest.objects[1].object.data).unwrap(),
            expected_total_supply
        );
        assert_eq!(
            manifest.objects[1].object.owner,
            Owner::Address(Address::new(*owners[0].as_bytes()))
        );
        let coin_total: u64 = manifest.objects[2..]
            .iter()
            .map(|entry| public_standard_asset::coin_amount(&entry.object.data).unwrap())
            .sum();
        assert_eq!(coin_total, expected_total_supply);
        for owner_coins in &metadata.owner_coins {
            assert_ne!(owner_coins.fee_coin, owner_coins.spend_coin);
        }
        let genesis_owner: Owner = Owner::Address(Address::new(paid_genesis_authority()));
        for entry in &manifest.objects[1..] {
            assert_ne!(
                entry.object.owner, genesis_owner,
                "genesis authority must own no Coin or TreasuryCap"
            );
        }

        let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap();
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let first = install_paid_contracts(
            &store,
            &operation(),
            domain,
            protocol.resolver(),
            &context,
            &owners,
            owner(3),
        )
        .unwrap();
        assert!(matches!(
            first.outcome,
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        let second = install_paid_contracts(
            &store,
            &operation(),
            domain,
            protocol.resolver(),
            &context,
            &owners,
            owner(3),
        )
        .unwrap();
        assert!(matches!(
            second.outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
        assert_eq!(first.manifest_digest, second.manifest_digest);
        assert!(matches!(
            install_paid_contracts(
                &store,
                &operation(),
                domain,
                protocol.resolver(),
                &context,
                &[owners[0]],
                owner(3),
            ),
            Err(PaidContractGenesisError::Genesis(error))
                if matches!(*error, GenesisError::ManifestCommitmentMismatch)
        ));
    }
}
