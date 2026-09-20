//! Closed, signed public paid-contract genesis for the local developer network.
//!
//! This module alone knows that the genesis package is Standard Asset. Node
//! core receives only bounded canonical manifest entries and never decodes an
//! amount or supply field.

use abi::{
    AccessManifest,
    call_values::{CallValue, encode_call_value},
    package_types::{PackageOrigin, derive_scoped_type_id},
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::{
    call::CallIntent,
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
use fees::GasSchedule;
use hashing::HashSuiteResolver;
use node_core::genesis::{
    GenesisError, GenesisInstallOutcome, GenesisManifest, GenesisObjectEntry,
    genesis_manifest_commitment, genesis_manifest_signing_frame, install_genesis,
};
use objects::{Address, Object, ObjectId, Owner};
use protocol_types::{Digest32, Epoch, HashPurpose};
use public_standard_asset::{
    SCHEMA_VERSION, asset_type_argument, build_package, coin_body_layout, coin_type_tag,
    definition_body_layout, definition_type_tag, no_arguments, reservation_type_tag,
    treasury_cap_body_layout, treasury_cap_type_tag,
};
use runtime::{AtomicityDomainId, DurableOperationContext, StructuredDurableDomainStateStore};
use std::{error::Error, fmt};

use crate::config::DevOwner;

/// Development-only seed for the fixed genesis authority. This is public test
/// material, never a production or operator secret.
pub const DEVNET_PAID_GENESIS_SEED: [u8; 32] = [0x47; 32];
/// Initial fee balance in each configured development owner's public Coin.
pub const DEVNET_PAID_FEE_COIN_BALANCE: u64 = 10_000_000;
const GENESIS_CHECKPOINT: u64 = 1;
const APPLICATION_GAS_LIMIT: u64 = 500_000;

/// Fully verified output used to compose the paid native HTTP route.
#[derive(Clone, Debug)]
pub struct PaidContractActivation {
    pub base_policy: LocalExecutionPolicy,
    pub fee_policy: PaidFeePolicy,
    pub fee_coins: Vec<(DevOwner, ObjectId)>,
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
) -> Result<(GenesisManifest, Vec<(DevOwner, ObjectId)>), PaidContractGenesisError> {
    if dev_owners.is_empty() {
        return Err(PaidContractGenesisError::Invalid("no development owners"));
    }
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
    let total_supply: u64 =
        DEVNET_PAID_FEE_COIN_BALANCE
            .checked_mul(u64::try_from(dev_owners.len()).map_err(|_| {
                PaidContractGenesisError::Invalid("development owner count overflow")
            })?)
            .ok_or(PaidContractGenesisError::Invalid("initial supply overflow"))?;
    let mut objects: Vec<GenesisObjectEntry> = Vec::with_capacity(dev_owners.len() + 2);
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
    let treasury: Object = Object {
        id: treasury_cap_id,
        version: 1,
        owner: Owner::Address(Address::new(genesis_authority)),
        type_hash: derive_scoped_type_id(resolver, context.epoch(), &treasury_tag)?,
        schema_version: SCHEMA_VERSION,
        data: encode_call_value(&treasury_cap_body_layout(), &CallValue::U64(total_supply))?,
    };
    objects.push(GenesisObjectEntry {
        authority: authority(treasury.id, context, &instance, &code, treasury_tag),
        object: treasury,
    });

    let mut fee_coins: Vec<(DevOwner, ObjectId)> = Vec::with_capacity(dev_owners.len());
    for (index, owner) in dev_owners.iter().copied().enumerate() {
        let mut label: Vec<u8> = b"sunrise.devnet.public-standard-asset.fee-coin.v1/".to_vec();
        label.extend_from_slice(
            &u64::try_from(index)
                .map_err(|_| PaidContractGenesisError::Invalid("owner index overflow"))?
                .to_le_bytes(),
        );
        label.extend_from_slice(owner.as_bytes());
        let coin_id: ObjectId = derived_object_id(resolver, context.epoch(), &label)?;
        let coin: Object = Object {
            id: coin_id,
            version: 1,
            owner: Owner::Address(Address::new(*owner.as_bytes())),
            type_hash: derive_scoped_type_id(resolver, context.epoch(), &coin_tag)?,
            schema_version: SCHEMA_VERSION,
            data: encode_call_value(
                &coin_body_layout(),
                &CallValue::U64(DEVNET_PAID_FEE_COIN_BALANCE),
            )?,
        };
        objects.push(GenesisObjectEntry {
            authority: authority(coin.id, context, &instance, &code, coin_tag.clone()),
            object: coin,
        });
        fee_coins.push((owner, coin_id));
    }

    let fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: context.clone(),
        base_policy_digest,
        instance,
        code,
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
        objects,
        signature: [0; 64],
    };
    manifest.signature = genesis_key()
        .sign(&genesis_manifest_signing_frame(&manifest)?)
        .into();
    Ok((manifest, fee_coins))
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
    let (manifest, fee_coins): (GenesisManifest, Vec<(DevOwner, ObjectId)>) =
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
        fee_coins,
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
        let (manifest, fee_coins) =
            build_paid_genesis_manifest(protocol.resolver(), &context, &owners, owner(3)).unwrap();
        assert_eq!(fee_coins.len(), owners.len());
        assert_eq!(
            public_standard_asset::treasury_supply(&manifest.objects[1].object.data).unwrap(),
            DEVNET_PAID_FEE_COIN_BALANCE * 2
        );
        let coin_total: u64 = manifest.objects[2..]
            .iter()
            .map(|entry| public_standard_asset::coin_amount(&entry.object.data).unwrap())
            .sum();
        assert_eq!(coin_total, DEVNET_PAID_FEE_COIN_BALANCE * 2);

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
