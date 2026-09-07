//! Trusted preinstalled Standard Asset v1 whole-coin transfer module
//! composition for the local devnet.

use crate::{
    genesis::DevnetProtocolContext,
    standard_asset::{
        BURN_ENTRYPOINT, MERGE_ENTRYPOINT, MINT_ENTRYPOINT, MODULE_NAME, SPLIT_ENTRYPOINT,
        STANDARD_ASSET_MODULE_ID_BYTES, TRANSFER_ENTRYPOINT,
    },
};
use abi::{AbiError, ConstructorDeclaration, EntrypointSignature, ParamDeclaration};
use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use hashing::{HashSuiteResolver, HashingError};
use node_core::{
    NodeCoreError, PreinstalledModuleCatalog, PreinstalledModuleCatalogEntry,
    PreinstalledModuleSemanticsEnvelope, PreinstalledObjectCreationPolicy,
    PreinstalledOwnerTransitionPolicy, PreinstalledTypedEntrypointPolicy,
    encode_preinstalled_semantics_envelope, reconcile_preinstalled_registry_and_catalog,
};
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_config::{ProtocolConfig, ProtocolConfigError};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion};
use standard_assets::{
    AssetId, STANDARD_ASSET_COIN_V1_CONSTRUCTOR, STANDARD_ASSET_MINT_ARGS_V1_TYPE_ID,
    STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR, STANDARD_ASSET_SCHEMA_VERSION_V1,
    STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID,
    STANDARD_ASSET_TREASURY_CAP_V1_CONSTRUCTOR, coin_constructor_declaration,
    mint_capability_constructor_declaration, treasury_cap_constructor_declaration,
};
use std::{error::Error, fmt};
use system_modules::{
    GasModel, ModuleId, ModuleStatus, SystemModule, SystemModuleError, SystemModuleManifest,
    TypeSchema, encode_system_module_manifest,
};

/// Stable dev-profile module ID (see
/// [`crate::standard_asset::STANDARD_ASSET_MODULE_ID_BYTES`]).
pub const STANDARD_ASSET_MODULE_ID: ModuleId = ModuleId::new(STANDARD_ASSET_MODULE_ID_BYTES);

/// Discarded development-only transfer fixture, isolated from the canonical
/// Standard Asset version line. SHA-256 of
/// `sunrise.devnet.legacy.standard_asset.transfer.v1`.
const LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID: ModuleId = ModuleId::new([
    0x73, 0xD3, 0x01, 0xDE, 0x2E, 0x5B, 0xC8, 0x52, 0xC4, 0x15, 0x82, 0x81, 0x6D, 0x5C, 0x6C, 0xC0,
    0xEA, 0xB5, 0x24, 0x26, 0xE9, 0x44, 0x43, 0xCC, 0x1A, 0x52, 0x1B, 0xEF, 0x46, 0x9F, 0x72, 0xE3,
]);
/// Discarded development-only split/merge fixture. SHA-256 of
/// `sunrise.devnet.legacy.standard_asset.split_merge.v1`.
const LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID: ModuleId = ModuleId::new([
    0xB3, 0x55, 0x57, 0xD3, 0xFB, 0xED, 0x25, 0x31, 0xDA, 0x09, 0x67, 0xD4, 0xF3, 0x87, 0xB6, 0xA2,
    0x8B, 0xC6, 0x39, 0x26, 0xAE, 0xCB, 0xA9, 0xEB, 0xD4, 0x09, 0xC2, 0x19, 0x3B, 0x2C, 0xD0, 0xE1,
]);
/// Discarded development-only unbounded-mint fixture. SHA-256 of
/// `sunrise.devnet.legacy.standard_asset.unbounded_mint.v1`.
const LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID: ModuleId = ModuleId::new([
    0xC2, 0xC7, 0x29, 0xD5, 0x9A, 0xBB, 0xD5, 0x50, 0xA9, 0xAE, 0xA5, 0xEA, 0xD6, 0xCB, 0x01, 0xC4,
    0x3E, 0x5A, 0x46, 0x49, 0xEE, 0xBE, 0x77, 0x73, 0x8C, 0x7B, 0x11, 0x7B, 0x65, 0xF0, 0xFF, 0x8E,
]);
const LEGACY_STANDARD_ASSET_TRANSFER_MODULE_NAME: &str =
    "sunrise.devnet.legacy.standard_asset.transfer.v1";
const LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_NAME: &str =
    "sunrise.devnet.legacy.standard_asset.split_merge.v1";
const LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_NAME: &str =
    "sunrise.devnet.legacy.standard_asset.unbounded_mint.v1";

/// Version of the isolated whole-coin transfer development fixture.
pub const STANDARD_ASSET_HISTORICAL_MODULE_VERSION: u64 = 1;

/// Version of the isolated transfer/split/merge development fixture.
pub const STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION: u64 = 1;

/// Version of the isolated capability-authorized mint development fixture.
pub const STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION: u64 = 1;

/// Initial active canonical Standard Asset module version.
pub const STANDARD_ASSET_MODULE_VERSION: u64 = 1;

/// Exact encoded length of one `standard_assets::StandardAssetTransferArgsV1`
/// frame: a 10-byte canonical frame header plus one 6-byte field header and a
/// 32-byte `Address` payload.
pub const STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE: u64 =
    crate::standard_asset::STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE as u64;
/// Maximum canonical argument-frame size accepted by the active module.
pub const STANDARD_ASSET_MODULE_MAX_INPUT_SIZE: u64 =
    if crate::standard_asset::STANDARD_ASSET_SPLIT_MAX_INPUT_SIZE
        > crate::standard_asset::STANDARD_ASSET_MINT_MAX_INPUT_SIZE
    {
        crate::standard_asset::STANDARD_ASSET_SPLIT_MAX_INPUT_SIZE as u64
    } else {
        crate::standard_asset::STANDARD_ASSET_MINT_MAX_INPUT_SIZE as u64
    };

const STANDARD_ASSET_SCHEMA_DECLARATION_TYPE_ID: u16 = 0xF020;
const STANDARD_ASSET_SEMANTICS_DECLARATION_TYPE_ID: u16 = 0xF021;
const STANDARD_ASSET_SCHEMA_DECLARATION_ENCODING_VERSION: u16 = 1;
const STANDARD_ASSET_SEMANTICS_ENCODING_VERSION: u16 = 1;
/// Recipient-args canonical encoding version
/// (`standard_assets::StandardAssetTransferArgsV1`'s own encoding version).
const RECIPIENT_ARGS_ENCODING_VERSION: u16 = 1;
/// Recipient-args canonical field id (the sole field,
/// `StandardAssetTransferArgsV1::recipient`).
const TRANSFER_RECIPIENT_ARGS_FIELD_ID: u16 = 1;
const SPLIT_RECIPIENT_ARGS_FIELD_ID: u16 = 2;
const MINT_RECIPIENT_ARGS_FIELD_ID: u16 = 2;

const STANDARD_ASSET_V1_ACCESS_SEMANTICS: &str = "exactly two ordered Write Coin<A> objects, both typed-ABI verified to share one asset-identity type argument: the transferred coin at index 0 and a distinct fee-payer coin at index 1; a required trusted-composition fee-treasury Write access, when the committed fee schedule requires a charge, is appended by node-core strictly after these two indices and is never included in this module's execution inputs; the transferred coin's owner transitions to the signed recipient via a committed owner-transition policy, never via this module";
const STANDARD_ASSET_V1_VALIDATION_FACTS: &str = concat!(
    "this module's WASM performs no state transition: it asserts exactly two ",
    "engine-visible objects and the exact StandardAssetTransferArgsV1 frame ",
    "length, then returns with no object or event effects; the transferred ",
    "coin's owner-only mutation is synthesized and independently re-verified ",
    "by node-core's committed owner-transition policy, and the fee debit/",
    "credit is composed entirely by trusted node fee composition, never by ",
    "this module"
);
const STANDARD_ASSET_V1_TYPE_VARIABLE_LIMITATION: &str = concat!(
    "abi carries at most one shared type variable per entrypoint signature, ",
    "so unifying both Write params as Coin<A> forces the fee asset to equal ",
    "the transferred asset for this entrypoint; a distinct fee-in-a-different-",
    "asset shape is not expressible here and remains a deliberate limitation, ",
    "not an oversight"
);
const STANDARD_ASSET_V1_TREASURY_VISIBILITY_FACTS: &str = concat!(
    "the fee-treasury object, when accessed, is excluded from this module's ",
    "execution inputs by node-core before this entrypoint runs: this module ",
    "cannot read, observe, or authorize the treasury access, and ",
    "get_object_count reflects only the two ordinary transfer/fee Coin<A> ",
    "accesses above; the treasury is never reached by abi::verify_entrypoint_inputs ",
    "either, so its nominal Coin<A> type is instead verified once, at boot, by ",
    "seeding (standard_assets::derive_coin_type_id / abi::verify_type_id), never by raw Digest32 equality"
);
const STANDARD_ASSET_V1_TRANSFER_INPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.transfer.input.v1";
const STANDARD_ASSET_V1_TRANSFER_OUTPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.transfer.output.v1";
const STANDARD_ASSET_V1_TRANSFER_INPUT_SCHEMA: &str =
    "CanonicalStruct(0x7104,v1){1: 32-byte recipient Address}";
const STANDARD_ASSET_V1_TRANSFER_OUTPUT_SCHEMA: &str = concat!(
    "one synthesized owner-only Update effect over the index-0 Coin<A> using ",
    "CanonicalStruct(0x7102,v1), unchanged data/type_hash/schema_version, ",
    "version+1, owner set to the signed recipient; no event is emitted"
);

const STANDARD_ASSET_V2_ACCESS_SEMANTICS: &str = "transfer and split use exactly two ordered Write Coin<A> inputs: source index 0 and a distinct fee-payer index 1; merge uses primary Write index 0, secondary Consume index 1, and distinct fee-payer Write index 2. Every signature unifies one Coin<A> asset identity. The trusted fee-treasury Write is final and hidden from WASM. Transfer owner transition is node-core synthesized; split creates exactly one recipient-owned same-typed coin under a committed creation policy; merge creates none.";
const STANDARD_ASSET_V2_VALIDATION_FACTS: &str = concat!(
    "transfer remains validation-only and its owner-only update is synthesized ",
    "by node-core. split and merge perform all checked StandardAssetCoinV1 ",
    "u64 arithmetic in committed WASM: split writes a nonzero source remainder ",
    "and creates one recipient coin; merge checked-adds primary and secondary ",
    "then consumes secondary. The fee debit/credit is trusted node composition, ",
    "never this module"
);
const STANDARD_ASSET_V2_TYPE_VARIABLE_LIMITATION: &str = concat!(
    "abi carries at most one shared type variable per entrypoint signature, ",
    "so unifying both Write params as Coin<A> forces the fee asset to equal ",
    "the transferred asset for this entrypoint; a distinct fee-in-a-different-",
    "asset shape is not expressible here and remains a deliberate limitation, ",
    "not an oversight"
);
const STANDARD_ASSET_V2_TREASURY_VISIBILITY_FACTS: &str = concat!(
    "the fee-treasury object, when accessed, is excluded from this module's ",
    "execution inputs by node-core before this entrypoint runs: this module ",
    "cannot read, observe, or authorize the treasury access, and ",
    "get_object_count reflects only the two ordinary transfer/fee Coin<A> ",
    "accesses above; the treasury is never reached by abi::verify_entrypoint_inputs ",
    "either, so its nominal Coin<A> type is instead verified once, at boot, by ",
    "seeding (standard_assets::derive_coin_type_id / abi::verify_type_id), never by raw Digest32 equality"
);
const STANDARD_ASSET_V2_TRANSFER_INPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.transfer.input.v1";
const STANDARD_ASSET_V2_TRANSFER_OUTPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.transfer.output.v1";
const STANDARD_ASSET_V2_TRANSFER_INPUT_SCHEMA: &str =
    "CanonicalStruct(0x7104,v1){1: 32-byte recipient Address}";
const STANDARD_ASSET_V2_TRANSFER_OUTPUT_SCHEMA: &str = concat!(
    "transfer: one synthesized owner-only Update; split: source Update plus ",
    "one deterministic recipient-owned Create; merge: primary Update plus ",
    "secondary Consume. All coin bodies use CanonicalStruct(0x7102,v1); no ",
    "event is emitted"
);

const STANDARD_ASSET_V3_ACCESS_SEMANTICS: &str = "transfer and split use exactly two ordered Write Coin<A> inputs; merge uses primary Write Coin<A>, secondary Consume Coin<A>, and fee Write Coin<A>; mint uses Read MintCapability<A> index 0 and fee Write Coin<A> index 1. Each signature unifies exactly one asset identity A. The trusted fee-treasury Write is final and hidden from WASM. Transfer owner transition is node-core synthesized; split and mint each create exactly one recipient-owned Coin<A> under separate committed creation policies; merge creates none.";
const STANDARD_ASSET_V3_VALIDATION_FACTS: &str = concat!(
    "transfer remains validation-only and its owner-only update is synthesized ",
    "by node-core. split, merge, and mint perform all checked Standard Asset ",
    "coin-body construction and u64 arithmetic in committed WASM. mint copies ",
    "the AssetId from the verified capability and the Coin<A> nominal type from ",
    "the verified fee coin; node-core never decodes balances or asset bodies"
);
const STANDARD_ASSET_V3_TYPE_VARIABLE_LIMITATION: &str = concat!(
    "abi carries at most one shared type variable per entrypoint signature, ",
    "so mint's MintCapability<A> and fee Coin<A> must name the same asset; a ",
    "distinct fee asset remains deliberately inexpressible in this module"
);
const STANDARD_ASSET_V3_TREASURY_VISIBILITY_FACTS: &str = concat!(
    "the fee-treasury object is excluded from module execution inputs and typed ",
    "entrypoint verification; boot seeding verifies its nominal Coin<A> type. ",
    "mint cannot observe or authorize treasury access"
);
const STANDARD_ASSET_V3_TRANSFER_INPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.operations.input.v3";
const STANDARD_ASSET_V3_TRANSFER_OUTPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.operations.output.v3";
const STANDARD_ASSET_V3_TRANSFER_INPUT_SCHEMA: &str = "entrypoint-specific canonical args: TransferArgsV1(0x7104), SplitArgsV1(0x7105), MintArgsV1(0x7106), or empty merge args";
const STANDARD_ASSET_V3_TRANSFER_OUTPUT_SCHEMA: &str = concat!(
    "transfer: one synthesized owner-only Update; split: source Update plus one ",
    "recipient Coin<A> Create; merge: primary Update plus secondary Consume; ",
    "mint: exactly one recipient Coin<A> Create. Coin bodies use CanonicalStruct",
    "(0x7102,v1); no event is emitted"
);

const STANDARD_ASSET_ACCESS_SEMANTICS: &str = "transfer and split use exactly two ordered Write Coin<A> inputs; merge uses primary Write Coin<A>, secondary Consume Coin<A>, and fee Write Coin<A>; mint uses Write TreasuryCap<A> index 0 and fee Write Coin<A> index 1; burn uses Write TreasuryCap<A> index 0, Consume Coin<A> index 1, and fee Write Coin<A> index 2. Each signature unifies exactly one asset identity A. The trusted fee-treasury Write is final and hidden from WASM. Transfer owner transition is node-core synthesized; split and mint each create exactly one recipient-owned Coin<A> under separate committed creation policies; merge and burn create none.";
const STANDARD_ASSET_VALIDATION_FACTS: &str = concat!(
    "transfer remains validation-only and its owner-only update is synthesized ",
    "by node-core. split, merge, mint, and burn perform all checked Standard ",
    "Asset coin-body construction and u64 arithmetic in committed WASM. mint ",
    "checked-adds the requested amount into the TreasuryCap<A>'s total_supply, ",
    "rejects any amount that would exceed max_supply, and atomically mutates ",
    "the cap alongside the one created Coin<A>, whose nominal type is copied ",
    "from the verified fee coin; burn checked-subtracts a whole consumed ",
    "coin's amount from the same cap and atomically mutates it alongside the ",
    "coin's Consume; node-core never decodes balances, supply, or asset bodies"
);
const STANDARD_ASSET_TYPE_VARIABLE_LIMITATION: &str = concat!(
    "abi carries at most one shared type variable per entrypoint signature, so ",
    "mint's TreasuryCap<A> and fee Coin<A>, and burn's TreasuryCap<A>, consumed ",
    "Coin<A>, and fee Coin<A>, must all name the same asset; a distinct fee ",
    "asset remains deliberately inexpressible in this module"
);
const STANDARD_ASSET_TREASURY_VISIBILITY_FACTS: &str = concat!(
    "the fee-treasury object is excluded from module execution inputs and typed ",
    "entrypoint verification; boot seeding verifies its nominal Coin<A> type and ",
    "the seeded TreasuryCap<A>'s nominal type. mint and burn cannot observe or ",
    "authorize treasury access"
);
const STANDARD_ASSET_TRANSFER_INPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.operations.input.v4";
const STANDARD_ASSET_TRANSFER_OUTPUT_DESCRIPTOR: &str =
    "sunrise.devnet.standard_asset.operations.output.v4";
const STANDARD_ASSET_TRANSFER_INPUT_SCHEMA: &str = "entrypoint-specific canonical args: TransferArgsV1(0x7104), SplitArgsV1(0x7105), MintArgsV1(0x7106), or empty merge/burn args";
const STANDARD_ASSET_TRANSFER_OUTPUT_SCHEMA: &str = concat!(
    "transfer: one synthesized owner-only Update; split: source Update plus one ",
    "recipient Coin<A> Create; merge: primary Update plus secondary Consume; ",
    "mint: TreasuryCap<A> Update plus one recipient Coin<A> Create; burn: ",
    "TreasuryCap<A> Update plus consumed Coin<A> Consume. Coin bodies use ",
    "CanonicalStruct(0x7102,v1); cap bodies use CanonicalStruct(0x7107,v1); no ",
    "event is emitted"
);

/// A fully reconciled preinstalled Standard Asset v1 module and the updated
/// protocol configuration that commits its active registry entry.
#[derive(Clone, Debug)]
pub struct DevnetAssetModule {
    chain_id: ChainId,
    epoch: Epoch,
    domain: AtomicityDomainId,
    protocol_config: ProtocolConfig,
    resolver: HashSuiteResolver,
    catalog: PreinstalledModuleCatalog,
    module_ref: ObjectRef,
    semantics_hash: Digest32,
    asset_id: AssetId,
}

impl DevnetAssetModule {
    /// Returns the chain identifier bound into module commitments.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the epoch at which startup reconciliation succeeded.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the sole logical atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the updated configuration containing the active asset module.
    #[must_use]
    pub const fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the resolver derived from the updated configuration.
    #[must_use]
    pub const fn resolver(&self) -> &HashSuiteResolver {
        &self.resolver
    }

    /// Returns the immutable, startup-reconciled preinstalled catalog.
    #[must_use]
    pub const fn catalog(&self) -> &PreinstalledModuleCatalog {
        &self.catalog
    }

    /// Returns the object reference transactions use to select this module.
    #[must_use]
    pub const fn module_ref(&self) -> &ObjectRef {
        &self.module_ref
    }

    /// Returns the computed behavior-declaration commitment.
    #[must_use]
    pub const fn semantics_hash(&self) -> Digest32 {
        self.semantics_hash
    }

    /// Returns the devnet's one derived Standard Asset v1 [`AssetId`].
    #[must_use]
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    /// Consumes the composition into the ownership pieces required by the
    /// native router.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
        PreinstalledModuleCatalog,
        ObjectRef,
    ) {
        (
            self.chain_id,
            self.epoch,
            self.domain,
            self.protocol_config,
            self.resolver,
            self.catalog,
            self.module_ref,
        )
    }
}

/// Commits the canonical Standard Asset v1 whole-coin transfer WASM bytes
/// into protocol configuration and builds the exact catalog that can execute
/// them.
///
/// All code, schema, manifest, and semantic digests are computed through the
/// resolver tied to `context`; no caller-supplied or pasted digest is
/// trusted. The returned `ProtocolConfig` contains the active `SystemModule`
/// entry, and the returned resolver is freshly derived from that updated
/// configuration's own version and schedule before full registry/catalog
/// reconciliation.
pub fn build_standard_asset_module(
    context: DevnetProtocolContext,
    wasm_bytes: Vec<u8>,
) -> Result<DevnetAssetModule, DevnetCatalogError> {
    let (chain_id, epoch, domain, mut protocol_config, commitment_resolver, asset_id): (
        ChainId,
        Epoch,
        AtomicityDomainId,
        ProtocolConfig,
        HashSuiteResolver,
        AssetId,
    ) = context.into_parts();

    let input_schema: TypeSchema = build_schema(
        &commitment_resolver,
        epoch,
        STANDARD_ASSET_TRANSFER_INPUT_DESCRIPTOR,
        STANDARD_ASSET_TRANSFER_INPUT_SCHEMA,
    )?;
    let output_schema: TypeSchema = build_schema(
        &commitment_resolver,
        epoch,
        STANDARD_ASSET_TRANSFER_OUTPUT_DESCRIPTOR,
        STANDARD_ASSET_TRANSFER_OUTPUT_SCHEMA,
    )?;
    let manifest: SystemModuleManifest = SystemModuleManifest {
        module_id: STANDARD_ASSET_MODULE_ID,
        input_schema,
        output_schema,
        max_input_size: STANDARD_ASSET_MODULE_MAX_INPUT_SIZE,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    };
    manifest
        .validate()
        .map_err(DevnetCatalogError::SystemModule)?;

    let code_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::ContractCode, &wasm_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let manifest_bytes: Vec<u8> =
        encode_system_module_manifest(&manifest).map_err(DevnetCatalogError::SystemModule)?;
    let manifest_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &manifest_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let opaque_semantics: Vec<u8> = encode_standard_asset_semantics()?;
    let coin_constructor: ConstructorDeclaration = coin_constructor_declaration();
    let transfer_signature: EntrypointSignature = EntrypointSignature::new(
        TRANSFER_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let transfer_typed_policy: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], transfer_signature)
            .map_err(DevnetCatalogError::NodeCore)?;
    let split_signature: EntrypointSignature = EntrypointSignature::new(
        SPLIT_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let split_typed_policy: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], split_signature)
            .map_err(DevnetCatalogError::NodeCore)?;
    let merge_signature: EntrypointSignature = EntrypointSignature::new(
        MERGE_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Consume,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let merge_typed_policy: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], merge_signature)
            .map_err(DevnetCatalogError::NodeCore)?;
    let mint_signature: EntrypointSignature = EntrypointSignature::new(
        MINT_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_TREASURY_CAP_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let mint_typed_policy: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(
            vec![
                coin_constructor.clone(),
                treasury_cap_constructor_declaration(),
            ],
            mint_signature,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let burn_signature: EntrypointSignature = EntrypointSignature::new(
        BURN_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_TREASURY_CAP_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Consume,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let burn_typed_policy: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(
            vec![coin_constructor, treasury_cap_constructor_declaration()],
            burn_signature,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let owner_transition_policy: PreinstalledOwnerTransitionPolicy =
        PreinstalledOwnerTransitionPolicy::new(
            TRANSFER_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            TRANSFER_RECIPIENT_ARGS_FIELD_ID,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let split_creation_policy: PreinstalledObjectCreationPolicy =
        PreinstalledObjectCreationPolicy::new(
            SPLIT_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            SPLIT_RECIPIENT_ARGS_FIELD_ID,
            vec![1, 2],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let mint_creation_policy: PreinstalledObjectCreationPolicy =
        PreinstalledObjectCreationPolicy::new(
            MINT_ENTRYPOINT.to_string(),
            1,
            STANDARD_ASSET_MINT_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            MINT_RECIPIENT_ARGS_FIELD_ID,
            vec![1, 2],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_all_policies(
            opaque_semantics,
            Vec::new(),
            vec![
                transfer_typed_policy,
                split_typed_policy,
                merge_typed_policy,
                mint_typed_policy,
                burn_typed_policy,
            ],
            vec![owner_transition_policy],
            vec![split_creation_policy, mint_creation_policy],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&semantics_envelope)
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_hash: Digest32 = commitment_resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &semantics_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let historical_resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        ProtocolVersion::new(4),
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetCatalogError::Hashing)?;
    let (historical_module, historical_entry): (SystemModule, PreinstalledModuleCatalogEntry) =
        build_historical_standard_asset_v1(&historical_resolver, epoch)?;
    protocol_config
        .system_modules
        .add_module(historical_module)
        .map_err(DevnetCatalogError::SystemModule)?;

    // The discarded split/merge and unbounded-mint fixtures were built under
    // protocol version 5. Keep their regression commitments under that exact
    // resolver rather than reinterpreting them under the active protocol-v6
    // hash frame. Their separate legacy module IDs make this test history, not
    // a compatibility claim on the canonical Standard Asset version line.
    let historical_resolver_v5: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        ProtocolVersion::new(5),
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetCatalogError::Hashing)?;
    let (historical_v2_module, historical_v2_entry): (
        SystemModule,
        PreinstalledModuleCatalogEntry,
    ) = build_historical_standard_asset_v2(&historical_resolver_v5, epoch)?;
    protocol_config
        .system_modules
        .add_module(historical_v2_module)
        .map_err(DevnetCatalogError::SystemModule)?;
    let (historical_v3_module, historical_v3_entry): (
        SystemModule,
        PreinstalledModuleCatalogEntry,
    ) = build_historical_standard_asset_v3(&historical_resolver_v5, epoch)?;
    protocol_config
        .system_modules
        .add_module(historical_v3_module)
        .map_err(DevnetCatalogError::SystemModule)?;

    let module: SystemModule = SystemModule {
        module_id: STANDARD_ASSET_MODULE_ID,
        version: STANDARD_ASSET_MODULE_VERSION,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Active,
    };
    protocol_config
        .system_modules
        .add_module(module)
        .map_err(DevnetCatalogError::SystemModule)?;
    protocol_config
        .validate()
        .map_err(DevnetCatalogError::ProtocolConfig)?;

    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain_id.clone(),
        protocol_config.protocol_version,
        protocol_config.hash_suite_schedule.entries().to_vec(),
    )
    .map_err(DevnetCatalogError::Hashing)?;
    let entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
        STANDARD_ASSET_MODULE_ID,
        STANDARD_ASSET_MODULE_VERSION,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    let catalog: PreinstalledModuleCatalog = PreinstalledModuleCatalog::new(vec![
        historical_entry,
        historical_v2_entry,
        historical_v3_entry,
        entry,
    ])
    .map_err(DevnetCatalogError::NodeCore)?;
    reconcile_preinstalled_registry_and_catalog(
        &protocol_config.system_modules,
        &catalog,
        epoch,
        &resolver,
    )
    .map_err(DevnetCatalogError::NodeCore)?;

    let module_ref: ObjectRef = ObjectRef {
        id: ObjectId::new(*STANDARD_ASSET_MODULE_ID.as_bytes()),
        version: STANDARD_ASSET_MODULE_VERSION,
        digest: code_hash,
    };
    Ok(DevnetAssetModule {
        chain_id,
        epoch,
        domain,
        protocol_config,
        resolver,
        catalog,
        module_ref,
        semantics_hash,
        asset_id,
    })
}

/// Builds the isolated transfer-only development fixture catalog record.
fn build_historical_standard_asset_v1(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<(SystemModule, PreinstalledModuleCatalogEntry), DevnetCatalogError> {
    let input_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V1_TRANSFER_INPUT_DESCRIPTOR,
        STANDARD_ASSET_V1_TRANSFER_INPUT_SCHEMA,
    )?;
    let output_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V1_TRANSFER_OUTPUT_DESCRIPTOR,
        STANDARD_ASSET_V1_TRANSFER_OUTPUT_SCHEMA,
    )?;
    let manifest: SystemModuleManifest = SystemModuleManifest {
        module_id: LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
        input_schema,
        output_schema,
        max_input_size: STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    };
    manifest
        .validate()
        .map_err(DevnetCatalogError::SystemModule)?;
    let wasm_bytes: Vec<u8> = crate::standard_asset::STANDARD_ASSET_TRANSFER_V1_WASM.to_vec();
    let code_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::ContractCode, &wasm_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let manifest_bytes: Vec<u8> =
        encode_system_module_manifest(&manifest).map_err(DevnetCatalogError::SystemModule)?;
    let manifest_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &manifest_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let transfer_signature: EntrypointSignature = EntrypointSignature::new(
        TRANSFER_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let typed_policy: PreinstalledTypedEntrypointPolicy = PreinstalledTypedEntrypointPolicy::new(
        vec![coin_constructor_declaration()],
        transfer_signature,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    let owner_transition_policy: PreinstalledOwnerTransitionPolicy =
        PreinstalledOwnerTransitionPolicy::new(
            TRANSFER_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            TRANSFER_RECIPIENT_ARGS_FIELD_ID,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_typed_policies(
            encode_standard_asset_v1_semantics()?,
            Vec::new(),
            vec![typed_policy],
            vec![owner_transition_policy],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&semantics_envelope)
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &semantics_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let module: SystemModule = SystemModule {
        module_id: LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
        version: STANDARD_ASSET_HISTORICAL_MODULE_VERSION,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Disabled,
    };
    let entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
        LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
        STANDARD_ASSET_HISTORICAL_MODULE_VERSION,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    Ok((module, entry))
}

/// Builds the isolated split/merge development fixture catalog record containing
/// transfer, split, and merge but no mint entrypoint.
fn build_historical_standard_asset_v2(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<(SystemModule, PreinstalledModuleCatalogEntry), DevnetCatalogError> {
    let input_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V2_TRANSFER_INPUT_DESCRIPTOR,
        STANDARD_ASSET_V2_TRANSFER_INPUT_SCHEMA,
    )?;
    let output_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V2_TRANSFER_OUTPUT_DESCRIPTOR,
        STANDARD_ASSET_V2_TRANSFER_OUTPUT_SCHEMA,
    )?;
    let manifest: SystemModuleManifest = SystemModuleManifest {
        module_id: LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
        input_schema,
        output_schema,
        max_input_size: STANDARD_ASSET_MODULE_MAX_INPUT_SIZE,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    };
    manifest
        .validate()
        .map_err(DevnetCatalogError::SystemModule)?;
    let wasm_bytes: Vec<u8> = crate::standard_asset::STANDARD_ASSET_OPERATIONS_V2_WASM.to_vec();
    let code_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::ContractCode, &wasm_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let manifest_bytes: Vec<u8> =
        encode_system_module_manifest(&manifest).map_err(DevnetCatalogError::SystemModule)?;
    let manifest_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &manifest_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let coin_constructor: ConstructorDeclaration = coin_constructor_declaration();
    let transfer_signature: EntrypointSignature = EntrypointSignature::new(
        TRANSFER_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let split_signature: EntrypointSignature = EntrypointSignature::new(
        SPLIT_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let merge_signature: EntrypointSignature = EntrypointSignature::new(
        MERGE_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Consume,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let typed_policies: Vec<PreinstalledTypedEntrypointPolicy> = vec![
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], transfer_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], split_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor], merge_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
    ];
    let owner_transition_policy: PreinstalledOwnerTransitionPolicy =
        PreinstalledOwnerTransitionPolicy::new(
            TRANSFER_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            TRANSFER_RECIPIENT_ARGS_FIELD_ID,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let creation_policy: PreinstalledObjectCreationPolicy = PreinstalledObjectCreationPolicy::new(
        SPLIT_ENTRYPOINT.to_string(),
        0,
        STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID,
        RECIPIENT_ARGS_ENCODING_VERSION,
        SPLIT_RECIPIENT_ARGS_FIELD_ID,
        vec![1, 2],
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_all_policies(
            encode_standard_asset_v2_semantics()?,
            Vec::new(),
            typed_policies,
            vec![owner_transition_policy],
            vec![creation_policy],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&semantics_envelope)
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &semantics_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let module: SystemModule = SystemModule {
        module_id: LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
        version: STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Disabled,
    };
    let entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
        LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
        STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    Ok((module, entry))
}

/// Builds the isolated unbounded-mint development fixture catalog record containing
/// `transfer`, `split`, `merge`, and the frozen capability-authorized `mint`.
/// The executable behavior is kept for regression coverage without extending
/// the canonical Standard Asset module's version line.
fn build_historical_standard_asset_v3(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<(SystemModule, PreinstalledModuleCatalogEntry), DevnetCatalogError> {
    let input_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V3_TRANSFER_INPUT_DESCRIPTOR,
        STANDARD_ASSET_V3_TRANSFER_INPUT_SCHEMA,
    )?;
    let output_schema: TypeSchema = build_schema(
        resolver,
        epoch,
        STANDARD_ASSET_V3_TRANSFER_OUTPUT_DESCRIPTOR,
        STANDARD_ASSET_V3_TRANSFER_OUTPUT_SCHEMA,
    )?;
    let manifest: SystemModuleManifest = SystemModuleManifest {
        module_id: LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
        input_schema,
        output_schema,
        max_input_size: STANDARD_ASSET_MODULE_MAX_INPUT_SIZE,
        gas_model: GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    };
    manifest
        .validate()
        .map_err(DevnetCatalogError::SystemModule)?;
    let wasm_bytes: Vec<u8> = crate::standard_asset::STANDARD_ASSET_OPERATIONS_V3_WASM.to_vec();
    let code_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::ContractCode, &wasm_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let manifest_bytes: Vec<u8> =
        encode_system_module_manifest(&manifest).map_err(DevnetCatalogError::SystemModule)?;
    let manifest_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &manifest_bytes)
        .map_err(DevnetCatalogError::Hashing)?;

    let coin_constructor: ConstructorDeclaration = coin_constructor_declaration();
    let transfer_signature: EntrypointSignature = EntrypointSignature::new(
        TRANSFER_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let split_signature: EntrypointSignature = EntrypointSignature::new(
        SPLIT_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let merge_signature: EntrypointSignature = EntrypointSignature::new(
        MERGE_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Consume,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let mint_signature: EntrypointSignature = EntrypointSignature::new(
        MINT_ENTRYPOINT,
        vec![
            ParamDeclaration {
                mode: AccessMode::Read,
                constructor: STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            },
        ],
    )
    .map_err(DevnetCatalogError::TypedAbi)?;
    let typed_policies: Vec<PreinstalledTypedEntrypointPolicy> = vec![
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], transfer_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], split_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
        PreinstalledTypedEntrypointPolicy::new(vec![coin_constructor.clone()], merge_signature)
            .map_err(DevnetCatalogError::NodeCore)?,
        PreinstalledTypedEntrypointPolicy::new(
            vec![coin_constructor, mint_capability_constructor_declaration()],
            mint_signature,
        )
        .map_err(DevnetCatalogError::NodeCore)?,
    ];
    let owner_transition_policy: PreinstalledOwnerTransitionPolicy =
        PreinstalledOwnerTransitionPolicy::new(
            TRANSFER_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            TRANSFER_RECIPIENT_ARGS_FIELD_ID,
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let split_creation_policy: PreinstalledObjectCreationPolicy =
        PreinstalledObjectCreationPolicy::new(
            SPLIT_ENTRYPOINT.to_string(),
            0,
            STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            SPLIT_RECIPIENT_ARGS_FIELD_ID,
            vec![1, 2],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let mint_creation_policy: PreinstalledObjectCreationPolicy =
        PreinstalledObjectCreationPolicy::new(
            MINT_ENTRYPOINT.to_string(),
            1,
            STANDARD_ASSET_MINT_ARGS_V1_TYPE_ID,
            RECIPIENT_ARGS_ENCODING_VERSION,
            MINT_RECIPIENT_ARGS_FIELD_ID,
            vec![1, 2],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_all_policies(
            encode_standard_asset_v3_semantics()?,
            Vec::new(),
            typed_policies,
            vec![owner_transition_policy],
            vec![split_creation_policy, mint_creation_policy],
        )
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&semantics_envelope)
        .map_err(DevnetCatalogError::NodeCore)?;
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &semantics_bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    let module: SystemModule = SystemModule {
        module_id: LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
        version: STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch: Epoch::new(0),
        status: ModuleStatus::Disabled,
    };
    let entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
        LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
        STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION,
        wasm_bytes,
        manifest,
        semantics_envelope,
    )
    .map_err(DevnetCatalogError::NodeCore)?;
    Ok((module, entry))
}

fn build_schema(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    descriptor: &'static str,
    definition: &'static str,
) -> Result<TypeSchema, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        STANDARD_ASSET_SCHEMA_DECLARATION_TYPE_ID,
        STANDARD_ASSET_SCHEMA_DECLARATION_ENCODING_VERSION,
    );
    canonical
        .field_str(1, descriptor)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(2, definition)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    let bytes: Vec<u8> = canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    let schema_hash: Digest32 = resolver
        .hash_for_purpose(epoch, HashPurpose::SystemModuleManifest, &bytes)
        .map_err(DevnetCatalogError::Hashing)?;
    Ok(TypeSchema {
        descriptor: descriptor.to_string(),
        schema_hash,
    })
}

/// Encodes the Standard Asset v1 module's opaque semantics declaration.
///
/// States, in order: module identity/version/name/entrypoint; the exact
/// access shape (F5); the honest validation-only WASM facts (F8); the
/// single-shared-type-variable fee-asset limitation (F5); and the hidden
/// treasury's boot-time-only type verification (F4).
fn encode_standard_asset_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        STANDARD_ASSET_SEMANTICS_DECLARATION_TYPE_ID,
        STANDARD_ASSET_SEMANTICS_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, STANDARD_ASSET_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, STANDARD_ASSET_MODULE_VERSION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(5, STANDARD_ASSET_ACCESS_SEMANTICS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(6, STANDARD_ASSET_VALIDATION_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(7, STANDARD_ASSET_TYPE_VARIABLE_LIMITATION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(8, STANDARD_ASSET_TREASURY_VISIBILITY_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)
}

/// Encodes the immutable protocol-v5 module-v2 semantics declaration.
fn encode_standard_asset_v2_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        STANDARD_ASSET_SEMANTICS_DECLARATION_TYPE_ID,
        STANDARD_ASSET_SEMANTICS_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(5, STANDARD_ASSET_V2_ACCESS_SEMANTICS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(6, STANDARD_ASSET_V2_VALIDATION_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(7, STANDARD_ASSET_V2_TYPE_VARIABLE_LIMITATION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(8, STANDARD_ASSET_V2_TREASURY_VISIBILITY_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)
}

/// Encodes the immutable protocol-v5 module-v3 semantics declaration (frozen
/// capability-authorized mint). Keep this separate from
/// [`encode_standard_asset_semantics`]: even a prose cleanup changes the
/// governance commitment of this now-historical module reference.
fn encode_standard_asset_v3_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        STANDARD_ASSET_SEMANTICS_DECLARATION_TYPE_ID,
        STANDARD_ASSET_SEMANTICS_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(5, STANDARD_ASSET_V3_ACCESS_SEMANTICS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(6, STANDARD_ASSET_V3_VALIDATION_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(7, STANDARD_ASSET_V3_TYPE_VARIABLE_LIMITATION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(8, STANDARD_ASSET_V3_TREASURY_VISIBILITY_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)
}

/// Encodes the original protocol-v4 Standard Asset v1 semantics declaration.
///
/// Keep this separate from [`encode_standard_asset_semantics`]: even a prose
/// cleanup changes the governance commitment of an old module reference.
fn encode_standard_asset_v1_semantics() -> Result<Vec<u8>, DevnetCatalogError> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(
        STANDARD_ASSET_SEMANTICS_DECLARATION_TYPE_ID,
        STANDARD_ASSET_SEMANTICS_ENCODING_VERSION,
    );
    canonical
        .field_bytes(1, LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID.as_bytes())
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_u64(2, STANDARD_ASSET_HISTORICAL_MODULE_VERSION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(3, LEGACY_STANDARD_ASSET_TRANSFER_MODULE_NAME)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(4, TRANSFER_ENTRYPOINT)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(5, STANDARD_ASSET_V1_ACCESS_SEMANTICS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(6, STANDARD_ASSET_V1_VALIDATION_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(7, STANDARD_ASSET_V1_TYPE_VARIABLE_LIMITATION)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .field_str(8, STANDARD_ASSET_V1_TREASURY_VISIBILITY_FACTS)
        .map_err(DevnetCatalogError::CanonicalEncoding)?;
    canonical
        .finish()
        .map_err(DevnetCatalogError::CanonicalEncoding)
}

/// Failures while committing and reconciling the trusted devnet catalog.
#[derive(Debug)]
pub enum DevnetCatalogError {
    /// A dev-local commitment declaration could not be canonically encoded.
    CanonicalEncoding(CanonicalEncodingError),
    /// Hash-suite resolution or commitment hashing failed.
    Hashing(HashingError),
    /// System-module manifest or registry construction failed.
    SystemModule(SystemModuleError),
    /// The updated protocol configuration failed validation.
    ProtocolConfig(ProtocolConfigError),
    /// Typed-ABI signature or constructor construction failed.
    TypedAbi(AbiError),
    /// Catalog construction or full startup reconciliation failed closed.
    NodeCore(NodeCoreError),
}

impl fmt::Display for DevnetCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => {
                write!(
                    formatter,
                    "devnet asset declaration encoding failed: {error}"
                )
            }
            Self::Hashing(error) => {
                write!(formatter, "devnet asset commitment hashing failed: {error}")
            }
            Self::SystemModule(error) => {
                write!(
                    formatter,
                    "devnet asset system-module definition failed: {error}"
                )
            }
            Self::ProtocolConfig(error) => {
                write!(
                    formatter,
                    "devnet asset protocol configuration failed: {error}"
                )
            }
            Self::TypedAbi(error) => {
                write!(
                    formatter,
                    "devnet asset typed-ABI declaration failed: {error}"
                )
            }
            Self::NodeCore(error) => {
                write!(
                    formatter,
                    "devnet asset catalog reconciliation failed: {error}"
                )
            }
        }
    }
}

impl Error for DevnetCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::SystemModule(error) => Some(error),
            Self::ProtocolConfig(error) => Some(error),
            Self::TypedAbi(error) => Some(error),
            Self::NodeCore(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        genesis::build_devnet_protocol_context, standard_asset::STANDARD_ASSET_MODULE_WASM,
    };

    fn module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_standard_asset_module(context, b"canonical-standard-asset-wasm".to_vec()).unwrap()
    }

    fn actual_asset_module() -> DevnetAssetModule {
        let chain_id: ChainId = ChainId::new("sunrise-devnet-catalog-test").unwrap();
        let context: DevnetProtocolContext =
            build_devnet_protocol_context(chain_id, Epoch::new(7)).unwrap();
        build_standard_asset_module(context, STANDARD_ASSET_MODULE_WASM.to_vec()).unwrap()
    }

    #[test]
    fn semantics_declares_canonical_v1_mint_burn_type_variable_and_treasury_facts() {
        let bytes: Vec<u8> = encode_standard_asset_semantics().unwrap();
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("transfer remains validation-only"));
        assert!(text.contains("split, merge, mint, and burn perform all checked"));
        assert!(text.contains("TreasuryCap<A> and fee Coin<A>"));
        assert!(text.contains("checked-adds the requested amount"));
        assert!(text.contains("checked-subtracts a whole consumed"));
        assert!(text.contains("excluded from module execution inputs"));
        assert!(text.contains("mint and burn cannot observe"));
    }

    #[test]
    fn historical_v3_semantics_retains_frozen_mint_capability_text() {
        let bytes: Vec<u8> = encode_standard_asset_v3_semantics().unwrap();
        let text: String = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("transfer remains validation-only"));
        assert!(text.contains("split, merge, and mint perform all checked"));
        assert!(text.contains("MintCapability<A> and fee Coin<A>"));
        assert!(text.contains("excluded from module execution inputs"));
        assert!(text.contains("mint cannot observe"));
        assert!(!text.contains("TreasuryCap"));
        assert!(!text.contains("burn"));
    }

    #[test]
    fn updated_config_and_catalog_reconcile() {
        let module: DevnetAssetModule = module();
        let registered: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(STANDARD_ASSET_MODULE_ID, STANDARD_ASSET_MODULE_VERSION)
            .unwrap();

        assert_eq!(registered.status, ModuleStatus::Active);
        assert_eq!(registered.version, STANDARD_ASSET_MODULE_VERSION);
        assert_eq!(registered.canonical_code_hash, module.module_ref().digest);
        assert_eq!(registered.semantics_hash, module.semantics_hash());
        let fee_asset = module
            .protocol_config()
            .fee_assets
            .get(module.asset_id())
            .unwrap();
        assert!(fee_asset.enabled);
        assert_eq!(fee_asset.fee_units_per_asset_unit, 1);
        assert_eq!(module.protocol_config().gas_schedule.base_fee, 1);
        assert_eq!(module.protocol_config().gas_schedule.execution_price, 1);
        assert_eq!(module.resolver().chain_id(), module.chain_id());
        assert_eq!(
            module.resolver().protocol_version(),
            module.protocol_config().protocol_version
        );
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &module.protocol_config().system_modules,
                module.catalog(),
                module.epoch(),
                module.resolver(),
            ),
            Ok(())
        );
    }

    #[test]
    fn catalog_stores_the_exact_committed_standard_asset_wasm_bytes() {
        let module: DevnetAssetModule = actual_asset_module();
        let entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(STANDARD_ASSET_MODULE_ID, STANDARD_ASSET_MODULE_VERSION)
            .unwrap();
        assert_eq!(entry.wasm_bytes(), STANDARD_ASSET_MODULE_WASM);
    }

    #[test]
    fn legacy_transfer_catalog_record_is_isolated_and_disabled() {
        let module: DevnetAssetModule = actual_asset_module();
        let archived: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
                STANDARD_ASSET_HISTORICAL_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(archived.status, ModuleStatus::Disabled);
        let archived_entry: PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(
                LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
                STANDARD_ASSET_HISTORICAL_MODULE_VERSION,
            )
            .unwrap()
            .clone();
        assert_eq!(
            archived_entry.wasm_bytes(),
            crate::standard_asset::STANDARD_ASSET_TRANSFER_V1_WASM
        );

        let historical_resolver: HashSuiteResolver = HashSuiteResolver::new(
            module.chain_id().clone(),
            ProtocolVersion::new(4),
            module
                .protocol_config()
                .hash_suite_schedule
                .entries()
                .to_vec(),
        )
        .unwrap();
        let mut historical_module: SystemModule = archived.clone();
        historical_module.status = ModuleStatus::Active;
        let mut historical_registry = system_modules::SystemModuleRegistry::new();
        historical_registry.add_module(historical_module).unwrap();
        let historical_catalog: PreinstalledModuleCatalog =
            PreinstalledModuleCatalog::new(vec![archived_entry]).unwrap();
        assert_eq!(
            reconcile_preinstalled_registry_and_catalog(
                &historical_registry,
                &historical_catalog,
                module.epoch(),
                &historical_resolver,
            ),
            Ok(())
        );
    }

    #[test]
    fn legacy_split_merge_catalog_record_is_disabled_and_byte_exact() {
        let module: DevnetAssetModule = actual_asset_module();
        let archived: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION,
            )
            .unwrap();
        let archived_entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(
                LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(archived.status, ModuleStatus::Disabled);
        assert_eq!(
            archived_entry.wasm_bytes(),
            crate::standard_asset::STANDARD_ASSET_OPERATIONS_V2_WASM
        );
        assert_eq!(
            crate::standard_asset::STANDARD_ASSET_OPERATIONS_V2_WASM,
            wat::parse_str(crate::standard_asset::STANDARD_ASSET_OPERATIONS_V2_WAT).unwrap()
        );
        assert_eq!(
            archived_entry
                .semantics_envelope()
                .typed_entrypoint_policies()
                .len(),
            3
        );
        assert_eq!(
            archived_entry
                .semantics_envelope()
                .object_creation_policies()
                .len(),
            1
        );
    }

    #[test]
    fn legacy_unbounded_mint_catalog_record_is_disabled_and_byte_exact() {
        let module: DevnetAssetModule = actual_asset_module();
        let archived: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION,
            )
            .unwrap();
        let archived_entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(
                LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(archived.status, ModuleStatus::Disabled);
        assert_eq!(
            archived_entry.wasm_bytes(),
            crate::standard_asset::STANDARD_ASSET_OPERATIONS_V3_WASM
        );
        assert_eq!(
            crate::standard_asset::STANDARD_ASSET_OPERATIONS_V3_WASM,
            wat::parse_str(crate::standard_asset::STANDARD_ASSET_OPERATIONS_V3_WAT).unwrap()
        );
        assert_eq!(
            archived_entry
                .semantics_envelope()
                .typed_entrypoint_policies()
                .len(),
            4
        );
        let mint = archived_entry
            .semantics_envelope()
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == MINT_ENTRYPOINT)
            .unwrap();
        assert_eq!(mint.signature().params()[0].mode, AccessMode::Read);
        assert_eq!(
            mint.signature().params()[0].constructor,
            STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR
        );
        assert_eq!(
            archived_entry
                .semantics_envelope()
                .object_creation_policies()
                .len(),
            2
        );
    }

    #[test]
    fn v2_and_v3_commitments_are_pinned_under_protocol_v5() {
        let module: DevnetAssetModule = actual_asset_module();
        let v2: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_SPLIT_MERGE_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V2_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(
            v2.canonical_code_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x11, 0xcb, 0x6e, 0x38, 0xbd, 0x8d, 0x03, 0x68, 0x5d, 0xd2, 0x38, 0x8a, 0x21,
                    0xd9, 0xb3, 0x7b, 0xbf, 0xbb, 0x9b, 0x78, 0x56, 0x59, 0x4c, 0x50, 0x8d, 0xac,
                    0x8d, 0x55, 0xd9, 0xeb, 0x3b, 0x1c,
                ],
            )
        );
        assert_eq!(
            v2.manifest_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x24, 0xe1, 0x82, 0x28, 0x24, 0x5a, 0x35, 0xb3, 0x5d, 0x3d, 0x6c, 0xe8, 0xa0,
                    0x0f, 0x8f, 0xa7, 0x17, 0x19, 0xa0, 0x40, 0x59, 0xf8, 0xe5, 0x2f, 0x35, 0x90,
                    0x81, 0x14, 0x1e, 0x4e, 0xa5, 0x5a,
                ],
            )
        );
        assert_eq!(
            v2.semantics_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0xe2, 0x16, 0x08, 0xb0, 0x76, 0x5c, 0x30, 0x22, 0xfa, 0xd0, 0x3f, 0x03, 0xc8,
                    0x12, 0x92, 0x6d, 0x77, 0xc6, 0xe5, 0xfc, 0xcd, 0x7a, 0x1d, 0x4c, 0x62, 0xc7,
                    0x27, 0xc8, 0xca, 0x69, 0x58, 0xd7,
                ],
            )
        );

        let v3: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_UNBOUNDED_MINT_MODULE_ID,
                STANDARD_ASSET_OPERATIONS_V3_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(v3.status, ModuleStatus::Disabled);
        assert_eq!(
            v3.canonical_code_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x23, 0x43, 0xf4, 0x41, 0xc8, 0x1a, 0x13, 0x4c, 0x7b, 0xdc, 0xe5, 0xc1, 0x7b,
                    0x23, 0x1e, 0xca, 0x9c, 0x36, 0xd7, 0xff, 0x4f, 0x97, 0xa0, 0x97, 0xe4, 0x9f,
                    0x1c, 0x1e, 0x20, 0xcc, 0x45, 0x64,
                ],
            )
        );
        assert_eq!(
            v3.manifest_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x06, 0xdc, 0xca, 0xc0, 0x32, 0x00, 0x2e, 0x96, 0xb0, 0x5c, 0x22, 0x4c, 0xce,
                    0x62, 0x12, 0x2b, 0x07, 0x59, 0x04, 0xe5, 0x43, 0x1f, 0xeb, 0xf5, 0xe9, 0x6f,
                    0x6f, 0x4e, 0xa4, 0x1e, 0xbb, 0x08,
                ],
            )
        );
        assert_eq!(
            v3.semantics_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x3a, 0xec, 0x18, 0x0e, 0xa3, 0xb2, 0xef, 0xb1, 0x3d, 0x30, 0x9c, 0x36, 0x71,
                    0x6f, 0x20, 0x9c, 0xe2, 0xc0, 0xf1, 0x0b, 0xf9, 0x98, 0xe8, 0xb3, 0x4e, 0x57,
                    0x42, 0xf3, 0xcc, 0xc0, 0x65, 0x33,
                ],
            )
        );
    }

    #[test]
    fn v1_commitments_are_pinned_under_the_original_protocol_context() {
        let module: DevnetAssetModule = actual_asset_module();
        let archived: &SystemModule = module
            .protocol_config()
            .system_modules
            .get(
                LEGACY_STANDARD_ASSET_TRANSFER_MODULE_ID,
                STANDARD_ASSET_HISTORICAL_MODULE_VERSION,
            )
            .unwrap();
        assert_eq!(
            archived.canonical_code_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0xbd, 0xa1, 0x64, 0x9e, 0xeb, 0x4b, 0x10, 0xf2, 0x15, 0x95, 0xdc, 0xeb, 0xf8,
                    0x85, 0x45, 0x11, 0xc7, 0x1e, 0xe0, 0x35, 0xbb, 0x29, 0x7d, 0x12, 0x2e, 0xff,
                    0xd6, 0x73, 0x7b, 0x5a, 0xa9, 0xba,
                ],
            )
        );
        assert_eq!(
            archived.manifest_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0xcd, 0x46, 0xaa, 0xb4, 0x43, 0xe9, 0xb1, 0x06, 0x05, 0xf7, 0xbb, 0xb4, 0x4a,
                    0xee, 0x82, 0x3d, 0xb4, 0x44, 0x52, 0xff, 0x2e, 0xc0, 0x02, 0xa1, 0xe8, 0x15,
                    0x32, 0x63, 0x1b, 0x1e, 0xfd, 0x4b,
                ],
            )
        );
        assert_eq!(
            archived.semantics_hash,
            Digest32::new(
                protocol_types::HashAlgorithmId::Sha2_256,
                [
                    0x5d, 0x3e, 0xed, 0x2f, 0x5a, 0x24, 0x8e, 0xc2, 0xfb, 0xed, 0x80, 0x21, 0xe4,
                    0x3f, 0xe4, 0xe8, 0x05, 0x86, 0x7b, 0x72, 0x52, 0x08, 0x70, 0x86, 0x2b, 0x35,
                    0xf8, 0x8a, 0x1f, 0xc0, 0xc8, 0x44,
                ],
            )
        );
        assert_eq!(
            crate::standard_asset::STANDARD_ASSET_TRANSFER_V1_WASM,
            wat::parse_str(crate::standard_asset::STANDARD_ASSET_TRANSFER_V1_WAT).unwrap()
        );
    }

    #[test]
    fn tampered_wasm_fails_startup_reconciliation() {
        let module: DevnetAssetModule = module();
        let original: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(STANDARD_ASSET_MODULE_ID, STANDARD_ASSET_MODULE_VERSION)
            .unwrap();
        let tampered_entry: PreinstalledModuleCatalogEntry = PreinstalledModuleCatalogEntry::new(
            STANDARD_ASSET_MODULE_ID,
            STANDARD_ASSET_MODULE_VERSION,
            b"tampered-standard-asset-wasm".to_vec(),
            original.manifest().clone(),
            original.semantics_envelope().clone(),
        )
        .unwrap();
        let tampered_catalog: PreinstalledModuleCatalog =
            PreinstalledModuleCatalog::new(vec![tampered_entry]).unwrap();

        assert!(matches!(
            reconcile_preinstalled_registry_and_catalog(
                &module.protocol_config().system_modules,
                &tampered_catalog,
                module.epoch(),
                module.resolver(),
            ),
            Err(NodeCoreError::PreinstalledModuleCodeHashMismatch {
                module_id: STANDARD_ASSET_MODULE_ID,
                version: STANDARD_ASSET_MODULE_VERSION,
            })
        ));
    }

    #[test]
    fn commitment_is_bound_to_chain_context() {
        let first: DevnetAssetModule = module();
        let second_context: DevnetProtocolContext = build_devnet_protocol_context(
            ChainId::new("sunrise-other-devnet").unwrap(),
            Epoch::new(7),
        )
        .unwrap();
        let second: DevnetAssetModule =
            build_standard_asset_module(second_context, b"canonical-standard-asset-wasm".to_vec())
                .unwrap();

        assert_ne!(first.module_ref().digest, second.module_ref().digest);
        assert_ne!(first.semantics_hash(), second.semantics_hash());
        assert_ne!(first.asset_id(), second.asset_id());
    }

    #[test]
    fn catalog_commits_exact_canonical_v1_typed_creation_and_owner_transition_policies() {
        let module: DevnetAssetModule = module();
        let entry: &PreinstalledModuleCatalogEntry = module
            .catalog()
            .get(STANDARD_ASSET_MODULE_ID, STANDARD_ASSET_MODULE_VERSION)
            .unwrap();
        let envelope = entry.semantics_envelope();

        assert!(envelope.object_access_policies().is_empty());
        assert_eq!(envelope.typed_entrypoint_policies().len(), 5);
        let transfer = envelope
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == TRANSFER_ENTRYPOINT)
            .unwrap();
        assert_eq!(transfer.signature().params().len(), 2);
        for param in transfer.signature().params() {
            assert_eq!(param.mode, AccessMode::Write);
            assert_eq!(param.constructor, STANDARD_ASSET_COIN_V1_CONSTRUCTOR);
            assert_eq!(param.schema_version, STANDARD_ASSET_SCHEMA_VERSION_V1);
        }
        let split = envelope
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == SPLIT_ENTRYPOINT)
            .unwrap();
        assert_eq!(split.signature().params().len(), 2);
        let merge = envelope
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == MERGE_ENTRYPOINT)
            .unwrap();
        assert_eq!(merge.signature().params().len(), 3);
        assert_eq!(merge.signature().params()[1].mode, AccessMode::Consume);
        let mint = envelope
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == MINT_ENTRYPOINT)
            .unwrap();
        assert_eq!(mint.signature().params().len(), 2);
        assert_eq!(mint.signature().params()[0].mode, AccessMode::Write);
        assert_eq!(
            mint.signature().params()[0].constructor,
            STANDARD_ASSET_TREASURY_CAP_V1_CONSTRUCTOR
        );
        assert_eq!(mint.signature().params()[1].mode, AccessMode::Write);
        assert_eq!(
            mint.signature().params()[1].constructor,
            STANDARD_ASSET_COIN_V1_CONSTRUCTOR
        );
        let burn = envelope
            .typed_entrypoint_policies()
            .iter()
            .find(|policy| policy.entrypoint() == BURN_ENTRYPOINT)
            .unwrap();
        assert_eq!(burn.signature().params().len(), 3);
        assert_eq!(burn.signature().params()[0].mode, AccessMode::Write);
        assert_eq!(
            burn.signature().params()[0].constructor,
            STANDARD_ASSET_TREASURY_CAP_V1_CONSTRUCTOR
        );
        assert_eq!(burn.signature().params()[1].mode, AccessMode::Consume);
        assert_eq!(
            burn.signature().params()[1].constructor,
            STANDARD_ASSET_COIN_V1_CONSTRUCTOR
        );
        assert_eq!(burn.signature().params()[2].mode, AccessMode::Write);
        assert_eq!(
            burn.signature().params()[2].constructor,
            STANDARD_ASSET_COIN_V1_CONSTRUCTOR
        );

        assert_eq!(envelope.owner_transition_policies().len(), 1);
        let owner = &envelope.owner_transition_policies()[0];
        assert_eq!(owner.entrypoint(), TRANSFER_ENTRYPOINT);
        assert_eq!(owner.transferred_access_index(), 0);
        // burn has no owner-transition and no creation policy — identical to
        // merge's precedent (a Consume-mode param plus zero policy commitments).
        assert!(
            !envelope
                .owner_transition_policies()
                .iter()
                .any(|policy| policy.entrypoint() == BURN_ENTRYPOINT)
        );
        assert_eq!(envelope.object_creation_policies().len(), 2);
        assert!(
            !envelope
                .object_creation_policies()
                .iter()
                .any(|policy| policy.entrypoint() == BURN_ENTRYPOINT)
        );
        let split_creation = envelope
            .object_creation_policies()
            .iter()
            .find(|policy| policy.entrypoint() == SPLIT_ENTRYPOINT)
            .unwrap();
        assert_eq!(split_creation.type_source_access_index(), 0);
        assert_eq!(split_creation.allowed_args_field_ids(), &[1, 2]);
        let mint_creation = envelope
            .object_creation_policies()
            .iter()
            .find(|policy| policy.entrypoint() == MINT_ENTRYPOINT)
            .unwrap();
        assert_eq!(mint_creation.type_source_access_index(), 1);
        assert_eq!(mint_creation.allowed_args_field_ids(), &[1, 2]);
    }
}
