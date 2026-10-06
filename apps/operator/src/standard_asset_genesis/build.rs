//! Ordinary package, objects and policy composition. Standard Asset knowledge
//! stays in this operator preset, never in a special core admission path.

use super::input::{Allocation, Config, Validator};
use abi::{
    AccessManifest,
    call_values::{CallValue, encode_call_value},
    package_types::{PackageOrigin, ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id},
};
use bonds::{BondResourceConfig, BondResourceId};
use ed25519_zebra::SigningKey;
use execution::{
    call::{CallIntent, InstanceTarget},
    local_execution::{
        InstanceRecord, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
        ObjectAuthority, SignedLocalExecutionIntent, generic_object_result_semantics,
        instance_target, local_execution_signing_frame,
    },
    paid_execution::{
        PHASE_CALLS, PHASE_CREATIONS, PHASE_EVENTS, PHASE_HANDLES, PHASE_MEMORY_BYTES,
        PHASE_OUTPUT_BYTES, PaidFeePolicy,
    },
    publication::{
        ArtifactParts, CodeArtifact, PublicationContext, PublicationRequest, PublicationSubmission,
        UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
    },
};
use fees::Amount;
use hashing::HashSuiteResolver;
use node_core::{
    economics::{FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy},
    fast_path::{FastPathValidatorEntry, FastPathValidatorSetRecord},
    genesis::{GenesisManifest, GenesisObjectEntry, genesis_manifest_signing_frame},
    logical_generation::CommitmentProfile,
};
use objects::{Address, Object, ObjectId, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::{Digest32, SignatureSchemeId};
use public_standard_asset::{
    SCHEMA_VERSION, asset_type_argument, build_package, coin_amount, coin_body_layout,
    coin_type_tag, definition_body_layout, definition_type_tag, no_arguments, reservation_type_tag,
    treasury_cap_body_layout, treasury_cap_type_tag, treasury_supply,
};
use std::error::Error;

struct ObjectComposer<'a> {
    context: &'a PublicationContext,
    resolver: &'a HashSuiteResolver,
    instance: &'a InstanceTarget,
    code: &'a UnverifiedDependencyRef,
}

impl ObjectComposer<'_> {
    fn entry(
        &self,
        id: ObjectId,
        owner: Owner,
        ty: ScopedTypeTag,
        body: Vec<u8>,
    ) -> Result<GenesisObjectEntry, Box<dyn Error>> {
        let object: Object = Object {
            id,
            version: 1,
            owner,
            type_hash: derive_scoped_type_id(self.resolver, self.context.epoch(), &ty)?,
            schema_version: SCHEMA_VERSION,
            data: body,
        };
        let authority: ObjectAuthority = ObjectAuthority {
            object_id: id,
            instance_context: self.context.clone(),
            instance: self.instance.clone(),
            code: self.code.clone(),
            ty,
        };
        Ok(GenesisObjectEntry { object, authority })
    }
}

pub(super) fn build(
    config: &Config,
    validators: &[Validator],
    allocations: &[Allocation],
    key: &SigningKey,
) -> Result<GenesisManifest, Box<dyn Error>> {
    let context: &PublicationContext = &config.context;
    let resolver: &HashSuiteResolver = &config.resolver;
    let origin: PackageOrigin = PackageOrigin::unverified(
        context.chain_id().clone(),
        config.authority,
        config.origin_seed,
    )?;
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
    let publication_frame: Vec<u8> = publication_submission_signing_frame(
        resolver,
        context,
        &artifact,
        0,
        config.publication_request_id,
    )?;
    let publication_signature: [u8; 64] = key.sign(&publication_frame).into();
    let publication: PublicationSubmission = PublicationSubmission::new(
        config.publication_request_id,
        PublicationRequest::new(artifact, 0, artifact_digest, publication_signature),
    )?;
    let code: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), artifact_digest)?;
    let record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: config.authority,
        seed: config.instance_seed,
        code: code.clone(),
        revision: 1,
        initializer: public_standard_asset::INITIALIZER.to_owned(),
    };
    let instance: InstanceTarget = instance_target(resolver, &record)?;
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let base_policy_digest: Digest32 = base_policy.digest(resolver)?;
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Instantiate,
        policy_digest: base_policy_digest,
        call: CallIntent {
            context: context.clone(),
            request_id: config.initialization_request_id,
            sender: config.authority,
            nonce: 0,
            code: code.clone(),
            instance: instance.clone(),
            entrypoint: public_standard_asset::INITIALIZER.to_owned(),
            type_arguments: Vec::new(),
            access: AccessManifest::new(),
            arguments: no_arguments()?,
            gas_limit: config.initialization_gas_limit,
        },
        authorizations: Vec::new(),
    };
    let initialization_frame: Vec<u8> = local_execution_signing_frame(context, &intent)?;
    let initialization_signature: [u8; 64] = key.sign(&initialization_frame).into();
    let initialization: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent,
        signature: initialization_signature,
    };
    let definition: ScopedTypeTag = definition_type_tag(&origin)?;
    let treasury: ScopedTypeTag = treasury_cap_type_tag(&origin, &config.definition_id)?;
    let coin: ScopedTypeTag = coin_type_tag(&origin, &config.definition_id)?;
    let (resource_domain, resource): (u16, [u8; 32]) = match coin.args() {
        [ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => return Err("Standard Asset Coin must carry one opaque resource".into()),
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource)?;
    let bond: BondResourceConfig = BondResourceConfig {
        resource_id,
        min_bond: Amount::new(config.economics.min_bond),
        enabled: true,
        unbonding_epochs: config.economics.unbonding_epochs,
        max_validator_exposure: config.economics.max_validator_exposure.map(Amount::new),
    };
    bond.validate()?;
    let mut supply: u64 = 0;
    for validator in validators {
        supply = supply
            .checked_add(validator.bond_amount)
            .ok_or("collateral supply overflow")?;
    }
    for allocation in allocations {
        supply = supply
            .checked_add(allocation.amount)
            .ok_or("allocation supply overflow")?;
    }
    let composer: ObjectComposer<'_> = ObjectComposer {
        context,
        resolver,
        instance: &instance,
        code: &code,
    };
    let mut objects: Vec<GenesisObjectEntry> =
        Vec::with_capacity(2 + validators.len() + allocations.len());
    objects.push(composer.entry(
        config.definition_id,
        Owner::Address(Address::new(config.authority)),
        definition,
        encode_call_value(&definition_body_layout(), &CallValue::Tuple(Vec::new()))?,
    )?);
    objects.push(composer.entry(
        config.treasury_cap_id,
        Owner::Address(Address::new(config.mint_authority)),
        treasury,
        encode_call_value(&treasury_cap_body_layout(), &CallValue::U64(supply))?,
    )?);
    for allocation in allocations {
        objects.push(composer.entry(
            allocation.coin_id,
            Owner::Address(Address::new(allocation.owner)),
            coin.clone(),
            encode_call_value(&coin_body_layout(), &CallValue::U64(allocation.amount))?,
        )?);
    }
    for validator in validators {
        let custody: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: context.chain_id().clone(),
            subject: *validator.id.as_bytes(),
            resource,
        };
        objects.push(composer.entry(
            validator.collateral_id,
            Owner::ProtocolCustody(custody),
            coin.clone(),
            encode_call_value(&coin_body_layout(), &CallValue::U64(validator.bond_amount))?,
        )?);
    }
    let mut decoded_supply: u64 = 0;
    for entry in &objects[2..] {
        decoded_supply = decoded_supply
            .checked_add(coin_amount(&entry.object.data)?)
            .ok_or("decoded supply overflow")?;
    }
    if decoded_supply != supply || treasury_supply(&objects[1].object.data)? != supply {
        return Err("allocation/collateral sum differs from TreasuryCap supply".into());
    }
    let fee_policy: PaidFeePolicy = PaidFeePolicy {
        context: context.clone(),
        base_policy_digest,
        instance: instance.clone(),
        code: code.clone(),
        reserve_entrypoint: "reserve".to_owned(),
        reserve_all_entrypoint: "reserve_all".to_owned(),
        settle_entrypoint: "settle".to_owned(),
        type_arguments: vec![asset_type_argument(&config.definition_id)],
        asset_type: coin.clone(),
        reservation_type: reservation_type_tag(&origin, &config.definition_id)?,
        schema: SCHEMA_VERSION,
        fee_recipient: config.fee_recipient,
        gas_schedule: config.economics.gas.clone(),
        conversion_divisor: config.economics.conversion_divisor,
        reserve_allowance: config.economics.reserve_allowance,
        settle_allowance: config.economics.settle_allowance,
        calls: PHASE_CALLS,
        handles: u32::try_from(PHASE_HANDLES)?,
        creations: PHASE_CREATIONS,
        events: u32::try_from(PHASE_EVENTS)?,
        memory_bytes: u64::try_from(PHASE_MEMORY_BYTES)?,
        output_bytes: u64::try_from(PHASE_OUTPUT_BYTES)?,
        publish_artifact_byte_price: config.economics.publish_artifact_byte_price,
        publish_closure_node_price: config.economics.publish_closure_node_price,
    };
    let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: context.clone(),
        resources: vec![FastPathEconomicsResourcePolicy {
            resource_id,
            context: context.clone(),
            instance,
            code,
            ty: coin,
            schema: SCHEMA_VERSION,
            split_entrypoint: "split".to_owned(),
            transfer_entrypoint: "transfer".to_owned(),
            bond: Some(bond),
            fee_escrow: true,
        }],
    };
    let entries: Vec<FastPathValidatorEntry> = validators
        .iter()
        .map(|validator: &Validator| FastPathValidatorEntry {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: validator.public_key.to_vec(),
        })
        .collect();
    let mut manifest: GenesisManifest = GenesisManifest {
        genesis_authority: config.authority,
        publication,
        initialization,
        fee_policy,
        economics_policy,
        objects,
        validator_set: FastPathValidatorSetRecord {
            context: context.clone(),
            validators: entries,
        },
        commitment_profile: CommitmentProfile::CausalAdmission,
        minimum_freeze_block_height: config.minimum_freeze_block_height,
        signature: [0; 64],
    };
    // The signed manifest embeds the final exact nested signatures.
    manifest.signature = key.sign(&genesis_manifest_signing_frame(&manifest)?).into();
    Ok(manifest)
}
