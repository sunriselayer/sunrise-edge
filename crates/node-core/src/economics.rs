//! DR-0137 signed FastVote economics policy codecs.
//!
//! These types pin public-contract authority and permitted custody operations.
//! They grant no execution or storage authority by themselves.

use abi::package_types::{
    ScopedTypeArg, ScopedTypeTag, decode_scoped_type_tag, encode_scoped_type_tag,
};
use bonds::{
    BondResourceConfig, BondResourceId, decode_bond_resource_config, decode_bond_resource_id,
    encode_bond_resource_config, encode_bond_resource_id,
};
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use execution::call::{InstanceTarget, decode_instance_target, encode_instance_target};
use execution::publication::{
    PublicationContext, UnverifiedDependencyRef, decode_dependency_ref, decode_publication_context,
    encode_dependency_ref, encode_publication_context,
};

use crate::NodeCoreError;

const FASTPATH_ECONOMICS_RESOURCE_POLICY_TYPE: u16 = 0x642B;
const FASTPATH_ECONOMICS_POLICY_TYPE: u16 = 0x642C;
const ENCODING_VERSION: u16 = 1;
const BOND_ENABLED_FLAG: u16 = 1 << 0;
const FEE_ESCROW_ENABLED_FLAG: u16 = 1 << 1;
const KNOWN_FLAGS: u16 = BOND_ENABLED_FLAG | FEE_ESCROW_ENABLED_FLAG;
const MAX_ECONOMICS_RESOURCES: usize = 64;
const MAX_ENTRYPOINT_BYTES: usize = 256;
/// Maximum canonical size of a signed economics policy.
pub const MAX_FASTPATH_ECONOMICS_POLICY_BYTES: usize =
    MAX_ECONOMICS_RESOURCES * (abi::package_types::MAX_SCOPED_TYPE_BYTES + 4096);

/// One exact public-contract resource admitted for protocol economics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEconomicsResourcePolicy {
    /// Opaque resource identity carried by the nominal type.
    pub resource_id: BondResourceId,
    /// Exact publication context of the defining instance.
    pub context: PublicationContext,
    /// Exact instance authorization target.
    pub instance: InstanceTarget,
    /// Exact defining code revision.
    pub code: UnverifiedDependencyRef,
    /// Complete nominal type with `resource_id` as its sole opaque argument.
    pub ty: ScopedTypeTag,
    /// Non-zero object schema committed by the executable ABI.
    pub schema: u32,
    /// Public entrypoint used for a conserving partial release.
    pub split_entrypoint: String,
    /// Public entrypoint used for a conserving full owner transition.
    pub transfer_entrypoint: String,
    /// Bond admission/lifecycle policy, absent when this resource is fee-only.
    pub bond: Option<BondResourceConfig>,
    /// Whether certified fee outputs of this resource may enter fee escrow.
    pub fee_escrow: bool,
}

/// Complete signed economics policy for one publication context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathEconomicsPolicy {
    /// Chain/protocol/epoch replay boundary.
    pub context: PublicationContext,
    /// Strictly resource-ordered policy entries.
    pub resources: Vec<FastPathEconomicsResourcePolicy>,
}

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

fn validate_entrypoint(name: &str) -> Result<(), NodeCoreError> {
    if name.is_empty() || name.len() > MAX_ENTRYPOINT_BYTES || name == "memory" {
        return Err(invalid("invalid economics entrypoint"));
    }
    Ok(())
}

fn validate_resource_policy(policy: &FastPathEconomicsResourcePolicy) -> Result<(), NodeCoreError> {
    validate_entrypoint(&policy.split_entrypoint)?;
    validate_entrypoint(&policy.transfer_entrypoint)?;
    if policy.split_entrypoint == policy.transfer_entrypoint {
        return Err(invalid("economics entrypoints must be distinct"));
    }
    if policy.schema == 0 {
        return Err(invalid("economics resource schema must be nonzero"));
    }
    if policy.context != *policy.code.context()
        || policy.context.chain_id() != policy.code.origin().chain_id()
        || policy.ty.origin() != policy.code.origin()
    {
        return Err(invalid("economics resource authority mismatch"));
    }
    let type_resource_matches: bool = matches!(
        policy.ty.args(),
        [ScopedTypeArg::Opaque { domain, value }]
            if *domain == policy.resource_id.domain()
                && value == policy.resource_id.value()
    );
    if !type_resource_matches {
        return Err(invalid("economics resource does not match nominal type"));
    }
    if let Some(bond) = &policy.bond {
        bond.validate()
            .map_err(|_| invalid("invalid economics bond policy"))?;
        if bond.resource_id != policy.resource_id {
            return Err(invalid("economics bond resource mismatch"));
        }
    }
    if policy.bond.is_none() && !policy.fee_escrow {
        return Err(invalid("economics resource has no enabled purpose"));
    }
    Ok(())
}

fn policy_flags(policy: &FastPathEconomicsResourcePolicy) -> u16 {
    let mut flags: u16 = 0;
    if policy.bond.is_some() {
        flags |= BOND_ENABLED_FLAG;
    }
    if policy.fee_escrow {
        flags |= FEE_ESCROW_ENABLED_FLAG;
    }
    flags
}

/// Encodes frame `0x642B/v1`.
pub fn encode_fastpath_economics_resource_policy(
    policy: &FastPathEconomicsResourcePolicy,
) -> Result<Vec<u8>, NodeCoreError> {
    validate_resource_policy(policy)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_ECONOMICS_RESOURCE_POLICY_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_bond_resource_id(policy.resource_id)
            .map_err(|_| invalid("invalid economics resource id"))?,
    )?;
    frame.field_bytes(
        2,
        encode_publication_context(&policy.context)
            .map_err(|_| invalid("invalid economics context"))?,
    )?;
    frame.field_bytes(
        3,
        encode_instance_target(&policy.instance)
            .map_err(|_| invalid("invalid economics instance"))?,
    )?;
    frame.field_bytes(
        4,
        encode_dependency_ref(&policy.code)
            .map_err(|_| invalid("invalid economics code reference"))?,
    )?;
    frame.field_bytes(
        5,
        encode_scoped_type_tag(&policy.ty)
            .map_err(|_| invalid("invalid economics resource type"))?,
    )?;
    frame.field_u32(6, policy.schema)?;
    frame.field_str(7, &policy.split_entrypoint)?;
    frame.field_str(8, &policy.transfer_entrypoint)?;
    frame.field_u16(9, policy_flags(policy))?;
    if let Some(bond) = &policy.bond {
        frame.field_bytes(
            10,
            encode_bond_resource_config(bond)
                .map_err(|_| invalid("invalid economics bond policy"))?,
        )?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x642B/v1`.
pub fn decode_fastpath_economics_resource_policy(
    bytes: &[u8],
) -> Result<FastPathEconomicsResourcePolicy, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_ECONOMICS_RESOURCE_POLICY_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let flags: u16 = frame.required_u16(9)?;
    if flags == 0 || flags & !KNOWN_FLAGS != 0 {
        return Err(invalid("invalid economics resource flags"));
    }
    let bond_enabled: bool = flags & BOND_ENABLED_FLAG != 0;
    if bond_enabled {
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    } else {
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    }
    let policy: FastPathEconomicsResourcePolicy = FastPathEconomicsResourcePolicy {
        resource_id: decode_bond_resource_id(frame.required_field(1)?)
            .map_err(|_| invalid("invalid economics resource id"))?,
        context: decode_publication_context(frame.required_field(2)?)
            .map_err(|_| invalid("invalid economics context"))?,
        instance: decode_instance_target(frame.required_field(3)?)
            .map_err(|_| invalid("invalid economics instance"))?,
        code: decode_dependency_ref(frame.required_field(4)?)
            .map_err(|_| invalid("invalid economics code reference"))?,
        ty: decode_scoped_type_tag(frame.required_field(5)?)
            .map_err(|_| invalid("invalid economics resource type"))?,
        schema: frame.required_u32(6)?,
        split_entrypoint: frame.required_str(7)?.to_owned(),
        transfer_entrypoint: frame.required_str(8)?.to_owned(),
        bond: if bond_enabled {
            Some(
                decode_bond_resource_config(frame.required_field(10)?)
                    .map_err(|_| invalid("invalid economics bond policy"))?,
            )
        } else {
            None
        },
        fee_escrow: flags & FEE_ESCROW_ENABLED_FLAG != 0,
    };
    if encode_fastpath_economics_resource_policy(&policy)? != bytes {
        return Err(invalid("noncanonical economics resource policy"));
    }
    Ok(policy)
}

fn validate_policy(policy: &FastPathEconomicsPolicy) -> Result<(), NodeCoreError> {
    if policy.resources.len() > MAX_ECONOMICS_RESOURCES {
        return Err(invalid("too many economics resources"));
    }
    let mut previous: Option<BondResourceId> = None;
    for resource in &policy.resources {
        validate_resource_policy(resource)?;
        if resource.context != policy.context {
            return Err(invalid("economics resource context mismatch"));
        }
        if previous.is_some_and(|id: BondResourceId| id >= resource.resource_id) {
            return Err(invalid("economics resources must be strictly ordered"));
        }
        previous = Some(resource.resource_id);
    }
    Ok(())
}

/// Encodes frame `0x642C/v1`.
pub fn encode_fastpath_economics_policy(
    policy: &FastPathEconomicsPolicy,
) -> Result<Vec<u8>, NodeCoreError> {
    validate_policy(policy)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_ECONOMICS_POLICY_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&policy.context)
            .map_err(|_| invalid("invalid economics context"))?,
    )?;
    let count: u32 = u32::try_from(policy.resources.len())
        .map_err(|_| invalid("too many economics resources"))?;
    frame.field_u32(2, count)?;
    for (index, resource) in policy.resources.iter().enumerate() {
        let field_id: u16 =
            u16::try_from(index + 3).map_err(|_| invalid("economics resource field overflow"))?;
        frame.field_bytes(
            field_id,
            encode_fastpath_economics_resource_policy(resource)?,
        )?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_FASTPATH_ECONOMICS_POLICY_BYTES {
        return Err(invalid("economics policy exceeds maximum bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes frame `0x642C/v1`.
pub fn decode_fastpath_economics_policy(
    bytes: &[u8],
) -> Result<FastPathEconomicsPolicy, NodeCoreError> {
    if bytes.len() > MAX_FASTPATH_ECONOMICS_POLICY_BYTES {
        return Err(invalid("economics policy exceeds maximum bytes"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_ECONOMICS_POLICY_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let count: usize = frame.required_u32(2)? as usize;
    if count > MAX_ECONOMICS_RESOURCES {
        return Err(invalid("too many economics resources"));
    }
    let mut fields: Vec<u16> = Vec::with_capacity(count + 2);
    fields.push(1);
    fields.push(2);
    let mut resources: Vec<FastPathEconomicsResourcePolicy> = Vec::with_capacity(count);
    for index in 0..count {
        let field_id: u16 =
            u16::try_from(index + 3).map_err(|_| invalid("economics resource field overflow"))?;
        fields.push(field_id);
        resources.push(decode_fastpath_economics_resource_policy(
            frame.required_field(field_id)?,
        )?);
    }
    frame.require_only_fields(&fields)?;
    let policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("invalid economics context"))?,
        resources,
    };
    if encode_fastpath_economics_policy(&policy)? != bytes {
        return Err(invalid("noncanonical economics policy"));
    }
    Ok(policy)
}

#[cfg(test)]
mod tests;
