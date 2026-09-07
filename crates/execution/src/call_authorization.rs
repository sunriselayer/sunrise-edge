//! Signed ceilings for one general contract-call frame model (DR-0123).
//! These claims grant no durable authority until scopes and original inputs resolve.
use crate::call::{CallIntent, InstanceTarget, decode_instance_target, encode_instance_target};
use crate::local_execution::LocalExecutionError as Error;
use crate::publication::{UnverifiedDependencyRef, decode_dependency_ref, encode_dependency_ref};
use abi::package_types::{
    PackageOrigin, ScopedTypeArg, decode_scoped_type_arguments, encode_scoped_type_arguments,
};
use canonical_encoding::{CanonicalFrame, CanonicalStruct, decode_canonical_frame};
use objects::{AccessMode, ObjectId, decode_access_mode, encode_access_mode};
use std::collections::{BTreeMap, BTreeSet};

/// Invocation-wide signed authorization count.
pub const MAX_CALL_AUTHORIZATIONS: usize = 16;
/// Complete canonical authorization table including all framing.
pub const MAX_CALL_AUTHORIZATION_BYTES: usize = 64 * 1024;
/// Invocation-wide distinct immutable instance identities.
pub const MAX_EXECUTION_SCOPES: usize = 8;
/// Invocation-wide distinct original signed input objects.
pub const MAX_AUTHORIZED_INPUTS: usize = 32;
/// Globally deduplicated exact code nodes across every admitted scope.
pub const MAX_EXECUTION_CODE_NODES: usize = crate::publication::MAX_INTERFACE_NODES;
/// Aggregate complete publication bytes across all admitted scopes.
pub const MAX_EXECUTION_CODE_BYTES: usize = 16 * 1024 * 1024;

/// Exact code executing within one immutable instance scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionTarget {
    /// Exact independently verified instance target.
    pub instance: InstanceTarget,
    /// Exact code; scope admission must prove membership in the instance closure.
    pub code: UnverifiedDependencyRef,
}
/// Original signed input selector and maximum delegated right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedObject {
    /// Resolves only through the root signed access manifest, never a latest lookup.
    pub object_id: ObjectId,
    /// Maximum right; current caller rights and callee ABI further attenuate it.
    pub mode: AccessMode,
}
/// Reusable capability selected by guest code; never an automatically executed step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallAuthorization {
    /// Exact permitted calling frame.
    pub caller: ExecutionTarget,
    /// Exact selected execution frame.
    pub callee: ExecutionTarget,
    /// Committed callee export; initializer exclusion is part of frame admission.
    pub entrypoint: String,
    /// Ordered concrete generic arguments.
    pub type_arguments: Vec<ScopedTypeArg>,
    /// Ordered unique original input selectors.
    pub objects: Vec<AuthorizedObject>,
}
/// Encodes 0x640B/v1 (instance target, exact code reference).
pub fn encode_execution_target(target: &ExecutionTarget) -> Result<Vec<u8>, Error> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640B, 1);
    frame.field_bytes(1, encode_instance_target(&target.instance)?)?;
    frame.field_bytes(2, encode_dependency_ref(&target.code)?)?;
    Ok(frame.finish()?)
}
/// Strict bounded execution-target decoder.
pub fn decode_execution_target(bytes: &[u8]) -> Result<ExecutionTarget, Error> {
    let frame: CanonicalFrame<'_> = bounded_frame(bytes, 0x640B, &[1, 2])?;
    let target: ExecutionTarget = ExecutionTarget {
        instance: decode_instance_target(frame.required_field(1)?)?,
        code: decode_dependency_ref(frame.required_field(2)?)?,
    };
    if encode_execution_target(&target)? != bytes {
        return Err(Error::Invalid("noncanonical execution target"));
    }
    Ok(target)
}
fn bounded_frame<'a>(
    bytes: &'a [u8],
    id: u16,
    fields: &[u16],
) -> Result<CanonicalFrame<'a>, Error> {
    if bytes.len() > MAX_CALL_AUTHORIZATION_BYTES {
        return Err(Error::Limit("authorization bytes"));
    }
    let frame: CanonicalFrame<'a> = decode_canonical_frame(bytes)?;
    frame.require_type(id)?;
    frame.require_version(1)?;
    frame.require_only_fields(fields)?;
    Ok(frame)
}
/// Encodes 0x640C/v1 (object ID, canonical existing access mode).
pub fn encode_authorized_object(object: &AuthorizedObject) -> Result<Vec<u8>, Error> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640C, 1);
    frame.field_bytes(1, object.object_id.as_bytes().to_vec())?;
    frame.field_bytes(
        2,
        encode_access_mode(object.mode).map_err(|_| Error::Invalid("access mode"))?,
    )?;
    Ok(frame.finish()?)
}
/// Strict original-object selector decoder.
pub fn decode_authorized_object(bytes: &[u8]) -> Result<AuthorizedObject, Error> {
    let frame: CanonicalFrame<'_> = bounded_frame(bytes, 0x640C, &[1, 2])?;
    Ok(AuthorizedObject {
        object_id: ObjectId::try_from_slice(frame.required_field(1)?)
            .map_err(|_| Error::Invalid("object id"))?,
        mode: decode_access_mode(frame.required_field(2)?)
            .map_err(|_| Error::Invalid("access mode"))?,
    })
}
fn encode_objects(objects: &[AuthorizedObject]) -> Result<Vec<u8>, Error> {
    if objects.len() > MAX_AUTHORIZED_INPUTS {
        return Err(Error::Limit("authorization objects"));
    }
    let mut unique: BTreeSet<ObjectId> = BTreeSet::new();
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640D, 1);
    frame.field_u32(
        1,
        u32::try_from(objects.len()).map_err(|_| Error::Limit("objects"))?,
    )?;
    for (index, object) in objects.iter().enumerate() {
        if !unique.insert(object.object_id) {
            return Err(Error::Invalid("duplicate authorization object"));
        }
        frame.field_bytes(
            u16::try_from(index + 2).map_err(|_| Error::Limit("objects"))?,
            encode_authorized_object(object)?,
        )?;
    }
    Ok(frame.finish()?)
}
fn list_frame(bytes: &[u8], id: u16, max: usize) -> Result<(CanonicalFrame<'_>, usize), Error> {
    if bytes.len() > MAX_CALL_AUTHORIZATION_BYTES {
        return Err(Error::Limit("authorization bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(id)?;
    frame.require_version(1)?;
    let count: usize =
        usize::try_from(frame.required_u32(1)?).map_err(|_| Error::Limit("list count"))?;
    if count > max {
        return Err(Error::Limit("authorization count"));
    }
    let fields: Vec<u16> = (1..=count + 1)
        .map(|field| u16::try_from(field).map_err(|_| Error::Limit("list field")))
        .collect::<Result<Vec<u16>, Error>>()?;
    frame.require_only_fields(&fields)?;
    Ok((frame, count))
}
fn decode_objects(bytes: &[u8]) -> Result<Vec<AuthorizedObject>, Error> {
    let (frame, count) = list_frame(bytes, 0x640D, MAX_AUTHORIZED_INPUTS)?;
    let mut objects: Vec<AuthorizedObject> = Vec::with_capacity(count);
    for index in 0..count {
        objects.push(decode_authorized_object(frame.required_field(
            u16::try_from(index + 2).map_err(|_| Error::Limit("objects"))?,
        )?)?);
    }
    if encode_objects(&objects)? != bytes {
        return Err(Error::Invalid("noncanonical authorized objects"));
    }
    Ok(objects)
}
/// Encodes 0x640E/v1: caller, callee, entrypoint, type arguments, object ceilings.
pub fn encode_call_authorization(authorization: &CallAuthorization) -> Result<Vec<u8>, Error> {
    if authorization.entrypoint.is_empty()
        || authorization.entrypoint.len() > 64
        || authorization.caller.code.origin().chain_id()
            != authorization.callee.code.origin().chain_id()
    {
        return Err(Error::Invalid("authorization chain or entrypoint"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640E, 1);
    frame.field_bytes(1, encode_execution_target(&authorization.caller)?)?;
    frame.field_bytes(2, encode_execution_target(&authorization.callee)?)?;
    frame.field_str(3, &authorization.entrypoint)?;
    frame.field_bytes(
        4,
        encode_scoped_type_arguments(
            authorization.callee.code.origin().chain_id(),
            &authorization.type_arguments,
        )?,
    )?;
    frame.field_bytes(5, encode_objects(&authorization.objects)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_CALL_AUTHORIZATION_BYTES {
        return Err(Error::Limit("authorization bytes"));
    }
    Ok(bytes)
}
/// Strict single capability decoder; does not authenticate it.
pub fn decode_call_authorization(bytes: &[u8]) -> Result<CallAuthorization, Error> {
    let frame: CanonicalFrame<'_> = bounded_frame(bytes, 0x640E, &[1, 2, 3, 4, 5])?;
    let callee: ExecutionTarget = decode_execution_target(frame.required_field(2)?)?;
    let entrypoint: &str = frame.required_str(3)?;
    if entrypoint.len() > 64 {
        return Err(Error::Limit("entrypoint"));
    }
    let authorization: CallAuthorization = CallAuthorization {
        caller: decode_execution_target(frame.required_field(1)?)?,
        type_arguments: decode_scoped_type_arguments(
            callee.code.origin().chain_id(),
            frame.required_field(4)?,
        )?,
        callee,
        entrypoint: entrypoint.into(),
        objects: decode_objects(frame.required_field(5)?)?,
    };
    if encode_call_authorization(&authorization)? != bytes {
        return Err(Error::Invalid("noncanonical authorization"));
    }
    Ok(authorization)
}
/// Encodes bounded ordered capability table 0x640F/v1.
pub fn encode_call_authorizations(authorizations: &[CallAuthorization]) -> Result<Vec<u8>, Error> {
    if authorizations.len() > MAX_CALL_AUTHORIZATIONS {
        return Err(Error::Limit("authorizations"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640F, 1);
    frame.field_u32(
        1,
        u32::try_from(authorizations.len()).map_err(|_| Error::Limit("authorizations"))?,
    )?;
    let mut total: usize = 20;
    for (index, authorization) in authorizations.iter().enumerate() {
        let bytes: Vec<u8> = encode_call_authorization(authorization)?;
        total = total
            .checked_add(6)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or(Error::Limit("authorization bytes"))?;
        if total > MAX_CALL_AUTHORIZATION_BYTES {
            return Err(Error::Limit("authorization bytes"));
        }
        frame.field_bytes(
            u16::try_from(index + 2).map_err(|_| Error::Limit("authorizations"))?,
            bytes,
        )?;
    }
    Ok(frame.finish()?)
}
/// Decodes only after validating table and per-list allocation limits.
pub fn decode_call_authorizations(bytes: &[u8]) -> Result<Vec<CallAuthorization>, Error> {
    let (frame, count) = list_frame(bytes, 0x640F, MAX_CALL_AUTHORIZATIONS)?;
    let mut authorizations: Vec<CallAuthorization> = Vec::with_capacity(count);
    for index in 0..count {
        authorizations.push(decode_call_authorization(frame.required_field(
            u16::try_from(index + 2).map_err(|_| Error::Limit("authorizations"))?,
        )?)?);
    }
    if encode_call_authorizations(&authorizations)? != bytes {
        return Err(Error::Invalid("noncanonical authorizations"));
    }
    Ok(authorizations)
}
/// Checks signed selectors against the root manifest, without granting runtime rights.
pub fn validate_call_authorizations(
    call: &CallIntent,
    authorizations: &[CallAuthorization],
) -> Result<(), Error> {
    encode_call_authorizations(authorizations)?;
    if call.access.entries.len() > MAX_AUTHORIZED_INPUTS {
        return Err(Error::Limit("original inputs"));
    }
    let mut inputs: BTreeMap<ObjectId, AccessMode> = BTreeMap::new();
    for entry in &call.access.entries {
        if inputs.insert(entry.object_ref.id, entry.mode).is_some() {
            return Err(Error::Invalid("duplicate input"));
        }
    }
    let mut codes: BTreeMap<PackageOrigin, UnverifiedDependencyRef> = BTreeMap::new();
    let mut instances: BTreeMap<([u8; 32], [u8; 32]), InstanceTarget> = BTreeMap::new();
    let root: ExecutionTarget = ExecutionTarget {
        instance: call.instance.clone(),
        code: call.code.clone(),
    };
    for target in std::iter::once(&root).chain(
        authorizations
            .iter()
            .flat_map(|authorization| [&authorization.caller, &authorization.callee]),
    ) {
        if target.code.origin().chain_id() != call.context.chain_id() {
            return Err(Error::Invalid("authorization chain"));
        }
        if codes
            .insert(target.code.origin().clone(), target.code.clone())
            .is_some_and(|prior| prior != target.code)
        {
            return Err(Error::Invalid("conflicting code references"));
        }
        if instances
            .insert(
                (target.instance.creator, target.instance.seed),
                target.instance.clone(),
            )
            .is_some_and(|prior| prior != target.instance)
        {
            return Err(Error::Invalid("conflicting instance references"));
        }
    }
    if instances.len() > MAX_EXECUTION_SCOPES {
        return Err(Error::Limit("instance scopes"));
    }
    for authorization in authorizations {
        for object in &authorization.objects {
            let mode: AccessMode = *inputs
                .get(&object.object_id)
                .ok_or(Error::Invalid("undeclared authorization object"))?;
            if rank(object.mode) > rank(mode) {
                return Err(Error::Invalid("authorization rights escalation"));
            }
        }
    }
    Ok(())
}
fn rank(mode: AccessMode) -> u8 {
    match mode {
        AccessMode::Read => 0,
        AccessMode::Write => 1,
        AccessMode::Consume => 2,
    }
}
