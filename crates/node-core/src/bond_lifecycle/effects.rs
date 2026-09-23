//! Generic, contract-produced whole-object custody-effect validation.
//!
//! [`validate`] knows nothing about which contract produced `effects`; it
//! checks only the exact object-effect shape DR-0137 requires for a
//! whole-object custody transfer (deposit or release), and observes value
//! solely through the signed executable ABI
//! ([`execution::publication::observe_nominal_value`]). It grants no
//! authority of its own: the caller has already constructed and bound one
//! [`execution::protocol_custody::ProtocolCustodyCapability`] from committed
//! economics policy before `effects` could exist at all.
use super::*;
use abi::call_values::CallValue;
use execution::ObjectEffect;
use execution::local_execution::ObjectAuthority;
use execution::publication::VerifiedPublicationInterface;

/// One exact whole-object custody transition a leg's effects must match.
pub(super) struct ExpectedCustodyTransfer<'a> {
    pub(super) object_id: ObjectId,
    pub(super) owner_before: &'a Owner,
    pub(super) owner_after: &'a Owner,
}

/// Checks every DR-0137 "generic custody execution" invariant and returns
/// the validated resulting object and its conserved positive `u64` value.
/// Rejects a trap, any event, any effect count other than exactly one, any
/// effect other than `Mutated`, any identity/version/type/schema/body change
/// beyond the exact expected owner transition, and any non-positive or
/// non-conserved value.
pub(super) fn validate(
    interface: &VerifiedPublicationInterface,
    authority: &ObjectAuthority,
    expected: &ExpectedCustodyTransfer<'_>,
    checkpoint: u64,
    snapshot: &object_snapshots::ObjectSnapshot,
    effects: &ExecutionEffects,
) -> Result<(Object, u64), BondLifecycleError> {
    if effects.status != ExecutionStatus::Success {
        return Err(BondLifecycleError::Invalid("custody leg trapped"));
    }
    if !effects.events.is_empty() {
        return Err(BondLifecycleError::Invalid("custody leg emitted an event"));
    }
    let [
        ObjectEffect::Mutated {
            previous_version,
            new_object,
        },
    ] = effects.object_effects.as_slice()
    else {
        return Err(BondLifecycleError::Invalid(
            "custody leg must produce exactly one whole-object mutation",
        ));
    };
    if snapshot.object.id != expected.object_id
        || new_object.id != expected.object_id
        || *previous_version != snapshot.object.version
        || new_object.version
            != previous_version
                .checked_add(1)
                .ok_or(BondLifecycleError::Invalid(
                    "custody object version overflow",
                ))?
        || new_object.type_hash != snapshot.object.type_hash
        || new_object.schema_version != snapshot.object.schema_version
        || new_object.data != snapshot.object.data
        || checkpoint < snapshot.created_checkpoint
    {
        return Err(BondLifecycleError::Invalid(
            "custody leg effect identity, version, type, schema or body changed",
        ));
    }
    if &snapshot.object.owner != expected.owner_before {
        return Err(BondLifecycleError::Invalid(
            "custody leg observed owner does not match the expected precondition",
        ));
    }
    if &new_object.owner != expected.owner_after {
        return Err(BondLifecycleError::Invalid(
            "custody leg did not produce the exact expected owner transition",
        ));
    }
    let before: CallValue = execution::publication::observe_nominal_value(
        interface,
        &authority.ty,
        snapshot.object.schema_version,
        &snapshot.object.data,
    )
    .map_err(|_| BondLifecycleError::Invalid("custody value observation"))?;
    let after: CallValue = execution::publication::observe_nominal_value(
        interface,
        &authority.ty,
        new_object.schema_version,
        &new_object.data,
    )
    .map_err(|_| BondLifecycleError::Invalid("custody value observation"))?;
    let amount: u64 = match (before, after) {
        (CallValue::U64(before), CallValue::U64(after)) if before > 0 && before == after => before,
        _ => {
            return Err(BondLifecycleError::Invalid(
                "custody value must be a positive, conserved u64",
            ));
        }
    };
    Ok((new_object.clone(), amount))
}

/// Builds the durable object-head mutation for one validated custody
/// transfer, reusing the exact digest/provenance/projection construction
/// ordinary local-execution effect translation uses.
pub(super) fn build_mutation_entry(
    resolver: &HashSuiteResolver,
    current_context: &PublicationContext,
    checkpoint: u64,
    snapshot: &object_snapshots::ObjectSnapshot,
    new_object: &Object,
) -> Result<(DurableObjectMutationEntry, Digest32), BondLifecycleError> {
    let canonical: Vec<u8> = objects::encode_object(new_object)
        .map_err(|_| BondLifecycleError::Invalid("invalid custody output encoding"))?;
    if canonical.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(BondLifecycleError::Invalid("custody output body limit"));
    }
    let digest: Digest32 =
        resolver.hash_for_purpose(current_context.epoch(), HashPurpose::Object, &canonical)?;
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        new_object.clone(),
        digest,
        runtime::DurableObjectProvenance::new(
            current_context.chain_id().clone(),
            current_context.protocol_version(),
        ),
        checkpoint,
    )?;
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(new_object.owner.clone())?;
    let routing_projection = match &snapshot.head {
        DurableObjectHead::Current {
            routing_projection, ..
        } => routing_projection.clone(),
        _ => return Err(BondLifecycleError::Invalid("custody input not live")),
    };
    Ok((
        DurableObjectMutationEntry::new(
            new_object.id,
            DurableObjectMutation::Update {
                version,
                owner_projection,
                routing_projection,
            },
        ),
        digest,
    ))
}
