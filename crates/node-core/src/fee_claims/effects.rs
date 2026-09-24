//! Independent fee-claim effect validation.
//!
//! [`validate`] knows nothing about which contract produced `effects`; it
//! checks only the exact object-effect shape DR-0137 "certified fee escrow
//! and claims" requires for one positive fee claim (`split` or `transfer`),
//! and observes value solely through the signed executable ABI
//! ([`execution::publication::observe_nominal_value`]). It grants no
//! authority of its own: the caller has already constructed and bound one
//! [`execution::protocol_custody::ProtocolCustodyCapability`] (`FeeClaim`
//! direction) from the committed economics policy and the settlement row's
//! own bookkeeping before `effects` could exist at all, and the generic
//! [`crate::local_execution::admit_and_execute_leg`] translator (invoked in
//! [`crate::local_execution::CustodyEffectMode::Translate`] mode) has
//! already independently checked every output's owner address validity,
//! declared ABI type/schema and durable persistence. This module adds the
//! fee-claim-specific invariants that generic translation does not know to
//! enforce on its own: the exact effect count/shape per operation, that a
//! split's created output carries the exact pinned fee-resource identity
//! (not merely some other type the same code happens to also define), the
//! exact recipient, and `u64` value conservation against the settlement
//! row's own currently unclaimed positive share total.
use super::*;
use abi::package_types::ScopedTypeTag;
use execution::ObjectEffect;
use execution::local_execution::{CreatedObjectAuthority, ObjectAuthority};
use execution::publication::VerifiedPublicationInterface;

#[cfg(test)]
mod tests;

/// One exact fee-claim transfer a leg's effects must match.
pub(super) struct ExpectedFeeClaim<'a> {
    /// Exact current `FeeEscrow` object the settlement row carries.
    pub(super) escrow_id: ObjectId,
    /// Exact current fee-escrow custody scope.
    pub(super) escrow_scope: &'a ProtocolCustodyScope,
    /// The escrow input's own independently checked host authority --
    /// already pinned to the committed economics resource's exact
    /// instance/code/type by [`execution::protocol_custody::ProtocolCustodyCapability::bind`].
    pub(super) resource_authority: &'a ObjectAuthority,
    /// Exact claimant-signed recipient.
    pub(super) recipient: Address,
    /// Sum of every currently unclaimed positive share in the row,
    /// including this claim's own.
    pub(super) unclaimed_before: u64,
    /// Exact signed amount this claim releases.
    pub(super) claim_amount: u64,
}

/// The validated resulting object: the retained (still custody-owned)
/// remainder for a partial claim, or the fully transferred (now
/// recipient-owned) object for the final claim.
pub(super) enum ValidatedFeeClaim {
    Split { retained: Object },
    Final { transferred: Object },
}

fn observe(
    interface: &VerifiedPublicationInterface,
    ty: &ScopedTypeTag,
    schema_version: u32,
    data: &[u8],
) -> Result<u64, FeeClaimError> {
    match execution::publication::observe_nominal_value(interface, ty, schema_version, data)
        .map_err(|_| FeeClaimError::Invalid("fee claim value observation"))?
    {
        abi::call_values::CallValue::U64(value) => Ok(value),
        _ => Err(FeeClaimError::Invalid("fee claim value must be u64")),
    }
}

/// Checks the shared whole-object mutation shape (identity, monotonic
/// version, unchanged nominal type, checkpoint monotonicity) every fee-claim
/// mutation of the escrow object must satisfy, regardless of which owner
/// transition follows.
fn check_mutation_shape(
    escrow_id: ObjectId,
    previous_version: u64,
    new_object: &Object,
    snapshot: &object_snapshots::ObjectSnapshot,
    checkpoint: u64,
) -> Result<(), FeeClaimError> {
    if new_object.id != escrow_id || previous_version != snapshot.object.version {
        return Err(FeeClaimError::Invalid(
            "fee claim mutation does not target the exact escrow object",
        ));
    }
    let next_version: u64 = previous_version
        .checked_add(1)
        .ok_or(FeeClaimError::Invalid("fee claim object version overflow"))?;
    if new_object.version != next_version
        || new_object.type_hash != snapshot.object.type_hash
        || checkpoint < snapshot.created_checkpoint
    {
        return Err(FeeClaimError::Invalid(
            "fee claim mutation identity, version or type changed",
        ));
    }
    Ok(())
}

/// Checks every DR-0137 fee-claim invariant and returns the validated
/// resulting object. Rejects a trap, any event, any effect shape other than
/// exactly what the derived operation requires, any output whose owner is
/// not the exact expected transition, any created output whose resource
/// identity does not match the escrow's own pinned resource, and any
/// non-conserved or non-positive value.
pub(super) fn validate(
    interface: &VerifiedPublicationInterface,
    created_authorities: &[CreatedObjectAuthority],
    expected: &ExpectedFeeClaim<'_>,
    checkpoint: u64,
    snapshot: &object_snapshots::ObjectSnapshot,
    effects: &ExecutionEffects,
    is_final: bool,
) -> Result<ValidatedFeeClaim, FeeClaimError> {
    if effects.status != ExecutionStatus::Success {
        return Err(FeeClaimError::Invalid("fee claim leg trapped"));
    }
    if !effects.events.is_empty() {
        return Err(FeeClaimError::Invalid("fee claim leg emitted an event"));
    }
    if snapshot.object.id != expected.escrow_id
        || snapshot.object.owner != Owner::ProtocolCustody(expected.escrow_scope.clone())
        || checkpoint < snapshot.created_checkpoint
    {
        return Err(FeeClaimError::Invalid("fee claim escrow precondition"));
    }
    let before: u64 = observe(
        interface,
        &expected.resource_authority.ty,
        snapshot.object.schema_version,
        &snapshot.object.data,
    )?;
    if before == 0 || before != expected.unclaimed_before {
        return Err(FeeClaimError::Invalid(
            "fee claim escrow value does not equal the unclaimed positive share total",
        ));
    }
    if expected.claim_amount == 0 || expected.claim_amount > before {
        return Err(FeeClaimError::Invalid("fee claim amount"));
    }

    if is_final {
        if !created_authorities.is_empty() {
            return Err(FeeClaimError::Invalid(
                "final fee claim must not create an object",
            ));
        }
        let [
            ObjectEffect::Mutated {
                previous_version,
                new_object,
            },
        ] = effects.object_effects.as_slice()
        else {
            return Err(FeeClaimError::Invalid(
                "final fee claim must produce exactly one whole-object mutation",
            ));
        };
        check_mutation_shape(
            expected.escrow_id,
            *previous_version,
            new_object,
            snapshot,
            checkpoint,
        )?;
        if new_object.owner != Owner::Address(expected.recipient) {
            return Err(FeeClaimError::Invalid("final fee claim owner mismatch"));
        }
        let after: u64 = observe(
            interface,
            &expected.resource_authority.ty,
            new_object.schema_version,
            &new_object.data,
        )?;
        if after != before || expected.claim_amount != before {
            return Err(FeeClaimError::Invalid(
                "final fee claim does not conserve or exhaust the unclaimed total",
            ));
        }
        Ok(ValidatedFeeClaim::Final {
            transferred: new_object.clone(),
        })
    } else {
        let [first, second] = effects.object_effects.as_slice() else {
            return Err(FeeClaimError::Invalid(
                "split fee claim must produce exactly one mutation and one creation",
            ));
        };
        let (previous_version, retained, created_object) = match (first, second) {
            (
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                },
                ObjectEffect::Created(created_object),
            )
            | (
                ObjectEffect::Created(created_object),
                ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                },
            ) => (*previous_version, new_object, created_object),
            _ => {
                return Err(FeeClaimError::Invalid(
                    "split fee claim must produce exactly one mutation and one creation",
                ));
            }
        };
        check_mutation_shape(
            expected.escrow_id,
            previous_version,
            retained,
            snapshot,
            checkpoint,
        )?;
        if retained.owner != Owner::ProtocolCustody(expected.escrow_scope.clone()) {
            return Err(FeeClaimError::Invalid(
                "split fee claim retained owner mismatch",
            ));
        }
        if created_object.owner != Owner::Address(expected.recipient) {
            return Err(FeeClaimError::Invalid(
                "split fee claim released owner mismatch",
            ));
        }
        // The newly created nominal-type fingerprint is checked by generic
        // translation under the current hash suite. It need not equal the
        // old escrow object's fingerprint after a hash-suite rotation.
        if created_object.version != 1
            || created_object.schema_version != snapshot.object.schema_version
        {
            return Err(FeeClaimError::Invalid(
                "split fee claim created object identity",
            ));
        }
        let [created_authority] = created_authorities else {
            return Err(FeeClaimError::Invalid(
                "split fee claim creation authority count",
            ));
        };
        if created_authority.authority.object_id != created_object.id
            || created_authority.authority.ty != expected.resource_authority.ty
            || created_authority.authority.instance != expected.resource_authority.instance
            || created_authority.authority.code != expected.resource_authority.code
        {
            return Err(FeeClaimError::Invalid(
                "split fee claim created output resource identity",
            ));
        }
        let retained_after: u64 = observe(
            interface,
            &expected.resource_authority.ty,
            retained.schema_version,
            &retained.data,
        )?;
        let released: u64 = observe(
            interface,
            &expected.resource_authority.ty,
            created_object.schema_version,
            &created_object.data,
        )?;
        if released == 0 || released != expected.claim_amount || retained_after == 0 {
            return Err(FeeClaimError::Invalid(
                "split fee claim released amount mismatch",
            ));
        }
        let sum: u64 = retained_after
            .checked_add(released)
            .ok_or(FeeClaimError::Invalid("split fee claim value overflow"))?;
        if sum != before {
            return Err(FeeClaimError::Invalid(
                "split fee claim does not conserve the unclaimed total",
            ));
        }
        Ok(ValidatedFeeClaim::Split {
            retained: retained.clone(),
        })
    }
}
