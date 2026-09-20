//! DR-0126 installed fee ABI/role admission.
//!
//! [`validate_fee_interface_admission`] is the reusable proof that one
//! [`VerifiedPublicationInterface`]'s exact declared `reserve`,
//! `reserve_all` and `settle` exports match one [`PaidFeePolicy`]'s pinned
//! roles, independent of any specific fee package (it names Standard Asset
//! nowhere; it reads only the policy's own pinned entrypoint names, asset
//! and reservation types and schema). This closes the gap `PaidFeePolicy`'s
//! intrinsic wire validation ([`super::validate_paid_fee_policy`], via
//! [`super::encode_paid_fee_policy`]/[`super::decode_paid_fee_policy`])
//! explicitly leaves open: intrinsic decoding proves the policy bytes are
//! self-consistent, never that the installed contract's actual ABI still
//! matches those pinned roles.
//!
//! Proves, against the exact resolved [`abi::public_abi::ObjectParameter`]/
//! [`abi::public_abi::ObjectResultDeclaration`] shapes bound at the policy's
//! own pinned `type_arguments`:
//!
//! - `reserve`: one required `Write` object of the policy's asset type, one
//!   required `Consume` result of the policy's reservation type, and the
//!   fixed DR-0124 five-field reserve argument layout;
//! - `reserve_all`: the same result and argument shape, but a required
//!   `Consume` object;
//! - `settle`: one required `Consume` object of the policy's reservation
//!   type, a required `Read` result of the asset type in slot zero, an
//!   optional `Read` result of the asset type in slot one, exactly two
//!   result slots, and the fixed DR-0124 three-field settle argument layout;
//! - the reservation type is absent from `transferable_constructors` for
//!   its defining origin; and
//! - no *other entrypoint of the fee package interface selected by
//!   `policy.code.origin()`* than the pinned `settle` export declares an
//!   object parameter of the reservation type. This is scoped to that one
//!   package's own declared entrypoints, not its transitive dependency
//!   closure; see [`validate_no_other_reservation_consumer`] for why no
//!   other origin can declare that exact reservation constructor anyway.
//!
//! A mismatch anywhere here is [`PaidExecutionError::Invalid`] or
//! [`PaidExecutionError::Binding`]; nothing here decodes an asset amount or
//! Coin/Reservation body.
use abi::call_values::ValueLayout;
use abi::package_types::ScopedTypeTag;
use abi::public_abi::ObjectMode;

use crate::publication::{
    BoundObjectSignature, VerifiedPublicationInterface, bind_object_signature,
};

use super::{PaidExecutionError, PaidFeePolicy};

/// Encoded byte length of one self-describing `Digest32` under the current
/// canonical encoding: a 10-byte `CanonicalStruct` header (magic, type,
/// version, field count) plus an 8-byte algorithm-id field (2+4+2) and a
/// 38-byte digest-bytes field (2+4+32). This is a fixed protocol shape, not
/// a Standard-Asset-specific choice, and is deliberately not imported from
/// `public-standard-asset`: this validator must stay usable for any
/// conforming fee contract.
const ENCODED_DIGEST32_BYTES: u32 = 56;
const RECIPIENT_BYTES: u32 = 32;

fn digest32_layout() -> ValueLayout {
    ValueLayout::Bytes {
        min_len: ENCODED_DIGEST32_BYTES,
        max_len: ENCODED_DIGEST32_BYTES,
    }
}
fn recipient_layout() -> ValueLayout {
    ValueLayout::Bytes {
        min_len: RECIPIENT_BYTES,
        max_len: RECIPIENT_BYTES,
    }
}

/// DR-0124's fixed `reserve`/`reserve_all` argument layout: reserved `u64`
/// units, the encoded invocation digest, the encoded fee-policy digest, the
/// fee recipient and the refund recipient. Identical to the `Reservation`
/// body layout so the stored commitment is the exact signed tuple.
fn reserve_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![
        ValueLayout::U64,
        digest32_layout(),
        digest32_layout(),
        recipient_layout(),
        recipient_layout(),
    ])
}

/// DR-0124's fixed `settle` argument layout: actual `u64` units, the
/// encoded invocation digest and the encoded fee-policy digest.
fn settle_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![ValueLayout::U64, digest32_layout(), digest32_layout()])
}

fn invalid(message: &'static str) -> PaidExecutionError {
    PaidExecutionError::Invalid(message)
}

/// Proves `entrypoint` declares exactly one required object of `object_mode`
/// and `object_type`, exactly one required result of `Consume` mode and
/// `result_type`, and the fixed reserve/reserve_all argument layout.
fn validate_reserve_shaped_export(
    interface: &VerifiedPublicationInterface,
    policy: &PaidFeePolicy,
    entrypoint: &str,
    object_mode: ObjectMode,
) -> Result<(), PaidExecutionError> {
    let bound: BoundObjectSignature<'_> =
        bind_object_signature(interface, entrypoint, &policy.type_arguments)?;
    let [object] = bound.objects() else {
        return Err(invalid("reserve-shaped export object arity"));
    };
    if object.mode() != object_mode
        || object.schema() != policy.schema
        || object.ty() != &policy.asset_type
    {
        return Err(invalid("reserve-shaped export object role"));
    }
    let [result] = bound.results() else {
        return Err(invalid("reserve-shaped export result arity"));
    };
    if result.mode() != ObjectMode::Consume
        || result.schema() != policy.schema
        || result.ty() != &policy.reservation_type
        || result.optional()
    {
        return Err(invalid("reserve-shaped export result role"));
    }
    if bound.argument_layout() != &reserve_argument_layout() {
        return Err(invalid("reserve-shaped export argument layout"));
    }
    Ok(())
}

/// Proves `settle` declares exactly one required `Consume` object of the
/// reservation type, exactly two result slots (a required fee slot zero and
/// an optional refund slot one, both `Read` of the asset type), and the
/// fixed settle argument layout.
fn validate_settle_export(
    interface: &VerifiedPublicationInterface,
    policy: &PaidFeePolicy,
) -> Result<(), PaidExecutionError> {
    let bound: BoundObjectSignature<'_> =
        bind_object_signature(interface, &policy.settle_entrypoint, &policy.type_arguments)?;
    let [object] = bound.objects() else {
        return Err(invalid("settle export object arity"));
    };
    if object.mode() != ObjectMode::Consume
        || object.schema() != policy.schema
        || object.ty() != &policy.reservation_type
    {
        return Err(invalid("settle export object role"));
    }
    let [fee, refund] = bound.results() else {
        return Err(invalid("settle export result arity"));
    };
    if fee.mode() != ObjectMode::Read
        || fee.schema() != policy.schema
        || fee.ty() != &policy.asset_type
        || fee.optional()
    {
        return Err(invalid("settle export fee result role"));
    }
    if refund.mode() != ObjectMode::Read
        || refund.schema() != policy.schema
        || refund.ty() != &policy.asset_type
        || !refund.optional()
    {
        return Err(invalid("settle export refund result role"));
    }
    if bound.argument_layout() != &settle_argument_layout() {
        return Err(invalid("settle export argument layout"));
    }
    Ok(())
}

/// Proves the reservation type is not in `transferable_constructors` for its
/// defining origin: a manually acquired `Reservation` handle must never be
/// transferable to another owner.
fn validate_reservation_non_transferable(
    interface: &VerifiedPublicationInterface,
    reservation_type: &ScopedTypeTag,
) -> Result<(), PaidExecutionError> {
    let executable = interface
        .executable_abi(reservation_type.origin())
        .ok_or(invalid("reservation defining executable ABI absent"))?;
    if executable
        .transferable_constructors
        .contains(&reservation_type.constructor())
    {
        return Err(invalid("reservation type is transferable"));
    }
    Ok(())
}

/// Proves no entrypoint *of the fee package interface selected by
/// `policy.code.origin()`* other than the pinned `settle` export declares an
/// object parameter whose nominal pattern names the reservation type's
/// `(origin, constructor)`. `interface.abi()` is already rooted at exactly
/// that origin (see [`validate_fee_interface_admission`]), so this walks
/// only the fee package's own declared entrypoints, never any entrypoint of
/// a *different* origin in its dependency closure: the reservation type is
/// required to originate from `policy.code` itself
/// (`super::validate_paid_fee_policy`'s intrinsic check), so no other origin
/// could declare a constructor with that exact `(origin, constructor)` pair
/// in the first place, and this function does not attempt to prove that
/// independently. This is a structural pattern check, not a substitution:
/// every declared object parameter pattern names its constructor directly
/// regardless of any generic type argument, so no instantiation is required
/// to rule out an undeclared reservation-consuming export within that one
/// package.
fn validate_no_other_reservation_consumer(
    interface: &VerifiedPublicationInterface,
    policy: &PaidFeePolicy,
) -> Result<(), PaidExecutionError> {
    for entry in &interface.abi().entrypoints {
        if entry.name == policy.settle_entrypoint {
            continue;
        }
        for object in &entry.objects {
            if &object.ty.origin == policy.reservation_type.origin()
                && object.ty.constructor == policy.reservation_type.constructor()
            {
                return Err(invalid("reservation type accepted by a non-settle export"));
            }
        }
    }
    Ok(())
}

/// Validates that `interface` (the installed fee contract's verified
/// publication interface) matches every role `policy` pins for `reserve`,
/// `reserve_all` and `settle`, and that the reservation type is
/// non-transferable and accepted by no other export *of the fee package
/// interface selected by `policy.code.origin()`* (not its transitive
/// dependency closure; see [`validate_no_other_reservation_consumer`]).
///
/// This is intentionally separate from [`super::validate_paid_fee_policy`]:
/// that function proves the policy's own bytes are self-consistent without
/// ever resolving installed code; this function proves the resolved,
/// authenticated interface actually implements what the policy claims. Both
/// checks are required, in that order, before a policy is trusted for
/// admission.
pub fn validate_fee_interface_admission(
    interface: &VerifiedPublicationInterface,
    policy: &PaidFeePolicy,
) -> Result<(), PaidExecutionError> {
    let interface: VerifiedPublicationInterface = interface
        .for_origin(policy.code.origin())
        .map_err(|_| invalid("fee interface outside admitted closure"))?;
    validate_reserve_shaped_export(
        &interface,
        policy,
        &policy.reserve_entrypoint,
        ObjectMode::Write,
    )?;
    validate_reserve_shaped_export(
        &interface,
        policy,
        &policy.reserve_all_entrypoint,
        ObjectMode::Consume,
    )?;
    validate_settle_export(&interface, policy)?;
    validate_reservation_non_transferable(&interface, &policy.reservation_type)?;
    validate_no_other_reservation_consumer(&interface, policy)?;
    Ok(())
}
