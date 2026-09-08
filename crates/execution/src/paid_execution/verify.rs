//! Independent verification of a [`PaidExecutionResult`] against the signed
//! intent and the trusted policies (DR-0124 "Authenticated durable
//! integration", 2026-09-08).
//!
//! [`encode_paid_execution_result`]/[`decode_paid_execution_result`] prove
//! only that a receipt is canonical and internally consistent. That is not
//! enough for a party that did not run the invocation: a canonical receipt
//! can still name the wrong request, the wrong instance, a fabricated charge,
//! an output owned by the wrong recipient, or a reservation that survived.
//!
//! [`verify_paid_execution_result`] closes that gap. It takes only the
//! receipt, the surviving creation authority, the already
//! signature-authenticated intent and the trusted base/fee policy pair, and
//! independently recomputes everything it checks: the invocation digest, the
//! instance target, the reservation quote and every output's complete
//! canonical `ObjectRef`. It consults no VM, no storage and no
//! caller-supplied pricing.
//!
//! Success still does not make the receipt durable: replay reconciliation,
//! nonce freshness and the fenced commit remain separate obligations.
use super::engine::PaidExecutionOutcome;
use super::{
    AuthenticatedPaidIntent, PaidApplication, PaidChargedOutcome, PaidExecutionError,
    PaidExecutionResult, PaidFeePolicy, PaidResultKind, PaidResultTarget,
    encode_paid_execution_result, paid_invocation_digest, quote_paid_intent,
};
use crate::local_execution::{
    CreatedObjectAuthority, InstanceRecord, LocalExecutionPolicy, instance_target,
};
use crate::{ExecutionEffects, ObjectEffect};
use fees::Amount;
use fees::reservation::{Admission, ReservationPricer, Settlement};
use hashing::HashSuiteResolver;
use objects::{Address, Object, ObjectId, ObjectRef, Owner, encode_object};
use protocol_types::{Epoch, HashPurpose};
use std::collections::BTreeSet;

fn invalid(message: &'static str) -> PaidExecutionError {
    PaidExecutionError::Invalid(message)
}

fn object_ref(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    object: &Object,
) -> Result<ObjectRef, PaidExecutionError> {
    Ok(ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver.hash_for_purpose(epoch, HashPurpose::Object, &encode_object(object)?)?,
    })
}

/// One created object together with the creation authority the engine
/// reported for it. Both must be present: an effect without authority, or
/// authority without a surviving effect, is rejected.
struct Creation<'a> {
    object: &'a Object,
    authority: &'a CreatedObjectAuthority,
}

fn creation<'a>(
    effects: &'a ExecutionEffects,
    authorities: &'a [CreatedObjectAuthority],
    id: ObjectId,
    missing: &'static str,
) -> Result<Creation<'a>, PaidExecutionError> {
    let object: &Object = effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::Created(object) if object.id == id => Some(object),
            _ => None,
        })
        .ok_or(invalid(missing))?;
    let authority: &CreatedObjectAuthority = authorities
        .iter()
        .find(|created| created.authority.object_id == id)
        .ok_or(invalid("paid result creation authority missing"))?;
    Ok(Creation { object, authority })
}

/// The two exact canonical messages one settlement output check may report.
struct OutputErrors {
    reference: &'static str,
    authority: &'static str,
}

/// The trusted inputs every check below shares. None of them come from the
/// receipt under verification.
struct Verifier<'a> {
    resolver: &'a HashSuiteResolver,
    epoch: Epoch,
    fee_policy: &'a PaidFeePolicy,
}

impl Verifier<'_> {
    /// Checks one settlement output: the receipt's `ObjectRef` must be the
    /// exact recomputed reference of a *fresh* created object owned by the
    /// pinned recipient, carrying the fee policy's asset type, schema,
    /// defining code and exact instance authority.
    fn check_output(
        &self,
        creation: &Creation<'_>,
        expected: &ObjectRef,
        recipient: &[u8; 32],
        errors: &OutputErrors,
    ) -> Result<(), PaidExecutionError> {
        let policy: &PaidFeePolicy = self.fee_policy;
        if &object_ref(self.resolver, self.epoch, creation.object)? != expected {
            return Err(invalid(errors.reference));
        }
        if creation.object.owner != Owner::Address(Address::new(*recipient))
            || creation.object.schema_version != policy.schema
            || creation.authority.authority.ty != policy.asset_type
            || creation.authority.authority.code != policy.code
            || creation.authority.authority.instance != policy.instance
            || creation.authority.authority.instance_context != policy.context
        {
            return Err(invalid(errors.authority));
        }
        Ok(())
    }
}

/// The total metered fuel one invocation may report: the signed application
/// limit `L` plus the policy's fixed `R` and `S` allowances.
fn gas_bound(gas_limit: u64, pricer: &ReservationPricer) -> Result<u64, PaidExecutionError> {
    gas_limit
        .checked_add(pricer.reserve_allowance())
        .and_then(|gas| gas.checked_add(pricer.settle_allowance()))
        .ok_or(invalid("paid result gas bound overflow"))
}

fn check_target(
    resolver: &HashSuiteResolver,
    result: &PaidExecutionResult,
    intent_application: &PaidApplication,
) -> Result<(), PaidExecutionError> {
    match (intent_application, &result.kind, &result.target) {
        (
            PaidApplication::Call(inner),
            PaidResultKind::Call,
            PaidResultTarget::Instance(record),
        )
        | (
            PaidApplication::Instantiate(inner),
            PaidResultKind::Instantiate,
            PaidResultTarget::Instance(record),
        ) => {
            let record: &InstanceRecord = record;
            if instance_target(resolver, record)? != inner.instance {
                return Err(invalid("paid result instance target"));
            }
            if record.code != inner.code {
                return Err(invalid("paid result instance code"));
            }
        }
        (
            PaidApplication::Publish(artifact),
            PaidResultKind::Publish,
            PaidResultTarget::Package(origin),
        ) => {
            if origin != artifact.origin() {
                return Err(invalid("paid result package origin"));
            }
        }
        _ => return Err(invalid("paid result kind")),
    }
    Ok(())
}

/// Everything the charged-branch check needs from the signed intent, so it
/// never reads a recipient or limit back out of the receipt it is checking.
struct SignedTerms {
    /// Signed application gas limit `L`.
    gas_limit: u64,
    /// Signed refund recipient.
    refund_recipient: [u8; 32],
}

fn check_charged(
    verifier: &Verifier<'_>,
    result: &PaidExecutionResult,
    charged: &PaidChargedOutcome,
    authorities: &[CreatedObjectAuthority],
    admission: &Admission,
    signed: &SignedTerms,
) -> Result<(), PaidExecutionError> {
    let fee_policy: &PaidFeePolicy = verifier.fee_policy;
    // The metered application gas the charge is based on can never exceed
    // the signed application limit `L`.
    if charged.application_gas_units > signed.gas_limit {
        return Err(invalid("paid result application gas exceeds signed limit"));
    }
    // The reserved, actual and refund units are recomputed from the
    // immutable quote and the fixed `R`/`S` allowances, never trusted.
    let settlement: Settlement = admission
        .settle(charged.application_gas_units)
        .map_err(|_| invalid("paid result charge is not derivable from the quote"))?;
    let reserved: Amount = admission.reserved();
    if charged.reserved != reserved {
        return Err(invalid("paid result reserved does not match the quote"));
    }
    if charged.actual != settlement.actual {
        return Err(invalid("paid result actual does not match the quote"));
    }
    if charged.refund != settlement.refund {
        return Err(invalid("paid result refund does not match the quote"));
    }

    // The fee output and, when the independently computed refund is
    // positive, the refund output must be distinct fresh survivors with the
    // pinned type, owner and creation authority.
    let fee: Creation<'_> = creation(
        &result.effects,
        authorities,
        charged.fee_output.id,
        "paid result fee output not created",
    )?;
    verifier.check_output(
        &fee,
        &charged.fee_output,
        &fee_policy.fee_recipient,
        &OutputErrors {
            reference: "paid result fee output reference",
            authority: "paid result fee output authority",
        },
    )?;
    match (&charged.refund_output, settlement.refund.get() > 0) {
        (Some(refund_ref), true) => {
            if refund_ref.id == charged.fee_output.id {
                return Err(invalid(
                    "paid result fee and refund outputs must be distinct",
                ));
            }
            let refund: Creation<'_> = creation(
                &result.effects,
                authorities,
                refund_ref.id,
                "paid result refund output not created",
            )?;
            if refund.authority.creation_ordinal == fee.authority.creation_ordinal {
                return Err(invalid(
                    "paid result fee and refund outputs must be distinct",
                ));
            }
            verifier.check_output(
                &refund,
                refund_ref,
                &signed.refund_recipient,
                &OutputErrors {
                    reference: "paid result refund output reference",
                    authority: "paid result refund output authority",
                },
            )?;
        }
        (None, false) => {}
        _ => return Err(invalid("paid result refund output presence")),
    }

    // No object of the pinned reservation type may survive, and the consumed
    // reservation itself must not appear as a surviving creation.
    if result
        .effects
        .object_effects
        .iter()
        .any(|effect| matches!(effect, ObjectEffect::Created(object) if object.id == charged.reservation))
    {
        return Err(invalid("paid result reservation survives"));
    }
    if authorities
        .iter()
        .any(|created| created.authority.ty == fee_policy.reservation_type)
    {
        return Err(invalid("paid result reservation type survives"));
    }
    Ok(())
}

/// Requires the reported creation authority to describe exactly the created
/// object effects, with distinct object identities and distinct global
/// creation ordinals.
fn check_creation_authority(
    effects: &ExecutionEffects,
    authorities: &[CreatedObjectAuthority],
) -> Result<(), PaidExecutionError> {
    let created: BTreeSet<ObjectId> = effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object.id),
            _ => None,
        })
        .collect();
    let mut ids: BTreeSet<ObjectId> = BTreeSet::new();
    let mut ordinals: BTreeSet<u32> = BTreeSet::new();
    for authority in authorities {
        if !ids.insert(authority.authority.object_id)
            || !ordinals.insert(authority.creation_ordinal)
        {
            return Err(invalid("paid result duplicate creation authority"));
        }
    }
    if ids != created {
        return Err(invalid("paid result creation authority mismatch"));
    }
    Ok(())
}

/// Independently verifies one paid receipt against the signed intent and the
/// trusted policies. See the module documentation for what this does and does
/// not establish.
pub fn verify_paid_execution_result(
    outcome: &PaidExecutionOutcome,
    authenticated: &AuthenticatedPaidIntent,
    resolver: &HashSuiteResolver,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
) -> Result<(), PaidExecutionError> {
    let result: &PaidExecutionResult = &outcome.result;
    // Canonical/self-consistency first; it is necessary but never sufficient.
    let _: Vec<u8> = encode_paid_execution_result(result)?;

    let intent = authenticated.intent();
    let epoch: Epoch = intent.context.epoch();
    if result.request_id != intent.request_id {
        return Err(invalid("paid result request id"));
    }
    check_target(resolver, result, &intent.application)?;
    if result.effects.tx_hash != paid_invocation_digest(resolver, authenticated.signed())? {
        return Err(invalid("paid result event digest"));
    }
    check_creation_authority(&result.effects, &outcome.created_authorities)?;

    // The quote is recomputed from the authenticated intent and the trusted
    // policies; the receipt never supplies its own pricing basis.
    let admission: Admission = quote_paid_intent(authenticated, resolver, base_policy, fee_policy)?;
    let pricer: ReservationPricer = ReservationPricer::new(
        fee_policy.gas_schedule.clone(),
        fee_policy.conversion_divisor,
        fee_policy.reserve_allowance,
        fee_policy.settle_allowance,
    )?;
    if result.effects.gas_used > gas_bound(intent.gas_limit, &pricer)? {
        return Err(invalid("paid result gas exceeds total caps"));
    }

    match &result.charged {
        Some(charged) => check_charged(
            &Verifier {
                resolver,
                epoch,
                fee_policy,
            },
            result,
            charged,
            &outcome.created_authorities,
            &admission,
            &SignedTerms {
                gas_limit: intent.gas_limit,
                refund_recipient: intent.consent.refund_recipient,
            },
        ),
        None => {
            if !outcome.created_authorities.is_empty() {
                return Err(invalid("zero-charge paid result must have empty effects"));
            }
            Ok(())
        }
    }
}
