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
//! signature-authenticated intent, the trusted base/fee policy pair and the
//! caller's trusted resolved fee [`InstanceRecord`], and independently
//! recomputes everything it checks: the invocation digest, the application
//! and fee instance targets, the reservation quote, each settlement
//! output's complete canonical `ObjectRef`, its host-derived creation
//! identity and its nominal type commitment. It consults no VM, no storage
//! and no caller-supplied pricing, and it never accepts a context, instance
//! target or nominal type as an unchecked claim.
//!
//! Its object-level scope is exactly the two settlement outputs and the
//! reservation postcondition. Validating the *application*'s own effects —
//! their bodies, amounts, types and durable admissibility — is node-core's
//! separate obligation, and no asset body is decoded anywhere here.
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
    CreatedObjectAuthority, InstanceRecord, LocalExecutionPolicy, derive_local_created_object_id,
    instance_target,
};
use crate::publication::PublicationContext;
use crate::{ExecutionEffects, ObjectEffect};
use abi::package_types::verify_scoped_type_id;
use fees::Amount;
use fees::reservation::{Admission, ReservationPricer, Settlement};
use hashing::HashSuiteResolver;
use objects::{Address, Object, ObjectId, ObjectRef, Owner, encode_object};
use protocol_types::{Digest32, Epoch, HashPurpose};
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

/// The three exact canonical messages one settlement output check may
/// report: a reference that does not recompute, a host-derived identity or
/// nominal type commitment that does not reproduce, and an authority row
/// that does not match the pinned fee implementation.
struct OutputErrors {
    reference: &'static str,
    identity: &'static str,
    authority: &'static str,
}

/// The trusted inputs every check below shares. None of them come from the
/// receipt under verification.
struct Verifier<'a> {
    resolver: &'a HashSuiteResolver,
    /// The authenticated execution epoch, taken from the signed intent's
    /// context, never from the receipt.
    epoch: Epoch,
    /// The signed invocation context. Creation identity is domain-separated
    /// by it, so it is an input to the derivation, not a comparison.
    call_context: &'a PublicationContext,
    /// The invocation digest independently recomputed from the signed
    /// intent; it seeds every host-derived creation identity.
    event: Digest32,
    fee_policy: &'a PaidFeePolicy,
    /// The caller's trusted, resolved fee [`InstanceRecord`], pinned to the
    /// policy by [`check_fee_instance`] before any output is checked. Its
    /// own original context is what a legitimate fee output's authority
    /// records, which is not necessarily the current policy context.
    fee_instance: &'a InstanceRecord,
}

/// Independently pins the caller's trusted fee [`InstanceRecord`] to the
/// fee policy before it is used to validate any output authority.
///
/// The record's [`InstanceTarget`](crate::call::InstanceTarget) is derived
/// here, never accepted as a claim, and must equal the policy's exact
/// pinned instance; its code must be the policy's exact pinned code. Its
/// original context may legitimately predate the policy context — an
/// instance created in an earlier epoch keeps that context forever — so
/// only the chain, protocol version and an epoch at or before the policy's
/// are required. Supplying an unchecked context here would defeat the
/// output-authority check entirely, which is why the *record* is the
/// parameter and the context is a derived consequence of it.
fn check_fee_instance(
    resolver: &HashSuiteResolver,
    fee_policy: &PaidFeePolicy,
    record: &InstanceRecord,
) -> Result<(), PaidExecutionError> {
    if record.context.chain_id() != fee_policy.context.chain_id()
        || record.context.protocol_version() != fee_policy.context.protocol_version()
        || record.context.epoch() > fee_policy.context.epoch()
        || record.code != fee_policy.code
        || instance_target(resolver, record)? != fee_policy.instance
    {
        return Err(invalid("paid result fee instance authority"));
    }
    Ok(())
}

impl Verifier<'_> {
    /// Checks one settlement output: the receipt's `ObjectRef` must be the
    /// exact recomputed reference of a *fresh* created object owned by the
    /// pinned recipient, carrying the fee policy's asset type, schema,
    /// defining code and exact instance authority.
    ///
    /// Three independent things are checked, not one:
    ///
    /// * the complete canonical `ObjectRef` recomputed from the object
    ///   actually present in the effects;
    /// * the object's *own* host-stamped identity — version one and the
    ///   deterministic creation id derived from this invocation's context,
    ///   the fee instance's original context, the pinned instance/code, the
    ///   invocation digest and the reported global creation ordinal — plus
    ///   its stored `type_hash`, verified against the policy's nominal
    ///   asset type through the central scoped-type verifier rather than
    ///   trusting the sidecar authority's `ty` field alone;
    /// * the reported creation authority row itself.
    ///
    /// The host decodes no asset body here: amount correctness remains the
    /// pinned contract's audited arithmetic (DR-0124). This also validates
    /// *only* the two settlement outputs. Objects the application created
    /// are not validated by this function at all; their type, authority and
    /// effect admissibility remain node-core's separate durable obligation.
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
        // A settlement output is always freshly created by this invocation,
        // so its version is one and its identity is reproducible from the
        // pinned inputs and the reported ordinal alone.
        let derived: ObjectId = derive_local_created_object_id(
            self.resolver,
            self.call_context,
            &self.fee_instance.context,
            &policy.instance,
            &policy.code,
            self.event,
            creation.authority.creation_ordinal,
        )?;
        if creation.object.version != 1
            || creation.object.id != derived
            || !verify_scoped_type_id(
                self.resolver,
                &creation.object.type_hash,
                self.epoch,
                &policy.asset_type,
            )?
        {
            return Err(invalid(errors.identity));
        }
        if creation.object.owner != Owner::Address(Address::new(*recipient))
            || creation.object.schema_version != policy.schema
            || creation.authority.authority.ty != policy.asset_type
            || creation.authority.authority.code != policy.code
            || creation.authority.authority.instance != policy.instance
            || creation.authority.authority.instance_context != self.fee_instance.context
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
            identity: "paid result fee output identity",
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
                    identity: "paid result refund output identity",
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
///
/// The created effects themselves are also required to name distinct
/// objects: collecting them into a set alone would silently accept a
/// receipt that lists the same created object twice, so duplicates are
/// rejected explicitly while the set is built.
fn check_creation_authority(
    effects: &ExecutionEffects,
    authorities: &[CreatedObjectAuthority],
) -> Result<(), PaidExecutionError> {
    let mut created: BTreeSet<ObjectId> = BTreeSet::new();
    for effect in &effects.object_effects {
        if let ObjectEffect::Created(object) = effect
            && !created.insert(object.id)
        {
            return Err(invalid("paid result duplicate created effect"));
        }
    }
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
    fee_instance: &InstanceRecord,
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
    let event: Digest32 = paid_invocation_digest(resolver, authenticated.signed())?;
    if result.effects.tx_hash != event {
        return Err(invalid("paid result event digest"));
    }
    check_creation_authority(&result.effects, &outcome.created_authorities)?;

    // The quote is recomputed from the authenticated intent and the trusted
    // policies; the receipt never supplies its own pricing basis.
    let admission: Admission = quote_paid_intent(authenticated, resolver, base_policy, fee_policy)?;
    // `quote_paid_intent` has now proven the signed intent, the base policy
    // and the fee policy share one context, so pinning the trusted fee
    // instance to the fee policy also pins it to this invocation.
    check_fee_instance(resolver, fee_policy, fee_instance)?;
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
                call_context: &intent.context,
                event,
                fee_policy,
                fee_instance,
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
