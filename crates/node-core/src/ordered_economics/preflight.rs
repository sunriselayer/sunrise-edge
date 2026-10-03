//! The typed semantic-refusal preflight DR-0153 and the parent integration
//! review require.
//!
//! The existing economics handlers signal every failure through
//! `Invalid(&'static str)`, which mixes a genuine stale signed predecessor
//! ("bond lifecycle stale expected generation") with a missing prerequisite
//! ("fee preparation output missing", "fast-path economics policy not
//! installed", "historical validator set unavailable"). A string is not a
//! typed refusal category, so `super`'s classifier defaults every one of them
//! to a stop.
//!
//! This module closes that gap from the other side: **before** the handler
//! runs, it re-reads the same committed rows the handler will read and
//! positively decides, per real business check, whether this candidate is
//! refusable against a *healthy, present, decodable* row. Only those
//! positively identified conditions become a retained
//! [`OrderedRefusal`]. Anything absent, tombstoned, undecodable, fenced or
//! diverging from the pinned authority is an
//! [`OrderedEconomicsError::Prerequisite`] stop, so the applied prefix never
//! advances past an operation whose outcome is unknown.
//!
//! It duplicates no arithmetic: it recomputes only the two existing row
//! digests ([`bond_lifecycle::bond_row_digest`],
//! [`fee_claims::fee_claim_row_digest`]) and compares the same equality
//! predicates the handlers already own. Every accepted candidate still goes
//! through the same owning preparation, which re-checks all of this itself.
use super::*;
use bond_lifecycle::{
    BondLifecycleOperation, bond_row_digest, decode_signed_bond_lifecycle_intent,
};
use fast_path::records::{
    FastPathBondRecord, FastPathBondState, FastPathFeeShare, FastPathSettlementRecord,
    decode_fastpath_bond_record, decode_fastpath_settlement_record,
};
use fee_claims::codec::{FeeClaimOperation, SignedFeeClaimIntent, decode_signed_fee_claim_intent};
use fee_claims::fee_claim_row_digest;
use local_instance_state::{
    FastPathEpochRecord, decode_fastpath_epoch_record, fastpath_bond_record_key,
    fastpath_epoch_record_key, fastpath_equivocation_evidence_key, fastpath_settlement_key,
};
use protocol_types::ValidatorId;
use validator_set::ValidatorInfo;

/// Reads one durable row, requiring it to be present.
fn require_row<S: StructuredStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: &[u8],
    missing: &'static str,
) -> Result<Vec<u8>, OrderedEconomicsError> {
    let observed: VersionedStateValue = store.read_versioned_state(context, domain, key)?;
    Ok(observed
        .value()
        .ok_or(OrderedEconomicsError::Prerequisite(missing))?
        .to_vec())
}

/// The fresh runtime authority check the parent integration review requires:
/// the committed epoch record must be installed, name exactly the pinned
/// profile epoch, and carry exactly the pinned validator set's own identity
/// digest -- the same digest `fast_path::load_validator_set` verifies the
/// installed row against.
///
/// A non-current epoch here is a *fence*, not a stale candidate: the profile
/// pinned one epoch, and an epoch transition invalidates this whole profile
/// rather than this one candidate. It therefore stops.
pub(crate) fn require_live_authority<S: StructuredStateReader + ?Sized>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Result<FastPathEpochRecord, OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let bytes: Vec<u8> = require_row(
        store,
        context,
        env.policy.domain(),
        &fastpath_epoch_record_key(chain)?,
        "fast-path epoch record is not installed",
    )?;
    let record: FastPathEpochRecord = decode_fastpath_epoch_record(&bytes)?;
    if record.current_epoch != env.policy.context().epoch() {
        return Err(OrderedEconomicsError::Prerequisite(
            "committed current epoch is not the pinned profile epoch",
        ));
    }
    let pinned: Digest32 = env
        .policy
        .engine()
        .validator_set()
        .digest(env.resolver())
        .map_err(|_| {
            OrderedEconomicsError::Prerequisite("pinned validator set identity is not derivable")
        })?;
    if record.current_validator_set_digest != pinned {
        return Err(OrderedEconomicsError::Prerequisite(
            "installed live validator set does not match the pinned trusted authority",
        ));
    }
    Ok(record)
}

/// Requires the sender's committed next nonce to equal `nonce`.
///
/// A healthy row that simply names a different next nonce is the ordinary
/// user-invalid/stale case and refuses; an undecodable or
/// deleted-but-not-initial row is corruption `read_sender_next_nonce` itself
/// raises, and stops.
fn require_next_nonce<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    sender: [u8; 32],
    nonce: u64,
) -> Result<(), OrderedEconomicsError> {
    let observed: u64 = query::query_sender_next_nonce(
        store,
        context,
        env.policy.domain(),
        env.policy.context().chain_id().clone(),
        env.policy.context().protocol_version(),
        env.policy.context().epoch(),
        sender,
    )?;
    if observed != nonce {
        if env.policy.is_causal() {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered committed nonce prerequisite is unavailable; verified recovery required",
            ));
        }
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::StaleSenderNonce,
        ));
    }
    Ok(())
}

/// Every leg's `(sender, nonce)` pair, in the exact consecutive order the
/// handler consumes them. Derived from the already-authenticated reservation
/// plan's own first nonce plus the operation's leg count, so a `Replace`'s
/// second leg is checked at `first_nonce + 1` -- not at `first_nonce`.
fn require_leg_nonces<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let plan: reservation::OrderedReservationPlan = reservation::reservation_plan(env, candidate)?;
    let Some(nonce) = plan.nonce else {
        return Ok(());
    };
    // One `(sender, epoch)` row backs the whole consecutive range, so
    // checking its first nonce is exactly the handler's own
    // `reserve_sender_nonce_range` precondition.
    require_next_nonce(store, context, env, nonce.sender, nonce.first_nonce)
}

/// DR-0154: the sole gate deciding whether admission is still open, run
/// before every kind's own preflight. A present [`super::AdmissionClosureRecord`]
/// means an earlier candidate already committed `Freeze`:
///
/// * every other kind is refused with [`OrderedRefusal::ClosedEpoch`] -- the
///   deterministic, authenticated no-effect closed-epoch refusal DR-0154
///   requires for "an inherited economic candidate that commits after
///   Freeze": no value or nonce movement, and the existing handler (which
///   itself may separately call
///   `crate::mutation_fence::fence_current_epoch` and observe the very same
///   closed row) is never reached;
/// * a second `Freeze` is refused with [`OrderedRefusal::AlreadyFrozen`]
///   instead of re-installing or rewriting the closure record -- "In this
///   initial profile a committed Freeze is a commitment to finish that
///   epoch... There is no local unfreeze."
///
/// This read goes through `store` (the caller's observed read scope during
/// real execution), so it becomes a CAS assertion in the final commit exactly
/// like every other row this module reads.
pub(crate) fn require_admission_open<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let closure = super::freeze::read_authorized_closure(store, context, env)?;
    match (candidate.kind, closure.is_some()) {
        (OrderedOperationKind::Freeze, true) => Err(OrderedEconomicsError::Refused(
            OrderedRefusal::AlreadyFrozen,
        )),
        (OrderedOperationKind::DrainSet, true) => Ok(()),
        (OrderedOperationKind::DrainSet, false) => {
            Err(OrderedEconomicsError::Refused(OrderedRefusal::NoFreeze))
        }
        // DR-0187: Seal, like DrainSet, is admitted only after a committed
        // Freeze -- it cannot warrant before a complete post-drain cut
        // exists.
        (OrderedOperationKind::Seal, true) => Ok(()),
        (OrderedOperationKind::Seal, false) => {
            Err(OrderedEconomicsError::Refused(OrderedRefusal::NoFreeze))
        }
        (_, true) => Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch)),
        (_, false) => Ok(()),
    }
}

/// Runs every typed business check this candidate's kind admits, against the
/// current committed state, before the existing handler is invoked.
pub(crate) fn preflight<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    block_height: u64,
) -> Result<(), OrderedEconomicsError> {
    require_live_authority(store, context, env)?;
    require_admission_open(store, context, env, candidate)?;
    match candidate.kind {
        OrderedOperationKind::FeeClaim => preflight_fee_claim(store, context, env, candidate),
        OrderedOperationKind::BondLifecycle => {
            preflight_bond_lifecycle(store, context, env, candidate)
        }
        OrderedOperationKind::BondSlash => preflight_bond_slash(store, context, env, candidate),
        OrderedOperationKind::BondRegistration => {
            bond_lifecycle::registration::preflight_registration(store, context, env, candidate)
                .map_err(|error| bond_registration_failure(&error))?;
            require_leg_nonces(store, context, env, candidate)
        }
        // Evidence admission is content-addressed and idempotent: a repeated
        // submission is recorded once and re-reports the same record, so
        // there is no stale predecessor to refuse. Its entire validity is
        // proven purely by `authenticate_candidate`.
        OrderedOperationKind::Evidence => Ok(()),
        OrderedOperationKind::Freeze => {
            super::freeze::require_freeze_warrant(store, context, env, candidate, block_height)
        }
        OrderedOperationKind::DrainSet => {
            super::drain_set::preflight_drain_set(store, context, env, candidate)
        }
        OrderedOperationKind::Seal => {
            super::seal::require_seal_warrant(store, context, env, candidate)
        }
    }
}

/// Loads and identity-checks the committed bond row for `validator_id`.
/// `authority` is the exact trusted key authority the candidate outer
/// signature was authenticated against.
fn committed_bond<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    validator_id: ValidatorId,
    authority: Option<&ValidatorInfo>,
    missing: &'static str,
) -> Result<(FastPathBondRecord, Vec<u8>), OrderedEconomicsError> {
    let chain: &ChainId = env.policy.context().chain_id();
    let bytes: Vec<u8> = require_row(
        store,
        context,
        env.policy.domain(),
        &fastpath_bond_record_key(chain, &validator_id)?,
        missing,
    )?;
    let bond: FastPathBondRecord = decode_fastpath_bond_record(&bytes)?;
    if bond.context.chain_id() != chain || bond.validator_id != validator_id {
        return Err(OrderedEconomicsError::Prerequisite(
            "committed bond row identity does not match its own key",
        ));
    }
    // The committed row's authorization key must still agree with the pinned
    // trusted authority this candidate's outer signature was verified
    // against. A divergence means the installed row and the pinned set
    // disagree about who controls this validator: an operator/storage
    // inconsistency, never a stale candidate.
    let registered: &ValidatorInfo = authority.ok_or(OrderedEconomicsError::Prerequisite(
        "committed bond row names a validator outside the pinned set",
    ))?;
    if registered.signature_scheme != bond.authorization_scheme
        || registered.public_key.as_slice() != bond.authorization_key.as_slice()
    {
        return Err(OrderedEconomicsError::Prerequisite(
            "committed bond row authorization key diverges from the pinned trusted authority",
        ));
    }
    Ok((bond, bytes))
}

/// Requires the signed resource/generation/previous-row triple to match the
/// healthy committed row. These are exactly the three predicates the handlers
/// check immediately after reading the row, and they are the canonical
/// "genuine stale writer" conditions.
fn require_signed_predecessor(
    env: &OrderedEconomicsEnvironment<'_>,
    bond: &FastPathBondRecord,
    bond_bytes: &[u8],
    resource_id: bonds::BondResourceId,
    expected_generation: u64,
    expected_previous_row_digest: Option<Digest32>,
) -> Result<(), OrderedEconomicsError> {
    let committed_resource: bonds::BondResourceId =
        bonds::BondResourceId::new(bond.resource_domain, bond.resource).map_err(|_| {
            OrderedEconomicsError::Prerequisite("committed bond row resource identity is invalid")
        })?;
    if resource_id != committed_resource {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::SignedRowMismatch,
        ));
    }
    if expected_generation != bond.generation {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::StaleGeneration,
        ));
    }
    if let Some(expected) = expected_previous_row_digest {
        let actual: Digest32 = bond_row_digest(env.resolver(), bond.lifecycle_epoch, bond_bytes)?;
        if expected != actual {
            return Err(OrderedEconomicsError::Refused(
                OrderedRefusal::StalePreviousRow,
            ));
        }
    }
    Ok(())
}

fn preflight_bond_lifecycle<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let signed = decode_signed_bond_lifecycle_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid bond lifecycle candidate intent")
    })?;
    let (bond, bond_bytes) = committed_bond(
        store,
        context,
        env,
        signed.intent.validator_id,
        env.policy
            .bond_owner_authority(signed.intent.validator_id, &signed.intent.operation),
        "bond lifecycle requires an existing committed bond row",
    )?;
    // Jail is an evidence-driven state; only `Reactivate` may leave it. Any
    // other signed operation against a jailed bond is a healthy-state
    // refusal, exactly as the handler decides it.
    if matches!(bond.state, FastPathBondState::Jailed { .. })
        && !matches!(
            signed.intent.operation,
            BondLifecycleOperation::Reactivate { .. }
        )
    {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::IneligibleState,
        ));
    }
    require_signed_predecessor(
        env,
        &bond,
        &bond_bytes,
        signed.intent.resource_id,
        signed.intent.expected_generation,
        Some(signed.intent.expected_previous_row_digest),
    )?;
    let eligible: bool = match &signed.intent.operation {
        BondLifecycleOperation::Deposit { .. } => bond.state == FastPathBondState::Exited,
        BondLifecycleOperation::Reactivate { .. } => {
            matches!(bond.state, FastPathBondState::Jailed { .. })
        }
        BondLifecycleOperation::Replace { .. } | BondLifecycleOperation::Unbond { .. } => {
            bond.state == FastPathBondState::Active
        }
        BondLifecycleOperation::Withdraw { .. } => match bond.state {
            FastPathBondState::Unbonding { unlock_epoch, .. } => {
                // Early withdrawal, and withdrawal by a validator still in
                // the committed live set, are both healthy-state refusals.
                env.policy.context().epoch().get() >= unlock_epoch.get()
                    && env
                        .policy
                        .registered_validator(signed.intent.validator_id)
                        .is_none()
            }
            _ => false,
        },
    };
    if !eligible {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::IneligibleState,
        ));
    }
    require_leg_nonces(store, context, env, candidate)
}

fn preflight_bond_slash<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let intent = bond_lifecycle::slash::decode_slash_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid bond slash candidate intent")
    })?;
    let (bond, bond_bytes) = committed_bond(
        store,
        context,
        env,
        intent.validator_id,
        env.policy.registered_validator(intent.validator_id),
        "bond slash requires an existing committed bond row",
    )?;
    require_signed_predecessor(
        env,
        &bond,
        &bond_bytes,
        intent.resource_id,
        intent.expected_generation,
        // Unsigned, evidence-authorized: there is no signer to pin a previous
        // row digest ahead of execution, so there is none to compare.
        None,
    )?;
    if matches!(
        bond.state,
        FastPathBondState::Jailed { .. } | FastPathBondState::Exited
    ) {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::IneligibleState,
        ));
    }
    // The permanent DR-0133 evidence row this slash consumes must already
    // exist. Its absence is precisely the parent review's "missing prior
    // evidence must stop for declared recovery, not produce a rejection
    // advancing the prefix" case.
    require_row(
        store,
        context,
        env.policy.domain(),
        &fastpath_equivocation_evidence_key(
            env.policy.context().chain_id(),
            intent.evidence_epoch,
            *intent.validator_id.as_bytes(),
            intent.conflict_digest,
        )?,
        "bond slash names evidence that is not recorded locally",
    )?;
    require_leg_nonces(store, context, env, candidate)
}

fn preflight_fee_claim<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let signed: SignedFeeClaimIntent =
        decode_signed_fee_claim_intent(&candidate.intent).map_err(|_| {
            OrderedEconomicsError::Unauthenticated("invalid fee claim candidate intent")
        })?;
    let chain: &ChainId = env.policy.context().chain_id();
    let bytes: Vec<u8> = require_row(
        store,
        context,
        env.policy.domain(),
        &fastpath_settlement_key(chain, &signed.intent.escrow_request_id)?,
        "fee claim requires an existing committed settlement row",
    )?;
    let settlement: FastPathSettlementRecord = decode_fastpath_settlement_record(&bytes)?;
    if settlement.request_id != signed.intent.escrow_request_id
        || settlement.context.chain_id() != chain
        || settlement.context.protocol_version() != env.policy.context().protocol_version()
    {
        return Err(OrderedEconomicsError::Prerequisite(
            "committed settlement row identity does not match its own key",
        ));
    }
    if settlement.context.epoch() != signed.intent.certificate_epoch {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::SignedRowMismatch,
        ));
    }
    if settlement.generation != signed.intent.expected_generation {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::StaleGeneration,
        ));
    }
    // An uncharged row has no fee-preparation output at all: the prerequisite
    // the claim depends on has not been produced yet. Explicitly a stop, per
    // the parent integration review.
    let (resource_id, fee_output) = match (
        settlement.resource_id,
        settlement.fee_output.clone(),
        settlement.fee_output_epoch,
        settlement.total_amount,
    ) {
        (Some(resource_id), Some(fee_output), Some(_), Some(_)) => (resource_id, fee_output),
        _ => {
            return Err(OrderedEconomicsError::Prerequisite(
                "fee claim settlement row carries no charged fee output yet",
            ));
        }
    };
    if resource_id != signed.intent.resource_id || fee_output != signed.intent.expected_fee_output {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::SignedRowMismatch,
        ));
    }
    let previous_row_digest: Digest32 =
        fee_claim_row_digest(env.resolver(), settlement.context.epoch(), &bytes)?;
    if previous_row_digest != signed.intent.expected_previous_row_digest {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::StalePreviousRow,
        ));
    }
    let share: &FastPathFeeShare = settlement
        .shares
        .iter()
        .find(|share| share.validator_id == signed.intent.validator_id)
        .ok_or(OrderedEconomicsError::Refused(
            OrderedRefusal::ShareUnavailable,
        ))?;
    if share.claimed || share.amount != signed.intent.share_amount {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ShareUnavailable,
        ));
    }
    // A zero-share claim executes no leg and consumes no nonce.
    if matches!(signed.intent.operation, FeeClaimOperation::ZeroShare) {
        return Ok(());
    }
    require_leg_nonces(store, context, env, candidate)
}
