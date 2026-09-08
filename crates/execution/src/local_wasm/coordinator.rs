//! Internal DR-0124 reserve/application/settle phase coordinator.
//!
//! # TEST-ONLY ENTRY, NOT PAID EXECUTION
//!
//! This whole module is compiled under `cfg(test)`. There is no paid
//! signing envelope, no committed fee-policy type and no authenticated
//! paid admission yet, so nothing here is reachable from `execute`, from
//! `execution`'s public API, or from node-core/HTTP/CLI. An existing
//! authenticated zero-fee intent never authorizes a reservation: the phase
//! plan below is constructed directly by internal tests, which is evidence
//! about VM behaviour, not admission. Public activation still requires one
//! signed envelope covering Call/Instantiate/Publish, a separate
//! non-circular fee-policy commitment, explicit paid outcomes and
//! calibrated `R`/`S`.
//!
//! What is *not* test-only is the machinery it drives: one store, one
//! arena, one linker, shared module compilation, `prepare_frame`,
//! `validate_returned_slots`, the phase budgets and the effect collector
//! are the same production code the zero-fee root path uses.
use super::*;
use abi::call_values::{CallValue, ValueLayout, encode_call_value};
use abi::package_types::{ScopedTypeArg, ScopedTypeTag};
use canonical_encoding::encode_digest32;
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use fees::Amount;
use fees::reservation::{Admission, ReservationPricer};
use host::{ArenaObject, Frame, PhaseBudget};
use objects::ObjectId;
use protocol_types::Digest32;

mod fixture;
mod tests;

/// DR-0124 first-profile reserve/settle phase ceilings. Each phase receives
/// at most these resources; the application receives the remaining global
/// capacity after settlement's share is withheld.
const PHASE_CALLS: u32 = 8;
const PHASE_HANDLES: usize = 16;
const PHASE_CREATIONS: u32 = 4;
const PHASE_EVENTS: usize = 16;
const PHASE_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const PHASE_OUTPUT_BYTES: usize = 1024 * 1024;
/// Conservative encoded-effect allowance withheld from every phase for the
/// result envelope and per-object account metadata that is not charged as
/// body bytes at the host boundary.
const RESULT_ENVELOPE_BYTES: usize = 256 * 1024;
/// Encoded length of one canonical self-describing `Digest32`.
const ENCODED_DIGEST_BYTES: u32 = 56;

fn invalid(message: &'static str) -> LocalExecutionError {
    LocalExecutionError::Invalid(message)
}

fn digest_layout() -> ValueLayout {
    ValueLayout::Bytes {
        min_len: ENCODED_DIGEST_BYTES,
        max_len: ENCODED_DIGEST_BYTES,
    }
}
fn address_layout() -> ValueLayout {
    ValueLayout::Bytes {
        min_len: 32,
        max_len: 32,
    }
}
/// The pinned generic reserve argument tuple: reserved units, encoded
/// invocation and fee-policy digests, fee recipient and refund recipient.
/// The coordinator declares and encodes this shape itself and requires the
/// pinned interface to declare exactly it; no asset implementation is a
/// dependency of this host.
fn reserve_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![
        ValueLayout::U64,
        digest_layout(),
        digest_layout(),
        address_layout(),
        address_layout(),
    ])
}
/// The pinned generic settle argument tuple: actual units and the two
/// attested digests. The refund is never a caller-supplied amount.
fn settle_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![ValueLayout::U64, digest_layout(), digest_layout()])
}

fn encoded_digest(digest: &Digest32) -> Result<Vec<u8>, LocalExecutionError> {
    let bytes: Vec<u8> = encode_digest32(digest)?;
    if bytes.len() != ENCODED_DIGEST_BYTES as usize {
        return Err(invalid("encoded digest length"));
    }
    Ok(bytes)
}

fn encode_arguments(
    layout: &ValueLayout,
    value: &CallValue,
) -> Result<Vec<u8>, LocalExecutionError> {
    encode_call_value(layout, value).map_err(|_| invalid("phase arguments"))
}

/// The signed reservation access mode. It selects the pinned export and,
/// for `Consume`, forbids any application access to the same source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReservationAccess {
    /// Debit the source in place; `0 < reserved < balance`.
    Write,
    /// Consume the whole source; `reserved == balance > 0`.
    Consume,
}
impl ReservationAccess {
    fn mode(self) -> ObjectMode {
        match self {
            Self::Write => ObjectMode::Write,
            Self::Consume => ObjectMode::Consume,
        }
    }
    fn access(self) -> objects::AccessMode {
        match self {
            Self::Write => objects::AccessMode::Write,
            Self::Consume => objects::AccessMode::Consume,
        }
    }
}

/// The exact committed fee implementation. Every field is pinned before
/// execution: a request can never nominate another instance, defining code,
/// export, argument layout, nominal type, result declaration or recipient.
pub(super) struct FeeTarget {
    /// Index of the pinned fee scope.
    pub scope: usize,
    /// Exact defining code revision of that scope's instance.
    pub code: UnverifiedDependencyRef,
    /// Pinned export debiting the source in place.
    pub reserve_entrypoint: String,
    /// Pinned export consuming the whole source.
    pub reserve_all_entrypoint: String,
    /// Pinned settlement export.
    pub settle_entrypoint: String,
    /// Bound type arguments shared by every phase call.
    pub type_arguments: Vec<ScopedTypeArg>,
    /// Pinned nominal type of the fee source, fee coin and refund coin.
    pub asset_type: ScopedTypeTag,
    /// Pinned nominal type of the reservation resource.
    pub reservation_type: ScopedTypeTag,
    /// Pinned schema version of all of the above.
    pub schema: u32,
}

/// The application phase's own root call.
pub(super) struct ApplicationCall {
    /// Index of the application scope, which need not be the fee scope.
    pub scope: usize,
    /// Root defining code of the application call.
    pub code: UnverifiedDependencyRef,
    /// Root entrypoint.
    pub entrypoint: String,
    /// Bound type arguments.
    pub type_arguments: Vec<ScopedTypeArg>,
    /// Canonical arguments.
    pub arguments: Vec<u8>,
    /// Declared application inputs in signed order. Only these are exposed
    /// to the application frame.
    pub inputs: Vec<ScopedResolvedObject>,
    /// Reusable signed call ceilings available to the application.
    pub authorizations: Vec<crate::call_authorization::CallAuthorization>,
}

/// One internal phase plan. Constructing it is not paid admission.
pub(super) struct PhasePlan<'a> {
    /// Bounded admitted scopes.
    pub scopes: &'a [ResolvedExecutionScope],
    /// Trusted hash history.
    pub resolver: &'a HashSuiteResolver,
    /// Committed profile-four execution policy.
    pub policy: &'a LocalExecutionPolicy,
    /// Active call context.
    pub context: publication::PublicationContext,
    /// Authenticated sender and owner of the fee source.
    pub sender: [u8; 32],
    /// Complete signed event digest; also seeds creation identity.
    pub event_digest: Digest32,
    /// Attested invocation digest stored in the reservation body.
    pub invocation_digest: Digest32,
    /// Attested fee-policy digest stored in the reservation body.
    pub fee_policy_digest: Digest32,
    /// The pinned fee implementation.
    pub target: FeeTarget,
    /// Signed reservation access mode.
    pub access: ReservationAccess,
    /// The single sender-owned fee source.
    pub source: ScopedResolvedObject,
    /// The application root call.
    pub application: ApplicationCall,
    /// Immutable reservation-pricing admission. The host never decodes an
    /// asset body and never calls a quote callback.
    pub admission: Admission,
    /// The committed pricer the admission must reproduce. It also supplies
    /// the fixed `R` and `S` phase fuel allowances.
    pub pricer: ReservationPricer,
    /// Pinned fee recipient.
    pub fee_recipient: [u8; 32],
    /// Signed refund recipient.
    pub refund_recipient: [u8; 32],
}

/// Which phase determined the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PhaseStatus {
    /// All three phases succeeded.
    Success,
    /// The application failed; its effects were discarded and the fee was
    /// still settled.
    ApplicationFailed,
    /// Reservation failed: zero charge, no effects.
    ReservationFailed,
    /// Settlement failed: zero charge, no effects.
    SettlementFailed,
}

/// Provisional internal outcome. This is not a wire type: no paid result
/// frame is allocated by this slice, and no zero-fee frame is reused to
/// describe a charged execution.
pub(super) struct PhaseOutcome {
    /// Which phase determined the outcome.
    pub status: PhaseStatus,
    /// Committed effects, empty for a zero-charge phase failure.
    pub effects: ExecutionEffects,
    /// Surviving creations with their original global ordinals.
    pub created_authorities: Vec<CreatedObjectAuthority>,
    /// Reserved asset units, zero for a zero-charge outcome.
    pub reserved: Amount,
    /// Actual charged asset units, zero for a zero-charge outcome.
    pub actual_charge: Amount,
    /// Refunded asset units.
    pub refund: Amount,
    /// Metered reserve, application and settle fuel.
    pub reserve_gas: u64,
    pub application_gas: u64,
    /// Test diagnostic proving an application failure came from the limiter.
    pub application_memory_exhausted: bool,
    pub settle_gas: u64,
    /// Identity of the created fee coin, when settlement committed.
    pub fee_output: Option<ObjectId>,
    /// Identity of the created refund coin, present exactly when the
    /// independently computed refund is positive.
    pub refund_output: Option<ObjectId>,
    /// Identity of the consumed reservation resource.
    pub reservation: Option<ObjectId>,
}

/// Deterministic per-phase resources.
struct PhaseProfile {
    calls: u32,
    handles: usize,
    creations: u32,
    events: usize,
    memory_bytes: usize,
    output_bytes: usize,
    fuel: u64,
}

/// One completed phase.
struct PhaseRun {
    failed: bool,
    memory_exhausted: bool,
    gas: u64,
    returned: Vec<Option<Grant>>,
}

/// One captured arena entry. `original` and `authority` are immutable once
/// an entry exists, so a savepoint only restores mutable value and flags.
struct SavedObject {
    object: Object,
    ordinal: Option<u32>,
    consumed: bool,
    transferred: bool,
    dirty: bool,
}

/// A complete object/event savepoint. It deliberately captures no fuel, no
/// counters, no creation ordinal and no allocated memory: rollback discards
/// state, never resource consumption.
struct Savepoint {
    objects: Vec<SavedObject>,
    events: usize,
}

fn savepoint(state: &HostState) -> Savepoint {
    Savepoint {
        objects: state
            .arena
            .iter()
            .map(|item| SavedObject {
                object: item.object.clone(),
                ordinal: item.ordinal,
                consumed: item.consumed,
                transferred: item.transferred,
                dirty: item.dirty,
            })
            .collect(),
        events: state.events.len(),
    }
}

/// Truncates entries created after the savepoint and restores the value and
/// liveness/transfer/dirty flags of the entries that preceded it.
fn restore(state: &mut HostState, point: &Savepoint) -> Result<(), LocalExecutionError> {
    if state.arena.len() < point.objects.len() || state.events.len() < point.events {
        return Err(invalid("savepoint rollback"));
    }
    state.arena.truncate(point.objects.len());
    for (item, saved) in state.arena.iter_mut().zip(&point.objects) {
        item.object = saved.object.clone();
        item.ordinal = saved.ordinal;
        item.consumed = saved.consumed;
        item.transferred = saved.transferred;
        item.dirty = saved.dirty;
    }
    state.events.truncate(point.events);
    Ok(())
}

/// Runs one phase root in the shared store under its own fuel, failure flag
/// and resource window. Cumulative counters are never reset here.
#[allow(clippy::too_many_arguments)]
fn run_phase(
    store: &mut Store<HostState>,
    linker: &Linker<HostState>,
    scope: usize,
    code: &UnverifiedDependencyRef,
    entry: &str,
    types: &[ScopedTypeArg],
    grants: Vec<Grant>,
    args: Vec<u8>,
    profile: &PhaseProfile,
) -> Result<PhaseRun, LocalExecutionError> {
    if !store.data().frames.is_empty() {
        return Err(invalid("phase frame leak"));
    }
    let budget: PhaseBudget = PhaseBudget::start(
        store.data(),
        profile.calls,
        profile.handles,
        profile.creations,
        profile.events,
    );
    {
        let state: &mut HostState = store.data_mut();
        state.budget = Some(budget);
        state.limiter.open_phase(profile.memory_bytes);
        state.output.open_phase(profile.output_bytes);
        // Each phase starts with its own failure flag; a previous phase's
        // denied allocation must not poison this one.
        state.limiter.failed = false;
    }
    store
        .set_fuel(profile.fuel)
        .map_err(|_| invalid("phase fuel"))?;
    let prepared: Frame = match host::prepare_frame(
        store.data(),
        scope,
        code.clone(),
        entry,
        types,
        grants,
        args,
        None,
    ) {
        Ok(prepared) => prepared,
        Err(_) => {
            store.data_mut().budget = None;
            return Ok(PhaseRun {
                failed: true,
                memory_exhausted: false,
                gas: 0,
                returned: Vec::new(),
            });
        }
    };
    let handles: usize = prepared.grants.len();
    {
        let state: &mut HostState = store.data_mut();
        state.handles = state
            .handles
            .checked_add(handles)
            .ok_or_else(|| invalid("phase handles"))?;
        state.calls = state
            .calls
            .checked_add(1)
            .ok_or_else(|| invalid("phase calls"))?;
        state.frames.push(prepared);
    }
    let module: Arc<Module> = runner::root_module(store, code)?;
    let run: Result<(), wasmi::Error> = runner::call_root(store, linker, &module, entry);
    let remaining: u64 = store.get_fuel().map_err(|_| invalid("phase fuel"))?;
    // Actual usage is the metered difference even when the phase trapped.
    let gas: u64 = profile
        .fuel
        .checked_sub(remaining)
        .ok_or_else(|| invalid("phase fuel accounting"))?;
    // Nested frames unwind through their own host entries; anything other
    // than exactly this phase's root frame is a fail-closed inconsistency.
    let frames: Vec<Frame> = std::mem::take(&mut store.data_mut().frames);
    let mut failed: bool = run.is_err() || store.data().limiter.failed || frames.len() != 1;
    let mut returned: Vec<Option<Grant>> = Vec::new();
    if !failed {
        match host::validate_returned_slots(store.data(), &frames[0]) {
            Ok(()) => returned = frames[0].returned.clone(),
            Err(_) => failed = true,
        }
    }
    store.data_mut().budget = None;
    Ok(PhaseRun {
        failed,
        memory_exhausted: store.data().limiter.failed,
        gas,
        returned,
    })
}

/// Everything pinned and encoded before any WASM runs.
struct Validated {
    reserve_entry: String,
    reserve_arguments: Vec<u8>,
    reserve_fuel: u64,
    settle_fuel: u64,
    application_fuel: u64,
}

/// One pinned entrypoint declaration: exact export name, object
/// parameters, ordered result slots, argument layout and the exact
/// arguments the coordinator will pass.
struct PinnedEntrypoint<'a> {
    entry: &'a str,
    inputs: &'a [(ObjectMode, &'a ScopedTypeTag)],
    results: &'a [(ObjectMode, &'a ScopedTypeTag, bool)],
    layout: ValueLayout,
    arguments: &'a [u8],
}

/// Requires one entrypoint to declare exactly the pinned object parameter,
/// result slots and argument layout, and the supplied arguments to decode
/// under that layout.
fn pin_entrypoint(
    interface: &VerifiedPublicationInterface,
    types: &[ScopedTypeArg],
    schema: u32,
    pinned: &PinnedEntrypoint<'_>,
) -> Result<(), LocalExecutionError> {
    let signature = publication::bind_object_signature(interface, pinned.entry, types)
        .map_err(|_| invalid("pinned fee entrypoint"))?;
    if signature.objects().len() != pinned.inputs.len()
        || signature.results().len() != pinned.results.len()
    {
        return Err(invalid("pinned fee declaration"));
    }
    for (bound, (mode, ty)) in signature.objects().iter().zip(pinned.inputs) {
        if bound.mode() != *mode || bound.ty() != *ty || bound.schema() != schema {
            return Err(invalid("pinned fee input"));
        }
    }
    for (bound, (mode, ty, optional)) in signature.results().iter().zip(pinned.results) {
        if bound.mode() != *mode
            || bound.ty() != *ty
            || bound.schema() != schema
            || bound.optional() != *optional
        {
            return Err(invalid("pinned fee result"));
        }
    }
    if signature.argument_layout() != &pinned.layout {
        return Err(invalid("pinned fee argument layout"));
    }
    publication::validate_call_arguments(&signature, pinned.arguments)
        .map_err(|_| invalid("pinned fee arguments"))?;
    Ok(())
}

/// Validates every pinned declaration, recipient, input and amount before
/// any phase executes. Every failure here rejects without a single write.
fn validate(plan: &PhasePlan<'_>) -> Result<Validated, LocalExecutionError> {
    if plan.policy.profile() != crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION {
        return Err(invalid("fee policy profile"));
    }
    if plan.scopes.len() > crate::call_authorization::MAX_EXECUTION_SCOPES {
        return Err(LocalExecutionError::Limit("execution scopes"));
    }
    if plan.application.inputs.len() > crate::call_authorization::MAX_AUTHORIZED_INPUTS {
        return Err(LocalExecutionError::Limit("application inputs"));
    }
    let fee_scope: &ResolvedExecutionScope = plan
        .scopes
        .get(plan.target.scope)
        .ok_or_else(|| invalid("fee scope"))?;
    if plan.scopes.get(plan.application.scope).is_none() {
        return Err(invalid("application scope"));
    }
    // The pinned fee implementation is the exact instance code revision.
    if fee_scope.instance.code != plan.target.code {
        return Err(invalid("pinned fee code"));
    }
    let interface: VerifiedPublicationInterface = fee_scope
        .interface
        .for_origin(plan.target.code.origin())
        .map_err(|_| invalid("fee defining code"))?;
    if reference(&interface)? != plan.target.code
        || interface.candidate().request().artifact().wasm_profile()
            != crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION
    {
        return Err(invalid("pinned fee code"));
    }
    // Recipients must be canonical owner addresses before reservation:
    // otherwise settlement could not create its outputs and the resource
    // would strand.
    validate_ed25519_owner_address(
        &plan.fee_recipient,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;
    validate_ed25519_owner_address(
        &plan.refund_recipient,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;
    // The admission must be exactly what the committed pricer produces.
    let rebound: Admission = plan
        .pricer
        .admit(
            plan.admission.application_limit(),
            plan.admission.reserved(),
        )
        .map_err(|_| invalid("reservation admission"))?;
    if rebound != plan.admission {
        return Err(invalid("reservation admission"));
    }
    let reserved: Amount = plan.admission.reserved();
    if reserved.get() == 0 {
        return Err(invalid("nonpositive reservation"));
    }
    // The paid schedule must price a nonzero actual fee even at zero
    // application usage, so the required fee slot can always be filled.
    if plan
        .admission
        .settle(0)
        .map_err(|_| invalid("reservation admission"))?
        .actual
        .get()
        == 0
    {
        return Err(invalid("zero actual fee schedule"));
    }
    // Fee source identity, type, schema and exact instance authority.
    let source: &ScopedResolvedObject = &plan.source;
    if source.resolved.mode != plan.access.access()
        || source.authority.ty != plan.target.asset_type
        || source.resolved.object.schema_version != plan.target.schema
        || source.authority.code != plan.target.code
        || source.authority.instance != fee_scope.target
        || source.authority.instance_context != fee_scope.instance.context
    {
        return Err(invalid("fee source authority"));
    }
    for input in &plan.application.inputs {
        if input.resolved.object.id != source.resolved.object.id {
            continue;
        }
        // A consumed source is incompatible with any application access and
        // is rejected before reserve executes.
        if plan.access == ReservationAccess::Consume {
            return Err(invalid("consumed source in application access"));
        }
        // Otherwise the application's reference must match exactly.
        if input.resolved.object != source.resolved.object || input.authority != source.authority {
            return Err(invalid("fee source reference mismatch"));
        }
    }
    let reserve_entry: String = match plan.access {
        ReservationAccess::Write => plan.target.reserve_entrypoint.clone(),
        ReservationAccess::Consume => plan.target.reserve_all_entrypoint.clone(),
    };
    let reserve_arguments: Vec<u8> = encode_arguments(
        &reserve_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(reserved.get()),
            CallValue::Bytes(encoded_digest(&plan.invocation_digest)?),
            CallValue::Bytes(encoded_digest(&plan.fee_policy_digest)?),
            CallValue::Bytes(plan.fee_recipient.to_vec()),
            CallValue::Bytes(plan.refund_recipient.to_vec()),
        ]),
    )?;
    pin_entrypoint(
        &interface,
        &plan.target.type_arguments,
        plan.target.schema,
        &PinnedEntrypoint {
            entry: &reserve_entry,
            inputs: &[(plan.access.mode(), &plan.target.asset_type)],
            results: &[(ObjectMode::Consume, &plan.target.reservation_type, false)],
            layout: reserve_argument_layout(),
            arguments: &reserve_arguments,
        },
    )?;
    // Settlement is pinned with the maximum actual charge, so its declared
    // shape is validated before execution rather than after metering.
    let probe: Vec<u8> = settle_arguments(plan, reserved)?;
    pin_entrypoint(
        &interface,
        &plan.target.type_arguments,
        plan.target.schema,
        &PinnedEntrypoint {
            entry: &plan.target.settle_entrypoint,
            inputs: &[(ObjectMode::Consume, &plan.target.reservation_type)],
            results: &[
                (ObjectMode::Read, &plan.target.asset_type, false),
                (ObjectMode::Read, &plan.target.asset_type, true),
            ],
            layout: settle_argument_layout(),
            arguments: &probe,
        },
    )?;
    Ok(Validated {
        reserve_entry,
        reserve_arguments,
        reserve_fuel: plan.pricer.reserve_allowance(),
        settle_fuel: plan.pricer.settle_allowance(),
        application_fuel: plan.admission.application_limit(),
    })
}

fn settle_arguments(plan: &PhasePlan<'_>, actual: Amount) -> Result<Vec<u8>, LocalExecutionError> {
    encode_arguments(
        &settle_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(actual.get()),
            CallValue::Bytes(encoded_digest(&plan.invocation_digest)?),
            CallValue::Bytes(encoded_digest(&plan.fee_policy_digest)?),
        ]),
    )
}

fn fixed_profile(fuel: u64) -> PhaseProfile {
    PhaseProfile {
        calls: PHASE_CALLS,
        handles: PHASE_HANDLES,
        creations: PHASE_CREATIONS,
        events: PHASE_EVENTS,
        memory_bytes: PHASE_MEMORY_BYTES,
        output_bytes: PHASE_OUTPUT_BYTES,
        fuel,
    }
}

/// The application receives the remaining global capacity after the
/// settlement phase's share is withheld, so an application cannot prevent
/// charging by exhausting fuel, memory, calls, handles, creations, events
/// or encoded output.
fn application_profile(state: &HostState, fuel: u64) -> Result<PhaseProfile, LocalExecutionError> {
    fn remaining<T: Copy + Ord + std::ops::Sub<Output = T>>(
        total: T,
        used: T,
        reserved: T,
    ) -> Result<T, LocalExecutionError> {
        if used > total || total - used < reserved {
            return Err(invalid("settlement headroom"));
        }
        Ok(total - used - reserved)
    }
    let global_output: usize = MAX_LOCAL_EXECUTION_OUTPUT_BYTES
        .checked_sub(RESULT_ENVELOPE_BYTES)
        .ok_or_else(|| invalid("output envelope"))?;
    Ok(PhaseProfile {
        calls: remaining(MAX_LOCAL_EXECUTION_CALLS, state.calls, PHASE_CALLS)?,
        handles: remaining(
            MAX_LOCAL_OBJECT_HANDLES as usize,
            state.handles,
            PHASE_HANDLES,
        )?,
        creations: remaining(MAX_LOCAL_CREATED_OBJECTS, state.creations, PHASE_CREATIONS)?,
        events: remaining(
            MAX_LOCAL_EXECUTION_EVENTS,
            state.emitted_events,
            PHASE_EVENTS,
        )?,
        memory_bytes: remaining(
            MAX_LOCAL_EXECUTION_MEMORY_BYTES as usize,
            state.limiter.allocated(),
            PHASE_MEMORY_BYTES,
        )?,
        output_bytes: remaining(global_output, state.output.used(), PHASE_OUTPUT_BYTES)?,
        fuel,
    })
}

/// Validates the single returned reservation slot against the final live
/// arena: exactly one required slot, a fresh sender-owned resource of the
/// pinned type, schema, defining code and exact instance, still live and
/// delivered with the declared Consume right. There is no creation-order
/// guess and no arena index supplied by the guest.
fn validated_reservation(
    state: &HostState,
    returned: &[Option<Grant>],
    plan: &PhasePlan<'_>,
) -> Result<usize, LocalExecutionError> {
    let [Some(grant)] = returned else {
        return Err(invalid("reservation slot"));
    };
    let scope: &ResolvedExecutionScope = plan
        .scopes
        .get(plan.target.scope)
        .ok_or_else(|| invalid("fee scope"))?;
    let item: &ArenaObject = state
        .arena
        .get(grant.index)
        .ok_or_else(|| invalid("reservation slot"))?;
    if grant.mode != ObjectMode::Consume
        || item.original.is_some()
        || item.ordinal.is_none()
        || item.consumed
        || item.transferred
        || item.object.owner != Owner::Address(Address::new(plan.sender))
        || item.object.schema_version != plan.target.schema
        || item.authority.ty != plan.target.reservation_type
        || item.authority.code != plan.target.code
        || item.authority.instance != scope.target
        || item.authority.instance_context != scope.instance.context
    {
        return Err(invalid("reservation authority"));
    }
    Ok(grant.index)
}

/// Validates settlement's declared outputs against the final live arena:
/// slot presence, freshness, nominal type, schema, exact defining code and
/// instance, and pinned recipient ownership. Amount correctness remains the
/// pinned contract's audited arithmetic; the host decodes no asset body.
fn validated_settlement(
    state: &HostState,
    returned: &[Option<Grant>],
    plan: &PhasePlan<'_>,
    refund: Amount,
) -> Result<(ObjectId, Option<ObjectId>), LocalExecutionError> {
    let [fee_slot, refund_slot] = returned else {
        return Err(invalid("settlement slots"));
    };
    let fee: Grant = fee_slot.ok_or_else(|| invalid("missing fee output"))?;
    // The refund slot is present exactly when the independently computed
    // refund is positive; a zero refund is absence, never a zero coin.
    if refund_slot.is_some() != (refund.get() > 0) {
        return Err(invalid("refund slot presence"));
    }
    let scope: &ResolvedExecutionScope = plan
        .scopes
        .get(plan.target.scope)
        .ok_or_else(|| invalid("fee scope"))?;
    let check = |grant: Grant, recipient: &[u8; 32]| -> Result<ObjectId, LocalExecutionError> {
        let item: &ArenaObject = state
            .arena
            .get(grant.index)
            .ok_or_else(|| invalid("settlement output"))?;
        if grant.mode != ObjectMode::Read
            || item.original.is_some()
            || item.ordinal.is_none()
            || item.consumed
            || item.object.owner != Owner::Address(Address::new(*recipient))
            || item.object.schema_version != plan.target.schema
            || item.authority.ty != plan.target.asset_type
            || item.authority.code != plan.target.code
            || item.authority.instance != scope.target
            || item.authority.instance_context != scope.instance.context
        {
            return Err(invalid("settlement output"));
        }
        Ok(item.object.id)
    };
    let fee_id: ObjectId = check(fee, &plan.fee_recipient)?;
    let refund_id: Option<ObjectId> = match refund_slot {
        Some(grant) => {
            if grant.index == fee.index {
                return Err(invalid("aliased settlement outputs"));
            }
            Some(check(*grant, &plan.refund_recipient)?)
        }
        None => None,
    };
    Ok((fee_id, refund_id))
}

/// Rejects any surviving object of the pinned reservation type as a
/// host-validated postcondition, not a contract promise.
fn no_surviving_reservation(
    state: &HostState,
    plan: &PhasePlan<'_>,
) -> Result<(), LocalExecutionError> {
    if state
        .arena
        .iter()
        .any(|item| !item.consumed && item.authority.ty == plan.target.reservation_type)
    {
        return Err(invalid("surviving reservation"));
    }
    Ok(())
}

fn total_gas(reserve: u64, application: u64, settle: u64) -> Result<u64, LocalExecutionError> {
    reserve
        .checked_add(application)
        .and_then(|gas| gas.checked_add(settle))
        .ok_or_else(|| invalid("phase gas accounting"))
}

/// Restores the pre-reservation state and returns an explicit zero-charge
/// outcome. No application change, partial fee or escrow survives, and no
/// native fallback debit exists.
fn zero_charge(
    store: &mut Store<HostState>,
    initial: &Savepoint,
    plan: &PhasePlan<'_>,
    status: PhaseStatus,
    reserve_gas: u64,
    application_gas: u64,
    settle_gas: u64,
) -> Result<PhaseOutcome, LocalExecutionError> {
    restore(store.data_mut(), initial)?;
    let arena: Vec<ArenaObject> = std::mem::take(&mut store.data_mut().arena);
    let (effects, authorities) =
        runner::collect_effects(arena).ok_or_else(|| invalid("zero-charge effects"))?;
    if !effects.is_empty() || !authorities.is_empty() || !store.data().events.is_empty() {
        return Err(invalid("zero-charge effects"));
    }
    Ok(PhaseOutcome {
        status,
        effects: ExecutionEffects {
            tx_hash: plan.event_digest,
            status: ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.into(),
            },
            object_effects: Vec::new(),
            events: Vec::new(),
            gas_used: total_gas(reserve_gas, application_gas, settle_gas)?,
        },
        created_authorities: Vec::new(),
        reserved: Amount::new(0),
        actual_charge: Amount::new(0),
        refund: Amount::new(0),
        reserve_gas,
        application_gas,
        application_memory_exhausted: false,
        settle_gas,
        fee_output: None,
        refund_output: None,
        reservation: None,
    })
}

/// Runs reserve, application and settle as one invocation in one store and
/// one arena.
///
/// TEST-ONLY: this is not authenticated paid admission. See the module
/// documentation.
pub(super) fn run(plan: &PhasePlan<'_>) -> Result<PhaseOutcome, LocalExecutionError> {
    let validated: Validated = validate(plan)?;
    let engine: Engine = runner::interpreter();
    // One compilation of each admitted module for all three phases.
    let modules = admission::scopes(plan.scopes, &engine)?;
    let linker: Arc<Linker<HostState>> =
        Arc::new(host::linker(&engine).map_err(|_| invalid("host linker"))?);
    let epoch: protocol_types::Epoch = plan.context.epoch();
    let mut arena: Vec<ArenaObject> = Vec::new();
    let mut body_bytes: usize = 0;
    // The fee source is loaded exactly once, at index zero.
    arena.push(runner::bind_input(
        plan.resolver,
        plan.scopes,
        plan.sender,
        epoch,
        &plan.source,
    )?);
    runner::accumulate_body_bytes(&mut body_bytes, &plan.source.resolved.object)?;
    const SOURCE_INDEX: usize = 0;
    let mut application_grants: Vec<Grant> = Vec::new();
    let mut ids: BTreeSet<ObjectId> = BTreeSet::new();
    for input in &plan.application.inputs {
        if !ids.insert(input.resolved.object.id) {
            return Err(invalid("duplicate application input"));
        }
        let index: usize = if input.resolved.object.id == plan.source.resolved.object.id {
            SOURCE_INDEX
        } else {
            let bound: ArenaObject =
                runner::bind_input(plan.resolver, plan.scopes, plan.sender, epoch, input)?;
            runner::accumulate_body_bytes(&mut body_bytes, &input.resolved.object)?;
            arena.push(bound);
            arena.len() - 1
        };
        // The application keeps exactly its declared access mode.
        application_grants.push(Grant {
            index,
            mode: host::object_mode(input.resolved.mode),
        });
    }
    let state: HostState = runner::host_state(runner::StateParts {
        resolver: plan.resolver,
        scopes: plan.scopes,
        authorizations: plan.application.authorizations.clone(),
        profile: plan.policy.profile(),
        context: plan.context.clone(),
        event: plan.event_digest,
        sender: plan.sender,
        arena,
        modules,
        linker: Arc::clone(&linker),
    })?;
    let mut store: Store<HostState> = Store::new(&engine, state);
    store.limiter(|state| &mut state.limiter);
    let global_output: usize = MAX_LOCAL_EXECUTION_OUTPUT_BYTES
        .checked_sub(RESULT_ENVELOPE_BYTES)
        .ok_or_else(|| invalid("output envelope"))?;
    store.data_mut().output.set_limit(global_output);
    let initial: Savepoint = savepoint(store.data());

    // Reject structurally invalid application calls before reservation, without
    // entering a frame or spending any resource. Revalidate after reservation
    // because the application must observe the updated source remainder.
    host::prepare_frame(
        store.data(),
        plan.application.scope,
        plan.application.code.clone(),
        &plan.application.entrypoint,
        &plan.application.type_arguments,
        application_grants.clone(),
        plan.application.arguments.clone(),
        Some(LocalExecutionMode::Call),
    )
    .map_err(|_| invalid("application frame"))?;

    // ---- reserve: the source is the only grant, and its result is kept in
    // coordinator-local state, never in an application grant.
    let reserve: PhaseRun = run_phase(
        &mut store,
        &linker,
        plan.target.scope,
        &plan.target.code,
        &validated.reserve_entry,
        &plan.target.type_arguments,
        vec![Grant {
            index: SOURCE_INDEX,
            mode: plan.access.mode(),
        }],
        validated.reserve_arguments.clone(),
        &fixed_profile(validated.reserve_fuel),
    )?;
    if reserve.failed {
        return zero_charge(
            &mut store,
            &initial,
            plan,
            PhaseStatus::ReservationFailed,
            reserve.gas,
            0,
            0,
        );
    }
    let reservation_index: usize =
        match validated_reservation(store.data(), &reserve.returned, plan) {
            Ok(index) => index,
            Err(_) => {
                return zero_charge(
                    &mut store,
                    &initial,
                    plan,
                    PhaseStatus::ReservationFailed,
                    reserve.gas,
                    0,
                    0,
                );
            }
        };
    let reservation_id: ObjectId = store.data().arena[reservation_index].object.id;
    let post_reserve: Savepoint = savepoint(store.data());

    // ---- application: only the declared application inputs are exposed.
    let profile: PhaseProfile = application_profile(store.data(), validated.application_fuel)?;
    let application: PhaseRun = run_phase(
        &mut store,
        &linker,
        plan.application.scope,
        &plan.application.code,
        &plan.application.entrypoint,
        &plan.application.type_arguments,
        application_grants,
        plan.application.arguments.clone(),
        &profile,
    )?;
    if application.failed {
        // Discard every application object effect and event, but not gas or
        // any cumulative resource counter.
        restore(store.data_mut(), &post_reserve)?;
    }

    // ---- settle: only the freshly returned private reservation is granted.
    let settlement = plan
        .admission
        .settle(application.gas)
        .map_err(|_| invalid("settlement pricing"))?;
    let settle: PhaseRun = run_phase(
        &mut store,
        &linker,
        plan.target.scope,
        &plan.target.code,
        &plan.target.settle_entrypoint,
        &plan.target.type_arguments,
        vec![Grant {
            index: reservation_index,
            mode: ObjectMode::Consume,
        }],
        settle_arguments(plan, settlement.actual)?,
        &fixed_profile(validated.settle_fuel),
    )?;
    let outputs: Option<(ObjectId, Option<ObjectId>)> = if settle.failed {
        None
    } else {
        validated_settlement(store.data(), &settle.returned, plan, settlement.refund)
            .ok()
            .filter(|_| store.data().arena[reservation_index].consumed)
            .filter(|_| no_surviving_reservation(store.data(), plan).is_ok())
    };
    let Some((fee_output, refund_output)) = outputs else {
        return zero_charge(
            &mut store,
            &initial,
            plan,
            PhaseStatus::SettlementFailed,
            reserve.gas,
            application.gas,
            settle.gas,
        );
    };
    let status: PhaseStatus = if application.failed {
        PhaseStatus::ApplicationFailed
    } else {
        PhaseStatus::Success
    };
    let state: HostState = store.into_data();
    let (object_effects, created_authorities) =
        runner::collect_effects(state.arena).ok_or_else(|| invalid("phase effects"))?;
    let effects: ExecutionEffects = ExecutionEffects {
        tx_hash: plan.event_digest,
        status: match status {
            PhaseStatus::Success => ExecutionStatus::Success,
            _ => ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.into(),
            },
        },
        object_effects,
        events: state.events,
        gas_used: total_gas(reserve.gas, application.gas, settle.gas)?,
    };
    // Final canonical bound in addition to the running per-phase and global
    // output accounting enforced before every host mutation.
    if crate::encode_execution_effects(&effects)?.len() > MAX_LOCAL_EXECUTION_OUTPUT_BYTES {
        return Err(LocalExecutionError::Limit("phase result bytes"));
    }
    Ok(PhaseOutcome {
        status,
        effects,
        created_authorities,
        reserved: plan.admission.reserved(),
        actual_charge: settlement.actual,
        refund: settlement.refund,
        reserve_gas: reserve.gas,
        application_gas: application.gas,
        application_memory_exhausted: application.memory_exhausted,
        settle_gas: settle.gas,
        fee_output: Some(fee_output),
        refund_output,
        reservation: Some(reservation_id),
    })
}
