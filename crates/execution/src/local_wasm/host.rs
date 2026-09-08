//! The guest can name only frame-local handles, never storage keys or object IDs.
use super::*;
use abi::package_types::{
    decode_scoped_type_arguments, decode_scoped_type_tag, derive_scoped_type_id,
    encode_scoped_type_tag,
};
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use wasmi::{Caller, Memory, ResourceLimiter};
use wasmi_core::LimiterError;

/// Sentinel marking an absent optional result slot in fixed-length delivery.
const ABSENT_RESULT_SLOT: u32 = u32::MAX;

/// Conservative encoded-effect overhead charged for one created, mutated or
/// deleted object in addition to its body bytes: identity, version, owner,
/// nominal type commitment, schema, the enclosing `ObjectEffect` framing and
/// the one list-entry field the effects list wrapper adds for it. Sized
/// above the real canonical encoder's worst observed case (`Mutated`, whose
/// owner is the largest `Owner::Address` variant), checked in
/// `object_overhead_bounds_the_real_encoder` below. A deletion emits no body
/// at all, so charging this same bound for it is conservative, not exact.
pub(super) const OUTPUT_OBJECT_OVERHEAD_BYTES: usize = 320;
/// Conservative encoded-effect overhead charged for one event record in
/// addition to its type tag and body bytes.
const OUTPUT_EVENT_OVERHEAD_BYTES: usize = 128;

pub(super) fn trap() -> wasmi::Error {
    wasmi::Error::new(LOCAL_EXECUTION_TRAP_REASON)
}
type HostResult = Result<i32, wasmi::Error>;

pub(super) struct ArenaObject {
    pub object: Object,
    pub original: Option<Object>,
    pub authority: ObjectAuthority,
    pub ordinal: Option<u32>,
    pub consumed: bool,
    pub transferred: bool,
    pub dirty: bool,
}
#[derive(Clone, Copy)]
pub(super) struct Grant {
    pub index: usize,
    pub mode: ObjectMode,
}
pub(super) struct Frame {
    pub scope: usize,
    pub interface: VerifiedPublicationInterface,
    pub code: UnverifiedDependencyRef,
    pub grants: Vec<Grant>,
    pub args: Vec<u8>,
    // Ordered, signed result-slot declarations (DR-0124), at most four.
    pub declared_results: Vec<BoundObjectResult>,
    // Fixed-length slots, positionally aligned with `declared_results`;
    // `None` is the explicit absence sentinel until delivery/drop.
    pub returned: Vec<Option<Grant>>,
}
pub(super) struct HostState {
    pub resolver: HashSuiteResolver,
    pub scopes: Vec<ResolvedExecutionScope>,
    pub authorizations: Vec<crate::call_authorization::CallAuthorization>,
    pub profile: u32,
    pub context: publication::PublicationContext,
    pub event: protocol_types::Digest32,
    pub sender: [u8; 32],
    pub instance_bytes: Vec<Vec<u8>>,
    pub arena: Vec<ArenaObject>,
    pub frames: Vec<Frame>,
    pub modules: BTreeMap<PackageOrigin, Arc<Module>>,
    pub linker: Arc<Linker<HostState>>,
    pub limiter: RetainedMemory,
    pub events: Vec<EventRecord>,
    // Monotonic count of every event ever admitted and pushed, including
    // ones later discarded by a savepoint rollback. `events.len()` alone is
    // not this count: a rollback truncates the retained log, but resource
    // consumption must never be rewound, so budgets are measured against
    // this counter instead.
    pub emitted_events: usize,
    pub creations: u32,
    pub calls: u32,
    // Every allocated selector counts permanently, including popped child aliases.
    pub handles: usize,
    // Optional per-phase ceilings (DR-0124). `None` is the historical
    // zero-fee behaviour: only the global counters bound the invocation.
    pub budget: Option<PhaseBudget>,
    // Running encoded-effect byte accounting, unbounded unless a phase
    // coordinator installs explicit ceilings.
    pub output: OutputAccount,
}

/// One open phase window (DR-0124): the cumulative counters observed when
/// the phase started, plus the ceilings applied on top of them.
///
/// A budget bounds only the work performed inside its phase. The cumulative
/// counters it measures are never rewound by a phase boundary or by a
/// savepoint rollback.
pub(super) struct PhaseBudget {
    call_limit: u32,
    handle_limit: usize,
    creation_limit: u32,
    event_limit: usize,
    calls: u32,
    handles: usize,
    creations: u32,
    events: usize,
}

impl PhaseBudget {
    /// Opens a phase window over the current cumulative counters.
    #[cfg(test)]
    pub fn start(
        state: &HostState,
        call_limit: u32,
        handle_limit: usize,
        creation_limit: u32,
        event_limit: usize,
    ) -> Self {
        Self {
            call_limit,
            handle_limit,
            creation_limit,
            event_limit,
            calls: state.calls,
            handles: state.handles,
            creations: state.creations,
            events: state.emitted_events,
        }
    }
    fn admit(
        start: usize,
        current: usize,
        additional: usize,
        limit: usize,
    ) -> Result<(), wasmi::Error> {
        let used: usize = current
            .checked_sub(start)
            .and_then(|used| used.checked_add(additional))
            .ok_or_else(trap)?;
        if used > limit {
            return Err(trap());
        }
        Ok(())
    }
}

/// Running encoded-effect byte accounting.
///
/// The historical zero-fee path installs no ceiling here and keeps the
/// final canonical result encode as its only output bound, so its accepted
/// executions are unchanged. A coordinator phase installs both a global
/// remaining ceiling and a phase window, so an application cannot consume
/// the output allowance reserved for settlement.
#[derive(Default)]
pub(super) struct OutputAccount {
    used: usize,
    limit: Option<usize>,
    phase_start: usize,
    phase_limit: Option<usize>,
}

impl OutputAccount {
    /// Charges `bytes` of prospective encoded output before the host
    /// mutates the arena or the event log. Charges are monotone: a later
    /// overwrite or rollback never returns previously charged bytes.
    fn charge(&mut self, bytes: usize) -> Result<(), wasmi::Error> {
        let next: usize = self.used.checked_add(bytes).ok_or_else(trap)?;
        if self.limit.is_some_and(|limit| next > limit) {
            return Err(trap());
        }
        if let Some(limit) = self.phase_limit {
            let used: usize = next.checked_sub(self.phase_start).ok_or_else(trap)?;
            if used > limit {
                return Err(trap());
            }
        }
        self.used = next;
        Ok(())
    }
    /// Installs the invocation-wide remaining output ceiling.
    #[cfg(test)]
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = Some(limit);
    }
    /// Opens a phase output window over the bytes charged so far.
    #[cfg(test)]
    pub fn open_phase(&mut self, limit: usize) {
        self.phase_start = self.used;
        self.phase_limit = Some(limit);
    }
    /// Cumulative charged output bytes; never reduced by a rollback.
    #[cfg(test)]
    pub fn used(&self) -> usize {
        self.used
    }
}

impl HostState {
    /// Global and phase frame-entry admission, checked before entry.
    fn admit_calls(&self, additional: u32) -> Result<(), wasmi::Error> {
        if self
            .calls
            .checked_add(additional)
            .is_none_or(|calls| calls > MAX_LOCAL_EXECUTION_CALLS)
        {
            return Err(trap());
        }
        match &self.budget {
            Some(budget) => PhaseBudget::admit(
                budget.calls as usize,
                self.calls as usize,
                additional as usize,
                budget.call_limit as usize,
            ),
            None => Ok(()),
        }
    }
    /// Global and phase handle admission, checked before allocation.
    fn admit_handles(&self, additional: usize) -> Result<(), wasmi::Error> {
        if self
            .handles
            .checked_add(additional)
            .is_none_or(|handles| handles > MAX_LOCAL_OBJECT_HANDLES as usize)
        {
            return Err(trap());
        }
        match &self.budget {
            Some(budget) => PhaseBudget::admit(
                budget.handles,
                self.handles,
                additional,
                budget.handle_limit,
            ),
            None => Ok(()),
        }
    }
    /// Global and phase creation admission, checked before creation.
    fn admit_creations(&self, additional: u32) -> Result<(), wasmi::Error> {
        if self
            .creations
            .checked_add(additional)
            .is_none_or(|creations| creations > MAX_LOCAL_CREATED_OBJECTS)
        {
            return Err(trap());
        }
        match &self.budget {
            Some(budget) => PhaseBudget::admit(
                budget.creations as usize,
                self.creations as usize,
                additional as usize,
                budget.creation_limit as usize,
            ),
            None => Ok(()),
        }
    }
    /// Global and phase event admission, checked before recording.
    fn admit_events(&self, additional: usize) -> Result<(), wasmi::Error> {
        if self
            .emitted_events
            .checked_add(additional)
            .is_none_or(|events| events > MAX_LOCAL_EXECUTION_EVENTS)
        {
            return Err(trap());
        }
        match &self.budget {
            Some(budget) => PhaseBudget::admit(
                budget.events,
                self.emitted_events,
                additional,
                budget.event_limit,
            ),
            None => Ok(()),
        }
    }
}

#[derive(Default)]
pub(super) struct RetainedMemory {
    retained: usize,
    pub failed: bool,
    // Cumulative growth, never reduced by a rollback or a phase boundary.
    allocated: usize,
    phase_start_allocated: usize,
    phase_limit: Option<usize>,
}
impl ResourceLimiter for RetainedMemory {
    // Wasmi returns standard WASM -1 before this hook for growth beyond a
    // module's declared maximum. Global retained-memory denial here traps.
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        let delta: Option<usize> = desired.checked_sub(current);
        let next: Option<usize> = delta.and_then(|delta| self.retained.checked_add(delta));
        let allocated: Option<usize> = delta.and_then(|delta| self.allocated.checked_add(delta));
        if maximum.is_some_and(|max| desired > max)
            || next.is_none_or(|n| n > MAX_LOCAL_EXECUTION_MEMORY_BYTES as usize)
            || allocated.is_none_or(|total| {
                self.phase_limit
                    .is_some_and(|limit| total.saturating_sub(self.phase_start_allocated) > limit)
            })
        {
            self.failed = true;
            return Err(LimiterError::ResourceLimiterDeniedAllocation);
        }
        self.retained = next.ok_or(LimiterError::ResourceLimiterDeniedAllocation)?;
        self.allocated = allocated.ok_or(LimiterError::ResourceLimiterDeniedAllocation)?;
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        // The same per-table bound is already enforced by contract_wasm profile 2.
        if desired > 4096 || maximum.is_some_and(|max| desired > max) {
            self.failed = true;
            return Err(LimiterError::ResourceLimiterDeniedAllocation);
        }
        Ok(true)
    }
    fn memory_grow_failed(&mut self, _error: &LimiterError) {
        self.failed = true;
    }
    fn table_grow_failed(&mut self, _error: &LimiterError) {
        self.failed = true;
    }
    fn instances(&self) -> usize {
        MAX_LOCAL_EXECUTION_CALLS as usize
    }
    fn memories(&self) -> usize {
        MAX_LOCAL_EXECUTION_CALLS as usize
    }
    fn tables(&self) -> usize {
        MAX_LOCAL_EXECUTION_CALLS as usize
    }
}
impl RetainedMemory {
    /// Opens a phase linear-memory window over the cumulative allocation.
    /// Retained memory is never returned to the store, so a phase that
    /// exhausts its own window cannot reach capacity reserved for a later
    /// phase.
    #[cfg(test)]
    pub fn open_phase(&mut self, limit: usize) {
        self.phase_start_allocated = self.allocated;
        self.phase_limit = Some(limit);
    }
    /// Cumulative allocated linear-memory bytes.
    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        self.allocated
    }
}
fn size(value: i32) -> Result<usize, wasmi::Error> {
    usize::try_from(value).map_err(|_| trap())
}
fn integer(value: usize) -> HostResult {
    i32::try_from(value).map_err(|_| trap())
}
fn charge(caller: &mut Caller<'_, HostState>, bytes: usize) -> Result<(), wasmi::Error> {
    let gas: u64 = u64::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(LOCAL_HOST_BYTE_GAS))
        .and_then(|gas| gas.checked_add(LOCAL_HOST_BASE_GAS))
        .ok_or_else(trap)?;
    debit(caller, gas)
}
fn charge_bytes(caller: &mut Caller<'_, HostState>, bytes: usize) -> Result<(), wasmi::Error> {
    let gas: u64 = u64::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(LOCAL_HOST_BYTE_GAS))
        .ok_or_else(trap)?;
    debit(caller, gas)
}
fn debit(caller: &mut Caller<'_, HostState>, gas: u64) -> Result<(), wasmi::Error> {
    let fuel: u64 = caller.get_fuel()?;
    let Some(remaining) = fuel.checked_sub(gas) else {
        caller.set_fuel(0)?;
        return Err(trap());
    };
    caller.set_fuel(remaining)?;
    Ok(())
}
fn memory(caller: &Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
        .ok_or_else(trap)
}
fn range(
    caller: &Caller<'_, HostState>,
    pointer: i32,
    length: usize,
) -> Result<(Memory, usize), wasmi::Error> {
    let offset: usize = size(pointer)?;
    let memory: Memory = memory(caller)?;
    if offset
        .checked_add(length)
        .is_none_or(|end| end > memory.data(caller).len())
    {
        return Err(trap());
    }
    Ok((memory, offset))
}
// Debit before any allocation derived from guest lengths.
fn read(
    caller: &mut Caller<'_, HostState>,
    pointer: i32,
    length: i32,
) -> Result<Vec<u8>, wasmi::Error> {
    let length: usize = size(length)?;
    charge_bytes(caller, length)?;
    let (memory, offset) = range(caller, pointer, length)?;
    let mut bytes: Vec<u8> = vec![0; length];
    memory
        .read(&*caller, offset, &mut bytes)
        .map_err(|_| trap())?;
    Ok(bytes)
}
fn write(
    caller: &mut Caller<'_, HostState>,
    pointer: i32,
    capacity: i32,
    bytes: &[u8],
) -> HostResult {
    let capacity: usize = size(capacity)?;
    if bytes.len() > capacity {
        return Err(trap());
    }
    charge_bytes(caller, bytes.len())?;
    let (memory, offset) = range(caller, pointer, capacity)?;
    memory
        .write(&mut *caller, offset, bytes)
        .map_err(|_| trap())?;
    integer(bytes.len())
}
fn frame(state: &HostState) -> Result<&Frame, wasmi::Error> {
    state.frames.last().ok_or_else(trap)
}
fn grant(state: &HostState, handle: i32) -> Result<Grant, wasmi::Error> {
    let mut grant: Grant = *frame(state)?.grants.get(size(handle)?).ok_or_else(trap)?;
    let item: &ArenaObject = state.arena.get(grant.index).ok_or_else(trap)?;
    if item.consumed {
        return Err(trap());
    }
    if item.transferred {
        grant.mode = ObjectMode::Read;
    }
    Ok(grant)
}
fn writable(state: &HostState, handle: i32, consume: bool) -> Result<usize, wasmi::Error> {
    let grant: Grant = grant(state, handle)?;
    let item: &ArenaObject = &state.arena[grant.index];
    if grant.mode == ObjectMode::Read
        || (consume && grant.mode != ObjectMode::Consume)
        || item.authority.code != frame(state)?.code
        || item.object.owner != Owner::Address(Address::new(state.sender))
        || item.authority.instance != state.scopes[frame(state)?.scope].target
        || item.authority.instance_context != state.scopes[frame(state)?.scope].instance.context
    {
        return Err(trap());
    }
    Ok(grant.index)
}
fn owner(bytes: &[u8]) -> Result<Owner, wasmi::Error> {
    let address: [u8; 32] = bytes.try_into().map_err(|_| trap())?;
    validate_ed25519_owner_address(&address, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)
        .map_err(|_| trap())?;
    Ok(Owner::Address(Address::new(address)))
}
fn own_body(
    state: &HostState,
    tag: &[u8],
    body: &[u8],
) -> Result<(abi::package_types::ScopedTypeTag, u32), wasmi::Error> {
    let ty = decode_scoped_type_tag(tag).map_err(|_| trap())?;
    let frame: &Frame = frame(state)?;
    if ty.origin() != frame.code.origin() {
        return Err(trap());
    }
    let schema: u32 = frame
        .interface
        .abi()
        .constructors
        .iter()
        .find(|constructor| constructor.local_id == ty.constructor())
        .ok_or_else(trap)?
        .schema;
    publication::validate_nominal_body(&frame.interface, &ty, schema, body).map_err(|_| trap())?;
    Ok((ty, schema))
}

/// Rejects every DR-0124 object-result selector unless BOTH the committed
/// execution policy and the executing frame's own admitted artifact are
/// profile four. Module admission already restricts these imports to
/// profile-four code; this is the runtime half of the same rule, so a
/// profile-two or profile-three policy can never reach typed-result
/// behaviour even if a module were somehow linked against it.
fn require_object_result_profile(caller: &Caller<'_, HostState>) -> Result<(), wasmi::Error> {
    let state: &HostState = caller.data();
    if state.profile != crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION
        || frame(state)?
            .interface
            .candidate()
            .request()
            .artifact()
            .wasm_profile()
            != crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION
    {
        return Err(trap());
    }
    Ok(())
}

/// Prevalidates the guest's fixed-length result output buffer against the
/// declared slot count before any caller-visible grant mutation, so a
/// too-small or out-of-bounds buffer can never leave the receiving frame
/// holding a partially delivered batch.
fn check_result_buffer(
    caller: &Caller<'_, HostState>,
    pointer: i32,
    capacity: i32,
    slots: usize,
) -> Result<(), wasmi::Error> {
    let needed: usize = slots.checked_mul(4).ok_or_else(trap)?;
    let capacity: usize = size(capacity)?;
    if needed > capacity {
        return Err(trap());
    }
    range(caller, pointer, capacity)?;
    Ok(())
}

pub(super) fn linker(engine: &Engine) -> Result<Linker<HostState>, wasmi::Error> {
    let mut linker: Linker<HostState> = Linker::new(engine);
    linker.func_wrap(
        "sunrise",
        "get_object_count",
        |mut caller: Caller<'_, HostState>| -> HostResult {
            charge(&mut caller, 0)?;
            integer(frame(caller.data())?.grants.len())
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_object_data_len",
        |mut caller: Caller<'_, HostState>, handle: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let grant = grant(caller.data(), handle)?;
            integer(caller.data().arena[grant.index].object.data.len())
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "read_object_data",
        |mut caller: Caller<'_, HostState>,
         handle: i32,
         offset: i32,
         out: i32,
         length: i32|
         -> HostResult {
            charge(&mut caller, 0)?;
            let grant = grant(caller.data(), handle)?;
            let body: &[u8] = &caller.data().arena[grant.index].object.data;
            let start: usize = size(offset)?;
            let capacity: usize = size(length)?;
            let available: &[u8] = body.get(start..).ok_or_else(trap)?;
            let bytes: Vec<u8> = available[..available.len().min(capacity)].to_vec();
            write(&mut caller, out, length, &bytes)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "write_object_data",
        |mut caller: Caller<'_, HostState>, handle: i32, ptr: i32, len: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let bytes: Vec<u8> = read(&mut caller, ptr, len)?;
            let index: usize = writable(caller.data(), handle, false)?;
            let item: &ArenaObject = &caller.data().arena[index];
            publication::validate_nominal_body(
                &frame(caller.data())?.interface,
                &item.authority.ty,
                item.object.schema_version,
                &bytes,
            )
            .map_err(|_| trap())?;
            let charged: usize = bytes
                .len()
                .checked_add(OUTPUT_OBJECT_OVERHEAD_BYTES)
                .ok_or_else(trap)?;
            caller.data_mut().output.charge(charged)?;
            let item: &mut ArenaObject = &mut caller.data_mut().arena[index];
            item.object.data = bytes;
            item.dirty = true;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "consume_object",
        |mut caller: Caller<'_, HostState>, handle: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let index: usize = writable(caller.data(), handle, true)?;
            // Consuming an object the invocation did not itself create emits
            // a `Deleted` effect (id + version, no body) at collection time;
            // charge its conservative encoded overhead before the consuming
            // mutation, exactly like a create or a write. Consuming a
            // same-invocation creation produces no effect at all, so it is
            // never charged here.
            if caller.data().arena[index].original.is_some() {
                caller
                    .data_mut()
                    .output
                    .charge(OUTPUT_OBJECT_OVERHEAD_BYTES)?;
            }
            caller.data_mut().arena[index].consumed = true;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "transfer_object",
        |mut caller: Caller<'_, HostState>, handle: i32, ptr: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let bytes: Vec<u8> = read(&mut caller, ptr, 32)?;
            let owner: Owner = owner(&bytes)?;
            let index: usize = writable(caller.data(), handle, false)?;
            let current: &Frame = frame(caller.data())?;
            let metadata = current
                .interface
                .executable_abi(current.code.origin())
                .ok_or_else(trap)?;
            if !metadata
                .transferable_constructors
                .contains(&caller.data().arena[index].authority.ty.constructor())
            {
                return Err(trap());
            }
            // A transfer always leaves the object `dirty`, so it always
            // produces a `Mutated` effect at collection time that re-encodes
            // the object's full current body, not just the 32-byte new
            // owner. Charge that prospective body-plus-overhead cost before
            // any mutation, exactly like a body write, so a transfer can
            // never emit output the phase or global ceiling never saw.
            let charged: usize = caller.data().arena[index]
                .object
                .data
                .len()
                .checked_add(OUTPUT_OBJECT_OVERHEAD_BYTES)
                .ok_or_else(trap)?;
            caller.data_mut().output.charge(charged)?;
            let item: &mut ArenaObject = &mut caller.data_mut().arena[index];
            item.object.owner = owner;
            item.transferred = true;
            item.dirty = true;
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "create_object",
        |mut caller: Caller<'_, HostState>,
         tp: i32,
         tl: i32,
         op: i32,
         bp: i32,
         bl: i32|
         -> HostResult {
            charge(&mut caller, 0)?;
            let tag: Vec<u8> = read(&mut caller, tp, tl)?;
            let address: Vec<u8> = read(&mut caller, op, 32)?;
            let body: Vec<u8> = read(&mut caller, bp, bl)?;
            let owner: Owner = owner(&address)?;
            let (ty, schema) = own_body(caller.data(), &tag, &body)?;
            caller.data().admit_creations(1)?;
            caller.data().admit_handles(1)?;
            let charged: usize = body
                .len()
                .checked_add(OUTPUT_OBJECT_OVERHEAD_BYTES)
                .ok_or_else(trap)?;
            caller.data_mut().output.charge(charged)?;
            let state: &HostState = caller.data();
            let current: &Frame = frame(state)?;
            let id = derive_local_created_object_id(
                &state.resolver,
                &state.context,
                &state.scopes[frame(state)?.scope].instance.context,
                &state.scopes[frame(state)?.scope].target,
                &current.code,
                state.event,
                state.creations,
            )
            .map_err(|_| trap())?;
            if state.arena.iter().any(|item| item.object.id == id) {
                return Err(trap());
            }
            let type_hash = derive_scoped_type_id(&state.resolver, state.context.epoch(), &ty)
                .map_err(|_| trap())?;
            let authority: ObjectAuthority = ObjectAuthority {
                object_id: id,
                instance_context: state.scopes[frame(state)?.scope].instance.context.clone(),
                instance: state.scopes[frame(state)?.scope].target.clone(),
                code: current.code.clone(),
                ty,
            };
            let mode: ObjectMode = if owner == Owner::Address(Address::new(state.sender)) {
                ObjectMode::Consume
            } else {
                ObjectMode::Read
            };
            let object: Object = Object {
                id,
                version: 1,
                owner,
                type_hash,
                schema_version: schema,
                data: body,
            };
            let state: &mut HostState = caller.data_mut();
            state.handles = state.handles.checked_add(1).ok_or_else(trap)?;
            let index: usize = state.arena.len();
            state.arena.push(ArenaObject {
                object,
                original: None,
                authority,
                ordinal: Some(state.creations),
                consumed: false,
                transferred: false,
                dirty: false,
            });
            state.creations = state.creations.checked_add(1).ok_or_else(trap)?;
            let current: &mut Frame = state.frames.last_mut().ok_or_else(trap)?;
            let handle: usize = current.grants.len();
            current.grants.push(Grant { index, mode });
            integer(handle)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_args_len",
        |mut caller: Caller<'_, HostState>| -> HostResult {
            charge(&mut caller, 0)?;
            integer(frame(caller.data())?.args.len())
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "read_args",
        |mut caller: Caller<'_, HostState>, offset: i32, out: i32, length: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let capacity: usize = size(length)?;
            let available: &[u8] = frame(caller.data())?
                .args
                .get(size(offset)?..)
                .ok_or_else(trap)?;
            let bytes: Vec<u8> = available[..available.len().min(capacity)].to_vec();
            write(&mut caller, out, length, &bytes)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_caller",
        |mut caller: Caller<'_, HostState>, out: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let bytes: [u8; 32] = caller.data().sender;
            write(&mut caller, out, 32, &bytes)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_instance",
        |mut caller: Caller<'_, HostState>, out: i32, length: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let bytes: Vec<u8> = caller.data().instance_bytes[frame(caller.data())?.scope].clone();
            write(&mut caller, out, length, &bytes)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "emit_event",
        |mut caller: Caller<'_, HostState>, tp: i32, tl: i32, bp: i32, bl: i32| -> HostResult {
            charge(&mut caller, 0)?;
            let tag: Vec<u8> = read(&mut caller, tp, tl)?;
            let body: Vec<u8> = read(&mut caller, bp, bl)?;
            own_body(caller.data(), &tag, &body)?;
            caller.data().admit_events(1)?;
            // Monotonic regardless of any later savepoint rollback: this
            // counter is what phase and global event budgets are measured
            // against, never the truncatable retained log.
            caller.data_mut().emitted_events = caller
                .data()
                .emitted_events
                .checked_add(1)
                .ok_or_else(trap)?;
            let charged: usize = tag
                .len()
                .checked_add(body.len())
                .and_then(|bytes| bytes.checked_add(OUTPUT_EVENT_OVERHEAD_BYTES))
                .ok_or_else(trap)?;
            caller.data_mut().output.charge(charged)?;
            caller.data_mut().events.push(EventRecord {
                type_tag: tag,
                data: body,
            });
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "abort",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> Result<(), wasmi::Error> {
            charge(&mut caller, 0)?;
            let _bytes: Vec<u8> = read(&mut caller, ptr, len)?;
            Err(trap())
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_object_id",
        |mut caller: Caller<'_, HostState>, handle: i32, out: i32| -> HostResult {
            charge(&mut caller, 0)?;
            require_object_result_profile(&caller)?;
            let grant = grant(caller.data(), handle)?;
            let bytes: [u8; 32] = *caller.data().arena[grant.index].object.id.as_bytes();
            write(&mut caller, out, 32, &bytes)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "get_object_type",
        |mut caller: Caller<'_, HostState>, handle: i32, out: i32, capacity: i32| -> HostResult {
            charge(&mut caller, 0)?;
            require_object_result_profile(&caller)?;
            let grant = grant(caller.data(), handle)?;
            let ty = caller.data().arena[grant.index].authority.ty.clone();
            let encoded: Vec<u8> = encode_scoped_type_tag(&ty).map_err(|_| trap())?;
            write(&mut caller, out, capacity, &encoded)
        },
    )?;
    linker.func_wrap(
        "sunrise",
        "return_object",
        |mut caller: Caller<'_, HostState>, slot: i32, handle: i32| -> HostResult {
            charge(&mut caller, 0)?;
            require_object_result_profile(&caller)?;
            let slot_index: usize = size(slot)?;
            let grant: Grant = grant(caller.data(), handle)?;
            let state: &HostState = caller.data();
            let current: &Frame = frame(state)?;
            let declared: BoundObjectResult = current
                .declared_results
                .get(slot_index)
                .ok_or_else(trap)?
                .clone();
            if current.returned.get(slot_index).ok_or_else(trap)?.is_some() {
                return Err(trap());
            }
            if current
                .returned
                .iter()
                .flatten()
                .any(|existing| existing.index == grant.index)
            {
                return Err(trap());
            }
            let object: &ArenaObject = &state.arena[grant.index];
            // Returning a grant is not a write: any current unconsumed
            // handle right up to the declared mode ceiling may be
            // delivered, including Read of a foreign-owned object or a
            // forwarded dependency-defined grant. Ownership/defining-code
            // authority still gates any later mutation through `writable`.
            let provenance_ok: bool = state.scopes.iter().any(|scope| {
                scope.target == object.authority.instance
                    && scope.instance.context == object.authority.instance_context
            });
            if rank(declared.mode()) > rank(grant.mode)
                || declared.ty() != &object.authority.ty
                || declared.schema() != object.object.schema_version
                || !provenance_ok
            {
                return Err(trap());
            }
            publication::validate_nominal_body(
                &current.interface,
                declared.ty(),
                declared.schema(),
                &object.object.data,
            )
            .map_err(|_| trap())?;
            let mode: ObjectMode = declared.mode();
            let index: usize = grant.index;
            let current: &mut Frame = caller.data_mut().frames.last_mut().ok_or_else(trap)?;
            current.returned[slot_index] = Some(Grant { index, mode });
            Ok(0)
        },
    )?;
    linker.func_wrap("sunrise", "call_dependency", dependency)?;
    linker.func_wrap("sunrise", "call_contract", contract)?;
    linker.func_wrap(
        "sunrise",
        "call_dependency_with_results",
        dependency_with_results,
    )?;
    linker.func_wrap(
        "sunrise",
        "call_contract_with_results",
        contract_with_results,
    )?;
    Ok(linker)
}

/// The sole frame-entry validator, used by root, dependency and authorization selectors.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_frame(
    state: &HostState,
    scope: usize,
    code: UnverifiedDependencyRef,
    entry: &str,
    types: &[abi::package_types::ScopedTypeArg],
    supplied: Vec<Grant>,
    args: Vec<u8>,
    root: Option<LocalExecutionMode>,
) -> Result<Frame, wasmi::Error> {
    if state.frames.len() >= MAX_LOCAL_EXECUTION_DEPTH as usize
        || args.len() > crate::call::MAX_CALL_ARGUMENT_BYTES
    {
        return Err(trap());
    }
    state.admit_calls(1)?;
    state.admit_handles(supplied.len())?;
    let selected = state.scopes.get(scope).ok_or_else(trap)?;
    if state
        .frames
        .iter()
        .any(|active| state.scopes[active.scope].target == selected.target && active.code == code)
    {
        return Err(trap());
    }
    let interface = selected
        .interface
        .for_origin(code.origin())
        .map_err(|_| trap())?;
    if reference(&interface).map_err(|_| trap())? != code {
        return Err(trap());
    }
    let metadata = interface.executable_abi(code.origin()).ok_or_else(trap)?;
    match root {
        Some(LocalExecutionMode::Instantiate)
            if state.frames.is_empty()
                && scope == 0
                && code == selected.instance.code
                && metadata.initializer.as_deref() == Some(entry) => {}
        Some(LocalExecutionMode::Instantiate) => return Err(trap()),
        _ if metadata.initializer.as_deref() == Some(entry) => return Err(trap()),
        _ => {}
    }
    let signature =
        publication::bind_object_signature(&interface, entry, types).map_err(|_| trap())?;
    publication::validate_call_arguments(&signature, &args).map_err(|_| trap())?;
    if signature.objects().len() != supplied.len() {
        return Err(trap());
    }
    let mut unique: BTreeSet<usize> = BTreeSet::new();
    let mut grants: Vec<Grant> = Vec::with_capacity(supplied.len());
    for (supplied, parameter) in supplied.iter().zip(signature.objects()) {
        let object = state.arena.get(supplied.index).ok_or_else(trap)?;
        let current = if object.transferred {
            ObjectMode::Read
        } else {
            supplied.mode
        };
        if object.consumed
            || !unique.insert(supplied.index)
            || rank(parameter.mode()) > rank(current)
            || parameter.ty() != &object.authority.ty
            || parameter.schema() != object.object.schema_version
        {
            return Err(trap());
        }
        publication::validate_nominal_body(
            &interface,
            parameter.ty(),
            parameter.schema(),
            &object.object.data,
        )
        .map_err(|_| trap())?;
        grants.push(Grant {
            index: supplied.index,
            mode: parameter.mode(),
        });
    }
    let declared_results: Vec<BoundObjectResult> = signature.results().to_vec();
    let returned: Vec<Option<Grant>> = vec![None; declared_results.len()];
    Ok(Frame {
        scope,
        interface,
        code,
        grants,
        args,
        declared_results,
        returned,
    })
}
fn rank(mode: ObjectMode) -> u8 {
    match mode {
        ObjectMode::Read => 0,
        ObjectMode::Write => 1,
        ObjectMode::Consume => 2,
    }
}
pub(super) fn object_mode(mode: objects::AccessMode) -> ObjectMode {
    match mode {
        objects::AccessMode::Read => ObjectMode::Read,
        objects::AccessMode::Write => ObjectMode::Write,
        objects::AccessMode::Consume => ObjectMode::Consume,
    }
}
fn read_handles(
    caller: &mut Caller<'_, HostState>,
    pointer: i32,
    count: i32,
) -> Result<Vec<Grant>, wasmi::Error> {
    let count: usize = size(count)?;
    if count > crate::call_authorization::MAX_AUTHORIZED_INPUTS {
        return Err(trap());
    }
    let length: i32 = i32::try_from(count.checked_mul(4).ok_or_else(trap)?).map_err(|_| trap())?;
    let bytes: Vec<u8> = read(caller, pointer, length)?;
    let mut grants: Vec<Grant> = Vec::with_capacity(count);
    for handle in bytes.chunks_exact(4) {
        let value: u32 = u32::from_le_bytes(handle.try_into().map_err(|_| trap())?);
        grants.push(grant(
            caller.data(),
            i32::try_from(value).map_err(|_| trap())?,
        )?);
    }
    Ok(grants)
}
fn enter<'c>(
    mut caller: Caller<'c, HostState>,
    prepared: Frame,
    entry: &str,
) -> Result<(Caller<'c, HostState>, Frame), wasmi::Error> {
    let module: Arc<Module> = Arc::clone(
        caller
            .data()
            .modules
            .get(prepared.code.origin())
            .ok_or_else(trap)?,
    );
    let linker: Arc<Linker<HostState>> = Arc::clone(&caller.data().linker);
    let state = caller.data_mut();
    state.handles = state
        .handles
        .checked_add(prepared.grants.len())
        .ok_or_else(trap)?;
    state.calls = state.calls.checked_add(1).ok_or_else(trap)?;
    state.frames.push(prepared);
    let result: Result<(), wasmi::Error> = (|| {
        let instance = linker.instantiate_and_start(&mut caller, &module)?;
        let function = instance.get_typed_func::<(), ()>(&caller, entry)?;
        function.call(&mut caller, ())
    })();
    let finished: Frame = caller.data_mut().frames.pop().ok_or_else(trap)?;
    result?;
    validate_returned_slots(caller.data(), &finished)?;
    Ok((caller, finished))
}

/// Returns the frame's current effective right over `index`, or `None` if
/// the underlying object is consumed or the frame holds no grant for it.
/// Mirrors `grant`'s per-handle transferred-downgrade rule, but keyed by
/// arena index since a returned slot only records the index.
fn effective_mode(state: &HostState, owning_frame: &Frame, index: usize) -> Option<ObjectMode> {
    let item: &ArenaObject = state.arena.get(index)?;
    if item.consumed {
        return None;
    }
    let held: ObjectMode = owning_frame
        .grants
        .iter()
        .find(|grant| grant.index == index)?
        .mode;
    if item.transferred {
        Some(ObjectMode::Read)
    } else {
        Some(held)
    }
}

/// Revalidates every present result slot against the FINAL arena state and
/// the frame's current effective grant rights, after every callee
/// instruction has run. A slot set by `return_object` and later consumed,
/// transferred (including self-transfer attenuation), or otherwise
/// invalidated must never deliver a stale capability. Required slots must
/// still be filled. Called for every nested frame before delivery/drop and
/// for the root frame before its results are dropped.
pub(super) fn validate_returned_slots(
    state: &HostState,
    owning_frame: &Frame,
) -> Result<(), wasmi::Error> {
    for (declared, slot) in owning_frame
        .declared_results
        .iter()
        .zip(&owning_frame.returned)
    {
        match slot {
            None => {
                if !declared.optional() {
                    return Err(trap());
                }
            }
            Some(grant) => {
                let object: &ArenaObject = state.arena.get(grant.index).ok_or_else(trap)?;
                let effective: ObjectMode =
                    effective_mode(state, owning_frame, grant.index).ok_or_else(trap)?;
                if rank(declared.mode()) > rank(effective)
                    || declared.ty() != &object.authority.ty
                    || declared.schema() != object.object.schema_version
                {
                    return Err(trap());
                }
            }
        }
    }
    Ok(())
}

/// Delivers a finished callee's set result slots into the receiving (parent)
/// frame's own handle namespace as new grants, checked against duplicate
/// aliases already held by the receiver, and bumps the permanent cumulative
/// handle counter. Returns a fixed-length sentinel array (one `u32` per
/// declared slot, in slot order): the new parent-local handle index, or
/// `ABSENT_RESULT_SLOT` for a slot delivered absent. Never compacted.
fn deliver_results(state: &mut HostState, finished: &Frame) -> Result<Vec<u32>, wasmi::Error> {
    let filled: usize = finished
        .returned
        .iter()
        .filter(|slot| slot.is_some())
        .count();
    state.admit_handles(filled)?;
    let next_handles: usize = state.handles.checked_add(filled).ok_or_else(trap)?;
    // Prevalidate the entire batch before any caller-visible mutation: an
    // alias against a handle the receiver already holds, or a duplicate
    // within the batch itself, rejects the whole delivery rather than
    // leaving the receiver with a prefix of it.
    let parent: &Frame = state.frames.last().ok_or_else(trap)?;
    let mut seen: BTreeSet<usize> = parent.grants.iter().map(|grant| grant.index).collect();
    let mut sentinel: Vec<u32> = Vec::with_capacity(finished.returned.len());
    let mut next: usize = parent.grants.len();
    for slot in &finished.returned {
        match slot {
            Some(grant) => {
                if !seen.insert(grant.index) {
                    return Err(trap());
                }
                let handle: u32 = u32::try_from(next).map_err(|_| trap())?;
                // A real handle must never collide with the absence sentinel.
                if handle == ABSENT_RESULT_SLOT {
                    return Err(trap());
                }
                sentinel.push(handle);
                next = next.checked_add(1).ok_or_else(trap)?;
            }
            None => sentinel.push(ABSENT_RESULT_SLOT),
        }
    }
    let parent: &mut Frame = state.frames.last_mut().ok_or_else(trap)?;
    parent
        .grants
        .extend(finished.returned.iter().flatten().copied());
    state.handles = next_handles;
    Ok(sentinel)
}

fn encode_result_sentinel(sentinel: &[u32]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(sentinel.len() * 4);
    for value in sentinel {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}
#[allow(clippy::too_many_arguments)]
fn dependency(
    mut caller: Caller<'_, HostState>,
    dependency: i32,
    ep: i32,
    el: i32,
    tp: i32,
    tl: i32,
    hp: i32,
    hc: i32,
    ap: i32,
    al: i32,
) -> HostResult {
    charge(&mut caller, 0)?;
    debit(&mut caller, LOCAL_LIBRARY_BINDING_GAS)?;
    let entry: String = String::from_utf8(read(&mut caller, ep, el)?).map_err(|_| trap())?;
    let types: Vec<u8> = read(&mut caller, tp, tl)?;
    let grants: Vec<Grant> = read_handles(&mut caller, hp, hc)?;
    let args: Vec<u8> = read(&mut caller, ap, al)?;
    let parent = frame(caller.data())?;
    let code = parent
        .interface
        .candidate()
        .request()
        .artifact()
        .unverified_dependencies()
        .get(size(dependency)?)
        .ok_or_else(trap)?
        .clone();
    let types = decode_scoped_type_arguments(caller.data().context.chain_id(), &types)
        .map_err(|_| trap())?;
    let prepared = prepare_frame(
        caller.data(),
        parent.scope,
        code,
        &entry,
        &types,
        grants,
        args,
        None,
    )?;
    enter(caller, prepared, &entry)?;
    Ok(0)
}
#[allow(clippy::too_many_arguments)]
fn dependency_with_results(
    mut caller: Caller<'_, HostState>,
    dependency: i32,
    ep: i32,
    el: i32,
    tp: i32,
    tl: i32,
    hp: i32,
    hc: i32,
    ap: i32,
    al: i32,
    rp: i32,
    rc: i32,
) -> HostResult {
    charge(&mut caller, 0)?;
    require_object_result_profile(&caller)?;
    debit(&mut caller, LOCAL_LIBRARY_BINDING_GAS)?;
    let entry: String = String::from_utf8(read(&mut caller, ep, el)?).map_err(|_| trap())?;
    let types: Vec<u8> = read(&mut caller, tp, tl)?;
    let grants: Vec<Grant> = read_handles(&mut caller, hp, hc)?;
    let args: Vec<u8> = read(&mut caller, ap, al)?;
    let parent = frame(caller.data())?;
    let code = parent
        .interface
        .candidate()
        .request()
        .artifact()
        .unverified_dependencies()
        .get(size(dependency)?)
        .ok_or_else(trap)?
        .clone();
    let types = decode_scoped_type_arguments(caller.data().context.chain_id(), &types)
        .map_err(|_| trap())?;
    let prepared = prepare_frame(
        caller.data(),
        parent.scope,
        code,
        &entry,
        &types,
        grants,
        args,
        None,
    )?;
    let (mut caller, finished) = enter(caller, prepared, &entry)?;
    check_result_buffer(&caller, rp, rc, finished.returned.len())?;
    let sentinel: Vec<u32> = deliver_results(caller.data_mut(), &finished)?;
    let encoded: Vec<u8> = encode_result_sentinel(&sentinel);
    write(&mut caller, rp, rc, &encoded)
}
fn contract(
    mut caller: Caller<'_, HostState>,
    authorization: i32,
    hp: i32,
    hc: i32,
    ap: i32,
    al: i32,
) -> HostResult {
    charge(&mut caller, 0)?;
    debit(&mut caller, LOCAL_LIBRARY_BINDING_GAS)?;
    let parent = frame(caller.data())?;
    // The general selector stays available under the profile-four superset.
    if !matches!(caller.data().profile, 3 | 4)
        || !matches!(
            parent
                .interface
                .candidate()
                .request()
                .artifact()
                .wasm_profile(),
            3 | 4
        )
    {
        return Err(trap());
    }
    let authorization = caller
        .data()
        .authorizations
        .get(size(authorization)?)
        .ok_or_else(trap)?
        .clone();
    if authorization.caller.code != parent.code
        || authorization.caller.instance != caller.data().scopes[parent.scope].target
    {
        return Err(trap());
    }
    if size(al)? > crate::call::MAX_CALL_ARGUMENT_BYTES {
        return Err(trap());
    }
    let mut grants: Vec<Grant> = read_handles(&mut caller, hp, hc)?;
    let args: Vec<u8> = read(&mut caller, ap, al)?;
    if grants.len() != authorization.objects.len() {
        return Err(trap());
    }
    for (grant, ceiling) in grants.iter_mut().zip(&authorization.objects) {
        let object = &caller.data().arena[grant.index];
        if object.original.is_none() || object.object.id != ceiling.object_id {
            return Err(trap());
        }
        let maximum = object_mode(ceiling.mode);
        if rank(maximum) < rank(grant.mode) {
            grant.mode = maximum;
        }
    }
    let scope = super::admission::selected_scope(&caller.data().scopes, &authorization.callee)
        .map_err(|_| trap())?;
    let prepared = prepare_frame(
        caller.data(),
        scope,
        authorization.callee.code,
        &authorization.entrypoint,
        &authorization.type_arguments,
        grants,
        args,
        None,
    )?;
    enter(caller, prepared, &authorization.entrypoint)?;
    Ok(0)
}
#[allow(clippy::too_many_arguments)]
fn contract_with_results(
    mut caller: Caller<'_, HostState>,
    authorization: i32,
    hp: i32,
    hc: i32,
    ap: i32,
    al: i32,
    rp: i32,
    rc: i32,
) -> HostResult {
    charge(&mut caller, 0)?;
    require_object_result_profile(&caller)?;
    debit(&mut caller, LOCAL_LIBRARY_BINDING_GAS)?;
    let parent = frame(caller.data())?;
    let authorization = caller
        .data()
        .authorizations
        .get(size(authorization)?)
        .ok_or_else(trap)?
        .clone();
    if authorization.caller.code != parent.code
        || authorization.caller.instance != caller.data().scopes[parent.scope].target
    {
        return Err(trap());
    }
    if size(al)? > crate::call::MAX_CALL_ARGUMENT_BYTES {
        return Err(trap());
    }
    let mut grants: Vec<Grant> = read_handles(&mut caller, hp, hc)?;
    let args: Vec<u8> = read(&mut caller, ap, al)?;
    if grants.len() != authorization.objects.len() {
        return Err(trap());
    }
    for (grant, ceiling) in grants.iter_mut().zip(&authorization.objects) {
        let object = &caller.data().arena[grant.index];
        if object.original.is_none() || object.object.id != ceiling.object_id {
            return Err(trap());
        }
        let maximum = object_mode(ceiling.mode);
        if rank(maximum) < rank(grant.mode) {
            grant.mode = maximum;
        }
    }
    let scope = super::admission::selected_scope(&caller.data().scopes, &authorization.callee)
        .map_err(|_| trap())?;
    let prepared = prepare_frame(
        caller.data(),
        scope,
        authorization.callee.code,
        &authorization.entrypoint,
        &authorization.type_arguments,
        grants,
        args,
        None,
    )?;
    let (mut caller, finished) = enter(caller, prepared, &authorization.entrypoint)?;
    check_result_buffer(&caller, rp, rc, finished.returned.len())?;
    let sentinel: Vec<u32> = deliver_results(caller.data_mut(), &finished)?;
    let encoded: Vec<u8> = encode_result_sentinel(&sentinel);
    write(&mut caller, rp, rc, &encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_accounting_is_unbounded_until_a_ceiling_is_installed() {
        // The historical zero-fee path installs no ceiling, so its accepted
        // executions are unchanged by the introduction of accounting.
        let mut account: OutputAccount = OutputAccount::default();
        account.charge(usize::MAX / 2).expect("first charge");
        account.charge(1).expect("second charge");
        assert_eq!(account.used(), usize::MAX / 2 + 1);
    }

    #[test]
    fn output_accounting_rejects_the_byte_that_crosses_a_ceiling() {
        let mut account: OutputAccount = OutputAccount::default();
        account.set_limit(100);
        account
            .charge(100)
            .expect("exactly the ceiling is admitted");
        assert!(account.charge(1).is_err());
        assert_eq!(account.used(), 100, "a rejected charge is not applied");
    }

    #[test]
    fn a_phase_output_window_bounds_only_that_phase_and_never_returns_bytes() {
        let mut account: OutputAccount = OutputAccount::default();
        account.set_limit(1_000);
        account.open_phase(10);
        account.charge(10).expect("phase ceiling is admitted");
        // The global ceiling still has room, but this phase does not.
        assert!(account.charge(1).is_err());
        // A new phase window opens over the bytes already charged: earlier
        // consumption is never returned to the invocation.
        account.open_phase(10);
        account.charge(10).expect("second phase window");
        assert_eq!(account.used(), 20);
        account.open_phase(1_000);
        assert!(
            account.charge(981).is_err(),
            "the global ceiling still binds across phases"
        );
    }

    #[test]
    fn phase_budget_admits_exactly_up_to_its_ceiling() {
        // Cumulative counter 5, phase started at 3, ceiling 4: two more
        // units fit, three do not.
        assert!(PhaseBudget::admit(3, 5, 2, 4).is_ok());
        assert!(PhaseBudget::admit(3, 5, 3, 4).is_err());
        // A counter below the phase start is an inconsistency, not a
        // silently forgiven negative usage.
        assert!(PhaseBudget::admit(5, 3, 0, 4).is_err());
    }

    #[test]
    fn a_phase_memory_window_denies_growth_and_flags_the_phase_failed() {
        let mut limiter: RetainedMemory = RetainedMemory::default();
        limiter.open_phase(1_000);
        assert!(limiter.memory_growing(0, 800, Some(65_536)).is_ok());
        assert_eq!(limiter.allocated(), 800);
        assert!(limiter.memory_growing(800, 1_900, Some(65_536)).is_err());
        assert!(limiter.failed);
        // Cumulative allocation is unchanged by the denial, and a new phase
        // window measures only its own growth.
        assert_eq!(limiter.allocated(), 800);
        limiter.failed = false;
        limiter.open_phase(1_000);
        assert!(limiter.memory_growing(800, 1_700, Some(65_536)).is_ok());
        assert_eq!(limiter.allocated(), 1_700);
        assert!(!limiter.failed);
    }

    #[test]
    fn the_global_retained_memory_bound_still_applies_without_a_phase_window() {
        let mut limiter: RetainedMemory = RetainedMemory::default();
        let beyond: usize = MAX_LOCAL_EXECUTION_MEMORY_BYTES as usize + 1;
        assert!(limiter.memory_growing(0, beyond, None).is_err());
        assert!(limiter.failed);
    }

    /// Derives the real canonical-encoder overhead for one `Created`,
    /// `Mutated` or `Deleted` object effect -- including the one list-entry
    /// field the effects list wrapper adds for it -- and checks that
    /// `OUTPUT_OBJECT_OVERHEAD_BYTES` conservatively bounds every variant,
    /// with a fixed body length isolating the per-effect overhead from the
    /// body it carries.
    #[test]
    fn object_overhead_bounds_the_real_encoder() {
        fn effects_len(effects: Vec<ObjectEffect>) -> usize {
            crate::encode_execution_effects(&ExecutionEffects {
                tx_hash: protocol_types::Digest32::new(
                    protocol_types::HashAlgorithmId::Sha2_256,
                    [0u8; 32],
                ),
                status: ExecutionStatus::Success,
                object_effects: effects,
                events: Vec::new(),
                gas_used: 0,
            })
            .expect("encode execution effects")
            .len()
        }
        fn object(data: Vec<u8>) -> Object {
            Object {
                id: objects::ObjectId::new([0x11; 32]),
                version: 1,
                // The largest `Owner` variant: a full 32-byte address, the
                // shape every transfer recipient uses.
                owner: Owner::Address(Address::new([0x22; 32])),
                type_hash: protocol_types::Digest32::new(
                    protocol_types::HashAlgorithmId::Sha2_256,
                    [0x33; 32],
                ),
                schema_version: 7,
                data,
            }
        }
        let empty: usize = effects_len(Vec::new());
        let created: usize = effects_len(vec![ObjectEffect::Created(object(Vec::new()))]);
        let mutated: usize = effects_len(vec![ObjectEffect::Mutated {
            previous_version: 1,
            new_object: object(Vec::new()),
        }]);
        let deleted: usize = effects_len(vec![ObjectEffect::Deleted {
            id: objects::ObjectId::new([0x11; 32]),
            version: 1,
        }]);
        let created_overhead: usize = created - empty;
        let mutated_overhead: usize = mutated - empty;
        let deleted_overhead: usize = deleted - empty;
        assert!(
            created_overhead <= OUTPUT_OBJECT_OVERHEAD_BYTES,
            "created overhead {created_overhead} exceeds the charged bound"
        );
        assert!(
            mutated_overhead <= OUTPUT_OBJECT_OVERHEAD_BYTES,
            "mutated overhead {mutated_overhead} exceeds the charged bound"
        );
        assert!(
            deleted_overhead <= OUTPUT_OBJECT_OVERHEAD_BYTES,
            "deleted overhead {deleted_overhead} exceeds the charged bound"
        );
        // The overhead is a fixed per-effect cost: every additional body
        // byte adds exactly one encoded byte, so charging `body.len() +
        // OUTPUT_OBJECT_OVERHEAD_BYTES` never under-charges a larger body.
        let created_with_body: usize =
            effects_len(vec![ObjectEffect::Created(object(vec![0u8; 100]))]);
        assert_eq!(created_with_body - created, 100);
    }
}
