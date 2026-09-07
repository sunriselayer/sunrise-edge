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
    pub creations: u32,
    pub calls: u32,
    // Every allocated selector counts permanently, including popped child aliases.
    pub handles: usize,
}
#[derive(Default)]
pub(super) struct RetainedMemory {
    retained: usize,
    pub failed: bool,
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
        let next: Option<usize> = desired
            .checked_sub(current)
            .and_then(|delta| self.retained.checked_add(delta));
        if maximum.is_some_and(|max| desired > max)
            || next.is_none_or(|n| n > MAX_LOCAL_EXECUTION_MEMORY_BYTES as usize)
        {
            self.failed = true;
            return Err(LimiterError::ResourceLimiterDeniedAllocation);
        }
        self.retained = next.ok_or(LimiterError::ResourceLimiterDeniedAllocation)?;
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
            let state: &HostState = caller.data();
            if state.creations >= MAX_LOCAL_CREATED_OBJECTS
                || state.handles >= MAX_LOCAL_OBJECT_HANDLES as usize
            {
                return Err(trap());
            }
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
            if caller.data().events.len() >= MAX_LOCAL_EXECUTION_EVENTS {
                return Err(trap());
            }
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
        || state.calls >= MAX_LOCAL_EXECUTION_CALLS
        || state
            .handles
            .checked_add(supplied.len())
            .is_none_or(|count| count > MAX_LOCAL_OBJECT_HANDLES as usize)
        || args.len() > crate::call::MAX_CALL_ARGUMENT_BYTES
    {
        return Err(trap());
    }
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
fn object_mode(mode: objects::AccessMode) -> ObjectMode {
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
    let next_handles: usize = state.handles.checked_add(filled).ok_or_else(trap)?;
    if next_handles > MAX_LOCAL_OBJECT_HANDLES as usize {
        return Err(trap());
    }
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
