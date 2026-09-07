//! The guest can name only frame-local handles, never storage keys or object IDs.
use super::*;
use abi::package_types::{
    decode_scoped_type_arguments, decode_scoped_type_tag, derive_scoped_type_id,
};
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use wasmi::{Caller, Memory, ResourceLimiter};
use wasmi_core::LimiterError;

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
    pub interface: VerifiedPublicationInterface,
    pub code: UnverifiedDependencyRef,
    pub grants: Vec<Grant>,
    pub args: Vec<u8>,
}
pub(super) struct HostState {
    pub resolver: HashSuiteResolver,
    pub instance: InstanceRecord,
    pub target: crate::call::InstanceTarget,
    pub context: publication::PublicationContext,
    pub event: protocol_types::Digest32,
    pub sender: [u8; 32],
    pub instance_bytes: Vec<u8>,
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
        || item.authority.instance != state.target
        || item.authority.instance_context != state.instance.context
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
                &state.instance.context,
                &state.target,
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
                instance_context: state.instance.context.clone(),
                instance: state.target.clone(),
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
            let bytes: Vec<u8> = caller.data().instance_bytes.clone();
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
    linker.func_wrap("sunrise", "call_dependency", dependency)?;
    Ok(linker)
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
    let count: usize = size(hc)?;
    if count > 32 {
        return Err(trap());
    }
    let entry: Vec<u8> = read(&mut caller, ep, el)?;
    let entry: String = String::from_utf8(entry).map_err(|_| trap())?;
    let types: Vec<u8> = read(&mut caller, tp, tl)?;
    let handles: Vec<u8> = read(
        &mut caller,
        hp,
        i32::try_from(count.checked_mul(4).ok_or_else(trap)?).map_err(|_| trap())?,
    )?;
    let args: Vec<u8> = read(&mut caller, ap, al)?;
    let state: &HostState = caller.data();
    let handles_allocated: usize = state.handles.checked_add(count).ok_or_else(trap)?;
    if handles_allocated > MAX_LOCAL_OBJECT_HANDLES as usize {
        return Err(trap());
    }
    if state.frames.len() >= MAX_LOCAL_EXECUTION_DEPTH as usize
        || state.calls >= MAX_LOCAL_EXECUTION_CALLS
    {
        return Err(trap());
    }
    let parent: &Frame = frame(state)?;
    let code: UnverifiedDependencyRef = parent
        .interface
        .candidate()
        .request()
        .artifact()
        .unverified_dependencies()
        .get(size(dependency)?)
        .ok_or_else(trap)?
        .clone();
    let interface: VerifiedPublicationInterface = parent
        .interface
        .for_origin(code.origin())
        .map_err(|_| trap())?;
    if reference(&interface).map_err(|_| trap())? != code
        || interface
            .executable_abi(code.origin())
            .ok_or_else(trap)?
            .initializer
            .as_deref()
            == Some(entry.as_str())
    {
        return Err(trap());
    }
    let arguments =
        decode_scoped_type_arguments(state.context.chain_id(), &types).map_err(|_| trap())?;
    let signature =
        publication::bind_object_signature(&interface, &entry, &arguments).map_err(|_| trap())?;
    publication::validate_call_arguments(&signature, &args).map_err(|_| trap())?;
    if signature.objects().len() != count {
        return Err(trap());
    }
    let mut grants: Vec<Grant> = Vec::new();
    let mut unique: BTreeSet<usize> = BTreeSet::new();
    for (bytes, parameter) in handles.chunks_exact(4).zip(signature.objects()) {
        let handle: u32 = u32::from_le_bytes(bytes.try_into().map_err(|_| trap())?);
        let supplied: Grant = grant(state, i32::try_from(handle).map_err(|_| trap())?)?;
        let rank = |mode: ObjectMode| match mode {
            ObjectMode::Read => 0,
            ObjectMode::Write => 1,
            ObjectMode::Consume => 2,
        };
        let item: &ArenaObject = &state.arena[supplied.index];
        if !unique.insert(supplied.index)
            || rank(parameter.mode()) > rank(supplied.mode)
            || parameter.ty() != &item.authority.ty
            || parameter.schema() != item.object.schema_version
        {
            return Err(trap());
        }
        publication::validate_nominal_body(
            &interface,
            parameter.ty(),
            parameter.schema(),
            &item.object.data,
        )
        .map_err(|_| trap())?;
        grants.push(Grant {
            index: supplied.index,
            mode: parameter.mode(),
        });
    }
    let module: Arc<Module> = Arc::clone(state.modules.get(code.origin()).ok_or_else(trap)?);
    let linker: Arc<Linker<HostState>> = Arc::clone(&state.linker);
    let state: &mut HostState = caller.data_mut();
    state.handles = handles_allocated;
    state.calls = state.calls.checked_add(1).ok_or_else(trap)?;
    state.frames.push(Frame {
        interface,
        code,
        grants,
        args,
    });
    let result: Result<(), wasmi::Error> = (|| {
        let instance = linker.instantiate_and_start(&mut caller, &module)?;
        let function = instance.get_typed_func::<(), ()>(&caller, &entry)?;
        function.call(&mut caller, ())
    })();
    caller.data_mut().frames.pop();
    result?;
    Ok(0)
}
