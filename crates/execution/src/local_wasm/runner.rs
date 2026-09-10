//! Shared interpreter construction, root invocation and effect collection.
//!
//! Every root this engine runs goes through exactly these helpers: the
//! authenticated zero-fee `execute` path and the internal DR-0124 phase
//! coordinator share one store, one host, one frame validator and one
//! effect collector rather than parallel implementations.
use super::*;
use host::{ArenaObject, HostState, RetainedMemory};

/// Builds the pinned interpreter configuration and engine. One engine
/// compiles every admitted module once for the whole invocation.
pub(super) fn interpreter() -> Engine {
    let mut config: Config = Config::default();
    config.consume_fuel(true);
    config.set_min_stack_height(LOCAL_WASM_INITIAL_STACK);
    config.set_max_stack_height(LOCAL_WASM_MAX_STACK);
    config.set_max_recursion_depth(LOCAL_WASM_MAX_RECURSION);
    Engine::new(&config)
}

/// Validates one admitted input against its scope, defining code, exact
/// instance authority, sender ownership, committed nominal type and
/// declared body layout, returning the arena entry the VM will hold.
///
/// Caller-specific obligations stay with the caller: signed access-entry
/// identity/version/mode agreement and per-invocation object uniqueness.
pub(super) fn bind_input(
    resolver: &HashSuiteResolver,
    scopes: &[ResolvedExecutionScope],
    sender: [u8; 32],
    epoch: protocol_types::Epoch,
    input: &ScopedResolvedObject,
) -> Result<ArenaObject, LocalExecutionError> {
    let object: &Object = &input.resolved.object;
    let authority: &ObjectAuthority = &input.authority;
    let scope: &ResolvedExecutionScope = scopes
        .iter()
        .find(|scope| {
            scope.target == authority.instance
                && scope.instance.context == authority.instance_context
        })
        .ok_or(LocalExecutionError::Invalid("input scope"))?;
    let defining = scope
        .interface
        .for_origin(authority.ty.origin())
        .map_err(|_| LocalExecutionError::Invalid("input defining code"))?;
    if object.owner != Owner::Address(Address::new(sender))
        || authority.object_id != object.id
        || authority.code != reference(&defining)?
        || !abi::package_types::verify_scoped_type_id(
            resolver,
            &object.type_hash,
            epoch,
            &authority.ty,
        )?
    {
        return Err(LocalExecutionError::Invalid("input authority"));
    }
    publication::validate_nominal_body(
        &defining,
        &authority.ty,
        object.schema_version,
        &object.data,
    )
    .map_err(|_| LocalExecutionError::Invalid("input body"))?;
    Ok(ArenaObject {
        object: object.clone(),
        original: Some(object.clone()),
        authority: authority.clone(),
        ordinal: None,
        consumed: false,
        transferred: false,
        dirty: false,
    })
}

/// Accumulates the bounded aggregate input-body allowance.
pub(super) fn accumulate_body_bytes(
    total: &mut usize,
    object: &Object,
) -> Result<(), LocalExecutionError> {
    *total = total
        .checked_add(object.data.len())
        .ok_or(LocalExecutionError::Limit("input body"))?;
    if *total > publication::MAX_BOUND_BODY_BYTES {
        return Err(LocalExecutionError::Limit("input body"));
    }
    Ok(())
}

/// Immutable per-invocation inputs of the host state.
pub(super) struct StateParts<'a> {
    /// Trusted hash history.
    pub resolver: &'a HashSuiteResolver,
    /// Admitted scopes; index zero is the root scope.
    pub scopes: &'a [ResolvedExecutionScope],
    /// Signed reusable call ceilings, empty for profile two.
    pub authorizations: Vec<crate::call_authorization::CallAuthorization>,
    /// Committed executable host profile.
    pub profile: u32,
    /// Active call context.
    pub context: publication::PublicationContext,
    /// Complete signed event digest.
    pub event: protocol_types::Digest32,
    /// Authenticated sender.
    pub sender: [u8; 32],
    /// Pre-bound arena entries.
    pub arena: Vec<ArenaObject>,
    /// Modules compiled once for every scope.
    pub modules: BTreeMap<PackageOrigin, Arc<Module>>,
    /// Shared host linker.
    pub linker: Arc<Linker<HostState>>,
}

/// Builds the single host state shared by every frame of one invocation.
pub(super) fn host_state(parts: StateParts<'_>) -> Result<HostState, LocalExecutionError> {
    Ok(HostState {
        resolver: parts.resolver.clone(),
        scopes: parts.scopes.to_vec(),
        authorizations: parts.authorizations,
        profile: parts.profile,
        context: parts.context,
        event: parts.event,
        sender: parts.sender,
        instance_bytes: parts
            .scopes
            .iter()
            .map(|scope| encode_instance_record(&scope.instance))
            .collect::<Result<Vec<Vec<u8>>, LocalExecutionError>>()?,
        arena: parts.arena,
        frames: Vec::new(),
        modules: parts.modules,
        linker: parts.linker,
        limiter: RetainedMemory::default(),
        events: Vec::new(),
        emitted_events: 0,
        creations: 0,
        calls: 0,
        handles: 0,
        budget: None,
        output: host::OutputAccount::default(),
    })
}

/// Resolves the compiled module defining one root entrypoint.
pub(super) fn root_module(
    store: &Store<HostState>,
    code: &UnverifiedDependencyRef,
) -> Result<Arc<Module>, LocalExecutionError> {
    Ok(Arc::clone(
        store
            .data()
            .modules
            .get(code.origin())
            .ok_or(LocalExecutionError::Invalid("root module"))?,
    ))
}

/// Instantiates and runs one root entrypoint in the shared store.
pub(super) fn call_root(
    store: &mut Store<HostState>,
    linker: &Linker<HostState>,
    module: &Module,
    entry: &str,
) -> Result<(), wasmi::Error> {
    let instance = linker.instantiate_and_start(&mut *store, module)?;
    let function = instance.get_typed_func::<(), ()>(&*store, entry)?;
    function.call(&mut *store, ())
}

/// Converts the final arena into canonical object effects and surviving
/// creation authorities. Returns `None` when an entry cannot be expressed
/// (version overflow or a creation without its global ordinal), which the
/// caller must treat as a failed execution.
pub(super) fn collect_effects(
    arena: Vec<ArenaObject>,
) -> Option<(Vec<ObjectEffect>, Vec<CreatedObjectAuthority>)> {
    let mut effects: Vec<ObjectEffect> = Vec::new();
    let mut authorities: Vec<CreatedObjectAuthority> = Vec::new();
    for mut item in arena {
        match item.original {
            Some(original) if item.consumed => effects.push(ObjectEffect::Deleted {
                id: original.id,
                version: original.version,
            }),
            Some(original) if item.dirty => {
                // One original version advances at most once per invocation.
                let version: u64 = original.version.checked_add(1)?;
                item.object.version = version;
                effects.push(ObjectEffect::Mutated {
                    previous_version: original.version,
                    new_object: item.object,
                });
            }
            None if !item.consumed => {
                let ordinal: u32 = item.ordinal?;
                effects.push(ObjectEffect::Created(item.object));
                authorities.push(CreatedObjectAuthority {
                    creation_ordinal: ordinal,
                    authority: item.authority,
                });
            }
            _ => {}
        }
    }
    Some((effects, authorities))
}
