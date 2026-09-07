//! Typed interpreter. One store, fuel budget and arena span every contract frame.
use crate::local_execution::*;
use crate::publication::{
    self, BoundObjectResult, UnverifiedDependencyRef, VerifiedPublicationInterface,
};
use crate::{EventRecord, ExecutionEffects, ExecutionStatus, ObjectEffect};
use abi::package_types::PackageOrigin;
use abi::public_abi::ObjectMode;
use hashing::HashSuiteResolver;
use objects::{Address, Object, Owner};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use wasmi::{Config, Engine, Linker, Module, Store};

mod admission;
mod host;
use host::{ArenaObject, Grant, HostState, RetainedMemory};

/// Deterministic, zero-fee local typed-host execution. This grants no storage authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalWasmExecutionEngine;
impl LocalWasmExecutionEngine {
    /// Creates a stateless engine; each invocation owns its complete interpreter state.
    pub const fn new() -> Self {
        Self
    }
}

fn reference(
    interface: &VerifiedPublicationInterface,
) -> Result<UnverifiedDependencyRef, publication::PublicationError> {
    let request = interface.candidate().request();
    let artifact = request.artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *request.artifact_digest(),
    )
}

impl LocalContractEngine for LocalWasmExecutionEngine {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        let root = request.root_scope()?;
        let instance = &root.instance;
        let call = &request.intent.intent().call;
        if request.event_digest
            != local_execution_event_digest(request.resolver, request.intent.signed())?
        {
            return Err(LocalExecutionError::Invalid("execution event digest"));
        }
        crate::execution_scopes::validate_local_execution_scopes(
            request.resolver,
            request.policy,
            request.intent.intent(),
            request.scopes,
        )?;
        if request.inputs.len() != call.access.entries.len()
            || request.inputs.len() > crate::call_authorization::MAX_AUTHORIZED_INPUTS
        {
            return Err(LocalExecutionError::Invalid("input count"));
        }
        let mut arena: Vec<ArenaObject> = Vec::new();
        let mut grants: Vec<Grant> = Vec::new();
        let mut ids: BTreeSet<objects::ObjectId> = BTreeSet::new();
        let mut body_bytes: usize = 0;
        for (input, access) in request.inputs.iter().zip(&call.access.entries) {
            let object = &input.resolved.object;
            let authority = &input.authority;
            let scope = request
                .scopes
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
            if object.owner != Owner::Address(Address::new(call.sender))
                || !ids.insert(object.id)
                || object.id != access.object_ref.id
                || object.version != access.object_ref.version
                || input.resolved.mode != access.mode
                || authority.object_id != object.id
                || authority.code != reference(&defining)?
                || !abi::package_types::verify_scoped_type_id(
                    request.resolver,
                    &object.type_hash,
                    call.context.epoch(),
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
            body_bytes = body_bytes
                .checked_add(object.data.len())
                .ok_or(LocalExecutionError::Limit("input body"))?;
            if body_bytes > publication::MAX_BOUND_BODY_BYTES {
                return Err(LocalExecutionError::Limit("input body"));
            }
            let mode = match access.mode {
                objects::AccessMode::Read => ObjectMode::Read,
                objects::AccessMode::Write => ObjectMode::Write,
                objects::AccessMode::Consume => ObjectMode::Consume,
            };
            grants.push(Grant {
                index: arena.len(),
                mode,
            });
            arena.push(ArenaObject {
                object: object.clone(),
                original: Some(object.clone()),
                authority: authority.clone(),
                ordinal: None,
                consumed: false,
                transferred: false,
                dirty: false,
            });
        }
        let mut config: Config = Config::default();
        config.consume_fuel(true);
        config.set_min_stack_height(LOCAL_WASM_INITIAL_STACK);
        config.set_max_stack_height(LOCAL_WASM_MAX_STACK);
        config.set_max_recursion_depth(LOCAL_WASM_MAX_RECURSION);
        let engine: Engine = Engine::new(&config);
        let modules = admission::scopes(&request, &engine)?;
        let linker: Arc<Linker<HostState>> = Arc::new(
            host::linker(&engine).map_err(|_| LocalExecutionError::Invalid("host linker"))?,
        );
        let mut state: HostState = HostState {
            resolver: request.resolver.clone(),
            scopes: request.scopes.to_vec(),
            authorizations: request.intent.intent().authorizations.clone(),
            profile: request.policy.profile(),
            context: call.context.clone(),
            event: request.event_digest,
            sender: call.sender,
            instance_bytes: request
                .scopes
                .iter()
                .map(|scope| encode_instance_record(&scope.instance))
                .collect::<Result<Vec<Vec<u8>>, LocalExecutionError>>()?,
            arena,
            frames: Vec::new(),
            modules,
            linker: Arc::clone(&linker),
            limiter: RetainedMemory::default(),
            events: Vec::new(),
            creations: 0,
            calls: 0,
            handles: 0,
        };
        let prepared = host::prepare_frame(
            &state,
            0,
            call.code.clone(),
            &call.entrypoint,
            &call.type_arguments,
            grants,
            call.arguments.clone(),
            Some(request.intent.intent().mode),
        )
        .map_err(|_| LocalExecutionError::Invalid("root frame"))?;
        state.handles = prepared.grants.len();
        state.calls = 1;
        state.frames.push(prepared);
        let mut store: Store<HostState> = Store::new(&engine, state);
        store.limiter(|state| &mut state.limiter);
        store
            .set_fuel(call.gas_limit)
            .map_err(|_| LocalExecutionError::Invalid("fuel"))?;
        let root: Arc<Module> = Arc::clone(
            store
                .data()
                .modules
                .get(call.code.origin())
                .ok_or(LocalExecutionError::Invalid("root module"))?,
        );
        let run: Result<(), wasmi::Error> = (|| {
            let instance = linker.instantiate_and_start(&mut store, &root)?;
            let function = instance.get_typed_func::<(), ()>(&store, &call.entrypoint)?;
            function.call(&mut store, ())
        })();
        let remaining: u64 = store
            .get_fuel()
            .map_err(|_| LocalExecutionError::Invalid("fuel"))?;
        let gas_used: u64 = call
            .gas_limit
            .checked_sub(remaining)
            .ok_or(LocalExecutionError::Invalid("fuel accounting"))?;
        let failed = || LocalExecutionOutcome {
            effects: ExecutionEffects {
                tx_hash: request.event_digest,
                status: ExecutionStatus::Failure {
                    reason: LOCAL_EXECUTION_TRAP_REASON.into(),
                },
                object_effects: Vec::new(),
                events: Vec::new(),
                gas_used,
            },
            created_authorities: Vec::new(),
        };
        if run.is_err() || store.data().limiter.failed {
            return Ok(failed());
        }
        // Root has no receiving frame: validate required slots per DR-0124,
        // then drop the returned handles. Their underlying object effects
        // (create/mutate/consume) persist independently of this bookkeeping;
        // a coordinator composing typed calls retains slots via the nested
        // `call_dependency_with_results`/`call_contract_with_results` path.
        let root_results_ok: bool = {
            let state = store.data();
            match state.frames.last() {
                Some(root_frame) => host::validate_returned_slots(state, root_frame).is_ok(),
                None => false,
            }
        };
        if !root_results_ok {
            return Ok(failed());
        }
        let state: HostState = store.into_data();
        let mut effects: Vec<ObjectEffect> = Vec::new();
        let mut authorities: Vec<CreatedObjectAuthority> = Vec::new();
        for mut item in state.arena {
            match item.original {
                Some(original) if item.consumed => effects.push(ObjectEffect::Deleted {
                    id: original.id,
                    version: original.version,
                }),
                Some(original) if item.dirty => {
                    let Some(version) = original.version.checked_add(1) else {
                        return Ok(failed());
                    };
                    item.object.version = version;
                    effects.push(ObjectEffect::Mutated {
                        previous_version: original.version,
                        new_object: item.object,
                    });
                }
                None if !item.consumed => {
                    let Some(ordinal) = item.ordinal else {
                        return Ok(failed());
                    };
                    effects.push(ObjectEffect::Created(item.object));
                    authorities.push(CreatedObjectAuthority {
                        creation_ordinal: ordinal,
                        authority: item.authority,
                    });
                }
                _ => {}
            }
        }
        let outcome: LocalExecutionOutcome = LocalExecutionOutcome {
            effects: ExecutionEffects {
                tx_hash: request.event_digest,
                status: ExecutionStatus::Success,
                object_effects: effects,
                events: state.events,
                gas_used,
            },
            created_authorities: authorities,
        };
        let result: LocalExecutionResult = LocalExecutionResult {
            request_id: call.request_id,
            instance: instance.clone(),
            mode: request.intent.intent().mode,
            effects: outcome.effects.clone(),
        };
        if encode_local_execution_result(&result).is_err() {
            return Ok(failed());
        }
        Ok(outcome)
    }
}
