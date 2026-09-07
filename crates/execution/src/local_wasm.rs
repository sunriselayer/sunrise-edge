//! Profile-two interpreter. One store, fuel budget and arena span every library frame.
use crate::local_execution::*;
use crate::publication::{self, UnverifiedDependencyRef, VerifiedPublicationInterface};
use crate::{EventRecord, ExecutionEffects, ExecutionStatus, ObjectEffect, ResolvedObject};
use abi::package_types::PackageOrigin;
use abi::public_abi::ObjectMode;
use hashing::HashSuiteResolver;
use objects::{Address, Object, Owner};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use wasmi::{Config, Engine, Linker, Module, Store};

mod host;
use host::{ArenaObject, Frame, Grant, HostState, RetainedMemory};

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
        if request.policy.profile() != 2
            || !request.intent.intent().authorizations.is_empty()
            || request.scopes.len() != 1
        {
            return Err(LocalExecutionError::Invalid(
                "general call runtime not activated",
            ));
        }
        let root = request.root_scope()?;
        let interface = &root.interface;
        let instance = &root.instance;
        let call = &request.intent.intent().call;
        if root.target != call.instance {
            return Err(LocalExecutionError::Invalid("root scope target mismatch"));
        }
        // This first executable profile does not authorize cross-protocol execution.
        // Historical bytes remain readable; historical epochs within this resolver
        // continue to resolve through its trusted hash schedule.
        if instance.context.protocol_version() != request.resolver.protocol_version()
            || std::iter::once(interface.candidate())
                .chain(interface.dependencies().iter())
                .any(|candidate| {
                    candidate.request().artifact().context().protocol_version()
                        != request.resolver.protocol_version()
                })
        {
            return Err(LocalExecutionError::Invalid(
                "historical protocol execution unsupported",
            ));
        }
        if call.context != *request.policy.context()
            || request.intent.intent().policy_digest != request.policy.digest(request.resolver)?
            || request.event_digest
                != local_execution_event_digest(request.resolver, request.intent.signed())?
            || call.code != reference(interface)?
            || call.code != instance.code
            || call.instance != instance_target(request.resolver, instance)?
            || call.gas_limit == 0
            || call.gas_limit > request.policy.max_gas()
        {
            return Err(LocalExecutionError::Invalid("execution request context"));
        }
        if interface
            .executable_abi(call.code.origin())
            .and_then(|metadata| metadata.initializer.as_deref())
            != Some(instance.initializer.as_str())
        {
            return Err(LocalExecutionError::Invalid("instance initializer"));
        }
        if request.intent.intent().mode == LocalExecutionMode::Instantiate
            && (call.sender != instance.creator || call.context != instance.context)
        {
            return Err(LocalExecutionError::Invalid("instance creation context"));
        }
        let signature = bind_local_execution(request.intent, interface)?;
        let inputs: Vec<ResolvedObject> = request
            .inputs
            .iter()
            .map(|input| input.resolved.clone())
            .collect();
        publication::validate_object_input_bodies(
            &signature,
            request.resolver,
            call.context.epoch(),
            &call.access,
            &inputs,
        )
        .map_err(|_| LocalExecutionError::Invalid("input body or metadata"))?;
        let mut arena: Vec<ArenaObject> = Vec::new();
        let mut grants: Vec<Grant> = Vec::new();
        let mut ids: BTreeSet<objects::ObjectId> = BTreeSet::new();
        for (input, parameter) in request.inputs.iter().zip(signature.objects()) {
            let object = &input.resolved.object;
            let authority = &input.authority;
            let defining = interface
                .for_origin(authority.ty.origin())
                .map_err(|_| LocalExecutionError::Invalid("input defining code"))?;
            if object.owner != Owner::Address(Address::new(call.sender))
                || !ids.insert(object.id)
                || authority.object_id != object.id
                || authority.instance != call.instance
                || authority.instance_context != instance.context
                || authority.code != reference(&defining)?
                || authority.ty != *parameter.ty()
            {
                return Err(LocalExecutionError::Invalid("input authority"));
            }
            grants.push(Grant {
                index: arena.len(),
                mode: parameter.mode(),
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
        let mut modules: BTreeMap<PackageOrigin, Arc<Module>> = BTreeMap::new();
        for origin in std::iter::once(interface.candidate().request().artifact().origin()).chain(
            interface
                .dependencies()
                .iter()
                .map(|candidate| candidate.request().artifact().origin()),
        ) {
            let view = interface
                .for_origin(origin)
                .map_err(|_| LocalExecutionError::Invalid("code closure"))?;
            let artifact = view.candidate().request().artifact();
            if artifact.wasm_profile() != 2
                || *artifact.semantics()
                    != local_execution_semantics(request.resolver, artifact.context())?
            {
                return Err(LocalExecutionError::Invalid("executable profile"));
            }
            let exports: Vec<&str> = artifact.exports().iter().map(String::as_str).collect();
            crate::validate_contract_wasm_profile(artifact.wasm(), &exports, 2)
                .map_err(|_| LocalExecutionError::Invalid("WASM profile"))?;
            let module: Module = Module::new(&engine, artifact.wasm())
                .map_err(|_| LocalExecutionError::Invalid("WASM module"))?;
            modules.insert(origin.clone(), Arc::new(module));
        }
        let linker: Arc<Linker<HostState>> = Arc::new(
            host::linker(&engine).map_err(|_| LocalExecutionError::Invalid("host linker"))?,
        );
        let state: HostState = HostState {
            resolver: request.resolver.clone(),
            instance: instance.clone(),
            target: call.instance.clone(),
            context: call.context.clone(),
            event: request.event_digest,
            sender: call.sender,
            instance_bytes: encode_instance_record(instance)?,
            arena,
            frames: vec![Frame {
                interface: interface.clone(),
                code: call.code.clone(),
                grants,
                args: call.arguments.clone(),
            }],
            modules,
            linker: Arc::clone(&linker),
            limiter: RetainedMemory::default(),
            events: Vec::new(),
            creations: 0,
            calls: 1,
            handles: request.inputs.len(),
        };
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
