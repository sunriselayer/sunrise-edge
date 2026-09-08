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
// The DR-0124 reserve/application/settle phase coordinator is internal
// (`pub(crate)`, never re-exported): raw phase/grant/source APIs stay
// private to this crate. It is driven only by `crate::paid_execution`'s
// `PaidContractEngine`, which recomputes quote/digest/policy/input
// correspondence and builds the private `PhasePlan` from an
// `AuthenticatedPaidIntent` plus validated resolved scopes; it is never
// reachable directly from node-core/HTTP/CLI. It drives the same
// production store, host, frame validator and effect collector as the
// zero-fee root path below.
mod coordinator;
mod host;
mod runner;
use host::{ArenaObject, Grant, HostState};

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
    let candidate = interface.candidate();
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *candidate.digest(),
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
            let bound: ArenaObject = runner::bind_input(
                request.resolver,
                request.scopes,
                call.sender,
                call.context.epoch(),
                input,
            )?;
            let object: &Object = &input.resolved.object;
            if !ids.insert(object.id)
                || object.id != access.object_ref.id
                || object.version != access.object_ref.version
                || input.resolved.mode != access.mode
            {
                return Err(LocalExecutionError::Invalid("input authority"));
            }
            runner::accumulate_body_bytes(&mut body_bytes, object)?;
            let mode = match access.mode {
                objects::AccessMode::Read => ObjectMode::Read,
                objects::AccessMode::Write => ObjectMode::Write,
                objects::AccessMode::Consume => ObjectMode::Consume,
            };
            grants.push(Grant {
                index: arena.len(),
                mode,
            });
            arena.push(bound);
        }
        let engine: Engine = runner::interpreter();
        let modules = admission::scopes(request.scopes, &engine)?;
        let linker: Arc<Linker<HostState>> = Arc::new(
            host::linker(&engine).map_err(|_| LocalExecutionError::Invalid("host linker"))?,
        );
        let mut state: HostState = runner::host_state(runner::StateParts {
            resolver: request.resolver,
            scopes: request.scopes,
            authorizations: request.intent.intent().authorizations.clone(),
            profile: request.policy.profile(),
            context: call.context.clone(),
            event: request.event_digest,
            sender: call.sender,
            arena,
            modules,
            linker: Arc::clone(&linker),
        })?;
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
        let root: Arc<Module> = runner::root_module(&store, &call.code)?;
        let run: Result<(), wasmi::Error> =
            runner::call_root(&mut store, &linker, &root, &call.entrypoint);
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
        let Some((effects, authorities)) = runner::collect_effects(state.arena) else {
            return Ok(failed());
        };
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
