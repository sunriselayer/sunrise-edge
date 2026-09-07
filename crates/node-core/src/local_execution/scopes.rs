//! One exact instance/code registry for all frames and output authority checks.
use super::*;
use execution::call_authorization::{ExecutionTarget, MAX_EXECUTION_SCOPES};

pub(super) fn for_authority<'a>(
    scopes: &'a [ResolvedExecutionScope],
    authority: &ObjectAuthority,
) -> AdmissionResult<&'a ResolvedExecutionScope> {
    scopes
        .iter()
        .find(|scope| {
            scope.target == authority.instance
                && scope.instance.context == authority.instance_context
        })
        .ok_or(LocalExecutionAdmissionError::Invalid(
            "object scope not admitted",
        ))
}

fn selected_view(
    scope: &ResolvedExecutionScope,
    target: &ExecutionTarget,
) -> AdmissionResult<VerifiedPublicationInterface> {
    if scope.target != target.instance {
        return Err(LocalExecutionAdmissionError::Invalid(
            "scope target mismatch",
        ));
    }
    let view: VerifiedPublicationInterface = scope
        .interface
        .for_origin(target.code.origin())
        .map_err(|_| {
            LocalExecutionAdmissionError::Invalid("selected code outside instance closure")
        })?;
    if !reference_matches(&target.code, &view) {
        return Err(LocalExecutionAdmissionError::Invalid(
            "selected exact code mismatch",
        ));
    }
    Ok(view)
}

pub(super) fn validate_inputs(
    authenticated: &AuthenticatedLocalExecutionIntent,
    scopes: &[ResolvedExecutionScope],
    inputs: &[ScopedResolvedObject],
    resolver: &HashSuiteResolver,
) -> AdmissionResult<()> {
    let call = &authenticated.intent().call;
    for authorization in &authenticated.intent().authorizations {
        let scope: &ResolvedExecutionScope = scopes
            .iter()
            .find(|scope| scope.target == authorization.callee.instance)
            .ok_or(LocalExecutionAdmissionError::Invalid("callee scope absent"))?;
        let view: VerifiedPublicationInterface = selected_view(scope, &authorization.callee)?;
        let binding = execution::publication::bind_object_signature(
            &view,
            &authorization.entrypoint,
            &authorization.type_arguments,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("authorized ABI binding"))?;
        let mut entries: Vec<AccessEntry> = Vec::new();
        let mut resolved: Vec<ResolvedObject> = Vec::new();
        for (parameter, selector) in binding.objects().iter().zip(&authorization.objects) {
            let input: &ScopedResolvedObject = inputs
                .iter()
                .find(|input| input.resolved.object.id == selector.object_id)
                .ok_or(LocalExecutionAdmissionError::Invalid(
                    "authorized input absent",
                ))?;
            let original: &AccessEntry = call
                .access
                .entries
                .iter()
                .find(|entry| entry.object_ref.id == selector.object_id)
                .ok_or(LocalExecutionAdmissionError::Invalid(
                    "authorized reference absent",
                ))?;
            let mode: AccessMode = match parameter.mode() {
                abi::public_abi::ObjectMode::Read => AccessMode::Read,
                abi::public_abi::ObjectMode::Write => AccessMode::Write,
                abi::public_abi::ObjectMode::Consume => AccessMode::Consume,
            };
            entries.push(AccessEntry {
                object_ref: original.object_ref.clone(),
                mode,
            });
            resolved.push(ResolvedObject {
                object: input.resolved.object.clone(),
                mode,
            });
        }
        execution::publication::validate_object_input_bodies(
            &binding,
            resolver,
            call.context.epoch(),
            &abi::AccessManifest { entries },
            &resolved,
        )
        .map_err(|_| LocalExecutionAdmissionError::Invalid("authorized input body mismatch"))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admit<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    policy: &LocalExecutionPolicy,
    authenticated: &AuthenticatedLocalExecutionIntent,
    root: ResolvedExecutionScope,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    budget: &mut publication::PublicationLoadBudget,
) -> AdmissionResult<Vec<ResolvedExecutionScope>> {
    let call = &authenticated.intent().call;
    let mut scopes: Vec<ResolvedExecutionScope> = vec![root];
    for authorization in &authenticated.intent().authorizations {
        for target in [&authorization.caller, &authorization.callee] {
            if let Some(scope) = scopes.iter().find(|scope| {
                scope.target.creator == target.instance.creator
                    && scope.target.seed == target.instance.seed
            }) {
                selected_view(scope, target)?;
                continue;
            }
            if scopes.len() >= MAX_EXECUTION_SCOPES {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "execution scope limit",
                ));
            }
            let key: Vec<u8> = instance_record_key(
                call.context.chain_id(),
                &target.instance.creator,
                &target.instance.seed,
            )?;
            let observed: VersionedStateValue = read_state(store, context, domain, key, reads)?;
            let instance: InstanceRecord = decode_instance_record(observed.value().ok_or(
                LocalExecutionAdmissionError::Invalid("authorized instance absent"),
            )?)?;
            if instance.context.chain_id() != call.context.chain_id()
                || instance.context.protocol_version() != call.context.protocol_version()
                || instance.context.epoch() > call.context.epoch()
                || instance_target(
                    original_resolver(resolver, history, &instance.context)?,
                    &instance,
                )? != target.instance
            {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "authorized instance mismatch",
                ));
            }
            // Reuse an already verified closure view when possible. Otherwise the
            // durable loader verifies the new root and contributes every CAS read.
            let shared: Option<VerifiedPublicationInterface> = scopes
                .iter()
                .find_map(|scope| scope.interface.for_origin(instance.code.origin()).ok());
            let interface: VerifiedPublicationInterface = if let Some(view) = shared {
                view
            } else {
                let loaded: VerifiedDurablePublication =
                    publication::load_verified_publication_with_budget(
                        store,
                        context,
                        domain,
                        resolver,
                        history,
                        instance.code.origin(),
                        budget,
                    )?
                    .ok_or(LocalExecutionAdmissionError::Invalid(
                        "authorized code absent",
                    ))?;
                for assertion in loaded.reads {
                    if let Some(old) =
                        reads.insert(assertion.key().to_vec(), assertion.expected_revision())
                        && old != assertion.expected_revision()
                    {
                        return Err(NodeCoreError::StateConflict.into());
                    }
                }
                loaded.interface
            };
            if !reference_matches(&instance.code, &interface)
                || interface
                    .executable_abi(instance.code.origin())
                    .and_then(|abi| abi.initializer.as_ref())
                    != Some(&instance.initializer)
            {
                return Err(LocalExecutionAdmissionError::Invalid(
                    "authorized instance root code mismatch",
                ));
            }
            let scope: ResolvedExecutionScope = ResolvedExecutionScope {
                instance,
                target: target.instance.clone(),
                interface,
            };
            selected_view(&scope, target)?;
            scopes.push(scope);
        }
    }
    execution::execution_scopes::validate_local_execution_scopes(
        resolver,
        policy,
        authenticated.intent(),
        &scopes,
    )?;
    Ok(scopes)
}
