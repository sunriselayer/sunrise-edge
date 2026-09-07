//! Shared pre-signing and execution admission for exact call scopes (DR-0123).
//! This validates pinned claims, not storage existence or runtime handle rights.
use crate::call_authorization::*;
use crate::local_execution::*;
use crate::publication::{self, UnverifiedDependencyRef, VerifiedPublicationInterface};
use abi::package_types::PackageOrigin;
use abi::public_abi::ObjectMode;
use hashing::HashSuiteResolver;
use objects::AccessMode;
use std::collections::{BTreeMap, BTreeSet};

/// Reconstructs the exact reference authenticated by a verified code view.
pub fn verified_code_reference(
    interface: &VerifiedPublicationInterface,
) -> Result<UnverifiedDependencyRef, LocalExecutionError> {
    let request = interface.candidate().request();
    let artifact = request.artifact();
    Ok(UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *request.artifact_digest(),
    )?)
}

/// Checks the same bounded target model before client signing and engine entry.
/// Callers must independently verify durable read sets or locally trusted pins.
/// Runtime still verifies current caller identity, handles and computed arguments.
pub fn validate_local_execution_scopes(
    resolver: &HashSuiteResolver,
    policy: &LocalExecutionPolicy,
    intent: &LocalExecutionIntent,
    scopes: &[ResolvedExecutionScope],
) -> Result<(), LocalExecutionError> {
    let invalid = LocalExecutionError::Invalid;
    validate_call_authorizations(&intent.call, &intent.authorizations)?;
    let call = &intent.call;
    if scopes.is_empty() || scopes.len() > MAX_EXECUTION_SCOPES {
        return Err(LocalExecutionError::Limit("execution scopes"));
    }
    if policy.context() != &call.context
        || resolver.chain_id() != call.context.chain_id()
        || resolver.protocol_version() != call.context.protocol_version()
        || intent.policy_digest != policy.digest(resolver)?
        || call.gas_limit == 0
        || call.gas_limit > policy.max_gas()
        || (policy.profile() == 2 && (scopes.len() != 1 || !intent.authorizations.is_empty()))
    {
        return Err(invalid("execution scope policy or context"));
    }
    let mut required: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    required.insert((call.instance.creator, call.instance.seed));
    for authorization in &intent.authorizations {
        for target in [&authorization.caller, &authorization.callee] {
            required.insert((target.instance.creator, target.instance.seed));
        }
    }
    let mut unique: BTreeSet<([u8; 32], [u8; 32])> = BTreeSet::new();
    let mut codes: BTreeMap<PackageOrigin, UnverifiedDependencyRef> = BTreeMap::new();
    let mut bytes: usize = 0;
    for scope in scopes {
        let instance = &scope.instance;
        if !required.contains(&(instance.creator, instance.seed))
            || !unique.insert((instance.creator, instance.seed))
            || instance.context.chain_id() != call.context.chain_id()
            || instance.context.protocol_version() != call.context.protocol_version()
            || instance.context.epoch() > call.context.epoch()
            || instance_target(resolver, instance)? != scope.target
            || verified_code_reference(&scope.interface)? != instance.code
            || scope
                .interface
                .executable_abi(instance.code.origin())
                .and_then(|abi| abi.initializer.as_deref())
                != Some(instance.initializer.as_str())
        {
            return Err(invalid("execution scope instance authority"));
        }
        for candidate in
            std::iter::once(scope.interface.candidate()).chain(scope.interface.dependencies())
        {
            let request = candidate.request();
            let artifact = request.artifact();
            if artifact.context().chain_id() != call.context.chain_id()
                || artifact.context().protocol_version() != call.context.protocol_version()
                || artifact.context().epoch() > call.context.epoch()
            {
                return Err(invalid("execution code context"));
            }
            let semantics = match artifact.wasm_profile() {
                2 => local_execution_semantics(resolver, artifact.context())?,
                3 if policy.profile() == 3 => {
                    general_execution_semantics(resolver, artifact.context())?
                }
                _ => return Err(invalid("execution code profile")),
            };
            if artifact.semantics() != &semantics {
                return Err(invalid("execution code semantics"));
            }
            let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
                artifact.origin().clone(),
                artifact.revision(),
                artifact.context().clone(),
                *request.artifact_digest(),
            )?;
            if let Some(old) = codes.get(artifact.origin()) {
                if old != &reference {
                    return Err(invalid("conflicting execution code"));
                }
                continue;
            }
            // A publication submission adds a 10-byte header, two 6-byte field
            // headers and a fixed 32-byte request ID to this exact request.
            let size: usize = publication::encode_publication_request(request)?.len();
            bytes = bytes
                .checked_add(size)
                .and_then(|total| total.checked_add(54))
                .ok_or(LocalExecutionError::Limit("execution code bytes"))?;
            codes.insert(artifact.origin().clone(), reference);
            if codes.len() > MAX_EXECUTION_CODE_NODES || bytes > MAX_EXECUTION_CODE_BYTES {
                return Err(LocalExecutionError::Limit("execution code closure"));
            }
        }
    }
    if unique != required {
        return Err(invalid("missing execution scope"));
    }
    let root: &ResolvedExecutionScope = &scopes[0];
    if root.target != call.instance || root.instance.code != call.code {
        return Err(invalid("root execution scope"));
    }
    let metadata = root
        .interface
        .executable_abi(call.code.origin())
        .ok_or(invalid("root executable ABI"))?;
    match intent.mode {
        LocalExecutionMode::Instantiate
            if root.instance.creator != call.sender
                || root.instance.context != call.context
                || metadata.initializer.as_deref() != Some(call.entrypoint.as_str())
                || !call.access.entries.is_empty() =>
        {
            return Err(invalid("initializer authority"));
        }
        LocalExecutionMode::Call
            if metadata.initializer.as_deref() == Some(call.entrypoint.as_str()) =>
        {
            return Err(invalid("initializer replay"));
        }
        _ => {}
    }
    crate::call::bind_call_intent(call, &root.interface)?;
    for authorization in &intent.authorizations {
        for target in [&authorization.caller, &authorization.callee] {
            let scope: &ResolvedExecutionScope = scopes
                .iter()
                .find(|scope| scope.target == target.instance)
                .ok_or(invalid("signed target scope mismatch"))?;
            let view: VerifiedPublicationInterface = scope
                .interface
                .for_origin(target.code.origin())
                .map_err(|_| invalid("target code not in instance closure"))?;
            if verified_code_reference(&view)? != target.code {
                return Err(invalid("signed exact target code"));
            }
        }
        let scope: &ResolvedExecutionScope = scopes
            .iter()
            .find(|scope| scope.target == authorization.callee.instance)
            .ok_or(invalid("callee scope absent"))?;
        let view: VerifiedPublicationInterface = scope
            .interface
            .for_origin(authorization.callee.code.origin())
            .map_err(|_| invalid("callee code absent"))?;
        let abi = view
            .executable_abi(authorization.callee.code.origin())
            .ok_or(invalid("callee executable ABI"))?;
        if abi.initializer.as_deref() == Some(authorization.entrypoint.as_str()) {
            return Err(invalid("nested initializer"));
        }
        let signature = publication::bind_object_signature(
            &view,
            &authorization.entrypoint,
            &authorization.type_arguments,
        )
        .map_err(|_| invalid("callee ABI binding"))?;
        if signature.objects().len() != authorization.objects.len() {
            return Err(invalid("callee object count"));
        }
        for (parameter, selector) in signature.objects().iter().zip(&authorization.objects) {
            let mode: u8 = match parameter.mode() {
                ObjectMode::Read => 1,
                ObjectMode::Write => 2,
                ObjectMode::Consume => 3,
            };
            let ceiling: u8 = match selector.mode {
                AccessMode::Read => 1,
                AccessMode::Write => 2,
                AccessMode::Consume => 3,
            };
            if mode > ceiling {
                return Err(invalid("callee rights exceed signed ceiling"));
            }
        }
    }
    Ok(())
}
