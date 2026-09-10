//! Compile each already-admitted immutable module once across all scopes.
use super::*;
pub(super) fn scopes(
    scopes: &[ResolvedExecutionScope],
    engine: &Engine,
) -> Result<BTreeMap<PackageOrigin, Arc<Module>>, LocalExecutionError> {
    let mut modules: BTreeMap<PackageOrigin, Arc<Module>> = BTreeMap::new();
    for scope in scopes {
        for candidate in
            std::iter::once(scope.interface.candidate()).chain(scope.interface.dependencies())
        {
            let artifact = candidate.artifact();
            if modules.contains_key(artifact.origin()) {
                continue;
            }
            let module: Module = Module::new(engine, artifact.wasm())
                .map_err(|_| LocalExecutionError::Invalid("WASM module"))?;
            modules.insert(artifact.origin().clone(), Arc::new(module));
        }
    }
    Ok(modules)
}
pub(super) fn selected_scope(
    scopes: &[ResolvedExecutionScope],
    target: &crate::call_authorization::ExecutionTarget,
) -> Result<usize, LocalExecutionError> {
    scopes
        .iter()
        .position(|scope| scope.target == target.instance)
        .ok_or(LocalExecutionError::Invalid("unresolved execution target"))
}
