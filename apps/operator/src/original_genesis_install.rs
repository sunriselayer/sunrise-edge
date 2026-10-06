//! One local operator composition of the defining original-genesis installers.
//! Callers independently own fresh storage, verified root and bounded context.
//! This private helper grants no serving, overwrite or successor authority.

use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use hashing::HashSuiteResolver;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{OrderedEconomicsEnvironment, OrderedEconomicsPolicy};
use protocol_types::AtomicityDomainId;
use runtime::{
    BlobStore, Clock, DurableOperationContext, StructuredDurableDomainStateStore, SystemClock,
};
use std::error::Error;

pub(crate) struct OriginalGenesisInstallation<'a> {
    pub context: &'a DurableOperationContext,
    pub domain: AtomicityDomainId,
    pub resolver: &'a HashSuiteResolver,
    pub root: &'a VerifiedGenesisRoot,
    pub policy: &'a OrderedEconomicsPolicy,
    pub checkpoint: u64,
}

pub(crate) fn install_original_genesis<S: StructuredDurableDomainStateStore>(
    store: &S,
    blobs: &dyn BlobStore,
    installation: &OriginalGenesisInstallation<'_>,
) -> Result<(), Box<dyn Error>> {
    node_core::genesis::install_genesis(
        store,
        installation.context,
        installation.domain,
        installation.resolver,
        installation.root.manifest(),
        installation.checkpoint,
    )?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(installation.root.genesis_context().clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: installation.policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs,
        seal: None,
    };
    // Clock affects only the existing, local pacemaker's liveness timer.
    node_core::ordered_economics::install_ordered_genesis(
        store,
        installation.context,
        &environment,
        SystemClock.now_unix_millis()?,
    )?;
    Ok(())
}
