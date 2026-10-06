//! One local operator composition of the defining original-genesis installers.
//! Callers independently own fresh storage, verified root and bounded context.
//! This private helper grants no serving, overwrite or successor authority.

use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use hashing::HashSuiteResolver;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{OrderedEconomicsEnvironment, OrderedEconomicsPolicy};
use protocol_types::AtomicityDomainId;
use runtime::{
    BlobStore, Clock, DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore,
    StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore, SystemClock,
    WriterFenceGeneration,
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

/// Validates one signed genesis root in a private, bounded, in-memory
/// installation using only the resolver carried by `root` itself. Both the
/// offline `author` and the offline `inspect` commands share this sole
/// installer-composition owner; neither claims a disk-backed writer fence.
pub(crate) fn validate_original_genesis_in_memory(
    root: &VerifiedGenesisRoot,
    domain: AtomicityDomainId,
    checkpoint: u64,
    timeout_millis: u64,
) -> Result<(), Box<dyn Error>> {
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_genesis_root(root, domain)?;
    let fence: WriterFenceGeneration =
        WriterFenceGeneration::new(1).ok_or("invalid initial validation fence")?;
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain, fence);
    let blobs: MemoryBlobStore = MemoryBlobStore::default();
    let deadline: u64 = SystemClock
        .now_unix_millis()?
        .checked_add(timeout_millis)
        .ok_or("validation deadline overflow")?;
    let context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(deadline).ok_or("invalid validation deadline")?,
        StorageCorrelationId::new([0x61; 16]).ok_or("invalid validation correlation ID")?,
    );
    let installation: OriginalGenesisInstallation<'_> = OriginalGenesisInstallation {
        context: &context,
        domain,
        resolver: root.genesis_resolver(),
        root,
        policy: &policy,
        checkpoint,
    };
    install_original_genesis(&store, &blobs, &installation)
}
