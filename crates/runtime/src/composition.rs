//! Explicit composition of independently supplied runtime components.

use crate::{
    BlobStore, Clock, ManualClock, MemoryBlobStore, MemoryScheduler, MemorySigner,
    MemoryStateStore, MemoryTransport, Runtime, Scheduler, Signer, StateStore, Transport,
    ValidatorId,
};

/// Explicit runtime composition from independently owned components.
///
/// This keeps storage, transport, signing, time, and scheduling policy visible
/// at the embedding boundary. Constructing this value does not certify that
/// any supplied component is durable or production-ready.
#[derive(Debug)]
pub struct ComposedRuntime<S, B, N, T, C, Q> {
    state_store: S,
    blob_store: B,
    signer: N,
    transport: T,
    clock: C,
    scheduler: Q,
}

impl<S, B, N, T, C, Q> ComposedRuntime<S, B, N, T, C, Q> {
    /// Creates a runtime without adding hidden defaults or global state.
    #[must_use]
    pub const fn new(
        state_store: S,
        blob_store: B,
        signer: N,
        transport: T,
        clock: C,
        scheduler: Q,
    ) -> Self {
        Self {
            state_store,
            blob_store,
            signer,
            transport,
            clock,
            scheduler,
        }
    }
}

impl<S, B, N, T, C, Q> Runtime for ComposedRuntime<S, B, N, T, C, Q>
where
    S: StateStore,
    B: BlobStore,
    N: Signer,
    T: Transport,
    C: Clock,
    Q: Scheduler,
{
    type State = S;
    type Blobs = B;
    type NodeSigner = N;
    type Network = T;
    type Time = C;
    type TaskScheduler = Q;

    fn state_store(&self) -> &Self::State {
        &self.state_store
    }

    fn blob_store(&self) -> &Self::Blobs {
        &self.blob_store
    }

    fn signer(&self) -> &Self::NodeSigner {
        &self.signer
    }

    fn transport(&self) -> &Self::Network {
        &self.transport
    }

    fn clock(&self) -> &Self::Time {
        &self.clock
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        &self.scheduler
    }
}

/// In-memory runtime composition.
#[derive(Debug)]
pub struct MemoryRuntime {
    state_store: MemoryStateStore,
    blob_store: MemoryBlobStore,
    signer: MemorySigner,
    transport: MemoryTransport,
    clock: ManualClock,
    scheduler: MemoryScheduler,
}

impl MemoryRuntime {
    /// Creates an in-memory runtime.
    #[must_use]
    pub fn new(validator_id: ValidatorId) -> Self {
        Self {
            state_store: MemoryStateStore::default(),
            blob_store: MemoryBlobStore::default(),
            signer: MemorySigner::new(validator_id),
            transport: MemoryTransport::default(),
            clock: ManualClock::default(),
            scheduler: MemoryScheduler::default(),
        }
    }

    /// Sets current time for the internal manual clock.
    pub fn set_time(&self, unix_millis: u64) {
        self.clock.set(unix_millis);
    }
}

impl Runtime for MemoryRuntime {
    type State = MemoryStateStore;
    type Blobs = MemoryBlobStore;
    type NodeSigner = MemorySigner;
    type Network = MemoryTransport;
    type Time = ManualClock;
    type TaskScheduler = MemoryScheduler;

    fn state_store(&self) -> &Self::State {
        &self.state_store
    }

    fn blob_store(&self) -> &Self::Blobs {
        &self.blob_store
    }

    fn signer(&self) -> &Self::NodeSigner {
        &self.signer
    }

    fn transport(&self) -> &Self::Network {
        &self.transport
    }

    fn clock(&self) -> &Self::Time {
        &self.clock
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        &self.scheduler
    }
}
