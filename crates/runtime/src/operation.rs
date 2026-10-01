//! Operational writer identity, budget and cancellation for durable invocations.

use core::fmt;
use std::num::NonZeroU64;

/// Monotonic deployment-generation token for one domain's authoritative writer.
///
/// This token belongs to fenced deployment metadata, not canonical protocol
/// state. Generation zero is reserved so an omitted fence cannot authorize a
/// write accidentally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriterFenceGeneration(NonZeroU64);

impl WriterFenceGeneration {
    /// Creates a non-zero writer generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the deployment-metadata representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next generation without permitting wraparound.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Absolute storage-operation deadline in Unix milliseconds.
///
/// Adapters must propagate this deadline through acquisition, statements, and
/// commit. Expiry does not by itself prove that an already-dispatched commit
/// aborted; such a result is [`crate::DurableCommitOutcome::Indeterminate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageDeadline(NonZeroU64);

impl StorageDeadline {
    /// Creates a non-zero absolute deadline.
    #[must_use]
    pub const fn new(unix_millis: u64) -> Option<Self> {
        match NonZeroU64::new(unix_millis) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the absolute Unix-millisecond deadline.
    #[must_use]
    pub const fn unix_millis(self) -> u64 {
        self.0.get()
    }

    /// Returns whether the deadline has elapsed at the supplied trusted time.
    #[must_use]
    pub const fn is_expired_at(self, now_unix_millis: u64) -> bool {
        now_unix_millis >= self.unix_millis()
    }
}

/// Bounded operational identity used to correlate one durable invocation.
///
/// Correlation IDs are observability metadata. They are not accepted as
/// request identity, deduplication identity, or a protocol authorization input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageCorrelationId([u8; 16]);

impl StorageCorrelationId {
    /// Creates a non-zero correlation identity.
    #[must_use]
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        if bytes == [0; 16] {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Returns the exact operational identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Authority and budget shared by every storage operation in one invocation.
///
/// The same context must be used for all reads and the corresponding commit.
/// A store must revalidate the writer fence at commit even if earlier reads
/// accepted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableOperationContext {
    writer_fence: WriterFenceGeneration,
    deadline: StorageDeadline,
    correlation_id: StorageCorrelationId,
}

impl DurableOperationContext {
    /// Creates the bounded operational context for one durable invocation.
    #[must_use]
    pub const fn new(
        writer_fence: WriterFenceGeneration,
        deadline: StorageDeadline,
        correlation_id: StorageCorrelationId,
    ) -> Self {
        Self {
            writer_fence,
            deadline,
            correlation_id,
        }
    }

    /// Returns the writer generation that the adapter must validate.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }

    /// Returns the deadline covering acquisition through commit resolution.
    #[must_use]
    pub const fn deadline(self) -> StorageDeadline {
        self.deadline
    }

    /// Returns the operational correlation identity.
    #[must_use]
    pub const fn correlation_id(self) -> StorageCorrelationId {
        self.correlation_id
    }
}

/// Trusted cooperative signal that can stop an invocation before storage dispatch.
///
/// Native compositions may consult this signal until the first durable storage
/// operation is dispatched. Durable stores deliberately do not receive it:
/// once that operation begins, cancellation cannot prove that a later commit
/// aborted and must not terminate started synchronous work.
pub trait InvocationCancellation: fmt::Debug + Send + Sync {
    /// Returns whether the composition should reject a not-yet-dispatched invocation.
    fn is_cancelled(&self) -> bool;
}

/// Explicit cancellation policy for compositions that never cancel dispatch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeverCancelled;

impl InvocationCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}
