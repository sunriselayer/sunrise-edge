//! Existing SQLite source composition, never bootstrap or writer acquisition.

use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, NamespaceLifecycle,
    StorageCorrelationId, StorageDeadline, SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{error::Error, io, path::Path};

/// Read-only consumer handles for an already initialized local namespace.
/// Opening this composition neither creates files nor advances a writer fence.
pub struct ExistingSqliteSource {
    pub durable: SqliteDurableStore,
    pub blobs: SqliteBlobStore,
    pub operation: DurableOperationContext,
}

impl ExistingSqliteSource {
    /// Uses the named historical open and the current persisted writer accessor.
    /// An outgoing Sealed namespace remains inspectable; permanent import
    /// origin remains excluded from this source composition. A subsequent
    /// mutation or fence change is refused by the snapshot token.
    pub fn open(
        durable_file: &Path,
        blob_file: &Path,
        chain: ChainId,
        validator: ValidatorId,
        domain: AtomicityDomainId,
        timeout_seconds: u64,
    ) -> Result<Self, Box<dyn Error>> {
        if !(1..=3600).contains(&timeout_seconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be 1..3600 seconds",
            )
            .into());
        }
        let namespace: SqliteNamespace = SqliteNamespace::new(chain, validator, domain);
        let durable: SqliteDurableStore =
            SqliteDurableStore::open_historical(durable_file, namespace)?;
        let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(blob_file)?;
        let writer: WriterFenceGeneration = durable.writer_fence()?;
        let deadline: u64 = SystemClock
            .now_unix_millis()?
            .checked_add(timeout_seconds.checked_mul(1000).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "source timeout overflow")
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "source deadline overflow")
            })?;
        let operation: DurableOperationContext = DurableOperationContext::new(
            writer,
            StorageDeadline::new(deadline).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid source deadline")
            })?,
            StorageCorrelationId::new([0xB8; 16]).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid source correlation")
            })?,
        );
        let origin: NamespaceLifecycle = durable
            .get_namespace_lifecycle(&operation, domain)
            .map_err(|error| io::Error::other(format!("source origin read failed: {error:?}")))?;
        if !origin.is_ordinary() {
            return Err(runtime_sqlite::SqliteDurableStoreError::InactiveNamespace.into());
        }
        Ok(Self {
            durable,
            blobs,
            operation,
        })
    }
}

#[cfg(test)]
mod tests;
