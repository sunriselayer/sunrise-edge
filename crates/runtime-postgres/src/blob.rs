//! Namespace-bound PostgreSQL implementation of [`runtime::BlobStore`].
//!
//! [`runtime::BlobStore`] carries no [`runtime::DurableOperationContext`] and
//! no writer-fence generation: unlike [`crate::PostgresDurableStore`], a
//! [`PostgresBlobStore`] cannot fence a live writer out, and callers must not
//! treat it as though it could. It exists only for immutable,
//! content-addressed `put`/`get` of blob bytes referenced by digest from the
//! fence-bearing structured store; ordering, exclusivity, and failover
//! authority all remain the structured store's job.

use postgres::Client;
use protocol_types::Digest32;
use r2d2_postgres::r2d2::{self, ManageConnection, Pool, PooledConnection};
use runtime::{BlobStore, MAX_STATE_VALUE_BYTES, RuntimeError};
use std::{error::Error, fmt};

use crate::{PostgresNamespace, PostgresSchemaError, inspect_namespace, verify_initial_schema};

/// Construction-time failure binding a [`PostgresBlobStore`] to its pool and namespace.
#[derive(Debug)]
pub enum PostgresBlobStoreError {
    /// The bounded pool could not hand back a connection.
    Pool(r2d2::Error),
    /// The applied schema identity or bootstrapped namespace metadata did
    /// not verify.
    Schema(PostgresSchemaError),
}

impl fmt::Display for PostgresBlobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pool(error) => write!(f, "PostgreSQL pool connection failed: {error}"),
            Self::Schema(error) => write!(f, "PostgreSQL blob store schema check failed: {error}"),
        }
    }
}

impl Error for PostgresBlobStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pool(error) => Some(error),
            Self::Schema(error) => Some(error),
        }
    }
}

impl From<PostgresSchemaError> for PostgresBlobStoreError {
    fn from(value: PostgresSchemaError) -> Self {
        Self::Schema(value)
    }
}

/// Namespace-bound PostgreSQL [`BlobStore`] over `sunrise_edge.blobs`.
///
/// Every row is keyed by the exact chain/validator/domain namespace triple
/// plus a hash algorithm and digest, and is bound by a foreign key to the
/// same `storage_metadata` row a [`crate::PostgresDurableStore`] for this
/// namespace verifies. Content is immutable: `put_blob` is atomic
/// insert-if-absent (byte-identical content already stored under `digest` is
/// an idempotent no-op; different content already stored under `digest` is a
/// fail-closed [`RuntimeError::BlobDigestConflict`] that never overwrites the
/// existing bytes), and this type defines no delete operation. See the
/// module documentation for why this type cannot fence a live writer the way
/// [`crate::PostgresDurableStore`] can.
pub struct PostgresBlobStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error>,
{
    pool: Pool<M>,
    namespace: PostgresNamespace,
}

impl<M> PostgresBlobStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    /// Binds an already configured bounded pool to one exact namespace.
    ///
    /// The applied schema identity and the namespace's already-bootstrapped
    /// metadata row are verified now, at construction, exactly once; request
    /// handling (`put_blob`/`get_blob`) never re-runs this bootstrap check.
    /// Every write still goes through the `blobs` table's foreign key to
    /// `storage_metadata`, so a namespace whose metadata row somehow stopped
    /// existing after construction still fails closed on the next write.
    pub fn new(
        pool: Pool<M>,
        namespace: PostgresNamespace,
    ) -> Result<Self, PostgresBlobStoreError> {
        let mut connection = pool.get().map_err(PostgresBlobStoreError::Pool)?;
        verify_initial_schema(&mut *connection)?;
        let metadata = inspect_namespace(&mut *connection, &namespace)?;
        if metadata.is_none() {
            return Err(PostgresBlobStoreError::Schema(
                PostgresSchemaError::NamespaceMetadataMismatch,
            ));
        }
        // Reject a tampered or partially installed blob schema before an
        // operator claims a new writer generation. This prepares but never
        // scans rows or mutates the namespace.
        connection
            .prepare(
                "SELECT blob_bytes FROM sunrise_edge.blobs
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND digest_algorithm_id = $4
               AND digest_bytes = $5",
            )
            .map_err(PostgresSchemaError::from)?;
        drop(connection);
        Ok(Self { pool, namespace })
    }

    /// Returns the exact namespace this store is authorized to access.
    #[must_use]
    pub const fn namespace(&self) -> &PostgresNamespace {
        &self.namespace
    }

    fn acquire(&self) -> Result<PooledConnection<M>, RuntimeError> {
        self.pool
            .get()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)
    }
}

impl<M> BlobStore for PostgresBlobStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        if bytes.len() > MAX_STATE_VALUE_BYTES {
            return Err(RuntimeError::StateValueTooLarge {
                length: bytes.len(),
                maximum: MAX_STATE_VALUE_BYTES,
            });
        }
        let algorithm_id: i32 = i32::from(digest.algorithm().as_u16());
        let digest_bytes: [u8; 32] = digest.bytes();
        let mut connection: PooledConnection<M> = self.acquire()?;
        let mut transaction = connection
            .transaction()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        // `ON CONFLICT DO NOTHING` takes the same unique-index row lock a
        // conflicting insert would, so a concurrent `put_blob` for the same
        // digest serializes here: the second transaction blocks until the
        // first commits or aborts, then either sees its row already present
        // (first committed) or inserts it itself (first aborted). The
        // `FOR SHARE` select that follows locks the settled row for the rest
        // of this transaction, so nothing else can be mid-write to it when
        // the byte comparison below runs.
        transaction
            .execute(
                "INSERT INTO sunrise_edge.blobs (
                     chain_id_bytes, validator_id, atomicity_domain_id,
                     digest_algorithm_id, digest_bytes, blob_bytes
                 ) VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (
                     chain_id_bytes, validator_id, atomicity_domain_id,
                     digest_algorithm_id, digest_bytes
                 ) DO NOTHING",
                &[
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                    &algorithm_id,
                    &&digest_bytes[..],
                    &bytes,
                ],
            )
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        let row = transaction
            .query_opt(
                "SELECT blob_bytes FROM sunrise_edge.blobs
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND digest_algorithm_id = $4
                   AND digest_bytes = $5
                 FOR SHARE",
                &[
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                    &algorithm_id,
                    &&digest_bytes[..],
                ],
            )
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        let Some(row) = row else {
            // The insert above unconditionally targets this exact row, so a
            // read-committed select of the same key inside the same
            // transaction finding nothing means the namespace's foreign key
            // rejected the insert or something else left persisted state
            // inconsistent with what this transaction just wrote.
            return Err(RuntimeError::DurableStoreUnavailable);
        };
        let stored_bytes: Vec<u8> = row
            .try_get(0)
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        if stored_bytes != bytes {
            transaction
                .rollback()
                .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
            return Err(RuntimeError::BlobDigestConflict { digest });
        }
        transaction
            .commit()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        Ok(())
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        let algorithm_id: i32 = i32::from(digest.algorithm().as_u16());
        let digest_bytes: [u8; 32] = digest.bytes();
        let mut connection: PooledConnection<M> = self.acquire()?;
        let row = connection
            .query_opt(
                "SELECT blob_bytes FROM sunrise_edge.blobs
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND digest_algorithm_id = $4
                   AND digest_bytes = $5",
                &[
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                    &algorithm_id,
                    &&digest_bytes[..],
                ],
            )
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        match row {
            None => Ok(None),
            Some(row) => {
                let bytes: Vec<u8> = row
                    .try_get(0)
                    .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
                Ok(Some(bytes))
            }
        }
    }
}
