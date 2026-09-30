//! Body-free key/metadata reads and strict payload-range reads. These share
//! the engine's ordinary namespace/schema/writer/deadline read transaction.

use super::*;
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurablePortableRepository,
    DurablePortableSnapshotRepository, DurableRecordChunk, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordMetadata,
    DurableRecordPage, DurableRecordScan, MAX_PORTABLE_CHAIN_ID_BYTES, PortableSnapshotError,
    PortableSnapshotToken,
};
use std::num::NonZeroUsize;

impl From<crate::backend::SqlDecodeError> for PreCommitFailure {
    fn from(_: crate::backend::SqlDecodeError) -> Self {
        Self::InvalidPersistedState
    }
}

fn invalid(_: runtime::RuntimeError) -> PreCommitFailure {
    PreCommitFailure::InvalidPersistedState
}

fn nonzero_length(value: i64) -> Result<NonZeroUsize, PreCommitFailure> {
    usize::try_from(value)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)
}

fn version_descriptor(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    object_id: ObjectId,
    version: DurableObjectVersion,
) -> Result<Option<DurableRecordDescriptor>, PreCommitFailure> {
    let rows = session.exec(
        "SELECT digest_algorithm, digest_bytes, schema_version, type_id,
                substr(created_chain_id, 1, 129), created_protocol_version,
                created_checkpoint, length(inline_canonical_bytes),
                blob_digest_algorithm, blob_digest_bytes, typeof(inline_canonical_bytes)
         FROM durable_object_versions WHERE object_id = ?1 AND object_version = ?2",
        &[
            SqlValue::Blob(object_id.as_bytes().to_vec()),
            SqlValue::Blob(encode_u64(version.get()).to_vec()),
        ],
    )?;
    let Some(row) = rows.one()? else {
        return Ok(None);
    };
    let digest: Digest32 = decode_required_digest(row.integer(0)?, row.blob(1)?)?;
    let schema_version: u32 =
        u32::try_from(row.integer(2)?).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if u32::try_from(row.integer(3)?).ok() != Some(DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID) {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let chain: &str = row.text(4)?;
    if chain.len() > MAX_PORTABLE_CHAIN_ID_BYTES || chain != namespace.chain_id().as_str() {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let provenance: DurableObjectProvenance = DurableObjectProvenance::new(
        namespace.chain_id().clone(),
        ProtocolVersion::new(
            u32::try_from(row.integer(5)?).map_err(|_| PreCommitFailure::InvalidPersistedState)?,
        ),
    );
    let created_checkpoint: u64 =
        decode_u64(row.blob(6)?).ok_or(PreCommitFailure::InvalidPersistedState)?;
    let length: Option<i64> = row.opt_integer(7)?;
    let blob: Option<Digest32> = decode_optional_digest(row.opt_integer(8)?, row.opt_blob(9)?)?;
    let payload: DurablePayloadDescriptor = match (length, blob, row.text(10)?) {
        (Some(length), None, "blob") => DurablePayloadDescriptor::Inline(nonzero_length(length)?),
        (None, Some(digest), "null") => DurablePayloadDescriptor::BlobReference(digest),
        _ => return Err(PreCommitFailure::InvalidPersistedState),
    };
    DurableRecordDescriptor::new(
        DurableRecordKey::ObjectVersion(object_id, version),
        DurableRecordMetadata::ObjectVersion {
            digest,
            schema_version,
            provenance,
            created_checkpoint,
            payload,
        },
    )
    .map(Some)
    .map_err(invalid)
}

/// Cross-check against complete immutable-version metadata, without loading
/// that version's inline canonical body. Protocol content verification follows
/// after downloading the chunks; metadata alone is never execution authority.
fn head_descriptor(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    id: ObjectId,
) -> Result<Option<DurableRecordDescriptor>, PreCommitFailure> {
    let rows = session.exec(
        "SELECT status,head_revision,object_version,digest_algorithm,digest_bytes,
                substr(owner_projection,1,4097),substr(routing_projection,1,4097)
         FROM durable_object_heads WHERE object_id = ?1",
        &[SqlValue::Blob(id.as_bytes().to_vec())],
    )?;
    let Some(row) = rows.one()? else {
        if max_object_version(session, id)?.is_some() {
            return Err(PreCommitFailure::InvalidPersistedState);
        }
        return Ok(None);
    };
    let status: i64 = row.integer(0)?;
    let revision: ObjectHeadRevision = decode_u64(row.blob(1)?)
        .and_then(ObjectHeadRevision::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let version: Option<DurableObjectVersion> = row
        .opt_blob(2)?
        .map(|bytes| {
            decode_u64(bytes)
                .and_then(DurableObjectVersion::new)
                .ok_or(PreCommitFailure::InvalidPersistedState)
        })
        .transpose()?;
    let digest: Option<Digest32> = decode_optional_digest(row.opt_integer(3)?, row.opt_blob(4)?)?;
    let owner: Option<&[u8]> = row.opt_blob(5)?;
    let routing: Option<&[u8]> = row.opt_blob(6)?;
    let latest: DurableObjectVersion =
        max_object_version(session, id)?.ok_or(PreCommitFailure::InvalidPersistedState)?;
    let retained: DurableRecordDescriptor = version_descriptor(session, namespace, id, latest)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let head: DurableObjectHead = match status {
        OBJECT_HEAD_STATUS_TOMBSTONED
            if version.is_none() && digest.is_none() && owner.is_none() && routing.is_none() =>
        {
            DurableObjectHead::Tombstoned {
                head_revision: revision,
                last_object_version: latest,
            }
        }
        OBJECT_HEAD_STATUS_CURRENT if version == Some(latest) => {
            let digest: Digest32 = digest.ok_or(PreCommitFailure::InvalidPersistedState)?;
            if !matches!(retained.metadata(),DurableRecordMetadata::ObjectVersion{digest:stored,..} if *stored == digest)
            {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            DurableObjectHead::Current {
                head_revision: revision,
                object_version: latest,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_canonical_bytes(
                    owner.map(<[u8]>::to_vec),
                )
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
                routing_projection: DurableObjectRoutingProjection::new(
                    routing.map(<[u8]>::to_vec),
                )
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            }
        }
        _ => return Err(PreCommitFailure::InvalidPersistedState),
    };
    DurableRecordDescriptor::new(
        DurableRecordKey::ObjectHead(id),
        DurableRecordMetadata::ObjectHead(head),
    )
    .map(Some)
    .map_err(invalid)
}

fn descriptor(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    key: &DurableRecordKey,
) -> Result<Option<DurableRecordDescriptor>, PreCommitFailure> {
    let metadata: DurableRecordMetadata = match key {
        DurableRecordKey::State(key) => {
            let rows = session.exec(
                "SELECT revision,length(value),typeof(value) FROM durable_state WHERE key = ?1",
                &[SqlValue::Blob(key.clone())],
            )?;
            let Some(row) = rows.one()? else {
                return Ok(None);
            };
            let revision: StateRevision = StateRevision::new(
                decode_u64(row.blob(0)?).ok_or(PreCommitFailure::InvalidPersistedState)?,
            );
            let length: Option<i64> = row.opt_integer(1)?;
            if !matches!((length, row.text(2)?), (Some(_), "blob") | (None, "null")) {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            let value_length: Option<usize> = length
                .map(|n| usize::try_from(n).map_err(|_| PreCommitFailure::InvalidPersistedState))
                .transpose()?;
            DurableRecordMetadata::State {
                revision,
                value_length,
            }
        }
        DurableRecordKey::Receipt(id) => {
            let rows = session.exec("SELECT event_digest_algorithm,event_digest_bytes,length(canonical_bytes),typeof(canonical_bytes) FROM durable_receipts WHERE request_id = ?1",&[SqlValue::Blob(id.as_bytes().to_vec())])?;
            let Some(row) = rows.one()? else {
                return Ok(None);
            };
            if row.text(3)? != "blob" {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            DurableRecordMetadata::Receipt {
                event_digest: decode_required_digest(row.integer(0)?, row.blob(1)?)?,
                length: nonzero_length(row.integer(2)?)?,
            }
        }
        DurableRecordKey::ObjectHead(id) => return head_descriptor(session, namespace, *id),
        DurableRecordKey::ObjectVersion(id, version) => {
            return version_descriptor(session, namespace, *id, *version);
        }
    };
    DurableRecordDescriptor::new(key.clone(), metadata)
        .map(Some)
        .map_err(invalid)
}

fn key_page(
    session: &mut dyn SqlSession,
    scan: &DurableRecordScan,
) -> Result<DurableRecordPage, PreCommitFailure> {
    let count: i64 = i64::try_from(scan.limit().get() + 1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    // All interpolated identifiers/operators below are closed literals, never
    // caller strings. Cursor data remains bound SQL parameters.
    let (sql, params): (String, Vec<SqlValue>) = if scan.collection()
        == DurableCollection::ObjectVersions
    {
        match scan.after() {
            Some(DurableRecordKey::ObjectVersion(id,version)) => (
                "SELECT substr(object_id,1,33),substr(object_version,1,9) FROM durable_object_versions WHERE (object_id,object_version) > (?1,?2) ORDER BY object_id,object_version LIMIT ?3".to_owned(),
                vec![SqlValue::Blob(id.as_bytes().to_vec()),SqlValue::Blob(encode_u64(version.get()).to_vec()),SqlValue::Integer(count)]),
            None => ("SELECT substr(object_id,1,33),substr(object_version,1,9) FROM durable_object_versions ORDER BY object_id,object_version LIMIT ?1".to_owned(),vec![SqlValue::Integer(count)]),
            Some(_) => return Err(PreCommitFailure::InvalidPersistedState),
        }
    } else {
        let (table, column, start): (&str, &str, Vec<u8>) = match scan.collection() {
            DurableCollection::State => (
                "durable_state",
                "key",
                match scan.after() {
                    Some(DurableRecordKey::State(key)) => key.clone(),
                    None => Vec::new(),
                    Some(_) => return Err(PreCommitFailure::InvalidPersistedState),
                },
            ),
            DurableCollection::Receipts => (
                "durable_receipts",
                "request_id",
                match scan.after() {
                    Some(DurableRecordKey::Receipt(id)) => id.as_bytes().to_vec(),
                    None => vec![0; 32],
                    Some(_) => return Err(PreCommitFailure::InvalidPersistedState),
                },
            ),
            DurableCollection::ObjectHeads => (
                "durable_object_heads",
                "object_id",
                match scan.after() {
                    Some(DurableRecordKey::ObjectHead(id)) => id.as_bytes().to_vec(),
                    None => vec![0; 32],
                    Some(_) => return Err(PreCommitFailure::InvalidPersistedState),
                },
            ),
            DurableCollection::ObjectVersions => {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
        };
        // Bound even corrupt stored keys before copying them out of SQL. The
        // extra byte makes oversized keys fail validation, not truncate into
        // an apparently valid key. Order and cursor compare the original key.
        let bound: usize = if scan.collection() == DurableCollection::State {
            runtime::MAX_STATE_KEY_BYTES + 1
        } else {
            33
        };
        if scan.after().is_some() {
            (
                format!(
                    "SELECT substr({column},1,{bound}) FROM {table} WHERE {column} > ?1 ORDER BY {column} LIMIT ?2"
                ),
                vec![SqlValue::Blob(start), SqlValue::Integer(count)],
            )
        } else {
            (
                format!(
                    "SELECT substr({column},1,{bound}) FROM {table} ORDER BY {column} LIMIT ?1"
                ),
                vec![SqlValue::Integer(count)],
            )
        }
    };
    let rows = session.exec(&sql, &params)?;
    let mut keys: Vec<DurableRecordKey> = Vec::with_capacity(rows.rows().len());
    for row in rows.rows() {
        let bytes: &[u8] = row.blob(0)?;
        let key: DurableRecordKey = match scan.collection() {
            DurableCollection::State => DurableRecordKey::State(bytes.to_vec()),
            DurableCollection::Receipts => DurableRecordKey::Receipt(
                DurableRequestId::new(
                    bytes
                        .try_into()
                        .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
                )
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            ),
            DurableCollection::ObjectHeads => DurableRecordKey::ObjectHead(ObjectId::new(
                bytes
                    .try_into()
                    .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            )),
            DurableCollection::ObjectVersions => DurableRecordKey::ObjectVersion(
                ObjectId::new(
                    bytes
                        .try_into()
                        .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
                ),
                decode_u64(row.blob(1)?)
                    .and_then(DurableObjectVersion::new)
                    .ok_or(PreCommitFailure::InvalidPersistedState)?,
            ),
        };
        keys.push(key);
    }
    DurableRecordPage::from_ordered_candidates(scan, keys).map_err(invalid)
}

fn chunk(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    request: &DurableRecordChunkRequest,
) -> Result<DurableRecordChunkOutcome, PreCommitFailure> {
    let key: &DurableRecordKey = request.descriptor().key();
    if descriptor(session, namespace, key)?.as_ref() != Some(request.descriptor()) {
        return Ok(DurableRecordChunkOutcome::Changed);
    }
    let range: std::ops::Range<usize> = request.range();
    if range.is_empty() {
        // SQLite substr(x'', 1, 0) returns NULL. The exact descriptor was
        // already revalidated in this snapshot as Some(0), not a tombstone.
        return DurableRecordChunk::new(request.clone(), Vec::new())
            .map(|chunk| DurableRecordChunkOutcome::Chunk(Box::new(chunk)))
            .map_err(invalid);
    }
    let offset: i64 =
        i64::try_from(range.start + 1).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let count: i64 =
        i64::try_from(range.len()).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let (sql, params): (&str, Vec<SqlValue>) = match key {
        DurableRecordKey::State(key) => (
            "SELECT substr(value,?2,?3) FROM durable_state WHERE key = ?1",
            vec![
                SqlValue::Blob(key.clone()),
                SqlValue::Integer(offset),
                SqlValue::Integer(count),
            ],
        ),
        DurableRecordKey::Receipt(id) => (
            "SELECT substr(canonical_bytes,?2,?3) FROM durable_receipts WHERE request_id = ?1",
            vec![
                SqlValue::Blob(id.as_bytes().to_vec()),
                SqlValue::Integer(offset),
                SqlValue::Integer(count),
            ],
        ),
        DurableRecordKey::ObjectVersion(id, version) => (
            "SELECT substr(inline_canonical_bytes,?3,?4) FROM durable_object_versions WHERE object_id = ?1 AND object_version = ?2",
            vec![
                SqlValue::Blob(id.as_bytes().to_vec()),
                SqlValue::Blob(encode_u64(version.get()).to_vec()),
                SqlValue::Integer(offset),
                SqlValue::Integer(count),
            ],
        ),
        DurableRecordKey::ObjectHead(_) => return Err(PreCommitFailure::InvalidPersistedState),
    };
    let rows = session.exec(sql, &params)?;
    let bytes: Vec<u8> = rows
        .one()?
        .ok_or(PreCommitFailure::InvalidPersistedState)?
        .blob(0)?
        .to_vec();
    DurableRecordChunk::new(request.clone(), bytes)
        .map(|chunk| DurableRecordChunkOutcome::Chunk(Box::new(chunk)))
        .map_err(invalid)
}

impl<B: SqlBackend> DurablePortableRepository for SqlDurableEngine<B> {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.portable_read(context, domain, |session| key_page(session, scan))
    }
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        key.validate().map_err(DurableReadError::InvalidRequest)?;
        self.portable_read(context, domain, |session| {
            descriptor(session, &self.namespace, key)
        })
    }
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.portable_read(context, domain, |session| {
            chunk(session, &self.namespace, request)
        })
    }
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    fn portable_read<T>(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        read: impl FnOnce(&mut dyn SqlSession) -> Result<T, PreCommitFailure>,
    ) -> Result<T, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata: NamespaceMetadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            let value: T = read(session)?;
            check_deadline_before_commit(session, context)?;
            Ok(value)
        })
        .map_err(PreCommitFailure::into_read_error)
    }
}

/// Exact bounded local namespace identity: a one-byte chain-id length
/// prefix (explicit framing over a variable-length field, never bare
/// concatenation), the chain id itself (bounded to
/// [`MAX_PORTABLE_CHAIN_ID_BYTES`]), the 32-byte validator id, the 32-byte
/// atomicity domain, and the 16-byte random `source_instance_id` persisted
/// at trusted bootstrap. The last field is what distinguishes two
/// independently bootstrapped stores that otherwise share the same
/// chain/validator/domain tuple, so the same fence/sequence pair can never
/// validate against a different store's bytes. This is a local
/// source-identity bound, not a protocol or cut identifier; it is never
/// compared across replicas.
fn portable_namespace_bytes(
    namespace: &SqlDurableNamespace,
    source_instance_id: &[u8; 16],
) -> Result<Vec<u8>, runtime::RuntimeError> {
    // `PROVIDER_PREFIX` distinguishes this backend's identity bytes from any
    // other backend's, so two stores that happen to share the same
    // chain/validator/domain roots (e.g. a PostgreSQL and a SQL-durable
    // deployment mirroring the same namespace) never produce equal tokens.
    const PROVIDER_PREFIX: &[u8] = b"sql/";
    let chain_id: &[u8] = namespace.chain_id().as_str().as_bytes();
    if chain_id.len() > MAX_PORTABLE_CHAIN_ID_BYTES {
        return Err(runtime::RuntimeError::InvalidStateScanPage);
    }
    let length: u8 =
        u8::try_from(chain_id.len()).map_err(|_| runtime::RuntimeError::InvalidStateScanPage)?;
    let mut bytes: Vec<u8> =
        Vec::with_capacity(PROVIDER_PREFIX.len() + 1 + chain_id.len() + 32 + 32 + 16);
    bytes.extend_from_slice(PROVIDER_PREFIX);
    bytes.push(length);
    bytes.extend_from_slice(chain_id);
    bytes.extend_from_slice(namespace.validator_id().as_bytes());
    bytes.extend_from_slice(namespace.domain().as_bytes());
    bytes.extend_from_slice(source_instance_id);
    Ok(bytes)
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    fn portable_snapshot_read<T>(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        read: impl FnOnce(&mut dyn SqlSession) -> Result<T, PreCommitFailure>,
    ) -> Result<T, PortableSnapshotError> {
        if !self.domain_is_bound(domain) {
            return Err(PortableSnapshotError::Read(
                DurableReadError::InvalidRequest(RuntimeError::AtomicityDomainMismatch),
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata: NamespaceMetadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            let namespace_bytes: Vec<u8> =
                portable_namespace_bytes(&self.namespace, &metadata.source_instance_id())
                    .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
            if token
                .check(
                    &namespace_bytes,
                    domain,
                    metadata.writer_fence(),
                    metadata.mutation_sequence(),
                )
                .is_err()
            {
                return Err(PreCommitFailure::Changed);
            }
            let value: T = read(session)?;
            check_deadline_before_commit(session, context)?;
            Ok(value)
        })
        .map_err(|failure| match failure {
            PreCommitFailure::Changed => PortableSnapshotError::Changed,
            PreCommitFailure::NonemptyOutbox => PortableSnapshotError::NonemptyOutbox,
            other => PortableSnapshotError::Read(other.into_read_error()),
        })
    }
}

impl<B: SqlBackend> DurablePortableSnapshotRepository for SqlDurableEngine<B> {
    fn begin_portable_snapshot(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        if !self.domain_is_bound(domain) {
            return Err(PortableSnapshotError::Read(
                DurableReadError::InvalidRequest(RuntimeError::AtomicityDomainMismatch),
            ));
        }
        let (namespace_bytes, writer_fence, mutation_sequence) =
            run_read(&self.backend, Self::budget(context), |session, now| {
                check_deadline(context, now)?;
                let metadata: NamespaceMetadata =
                    schema::verify_namespace(session, &self.namespace)?;
                validate_authority(&metadata, context, now)?;
                let namespace_bytes: Vec<u8> =
                    portable_namespace_bytes(&self.namespace, &metadata.source_instance_id())
                        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
                check_deadline_before_commit(session, context)?;
                Ok((
                    namespace_bytes,
                    metadata.writer_fence(),
                    metadata.mutation_sequence(),
                ))
            })
            .map_err(|failure| PortableSnapshotError::Read(failure.into_read_error()))?;
        Ok(PortableSnapshotToken::new(
            namespace_bytes,
            domain,
            writer_fence,
            mutation_sequence,
        )?)
    }

    fn scan_portable_keys_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.portable_snapshot_read(context, domain, token, |session| key_page(session, scan))
    }

    fn read_portable_descriptor_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        key.validate().map_err(|error| {
            PortableSnapshotError::Read(DurableReadError::InvalidRequest(error))
        })?;
        self.portable_snapshot_read(context, domain, token, |session| {
            descriptor(session, &self.namespace, key)
        })
    }

    fn read_portable_chunk_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.portable_snapshot_read(context, domain, token, |session| {
            chunk(session, &self.namespace, request)
        })
    }

    fn check_portable_outbox_empty_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.portable_snapshot_read(context, domain, token, |session| {
            let inventory = super::outbox_guard::probe(session)?;
            if inventory.blocks_exclusion() {
                return Err(PreCommitFailure::NonemptyOutbox);
            }
            Ok(())
        })
    }
}
