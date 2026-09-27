//! Namespace-scoped keyset enumeration and serializable bounded range reads.
//! No full payload column is selected by key/descriptor reads.

use super::*;
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurablePortableRepository, DurableRecordChunk,
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordDescriptor,
    DurableRecordKey, DurableRecordMetadata, DurableRecordPage, DurableRecordScan,
};
use std::num::NonZeroUsize;

fn row_value<T: postgres::types::FromSqlOwned>(
    row: &postgres::Row,
    index: usize,
) -> Result<T, PreCommitFailure> {
    row.try_get(index)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}
fn length(value: i32) -> Result<NonZeroUsize, PreCommitFailure> {
    usize::try_from(value)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)
}
fn descriptor(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    key: &DurableRecordKey,
) -> Result<Option<DurableRecordDescriptor>, PreCommitFailure> {
    let prefix: &str = "chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3";
    let metadata: DurableRecordMetadata = match key {
        DurableRecordKey::State(key) => {
            let sql: String = format!(
                "SELECT revision::TEXT,octet_length(canonical_bytes),tombstone,type_id,encoding_version FROM sunrise_edge.state_records WHERE {prefix} AND record_kind_id = $4 AND state_key = $5"
            );
            let row: Option<postgres::Row> = transaction
                .query_opt(
                    &sql,
                    &[
                        &namespace.chain_id_bytes(),
                        &&namespace.validator_id().as_bytes()[..],
                        &&namespace.domain().as_bytes()[..],
                        &STATE_RECORD_KIND_APPLICATION,
                        &key.as_slice(),
                    ],
                )
                .map_err(|error| PreCommitFailure::from_database(&error))?;
            let Some(row) = row else { return Ok(None) };
            let revision: StateRevision = StateRevision::new(parse_database_u64(&row, 0)?);
            let value_length: Option<i32> = row_value(&row, 1)?;
            let tombstone: bool = row_value(&row, 2)?;
            if tombstone != value_length.is_none()
                || row_value::<i64>(&row, 3)? != STATE_RECORD_TYPE_OPAQUE_CANONICAL
                || row_value::<i64>(&row, 4)? != STATE_RECORD_ENCODING_VERSION
            {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            DurableRecordMetadata::State {
                revision,
                value_length: value_length
                    .map(|n| {
                        usize::try_from(n).map_err(|_| PreCommitFailure::InvalidPersistedState)
                    })
                    .transpose()?,
            }
        }
        DurableRecordKey::Receipt(id) => {
            let sql: String = format!(
                "SELECT event_digest_algorithm_id,event_digest_bytes,octet_length(canonical_response_bytes),terminal_result_id,commit_sequence::TEXT FROM sunrise_edge.request_receipts WHERE {prefix} AND request_id = $4"
            );
            let row: Option<postgres::Row> = transaction
                .query_opt(
                    &sql,
                    &[
                        &namespace.chain_id_bytes(),
                        &&namespace.validator_id().as_bytes()[..],
                        &&namespace.domain().as_bytes()[..],
                        &&id.as_bytes()[..],
                    ],
                )
                .map_err(|error| PreCommitFailure::from_database(&error))?;
            let Some(row) = row else { return Ok(None) };
            if row_value::<i64>(&row, 3)? != RECEIPT_TERMINAL_RESULT_COMMITTED
                || parse_database_u64(&row, 4)? == 0
            {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            DurableRecordMetadata::Receipt {
                event_digest: parse_optional_digest(&row, 0, 1)?
                    .ok_or(PreCommitFailure::InvalidPersistedState)?,
                length: length(row_value(&row, 2)?)?,
            }
        }
        DurableRecordKey::ObjectHead(id) => {
            // Existing body-free head path checks latest immutable-version
            // metadata, including unsigned numeric history ordering.
            match load_object_head(transaction, namespace, *id, false)? {
                DurableObjectHead::Absent => return Ok(None),
                head => DurableRecordMetadata::ObjectHead(head),
            }
        }
        DurableRecordKey::ObjectVersion(id, version) => {
            let sql: String = format!(
                "SELECT digest_algorithm_id,digest_bytes,schema_version,type_id,created_chain_id_bytes,created_protocol_version,created_checkpoint::TEXT,octet_length(inline_canonical_bytes),blob_digest_algorithm_id,blob_digest_bytes FROM sunrise_edge.object_versions WHERE {prefix} AND object_id = $4 AND object_version = CAST(CAST($5 AS TEXT) AS NUMERIC)"
            );
            let row: Option<postgres::Row> = transaction
                .query_opt(
                    &sql,
                    &[
                        &namespace.chain_id_bytes(),
                        &&namespace.validator_id().as_bytes()[..],
                        &&namespace.domain().as_bytes()[..],
                        &&id.as_bytes()[..],
                        &version.get().to_string(),
                    ],
                )
                .map_err(|error| PreCommitFailure::from_database(&error))?;
            let Some(row) = row else { return Ok(None) };
            let digest: Digest32 = parse_optional_digest(&row, 0, 1)?
                .ok_or(PreCommitFailure::InvalidPersistedState)?;
            let schema_version: u32 = u32::try_from(row_value::<i64>(&row, 2)?)
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
            if u32::try_from(row_value::<i64>(&row, 3)?).ok()
                != Some(DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID)
            {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            let chain: Vec<u8> = row_value(&row, 4)?;
            if chain.as_slice() != namespace.chain_id_bytes() {
                return Err(PreCommitFailure::InvalidPersistedState);
            }
            let protocol: ProtocolVersion = ProtocolVersion::new(
                u32::try_from(row_value::<i64>(&row, 5)?)
                    .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            );
            let chain_id: ChainId = ChainId::new(
                String::from_utf8(chain).map_err(|_| PreCommitFailure::InvalidPersistedState)?,
            )
            .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
            let provenance: DurableObjectProvenance =
                DurableObjectProvenance::new(chain_id, protocol);
            let created_checkpoint: u64 = parse_database_u64(&row, 6)?;
            let inline: Option<i32> = row_value(&row, 7)?;
            let blob: Option<Digest32> = parse_optional_digest(&row, 8, 9)?;
            let payload: DurablePayloadDescriptor = match (inline, blob) {
                (Some(n), None) => DurablePayloadDescriptor::Inline(length(n)?),
                (None, Some(digest)) => DurablePayloadDescriptor::BlobReference(digest),
                _ => return Err(PreCommitFailure::InvalidPersistedState),
            };
            DurableRecordMetadata::ObjectVersion {
                digest,
                schema_version,
                provenance,
                created_checkpoint,
                payload,
            }
        }
    };
    DurableRecordDescriptor::new(key.clone(), metadata)
        .map(Some)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn key_page(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    scan: &DurableRecordScan,
) -> Result<DurableRecordPage, PreCommitFailure> {
    let count: i64 = i64::try_from(scan.limit().get() + 1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let prefix: &str = "chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3";
    // Closed identifier interpolation only. Numeric ORDER BY refers to the
    // qualified table column, not the object_version::TEXT output alias.
    let rows:Vec<postgres::Row>=match scan.collection() {
        DurableCollection::State=>{
            match scan.after() {
                Some(DurableRecordKey::State(key))=>transaction.query(&format!("SELECT substring(state_key from 1 for 4097),record_kind_id FROM sunrise_edge.state_records WHERE {prefix} AND (record_kind_id,state_key) > ($4,$5) ORDER BY record_kind_id,state_key LIMIT $6"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&STATE_RECORD_KIND_APPLICATION,&key.as_slice(),&count]),
                _=>transaction.query(&format!("SELECT substring(state_key from 1 for 4097),record_kind_id FROM sunrise_edge.state_records WHERE {prefix} ORDER BY record_kind_id,state_key LIMIT $4"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&count]),
            }
        }
        DurableCollection::Receipts|DurableCollection::ObjectHeads=>{
            let (table,column,start):(&str,&str,Vec<u8>)=match scan.collection() {
                DurableCollection::Receipts=>("request_receipts","request_id",match scan.after(){Some(DurableRecordKey::Receipt(id))=>id.as_bytes().to_vec(),_=>vec![0;32]}),
                _=>("object_heads","object_id",match scan.after(){Some(DurableRecordKey::ObjectHead(id))=>id.as_bytes().to_vec(),_=>vec![0;32]}),
            };
            let operator:&str=if scan.after().is_some(){">"}else{">="};
            transaction.query(&format!("SELECT {column} FROM sunrise_edge.{table} WHERE {prefix} AND {column} {operator} $4 ORDER BY {column} LIMIT $5"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&start,&count])
        }
        DurableCollection::ObjectVersions=>{
            match scan.after() {
                Some(DurableRecordKey::ObjectVersion(id,version))=>transaction.query(&format!("SELECT object_id,object_version::TEXT FROM sunrise_edge.object_versions AS v WHERE {prefix} AND (object_id,v.object_version) > ($4,CAST(CAST($5 AS TEXT) AS NUMERIC)) ORDER BY object_id,v.object_version LIMIT $6"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&&id.as_bytes()[..],&version.get().to_string(),&count]),
                _=>transaction.query(&format!("SELECT object_id,object_version::TEXT FROM sunrise_edge.object_versions AS v WHERE {prefix} ORDER BY object_id,v.object_version LIMIT $4"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&count]),
            }
        }
    }.map_err(|error|PreCommitFailure::from_database(&error))?;
    let mut keys: Vec<DurableRecordKey> = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes: Vec<u8> = row_value(&row, 0)?;
        let key: DurableRecordKey = match scan.collection() {
            DurableCollection::State => {
                if row_value::<i32>(&row, 1)? != STATE_RECORD_KIND_APPLICATION {
                    return Err(PreCommitFailure::InvalidPersistedState);
                }
                DurableRecordKey::State(bytes)
            }
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
                DurableObjectVersion::new(parse_database_u64(&row, 1)?)
                    .ok_or(PreCommitFailure::InvalidPersistedState)?,
            ),
        };
        keys.push(key);
    }
    DurableRecordPage::from_ordered_candidates(scan, keys)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn chunk(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    request: &DurableRecordChunkRequest,
) -> Result<DurableRecordChunkOutcome, PreCommitFailure> {
    let key: &DurableRecordKey = request.descriptor().key();
    if descriptor(transaction, namespace, key)?.as_ref() != Some(request.descriptor()) {
        return Ok(DurableRecordChunkOutcome::Changed);
    }
    let range: std::ops::Range<usize> = request.range();
    let start: i32 =
        i32::try_from(range.start + 1).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let count: i32 =
        i32::try_from(range.len()).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let prefix: &str = "chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3";
    let row:Option<postgres::Row>=match key {
        DurableRecordKey::State(key)=>transaction.query_opt(&format!("SELECT substring(canonical_bytes FROM $6 FOR $7) FROM sunrise_edge.state_records WHERE {prefix} AND record_kind_id = $4 AND state_key = $5"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&STATE_RECORD_KIND_APPLICATION,&key.as_slice(),&start,&count]),
        DurableRecordKey::Receipt(id)=>transaction.query_opt(&format!("SELECT substring(canonical_response_bytes FROM $5 FOR $6) FROM sunrise_edge.request_receipts WHERE {prefix} AND request_id = $4"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&&id.as_bytes()[..],&start,&count]),
        DurableRecordKey::ObjectVersion(id,version)=>transaction.query_opt(&format!("SELECT substring(inline_canonical_bytes FROM $6 FOR $7) FROM sunrise_edge.object_versions WHERE {prefix} AND object_id = $4 AND object_version = CAST(CAST($5 AS TEXT) AS NUMERIC)"),&[&namespace.chain_id_bytes(),&&namespace.validator_id().as_bytes()[..],&&namespace.domain().as_bytes()[..],&&id.as_bytes()[..],&version.get().to_string(),&start,&count]),
        DurableRecordKey::ObjectHead(_)=>return Err(PreCommitFailure::InvalidPersistedState),
    }.map_err(|error|PreCommitFailure::from_database(&error))?;
    let row: postgres::Row = row.ok_or(PreCommitFailure::InvalidPersistedState)?;
    let bytes: Vec<u8> = row_value(&row, 0)?;
    DurableRecordChunk::new(request.clone(), bytes)
        .map(|chunk| DurableRecordChunkOutcome::Chunk(Box::new(chunk)))
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

impl<M> DurablePortableRepository for PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.portable_read(context, domain, |transaction| {
            key_page(transaction, &self.namespace, scan)
        })
    }
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        key.validate().map_err(DurableReadError::InvalidRequest)?;
        self.portable_read(context, domain, |transaction| {
            descriptor(transaction, &self.namespace, key)
        })
    }
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.portable_read(context, domain, |transaction| {
            chunk(transaction, &self.namespace, request)
        })
    }
}
impl<M> PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn portable_read<T>(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        read: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<T, PreCommitFailure>,
    ) -> Result<T, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                runtime::RuntimeError::AtomicityDomainMismatch,
            ));
        }
        let mut client = self
            .acquire(context)
            .map_err(PreCommitFailure::into_read_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(true)
            .start()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        set_local_timeouts(&mut transaction, context).map_err(PreCommitFailure::into_read_error)?;
        let metadata =
            load_namespace_metadata(&mut transaction, &self.namespace, MetadataLockMode::None)
                .map_err(PreCommitFailure::into_read_error)?;
        validate_operation_authority(metadata, context)
            .map_err(PreCommitFailure::into_read_error)?;
        let value: T = read(&mut transaction).map_err(PreCommitFailure::into_read_error)?;
        transaction
            .rollback()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        remaining_deadline(context).map_err(PreCommitFailure::into_read_error)?;
        Ok(value)
    }
}
