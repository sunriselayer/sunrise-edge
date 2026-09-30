//! Backend-neutral structured durable engine.
//!
//! Every function here issues the exact statement text and applies the
//! exact validation/commit rules `runtime-sqlite` used to implement
//! directly against `rusqlite`. `SqlDurableEngine` wires those functions
//! into the four `runtime` durable traits for any `SqlBackend`; a native
//! host and a Durable Object host both get identical statements, decoding,
//! and rejection rules by construction, never two independently
//! maintained copies.

mod outbox_guard;
mod portable;

use crate::backend::{
    SqlBackend, SqlBackendError, SqlSession, SqlSessionError, SqlValue, TransactionBudget,
    TransactionDecision,
};
use crate::schema::{
    self, NamespaceMetadata, OBJECT_HEAD_STATUS_CURRENT, OBJECT_HEAD_STATUS_TOMBSTONED,
    OUTBOX_ATTEMPT_ACKNOWLEDGED, OUTBOX_ATTEMPT_CLAIMED, OUTBOX_ATTEMPT_EXPIRED,
    SqlDurableNamespace, decode_u64, encode_u64,
};
use protocol_types::{ChainId, Digest32, HashAlgorithmId, ProtocolVersion};
use runtime::{
    AtomicStateTransaction, AtomicityDomainId, DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID,
    DueOutboxClaimRequest, DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectHeadSummary, DurableObjectMutation, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaim, DurableOutboxClaimOutcome,
    DurableOutboxClaimRejection, DurableOutboxLeaseId, DurableReadError, DurableRequestId,
    DurableRequestReceipt, DurableStateKeyScanner, IndeterminateCommitReason,
    IndexedOutboxRepository, ObjectHeadRevision, ObjectId, OutboxRequestId,
    RequestOutboxClaimRequest, RuntimeError, StateKeyPage, StateKeyScan, StateMutation,
    StateMutationEntry, StateReadAssertion, StateRevision, StructuredDurableDomainStateStore,
    VersionedStateValue, WriterFenceGeneration,
};

/// Pre-commit classification of one failed SQL read/write attempt.
#[derive(Debug)]
enum PreCommitFailure {
    Deadline,
    WriterFenced(WriterFenceGeneration),
    SchemaMismatch,
    InvalidPersistedState,
    Unavailable,
    MutationSequenceOverflow,
    Changed,
    NonemptyOutbox,
}

impl PreCommitFailure {
    fn into_read_error(self) -> DurableReadError {
        match self {
            Self::Deadline => DurableReadError::DeadlineExceeded,
            Self::WriterFenced(active_generation) => {
                DurableReadError::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableReadError::SchemaMismatch,
            Self::InvalidPersistedState => DurableReadError::InvalidPersistedState,
            Self::Unavailable => DurableReadError::Unavailable,
            Self::MutationSequenceOverflow | Self::Changed | Self::NonemptyOutbox => {
                DurableReadError::InvalidPersistedState
            }
        }
    }

    fn into_commit_rejection(self) -> DurableCommitRejection {
        match self {
            Self::Deadline => DurableCommitRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableCommitRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableCommitRejection::SchemaMismatch,
            Self::InvalidPersistedState => DurableCommitRejection::InvalidPersistedState,
            Self::Unavailable => DurableCommitRejection::UnavailableBeforeCommit,
            Self::MutationSequenceOverflow => DurableCommitRejection::CommitSequenceOverflow,
            Self::Changed | Self::NonemptyOutbox => DurableCommitRejection::InvalidPersistedState,
        }
    }

    fn into_claim_rejection(self) -> DurableOutboxClaimRejection {
        match self {
            Self::Deadline => DurableOutboxClaimRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxClaimRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableOutboxClaimRejection::SchemaMismatch,
            Self::InvalidPersistedState => DurableOutboxClaimRejection::InvalidPersistedState,
            Self::Unavailable => DurableOutboxClaimRejection::UnavailableBeforeCommit,
            Self::MutationSequenceOverflow => DurableOutboxClaimRejection::ArithmeticOverflow,
            Self::Changed | Self::NonemptyOutbox => {
                DurableOutboxClaimRejection::InvalidPersistedState
            }
        }
    }

    fn into_acknowledgement_rejection(self) -> DurableOutboxAcknowledgementRejection {
        match self {
            Self::Deadline => DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxAcknowledgementRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableOutboxAcknowledgementRejection::SchemaMismatch,
            Self::InvalidPersistedState => {
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            }
            Self::Unavailable => DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
            Self::MutationSequenceOverflow => {
                DurableOutboxAcknowledgementRejection::ArithmeticOverflow
            }
            Self::Changed | Self::NonemptyOutbox => {
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            }
        }
    }
}

impl From<SqlSessionError> for PreCommitFailure {
    fn from(_value: SqlSessionError) -> Self {
        Self::Unavailable
    }
}

impl From<schema::SchemaError> for PreCommitFailure {
    fn from(value: schema::SchemaError) -> Self {
        match value {
            schema::SchemaError::Session(_) => Self::Unavailable,
            schema::SchemaError::SchemaIdentityMismatch
            | schema::SchemaError::NamespaceMismatch
            | schema::SchemaError::InvalidPersistedMetadata => Self::SchemaMismatch,
            schema::SchemaError::ZeroWriterFence => Self::InvalidPersistedState,
            schema::SchemaError::WriterFenceMismatch { .. } => Self::InvalidPersistedState,
            schema::SchemaError::MutationSequenceOverflow => Self::MutationSequenceOverflow,
            schema::SchemaError::MutationSequenceConflict => Self::InvalidPersistedState,
        }
    }
}

fn check_deadline(
    context: &DurableOperationContext,
    now_unix_millis: u64,
) -> Result<(), PreCommitFailure> {
    if context.deadline().is_expired_at(now_unix_millis) {
        return Err(PreCommitFailure::Deadline);
    }
    Ok(())
}

/// Re-reads the host's trusted clock through the active session
/// immediately before finalizing a commit decision, instead of reusing
/// the `now` `SqlBackend::transaction` supplied when the transaction
/// began.
///
/// A native backend samples that initial `now` only after it already
/// holds its file lock, so real time can still advance past the
/// caller's deadline while an earlier statement inside this same
/// transaction was blocked on a contended lock; only a value read after
/// every statement has already run proves the deadline held throughout.
/// Every other deadline check in this module, and every outbox lease
/// decision, intentionally keeps using the initial `now` so a single
/// transaction stays internally consistent.
fn check_deadline_before_commit(
    session: &mut dyn SqlSession,
    context: &DurableOperationContext,
) -> Result<(), PreCommitFailure> {
    let now = session
        .now_unix_millis()
        .map_err(|_| PreCommitFailure::Unavailable)?;
    check_deadline(context, now)
}

fn validate_authority(
    metadata: &NamespaceMetadata,
    context: &DurableOperationContext,
    now_unix_millis: u64,
) -> Result<(), PreCommitFailure> {
    if metadata.writer_fence() != context.writer_fence() {
        return Err(PreCommitFailure::WriterFenced(metadata.writer_fence()));
    }
    check_deadline(context, now_unix_millis)
}

/// Strictly decodes one required `(algorithm, bytes)` digest column pair.
fn decode_required_digest(algorithm: i64, bytes: &[u8]) -> Result<Digest32, PreCommitFailure> {
    let algorithm: HashAlgorithmId = u16::try_from(algorithm)
        .ok()
        .and_then(|value| HashAlgorithmId::try_from(value).ok())
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    Ok(Digest32::new(algorithm, bytes))
}

/// Strictly decodes one optional `(algorithm, bytes)` digest column pair.
/// Only both columns null means the digest is genuinely absent.
fn decode_optional_digest(
    algorithm: Option<i64>,
    bytes: Option<&[u8]>,
) -> Result<Option<Digest32>, PreCommitFailure> {
    match (algorithm, bytes) {
        (None, None) => Ok(None),
        (Some(algorithm), Some(bytes)) => decode_required_digest(algorithm, bytes).map(Some),
        (None, Some(_)) | (Some(_), None) => Err(PreCommitFailure::InvalidPersistedState),
    }
}

/// Strictly decodes one `0`/`1` `INTEGER` column as a boolean.
fn decode_bool(value: i64) -> Result<bool, PreCommitFailure> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PreCommitFailure::InvalidPersistedState),
    }
}

/// Typed, strictly decoded status of one `durable_outbox_attempts` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboxAttemptStatus {
    Claimed,
    Acknowledged,
    Expired,
}

impl OutboxAttemptStatus {
    fn decode(value: i64) -> Result<Self, PreCommitFailure> {
        match value {
            OUTBOX_ATTEMPT_CLAIMED => Ok(Self::Claimed),
            OUTBOX_ATTEMPT_ACKNOWLEDGED => Ok(Self::Acknowledged),
            OUTBOX_ATTEMPT_EXPIRED => Ok(Self::Expired),
            _ => Err(PreCommitFailure::InvalidPersistedState),
        }
    }

    const fn encode(self) -> i64 {
        match self {
            Self::Claimed => OUTBOX_ATTEMPT_CLAIMED,
            Self::Acknowledged => OUTBOX_ATTEMPT_ACKNOWLEDGED,
            Self::Expired => OUTBOX_ATTEMPT_EXPIRED,
        }
    }
}

/// Returns the smallest exclusive upper bound for every key sharing
/// `prefix`, or `None` if `prefix` has no finite upper bound (for example
/// an all-`0xFF` prefix).
fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    let index = upper.iter().rposition(|byte| *byte != u8::MAX)?;
    upper[index] += 1;
    upper.truncate(index + 1);
    Some(upper)
}

fn load_state_value(
    session: &mut dyn SqlSession,
    key: &[u8],
) -> Result<VersionedStateValue, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT revision, value FROM durable_state WHERE key = ?1",
            &[SqlValue::Blob(key.to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
            .map_err(|_| PreCommitFailure::InvalidPersistedState);
    };
    let revision = decode_u64(row.blob(0).map_err(SqlSessionError::from)?)
        .map(StateRevision::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    if revision == StateRevision::INITIAL {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let value = row
        .opt_blob(1)
        .map_err(SqlSessionError::from)?
        .map(<[u8]>::to_vec);
    VersionedStateValue::from_persisted_parts(revision, value)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

/// Loads at most `scan.limit() + 1` ordered candidate keys strictly after
/// the cursor and within the prefix. Tombstoned keys are not filtered:
/// the caller must see them to fail closed instead of treating a
/// deletion as absent.
fn load_state_key_page(
    session: &mut dyn SqlSession,
    scan: &StateKeyScan,
) -> Result<StateKeyPage, PreCommitFailure> {
    let upper_bound = prefix_upper_bound(scan.prefix());
    let candidate_limit = i64::try_from(scan.limit().get() + 1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let start_key: &[u8] = scan.after().unwrap_or_else(|| scan.prefix());
    let (sql, params): (&str, Vec<SqlValue>) =
        match (scan.after().is_some(), upper_bound.as_deref()) {
            (true, Some(upper)) => (
                "SELECT key FROM durable_state WHERE key > ?1 AND key < ?2 ORDER BY key LIMIT ?3",
                vec![
                    SqlValue::Blob(start_key.to_vec()),
                    SqlValue::Blob(upper.to_vec()),
                    SqlValue::Integer(candidate_limit),
                ],
            ),
            (true, None) => (
                "SELECT key FROM durable_state WHERE key > ?1 ORDER BY key LIMIT ?2",
                vec![
                    SqlValue::Blob(start_key.to_vec()),
                    SqlValue::Integer(candidate_limit),
                ],
            ),
            (false, Some(upper)) => (
                "SELECT key FROM durable_state WHERE key >= ?1 AND key < ?2 ORDER BY key LIMIT ?3",
                vec![
                    SqlValue::Blob(start_key.to_vec()),
                    SqlValue::Blob(upper.to_vec()),
                    SqlValue::Integer(candidate_limit),
                ],
            ),
            (false, None) => (
                "SELECT key FROM durable_state WHERE key >= ?1 ORDER BY key LIMIT ?2",
                vec![
                    SqlValue::Blob(start_key.to_vec()),
                    SqlValue::Integer(candidate_limit),
                ],
            ),
        };
    let rows = session.exec(sql, &params).map_err(PreCommitFailure::from)?;
    let mut keys = Vec::new();
    for row in rows.rows() {
        keys.push(row.blob(0).map_err(SqlSessionError::from)?.to_vec());
    }
    StateKeyPage::from_ordered_candidates(scan, keys)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn upsert_state(
    session: &mut dyn SqlSession,
    key: &[u8],
    revision: StateRevision,
    value: Option<&[u8]>,
) -> Result<(), PreCommitFailure> {
    session
        .exec(
            "INSERT INTO durable_state (key, revision, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET revision = excluded.revision, value = excluded.value",
            &[
                SqlValue::Blob(key.to_vec()),
                SqlValue::Blob(encode_u64(revision.get()).to_vec()),
                value.map(<[u8]>::to_vec).into(),
            ],
        )
        .map_err(PreCommitFailure::from)?;
    Ok(())
}

fn validate_state_reads(
    session: &mut dyn SqlSession,
    reads: &[StateReadAssertion],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current = load_state_value(session, read.key())
            .map_err(PreCommitFailure::into_commit_rejection)?;
        if current.revision() != read.expected_revision() {
            return Err(DurableCommitRejection::Conflict {
                key: read.key().to_vec(),
                current_revision: current.revision(),
            });
        }
    }
    Ok(())
}

fn apply_state_mutations(
    session: &mut dyn SqlSession,
    reads: &[StateReadAssertion],
    mutations: &[StateMutationEntry],
) -> Result<(), DurableCommitRejection> {
    for mutation in mutations {
        let expected_revision = reads
            .iter()
            .find(|read| read.key() == mutation.key())
            .map(StateReadAssertion::expected_revision)
            .ok_or(DurableCommitRejection::InvalidPersistedState)?;
        let next = expected_revision
            .checked_next()
            .map_err(|_| DurableCommitRejection::StateRevisionOverflow)?;
        match mutation.mutation() {
            StateMutation::Put(value) => upsert_state(session, mutation.key(), next, Some(value)),
            StateMutation::Delete => upsert_state(session, mutation.key(), next, None),
            StateMutation::Assert => return Err(DurableCommitRejection::InvalidPersistedState),
        }
        .map_err(PreCommitFailure::into_commit_rejection)?;
    }
    Ok(())
}

/// Returns the maximum retained immutable object version for
/// `object_id`, or `None` if no version row exists.
fn max_object_version(
    session: &mut dyn SqlSession,
    object_id: ObjectId,
) -> Result<Option<DurableObjectVersion>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT MAX(object_version) FROM durable_object_versions WHERE object_id = ?1",
            &[SqlValue::Blob(object_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let Some(max_version) = row.opt_blob(0).map_err(SqlSessionError::from)? else {
        return Ok(None);
    };
    let max_version = decode_u64(max_version)
        .and_then(DurableObjectVersion::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    Ok(Some(max_version))
}

/// Reads and cross-validates one object head against its exact immutable
/// version history. A `Current` head is trusted only after the object
/// version it names is loaded through the fully validated
/// `load_object_version` path and confirmed to be the maximum retained
/// version, with its digest matching the head row's own digest columns.
fn load_object_head(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    object_id: ObjectId,
) -> Result<DurableObjectHead, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT status, head_revision, object_version, digest_algorithm, digest_bytes,
                    owner_projection, routing_projection
             FROM durable_object_heads WHERE object_id = ?1",
            &[SqlValue::Blob(object_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        let retained = session
            .exec(
                "SELECT EXISTS(SELECT 1 FROM durable_object_versions WHERE object_id = ?1)",
                &[SqlValue::Blob(object_id.as_bytes().to_vec())],
            )
            .map_err(PreCommitFailure::from)?;
        let retained_exists = decode_bool(
            retained
                .one()
                .map_err(PreCommitFailure::from)?
                .ok_or(PreCommitFailure::InvalidPersistedState)?
                .integer(0)
                .map_err(SqlSessionError::from)?,
        )?;
        if retained_exists {
            return Err(PreCommitFailure::InvalidPersistedState);
        }
        return Ok(DurableObjectHead::Absent);
    };
    let status = row.integer(0).map_err(SqlSessionError::from)?;
    let head_revision = decode_u64(row.blob(1).map_err(SqlSessionError::from)?)
        .and_then(ObjectHeadRevision::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let object_version_bytes = row.opt_blob(2).map_err(SqlSessionError::from)?;
    let digest_algorithm = row.opt_integer(3).map_err(SqlSessionError::from)?;
    let digest_bytes = row.opt_blob(4).map_err(SqlSessionError::from)?;
    let owner_projection = row
        .opt_blob(5)
        .map_err(SqlSessionError::from)?
        .map(<[u8]>::to_vec);
    let routing_projection = row
        .opt_blob(6)
        .map_err(SqlSessionError::from)?
        .map(<[u8]>::to_vec);
    if status == OBJECT_HEAD_STATUS_TOMBSTONED {
        if object_version_bytes.is_some()
            || digest_algorithm.is_some()
            || digest_bytes.is_some()
            || owner_projection.is_some()
            || routing_projection.is_some()
        {
            return Err(PreCommitFailure::InvalidPersistedState);
        }
        let last_object_version = max_object_version(session, object_id)?
            .ok_or(PreCommitFailure::InvalidPersistedState)?;
        let last_object_version_record =
            load_object_version(session, namespace, object_id, last_object_version)?
                .ok_or(PreCommitFailure::InvalidPersistedState)?;
        return Ok(DurableObjectHead::Tombstoned {
            head_revision,
            last_object_version: last_object_version_record.object_version(),
        });
    }
    if status != OBJECT_HEAD_STATUS_CURRENT {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let object_version = object_version_bytes
        .and_then(decode_u64)
        .and_then(DurableObjectVersion::new)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let digest = decode_optional_digest(digest_algorithm, digest_bytes)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let version_record = load_object_version(session, namespace, object_id, object_version)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    if version_record.digest() != digest {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let max_version =
        max_object_version(session, object_id)?.ok_or(PreCommitFailure::InvalidPersistedState)?;
    if max_version != object_version {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let owner_projection = DurableObjectOwnerProjection::from_canonical_bytes(owner_projection)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let routing_projection = DurableObjectRoutingProjection::new(routing_projection)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    Ok(DurableObjectHead::Current {
        head_revision,
        object_version,
        digest,
        owner_projection,
        routing_projection,
    })
}

fn load_object_version(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    object_id: ObjectId,
    object_version: DurableObjectVersion,
) -> Result<Option<DurableObjectVersionRecord>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT digest_algorithm, digest_bytes, schema_version, type_id, created_chain_id,
                    created_protocol_version, created_checkpoint, inline_canonical_bytes,
                    blob_digest_algorithm, blob_digest_bytes
             FROM durable_object_versions WHERE object_id = ?1 AND object_version = ?2",
            &[
                SqlValue::Blob(object_id.as_bytes().to_vec()),
                SqlValue::Blob(encode_u64(object_version.get()).to_vec()),
            ],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let digest_algorithm = row.integer(0).map_err(SqlSessionError::from)?;
    let digest_bytes = row.blob(1).map_err(SqlSessionError::from)?;
    let schema_version = row.integer(2).map_err(SqlSessionError::from)?;
    let type_id = row.integer(3).map_err(SqlSessionError::from)?;
    let created_chain_id = row.text(4).map_err(SqlSessionError::from)?;
    let created_protocol_version = row.integer(5).map_err(SqlSessionError::from)?;
    let created_checkpoint = row.blob(6).map_err(SqlSessionError::from)?;
    let inline_bytes = row
        .opt_blob(7)
        .map_err(SqlSessionError::from)?
        .map(<[u8]>::to_vec);
    let blob_algorithm = row.opt_integer(8).map_err(SqlSessionError::from)?;
    let blob_bytes = row.opt_blob(9).map_err(SqlSessionError::from)?;

    let digest = decode_required_digest(digest_algorithm, digest_bytes)?;
    let schema_version =
        u32::try_from(schema_version).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let type_id = u32::try_from(type_id).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if type_id != DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let created_chain_id =
        ChainId::new(created_chain_id).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if &created_chain_id != namespace.chain_id() {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let created_protocol_version = ProtocolVersion::new(
        u32::try_from(created_protocol_version)
            .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
    );
    let provenance = DurableObjectProvenance::new(created_chain_id, created_protocol_version);
    let created_checkpoint =
        decode_u64(created_checkpoint).ok_or(PreCommitFailure::InvalidPersistedState)?;
    let blob_digest = decode_optional_digest(blob_algorithm, blob_bytes)?;
    let record = match (inline_bytes, blob_digest) {
        (Some(inline_bytes), None) => DurableObjectVersionRecord::from_inline_canonical_bytes(
            inline_bytes,
            digest,
            provenance,
            created_checkpoint,
        )
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?,
        (None, Some(blob_digest)) => DurableObjectVersionRecord::from_blob_reference(
            object_id,
            object_version,
            digest,
            schema_version,
            provenance,
            created_checkpoint,
            blob_digest,
        ),
        (None, None) | (Some(_), Some(_)) => {
            return Err(PreCommitFailure::InvalidPersistedState);
        }
    };
    if record.object_id() != object_id
        || record.object_version() != object_version
        || record.schema_version() != schema_version
        || record.canonical_record_type_id() != type_id
    {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    Ok(Some(record))
}

fn load_receipt(
    session: &mut dyn SqlSession,
    request_id: DurableRequestId,
) -> Result<Option<DurableRequestReceipt>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT event_digest_algorithm, event_digest_bytes, canonical_bytes
             FROM durable_receipts WHERE request_id = ?1",
            &[SqlValue::Blob(request_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let algorithm = row.integer(0).map_err(SqlSessionError::from)?;
    let digest_bytes = row.blob(1).map_err(SqlSessionError::from)?;
    let canonical_bytes = row.blob(2).map_err(SqlSessionError::from)?.to_vec();
    let event_digest = decode_required_digest(algorithm, digest_bytes)?;
    let receipt = DurableRequestReceipt::new(request_id, event_digest, canonical_bytes)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    Ok(Some(receipt))
}

fn receipt_exists(
    session: &mut dyn SqlSession,
    request_id: DurableRequestId,
) -> Result<bool, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT EXISTS(SELECT 1 FROM durable_receipts WHERE request_id = ?1)",
            &[SqlValue::Blob(request_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let row = rows
        .one()
        .map_err(PreCommitFailure::from)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    decode_bool(row.integer(0).map_err(SqlSessionError::from)?)
}

fn validate_object_reads(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    reads: &[DurableObjectHeadRead],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current = load_object_head(session, namespace, read.object_id())
            .map_err(PreCommitFailure::into_commit_rejection)?;
        if &current != read.expected() {
            return Err(DurableCommitRejection::ObjectConflict {
                object_id: read.object_id(),
                current: DurableObjectHeadSummary::from(&current),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PreparedObjectMutation {
    object_id: ObjectId,
    next_head_revision: ObjectHeadRevision,
}

fn prepare_object_mutations(
    session: &mut dyn SqlSession,
    changes: &DurableObjectChanges,
) -> Result<Vec<PreparedObjectMutation>, DurableCommitRejection> {
    let mut prepared = Vec::with_capacity(changes.mutations().len());
    for mutation in changes.mutations() {
        let read_index = changes
            .reads()
            .binary_search_by_key(&mutation.object_id(), DurableObjectHeadRead::object_id)
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let expected = changes.reads()[read_index].expected();
        let next_head_revision = match expected.head_revision() {
            Some(revision) => revision
                .checked_next()
                .ok_or(DurableCommitRejection::InvalidPersistedState)?,
            None => ObjectHeadRevision::FIRST,
        };
        if let Some(version) = mutation.mutation().version() {
            let rows = session
                .exec(
                    "SELECT EXISTS(SELECT 1 FROM durable_object_versions
                     WHERE object_id = ?1 AND object_version = ?2)",
                    &[
                        SqlValue::Blob(mutation.object_id().as_bytes().to_vec()),
                        SqlValue::Blob(encode_u64(version.object_version().get()).to_vec()),
                    ],
                )
                .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
            let row = rows
                .one()
                .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?
                .ok_or(DurableCommitRejection::InvalidPersistedState)?;
            let existing = decode_bool(row.integer(0).map_err(|error| {
                PreCommitFailure::from(SqlSessionError::from(error)).into_commit_rejection()
            })?)
            .map_err(PreCommitFailure::into_commit_rejection)?;
            if existing {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
        }
        prepared.push(PreparedObjectMutation {
            object_id: mutation.object_id(),
            next_head_revision,
        });
    }
    Ok(prepared)
}

fn insert_object_version(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    version: &DurableObjectVersionRecord,
) -> Result<(), DurableCommitRejection> {
    if version.provenance().chain_id() != namespace.chain_id() {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    let (inline_bytes, blob_algorithm, blob_bytes): (Option<Vec<u8>>, SqlValue, SqlValue) =
        match version.payload() {
            DurableObjectPayload::Inline(inline) => (
                Some(inline.canonical_bytes().to_vec()),
                SqlValue::Null,
                SqlValue::Null,
            ),
            DurableObjectPayload::BlobReference(blob_digest) => (
                None,
                SqlValue::Integer(i64::from(blob_digest.algorithm().as_u16())),
                SqlValue::Blob(blob_digest.bytes().to_vec()),
            ),
        };
    let digest = version.digest();
    let result = session
        .exec(
            "INSERT INTO durable_object_versions (
                 object_id, object_version, digest_algorithm, digest_bytes, schema_version,
                 type_id, created_chain_id, created_protocol_version, created_checkpoint,
                 inline_canonical_bytes, blob_digest_algorithm, blob_digest_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                SqlValue::Blob(version.object_id().as_bytes().to_vec()),
                SqlValue::Blob(encode_u64(version.object_version().get()).to_vec()),
                SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
                SqlValue::Blob(digest.bytes().to_vec()),
                SqlValue::Integer(i64::from(version.schema_version())),
                SqlValue::Integer(i64::from(version.canonical_record_type_id())),
                SqlValue::Text(version.provenance().chain_id().as_str().to_owned()),
                SqlValue::Integer(i64::from(version.provenance().protocol_version().get())),
                SqlValue::Blob(encode_u64(version.created_checkpoint()).to_vec()),
                inline_bytes.into(),
                blob_algorithm,
                blob_bytes,
            ],
        )
        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
    if result.rows_affected() != 1 {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    Ok(())
}

fn apply_object_mutations(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    changes: &DurableObjectChanges,
    prepared: &[PreparedObjectMutation],
) -> Result<(), DurableCommitRejection> {
    if changes.mutations().len() != prepared.len() {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    for (mutation, prepared) in changes.mutations().iter().zip(prepared) {
        if mutation.object_id() != prepared.object_id {
            return Err(DurableCommitRejection::InvalidPersistedState);
        }
        match mutation.mutation() {
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            }
            | DurableObjectMutation::Update {
                version,
                owner_projection,
                routing_projection,
            } => {
                insert_object_version(session, namespace, version)?;
                let digest = version.digest();
                let result = session
                    .exec(
                        "INSERT INTO durable_object_heads (
                             object_id, status, head_revision, object_version,
                             digest_algorithm, digest_bytes, owner_projection, routing_projection
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(object_id) DO UPDATE SET
                             status = excluded.status,
                             head_revision = excluded.head_revision,
                             object_version = excluded.object_version,
                             digest_algorithm = excluded.digest_algorithm,
                             digest_bytes = excluded.digest_bytes,
                             owner_projection = excluded.owner_projection,
                             routing_projection = excluded.routing_projection",
                        &[
                            SqlValue::Blob(mutation.object_id().as_bytes().to_vec()),
                            SqlValue::Integer(OBJECT_HEAD_STATUS_CURRENT),
                            SqlValue::Blob(encode_u64(prepared.next_head_revision.get()).to_vec()),
                            SqlValue::Blob(encode_u64(version.object_version().get()).to_vec()),
                            SqlValue::Integer(i64::from(digest.algorithm().as_u16())),
                            SqlValue::Blob(digest.bytes().to_vec()),
                            owner_projection.bytes().map(<[u8]>::to_vec).into(),
                            routing_projection.bytes().map(<[u8]>::to_vec).into(),
                        ],
                    )
                    .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                if result.rows_affected() != 1 {
                    return Err(DurableCommitRejection::InvalidPersistedState);
                }
            }
            DurableObjectMutation::Delete => {
                let result = session
                    .exec(
                        "UPDATE durable_object_heads SET
                             status = ?1, head_revision = ?2, object_version = NULL,
                             digest_algorithm = NULL, digest_bytes = NULL,
                             owner_projection = NULL, routing_projection = NULL
                         WHERE object_id = ?3",
                        &[
                            SqlValue::Integer(OBJECT_HEAD_STATUS_TOMBSTONED),
                            SqlValue::Blob(encode_u64(prepared.next_head_revision.get()).to_vec()),
                            SqlValue::Blob(mutation.object_id().as_bytes().to_vec()),
                        ],
                    )
                    .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                if result.rows_affected() != 1 {
                    return Err(DurableCommitRejection::InvalidPersistedState);
                }
            }
        }
    }
    Ok(())
}

fn insert_structured_invocation(
    session: &mut dyn SqlSession,
    invocation: &DurableInvocationTransaction,
) -> Result<(), DurableCommitRejection> {
    let receipt = invocation.receipt();
    let event_digest = receipt.event_digest();
    let result = session
        .exec(
            "INSERT OR IGNORE INTO durable_receipts (
                 request_id, event_digest_algorithm, event_digest_bytes, canonical_bytes
             ) VALUES (?1, ?2, ?3, ?4)",
            &[
                SqlValue::Blob(receipt.request_id().as_bytes().to_vec()),
                SqlValue::Integer(i64::from(event_digest.algorithm().as_u16())),
                SqlValue::Blob(event_digest.bytes().to_vec()),
                SqlValue::Blob(receipt.canonical_bytes().to_vec()),
            ],
        )
        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
    if result.rows_affected() != 1 {
        return Err(DurableCommitRejection::RequestAlreadyCommitted);
    }

    let Some(outbox) = invocation.outbox() else {
        return Ok(());
    };
    let message_count = i64::try_from(outbox.messages().len())
        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
    for (index, message) in outbox.messages().iter().enumerate() {
        let message_index =
            i64::try_from(index).map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let payload_digest = message.payload_digest();
        session
            .exec(
                "INSERT INTO durable_outbox_messages (
                     request_id, message_index, payload_digest_algorithm,
                     payload_digest_bytes, canonical_payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Blob(outbox.request_id().as_bytes().to_vec()),
                    SqlValue::Integer(message_index),
                    SqlValue::Integer(i64::from(payload_digest.algorithm().as_u16())),
                    SqlValue::Blob(payload_digest.bytes().to_vec()),
                    SqlValue::Blob(message.canonical_payload().to_vec()),
                ],
            )
            .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
    }
    let completed = i64::from(outbox.messages().is_empty());
    session
        .exec(
            "INSERT INTO durable_outbox_delivery (
                 request_id, message_count, next_message_index, completed,
                 available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis,
                 attempt_count
             ) VALUES (?1, ?2, 0, ?3, ?4, NULL, NULL, ?4)",
            &[
                SqlValue::Blob(outbox.request_id().as_bytes().to_vec()),
                SqlValue::Integer(message_count),
                SqlValue::Integer(completed),
                SqlValue::Blob(encode_u64(0).to_vec()),
            ],
        )
        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxAttempt {
    request_id: OutboxRequestId,
    message_index: u32,
    lease_expires_at_unix_millis: u64,
    status: OutboxAttemptStatus,
}

fn load_outbox_attempt(
    session: &mut dyn SqlSession,
    lease_id: DurableOutboxLeaseId,
) -> Result<Option<PersistedOutboxAttempt>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT request_id, message_index, lease_expires_at_unix_millis, status
             FROM durable_outbox_attempts WHERE lease_id = ?1",
            &[SqlValue::Blob(lease_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let request_id: [u8; 32] = row
        .blob(0)
        .map_err(SqlSessionError::from)?
        .try_into()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let request_id =
        OutboxRequestId::new(request_id).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let message_index = u32::try_from(row.integer(1).map_err(SqlSessionError::from)?)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let lease_expires_at_unix_millis = decode_u64(row.blob(2).map_err(SqlSessionError::from)?)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let status = OutboxAttemptStatus::decode(row.integer(3).map_err(SqlSessionError::from)?)?;
    Ok(Some(PersistedOutboxAttempt {
        request_id,
        message_index,
        lease_expires_at_unix_millis,
        status,
    }))
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxDelivery {
    request_id: OutboxRequestId,
    next_message_index: u32,
    message_count: u32,
    completed: bool,
    available_at_unix_millis: u64,
    active_lease_id: Option<DurableOutboxLeaseId>,
    lease_expires_at_unix_millis: Option<u64>,
    attempt_count: u64,
}

fn load_outbox_delivery(
    session: &mut dyn SqlSession,
    request_id: OutboxRequestId,
) -> Result<Option<PersistedOutboxDelivery>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT next_message_index, message_count, completed, available_at_unix_millis,
                    active_lease_id, lease_expires_at_unix_millis, attempt_count
             FROM durable_outbox_delivery WHERE request_id = ?1",
            &[SqlValue::Blob(request_id.as_bytes().to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let next_message_index = u32::try_from(row.integer(0).map_err(SqlSessionError::from)?)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let message_count = u32::try_from(row.integer(1).map_err(SqlSessionError::from)?)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let completed = decode_bool(row.integer(2).map_err(SqlSessionError::from)?)?;
    let available_at_unix_millis = decode_u64(row.blob(3).map_err(SqlSessionError::from)?)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let lease_id_bytes = row.opt_blob(4).map_err(SqlSessionError::from)?;
    let lease_expires_bytes = row.opt_blob(5).map_err(SqlSessionError::from)?;
    let active_lease_id = lease_id_bytes
        .map(|bytes| -> Result<DurableOutboxLeaseId, PreCommitFailure> {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
            DurableOutboxLeaseId::new(bytes).map_err(|_| PreCommitFailure::InvalidPersistedState)
        })
        .transpose()?;
    let lease_expires_at_unix_millis = lease_expires_bytes
        .map(|bytes| decode_u64(bytes).ok_or(PreCommitFailure::InvalidPersistedState))
        .transpose()?;
    if active_lease_id.is_some() != lease_expires_at_unix_millis.is_some() {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let attempt_count = decode_u64(row.blob(6).map_err(SqlSessionError::from)?)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    Ok(Some(PersistedOutboxDelivery {
        request_id,
        next_message_index,
        message_count,
        completed,
        available_at_unix_millis,
        active_lease_id,
        lease_expires_at_unix_millis,
        attempt_count,
    }))
}

fn load_due_outbox_delivery(
    session: &mut dyn SqlSession,
    now_unix_millis: u64,
) -> Result<Option<PersistedOutboxDelivery>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT request_id FROM durable_outbox_delivery
             WHERE completed = 0 AND available_at_unix_millis <= ?1
             ORDER BY available_at_unix_millis, request_id
             LIMIT 1",
            &[SqlValue::Blob(encode_u64(now_unix_millis).to_vec())],
        )
        .map_err(PreCommitFailure::from)?;
    let Some(row) = rows.one().map_err(PreCommitFailure::from)? else {
        return Ok(None);
    };
    let request_id: [u8; 32] = row
        .blob(0)
        .map_err(SqlSessionError::from)?
        .try_into()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let request_id =
        OutboxRequestId::new(request_id).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    load_outbox_delivery(session, request_id)
}

fn load_outbox_payload(
    session: &mut dyn SqlSession,
    request_id: OutboxRequestId,
    message_index: u32,
) -> Result<Vec<u8>, PreCommitFailure> {
    let rows = session
        .exec(
            "SELECT canonical_payload FROM durable_outbox_messages
             WHERE request_id = ?1 AND message_index = ?2",
            &[
                SqlValue::Blob(request_id.as_bytes().to_vec()),
                SqlValue::Integer(i64::from(message_index)),
            ],
        )
        .map_err(PreCommitFailure::from)?;
    let row = rows
        .one()
        .map_err(PreCommitFailure::from)?
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    Ok(row.blob(0).map_err(SqlSessionError::from)?.to_vec())
}

fn reconcile_outbox_claim(
    session: &mut dyn SqlSession,
    lease_id: DurableOutboxLeaseId,
    attempt: PersistedOutboxAttempt,
    now_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if attempt.status != OutboxAttemptStatus::Claimed
        || attempt.lease_expires_at_unix_millis <= now_unix_millis
    {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    let delivery = load_outbox_delivery(session, attempt.request_id)
        .map_err(PreCommitFailure::into_claim_rejection)?
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    if delivery.completed
        || delivery.next_message_index != attempt.message_index
        || delivery.active_lease_id != Some(lease_id)
        || delivery.lease_expires_at_unix_millis != Some(attempt.lease_expires_at_unix_millis)
        || delivery.available_at_unix_millis != attempt.lease_expires_at_unix_millis
    {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    let payload = load_outbox_payload(session, attempt.request_id, attempt.message_index)
        .map_err(PreCommitFailure::into_claim_rejection)?;
    DurableOutboxClaim::from_parts(
        attempt.request_id,
        attempt.message_index,
        lease_id,
        attempt.lease_expires_at_unix_millis,
        payload,
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)
}

fn install_outbox_claim(
    session: &mut dyn SqlSession,
    delivery: PersistedOutboxDelivery,
    now_unix_millis: u64,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if delivery.completed || delivery.available_at_unix_millis > now_unix_millis {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    if delivery.next_message_index >= delivery.message_count {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    match (
        delivery.active_lease_id,
        delivery.lease_expires_at_unix_millis,
    ) {
        (Some(expired_lease_id), Some(expired_at)) if expired_at <= now_unix_millis => {
            if delivery.available_at_unix_millis != expired_at {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
            let expired_attempt = load_outbox_attempt(session, expired_lease_id)
                .map_err(PreCommitFailure::into_claim_rejection)?
                .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
            if expired_attempt.request_id != delivery.request_id
                || expired_attempt.message_index != delivery.next_message_index
                || expired_attempt.lease_expires_at_unix_millis != expired_at
                || expired_attempt.status != OutboxAttemptStatus::Claimed
            {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
            let result = session
                .exec(
                    "UPDATE durable_outbox_attempts SET status = ?1 WHERE lease_id = ?2 AND status = ?3",
                    &[
                        SqlValue::Integer(OutboxAttemptStatus::Expired.encode()),
                        SqlValue::Blob(expired_lease_id.as_bytes().to_vec()),
                        SqlValue::Integer(OutboxAttemptStatus::Claimed.encode()),
                    ],
                )
                .map_err(|error| PreCommitFailure::from(error).into_claim_rejection())?;
            if result.rows_affected() != 1 {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
        }
        (None, None) => {}
        (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
            return Err(DurableOutboxClaimRejection::InvalidPersistedState);
        }
    }

    let attempt_count = delivery
        .attempt_count
        .checked_add(1)
        .ok_or(DurableOutboxClaimRejection::ArithmeticOverflow)?;
    let payload = load_outbox_payload(session, delivery.request_id, delivery.next_message_index)
        .map_err(PreCommitFailure::into_claim_rejection)?;
    let claim = DurableOutboxClaim::from_parts(
        delivery.request_id,
        delivery.next_message_index,
        lease_id,
        lease_expires_at_unix_millis,
        payload,
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)?;
    let inserted = session
        .exec(
            "INSERT OR IGNORE INTO durable_outbox_attempts (
                 lease_id, request_id, message_index, lease_expires_at_unix_millis, status
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                SqlValue::Blob(lease_id.as_bytes().to_vec()),
                SqlValue::Blob(delivery.request_id.as_bytes().to_vec()),
                SqlValue::Integer(i64::from(delivery.next_message_index)),
                SqlValue::Blob(encode_u64(lease_expires_at_unix_millis).to_vec()),
                SqlValue::Integer(OutboxAttemptStatus::Claimed.encode()),
            ],
        )
        .map_err(|error| PreCommitFailure::from(error).into_claim_rejection())?;
    if inserted.rows_affected() != 1 {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    let updated = session
        .exec(
            "UPDATE durable_outbox_delivery SET
                 active_lease_id = ?1, lease_expires_at_unix_millis = ?2,
                 available_at_unix_millis = ?2, attempt_count = ?3
             WHERE request_id = ?4",
            &[
                SqlValue::Blob(lease_id.as_bytes().to_vec()),
                SqlValue::Blob(encode_u64(lease_expires_at_unix_millis).to_vec()),
                SqlValue::Blob(encode_u64(attempt_count).to_vec()),
                SqlValue::Blob(delivery.request_id.as_bytes().to_vec()),
            ],
        )
        .map_err(|error| PreCommitFailure::from(error).into_claim_rejection())?;
    if updated.rows_affected() != 1 {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    Ok(claim)
}

/// Runs one read-only snapshot: `load` always ends in a rollback, since a
/// read never writes. A genuine backend failure (never a business
/// rejection, which `load` folds into its own `Result`) is reported as
/// `PreCommitFailure::Unavailable`.
fn run_read<B: SqlBackend, T>(
    backend: &B,
    budget: TransactionBudget,
    load: impl FnOnce(&mut dyn SqlSession, u64) -> Result<T, PreCommitFailure>,
) -> Result<T, PreCommitFailure> {
    let outcome = backend.transaction(budget, |session, now| {
        Ok(TransactionDecision::Rollback(load(session, now)))
    });
    match outcome {
        Ok(result) => result,
        Err(
            SqlBackendError::SessionFailed(_)
            | SqlBackendError::Unavailable
            | SqlBackendError::CommitIndeterminate,
        ) => Err(PreCommitFailure::Unavailable),
    }
}

/// Runs one write transaction. `body` returns the final domain outcome
/// wrapped in `Commit` to persist it or `Rollback` to discard every SQL
/// change while still returning a definite, already fully explained
/// value (for example a revision conflict). `on_backend_error` maps a
/// genuine backend failure, including a commit whose effect is unknown,
/// onto the same outcome type.
fn run_write<B: SqlBackend, T>(
    backend: &B,
    budget: TransactionBudget,
    body: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    on_backend_error: impl FnOnce(SqlBackendError) -> T,
) -> T {
    match backend.transaction(budget, body) {
        Ok(value) => value,
        Err(error) => on_backend_error(error),
    }
}

/// A backend-neutral structured durable store: the exact statements and
/// rejection rules in this module, driven through any `SqlBackend`.
pub struct SqlDurableEngine<B> {
    backend: B,
    namespace: SqlDurableNamespace,
}

impl<B: SqlBackend> SqlDurableEngine<B> {
    /// Wires one host transaction provider to one trusted namespace.
    ///
    /// The caller must have already bootstrapped or verified `namespace`
    /// against the database `backend` opens, typically with
    /// `schema::bootstrap_namespace`/`schema::verify_namespace` inside its
    /// own native-only open sequence, before constructing this engine.
    #[must_use]
    pub const fn new(backend: B, namespace: SqlDurableNamespace) -> Self {
        Self { backend, namespace }
    }

    /// Returns the exact namespace this engine is bound to.
    #[must_use]
    pub const fn namespace(&self) -> &SqlDurableNamespace {
        &self.namespace
    }

    /// Returns the host transaction provider this engine drives.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    fn domain_is_bound(&self, domain: AtomicityDomainId) -> bool {
        domain == self.namespace.domain()
    }

    fn budget(context: &DurableOperationContext) -> TransactionBudget {
        TransactionBudget::Deadline(context.deadline().unix_millis())
    }

    fn unavailable_commit_outcome(error: SqlBackendError) -> DurableCommitOutcome {
        match error {
            SqlBackendError::CommitIndeterminate => {
                DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
            SqlBackendError::Unavailable | SqlBackendError::SessionFailed(_) => {
                DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
            }
        }
    }

    fn unavailable_claim_outcome(error: SqlBackendError) -> DurableOutboxClaimOutcome {
        match error {
            SqlBackendError::CommitIndeterminate => {
                DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
            SqlBackendError::Unavailable | SqlBackendError::SessionFailed(_) => {
                DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::UnavailableBeforeCommit,
                )
            }
        }
    }

    fn unavailable_acknowledgement_outcome(
        error: SqlBackendError,
    ) -> DurableOutboxAcknowledgementOutcome {
        match error {
            SqlBackendError::CommitIndeterminate => {
                DurableOutboxAcknowledgementOutcome::Indeterminate(
                    IndeterminateCommitReason::ConnectionLost,
                )
            }
            SqlBackendError::Unavailable | SqlBackendError::SessionFailed(_) => {
                DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
                )
            }
        }
    }
}

impl<B: SqlBackend> DurableDomainStateStore for SqlDurableEngine<B> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL)
            .map_err(DurableReadError::InvalidRequest)?;
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        let key = key.to_vec();
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            load_state_value(session, &key)
        })
        .map_err(PreCommitFailure::into_read_error)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(transaction.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    validate_authority(&metadata, context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    validate_state_reads(session, transaction.reads())?;
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    apply_state_mutations(session, transaction.reads(), transaction.mutations())?;
                    check_deadline_before_commit(session, context)
                        .map_err(PreCommitFailure::into_commit_rejection)
                })();
                Ok(match decision {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }
}

impl<B: SqlBackend> StructuredDurableDomainStateStore for SqlDurableEngine<B> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            load_object_head(session, &self.namespace, object_id)
        })
        .map_err(PreCommitFailure::into_read_error)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            load_object_version(session, &self.namespace, object_id, object_version)
        })
        .map_err(PreCommitFailure::into_read_error)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            load_receipt(session, request_id)
        })
        .map_err(PreCommitFailure::into_read_error)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        invocation: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(invocation.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let decision = (|| -> Result<(), DurableCommitRejection> {
                    check_deadline(context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    let metadata = schema::verify_namespace(session, &self.namespace)
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    validate_authority(&metadata, context, now)
                        .map_err(PreCommitFailure::into_commit_rejection)?;
                    let receipt = invocation.receipt();
                    if receipt_exists(session, receipt.request_id())
                        .map_err(PreCommitFailure::into_commit_rejection)?
                    {
                        return Err(DurableCommitRejection::RequestAlreadyCommitted);
                    }
                    if let Some(state) = invocation.state() {
                        validate_state_reads(session, state.reads())?;
                    }
                    validate_object_reads(
                        session,
                        &self.namespace,
                        invocation.object_changes().reads(),
                    )?;
                    let prepared = prepare_object_mutations(session, invocation.object_changes())?;
                    schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                        .map_err(|error| PreCommitFailure::from(error).into_commit_rejection())?;
                    if let Some(state) = invocation.state() {
                        apply_state_mutations(session, state.reads(), state.mutations())?;
                    }
                    apply_object_mutations(
                        session,
                        &self.namespace,
                        invocation.object_changes(),
                        &prepared,
                    )?;
                    insert_structured_invocation(session, &invocation)?;
                    check_deadline_before_commit(session, context)
                        .map_err(PreCommitFailure::into_commit_rejection)
                })();
                Ok(match decision {
                    Ok(()) => TransactionDecision::Commit(DurableCommitOutcome::Committed),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableCommitOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_commit_outcome,
        )
    }
}

impl<B: SqlBackend> DurableStateKeyScanner for SqlDurableEngine<B> {
    fn scan_durable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &StateKeyScan,
    ) -> Result<StateKeyPage, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        run_read(&self.backend, Self::budget(context), |session, now| {
            check_deadline(context, now)?;
            let metadata = schema::verify_namespace(session, &self.namespace)?;
            validate_authority(&metadata, context, now)?;
            load_state_key_page(session, scan)
        })
        .map_err(PreCommitFailure::into_read_error)
    }
}

impl<B: SqlBackend> IndexedOutboxRepository for SqlDurableEngine<B> {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let outcome =
                    (|| -> Result<DurableOutboxClaimOutcome, DurableOutboxClaimRejection> {
                        check_deadline(context, now)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        let metadata = schema::verify_namespace(session, &self.namespace).map_err(
                            |error| PreCommitFailure::from(error).into_claim_rejection(),
                        )?;
                        validate_authority(&metadata, context, now)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        let existing = load_outbox_attempt(session, request.lease_id())
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        if let Some(attempt) = existing {
                            if attempt.request_id != request.request_id() {
                                return Err(DurableOutboxClaimRejection::LeaseIdReuse);
                            }
                            let claim = reconcile_outbox_claim(
                                session,
                                request.lease_id(),
                                attempt,
                                request.now_unix_millis(),
                            )?;
                            return Ok(DurableOutboxClaimOutcome::Claimed(claim));
                        }
                        let Some(delivery) = load_outbox_delivery(session, request.request_id())
                            .map_err(PreCommitFailure::into_claim_rejection)?
                        else {
                            return Ok(DurableOutboxClaimOutcome::NoDueWork);
                        };
                        if delivery.completed
                            || delivery.available_at_unix_millis > request.now_unix_millis()
                            || delivery
                                .lease_expires_at_unix_millis
                                .is_some_and(|expires_at| expires_at > request.now_unix_millis())
                        {
                            return Ok(DurableOutboxClaimOutcome::NoDueWork);
                        }
                        schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                            .map_err(|error| {
                                PreCommitFailure::from(error).into_claim_rejection()
                            })?;
                        let claim = install_outbox_claim(
                            session,
                            delivery,
                            request.now_unix_millis(),
                            request.lease_id(),
                            request.lease_expires_at_unix_millis(),
                        )?;
                        check_deadline_before_commit(session, context)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        Ok(DurableOutboxClaimOutcome::Claimed(claim))
                    })();
                Ok(match outcome {
                    Ok(outcome @ DurableOutboxClaimOutcome::Claimed(_)) => {
                        TransactionDecision::Commit(outcome)
                    }
                    Ok(outcome) => TransactionDecision::Rollback(outcome),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableOutboxClaimOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_claim_outcome,
        )
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                let outcome =
                    (|| -> Result<DurableOutboxClaimOutcome, DurableOutboxClaimRejection> {
                        check_deadline(context, now)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        let metadata = schema::verify_namespace(session, &self.namespace).map_err(
                            |error| PreCommitFailure::from(error).into_claim_rejection(),
                        )?;
                        validate_authority(&metadata, context, now)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        let existing = load_outbox_attempt(session, request.lease_id())
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        if let Some(attempt) = existing {
                            let claim = reconcile_outbox_claim(
                                session,
                                request.lease_id(),
                                attempt,
                                request.now_unix_millis(),
                            )?;
                            return Ok(DurableOutboxClaimOutcome::Claimed(claim));
                        }
                        let Some(delivery) =
                            load_due_outbox_delivery(session, request.now_unix_millis())
                                .map_err(PreCommitFailure::into_claim_rejection)?
                        else {
                            return Ok(DurableOutboxClaimOutcome::NoDueWork);
                        };
                        schema::advance_mutation_sequence(session, metadata.mutation_sequence())
                            .map_err(|error| {
                                PreCommitFailure::from(error).into_claim_rejection()
                            })?;
                        let claim = install_outbox_claim(
                            session,
                            delivery,
                            request.now_unix_millis(),
                            request.lease_id(),
                            request.lease_expires_at_unix_millis(),
                        )?;
                        check_deadline_before_commit(session, context)
                            .map_err(PreCommitFailure::into_claim_rejection)?;
                        Ok(DurableOutboxClaimOutcome::Claimed(claim))
                    })();
                Ok(match outcome {
                    Ok(outcome @ DurableOutboxClaimOutcome::Claimed(_)) => {
                        TransactionDecision::Commit(outcome)
                    }
                    Ok(outcome) => TransactionDecision::Rollback(outcome),
                    Err(reason) => {
                        TransactionDecision::Rollback(DurableOutboxClaimOutcome::Rejected(reason))
                    }
                })
            },
            Self::unavailable_claim_outcome,
        )
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        if !self.domain_is_bound(acknowledgement.domain()) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        run_write(
            &self.backend,
            Self::budget(context),
            |session, now| {
                acknowledge_outbox_step(session, &self.namespace, context, now, &acknowledgement)
            },
            Self::unavailable_acknowledgement_outcome,
        )
    }
}

/// The full body of one `acknowledge_outbox` attempt, isolated from the
/// trait method so its many early returns read as ordinary control flow
/// rather than a deeply nested closure.
fn acknowledge_outbox_step(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    context: &DurableOperationContext,
    now: u64,
    acknowledgement: &DurableOutboxAcknowledgement,
) -> Result<TransactionDecision<DurableOutboxAcknowledgementOutcome>, SqlSessionError> {
    use DurableOutboxAcknowledgementOutcome as Outcome;
    use DurableOutboxAcknowledgementRejection as Rejection;
    let reject = |reason: Rejection| Ok(TransactionDecision::Rollback(Outcome::Rejected(reason)));

    if let Err(failure) = check_deadline(context, now) {
        return reject(failure.into_acknowledgement_rejection());
    }
    let metadata = match schema::verify_namespace(session, namespace) {
        Ok(metadata) => metadata,
        Err(error) => {
            return reject(PreCommitFailure::from(error).into_acknowledgement_rejection());
        }
    };
    if let Err(failure) = validate_authority(&metadata, context, now) {
        return reject(failure.into_acknowledgement_rejection());
    }
    let attempt = match load_outbox_attempt(session, acknowledgement.lease_id()) {
        Ok(Some(attempt)) => attempt,
        Ok(None) => return reject(Rejection::LeaseMismatch),
        Err(failure) => return reject(failure.into_acknowledgement_rejection()),
    };
    if attempt.request_id != acknowledgement.request_id()
        || attempt.message_index != acknowledgement.message_index()
    {
        return reject(Rejection::LeaseMismatch);
    }
    let delivery = match load_outbox_delivery(session, acknowledgement.request_id()) {
        Ok(Some(delivery)) => delivery,
        Ok(None) => return reject(Rejection::InvalidPersistedState),
        Err(failure) => return reject(failure.into_acknowledgement_rejection()),
    };
    if attempt.status == OutboxAttemptStatus::Acknowledged {
        if attempt.message_index >= delivery.message_count
            || delivery.next_message_index <= attempt.message_index
            || delivery.next_message_index > delivery.message_count
        {
            return reject(Rejection::InvalidPersistedState);
        }
        return Ok(TransactionDecision::Rollback(Outcome::Acknowledged));
    }
    if attempt.status != OutboxAttemptStatus::Claimed {
        return reject(Rejection::LeaseMismatch);
    }
    if delivery.next_message_index != acknowledgement.message_index() {
        return reject(Rejection::IndexMismatch);
    }
    if delivery.completed
        || delivery.active_lease_id != Some(acknowledgement.lease_id())
        || delivery.lease_expires_at_unix_millis != Some(attempt.lease_expires_at_unix_millis)
        || delivery.available_at_unix_millis != attempt.lease_expires_at_unix_millis
    {
        return reject(Rejection::LeaseMismatch);
    }
    let Some(next_message_index) = delivery.next_message_index.checked_add(1) else {
        return reject(Rejection::ArithmeticOverflow);
    };
    if next_message_index > delivery.message_count {
        return reject(Rejection::InvalidPersistedState);
    }
    if let Err(error) = schema::advance_mutation_sequence(session, metadata.mutation_sequence()) {
        return reject(PreCommitFailure::from(error).into_acknowledgement_rejection());
    }
    let attempt_updated = session.exec(
        "UPDATE durable_outbox_attempts SET status = ?1 WHERE lease_id = ?2 AND status = ?3",
        &[
            SqlValue::Integer(OutboxAttemptStatus::Acknowledged.encode()),
            SqlValue::Blob(acknowledgement.lease_id().as_bytes().to_vec()),
            SqlValue::Integer(OutboxAttemptStatus::Claimed.encode()),
        ],
    )?;
    if attempt_updated.rows_affected() != 1 {
        return reject(Rejection::InvalidPersistedState);
    }
    let completed = i64::from(next_message_index == delivery.message_count);
    let delivery_updated = session.exec(
        "UPDATE durable_outbox_delivery SET
             next_message_index = ?1, completed = ?2, available_at_unix_millis = ?3,
             active_lease_id = NULL, lease_expires_at_unix_millis = NULL
         WHERE request_id = ?4",
        &[
            SqlValue::Integer(i64::from(next_message_index)),
            SqlValue::Integer(completed),
            SqlValue::Blob(encode_u64(0).to_vec()),
            SqlValue::Blob(acknowledgement.request_id().as_bytes().to_vec()),
        ],
    )?;
    if delivery_updated.rows_affected() != 1 {
        return reject(Rejection::InvalidPersistedState);
    }
    if let Err(failure) = check_deadline_before_commit(session, context) {
        return reject(failure.into_acknowledgement_rejection());
    }
    Ok(TransactionDecision::Commit(Outcome::Acknowledged))
}
