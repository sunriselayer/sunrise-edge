//! Bounded storage enumeration and range reads for portable reconstruction.
//!
//! Pages contain keys, never full values. A descriptor and each payload chunk
//! are separate fenced reads. Mutable payload reads compare the entire expected
//! descriptor within the same read snapshot; changed rows return `Changed`,
//! never bytes stitched from different revisions. These observations are NOT
//! authenticated cuts: the protocol must freeze the source, classify every row,
//! bind descriptors/chunks to the cut, and verify content and completeness.

use crate::{BlobStore, MemoryBlobStore};
use crate::{
    DurableObjectHead, DurableObjectPayload, DurableObjectProvenance, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    MAX_DURABLE_INLINE_OBJECT_BYTES, MAX_DURABLE_RECEIPT_BYTES, MAX_STATE_VALUE_BYTES,
    MemoryDurableStateStore, MemoryDurableStoreData, ObjectId, RuntimeError, StateRevision,
    StructuredDurableDomainStateStore, read_memory_object_head,
    validate_memory_durable_read_authority, validate_memory_durable_read_domain,
    validate_state_key,
};
use protocol_types::{AtomicityDomainId, Digest32};
use std::num::NonZeroUsize;
use std::ops::{Bound, Range};

/// Maximum keys fetched in a page. Even 128 maximum-length state keys fit
/// below one MiB; a backend may fetch one additional key for lookahead.
pub const MAX_PORTABLE_PAGE_KEYS: usize = 128;
/// Hard payload-chunk bound, including the first chunk of a large legal row.
pub const MAX_PORTABLE_CHUNK_BYTES: usize = 1024 * 1024;
/// Conservative bound for one body-free descriptor, not a wire-frame size.
pub const MAX_PORTABLE_DESCRIPTOR_BYTES: usize = 16 * 1024;
/// Matches existing execution/publication and PostgreSQL namespace boundaries.
/// `ChainId` itself does not enforce a byte-length bound.
pub const MAX_PORTABLE_CHAIN_ID_BYTES: usize = 128;

/// Closed structured collections; the core classifier decides which state
/// keys are protocol facts and which are replica-local metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurableCollection {
    State,
    Receipts,
    ObjectHeads,
    ObjectVersions,
}

/// Exact natural primary key, with unsigned numeric object-version ordering.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DurableRecordKey {
    State(Vec<u8>),
    Receipt(DurableRequestId),
    ObjectHead(ObjectId),
    ObjectVersion(ObjectId, DurableObjectVersion),
}

impl DurableRecordKey {
    #[must_use]
    pub const fn collection(&self) -> DurableCollection {
        match self {
            Self::State(_) => DurableCollection::State,
            Self::Receipt(_) => DurableCollection::Receipts,
            Self::ObjectHead(_) => DurableCollection::ObjectHeads,
            Self::ObjectVersion(_, _) => DurableCollection::ObjectVersions,
        }
    }

    /// Must run before backend I/O, including callers constructing enum values.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        match self {
            Self::State(key) => validate_state_key(key),
            Self::Receipt(_) | Self::ObjectHead(_) | Self::ObjectVersion(_, _) => Ok(()),
        }
    }

    fn byte_bound(&self) -> usize {
        match self {
            Self::State(key) => key.len() + 8,
            Self::Receipt(_) | Self::ObjectHead(_) => 40,
            Self::ObjectVersion(_, _) => 48,
        }
    }
}

/// Forward-only keyset scan of exactly one collection. This is not a
/// multi-page snapshot: freeze and completeness are protocol responsibilities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRecordScan {
    collection: DurableCollection,
    after: Option<DurableRecordKey>,
    limit: NonZeroUsize,
}

impl DurableRecordScan {
    pub fn new(
        collection: DurableCollection,
        after: Option<DurableRecordKey>,
        limit: NonZeroUsize,
    ) -> Result<Self, RuntimeError> {
        if limit.get() > MAX_PORTABLE_PAGE_KEYS {
            return Err(RuntimeError::StateScanLimitTooLarge {
                requested: limit.get(),
                maximum: MAX_PORTABLE_PAGE_KEYS,
            });
        }
        if let Some(key) = &after {
            key.validate()?;
            if key.collection() != collection {
                return Err(RuntimeError::InvalidStateScanPage);
            }
        }
        Ok(Self {
            collection,
            after,
            limit,
        })
    }

    #[must_use]
    pub const fn collection(&self) -> DurableCollection {
        self.collection
    }
    #[must_use]
    pub const fn after(&self) -> Option<&DurableRecordKey> {
        self.after.as_ref()
    }
    #[must_use]
    pub const fn limit(&self) -> NonZeroUsize {
        self.limit
    }
}

/// Strictly ordered keys plus an exclusive last-exposed-key continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRecordPage {
    keys: Vec<DurableRecordKey>,
    continuation: Option<DurableRecordKey>,
}

impl DurableRecordPage {
    /// Backends fetch at most limit+1 indexed keys, with no payload columns.
    pub fn from_ordered_candidates(
        scan: &DurableRecordScan,
        mut keys: Vec<DurableRecordKey>,
    ) -> Result<Self, RuntimeError> {
        if keys.len() > scan.limit.get() + 1 {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        let mut total: usize = 0;
        let mut previous: Option<&DurableRecordKey> = scan.after();
        for key in &keys {
            key.validate()?;
            if key.collection() != scan.collection
                || previous.is_some_and(|previous| previous >= key)
            {
                return Err(RuntimeError::InvalidStateScanPage);
            }
            total = total
                .checked_add(key.byte_bound())
                .ok_or(RuntimeError::InvalidStateScanPage)?;
            previous = Some(key);
        }
        // Lookahead work is bounded too, not just the exposed page.
        if total > MAX_PORTABLE_CHUNK_BYTES {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        let more: bool = keys.len() > scan.limit.get();
        if more {
            keys.pop();
        }
        let continuation: Option<DurableRecordKey> = if more { keys.last().cloned() } else { None };
        Ok(Self { keys, continuation })
    }

    #[must_use]
    pub fn keys(&self) -> &[DurableRecordKey] {
        &self.keys
    }
    #[must_use]
    pub const fn continuation(&self) -> Option<&DurableRecordKey> {
        self.continuation.as_ref()
    }
}

/// Exact inline-length or externally content-addressed payload distinction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurablePayloadDescriptor {
    Inline(NonZeroUsize),
    BlobReference(Digest32),
}

/// Body-free original storage facts. Physical revisions/checkpoints remain
/// local audit/CAS facts, never substituted for authenticated logical generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableRecordMetadata {
    State {
        revision: StateRevision,
        value_length: Option<usize>,
    },
    Receipt {
        event_digest: Digest32,
        length: NonZeroUsize,
    },
    ObjectHead(DurableObjectHead),
    ObjectVersion {
        digest: Digest32,
        schema_version: u32,
        provenance: DurableObjectProvenance,
        created_checkpoint: u64,
        payload: DurablePayloadDescriptor,
    },
}

/// Validated exact identity used to detect row changes during range reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRecordDescriptor {
    key: DurableRecordKey,
    metadata: DurableRecordMetadata,
}

impl DurableRecordDescriptor {
    pub fn new(
        key: DurableRecordKey,
        metadata: DurableRecordMetadata,
    ) -> Result<Self, RuntimeError> {
        key.validate()?;
        let metadata_bytes: usize = match (&key, &metadata) {
            (
                DurableRecordKey::State(_),
                DurableRecordMetadata::State {
                    revision,
                    value_length,
                },
            ) => {
                if *revision == StateRevision::INITIAL
                    || value_length.is_some_and(|length| length > MAX_STATE_VALUE_BYTES)
                {
                    return Err(RuntimeError::InvalidPersistedState);
                }
                32
            }
            (DurableRecordKey::Receipt(_), DurableRecordMetadata::Receipt { length, .. }) => {
                if length.get() > MAX_DURABLE_RECEIPT_BYTES {
                    return Err(RuntimeError::InvalidPersistedState);
                }
                64
            }
            (DurableRecordKey::ObjectHead(_), DurableRecordMetadata::ObjectHead(head)) => {
                if matches!(head, DurableObjectHead::Absent) {
                    return Err(RuntimeError::InvalidPersistedState);
                }
                let owner: usize = head
                    .owner_projection()
                    .and_then(|owner| owner.bytes())
                    .map_or(0, <[u8]>::len);
                let routing: usize = head
                    .routing_projection()
                    .and_then(|routing| routing.bytes())
                    .map_or(0, <[u8]>::len);
                128 + owner + routing
            }
            (
                DurableRecordKey::ObjectVersion(_, _),
                DurableRecordMetadata::ObjectVersion {
                    provenance,
                    payload,
                    ..
                },
            ) => {
                if provenance.chain_id().as_str().len() > MAX_PORTABLE_CHAIN_ID_BYTES
                    || matches!(payload, DurablePayloadDescriptor::Inline(length) if length.get() > MAX_DURABLE_INLINE_OBJECT_BYTES)
                {
                    return Err(RuntimeError::InvalidPersistedState);
                }
                256 + provenance.chain_id().as_str().len()
            }
            _ => return Err(RuntimeError::InvalidPersistedState),
        };
        let total: usize = key
            .byte_bound()
            .checked_add(metadata_bytes)
            .ok_or(RuntimeError::InvalidPersistedState)?;
        if total > MAX_PORTABLE_DESCRIPTOR_BYTES {
            return Err(RuntimeError::InvalidPersistedState);
        }
        Ok(Self { key, metadata })
    }

    #[must_use]
    pub const fn key(&self) -> &DurableRecordKey {
        &self.key
    }
    #[must_use]
    pub const fn metadata(&self) -> &DurableRecordMetadata {
        &self.metadata
    }
    /// None means no local body: tombstone, body-free head or blob reference.
    /// Some(0) is distinct: an existing, present empty state value.
    #[must_use]
    pub const fn payload_length(&self) -> Option<usize> {
        match &self.metadata {
            DurableRecordMetadata::State { value_length, .. } => *value_length,
            DurableRecordMetadata::Receipt { length, .. } => Some(length.get()),
            DurableRecordMetadata::ObjectVersion {
                payload: DurablePayloadDescriptor::Inline(length),
                ..
            } => Some(length.get()),
            DurableRecordMetadata::ObjectHead(_) | DurableRecordMetadata::ObjectVersion { .. } => {
                None
            }
        }
    }
}

/// A strict range request, with no zero-length progress except a present empty
/// value's single terminal response at offset zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRecordChunkRequest {
    descriptor: DurableRecordDescriptor,
    offset: usize,
    limit: NonZeroUsize,
    /// Resolved once from `descriptor.payload_length()` at construction. The
    /// fields are private with no setters, so `range`/`is_last` always agree
    /// with the descriptor this request was validated against.
    length: usize,
}

impl DurableRecordChunkRequest {
    pub fn new(
        descriptor: DurableRecordDescriptor,
        offset: usize,
        limit: NonZeroUsize,
    ) -> Result<Self, RuntimeError> {
        if limit.get() > MAX_PORTABLE_CHUNK_BYTES {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        let length: usize = descriptor
            .payload_length()
            .ok_or(RuntimeError::InvalidStateScanPage)?;
        if (length == 0 && offset != 0) || (length > 0 && offset >= length) {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        Ok(Self {
            descriptor,
            offset,
            limit,
            length,
        })
    }
    #[must_use]
    pub const fn descriptor(&self) -> &DurableRecordDescriptor {
        &self.descriptor
    }
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
    /// Constructor invariants prove the subtraction/addition cannot overflow.
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.limit.get().min(self.length - self.offset)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableRecordChunk {
    request: DurableRecordChunkRequest,
    bytes: Vec<u8>,
}
impl DurableRecordChunk {
    /// Exact expected length, never a truncated successful response.
    pub fn new(request: DurableRecordChunkRequest, bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.len() != request.range().len() {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        Ok(Self { request, bytes })
    }
    #[must_use]
    pub const fn request(&self) -> &DurableRecordChunkRequest {
        &self.request
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.request.range().end == self.request.length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableRecordChunkOutcome {
    Chunk(Box<DurableRecordChunk>),
    /// Missing or mismatching descriptor. Discard partial downloads and obtain
    /// a new descriptor; this is NOT evidence of logical absence or a tombstone.
    Changed,
}

/// Every method enforces domain/schema/writer/deadline rules of point reads.
/// Chunk metadata comparison and range extraction share one read snapshot.
pub trait DurablePortableRepository: StructuredDurableDomainStateStore {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError>;
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError>;
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError>;
}

fn version_metadata(
    record: &DurableObjectVersionRecord,
) -> Result<DurableRecordMetadata, DurableReadError> {
    let payload: DurablePayloadDescriptor = match record.payload() {
        DurableObjectPayload::Inline(inline) => DurablePayloadDescriptor::Inline(
            NonZeroUsize::new(inline.canonical_bytes().len())
                .ok_or(DurableReadError::InvalidPersistedState)?,
        ),
        DurableObjectPayload::BlobReference(digest) => {
            DurablePayloadDescriptor::BlobReference(*digest)
        }
    };
    Ok(DurableRecordMetadata::ObjectVersion {
        digest: record.digest(),
        schema_version: record.schema_version(),
        provenance: record.provenance().clone(),
        created_checkpoint: record.created_checkpoint(),
        payload,
    })
}

fn memory_descriptor(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
    key: &DurableRecordKey,
) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
    let domain_bytes: [u8; 32] = *domain.as_bytes();
    let metadata: Option<DurableRecordMetadata> = match key {
        DurableRecordKey::State(key) => data
            .state_domains
            .get(&domain_bytes)
            .and_then(|state| state.get(key))
            .map(|row| DurableRecordMetadata::State {
                revision: row.revision,
                value_length: row.value.as_ref().map(Vec::len),
            }),
        DurableRecordKey::Receipt(id) => data
            .receipts
            .get(&(domain_bytes, *id.as_bytes()))
            .map(|receipt| {
                NonZeroUsize::new(receipt.canonical_bytes().len())
                    .map(|length| DurableRecordMetadata::Receipt {
                        event_digest: receipt.event_digest(),
                        length,
                    })
                    .ok_or(DurableReadError::InvalidPersistedState)
            })
            .transpose()?,
        DurableRecordKey::ObjectHead(id) => match read_memory_object_head(data, domain, *id)? {
            DurableObjectHead::Absent => None,
            head => Some(DurableRecordMetadata::ObjectHead(head)),
        },
        DurableRecordKey::ObjectVersion(id, version) => data
            .object_versions
            .get(&(domain_bytes, *id, *version))
            .map(version_metadata)
            .transpose()?,
    };
    metadata
        .map(|metadata| {
            DurableRecordDescriptor::new(key.clone(), metadata)
                .map_err(|_| DurableReadError::InvalidPersistedState)
        })
        .transpose()
}

impl DurablePortableRepository for MemoryDurableStateStore {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        if scan
            .after()
            .is_some_and(|after| after.collection() != scan.collection())
        {
            return Err(DurableReadError::InvalidPersistedState);
        }
        let data = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        let domain_bytes: [u8; 32] = *domain.as_bytes();
        let count: usize = scan.limit.get() + 1;
        let keys: Vec<DurableRecordKey> = match scan.collection {
            DurableCollection::State => match data.state_domains.get(&domain_bytes) {
                None => Vec::new(),
                Some(state) => {
                    let start: Bound<Vec<u8>> = match &scan.after {
                        None => Bound::Unbounded,
                        Some(DurableRecordKey::State(key)) => Bound::Excluded(key.clone()),
                        Some(_) => return Err(DurableReadError::InvalidPersistedState),
                    };
                    state
                        .range((start, Bound::Unbounded))
                        .take(count)
                        .map(|(key, _)| DurableRecordKey::State(key.clone()))
                        .collect()
                }
            },
            DurableCollection::Receipts => {
                let start: Bound<([u8; 32], [u8; 32])> = match &scan.after {
                    None => Bound::Included((domain_bytes, [0; 32])),
                    Some(DurableRecordKey::Receipt(id)) => {
                        Bound::Excluded((domain_bytes, *id.as_bytes()))
                    }
                    Some(_) => return Err(DurableReadError::InvalidPersistedState),
                };
                data.receipts
                    .range((start, Bound::Included((domain_bytes, [0xff; 32]))))
                    .take(count)
                    .map(|((_, id), _)| {
                        DurableRequestId::new(*id)
                            .map(DurableRecordKey::Receipt)
                            .map_err(|_| DurableReadError::InvalidPersistedState)
                    })
                    .collect::<Result<Vec<DurableRecordKey>, DurableReadError>>()?
            }
            DurableCollection::ObjectHeads => {
                let start: Bound<([u8; 32], ObjectId)> = match &scan.after {
                    None => Bound::Included((domain_bytes, ObjectId::new([0; 32]))),
                    Some(DurableRecordKey::ObjectHead(id)) => Bound::Excluded((domain_bytes, *id)),
                    Some(_) => return Err(DurableReadError::InvalidPersistedState),
                };
                data.object_heads
                    .range((
                        start,
                        Bound::Included((domain_bytes, ObjectId::new([0xff; 32]))),
                    ))
                    .take(count)
                    .map(|((_, id), _)| DurableRecordKey::ObjectHead(*id))
                    .collect()
            }
            DurableCollection::ObjectVersions => {
                let start: Bound<([u8; 32], ObjectId, DurableObjectVersion)> = match &scan.after {
                    None => Bound::Included((
                        domain_bytes,
                        ObjectId::new([0; 32]),
                        DurableObjectVersion::FIRST,
                    )),
                    Some(DurableRecordKey::ObjectVersion(id, version)) => {
                        Bound::Excluded((domain_bytes, *id, *version))
                    }
                    Some(_) => return Err(DurableReadError::InvalidPersistedState),
                };
                data.object_versions
                    .range((
                        start,
                        Bound::Included((
                            domain_bytes,
                            ObjectId::new([0xff; 32]),
                            DurableObjectVersion::MAX,
                        )),
                    ))
                    .take(count)
                    .map(|((_, id, version), _)| DurableRecordKey::ObjectVersion(*id, *version))
                    .collect()
            }
        };
        DurableRecordPage::from_ordered_candidates(scan, keys)
            .map_err(|_| DurableReadError::InvalidPersistedState)
    }

    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        key.validate().map_err(DurableReadError::InvalidRequest)?;
        let data = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        memory_descriptor(&data, domain, key)
    }

    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        let data = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        let key: &DurableRecordKey = request.descriptor.key();
        if memory_descriptor(&data, domain, key)?.as_ref() != Some(&request.descriptor) {
            return Ok(DurableRecordChunkOutcome::Changed);
        }
        let domain_bytes: [u8; 32] = *domain.as_bytes();
        let bytes: Option<&[u8]> = match key {
            DurableRecordKey::State(key) => data
                .state_domains
                .get(&domain_bytes)
                .and_then(|state| state.get(key))
                .and_then(|row| row.value.as_deref()),
            DurableRecordKey::Receipt(id) => data
                .receipts
                .get(&(domain_bytes, *id.as_bytes()))
                .map(|receipt| receipt.canonical_bytes()),
            DurableRecordKey::ObjectVersion(id, version) => data
                .object_versions
                .get(&(domain_bytes, *id, *version))
                .and_then(|row| row.payload().inline())
                .map(|inline| inline.canonical_bytes()),
            DurableRecordKey::ObjectHead(_) => None,
        };
        let bytes: Vec<u8> = bytes
            .and_then(|bytes| bytes.get(request.range()))
            .ok_or(DurableReadError::InvalidPersistedState)?
            .to_vec();
        DurableRecordChunk::new(request.clone(), bytes)
            .map(|chunk| DurableRecordChunkOutcome::Chunk(Box::new(chunk)))
            .map_err(|_| DurableReadError::InvalidPersistedState)
    }
}

/// Validated exact identity of one content-addressed blob, used to detect
/// storage inconsistency during a chunked range read.
///
/// [`BlobStore::put_blob`] forbids differing content under the same digest
/// and the current contract defines no delete or garbage collection. Under
/// that contract, a later length mismatch or disappearance is a storage
/// inconsistency, not a valid update. Introducing reclamation would require
/// revisiting this outcome. `length` zero is a present, empty blob,
/// distinct from an absent digest (`None` from
/// [`PortableBlobRepository::read_portable_blob_descriptor`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableBlobDescriptor {
    digest: Digest32,
    length: usize,
}

impl PortableBlobDescriptor {
    /// Constructs a descriptor for an exact digest and stored byte length.
    #[must_use]
    pub const fn new(digest: Digest32, length: usize) -> Self {
        Self { digest, length }
    }

    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }
}

/// A strict range request, with no zero-length progress except a present
/// empty blob's single terminal response at offset zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlobChunkRequest {
    descriptor: PortableBlobDescriptor,
    offset: usize,
    limit: NonZeroUsize,
}

impl PortableBlobChunkRequest {
    pub fn new(
        descriptor: PortableBlobDescriptor,
        offset: usize,
        limit: NonZeroUsize,
    ) -> Result<Self, RuntimeError> {
        if limit.get() > MAX_PORTABLE_CHUNK_BYTES {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        let length: usize = descriptor.length();
        if (length == 0 && offset != 0) || (length > 0 && offset >= length) {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        Ok(Self {
            descriptor,
            offset,
            limit,
        })
    }

    #[must_use]
    pub const fn descriptor(&self) -> &PortableBlobDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Constructor invariants prove the subtraction/addition cannot overflow.
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.limit.get().min(self.descriptor.length() - self.offset)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableBlobChunk {
    request: PortableBlobChunkRequest,
    bytes: Vec<u8>,
}

impl PortableBlobChunk {
    /// Exact expected length, never a truncated successful response.
    pub fn new(request: PortableBlobChunkRequest, bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.len() != request.range().len() {
            return Err(RuntimeError::InvalidStateScanPage);
        }
        Ok(Self { request, bytes })
    }

    #[must_use]
    pub const fn request(&self) -> &PortableBlobChunkRequest {
        &self.request
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn is_last(&self) -> bool {
        self.request.range().end == self.request.descriptor.length()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableBlobChunkOutcome {
    Chunk(Box<PortableBlobChunk>),
    /// The digest-keyed row has become absent or its stored byte length
    /// differs from the descriptor. This does not verify the content hash.
    /// Under the current no-delete/no-GC [`BlobStore`] contract, neither
    /// change is legitimate: discard partial downloads and do not trust any
    /// bytes already retrieved.
    Corrupt,
}

/// Bounded, exact byte-range reads over one content-addressed [`BlobStore`],
/// for reconstructing a large blob-referenced payload without materializing
/// the entire blob in the Rust process at once. Database-side work per range
/// has not been measured and is not claimed to be proportional to the range.
///
/// This is NOT an authenticated cut: it exposes exactly what [`BlobStore`]
/// already exposes, one bounded chunk at a time. A caller MUST hash the
/// fully reconstructed bytes against the digest it already trusts before
/// treating them as authentic, and MUST separately validate the structured
/// store's own cut authority; storing bytes under a digest key is not, by
/// itself, a claim of either. The trait takes no namespace or writer-fence
/// argument. A backend may bind a namespace at construction, as PostgreSQL
/// does, but no implementation here fences a live writer. A caller must not
/// infer writer authority from these reads.
pub trait PortableBlobRepository: BlobStore {
    /// Returns the descriptor for a present digest, or `None` if absent.
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<PortableBlobDescriptor>, RuntimeError>;

    /// Confirms the digest-keyed row is still present with exactly the
    /// descriptor's stored byte length in the same read that extracts the
    /// range. It does not re-hash the stored bytes.
    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError>;
}

impl PortableBlobRepository for MemoryBlobStore {
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<PortableBlobDescriptor>, RuntimeError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        Ok(guard
            .get(digest)
            .map(|bytes| PortableBlobDescriptor::new(*digest, bytes.len())))
    }

    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| RuntimeError::DurableStoreUnavailable)?;
        let descriptor: &PortableBlobDescriptor = request.descriptor();
        let Some(bytes) = guard.get(&descriptor.digest()) else {
            return Ok(PortableBlobChunkOutcome::Corrupt);
        };
        if bytes.len() != descriptor.length() {
            return Ok(PortableBlobChunkOutcome::Corrupt);
        }
        let chunk_bytes: Vec<u8> = bytes
            .get(request.range())
            .ok_or(RuntimeError::InvalidPersistedState)?
            .to_vec();
        PortableBlobChunk::new(request.clone(), chunk_bytes)
            .map(|chunk| PortableBlobChunkOutcome::Chunk(Box::new(chunk)))
    }
}

#[cfg(test)]
mod tests;

/// Shared test-only contract exercise used by memory, SQLite and PostgreSQL.
#[cfg(any(test, feature = "durable-conformance"))]
pub mod conformance;
