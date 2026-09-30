//! DR-0166 driver: begins a guarded local candidate enumeration bound to one
//! already-verified [`CandidateFreeTerminalWitness`], then advances it one
//! bounded [`PortableCandidateTransferItem`] per call. See
//! `docs/architecture/decisions/0166-portable-candidate-snapshot.md` for the
//! exact contract this proves and does not prove.
use super::*;

const PORTABLE_CANDIDATE_HASH_STEP_TYPE: u16 = 0x6495;
const HASH_STEP_VERSION: u16 = 1;

/// One canonical fold step of the resumable running commitment: identity,
/// explicit cumulative item count, previous step and exact canonical item
/// bytes. Before any item, the running value is the identity digest itself
/// (no frame is hashed for that seed state).
pub(super) fn next_hash_step(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    identity_digest: &Digest32,
    item_count: u64,
    previous: &Digest32,
    item_bytes: &[u8],
) -> Result<Digest32, PortableCandidateError> {
    let bytes: Vec<u8> = encode_hash_step(identity_digest, item_count, previous, item_bytes)?;
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, &bytes)?)
}

pub(super) fn encode_hash_step(
    identity_digest: &Digest32,
    item_count: u64,
    previous: &Digest32,
    item_bytes: &[u8],
) -> Result<Vec<u8>, PortableCandidateError> {
    if item_count == 0 || item_bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES {
        return Err(PortableCandidateError::Invalid(
            "invalid hash-step item bound or index",
        ));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_HASH_STEP_TYPE, HASH_STEP_VERSION);
    frame.field_bytes(1, canonical_encoding::encode_digest32(identity_digest)?)?;
    frame.field_u64(2, item_count)?;
    frame.field_bytes(3, canonical_encoding::encode_digest32(previous)?)?;
    frame.field_bytes(4, item_bytes.to_vec())?;
    Ok(frame.finish()?)
}

/// Result of one [`begin_portable_candidate_enumeration`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateBegin {
    pub identity: PortableCandidateIdentity,
    pub source_token: PortableSnapshotToken,
}

/// Result of one [`advance_portable_candidate_transfer`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableCandidateAdvanceOutcome {
    /// One bounded item was committed (or, on an exact-prior-index replay,
    /// re-served without a new write).
    Item(PortableCandidateTransferItem),
    /// A bounded page of physically scanned keys classified entirely as
    /// excluded local rows; progress advanced its skip cursor but committed
    /// no item. The caller must call again with the same `expected_item_index`.
    Continue,
    /// Every collection's `CollectionEnd` has already been committed.
    Complete(PortableCandidateManifest),
}

fn classify_record_key(
    collection: DurableCollection,
    key: &DurableRecordKey,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
) -> Result<PortableStateKeyClass, PortableCandidateError> {
    match (collection, key) {
        (DurableCollection::State, DurableRecordKey::State(bytes)) => {
            classify_state_key(bytes, chain, protocol_version)
        }
        _ => Ok(PortableStateKeyClass::Included),
    }
}

enum ScanOutcome {
    Found(DurableRecordKey),
    Continue(DurableRecordKey),
    Exhausted,
}

#[allow(clippy::too_many_arguments)]
fn scan_for_next_key<Source: DurablePortableSnapshotRepository>(
    source: &Source,
    source_context: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    collection: DurableCollection,
    chain: &ChainId,
    protocol_version: ProtocolVersion,
    after: Option<DurableRecordKey>,
) -> Result<ScanOutcome, PortableCandidateError> {
    let limit: NonZeroUsize = NonZeroUsize::new(MAX_PORTABLE_PAGE_KEYS)
        .ok_or(PortableCandidateError::Invalid("zero portable page bound"))?;
    let scan: DurableRecordScan = DurableRecordScan::new(collection, after, limit)?;
    let page: DurableRecordPage =
        source.scan_portable_keys_at(source_context, domain, token, &scan)?;
    for key in page.keys() {
        if classify_record_key(collection, key, chain, protocol_version)?
            == PortableStateKeyClass::Included
        {
            return Ok(ScanOutcome::Found(key.clone()));
        }
    }
    Ok(match page.continuation() {
        Some(key) => ScanOutcome::Continue(key.clone()),
        None => ScanOutcome::Exhausted,
    })
}

/// Reads one row's exact descriptor and, unless it has no local body
/// (tombstone, body-free head, or blob reference), one bounded chunk.
#[allow(clippy::too_many_arguments)]
fn read_row_item<Source: DurablePortableSnapshotRepository>(
    source: &Source,
    source_context: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    identity_digest: Digest32,
    collection: DurableCollection,
    row_index: u64,
    key: DurableRecordKey,
    chunk_offset: u64,
) -> Result<PortableCandidateTransferItem, PortableCandidateError> {
    let descriptor: DurableRecordDescriptor = source
        .read_portable_descriptor_at(source_context, domain, token, &key)?
        .ok_or(PortableCandidateError::Invalid(
            "portable candidate row disappeared under a guarded source snapshot",
        ))?;
    let projected: PortableCandidateDescriptor =
        project_portable_candidate_descriptor(&descriptor)?;
    let payload_length: Option<usize> = descriptor.payload_length();
    let (chunk_bytes, chunk_is_last): (Vec<u8>, bool) = match payload_length {
        None => {
            if chunk_offset != 0 {
                return Err(PortableCandidateError::Invalid(
                    "portable candidate resumed a body-free row at a nonzero offset",
                ));
            }
            (Vec::new(), true)
        }
        Some(_) => {
            let offset: usize = usize::try_from(chunk_offset).map_err(|_| {
                PortableCandidateError::Invalid("portable candidate chunk offset out of range")
            })?;
            let limit: NonZeroUsize = NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES)
                .ok_or(PortableCandidateError::Invalid("zero portable chunk bound"))?;
            let request: DurableRecordChunkRequest =
                DurableRecordChunkRequest::new(descriptor, offset, limit)?;
            match source.read_portable_chunk_at(source_context, domain, token, &request)? {
                DurableRecordChunkOutcome::Chunk(chunk) => {
                    (chunk.bytes().to_vec(), chunk.is_last())
                }
                DurableRecordChunkOutcome::Changed => {
                    return Err(PortableCandidateError::Source(
                        PortableSnapshotError::Changed,
                    ));
                }
            }
        }
    };
    Ok(PortableCandidateTransferItem {
        identity_digest,
        collection,
        row_index,
        boundary: PortableCandidateBoundary::Row(PortableCandidateRowTransfer {
            key,
            descriptor: projected,
            chunk_offset,
            chunk_bytes,
            chunk_is_last,
        }),
    })
}

pub(super) fn persist_progress<Progress: StructuredDurableDomainStateStore>(
    progress_store: &Progress,
    progress_context: &DurableOperationContext,
    progress_domain: AtomicityDomainId,
    key: &[u8],
    expected_revision: StateRevision,
    progress: &PortableCandidateProgress,
) -> Result<(), PortableCandidateError> {
    let bytes: Vec<u8> = progress::encode_portable_candidate_progress(progress)?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        progress_domain,
        AtomicStateReadSet::new(vec![StateReadAssertion::new(
            key.to_vec(),
            expected_revision,
        )?])?,
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(
            key.to_vec(),
            StateMutation::Put(bytes),
        )?])?,
    )?;
    match progress_store.commit_durable(progress_context, transaction) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(_) => Err(PortableCandidateError::Conflict(
            "portable candidate progress write conflicted",
        )),
        DurableCommitOutcome::Indeterminate(_) => Err(PortableCandidateError::Indeterminate(
            "portable candidate progress write outcome is indeterminate",
        )),
    }
}

/// Begins a guarded candidate enumeration: opens the source's
/// [`PortableSnapshotToken`] *before* deriving the candidate-free terminal
/// witness, derives that witness, then guards the token *after* derivation
/// by requiring an empty outbox in the same read snapshot -- so a
/// Freeze/DrainSet candidate committed between those two steps is still
/// caught. `progress_store`/`progress_domain` must be a distinct namespace
/// and domain from the source, so progress writes never mutate or fence the
/// exact source snapshot this call just pinned.
pub fn begin_portable_candidate_enumeration<Source, Progress>(
    source: &Source,
    source_context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    progress_store: &Progress,
    progress_context: &DurableOperationContext,
    progress_domain: AtomicityDomainId,
) -> Result<PortableCandidateBegin, PortableCandidateError>
where
    Source: DurablePortableSnapshotRepository,
    Progress: DurablePortableSnapshotRepository,
{
    let domain: AtomicityDomainId = env.policy.domain();
    let source_token: PortableSnapshotToken =
        source.begin_portable_snapshot(source_context, domain)?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let terminal: CandidateFreeTerminalWitness =
        derive_candidate_free_terminal_into(source, source_context, env, &mut reads)?;
    source.check_portable_outbox_empty_at(source_context, domain, &source_token)?;
    let identity: PortableCandidateIdentity =
        PortableCandidateIdentity::bind(env.resolver, &terminal)?;

    let progress_token: PortableSnapshotToken =
        progress_store.begin_portable_snapshot(progress_context, progress_domain)?;
    if progress_domain == domain || progress_token.namespace() == source_token.namespace() {
        return Err(PortableCandidateError::Invalid(
            "portable candidate progress must use a namespace and domain distinct from its source",
        ));
    }

    let identity_digest: Digest32 = identity.digest(env.resolver)?;
    let key: Vec<u8> = progress::portable_candidate_progress_key(&identity_digest);
    let row: VersionedStateValue =
        progress_store.get_versioned_durable(progress_context, progress_domain, &key)?;
    if let Some(bytes) = row.value() {
        let existing: PortableCandidateProgress = decode_portable_candidate_progress(bytes)?;
        if existing.identity_digest == identity_digest
            && existing.source_namespace.as_slice() == source_token.namespace()
            && existing.source_domain == domain
            && existing.source_writer_fence == source_token.writer_fence()
            && existing.source_mutation_sequence == source_token.mutation_sequence()
        {
            return Ok(PortableCandidateBegin {
                identity,
                source_token,
            });
        }
        return Err(PortableCandidateError::Conflict(
            "portable candidate progress already exists for a different source snapshot",
        ));
    }
    if row.revision() != StateRevision::INITIAL {
        return Err(PortableCandidateError::Invalid(
            "portable candidate progress is tombstoned",
        ));
    }
    let initial: PortableCandidateProgress = PortableCandidateProgress {
        identity_digest,
        source_namespace: source_token.namespace().to_vec(),
        source_domain: domain,
        source_writer_fence: source_token.writer_fence(),
        source_mutation_sequence: source_token.mutation_sequence(),
        collection_index: 0,
        next_row_index: 0,
        next_chunk_offset: 0,
        item_count: 0,
        running_hash_step: identity_digest,
        last_item_bytes: Vec::new(),
        row_counts: [0; 4],
        skip_scan_after: Vec::new(),
    };
    persist_progress(
        progress_store,
        progress_context,
        progress_domain,
        &key,
        row.revision(),
        &initial,
    )?;
    Ok(PortableCandidateBegin {
        identity,
        source_token,
    })
}

#[allow(clippy::too_many_arguments)]
fn commit_item<Progress: StructuredDurableDomainStateStore>(
    progress_store: &Progress,
    progress_context: &DurableOperationContext,
    progress_domain: AtomicityDomainId,
    key: &[u8],
    expected_revision: StateRevision,
    mut progress: PortableCandidateProgress,
    item: PortableCandidateTransferItem,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<PortableCandidateAdvanceOutcome, PortableCandidateError> {
    let item_bytes: Vec<u8> = encode_portable_candidate_transfer_item(&item)?;
    let new_item_count: u64 =
        progress
            .item_count
            .checked_add(1)
            .ok_or(PortableCandidateError::Invalid(
                "portable candidate item count overflow",
            ))?;
    let new_hash: Digest32 = next_hash_step(
        resolver,
        epoch,
        &progress.identity_digest,
        new_item_count,
        &progress.running_hash_step,
        &item_bytes,
    )?;
    match &item.boundary {
        PortableCandidateBoundary::Row(row) => {
            let collection_index: usize = progress.collection_index as usize;
            if row.chunk_is_last {
                progress.row_counts[collection_index] =
                    progress.row_counts[collection_index].checked_add(1).ok_or(
                        PortableCandidateError::Invalid("portable candidate row count overflow"),
                    )?;
                progress.next_row_index =
                    item.row_index
                        .checked_add(1)
                        .ok_or(PortableCandidateError::Invalid(
                            "portable candidate row index overflow",
                        ))?;
                progress.next_chunk_offset = 0;
            } else {
                progress.next_row_index = item.row_index;
                progress.next_chunk_offset = row
                    .chunk_offset
                    .checked_add(row.chunk_bytes.len() as u64)
                    .ok_or(PortableCandidateError::Invalid(
                        "portable candidate chunk offset overflow",
                    ))?;
            }
            progress.skip_scan_after.clear();
        }
        PortableCandidateBoundary::CollectionEnd { .. } => {
            progress.collection_index =
                progress
                    .collection_index
                    .checked_add(1)
                    .ok_or(PortableCandidateError::Invalid(
                        "portable candidate collection index overflow",
                    ))?;
            progress.next_row_index = 0;
            progress.next_chunk_offset = 0;
            progress.skip_scan_after.clear();
        }
    }
    progress.item_count = new_item_count;
    progress.running_hash_step = new_hash;
    progress.last_item_bytes = item_bytes;
    persist_progress(
        progress_store,
        progress_context,
        progress_domain,
        key,
        expected_revision,
        &progress,
    )?;
    Ok(PortableCandidateAdvanceOutcome::Item(item))
}

/// Advances one already-begun candidate enumeration by exactly one bounded
/// item. `expected_item_index` must equal the persisted item count (produce
/// the next item) or one less than it (exact replay of the last committed
/// item, with no new source read or write); any other value conflicts. A
/// bounded page (at most [`runtime::portable::MAX_PORTABLE_PAGE_KEYS`] keys)
/// of entirely excluded local rows advances a skip cursor and returns
/// [`PortableCandidateAdvanceOutcome::Continue`] instead of looping.
#[allow(clippy::too_many_arguments)]
pub fn advance_portable_candidate_transfer<Source, Progress>(
    source: &Source,
    source_context: &DurableOperationContext,
    resolver: &HashSuiteResolver,
    identity: &PortableCandidateIdentity,
    progress_store: &Progress,
    progress_context: &DurableOperationContext,
    progress_domain: AtomicityDomainId,
    expected_item_index: u64,
) -> Result<PortableCandidateAdvanceOutcome, PortableCandidateError>
where
    Source: DurablePortableSnapshotRepository,
    Progress: StructuredDurableDomainStateStore,
{
    let identity_digest: Digest32 = identity.digest(resolver)?;
    let key: Vec<u8> = progress::portable_candidate_progress_key(&identity_digest);
    let row: VersionedStateValue =
        progress_store.get_versioned_durable(progress_context, progress_domain, &key)?;
    let bytes: &[u8] = row.value().ok_or(PortableCandidateError::Invalid(
        "portable candidate progress is missing; call begin first",
    ))?;
    let progress: PortableCandidateProgress = decode_portable_candidate_progress(bytes)?;
    if progress.identity_digest != identity_digest
        || progress.source_domain != identity.drain_identity.domain
    {
        return Err(PortableCandidateError::Invalid(
            "portable candidate progress identity mismatch",
        ));
    }
    let total_collections: u16 = u16::try_from(PORTABLE_CANDIDATE_COLLECTION_ORDER.len())
        .map_err(|_| PortableCandidateError::Invalid("collection count out of range"))?;

    if progress.collection_index >= total_collections {
        if progress.item_count > 0
            && expected_item_index.checked_add(1) == Some(progress.item_count)
        {
            return Ok(PortableCandidateAdvanceOutcome::Item(
                decode_portable_candidate_transfer_item(&progress.last_item_bytes)?,
            ));
        }
        if expected_item_index == progress.item_count {
            return Ok(PortableCandidateAdvanceOutcome::Complete(
                PortableCandidateManifest {
                    identity: identity.clone(),
                    row_counts: progress.row_counts,
                    final_hash_step: progress.running_hash_step,
                },
            ));
        }
        return Err(PortableCandidateError::Conflict(
            "portable candidate transfer expected item index disagrees with completed progress",
        ));
    }
    if progress.item_count > 0 && expected_item_index.checked_add(1) == Some(progress.item_count) {
        return Ok(PortableCandidateAdvanceOutcome::Item(
            decode_portable_candidate_transfer_item(&progress.last_item_bytes)?,
        ));
    }
    if expected_item_index != progress.item_count {
        return Err(PortableCandidateError::Conflict(
            "portable candidate transfer expected item index disagrees with progress",
        ));
    }

    let domain: AtomicityDomainId = progress.source_domain;
    let token: PortableSnapshotToken = PortableSnapshotToken::new(
        progress.source_namespace.clone(),
        progress.source_domain,
        progress.source_writer_fence,
        progress.source_mutation_sequence,
    )?;
    let chain: ChainId = identity.drain_identity.chain_id.clone();
    let protocol_version: ProtocolVersion = identity.drain_identity.protocol_version;
    let epoch: Epoch = identity.drain_identity.epoch;
    let collection: DurableCollection =
        PORTABLE_CANDIDATE_COLLECTION_ORDER[progress.collection_index as usize];

    let decoded_last: Option<PortableCandidateTransferItem> = if progress.item_count > 0 {
        Some(decode_portable_candidate_transfer_item(
            &progress.last_item_bytes,
        )?)
    } else {
        None
    };

    if let Some(item) = &decoded_last
        && item.collection == collection
        && let PortableCandidateBoundary::Row(pending) = &item.boundary
        && !pending.chunk_is_last
    {
        let next_item: PortableCandidateTransferItem = read_row_item(
            source,
            source_context,
            domain,
            &token,
            identity_digest,
            collection,
            item.row_index,
            pending.key.clone(),
            progress.next_chunk_offset,
        )?;
        return commit_item(
            progress_store,
            progress_context,
            progress_domain,
            &key,
            row.revision(),
            progress,
            next_item,
            resolver,
            epoch,
        );
    }

    let after: Option<DurableRecordKey> = if !progress.skip_scan_after.is_empty() {
        Some(transfer::decode_durable_record_key(
            collection,
            &progress.skip_scan_after,
        )?)
    } else {
        match &decoded_last {
            Some(item) if item.collection == collection => match &item.boundary {
                PortableCandidateBoundary::Row(row) => Some(row.key.clone()),
                PortableCandidateBoundary::CollectionEnd { .. } => None,
            },
            _ => None,
        }
    };

    match scan_for_next_key(
        source,
        source_context,
        domain,
        &token,
        collection,
        &chain,
        protocol_version,
        after,
    )? {
        ScanOutcome::Found(next_key) => {
            let next_item: PortableCandidateTransferItem = read_row_item(
                source,
                source_context,
                domain,
                &token,
                identity_digest,
                collection,
                progress.next_row_index,
                next_key,
                0,
            )?;
            commit_item(
                progress_store,
                progress_context,
                progress_domain,
                &key,
                row.revision(),
                progress,
                next_item,
                resolver,
                epoch,
            )
        }
        ScanOutcome::Continue(cursor) => {
            let mut next_progress: PortableCandidateProgress = progress;
            next_progress.skip_scan_after = transfer::encode_durable_record_key(&cursor);
            persist_progress(
                progress_store,
                progress_context,
                progress_domain,
                &key,
                row.revision(),
                &next_progress,
            )?;
            Ok(PortableCandidateAdvanceOutcome::Continue)
        }
        ScanOutcome::Exhausted => {
            let row_count: u64 = progress.row_counts[progress.collection_index as usize];
            let end_item: PortableCandidateTransferItem = PortableCandidateTransferItem {
                identity_digest,
                collection,
                row_index: progress.next_row_index,
                boundary: PortableCandidateBoundary::CollectionEnd { row_count },
            };
            commit_item(
                progress_store,
                progress_context,
                progress_domain,
                &key,
                row.revision(),
                progress,
                end_item,
                resolver,
                epoch,
            )
        }
    }
}
