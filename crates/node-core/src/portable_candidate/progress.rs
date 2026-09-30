//! `PortableCandidateProgress` (frame `0x6494`): the replica-local resumable
//! cursor row [`super::driver`] persists under
//! [`super::PORTABLE_CANDIDATE_STATE_PREFIX`] -- reusing
//! [`crate::local_instance_state::INSTANCE_STATE_PREFIX`]'s existing
//! enforcement -- on its own CAS/writer fence, under a domain *different*
//! from the source it observes. Progress publication is never atomically
//! fenced against the source's own CAS read set (DR-0166): it is a local
//! bookkeeping row, never portable cut authority. It never mutates its own
//! source, so beginning or advancing a candidate never invalidates the very
//! [`runtime::portable::PortableSnapshotToken`] it is reading through.
use super::*;

const PORTABLE_CANDIDATE_PROGRESS_TYPE: u16 = 0x6494;
const ENCODING_VERSION: u16 = 1;
pub const MAX_ENCODED_PORTABLE_CANDIDATE_PROGRESS_BYTES: usize =
    MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES + 8192;

/// Resumable local progress for one candidate identity. `last_item_bytes` is
/// the exact encoded bytes of the most recently committed transfer item (or
/// empty before the first item), enabling an exact-retry of the same request
/// to return saved bytes without a new source read or write
/// ([`super::driver::advance_portable_candidate_transfer`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateProgress {
    pub identity_digest: Digest32,
    /// The source token's fields, persisted outside the hashed identity root
    /// purely as a local storage fence, per
    /// [`runtime::portable::PortableSnapshotToken`].
    pub source_namespace: Vec<u8>,
    pub source_domain: AtomicityDomainId,
    pub source_writer_fence: WriterFenceGeneration,
    pub source_mutation_sequence: u64,
    /// Index into [`super::PORTABLE_CANDIDATE_COLLECTION_ORDER`]; `4` means
    /// every collection's `CollectionEnd` has been emitted.
    pub collection_index: u16,
    pub next_row_index: u64,
    pub next_chunk_offset: u64,
    /// Monotonic count of items committed so far; `0` before the first item.
    pub item_count: u64,
    pub running_hash_step: Digest32,
    pub last_item_bytes: Vec<u8>,
    pub row_counts: [u64; 4],
    /// Exact physical continuation key from a prior page whose entire
    /// bounded scan (DR-0166: at most [`runtime::portable::MAX_PORTABLE_PAGE_KEYS`]
    /// keys) classified as excluded local rows, with no included row found
    /// yet. Empty means no pending skip continuation. Collection completion
    /// and every emitted row clear it; it is interpreted against the
    /// collection at [`Self::collection_index`], never a different one.
    pub skip_scan_after: Vec<u8>,
}

pub(crate) fn portable_candidate_progress_key(identity_digest: &Digest32) -> Vec<u8> {
    let mut key: Vec<u8> = PORTABLE_CANDIDATE_STATE_PREFIX.to_vec();
    key.extend_from_slice(&identity_digest.algorithm().as_u16().to_be_bytes());
    key.extend_from_slice(&identity_digest.bytes());
    key
}

pub(crate) fn encode_portable_candidate_progress(
    progress: &PortableCandidateProgress,
) -> Result<Vec<u8>, PortableCandidateError> {
    validate_progress(progress)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(PORTABLE_CANDIDATE_PROGRESS_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        canonical_encoding::encode_digest32(&progress.identity_digest)?,
    )?;
    frame.field_bytes(2, progress.source_namespace.clone())?;
    frame.field_bytes(3, progress.source_domain.as_bytes().to_vec())?;
    frame.field_u64(4, progress.source_writer_fence.get())?;
    frame.field_u64(5, progress.source_mutation_sequence)?;
    frame.field_u16(6, progress.collection_index)?;
    frame.field_u64(7, progress.next_row_index)?;
    frame.field_u64(8, progress.next_chunk_offset)?;
    frame.field_u64(9, progress.item_count)?;
    frame.field_bytes(
        10,
        canonical_encoding::encode_digest32(&progress.running_hash_step)?,
    )?;
    if progress.last_item_bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES {
        return Err(PortableCandidateError::Invalid(
            "progress last item bytes exceed the transfer item bound",
        ));
    }
    frame.field_bytes(11, progress.last_item_bytes.clone())?;
    for (index, count) in progress.row_counts.iter().enumerate() {
        let index: u16 = u16::try_from(index)
            .map_err(|_| PortableCandidateError::Invalid("row count field index out of range"))?;
        frame.field_u64(12 + index, *count)?;
    }
    if progress.skip_scan_after.len() > runtime::portable::MAX_PORTABLE_DESCRIPTOR_BYTES {
        return Err(PortableCandidateError::Invalid(
            "progress skip scan key exceeds the descriptor key bound",
        ));
    }
    frame.field_bytes(16, progress.skip_scan_after.clone())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_PROGRESS_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate progress frame too large",
        ));
    }
    Ok(bytes)
}

/// Reject impossible cursor combinations before serving saved bytes or
/// issuing any new source I/O. These are local consistency checks, not proof
/// that this progress row or the source represents a legitimate chain cut.
fn validate_progress(progress: &PortableCandidateProgress) -> Result<(), PortableCandidateError> {
    PortableSnapshotToken::new(
        progress.source_namespace.clone(),
        progress.source_domain,
        progress.source_writer_fence,
        progress.source_mutation_sequence,
    )?;
    let current: usize = usize::from(progress.collection_index);
    if current > PORTABLE_CANDIDATE_COLLECTION_ORDER.len()
        || progress
            .row_counts
            .iter()
            .skip(current + usize::from(current < 4))
            .any(|count| *count != 0)
        || (current < 4 && progress.next_row_index != progress.row_counts[current])
        || (current == 4
            && (progress.next_row_index != 0
                || progress.next_chunk_offset != 0
                || !progress.skip_scan_after.is_empty()))
    {
        return Err(PortableCandidateError::Invalid(
            "inconsistent progress collection or row counts",
        ));
    }
    if !progress.skip_scan_after.is_empty() {
        if current >= 4 || progress.next_chunk_offset != 0 {
            return Err(PortableCandidateError::Invalid(
                "invalid progress skip cursor",
            ));
        }
        transfer::decode_durable_record_key(
            PORTABLE_CANDIDATE_COLLECTION_ORDER[current],
            &progress.skip_scan_after,
        )?;
    }
    if progress.item_count == 0 {
        if !progress.last_item_bytes.is_empty()
            || current != 0
            || progress.row_counts != [0; 4]
            || progress.next_chunk_offset != 0
            || progress.running_hash_step != progress.identity_digest
        {
            return Err(PortableCandidateError::Invalid("invalid initial progress"));
        }
        return Ok(());
    }
    let last: PortableCandidateTransferItem =
        decode_portable_candidate_transfer_item(&progress.last_item_bytes)?;
    if last.identity_digest != progress.identity_digest {
        return Err(PortableCandidateError::Invalid(
            "progress last item identity mismatch",
        ));
    }
    let last_index: usize = usize::from(collection_tag(last.collection) - 1);
    match &last.boundary {
        PortableCandidateBoundary::CollectionEnd { row_count } => {
            if current != last_index + 1
                || *row_count != progress.row_counts[last_index]
                || last.row_index != *row_count
                || progress.next_chunk_offset != 0
            {
                return Err(PortableCandidateError::Invalid(
                    "inconsistent collection-end progress",
                ));
            }
        }
        PortableCandidateBoundary::Row(row) => {
            let expected_row: Option<u64> = if row.chunk_is_last {
                last.row_index.checked_add(1)
            } else {
                Some(last.row_index)
            };
            let expected_offset: Option<u64> = if row.chunk_is_last {
                Some(0)
            } else {
                row.chunk_offset.checked_add(
                    u64::try_from(row.chunk_bytes.len()).map_err(|_| {
                        PortableCandidateError::Invalid("chunk length out of range")
                    })?,
                )
            };
            if current != last_index
                || expected_row != Some(progress.next_row_index)
                || expected_offset != Some(progress.next_chunk_offset)
                || (!row.chunk_is_last
                    && (row.chunk_bytes.len() != MAX_PORTABLE_CHUNK_BYTES
                        || !progress.skip_scan_after.is_empty()))
            {
                return Err(PortableCandidateError::Invalid(
                    "inconsistent row-chunk progress",
                ));
            }
        }
    }
    Ok(())
}

pub fn decode_portable_candidate_progress(
    input: &[u8],
) -> Result<PortableCandidateProgress, PortableCandidateError> {
    if input.len() > MAX_ENCODED_PORTABLE_CANDIDATE_PROGRESS_BYTES {
        return Err(PortableCandidateError::Invalid(
            "candidate progress frame too large",
        ));
    }
    let frame = decode_canonical_frame(input)?;
    frame.require_type(PORTABLE_CANDIDATE_PROGRESS_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])?;
    let identity_digest: Digest32 = canonical_encoding::decode_digest32(frame.required_field(1)?)?;
    let source_namespace: Vec<u8> = frame.required_field(2)?.to_vec();
    let domain_bytes: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| PortableCandidateError::Invalid("invalid progress source domain length"))?;
    let source_domain: AtomicityDomainId = AtomicityDomainId::new(domain_bytes)
        .map_err(|_| PortableCandidateError::Invalid("zero progress source domain"))?;
    let source_writer_fence: WriterFenceGeneration =
        WriterFenceGeneration::new(frame.required_u64(4)?).ok_or(
            PortableCandidateError::Invalid("zero progress source writer fence"),
        )?;
    let source_mutation_sequence: u64 = frame.required_u64(5)?;
    let collection_index: u16 = frame.required_u16(6)?;
    if collection_index as usize > PORTABLE_CANDIDATE_COLLECTION_ORDER.len() {
        return Err(PortableCandidateError::Invalid(
            "progress collection index out of range",
        ));
    }
    let next_row_index: u64 = frame.required_u64(7)?;
    let next_chunk_offset: u64 = frame.required_u64(8)?;
    let item_count: u64 = frame.required_u64(9)?;
    let running_hash_step: Digest32 =
        canonical_encoding::decode_digest32(frame.required_field(10)?)?;
    let last_item_bytes: Vec<u8> = frame.required_field(11)?.to_vec();
    if last_item_bytes.len() > MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES {
        return Err(PortableCandidateError::Invalid(
            "progress last item bytes exceed the transfer item bound",
        ));
    }
    let skip_scan_after: Vec<u8> = frame.required_field(16)?.to_vec();
    if skip_scan_after.len() > runtime::portable::MAX_PORTABLE_DESCRIPTOR_BYTES {
        return Err(PortableCandidateError::Invalid(
            "progress skip scan key exceeds the descriptor key bound",
        ));
    }
    let progress = PortableCandidateProgress {
        identity_digest,
        source_namespace,
        source_domain,
        source_writer_fence,
        source_mutation_sequence,
        collection_index,
        next_row_index,
        next_chunk_offset,
        item_count,
        running_hash_step,
        last_item_bytes,
        row_counts: [
            frame.required_u64(12)?,
            frame.required_u64(13)?,
            frame.required_u64(14)?,
            frame.required_u64(15)?,
        ],
        skip_scan_after,
    };
    if encode_portable_candidate_progress(&progress)? != input {
        return Err(PortableCandidateError::Invalid(
            "noncanonical portable candidate progress",
        ));
    }
    Ok(progress)
}
