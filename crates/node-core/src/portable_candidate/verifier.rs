//! DR-0166 incremental verifier against one externally pinned
//! [`PortableCandidateManifest`]. Proves transport integrity of exactly the
//! source records that arrived; it grants no import, eligibility, cut or
//! Seal authority (see
//! `docs/architecture/decisions/0166-portable-candidate-snapshot.md`). Every
//! check runs against locally computed state and is only committed to
//! `self` after it succeeds, so a rejected item leaves the verifier
//! unchanged and safe to retry with a corrected item.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingRow {
    key: DurableRecordKey,
    descriptor: PortableCandidateDescriptor,
    next_offset: u64,
}

/// Failure verifying one item against the pinned manifest and prior state.
#[derive(Debug)]
pub enum PortableCandidateVerifierError {
    Candidate(PortableCandidateError),
    /// The verifier already reached [`PortableCandidateManifest`] completion.
    Complete,
    Invalid(&'static str),
}

impl fmt::Display for PortableCandidateVerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => error.fmt(f),
            Self::Complete => f.write_str("portable candidate verifier is already complete"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for PortableCandidateVerifierError {}
impl From<PortableCandidateError> for PortableCandidateVerifierError {
    fn from(value: PortableCandidateError) -> Self {
        Self::Candidate(value)
    }
}

/// Incremental checker for one pinned [`PortableCandidateManifest`]:
/// identity, sorted-key order, collection sequencing, row-index/chunk
/// continuity, descriptor agreement across a row's chunks, no payload on a
/// tombstone/head/blob-referenced row, and the final row counts/running
/// hash against the pinned root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCandidateVerifier {
    identity_digest: Digest32,
    epoch: Epoch,
    manifest: PortableCandidateManifest,
    collection_index: u16,
    expected_row_index: u64,
    row_counts: [u64; 4],
    item_count: u64,
    running_hash_step: Digest32,
    pending_row: Option<PendingRow>,
    last_completed_key: Option<DurableRecordKey>,
    complete: bool,
}

impl PortableCandidateVerifier {
    pub fn new(
        resolver: &HashSuiteResolver,
        manifest: PortableCandidateManifest,
    ) -> Result<Self, PortableCandidateVerifierError> {
        let identity_digest: Digest32 = manifest.identity.digest(resolver)?;
        Ok(Self {
            identity_digest,
            epoch: manifest.identity.drain_identity.epoch,
            manifest,
            collection_index: 0,
            expected_row_index: 0,
            row_counts: [0; 4],
            item_count: 0,
            running_hash_step: identity_digest,
            pending_row: None,
            last_completed_key: None,
            complete: false,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &PortableCandidateManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Verifies exactly one item in the exact order it arrived. On `Err`,
    /// `self` is guaranteed unchanged.
    pub fn verify_next(
        &mut self,
        resolver: &HashSuiteResolver,
        item: &PortableCandidateTransferItem,
    ) -> Result<(), PortableCandidateVerifierError> {
        if self.complete {
            return Err(PortableCandidateVerifierError::Complete);
        }
        if self.manifest.identity.digest(resolver)? != self.identity_digest {
            return Err(PortableCandidateVerifierError::Invalid(
                "candidate verifier resolver binding changed",
            ));
        }
        if item.identity_digest != self.identity_digest {
            return Err(PortableCandidateVerifierError::Invalid(
                "portable candidate item identity does not match the pinned manifest",
            ));
        }
        if self.collection_index as usize >= PORTABLE_CANDIDATE_COLLECTION_ORDER.len() {
            return Err(PortableCandidateVerifierError::Invalid(
                "portable candidate item arrived after the pinned manifest's last collection",
            ));
        }
        let expected_collection: DurableCollection =
            PORTABLE_CANDIDATE_COLLECTION_ORDER[self.collection_index as usize];
        if item.collection != expected_collection {
            return Err(PortableCandidateVerifierError::Invalid(
                "portable candidate item names the wrong collection",
            ));
        }

        let mut next_row_counts: [u64; 4] = self.row_counts;
        let mut next_collection_index: u16 = self.collection_index;
        let mut next_expected_row_index: u64 = self.expected_row_index;
        let mut next_pending_row: Option<PendingRow> = self.pending_row.clone();
        let mut next_last_key: Option<DurableRecordKey> = self.last_completed_key.clone();

        match &item.boundary {
            PortableCandidateBoundary::Row(row) => {
                row.key.validate().map_err(PortableCandidateError::from)?;
                let kinds_match: bool = matches!(
                    (&row.key, &row.descriptor, item.collection),
                    (
                        DurableRecordKey::State(_),
                        PortableCandidateDescriptor::State { .. },
                        DurableCollection::State
                    ) | (
                        DurableRecordKey::Receipt(_),
                        PortableCandidateDescriptor::Receipt { .. },
                        DurableCollection::Receipts
                    ) | (
                        DurableRecordKey::ObjectHead(_),
                        PortableCandidateDescriptor::ObjectHead(_),
                        DurableCollection::ObjectHeads
                    ) | (
                        DurableRecordKey::ObjectVersion(..),
                        PortableCandidateDescriptor::ObjectVersion { .. },
                        DurableCollection::ObjectVersions
                    )
                );
                if !kinds_match {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "candidate key/descriptor/collection mismatch",
                    ));
                }
                if let DurableRecordKey::State(key) = &row.key {
                    let identity: &PortableCandidateIdentity = &self.manifest.identity;
                    if classify_state_key(
                        key,
                        &identity.drain_identity.chain_id,
                        identity.drain_identity.protocol_version,
                    )? != PortableStateKeyClass::Included
                    {
                        return Err(PortableCandidateVerifierError::Invalid(
                            "replica-local row in candidate transfer",
                        ));
                    }
                }
                if !row.chunk_is_last && row.chunk_bytes.len() != MAX_PORTABLE_CHUNK_BYTES {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "nonterminal chunk must have the fixed chunk length",
                    ));
                }
                if row.chunk_bytes.len() > MAX_PORTABLE_CHUNK_BYTES {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "portable candidate chunk exceeds the fixed chunk bound",
                    ));
                }
                match &self.pending_row {
                    Some(pending) => {
                        if item.row_index != self.expected_row_index
                            || row.key != pending.key
                            || row.descriptor != pending.descriptor
                            || row.chunk_offset != pending.next_offset
                        {
                            return Err(PortableCandidateVerifierError::Invalid(
                                "portable candidate row chunk is discontinuous",
                            ));
                        }
                    }
                    None => {
                        if item.row_index != self.expected_row_index {
                            return Err(PortableCandidateVerifierError::Invalid(
                                "portable candidate row index is out of order",
                            ));
                        }
                        if row.chunk_offset != 0 {
                            return Err(PortableCandidateVerifierError::Invalid(
                                "portable candidate row starts at a nonzero offset",
                            ));
                        }
                        if let Some(previous) = &self.last_completed_key
                            && previous >= &row.key
                        {
                            return Err(PortableCandidateVerifierError::Invalid(
                                "portable candidate rows are not strictly sorted",
                            ));
                        }
                        let payload_free: bool = matches!(
                            row.descriptor,
                            PortableCandidateDescriptor::State { deleted: true }
                                | PortableCandidateDescriptor::ObjectHead(_)
                                | PortableCandidateDescriptor::ObjectVersion {
                                    payload: PortableCandidatePayloadKind::BlobReference(_),
                                    ..
                                }
                        );
                        if payload_free && (!row.chunk_bytes.is_empty() || !row.chunk_is_last) {
                            return Err(PortableCandidateVerifierError::Invalid(
                                "portable candidate tombstone, head or blob-referenced row carries a payload",
                            ));
                        }
                    }
                }
                if row.chunk_is_last {
                    next_row_counts[self.collection_index as usize] = next_row_counts
                        [self.collection_index as usize]
                        .checked_add(1)
                        .ok_or(PortableCandidateVerifierError::Invalid(
                            "portable candidate row count overflow",
                        ))?;
                    next_expected_row_index = item.row_index.checked_add(1).ok_or(
                        PortableCandidateVerifierError::Invalid(
                            "portable candidate row index overflow",
                        ),
                    )?;
                    next_pending_row = None;
                    next_last_key = Some(row.key.clone());
                } else {
                    let next_offset: u64 = row
                        .chunk_offset
                        .checked_add(row.chunk_bytes.len() as u64)
                        .ok_or(PortableCandidateVerifierError::Invalid(
                            "portable candidate chunk offset overflow",
                        ))?;
                    next_pending_row = Some(PendingRow {
                        key: row.key.clone(),
                        descriptor: row.descriptor.clone(),
                        next_offset,
                    });
                }
            }
            PortableCandidateBoundary::CollectionEnd { row_count } => {
                if self.pending_row.is_some() {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "portable candidate collection ended with a row still in progress",
                    ));
                }
                if item.row_index != self.expected_row_index
                    || *row_count != self.expected_row_index
                {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "portable candidate collection end disagrees with its counted rows",
                    ));
                }
                if *row_count != self.manifest.row_counts[self.collection_index as usize] {
                    return Err(PortableCandidateVerifierError::Invalid(
                        "portable candidate collection end disagrees with the pinned manifest count",
                    ));
                }
                next_collection_index = self.collection_index.checked_add(1).ok_or(
                    PortableCandidateVerifierError::Invalid(
                        "portable candidate collection index overflow",
                    ),
                )?;
                next_expected_row_index = 0;
                next_last_key = None;
            }
        }

        let item_bytes: Vec<u8> = encode_portable_candidate_transfer_item(item)?;
        let next_item_count: u64 =
            self.item_count
                .checked_add(1)
                .ok_or(PortableCandidateVerifierError::Invalid(
                    "portable candidate item count overflow",
                ))?;
        let next_hash: Digest32 = super::driver::next_hash_step(
            resolver,
            self.epoch,
            &self.identity_digest,
            next_item_count,
            &self.running_hash_step,
            &item_bytes,
        )?;

        let complete: bool =
            next_collection_index as usize == PORTABLE_CANDIDATE_COLLECTION_ORDER.len();
        if complete {
            if next_row_counts != self.manifest.row_counts {
                return Err(PortableCandidateVerifierError::Invalid(
                    "portable candidate final row counts disagree with the pinned manifest",
                ));
            }
            if next_hash != self.manifest.final_hash_step {
                return Err(PortableCandidateVerifierError::Invalid(
                    "portable candidate final running hash disagrees with the pinned manifest",
                ));
            }
        }

        self.row_counts = next_row_counts;
        self.collection_index = next_collection_index;
        self.expected_row_index = next_expected_row_index;
        self.pending_row = next_pending_row;
        self.last_completed_key = next_last_key;
        self.item_count = next_item_count;
        self.running_hash_step = next_hash;
        self.complete = complete;
        Ok(())
    }
}
