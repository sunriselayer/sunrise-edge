//! DR-0166: connected, bounded portable CANDIDATE enumeration and transport
//! verification driver.
//!
//! This module proves exactly one thing: that a quiet local source's
//! structured `State`/`Receipts`/`ObjectHeads`/`ObjectVersions`
//! (`runtime::portable::DurableCollection`) rows can be consistently
//! enumerated, bound to one already-verified candidate-free terminal
//! identity, and transported intact against an externally pinned candidate
//! manifest. It does **not** perform a full authenticated cut, replay
//! closure, signed cut decision, next-set ready marker, target-side import,
//! or activation: see
//! `docs/architecture/decisions/0166-portable-candidate-snapshot.md`.
//!
//! The driver ([`begin_portable_candidate_enumeration`],
//! [`advance_portable_candidate_transfer`]) begins the source's
//! `PortableSnapshotToken` *before* deriving the candidate-free terminal
//! witness, then performs the guarded outbox-empty check *after* that
//! derivation -- exactly the order DR-0166 requires, since a Freeze/DrainSet
//! candidate committed between those two steps must still be caught by the
//! outbox check rather than silently admitted. Identity binds the complete
//! drain identity, terminal height/digest and exact proof digest; every
//! digest this module computes reuses the existing [`HashSuiteResolver`]
//! framing with `HashPurpose::ExecutionEffects` and distinct canonical type
//! identifiers rather than inventing a parallel hash domain.
//!
//! Six new node-core canonical frames are allocated from the swept,
//! previously unused `0x6490..=0x6495` block (see
//! [`crate::logical_generation`]'s own `0x6480..=0x648F` allocation note for
//! provenance of that sweep): `0x6490` identity, `0x6491` semantic descriptor
//! projection, `0x6492` transfer item, `0x6493` manifest, `0x6494` progress
//! envelope, `0x6495` hash-step. None of these are consensus type IDs.
use super::*;
use consensus::{
    DrainUnionIdentity, decode_drain_union_identity, encode_committed_block_proof,
    encode_drain_union_identity,
};
use ordered_economics::{
    CandidateFreeTerminalWitness, OrderedEconomicsEnvironment, TerminalAnchorError,
    derive_candidate_free_terminal_into,
};
use runtime::WriterFenceGeneration;
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurablePortableSnapshotRepository,
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordDescriptor,
    DurableRecordKey, DurableRecordMetadata, DurableRecordPage, DurableRecordScan,
    MAX_PORTABLE_CHUNK_BYTES, MAX_PORTABLE_PAGE_KEYS, PortableSnapshotError, PortableSnapshotToken,
};
use std::num::NonZeroUsize;

mod classifier;
mod descriptor;
mod driver;
mod identity;
mod manifest;
mod progress;
mod transfer;
mod verifier;

pub use classifier::{PortableStateKeyClass, classify_state_key};
pub use descriptor::{
    PortableCandidateDescriptor, PortableCandidatePayloadKind, PortableObjectHeadProjection,
    decode_portable_candidate_descriptor, encode_portable_candidate_descriptor,
    project_portable_candidate_descriptor,
};
pub use driver::{
    PortableCandidateAdvanceOutcome, PortableCandidateBegin, advance_portable_candidate_transfer,
    begin_portable_candidate_enumeration,
};
pub use identity::{
    PortableCandidateIdentity, decode_portable_candidate_identity,
    encode_portable_candidate_identity,
};
pub use manifest::{
    PortableCandidateManifest, decode_portable_candidate_manifest,
    encode_portable_candidate_manifest,
};
pub use progress::{PortableCandidateProgress, decode_portable_candidate_progress};
pub use transfer::{
    MAX_ENCODED_PORTABLE_CANDIDATE_TRANSFER_ITEM_BYTES, PortableCandidateBoundary,
    PortableCandidateRowTransfer, PortableCandidateTransferItem,
    decode_portable_candidate_transfer_item, encode_portable_candidate_transfer_item,
};
pub use verifier::{PortableCandidateVerifier, PortableCandidateVerifierError};

/// Reserved under [`crate::local_instance_state::INSTANCE_STATE_PREFIX`], so
/// every existing enforcement point that already covers `se/instances/`
/// covers this progress row for free.
pub(crate) const PORTABLE_CANDIDATE_STATE_PREFIX: &[u8] = b"se/instances/v1/portable-candidate/";

/// The fixed, required collection order (DR-0166): source enumeration and
/// every transport item, manifest count and hash-step index follow exactly
/// this order and no other.
pub(crate) const PORTABLE_CANDIDATE_COLLECTION_ORDER: [DurableCollection; 4] = [
    DurableCollection::State,
    DurableCollection::Receipts,
    DurableCollection::ObjectHeads,
    DurableCollection::ObjectVersions,
];

pub(crate) fn collection_tag(collection: DurableCollection) -> u16 {
    match collection {
        DurableCollection::State => 1,
        DurableCollection::Receipts => 2,
        DurableCollection::ObjectHeads => 3,
        DurableCollection::ObjectVersions => 4,
    }
}

pub(crate) fn collection_from_tag(tag: u16) -> Result<DurableCollection, PortableCandidateError> {
    match tag {
        1 => Ok(DurableCollection::State),
        2 => Ok(DurableCollection::Receipts),
        3 => Ok(DurableCollection::ObjectHeads),
        4 => Ok(DurableCollection::ObjectVersions),
        _ => Err(PortableCandidateError::Invalid(
            "unknown portable candidate collection tag",
        )),
    }
}

/// Failures specific to DR-0166 portable candidate enumeration and transport
/// verification. None of these permits a caller to fall back to an
/// unauthenticated shortcut or to retry unsafely: [`Self::Conflict`] and
/// [`Self::Indeterminate`] are typed outcomes a caller must handle
/// explicitly, never silently retried as if they were success.
#[derive(Debug)]
pub enum PortableCandidateError {
    /// Storage, encoding or canonical-decoding boundary failure.
    Node(NodeCoreError),
    /// The local candidate-free terminal witness could not be derived.
    Terminal(Box<TerminalAnchorError>),
    /// The guarded portable source snapshot changed, is unsupported, or the
    /// source has a nonempty outbox.
    Source(PortableSnapshotError),
    /// A persisted or supplied row, cursor or manifest is structurally
    /// invalid, noncanonical, or disagrees with a pinned binding.
    Invalid(&'static str),
    /// A requested item index disagrees with the persisted cursor, or a
    /// commit was rejected. Never silently retried.
    Conflict(&'static str),
    /// A commit's outcome is unknown; a caller must reconcile before
    /// retrying, never assume either success or failure.
    Indeterminate(&'static str),
}

impl fmt::Display for PortableCandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Terminal(error) => error.fmt(f),
            Self::Source(error) => error.fmt(f),
            Self::Invalid(message) | Self::Conflict(message) | Self::Indeterminate(message) => {
                f.write_str(message)
            }
        }
    }
}

impl Error for PortableCandidateError {}

impl From<NodeCoreError> for PortableCandidateError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<TerminalAnchorError> for PortableCandidateError {
    fn from(value: TerminalAnchorError) -> Self {
        Self::Terminal(Box::new(value))
    }
}
impl From<PortableSnapshotError> for PortableCandidateError {
    fn from(value: PortableSnapshotError) -> Self {
        Self::Source(value)
    }
}
impl From<RuntimeError> for PortableCandidateError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for PortableCandidateError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalEncodingError> for PortableCandidateError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<CanonicalDecodingError> for PortableCandidateError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Node(value.into())
    }
}
impl From<HashingError> for PortableCandidateError {
    fn from(value: HashingError) -> Self {
        Self::Node(NodeCoreError::Hashing(value))
    }
}

#[cfg(test)]
mod tests;
