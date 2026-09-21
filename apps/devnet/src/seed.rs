//! Fail-closed protocol-context marker for the local devnet.
//!
//! A protocol-N data directory reused under a binary built for a different
//! protocol version or epoch would otherwise never fail closed: every
//! derived identity that depends on `protocol_version`/`epoch` would simply
//! diverge silently. [`verify_or_seed_protocol_context`] persists a single,
//! fixed, protocol-version-independent marker object on first boot and
//! reverifies it (protocol version, epoch, and canonical bytes) on every
//! later boot, so an incompatible data directory is rejected before any
//! genesis state is installed.

use crate::genesis::DEVNET_DOMAIN_BYTES;
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use hashing::{HashSuiteResolver, HashingError, verify_digest};
use objects::{
    Object, ObjectError, ObjectId, ObjectRef, Owner, decode_object, encode_object,
    encode_object_ref,
};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, HashPurpose};
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableInvocationError,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, IndeterminateCommitReason, IndexedOutboxContractError,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use std::{error::Error, fmt};

const PROTOCOL_CONTEXT_MARKER_TYPE_ID: u16 = 0x7A10;
const PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION: u16 = 1;
/// Fixed, protocol-version-independent object identifier for the persisted
/// protocol-context marker. Deliberately **not** derived through
/// [`HashSuiteResolver::hash_for_purpose`] (which mixes in
/// `protocol_version`): a marker whose own identity depended on the value it
/// exists to check could never detect a mismatch.
const PROTOCOL_CONTEXT_MARKER_OBJECT_ID: ObjectId = ObjectId::new([0xFE; 32]);

// ── Protocol-version marker ──────────────────────────────────────────────

fn protocol_context_marker_type_hash() -> Digest32 {
    Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0xFE; 32])
}

fn encode_protocol_context_marker(
    protocol_version: u32,
    epoch: Epoch,
) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        PROTOCOL_CONTEXT_MARKER_TYPE_ID,
        PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION,
    );
    frame.field_u32(1, protocol_version)?;
    frame.field_u64(2, epoch.get())?;
    frame.finish()
}

fn decode_protocol_context_marker(input: &[u8]) -> Result<(u32, u64), DevnetSeedError> {
    let frame: CanonicalFrame<'_> =
        decode_canonical_frame(input).map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_type(PROTOCOL_CONTEXT_MARKER_TYPE_ID)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_version(PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_only_fields(&[1, 2])
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    let protocol_version: u32 = frame
        .required_u32(1)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    let epoch: u64 = frame
        .required_u64(2)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    Ok((protocol_version, epoch))
}

/// Verifies (or, on first boot, seeds) a persisted marker recording the
/// exact protocol version and epoch this data directory was created under.
///
/// A data directory reused under a binary with a different protocol version
/// could otherwise derive a disjoint fresh object set in the same SQLite file
/// instead of refusing to boot. This
/// marker is deliberately keyed by a fixed, protocol-version-independent
/// `ObjectId` so it can actually detect that mismatch instead of silently
/// deriving a different identity for itself too.
///
/// Like its sibling seed functions, this rejects a `context` whose writer
/// fence disagrees with `boot_generation` before any storage work.
pub fn verify_or_seed_protocol_context<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    object_store_was_empty: bool,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if context.writer_fence() != boot_generation {
        return Err(DevnetSeedError::ContextFenceMismatch {
            context: context.writer_fence(),
            boot: boot_generation,
        });
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetSeedError::InvalidStaticDomain)?;
    let head: DurableObjectHead = store
        .get_object_head(context, domain, PROTOCOL_CONTEXT_MARKER_OBJECT_ID)
        .map_err(DevnetSeedError::Read)?;
    match head {
        DurableObjectHead::Absent => {
            if !object_store_was_empty {
                return Err(DevnetSeedError::UnmarkedExistingObjectState);
            }
            match create_protocol_context_marker(
                store,
                resolver,
                epoch,
                boot_generation,
                context,
                domain,
            ) {
                Ok(()) => Ok(()),
                Err(DevnetSeedError::CommitRejected(
                    DurableCommitRejection::ObjectConflict { .. }
                    | DurableCommitRejection::RequestAlreadyCommitted,
                )) => verify_protocol_context_marker_current(
                    store,
                    resolver,
                    epoch,
                    boot_generation,
                    context,
                    domain,
                ),
                Err(error) => Err(error),
            }
        }
        DurableObjectHead::Current { .. } => verify_protocol_context_marker_current(
            store,
            resolver,
            epoch,
            boot_generation,
            context,
            domain,
        ),
        DurableObjectHead::Tombstoned { .. } => Err(DevnetSeedError::UnexpectedHead {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            kind: "tombstoned",
        }),
    }
}

fn verify_protocol_context_marker_current<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let head: DurableObjectHead = store
        .get_object_head(context, domain, PROTOCOL_CONTEXT_MARKER_OBJECT_ID)
        .map_err(DevnetSeedError::Read)?;
    let DurableObjectHead::Current {
        object_version,
        digest: head_digest,
        owner_projection,
        routing_projection,
        ..
    } = head
    else {
        return Err(DevnetSeedError::UnexpectedHead {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            kind: head_kind(&head),
        });
    };
    let expected_owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Immutable)?;
    let expected_routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    if object_version != DurableObjectVersion::FIRST
        || owner_projection != expected_owner_projection
        || routing_projection != expected_routing_projection
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker head metadata differs",
        });
    }
    let record: DurableObjectVersionRecord = store
        .get_object_version(
            context,
            domain,
            PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            object_version,
        )
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            version: object_version,
        })?;
    if record.object_id() != PROTOCOL_CONTEXT_MARKER_OBJECT_ID
        || record.object_version() != DurableObjectVersion::FIRST
        || record.digest() != head_digest
        || record.schema_version() != 1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker head and immutable metadata differ",
        });
    }
    if record.provenance().chain_id() != resolver.chain_id() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker creating chain differs",
        });
    }
    let created_checkpoint: u64 = record.created_checkpoint();
    if created_checkpoint == 0 || created_checkpoint > boot_generation.get() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker checkpoint is zero or from a future boot generation",
        });
    }
    let inline = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline,
        DurableObjectPayload::BlobReference(_) => {
            return Err(DevnetSeedError::BlobBackedSeedObject(
                PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            ));
        }
    };
    let object: Object = decode_object(inline.canonical_bytes())?;
    if object.id != PROTOCOL_CONTEXT_MARKER_OBJECT_ID
        || object.version != DurableObjectVersion::FIRST.get()
        || object.owner != Owner::Immutable
        || object.type_hash != protocol_context_marker_type_hash()
        || object.schema_version != 1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker typed object differs",
        });
    }
    let canonical_object: Vec<u8> = encode_object(&object)?;
    if canonical_object != inline.canonical_bytes() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker bytes are not canonical",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        &canonical_object,
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker digest does not verify",
        });
    }
    let (stored_version, stored_epoch): (u32, u64) = decode_protocol_context_marker(&object.data)?;
    let canonical_body: Vec<u8> =
        encode_protocol_context_marker(stored_version, Epoch::new(stored_epoch))
            .map_err(DevnetSeedError::CanonicalEncoding)?;
    if canonical_body != object.data {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker body is not canonical",
        });
    }
    if record.provenance().protocol_version().get() != stored_version {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker body and provenance differ",
        });
    }
    let expected: u32 = resolver.protocol_version().get();
    if stored_version != expected {
        return Err(DevnetSeedError::ProtocolVersionMismatch {
            expected,
            actual: stored_version,
        });
    }
    if stored_epoch != epoch.get() {
        return Err(DevnetSeedError::EpochMismatch {
            expected: epoch.get(),
            actual: stored_epoch,
        });
    }
    let object_ref: ObjectRef = ObjectRef {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: object.version,
        digest: record.digest(),
    };
    let expected_receipt: DurableRequestReceipt = build_seed_receipt(resolver, epoch, &object_ref)?;
    verify_seed_receipt(store, context, domain, &expected_receipt)?;
    Ok(())
}

fn create_protocol_context_marker<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let body: Vec<u8> = encode_protocol_context_marker(resolver.protocol_version().get(), epoch)
        .map_err(DevnetSeedError::CanonicalEncoding)?;
    let object: Object = Object {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: DurableObjectVersion::FIRST.get(),
        owner: Owner::Immutable,
        type_hash: protocol_context_marker_type_hash(),
        schema_version: 1,
        data: body,
    };
    let canonical_object: Vec<u8> = encode_object(&object)?;
    let digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &canonical_object)?;
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version());
    let record: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        object,
        digest,
        provenance,
        boot_generation.get(),
    )?;
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Immutable)?;
    let routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    let reads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        DurableObjectHead::Absent,
    )];
    let mutations: Vec<DurableObjectMutationEntry> = vec![DurableObjectMutationEntry::new(
        PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        DurableObjectMutation::Create {
            version: record,
            owner_projection,
            routing_projection,
        },
    )];
    let objects: DurableObjectChanges = DurableObjectChanges::new(reads, mutations)?;
    let object_ref: ObjectRef = ObjectRef {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: DurableObjectVersion::FIRST.get(),
        digest,
    };
    let receipt: DurableRequestReceipt = build_seed_receipt(resolver, epoch, &object_ref)?;
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain, None, objects, receipt, None)?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(rejection) => {
            Err(DevnetSeedError::CommitRejected(rejection))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(DevnetSeedError::CommitIndeterminate(reason))
        }
    }
}

/// An `ObjectRef` is already a stable canonical record. Using the marker's
/// immutable version-one reference as the seed receipt avoids inventing a
/// new devnet-local wire type purely to name "the seeded protocol-context
/// marker".
fn build_seed_receipt(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    marker: &ObjectRef,
) -> Result<DurableRequestReceipt, DevnetSeedError> {
    let receipt_bytes: Vec<u8> = encode_object_ref(marker)?;
    let request_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Transaction, &receipt_bytes)?;
    let event_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &receipt_bytes)?;
    let request_id: DurableRequestId = DurableRequestId::new(request_digest.bytes())?;
    Ok(DurableRequestReceipt::new(
        request_id,
        event_digest,
        receipt_bytes,
    )?)
}

fn verify_seed_receipt<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &DurableRequestReceipt,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(context, domain, expected.request_id())
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingSeedReceipt)?;
    if &receipt != expected {
        return Err(DevnetSeedError::ReceiptMismatch);
    }
    Ok(())
}

fn head_kind(head: &DurableObjectHead) -> &'static str {
    match head {
        DurableObjectHead::Absent => "absent",
        DurableObjectHead::Tombstoned { .. } => "tombstoned",
        DurableObjectHead::Current { .. } => "current",
    }
}

/// Fail-closed errors while creating or verifying the devnet protocol-context
/// marker.
#[derive(Debug)]
pub enum DevnetSeedError {
    /// The hard-coded devnet atomicity domain unexpectedly violated its invariant.
    InvalidStaticDomain,
    /// The supplied operation context does not carry this boot's writer fence.
    ContextFenceMismatch {
        /// Fence carried by the operation context.
        context: WriterFenceGeneration,
        /// Fence exclusively claimed by this boot.
        boot: WriterFenceGeneration,
    },
    /// Existing object framing failed.
    Object(ObjectError),
    /// Domain-separated hash derivation or verification failed.
    Hashing(HashingError),
    /// The persisted protocol-context marker failed to encode.
    CanonicalEncoding(CanonicalEncodingError),
    /// The persisted protocol-context marker failed to decode.
    CanonicalDecoding(CanonicalDecodingError),
    /// The bounded durable envelope was invalid.
    Invocation(DurableInvocationError),
    /// A deterministic non-zero durable request identity could not be built.
    RequestIdentity(IndexedOutboxContractError),
    /// A structured read failed.
    Read(DurableReadError),
    /// The protocol-context marker had an unexpected head kind.
    UnexpectedHead {
        /// The object identifier.
        object_id: ObjectId,
        /// The unexpected head kind.
        kind: &'static str,
    },
    /// An exact immutable version referenced by the marker's current head was missing.
    MissingObjectVersion {
        /// Missing object's identity.
        object_id: ObjectId,
        /// Missing immutable version.
        version: DurableObjectVersion,
    },
    /// The genesis (version-one) marker record was blob-backed. Seeding
    /// always creates version one inline, and nothing ever republishes an
    /// existing immutable version under a different representation, so this
    /// is persisted corruption, not a currently-reachable case.
    BlobBackedSeedObject(ObjectId),
    /// Stored marker metadata, bytes, digest, or provenance did not match.
    StoredObjectMismatch {
        /// Mismatched object's identity.
        object_id: ObjectId,
        /// Stable operator-facing mismatch category.
        detail: &'static str,
    },
    /// The deterministic original seed receipt was absent.
    MissingSeedReceipt,
    /// The deterministic seed request identity resolved to different receipt bytes.
    ReceiptMismatch,
    /// The store proved that marker creation did not commit.
    CommitRejected(DurableCommitRejection),
    /// The store could not determine whether marker creation committed.
    CommitIndeterminate(IndeterminateCommitReason),
    /// The persisted protocol-context marker disagrees with the configured
    /// protocol version: this data directory was created under a different,
    /// incompatible protocol version and must not be reused.
    ProtocolVersionMismatch {
        /// The currently configured protocol version.
        expected: u32,
        /// The protocol version this data directory was created under.
        actual: u32,
    },
    /// The persisted marker's creation epoch disagrees with the configured
    /// epoch. Because devnet genesis identity is epoch-bound, the data
    /// directory must not be reused under another epoch.
    EpochMismatch {
        /// The currently configured epoch.
        expected: u64,
        /// The epoch this data directory was created under.
        actual: u64,
    },
    /// Object state already existed before the first protocol-context marker
    /// could be installed. This is an unsupported pre-marker data directory
    /// and must not be mixed with newly derived object state.
    UnmarkedExistingObjectState,
}

impl fmt::Display for DevnetSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStaticDomain => f.write_str("devnet's fixed atomicity domain is invalid"),
            Self::ContextFenceMismatch { context, boot } => write!(
                f,
                "seed context fence {} differs from boot generation {}",
                context.get(),
                boot.get()
            ),
            Self::Object(error) => write!(f, "seed object framing failed: {error}"),
            Self::Hashing(error) => write!(f, "seed hash derivation failed: {error}"),
            Self::CanonicalEncoding(error) => {
                write!(f, "seed marker encoding failed: {error}")
            }
            Self::CanonicalDecoding(error) => {
                write!(f, "seed marker decoding failed: {error}")
            }
            Self::Invocation(error) => write!(f, "seed durable envelope is invalid: {error}"),
            Self::RequestIdentity(error) => {
                write!(f, "seed request identity is invalid: {error}")
            }
            Self::Read(error) => write!(f, "seed structured read failed: {error:?}"),
            Self::UnexpectedHead { object_id, kind } => write!(
                f,
                "seed object {object_id} has an unexpected head kind: {kind}"
            ),
            Self::MissingObjectVersion { object_id, version } => write!(
                f,
                "seed object {object_id} immutable version {} is missing",
                version.get()
            ),
            Self::BlobBackedSeedObject(object_id) => write!(
                f,
                "seed object {object_id} genesis version is blob-backed, expected inline"
            ),
            Self::StoredObjectMismatch { object_id, detail } => {
                write!(f, "seed object {object_id} failed verification: {detail}")
            }
            Self::MissingSeedReceipt => f.write_str("deterministic seed receipt is missing"),
            Self::ReceiptMismatch => f.write_str("deterministic seed receipt differs"),
            Self::CommitRejected(rejection) => {
                write!(f, "seed commit was rejected: {rejection:?}")
            }
            Self::CommitIndeterminate(reason) => {
                write!(f, "seed commit is indeterminate: {reason:?}")
            }
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "data directory was seeded under protocol version {actual}, current configuration is protocol version {expected}; use a fresh --data-dir"
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "data directory was seeded under epoch {actual}, current configuration is epoch {expected}; use a fresh --data-dir"
            ),
            Self::UnmarkedExistingObjectState => f.write_str(
                "data directory contains object state but no protocol-context marker; it predates the marker and must be replaced with a fresh --data-dir",
            ),
        }
    }
}

impl Error for DevnetSeedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::Invocation(error) => Some(error),
            Self::RequestIdentity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ObjectError> for DevnetSeedError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<HashingError> for DevnetSeedError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<DurableInvocationError> for DevnetSeedError {
    fn from(value: DurableInvocationError) -> Self {
        Self::Invocation(value)
    }
}

impl From<IndexedOutboxContractError> for DevnetSeedError {
    fn from(value: IndexedOutboxContractError) -> Self {
        Self::RequestIdentity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use runtime::{MemoryDurableStateStore, StorageCorrelationId, StorageDeadline};

    fn resolver(protocol_version: u32) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("seed-test-chain").unwrap(),
            ProtocolVersion::new(protocol_version),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn generation() -> WriterFenceGeneration {
        WriterFenceGeneration::new(2).unwrap()
    }

    fn context() -> DurableOperationContext {
        DurableOperationContext::new(
            generation(),
            StorageDeadline::new(1_000).unwrap(),
            StorageCorrelationId::new([0x51; 16]).unwrap(),
        )
    }

    fn domain() -> AtomicityDomainId {
        AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap()
    }

    fn store() -> MemoryDurableStateStore {
        let store = MemoryDurableStateStore::new_bound(domain(), generation());
        store.set_time(0);
        store
    }

    #[test]
    fn protocol_context_marker_is_seeded_once_and_reverified_on_restart() {
        let store = store();
        let resolver = resolver(4);

        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();
        // Idempotent: a second call under the same protocol version succeeds.
        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn verify_or_seed_protocol_context_rejects_a_context_fence_mismatch() {
        let store = store();
        let resolver = resolver(4);
        let mismatched_context = DurableOperationContext::new(
            WriterFenceGeneration::new(3).unwrap(),
            StorageDeadline::new(1_000).unwrap(),
            StorageCorrelationId::new([0x52; 16]).unwrap(),
        );

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &mismatched_context,
            true,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::ContextFenceMismatch { .. })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_a_mismatched_reused_data_directory() {
        let store = store();
        let v4_resolver = resolver(4);
        verify_or_seed_protocol_context(
            &store,
            &v4_resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();

        let v5_resolver = resolver(5);
        let result = verify_or_seed_protocol_context(
            &store,
            &v5_resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::ProtocolVersionMismatch {
                expected: 5,
                actual: 4,
            })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_a_mismatched_epoch() {
        let store = store();
        let resolver = resolver(4);
        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(1),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::EpochMismatch {
                expected: 1,
                actual: 0,
            })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_unmarked_existing_object_state() {
        let store = store();
        let resolver = resolver(4);

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::UnmarkedExistingObjectState)
        ));
    }
}
