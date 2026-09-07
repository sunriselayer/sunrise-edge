#![forbid(unsafe_code)]

//! Durable snapshot integrity shared by authenticated submission and ABI-bound reads.
//! Reading proves neither call/owner/instance authority nor atomic snapshot isolation.
//! Head observations must be revalidated by a later fenced commit after replay checks.

use execution::publication::{BindingError, BodyError, BoundObjectParameter};
use std::collections::BTreeSet;
use std::fmt;

use super::*;

pub(super) struct ObjectSnapshot {
    pub(super) head: DurableObjectHead,
    pub(super) object: Object,
    pub(super) created_checkpoint: u64,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn load_object_snapshot<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    reference: &ObjectRef,
    total_body_bytes: &mut usize,
) -> Result<ObjectSnapshot, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let object_id: ObjectId = reference.id;
    let head: DurableObjectHead = store.get_object_head(context, domain, object_id)?;
    let (object_version, digest): (DurableObjectVersion, Digest32) = match &head {
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            return Err(NodeCoreError::ObjectNotFound { object_id });
        }
        DurableObjectHead::Current {
            object_version,
            digest,
            ..
        } => (*object_version, *digest),
    };

    if object_version.get() != reference.version {
        return Err(NodeCoreError::ObjectVersionMismatch {
            object_id,
            expected: reference.version,
            actual: object_version.get(),
        });
    }
    if digest != reference.digest {
        return Err(NodeCoreError::ObjectDigestMismatch {
            object_id,
            expected: reference.digest,
            actual: digest,
        });
    }

    let record: DurableObjectVersionRecord = store
        .get_object_version(context, domain, object_id, object_version)?
        .ok_or(NodeCoreError::ObjectRecordMissing { object_id })?;
    if record.object_id() != object_id
        || record.object_version() != object_version
        || record.digest() != digest
    {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id });
    }

    // Objects never migrate chains: the event chain is already validated
    // trusted input, so a mismatch here means a misbound namespace, a
    // cross-chain body transplant, or adapter corruption, never a
    // legitimate object. No equivalent check exists for the recorded
    // protocol version: a legitimately older object must still verify.
    // Checked from the record header alone, before any blob-store I/O,
    // so a misbound namespace never spends a blob fetch.
    if record.provenance().chain_id() != chain_id {
        return Err(NodeCoreError::ObjectProvenanceMismatch { object_id });
    }

    // Loads the canonical object body, either already inline or fetched
    // and independently verified from content-addressed blob storage.
    // Bytes are bounded at both the per-object and running-aggregate
    // limits before either digest is verified or the body is decoded —
    // for a blob body that bound runs immediately after the fetch, since
    // hashing and decoding are otherwise the first things that would
    // touch attacker-influenced bytes.
    let loaded_body: LoadedObjectBody<'_> = match record.payload() {
        DurableObjectPayload::Inline(inline) => LoadedObjectBody::Inline(inline),
        DurableObjectPayload::BlobReference(blob_digest) => {
            let blob_digest: Digest32 = *blob_digest;
            let bytes: Vec<u8> = blob_store
                .get_blob(&blob_digest)
                .map_err(NodeCoreError::Runtime)?
                .ok_or(NodeCoreError::ObjectBlobMissing {
                    object_id,
                    blob_digest,
                })?;
            *total_body_bytes =
                accumulate_authenticated_body_bytes(*total_body_bytes, object_id, bytes.len())?;
            let blob_verified: bool = hashing::verify_digest(
                &blob_digest,
                HashPurpose::Object,
                record.provenance().protocol_version(),
                record.provenance().chain_id(),
                &bytes,
            )
            .map_err(|error| match error {
                HashingError::UnsupportedAlgorithm(algorithm) => {
                    NodeCoreError::ObjectDigestUnverifiable {
                        object_id,
                        algorithm,
                    }
                }
                other => NodeCoreError::Hashing(other),
            })?;
            if !blob_verified {
                return Err(NodeCoreError::ObjectBlobDigestMismatch {
                    object_id,
                    blob_digest,
                });
            }
            let object: Object = decode_object(&bytes)
                .map_err(DurableInvocationError::from)
                .map_err(NodeCoreError::from)?;
            LoadedObjectBody::Blob { bytes, object }
        }
    };
    let object: &Object = loaded_body.object();
    if object.id != object_id
        || object.version != reference.version
        || record.schema_version() != object.schema_version
    {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id });
    }

    // A blob body was already bounded and folded into the aggregate
    // above, before its digest/decode; re-running this here would
    // double-count it. An inline body's bytes were already available
    // (no I/O, digest, or decode precedes this point for it), so its
    // bound/aggregate check keeps its original position, unaffected by
    // the blob-only reordering above.
    if matches!(record.payload(), DurableObjectPayload::Inline(_)) {
        *total_body_bytes = accumulate_authenticated_body_bytes(
            *total_body_bytes,
            object_id,
            loaded_body.canonical_bytes().len(),
        )?;
    }

    let verified: bool = hashing::verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        loaded_body.canonical_bytes(),
    )
    .map_err(|error| match error {
        HashingError::UnsupportedAlgorithm(algorithm) => NodeCoreError::ObjectDigestUnverifiable {
            object_id,
            algorithm,
        },
        other => NodeCoreError::Hashing(other),
    })?;
    if !verified {
        return Err(NodeCoreError::ObjectBodyDigestMismatch { object_id });
    }

    // Corruption guard, not authorization: mirrors
    // `validate_object_transition`'s owner-projection cross-check. An
    // absent projection is corruption, not a trust-the-inline fallback.
    if head
        .owner_projection()
        .and_then(DurableObjectOwnerProjection::owner)
        != Some(&object.owner)
    {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id });
    }

    let created_checkpoint: u64 = record.created_checkpoint();
    let object: Object = object.clone();

    Ok(ObjectSnapshot {
        head,
        object,
        created_checkpoint,
    })
}

/// Integrity-checked object data and exact head observations, not execution authority.
/// The observations are CAS obligations, not reservations or an atomic snapshot.
#[derive(Debug)]
pub struct BoundObjectSnapshots {
    objects: Vec<ResolvedObject>,
    reads: Vec<runtime::DurableObjectHeadRead>,
}

impl BoundObjectSnapshots {
    /// Returns data in declared access order, without ownership authorization.
    pub fn objects(&self) -> &[ResolvedObject] {
        &self.objects
    }

    /// Returns every exact head observation for later atomic commit validation.
    pub fn reads(&self) -> &[runtime::DurableObjectHeadRead] {
        &self.reads
    }
}

/// Storage-integrity or signed ABI representation failure.
#[derive(Debug)]
pub enum BoundSnapshotError {
    /// Durable read or object integrity failure.
    Node(NodeCoreError),
    /// Declared input metadata or body representation failure.
    Body(BodyError),
}

impl fmt::Display for BoundSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundSnapshotError::Node(error) => fmt::Display::fmt(error, f),
            BoundSnapshotError::Body(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for BoundSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BoundSnapshotError::Node(error) => Some(error),
            BoundSnapshotError::Body(error) => Some(error),
        }
    }
}

impl From<NodeCoreError> for BoundSnapshotError {
    fn from(error: NodeCoreError) -> Self {
        BoundSnapshotError::Node(error)
    }
}

impl From<BodyError> for BoundSnapshotError {
    fn from(error: BodyError) -> Self {
        BoundSnapshotError::Body(error)
    }
}

/// Loads declared inputs and validates integrity plus the bound signed body layouts.
/// Domain, context and resolver must be trusted composition inputs. This reads only:
/// no call signature, nonce, ownership, code/instance authority or mutation rights are
/// established. Future callers must reconcile replay before loading and carry every
/// head observation into the eventual fenced atomic commit. No public route or
/// execution consumer is activated by this helper.
#[allow(clippy::too_many_arguments)]
pub fn load_bound_object_snapshots<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    signature: &execution::publication::BoundObjectSignature<'_>,
    manifest: &abi::AccessManifest,
) -> Result<BoundObjectSnapshots, BoundSnapshotError>
where
    S: StructuredDurableDomainStateStore,
{
    let parameters: &[BoundObjectParameter] = signature.objects();
    let entries: &[abi::AccessEntry] = &manifest.entries;

    if entries.len() > abi::public_abi::MAX_ABI_OBJECT_PARAMS || parameters.len() != entries.len() {
        return Err(BoundSnapshotError::Body(BodyError::Binding(
            BindingError::InputCount,
        )));
    }

    let mut seen: BTreeSet<ObjectId> = BTreeSet::new();
    for entry in entries {
        if !seen.insert(entry.object_ref.id) {
            return Err(BoundSnapshotError::Body(BodyError::Binding(
                BindingError::DuplicateObject,
            )));
        }
    }

    if resolver.chain_id() != signature.chain_id() {
        return Err(BoundSnapshotError::Body(BodyError::Binding(
            BindingError::ChainMismatch,
        )));
    }

    for (entry, param) in entries.iter().zip(parameters) {
        let expected_mode: abi::public_abi::ObjectMode = match entry.mode {
            AccessMode::Read => abi::public_abi::ObjectMode::Read,
            AccessMode::Write => abi::public_abi::ObjectMode::Write,
            AccessMode::Consume => abi::public_abi::ObjectMode::Consume,
        };
        if expected_mode != param.mode() {
            return Err(BoundSnapshotError::Body(BodyError::Binding(
                BindingError::AccessMismatch,
            )));
        }
    }

    let mut total_body_bytes: usize = 0;
    let mut objects: Vec<ResolvedObject> = Vec::with_capacity(entries.len());
    let mut reads: Vec<runtime::DurableObjectHeadRead> = Vec::with_capacity(entries.len());

    for entry in entries {
        let snapshot: ObjectSnapshot = load_object_snapshot(
            store,
            blob_store,
            context,
            domain,
            resolver.chain_id(),
            &entry.object_ref,
            &mut total_body_bytes,
        )?;

        reads.push(runtime::DurableObjectHeadRead::new(
            entry.object_ref.id,
            snapshot.head,
        ));
        objects.push(ResolvedObject {
            object: snapshot.object,
            mode: entry.mode,
        });
    }

    execution::publication::validate_object_input_bodies(
        signature, resolver, epoch, manifest, &objects,
    )?;

    Ok(BoundObjectSnapshots { objects, reads })
}
