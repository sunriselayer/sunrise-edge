//! Closed, field-aware equality against independently reconstructed memory.
//! No source value is installed into that memory store. Local bookkeeping is
//! excluded only after its owning schema validates the complete key and value.

use super::{
    BusinessReconstructionError, BusinessReconstructionOverlay, ReconstructionEd25519Verifier,
    SourceBusinessSnapshot, SourceSnapshotRecord, invalid,
};
use crate::NodeDedupRecord;
use crate::fast_path::{prepared_material, publication, records};
use crate::genesis::{
    decode_genesis_install_marker, encode_genesis_install_marker, genesis_marker_key,
};
use crate::local_instance_state::{
    FASTPATH_STATE_PREFIX, decode_fastpath_epoch_record, decode_fastpath_lock_record,
    decode_fastpath_nonce_lock_record, encode_fastpath_epoch_record, fastpath_epoch_record_key,
    fastpath_lock_key, fastpath_nonce_lock_key, fastpath_prepared_record_key,
    fastpath_synthetic_prepare_request_id, is_reserved_paid_request_id,
};
use canonical_encoding::encode_chain_id;
use consensus::{
    AvailabilityCertifier, FastPathCertifier, decode_availability_identity,
    decode_availability_vote, decode_fast_vote,
};
use protocol_types::{Digest32, HashPurpose};
use runtime::portable::{
    DurableCollection, DurablePayloadDescriptor, DurablePortableSnapshotRepository,
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordKey, DurableRecordMetadata,
    DurableRecordScan, MAX_PORTABLE_CHUNK_BYTES, MAX_PORTABLE_PAGE_KEYS, PortableSnapshotToken,
};
use runtime::{
    AtomicStateTransaction, AtomicityDomainId, BlobStore, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectHead, DurableObjectProvenance, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, StateRevision, StructuredDurableDomainStateStore,
    VersionedStateValue,
};
use std::{collections::BTreeMap, num::NonZeroUsize};

#[derive(Clone, Debug, PartialEq, Eq)]
enum SemanticRecord {
    State(Option<Vec<u8>>),
    Receipt(Digest32, Vec<u8>),
    Head {
        live: bool,
        version: u64,
        digest: Option<Digest32>,
        owner: Option<Vec<u8>>,
        routing: Option<Vec<u8>>,
    },
    ObjectVersion {
        digest: Digest32,
        schema: u32,
        provenance: DurableObjectProvenance,
        payload: DurablePayloadDescriptor,
        bytes: Vec<u8>,
    },
}

type SemanticProjection = BTreeMap<DurableRecordKey, SemanticRecord>;
type StateRows<'a> = BTreeMap<Vec<u8>, &'a SourceSnapshotRecord>;

/// A non-mutating view used exclusively to validate source-local backing rows.
/// It cannot commit, and is never passed to any business execution handler.
struct CapturedStateView<'a> {
    domain: AtomicityDomainId,
    rows: StateRows<'a>,
}

impl DurableDomainStateStore for CapturedStateView<'_> {
    fn get_versioned_durable(
        &self,
        _operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        if domain != self.domain {
            return Err(DurableReadError::InvalidPersistedState);
        }
        match self.rows.get(key) {
            Some(row) => match row.descriptor.metadata() {
                DurableRecordMetadata::State { revision, .. } => {
                    VersionedStateValue::from_persisted_parts(*revision, row.value.clone())
                        .map_err(DurableReadError::InvalidRequest)
                }
                _ => Err(DurableReadError::InvalidPersistedState),
            },
            None => VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                .map_err(DurableReadError::InvalidRequest),
        }
    }

    fn commit_durable(
        &self,
        _operation: &DurableOperationContext,
        _transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    }
}

impl StructuredDurableDomainStateStore for CapturedStateView<'_> {
    fn get_request_receipt(
        &self,
        _operation: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        // Prepared-material validation never reads receipts. There is no
        // fallback that turns source companions into completed execution.
        Err(DurableReadError::InvalidPersistedState)
    }

    fn commit_invocation(
        &self,
        _operation: &DurableOperationContext,
        _transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    }
}

fn state_rows(records: &[SourceSnapshotRecord]) -> StateRows<'_> {
    records
        .iter()
        .filter_map(|row| match row.descriptor.key() {
            DurableRecordKey::State(key) => Some((key.clone(), row)),
            _ => None,
        })
        .collect()
}

fn family_tail<'a>(key: &'a [u8], family: &[u8], chain: &[u8]) -> Option<&'a [u8]> {
    key.strip_prefix(FASTPATH_STATE_PREFIX)?
        .strip_prefix(family)?
        .strip_prefix(chain)
}

/// Recognizes complete keys, not an entire familiar namespace prefix.
fn exact_tail<'a>(
    key: &'a [u8],
    family: &[u8],
    chain: &[u8],
    length: usize,
) -> Result<Option<&'a [u8]>, BusinessReconstructionError> {
    let Some(suffix) = key.strip_prefix(FASTPATH_STATE_PREFIX) else {
        return Ok(None);
    };
    if !suffix.starts_with(family) {
        return Ok(None);
    }
    let tail: &[u8] =
        family_tail(key, family, chain).ok_or(invalid("local row names another chain"))?;
    if tail.len() != length {
        return Err(invalid("local row key has an unknown suffix"));
    }
    Ok(Some(tail))
}

fn local_fastpath_rows(
    overlay: &BusinessReconstructionOverlay<'_>,
    records: &[SourceSnapshotRecord],
) -> Result<(BTreeMap<Vec<u8>, ()>, BTreeMap<[u8; 32], Digest32>), BusinessReconstructionError> {
    let plan = &overlay.plan;
    let chain = plan.genesis.context().chain_id();
    let encoded_chain: Vec<u8> =
        encode_chain_id(chain).map_err(|_| invalid("projection chain key encoding"))?;
    let view: CapturedStateView<'_> = CapturedStateView {
        domain: plan.domain,
        rows: state_rows(records),
    };
    let validators = plan.ordered_policy.engine().validator_set().clone();
    let fast: FastPathCertifier = FastPathCertifier::new(
        chain.clone(),
        plan.genesis.context().protocol_version(),
        plan.genesis.context().epoch(),
        validators.clone(),
    )
    .map_err(|_| invalid("projection FastVote authority"))?;
    let availability: AvailabilityCertifier = AvailabilityCertifier::new(
        chain.clone(),
        plan.genesis.context().protocol_version(),
        plan.genesis.context().epoch(),
        validators,
    )
    .map_err(|_| invalid("projection availability authority"))?;
    let mut excluded: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
    let mut internal_receipts: BTreeMap<[u8; 32], Digest32> = BTreeMap::new();
    for (key, row) in &view.rows {
        if let Some(tail) = exact_tail(key, b"prepared/", &encoded_chain, 32)? {
            let request: [u8; 32] = tail.try_into().map_err(|_| invalid("prepared identity"))?;
            let bytes: &[u8] = row
                .value
                .as_deref()
                .ok_or(invalid("deleted prepared row"))?;
            let prepared = records::decode_fastpath_prepared_record(bytes)
                .map_err(|_| invalid("local prepared schema"))?;
            if prepared.request_id != request
                || prepared.context != *plan.genesis.context()
                || prepared.prepared_generation.is_none()
                || fastpath_prepared_record_key(chain, &request)
                    .map_err(|_| invalid("prepared key"))?
                    != *key
            {
                return Err(invalid("local prepared key/context/generation differs"));
            }
            crate::admission_profile::require_external_request_lane(
                plan.admission_profile,
                crate::admission_profile::ExternalRequestLane::Owned,
                &request,
            )
            .map_err(|_| invalid("local prepared external lane"))?;
            let vote = decode_fast_vote(&prepared.vote)
                .map_err(|_| invalid("local prepared vote schema"))?;
            fast.verify_vote(&vote, &ReconstructionEd25519Verifier)
                .map_err(|_| invalid("local prepared vote signature"))?;
            if vote.tx_hash != prepared.signed_intent_digest
                || vote.execution_effects_hash != prepared.commitment
            {
                return Err(invalid("local prepared vote disagrees with record"));
            }
            prepared_material::verify_prepared_material(
                &view,
                &plan.operation_context,
                plan.domain,
                plan.resolver,
                plan.resolver_history,
                &prepared,
            )
            .map_err(|_| invalid("local prepared closure is missing or corrupt"))?;
            let witness_key: Vec<u8> =
                prepared_material::fastpath_prepared_witness_key(chain, &request)
                    .map_err(|_| invalid("prepared witness key"))?;
            let witness: &[u8] = view
                .rows
                .get(&witness_key)
                .and_then(|row| row.value.as_deref())
                .ok_or(invalid("prepared witness is absent"))?;
            let (_, required) = publication::witness::required_artifacts(witness)
                .map_err(|_| invalid("prepared witness operand schema"))?;
            excluded.insert(witness_key, ());
            for ((kind, _identity), digest) in required.iter() {
                let kind = consensus::bundle::ArtifactKind::from_u16(*kind)
                    .map_err(|_| invalid("prepared artifact kind"))?;
                excluded.insert(
                    prepared_material::fastpath_prepared_artifact_key(
                        chain, &request, kind, digest,
                    )
                    .map_err(|_| invalid("prepared artifact key"))?,
                    (),
                );
            }
            let internal: [u8; 32] = fastpath_synthetic_prepare_request_id(
                plan.resolver,
                prepared.context.epoch(),
                &request,
            )
            .map_err(|_| invalid("internal prepare receipt key"))?;
            if internal_receipts
                .insert(internal, prepared.commitment)
                .is_some()
            {
                return Err(invalid("duplicate internal prepare receipt identity"));
            }
            excluded.insert(key.clone(), ());
        } else if exact_tail(key, b"lock/", &encoded_chain, 32)?.is_some() {
            if let Some(bytes) = row.value.as_deref() {
                let lock = decode_fastpath_lock_record(bytes)
                    .map_err(|_| invalid("local object lock schema"))?;
                if fastpath_lock_key(chain, lock.object.id)
                    .map_err(|_| invalid("local object lock key"))?
                    != *key
                    || lock.locked_epoch != plan.genesis.context().epoch()
                    || is_reserved_paid_request_id(&lock.request_id)
                    || lock.request_id == [0; 32]
                {
                    return Err(invalid("local object lock key/epoch differs"));
                }
            }
            excluded.insert(key.clone(), ());
        } else if exact_tail(key, b"nonce-lock/", &encoded_chain, 40)?.is_some() {
            if let Some(bytes) = row.value.as_deref() {
                let lock = decode_fastpath_nonce_lock_record(bytes)
                    .map_err(|_| invalid("local nonce lock schema"))?;
                if fastpath_nonce_lock_key(chain, &lock.sender, lock.epoch)
                    .map_err(|_| invalid("local nonce lock key"))?
                    != *key
                    || lock.epoch != plan.genesis.context().epoch()
                    || is_reserved_paid_request_id(&lock.request_id)
                    || lock.request_id == [0; 32]
                {
                    return Err(invalid("local nonce lock key/epoch differs"));
                }
            }
            excluded.insert(key.clone(), ());
        } else if let Some(tail) = exact_tail(key, b"availability-ack/", &encoded_chain, 32)? {
            let ack = publication::decode_fastpath_availability_ack_record(
                row.value
                    .as_deref()
                    .ok_or(invalid("deleted availability ACK"))?,
            )
            .map_err(|_| invalid("local availability ACK schema"))?;
            let identity = decode_availability_identity(&ack.identity)
                .map_err(|_| invalid("local availability identity"))?;
            let vote = decode_availability_vote(&ack.vote)
                .map_err(|_| invalid("local availability vote"))?;
            if identity.request_id.as_slice() != tail
                || vote.identity != identity
                || identity.domain != plan.domain
            {
                return Err(invalid("local availability key/identity differs"));
            }
            availability
                .verify_vote(&vote, &ReconstructionEd25519Verifier)
                .map_err(|_| invalid("local availability vote signature"))?;
            excluded.insert(key.clone(), ());
        } else if key
            .strip_prefix(FASTPATH_STATE_PREFIX)
            .is_some_and(|suffix| suffix.starts_with(b"drain-lock-resolution/"))
        {
            let resolution = crate::fast_path::drain_apply::decode_drain_lock_resolution_record(
                row.value
                    .as_deref()
                    .ok_or(invalid("deleted drain lock resolution"))?,
            )
            .map_err(|_| invalid("local drain lock resolution schema"))?;
            if crate::fast_path::drain_apply::drain_lock_resolution_key(
                chain,
                resolution.epoch,
                &resolution.resolving_request_id,
                &resolution.resolved_key,
            )
            .map_err(|_| invalid("drain resolution key"))?
                != *key
                || resolution.epoch != plan.genesis.context().epoch()
            {
                return Err(invalid("local drain resolution key differs"));
            }
            excluded.insert(key.clone(), ());
        }
    }
    // A backing witness/artifact is excluded only when a typed prepared row
    // independently verified its exact required closure. Orphans stay visible
    // and necessarily fail equality against independently produced business.
    Ok((excluded, internal_receipts))
}

fn capture_overlay(
    overlay: &BusinessReconstructionOverlay<'_>,
) -> Result<SourceBusinessSnapshot, BusinessReconstructionError> {
    let plan = &overlay.plan;
    let token: PortableSnapshotToken = overlay
        .store
        .begin_portable_snapshot(&plan.operation_context, plan.domain)
        .map_err(|_| invalid("private snapshot capture failed"))?;
    let mut records: Vec<SourceSnapshotRecord> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan = DurableRecordScan::new(
                collection,
                after,
                NonZeroUsize::new(MAX_PORTABLE_PAGE_KEYS).ok_or(invalid("page bound"))?,
            )
            .map_err(|_| invalid("private scan shape"))?;
            let page = overlay
                .store
                .scan_portable_keys_at(&plan.operation_context, plan.domain, &token, &scan)
                .map_err(|_| invalid("private scan failed"))?;
            for key in page.keys() {
                let descriptor = overlay
                    .store
                    .read_portable_descriptor_at(&plan.operation_context, plan.domain, &token, key)
                    .map_err(|_| invalid("private descriptor failed"))?
                    .ok_or(invalid("private enumerated record disappeared"))?;
                let mut value: Option<Vec<u8>> = descriptor.payload_length().map(|_| Vec::new());
                if let Some(length) = descriptor.payload_length() {
                    let mut offset: usize = 0;
                    while offset < length {
                        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(length - offset);
                        let request = DurableRecordChunkRequest::new(
                            descriptor.clone(),
                            offset,
                            NonZeroUsize::new(count).ok_or(invalid("private chunk bound"))?,
                        )
                        .map_err(|_| invalid("private chunk shape"))?;
                        let DurableRecordChunkOutcome::Chunk(chunk) = overlay
                            .store
                            .read_portable_chunk_at(
                                &plan.operation_context,
                                plan.domain,
                                &token,
                                &request,
                            )
                            .map_err(|_| invalid("private chunk failed"))?
                        else {
                            return Err(invalid("private descriptor changed"));
                        };
                        if chunk.request() != &request || chunk.bytes().len() != count {
                            return Err(invalid("private chunk differs"));
                        }
                        value
                            .as_mut()
                            .ok_or(invalid("private payload shape"))?
                            .extend_from_slice(chunk.bytes());
                        offset = offset
                            .checked_add(count)
                            .ok_or(invalid("private chunk overflow"))?;
                    }
                }
                records.push(SourceSnapshotRecord { descriptor, value });
            }
            let Some(next) = page.continuation() else {
                break;
            };
            after = Some(next.clone());
        }
    }
    let mut result: SourceBusinessSnapshot = SourceBusinessSnapshot {
        token,
        records,
        referenced_blobs: BTreeMap::new(),
    };
    for (digest, maximum) in super::referenced_blob_bounds(&result)? {
        let bytes: Vec<u8> = overlay
            .blobs
            .get_blob(&digest)
            .map_err(|_| invalid("private referenced blob read failed"))?
            .ok_or(invalid("private referenced blob is absent"))?;
        if bytes.len() > maximum {
            return Err(invalid(
                "private referenced blob exceeds owning-schema bound",
            ));
        }
        result.referenced_blobs.insert(digest, bytes);
    }
    result.validate()?;
    Ok(result)
}

fn normalized_state(
    overlay: &BusinessReconstructionOverlay<'_>,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, BusinessReconstructionError> {
    let Some(bytes) = value else {
        return Ok(None);
    };
    let expected = overlay.plan.genesis.context();
    if genesis_marker_key(expected).map_err(|_| invalid("genesis marker key"))? == key {
        let mut marker =
            decode_genesis_install_marker(bytes).map_err(|_| invalid("genesis marker schema"))?;
        if marker.context != *expected
            || marker.manifest_digest != overlay.genesis_digest
            || marker.genesis_authority != overlay.plan.genesis.genesis_authority
        {
            return Err(invalid("genesis marker differs from independent pin"));
        }
        // This coordinate is local installation bookkeeping, never a signed
        // generation or a historical transition's hash-linked checkpoint.
        marker.installed_at_checkpoint = 0;
        return encode_genesis_install_marker(&marker)
            .map(Some)
            .map_err(|_| invalid("genesis marker projection"));
    }
    if fastpath_epoch_record_key(expected.chain_id()).map_err(|_| invalid("genesis epoch key"))?
        == key
    {
        let mut epoch =
            decode_fastpath_epoch_record(bytes).map_err(|_| invalid("epoch record schema"))?;
        if epoch.current_epoch != expected.epoch() || epoch.previous_epoch.is_some() {
            // There is no implicit import/activation in this fixed outgoing
            // profile. A genuine transition requires its separate history.
            return Err(invalid(
                "source epoch advanced outside reconstruction target",
            ));
        }
        let set_digest: Digest32 = overlay
            .plan
            .ordered_policy
            .engine()
            .validator_set()
            .digest(overlay.plan.resolver)
            .map_err(|_| invalid("genesis set digest"))?;
        if epoch.current_validator_set_digest != set_digest {
            return Err(invalid("genesis epoch committee differs"));
        }
        // Only the genesis activation has no preceding hash-linked transition.
        // Never normalize this field on a post-genesis transition record.
        epoch.activated_at_checkpoint = 0;
        return encode_fastpath_epoch_record(&epoch)
            .map(Some)
            .map_err(|_| invalid("genesis epoch projection"));
    }
    Ok(Some(bytes.to_vec()))
}

fn project(
    overlay: &BusinessReconstructionOverlay<'_>,
    snapshot: &SourceBusinessSnapshot,
    reconstructed_state: &StateRows<'_>,
    is_source: bool,
) -> Result<SemanticProjection, BusinessReconstructionError> {
    snapshot.validate()?;
    let (local_rows, mut internal_receipts) = local_fastpath_rows(overlay, &snapshot.records)?;
    let ordered = crate::ordered_economics::audit_projection::validate_local_rows(
        overlay.plan.ordered_policy,
        overlay.plan.ordered_history_identity,
        overlay.plan.resolver,
        &snapshot.records,
        reconstructed_state.keys().cloned().collect(),
        is_source,
    )
    .map_err(|_| invalid("source local ordered key/schema/proof differs"))?;
    for (request, digest) in ordered.internal_receipts {
        if internal_receipts.insert(request, digest).is_some() {
            return Err(invalid("internal admission receipt identity collision"));
        }
    }
    let mut projected: SemanticProjection = BTreeMap::new();
    for row in &snapshot.records {
        let key = row.descriptor.key();
        let fact: SemanticRecord = match (key, row.descriptor.metadata()) {
            (DurableRecordKey::State(key), DurableRecordMetadata::State { .. }) => {
                if local_rows.contains_key(key) || ordered.excluded.contains(key) {
                    continue;
                }
                SemanticRecord::State(normalized_state(overlay, key, row.value.as_deref())?)
            }
            (
                DurableRecordKey::Receipt(request),
                DurableRecordMetadata::Receipt { event_digest, .. },
            ) => {
                let bytes: &[u8] = row
                    .value
                    .as_deref()
                    .ok_or(invalid("missing receipt body"))?;
                if is_reserved_paid_request_id(request.as_bytes()) {
                    let receipt = NodeDedupRecord::decode(bytes)
                        .map_err(|_| invalid("internal receipt schema"))?;
                    if internal_receipts.get(request.as_bytes()) != Some(event_digest)
                        || !receipt.responses().is_empty()
                    {
                        return Err(invalid("unexplained internal admission receipt"));
                    }
                    continue;
                }
                SemanticRecord::Receipt(*event_digest, bytes.to_vec())
            }
            (DurableRecordKey::ObjectHead(_), DurableRecordMetadata::ObjectHead(head)) => {
                match head {
                    DurableObjectHead::Absent => {
                        return Err(invalid("persisted virgin object head"));
                    }
                    DurableObjectHead::Tombstoned {
                        last_object_version,
                        ..
                    } => SemanticRecord::Head {
                        live: false,
                        version: last_object_version.get(),
                        digest: None,
                        owner: None,
                        routing: None,
                    },
                    DurableObjectHead::Current {
                        object_version,
                        digest,
                        owner_projection,
                        routing_projection,
                        ..
                    } => SemanticRecord::Head {
                        live: true,
                        version: object_version.get(),
                        digest: Some(*digest),
                        owner: owner_projection.bytes().map(<[u8]>::to_vec),
                        routing: routing_projection.bytes().map(<[u8]>::to_vec),
                    },
                }
            }
            (
                DurableRecordKey::ObjectVersion(object_id, version),
                DurableRecordMetadata::ObjectVersion {
                    digest,
                    schema_version,
                    provenance,
                    payload,
                    ..
                },
            ) => {
                let bytes: Vec<u8> = match payload {
                    DurablePayloadDescriptor::Inline(_) => row
                        .value
                        .clone()
                        .ok_or(invalid("inline object body is absent"))?,
                    DurablePayloadDescriptor::BlobReference(blob) => {
                        let bytes: Vec<u8> = snapshot
                            .referenced_blobs
                            .get(blob)
                            .ok_or(invalid("referenced object body is absent"))?
                            .clone();
                        if !hashing::verify_digest(
                            blob,
                            HashPurpose::Object,
                            provenance.protocol_version(),
                            provenance.chain_id(),
                            &bytes,
                        )
                        .map_err(|_| invalid("referenced blob digest verification failed"))?
                        {
                            return Err(invalid("referenced object blob digest differs"));
                        }
                        bytes
                    }
                };
                let object = objects::decode_object(&bytes)
                    .map_err(|_| invalid("object-version body schema"))?;
                if object.id != *object_id
                    || object.version != version.get()
                    || object.schema_version != *schema_version
                    || provenance.chain_id() != overlay.plan.genesis.context().chain_id()
                    || !hashing::verify_digest(
                        digest,
                        HashPurpose::Object,
                        provenance.protocol_version(),
                        provenance.chain_id(),
                        &bytes,
                    )
                    .map_err(|_| invalid("object digest verification failed"))?
                {
                    return Err(invalid("object-version identity/digest/provenance differs"));
                }
                SemanticRecord::ObjectVersion {
                    digest: *digest,
                    schema: *schema_version,
                    provenance: provenance.clone(),
                    payload: *payload,
                    bytes,
                }
            }
            _ => return Err(invalid("unrecognized portable semantic schema")),
        };
        if projected.insert(key.clone(), fact).is_some() {
            return Err(invalid("duplicate semantic projection key"));
        }
    }
    Ok(projected)
}

pub(super) fn compare_source(
    overlay: &BusinessReconstructionOverlay<'_>,
    source: &SourceBusinessSnapshot,
) -> Result<(), BusinessReconstructionError> {
    if source.token.domain() != overlay.plan.domain {
        return Err(invalid("source snapshot belongs to another domain"));
    }
    let reconstructed: SourceBusinessSnapshot = capture_overlay(overlay)?;
    let reconstructed_state: StateRows<'_> = state_rows(&reconstructed.records);
    let actual: SemanticProjection = project(overlay, source, &reconstructed_state, true)?;
    let expected: SemanticProjection =
        project(overlay, &reconstructed, &reconstructed_state, false)?;
    if actual != expected {
        return Err(invalid(
            "complete source semantic projection differs from independent reconstruction",
        ));
    }
    Ok(())
}
