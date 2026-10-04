//! Private, causal business reconstruction from signed genesis.
//!
//! Source rows and ordered-history completion companions are comparison data,
//! never replay authority. The only replay target owned by this module is a
//! fresh `MemoryDurableStateStore` initialized from locally pinned genesis.
//! Inactive installation is a separate opaque private-plan capability. Neither
//! reconstruction nor installation grants activation or readiness authority.

pub mod control;
pub mod cut;
mod dependency_graph;
pub mod inactive_import;
mod projection;
mod root_policy_binding;

pub use control::{
    DrainSetControlMaterial, DrainSetControlProofError, DrainSetSignerFrontierMaterial,
    drain_control_material_from_source_snapshot,
};

use self::root_policy_binding::{
    RootAnchorBindingError, require_configuration, require_root_anchor,
};
use crate::NodeDedupRecord;
use crate::fast_path::drain_publication::{drain_publication_artifact_key, drain_publication_key};
use crate::fast_path::publication::witness::{
    DecodedLogicalWitness, DecodedObjectHeadObservation, DecodedObjectMutationKind,
};
use crate::fast_path::publication::{
    FastPathPublicationRecord, decode_fastpath_publication_record,
    fastpath_publication_artifact_key, fastpath_publication_key,
};
use crate::fast_path::records::{
    FastPathAvailabilityCertificateRecord, FastPathCertificateRecord,
    decode_fastpath_availability_certificate_record, decode_fastpath_settlement_record,
    fastpath_availability_certificate_key,
};
use crate::genesis::{GenesisInstallOutcome, VerifiedGenesisRoot};
use crate::local_instance_state::fastpath_certificate_key;
use crate::logical_generation::{
    LogicalKeySpace, LogicalObservation, LogicalProvenanceRecord, LogicalSubject,
    decode_logical_profile_record, decode_logical_provenance_record, logical_profile_key,
};
use crate::ordered_economics::{
    OrderedEconomicsEnvironment, OrderedEconomicsError, OrderedEconomicsPolicy,
    OrderedHistoryComponentKind, OrderedHistoryHeightMaterial, OrderedHistoryIdentity,
    OrderedHistoryVerifier, OrderedOperationKind, decode_ordered_candidate,
};
use crate::serving_authority::{
    ReconstructionBase, ServingGate, VerifiedCommitteeHistory, VerifiedOwnerRegistry,
};
use crate::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, genesis};
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use consensus::bundle::{
    ArtifactKind, LOGICAL_COMMITMENT_PROFILE, PublicationBundle, decode_artifact_manifest,
    encode_artifact_manifest, verify_publication_bundle,
};
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, AvailabilityIdentity, ConsensusVerifier,
    FastCertificate, FastPathCertifier, decode_availability_certificate, decode_fast_certificate,
    encode_availability_identity, encode_fast_certificate,
};
use crypto::{Ed25519Verifier, SignatureVerifier};
use execution::{
    local_execution::{LocalContractEngine, LocalExecutionPolicy},
    paid_execution::PaidContractEngine,
};
use hashing::HashSuiteResolver;
use protocol_types::ExecutionGeneration;
use protocol_types::{Digest32, Epoch, HashPurpose, SignatureSchemeId, ValidatorId};
use runtime::portable::{
    DurablePayloadDescriptor, DurableRecordDescriptor, DurableRecordKey, DurableRecordMetadata,
    PortableSnapshotToken,
};
use runtime::{
    AtomicityDomainId, DurableDomainStateStore, DurableObjectHead, DurableOperationContext,
    MemoryBlobStore, MemoryDurableStateStore, PersistenceLayout, StateMutation, StateRevision,
    StructuredDurableDomainStateStore,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use validator_set::ValidatorSet;

/// One complete authenticated-publication candidate supplied to reconstruction.
/// Every field remains untrusted until the overlay independently verifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedPublicationMaterial {
    /// Exact original signed intent, certificate, witness, manifest and bodies.
    pub bundle: PublicationBundle,
    /// Exact source-retained availability quorum certificate for an ordinary
    /// application. Absence also permits a completed frozen member, but only
    /// the independently committed DrainSet can authorize its replay.
    pub availability_certificate: Option<Vec<u8>>,
    /// Comparison-target hint derived from source certificate/receipt rows; it
    /// is never authority to apply or accept an outcome.
    pub source_application_present: bool,
    /// Local recovery coordinate, used only by existing apply logic. Under the
    /// logical witness profile it is not a signed semantic generation.
    pub recovery_created_checkpoint: u64,
}

/// One record from a single backend-enforced four-collection source snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshotRecord {
    /// Exact key plus physical descriptor captured under the snapshot token.
    pub descriptor: DurableRecordDescriptor,
    /// Exact State/Receipt/inline object-version bytes; `None` for head rows,
    /// blob-backed object versions, or a physical tombstone.
    pub value: Option<Vec<u8>>,
}

/// Complete structured rows and only the source's referenced blob closure.
/// The token is local continuity evidence, not a portable state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBusinessSnapshot {
    /// The exact backend-local snapshot token used for all records and blobs.
    pub token: PortableSnapshotToken,
    /// Strictly unique records covering State, Receipts, ObjectHeads and
    /// ObjectVersions. Callers must prove collection enumeration completed.
    pub records: Vec<SourceSnapshotRecord>,
    /// Bounded bytes for every blob referenced by an object-version row.
    pub referenced_blobs: BTreeMap<Digest32, Vec<u8>>,
}

impl SourceBusinessSnapshot {
    /// Validates exact descriptor/value shape, uniqueness, and the complete
    /// bounded blob closure. Enumeration completeness itself is supplied by
    /// the snapshot backend/capture owner, not inferred from this vector.
    pub fn validate(&self) -> Result<(), BusinessReconstructionError> {
        let mut keys: BTreeSet<DurableRecordKey> = BTreeSet::new();
        for record in &self.records {
            let key: &DurableRecordKey = record.descriptor.key();
            if !keys.insert(key.clone()) {
                return Err(BusinessReconstructionError::Duplicate(
                    "duplicate portable structured key",
                ));
            }
            match (record.descriptor.metadata(), key, &record.value) {
                (
                    DurableRecordMetadata::State { value_length, .. },
                    DurableRecordKey::State(_),
                    value,
                ) if value.as_ref().map(Vec::len) == *value_length => {}
                (
                    DurableRecordMetadata::Receipt {
                        event_digest,
                        length,
                    },
                    DurableRecordKey::Receipt(request_id),
                    Some(bytes),
                ) if bytes.len() == length.get() => {
                    let receipt: NodeDedupRecord = NodeDedupRecord::decode(bytes)
                        .map_err(|_| invalid("source receipt canonical decoding failed"))?;
                    if receipt.request_id().as_bytes() != request_id.as_bytes()
                        || receipt.event_digest() != *event_digest
                    {
                        return Err(invalid("source receipt descriptor linkage differs"));
                    }
                }
                (DurableRecordMetadata::ObjectHead(_), DurableRecordKey::ObjectHead(_), None) => {}
                (
                    DurableRecordMetadata::ObjectVersion { .. },
                    DurableRecordKey::ObjectVersion(_, _),
                    _,
                ) => {}
                _ => return Err(invalid("portable descriptor/value shape mismatch")),
            }
        }
        let bounds: ReferencedBlobBounds = referenced_blob_bounds(self)?;
        if bounds.len() != self.referenced_blobs.len() {
            return Err(invalid("source referenced blob closure is incomplete"));
        }
        for (digest, maximum) in &bounds {
            let bytes: &Vec<u8> = self.referenced_blobs.get(digest).ok_or(
                BusinessReconstructionError::Incomplete("referenced object body is missing"),
            )?;
            if bytes.len() > *maximum {
                return Err(invalid(
                    "referenced object body exceeds owning-schema bound",
                ));
            }
        }
        Ok(())
    }
}

/// A per-digest allocation ceiling derived from the owning object schema.
pub type ReferencedBlobBounds = BTreeMap<Digest32, usize>;

/// Strictly derives the portable object-body closure and its existing schema
/// bounds. It does not trust a `PortableBlobDescriptor` length or hash.
pub fn referenced_blob_bounds(
    snapshot: &SourceBusinessSnapshot,
) -> Result<ReferencedBlobBounds, BusinessReconstructionError> {
    let mut bounds: ReferencedBlobBounds = BTreeMap::new();
    for record in &snapshot.records {
        let descriptor: &DurableRecordDescriptor = &record.descriptor;
        if let DurableRecordKey::ObjectVersion(_, _) = descriptor.key() {
            match (descriptor.metadata(), &record.value) {
                (
                    DurableRecordMetadata::ObjectVersion {
                        payload: DurablePayloadDescriptor::BlobReference(digest),
                        ..
                    },
                    None,
                ) => {
                    bounds.insert(*digest, MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
                }
                (
                    DurableRecordMetadata::ObjectVersion {
                        payload: DurablePayloadDescriptor::Inline(length),
                        ..
                    },
                    Some(bytes),
                ) if length.get() == bytes.len() => {}
                (
                    DurableRecordMetadata::ObjectVersion {
                        payload: DurablePayloadDescriptor::Inline(_),
                        ..
                    },
                    _,
                ) => {
                    return Err(invalid(
                        "object version inline payload disagrees with descriptor",
                    ));
                }
                _ => return Err(invalid("object version descriptor schema mismatch")),
            }
        }
    }
    for digest in snapshot.referenced_blobs.keys() {
        if !bounds.contains_key(digest) {
            return Err(invalid("snapshot contains an unreferenced blob"));
        }
    }
    Ok(bounds)
}

/// Returns the exact set of referenced blob identities after validating the
/// descriptor-derived closure and rejecting unreferenced supplied bytes.
pub fn referenced_blob_digests(
    snapshot: &SourceBusinessSnapshot,
) -> Result<BTreeSet<Digest32>, BusinessReconstructionError> {
    Ok(referenced_blob_bounds(snapshot)?.into_keys().collect())
}

/// All trusted composition inputs required to replay existing handlers.
/// Engines and policies are borrowed, while the operation context is copied
/// only into an isolated memory store. No source-store handle is accepted.
pub struct BusinessReconstructionPlan<'a> {
    /// One immutable verified genesis root (DR-0182): its manifest, digest,
    /// admission profile, original committee and resolver are already
    /// mutually consistent, so this plan no longer carries those as
    /// independently supplied values that could disagree with each other.
    pub genesis_root: &'a VerifiedGenesisRoot,
    /// Operational context used only for the private memory store.
    pub operation_context: DurableOperationContext,
    /// Fixed logical atomicity domain.
    pub domain: AtomicityDomainId,
    /// Locally trusted historical resolver schedule.
    pub resolver_history: &'a [HashSuiteResolver],
    /// Fixed ordered-consensus authority derived from this genesis.
    pub ordered_policy: &'a OrderedEconomicsPolicy,
    /// Independently fixed ordered-history identity from the saved archive.
    /// A source-advertised summary cannot replace or widen this target.
    pub ordered_history_identity: &'a OrderedHistoryIdentity,
    /// Existing deterministic local execution policy for embedded ordered legs.
    pub ordered_leg_policy: &'a LocalExecutionPolicy,
    /// Existing deterministic local contract engine for embedded ordered legs.
    pub ordered_engine: &'a dyn LocalContractEngine,
    /// Existing deterministic paid execution policy for owned operations.
    pub paid_base_policy: &'a LocalExecutionPolicy,
    /// Existing deterministic paid execution engine.
    pub paid_engine: &'a dyn PaidContractEngine,
}

/// Reconstructs complete retained owned publications from the exact source
/// snapshot. Normal and DrainSet publication rows are aliases for one logical
/// availability identity; every artifact row must be accounted for exactly.
/// Source application rows only set a replay-target hint and are never applied
/// without independent execution and later semantic comparison.
pub fn owned_material_from_source_snapshot(
    snapshot: &SourceBusinessSnapshot,
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<Vec<OwnedPublicationMaterial>, BusinessReconstructionError> {
    snapshot.validate()?;
    if snapshot.token.domain() != plan.domain {
        return Err(invalid("source snapshot belongs to another domain"));
    }
    for (digest, bytes) in &snapshot.referenced_blobs {
        let body_valid: bool = hashing::verify_digest(
            digest,
            HashPurpose::Object,
            plan.ordered_policy.context().protocol_version(),
            plan.ordered_policy.context().chain_id(),
            bytes,
        )
        .map_err(|_| invalid("referenced source object blob hash is not verifiable"))?;
        if !body_valid {
            return Err(invalid("referenced source object blob digest mismatch"));
        }
    }
    let mut state: BTreeMap<Vec<u8>, &[u8]> = BTreeMap::new();
    for record in &snapshot.records {
        if let (DurableRecordKey::State(key), Some(bytes)) =
            (record.descriptor.key(), record.value.as_deref())
        {
            state.insert(key.clone(), bytes);
        }
    }
    let chain = plan.ordered_policy.context().chain_id();
    let mut normal: BTreeMap<[u8; 32], FastPathPublicationRecord> = BTreeMap::new();
    let mut drain: BTreeMap<[u8; 32], FastPathPublicationRecord> = BTreeMap::new();
    let mut expected_artifacts: BTreeSet<Vec<u8>> = BTreeSet::new();

    let normal_prefix: Vec<u8> = [
        crate::local_instance_state::FASTPATH_STATE_PREFIX,
        b"publication/",
    ]
    .concat();
    let drain_prefix: Vec<u8> = [
        crate::local_instance_state::FASTPATH_STATE_PREFIX,
        b"drain-publication/",
    ]
    .concat();
    for record in &snapshot.records {
        let DurableRecordKey::State(key) = record.descriptor.key() else {
            continue;
        };
        let Some(bytes) = record.value.as_deref() else {
            if key.starts_with(&normal_prefix) || key.starts_with(&drain_prefix) {
                return Err(invalid("retained publication is tombstoned"));
            }
            continue;
        };
        let target = if key.starts_with(&normal_prefix) {
            Some(false)
        } else if key.starts_with(&drain_prefix) {
            Some(true)
        } else {
            None
        };
        let Some(imported) = target else { continue };
        let retained: FastPathPublicationRecord = decode_fastpath_publication_record(bytes)
            .map_err(|_| invalid("retained publication record decoding failed"))?;
        if retained.context != *plan.ordered_policy.context() {
            return Err(invalid(
                "retained publication context differs from pinned genesis",
            ));
        }
        let expected_key: Vec<u8> = if imported {
            drain_publication_key(chain, retained.context.epoch(), &retained.request_id)
                .map_err(|_| invalid("DrainSet publication key derivation failed"))?
        } else {
            fastpath_publication_key(chain, &retained.request_id)
                .map_err(|_| invalid("publication key derivation failed"))?
        };
        if key != &expected_key {
            return Err(invalid(
                "retained publication key does not bind record identity",
            ));
        }
        let manifest = decode_artifact_manifest(&retained.manifest)
            .map_err(|_| invalid("retained publication manifest is malformed"))?;
        for entry in &manifest.entries {
            let artifact_key: Vec<u8> = if imported {
                drain_publication_artifact_key(
                    chain,
                    retained.context.epoch(),
                    &retained.request_id,
                    entry,
                )
                .map_err(|_| invalid("DrainSet artifact key derivation failed"))?
            } else {
                fastpath_publication_artifact_key(
                    chain,
                    &retained.request_id,
                    entry.kind,
                    &entry.content_digest.bytes(),
                )
                .map_err(|_| invalid("artifact key derivation failed"))?
            };
            expected_artifacts.insert(artifact_key);
        }
        let family: &mut BTreeMap<[u8; 32], FastPathPublicationRecord> =
            if imported { &mut drain } else { &mut normal };
        if family.insert(retained.request_id, retained).is_some() {
            return Err(BusinessReconstructionError::Duplicate(
                "retained publication identity",
            ));
        }
    }

    let normal_artifact_prefix: Vec<u8> = [
        crate::local_instance_state::FASTPATH_STATE_PREFIX,
        b"publication-artifact/",
    ]
    .concat();
    let drain_artifact_prefix: Vec<u8> = [
        crate::local_instance_state::FASTPATH_STATE_PREFIX,
        b"drain-publication-artifact/",
    ]
    .concat();
    for key in state.keys() {
        if (key.starts_with(&normal_artifact_prefix) || key.starts_with(&drain_artifact_prefix))
            && !expected_artifacts.contains(key)
        {
            return Err(invalid("orphan retained publication artifact"));
        }
    }
    if expected_artifacts
        .iter()
        .any(|key| !state.contains_key(key))
    {
        return Err(BusinessReconstructionError::Incomplete(
            "retained publication artifact is missing",
        ));
    }

    // The root already validated the original committee (DR-0182); no
    // independent reconstruction from the manifest's raw validator-set
    // record is needed or trusted here.
    let validator_set: ValidatorSet = plan.ordered_policy.engine().validator_set().clone();
    let fast_certifier: FastPathCertifier = FastPathCertifier::new(
        chain.clone(),
        plan.ordered_policy.context().protocol_version(),
        plan.ordered_policy.context().epoch(),
        validator_set.clone(),
    )
    .map_err(|_| invalid("signed genesis FastVote authority is malformed"))?;
    let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        chain.clone(),
        plan.ordered_policy.context().protocol_version(),
        plan.ordered_policy.context().epoch(),
        validator_set,
    )
    .map_err(|_| invalid("signed genesis availability authority is malformed"))?;
    let verifier: ReconstructionEd25519Verifier = ReconstructionEd25519Verifier;
    let mut output: Vec<OwnedPublicationMaterial> = Vec::with_capacity(normal.len() + drain.len());
    let ids: BTreeSet<[u8; 32]> = normal.keys().chain(drain.keys()).copied().collect();
    let mut consumed_normal: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut consumed_drain: BTreeSet<[u8; 32]> = BTreeSet::new();
    for request_id in ids {
        let normal_record: Option<&FastPathPublicationRecord> = normal.get(&request_id);
        let drain_record: Option<&FastPathPublicationRecord> = drain.get(&request_id);
        let selected: &FastPathPublicationRecord =
            normal_record
                .or(drain_record)
                .ok_or(BusinessReconstructionError::Incomplete(
                    "publication alias vanished",
                ))?;
        let selected_is_drain_only: bool = normal_record.is_none();
        let bundle: PublicationBundle =
            bundle_from_retained_record(selected, selected_is_drain_only, &state, plan)?;
        let verified = verify_publication_bundle(
            &bundle,
            &fast_certifier,
            &verifier,
            plan.genesis_root.genesis_resolver(),
            plan.resolver_history,
        )
        .map_err(|_| invalid("retained publication certificate or artifact closure failed"))?;
        if verified.identity.domain != plan.domain
            || verified.identity.request_id != request_id
            || selected.identity
                != encode_availability_identity(&verified.identity)
                    .map_err(|_| invalid("publication identity encoding failed"))?
        {
            return Err(invalid("retained publication identity differs from bundle"));
        }
        let (witness_event, required) =
            crate::fast_path::publication::witness::required_artifacts(&bundle.witness)
                .map_err(|_| invalid("retained publication witness is malformed"))?;
        if witness_event != bundle.certificate.tx_hash {
            return Err(invalid("publication witness is not bound to certificate"));
        }
        required
            .require_closed(&bundle.manifest)
            .map_err(|_| invalid("retained publication does not close witness artifacts"))?;
        if let Some(other) = drain_record.filter(|_| normal_record.is_some()) {
            if other.context != selected.context
                || other.request_id != selected.request_id
                || other.identity != selected.identity
                || other.signed_intent != selected.signed_intent
                || other.witness != selected.witness
                || other.manifest != selected.manifest
            {
                return Err(invalid("normal and DrainSet publication aliases conflict"));
            }
            let alias_bundle: PublicationBundle =
                bundle_from_retained_record(other, true, &state, plan)?;
            let alias_verified = verify_publication_bundle(
                &alias_bundle,
                &fast_certifier,
                &verifier,
                plan.genesis_root.genesis_resolver(),
                plan.resolver_history,
            )
            .map_err(|_| invalid("DrainSet publication alias proof failed"))?;
            if alias_verified.identity != verified.identity
                || alias_bundle.contents != bundle.contents
            {
                return Err(invalid("normal and DrainSet publication aliases disagree"));
            }
        }
        if normal_record.is_some() {
            consumed_normal.insert(request_id);
        }
        if drain_record.is_some() {
            consumed_drain.insert(request_id);
        }

        let certificate_key =
            crate::local_instance_state::fastpath_certificate_key(chain, &request_id)
                .map_err(|_| invalid("application certificate key derivation failed"))?;
        let witness_key =
            crate::local_instance_state::fastpath_commitment_witness_key(chain, &request_id)
                .map_err(|_| invalid("application witness key derivation failed"))?;
        let settlement_key =
            crate::local_instance_state::fastpath_settlement_key(chain, &request_id)
                .map_err(|_| invalid("settlement key derivation failed"))?;
        let availability_key = fastpath_availability_certificate_key(chain, &request_id)
            .map_err(|_| invalid("availability certificate key derivation failed"))?;
        let receipt_key = DurableRecordKey::Receipt(
            runtime::DurableRequestId::new(request_id)
                .map_err(|_| invalid("original request id is invalid"))?,
        );
        let receipt: Option<&SourceSnapshotRecord> = snapshot
            .records
            .iter()
            .find(|row| row.descriptor.key() == &receipt_key);
        let completion_presence: [bool; 4] = [
            state.contains_key(&certificate_key),
            state.contains_key(&witness_key),
            state.contains_key(&settlement_key),
            receipt.is_some_and(|row| row.value.is_some()),
        ];
        let applied: bool = completion_presence.iter().all(|present| *present);
        let has_availability: bool = state.contains_key(&availability_key);
        let completion_keys: [&Vec<u8>; 4] = [
            &certificate_key,
            &witness_key,
            &settlement_key,
            &availability_key,
        ];
        if snapshot.records.iter().any(|row| {
            matches!(row.descriptor.key(), DurableRecordKey::State(key)
                if completion_keys.contains(&key) && row.value.is_none())
        }) {
            return Err(invalid("owned application companion is tombstoned"));
        }
        if (completion_presence.iter().any(|present| *present) || has_availability) && !applied {
            return Err(invalid(
                "owned application records are only partially retained",
            ));
        }
        if applied && !has_availability && drain_record.is_none() {
            return Err(invalid(
                "completed publication without availability has no frozen carrier",
            ));
        }
        let availability_certificate: Option<Vec<u8>> = if applied {
            let cert_record: FastPathCertificateRecord =
                crate::fast_path::records::decode_fastpath_certificate_record(
                    state[&certificate_key],
                )
                .map_err(|_| invalid("applied certificate record malformed"))?;
            if cert_record.request_id != request_id {
                return Err(invalid("applied certificate request linkage differs"));
            }
            let applied_certificate: FastCertificate =
                decode_fast_certificate(&cert_record.certificate)
                    .map_err(|_| invalid("applied FastCertificate malformed"))?;
            fast_certifier
                .verify_certificate(&applied_certificate, &verifier)
                .map_err(|_| invalid("applied FastCertificate authentication failed"))?;
            if applied_certificate.tx_hash != bundle.certificate.tx_hash
                || applied_certificate.execution_effects_hash
                    != bundle.certificate.execution_effects_hash
                || applied_certificate.locked_objects_digest
                    != bundle.certificate.locked_objects_digest
            {
                return Err(invalid(
                    "applied FastCertificate differs from retained publication",
                ));
            }
            if state.get(&witness_key).copied() != Some(bundle.witness.as_slice()) {
                return Err(invalid("applied witness differs from retained publication"));
            }
            let settlement = decode_fastpath_settlement_record(state[&settlement_key])
                .map_err(|_| invalid("applied settlement record malformed"))?;
            if settlement.request_id != request_id
                || settlement.context != *plan.ordered_policy.context()
            {
                return Err(invalid("applied settlement linkage differs"));
            }
            let availability_bytes: Option<Vec<u8>> = if has_availability {
                let availability_record: FastPathAvailabilityCertificateRecord =
                    decode_fastpath_availability_certificate_record(state[&availability_key])
                        .map_err(|_| invalid("availability certificate record malformed"))?;
                if availability_record.request_id != request_id {
                    return Err(invalid("availability certificate request linkage differs"));
                }
                let certificate: AvailabilityCertificate =
                    decode_availability_certificate(&availability_record.certificate)
                        .map_err(|_| invalid("availability certificate malformed"))?;
                if certificate.identity != verified.identity {
                    return Err(invalid("availability certificate identity differs"));
                }
                availability_certifier
                    .verify_certificate(&certificate, &verifier)
                    .map_err(|_| invalid("availability certificate authentication failed"))?;
                Some(availability_record.certificate)
            } else {
                None
            };
            let original_receipt: &SourceSnapshotRecord = receipt.unwrap();
            let DurableRecordKey::Receipt(original_id) = original_receipt.descriptor.key() else {
                return Err(invalid("original receipt key shape changed"));
            };
            let receipt_bytes: &[u8] = original_receipt
                .value
                .as_deref()
                .ok_or(invalid("original receipt body missing"))?;
            let dedup: NodeDedupRecord = NodeDedupRecord::decode(receipt_bytes)
                .map_err(|_| invalid("original receipt malformed"))?;
            if dedup.request_id().as_bytes() != original_id.as_bytes()
                || dedup.event_digest() != bundle.certificate.tx_hash
            {
                return Err(invalid("original receipt linkage differs from publication"));
            }
            availability_bytes
        } else {
            None
        };
        output.push(OwnedPublicationMaterial {
            bundle,
            availability_certificate,
            source_application_present: applied,
            recovery_created_checkpoint: 0,
        });
    }
    if consumed_normal.len() != normal.len() || consumed_drain.len() != drain.len() {
        return Err(invalid("unaccounted normal or DrainSet publication row"));
    }
    Ok(output)
}

fn bundle_from_retained_record(
    record: &FastPathPublicationRecord,
    imported: bool,
    state: &BTreeMap<Vec<u8>, &[u8]>,
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<PublicationBundle, BusinessReconstructionError> {
    let manifest = decode_artifact_manifest(&record.manifest)
        .map_err(|_| invalid("retained artifact manifest decoding failed"))?;
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let key: Vec<u8> = if imported {
            drain_publication_artifact_key(
                plan.ordered_policy.context().chain_id(),
                record.context.epoch(),
                &record.request_id,
                entry,
            )
            .map_err(|_| invalid("DrainSet artifact key derivation failed"))?
        } else {
            fastpath_publication_artifact_key(
                plan.ordered_policy.context().chain_id(),
                &record.request_id,
                entry.kind,
                &entry.content_digest.bytes(),
            )
            .map_err(|_| invalid("artifact key derivation failed"))?
        };
        let bytes: &[u8] =
            state
                .get(&key)
                .copied()
                .ok_or(BusinessReconstructionError::Incomplete(
                    "retained publication artifact row is absent",
                ))?;
        if bytes.len() != entry.content_length as usize {
            return Err(invalid("retained artifact length differs from manifest"));
        }
        contents.push(bytes.to_vec());
    }
    let certificate: FastCertificate = decode_fast_certificate(&record.certificate)
        .map_err(|_| invalid("retained FastCertificate decoding failed"))?;
    Ok(PublicationBundle {
        domain: plan.domain,
        request_id: record.request_id,
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: record.signed_intent.clone(),
        certificate,
        witness: record.witness.clone(),
        manifest,
        contents,
    })
}

struct ReconstructionEd25519Verifier;

impl ConsensusVerifier for ReconstructionEd25519Verifier {
    fn verify_framed(
        &self,
        _validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        framed: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if scheme != SignatureSchemeId::Ed25519 {
            return Ok(false);
        }
        let verifier: Ed25519Verifier = Ed25519Verifier::from_verifying_key_bytes(public_key)
            .map_err(|error| error.to_string())?;
        verifier
            .verify_framed(framed, signature)
            .map_err(|error| error.to_string())
    }
}

fn nonce_next_value(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &protocol_types::ChainId,
    protocol_version: protocol_types::ProtocolVersion,
    sender: [u8; 32],
    epoch: Epoch,
) -> Result<u64, BusinessReconstructionError> {
    let layout: PersistenceLayout = PersistenceLayout::new(chain.clone(), protocol_version);
    let key: Vec<u8> = layout.sender_nonce_key(sender, epoch);
    let row = store
        .get_versioned_durable(context, domain, &key)
        .map_err(|_| invalid("private sender nonce read failed"))?;
    let Some(bytes) = row.value() else {
        if row.revision() == StateRevision::INITIAL {
            return Ok(0);
        }
        return Err(invalid("private sender nonce is tombstoned"));
    };
    let frame = decode_canonical_frame(bytes)
        .map_err(|_| invalid("private sender nonce record is malformed"))?;
    frame
        .require_type(0xE006)
        .map_err(|_| invalid("private sender nonce record type differs"))?;
    frame
        .require_version(1)
        .map_err(|_| invalid("private sender nonce record version differs"))?;
    frame
        .require_only_fields(&[1, 2, 3])
        .map_err(|_| invalid("private sender nonce record fields differ"))?;
    let stored_sender: [u8; 32] = frame
        .required_field(1)
        .map_err(|_| invalid("private sender nonce sender missing"))?
        .try_into()
        .map_err(|_| invalid("private sender nonce sender length differs"))?;
    let stored_epoch: u64 = frame
        .required_u64(2)
        .map_err(|_| invalid("private sender nonce epoch missing"))?;
    let next: u64 = frame
        .required_u64(3)
        .map_err(|_| invalid("private sender nonce value missing"))?;
    let mut canonical: CanonicalStruct = CanonicalStruct::new(0xE006, 1);
    canonical
        .field_bytes(1, stored_sender.to_vec())
        .map_err(|_| invalid("private sender nonce re-encoding failed"))?;
    canonical
        .field_u64(2, stored_epoch)
        .map_err(|_| invalid("private sender nonce re-encoding failed"))?;
    canonical
        .field_u64(3, next)
        .map_err(|_| invalid("private sender nonce re-encoding failed"))?;
    let encoded: Vec<u8> = canonical
        .finish()
        .map_err(|_| invalid("private sender nonce re-encoding failed"))?;
    if stored_sender != sender || stored_epoch != epoch.get() || encoded.as_slice() != bytes {
        return Err(invalid("private sender nonce record is misbound"));
    }
    Ok(next)
}

fn provenance_observation(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    keyspace: &LogicalKeySpace<'_>,
    subject: &LogicalSubject,
    expected: Option<(
        LogicalObservation,
        Option<protocol_types::ExecutionGeneration>,
    )>,
) -> Result<bool, BusinessReconstructionError> {
    let key: Vec<u8> = keyspace
        .provenance_key(subject)
        .map_err(|_| invalid("logical provenance key derivation failed"))?;
    let row = store
        .get_versioned_durable(context, domain, &key)
        .map_err(|_| invalid("private logical provenance read failed"))?;
    match (row.value(), expected) {
        (None, None) if row.revision() == StateRevision::INITIAL => Ok(true),
        (Some(bytes), Some((observation, Some(generation)))) => {
            let record: LogicalProvenanceRecord = decode_logical_provenance_record(bytes)
                .map_err(|_| invalid("private logical provenance record malformed"))?;
            Ok(record.subject == *subject
                && record.generation == generation
                && record.observation == observation)
        }
        _ => Ok(false),
    }
}

fn owned_material_is_ready(
    overlay: &BusinessReconstructionOverlay<'_>,
    material: &OwnedPublicationMaterial,
) -> Result<bool, BusinessReconstructionError> {
    let plan: &BusinessReconstructionPlan<'_> = &overlay.plan;
    let decoded =
        crate::fast_path::publication::witness::decode_logical_witness(&material.bundle.witness)
            .map_err(|_| invalid("owned publication witness decoding failed"))?;
    let profile_key: Vec<u8> = logical_profile_key(plan.ordered_policy.context().chain_id())
        .map_err(|_| invalid("logical profile key derivation failed"))?;
    let profile_row = overlay
        .store
        .get_versioned_durable(&plan.operation_context, plan.domain, &profile_key)
        .map_err(|_| invalid("private logical profile read failed"))?;
    let profile: crate::logical_generation::LogicalProfileRecord = decode_logical_profile_record(
        profile_row
            .value()
            .ok_or(invalid("private logical profile row missing"))?,
    )
    .map_err(|_| invalid("private logical profile row malformed"))?;
    let keyspace: LogicalKeySpace<'_> =
        LogicalKeySpace::new(&profile, plan.genesis_root.genesis_resolver());
    let mut expected_observations: BTreeMap<
        LogicalSubject,
        (
            LogicalObservation,
            Option<protocol_types::ExecutionGeneration>,
        ),
    > = BTreeMap::new();

    for read in &decoded.state_reads {
        let row = overlay
            .store
            .get_versioned_durable(&plan.operation_context, plan.domain, &read.key)
            .map_err(|_| invalid("private owned state input read failed"))?;
        let observation: LogicalObservation = match read.observation {
            crate::fast_path::publication::witness::DecodedStateObservation::NeverWritten => {
                if row.value().is_some() || row.revision() != StateRevision::INITIAL {
                    return Ok(false);
                }
                return_if_generation_none(read.generation)?;
                if !provenance_observation(
                    &overlay.store,
                    &plan.operation_context,
                    plan.domain,
                    &keyspace,
                    &LogicalSubject::StateKey(read.key.clone()),
                    None,
                )? {
                    return Ok(false);
                }
                continue;
            }
            crate::fast_path::publication::witness::DecodedStateObservation::Present {
                content_digest,
            } => {
                let Some(bytes) = row.value() else {
                    return Ok(false);
                };
                let digest: Digest32 = plan
                    .genesis_root
                    .genesis_resolver()
                    .hash_for_purpose(
                        plan.ordered_policy.context().epoch(),
                        HashPurpose::ExecutionEffects,
                        bytes,
                    )
                    .map_err(|_| invalid("owned state input digest failed"))?;
                if digest.bytes() != content_digest {
                    return Ok(false);
                }
                LogicalObservation::StatePresent {
                    content_digest: digest,
                }
            }
            crate::fast_path::publication::witness::DecodedStateObservation::Deleted => {
                if row.value().is_some() || row.revision() == StateRevision::INITIAL {
                    return Ok(false);
                }
                LogicalObservation::StateDeleted
            }
        };
        expected_observations.insert(
            LogicalSubject::StateKey(read.key.clone()),
            (observation, read.generation),
        );
    }

    for read in &decoded.head_reads {
        let head = overlay
            .store
            .get_object_head(&plan.operation_context, plan.domain, read.object_id)
            .map_err(|_| invalid("private owned object head read failed"))?;
        let (observation, generation): (
            LogicalObservation,
            Option<protocol_types::ExecutionGeneration>,
        ) = match (&read.observation, &head) {
            (
                crate::fast_path::publication::witness::DecodedObjectHeadObservation::Absent,
                DurableObjectHead::Absent,
            ) => {
                if decoded
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.subject == LogicalSubject::Object(read.object_id))
                    || !provenance_observation(
                        &overlay.store,
                        &plan.operation_context,
                        plan.domain,
                        &keyspace,
                        &LogicalSubject::Object(read.object_id),
                        None,
                    )?
                {
                    return Ok(false);
                }
                continue;
            }
            (
                crate::fast_path::publication::witness::DecodedObjectHeadObservation::Tombstoned {
                    last_object_version,
                },
                DurableObjectHead::Tombstoned {
                    last_object_version: actual,
                    ..
                },
            ) if last_object_version == &actual.get() => {
                let subject: LogicalSubject = LogicalSubject::Object(read.object_id);
                let generations: Vec<protocol_types::ExecutionGeneration> = decoded
                    .dependencies
                    .iter()
                    .filter(|dependency| dependency.subject == subject)
                    .map(|dependency| dependency.generation)
                    .collect();
                if generations.len() != 1 {
                    return Ok(false);
                }
                (
                    LogicalObservation::ObjectDeleted {
                        last_object_version: *last_object_version,
                    },
                    Some(generations[0]),
                )
            }
            (
                crate::fast_path::publication::witness::DecodedObjectHeadObservation::Current {
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                },
                DurableObjectHead::Current {
                    object_version: actual_version,
                    digest: actual_digest,
                    owner_projection: actual_owner,
                    routing_projection: actual_routing,
                    ..
                },
            ) if object_version == &actual_version.get()
                && *digest == actual_digest.bytes()
                && *owner_projection == *actual_owner
                && *routing_projection == *actual_routing =>
            {
                let subject: LogicalSubject = LogicalSubject::Object(read.object_id);
                let generations: Vec<protocol_types::ExecutionGeneration> = decoded
                    .dependencies
                    .iter()
                    .filter(|dependency| dependency.subject == subject)
                    .map(|dependency| dependency.generation)
                    .collect();
                if generations.len() != 1 {
                    return Ok(false);
                }
                (
                    LogicalObservation::ObjectLive {
                        object_version: *object_version,
                        digest: actual_digest.to_owned(),
                    },
                    Some(generations[0]),
                )
            }
            _ => return Ok(false),
        };
        expected_observations.insert(
            LogicalSubject::Object(read.object_id),
            (observation, generation),
        );
    }

    let authenticated = execution::paid_execution::authenticate_paid_intent(
        plan.genesis_root.genesis_resolver(),
        plan.ordered_policy.context(),
        &material.bundle.signed_intent,
    )
    .map_err(|_| invalid("owned signed intent authentication failed"))?;
    let intent = authenticated.intent();
    if intent.request_id != material.bundle.request_id
        || decoded.nonce.sender != intent.sender
        || decoded.nonce.epoch != intent.context.epoch()
        || intent.nonce.checked_add(1) != Some(decoded.nonce.next_nonce)
    {
        return Err(invalid("owned nonce witness differs from signed intent"));
    }
    let current_nonce: u64 = nonce_next_value(
        &overlay.store,
        &plan.operation_context,
        plan.domain,
        plan.ordered_policy.context().chain_id(),
        plan.ordered_policy.context().protocol_version(),
        intent.sender,
        intent.context.epoch(),
    )?;
    if current_nonce != intent.nonce {
        return Ok(false);
    }
    let nonce_subject: LogicalSubject = LogicalSubject::SenderNonce {
        sender: intent.sender,
        epoch: intent.context.epoch(),
    };
    let nonce_row_key: Vec<u8> = PersistenceLayout::new(
        plan.ordered_policy.context().chain_id().clone(),
        plan.ordered_policy.context().protocol_version(),
    )
    .sender_nonce_key(intent.sender, intent.context.epoch());
    if decoded.nonce.key != nonce_row_key {
        return Err(invalid(
            "owned nonce witness key differs from signed sender",
        ));
    }
    let nonce_row = overlay
        .store
        .get_versioned_durable(&plan.operation_context, plan.domain, &nonce_row_key)
        .map_err(|_| invalid("private sender nonce reread failed"))?;
    if nonce_row.value().is_some() {
        let nonce_dependencies: Vec<_> = decoded
            .dependencies
            .iter()
            .filter(|dependency| dependency.subject == nonce_subject)
            .collect();
        if nonce_dependencies.len() != 1 {
            return Ok(false);
        }
        expected_observations.insert(
            nonce_subject,
            (
                LogicalObservation::NonceNext {
                    next_nonce: intent.nonce,
                },
                Some(nonce_dependencies[0].generation),
            ),
        );
    } else {
        return_if_nonce_pristine(&decoded, &nonce_subject)?;
        if !provenance_observation(
            &overlay.store,
            &plan.operation_context,
            plan.domain,
            &keyspace,
            &nonce_subject,
            None,
        )? {
            return Ok(false);
        }
    }

    for dependency in &decoded.dependencies {
        let expected = expected_observations.get(&dependency.subject).copied();
        let Some((_, Some(generation))) = expected else {
            return Ok(false);
        };
        if generation != dependency.generation
            || !provenance_observation(
                &overlay.store,
                &plan.operation_context,
                plan.domain,
                &keyspace,
                &dependency.subject,
                expected,
            )?
        {
            return Ok(false);
        }
    }
    for (subject, expected) in expected_observations {
        if expected.1.is_some()
            && !decoded.dependencies.iter().any(|dependency| {
                dependency.subject == subject && Some(dependency.generation) == expected.1
            })
        {
            return Ok(false);
        }
        if !provenance_observation(
            &overlay.store,
            &plan.operation_context,
            plan.domain,
            &keyspace,
            &subject,
            Some(expected),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProducerKey {
    subject: LogicalSubject,
    generation: ExecutionGeneration,
}

struct OwnedWork<'m> {
    material: &'m OwnedPublicationMaterial,
    witness: DecodedLogicalWitness,
    dependencies: Vec<usize>,
    priority: (ExecutionGeneration, LogicalSubject),
}

impl<'a> BusinessReconstructionOverlay<'a> {
    /// Replays the exact supplied fixed history and only those owned producers
    /// needed at each causal boundary. Remaining independently applied owned
    /// operations run after the ordered prefix, in dependency-ready batches,
    /// unless an owning-preflight-accepted Freeze requires them before admission
    /// closes.
    /// Source outcomes and receipts are checked by the existing ordered and
    /// owned application paths; they never seed this store.
    pub fn reconstruct(
        &mut self,
        owned: &[OwnedPublicationMaterial],
        ordered: &[OrderedHistoryHeightMaterial],
    ) -> Result<BusinessReconstructionReport, BusinessReconstructionError> {
        self.reconstruct_with_control_material(owned, ordered, &[])
    }

    /// Replays with explicit source-captured DrainSet signer proof material.
    /// Controls only reconstruct ordinary local readiness in the private
    /// overlay; they do not confer execution or import authority.
    pub fn reconstruct_with_control_material(
        &mut self,
        owned: &[OwnedPublicationMaterial],
        ordered: &[OrderedHistoryHeightMaterial],
        controls: &[DrainSetControlMaterial],
    ) -> Result<BusinessReconstructionReport, BusinessReconstructionError> {
        if self.reconstruction_started {
            return Err(invalid("overlay reconstruction was already attempted"));
        }
        control::validate_control_inputs(&self.plan, ordered, controls)
            .map_err(BusinessReconstructionError::ControlProof)?;
        self.reconstruction_started = true;
        let semantic_catalog: Vec<VerifiedPublicationSemantic> =
            self.validate_owned_inputs(owned)?;
        let mut works: Vec<OwnedWork<'_>> = Vec::with_capacity(owned.len());
        let mut producer_index: BTreeMap<ProducerKey, usize> = BTreeMap::new();
        let mut state_producers: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        let mut object_producers: BTreeMap<(objects::ObjectId, u64, [u8; 32]), usize> =
            BTreeMap::new();
        let mut nonce_producers: BTreeMap<([u8; 32], Epoch, u64), usize> = BTreeMap::new();
        let mut request_producers: BTreeMap<[u8; 32], usize> = BTreeMap::new();

        for (index, material) in owned.iter().enumerate() {
            let witness = crate::fast_path::publication::witness::decode_logical_witness(
                &material.bundle.witness,
            )
            .map_err(|_| invalid("owned witness decode failed during replay"))?;
            let decoded_outputs: Vec<(LogicalSubject, LogicalObservation)> = logical_outputs(
                &witness,
                self.plan.genesis_root.genesis_resolver(),
                self.plan.ordered_policy.context().epoch(),
            )?;
            let first_output: LogicalSubject = decoded_outputs
                .first()
                .map(|(subject, _)| subject.clone())
                .ok_or(invalid("owned operation has no logical output"))?;
            for (subject, _observation) in decoded_outputs {
                let key: ProducerKey = ProducerKey {
                    subject,
                    generation: witness.generation,
                };
                if producer_index.insert(key, index).is_some() {
                    return Err(invalid("two owned operations claim one logical producer"));
                }
            }
            for mutation in &witness.state_mutations {
                if matches!(&mutation.mutation, StateMutation::Put(_)) {
                    state_producers
                        .entry(mutation.key.clone())
                        .or_default()
                        .push(index);
                }
            }
            for mutation in &witness.object_mutations {
                let produced: Option<(u64, [u8; 32])> = match &mutation.mutation {
                    DecodedObjectMutationKind::Create { version, .. }
                    | DecodedObjectMutationKind::Update { version, .. } => {
                        Some((version.object_version, version.digest))
                    }
                    DecodedObjectMutationKind::Delete => None,
                };
                if let Some((version, digest)) = produced
                    && object_producers
                        .insert((mutation.object_id, version, digest), index)
                        .is_some()
                {
                    return Err(invalid("two owned operations claim one object producer"));
                }
            }
            let nonce_key: ([u8; 32], Epoch, u64) = (
                witness.nonce.sender,
                witness.nonce.epoch,
                witness.nonce.next_nonce,
            );
            if nonce_producers.insert(nonce_key, index).is_some() {
                return Err(invalid("two owned operations claim one nonce producer"));
            }
            if request_producers
                .insert(material.bundle.request_id, index)
                .is_some()
            {
                return Err(BusinessReconstructionError::Duplicate(
                    "owned external request identity",
                ));
            }
            let priority: (ExecutionGeneration, LogicalSubject) =
                (witness.generation, first_output);
            works.push(OwnedWork {
                material,
                witness,
                dependencies: Vec::new(),
                priority,
            });
        }

        for (index, work) in works.iter_mut().enumerate() {
            let dependencies: Vec<usize> = work
                .witness
                .dependencies
                .iter()
                .filter_map(|dependency| {
                    producer_index
                        .get(&ProducerKey {
                            subject: dependency.subject.clone(),
                            generation: dependency.generation,
                        })
                        .copied()
                })
                .collect();
            if dependencies.contains(&index) {
                return Err(invalid("owned operation depends on its own output"));
            }
            work.dependencies = dependencies;
        }

        let mut applied_owned: BTreeSet<usize> = BTreeSet::new();
        let mut verifier: OrderedHistoryVerifier = OrderedHistoryVerifier::new(
            self.plan.ordered_policy.clone(),
            self.plan.ordered_history_identity.clone(),
        )
        .map_err(|_| invalid("ordered history verifier pin refused"))?;
        let mut ordered_originals: usize = 0;
        let mut empty_heights: usize = 0;
        let mut consumed_controls: BTreeSet<Digest32> = BTreeSet::new();

        for material in ordered {
            if material.descriptor.identity != *self.plan.ordered_history_identity {
                return Err(invalid("ordered height belongs to another fixed identity"));
            }
            let candidate_bytes: Option<&[u8]> = material
                .components
                .iter()
                .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
                .map(|(_, bytes)| bytes.as_slice());
            if let Some(bytes) = candidate_bytes {
                let candidate = decode_ordered_candidate(bytes)
                    .map_err(|_| invalid("ordered candidate decoding failed"))?;
                let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
                    policy: self.plan.ordered_policy,
                    history: self.plan.resolver_history,
                    leg_policy: self.plan.ordered_leg_policy,
                    engine: self.plan.ordered_engine,
                    blobs: &self.blobs,
                    seal: None,
                };
                let requirements =
                    crate::ordered_economics::ordered_causal_requirements(&environment, &candidate)
                        .map_err(|_| {
                            BusinessReconstructionError::Execution(
                                "ordered causal requirements authentication failed",
                            )
                        })?;
                let roots: BTreeSet<usize> = self.required_owned_producers(
                    &requirements,
                    &works,
                    &state_producers,
                    &object_producers,
                    &nonce_producers,
                    &request_producers,
                )?;
                let closure: BTreeSet<usize> = dependency_closure(&roots, &works)?;
                apply_owned_closure(self, &works, &closure, &mut applied_owned)?;
                if candidate.kind == OrderedOperationKind::Freeze {
                    let barrier: bool = {
                        let barrier_environment: OrderedEconomicsEnvironment<'_> =
                            OrderedEconomicsEnvironment {
                                policy: self.plan.ordered_policy,
                                history: self.plan.resolver_history,
                                leg_policy: self.plan.ordered_leg_policy,
                                engine: self.plan.ordered_engine,
                                blobs: &self.blobs,
                                seal: None,
                            };
                        crate::ordered_economics::engine::reconstruction_freeze_barrier_needed(
                            &self.store,
                            &self.plan.operation_context,
                            &barrier_environment,
                            &candidate,
                            material.descriptor.height,
                        )
                        .map_err(|source| {
                            BusinessReconstructionError::OrderedHistory {
                                height: material.descriptor.height,
                                source: Box::new(source),
                            }
                        })?
                    };
                    if barrier {
                        // A fresh, independently preflight-accepted Freeze is
                        // the last ordinary-admission point. Only the existing
                        // authenticated ordinary completion targets cross
                        // this boundary; no-AV frozen completions and retained-
                        // but-unapplied publications never enter this set.
                        // Their signed witness dependency
                        // closure still determines execution order, after every
                        // earlier certified ordered event has been replayed.
                        let remaining_applied_targets: BTreeSet<usize> = owned
                            .iter()
                            .enumerate()
                            .filter_map(|(index, item)| {
                                (item.source_application_present
                                    && item.availability_certificate.is_some()
                                    && !applied_owned.contains(&index))
                                .then_some(index)
                            })
                            .collect();
                        let closure: BTreeSet<usize> =
                            dependency_closure(&remaining_applied_targets, &works)?;
                        apply_owned_closure(self, &works, &closure, &mut applied_owned)?;
                    }
                }
                control::prepare_drain_control(
                    self,
                    &candidate,
                    material.descriptor.height,
                    controls,
                    owned,
                    &semantic_catalog,
                    &mut consumed_controls,
                )
                .map_err(BusinessReconstructionError::ControlProof)?;
            }

            let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
                policy: self.plan.ordered_policy,
                history: self.plan.resolver_history,
                leg_policy: self.plan.ordered_leg_policy,
                engine: self.plan.ordered_engine,
                blobs: &self.blobs,
                seal: None,
            };
            let replay_scope: Option<ReplayScope<'_>> = self.replay_scope();
            let gate: ServingGate<'_> = replay_scope
                .as_ref()
                .map_or(ServingGate::Original, ServingGate::Replay);
            let outcome =
                crate::ordered_economics::engine::reconstruct_ordered_history_height_gated(
                    gate,
                    &self.store,
                    &self.plan.operation_context,
                    &environment,
                    &mut verifier,
                    material,
                )
                .map_err(|source| BusinessReconstructionError::OrderedHistory {
                    height: material.descriptor.height,
                    source: Box::new(source),
                })?;
            drop(replay_scope);
            if let Some(outcome) = outcome {
                // A later certified recommit preserves the original height
                // and receipt. It is not another business application.
                if outcome.block_height == material.descriptor.height {
                    ordered_originals = ordered_originals
                        .checked_add(1)
                        .ok_or(invalid("ordered reconstruction counter overflow"))?;
                }
            } else {
                empty_heights = empty_heights
                    .checked_add(1)
                    .ok_or(invalid("empty-height counter overflow"))?;
            }
        }
        let verified = verifier.finish().map_err(|_| {
            BusinessReconstructionError::Incomplete("ordered fixed prefix is incomplete")
        })?;
        if verified.identity() != self.plan.ordered_history_identity {
            return Err(invalid("verified ordered identity changed"));
        }

        let remaining: BTreeSet<usize> = owned
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                (item.source_application_present && !applied_owned.contains(&index))
                    .then_some(index)
            })
            .collect();
        apply_owned_closure(self, &works, &remaining, &mut applied_owned)?;
        let expected_applied: usize = owned
            .iter()
            .filter(|material| material.source_application_present)
            .count();
        if applied_owned.len() != expected_applied {
            return Err(BusinessReconstructionError::Incomplete(
                "an applied owned publication was not independently replayed",
            ));
        }
        self.publication_catalog = Some(semantic_catalog);
        self.reconstruction_complete = true;
        Ok(BusinessReconstructionReport {
            genesis_digest: self.genesis_digest,
            ordered_identity: verified.identity().clone(),
            ordered_height: verified.identity().through_height,
            owned_originals_replayed: applied_owned.len(),
            ordered_originals_replayed: ordered_originals,
            empty_ordered_heights: empty_heights,
            semantic_snapshot_equal: None,
        })
    }

    /// Compares the complete source's four portable collections with a fresh
    /// portable snapshot of this independently replayed private overlay.
    /// Source results, receipts and local ordered metadata remain comparison
    /// targets; none become replay authority here.
    pub fn compare_source(
        &self,
        source: &SourceBusinessSnapshot,
    ) -> Result<(), BusinessReconstructionError> {
        projection::compare_source(self, source)
    }

    /// Returns exact authenticated retention keys and normalized application
    /// certificate carriers for the sibling semantic projector. Both the
    /// replay catalog and captured source are independently verified; source
    /// rows are never copied into the private execution store.
    pub(super) fn authenticated_publication_projection(
        &self,
        source: &SourceBusinessSnapshot,
    ) -> Result<AuthenticatedPublicationProjection, BusinessReconstructionError> {
        if !self.reconstruction_complete {
            return Err(BusinessReconstructionError::Incomplete(
                "publication projection requires successful complete replay",
            ));
        }
        let expected_catalog: &[VerifiedPublicationSemantic] = self
            .publication_catalog
            .as_deref()
            .ok_or(invalid("verified publication catalog is absent"))?;
        let current: SourceBusinessSnapshot = self.current_snapshot(source)?;
        let source_material: Vec<OwnedPublicationMaterial> =
            owned_material_from_source_snapshot(&current, &self.plan)?;
        let source_catalog: Vec<VerifiedPublicationSemantic> =
            self.validate_owned_inputs(&source_material)?;
        if source_catalog != expected_catalog {
            return Err(invalid(
                "captured source publication catalog differs from replay inputs",
            ));
        }
        let retention_keys: BTreeSet<Vec<u8>> =
            source_retention_keys(source, &source_material, &self.plan)?;
        let source_normalized: BTreeMap<Vec<u8>, Vec<u8>> =
            normalize_source_carriers(source, expected_catalog, &self.plan)?;
        let private_normalized: BTreeMap<Vec<u8>, Vec<u8>> =
            normalize_private_carriers(&self.store, expected_catalog, &self.plan)?;
        if source_normalized != private_normalized {
            return Err(invalid(
                "source certificate carriers differ from independently replayed subjects",
            ));
        }
        Ok(AuthenticatedPublicationProjection {
            retention_keys,
            normalized_state: source_normalized,
            identities: expected_catalog
                .iter()
                .map(|item| (item.request_id, item.identity.clone()))
                .collect(),
        })
    }

    fn validate_owned_inputs(
        &self,
        owned: &[OwnedPublicationMaterial],
    ) -> Result<Vec<VerifiedPublicationSemantic>, BusinessReconstructionError> {
        // The root already validated the original committee (DR-0182); no
        // independent reconstruction from the manifest's raw validator-set
        // record is needed or trusted here.
        let validator_set: ValidatorSet = self.base.committee().clone();
        let fast_certifier: FastPathCertifier = FastPathCertifier::new(
            self.plan
                .genesis_root
                .manifest()
                .context()
                .chain_id()
                .clone(),
            self.plan
                .genesis_root
                .manifest()
                .context()
                .protocol_version(),
            self.plan.ordered_policy.context().epoch(),
            validator_set.clone(),
        )
        .map_err(|_| invalid("pinned FastVote authority invalid"))?;
        let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
            self.plan
                .genesis_root
                .manifest()
                .context()
                .chain_id()
                .clone(),
            self.plan
                .genesis_root
                .manifest()
                .context()
                .protocol_version(),
            self.plan.ordered_policy.context().epoch(),
            validator_set,
        )
        .map_err(|_| invalid("pinned availability authority invalid"))?;
        let verifier: ReconstructionEd25519Verifier = ReconstructionEd25519Verifier;
        let mut request_ids: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut semantic_catalog: Vec<VerifiedPublicationSemantic> =
            Vec::with_capacity(owned.len());
        for material in owned {
            let bundle: &PublicationBundle = &material.bundle;
            if !request_ids.insert(bundle.request_id)
                || bundle.domain != self.plan.domain
                || bundle.commitment_profile != LOGICAL_COMMITMENT_PROFILE
                || (material.availability_certificate.is_some()
                    && !material.source_application_present)
            {
                return Err(invalid(
                    "owned material identity or application marker mismatch",
                ));
            }
            let verified = verify_publication_bundle(
                bundle,
                &fast_certifier,
                &verifier,
                self.plan.genesis_root.genesis_resolver(),
                self.plan.resolver_history,
            )
            .map_err(|_| invalid("owned publication certificate or closure failed"))?;
            if verified.identity.domain != self.plan.domain
                || verified.identity.request_id != bundle.request_id
                || bundle.signed_intent.is_empty()
            {
                return Err(invalid("owned publication verified identity mismatch"));
            }
            let authenticated = execution::paid_execution::authenticate_paid_intent(
                self.plan.genesis_root.genesis_resolver(),
                self.plan.ordered_policy.context(),
                &bundle.signed_intent,
            )
            .map_err(|_| invalid("owned paid intent authentication failed"))?;
            if authenticated.intent().request_id != bundle.request_id
                || authenticated.intent().context != *self.plan.ordered_policy.context()
                || bundle.request_id[0] & 0x80 != 0
            {
                return Err(invalid(
                    "owned request is misbound or outside the Owned lane",
                ));
            }
            let availability_identity: Option<AvailabilityIdentity> =
                if let Some(bytes) = &material.availability_certificate {
                    let certificate: AvailabilityCertificate =
                        decode_availability_certificate(bytes)
                            .map_err(|_| invalid("owned availability certificate decode failed"))?;
                    if certificate.identity != verified.identity {
                        return Err(invalid("owned availability identity mismatch"));
                    }
                    availability_certifier
                        .verify_certificate(&certificate, &verifier)
                        .map_err(|_| invalid("owned availability proof failed"))?;
                    Some(certificate.identity)
                } else {
                    None
                };
            let artifacts: Vec<SemanticArtifact> = bundle
                .manifest
                .entries
                .iter()
                .zip(bundle.contents.iter())
                .map(|(entry, bytes)| SemanticArtifact {
                    kind: entry.kind,
                    digest: entry.content_digest,
                    bytes: bytes.clone(),
                })
                .collect();
            let manifest: Vec<u8> = encode_artifact_manifest(&bundle.manifest)
                .map_err(|_| invalid("owned artifact manifest encoding failed"))?;
            if artifacts.len() != bundle.manifest.entries.len() {
                return Err(invalid("owned artifact closure is incomplete"));
            }
            semantic_catalog.push(VerifiedPublicationSemantic {
                request_id: bundle.request_id,
                identity: verified.identity.clone(),
                tx_hash: bundle.certificate.tx_hash,
                execution_effects_hash: bundle.certificate.execution_effects_hash,
                locked_objects_digest: bundle.certificate.locked_objects_digest,
                signed_intent: bundle.signed_intent.clone(),
                witness: bundle.witness.clone(),
                manifest,
                artifacts,
                applied: material.source_application_present,
                availability_identity,
            });
        }
        semantic_catalog.sort_by_key(|entry| entry.request_id);
        Ok(semantic_catalog)
    }

    fn required_owned_producers(
        &self,
        requirements: &crate::ordered_economics::OrderedCausalRequirements,
        works: &[OwnedWork<'_>],
        state_producers: &BTreeMap<Vec<u8>, Vec<usize>>,
        object_producers: &BTreeMap<(objects::ObjectId, u64, [u8; 32]), usize>,
        nonce_producers: &BTreeMap<([u8; 32], Epoch, u64), usize>,
        request_producers: &BTreeMap<[u8; 32], usize>,
    ) -> Result<BTreeSet<usize>, BusinessReconstructionError> {
        let mut roots: BTreeSet<usize> = BTreeSet::new();
        for object_ref in &requirements.objects {
            let head = self
                .store
                .get_object_head(
                    &self.plan.operation_context,
                    self.plan.domain,
                    object_ref.id,
                )
                .map_err(|_| invalid("private ordered prerequisite object read failed"))?;
            let satisfied: bool = matches!(head,
                DurableObjectHead::Current { object_version, digest, .. }
                    if object_version.get() == object_ref.version && digest == object_ref.digest
            );
            if !satisfied
                && let Some(index) = object_producers.get(&(
                    object_ref.id,
                    object_ref.version,
                    object_ref.digest.bytes(),
                ))
            {
                require_applied_producer(works, *index)?;
                roots.insert(*index);
            }
        }
        if let Some(nonce) = requirements.nonce {
            let current: u64 = nonce_next_value(
                &self.store,
                &self.plan.operation_context,
                self.plan.domain,
                self.plan.ordered_policy.context().chain_id(),
                self.plan
                    .genesis_root
                    .manifest()
                    .context()
                    .protocol_version(),
                nonce.sender,
                nonce.epoch,
            )?;
            if current < nonce.first_nonce
                && let Some(index) =
                    nonce_producers.get(&(nonce.sender, nonce.epoch, nonce.first_nonce))
            {
                require_applied_producer(works, *index)?;
                roots.insert(*index);
            }
        }
        for leg in &requirements.legs {
            let call = &leg.intent().call;
            let code_key: Vec<u8> = crate::publication::publication_record_key(call.code.origin())
                .map_err(|_| invalid("ordered leg code key derivation failed"))?;
            if self.state_is_pristine(&code_key)?
                && let Some(index) = state_producers.get(&code_key)
            {
                add_unique_applied_state_producer(works, index, &mut roots)?;
            }
            let instance_key: Vec<u8> = crate::local_instance_state::instance_record_key(
                self.plan.ordered_policy.context().chain_id(),
                &call.instance.creator,
                &call.instance.seed,
            )
            .map_err(|_| invalid("ordered leg instance key derivation failed"))?;
            if self.state_is_pristine(&instance_key)?
                && let Some(index) = state_producers.get(&instance_key)
            {
                add_unique_applied_state_producer(works, index, &mut roots)?;
            }
            for access in &call.access.entries {
                let head = self
                    .store
                    .get_object_head(
                        &self.plan.operation_context,
                        self.plan.domain,
                        access.object_ref.id,
                    )
                    .map_err(|_| invalid("ordered leg object prerequisite read failed"))?;
                let present: bool = matches!(head,
                    DurableObjectHead::Current { object_version, digest, .. }
                        if object_version.get() == access.object_ref.version
                            && digest == access.object_ref.digest
                );
                if !present
                    && let Some(index) = object_producers.get(&(
                        access.object_ref.id,
                        access.object_ref.version,
                        access.object_ref.digest.bytes(),
                    ))
                {
                    require_applied_producer(works, *index)?;
                    roots.insert(*index);
                }
            }
        }
        if let Some(request_id) = requirements.fee_escrow_request_id {
            let key: Vec<u8> = crate::local_instance_state::fastpath_settlement_key(
                self.plan.ordered_policy.context().chain_id(),
                &request_id,
            )
            .map_err(|_| invalid("fee escrow producer key derivation failed"))?;
            if self.state_is_pristine(&key)?
                && let Some(index) = request_producers.get(&request_id)
            {
                require_applied_producer(works, *index)?;
                roots.insert(*index);
            }
        }
        Ok(roots)
    }

    fn state_is_pristine(&self, key: &[u8]) -> Result<bool, BusinessReconstructionError> {
        let row = self
            .store
            .get_versioned_durable(&self.plan.operation_context, self.plan.domain, key)
            .map_err(|_| invalid("private prerequisite state read failed"))?;
        Ok(row.value().is_none() && row.revision() == StateRevision::INITIAL)
    }
}

fn require_applied_producer(
    works: &[OwnedWork<'_>],
    index: usize,
) -> Result<(), BusinessReconstructionError> {
    let work: &OwnedWork<'_> = works
        .get(index)
        .ok_or(invalid("owned producer index is outside the catalog"))?;
    if !work.material.source_application_present {
        return Err(BusinessReconstructionError::Incomplete(
            "required owned producer has no retained application completion",
        ));
    }
    Ok(())
}

fn add_unique_applied_state_producer(
    works: &[OwnedWork<'_>],
    candidates: &[usize],
    roots: &mut BTreeSet<usize>,
) -> Result<(), BusinessReconstructionError> {
    let mut applied: Option<usize> = None;
    for index in candidates {
        let work: &OwnedWork<'_> = works
            .get(*index)
            .ok_or(invalid("state producer index is outside the catalog"))?;
        if work.material.source_application_present && applied.replace(*index).is_some() {
            return Err(invalid(
                "multiple applied owned producers target one immutable prerequisite",
            ));
        }
    }
    if let Some(index) = applied {
        require_applied_producer(works, index)?;
        roots.insert(index);
    }
    Ok(())
}

fn dependency_closure(
    roots: &BTreeSet<usize>,
    works: &[OwnedWork<'_>],
) -> Result<BTreeSet<usize>, BusinessReconstructionError> {
    dependency_graph::closure(roots, |index: usize| {
        let work: &OwnedWork<'_> = works
            .get(index)
            .ok_or(invalid("owned dependency index is outside the catalog"))?;
        Ok(work.dependencies.as_slice())
    })
}

fn apply_owned_closure(
    overlay: &mut BusinessReconstructionOverlay<'_>,
    works: &[OwnedWork<'_>],
    selected: &BTreeSet<usize>,
    applied: &mut BTreeSet<usize>,
) -> Result<(), BusinessReconstructionError> {
    let mut pending: BTreeSet<usize> = selected
        .iter()
        .filter(|index| !applied.contains(index))
        .copied()
        .collect();
    while !pending.is_empty() {
        let mut advanced: bool = false;
        let mut ready_order: Vec<usize> = pending.iter().copied().collect();
        ready_order.sort_by(|left, right| works[*left].priority.cmp(&works[*right].priority));
        for index in ready_order {
            let work: &OwnedWork<'_> = works
                .get(index)
                .ok_or(invalid("owned work index is outside the catalog"))?;
            require_applied_producer(works, index)?;
            if !work
                .dependencies
                .iter()
                .all(|dependency| applied.contains(dependency) || !selected.contains(dependency))
            {
                continue;
            }
            if !owned_material_is_ready(overlay, work.material)? {
                continue;
            }
            if let Some(availability) = work.material.availability_certificate.as_deref() {
                let certificate: Vec<u8> =
                    encode_fast_certificate(&work.material.bundle.certificate)
                        .map_err(|_| invalid("owned FastCertificate encoding failed"))?;
                let replay_scope: Option<ReplayScope<'_>> = overlay.replay_scope();
                let gate: ServingGate<'_> = replay_scope
                    .as_ref()
                    .map_or(ServingGate::Original, ServingGate::Replay);
                let fee_policy: execution::paid_execution::PaidFeePolicy = overlay.fee_policy()?;
                crate::fast_path::apply_internal(
                    gate,
                    &overlay.store,
                    &overlay.blobs,
                    &overlay.plan.operation_context,
                    overlay.plan.domain,
                    overlay.plan.genesis_root.genesis_resolver(),
                    overlay.plan.resolver_history,
                    overlay.plan.ordered_policy.context(),
                    overlay.plan.paid_base_policy,
                    &fee_policy,
                    overlay.plan.paid_engine,
                    &work.material.bundle.signed_intent,
                    &certificate,
                    Some(work.material.recovery_created_checkpoint),
                    Some(availability),
                )
                .map_err(|_| {
                    BusinessReconstructionError::Execution(
                        "independent owned operation application failed",
                    )
                })?;
            } else {
                // No-AV completion is not ordinary publication authority. The
                // owning handler reads only privately reconstructed committed
                // Freeze/DrainSet, exact selected membership and full retained
                // proof; it refuses before paid execution if any is absent.
                let replay_scope: Option<ReplayScope<'_>> = overlay.replay_scope();
                let gate: ServingGate<'_> = replay_scope
                    .as_ref()
                    .map_or(ServingGate::Original, ServingGate::Replay);
                let fee_policy: execution::paid_execution::PaidFeePolicy = overlay.fee_policy()?;
                crate::fast_path::drain_apply::apply_drain_member_gated(
                    gate,
                    &overlay.store,
                    &overlay.blobs,
                    &overlay.plan.operation_context,
                    overlay.plan.domain,
                    overlay.plan.genesis_root.genesis_resolver(),
                    overlay.plan.resolver_history,
                    overlay.plan.ordered_policy.context(),
                    overlay.plan.paid_base_policy,
                    &fee_policy,
                    overlay.plan.paid_engine,
                    work.material.bundle.request_id,
                    work.material.recovery_created_checkpoint,
                )
                .map_err(|_| {
                    BusinessReconstructionError::Execution(
                        "independent frozen member application failed",
                    )
                })?;
            }
            applied.insert(index);
            pending.remove(&index);
            advanced = true;
        }
        if !advanced {
            return Err(BusinessReconstructionError::Incomplete(
                "owned producer is missing, conflicting or not causally ready",
            ));
        }
    }
    Ok(())
}

fn logical_outputs(
    witness: &DecodedLogicalWitness,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<Vec<(LogicalSubject, LogicalObservation)>, BusinessReconstructionError> {
    let mut output: Vec<(LogicalSubject, LogicalObservation)> = Vec::new();
    for mutation in &witness.state_mutations {
        let observation: Option<LogicalObservation> = match &mutation.mutation {
            StateMutation::Assert => None,
            StateMutation::Delete => Some(LogicalObservation::StateDeleted),
            StateMutation::Put(bytes) => {
                let digest = resolver
                    .hash_for_purpose(epoch, HashPurpose::ExecutionEffects, bytes)
                    .map_err(|_| invalid("owned producer state digest failed"))?;
                Some(LogicalObservation::StatePresent {
                    content_digest: digest,
                })
            }
        };
        if let Some(observation) = observation {
            output.push((LogicalSubject::StateKey(mutation.key.clone()), observation));
        }
    }
    for mutation in &witness.object_mutations {
        let observation: LogicalObservation = match &mutation.mutation {
            DecodedObjectMutationKind::Create { version, .. }
            | DecodedObjectMutationKind::Update { version, .. } => LogicalObservation::ObjectLive {
                object_version: version.object_version,
                digest: Digest32::new(
                    resolver
                        .suite_for_epoch(epoch)
                        .map_err(|_| invalid("owned object digest suite unavailable"))?
                        .algorithm_for(HashPurpose::Object),
                    version.digest,
                ),
            },
            DecodedObjectMutationKind::Delete => {
                let previous = witness
                    .head_reads
                    .iter()
                    .find(|read| read.object_id == mutation.object_id)
                    .ok_or(invalid("owned object deletion lacks its signed prior head"))?;
                let last_object_version: u64 = match previous.observation {
                    DecodedObjectHeadObservation::Current { object_version, .. } => object_version,
                    DecodedObjectHeadObservation::Tombstoned {
                        last_object_version,
                    } => last_object_version,
                    DecodedObjectHeadObservation::Absent => {
                        return Err(invalid("owned object deletion prior head is absent"));
                    }
                };
                LogicalObservation::ObjectDeleted {
                    last_object_version,
                }
            }
        };
        output.push((LogicalSubject::Object(mutation.object_id), observation));
    }
    output.push((
        LogicalSubject::SenderNonce {
            sender: witness.nonce.sender,
            epoch: witness.nonce.epoch,
        },
        LogicalObservation::NonceNext {
            next_nonce: witness.nonce.next_nonce,
        },
    ));
    Ok(output)
}

fn return_if_generation_none(
    generation: Option<protocol_types::ExecutionGeneration>,
) -> Result<(), BusinessReconstructionError> {
    if generation.is_none() {
        Ok(())
    } else {
        Err(invalid("never-written state read has a logical generation"))
    }
}

fn return_if_nonce_pristine(
    decoded: &crate::fast_path::publication::witness::DecodedLogicalWitness,
    subject: &LogicalSubject,
) -> Result<(), BusinessReconstructionError> {
    if decoded
        .dependencies
        .iter()
        .any(|dependency| &dependency.subject == subject)
    {
        return Err(invalid("pristine sender nonce has a logical dependency"));
    }
    Ok(())
}

/// Data-only outcome of independently replaying and comparing supplied material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessReconstructionReport {
    /// Locally pinned root that initialized the private overlay.
    pub genesis_digest: Digest32,
    /// Exact fixed ordered-history target which was replayed.
    pub ordered_identity: OrderedHistoryIdentity,
    /// Final verified ordered prefix height.
    pub ordered_height: u64,
    /// Number of owned originals independently applied in the private overlay.
    pub owned_originals_replayed: usize,
    /// Number of ordered business originals/refusals reconstructed.
    pub ordered_originals_replayed: usize,
    /// Number of empty committed ordered heights preserved.
    pub empty_ordered_heights: usize,
    /// Whether the supplied source snapshot's closed semantic projection
    /// exactly matched the private reconstruction.
    /// `None` means no closed projection comparison has been run yet.
    pub semantic_snapshot_equal: Option<bool>,
}

/// Comparison-only catalog returned to the sibling semantic projector after
/// complete replay. It carries no import or execution authority.
pub(super) struct AuthenticatedPublicationProjection {
    /// Exact, verified retained-publication and artifact keys present in the
    /// captured source. The projector may exclude only these keys.
    pub retention_keys: BTreeSet<Vec<u8>>,
    /// Canonical comparison-only values for exactly verified application
    /// certificate and availability-certificate rows.
    pub normalized_state: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Complete verified retention identity required by each local ACK.
    pub identities: BTreeMap<[u8; 32], AvailabilityIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SemanticArtifact {
    kind: ArtifactKind,
    digest: Digest32,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedPublicationSemantic {
    request_id: [u8; 32],
    identity: AvailabilityIdentity,
    tx_hash: Digest32,
    execution_effects_hash: Digest32,
    locked_objects_digest: Digest32,
    signed_intent: Vec<u8>,
    witness: Vec<u8>,
    manifest: Vec<u8>,
    artifacts: Vec<SemanticArtifact>,
    applied: bool,
    availability_identity: Option<AvailabilityIdentity>,
}

/// Refusal while pinning, reconstructing, or comparing business history.
#[derive(Debug)]
pub enum BusinessReconstructionError {
    /// Closed-profile, authority, causal placement, or projection violation.
    Invalid(&'static str),
    /// A source row or a component is duplicated rather than reconciled.
    Duplicate(&'static str),
    /// Authenticated or deterministic existing execution refused.
    Execution(&'static str),
    /// Independent ordered execution or companion verification failed at a
    /// pinned proof height. The cause is typed and contains no candidate or
    /// artifact bytes.
    OrderedHistory {
        /// Exact fixed-history height under independent reconstruction.
        height: u64,
        /// Existing core error category and static/canonical reason.
        source: Box<OrderedEconomicsError>,
    },
    /// Optional DrainSet control material failed strict binding or could not
    /// produce independently required private readiness.
    ControlProof(DrainSetControlProofError),
    /// Source data cannot be proven complete under the captured token.
    Incomplete(&'static str),
}

impl fmt::Display for BusinessReconstructionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "business reconstruction refused: {reason}"),
            Self::Duplicate(reason) => write!(f, "business reconstruction duplicate: {reason}"),
            Self::Execution(reason) => write!(f, "business reconstruction execution: {reason}"),
            Self::OrderedHistory { height, source } => write!(
                f,
                "business reconstruction ordered height {height}: {source}"
            ),
            Self::ControlProof(source) => {
                write!(f, "business reconstruction control proof: {source}")
            }
            Self::Incomplete(reason) => write!(f, "business reconstruction incomplete: {reason}"),
        }
    }
}

impl Error for BusinessReconstructionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OrderedHistory { source, .. } => Some(source.as_ref()),
            Self::ControlProof(source) => Some(source),
            Self::Invalid(_) | Self::Duplicate(_) | Self::Execution(_) | Self::Incomplete(_) => {
                None
            }
        }
    }
}

const fn invalid(reason: &'static str) -> BusinessReconstructionError {
    BusinessReconstructionError::Invalid(reason)
}

fn source_retention_keys(
    source: &SourceBusinessSnapshot,
    materials: &[OwnedPublicationMaterial],
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<BTreeSet<Vec<u8>>, BusinessReconstructionError> {
    let source_keys: BTreeSet<Vec<u8>> = source
        .records
        .iter()
        .filter_map(|record| match record.descriptor.key() {
            DurableRecordKey::State(key) => Some(key.clone()),
            _ => None,
        })
        .collect();
    let mut retained: BTreeSet<Vec<u8>> = BTreeSet::new();
    for material in materials {
        let request: [u8; 32] = material.bundle.request_id;
        let chain = plan.ordered_policy.context().chain_id();
        let normal_key: Vec<u8> = fastpath_publication_key(chain, &request)
            .map_err(|_| invalid("normal publication key derivation failed"))?;
        let drain_key: Vec<u8> =
            drain_publication_key(chain, material.bundle.certificate.epoch, &request)
                .map_err(|_| invalid("DrainSet publication key derivation failed"))?;
        let mut aliases: Vec<bool> = Vec::new();
        if source_keys.contains(&normal_key) {
            aliases.push(false);
            retained.insert(normal_key);
        }
        if source_keys.contains(&drain_key) {
            aliases.push(true);
            retained.insert(drain_key);
        }
        if aliases.is_empty() {
            return Err(BusinessReconstructionError::Incomplete(
                "authenticated publication has no retained key",
            ));
        }
        for imported in aliases {
            for entry in &material.bundle.manifest.entries {
                let key: Vec<u8> = if imported {
                    drain_publication_artifact_key(
                        chain,
                        material.bundle.certificate.epoch,
                        &request,
                        entry,
                    )
                    .map_err(|_| invalid("DrainSet artifact key derivation failed"))?
                } else {
                    fastpath_publication_artifact_key(
                        chain,
                        &request,
                        entry.kind,
                        &entry.content_digest.bytes(),
                    )
                    .map_err(|_| invalid("normal artifact key derivation failed"))?
                };
                if !source_keys.contains(&key) {
                    return Err(BusinessReconstructionError::Incomplete(
                        "authenticated publication artifact key is absent",
                    ));
                }
                retained.insert(key);
            }
        }
    }
    Ok(retained)
}

type CarrierRow = (bool, Option<Vec<u8>>);

fn normalize_source_carriers(
    source: &SourceBusinessSnapshot,
    catalog: &[VerifiedPublicationSemantic],
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, BusinessReconstructionError> {
    let keys: BTreeSet<Vec<u8>> = carrier_keys(catalog, plan)?;
    let mut rows: BTreeMap<Vec<u8>, CarrierRow> = BTreeMap::new();
    for record in &source.records {
        if let DurableRecordKey::State(key) = record.descriptor.key()
            && keys.contains(key)
        {
            rows.insert(key.clone(), (true, record.value.clone()));
        }
    }
    normalize_carrier_rows(&rows, catalog, plan)
}

fn normalize_private_carriers(
    store: &MemoryDurableStateStore,
    catalog: &[VerifiedPublicationSemantic],
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, BusinessReconstructionError> {
    let keys: BTreeSet<Vec<u8>> = carrier_keys(catalog, plan)?;
    let mut rows: BTreeMap<Vec<u8>, CarrierRow> = BTreeMap::new();
    for key in keys {
        let row = store
            .get_versioned_durable(&plan.operation_context, plan.domain, &key)
            .map_err(|_| invalid("private certificate carrier read failed"))?;
        let present: bool = row.value().is_some() || row.revision() != StateRevision::INITIAL;
        rows.insert(key, (present, row.value().map(<[u8]>::to_vec)));
    }
    normalize_carrier_rows(&rows, catalog, plan)
}

fn carrier_keys(
    catalog: &[VerifiedPublicationSemantic],
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<BTreeSet<Vec<u8>>, BusinessReconstructionError> {
    let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    for item in catalog {
        if item.applied {
            keys.insert(
                fastpath_certificate_key(
                    plan.ordered_policy.context().chain_id(),
                    &item.request_id,
                )
                .map_err(|_| invalid("application certificate key derivation failed"))?,
            );
            keys.insert(
                fastpath_availability_certificate_key(
                    plan.ordered_policy.context().chain_id(),
                    &item.request_id,
                )
                .map_err(|_| invalid("availability certificate key derivation failed"))?,
            );
        }
    }
    Ok(keys)
}

fn normalize_carrier_rows(
    rows: &BTreeMap<Vec<u8>, CarrierRow>,
    catalog: &[VerifiedPublicationSemantic],
    plan: &BusinessReconstructionPlan<'_>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, BusinessReconstructionError> {
    // The root already validated the original committee (DR-0182); no
    // independent reconstruction from the manifest's raw validator-set
    // record is needed or trusted here.
    let validator_set: ValidatorSet = plan.ordered_policy.engine().validator_set().clone();
    let fast: FastPathCertifier = FastPathCertifier::new(
        plan.ordered_policy.context().chain_id().clone(),
        plan.ordered_policy.context().protocol_version(),
        plan.ordered_policy.context().epoch(),
        validator_set.clone(),
    )
    .map_err(|_| invalid("carrier FastVote authority invalid"))?;
    let availability: AvailabilityCertifier = AvailabilityCertifier::new(
        plan.ordered_policy.context().chain_id().clone(),
        plan.ordered_policy.context().protocol_version(),
        plan.ordered_policy.context().epoch(),
        validator_set,
    )
    .map_err(|_| invalid("carrier availability authority invalid"))?;
    let verifier: ReconstructionEd25519Verifier = ReconstructionEd25519Verifier;
    let mut normalized: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for item in catalog {
        let certificate_key: Vec<u8> =
            fastpath_certificate_key(plan.ordered_policy.context().chain_id(), &item.request_id)
                .map_err(|_| invalid("application certificate key derivation failed"))?;
        let availability_key: Vec<u8> = fastpath_availability_certificate_key(
            plan.ordered_policy.context().chain_id(),
            &item.request_id,
        )
        .map_err(|_| invalid("availability certificate key derivation failed"))?;
        let absent: CarrierRow = (false, None);
        let cert_row: &(bool, Option<Vec<u8>>) = rows.get(&certificate_key).unwrap_or(&absent);
        let availability_row: &(bool, Option<Vec<u8>>) =
            rows.get(&availability_key).unwrap_or(&absent);
        if !item.applied {
            if cert_row.0 || availability_row.0 {
                return Err(invalid(
                    "unapplied publication has an application certificate carrier",
                ));
            }
            continue;
        }
        let cert_bytes: &[u8] = cert_row.1.as_deref().filter(|_| cert_row.0).ok_or(
            BusinessReconstructionError::Incomplete(
                "applied publication application certificate is absent",
            ),
        )?;
        let cert_record: FastPathCertificateRecord =
            crate::fast_path::records::decode_fastpath_certificate_record(cert_bytes)
                .map_err(|_| invalid("application certificate carrier is malformed"))?;
        if cert_record.request_id != item.request_id {
            return Err(invalid("application certificate carrier identity differs"));
        }
        let fast_certificate: FastCertificate =
            decode_fast_certificate(&cert_record.certificate)
                .map_err(|_| invalid("application FastCertificate is malformed"))?;
        fast.verify_certificate(&fast_certificate, &verifier)
            .map_err(|_| invalid("application FastCertificate proof is invalid"))?;
        if fast_certificate.tx_hash != item.tx_hash
            || fast_certificate.execution_effects_hash != item.execution_effects_hash
            || fast_certificate.locked_objects_digest != item.locked_objects_digest
        {
            return Err(invalid("application certificate subject differs"));
        }
        let mut fast_subject: Vec<u8> = encode_availability_identity(&item.identity)
            .map_err(|_| invalid("certificate subject encoding failed"))?;
        fast_subject.extend_from_slice(&fast_certificate.tx_hash.bytes());
        fast_subject.extend_from_slice(&fast_certificate.execution_effects_hash.bytes());
        fast_subject.extend_from_slice(&fast_certificate.locked_objects_digest.bytes());
        normalized.insert(certificate_key, fast_subject);
        let Some(expected_identity) = item.availability_identity.as_ref() else {
            if availability_row.0 {
                return Err(invalid(
                    "frozen completion has an unexpected availability carrier",
                ));
            }
            continue;
        };
        let availability_bytes: &[u8] = availability_row
            .1
            .as_deref()
            .filter(|_| availability_row.0)
            .ok_or(BusinessReconstructionError::Incomplete(
                "applied publication availability certificate is absent",
            ))?;
        let availability_record: FastPathAvailabilityCertificateRecord =
            decode_fastpath_availability_certificate_record(availability_bytes)
                .map_err(|_| invalid("availability carrier is malformed"))?;
        if availability_record.request_id != item.request_id {
            return Err(invalid("availability carrier identity differs"));
        }
        let certificate: AvailabilityCertificate =
            decode_availability_certificate(&availability_record.certificate)
                .map_err(|_| invalid("availability certificate is malformed"))?;
        availability
            .verify_certificate(&certificate, &verifier)
            .map_err(|_| invalid("availability certificate proof is invalid"))?;
        if &certificate.identity != expected_identity || expected_identity != &item.identity {
            return Err(invalid("availability carrier subject differs"));
        }
        let availability_subject: Vec<u8> = encode_availability_identity(&certificate.identity)
            .map_err(|_| invalid("availability subject encoding failed"))?;
        normalized.insert(availability_key, availability_subject);
    }
    Ok(normalized)
}

/// Non-exportable private state and trusted replay composition.
pub struct BusinessReconstructionOverlay<'a> {
    plan: BusinessReconstructionPlan<'a>,
    base: ReconstructionBase<'a>,
    base_snapshot: Option<SourceBusinessSnapshot>,
    store: MemoryDurableStateStore,
    blobs: MemoryBlobStore,
    genesis_digest: Digest32,
    reconstruction_started: bool,
    reconstruction_complete: bool,
    publication_catalog: Option<Vec<VerifiedPublicationSemantic>>,
}

impl<'a> BusinessReconstructionOverlay<'a> {
    /// Verifies the signed-v4 causal-admission pin and installs genesis into a
    /// fresh private store. The supplied context/domain cannot select genesis.
    pub fn new(plan: BusinessReconstructionPlan<'a>) -> Result<Self, BusinessReconstructionError> {
        let base: ReconstructionBase<'a> = ReconstructionBase::genesis(plan.genesis_root);
        Self::new_with_base(plan, base)
    }

    pub(crate) fn new_with_base(
        plan: BusinessReconstructionPlan<'a>,
        base: ReconstructionBase<'a>,
    ) -> Result<Self, BusinessReconstructionError> {
        base.require_policy(plan.ordered_policy, plan.domain)
            .map_err(|_| invalid("reconstruction policy differs from verified base"))?;
        // `plan.genesis_root` is one immutable `VerifiedGenesisRoot`
        // (DR-0182): its manifest, digest, admission profile, original
        // committee and resolver are already mutually consistent by
        // construction, so disagreement among those specific values is
        // unrepresentable here and is no longer independently re-checked.
        // The still-independent policy/history/domain inputs below are not
        // guaranteed by the root and keep their real cross-checks.
        if !base.is_successor() {
            require_configuration(plan.genesis_root, plan.ordered_policy, plan.domain)
                .map_err(|_| invalid("trusted genesis/profile/policy pins disagree"))?;
        }
        if plan.ordered_history_identity.context != *base.context()
            || plan.ordered_history_identity.domain != plan.domain
            || plan.ordered_history_identity.genesis_digest != plan.genesis_root.digest()
            || plan.ordered_history_identity.anchor != plan.ordered_policy.anchor()
            || plan.ordered_leg_policy.context() != base.context()
            || plan.paid_base_policy.context() != base.context()
            || plan.genesis_root.manifest().fee_policy.context
                != *plan.genesis_root.genesis_context()
        {
            return Err(invalid("trusted genesis/profile/policy pins disagree"));
        }
        // Companion disagreement keeps its original diagnostic precedence
        // over a policy anchor which differs from the signed root's anchor.
        if !base.is_successor() {
            require_root_anchor(plan.genesis_root, plan.ordered_policy, plan.domain).map_err(
                |error: RootAnchorBindingError| match error {
                    RootAnchorBindingError::Derivation => {
                        invalid("genesis root anchor could not be derived")
                    }
                    RootAnchorBindingError::Mismatch => {
                        invalid("ordered policy anchor does not match the genesis root")
                    }
                },
            )?;
        }
        if let Some(bootstrapped) = base
            .bootstrap(&plan.operation_context)
            .map_err(|_| invalid("verified successor bootstrap refused"))?
        {
            let genesis_digest: Digest32 = plan.genesis_root.digest();
            return Ok(Self {
                plan,
                base,
                base_snapshot: Some(bootstrapped.snapshot),
                store: bootstrapped.store,
                blobs: bootstrapped.blobs,
                genesis_digest,
                reconstruction_started: false,
                reconstruction_complete: false,
                publication_catalog: None,
            });
        }
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(plan.domain, plan.operation_context.writer_fence());
        let install: GenesisInstallOutcome = genesis::install_genesis_with_history(
            &store,
            &plan.operation_context,
            plan.domain,
            plan.genesis_root.genesis_resolver(),
            plan.resolver_history,
            plan.genesis_root.manifest(),
            0,
        )
        .map_err(|_| invalid("private signed-genesis installation failed"))?;
        match install {
            GenesisInstallOutcome::FreshInstall {
                manifest_digest, ..
            }
            | GenesisInstallOutcome::VerifiedExisting {
                manifest_digest, ..
            } if manifest_digest == plan.genesis_root.digest() => {}
            _ => return Err(invalid("private genesis install returned another digest")),
        }
        let genesis_digest: Digest32 = plan.genesis_root.digest();
        Ok(Self {
            plan,
            base,
            base_snapshot: None,
            store,
            blobs: MemoryBlobStore::default(),
            genesis_digest,
            reconstruction_started: false,
            reconstruction_complete: false,
            publication_catalog: None,
        })
    }

    /// Locally pinned digest, not a source-advertised target.
    #[must_use]
    pub const fn genesis_digest(&self) -> Digest32 {
        self.genesis_digest
    }

    /// A fresh, non-exportable scope per shared handler call. The caller
    /// drops this borrow before updating mutable overlay progress.
    fn replay_scope(&self) -> Option<ReplayScope<'_>> {
        let (committees, owners): (&VerifiedCommitteeHistory, &VerifiedOwnerRegistry) =
            self.base.histories()?;
        Some(ReplayScope {
            issuer: &self.store,
            context: &self.plan.operation_context,
            domain: self.plan.domain,
            floor: self.base.floor()?,
            committees,
            owners,
            prior: self.base_snapshot.as_ref()?,
            epoch: self.base.context().epoch(),
        })
    }

    /// A fresh scope whose borrow cannot escape the one shared handler
    /// call. Mutable replay progress is updated only after this returns.
    fn replay_call<T>(&self, call: impl for<'s> FnOnce(ServingGate<'s>) -> T) -> T {
        let scope: Option<ReplayScope<'_>> = self.replay_scope();
        let gate: ServingGate<'_> = scope
            .as_ref()
            .map_or(ServingGate::Original, ServingGate::Replay);
        call(gate)
    }

    fn fee_policy(
        &self,
    ) -> Result<execution::paid_execution::PaidFeePolicy, BusinessReconstructionError> {
        let key: Vec<u8> = crate::local_instance_state::paid_fee_policy_key(self.base.context())
            .map_err(|_| invalid("replay fee policy key"))?;
        let row = self
            .store
            .get_versioned_durable(&self.plan.operation_context, self.plan.domain, &key)
            .map_err(|_| invalid("replay fee policy read"))?;
        execution::paid_execution::decode_paid_fee_policy(
            row.value().ok_or(invalid("replay fee policy absent"))?,
        )
        .map_err(|_| invalid("replay fee policy decode"))
    }

    /// Earlier immutable rows are retained exactly as the verified base
    /// installed them. They are never authenticated with the current engine
    /// or admitted to the current publication replay catalog.
    fn earlier_rows(
        &self,
    ) -> Result<BTreeMap<Vec<u8>, Option<Vec<u8>>>, BusinessReconstructionError> {
        let mut earlier: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let Some(snapshot) = &self.base_snapshot else {
            return Ok(earlier);
        };
        for row in &snapshot.records {
            let DurableRecordKey::State(key) = row.descriptor.key() else {
                continue;
            };
            let ordered: bool = key
                .starts_with(crate::ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX)
                && !crate::ordered_economics::engine::is_ordered_key_of_scope(
                    key,
                    self.base.context().chain_id(),
                    self.plan.ordered_policy.key_scope(),
                )
                .map_err(|_| invalid("base ordered scope classification"))?;
            let fast: bool = key
                .strip_prefix(crate::local_instance_state::FASTPATH_STATE_PREFIX)
                .is_some_and(|tail: &[u8]| {
                    [
                        b"publication/".as_slice(),
                        b"publication-artifact/",
                        b"drain-publication/",
                        b"drain-publication-artifact/",
                        b"certificate/",
                        b"availability-certificate/",
                        b"commitment-witness/",
                    ]
                    .iter()
                    .any(|family| tail.starts_with(family))
                });
            // A carried settlement is mutable business state: a current
            // owner may claim its historical-epoch share. It stays in the
            // exact source/private semantic comparison after the SAME claim
            // handler independently derives it; it is not an immutable
            // publication carrier or a current-epoch producer to re-execute.
            if ordered || fast {
                earlier.insert(key.clone(), row.value.clone());
            }
        }
        Ok(earlier)
    }

    fn current_snapshot(
        &self,
        snapshot: &SourceBusinessSnapshot,
    ) -> Result<SourceBusinessSnapshot, BusinessReconstructionError> {
        let earlier: BTreeMap<Vec<u8>, Option<Vec<u8>>> = self.earlier_rows()?;
        let mut current: SourceBusinessSnapshot = snapshot.clone();
        for row in &current.records {
            if let DurableRecordKey::State(key) = row.descriptor.key()
                && let Some(expected) = earlier.get(key)
                && expected != &row.value
            {
                return Err(invalid(
                    "earlier protected row differs from the verified base",
                ));
            }
        }
        current.records.retain(|row| !matches!(row.descriptor.key(), DurableRecordKey::State(key) if earlier.contains_key(key)));
        let bounds: ReferencedBlobBounds = referenced_blob_bounds(&current)?;
        current
            .referenced_blobs
            .retain(|digest, _| bounds.contains_key(digest));
        Ok(current)
    }
}

/// Only this module's private overlay method constructs this issuer-bound
/// per-call replay authority. It never contains a key or signing capability.
pub(crate) struct ReplayScope<'o> {
    issuer: &'o MemoryDurableStateStore,
    context: &'o DurableOperationContext,
    domain: AtomicityDomainId,
    floor: ExecutionGeneration,
    committees: &'o VerifiedCommitteeHistory,
    owners: &'o VerifiedOwnerRegistry,
    prior: &'o SourceBusinessSnapshot,
    epoch: Epoch,
}

impl ReplayScope<'_> {
    pub(crate) fn require_issuer<S: ?Sized>(
        &self,
        store: &S,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), crate::NodeCoreError> {
        if !std::ptr::addr_eq(
            store as *const S,
            self.issuer as *const MemoryDurableStateStore,
        ) || context != self.context
            || domain != self.domain
        {
            return Err(crate::NodeCoreError::PersistenceInvariant(
                "replay call differs from its private issuer",
            ));
        }
        let (committee, _digest): (&validator_set::ValidatorSet, Digest32) = self
            .committees
            .get(self.epoch)
            .ok_or(crate::NodeCoreError::PersistenceInvariant(
                "replay current committee is not verified",
            ))?;
        if committee
            .validators()
            .iter()
            .any(|member: &validator_set::ValidatorInfo| {
                self.owners.owner(member.id).is_none_or(|owner| {
                    owner.scheme() != member.signature_scheme
                        || owner.key().as_slice() != member.public_key.as_slice()
                })
            })
        {
            return Err(crate::NodeCoreError::PersistenceInvariant(
                "replay current committee has no verified owner provenance",
            ));
        }
        Ok(())
    }

    pub(crate) const fn floor(&self) -> ExecutionGeneration {
        self.floor
    }

    pub(crate) fn predecessor_certificate_anchor(&self, epoch: Epoch) -> Option<Digest32> {
        (epoch < self.epoch)
            .then(|| self.committees.get(epoch).map(|(_, digest)| digest))
            .flatten()
    }

    pub(crate) fn prior_state_row(&self, key: &[u8]) -> Option<&[u8]> {
        self.prior
            .records
            .iter()
            .find_map(|row: &SourceSnapshotRecord| match row.descriptor.key() {
                DurableRecordKey::State(found) if found == key => row.value.as_deref(),
                _ => None,
            })
    }
}
