//! Post-Freeze full-publication possession for DR-0154.
//!
//! An imported proof belongs to a selected frozen-frontier union, not to this
//! replica's pre-Freeze availability log. Import therefore never calls
//! `retain_publication`, writes `publication/`, or creates an availability
//! ACK. A separate marker is committed only with the complete verified proof
//! and exact replay artifacts. The marker alone does not authorize DrainSet:
//! the caller must also finish every selected signed frontier page.

use super::*;
use crate::fast_path::publication::{
    FastPathPublicationRecord, MAX_RETAINED_ARTIFACTS, PublicationRetentionError,
    decode_fastpath_publication_record, encode_fastpath_publication_record, witness,
};
use consensus::bundle::{
    ArtifactEntry, ArtifactManifest, LOGICAL_COMMITMENT_PROFILE, MAX_ENCODED_BUNDLE_BYTES,
    PublicationBundle, VerifiedPublicationBundle, decode_artifact_manifest,
    decode_publication_bundle, encode_artifact_manifest, verify_publication_bundle,
};
use consensus::{
    AvailabilityIdentity, decode_fast_certificate, encode_availability_identity,
    encode_fast_certificate,
};
use std::collections::BTreeMap;

type DrainResult<T> = Result<T, PublicationRetentionError>;

/// A pending `(key, bytes)` write for a possession marker this host has
/// independently re-verified is safe to rebuild; `None` means the marker
/// already matched and nothing needs to change.
pub(crate) type PossessionMarkerRebuild = Option<(Vec<u8>, Vec<u8>)>;

fn drain_key(
    chain: &ChainId,
    epoch: Epoch,
    request_id: &[u8; 32],
    prefix: &[u8],
) -> DrainResult<Vec<u8>> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(prefix);
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Full imported publication record, distinct from the local pre-Freeze
/// `publication/` log. Its epoch always comes from the locally fenced context.
pub fn drain_publication_key(
    chain: &ChainId,
    epoch: Epoch,
    request_id: &[u8; 32],
) -> DrainResult<Vec<u8>> {
    drain_key(chain, epoch, request_id, b"drain-publication/")
}

/// Exact retained content of one imported replay artifact.
pub fn drain_publication_artifact_key(
    chain: &ChainId,
    epoch: Epoch,
    request_id: &[u8; 32],
    entry: &ArtifactEntry,
) -> DrainResult<Vec<u8>> {
    let mut key: Vec<u8> = drain_key(chain, epoch, request_id, b"drain-publication-artifact/")?;
    key.extend_from_slice(&entry.kind.as_u16().to_be_bytes());
    key.extend_from_slice(&entry.content_digest.bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Local progress marker. It is not an availability ACK or a transferable
/// business record; a future DrainSet voter must re-read the proof itself.
pub fn drain_possession_key(
    chain: &ChainId,
    epoch: Epoch,
    request_id: &[u8; 32],
) -> DrainResult<Vec<u8>> {
    let mut key: Vec<u8> =
        crate::ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-possession/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> DrainResult<()> {
    if reads
        .insert(key, revision)
        .is_some_and(|prior: StateRevision| prior != revision)
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

pub(crate) fn fence_closed_epoch<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> DrainResult<ValidatorSet> {
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let installed =
        logical_generation::fence_commitment_profile(store, context, domain, &chain, reads)?;
    if installed.logical().is_none() {
        return Err(NodeCoreError::PersistenceInvariant(
            "historical profile has no drain publication",
        )
        .into());
    }
    let epoch_record: local_instance_state::FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, reads)?;
    if epoch_record.current_epoch != epoch {
        return Err(NodeCoreError::EpochMismatch {
            expected: epoch_record.current_epoch,
            actual: epoch,
        }
        .into());
    }
    let validators: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        expected,
        &epoch_record,
        reads,
    )?;
    let closure_key: Vec<u8> = crate::ordered_economics::admission_closure_key(&chain, epoch)?;
    let closure_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &closure_key)?;
    put_read(reads, closure_key, closure_row.revision())?;
    let closure_bytes: &[u8] =
        closure_row
            .value()
            .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                "ordered Freeze is not committed",
            ))?;
    let closure: crate::ordered_economics::AdmissionClosureRecord =
        crate::ordered_economics::decode_admission_closure_record(closure_bytes)?;
    if closure.closed_epoch != epoch
        || closure.request_id == [0; 32]
        || closure.closed_at_block_height == 0
    {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "invalid committed Freeze",
        ));
    }
    Ok(validators)
}

fn verify_bundle(
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    domain: AtomicityDomainId,
    validators: &ValidatorSet,
    bundle: &PublicationBundle,
) -> DrainResult<AvailabilityIdentity> {
    if bundle.domain != domain {
        return Err(PublicationRetentionError::ForeignDomain);
    }
    if bundle.certificate.chain_id != *expected.chain_id()
        || bundle.certificate.protocol_version != expected.protocol_version()
        || bundle.certificate.epoch != expected.epoch()
    {
        return Err(PublicationRetentionError::ContextMismatch);
    }
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        validators.clone(),
    )?;
    let verified: VerifiedPublicationBundle = verify_publication_bundle(
        bundle,
        &certifier,
        &FastPathEd25519Verifier,
        resolver,
        history,
    )?;
    let (authenticated, event_digest, _request) =
        authenticate_and_identify(resolver, expected, &bundle.signed_intent)?;
    if event_digest != bundle.certificate.tx_hash {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    if authenticated.intent().request_id != bundle.request_id {
        return Err(PublicationRetentionError::RequestIdMismatch);
    }
    if authenticated.intent().context != *expected {
        return Err(PublicationRetentionError::ContextMismatch);
    }
    let (witness_digest, required) = witness::required_artifacts(&bundle.witness)?;
    if witness_digest != event_digest {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    if required.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: required.len(),
            max: MAX_RETAINED_ARTIFACTS,
        });
    }
    required.require_closed(&bundle.manifest)?;
    Ok(verified.identity)
}

fn load_imported_bundle<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    request_id: &[u8; 32],
    record: &FastPathPublicationRecord,
) -> DrainResult<PublicationBundle> {
    if record.context != *expected || record.request_id != *request_id {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain publication context or request id",
        ));
    }
    let manifest: ArtifactManifest = decode_artifact_manifest(&record.manifest)?;
    if manifest.entries.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: manifest.entries.len(),
            max: MAX_RETAINED_ARTIFACTS,
        });
    }
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(manifest.entries.len());
    let mut total: usize = 0;
    for entry in &manifest.entries {
        let key: Vec<u8> = drain_publication_artifact_key(
            expected.chain_id(),
            expected.epoch(),
            request_id,
            entry,
        )?;
        let row: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
        let bytes: &[u8] =
            row.value()
                .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                    "missing or tombstoned drain artifact",
                ))?;
        total = total.checked_add(bytes.len()).ok_or(
            PublicationRetentionError::InconsistentRetainedRecord("drain artifact size overflow"),
        )?;
        if total > MAX_ENCODED_BUNDLE_BYTES {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "drain artifact budget exceeded",
            ));
        }
        contents.push(bytes.to_vec());
    }
    Ok(PublicationBundle {
        domain,
        request_id: *request_id,
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: record.signed_intent.clone(),
        certificate: decode_fast_certificate(&record.certificate)?,
        witness: record.witness.clone(),
        manifest,
        contents,
    })
}

/// Verifies and atomically imports one complete bundle after committed
/// Freeze, against an identity from a signed frontier page. This bounded
/// event never signs, acknowledges, executes, or mutates the original local
/// `publication/` log. A successful exact retry re-verifies all saved bytes.
/// It does **not** establish that any full frontier or quorum is complete.
#[allow(clippy::too_many_arguments)]
pub fn retain_drain_publication<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    expected_identity: &AvailabilityIdentity,
    bundle_bytes: &[u8],
) -> DrainResult<AvailabilityIdentity> {
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return Err(NodeCoreError::PersistenceInvariant("resolver history bound").into());
    }
    let bundle: PublicationBundle = decode_publication_bundle(bundle_bytes)?;
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let validators: ValidatorSet =
        fence_closed_epoch(store, context, domain, resolver, expected, &mut reads)?;
    let identity: AvailabilityIdentity =
        verify_bundle(resolver, history, expected, domain, &validators, &bundle)?;
    if identity != *expected_identity {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain bundle differs from frontier entry",
        ));
    }
    let identity_bytes: Vec<u8> = encode_availability_identity(&identity)?;
    let publication_key: Vec<u8> = drain_publication_key(&chain, epoch, &bundle.request_id)?;
    let possession_key: Vec<u8> = drain_possession_key(&chain, epoch, &bundle.request_id)?;
    let publication_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &publication_key)?;
    let possession_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &possession_key)?;
    put_read(
        &mut reads,
        publication_key.clone(),
        publication_row.revision(),
    )?;
    put_read(
        &mut reads,
        possession_key.clone(),
        possession_row.revision(),
    )?;
    if let Some(saved_bytes) = publication_row.value() {
        let saved: FastPathPublicationRecord = decode_fastpath_publication_record(saved_bytes)?;
        if saved.identity != identity_bytes {
            return Err(PublicationRetentionError::ConflictingRetainedIdentity);
        }
        let saved_bundle: PublicationBundle =
            load_imported_bundle(store, context, domain, expected, &bundle.request_id, &saved)?;
        let saved_identity: AvailabilityIdentity = verify_bundle(
            resolver,
            history,
            expected,
            domain,
            &validators,
            &saved_bundle,
        )?;
        if saved_identity != identity || possession_row.value() != Some(identity_bytes.as_slice()) {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "drain possession marker or retained proof",
            ));
        }
        return Ok(identity);
    }
    if publication_row.revision() != StateRevision::INITIAL
        || possession_row.value().is_some()
        || possession_row.revision() != StateRevision::INITIAL
    {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "partial or tombstoned drain possession",
        ));
    }
    let record: FastPathPublicationRecord = FastPathPublicationRecord {
        context: expected.clone(),
        request_id: bundle.request_id,
        identity: identity_bytes.clone(),
        signed_intent: bundle.signed_intent.clone(),
        certificate: encode_fast_certificate(&bundle.certificate)?,
        witness: bundle.witness.clone(),
        manifest: encode_artifact_manifest(&bundle.manifest)?,
    };
    let mut staged_artifacts: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (entry, content) in bundle.manifest.entries.iter().zip(bundle.contents.iter()) {
        let artifact_key: Vec<u8> =
            drain_publication_artifact_key(&chain, epoch, &bundle.request_id, entry)?;
        match staged_artifacts.insert(artifact_key.clone(), content.clone()) {
            Some(prior) if prior != *content => {
                return Err(PublicationRetentionError::InconsistentRetainedRecord(
                    "conflicting drain artifact content",
                ));
            }
            _ => {}
        }
    }
    let mut mutations: Vec<StateMutationEntry> = Vec::with_capacity(staged_artifacts.len() + 2);
    for (artifact_key, content) in staged_artifacts {
        let observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &artifact_key)?;
        if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "orphan or tombstoned drain artifact",
            ));
        }
        put_read(&mut reads, artifact_key.clone(), observed.revision())?;
        mutations.push(StateMutationEntry::new(
            artifact_key,
            StateMutation::Put(content),
        )?);
    }
    mutations.push(StateMutationEntry::new(
        publication_key,
        StateMutation::Put(encode_fastpath_publication_record(&record)?),
    )?);
    mutations.push(StateMutationEntry::new(
        possession_key,
        StateMutation::Put(identity_bytes),
    )?);
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision): (Vec<u8>, StateRevision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<_>, _>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => Ok(identity),
        DurableCommitOutcome::Rejected(reason) => {
            Err(NodeCoreError::DurableCommitRejected(reason).into())
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(NodeCoreError::DurableCommitIndeterminate(reason).into())
        }
    }
}

/// Read-only check of an imported marker plus all exact stored proof bytes.
/// A future frontier-page progress step must call this for every entry before
/// it can make that entry locally complete.
#[allow(clippy::too_many_arguments)]
pub fn verify_drain_possession<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    expected_identity: &AvailabilityIdentity,
) -> DrainResult<()> {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let validators: ValidatorSet =
        fence_closed_epoch(store, context, domain, resolver, expected, &mut reads)?;
    verify_drain_possession_into(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        &validators,
        expected_identity,
        &mut reads,
    )?;
    Ok(())
}

/// Re-verifies the retained proof and every exact artifact byte against
/// `expected_identity`, folding every read into `reads`. Does not itself
/// read or write the possession marker: callers decide separately whether a
/// missing marker is a hard failure ([`verify_drain_possession_into`]) or a
/// safe rebuild candidate ([`verify_or_stage_drain_possession_rebuild`]).
#[allow(clippy::too_many_arguments)]
fn verify_drain_proof_into<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    validators: &ValidatorSet,
    expected_identity: &AvailabilityIdentity,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> DrainResult<AvailabilityIdentity> {
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return Err(NodeCoreError::PersistenceInvariant("resolver history bound").into());
    }
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let request_id: [u8; 32] = expected_identity.request_id;
    let key: Vec<u8> = drain_publication_key(&chain, epoch, &request_id)?;
    let row: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    put_read(reads, key, row.revision())?;
    let bytes: &[u8] = row
        .value()
        .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
            "missing drain publication",
        ))?;
    let record: FastPathPublicationRecord = decode_fastpath_publication_record(bytes)?;
    if record.context != *expected || record.request_id != request_id {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain publication context or request id",
        ));
    }
    let manifest: ArtifactManifest = decode_artifact_manifest(&record.manifest)?;
    if manifest.entries.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: manifest.entries.len(),
            max: MAX_RETAINED_ARTIFACTS,
        });
    }
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(manifest.entries.len());
    let mut total: usize = 0;
    for entry in &manifest.entries {
        let artifact_key: Vec<u8> =
            drain_publication_artifact_key(&chain, epoch, &request_id, entry)?;
        let artifact_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &artifact_key)?;
        put_read(reads, artifact_key, artifact_row.revision())?;
        let content_bytes: &[u8] =
            artifact_row
                .value()
                .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                    "missing or tombstoned drain artifact",
                ))?;
        total = total.checked_add(content_bytes.len()).ok_or(
            PublicationRetentionError::InconsistentRetainedRecord("drain artifact size overflow"),
        )?;
        if total > MAX_ENCODED_BUNDLE_BYTES {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "drain artifact budget exceeded",
            ));
        }
        contents.push(content_bytes.to_vec());
    }
    let bundle: PublicationBundle = PublicationBundle {
        domain,
        request_id,
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: record.signed_intent.clone(),
        certificate: decode_fast_certificate(&record.certificate)?,
        witness: record.witness.clone(),
        manifest,
        contents,
    };
    let identity: AvailabilityIdentity =
        verify_bundle(resolver, history, expected, domain, validators, &bundle)?;
    if identity != *expected_identity || record.identity != encode_availability_identity(&identity)?
    {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain publication identity mismatch",
        ));
    }
    Ok(identity)
}

/// Same check as [`verify_drain_possession`], but for a caller that already
/// fenced the closed epoch and outgoing set, and that folds every read
/// revision this performs (publication, every artifact, and the possession
/// marker) into its own CAS read set so a signer-entry confirmation and this
/// re-verification commit atomically together. Returns the re-verified
/// identity so a caller never needs to trust its own request as authority.
/// A pristine (never-written) marker is treated exactly like a tombstoned
/// one here: this function never mutates anything, so it cannot safely
/// rebuild a missing marker itself. See
/// [`verify_or_stage_drain_possession_rebuild`] for the repair-capable path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_drain_possession_into<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    validators: &ValidatorSet,
    expected_identity: &AvailabilityIdentity,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> DrainResult<AvailabilityIdentity> {
    let identity: AvailabilityIdentity = verify_drain_proof_into(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        validators,
        expected_identity,
        reads,
    )?;
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let request_id: [u8; 32] = expected_identity.request_id;
    let marker_key: Vec<u8> = drain_possession_key(&chain, epoch, &request_id)?;
    let marker: VersionedStateValue = store.get_versioned_durable(context, domain, &marker_key)?;
    put_read(reads, marker_key, marker.revision())?;
    let identity_bytes: Vec<u8> = encode_availability_identity(&identity)?;
    if marker.value() != Some(identity_bytes.as_slice()) {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain possession identity or marker",
        ));
    }
    Ok(identity)
}

/// A same-epoch restore may carry the authenticated `drain-publication/` and
/// `drain-publication-artifact/` history while its local `drain-possession/`
/// marker is pristine (never written on this host): DR-0156 requires that
/// marker never be inferred from the proof row alone, but does allow it to
/// be safely *rebuilt* once the complete saved proof and every artifact have
/// been independently re-verified against the caller's own locally staged,
/// page-authenticated `expected_identity` -- never a caller-supplied claim
/// and never the proof's own self-reported identity alone. This function
/// never writes anything itself; it folds the marker's own read revision
/// into `reads` and, only for the pristine case, returns the exact
/// `(key, bytes)` pair the caller must fold into the *same* atomic commit as
/// every other read this function performed. A tombstoned marker -- like a
/// tombstoned or missing proof/artifact -- still fails closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_or_stage_drain_possession_rebuild<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    validators: &ValidatorSet,
    expected_identity: &AvailabilityIdentity,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> DrainResult<(AvailabilityIdentity, PossessionMarkerRebuild)> {
    let identity: AvailabilityIdentity = verify_drain_proof_into(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        validators,
        expected_identity,
        reads,
    )?;
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();
    let request_id: [u8; 32] = expected_identity.request_id;
    let marker_key: Vec<u8> = drain_possession_key(&chain, epoch, &request_id)?;
    let marker: VersionedStateValue = store.get_versioned_durable(context, domain, &marker_key)?;
    put_read(reads, marker_key.clone(), marker.revision())?;
    let identity_bytes: Vec<u8> = encode_availability_identity(&identity)?;
    match marker.value() {
        Some(bytes) if bytes == identity_bytes.as_slice() => Ok((identity, None)),
        Some(_) => Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain possession identity or marker",
        )),
        None if marker.revision() == StateRevision::INITIAL => {
            Ok((identity, Some((marker_key, identity_bytes))))
        }
        None => Err(PublicationRetentionError::InconsistentRetainedRecord(
            "drain possession marker is tombstoned",
        )),
    }
}

#[cfg(test)]
mod tests;
