//! U7 (DR-0154 §2 "Drain without speculative execution or rollback"):
//! narrowly scoped drain application of one exact committed `DrainSet`
//! union member's full certificate and original signed intent, including a
//! certificate for which no aggregated [`consensus::AvailabilityCertificate`]
//! was ever formed.
//!
//! This is a *separate* entry point from [`super::apply`]/
//! [`super::apply_with_recovery`]/[`super::apply_after_publication`]: it
//! never touches [`super::PublicationAuthority`] or
//! [`super::require_publication_authority`] (the ordinary
//! publication-before-apply gate stays exactly as strict, and exactly as
//! un-bypassable by construction, for every other apply entry point) and it
//! never accepts a caller-supplied certificate or signed intent. Its only
//! authority, all independently reconstructed and re-verified from durable
//! local storage in the same atomic commit as the effects it authorizes, is:
//!
//! 1. a committed [`ordered_economics::DrainSetRecord`] for the exact
//!    `(chain, epoch)` this call targets;
//! 2. this replica's own re-verified local `drain-union-ready/` marker
//!    ([`ordered_economics::verify_drain_ready_into`]), proving its
//!    independently reconstructed union for that record's exact
//!    `selected_votes` still equals the record's committed
//!    `drain_union_identity`;
//! 3. an immutable per-signer `drain-signer-entry/` row
//!    ([`ordered_economics::drain_signer_entry_key`]) from at least one of
//!    those selected signers, naming the target member's exact
//!    [`consensus::AvailabilityIdentity`] byte-for-byte -- proof, given (1)
//!    and (2), that this member was actually folded into that exact
//!    committed union. [`ordered_economics::advance_drain_union`]'s
//!    deterministic min-request-id merge visits every confirmed entry of
//!    every selected, locally-complete signer before it can ever reach
//!    readiness (each step scans every selected signer's next unmerged
//!    entry and only stops once every signer is exhausted), so a confirmed
//!    entry can never be silently excluded from a union that reached the
//!    identity step 2 re-verifies;
//! 4. this replica's own durably retained and freshly re-verified
//!    `drain-publication/` proof and artifact closure for that identity
//!    ([`super::drain_publication::verify_drain_possession_into`]).
//!
//! Given all four, this applies the member's certified effects exactly like
//! [`super::apply_with_recovery`] does (re-running the identical admission/
//! execution pipeline and independently re-deriving the same commitment
//! from the durably retained signed intent and certificate), except that a
//! local partial-prepare lock this admission's own required inputs conflict
//! with is atomically resolved (deleted) with the member's own
//! effects/receipt/nonce/settlement, instead of failing closed. DR-0154 §2
//! proves this is always safe: two conflicting full certificates can never
//! both exist (their prepare quorums share an honest voter that cannot
//! reserve the same object/nonce lock for both), so any local partial
//! prepare still holding the same lock as a genuinely drained full
//! certificate can never itself be certified. Every resolved lock is
//! recorded as a durable, immutable `fastpath/drain-lock-resolution/` audit
//! row in the same commit that deletes it -- "no sweeping unrelated locks":
//! only locks this admission's own required object/sender-epoch inputs
//! actually touch are ever considered, via
//! [`mutation_fence::LockMode::DrainResolve`].

use super::*;
use super::{commitment, records};
use crate::fast_path::drain_publication::{
    drain_publication_key, fence_closed_epoch, verify_drain_possession_into,
};
use crate::fast_path::publication::{
    FastPathPublicationRecord, decode_fastpath_publication_record,
};
use crate::ordered_economics::{
    self, DrainSetRecord, decode_drain_set_record, drain_set_record_key, drain_signer_entry_key,
    verify_drain_ready_into,
};
use consensus::{AvailabilityIdentity, decode_availability_identity};
use std::collections::BTreeSet;

impl From<ordered_economics::DrainSignerError> for FastPathError {
    fn from(error: ordered_economics::DrainSignerError) -> Self {
        match error {
            ordered_economics::DrainSignerError::Node(inner) => Self::Node(inner),
            ordered_economics::DrainSignerError::Publication(inner) => Self::Publication(*inner),
            ordered_economics::DrainSignerError::NotReady(message)
            | ordered_economics::DrainSignerError::Invalid(message) => Self::Invalid(message),
            ordered_economics::DrainSignerError::Frontier(_) => {
                Self::Invalid("drain union frontier re-verification failed")
            }
        }
    }
}

const FASTPATH_DRAIN_LOCK_RESOLUTION_RECORD_TYPE: u16 = 0x6450;
const ENCODING_VERSION: u16 = 1;

/// Cannot be constructed outside this module. Another paid-admission caller
/// cannot select post-Freeze lock resolution without traversing the committed
/// DrainSet proof path here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DrainApplyPermit {
    _private: (),
}

impl DrainApplyPermit {
    fn new_after_verified_member() -> Self {
        Self { _private: () }
    }
}

/// Immutable audit row for one local partial-prepare lock resolved by a
/// narrowly scoped U7 drain application: DR-0154 §2's "Keep an internal
/// resolution audit". Never read by any protocol path; a durable record of
/// which displaced request lost which exact lock to which resolving drain
/// member, for operator/audit visibility only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathDrainLockResolutionRecord {
    pub epoch: Epoch,
    /// The drain member (X) whose admission required resolving this lock.
    pub resolving_request_id: [u8; 32],
    /// The displaced local partial prepare (Y) that previously held it.
    pub displaced_request_id: [u8; 32],
    /// The exact resolved lock key (an object lock or the sender/epoch nonce
    /// lock).
    pub resolved_key: Vec<u8>,
}

fn encode_drain_lock_resolution_record(
    record: &FastPathDrainLockResolutionRecord,
) -> FastPathResult<Vec<u8>> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_DRAIN_LOCK_RESOLUTION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.epoch.get())?;
    frame.field_bytes(2, record.resolving_request_id.to_vec())?;
    frame.field_bytes(3, record.displaced_request_id.to_vec())?;
    frame.field_bytes(4, record.resolved_key.clone())?;
    Ok(frame.finish()?)
}

/// Decodes one durable local resolution-audit row for operator inspection.
pub fn decode_drain_lock_resolution_record(
    bytes: &[u8],
) -> FastPathResult<FastPathDrainLockResolutionRecord> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_DRAIN_LOCK_RESOLUTION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let resolving_request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| FastPathError::Invalid("drain lock resolution request id length"))?;
    let displaced_request_id: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| FastPathError::Invalid("drain lock resolution displaced id length"))?;
    let record: FastPathDrainLockResolutionRecord = FastPathDrainLockResolutionRecord {
        epoch: Epoch::new(frame.required_u64(1)?),
        resolving_request_id,
        displaced_request_id,
        resolved_key: frame.required_field(4)?.to_vec(),
    };
    if encode_drain_lock_resolution_record(&record)?.as_slice() != bytes {
        return Err(FastPathError::Invalid(
            "noncanonical drain lock resolution record",
        ));
    }
    Ok(record)
}

fn drain_lock_resolution_key(
    chain: &ChainId,
    epoch: Epoch,
    resolving_request_id: &[u8; 32],
    resolved_key: &[u8],
) -> FastPathResult<Vec<u8>> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"drain-lock-resolution/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    key.extend_from_slice(resolving_request_id);
    key.extend_from_slice(resolved_key);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

fn put_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> FastPathResult<()> {
    if reads
        .insert(key, revision)
        .is_some_and(|prior: StateRevision| prior != revision)
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

/// Independently reconstructs and re-verifies that `member_request_id`
/// belongs to the exact committed `DrainSet` union for `expected`'s
/// `(chain, epoch)`, and that its full publication proof and artifact
/// closure are durably present, folding every read into `reads`. Returns the
/// committed [`DrainSetRecord`], the reconstructed member
/// [`AvailabilityIdentity`] and the validator set used by possession
/// verification. The apply path independently re-reads the validator set for
/// certificate verification; both reads enter its final CAS. See the module documentation for the
/// exact four-part authority this establishes.
#[allow(clippy::too_many_arguments)]
fn verify_drain_member<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    member_request_id: [u8; 32],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> FastPathResult<(DrainSetRecord, AvailabilityIdentity, ValidatorSet)> {
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();

    let validators: ValidatorSet =
        fence_closed_epoch(store, context, domain, resolver, expected, reads)?;

    // (1) the committed DrainSetRecord.
    let record_key: Vec<u8> = drain_set_record_key(&chain, epoch)?;
    let record_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &record_key)?;
    put_read(reads, record_key, record_row.revision())?;
    let record: DrainSetRecord = match record_row.value() {
        Some(bytes) => decode_drain_set_record(bytes)?,
        None if record_row.revision() == StateRevision::INITIAL => {
            return invalid("drain set is not committed for this epoch");
        }
        None => return invalid("drain set record is tombstoned"),
    };
    if record.closed_epoch != epoch || record.drain_union_identity.chain_id != chain {
        return invalid("drain set record context mismatch");
    }

    // (2) this replica's own re-verified local union readiness for the
    // record's exact selected votes.
    let reconstructed: consensus::DrainUnionIdentity = verify_drain_ready_into(
        store,
        context,
        domain,
        resolver,
        expected,
        &record.selected_votes,
        reads,
    )?;
    if reconstructed != record.drain_union_identity {
        return invalid("drain union readiness disagrees with the committed drain set");
    }

    // (3) an immutable per-signer entry naming member_request_id, agreeing
    // byte-for-byte across every selected signer that names it.
    let mut member_identity: Option<AvailabilityIdentity> = None;
    for vote in &record.selected_votes {
        let entry_key: Vec<u8> =
            drain_signer_entry_key(&chain, epoch, vote.validator, &member_request_id)?;
        let entry_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &entry_key)?;
        put_read(reads, entry_key, entry_row.revision())?;
        let Some(bytes) = entry_row.value() else {
            if entry_row.revision() != StateRevision::INITIAL {
                return invalid("drain signer entry is tombstoned");
            }
            continue;
        };
        let identity: AvailabilityIdentity = decode_availability_identity(bytes)?;
        if identity.request_id != member_request_id {
            return invalid("drain signer entry request id mismatch");
        }
        match &member_identity {
            None => member_identity = Some(identity),
            Some(existing) if *existing != identity => {
                return invalid("cross-signer conflicting drain member identity");
            }
            Some(_) => {}
        }
    }
    let identity: AvailabilityIdentity = member_identity.ok_or(FastPathError::Invalid(
        "request id is not a member of the committed drain union",
    ))?;

    // (4) the durably retained, freshly re-verified full proof and artifact
    // closure for that exact identity.
    let reconfirmed: AvailabilityIdentity = verify_drain_possession_into(
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        &validators,
        &identity,
        reads,
    )?;
    if reconfirmed != identity {
        return invalid("drain publication identity mismatch");
    }

    Ok((record, identity, validators))
}

/// Re-reads every displaced local reservation and its originating prepared
/// record under the eventual effects CAS. A matching key alone is not proof
/// that it is an old-epoch partial prepare for the same object version or
/// sender nonce. No unrelated row may be deleted through DrainApply.
#[allow(clippy::too_many_arguments)]
fn verify_partial_prepare_conflicts<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &PublicationContext,
    resolving_request_id: [u8; 32],
    sender: [u8; 32],
    nonce: u64,
    locked_objects: &[ObjectRef],
    resolutions: &[paid_execution::DrainLockResolution],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> FastPathResult<()> {
    let chain: &ChainId = expected.chain_id();
    let epoch: Epoch = expected.epoch();
    let nonce_key: Vec<u8> = fastpath_nonce_lock_key(chain, &sender, epoch)?;
    for resolution in resolutions {
        if resolution.owner_request_id == resolving_request_id {
            return invalid("drain conflict cannot displace its own request");
        }
        let lock_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &resolution.key)?;
        put_read(reads, resolution.key.clone(), lock_row.revision())?;
        let bytes: &[u8] = lock_row
            .value()
            .ok_or(FastPathError::Invalid("drain conflict lock disappeared"))?;
        let conflicting_object: Option<&ObjectRef> = if resolution.key == nonce_key {
            let lock: FastPathNonceLockRecord =
                local_instance_state::decode_fastpath_nonce_lock_record(bytes)?;
            if lock.request_id != resolution.owner_request_id
                || lock.sender != sender
                || lock.epoch != epoch
                || lock.nonce != nonce
            {
                return invalid("drain conflict nonce lock does not match the certified input");
            }
            None
        } else {
            let reference: &ObjectRef = locked_objects
                .iter()
                .find(|reference| {
                    fastpath_lock_key(chain, reference.id).is_ok_and(|key| key == resolution.key)
                })
                .ok_or(FastPathError::Invalid(
                    "drain conflict lock is not a certified input",
                ))?;
            let lock: FastPathLockRecord =
                local_instance_state::decode_fastpath_lock_record(bytes)?;
            if lock.request_id != resolution.owner_request_id
                || lock.object != *reference
                || lock.locked_epoch != epoch
            {
                return invalid("drain conflict object lock does not match the certified input");
            }
            Some(reference)
        };
        let prepared_key: Vec<u8> =
            fastpath_prepared_record_key(chain, &resolution.owner_request_id)?;
        let prepared_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &prepared_key)?;
        put_read(reads, prepared_key, prepared_row.revision())?;
        let prepared_bytes: &[u8] = prepared_row.value().ok_or(FastPathError::Invalid(
            "drain conflict has no local partial prepared record",
        ))?;
        let prepared: records::FastPathPreparedRecord =
            records::decode_fastpath_prepared_record(prepared_bytes)?;
        if prepared.context != *expected
            || prepared.request_id != resolution.owner_request_id
            || prepared.prepared_generation.is_none()
            || conflicting_object
                .is_some_and(|reference| !prepared.locked_objects.contains(reference))
            || (resolution.key == nonce_key && prepared.pending_nonce != nonce)
        {
            return invalid("drain conflict is not the exact local partial prepare");
        }
        let certificate_key: Vec<u8> =
            fastpath_certificate_key(chain, &resolution.owner_request_id)?;
        let certificate_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &certificate_key)?;
        put_read(reads, certificate_key, certificate_row.revision())?;
        if certificate_row.value().is_some() || certificate_row.revision() != StateRevision::INITIAL
        {
            return invalid("drain conflict already has a local certificate outcome");
        }
        let displaced_id: DurableRequestId = DurableRequestId::new(resolution.owner_request_id)
            .map_err(|_| FastPathError::Invalid("invalid displaced request id"))?;
        if store
            .get_request_receipt(context, domain, displaced_id)?
            .is_some()
        {
            return invalid("drain conflict already has a local request receipt");
        }
    }
    Ok(())
}

/// Applies one exact committed `DrainSet` union member's full certificate
/// and original signed intent. See the module documentation for the
/// complete authority and safety argument.
///
/// `drain_created_checkpoint` is a purely local physical bookkeeping value,
/// exactly like [`super::apply_with_recovery`]'s own
/// `recovery_created_checkpoint`: per `docs/architecture/epoch-handoff.md`
/// ("Portable commitment and cut schema"), a handoff-capable admission's
/// signed commitment never depends on any physical creation checkpoint, only
/// on the authenticated semantic execution generation this admission
/// independently re-derives and checks below.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn apply_drain_member<S, E>(
    store: &S,
    blob_store: &dyn BlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
    engine: &E,
    member_request_id: [u8; 32],
    drain_created_checkpoint: u64,
) -> FastPathResult<NodeOutput>
where
    S: StructuredDurableDomainStateStore,
    E: PaidContractEngine + ?Sized,
{
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return invalid("resolver history bound");
    }
    let chain: ChainId = expected.chain_id().clone();
    let epoch: Epoch = expected.epoch();

    let mut drain_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let publication_key: Vec<u8> = drain_publication_key(&chain, epoch, &member_request_id)?;
    let publication_row: VersionedStateValue =
        store.get_versioned_durable(context, domain, &publication_key)?;
    put_read(
        &mut drain_reads,
        publication_key,
        publication_row.revision(),
    )?;
    let publication_bytes: &[u8] = publication_row
        .value()
        .ok_or(FastPathError::Invalid("drain publication proof missing"))?;
    let publication_record: FastPathPublicationRecord =
        decode_fastpath_publication_record(publication_bytes)?;
    if publication_record.context != *expected || publication_record.request_id != member_request_id
    {
        return invalid("drain publication record context or request id mismatch");
    }
    let signed_bytes: Vec<u8> = publication_record.signed_intent.clone();
    let certificate_bytes: Vec<u8> = publication_record.certificate.clone();

    let (authenticated, event_digest, request_id) =
        authenticate_and_identify(resolver, expected, &signed_bytes)?;
    if authenticated.intent().request_id != member_request_id {
        return invalid("drain publication signed intent request id mismatch");
    }
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(output);
    }
    // Fresh work needs the complete committed DrainSet authority. A completed
    // exact replay is receipt-first and must not be re-blocked by a later
    // epoch transition or by a now-stale local ready marker.
    let (_record, identity, _validators): (DrainSetRecord, AvailabilityIdentity, ValidatorSet) =
        verify_drain_member(
            store,
            context,
            domain,
            resolver,
            history,
            expected,
            member_request_id,
            &mut drain_reads,
        )?;
    if publication_record.identity != consensus::encode_availability_identity(&identity)? {
        return invalid("drain publication record identity mismatch");
    }
    if authenticated.intent().context.epoch() != base_policy.context().epoch() {
        return Err(NodeCoreError::EpochMismatch {
            expected: base_policy.context().epoch(),
            actual: authenticated.intent().context.epoch(),
        }
        .into());
    }
    let intent_context: PublicationContext = authenticated.intent().context.clone();
    let original_request_id: [u8; 32] = authenticated.intent().request_id;
    let intent_sender: [u8; 32] = authenticated.intent().sender;
    let intent_nonce: u64 = authenticated.intent().nonce;
    let fee_escrow_creation: FeeEscrowCreationCapability = fee_escrow_creation_capability(
        &intent_context,
        fee_policy,
        intent_sender,
        original_request_id,
        event_digest,
    )?;

    let mut fence_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: local_instance_state::FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, &mut fence_reads)?;
    if epoch_record.current_epoch != intent_context.epoch() {
        return Err(NodeCoreError::EpochMismatch {
            expected: epoch_record.current_epoch,
            actual: intent_context.epoch(),
        }
        .into());
    }

    let certificate: FastCertificate = consensus::decode_fast_certificate(&certificate_bytes)?;
    let validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        &intent_context,
        &epoch_record,
        &mut fence_reads,
    )?;
    require_fee_claim_capacity(&validator_set)?;
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        intent_context.protocol_version(),
        intent_context.epoch(),
        validator_set,
    )?;
    certifier.verify_certificate(&certificate, &FastPathEd25519Verifier)?;
    if certificate.chain_id != chain
        || certificate.protocol_version != intent_context.protocol_version()
        || certificate.epoch != intent_context.epoch()
        || certificate.tx_hash != event_digest
    {
        return invalid("drain certificate does not match its signed intent");
    }

    // No local prepared record lookup: X's own prepare may never have
    // existed on this replica. `NonceMode::DrainApply` alone permits (and
    // resolves) a conflicting local partial prepare on the exact
    // object/sender-epoch locks this admission's own inputs touch, instead
    // of failing closed like ordinary `NonceMode::RecoveryApply`.
    let admission: PaidAdmissionOutput = build_paid_admission(
        store,
        blob_store,
        context,
        domain,
        resolver,
        history,
        base_policy,
        fee_policy,
        Some(&fee_escrow_creation),
        engine,
        authenticated,
        event_digest,
        drain_created_checkpoint,
        NonceMode::DrainApply(DrainApplyPermit::new_after_verified_member()),
    )?;
    logical_generation::require_application_admissible(
        &admission.logical.profile,
        admission.logical.derived.as_ref(),
    )?;
    let pending_nonce_write: &PendingSenderNonceWrite = admission
        .nonce_write
        .as_ref()
        .ok_or(FastPathError::Invalid("drain apply must advance the nonce"))?;
    let pending_nonce_bytes: Vec<u8> = pending_nonce_write.record.encode()?;
    let (commitment_witness_bytes, fresh_commitment): (Vec<u8>, Digest32) =
        commitment::compute_with_envelope(
            resolver,
            intent_context.epoch(),
            admission.event_digest,
            &admission.result_bytes,
            &admission.outcome.created_authorities,
            &admission.head_reads,
            &admission.object_mutations,
            &admission.reads,
            &admission.state_mutations,
            &pending_nonce_write.key,
            pending_nonce_write.read_revision,
            &pending_nonce_bytes,
            admission.logical.derived.as_ref(),
        )?;
    if fresh_commitment != certificate.execution_effects_hash {
        return invalid("drain re-derived commitment no longer matches the certificate");
    }
    let fresh_locked_objects_digest: Digest32 = compute_locked_objects_digest(
        resolver,
        &chain,
        intent_context.protocol_version(),
        intent_context.epoch(),
        &admission.locked_objects,
    )?;
    if fresh_locked_objects_digest != certificate.locked_objects_digest {
        return invalid("drain re-derived locked-object digest no longer matches the certificate");
    }

    let PaidAdmissionOutput {
        result_bytes,
        success,
        reads: admission_reads,
        head_reads,
        state_mutations: mut mutations,
        object_mutations,
        outcome,
        nonce_write,
        locked_objects,
        drain_resolved_locks,
        ..
    } = admission;

    // Boundary defense in depth: admission is allowed to resolve only exact
    // object/sender-epoch lock keys this certificate itself admits. A future
    // change to the shared paid pipeline cannot smuggle an unrelated
    // fastpath mutation into this post-Freeze special case merely because
    // such local reservation bytes are excluded from the signed commitment.
    let mut allowed_lock_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    allowed_lock_keys.insert(fastpath_nonce_lock_key(
        &chain,
        &intent_sender,
        intent_context.epoch(),
    )?);
    for reference in &locked_objects {
        allowed_lock_keys.insert(fastpath_lock_key(&chain, reference.id)?);
    }
    let mut staged_lock_deletes: BTreeSet<Vec<u8>> = BTreeSet::new();
    for mutation in &mutations {
        if mutation
            .key()
            .starts_with(local_instance_state::FASTPATH_STATE_PREFIX)
            && (!allowed_lock_keys.contains(mutation.key())
                || !matches!(mutation.mutation(), StateMutation::Delete)
                || !staged_lock_deletes.insert(mutation.key().to_vec()))
        {
            return invalid("drain admission staged an unauthorized fast-path mutation");
        }
    }
    if drain_resolved_locks
        .iter()
        .any(|resolution| !staged_lock_deletes.contains(&resolution.key))
    {
        return invalid("drain conflict resolution is missing its exact staged lock delete");
    }

    let mut tx_reads: BTreeMap<Vec<u8>, StateRevision> = admission_reads;
    merge_apply_reads(&mut tx_reads, fence_reads)?;
    merge_apply_reads(&mut tx_reads, drain_reads)?;
    verify_partial_prepare_conflicts(
        store,
        context,
        domain,
        expected,
        original_request_id,
        intent_sender,
        intent_nonce,
        &locked_objects,
        &drain_resolved_locks,
        &mut tx_reads,
    )?;

    let nonce: PendingSenderNonceWrite =
        nonce_write.ok_or(FastPathError::Invalid("drain apply must advance the nonce"))?;
    tx_reads.insert(nonce.key.clone(), nonce.read_revision);
    mutations.push(StateMutationEntry::new(
        nonce.key,
        StateMutation::Put(nonce.record.encode()?),
    )?);
    let nonce_lock_key: Vec<u8> =
        fastpath_nonce_lock_key(&chain, &intent_sender, intent_context.epoch())?;
    if !tx_reads.contains_key(&nonce_lock_key) {
        return invalid("drain apply missing nonce-lock read");
    }

    let certificate_key: Vec<u8> = fastpath_certificate_key(&chain, &original_request_id)?;
    let observed_certificate: VersionedStateValue =
        store.get_versioned_durable(context, domain, &certificate_key)?;
    if observed_certificate.value().is_some() {
        return invalid("drain certificate record already exists");
    }
    tx_reads.insert(certificate_key.clone(), observed_certificate.revision());
    let certificate_record: FastPathCertificateRecord = FastPathCertificateRecord {
        request_id: original_request_id,
        certificate: certificate_bytes.clone(),
    };
    mutations.push(StateMutationEntry::new(
        certificate_key,
        StateMutation::Put(records::encode_fastpath_certificate_record(
            &certificate_record,
        )?),
    )?);

    let settlement_key: Vec<u8> = fastpath_settlement_key(&chain, &original_request_id)?;
    let observed_settlement: VersionedStateValue =
        store.get_versioned_durable(context, domain, &settlement_key)?;
    if observed_settlement.value().is_some() {
        return invalid("drain settlement record already exists");
    }
    tx_reads.insert(settlement_key.clone(), observed_settlement.revision());
    let charged = outcome.result.charged.as_ref();
    let settlement_record: FastPathSettlementRecord = FastPathSettlementRecord {
        context: intent_context.clone(),
        request_id: original_request_id,
        generation: u64::from(charged.is_some()),
        resource_id: charged.map(|_| fee_resource_id(fee_policy)).transpose()?,
        fee_output: charged.map(|charged| charged.fee_output.clone()),
        fee_output_epoch: charged.map(|_| intent_context.epoch()),
        total_amount: charged.map(|charged| charged.actual.get()),
        shares: charged
            .map(|charged| validator_fee_shares(certifier.validator_set(), charged.actual.get()))
            .transpose()?
            .unwrap_or_default(),
    };
    mutations.push(StateMutationEntry::new(
        settlement_key,
        StateMutation::Put(records::encode_fastpath_settlement_record(
            &settlement_record,
        )?),
    )?);

    let commitment_witness_key: Vec<u8> =
        fastpath_commitment_witness_key(&chain, &original_request_id)?;
    let observed_commitment_witness: VersionedStateValue =
        store.get_versioned_durable(context, domain, &commitment_witness_key)?;
    if observed_commitment_witness.revision() != StateRevision::INITIAL
        || observed_commitment_witness.value().is_some()
    {
        return invalid("drain commitment witness already exists");
    }
    tx_reads.insert(
        commitment_witness_key.clone(),
        observed_commitment_witness.revision(),
    );
    mutations.push(StateMutationEntry::new(
        commitment_witness_key,
        StateMutation::Put(commitment_witness_bytes),
    )?);

    // DR-0154 §2's "Keep an internal resolution audit": one immutable row per
    // conflicting local partial-prepare lock this admission's own required
    // inputs resolved (already staged for deletion inside `mutations` via
    // `build_paid_admission`'s own `reclaimed_lock_keys` pipeline). Never a
    // lock outside this admission's own `order`/nonce -- "no sweeping
    // unrelated locks".
    for resolution in &drain_resolved_locks {
        let audit_key: Vec<u8> =
            drain_lock_resolution_key(&chain, epoch, &original_request_id, &resolution.key)?;
        let audit_row: VersionedStateValue =
            store.get_versioned_durable(context, domain, &audit_key)?;
        if audit_row.value().is_some() || audit_row.revision() != StateRevision::INITIAL {
            return invalid("drain lock resolution audit row already exists");
        }
        tx_reads.insert(audit_key.clone(), audit_row.revision());
        let audit_record: FastPathDrainLockResolutionRecord = FastPathDrainLockResolutionRecord {
            epoch,
            resolving_request_id: original_request_id,
            displaced_request_id: resolution.owner_request_id,
            resolved_key: resolution.key.clone(),
        };
        mutations.push(StateMutationEntry::new(
            audit_key,
            StateMutation::Put(encode_drain_lock_resolution_record(&audit_record)?),
        )?);
    }

    let assertions: Vec<StateReadAssertion> = tx_reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;
    let output: NodeOutput = NodeOutput::new(
        vec![NodeResponse::new(
            request_id,
            if success {
                NodeResponseStatus::Accepted
            } else {
                NodeResponseStatus::Rejected
            },
            Some(result_bytes),
        )?],
        Vec::new(),
    )?;
    let dedup: NodeDedupRecord =
        NodeDedupRecord::new(request_id, event_digest, output.responses().to_vec())?;
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(*request_id.as_bytes())
            .map_err(|_| FastPathError::Invalid("request id"))?,
        event_digest,
        dedup.encode()?,
    )?;
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(head_reads, object_mutations)?,
        receipt,
        None,
    )?;
    match store.commit_invocation(context, transaction) {
        DurableCommitOutcome::Committed => Ok(output),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(FastPathError::Node(NodeCoreError::StateConflict)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ObjectConflict {
            object_id,
            ..
        }) => Err(FastPathError::Node(NodeCoreError::ObjectConflict {
            object_id,
        })),
        DurableCommitOutcome::Rejected(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        DurableCommitOutcome::Indeterminate(reason) => Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}

#[cfg(test)]
mod tests;
