//! Shared destination comparisons of DR-0189 Sections 6.2, 7 and 8. Every
//! check compares destination bytes with freshly verified evidence; none
//! constructs authority on its own.

use super::*;
use crate::epoch_transition::{DerivedActivation, EpochTransitionError, derive_activation_set};
use crate::genesis::VerifiedGenesisRoot;
use crate::local_instance_state::{
    FastPathEpochRecord, encode_fastpath_epoch_record, execution_policy_key_for_profile,
    fastpath_epoch_record_key, fastpath_validator_set_key, paid_fee_policy_key,
};
use crate::ordered_economics::engine::{
    ordered_candidate_record_key, ordered_committed_proof_key, ordered_outcome_key,
    ordered_request_header_key,
};
use crate::publication::publication_policy_key_for_profile;
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::{
    DurableRequestId, DurableRequestReceipt, StructuredDurableDomainStateStore,
    SuccessorServingRecord, VersionedStateReader, VersionedStateValue,
    decode_successor_serving_record,
};
use validator_set::ValidatorInfo;

fn invalid(message: &'static str) -> SuccessorActivationError {
    SuccessorActivationError::Invalid(message)
}

pub(super) fn epoch_transition_error(error: EpochTransitionError) -> SuccessorActivationError {
    match error {
        EpochTransitionError::Node(error) => SuccessorActivationError::Node(Box::new(error)),
        _ => invalid("successor activation set derivation refused"),
    }
}

/// The physical namespace validator must be a verified e+1 member whose
/// registered Ed25519 key is exactly the local key. A retired predecessor
/// member is refused here only as a consensus signer.
pub(super) fn require_local_member(
    evidence: &VerifiedSuccessorActivation,
    namespace_validator: ValidatorId,
    public_key: [u8; 32],
) -> Result<(), SuccessorActivationError> {
    let member: &ValidatorInfo = evidence
        .policy_inputs
        .validator_set
        .get(namespace_validator)
        .ok_or(invalid(
            "namespace validator is not a verified successor member",
        ))?;
    if member.signature_scheme != SignatureSchemeId::Ed25519
        || member.public_key.as_slice() != public_key.as_slice()
    {
        return Err(invalid(
            "successor member key differs from the local signing key",
        ));
    }
    Ok(())
}

/// Section 7 / Section 8 step 3: record fields 1-4 and 6 equal the verified
/// subject, manifest, binding, complete progress and anchor, field 5 only
/// decodes (a used creation token is never compared with a fresh one), field
/// 7 is the namespace validator and field 8 the local member key. The raw
/// observation must agree with its own record.
pub(super) fn require_installed_record(
    evidence: &VerifiedSuccessorActivation,
    observation: &SuccessorServingObservation,
    namespace_validator: ValidatorId,
    public_key: [u8; 32],
) -> Result<(), SuccessorActivationError> {
    let record: SuccessorServingRecord = decode_successor_serving_record(&observation.record)?;
    if record.subject != evidence.subject_digest
        || record.manifest != evidence.manifest_digest
        || &record.binding != evidence.import.binding()
        || &record.progress != evidence.import.complete_progress()
        || record.anchor != evidence.policy_inputs.anchor
        || record.validator != namespace_validator
        || record.public_key != public_key
        || observation.binding != record.binding
        || observation.progress != record.progress
    {
        return Err(invalid(
            "installed successor serving record differs from verified evidence",
        ));
    }
    Ok(())
}

/// Exact verified bytes of the four e+1 rows and the successor epoch record,
/// re-derived through the existing activation-set derivation, which reads
/// the carried-forward epoch-e paid fee policy as a real dependency.
pub(super) struct SuccessorRows {
    pub(super) next_rows: [(Vec<u8>, Vec<u8>); 4],
    pub(super) epoch_record_key: Vec<u8>,
    pub(super) epoch_record: Vec<u8>,
    pub(super) derived: DerivedActivation,
}

pub(super) fn derive_successor_rows<S: VersionedStateReader + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    root: &VerifiedGenesisRoot,
    evidence: &VerifiedSuccessorActivation,
) -> Result<SuccessorRows, SuccessorActivationError> {
    let inputs: &SuccessorPolicyInputs = &evidence.policy_inputs;
    let outgoing: &PublicationContext = &evidence.outgoing_context;
    let derived: DerivedActivation = derive_activation_set(
        store,
        operation,
        inputs.domain,
        root.genesis_resolver(),
        outgoing.chain_id(),
        outgoing.protocol_version(),
        outgoing.epoch(),
        inputs.context.epoch(),
        &evidence.next_members,
    )
    .map_err(epoch_transition_error)?;
    if derived.next_validator_set_digest != evidence.subject.successor_set_digest
        || derived.activation_set.next_context != inputs.context
    {
        return Err(invalid("derived successor set differs from the verified subject"));
    }
    let next: &PublicationContext = &inputs.context;
    let publication_key: Vec<u8> = publication_policy_key_for_profile(next, 4)
        .map_err(|_| invalid("successor publication policy key"))?;
    let next_rows: [(Vec<u8>, Vec<u8>); 4] = [
        (
            fastpath_validator_set_key(next)?,
            derived.activation_set.validator_set_record.clone(),
        ),
        (
            execution_policy_key_for_profile(next, 4)?,
            derived.activation_set.execution_policy.clone(),
        ),
        (
            paid_fee_policy_key(next)?,
            derived.activation_set.paid_fee_policy.clone(),
        ),
        (
            publication_key,
            derived.activation_set.publication_policy.clone(),
        ),
    ];
    let epoch_record: Vec<u8> = encode_fastpath_epoch_record(&FastPathEpochRecord {
        current_epoch: next.epoch(),
        current_validator_set_digest: evidence.subject.successor_set_digest,
        previous_epoch: Some(outgoing.epoch()),
        activated_at_checkpoint: evidence.subject.seal_height,
    })?;
    Ok(SuccessorRows {
        next_rows,
        epoch_record_key: fastpath_epoch_record_key(outgoing.chain_id())?,
        epoch_record,
        derived,
    })
}

fn require_exact<S: VersionedStateReader + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: &[u8],
    expected: &[u8],
    message: &'static str,
) -> Result<StateRevision, SuccessorActivationError> {
    let observed: VersionedStateValue = store.read_versioned_state(operation, domain, key)?;
    if observed.value() != Some(expected) {
        return Err(invalid(message));
    }
    Ok(observed.revision())
}

/// Exact DurableRequestId of the verified Seal candidate.
pub(super) fn seal_request_id(
    evidence: &VerifiedSuccessorActivation,
) -> Result<DurableRequestId, SuccessorActivationError> {
    DurableRequestId::new(evidence.seal.request_id)
        .map_err(|_| invalid("Seal request id is not a durable request id"))
}

/// Section 7 / Section 8 steps 5 and 6 over an installed successor.
///
/// The four e+1 rows must equal a fresh derivation and the epoch record must
/// equal exactly the verified successor record, not its epoch alone. Those
/// five rows plus the carried-forward epoch-e fee policy row become the
/// returned deciding CAS reads. The immutable Seal closure (proofs T+1..h,
/// Seal candidate, header, outcome and original receipt) is compared by
/// fenced exact reads and is deliberately not added to the CAS set: no e+1
/// path writes those keys. Advanced business inventory and the singleton
/// safety rows are never compared.
pub(super) fn require_installed_closure<S: StructuredDurableDomainStateStore + ?Sized>(
    store: &S,
    operation: &DurableOperationContext,
    evidence: &VerifiedSuccessorActivation,
    rows: &SuccessorRows,
) -> Result<BTreeMap<Vec<u8>, StateRevision>, SuccessorActivationError> {
    let domain: AtomicityDomainId = evidence.policy_inputs.domain;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    for (key, expected) in &rows.next_rows {
        let revision: StateRevision = require_exact(
            store,
            operation,
            domain,
            key,
            expected,
            "installed successor policy or set row differs from verified derivation",
        )?;
        reads.insert(key.clone(), revision);
    }
    let epoch_revision: StateRevision = require_exact(
        store,
        operation,
        domain,
        &rows.epoch_record_key,
        &rows.epoch_record,
        "installed epoch record is not the exact verified successor record",
    )?;
    reads.insert(rows.epoch_record_key.clone(), epoch_revision);
    if reads
        .insert(
            rows.derived.current_fee_policy_key.clone(),
            rows.derived.current_fee_policy_revision,
        )
        .is_some()
    {
        return Err(invalid("carried-forward fee policy aliases a successor row"));
    }
    let chain: &protocol_types::ChainId = evidence.outgoing_context.chain_id();
    let outgoing: protocol_types::Epoch = evidence.outgoing_context.epoch();
    for (height, bytes) in &evidence.suffix_proofs {
        require_exact(
            store,
            operation,
            domain,
            &ordered_committed_proof_key(chain, outgoing, *height)?,
            bytes,
            "installed Seal suffix proof differs from the verified variant",
        )?;
    }
    let seal: &SealClosure = &evidence.seal;
    require_exact(
        store,
        operation,
        domain,
        &ordered_candidate_record_key(chain, seal.candidate_digest)?,
        &seal.candidate,
        "installed Seal candidate differs",
    )?;
    require_exact(
        store,
        operation,
        domain,
        &ordered_request_header_key(chain, &seal.request_id)?,
        &seal.header,
        "installed Seal request header differs",
    )?;
    require_exact(
        store,
        operation,
        domain,
        &ordered_outcome_key(chain, &seal.request_id)?,
        &seal.outcome,
        "installed Seal outcome differs",
    )?;
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(operation, domain, seal_request_id(evidence)?)?
        .ok_or(invalid("installed original Seal receipt is missing"))?;
    if receipt.canonical_bytes() != seal.receipt.as_slice()
        || receipt.event_digest() != seal.receipt_event_digest
    {
        return Err(invalid("installed original Seal receipt differs"));
    }
    Ok(reads)
}
