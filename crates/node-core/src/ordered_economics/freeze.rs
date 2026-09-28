//! DR-0154 "One ordered epoch-control chain": the closed-admission `Freeze`
//! control command.
//!
//! `Freeze` is an [`OrderedOperationKind`] exactly like `FeeClaim` or
//! `BondLifecycle`: it occupies the same economic-height proposal slot and is
//! committed through the existing shared three-chain
//! `ChainedHotStuff` rules -- the same leader/view/lock/QC machinery every
//! other ordered candidate already uses. There is no separate signature or
//! parallel voting chain: a *proposed* `Freeze` changes nothing, and only a
//! *committed* one -- decided in [`super::preflight`] and applied here, after
//! the same [`super::authenticate_candidate`]/preflight sequence every other
//! kind goes through -- installs the durable [`AdmissionClosureRecord`].
//! Quorum ordering is not a substitute for the signed-genesis epoch-end
//! height and the advisory next set's committed eligibility. Both are
//! checked before honest proposal/vote and again at committed execution.
//!
//! Scope of this slice (DR-0154 Delivery 3, partial): closing admission and
//! refusing business after closure. Fresh publication-retention ACKs are
//! fenced in `crate::fast_path::publication`. `DrainSet`, `Seal` and the
//! next-set readiness/activation sequence are **not** implemented here; see
//! the module-level remaining-integration note in [`super`].
use super::*;
use crate::epoch_transition::{self, EpochTransitionError, NextSetEligibilityError};
use canonical_encoding::encode_chain_id;
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use fast_path::records::{
    FastPathValidatorSetRecord, MAX_FASTPATH_ACTIVE_VALIDATORS,
    decode_fastpath_validator_set_record, encode_fastpath_validator_set_record,
};
use protocol_types::SignatureSchemeId;
use validator_set::{ValidatorInfo, ValidatorSet};

/// Canonical frame type of an encoded [`FreezeIntent`] (an
/// [`OrderedCandidate::intent`] body for [`OrderedOperationKind::Freeze`]).
///
/// Allocated from the `0x6454..=0x645D` block the repository-wide sweep
/// reserved for "the concurrently owned retention/control/cut work"
/// (`crate::logical_generation::LOGICAL_PROFILE_RECORD_FRAME_TYPE`'s own
/// doc comment). `0x6455`/`0x6456` are reserved by the concurrently owned
/// execution-free publication slice and are not reused here.
const FREEZE_INTENT_TYPE: u16 = 0x6454;
/// Canonical frame type of an encoded [`AdmissionClosureRecord`]. Allocated
/// from the same reserved block as [`FREEZE_INTENT_TYPE`].
const ADMISSION_CLOSURE_RECORD_TYPE: u16 = 0x6457;
const ENCODING_VERSION: u16 = 1;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// The candidate body for [`OrderedOperationKind::Freeze`].
///
/// Deliberately carries no signature: unlike a user-originated request
/// (`FeeClaim`, `BondLifecycle`), `Freeze` is a control decision whose
/// authorization is the signed genesis height rule and an eligible next set,
/// checked by honest outgoing signers before their ordinary HotStuff votes.
/// A committed quorum orders the authorized decision; it is not the warrant
/// by itself. `context` and `request_id` duplicate
/// [`OrderedCandidate::context`]/[`OrderedCandidate::request_id`] so
/// [`authenticate_freeze`](super::policy) can cross-check the two bindings
/// exactly like every other kind's intent envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreezeIntent {
    /// Chain/protocol/epoch replay boundary; must equal the candidate's own.
    pub context: PublicationContext,
    /// Replay identity; must equal the candidate's own request id.
    pub request_id: [u8; 32],
    /// Canonical, advisory set for the immediately following epoch. Freeze
    /// proves at least one viable continuation, but does not select the final
    /// membership before readiness and Seal.
    pub advisory_next_set: FastPathValidatorSetRecord,
}

pub(crate) fn validate_freeze_intent_structure(intent: &FreezeIntent) -> Result<(), NodeCoreError> {
    if intent.request_id == [0u8; 32] {
        return Err(invalid("freeze intent request id must not be zero"));
    }
    let next_epoch: u64 = intent
        .context
        .epoch()
        .get()
        .checked_add(1)
        .ok_or(invalid("freeze next epoch overflows"))?;
    let next_context: &PublicationContext = &intent.advisory_next_set.context;
    if next_context.chain_id() != intent.context.chain_id()
        || next_context.protocol_version() != intent.context.protocol_version()
        || next_context.epoch() != Epoch::new(next_epoch)
    {
        return Err(invalid(
            "freeze advisory set is not bound to the next epoch",
        ));
    }
    let validators = &intent.advisory_next_set.validators;
    if validators.is_empty() || validators.len() > MAX_FASTPATH_ACTIVE_VALIDATORS {
        return Err(invalid("freeze advisory set has invalid member count"));
    }
    if validators.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(invalid("freeze advisory set is not strictly ordered"));
    }
    let mut info: Vec<ValidatorInfo> = Vec::with_capacity(validators.len());
    for validator in validators {
        if validator.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(invalid("freeze advisory set supports only Ed25519"));
        }
        info.push(ValidatorInfo {
            id: validator.id,
            voting_power: validator.voting_power,
            signature_scheme: validator.signature_scheme,
            public_key: validator.public_key.clone(),
        });
    }
    ValidatorSet::new(next_context.epoch(), info)
        .map_err(|_| invalid("freeze advisory validator set is invalid"))?;
    Ok(())
}

/// Encodes frame `0x6454/v1`.
pub fn encode_freeze_intent(intent: &FreezeIntent) -> Result<Vec<u8>, NodeCoreError> {
    validate_freeze_intent_structure(intent)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(FREEZE_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&intent.context)
            .map_err(|_| invalid("invalid freeze intent context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(
        3,
        encode_fastpath_validator_set_record(&intent.advisory_next_set)?,
    )?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6454/v1`.
pub fn decode_freeze_intent(bytes: &[u8]) -> Result<FreezeIntent, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FREEZE_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("freeze intent request id length"))?;
    let intent = FreezeIntent {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("freeze intent context"))?,
        request_id,
        advisory_next_set: decode_fastpath_validator_set_record(frame.required_field(3)?)?,
    };
    if encode_freeze_intent(&intent)? != bytes {
        return Err(invalid("noncanonical freeze intent"));
    }
    Ok(intent)
}

/// The independently checked Freeze warrant. The minimum height is pinned by
/// signed genesis and the proposal's actual consensus block height, never a
/// candidate-declared number. The advisory set must be an executable next
/// epoch activation candidate, and each of its members must be eligible in
/// the current committed bond/policy state. The signer calls this before
/// exposing a proposal or vote; committed execution calls it again through
/// the staging store, whose observed rows become final CAS assertions.
pub(crate) fn require_freeze_warrant<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
    block_height: u64,
) -> Result<(), OrderedEconomicsError> {
    let minimum: u64 = env.policy.minimum_freeze_block_height();
    if minimum == 0 {
        return Err(OrderedEconomicsError::Prerequisite(
            "signed genesis does not enable freeze",
        ));
    }
    if block_height < minimum {
        return Err(OrderedEconomicsError::Refused(
            OrderedRefusal::PrematureFreeze,
        ));
    }
    super::preflight::require_live_authority(store, context, env)?;
    let intent: FreezeIntent = decode_freeze_intent(&candidate.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid freeze candidate intent"))?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "freeze candidate context or request id mismatch",
        ));
    }
    let current_epoch: Epoch = env.policy.context().epoch();
    let next_epoch: Epoch = intent.advisory_next_set.context.epoch();
    epoch_transition::derive_activation_set(
        store,
        context,
        env.policy.domain(),
        env.resolver,
        env.policy.context().chain_id(),
        env.policy.context().protocol_version(),
        current_epoch,
        next_epoch,
        &intent.advisory_next_set.validators,
    )
    .map_err(|error: EpochTransitionError| match error {
        EpochTransitionError::Node(error) => OrderedEconomicsError::Node(error),
        _ => OrderedEconomicsError::Prerequisite(
            "freeze next epoch activation prerequisites are unavailable",
        ),
    })?;
    epoch_transition::check_next_set_eligibility(
        store,
        context,
        env.policy.domain(),
        env.policy.context().chain_id(),
        current_epoch,
        &intent.advisory_next_set.validators,
    )
    .map_err(|error: NextSetEligibilityError| match error {
        NextSetEligibilityError::Ineligible => {
            OrderedEconomicsError::Refused(OrderedRefusal::IneligibleNextSet)
        }
        NextSetEligibilityError::Prerequisite => OrderedEconomicsError::Prerequisite(
            "freeze advisory next set lacks a committed eligibility prerequisite",
        ),
        NextSetEligibilityError::Node(error) => OrderedEconomicsError::Node(error),
    })
}

/// The durable, per-chain-and-epoch closed-admission marker DR-0154's
/// "Freeze and fix authenticated frontiers" requires.
///
/// Installed exactly once by the first committed `Freeze` candidate in an
/// epoch. Its
/// presence is the sole fact every admission gate this delivery closes
/// (ordinary fast-path prepare/apply, direct/local paid mutation, local
/// publication, and every ordered-economics business kind) consults. This
/// initial profile never removes it. The next epoch has a distinct key, so
/// admission can reopen at the next epoch without erasing the historical
/// closure. The older standalone epoch-transition route is refused for a
/// v2-bound store; only the future ordered `DrainSet`/`Seal`/Activate path may
/// advance it. Historical v1 transition behavior remains separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionClosureRecord {
    /// The epoch admission was closed for.
    pub closed_epoch: Epoch,
    /// The committed `Freeze` candidate's own replay identity, retained for
    /// audit; never re-derived from anything else.
    pub request_id: [u8; 32],
    /// The ordered-economics block height at which `Freeze` committed.
    pub closed_at_block_height: u64,
}

/// Encodes frame `0x6457/v1`.
pub fn encode_admission_closure_record(
    record: &AdmissionClosureRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ADMISSION_CLOSURE_RECORD_TYPE, ENCODING_VERSION);
    frame.field_u64(1, record.closed_epoch.get())?;
    frame.field_bytes(2, record.request_id.to_vec())?;
    frame.field_u64(3, record.closed_at_block_height)?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6457/v1`.
pub fn decode_admission_closure_record(
    bytes: &[u8],
) -> Result<AdmissionClosureRecord, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(ADMISSION_CLOSURE_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("admission closure record request id length"))?;
    let record = AdmissionClosureRecord {
        closed_epoch: Epoch::new(frame.required_u64(1)?),
        request_id,
        closed_at_block_height: frame.required_u64(3)?,
    };
    if encode_admission_closure_record(&record)? != bytes {
        return Err(invalid("noncanonical admission closure record"));
    }
    Ok(record)
}

/// Per-chain-and-epoch key for [`AdmissionClosureRecord`], reserved under
/// [`super::engine::ORDERED_ECONOMICS_STATE_PREFIX`] -- already covered by
/// [`local_instance_state::is_reserved`]'s generic `se/instances/` prefix
/// check, so no contract or generic transactional plan can read or write it.
pub(crate) fn admission_closure_key(
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = super::engine::ORDERED_ECONOMICS_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"freeze/");
    key.extend(encode_chain_id(chain)?);
    key.extend_from_slice(&epoch.get().to_be_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Reads the durable closure record for `chain`, if any, recording the read
/// as a CAS precondition exactly like every other ordered-economics row this
/// module's callers observe.
pub(crate) fn read_admission_closure<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    epoch: Epoch,
) -> Result<Option<AdmissionClosureRecord>, NodeCoreError> {
    let key = admission_closure_key(chain, epoch)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    match observed.value() {
        Some(bytes) => {
            let record: AdmissionClosureRecord = decode_admission_closure_record(bytes)?;
            if record.closed_epoch != epoch {
                return Err(invalid("admission closure epoch disagrees with its key"));
            }
            Ok(Some(record))
        }
        None if observed.revision() == StateRevision::INITIAL => Ok(None),
        None => Err(invalid("admission closure record is tombstoned")),
    }
}

/// Shared admission gate every non-ordered-economics mutation path
/// (`crate::mutation_fence::fence_current_epoch`, and local publication's
/// direct call into `crate::mutation_fence::fence_epoch_state`) consults
/// through [`fence_admission_open`]. Fails closed once a committed `Freeze`
/// has installed [`AdmissionClosureRecord`] for `chain`: stop new prepares,
/// direct local/paid mutations and construction of fresh economic candidates.
/// Publication-retention ACKs use this gate after exact retained-ACK replay.
///
/// This is a distinct, lower-level check from
/// [`super::preflight::preflight`]'s own closed-admission refusal: this one
/// stops with a plain [`NodeCoreError`] (there is no ordered-economics
/// candidate/request id here to attach a typed [`super::OrderedRefusal`]
/// to), while an ordered-economics business candidate itself is refused
/// deterministically, without ever reaching its handler's own call into this
/// function.
pub(crate) fn fence_admission_open<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    epoch: Epoch,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let key = admission_closure_key(chain, epoch)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(previous_revision) = reads.insert(key, observed.revision())
        && previous_revision != observed.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    if let Some(bytes) = observed.value() {
        let record: AdmissionClosureRecord = decode_admission_closure_record(bytes)?;
        if record.closed_epoch != epoch {
            return Err(invalid("admission closure epoch disagrees with its key"));
        }
        return Err(invalid(
            "admission closed by a committed ordered-economics epoch freeze",
        ));
    }
    if observed.revision() != StateRevision::INITIAL {
        return Err(invalid("admission closure record is tombstoned"));
    }
    Ok(())
}

/// Executes a committed `Freeze` candidate against `staging`.
///
/// [`super::preflight::preflight`] already refused this candidate with
/// [`super::OrderedRefusal::AlreadyFrozen`] if [`AdmissionClosureRecord`] was
/// already present, so this handler only ever runs while the row is
/// genuinely absent: it installs the record, atomically closing admission,
/// and returns an accepted response. It never touches an object, a
/// sender-nonce row, or any other business state -- "Retention does not
/// execute WASM again, move objects or custody, charge fees, advance the
/// sender nonce, release locks or create an original user receipt" applies
/// equally to `Freeze` itself: it is pure control.
pub(crate) fn handle_freeze_ordered<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    candidate: &OrderedCandidate,
    block_height: u64,
) -> Result<NodeOutput, NodeCoreError> {
    let key = admission_closure_key(chain, candidate.context.epoch())?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if observed.value().is_some() || observed.revision() != StateRevision::INITIAL {
        // Preflight already proves this is unreachable in the ordinary
        // sequence (it would have refused with `AlreadyFrozen` first); fail
        // closed rather than silently accepting a second closure.
        return Err(invalid("freeze admission closure record already installed"));
    }
    let record = AdmissionClosureRecord {
        closed_epoch: candidate.context.epoch(),
        request_id: candidate.request_id,
        closed_at_block_height: block_height,
    };
    let mutation = StateMutationEntry::new(
        key.clone(),
        StateMutation::Put(encode_admission_closure_record(&record)?),
    )?;
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![StateReadAssertion::new(key, observed.revision())?])?,
        AtomicStateMutationSet::new(vec![mutation])?,
    )?;
    match store.commit_durable(context, transaction) {
        DurableCommitOutcome::Committed => {}
        DurableCommitOutcome::Rejected(reason) => {
            return Err(NodeCoreError::DurableCommitRejected(reason));
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            return Err(NodeCoreError::DurableCommitIndeterminate(reason));
        }
    }
    let response = NodeResponse::new(
        RequestId::new(candidate.request_id)?,
        NodeResponseStatus::Accepted,
        None,
    )?;
    NodeOutput::new(vec![response], Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, ProtocolVersion, ValidatorId};
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };

    fn context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("ordered-economics-freeze-tests").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(3),
        )
        .unwrap()
    }

    fn next_set() -> FastPathValidatorSetRecord {
        FastPathValidatorSetRecord {
            context: PublicationContext::new(
                context().chain_id().clone(),
                context().protocol_version(),
                Epoch::new(4),
            )
            .unwrap(),
            validators: vec![fast_path::FastPathValidatorEntry {
                id: ValidatorId::new([7; 32]),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: vec![7; 32],
            }],
        }
    }

    #[test]
    fn freeze_intent_round_trips_and_rejects_a_zero_request_id() {
        let intent = FreezeIntent {
            context: context(),
            request_id: [9; 32],
            advisory_next_set: next_set(),
        };
        let bytes = encode_freeze_intent(&intent).unwrap();
        assert_eq!(decode_freeze_intent(&bytes).unwrap(), intent);

        let zero = FreezeIntent {
            context: context(),
            request_id: [0; 32],
            advisory_next_set: next_set(),
        };
        assert!(encode_freeze_intent(&zero).is_err());
    }

    #[test]
    fn freeze_intent_decode_rejects_wrong_frame_type() {
        let mut frame = CanonicalStruct::new(0x1234, ENCODING_VERSION);
        frame.field_bytes(1, vec![1, 2, 3]).unwrap();
        let bytes = frame.finish().unwrap();
        assert!(decode_freeze_intent(&bytes).is_err());
    }

    #[test]
    fn admission_closure_record_round_trips() {
        let record = AdmissionClosureRecord {
            closed_epoch: Epoch::new(4),
            request_id: [5; 32],
            closed_at_block_height: 7,
        };
        let bytes = encode_admission_closure_record(&record).unwrap();
        assert_eq!(decode_admission_closure_record(&bytes).unwrap(), record);
    }

    #[test]
    fn admission_closure_record_decode_rejects_truncation() {
        let record = AdmissionClosureRecord {
            closed_epoch: Epoch::new(4),
            request_id: [5; 32],
            closed_at_block_height: 7,
        };
        let mut bytes = encode_admission_closure_record(&record).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(decode_admission_closure_record(&bytes).is_err());
    }

    #[test]
    fn admission_closure_key_is_stable_and_chain_and_epoch_scoped() {
        let a = ChainId::new("chain-a").unwrap();
        let b = ChainId::new("chain-b").unwrap();
        assert_eq!(
            admission_closure_key(&a, Epoch::new(4)).unwrap(),
            admission_closure_key(&a, Epoch::new(4)).unwrap()
        );
        assert_ne!(
            admission_closure_key(&a, Epoch::new(4)).unwrap(),
            admission_closure_key(&b, Epoch::new(4)).unwrap()
        );
        assert_ne!(
            admission_closure_key(&a, Epoch::new(4)).unwrap(),
            admission_closure_key(&a, Epoch::new(5)).unwrap()
        );
    }

    fn store_context() -> (
        MemoryDurableStateStore,
        DurableOperationContext,
        AtomicityDomainId,
    ) {
        let generation = WriterFenceGeneration::new(1).unwrap();
        let store = MemoryDurableStateStore::new(generation);
        let context = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        );
        let domain = AtomicityDomainId::new([2; 32]).unwrap();
        (store, context, domain)
    }

    #[test]
    fn fence_admission_open_is_open_until_a_closure_record_is_written() {
        let (store, context, domain) = store_context();
        let chain = ChainId::new("fence-admission").unwrap();
        let mut reads = BTreeMap::new();
        fence_admission_open(&store, &context, domain, &chain, Epoch::new(0), &mut reads).unwrap();
        assert!(reads.contains_key(&admission_closure_key(&chain, Epoch::new(0)).unwrap()));

        let key = admission_closure_key(&chain, Epoch::new(0)).unwrap();
        let observed = store.get_versioned_durable(&context, domain, &key).unwrap();
        let record = AdmissionClosureRecord {
            closed_epoch: Epoch::new(0),
            request_id: [1; 32],
            closed_at_block_height: 1,
        };
        let transaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    key,
                    StateMutation::Put(encode_admission_closure_record(&record).unwrap()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );

        let mut reads = BTreeMap::new();
        assert!(matches!(
            fence_admission_open(&store, &context, domain, &chain, Epoch::new(0), &mut reads),
            Err(NodeCoreError::PersistenceInvariant(
                "admission closed by a committed ordered-economics epoch freeze"
            ))
        ));
        let mut next_epoch_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        fence_admission_open(
            &store,
            &context,
            domain,
            &chain,
            Epoch::new(1),
            &mut next_epoch_reads,
        )
        .unwrap();

        // A missing next-epoch row is open, but deleting the old closure is
        // corruption, never an authorized local unfreeze.
        let old_key: Vec<u8> = admission_closure_key(&chain, Epoch::new(0)).unwrap();
        let old: VersionedStateValue = store
            .get_versioned_durable(&context, domain, &old_key)
            .unwrap();
        let delete: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(old_key.clone(), old.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(old_key, StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, delete),
            DurableCommitOutcome::Committed
        );
        let mut tombstone_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            fence_admission_open(
                &store,
                &context,
                domain,
                &chain,
                Epoch::new(0),
                &mut tombstone_reads,
            ),
            Err(NodeCoreError::PersistenceInvariant(
                "admission closure record is tombstoned"
            ))
        ));
    }
}
