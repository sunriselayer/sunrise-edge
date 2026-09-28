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
//! This partial implementation checks no independent epoch-end warrant or
//! next-set eligibility before honest votes; quorum ordering is not a
//! substitute for that authorization. It must not be enabled until both
//! checks are defined and enforced.
//!
//! Scope of this slice (DR-0154 Delivery 3, partial): closing admission and
//! refusing business after closure. Fresh publication-retention ACKs are
//! fenced in `crate::fast_path::publication`. `DrainSet`, `Seal` and the
//! next-set readiness/activation sequence are **not** implemented here; see
//! the module-level remaining-integration note in [`super`].
use super::*;
use canonical_encoding::encode_chain_id;
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};

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
/// (`FeeClaim`, `BondLifecycle`), `Freeze` is a control decision whose only
/// authority is having been committed by the outgoing set's own quorum
/// through the shared `ChainedHotStuff` three-chain rule -- structurally
/// identical to how `BondSlash` is "unsigned, evidence-authorized" rather
/// than user-signed. `context` and `request_id` duplicate
/// [`OrderedCandidate::context`]/[`OrderedCandidate::request_id`] so
/// [`authenticate_freeze`](super::policy) can cross-check the two bindings
/// exactly like every other kind's intent envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreezeIntent {
    /// Chain/protocol/epoch replay boundary; must equal the candidate's own.
    pub context: PublicationContext,
    /// Replay identity; must equal the candidate's own request id.
    pub request_id: [u8; 32],
}

/// Encodes frame `0x6454/v1`.
pub fn encode_freeze_intent(intent: &FreezeIntent) -> Result<Vec<u8>, NodeCoreError> {
    if intent.request_id == [0u8; 32] {
        return Err(invalid("freeze intent request id must not be zero"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(FREEZE_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&intent.context)
            .map_err(|_| invalid("invalid freeze intent context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    Ok(frame.finish()?)
}

/// Strictly decodes frame `0x6454/v1`.
pub fn decode_freeze_intent(bytes: &[u8]) -> Result<FreezeIntent, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(FREEZE_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("freeze intent request id length"))?;
    let intent = FreezeIntent {
        context: decode_publication_context(frame.required_field(1)?)
            .map_err(|_| invalid("freeze intent context"))?,
        request_id,
    };
    if intent.request_id == [0u8; 32] || encode_freeze_intent(&intent)? != bytes {
        return Err(invalid("noncanonical freeze intent"));
    }
    Ok(intent)
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
/// closure. The older standalone epoch-transition route can currently advance
/// to that key without `DrainSet`/`Seal`; this is *not* verified DR-0154
/// activation and must be retired before this slice is enabled.
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
    use protocol_types::{ChainId, ProtocolVersion};
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

    #[test]
    fn freeze_intent_round_trips_and_rejects_a_zero_request_id() {
        let intent = FreezeIntent {
            context: context(),
            request_id: [9; 32],
        };
        let bytes = encode_freeze_intent(&intent).unwrap();
        assert_eq!(decode_freeze_intent(&bytes).unwrap(), intent);

        let zero = FreezeIntent {
            context: context(),
            request_id: [0; 32],
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
