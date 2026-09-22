//! DR-0131 slice 1: the one general mutation authorization/fencing model
//! every current mutation path commits through in the same durable
//! invocation.
//!
//! Two kinds of fence live here:
//!
//! * [`fence_epoch_state`] / [`fence_current_epoch`] -- read and CAS-fence the singleton
//!   [`local_instance_state::FastPathEpochRecord`], and reject a request
//!   bound to a non-current epoch before any lock, execution, or mutation.
//!   Every mutation path that can consume/write a sender-owned object or a
//!   sender/epoch nonce calls this: fast-path prepare/apply
//!   (`crate::fast_path`), the direct paid path
//!   (`crate::paid_execution::build_paid_admission`, shared by both), local
//!   execution (`crate::local_execution::handle_local_execution`), local
//!   publication (`crate::publication::handle_local_publication_with_history`,
//!   which fences without narrowing its historical policy selector),
//!   and every authenticated `SubmitTransaction` path that advances a nonce
//!   (object-read-only, owned-effects, and preinstalled WASM), all enforced
//!   once inside `crate::handle_durable_idempotent_event_with_plan` after
//!   exact replay and stale-nonce reconciliation.
//! * [`fence_object_lock`] and [`fence_sender_nonce_lock`] -- read and
//!   CAS-fence one [`local_instance_state::FastPathLockRecord`] or
//!   [`local_instance_state::FastPathNonceLockRecord`] respectively, honoring
//!   any lock a fast-path prepare already holds. Every mutation path above
//!   that can itself consume/write a sender-owned object or sender/epoch
//!   nonce calls these with [`LockMode::Fresh`]; only
//!   `crate::fast_path::apply` ever calls them with
//!   [`LockMode::OwnedByRequest`], since it alone may act on a lock a prior
//!   prepare created.
//!
//! Validator-authorized prepare/apply additionally fence the active
//! per-epoch `ValidatorSet` row and verify its digest against the epoch
//! record; that fence is fast-path-specific (it needs
//! `crate::fast_path::records`, which non-fast-path callers must not depend
//! on) and stays in `crate::fast_path::load_validator_set`, strictly
//! additive to [`fence_current_epoch`].
use super::*;
use local_instance_state::{
    FastPathEpochRecord, FastPathLockRecord, FastPathNonceLockRecord, decode_fastpath_epoch_record,
    decode_fastpath_lock_record, decode_fastpath_nonce_lock_record, fastpath_epoch_record_key,
    fastpath_lock_key, fastpath_nonce_lock_key,
};
#[cfg(test)]
use local_instance_state::{encode_fastpath_epoch_record, encode_fastpath_lock_record};

/// Reads one durable value and records its revision as a CAS precondition,
/// exactly like `local_execution::read_state`, but returning [`NodeCoreError`]
/// directly so every one of this module's callers -- each with its own local
/// admission error type -- can convert with a single `?`.
fn read_and_fence<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    key: Vec<u8>,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<VersionedStateValue, NodeCoreError> {
    let value: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    if let Some(previous_revision) = reads.insert(key, value.revision())
        && previous_revision != value.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(value)
}

/// How a mutation path relates to a [`FastPathLockRecord`]/
/// [`FastPathNonceLockRecord`] it observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockMode {
    /// Direct commit, local execution, local publication, live owned-effects
    /// `SubmitTransaction`, or a fresh fast-path prepare: no fast-path lock
    /// may already exist for this object/sender-epoch.
    Fresh,
    /// Certificate apply: the exact original request must own every
    /// object/nonce lock it touches.
    OwnedByRequest,
}

/// Reads, and (in [`LockMode::OwnedByRequest`]) validates ownership of, the
/// fast-path object-lock row for one object. A lock owned by a different
/// request id, or held at all under [`LockMode::Fresh`], fails closed: an
/// in-flight fast-path prepare's exclusive inputs can never be reused by a
/// direct commit, local execution, local publication, live owned-effects
/// `SubmitTransaction`, a different prepare, or anything other than that same
/// request's own certificate apply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fence_object_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    object_ref: &ObjectRef,
    current_request_id: &[u8; 32],
    expected_epoch: Epoch,
    mode: LockMode,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let key: Vec<u8> = fastpath_lock_key(chain, object_ref.id)?;
    let observed: VersionedStateValue = read_and_fence(store, context, domain, key, reads)?;
    match (mode, observed.value()) {
        (LockMode::Fresh, None) => Ok(()),
        (LockMode::Fresh, Some(_)) => Err(NodeCoreError::PersistenceInvariant(
            "object locked by a pending fast-path certificate",
        )),
        (LockMode::OwnedByRequest, Some(bytes)) => {
            let lock: FastPathLockRecord = decode_fastpath_lock_record(bytes)?;
            if &lock.request_id != current_request_id
                || &lock.object != object_ref
                || lock.locked_epoch != expected_epoch
            {
                return Err(NodeCoreError::PersistenceInvariant(
                    "fast-path apply does not own the exact object lock",
                ));
            }
            Ok(())
        }
        (LockMode::OwnedByRequest, None) => Err(NodeCoreError::PersistenceInvariant(
            "fast-path apply object lock absent",
        )),
    }
}

/// Reconciles the sender/epoch nonce lock with the calling mutation path.
/// [`LockMode::Fresh`] requires absence; [`LockMode::OwnedByRequest`]
/// (certificate apply only) requires the exact locally prepared request and
/// nonce. The ordinary sender-nonce row itself is a separate concern, read
/// and reserved by `durable_reconciliation::reserve_sender_nonce`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn fence_sender_nonce_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    sender: &[u8; 32],
    epoch: Epoch,
    expected_request_id: &[u8; 32],
    expected_nonce: u64,
    mode: LockMode,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<(), NodeCoreError> {
    let key: Vec<u8> = fastpath_nonce_lock_key(chain, sender, epoch)?;
    let observed: VersionedStateValue = read_and_fence(store, context, domain, key, reads)?;
    match (mode, observed.value()) {
        (LockMode::Fresh, None) => Ok(()),
        (LockMode::Fresh, Some(_)) => Err(NodeCoreError::PersistenceInvariant(
            "sender nonce locked by a pending fast path",
        )),
        (LockMode::OwnedByRequest, Some(bytes)) => {
            let lock: FastPathNonceLockRecord = decode_fastpath_nonce_lock_record(bytes)?;
            if &lock.request_id != expected_request_id
                || &lock.sender != sender
                || lock.epoch != epoch
                || lock.nonce != expected_nonce
            {
                return Err(NodeCoreError::PersistenceInvariant(
                    "fast-path apply does not own the exact nonce lock",
                ));
            }
            Ok(())
        }
        (LockMode::OwnedByRequest, None) => Err(NodeCoreError::PersistenceInvariant(
            "fast-path apply nonce lock absent",
        )),
    }
}

/// Reads and CAS-fences the singleton [`FastPathEpochRecord`], and rejects
/// `request_epoch` before any lock, execution, or mutation if it does not
/// equal the currently committed epoch. Slice 1 defines no post-genesis
/// write to this record, so a rejection here is only reachable once Slice 2
/// ships a real transition; the check itself is real and enforced from
/// Slice 1's first commit.
pub(crate) fn fence_epoch_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<FastPathEpochRecord, NodeCoreError> {
    let key: Vec<u8> = fastpath_epoch_record_key(chain)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    let record: FastPathEpochRecord = decode_fastpath_epoch_record(observed.value().ok_or(
        NodeCoreError::PersistenceInvariant("fast-path epoch record not installed"),
    )?)?;
    if let Some(previous_revision) = reads.insert(key, observed.revision())
        && previous_revision != observed.revision()
    {
        return Err(NodeCoreError::StateConflict);
    }
    Ok(record)
}

/// Fences the committed epoch state and additionally requires a request's
/// transaction epoch to be current. Historical policy selectors use
/// [`fence_epoch_state`] directly: they still serialize against a transition
/// without being reinterpreted as a transaction-epoch claim.
pub(crate) fn fence_current_epoch<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    request_epoch: Epoch,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<FastPathEpochRecord, NodeCoreError> {
    let record: FastPathEpochRecord = fence_epoch_state(store, context, domain, chain, reads)?;
    if record.current_epoch != request_epoch {
        return Err(NodeCoreError::EpochMismatch {
            expected: record.current_epoch,
            actual: request_epoch,
        });
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };

    fn store_context() -> (
        MemoryDurableStateStore,
        DurableOperationContext,
        AtomicityDomainId,
    ) {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new(generation);
        let context: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        );
        let domain: AtomicityDomainId = AtomicityDomainId::new([2; 32]).unwrap();
        (store, context, domain)
    }

    fn install_epoch_record(
        store: &MemoryDurableStateStore,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        chain: &ChainId,
        record: &FastPathEpochRecord,
    ) {
        let key: Vec<u8> = fastpath_epoch_record_key(chain).unwrap();
        let observed: VersionedStateValue =
            store.get_versioned_durable(context, domain, &key).unwrap();
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    key,
                    StateMutation::Put(encode_fastpath_epoch_record(record).unwrap()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(context, transaction),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn fence_current_epoch_is_fail_closed_when_not_installed() {
        let (store, context, domain) = store_context();
        let chain: ChainId = ChainId::new("epoch-fence").unwrap();
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            fence_current_epoch(&store, &context, domain, &chain, Epoch::new(0), &mut reads),
            Err(NodeCoreError::PersistenceInvariant(
                "fast-path epoch record not installed"
            ))
        ));
    }

    /// The read is recorded as a CAS precondition *before* `fence_current_epoch`
    /// ever compares the epoch: `fence_epoch_state` inserts into `reads`
    /// unconditionally, then its caller decides whether to reject. So a
    /// rejected request does not commit, but the helper's returned read map
    /// still truthfully records what it observed -- proven here by asserting
    /// the read landed in `reads` even though the call returned `Err`.
    #[test]
    fn fence_current_epoch_rejects_a_non_current_epoch_after_recording_the_read() {
        let (store, context, domain) = store_context();
        let chain: ChainId = ChainId::new("epoch-fence").unwrap();
        install_epoch_record(
            &store,
            &context,
            domain,
            &chain,
            &FastPathEpochRecord {
                current_epoch: Epoch::new(0),
                current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [7; 32]),
                previous_epoch: None,
                activated_at_checkpoint: 3,
            },
        );
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        let result =
            fence_current_epoch(&store, &context, domain, &chain, Epoch::new(1), &mut reads);
        assert!(matches!(
            result,
            Err(NodeCoreError::EpochMismatch { expected, actual })
                if expected == Epoch::new(0) && actual == Epoch::new(1)
        ));
        let key: Vec<u8> = fastpath_epoch_record_key(&chain).unwrap();
        let observed_revision: StateRevision = store
            .get_versioned_durable(&context, domain, &key)
            .unwrap()
            .revision();
        assert_eq!(reads.get(&key), Some(&observed_revision));

        let record: FastPathEpochRecord =
            fence_current_epoch(&store, &context, domain, &chain, Epoch::new(0), &mut reads)
                .unwrap();
        assert_eq!(record.current_epoch, Epoch::new(0));
        assert_eq!(record.activated_at_checkpoint, 3);
    }

    #[test]
    fn fence_object_lock_fresh_rejects_a_held_lock_and_owned_by_request_requires_exact_owner() {
        let (store, context, domain) = store_context();
        let chain: ChainId = ChainId::new("lock-fence").unwrap();
        let object_ref: ObjectRef = ObjectRef {
            id: ObjectId::new([9; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
        };
        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        fence_object_lock(
            &store,
            &context,
            domain,
            &chain,
            &object_ref,
            &[3; 32],
            Epoch::new(0),
            LockMode::Fresh,
            &mut reads,
        )
        .unwrap();

        let lock_key: Vec<u8> = fastpath_lock_key(&chain, object_ref.id).unwrap();
        let observed: VersionedStateValue = store
            .get_versioned_durable(&context, domain, &lock_key)
            .unwrap();
        let lock: FastPathLockRecord = FastPathLockRecord {
            request_id: [3; 32],
            object: object_ref.clone(),
            locked_epoch: Epoch::new(0),
        };
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(lock_key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    lock_key,
                    StateMutation::Put(encode_fastpath_lock_record(&lock).unwrap()),
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

        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            fence_object_lock(
                &store,
                &context,
                domain,
                &chain,
                &object_ref,
                &[4; 32],
                Epoch::new(0),
                LockMode::Fresh,
                &mut reads,
            ),
            Err(NodeCoreError::PersistenceInvariant(
                "object locked by a pending fast-path certificate"
            ))
        ));

        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            fence_object_lock(
                &store,
                &context,
                domain,
                &chain,
                &object_ref,
                &[4; 32],
                Epoch::new(0),
                LockMode::OwnedByRequest,
                &mut reads,
            ),
            Err(NodeCoreError::PersistenceInvariant(
                "fast-path apply does not own the exact object lock"
            ))
        ));

        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        assert!(matches!(
            fence_object_lock(
                &store,
                &context,
                domain,
                &chain,
                &object_ref,
                &[3; 32],
                Epoch::new(1),
                LockMode::OwnedByRequest,
                &mut reads,
            ),
            Err(NodeCoreError::PersistenceInvariant(
                "fast-path apply does not own the exact object lock"
            ))
        ));

        let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
        fence_object_lock(
            &store,
            &context,
            domain,
            &chain,
            &object_ref,
            &[3; 32],
            Epoch::new(0),
            LockMode::OwnedByRequest,
            &mut reads,
        )
        .unwrap();
    }
}
