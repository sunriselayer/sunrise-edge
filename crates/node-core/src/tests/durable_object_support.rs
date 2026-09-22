struct IdempotentMachine {
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for IdempotentMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/idempotent".to_vec(),
            NodeStateAccessMode::ReadWrite,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let current = match state
            .get(b"state/idempotent")
            .and_then(VersionedStateValue::value)
        {
            Some(bytes) => decode_canonical_frame(bytes)?.required_u64(1)?,
            None => 0,
        };
        let next = current + 1;
        let response = NodeResponse::new(
            event.request_id(),
            NodeResponseStatus::Accepted,
            Some(canonical(TEST_PAYLOAD_TYPE_ID, next)),
        )?;
        let outbound = OutboundMessage::new(NodeEvent::new(
            event.chain_id().clone(),
            event.protocol_version(),
            event.epoch(),
            request(0xFE),
            NodeEventKind::Tick,
            canonical(TEST_PAYLOAD_TYPE_ID, next),
        )?);
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/idempotent".to_vec(),
                canonical(TEST_STATE_TYPE_ID, next),
            )?],
            NodeOutput::new(vec![response], vec![outbound])?,
        )
    }
}

type ScriptedStateReads = BTreeMap<Vec<u8>, (StateRevision, Option<Vec<u8>>)>;

struct ScriptedDurableStore {
    receipt: Mutex<Option<DurableRequestReceipt>>,
    commits: Mutex<Vec<DurableInvocationTransaction>>,
    state_reads: AtomicUsize,
    object_head_reads: AtomicUsize,
    object_heads: Mutex<BTreeMap<ObjectId, DurableObjectHead>>,
    object_versions: Mutex<BTreeMap<(ObjectId, u64), DurableObjectVersionRecord>>,
    commit_outcome: DurableCommitOutcome,
    preloaded: Mutex<ScriptedStateReads>,
}

impl ScriptedDurableStore {
    fn new(commit_outcome: DurableCommitOutcome) -> Self {
        let store: Self = Self {
            receipt: Mutex::new(None),
            commits: Mutex::new(Vec::new()),
            state_reads: AtomicUsize::new(0),
            object_head_reads: AtomicUsize::new(0),
            object_heads: Mutex::new(BTreeMap::new()),
            object_versions: Mutex::new(BTreeMap::new()),
            commit_outcome,
            preloaded: Mutex::new(BTreeMap::new()),
        };
        // Authenticated `SubmitTransaction` tests use this store as their
        // standard committed-state fixture. Genesis now always installs the
        // DR-0131 epoch singleton, so mirror that production invariant once
        // here instead of letting dozens of unrelated branch tests fail at
        // the new lifecycle fence before reaching their intended assertion.
        preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));
        store
    }

    /// Scripts a fixed read response for one exact key, overriding the
    /// default absent/`INITIAL` response used by every other key.
    fn preload(&self, key: Vec<u8>, revision: StateRevision, value: Vec<u8>) {
        self.preloaded
            .lock()
            .unwrap()
            .insert(key, (revision, Some(value)));
    }

    fn preload_tombstone(&self, key: Vec<u8>, revision: StateRevision) {
        self.preloaded.lock().unwrap().insert(key, (revision, None));
    }

    fn preload_object(
        &self,
        object_id: ObjectId,
        head: DurableObjectHead,
        version: Option<DurableObjectVersionRecord>,
    ) {
        self.object_heads.lock().unwrap().insert(object_id, head);
        if let Some(version) = version {
            self.object_versions
                .lock()
                .unwrap()
                .insert((object_id, version.object_version().get()), version);
        }
    }
}

impl DurableDomainStateStore for ScriptedDurableStore {
    fn get_versioned_durable(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.state_reads.fetch_add(1, Ordering::SeqCst);
        match self.preloaded.lock().unwrap().get(key) {
            Some((revision, value)) => {
                VersionedStateValue::from_persisted_parts(*revision, value.clone())
                    .map_err(DurableReadError::InvalidRequest)
            }
            None => VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                .map_err(DurableReadError::InvalidRequest),
        }
    }

    fn commit_durable(
        &self,
        _context: &DurableOperationContext,
        _transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    }
}

impl StructuredDurableDomainStateStore for ScriptedDurableStore {
    fn get_request_receipt(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        _request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        Ok(self.receipt.lock().unwrap().clone())
    }

    fn commit_invocation(
        &self,
        _context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.commits.lock().unwrap().push(transaction);
        self.commit_outcome.clone()
    }

    fn get_object_head(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.object_head_reads.fetch_add(1, Ordering::SeqCst);
        self.object_heads
            .lock()
            .unwrap()
            .get(&object_id)
            .cloned()
            .ok_or(DurableReadError::InvalidRequest(
                RuntimeError::UnsupportedObjectStorage,
            ))
    }

    fn get_object_version(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        Ok(self
            .object_versions
            .lock()
            .unwrap()
            .get(&(object_id, object_version.get()))
            .cloned())
    }
}

fn preload_inline_object(
    store: &ScriptedDurableStore,
    chain: &str,
    object_id: ObjectId,
    owner: Owner,
    byte: u8,
) -> (ObjectRef, DurableObjectHead) {
    let object: Object = test_object(object_id, 1, owner.clone(), byte);
    let (record, digest): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version(object, chain, 1);
    let head: DurableObjectHead = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head.clone(), Some(record));
    (
        ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        head,
    )
}

/// A [`BlobStore`] test double that counts every [`BlobStore::get_blob`]
/// call and can be scripted to fail closed with a fixed [`RuntimeError`],
/// so tests can prove ordering (a blob fetch never happens before an
/// earlier fail-closed check) as well as exact digest-keyed content.
#[derive(Clone, Default)]
struct InstrumentedBlobStore {
    blobs: Arc<Mutex<BTreeMap<Digest32, Vec<u8>>>>,
    get_calls: Arc<AtomicUsize>,
    put_calls: Arc<AtomicUsize>,
    fail_with: Arc<Mutex<Option<RuntimeError>>>,
    fail_put_with: Arc<Mutex<Option<RuntimeError>>>,
}

impl InstrumentedBlobStore {
    fn insert(&self, digest: Digest32, bytes: Vec<u8>) {
        self.blobs.lock().unwrap().insert(digest, bytes);
    }

    fn fail_with(&self, error: RuntimeError) {
        *self.fail_with.lock().unwrap() = Some(error);
    }

    fn fail_put_with(&self, error: RuntimeError) {
        *self.fail_put_with.lock().unwrap() = Some(error);
    }

    fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }

    fn put_calls(&self) -> usize {
        self.put_calls.load(Ordering::SeqCst)
    }
}

impl BlobStore for InstrumentedBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.fail_put_with.lock().unwrap().clone() {
            return Err(error);
        }
        self.insert(digest, bytes);
        Ok(())
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.fail_with.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.blobs.lock().unwrap().get(digest).cloned())
    }
}

/// Preloads a blob-backed current object version: canonical bytes live
/// only in `blob_store`, keyed under the returned `blob_digest`, exactly
/// like a production content-addressed store. Both the immutable
/// version's own `digest` (checked against the head and independently
/// re-verified against the fetched bytes) and the payload's separate
/// `blob_digest` (independently verified against the same fetched bytes
/// first) are computed from the identical canonical bytes, matching the
/// non-adversarial case; individual tests overwrite one or the other to
/// exercise a specific corruption.
fn preload_blob_object(
    store: &ScriptedDurableStore,
    blob_store: &InstrumentedBlobStore,
    chain: &str,
    object_id: ObjectId,
    owner: Owner,
    byte: u8,
) -> (ObjectRef, DurableObjectHead, Digest32) {
    let object: Object = test_object(object_id, 1, owner.clone(), byte);
    let canonical_bytes: Vec<u8> = encode_object(&object).unwrap();
    let chain_id = ChainId::new(chain).unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let content_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &canonical_bytes,
        )
        .unwrap();
    blob_store.insert(content_digest, canonical_bytes);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        content_digest,
        object.schema_version,
        provenance,
        1,
        content_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: content_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head.clone(), Some(record));
    (
        ObjectRef {
            id: object_id,
            version: 1,
            digest: content_digest,
        },
        head,
        content_digest,
    )
}

fn commit_memory_inline_object(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    object_domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef {
    commit_memory_inline_object_with_protocol_version(
        store,
        context,
        object_domain,
        object,
        chain,
        ProtocolVersion::new(3),
        created_checkpoint,
        receipt_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_memory_inline_object_with_protocol_version(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    object_domain: AtomicityDomainId,
    object: Object,
    chain: &str,
    protocol_version: ProtocolVersion,
    created_checkpoint: u64,
    receipt_byte: u8,
) -> ObjectRef {
    ensure_fastpath_epoch_record(store, context, object_domain, chain, Epoch::new(7));
    let object_id: ObjectId = object.id;
    let object_version: u64 = object.version;
    let owner: Owner = object.owner.clone();
    let (record, digest): (DurableObjectVersionRecord, Digest32) =
        hashed_object_version_with_protocol_version(
            object,
            chain,
            protocol_version,
            created_checkpoint,
        );
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            runtime::DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([receipt_byte; 32]).unwrap(),
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [receipt_byte.wrapping_add(1); 32],
        ),
        vec![receipt_byte.wrapping_add(2)],
    )
    .unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(object_domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    );
    ObjectRef {
        id: object_id,
        version: object_version,
        digest,
    }
}

/// DR-0131: the live owned-effects `SubmitTransaction` path now fences the
/// singleton `FastPathEpochRecord`. Scripts a fixed read response for it on
/// a [`ScriptedDurableStore`], matching `preload`'s own convention.
fn preload_fastpath_epoch_record(store: &ScriptedDurableStore, chain: &str, epoch: Epoch) {
    let chain_id: ChainId = ChainId::new(chain).unwrap();
    let key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain_id).unwrap();
    let record = local_instance_state::FastPathEpochRecord {
        current_epoch: epoch,
        current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0u8; 32]),
        previous_epoch: None,
        activated_at_checkpoint: 0,
    };
    store.preload(
        key,
        StateRevision::INITIAL.checked_next().unwrap(),
        local_instance_state::encode_fastpath_epoch_record(&record).unwrap(),
    );
}

/// Same as [`preload_fastpath_epoch_record`], but durably committed on a real
/// [`MemoryDurableStateStore`] at the exact domain the caller's own admission
/// call resolves to.
fn commit_fastpath_epoch_record(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &str,
    epoch: Epoch,
) {
    let chain_id: ChainId = ChainId::new(chain).unwrap();
    let key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain_id).unwrap();
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key).unwrap();
    let record = local_instance_state::FastPathEpochRecord {
        current_epoch: epoch,
        current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0u8; 32]),
        previous_epoch: None,
        activated_at_checkpoint: 0,
    };
    let bytes: Vec<u8> = local_instance_state::encode_fastpath_epoch_record(&record).unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(context, transaction),
        DurableCommitOutcome::Committed
    );
}

/// Installs the genesis lifecycle record only when a fixture has not already
/// selected an explicit current epoch of its own.
fn ensure_fastpath_epoch_record(
    store: &MemoryDurableStateStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &str,
    epoch: Epoch,
) {
    let chain_id: ChainId = ChainId::new(chain).unwrap();
    let key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain_id).unwrap();
    if store
        .get_versioned_durable(context, domain, &key)
        .unwrap()
        .value()
        .is_none()
    {
        commit_fastpath_epoch_record(store, context, domain, chain, epoch);
    }
}

/// Production-like in-memory fixture for authenticated transaction tests:
/// genesis has already installed the chain's current epoch singleton in the
/// same placement domain the test will commit through.
fn memory_store_with_fastpath_epoch(domain: AtomicityDomainId) -> MemoryDurableStateStore {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain,
        "sunrise-test",
        Epoch::new(7),
    );
    store
}

struct OwnedObjectEffectMachine {
    expected_inputs: Vec<(ObjectId, AccessMode)>,
    replacement_data: Vec<u8>,
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for OwnedObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/owned-object-effects".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let actual_inputs: Vec<(ObjectId, AccessMode)> = state
            .resolved_objects()
            .iter()
            .map(|input: &ResolvedObject| (input.object.id, input.mode))
            .collect();
        assert_eq!(actual_inputs, self.expected_inputs);

        let mut effects: Vec<ObjectEffect> = Vec::new();
        for input in state.resolved_objects() {
            match input.mode {
                AccessMode::Read => {}
                AccessMode::Write => {
                    let mut new_object: Object = input.object.clone();
                    new_object.version = new_object.version.checked_add(1).unwrap();
                    new_object.data = self.replacement_data.clone();
                    effects.push(ObjectEffect::Mutated {
                        previous_version: input.object.version,
                        new_object,
                    });
                }
                AccessMode::Consume => effects.push(ObjectEffect::Deleted {
                    id: input.object.id,
                    version: input.object.version,
                }),
            }
        }
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), effects, output)
    }
}

struct UndeclaredObjectEffectMachine;

impl TransactionalNodeStateMachine for UndeclaredObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/undeclared-object-effect".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        assert!(state.resolved_objects().is_empty());
        let object_id: ObjectId = ObjectId::new([0xA1; 32]);
        let effect: ObjectEffect = ObjectEffect::Deleted {
            id: object_id,
            version: 1,
        };
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
    }
}

struct ReadObjectEffectMachine;

impl TransactionalNodeStateMachine for ReadObjectEffectMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/read-object-effect".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let [input]: &[ResolvedObject] = state.resolved_objects() else {
            panic!("expected one authenticated read object");
        };
        let effect: ObjectEffect = ObjectEffect::Deleted {
            id: input.object.id,
            version: input.object.version,
        };
        let output: NodeOutput = NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?;
        TransactionalNodeTransition::with_object_effects(Vec::new(), vec![effect], output)
    }
}
