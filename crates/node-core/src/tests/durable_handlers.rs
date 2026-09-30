#[test]
fn durable_idempotent_handler_builds_typed_sections_and_replays_receipt() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let input = event("sunrise-test", request(0x91));
    let resolver = resolver("sunrise-test");
    let first = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC1, 7),
        &config("sunrise-test"),
        &resolver,
        input.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(first.domain(), domain(0xC1));
    assert_eq!(first.output().outbound_messages().len(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let invocation = &commits[0];
    let state = invocation.state().unwrap();
    assert_eq!(state.domain(), domain(0xC1));
    assert_eq!(state.reads().len(), 1);
    assert_eq!(state.mutations().len(), 1);
    assert!(invocation.objects().is_empty());
    let receipt = invocation.receipt().clone();
    assert_eq!(
        NodeDedupRecord::decode(receipt.canonical_bytes())
            .unwrap()
            .responses()
            .len(),
        1
    );
    let outbox = invocation.outbox().unwrap();
    assert_eq!(outbox.messages().len(), 1);
    let outbound_event = NodeEvent::decode(outbox.messages()[0].canonical_payload()).unwrap();
    assert_eq!(
        outbox.messages()[0].payload_digest(),
        outbound_event.digest(&resolver).unwrap()
    );
    drop(commits);

    store.receipt.lock().unwrap().replace(receipt);
    let replay = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC1, 7),
        &config("sunrise-test"),
        &resolver,
        input.clone(),
        &machine,
    )
    .unwrap();
    assert_eq!(replay.output().responses(), first.output().responses());
    assert!(replay.output().outbound_messages().is_empty());
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    // The plan's one application key plus the DR-0154 commitment-profile row,
    // read exactly once per transition. It is absent here, so this historical
    // store adds no read assertion and no provenance write: the committed read
    // set above is still exactly the plan's own single key.
    assert_eq!(store.state_reads.load(Ordering::SeqCst), 2);
    assert_eq!(store.commits.lock().unwrap().len(), 1);

    assert_eq!(
        handle_resolved_durable_idempotent_event(
            &store,
            &durable_context(),
            &placement(0xC1, 7),
            &config("sunrise-test"),
            &resolver,
            event_value("sunrise-test", request(0x91), 10),
            &machine,
        ),
        Err(NodeCoreError::RequestIdReuse)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_idempotent_handler_conforms_against_memory_store() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let input = event("sunrise-test", request(0x93));
    let context = durable_context();
    let first = handle_resolved_durable_idempotent_event(
        &store,
        &context,
        &placement(0xC3, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        input.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_resolved_durable_idempotent_event(
        &store,
        &context,
        &placement(0xC3, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        input,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.output().responses(), replay.output().responses());
    assert!(replay.output().outbound_messages().is_empty());
    let persisted = store
        .get_versioned_durable(&context, domain(0xC3), b"state/idempotent")
        .unwrap();
    assert_eq!(persisted.revision(), StateRevision::new(1));
    assert_eq!(
        decode_canonical_frame(persisted.value().unwrap())
            .unwrap()
            .required_u64(1),
        Ok(1)
    );
}

/// The provenance key the application row would occupy under the binding this
/// fixture's chain would install, derived without installing it.
fn unbound_provenance_key() -> Vec<u8> {
    let hashes: HashSuiteResolver = resolver("sunrise-test");
    let profile: LogicalProfileRecord = logical_profile_for("sunrise-test");
    let space = logical_generation::LogicalKeySpace::new(&profile, &hashes);
    let subject = logical_generation::LogicalSubject::StateKey(b"state/idempotent".to_vec());
    space.provenance_key(&subject).unwrap()
}

/// Binds one fixture store to the handoff-capable profile (DR-0154) and returns
/// the installed record.
///
/// The row's authenticity, atomic installation and byte-exact reopen
/// verification are covered by the genesis tests; this writes the same
/// authenticated bytes so the generic durable-event path can be exercised under
/// the profile without rebuilding a signed genesis on this fixture's chain.
fn bind_logical_profile(store: &MemoryDurableStateStore, chain: &str) -> LogicalProfileRecord {
    let record: LogicalProfileRecord = logical_profile_for(chain);
    commit_generic_row(
        store,
        chain,
        &logical_generation::logical_profile_key(&ChainId::new(chain).unwrap()).unwrap(),
        encode_logical_profile_record(&record).unwrap(),
    );
    record
}

/// The exact authenticated profile record a signed version-two genesis installs
/// for `chain`, built without writing it.
fn logical_profile_for(chain: &str) -> LogicalProfileRecord {
    LogicalProfileRecord {
        context: execution::publication::PublicationContext::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(7),
        )
        .unwrap(),
        profile: CommitmentProfile::LogicalGenerationV2,
        manifest_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x6d; 32]),
        genesis_authority: [0x6e; 32],
        genesis_floor: protocol_types::ExecutionGeneration::genesis_floor(),
    }
}

/// Runs one generic durable idempotent transition against a fixture store,
/// with [`IdempotentMachine`]. Its transition always carries one outbound
/// message; tests that are not about that must use [`run_generic_event`]
/// with [`SilentIdempotentMachine`] instead.
fn run_generic_idempotent(
    store: &MemoryDurableStateStore,
    request_id: RequestId,
) -> Result<ResolvedNodeOutput, NodeCoreError> {
    run_generic_event(
        store,
        request_id,
        &IdempotentMachine {
            calls: AtomicUsize::new(0),
        },
    )
}

/// Same generic durable-event plumbing as [`run_generic_idempotent`], but
/// against a caller-supplied machine.
fn run_generic_event<M: TransactionalNodeStateMachine>(
    store: &MemoryDurableStateStore,
    request_id: RequestId,
    machine: &M,
) -> Result<ResolvedNodeOutput, NodeCoreError> {
    handle_resolved_durable_idempotent_event(
        store,
        &durable_context(),
        &placement(0xC5, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request_id),
        machine,
    )
}

/// Identical to [`IdempotentMachine`], except its transition carries no
/// outbound message. DR-0154's outbox refusal (below) is orthogonal to what
/// the provenance-commit and unauthenticated-row tests exercise, so they use
/// this machine instead of entangling their assertions with it.
struct SilentIdempotentMachine {
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for SilentIdempotentMachine {
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
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/idempotent".to_vec(),
                canonical(TEST_STATE_TYPE_ID, next),
            )?],
            NodeOutput::new(vec![response], Vec::new())?,
        )
    }
}

/// Commits one raw row into a generic-path fixture store, fenced at its exact
/// observed revision.
fn commit_generic_row(store: &MemoryDurableStateStore, _chain: &str, key: &[u8], value: Vec<u8>) {
    let context = durable_context();
    let observed = store
        .get_versioned_durable(&context, domain(0xC5), key)
        .unwrap();
    let transaction = AtomicStateTransaction::new(
        domain(0xC5),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), StateMutation::Put(value)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );
}

struct ReadOnlyMachine;

impl TransactionalNodeStateMachine for ReadOnlyMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/read-only".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

#[test]
fn durable_idempotent_handler_asserts_read_only_state_and_hides_ambiguity() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Indeterminate(
        IndeterminateCommitReason::ConnectionLost,
    ));
    let result = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC2, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0x92)),
        &ReadOnlyMachine,
    );

    assert_eq!(
        result,
        Err(NodeCoreError::DurableCommitIndeterminate(
            IndeterminateCommitReason::ConnectionLost
        ))
    );
    let commits = store.commits.lock().unwrap();
    let state = commits[0].state().unwrap();
    assert_eq!(state.reads().len(), 1);
    assert!(state.mutations().is_empty());
    assert!(commits[0].outbox().is_none());
}

#[test]
fn durable_concurrent_receipt_publication_requests_reconciliation_retry() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(
        DurableCommitRejection::RequestAlreadyCommitted,
    ));
    let result = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC2, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0x93)),
        &ReadOnlyMachine,
    );

    assert_eq!(result, Err(NodeCoreError::StateConflict));
}

#[test]
fn idempotent_handler_commits_dedup_and_outbox_and_replays_response() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x6B));
    let resolver = resolver("sunrise-test");
    let first = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.responses(), replay.responses());
    assert_eq!(first.outbound_messages().len(), 1);
    assert!(replay.outbound_messages().is_empty());
    let persisted = runtime
        .state_store()
        .get(b"state/idempotent")
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_canonical_frame(&persisted).unwrap().required_u64(1),
        Ok(1)
    );

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let dedup = runtime
        .state_store()
        .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let outbox = runtime
        .state_store()
        .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let delivery = runtime
        .state_store()
        .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(
        NodeDedupRecord::decode(&dedup).unwrap().responses().len(),
        1
    );
    assert_eq!(
        NodeOutboxBatch::decode(&outbox).unwrap().messages().len(),
        1
    );
    assert_eq!(
        NodeOutboxDelivery::decode(&delivery).unwrap().next_index(),
        0
    );

    assert_eq!(
        handle_idempotent_event(
            &runtime,
            &config("sunrise-test"),
            &resolver,
            event_value("sunrise-test", request(0x6B), 10),
            &machine,
        ),
        Err(NodeCoreError::RequestIdReuse)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn domain_idempotent_handler_scopes_state_receipt_and_outbox() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let first_domain = domain(0xB1);
    let second_domain = domain(0xB2);
    let event = event("sunrise-test", request(0x82));
    let resolver = resolver("sunrise-test");

    let first = handle_domain_idempotent_event(
        &runtime,
        first_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_domain_idempotent_event(
        &runtime,
        first_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    handle_domain_idempotent_event(
        &runtime,
        second_domain,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 2);
    assert_eq!(first.responses(), replay.responses());
    assert!(replay.outbound_messages().is_empty());
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for active_domain in [first_domain, second_domain] {
        for key in [
            b"state/idempotent".to_vec(),
            layout.request_dedup_key(*event.request_id().as_bytes()),
            layout.outbox_batch_key(*event.request_id().as_bytes()),
            layout.outbox_delivery_key(*event.request_id().as_bytes()),
        ] {
            assert!(
                runtime
                    .state_store()
                    .get_versioned_in_domain(active_domain, &key)
                    .unwrap()
                    .value()
                    .is_some()
            );
            assert_eq!(runtime.state_store().get(&key).unwrap(), None);
        }
    }
}

#[test]
fn resolved_idempotent_handler_uses_committed_domain_and_returns_it() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let placement = placement(0xB4, 7);
    let event = event("sunrise-test", request(0x85));
    let resolver = resolver("sunrise-test");

    let first = handle_resolved_idempotent_event(
        &runtime,
        &placement,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();
    let replay = handle_resolved_idempotent_event(
        &runtime,
        &placement,
        &config("sunrise-test"),
        &resolver,
        event.clone(),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.domain(), placement.domain());
    assert_eq!(replay.domain(), placement.domain());
    assert_eq!(first.output().responses(), replay.output().responses());
    assert_eq!(first.output().outbound_messages().len(), 1);
    assert!(replay.output().outbound_messages().is_empty());
    assert_eq!(replay.clone().into_output(), replay.output);

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    assert!(
        claim_next_outbox_message_in_domain(
            runtime.state_store(),
            first.domain(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x45; 32]).unwrap(),
            100,
            10,
        )
        .unwrap()
        .is_some()
    );
    assert_eq!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain(0xB5), b"state/idempotent")
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn resolved_handler_rejects_inactive_manifest_before_transition_or_read() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x86));
    let error = handle_resolved_idempotent_event(
        &runtime,
        &placement(0xB6, 8),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event,
        &machine,
    )
    .unwrap_err();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        error,
        NodeCoreError::ProtocolConfig(ProtocolConfigError::InactiveDomainPlacement {
            activation_epoch: Epoch::new(8),
            event_epoch: Epoch::new(7),
        })
    );
    assert_eq!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain(0xB6), b"state/idempotent")
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn outbox_lease_expiry_redelivers_and_matching_ack_advances_cursor() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let event = event("sunrise-test", request(0x6D));
    handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &machine,
    )
    .unwrap();
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let first_lease = OutboxLeaseId::new([0x31; 32]).unwrap();
    let second_lease = OutboxLeaseId::new([0x32; 32]).unwrap();
    assert_eq!(
        OutboxLeaseId::new([0; 32]),
        Err(NodeCoreError::ZeroOutboxLeaseId)
    );
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            first_lease,
            100,
            0,
        ),
        Err(NodeCoreError::InvalidOutboxLeaseDuration(0))
    );

    let first = claim_next_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        first_lease,
        100,
        10,
    )
    .unwrap()
    .unwrap();
    assert_eq!(first.index(), 0);
    assert_eq!(first.expires_at_unix_millis(), 110);
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            second_lease,
            109,
            10,
        ),
        Err(NodeCoreError::OutboxLeaseActive {
            expires_at_unix_millis: 110,
        })
    );

    let redelivered = claim_next_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        second_lease,
        110,
        10,
    )
    .unwrap()
    .unwrap();
    assert_eq!(redelivered.index(), first.index());
    assert_eq!(redelivered.message(), first.message());
    assert_eq!(
        acknowledge_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            1,
            second_lease,
        ),
        Err(NodeCoreError::OutboxIndexMismatch)
    );
    assert_eq!(
        acknowledge_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            0,
            first_lease,
        ),
        Err(NodeCoreError::OutboxLeaseMismatch)
    );
    acknowledge_outbox_message(
        runtime.state_store(),
        &layout,
        event.request_id(),
        0,
        second_lease,
    )
    .unwrap();
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x33; 32]).unwrap(),
            121,
            10,
        )
        .unwrap(),
        None
    );

    let delivery = runtime
        .state_store()
        .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
        .unwrap()
        .unwrap();
    let delivery = NodeOutboxDelivery::decode(&delivery).unwrap();
    assert_eq!(delivery.next_index(), 1);
    assert_eq!(delivery.attempts(), 2);
    assert_eq!(delivery.lease(), None);
}

#[test]
fn domain_outbox_claim_and_ack_never_cross_domain_boundaries() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let first_domain = domain(0xC1);
    let second_domain = domain(0xC2);
    let event = event("sunrise-test", request(0x84));
    let config = config("sunrise-test");
    let resolver = resolver("sunrise-test");
    for active_domain in [first_domain, second_domain] {
        handle_domain_idempotent_event(
            &runtime,
            active_domain,
            &config,
            &resolver,
            event.clone(),
            &machine,
        )
        .unwrap();
    }
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    let lease = OutboxLeaseId::new([0x41; 32]).unwrap();
    let claim = claim_next_outbox_message_in_domain(
        runtime.state_store(),
        first_domain,
        &layout,
        event.request_id(),
        lease,
        100,
        10,
    )
    .unwrap()
    .unwrap();
    acknowledge_outbox_message_in_domain(
        runtime.state_store(),
        first_domain,
        &layout,
        event.request_id(),
        claim.index(),
        lease,
    )
    .unwrap();

    assert_eq!(
        claim_next_outbox_message_in_domain(
            runtime.state_store(),
            first_domain,
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x42; 32]).unwrap(),
            111,
            10,
        )
        .unwrap(),
        None
    );
    let second_claim = claim_next_outbox_message_in_domain(
        runtime.state_store(),
        second_domain,
        &layout,
        event.request_id(),
        OutboxLeaseId::new([0x43; 32]).unwrap(),
        111,
        10,
    )
    .unwrap();
    assert!(second_claim.is_some());
    assert_eq!(
        claim_next_outbox_message(
            runtime.state_store(),
            &layout,
            event.request_id(),
            OutboxLeaseId::new([0x44; 32]).unwrap(),
            111,
            10,
        ),
        Err(NodeCoreError::OutboxNotFound)
    );
}

#[test]
fn idempotent_conflict_does_not_publish_dedup_or_outbox_records() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let event = event("sunrise-test", request(0x6C));
    let error = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &TransactionalConflictMachine { runtime: &runtime },
    )
    .unwrap_err();
    assert_eq!(error, NodeCoreError::StateConflict);

    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.request_dedup_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.outbox_batch_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
    assert_eq!(
        runtime
            .state_store()
            .get(&layout.outbox_delivery_key(*event.request_id().as_bytes()))
            .unwrap(),
        None
    );
}

struct InvalidAccessMachine {
    plan_mode: NodeStateAccessMode,
    update_key: &'static [u8],
}

impl TransactionalNodeStateMachine for InvalidAccessMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/a".to_vec(),
            self.plan_mode,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                self.update_key.to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn transactional_handler_rejects_undeclared_and_read_only_updates() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let undeclared = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x68)),
        &InvalidAccessMachine {
            plan_mode: NodeStateAccessMode::ReadWrite,
            update_key: b"state/b",
        },
    );
    assert_eq!(
        undeclared,
        Err(NodeCoreError::UndeclaredStateUpdate(b"state/b".to_vec()))
    );

    let read_only = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x69)),
        &InvalidAccessMachine {
            plan_mode: NodeStateAccessMode::ReadOnly,
            update_key: b"state/a",
        },
    );
    assert_eq!(
        read_only,
        Err(NodeCoreError::ReadOnlyStateUpdate(b"state/a".to_vec()))
    );
    assert_eq!(runtime.state_store().get(b"state/a").unwrap(), None);
    assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
}

struct TransactionalConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
}

impl TransactionalNodeStateMachine for TransactionalConflictMachine<'_> {
    fn access_plan(&self, event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        MultiKeyMachine.access_plan(event)
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.runtime
            .state_store()
            .put(b"state/a".to_vec(), canonical(TEST_STATE_TYPE_ID, 99))?;
        MultiKeyMachine.transition(state, event)
    }
}

#[test]
fn transactional_conflict_applies_none_of_the_candidate_updates() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x6A)),
        &TransactionalConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    let a = runtime.state_store().get(b"state/a").unwrap().unwrap();
    assert_eq!(decode_canonical_frame(&a).unwrap().required_u64(1), Ok(99));
    assert_eq!(runtime.state_store().get(b"state/b").unwrap(), None);
}

struct ReadDependencyConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
}

impl TransactionalNodeStateMachine for ReadDependencyConflictMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
            NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        assert_eq!(
            state
                .get(b"state/dependency")
                .and_then(VersionedStateValue::value),
            None
        );
        self.runtime.state_store().put(
            b"state/dependency".to_vec(),
            canonical(TEST_STATE_TYPE_ID, 99),
        )?;
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/result".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn transactional_handler_asserts_read_only_absence_before_commit() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_transactional_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x7B)),
        &ReadDependencyConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert!(
        runtime
            .state_store()
            .get(b"state/dependency")
            .unwrap()
            .is_some()
    );
    assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
}

#[test]
fn idempotent_handler_asserts_read_only_absence_before_commit() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let event = event("sunrise-test", request(0x7C));
    let error = handle_idempotent_event(
        &runtime,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &ReadDependencyConflictMachine { runtime: &runtime },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert_eq!(runtime.state_store().get(b"state/result").unwrap(), None);
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for key in [
        layout.request_dedup_key(*event.request_id().as_bytes()),
        layout.outbox_batch_key(*event.request_id().as_bytes()),
        layout.outbox_delivery_key(*event.request_id().as_bytes()),
    ] {
        assert_eq!(runtime.state_store().get(&key).unwrap(), None);
    }
}

struct DomainReadDependencyConflictMachine<'a> {
    runtime: &'a MemoryRuntime,
    domain: AtomicityDomainId,
}

impl TransactionalNodeStateMachine for DomainReadDependencyConflictMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(b"state/dependency".to_vec(), NodeStateAccessMode::ReadOnly)?,
            NodeStateAccess::new(b"state/result".to_vec(), NodeStateAccessMode::ReadWrite)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let dependency =
            state
                .get(b"state/dependency")
                .ok_or(NodeCoreError::PersistenceInvariant(
                    "dependency missing from snapshot",
                ))?;
        let competing = AtomicStateTransaction::new(
            self.domain,
            AtomicStateReadSet::new(vec![StateReadAssertion::new(
                b"state/dependency".to_vec(),
                dependency.revision(),
            )?])?,
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(
                b"state/dependency".to_vec(),
                StateMutation::Put(canonical(TEST_STATE_TYPE_ID, 99)),
            )?])?,
        )?;
        assert_eq!(
            self.runtime.state_store().commit_transaction(competing)?,
            AtomicStateWriteResult::Committed
        );
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                b"state/result".to_vec(),
                canonical(TEST_STATE_TYPE_ID, 1),
            )?],
            NodeOutput::default(),
        )
    }
}

#[test]
fn domain_idempotent_conflict_publishes_neither_result_receipt_nor_outbox() {
    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let domain = domain(0xB3);
    let event = event("sunrise-test", request(0x83));
    let error = handle_domain_idempotent_event(
        &runtime,
        domain,
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event.clone(),
        &DomainReadDependencyConflictMachine {
            runtime: &runtime,
            domain,
        },
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::StateConflict);
    assert!(
        runtime
            .state_store()
            .get_versioned_in_domain(domain, b"state/dependency")
            .unwrap()
            .value()
            .is_some()
    );
    let layout = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    );
    for key in [
        b"state/result".to_vec(),
        layout.request_dedup_key(*event.request_id().as_bytes()),
        layout.outbox_batch_key(*event.request_id().as_bytes()),
        layout.outbox_delivery_key(*event.request_id().as_bytes()),
    ] {
        assert_eq!(
            runtime
                .state_store()
                .get_versioned_in_domain(domain, &key)
                .unwrap()
                .value(),
            None
        );
    }
}

#[test]
fn transactional_access_and_update_sets_are_bounded_and_unique() {
    let access = NodeStateAccess::new(b"state/a".to_vec(), NodeStateAccessMode::ReadWrite).unwrap();
    assert_eq!(
        NodeStateAccessPlan::new(vec![access.clone(), access]),
        Err(NodeCoreError::DuplicateStateAccessKey)
    );
    assert_eq!(
        NodeStateAccessPlan::new(Vec::new()),
        Err(NodeCoreError::EmptyStateAccessPlan)
    );

    let update = NodeStateUpdate::delete(b"state/a".to_vec()).unwrap();
    assert_eq!(
        TransactionalNodeTransition::new(vec![update.clone(), update], NodeOutput::default(),),
        Err(NodeCoreError::DuplicateStateUpdateKey)
    );
    assert_eq!(
        TransactionalNodeTransition::new(Vec::new(), NodeOutput::default()),
        Err(NodeCoreError::EmptyStateUpdates)
    );
    assert_eq!(
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            Vec::new(),
            NodeOutput::default(),
        ),
        Err(NodeCoreError::EmptyStateUpdates)
    );
    let effects: Vec<ObjectEffect> = (0..=MAX_AUTHENTICATED_OBJECT_READS)
        .map(|index: usize| {
            ObjectEffect::Created(test_object(
                ObjectId::new([u8::try_from(index).unwrap(); 32]),
                1,
                Owner::Immutable,
                u8::try_from(index).unwrap(),
            ))
        })
        .collect();
    assert_eq!(
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            effects,
            NodeOutput::default(),
        ),
        Err(NodeCoreError::TooManyObjectEffects {
            actual: MAX_AUTHENTICATED_OBJECT_READS + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        })
    );
}

#[test]
fn response_must_match_event_request() {
    struct WrongResponseMachine;

    impl NodeStateMachine for WrongResponseMachine {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let response = NodeResponse::new(request(0x77), NodeResponseStatus::Accepted, None)?;
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, 1),
                NodeOutput::new(vec![response], Vec::new())?,
            )
        }
    }

    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x78)),
        &WrongResponseMachine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ResponseRequestMismatch { .. }
    ));
    assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
}

#[test]
fn outbound_event_must_match_invocation_context() {
    struct CrossChainOutputMachine;

    impl NodeStateMachine for CrossChainOutputMachine {
        fn transition(
            &self,
            _current_state: Option<&[u8]>,
            _event: &NodeEvent,
        ) -> Result<NodeTransition, NodeCoreError> {
            let outbound = OutboundMessage::new(event("other-chain", request(0x79)));
            NodeTransition::new(
                canonical(TEST_STATE_TYPE_ID, 1),
                NodeOutput::new(Vec::new(), vec![outbound])?,
            )
        }
    }

    let runtime = MemoryRuntime::new(runtime::ValidatorId::new([0x44; 32]));
    let error = handle_event(
        &runtime,
        &config("sunrise-test"),
        event("sunrise-test", request(0x7A)),
        &CrossChainOutputMachine,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::ChainMismatch { .. }));
    assert_eq!(runtime.state_store().get(b"node/state").unwrap(), None);
}

/// DR-0154: the generic durable-event path commits authenticated provenance for
/// the application key it wrote when the store's signed genesis bound the
/// handoff-capable profile.
///
/// This is a reservation-less event, so it now also depends on the bounded
/// safety fix below: `FastPathEpochRecord` must be installed and current, and
/// `SilentIdempotentMachine` (rather than [`IdempotentMachine`]) is used so
/// this test's assertions stay about provenance, not about the separate
/// nonempty-outbox refusal `the_generic_path_refuses_a_nonempty_outbox_under_the_new_profile`
/// below covers.
#[test]
fn the_generic_path_commits_provenance_under_the_new_profile() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let profile: LogicalProfileRecord = bind_logical_profile(&store, "sunrise-test");
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain(0xC5),
        "sunrise-test",
        Epoch::new(7),
    );
    run_generic_event(
        &store,
        request(0x95),
        &SilentIdempotentMachine {
            calls: AtomicUsize::new(0),
        },
    )
    .unwrap();
    let provenance: LogicalProvenanceRecord =
        read_provenance(&store, &profile, b"state/idempotent");
    assert_eq!(provenance.generation.get(), profile.genesis_floor.get() + 1);
    // The row is bound to the exact bytes this transition wrote, not merely
    // present: a provenance row that described anything else would fail the
    // very next operation's verification.
    let written = store
        .get_versioned_durable(&durable_context(), domain(0xC5), b"state/idempotent")
        .unwrap();
    assert_eq!(
        provenance.observation,
        LogicalObservation::StatePresent {
            content_digest: logical_generation::content_digest(
                &resolver("sunrise-test"),
                Epoch::new(7),
                written.value().unwrap(),
            )
            .unwrap(),
        }
    );
}

/// DR-0154 refusal on the generic durable-event path: a handoff-capable store
/// will not apply a transition over an application row that exists without
/// authenticated provenance. It fails closed instead of treating an
/// unauthenticated row as a verified input.
///
/// Uses [`SilentIdempotentMachine`] and an installed `FastPathEpochRecord` for
/// the same reason as `the_generic_path_commits_provenance_under_the_new_profile`
/// above: this reservation-less event now also passes through the bounded
/// safety fix's epoch/admission fence before reaching the provenance check
/// this test is actually about.
#[test]
fn the_generic_path_refuses_an_unauthenticated_application_row() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    bind_logical_profile(&store, "sunrise-test");
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain(0xC5),
        "sunrise-test",
        Epoch::new(7),
    );
    commit_generic_row(
        &store,
        "sunrise-test",
        b"state/idempotent",
        canonical(TEST_STATE_TYPE_ID, 41),
    );
    assert!(matches!(
        run_generic_event(
            &store,
            request(0x96),
            &SilentIdempotentMachine {
                calls: AtomicUsize::new(0),
            },
        ),
        Err(NodeCoreError::LogicalProvenance(_))
    ));
}

/// A historical store still performs fresh mutations, unchanged, and writes no
/// provenance at all: DR-0154 adds no row and no assertion to a store whose
/// signed genesis never bound the new profile.
#[test]
fn a_historical_store_still_mutates_and_writes_no_provenance() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    run_generic_idempotent(&store, request(0x97)).unwrap();
    let written = store
        .get_versioned_durable(&durable_context(), domain(0xC5), b"state/idempotent")
        .unwrap();
    assert!(written.value().is_some());
    let absent = store
        .get_versioned_durable(&durable_context(), domain(0xC5), &unbound_provenance_key())
        .unwrap();
    assert_eq!(absent.value(), None);
    assert_eq!(absent.revision(), StateRevision::INITIAL);
}

/// Returns one subject's authenticated provenance row.
fn read_provenance(
    store: &MemoryDurableStateStore,
    profile: &LogicalProfileRecord,
    key: &[u8],
) -> LogicalProvenanceRecord {
    let hashes: HashSuiteResolver = resolver("sunrise-test");
    let space = logical_generation::LogicalKeySpace::new(profile, &hashes);
    let subject = logical_generation::LogicalSubject::StateKey(key.to_vec());
    let at: Vec<u8> = space.provenance_key(&subject).unwrap();
    let row = store
        .get_versioned_durable(&durable_context(), domain(0xC5), &at)
        .unwrap();
    logical_generation::decode_logical_provenance_record(row.value().unwrap()).unwrap()
}

/// DR-0154 bounded safety fix: a reservation-less generic durable event still
/// asserts the current-epoch and admission-closure key revisions in the same
/// atomic commit as its application effects, under the handoff-capable
/// profile. [`ScriptedDurableStore::new`] already preloads a matching
/// `FastPathEpochRecord` at epoch 7 for `"sunrise-test"`; admission closure is
/// left unpreloaded (open, at `StateRevision::INITIAL`).
#[test]
fn the_generic_path_fences_epoch_and_admission_even_without_a_reservation() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let chain: ChainId = ChainId::new("sunrise-test").unwrap();
    let profile: LogicalProfileRecord = logical_profile_for("sunrise-test");
    let profile_key: Vec<u8> = logical_generation::logical_profile_key(&chain).unwrap();
    store.preload(
        profile_key,
        StateRevision::new(1),
        encode_logical_profile_record(&profile).unwrap(),
    );

    let machine = SilentIdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xC5, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0x9A)),
        &machine,
    )
    .unwrap();

    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let state = commits[0].state().unwrap();
    let epoch_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain).unwrap();
    let admission_key: Vec<u8> =
        ordered_economics::engine::admission_closure_key_for_tests(&chain, Epoch::new(7));
    let epoch_read = state
        .reads()
        .iter()
        .find(|assertion| assertion.key() == epoch_key.as_slice())
        .expect("current-epoch key must be asserted in the same atomic commit");
    assert_eq!(
        epoch_read.expected_revision(),
        StateRevision::INITIAL.checked_next().unwrap()
    );
    let admission_read = state
        .reads()
        .iter()
        .find(|assertion| assertion.key() == admission_key.as_slice())
        .expect("admission-closure key must be asserted in the same atomic commit");
    assert_eq!(admission_read.expected_revision(), StateRevision::INITIAL);
}

/// A reservation-less generic durable event under the handoff-capable profile
/// refuses a stale (non-current) request epoch, exactly like every reserved
/// mutation path already did.
#[test]
fn the_generic_path_refuses_a_stale_epoch_without_a_reservation() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    bind_logical_profile(&store, "sunrise-test");
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain(0xC5),
        "sunrise-test",
        Epoch::new(8),
    );
    assert_eq!(
        run_generic_idempotent(&store, request(0x9B)),
        Err(NodeCoreError::EpochMismatch {
            expected: Epoch::new(8),
            actual: Epoch::new(7),
        })
    );
}

/// A reservation-less generic durable event under the handoff-capable profile
/// refuses once a committed ordered-economics `Freeze` has installed an
/// `AdmissionClosureRecord` for the current epoch, exactly like every
/// reserved mutation path already does.
#[test]
fn the_generic_path_refuses_when_admission_is_closed_without_a_reservation() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    bind_logical_profile(&store, "sunrise-test");
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain(0xC5),
        "sunrise-test",
        Epoch::new(7),
    );
    let chain: ChainId = ChainId::new("sunrise-test").unwrap();
    let closure_key: Vec<u8> =
        ordered_economics::engine::admission_closure_key_for_tests(&chain, Epoch::new(7));
    let closure = ordered_economics::AdmissionClosureRecord {
        closed_epoch: Epoch::new(7),
        request_id: [9; 32],
        closed_at_block_height: 1,
    };
    commit_generic_row(
        &store,
        "sunrise-test",
        &closure_key,
        ordered_economics::encode_admission_closure_record(&closure).unwrap(),
    );
    assert!(matches!(
        run_generic_idempotent(&store, request(0x9C)),
        Err(NodeCoreError::PersistenceInvariant(
            "admission closed by a committed ordered-economics epoch freeze"
        ))
    ));
}

/// DR-0154 bounded safety fix: the handoff-capable profile has no proven
/// cross-epoch outbox delivery guarantee, so a generic durable event that
/// would produce a nonempty outbox obligation is refused before any mutation
/// is staged or committed, rather than silently admitted.
#[test]
fn the_generic_path_refuses_a_nonempty_outbox_under_the_new_profile() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    bind_logical_profile(&store, "sunrise-test");
    commit_fastpath_epoch_record(
        &store,
        &durable_context(),
        domain(0xC5),
        "sunrise-test",
        Epoch::new(7),
    );
    assert_eq!(
        run_generic_idempotent(&store, request(0x9D)),
        Err(NodeCoreError::LogicalProfileOutboxUnsupported)
    );
    let written = store
        .get_versioned_durable(&durable_context(), domain(0xC5), b"state/idempotent")
        .unwrap();
    assert_eq!(written.value(), None);
    assert_eq!(written.revision(), StateRevision::INITIAL);
}

/// Historical (v1) behavior is unaffected by the outbox refusal above: a
/// store whose signed genesis never bound the handoff-capable profile still
/// admits a generic durable event that produces a nonempty outbox, exactly as
/// before this fix.
#[test]
fn a_historical_store_still_admits_a_nonempty_outbox() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let output = run_generic_idempotent(&store, request(0x9E)).unwrap();
    assert_eq!(output.output().outbound_messages().len(), 1);
}
