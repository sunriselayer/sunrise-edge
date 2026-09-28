use super::*;

// --- DR-0082 bounded query API: router integration --------------------

fn query_object_path(object_id: ObjectId) -> String {
    format!("/v1/objects/{}", hex(object_id.as_bytes()))
}

fn query_receipt_path(id: RequestId) -> String {
    format!("/v1/receipts/{}", hex(id.as_bytes()))
}

fn query_next_nonce_path(sender: &Address) -> String {
    format!("/v1/senders/{}/next-nonce", hex(sender.as_bytes()))
}

#[tokio::test]
async fn context_route_returns_trusted_composition() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD1; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD1; 16]).unwrap(),
    );
    install_fastpath_epoch_record(store.as_ref(), &setup_context, domain);
    let expected_bytes = protocol_config.canonical_bytes().unwrap();
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        QUERY_RESULT_MEDIA_TYPE
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpContextQueryResult::decode(&bytes).unwrap();
    assert_eq!(result.chain_id(), &ChainId::new("sunrise-test").unwrap());
    assert_eq!(result.protocol_version(), ProtocolVersion::new(3));
    assert_eq!(result.epoch(), Epoch::new(7));
    assert_eq!(result.domain(), domain);
    assert_eq!(result.protocol_config_bytes(), expected_bytes.as_slice());
}

/// DR-0132 C7: the public epoch-bearing reads and authenticated native
/// mutation boundary follow the committed singleton after the same e -> e+1
/// record change installed by `epoch_transition::activate`, even while the
/// process-local `NodeConfig` remains at e. The node-core transition suite
/// separately drives the real certified activation that produces this row
/// and deterministically races that activation against direct paid admission,
/// proving the adapter's preliminary read is not mutation authority.
#[tokio::test]
async fn committed_epoch_advance_drives_context_nonce_and_submit_authority() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(3).unwrap();
    let store: Arc<MemoryDurableStateStore> = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain: AtomicityDomainId = AtomicityDomainId::new([0xD0; 32]).unwrap();
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD0; 16]).unwrap(),
    );
    install_fastpath_epoch_record(store.as_ref(), &setup_context, domain);
    install_fastpath_epoch_record_for_epoch(
        store.as_ref(),
        &setup_context,
        domain,
        Epoch::new(8),
        Some(Epoch::new(7)),
    );
    let app: Router = structured_app(
        Arc::clone(&store),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        active_protocol_config(domain),
        config(),
    );

    let context_response: Response = app
        .clone()
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(context_response.status(), StatusCode::OK);
    let context_bytes: Bytes = to_bytes(context_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let context_result: HttpContextQueryResult =
        HttpContextQueryResult::decode(&context_bytes).unwrap();
    assert_eq!(context_result.epoch(), Epoch::new(8));

    let signing_key: ed25519_zebra::SigningKey = dev_signing_key(0xD0);
    let sender: Address = dev_sender_address(&signing_key);
    let nonce_response: Response = app
        .clone()
        .oneshot(
            Request::get(query_next_nonce_path(&sender))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let nonce_bytes: Bytes = to_bytes(nonce_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let nonce_result: HttpNextNonceQueryResult =
        HttpNextNonceQueryResult::decode(&nonce_bytes).unwrap();
    assert_eq!(nonce_result.epoch(), Epoch::new(8));
    assert_eq!(nonce_result.next_nonce(), 0);

    let stale: NodeEvent = signed_submit_transaction_event(&signing_key, request_id(0xD1), 0);
    let stale_response: Response = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(stale.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_response.status(), StatusCode::CONFLICT);

    let fresh_transaction: Transaction = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(8),
        0,
    );
    let fresh: NodeEvent = submit_transaction_event_at_epoch(
        Epoch::new(8),
        request_id(0xD2),
        signed_transaction_bytes(&signing_key, &fresh_transaction),
    );
    let fresh_response: Response = app
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(fresh.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fresh_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn context_route_rejects_inactive_domain_placement_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let config = config();
    // `config()`'s epoch is 7; an activation epoch of 100 makes this
    // placement inactive at the trusted current epoch, exactly like the
    // storage-backed routes' inactive-placement rejection.
    let mut protocol_config = active_protocol_config(AtomicityDomainId::new([0xFC; 32]).unwrap());
    protocol_config.domain_placement = Some(placement(0xFC, 100));
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xFC; 16]).unwrap(),
    );
    install_fastpath_epoch_record(
        store.as_ref(),
        &setup_context,
        AtomicityDomainId::new([0xFC; 32]).unwrap(),
    );
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(QUERY_CONTEXT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn object_route_returns_true_absence() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xD2; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let object_id = ObjectId::new([0x01; 32]);

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::Absent { object_id }
    );
}

#[tokio::test]
async fn object_route_returns_verified_current_inline() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD3; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD3; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xD3));
    let object = owned_object(ObjectId::new([0xD4; 32]), owner, 0x40);
    let object_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x41,
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_ref.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    match HttpObjectQueryResult::decode(&bytes).unwrap() {
        HttpObjectQueryResult::CurrentInline {
            object_id,
            digest,
            canonical_object_bytes,
            ..
        } => {
            assert_eq!(object_id, object_ref.id);
            assert_eq!(digest, object_ref.digest);
            let decoded = objects::decode_object(&canonical_object_bytes).unwrap();
            assert_eq!(decoded.id, object_ref.id);
        }
        other => panic!("expected current inline object, got {other:?}"),
    }
}

#[tokio::test]
async fn object_route_returns_retained_tombstone() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD5; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD5; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xD5));
    let object = owned_object(ObjectId::new([0xD6; 32]), owner, 0x42);
    let object_id = object.id;
    commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x43,
    );
    let current_head = store
        .get_object_head(&setup_context, domain, object_id)
        .unwrap();
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(object_id, current_head)],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Delete,
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x44; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
        vec![0x46],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::Tombstoned {
            object_id,
            head_revision: ObjectHeadRevision::new(2).unwrap(),
            last_object_version: DurableObjectVersion::FIRST,
        }
    );
}

#[tokio::test]
async fn object_route_returns_current_blob_reference_without_fetching_body() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xD7; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xD7; 16]).unwrap(),
    );
    let object_id = ObjectId::new([0xD8; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xD9; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0xDA; 32]);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        digest,
        1,
        DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
        blob_digest,
    );
    let owner = dev_sender_address(&dev_signing_key(0xDB));
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(owner))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0xDC; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xDD; 32]),
        vec![0xDE],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let blob_store = Arc::new(CountingBlobStore::default());
    let app = structured_app_with_blob_store(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpObjectQueryResult::decode(&bytes).unwrap(),
        HttpObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            blob_digest,
        }
    );
    assert_eq!(
        blob_store.get_calls(),
        0,
        "the query route must never fetch a blob body through the supplied blob store"
    );
}

#[tokio::test]
async fn object_route_tampered_digest_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xE1; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xE1; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xE2));
    let object_id = ObjectId::new([0xE3; 32]);
    let object = owned_object(object_id, owner, 0x50);
    let canonical_bytes = encode_object(&object).unwrap();
    let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
    let record = DurableObjectVersionRecord::from_inline_canonical_bytes(
        canonical_bytes,
        tampered_digest,
        DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
    )
    .unwrap();
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version: record,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(owner))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0xE4; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xE5; 32]),
        vec![0xE6],
    )
    .unwrap();
    let invocation =
        DurableInvocationTransaction::new(domain, None, changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_object_path(object_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn object_route_writer_fence_mismatch_is_opaque_unavailable() {
    let authority_fence = WriterFenceGeneration::new(3).unwrap();
    // The store's own active fence differs from the authority's fence
    // that `structured_app` fixes via `structured_request_authority()`,
    // so the durable read proves `WriterFenced` rather than corruption.
    let store_fence = WriterFenceGeneration::new(9).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(store_fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF6; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let _ = authority_fence;

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[tokio::test]
async fn object_route_identity_unavailable_is_opaque_unavailable() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF7; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(FailingIndexedIdentities {
                error: IndexedOutboxIdentitySourceError::Unavailable,
            }),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[tokio::test]
async fn object_route_identity_exhausted_is_opaque_invalid() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xF9; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(FailingIndexedIdentities {
                error: IndexedOutboxIdentitySourceError::Exhausted,
            }),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn object_route_clock_failure_is_opaque_unavailable() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xFA; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(FailingClock),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
}

#[test]
fn query_node_error_response_parts_classifies_durable_read_variants() {
    let cases: Vec<(NodeCoreError, StatusCode, &str)> = vec![
        (
            NodeCoreError::DurableRead(DurableReadError::WriterFenced {
                active_generation: WriterFenceGeneration::new(3).unwrap(),
            }),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::DeadlineExceeded),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        // `SchemaMismatch` is an explicit decision (DR-0082): it proves an
        // adapter/deployment schema disagreement, not corrupted persisted
        // bytes, so it is grouped with the other availability conditions
        // rather than with `query-state-invalid`.
        (
            NodeCoreError::DurableRead(DurableReadError::SchemaMismatch),
            StatusCode::SERVICE_UNAVAILABLE,
            "query-unavailable",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::InvalidPersistedState),
            StatusCode::INTERNAL_SERVER_ERROR,
            "query-state-invalid",
        ),
        (
            NodeCoreError::DurableRead(DurableReadError::InvalidRequest(
                RuntimeError::UnsupportedObjectStorage,
            )),
            StatusCode::INTERNAL_SERVER_ERROR,
            "query-state-invalid",
        ),
    ];
    for (error, expected_status, expected_code) in cases {
        let (status, code) = query_node_error_response_parts(&error);
        assert_eq!(status, expected_status, "error: {error:?}");
        assert_eq!(code, expected_code, "error: {error:?}");
    }
}

#[tokio::test]
async fn object_route_rejects_inactive_domain_placement_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let config = config();
    // `config()`'s epoch is 7; an activation epoch of 100 makes this
    // placement inactive at the trusted current epoch.
    let mut protocol_config = active_protocol_config(AtomicityDomainId::new([0xFB; 32]).unwrap());
    protocol_config.domain_placement = Some(placement(0xFB, 100));
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-unavailable"
    );
    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn receipt_route_returns_true_absence() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xE7; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let id = request_id(0x01);

    let response = app
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes).unwrap(),
        HttpReceiptQueryResult::Absent { request_id: id }
    );
}

#[tokio::test]
async fn receipt_route_corrupt_receipt_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xE9; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xE9; 16]).unwrap(),
    );
    let id = request_id(0x02);
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(*id.as_bytes()).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xEA; 32]),
        vec![0xEB, 0x00],
    )
    .unwrap();
    let invocation = DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::empty(),
        receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&setup_context, invocation),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn receipt_and_next_nonce_routes_reflect_a_real_submission() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xE8; 32]).unwrap();
    install_fastpath_epoch_record(store.as_ref(), &live_operation_context(fence, 0xF6), domain);
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let signing_key = dev_signing_key(0xE9);
    let sender = dev_sender_address(&signing_key);
    let id = request_id(0xEA);
    let event = signed_submit_transaction_event(&signing_key, id, 0);

    let submit_response = app
        .clone()
        .oneshot(
            Request::post(NODE_EVENT_PATH)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(event.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(submit_response.status(), StatusCode::OK);

    let receipt_response = app
        .clone()
        .oneshot(
            Request::get(query_receipt_path(id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt_response.status(), StatusCode::OK);
    let receipt_bytes = to_bytes(receipt_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    match HttpReceiptQueryResult::decode(&receipt_bytes).unwrap() {
        HttpReceiptQueryResult::Present {
            request_id,
            dedup_record_bytes,
            ..
        } => {
            assert_eq!(request_id, id);
            let record = NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
            assert_eq!(record.request_id(), id);
        }
        other => panic!("expected present receipt, got {other:?}"),
    }

    let nonce_response = app
        .oneshot(
            Request::get(query_next_nonce_path(&sender))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_response.status(), StatusCode::OK);
    let nonce_bytes = to_bytes(nonce_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let nonce_result = HttpNextNonceQueryResult::decode(&nonce_bytes).unwrap();
    assert_eq!(nonce_result.sender(), sender);
    assert_eq!(nonce_result.epoch(), Epoch::new(7));
    assert_eq!(nonce_result.next_nonce(), 1);
}

#[tokio::test]
async fn next_nonce_route_true_absence_returns_zero() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xEB; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let setup_context: DurableOperationContext = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xEB; 16]).unwrap(),
    );
    install_fastpath_epoch_record(store.as_ref(), &setup_context, domain);
    let app = structured_app(
        store,
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );
    let sender = Address::new([0x01; 32]);

    let response = app
        .oneshot(
            Request::get(query_next_nonce_path(&sender))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
        .await
        .unwrap();
    let result = HttpNextNonceQueryResult::decode(&bytes).unwrap();
    assert_eq!(result.sender(), sender);
    assert_eq!(result.next_nonce(), 0);
    assert_eq!(result.epoch(), Epoch::new(7));
}

#[tokio::test]
async fn next_nonce_route_deleted_record_is_opaque_server_error() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xEC; 32]).unwrap();
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xEC; 16]).unwrap(),
    );
    let sender = [0x02; 32];
    let key = PersistenceLayout::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
    )
    .sender_nonce_key(sender, Epoch::new(7));
    let transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&setup_context, transaction),
        DurableCommitOutcome::Committed
    );

    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let app = structured_app(
        Arc::clone(&store),
        transport,
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
    );

    let response = app
        .oneshot(
            Request::get(query_next_nonce_path(&Address::new(sender)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), 128).await.unwrap(),
        "query-state-invalid"
    );
}

#[tokio::test]
async fn query_routes_reject_malformed_selectors_before_any_side_effect() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xED; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let clock = Arc::new(CountingClock::new(10_000));
    let identities = Arc::new(CountingIndexedIdentities::default());
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::clone(&clock),
            Arc::clone(&identities),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let malformed_paths: Vec<String> = vec![
        "/v1/objects/too-short".to_string(),
        format!("/v1/objects/{}", "A".repeat(64)),
        format!("/v1/receipts/{}", "0".repeat(64)),
        format!("/v1/receipts/{}", "g".repeat(64)),
        "/v1/senders/short/next-nonce".to_string(),
    ];
    for path in malformed_paths {
        let response = app
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path: {path}");
    }

    assert_eq!(clock.calls.load(Ordering::SeqCst), 0);
    assert_eq!(identities.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn both_routers_return_identical_results_for_all_four_query_routes() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let domain = AtomicityDomainId::new([0xEE; 32]).unwrap();
    let config = config();
    let protocol_config = active_protocol_config(domain);
    let catalog = Arc::new(PreinstalledModuleCatalog::new(Vec::new()).unwrap());

    // Populate one verified current-inline object and one present receipt
    // so parity is checked against real content, not only absence.
    // Tombstone and blob-reference results are covered by dedicated
    // structured-router tests and need not be duplicated here.
    let setup_context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(20_000).unwrap(),
        StorageCorrelationId::new([0xEE; 16]).unwrap(),
    );
    let owner = dev_sender_address(&dev_signing_key(0xEE));
    let object = owned_object(ObjectId::new([0xEF; 32]), owner, 0x46);
    let object_ref = commit_owned_object(
        store.as_ref(),
        &setup_context,
        domain,
        object,
        "sunrise-test",
        1,
        0x47,
    );

    let structured = structured_app(
        Arc::clone(&store),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        protocol_config.clone(),
        config.clone(),
    );
    let preinstalled = preinstalled_app(
        Arc::clone(&store),
        Arc::new(MemoryTransport::default()),
        Arc::new(ManualClock::new(10_000)),
        protocol_config,
        config,
        catalog,
        9,
    );

    let populated_object_path: String = query_object_path(object_ref.id);
    let populated_receipt_path: String = query_receipt_path(request_id(0x47));
    let paths: [String; 6] = [
        QUERY_CONTEXT_PATH.to_string(),
        query_object_path(ObjectId::new([0x01; 32])),
        populated_object_path.clone(),
        query_receipt_path(request_id(0x02)),
        populated_receipt_path.clone(),
        query_next_nonce_path(&Address::new([0x03; 32])),
    ];
    for path in paths {
        let structured_response = structured
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let preinstalled_response = preinstalled
            .clone()
            .oneshot(Request::get(path.as_str()).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            structured_response.status(),
            preinstalled_response.status(),
            "path: {path}"
        );
        assert_eq!(
            structured_response.headers().get(header::CONTENT_TYPE),
            preinstalled_response.headers().get(header::CONTENT_TYPE),
            "path: {path}"
        );
        assert_eq!(
            structured_response.headers().get(header::CACHE_CONTROL),
            preinstalled_response.headers().get(header::CACHE_CONTROL),
            "path: {path}"
        );
        let structured_bytes = to_bytes(structured_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
            .await
            .unwrap();
        let preinstalled_bytes =
            to_bytes(preinstalled_response.into_body(), MAX_HTTP_EVENT_BODY_BYTES)
                .await
                .unwrap();
        assert_eq!(structured_bytes, preinstalled_bytes, "path: {path}");
        if path == populated_object_path {
            assert!(matches!(
                HttpObjectQueryResult::decode(&structured_bytes).unwrap(),
                HttpObjectQueryResult::CurrentInline { .. }
            ));
        } else if path == populated_receipt_path {
            assert!(matches!(
                HttpReceiptQueryResult::decode(&structured_bytes).unwrap(),
                HttpReceiptQueryResult::Present { .. }
            ));
        }
    }
}

#[tokio::test]
async fn object_route_admission_rejects_when_blocking_capacity_exhausted() {
    let fence = WriterFenceGeneration::new(3).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    store.set_time(10_000);
    let transport = Arc::new(MemoryTransport::default());
    let config = config();
    let domain = AtomicityDomainId::new([0xEF; 32]).unwrap();
    let protocol_config = active_protocol_config(domain);
    let blocking_executor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
    let machine = Arc::new(IncrementMachine::new(config.state_key()));
    let app = structured_durable_router_with_executor(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            transport,
            Arc::new(ManualClock::new(10_000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        protocol_config,
        structured_request_authority(),
        config,
        resolver(),
        machine,
        blocking_executor.clone(),
    )
    .unwrap();
    let held_permit = blocking_executor.try_acquire().unwrap();

    let response = app
        .oneshot(
            Request::get(query_object_path(ObjectId::new([0x01; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(held_permit);
}

#[tokio::test]
async fn object_route_rejects_cancellation_at_each_pre_storage_checkpoint() {
    for cancel_at_call in 1_usize..=3_usize {
        let fence = WriterFenceGeneration::new(3).unwrap();
        let store = Arc::new(MemoryDurableStateStore::new(fence));
        store.set_time(10_000);
        let transport = Arc::new(MemoryTransport::default());
        let clock = Arc::new(ManualClock::new(10_000));
        let config = config();
        let domain = AtomicityDomainId::new([0xF5; 32]).unwrap();
        let protocol_config = active_protocol_config(domain);
        let cancellation: Arc<StepCancellation> = Arc::new(StepCancellation::new(cancel_at_call));
        let app = structured_app_with_cancellation(
            store,
            transport,
            clock,
            protocol_config,
            config,
            cancellation.clone(),
        );

        let response = app
            .oneshot(
                Request::get(query_object_path(ObjectId::new([0x01; 32])))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            to_bytes(response.into_body(), 128).await.unwrap(),
            "invocation-cancelled-before-storage"
        );
        assert_eq!(cancellation.calls(), cancel_at_call);
    }
}
