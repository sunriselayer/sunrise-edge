// --- DR-0082 bounded Developer MVP query API -------------------------

#[test]
fn query_next_nonce_true_absence_returns_zero() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();

    let next_nonce = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF1),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        [0x11; 32],
    )
    .unwrap();

    assert_eq!(next_nonce, 0);
}

#[test]
fn query_next_nonce_returns_advanced_persisted_value() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x12; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    let record = SenderNonceRecord::new(sender, Epoch::new(7), 5);
    let transaction = AtomicStateTransaction::new(
        domain(0xF2),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(record.encode().unwrap())).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let next_nonce = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF2),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap();

    assert_eq!(next_nonce, 5);
}

#[test]
fn query_next_nonce_deleted_record_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x13; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    // A delete from true absence still installs a non-`INITIAL` revision
    // with no value: the exact "deleted while its epoch may be accepted"
    // corruption this query must fail closed on, distinct from true
    // absence (which is `INITIAL` with no value).
    let transaction = AtomicStateTransaction::new(
        domain(0xF3),
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
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let error = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF3),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_next_nonce_corrupt_record_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context = durable_context();
    let sender = [0x14; 32];
    let key = sender_nonce_key_for("sunrise-test", sender, Epoch::new(7));
    let transaction = AtomicStateTransaction::new(
        domain(0xF4),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(vec![0xFF, 0x00, 0x01])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    let error = query_sender_next_nonce(
        &store,
        &context,
        domain(0xF4),
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        sender,
    )
    .unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_object_true_absence() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x21; 32]);
    store.preload_object(object_id, DurableObjectHead::Absent, None);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x61), &chain_id, object_id).unwrap();

    assert_eq!(result, ObjectQueryResult::Absent { object_id });
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_retained_tombstone() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x22; 32]);
    let head = DurableObjectHead::Tombstoned {
        head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
        last_object_version: DurableObjectVersion::new(2).unwrap(),
    };
    store.preload_object(object_id, head, None);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x62), &chain_id, object_id).unwrap();

    assert_eq!(
        result,
        ObjectQueryResult::Tombstoned {
            object_id,
            head_revision: runtime::ObjectHeadRevision::new(3).unwrap(),
            last_object_version: DurableObjectVersion::new(2).unwrap(),
        }
    );
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_verified_current_inline() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x23; 32]);
    let owner = Owner::Address(Address::new([0x24; 32]));
    let (object_ref, _head) = preload_inline_object(&store, "sunrise-test", object_id, owner, 0x25);
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x63), &chain_id, object_id).unwrap();

    match &result {
        ObjectQueryResult::CurrentInline {
            object_id: result_object_id,
            head_revision,
            object_version,
            digest,
            creating_chain_id,
            protocol_version,
            canonical_object_bytes,
        } => {
            assert_eq!(*result_object_id, object_id);
            assert_eq!(*head_revision, runtime::ObjectHeadRevision::FIRST);
            assert_eq!(*object_version, DurableObjectVersion::FIRST);
            assert_eq!(*digest, object_ref.digest);
            assert_eq!(creating_chain_id.as_str(), "sunrise-test");
            assert_eq!(*protocol_version, ProtocolVersion::new(3));
            let decoded = objects::decode_object(canonical_object_bytes).unwrap();
            assert_eq!(decoded.id, object_id);
            assert_eq!(decoded.version, 1);
        }
        other => panic!("expected verified current inline object, got {other:?}"),
    }
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_current_blob_reference_returns_metadata_without_fetching_body() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x26; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x27; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x28; 32]);
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
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::default(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let result = query_object(&store, &context, domain(0x64), &chain_id, object_id).unwrap();

    assert_eq!(
        result,
        ObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            blob_digest,
        }
    );
    assert_eq!(result.object_id(), object_id);
}

#[test]
fn query_object_wrong_chain_blob_reference_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x2C; 32]);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x2D; 32]);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha3_256, [0x2E; 32]);
    // Provenance names a different chain than the trusted chain the
    // query is scoped to: this must fail closed before ever branching on
    // inline vs. blob payload, even though a blob body is never fetched.
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        digest,
        1,
        DurableObjectProvenance::new(
            ChainId::new("other-chain").unwrap(),
            ProtocolVersion::new(3),
        ),
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::default(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let error = query_object(&store, &context, domain(0x6D), &chain_id, object_id).unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectProvenanceMismatch { object_id: id } if id == object_id
    ));
}

#[test]
fn query_object_tampered_digest_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x29; 32]);
    let owner = Owner::Address(Address::new([0x2A; 32]));
    let object = test_object(object_id, 1, owner.clone(), 0x2B);
    let (record, _correct_digest) = hashed_object_version(object, "sunrise-test", 1);
    let inline = record.payload().inline().unwrap().clone();
    // A digest that disagrees with the actual canonical body, while head
    // and version still agree with each other, so only the independent
    // recomputation against the body itself can catch the tamper.
    let tampered_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x00; 32]);
    let tampered_record = DurableObjectVersionRecord::from_inline_canonical_bytes(
        inline.canonical_bytes().to_vec(),
        tampered_digest,
        record.provenance().clone(),
        record.created_checkpoint(),
    )
    .unwrap();
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: tampered_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(tampered_record));
    let context = durable_context();
    let chain_id = ChainId::new("sunrise-test").unwrap();

    let error = query_object(&store, &context, domain(0x65), &chain_id, object_id).unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyDigestMismatch { object_id: id } if id == object_id
    ));
}

#[test]
fn query_receipt_true_absence() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x31);

    let result = query_request_receipt(&store, &context, domain(0x71), req).unwrap();

    assert_eq!(result, ReceiptQueryResult::Absent { request_id: req });
    assert_eq!(result.request_id(), req);
}

#[test]
fn query_receipt_present_is_independently_reverified() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x32);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
    let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
    let dedup = NodeDedupRecord::new(req, event_digest, vec![response]).unwrap();
    let canonical_bytes = dedup.encode().unwrap();
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let receipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, canonical_bytes.clone())
            .unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let result = query_request_receipt(&store, &context, domain(0x72), req).unwrap();

    match &result {
        ReceiptQueryResult::Present {
            request_id: result_request_id,
            event_digest: got_digest,
            record,
        } => {
            assert_eq!(*result_request_id, req);
            assert_eq!(*got_digest, event_digest);
            assert_eq!(record.encode().unwrap(), canonical_bytes);
        }
        other => panic!("expected present receipt, got {other:?}"),
    }
    assert_eq!(result.request_id(), req);
}

#[test]
fn query_receipt_corrupt_bytes_fail_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x34);
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x35; 32]);
    let receipt =
        DurableRequestReceipt::new(durable_request_id, event_digest, vec![0xEE, 0x00]).unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let error = query_request_receipt(&store, &context, domain(0x73), req).unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}

#[test]
fn query_receipt_outer_digest_mismatch_fails_closed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let context = durable_context();
    let req = request(0x36);
    let durable_request_id = DurableRequestId::new(*req.as_bytes()).unwrap();
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x37; 32]);
    let outer_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x38; 32]);
    let response = NodeResponse::new(req, NodeResponseStatus::Accepted, None).unwrap();
    let dedup = NodeDedupRecord::new(req, record_digest, vec![response]).unwrap();
    let canonical_bytes = dedup.encode().unwrap();
    let receipt =
        DurableRequestReceipt::new(durable_request_id, outer_digest, canonical_bytes).unwrap();
    store.receipt.lock().unwrap().replace(receipt);

    let error = query_request_receipt(&store, &context, domain(0x74), req).unwrap_err();

    assert!(matches!(error, NodeCoreError::PersistenceInvariant(_)));
}
