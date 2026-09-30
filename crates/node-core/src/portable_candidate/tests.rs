//! Independent golden framing and incremental adversarial transport tests.
use super::*;
use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteSchedule};
use runtime::{DurableDomainStateStore, MemoryDurableStateStore};
use sha2::{Digest, Sha256};

fn marked(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("portable-vectors").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn identity() -> PortableCandidateIdentity {
    PortableCandidateIdentity {
        drain_identity: DrainUnionIdentity {
            chain_id: ChainId::new("portable-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            domain: AtomicityDomainId::new([0x14; 32]).unwrap(),
            closure_request_id: [0x15; 32],
            closure_height: 2,
            signer_count: 3,
            member_count: 0,
            entries_digest: marked(0x11),
        },
        terminal_height: 7,
        terminal_digest: marked(0x12),
        terminal_proof_digest: marked(0x13),
    }
}
fn row(bytes: Vec<u8>) -> PortableCandidateTransferItem {
    PortableCandidateTransferItem {
        identity_digest: identity().digest(&resolver()).unwrap(),
        collection: DurableCollection::State,
        row_index: 0,
        boundary: PortableCandidateBoundary::Row(PortableCandidateRowTransfer {
            key: DurableRecordKey::State(b"app/key".to_vec()),
            descriptor: PortableCandidateDescriptor::State { deleted: false },
            chunk_offset: 0,
            chunk_bytes: bytes,
            chunk_is_last: true,
        }),
    }
}
fn row_mut(item: &mut PortableCandidateTransferItem) -> &mut PortableCandidateRowTransfer {
    let PortableCandidateBoundary::Row(row) = &mut item.boundary else {
        panic!("row required")
    };
    row
}
fn stream(
    mut rows: Vec<PortableCandidateTransferItem>,
) -> (
    Vec<PortableCandidateTransferItem>,
    PortableCandidateManifest,
) {
    let identity: PortableCandidateIdentity = identity();
    let id: Digest32 = identity.digest(&resolver()).unwrap();
    for (index, collection) in PORTABLE_CANDIDATE_COLLECTION_ORDER.into_iter().enumerate() {
        let count: u64 = u64::from(index == 0);
        rows.push(PortableCandidateTransferItem {
            identity_digest: id,
            collection,
            row_index: count,
            boundary: PortableCandidateBoundary::CollectionEnd { row_count: count },
        });
    }
    let mut running: Digest32 = id;
    for (index, item) in rows.iter().enumerate() {
        running = driver::next_hash_step(
            &resolver(),
            identity.drain_identity.epoch,
            &id,
            u64::try_from(index).unwrap() + 1,
            &running,
            &encode_portable_candidate_transfer_item(item).unwrap(),
        )
        .unwrap();
    }
    (
        rows,
        PortableCandidateManifest {
            identity,
            row_counts: [1, 0, 0, 0],
            final_hash_step: running,
        },
    )
}
fn raw_sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Loss before or after the actual CAS must remain a typed unknown outcome,
/// never an emitted item. Reads delegate to the real durable memory store.
struct UnconfirmedProgress<'a> {
    inner: &'a MemoryDurableStateStore,
    commit_before_loss: bool,
}
impl DurableDomainStateStore for UnconfirmedProgress<'_> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if self.commit_before_loss {
            let outcome: DurableCommitOutcome = self.inner.commit_durable(context, transaction);
            if outcome != DurableCommitOutcome::Committed {
                return outcome;
            }
        }
        DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost)
    }
}
impl StructuredDurableDomainStateStore for UnconfirmedProgress<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn unconfirmed_progress_is_not_success_and_committed_bytes_can_be_reconciled_without_reapplication()
{
    let progress: PortableCandidateProgress = progress_vector();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x21; 32]).unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let context: DurableOperationContext = DurableOperationContext::new(
        fence,
        runtime::StorageDeadline::new(u64::MAX).unwrap(),
        runtime::StorageCorrelationId::new([1; 16]).unwrap(),
    );
    let key: Vec<u8> = progress::portable_candidate_progress_key(&progress.identity_digest);
    for commit_before_loss in [false, true] {
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain, fence);
        let unconfirmed: UnconfirmedProgress<'_> = UnconfirmedProgress {
            inner: &store,
            commit_before_loss,
        };
        assert!(matches!(
            driver::persist_progress(
                &unconfirmed,
                &context,
                domain,
                &key,
                StateRevision::INITIAL,
                &progress
            ),
            Err(PortableCandidateError::Indeterminate(_))
        ));
        let saved: VersionedStateValue =
            store.get_versioned_durable(&context, domain, &key).unwrap();
        if commit_before_loss {
            assert_eq!(
                decode_portable_candidate_progress(saved.value().unwrap()).unwrap(),
                progress
            );
            let source: MemoryDurableStateStore =
                MemoryDurableStateStore::new_bound(progress.source_domain, fence);
            // This intentionally has a different namespace from the vector.
            // Any fresh source read would fail, while saved-item replay works.
            assert_eq!(
                advance_portable_candidate_transfer(
                    &source,
                    &context,
                    &resolver(),
                    &identity(),
                    &store,
                    &context,
                    domain,
                    0
                )
                .unwrap(),
                PortableCandidateAdvanceOutcome::Item(row(vec![0xa1, 0xa2]))
            );
            assert_eq!(
                store.get_versioned_durable(&context, domain, &key).unwrap(),
                saved
            );
            assert!(matches!(
                driver::persist_progress(
                    &unconfirmed,
                    &context,
                    domain,
                    &key,
                    StateRevision::INITIAL,
                    &progress
                ),
                Err(PortableCandidateError::Conflict(_))
            ));
            assert_eq!(
                store.get_versioned_durable(&context, domain, &key).unwrap(),
                saved
            );
        } else {
            assert!(saved.value().is_none());
            assert_eq!(saved.revision(), StateRevision::INITIAL);
        }
    }
}

fn progress_vector() -> PortableCandidateProgress {
    let id: Digest32 = identity().digest(&resolver()).unwrap();
    let item: Vec<u8> = encode_portable_candidate_transfer_item(&row(vec![0xa1, 0xa2])).unwrap();
    PortableCandidateProgress {
        identity_digest: id,
        source_namespace: b"mem/portable-test".to_vec(),
        source_domain: AtomicityDomainId::new([0x14; 32]).unwrap(),
        source_writer_fence: WriterFenceGeneration::new(1).unwrap(),
        source_mutation_sequence: 4,
        collection_index: 0,
        next_row_index: 1,
        next_chunk_offset: 0,
        item_count: 1,
        running_hash_step: driver::next_hash_step(&resolver(), Epoch::new(9), &id, 1, &id, &item)
            .unwrap(),
        last_item_bytes: item,
        row_counts: [1, 0, 0, 0],
        skip_scan_after: Vec::new(),
    }
}

#[test]
fn excluded_pages_persist_a_bounded_skip_cursor_without_emitting_or_hashing_an_item() {
    let mut progress: PortableCandidateProgress = progress_vector();
    let domain: AtomicityDomainId = AtomicityDomainId::new([0x21; 32]).unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let context: DurableOperationContext = DurableOperationContext::new(
        fence,
        runtime::StorageDeadline::new(u64::MAX).unwrap(),
        runtime::StorageCorrelationId::new([1; 16]).unwrap(),
    );
    let source: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(progress.source_domain, fence);
    // Transport-only synthetic local rows, not authenticated business state.
    for index in 0..=MAX_PORTABLE_PAGE_KEYS {
        let key: Vec<u8> =
            format!("se/instances/v1/portable-candidate/local-{index:04}").into_bytes();
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            progress.source_domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(Vec::new())).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            source.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );
    }
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context, progress.source_domain)
        .unwrap();
    progress.source_namespace = token.namespace().to_vec();
    progress.source_mutation_sequence = token.mutation_sequence();
    progress.item_count = 0;
    progress.next_row_index = 0;
    progress.last_item_bytes.clear();
    progress.row_counts = [0; 4];
    progress.running_hash_step = progress.identity_digest;
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(domain, fence);
    let key: Vec<u8> = progress::portable_candidate_progress_key(&progress.identity_digest);
    driver::persist_progress(
        &store,
        &context,
        domain,
        &key,
        StateRevision::INITIAL,
        &progress,
    )
    .unwrap();
    assert_eq!(
        advance_portable_candidate_transfer(
            &source,
            &context,
            &resolver(),
            &identity(),
            &store,
            &context,
            domain,
            0
        )
        .unwrap(),
        PortableCandidateAdvanceOutcome::Continue
    );
    let skipped: PortableCandidateProgress = decode_portable_candidate_progress(
        store
            .get_versioned_durable(&context, domain, &key)
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        skipped.skip_scan_after,
        format!(
            "se/instances/v1/portable-candidate/local-{:04}",
            MAX_PORTABLE_PAGE_KEYS - 1
        )
        .into_bytes()
    );
    assert_eq!(skipped.item_count, 0);
    assert_eq!(skipped.running_hash_step, progress.identity_digest);
    assert!(skipped.last_item_bytes.is_empty());
    assert_eq!(skipped.row_counts, [0; 4]);
    let end: PortableCandidateTransferItem = PortableCandidateTransferItem {
        identity_digest: progress.identity_digest,
        collection: DurableCollection::State,
        row_index: 0,
        boundary: PortableCandidateBoundary::CollectionEnd { row_count: 0 },
    };
    assert_eq!(
        advance_portable_candidate_transfer(
            &source,
            &context,
            &resolver(),
            &identity(),
            &store,
            &context,
            domain,
            0
        )
        .unwrap(),
        PortableCandidateAdvanceOutcome::Item(end)
    );
    assert_eq!(
        token,
        source
            .begin_portable_snapshot(&context, progress.source_domain)
            .unwrap()
    );
}

#[test]
fn progress_and_hash_step_match_independent_javascript_vectors_and_reject_impossible_cursors() {
    let progress: PortableCandidateProgress = progress_vector();
    let step: Vec<u8> = driver::encode_hash_step(
        &progress.identity_digest,
        1,
        &progress.identity_digest,
        &progress.last_item_bytes,
    )
    .unwrap();
    assert_eq!(
        raw_sha(&step),
        "104ab01d79d78338ea57de6a47ca560bd7b18ca626e51ec0d181d764b0ad60ed"
    );
    assert_eq!(
        progress
            .running_hash_step
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "c9eff8a83ee1d29f3b64741c324a3b06b5bd4498741e85633d03bbf766a57aba"
    );
    let bytes: Vec<u8> = progress::encode_portable_candidate_progress(&progress).unwrap();
    assert_eq!(
        raw_sha(&bytes),
        "4c195531b3fca41b0d7be6e3feb0a8f29bc56f642b9a976f3a1f2ead2e450671"
    );
    assert_eq!(
        decode_portable_candidate_progress(&bytes).unwrap(),
        progress
    );
    let mut invalid: Vec<PortableCandidateProgress> = vec![progress.clone(); 7];
    invalid[0].source_namespace = Vec::new();
    invalid[1].collection_index = 5;
    invalid[2].next_row_index = 0;
    invalid[3].next_chunk_offset = 1;
    invalid[4].row_counts[1] = 1;
    invalid[5].item_count = 0;
    invalid[6].last_item_bytes = Vec::new();
    for bad in invalid {
        assert!(progress::encode_portable_candidate_progress(&bad).is_err());
    }
    assert!(
        driver::encode_hash_step(
            &progress.identity_digest,
            0,
            &progress.identity_digest,
            &progress.last_item_bytes
        )
        .is_err()
    );
    let mut unknown_version: Vec<u8> = bytes.clone();
    unknown_version[6..8].copy_from_slice(&2u16.to_le_bytes());
    assert!(decode_portable_candidate_progress(&unknown_version).is_err());
    let mut trailing: Vec<u8> = bytes;
    trailing.push(0);
    assert!(decode_portable_candidate_progress(&trailing).is_err());
}

#[test]
fn canonical_frames_match_independent_javascript_vectors() {
    let id: PortableCandidateIdentity = identity();
    let bytes: Vec<u8> = encode_portable_candidate_identity(&id).unwrap();
    assert_eq!(decode_portable_candidate_identity(&bytes).unwrap(), id);
    assert_eq!(
        raw_sha(&bytes),
        "4ae1364d4cc5d738f8d28398cbf5e3456f11a7ac0cad26813d73fc4854ee5ce2"
    );
    assert_eq!(
        id.digest(&resolver())
            .unwrap()
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "d915ef86d6052b224eb5e166ef09a212cc81807ee52afe9c0adf056eab5bbf1e"
    );
    for (deleted, hash) in [
        (
            false,
            "a69598e2550231fd29badb10bc6693f414b1fbfcefbda923de1894ddc9cdae9a",
        ),
        (
            true,
            "e4608b50a109ab1930362dd7d91a368df1c70a6037a73f818a8080c770a65230",
        ),
    ] {
        let descriptor: PortableCandidateDescriptor =
            PortableCandidateDescriptor::State { deleted };
        let bytes: Vec<u8> = encode_portable_candidate_descriptor(&descriptor).unwrap();
        assert_eq!(
            decode_portable_candidate_descriptor(&bytes).unwrap(),
            descriptor
        );
        assert_eq!(raw_sha(&bytes), hash);
    }
    let item: PortableCandidateTransferItem = row(vec![0xa1, 0xa2]);
    let bytes: Vec<u8> = encode_portable_candidate_transfer_item(&item).unwrap();
    assert_eq!(
        decode_portable_candidate_transfer_item(&bytes).unwrap(),
        item
    );
    assert_eq!(
        raw_sha(&bytes),
        "b537b3dbd46b0ad7077cd4cf941dc148c77baad2067fff13e60ff64e8b4f6333"
    );
    let manifest: PortableCandidateManifest = PortableCandidateManifest {
        identity: id,
        row_counts: [1, 0, 0, 0],
        final_hash_step: marked(0x17),
    };
    let bytes: Vec<u8> = encode_portable_candidate_manifest(&manifest).unwrap();
    assert_eq!(
        decode_portable_candidate_manifest(&bytes).unwrap(),
        manifest
    );
    assert_eq!(
        raw_sha(&bytes),
        "7875d834a587f818ecfcbfc2e5d579f9747b2e3fc40a7e9804827fd130e75e6e"
    );
}

#[test]
fn verifier_rejects_foreign_gap_kind_tombstone_local_rows_without_advancing() {
    let (items, manifest) = stream(vec![row(vec![0xa1, 0xa2])]);
    let original: PortableCandidateVerifier =
        PortableCandidateVerifier::new(&resolver(), manifest).unwrap();
    let mut bad: Vec<PortableCandidateTransferItem> = vec![items[0].clone(); 7];
    bad[0].identity_digest = marked(0xee);
    bad[1].row_index = 1;
    row_mut(&mut bad[2]).chunk_offset = 1;
    row_mut(&mut bad[3]).descriptor = PortableCandidateDescriptor::Receipt {
        event_digest: marked(3),
    };
    row_mut(&mut bad[4]).descriptor = PortableCandidateDescriptor::State { deleted: true };
    row_mut(&mut bad[5]).key = DurableRecordKey::State(b"se/instances/v1/fastpath/lock/x".to_vec());
    row_mut(&mut bad[6]).chunk_is_last = false;
    for item in bad {
        let mut verifier: PortableCandidateVerifier = original.clone();
        assert!(verifier.verify_next(&resolver(), &item).is_err());
        assert_eq!(verifier, original);
        verifier.verify_next(&resolver(), &items[0]).unwrap();
    }
    let mut verifier: PortableCandidateVerifier = original;
    for item in &items {
        verifier.verify_next(&resolver(), item).unwrap();
    }
    assert!(verifier.is_complete());
    assert!(verifier.verify_next(&resolver(), &items[0]).is_err());
}

#[test]
fn verifier_large_chunk_continuity_duplicate_and_truncation() {
    let mut first: PortableCandidateTransferItem = row(vec![0xab; MAX_PORTABLE_CHUNK_BYTES]);
    row_mut(&mut first).chunk_is_last = false;
    let mut last: PortableCandidateTransferItem = row(vec![1, 2, 3]);
    row_mut(&mut last).chunk_offset = u64::try_from(MAX_PORTABLE_CHUNK_BYTES).unwrap();
    let (items, manifest) = stream(vec![first, last]);
    let mut verifier: PortableCandidateVerifier =
        PortableCandidateVerifier::new(&resolver(), manifest).unwrap();
    verifier.verify_next(&resolver(), &items[0]).unwrap();
    let after_first: PortableCandidateVerifier = verifier.clone();
    for item in [&items[0], &items[2]] {
        assert!(verifier.verify_next(&resolver(), item).is_err());
        assert_eq!(verifier, after_first);
    }
    let mut gap: PortableCandidateTransferItem = items[1].clone();
    row_mut(&mut gap).chunk_offset += 1;
    assert!(verifier.verify_next(&resolver(), &gap).is_err());
    assert_eq!(verifier, after_first);
    let mut changed: PortableCandidateTransferItem = items[1].clone();
    row_mut(&mut changed).descriptor = PortableCandidateDescriptor::State { deleted: true };
    assert!(verifier.verify_next(&resolver(), &changed).is_err());
    assert_eq!(verifier, after_first);
    for item in &items[1..] {
        verifier.verify_next(&resolver(), item).unwrap();
    }
    assert!(verifier.is_complete());
}

#[test]
fn pinned_root_counts_and_stream_order_are_not_source_advice() {
    let (items, manifest) = stream(vec![row(vec![1, 2])]);
    let foreign_resolver: HashSuiteResolver = HashSuiteResolver::new(
        ChainId::new("foreign-chain").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    assert!(PortableCandidateVerifier::new(&foreign_resolver, manifest.clone()).is_err());
    let mut correct: PortableCandidateVerifier =
        PortableCandidateVerifier::new(&resolver(), manifest.clone()).unwrap();
    let before_foreign: PortableCandidateVerifier = correct.clone();
    assert!(correct.verify_next(&foreign_resolver, &items[0]).is_err());
    assert_eq!(correct, before_foreign);
    let mut wrong_root: PortableCandidateManifest = manifest.clone();
    wrong_root.final_hash_step = marked(0xff);
    let mut verifier: PortableCandidateVerifier =
        PortableCandidateVerifier::new(&resolver(), wrong_root).unwrap();
    for item in &items[..items.len() - 1] {
        verifier.verify_next(&resolver(), item).unwrap();
    }
    let before: PortableCandidateVerifier = verifier.clone();
    assert!(
        verifier
            .verify_next(&resolver(), items.last().unwrap())
            .is_err()
    );
    assert_eq!(verifier, before);
    let mut verifier: PortableCandidateVerifier =
        PortableCandidateVerifier::new(&resolver(), manifest).unwrap();
    assert!(verifier.verify_next(&resolver(), &items[1]).is_err());
    verifier.verify_next(&resolver(), &items[0]).unwrap();
    let before: PortableCandidateVerifier = verifier.clone();
    assert!(verifier.verify_next(&resolver(), &items[0]).is_err());
    assert_eq!(verifier, before);
    let mut counts: PortableCandidateTransferItem = items[1].clone();
    counts.boundary = PortableCandidateBoundary::CollectionEnd { row_count: 2 };
    assert!(verifier.verify_next(&resolver(), &counts).is_err());
    assert_eq!(verifier, before);
    for item in &items[1..] {
        verifier.verify_next(&resolver(), item).unwrap();
    }
    assert!(verifier.is_complete());
}

#[test]
fn descriptor_roundtrips_body_free_heads_and_blob_references() {
    let head: PortableCandidateDescriptor =
        PortableCandidateDescriptor::ObjectHead(PortableObjectHeadProjection::Tombstoned {
            last_object_version: DurableObjectVersion::new(9).unwrap(),
        });
    let version: PortableCandidateDescriptor = PortableCandidateDescriptor::ObjectVersion {
        digest: marked(4),
        schema_version: 2,
        chain_id: identity().drain_identity.chain_id,
        protocol_version: ProtocolVersion::new(3),
        payload: PortableCandidatePayloadKind::BlobReference(marked(5)),
    };
    for descriptor in [head, version] {
        let bytes: Vec<u8> = encode_portable_candidate_descriptor(&descriptor).unwrap();
        assert_eq!(
            decode_portable_candidate_descriptor(&bytes).unwrap(),
            descriptor
        );
        let mut unknown_version: Vec<u8> = bytes.clone();
        unknown_version[6..8].copy_from_slice(&2u16.to_le_bytes());
        assert!(decode_portable_candidate_descriptor(&unknown_version).is_err());
        let mut trailing: Vec<u8> = bytes;
        trailing.push(0);
        assert!(decode_portable_candidate_descriptor(&trailing).is_err());
    }
    let mut invalid_bool: CanonicalStruct = CanonicalStruct::new(0x6491, 1);
    invalid_bool.field_u16(1, 1).unwrap();
    invalid_bool.field_u16(2, 2).unwrap();
    assert!(decode_portable_candidate_descriptor(&invalid_bool.finish().unwrap()).is_err());
}
