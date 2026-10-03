use super::*;
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{MemoryBlobStore, MemoryDurableStateStore};

#[derive(Clone, Copy, Debug)]
enum BrokenContribution {
    ConfigurationRevision,
    PendingNonceRevision,
    DuplicateNonceMutation,
}

#[test]
fn paid_state_assembly_errors_preserve_conflict_and_runtime_stop_classification() {
    let conflict: PaidExecutionAdmissionError = StateAssemblyError::ConflictingObservation {
        key: b"observed".to_vec(),
        first: StateRevision::new(1),
        second: StateRevision::new(2),
    }
    .into();
    assert!(matches!(
        conflict,
        PaidExecutionAdmissionError::Node(NodeCoreError::StateConflict)
    ));
    for error in [
        StateAssemblyError::Runtime(RuntimeError::DuplicateStateWriteKey),
        StateAssemblyError::ConflictingMutation {
            key: b"owned".to_vec(),
        },
    ] {
        assert!(matches!(
            PaidExecutionAdmissionError::from(error),
            PaidExecutionAdmissionError::Node(NodeCoreError::Runtime(
                RuntimeError::DuplicateStateWriteKey
            ))
        ));
    }
}

#[test]
fn paid_observed_completion_refuses_conflicting_or_duplicate_contributions_before_effects() {
    // All invalid assemblies start from a real signed call and the owning
    // WASM engine's genuine admission. No supplied result authorizes effects.
    for case in [
        BrokenContribution::ConfigurationRevision,
        BrokenContribution::PendingNonceRevision,
        BrokenContribution::DuplicateNonceMutation,
    ] {
        let store: MemoryDurableStateStore = tests::memory_store();
        let fixture: tests::Fixture = tests::install(&store);
        let blobs: MemoryBlobStore = MemoryBlobStore::default();
        let engine: tests::CountingEngine = tests::CountingEngine::new();
        let resolver: HashSuiteResolver = tests::resolver();
        let context: DurableOperationContext = tests::context();
        let domain: AtomicityDomainId = tests::domain();
        let expected: PublicationContext = tests::protocol();
        let base_policy: LocalExecutionPolicy = tests::base_policy();
        let signing_key: ed25519_zebra::SigningKey = tests::key();
        let bytes: Vec<u8> = tests::lane_paid_transfer(tests::LanePaidTransfer {
            fixture: &fixture,
            policy: &fixture.policy,
            request_id: [92; 32],
            nonce: tests::FIRST_PAID_NONCE,
            source: &fixture.coin,
            sender: tests::sender(),
            signing_key: &signing_key,
        });
        let before: PortableSnapshotToken =
            store.begin_portable_snapshot(&context, domain).unwrap();
        let (authenticated, digest, request): (AuthenticatedPaidIntent, Digest32, RequestId) =
            authenticate_and_identify(&resolver, &expected, &bytes).unwrap();
        let mut admission: PaidAdmissionOutput = build_paid_admission(
            crate::serving_authority::ServingGate::Original,
            &store,
            &blobs,
            &context,
            domain,
            &resolver,
            &[],
            &base_policy,
            &fixture.policy,
            None,
            &engine,
            authenticated,
            digest,
            10,
            NonceMode::Fresh,
        )
        .unwrap();
        match case {
            BrokenContribution::ConfigurationRevision => {
                let (key, revision): (&Vec<u8>, &StateRevision) =
                    admission.reads.first_key_value().unwrap();
                admission
                    .admission_profile_reads
                    .insert(key.clone(), revision.checked_next().unwrap());
            }
            BrokenContribution::PendingNonceRevision => {
                let nonce: &PendingSenderNonceWrite = admission.nonce_write.as_ref().unwrap();
                assert!(!admission.admission_profile_reads.contains_key(&nonce.key));
                assert!(
                    admission
                        .reads
                        .insert(
                            nonce.key.clone(),
                            nonce.read_revision.checked_next().unwrap(),
                        )
                        .is_none(),
                    "genuine admission excludes the separately owned nonce row"
                );
            }
            BrokenContribution::DuplicateNonceMutation => {
                let nonce: &PendingSenderNonceWrite = admission.nonce_write.as_ref().unwrap();
                admission.state_mutations.push(
                    StateMutationEntry::new(
                        nonce.key.clone(),
                        StateMutation::Put(nonce.record.encode().unwrap()),
                    )
                    .unwrap(),
                );
            }
        }
        let refused: PaidResult<NodeOutput> = commit_direct_paid_admission(
            crate::serving_authority::ServingGate::Original,
            &store,
            &context,
            domain,
            request,
            digest,
            admission,
        );
        match case {
            BrokenContribution::ConfigurationRevision
            | BrokenContribution::PendingNonceRevision => {
                assert!(
                    matches!(
                        refused,
                        Err(PaidExecutionAdmissionError::Node(
                            NodeCoreError::StateConflict
                        ))
                    ),
                    "{case:?}"
                );
            }
            BrokenContribution::DuplicateNonceMutation => {
                assert!(
                    matches!(
                        refused,
                        Err(PaidExecutionAdmissionError::Node(NodeCoreError::Runtime(
                            RuntimeError::DuplicateStateWriteKey
                        )))
                    ),
                    "{case:?}"
                );
            }
        }
        assert_eq!(
            store.begin_portable_snapshot(&context, domain).unwrap(),
            before
        );
        assert!(
            store
                .get_request_receipt(
                    &context,
                    domain,
                    DurableRequestId::new(*request.as_bytes()).unwrap()
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(tests::next_nonce(&store), tests::FIRST_PAID_NONCE);
        assert_eq!(
            store
                .get_object_head(&context, domain, fixture.coin.id)
                .unwrap()
                .object_version()
                .unwrap()
                .get(),
            fixture.coin.version
        );
        assert_eq!(engine.calls.get(), 1);

        // A refused assembly cannot strand the normal owner. The same
        // original signed bytes make fresh progress, then exact replay
        // returns without another execution, nonce advance or recharge.
        let output: NodeOutput = handle_paid_execution(
            &store,
            &blobs,
            &context,
            domain,
            &resolver,
            &[],
            &expected,
            &base_policy,
            &fixture.policy,
            &engine,
            &bytes,
            10,
        )
        .unwrap();
        assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
        assert_eq!(tests::next_nonce(&store), tests::FIRST_PAID_NONCE + 1);
        assert_eq!(engine.calls.get(), 2);
        let after: PortableSnapshotToken = store.begin_portable_snapshot(&context, domain).unwrap();
        let replay: NodeOutput = handle_paid_execution(
            &store,
            &blobs,
            &context,
            domain,
            &resolver,
            &[],
            &expected,
            &base_policy,
            &fixture.policy,
            &engine,
            &bytes,
            10,
        )
        .unwrap();
        assert_eq!(replay, output);
        assert_eq!(engine.calls.get(), 2);
        assert_eq!(
            store.begin_portable_snapshot(&context, domain).unwrap(),
            after
        );
    }
}
