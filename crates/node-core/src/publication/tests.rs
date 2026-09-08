use super::*;
use abi::call_values::{CallAbi, ValueLayout, encode_call_abi};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::public_abi::{ConstructorDeclaration, EntrypointDeclaration, PackageAbi};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationRequest, artifact_commitment,
    publication_submission_signing_frame,
};
use protocol_types::{HashSuite, HashSuiteSchedule, ValidatorId};
use runtime::{
    DurableDomainStateStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::cell::Cell;

#[test]
fn profile_two_requires_its_own_committed_policy_and_returns_cas_closure() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let old_policy: LocalPublicationPolicy = policy(0);
    seed(&store, &old_policy);
    let typed_policy: LocalPublicationPolicy = LocalPublicationPolicy::executable(
        old_policy.context().clone(),
        local_executable_publication_semantics(&resolver(), old_policy.context()).unwrap(),
    );
    let original: PublicationSubmission = make_submission(&old_policy, 15, 0, vec![]);
    let old: &CodeArtifact = original.request().artifact();
    let call: abi::call_values::CallAbi =
        abi::call_values::decode_call_abi(old.unverified_abi()).unwrap();
    let entrypoints: usize = call.objects.entrypoints.len();
    let wrapper: abi::executable_abi::ExecutableAbi = abi::executable_abi::ExecutableAbi {
        call,
        initializer: Some("run".into()),
        transferable_constructors: vec![],
        results: vec![Vec::new(); entrypoints],
    };
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: old.context().clone(),
        origin: old.origin().clone(),
        revision: 1,
        wasm_profile: 2,
        semantics: *typed_policy.semantics(),
        wasm: old.wasm().to_vec(),
        unverified_abi: abi::executable_abi::encode_executable_abi(&wrapper).unwrap(),
        exports: old.exports().to_vec(),
        unverified_dependencies: vec![],
    })
    .unwrap();
    let submission: PublicationSubmission = signed_artifact(artifact, 0, [15; 32], &signing_key());
    assert!(matches!(
        publish(&store, &old_policy, submission.clone()),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
    assert!(matches!(
        publish(&store, &typed_policy, submission.clone()),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
    assert_eq!(nonce(&store, &old_policy), 0);
    let typed_key: Vec<u8> = publication_policy_key_for_profile(typed_policy.context(), 2).unwrap();
    assert_ne!(
        typed_key,
        publication_policy_key(typed_policy.context()).unwrap()
    );
    set_state(
        &store,
        typed_key.clone(),
        StateMutation::Put(typed_policy.encode().unwrap()),
    );
    assert_eq!(
        LocalPublicationPolicy::decode(&typed_policy.encode().unwrap()).unwrap(),
        typed_policy
    );
    publish(&store, &typed_policy, submission.clone()).unwrap();
    let origin: &PackageOrigin = submission.request().artifact().origin();
    let loaded: VerifiedDurablePublication =
        load_verified_publication(&store, &context(), domain(), &resolver(), &[], origin)
            .unwrap()
            .unwrap();
    assert_eq!(loaded.submission, submission);
    assert_eq!(
        loaded
            .interface
            .executable_abi(origin)
            .unwrap()
            .initializer
            .as_deref(),
        Some("run")
    );
    assert_eq!(loaded.reads.len(), 2);
    assert!(loaded.reads.iter().any(|read| read.key() == typed_key));
    assert!(
        loaded
            .reads
            .iter()
            .any(|read| read.key() == publication_record_key(origin).unwrap())
    );
    assert_eq!(
        query_publication(&store, &context(), domain(), &resolver(), origin).unwrap(),
        Some(submission)
    );
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("publication-tests").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn policy(epoch: u64) -> LocalPublicationPolicy {
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("publication-tests").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(epoch),
    )
    .unwrap();
    let semantics: Digest32 = local_publication_profile_semantics(&resolver(), &context).unwrap();
    LocalPublicationPolicy::new(context, semantics)
}
fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    )
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([8; 32]).unwrap()
}
fn signing_key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn make_submission(
    policy: &LocalPublicationPolicy,
    seed: u8,
    nonce: u64,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> PublicationSubmission {
    let key: SigningKey = signing_key();
    let publisher: [u8; 32] = VerificationKey::from(&key).into();
    let origin: PackageOrigin =
        PackageOrigin::unverified(policy.context.chain_id().clone(), publisher, [seed; 32])
            .unwrap();
    let abi: CallAbi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: vec![],
            entrypoints: vec![EntrypointDeclaration {
                name: "run".into(),
                type_parameters: vec![],
                objects: vec![],
            }],
        },
        arguments: vec![ValueLayout::Tuple(vec![])],
        bodies: vec![],
    };
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: policy.context.clone(),
        origin,
        revision: 1,
        wasm_profile: 1,
        semantics: policy.semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: encode_call_abi(&abi).unwrap(),
        exports: vec!["run".into()],
        unverified_dependencies: dependencies,
    })
    .unwrap();
    signed_artifact(artifact, nonce, [seed; 32], &key)
}
fn signed_artifact(
    artifact: CodeArtifact,
    nonce: u64,
    request_id: [u8; 32],
    key: &SigningKey,
) -> PublicationSubmission {
    let frame: Vec<u8> = publication_submission_signing_frame(
        &resolver(),
        artifact.context(),
        &artifact,
        nonce,
        request_id,
    )
    .unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), artifact.context(), &artifact).unwrap();
    PublicationSubmission::new(
        request_id,
        PublicationRequest::new(artifact, nonce, digest, key.sign(&frame).into()),
    )
    .unwrap()
}
fn reference(submission: &PublicationSubmission) -> UnverifiedDependencyRef {
    let artifact: &CodeArtifact = submission.request().artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *submission.request().artifact_digest(),
    )
    .unwrap()
}
fn set_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    key: Vec<u8>,
    mutation: StateMutation,
) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}
fn seed<S: StructuredDurableDomainStateStore>(store: &S, policy: &LocalPublicationPolicy) {
    set_state(
        store,
        publication_policy_key(policy.context()).unwrap(),
        StateMutation::Put(policy.encode().unwrap()),
    );
}
fn nonce<S: StructuredDurableDomainStateStore>(store: &S, policy: &LocalPublicationPolicy) -> u64 {
    query::query_sender_next_nonce(
        store,
        &context(),
        domain(),
        policy.context.chain_id().clone(),
        policy.context.protocol_version(),
        policy.context.epoch(),
        VerificationKey::from(&signing_key()).into(),
    )
    .unwrap()
}
fn publish<S: StructuredDurableDomainStateStore>(
    store: &S,
    policy: &LocalPublicationPolicy,
    submission: PublicationSubmission,
) -> Result<NodeOutput, PublicationAdmissionError> {
    handle_local_publication(store, &context(), domain(), &resolver(), policy, submission)
}

#[test]
fn signed_request_identity_domain_and_canonical_shape() {
    let policy: LocalPublicationPolicy = policy(0);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let bytes: Vec<u8> = encode_publication_submission(&submission).unwrap();
    assert_eq!(
        resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, &bytes)
            .unwrap()
            .bytes(),
        [
            15, 9, 95, 120, 191, 103, 162, 254, 36, 112, 22, 85, 158, 170, 13, 126, 191, 27, 133,
            151, 58, 51, 123, 29, 1, 237, 228, 106, 167, 214, 191, 195
        ]
    );
    assert_eq!(
        submission.request().signature(),
        &[
            47, 166, 193, 181, 225, 216, 44, 29, 248, 202, 138, 3, 26, 239, 166, 106, 189, 2, 62,
            76, 84, 7, 248, 185, 160, 119, 49, 122, 153, 131, 209, 83, 10, 182, 76, 96, 178, 70,
            117, 126, 49, 199, 45, 99, 191, 81, 173, 176, 99, 41, 117, 165, 30, 217, 107, 165, 160,
            84, 77, 130, 31, 215, 104, 4
        ]
    );
    assert_eq!(decode_publication_submission(&bytes).unwrap(), submission);
    assert!(
        authenticate_publication_submission(
            &resolver(),
            policy.context(),
            policy.semantics(),
            submission.clone()
        )
        .is_ok()
    );
    assert!(
        execution::publication::authenticate_publication(
            &resolver(),
            policy.context(),
            policy.semantics(),
            submission.request().clone()
        )
        .is_err()
    );
    let changed: PublicationSubmission =
        PublicationSubmission::new([11; 32], submission.request().clone()).unwrap();
    assert!(
        authenticate_publication_submission(
            &resolver(),
            policy.context(),
            policy.semantics(),
            changed
        )
        .is_err()
    );
    let mut trailing: Vec<u8> = bytes.clone();
    trailing.push(0);
    assert!(decode_publication_submission(&trailing).is_err());
    let mut unknown: CanonicalStruct = CanonicalStruct::new(0x6308, 1);
    unknown
        .field_bytes(1, submission.request_id().to_vec())
        .unwrap();
    unknown
        .field_bytes(
            2,
            execution::publication::encode_publication_request(submission.request()).unwrap(),
        )
        .unwrap();
    unknown.field_u16(3, 1).unwrap();
    assert!(decode_publication_submission(&unknown.finish().unwrap()).is_err());
    assert!(PublicationSubmission::new([0; 32], submission.request().clone()).is_err());
}

#[test]
fn independent_node_publication_frame_vectors() {
    // Independently reconstructed by scripts/publication-submission-vectors.mjs.
    // NodeEvent framing is used only to compare complete byte strings here.
    let policy: LocalPublicationPolicy = policy(0);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let signing: Vec<u8> = publication_submission_signing_frame(
        &resolver(),
        policy.context(),
        submission.request().artifact(),
        0,
        *submission.request_id(),
    )
    .unwrap();
    let signing_payload: Vec<u8> = decode_canonical_frame(&signing)
        .unwrap()
        .required_field(6)
        .unwrap()
        .to_vec();
    let vectors: Vec<(Vec<u8>, usize, &str)> = vec![
        (
            encode_local_publication_profile().unwrap(),
            89,
            "632c3f95d19be4e74bb19842300bb4e8928a7241dfbf63c6dac061a2b94258ac",
        ),
        (
            policy.encode().unwrap(),
            167,
            "0c71581f72f429f4e160a21616eee076137481cd9012f72ecca7028b01b99187",
        ),
        (
            signing_payload,
            332,
            "b1b7bc73834c9b31afaf081dc65ab7f036886cdd8112acddf3ed333319dd5699",
        ),
        (
            signing,
            432,
            "2fbc5353034ab85b88726ed2c9f238a909fce16c8504884ae3f4a5bcdfc62c75",
        ),
        (
            encode_publication_submission(&submission).unwrap(),
            981,
            "0f095f78bf67a2fe247016559eaa0d7ebf1b85973a337b1d01ede46aa7d6bfc3",
        ),
    ];
    for (bytes, length, expected) in vectors {
        assert_eq!(bytes.len(), length);
        let digest: Digest32 = resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, &bytes)
            .unwrap();
        let actual: String = digest
            .bytes()
            .iter()
            .map(|byte: &u8| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, expected);
    }
    assert_eq!(
        LocalPublicationPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
}

#[test]
fn sqlite_restart_replay_retains_exact_code_dependencies_receipt_and_nonce() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path: std::path::PathBuf = std::env::temp_dir().join(format!(
        "publication-core-{}-{unique}.sqlite",
        std::process::id()
    ));
    let namespace: SqliteNamespace = SqliteNamespace::new(
        resolver().chain_id().clone(),
        ValidatorId::new([4; 32]),
        domain(),
    );
    let policy: LocalPublicationPolicy = policy(0);
    let first: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let second: PublicationSubmission = make_submission(&policy, 11, 1, vec![reference(&first)]);
    let reused: PublicationSubmission = signed_artifact(
        second.request().artifact().clone(),
        2,
        *first.request_id(),
        &signing_key(),
    );
    let first_output: NodeOutput;
    let second_output: NodeOutput;
    let snapshot: PublicationSnapshot;
    let generation_two: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        seed(&store, &policy);
        first_output = publish(&store, &policy, first.clone()).unwrap();
        second_output = publish(&store, &policy, second.clone()).unwrap();
        assert!(first_output.outbound_messages().is_empty());
        assert!(second_output.outbound_messages().is_empty());
        snapshot = publication_snapshot(&store, &context(), &policy, &first, &second);
        assert_eq!(snapshot.next_nonce, 2);
        assert_eq!(
            snapshot.state[0].value(),
            Some(encode_publication_submission(&first).unwrap().as_slice())
        );
        assert_eq!(
            snapshot.state[1].value(),
            Some(encode_publication_submission(&second).unwrap().as_slice())
        );
        assert_eq!(
            publish(&store, &policy, first.clone()).unwrap(),
            first_output
        );
        assert_eq!(
            publish(&store, &policy, second.clone()).unwrap(),
            second_output
        );
        assert_eq!(
            publication_snapshot(&store, &context(), &policy, &first, &second),
            snapshot
        );
        assert!(matches!(
            publish(&store, &policy, reused.clone()),
            Err(PublicationAdmissionError::Node(
                NodeCoreError::RequestIdReuse
            ))
        ));
        assert_eq!(
            publication_snapshot(&store, &context(), &policy, &first, &second),
            snapshot
        );
        assert_eq!(
            store
                .advance_writer_fence(WriterFenceGeneration::new(1).unwrap(), generation_two)
                .unwrap(),
            generation_two
        );
    }
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace, WriterFenceGeneration::new(1).unwrap())
                .unwrap();
        assert_eq!(store.writer_fence().unwrap(), generation_two);
        let fresh: DurableOperationContext = DurableOperationContext::new(
            generation_two,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([4; 16]).unwrap(),
        );
        let first_key: Vec<u8> =
            publication_record_key(first.request().artifact().origin()).unwrap();
        // Both runtime-trait reads and writes reject the old process authority.
        assert_eq!(
            store.get_versioned_durable(&context(), domain(), &first_key),
            Err(DurableReadError::WriterFenced {
                active_generation: generation_two
            })
        );
        let stale_write: AtomicStateTransaction = AtomicStateTransaction::new(
            domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(first_key.clone(), snapshot.state[0].revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    first_key,
                    StateMutation::Put(snapshot.state[0].value().unwrap().to_vec()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context(), stale_write),
            DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
                active_generation: generation_two
            })
        );
        assert!(publish(&store, &policy, second.clone()).is_err());
        assert_eq!(
            publication_snapshot(&store, &fresh, &policy, &first, &second),
            snapshot
        );
        assert_eq!(
            query_publication(
                &store,
                &fresh,
                domain(),
                &resolver(),
                second.request().artifact().origin()
            )
            .unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            handle_local_publication(
                &store,
                &fresh,
                domain(),
                &resolver(),
                &policy,
                first.clone()
            )
            .unwrap(),
            first_output
        );
        assert_eq!(
            handle_local_publication(
                &store,
                &fresh,
                domain(),
                &resolver(),
                &policy,
                second.clone()
            )
            .unwrap(),
            second_output
        );
        assert_eq!(
            publication_snapshot(&store, &fresh, &policy, &first, &second),
            snapshot
        );
        assert!(matches!(
            handle_local_publication(&store, &fresh, domain(), &resolver(), &policy, reused),
            Err(PublicationAdmissionError::Node(
                NodeCoreError::RequestIdReuse
            ))
        ));
        assert_eq!(
            publication_snapshot(&store, &fresh, &policy, &first, &second),
            snapshot
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct PublicationSnapshot {
    // Exact root/dependency bytes and revisions, plus canonical nonce record.
    state: Vec<VersionedStateValue>,
    receipts: Vec<DurableRequestReceipt>,
    next_nonce: u64,
}

fn publication_snapshot<S: StructuredDurableDomainStateStore>(
    store: &S,
    operation: &DurableOperationContext,
    policy: &LocalPublicationPolicy,
    first: &PublicationSubmission,
    second: &PublicationSubmission,
) -> PublicationSnapshot {
    let mut state: Vec<VersionedStateValue> = Vec::new();
    let mut receipts: Vec<DurableRequestReceipt> = Vec::new();
    for submission in [first, second] {
        let key: Vec<u8> =
            publication_record_key(submission.request().artifact().origin()).unwrap();
        state.push(
            store
                .get_versioned_durable(operation, domain(), &key)
                .unwrap(),
        );
        let receipt: DurableRequestReceipt = store
            .get_request_receipt(
                operation,
                domain(),
                DurableRequestId::new(*submission.request_id()).unwrap(),
            )
            .unwrap()
            .unwrap();
        // Independently query/re-encode both receipts, beyond byte preservation.
        let query: query::ReceiptQueryResult = query::query_request_receipt(
            store,
            operation,
            domain(),
            RequestId::new(*submission.request_id()).unwrap(),
        )
        .unwrap();
        let query::ReceiptQueryResult::Present { record, .. } = query else {
            panic!("publication receipt missing");
        };
        assert_eq!(record.encode().unwrap(), receipt.canonical_bytes());
        receipts.push(receipt);
    }
    let sender: [u8; 32] = VerificationKey::from(&signing_key()).into();
    let layout: PersistenceLayout = PersistenceLayout::new(
        policy.context.chain_id().clone(),
        policy.context.protocol_version(),
    );
    state.push(
        store
            .get_versioned_durable(
                operation,
                domain(),
                &layout.sender_nonce_key(sender, policy.context.epoch()),
            )
            .unwrap(),
    );
    let next_nonce: u64 = query::query_sender_next_nonce(
        store,
        operation,
        domain(),
        policy.context.chain_id().clone(),
        policy.context.protocol_version(),
        policy.context.epoch(),
        sender,
    )
    .unwrap();
    PublicationSnapshot {
        state,
        receipts,
        next_nonce,
    }
}

#[test]
fn failed_admission_leaves_no_publication_receipt_or_nonce() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let policy: LocalPublicationPolicy = policy(0);
    let missing: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let submission: PublicationSubmission =
        make_submission(&policy, 11, 0, vec![reference(&missing)]);
    assert!(matches!(
        publish(&store, &policy, submission.clone()),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
    seed(&store, &policy);
    assert!(matches!(
        publish(&store, &policy, submission.clone()),
        Err(PublicationAdmissionError::MissingDependency)
    ));
    assert_eq!(nonce(&store, &policy), 0);
    assert!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            submission.request().artifact().origin()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(*submission.request_id()).unwrap()
            )
            .unwrap()
            .is_none()
    );
    set_state(
        &store,
        publication_record_key(missing.request().artifact().origin()).unwrap(),
        StateMutation::Delete,
    );
    assert!(matches!(
        publish(&store, &policy, missing),
        Err(PublicationAdmissionError::OriginExists)
    ));
}

#[test]
fn shared_loader_budget_rejects_next_union_node_before_record_io() {
    let store: ObservedStore = ObservedStore::new();
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let mut submissions: Vec<PublicationSubmission> = Vec::new();
    // Each root is individually within the old per-closure bound. The last
    // two-node closure would overflow only their shared invocation union.
    for index in 0..33_u8 {
        let submission: PublicationSubmission =
            make_submission(&policy, index + 10, u64::from(index), vec![]);
        publish(&store, &policy, submission.clone()).unwrap();
        submissions.push(submission);
    }
    let root: PublicationSubmission =
        make_submission(&policy, 44, 33, vec![reference(&submissions[32])]);
    publish(&store, &policy, root.clone()).unwrap();
    store.state_reads.borrow_mut().clear();
    let mut budget: PublicationLoadBudget = PublicationLoadBudget::default();
    let mut first: Option<VerifiedDurablePublication> = None;
    for submission in &submissions[..32] {
        let loaded: VerifiedDurablePublication = load_verified_publication_with_budget(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            submission.request().artifact().origin(),
            &mut budget,
        )
        .unwrap()
        .unwrap();
        if first.is_none() {
            first = Some(loaded);
        }
    }
    let reads_before_cache: usize = store.state_reads.borrow().len();
    let cached: VerifiedDurablePublication = load_verified_publication_with_budget(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        submissions[0].request().artifact().origin(),
        &mut budget,
    )
    .unwrap()
    .unwrap();
    assert_eq!(store.state_reads.borrow().len(), reads_before_cache);
    assert!(std::ptr::eq(
        first.as_ref().unwrap().interface.candidate().request(),
        cached.interface.candidate().request()
    ));
    assert_eq!(cached.reads.len(), 33); // 32 immutable records and their one policy.
    assert!(matches!(
        load_verified_publication_with_budget(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            root.request().artifact().origin(),
            &mut budget
        ),
        Err(PublicationAdmissionError::Limit)
    ));
    let unbudgeted: Vec<u8> =
        publication_record_key(submissions[32].request().artifact().origin()).unwrap();
    let root_key: Vec<u8> = publication_record_key(root.request().artifact().origin()).unwrap();
    assert!(
        !store
            .state_reads
            .borrow()
            .iter()
            .any(|key| key == &unbudgeted)
    );
    assert_eq!(
        store
            .state_reads
            .borrow()
            .iter()
            .filter(|key| *key == &root_key)
            .count(),
        1
    );
    for submission in &submissions[..32] {
        let key: Vec<u8> =
            publication_record_key(submission.request().artifact().origin()).unwrap();
        assert_eq!(
            store
                .state_reads
                .borrow()
                .iter()
                .filter(|read| *read == &key)
                .count(),
            1
        );
    }
    assert_eq!(nonce(&store, &policy), 34);
}

struct ObservedStore {
    inner: MemoryDurableStateStore,
    forbid_application_reads: Cell<bool>,
    reject_commit: Cell<bool>,
    indeterminate: Cell<bool>,
    race_policy: Cell<bool>,
    state_reads: std::cell::RefCell<Vec<Vec<u8>>>,
}
impl ObservedStore {
    fn new() -> Self {
        Self {
            inner: MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap()),
            forbid_application_reads: Cell::new(false),
            reject_commit: Cell::new(false),
            indeterminate: Cell::new(false),
            race_policy: Cell::new(false),
            state_reads: std::cell::RefCell::new(Vec::new()),
        }
    }
}
impl runtime::DurableDomainStateStore for ObservedStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.state_reads.borrow_mut().push(key.to_vec());
        assert!(
            !self.forbid_application_reads.get(),
            "replay must not read policy, dependencies or nonce"
        );
        self.inner.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for ObservedStore {
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
        if self.reject_commit.get() {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted);
        }
        if self.race_policy.get() {
            let policy_key: Vec<u8> = transaction
                .state()
                .unwrap()
                .reads()
                .iter()
                .find(|read| read.key() == publication_policy_key(policy(0).context()).unwrap())
                .unwrap()
                .key()
                .to_vec();
            let value: Vec<u8> = self
                .inner
                .get_versioned_durable(context, domain(), &policy_key)
                .unwrap()
                .value()
                .unwrap()
                .to_vec();
            set_state(&self.inner, policy_key, StateMutation::Put(value));
        }
        let outcome: DurableCommitOutcome = self.inner.commit_invocation(context, transaction);
        if self.indeterminate.get() {
            return DurableCommitOutcome::Indeterminate(
                runtime::IndeterminateCommitReason::ConnectionLost,
            );
        }
        outcome
    }
}

#[test]
fn replay_precedes_every_state_read_and_indeterminate_reconciles() {
    let store: ObservedStore = ObservedStore::new();
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    store.indeterminate.set(true);
    assert!(matches!(
        publish(&store, &policy, submission.clone()),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::DurableCommitIndeterminate(_)
        ))
    ));
    store.forbid_application_reads.set(true);
    assert!(
        publish(&store, &policy, submission)
            .unwrap()
            .outbound_messages()
            .is_empty()
    );
}

#[test]
fn commit_conflict_exposes_no_partial_state() {
    let store: ObservedStore = ObservedStore::new();
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    store.reject_commit.set(true);
    assert!(matches!(
        publish(&store, &policy, submission.clone()),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));
    assert_eq!(nonce(&store, &policy), 0);
    assert!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            submission.request().artifact().origin()
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn policy_revision_race_rolls_back_publication_nonce_and_receipt() {
    let store: ObservedStore = ObservedStore::new();
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    store.race_policy.set(true);
    assert!(matches!(
        publish(&store, &policy, submission.clone()),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));
    assert_eq!(nonce(&store, &policy), 0);
    assert!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            submission.request().artifact().origin()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new(*submission.request_id()).unwrap()
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn shared_nonce_and_origin_collision_are_enforced() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let first: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    publish(&store, &policy, first.clone()).unwrap();
    assert!(matches!(
        publish(&store, &policy, make_submission(&policy, 11, 0, vec![])),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::SenderNonceMismatch { .. }
        ))
    ));
    let collision: PublicationSubmission = signed_artifact(
        first.request().artifact().clone(),
        1,
        [12; 32],
        &signing_key(),
    );
    assert!(matches!(
        publish(&store, &policy, collision),
        Err(PublicationAdmissionError::OriginExists)
    ));
    // Reserve through the exact helper used by authenticated transactions.
    let layout: PersistenceLayout = PersistenceLayout::new(
        policy.context.chain_id().clone(),
        policy.context.protocol_version(),
    );
    let sender: [u8; 32] = VerificationKey::from(&signing_key()).into();
    let transaction_nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce(
        &store,
        &context(),
        domain(),
        &layout,
        SenderNonceReservation {
            sender,
            epoch: policy.context.epoch(),
            nonce: 1,
        },
    )
    .unwrap();
    set_state(
        &store,
        transaction_nonce.key,
        StateMutation::Put(transaction_nonce.record.encode().unwrap()),
    );
    assert!(matches!(
        publish(&store, &policy, make_submission(&policy, 13, 1, vec![])),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::SenderNonceMismatch { .. }
        ))
    ));
    publish(&store, &policy, make_submission(&policy, 13, 2, vec![])).unwrap();
    assert_eq!(nonce(&store, &policy), 3);
}

#[test]
fn historical_epoch_policy_and_exact_dependency_digest() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let old: LocalPublicationPolicy = policy(0);
    let current: LocalPublicationPolicy = policy(7);
    seed(&store, &old);
    seed(&store, &current);
    let dependency: PublicationSubmission = make_submission(&old, 10, 0, vec![]);
    publish(&store, &old, dependency.clone()).unwrap();
    let publication: PublicationSubmission =
        make_submission(&current, 11, 0, vec![reference(&dependency)]);
    publish(&store, &current, publication.clone()).unwrap();
    assert_eq!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            publication.request().artifact().origin()
        )
        .unwrap(),
        Some(publication)
    );
    let invalid: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        dependency.request().artifact().origin().clone(),
        1,
        old.context.clone(),
        Digest32::new(HashAlgorithmId::Sha2_256, [99; 32]),
    )
    .unwrap();
    assert!(matches!(
        publish(
            &store,
            &current,
            make_submission(&current, 12, 1, vec![invalid])
        ),
        Err(PublicationAdmissionError::CorruptRecord)
    ));
    assert_eq!(nonce(&store, &current), 1);
}

#[test]
fn generic_machines_cannot_access_publication_namespace() {
    let plan: NodeStateAccessPlan = NodeStateAccessPlan::new(vec![
        NodeStateAccess::new(
            PUBLICATION_STATE_PREFIX.to_vec(),
            NodeStateAccessMode::ReadWrite,
        )
        .unwrap(),
    ])
    .unwrap();
    let layout: PersistenceLayout =
        PersistenceLayout::new(resolver().chain_id().clone(), ProtocolVersion::new(99));
    assert!(matches!(
        validate_sender_nonce_namespace(&plan, &layout),
        Err(NodeCoreError::ReservedStateAccess(_))
    ));
    let future_plan: NodeStateAccessPlan = NodeStateAccessPlan::new(vec![
        NodeStateAccess::new(
            b"se/publications/v2/records/future".to_vec(),
            NodeStateAccessMode::ReadWrite,
        )
        .unwrap(),
    ])
    .unwrap();
    assert!(matches!(
        validate_sender_nonce_namespace(&future_plan, &layout),
        Err(NodeCoreError::ReservedStateAccess(_))
    ));
    let policy: LocalPublicationPolicy = policy(0);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let policy_key: Vec<u8> = publication_policy_key(policy.context()).unwrap();
    let record_key: Vec<u8> =
        publication_record_key(submission.request().artifact().origin()).unwrap();
    assert!(policy_key.starts_with(PUBLICATION_STATE_PREFIX));
    assert!(record_key.starts_with(PUBLICATION_STATE_PREFIX));
    assert!(policy_key.starts_with(b"se/publications/v1/policies/"));
    assert!(record_key.starts_with(b"se/publications/v1/records/"));
}

#[test]
fn transitive_dependencies_are_admitted_and_reverified_from_durable_records() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let a: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let b: PublicationSubmission = make_submission(&policy, 11, 1, vec![reference(&a)]);
    let c: PublicationSubmission = make_submission(&policy, 12, 2, vec![reference(&b)]);
    publish(&store, &policy, a.clone()).unwrap();
    publish(&store, &policy, b.clone()).unwrap();
    publish(&store, &policy, c.clone()).unwrap();
    assert_eq!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            c.request().artifact().origin()
        )
        .unwrap(),
        Some(c.clone())
    );
    assert_eq!(nonce(&store, &policy), 3);
    // C names only B, so this failure proves that readback traverses B's edge to A.
    set_state(
        &store,
        publication_record_key(a.request().artifact().origin()).unwrap(),
        StateMutation::Delete,
    );
    assert!(matches!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            c.request().artifact().origin()
        ),
        Err(PublicationAdmissionError::MissingDependency)
    ));
    let d: PublicationSubmission = make_submission(&policy, 13, 3, vec![reference(&b)]);
    assert!(matches!(
        publish(&store, &policy, d),
        Err(PublicationAdmissionError::MissingDependency)
    ));
    assert_eq!(nonce(&store, &policy), 3);
}

#[test]
fn upper_revision_is_rejected_by_builder_and_ingress_decoder_before_admission() {
    let policy: LocalPublicationPolicy = policy(0);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let artifact: &CodeArtifact = submission.request().artifact();
    // This is the same checked CodeArtifact builder used by software clients.
    let upper: Result<CodeArtifact, PublicationError> = CodeArtifact::new(ArtifactParts {
        context: artifact.context().clone(),
        origin: artifact.origin().clone(),
        revision: 2,
        wasm_profile: artifact.wasm_profile(),
        semantics: *artifact.semantics(),
        wasm: artifact.wasm().to_vec(),
        unverified_abi: artifact.unverified_abi().to_vec(),
        exports: artifact.exports().to_vec(),
        unverified_dependencies: vec![],
    });
    assert!(matches!(upper, Err(PublicationError::InvalidRevision(2))));
    // An external encoder cannot bypass the same rule with canonical wire bytes.
    let original: Vec<u8> = execution::publication::encode_code_artifact(artifact).unwrap();
    let original_frame: CanonicalFrame<'_> = decode_canonical_frame(&original).unwrap();
    let mut changed: CanonicalStruct = CanonicalStruct::new(0x6303, 1);
    for field in 1_u16..=9 {
        if field == 3 {
            changed.field_u64(field, 2).unwrap();
        } else {
            changed
                .field_bytes(field, original_frame.required_field(field).unwrap())
                .unwrap();
        }
    }
    let mut request: CanonicalStruct = CanonicalStruct::new(0x6306, 1);
    request.field_bytes(1, changed.finish().unwrap()).unwrap();
    request.field_u64(2, 0).unwrap();
    request
        .field_bytes(
            3,
            encode_digest32(submission.request().artifact_digest()).unwrap(),
        )
        .unwrap();
    request
        .field_bytes(4, submission.request().signature().to_vec())
        .unwrap();
    let mut envelope: CanonicalStruct = CanonicalStruct::new(0x6308, 1);
    envelope
        .field_bytes(1, submission.request_id().to_vec())
        .unwrap();
    envelope.field_bytes(2, request.finish().unwrap()).unwrap();
    assert!(matches!(
        decode_publication_submission(&envelope.finish().unwrap()),
        Err(PublicationError::InvalidRevision(2))
    ));
}

#[test]
fn original_protocol_query_requires_explicit_trusted_history() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let submission: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    publish(&store, &policy, submission.clone()).unwrap();
    let current: HashSuiteResolver = HashSuiteResolver::new(
        resolver().chain_id().clone(),
        ProtocolVersion::new(4),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let origin: &PackageOrigin = submission.request().artifact().origin();
    assert!(matches!(
        query_publication(&store, &context(), domain(), &current, origin),
        Err(PublicationAdmissionError::HistoricalContextUnavailable)
    ));
    assert_eq!(
        query_publication_with_history(
            &store,
            &context(),
            domain(),
            &current,
            &[resolver()],
            origin
        )
        .unwrap(),
        Some(submission)
    );
}

#[test]
fn copied_abi_is_rejected_and_unreceipted_record_is_not_a_publication() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let first: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    let second: PublicationSubmission = make_submission(&policy, 11, 0, vec![]);
    let artifact: &CodeArtifact = second.request().artifact();
    let copied: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: artifact.context().clone(),
        origin: artifact.origin().clone(),
        revision: 1,
        wasm_profile: 1,
        semantics: *artifact.semantics(),
        wasm: artifact.wasm().to_vec(),
        unverified_abi: first.request().artifact().unverified_abi().to_vec(),
        exports: artifact.exports().to_vec(),
        unverified_dependencies: vec![],
    })
    .unwrap();
    let submission: PublicationSubmission = signed_artifact(copied, 0, [12; 32], &signing_key());
    assert!(matches!(
        publish(&store, &policy, submission),
        Err(PublicationAdmissionError::Interface(_))
    ));
    assert_eq!(nonce(&store, &policy), 0);
    set_state(
        &store,
        publication_record_key(first.request().artifact().origin()).unwrap(),
        StateMutation::Put(encode_publication_submission(&first).unwrap()),
    );
    assert!(matches!(
        query_publication(
            &store,
            &context(),
            domain(),
            &resolver(),
            first.request().artifact().origin()
        ),
        Err(PublicationAdmissionError::CorruptRecord)
    ));
}

#[test]
fn request_id_reuse_is_rejected_before_state_reads() {
    let store: ObservedStore = ObservedStore::new();
    let policy: LocalPublicationPolicy = policy(0);
    seed(&store, &policy);
    let first: PublicationSubmission = make_submission(&policy, 10, 0, vec![]);
    publish(&store, &policy, first.clone()).unwrap();
    let second: PublicationSubmission = make_submission(&policy, 11, 1, vec![]);
    let reused: PublicationSubmission = signed_artifact(
        second.request().artifact().clone(),
        1,
        *first.request_id(),
        &signing_key(),
    );
    store.forbid_application_reads.set(true);
    assert!(matches!(
        publish(&store, &policy, reused),
        Err(PublicationAdmissionError::Node(
            NodeCoreError::RequestIdReuse
        ))
    ));
}

#[test]
fn profile_four_policy_codec_roundtrips_and_diverges_from_earlier_profiles() {
    let context: PublicationContext = policy(0).context().clone();
    let semantics: Digest32 =
        local_object_result_publication_semantics(&resolver(), &context).unwrap();
    let object_results: LocalPublicationPolicy =
        LocalPublicationPolicy::object_results(context.clone(), semantics);
    assert_eq!(object_results.profile(), 4);
    let bytes: Vec<u8> = object_results.encode().unwrap();
    assert_eq!(
        LocalPublicationPolicy::decode(&bytes).unwrap(),
        object_results
    );

    let general_semantics: Digest32 =
        local_general_publication_semantics(&resolver(), &context).unwrap();
    let general: LocalPublicationPolicy =
        LocalPublicationPolicy::general(context.clone(), general_semantics);
    assert_ne!(general.encode().unwrap(), bytes);
    assert_ne!(*general.semantics(), *object_results.semantics());
}

#[test]
fn profile_four_policy_rejects_unknown_wire_version() {
    let context: PublicationContext = policy(0).context().clone();
    let semantics: Digest32 =
        local_object_result_publication_semantics(&resolver(), &context).unwrap();
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x630A, 5);
    frame
        .field_bytes(1, encode_publication_context(&context).unwrap())
        .unwrap();
    frame
        .field_bytes(2, encode_digest32(&semantics).unwrap())
        .unwrap();
    frame.field_u16(3, 1).unwrap();
    frame.field_u32(4, MAX_INTERFACE_NODES as u32).unwrap();
    frame
        .field_u64(5, MAX_PUBLICATION_CLOSURE_BYTES as u64)
        .unwrap();
    frame.field_u32(6, 5).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(matches!(
        LocalPublicationPolicy::decode(&bytes),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
}

#[test]
fn profile_four_policy_key_is_distinct_from_every_historical_profile_and_context_bound() {
    let context: PublicationContext = policy(0).context().clone();
    let other_context: PublicationContext = policy(1).context().clone();
    let keys: Vec<Vec<u8>> = (1..=4)
        .map(|profile| publication_policy_key_for_profile(&context, profile).unwrap())
        .collect();
    for (index, key) in keys.iter().enumerate() {
        for (other_index, other_key) in keys.iter().enumerate() {
            if index != other_index {
                assert_ne!(key, other_key);
            }
        }
    }
    assert_ne!(
        publication_policy_key_for_profile(&context, 4).unwrap(),
        publication_policy_key_for_profile(&other_context, 4).unwrap()
    );
    assert!(matches!(
        publication_policy_key_for_profile(&context, 5),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
}

fn general_submission(context: &PublicationContext, seed: u8, nonce: u64) -> PublicationSubmission {
    let key: SigningKey = signing_key();
    let publisher: [u8; 32] = VerificationKey::from(&key).into();
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), publisher, [seed; 32]).unwrap();
    let meta: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![],
                entrypoints: vec![EntrypointDeclaration {
                    name: "run".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![],
        },
        initializer: Some("run".into()),
        transferable_constructors: vec![],
        results: vec![Vec::new()],
    };
    let semantics: Digest32 = local_general_publication_semantics(&resolver(), context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin,
        revision: 1,
        wasm_profile: 3,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: encode_executable_abi(&meta).unwrap(),
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    signed_artifact(artifact, nonce, [seed; 32], &key)
}

fn object_results_submission(
    context: &PublicationContext,
    seed: u8,
    nonce: u64,
) -> PublicationSubmission {
    let key: SigningKey = signing_key();
    let publisher: [u8; 32] = VerificationKey::from(&key).into();
    let origin: PackageOrigin =
        PackageOrigin::unverified(context.chain_id().clone(), publisher, [seed; 32]).unwrap();
    let meta: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![EntrypointDeclaration {
                    name: "init".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("init".into()),
        transferable_constructors: vec![1],
        results: vec![Vec::new()],
    };
    let semantics: Digest32 =
        local_object_result_publication_semantics(&resolver(), context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin,
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"init\")))")
            .unwrap(),
        unverified_abi: encode_executable_abi(&meta).unwrap(),
        exports: vec!["init".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    signed_artifact(artifact, nonce, [seed; 32], &key)
}

#[test]
fn profile_four_policy_bytes_at_profile_three_key_are_rejected_by_legacy_path() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context: PublicationContext = policy(0).context().clone();
    let general_semantics: Digest32 =
        local_general_publication_semantics(&resolver(), &context).unwrap();
    let general: LocalPublicationPolicy =
        LocalPublicationPolicy::general(context.clone(), general_semantics);
    let object_semantics: Digest32 =
        local_object_result_publication_semantics(&resolver(), &context).unwrap();
    let object_results: LocalPublicationPolicy =
        LocalPublicationPolicy::object_results(context.clone(), object_semantics);
    set_state(
        &store,
        publication_policy_key_for_profile(&context, 3).unwrap(),
        StateMutation::Put(object_results.encode().unwrap()),
    );
    let submission: PublicationSubmission = general_submission(&context, 51, 0);
    assert!(matches!(
        publish(&store, &general, submission),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
}

#[test]
fn profile_four_artifact_is_rejected_by_profile_three_policy() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let context: PublicationContext = policy(0).context().clone();
    let general_semantics: Digest32 =
        local_general_publication_semantics(&resolver(), &context).unwrap();
    let general: LocalPublicationPolicy =
        LocalPublicationPolicy::general(context.clone(), general_semantics);
    set_state(
        &store,
        publication_policy_key_for_profile(&context, 3).unwrap(),
        StateMutation::Put(general.encode().unwrap()),
    );
    let submission: PublicationSubmission = object_results_submission(&context, 52, 0);
    assert!(matches!(
        publish(&store, &general, submission),
        Err(PublicationAdmissionError::PolicyMismatch)
    ));
}
