//! Real typed WASM, exact dependency calls and fenced file-backed persistence.
#[path = "../../execution/tests/common/inventory.rs"]
mod inventory;

use abi::AccessEntry;
use abi::call_values::{CallValue, decode_call_value};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect};
use hashing::HashSuiteResolver;
use node_core::local_execution::{
    LocalExecutionAdmissionError, handle_local_execution, query_local_instance,
};
use node_core::local_instance_state::{
    execution_policy_key, instance_record_key, object_authority_key,
};
use node_core::publication::{
    LocalPublicationPolicy, handle_local_publication, publication_policy_key_for_profile,
    publication_record_key,
};
use node_core::{NodeCoreError, NodeOutput, NodeResponseStatus, query_sender_next_nonce};
use objects::{AccessMode, Address, Object, ObjectId, ObjectRef, Owner};
use protocol_types::{
    ChainId, Digest32, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion,
    ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableCommitOutcome, DurableDomainStateStore, DurableObjectHead, DurableObjectPayload,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableRequestId,
    DurableRequestReceipt, MemoryBlobStore, PersistenceLayout, StateMutation, StateMutationEntry,
    StateReadAssertion, StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
    VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}
fn address(seed: u8) -> [u8; 32] {
    VerificationKey::from(&key(seed)).into()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("inventory-durable-e2e").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn protocol() -> PublicationContext {
    PublicationContext::new(
        resolver().chain_id().clone(),
        resolver().protocol_version(),
        Epoch::new(0),
    )
    .unwrap()
}
fn policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::new(protocol())
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([8; 32]).unwrap()
}
fn operation(generation: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(generation).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    )
}
fn set_state(store: &SqliteDurableStore, key: Vec<u8>, value: Vec<u8>) {
    let prior: VersionedStateValue = store
        .get_versioned_durable(&operation(1), domain(), &key)
        .unwrap();
    let tx: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), prior.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(value)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&operation(1), tx),
        DurableCommitOutcome::Committed
    );
}
fn publish(
    store: &SqliteDurableStore,
    package: inventory::InventoryPackage,
    nonce: u64,
    id: u8,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> UnverifiedDependencyRef {
    assert!(package.wat.contains("sunrise"));
    let exports: Vec<String> = package
        .abi
        .objects
        .entrypoints
        .iter()
        .map(|e| e.name.clone())
        .collect();
    let origin: PackageOrigin = package.abi.objects.origin.clone();
    let abi: ExecutableAbi = ExecutableAbi {
        call: package.abi,
        initializer: package.initializer,
        transferable_constructors: package.transferable_constructors,
    };
    let semantics: Digest32 = local_execution_semantics(&resolver(), &protocol()).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: 2,
        semantics,
        wasm: package.wasm,
        unverified_abi: encode_executable_abi(&abi).unwrap(),
        exports,
        unverified_dependencies: dependencies,
    })
    .unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver(), &protocol(), &artifact, nonce, [id; 32])
            .unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [id; 32],
        PublicationRequest::new(artifact, nonce, digest, key(5).sign(&frame).into()),
    )
    .unwrap();
    let result: NodeOutput = handle_local_publication(
        store,
        &operation(1),
        domain(),
        &resolver(),
        &LocalPublicationPolicy::executable(protocol(), semantics),
        submission,
    )
    .unwrap();
    assert!(result.outbound_messages().is_empty());
    UnverifiedDependencyRef::new(origin, 1, protocol(), digest).unwrap()
}
fn instance(code: &UnverifiedDependencyRef, actor: u8, seed: u8) -> InstanceRecord {
    InstanceRecord {
        context: protocol(),
        creator: address(actor),
        seed: [seed; 32],
        code: code.clone(),
        revision: 1,
        initializer: "init".into(),
    }
}
fn signed(
    record: &InstanceRecord,
    actor: u8,
    nonce: u64,
    id: u8,
    entrypoint: &str,
    args: Vec<u8>,
    entries: Vec<AccessEntry>,
) -> Vec<u8> {
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: if entrypoint == "init" {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy().digest(&resolver()).unwrap(),
        call: CallIntent {
            context: protocol(),
            request_id: [id; 32],
            sender: address(actor),
            nonce,
            code: record.code.clone(),
            instance: instance_target(&resolver(), record).unwrap(),
            entrypoint: entrypoint.into(),
            type_arguments: vec![],
            access: abi::AccessManifest { entries },
            arguments: args,
            gas_limit: MAX_LOCAL_EXECUTION_GAS,
        },
    };
    let frame: Vec<u8> = local_execution_signing_frame(&protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key(actor).sign(&frame).into(),
    })
    .unwrap()
}
// Preserve the public boundary's typed error for exact conflict assertions.
#[allow(clippy::result_large_err)]
fn run(
    store: &SqliteDurableStore,
    generation: u64,
    bytes: &[u8],
) -> Result<NodeOutput, LocalExecutionAdmissionError> {
    handle_local_execution(
        store,
        &MemoryBlobStore::default(),
        &operation(generation),
        domain(),
        &resolver(),
        &[],
        &policy(),
        &LocalWasmExecutionEngine::new(),
        bytes,
        10,
    )
}
fn result(output: &NodeOutput) -> LocalExecutionResult {
    assert!(output.outbound_messages().is_empty());
    decode_local_execution_result(output.responses()[0].payload().unwrap()).unwrap()
}
fn created(output: &NodeOutput) -> Vec<Object> {
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    result(output)
        .effects
        .object_effects
        .into_iter()
        .filter_map(|e| {
            if let ObjectEffect::Created(o) = e {
                Some(o)
            } else {
                None
            }
        })
        .collect()
}
fn authority(store: &SqliteDurableStore, id: ObjectId) -> ObjectAuthority {
    decode_object_authority(
        store
            .get_versioned_durable(&operation(1), domain(), &object_authority_key(id))
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap()
}
fn by_type(
    store: &SqliteDurableStore,
    objects: &[Object],
    origin: &PackageOrigin,
    constructor: u16,
) -> Object {
    objects
        .iter()
        .find(|o| {
            let a: ObjectAuthority = authority(store, o.id);
            a.ty.origin() == origin && a.ty.constructor() == constructor
        })
        .unwrap()
        .clone()
}
fn live(store: &SqliteDurableStore, id: ObjectId) -> Object {
    let head: DurableObjectHead = store.get_object_head(&operation(1), domain(), id).unwrap();
    let record: DurableObjectVersionRecord = store
        .get_object_version(&operation(1), domain(), id, head.object_version().unwrap())
        .unwrap()
        .unwrap();
    match record.payload() {
        DurableObjectPayload::Inline(body) => body.object().clone(),
        _ => panic!("bounded fixture expected inline object"),
    }
}
fn access(object: &Object, mode: AccessMode) -> AccessEntry {
    AccessEntry {
        mode,
        object_ref: ObjectRef {
            id: object.id,
            version: object.version,
            digest: resolver()
                .hash_for_purpose(
                    protocol().epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(object).unwrap(),
                )
                .unwrap(),
        },
    }
}
fn values(object: &Object, count: usize) -> Vec<u64> {
    let decoded: CallValue =
        decode_call_value(&inventory::tuple_layout(count), &object.data).unwrap();
    let CallValue::Tuple(values) = decoded else {
        panic!("tuple expected")
    };
    values
        .into_iter()
        .map(|v| {
            if let CallValue::U64(n) = v {
                n
            } else {
                panic!("u64 expected")
            }
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    states: Vec<VersionedStateValue>,
    heads: Vec<DurableObjectHead>,
    versions: Vec<Vec<Option<DurableObjectVersionRecord>>>,
    receipts: Vec<Option<DurableRequestReceipt>>,
}
fn snapshot(
    store: &SqliteDurableStore,
    generation: u64,
    instances: &[InstanceRecord],
    origins: &[PackageOrigin],
    ids: &[ObjectId],
    receipt_ids: &[u8],
) -> Snapshot {
    let context: DurableOperationContext = operation(generation);
    let mut keys: Vec<Vec<u8>> = instances
        .iter()
        .map(|i| instance_record_key(protocol().chain_id(), &i.creator, &i.seed).unwrap())
        .collect();
    keys.extend(origins.iter().map(|o| publication_record_key(o).unwrap()));
    keys.extend(ids.iter().map(|id| object_authority_key(*id)));
    for actor in [5, 7, 8, 9] {
        keys.push(
            PersistenceLayout::new(protocol().chain_id().clone(), protocol().protocol_version())
                .sender_nonce_key(address(actor), protocol().epoch()),
        );
    }
    keys.push(execution_policy_key(&protocol()).unwrap());
    keys.push(publication_policy_key_for_profile(&protocol(), 2).unwrap());
    Snapshot {
        states: keys
            .iter()
            .map(|k| store.get_versioned_durable(&context, domain(), k).unwrap())
            .collect(),
        heads: ids
            .iter()
            .map(|id| store.get_object_head(&context, domain(), *id).unwrap())
            .collect(),
        versions: ids
            .iter()
            .map(|id| {
                (1..=3)
                    .map(|v| {
                        store
                            .get_object_version(
                                &context,
                                domain(),
                                *id,
                                DurableObjectVersion::new(v).unwrap(),
                            )
                            .unwrap()
                    })
                    .collect()
            })
            .collect(),
        receipts: receipt_ids
            .iter()
            .map(|id| {
                store
                    .get_request_receipt(
                        &context,
                        domain(),
                        DurableRequestId::new([*id; 32]).unwrap(),
                    )
                    .unwrap()
            })
            .collect(),
    }
}

#[test]
fn inventory_real_wasm_sqlite_success_nested_rollback_and_fenced_restart() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path: std::path::PathBuf = std::env::temp_dir().join(format!(
        "inventory-wasm-e2e-{}-{unique}.sqlite",
        std::process::id()
    ));
    let namespace: SqliteNamespace = SqliteNamespace::new(
        protocol().chain_id().clone(),
        ValidatorId::new([4; 32]),
        domain(),
    );
    let policy_origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), address(5), [1; 32]).unwrap();
    let warehouse_origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), address(5), [2; 32]).unwrap();
    let origins: Vec<PackageOrigin> = vec![policy_origin.clone(), warehouse_origin.clone()];
    let a: InstanceRecord;
    let b: InstanceRecord;
    let ids: Vec<ObjectId>;
    let baseline: Snapshot;
    let mut replay: Vec<(Vec<u8>, NodeOutput)> = Vec::new();
    let receipts: Vec<u8> = vec![1, 2, 10, 11, 12, 13, 14, 15, 16];
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let publication_policy: LocalPublicationPolicy = LocalPublicationPolicy::executable(
            protocol(),
            local_execution_semantics(&resolver(), &protocol()).unwrap(),
        );
        set_state(
            &store,
            publication_policy_key_for_profile(&protocol(), 2).unwrap(),
            publication_policy.encode().unwrap(),
        );
        set_state(
            &store,
            execution_policy_key(&protocol()).unwrap(),
            policy().encode().unwrap(),
        );
        let dependency: UnverifiedDependencyRef = publish(
            &store,
            inventory::dispatch_policy(&policy_origin),
            0,
            1,
            vec![],
        );
        let code: UnverifiedDependencyRef = publish(
            &store,
            inventory::warehouse(&warehouse_origin, &policy_origin),
            1,
            2,
            vec![dependency],
        );
        a = instance(&code, 7, 10);
        b = instance(&code, 8, 11);
        let init_a: Vec<u8> = signed(
            &a,
            7,
            0,
            10,
            "init",
            inventory::tuple_arguments(&[101, 100, 20]),
            vec![],
        );
        let output_a: NodeOutput = run(&store, 1, &init_a).unwrap();
        let objects_a: Vec<Object> = created(&output_a);
        assert_eq!(objects_a.len(), 3);
        replay.push((init_a, output_a));
        let init_b: Vec<u8> = signed(
            &b,
            8,
            0,
            11,
            "init",
            inventory::tuple_arguments(&[202, 80, 10]),
            vec![],
        );
        let output_b: NodeOutput = run(&store, 1, &init_b).unwrap();
        let objects_b: Vec<Object> = created(&output_b);
        assert_eq!(objects_b.len(), 3);
        replay.push((init_b, output_b));
        let cap: Object = by_type(&store, &objects_a, &warehouse_origin, 1);
        let stock: Object = by_type(&store, &objects_a, &warehouse_origin, 2);
        let dispatch: Object = by_type(&store, &objects_a, &policy_origin, 1);
        let bob_stock: Object = by_type(&store, &objects_b, &warehouse_origin, 2);
        assert_eq!(values(&stock, 2), vec![101, 100]);
        assert_eq!(values(&bob_stock, 2), vec![202, 80]);
        let bob_ids: Vec<ObjectId> = objects_b.iter().map(|o| o.id).collect();
        let bob_before: Snapshot =
            snapshot(&store, 1, std::slice::from_ref(&b), &[], &bob_ids, &[11]);
        // Correctly signed A invocation cannot substitute an object from B.
        let cross: Vec<u8> = signed(
            &a,
            7,
            1,
            90,
            "reserve",
            inventory::tuple_arguments(&[300, 1]),
            vec![
                access(&cap, AccessMode::Read),
                access(&bob_stock, AccessMode::Write),
            ],
        );
        assert!(run(&store, 1, &cross).is_err());
        let reserve: Vec<u8> = signed(
            &a,
            7,
            1,
            12,
            "reserve",
            inventory::tuple_arguments(&[301, 12]),
            vec![
                access(&cap, AccessMode::Read),
                access(&stock, AccessMode::Write),
            ],
        );
        let reserved: NodeOutput = run(&store, 1, &reserve).unwrap();
        let reservation: Object = by_type(&store, &created(&reserved), &warehouse_origin, 3);
        assert_eq!(values(&live(&store, stock.id), 2), vec![101, 88]);
        assert_eq!(result(&reserved).effects.events.len(), 1);
        replay.push((reserve, reserved));
        let fulfil: Vec<u8> = signed(
            &a,
            7,
            2,
            13,
            "fulfil",
            inventory::tuple_arguments(&[]),
            vec![
                access(&cap, AccessMode::Read),
                access(&reservation, AccessMode::Consume),
                access(&dispatch, AccessMode::Read),
            ],
        );
        let fulfilled: NodeOutput = run(&store, 1, &fulfil).unwrap();
        let shipment: Object = by_type(&store, &created(&fulfilled), &warehouse_origin, 4);
        assert_eq!(values(&shipment, 3), vec![301, 101, 12]);
        assert!(matches!(
            store
                .get_object_head(&operation(1), domain(), reservation.id)
                .unwrap(),
            DurableObjectHead::Tombstoned { .. }
        ));
        replay.push((fulfil, fulfilled));
        let transfer: Vec<u8> = signed(
            &a,
            7,
            3,
            14,
            "transfer",
            inventory::recipient_argument(address(9)),
            vec![access(&shipment, AccessMode::Write)],
        );
        let transferred: NodeOutput = run(&store, 1, &transfer).unwrap();
        assert_eq!(
            live(&store, shipment.id).owner,
            Owner::Address(Address::new(address(9)))
        );
        replay.push((transfer, transferred));
        let current_stock: Object = live(&store, stock.id);
        let reserve_large: Vec<u8> = signed(
            &a,
            7,
            4,
            15,
            "reserve",
            inventory::tuple_arguments(&[302, 25]),
            vec![
                access(&cap, AccessMode::Read),
                access(&current_stock, AccessMode::Write),
            ],
        );
        let large_output: NodeOutput = run(&store, 1, &reserve_large).unwrap();
        let large: Object = by_type(&store, &created(&large_output), &warehouse_origin, 3);
        replay.push((reserve_large, large_output));
        let before_head: DurableObjectHead = store
            .get_object_head(&operation(1), domain(), large.id)
            .unwrap();
        let before_authority: ObjectAuthority = authority(&store, large.id);
        let trap: Vec<u8> = signed(
            &a,
            7,
            5,
            16,
            "fulfil",
            inventory::tuple_arguments(&[]),
            vec![
                access(&cap, AccessMode::Read),
                access(&large, AccessMode::Consume),
                access(&dispatch, AccessMode::Read),
            ],
        );
        let trapped: NodeOutput = run(&store, 1, &trap).unwrap();
        assert_eq!(
            trapped.responses()[0].status(),
            NodeResponseStatus::Rejected
        );
        let failure: LocalExecutionResult = result(&trapped);
        assert_eq!(
            failure.effects.status,
            ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.into()
            }
        );
        assert!(failure.effects.object_effects.is_empty());
        assert!(failure.effects.events.is_empty());
        assert!(failure.effects.gas_used > 0);
        assert_eq!(
            store
                .get_object_head(&operation(1), domain(), large.id)
                .unwrap(),
            before_head
        );
        assert_eq!(authority(&store, large.id), before_authority);
        assert_eq!(live(&store, large.id), large);
        let phantom: ObjectId = derive_local_created_object_id(
            &resolver(),
            &protocol(),
            &a.context,
            &instance_target(&resolver(), &a).unwrap(),
            &a.code,
            failure.effects.tx_hash,
            0,
        )
        .unwrap();
        assert_eq!(
            store
                .get_object_head(&operation(1), domain(), phantom)
                .unwrap(),
            DurableObjectHead::Absent
        );
        assert!(
            store
                .get_versioned_durable(&operation(1), domain(), &object_authority_key(phantom))
                .unwrap()
                .value()
                .is_none()
        );
        replay.push((trap, trapped));
        assert_eq!(
            query_sender_next_nonce(
                &store,
                &operation(1),
                domain(),
                protocol().chain_id().clone(),
                protocol().protocol_version(),
                protocol().epoch(),
                address(7)
            )
            .unwrap(),
            6
        );
        // Compare B's exact instance and objects separately from shared nonce rows.
        let bob_after: Snapshot =
            snapshot(&store, 1, std::slice::from_ref(&b), &[], &bob_ids, &[11]);
        assert_eq!(bob_before.heads, bob_after.heads);
        assert_eq!(bob_before.versions, bob_after.versions);
        assert_eq!(bob_before.receipts, bob_after.receipts);
        assert_eq!(&bob_before.states[..4], &bob_after.states[..4]);
        ids = objects_a
            .iter()
            .chain(&objects_b)
            .map(|o| o.id)
            .chain([reservation.id, shipment.id, large.id, phantom])
            .collect();
        baseline = snapshot(
            &store,
            1,
            &[a.clone(), b.clone()],
            &origins,
            &ids,
            &receipts,
        );
        for (bytes, output) in &replay {
            assert_eq!(&run(&store, 1, bytes).unwrap(), output);
        }
        let reuse: Vec<u8> = signed(
            &a,
            7,
            6,
            16,
            "reserve",
            inventory::tuple_arguments(&[303, 1]),
            vec![
                access(&cap, AccessMode::Read),
                access(&live(&store, stock.id), AccessMode::Write),
            ],
        );
        assert!(matches!(
            run(&store, 1, &reuse),
            Err(LocalExecutionAdmissionError::Node(
                NodeCoreError::RequestIdReuse
            ))
        ));
        assert_eq!(
            snapshot(
                &store,
                1,
                &[a.clone(), b.clone()],
                &origins,
                &ids,
                &receipts
            ),
            baseline
        );
        store
            .advance_writer_fence(
                WriterFenceGeneration::new(1).unwrap(),
                WriterFenceGeneration::new(2).unwrap(),
            )
            .unwrap();
    }
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace, WriterFenceGeneration::new(1).unwrap())
                .unwrap();
        assert_eq!(
            store.writer_fence().unwrap(),
            WriterFenceGeneration::new(2).unwrap()
        );
        assert!(run(&store, 1, &replay[0].0).is_err());
        for (bytes, output) in &replay {
            assert_eq!(&run(&store, 2, bytes).unwrap(), output);
        }
        assert_eq!(
            snapshot(
                &store,
                2,
                &[a.clone(), b.clone()],
                &origins,
                &ids,
                &receipts
            ),
            baseline
        );
        for record in [&a, &b] {
            assert_eq!(
                query_local_instance(
                    &store,
                    &operation(2),
                    domain(),
                    &resolver(),
                    &[],
                    protocol().chain_id(),
                    record.creator,
                    record.seed
                )
                .unwrap(),
                Some(record.clone())
            );
        }
    }
    // Both stores are closed; retain the fixture only when an assertion failed.
    std::fs::remove_file(path).unwrap();
}
