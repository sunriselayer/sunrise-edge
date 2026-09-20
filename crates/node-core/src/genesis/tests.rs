use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::{PackageOrigin, derive_scoped_type_id};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    InstanceRecord, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
    ObjectAuthority, SignedLocalExecutionIntent, generic_object_result_semantics, instance_target,
    local_execution_signing_frame,
};
use execution::paid_execution::{MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidFeePolicy};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationContext, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
};
use fees::GasSchedule;
use hashing::HashSuiteResolver;
use objects::{Address, Object, ObjectId, Owner, encode_object};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion, ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectProvenance, DurableObjectRoutingProjection, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    DurableRequestReceipt, MemoryDurableStateStore, StateMutation, StateMutationEntry,
    StateReadAssertion, StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use sha2::{Digest, Sha256};

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key() -> SigningKey {
    SigningKey::from([7; 32])
}

fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}

fn chain() -> ChainId {
    ChainId::new("genesis-test").unwrap()
}

fn protocol() -> PublicationContext {
    PublicationContext::new(chain(), ProtocolVersion::new(3), Epoch::new(0)).unwrap()
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}

fn context(generation: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(generation).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    )
}

fn build_fixture() -> (
    GenesisManifest,
    PackageOrigin,
    InstanceRecord,
    ObjectId,
    ObjectId,
) {
    let origin = PackageOrigin::unverified(chain(), sender(), [1; 32]).unwrap();
    let package = public_standard_asset::build_package(&origin).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &protocol()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: Vec::new(),
    })
    .unwrap();

    let digest = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &protocol(), &artifact, 0, [1; 32])
            .unwrap();
    let submission = PublicationSubmission::new(
        [1; 32],
        PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
    )
    .unwrap();

    let code_ref = UnverifiedDependencyRef::new(origin.clone(), 1, protocol(), digest).unwrap();
    let instance_record = InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [2; 32],
        code: code_ref.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let target = instance_target(&resolver(), &instance_record).unwrap();

    let base_policy = LocalExecutionPolicy::generic_object_results(protocol());
    let base_policy_digest = base_policy.digest(&resolver()).unwrap();

    let call = CallIntent {
        context: protocol(),
        request_id: [2; 32],
        sender: sender(),
        nonce: 0,
        code: code_ref.clone(),
        instance: target.clone(),
        entrypoint: "init".into(),
        type_arguments: Vec::new(),
        access: abi::AccessManifest {
            entries: Vec::new(),
        },
        arguments: Vec::new(),
        gas_limit: 500_000,
    };
    let init_intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Instantiate,
        policy_digest: base_policy_digest,
        call,
        authorizations: Vec::new(),
    };
    let init_frame = local_execution_signing_frame(&protocol(), &init_intent).unwrap();
    let signed_init = SignedLocalExecutionIntent {
        intent: init_intent,
        signature: key().sign(&init_frame).into(),
    };

    let def_id = ObjectId::new([0x10; 32]);
    let coin_id = ObjectId::new([0x20; 32]);

    let def_tag = public_standard_asset::definition_type_tag(&origin).unwrap();
    let coin_tag = public_standard_asset::coin_type_tag(&origin, &def_id).unwrap();

    let fee_policy = PaidFeePolicy {
        context: protocol(),
        base_policy_digest,
        instance: target.clone(),
        code: code_ref.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
        asset_type: coin_tag.clone(),
        reservation_type: public_standard_asset::reservation_type_tag(&origin, &def_id).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: sender(),
        gas_schedule: GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: MIN_RESERVE_ALLOWANCE,
        settle_allowance: MIN_SETTLE_ALLOWANCE,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    };

    let def_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &def_tag).unwrap();
    let coin_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &coin_tag).unwrap();

    let def_obj = Object {
        id: def_id,
        version: 1,
        owner: Owner::Address(Address::new(sender())),
        type_hash: def_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: encode_call_value(
            &public_standard_asset::definition_body_layout(),
            &CallValue::Tuple(Vec::new()),
        )
        .unwrap(),
    };
    let def_auth = ObjectAuthority {
        object_id: def_id,
        instance_context: protocol(),
        instance: target.clone(),
        code: code_ref.clone(),
        ty: def_tag,
    };

    let coin_data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(1_000_000),
    )
    .unwrap();
    let coin_obj = Object {
        id: coin_id,
        version: 1,
        owner: Owner::Address(Address::new(sender())),
        type_hash: coin_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: coin_data,
    };
    let coin_auth = ObjectAuthority {
        object_id: coin_id,
        instance_context: protocol(),
        instance: target,
        code: code_ref,
        ty: coin_tag,
    };

    let mut manifest = GenesisManifest {
        genesis_authority: sender(),
        publication: submission,
        initialization: signed_init,
        fee_policy,
        objects: vec![
            GenesisObjectEntry {
                object: def_obj,
                authority: def_auth,
            },
            GenesisObjectEntry {
                object: coin_obj,
                authority: coin_auth,
            },
        ],
        signature: [0; 64],
    };
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    (manifest, origin, instance_record, def_id, coin_id)
}

#[test]
fn stable_vectors_0x6416_manifest_and_0x6417_marker() {
    let (manifest, _, _, _, _) = build_fixture();
    let manifest_bytes = encode_genesis_manifest(&manifest).unwrap();
    assert_eq!(manifest_bytes.len(), 15964);
    let manifest_sha256 = hex(&Sha256::digest(&manifest_bytes));
    assert_eq!(
        manifest_sha256,
        "4dca0d2690f5198a0e64a1fbe595bad60388f007d38b33f37e3f111cd8ada458"
    );

    let decoded = decode_genesis_manifest(&manifest_bytes).unwrap();
    assert_eq!(decoded, manifest);

    let manifest_digest = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    let marker = GenesisInstallMarker {
        context: protocol(),
        manifest_digest,
        genesis_authority: manifest.genesis_authority,
        installed_at_checkpoint: 42,
    };
    let marker_bytes = encode_genesis_install_marker(&marker).unwrap();
    assert_eq!(marker_bytes.len(), 182);
    let marker_sha256 = hex(&Sha256::digest(&marker_bytes));
    assert_eq!(
        marker_sha256,
        "4f7a7a32443803ed6127bbd23242116c3e57d7a713fd812bf3c538e8261c34f9"
    );

    let decoded_marker = decode_genesis_install_marker(&marker_bytes).unwrap();
    assert_eq!(decoded_marker, marker);
}

#[test]
fn unsigned_manifest_object_tampering_fails_before_install() {
    let (mut manifest, _, _, _, _) = build_fixture();
    manifest.objects[1].object.data[0] ^= 0x01;
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error = install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 1)
        .expect_err("objects not covered by the genesis signature must fail closed");
    assert!(matches!(
        error,
        GenesisError::Invalid("invalid genesis manifest signature")
    ));
}

#[test]
fn fresh_install_and_verify_only_restart_in_memory() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, instance_record, def_id, coin_id) = build_fixture();

    // 1. Fresh install.
    let outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let (marker, digest) = match outcome {
        GenesisInstallOutcome::FreshInstall {
            marker,
            manifest_digest,
        } => (marker, manifest_digest),
        _ => panic!("expected FreshInstall"),
    };
    assert_eq!(marker.manifest_digest, digest);
    assert_eq!(marker.genesis_authority, manifest.genesis_authority);
    assert_eq!(marker.installed_at_checkpoint, 10);

    // Verify all installed records in store.
    let man_key = genesis_manifest_key(&protocol()).unwrap();
    let mark_key = genesis_marker_key(&protocol()).unwrap();
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let inst_key = local_instance_state::instance_record_key(
        protocol().chain_id(),
        &instance_record.creator,
        &instance_record.seed,
    )
    .unwrap();
    let pub_pol_key = publication::publication_policy_key_for_profile(&protocol(), 4).unwrap();
    let exec_pol_key =
        local_instance_state::execution_policy_key_for_profile(&protocol(), 4).unwrap();
    let fee_pol_key = local_instance_state::paid_fee_policy_key(&protocol()).unwrap();

    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &man_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &mark_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &pub_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &inst_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &pub_pol_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &exec_pol_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &fee_pol_key)
            .unwrap()
            .value()
            .is_some()
    );

    for obj_id in [def_id, coin_id] {
        let auth_key = local_instance_state::object_authority_key(obj_id);
        assert!(
            store
                .get_versioned_durable(&context(1), domain(), &auth_key)
                .unwrap()
                .value()
                .is_some()
        );
        assert!(matches!(
            store
                .get_object_head(&context(1), domain(), obj_id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
        let ver = store
            .get_object_version(&context(1), domain(), obj_id, DurableObjectVersion::FIRST)
            .unwrap();
        assert!(ver.is_some());
    }

    // 2. Restart verify-only.
    let restart_outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    match restart_outcome {
        GenesisInstallOutcome::VerifiedExisting {
            marker: remk,
            manifest_digest: redig,
        } => {
            assert_eq!(remk, marker);
            assert_eq!(redig, digest);
        }
        _ => panic!("expected VerifiedExisting"),
    }
}

#[test]
fn mutable_balance_changes_tolerated_while_version_1_provenance_exact_and_supply_reissue_prevented()
{
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, _, _, _, coin_id) = build_fixture();

    // 1. Fresh install.
    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    // 2. Simulate subsequent mutation (e.g. transfer/split, balance reduced to 500_000, version advanced to 2).
    let mutated_coin_data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(500_000),
    )
    .unwrap();
    let mutated_coin = Object {
        id: coin_id,
        version: 2,
        owner: Owner::Address(Address::new(sender())),
        type_hash: manifest.objects[1].object.type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: mutated_coin_data,
    };
    let canonical_bytes = encode_object(&mutated_coin).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let version_two_record = DurableObjectVersionRecord::from_inline_object(
        mutated_coin.clone(),
        digest,
        DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
        20,
    )
    .unwrap();

    let head_read = DurableObjectHeadRead::new(
        coin_id,
        store
            .get_object_head(&context(1), domain(), coin_id)
            .unwrap(),
    );
    let update_mutation = DurableObjectMutationEntry::new(
        coin_id,
        DurableObjectMutation::Update {
            version: version_two_record,
            owner_projection: DurableObjectOwnerProjection::from_owner(mutated_coin.owner.clone())
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
    );
    let object_changes = DurableObjectChanges::new(vec![head_read], vec![update_mutation]).unwrap();

    let durable_id = DurableRequestId::new([9; 32]).unwrap();
    let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1, 2, 3]).unwrap();
    let tx =
        DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    // Verify current head is at version 2.
    let head = store
        .get_object_head(&context(1), domain(), coin_id)
        .unwrap();
    match head {
        DurableObjectHead::Current { object_version, .. } => assert_eq!(object_version.get(), 2),
        _ => panic!("expected Current head at version 2"),
    }

    // 3. Restart: verify-only path MUST succeed because version-1 provenance is exact.
    let restart_outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));

    // 4. Supply reissue prevented: head is STILL version 2, NOT overwritten or reset to version 1.
    let head_after = store
        .get_object_head(&context(1), domain(), coin_id)
        .unwrap();
    match head_after {
        DurableObjectHead::Current { object_version, .. } => assert_eq!(object_version.get(), 2),
        _ => panic!("expected Current head at version 2 after restart"),
    }
}

#[test]
fn partial_prior_state_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, _, _, coin_id) = build_fixture();

    // Partial case 1: publication record exists without marker.
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let obs = store
        .get_versioned_durable(&context(1), domain(), &pub_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(pub_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(pub_key, StateMutation::Put(vec![1, 2])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::PartialPriorState("publication")
    ));

    // Partial case 2: object head exists without marker.
    let store2 = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let canonical_bytes = encode_object(&manifest.objects[1].object).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let version = DurableObjectVersionRecord::from_inline_object(
        manifest.objects[1].object.clone(),
        digest,
        DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
        10,
    )
    .unwrap();
    let object_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            coin_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(
                    manifest.objects[1].object.owner.clone(),
                )
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let durable_id = DurableRequestId::new([8; 32]).unwrap();
    let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1]).unwrap();
    let tx =
        DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None).unwrap();
    assert_eq!(
        store2.commit_invocation(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err2 =
        install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err2,
        GenesisError::PartialPriorState("object head")
    ));
}

#[test]
fn tombstoned_marker_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, _, _, _, _) = build_fixture();

    let mark_key = genesis_marker_key(&protocol()).unwrap();
    // Put then delete marker.
    let obs0 = store
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx1 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs0.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(mark_key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx1),
        DurableCommitOutcome::Committed
    );

    let obs = store
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx2 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(mark_key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx2),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err, GenesisError::TombstonedMarker));
}

#[test]
fn missing_or_tampered_records_fail_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, _, _, _) = build_fixture();

    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    // 1. Missing record on restart: delete publication record.
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let obs = store
        .get_versioned_durable(&context(1), domain(), &pub_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(pub_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(pub_key.clone(), StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::TamperedInstalledRecord("publication record")
    ));

    // 2. Tampered marker manifest digest.
    let store2 = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    let mark_key = genesis_marker_key(&protocol()).unwrap();
    let bad_marker = GenesisInstallMarker {
        context: protocol(),
        manifest_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xff; 32]),
        genesis_authority: manifest.genesis_authority,
        installed_at_checkpoint: 10,
    };
    let obs2 = store2
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx2 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs2.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                mark_key,
                StateMutation::Put(encode_genesis_install_marker(&bad_marker).unwrap()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store2.commit_durable(&context(1), tx2),
        DurableCommitOutcome::Committed
    );

    let err2 =
        install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err2, GenesisError::ManifestCommitmentMismatch));
}

#[test]
fn fencing_rejects_stale_writer() {
    // Store fenced at generation 2.
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(2).unwrap());
    let (manifest, _, _, _, _) = build_fixture();

    // Invocation with generation 1 (stale).
    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::DurableRead(DurableReadError::WriterFenced { .. })
            | GenesisError::CommitRejected(DurableCommitRejection::WriterFenced { .. })
    ));
}

#[test]
fn fee_abi_admission_mismatch_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (mut manifest, _, _, _, _) = build_fixture();

    // Tamper reserve entrypoint so fee interface admission fails.
    manifest.fee_policy.reserve_entrypoint = "unknown_reserve".into();
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err, GenesisError::FeeInterfaceAdmission(_)));
}

#[test]
fn file_backed_sqlite_fresh_install_restart_mutation_and_fencing() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("genesis-durable-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([4; 32]), domain());

    let (manifest, _, _, _, coin_id) = build_fixture();

    // 1. Fresh install on file-backed SQLite with generation 1.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            outcome,
            GenesisInstallOutcome::FreshInstall { .. }
        ));
    }

    // 2. Reopen and verify-only restart.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let restart_outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
    }

    // 3. Mutate coin object to version 2 on SQLite.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let mutated_coin_data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(250_000),
        )
        .unwrap();
        let mutated_coin = Object {
            id: coin_id,
            version: 2,
            owner: Owner::Address(Address::new(sender())),
            type_hash: manifest.objects[1].object.type_hash,
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: mutated_coin_data,
        };
        let canonical_bytes = encode_object(&mutated_coin).unwrap();
        let digest = resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
            .unwrap();
        let version_two_record = DurableObjectVersionRecord::from_inline_object(
            mutated_coin.clone(),
            digest,
            DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
            25,
        )
        .unwrap();

        let head_read = DurableObjectHeadRead::new(
            coin_id,
            store
                .get_object_head(&context(1), domain(), coin_id)
                .unwrap(),
        );
        let update_mutation = DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Update {
                version: version_two_record,
                owner_projection: DurableObjectOwnerProjection::from_owner(
                    mutated_coin.owner.clone(),
                )
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        );
        let object_changes =
            DurableObjectChanges::new(vec![head_read], vec![update_mutation]).unwrap();

        let durable_id = DurableRequestId::new([7; 32]).unwrap();
        let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1, 2]).unwrap();
        let tx = DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None)
            .unwrap();
        assert_eq!(
            store.commit_invocation(&context(1), tx),
            DurableCommitOutcome::Committed
        );
    }

    // 4. Reopen and verify restart still succeeds and head is STILL version 2 (supply reissue prevented).
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let restart_outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));

        let head = store
            .get_object_head(&context(1), domain(), coin_id)
            .unwrap();
        match head {
            DurableObjectHead::Current { object_version, .. } => {
                assert_eq!(object_version.get(), 2)
            }
            _ => panic!("expected Current head at version 2 on SQLite"),
        }
    }

    // 5. Advance writer fence to generation 2: attempt install with generation 1 (stale) fails with fencing.
    {
        let store =
            SqliteDurableStore::open(&db_path, namespace, WriterFenceGeneration::new(1).unwrap())
                .unwrap();
        store
            .advance_writer_fence(
                WriterFenceGeneration::new(1).unwrap(),
                WriterFenceGeneration::new(2).unwrap(),
            )
            .unwrap();
        let err =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
        assert!(matches!(
            err,
            GenesisError::DurableRead(DurableReadError::WriterFenced { .. })
                | GenesisError::CommitRejected(DurableCommitRejection::WriterFenced { .. })
        ));
    }
}
