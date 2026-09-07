use super::*;
use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_abi, encode_call_value};
use abi::package_types::{PackageOrigin, ScopedTypeTag, derive_scoped_type_id};
use abi::public_abi as public;
use execution::publication::*;

fn publication(count: usize) -> VerifiedPublicationInterface {
    let key: SigningKey = SigningKey::from([7; 32]);
    let origin: PackageOrigin = PackageOrigin::unverified(
        ChainId::new("sunrise-test").unwrap(),
        ed25519_zebra::VerificationKey::from(&key).into(),
        [1; 32],
    )
    .unwrap();
    let context: PublicationContext = PublicationContext::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    let semantics: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]);
    let abi: CallAbi = CallAbi {
        objects: public::PackageAbi {
            origin: origin.clone(),
            constructors: vec![public::ConstructorDeclaration {
                local_id: 1,
                schema: 1,
                arguments: vec![],
            }],
            entrypoints: vec![public::EntrypointDeclaration {
                name: "run".into(),
                type_parameters: vec![],
                objects: vec![
                    public::ObjectParameter {
                        mode: public::ObjectMode::Write,
                        schema: 1,
                        ty: public::TypePattern {
                            origin: origin.clone(),
                            constructor: 1,
                            arguments: vec![]
                        }
                    };
                    count
                ],
            }],
        },
        arguments: vec![ValueLayout::Tuple(vec![])],
        bodies: vec![ValueLayout::U64],
    };
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin,
        revision: 1,
        wasm_profile: 1,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: encode_call_abi(&abi).unwrap(),
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let resolver: HashSuiteResolver = resolver("sunrise-test");
    let digest: Digest32 = artifact_commitment(&resolver, &context, &artifact).unwrap();
    let frame: Vec<u8> = publication_signing_frame(&resolver, &context, &artifact, 0).unwrap();
    let candidate = authenticate_publication(
        &resolver,
        &context,
        &semantics,
        PublicationRequest::new(artifact, 0, digest, key.sign(&frame).into()),
    )
    .unwrap();
    verify_publication_interface(candidate, vec![]).unwrap()
}
fn typed_object(interface: &VerifiedPublicationInterface, id: u8) -> Object {
    let ty: ScopedTypeTag = ScopedTypeTag::new(interface.abi().origin.clone(), 1, vec![]).unwrap();
    Object {
        id: ObjectId::new([id; 32]),
        version: 1,
        owner: Owner::System,
        type_hash: derive_scoped_type_id(&resolver("sunrise-test"), Epoch::new(0), &ty).unwrap(),
        schema_version: 1,
        data: encode_call_value(&ValueLayout::U64, &CallValue::U64(7)).unwrap(),
    }
}
fn install(
    store: &ScriptedDurableStore,
    blob: &InstrumentedBlobStore,
    object: Object,
    as_blob: bool,
    chain: &str,
    version: u32,
) -> (ObjectRef, DurableObjectHead) {
    let bytes: Vec<u8> = encode_object(&object).unwrap();
    let digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            ProtocolVersion::new(version),
            &ChainId::new(chain).unwrap(),
            &bytes,
        )
        .unwrap();
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(ChainId::new(chain).unwrap(), ProtocolVersion::new(version));
    let record: DurableObjectVersionRecord = if as_blob {
        blob.insert(digest, bytes);
        DurableObjectVersionRecord::from_blob_reference(
            object.id,
            DurableObjectVersion::new(object.version).unwrap(),
            digest,
            object.schema_version,
            provenance,
            7,
            digest,
        )
    } else {
        DurableObjectVersionRecord::from_inline_object(object.clone(), digest, provenance, 7)
            .unwrap()
    };
    let head: DurableObjectHead = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::new(object.version).unwrap(),
        object_version: DurableObjectVersion::new(object.version).unwrap(),
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(object.owner).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object.id, head.clone(), Some(record));
    (
        ObjectRef {
            id: object.id,
            version: object.version,
            digest,
        },
        head,
    )
}
fn access(reference: ObjectRef) -> AccessManifest {
    AccessManifest {
        entries: vec![AccessEntry {
            object_ref: reference,
            mode: AccessMode::Write,
        }],
    }
}
fn load(
    store: &ScriptedDurableStore,
    blob: &InstrumentedBlobStore,
    bound: &BoundObjectSignature<'_>,
    manifest: &AccessManifest,
) -> Result<BoundObjectSnapshots, BoundSnapshotError> {
    load_bound_object_snapshots(
        store,
        blob,
        &durable_context(),
        domain(1),
        &resolver("sunrise-test"),
        Epoch::new(7),
        bound,
        manifest,
    )
}

#[test]
fn inline_and_blob_reads_reuse_integrity_checks_and_return_exact_head_obligations() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    for as_blob in [false, true] {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob = InstrumentedBlobStore::default();
        let object = typed_object(&interface, 1);
        let (reference, head) = install(&store, &blob, object.clone(), as_blob, "sunrise-test", 3);
        let result = load(&store, &blob, &bound, &access(reference)).unwrap();
        assert_eq!(result.objects().len(), 1);
        assert_eq!(result.objects()[0].object, object);
        assert_eq!(
            result.reads(),
            &[runtime::DurableObjectHeadRead::new(object.id, head)]
        );
        assert_eq!(blob.get_calls.load(Ordering::SeqCst), usize::from(as_blob));
        assert!(store.commits.lock().unwrap().is_empty());
        assert!(store.receipt.lock().unwrap().is_none());
        assert_eq!(store.state_reads.load(Ordering::SeqCst), 0);
        // System Write is readable here but is NOT authorized for execution.
        assert_eq!(result.objects()[0].object.owner, Owner::System);
    }
}

#[test]
fn malformed_manifest_and_wrong_chain_fail_before_storage_reads() {
    let interface = publication(2);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob = InstrumentedBlobStore::default();
    let entry = AccessEntry {
        object_ref: sample_object_ref(1),
        mode: AccessMode::Write,
    };
    for entries in [
        vec![],
        vec![entry.clone()],
        vec![entry.clone(); 2],
        vec![entry.clone(); 33],
    ] {
        assert!(load(&store, &blob, &bound, &AccessManifest { entries }).is_err());
    }
    let manifest = AccessManifest {
        entries: vec![
            entry,
            AccessEntry {
                object_ref: sample_object_ref(2),
                mode: AccessMode::Write,
            },
        ],
    };
    assert!(
        load_bound_object_snapshots(
            &store,
            &blob,
            &durable_context(),
            domain(1),
            &resolver("other-chain"),
            Epoch::new(7),
            &bound,
            &manifest
        )
        .is_err()
    );
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 0);
    assert_eq!(blob.get_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn empty_declarations_read_nothing_and_wrong_mode_rejects_before_io() {
    let empty = publication(0);
    let bound = bind_object_signature(&empty, "run", &[]).unwrap();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob = InstrumentedBlobStore::default();
    let result = load(&store, &blob, &bound, &AccessManifest::new()).unwrap();
    assert!(result.objects().is_empty());
    assert!(result.reads().is_empty());
    let single = publication(1);
    let bound = bind_object_signature(&single, "run", &[]).unwrap();
    let mut wrong = access(sample_object_ref(1));
    wrong.entries[0].mode = AccessMode::Read;
    assert!(load(&store, &blob, &bound, &wrong).is_err());
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 0);
}

#[test]
fn valid_storage_hash_is_not_a_substitute_for_signed_body_type_and_schema() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    for change in 0..4 {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob = InstrumentedBlobStore::default();
        let mut object = typed_object(&interface, 1);
        match change {
            0 => object.data = vec![0xff],
            1 => object.data.push(0),
            2 => object.schema_version = 2,
            _ => object.type_hash = sample_object_ref(5).digest,
        }
        let (reference, _) = install(&store, &blob, object, true, "sunrise-test", 3);
        assert!(matches!(
            load(&store, &blob, &bound, &access(reference)),
            Err(BoundSnapshotError::Body(_))
        ));
        assert!(store.commits.lock().unwrap().is_empty());
    }
}

#[test]
fn stale_reference_and_storage_corruption_fail_closed() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    for change in 0..5 {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob = InstrumentedBlobStore::default();
        let object = typed_object(&interface, 1);
        let (mut reference, _) = install(&store, &blob, object.clone(), false, "sunrise-test", 3);
        match change {
            0 => reference.version = 2,
            1 => reference.digest = sample_object_ref(5).digest,
            2 => {
                let mut corrupt = object.clone();
                corrupt.data = encode_call_value(&ValueLayout::U64, &CallValue::U64(99)).unwrap();
                let record = DurableObjectVersionRecord::from_inline_object(
                    corrupt,
                    reference.digest,
                    DurableObjectProvenance::new(
                        ChainId::new("sunrise-test").unwrap(),
                        ProtocolVersion::new(3),
                    ),
                    7,
                )
                .unwrap();
                store
                    .object_versions
                    .lock()
                    .unwrap()
                    .insert((object.id, 1), record);
            }
            3 => {
                store.object_versions.lock().unwrap().clear();
            }
            _ => {
                let mut heads = store.object_heads.lock().unwrap();
                if let DurableObjectHead::Current {
                    owner_projection, ..
                } = heads.get_mut(&object.id).unwrap()
                {
                    *owner_projection =
                        DurableObjectOwnerProjection::from_owner(Owner::Immutable).unwrap();
                }
            }
        }
        assert!(matches!(
            load(&store, &blob, &bound, &access(reference)),
            Err(BoundSnapshotError::Node(_))
        ));
        assert!(store.commits.lock().unwrap().is_empty());
    }
}

#[test]
fn cross_chain_provenance_rejects_before_blob_fetch_and_blob_corruption_is_rejected() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob = InstrumentedBlobStore::default();
    let object = typed_object(&interface, 1);
    let (reference, _) = install(&store, &blob, object.clone(), true, "other-chain", 3);
    assert!(matches!(
        load(&store, &blob, &bound, &access(reference)),
        Err(BoundSnapshotError::Node(
            NodeCoreError::ObjectProvenanceMismatch { .. }
        ))
    ));
    assert_eq!(blob.get_calls.load(Ordering::SeqCst), 0);
    let (reference, _) = install(&store, &blob, object, true, "sunrise-test", 3);
    blob.insert(reference.digest, vec![0xff]);
    assert!(matches!(
        load(&store, &blob, &bound, &access(reference)),
        Err(BoundSnapshotError::Node(
            NodeCoreError::ObjectBlobDigestMismatch { .. }
        ))
    ));
}

#[test]
fn original_object_hash_context_survives_reader_protocol_and_hash_rotation() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    for as_blob in [false, true] {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob = InstrumentedBlobStore::default();
        let object = typed_object(&interface, 1);
        let (reference, _) = install(&store, &blob, object, as_blob, "sunrise-test", 2);
        let current = resolver_with_rotation("sunrise-test", Epoch::new(4));
        assert!(
            load_bound_object_snapshots(
                &store,
                &blob,
                &durable_context(),
                domain(1),
                &current,
                Epoch::new(7),
                &bound,
                &access(reference)
            )
            .is_ok()
        );
    }
}

#[test]
fn later_head_changes_do_not_turn_read_observations_into_reservations() {
    let interface = publication(1);
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob = InstrumentedBlobStore::default();
    let object = typed_object(&interface, 1);
    let (reference, head) = install(&store, &blob, object.clone(), false, "sunrise-test", 3);
    let snapshot = load(&store, &blob, &bound, &access(reference.clone())).unwrap();
    let mut changed = object;
    changed.version = 2;
    changed.data = encode_call_value(&ValueLayout::U64, &CallValue::U64(42)).unwrap();
    let (_, new_head) = install(&store, &blob, changed, false, "sunrise-test", 3);
    assert_eq!(snapshot.reads()[0].expected(), &head);
    assert_ne!(snapshot.reads()[0].expected(), &new_head);
    assert!(store.commits.lock().unwrap().is_empty());
    assert!(load(&store, &blob, &bound, &access(reference)).is_err());
}
