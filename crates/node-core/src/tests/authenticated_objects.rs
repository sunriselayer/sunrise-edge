#[test]
fn authenticated_read_only_manifest_commits_sorted_exact_head_assertions() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF1);
    let signing_key = dev_signing_key(0xB1);
    let sender: Address = dev_sender_address(&signing_key);
    let higher_id: ObjectId = ObjectId::new([0x31; 32]);
    let lower_id: ObjectId = ObjectId::new([0x21; 32]);
    let (higher_ref, higher_head): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        higher_id,
        Owner::Address(sender),
        0x31,
    );
    let (lower_ref, lower_head): (ObjectRef, DurableObjectHead) =
        preload_inline_object(&store, "sunrise-test", lower_id, Owner::Immutable, 0x21);
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: higher_ref,
            mode: AccessMode::Read,
        },
        AccessEntry {
            object_ref: lower_ref,
            mode: AccessMode::Read,
        },
    ]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD1),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 2);
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert!(object_changes.mutations().is_empty());
    assert_eq!(
        object_changes.reads(),
        &[
            runtime::DurableObjectHeadRead::new(lower_id, lower_head),
            runtime::DurableObjectHeadRead::new(higher_id, higher_head),
        ]
    );
}

/// Every pure, zero-I/O rejection in [`validate_object_entries`]. The
/// duplicate-`ObjectId` branch is otherwise unreachable through
/// [`authenticated_submission_with_manifest`], since
/// [`abi::decode_access_manifest`] already rejects a duplicate id while
/// decoding the authenticated transaction, so it is exercised directly
/// against the extracted validator here.
#[test]
fn validate_object_entries_rejects_every_pure_branch() {
    fn entry(byte: u8, version: u64, mode: AccessMode) -> AccessEntry {
        AccessEntry {
            object_ref: ObjectRef {
                id: ObjectId::new([byte; 32]),
                version,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
            },
            mode,
        }
    }

    let accepted: Vec<AccessEntry> = (0..32u8)
        .map(|byte| entry(byte, 1, AccessMode::Read))
        .collect();
    let accesses = validate_object_entries(&accepted, AuthenticatedObjectPolicy::ReadOnly).unwrap();
    assert_eq!(accesses.len(), 32);
    assert!(
        accesses
            .windows(2)
            .all(|pair| pair[0].object_ref.id < pair[1].object_ref.id)
    );

    let too_many: Vec<AccessEntry> = (0..33u8)
        .map(|byte| entry(byte, 1, AccessMode::Read))
        .collect();
    assert_eq!(
        validate_object_entries(&too_many, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
        NodeCoreError::ObjectManifestTooLarge {
            count: 33,
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        }
    );

    let duplicate_id = ObjectId::new([0x09; 32]);
    let duplicate = vec![
        AccessEntry {
            object_ref: ObjectRef {
                id: duplicate_id,
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x01; 32]),
            },
            mode: AccessMode::Read,
        },
        AccessEntry {
            object_ref: ObjectRef {
                id: duplicate_id,
                version: 2,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x02; 32]),
            },
            mode: AccessMode::Read,
        },
    ];
    assert_eq!(
        validate_object_entries(&duplicate, AuthenticatedObjectPolicy::ReadOnly).unwrap_err(),
        NodeCoreError::DuplicateObjectAccess {
            object_id: duplicate_id
        }
    );

    let zero_version_id = ObjectId::new([0x0A; 32]);
    assert_eq!(
        validate_object_entries(
            &[entry(0x0A, 0, AccessMode::Read)],
            AuthenticatedObjectPolicy::ReadOnly,
        )
        .unwrap_err(),
        NodeCoreError::InvalidObjectVersion {
            object_id: zero_version_id,
            version: 0,
        }
    );

    for mode in [AccessMode::Write, AccessMode::Consume] {
        let object_id = ObjectId::new([0x0B; 32]);
        assert_eq!(
            validate_object_entries(&[entry(0x0B, 1, mode)], AuthenticatedObjectPolicy::ReadOnly,)
                .unwrap_err(),
            NodeCoreError::ObjectAccessModeUnsupported { object_id, mode }
        );
    }

    let owned_modes = validate_object_entries(
        &[
            entry(0x0D, 1, AccessMode::Consume),
            entry(0x0C, 1, AccessMode::Write),
        ],
        AuthenticatedObjectPolicy::OwnedMutations {
            created_checkpoint: 1,
        },
    )
    .unwrap();
    assert_eq!(owned_modes.len(), 2);
    assert_eq!(owned_modes[0].object_ref.id, ObjectId::new([0x0D; 32]));
    assert_eq!(owned_modes[1].object_ref.id, ObjectId::new([0x0C; 32]));
}

/// Every storage-facing branch of `load_and_authorize_objects` that only
/// runs once the pure manifest validation above has already passed:
/// unsupported access modes, absence, tombstones, version/digest
/// disagreement with the signed reference, unsupported owner kinds,
/// unreadable blob bodies, a missing immutable version record, and every
/// distinct shape of storage corruption the corruption guard must catch
/// — including an owner projection that disagreed with the inline
/// object's owner and one that was absent entirely.
#[test]
fn authenticated_object_dispatch_fails_closed_for_every_pure_and_storage_branch() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF2);
    let signing_key = dev_signing_key(0xB2);
    let sender: Address = dev_sender_address(&signing_key);

    // `expect_zero_object_io`: true only for manifest entries rejected by
    // the pure, zero-I/O `validate_object_entries` stage, before
    // `load_and_authorize_objects` ever calls `get_object_head`.
    type DispatchCase = (
        &'static str,
        Box<dyn Fn() -> (ScriptedDurableStore, AccessManifest, NodeCoreError)>,
        bool,
    );

    fn current_head_with_owner_projection(
        head: DurableObjectHead,
        owner_projection: DurableObjectOwnerProjection,
    ) -> DurableObjectHead {
        match head {
            DurableObjectHead::Current {
                head_revision,
                object_version,
                digest,
                routing_projection,
                ..
            } => DurableObjectHead::Current {
                head_revision,
                object_version,
                digest,
                owner_projection,
                routing_projection,
            },
            other => panic!("expected current head, got {other:?}"),
        }
    }

    let cases: Vec<DispatchCase> = vec![
        (
            "write mode unsupported",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_ref = sample_object_ref(0x41);
                let object_id = object_ref.id;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Write,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectAccessModeUnsupported {
                        object_id,
                        mode: AccessMode::Write,
                    },
                )
            }),
            true,
        ),
        (
            "consume mode unsupported",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_ref = sample_object_ref(0x4A);
                let object_id = object_ref.id;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Consume,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectAccessModeUnsupported {
                        object_id,
                        mode: AccessMode::Consume,
                    },
                )
            }),
            true,
        ),
        (
            "absent object",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x42; 32]);
                store.preload_object(object_id, DurableObjectHead::Absent, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: sample_object_ref(0x42),
                    mode: AccessMode::Read,
                }]);
                (store, manifest, NodeCoreError::ObjectNotFound { object_id })
            }),
            false,
        ),
        (
            "tombstoned object",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x48; 32]);
                store.preload_object(
                    object_id,
                    DurableObjectHead::Tombstoned {
                        head_revision: runtime::ObjectHeadRevision::FIRST,
                        last_object_version: DurableObjectVersion::FIRST,
                    },
                    None,
                );
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: sample_object_ref(0x48),
                    mode: AccessMode::Read,
                }]);
                (store, manifest, NodeCoreError::ObjectNotFound { object_id })
            }),
            false,
        ),
        (
            "object version mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x49; 32]);
                let (mut object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x49,
                );
                object_ref.version = 2;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectVersionMismatch {
                        object_id,
                        expected: 2,
                        actual: 1,
                    },
                )
            }),
            false,
        ),
        (
            "object digest mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4B; 32]);
                let (mut object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x4B,
                );
                let actual_digest = object_ref.digest;
                let wrong_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xFE; 32]);
                object_ref.digest = wrong_digest;
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectDigestMismatch {
                        object_id,
                        expected: wrong_digest,
                        actual: actual_digest,
                    },
                )
            }),
            false,
        ),
        (
            "owner mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x43; 32]);
                let (object_ref, _head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(Address::new([0xEE; 32])),
                    0x43,
                );
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "shared owner rejected",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4C; 32]);
                let (object_ref, _head) =
                    preload_inline_object(&store, "sunrise-test", object_id, Owner::Shared, 0x4C);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                )
            }),
            false,
        ),
        (
            "system owner rejected",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4D; 32]);
                let (object_ref, _head) =
                    preload_inline_object(&store, "sunrise-test", object_id, Owner::System, 0x4D);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectOwnerKindUnsupported { object_id },
                )
            }),
            false,
        ),
        (
            "blob payload missing from blob store",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x44; 32]);
                let record_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]);
                let blob_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha3_256, [0x46; 32]);
                let blob_record: DurableObjectVersionRecord =
                    DurableObjectVersionRecord::from_blob_reference(
                        object_id,
                        DurableObjectVersion::FIRST,
                        record_digest,
                        1,
                        DurableObjectProvenance::new(
                            ChainId::new("sunrise-test").unwrap(),
                            ProtocolVersion::new(3),
                        ),
                        1,
                        blob_digest,
                    );
                let blob_head: DurableObjectHead = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest: record_digest,
                    owner_projection: DurableObjectOwnerProjection::default(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, blob_head, Some(blob_record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest: record_digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBlobMissing {
                        object_id,
                        blob_digest,
                    },
                )
            }),
            false,
        ),
        (
            "missing version record",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4E; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x4E);
                let (_, digest) = hashed_object_version(object, "sunrise-test", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMissing { object_id },
                )
            }),
            false,
        ),
        (
            "record identity disagrees with owner projection",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x47; 32]);
                let (object_ref, head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x47,
                );
                let corrupt_head = current_head_with_owner_projection(
                    head,
                    DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(
                        [0xEF; 32],
                    )))
                    .unwrap(),
                );
                store.preload_object(object_id, corrupt_head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "absent owner projection",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x4F; 32]);
                let (object_ref, head) = preload_inline_object(
                    &store,
                    "sunrise-test",
                    object_id,
                    Owner::Address(sender),
                    0x4F,
                );
                let corrupt_head = current_head_with_owner_projection(
                    head,
                    DurableObjectOwnerProjection::default(),
                );
                store.preload_object(object_id, corrupt_head, None);
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref,
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectRecordMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "object body substitution",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x61; 32]);
                let genuine_object = test_object(object_id, 1, Owner::Address(sender), 0x61);
                let (_, digest) = hashed_object_version(genuine_object.clone(), "sunrise-test", 1);
                let mut substituted_object = genuine_object;
                substituted_object.data = vec![0xFF; 4];
                let provenance = DurableObjectProvenance::new(
                    ChainId::new("sunrise-test").unwrap(),
                    ProtocolVersion::new(3),
                );
                let tampered_record = DurableObjectVersionRecord::from_inline_object(
                    substituted_object,
                    digest,
                    provenance,
                    1,
                )
                .unwrap();
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(tampered_record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBodyDigestMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "object provenance chain mismatch",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x64; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x64);
                let (record, digest) = hashed_object_version(object, "sunrise-other-chain", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectProvenanceMismatch { object_id },
                )
            }),
            false,
        ),
        (
            "unsupported digest algorithm",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x65; 32]);
                let object = test_object(object_id, 1, Owner::Address(sender), 0x65);
                let digest = Digest32::new(HashAlgorithmId::Blake3_256, [0x66; 32]);
                let provenance = DurableObjectProvenance::new(
                    ChainId::new("sunrise-test").unwrap(),
                    ProtocolVersion::new(3),
                );
                let record =
                    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, 1)
                        .unwrap();
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectDigestUnverifiable {
                        object_id,
                        algorithm: HashAlgorithmId::Blake3_256,
                    },
                )
            }),
            false,
        ),
        (
            "object body over per-object bound",
            Box::new(move || {
                let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
                let object_id = ObjectId::new([0x67; 32]);
                let mut object = test_object(object_id, 1, Owner::Address(sender), 0x67);
                object.data = Vec::new();
                let empty_length = encode_object(&object).unwrap().len();
                object.data = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1 - empty_length];
                let body_length = encode_object(&object).unwrap().len();
                let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
                let head = DurableObjectHead::Current {
                    head_revision: runtime::ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest,
                    owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                        sender,
                    ))
                    .unwrap(),
                    routing_projection: DurableObjectRoutingProjection::default(),
                };
                store.preload_object(object_id, head, Some(record));
                let manifest = manifest_with(vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: object_id,
                        version: 1,
                        digest,
                    },
                    mode: AccessMode::Read,
                }]);
                (
                    store,
                    manifest,
                    NodeCoreError::ObjectBodyTooLarge {
                        object_id,
                        actual: body_length,
                        maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                    },
                )
            }),
            false,
        ),
    ];

    for (index, (name, build, expect_zero_object_io)) in cases.into_iter().enumerate() {
        let (store, manifest, expected_error) = build();
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        let request_byte = 0xD2u8.wrapping_add(u8::try_from(index).unwrap());
        let error = handle_authenticated_resolved_durable_submit_transaction(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            authenticated_submission_with_manifest(
                "sunrise-test",
                request(request_byte),
                &signing_key,
                Epoch::new(7),
                0,
                manifest,
                &node_config,
                &protocol_config,
            ),
            &machine,
        )
        .unwrap_err();
        assert_eq!(error, expected_error, "case: {name}");
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0, "case: {name}");
        if expect_zero_object_io {
            assert_eq!(store.state_reads.load(Ordering::SeqCst), 0, "case: {name}");
            assert_eq!(
                store.object_head_reads.load(Ordering::SeqCst),
                0,
                "case: {name}"
            );
        }
    }
}

/// A signed read-only access naming a blob-backed object is fetched from
/// the supplied `BlobStore`, independently verified, decoded, and
/// committed exactly like an inline object.
#[test]
fn authenticated_read_only_blob_reference_is_fetched_verified_and_commits() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB0);
    let signing_key = dev_signing_key(0xB0);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x70; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x70,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB0),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(blob_store.get_calls(), 1);
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert!(object_changes.mutations().is_empty());
    assert_eq!(
        object_changes.reads(),
        &[runtime::DurableObjectHeadRead::new(object_id, head)]
    );
    let _ = blob_digest;
}

/// A declared `Write` access may read a blob-backed previous version: the
/// owned-effects entrypoint fetches and verifies it exactly like the
/// read-only entrypoint. The new immutable version it commits here is an
/// ordinary small body (well under `MAX_INLINE_OBJECT_BODY_BYTES`, like
/// every devnet asset account), so it stays inline and zero blobs are
/// published for it — reading a blob-backed previous version never by
/// itself forces the next version to also be blob-backed. The
/// preinstalled-WASM entrypoint shares the identical
/// `load_and_authorize_objects` loader and is not separately exercised
/// here.
#[test]
fn authenticated_owned_write_is_blocked_by_a_held_fastpath_object_lock() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB6);
    let signing_key = dev_signing_key(0xB6);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x76; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x76,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: object_ref.clone(),
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB6),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x77],
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    // An in-flight fast-path prepare, for a different original request id,
    // already holds an exclusive lock on this exact object.
    let chain_id: ChainId = ChainId::new("sunrise-test").unwrap();
    let lock_key: Vec<u8> = local_instance_state::fastpath_lock_key(&chain_id, object_id).unwrap();
    let lock: local_instance_state::FastPathLockRecord = local_instance_state::FastPathLockRecord {
        request_id: [0x11; 32],
        object: object_ref,
        locked_epoch: Epoch::new(7),
    };
    store.preload(
        lock_key,
        StateRevision::INITIAL.checked_next().unwrap(),
        local_instance_state::encode_fastpath_lock_record(&lock).unwrap(),
    );

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        NodeCoreError::PersistenceInvariant("object locked by a pending fast-path certificate")
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// DR-0132 §3.D: the same shared object-lock boundary the test above
/// exercises, but with the pre-existing lock stamped a strictly older epoch
/// than the fenced current epoch: this is stale (the transition that would
/// have consumed it can never reach `apply` again, DR-0132's fenced-epoch
/// proof), so the owned-effects `SubmitTransaction` entrypoint proceeds and
/// reclaims it by emitting a `Delete` for it in the same commit as this
/// request's own effect mutations, instead of failing closed.
#[test]
fn authenticated_owned_write_reclaims_a_stale_fastpath_object_lock() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB7);
    let signing_key = dev_signing_key(0xB7);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x77; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x77,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: object_ref.clone(),
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB7),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x78],
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    // A lock stamped epoch 6, strictly older than the fenced current epoch
    // 7: stale, and lazily reclaimable rather than blocking.
    let chain_id: ChainId = ChainId::new("sunrise-test").unwrap();
    let lock_key: Vec<u8> = local_instance_state::fastpath_lock_key(&chain_id, object_id).unwrap();
    let lock: local_instance_state::FastPathLockRecord = local_instance_state::FastPathLockRecord {
        request_id: [0x11; 32],
        object: object_ref,
        locked_epoch: Epoch::new(6),
    };
    store.preload(
        lock_key.clone(),
        StateRevision::INITIAL.checked_next().unwrap(),
        local_instance_state::encode_fastpath_lock_record(&lock).unwrap(),
    );

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let commits = store.commits.lock().unwrap();
    let state = commits[0].state().expect("effect mutations were committed");
    assert!(
        state
            .mutations()
            .iter()
            .any(|entry| entry.key() == lock_key.as_slice()
                && matches!(entry.mutation(), StateMutation::Delete)),
        "the stale lock must be deleted in the same commit as this request's own mutations"
    );
}

/// DR-0131 criterion 4: the owned-effects `SubmitTransaction` entrypoint
/// rejects a request bound to a non-current epoch before any lock, machine
/// execution, or mutation -- the same shared boundary the held-lock test
/// above exercises, but for the epoch fence rather than the object-lock
/// fence.
#[test]
fn authenticated_owned_write_rejects_a_wrong_current_epoch() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB8);
    let signing_key = dev_signing_key(0xB8);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x79; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x79,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x7A],
        calls: AtomicUsize::new(0),
    };
    // Overrides the store's own default (Epoch::new(7)) installed by
    // `ScriptedDurableStore::new`, simulating a Slice-2 transition this DR
    // does not implement.
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(8));

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        NodeCoreError::EpochMismatch { expected, actual }
            if expected == Epoch::new(8) && actual == Epoch::new(7)
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn authenticated_owned_write_updates_blob_backed_previous_version_stays_inline_when_small() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB1);
    let signing_key = dev_signing_key(0xB1);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x71; 32]);
    let (object_ref, _head, _blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x71,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB1),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x72],
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        blob_store.get_calls(),
        1,
        "the blob-backed previous version is still fetched"
    );
    assert_eq!(
        blob_store.put_calls(),
        0,
        "a body at or under the threshold must publish nothing"
    );
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert_eq!(object_changes.mutations().len(), 1);
    match object_changes.mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => {
            assert!(matches!(version.payload(), DurableObjectPayload::Inline(_)));
            assert_eq!(version.object_version().get(), 2);
            assert_eq!(committed_object(version, &blob_store).data, vec![0x72]);
        }
        other => panic!("expected an inline Update mutation, got {other:?}"),
    }
}

/// A new version whose canonical bytes exceed `MAX_INLINE_OBJECT_BODY_BYTES`
/// is published to the supplied `BlobStore` and stored as a
/// `BlobReference` keyed under its own object digest, unlike the small
/// body proven inline above.
#[test]
fn authenticated_owned_write_large_update_publishes_and_references_blob() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x75; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x75,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let large_body = vec![0x76; MAX_INLINE_OBJECT_BODY_BYTES + 1];
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: large_body.clone(),
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        blob_store.put_calls(),
        1,
        "a body over the threshold must publish exactly once"
    );
    let commits = store.commits.lock().unwrap();
    let object_changes: &DurableObjectChanges = commits[0].object_changes();
    assert_eq!(object_changes.mutations().len(), 1);
    match object_changes.mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => {
            assert!(matches!(
                version.payload(),
                DurableObjectPayload::BlobReference(_)
            ));
            assert_eq!(version.object_version().get(), 2);
            assert_eq!(committed_object(version, &blob_store).data, large_body);
        }
        other => panic!("expected a blob-referenced Update mutation, got {other:?}"),
    }
}

/// Exact request replay returns the persisted receipt before the
/// transition, effect translation, or blob publication ever run, even for
/// an owned `Write` that would otherwise publish a new version.
#[test]
fn authenticated_owned_write_exact_replay_publishes_no_blob() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x77);
    let signing_key = dev_signing_key(0x77);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x77; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x77,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x78; MAX_INLINE_OBJECT_BODY_BYTES + 1],
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    let first_blob_store = InstrumentedBlobStore::default();
    let first_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x77),
        &signing_key,
        Epoch::new(7),
        0,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &first_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        first_submission,
        2,
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(first_blob_store.put_calls(), 1);

    // The scripted store's `commit_invocation` does not itself persist
    // the receipt for later `get_request_receipt` reads, unlike a real
    // durable adapter; wire the exact committed receipt through so the
    // second call is a genuine exact replay.
    let commits = store.commits.lock().unwrap();
    let committed_receipt = commits[0].receipt().clone();
    drop(commits);
    *store.receipt.lock().unwrap() = Some(committed_receipt);

    let replay_blob_store = InstrumentedBlobStore::default();
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x77),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &replay_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        999,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        replay_blob_store.put_calls(),
        0,
        "exact replay must publish no blob"
    );
    assert_eq!(
        replay_blob_store.get_calls(),
        0,
        "exact replay must return before any blob-store I/O"
    );
}

/// A `BlobStore::put_blob` failure while publishing a new version aborts
/// the request before `commit_invocation` is ever called: zero
/// state/receipt/nonce/outbox/object changes, distinct from a later
/// commit-time rejection.
#[test]
fn authenticated_owned_write_blob_publish_failure_aborts_before_commit() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    blob_store.fail_put_with(RuntimeError::DurableStoreUnavailable);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x78);
    let signing_key = dev_signing_key(0x78);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x78; 32]);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x78,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x78),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0x79; MAX_INLINE_OBJECT_BODY_BYTES + 1],
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBlobPublishFailed {
            object_id: id,
            source: RuntimeError::DurableStoreUnavailable,
            ..
        } if id == object_id
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(blob_store.put_calls(), 1);
    assert!(
        store.commits.lock().unwrap().is_empty(),
        "a publish failure must never reach commit_invocation"
    );
    assert!(store.receipt.lock().unwrap().is_none());
}

/// A later `commit_invocation` rejection (e.g. a concurrent object head
/// conflict) can only ever leave an already-published blob as an
/// unreachable content-addressed orphan: the blob was published before
/// the rejected commit attempt and remains directly readable from the
/// `BlobStore`, but no head or receipt ever came to reference it.
#[test]
fn authenticated_owned_write_commit_rejection_leaves_only_an_orphan_blob() {
    let object_id = ObjectId::new([0x7A; 32]);
    let conflict = DurableCommitRejection::ObjectConflict {
        object_id,
        current: runtime::DurableObjectHeadSummary::Absent,
    };
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(conflict));
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0x7A);
    let signing_key = dev_signing_key(0x7A);
    let sender: Address = dev_sender_address(&signing_key);
    let (object_ref, _head) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7A,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0x7A),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let large_body = vec![0x7B; MAX_INLINE_OBJECT_BODY_BYTES + 1];
    let machine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: large_body.clone(),
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        2,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectConflict { object_id });
    // `commit_invocation` was attempted (and scripted to reject),
    // strictly after the blob was already published.
    assert_eq!(blob_store.put_calls(), 1);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let version = match commits[0].object_changes().mutations()[0].mutation() {
        runtime::DurableObjectMutation::Update { version, .. } => version.clone(),
        other => panic!("expected an Update mutation, got {other:?}"),
    };
    drop(commits);
    assert!(matches!(
        version.payload(),
        DurableObjectPayload::BlobReference(_)
    ));
    assert_eq!(
        committed_object(&version, &blob_store).data,
        large_body,
        "the orphaned blob remains directly readable from the BlobStore"
    );
}

/// A [`RuntimeError`] surfaced by the supplied `BlobStore` is a typed
/// runtime/storage error, not silently treated as a missing blob.
#[test]
fn authenticated_object_dispatch_blob_store_runtime_error_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    blob_store.fail_with(RuntimeError::DurableStoreUnavailable);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB2);
    let signing_key = dev_signing_key(0xB2);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x73; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x73,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB2),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::Runtime(RuntimeError::DurableStoreUnavailable)
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A blob digest absent from the supplied `BlobStore` is a distinct typed
/// missing-blob error.
#[test]
fn authenticated_object_dispatch_missing_blob_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB3);
    let signing_key = dev_signing_key(0xB3);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x74; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x74,
    );
    // The record/head are preloaded, but the blob content itself is
    // never inserted into `blob_store`.
    let _ = head;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB3),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let empty_blob_store = InstrumentedBlobStore::default();

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &empty_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBlobMissing {
            object_id,
            blob_digest,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// Fetched blob bytes are bounded at the same per-object limit as an
/// inline body before either digest is verified or the body is decoded:
/// oversized bytes that are also not a valid canonical `Object` still
/// reject as `ObjectBodyTooLarge`, never a decode error, proving the
/// bound runs first.
#[test]
fn authenticated_object_dispatch_oversized_blob_rejects_before_hashing_or_decode() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB4);
    let signing_key = dev_signing_key(0xB4);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x75; 32]);
    // Deliberately malformed (not a canonical `Object` encoding) so a
    // check that ran hashing or decoding first would fail differently.
    let oversized_bytes: Vec<u8> = vec![0xAB; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1];
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let blob_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x75; 32]);
    blob_store.insert(blob_digest, oversized_bytes);
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x76; 32]);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        record_digest,
        0,
        provenance,
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: record_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: record_digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB4),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        }
    );
    assert_eq!(blob_store.get_calls(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// A blob whose fetched bytes do not hash to their own claimed
/// `blob_digest` is a distinct typed corruption from
/// `ObjectBodyDigestMismatch`, and is caught before `objects::decode_object`
/// ever runs (the substituted bytes below are not a valid canonical
/// `Object` encoding either).
#[test]
fn authenticated_object_dispatch_blob_digest_mismatch_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x77; 32]);
    let (object_ref, head, blob_digest) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x77,
    );
    // Substitute the stored bytes for something that does not hash to
    // the payload's own claimed `blob_digest`.
    blob_store.insert(blob_digest, vec![0xEE; 16]);
    let _ = head;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectBlobDigestMismatch {
            object_id,
            blob_digest,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Fetched blob bytes that are not a valid canonical `Object` encoding,
/// but do hash to their own claimed `blob_digest`, fail closed as a
/// typed `DurableInvocation` decode error rather than panicking.
#[test]
fn authenticated_object_dispatch_malformed_blob_bytes_fail_decode() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB6);
    let signing_key = dev_signing_key(0xB6);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x78; 32]);
    let garbage: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44];
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let blob_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(HashPurpose::Object, protocol_version, &chain_id, &garbage)
        .unwrap();
    blob_store.insert(blob_digest, garbage);
    let record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]);
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        record_digest,
        0,
        provenance,
        1,
        blob_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: record_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: record_digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB6),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert!(
        matches!(error, NodeCoreError::DurableInvocation(_)),
        "expected a typed decode error, got {error:?}"
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// A blob whose decoded object identity disagrees with the signed
/// reference is corruption distinct from a digest mismatch, exactly like
/// the existing inline record-mismatch checks.
#[test]
fn authenticated_object_dispatch_blob_identity_mismatch_is_typed() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB7);
    let signing_key = dev_signing_key(0xB7);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7A; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7A,
    );
    // Overwrite the stored blob with a validly encoded but differently
    // identified object, still hashing to the same `blob_digest` value
    // is not possible; instead this proves the identity cross-check
    // fires once the (different) content is legitimately fetched and
    // decoded under its own consistent digest.
    let substituted_object =
        test_object(ObjectId::new([0x7B; 32]), 1, Owner::Address(sender), 0x7A);
    let substituted_bytes = encode_object(&substituted_object).unwrap();
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let substituted_digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &substituted_bytes,
        )
        .unwrap();
    // Re-preload the head/version so the record's own `digest` and
    // `blob_digest` both consistently name the substituted content,
    // isolating the identity check from the earlier digest checks.
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::FIRST,
        substituted_digest,
        substituted_object.schema_version,
        provenance,
        1,
        substituted_digest,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest: substituted_digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    blob_store.insert(substituted_digest, substituted_bytes);
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: substituted_digest,
        },
        mode: AccessMode::Read,
    }]);
    let _ = object_ref;
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB7),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectRecordMismatch { object_id });
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Focused corruption cases exercised only after a blob is successfully
/// fetched and its own `blob_digest` independently verifies, proving each
/// later independent check still fails closed: the record's own `digest`
/// re-verified against the same fetched bytes (distinct from the earlier
/// `blob_digest` check), the decoded object's `version` disagreeing with
/// the signed reference, the decoded object's `schema_version`
/// disagreeing with the row, and an unsupported `blob_digest` algorithm.
#[test]
fn authenticated_object_dispatch_blob_specific_corruption_cases_fail_closed() {
    struct Case {
        name: &'static str,
        object: Object,
        store_blob: bool,
        blob_digest: fn(&[u8]) -> Digest32,
        /// `None` means "compute correctly from the encoded bytes".
        record_digest: Option<Digest32>,
        record_schema_version: Option<u32>,
        declared_version: u64,
        expected_error: fn(ObjectId) -> NodeCoreError,
    }

    fn correct_digest(bytes: &[u8]) -> Digest32 {
        BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
            .hash(
                HashPurpose::Object,
                ProtocolVersion::new(3),
                &ChainId::new("sunrise-test").unwrap(),
                bytes,
            )
            .unwrap()
    }

    fn unsupported_algorithm_digest(_bytes: &[u8]) -> Digest32 {
        Digest32::new(HashAlgorithmId::Blake3_256, [0x11; 32])
    }

    let sender: Address = dev_sender_address(&dev_signing_key(0xC1));
    let cases = [
        Case {
            name: "record digest mismatch after a valid blob_digest",
            object: test_object(ObjectId::new([0x81; 32]), 1, Owner::Address(sender), 0x81),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: Some(Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32])),
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectBodyDigestMismatch { object_id },
        },
        Case {
            name: "decoded object version mismatch",
            object: test_object(ObjectId::new([0x82; 32]), 2, Owner::Address(sender), 0x82),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: None,
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectRecordMismatch { object_id },
        },
        Case {
            name: "decoded object schema mismatch",
            object: test_object(ObjectId::new([0x83; 32]), 1, Owner::Address(sender), 0x83),
            store_blob: true,
            blob_digest: correct_digest,
            record_digest: None,
            record_schema_version: Some(0xFFFF_FFFF),
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectRecordMismatch { object_id },
        },
        Case {
            name: "unsupported blob_digest algorithm fails closed",
            object: test_object(ObjectId::new([0x84; 32]), 1, Owner::Address(sender), 0x84),
            store_blob: true,
            blob_digest: unsupported_algorithm_digest,
            record_digest: None,
            record_schema_version: None,
            declared_version: 1,
            expected_error: |object_id| NodeCoreError::ObjectDigestUnverifiable {
                object_id,
                algorithm: HashAlgorithmId::Blake3_256,
            },
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let object_id = case.object.id;
        let encoded_bytes = encode_object(&case.object).unwrap();
        let blob_digest = (case.blob_digest)(&encoded_bytes);
        let record_digest = case
            .record_digest
            .unwrap_or_else(|| correct_digest(&encoded_bytes));
        let schema_version = case
            .record_schema_version
            .unwrap_or(case.object.schema_version);

        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let blob_store = InstrumentedBlobStore::default();
        if case.store_blob {
            blob_store.insert(blob_digest, encoded_bytes);
        }
        let provenance = DurableObjectProvenance::new(
            ChainId::new("sunrise-test").unwrap(),
            ProtocolVersion::new(3),
        );
        let record = DurableObjectVersionRecord::from_blob_reference(
            object_id,
            DurableObjectVersion::FIRST,
            record_digest,
            schema_version,
            provenance,
            1,
            blob_digest,
        );
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest: record_digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        let manifest = manifest_with(vec![AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: case.declared_version,
                digest: record_digest,
            },
            mode: AccessMode::Read,
        }]);
        let signing_key = dev_signing_key(0xC1);
        let node_config = config("sunrise-test");
        let protocol_config = active_protocol_config(0xC1);
        let submission = authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xC1u8.wrapping_add(u8::try_from(index).unwrap())),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        );
        let machine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };

        let error = handle_authenticated_resolved_durable_submit_transaction(
            &blob_store,
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            &machine,
        )
        .unwrap_err();

        assert_eq!(
            error,
            (case.expected_error)(object_id),
            "case: {}",
            case.name
        );
        assert_eq!(
            machine.calls.load(Ordering::SeqCst),
            0,
            "case: {}",
            case.name
        );
    }
}

/// The version record's stored chain provenance is checked from the
/// record header alone, before any blob-store I/O: a cross-chain
/// blob-backed record rejects without ever calling `get_blob`.
#[test]
fn authenticated_object_dispatch_provenance_mismatch_rejects_before_blob_fetch() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB8);
    let signing_key = dev_signing_key(0xB8);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7C; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &blob_store,
        "sunrise-other-chain",
        object_id,
        Owner::Address(sender),
        0x7C,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectProvenanceMismatch { object_id });
    assert_eq!(
        blob_store.get_calls(),
        0,
        "provenance mismatch must reject before any blob-store I/O"
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

/// Exact request replay returns the persisted receipt before any
/// `BlobStore` I/O, even when the replayed request's own manifest names a
/// blob-backed object.
#[test]
fn exact_replay_returns_before_blob_store_io() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let first_blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xB9);
    let signing_key = dev_signing_key(0xB9);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id = ObjectId::new([0x7D; 32]);
    let (object_ref, ..) = preload_blob_object(
        &store,
        &first_blob_store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x7D,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let first_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &first_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        first_submission,
        &machine,
    )
    .unwrap();
    assert_eq!(first_blob_store.get_calls(), 1);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);

    // The scripted store's `commit_invocation` does not itself persist
    // the receipt for later `get_request_receipt` reads, unlike a real
    // durable adapter; wire the exact committed receipt through so the
    // second call is a genuine exact replay.
    let commits = store.commits.lock().unwrap();
    let committed_receipt = commits[0].receipt().clone();
    drop(commits);
    *store.receipt.lock().unwrap() = Some(committed_receipt);

    let replay_blob_store = InstrumentedBlobStore::default();
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xB9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    handle_authenticated_resolved_durable_submit_transaction(
        &replay_blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        replay_blob_store.get_calls(),
        0,
        "exact replay must return before any blob-store I/O"
    );
    assert_eq!(store.object_head_reads.load(Ordering::SeqCst), 1);
}

/// The aggregate 8 MiB inline/blob body budget is shared: an inline body
/// and a blob-fetched body count against the same running total, and the
/// bound rejects before the transition runs regardless of which entry
/// pushed it over.
#[test]
fn mixed_inline_and_blob_bodies_share_the_aggregate_bound() {
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let blob_store = InstrumentedBlobStore::default();
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xBA);
    let signing_key = dev_signing_key(0xBA);
    let sender: Address = dev_sender_address(&signing_key);
    const PER_OBJECT_BYTES: usize = 300_000;
    const _: () = assert!(PER_OBJECT_BYTES < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
    // 30 objects at 300,000 bytes each is 9,000,000 bytes, safely over
    // the 8 MiB aggregate bound while each individual body stays under
    // the 1 MiB per-object bound and the 32-entry manifest bound.
    const OBJECT_COUNT: usize = 30;
    const _: () = assert!(OBJECT_COUNT <= MAX_AUTHENTICATED_OBJECT_READS);
    const _: () =
        assert!(OBJECT_COUNT * PER_OBJECT_BYTES > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES);
    let mut entries: Vec<AccessEntry> = Vec::with_capacity(OBJECT_COUNT);
    for index in 0..OBJECT_COUNT {
        let byte = u8::try_from(index).unwrap();
        let object_id = ObjectId::new([byte; 32]);
        if index % 2 == 0 {
            let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
            object.data = Vec::new();
            let empty_length = encode_object(&object).unwrap().len();
            object.data = vec![0; PER_OBJECT_BYTES - empty_length];
            let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
            let head = DurableObjectHead::Current {
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            };
            store.preload_object(object_id, head, Some(record));
            entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: object_id,
                    version: 1,
                    digest,
                },
                mode: AccessMode::Read,
            });
        } else {
            let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
            object.data = Vec::new();
            let empty_length = encode_object(&object).unwrap().len();
            object.data = vec![0; PER_OBJECT_BYTES - empty_length];
            let canonical_bytes = encode_object(&object).unwrap();
            let chain_id = ChainId::new("sunrise-test").unwrap();
            let protocol_version = ProtocolVersion::new(3);
            let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
                .hash(
                    HashPurpose::Object,
                    protocol_version,
                    &chain_id,
                    &canonical_bytes,
                )
                .unwrap();
            blob_store.insert(digest, canonical_bytes);
            let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
            let record = DurableObjectVersionRecord::from_blob_reference(
                object_id,
                DurableObjectVersion::FIRST,
                digest,
                object.schema_version,
                provenance,
                1,
                digest,
            );
            let head = DurableObjectHead::Current {
                head_revision: runtime::ObjectHeadRevision::FIRST,
                object_version: DurableObjectVersion::FIRST,
                digest,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            };
            store.preload_object(object_id, head, Some(record));
            entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: object_id,
                    version: 1,
                    digest,
                },
                mode: AccessMode::Read,
            });
        }
    }
    let manifest = manifest_with(entries);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &blob_store,
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xBA),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            ..
        }
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// An object created under a different protocol version than the current
/// event still verifies, because node-core recomputes with the record's
/// own stored provenance and never with the reader's epoch-selected hash
/// suite. This is the regression test that forbids reintroducing
/// `HashSuiteResolver`-based digest recomputation.
#[test]
fn object_created_under_an_older_protocol_version_still_verifies() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF5);
    let signing_key = dev_signing_key(0xB5);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x62; 32]);
    let object = test_object(object_id, 1, Owner::Address(sender), 0x62);
    let (record, digest) = hashed_object_version_with_protocol_version(
        object,
        "sunrise-test",
        ProtocolVersion::new(2),
        1,
    );
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE1),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.commits.lock().unwrap().len(), 1);
}

/// A stored digest whose algorithm differs from the reader's active epoch
/// suite still verifies, because the algorithm comes from the
/// self-describing stored digest, not the epoch suite.
#[test]
fn object_digest_algorithm_differing_from_reader_epoch_suite_still_verifies() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF6);
    let signing_key = dev_signing_key(0xB6);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id = ObjectId::new([0x63; 32]);
    let object = test_object(object_id, 1, Owner::Address(sender), 0x63);
    let canonical_bytes = encode_object(&object).unwrap();
    let chain_id = ChainId::new("sunrise-test").unwrap();
    let protocol_version = ProtocolVersion::new(3);
    let digest = BuiltinHashFunction::new(HashAlgorithmId::Sha3_256)
        .hash(
            HashPurpose::Object,
            protocol_version,
            &chain_id,
            &canonical_bytes,
        )
        .unwrap();
    let provenance = DurableObjectProvenance::new(chain_id, protocol_version);
    let record =
        DurableObjectVersionRecord::from_inline_object(object, digest, provenance, 1).unwrap();
    let head = DurableObjectHead::Current {
        head_revision: runtime::ObjectHeadRevision::FIRST,
        object_version: DurableObjectVersion::FIRST,
        digest,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    store.preload_object(object_id, head, Some(record));
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE2),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap();
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
}

/// 32 entries individually under the per-object bound whose sum crosses
/// the aggregate bound are rejected without ever reaching the transition.
#[test]
fn object_bodies_over_aggregate_bound_reject_before_transition_or_commit() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xFA);
    let signing_key = dev_signing_key(0xBA);
    let sender: Address = dev_sender_address(&signing_key);
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    const PER_OBJECT_BYTES: usize = 300_000;
    const _: () = assert!(PER_OBJECT_BYTES < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
    const _: () = assert!(
        MAX_AUTHENTICATED_OBJECT_READS * PER_OBJECT_BYTES
            > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES
    );
    let mut entries: Vec<AccessEntry> = Vec::with_capacity(MAX_AUTHENTICATED_OBJECT_READS);
    for index in 0..MAX_AUTHENTICATED_OBJECT_READS {
        let byte = u8::try_from(index).unwrap();
        let object_id = ObjectId::new([byte; 32]);
        let mut object = test_object(object_id, 1, Owner::Address(sender), byte);
        object.data = Vec::new();
        let empty_length = encode_object(&object).unwrap().len();
        object.data = vec![0; PER_OBJECT_BYTES - empty_length];
        let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
        let head = DurableObjectHead::Current {
            head_revision: runtime::ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender))
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        store.preload_object(object_id, head, Some(record));
        entries.push(AccessEntry {
            object_ref: ObjectRef {
                id: object_id,
                version: 1,
                digest,
            },
            mode: AccessMode::Read,
        });
    }
    let manifest = manifest_with(entries);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        authenticated_submission_with_manifest(
            "sunrise-test",
            request(0xE6),
            &signing_key,
            Epoch::new(7),
            0,
            manifest,
            &node_config,
            &protocol_config,
        ),
        &machine,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        NodeCoreError::ObjectBodyTooLarge {
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            ..
        }
    ));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn receipt_and_nonce_short_circuit_before_authenticated_object_reads() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF3);
    let signing_key = dev_signing_key(0xB3);
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: sample_object_ref(0x51),
        mode: AccessMode::Read,
    }]);
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let stale_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let stale_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD7),
        &signing_key,
        Epoch::new(7),
        1,
        manifest.clone(),
        &node_config,
        &protocol_config,
    );
    assert!(matches!(
        handle_authenticated_resolved_durable_submit_transaction(
            &MemoryBlobStore::default(),
            &stale_store,
            &durable_context(),
            &resolver("sunrise-test"),
            stale_submission,
            &machine,
        ),
        Err(NodeCoreError::SenderNonceMismatch { .. })
    ));
    assert_eq!(stale_store.object_head_reads.load(Ordering::SeqCst), 0);

    let replay_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let replay_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let event_digest: Digest32 = replay_submission
        .event()
        .digest(&resolver("sunrise-test"))
        .unwrap();
    let response: NodeResponse = NodeResponse::new(
        replay_submission.event().request_id(),
        NodeResponseStatus::Accepted,
        None,
    )
    .unwrap();
    let record: NodeDedupRecord = NodeDedupRecord::new(
        replay_submission.event().request_id(),
        event_digest,
        vec![response],
    )
    .unwrap();
    replay_store.receipt.lock().unwrap().replace(
        DurableRequestReceipt::new(
            DurableRequestId::new(*replay_submission.event().request_id().as_bytes()).unwrap(),
            event_digest,
            record.encode().unwrap(),
        )
        .unwrap(),
    );
    let replay = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &replay_store,
        &durable_context(),
        &resolver("sunrise-test"),
        replay_submission,
        &machine,
    )
    .unwrap();
    assert_eq!(replay.output().responses().len(), 1);
    assert_eq!(replay_store.state_reads.load(Ordering::SeqCst), 0);
    assert_eq!(replay_store.object_head_reads.load(Ordering::SeqCst), 0);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn authenticated_object_head_conflict_is_retryable_and_distinct() {
    let object_id: ObjectId = ObjectId::new([0x61; 32]);
    let conflict = DurableCommitRejection::ObjectConflict {
        object_id,
        current: runtime::DurableObjectHeadSummary::Absent,
    };
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Rejected(conflict));
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF4);
    let signing_key = dev_signing_key(0xB4);
    let sender: Address = dev_sender_address(&signing_key);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x61,
    );
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xD9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::ObjectConflict { object_id });
    assert_eq!(store.commits.lock().unwrap().len(), 1);
    assert!(store.receipt.lock().unwrap().is_none());
}

/// Commits an object directly against a real [`MemoryDurableStateStore`]
/// (bypassing node-core, which does not implement object writes), then
/// authorizes and commits a non-empty read-only manifest referencing it
/// through the full authenticated submit-transaction path.
#[test]
fn memory_store_authenticated_read_only_manifest_commits_against_real_object_store() {
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF7);
    let signing_key = dev_signing_key(0xC7);
    let sender: Address = dev_sender_address(&signing_key);
    let context = durable_context();
    let resolver = resolver("sunrise-test");
    let object_domain = domain(0xF7);
    let store: MemoryDurableStateStore = memory_store_with_fastpath_epoch(object_domain);
    store.set_time(100);
    let object_id = ObjectId::new([0x81; 32]);

    let object = test_object(object_id, 1, Owner::Address(sender), 0x81);
    let (record, digest) = hashed_object_version(object, "sunrise-test", 1);
    let create_mutation = runtime::DurableObjectMutation::Create {
        version: record,
        owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let create_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            create_mutation,
        )],
    )
    .unwrap();
    let create_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x21; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        vec![0x23],
    )
    .unwrap();
    let create_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        create_changes,
        create_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, create_invocation),
        DurableCommitOutcome::Committed
    );

    let manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest,
        },
        mode: AccessMode::Read,
    }]);
    let submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE5),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };

    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        submission,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolved.domain(), object_domain);
    assert_eq!(resolved.output().responses().len(), 1);

    let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record = SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn memory_store_authenticated_owned_write_commits_atomically_and_replays_receipt() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFA);
    let signing_key: SigningKey = dev_signing_key(0xCA);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFA);
    let read_id: ObjectId = ObjectId::new([0x84; 32]);
    let write_id: ObjectId = ObjectId::new([0x94; 32]);
    let read_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(read_id, 1, Owner::Immutable, 0x84),
        "sunrise-test",
        4,
        0x31,
    );
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x94),
        "sunrise-test",
        5,
        0x34,
    );
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: write_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: read_ref,
            mode: AccessMode::Read,
        },
    ]);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE8),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(write_id, AccessMode::Write), (read_id, AccessMode::Read)],
        replacement_data: vec![0xA4],
        calls: AtomicUsize::new(0),
    };
    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(7),
    );

    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let first: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            submission,
            6,
            &machine,
        )
        .unwrap();
    let replay: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            replay_submission,
            999,
            &machine,
        )
        .unwrap();

    assert_eq!(first, replay);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    let write_v2: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            write_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(write_v2.created_checkpoint(), 6);
    assert!(
        matches!(write_v2.payload(), DurableObjectPayload::Inline(_)),
        "a body at or under the threshold must stay inline"
    );
    assert_eq!(committed_object(&write_v2, &blob_store).data, vec![0xA4]);
    let read_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, read_id)
        .unwrap();
    assert_eq!(read_head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}
