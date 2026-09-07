use super::*;
use abi::package_types::{ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id};
use abi::{AccessEntry, AccessManifest};
use execution::ResolvedObject;
use objects::{AccessMode, Object, ObjectId, ObjectRef, Owner};

fn arg(value: u8) -> ScopedTypeArg {
    ScopedTypeArg::Opaque {
        domain: 9,
        value: [value; 32],
    }
}
fn tag(seed: u8, id: u16, args: Vec<ScopedTypeArg>) -> ScopedTypeTag {
    ScopedTypeTag::new(origin(seed), id, args).unwrap()
}
fn snapshot(ty: &ScopedTypeTag, id: u8, mode: AccessMode) -> (AccessEntry, ResolvedObject) {
    let object: Object = Object {
        id: ObjectId::new([id; 32]),
        version: 1,
        owner: Owner::Shared,
        type_hash: derive_scoped_type_id(&resolver(), Epoch::new(0), ty).unwrap(),
        schema_version: 1,
        data: vec![0xff],
    };
    let entry: AccessEntry = AccessEntry {
        object_ref: ObjectRef {
            id: object.id,
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
        },
        mode,
    };
    (entry, ResolvedObject { object, mode })
}
fn manifest(entries: Vec<AccessEntry>) -> AccessManifest {
    AccessManifest { entries }
}

#[test]
fn binding_repeats_flat_arguments_and_matches_ordered_metadata() {
    let mut abi: PackageAbi = generic(1);
    abi.entrypoints[0].objects = [ObjectMode::Read, ObjectMode::Write, ObjectMode::Consume]
        .into_iter()
        .map(|mode| {
            let mut obj = object(1, vec![PatternArgument::Parameter(0)]);
            obj.mode = mode;
            obj
        })
        .collect();
    let interface = verify(abi).unwrap();
    let args: Vec<ScopedTypeArg> = vec![arg(7)];
    let bound = bind_object_signature(&interface, "run", &args).unwrap();
    assert_eq!(bound.entrypoint(), "run");
    let expected: ScopedTypeTag = tag(1, 1, vec![arg(7)]);
    for parameter in bound.objects() {
        assert_eq!(parameter.ty(), &expected);
        assert_eq!(parameter.schema(), 1);
    }
    let pairs: Vec<(AccessEntry, ResolvedObject)> =
        [AccessMode::Read, AccessMode::Write, AccessMode::Consume]
            .into_iter()
            .enumerate()
            .map(|(i, mode)| snapshot(&expected, u8::try_from(i + 1).unwrap(), mode))
            .collect();
    let access: AccessManifest = manifest(pairs.iter().map(|(entry, _)| entry.clone()).collect());
    let inputs: Vec<ResolvedObject> = pairs.into_iter().map(|(_, input)| input).collect();
    assert_eq!(
        match_object_input_metadata(&bound, &resolver(), Epoch::new(0), &access, &inputs),
        Ok(())
    );
    let mut swapped: Vec<ResolvedObject> = inputs.clone();
    swapped.swap(0, 1);
    assert!(
        match_object_input_metadata(&bound, &resolver(), Epoch::new(0), &access, &swapped).is_err()
    );
    assert!(bind_object_signature(&interface, "RUN", &args).is_err());
    assert!(bind_object_signature(&interface, &"x".repeat(257), &args).is_err());
    assert!(bind_object_signature(&interface, "run", &[]).is_err());
    assert!(bind_object_signature(&interface, "run", &[arg(1), arg(2)]).is_err());
    assert!(
        bind_object_signature(
            &interface,
            "run",
            &[ScopedTypeArg::Opaque {
                domain: 10,
                value: [7; 32]
            }]
        )
        .is_err()
    );
}

#[test]
fn metadata_mismatches_fail_and_dont_authenticate_owner_body_or_digest() {
    let interface = verify(generic(1)).unwrap();
    let bound = bind_object_signature(&interface, "run", &[arg(7)]).unwrap();
    let (entry, input) = snapshot(&tag(1, 1, vec![arg(7)]), 1, AccessMode::Write);
    let access: AccessManifest = manifest(vec![entry.clone()]);
    for change in 0..6 {
        let mut bad = input.clone();
        match change {
            0 => bad.object.id = ObjectId::new([2; 32]),
            1 => bad.object.version = 2,
            2 => bad.mode = AccessMode::Read,
            3 => bad.object.schema_version = 2,
            4 => {
                bad.object.type_hash =
                    derive_scoped_type_id(&resolver(), Epoch::new(0), &tag(1, 1, vec![arg(8)]))
                        .unwrap()
            }
            _ => {
                bad.object.type_hash =
                    derive_scoped_type_id(&resolver(), Epoch::new(0), &tag(2, 1, vec![arg(7)]))
                        .unwrap()
            }
        }
        assert!(
            match_object_input_metadata(&bound, &resolver(), Epoch::new(0), &access, &[bad])
                .is_err()
        );
    }
    let mut wrong_mode = entry.clone();
    wrong_mode.mode = AccessMode::Read;
    assert!(
        match_object_input_metadata(
            &bound,
            &resolver(),
            Epoch::new(0),
            &manifest(vec![wrong_mode]),
            std::slice::from_ref(&input)
        )
        .is_err()
    );
    assert!(
        match_object_input_metadata(
            &bound,
            &resolver(),
            Epoch::new(0),
            &AccessManifest::new(),
            std::slice::from_ref(&input)
        )
        .is_err()
    );
    assert!(match_object_input_metadata(&bound, &resolver(), Epoch::new(0), &access, &[]).is_err());
    // This helper is deliberately NOT snapshot, ownership or body authentication.
    let mut changed = input.clone();
    changed.object.owner = Owner::System;
    changed.object.data = vec![1, 2, 3];
    let mut changed_entry = entry;
    changed_entry.object_ref.digest = semantics();
    assert_eq!(
        match_object_input_metadata(
            &bound,
            &resolver(),
            Epoch::new(0),
            &manifest(vec![changed_entry]),
            &[changed]
        ),
        Ok(())
    );
}

#[test]
fn duplicate_reads_cannot_alias_bound_parameters() {
    let mut abi: PackageAbi = generic(1);
    abi.entrypoints[0].objects[0].mode = ObjectMode::Read;
    let repeated: ObjectParameter = abi.entrypoints[0].objects[0].clone();
    abi.entrypoints[0].objects.push(repeated);
    let interface = verify(abi).unwrap();
    let bound = bind_object_signature(&interface, "run", &[arg(1)]).unwrap();
    let (entry, input) = snapshot(&tag(1, 1, vec![arg(1)]), 1, AccessMode::Read);
    assert_eq!(
        match_object_input_metadata(
            &bound,
            &resolver(),
            Epoch::new(0),
            &manifest(vec![entry.clone(), entry]),
            &[input.clone(), input]
        ),
        Err(BindingError::DuplicateObject)
    );
}

fn nominal_abi() -> PackageAbi {
    let mut abi: PackageAbi = generic(1);
    abi.constructors[0].arguments = vec![ArgumentKind::Nominal];
    abi.constructors.push(ConstructorDeclaration {
        local_id: 2,
        schema: 1,
        arguments: vec![ArgumentKind::Nominal],
    });
    abi.constructors.push(ConstructorDeclaration {
        local_id: 3,
        schema: 1,
        arguments: vec![],
    });
    abi.entrypoints[0].type_parameters = vec![ArgumentKind::Nominal];
    abi
}

#[test]
fn concrete_nominal_arguments_must_resolve_even_when_unused() {
    let mut abi = nominal_abi();
    abi.entrypoints[0].objects.clear();
    let interface = verify(abi.clone()).unwrap();
    let good = ScopedTypeArg::Nominal(Box::new(tag(1, 3, vec![])));
    assert!(bind_object_signature(&interface, "run", &[good]).is_ok());
    let unknown = ScopedTypeArg::Nominal(Box::new(tag(1, 99, vec![])));
    assert!(bind_object_signature(&interface, "run", &[unknown]).is_err());
    let wrong_arity = ScopedTypeArg::Nominal(Box::new(tag(1, 2, vec![])));
    assert!(bind_object_signature(&interface, "run", &[wrong_arity]).is_err());
    let wrong_kind = ScopedTypeArg::Nominal(Box::new(tag(1, 2, vec![arg(1)])));
    assert!(bind_object_signature(&interface, "run", &[wrong_kind]).is_err());
    let leaf = candidate(generic(3), &[]);
    let middle = candidate(minimal(2), &[&leaf]);
    let root = candidate(abi.clone(), &[&middle]);
    let interface = verify_publication_interface(root, vec![middle.clone(), leaf.clone()]).unwrap();
    let transitive = ScopedTypeArg::Nominal(Box::new(tag(3, 1, vec![arg(1)])));
    assert!(bind_object_signature(&interface, "run", std::slice::from_ref(&transitive)).is_err());
    let root = candidate(abi, &[&middle, &leaf]);
    let interface = verify_publication_interface(root, vec![middle, leaf]).unwrap();
    assert!(bind_object_signature(&interface, "run", &[transitive]).is_ok());
}

#[test]
fn expansion_rechecks_depth_and_node_budgets_after_substitution() {
    let mut abi = nominal_abi();
    // Two pattern levels plus a 3-level supplied nominal tag would produce depth5.
    abi.entrypoints[0].objects[0].ty.arguments =
        vec![PatternArgument::Nominal(Box::new(TypePattern {
            origin: origin(1),
            constructor: 2,
            arguments: vec![PatternArgument::Parameter(0)],
        }))];
    let interface = verify(abi).unwrap();
    let leaf = tag(1, 3, vec![]);
    let depth2 = tag(1, 2, vec![ScopedTypeArg::Nominal(Box::new(leaf.clone()))]);
    let depth3 = tag(1, 2, vec![ScopedTypeArg::Nominal(Box::new(depth2.clone()))]);
    assert!(
        bind_object_signature(
            &interface,
            "run",
            &[ScopedTypeArg::Nominal(Box::new(depth2))]
        )
        .is_ok()
    );
    assert!(
        bind_object_signature(
            &interface,
            "run",
            &[ScopedTypeArg::Nominal(Box::new(depth3))]
        )
        .is_err()
    );
    let mut abi = nominal_abi();
    abi.constructors[0].arguments = vec![ArgumentKind::Nominal; 8];
    abi.constructors.push(ConstructorDeclaration {
        local_id: 4,
        schema: 1,
        arguments: vec![ArgumentKind::Opaque(9); 8],
    });
    abi.entrypoints[0].objects[0].ty.arguments = vec![PatternArgument::Parameter(0); 8];
    let interface = verify(abi).unwrap();
    let wide = tag(1, 4, vec![arg(1); 8]); // 9 nodes alone; expansion is 1+8*(1+9)=81.
    assert!(
        bind_object_signature(&interface, "run", &[ScopedTypeArg::Nominal(Box::new(wide))])
            .is_err()
    );
}

#[test]
fn current_trusted_hash_history_not_publication_epoch_controls_type_checks() {
    let interface = verify(generic(1)).unwrap();
    let bound = bind_object_signature(&interface, "run", &[arg(7)]).unwrap();
    let ty = tag(1, 1, vec![arg(7)]);
    let r = HashSuiteResolver::new(
        ChainId::new("test").unwrap(),
        ProtocolVersion::new(2),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(5),
                suite: HashSuite::uniform(
                    protocol_types::HashSuiteId::new(2),
                    HashAlgorithmId::Sha3_256,
                ),
            },
        ],
    )
    .unwrap();
    let (entry, mut input) = snapshot(&ty, 1, AccessMode::Write);
    let access = manifest(vec![entry]);
    assert_eq!(
        match_object_input_metadata(
            &bound,
            &r,
            Epoch::new(5),
            &access,
            std::slice::from_ref(&input)
        ),
        Ok(())
    );
    input.object.type_hash = derive_scoped_type_id(&r, Epoch::new(5), &ty).unwrap();
    assert!(
        match_object_input_metadata(
            &bound,
            &r,
            Epoch::new(0),
            &access,
            std::slice::from_ref(&input)
        )
        .is_err()
    );
    assert_eq!(
        match_object_input_metadata(
            &bound,
            &r,
            Epoch::new(5),
            &access,
            std::slice::from_ref(&input)
        ),
        Ok(())
    );
    let wrong_chain = HashSuiteResolver::new(
        ChainId::new("other").unwrap(),
        ProtocolVersion::new(2),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    assert!(
        match_object_input_metadata(&bound, &wrong_chain, Epoch::new(5), &access, &[input])
            .is_err()
    );
}

#[test]
fn aggregate_expanded_bytes_are_bounded_separately_from_each_tag() {
    let chain = ChainId::new("x".repeat(128)).unwrap();
    let key: SigningKey = SigningKey::from([7; 32]);
    let defining =
        PackageOrigin::unverified(chain.clone(), VerificationKey::from(&key).into(), [1; 32])
            .unwrap();
    let nominal = |count| vec![ArgumentKind::Nominal; count];
    let mut abi = PackageAbi {
        origin: defining.clone(),
        constructors: vec![
            ConstructorDeclaration {
                local_id: 1,
                schema: 1,
                arguments: nominal(2),
            },
            ConstructorDeclaration {
                local_id: 2,
                schema: 1,
                arguments: nominal(4),
            },
            ConstructorDeclaration {
                local_id: 3,
                schema: 1,
                arguments: vec![],
            },
            ConstructorDeclaration {
                local_id: 4,
                schema: 1,
                arguments: nominal(5),
            },
        ],
        entrypoints: vec![EntrypointDeclaration {
            name: "run".into(),
            type_parameters: nominal(1),
            objects: vec![],
        }],
    };
    let param = ObjectParameter {
        mode: ObjectMode::Read,
        schema: 1,
        ty: TypePattern {
            origin: defining.clone(),
            constructor: 1,
            arguments: vec![PatternArgument::Parameter(0); 2],
        },
    };
    abi.entrypoints[0].objects = vec![param; 32];
    let leaf = ScopedTypeTag::new(defining.clone(), 3, vec![]).unwrap();
    let branch = ScopedTypeTag::new(
        defining.clone(),
        4,
        vec![ScopedTypeArg::Nominal(Box::new(leaf.clone())); 5],
    )
    .unwrap();
    let supplied = ScopedTypeTag::new(
        defining.clone(),
        2,
        vec![
            ScopedTypeArg::Nominal(Box::new(branch.clone())),
            ScopedTypeArg::Nominal(Box::new(branch)),
            ScopedTypeArg::Nominal(Box::new(leaf.clone())),
            ScopedTypeArg::Nominal(Box::new(leaf)),
        ],
    )
    .unwrap();
    // 29-node argument duplicated under the root makes 61 nodes at depth4.
    let expanded = ScopedTypeTag::new(
        defining.clone(),
        1,
        vec![ScopedTypeArg::Nominal(Box::new(supplied.clone())); 2],
    )
    .unwrap();
    let encoded_size = abi::package_types::encode_scoped_type_tag(&expanded)
        .unwrap()
        .len();
    assert!(encoded_size <= abi::package_types::MAX_SCOPED_TYPE_BYTES);
    assert!(encoded_size * 32 > MAX_BOUND_TYPE_BYTES);
    let context =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(1), Epoch::new(0)).unwrap();
    let r = HashSuiteResolver::new(
        chain,
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin: defining,
        revision: 1,
        wasm_profile: 1,
        semantics: semantics(),
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: wire_abi(&abi),
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest = artifact_commitment(&r, &context, &artifact).unwrap();
    let frame = publication_signing_frame(&r, &context, &artifact, 0).unwrap();
    let request = PublicationRequest::new(artifact, 0, digest, key.sign(&frame).into());
    let candidate = authenticate_publication(&r, &context, &semantics(), request).unwrap();
    let interface = verify_publication_interface(candidate, vec![]).unwrap();
    assert!(matches!(
        bind_object_signature(
            &interface,
            "run",
            &[ScopedTypeArg::Nominal(Box::new(supplied))]
        ),
        Err(BindingError::Limit("bound type bytes"))
    ));
}
