use abi::package_types::PackageOrigin;
use abi::public_abi::*;
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::*;
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use sha2::{Digest as _, Sha256};

fn origin(seed: u8) -> PackageOrigin {
    let key: SigningKey = SigningKey::from([7; 32]);
    PackageOrigin::unverified(
        ChainId::new("test").unwrap(),
        VerificationKey::from(&key).into(),
        [seed; 32],
    )
    .unwrap()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("test").unwrap(),
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn semantics() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32])
}
fn minimal(seed: u8) -> PackageAbi {
    PackageAbi {
        origin: origin(seed),
        constructors: vec![],
        entrypoints: vec![EntrypointDeclaration {
            name: "run".into(),
            type_parameters: vec![],
            objects: vec![],
        }],
    }
}
fn constructor(kinds: Vec<ArgumentKind>) -> ConstructorDeclaration {
    ConstructorDeclaration {
        local_id: 1,
        schema: 1,
        arguments: kinds,
    }
}
fn object(seed: u8, args: Vec<PatternArgument>) -> ObjectParameter {
    ObjectParameter {
        mode: ObjectMode::Write,
        schema: 1,
        ty: TypePattern {
            origin: origin(seed),
            constructor: 1,
            arguments: args,
        },
    }
}
fn generic(seed: u8) -> PackageAbi {
    let mut abi: PackageAbi = minimal(seed);
    abi.constructors
        .push(constructor(vec![ArgumentKind::Opaque(9)]));
    abi.entrypoints[0]
        .type_parameters
        .push(ArgumentKind::Opaque(9));
    abi.entrypoints[0]
        .objects
        .push(object(seed, vec![PatternArgument::Parameter(0)]));
    abi
}
fn reference(node: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact: &CodeArtifact = node.request().artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *node.request().artifact_digest(),
    )
    .unwrap()
}
fn raw_candidate(
    seed: u8,
    abi: Vec<u8>,
    refs: Vec<UnverifiedDependencyRef>,
) -> AuthenticatedPublicationCandidate {
    let wasm: Vec<u8> =
        wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 1,
        semantics: semantics(),
        wasm,
        unverified_abi: abi,
        exports: vec!["run".into()],
        unverified_dependencies: refs,
    })
    .unwrap();
    let r: HashSuiteResolver = resolver();
    let digest: Digest32 = artifact_commitment(&r, &context(), &artifact).unwrap();
    let frame: Vec<u8> = publication_signing_frame(&r, &context(), &artifact, 0).unwrap();
    let key: SigningKey = SigningKey::from([7; 32]);
    let request: PublicationRequest =
        PublicationRequest::new(artifact, 0, digest, key.sign(&frame).into());
    authenticate_publication(&r, &context(), &semantics(), request).unwrap()
}
fn candidate(
    abi: PackageAbi,
    deps: &[&AuthenticatedPublicationCandidate],
) -> AuthenticatedPublicationCandidate {
    let mut refs: Vec<UnverifiedDependencyRef> = deps.iter().map(|node| reference(node)).collect();
    refs.sort_by(|a, b| a.origin().cmp(b.origin()));
    raw_candidate(
        abi.origin.seed()[0],
        encode_package_abi(&abi).unwrap(),
        refs,
    )
}
fn verify(abi: PackageAbi) -> Result<VerifiedPublicationInterface, InterfaceError> {
    verify_publication_interface(candidate(abi, &[]), vec![])
}
fn replace(bytes: &[u8], id: u16, value: &[u8]) -> Vec<u8> {
    let frame = decode_canonical_frame(bytes).unwrap();
    let mut out: CanonicalStruct = CanonicalStruct::new(frame.type_id(), frame.version());
    for key in 1..=128 {
        if key == id {
            out.field_bytes(key, value).unwrap();
        } else if let Some(existing) = frame.field(key) {
            out.field_bytes(key, existing).unwrap();
        }
    }
    out.finish().unwrap()
}

#[test]
fn canonical_vector_and_strict_decoder() {
    let abi: PackageAbi = minimal(1);
    let bytes: Vec<u8> = encode_package_abi(&abi).unwrap();
    assert_eq!(decode_package_abi(&bytes).unwrap(), abi);
    // Independent Node Buffer canonical-frame reconstruction pins the raw ABI.
    let hash: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(bytes.len(), 241);
    assert_eq!(
        hash,
        "c8c326fd8cbb971526b7337e8d8521a28465822b7a0fe444a0f2897cb01d0521"
    );
    for end in 0..bytes.len() {
        assert!(decode_package_abi(&bytes[..end]).is_err());
    }
    let mut trailing: Vec<u8> = bytes.clone();
    trailing.push(0);
    assert!(decode_package_abi(&trailing).is_err());
    for offset in [4, 6] {
        let mut changed: Vec<u8> = bytes.clone();
        changed[offset] = 0xff;
        assert!(decode_package_abi(&changed).is_err());
    }
    assert!(decode_package_abi(&replace(&bytes, 99, b"unknown")).is_err());
    let mut count_bomb: CanonicalStruct = CanonicalStruct::new(0x5308, 1);
    count_bomb.field_u16(1, u16::MAX).unwrap();
    assert!(decode_package_abi(&replace(&bytes, 2, &count_bomb.finish().unwrap())).is_err());
    assert!(decode_package_abi(&vec![0; MAX_PUBLIC_ABI_BYTES + 1]).is_err());
    let mut duplicate: Vec<u8> = bytes.clone();
    duplicate[8..10].copy_from_slice(&4u16.to_le_bytes());
    duplicate.extend_from_slice(&[3, 0, 0, 0, 0, 0]);
    assert!(decode_package_abi(&duplicate).is_err());
}

#[test]
fn generic_signatures_are_checked_without_asset_specific_types() {
    let mut abi: PackageAbi = generic(1);
    for mode in [ObjectMode::Read, ObjectMode::Write, ObjectMode::Consume] {
        let mut second: ObjectParameter = abi.entrypoints[0].objects[0].clone();
        second.mode = mode;
        abi.entrypoints[0].objects.push(second);
    }
    let witness: VerifiedPublicationInterface = verify(abi.clone()).unwrap();
    assert_eq!(witness.abi(), &abi);
    assert!(witness.dependencies().is_empty());
    // Declaration checks grant no runtime handle or object authority.
    assert_eq!(
        witness.candidate().request().artifact().origin(),
        &abi.origin
    );
    let mut wrong: PackageAbi = abi.clone();
    wrong.entrypoints[0].type_parameters[0] = ArgumentKind::Nominal;
    assert_eq!(verify(wrong), Err(InterfaceError::KindMismatch));
    let mut wrong: PackageAbi = abi.clone();
    wrong.entrypoints[0].objects[0].schema = 2;
    assert_eq!(verify(wrong), Err(InterfaceError::SchemaMismatch));
    let mut wrong: PackageAbi = abi.clone();
    wrong.entrypoints[0].objects[0].ty.constructor = 2;
    assert_eq!(verify(wrong), Err(InterfaceError::UnknownConstructor));
    let mut wrong: PackageAbi = abi.clone();
    wrong.entrypoints[0].objects[0].ty.arguments.clear();
    assert_eq!(verify(wrong), Err(InterfaceError::ArityMismatch));
    let mut concrete: PackageAbi = abi.clone();
    concrete.entrypoints[0].objects[0].ty.arguments[0] = PatternArgument::Opaque {
        domain: 9,
        value: [0; 32],
    };
    assert!(verify(concrete.clone()).is_ok());
    concrete.entrypoints[0].objects[0].ty.arguments[0] = PatternArgument::Opaque {
        domain: 10,
        value: [0; 32],
    };
    assert_eq!(verify(concrete), Err(InterfaceError::KindMismatch));
}

#[test]
fn exact_diamond_closure_is_verified_independent_of_input_order() {
    let leaf = candidate(generic(4), &[]);
    let left = candidate(minimal(2), &[&leaf]);
    let right = candidate(minimal(3), &[&leaf]);
    let root = candidate(minimal(1), &[&left, &right]);
    assert!(
        verify_publication_interface(
            root.clone(),
            vec![leaf.clone(), right.clone(), left.clone()]
        )
        .is_ok()
    );
    assert!(
        verify_publication_interface(
            root.clone(),
            vec![left.clone(), right.clone(), leaf.clone()]
        )
        .is_ok()
    );
    assert_eq!(
        verify_publication_interface(root.clone(), vec![left.clone(), right.clone()]),
        Err(InterfaceError::MissingDependency)
    );
    assert_eq!(
        verify_publication_interface(
            root.clone(),
            vec![left.clone(), right.clone(), leaf.clone(), leaf.clone()]
        ),
        Err(InterfaceError::DuplicateOrigin)
    );
    assert_eq!(
        verify_publication_interface(root.clone(), vec![root.clone()]),
        Err(InterfaceError::DuplicateOrigin)
    );
    let extra = candidate(minimal(5), &[]);
    assert_eq!(
        verify_publication_interface(root, vec![left, right, leaf, extra]),
        Err(InterfaceError::ExtraDependency)
    );
}

#[test]
fn copied_origins_and_undeclared_transitive_types_cannot_supply_a_declaration() {
    let leaf = candidate(generic(3), &[]);
    let middle = candidate(minimal(2), &[&leaf]);
    let mut abi: PackageAbi = minimal(1);
    abi.entrypoints[0].objects.push(object(
        3,
        vec![PatternArgument::Opaque {
            domain: 9,
            value: [0; 32],
        }],
    ));
    let root = candidate(abi.clone(), &[&middle]);
    assert_eq!(
        verify_publication_interface(root, vec![middle.clone(), leaf.clone()]),
        Err(InterfaceError::UndeclaredOrigin)
    );
    let root = candidate(abi.clone(), &[&middle, &leaf]);
    assert!(verify_publication_interface(root, vec![middle, leaf.clone()]).is_ok());
    assert_eq!(verify(abi), Err(InterfaceError::UndeclaredOrigin));
    let forged = raw_candidate(1, encode_package_abi(&minimal(3)).unwrap(), vec![]);
    assert_eq!(
        verify_publication_interface(forged, vec![]),
        Err(InterfaceError::OriginMismatch)
    );
    // Same local constructor number in another package is a different declaration.
    let mut own: PackageAbi = generic(1);
    own.constructors[0].schema = 2;
    own.entrypoints[0].objects[0].ty.origin = origin(3);
    let root = candidate(own, &[&leaf]);
    assert!(verify_publication_interface(root, vec![leaf]).is_ok());
}

#[test]
fn exact_reference_fields_and_every_dependency_abi_are_checked() {
    let leaf = candidate(generic(2), &[]);
    let original: UnverifiedDependencyRef = reference(&leaf);
    let bad_refs: Vec<UnverifiedDependencyRef> = vec![
        UnverifiedDependencyRef::new(origin(2), 2, context(), *original.artifact_digest()).unwrap(),
        UnverifiedDependencyRef::new(
            origin(2),
            1,
            PublicationContext::new(
                ChainId::new("test").unwrap(),
                ProtocolVersion::new(2),
                Epoch::new(0),
            )
            .unwrap(),
            *original.artifact_digest(),
        )
        .unwrap(),
        UnverifiedDependencyRef::new(
            origin(2),
            1,
            PublicationContext::new(
                ChainId::new("test").unwrap(),
                ProtocolVersion::new(1),
                Epoch::new(1),
            )
            .unwrap(),
            *original.artifact_digest(),
        )
        .unwrap(),
        UnverifiedDependencyRef::new(
            origin(2),
            1,
            context(),
            Digest32::new(
                HashAlgorithmId::Sha3_256,
                original.artifact_digest().bytes(),
            ),
        )
        .unwrap(),
    ];
    for bad in bad_refs {
        let root = raw_candidate(1, encode_package_abi(&minimal(1)).unwrap(), vec![bad]);
        assert_eq!(
            verify_publication_interface(root, vec![leaf.clone()]),
            Err(InterfaceError::DependencyMismatch)
        );
    }
    let invalid = raw_candidate(2, b"signed but invalid ABI".to_vec(), vec![]);
    let root = candidate(minimal(1), &[&invalid]);
    assert!(matches!(
        verify_publication_interface(root, vec![invalid]),
        Err(InterfaceError::Abi(_))
    ));
    let mut bad: PackageAbi = generic(2);
    bad.entrypoints[0].objects[0].ty.constructor = 7;
    let invalid = candidate(bad, &[]);
    let root = candidate(minimal(1), &[&invalid]);
    assert_eq!(
        verify_publication_interface(root, vec![invalid]),
        Err(InterfaceError::UnknownConstructor)
    );
    let mut wrong_export: PackageAbi = minimal(2);
    wrong_export.entrypoints[0].name = "other".into();
    let invalid = candidate(wrong_export, &[]);
    let root = candidate(minimal(1), &[&invalid]);
    assert_eq!(
        verify_publication_interface(root, vec![invalid]),
        Err(InterfaceError::ExportMismatch)
    );
}

#[test]
fn declaration_shape_and_shared_tree_budgets_fail_closed() {
    let valid: PackageAbi = generic(1);
    let mut cases: Vec<PackageAbi> = vec![];
    let mut bad = valid.clone();
    bad.constructors[0].local_id = 0;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.constructors[0].schema = 0;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.constructors.push(bad.constructors[0].clone());
    cases.push(bad);
    let mut bad = valid.clone();
    bad.constructors[0].arguments[0] = ArgumentKind::Opaque(0);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints.clear();
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].name = "memory".into();
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].name = "x".repeat(257);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].objects[0].schema = 0;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].objects[0].ty.arguments[0] = PatternArgument::Parameter(1);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].objects[0].ty.origin =
        PackageOrigin::unverified(ChainId::new("other").unwrap(), [1; 32], [1; 32]).unwrap();
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].objects = vec![object(1, vec![]); 33];
    cases.push(bad);
    let mut bad = valid.clone();
    bad.entrypoints[0].type_parameters = vec![ArgumentKind::Nominal; 9];
    cases.push(bad);
    for bad in cases {
        assert!(encode_package_abi(&bad).is_err());
    }
    let mut deep: TypePattern = object(1, vec![]).ty;
    for _ in 0..4 {
        deep = TypePattern {
            origin: origin(1),
            constructor: 1,
            arguments: vec![PatternArgument::Nominal(Box::new(deep))],
        };
    }
    let mut bad: PackageAbi = valid.clone();
    bad.entrypoints[0].objects[0].ty = deep;
    assert!(encode_package_abi(&bad).is_err());
    let mut broad: PackageAbi = minimal(1);
    broad.entrypoints = (0..64)
        .map(|i| EntrypointDeclaration {
            name: format!("e{i:02}"),
            type_parameters: vec![],
            objects: vec![object(1, vec![]); 32],
        })
        .collect();
    assert!(validate_package_abi_shape(&broad).is_err());
}

#[test]
fn closure_limits_precede_abi_decoding_and_bound_longest_paths() {
    let root = candidate(minimal(1), &[]);
    assert_eq!(
        verify_publication_interface(root.clone(), vec![root.clone(); MAX_INTERFACE_NODES]),
        Err(InterfaceError::Limit("nodes"))
    );
    let invalid: Vec<AuthenticatedPublicationCandidate> = (2..=5)
        .map(|seed| raw_candidate(seed, vec![0; MAX_PUBLIC_ABI_BYTES], vec![]))
        .collect();
    assert_eq!(
        verify_publication_interface(root, invalid),
        Err(InterfaceError::Limit("ABI bytes"))
    );
    let mut nodes: Vec<AuthenticatedPublicationCandidate> = vec![candidate(minimal(9), &[])];
    for seed in (1..9).rev() {
        let next = candidate(minimal(seed), &[nodes.last().unwrap()]);
        nodes.push(next);
    }
    let root = nodes.pop().unwrap();
    assert_eq!(
        verify_publication_interface(root, nodes.clone()),
        Err(InterfaceError::Limit("dependency depth"))
    );
    let root = nodes.pop().unwrap();
    assert!(verify_publication_interface(root, nodes).is_ok());
}

#[test]
fn nested_nominal_arguments_preserve_entrypoint_parameter_scope() {
    let mut abi: PackageAbi = generic(1);
    abi.constructors.push(ConstructorDeclaration {
        local_id: 2,
        schema: 1,
        arguments: vec![ArgumentKind::Nominal],
    });
    let inner: TypePattern = abi.entrypoints[0].objects[0].ty.clone();
    abi.entrypoints[0].objects[0].ty = TypePattern {
        origin: origin(1),
        constructor: 2,
        arguments: vec![PatternArgument::Nominal(Box::new(inner))],
    };
    assert!(verify(abi.clone()).is_ok());
    abi.entrypoints[0].type_parameters[0] = ArgumentKind::Opaque(10);
    assert_eq!(verify(abi), Err(InterfaceError::KindMismatch));
}

#[test]
fn full_generic_vector_and_nested_wire_rejection() {
    let mut abi: PackageAbi = minimal(1);
    abi.constructors = vec![
        constructor(vec![ArgumentKind::Nominal, ArgumentKind::Opaque(9)]),
        ConstructorDeclaration {
            local_id: 2,
            schema: 1,
            arguments: vec![ArgumentKind::Opaque(9)],
        },
    ];
    abi.entrypoints[0].type_parameters = vec![ArgumentKind::Opaque(9)];
    let inner: TypePattern = TypePattern {
        origin: origin(1),
        constructor: 2,
        arguments: vec![PatternArgument::Parameter(0)],
    };
    let outer: TypePattern = TypePattern {
        origin: origin(1),
        constructor: 1,
        arguments: vec![
            PatternArgument::Nominal(Box::new(inner)),
            PatternArgument::Opaque {
                domain: 9,
                value: [7; 32],
            },
        ],
    };
    abi.entrypoints[0].objects = [ObjectMode::Read, ObjectMode::Write, ObjectMode::Consume]
        .into_iter()
        .map(|mode| ObjectParameter {
            mode,
            schema: 1,
            ty: outer.clone(),
        })
        .collect();
    let encoded: Vec<u8> = encode_package_abi(&abi).unwrap();
    assert_eq!(encoded.len(), 1905);
    let hash: String = Sha256::digest(&encoded)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hash,
        "814a017d9baa8302f07e9f97e7b98231fbca2ba1fb1a8d71dc0f410bf57d223b"
    );
    assert_eq!(decode_package_abi(&encoded).unwrap(), abi);
    assert!(verify(abi).is_ok());
    fn rewrite(bytes: &[u8], path: &[u16], value: &[u8]) -> Vec<u8> {
        if path.len() == 1 {
            return replace(bytes, path[0], value);
        }
        let frame = decode_canonical_frame(bytes).unwrap();
        let child: Vec<u8> = rewrite(frame.required_field(path[0]).unwrap(), &path[1..], value);
        replace(bytes, path[0], &child)
    }
    // Unknown mode/kind/argument variant and opaque length/domain errors at nested frames.
    for path in [
        vec![3, 2, 3, 2, 1],
        vec![2, 2, 3, 2, 1],
        vec![3, 2, 3, 2, 3, 3, 2, 1],
    ] {
        assert!(decode_package_abi(&rewrite(&encoded, &path, &99u16.to_le_bytes())).is_err());
    }
    assert!(
        decode_package_abi(&rewrite(
            &encoded,
            &[3, 2, 3, 2, 3, 3, 3, 2],
            &0u16.to_le_bytes()
        ))
        .is_err()
    );
    assert!(decode_package_abi(&rewrite(&encoded, &[3, 2, 3, 2, 3, 3, 3, 3], &[7; 31])).is_err());
    assert!(
        decode_package_abi(&rewrite(
            &encoded,
            &[3, 2, 3, 2, 3, 3, 2, 2, 3, 2, 2],
            &8u16.to_le_bytes()
        ))
        .is_err()
    );
    assert!(decode_package_abi(&rewrite(&encoded, &[3, 2, 1], &[0xff])).is_err());
    assert!(decode_package_abi(&rewrite(&encoded, &[3, 2, 1], &vec![b'x'; 257])).is_err());
    assert!(
        decode_package_abi(&rewrite(&encoded, &[3, 2, 3, 1], &u16::MAX.to_le_bytes())).is_err()
    );
}

#[test]
fn wire_tree_depth_and_shared_node_budget_cannot_be_reset_per_entrypoint() {
    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x5308, 1);
        frame
            .field_u16(1, u16::try_from(items.len()).unwrap())
            .unwrap();
        for (i, item) in items.iter().enumerate() {
            frame
                .field_bytes(u16::try_from(i + 2).unwrap(), item.as_slice())
                .unwrap();
        }
        frame.finish().unwrap()
    }
    fn entry(name: &str, kinds: &[u8], objects: &[Vec<u8>]) -> Vec<u8> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x5304, 1);
        frame.field_str(1, name).unwrap();
        frame.field_bytes(2, kinds).unwrap();
        frame.field_bytes(3, list(objects)).unwrap();
        frame.finish().unwrap()
    }
    let mut abi: PackageAbi = generic(1);
    abi.entrypoints[0].objects[0].ty.arguments = vec![PatternArgument::Parameter(0); 8];
    let encoded: Vec<u8> = encode_package_abi(&abi).unwrap(); // shape only, arity is a later check
    let root = decode_canonical_frame(&encoded).unwrap();
    let entries = decode_canonical_frame(root.required_field(3).unwrap()).unwrap();
    let first = decode_canonical_frame(entries.required_field(2).unwrap()).unwrap();
    let objects = decode_canonical_frame(first.required_field(3).unwrap()).unwrap();
    let object: Vec<u8> = objects.required_field(2).unwrap().to_vec();
    // Each pattern plus 8 arguments consumes 9 nodes. Four entries with 29
    // objects each exceed 1024 nodes, despite each entry individually fitting.
    let entry_bytes: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            entry(
                &format!("e{i}"),
                first.required_field(2).unwrap(),
                &vec![object.clone(); 29],
            )
        })
        .collect();
    let broad: Vec<u8> = replace(&encoded, 3, &list(&entry_bytes));
    assert!(broad.len() < MAX_PUBLIC_ABI_BYTES);
    assert!(matches!(
        decode_package_abi(&broad),
        Err(PublicAbiError::Limit(_))
    ));
    let object_frame = decode_canonical_frame(&object).unwrap();
    let mut pattern: Vec<u8> = object_frame.required_field(3).unwrap().to_vec();
    for _ in 0..4 {
        let mut argument: CanonicalStruct = CanonicalStruct::new(0x5307, 1);
        argument.field_u16(1, 1).unwrap();
        argument.field_bytes(2, pattern.clone()).unwrap();
        pattern = replace(&pattern, 3, &list(&[argument.finish().unwrap()]));
    }
    let deep_object: Vec<u8> = replace(&object, 3, &pattern);
    let deep: Vec<u8> = replace(
        &encoded,
        3,
        &list(&[entry(
            "run",
            first.required_field(2).unwrap(),
            &[deep_object],
        )]),
    );
    assert!(matches!(
        decode_package_abi(&deep),
        Err(PublicAbiError::Limit(_))
    ));
}
