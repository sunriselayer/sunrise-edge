use super::*;
use abi::call_values::{CallValue, decode_call_abi, encode_call_value, encode_value_layout};
use abi::package_types::{ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id};
use abi::{AccessEntry, AccessManifest};
use execution::ResolvedObject;
use objects::{AccessMode, Object, ObjectId, ObjectRef, Owner};

fn envelope(objects: PackageAbi, bodies: Vec<ValueLayout>) -> CallAbi {
    CallAbi {
        arguments: vec![ValueLayout::Tuple(vec![]); objects.entrypoints.len()],
        objects,
        bodies,
    }
}
fn signed(
    call: &CallAbi,
    deps: &[&AuthenticatedPublicationCandidate],
) -> AuthenticatedPublicationCandidate {
    let mut refs: Vec<UnverifiedDependencyRef> = deps.iter().map(|node| reference(node)).collect();
    refs.sort_by(|a, b| a.origin().cmp(b.origin()));
    raw_candidate(
        call.objects.origin.seed()[0],
        encode_call_abi(call).unwrap(),
        refs,
    )
}
fn opaque() -> ScopedTypeArg {
    ScopedTypeArg::Opaque {
        domain: 9,
        value: [7; 32],
    }
}
fn snapshot(ty: ScopedTypeTag, data: Vec<u8>, id: u8) -> (AccessEntry, ResolvedObject) {
    let object: Object = Object {
        id: ObjectId::new([id; 32]),
        version: 1,
        owner: Owner::Shared,
        type_hash: derive_scoped_type_id(&resolver(), Epoch::new(0), &ty).unwrap(),
        schema_version: 1,
        data,
    };
    (
        AccessEntry {
            object_ref: ObjectRef {
                id: object.id,
                version: object.version,
                digest: semantics(),
            },
            mode: AccessMode::Write,
        },
        ResolvedObject {
            object,
            mode: AccessMode::Write,
        },
    )
}
fn check(
    bound: &BoundObjectSignature<'_>,
    pairs: &[(AccessEntry, ResolvedObject)],
) -> Result<(), BodyError> {
    let manifest: AccessManifest = AccessManifest {
        entries: pairs.iter().map(|p| p.0.clone()).collect(),
    };
    let inputs: Vec<ResolvedObject> = pairs.iter().map(|p| p.1.clone()).collect();
    validate_object_input_bodies(bound, &resolver(), Epoch::new(0), &manifest, &inputs)
}
fn encoded_u64(value: u64) -> Vec<u8> {
    encode_call_value(&ValueLayout::U64, &CallValue::U64(value)).unwrap()
}
fn list(layouts: &[ValueLayout]) -> Vec<u8> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x5402, 1);
    frame
        .field_u16(1, u16::try_from(layouts.len()).unwrap())
        .unwrap();
    for (i, l) in layouts.iter().enumerate() {
        frame
            .field_bytes(
                u16::try_from(i + 2).unwrap(),
                encode_value_layout(l).unwrap(),
            )
            .unwrap();
    }
    frame.finish().unwrap()
}

#[test]
fn active_body_envelope_vector_is_independently_pinned() {
    let mut objects: PackageAbi = minimal(1);
    objects
        .constructors
        .push(constructor(vec![ArgumentKind::Opaque(9)]));
    let call: CallAbi = envelope(
        objects,
        vec![ValueLayout::Tuple(vec![
            ValueLayout::U64,
            ValueLayout::Bytes {
                min_len: 32,
                max_len: 32,
            },
        ])],
    );
    let bytes: Vec<u8> = encode_call_abi(&call).unwrap();
    assert_eq!(bytes.len(), 559);
    let hash: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hash,
        "997d53ee8787f53f8826841452216d6b6e0c4c0e88701fbd4a4f2853c9378839"
    );
    assert_eq!(decode_call_abi(&bytes).unwrap(), call);
    assert_eq!(
        encode_call_abi(&decode_call_abi(&bytes).unwrap()).unwrap(),
        bytes
    );
    for n in 0..bytes.len() {
        assert!(decode_call_abi(&bytes[..n]).is_err());
    }
}

#[test]
fn body_pairing_is_required_even_for_unused_constructors() {
    let call: CallAbi = envelope(generic(1), vec![ValueLayout::U64]);
    let bytes: Vec<u8> = encode_call_abi(&call).unwrap();
    for bodies in [vec![], vec![ValueLayout::U64, ValueLayout::Bool]] {
        let mut bad: CallAbi = call.clone();
        bad.bodies = bodies.clone();
        assert!(encode_call_abi(&bad).is_err());
        let raw: Vec<u8> = replace(&bytes, 3, &list(&bodies));
        assert!(decode_call_abi(&raw).is_err());
        assert!(matches!(
            verify_publication_interface(raw_candidate(1, raw, vec![]), vec![]),
            Err(InterfaceError::Abi(_))
        ));
    }
    let decoded = decode_canonical_frame(&bytes).unwrap();
    let mut missing: CanonicalStruct = CanonicalStruct::new(0x5405, 2);
    for field in [1, 2] {
        missing
            .field_bytes(field, decoded.required_field(field).unwrap())
            .unwrap();
    }
    assert!(decode_call_abi(&missing.finish().unwrap()).is_err());
    let mut unused: CallAbi = envelope(minimal(1), vec![]);
    unused.objects.constructors.push(constructor(vec![]));
    unused.bodies.push(ValueLayout::Bytes {
        min_len: 2,
        max_len: 1,
    });
    assert!(encode_call_abi(&unused).is_err());
}

#[test]
fn sparse_constructor_ids_and_schemas_select_exact_positional_bodies() {
    let mut objects: PackageAbi = minimal(1);
    objects.constructors = vec![
        ConstructorDeclaration {
            local_id: 2,
            schema: 1,
            arguments: vec![],
        },
        ConstructorDeclaration {
            local_id: 9,
            schema: 7,
            arguments: vec![],
        },
    ];
    objects.entrypoints[0].objects = [(2, 1), (9, 7)]
        .into_iter()
        .map(|(id, schema)| ObjectParameter {
            mode: ObjectMode::Write,
            schema,
            ty: TypePattern {
                origin: origin(1),
                constructor: id,
                arguments: vec![],
            },
        })
        .collect();
    let call: CallAbi = envelope(objects, vec![ValueLayout::U64, ValueLayout::Bool]);
    let interface = verify_publication_interface(signed(&call, &[]), vec![]).unwrap();
    let bound = bind_object_signature(&interface, "run", &[]).unwrap();
    let a = snapshot(
        ScopedTypeTag::new(origin(1), 2, vec![]).unwrap(),
        encoded_u64(7),
        1,
    );
    let mut b = snapshot(
        ScopedTypeTag::new(origin(1), 9, vec![]).unwrap(),
        encode_call_value(&ValueLayout::Bool, &CallValue::Bool(true)).unwrap(),
        2,
    );
    b.1.object.schema_version = 7;
    assert_eq!(check(&bound, &[a.clone(), b.clone()]), Ok(()));
    b.1.object.data = a.1.object.data.clone();
    assert!(check(&bound, &[a, b]).is_err());
}

#[test]
fn argument_and_body_lists_share_one_layout_node_budget() {
    let mut objects: PackageAbi = minimal(1);
    objects.constructors = (1..=64)
        .map(|id| ConstructorDeclaration {
            local_id: id,
            schema: 1,
            arguments: vec![],
        })
        .collect();
    let mut call: CallAbi = envelope(
        objects,
        vec![ValueLayout::Tuple(vec![ValueLayout::Bool; 3]); 64],
    );
    call.bodies[0] = ValueLayout::Tuple(vec![ValueLayout::Bool; 2]); // 1 argument + 255 body nodes
    let bytes: Vec<u8> = encode_call_abi(&call).unwrap();
    assert!(decode_call_abi(&bytes).is_ok());
    call.bodies[0] = ValueLayout::Tuple(vec![ValueLayout::Bool; 3]);
    assert!(encode_call_abi(&call).is_err());
    assert!(decode_call_abi(&replace(&bytes, 3, &list(&call.bodies))).is_err());
}

#[test]
fn body_validation_rejects_shape_and_all_metadata_mismatches() {
    let call: CallAbi = envelope(generic(1), vec![ValueLayout::U64]);
    let interface = verify_publication_interface(signed(&call, &[]), vec![]).unwrap();
    let bound = bind_object_signature(&interface, "run", &[opaque()]).unwrap();
    let pair = snapshot(
        ScopedTypeTag::new(origin(1), 1, vec![opaque()]).unwrap(),
        encoded_u64(4),
        1,
    );
    assert_eq!(check(&bound, std::slice::from_ref(&pair)), Ok(()));
    for change in 0..8 {
        let mut bad = pair.clone();
        match change {
            0 => bad.1.object.data = vec![0xff],
            1 => bad.1.object.data.push(0),
            2 => {
                bad.1.object.data =
                    encode_call_value(&ValueLayout::Bool, &CallValue::Bool(true)).unwrap()
            }
            3 => bad.1.object.id = ObjectId::new([2; 32]),
            4 => bad.1.object.version = 2,
            5 => bad.1.object.schema_version = 2,
            6 => bad.1.mode = AccessMode::Consume,
            _ => bad.1.object.type_hash = semantics(),
        }
        assert!(check(&bound, &[bad]).is_err());
    }
    assert!(check(&bound, &[]).is_err());
}

#[test]
fn dependency_body_layout_is_not_replaced_by_same_local_constructor() {
    let dependency: CallAbi = envelope(generic(2), vec![ValueLayout::U64]);
    let dep = signed(&dependency, &[]);
    let mut root: CallAbi = envelope(generic(1), vec![ValueLayout::Bool]);
    root.objects.entrypoints[0]
        .objects
        .insert(0, object(2, vec![PatternArgument::Parameter(0)]));
    let interface =
        verify_publication_interface(signed(&root, &[&dep]), vec![dep.clone()]).unwrap();
    let bound = bind_object_signature(&interface, "run", &[opaque()]).unwrap();
    let a = snapshot(
        ScopedTypeTag::new(origin(2), 1, vec![opaque()]).unwrap(),
        encoded_u64(7),
        1,
    );
    let b = snapshot(
        ScopedTypeTag::new(origin(1), 1, vec![opaque()]).unwrap(),
        encode_call_value(&ValueLayout::Bool, &CallValue::Bool(false)).unwrap(),
        2,
    );
    assert_eq!(check(&bound, &[a.clone(), b.clone()]), Ok(()));
    let mut swapped = a.clone();
    swapped.1.object.data = b.1.object.data.clone();
    assert!(check(&bound, &[swapped, b.clone()]).is_err());
    let mut substituted: CallAbi = dependency;
    substituted.bodies[0] = ValueLayout::Bool;
    assert!(
        verify_publication_interface(signed(&root, &[&dep]), vec![signed(&substituted, &[])])
            .is_err()
    );
    let mut aliased = b;
    aliased.0.object_ref.id = a.0.object_ref.id;
    aliased.1.object.id = a.1.object.id;
    assert!(check(&bound, &[a, aliased]).is_err());
}

#[test]
fn body_byte_budget_is_aggregate_and_per_object() {
    let layout: ValueLayout = ValueLayout::Bytes {
        min_len: 0,
        max_len: 65536,
    };
    let mut call: CallAbi = envelope(generic(1), vec![layout.clone()]);
    call.objects.entrypoints[0].objects = vec![object(1, vec![PatternArgument::Parameter(0)]); 5];
    let interface = verify_publication_interface(signed(&call, &[]), vec![]).unwrap();
    let bound = bind_object_signature(&interface, "run", &[opaque()]).unwrap();
    let large: Vec<u8> =
        encode_call_value(&layout, &CallValue::Bytes(vec![0; 65536 - 24])).unwrap();
    let mut pairs: Vec<(AccessEntry, ResolvedObject)> = (1..=5)
        .map(|id| {
            snapshot(
                ScopedTypeTag::new(origin(1), 1, vec![opaque()]).unwrap(),
                large.clone(),
                id,
            )
        })
        .collect();
    assert!(matches!(check(&bound, &pairs), Err(BodyError::Limit)));
    pairs[4].1.object.data = encode_call_value(&layout, &CallValue::Bytes(vec![])).unwrap();
    // The fifth frame itself counts, even with an empty payload.
    assert!(matches!(check(&bound, &pairs), Err(BodyError::Limit)));
    pairs[0].1.object.data =
        encode_call_value(&layout, &CallValue::Bytes(vec![0; 65536 - 48])).unwrap();
    assert_eq!(
        pairs.iter().map(|p| p.1.object.data.len()).sum::<usize>(),
        MAX_BOUND_BODY_BYTES
    );
    assert_eq!(check(&bound, &pairs), Ok(()));
    pairs[0].1.object.data.push(0);
    assert!(matches!(check(&bound, &pairs), Err(BodyError::Limit)));
    pairs[0].1.object.data = vec![0; 65537];
    assert!(matches!(check(&bound, &pairs), Err(BodyError::Limit)));
}

#[test]
fn body_layout_mutation_is_signature_bound() {
    let call: CallAbi = envelope(generic(1), vec![ValueLayout::U64]);
    let original = signed(&call, &[]);
    let request = original.request().expect("legacy publication candidate");
    let a = request.artifact();
    let mut changed: CallAbi = call;
    changed.bodies[0] = ValueLayout::Bool;
    let artifact = CodeArtifact::new(ArtifactParts {
        context: a.context().clone(),
        origin: a.origin().clone(),
        revision: a.revision(),
        wasm_profile: a.wasm_profile(),
        semantics: *a.semantics(),
        wasm: a.wasm().to_vec(),
        exports: a.exports().to_vec(),
        unverified_dependencies: vec![],
        unverified_abi: encode_call_abi(&changed).unwrap(),
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    assert_ne!(&digest, request.artifact_digest());
    assert!(
        authenticate_publication(
            &resolver(),
            &context(),
            &semantics(),
            PublicationRequest::new(artifact, request.nonce(), digest, *request.signature())
        )
        .is_err()
    );
}

#[test]
fn well_formed_bodies_do_not_authenticate_owner_digest_or_business_invariants() {
    let call: CallAbi = envelope(generic(1), vec![ValueLayout::U64]);
    let interface = verify_publication_interface(signed(&call, &[]), vec![]).unwrap();
    let bound = bind_object_signature(&interface, "run", &[opaque()]).unwrap();
    let mut pair = snapshot(
        ScopedTypeTag::new(origin(1), 1, vec![opaque()]).unwrap(),
        encoded_u64(u64::MAX),
        1,
    );
    for owner in [Owner::Shared, Owner::Immutable, Owner::System] {
        pair.1.object.owner = owner;
        pair.0.object_ref.digest = Digest32::new(HashAlgorithmId::Sha3_256, [0xff; 32]);
        assert_eq!(check(&bound, std::slice::from_ref(&pair)), Ok(()));
    }
}
