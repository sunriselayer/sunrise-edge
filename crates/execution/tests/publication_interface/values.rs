use super::*;
use abi::call_values::*;

fn layout() -> ValueLayout {
    ValueLayout::Tuple(vec![
        ValueLayout::Bool,
        ValueLayout::U64,
        ValueLayout::U128,
        ValueLayout::Bytes {
            min_len: 2,
            max_len: 2,
        },
        ValueLayout::Utf8 { max_bytes: 8 },
        ValueLayout::List {
            max_len: 3,
            element: Box::new(ValueLayout::Tuple(vec![
                ValueLayout::U64,
                ValueLayout::Bytes {
                    min_len: 0,
                    max_len: 4,
                },
            ])),
        },
    ])
}
fn value() -> CallValue {
    CallValue::Tuple(vec![
        CallValue::Bool(true),
        CallValue::U64(42),
        CallValue::U128(u128::MAX),
        CallValue::Bytes(vec![0, 255]),
        CallValue::Utf8("é".into()),
        CallValue::List(vec![
            CallValue::Tuple(vec![CallValue::U64(7), CallValue::Bytes(vec![])]),
            CallValue::Tuple(vec![CallValue::U64(9), CallValue::Bytes(vec![1, 2])]),
        ]),
    ])
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn list_frame(id: u16, items: &[Vec<u8>]) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(id, 1);
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
fn raw_value(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = CanonicalStruct::new(0x5403, 1);
    f.field_u16(1, kind).unwrap();
    f.field_bytes(2, payload).unwrap();
    f.finish().unwrap()
}
fn typed_candidate(call: &CallAbi) -> AuthenticatedPublicationCandidate {
    let exports: Vec<String> = call
        .objects
        .entrypoints
        .iter()
        .map(|e| e.name.clone())
        .collect();
    let functions: String = exports
        .iter()
        .map(|e| format!("(func (export \"{e}\"))"))
        .collect();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: call.objects.origin.clone(),
        revision: 1,
        wasm_profile: 1,
        semantics: semantics(),
        wasm: wat::parse_str(format!(
            "(module (memory (export \"memory\") 1 2) {functions})"
        ))
        .unwrap(),
        unverified_abi: encode_call_abi(call).unwrap(),
        exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame = publication_signing_frame(&resolver(), &context(), &artifact, 0).unwrap();
    let key = SigningKey::from([7; 32]);
    authenticate_publication(
        &resolver(),
        &context(),
        &semantics(),
        PublicationRequest::new(artifact, 0, digest, key.sign(&frame).into()),
    )
    .unwrap()
}

#[test]
fn independent_layout_value_and_envelope_vectors_roundtrip_exactly() {
    let l = layout();
    let v = value();
    let encoded_layout = encode_value_layout(&l).unwrap();
    let encoded_value = encode_call_value(&l, &v).unwrap();
    let call = CallAbi {
        objects: minimal(1),
        arguments: vec![l.clone()],
    };
    let encoded_call = encode_call_abi(&call).unwrap();
    assert_eq!(
        digest(&encoded_layout),
        "214d902457fa9cb3ad44048a2b63f9cfcf6b959941c02f2f960c6cac854e389d"
    );
    assert_eq!(
        digest(&encoded_value),
        "4198b85cdec540d1de9c2303f145cbd67cc83f54247a5acece025340dfa04dbe"
    );
    assert_eq!(
        digest(&encoded_call),
        "3c80fc2beb2a8365c789680efc3f13db610c2d3ae941bb9dddb5a866a1eae28c"
    );
    assert_eq!(decode_value_layout(&encoded_layout).unwrap(), l);
    assert_eq!(decode_call_value(&l, &encoded_value).unwrap(), v);
    assert_eq!(decode_call_abi(&encoded_call).unwrap(), call);
    assert_eq!(
        encode_value_layout(&decode_value_layout(&encoded_layout).unwrap()).unwrap(),
        encoded_layout
    );
    assert_eq!(
        encode_call_value(&l, &decode_call_value(&l, &encoded_value).unwrap()).unwrap(),
        encoded_value
    );
    assert_eq!(
        encode_call_abi(&decode_call_abi(&encoded_call).unwrap()).unwrap(),
        encoded_call
    );
    for n in 0..encoded_value.len() {
        assert!(decode_call_value(&l, &encoded_value[..n]).is_err());
    }
    for n in 0..encoded_layout.len() {
        assert!(decode_value_layout(&encoded_layout[..n]).is_err());
    }
    for n in 0..encoded_call.len() {
        assert!(decode_call_abi(&encoded_call[..n]).is_err());
    }
}

#[test]
fn strict_scalar_shapes_and_utf8_have_no_coercion_or_normalization() {
    assert!(decode_call_value(&ValueLayout::Bool, &raw_value(1, &2u16.to_le_bytes())).is_err());
    for width in [0, 7, 9] {
        assert!(decode_call_value(&ValueLayout::U64, &raw_value(2, &vec![0; width])).is_err());
    }
    for width in [0, 15, 17] {
        assert!(decode_call_value(&ValueLayout::U128, &raw_value(3, &vec![0; width])).is_err());
    }
    assert!(decode_call_value(&ValueLayout::Bool, &raw_value(2, &0u64.to_le_bytes())).is_err());
    assert!(decode_call_value(&ValueLayout::Bool, &raw_value(99, &[0, 0])).is_err());
    let text = ValueLayout::Utf8 { max_bytes: 4 };
    for bytes in [vec![0xff], vec![0xed, 0xa0, 0x80], vec![0xc0, 0x80]] {
        assert!(decode_call_value(&text, &raw_value(5, &bytes)).is_err());
    }
    let a = encode_call_value(&text, &CallValue::Utf8("é".into())).unwrap();
    let b = encode_call_value(&text, &CallValue::Utf8("e\u{301}".into())).unwrap();
    assert_ne!(a, b);
    assert!(
        encode_call_value(
            &ValueLayout::Utf8 { max_bytes: 1 },
            &CallValue::Utf8("é".into())
        )
        .is_err()
    );
    assert!(
        encode_call_value(
            &ValueLayout::Bytes {
                min_len: 2,
                max_len: 2
            },
            &CallValue::Bytes(vec![1])
        )
        .is_err()
    );
    assert!(
        encode_call_value(
            &ValueLayout::Bytes {
                min_len: 2,
                max_len: 2
            },
            &CallValue::Bytes(vec![1; 3])
        )
        .is_err()
    );
    for encoded in [a, b] {
        let mut tail = encoded.clone();
        tail.push(0);
        assert!(decode_call_value(&text, &tail).is_err());
        assert!(decode_call_value(&text, &replace(&encoded, 99, b"x")).is_err());
    }
}

#[test]
fn byte_budget_includes_framing_and_aggregate_payload() {
    let l = ValueLayout::Bytes {
        min_len: 0,
        max_len: MAX_VALUE_BYTES as u32,
    };
    let encoded = encode_call_value(&l, &CallValue::Bytes(vec![0; MAX_VALUE_BYTES - 24])).unwrap();
    assert_eq!(encoded.len(), MAX_VALUE_BYTES);
    assert!(decode_call_value(&l, &encoded).is_ok());
    assert!(encode_call_value(&l, &CallValue::Bytes(vec![0; MAX_VALUE_BYTES - 23])).is_err());
    assert!(decode_call_value(&l, &vec![0; MAX_VALUE_BYTES + 1]).is_err());
    let pair = ValueLayout::Tuple(vec![l.clone(), l]);
    assert!(
        encode_call_value(
            &pair,
            &CallValue::Tuple(vec![
                CallValue::Bytes(vec![0; 32768]),
                CallValue::Bytes(vec![0; 32769])
            ])
        )
        .is_err()
    );
}

#[test]
fn shared_value_nodes_and_declared_collection_counts_are_bounded() {
    let list = ValueLayout::List {
        element: Box::new(ValueLayout::Bool),
        max_len: 256,
    };
    let l = ValueLayout::Tuple(vec![list.clone(); 4]);
    let mut values = vec![CallValue::List(vec![CallValue::Bool(false); 256]); 3];
    values.push(CallValue::List(vec![CallValue::Bool(false); 251]));
    let positive = encode_call_value(&l, &CallValue::Tuple(values.clone())).unwrap(); // 1+4+768+251=1024
    assert!(decode_call_value(&l, &positive).is_ok());
    values[3] = CallValue::List(vec![CallValue::Bool(false); 252]);
    assert!(encode_call_value(&l, &CallValue::Tuple(values)).is_err());
    let scalar = raw_value(1, &[0, 0]);
    let raw_lists: Vec<Vec<u8>> = [256, 256, 256, 252]
        .into_iter()
        .map(|n| raw_value(7, &list_frame(0x5404, &vec![scalar.clone(); n])))
        .collect();
    let hostile = raw_value(6, &list_frame(0x5404, &raw_lists));
    assert!(hostile.len() < MAX_VALUE_BYTES);
    assert!(decode_call_value(&l, &hostile).is_err());
    let bomb = raw_value(7, &list_frame(0x5404, &vec![scalar; 257]));
    assert!(decode_call_value(&list, &bomb).is_err());
    let wrong_type = raw_value(7, &list_frame(0x5404, &[raw_value(2, &[0; 8])]));
    assert!(decode_call_value(&list, &wrong_type).is_err());
    assert!(
        encode_call_value(
            &ValueLayout::Tuple(vec![ValueLayout::Bool]),
            &CallValue::Tuple(vec![])
        )
        .is_err()
    );
}

#[test]
fn layout_depth_and_shared_envelope_node_budget_are_exact() {
    let mut l = ValueLayout::Tuple(vec![]);
    let mut v = CallValue::Tuple(vec![]);
    for _ in 0..7 {
        l = ValueLayout::Tuple(vec![l]);
        v = CallValue::Tuple(vec![v]);
    }
    let encoded = encode_value_layout(&l).unwrap();
    assert!(decode_value_layout(&encoded).is_ok());
    assert!(encode_call_value(&l, &v).is_ok());
    let mut raw = CanonicalStruct::new(0x5401, 1);
    raw.field_u16(1, 6).unwrap();
    raw.field_bytes(2, list_frame(0x5402, &[encoded])).unwrap();
    assert!(decode_value_layout(&raw.finish().unwrap()).is_err());
    assert!(encode_value_layout(&ValueLayout::Tuple(vec![l])).is_err());
    for bad in [
        ValueLayout::Bytes {
            min_len: 2,
            max_len: 1,
        },
        ValueLayout::Utf8 { max_bytes: 65537 },
        ValueLayout::Tuple(vec![ValueLayout::Bool; 33]),
        ValueLayout::List {
            element: Box::new(ValueLayout::Bool),
            max_len: 257,
        },
    ] {
        assert!(validate_value_layout(&bad).is_err());
        assert!(
            encode_call_value(
                &ValueLayout::List {
                    element: Box::new(bad),
                    max_len: 0
                },
                &CallValue::List(vec![])
            )
            .is_err()
        );
    }
    let mut objects = minimal(1);
    objects.entrypoints = (0..64)
        .map(|n| EntrypointDeclaration {
            name: format!("e{n:02}"),
            type_parameters: vec![],
            objects: vec![],
        })
        .collect();
    let mut call = CallAbi {
        objects,
        arguments: vec![ValueLayout::Tuple(vec![ValueLayout::Bool; 3]); 64],
    }; // 64*4=256
    let encoded = encode_call_abi(&call).unwrap();
    assert!(decode_call_abi(&encoded).is_ok());
    call.arguments[0] = ValueLayout::Tuple(vec![ValueLayout::Bool; 4]);
    assert!(encode_call_abi(&call).is_err());
    let raw_layouts: Vec<Vec<u8>> = call
        .arguments
        .iter()
        .map(|layout| encode_value_layout(layout).unwrap())
        .collect();
    let hostile = replace(&encoded, 2, &list_frame(0x5402, &raw_layouts));
    assert!(decode_call_abi(&hostile).is_err());
}

#[test]
fn signed_layout_pairing_is_exact_and_object_only_candidates_fail_closed() {
    let mut objects = minimal(1);
    objects.entrypoints.push(EntrypointDeclaration {
        name: "zap".into(),
        type_parameters: vec![],
        objects: vec![],
    });
    let call = CallAbi {
        objects,
        arguments: vec![ValueLayout::U64, ValueLayout::Bool],
    };
    let candidate = typed_candidate(&call);
    let interface = verify_publication_interface(candidate, vec![]).unwrap();
    let run = bind_object_signature(&interface, "run", &[]).unwrap();
    let zap = bind_object_signature(&interface, "zap", &[]).unwrap();
    let int = encode_call_value(&ValueLayout::U64, &CallValue::U64(42)).unwrap();
    assert_eq!(validate_call_arguments(&run, &int), Ok(()));
    assert!(validate_call_arguments(&zap, &int).is_err());
    assert_eq!(run.argument_layout(), &ValueLayout::U64);
    let old = raw_candidate(1, encode_package_abi(&minimal(1)).unwrap(), vec![]);
    assert!(matches!(
        verify_publication_interface(old, vec![]),
        Err(InterfaceError::Abi(_))
    ));
    let mut missing = call.clone();
    missing.arguments.pop();
    assert!(encode_call_abi(&missing).is_err());
    let encoded = encode_call_abi(&call).unwrap();
    assert!(decode_call_abi(&replace(&encoded, 2, &list_frame(0x5402, &[]))).is_err());
    let noargs = verify(minimal(1)).unwrap();
    let bound = bind_object_signature(&noargs, "run", &[]).unwrap();
    assert!(validate_call_arguments(&bound, &[]).is_err());
    assert_eq!(
        validate_call_arguments(
            &bound,
            &encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![])).unwrap()
        ),
        Ok(())
    );
}

#[test]
fn signature_binds_layout_changes_even_with_recomputed_artifact_digest() {
    let original = typed_candidate(&CallAbi {
        objects: minimal(1),
        arguments: vec![ValueLayout::U64],
    });
    let request = original.request();
    let a = request.artifact();
    let changed = CodeArtifact::new(ArtifactParts {
        context: a.context().clone(),
        origin: a.origin().clone(),
        revision: a.revision(),
        wasm_profile: a.wasm_profile(),
        semantics: *a.semantics(),
        wasm: a.wasm().to_vec(),
        exports: a.exports().to_vec(),
        unverified_dependencies: vec![],
        unverified_abi: encode_call_abi(&CallAbi {
            objects: minimal(1),
            arguments: vec![ValueLayout::Bool],
        })
        .unwrap(),
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &changed).unwrap();
    assert_ne!(&digest, request.artifact_digest());
    let tampered = PublicationRequest::new(changed, request.nonce(), digest, *request.signature());
    assert!(authenticate_publication(&resolver(), &context(), &semantics(), tampered).is_err());
}

#[test]
fn nested_headers_fields_and_list_counts_are_strict() {
    let l: ValueLayout = ValueLayout::Tuple(vec![ValueLayout::Bool]);
    let layout_bytes: Vec<u8> = encode_value_layout(&l).unwrap();
    let value_bytes: Vec<u8> =
        encode_call_value(&l, &CallValue::Tuple(vec![CallValue::Bool(false)])).unwrap();
    let call_bytes: Vec<u8> = encode_call_abi(&CallAbi {
        objects: minimal(1),
        arguments: vec![l.clone()],
    })
    .unwrap();
    for offset in [4, 6] {
        for (which, original) in [&layout_bytes, &value_bytes, &call_bytes]
            .into_iter()
            .enumerate()
        {
            let mut bad: Vec<u8> = original.clone();
            bad[offset] = 255;
            assert!(match which {
                0 => decode_value_layout(&bad).is_err(),
                1 => decode_call_value(&l, &bad).is_err(),
                _ => decode_call_abi(&bad).is_err(),
            });
        }
    }
    let scalar: Vec<u8> = raw_value(1, &[0, 0]);
    let valid_list: Vec<u8> = list_frame(0x5404, std::slice::from_ref(&scalar));
    for bad_list in [
        replace(&valid_list, 1, &2u16.to_le_bytes()),
        replace(&valid_list, 99, &scalar),
    ] {
        assert!(decode_call_value(&l, &raw_value(6, &bad_list)).is_err());
    }
    let mut duplicate: Vec<u8> = scalar.clone();
    duplicate[18..20].copy_from_slice(&1u16.to_le_bytes());
    let mut reversed: Vec<u8> = scalar[..10].to_vec();
    reversed.extend_from_slice(&scalar[18..]);
    reversed.extend_from_slice(&scalar[10..18]);
    for bad in [duplicate, reversed] {
        assert!(decode_call_value(&l, &raw_value(6, &list_frame(0x5404, &[bad]))).is_err());
    }
    let mut bad_layout: Vec<u8> = encode_value_layout(&ValueLayout::Bool).unwrap();
    bad_layout[16..18].copy_from_slice(&99u16.to_le_bytes());
    assert!(
        decode_value_layout(&replace(
            &layout_bytes,
            2,
            &list_frame(0x5402, &[bad_layout])
        ))
        .is_err()
    );
    let no_fields: Vec<u8> = CanonicalStruct::new(0x5401, 1).finish().unwrap();
    assert!(decode_value_layout(&no_fields).is_err());
}
