use super::*;
use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::ScopedTypeArg;
use abi::{AccessEntry, AccessManifest};
use execution::call::*;
use objects::{AccessMode, ObjectId, ObjectRef};

fn intent(code: UnverifiedDependencyRef) -> CallIntent {
    let key: SigningKey = SigningKey::from([7; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    CallIntent {
        context: context(),
        request_id: [3; 32],
        sender,
        nonce: 4,
        code,
        instance: InstanceTarget {
            creator: sender,
            seed: [2; 32],
            revision: 1,
            record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
        },
        entrypoint: "run".into(),
        type_arguments: vec![],
        access: AccessManifest { entries: vec![] },
        arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
            .unwrap(),
        gas_limit: 100,
    }
}
fn sign(intent: CallIntent) -> SignedCallIntent {
    let key: SigningKey = SigningKey::from([7; 32]);
    let signature: [u8; 64] = key
        .sign(&call_signing_frame(&context(), &intent).unwrap())
        .into();
    SignedCallIntent { intent, signature }
}
fn authenticate(signed: &SignedCallIntent) -> Result<AuthenticatedCallIntent, CallError> {
    authenticate_call_intent(&context(), &encode_signed_call_intent(signed)?)
}
fn exact() -> (VerifiedPublicationInterface, CallIntent) {
    let verified: VerifiedPublicationInterface = verify(minimal(1)).unwrap();
    let call: CallIntent = intent(reference(verified.candidate()));
    (verified, call)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn independent_call_intent_signature_vector_and_roundtrip() {
    let call: CallIntent =
        intent(UnverifiedDependencyRef::new(origin(1), 1, context(), semantics()).unwrap());
    let bytes: Vec<u8> = encode_call_intent(&call).unwrap();
    assert_eq!(decode_call_intent(&bytes).unwrap(), call);
    assert_eq!(bytes.len(), 691);
    assert_eq!(
        hex(&Sha256::digest(&bytes)),
        "1cadd5da6a108e7aa5e8e1946a9935a71da214824cab3db810a72af23f1c8487"
    );
    let frame: Vec<u8> = call_signing_frame(&context(), &call).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&frame)),
        "87044fa904b6282722a73670550544ed6c573b8ffe3261ec2f5c77e9bc4c1805"
    );
    let signed: SignedCallIntent = sign(call.clone());
    assert_eq!(
        hex(&signed.signature),
        "bcfb80b5d84df58cfb99bc9127c2af2b8c34abbd5790a49ac281b1df695d8d78d9381229a7caffb65c72618b299d0be515c23b81b07a1cea82eb4cb8191b6603"
    );
    let signed_bytes: Vec<u8> = encode_signed_call_intent(&signed).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&signed_bytes)),
        "c64e2ecb8d1bf71ab98962a652aad01ead5fd5fea9a4c5bbc9584ae4df594257"
    );
    assert_eq!(decode_signed_call_intent(&signed_bytes).unwrap(), signed);
    assert_eq!(authenticate(&signed).unwrap().intent(), &call);
}

#[test]
fn every_signed_component_rejects_substitution() {
    let (_, call) = exact();
    let signed: SignedCallIntent = sign(call.clone());
    let mut mutations: Vec<CallIntent> = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut c = call.clone();
            c.$field = $value;
            mutations.push(c);
        }};
    }
    changed!(request_id, [4; 32]);
    changed!(nonce, 5);
    changed!(gas_limit, 101);
    changed!(entrypoint, "other".into());
    changed!(
        sender,
        VerificationKey::from(&SigningKey::from([8; 32])).into()
    );
    changed!(
        arguments,
        encode_call_value(&ValueLayout::U64, &CallValue::U64(8)).unwrap()
    );
    changed!(
        type_arguments,
        vec![ScopedTypeArg::Opaque {
            domain: 9,
            value: [3; 32]
        }]
    );
    changed!(
        access,
        AccessManifest {
            entries: vec![AccessEntry {
                object_ref: ObjectRef {
                    id: ObjectId::new([1; 32]),
                    version: 1,
                    digest: semantics()
                },
                mode: AccessMode::Read
            }]
        }
    );
    for variant in 0..4 {
        let mut c: CallIntent = call.clone();
        match variant {
            0 => c.instance.creator = [8; 32],
            1 => c.instance.seed = [8; 32],
            2 => c.instance.revision = 2,
            _ => c.instance.record_digest = semantics(),
        }
        mutations.push(c);
    }
    for code in [
        UnverifiedDependencyRef::new(origin(2), 1, context(), *call.code.artifact_digest())
            .unwrap(),
        UnverifiedDependencyRef::new(origin(1), 2, context(), *call.code.artifact_digest())
            .unwrap(),
        UnverifiedDependencyRef::new(origin(1), 1, context(), semantics()).unwrap(),
        UnverifiedDependencyRef::new(
            origin(1),
            1,
            PublicationContext::new(
                ChainId::new("test").unwrap(),
                ProtocolVersion::new(2),
                Epoch::new(1),
            )
            .unwrap(),
            *call.code.artifact_digest(),
        )
        .unwrap(),
    ] {
        changed!(code, code);
    }
    for mutated in mutations {
        assert!(matches!(
            authenticate(&SignedCallIntent {
                intent: mutated,
                signature: signed.signature
            }),
            Err(CallError::InvalidSignature)
        ));
    }
}

#[test]
fn signature_domains_context_and_noncanonical_senders_fail_closed() {
    let (_, call) = exact();
    let signed: SignedCallIntent = sign(call.clone());
    for expected in [
        PublicationContext::new(
            ChainId::new("other").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
        )
        .unwrap(),
        PublicationContext::new(
            ChainId::new("test").unwrap(),
            ProtocolVersion::new(2),
            Epoch::new(0),
        )
        .unwrap(),
        PublicationContext::new(
            ChainId::new("test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
        )
        .unwrap(),
    ] {
        assert!(matches!(
            authenticate_call_intent(&expected, &encode_signed_call_intent(&signed).unwrap()),
            Err(CallError::ContextMismatch)
        ));
        assert!(matches!(
            call_signing_frame(&expected, &call),
            Err(CallError::ContextMismatch)
        ));
    }
    for sender in [[0; 32], [0xff; 32], {
        let mut x = [0; 32];
        x[0] = 1;
        x
    }] {
        let mut forged: SignedCallIntent = signed.clone();
        forged.intent.sender = sender;
        assert!(authenticate(&forged).is_err());
    }
    for message in ["CreatePackage", "transaction-v1", "submit-transaction-v1"] {
        let domain = crypto::SignatureDomain {
            chain_id: context().chain_id().clone(),
            protocol_version: context().protocol_version(),
            epoch: context().epoch(),
            message_type: crypto::SignatureMessageType::new(message).unwrap(),
            signature_scheme_id: protocol_types::SignatureSchemeId::Ed25519,
        };
        let frame =
            crypto::frame_signature_message(&domain, &encode_call_intent(&call).unwrap()).unwrap();
        let signature = SigningKey::from([7; 32]).sign(&frame).into();
        assert!(matches!(
            authenticate(&SignedCallIntent {
                intent: call.clone(),
                signature
            }),
            Err(CallError::InvalidSignature)
        ));
    }
}

#[test]
fn binding_uses_only_exact_signed_interface_and_arguments() {
    let (verified, call) = exact();
    let authenticated: AuthenticatedCallIntent = authenticate(&sign(call.clone())).unwrap();
    assert!(bind_authenticated_call(&authenticated, &verified).is_ok());
    let other: VerifiedPublicationInterface = verify(minimal(2)).unwrap();
    assert!(matches!(
        bind_authenticated_call(&authenticated, &other),
        Err(CallError::CodeMismatch)
    ));
    for variant in 0..5 {
        let mut bad: CallIntent = call.clone();
        match variant {
            0 => bad.entrypoint = "absent".into(),
            1 => {
                bad.type_arguments = vec![ScopedTypeArg::Opaque {
                    domain: 9,
                    value: [0; 32],
                }]
            }
            2 => bad.arguments = vec![],
            3 => bad.access.entries.push(AccessEntry {
                object_ref: ObjectRef {
                    id: ObjectId::new([1; 32]),
                    version: 1,
                    digest: semantics(),
                },
                mode: AccessMode::Read,
            }),
            _ => {
                bad.code = UnverifiedDependencyRef::new(
                    origin(1),
                    2,
                    context(),
                    *call.code.artifact_digest(),
                )
                .unwrap()
            }
        }
        let authenticated: AuthenticatedCallIntent = authenticate(&sign(bad)).unwrap();
        assert!(bind_authenticated_call(&authenticated, &verified).is_err());
    }
}

#[test]
fn typed_access_modes_match_signed_manifest_without_granting_ownership() {
    let verified: VerifiedPublicationInterface = verify(generic(1)).unwrap();
    let mut call: CallIntent = intent(reference(verified.candidate()));
    call.type_arguments = vec![ScopedTypeArg::Opaque {
        domain: 9,
        value: [3; 32],
    }];
    call.access.entries.push(AccessEntry {
        object_ref: ObjectRef {
            id: ObjectId::new([1; 32]),
            version: 1,
            digest: semantics(),
        },
        mode: AccessMode::Write,
    });
    for mode in [AccessMode::Write, AccessMode::Read, AccessMode::Consume] {
        call.access.entries[0].mode = mode;
        let authenticated: AuthenticatedCallIntent = authenticate(&sign(call.clone())).unwrap();
        assert_eq!(
            bind_authenticated_call(&authenticated, &verified).is_ok(),
            mode == AccessMode::Write
        );
    }
}

#[test]
fn signed_access_references_and_order_cannot_be_changed() {
    let (_, mut call) = exact();
    call.access.entries = (1..=2)
        .map(|id| AccessEntry {
            object_ref: ObjectRef {
                id: ObjectId::new([id; 32]),
                version: 1,
                digest: semantics(),
            },
            mode: AccessMode::Read,
        })
        .collect();
    let original: SignedCallIntent = sign(call);
    for change in 0..5 {
        let mut mutated: SignedCallIntent = original.clone();
        match change {
            0 => mutated.intent.access.entries.swap(0, 1),
            1 => mutated.intent.access.entries[0].object_ref.id = ObjectId::new([3; 32]),
            2 => mutated.intent.access.entries[0].object_ref.version = 2,
            3 => {
                mutated.intent.access.entries[0].object_ref.digest =
                    Digest32::new(HashAlgorithmId::Sha2_256, [3; 32])
            }
            _ => mutated.intent.access.entries[0].mode = AccessMode::Write,
        }
        assert!(matches!(
            authenticate(&mutated),
            Err(CallError::InvalidSignature)
        ));
    }
    let mut reused_id: CallIntent = original.intent;
    reused_id.access.entries[1].object_ref.id = reused_id.access.entries[0].object_ref.id;
    reused_id.access.entries[1].object_ref.version = 2;
    assert!(encode_call_intent(&reused_id).is_err());
}

#[test]
fn old_publication_context_is_pinned_not_rewritten_to_call_context() {
    let (verified, mut call) = exact();
    let upgraded: PublicationContext = PublicationContext::new(
        ChainId::new("test").unwrap(),
        ProtocolVersion::new(2),
        Epoch::new(5),
    )
    .unwrap();
    call.context = upgraded.clone();
    let key: SigningKey = SigningKey::from([7; 32]);
    let signature: [u8; 64] = key
        .sign(&call_signing_frame(&upgraded, &call).unwrap())
        .into();
    let bytes = encode_signed_call_intent(&SignedCallIntent {
        intent: call.clone(),
        signature,
    })
    .unwrap();
    let authenticated = authenticate_call_intent(&upgraded, &bytes).unwrap();
    assert!(bind_authenticated_call(&authenticated, &verified).is_ok());
    for code in [
        UnverifiedDependencyRef::new(origin(1), 1, upgraded.clone(), *call.code.artifact_digest())
            .unwrap(),
        UnverifiedDependencyRef::new(origin(1), 1, context(), semantics()).unwrap(),
    ] {
        let mut forged = call.clone();
        forged.code = code;
        let signature = key
            .sign(&call_signing_frame(&upgraded, &forged).unwrap())
            .into();
        let bytes = encode_signed_call_intent(&SignedCallIntent {
            intent: forged,
            signature,
        })
        .unwrap();
        let authenticated = authenticate_call_intent(&upgraded, &bytes).unwrap();
        assert!(matches!(
            bind_authenticated_call(&authenticated, &verified),
            Err(CallError::CodeMismatch)
        ));
    }
}

#[test]
fn bounded_strict_decoding_rejects_partial_and_extended_envelopes() {
    let (_, call) = exact();
    let bytes: Vec<u8> = encode_call_intent(&call).unwrap();
    let signed: Vec<u8> = encode_signed_call_intent(&sign(call.clone())).unwrap();
    for end in [0, 4, 9, bytes.len() - 1] {
        assert!(decode_call_intent(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode_call_intent(&extra).is_err());
    // Arguments are opaque until binding to the signed ABI, not defaulted here.
    for id in (1..=11).filter(|id| *id != 10) {
        assert!(decode_call_intent(&replace(&bytes, id, &[])).is_err());
    }
    let mut unknown: CanonicalStruct = CanonicalStruct::new(0x6402, 1);
    let f = decode_canonical_frame(&bytes).unwrap();
    for id in 1..=11 {
        unknown
            .field_bytes(id, f.required_field(id).unwrap())
            .unwrap();
    }
    unknown.field_u16(12, 1).unwrap();
    assert!(decode_call_intent(&unknown.finish().unwrap()).is_err());
    for version in [0, 2] {
        let mut b = bytes.clone();
        b[6..8].copy_from_slice(&u16::to_le_bytes(version));
        assert!(decode_call_intent(&b).is_err());
    }
    for len in [0, 63, 65] {
        assert!(decode_signed_call_intent(&replace(&signed, 2, &vec![0; len])).is_err());
    }
    assert!(decode_call_intent(&vec![0; MAX_CALL_INTENT_BYTES + 1]).is_err());
    let mut bad = call.clone();
    bad.arguments = vec![0; MAX_CALL_ARGUMENT_BYTES + 1];
    assert!(encode_call_intent(&bad).is_err());
    assert!(decode_call_intent(&replace(&bytes, 10, &bad.arguments)).is_err());
    let entry = AccessEntry {
        object_ref: ObjectRef {
            id: ObjectId::new([1; 32]),
            version: 1,
            digest: semantics(),
        },
        mode: AccessMode::Read,
    };
    bad = call.clone();
    bad.access.entries = vec![entry.clone(); 2];
    assert!(encode_call_intent(&bad).is_err());
    assert!(
        decode_call_intent(&replace(
            &bytes,
            9,
            &abi::encode_access_manifest(&bad.access).unwrap()
        ))
        .is_err()
    );
    bad.access.entries = vec![entry; 33];
    assert!(encode_call_intent(&bad).is_err());
    bad = call.clone();
    bad.gas_limit = 0;
    assert!(encode_call_intent(&bad).is_err());
    bad = call.clone();
    bad.instance.revision = 0;
    assert!(encode_call_intent(&bad).is_err());
    for name in [String::new(), "memory".into(), "x".repeat(65)] {
        bad = call.clone();
        bad.entrypoint = name;
        assert!(encode_call_intent(&bad).is_err());
    }
}
