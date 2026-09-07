use abi::package_types::{
    PackageOrigin, ScopedTypeArg, ScopedTypeTag, decode_package_origin, decode_scoped_type_tag,
    derive_scoped_type_id, encode_package_origin, encode_scoped_type_tag, verify_scoped_type_id,
};
use canonical_encoding::CanonicalStruct;
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule, ProtocolVersion,
};

fn origin(chain: &str, publisher: u8, seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(ChainId::new(chain).unwrap(), [publisher; 32], [seed; 32]).unwrap()
}

fn tag(package: PackageOrigin) -> ScopedTypeTag {
    ScopedTypeTag::new(
        package,
        7,
        vec![ScopedTypeArg::Opaque {
            domain: 2,
            value: [0x33; 32],
        }],
    )
    .unwrap()
}

fn resolver(chain: &str, version: u32) -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new(chain).unwrap(),
        ProtocolVersion::new(version),
        vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(5),
                suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
            },
        ],
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn frame(id: u16, version: u16, fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut canonical: CanonicalStruct = CanonicalStruct::new(id, version);
    for (field, bytes) in fields {
        canonical.field_bytes(*field, bytes.clone()).unwrap();
    }
    canonical.finish().unwrap()
}

fn origin_fields() -> Vec<(u16, Vec<u8>)> {
    vec![
        (1, b"test".to_vec()),
        (2, 1_u16.to_le_bytes().to_vec()),
        (3, vec![0x11; 32]),
        (4, vec![0x22; 32]),
    ]
}

fn tag_frame(origin_bytes: Vec<u8>, constructor: u16, count: u16, args: Vec<Vec<u8>>) -> Vec<u8> {
    let mut fields: Vec<(u16, Vec<u8>)> = vec![
        (1, origin_bytes),
        (2, constructor.to_le_bytes().to_vec()),
        (3, count.to_le_bytes().to_vec()),
    ];
    for (index, arg) in args.into_iter().enumerate() {
        fields.push((4 + u16::try_from(index).unwrap(), arg));
    }
    frame(0x5203, 1, &fields)
}

#[test]
fn stable_vectors_roundtrip_and_independently_calculated_digest() {
    // Expected bytes and SHA-256 were independently constructed from DR-0113
    // framing with Node Buffer/writeUIntLE and node:crypto, not this encoder.
    let package: PackageOrigin = origin("test", 0x11, 0x22);
    let value: ScopedTypeTag = tag(package.clone());
    let encoded_origin: Vec<u8> = encode_package_origin(&package).unwrap();
    assert_eq!(
        hex(&encoded_origin),
        "534e524501520100040001000400000074657374020002000000010003002000000011111111111111111111111111111111111111111111111111111111111111110400200000002222222222222222222222222222222222222222222222222222222222222222"
    );
    let encoded: Vec<u8> = encode_scoped_type_tag(&value).unwrap();
    assert_eq!(
        hex(&encoded),
        "534e5245035201000400010068000000534e52450152010004000100040000007465737402000200000001000300200000001111111111111111111111111111111111111111111111111111111111111111040020000000222222222222222222222222222222222222222222222222222222222222222202000200000007000300020000000100040040000000534e5245025201000300010002000000020002000200000002000300200000003333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(decode_package_origin(&encoded_origin).unwrap(), package);
    assert_eq!(decode_scoped_type_tag(&encoded).unwrap(), value);
    let digest = derive_scoped_type_id(&resolver("test", 1), Epoch::new(0), &value).unwrap();
    assert_eq!(
        hex(&digest.bytes()),
        "77175de6755490d93a4a947e4375c4a519ae5636019579ca6db7d49a3a2ed11a"
    );
}

#[test]
fn package_and_local_constructor_define_identity_not_code_revision_or_hash_algorithm() {
    let base: ScopedTypeTag = tag(origin("test", 0x11, 0x22));
    let schedule: HashSuiteResolver = resolver("test", 1);
    let old = derive_scoped_type_id(&schedule, Epoch::new(0), &base).unwrap();
    let new = derive_scoped_type_id(&schedule, Epoch::new(5), &base).unwrap();
    assert_ne!(old, new);
    assert!(verify_scoped_type_id(&schedule, &old, Epoch::new(5), &base).unwrap());
    assert!(verify_scoped_type_id(&schedule, &new, Epoch::new(5), &base).unwrap());
    assert!(verify_scoped_type_id(&schedule, &new, Epoch::new(0), &base).is_err());
    assert_eq!(
        new,
        derive_scoped_type_id(&resolver("test", 99), Epoch::new(5), &base).unwrap()
    );
    for different in [
        tag(origin("test", 0x12, 0x22)),
        tag(origin("test", 0x11, 0x23)),
        ScopedTypeTag::new(base.origin().clone(), 8, base.args().to_vec()).unwrap(),
    ] {
        assert_ne!(base, different);
        assert!(!verify_scoped_type_id(&schedule, &old, Epoch::new(5), &different).unwrap());
    }
    assert!(derive_scoped_type_id(&resolver("other", 1), Epoch::new(0), &base).is_err());
    assert!(verify_scoped_type_id(&resolver("other", 1), &old, Epoch::new(0), &base).is_err());
}

#[test]
fn nested_arguments_are_ordered_generic_and_chain_checked() {
    let package: PackageOrigin = origin("test", 0x11, 0x22);
    let nested: ScopedTypeTag = tag(origin("test", 0x44, 0x55));
    let args: Vec<ScopedTypeArg> = vec![
        ScopedTypeArg::Nominal(Box::new(nested)),
        ScopedTypeArg::Opaque {
            domain: 9,
            value: [7; 32],
        },
    ];
    let forward: ScopedTypeTag = ScopedTypeTag::new(package.clone(), 2, args.clone()).unwrap();
    let backward: ScopedTypeTag =
        ScopedTypeTag::new(package.clone(), 2, args.into_iter().rev().collect()).unwrap();
    assert_ne!(
        derive_scoped_type_id(&resolver("test", 1), Epoch::new(0), &forward).unwrap(),
        derive_scoped_type_id(&resolver("test", 1), Epoch::new(0), &backward).unwrap()
    );
    assert_eq!(
        decode_scoped_type_tag(&encode_scoped_type_tag(&forward).unwrap()).unwrap(),
        forward
    );
    let foreign: ScopedTypeTag = tag(origin("other", 1, 2));
    assert!(
        ScopedTypeTag::new(
            package.clone(),
            2,
            vec![ScopedTypeArg::Nominal(Box::new(foreign.clone()))]
        )
        .is_err()
    );
    let raw_arg: Vec<u8> = frame(
        0x5202,
        1,
        &[
            (1, 1_u16.to_le_bytes().to_vec()),
            (2, encode_scoped_type_tag(&foreign).unwrap()),
        ],
    );
    assert!(
        decode_scoped_type_tag(&tag_frame(
            encode_package_origin(&package).unwrap(),
            2,
            1,
            vec![raw_arg]
        ))
        .is_err()
    );
    let opaque: ScopedTypeArg = ScopedTypeArg::Opaque {
        domain: 1,
        value: [0; 32],
    };
    assert!(ScopedTypeTag::new(package, 1, vec![opaque.clone(), opaque]).is_ok());
}

#[test]
fn constructors_and_decoders_enforce_depth_arity_and_one_shared_node_budget() {
    let package: PackageOrigin = origin("test", 1, 0);
    let mut nested: ScopedTypeTag = ScopedTypeTag::new(package.clone(), 1, vec![]).unwrap();
    for _ in 1..4 {
        nested = ScopedTypeTag::new(
            package.clone(),
            1,
            vec![ScopedTypeArg::Nominal(Box::new(nested))],
        )
        .unwrap();
    }
    let encoded: Vec<u8> = encode_scoped_type_tag(&nested).unwrap();
    assert_eq!(decode_scoped_type_tag(&encoded).unwrap(), nested);
    assert!(
        ScopedTypeTag::new(
            package.clone(),
            1,
            vec![ScopedTypeArg::Nominal(Box::new(nested))]
        )
        .is_err()
    );
    let extra: Vec<u8> = frame(
        0x5202,
        1,
        &[(1, 1_u16.to_le_bytes().to_vec()), (2, encoded)],
    );
    assert!(
        decode_scoped_type_tag(&tag_frame(
            encode_package_origin(&package).unwrap(),
            1,
            1,
            vec![extra]
        ))
        .is_err()
    );
    let arg: ScopedTypeArg = ScopedTypeArg::Opaque {
        domain: 1,
        value: [0; 32],
    };
    assert!(ScopedTypeTag::new(package.clone(), 0, vec![]).is_err());
    assert!(
        ScopedTypeTag::new(
            package.clone(),
            1,
            vec![ScopedTypeArg::Opaque {
                domain: 0,
                value: [0; 32]
            }]
        )
        .is_err()
    );
    assert!(ScopedTypeTag::new(package.clone(), 1, vec![arg.clone(); 8]).is_ok());
    assert!(ScopedTypeTag::new(package.clone(), 1, vec![arg.clone(); 9]).is_err());
    // root 1 + seven (wrapper 1 + tag 1 + six opaque args) + one
    // (wrapper 1 + tag 1 + five args) = exactly 64 nodes.
    let six: ScopedTypeTag = ScopedTypeTag::new(package.clone(), 1, vec![arg.clone(); 6]).unwrap();
    let five: ScopedTypeTag = ScopedTypeTag::new(package.clone(), 1, vec![arg.clone(); 5]).unwrap();
    let mut args: Vec<ScopedTypeArg> = vec![ScopedTypeArg::Nominal(Box::new(six.clone())); 7];
    args.push(ScopedTypeArg::Nominal(Box::new(five)));
    let boundary: ScopedTypeTag = ScopedTypeTag::new(package.clone(), 1, args).unwrap();
    assert_eq!(
        decode_scoped_type_tag(&encode_scoped_type_tag(&boundary).unwrap()).unwrap(),
        boundary
    );
    assert!(
        ScopedTypeTag::new(
            package.clone(),
            1,
            vec![ScopedTypeArg::Nominal(Box::new(six.clone())); 8]
        )
        .is_err()
    );
    let raw_arg: Vec<u8> = frame(
        0x5202,
        1,
        &[
            (1, 1_u16.to_le_bytes().to_vec()),
            (2, encode_scoped_type_tag(&six).unwrap()),
        ],
    );
    assert!(
        decode_scoped_type_tag(&tag_frame(
            encode_package_origin(&package).unwrap(),
            1,
            8,
            vec![raw_arg; 8]
        ))
        .is_err()
    );
}

#[test]
fn malformed_canonical_shapes_and_count_bombs_fail_closed() {
    let valid: Vec<u8> = encode_scoped_type_tag(&tag(origin("test", 0x11, 0x22))).unwrap();
    for end in 0..valid.len() {
        assert!(
            decode_scoped_type_tag(&valid[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing: Vec<u8> = valid.clone();
    trailing.push(0);
    assert!(decode_scoped_type_tag(&trailing).is_err());
    assert!(decode_scoped_type_tag(&vec![0; 32769]).is_err());
    let package_bytes: Vec<u8> = encode_package_origin(&origin("test", 0x11, 0x22)).unwrap();
    for count in [9, u16::MAX] {
        assert!(
            decode_scoped_type_tag(&tag_frame(package_bytes.clone(), 1, count, vec![])).is_err()
        );
    }
    for raw_arg in [
        frame(0x5202, 1, &[(1, 0_u16.to_le_bytes().to_vec())]),
        frame(0x5202, 1, &[(1, 3_u16.to_le_bytes().to_vec())]),
        frame(
            0x5202,
            2,
            &[
                (1, 2_u16.to_le_bytes().to_vec()),
                (2, 1_u16.to_le_bytes().to_vec()),
                (3, vec![0; 32]),
            ],
        ),
        frame(
            0x5202,
            1,
            &[
                (1, 2_u16.to_le_bytes().to_vec()),
                (2, 0_u16.to_le_bytes().to_vec()),
                (3, vec![0; 32]),
            ],
        ),
        frame(
            0x5202,
            1,
            &[
                (1, 2_u16.to_le_bytes().to_vec()),
                (2, 1_u16.to_le_bytes().to_vec()),
                (3, vec![0; 31]),
            ],
        ),
        frame(
            0x5202,
            1,
            &[
                (1, 2_u16.to_le_bytes().to_vec()),
                (2, 1_u16.to_le_bytes().to_vec()),
                (3, vec![0; 32]),
                (4, vec![]),
            ],
        ),
        frame(
            0x5202,
            1,
            &[(1, 1_u16.to_le_bytes().to_vec()), (2, valid), (3, vec![])],
        ),
    ] {
        assert!(
            decode_scoped_type_tag(&tag_frame(package_bytes.clone(), 1, 1, vec![raw_arg])).is_err()
        );
    }
    assert!(decode_scoped_type_tag(&tag_frame(package_bytes.clone(), 0, 0, vec![])).is_err());
    // Count and actual framed argument fields must match exactly.
    assert!(decode_scoped_type_tag(&tag_frame(package_bytes.clone(), 1, 1, vec![])).is_err());
    assert!(decode_scoped_type_tag(&tag_frame(package_bytes, 1, 0, vec![vec![]])).is_err());
}

#[test]
fn origins_reject_bad_wire_shapes_without_claiming_authentication() {
    for field in 1..=4 {
        let fields: Vec<(u16, Vec<u8>)> = origin_fields()
            .into_iter()
            .filter(|(id, _)| *id != field)
            .collect();
        assert!(decode_package_origin(&frame(0x5201, 1, &fields)).is_err());
    }
    for (field, bytes) in [
        (1, vec![0xff]),
        (1, b" ".to_vec()),
        (1, vec![b'a'; 129]),
        (2, 0_u16.to_le_bytes().to_vec()),
        (2, 2_u16.to_le_bytes().to_vec()),
        (3, vec![1; 31]),
        (4, vec![2; 33]),
    ] {
        let mut fields: Vec<(u16, Vec<u8>)> = origin_fields();
        fields[usize::from(field - 1)] = (field, bytes);
        assert!(decode_package_origin(&frame(0x5201, 1, &fields)).is_err());
    }
    for (id, version) in [(0x5202, 1), (0x5201, 2)] {
        assert!(decode_package_origin(&frame(id, version, &origin_fields())).is_err());
    }
    let mut extra: Vec<(u16, Vec<u8>)> = origin_fields();
    extra.push((5, vec![]));
    assert!(decode_package_origin(&frame(0x5201, 1, &extra)).is_err());
    assert!(decode_package_origin(&vec![0; 257]).is_err());
    assert!(
        PackageOrigin::unverified(ChainId::new("a".repeat(129)).unwrap(), [0; 32], [0; 32])
            .is_err()
    );
    let max: PackageOrigin =
        PackageOrigin::unverified(ChainId::new("a".repeat(128)).unwrap(), [0; 32], [0; 32])
            .unwrap();
    assert_eq!(
        decode_package_origin(&encode_package_origin(&max).unwrap()).unwrap(),
        max
    );
    // Unverified references may contain non-owning keys; no signature/key
    // authority can be obtained from this value API.
    assert_eq!(max.publisher(), &[0; 32]);
    assert_eq!(max.seed(), &[0; 32]);
}
