use abi::package_types::*;
use canonical_encoding::CanonicalStruct;
use protocol_types::ChainId;

fn chain() -> ChainId {
    ChainId::new("test").unwrap()
}
fn opaque() -> ScopedTypeArg {
    ScopedTypeArg::Opaque {
        domain: 9,
        value: [3; 32],
    }
}
fn nominal(args: Vec<ScopedTypeArg>) -> ScopedTypeArg {
    ScopedTypeArg::Nominal(Box::new(
        ScopedTypeTag::new(
            PackageOrigin::unverified(chain(), [7; 32], [1; 32]).unwrap(),
            1,
            args,
        )
        .unwrap(),
    ))
}

#[test]
fn ordered_arguments_roundtrip_without_nominal_wrapper() {
    for args in [
        vec![],
        vec![opaque()],
        vec![nominal(vec![opaque()]), opaque()],
    ] {
        let bytes: Vec<u8> = encode_scoped_type_arguments(&chain(), &args).unwrap();
        assert_eq!(
            decode_scoped_type_arguments(&chain(), &bytes).unwrap(),
            args
        );
        let mut trailing: Vec<u8> = bytes;
        trailing.push(0);
        assert!(decode_scoped_type_arguments(&chain(), &trailing).is_err());
    }
    let bytes: Vec<u8> = encode_scoped_type_arguments(&chain(), &[]).unwrap();
    assert_eq!(
        bytes,
        b"SNRE\x04\x52\x01\x00\x01\x00\x01\x00\x02\x00\x00\x00\x00\x00"
    );
}

#[test]
fn shared_node_count_count_bombs_and_chain_fail_closed() {
    // Each root has one argument node, one tag node and eight opaque nodes.
    let root: ScopedTypeArg = nominal(vec![opaque(); 8]);
    let accepted: Vec<ScopedTypeArg> = vec![root.clone(); 6];
    let bytes: Vec<u8> = encode_scoped_type_arguments(&chain(), &accepted).unwrap();
    assert_eq!(
        decode_scoped_type_arguments(&chain(), &bytes).unwrap(),
        accepted
    );
    assert!(matches!(
        encode_scoped_type_arguments(&chain(), &vec![root.clone(); 7]),
        Err(PackageTypeError::NodeLimitExceeded(_))
    ));
    // Manually build a forest whose individual roots are valid but aggregate is not.
    let tag: &ScopedTypeTag = match &root {
        ScopedTypeArg::Nominal(tag) => tag,
        _ => unreachable!(),
    };
    let mut arg: CanonicalStruct = CanonicalStruct::new(0x5202, 1);
    arg.field_u16(1, 1).unwrap();
    arg.field_bytes(2, encode_scoped_type_tag(tag).unwrap())
        .unwrap();
    let arg_bytes: Vec<u8> = arg.finish().unwrap();
    let mut list: CanonicalStruct = CanonicalStruct::new(0x5204, 1);
    list.field_u16(1, 7).unwrap();
    for id in 2..9 {
        list.field_bytes(id, arg_bytes.clone()).unwrap();
    }
    assert!(matches!(
        decode_scoped_type_arguments(&chain(), &list.finish().unwrap()),
        Err(PackageTypeError::NodeLimitExceeded(_))
    ));
    assert!(matches!(
        encode_scoped_type_arguments(&chain(), &vec![opaque(); 9]),
        Err(PackageTypeError::ArgCountLimitExceeded(9))
    ));
    let mut bomb: CanonicalStruct = CanonicalStruct::new(0x5204, 1);
    bomb.field_u16(1, u16::MAX).unwrap();
    assert!(matches!(
        decode_scoped_type_arguments(&chain(), &bomb.finish().unwrap()),
        Err(PackageTypeError::ArgCountLimitExceeded(_))
    ));
    let other: ChainId = ChainId::new("other").unwrap();
    assert!(matches!(
        decode_scoped_type_arguments(&other, &bytes),
        Err(PackageTypeError::ChainMismatch)
    ));
    assert!(matches!(
        encode_scoped_type_arguments(&other, &[root]),
        Err(PackageTypeError::ChainMismatch)
    ));
}

#[test]
fn malformed_and_oversized_lists_are_rejected() {
    assert!(decode_scoped_type_arguments(&chain(), &vec![0; MAX_SCOPED_TYPE_BYTES + 1]).is_err());
    for (id, version, count) in [(0x5204, 2, 0), (0x5203, 1, 0), (0x5204, 1, 1)] {
        let mut list: CanonicalStruct = CanonicalStruct::new(id, version);
        list.field_u16(1, count).unwrap();
        assert!(decode_scoped_type_arguments(&chain(), &list.finish().unwrap()).is_err());
    }
    for (variant, domain, len) in [(0, 9, 32), (3, 9, 32), (2, 0, 32), (2, 9, 31), (2, 9, 33)] {
        let mut arg: CanonicalStruct = CanonicalStruct::new(0x5202, 1);
        arg.field_u16(1, variant).unwrap();
        arg.field_u16(2, domain).unwrap();
        arg.field_bytes(3, vec![0; len]).unwrap();
        let mut list: CanonicalStruct = CanonicalStruct::new(0x5204, 1);
        list.field_u16(1, 1).unwrap();
        list.field_bytes(2, arg.finish().unwrap()).unwrap();
        assert!(decode_scoped_type_arguments(&chain(), &list.finish().unwrap()).is_err());
    }
    assert!(matches!(
        encode_scoped_type_arguments(
            &chain(),
            &[ScopedTypeArg::Opaque {
                domain: 0,
                value: [0; 32]
            }]
        ),
        Err(PackageTypeError::ZeroOpaqueDomain)
    ));
}
