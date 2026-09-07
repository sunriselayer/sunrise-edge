//! Independent review regression: every accepted result ABI must decode itself.
use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, decode_executable_abi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use abi::public_abi::{
    ArgumentKind, ConstructorDeclaration, EntrypointDeclaration, ObjectMode,
    ObjectResultDeclaration, PackageAbi, PatternArgument, TypePattern,
};
use protocol_types::ChainId;

#[test]
fn accepted_result_metadata_roundtrips_across_global_node_boundaries() {
    let origin: PackageOrigin =
        PackageOrigin::unverified(ChainId::new("a").unwrap(), [1; 32], [2; 32]).unwrap();
    let mut accepted: usize = 0;
    for arity in 0_u16..=8 {
        for count in 1_usize..=64 {
            let entries: Vec<EntrypointDeclaration> = (0..count)
                .map(|index: usize| EntrypointDeclaration {
                    name: format!("e{index:02}"),
                    type_parameters: vec![ArgumentKind::Opaque(1); usize::from(arity)],
                    objects: vec![],
                })
                .collect();
            let result: ObjectResultDeclaration = ObjectResultDeclaration {
                mode: ObjectMode::Read,
                schema: 1,
                ty: TypePattern {
                    origin: origin.clone(),
                    constructor: 1,
                    arguments: (0..arity).map(PatternArgument::Parameter).collect(),
                },
                optional: true,
            };
            let abi: ExecutableAbi = ExecutableAbi {
                call: CallAbi {
                    objects: PackageAbi {
                        origin: origin.clone(),
                        constructors: vec![ConstructorDeclaration {
                            local_id: 1,
                            schema: 1,
                            arguments: vec![ArgumentKind::Opaque(1); usize::from(arity)],
                        }],
                        entrypoints: entries,
                    },
                    arguments: vec![ValueLayout::Tuple(vec![]); count],
                    bodies: vec![ValueLayout::U64],
                },
                initializer: None,
                transferable_constructors: vec![],
                results: vec![vec![result; 4]; count],
            };
            // Oversize metadata may be rejected, but encoding must never emit
            // a representation which its own canonical decoder rejects.
            if let Ok(bytes) = encode_executable_abi(&abi) {
                accepted += 1;
                assert_eq!(
                    decode_executable_abi(&bytes),
                    Ok(abi),
                    "encoder/decoder disagree: arity={arity}, entrypoints={count}, bytes={}",
                    bytes.len(),
                );
            }
        }
    }
    assert!(accepted > 0);
}
