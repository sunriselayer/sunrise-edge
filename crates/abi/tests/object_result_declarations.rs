//! Adversarial coverage for DR-0124 ordered typed object result declarations:
//! ABI shape/count bounds and aggregate node-budget alignment between
//! validation (encode-time) and decode-time parsing, so a value can never
//! pass `encode_executable_abi` and then fail `decode_executable_abi`.

use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, decode_executable_abi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use abi::public_abi::{
    ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectResultDeclaration, PackageAbi,
    PatternArgument, TypePattern,
};
use protocol_types::ChainId;

fn origin() -> PackageOrigin {
    PackageOrigin::unverified(ChainId::new("results-test").unwrap(), [7; 32], [9; 32]).unwrap()
}

fn opaque_leaf() -> PatternArgument {
    PatternArgument::Opaque {
        domain: 1,
        value: [0; 32],
    }
}

/// A wide (not deep) type pattern: 8 args at each of 3 nominal levels, with
/// opaque leaves at the third level. Node count = 1 + 8*(1 + (1 + 8*(1+0)))
/// = 657, comfortably under `MAX_ABI_TYPE_NODES` (1024) alone, but two such
/// declarations together exceed it — the shape stays within
/// `MAX_ABI_TYPE_DEPTH` (reaches depth 3, never depth 4).
fn heavy_pattern() -> TypePattern {
    let leaf = TypePattern {
        origin: origin(),
        constructor: 1,
        arguments: vec![opaque_leaf(); 8],
    };
    let mid = TypePattern {
        origin: origin(),
        constructor: 1,
        arguments: (0..8)
            .map(|_| PatternArgument::Nominal(Box::new(leaf.clone())))
            .collect(),
    };
    TypePattern {
        origin: origin(),
        constructor: 1,
        arguments: (0..8)
            .map(|_| PatternArgument::Nominal(Box::new(mid.clone())))
            .collect(),
    }
}

fn base_call(entrypoints: Vec<EntrypointDeclaration>) -> CallAbi {
    let entrypoint_count: usize = entrypoints.len();
    CallAbi {
        objects: PackageAbi {
            origin: origin(),
            constructors: vec![ConstructorDeclaration {
                local_id: 1,
                schema: 1,
                arguments: vec![],
            }],
            entrypoints,
        },
        arguments: vec![ValueLayout::Tuple(vec![]); entrypoint_count],
        bodies: vec![ValueLayout::U64],
    }
}

fn two_entrypoints() -> Vec<EntrypointDeclaration> {
    vec![
        EntrypointDeclaration {
            name: "a".into(),
            type_parameters: vec![],
            objects: vec![],
        },
        EntrypointDeclaration {
            name: "b".into(),
            type_parameters: vec![],
            objects: vec![],
        },
    ]
}

fn heavy_result() -> ObjectResultDeclaration {
    ObjectResultDeclaration {
        mode: ObjectMode::Read,
        schema: 1,
        ty: heavy_pattern(),
        optional: true,
    }
}

#[test]
fn one_heavy_declaration_alone_is_within_the_shared_node_budget() {
    let abi = ExecutableAbi {
        call: base_call(two_entrypoints()),
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![heavy_result()], vec![]],
    };
    let encoded = encode_executable_abi(&abi).unwrap();
    assert_eq!(decode_executable_abi(&encoded).unwrap(), abi);
}

#[test]
fn aggregate_node_budget_is_shared_across_entrypoints_not_reset_per_entry() {
    // Two entrypoints each declare one heavy result (~657 nodes); the
    // aggregate (~1314) exceeds MAX_ABI_TYPE_NODES even though each
    // individual entrypoint's own results would fit alone. Encoding must
    // fail closed here so no accepted value can ever be produced whose
    // bytes then fail to decode under the same shared-counter policy.
    let abi = ExecutableAbi {
        call: base_call(two_entrypoints()),
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![heavy_result()], vec![heavy_result()]],
    };
    assert!(encode_executable_abi(&abi).is_err());
}

#[test]
fn result_slot_count_is_bounded_to_four_per_entrypoint() {
    let mut abi: ExecutableAbi = ExecutableAbi {
        call: base_call(vec![EntrypointDeclaration {
            name: "a".into(),
            type_parameters: vec![],
            objects: vec![],
        }]),
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![
            ObjectResultDeclaration {
                mode: ObjectMode::Read,
                schema: 1,
                ty: TypePattern {
                    origin: origin(),
                    constructor: 1,
                    arguments: vec![],
                },
                optional: true,
            };
            5
        ]],
    };
    assert!(encode_executable_abi(&abi).is_err());
    // The otherwise identical four-slot ABI must encode and decode, proving
    // that the rejection above is the slot bound, not another shape mismatch.
    abi.results[0].pop();
    let encoded: Vec<u8> = encode_executable_abi(&abi).unwrap();
    assert_eq!(decode_executable_abi(&encoded).unwrap(), abi);
}

#[test]
fn empty_results_preserve_historical_version_one_bytes() {
    let mut abi = ExecutableAbi {
        call: base_call(vec![EntrypointDeclaration {
            name: "run".into(),
            type_parameters: vec![],
            objects: vec![],
        }]),
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![]],
    };
    abi.call.arguments = vec![ValueLayout::Tuple(vec![])];
    let v1_bytes = encode_executable_abi(&abi).unwrap();
    abi.results = vec![vec![ObjectResultDeclaration {
        mode: ObjectMode::Read,
        schema: 1,
        ty: TypePattern {
            origin: origin(),
            constructor: 1,
            arguments: vec![],
        },
        optional: true,
    }]];
    let v2_bytes = encode_executable_abi(&abi).unwrap();
    assert_ne!(v1_bytes, v2_bytes);
    assert!(v2_bytes.len() > v1_bytes.len());
    assert_eq!(
        decode_executable_abi(&v1_bytes).unwrap().results,
        vec![vec![]]
    );
    assert_eq!(decode_executable_abi(&v2_bytes).unwrap(), abi);
}
