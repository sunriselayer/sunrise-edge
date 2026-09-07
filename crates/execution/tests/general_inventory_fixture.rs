#[path = "common/general_inventory.rs"]
mod inventory;

use abi::call_values::{decode_call_abi, decode_call_value, encode_call_abi};
use abi::package_types::PackageOrigin;
use protocol_types::ChainId;
use std::collections::BTreeSet;

#[test]
fn fixtures_have_canonical_abi_and_valid_typed_host_wasm() {
    let chain: ChainId = ChainId::new("inventory-test").unwrap();
    let root: PackageOrigin = PackageOrigin::unverified(chain.clone(), [7; 32], [1; 32]).unwrap();
    let policy: PackageOrigin = PackageOrigin::unverified(chain, [7; 32], [2; 32]).unwrap();
    let packages: Vec<inventory::InventoryPackage> = vec![
        inventory::warehouse(&root, &policy, 3),
        inventory::dispatch_policy(&policy),
    ];
    for package in &packages {
        wasmparser::Validator::new()
            .validate_all(&package.wasm)
            .unwrap();
        assert_eq!(wat::parse_str(&package.wat).unwrap(), package.wasm);
        let bytes: Vec<u8> = encode_call_abi(&package.abi).unwrap();
        assert_eq!(decode_call_abi(&bytes).unwrap(), package.abi);
        let mut corrupted: Vec<u8> = bytes;
        corrupted.push(0);
        assert!(decode_call_abi(&corrupted).is_err());
        let mut exports: BTreeSet<String> = BTreeSet::new();
        let mut imports: BTreeSet<String> = BTreeSet::new();
        for payload in wasmparser::Parser::new(0).parse_all(&package.wasm) {
            match payload.unwrap() {
                wasmparser::Payload::ImportSection(section) => {
                    for import in section {
                        let import = import.unwrap();
                        assert_eq!(import.module, "sunrise");
                        imports.insert(import.name.to_owned());
                    }
                }
                wasmparser::Payload::ExportSection(section) => {
                    for export in section {
                        let export = export.unwrap();
                        if export.name != "memory" {
                            exports.insert(export.name.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            exports,
            package
                .abi
                .objects
                .entrypoints
                .iter()
                .map(|entry| entry.name.clone())
                .collect()
        );
        assert_eq!(imports.len(), 14);
        assert!(imports.contains("call_contract"));
        assert!(imports.contains("consume_object"));
        assert!(imports.contains("transfer_object"));
    }
    assert_eq!(packages[0].initializer.as_deref(), Some("init"));
    assert_eq!(packages[0].transferable_constructors, vec![4]);
    assert_eq!(packages[1].initializer.as_deref(), Some("configure"));
    assert!(packages[1].transferable_constructors.is_empty());
    for (index, arguments) in [
        (0, inventory::tuple_arguments(&[])),
        (1, inventory::tuple_arguments(&[42, 100])),
        (2, inventory::tuple_arguments(&[1001, 12])),
        (3, inventory::recipient_argument([9; 32])),
    ] {
        decode_call_value(&packages[0].abi.arguments[index], &arguments).unwrap();
    }
    decode_call_value(
        &packages[1].abi.arguments[0],
        &inventory::scalar_argument(12),
    )
    .unwrap();
}

#[test]
fn dispatch_metadata_and_signed_selector_are_explicit() {
    use abi::call_values::ValueLayout;
    use abi::public_abi::ObjectMode;

    let chain: ChainId = ChainId::new("inventory-test").unwrap();
    let root: PackageOrigin = PackageOrigin::unverified(chain.clone(), [7; 32], [1; 32]).unwrap();
    let policy: PackageOrigin = PackageOrigin::unverified(chain, [7; 32], [2; 32]).unwrap();
    let warehouse: inventory::InventoryPackage = inventory::warehouse(&root, &policy, 15);
    let dispatch: inventory::InventoryPackage = inventory::dispatch_policy(&policy);
    assert_ne!(warehouse.wasm, inventory::warehouse(&root, &policy, 0).wasm);
    assert!(
        warehouse
            .wat
            .contains("(call $call (i32.const 15) (i32.const 512) (i32.const 1)")
    );
    let modes: Vec<ObjectMode> = warehouse.abi.objects.entrypoints[0]
        .objects
        .iter()
        .map(|object| object.mode)
        .collect();
    assert_eq!(
        modes,
        vec![ObjectMode::Read, ObjectMode::Consume, ObjectMode::Write]
    );
    assert_eq!(
        warehouse.abi.objects.entrypoints[0].objects[2].ty.origin,
        policy
    );
    assert_eq!(
        dispatch.abi.objects.entrypoints[0].objects[0].mode,
        ObjectMode::Write
    );
    assert_eq!(dispatch.abi.arguments[0], ValueLayout::U64);
    assert_eq!(dispatch.abi.bodies, vec![inventory::tuple_layout(2); 2]);

    // Verify the actual imported function type, not just a source substring.
    let mut types: Vec<wasmparser::FuncType> = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(&warehouse.wasm) {
        match payload.unwrap() {
            wasmparser::Payload::TypeSection(section) => {
                for ty in section.into_iter_err_on_gc_types() {
                    types.push(ty.unwrap());
                }
            }
            wasmparser::Payload::ImportSection(section) => {
                for import in section {
                    let import = import.unwrap();
                    if import.name == "call_contract" {
                        let wasmparser::TypeRef::Func(index) = import.ty else {
                            panic!("call_contract must be a function")
                        };
                        assert_eq!(
                            types[index as usize].params(),
                            &[wasmparser::ValType::I32; 5]
                        );
                        assert_eq!(types[index as usize].results(), &[wasmparser::ValType::I32]);
                    }
                }
            }
            _ => {}
        }
    }
}

#[test]
#[should_panic]
fn authorization_index_must_fit_the_host_integer() {
    let chain: ChainId = ChainId::new("inventory-test").unwrap();
    let origin: PackageOrigin = PackageOrigin::unverified(chain, [7; 32], [1; 32]).unwrap();
    let _package: inventory::InventoryPackage = inventory::warehouse(&origin, &origin, u32::MAX);
}
