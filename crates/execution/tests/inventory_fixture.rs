#[path = "common/inventory.rs"]
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
        inventory::warehouse(&root, &policy),
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
        assert!(imports.contains("call_dependency"));
        assert!(imports.contains("consume_object"));
        assert!(imports.contains("transfer_object"));
    }
    assert_eq!(packages[0].initializer.as_deref(), Some("init"));
    assert_eq!(packages[0].transferable_constructors, vec![4]);
    assert_eq!(packages[1].initializer, None);
    assert!(packages[1].transferable_constructors.is_empty());
    for (index, arguments) in [
        (0, inventory::tuple_arguments(&[])),
        (1, inventory::tuple_arguments(&[42, 100, 20])),
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
