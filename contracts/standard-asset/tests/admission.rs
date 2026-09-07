use abi::package_types::PackageOrigin;
use execution::validate_contract_wasm_profile;
use protocol_types::ChainId;
use public_standard_asset::{ENTRYPOINTS, REQUIRED_WASM_PROFILE, build_package};

#[test]
fn generated_package_is_admissible_under_the_ordinary_profile() {
    let origin: PackageOrigin =
        PackageOrigin::unverified(ChainId::new("asset-test").unwrap(), [7; 32], [1; 32]).unwrap();
    let package = build_package(&origin).unwrap();
    validate_contract_wasm_profile(&package.wasm, &ENTRYPOINTS, REQUIRED_WASM_PROFILE).unwrap();
    assert_eq!(package.abi.results.len(), ENTRYPOINTS.len());
    assert_eq!(package.abi.transferable_constructors, vec![2]);
}
