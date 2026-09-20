use abi::package_types::PackageOrigin;
use execution::validate_contract_wasm_profile;
use protocol_types::ChainId;
use public_standard_asset::{
    ENTRYPOINTS, REQUIRED_WASM_PROFILE, StandardAssetPackage, build_package,
};
use sha2::{Digest, Sha256};

#[test]
fn generated_package_is_admissible_under_the_ordinary_profile() {
    let origin: PackageOrigin =
        PackageOrigin::unverified(ChainId::new("asset-test").unwrap(), [7; 32], [1; 32]).unwrap();
    let package: StandardAssetPackage = build_package(&origin).unwrap();
    validate_contract_wasm_profile(&package.wasm, &ENTRYPOINTS, REQUIRED_WASM_PROFILE).unwrap();
    assert_eq!(package.abi.results.len(), ENTRYPOINTS.len());
    assert_eq!(package.abi.transferable_constructors, vec![2]);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The generated core WASM is an origin-independent, protocol-relevant
/// build artifact (DR-0125): the pinned `wat` compiler version must keep
/// producing exactly these bytes for every publisher and instance. A
/// mismatch here means either the WAT source or the pinned compiler drifted
/// and requires an explicit reviewed change with regenerated evidence, not a
/// silent update.
#[test]
fn package_wasm_matches_the_permanent_sha256_vector() {
    let origin: PackageOrigin =
        PackageOrigin::unverified(ChainId::new("asset-wasm-vector").unwrap(), [7; 32], [1; 32])
            .unwrap();
    let package: StandardAssetPackage = build_package(&origin).unwrap();
    assert_eq!(package.wasm.len(), 3808);
    assert_eq!(
        hex(&Sha256::digest(&package.wasm)),
        "79255eb87298521ced82a66a05e7b8d24c27382fd616707802bb5e2a5141ff0c"
    );
}
