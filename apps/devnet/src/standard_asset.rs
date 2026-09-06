//! Canonical local-devnet Standard Asset v1 module identity and dev-profile
//! asset-creation provenance.
//!
//! Unlike the removed `sunrise.devnet.asset_account.v1` fixture (protocol-3,
//! deleted by this slice), this module never defines its own object bodies:
//! [`standard_assets::StandardAssetCoinV1`] and
//! [`standard_assets::StandardAssetTransferArgsV1`] are the sole wire types,
//! owned by the `standard-assets` crate. This module owns only the WASM
//! bytecode identity and the fixed development-profile asset-creation
//! provenance (creation authority + creation seed) `apps/devnet/src/genesis.rs`
//! uses to derive the devnet's one [`standard_assets::AssetId`] via
//! [`standard_assets::derive_asset_id`]. Protocol v5 adds a narrowly committed
//! `split` path that creates one more coin of that same `AssetId`; it does not
//! create a new asset identity (see DR-0107 and DR-0108).

use hashing::HashSuiteResolver;
use objects::Address;
use protocol_types::Epoch;
use standard_assets::{AssetCreationSeed, AssetId, StandardAssetError, derive_asset_id};

/// Preinstalled module name used by the local devnet catalog.
pub const MODULE_NAME: &str = "sunrise.devnet.standard_asset.v1";
/// Whole-coin owner-transition entrypoint retained by the local devnet module.
pub const TRANSFER_ENTRYPOINT: &str = "transfer";
/// Protocol-v5 partial-transfer entrypoint.
pub const SPLIT_ENTRYPOINT: &str = "split";
/// Protocol-v5 two-coin merge entrypoint.
pub const MERGE_ENTRYPOINT: &str = "merge";

/// SHA-256 of `sunrise.devnet.standard_asset.module.v1`, fixed as an opaque
/// dev-profile module identifier.
pub const STANDARD_ASSET_MODULE_ID_BYTES: [u8; 32] = [
    0x6B, 0x71, 0xF9, 0xD8, 0x7B, 0x0C, 0x78, 0x49, 0xF5, 0x0A, 0x0B, 0xF1, 0x15, 0x38, 0x60, 0x6B,
    0x9E, 0xA9, 0x18, 0x59, 0xB8, 0x4D, 0xB6, 0xF7, 0xC5, 0xEF, 0x7D, 0x6B, 0x7D, 0xB2, 0x59, 0x69,
];

/// SHA-256 of `sunrise.devnet.standard_asset.dev_creation_authority.v1`, fixed
/// as the devnet's one Standard Asset v1 creation authority. There is no
/// asset-definition or initial-issuance entrypoint, so this address never
/// signs a transaction; it exists purely as a stable derivation input for
/// [`derive_devnet_asset_id`].
pub const DEV_CREATION_AUTHORITY: Address = Address::new([
    0x60, 0x71, 0x5B, 0x94, 0x68, 0xF5, 0xBF, 0xEB, 0x96, 0x26, 0x1F, 0x2D, 0x4D, 0x07, 0xCA, 0xA3,
    0x45, 0x53, 0x40, 0x36, 0xE4, 0x4B, 0xAD, 0x20, 0xAF, 0x0D, 0xD6, 0xE1, 0x7B, 0xD6, 0xB5, 0x2A,
]);

/// SHA-256 of `sunrise.devnet.standard_asset.dev_creation_seed.v1`, fixed as
/// the devnet's one non-zero Standard Asset v1 creation seed (see
/// [`DEV_CREATION_AUTHORITY`]'s docs). Split coins retain the already verified
/// source coin's `AssetId`; this seed is not reused for per-coin identity.
pub const DEV_CREATION_SEED_BYTES: [u8; 32] = [
    0xA9, 0x9B, 0x68, 0xE6, 0x35, 0x0F, 0x84, 0x9B, 0xC0, 0x34, 0xA6, 0xCB, 0x93, 0xEF, 0x41, 0xB8,
    0xA9, 0x01, 0xD7, 0x43, 0x02, 0xD9, 0xC4, 0x5A, 0xEC, 0x82, 0x34, 0x5E, 0xF0, 0xE6, 0x19, 0xDF,
];

/// Returns the fixed, non-zero devnet Standard Asset v1 creation seed.
///
/// Construction remains fallible instead of asserting in a library path; the
/// stable test below pins that the compiled-in bytes satisfy the invariant.
pub fn dev_creation_seed() -> Result<AssetCreationSeed, StandardAssetError> {
    AssetCreationSeed::new(DEV_CREATION_SEED_BYTES)
}

/// Derives the devnet's one Standard Asset v1 [`AssetId`] from the fixed
/// [`DEV_CREATION_AUTHORITY`]/[`dev_creation_seed`] under `resolver`'s
/// chain/protocol-version context at `epoch`.
///
/// Changing `--chain-id`, `--epoch`, or the committed protocol version
/// changes the derived `AssetId` (see [`standard_assets::derive_asset_id`]);
/// this is a deliberate, documented consequence (DR-0107), not a defect.
pub fn derive_devnet_asset_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<AssetId, StandardAssetError> {
    let (asset_id, _algorithm) = derive_asset_id(
        resolver,
        epoch,
        DEV_CREATION_AUTHORITY,
        dev_creation_seed()?,
    )?;
    Ok(asset_id)
}

/// Exact committed WASM artifact generated from
/// [`STANDARD_ASSET_TRANSFER_WAT`].
pub const STANDARD_ASSET_TRANSFER_V1_WASM: &[u8] =
    include_bytes!("../modules/standard_asset_transfer.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_TRANSFER_WASM`].
pub const STANDARD_ASSET_TRANSFER_V1_WAT: &str =
    include_str!("../modules/standard_asset_transfer.wat");
/// Committed protocol-v5 module bytes, retaining `transfer` and adding
/// module-side `split` and `merge` arithmetic.
pub const STANDARD_ASSET_TRANSFER_WASM: &[u8] =
    include_bytes!("../modules/standard_asset_operations_v2.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_TRANSFER_WASM`].
pub const STANDARD_ASSET_TRANSFER_WAT: &str =
    include_str!("../modules/standard_asset_operations_v2.wat");

/// Exact canonical encoded length of a [`standard_assets::StandardAssetTransferArgsV1`]
/// frame.
///
/// [`STANDARD_ASSET_TRANSFER_WAT`] hardcodes this same value in its
/// `get_args_len` check; `tests::committed_transfer_args_length_matches_the_wat_and_wasm_contract`
/// pins that a freshly encoded args frame, this constant, and the WAT's
/// literal `48` never drift apart.
pub const STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE: usize = 48;
/// Exact encoded length of one `StandardAssetSplitArgsV1` frame.
pub const STANDARD_ASSET_SPLIT_MAX_INPUT_SIZE: usize = 62;

#[cfg(test)]
mod tests {
    use super::*;
    use execution::{ExecutionEngine, ExecutionStatus, ResolvedObject, WasmExecutionEngine};
    use objects::{AccessMode, Object, ObjectId, Owner};
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    };
    use standard_assets::{
        AssetId, StandardAssetCoinV1, StandardAssetSplitArgsV1, StandardAssetTransferArgsV1,
        decode_standard_asset_coin_v1, encode_standard_asset_coin_v1,
        encode_standard_asset_split_args_v1, encode_standard_asset_transfer_args_v1,
    };

    #[test]
    fn committed_wasm_exactly_matches_a_fresh_wat_parse() {
        let rebuilt: Vec<u8> =
            wat::parse_str(STANDARD_ASSET_TRANSFER_WAT).expect("valid committed WAT");
        assert_eq!(rebuilt, STANDARD_ASSET_TRANSFER_WASM);
    }

    #[test]
    fn committed_transfer_args_length_matches_the_wat_and_wasm_contract() {
        let args = StandardAssetTransferArgsV1::new(Address::new([0x41; 32]));
        let encoded: Vec<u8> = encode_standard_asset_transfer_args_v1(&args).unwrap();
        assert_eq!(encoded.len(), STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE);
        assert_eq!(
            u64::try_from(encoded.len()).unwrap(),
            crate::catalog::STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE
        );
        assert!(STANDARD_ASSET_TRANSFER_WAT.contains("i32.const 48"));
    }

    fn sample_resolved_object(id_byte: u8) -> ResolvedObject {
        ResolvedObject {
            object: Object {
                id: ObjectId::new([id_byte; 32]),
                version: 1,
                owner: Owner::Address(Address::new([id_byte; 32])),
                type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [id_byte; 32]),
                schema_version: 1,
                data: vec![id_byte; 8],
            },
            mode: AccessMode::Write,
        }
    }

    fn run_transfer_wasm(inputs: &[ResolvedObject], args: &[u8]) -> ExecutionStatus {
        let engine = WasmExecutionEngine;
        engine
            .execute(
                ProtocolVersion::new(4),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
                STANDARD_ASSET_TRANSFER_WASM,
                TRANSFER_ENTRYPOINT,
                inputs,
                args,
                1_000_000,
            )
            .unwrap()
            .status
    }

    #[test]
    fn transfer_wasm_accepts_exactly_two_objects_and_the_exact_args_length() {
        let inputs = vec![sample_resolved_object(0x01), sample_resolved_object(0x02)];
        let args = vec![0u8; STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE];
        assert_eq!(run_transfer_wasm(&inputs, &args), ExecutionStatus::Success);
    }

    #[test]
    fn transfer_wasm_rejects_the_wrong_object_count() {
        let args = vec![0u8; STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE];
        for inputs in [
            vec![sample_resolved_object(0x01)],
            vec![
                sample_resolved_object(0x01),
                sample_resolved_object(0x02),
                sample_resolved_object(0x03),
            ],
        ] {
            assert!(matches!(
                run_transfer_wasm(&inputs, &args),
                ExecutionStatus::Failure { .. }
            ));
        }
    }

    #[test]
    fn transfer_wasm_rejects_a_malformed_args_length() {
        let inputs = vec![sample_resolved_object(0x01), sample_resolved_object(0x02)];
        for bad_len in [
            STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE - 1,
            STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE + 1,
        ] {
            let args = vec![0u8; bad_len];
            assert!(matches!(
                run_transfer_wasm(&inputs, &args),
                ExecutionStatus::Failure { .. }
            ));
        }
    }

    fn coin_input(id_byte: u8, amount: u64, mode: AccessMode) -> ResolvedObject {
        let coin = StandardAssetCoinV1::new(AssetId::new([0xA1; 32]), amount).unwrap();
        ResolvedObject {
            object: Object {
                id: ObjectId::new([id_byte; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0x11; 32])),
                type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xA2; 32]),
                schema_version: 1,
                data: encode_standard_asset_coin_v1(&coin).unwrap(),
            },
            mode,
        }
    }

    #[test]
    fn split_wasm_checked_arithmetic_creates_recipient_coin() {
        let inputs = vec![
            coin_input(0x01, 100, AccessMode::Write),
            coin_input(0x02, 50, AccessMode::Write),
        ];
        let recipient = Address::new([0x44; 32]);
        let args = encode_standard_asset_split_args_v1(
            &StandardAssetSplitArgsV1::new(30, recipient).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(5),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
                STANDARD_ASSET_TRANSFER_WASM,
                SPLIT_ENTRYPOINT,
                &inputs,
                &args,
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 2);
        let execution::ObjectEffect::Mutated { new_object, .. } = &effects.object_effects[0] else {
            panic!("split must first mutate its source");
        };
        assert_eq!(
            decode_standard_asset_coin_v1(&new_object.data)
                .unwrap()
                .amount(),
            70
        );
        let execution::ObjectEffect::Created(created) = &effects.object_effects[1] else {
            panic!("split must create exactly one recipient coin");
        };
        assert_eq!(created.owner, Owner::Address(recipient));
        assert_eq!(
            decode_standard_asset_coin_v1(&created.data)
                .unwrap()
                .amount(),
            30
        );
    }

    #[test]
    fn merge_wasm_checked_add_consumes_secondary() {
        let inputs = vec![
            coin_input(0x01, 40, AccessMode::Write),
            coin_input(0x02, 60, AccessMode::Consume),
            coin_input(0x03, 50, AccessMode::Write),
        ];
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(5),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x78; 32]),
                STANDARD_ASSET_TRANSFER_WASM,
                MERGE_ENTRYPOINT,
                &inputs,
                &[],
                1_000_000,
            )
            .unwrap();
        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 2);
        let execution::ObjectEffect::Mutated { new_object, .. } = &effects.object_effects[0] else {
            panic!("merge must first mutate primary");
        };
        assert_eq!(
            decode_standard_asset_coin_v1(&new_object.data)
                .unwrap()
                .amount(),
            100
        );
        assert!(
            matches!(effects.object_effects[1], execution::ObjectEffect::Deleted { id, .. } if id == ObjectId::new([0x02; 32]))
        );
    }

    #[test]
    fn dev_creation_seed_is_valid_and_stable() {
        let seed = dev_creation_seed().unwrap();
        assert_eq!(seed.as_bytes(), &DEV_CREATION_SEED_BYTES);
    }

    fn test_resolver(chain: &str, protocol_version: u32) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(protocol_version),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    #[test]
    fn derived_asset_id_changes_with_chain_epoch_and_protocol_version() {
        let base = derive_devnet_asset_id(&test_resolver("chain-a", 4), Epoch::new(0)).unwrap();
        let other_chain =
            derive_devnet_asset_id(&test_resolver("chain-b", 4), Epoch::new(0)).unwrap();
        let other_epoch =
            derive_devnet_asset_id(&test_resolver("chain-a", 4), Epoch::new(1)).unwrap();
        let other_protocol =
            derive_devnet_asset_id(&test_resolver("chain-a", 5), Epoch::new(0)).unwrap();

        assert_ne!(base, other_chain);
        assert_ne!(base, other_epoch);
        assert_ne!(base, other_protocol);
    }

    #[test]
    fn derived_asset_id_is_deterministic() {
        let resolver = test_resolver("chain-a", 4);
        let first = derive_devnet_asset_id(&resolver, Epoch::new(3)).unwrap();
        let second = derive_devnet_asset_id(&resolver, Epoch::new(3)).unwrap();
        assert_eq!(first, second);
    }
}
