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
//! [`standard_assets::derive_asset_id`]. The canonical module begins at version
//! 1 with transfer, split, merge, bounded mint, and whole-coin burn. Earlier
//! development fixtures live under separate disabled module identifiers; they
//! do not consume versions in this module's namespace (see DR-0107--DR-0110).

use hashing::HashSuiteResolver;
use objects::Address;
use protocol_types::Epoch;
use standard_assets::{AssetCreationSeed, AssetId, StandardAssetError, derive_asset_id};

/// Canonical preinstalled Standard Asset module name.
pub const MODULE_NAME: &str = "sunrise.standard_asset.v1";
/// Whole-coin owner-transition entrypoint retained by the local devnet module.
pub const TRANSFER_ENTRYPOINT: &str = "transfer";
/// Partial-transfer entrypoint.
pub const SPLIT_ENTRYPOINT: &str = "split";
/// Two-coin merge entrypoint.
pub const MERGE_ENTRYPOINT: &str = "merge";
/// Supply-controlled mint entrypoint. Discarded development modules used a
/// capability-authorized entrypoint with the same name; they are isolated
/// under separate legacy module identifiers rather than versioned as part of
/// this canonical module (DR-0110).
pub const MINT_ENTRYPOINT: &str = "mint";
/// Whole-coin burn entrypoint, added alongside supply-controlled mint
/// (DR-0110).
pub const BURN_ENTRYPOINT: &str = "burn";

/// SHA-256 of `sunrise.standard_asset.v1`, fixed as the canonical module
/// identifier. This active module begins at version 1; discarded development
/// fixtures use separate legacy identifiers and do not consume its versions.
pub const STANDARD_ASSET_MODULE_ID_BYTES: [u8; 32] = [
    0xA9, 0x57, 0x34, 0xB4, 0xE6, 0xE4, 0x0E, 0x99, 0xA8, 0x0F, 0x5B, 0x4A, 0x32, 0xBD, 0xF6, 0xE7,
    0x7B, 0x49, 0xC0, 0x0A, 0x48, 0xBD, 0xDB, 0xDE, 0x3B, 0xE2, 0xBB, 0xD0, 0xF5, 0x09, 0x20, 0xFE,
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
/// [`STANDARD_ASSET_TRANSFER_V1_WAT`].
pub const STANDARD_ASSET_TRANSFER_V1_WASM: &[u8] =
    include_bytes!("../modules/standard_asset_transfer.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_TRANSFER_V1_WASM`].
pub const STANDARD_ASSET_TRANSFER_V1_WAT: &str =
    include_str!("../modules/standard_asset_transfer.wat");
/// Discarded development fixture containing `transfer`, `split`, and `merge`.
/// It is cataloged under a separate disabled legacy module identifier.
pub const STANDARD_ASSET_OPERATIONS_V2_WASM: &[u8] =
    include_bytes!("../modules/standard_asset_operations_v2.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_OPERATIONS_V2_WASM`].
pub const STANDARD_ASSET_OPERATIONS_V2_WAT: &str =
    include_str!("../modules/standard_asset_operations_v2.wat");
/// Discarded development fixture containing `transfer`, `split`, `merge`, and
/// the frozen capability-authorized `mint`. It is cataloged under a separate
/// disabled legacy module identifier (DR-0110).
pub const STANDARD_ASSET_OPERATIONS_V3_WASM: &[u8] =
    include_bytes!("../modules/standard_asset_operations_v3.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_OPERATIONS_V3_WASM`].
pub const STANDARD_ASSET_OPERATIONS_V3_WAT: &str =
    include_str!("../modules/standard_asset_operations_v3.wat");
/// Active canonical Standard Asset v1 module bytes, including transfer,
/// split, merge, supply-controlled `TreasuryCap<A>` mint, and whole-coin burn
/// (DR-0110).
pub const STANDARD_ASSET_MODULE_WASM: &[u8] = include_bytes!("../modules/standard_asset_v1.wasm");
/// Auditable WAT source for [`STANDARD_ASSET_MODULE_WASM`].
pub const STANDARD_ASSET_MODULE_WAT: &str = include_str!("../modules/standard_asset_v1.wat");

/// Exact canonical encoded length of a [`standard_assets::StandardAssetTransferArgsV1`]
/// frame.
///
/// [`STANDARD_ASSET_MODULE_WAT`] hardcodes this same value in its
/// `get_args_len` check; `tests::committed_transfer_args_length_matches_the_wat_and_wasm_contract`
/// pins that a freshly encoded args frame, this constant, and the WAT's
/// literal `48` never drift apart.
pub const STANDARD_ASSET_TRANSFER_MAX_INPUT_SIZE: usize = 48;
/// Exact encoded length of one `StandardAssetSplitArgsV1` frame.
pub const STANDARD_ASSET_SPLIT_MAX_INPUT_SIZE: usize = 62;
/// Exact encoded length of one `StandardAssetMintArgsV1` frame.
pub const STANDARD_ASSET_MINT_MAX_INPUT_SIZE: usize = 62;
/// Exact canonical encoded length of a `StandardAssetTreasuryCapV1` body:
/// header(10) + asset_id field(54) + total_supply field(14) + max_supply
/// field(14). [`STANDARD_ASSET_MODULE_WAT`]'s `mint`/`burn` entrypoints
/// hardcode this same value in their `get_object_data_len` checks.
pub const STANDARD_ASSET_TREASURY_CAP_ENCODED_LEN: usize = 92;
/// `burn` takes no canonical arguments.
pub const STANDARD_ASSET_BURN_MAX_INPUT_SIZE: usize = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use execution::{ExecutionEngine, ExecutionStatus, ResolvedObject, WasmExecutionEngine};
    use objects::{AccessMode, Object, ObjectId, Owner};
    use protocol_types::{
        ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    };
    use standard_assets::{
        AssetId, StandardAssetCoinV1, StandardAssetMintArgsV1, StandardAssetMintCapabilityV1,
        StandardAssetSplitArgsV1, StandardAssetTransferArgsV1, StandardAssetTreasuryCapV1,
        decode_standard_asset_coin_v1, encode_standard_asset_coin_v1,
        encode_standard_asset_mint_args_v1, encode_standard_asset_mint_capability_v1,
        encode_standard_asset_split_args_v1, encode_standard_asset_transfer_args_v1,
        encode_standard_asset_treasury_cap_v1,
    };

    #[test]
    fn committed_wasm_exactly_matches_a_fresh_wat_parse() {
        let rebuilt: Vec<u8> =
            wat::parse_str(STANDARD_ASSET_MODULE_WAT).expect("valid committed WAT");
        assert_eq!(rebuilt, STANDARD_ASSET_MODULE_WASM);
    }

    #[test]
    fn treasury_cap_encoded_length_matches_the_wat_contract() {
        let cap: StandardAssetTreasuryCapV1 =
            StandardAssetTreasuryCapV1::new(AssetId::new([0xA1; 32]), 100, 1_000).unwrap();
        let encoded: Vec<u8> = encode_standard_asset_treasury_cap_v1(&cap).unwrap();
        assert_eq!(encoded.len(), STANDARD_ASSET_TREASURY_CAP_ENCODED_LEN);
        assert!(STANDARD_ASSET_MODULE_WAT.contains("i32.const 92"));
    }

    #[test]
    fn committed_historical_v3_wasm_exactly_matches_a_fresh_wat_parse() {
        let rebuilt: Vec<u8> =
            wat::parse_str(STANDARD_ASSET_OPERATIONS_V3_WAT).expect("valid committed v3 WAT");
        assert_eq!(rebuilt, STANDARD_ASSET_OPERATIONS_V3_WASM);
    }

    #[test]
    fn committed_historical_v1_and_v2_wasm_exactly_match_a_fresh_wat_parse() {
        assert_eq!(
            wat::parse_str(STANDARD_ASSET_TRANSFER_V1_WAT).expect("valid committed v1 WAT"),
            STANDARD_ASSET_TRANSFER_V1_WASM
        );
        assert_eq!(
            wat::parse_str(STANDARD_ASSET_OPERATIONS_V2_WAT).expect("valid committed v2 WAT"),
            STANDARD_ASSET_OPERATIONS_V2_WASM
        );
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
        assert!(STANDARD_ASSET_MODULE_WAT.contains("i32.const 48"));
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
                STANDARD_ASSET_MODULE_WASM,
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
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
                STANDARD_ASSET_MODULE_WASM,
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
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x78; 32]),
                STANDARD_ASSET_MODULE_WASM,
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
    fn historical_v3_mint_wasm_creates_one_recipient_coin_from_capability_asset() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let capability: StandardAssetMintCapabilityV1 = StandardAssetMintCapabilityV1 { asset_id };
        let capability_input: ResolvedObject = ResolvedObject {
            object: Object {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0x11; 32])),
                type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xA3; 32]),
                schema_version: 1,
                data: encode_standard_asset_mint_capability_v1(&capability).unwrap(),
            },
            mode: AccessMode::Read,
        };
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let recipient: Address = Address::new([0x44; 32]);
        let args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(30, recipient).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(5),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]),
                STANDARD_ASSET_OPERATIONS_V3_WASM,
                MINT_ENTRYPOINT,
                &[capability_input, fee_input.clone()],
                &args,
                1_000_000,
            )
            .unwrap();

        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 1);
        let execution::ObjectEffect::Created(created) = &effects.object_effects[0] else {
            panic!("mint must create exactly one recipient coin");
        };
        assert_eq!(created.owner, Owner::Address(recipient));
        assert_eq!(created.type_hash, fee_input.object.type_hash);
        assert_eq!(created.schema_version, fee_input.object.schema_version);
        assert_eq!(
            decode_standard_asset_coin_v1(&created.data).unwrap(),
            StandardAssetCoinV1::new(asset_id, 30).unwrap()
        );
    }

    #[test]
    fn historical_v3_mint_wasm_rejects_zero_amount_wrong_count_and_malformed_inputs() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let capability: StandardAssetMintCapabilityV1 = StandardAssetMintCapabilityV1 { asset_id };
        let capability_input: ResolvedObject = ResolvedObject {
            object: Object {
                id: ObjectId::new([0x01; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0x11; 32])),
                type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xA3; 32]),
                schema_version: 1,
                data: encode_standard_asset_mint_capability_v1(&capability).unwrap(),
            },
            mode: AccessMode::Read,
        };
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let recipient: Address = Address::new([0x44; 32]);
        let valid_args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(30, recipient).unwrap(),
        )
        .unwrap();
        let run = |inputs: &[ResolvedObject], args: &[u8]| -> ExecutionStatus {
            WasmExecutionEngine
                .execute(
                    ProtocolVersion::new(5),
                    Digest32::new(HashAlgorithmId::Sha2_256, [0x7A; 32]),
                    STANDARD_ASSET_OPERATIONS_V3_WASM,
                    MINT_ENTRYPOINT,
                    inputs,
                    args,
                    1_000_000,
                )
                .unwrap()
                .status
        };

        let mut zero_args: Vec<u8> = valid_args.clone();
        zero_args[16..24].copy_from_slice(&0_u64.to_le_bytes());
        assert!(matches!(
            run(&[capability_input.clone(), fee_input.clone()], &zero_args),
            ExecutionStatus::Failure { .. }
        ));
        assert!(matches!(
            run(std::slice::from_ref(&capability_input), &valid_args),
            ExecutionStatus::Failure { .. }
        ));
        assert!(matches!(
            run(
                &[capability_input.clone(), fee_input.clone()],
                &valid_args[..STANDARD_ASSET_MINT_MAX_INPUT_SIZE - 1]
            ),
            ExecutionStatus::Failure { .. }
        ));
        let mut malformed_capability: ResolvedObject = capability_input;
        malformed_capability.object.data.pop();
        assert!(matches!(
            run(&[malformed_capability, fee_input], &valid_args),
            ExecutionStatus::Failure { .. }
        ));
    }

    fn treasury_cap_input(
        id_byte: u8,
        asset_id: AssetId,
        total_supply: u64,
        max_supply: u64,
        mode: AccessMode,
    ) -> ResolvedObject {
        let cap = StandardAssetTreasuryCapV1::new(asset_id, total_supply, max_supply).unwrap();
        ResolvedObject {
            object: Object {
                id: ObjectId::new([id_byte; 32]),
                version: 1,
                owner: Owner::Address(Address::new([0x11; 32])),
                type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xA4; 32]),
                schema_version: 1,
                data: encode_standard_asset_treasury_cap_v1(&cap).unwrap(),
            },
            mode,
        }
    }

    #[test]
    fn mint_wasm_checked_add_creates_coin_and_mutates_cap() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 100, 1000, AccessMode::Write);
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let recipient: Address = Address::new([0x44; 32]);
        let args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(30, recipient).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]),
                STANDARD_ASSET_MODULE_WASM,
                MINT_ENTRYPOINT,
                &[cap_input, fee_input.clone()],
                &args,
                1_000_000,
            )
            .unwrap();

        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 2);
        let execution::ObjectEffect::Mutated { new_object, .. } = &effects.object_effects[0] else {
            panic!("mint must first mutate the treasury cap");
        };
        assert_eq!(
            standard_assets::decode_standard_asset_treasury_cap_v1(&new_object.data).unwrap(),
            StandardAssetTreasuryCapV1::new(asset_id, 130, 1000).unwrap()
        );
        let execution::ObjectEffect::Created(created) = &effects.object_effects[1] else {
            panic!("mint must create exactly one recipient coin");
        };
        assert_eq!(created.owner, Owner::Address(recipient));
        assert_eq!(created.type_hash, fee_input.object.type_hash);
        assert_eq!(created.schema_version, fee_input.object.schema_version);
        assert_eq!(
            decode_standard_asset_coin_v1(&created.data).unwrap(),
            StandardAssetCoinV1::new(asset_id, 30).unwrap()
        );
    }

    #[test]
    fn mint_wasm_rejects_amount_exceeding_max_supply() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 990, 1000, AccessMode::Write);
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(20, Address::new([0x44; 32])).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]),
                STANDARD_ASSET_MODULE_WASM,
                MINT_ENTRYPOINT,
                &[cap_input, fee_input],
                &args,
                1_000_000,
            )
            .unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
    }

    #[test]
    fn mint_wasm_rejects_total_supply_overflow() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input =
            treasury_cap_input(0x01, asset_id, u64::MAX - 3, u64::MAX, AccessMode::Write);
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(10, Address::new([0x44; 32])).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]),
                STANDARD_ASSET_MODULE_WASM,
                MINT_ENTRYPOINT,
                &[cap_input, fee_input],
                &args,
                1_000_000,
            )
            .unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
    }

    #[test]
    fn mint_wasm_rejects_wrong_object_count_zero_amount_and_malformed_cap() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 100, 1000, AccessMode::Write);
        let fee_input: ResolvedObject = coin_input(0x02, 50, AccessMode::Write);
        let valid_args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(30, Address::new([0x44; 32])).unwrap(),
        )
        .unwrap();
        let run = |inputs: &[ResolvedObject], args: &[u8]| -> ExecutionStatus {
            WasmExecutionEngine
                .execute(
                    ProtocolVersion::new(6),
                    Digest32::new(HashAlgorithmId::Sha2_256, [0x7A; 32]),
                    STANDARD_ASSET_MODULE_WASM,
                    MINT_ENTRYPOINT,
                    inputs,
                    args,
                    1_000_000,
                )
                .unwrap()
                .status
        };

        assert!(matches!(
            run(std::slice::from_ref(&cap_input), &valid_args),
            ExecutionStatus::Failure { .. }
        ));

        let mut zero_args: Vec<u8> = valid_args.clone();
        zero_args[16..24].copy_from_slice(&0_u64.to_le_bytes());
        assert!(matches!(
            run(&[cap_input.clone(), fee_input.clone()], &zero_args),
            ExecutionStatus::Failure { .. }
        ));

        let mut malformed_cap: ResolvedObject = cap_input;
        malformed_cap.object.data.pop();
        assert!(matches!(
            run(&[malformed_cap, fee_input], &valid_args),
            ExecutionStatus::Failure { .. }
        ));
    }

    /// A treasury cap's 92-byte canonical body is never a valid 78-byte
    /// `Coin<A>` fee input: presenting one where the module expects the fee
    /// coin must fail closed, never silently coerce or misread cap fields as
    /// coin fields.
    #[test]
    fn mint_wasm_rejects_a_treasury_cap_presented_as_the_fee_coin() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 100, 1000, AccessMode::Write);
        let cap_as_fee_input = treasury_cap_input(0x02, asset_id, 100, 1000, AccessMode::Write);
        let args: Vec<u8> = encode_standard_asset_mint_args_v1(
            &StandardAssetMintArgsV1::new(30, Address::new([0x44; 32])).unwrap(),
        )
        .unwrap();
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x79; 32]),
                STANDARD_ASSET_MODULE_WASM,
                MINT_ENTRYPOINT,
                &[cap_input, cap_as_fee_input],
                &args,
                1_000_000,
            )
            .unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
    }

    #[test]
    fn burn_wasm_checked_sub_consumes_coin_and_mutates_cap() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 100, 1000, AccessMode::Write);
        let burned_input = coin_input(0x02, 40, AccessMode::Consume);
        let fee_input = coin_input(0x03, 50, AccessMode::Write);
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x80; 32]),
                STANDARD_ASSET_MODULE_WASM,
                BURN_ENTRYPOINT,
                &[cap_input, burned_input, fee_input],
                &[],
                1_000_000,
            )
            .unwrap();

        assert_eq!(effects.status, ExecutionStatus::Success);
        assert_eq!(effects.object_effects.len(), 2);
        let execution::ObjectEffect::Mutated { new_object, .. } = &effects.object_effects[0] else {
            panic!("burn must first mutate the treasury cap");
        };
        assert_eq!(
            standard_assets::decode_standard_asset_treasury_cap_v1(&new_object.data).unwrap(),
            StandardAssetTreasuryCapV1::new(asset_id, 60, 1000).unwrap()
        );
        assert!(matches!(
            effects.object_effects[1],
            execution::ObjectEffect::Deleted { id, .. } if id == ObjectId::new([0x02; 32])
        ));
    }

    #[test]
    fn burn_wasm_rejects_underflow() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 10, 1000, AccessMode::Write);
        let burned_input = coin_input(0x02, 40, AccessMode::Consume);
        let fee_input = coin_input(0x03, 50, AccessMode::Write);
        let effects = WasmExecutionEngine
            .execute(
                ProtocolVersion::new(6),
                Digest32::new(HashAlgorithmId::Sha2_256, [0x80; 32]),
                STANDARD_ASSET_MODULE_WASM,
                BURN_ENTRYPOINT,
                &[cap_input, burned_input, fee_input],
                &[],
                1_000_000,
            )
            .unwrap();
        assert!(matches!(effects.status, ExecutionStatus::Failure { .. }));
    }

    #[test]
    fn burn_wasm_rejects_wrong_object_count_and_nonempty_args() {
        let asset_id: AssetId = AssetId::new([0xA1; 32]);
        let cap_input = treasury_cap_input(0x01, asset_id, 100, 1000, AccessMode::Write);
        let burned_input = coin_input(0x02, 40, AccessMode::Consume);
        let fee_input = coin_input(0x03, 50, AccessMode::Write);
        let run = |inputs: &[ResolvedObject], args: &[u8]| -> ExecutionStatus {
            WasmExecutionEngine
                .execute(
                    ProtocolVersion::new(6),
                    Digest32::new(HashAlgorithmId::Sha2_256, [0x81; 32]),
                    STANDARD_ASSET_MODULE_WASM,
                    BURN_ENTRYPOINT,
                    inputs,
                    args,
                    1_000_000,
                )
                .unwrap()
                .status
        };

        assert!(matches!(
            run(&[cap_input.clone(), burned_input.clone()], &[]),
            ExecutionStatus::Failure { .. }
        ));
        assert!(matches!(
            run(
                &[cap_input, burned_input, fee_input],
                &[0u8; STANDARD_ASSET_BURN_MAX_INPUT_SIZE + 1]
            ),
            ExecutionStatus::Failure { .. }
        ));
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
