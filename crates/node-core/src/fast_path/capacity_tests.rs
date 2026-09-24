//! Deterministic encoded-size inputs for the Phase 3 fee-claim capacity gate.
//! The sample chain id is fixed; these are not universal bounds, throughput,
//! or durability benchmarks.
use super::*;
use crate::fast_path::records::encode_fastpath_settlement_record;
use protocol_types::{HashAlgorithmId, ValidatorId};
use validator_set::ValidatorInfo;

#[test]
fn maximum_admitted_fee_share_row_and_claim_retention_are_measurable() {
    for (count, expected_row, expected_rewrites, expected_envelopes) in [
        (1usize, 458u64, 458u64, 201_728u64),
        (128, 10_110, 1_294_080, 25_821_184),
        (256, 19_838, 5_078_528, 51_642_368),
        (10_000, 760_382, 7_603_820_000, 2_017_280_000),
    ] {
        let mut shares: Vec<FastPathFeeShare> = Vec::with_capacity(count);
        for index in 0..count {
            let mut id: [u8; 32] = [0; 32];
            id[28..].copy_from_slice(&u32::try_from(index).unwrap().to_be_bytes());
            shares.push(FastPathFeeShare {
                validator_id: ValidatorId::new(id),
                amount: 1,
                claimed: false,
            });
        }
        let row: FastPathSettlementRecord = FastPathSettlementRecord {
            context: crate::genesis::tests::protocol(),
            request_id: [0x41; 32],
            generation: 1,
            resource_id: Some(BondResourceId::new(1, [0x42; 32]).unwrap()),
            fee_output: Some(ObjectRef {
                id: ObjectId::new([0x43; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
            }),
            fee_output_epoch: Some(crate::genesis::tests::protocol().epoch()),
            total_amount: Some(u64::try_from(count).unwrap()),
            shares,
        };
        let encoded: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
        let row_bytes: u64 = u64::try_from(encoded.len()).unwrap();
        let count_u64: u64 = u64::try_from(count).unwrap();
        let worst_case_row_rewrites: u64 = row_bytes.checked_mul(count_u64).unwrap();
        let worst_case_envelope_retention: u64 =
            u64::try_from(crate::fee_claims::codec::MAX_FEE_CLAIM_INTENT_BYTES)
                .unwrap()
                .checked_mul(count_u64)
                .unwrap();
        assert_eq!(row_bytes, expected_row, "validator count {count}");
        assert_eq!(worst_case_row_rewrites, expected_rewrites);
        assert_eq!(worst_case_envelope_retention, expected_envelopes);
        assert!(row_bytes < u64::try_from(runtime::MAX_STATE_VALUE_BYTES).unwrap());
        eprintln!(
            "fee-claim capacity: validators={count}, row_bytes={row_bytes}, upper_row_rewrite_bytes={worst_case_row_rewrites}, upper_retained_envelope_bytes={worst_case_envelope_retention}"
        );
    }
}

#[test]
fn fee_share_admission_cap_is_stricter_than_historical_decode_ceiling() {
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    let mut info: Vec<ValidatorInfo> = Vec::new();
    for index in 0..=records::MAX_FASTPATH_ACTIVE_VALIDATORS {
        let mut seed: [u8; 32] = [0; 32];
        seed[28..].copy_from_slice(&u32::try_from(index + 1).unwrap().to_be_bytes());
        let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(seed);
        let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
        let id: ValidatorId = ValidatorId::new(public_key);
        entries.push(FastPathValidatorEntry {
            id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        });
        info.push(ValidatorInfo {
            id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: public_key.to_vec(),
        });
    }
    entries.sort_by_key(|entry| entry.id);
    let historical: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: crate::genesis::tests::protocol(),
        validators: entries,
    };
    let encoded: Vec<u8> = records::encode_fastpath_validator_set_record(&historical).unwrap();
    assert_eq!(
        records::decode_fastpath_validator_set_record(&encoded).unwrap(),
        historical,
    );
    let admitted: ValidatorSet = ValidatorSet::new(
        historical.context.epoch(),
        info[..records::MAX_FASTPATH_ACTIVE_VALIDATORS].to_vec(),
    )
    .unwrap();
    assert_eq!(
        validator_fee_shares(&admitted, 256).unwrap().len(),
        records::MAX_FASTPATH_ACTIVE_VALIDATORS
    );
    let set: ValidatorSet = ValidatorSet::new(historical.context.epoch(), info).unwrap();
    assert!(matches!(
        validator_fee_shares(&set, 257),
        Err(FastPathError::Invalid(
            "fast-path active validator set exceeds the fee-claim capacity bound"
        ))
    ));
}
