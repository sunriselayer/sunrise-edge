//! Deterministic encoded-size inputs for the Phase 3 fee-claim capacity gate.
//! The sample chain id is fixed; these are not universal bounds, throughput,
//! or durability benchmarks.
use super::*;
use crate::fast_path::records::encode_fastpath_settlement_record;
use crate::fee_claims::codec::{self, FeeClaimIntent, FeeClaimOperation, SignedFeeClaimIntent};
use crate::fee_claims::{fee_claim_intent_digest, fee_claim_signing_frame, handle_fee_claim};
use crate::local_instance_state::fastpath_fee_claim_key;
use execution::LocalWasmExecutionEngine;
use protocol_types::{HashAlgorithmId, ValidatorId};
use runtime::{DurableDomainStateStore, MemoryBlobStore, WriterFenceGeneration};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::time::{Duration, Instant};
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

/// One synthetic escrow row (generation 1, single zero-amount share) plus
/// its generation-2 claim envelope, durably set up in a real file-backed
/// [`SqliteDurableStore`] to isolate concurrent [`handle_fee_claim`] work.
struct CapacityEscrow {
    row_key: Vec<u8>,
    next_row_bytes: Vec<u8>,
    claim_key: Vec<u8>,
    signed: Vec<u8>,
}

/// Builds and durably records the generation-1 settlement row for one
/// distinct escrow, then returns the precomputed generation-2 zero-share
/// claim envelope that later races (across distinct rows, not the same row)
/// against every other escrow's claim under real concurrent SQLite writers.
///
/// The two-line derivations below duplicate `fee_claims::fee_claim_row_digest`
/// (`resolver.hash_for_purpose(epoch, HashPurpose::ExecutionEffects, bytes)`)
/// rather than calling it: that function is module-private to `fee_claims`
/// and this test lives in `fast_path`, mirroring the existing, deliberate
/// `object_ref` duplication documented in `fee_claims::recovery_tests`.
fn build_capacity_escrow<S: StructuredDurableDomainStateStore>(
    store: &S,
    zero_key: &ed25519_zebra::SigningKey,
    zero_id: ValidatorId,
    positive_id: ValidatorId,
    index: u32,
) -> CapacityEscrow {
    let chain_id: ChainId = crate::genesis::tests::chain();
    let op_context: DurableOperationContext = crate::genesis::tests::context(1);
    let atomic_domain: AtomicityDomainId = crate::genesis::tests::domain();
    let publication: PublicationContext = crate::genesis::tests::protocol();
    let hash_resolver: HashSuiteResolver = crate::genesis::tests::resolver();

    let mut escrow_request_id: [u8; 32] = [0xd2; 32];
    escrow_request_id[28..].copy_from_slice(&index.to_be_bytes());
    let resource_id: BondResourceId = BondResourceId::new(1, escrow_request_id).unwrap();
    let fee_output: ObjectRef = ObjectRef {
        id: ObjectId::new(escrow_request_id),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, escrow_request_id),
    };
    // A charged row requires a nonzero total; the untouched positive share
    // keeps this escrow's total_amount == 1 while the zero-amount share is
    // the one this test's claim actually finalizes, mirroring
    // `fee_claims::recovery_tests::zero_claim_fixture`.
    let mut shares: Vec<FastPathFeeShare> = vec![
        FastPathFeeShare {
            validator_id: positive_id,
            amount: 1,
            claimed: false,
        },
        FastPathFeeShare {
            validator_id: zero_id,
            amount: 0,
            claimed: false,
        },
    ];
    shares.sort_by_key(|share| share.validator_id);
    let row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: publication.clone(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(fee_output.clone()),
        fee_output_epoch: Some(publication.epoch()),
        total_amount: Some(1),
        shares,
    };
    let row_key: Vec<u8> = fastpath_settlement_key(&chain_id, &escrow_request_id).unwrap();
    let row_bytes: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
    let setup: AtomicStateTransaction = AtomicStateTransaction::new(
        atomic_domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(row_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(row_key.clone(), StateMutation::Put(row_bytes.clone()))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&op_context, setup),
        DurableCommitOutcome::Committed
    );

    let mut next_row: FastPathSettlementRecord = row.clone();
    next_row.generation = 2;
    next_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == zero_id)
        .unwrap()
        .claimed = true;
    let next_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();

    let previous_digest: Digest32 = hash_resolver
        .hash_for_purpose(
            publication.epoch(),
            HashPurpose::ExecutionEffects,
            &row_bytes,
        )
        .unwrap();
    let next_digest: Digest32 = hash_resolver
        .hash_for_purpose(
            publication.epoch(),
            HashPurpose::ExecutionEffects,
            &next_row_bytes,
        )
        .unwrap();

    let mut claim_request_id: [u8; 32] = [0xd3; 32];
    claim_request_id[28..].copy_from_slice(&index.to_be_bytes());
    let intent: FeeClaimIntent = FeeClaimIntent {
        context: publication.clone(),
        request_id: claim_request_id,
        escrow_request_id,
        certificate_epoch: publication.epoch(),
        validator_id: zero_id,
        resource_id,
        expected_generation: 1,
        expected_fee_output: fee_output,
        expected_previous_row_digest: previous_digest,
        expected_next_row_digest: next_digest,
        share_amount: 0,
        recipient: Address::new(claim_request_id),
        operation: FeeClaimOperation::ZeroShare,
    };
    let digest: Digest32 = fee_claim_intent_digest(&hash_resolver, &intent).unwrap();
    let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
    let signed: Vec<u8> = codec::encode_signed_fee_claim_intent(&SignedFeeClaimIntent {
        signature: zero_key.sign(&frame).into(),
        intent,
    })
    .unwrap();

    CapacityEscrow {
        row_key,
        next_row_bytes,
        claim_key: fastpath_fee_claim_key(&chain_id, &escrow_request_id, 2).unwrap(),
        signed,
    }
}

/// DR-0138 capacity evidence beyond static row-byte math: many distinct
/// escrow rows and their zero-share claims, driven through the real
/// `handle_fee_claim` path by several concurrent writer connections against
/// one real file-backed SQLite database, then a real close/reopen that
/// reads every row back. Rows are set up directly rather than through
/// certificate apply; the measured byte counts are logical retained value
/// payloads, not SQLite file size or write amplification. This remains one
/// process on one disk in one run: a bounded local harness, not a network
/// throughput or durability certification.
#[test]
fn file_backed_sqlite_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency() {
    const ESCROWS: u32 = 48;
    const WRITERS: usize = 6;
    assert_eq!(
        ESCROWS as usize % WRITERS,
        0,
        "evenly shardable escrow count"
    );

    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "fee-claim-capacity-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db_path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        crate::genesis::tests::chain(),
        ValidatorId::new([0xd0; 32]),
        crate::genesis::tests::domain(),
    );
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();

    let zero_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xd1; 32]);
    let zero_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&zero_key).into();
    let zero_id: ValidatorId = ValidatorId::new(zero_public);
    let positive_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xd4; 32]);
    let positive_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&positive_key).into();
    let positive_id: ValidatorId = ValidatorId::new(positive_public);

    let escrows: Vec<CapacityEscrow> = {
        let setup: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        let mut validators: Vec<FastPathValidatorEntry> = vec![
            FastPathValidatorEntry {
                id: zero_id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: zero_public.to_vec(),
            },
            FastPathValidatorEntry {
                id: positive_id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: positive_public.to_vec(),
            },
        ];
        validators.sort_by_key(|entry| entry.id);
        install_validator_set(
            &setup,
            &crate::genesis::tests::context(1),
            crate::genesis::tests::domain(),
            &crate::genesis::tests::resolver(),
            crate::genesis::tests::protocol(),
            validators,
        )
        .unwrap();
        (0..ESCROWS)
            .map(|index| build_capacity_escrow(&setup, &zero_key, zero_id, positive_id, index))
            .collect()
    };

    let shard_size: usize = ESCROWS as usize / WRITERS;
    let writer_stores: Vec<SqliteDurableStore> = (0..WRITERS)
        .map(|_| SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap())
        .collect();
    let concurrent_start: Instant = Instant::now();
    std::thread::scope(|scope| {
        for (writer, shard) in writer_stores.into_iter().zip(escrows.chunks(shard_size)) {
            scope.spawn(move || {
                for escrow in shard {
                    handle_fee_claim(
                        &writer,
                        &MemoryBlobStore::default(),
                        &crate::genesis::tests::context(1),
                        crate::genesis::tests::domain(),
                        &crate::genesis::tests::resolver(),
                        &[],
                        &crate::genesis::tests::protocol(),
                        &LocalExecutionPolicy::generic_object_results(
                            crate::genesis::tests::protocol(),
                        ),
                        &LocalWasmExecutionEngine::new(),
                        &escrow.signed,
                        12,
                    )
                    .unwrap();
                }
            });
        }
    });
    let concurrent_elapsed: Duration = concurrent_start.elapsed();

    let measured_claim_bytes: u64 = escrows
        .iter()
        .map(|escrow| escrow.signed.len() as u64)
        .sum();
    let measured_row_bytes: u64 = escrows
        .iter()
        .map(|escrow| escrow.next_row_bytes.len() as u64)
        .sum();

    let reopen_start: Instant = Instant::now();
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
    let mut read_claim_bytes: u64 = 0;
    let mut read_row_bytes: u64 = 0;
    for escrow in &escrows {
        let row: VersionedStateValue = reopened
            .get_versioned_durable(
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                &escrow.row_key,
            )
            .unwrap();
        assert_eq!(row.value(), Some(escrow.next_row_bytes.as_slice()));
        assert_eq!(row.revision(), StateRevision::new(2));
        let claim: VersionedStateValue = reopened
            .get_versioned_durable(
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                &escrow.claim_key,
            )
            .unwrap();
        assert_eq!(claim.value(), Some(escrow.signed.as_slice()));
        read_row_bytes += u64::try_from(row.value().unwrap().len()).unwrap();
        read_claim_bytes += u64::try_from(claim.value().unwrap().len()).unwrap();
    }
    let reopen_elapsed: Duration = reopen_start.elapsed();

    assert_eq!(read_claim_bytes, measured_claim_bytes);
    assert_eq!(read_row_bytes, measured_row_bytes);
    // A generous ceiling that only catches a catastrophic regression, not a
    // performance certification: one process, one disk, one run.
    assert!(
        reopen_elapsed < Duration::from_secs(30),
        "close/reopen + full read of {ESCROWS} rows took {reopen_elapsed:?}"
    );

    eprintln!(
        "fee-claim capacity: escrows={ESCROWS}, writers={WRITERS}, concurrent_commit_latency={concurrent_elapsed:?}, reopen_and_read_latency={reopen_elapsed:?}, measured_retained_claim_envelope_bytes={measured_claim_bytes}, measured_retained_settlement_row_bytes={measured_row_bytes}"
    );

    std::fs::remove_dir_all(&directory).unwrap();
}
