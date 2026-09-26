//! Deterministic encoded-size inputs for the Phase 3 fee-claim capacity gate.
//! The sample chain id is fixed; these are not universal bounds, throughput,
//! or durability benchmarks.
use super::*;
use crate::fast_path::records::encode_fastpath_settlement_record;
use crate::fee_claims::codec::{self, FeeClaimIntent, FeeClaimOperation, SignedFeeClaimIntent};
use crate::fee_claims::{fee_claim_intent_digest, fee_claim_signing_frame, handle_fee_claim};
use crate::local_instance_state::fastpath_fee_claim_key;
use abi::AccessManifest;
use abi::call_values::{CallValue, encode_call_value};
use execution::LocalWasmExecutionEngine;
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, ObjectAuthority, SignedLocalExecutionIntent,
    derive_local_created_object_id, encode_signed_local_execution, instance_target,
    local_execution_event_digest, local_execution_signing_frame,
};
use protocol_types::{HashAlgorithmId, ValidatorId};
use runtime::{
    DurableDomainStateStore, DurableObjectProvenance, DurableObjectRoutingProjection,
    MemoryBlobStore, WriterFenceGeneration,
};
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
    additional_zero_ids: &[ValidatorId],
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
    shares.extend(
        additional_zero_ids
            .iter()
            .copied()
            .map(|validator_id| FastPathFeeShare {
                validator_id,
                amount: 0,
                claimed: false,
            }),
    );
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
            .map(|index| build_capacity_escrow(&setup, &zero_key, zero_id, positive_id, index, &[]))
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

/// One synthetic escrow row backing a real object-mutating positive claim
/// (`Split` or `FinalTransfer`), durably set up in a real file-backed
/// [`SqliteDurableStore`]. Unlike [`CapacityEscrow`] (zero-share, no object
/// or nonce I/O), each of these routes through the real Standard Asset WASM
/// `split`/`transfer` entrypoints via [`handle_fee_claim`], so every escrow
/// carries its own distinct escrow coin object and its own distinct claim
/// sender/nonce identity -- reusing one shared sender across escrows would
/// serialize them on that sender's nonce sequence instead of exercising
/// genuinely independent concurrent writers.
struct PositiveCapacityEscrow {
    row_key: Vec<u8>,
    claim_key: Vec<u8>,
    claim_request_id: [u8; 32],
    signed: Vec<u8>,
    next_row_bytes: Vec<u8>,
    escrow_id: ObjectId,
    escrow_expected_version: u64,
    escrow_expected_bytes: Vec<u8>,
    /// `Some` only for a `Split` escrow: the newly created recipient-owned
    /// payout object distinct from the retained escrow. A `FinalTransfer`
    /// escrow instead turns the escrow object itself into the payout (same
    /// id, next version, owner now the recipient), so it has none.
    payout: Option<(ObjectId, Vec<u8>)>,
}

struct ExpectedPositiveObjects {
    escrow_bytes: Vec<u8>,
    escrow_version: u64,
    payout: Option<(ObjectId, Vec<u8>)>,
}

/// Duplicated from `fee_claims::recovery_tests::object_ref` rather than
/// shared across module boundaries, mirroring this file's existing,
/// deliberate duplication of `fee_claim_row_digest`'s two-line hash above.
fn positive_capacity_object_ref(object: &Object) -> ObjectRef {
    let bytes: Vec<u8> = objects::encode_object(object).unwrap();
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: crate::genesis::tests::resolver()
            .hash_for_purpose(
                crate::genesis::tests::protocol().epoch(),
                HashPurpose::Object,
                &bytes,
            )
            .unwrap(),
    }
}

/// Moves genesis coin object `coin_id` (already installed, `Address`-owned,
/// version 1, value `total_amount`) into `FeeEscrow` custody keyed on its
/// own distinct `escrow_request_id`, records its generation-1 settlement
/// row, then builds and signs the generation-2 positive claim envelope
/// (`Split` when `is_final` is false, `FinalTransfer` when true) that a
/// later real [`handle_fee_claim`] call finalizes. Mirrors
/// `fee_claims::recovery_tests::positive_claim_fixture`'s single-escrow
/// construction, generalized to one of several independent escrows.
#[allow(clippy::too_many_arguments)]
fn build_positive_capacity_escrow<S: StructuredDurableDomainStateStore>(
    store: &S,
    def_id: ObjectId,
    instance: &execution::local_execution::InstanceRecord,
    coin_template: &GenesisObjectEntry,
    coin_id: ObjectId,
    resource_id: BondResourceId,
    validator_a: ValidatorId,
    validator_a_key: &ed25519_zebra::SigningKey,
    second_validator: ValidatorId,
    index: u32,
    is_final: bool,
) -> PositiveCapacityEscrow {
    let resolver: HashSuiteResolver = crate::genesis::tests::resolver();
    let chain_id: ChainId = crate::genesis::tests::chain();
    let op_context: DurableOperationContext = crate::genesis::tests::context(1);
    let atomic_domain: AtomicityDomainId = crate::genesis::tests::domain();
    let publication: PublicationContext = crate::genesis::tests::protocol();
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(publication.clone());
    let total_amount: u64 = 1_000_000;

    let mut escrow_request_id: [u8; 32] = [0xe2; 32];
    escrow_request_id[28..].copy_from_slice(&index.to_be_bytes());

    let scope: objects::ProtocolCustodyScope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::FeeEscrow,
        chain_id: chain_id.clone(),
        subject: escrow_request_id,
        resource: *resource_id.value(),
    };
    let escrow: Object = Object {
        id: coin_id,
        version: 2,
        owner: Owner::ProtocolCustody(scope),
        type_hash: coin_template.object.type_hash,
        schema_version: coin_template.object.schema_version,
        data: encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(total_amount),
        )
        .unwrap(),
    };
    let escrow_ref: ObjectRef = positive_capacity_object_ref(&escrow);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        escrow.clone(),
        escrow_ref.digest,
        DurableObjectProvenance::new(chain_id.clone(), publication.protocol_version()),
        11,
    )
    .unwrap();
    let changes: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            coin_id,
            store
                .get_object_head(&op_context, atomic_domain, coin_id)
                .unwrap(),
        )],
        vec![DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Update {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(escrow.owner.clone())
                    .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let mut setup_request_id: [u8; 32] = [0xe4; 32];
    setup_request_id[28..].copy_from_slice(&index.to_be_bytes());
    let setup_receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(setup_request_id).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, setup_request_id),
        vec![0xe4],
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(
            &op_context,
            DurableInvocationTransaction::new(atomic_domain, None, changes, setup_receipt, None)
                .unwrap(),
        ),
        DurableCommitOutcome::Committed
    );

    let share_a: u64 = if is_final { total_amount } else { 300_000 };
    let mut shares: Vec<FastPathFeeShare> = vec![FastPathFeeShare {
        validator_id: validator_a,
        amount: share_a,
        claimed: false,
    }];
    if !is_final {
        shares.push(FastPathFeeShare {
            validator_id: second_validator,
            amount: total_amount - share_a,
            claimed: false,
        });
    }
    shares.sort_by_key(|share| share.validator_id);
    let row: FastPathSettlementRecord = FastPathSettlementRecord {
        context: publication.clone(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(resource_id),
        fee_output: Some(escrow_ref.clone()),
        fee_output_epoch: Some(publication.epoch()),
        total_amount: Some(total_amount),
        shares,
    };
    let row_key: Vec<u8> = fastpath_settlement_key(&chain_id, &escrow_request_id).unwrap();
    let row_bytes: Vec<u8> = encode_fastpath_settlement_record(&row).unwrap();
    let setup_row: AtomicStateTransaction = AtomicStateTransaction::new(
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
        store.commit_durable(&op_context, setup_row),
        DurableCommitOutcome::Committed
    );

    let mut recipient_seed: [u8; 32] = [0xe6; 32];
    recipient_seed[28..].copy_from_slice(&index.to_be_bytes());
    let recipient: Address = Address::new(
        ed25519_zebra::VerificationKey::from(&ed25519_zebra::SigningKey::from(recipient_seed))
            .into(),
    );

    let mut call_sender_seed: [u8; 32] = [0xe5; 32];
    call_sender_seed[28..].copy_from_slice(&index.to_be_bytes());
    let call_sender_key: ed25519_zebra::SigningKey =
        ed25519_zebra::SigningKey::from(call_sender_seed);
    let call_sender: [u8; 32] = ed25519_zebra::VerificationKey::from(&call_sender_key).into();

    let mut claim_request_id: [u8; 32] = [0xe3; 32];
    claim_request_id[28..].copy_from_slice(&index.to_be_bytes());

    let entrypoint: &str = if is_final { "transfer" } else { "split" };
    let arguments: Vec<u8> = if is_final {
        public_standard_asset::transfer_arguments(recipient.as_bytes()).unwrap()
    } else {
        public_standard_asset::split_arguments(share_a, recipient.as_bytes()).unwrap()
    };
    let instance_target: execution::call::InstanceTarget =
        instance_target(&resolver, instance).unwrap();
    let call: CallIntent = CallIntent {
        context: publication.clone(),
        request_id: claim_request_id,
        sender: call_sender,
        nonce: 0,
        code: instance.code.clone(),
        instance: instance_target.clone(),
        entrypoint: entrypoint.to_owned(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
        access: AccessManifest {
            entries: vec![AccessEntry {
                object_ref: escrow_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments,
        gas_limit: 500_000,
    };
    let leg_intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver).unwrap(),
        call,
        authorizations: Vec::new(),
    };
    let leg_frame: Vec<u8> = local_execution_signing_frame(&publication, &leg_intent).unwrap();
    let signed_leg: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        signature: call_sender_key.sign(&leg_frame).into(),
        intent: leg_intent,
    };
    let leg: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();

    let mut next_row: FastPathSettlementRecord = row.clone();
    next_row.generation = 2;
    next_row
        .shares
        .iter_mut()
        .find(|share| share.validator_id == validator_a)
        .unwrap()
        .claimed = true;

    let expected_objects: ExpectedPositiveObjects = if is_final {
        let mut transferred: Object = escrow.clone();
        transferred.version += 1;
        transferred.owner = Owner::Address(recipient);
        next_row.fee_output = Some(positive_capacity_object_ref(&transferred));
        ExpectedPositiveObjects {
            escrow_bytes: objects::encode_object(&transferred).unwrap(),
            escrow_version: transferred.version,
            payout: None,
        }
    } else {
        let mut retained: Object = escrow.clone();
        retained.version += 1;
        retained.data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(total_amount - share_a),
        )
        .unwrap();
        next_row.fee_output = Some(positive_capacity_object_ref(&retained));

        let leg_digest: Digest32 = local_execution_event_digest(&resolver, &signed_leg).unwrap();
        let payout_id: ObjectId = derive_local_created_object_id(
            &resolver,
            &publication,
            &instance.context,
            &instance_target,
            &instance.code,
            leg_digest,
            0,
        )
        .unwrap();
        let payout: Object = Object {
            id: payout_id,
            version: 1,
            owner: Owner::Address(recipient),
            type_hash: escrow.type_hash,
            schema_version: escrow.schema_version,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(share_a),
            )
            .unwrap(),
        };
        ExpectedPositiveObjects {
            escrow_bytes: objects::encode_object(&retained).unwrap(),
            escrow_version: retained.version,
            payout: Some((payout_id, objects::encode_object(&payout).unwrap())),
        }
    };
    let next_row_bytes: Vec<u8> = encode_fastpath_settlement_record(&next_row).unwrap();

    let previous_digest: Digest32 = resolver
        .hash_for_purpose(
            publication.epoch(),
            HashPurpose::ExecutionEffects,
            &row_bytes,
        )
        .unwrap();
    let next_digest: Digest32 = resolver
        .hash_for_purpose(
            publication.epoch(),
            HashPurpose::ExecutionEffects,
            &next_row_bytes,
        )
        .unwrap();

    let operation: FeeClaimOperation = if is_final {
        FeeClaimOperation::FinalTransfer { leg }
    } else {
        let (payout_id, payout_bytes): &(ObjectId, Vec<u8>) = expected_objects
            .payout
            .as_ref()
            .expect("split payout fixture");
        FeeClaimOperation::Split {
            leg,
            expected_payout: Some(ObjectRef {
                id: *payout_id,
                version: 1,
                digest: resolver
                    .hash_for_purpose(publication.epoch(), HashPurpose::Object, payout_bytes)
                    .unwrap(),
            }),
        }
    };
    let intent: FeeClaimIntent = FeeClaimIntent {
        context: publication.clone(),
        request_id: claim_request_id,
        escrow_request_id,
        certificate_epoch: publication.epoch(),
        validator_id: validator_a,
        resource_id,
        expected_generation: 1,
        expected_fee_output: escrow_ref,
        expected_previous_row_digest: previous_digest,
        expected_next_row_digest: next_digest,
        share_amount: share_a,
        recipient,
        operation,
    };
    let digest: Digest32 = fee_claim_intent_digest(&resolver, &intent).unwrap();
    let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
    let signed: Vec<u8> = codec::encode_signed_fee_claim_intent(&SignedFeeClaimIntent {
        signature: validator_a_key.sign(&frame).into(),
        intent,
    })
    .unwrap();

    PositiveCapacityEscrow {
        row_key,
        claim_key: fastpath_fee_claim_key(&chain_id, &escrow_request_id, 2).unwrap(),
        claim_request_id,
        signed,
        next_row_bytes,
        escrow_id: coin_id,
        escrow_expected_version: expected_objects.escrow_version,
        escrow_expected_bytes: expected_objects.escrow_bytes,
        payout: expected_objects.payout,
    }
}

/// DR-0138 capacity evidence for the *positive* (object-mutating) fee-claim
/// path, complementing the zero-share capacity test above: several distinct
/// escrows, half finalized through `split` and half through `transfer`,
/// each a real Standard Asset WASM call driven through the real
/// `handle_fee_claim` pipeline by several concurrent writer connections
/// against one real file-backed SQLite database, then a real close/reopen
/// that reads every settlement row, claim envelope, escrow/payout object
/// and outer receipt back. Rows and escrow objects are set up directly
/// (mutating genesis-installed objects, not through certificate apply); the
/// measured logical byte counts are retained value payloads, while the
/// physical SQLite/WAL byte counts are the actual on-disk file sizes at
/// each phase. This remains one process on one disk in one run: a bounded
/// local diagnostic harness, not a network throughput or durability
/// certification.
#[test]
fn file_backed_sqlite_concurrent_positive_claims_measure_retained_bytes_and_physical_footprint() {
    const ESCROWS: u32 = 12;
    const WRITERS: usize = 3;
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
        "fee-claim-positive-capacity-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let db_path: std::path::PathBuf = directory.join("state.sqlite");
    let namespace: SqliteNamespace = SqliteNamespace::new(
        crate::genesis::tests::chain(),
        ValidatorId::new([0xe9; 32]),
        crate::genesis::tests::domain(),
    );
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let file_bytes = |suffix: &str| -> u64 {
        std::fs::metadata(format!("{}{suffix}", db_path.display()))
            .map(|metadata| metadata.len())
            .unwrap_or(0)
    };

    let (_base_manifest, _origin, instance, def_id, _coin_id) =
        crate::genesis::tests::build_fixture();
    let mut manifest: GenesisManifest =
        crate::genesis::tests::manifest_with_custody(ObjectId::new([0xe1; 32]));
    let second_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xe7; 32]);
    let second_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&second_key).into();
    let second_validator: ValidatorId = ValidatorId::new(second_public);
    let mut second_bond: GenesisObjectEntry = crate::genesis::tests::custody_object_entry(
        &manifest,
        ObjectId::new([0xe8; 32]),
        crate::genesis::tests::chain(),
    );
    let Owner::ProtocolCustody(second_scope) = &mut second_bond.object.owner else {
        panic!("second bond custody owner");
    };
    second_scope.subject = second_public;
    manifest.objects.push(second_bond);
    manifest
        .validator_set
        .validators
        .push(FastPathValidatorEntry {
            id: second_validator,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: second_public.to_vec(),
        });
    manifest
        .validator_set
        .validators
        .sort_by_key(|entry| entry.id);

    let coin_template: GenesisObjectEntry = manifest.objects[1].clone();
    let mut coin_ids: Vec<ObjectId> = Vec::with_capacity(ESCROWS as usize);
    for index in 0..ESCROWS {
        let mut coin_id_bytes: [u8; 32] = [0xe0; 32];
        coin_id_bytes[28..].copy_from_slice(&index.to_be_bytes());
        let coin_id: ObjectId = ObjectId::new(coin_id_bytes);
        coin_ids.push(coin_id);
        manifest.objects.push(GenesisObjectEntry {
            object: Object {
                id: coin_id,
                version: 1,
                owner: Owner::Address(Address::new(crate::genesis::tests::sender())),
                type_hash: coin_template.object.type_hash,
                schema_version: coin_template.object.schema_version,
                data: encode_call_value(
                    &public_standard_asset::coin_body_layout(),
                    &CallValue::U64(1_000_000),
                )
                .unwrap(),
            },
            authority: ObjectAuthority {
                object_id: coin_id,
                instance_context: coin_template.authority.instance_context.clone(),
                instance: coin_template.authority.instance.clone(),
                code: coin_template.authority.code.clone(),
                ty: coin_template.authority.ty.clone(),
            },
        });
    }
    crate::genesis::tests::resign_manifest(&mut manifest);

    let resource_id: BondResourceId = manifest.economics_policy.resources[0].resource_id;
    let validator_a: ValidatorId = ValidatorId::new(crate::genesis::tests::sender());
    let validator_a_key: ed25519_zebra::SigningKey = crate::genesis::tests::key();

    let escrows: Vec<PositiveCapacityEscrow> = {
        let setup: SqliteDurableStore =
            SqliteDurableStore::open(&db_path, namespace.clone(), fence).unwrap();
        install_genesis(
            &setup,
            &crate::genesis::tests::context(1),
            crate::genesis::tests::domain(),
            &crate::genesis::tests::resolver(),
            &manifest,
            10,
        )
        .unwrap();
        (0..ESCROWS)
            .map(|index| {
                build_positive_capacity_escrow(
                    &setup,
                    def_id,
                    &instance,
                    &coin_template,
                    coin_ids[index as usize],
                    resource_id,
                    validator_a,
                    &validator_a_key,
                    second_validator,
                    index,
                    index % 2 == 1,
                )
            })
            .collect()
    };
    let setup_db_bytes: u64 = file_bytes("");
    let setup_wal_bytes: u64 = file_bytes("-wal");

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
    let committed_db_bytes: u64 = file_bytes("");
    let committed_wal_bytes: u64 = file_bytes("-wal");

    let measured_claim_bytes: u64 = escrows
        .iter()
        .map(|escrow| escrow.signed.len() as u64)
        .sum();
    let measured_row_bytes: u64 = escrows
        .iter()
        .map(|escrow| escrow.next_row_bytes.len() as u64)
        .sum();
    let measured_escrow_bytes: u64 = escrows
        .iter()
        .map(|escrow| escrow.escrow_expected_bytes.len() as u64)
        .sum();
    let measured_payout_bytes: u64 = escrows
        .iter()
        .filter_map(|escrow| escrow.payout.as_ref())
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();

    let reopen_start: Instant = Instant::now();
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&db_path, namespace, fence).unwrap();
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

        let head: DurableObjectHead = reopened
            .get_object_head(
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                escrow.escrow_id,
            )
            .unwrap();
        let DurableObjectHead::Current {
            object_version,
            digest,
            ..
        } = head
        else {
            panic!("positive capacity escrow must retain a current object");
        };
        assert_eq!(object_version.get(), escrow.escrow_expected_version);
        let record: DurableObjectVersionRecord = reopened
            .get_object_version(
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                escrow.escrow_id,
                object_version,
            )
            .unwrap()
            .unwrap();
        assert_eq!(record.digest(), digest);
        let runtime::DurableObjectPayload::Inline(inline) = record.payload() else {
            panic!("positive capacity escrow must keep the object inline");
        };
        assert_eq!(
            inline.canonical_bytes(),
            escrow.escrow_expected_bytes.as_slice()
        );

        if let Some((payout_id, payout_bytes)) = &escrow.payout {
            let payout_head: DurableObjectHead = reopened
                .get_object_head(
                    &crate::genesis::tests::context(1),
                    crate::genesis::tests::domain(),
                    *payout_id,
                )
                .unwrap();
            let DurableObjectHead::Current {
                object_version: payout_version,
                digest: payout_digest,
                ..
            } = payout_head
            else {
                panic!("positive capacity split claim must create a payout object");
            };
            assert_eq!(payout_version.get(), 1);
            let payout_record: DurableObjectVersionRecord = reopened
                .get_object_version(
                    &crate::genesis::tests::context(1),
                    crate::genesis::tests::domain(),
                    *payout_id,
                    payout_version,
                )
                .unwrap()
                .unwrap();
            assert_eq!(payout_record.digest(), payout_digest);
            let runtime::DurableObjectPayload::Inline(payout_inline) = payout_record.payload()
            else {
                panic!("positive capacity payout object must be inline");
            };
            assert_eq!(payout_inline.canonical_bytes(), payout_bytes.as_slice());
        }

        let receipt: Option<DurableRequestReceipt> = reopened
            .get_request_receipt(
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                DurableRequestId::new(escrow.claim_request_id).unwrap(),
            )
            .unwrap();
        assert!(
            receipt.is_some(),
            "positive capacity claim must retain its outer receipt"
        );
    }
    let reopen_elapsed: Duration = reopen_start.elapsed();
    let reopened_db_bytes: u64 = file_bytes("");
    let reopened_wal_bytes: u64 = file_bytes("-wal");

    // A generous ceiling that only catches a catastrophic regression, not a
    // performance certification: one process, one disk, one run.
    assert!(
        reopen_elapsed < Duration::from_secs(30),
        "close/reopen + full read of {ESCROWS} positive escrows took {reopen_elapsed:?}"
    );

    eprintln!(
        "fee-claim capacity (positive): escrows={ESCROWS}, writers={WRITERS}, concurrent_commit_latency={concurrent_elapsed:?}, reopen_and_read_latency={reopen_elapsed:?}, measured_retained_claim_envelope_bytes={measured_claim_bytes}, measured_retained_settlement_row_bytes={measured_row_bytes}, measured_retained_escrow_object_bytes={measured_escrow_bytes}, measured_retained_payout_object_bytes={measured_payout_bytes}, physical_sqlite_db_bytes[setup={setup_db_bytes},committed={committed_db_bytes},reopened={reopened_db_bytes}], physical_sqlite_wal_bytes[setup={setup_wal_bytes},committed={committed_wal_bytes},reopened={reopened_wal_bytes}]"
    );

    std::fs::remove_dir_all(&directory).unwrap();
}

/// Bounded, opt-in live-PostgreSQL Phase 3 fee-claim capacity/recovery
/// evidence, exercising the same real `handle_fee_claim` pipeline as the
/// file-backed SQLite tests above against a genuine `PostgresDurableStore`/
/// `PostgresBlobStore` pair instead of SQLite/`MemoryBlobStore`. Both tests
/// are deliberately `#[ignore]`d and gated on `SUNRISE_EDGE_TEST_POSTGRES_URL`
/// (never run by ordinary `cargo test`), and serialize against every other
/// live-PostgreSQL test family in this repo through the same cross-process
/// lock file used by `fee_claims::tests::certified_multi_escrow_inventory`.
/// Each run bootstraps one fresh, time-and-process-derived storage namespace
/// so repeated runs against the shared `sunrise_edge_test` database never
/// collide with a prior run's rows or already-advanced writer fence.
mod live_postgres {
    use super::*;
    use crate::fee_claims::FeeClaimError;
    use postgres::{Client, NoTls};
    use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
    use runtime_postgres::{
        POSTGRES_SCHEMA_GENERATION, PostgresBlobStore, PostgresDurableStore, PostgresNamespace,
        PostgresPoolConfig, PostgresTransactionPolicy, advance_writer_fence, apply_initial_schema,
        bootstrap_namespace, build_postgres_pool,
    };
    use std::{
        num::NonZeroU32,
        sync::atomic::{AtomicU64, Ordering},
    };

    /// Cross-process file lock shared with every other live-PostgreSQL test
    /// family in this repo (see the identically named lock in
    /// `crate::fee_claims::tests::certified_multi_escrow_inventory`):
    /// `cargo test` may run each crate's live-database tests as independent
    /// concurrent processes against the same shared database, so they must
    /// all serialize on the same file. `Drop` only removes the file if it
    /// still records this exact acquisition, mirroring that module's
    /// abandoned-lock rationale.
    struct PostgresLiveLock {
        path: std::path::PathBuf,
        owner: String,
    }

    impl PostgresLiveLock {
        fn acquire() -> Self {
            let path: std::path::PathBuf =
                std::env::temp_dir().join("sunrise-edge-runtime-postgres-live-test.lock");
            let owner: String = format!(
                "{}:{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            );
            let deadline: std::time::Instant =
                std::time::Instant::now() + std::time::Duration::from_secs(600);
            loop {
                let created = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path);
                match created {
                    Ok(mut file) => {
                        use std::io::Write;
                        file.write_all(owner.as_bytes()).unwrap();
                        file.sync_all().unwrap();
                        return Self { path, owner };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if std::time::Instant::now() >= deadline {
                            panic!(
                                "timed out waiting for the exclusive live PostgreSQL test lock \
                                 at {}; if no other live test is actually running, delete this \
                                 file",
                                path.display()
                            );
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    Err(error) => panic!(
                        "failed to create live PostgreSQL test lock at {}: {error}",
                        path.display()
                    ),
                }
            }
        }
    }

    impl Drop for PostgresLiveLock {
        fn drop(&mut self) {
            if std::fs::read_to_string(&self.path).ok().as_deref() == Some(self.owner.as_str()) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    type LiveTestPostgresManager = PostgresConnectionManager<NoTls>;

    fn live_test_postgres_pool(url: &str) -> Pool<LiveTestPostgresManager> {
        let config: postgres::Config = url.parse().unwrap();
        build_postgres_pool(
            config,
            NoTls,
            PostgresPoolConfig::new(
                NonZeroU32::new(12).unwrap(),
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(300),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn transaction_policy() -> PostgresTransactionPolicy {
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap()
    }

    /// Retry only a definite serialization non-commit with unchanged signed
    /// bytes. The caller bound and per-writer delay avoid retry storms.
    fn claim_with_bounded_retry(
        mut attempt_claim: impl FnMut() -> Result<NodeOutput, FeeClaimError>,
        writer_slot: usize,
        retry_counter: &AtomicU64,
    ) {
        const MAX_CALLER_ATTEMPTS: u64 = 32;
        let slot_delay_ms: u64 = u64::try_from(writer_slot % 4).unwrap();
        for attempt in 1_u64..=MAX_CALLER_ATTEMPTS {
            match attempt_claim() {
                Ok(_) => return,
                Err(FeeClaimError::Node(NodeCoreError::DurableCommitRejected(
                    DurableCommitRejection::SerializationFailure,
                ))) if attempt < MAX_CALLER_ATTEMPTS => {
                    retry_counter.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(attempt.min(10) + slot_delay_ms));
                }
                Err(error) => panic!("fee claim failed after {attempt} attempts: {error}"),
            }
        }
        unreachable!("the last attempt either succeeds or panics")
    }

    /// A fresh, time-and-process-derived storage identity: not a real signing
    /// key, only the opaque partition key selecting this run's namespace, so
    /// repeated runs against the shared test database never reuse another
    /// run's rows or writer fence.
    fn fresh_storage_validator_id(tag: u8) -> ValidatorId {
        let nanos: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut id: [u8; 32] = [0; 32];
        id[..16].copy_from_slice(&nanos.to_be_bytes());
        id[16..20].copy_from_slice(&std::process::id().to_be_bytes());
        id[20] = tag;
        ValidatorId::new(id)
    }

    /// Whole-relation physical size in bytes, including indexes and TOAST.
    ///
    /// Every namespace in `sunrise_edge_test` shares these tables, so this is
    /// never an isolated per-namespace measurement: it is only meaningful as
    /// a before/after delta around this exact test's own writes, and even
    /// that delta can include any other live-PostgreSQL activity in the
    /// shared database that is not excluded by [`PostgresLiveLock`].
    fn relation_bytes(admin: &mut Client, qualified_table: &str) -> i64 {
        admin
            .query_one(
                "SELECT pg_total_relation_size(to_regclass($1))",
                &[&qualified_table],
            )
            .unwrap()
            .get(0)
    }

    /// Connects the admin client, refuses to run against anything but the
    /// dedicated test database, applies the schema, and bootstraps one fresh
    /// namespace at writer fence 1.
    fn open_fresh_namespace(database_url: &str, tag: u8) -> (Client, PostgresNamespace) {
        let mut admin: Client = Client::connect(database_url, NoTls).unwrap();
        let current_database: String = admin
            .query_one("SELECT current_database()", &[])
            .unwrap()
            .get(0);
        assert_eq!(
            current_database, "sunrise_edge_test",
            "refusing to run the live PostgreSQL capacity test against a non-test database"
        );
        apply_initial_schema(&mut admin).unwrap();
        let namespace: PostgresNamespace = PostgresNamespace::new(
            &crate::genesis::tests::chain(),
            fresh_storage_validator_id(tag),
            crate::genesis::tests::domain(),
        )
        .unwrap();
        bootstrap_namespace(
            &mut admin,
            &namespace,
            POSTGRES_SCHEMA_GENERATION,
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        (admin, namespace)
    }

    /// DR-0138/DR-0143 live-PostgreSQL capacity evidence for the zero-share
    /// claim path: 48 distinct maximum-admitted 256-share escrows, six
    /// concurrent real PostgreSQL writers with bounded caller retries for
    /// definite serialization rejection, then a real close/reopen under a
    /// newer writer fence that reads every settlement row and claim envelope,
    /// plus a physical `pg_total_relation_size` snapshot around the
    /// concurrent commit phase (see [`relation_bytes`] for its shared-table
    /// caveat). This remains one process against one shared live database in
    /// one run: bounded evidence, not a throughput or capacity certification,
    /// and it says nothing about CI hardware or a production target.
    #[test]
    #[ignore = "requires SUNRISE_EDGE_TEST_POSTGRES_URL against a live PostgreSQL sunrise_edge_test database"]
    fn live_postgres_concurrent_zero_share_claims_measure_retained_bytes_and_reopen_latency() {
        const ESCROWS: u32 = 48;
        const WRITERS: usize = 6;
        assert_eq!(
            ESCROWS as usize % WRITERS,
            0,
            "evenly shardable escrow count"
        );

        let database_url: String = std::env::var("SUNRISE_EDGE_TEST_POSTGRES_URL")
            .expect("live PostgreSQL capacity evidence requires SUNRISE_EDGE_TEST_POSTGRES_URL");
        let _lock: PostgresLiveLock = PostgresLiveLock::acquire();
        let (mut admin, namespace): (Client, PostgresNamespace) =
            open_fresh_namespace(&database_url, 0x01);
        let policy: PostgresTransactionPolicy = transaction_policy();

        let zero_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xd1; 32]);
        let zero_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&zero_key).into();
        let zero_id: ValidatorId = ValidatorId::new(zero_public);
        let positive_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xd4; 32]);
        let positive_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&positive_key).into();
        let positive_id: ValidatorId = ValidatorId::new(positive_public);

        // Exercise a real 256-share settlement row on PostgreSQL, not just
        // the two-member row used by the local SQLite concurrency regression.
        // Only one zero-share claimant signs; the other 254 retained shares
        // make this the maximum admitted row shape without manufacturing
        // 256 separate claims per escrow.
        let mut additional_zero_ids: Vec<ValidatorId> = Vec::with_capacity(254);
        let mut additional_entries: Vec<FastPathValidatorEntry> = Vec::with_capacity(254);
        for index in 0_u32..254 {
            let mut seed: [u8; 32] = [0x55; 32];
            seed[28..].copy_from_slice(&index.to_be_bytes());
            let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(seed);
            let public_key: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
            let id: ValidatorId = ValidatorId::new(public_key);
            additional_zero_ids.push(id);
            additional_entries.push(FastPathValidatorEntry {
                id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key.to_vec(),
            });
        }

        let pool: Pool<LiveTestPostgresManager> = live_test_postgres_pool(&database_url);
        let escrows: Vec<CapacityEscrow> = {
            let setup: PostgresDurableStore<LiveTestPostgresManager> =
                PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
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
            validators.extend(additional_entries);
            validators.sort_by_key(|entry| entry.id);
            assert_eq!(validators.len(), records::MAX_FASTPATH_ACTIVE_VALIDATORS);
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
                .map(|index| {
                    build_capacity_escrow(
                        &setup,
                        &zero_key,
                        zero_id,
                        positive_id,
                        index,
                        &additional_zero_ids,
                    )
                })
                .collect()
        };
        let setup_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");

        let shard_size: usize = ESCROWS as usize / WRITERS;
        let concurrent_start: Instant = Instant::now();
        let serialization_retries: AtomicU64 = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for (writer_slot, shard) in escrows.chunks(shard_size).enumerate() {
                let writer_pool: Pool<LiveTestPostgresManager> = pool.clone();
                let writer_namespace: PostgresNamespace = namespace.clone();
                let retry_counter: &AtomicU64 = &serialization_retries;
                scope.spawn(move || {
                    let writer: PostgresDurableStore<LiveTestPostgresManager> =
                        PostgresDurableStore::new(
                            writer_pool.clone(),
                            writer_namespace.clone(),
                            policy,
                        );
                    let blobs: PostgresBlobStore<LiveTestPostgresManager> =
                        PostgresBlobStore::new(writer_pool, writer_namespace).unwrap();
                    for escrow in shard {
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &blobs,
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
                            },
                            writer_slot,
                            retry_counter,
                        );
                    }
                });
            }
        });
        let concurrent_elapsed: Duration = concurrent_start.elapsed();
        let committed_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");

        let measured_claim_bytes: u64 = escrows
            .iter()
            .map(|escrow| escrow.signed.len() as u64)
            .sum();
        let measured_row_bytes: u64 = escrows
            .iter()
            .map(|escrow| escrow.next_row_bytes.len() as u64)
            .sum();

        drop(pool);

        let stale_context: DurableOperationContext = crate::genesis::tests::context(1);
        let advanced_fence: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
        advance_writer_fence(
            &mut admin,
            &namespace,
            WriterFenceGeneration::new(1).unwrap(),
            advanced_fence,
        )
        .unwrap();

        let reopen_start: Instant = Instant::now();
        let reopened_pool: Pool<LiveTestPostgresManager> = live_test_postgres_pool(&database_url);
        let reopened: PostgresDurableStore<LiveTestPostgresManager> =
            PostgresDurableStore::new(reopened_pool, namespace, policy);
        let fresh_context: DurableOperationContext = crate::genesis::tests::context(2);
        let mut read_claim_bytes: u64 = 0;
        let mut read_row_bytes: u64 = 0;
        for escrow in &escrows {
            let row: VersionedStateValue = reopened
                .get_versioned_durable(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    &escrow.row_key,
                )
                .unwrap();
            assert_eq!(row.value(), Some(escrow.next_row_bytes.as_slice()));
            assert_eq!(row.revision(), StateRevision::new(2));
            let claim: VersionedStateValue = reopened
                .get_versioned_durable(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    &escrow.claim_key,
                )
                .unwrap();
            assert_eq!(claim.value(), Some(escrow.signed.as_slice()));
            read_row_bytes += u64::try_from(row.value().unwrap().len()).unwrap();
            read_claim_bytes += u64::try_from(claim.value().unwrap().len()).unwrap();
        }
        let reopen_elapsed: Duration = reopen_start.elapsed();
        let reopened_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");

        assert_eq!(read_claim_bytes, measured_claim_bytes);
        assert_eq!(read_row_bytes, measured_row_bytes);
        assert_eq!(
            reopened
                .get_versioned_durable(
                    &stale_context,
                    crate::genesis::tests::domain(),
                    &escrows[0].row_key,
                )
                .unwrap_err(),
            DurableReadError::WriterFenced {
                active_generation: advanced_fence,
            }
        );
        // A generous ceiling over a real network round trip that only catches
        // a catastrophic regression, not a performance certification.
        assert!(
            reopen_elapsed < Duration::from_secs(60),
            "close/reopen + full read of {ESCROWS} live PostgreSQL rows took {reopen_elapsed:?}"
        );

        eprintln!(
            "fee-claim capacity (live PostgreSQL, zero-share): escrows={ESCROWS}, writers={WRITERS}, caller_serialization_retries={}, concurrent_commit_latency={concurrent_elapsed:?}, reopen_under_newer_writer_fence_and_read_latency={reopen_elapsed:?}, measured_retained_claim_envelope_bytes={measured_claim_bytes}, measured_retained_settlement_row_bytes={measured_row_bytes}, physical_state_records_relation_bytes_whole_shared_table[setup={setup_state_records_bytes},committed={committed_state_records_bytes},reopened={reopened_state_records_bytes}]",
            serialization_retries.load(Ordering::Relaxed)
        );

        drop(reopened);
        drop(admin);
    }

    /// DR-0138/DR-0143 live-PostgreSQL capacity evidence for the *positive*
    /// (object-mutating) fee-claim path: several distinct escrows, half
    /// finalized through `split` and half through `transfer`, driven through
    /// the real `handle_fee_claim` pipeline by concurrent PostgreSQL writer
    /// connections, then a real close/reopen under a **strictly newer**
    /// writer fence generation (an operator-style failover, not merely a
    /// plain reconnect) that reads every settlement row, claim envelope,
    /// escrow/payout object and outer receipt back, followed by a direct
    /// stale-generation read proving `DurableReadError::WriterFenced` against
    /// the real, already-advanced fence. See [`relation_bytes`] for the
    /// physical-measurement shared-table caveat. This remains one process
    /// against one shared live database in one run: bounded evidence, not a
    /// throughput or capacity certification.
    #[test]
    #[ignore = "requires SUNRISE_EDGE_TEST_POSTGRES_URL against a live PostgreSQL sunrise_edge_test database"]
    fn live_postgres_concurrent_positive_claims_measure_retained_bytes_and_writer_fence_recovery() {
        const ESCROWS: u32 = 12;
        const WRITERS: usize = 3;
        assert_eq!(
            ESCROWS as usize % WRITERS,
            0,
            "evenly shardable escrow count"
        );

        let database_url: String = std::env::var("SUNRISE_EDGE_TEST_POSTGRES_URL")
            .expect("live PostgreSQL capacity evidence requires SUNRISE_EDGE_TEST_POSTGRES_URL");
        let _lock: PostgresLiveLock = PostgresLiveLock::acquire();
        let (mut admin, namespace): (Client, PostgresNamespace) =
            open_fresh_namespace(&database_url, 0x02);
        let policy: PostgresTransactionPolicy = transaction_policy();

        let (_base_manifest, _origin, instance, def_id, _coin_id) =
            crate::genesis::tests::build_fixture();
        let mut manifest: GenesisManifest =
            crate::genesis::tests::manifest_with_custody(ObjectId::new([0xe1; 32]));
        let second_key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from([0xe7; 32]);
        let second_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&second_key).into();
        let second_validator: ValidatorId = ValidatorId::new(second_public);
        let mut second_bond: GenesisObjectEntry = crate::genesis::tests::custody_object_entry(
            &manifest,
            ObjectId::new([0xe8; 32]),
            crate::genesis::tests::chain(),
        );
        let Owner::ProtocolCustody(second_scope) = &mut second_bond.object.owner else {
            panic!("second bond custody owner");
        };
        second_scope.subject = second_public;
        manifest.objects.push(second_bond);
        manifest
            .validator_set
            .validators
            .push(FastPathValidatorEntry {
                id: second_validator,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: second_public.to_vec(),
            });
        manifest
            .validator_set
            .validators
            .sort_by_key(|entry| entry.id);

        let coin_template: GenesisObjectEntry = manifest.objects[1].clone();
        let mut coin_ids: Vec<ObjectId> = Vec::with_capacity(ESCROWS as usize);
        for index in 0..ESCROWS {
            let mut coin_id_bytes: [u8; 32] = [0xe0; 32];
            coin_id_bytes[28..].copy_from_slice(&index.to_be_bytes());
            let coin_id: ObjectId = ObjectId::new(coin_id_bytes);
            coin_ids.push(coin_id);
            manifest.objects.push(GenesisObjectEntry {
                object: Object {
                    id: coin_id,
                    version: 1,
                    owner: Owner::Address(Address::new(crate::genesis::tests::sender())),
                    type_hash: coin_template.object.type_hash,
                    schema_version: coin_template.object.schema_version,
                    data: encode_call_value(
                        &public_standard_asset::coin_body_layout(),
                        &CallValue::U64(1_000_000),
                    )
                    .unwrap(),
                },
                authority: ObjectAuthority {
                    object_id: coin_id,
                    instance_context: coin_template.authority.instance_context.clone(),
                    instance: coin_template.authority.instance.clone(),
                    code: coin_template.authority.code.clone(),
                    ty: coin_template.authority.ty.clone(),
                },
            });
        }
        crate::genesis::tests::resign_manifest(&mut manifest);

        let resource_id: BondResourceId = manifest.economics_policy.resources[0].resource_id;
        let validator_a: ValidatorId = ValidatorId::new(crate::genesis::tests::sender());
        let validator_a_key: ed25519_zebra::SigningKey = crate::genesis::tests::key();

        let pool: Pool<LiveTestPostgresManager> = live_test_postgres_pool(&database_url);
        let escrows: Vec<PositiveCapacityEscrow> = {
            let setup: PostgresDurableStore<LiveTestPostgresManager> =
                PostgresDurableStore::new(pool.clone(), namespace.clone(), policy);
            install_genesis(
                &setup,
                &crate::genesis::tests::context(1),
                crate::genesis::tests::domain(),
                &crate::genesis::tests::resolver(),
                &manifest,
                10,
            )
            .unwrap();
            (0..ESCROWS)
                .map(|index| {
                    build_positive_capacity_escrow(
                        &setup,
                        def_id,
                        &instance,
                        &coin_template,
                        coin_ids[index as usize],
                        resource_id,
                        validator_a,
                        &validator_a_key,
                        second_validator,
                        index,
                        index % 2 == 1,
                    )
                })
                .collect()
        };
        let setup_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");
        let setup_object_versions_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.object_versions");

        let shard_size: usize = ESCROWS as usize / WRITERS;
        let concurrent_start: Instant = Instant::now();
        let serialization_retries: AtomicU64 = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for (writer_slot, shard) in escrows.chunks(shard_size).enumerate() {
                let writer_pool: Pool<LiveTestPostgresManager> = pool.clone();
                let writer_namespace: PostgresNamespace = namespace.clone();
                let retry_counter: &AtomicU64 = &serialization_retries;
                scope.spawn(move || {
                    let writer: PostgresDurableStore<LiveTestPostgresManager> =
                        PostgresDurableStore::new(
                            writer_pool.clone(),
                            writer_namespace.clone(),
                            policy,
                        );
                    let blobs: PostgresBlobStore<LiveTestPostgresManager> =
                        PostgresBlobStore::new(writer_pool, writer_namespace).unwrap();
                    for escrow in shard {
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &blobs,
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
                            },
                            writer_slot,
                            retry_counter,
                        );
                    }
                });
            }
        });
        let concurrent_elapsed: Duration = concurrent_start.elapsed();
        let committed_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");
        let committed_object_versions_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.object_versions");

        let measured_claim_bytes: u64 = escrows
            .iter()
            .map(|escrow| escrow.signed.len() as u64)
            .sum();
        let measured_row_bytes: u64 = escrows
            .iter()
            .map(|escrow| escrow.next_row_bytes.len() as u64)
            .sum();
        let measured_escrow_bytes: u64 = escrows
            .iter()
            .map(|escrow| escrow.escrow_expected_bytes.len() as u64)
            .sum();
        let measured_payout_bytes: u64 = escrows
            .iter()
            .filter_map(|escrow| escrow.payout.as_ref())
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();

        drop(pool);

        // Real operator-style failover: advance the writer fence on the exact
        // namespace this test just wrote to, then reopen under a fresh pool
        // and a strictly newer generation.
        let stale_context: DurableOperationContext = crate::genesis::tests::context(1);
        let advanced_fence: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
        advance_writer_fence(
            &mut admin,
            &namespace,
            WriterFenceGeneration::new(1).unwrap(),
            advanced_fence,
        )
        .unwrap();

        let reopen_start: Instant = Instant::now();
        let reopened_pool: Pool<LiveTestPostgresManager> = live_test_postgres_pool(&database_url);
        let reopened: PostgresDurableStore<LiveTestPostgresManager> =
            PostgresDurableStore::new(reopened_pool, namespace.clone(), policy);
        let fresh_context: DurableOperationContext = crate::genesis::tests::context(2);
        for escrow in &escrows {
            let row: VersionedStateValue = reopened
                .get_versioned_durable(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    &escrow.row_key,
                )
                .unwrap();
            assert_eq!(row.value(), Some(escrow.next_row_bytes.as_slice()));
            assert_eq!(row.revision(), StateRevision::new(2));

            let claim: VersionedStateValue = reopened
                .get_versioned_durable(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    &escrow.claim_key,
                )
                .unwrap();
            assert_eq!(claim.value(), Some(escrow.signed.as_slice()));

            let head: DurableObjectHead = reopened
                .get_object_head(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    escrow.escrow_id,
                )
                .unwrap();
            let DurableObjectHead::Current {
                object_version,
                digest,
                ..
            } = head
            else {
                panic!("live PostgreSQL positive capacity escrow must retain a current object");
            };
            assert_eq!(object_version.get(), escrow.escrow_expected_version);
            let record: DurableObjectVersionRecord = reopened
                .get_object_version(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    escrow.escrow_id,
                    object_version,
                )
                .unwrap()
                .unwrap();
            assert_eq!(record.digest(), digest);
            let runtime::DurableObjectPayload::Inline(inline) = record.payload() else {
                panic!("live PostgreSQL positive capacity escrow must keep the object inline");
            };
            assert_eq!(
                inline.canonical_bytes(),
                escrow.escrow_expected_bytes.as_slice()
            );

            if let Some((payout_id, payout_bytes)) = &escrow.payout {
                let payout_head: DurableObjectHead = reopened
                    .get_object_head(&fresh_context, crate::genesis::tests::domain(), *payout_id)
                    .unwrap();
                let DurableObjectHead::Current {
                    object_version: payout_version,
                    digest: payout_digest,
                    ..
                } = payout_head
                else {
                    panic!("live PostgreSQL positive split claim must create a payout object");
                };
                assert_eq!(payout_version.get(), 1);
                let payout_record: DurableObjectVersionRecord = reopened
                    .get_object_version(
                        &fresh_context,
                        crate::genesis::tests::domain(),
                        *payout_id,
                        payout_version,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(payout_record.digest(), payout_digest);
                let runtime::DurableObjectPayload::Inline(payout_inline) = payout_record.payload()
                else {
                    panic!("live PostgreSQL positive payout object must be inline");
                };
                assert_eq!(payout_inline.canonical_bytes(), payout_bytes.as_slice());
            }

            let receipt: Option<DurableRequestReceipt> = reopened
                .get_request_receipt(
                    &fresh_context,
                    crate::genesis::tests::domain(),
                    DurableRequestId::new(escrow.claim_request_id).unwrap(),
                )
                .unwrap();
            assert!(
                receipt.is_some(),
                "live PostgreSQL positive capacity claim must retain its outer receipt"
            );
        }
        let reopen_elapsed: Duration = reopen_start.elapsed();
        let reopened_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");
        let reopened_object_versions_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.object_versions");

        // The stale generation must fail closed against the real,
        // already-advanced fence, not silently succeed or read stale data.
        let stale_error: DurableReadError = reopened
            .get_versioned_durable(
                &stale_context,
                crate::genesis::tests::domain(),
                &escrows[0].row_key,
            )
            .unwrap_err();
        assert_eq!(
            stale_error,
            DurableReadError::WriterFenced {
                active_generation: advanced_fence
            }
        );

        // A generous ceiling over a real network round trip that only catches
        // a catastrophic regression, not a performance certification.
        assert!(
            reopen_elapsed < Duration::from_secs(60),
            "close/reopen under a newer writer fence + full read of {ESCROWS} live PostgreSQL \
             positive escrows took {reopen_elapsed:?}"
        );

        eprintln!(
            "fee-claim capacity (live PostgreSQL, positive): escrows={ESCROWS}, writers={WRITERS}, caller_serialization_retries={}, concurrent_commit_latency={concurrent_elapsed:?}, reopen_under_newer_writer_fence_and_read_latency={reopen_elapsed:?}, measured_retained_claim_envelope_bytes={measured_claim_bytes}, measured_retained_settlement_row_bytes={measured_row_bytes}, measured_retained_escrow_object_bytes={measured_escrow_bytes}, measured_retained_payout_object_bytes={measured_payout_bytes}, physical_state_records_relation_bytes_whole_shared_table[setup={setup_state_records_bytes},committed={committed_state_records_bytes},reopened={reopened_state_records_bytes}], physical_object_versions_relation_bytes_whole_shared_table[setup={setup_object_versions_bytes},committed={committed_object_versions_bytes},reopened={reopened_object_versions_bytes}]",
            serialization_retries.load(Ordering::Relaxed)
        );

        drop(reopened);
        drop(admin);
    }
}
