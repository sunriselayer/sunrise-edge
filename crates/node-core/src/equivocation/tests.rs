//! Regressions and adversarial tests for DR-0133 equivocation evidence
//! persistence and historical verification.

use super::*;
use crate::epoch_transition::{
    activate, propose_and_vote,
    tests::{GenesisFixture, build_genesis_fixture},
};
use crate::fast_path::records::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use crate::fast_path::{FastPathEd25519Verifier, records};
use crate::genesis::{GenesisInstallOutcome, install_genesis_with_history};
use crate::local_instance_state::{
    FastPathEpochRecord, encode_fastpath_epoch_record, fastpath_epoch_record_key,
    fastpath_equivocation_evidence_key, fastpath_validator_set_key,
};
use crate::paid_execution::tests::{context, domain, memory_store};
use crate::query::query_fastpath_equivocation_evidence;
use consensus::{
    ConsensusError, ConsensusSigner, EpochTransitionCertifier, EpochTransitionVote,
    FastPathCertifier, FastVote, LockedObjectSetPreimage,
    decode_fast_vote_object_conflict_evidence, encode_epoch_transition_vote, encode_fast_vote,
    encode_locked_object_set_preimage, verify_fast_vote_equivocation_evidence,
    verify_fast_vote_object_conflict_evidence,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::PublicationContext;
use objects::{ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, DurableOperationContext, DurableReadError, MemoryDurableStateStore,
    StateMutation, StateMutationEntry, StructuredDurableDomainStateStore, VersionedStateValue,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use validator_set::{ValidatorInfo, ValidatorSet};

fn chain() -> ChainId {
    ChainId::new("epoch-transition-test").unwrap()
}

fn protocol_version() -> ProtocolVersion {
    ProtocolVersion::new(3)
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct TestSigner {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl ConsensusSigner for TestSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature_bytes: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature_bytes.to_vec())
    }
}

fn validator(seed: u8) -> (TestSigner, FastPathValidatorEntry) {
    let signing_key: SigningKey = SigningKey::from([seed; 32]);
    let verification_key: VerificationKey = VerificationKey::from(&signing_key);
    let id_bytes: [u8; 32] = verification_key.into();
    let id: ValidatorId = ValidatorId::new(id_bytes);
    let signer: TestSigner = TestSigner {
        validator_id: id,
        signing_key,
    };
    let entry: FastPathValidatorEntry = FastPathValidatorEntry {
        id,
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: id_bytes.to_vec(),
    };
    (signer, entry)
}

fn four_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [101u8, 102, 103, 104] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

fn four_next_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [102u8, 103, 104, 105] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

fn fast_certifier(epoch: Epoch, entries: &[FastPathValidatorEntry]) -> FastPathCertifier {
    let validator_set: ValidatorSet = ValidatorSet::new(
        epoch,
        entries
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    FastPathCertifier::new(chain(), protocol_version(), epoch, validator_set).unwrap()
}

fn transition_certifier(
    epoch: Epoch,
    entries: &[FastPathValidatorEntry],
) -> EpochTransitionCertifier {
    let validator_set: ValidatorSet = ValidatorSet::new(
        epoch,
        entries
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    EpochTransitionCertifier::new(chain(), protocol_version(), epoch, validator_set).unwrap()
}

fn object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version,
        digest: digest(digest_byte),
    }
}

fn make_preimage(epoch: Epoch, entries: Vec<ObjectRef>) -> LockedObjectSetPreimage {
    let mut sorted: Vec<ObjectRef> = entries;
    sorted.sort_by_key(|entry| entry.id);
    LockedObjectSetPreimage {
        chain_id: chain(),
        protocol_version: protocol_version(),
        epoch,
        entries: sorted,
    }
}

fn compute_preimage_digest(
    resolver: &HashSuiteResolver,
    preimage: &LockedObjectSetPreimage,
) -> Digest32 {
    let bytes: Vec<u8> = encode_locked_object_set_preimage(preimage).unwrap();
    resolver
        .hash_for_purpose(preimage.epoch, HashPurpose::ExecutionEffects, &bytes)
        .unwrap()
}

fn install_test_environment<S: StructuredDurableDomainStateStore>(
    store: &S,
    epoch: Epoch,
    entries: &[FastPathValidatorEntry],
) {
    let validator_set: ValidatorSet = ValidatorSet::new(
        epoch,
        entries
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    let validator_set_digest: Digest32 = validator_set.digest(&resolver()).unwrap();

    let validator_context: PublicationContext =
        PublicationContext::new(chain(), protocol_version(), epoch).unwrap();
    let val_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&validator_context).unwrap();
    let val_record: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: validator_context,
        validators: entries.to_vec(),
    };
    let val_bytes: Vec<u8> = records::encode_fastpath_validator_set_record(&val_record).unwrap();

    let epoch_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain()).unwrap();
    let epoch_record: FastPathEpochRecord = FastPathEpochRecord {
        current_epoch: epoch,
        current_validator_set_digest: validator_set_digest,
        previous_epoch: None,
        activated_at_checkpoint: 1,
    };
    let epoch_bytes: Vec<u8> = encode_fastpath_epoch_record(&epoch_record).unwrap();

    let val_observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &val_key)
        .unwrap();
    let epoch_observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &epoch_key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(val_key.clone(), val_observed.revision()).unwrap(),
            StateReadAssertion::new(epoch_key.clone(), epoch_observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(val_key, StateMutation::Put(val_bytes)).unwrap(),
            StateMutationEntry::new(epoch_key, StateMutation::Put(epoch_bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

// ── 0x6429 Codec and Vector Stability ────────────────────────────────────

#[test]
fn fastpath_equivocation_evidence_record_frame_0x6429_is_stable() {
    let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
        evidence_bytes: vec![0xaa, 0xbb, 0xcc],
        recorded_at_checkpoint: 0x42,
    };
    let bytes: Vec<u8> = encode_fastpath_equivocation_evidence_record(&record).unwrap();
    assert_eq!(
        decode_fastpath_equivocation_evidence_record(&bytes).unwrap(),
        record
    );
    assert_eq!(
        hex(&bytes),
        "534e5245296401000200010003000000aabbcc0200080000004200000000000000"
    );
}

#[test]
fn decode_fastpath_equivocation_evidence_record_adversarial_checks() {
    let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
        evidence_bytes: vec![0x11, 0x22],
        recorded_at_checkpoint: 5,
    };
    let valid_bytes: Vec<u8> = encode_fastpath_equivocation_evidence_record(&record).unwrap();

    // 1. Truncated
    assert!(
        decode_fastpath_equivocation_evidence_record(&valid_bytes[..valid_bytes.len() - 1])
            .is_err()
    );

    // 2. Wrong type ID
    let mut wrong_type: Vec<u8> = valid_bytes.clone();
    wrong_type[4] = 0x28;
    assert!(decode_fastpath_equivocation_evidence_record(&wrong_type).is_err());

    // 3. Wrong version
    let mut wrong_version: Vec<u8> = valid_bytes.clone();
    wrong_version[6] = 0x02;
    assert!(decode_fastpath_equivocation_evidence_record(&wrong_version).is_err());

    // 4. Extra field
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_EQUIVOCATION_EVIDENCE_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, vec![0x11, 0x22]).unwrap();
    frame.field_u64(2, 5).unwrap();
    frame.field_u64(3, 99).unwrap();
    let extra_bytes: Vec<u8> = frame.finish().unwrap();
    assert!(decode_fastpath_equivocation_evidence_record(&extra_bytes).is_err());
}

// ── Three Evidence Classes: Submit, Record, Query ────────────────────────

#[test]
fn submit_fast_vote_equivocation_evidence_succeeds_and_queries() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();

    let outcome: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_fast_vote_equivocation_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            10,
        )
        .unwrap();

    let record: FastPathEquivocationEvidenceRecord = match outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        EquivocationEvidenceOutcome::AlreadyRecorded(_) => panic!("expected Recorded"),
    };
    assert_eq!(record.recorded_at_checkpoint, 10);

    let decoded: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
    let conflict_digest: Digest32 = normalized_identity_digest(&resolver(), &decoded).unwrap();

    let queried: Option<FastPathEquivocationEvidenceRecord> = query_fastpath_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    assert_eq!(queried, Some(record.clone()));

    // Exact resubmission -> AlreadyRecorded
    let resubmit: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_fast_vote_equivocation_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            20,
        )
        .unwrap();
    assert_eq!(
        resubmit,
        EquivocationEvidenceOutcome::AlreadyRecorded(record)
    );
}

#[test]
fn submit_fast_vote_object_conflict_evidence_succeeds_and_queries() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let shared: ObjectRef = object_ref(0x10, 1, 0x20);
    let preimage_a: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x30, 1, 0x40)]);
    let preimage_b: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x50, 1, 0x60)]);
    let digest_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_a);
    let digest_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b);

    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest_a, &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x03), digest(0x04), digest_b, &signers[0])
        .unwrap();

    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();
    let preimage_bytes_a: Vec<u8> = encode_locked_object_set_preimage(&preimage_a).unwrap();
    let preimage_bytes_b: Vec<u8> = encode_locked_object_set_preimage(&preimage_b).unwrap();

    let outcome: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_fast_vote_object_conflict_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            &preimage_bytes_a,
            &preimage_bytes_b,
            15,
        )
        .unwrap();

    let record: FastPathEquivocationEvidenceRecord = match outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        EquivocationEvidenceOutcome::AlreadyRecorded(_) => panic!("expected Recorded"),
    };
    assert_eq!(record.recorded_at_checkpoint, 15);

    let decoded: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
    let conflict_digest: Digest32 = normalized_identity_digest(&resolver(), &decoded).unwrap();

    let queried: Option<FastPathEquivocationEvidenceRecord> = query_fastpath_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    assert_eq!(queried, Some(record.clone()));

    // Exact resubmission -> AlreadyRecorded
    let resubmit: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_fast_vote_object_conflict_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            &preimage_bytes_a,
            &preimage_bytes_b,
            25,
        )
        .unwrap();
    assert_eq!(
        resubmit,
        EquivocationEvidenceOutcome::AlreadyRecorded(record)
    );
}

#[test]
fn submit_epoch_transition_equivocation_evidence_succeeds_and_queries() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: EpochTransitionCertifier = transition_certifier(epoch_0, &entries);
    let a: EpochTransitionVote = cert
        .cast_vote(
            Epoch::new(1),
            digest(0x01),
            digest(0x02),
            digest(0x03),
            &signers[0],
        )
        .unwrap();
    let b: EpochTransitionVote = cert
        .cast_vote(
            Epoch::new(1),
            digest(0x01),
            digest(0x02),
            digest(0x04),
            &signers[0],
        )
        .unwrap();
    let bytes_a: Vec<u8> = encode_epoch_transition_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_epoch_transition_vote(&b).unwrap();

    let outcome: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_epoch_transition_equivocation_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            30,
        )
        .unwrap();

    let record: FastPathEquivocationEvidenceRecord = match outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        EquivocationEvidenceOutcome::AlreadyRecorded(_) => panic!("expected Recorded"),
    };
    assert_eq!(record.recorded_at_checkpoint, 30);

    let decoded: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
    let conflict_digest: Digest32 = normalized_identity_digest(&resolver(), &decoded).unwrap();

    let queried: Option<FastPathEquivocationEvidenceRecord> = query_fastpath_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();
    assert_eq!(queried, Some(record.clone()));

    // Exact resubmission -> AlreadyRecorded
    let resubmit: EquivocationEvidenceOutcome<FastPathEquivocationEvidenceRecord> =
        submit_epoch_transition_equivocation_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            40,
        )
        .unwrap();
    assert_eq!(
        resubmit,
        EquivocationEvidenceOutcome::AlreadyRecorded(record)
    );
}

// ── Signature-Variant Dedup Across All Three Classes ─────────────────────

#[test]
fn submit_is_idempotent_for_differently_signed_encoding_of_identical_pair() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    // Class (a)
    let fast_cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a_a: FastVote = fast_cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let a_b: FastVote = fast_cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let outcome_a = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a_a).unwrap(),
        &encode_fast_vote(&a_b).unwrap(),
        10,
    )
    .unwrap();
    let rec_a = match outcome_a {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    // Variant with different signature bytes (same payload)
    let mut variant_a_a: FastVote = a_a.clone();
    variant_a_a.signature[0] ^= 0xFF;
    let mut variant_a_b: FastVote = a_b.clone();
    variant_a_b.signature[0] ^= 0x55;
    let outcome_a_variant = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&variant_a_a).unwrap(),
        &encode_fast_vote(&variant_a_b).unwrap(),
        99,
    )
    .unwrap();
    assert_eq!(
        outcome_a_variant,
        EquivocationEvidenceOutcome::AlreadyRecorded(rec_a)
    );

    // Class (b)
    let shared: ObjectRef = object_ref(0x10, 1, 0x20);
    let preimage_b_a: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x30, 1, 0x40)]);
    let preimage_b_b: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x50, 1, 0x60)]);
    let digest_b_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_b_a);
    let digest_b_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b_b);
    let b_a: FastVote = fast_cert
        .cast_vote(digest(0x01), digest(0x02), digest_b_a, &signers[0])
        .unwrap();
    let b_b: FastVote = fast_cert
        .cast_vote(digest(0x03), digest(0x04), digest_b_b, &signers[0])
        .unwrap();
    let outcome_b = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&b_a).unwrap(),
        &encode_fast_vote(&b_b).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b_a).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b_b).unwrap(),
        10,
    )
    .unwrap();
    let rec_b = match outcome_b {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    let mut variant_b_a: FastVote = b_a.clone();
    variant_b_a.signature[0] ^= 0xFF;
    let outcome_b_variant = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&variant_b_a).unwrap(),
        &encode_fast_vote(&b_b).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b_a).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b_b).unwrap(),
        99,
    )
    .unwrap();
    assert_eq!(
        outcome_b_variant,
        EquivocationEvidenceOutcome::AlreadyRecorded(rec_b)
    );

    // Class (c)
    let trans_cert: EpochTransitionCertifier = transition_certifier(epoch_0, &entries);
    let c_a: EpochTransitionVote = trans_cert
        .cast_vote(
            Epoch::new(1),
            digest(0x01),
            digest(0x02),
            digest(0x03),
            &signers[0],
        )
        .unwrap();
    let c_b: EpochTransitionVote = trans_cert
        .cast_vote(
            Epoch::new(1),
            digest(0x01),
            digest(0x02),
            digest(0x04),
            &signers[0],
        )
        .unwrap();
    let outcome_c = submit_epoch_transition_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_epoch_transition_vote(&c_a).unwrap(),
        &encode_epoch_transition_vote(&c_b).unwrap(),
        10,
    )
    .unwrap();
    let rec_c = match outcome_c {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    let mut variant_c_a: EpochTransitionVote = c_a.clone();
    variant_c_a.signature[0] ^= 0xFF;
    let outcome_c_variant = submit_epoch_transition_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_epoch_transition_vote(&variant_c_a).unwrap(),
        &encode_epoch_transition_vote(&c_b).unwrap(),
        99,
    )
    .unwrap();
    assert_eq!(
        outcome_c_variant,
        EquivocationEvidenceOutcome::AlreadyRecorded(rec_c)
    );
}

#[test]
fn submit_never_reaches_verification_on_already_recorded_path() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();

    let initial = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        10,
    )
    .unwrap();
    let initial_rec = match initial {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    // Construct statements with completely invalid/garbage signatures.
    // If verification were called, this would fail ConsensusError::SignatureVerification.
    let mut garbage_a: FastVote = a;
    garbage_a.signature = vec![0xEE; 64];
    let mut garbage_b: FastVote = b;
    garbage_b.signature = vec![0xDD; 64];

    let replay = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&garbage_a).unwrap(),
        &encode_fast_vote(&garbage_b).unwrap(),
        99,
    )
    .unwrap();

    assert_eq!(
        replay,
        EquivocationEvidenceOutcome::AlreadyRecorded(initial_rec)
    );
}

// ── Concurrent Identical Submissions ─────────────────────────────────────

struct BarrierGatedEquivocationStore {
    inner: MemoryDurableStateStore,
    gate_key: Vec<u8>,
    barrier: Arc<std::sync::Barrier>,
    gated_count: AtomicUsize,
}

impl DurableDomainStateStore for BarrierGatedEquivocationStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let result = self.inner.get_versioned_durable(context, domain, key);
        if key == self.gate_key.as_slice() && self.gated_count.fetch_add(1, Ordering::SeqCst) < 2 {
            self.barrier.wait();
        }
        result
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for BarrierGatedEquivocationStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: runtime::DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: runtime::DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: runtime::DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn submit_resolves_a_concurrent_identical_submission_without_a_duplicate_row() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();

    let evidence = consensus::build_fast_vote_equivocation_evidence(&a, &b).unwrap();
    let identity_bytes = fast_vote_evidence_normalized_identity(&evidence).unwrap();
    let conflict_digest = resolver()
        .hash_for_purpose(epoch_0, HashPurpose::NodeEvent, &identity_bytes)
        .unwrap();
    let gate_key = fastpath_equivocation_evidence_key(
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let store_a = Arc::new(BarrierGatedEquivocationStore {
        inner: store,
        gate_key,
        barrier,
        gated_count: AtomicUsize::new(0),
    });
    let store_b = Arc::clone(&store_a);

    let bytes_a_1 = bytes_a.clone();
    let bytes_b_1 = bytes_b.clone();
    let handle_1 = std::thread::spawn(move || {
        submit_fast_vote_equivocation_evidence(
            store_a.as_ref(),
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a_1,
            &bytes_b_1,
            10,
        )
    });

    let bytes_a_2 = bytes_a;
    let bytes_b_2 = bytes_b;
    let handle_2 = std::thread::spawn(move || {
        submit_fast_vote_equivocation_evidence(
            store_b.as_ref(),
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a_2,
            &bytes_b_2,
            10,
        )
    });

    let res_1 = handle_1.join().unwrap().unwrap();
    let res_2 = handle_2.join().unwrap().unwrap();

    // Exactly one Recorded, one AlreadyRecorded
    let recorded_count = match (&res_1, &res_2) {
        (
            EquivocationEvidenceOutcome::Recorded(r1),
            EquivocationEvidenceOutcome::AlreadyRecorded(r2),
        ) => {
            assert_eq!(r1, r2);
            1
        }
        (
            EquivocationEvidenceOutcome::AlreadyRecorded(r1),
            EquivocationEvidenceOutcome::Recorded(r2),
        ) => {
            assert_eq!(r1, r2);
            1
        }
        _ => 0,
    };
    assert_eq!(
        recorded_count, 1,
        "expected exactly one Recorded and one AlreadyRecorded"
    );
}

// ── Context, Resolver, and No-History Failures ───────────────────────────

#[test]
fn submit_fails_closed_on_context_resolver_and_no_history_failures() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();

    // 1. Resolver chain mismatch
    let wrong_chain = ChainId::new("wrong-chain").unwrap();
    let wrong_chain_resolver = HashSuiteResolver::new(
        wrong_chain,
        protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &wrong_chain_resolver,
        &chain(),
        protocol_version(),
        &bytes_a,
        &bytes_b,
        10,
    );
    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "resolver does not match declared chain/protocol context"
        ))
    ));

    // 2. Statement chain mismatch
    let other_chain = ChainId::new("other-chain").unwrap();
    let other_chain_cert = FastPathCertifier::new(
        other_chain,
        protocol_version(),
        epoch_0,
        ValidatorSet::new(
            epoch_0,
            entries
                .iter()
                .map(|entry| ValidatorInfo {
                    id: entry.id,
                    voting_power: entry.voting_power,
                    signature_scheme: entry.signature_scheme,
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        )
        .unwrap(),
    )
    .unwrap();
    let other_a = other_chain_cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let other_b = other_chain_cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&other_a).unwrap(),
        &encode_fast_vote(&other_b).unwrap(),
        10,
    );
    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "statement does not match the declared chain/protocol context"
        ))
    ));

    // 3. Evidence epoch > live.current_epoch
    let future_epoch = Epoch::new(10);
    let future_cert = FastPathCertifier::new(
        chain(),
        protocol_version(),
        future_epoch,
        ValidatorSet::new(
            future_epoch,
            entries
                .iter()
                .map(|entry| ValidatorInfo {
                    id: entry.id,
                    voting_power: entry.voting_power,
                    signature_scheme: entry.signature_scheme,
                    public_key: entry.public_key.clone(),
                })
                .collect(),
        )
        .unwrap(),
    )
    .unwrap();
    let future_a = future_cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let future_b = future_cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&future_a).unwrap(),
        &encode_fast_vote(&future_b).unwrap(),
        10,
    );
    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "evidence epoch is not yet committed"
        ))
    ));

    // 4. Evidence epoch < live.current_epoch but no transition record exists
    // Advance live epoch to 1 without installing transition record
    let epoch_key = fastpath_epoch_record_key(&chain()).unwrap();
    let advanced_epoch_record = FastPathEpochRecord {
        current_epoch: Epoch::new(1),
        current_validator_set_digest: digest(0xAA),
        previous_epoch: Some(Epoch::new(0)),
        activated_at_checkpoint: 2,
    };
    let epoch_observed = store
        .get_versioned_durable(&context(), domain(), &epoch_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(epoch_key.clone(), epoch_observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                epoch_key,
                StateMutation::Put(encode_fastpath_epoch_record(&advanced_epoch_record).unwrap()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    store.commit_durable(&context(), tx);

    let err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &bytes_a,
        &bytes_b,
        10,
    );
    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "no transition record for the evidence epoch"
        ))
    ));
}

// ── Row and History Tamper ───────────────────────────────────────────────

#[test]
fn submit_and_query_fail_closed_on_row_and_history_tamper() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    // 1. Tamper historical validator set row -> load_historical_validator_set fails
    let validator_context = PublicationContext::new(chain(), protocol_version(), epoch_0).unwrap();
    let val_key = fastpath_validator_set_key(&validator_context).unwrap();
    let mut tampered_entries = entries.clone();
    tampered_entries[0].voting_power = 999;
    let tampered_val_record = FastPathValidatorSetRecord {
        context: validator_context,
        validators: tampered_entries,
    };
    let tampered_bytes =
        records::encode_fastpath_validator_set_record(&tampered_val_record).unwrap();
    let val_observed = store
        .get_versioned_durable(&context(), domain(), &val_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(val_key.clone(), val_observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(val_key, StateMutation::Put(tampered_bytes)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    store.commit_durable(&context(), tx);

    let cert = fast_certifier(epoch_0, &entries);
    let a = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        10,
    );
    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "historical validator set does not match the restart-verified transition chain"
        ))
    ));

    // Restore valid validator set row
    install_test_environment(&store, epoch_0, &entries);

    // 2. Submit valid evidence
    let outcome = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        10,
    )
    .unwrap();
    let rec = match outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    let decoded = decode_dispatched(&rec.evidence_bytes).unwrap();
    let conflict_digest = normalized_identity_digest(&resolver(), &decoded).unwrap();
    let evidence_key = fastpath_equivocation_evidence_key(
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap();

    // 3. Tamper stored evidence row at rest
    let mut tampered_evidence: FastVote = b.clone();
    tampered_evidence.execution_effects_hash = digest(0x99);
    let tampered_env =
        consensus::build_fast_vote_equivocation_evidence(&a, &tampered_evidence).unwrap();
    let tampered_rec = FastPathEquivocationEvidenceRecord {
        evidence_bytes: consensus::encode_fast_vote_equivocation_evidence(&tampered_env).unwrap(),
        recorded_at_checkpoint: 10,
    };
    let tampered_rec_bytes = encode_fastpath_equivocation_evidence_record(&tampered_rec).unwrap();
    let ev_observed = store
        .get_versioned_durable(&context(), domain(), &evidence_key)
        .unwrap();
    let tx2 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(evidence_key.clone(), ev_observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(evidence_key.clone(), StateMutation::Put(tampered_rec_bytes))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    store.commit_durable(&context(), tx2);

    // Query detects mismatch against key digest
    let q_err = query_fastpath_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *signers[0].validator_id.as_bytes(),
        conflict_digest,
    );
    assert!(matches!(
        q_err,
        Err(NodeCoreError::PersistenceInvariant(
            "stored equivocation evidence does not match its own key digest"
        ))
    ));

    // Submit detects mismatch against existing row's key digest
    let s_err = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        10,
    );
    assert!(matches!(
        s_err,
        Err(EquivocationEvidenceError::Node(
            NodeCoreError::PersistenceInvariant(
                "evidence record does not match its own key digest"
            )
        ))
    ));

    // 4. Query selector mismatch (wrong validator)
    let q_sel_err = query_fastpath_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *signers[1].validator_id.as_bytes(),
        conflict_digest,
    );
    // Key derived with wrong validator will not be found -> Ok(None)
    assert_eq!(q_sel_err.unwrap(), None);
}

// ── Class (b) Preimage-Hash Verification and Overlap Rules ───────────────

#[test]
fn submit_fast_vote_object_conflict_evidence_fails_closed_when_a_preimage_does_not_hash_to_its_votes_signed_locked_objects_digest()
 {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    // Notice: we do NOT install the validator set here, proving that
    // the check fails at step 4 BEFORE validator set loading is ever attempted!

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let shared: ObjectRef = object_ref(0x10, 1, 0x20);
    let preimage_a: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x30, 1, 0x40)]);
    let preimage_b: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x50, 1, 0x60)]);
    let digest_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_a);
    let digest_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b);

    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest_a, &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x03), digest(0x04), digest_b, &signers[0])
        .unwrap();

    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();
    let preimage_bytes_a: Vec<u8> = encode_locked_object_set_preimage(&preimage_a).unwrap();

    // Swapped/unrelated preimage for b
    let unrelated_preimage: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared, object_ref(0x99, 1, 0x99)]);
    let unrelated_bytes: Vec<u8> = encode_locked_object_set_preimage(&unrelated_preimage).unwrap();

    let err = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &bytes_a,
        &bytes_b,
        &preimage_bytes_a,
        &unrelated_bytes,
        15,
    );

    assert!(matches!(
        err,
        Err(EquivocationEvidenceError::Invalid(
            "attached preimage does not hash to its FastVote locked_objects_digest"
        ))
    ));
}

#[test]
fn class_b_supports_both_equal_and_differing_object_digests() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    // Shared (ObjectId, version) with DIFFERENT digests:
    // a claims digest 0x20, b claims digest 0x99
    let entry_a: ObjectRef = object_ref(0x10, 1, 0x20);
    let entry_b: ObjectRef = object_ref(0x10, 1, 0x99);
    let preimage_a: LockedObjectSetPreimage = make_preimage(epoch_0, vec![entry_a]);
    let preimage_b: LockedObjectSetPreimage = make_preimage(epoch_0, vec![entry_b]);
    let digest_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_a);
    let digest_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b);

    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest_a, &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x03), digest(0x04), digest_b, &signers[0])
        .unwrap();

    let outcome = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        &encode_locked_object_set_preimage(&preimage_a).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b).unwrap(),
        10,
    )
    .unwrap();

    assert!(matches!(outcome, EquivocationEvidenceOutcome::Recorded(_)));
}

#[test]
fn class_b_canonical_smallest_overlap_when_multiple_objects_shared() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let shared_low: ObjectRef = object_ref(0x10, 1, 0x20);
    let shared_high: ObjectRef = object_ref(0x20, 1, 0x30);
    let preimage_a: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared_low.clone(), shared_high.clone()]);
    let preimage_b: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared_low.clone(), shared_high.clone()]);
    let digest_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_a);
    let digest_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b);

    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest_a, &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x03), digest(0x04), digest_b, &signers[0])
        .unwrap();

    let outcome = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&a).unwrap(),
        &encode_fast_vote(&b).unwrap(),
        &encode_locked_object_set_preimage(&preimage_a).unwrap(),
        &encode_locked_object_set_preimage(&preimage_b).unwrap(),
        10,
    )
    .unwrap();

    let record = match outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    let decoded = decode_fast_vote_object_conflict_evidence(&record.evidence_bytes).unwrap();
    assert_eq!(decoded.conflicting_object_id, shared_low.id);
    assert_eq!(decoded.conflicting_version, shared_low.version);
    assert_eq!(decoded.low_preimage.entries.len(), 2);
    assert_eq!(decoded.high_preimage.entries.len(), 2);
}

#[test]
fn multi_statement_pairwise_records() {
    let store: MemoryDurableStateStore = memory_store();
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);
    install_test_environment(&store, epoch_0, &entries);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let v1 = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x10), &signers[0])
        .unwrap();
    let v2 = cert
        .cast_vote(digest(0x01), digest(0x03), digest(0x10), &signers[0])
        .unwrap();
    let v3 = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x10), &signers[0])
        .unwrap();

    let r12 = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&v1).unwrap(),
        &encode_fast_vote(&v2).unwrap(),
        10,
    )
    .unwrap();
    let r23 = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&v2).unwrap(),
        &encode_fast_vote(&v3).unwrap(),
        10,
    )
    .unwrap();
    let r13 = submit_fast_vote_equivocation_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &encode_fast_vote(&v1).unwrap(),
        &encode_fast_vote(&v3).unwrap(),
        10,
    )
    .unwrap();

    assert!(matches!(r12, EquivocationEvidenceOutcome::Recorded(_)));
    assert!(matches!(r23, EquivocationEvidenceOutcome::Recorded(_)));
    assert!(matches!(r13, EquivocationEvidenceOutcome::Recorded(_)));
}

// ── Close / Reopen Persistence ───────────────────────────────────────────

#[test]
fn equivocation_evidence_survives_close_reopen_and_reverifies() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "equivocation-close-reopen-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let state_path = directory.join("state.sqlite");
    let (signers, entries) = four_validators();
    let epoch_0: Epoch = Epoch::new(0);

    let cert: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let a: FastVote = cert
        .cast_vote(digest(0x01), digest(0x02), digest(0x03), &signers[0])
        .unwrap();
    let b: FastVote = cert
        .cast_vote(digest(0x01), digest(0x04), digest(0x03), &signers[0])
        .unwrap();
    let bytes_a: Vec<u8> = encode_fast_vote(&a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&b).unwrap();

    let conflict_digest: Digest32 = {
        let store = SqliteDurableStore::open(
            &state_path,
            SqliteNamespace::new(chain(), signers[0].validator_id, domain()),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        install_test_environment(&store, epoch_0, &entries);

        let outcome = submit_fast_vote_equivocation_evidence(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            &bytes_a,
            &bytes_b,
            10,
        )
        .unwrap();
        let rec = match outcome {
            EquivocationEvidenceOutcome::Recorded(r) => r,
            _ => panic!("expected Recorded"),
        };
        let decoded = decode_dispatched(&rec.evidence_bytes).unwrap();
        normalized_identity_digest(&resolver(), &decoded).unwrap()
    };

    // Reopen store from disk
    {
        let reopened_store = SqliteDurableStore::open(
            &state_path,
            SqliteNamespace::new(chain(), signers[0].validator_id, domain()),
            WriterFenceGeneration::new(2).unwrap(),
        )
        .unwrap();

        let queried = query_fastpath_equivocation_evidence(
            &reopened_store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            epoch_0,
            *signers[0].validator_id.as_bytes(),
            conflict_digest,
        )
        .unwrap()
        .expect("record should survive reopen");

        let decoded = decode_dispatched(&queried.evidence_bytes).unwrap();
        let ev = match decoded {
            DecodedEquivocationEvidence::FastVote(ev) => ev,
            _ => panic!("expected FastVote"),
        };
        let hist_val_set = load_historical_validator_set(
            &reopened_store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            epoch_0,
        )
        .unwrap();
        verify_fast_vote_equivocation_evidence(&ev, hist_val_set, &FastPathEd25519Verifier)
            .unwrap();
    }
}

// ── Headline Test: Retired Validator After Real Transition ───────────────

#[test]
fn class_b_object_conflict_evidence_for_a_retired_validator_still_verifies_by_historical_key_after_a_real_transition()
 {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "equivocation-headline-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let (signers, entries) = four_validators();
    let (_next_signers, next_entries) = four_next_validators();
    let epoch_0: Epoch = Epoch::new(0);

    // Signers:
    // epoch 0: seeds [101, 102, 103, 104] -> signers[0] is seed 101.
    // epoch 1: seeds [102, 103, 104, 105] -> seed 101 is RETIRED!
    let retired_validator_id = signers[0].validator_id;

    let fixture: GenesisFixture = build_genesis_fixture(entries.clone());
    let state_path = directory.join("headline-state.sqlite");
    let blob_path = directory.join("headline-blobs.sqlite");
    let namespace = SqliteNamespace::new(chain(), retired_validator_id, domain());

    let (store, blob_store) = (
        SqliteDurableStore::open(
            &state_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap(),
        SqliteBlobStore::open(&blob_path).unwrap(),
    );

    // 1. Genesis at epoch 0
    let install_outcome = install_genesis_with_history(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &fixture.manifest,
        1,
    )
    .unwrap();
    assert!(matches!(
        install_outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));

    // 2. Offending validator (seed 101) casts two conflicting FastVotes over overlapping (ObjectId, version)
    let cert_0: FastPathCertifier = fast_certifier(epoch_0, &entries);
    let shared: ObjectRef = object_ref(0x10, 1, 0x20);
    let preimage_a: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x30, 1, 0x40)]);
    let preimage_b: LockedObjectSetPreimage =
        make_preimage(epoch_0, vec![shared.clone(), object_ref(0x50, 1, 0x60)]);
    let digest_a: Digest32 = compute_preimage_digest(&resolver(), &preimage_a);
    let digest_b: Digest32 = compute_preimage_digest(&resolver(), &preimage_b);

    let vote_a: FastVote = cert_0
        .cast_vote(digest(0x01), digest(0x02), digest_a, &signers[0])
        .unwrap();
    let vote_b: FastVote = cert_0
        .cast_vote(digest(0x03), digest(0x04), digest_b, &signers[0])
        .unwrap();

    let bytes_a: Vec<u8> = encode_fast_vote(&vote_a).unwrap();
    let bytes_b: Vec<u8> = encode_fast_vote(&vote_b).unwrap();
    let preimage_bytes_a: Vec<u8> = encode_locked_object_set_preimage(&preimage_a).unwrap();
    let preimage_bytes_b: Vec<u8> = encode_locked_object_set_preimage(&preimage_b).unwrap();

    // 3. Submit class (b) evidence: Recorded
    let submit_outcome = submit_fast_vote_object_conflict_evidence(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        &bytes_a,
        &bytes_b,
        &preimage_bytes_a,
        &preimage_bytes_b,
        5,
    )
    .unwrap();
    let record = match submit_outcome {
        EquivocationEvidenceOutcome::Recorded(r) => r,
        _ => panic!("expected Recorded"),
    };

    // 4. Real e -> e+1 transition excluding seed 101
    // Propose and vote with 3 of the epoch 0 validators (e.g. seeds 102, 103, 104)
    let mut transition_votes: Vec<EpochTransitionVote> = Vec::new();
    for signer in &signers[1..4] {
        let vote = propose_and_vote(
            &store,
            &context(),
            domain(),
            &resolver(),
            &chain(),
            protocol_version(),
            next_entries.clone(),
            signer,
        )
        .unwrap();
        transition_votes.push(vote);
    }

    let et_cert = transition_certifier(epoch_0, &entries);
    let certificate: consensus::EpochTransitionCertificate = et_cert
        .try_form_certificate(
            transition_votes[0].next_epoch,
            transition_votes[0].current_validator_set_digest,
            transition_votes[0].next_validator_set_digest,
            transition_votes[0].activation_digest,
            &transition_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let cert_bytes: Vec<u8> = consensus::encode_epoch_transition_certificate(&certificate).unwrap();

    activate(
        &store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        next_entries.clone(),
        &cert_bytes,
        10,
    )
    .unwrap();

    // Close stores
    drop(store);
    drop(blob_store);

    // Reopen store and restart-verify -> VerifiedExisting
    let reopened_store = SqliteDurableStore::open(
        &state_path,
        namespace,
        WriterFenceGeneration::new(2).unwrap(),
    )
    .unwrap();

    let restart_outcome = install_genesis_with_history(
        &reopened_store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &fixture.manifest,
        1,
    )
    .unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));

    // 5. Query evidence by historical key, decode, re-run verify against historical epoch 0 set
    let decoded_evidence = decode_dispatched(&record.evidence_bytes).unwrap();
    let conflict_digest = normalized_identity_digest(&resolver(), &decoded_evidence).unwrap();

    let queried_record = query_fastpath_equivocation_evidence(
        &reopened_store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        epoch_0,
        *retired_validator_id.as_bytes(),
        conflict_digest,
    )
    .unwrap()
    .expect("equivocation evidence must be queryable after transition");

    let queried_evidence =
        decode_fast_vote_object_conflict_evidence(&queried_record.evidence_bytes).unwrap();
    let historical_set = load_historical_validator_set(
        &reopened_store,
        &context(),
        domain(),
        &resolver(),
        &chain(),
        protocol_version(),
        epoch_0,
    )
    .unwrap();

    // Verification against historical set SUCCEEDS
    assert_eq!(
        verify_fast_vote_object_conflict_evidence(
            &queried_evidence,
            historical_set,
            &FastPathEd25519Verifier,
        ),
        Ok(())
    );

    // 6. Negative control: the same re-verification against the live epoch 1 set fails UnknownValidator
    let live_set: ValidatorSet = ValidatorSet::new(
        epoch_0,
        next_entries
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();

    let live_verify_result = verify_fast_vote_object_conflict_evidence(
        &queried_evidence,
        live_set,
        &FastPathEd25519Verifier,
    );
    assert_eq!(
        live_verify_result,
        Err(ConsensusError::UnknownValidator(retired_validator_id))
    );
}
