//! Focused DR-0130 commitment-witness regressions.
//!
//! [`crate::fast_path::apply`] persists the exact `0x6424/v1` commitment
//! envelope bytes ([`commitment::compute_with_envelope`]) at
//! [`local_instance_state::fastpath_commitment_witness_key`], atomically
//! alongside its certificate and settlement rows, because a
//! [`consensus::FastCertificate`] signs only that envelope's digest
//! (`execution_effects_hash`) and never retains its preimage. Without this
//! row, a later verifier could never recover the certified
//! `PaidExecutionResult` -- in particular the charged outcome that fixed the
//! initial settlement total and fee output -- from the certificate alone.
//!
//! This file duplicates a minimal slice of `fast_path::tests`' own
//! prepare/apply harness: that module's helpers are private to it and not
//! reachable from this sibling module.
use super::*;
use crate::paid_execution::tests::{
    CountingEngine, FIRST_PAID_NONCE, Fixture, PaidCall, base_policy, context, domain, entry,
    install, memory_store, paid_call_with_access, protocol, receipt, refund_account, resolver,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::paid_execution::{PaidChargedOutcome, PaidExecutionResult, ReservationAccessKind};
use runtime::{DurableDomainStateStore, MemoryBlobStore, MemoryDurableStateStore};

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

/// Four equal-power validators, mirroring `fast_path::tests::four_validators`
/// with a distinct seed range so keys never collide across the two files.
fn four_validators() -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let mut signers: Vec<TestSigner> = Vec::new();
    let mut entries: Vec<FastPathValidatorEntry> = Vec::new();
    for seed in [201u8, 202, 203, 204] {
        let (signer, entry) = validator(seed);
        signers.push(signer);
        entries.push(entry);
    }
    (signers, entries)
}

fn install_four_validators<S: StructuredDurableDomainStateStore>(
    store: &S,
) -> (Vec<TestSigner>, Vec<FastPathValidatorEntry>) {
    let (signers, entries) = four_validators();
    install_validator_set(
        store,
        &context(),
        domain(),
        &resolver(),
        protocol(),
        entries.clone(),
    )
    .unwrap();
    (signers, entries)
}

fn certifier(validator_set: ValidatorSet) -> consensus::FastPathCertifier {
    consensus::FastPathCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        validator_set,
    )
    .unwrap()
}

fn transfer_bytes(fixture: &Fixture, request: u8, nonce: u64) -> Vec<u8> {
    paid_call_with_access(
        PaidCall {
            fixture,
            policy: &fixture.policy,
            request,
            nonce,
            source: &fixture.coin,
            entrypoint: "transfer",
            arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
            access: vec![entry(&fixture.coin, objects::AccessMode::Write)],
        },
        ReservationAccessKind::Write,
    )
}

fn prepare_transfer<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    signer: &TestSigner,
    request: u8,
    nonce: u64,
) -> FastPathResult<FastVote> {
    prepare(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        signer,
        &transfer_bytes(fixture, request, nonce),
        10,
    )
}

fn apply_transfer<S: StructuredDurableDomainStateStore>(
    store: &S,
    fixture: &Fixture,
    request: u8,
    nonce: u64,
    certificate_bytes: &[u8],
) -> FastPathResult<NodeOutput> {
    apply(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        &transfer_bytes(fixture, request, nonce),
        certificate_bytes,
    )
}

/// Runs one full prepare -> 3-of-4 quorum certificate -> apply cycle for a
/// charged `transfer` call under a fresh store/fixture, then reads back the
/// commitment witness [`crate::fast_path::apply`] must have durably
/// persisted alongside the certificate and settlement rows.
fn prepare_and_apply(
    request: u8,
) -> (
    MemoryDurableStateStore,
    Vec<u8>,
    FastCertificate,
    PaidExecutionResult,
) {
    let store: MemoryDurableStateStore = memory_store();
    let fixture: Fixture = install(&store);
    let (signers, entries) = install_four_validators(&store);
    let vote: FastVote =
        prepare_transfer(&store, &fixture, &signers[0], request, FIRST_PAID_NONCE).unwrap();
    let validator_set: ValidatorSet = ValidatorSet::new(
        protocol().epoch(),
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
    let cert: consensus::FastPathCertifier = certifier(validator_set);
    let remote_votes: Vec<FastVote> = signers[1..3]
        .iter()
        .map(|signer| {
            cert.cast_vote(
                vote.tx_hash,
                vote.execution_effects_hash,
                vote.locked_objects_digest,
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut all_votes: Vec<FastVote> = vec![vote.clone()];
    all_votes.extend(remote_votes);
    let certificate: FastCertificate = cert
        .try_form_certificate(
            vote.tx_hash,
            vote.execution_effects_hash,
            vote.locked_objects_digest,
            &all_votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("three of four equal-power votes is quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();

    let output: NodeOutput = apply_transfer(
        &store,
        &fixture,
        request,
        FIRST_PAID_NONCE,
        &certificate_bytes,
    )
    .unwrap();
    let result: PaidExecutionResult = receipt(&output);

    let witness_key: Vec<u8> = local_instance_state::fastpath_commitment_witness_key(
        protocol().chain_id(),
        &[request; 32],
    )
    .unwrap();
    let witness_bytes: Vec<u8> = store
        .get_versioned_durable(&context(), domain(), &witness_key)
        .unwrap()
        .value()
        .expect("a successful certificate apply must persist the commitment witness")
        .to_vec();
    (store, witness_bytes, certificate, result)
}

/// The witness `apply` persists decodes back to the exact signed-intent
/// digest and `PaidExecutionResult` the certificate and receipt attest to,
/// its hash matches `certificate.execution_effects_hash`, and its decoded
/// charged outcome reconstructs the exact total/fee-output the committed
/// settlement row itself carries -- proving a verifier with only the
/// witness (never live admission internals) can recover both.
#[test]
fn apply_persists_a_commitment_witness_matching_the_certificate_and_charged_settlement() {
    let (store, witness_bytes, certificate, result): (
        MemoryDurableStateStore,
        Vec<u8>,
        FastCertificate,
        PaidExecutionResult,
    ) = prepare_and_apply(0x51);

    let decoded: commitment::DecodedCommitmentWitness =
        commitment::decode_witness(&witness_bytes).unwrap();
    assert_eq!(decoded.event_digest, certificate.tx_hash);
    assert_eq!(decoded.paid_execution_result, result);

    let rehashed: Digest32 =
        commitment::hash_witness_bytes(&resolver(), protocol().epoch(), &witness_bytes).unwrap();
    assert_eq!(rehashed, certificate.execution_effects_hash);

    let settlement_bytes: Vec<u8> = store
        .get_versioned_durable(
            &context(),
            domain(),
            &fastpath_settlement_key(protocol().chain_id(), &[0x51; 32]).unwrap(),
        )
        .unwrap()
        .value()
        .expect("certificate apply must commit its settlement row")
        .to_vec();
    let settlement: FastPathSettlementRecord =
        records::decode_fastpath_settlement_record(&settlement_bytes).unwrap();
    let charged: PaidChargedOutcome = decoded
        .paid_execution_result
        .charged
        .clone()
        .expect("this fixture's transfer call is charged");
    assert_eq!(settlement.total_amount, Some(charged.actual.get()));
    assert_eq!(settlement.fee_output, Some(charged.fee_output));
}

/// A witness row truncated by even one byte must never decode: the exact
/// preimage bytes are what the certificate's digest binds to, so a partial
/// copy is worthless and must fail closed rather than decode "enough".
#[test]
fn commitment_witness_decode_rejects_truncated_bytes() {
    let (_store, witness_bytes, _certificate, _result) = prepare_and_apply(0x52);
    let truncated: &[u8] = &witness_bytes[..witness_bytes.len() - 1];
    assert!(commitment::decode_witness(truncated).is_err());
}

/// A single-byte tamper inside the envelope's event-digest field (field 1)
/// changes no field length and no cross-checked invariant `decode_witness`
/// itself enforces, so the frame still decodes structurally -- but
/// `hash_witness_bytes` over the tampered bytes no longer reproduces
/// `certificate.execution_effects_hash`. This is the property a verifier
/// actually relies on: decode alone is not the tamper check, re-hashing
/// against the certified digest is.
#[test]
fn commitment_witness_tamper_in_event_digest_survives_decode_but_fails_hash_binding() {
    let (_store, witness_bytes, certificate, _result) = prepare_and_apply(0x53);
    let digest_bytes: [u8; 32] = certificate.tx_hash.bytes();
    let position: usize = witness_bytes
        .windows(digest_bytes.len())
        .position(|window| window == digest_bytes)
        .expect("the event digest bytes must appear verbatim in the witness");
    let mut altered: Vec<u8> = witness_bytes.clone();
    altered[position + digest_bytes.len() - 1] ^= 0xFF;

    let decoded: commitment::DecodedCommitmentWitness =
        commitment::decode_witness(&altered).expect("still a structurally valid 0x6424/v1 frame");
    assert_ne!(decoded.event_digest, certificate.tx_hash);

    let rehashed: Digest32 =
        commitment::hash_witness_bytes(&resolver(), protocol().epoch(), &altered).unwrap();
    assert_ne!(rehashed, certificate.execution_effects_hash);
}

/// A real envelope always carries exactly fields `1..=10`
/// (`commitment::encode_envelope`'s own closed layout): a frame missing the
/// nonce-value field (10) must be rejected, not silently accepted with a
/// default.
#[test]
fn commitment_witness_decode_rejects_a_frame_missing_a_required_field() {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6424, 1);
    for field_id in 1u16..=9 {
        if field_id == 9 {
            frame.field_u64(field_id, 0).unwrap();
        } else {
            frame.field_bytes(field_id, vec![0u8; 4]).unwrap();
        }
    }
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(commitment::decode_witness(&bytes).is_err());
}

/// Conversely, a frame carrying an extra, unrecognized field beyond the
/// closed `1..=10` set must also be rejected, not silently ignored.
#[test]
fn commitment_witness_decode_rejects_a_frame_with_an_unexpected_field() {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6424, 1);
    for field_id in 1u16..=10 {
        if field_id == 9 {
            frame.field_u64(field_id, 0).unwrap();
        } else {
            frame.field_bytes(field_id, vec![0u8; 4]).unwrap();
        }
    }
    frame.field_bytes(11, vec![0u8; 1]).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(commitment::decode_witness(&bytes).is_err());
}
