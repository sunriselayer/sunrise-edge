use super::*;
use crate::fast_path::tests::logical_replica;
use crate::logical_generation::{LogicalDerivation, LogicalObservation, ReadObservation};
use crate::paid_execution::tests::{context, domain, memory_store, protocol, resolver};
use execution::paid_execution::encode_paid_execution_result;
use protocol_types::{ExecutionGeneration, HashAlgorithmId};
use runtime::{DurableDomainStateStore, MemoryBlobStore, MemoryDurableStateStore};

const REQUEST: u8 = 0xE4;

/// Real, canonical `0x6415/v1` `PaidExecutionResult` bytes from one genuine
/// handoff-capable prepare (`crate::fast_path::tests::logical_replica`), so
/// every synthetic witness built below decodes under the same strict field-2
/// validation [`commitment::decode_witness`] applies to a real prepare/apply.
/// Only the read-operand list around it is synthetic.
fn real_v2_result_bytes() -> Vec<u8> {
    let replica = logical_replica();
    replica
        .prepare_transfer(REQUEST, crate::paid_execution::tests::FIRST_PAID_NONCE)
        .unwrap();
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    let witness_bytes: Vec<u8> = replica
        .row(&witness_key)
        .expect("a handoff-capable prepare retains its own witness");
    let decoded: commitment::DecodedCommitmentWitness =
        commitment::decode_witness(&witness_bytes).unwrap();
    encode_paid_execution_result(&decoded.paid_execution_result).unwrap()
}

/// Builds a synthetic handoff-capable (`0x6424/v2`) witness whose generic
/// state-read operand list carries exactly `count` distinct present reads,
/// each a required [`ArtifactKind::StateValue`] artifact under a distinct
/// identity, all sharing `content_digest`. Real admission never produces this
/// many reads in one request; this exists solely to exercise the retention-
/// size bound deterministically and cheaply, mirroring `commitment.rs`'s own
/// envelope encoder rather than reimplementing it. `result_bytes` must be
/// real, valid `0x6415/v1` bytes (see [`real_v2_result_bytes`]): only the
/// read-operand list is synthetic.
fn synthetic_witness_with_state_reads(
    result_bytes: &[u8],
    count: usize,
    content_digest: Digest32,
) -> (Vec<u8>, BTreeMap<Vec<u8>, StateRevision>) {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut observations: BTreeMap<Vec<u8>, ReadObservation> = BTreeMap::new();
    for index in 0..count {
        let key: Vec<u8> = format!("synthetic-artifact-key-{index:06}").into_bytes();
        reads.insert(key.clone(), StateRevision::new(1));
        observations.insert(
            key,
            ReadObservation {
                observed: Some(LogicalObservation::StatePresent { content_digest }),
                generation: Some(ExecutionGeneration::new(1)),
            },
        );
    }
    let derived: LogicalDerivation = LogicalDerivation {
        generation: ExecutionGeneration::new(2),
        reads: observations,
        inputs: BTreeMap::new(),
    };
    let witness: Vec<u8> = commitment::encode_envelope(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        result_bytes,
        &[],
        &[],
        &[],
        &reads,
        &[],
        b"synthetic-nonce-key",
        StateRevision::new(1),
        b"synthetic-nonce-value",
        Some(&derived),
    )
    .unwrap();
    (witness, reads)
}

#[test]
fn retain_prepared_material_refuses_an_over_bound_closure_before_any_write() {
    let store: MemoryDurableStateStore = memory_store();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let result_bytes: Vec<u8> = real_v2_result_bytes();
    let content_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x7a; 32]);
    let (witness, _reads) = synthetic_witness_with_state_reads(
        &result_bytes,
        MAX_RETAINED_ARTIFACTS + 1,
        content_digest,
    );
    let request_id: [u8; 32] = [0x33; 32];

    let error = retain_prepared_material(
        &store,
        &blob_store,
        &context(),
        domain(),
        &resolver(),
        protocol().chain_id(),
        &request_id,
        protocol().epoch(),
        &witness,
    )
    .expect_err("a closure over the retention bound must be refused");
    assert!(
        matches!(
            error,
            FastPathError::Publication(PublicationRetentionError::ClosureTooLarge {
                actual,
                max,
            }) if actual == MAX_RETAINED_ARTIFACTS + 1 && max == MAX_RETAINED_ARTIFACTS
        ),
        "unexpected error: {error:?}"
    );

    // Nothing was staged or written: neither the witness row nor any
    // artifact row exists.
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &request_id).unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn retain_prepared_material_accepts_a_closure_at_exactly_the_bound() {
    let store: MemoryDurableStateStore = memory_store();
    let result_bytes: Vec<u8> = real_v2_result_bytes();
    // `MAX_RETAINED_ARTIFACTS` distinct identities (state keys) all holding
    // byte-identical content: the closure has exactly `MAX_RETAINED_ARTIFACTS`
    // *required* `(kind, identity)` entries (proving the bound is measured
    // against distinct identities, not distinct content), even though they
    // content-address down to one physical storage row.
    let content: Vec<u8> = b"shared retained content".to_vec();
    let content_digest: Digest32 = resolver()
        .hash_for_purpose(protocol().epoch(), HashPurpose::ExecutionEffects, &content)
        .unwrap();
    let (witness, reads) =
        synthetic_witness_with_state_reads(&result_bytes, MAX_RETAINED_ARTIFACTS, content_digest);

    let mut mutations: Vec<StateMutationEntry> = Vec::with_capacity(MAX_RETAINED_ARTIFACTS);
    let mut assertions: Vec<StateReadAssertion> = Vec::with_capacity(MAX_RETAINED_ARTIFACTS);
    for key in reads.keys() {
        let observed: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), key)
            .unwrap();
        assertions.push(StateReadAssertion::new(key.clone(), observed.revision()).unwrap());
        mutations.push(
            StateMutationEntry::new(key.clone(), StateMutation::Put(content.clone())).unwrap(),
        );
    }
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(assertions).unwrap(),
        AtomicStateMutationSet::new(mutations).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );

    let request_id: [u8; 32] = [0x44; 32];
    retain_prepared_material(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        protocol().chain_id(),
        &request_id,
        protocol().epoch(),
        &witness,
    )
    .expect("a closure of exactly MAX_RETAINED_ARTIFACTS required identities is accepted");

    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &request_id).unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value(),
        Some(witness.as_slice())
    );
    let artifact_key: Vec<u8> = fastpath_prepared_artifact_key(
        protocol().chain_id(),
        &request_id,
        ArtifactKind::StateValue,
        &content_digest.bytes(),
    )
    .unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &artifact_key)
            .unwrap()
            .value(),
        Some(content.as_slice()),
        "MAX_RETAINED_ARTIFACTS identical-content identities content-address to one row"
    );
}
