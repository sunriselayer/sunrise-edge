use super::*;
use crate::{MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES};

fn domain(marker: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([marker; 32]).unwrap()
}

fn read(key: &[u8], revision: u64) -> StateReadAssertion {
    StateReadAssertion::new(key.to_vec(), StateRevision::new(revision)).unwrap()
}

fn mutation(key: &[u8], value: StateMutation) -> StateMutationEntry {
    StateMutationEntry::new(key.to_vec(), value).unwrap()
}

fn section(
    own_domain: AtomicityDomainId,
    reads: Vec<StateReadAssertion>,
    mutations: Vec<StateMutationEntry>,
) -> DurableStateTransaction {
    DurableStateTransaction::new(
        own_domain,
        AtomicStateReadSet::new(reads).unwrap(),
        mutations,
    )
    .unwrap()
}

#[test]
fn observations_coalesce_only_identical_revisions_and_preserve_failed_additions() {
    let mut observations: StateObservationSet = StateObservationSet::new(domain(1));
    observations.observe(read(b"tombstone", 7)).unwrap();
    observations.observe(read(b"absent", 0)).unwrap();
    let before: StateObservationSet = observations.clone();
    observations.observe(read(b"tombstone", 7)).unwrap();
    assert_eq!(observations, before);
    assert_eq!(
        observations.observe(read(b"tombstone", 8)),
        Err(StateAssemblyError::ConflictingObservation {
            key: b"tombstone".to_vec(),
            first: StateRevision::new(7),
            second: StateRevision::new(8),
        })
    );
    assert_eq!(observations, before);
    let canonical: AtomicStateReadSet = observations.into_read_set().unwrap();
    assert_eq!(
        canonical.reads(),
        &[read(b"absent", 0), read(b"tombstone", 7)]
    );
}

#[test]
fn observation_merge_is_same_domain_and_all_or_none() {
    let mut target: StateObservationSet = StateObservationSet::new(domain(1));
    target.observe(read(b"z", 3)).unwrap();
    let before: StateObservationSet = target.clone();
    let mut incoming: StateObservationSet = StateObservationSet::new(domain(1));
    incoming.observe(read(b"a", 0)).unwrap();
    incoming.observe(read(b"z", 4)).unwrap();
    assert!(matches!(
        target.merge_observations(&incoming),
        Err(StateAssemblyError::ConflictingObservation { .. })
    ));
    assert_eq!(
        target, before,
        "the earlier new key must not be partially merged"
    );
    let foreign: StateObservationSet = StateObservationSet::new(domain(2));
    assert_eq!(
        target.merge_observations(&foreign),
        Err(StateAssemblyError::Runtime(
            RuntimeError::AtomicityDomainMismatch
        ))
    );
    assert_eq!(target, before);
}

#[test]
fn strict_mutation_ownership_and_exact_coalescing_are_distinct() {
    let mut builder: StateTransactionBuilder = StateTransactionBuilder::new(domain(1));
    builder.observe(read(b"x", 5)).unwrap();
    let original: StateMutationEntry = mutation(b"x", StateMutation::Put(vec![9]));
    builder.insert_mutation_once(original.clone()).unwrap();
    let before: StateTransactionBuilder = builder.clone();
    assert_eq!(
        builder.insert_mutation_once(original.clone()),
        Err(StateAssemblyError::Runtime(
            RuntimeError::DuplicateStateWriteKey
        ))
    );
    assert_eq!(builder, before);
    builder.coalesce_mutation_exact(original).unwrap();
    assert_eq!(builder, before);
    for disagreeing in [StateMutation::Put(vec![10]), StateMutation::Delete] {
        assert_eq!(
            builder.coalesce_mutation_exact(mutation(b"x", disagreeing)),
            Err(StateAssemblyError::ConflictingMutation { key: b"x".to_vec() })
        );
        assert_eq!(builder, before);
    }
    assert_eq!(
        builder.insert_mutation_once(mutation(b"unobserved", StateMutation::Delete)),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateMutationWithoutRead
        ))
    );
    assert_eq!(builder, before);
    assert!(matches!(
        builder.observe(read(b"x", 6)),
        Err(StateAssemblyError::ConflictingObservation { .. })
    ));
    assert_eq!(builder, before);
}

#[test]
fn state_section_merge_preflights_domain_read_and_mutation_disagreement() {
    let mut builder: StateTransactionBuilder = StateTransactionBuilder::new(domain(1));
    builder.observe(read(b"z", 3)).unwrap();
    builder
        .insert_mutation_once(mutation(b"z", StateMutation::Delete))
        .unwrap();
    let before: StateTransactionBuilder = builder.clone();
    let read_conflict: DurableStateTransaction = section(
        domain(1),
        vec![read(b"a", 0), read(b"z", 4)],
        vec![mutation(b"a", StateMutation::Put(vec![1]))],
    );
    assert!(matches!(
        builder.merge_state_exact(&read_conflict),
        Err(StateAssemblyError::ConflictingObservation { .. })
    ));
    assert_eq!(builder, before);
    let mutation_conflict: DurableStateTransaction = section(
        domain(1),
        vec![read(b"a", 0), read(b"z", 3)],
        vec![
            mutation(b"a", StateMutation::Delete),
            mutation(b"z", StateMutation::Put(vec![2])),
        ],
    );
    assert_eq!(
        builder.merge_state_exact(&mutation_conflict),
        Err(StateAssemblyError::ConflictingMutation { key: b"z".to_vec() })
    );
    assert_eq!(builder, before);
    let foreign: DurableStateTransaction = section(domain(2), vec![read(b"a", 0)], Vec::new());
    assert_eq!(
        builder.merge_state_exact(&foreign),
        Err(StateAssemblyError::Runtime(
            RuntimeError::AtomicityDomainMismatch
        ))
    );
    assert_eq!(builder, before);
    let exact: DurableStateTransaction = section(
        domain(1),
        vec![read(b"a", 0), read(b"z", 3)],
        vec![
            mutation(b"a", StateMutation::Put(vec![1])),
            mutation(b"z", StateMutation::Delete),
        ],
    );
    builder.merge_state_exact(&exact).unwrap();
    assert_eq!(builder.clone().finish_invocation_state().unwrap(), exact);
    let merged: StateTransactionBuilder = builder.clone();
    builder.merge_state_exact(&exact).unwrap();
    assert_eq!(
        builder, merged,
        "exact replay must not inflate counts or bytes"
    );
}

#[test]
fn finishes_preserve_existing_canonical_transactions_and_accounting() {
    let own_domain: AtomicityDomainId = domain(1);
    let mut observations: StateObservationSet = StateObservationSet::new(own_domain);
    observations.observe(read(b"z", 0)).unwrap();
    observations.observe(read(b"a", 17)).unwrap();
    let mut builder: StateTransactionBuilder =
        StateTransactionBuilder::from_observations(observations);
    builder
        .insert_mutation_once(mutation(b"z", StateMutation::Put(vec![3, 4])))
        .unwrap();
    builder
        .insert_mutation_once(mutation(b"a", StateMutation::Delete))
        .unwrap();
    let expected: DurableStateTransaction = section(
        own_domain,
        vec![read(b"z", 0), read(b"a", 17)],
        vec![
            mutation(b"z", StateMutation::Put(vec![3, 4])),
            mutation(b"a", StateMutation::Delete),
        ],
    );
    assert_eq!(builder.clone().finish_invocation_state().unwrap(), expected);
    let expected_atomic: AtomicStateTransaction = AtomicStateTransaction::new(
        own_domain,
        AtomicStateReadSet::new(vec![read(b"z", 0), read(b"a", 17)]).unwrap(),
        AtomicStateMutationSet::new(vec![
            mutation(b"z", StateMutation::Put(vec![3, 4])),
            mutation(b"a", StateMutation::Delete),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(builder.finish_metadata().unwrap(), expected_atomic);
    // Independently fixed widths: domain32, two counts4, read(keylen4+key+rev8),
    // mutation(keylen4+key+tag1), Put additionally(value-length8+value2).
    assert_eq!(
        expected.represented_bytes(),
        32 + 8 + 2 * 13 + 2 * 6 + 8 + 2
    );
}

#[test]
fn metadata_and_receipt_bearing_state_keep_distinct_empty_mutation_rules() {
    let mut builder: StateTransactionBuilder = StateTransactionBuilder::new(domain(1));
    assert!(builder.is_unchanged());
    assert_eq!(
        builder.clone().finish_invocation_state(),
        Err(RuntimeError::EmptyReadSet)
    );
    assert_eq!(
        builder.clone().finish_metadata(),
        Err(RuntimeError::EmptyReadSet)
    );
    builder.observe(read(b"read-only", 9)).unwrap();
    assert_eq!(
        builder.clone().finish_metadata(),
        Err(RuntimeError::EmptyWriteSet)
    );
    let state: DurableStateTransaction = builder.finish_invocation_state().unwrap();
    assert!(state.mutations().is_empty());
    assert_eq!(state.reads(), &[read(b"read-only", 9)]);
}

#[test]
fn exact_count_boundary_and_oversized_merges_preserve_existing_state() {
    let mut observations: StateObservationSet = StateObservationSet::new(domain(1));
    for index in 0..MAX_ATOMIC_STATE_READS {
        observations.observe(read(&index.to_be_bytes(), 0)).unwrap();
    }
    let before: StateObservationSet = observations.clone();
    observations
        .observe(read(&0_usize.to_be_bytes(), 0))
        .unwrap();
    assert_eq!(observations, before);
    let excess_key: Vec<u8> = MAX_ATOMIC_STATE_READS.to_be_bytes().to_vec();
    assert_eq!(
        observations.observe(read(&excess_key, 0)),
        Err(StateAssemblyError::Runtime(
            RuntimeError::TooManyStateReads {
                count: MAX_ATOMIC_STATE_READS + 1,
                maximum: MAX_ATOMIC_STATE_READS,
            }
        ))
    );
    assert_eq!(observations, before);
    let mut additional: StateObservationSet = StateObservationSet::new(domain(1));
    additional.observe(read(&excess_key, 0)).unwrap();
    assert!(matches!(
        observations.merge_observations(&additional),
        Err(StateAssemblyError::Runtime(
            RuntimeError::TooManyStateReads { .. }
        ))
    ));
    assert_eq!(observations, before);
    let mut builder: StateTransactionBuilder =
        StateTransactionBuilder::from_observations(observations);
    for index in 0..MAX_ATOMIC_STATE_WRITES {
        builder
            .insert_mutation_once(mutation(&index.to_be_bytes(), StateMutation::Delete))
            .unwrap();
    }
    let complete: AtomicStateTransaction = builder.finish_metadata().unwrap();
    assert_eq!(complete.reads().len(), MAX_ATOMIC_STATE_READS);
    assert_eq!(complete.mutations().len(), MAX_ATOMIC_STATE_WRITES);
}

#[test]
fn typed_entries_keep_existing_individual_key_value_and_assert_bounds() {
    assert!(StateReadAssertion::new(vec![1; MAX_STATE_KEY_BYTES], StateRevision::INITIAL).is_ok());
    assert!(matches!(
        StateReadAssertion::new(vec![1; MAX_STATE_KEY_BYTES + 1], StateRevision::INITIAL),
        Err(RuntimeError::StateKeyTooLong { .. })
    ));
    assert!(matches!(
        StateMutationEntry::new(
            b"x".to_vec(),
            StateMutation::Put(vec![0; MAX_STATE_VALUE_BYTES + 1])
        ),
        Err(RuntimeError::StateValueTooLarge { .. })
    ));
    assert_eq!(
        StateMutationEntry::new(b"x".to_vec(), StateMutation::Assert),
        Err(RuntimeError::StateAssertionAsMutation)
    );
}

#[test]
fn legal_maximum_aggregate_and_one_byte_excess_are_not_conflated() {
    let mut builder: StateTransactionBuilder = StateTransactionBuilder::new(domain(1));
    builder.observe(read(b"a", 0)).unwrap();
    builder.observe(read(b"b", 0)).unwrap();
    builder
        .insert_mutation_once(mutation(
            b"a",
            StateMutation::Put(vec![1; MAX_STATE_VALUE_BYTES]),
        ))
        .unwrap();
    // Two one-byte keys: domain32+counts8+reads26+mutations12+Put-lengths16.
    let overhead: usize = 32 + 8 + 2 * (4 + 1 + 8) + 2 * (4 + 1 + 1 + 8);
    let remaining: usize = MAX_ATOMIC_STATE_TRANSACTION_BYTES - overhead - MAX_STATE_VALUE_BYTES;
    let before: StateTransactionBuilder = builder.clone();
    assert_eq!(
        builder.insert_mutation_once(mutation(b"b", StateMutation::Put(vec![2; remaining + 1]))),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateTransactionTooLarge {
                bytes: MAX_ATOMIC_STATE_TRANSACTION_BYTES + 1,
                maximum: MAX_ATOMIC_STATE_TRANSACTION_BYTES,
            }
        ))
    );
    assert_eq!(builder, before);
    builder
        .insert_mutation_once(mutation(b"b", StateMutation::Put(vec![2; remaining])))
        .unwrap();
    let state: DurableStateTransaction = builder.finish_invocation_state().unwrap();
    assert_eq!(
        state.represented_bytes(),
        MAX_ATOMIC_STATE_TRANSACTION_BYTES
    );
}

#[test]
fn byte_budget_failures_leave_whole_section_and_observation_merges_unchanged() {
    let mut builder: StateTransactionBuilder = StateTransactionBuilder::new(domain(1));
    builder.observe(read(b"a", 0)).unwrap();
    builder
        .insert_mutation_once(mutation(
            b"a",
            StateMutation::Put(vec![1; MAX_STATE_VALUE_BYTES]),
        ))
        .unwrap();
    let before: StateTransactionBuilder = builder.clone();
    let incoming: DurableStateTransaction = section(
        domain(1),
        vec![read(b"b", 0)],
        vec![mutation(
            b"b",
            StateMutation::Put(vec![2; MAX_STATE_VALUE_BYTES]),
        )],
    );
    assert!(matches!(
        builder.merge_state_exact(&incoming),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateTransactionTooLarge { .. }
        ))
    ));
    assert_eq!(builder, before);
    drop(incoming);
    // Build one exactly-full transaction, then prove both point observation
    // and a whole read-only contribution reject without changing that state.
    builder.observe(read(b"b", 0)).unwrap();
    let overhead: usize = 32 + 8 + 2 * (4 + 1 + 8) + 2 * (4 + 1 + 1 + 8);
    let remaining: usize = MAX_ATOMIC_STATE_TRANSACTION_BYTES - overhead - MAX_STATE_VALUE_BYTES;
    builder
        .insert_mutation_once(mutation(b"b", StateMutation::Put(vec![2; remaining])))
        .unwrap();
    let full: StateTransactionBuilder = builder.clone();
    assert!(matches!(
        builder.observe(read(b"c", 0)),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateTransactionTooLarge { .. }
        ))
    ));
    assert_eq!(builder, full);
    let mut additional: StateObservationSet = StateObservationSet::new(domain(1));
    additional.observe(read(b"c", 0)).unwrap();
    assert!(matches!(
        builder.merge_observations(&additional),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateTransactionTooLarge { .. }
        ))
    ));
    assert_eq!(builder, full);
    let read_only: DurableStateTransaction = section(domain(1), vec![read(b"c", 0)], Vec::new());
    assert!(matches!(
        builder.merge_state_exact(&read_only),
        Err(StateAssemblyError::Runtime(
            RuntimeError::StateTransactionTooLarge { .. }
        ))
    ));
    assert_eq!(builder, full);
}
