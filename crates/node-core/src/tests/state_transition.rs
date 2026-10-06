//! Independent refusal-order controls for the private preparation owner.

use super::*;
use crate::{MAX_NODE_STATE_BYTES, NodeStateAccess};
use runtime::RuntimeError;

fn plan(entries: &[(&[u8], NodeStateAccessMode)]) -> NodeStateAccessPlan {
    let accesses: Vec<NodeStateAccess> = entries
        .iter()
        .map(|(key, mode)| NodeStateAccess::new(key.to_vec(), *mode).unwrap())
        .collect();
    NodeStateAccessPlan::new(accesses).unwrap()
}

fn snapshot(entries: &[(&[u8], u64)]) -> NodeStateSnapshot {
    let values: BTreeMap<Vec<u8>, VersionedStateValue> = entries
        .iter()
        .map(|(key, revision)| {
            (
                key.to_vec(),
                VersionedStateValue::from_persisted_parts(StateRevision::new(*revision), None)
                    .unwrap(),
            )
        })
        .collect();
    NodeStateSnapshot {
        values,
        resolved_objects: Vec::new(),
    }
}

#[test]
fn loader_stops_at_first_read_failure_in_sorted_order() {
    let declared: NodeStateAccessPlan = plan(&[
        (b"state/c", NodeStateAccessMode::ReadOnly),
        (b"state/b", NodeStateAccessMode::ReadOnly),
        (b"state/a", NodeStateAccessMode::ReadOnly),
    ]);
    let mut calls: Vec<Vec<u8>> = Vec::new();
    let result: Result<BTreeMap<Vec<u8>, VersionedStateValue>, NodeCoreError> =
        load_declared_values(&declared, |key| {
            calls.push(key.to_vec());
            if key == b"state/b" {
                return Err(NodeCoreError::Runtime(
                    RuntimeError::DurableStoreUnavailable,
                ));
            }
            Ok(VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap())
        });
    assert_eq!(
        result,
        Err(NodeCoreError::Runtime(
            RuntimeError::DurableStoreUnavailable
        ))
    );
    assert_eq!(calls, vec![b"state/a".to_vec(), b"state/b".to_vec()]);
}

#[test]
fn state_size_refusal_precedes_canonical_decoding() {
    // Runtime observations already enforce the same size bound. Exercise the
    // existing core validator directly rather than inventing an invalid stored
    // observation or changing the runtime constructor to admit one.
    let oversized_invalid_frame: Vec<u8> = vec![0xFF; MAX_NODE_STATE_BYTES + 1];
    assert_eq!(
        validate_state(&oversized_invalid_frame),
        Err(NodeCoreError::StateTooLarge(MAX_NODE_STATE_BYTES + 1))
    );
}

#[test]
fn both_envelopes_keep_absent_and_tombstone_revisions() {
    let declared: NodeStateAccessPlan = plan(&[
        (b"state/b", NodeStateAccessMode::ReadOnly),
        (b"state/a", NodeStateAccessMode::ReadOnly),
    ]);
    let observations: NodeStateSnapshot = snapshot(&[(b"state/a", 0), (b"state/b", 7)]);
    let writes: Vec<StateWrite> =
        asserted_transition_writes(&declared, &observations, Vec::new()).unwrap();
    let (reads, mutations): (Vec<StateReadAssertion>, Vec<StateMutationEntry>) =
        domain_transition_parts(&declared, &observations, Vec::new()).unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(reads.len(), 2);
    assert!(mutations.is_empty());
    for (index, (key, revision)) in [(b"state/a".as_slice(), 0), (b"state/b".as_slice(), 7)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(writes[index].key(), key);
        assert_eq!(
            writes[index].expected_revision(),
            StateRevision::new(revision)
        );
        assert_eq!(writes[index].mutation(), &StateMutation::Assert);
        assert_eq!(reads[index].key(), key);
        assert_eq!(
            reads[index].expected_revision(),
            StateRevision::new(revision)
        );
    }
}

#[test]
fn both_assemblers_keep_missing_observation_invariant() {
    let declared: NodeStateAccessPlan = plan(&[(b"state/a", NodeStateAccessMode::ReadWrite)]);
    let missing: NodeStateSnapshot = snapshot(&[]);
    let expected: NodeCoreError =
        NodeCoreError::PersistenceInvariant("declared access missing from snapshot");
    assert_eq!(
        asserted_transition_writes(&declared, &missing, Vec::new()),
        Err(expected.clone())
    );
    assert_eq!(
        domain_transition_parts(&declared, &missing, Vec::new()),
        Err(expected)
    );
}

#[test]
fn update_refusals_precede_missing_observations_in_both_assemblers() {
    let declared: NodeStateAccessPlan = plan(&[(b"state/a", NodeStateAccessMode::ReadOnly)]);
    let missing: NodeStateSnapshot = snapshot(&[]);
    for (key, expected) in [
        (
            b"state/a".as_slice(),
            NodeCoreError::ReadOnlyStateUpdate(b"state/a".to_vec()),
        ),
        (
            b"state/z".as_slice(),
            NodeCoreError::UndeclaredStateUpdate(b"state/z".to_vec()),
        ),
    ] {
        let update: NodeStateUpdate = NodeStateUpdate::delete(key.to_vec()).unwrap();
        assert_eq!(
            asserted_transition_writes(&declared, &missing, vec![update.clone()]),
            Err(expected.clone())
        );
        assert_eq!(
            domain_transition_parts(&declared, &missing, vec![update]),
            Err(expected)
        );
    }
}

#[test]
fn domain_constructor_failure_precedes_a_later_undeclared_update() {
    let declared: NodeStateAccessPlan = plan(&[(b"state/a", NodeStateAccessMode::ReadWrite)]);
    let missing: NodeStateSnapshot = snapshot(&[]);
    // Public update constructors cannot create Assert. The internal control
    // keeps the original fallible per-item builder order observable without
    // weakening any public constructor.
    let invalid_mutation: NodeStateUpdate = NodeStateUpdate {
        key: b"state/a".to_vec(),
        mutation: StateMutation::Assert,
    };
    let later_undeclared: NodeStateUpdate = NodeStateUpdate::delete(b"state/z".to_vec()).unwrap();
    assert_eq!(
        domain_transition_parts(
            &declared,
            &missing,
            vec![invalid_mutation, later_undeclared]
        ),
        Err(NodeCoreError::Runtime(
            RuntimeError::StateAssertionAsMutation
        ))
    );
}

#[test]
fn assertion_assembler_checks_all_updates_before_any_write_constructor() {
    // These private invalid declarations pin a latent builder-order contract;
    // they do not replace the public-API baselines or grant invalid key access.
    let declared: NodeStateAccessPlan = NodeStateAccessPlan {
        accesses: vec![NodeStateAccess {
            key: Vec::new(),
            mode: NodeStateAccessMode::ReadWrite,
        }],
    };
    let observations: NodeStateSnapshot = snapshot(&[(b"", 1)]);
    let invalid_first: NodeStateUpdate = NodeStateUpdate {
        key: Vec::new(),
        mutation: StateMutation::Delete,
    };
    let later_undeclared: NodeStateUpdate = NodeStateUpdate::delete(b"state/z".to_vec()).unwrap();
    assert_eq!(
        asserted_transition_writes(
            &declared,
            &observations,
            vec![invalid_first, later_undeclared]
        ),
        Err(NodeCoreError::UndeclaredStateUpdate(b"state/z".to_vec()))
    );
}

#[test]
fn each_read_or_write_constructor_precedes_a_later_missing_observation() {
    let declared: NodeStateAccessPlan = NodeStateAccessPlan {
        accesses: vec![
            NodeStateAccess {
                key: Vec::new(),
                mode: NodeStateAccessMode::ReadOnly,
            },
            NodeStateAccess::new(b"state/z".to_vec(), NodeStateAccessMode::ReadOnly).unwrap(),
        ],
    };
    let observations: NodeStateSnapshot = snapshot(&[(b"", 1)]);
    assert_eq!(
        asserted_transition_writes(&declared, &observations, Vec::new()),
        Err(NodeCoreError::Runtime(RuntimeError::EmptyKey))
    );
    assert_eq!(
        domain_transition_parts(&declared, &observations, Vec::new()),
        Err(NodeCoreError::Runtime(RuntimeError::EmptyKey))
    );
}
