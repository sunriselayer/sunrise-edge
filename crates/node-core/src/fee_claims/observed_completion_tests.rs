use super::*;

#[test]
fn fee_state_assembly_errors_preserve_conflict_and_runtime_stop_classification() {
    let conflict: FeeClaimError = StateAssemblyError::ConflictingObservation {
        key: b"observed".to_vec(),
        first: StateRevision::new(1),
        second: StateRevision::new(2),
    }
    .into();
    assert!(matches!(
        conflict,
        FeeClaimError::Node(NodeCoreError::StateConflict)
    ));
    for error in [
        StateAssemblyError::Runtime(RuntimeError::DuplicateStateWriteKey),
        StateAssemblyError::ConflictingMutation {
            key: b"owned".to_vec(),
        },
    ] {
        assert!(matches!(
            FeeClaimError::from(error),
            FeeClaimError::Node(NodeCoreError::Runtime(RuntimeError::DuplicateStateWriteKey))
        ));
    }
}
