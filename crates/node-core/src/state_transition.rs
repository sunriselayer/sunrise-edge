//! Declared state preparation, without admission, object authority or I/O policy.
//!
//! Callers choose their real point-read capability and retain its original place
//! in admission. The two assembly strategies deliberately keep different error
//! ordering and persistence envelopes (DR-0203).

use super::{
    NodeCoreError, NodeStateAccessMode, NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate,
    validate_state,
};
use runtime::{
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StateWrite,
    VersionedStateValue,
};
use std::collections::BTreeMap;

pub(super) fn load_declared_values<F>(
    plan: &NodeStateAccessPlan,
    mut read: F,
) -> Result<BTreeMap<Vec<u8>, VersionedStateValue>, NodeCoreError>
where
    F: FnMut(&[u8]) -> Result<VersionedStateValue, NodeCoreError>,
{
    let mut values: BTreeMap<Vec<u8>, VersionedStateValue> = BTreeMap::new();
    for access in plan.accesses() {
        let observed: VersionedStateValue = read(access.key())?;
        if let Some(value) = observed.value() {
            validate_state(value)?;
        }
        values.insert(access.key().to_vec(), observed);
    }
    Ok(values)
}

fn require_writable_update(plan: &NodeStateAccessPlan, key: &[u8]) -> Result<(), NodeCoreError> {
    let Some(access) = plan.access(key) else {
        return Err(NodeCoreError::UndeclaredStateUpdate(key.to_vec()));
    };
    if access.mode() != NodeStateAccessMode::ReadWrite {
        return Err(NodeCoreError::ReadOnlyStateUpdate(key.to_vec()));
    }
    Ok(())
}

fn declared_revision(
    snapshot: &NodeStateSnapshot,
    key: &[u8],
) -> Result<StateRevision, NodeCoreError> {
    let observed: &VersionedStateValue =
        snapshot
            .get(key)
            .ok_or(NodeCoreError::PersistenceInvariant(
                "declared access missing from snapshot",
            ))?;
    Ok(observed.revision())
}

pub(super) fn asserted_transition_writes(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<Vec<StateWrite>, NodeCoreError> {
    // Every update refusal precedes observation lookup or fallible write building.
    let mut mutations: BTreeMap<Vec<u8>, StateMutation> = BTreeMap::new();
    for update in updates {
        require_writable_update(plan, update.key())?;
        mutations.insert(update.key, update.mutation);
    }

    let mut writes: Vec<StateWrite> = Vec::with_capacity(plan.accesses().len());
    for access in plan.accesses() {
        let revision: StateRevision = declared_revision(snapshot, access.key())?;
        let mutation: StateMutation = mutations
            .remove(access.key())
            .unwrap_or(StateMutation::Assert);
        writes.push(StateWrite::new(access.key().to_vec(), revision, mutation)?);
    }
    Ok(writes)
}

pub(super) fn domain_transition_parts(
    plan: &NodeStateAccessPlan,
    snapshot: &NodeStateSnapshot,
    updates: Vec<NodeStateUpdate>,
) -> Result<(Vec<StateReadAssertion>, Vec<StateMutationEntry>), NodeCoreError> {
    // Each mutation constructor can refuse before a later update is checked.
    let mut mutations: Vec<StateMutationEntry> = Vec::with_capacity(updates.len());
    for update in updates {
        require_writable_update(plan, update.key())?;
        mutations.push(StateMutationEntry::new(update.key, update.mutation)?);
    }

    let reads: Vec<StateReadAssertion> = plan
        .accesses()
        .iter()
        .map(|access| -> Result<StateReadAssertion, NodeCoreError> {
            let revision: StateRevision = declared_revision(snapshot, access.key())?;
            Ok(StateReadAssertion::new(access.key().to_vec(), revision)?)
        })
        .collect::<Result<Vec<StateReadAssertion>, NodeCoreError>>()?;
    Ok((reads, mutations))
}

#[cfg(test)]
#[path = "tests/state_transition.rs"]
mod tests;
