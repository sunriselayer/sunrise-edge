//! Domain-bound assembly of observed state transactions.
//!
//! These types describe a proposal, not authenticated reads, admission/signing
//! authority or confirmed storage. The backend still validates lifecycle,
//! fence, deadline and the complete read set at its one atomic commit.
//! Every failed addition leaves its receiver unchanged.

use crate::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableStateTransaction, MAX_ATOMIC_STATE_READS, MAX_ATOMIC_STATE_TRANSACTION_BYTES,
    MAX_ATOMIC_STATE_WRITES, RuntimeError, StateMutation, StateMutationEntry, StateReadAssertion,
    StateRevision,
};
use core::{fmt, mem::size_of};
use std::collections::BTreeMap;
use std::error::Error;

/// An assembly failure, never a business refusal or an indeterminate commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateAssemblyError {
    /// Two contributors observed different revisions for one exact key.
    ConflictingObservation {
        /// Exact bounded key, omitted from the display message.
        key: Vec<u8>,
        /// Revision already retained by the assembler.
        first: StateRevision,
        /// Disagreeing incoming revision.
        second: StateRevision,
    },
    /// Exact-coalescing contributors supplied different mutations for a key.
    ConflictingMutation {
        /// Exact bounded key, omitted from the display message.
        key: Vec<u8>,
    },
    /// The existing runtime validation or resource-bound failure.
    Runtime(RuntimeError),
}

impl From<RuntimeError> for StateAssemblyError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl fmt::Display for StateAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingObservation { .. } => {
                formatter.write_str("state contributors observed different revisions")
            }
            Self::ConflictingMutation { .. } => {
                formatter.write_str("state contributors supplied different mutations")
            }
            Self::Runtime(error) => error.fmt(formatter),
        }
    }
}

impl Error for StateAssemblyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::ConflictingObservation { .. } | Self::ConflictingMutation { .. } => None,
        }
    }
}

/// Bounded exact-key observations in one logical domain.
///
/// Revisions are CAS operands, not proof of authenticated history or a stable
/// snapshot. Absent and tombstoned revisions remain distinct and unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateObservationSet {
    domain: AtomicityDomainId,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    represented_read_bytes: usize,
}

impl StateObservationSet {
    /// Starts an empty observation set under one explicit logical domain.
    #[must_use]
    pub fn new(domain: AtomicityDomainId) -> Self {
        Self {
            domain,
            reads: BTreeMap::new(),
            represented_read_bytes: 0,
        }
    }

    /// Returns the only domain to which these observations belong.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Adds an observation, coalescing only an identical existing revision.
    pub fn observe(&mut self, assertion: StateReadAssertion) -> Result<(), StateAssemblyError> {
        self.check_revision(assertion.key(), assertion.expected_revision())?;
        if !self.reads.contains_key(assertion.key()) {
            check_read_count(self.reads.len().saturating_add(1))?;
            let bytes: usize = self
                .represented_read_bytes
                .saturating_add(represented_read_bytes(assertion.key()));
            check_transaction_bytes(represented_base_bytes(self.domain).saturating_add(bytes))?;
            self.reads
                .insert(assertion.key, assertion.expected_revision);
            self.represented_read_bytes = bytes;
        }
        Ok(())
    }

    /// Merges same-domain observations with no partial additions on failure.
    pub fn merge_observations(&mut self, additional: &Self) -> Result<(), StateAssemblyError> {
        let bytes: usize = self.checked_merge(additional.domain, additional.iter())?;
        self.apply_merge(additional.iter());
        self.represented_read_bytes = bytes;
        Ok(())
    }

    /// Consumes the set into the existing canonical read-set contract.
    /// An empty set preserves the existing `EmptyReadSet` error.
    pub fn into_read_set(self) -> Result<AtomicStateReadSet, RuntimeError> {
        let assertions: Vec<StateReadAssertion> = self
            .reads
            .into_iter()
            .map(|(key, revision): (Vec<u8>, StateRevision)| StateReadAssertion::new(key, revision))
            .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()?;
        AtomicStateReadSet::new(assertions)
    }

    fn iter(&self) -> impl Iterator<Item = (&[u8], StateRevision)> {
        self.reads
            .iter()
            .map(|(key, revision): (&Vec<u8>, &StateRevision)| (key.as_slice(), *revision))
    }

    fn check_revision(
        &self,
        key: &[u8],
        revision: StateRevision,
    ) -> Result<(), StateAssemblyError> {
        if let Some(first) = self.reads.get(key)
            && *first != revision
        {
            return Err(StateAssemblyError::ConflictingObservation {
                key: key.to_vec(),
                first: *first,
                second: revision,
            });
        }
        Ok(())
    }

    // Callers supply an already-unique set or validated state section. Check
    // the whole contribution before apply_merge can modify any observation.
    fn checked_merge<'a>(
        &self,
        domain: AtomicityDomainId,
        additional: impl Iterator<Item = (&'a [u8], StateRevision)>,
    ) -> Result<usize, StateAssemblyError> {
        if self.domain != domain {
            return Err(RuntimeError::AtomicityDomainMismatch.into());
        }
        let mut count: usize = self.reads.len();
        let mut bytes: usize = self.represented_read_bytes;
        for (key, revision) in additional {
            self.check_revision(key, revision)?;
            if !self.reads.contains_key(key) {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(represented_read_bytes(key));
            }
        }
        check_read_count(count)?;
        check_transaction_bytes(represented_base_bytes(self.domain).saturating_add(bytes))?;
        Ok(bytes)
    }

    fn apply_merge<'a>(&mut self, additional: impl Iterator<Item = (&'a [u8], StateRevision)>) {
        for (key, revision) in additional {
            if !self.reads.contains_key(key) {
                self.reads.insert(key.to_vec(), revision);
            }
        }
    }
}

/// A pure domain-bound assembler for one complete observed state section.
///
/// The builder chooses no admission, logical provenance inputs, original
/// receipt, object effects, outbox or commit policy. Configuration observations
/// must join only after the owning logical generation has been derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateTransactionBuilder {
    observations: StateObservationSet,
    mutations: BTreeMap<Vec<u8>, StateMutation>,
    represented_mutation_bytes: usize,
}

impl StateTransactionBuilder {
    /// Starts an empty transaction description in one logical domain.
    #[must_use]
    pub fn new(domain: AtomicityDomainId) -> Self {
        Self::from_observations(StateObservationSet::new(domain))
    }

    /// Takes bounded observations without granting new authority.
    #[must_use]
    pub fn from_observations(observations: StateObservationSet) -> Self {
        Self {
            observations,
            mutations: BTreeMap::new(),
            represented_mutation_bytes: 0,
        }
    }

    /// Returns the only domain this proposed transaction may affect.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.observations.domain()
    }

    /// Reports whether this description has no state mutations.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.mutations.is_empty()
    }

    /// Adds an observation without replacing a disagreeing revision.
    pub fn observe(&mut self, assertion: StateReadAssertion) -> Result<(), StateAssemblyError> {
        self.observations
            .check_revision(assertion.key(), assertion.expected_revision())?;
        let additional_bytes: usize = if self.observations.reads.contains_key(assertion.key()) {
            0
        } else {
            represented_read_bytes(assertion.key())
        };
        check_transaction_bytes(self.represented_bytes().saturating_add(additional_bytes))?;
        self.observations.observe(assertion)
    }

    /// Folds same-domain observations into this transaction atomically.
    pub fn merge_observations(
        &mut self,
        additional: &StateObservationSet,
    ) -> Result<(), StateAssemblyError> {
        let bytes: usize = self
            .observations
            .checked_merge(additional.domain, additional.iter())?;
        check_transaction_bytes(
            represented_base_bytes(self.domain())
                .saturating_add(bytes)
                .saturating_add(self.represented_mutation_bytes),
        )?;
        self.observations.apply_merge(additional.iter());
        self.observations.represented_read_bytes = bytes;
        Ok(())
    }

    /// Inserts a single-owner mutation, rejecting every duplicate key even if
    /// its bytes match. The key must already have an observation.
    pub fn insert_mutation_once(
        &mut self,
        entry: StateMutationEntry,
    ) -> Result<(), StateAssemblyError> {
        if self.mutations.contains_key(entry.key()) {
            return Err(RuntimeError::DuplicateStateWriteKey.into());
        }
        self.insert_new_mutation(entry)
    }

    /// Deliberately coalesces a byte-identical mutation contribution. A
    /// disagreement preserves the prior mutation and all observations.
    pub fn coalesce_mutation_exact(
        &mut self,
        entry: StateMutationEntry,
    ) -> Result<(), StateAssemblyError> {
        if let Some(existing) = self.mutations.get(entry.key()) {
            if existing != entry.mutation() {
                return Err(StateAssemblyError::ConflictingMutation { key: entry.key });
            }
            return Ok(());
        }
        self.insert_new_mutation(entry)
    }

    /// Merges a validated same-domain state section, explicitly coalescing
    /// identical observations and mutations. A disagreement or excessive bound
    /// refuses the whole contribution without partial additions.
    pub fn merge_state_exact(
        &mut self,
        state: &DurableStateTransaction,
    ) -> Result<(), StateAssemblyError> {
        let read_bytes: usize = self.observations.checked_merge(
            state.domain(),
            state.reads().iter().map(|assertion: &StateReadAssertion| {
                (assertion.key(), assertion.expected_revision())
            }),
        )?;
        let mut mutation_count: usize = self.mutations.len();
        let mut mutation_bytes: usize = self.represented_mutation_bytes;
        for entry in state.mutations() {
            match self.mutations.get(entry.key()) {
                Some(existing) if existing != entry.mutation() => {
                    return Err(StateAssemblyError::ConflictingMutation {
                        key: entry.key().to_vec(),
                    });
                }
                Some(_) => {}
                None => {
                    mutation_count = mutation_count.saturating_add(1);
                    mutation_bytes = mutation_bytes
                        .saturating_add(represented_mutation_bytes(entry.key(), entry.mutation()));
                }
            }
        }
        check_mutation_count(mutation_count)?;
        check_transaction_bytes(
            represented_base_bytes(self.domain())
                .saturating_add(read_bytes)
                .saturating_add(mutation_bytes),
        )?;
        self.observations.apply_merge(state.reads().iter().map(
            |assertion: &StateReadAssertion| (assertion.key(), assertion.expected_revision()),
        ));
        for entry in state.mutations() {
            if !self.mutations.contains_key(entry.key()) {
                self.mutations
                    .insert(entry.key().to_vec(), entry.mutation().clone());
            }
        }
        self.observations.represented_read_bytes = read_bytes;
        self.represented_mutation_bytes = mutation_bytes;
        Ok(())
    }

    /// Finishes a metadata-only atomic transaction, retaining the existing
    /// nonempty read/mutation requirements. This does not create a receipt.
    pub fn finish_metadata(self) -> Result<AtomicStateTransaction, RuntimeError> {
        let domain: AtomicityDomainId = self.domain();
        let reads: AtomicStateReadSet = self.observations.into_read_set()?;
        let mutations: Vec<StateMutationEntry> = into_mutations(self.mutations)?;
        AtomicStateTransaction::new(domain, reads, AtomicStateMutationSet::new(mutations)?)
    }

    /// Finishes the state section of an invocation, permitting read-only
    /// sections. The existing invocation constructor still takes an explicit
    /// original receipt, object changes and optional outbox separately.
    pub fn finish_invocation_state(self) -> Result<DurableStateTransaction, RuntimeError> {
        let domain: AtomicityDomainId = self.domain();
        let reads: AtomicStateReadSet = self.observations.into_read_set()?;
        DurableStateTransaction::new(domain, reads, into_mutations(self.mutations)?)
    }

    fn insert_new_mutation(&mut self, entry: StateMutationEntry) -> Result<(), StateAssemblyError> {
        if !self.observations.reads.contains_key(entry.key()) {
            return Err(RuntimeError::StateMutationWithoutRead.into());
        }
        check_mutation_count(self.mutations.len().saturating_add(1))?;
        let bytes: usize = represented_mutation_bytes(entry.key(), entry.mutation());
        check_transaction_bytes(self.represented_bytes().saturating_add(bytes))?;
        self.mutations.insert(entry.key, entry.mutation);
        self.represented_mutation_bytes = self.represented_mutation_bytes.saturating_add(bytes);
        Ok(())
    }

    fn represented_bytes(&self) -> usize {
        represented_base_bytes(self.domain())
            .saturating_add(self.observations.represented_read_bytes)
            .saturating_add(self.represented_mutation_bytes)
    }
}

fn into_mutations(
    mutations: BTreeMap<Vec<u8>, StateMutation>,
) -> Result<Vec<StateMutationEntry>, RuntimeError> {
    mutations
        .into_iter()
        .map(|(key, mutation): (Vec<u8>, StateMutation)| StateMutationEntry::new(key, mutation))
        .collect::<Result<Vec<StateMutationEntry>, RuntimeError>>()
}

fn check_read_count(count: usize) -> Result<(), RuntimeError> {
    if count > MAX_ATOMIC_STATE_READS {
        return Err(RuntimeError::TooManyStateReads {
            count,
            maximum: MAX_ATOMIC_STATE_READS,
        });
    }
    Ok(())
}

fn check_mutation_count(count: usize) -> Result<(), RuntimeError> {
    if count > MAX_ATOMIC_STATE_WRITES {
        return Err(RuntimeError::TooManyStateWrites {
            count,
            maximum: MAX_ATOMIC_STATE_WRITES,
        });
    }
    Ok(())
}

fn check_transaction_bytes(bytes: usize) -> Result<(), RuntimeError> {
    if bytes > MAX_ATOMIC_STATE_TRANSACTION_BYTES {
        return Err(RuntimeError::StateTransactionTooLarge {
            bytes,
            maximum: MAX_ATOMIC_STATE_TRANSACTION_BYTES,
        });
    }
    Ok(())
}

fn represented_base_bytes(domain: AtomicityDomainId) -> usize {
    domain.as_bytes().len().saturating_add(2 * size_of::<u32>())
}

fn represented_read_bytes(key: &[u8]) -> usize {
    size_of::<u32>()
        .saturating_add(key.len())
        .saturating_add(size_of::<u64>())
}

fn represented_mutation_bytes(key: &[u8], mutation: &StateMutation) -> usize {
    // Preserve the existing one-byte local mutation tag accounting exactly.
    let bytes: usize = size_of::<u32>().saturating_add(key.len()).saturating_add(1);
    match mutation {
        StateMutation::Put(value) => bytes
            .saturating_add(size_of::<u64>())
            .saturating_add(value.len()),
        StateMutation::Assert | StateMutation::Delete => bytes,
    }
}

// Both existing transaction constructors and the incremental builder use this
// same unchanged accounting; adding an assembler does not change the bound.
pub(super) fn represented_transaction_bytes(
    domain: AtomicityDomainId,
    reads: &AtomicStateReadSet,
    mutations: &AtomicStateMutationSet,
) -> usize {
    let mut bytes: usize = represented_base_bytes(domain);
    for read in reads.reads() {
        bytes = bytes.saturating_add(represented_read_bytes(read.key()));
    }
    for mutation in mutations.mutations() {
        bytes = bytes.saturating_add(represented_mutation_bytes(
            mutation.key(),
            mutation.mutation(),
        ));
    }
    bytes
}

#[cfg(test)]
mod tests;
