//! Opt-in local work limits. This is not a protocol history ceiling.

use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// Only downward local overrides are accepted by [`ArchiveReadBudget::new`].
#[derive(Clone, Copy, Debug)]
pub struct ArchiveReadLimits {
    /// Root/directory/entry and generated-inventory work, including repeats/orphans.
    pub observations: u64,
    /// Materialized history heights, counted again on repeated reads.
    pub heights: u64,
    /// Decoded cut/history components, counted before allocation on every decode.
    pub components: u64,
    /// Individual archive body/component bound, also subject to its owner's bound.
    pub file_bytes: u64,
    /// Cooperative deadline; cannot preempt filesystem I/O or opaque verification.
    pub deadline: Duration,
}

impl Default for ArchiveReadLimits {
    fn default() -> Self {
        Self {
            observations: 262_144,
            heights: 4_096,
            components: 32_768,
            file_bytes: 32 * 1024 * 1024,
            deadline: Duration::from_secs(300),
        }
    }
}

#[derive(Default)]
struct Counts {
    observations: u64,
    heights: u64,
    components: u64,
    refused: bool,
}

struct State {
    limits: ArchiveReadLimits,
    expires: Instant,
    counts: Counts,
}

/// One invocation's irreversible budget. Clones share counters AND refusal.
/// It contains no public reset/refund or independently clonable counter state.
#[derive(Clone)]
pub struct ArchiveReadBudget {
    state: Arc<Mutex<State>>,
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bounded archive work refused")
}

impl ArchiveReadBudget {
    /// Creates a finite local budget. No library path assumes a host resource policy.
    pub fn new(limits: ArchiveReadLimits) -> io::Result<Self> {
        let ceiling: ArchiveReadLimits = ArchiveReadLimits::default();
        if limits.observations > ceiling.observations
            || limits.heights > ceiling.heights
            || limits.components > ceiling.components
            || limits.file_bytes > ceiling.file_bytes
            || limits.deadline.is_zero()
            || limits.deadline > ceiling.deadline
        {
            return Err(refused());
        }
        let expires: Instant = Instant::now()
            .checked_add(limits.deadline)
            .ok_or_else(refused)?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                limits,
                expires,
                counts: Counts::default(),
            })),
        })
    }

    fn live(&self) -> io::Result<MutexGuard<'_, State>> {
        let mut state: MutexGuard<'_, State> = self.state.lock().map_err(|_| refused())?;
        if state.counts.refused || Instant::now() >= state.expires {
            state.counts.refused = true;
            return Err(refused());
        }
        Ok(state)
    }

    /// Checks the same invocation's deadline/refusal before and after opaque work.
    pub fn check(&self) -> io::Result<()> {
        drop(self.live()?);
        Ok(())
    }

    /// Permanently refuses this handle and all its clones after an admission error.
    pub fn refuse(&self) -> io::Error {
        if let Ok(mut state) = self.state.lock() {
            state.counts.refused = true;
        }
        refused()
    }

    fn add(&self, amount: u64, kind: u8) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let (current, ceiling): (u64, u64) = match kind {
            0 => (state.counts.observations, state.limits.observations),
            1 => (state.counts.heights, state.limits.heights),
            _ => (state.counts.components, state.limits.components),
        };
        let Some(next) = current
            .checked_add(amount)
            .filter(|next: &u64| *next <= ceiling)
        else {
            state.counts.refused = true;
            return Err(refused());
        };
        match kind {
            0 => state.counts.observations = next,
            1 => state.counts.heights = next,
            _ => state.counts.components = next,
        }
        Ok(())
    }

    /// Charges before path/string/collection growth or directory descent.
    pub fn charge_observations(&self, count: u64) -> io::Result<()> {
        self.add(count, 0)
    }

    /// Charges actual height materialization before its descriptor or vector growth.
    pub fn charge_heights(&self, count: u64) -> io::Result<()> {
        self.add(count, 1)
    }

    /// Checks a claimed whole prefix BEFORE looping/allocating; actual reads charge it.
    pub fn require_heights(&self, count: u64) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        if state
            .counts
            .heights
            .checked_add(count)
            .is_none_or(|next: u64| next > state.limits.heights)
        {
            state.counts.refused = true;
            return Err(refused());
        }
        Ok(())
    }

    /// Checks a fixed target before an inventory loop without charging unrelated
    /// materializations. Actual single-height reads charge their own height once.
    pub fn check_height_target(&self, count: u64) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        if count > state.limits.heights {
            state.counts.refused = true;
            return Err(refused());
        }
        Ok(())
    }

    /// Used by the defining decoder BEFORE count-driven descriptor allocations.
    pub fn charge_components(&self, count: u64) -> io::Result<()> {
        self.add(count, 2)
    }

    /// Rejects declared totals before loops; decoder admission charges actual work.
    pub fn require_components(&self, count: u64) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        if state
            .counts
            .components
            .checked_add(count)
            .is_none_or(|next: u64| next > state.limits.components)
        {
            state.counts.refused = true;
            return Err(refused());
        }
        Ok(())
    }

    /// Upper bound supplied to the canonical owner BEFORE field-count allocation.
    pub fn remaining_components(&self) -> io::Result<usize> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let Some(remaining) = state.limits.components.checked_sub(state.counts.components) else {
            state.counts.refused = true;
            return Err(refused());
        };
        let Ok(remaining) = usize::try_from(remaining) else {
            state.counts.refused = true;
            return Err(refused());
        };
        Ok(remaining)
    }

    /// Checks the caller's role count before role-vector allocation, not root repeats.
    /// Repeated root openings instead consume the shared observation allowance.
    pub fn check_roles(&self, count: usize) -> io::Result<()> {
        self.check()?;
        if count > 67 {
            return Err(self.refuse());
        }
        Ok(())
    }

    /// Checks a component's full length BEFORE chunk loops or byte concatenation.
    pub fn check_component_bytes(&self, count: u64, owner_maximum: usize) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let Ok(owner_maximum) = u64::try_from(owner_maximum) else {
            state.counts.refused = true;
            return Err(refused());
        };
        if count > owner_maximum || count > state.limits.file_bytes {
            state.counts.refused = true;
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn file_limit(&self, maximum: usize) -> io::Result<u64> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let Ok(maximum) = u64::try_from(maximum) else {
            state.counts.refused = true;
            return Err(refused());
        };
        Ok(maximum.min(state.limits.file_bytes))
    }

    #[cfg(test)]
    pub(super) fn used_observations(&self) -> u64 {
        self.state.lock().unwrap().counts.observations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_aggregate_and_refusal_never_resets() {
        let limits: ArchiveReadLimits = ArchiveReadLimits {
            components: 3,
            ..Default::default()
        };
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(limits).unwrap();
        let sibling: ArchiveReadBudget = budget.clone();
        budget.charge_components(2).unwrap();
        sibling.charge_components(1).unwrap();
        assert!(budget.charge_components(1).is_err());
        assert!(sibling.check().is_err());
        assert!(budget.charge_components(0).is_err());
    }

    #[test]
    fn overflow_and_claimed_work_refuse_before_growth() {
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        assert!(budget.charge_observations(u64::MAX).is_err());
        assert!(budget.check().is_err());
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        assert!(budget.require_heights(u64::MAX).is_err());
        assert!(budget.check().is_err());
    }

    #[test]
    fn expired_and_upward_limits_refuse() {
        assert!(
            ArchiveReadBudget::new(ArchiveReadLimits {
                observations: 262_145,
                ..Default::default()
            })
            .is_err()
        );
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        budget.state.lock().unwrap().expires = Instant::now();
        assert!(budget.check().is_err());
        assert!(budget.clone().check().is_err());
    }
}
