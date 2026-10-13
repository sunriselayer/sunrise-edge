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
            observations: 8_388_608,
            heights: 4_096,
            components: 32_768,
            file_bytes: 32 * 1024 * 1024,
            deadline: Duration::from_secs(300),
        }
    }
}

/// Static local refusal category only. It contains no path, provider error,
/// counter, input bytes or authority; inspecting it cannot reset the budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveReadRefusal {
    Observations,
    Heights,
    Components,
    FileBytes,
    Deadline,
    Admission,
    Poisoned,
}

impl ArchiveReadRefusal {
    /// Bounded public diagnostic label, never transport or proof authority.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Observations => "observations",
            Self::Heights => "heights",
            Self::Components => "components",
            Self::FileBytes => "file-bytes",
            Self::Deadline => "deadline",
            Self::Admission => "admission",
            Self::Poisoned => "poisoned",
        }
    }
}

#[derive(Default)]
struct Counts {
    observations: u64,
    heights: u64,
    components: u64,
    refusal: Option<ArchiveReadRefusal>,
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
        if state.counts.refusal.is_some() {
            return Err(refused());
        }
        if Instant::now() >= state.expires {
            state.counts.refusal = Some(ArchiveReadRefusal::Deadline);
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
            state
                .counts
                .refusal
                .get_or_insert(ArchiveReadRefusal::Admission);
        }
        refused()
    }

    /// Reads the first irreversible refusal without filesystem access, a new
    /// deadline, a counter refund or another work admission. All clones share it.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<ArchiveReadRefusal> {
        match self.state.lock() {
            Ok(state) => state.counts.refusal,
            Err(error) => error
                .into_inner()
                .counts
                .refusal
                .or(Some(ArchiveReadRefusal::Poisoned)),
        }
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
            state.counts.refusal = Some(match kind {
                0 => ArchiveReadRefusal::Observations,
                1 => ArchiveReadRefusal::Heights,
                _ => ArchiveReadRefusal::Components,
            });
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
            state.counts.refusal = Some(ArchiveReadRefusal::Heights);
            return Err(refused());
        }
        Ok(())
    }

    /// Checks a fixed target before an inventory loop without charging unrelated
    /// materializations. Actual single-height reads charge their own height once.
    pub fn check_height_target(&self, count: u64) -> io::Result<()> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        if count > state.limits.heights {
            state.counts.refusal = Some(ArchiveReadRefusal::Heights);
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
            state.counts.refusal = Some(ArchiveReadRefusal::Components);
            return Err(refused());
        }
        Ok(())
    }

    /// Upper bound supplied to the canonical owner BEFORE field-count allocation.
    pub fn remaining_components(&self) -> io::Result<usize> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let Some(remaining) = state.limits.components.checked_sub(state.counts.components) else {
            state.counts.refusal = Some(ArchiveReadRefusal::Components);
            return Err(refused());
        };
        let Ok(remaining) = usize::try_from(remaining) else {
            state.counts.refusal = Some(ArchiveReadRefusal::Components);
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
            state.counts.refusal = Some(ArchiveReadRefusal::FileBytes);
            return Err(refused());
        };
        if count > owner_maximum || count > state.limits.file_bytes {
            state.counts.refusal = Some(ArchiveReadRefusal::FileBytes);
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn file_limit(&self, maximum: usize) -> io::Result<u64> {
        let mut state: MutexGuard<'_, State> = self.live()?;
        let Ok(maximum) = u64::try_from(maximum) else {
            state.counts.refusal = Some(ArchiveReadRefusal::FileBytes);
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
                observations: 8_388_609,
                ..Default::default()
            })
            .is_err()
        );
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        budget.state.lock().unwrap().expires = Instant::now();
        assert!(budget.check().is_err());
        assert!(budget.clone().check().is_err());
    }

    #[test]
    fn former_observation_ceiling_is_a_downward_shared_limit_not_a_reset() {
        let limits: ArchiveReadLimits = ArchiveReadLimits {
            observations: 262_144,
            ..ArchiveReadLimits::default()
        };
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(limits).unwrap();
        let sibling: ArchiveReadBudget = budget.clone();
        budget.charge_observations(262_143).unwrap();
        sibling.charge_observations(1).unwrap();
        assert!(budget.charge_observations(1).is_err());
        assert!(sibling.check().is_err());
        assert!(sibling.charge_observations(0).is_err());
        let selected: ArchiveReadBudget =
            ArchiveReadBudget::new(ArchiveReadLimits::default()).unwrap();
        selected.charge_observations(262_145).unwrap();
        selected.charge_observations(8_388_608 - 262_145).unwrap();
        assert!(selected.charge_observations(1).is_err());
        assert!(selected.clone().check().is_err());
    }

    #[test]
    fn two_million_observation_profile_remains_a_sticky_downward_limit() {
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
            observations: 2_097_152,
            ..ArchiveReadLimits::default()
        })
        .unwrap();
        let sibling: ArchiveReadBudget = budget.clone();
        budget.charge_observations(2_097_151).unwrap();
        sibling.charge_observations(1).unwrap();
        assert!(budget.charge_observations(1).is_err());
        assert_eq!(
            sibling.refusal_reason(),
            Some(ArchiveReadRefusal::Observations)
        );
        assert!(sibling.check().is_err());
        assert!(sibling.charge_observations(0).is_err());
    }

    #[test]
    fn first_refusal_category_is_shared_and_cannot_be_overwritten() {
        for (kind, expected) in [
            (0_u8, ArchiveReadRefusal::Observations),
            (1_u8, ArchiveReadRefusal::Heights),
            (2_u8, ArchiveReadRefusal::Components),
        ] {
            let budget: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
                observations: 1,
                heights: 1,
                components: 1,
                ..ArchiveReadLimits::default()
            })
            .unwrap();
            assert_eq!(budget.refusal_reason(), None);
            let sibling: ArchiveReadBudget = budget.clone();
            budget.add(1, kind).unwrap();
            assert!(sibling.add(1, kind).is_err());
            assert_eq!(budget.refusal_reason(), Some(expected));
            budget.state.lock().unwrap().expires = Instant::now();
            assert!(budget.check().is_err());
            let _error: io::Error = sibling.refuse();
            assert!(sibling.add(0, kind).is_err());
            assert_eq!(sibling.refusal_reason(), Some(expected));
        }
    }

    #[test]
    fn refusal_categories_identify_deadline_file_and_admission_without_inputs() {
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        budget.state.lock().unwrap().expires = Instant::now();
        assert!(budget.check().is_err());
        let _error: io::Error = budget.refuse();
        assert_eq!(budget.refusal_reason(), Some(ArchiveReadRefusal::Deadline));
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        assert!(budget.check_component_bytes(2, 1).is_err());
        assert_eq!(budget.refusal_reason(), Some(ArchiveReadRefusal::FileBytes));
        let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
        let _error: io::Error = budget.refuse();
        assert_eq!(budget.refusal_reason(), Some(ArchiveReadRefusal::Admission));
        assert!(budget.check().is_err());
        assert_eq!(budget.refusal_reason().unwrap().label(), "admission");
    }

    #[test]
    fn poisoned_state_keeps_prior_refusal_but_never_reopens_work() {
        for prior in [None, Some(ArchiveReadRefusal::Observations)] {
            let budget: ArchiveReadBudget = ArchiveReadBudget::new(Default::default()).unwrap();
            if prior.is_some() {
                assert!(budget.charge_observations(u64::MAX).is_err());
            }
            let poisoned: Result<(), _> = std::panic::catch_unwind(|| {
                let _guard: MutexGuard<'_, State> = budget.state.lock().unwrap();
                panic!("test-only mutex poison");
            });
            assert!(poisoned.is_err());
            let expected: ArchiveReadRefusal = prior.unwrap_or(ArchiveReadRefusal::Poisoned);
            assert_eq!(budget.refusal_reason(), Some(expected));
            assert!(budget.check().is_err());
            assert!(budget.charge_observations(0).is_err());
            let _error: io::Error = budget.refuse();
            assert!(budget.state.is_poisoned());
            assert_eq!(budget.refusal_reason(), Some(expected));
        }
    }
}
