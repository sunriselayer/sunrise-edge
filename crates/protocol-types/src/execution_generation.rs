//! Authenticated causal execution generations (DR-0154).
//!
//! A generation is protocol provenance, not a database revision, checkpoint
//! timestamp, consensus height or globally serialized counter. Consumers must
//! obtain the floor and dependencies from verified protocol history. This type
//! does not authenticate caller-supplied numbers or reinterpret legacy physical
//! checkpoint fields as generations.

use core::fmt;
use std::error::Error;

/// Authenticated causal generation used by the handoff-capable profile.
///
/// Zero is the genesis floor. Independent operations can share a generation;
/// only a causal dependency requires a strictly later generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionGeneration(u64);

impl ExecutionGeneration {
    /// Constructs an exact decoded generation or verified cut floor.
    ///
    /// The caller remains responsible for verifying its provenance and profile.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the initial fresh-genesis floor.
    #[must_use]
    pub const fn genesis_floor() -> Self {
        Self(0)
    }

    /// Returns the exact canonical unsigned operand.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Derives `1 + max(verified_cut_floor, verified_dependencies)`.
    ///
    /// Dependencies must already be authenticated and resource-bounded by the
    /// calling admission path. Perform this derivation before reservation,
    /// mutation or signature exposure. Overflow is a typed refusal, never a
    /// saturating increment or a wrap back to genesis.
    pub fn successor_of(
        verified_cut_floor: Self,
        verified_dependencies: &[Self],
    ) -> Result<Self, ExecutionGenerationOverflow> {
        let mut maximum: u64 = verified_cut_floor.0;
        for dependency in verified_dependencies {
            maximum = maximum.max(dependency.0);
        }
        let next: u64 = maximum.checked_add(1).ok_or(ExecutionGenerationOverflow)?;
        Ok(Self(next))
    }
}

/// The authenticated predecessor generation has no representable successor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionGenerationOverflow;

impl fmt::Display for ExecutionGenerationOverflow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("semantic execution generation overflow")
    }
}

impl Error for ExecutionGenerationOverflow {}

#[cfg(test)]
mod tests {
    use super::{ExecutionGeneration, ExecutionGenerationOverflow};

    #[test]
    fn genesis_execution_starts_at_one() {
        let generation: ExecutionGeneration =
            ExecutionGeneration::successor_of(ExecutionGeneration::genesis_floor(), &[]).unwrap();
        assert_eq!(generation.get(), 1);
    }

    #[test]
    fn authenticated_floor_and_dependencies_determine_the_operand() {
        let dependencies: [ExecutionGeneration; 3] = [
            ExecutionGeneration::new(4),
            ExecutionGeneration::new(12),
            ExecutionGeneration::new(7),
        ];
        let generation: ExecutionGeneration =
            ExecutionGeneration::successor_of(ExecutionGeneration::new(9), &dependencies).unwrap();
        assert_eq!(generation.get(), 13);
        assert_eq!(
            ExecutionGeneration::successor_of(ExecutionGeneration::new(20), &dependencies)
                .unwrap()
                .get(),
            21
        );
    }

    #[test]
    fn order_and_duplicate_dependencies_do_not_change_the_generation() {
        let dependencies: [ExecutionGeneration; 3] = [
            ExecutionGeneration::new(12),
            ExecutionGeneration::new(4),
            ExecutionGeneration::new(12),
        ];
        let floor: ExecutionGeneration = ExecutionGeneration::new(5);
        let expected: ExecutionGeneration =
            ExecutionGeneration::successor_of(floor, &dependencies).unwrap();
        assert_eq!(
            ExecutionGeneration::successor_of(
                floor,
                &[ExecutionGeneration::new(4), ExecutionGeneration::new(12)]
            )
            .unwrap(),
            expected
        );
        // There is deliberately no globally incremented counter between calls.
        assert_eq!(
            ExecutionGeneration::successor_of(floor, &dependencies).unwrap(),
            expected
        );
    }

    #[test]
    fn largest_representable_successor_is_not_rejected_early() {
        assert_eq!(
            ExecutionGeneration::successor_of(ExecutionGeneration::new(u64::MAX - 1), &[])
                .unwrap()
                .get(),
            u64::MAX
        );
    }

    #[test]
    fn overflow_never_saturates_or_wraps() {
        assert_eq!(
            ExecutionGeneration::successor_of(ExecutionGeneration::new(u64::MAX), &[]),
            Err(ExecutionGenerationOverflow)
        );
        assert_eq!(
            ExecutionGeneration::successor_of(
                ExecutionGeneration::genesis_floor(),
                &[ExecutionGeneration::new(u64::MAX)]
            ),
            Err(ExecutionGenerationOverflow)
        );
    }
}
