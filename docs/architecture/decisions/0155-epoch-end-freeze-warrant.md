# DR-0155: Bind Freeze to an epoch-end rule and a viable next set

## Status

Accepted design direction, 2026-09-28. This refines the Freeze authorization
required by [DR-0154](0154-complete-epoch-handoff.md). Implementation and
validation status belong in [`TODO.md`](../../../TODO.md); this decision does
not by itself enable epoch handoff.

## Context

The existing ordered engine proves that the outgoing committee committed an
operation at a particular height. It does not prove that closing admission at
that height is permitted. A structurally valid Freeze can currently be
submitted through the opt-in ordered HTTP route. If honest replicas vote for
it without an independent rule, a caller can close an epoch before the
network can move to a next committee. Wall-clock time, local timeout ticks,
the leader's assertion and a caller-provided height are not common authority.

The existing epoch-transition path can check each proposed validator's
committed bond, key and economics policy before voting. That check is
reusable, but it must not be confused with a complete DrainSet, Seal or
readiness proof.

## Decision

The handoff-capable signed genesis manifest commits a positive
`minimum_freeze_block_height`. Historical genesis manifests carry no such
field and cannot authorize Freeze. The same signed rule applies to each epoch
until a future authenticated protocol change explicitly replaces it. An
ordered Freeze proposal may be signed or voted only if its actual proposal
height is at least that minimum. The rule is a minimum ordered-block height,
not elapsed real time or a guarantee that useful work occurred. The candidate
cannot set or lower the minimum.
The current ordered profile carries a candidate only at heights congruent to
1 modulo 3, so the first usable Freeze slot may be above the signed minimum.

The Freeze candidate carries a canonical advisory next validator set for the
immediately following epoch. Before signing a proposal or vote, each honest
replica validates the exact chain, protocol and next-epoch binding, canonical
set structure, keys and power, and every member's committed Active bond and
applicable economics policy. A same-member rollover is legal only when it
passes these same checks. This is a viability witness, not an irrevocable
membership choice: final membership is selected and checked again in the
later readiness and Seal sequence.

The committed Freeze executes against its actual ordered height and current
committed state. If the proposed set is now healthy but ineligible, retain a
deterministic refusal without closing admission. Missing, corrupt, ambiguous
or unavailable prerequisites stop local application rather than becoming a
success or an invented semantic refusal. A vote-time check does not replace
the commit-time check because bond and policy state may change in the
intervening ordered prefix. Exact completed replay returns the first retained
result without re-running eligibility or moving state.

The closure marker is installed only after all these checks succeed through
the ordinary ordered atomic commit. A quorum certificate establishes ordering
under the outgoing set, not an independent operator mandate. Neither a local
flag nor an HTTP caller may bypass the height or eligibility checks.

## Consequences and remaining gates

This rule prevents the simplest premature or stranded Freeze, but it cannot
guarantee next-set availability or successful activation. An eligible set may
still be offline, withhold artifacts or fail to satisfy the later cut and
readiness checks. The existing standalone transition route must be retired
or bound to the ordered Seal before the handoff path can be enabled. DrainSet,
verified cut, readiness, Seal, transition and independent multi-validator
network tests remain required by DR-0154. Do not report Delivery 3 complete
or merge its Draft PR on the strength of this warrant alone.
