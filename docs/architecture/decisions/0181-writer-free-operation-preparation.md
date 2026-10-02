# DR-0181: Writer-free business preparation and actual completion

Date: 2026-10-02 (Asia/Singapore)

Status: Proposed detailed refactoring contract, pending independent design
review. No new protocol bytes or admission/signing/serving authority.

## Context

DR-0153 reused existing business handlers by intercepting their persistence
calls. A captured transaction was acknowledged as `Committed` to the handler,
then composed with ordered progress and actually committed elsewhere. That
kept one business implementation, but gave preparation a writable interface
and a misleading success result. Live completion and private reconstruction
also duplicated transaction assembly.

The common completion kernel separates immutable order evidence, an exact
execution warrant, prepared effects and real confirmation. The remaining
capture adapter is not the desired permanent boundary. It also records reads
for fresh signing preflight; removing only the intercepted write methods
would leave that second actual consumer coupled to a pretend writer.

## Decision

Use [writer-free operation preparation](../operation-preparation.md). Add one
minimal structured read port over the existing versioned-state reader and
a private bounded observed-read view. Both ordered consumers use that view.
Each business family owns preparation; public direct handlers actually commit
that preparation, and ordered completion consumes the same result without
calling a committing wrapper.

Migrate all seven ordered arms together. Fee/lifecycle/slash/registration
invocations preserve their existing original receipt and reconciliation.
Evidence preserves its distinct existing/new result and same-key-race reread.
Freeze and DrainSet prepare bounded control-state proposals. Remove the
capture mechanism entirely, rather than retain a parallel handler framework.

Keep business logical dependency maps separate from complete physical CAS
observations. Existing generation derivation precedes configuration merging;
the broader observation closure joins only the final ordered/signing commit.
No common abstraction chooses different signed operands or weakens provenance.

## Alternatives and scope

Manually threading every read map through every pure helper and early-error
path is less suitable: several current checks intentionally discard their
local maps because the ordered observation scope records them. A read-only
observer preserves that complete deciding-read contract without granting a
write method. It does not claim a snapshot or become protocol authority.

No universal business handler trait, provider persistence framework, new
consensus engine, live stub, synthetic confirmation or successor authority is
needed. Immutable genesis/current serving/historical committee separation and
exact Seal/activation proof design remain distinct work.

## Acceptance

Prove writer-free preparation with real operations and no persistence effects,
retained direct/ordered/reconstruction generation and exact-byte comparisons,
all evidence families, refusal-row races, genuine backend ambiguity and real
SQLite restart/replay/fencing. Preserve original receipt-first replay and
owner-specific reconciliation. Use the complete required gate and independent
exact-head review before merging. Implementation progress belongs in TODO.
