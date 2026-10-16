# DR-0248: Independent ordered-history floor for inactive import

Date: 2026-10-16 (Asia/Singapore)

Status: Accepted narrow design. This does not satisfy M4's published
checkpoint/state-root requirement. Current qualification belongs in
[TODO](../../../TODO.md).

## Problem and decision

A genuine older saved history and matching cut remain authentic. Authentication
alone does not tell the operator that their ordered-history position is below a
previously observed position. Add an optional refusal guard to the existing
`business_import create-sqlite` and `resume-sqlite` consumers.

The operator supplies all three explicit pins or none:
`--history-floor-epoch`, `--history-floor-height`, `--history-floor-digest`.
Epoch is a u64, height is a nonzero u64, and digest uses the existing 32-byte
hexadecimal parser. Partial, zero, overflowing or malformed inputs refuse
before file access. The pins must be retained from an earlier independent
verification outside the artifacts being restored. Never derive them from the
same history directory, cut or recovery manifest being checked. CLI argv is
trusted local operator input; this is not protection from a compromised OS or
an operator who removes or substitutes their pins.

`BusinessPinInputs::load` or `load_with_successor` first authenticates the
current epoch's full contiguous direct-parent history under the existing
pinned genesis or verified successor authority. Compare the floor only with
that already-verified material. Require exact epoch equality, a floor height
at or below the verified tip and an exact block-digest match at that height.
Use checked indexing and require the descriptor's height to match. Never pick
between forks by height or view. A different digest at the pinned height
refuses even if its alternative proof also verifies.

Check immediately after loading authenticated pins and after the existing read-only path-containment checks and before reading cut
bodies or opening or creating destination databases. This is earlier than the initial design's
post-cut check and grants no additional authority: success only permits the
original independent cut verification to continue. Every create/resume still
verifies all saved proofs, binds the cut to that exact history identity and
finishes only through the original `CompleteInactive` path. No floor preserves
the original behavior. Output format and canonical bytes remain unchanged.

## Limits and compatibility

Heights are not compared across epochs. Both older and newer foreign-epoch
floors refuse; predecessor-link history comparison is outside this slice.
The floor bounds ordered-history position only. It does not commit to the
whole state, prove absence, authenticate the latest network state or order
owned fast-path changes. It cannot detect every whole-store rollback or
exclude an old physical writer. It grants no readiness, Seal, signing or
activation permission and creates no checkpoint protocol, certificate or ID.

Encrypted `business_recovery` already requires independently supplied exact
cut and package digest pins. Keep those stronger exact-artifact checks and
all existing 35-role source-free restore controls; add no redundant floor
argument to that command. Off-host custody and real recovery operation remain
separate qualification.

## Verification contract

Pure comparisons cover tip/interior acceptance, older history, conflicting
same-height digest, both directions of epoch mismatch, empty targets. Parser controls cover all partial flag subsets and numeric/
hexadecimal bounds. These synthetic materials test comparison, not proof
verification.

Compiled import controls use a genuine authenticated saved history/cut fixture.
They require refusal before destination creation for a floor above the tip,
a conflicting digest, a foreign epoch and a partial flag set; input archives
must stay unchanged. Exact tip and interior ancestors reach `CompleteInactive`.
A mismatched resume floor leaves existing destination bytes unchanged. The
original full import suite and complete required repository gate remain.

## 2026-10-16 addendum: floor oracle added over the existing successor import

A genuine positive `business_import` admission via `load_with_successor`
already existed before this addendum: `install_next` in
`apps/operator/tests/support/recurring_host_acceptance.rs` (the
recurring-sqlite ignored lane's per-epoch handoff) already runs compiled
`business_import create-sqlite` with the real `--successor-*` link flags
(`current_operator_pins`, built from `link_flags(links, true)`) against a
genuinely frozen, drained, empty-three-chain current-epoch history and cut
it exports immediately before, and already asserts
`business_import=complete-inactive`. What this addendum adds is narrow: an
independent ordered-history floor oracle layered on top of that same,
already-proven admission, scoped to the first successor link
(`links.len() == 1`, current epoch e+1) only.

`successor_import_history_floor_controls`, called from `install_next` in
`apps/operator/tests/support/recurring_host_acceptance.rs` right after that
function's own existing current-epoch history export, frozen/drained cut
export and compiled import loop, reuses exactly that call's own `history`,
`cut` and `current_operator_pins(fixture, links, history)` -- no new history
or cut export, no hand-rebuilt CLI flags, no production, runtime or
canonical-byte change. On a fresh extra destination it reads the
independently decoded `history` archive identity (asserting its epoch is
explicitly the current successor epoch and its committed height is at least
2, so an interior ancestor is never silently skipped) and runs
`create-sqlite`/`resume-sqlite` with `--history-floor-*`: a floor above the
tip, a conflicting digest at the tip, and a foreign epoch must each refuse
with `require_history_floor`'s exact message before a destination is
created (`symlink_metadata` reports both database files absent); the exact
tip must reach `CompleteInactive`; the interior ancestor must then resume
successfully with the same cut/package/plan binding; a wrong floor on resume
must refuse and leave the destination's existing bytes unchanged; a final
resume with no floor must still succeed with `new_batches=0` and the same
binding. Every read-only input -- the one link's four archives, `history`
and `cut` -- is snapshotted before the first control and reasserted
unchanged after every later one.

These controls run inside the full `recurring-sqlite` ignored case
(`compiled_registered_replacement_and_recurring_successor_hosts`) and add
real wall-clock work. The original eight links, e8 withdrawals, 35-role
source-free recovery and all waits and refusal controls remain in that case.
Execution is still pending. The placement requires the existing current-epoch
Freeze/DrainSet and empty-three-chain cut; the earlier active successor phase
cannot provide that cut.

This remains a narrow ordered-history position bound only. It does not add
checkpoint or state-root commitments, does not prove absence, and does not
detect or exclude a whole-store rollback or an old physical writer; those
stay open, tracked in [TODO](../../../TODO.md).
