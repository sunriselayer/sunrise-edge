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
