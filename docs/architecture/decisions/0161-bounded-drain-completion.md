# DR-0161: bounded resumable drain-completion state machine

Date: 2026-09-30

## Decision

A new `node-core` module (`ordered_economics::drain_completion`) tracks, one
member at a time, whether every member of the exact locally committed
`DrainSet` has actually been applied. It never accepts a caller-selected
member list: `advance_drain_completion` always re-derives `selected_votes`
from the one immutable, one-per-epoch committed `DrainSetRecord`, the same
authority [DR-0160](0160-certified-drain-application.md)'s own drain-member
application independently re-verifies, never from a request argument.

It reuses two existing primitives unmodified.
`ordered_economics::drain_union::verify_drain_ready_into` re-verifies this
replica's own local union readiness for the committed record's exact
selected votes, folding the committed Freeze, current epoch, outgoing set
and the immutable local ready marker into the caller's CAS read set.
`ordered_economics::drain_union::next_union_member_after` selects the exact
next canonical union member -- ascending by request id, deterministically
merged across every selected signer's confirmed entries -- after a cursor,
the same deterministic algorithm that built the ready marker in the first
place. One invocation advances at most one member.

Advancing a member does not apply it, execute it, or create a receipt: it
only recognizes that a separate committed, typed original receipt already
exists for that member's exact request id and carries that member's exact
certified signed-intent digest. Every genuine drain application binds a
member's `AvailabilityIdentity::signed_intent_digest` to its certificate's
`tx_hash`/event digest, so this digest -- already present on the union
member the deterministic merge selected -- is compared directly against the
receipt's own `event_digest`, with no separate re-derivation from a
publication record. A missing receipt is declared catch-up, not a failure:
some other path has not yet applied that member on this replica. A receipt
that exists under a different digest is never trusted as this member's
completion; that fails closed instead. A receipt is immutable in the
runtime storage contract once committed, so a positively matched member can
never later disagree on this replica -- but this alone proves only that
*this replica* observed the application, not that a future portable,
cross-replica cut has verified or carried it.

The progress row stores the running canonical `DrainUnionAccumulator`
identity, with its semantic `member_count`, digest and last request ID. A
member advances it only after its receipt check. At the terminal step, an
exhausted next-member scan alone is insufficient: a missing or skipped
signer entry could otherwise look like completion. The running identity,
count and digest must equal the locally ready union and the committed
`DrainSetRecord` before the local completion marker is persisted. That
commit CAS-fences the committed record, ready marker and its Freeze/epoch/set
prerequisites, signer entries observed on the terminal scan, and completion
progress. No physical storage revision counter enters the canonical bytes.
Both the progress cursor (`0x6461/v1`) and the
terminal marker (`0x6462/v1`) are swept-free type IDs from the repository's
reserved control/cut block, verified free at allocation time. Both key
families (`drain-completion-progress/`, `drain-completion/`) are added to
the closed `LocalProgress` classification in `logical_generation`, exactly
like every other replica-local `drain-*` row.

Pristine and tombstone semantics match every other local progress row in
this crate: a never-written progress or completion row is the ordinary
not-yet-reached case; a tombstoned one fails closed instead of being
reinterpreted as pristine. Retry and reconciliation are exact by
construction rather than by a separate mechanism: every call re-derives the
committed record, re-verifies readiness, and re-reads the progress cursor
fresh from storage, so a crash before a commit lands, or a repeated call
after it already landed, both resolve to the same deterministic next step --
either the same member is attempted again (identically), or the state
machine has already moved on and does no redundant work.

`verify_drain_complete_into` re-reads the committed DrainSet, independently
re-verifies the exact local ready union, and compares the terminal marker's
request ID and full identity to them. It folds every read into the caller's
CAS set for a future Seal vote or proposal; a marker alone cannot make a
different or corrupted DrainSet appear complete. It is not wired into any
consensus path by this module.

This does not select a DrainSet, apply a member, prove a portable cut, or
implement Seal, next-set readiness or activation. It is local progress and
audit history, exactly like every other row this crate's `drain-*` families
already are. A true receipt is immutable in the runtime storage contract,
but that alone does not verify a later portable cut: a future portable cut
must independently reconstruct and verify member completion from
authenticated receipts and the committed record across replicas, never
import this replica-local marker as authority.

## Required verification

Exercise two individually certified publication bundles in a reconstructed
two-member union across a 3-of-4 signed frontier fixture: advancing
each member in ascending request-id order, refusing to advance before any
receipt exists, refusing and recording nothing on a receipt whose digest
disagrees with the certified signed intent, reaching the terminal step only
after each test-inserted receipt matches, idempotent re-calls after completion,
and `verify_drain_complete`/`verify_drain_complete_into` before and after.
Tombstoned progress and completion rows fail closed. A completion marker
whose stored identity disagrees with the currently committed record is
rejected by both advancement and read-only verification. A forged progress
cursor that skips a member cannot mark the drain complete when its running
count/digest differs. This fixture does not prove that both bundles can be
jointly certified by honest validators or that receipts arose through actual
application; the nonempty ordered-network and application evidence is tracked
separately in `TODO.md`.

This does not itself provide an all-member causal scheduler that drives
`advance_drain_completion` to completion automatically, a portable cut, Seal,
next-set readiness, activation, or a PostgreSQL/network multi-validator run.
Implementation and validation status belong in `TODO.md`, not this ADR.
