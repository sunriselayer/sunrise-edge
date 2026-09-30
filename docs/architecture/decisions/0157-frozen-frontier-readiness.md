# DR-0157: Prove frozen-frontier union possession before DrainSet

## Status

Accepted design direction, 2026-09-29. This composes the signed frontier and
post-Freeze possession boundaries in [DR-0154](0154-complete-epoch-handoff.md)
and [DR-0156](0156-frozen-frontier-possession.md). Implementation and
validation status belongs in [`TODO.md`](../../../TODO.md).

## Context

A weighted quorum of signed frontier descriptors is not a complete frontier:
each signer has to supply consecutive pages through a terminal count and
digest. A page identity is not possession of the complete certificate,
original signed intent and replay artifacts. A locally imported proof is also
not evidence that the proof belongs to the selected quorum's union. Using a
caller-provided ready flag, or scanning every imported proof as if it were a
union member, would allow an untrusted driver to turn unrelated data into
DrainSet authority.

Readiness may involve more members than one atomic state transaction can
read or write. It must progress through bounded invocations without relying
on a long-lived process, while exact retries and crashes never skip a member.

## Decision

The node treats all delivered votes, pages, bundles, selection lists and
retry schedules as untrusted. Every step uses the host-pinned chain,
protocol, outgoing epoch and logical atomicity domain, and CAS-fences the
installed logical profile, live epoch record, outgoing validator set and
committed Freeze. Signed frontier votes are checked against that Freeze and
the locally installed weighted quorum threshold; duplicate or unordered
signers never gain voting power.

For each selected signer, a bounded local progress record pins its first
verified vote, the running frontier accumulator, at most one staged page,
the number of confirmed entries in that page and the terminal state. A new
page is accepted only at the exact previous cursor. Its entries cannot be
skipped, and the next page cannot replace one with unconfirmed entries.
Terminal completion requires the signed count and digest, not merely the
page's terminal flag. Confirmed entry rows are write-once local progress and
retain their signer and request identity. A second different vote, page or
identity for the same position fails closed.

The existing post-Freeze proof import remains a separate atomic step. Its
expected identity must be loaded from a locally staged, page-verified entry;
an external request cannot choose that identity. A later confirmation step
re-verifies the saved full proof, its local possession marker and every
artifact byte, asserts all observed revisions, and advances the signer
progress in the same CAS commit. A crash after import but before confirmation
can leave an extra independently verified proof; it cannot advance readiness.
A missing marker after cut restore may be rebuilt only from a complete proof
matching a staged entry under a pristine marker revision. A tombstoned proof,
artifact or marker is refused. The proof namespace is a possession store,
never the enumeration or membership authority for a DrainSet union.

An ascending, unique, weighted-quorum selection has a canonical identity
and a distinct union digest domain. One bounded merge step compares the next
confirmed entry of every selected signer, folds the lowest request ID once,
and requires byte-identical identities when multiple signers list it. Each
step rechecks local possession and CAS-advances a persisted union cursor.
When all signers' entry counts match their signed terminal counts and all
entries have been folded, one final CAS writes a local DrainSet-ready marker
for that selection. No single huge transaction or transient in-memory
accumulator is authority. Different selections may reuse confirmed signer
progress but have distinct union progress and ready markers. A later
DrainSet vote must read the matching marker under CAS; no request Boolean or
HTTP success substitutes for it.

All signer, entry, union and ready rows are local progress, not authenticated
cut history. After a same-epoch restore they are rebuilt by re-verifying
votes, pages and retained proofs. Protocol paths do not delete confirmed
proofs or progress before activation. If future pruning is added, it must
fence active readiness. Indeterminate commits expose no claimed progress.

## Consequences and boundary

This adds no availability ACK, signature, application effect, fee, nonce or
receipt. It never extends a validator's own immutable pre-Freeze publication
frontier. Extra imported proofs are harmless only while later drain and cut
logic derives membership from the committed selection and its verified
frontier entries, not from a scan of the possession store.

The ready marker is a local prerequisite, not a DrainSet decision. Ordered
DrainSet vote fencing, drain application, authenticated cut, conditional
next-set readiness, Seal and activation remain separate obligations. Any
network driver for these bounded steps must also enforce request and work
bounds before exposure to untrusted traffic.
