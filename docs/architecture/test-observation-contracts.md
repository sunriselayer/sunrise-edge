# Test observation ownership

Tests compose genuine owning fixtures for business authority. Shared test
infrastructure owns only observation mechanics: reader-only capabilities,
publication counters and exact portable capture. It does not generate a
committee, trusted genesis, certificate or accepted business result.
[DR-0183](decisions/0183-test-observation-ownership.md) records this boundary.
Implementation and acceptance belong in [TODO](../../TODO.md).

## Three distinct contracts

| Evidence | Owner | Meaning |
| --- | --- | --- |
| Reader-only view | Private test observation infrastructure | Preparation compiles without a durable writer capability |
| Counted immutable publication port | Private test observation infrastructure | Every preparation-side `put_blob` call is visible, including overwrite attempts |
| Exact structured capture | Existing portable snapshot backend and private capture helper | Complete State, Receipts, ObjectHeads, ObjectVersions and referenced blob bytes under one fenced local snapshot |

Share these small capabilities across fee, lifecycle, slash and registration
tests. A bond fixture must not import its reader capability from a fee-claim
test module. Keep the counting WASM engine and genuine business fixture setup
with their actual owners; do not create a universal fixture or production port
merely to shorten tests.

## Exact comparison where equivalence is real

Install the same genuine genesis and prior operations in two real stores, then
run the same signed operation through preparation plus real commit on one and
the direct committing entrypoint on the other. Compare all captured records
and their exact descriptor/value bytes, plus the complete referenced blob
closure. Retain existing outcome, original receipt, execution-count, nonce,
CAS failure, exact replay and genesis/provenance assertions.

No semantic projector, allowlist or normalization computes the expected side.
Both sides capture their actual persisted result. Preparation itself must leave
the source's complete capture and publication count unchanged. Exact replay
must leave the original completed capture unchanged and not execute again.

A portable snapshot token proves continuity only within its owning backend.
Do not equate tokens across independent stores or promote one to a portable
state root. Compare records and referenced bodies across stores; check each
store's own token before/after its read-only operations. Physical row revisions
and checkpoints remain part of exact capture for these equally initialized
same-engine tests.

Negative controls must exercise missing receipt/head rows, extra state and
changed referenced content where a real blob-backed capture exists. Distinguish
test-local mutation of a captured value from a genuine business operation or
blob-backed execution fixture. Never claim the latter from the former. Preserve
the existing page, descriptor, chunk, token and outbox integrity assertions.

## Different derivations are not interchangeable

Live-source versus independently replayed overlay is the production semantic
audit contract. Live-source versus verified SQLite cut/import is a different
boundary with legitimate local-cache exclusions and physical rebasing. Neither
is the equal-store direct/prepared contract above. Retain those owning verifiers
and tests; do not replace them with blind raw equality or a second parallel
normalization framework.

Capture plumbing may move to a private test module, but its existing consumers
must use that same implementation. Relocation alone is not the improvement:
the material change is complete persisted-result equivalence and removal of
test fixture dependency inversions, with no broadened authority.
