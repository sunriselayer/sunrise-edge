# DR-0183: Test observation ownership and complete preparation equivalence

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted bounded design under DR-0180. Independent implementation
review and actual acceptance remain required. This does not approve changes
to handoff normalization, canonical bytes or production authority.

## Context

PR #258 makes business preparation genuinely writer-free. Its review suggested
stronger complete state and immutable publication evidence. Fee, unbond and
slash tests already compose genuine equally initialized stores and compare the
direct and prepared outcomes and one receipt, but not every persisted result.
Bond tests borrow their reader view from fee-claim tests. Registration has its
own counted blob port and already exercises a complete production audit.

The existing portable capture scans every collection and referenced body.
Separate verified cut/import tests intentionally exclude local caches and
rebase physical coordinates. Treating every source/target pair as identical
would discard a legitimate architecture boundary, not simplify it.

## Decision

Adopt [test observation contracts](../test-observation-contracts.md). Share
private reader, publication-counter and existing raw capture mechanics across
actual consumers. Keep genuine genesis, quorum, WASM and business fixtures
with their owning tests. Delete duplicate mechanics and inverted fixture
dependencies, not merely wrap them in another common module.

For equally initialized same-engine stores executing the same operation,
compare complete exact rows and referenced blobs after real completion;
retain every existing assertion. Observe zero preparation publication attempts
and unchanged complete source state, then exact replay non-reapplication.
Do not compare independent opaque snapshot tokens as portable identity.

Retain production replay/source comparison and verified cut/import tests as
distinct contracts. No new normalization or generic production trait is needed.
Explicit negative controls distinguish missing/extra records and changed bodies;
fixture limitations must be stated instead of disguised as genuine execution.

## Acceptance

Run actual fee, lifecycle, slash, registration and existing capture/reconstruction
consumers, then the complete required storage-neutral gate and fresh independent
exact-head review. PostgreSQL is not required merely because private test
observation mechanics changed; affected real backend behavior still selects
its owning acceptance. No assertions, gates or positive provenance are waived.
