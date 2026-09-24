# DR-0140: Signed FastVote payout reference and escrow inventory

## Status

Accepted, 2026-09-24. Implementation and evidence status belong in
`TODO.md`. This decision does not certify capacity or network readiness.

## Context

DR-0139 reconstructs one certified fee escrow's initial row, retained
escrow object and signed claim chain after restart. For a split, however,
the prior signed payload does not name the claimant-owned payout. The
execution leg can derive a bounded *set* of creation IDs, but choosing a
semantically valid object from that set is not proof that it was the actual
payout committed by the claim. A substituted object at another ordinal can
pass owner/type/value checks after the actual payout has been deleted.

The verifier also needs an explicit escrow request id. It cannot by itself
establish coverage of every settlement row retained by a store. A global
mutable escrow index would add contention to the fast path without proving
history against deletion or whole-store rollback.

## Decision

The claimant signs an exact `expected_payout: ObjectRef` for a split. This
uses field 15 of explicit fee-claim intent `0x6437/v2`, embedded in signed
envelope `0x6438/v2`. The handler compares the actual created payout's ID,
version and canonical object digest with that signed ref *before* the atomic
commit. The field is forbidden for zero-share and final-transfer claims,
which retain v1 encoding. Historical v1 split bytes remain decodable and
re-encodable without change, but an unproved v1 split is not accepted as a
new claim or a fully verified historical payout.

On restart, the verifier loads exactly the signed payout version 1. It
authenticates its canonical body and digest against the signed ref, checks
the immutable creation-authority sidecar, owner, type, schema and ABI-decoded
amount, and checks that its ID belongs to the authenticated leg's bounded
creation-ID domain. Other candidates in that domain must have no retained
authority or immutable version; a tombstone also fails closed. The ordinal
search verifies provenance of the *signed* ID and absence of extra
creations; it never selects a substitute payout. The existing signed row and
retained-escrow conservation checks remain independent.

For inventory, a separate optional, read-only durable-key scanner pages the
structured state keyspace in lexicographic order with an exclusive cursor
and bounded page size. It is not a protocol-transition dependency. Memory,
SQLite and PostgreSQL implementations use existing indexed durable-state
keys and expose tombstones. A caller-driven verifier accepts only exact
chain-scoped settlement keys and invokes the per-escrow proof once per key.
It has no global mutable index or background loop.

A complete all-escrow claim requires a quiescent sweep over one fenced
store. Pages are not a multi-page snapshot: concurrent insertions before a
cursor can be missed, so operators must restart the sweep. Enumeration
proves coverage of present keys, not that a deleted key or rolled-back
database never existed. A separately anchored checkpoint/state root is
needed for that stronger history claim.

## Required evidence and limits

- Preserve byte-identical v1 vectors and add Rust plus independent JavaScript
  v2 vectors, including forbidden/missing payout fields.
- Prove exact split payout acceptance and rejection of an alternate ordinal,
  missing/tombstoned authority, wrong ref/digest/body/owner/value/schema/type
  across a real SQLite close/reopen. Final and zero-share claim paths must
  retain their existing semantics.
- Verify scanner ordering, prefix, cursor, bounds, tombstones, domain/fence
  and deadline checks. The PostgreSQL live case uses the existing CI database
  harness; a locally skipped case is not evidence of real query execution.
- The inventory sweep must reject malformed or tombstoned settlement keys
  and report continuation honestly. One page is never described as a
  complete global verification.
- Bounded ordinal checks add restart read amplification; measure that cost
  before claiming network recovery-time capacity.
- `FastCertificate`, settlement, transaction, receipt, nonce and object
  canonical bytes do not change. Only the explicitly versioned split claim
  intent and signed envelope gain a new canonical form.
