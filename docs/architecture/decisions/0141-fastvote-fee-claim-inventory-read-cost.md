# DR-0141: Bounded FastVote fee-claim inventory read cost

## Status

Accepted, 2026-09-25. Implementation and validation status are tracked in
`TODO.md`. This decision changes read-only recovery verification, not claim
admission, execution, canonical bytes, or network capacity policy.

## Context

DR-0139 verifies one certified escrow by point-reading every signed claim
generation through the installed settlement row. To reject orphan claims it
also probes every *absent* later generation through the active-validator
bound. This is safe for callers with only the structured durable-store API,
but a quiescent all-escrow sweep repeats 257 negative key reads for
each low-generation escrow. DR-0140 added a typed, bounded durable-key scanner
for the inventory but did not use it to check each escrow's claim-key set.

## Decision

The explicit-escrow verifier retains its existing bounded point-read path.
The inventory path, whose store already supports `DurableStateKeyScanner`,
may instead scan the exact chain-and-escrow claim-key prefix with a bound
derived from `MAX_FASTPATH_ACTIVE_VALIDATORS`. It must require precisely the
generation keys `2..=installed_generation` and reject any missing, malformed,
tombstoned, extra, or continued page. The signed-envelope, historical
validator, row-digest, object, creation-authority, and payout proofs remain
unchanged and are still performed through the authenticated versioned reads.
The scan is an additional key-set proof, not a replacement for envelope or
object verification.

This reduces absent-key point reads for the paged inventory without a global
mutable index or unbounded scan. It also rejects an extra retained key beyond
the old generation probe ceiling. It does not assert an atomic snapshot:
operators must run the whole multi-page sweep on one quiescent, fenced store
and restart it if writes can interleave. A deleted key or whole-store rollback
still requires an external anchor to detect.

## Evidence and limits

- Targeted tests must cover exact key-set acceptance, missing generations,
  malformed or out-of-range keys, tombstones, and continuation at the bound.
- A read-counting store demonstrates the negative-read reduction for the
  isolated orphan-key check. Certified inventory tests separately establish
  successful positive-claim and payout verification, but do not count those
  reads end-to-end.
- Timing and physical-storage observations are diagnostic only. Sustained
  claim throughput, disk life, and an acceptable network recovery-time bound
  still need a specified testnet topology, load profile, and SLO.
- No transaction, certificate, claim, receipt, object, nonce, or settlement
  encoding changes. A plain per-escrow caller without scanning support keeps
  its original fail-closed behavior.
