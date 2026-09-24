# DR-0138: FastVote fee-claim admission capacity and version boundary

## Status

Accepted, 2026-09-24. The validator admission cap and deterministic byte-size
regressions are implemented; network throughput, disk-life and recovery-time
capacity certification are not.

## Decision

An active FastVote validator set admitted at genesis or as an epoch's next set
has at most 256 validators. The fee-share constructor independently enforces
the same cap, so a caller cannot bypass genesis or epoch-transition admission.
The existing 10,000-entry validator-set decode ceiling is unchanged for
historical readability. This is a testnet admission policy, not a new codec
version, and no canonical transaction, certificate, escrow or claim frame is
changed.

One settlement row carries all validator shares and is rewritten on every
claim. With the current `0x641E/v1` encoding and maximum signed claim
envelope of 201,728 bytes, deterministic upper-bound inputs give:

| Validators | Settlement row | Sum of full-row rewrites for one claim per validator | Retained envelopes at maximum size |
| ---: | ---: | ---: | ---: |
| 128 | 10,110 B | 1,294,080 B | 25,821,184 B |
| 256 | 19,838 B | 5,078,528 B | 51,642,368 B |
| 10,000 (decode-only counterfactual) | 760,382 B | 7,603,820,000 B | 2,017,280,000 B |

These are deterministic encoded-size bounds per escrow, not measured I/O,
traffic, latency, or a disk budget. The 256 cap avoids admitting a 10,000-way
claim fan-out under the present whole-row representation. Before a network
capacity claim, load/soak work must still establish an acceptable number of
concurrent escrows, claim rate, storage retention and restart time. A later
increase in the cap requires that evidence and a reviewed admission change.

The current epoch transition always carries the same supplied protocol
version into the next context; there is no durable, atomic protocol-version
activation mechanism. The existing claim handler rejects a different version,
including zero-share claims, and typed local execution also rejects a
cross-version positive leg. We keep both fail-closed checks. A future
protocol-version activation must add its own gate: either authenticate and
execute every outstanding historical claim, or prove no claimable escrow
remains before activation. It must be restart-tested before any version
switch is enabled. Merely changing operator configuration is not an
authorized protocol migration.

## Consequences

- Genesis and epoch next-set admission reject 257 or more entries before
  committing; the fee-share path has a third guard. A 256-member share set
  remains accepted.
- Codec decode remains compatible with larger historical sets. Such a set
  cannot create a new fee-share row under this admission policy.
- Positive-claim SQLite race and ambiguous-commit regressions cover one
  object-mutating generation; independent signed-claim-chain verification
  after restart remains a separate Phase 3 requirement.
- This decision does not declare Phase 3, testnet, or production ready.
