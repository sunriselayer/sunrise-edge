# DR-0138: FastVote fee-claim admission capacity and version boundary

## Status

Accepted, 2026-09-24. The validator admission cap, deterministic byte-size
regressions, and bounded local concurrent SQLite zero/positive-claim reopen
regressions are implemented. Network throughput, sustained positive-claim
load, disk-life and recovery-time capacity certification are not.

## Context

The certified-fee settlement row contains one share per active validator and
is rewritten after each claim. The signed claim is also retained permanently.
The previous 10,000-entry codec ceiling is a decode/resource limit, not a
safe active-set size for this storage pattern. A prepare commits persistent
nonce/object locks before certificate application, so admission must reject
an unaffordable set before prepare, not only when fee settlement is applied.

## Decision

An active FastVote validator set admitted at genesis or as an epoch's next set
has at most 256 validators. `prepare` and `apply` independently reject an
oversized current set before executing or committing anything; the fee-share
constructor has a final guard. Thus a pre-existing oversized set cannot
acquire new prepare locks under this code, although any locks created before
the cap was introduced need explicit operator migration/cleanup.
The existing 10,000-entry validator-set decode ceiling is unchanged for
historical readability. This is a testnet admission policy, not a new codec
version, and no canonical transaction, certificate, escrow or claim frame is
changed.

One settlement row carries all validator shares and is rewritten on every
claim. With the current `0x641E/v1` encoding, the `genesis-test` fixture's
12-byte chain id, and maximum signed claim envelope of 201,728 bytes,
deterministic encoded-size inputs give:

| Validators | Settlement row | Sum of full-row rewrites for one claim per validator | Retained envelopes at maximum size |
| ---: | ---: | ---: | ---: |
| 128 | 10,110 B | 1,294,080 B | 25,821,184 B |
| 256 | 19,838 B | 5,078,528 B | 51,642,368 B |
| 10,000 (decode-only counterfactual) | 760,382 B | 7,603,820,000 B | 2,017,280,000 B |

These row sizes and row-rewrite sums are exact for the stated fixture context,
not universal upper bounds: `ChainId` is not capped to 12 bytes. The envelope
column is an upper bound for the current signed-claim codec. None of these
figures measures I/O, traffic, latency, or a disk budget. The 256 cap avoids
admitting a 10,000-way claim fan-out under the present whole-row
representation. Before a network capacity claim, load/soak work must still
establish acceptable concurrent escrows, claim rate, storage retention and
restart time. A later increase in the cap requires that evidence and a
reviewed admission change.

The local regression runs 48 directly set-up escrow rows through the real
zero-share claim handler using six concurrent connections to one file-backed
SQLite database, then closes/reopens it and reads every resulting row and
signed envelope. It reports elapsed time and exact logical retained-value
bytes for that run. The rows are synthetic rather than certificate-applied;
the test does not exercise WASM/object-mutating positive claims, report
physical SQLite/WAL disk usage, or establish sustained/multi-node capacity.
Its timing is diagnostic, not a network admission threshold.

A companion regression runs 12 distinct, directly set-up escrow rows through
real Standard Asset WASM `split` or `transfer` claims on three concurrent
SQLite writer connections. Six splits persist distinct payout objects and six
final transfers move the escrow object; every resulting row, signed claim,
object and outer receipt is checked after close/reopen. It reports logical
retained payload bytes, physical SQLite database/WAL file sizes and elapsed
times. The rows were not created by certificate apply, one process and disk
are used, and SQLite may checkpoint the WAL before measurement (including a
zero-byte WAL result). This is local regression evidence, not a certified
claim-rate, disk-life, multi-node or recovery-time bound.

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
  committing; prepare, apply and fee-share construction recheck the active
  set. A 256-member share set remains accepted.
- Codec decode remains compatible with larger historical sets. Such a set
  cannot create a new fee-share row under this admission policy.
- Positive-claim SQLite race and ambiguous-commit regressions cover one
  object-mutating generation; independent signed-claim-chain verification
  after restart remains a separate Phase 3 requirement.
- This decision does not declare Phase 3, testnet, or production ready.

## Required evidence

- The 256/257-member boundary and historical codec readability regressions
  remain green, including genesis and public epoch-vote rejection before
  transition writes.
- Real SQLite positive-claim competition and ambiguous-commit restart tests
  demonstrate exactly one settlement generation, object transfer, nonce and
  receipt, including the claimant's payout object.
- Before declaring network capacity, measure representative concurrent
  escrows, sustained claim rate, retained bytes, and restart/recovery time
  with the actual testnet chain id and storage backend.
- Before adding a protocol-version switch, exercise its outstanding-escrow
  rule across process restart, including zero-share claims.
