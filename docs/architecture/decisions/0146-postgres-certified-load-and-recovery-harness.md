# DR-0146: Bounded certified PostgreSQL load and recovery harness

## Status

Accepted, 2026-09-26. Measurements and remaining acceptance work belong in
`TODO.md`. A completed harness run is not network-capacity certification.

## Context

DR-0145 measures concurrent claims on directly installed settlement fixtures.
The certified PostgreSQL inventory fixture exercises two genuine escrows, but
does not scale the certificate-to-claim lifecycle. A measurement instrument
must preserve that provenance rather than treating synthetic setup rows as
certified traffic. No initial-network workload, sustained-rate target or
recovery budget has been adopted.

## Decision

Add a finite, explicitly invoked test harness with two ordered phases:

1. Create paid escrows through authenticated FastVote prepare, a real
   three-of-four quorum certificate and certificate apply. The primary uses
   real PostgreSQL structured and blob stores; independently instantiated
   memory-backed co-voters supply the quorum. This is **one PostgreSQL
   primary**, not a four-host network or independent-administrator test.
   Use distinct paid senders and source coins for independent lanes. Create
   every planned escrow before the claim phase. Execute one positive split,
   one positive final transfer and two zero-share claims per escrow, keeping
   the exact signed bytes for replay and restart comparison.
2. Close and reopen the PostgreSQL primary under an advanced writer
   generation. Verify retained settlement, claim, object, payout and receipt
   state and reject the old writer. Then invoke the real TLS
   `fee_escrow_inventory_pg` executable for repeated complete, paginated
   inventories, checking exact expected counts and the final fence.

Concurrency is a measurement-driver concern, never a protocol requirement.
Each sender's nonce chain is serial; independent senders may run concurrently.
Positive claim legs must use independent signing/nonce lanes or serialize
their shared nonce assignment. Only a definite serialization non-commit may
be retried, with unchanged signed bytes and a finite retry budget. Conflict,
indeterminate commit, deadline or pool failure is not silently retried as new
work. Report the actual retries, planned units and completed units.

The manual runner requires explicit bounds. Environment parameters are
`SUNRISE_EDGE_SOAK_ESCROWS` (1–4096), `SENDERS` (1–64, no more than escrows),
`CLAIM_WRITERS` (1–16, within the configured pool bound),
`MAX_CLAIM_RATE_PER_SEC` (1–1000), `DURATION_SECONDS` (1–21600),
`WALL_DEADLINE_SECONDS` (1–25200), and `RECOVERY_CYCLES` (1–32), all under
the `SUNRISE_EDGE_SOAK_` prefix. `DURATION_SECONDS` is a maximum workload
window, not proof that a minimum soak duration was exercised. The wall
deadline bounds the whole driver, including setup and recovery; it must
exceed the workload window. Finish every planned unit before success. A
deadline at a partial unit or an exhausted budget produces failure, not a
successful smaller run. Pacing is an upper offered-rate limit, not an
accepted throughput target. No performance acceptance threshold is invented.

Use only a disposable loopback PostgreSQL service named `sunrise_edge_test`
and fresh per-run namespaces. The manual mode requires an explicit
disposable-test confirmation; it never provisions or deploys a network.
CI invokes a separate fixed, bounded smoke profile; it does not inherit
operator long-run sizing. All required ignored tests must be enumerated with
`--ignored --list` and invoked with `--ignored --exact`, so renamed or
unignored tests fail closed rather than passing with zero executions.

## Handoff and measurement contract

The driver owns a fresh temporary `SUNRISE_EDGE_SOAK_DIR`. The workload
publishes `handoff.kv` only after its complete lifecycle and restart checks.
The recovery reader requires exactly these newline-terminated keys, with no
duplicates, missing or unknown keys:

| Key | Shape |
| --- | --- |
| `schema_version` | literal `1` |
| `validator_id` | 64 lowercase hex digits selecting the test storage namespace |
| `chain_id` | nonempty bounded ASCII chain identifier |
| `domain` | 64 lowercase hex digits |
| `protocol_version` | nonzero decimal integer |
| `epoch` | nonnegative decimal integer |
| `suite` | the exact colon-separated configured suite |
| `expected_rows` | planned escrows, 1–4096 |
| `expected_claims` | exactly four times planned escrows |
| `expected_payouts` | exactly one split payout per planned escrow |
| `writer_generation` | persisted generation after workload reopen |
| `workload_elapsed_ms` | measured integer milliseconds |

These counts are derived from the planned workload, not redefined from a
partial observed result. Every recovery cycle must match them and advance
the writer generation by exactly one. A malformed, stale or truncated
handoff grants no authority or complete result. Files are created fresh;
existing files and symlinks must not be overwritten.

Measurement lines use `sunrise_edge_soak_v1 kind=...` followed by bounded
`key=value` fields. Counts and durations are integers. Record configuration,
PostgreSQL version, creation and claim elapsed time, retries, logical retained
bytes and complete-inventory time. Physical relation sizes are whole shared
test-table diagnostics; previous local namespaces can inflate their baseline.
Never emit database credentials, DSNs or signing material. Only the ordered
driver may emit `kind=totals complete=true`, after both phases and every
recovery cycle succeed. Failed or interrupted runs exit nonzero and grant no
capacity result. The run ends and its invocation may terminate.

## Limits

The harness adds no canonical bytes, event ingress, consensus rule, fee
arithmetic, daemon or runtime requirement. Standard Asset fee bodies remain
small inline values; this does not exercise blob-backed fee history.
Accepted network workload and recovery targets, representative sustained
soak, independent administrators and failure domains, real host faults under
load, server-side TLS deployment, PITR/HA, external FastVote ingress,
protocol-version activation and the Phase 3 review gate remain separate
obligations. A six-hour execution ceiling is a safety bound on this
instrument, not a decision that six hours is sufficient for certification.

## Store correctness uncovered by the workload

The initial real-database run reached a TreasuryCap at object version 10 and
failed the next mint with `InvalidPersistedState`. PostgreSQL resolves
`ORDER BY object_version` against the selected `object_version::TEXT` output
name in the latest-version lookup; that selects `9` ahead of `10` rather than
ordering the underlying numeric column. On the same retained history, the
original query returned 9 and a base-column-qualified query returned 10.

Qualify the numeric base column in both locked and unlocked latest-version
queries. Do not skip head/history reconciliation or cap the workload below the
boundary. Live adapter regressions must exercise decimal-width transitions,
read and mutation paths, reopen, and continued fail-closed handling of
head/history disagreement. This corrects store lookup behavior without
changing schema, canonical bytes, object-version rules or protocol authority.
