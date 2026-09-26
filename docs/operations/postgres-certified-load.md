# Certified PostgreSQL load and recovery measurements

This finite test driver measures the paid certificate-to-claim lifecycle and
complete restart inventories. It is not a deployment tool, an admission
decision or a capacity certificate. Use only disposable test data on a
loopback PostgreSQL service named `sunrise_edge_test`. Never supply a
production DSN or real assets.

[DR-0146](../architecture/decisions/0146-postgres-certified-load-and-recovery-harness.md)
defines the measurement contract. `TODO.md` records actual validation and
remaining network gates.

## What is exercised

The workload creates genuine paid escrows through FastVote prepare, a
three-of-four certificate and certificate apply. One primary uses the real
PostgreSQL structured and blob-store adapters; independently instantiated
memory-backed co-voters provide the other signatures. Paid senders have
separate source coins and nonce lanes. Each planned escrow receives one
positive split, one final transfer and two zero-share claims, retaining one
signed split payout.

The workload then closes and reopens its primary under a newer writer fence,
checks retained state and exact replay, and rejects the stale writer. A
second phase runs the compiled `fee_escrow_inventory_pg` operator repeatedly
through an ephemeral test TLS relay, checks complete multi-page results and
compares exact planned row/claim/payout counts on every cycle.

This measures a PostgreSQL **primary with memory co-voters**, not four
independent PostgreSQL hosts. The separate
[four-validator rehearsal](fastvote-pg-rehearsal.md) covers distinct database
credentials. Neither test proves independently administered hardware,
production PostgreSQL-server TLS, public ingress or network fault tolerance.

## Bounded smoke

Install the normal repository dependencies first. Configure
`SUNRISE_EDGE_TEST_POSTGRES_URL` through a protected environment; do not put
credentials into argv or shell history. The service must be a disposable
loopback test instance. Then run:

```sh
bash scripts/check-postgres-soak.sh --smoke
```

Smoke uses eight escrows, two paid senders, two claim writers, a maximum
offered claim rate of 32/s, a 90-second workload window, a 180-second wall
deadline and two recovery cycles. These are test-size bounds, **not adopted
network targets**. The script overrides long-run sizing variables in smoke
mode. Repository validation runs only this bounded mode; it never starts a
long soak implicitly. Local smoke without a configured PostgreSQL service
reports a skip; CI treats the missing service as failure.
Argument-validation regressions can also run without a database:

```sh
bash scripts/check-postgres-soak.sh --self-test-cli
```

## Explicit manual measurements

Manual mode has no default workload. Every parameter and the disposable-test
confirmation is required. For example, the following is a finite diagnostic
profile, not an acceptance target:

```sh
export SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1
export SUNRISE_EDGE_SOAK_ESCROWS=64
export SUNRISE_EDGE_SOAK_SENDERS=4
export SUNRISE_EDGE_SOAK_CLAIM_WRITERS=4
export SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC=8
export SUNRISE_EDGE_SOAK_DURATION_SECONDS=600
export SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS=900
export SUNRISE_EDGE_SOAK_RECOVERY_CYCLES=3
bash scripts/check-postgres-soak.sh --run
```

The bounds are 1–4096 escrows, 1–64 senders (no more than escrows), 1–16
claim writers within the pool bound, maximum offered rate 1–1000 claims/s,
workload window 1–21600 seconds, wall deadline 1–25200 seconds and 1–32
recovery cycles. The wall deadline must exceed the workload window.
`DURATION_SECONDS` is an upper window for completing every planned unit,
not a minimum duration. An early completion does not establish a soak of
that length; no idle waiting is counted as sustained load. The rate limiter
caps offered calls; it neither requires nor certifies that achieved rate.
Longer or deployment-specific runs need their own explicitly approved
workload and resource budget.

The driver serializes against the shared live-PostgreSQL test lock. Do not
run it concurrently with repository PostgreSQL tests on the same service.
Its top-level timeout bounds the whole run, including setup, lock wait,
workload and recovery. Each inventory executable also has a 120-second
per-invocation timeout; valid sizing alone does not guarantee that a run
finishes within either budget. A killed test can retain disposable namespace
rows; do not remove unrelated namespaces to recover space. Prefer recreating the
dedicated disposable service after preserving the nonsecret measurements.
Forced termination may also leave the shared live-test lock file. Read its
recorded owner and confirm that the owning test process has exited before
removing that exact abandoned lock; never remove another live test's lock.
Recreating the database alone does not release a host-side lock.

## Interpreting results

Keep the source commit, exact parameters, PostgreSQL version, host CPU/RAM,
storage type/capacity, server durability settings and other load alongside
the output. Integers in `sunrise_edge_soak_v1` measurement lines record
counts, elapsed milliseconds, retries and retained payload sizes. Whole
shared-table physical sizes include earlier local namespaces; they are not
isolated per-validator storage accounting.

`retained_logical_bytes` sums each final settlement row, its four retained
claim envelopes, the latest fee-escrow and split-payout object payloads, and
the four outer receipt response payloads. It excludes storage keys, record
headers, nonce records and superseded row/object history; it is neither a
complete database footprint nor per-transaction disk consumption. Setup
and escrow creation are serial in this instrument; only the independent
claim lanes exercise the configured writer concurrency.

Only `kind=totals complete=true` from the ordered driver means the requested
workload, restart checks and every complete inventory cycle passed. A phase
record or libtest success from the workload alone is not a complete recovery
result. A deadline, failure, invalid parameter, missing test or malformed
handoff must exit nonzero without that totals line. Never infer rollback
from failure: keep the original signed bytes and inspect durable state before
retrying an indeterminate operation. Do not change request IDs merely to
turn an ambiguous result into apparent fresh work.

The test TLS relay protects the executable boundary on the local test
service; it is not evidence of production server certificate configuration
or rotation. Small inline Standard Asset bodies do not exercise blob-backed
fee history. Representative sustained load and fault/recovery trials,
independent administrative/failure domains and the separate Phase 3 review
gate remain necessary before any network-capacity claim.
