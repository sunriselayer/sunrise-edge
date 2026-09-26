# DR-0145: PostgreSQL Phase 3 capacity evidence and validator authority

## Status

Accepted, 2026-09-26. Implementation and measured results are tracked in
`TODO.md`; this decision does not certify a network launch.

## Context

DR-0138 bounds the active validator set at 256 but its measured claim work is
on a local SQLite file. DR-0143 proves a nonempty certified PostgreSQL escrow
inventory, and DR-0144 proves a four-validator FastVote flow using four
namespaces on one disposable database. Neither gives PostgreSQL claim-rate,
retention and restart-sweep evidence at representative load. A namespace
tuple in a shared `sunrise_edge` SQL schema is a protocol/storage key, not a
database authorization boundary: a login with table access can address a
different validator's tuple.

## Decision

Exercise Phase 3 on the selected PostgreSQL store with two complementary
bounded workloads. First, run distinct escrow claims concurrently through
the real claim handler: zero-share fan-out and positive Standard Asset WASM
split/final claims. Measure elapsed claim work, exact retained canonical
claim/settlement/object payload sizes, and PostgreSQL physical relation size
before and after the run. Close the writer pool, advance the namespace writer
generation, reopen it, then verify every resulting row, object, payout,
receipt and stale-writer rejection. Second, run the real stopped-validator
inventory operator over a nonempty certified escrow history with multiple
pages and record its complete-sweep wall time. A sweep is complete only after
its final fence recheck; a partial page or timeout is not a recovery result.

Keep CI workloads bounded and diagnostic. A deployment-capacity report must
record the exact hardware/service, PostgreSQL version and storage settings
alongside its timings. CI service timings are regressions, not throughput
service-level objectives; synthetic escrows are not certificate-applied
traffic, and a short run is not a soak.
Longer operator-initiated capacity runs need explicit size and duration
controls; they must never silently promote CI timing to a production admission
threshold. A first-network capacity target, sustained
positive-claim rate and recovery-time budget require a declared deployment
profile and representative long-run measurements before certification.

Each real validator uses a separately administered PostgreSQL authority and
credentials. For a disposable integration test, a separate PostgreSQL
database and login role per validator on one server is enough to prove
credential-level isolation when `CONNECT` is revoked from `PUBLIC` and
cross-database access is rejected. It does **not** prove independence of the
server administrator, host, disks, backup, failure domain or network. Merely
creating several namespace tuples or SQL login roles in one shared database
does not meet even this credential-isolation test. Each validator's CLI
invocations must be bound to its own DSN; no vote or certificate file can
select another validator's database. The role may initialize only its own
database during explicit bootstrap, while normal operation still requires
the independently configured expected protocol context and writer fencing.

Do not change canonical bytes, consensus rules, fee arithmetic or the
`SubmitTransaction`-only external event boundary for these measurements.
These are finite, operator-invoked checks; no daemon, relay, scheduled sweep
or long-lived process becomes a correctness requirement. An ambiguous
certificate-apply response is reconciled from the durable record under a
fresh fence before deciding whether an exact replay or a new request is safe.

## Required evidence and limits

- A real PostgreSQL regression covers concurrent distinct zero and positive
  claims, close/reopen, exact retained results and a stale generation. The
  256/257 admission boundary remains independently tested; a small positive
  workload does not prove positive-claim capacity at 256 validators.
- The certified multi-escrow inventory command completes more than one page
  and reports its observed wall time only after fence recheck. The complete
  history and payout checks remain authoritative, not just a row count.
- Four real validator CLI identities use four different database credentials
  and databases. A validator's login cannot connect to another validator's
  database; the existing quorum, replay and adversarial checks still pass.
- A PostgreSQL failure/recovery result must distinguish no commit from an
  ambiguous commit, verify the durable receipt/object/nonce after restart,
  and reject an old writer generation. Store-level fault tests alone do not
  prove the entire operator sequence.

The Phase 3 review gate remains independent of passing these regressions.
Protocol-version activation, authenticated external FastVote ingress,
post-genesis operator epoch transitions, independent multi-host operation,
PITR/HA, long soak, disk life, public testnet and production/mainnet
readiness are not granted by this decision.
