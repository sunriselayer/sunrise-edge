# DR-0222: Native stop, actual work drain and bounded observations

Date: 2026-10-08 (Asia/Singapore)

Status: Accepted design after independent Codex fallback design inspection and
parent review against `99c75e0c`. Acceptance covers the local implementation
contract below, not source/test approval, deployment or public activation.
Current status remains in TODO.md.

## Context and As-Is gap

DR-0219 already has one bounded accept/upgrade/HTTP owner. Its connection joins
do not certify completion of `spawn_blocking` jobs detached by a dropped HTTP
future. Both live operator hosts create a lazy Ctrl-C future after binding and
ignore signal-registration errors; signerless history does the same. They lack
an explicit orderly SIGTERM path. Connection/upgrade errors and overload
refusals also lack a bounded operational observation consumer.

Runtime destruction may wait for detached work, but is not an explicit
application-drain result. New lifecycle or observation counters must not become
protocol state, signing authority, a second admission queue or a new persistence
framework.

## Decision

Implement [the Native operations contract](../native-operations.md) with three
immediately used owners:

- A private operator stop owner installs Unix SIGINT/SIGTERM before binding and
  readiness, refuses installation errors and preserves buffered notifications.
  Check buffered stop before printing readiness. Live reopening advances the
  existing writer fence; history reopening claims or advances no live fence.
  Original live, successor live and signerless history consume the same owner.
- `NativeBlockingExecutor` closes admission and explicitly drains admitted
  tracked RAII permits. Acquisition/registration is synchronized with closure;
  the permit stays inside the existing blocking job. Transport cancellation
  never aborts a started write or invents rollback. Existing serving closes its
  listener and joins connections before the retained executor finishes drain.
- A Native HTTP observed seam has fixed saturating counters and snapshots, with
  one bounded secret-free host termination summary. It introduces no dynamic
  labels, per-request log, public route, external sink or background worker.

Preserve existing serve API paths, error priority, all transport/work deadlines,
canonical bytes, durable schema, fees, replay and writer fencing. Add no crate,
dependency version, unsafe code, daemon or provider assumption. Existing
independent-store/restart fixtures own acceptance; no extra long recurrence or
backend-every-PR lane is needed.

## Alternatives and limits

Connection joins alone are rejected because work can outlive a request. An HTTP
shutdown deadline that reports rollback is rejected because started blocking
storage cannot be aborted safely. Per-request error logging is rejected because
it can expose input and make abusive traffic an unbounded logging workload.
A generalized supervisor or telemetry framework has no needed consumer here.

The drain has no universal wall-clock guarantee. A force-killed process is not
an orderly-stop pass, and a fixed-size stderr record does not bound kernel I/O.
Counters are local observations, not public readiness or application success.
PKI, protected custody, alert/SLO policy, real host/storage faults, independent
release audit and launch authority remain separate requirements.

Source-bound design inspection: `native-operations-design-review-20261008.md`,
SHA-256 `26a082e01d395a72d2134387bf9fb2c992ef6e91b72718b7d6846911cc14d153`.
It explicitly blocks clean-drain claims based only on connection joins.
