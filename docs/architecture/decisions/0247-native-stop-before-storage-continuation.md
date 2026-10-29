# DR-0247: Native stop checks before recovery and ordered storage

Date: 2026-10-16 (Asia/Singapore)

Status: Accepted component design. Qualification and remaining D05/M5 criteria
belong in [TODO](../../../TODO.md).

## Decision

Retain DR-0222's shared admission, permit ownership and drain. Extend the same
stop signal to both optional scheduler recovery entry points:
`recover_indexed_outbox_once` and `recover_outboxes_once`. Capture the executor's
signal before admission and check it inside the blocking closure, while holding
the permit, before accessing any runtime capability. A queued job observes the
existing typed `AdmissionClosed` error. Initial closed/capacity refusal and
scan-argument validation retain their prior priority. The queued refusal does
not increment `blocking_closed`, which measures failed admission attempts;
`blocking_admitted` still includes admitted jobs that later refuse.

After recovery work enters, lease claim, send, acknowledgement and ambiguity
reconciliation retain their existing behavior. Stop does not abandon an issued
send, roll back a possible commit or shorten the permit's lifetime. The embedding
scheduler still owns scheduling; no timer, daemon or recovery route is added.

Ordered economics additionally checks its explicitly injected cancellation
signal at the end of its existing shared `build_context`. The seven economics
handlers authenticate their inputs before context preparation. Identity, clock
and deadline errors retain priority; the cancellation check precedes returning
the context to the first core storage operation. Existing ordered-history
callers keep their own immediate pre-storage check. An absent cancellation
signal preserves the original behavior.

These are cooperative check points. Cancellation can race with the next storage
call; neither a shutdown deadline nor atomic storage abort is promised. Once a
durable operation starts, its existing commit/reconciliation contract applies.

## Validation contract

A saturated one-thread Tokio pool exercises both actual public scheduler APIs.
The admitted recovery must return `AdmissionClosed` after close without accessing
clock, state, blobs, signer, transport or scheduler, then release its permit.
Fresh calls after close must retain the original admission refusal. A negative
control removing the new guards must fail the oracle; exact source is restored
before positive regression checks.

Actual ordered-router controls arm cancellation after the initial admission
check and require identity/clock preparation but zero storage/signing effects.
A noncancelled counterpart succeeds, and an invalid proposal signature must
still fail before identity/clock/storage. Shared dispatcher, request shape,
lease/reconciliation, receipt replay and complete required controls remain.

## Compatibility and limits

No canonical bytes, protocol identifier, signature payload, persisted layout,
dependency or wire error changes. Existing recovery errors are reused; no
production test hook, extra privilege or arbitrary delay is introduced.

This component does not establish measured capacity, circuit breaking, poison
message/backoff policy, complete alert/spend coverage, a real production PKI,
or whole D05/M5 qualification. Final source and actual results stay in TODO.
