# DR-0250: Successor operation-context stop check

Date: 2026-10-16 (Asia/Singapore)

Status: Accepted component design. Qualification and remaining D05/M5 criteria
belong in [TODO](../../../TODO.md).

## Decision

Extend [DR-0247](0247-native-stop-before-storage-continuation.md)'s cooperative
stop check to the recurring-successor Native host's own authority boundary.
`successor::operation_context` already builds the request's correlation
identity, trusted-clock reading and storage deadline before `with_authority`
calls `SuccessorAuthoritySource::resolve`; that sequence had no cooperative
check between a closed admission pool and the fresh authority/storage access
that follows. `operation_context` now derives a cancellation signal from the
same `SuccessorHostComposition::blocking_executor` every route already clones
and admits through (`successor::blocking`, shared with
`native_operations::serve`), and checks it once identity, clock and deadline
preparation have all succeeded, immediately before returning the context used
for authority resolution and storage. Identity, clock and deadline error
priority is unchanged; a closed executor never masks those errors, and an
open executor never introduces a new refusal.

No new composition field, constructor input, CLI knob or policy is added.
`SuccessorHostComposition` already carries `blocking_executor` for every
production call site; this reuses that single instance.

A closed pool reports the new `SuccessorInvocationError::CancelledBeforeStorage`
variant, mapped by `invocation_error_response` to the existing
`cancelled_before_storage_response()` 503 `invocation-cancelled-before-storage`
shape also used by DR-0222/DR-0247's blocking dispatch. Authority resolution,
malformed-request and signature-boundary handling are otherwise unchanged:
once `with_authority` calls `resolve`, this check does not run again, and
stopping does not preempt or roll back authority/storage work already in
progress.

## Validation contract

A fresh `NativeBlockingExecutor` cloned into the host composition, closed
after a request has already passed job-entry admission (`successor::blocking`
via `publication::admitted`) but before `operation_context` returns, must
produce the exact `invocation-cancelled-before-storage` 503 body and reach the
authority double zero times. A counterpart request against an equivalent composition
without closing the executor must reach the authority double exactly once and
observe its preexisting `OriginalGenesis`/error behavior unchanged. Identity,
clock and deadline failure controls close the shared executor from inside the
identity/clock double after admission, then require the original error rather
than cancellation. Already-closed admission still keeps its existing earlier
refusal; no test bypasses that router boundary.

Controls cover a representative read/status/query route and a representative
mutation route that both share `with_authority`/`serve`. A negative control
that removes the new check must fail these oracles; restoring the exact
guard must restore their success. A unit test in this
crate cannot observe the compiled successor host binary's or CLI's executor
wiring; it only exercises the manually composed `SuccessorHostComposition`
built in `successor::tests`. Structural inspection relates the production executor clone to
`native_operations::serve`. Compiled stop/TLS controls are separate evidence
and do not isolate this particular guard.

## Compatibility and limits

No canonical bytes, protocol identifier, signature payload, persisted layout,
dependency or wire error shape changes. The reused `InvocationCancellation`
and 503 shape are unchanged. No preemption, rollback or atomic-abort guarantee
is introduced once authority or storage work has started. This component does
not establish measured capacity, circuit breaking, alerting, real production
PKI, or whole D05/M5 qualification; final source and actual results stay in
TODO.
