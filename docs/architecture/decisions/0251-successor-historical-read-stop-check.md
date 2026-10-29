# DR-0251: Successor historical-read stop check

Date: 2026-10-16 (Asia/Singapore)

Status: Accepted component design. Qualification and remaining D05/M5 criteria
belong in [TODO](../../../TODO.md).

## Decision

Extend [DR-0250](0250-successor-operation-context-stop-check.md)'s cooperative
stop check to the separate signerless successor-history read owner,
`successor::historical::read`. This boundary has its own composition
(`SuccessorHistoricalComposition`) and does not call
`successor::operation_context`; it builds the request's correlation identity,
trusted-clock reading and storage deadline inline, then calls
`policy_source.ordered_policy` and goes on to storage. That sequence had no
cooperative check between a closed admission pool and the fresh
policy/storage access that follows. The generic `publication::admitted` entry
guard this router also shares cannot observe a close that lands during
`read`'s own clock call, because that guard's own stop snapshot is read
before the blocking closure's identity/clock/deadline work runs.

`read` now checks `SuccessorHistoricalComposition::blocking_executor`'s
existing `stop_cancellation()` once identity, clock and deadline preparation
have all succeeded, immediately before calling `policy_source.ordered_policy`.
Identity, clock and deadline error priority is unchanged; a closed executor
never masks those errors, and an open executor never introduces a new
refusal. No new composition field, constructor input, CLI knob, policy or
abort path is added. `SuccessorHistoricalComposition` already carries
`blocking_executor` for every production call site; this reuses that single
instance, the same one `admitted` already clones and admits through.

A closed pool returns the existing `cancelled_before_storage_response()` 503
`invocation-cancelled-before-storage` shape, the same shape DR-0222/DR-0247/
DR-0250 already use. The preexisting `unavailable()` 503
`ordered-history-unavailable` refusal used by every other failure in `read`
(including identity/clock/deadline and policy/storage errors) is otherwise
unchanged. All three signerless history routes (`summary`, `height`,
`component`) share this one `read` boundary, so the check applies uniformly.

## Validation contract

A fresh `NativeBlockingExecutor` cloned into the historical composition,
closed from inside the clock double after the request has already passed the
`admitted` entry guard but before `read` reaches `policy_source.ordered_policy`,
must produce the exact `invocation-cancelled-before-storage` 503 body and
reach the policy source zero times. A counterpart request against an
equivalent composition without closing the executor must reach the policy
source exactly once and observe the preexisting `ordered-history-unavailable`
refusal unchanged. Identity, clock and deadline failure controls close the
shared executor from inside the identity/clock double after admission, then
require the original `ordered-history-unavailable` refusal rather than
cancellation, and the policy source is still never reached. Already-closed
admission still keeps its existing earlier `admitted`-guard refusal; no test
bypasses that router boundary.

Controls cover the `summary` GET route. A negative control that removes the
new check must fail these oracles; restoring the exact guard must restore
their success. A unit test in this crate cannot observe the compiled
successor-history host binary's or CLI's executor wiring; it only exercises
the manually composed `SuccessorHistoricalComposition` built in
`successor::tests`. `apps/operator/src/successor_host/historical.rs` clones
the production executor into this same composition and passes it to
`native_operations::serve`; a manual unit composition cannot detect removal
of that wiring.

## Compatibility and limits

No canonical bytes, protocol identifier, signature payload, persisted layout,
dependency or wire error shape changes. The reused `InvocationCancellation`
and 503 shapes are unchanged. No preemption, rollback or atomic-abort
guarantee is introduced once policy or storage work has started. This
component does not establish measured capacity, circuit breaking, alerting,
real production PKI, or whole D05/M5 qualification; final source and actual
results stay in TODO.
