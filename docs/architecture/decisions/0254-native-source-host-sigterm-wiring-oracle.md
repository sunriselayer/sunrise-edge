# DR-0254: Native source-host SIGTERM wiring oracle

Date: 2026-10-16

Status: Accepted component design. Qualification and remaining D05/M5
criteria belong in [TODO](../../../TODO.md).

## Decision

Add one deterministic real-factory, real-compiled-process, real-`SIGTERM`
oracle to the existing exclusively-owned
`apps/operator/tests/sqlite_source_host_process.rs`, reusing its private
`Fixture`/`start_host` construction and every existing case/helper/
assertion/bound unchanged. The oracle isolates the production
`sqlite_source_host` constructor's own wiring: a real `SIGTERM` closes the
exact `NativeBlockingExecutor` instance it injects into both the certified
FastVote router and the opt-in ordered-economics router
(`apps/operator/src/sqlite_source_host.rs`), and the ordered-economics
`propose` route's own `publication::admitted()`/`build_context()`
cancellation check (`crates/native-http/src/publication.rs`,
`crates/native-http/src/ordered_economics.rs`) honors that close before any
durable write.

The barrier that proves the executor is already closed, from outside the
process, without a sleep: idle connection C observing EOF/reset, followed by
exactly one fresh `ConnectionRefused`, after the owned PID's `SIGTERM`. Both
effects can only follow `drop(listener)`/`shutdown_sender.send(true)`
(`crates/native-http/src/lib.rs`), which only run after the `shutdown` future
`apps/operator/src/native_operations.rs::serve` builds has already resolved
-- and that exact future's own body calls `stop_executor.close()` strictly
before it resolves. Connection A's own in-flight state is independently
proved by observing an automatic `HTTP/1.1 100 Continue` after sending its
head with `Expect: 100-continue` and withholding its body; the local `hyper
1.11.0` source cited in
[the design document](../native-source-host-sigterm-wiring-oracle.md)
establishes that this can only happen after this crate's own
`dispatch_bounded_request` has already been polled on a connection task that
already passed every per-connection shutdown check -- not from memory of
hyper's general `Expect` handling.

A second, independent, fresh fixture in the same test sends the identical
request's body before any signal, requiring an ordinary `200`,
`blocking_admitted=1`, and a confirmed durable `LeaderProposalRecord`
(decoded through only public `canonical-encoding`/`consensus` APIs against
its already-allocated `0x644B` frame type) in the before/after business
snapshot diff -- not merely a changed snapshot token or an unrelated
metadata write.

## Validation contract

Exact test:
`compiled_sqlite_source_host_sigterm_cancels_withheld_propose_not_a_delivered_one`
in `apps/operator/tests/sqlite_source_host_process.rs`.

Negative half: real compiled host, real SIGTERM while connection A's body is
withheld. Required, in this order: SQLite business records and referenced
blobs byte-for-byte unchanged; connection A's response is exactly `503
invocation-cancelled-before-storage`; the host's one `stderr`
termination-summary line reports `stop=sigterm blocking_admitted=0
blocking_closed=0`.

Positive half: a fresh fixture, body delivered before any signal. Required:
`200`, `blocking_admitted=1`, and the decoded `LeaderProposalRecord` match
described above.

Negative controls the parent will run against this same oracle, each
restoring exact bytes afterward:

- **N1**: remove only `apps/operator/src/native_operations.rs`'s
  `stop_executor.close()` call that currently runs inside the `shutdown`
  future, before `run(shutdown, ...)`. Expected: the no-write assertion
  fails, because connection A's propose call now writes before the serve
  wrapper's own post-`run` fallback `executor.close()`.
- **N2**: change `apps/operator/src/sqlite_source_host.rs`'s ordered-economics
  `cancellation: Some(blocking_executor.stop_cancellation())` to
  `cancellation: None`. Expected: no write still holds (admission now fails
  inside `try_acquire()` instead), but the exact response/metrics assertions
  fail: `blocking-admission-closed` instead of
  `invocation-cancelled-before-storage`, and `blocking_closed=1` instead of
  `0`.
- Removing `ordered_economics.rs`'s late `build_context` guard is *expected*
  to leave this oracle passing, since this fixture never lands inside that
  specific late window through a real binary; that isolation remains the
  separate manual-router fixture noted below.

## Compatibility and limits

No canonical bytes, protocol identifier, signature payload, persisted
layout, dependency, production code, or runtime knob changes. No test-only
production hook. The fixture spawns only the existing compiled
`sqlite_source_host` binary as this suite already does elsewhere.

This is wiring evidence only. It does not isolate the real-binary late
pre-storage window (that remains
`sqlite_source_host_stop_cancellation_oracle.rs`'s manual-router,
saturated-blocking-pool fixture), does not qualify FastVote, successor,
historical-read or TLS paths, and does not close D05/M5 or any whole-gate
requirement. Final status and remaining criteria stay in `TODO.md`.
