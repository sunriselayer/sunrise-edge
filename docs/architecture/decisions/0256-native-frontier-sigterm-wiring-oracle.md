# DR-0256: Native frontier-maintenance SIGTERM wiring oracle

Date: 2026-10-16

Status: Accepted component design. Qualification and remaining D05/M5
criteria belong in [TODO](../../../TODO.md).

## Decision

Add one additional deterministic real-factory, real-compiled-process,
real-`SIGTERM` oracle to the existing exclusively-owned
`apps/operator/tests/sqlite_source_host_process.rs`, reusing the unchanged
`Fixture`, `ChildGuard`, `start_leader_host`, `read_until`,
`wait_for_eof_or_reset`, `read_http_response`, `send_signal` and
`business_records` helpers [DR-0254](0254-native-source-host-sigterm-wiring-oracle.md)
already added, with no new shared fixture method, sender or hook and every
existing case/helper/assertion/bound left unchanged.

DR-0254's oracle isolates the production `sqlite_source_host` constructor's
ordered-economics wiring: `apps/operator/src/sqlite_source_host.rs`'s
`OrderedEconomicsState.cancellation: Some(blocking_executor.stop_cancellation())`
field, read by the ordered-economics `propose` route. This oracle isolates a
genuinely separate wiring path in the same constructor: the certified
FastVote router's own `components: StructuredDurableNativeComponents::with_cancellation(
..., blocking_executor.stop_cancellation())` (`sqlite_source_host.rs:268-281`),
read by `crates/native-http/src/fastvote.rs`'s `advance_frontier` route
through `state.components.is_cancelled()` before calling the shared
`crates/native-http/src/publication.rs::admitted` helper. The two paths
share the one `blocking_executor`, its stop state and the process's
listener/accept loop. Two separately wired references reach the two
routers composed by the same constructor and served over the same real
`SIGTERM`/listener-drop barrier DR-0254 already established.

`FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH` (`/v1/fastvote/frontier/advance`,
`crates/node-wire/src/fastvote_frontier.rs`) requires only a supported
`Content-Type` and an empty body (`crates/native-http/src/fastvote.rs:184-196`);
it never checks `Content-Length`. The oracle therefore withholds the body by
sending `Transfer-Encoding: chunked` with `Expect: 100-continue` and holding
back even the empty terminating `0\r\n\r\n` chunk, instead of a nonempty
`Content-Length` body as DR-0254's propose oracle uses. This is the only way
to keep this specific route's own request in flight without ever sending a
nonempty payload. The real pinned `hyper 1.11.0` source already cited by
[the existing design document](../native-source-host-sigterm-wiring-oracle.md)
establishes that the automatic `100 Continue` gate is the body's own "want"
channel, not the presence or shape of `Content-Length`; a chunked body with
an `Expect`-bearing head reaches the identical `WANT_PENDING` state before
`to_bytes` has polled it at least once, so observing `100 Continue` is the
same local, direct evidence of in-flight dispatch DR-0254 already
established, independent of framing.

A separate, independent, fresh fixture in the same test sends the identical
empty chunked body's zero-length terminator before any signal, requiring an
ordinary `204` with an empty body (the route's own mapping for
`FrozenFrontierStep::Advanced`, `crates/native-http/src/fastvote.rs:238`),
`blocking_admitted=1`, and a confirmed exact two-record durable delta:
one new frontier cursor record (`crates/node-core/src/ordered_economics/frontier.rs`'s
own already-allocated `FRONTIER_CURSOR_TYPE = 0x6459`, version 2) and one new
frontier entry record (`FRONTIER_ENTRY_TYPE = 0x6452`, version 1), decoded
through only public `canonical-encoding`/`consensus` APIs, never a
`FRONTIER_FINAL_TYPE = 0x645A` record. Validator index 3 is used because
`Fixture::freeze_and_complete`'s own `.take(3)` finalize loop only finalizes
the frontier for the first three stores, leaving the fourth genuinely fresh
with no cursor, entry or final record and exactly one retained publication
still available to advance into exactly one new entry.

## Validation contract

Exact test:
`compiled_sqlite_source_host_sigterm_cancels_withheld_frontier_advance_not_a_delivered_one`
in `apps/operator/tests/sqlite_source_host_process.rs`.

Negative half: real compiled host, real SIGTERM while connection A's empty
chunked body's terminator is withheld. Required, in this order: SQLite
business records and referenced blobs byte-for-byte unchanged, including no
frontier cursor/entry/final record; connection A's response is exactly `503
invocation-cancelled-before-storage`; the host's one `stderr`
termination-summary line reports `stop=sigterm blocking_admitted=0
blocking_closed=0`.

Positive half: a fresh fixture, zero-length chunk terminator delivered
before any signal. Required: `204` with an empty body, `blocking_admitted=1`,
and exactly the two decoded records described above added with none removed
and no referenced blob changed.

Negative controls the parent will run against this same oracle, each
restoring exact bytes afterward:

- **N1**: remove only `apps/operator/src/native_operations.rs`'s
  `stop_executor.close()` call inside the `shutdown` future (the same
  removal DR-0254's own N1 names). Expected: the no-write assertion fails,
  because connection A's frontier-advance call now writes before the serve
  wrapper's own post-`run` fallback `executor.close()`.
- **N2**: change `apps/operator/src/sqlite_source_host.rs`'s
  `StructuredDurableNativeComponents::with_cancellation(..., blocking_executor.stop_cancellation())`
  to `StructuredDurableNativeComponents::new(...)` (no cancellation wired).
  Expected: no write still holds (admission now fails inside
  `try_acquire()`/the blocking-pool close instead), but the exact
  response-body assertion fails first: `blocking-admission-closed`
  instead of `invocation-cancelled-before-storage`, after the record/blob
  checks pass. The source predicts `blocking_closed=1`, but the test panics
  before reaching its metrics assertions; this is not a dynamic N2 metric
  observation. `OrderedEconomicsState.cancellation` and DR-0254's own oracle stay
  untouched by this change: their separate reference to the same executor
  stop state remains wired.

The chunked-specific proof also uses the pinned `hyper 1.11.0`
`proto/h1/role.rs` and `proto/h1/decode.rs`: `role.rs` gives a chunked
request `DecodedLength::CHUNKED` with `expect_continue`, so `conn.rs`
does not take its zero-length Expect shortcut; `decode.rs` ends the body
empty on the terminating zero chunk. These steps extend the original DR-0254 want-channel proof; they are
not claims that DR-0254 already cited those additional parser files.

## Compatibility and limits

No canonical bytes, protocol identifier, signature payload, persisted
layout, dependency, production code, or runtime knob changes. No test-only
production hook. The fixture spawns only the existing compiled
`sqlite_source_host` binary this suite already spawns elsewhere.

This is wiring evidence only, for one additional route. It does not isolate
a real-binary late pre-storage window, a paid FastVote prepare/apply/
publication call, a Seal, a successor, historical-read or TLS path, or any
whole D05/M5 gate requirement. Final status and remaining criteria stay in
`TODO.md`.
