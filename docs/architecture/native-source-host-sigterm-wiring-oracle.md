# Native source-host SIGTERM wiring oracle

See [DR-0254](decisions/0254-native-source-host-sigterm-wiring-oracle.md) for
the accepted decision record. This page is the implementation-facing summary;
`TODO.md` owns current status.

## What this is

A deterministic, real-compiled-binary, real-`SIGTERM` oracle for the
production `sqlite_source_host` host. It exercises the constructor's ordered-
economics router: a real signal closes its `NativeBlockingExecutor`, and a
request whose HTTP exchange was already in flight observes the same
cancellation and is refused before any durable business write. The host also
composes a certified FastVote router; this oracle does not exercise that
router's signal wiring.

## What it is not

- **Not** a real-binary late pre-storage window isolation. The synchronous
  window between `publication::admitted`'s job recheck and
  `ordered_economics::build_context` has no externally controlled seam here.
  The late check is covered separately by
  `crates/native-http/src/tests/ordered_history_http.rs`'s
  `status_cancellation_during_build_context_stops_before_storage_after_identity_and_clock`
  and its companion controls. The manual SQLite/HTTP fixture
  `sqlite_source_host_stop_cancellation_oracle.rs` covers another boundary:
  queued work refused by the dispatcher's job recheck, plus a fresh post-stop
  request that observes injected router cancellation. It does not isolate
  `build_context` or the production factory/signal owner.
- **Not** a FastVote, successor, historical-read or TLS qualification. Only
  the ordered-economics `propose` route is exercised.
- **Not** a D05/M5 closure. The remaining code and verification conditions in
  `TODO.md` stay open. Applying production PKI, topology and workload/SLO
  values belongs to D04/D07.

## The deterministic barrier

The oracle needs to know, from outside the process, the exact moment after
which the host's `NativeBlockingExecutor` is guaranteed already closed,
without any sleep or fixed delay standing in for that fact.

`apps/operator/src/native_operations.rs`'s `serve` builds one `shutdown`
future:

```rust
let shutdown: StopFuture = Box::pin(async move {
    let result = stop.wait(shutdown_observations).await;
    stop_executor.close();
    let _sent = sender.send(result);
});
```

That exact future is the one `crates/native-http/src/lib.rs`'s
`serve_with_stream_upgrade_observed` polls as its own `shutdown` parameter.
Its accept loop only breaks once that future resolves (`_ = &mut shutdown =>
break`), and only after breaking does it `drop(listener)` and
`shutdown_sender.send(true)` -- the only two things that can make an idle,
already-open connection observe EOF/reset and make a brand-new connect
observe `ConnectionRefused`. Because `stop_executor.close()` runs strictly
before the `shutdown` future resolves, observing both of those effects from
outside the process proves the executor was already closed.

Connection C's own 5-second header-read timeout is a third, unrelated way it
could see EOF/reset while the listener is still open. That case still fails
closed: the fresh connect immediately afterward would then succeed instead
of being refused, and the oracle requires exactly that refusal.

The oracle therefore:

1. Opens connection A, sends only the `POST /v1/ordered-economics/propose`
   request head (a valid, nonempty, canonically encoded empty
   `OrderedProposeRequest`) with `Expect: 100-continue`, and withholds the
   body.
2. Opens an otherwise-untouched idle connection C.
3. Sends a real `SIGTERM` to the owned host PID.
4. Waits for connection C to observe EOF/reset, then performs exactly one
   fresh connect and requires `ConnectionRefused`. This is the barrier.
5. Only then releases connection A's body.
6. Reaps the host, then checks -- in this order -- that the SQLite business
   records and referenced blobs are byte-for-byte unchanged, that A's
   response is exactly `503 invocation-cancelled-before-storage`, and that
   the host's one `stderr` termination-summary line reports
   `stop=sigterm` with `blocking_admitted=0 blocking_closed=0`.

`blocking_admitted`/`blocking_closed` are both `0` because this crate's
`dispatch_bounded_request` (`crates/native-http/src/lib.rs`) fully collects a
request's body (`to_bytes(body, limit)`) *before* dispatching into the axum
router at all; by the time A's handler runs, `state.is_cancelled()` is
already `true`, so `publication::admitted()`'s very first check short-
circuits before ever calling `try_acquire()`.

## Step 1's own local proof: why `Expect: 100-continue` proves A is in flight

The oracle must not rely on remembered hyper behavior. Read directly, against
the real source of the exact `Cargo.lock`-pinned `hyper 1.11.0`
(checksum `d22053281f852e11534f5198498373cbb59295120a20771d90f7ed1897490a72`,
`Cargo.lock:1154-1157`). The gate is the body's own "want" channel, not
merely the connection's read/write/flush poll order:

- `proto/h1/dispatch.rs:304-311` (`poll_read_head`): creates this request's
  body channel with `wanter = wants.contains(Wants::EXPECT)`, true here.
- `body/incoming.rs:114-122` (`Incoming::new_channel`): when `wanter` is
  true, the channel starts at `WANT_PENDING`, not `WANT_READY`.
- `proto/h1/dispatch.rs:222-229` (`Dispatcher::poll_read`'s `body_tx`
  branch): calls `Sender::poll_ready`
  (`body/incoming.rs:362-368`), which calls `poll_want`
  (`body/incoming.rs:370-377`): `Poll::Pending` while `WANT_PENDING`. This
  parks before `proto/h1/conn.rs:409-415`'s `poll_read_body`
  (`Reading::Continue` arm, the code that actually buffers
  `b"HTTP/1.1 100 Continue\r\n\r\n"`) is ever reached.
- `body/incoming.rs:193-234` (`Incoming::poll_frame`): sends `WANT_READY`
  (`body/incoming.rs:220`) on every call, unconditionally, before touching
  any data.

So the buffered Continue line cannot reach the socket before
`Incoming::poll_frame` has already been called at least once -- and the only
caller of that method here is `to_bytes(body, limit)` inside this crate's own
`dispatch_bounded_request` (`crates/native-http/src/lib.rs:1604-1608`), which
itself only runs inside a connection task that already passed every one of
this crate's own per-connection shutdown checks
(`crates/native-http/src/lib.rs:1481`, `:1486`, `:1550`). Observing
`HTTP/1.1 100 Continue` on connection A is therefore direct, local evidence
that A's exchange is already dispatched and specifically blocked on its own
withheld body, not on some unrelated early refusal.

## Positive sensitivity control

A second, independent, fresh fixture (same genesis/policy/runtime
construction) in the same test sends the identical empty `propose` request's
body *before* any signal. It requires an ordinary `200` response,
`blocking_admitted=1`, and then confirms `capture_source_business_snapshot`
(`apps/operator/src/business_snapshot.rs`) actually observes the new durable
record: it decodes the added record through only public
`canonical-encoding`/`consensus` APIs, checks its frame type against
`node_core::ordered_economics::identity::ORDERED_LEADER_RECORD_TYPE`'s own
already-allocated `0x644B` (that module is crate-private, so this cites the
existing identifier rather than importing or re-deriving it), and checks that
the decoded `view`/`leader`/`ConsensusProposal` and recomputed proposal digest
match the proposal actually returned over HTTP. This rules out a bare
writer-fence metadata bump satisfying the "snapshot changed" assertion
without the specific `LeaderProposalRecord` actually being present.

## Composition with existing evidence

This ordered-router wiring fixture composes with distinct, bounded evidence:

- Native HTTP `ordered_history_http.rs`'s
  `status_cancellation_during_build_context_stops_before_storage_after_identity_and_clock`
  and companions exercise the late context check after identity/clock work.
- `sqlite_source_host_stop_cancellation_oracle.rs` manually composes real
  SQLite/HTTP components to cover queued dispatcher refusal and a fresh
  post-stop router refusal. It cannot detect factory or OS-signal wiring
  changes and does not isolate the late context check.
- DR-0250/DR-0251 cover the successor and historical executors' own later
  resolution points at component level.

Each claim remains attached to its own route and boundary. Together these
show selected runtime cancellation paths and the actual ordered host's
signal wiring; no single fixture observes the real-binary late window or
qualifies every accepted handler family.
