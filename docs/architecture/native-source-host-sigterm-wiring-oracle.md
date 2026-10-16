# Native source-host SIGTERM wiring oracle

See [DR-0254](decisions/0254-native-source-host-sigterm-wiring-oracle.md) for
the accepted decision record. This page is the implementation-facing summary;
`TODO.md` owns current status.

## What this is

A deterministic, real-compiled-binary, real-`SIGTERM` oracle for the
production `sqlite_source_host` host (used by every acceptance in
`apps/operator/tests/sqlite_source_host_process.rs`). It proves that a real
`SIGTERM` closes the exact `NativeBlockingExecutor` the host's constructor
injects into both the certified FastVote router and the opt-in ordered-
economics router (`apps/operator/src/sqlite_source_host.rs`), and that the
ordered-economics `propose` route's own `admitted()`/`build_context()`
cancellation check (`crates/native-http/src/publication.rs`,
`crates/native-http/src/ordered_economics.rs`) honors that same close before
any durable write.

## What it is not

- **Not** a real-binary late pre-storage window isolation. The actual gap
  between admission and `build_context`'s guard (between
  `crates/native-http/src/publication.rs`'s `admitted()` recheck and
  `crates/native-http/src/ordered_economics.rs`'s `build_context()`) is a
  handful of pure, synchronous, in-memory steps with no externally
  controllable seam; this oracle cannot and does not land a stop inside that
  specific window through a real compiled process. That isolation remains
  the dedicated manual-router fixture
  (`apps/operator/tests/sqlite_source_host_stop_cancellation_oracle.rs`),
  which composes the same public router/executor/store types directly and
  saturates a one-thread blocking pool to make "admitted but still queued"
  deterministic. The two fixtures are complementary, not duplicates: this one
  proves the real host wires the real signal to the real executor; the other
  proves the late guard inside that wiring.
- **Not** a FastVote, successor, historical-read or TLS qualification. Only
  the ordered-economics `propose` route is exercised.
- **Not** a D05/M5 closure. `TODO.md`'s open D05/M5 items (capacity policy,
  monitoring/incident wiring, production PKI, and the remaining qualification
  gates) are unaffected by this fixture.

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
this workspace's `Cargo.lock`-pinned `hyper 1.11.0`
(checksum `d22053281f852e11534f5198498373cbb59295120a20771d90f7ed1897490a72`):

- `proto/h1/conn.rs:187-192` (`can_read_body`): true for both
  `Reading::Body` and `Reading::Continue`.
- `proto/h1/conn.rs:409-415` (`poll_read_body`, `Reading::Continue` arm):
  buffers `b"HTTP/1.1 100 Continue\r\n\r\n"` into the connection's own write
  buffer the first time this arm runs, then recurses into `Reading::Body`.
- `proto/h1/dispatch.rs:216-290` (`Dispatcher::poll_read`): only reaches
  `poll_read_body` through its `body_tx` branch, gated by `can_read_body()`.
- `proto/h1/dispatch.rs:166-214` (`Dispatcher::poll_loop`): on every single
  poll of the connection, always runs `poll_read`, then `poll_write` (which
  is what first polls this crate's own service future -- here
  `dispatch_bounded_request`), then `poll_flush`, in that fixed order.

So the buffered Continue line cannot reach the socket (`poll_flush`) before
`dispatch_bounded_request` (`crates/native-http/src/lib.rs:1597-1608`,
specifically `to_bytes(body, limit)`) has already been polled at least once
on that same connection task -- and that task only runs after already
passing every one of this crate's own per-connection shutdown checks
(`crates/native-http/src/lib.rs:1481`, `:1486`, `:1550`). Observing
`HTTP/1.1 100 Continue` on connection A is therefore direct, local evidence
that A's exchange is already dispatched and specifically blocked on its own
withheld body, not on some unrelated early refusal.

This exact `hyper 1.11.0` source is not present under
`BASE/cargo-home/registry/src` (`BASE` =
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`); that
tree holds only this repository's own prior offline-build inputs (`age`,
`cookie-factory`, and similar), confirmed absent by directory listing. The
citations above are against the same `Cargo.lock`-pinned `hyper` version's
real source as fetched into the ordinary local cargo registry cache. This
substitution is recorded here rather than silently assumed.

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

This fixture is a third, narrower leg alongside:

- the manual-router late-guard oracle
  (`sqlite_source_host_stop_cancellation_oracle.rs`), which isolates
  `build_context`'s own cooperative check with a saturated blocking pool; and
- the existing successor/historical late-stop boundaries (DR-0250, DR-0251),
  which recheck their own executors at their own later resolution points.

Together they claim: the real compiled host wires a real `SIGTERM` to the
real `NativeBlockingExecutor` (this fixture), and every handler that shares
that executor honors its close before its own first storage call (the
others). No single fixture claims the whole chain end to end inside one real
process.
