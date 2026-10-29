# Native frontier-maintenance SIGTERM wiring oracle

See [DR-0256](decisions/0256-native-frontier-sigterm-wiring-oracle.md) for
the accepted decision record. This page is the implementation-facing
summary; `TODO.md` owns current status. It extends
[the existing native source-host SIGTERM wiring oracle](native-source-host-sigterm-wiring-oracle.md)
([DR-0254](decisions/0254-native-source-host-sigterm-wiring-oracle.md)) to a
second, separately wired route in the same production host.

## What this is

A deterministic, real-compiled-binary, real-`SIGTERM` oracle for the
production `sqlite_source_host` host's certified FastVote router. A real
signal closes the `NativeBlockingExecutor` shared by that router's own
`StructuredDurableNativeComponents::with_cancellation` wiring
(`apps/operator/src/sqlite_source_host.rs:268-281`), and a selected
frontier-maintenance `advance` request whose HTTP exchange was already in
flight observes that same cancellation and is refused before any durable
business write. This wiring path is genuinely separate from the one DR-0254
already isolates on the host's ordered-economics `propose` route: the two
routes read separately wired cancellation references to the same executor
stop state, through two different constructor call sites.

## What it is not

- **Not** a real-binary late pre-storage window isolation. As with DR-0254,
  the synchronous window between `publication::admitted`'s job recheck and
  the frontier handler's own storage work has no externally controlled seam
  here.
- **Not** a paid FastVote prepare/apply/publication-retain call or a Seal.
  `FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH` carries no signed intent, candidate
  or certificate; it only advances a bounded, already-committed, local
  frontier-maintenance step after a committed ordered Freeze. The existing
  file boundary (this file's own header comment) excluding paid FastVote
  calls and a real Seal through the compiled binary is unchanged by this
  addition.
- **Not** a successor, historical-read or TLS qualification. Only the
  certified FastVote router's `advance` route is exercised here, alongside
  DR-0254's own ordered-economics `propose` route.
- **Not** a D05/M5 closure. The remaining code and verification conditions in
  `TODO.md` stay open.

## Why chunked framing, not `Content-Length`

`advance_frontier` (`crates/native-http/src/fastvote.rs:166-261`) requires
only a supported `Content-Type` and an empty body
(`has_supported_content_type`/`has_unsupported_content_encoding` at
`:184-189`, then `body.is_empty()` at `:194-196`); it never inspects
`Content-Length`. Unlike DR-0254's propose oracle -- which withholds a
nonempty `Content-Length` body -- this route's only valid request body is
empty, so a `Content-Length: 0` request would already be complete the
instant its head is sent and could never be held open. The oracle instead
sends `Transfer-Encoding: chunked` with `Expect: 100-continue` and withholds
even the empty terminating `0\r\n\r\n` chunk. The decoded body stays empty
once the terminator finally arrives, satisfying `body.is_empty()` without
ever sending a nonempty payload. The `axum-core 0.5.6` `Bytes` extractor
(`extract/request_parts.rs`) collects `into_limited_body()`; the limiter in
`ext_traits/request.rs` maps the body using its extension limit and does
not inspect `Transfer-Encoding`. Thus the rebuilt zero-byte body remains
empty when extracted, even though the original chunked header is retained.

This still proves the same in-flight state DR-0254 established. Read
directly against the real source of the exact `Cargo.lock`-pinned
`hyper 1.11.0`: `proto/h1/role.rs` gives a `Transfer-Encoding: chunked`
request `DecodedLength::CHUNKED` and, combined with `Expect: 100-continue`,
the same `Wants::EXPECT`-driven `WANT_PENDING` body channel DR-0254's own
design document already cites for a `Content-Length`-bearing request. The
automatic `100 Continue` line is still buffered only once
`Incoming::poll_frame` has been called at least once, and the only caller
here remains `to_bytes(body, limit)` inside this crate's own
`dispatch_bounded_request`, itself reached only by a connection task that
already passed every per-connection shutdown check. Observing
`HTTP/1.1 100 Continue` on connection A is therefore the identical direct,
local evidence of already-dispatched, body-blocked state that DR-0254
established, independent of the body's framing.

The deterministic listener-drop barrier (idle connection C observing
EOF/reset, then exactly one fresh `ConnectionRefused`) is unchanged from
DR-0254: it proves the same executor-closed fact, from the same
`apps/operator/src/native_operations.rs::serve` shutdown future, for the one
shared process regardless of which route's connection is held open.

## Why validator index 3

`Fixture::freeze_and_complete`'s own finalize loop
(`apps/operator/tests/business_cut/fixture.rs:424-460`) only iterates the
first three stores (`.take(3)`), so only those three validators' frontier
state reaches `FrozenFrontierStep::Finalized`. The fourth validator's store
starts this test with no frontier cursor, entry or final record, and the
fixture's one retained publication is still available for it to advance
into exactly one new entry. This lets the positive half observe
`FrozenFrontierStep::Advanced { entry_count: 1 }` -- the route's own `204`
mapping -- rather than retrying against an already-finalized frontier.

## Record checks

These frame types are allocated in `crates/node-core/src/ordered_economics/frontier.rs`
(`FRONTIER_CURSOR_TYPE = 0x6459`, `FRONTIER_ENTRY_TYPE = 0x6452`,
`FRONTIER_FINAL_TYPE = 0x645A`); that module is crate-private, so the oracle
cites these already-allocated identifiers rather than importing or
re-deriving them, following the same pattern DR-0254 already uses for
`LeaderProposalRecord`'s `0x644B`.

| Frame | Before | After (positive half) |
|---|---|---|
| `0x6459` cursor, v2, fields `{1,2,3}` | absent | `decode_frozen_frontier_identity(f1).entry_count == 1`, `.closure_request_id == [0xCB; 32]`; `f2 == f3 == fixture.network.request_id` |
| `0x6452` entry, v1, fields `{1..4}` | absent | `f1 == [0xCB; 32]`, `f2 > 0`, `f3 == 1`, `decode_availability_identity(f4).request_id == fixture.network.request_id` |
| `0x645A` final | absent | still absent |

Exactly these two records are added, none removed, and no referenced blob
changes.

## Composition with existing evidence

This fixture composes with DR-0254's own oracle and the remaining evidence
its design document already lists: each claim stays attached to its own
route and boundary. Together they show the production host's SIGTERM wiring
reaches two separately composed routers through separately wired
references to the same cancellation state; neither isolates the real-binary late window or
qualifies every accepted handler family.
