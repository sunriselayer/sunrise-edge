# DR-0226: Exact certified-publication collector admission

Date: 2026-10-11 Asia/Singapore

Status: Accepted narrow implementation design after source-bound design review.
This is not compilation, executed-test acceptance, deployment or public readiness.

## Context

The original and activated-successor native routers admit publication-retain
and drain-import bundles up to `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES`,
the existing 32 MiB canonical frame ceiling. The native server collects the
body before invoking those routers. Its fallback is
`MAX_HTTP_EVENT_BODY_BYTES = node_core::MAX_NODE_PAYLOAD_BYTES + 512`, so a
bundle above that smaller limit is rejected before the owning handler sees it.
Existing local-publication and local-execution collector flags do not select
either certified bundle route. This is a transport compatibility mismatch,
not evidence that a particular large bundle is semantically acceptable.

## Decision

Add a private default-false `certified_publication` serve-policy flag and the
explicit `with_certified_publication(bool)` builder. One private body-limit
selector consumes the full serve policy, request method and raw URI path.
Only an opted-in POST receives the existing bundle ceiling for either:

- The exact `node_wire::FASTVOTE_PUBLICATION_RETAIN_PATH`.
- The concrete `node_wire::FASTVOTE_DRAIN_IMPORT_PATH` prefix followed by
  exactly 64 lowercase ASCII hex characters, checked with the existing
  `decode_hex64_selector` parser.

Use `Uri::path`, so query parameters do not change path selection. Do not trim,
normalize, percent-decode, redirect or broaden prefix matching. An extra slash,
segment, malformed or uppercase selector, unrelated path or other method keeps
its existing collector limit. Preserve both local-route flags and the fallback
constant; do not introduce a configurable general body-size override.

Explicitly opt in the three live compositions that already mount both routes:
the original PostgreSQL FastVote host's existing plaintext serve call, original
SQLite serving and activated-successor serving. The latter two use the same
policy in their existing plaintext and direct-TLS branches. Read-only successor
history, devnet and implicit/default serve callers remain default-off. There
is no inbound PostgreSQL TLS branch to add.

## Unchanged boundaries

Collector admission mounts no route and grants no caller, signer, quorum,
epoch, writer, retention or import authority. Disabled routes and direct-route
refusals retain their existing composition. Route extractors and canonical
decoders still enforce their own ceilings and grammar. Retention/import checks,
durable state, fees, receipts, nonces, canonical bytes and commit ambiguity do
not change. Historical requests and other legitimate route families fit their
existing smaller limits and do not need the bundle allowance.

Keep all connection/header/body/response deadlines, keep-alive refusal,
connection and blocking permits, request-read completion, shutdown/cancellation
and started-job ownership from DR-0100, DR-0219 and DR-0222. Do not raise the
global default request cap, output cap or a host-wide resource budget. Add no
package dependency or protocol type.

## Regression contract and limits

Add source controls in `native-http::tests::certified_publication_ingress`:

- Default/new/explicit-off policies remain off; toggling the new flag changes
  neither transport settings nor the independent local-route flags.
- An exact method/raw-path matrix covers retain, canonical drain selectors,
  query exclusion, trailing/extra slashes, malformed/uppercase/percent-encoded
  selectors, lookalike paths, sibling/history routes and unrelated methods.
- Actual native TCP requests use a fixed-size chunk buffer and one bounded
  exchange lifetime. A test-only probe explicitly overrides Axum's default
  Bytes extractor cap to the bundle ceiling; it records count and exact length,
  not a copied large body. At the default and bundle boundaries, require full
  probe receipt on admitted requests and HTTP 413 plus zero handler and native
  dispatch counts on rejection. Observe the existing collector counters.
- Keep existing phase, timeout, permit, TLS, blocking drain and authority/refusal
  controls unchanged. Probe dispatch is not authenticated business acceptance,
  durable retention, import success or measured capacity. A genuine large
  owning fixture would be required for those stronger semantic claims.

Source controls and executed validation are separate. Adding these controls
establishes no formatting, compilation or runtime validation pass, and grants
no TODO-group completion or release approval.
