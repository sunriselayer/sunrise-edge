# DR-0201: One envelope codec and acknowledgement binding owner

Date: 2026-10-06 (Asia/Singapore)

Status: Corrected independent Opus PLAN APPROVE, conditional on the explicit
invariants and caller ordering below, fixed pre-change vectors, flat error
mapping, HTTP classification coverage and complete required acceptance.
This is not implementation, source or security-audit approval.

## Context

The node-core root defines request/event/response/receipt envelope contracts
alongside execution and storage orchestration. Node-wire duplicates response
list decoding and carries the whole node-core error enum. Four Rust SDK families
repeat single-response acknowledgement checks. Their inner-ID tests are
unreachable because the HTTP decoder already rejects mismatched nested IDs.
Some local preparation and semantic-check ordering differs and must stay with
its owning caller. Generic submit checks only the outer request ID and returns the whole
HTTP result, including valid zero/multiple-response results. A new pure-contract
crate would currently
remove no Cargo edge because clients/wire still consume owning core verifiers
and other contracts. Moving those verifiers into foundations is not justified.

## Contract

- A node-core `envelope` owner defines `RequestId`, `NodeEventKind`, `NodeEvent`,
  `NodeResponseStatus`, `NodeResponse`, `NodeDedupRecord`, their canonical list
  codec and defining bounds. Existing node-core root paths remain reexports.
- A closed `EnvelopeError` describes only envelope construction/framing/bounds.
  Its conversion into `NodeCoreError` maps to existing flat variants, preserving
  the host classification vocabulary. No nested catch-all changes a 413/500
  into the native handler's default 400 invalid-event response.
- `NodeEvent::digest` and `validate_context` remain core-owned methods returning
  `NodeCoreError`, outside the pure envelope owner. Hashing and chain/protocol/
  epoch authority errors do not enter the framing error vocabulary.
- Node-wire owns HTTP frames and a bounded outer-result decoder. It binds the
  outer ID while retaining the generic submit whole-result return contract,
  without new response-cardinality, inner-ID or payload requirements.
- Its single-acknowledgement view checks exactly one response and payload
  presence after outer binding. The HTTP result constructor/decoder already
  enforces all nested IDs; add no redundant inner-ID error variant or new
  refusal. The full result stays available to publication's return path.
  Typed acknowledgement errors carry no execution or authorization capability.
- Paid submit, FastVote submit/apply, publication and local-instance SDK families
  use that single-acknowledgement primitive; generic submit uses the outer-only
  decoder. Each caller still decodes and
  verifies its owning outcome, transaction hash, request and status semantics.
  A syntactically bound response is not a verified successful operation.
- Wire/query envelope errors use the narrow envelope type instead of the
  entire core orchestration enum. Other real core verifier dependencies remain
  explicit; this slice does not claim complete SDK/core Cargo decoupling.
- Canonical size bounds have their defining core/consensus owner. Framing
  overhead and deployment resource budgets remain with their consumers.

## Preserved invariants and deliberate API changes

Keep all existing type IDs, versions, fields, integer/length framing and
canonical bytes. Keep list count/truncation/trailing checks, nonzero request
IDs, context-before-digest verification, exact retained receipt re-encoding
and receipt-first replay. The ordinary output and ordered-engine record layouts
are distinct; do not force the latter into this codec.

Preserve `NodeDedupRecord` validation order: item count, aggregate response
payload bound, then request binding. The shared encoder takes its owning
aggregate limit explicitly. HTTP encoding keeps only its existing canonical
frame bound, not a new core-state refusal that changes framing-error vocabulary
or precedence. The current canonical frame limit is also 32 MiB, so no test
or readiness claim assumes a valid HTTP frame larger than that limit.

Constructor count errors retain collection `responses`; decode checks count
with `dedup responses` before list parsing. Overflow retains `usize::MAX`,
then item/trailing parsing and constructor validation remain in their current
order. The envelope's response-only count/total validator does not call the
core-owned `NodeOutput::new`. Dedup and outbox encode use their explicit
`MAX_NODE_STATE_BYTES` limit and flat `StateTooLarge`; HTTP output encode keeps
its current lack of an aggregate state limit.

Changing unreleased envelope constructors' error type and narrow wire/SDK
error variants is explicit API work. Flatten conversion preserves native/DO
HTTP classification. Migrating `http_receipt_query_result` maps its envelope
error through `NodeCoreError::from` before native `QueryInvocationError::Node`
and DO `QueryDispatchError::Node`; neither host acquires a new catch-all arm.
SDK conversion may retain `ClientError::NodeCore` through the same flat mapping;
a new public SDK error variant is not required for this slice.

Nested-ID mismatch already fails as `ClientError::Contract(RequestMismatch)`
before typed payload parsing; preserve this, not an invented precedence change.
Publication must retain local expected-reference construction/encoding between
outer binding and the single-ack check: expose staged decoding/view operations
to do so. FastVote retains expected digest computation before HTTP decode.
Paid retains status before target validation; local execution retains result
validation before status. Remove only unreachable repeated inner-ID checks;
caller-specific semantic verifiers and their error order do not move into wire.

## Acceptance

Before migration, fix literal vectors for NodeEvent, NodeResponse,
NodeDedupRecord and HTTP result with zero/one/two responses against the existing
owner. Reuse existing vectors unchanged; never regenerate them after the move.
Retain count/bounds, malformed/truncated/trailing/noncanonical nested frames,
unknown kind/status and zero/mismatched ID negatives.

Test unchanged native and DO classification exhaustively for the migrated
error subset, including event and receipt-query conversion paths; preserve
valid near-bound HTTP-output encoding and the original oversized canonical
encoding refusal. Every single-ack SDK
family keeps authentic positive outcomes and outer/inner mismatch, zero/two
responses and missing-payload refusals with its intended typed errors. Generic
submit preserves valid zero/multiple-response results and refuses only its
existing malformed framing and outer-ID mismatch cases.

Migrate real callers, delete duplicated list parsing and binding mechanisms,
review the actual full source, and pass the complete storage-neutral gate plus
required CI before normal merge. No new crate, universal typed-handler trait,
new authority, protocol version, provider certification or deployed service.
