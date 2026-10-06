# DR-0201: One envelope codec and acknowledgement binding owner

Date: 2026-10-06 (Asia/Singapore)

Status: Initial independent Opus PLAN APPROVE was conditional on fixed
pre-change vectors, flat error mapping, HTTP classification coverage and
complete required acceptance. The corrected generic-submit consumer scope
below requires tech-lead reconfirmation before migration. This is not
implementation, source or security-audit approval.

## Context

The node-core root defines request/event/response/receipt envelope contracts
alongside execution and storage orchestration. Node-wire duplicates response
list decoding and carries the whole node-core error enum. Four Rust SDK families
repeat single-response acknowledgement checks; their check order already
differs. Generic submit checks only the outer request ID and returns the whole
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
- Node-wire owns HTTP frames and a bounded outer-result decoder. It binds the
  outer ID while retaining the generic submit whole-result return contract,
  without new response-cardinality, inner-ID or payload requirements.
- Its single-acknowledgement decoder additionally binds exactly one response,
  the inner ID and payload presence. Typed
  acknowledgement errors carry no execution or authorization capability.
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
aggregate limit explicitly; adding the core state limit to previously larger
valid HTTP output would be a behavior change, not cleanup.

Changing unreleased envelope constructors' error type and narrow wire/SDK
error variants is explicit API work. Flatten conversion preserves native/DO
HTTP classification. SDK envelope binding runs before typed payload decode,
so the formerly different paid/FastVote inner-ID-versus-invalid-payload error
precedence becomes consistent. Record and test this fail-closed difference;
do not pretend it is a mechanical move.

## Acceptance

Before migration, fix literal vectors for NodeEvent, NodeResponse,
NodeDedupRecord and HTTP result with zero/one/two responses against the existing
owner. Reuse existing vectors unchanged; never regenerate them after the move.
Retain count/bounds, malformed/truncated/trailing/noncanonical nested frames,
unknown kind/status and zero/mismatched ID negatives.

Test unchanged native `(status, code)` mappings exhaustively for the migrated
error subset; preserve valid large HTTP-output encoding. Every single-ack SDK
family keeps authentic positive outcomes and outer/inner mismatch, zero/two
responses and missing-payload refusals with its intended typed errors. Generic
submit preserves valid zero/multiple-response results and refuses only its
existing malformed framing and outer-ID mismatch cases.

Migrate real callers, delete duplicated list parsing and binding mechanisms,
review the actual full source, and pass the complete storage-neutral gate plus
required CI before normal merge. No new crate, universal typed-handler trait,
new authority, protocol version, provider certification or deployed service.
