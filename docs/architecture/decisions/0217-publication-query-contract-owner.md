# DR-0217: one publication-query codec and narrow error owner

Accepted design, 2026-10-07 (Asia/Singapore).

## Decision and current mismatch

Move DR-0126's pure provenance-query data, bound, framing and codec error to
the existing `execution::publication` owner beside both embedded payload
families. Node core retains verified-record conversion, durable loading,
authentication, historical context selection, admission and commit authority.
Actual SDK, native original/successor, Rust DO and operator fixture codec
consumers use the defining execution owner.

At `70702fbe`, the codec in `node_core::publication` performs no storage lookup
yet returns `PublicationAdmissionError`. That family additionally describes
durable ambiguity/conflict, missing dependencies, policy/installed-state
failure and historical authority. The SDK implicitly converts that whole
family to `ClientError::PublicationQueryResult`, even though only four
categories can originate in this transport decoder. A concrete narrow codec
error removes that cross-responsibility conversion. It is not a discovered
authentication bypass or a reason to move core verification into the SDK.

This is one useful R1 ownership slice, not a new foundational crate, complete
SDK/core decoupling, measured build improvement or a new functional gate. The
SDK and `node-wire` retain other genuine core imports and Cargo dependencies.
No Cargo dependency, lockfile, public route or CI lane changes are needed.

## Defining owner and explicit API change

One private `execution::publication::query_result` module defines and the
existing publication surface exports:

- `PublicationQueryResult::{Legacy(PublicationSubmission), Paid(SignedPaidIntent)}`;
- `PUBLICATION_QUERY_RESULT_FRAME_TYPE` and `MAX_PUBLICATION_QUERY_RESULT_BYTES`;
- `encode_publication_query_result` and `decode_publication_query_result`; and
- `PublicationQueryResultError::{Publication(PublicationError),
  Paid(PaidExecutionError), Limit, CorruptRecord}`.

Delete the old core definitions. Existing core data/codec/bound paths may be
direct re-exports of this sole owner; they contain no decoder, validator or
error adapter. Keep `From<VerifiedPublicationRecord>` and the verified query
in core. Decoded/constructed transport data cannot represent verified durable
publication merely because it uses the same enum as a trusted query result.

The SDK's current result and codec export paths remain usable by actual CLI
and preparation callers. Its existing `PublicationQueryResult` error variant
holds the new narrow error; replace the blanket conversion of core admission
errors with the narrow codec conversion. Real durable admission errors retain
their own core owner and host mapping.

**The concrete Rust error type returned by the codecs and held in this SDK
variant intentionally changes.** This accepted unreleased API correction does
not promise exact Rust source compatibility. Do not preserve the broad error
with conversion adapters or duplicate implementations. Preserve existing
reachable error categories, display text, priority and `ClientError::source()`
behavior; in particular, do not incidentally add a deeper source chain to the
inner codec error. External downstream callers have not been surveyed.

## Unchanged contract

1. Preserve frame `0x6418/v1`, field 1 `u16` provenance Legacy=1/Paid=2,
   Legacy's complete `0x6308` frame in field 2, Paid's complete `0x6413` frame
   in field 3, each branch's exact allowed fields and original signed bytes.
   The bound remains `MAX_SIGNED_PAID_INTENT_BYTES + 256`.
2. Refuse outer oversize before frame decoding/allocation, then canonical
   framing, type, version, discriminant, branch fields, required payload,
   nested decoding and canonical re-encoding equality in the original order.
   Preserve encoding order and final bound. Framing failures remain wrapped
   as `PublicationError::Encoding/Decoding`; nested errors retain their
   original Publication/Paid categories.
3. Do not strengthen structural decoding into paid-application admission.
   A well-formed non-Publish paid frame remains structurally decodable and
   is refused by the SDK's separate application-kind boundary. Raw data is
   neither authenticated code nor a receipt, dependency closure or resolver.
4. Keep independently expected active-context checking before publication
   GET, and existing Legacy selector/authentication and Paid application-kind,
   selector, expected-semantics and authentication order. Signed preparation,
   fee quoting, reservations, signatures and POST ordering do not change.
5. Core keeps verified loading, historical resolver budgets, receipt/nonce-first
   replay, conflict/ambiguity reconciliation, original/successor authority,
   atomic effects and writer fences. `local_publication_profile_semantics`
   remains core-owned with its caller's explicit error mapping.
6. Native original/successor and Rust DO still query the actual verified core
   loader before encoding. Missing publication, durable query failure and
   encoding failure retain distinct current status/tokens, media types, cache
   policy and bounds. A codec import cannot enable a route or trust source.

## Real migration and verification

Migrate SDK query/result exports, actual native original and successor query
encoders, the Rust DO encoder and operator fixture producer to execution.
Migrate direct type/codec/bound imports in existing SDK/core/host/operator/CLI
tests, including optional-PG annotations, without changing backend logic or
recurrence. Update the code map when the definitions actually move. Use
explicit Rust collection/result types and ordinary functions, not a generic
dispatcher or compatibility facade.

Add one pure execution-owned integration target with no core fixture or
production decoder copy. Pair independent low-level framed negatives with
valid Legacy and Paid controls: type/version, missing/unknown discriminant,
both/foreign branch fields, missing payload, malformed nested payload,
truncation and trailing bytes. Assert exact narrow categories and unchanged
display/source behavior. Dual-invalid inputs must prove oversize-first,
branch-fields-before-nested-decoding and unknown-provenance refusal priority.
Preserve structural non-Publish Paid acceptance plus its actual SDK refusal.

Retain core's independent pre-move literal vectors, without regenerating their
expectations from the migrated implementation: Legacy length 1005, SHA-256
`fdc7d2881fbe073d892f9eb7c3e9eb59d37af3ffbf7337b61689fbea89f56078`;
Paid length 982, SHA-256
`5b517db5b6cb9d313b4f1c09c1610602588a7bee08dcf48047dfc4524c8738b4`.
Keep genuine stored paid Publish and depth-two dependency, whole SDK
publication/local/paid targets, host historical/relay, shared-deadline/pre-sign
and compiled CLI publication/paid workflow coverage. Do not replace real-store
tests with mocks or delete expensive recurrence/fence/fault cases.

Final exact-head static review must verify one definition per data/codec/bound,
zero SDK admission-error decoding coupling, unchanged host maps/authority order
and no Cargo/lockfile/recipe expansion. Run proportionate focused checks,
literal npm-ci, the complete required repository gate and all seven required
CI owners plus `check`, under explicit parent compiler ownership. Focused,
compiled-only and ancestor checks are not complete final-source acceptance.

## Limits

This type/codec change does not implement custody, production TLS/revocation,
selected-provider faults, off-host recovery, native A/B evidence, an independent
security audit or M1–M8 completion. PostgreSQL implementation/dependencies are
outside scope; optional annotations are not a PG profile pass. Selected full
PG qualification stays separate under DR-0172. Status belongs in TODO, not
README or this contract. No network startup, cloud write, deployment or paid
resource authority is granted.
