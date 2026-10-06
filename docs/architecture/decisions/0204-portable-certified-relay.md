# DR-0204: A closed portable certified relay

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed. Independent design review precedes implementation. This is
transport qualification, not deployment, requester authority or launch approval.

## Context

The shared Web ingress, used by Cloudflare Workers, Deno and Vercel, forwards
only `POST /v1/events`. The configured HTTPS/Bearer fetcher additionally pins
exactly that one upstream path. The supplied certified native router rejects
that direct mutation route and exposes dedicated prepare, certificate apply,
retention/publication, frozen-frontier/drain and bounded query routes instead.
Merely adding a path prefix passthrough would make unrelated future routes
reachable without an explicit capability decision.

## Decision proposed

Keep the existing event-only profile and its public defaults unchanged. Add an
explicit `certified-fastvote` profile, selected by trusted composition, never a
request header/query/body. One shared, private closed route owner supplies the
exact method, request/response byte ceilings and successful status/media for that
profile. Both ingress and HTTPS forwarding use this same owner; neither accepts
a caller-selected upstream origin, wildcard route or additional authority.

The profile contains these actual native routes, and no others:

`canonical` below means `canonical_encoding::MAX_CANONICAL_FRAME_BYTES`.
Response limits describe the complete HTTP body, never just a nested payload.

| Method | Route | Existing request ceiling owner | Complete successful response ceiling owner |
| --- | --- | --- | --- |
| POST | `/v1/fastvote/prepare` | `execution::paid_execution::MAX_SIGNED_PAID_INTENT_BYTES` | `node_wire::MAX_FASTVOTE_VOTE_BYTES` |
| POST | `/v1/fastvote/certificates` | `node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES` | canonical, outer `HttpNodeResult` |
| POST | `/v1/fastvote/publications/source` | `node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` |
| POST | `/v1/fastvote/publications/retain` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` | `consensus::availability::MAX_ENCODED_VOTE_BYTES` |
| POST | `/v1/fastvote/publications/apply` | `node_wire::MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES` | canonical, outer `HttpNodeResult` |
| POST | `/v1/fastvote/publications/retained-source` | `node_wire::MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` |
| POST | `/v1/fastvote/frontier/page` | `node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES` | `node_wire::MAX_FRONTIER_PAGE_RESPONSE_BYTES` |
| POST | `/v1/fastvote/frontier/advance` | native frontier route, one-byte ceiling and semantically empty body | `node_wire::MAX_FRONTIER_VOTE_BYTES`, or zero for 204 |
| POST | `/v1/fastvote/drain/signer-page` | `node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES` | zero, 204 only |
| POST | `/v1/fastvote/drain/member-confirm` | `node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES` | zero, 204 only |
| POST | `/v1/fastvote/drain/union-advance` | `node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES` | `consensus::availability::union::MAX_DRAIN_UNION_IDENTITY_BYTES`, or zero for 204 |
| POST | `/v1/fastvote/drain/signer-progress` | `node_wire::MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES` | `node_wire::MAX_DRAIN_SIGNER_PROGRESS_RESPONSE_BYTES` |
| POST | `/v1/fastvote/drain/apply` | `node_wire::MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES` | canonical, outer `HttpNodeResult` |
| POST | `/v1/fastvote/drain/import/{validator_id}` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` | `consensus::availability::MAX_ENCODED_IDENTITY_BYTES` |
| GET | `/v1/context` | no request body | canonical, `HttpQueryResult` |
| GET | `/v1/objects/{object_id}` | no request body | canonical, `HttpQueryResult` |
| GET | `/v1/receipts/{request_id}` | no request body | canonical, `HttpQueryResult` |
| GET | `/v1/senders/{sender}/next-nonce` | no request body | canonical, `HttpQueryResult` |
| GET | `/v1/contracts/paid-fee-policy` | no request body | `execution::paid_execution::MAX_PAID_FEE_POLICY_BYTES` |
| GET | `/v1/contracts/publications/{publisher}/{origin_seed}` | no request body | `node_core::publication::MAX_PUBLICATION_QUERY_RESULT_BYTES` |
| GET | `/v1/contracts/instances/{creator}/{seed}` | no request body | canonical, `encode_instance_record` |

Expose the three existing private consensus identity/vote/union byte constants
above for reuse by the native test oracle; their values and enforcement do not
change. A paid apply's inner `MAX_PAID_EXECUTION_RESULT_BYTES` is not its HTTP
ceiling: native wraps that result in `NodeResponse` and `HttpNodeResult`, adding
framing. Keep the complete canonical outer cap rather than truncating a valid
maximum-size paid result. Instance encoding has no named tighter output cap;
its existing strict decoder and core validation remain unchanged.

Keep the storage-free `GET /health/live` local. POST uses the exact existing
`application/vnd.sunrise-edge.node-event` request media. A 200 POST response uses
`application/vnd.sunrise-edge.node-result`; a 200 GET response uses
`application/vnd.sunrise-edge.query-result`. Every GET and the ordinary POST
routes permits only 200. `frontier/advance` and `drain/union-advance` permit 200
or 204; `drain/signer-page` and `drain/member-confirm` permit only 204. A 204 must
have no content type, body or nonzero declared length. Do not turn those genuine
native progress successes into errors or admit 204 on unrelated routes.
Only `frontier/advance` accepts a null request body as empty; it rejects any
actual byte before dispatch. Other POSTs retain the missing-body refusal.
Before dispatch, refuse every certified GET, including local `/health/live`,
with a non-null body, any content length other than canonical `0`, a
`Transfer-Encoding` header or a `Content-Type` header. Do not silently strip
those inputs. Forward an admitted GET with no body or content type; reject HEAD and OPTIONS even though
native Axum GET mounts also handle HEAD. Selectors are exactly
64 lowercase ASCII hex characters, as native query parsing requires. Reject
query strings, encoded separators/selector aliases, extra suffixes, wrong
methods, unsupported content encoding and parameterized media before dispatch.
Identifiers remain locators; core checks nonzero/semantic identity where needed.

The HTTPS fetcher pins a trusted absolute HTTPS origin for the certified
profile, with no credentials, query, fragment or base-path. Revalidate the
selected closed route, synthesize only that method/path and fixed no-store/media
headers, and supply only its configured Bearer token. Never forward caller
Authorization, cookies, Host, redirect targets or forwarding identity headers.
Keep redirects disabled, the existing 5-second default/30-second maximum timeout
and no automatic retry. That abort signal covers response consumption too; a
late timeout can fail a partially delivered stream.
Transport authentication is distinct from signatures, quorum and protocol pins.

Classify pre-dispatch framing/size/method refusals separately from any failure
after a certified POST was dispatched. A thrown fetch, timeout, 5xx or invalid
response after dispatch returns opaque `503 node-core-outcome-unknown`, never a
claim of non-execution. Do not automatically retry or expose a partial result.
Clients reconcile the exact request/receipt before deciding whether to resubmit.
Read-only GET failure remains an unavailable transport result. Preserve the
event-only profile's existing status/error mapping unchanged. A stream failure
after headers remains a transport error, not a definite rollback or new receipt.

Native refusal responses may pass through only for the closed status set 400,
401, 403, 404, 405, 409, 413, 415 and 422, with exactly
`text/plain; charset=utf-8`. Read their entire body before returning headers,
with a fixed 1 KiB guard and the same consumption timeout. An unsupported
status/media, invalid length, oversized body or failed read becomes outcome
unknown for a dispatched POST and unavailable for GET. These are definite
HTTP refusal responses, not proof that an earlier attempt never committed:
receipt/frontier/drain reconciliation remains core-defined. Do not copy the
legacy unbounded error-body forwarding into the certified profile.

Fully bound request bodies before dispatch using the existing bounded reader.
The certified profile validates provider ceilings against its 32 MiB maximum,
then narrows each route's own ceiling; the legacy 16 MiB + 512 cap and its error
remain unchanged. Full publication/import frames keep their existing 32 MiB
native ceiling, not an unconditional claim for every provider.

The separate certified Cloudflare Worker uses the configured HTTPS/Bearer
fetcher to a native certified host, not the default Worker's `NODE_CORE`
service binding. Its trusted origin and token come from configuration/secrets;
the same closed-route revalidation and synthesized-header isolation apply.
The original binding-based, synthetic-origin event-only Worker is unchanged.
No conformant certified service-binding implementation is claimed or required.
The certified Worker explicitly caps requests at 8 MiB.
This accommodates current ordinary intent/certificate envelopes but intentionally
refuses larger publication/import bundles. The bounded reader holds chunks plus
a contiguous copy, so a 32 MiB request could require roughly twice that memory.
Workers has a [128 MB per-isolate limit shared by concurrent requests](https://developers.cloudflare.com/workers/platform/limits/#memory).
An 8 MiB ceiling reduces individual allocation; it does not certify concurrency,
CPU, capacity or full native-size parity. Its response ceiling is explicitly
32 MiB, streamed and narrowed by each route's response bound.

Vercel retains a conservative 4 MiB request ceiling and adds the same response
ceiling for this initial profile. Its [limits documentation](https://vercel.com/docs/functions/limitations#request-body-size)
describes a 4.5 MB request/response payload limit; the provider's
[streaming guidance](https://vercel.com/kb/guide/how-to-bypass-vercel-body-size-limit-serverless-functions)
describes a response-streaming exception. Do not assume that exception is
qualified by an undeployed Fetch handler. Larger native results/bundles are
outside the initial Vercel profile, and a mid-stream size/timeout failure is
tested as a transport error, not a definitely-aborted operation.

Deno's certified composition also explicitly defaults to an 8 MiB request
ceiling. A trusted operator may narrow it or opt into at most the native 32 MiB
maximum, but larger buffered requests are not qualified for provider memory or
concurrency. Its certified response ceiling is explicitly 32 MiB with streaming;
the event-only Deno constructor keeps its original defaults.

Provider ceilings narrow coverage, not protocol constants. Cloudflare's and
Deno's 8 MiB defaults accommodate the current maximum signed intent, certificate
apply and published apply frames, but not maximum 32 MiB retain/import bundles.
Vercel's 4 MiB ceiling can refuse maximum Publish-bearing `prepare`,
`certificates`, `publications/source` and `publications/apply` requests as well
as large retain/import bundles and query/results. Smaller non-Publish frames
fit, subject to their native route limits. A provider-side 413 for an explicitly
unsupported size is expected; no provider claims complete native-size parity.
A slow bounded response may exceed the configured full-consumption timeout;
that is an expected transport failure, not proof of a failed commit.

Every successful stream has the mandatory complete-body byte guard named in
the table, narrowed by the provider response ceiling. The TSV pins request and
response numbers independently and Rust asserts both against those real owners.
Validate declared length before returning;
otherwise stop before an over-budget chunk is emitted. No whole-response
buffering, detached pump, automatic retry or new provider state. Preserve exact
bytes, fixed media/no-store and backpressure; cancel/release the upstream reader
on disconnect, oversize, failure or completion. SDKs still decode/authenticate.

Add explicit Deno/Vercel composition selection and a separate Cloudflare
certified entrypoint/configuration rather than silently widening the existing
default Worker. The existing Supabase and AWS Lambda adapters remain event-only;
their `/v1/events` upstream URL validation and HTTP mapping remain unchanged.
Use an explicit shared certified composition factory without widening those
legacy constructors or accepting a profile from an HTTP request.
The current Durable Object subset is not the certified native profile. No provider DB,
D1 write, deployment, public listener or resource creation is part of this work.

## Verification and limits

Add independent shared/provider tests for every literal route, method, media,
selector/query refusal, pre-dispatch byte ceiling, configured-origin/header
isolation, redirect/timeout/cancellation, streamed result bytes and failure
classification. Keep original event-only fixtures unchanged. Derive an
executable transport reference: a checked-in TSV fixture is consumed independently
by TypeScript tests and a native Rust test. The Rust expected inventory is built
from real node-wire/native path and byte-bound constants, with explicit native
200/204 status cases. Probe the real `certified_fastvote_router` for every listed
method/path, its excluded direct mutations and unlisted routes; retain and extend
the actual success/204 tests rather than relying on malformed-body mounting
alone. The TSV is a test oracle, not production route configuration or authority.
Do not derive TypeScript expectations from the new route owner. Run owning local
portable/Workers checks and all existing required CI owners before normal merge.

Canonical protocol/storage/signature bytes, SDK signing, core policy and
atomicity remain unchanged. Stub transport conformance is not a deployed
provider, public end-to-end network proof, new requester authorization, complete
DO lifecycle or final security audit. Update the composition map and live TODO
with exactly those distinctions; mainnet ingress/runtime qualification and
human-approved topology remain open.

## References

- [Shared ingress](../../../adapters/shared/web-ingress.ts) and
  [configured fetcher](../../../adapters/shared/authenticated-node-core.ts).
- [Certified native routes](../../../crates/native-http/src/fastvote.rs) and
  [drain routes](../../../crates/native-http/src/fastvote/drain.rs).
- [Cloudflare streaming guidance](https://developers.cloudflare.com/workers/runtime-apis/streams/)
  and [HTTP service binding requirements](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/http/).
- [Live queue](../../../TODO.md); a relay implementation does not close the
  production ingress, runtime qualification or public-testnet gates by itself.
