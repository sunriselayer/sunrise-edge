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
exact method, request byte ceiling and successful response media for that
profile. Both ingress and HTTPS forwarding use this same owner; neither accepts
a caller-selected upstream origin, wildcard route or additional authority.

The profile contains these actual native routes, and no others:

| Method | Route | Existing request ceiling owner |
| --- | --- | --- |
| POST | `/v1/fastvote/prepare` | `execution::paid_execution::MAX_SIGNED_PAID_INTENT_BYTES` |
| POST | `/v1/fastvote/certificates` | `node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES` |
| POST | `/v1/fastvote/publications/source` | `node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES` |
| POST | `/v1/fastvote/publications/retain` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` |
| POST | `/v1/fastvote/publications/apply` | `node_wire::MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES` |
| POST | `/v1/fastvote/publications/retained-source` | `node_wire::MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES` |
| POST | `/v1/fastvote/frontier/page` | `node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES` |
| POST | `/v1/fastvote/frontier/advance` | native frontier route, one-byte ceiling and semantically empty body |
| POST | `/v1/fastvote/drain/signer-page` | `node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES` |
| POST | `/v1/fastvote/drain/member-confirm` | `node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES` |
| POST | `/v1/fastvote/drain/union-advance` | `node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES` |
| POST | `/v1/fastvote/drain/signer-progress` | `node_wire::MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES` |
| POST | `/v1/fastvote/drain/apply` | `node_wire::MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES` |
| POST | `/v1/fastvote/drain/import/{validator_id}` | `consensus::bundle::MAX_ENCODED_BUNDLE_BYTES` |
| GET | `/v1/context` | no request body |
| GET | `/v1/objects/{object_id}` | no request body |
| GET | `/v1/receipts/{request_id}` | no request body |
| GET | `/v1/senders/{sender}/next-nonce` | no request body |
| GET | `/v1/contracts/paid-fee-policy` | no request body |
| GET | `/v1/contracts/publications/{publisher}/{origin_seed}` | no request body |
| GET | `/v1/contracts/instances/{creator}/{seed}` | no request body |

Keep the storage-free `GET /health/live` local. POST uses the exact existing
`application/vnd.sunrise-edge.node-event` request and
`application/vnd.sunrise-edge.node-result` success media; GET uses the exact
`application/vnd.sunrise-edge.query-result` success media. Selectors are exactly
64 lowercase ASCII hex characters, as native query parsing requires. Reject
query strings, encoded separators/selector aliases, extra suffixes, wrong
methods, unsupported content encoding and parameterized media before dispatch.
Identifiers remain locators; core checks nonzero/semantic identity where needed.

The HTTPS fetcher pins a trusted absolute HTTPS origin for the certified
profile, with no credentials, query, fragment or base-path. Revalidate the
selected closed route, synthesize only that method/path and fixed no-store/media
headers, and supply only its configured Bearer token. Never forward caller
Authorization, cookies, Host, redirect targets or forwarding identity headers.
Keep redirects disabled, the existing bounded timeout and no automatic retry.
Transport authentication is distinct from signatures, quorum and protocol pins.

Fully bound request bodies before dispatch using the existing bounded reader.
Use each route's own ceiling, narrowed by the provider/operator ceiling; never
increase a core bound. Full publication/import frames retain their existing
32 MiB ceiling. Vercel's smaller 4 MiB transport limit stays effective and is
documented as a qualification limit, not provider parity. Stream successful
downstream bytes without whole-response buffering, preserve exact bytes, fixed
response media/no-store and ambiguity, and propagate cancellation. If adding a
response byte guard, stop the stream at the canonical frame ceiling; after
headers were sent, truncation is a transport error, not a new successful or
definitely-aborted execution outcome. SDKs must still decode and authenticate.

Add explicit Deno/Vercel composition selection and a separate Cloudflare
certified entrypoint/configuration rather than silently widening the existing
default Worker. A service binding must actually implement the certified core
profile; the current Durable Object subset is not equivalent. No provider DB,
D1 write, deployment, public listener or resource creation is part of this work.

## Verification and limits

Add independent shared/provider tests for every literal route, method, media,
selector/query refusal, pre-dispatch byte ceiling, configured-origin/header
isolation, redirect/timeout/cancellation, streamed result bytes and failure
classification. Keep original event-only fixtures unchanged. Derive an
executable transport reference from real Rust constants/native route owners,
not a second test table copied from the new TypeScript owner. Run owning local
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
