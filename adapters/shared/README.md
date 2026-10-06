# Shared Web ingress

`web-ingress.ts` implements the default, event-only Fetch API contract used by
edge adapters. A provider wrapper supplies only a typed `NodeCoreFetcher`.

The shared layer owns request paths, exact media types, bounded stream reads,
status handling, and downstream response sanitization. It deliberately owns no
provider binding, secret lookup, durable state, retry policy, or mutable global
state. Provider wrappers must keep those concerns outside this module and must
not weaken its bounds or fail-closed behavior.

A provider whose request-body capacity is smaller than the protocol transport
limit may pass `maximumRequestBodyBytes`. The shared implementation accepts
only a positive integer no larger than its default bound, so an adapter can
narrow the capacity envelope but cannot silently raise the security limit.

`authenticated-node-core.ts` provides the reusable outbound capability for Web
providers that lack a private service binding. It requires an exact HTTPS
endpoint, injects an ASCII Bearer secret into an allow-listed request, rejects
redirects, and applies a bounded timeout. Provider entrypoints still own secret
lookup and must replace this incremental public transport with the stronger
private or mutually authenticated Phase 17 production design.

`conformance-fixtures.ts` holds provider-independent liveness and rejection
vectors. Cloudflare, Deno, Vercel, Supabase, and AWS mapper tests all consume
the same vectors so route, media, encoding, content-length, status, body, cache,
and `Allow` behavior cannot drift silently between local implementations.

## Explicit certified profile

`certified-web-ingress.ts` is a separate configured HTTPS/Bearer composition.
`certified-routes.ts` owns its closed methods, selectors, request/response limits,
media and 200/204 modes. It mounts certified FastVote/publication/frontier/drain
and bounded queries, not `/v1/events`, direct mutations, ordered economics or
successor fee-claim preparation. See [DR-0204](../../docs/architecture/decisions/0204-portable-certified-relay.md)
for the complete route and capability contract. The embedded DO policy is separate.

Only configuration selects a profile. Certified forwarding pins an HTTPS origin,
never caller headers/origin, uses no-follow `manual` redirects and rejects all
3xx. Requests are bounded before dispatch. Successful responses are pull-driven
streams with mandatory route/provider caps and a full-consumption timeout;
validated upstream Content-Length is not copied downstream. Native 4xx refusals
have a closed status/media contract and a fully consumed 1 KiB budget.
Dispatched POST transport failure is `503 node-core-outcome-unknown`; a late
stream failure is not a rollback or a reason for automatic retry. Reconcile
receipts/frontier/drain through their core-defined APIs.

The test-only literal `certified-route-contract.tsv` is read by portable and
Worker tests and independently checked against native Rust owners. It is not
production configuration. Providers deliberately narrow native limits. These
tests do not qualify deployed TLS, memory/concurrency, a complete host lifecycle,
or the Rust SDK against this lengthless streamed relay. The SDK already has
CA/DNS-pinned TLS as well as loopback HTTP, but both require Content-Length
except for bodyless 204 and reject Transfer-Encoding.
