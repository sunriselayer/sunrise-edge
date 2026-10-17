# Cloudflare adapters

Separately configured entrypoints keep their authority boundaries distinct:

- `profiles/ingress/cloudflare.config.ts`: shared-envelope relay through a private `NODE_CORE` Service Binding.
- `profiles/validator/cloudflare.config.ts`: experimental embedded Rust/Wasmi validator in one
  SQLite-backed Durable Object, with certified-only authenticated ingress.
- `profiles/certified/cloudflare.config.ts`: stateless [closed certified HTTPS/Bearer relay](../shared/README.md#explicit-certified-profile)
  to a native certified host. Configure the exact origin and secret; the checked-in
  `.invalid` origin is deliberately unusable. This uses no Service Binding or DB.

The certified relay caps requests at 8 MiB and streams responses under each
route's bound and a 32 MiB ceiling. Larger retain/import requests are outside its
profile; concurrency/memory, public TLS and deployed proxy-chain behavior are not
qualified by the local tests. It enables incoming request cancellation and uses
no-follow redirects. Local Vitest intercepts every outbound request, with public
test credentials and no production provider writes. The complete repository
Cloudflare build/check remains required; the focused certified suite is not a
substitute for the embedded validator's generated artifacts and real SQL tests.

See [local validation and configuration](../../docs/guides/cloudflare-validator.md)
and the [storage decision](../../docs/architecture/decisions/0152-durable-object-contract-host.md).
Implementation status and release gates belong in [TODO](../../TODO.md).


Use Node 24 and external `cf@1.0.0-beta.13` (CI declares that exact tool).
`npm run types` renders all five named Env declarations. `npm run typecheck`
validates each actual profile with `cf workers types`, compares the config and
renderer fingerprint without replacing declarations, then runs TypeScript.
SQL and contract tests have separate leaves; all four Vitest suites remain.

Vitest loads programmatic config and still uses the transitive Wrangler SDK
internally for Miniflare. Repository commands invoke only `cf`. Original JSONC
files retain historical SQLite migration tags; this local migration makes no
change or assertion about deployed namespace history.
