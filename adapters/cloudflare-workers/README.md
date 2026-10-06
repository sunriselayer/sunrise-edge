# Cloudflare adapters

Separately configured entrypoints keep their authority boundaries distinct:

- `wrangler.jsonc`: shared-envelope relay through a private `NODE_CORE` Service Binding.
- `wrangler.validator.jsonc`: experimental embedded Rust/Wasmi validator in one
  SQLite-backed Durable Object, with certified-only authenticated ingress.
- `wrangler.certified.jsonc`: stateless [closed certified HTTPS/Bearer relay](../shared/README.md#explicit-certified-profile)
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
