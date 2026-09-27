# Cloudflare adapters

Two separately configured entrypoints keep their authority boundaries distinct:

- `wrangler.jsonc`: shared-envelope relay through a private `NODE_CORE` Service Binding.
- `wrangler.validator.jsonc`: experimental embedded Rust/Wasmi validator in one
  SQLite-backed Durable Object, with certified-only authenticated ingress.

See [local validation and configuration](../../docs/guides/cloudflare-validator.md)
and the [storage decision](../../docs/architecture/decisions/0152-durable-object-contract-host.md).
Implementation status and release gates belong in [TODO](../../TODO.md).
