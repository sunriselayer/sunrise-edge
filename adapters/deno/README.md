# Deno ingress adapter

This adapter exposes the shared Web ingress contract through Deno's default `fetch`
export. It targets the current Deno 2 and Deno Deploy platform, not Deno Deploy Classic.

The default profile accepts only an exact HTTPS `/v1/events` node-core endpoint. It adds
a bounded Bearer capability from a secret environment variable, rejects redirects so
credentials cannot cross origins, applies a fixed downstream timeout, and delegates all
public request validation and response sanitization to `adapters/shared/web-ingress.ts`.

Required deployment configuration:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: Deno Deploy secret, never a checked-in plain-text
  variable.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults
  to 5000.

For the separate certified relay, set trusted `SUNRISE_INGRESS_PROFILE` to
`certified-fastvote` and use an exact HTTPS **origin** without a base path for
`SUNRISE_NODE_CORE_URL`. The existing `createDenoHandler` stays event-only;
`createCertifiedDenoHandler` exposes only the
[closed certified contract](../shared/README.md#explicit-certified-profile).
`SUNRISE_MAX_REQUEST_BYTES` optionally narrows the certified 8 MiB default, or
explicitly opts into at most the native 32 MiB cap. Responses are streamed under their
route bound and a 32 MiB ceiling. Maximum 32 MiB retain/import requests do not fit the
default. An opt-in size does not qualify memory or concurrency.

For local serving, grant only the named environment variables and the exact node-core
host, for example:

```bash
deno serve \
  --host=127.0.0.1 \
  --allow-env=SUNRISE_NODE_CORE_URL,SUNRISE_NODE_CORE_BEARER_TOKEN,SUNRISE_NODE_CORE_TIMEOUT_MS,SUNRISE_INGRESS_PROFILE,SUNRISE_MAX_REQUEST_BYTES \
  --allow-net=node.internal.example:443 \
  src/main.ts
```

Run static checks and local adapter tests with only the named TSV read permission:

```bash
deno task check
```

This is an As-Is authenticated relay, not the production trust architecture. Private
connectivity or mTLS/signed service requests, key rotation, durable deduplication and
outbox delivery, platform policy, load/fault testing, and a real Deno Deploy rehearsal
remain Phase 17 To-Be requirements.
