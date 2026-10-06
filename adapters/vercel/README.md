# Vercel ingress adapter

This adapter exposes the shared Web ingress contract as a Vercel Node.js Function using
the recommended Web `fetch` export. `vercel.json` rewrites the canonical `/v1/events`
and `/health/live` routes to the single function and caps the invocation at ten seconds.

Vercel documents a 4.5 MB request/response payload ceiling. The adapter uses a
conservative 4 MiB request budget so the shared handler can reject declared or streamed
oversize input before forwarding it. This is lower than the protocol transport limit and
is therefore an explicit As-Is conformance gap.

Required project configuration:

- `SUNRISE_NODE_CORE_URL`: exact HTTPS node-core `/v1/events` endpoint.
- `SUNRISE_NODE_CORE_BEARER_TOKEN`: Sensitive Environment Variable for production and
  preview, never a checked-in plain-text value.
- `SUNRISE_NODE_CORE_TIMEOUT_MS`: optional integer from 1 through 30000; defaults to
  5000 and should remain below the ten-second Function duration.

For an explicitly selected certified relay, set trusted `SUNRISE_INGRESS_PROFILE`
to `certified-fastvote` and set `SUNRISE_NODE_CORE_URL` to an exact HTTPS origin
without a base path. Use the separate `vercel.certified.json` configuration
template, whose closed noncapturing route patterns target the Fetch function and
whose maximum duration is 35 seconds. The default `vercel.json` and existing
`createVercelHandler` remain event-only.

The certified profile bounds **both** requests and complete streamed responses at
4 MiB. It can refuse maximum Publish-bearing intent/certificate frames and large
bundles/results; no native-size parity or provider streaming exception is claimed.
See the [shared contract](../shared/README.md#explicit-certified-profile). Do not
reconstruct routes from caller-supplied forwarding headers or query aliases.
The template's original-path behavior still needs a selected deployment rehearsal;
the local test verifies its inventory, not the provider's actual rewrite runtime.

Run local static checks and adapter tests with only the named fixture/config reads:

```bash
deno task check
```

This is an As-Is authenticated relay, not production equivalence. A deployment that
accepts every protocol-valid event requires a platform/path architecture that does not
truncate the larger shared envelope. Private connectivity or mutually authenticated
requests, secret rotation, durable deduplication and outbox delivery, real
preview/production tests, abuse controls, observability, and rollout/rollback rehearsal
remain Phase 17 To-Be requirements.
