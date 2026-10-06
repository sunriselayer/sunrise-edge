# Host compositions and capability boundaries

One backend-neutral storage contract does not imply one exposed protocol
surface. Identify the constructor actually used by the executable, its supplied
authority and store, and its mounted routes. A tested component is not a
production deployment. Readiness and the selected release profile belong in
[`TODO.md`](../../TODO.md), not this design map.

## Concrete composition owners

| Composition and actual source owner | Accepted surface and authority boundary | Must not be inferred |
| --- | --- | --- |
| Legacy native [`router` / `resolved_domain_router`](../../crates/native-http/src/lib.rs) | Their event routes refuse every non-`SubmitTransaction` family and refuse unauthenticated transactions. Legacy core library callbacks retain their own contracts behind these closed public guards. | Generic core handlers do not make these routes successful network mutation ingress. |
| Native structured and preinstalled-WASM router families in the same file | Authenticated `SubmitTransaction` with explicitly supplied trusted composition; other NodeEvent families refuse. Opt-in direct paid/local/publication routes are separate composition choices. | The mere presence of an opt-in constructor does not certify its inclusion in a network host. |
| [`certified_fastvote_router_with_executor`](../../crates/native-http/src/fastvote.rs) | Bounded queries, certified prepare/apply/publication, frozen-frontier advance/page and the [drain family](../../crates/native-http/src/fastvote/drain.rs), including union/member/import/progress and retained publication controls. Context, policy, signed intent, committee and durable owners enforce their contracts. Direct paid/local/publication mutations and `NODE_EVENT_PATH` are excluded. | These mounted handoff controls do not themselves supply ordered Seal, readiness, activation or a complete host lifecycle. An ordinary response or user signature is not a committee certificate or validator warrant. |
| [`certified_ordered_economics_router`](../../crates/native-http/src/ordered_economics.rs) | Explicit opt-in ordered proposal/observe/certificate/status/outcome/tick and read-only fixed-target history transport whose material is authenticated by history owners, composed with the certified router. Its supplied policy, signer and optional Seal composition decide authority. | Authenticating archive material does not authenticate the requester. An ordinary proposal or local tick is not a quorum commit. `Seal = None` is not an implemented handoff composition. |
| Original [`sqlite-source-host`](../../apps/operator/src/sqlite_source_host.rs) | Existing original-genesis namespace, explicit offline fence claim, locally pinned signer/policies and the certified/ordered router with Seal composition. Listen is numeric loopback only. | It neither authors genesis nor activates a successor; a loopback acceptance host is not a public validator deployment. |
| [`successor-host`](../../apps/operator/src/successor_host.rs) and live [`successor_router`](../../crates/native-http/src/successor.rs) | Each request obtains fresh verified serving authority from the original root, complete predecessor chain and exact target namespace. Mounts current certified, ordered and supported handoff controls, plus successor-only fee-claim preparation. Unsupported successor controls explicitly refuse. | Fee-claim preparation is not mounted by the original SQLite/PG hosts. A startup-time cached policy, completed import, readiness certificate or transport success does not independently grant serving authority. |
| [`successor_history_router`](../../crates/native-http/src/successor/historical.rs) | Exactly three material-only history routes; freshly verified current policy, no signer and no live serving warrant. The executable's `serve-history` does not advance the fence. | Historical availability must never be treated as paid execution, voting, receipt authority or successor activation. |
| Optional [`fastvote_host_pg`](../../apps/operator/src/bin/fastvote_host_pg.rs) | Loopback original host backed by explicitly configured PostgreSQL and the certified router, including its frontier/drain controls. Ordered economics is mounted only with `--enable-ordered-economics`; its Seal composition is `None`. | The PG host does not replace the native SQLite successor/Seal acceptance or make PostgreSQL mandatory. |
| Embedded Cloudflare [`ValidatorHost::dispatch`](../../adapters/cloudflare-workers/rust/src/lib.rs), [DO request wrapper](../../adapters/cloudflare-workers/src/validator/index.ts) and [ingress policy](../../adapters/cloudflare-workers/src/validator/ingress-policy.ts) | Exactly prepare/apply mutations plus bounded context/fee/object/receipt/nonce/publication/instance queries. Query bodies must be empty. The wrapper checks bearer authorization, pinned actor placement, bounded closed request decoding and storage confirmation before releasing output. Trusted adapter pins and the shared SQL engine remain distinct component contracts. | This dispatch does not mount the native ordered/handoff or complete network publication/instantiation surfaces. Bearer authentication does not replace protocol authority; sharing SQL rules is not provider feature parity or rollout evidence. |
| Default event-only provider ingress, including Cloudflare [`index.ts`](../../adapters/cloudflare-workers/src/index.ts) | The [shared bounded relay](../../adapters/shared/web-ingress.ts) forwards only `/v1/events` to an explicitly supplied node-core transport capability. Deno/Vercel legacy constructors and Supabase/AWS remain event-only. | Certified, ordered, live-successor and embedded DO hosts do not mount that NodeEvent path, so this default relay cannot front their other protocol families. It is not an embedded validator or persistence adapter and supplies no D1 validator store. |
| Explicit portable [`createCertifiedWebIngressHandler`](../../adapters/shared/certified-web-ingress.ts), [closed route owner](../../adapters/shared/certified-routes.ts), Deno/Vercel certified constructors and separate Cloudflare [`certified.ts`](../../adapters/cloudflare-workers/src/certified.ts) | Trusted configuration selects an exact HTTPS/Bearer origin and closed certified FastVote/publication/frontier/drain/query routes. Requester headers never choose profile, authority or upstream. Request/complete-response bounds, no-follow redirect handling and ambiguous post-dispatch failures are transport rules. | It supplies no signer, persistence, protocol authority, ordered economics, Seal/readiness/activation or successor fee-claim route. The embedded DO subset stays separate. Provider-size ceilings narrow coverage; local stub/workerd tests do not establish deployed conformance or current Rust SDK compatibility. |

Route framing, transport identity, user signatures, validator membership,
committee quorum, verified serving authority and physical writer fencing are
distinct controls. Do not replace one with another when composing an adapter.
Publication/Instantiate/Call use the generic contract owners; Standard Asset
has no separate node-core privilege.

## Store and signer capabilities

- Opaque [`SqliteStateStore`](../../crates/runtime-sqlite/src/lib.rs) implements
  the versioned key-value contracts. Structured
  [`SqliteDurableStore`](../../crates/runtime-sqlite/src/structured.rs) owns
  native file/PRAGMA/fence setup and delegates structured decisions to
  [`runtime-sql-durable`](../../crates/runtime-sql-durable/src/lib.rs). They use
  different application identities and separate files, not interchangeable
  schemas.
- The DO backend supplies its own SQL session/transaction boundary to that
  engine. Its implemented dispatcher is the bounded subset above. Native
  process/filesystem, provider SQL and protocol-surface qualification are
  separate even when they consume shared statements.
- PostgreSQL implements the runtime contract independently. Its selected
  conformance and operational evidence are scoped to that adapter. Pooling and
  HA are host choices, not reasons to weaken atomic commit/replay elsewhere.
- A validator's original or successor state/object/receipt/outbox commit is
  one atomicity-domain contract. Separate validator stores are expected;
  independently sharding one validator's related writes requires a separately
  designed atomic protocol and is not supplied by FastVote certificates.
- Operator binaries currently use explicit local key-file signers. The real
  loopback TLS/CLI acceptance uses disposable keys and a local relay. It does
  not certify mainnet key custody, production PKI rotation or a deployed proxy.
  Historical composition intentionally has no signing capability. Ledger's
  incomplete release gate is not closed by local signing success.

## Audit and release selection

The [network audit input contract](../security/network-code-audit-scope.md)
requires the exact executable, feature set, store, signer, routes and external
TLS/authentication configuration. Include every reachable security owner, not
only a provider-labelled folder. Declare omitted capabilities and refuse their
routes; selecting a subset does not waive the accepted protocol-v3 activation
constraint, original release gates or required human approval.

The [local startup procedure](../guides/sqlite-validator-startup.md) is an
executable local composition reference. It cannot establish public endpoints,
operational operator independence, approved economics or mainnet readiness.
