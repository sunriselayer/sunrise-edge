# DR-0152: Embedded Rust contract hosting in SQLite-backed Durable Objects

## Status

Accepted implementation direction, 2026-09-27. Implementation and validation
status belong in `TODO.md`. This decision authorizes local implementation and
tests, not public deployment, live activation or real-asset custody.

## Context

DR-0151 selects lightweight stores by capability rather than making PostgreSQL
a protocol prerequisite. The generic certified lifecycle is available, but the
existing Cloudflare adapter only forwards requests to another service. A relay
does not demonstrate execution or authoritative persistence inside an edge host.

`node-core` and its existing Wasmi interpreter compile for
`wasm32-unknown-unknown`. Guest contract execution must remain inside that same
interpreter: compiling user-selected code with the provider's JavaScript WASM
engine would change admission, instruction metering and consensus behavior.

## Decision

Embed the real Rust core in a separately configured, experimental Worker/DO
host. Keep the existing relay adapter unchanged. One trusted independently
controlled validator/domain maps to one SQLite-backed DO. Neither a URL nor a
caller-selected actor ID grants domain, chain, validator or writer authority.

Expose the existing bounded context/object/receipt/nonce and
publication/instance/paid-fee-policy reads needed by the Rust CLI, using the
shared canonical codecs rather than adapter-specific wire formats. Cohort
credentials are optional private files, bound to each exact configured target
and sent only after pinned TLS verification for remote peers. They grant
transport access only, never transaction or validator signing authority.

Extract the existing structured SQLite contract into provider-neutral
synchronous SQL sessions and host-owned atomic transaction callbacks. Native
SQLite and DO must reuse the same validation, statements and record rules:
complete state/head assertions, immutable versions, retained deletion revisions,
typed request receipts/outbox, deadlines and commit-time writer fencing. Keep
native filesystem/WAL/PRAGMA setup in the native adapter; DO schema identity is
explicit persisted metadata, not unsupported file PRAGMAs. Do not load or rewrite
the entire validator state on each request.

The DO bridge calls synchronous `sql.exec` from safe Rust bindings inside
`storage.transactionSync`. A deliberate abort must throw through the host
callback so SQL rolls back; imported exceptions are caught and translated, not
allowed to unwind unexpectedly through Rust. Backend transaction failures and
post-dispatch ambiguity are distinct from protocol conflicts. No fetch, send,
await or externally visible output belongs inside a SQL transaction. The DO
must await confirmed storage before releasing a successful signed vote/result;
a confirmation failure releases no provisional output and retries reconcile
persisted records. The object itself being single-threaded is not a substitute
for a persisted writer-generation check.

All u64 revisions, generations, times and versions remain exact eight-byte
big-endian BLOBs. JavaScript numeric SQL fields must be range-checked. Cursor
results are bounded and consumed synchronously. Storage adapters select no hash
algorithm and do not decode Standard Asset balances or grant asset-specific
authority. Preserve canonical intent, object, receipt, certificate and nonce
bytes, the interpreter version and its fuel/fee accounting.

The initial host is a bounded local integration profile. Provider row/memory/CPU
limits must be explicit, fail closed and never truncate data or silently split
a transaction across actors. Supporting every maximum-size protocol envelope,
full provider fault certification, cross-actor commit, public operation,
economics ordering and epoch activation are not established by this host.

## Acceptance

Run the real paid Publish → Instantiate → Call path, ordinary Standard Asset
operations and charged failures in workerd with actual SQLite-backed DO
storage. Verify independent validator identity/domain placement, authenticated
genesis/configuration, prepare/apply and exact result convergence where exposed.
Use genuine eviction/recreation or process close/reopen, then demonstrate exact
replay with unchanged fees, nonce, objects and receipts. Cover request-ID reuse,
wrong context/configuration, stale writer, rollback after partial SQL work,
immutable-version/tombstone corruption and oversized requests. Compare native
and embedded execution results, including gas and canonical bytes.

Shared SQL/native conformance and the complete repository gate remain required,
as do fresh exact-head Opus review and passing CI before merge. Provider API
documentation and mocked SQL alone are not restart or durability evidence.

## Primary references

Checked 2026-09-27:

- [DO SQL and transactionSync](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
- [DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/).
- [Workers WASM restrictions](https://developers.cloudflare.com/workers/runtime-apis/webassembly/).
- [Scoped Rust/JavaScript callbacks](https://wasm-bindgen.github.io/wasm-bindgen/api/wasm_bindgen/closure/index.html).
