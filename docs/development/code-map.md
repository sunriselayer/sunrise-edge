# Code ownership map

This is an As-Is navigation map, not another architecture specification or a
feature-status report. Accepted design and decisions live in
[architecture](../architecture/README.md); current completion gates live only
in [`TODO.md`](../../TODO.md). Update this map when responsibility moves, not
for every new function.

## Follow a request

```text
CLI -> Rust client -- node-wire bytes --> native HTTP -> node-core
operator / provider adapters ---------------------------> node-core
                                                          |-> execution
                                                          |-> consensus
                                                          `-> runtime traits -> PostgreSQL / SQLite / SQL-durable
```

The arrows show where to look, not every Cargo dependency. Canonical type
definitions are in the protocol crates, while HTTP, clients and provider
adapters transport or present them. The Rust client currently also depends on
`node-core`; review that coupling before treating it as a minimal standalone
protocol SDK. A client-side or HTTP check never replaces core authorization.

## Find the owner

| Capability | Entry and wire | Decision and effects | Storage and representative tests |
| --- | --- | --- | --- |
| Canonical identities, transactions and access | [`protocol-types`](../../crates/protocol-types), [`canonical-encoding`](../../crates/canonical-encoding), [`objects`](../../crates/objects), [`abi`](../../crates/abi), [`node-wire`](../../crates/node-wire) | The defining crate owns each type ID, encoder, bound and stable vector | Encoding tests in the defining crates and [`node-wire`](../../crates/node-wire/src/lib.rs) |
| Publish, Instantiate and Call | [CLI contract commands](../../apps/cli/src/commands/contract.rs), [Rust publication client](../../clients/rust/src/publication_client.rs), [native HTTP](../../crates/native-http/src/publication.rs) | [`node-core` publication](../../crates/node-core/src/publication.rs) and [local execution](../../crates/node-core/src/local_execution.rs) coordinate [execution publication](../../crates/execution/src/publication) and [call](../../crates/execution/src/call.rs) | [`runtime` transaction contract](../../crates/runtime/src/lib.rs); [publication tests](../../crates/node-core/src/publication/tests.rs), [local execution tests](../../crates/node-core/src/local_execution/tests.rs), [HTTP tests](../../crates/native-http/src/tests/local_execution_http.rs) |
| Standard Asset and paid execution | [contract package](../../contracts/standard-asset), [CLI paid commands](../../apps/cli/src/commands/paid_execution.rs), [HTTP paid route](../../crates/native-http/src/paid_execution.rs) | [execution fee/effect logic](../../crates/execution/src/paid_execution.rs) and [node-core paid admission](../../crates/node-core/src/paid_execution.rs); the contract owns asset semantics | [paid core tests](../../crates/node-core/src/paid_execution/tests.rs) and durable store conformance |
| Owned-object FastVote | [HTTP routes](../../crates/native-http/src/fastvote.rs), [Rust quorum client](../../clients/rust/src/fastvote_client.rs) | [consensus certificate rules](../../crates/consensus/src/fast_vote.rs) and [node-core prepare/apply](../../crates/node-core/src/fast_path.rs) | [`runtime` atomic commit](../../crates/runtime/src/lib.rs); [core tests](../../crates/node-core/src/fast_path/tests.rs), [HTTP tests](../../crates/native-http/src/tests/fastvote_router.rs) |
| Shared ordering and economics | [ordered HTTP surface](../../crates/native-http/src/ordered_economics.rs), [Rust client](../../clients/rust/src/ordered_economics_client.rs), [operator](../../apps/operator/src/economics.rs) | [consensus ordering](../../crates/consensus/src/durable.rs), [node-core ordered effects](../../crates/node-core/src/ordered_economics.rs), [bond lifecycle](../../crates/node-core/src/bond_lifecycle.rs) | [ordered core tests](../../crates/node-core/src/ordered_economics/tests.rs) and store-backed operator tests |
| Epoch membership and transition | [consensus epoch types](../../crates/consensus/src/epoch_transition.rs) and network/operator surfaces above | [node-core epoch transition](../../crates/node-core/src/epoch_transition.rs) owns mutation authorization | [runtime transaction contract](../../crates/runtime/src/lib.rs), [PostgreSQL store](../../crates/runtime-postgres/src/lib.rs), [epoch tests](../../crates/node-core/src/epoch_transition/tests.rs) |
| Object, receipt, nonce and context queries | [native HTTP query routes](../../crates/native-http/src/lib.rs), [query result codec](../../crates/node-wire/src/lib.rs) | [node-core query](../../crates/node-core/src/query.rs) validates committed state; queries do not authorize mutation | [query codec tests](../../crates/native-http/src/tests/query_codecs.rs), [HTTP query tests](../../crates/native-http/src/tests/query_http.rs) |
| Storage implementations | No request supplies its own authoritative domain or writer generation | [`runtime` traits](../../crates/runtime/src/lib.rs) define atomic state, receipts, objects, outbox and fencing | [PostgreSQL](../../crates/runtime-postgres/src/lib.rs), [SQLite](../../crates/runtime-sqlite/src/lib.rs), [SQL-durable](../../crates/runtime-sql-durable/src/lib.rs); [PostgreSQL tests](../../crates/runtime-postgres/tests), [SQLite tests](../../crates/runtime-sqlite/tests) |

Other cross-cutting owners are [`hashing`](../../crates/hashing),
[`crypto`](../../crates/crypto) and [`commitments`](../../crates/commitments)
for cryptographic framing; [`protocol-config`](../../crates/protocol-config)
and [`protocol-upgrades`](../../crates/protocol-upgrades) for active rules;
[`contract-sdk`](../../crates/contract-sdk),
[`chain-ir`](../../crates/chain-ir),
[`system-modules`](../../crates/system-modules) and
[`standard-assets`](../../crates/standard-assets) for contract-facing
interfaces and supporting types;
[`fees`](../../crates/fees), [`bonds`](../../crates/bonds),
[`governance`](../../crates/governance) and
[`validator-set`](../../crates/validator-set) for economic and membership
types. [`signing-view`](../../crates/signing-view) owns device-independent
clear-signing policy, while [`clients/ledger`](../../clients/ledger) owns
the Ledger transport. [`apps/devnet`](../../apps/devnet) assembles local
fixtures. [`adapters`](../../adapters) bind providers to the same core
contracts; they do not define protocol rules.

## Cross-layer change checklist

1. Trace the defining type through ingress, core decision, effects and store;
   check the tests at each boundary. Keep provider-specific dependencies out of
   protocol crates.
2. For canonical bytes, hashes, signatures, state layout or commit ordering,
   follow the protocol-critical checklist in [`AGENTS.md`](../../AGENTS.md).
3. Make structural moves reviewable separately from semantic changes. Preserve
   public paths and exact effects; do not create another crate just to shorten
   a source file.
