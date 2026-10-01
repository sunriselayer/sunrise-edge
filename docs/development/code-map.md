# Code ownership map

This is an As-Is navigation map, not another architecture specification or a
feature-status report. Accepted design and decisions live in
[architecture](../architecture/README.md); current completion gates live only
in [`TODO.md`](../../TODO.md). Update this map when responsibility moves, not
for every new function.

The [implementation structure](../architecture/implementation-structure.md)
describes intended responsibility boundaries, not existing file locations.
Its integrated implementation/refactoring queue remains only in TODO.

## Follow a request

```text
CLI -> Rust client -- node-wire bytes --> native HTTP -> node-core
operator / provider adapters ---------------------------> node-core
                                                          |-> execution
                                                          |-> consensus
                                                          `-> runtime traits -> PostgreSQL / SQLite / SQL-durable
```

The arrows show where to look, not every Cargo dependency. Foundational
canonical types are defined in the protocol crates. `node-wire` owns HTTP
result frames but currently depends on `node-core`; it is not a foundational
protocol crate. The Rust client also depends on `node-core`. Review those
couplings before treating either as a minimal standalone protocol SDK.
HTTP, clients and provider adapters cannot replace core authorization.

## Find the owner

| Capability | Entry and wire | Decision and effects | Storage and representative tests |
| --- | --- | --- | --- |
| Canonical identities, transactions and access | [`protocol-types`](../../crates/protocol-types), [`canonical-encoding`](../../crates/canonical-encoding), [`objects`](../../crates/objects), [`abi`](../../crates/abi); HTTP frames in [`node-wire`](../../crates/node-wire) | Each defining crate owns its type IDs, encoders, bounds and stable vectors | Encoding tests in the defining crates and [`node-wire`](../../crates/node-wire/src/lib.rs) |
| Publish, Instantiate and Call | [CLI contract commands](../../apps/cli/src/commands/contract.rs), [Rust publication client](../../clients/rust/src/publication_client.rs), [native HTTP](../../crates/native-http/src/publication.rs) | [`node-core` publication](../../crates/node-core/src/publication.rs) and [local execution](../../crates/node-core/src/local_execution.rs) coordinate [execution publication](../../crates/execution/src/publication) and [call](../../crates/execution/src/call.rs) | [`runtime` transaction contract](../../crates/runtime/src/lib.rs); [publication tests](../../crates/node-core/src/publication/tests.rs), [local execution tests](../../crates/node-core/src/local_execution/tests.rs), [HTTP tests](../../crates/native-http/src/tests/local_execution_http.rs) |
| Standard Asset and paid execution | [contract package](../../contracts/standard-asset), [CLI paid commands](../../apps/cli/src/commands/paid_execution.rs), [HTTP paid route](../../crates/native-http/src/paid_execution.rs) | [execution fee/effect logic](../../crates/execution/src/paid_execution.rs) and [node-core paid admission](../../crates/node-core/src/paid_execution.rs); the contract owns asset semantics | [paid core tests](../../crates/node-core/src/paid_execution/tests.rs) and durable store conformance |
| Owned-object FastVote | [HTTP routes](../../crates/native-http/src/fastvote.rs), [Rust quorum client](../../clients/rust/src/fastvote_client.rs) | [consensus certificate rules](../../crates/consensus/src/fast_vote.rs) and [node-core prepare/apply](../../crates/node-core/src/fast_path.rs) | [`runtime` atomic commit](../../crates/runtime/src/lib.rs); [core tests](../../crates/node-core/src/fast_path/tests.rs), [HTTP tests](../../crates/native-http/src/tests/fastvote_router.rs) |
| Shared local client and artifact primitives | [SDK local genesis](../../clients/rust/src/local_genesis.rs), [CLI network artifacts](../../apps/cli/src/commands/network_artifacts.rs) | SDK verifies locally pinned manifest bytes and converts the committee; each client retains its profile/policy checks. CLI shares only bounded I/O, fresh reservations and held-handle synchronization, not operation authority | [SDK primitive tests](../../clients/rust/src/local_genesis/tests.rs), [CLI artifact tests](../../apps/cli/src/commands/network_artifacts/tests.rs), existing network workflow tests; transport and offline operator authority remain separate |
| Shared ordering and economics | [ordered HTTP surface](../../crates/native-http/src/ordered_economics.rs), [Rust client](../../clients/rust/src/ordered_economics_client.rs), [operator](../../apps/operator/src/economics.rs) | [consensus ordering](../../crates/consensus/src/durable.rs), [node-core ordered effects](../../crates/node-core/src/ordered_economics.rs), [bond lifecycle](../../crates/node-core/src/bond_lifecycle.rs) | [ordered core tests](../../crates/node-core/src/ordered_economics/tests.rs) and store-backed operator tests |
| Ordered Freeze and immutable frontier | [CLI frontier commands](../../apps/cli/src/commands/fastvote_frontier.rs), [Rust frontier client](../../clients/rust/src/fastvote_frontier_client.rs), certified HTTP routes | [Freeze authority](../../crates/node-core/src/ordered_economics/freeze.rs), [frontier retention/export](../../crates/node-core/src/ordered_economics/frontier.rs), [canonical frontier proofs](../../crates/consensus/src/availability/frontier.rs) | [Freeze tests](../../crates/node-core/src/ordered_economics/tests/freeze_boundaries.rs), [frontier tests](../../crates/node-core/src/ordered_economics/frontier/tests.rs); closed frontier is not a complete business cut |
| Quorum-retained DrainSet and member completion | [HTTP drain surface](../../crates/native-http/src/fastvote/drain.rs), [Rust drain client](../../clients/rust/src/fastvote_drain_client.rs), [CLI member command](../../apps/cli/src/commands/fastvote_drain_member.rs) | [union retention](../../crates/node-core/src/ordered_economics/drain_union.rs), [ordered DrainSet](../../crates/node-core/src/ordered_economics/drain_set.rs), [narrow member apply](../../crates/node-core/src/fast_path/drain_apply.rs) | [union tests](../../crates/node-core/src/ordered_economics/drain_union/tests.rs), [member apply tests](../../crates/node-core/src/fast_path/drain_apply/tests.rs); retention does not itself execute business effects |
| Authenticated ordering history, not business-state import | [history wire](../../crates/node-wire/src/ordered_history.rs), [Rust history client](../../clients/rust/src/ordered_history_client.rs), CLI `economics history-export` | [per-height consensus proofs](../../crates/consensus/src/commit_proof.rs), [core archive and pure verifier](../../crates/node-core/src/ordered_economics/ordered_history.rs) | Immutable archives join the original atomic commit; [core history tests](../../crates/node-core/src/ordered_economics/tests/ordered_history.rs), [compiled CLI / real PostgreSQL acceptance](../../apps/operator/tests/support/ordered_history_acceptance.rs) |
| Causal admission and fixed-snapshot business audit | [profile-aware Rust client](../../clients/rust/src/causal_admission.rs), [saved-history reader](../../clients/rust/src/ordered_history_archive.rs), operator [`business_audit_pg`](../../apps/operator/src/bin/business_audit_pg.rs) | [locally verified profile](../../crates/node-core/src/admission_profile.rs), [private causal reconstruction](../../crates/node-core/src/business_reconstruction.rs), [closed comparison](../../crates/node-core/src/business_reconstruction/projection.rs); ordered local schemas remain owned by [ordered projection](../../crates/node-core/src/ordered_economics/audit_projection.rs) | [backend-neutral single-token capture](../../apps/operator/src/business_snapshot.rs), [real SQLite collector tests](../../apps/operator/tests/business_snapshot_sqlite.rs), [compiled CLI/PG acceptance](../../apps/operator/tests/business_audit_pg_e2e.rs); reconstruction has no source-write/import/readiness capability |
| Epoch membership and transition | [consensus epoch types](../../crates/consensus/src/epoch_transition.rs) and network/operator surfaces above | [node-core epoch transition](../../crates/node-core/src/epoch_transition.rs) owns mutation authorization | [runtime transaction contract](../../crates/runtime/src/lib.rs), [PostgreSQL store](../../crates/runtime-postgres/src/lib.rs), [epoch tests](../../crates/node-core/src/epoch_transition/tests.rs) |
| First-epoch pre-Seal candidate export, not persistent import | Operator [`business_cut`](../../apps/operator/src/bin/business_cut.rs), [bounded archive consumer](../../apps/operator/src/business_cut.rs), [shared local pins](../../apps/operator/src/business_pins.rs), [existing SQLite composition](../../apps/operator/src/source_sqlite.rs) | [private cut derivation](../../crates/node-core/src/business_reconstruction/cut/derive.rs), [original proof owner](../../crates/node-core/src/business_reconstruction/cut/proof.rs), [closed codec](../../crates/node-core/src/business_reconstruction/cut/codec.rs) and [bounded transfer](../../crates/node-core/src/business_reconstruction/cut/transfer.rs) | [single-token core capture](../../crates/node-core/src/business_reconstruction/cut/source.rs), [immutable archive owner](../../apps/operator/src/immutable_archive.rs), [real SQLite/executable acceptance](../../apps/operator/tests/business_cut_sqlite.rs), [independent vectors](../../scripts/business-cut-vectors.mjs) |
| Verified import-only namespace, not serving activation | Operator [`business_import`](../../apps/operator/src/bin/business_import.rs), [local composition](../../apps/operator/src/business_import.rs) and shared local pins | [opaque raw plan and complete comparison](../../crates/node-core/src/business_reconstruction/inactive_import.rs), [fenced core origin gate](../../crates/node-core/src/mutation_fence.rs), [typed runtime lifecycle/batches](../../crates/runtime/src/inactive_import.rs) | Dedicated native SQLite import target, atomic shared SQL metadata/row installation, live HTTP cached-output guards and independently selected Ordinary-only PostgreSQL; [DR-0176](../architecture/decisions/0176-verified-inactive-business-import.md) keeps readiness/Seal/activation separate |
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
