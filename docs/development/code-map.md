# Code ownership map

This is an As-Is navigation map, not another architecture specification or a
feature-status report. Accepted design and decisions live in
[architecture](../architecture/README.md); current completion gates live only
in [`TODO.md`](../../TODO.md). Update this map when responsibility moves, not
for every new function.

The [implementation structure](../architecture/implementation-structure.md)
describes intended responsibility boundaries, not existing file locations.
Its integrated implementation/refactoring queue remains only in TODO.

The private [declared-state preparation owner](../../crates/node-core/src/state_transition.rs)
shares the five legacy/structured-durable snapshot loaders and the two distinct
state assembly strategies. The facade retains admission and commit ordering,
object authority and caller-local read errors. Independent [public-library
baselines](../../crates/node-core/tests/declared_state_contract.rs), [actual durable
caller controls](../../crates/node-core/src/tests/declared_state_durable_contract.rs)
and [private priority controls](../../crates/node-core/src/tests/state_transition.rs)
separately pin those boundaries. The native closed event endpoint owns no
execution/storage capabilities (DR-0206); its canonical decoder returns only
a refusal. Authenticated hosts and standalone recovery have separate owners.

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

The pure [`node-core::envelope`](../../crates/node-core/src/envelope.rs)
owner defines request/event/response/dedup data, canonical nested lists and
their bounds. The core facade reexports existing type paths and retains event
digest/context authority. `node-wire` consumes that list codec and owns only
HTTP result framing, outer-request binding and the single-acknowledgement view.
Its narrow errors do not remove the remaining real core verifier Cargo edges.

## Find the owner

| Capability | Entry and wire | Decision and effects | Storage and representative tests |
| --- | --- | --- | --- |
| Canonical identities, transactions and access | [`protocol-types`](../../crates/protocol-types), [`canonical-encoding`](../../crates/canonical-encoding), [`objects`](../../crates/objects), [`abi`](../../crates/abi); HTTP frames in [`node-wire`](../../crates/node-wire) | Each defining crate owns its type IDs, encoders, bounds and stable vectors | Encoding tests in the defining crates and [`node-wire`](../../crates/node-wire/src/lib.rs) |
| Node envelopes and SDK acknowledgement syntax | [Pure envelope/list owner](../../crates/node-core/src/envelope.rs), [HTTP frame and bound views](../../crates/node-wire/src/lib.rs), actual paid/FastVote/publication/local SDK consumers | Core-owned context/hash checks and each SDK family's outcome/hash/status verifiers remain separate; flat error conversion preserves host classification | [Pre-move literal vectors](../../crates/node-core/src/tests/envelope_vectors.rs), [envelope ordering tests](../../crates/node-core/src/tests/envelope_contract.rs), [wire bound tests](../../crates/node-wire/src/http_node_result_tests.rs), [native mapping](../../crates/native-http/src/tests/envelope_classification.rs) and shared SDK [untrusted inputs](../../clients/rust/tests/support/acknowledgement.rs). Input builders are not expected-result oracles |
| Publish, Instantiate and Call | [CLI contract commands](../../apps/cli/src/commands/contract.rs), [Rust publication client](../../clients/rust/src/publication_client.rs), [native HTTP](../../crates/native-http/src/publication.rs) | [`node-core` publication](../../crates/node-core/src/publication.rs) and [local execution](../../crates/node-core/src/local_execution.rs) coordinate [execution publication](../../crates/execution/src/publication) and [call](../../crates/execution/src/call.rs) | [`runtime` transaction contract](../../crates/runtime/src/lib.rs); [publication tests](../../crates/node-core/src/publication/tests.rs), [local execution tests](../../crates/node-core/src/local_execution/tests.rs), [HTTP tests](../../crates/native-http/src/tests/local_execution_http.rs) |
| Standard Asset and paid execution | [contract package](../../contracts/standard-asset), [CLI paid commands](../../apps/cli/src/commands/paid_execution.rs), [HTTP paid route](../../crates/native-http/src/paid_execution.rs) | [execution fee/effect logic](../../crates/execution/src/paid_execution.rs) and [node-core paid admission](../../crates/node-core/src/paid_execution.rs); the contract owns asset semantics | [paid core tests](../../crates/node-core/src/paid_execution/tests.rs) and durable store conformance |
| Owned-object FastVote | [HTTP routes](../../crates/native-http/src/fastvote.rs), [Rust quorum client](../../clients/rust/src/fastvote_client.rs) | [consensus certificate rules](../../crates/consensus/src/fast_vote.rs) and [node-core prepare/apply](../../crates/node-core/src/fast_path.rs) | [`runtime` atomic commit](../../crates/runtime/src/lib.rs); [core tests](../../crates/node-core/src/fast_path/tests.rs), [HTTP tests](../../crates/native-http/src/tests/fastvote_router.rs) |
| Immutable original genesis trust | [Bounded SDK file loader](../../clients/rust/src/local_genesis.rs), [private FastVote bundle](../../clients/rust/src/fastvote_client.rs), [operator business pins](../../apps/operator/src/business_pins.rs) | [Verified root](../../crates/node-core/src/genesis/root.rs) owns signed-manifest/pin authentication, its exact resolver, profile and original committee; [genesis](../../crates/node-core/src/genesis.rs) owns shared strict primitives. Raw installation and actual installed-row/live-pin checks remain distinct | [Root negatives](../../crates/node-core/src/genesis/root/tests.rs), [frozen pre-migration baselines](../../crates/node-core/src/genesis/root_baseline_tests.rs), [SDK loader diagnostics](../../clients/rust/src/local_genesis/tests.rs), compiled CLI/operator and real reconstruction workflows; immutable genesis evidence grants no current serving or activation authority |
| FastVote committee record structure | [Core bounded row adapter](../../crates/node-core/src/fast_path.rs), [genesis and installed-chain verifier](../../crates/node-core/src/genesis.rs), [Freeze](../../crates/node-core/src/ordered_economics/freeze.rs), [activation derivation](../../crates/node-core/src/epoch_transition.rs), operator startup and CLI | [Pure typed validator](../../crates/node-core/src/fast_path/committee.rs) owns expected context, Ed25519-only registration and the existing generic set rules; actual callers retain capacity, ordering, digest, observation, certificate and activation authority | [Pure error-order negatives](../../crates/node-core/src/fast_path/committee/tests.rs), [genuine installed-chain restart negatives](../../crates/node-core/src/epoch_transition/tests.rs), [matching-digest SQLite startup pin](../../apps/operator/tests/fastvote_startup_pin.rs); structural validity grants no serving or successor authority |
| Immutable reconstruction configuration | [Business overlay](../../crates/node-core/src/business_reconstruction.rs) and [public control collector](../../crates/node-core/src/business_reconstruction/control.rs) | [Private two-stage binding](../../crates/node-core/src/business_reconstruction/root_policy_binding.rs) owns exact causal root/policy/domain/committee/full-schedule equality and canonical signed-Freeze anchor rederivation; overlay companions and genuine ordered-history verification retain their own owners | [Overlay substitution and error-order negatives](../../crates/node-core/src/ordered_economics/tests/causal_placement/business_reconstruction.rs), [genuine public control substitution/positive tests](../../crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction.rs), existing complete saved-cut, import/reopen/fencing consumers; agreement is not a cut, destination completion or activation token |
| Local artifact primitives | [CLI network artifacts](../../apps/cli/src/commands/network_artifacts.rs) | Bounded I/O, fresh reservations and held-handle synchronization, not operation authority or cryptographic verification | [CLI artifact tests](../../apps/cli/src/commands/network_artifacts/tests.rs) and existing network workflow tests; transport and offline operator authority remain separate |
| Shared ordering and economics | [ordered HTTP surface](../../crates/native-http/src/ordered_economics.rs), [Rust client](../../clients/rust/src/ordered_economics_client.rs), [operator](../../apps/operator/src/economics.rs) | [consensus ordering](../../crates/consensus/src/durable.rs), [node-core ordered effects](../../crates/node-core/src/ordered_economics.rs), [bond lifecycle](../../crates/node-core/src/bond_lifecycle.rs) | [ordered core tests](../../crates/node-core/src/ordered_economics/tests.rs) and store-backed operator tests |
| Original ordered results, separate from fresh admission | Existing ordered proposal and outcome-query routes | Private [request reconciliation](../../crates/node-core/src/ordered_economics/engine.rs) checks only the immutable header and outcome/receipt relationship; an unfinished result grants no admission or signing authority. Actual admission separately fences the installed profile and consumes the same binding observations in its atomic write | [Real inactive-import/reopen controls](../../crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction/frozen_completion/inactive_business_import.rs) distinguish exact original replies from genuine uncompleted and cached-signature refusals; partial imports do not become signing stores |
| Initial non-genesis validator bond | [SDK registration context](../../clients/rust/src/bond_registration.rs), [CLI preparation and wrapping](../../apps/cli/src/commands/bond_registration.rs), ordinary ordered submission | [registration authentication and custody owner](../../crates/node-core/src/bond_lifecycle/registration.rs), [generic effects and atomic registration](../../crates/node-core/src/bond_lifecycle/registration/handler.rs), early pristine-slot CAS in [ordered reservation](../../crates/node-core/src/ordered_economics/reservation.rs) | [genuine paid registration and refusal tests](../../crates/node-core/src/ordered_economics/tests/causal_placement/registration.rs), [actual SQLite reconstruction/restart](../../crates/node-core/src/ordered_economics/tests/causal_placement/registration/sqlite.rs); a bond is not committee membership or serving authority |
| Ordered Freeze and immutable frontier | [CLI frontier commands](../../apps/cli/src/commands/fastvote_frontier.rs), [Rust frontier client](../../clients/rust/src/fastvote_frontier_client.rs), certified HTTP routes | [Freeze authority](../../crates/node-core/src/ordered_economics/freeze.rs), [frontier retention/export](../../crates/node-core/src/ordered_economics/frontier.rs), [canonical frontier proofs](../../crates/consensus/src/availability/frontier.rs) | [Freeze tests](../../crates/node-core/src/ordered_economics/tests/freeze_boundaries.rs), [frontier tests](../../crates/node-core/src/ordered_economics/frontier/tests.rs); closed frontier is not a complete business cut |
| Quorum-retained DrainSet and member completion | [HTTP drain surface](../../crates/native-http/src/fastvote/drain.rs), [Rust drain client](../../clients/rust/src/fastvote_drain_client.rs), [CLI member command](../../apps/cli/src/commands/fastvote_drain_member.rs) | [union retention](../../crates/node-core/src/ordered_economics/drain_union.rs), [ordered DrainSet](../../crates/node-core/src/ordered_economics/drain_set.rs), [narrow member apply](../../crates/node-core/src/fast_path/drain_apply.rs) | [union tests](../../crates/node-core/src/ordered_economics/drain_union/tests.rs), [member apply tests](../../crates/node-core/src/fast_path/drain_apply/tests.rs); retention does not itself execute business effects |
| Authenticated ordering history, not business-state import | [history wire](../../crates/node-wire/src/ordered_history.rs), [Rust history client](../../clients/rust/src/ordered_history_client.rs), CLI `economics history-export` | [per-height consensus proofs](../../crates/consensus/src/commit_proof.rs), [core archive and pure verifier](../../crates/node-core/src/ordered_economics/ordered_history.rs) | Immutable archives join the original atomic commit; [core history tests](../../crates/node-core/src/ordered_economics/tests/ordered_history.rs), [compiled CLI / real PostgreSQL acceptance](../../apps/operator/tests/support/ordered_history_acceptance.rs) |
| Causal admission and fixed-snapshot business audit | [profile-aware Rust client](../../clients/rust/src/causal_admission.rs), [saved-history reader](../../clients/rust/src/ordered_history_archive.rs), operator [`business_audit_pg`](../../apps/operator/src/bin/business_audit_pg.rs) | [locally verified profile](../../crates/node-core/src/admission_profile.rs), [private causal reconstruction](../../crates/node-core/src/business_reconstruction.rs), [closed comparison](../../crates/node-core/src/business_reconstruction/projection.rs); ordered local schemas remain owned by [ordered projection](../../crates/node-core/src/ordered_economics/audit_projection.rs) | [backend-neutral single-token capture](../../apps/operator/src/business_snapshot.rs), [real SQLite collector tests](../../apps/operator/tests/business_snapshot_sqlite.rs), [compiled CLI/PG acceptance](../../apps/operator/tests/business_audit_pg_e2e.rs); reconstruction has no source-write/import/readiness capability |
| Epoch membership and transition | [consensus epoch types](../../crates/consensus/src/epoch_transition.rs) and network/operator surfaces above | [node-core epoch transition](../../crates/node-core/src/epoch_transition.rs) owns mutation authorization | [runtime transaction contract](../../crates/runtime/src/lib.rs), [PostgreSQL store](../../crates/runtime-postgres/src/lib.rs), [epoch tests](../../crates/node-core/src/epoch_transition/tests.rs) |
| First-epoch pre-Seal candidate export, not persistent import | Operator [`business_cut`](../../apps/operator/src/bin/business_cut.rs), [bounded archive consumer](../../apps/operator/src/business_cut.rs), [shared local pins](../../apps/operator/src/business_pins.rs), [existing SQLite composition](../../apps/operator/src/source_sqlite.rs) | [private cut derivation](../../crates/node-core/src/business_reconstruction/cut/derive.rs), [original proof owner](../../crates/node-core/src/business_reconstruction/cut/proof.rs), [closed codec](../../crates/node-core/src/business_reconstruction/cut/codec.rs) and [bounded transfer](../../crates/node-core/src/business_reconstruction/cut/transfer.rs) | [single-token core capture](../../crates/node-core/src/business_reconstruction/cut/source.rs), [immutable archive owner](../../apps/operator/src/immutable_archive.rs), [real SQLite/executable acceptance](../../apps/operator/tests/business_cut_sqlite.rs), [independent vectors](../../scripts/business-cut-vectors.mjs) |
| Verified import-only namespace, not serving activation | Operator [`business_import`](../../apps/operator/src/bin/business_import.rs), [local composition](../../apps/operator/src/business_import.rs) and shared local pins | [opaque raw plan and complete comparison](../../crates/node-core/src/business_reconstruction/inactive_import.rs), [fenced core origin gate](../../crates/node-core/src/mutation_fence.rs), [typed runtime lifecycle/batches](../../crates/runtime/src/inactive_import.rs) | Dedicated native SQLite import target, atomic shared SQL metadata/row installation, live HTTP cached-output guards and independently selected Ordinary-only PostgreSQL; [DR-0176](../architecture/decisions/0176-verified-inactive-business-import.md) keeps readiness/Seal/activation separate |
| Conditional successor readiness, not Seal or activation | Operator [`conditional_readiness`](../../apps/operator/src/bin/conditional_readiness.rs), [held local composition](../../apps/operator/src/conditional_readiness.rs), [public frames and weighted certificate](../../crates/consensus/src/readiness.rs) | [private producer](../../crates/node-core/src/conditional_readiness.rs) freshly reconstructs and compares the entire inactive target, checks eligible actual keys and binds the complete local schedule before protected retention | [narrow runtime contract](../../crates/runtime/src/conditional_readiness.rs), [atomic shared SQL owner](../../crates/runtime-sql-durable/src/engine/inactive_import/conditional_readiness.rs), [SQLite fault tests](../../crates/runtime-sqlite/src/structured/inactive_import/tests/readiness.rs), [genuine A/B/C/E imports](../../crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction/frozen_completion/conditional_readiness.rs) and [compiled operator workflow](../../apps/operator/tests/conditional_readiness_sqlite.rs); public readiness never authorizes live signing or serving |
| First-epoch outgoing Seal, not successor activation | Operator [unsigned preparation](../../apps/operator/src/ordered_seal.rs), existing ordered network client and typed [native host composition](../../crates/native-http/src/ordered_economics.rs) | [Seal codecs and warrant](../../crates/node-core/src/ordered_economics/seal.rs), [ordered engine](../../crates/node-core/src/ordered_economics/engine.rs) and private [cut closure](../../crates/node-core/src/business_reconstruction/cut.rs) own independent authority and original token retention | [Protected barrier and narrow capability](../../crates/runtime/src/outgoing_seal.rs), [shared SQL atomic owner](../../crates/runtime-sql-durable/src/engine/outgoing_seal.rs), [SQLite storage tests](../../crates/runtime-sqlite/tests/sqlite_structured.rs), [compiled preparation and four-store HTTP acceptance](../../apps/operator/tests/conditional_readiness_sqlite.rs), [independent vectors](../../scripts/ordered-seal-vectors.mjs). Progress and validation remain only in TODO |
| Object, receipt, nonce and context queries | [native HTTP query routes](../../crates/native-http/src/lib.rs), [query result codec](../../crates/node-wire/src/lib.rs) | [node-core query](../../crates/node-core/src/query.rs) validates committed state; queries do not authorize mutation | [query codec tests](../../crates/native-http/src/tests/query_codecs.rs), [HTTP query tests](../../crates/native-http/src/tests/query_http.rs) |
| Closed unauthenticated event ingress | `native_http::closed_event_router` and its shared-executor constructor | Bounded HTTP/canonical refusal only; no runtime, store, signer, configuration, execution callback or lease source can be injected. No query/recovery route is mounted | [Native closed ingress and unchanged authenticated side-effect tripwires](../../crates/native-http/src/tests.rs); [DR-0206](../architecture/decisions/0206-unauthenticated-ingress-without-execution-capabilities.md) |
| Storage implementations | No request supplies its own authoritative domain or writer generation | [`runtime` traits](../../crates/runtime/src/lib.rs) define atomic state, receipts, objects, outbox and fencing | [PostgreSQL](../../crates/runtime-postgres/src/lib.rs), [SQLite](../../crates/runtime-sqlite/src/lib.rs), [SQL-durable](../../crates/runtime-sql-durable/src/lib.rs); [PostgreSQL tests](../../crates/runtime-postgres/tests), [SQLite tests](../../crates/runtime-sqlite/tests) |
| Runtime operation context and component composition | Existing public paths remain reexported from [`runtime`](../../crates/runtime/src/lib.rs); no request supplies authority | Private [operation](../../crates/runtime/src/operation.rs) owns writer fence, deadline, correlation and pre-dispatch cancellation; private [composition](../../crates/runtime/src/composition.rs) wires supplied state/blob/signing/transport/time/scheduler components | Existing bounds/cancellation tests and [root-API component wiring tests](../../crates/runtime/src/tests.rs). Memory stores stay ordinarily compiled for private reconstruction; wiring does not certify provider durability |
| Observed transaction assembly and read-only verification | [`runtime` transaction builder](../../crates/runtime/src/transaction.rs) and [state/structured read ports](../../crates/runtime/src/state_read.rs), reexported from the runtime facade | Domain-bound observation consistency, explicit strict/exact mutation composition and shared bounds; [paid completion](../../crates/node-core/src/paid_execution.rs) and [fee claims](../../crates/node-core/src/fee_claims.rs) own their strict assembly. Read-only [prepared material](../../crates/node-core/src/fast_path/prepared_material.rs) and [bond-chain verification](../../crates/node-core/src/bond_lifecycle/registration/handler.rs) do not own persistence | [Assembly tests](../../crates/runtime/src/transaction/tests.rs), [genuine paid refusal/replay regression](../../crates/node-core/src/paid_execution/observed_completion_tests.rs), reader negative-capability doc tests, real adapter checks and existing captured reconstruction tests. A builder/reader is not an authenticated snapshot, protocol warrant or confirmed write |
| Writer-free original operation and atomic ordered completion | Private [owning proposals](../../crates/node-core/src/operation_preparation.rs), the fee/bond/evidence/control owners above and actual direct committing wrappers | [Observed read scope](../../crates/node-core/src/ordered_economics/observed_read.rs) records deciding physical CAS reads for execution and signing; [completion](../../crates/node-core/src/ordered_economics/completion.rs) shares original evaluation and real confirmation across live/recovery/private replay. Business owners retain their separate logical generation operands; no intercepted commit or fake writable store remains | Genuine preparation tests in each owner, [observation negatives](../../crates/node-core/src/ordered_economics/observed_read/tests.rs), [completion negatives](../../crates/node-core/src/ordered_economics/completion/tests.rs) and [typed real SQLite handoff faults](../../crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction/frozen_completion/sqlite_handoff_faults.rs). A prepared proposal cannot expose output as confirmed persistence |
| Test observation capabilities, not business fixtures | Private test-only [reader](../../crates/node-core/src/test_support/reader_view.rs), [publication counter](../../crates/node-core/src/test_support/counted_blobs.rs) and [complete capture](../../crates/node-core/src/test_support/capture.rs) | Real fee/bond/registration owners compose genuine prior operations and distinct quorum voters; same-signer mirrors establish complete direct/prepared equality without normalizing local history | [Storage-port capture negatives](../../crates/node-core/src/test_support/capture/tests.rs) exercise real reads and row/body differences, not business authority or blob-backed execution. Production replay/source audit and cut/import comparison keep their distinct owning verifiers |

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

## Original genesis and local startup

- [Offline Standard Asset author](../../apps/operator/src/standard_asset_genesis.rs)
  owns the named explicitly configured operator preset, not template authority
  in node-core. Its [public inputs](../../apps/operator/src/standard_asset_genesis/input.rs)
  and [ordinary manifest builder](../../apps/operator/src/standard_asset_genesis/build.rs)
  are separate from the [fresh single-file output owner](../../apps/operator/src/genesis_output.rs).
  The [actual process tests](../../apps/operator/tests/standard_asset_genesis.rs)
  consume that output through the shipped prepare/preflight/host executables.
- [SQLite genesis orchestration](../../apps/operator/src/sqlite_genesis.rs)
  separates fresh preparation from advisory public-key inspection. The private
  [shared installer composition](../../apps/operator/src/original_genesis_install.rs)
  only calls defining core installers; the
  [shared original startup checks](../../apps/operator/src/sqlite_genesis_checks.rs)
  own committed root/fee/committee agreement and stable advisory observation.
  Serving retains fence acquisition and protected-key derivation. Neither
  author output nor preflight grants network activation authority.
- [Pinned genesis inspection](../../apps/operator/src/genesis_inspection.rs)
  owns closed public pins and secret-free dispatch; its private input/render
  helpers are not authentication owners. Author and inspector reuse one
  [private in-memory installer composition](../../apps/operator/src/original_genesis_install.rs).
  [Disposable signed inputs](../../apps/operator/tests/support/offline_genesis_fixture.rs)
  are shared by genuine author/inspector process tests, without sharing their
  production decisions or fabricating durable rows.
- [Actual local TLS startup](../../apps/operator/tests/local_tls_startup.rs)
  composes those real binaries with four independent SQLite namespaces and the
  ordinary compiled CLI. Its local observation/certificate assertions reuse
  public codec, certifier, fee-quote and complete snapshot owners. The
  [bounded transparent TLS fixture](../../apps/operator/tests/support/https_relay.rs)
  owns only forwarding and transport counters, never a protocol response; its
  two framing cases run once through this integration target. The
  [neutral compiled-CLI locator](../../apps/operator/tests/support/compiled_cli_process.rs)
  is also reused by existing optional PostgreSQL tests, without importing their
  fixture/deployment authority into local acceptance.

## Successor invocation and immutable transport

- [Host runtime pieces](../../apps/operator/src/host_runtime.rs) own the
  shared local Ed25519 signer, original-root fee check and generation-bound
  attempt identities. Each host retains its provider-specific startup order,
  fence claim and original versus successor authority.
  [Original SQLite composition](../../apps/operator/src/sqlite_source_host.rs)
  binds existing paid, FastVote and ordered Seal engines to one owning store;
  it never installs genesis or activates a successor. The PostgreSQL host
  still mounts no Seal capability.
- [Host query configuration](../../apps/operator/src/host_protocol_context.rs)
  carries the independently pinned complete resolver schedule. The shared
  native HTTP query projection resolves the effective epoch freshly, and
  rejects schedule or protocol disagreement. Read-only advertised context
  does not replace the client's independently expected signing context.

- [Core authority](../../crates/node-core/src/serving_authority.rs) separates
  historical evidence from fresh issuer-bound warrants.
  [Chain verification](../../crates/node-core/src/serving_authority/chain.rs)
  owns ordered link budgets, committee/owner provenance and the immutable root;
  [base](../../crates/node-core/src/serving_authority/base.rs) selects the genuine
  reconstruction base. [The shared gate](../../crates/node-core/src/serving_authority/gate.rs)
  selects Original, Successor or private memory-only Replay, including the sole
  Seal port. Replay cannot sign or Seal; no host constructs these private roles.
  [Protected runtime slots](../../crates/runtime/src/successor_serving.rs) and
  backend completion ports own atomic persistence, not eligibility. The checked
  [memory bootstrap](../../crates/runtime/src/inactive_import/memory.rs) is data
  for private reconstruction, never a serving store or restore credential.
- [SDK artifact reader](../../clients/rust/src/immutable_archive.rs),
  [saved-cut reader](../../clients/rust/src/business_cut_archive.rs) and
  [successor artifacts](../../clients/rust/src/successor_artifacts.rs) own one
  bounded held-handle transport policy. The operator publication writer wraps
  that reader rather than duplicating its validation.
- [SDK successor workflow](../../clients/rust/src/successor_authority.rs) owns
  independently verified signing pins; [fee-claim client](../../clients/rust/src/fee_claim_client.rs)
  verifies them inside the signing API. [Native successor adapter](../../crates/native-http/src/successor.rs)
  resolves fresh authority for each request. The loopback host supplies local
  pins, artifacts, store, fence and signer; no response grants authority.
- [Replacement tests](../../crates/node-core/src/ordered_economics/tests/causal_placement/control_reconstruction/frozen_completion/successor_replacement.rs)
  own the real registration/Seal/activation and retired-owner distinction.
  [Process refusal tests](../../apps/operator/tests/successor_host_process_refusals.rs)
  prove executable refusal ordering, not a positive four-host workflow.
