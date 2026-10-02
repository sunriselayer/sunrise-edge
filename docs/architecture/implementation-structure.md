# Implementation structure and refactoring boundaries

This is the responsibility-oriented target for organizing the implementation,
not a second roadmap. Current owners are navigated through the
[code map](../development/code-map.md); scheduling, status and completion gates
belong only in [TODO.md](../../TODO.md).
[DR-0173](decisions/0173-integrated-implementation-refactoring.md) records why
refactoring is integrated with functional delivery rather than a prerequisite
repository rewrite.

## What organization should achieve

Make it possible to change one authority or lifecycle without reopening
unrelated codecs, provider plumbing and application behavior. A useful split
has one semantic owner, a small explicit interface and directly attributable
tests. File length alone is not a reason to introduce a module or crate.
Many large test suites are already extracted; count production responsibilities
separately from fixture and test code. No compilation/runtime improvement is
claimed without measurement.

Preserve the state-machine model: one explicit bounded invocation, authenticated
inputs, deterministic effects and confirmed durable output. Process lifetime,
transport authentication and provider placement do not confer protocol authority.

## Dependency and ownership direction

| Layer | Owns | Must not own |
| --- | --- | --- |
| Protocol foundations | Canonical framing, IDs, hash/signature domains, objects, ABI and committed protocol configuration | HTTP, provider APIs or execution orchestration |
| Execution and consensus | Deterministic contract execution, owned quorum verification and shared ordering rules | Store placement, local writer counters or a Standard Asset admission exception |
| Runtime contracts | Explicit operation context, bounded transaction/receipt/object/outbox/portable-read contracts and implementations used by reconstruction | Consensus authority or deployment readiness decisions |
| Node core | Authenticated admission, replay, lifecycle authority and atomic effect composition using execution/consensus/runtime contracts | HTTP credentials, provider SDKs, native asset balances or a transport-controlled serving epoch |
| Stores and hosts | Implement the runtime contract, trusted physical placement/fencing and bounded ingress/composition | Alternate business rules or arbitrary cross-store partial application |
| Wire, SDK and CLI | Closed frames, local pins, authenticated acknowledgement verification and exact retained artifacts | Replacing core authorization, manufacturing cut completeness or accepting peer context as a signing pin |

This is a logical ownership direction, not a claim that every current Cargo
edge already follows a minimal SDK graph. `node-wire` imports core errors,
receipts and query types; the Rust client depends on node-core and reexports
ordered-economics types. Keep those couplings explicit. Any later removal needs
a deliberate public-type owner and byte/API compatibility plan, not a new
foundational crate containing node-core execution logic.

## Concrete refactoring seams

The following are intended module responsibilities inside existing crates.
Names describe targets, not already-created files or mandatory standalone PRs.
Extract only the seams that a real change uses; preserve existing public
paths through reexports where possible. The active integration order is in TODO.

| Existing owner and concrete seam | Intended responsibilities | Boundary to retain |
| --- | --- | --- |
| [Core facade](../../crates/node-core/src/lib.rs): `NodeCoreError`, event/output codecs, durable invocation and outbox recovery | `error`, `event`, `invocation`, `outbox`, explicit preinstalled integration; a facade that composes them | Receipt-first replay, nonce/object dispatch and checkpoint/fence checks remain coupled by the same invocation contract. A mechanical move cannot revive a deleted asset-only path |
| [Runtime facade](../../crates/runtime/src/lib.rs), private [operation context](../../crates/runtime/src/operation.rs) and [composition](../../crates/runtime/src/composition.rs) owners | Operation owns writer fence, deadline, correlation and pre-dispatch cancellation. Composition owns explicit component wiring and memory-runtime assembly. The root reexports their existing public API; state transactions, objects, receipt/outbox, repository traits and memory stores retain their own responsibilities | Memory stores are used by genuine private reconstruction, not only tests. Keep them ordinarily compiled; do not weaken bounds or change durable outcomes during extraction |
| [Ordered engine](../../crates/node-core/src/ordered_economics/engine.rs): output codecs, retained records, `MergedWrites`, `finalize_event`, reconstruction entrypoints | Results/codecs, local records, atomic commit assembly and a narrow reconstruction bridge | Live and private reconstruction share the owning candidate executor. Original receipt, business effects, consensus progress and exact reservation release keep one atomic completion |
| [Frontier](../../crates/node-core/src/ordered_economics/frontier.rs) and [drain union](../../crates/node-core/src/ordered_economics/drain_union.rs): signer streams, publication import and union readiness | Stream verification, artifact retention, union derivation and local records; small checked-read/transaction assembly primitives only where semantics coincide | Freeze authority, terminal signed stream proofs, possession before voting and member completion remain distinct. Similar `put_read`/`commit_row` helpers do not justify a universal handler framework |
| [Business reconstruction](../../crates/node-core/src/business_reconstruction.rs): material extraction, producer indexes, dependency traversal, Freeze barrier and carrier normalization | Source material, producer catalog/scheduling, owned replay and carrier projection behind the existing private overlay facade | Supplied outcomes are comparison targets, never execution authority. Normal and frozen-member completions need their own verifying carrier, not an invented availability certificate |
| [Paid admission](../../crates/node-core/src/paid_execution.rs): scope, application and nonce/lock modes | Scope loading, application admission, lock admission and commit composition behind `PaidAdmissionOutput` | The execution crate already has a reserve/application/settle coordinator. Reuse it; no second fee engine, unchecked mode or asset-native amount rewrite |
| [Shared SQL engine](../../crates/runtime-sql-durable/src/engine.rs), [native SQLite composition](../../crates/runtime-sqlite/src/structured.rs), [PG store](../../crates/runtime-postgres/src/lib.rs) | Authority/schema lifecycle, state, objects, invocation/receipt and outbox internals | SQLite already forwards SQL and decisions to the shared engine used by DO. Preserve that reuse; do not force PostgreSQL pooling/retry behavior into an unsuitable SQLite abstraction |
| [Outgoing Seal storage](../../crates/runtime/src/outgoing_seal.rs), [shared SQL Seal completion](../../crates/runtime-sql-durable/src/engine/outgoing_seal.rs) and [ordered Seal](../../crates/node-core/src/ordered_economics/seal.rs) | Runtime owns protected metadata and atomic continuity; core owns certificate authority, independent reconstruction and selected consensus history | A real same-store capability consumes the original snapshot token. Ordinary writers cannot bypass Sealed, unsupported providers cannot fake completion, and storage never decides successor eligibility or activation |
| [Native ingress](../../crates/native-http/src/lib.rs) and [DO host](../../adapters/cloudflare-workers/rust/src/lib.rs) | Serving, shared blocking admission, query context, recovery and trusted composition; capability-specific provider dispatch | Preserve authentication before I/O, one permit pool and closed certified routes. Generic event proxy ingress must not acquire handoff authority; core must guard inactive imports |
| [FastVote client](../../clients/rust/src/fastvote_client.rs), [ordered client](../../clients/rust/src/ordered_economics_client.rs), [local genesis primitives](../../clients/rust/src/local_genesis.rs) and [transport](../../clients/rust/src/transport.rs) | Local genesis primitives own bounded file reads, signed manifest verification and committee conversion; clients retain their own profile/policy checks and public errors | Share verified primitives, not a peer-chosen trust context. Genesis trust and verified live serving context are different. Transport policy remains separate |
| [CLI network commands](../../apps/cli/src/commands/fastvote_network.rs), [ordered commands](../../apps/cli/src/commands/ordered_economics_network.rs), [network artifact primitives](../../apps/cli/src/commands/network_artifacts.rs) and [operator economics](../../apps/operator/src/economics.rs) | Commands-private artifact I/O owns reservations, held handles and synchronization; network configuration and operation-specific workflows stay with their command owners | Keep pre-reserved paths, held file handles, file/parent synchronization and exact bytes. Offline and certified-network operations do not share authority merely because file utilities match |

The rows are an inventory, not ten obligatory cleanup PRs. In particular,
complete drained-history support can reorganize its material/projection/replay
seams in the same feature; import can clarify runtime/store seams; epoch
rollover can clarify ordered commit and serving-context ownership. Unrelated
core/SQL facade extraction is optional parallel work, not a new activation gate.

## Handoff-specific ownership

Use the accepted [epoch-handoff](epoch-handoff.md) authority chain:

1. Authenticated source material and owning execution produce a complete
   pre-Seal business cut. Verify normal and genuine frozen-member completions;
   retention by itself is not application. Keep cut derivation independent of
   physical revisions and distinguish authority companions from business roots.
2. A persistent importer consumes that verified identity into a fresh inactive
   namespace under its own writer fence. Import progress, completeness and
   active serving authority are different states. Put the guard where business
   mutation and signatures are authorized, not only in an HTTP router.
3. Readiness proves the locally verified cut and an eligible proposed next set.
   Corrected pre-Seal candidates remain possible. Ordered Seal fixes the target;
   activation verifies the same authority and atomically installs the next
   serving policies/provenance without overwriting old consensus history.
   First-epoch Seal itself follows [DR-0187](ordered-seal.md): every fresh
   signature uses the same independently reconstructed business state and
   original snapshot token, and accepted completion atomically halts outgoing
   signatures and ordinary writes. Historical reads and original receipt replay
   stay separate from any future successor-serving capability.
4. SDK/CLI/hosts transport these exact artifacts and bind responses, but cannot
   create completeness or use a remote readiness signature instead of local
   verification. Historical request replay stays exact before fresh authority
   resolution.

Do not turn these steps into a single public `trusted=true` flag, general
maintenance bypass or shared mutable context with implicit state transitions.
Privately constructed verified capabilities and typed states must make the
distinction explicit. Their final API is chosen with the implementing feature,
not invented by this structural plan.

## Tests and validation follow the owning boundary

| Boundary | Evidence to preserve during restructuring |
| --- | --- |
| Defining type/codec | Stable byte vectors, bounds, unknown/trailing-field refusal and independent encoders |
| Core authority/commit | Authentic positive control and adversarial replay, wrong authority, request conflict, bounded-work and rejected/indeterminate commit cases; original receipts and state unchanged where required |
| Reconstruction/cut/import | Owning deterministic execution, source immutability, complete semantic collections/artifact closure, omitted/foreign/duplicate material refusal and inactive-state negatives |
| Durable implementation | Real file close/reopen, writer fencing, atomicity, tombstones, snapshot continuity and ambiguity; shared inputs with backend-specific execution |
| Host and CLI | Real authenticated router and compiled-CLI flow, retained byte identity, response binding, pre-sign pins and interruption/replay |
| Provider qualification | Actual selected profile and deployment-specific restart/fault evidence; local workerd or namespace tests are not operational independence |

Keep fixtures near their semantic owner. Share builders for unchanged signed
inputs and test environments; do not share an implementation-derived oracle
with the assertion meant to catch it. Avoid one enormous generic fixture that
initializes unrelated subsystems for each unit test. Negative cases retain an
independent valid positive control and check both receipts and business state.
Moving an existing real-store test to a mock is a coverage change, not cleanup.

[Repository validation](repository-validation.md) and DR-0172 define the gate.
Focused iterations and the four required DB-free lanes are distinct from
explicit full PostgreSQL acceptance. Generic authority changes still need
integration evidence proportional to their actual effects; a modularization
does not exempt them. No new heavy backend-every-PR gate is introduced here.

## Refactor acceptance and non-goals

A purely structural change must identify moved symbols/owners, preserve public
API paths and canonical output, keep all existing positive/negative checks and
pass the required gate plus independent exact-head review/CI. Record mechanical
moves separately from authority changes even if both belong to one coherent
feature PR. In Rust, keep explicit types at transaction and collection seams;
do not replace readable typed code with inference-heavy generic dispatch macros.

Do not add a crate just to meet a line-count target; rewrite working execution
or consensus; merge offline mutation into live network operations; share a
Standard Asset privilege; force every store behind a SQL interface; or split
one validator across independent databases without an accepted atomic commit/
visibility design. Historical verification remains explicit, but unreleased
superseded asset admission shortcuts are not protected compatibility features.

Dependency-light standalone SDK crates, universal store/handler frameworks,
full production provider support and broad SQL/native facade cleanup are not
prerequisites for functional membership and handoff. A future change needs its
own concrete consumer, boundary and evidence, not this inventory as authority.
