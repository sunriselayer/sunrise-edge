# 2026-09-07: Generic contracts and Standard Asset privilege removal

Date: 2026-09-07 (Asia/Singapore).
Decision reference: DR-0111. This dated record captures the discussion and
As-Is/To-Be gap at main commit
`362e7974b494125757983f1e90d683dc30eb31d2` (PR #141).
The living target is [`../design.md`](../design.md); changing implementation
status and the work queue belong only in [`../../TODO.md`](../../TODO.md).
This document is not evidence that the target has been implemented.

## User direction and decision

Prioritize generic contract publication and execution before adding more
Standard Asset-specific features. Preserve Standard Asset as a reusable public
contract standard. Remove privileged Standard Asset execution paths when
replacing them; unreleased backward compatibility is not a reason to retain
them. Research code reuse, instances, upgrades, and object-oriented execution
before implementing another trusted-catalog extension.

Accept immutable published code, authenticated type lineage, independent
instance/state scope, exact signed revision selection, and explicit upgrade
and migration authority as the target. Contract update support is intentional
product behavior, distinct from preserving discarded development fixtures.

## Source comparison and rationale

Sources were read on 2026-09-07. These are external design references, not
claims that Sunrise Edge implements their guarantees.

- [CosmWasm concepts](https://cosmwasm.github.io/tutorial/platform/concepts-overview):
  storing immutable bytecode and instantiating independent state are separate
  operations. Adopt code reuse and instance isolation.
- [CosmWasm migration interface](https://docs.rs/cosmwasm-std/3.0.9/cosmwasm_std/enum.WasmMsg.html):
  an instance administrator selects new code through migration; clearing the
  administrator prevents further migrations. Adopt explicit migration
  authority, without assuming every object must share one mutable instance
  head.
- [Sui package upgrades](https://docs.sui.io/develop/publish-upgrade-packages/upgrade):
  packages remain immutable, upgrades require capability authorization and
  compatibility checks, and older packages remain accessible. Adopt immutable
  revisions and explicit authority; old-code access and mixed-version state
  require deliberate treatment.
- [Sui custom policies](https://docs.sui.io/develop/publish-upgrade-packages/custom-policies):
  capability-based upgrade policy can be restricted or made immutable. It is
  a useful model for extensible custody without node-specific authorization.
- [Solana programs](https://solana.com/docs/core/programs) and
  [deployment](https://solana.com/docs/core/programs/program-deployment): code
  and mutable data are separate; loader-v3 can replace code behind a stable
  program address under upgrade authority, which can be relinquished. Adopt
  explicit state access and revocable upgrade authority. Prefer exact signed
  immutable code references over implicit code replacement at execution time.

These comparisons motivate Sunrise Edge choices; they do not establish
behavioral equivalence to any of the three systems.

## As-Is / To-Be gap

Paths and symbols refer to the snapshot above; line numbers are intentionally
omitted so this record remains usable after edits.

| Area | As-Is evidence | Required replacement |
| --- | --- | --- |
| Publication and resolution | `crates/node-core/src/preinstalled_wasm.rs`: `PreinstalledModuleCatalogEntry`, `resolve_preinstalled_module`; `apps/devnet/src/catalog.rs` builds trusted entries in Rust. `Transaction.module_ref` reuses `ObjectRef` as a registry lookup. | Durable validated publication with explicit code references and no catalog-membership authority. |
| Type declarations | `crates/abi/src/lib.rs`: `ConstructorDeclaration`/`ConstructorRegistry`; trusted per-entrypoint registries are supplied through `PreinstalledTypedEntrypointPolicy`. | Authenticate type namespace/lineage and instance scope; do not let a publisher claim another contract's type or construction rights. |
| Creation | `crates/node-core/src/lib.rs`: `verify_creation`; `PreinstalledObjectCreationPolicy` admits one fresh same-typed output using a verified input as type source. | Public bounded creation with defining-type authority, fresh host-derived IDs, and independently checked effects. Copying an input type is not authority to mint more values. |
| Transfer | `crates/node-core/src/lib.rs`: `synthesize_owner_transition` projects a recipient from args and synthesizes an owner change under a trusted policy. | Public typed transfer operations with verified ownership/type permissions, usable equally by Standard Asset and user contracts. |
| Cross-owner writes | `PreinstalledObjectAccessPolicy` admits an exact entrypoint/index/mode/type/schema exception; generic paths remain sender-only. | Explicit generic ownership/delegation rules. Never turn a publisher's policy declaration into permission to write others' objects. |
| Consumption | Existing authenticated effect translation permits declared sender-owned consumption on generic paths too. | Retain the reusable checks and add defining-type/call-scope authority; consumption itself is not a Standard Asset-only feature. |
| Fees | `crates/node-core/src/fee_effects.rs`: `FeeEffectComposer`; `apps/devnet/src/fee.rs`: `StandardAssetCoinFeeComposer` decodes and rewrites Coin amounts in trusted Rust composition. Generic owned-effects dispatch rejects fee payments. | Uniform fee-aware execution and committed bounded asset settlement code under explicit protocol fee authority. |
| Updates and instances | Trusted module version/hash records do not provide the public lineage, instance, upgrade-capability, and migration lifecycle described here. | Independent immutable revisions, instance isolation, authority, and host-enforced post-migration access rules. |

The node-core policies are structurally generic: this investigation did not
find a literal Standard Asset ID check in those policy mechanisms. The problem
is the trusted-only construction/dispatch boundary and the native asset
settlement callback. Do not misreport this observation as a demonstrated
externally exploitable vulnerability; arbitrary publication is not exposed
through that boundary in this snapshot.

## Review conclusions and rejected shortcuts

Sonnet inspected the existing paths, and Opus critiqued the proposed design.
The parent checked the cited code and selected the conclusions recorded here;
neither review is an implementation audit or approval of future code.

- Reuse sound validation and persistence machinery, but reject the suggestion
  that exposing trusted policy constructors is sufficient for permissionless
  publication. Digest verification and structural validation cannot establish
  a publisher's entitlement to a type or another owner's state.
- Keep type lineage distinct from code identity. New implementation bytes
  should not accidentally rename existing assets, while copied bytes must not
  inherit the original lineage's authority.
- Avoid competing instance/type authority systems and a mandatory shared
  writable root for all calls. Any shared upgrade switch needs explicit
  ordering against dependent calls.
- Enforce migrated-object revision authorization in the host and validate
  mixed-revision multi-object operations. ABI compatibility alone cannot prove
  supply conservation or other semantic invariants.
- Reject moving Coin split/merge or supply arithmetic into host primitives as
  a shortcut to upgrade safety. Those rules remain contract logic; generic
  authority and lifecycle checks belong in the host.
- Keep the distinction between a pre-execution rejection and an execution
  trap that charges fees. Replay must reapply neither application nor fees.

## Follow-through

The Generic Contract Publication Gate in TODO must include instance isolation,
type authority, Standard Asset parity, and removal of trusted-only paths.
Concrete identity derivation, wire IDs, verifier rules, upgrade policies,
migration authorization, call limits, and fee-settlement budgeting require
implementation decisions and tests; this record does not invent finalized
encodings or claim Move-level static verification.
