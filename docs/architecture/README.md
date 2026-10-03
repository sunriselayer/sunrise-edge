# Architecture

The accepted generic-contract To-Be is split by responsibility between
[`generic-contracts.md`](generic-contracts.md) and the
[smart-contract documentation](../smartcontract/README.md). Accepted dated
rationale and As-Is gaps are retained in the applicable
[decision records](decisions/README.md), not a parallel meeting-notes tree.
Read those targets before extending trusted preinstalled execution paths.

The architecture is split by responsibility so contributors can read the
smallest relevant document. Implemented canonical bytes, stable vectors, and
accepted decision records remain compatibility constraints even when the
roadmap describes a later target state.

- [Core protocol](core-protocol.md): sections 1–27, from canonical encoding and
  cryptography through consensus, execution, governance, and security.
- [Runtime and ingress](runtime-and-ingress.md): sections 28–40, including the
  node invocation boundary and provider adapters.
- [Persistence](persistence.md): section 41 and the runtime-neutral durable
  state boundary.
- [Developer product surfaces](product-surfaces.md): sections 42–46, covering
  the devnet, query API, Rust client, CLI, and signing host boundary.
- [Implementation structure](implementation-structure.md)
  ([DR-0173](decisions/0173-integrated-implementation-refactoring.md)):
  responsibility-oriented core/runtime/store/host/SDK boundaries, concrete
  extraction seams and behavior-preserving refactor acceptance; scheduling
  remains in TODO.
- [Architecture contracts](architecture-contracts.md)
  ([DR-0180](decisions/0180-architecture-first-interface-contracts.md)):
  responsibility, dependency, typed authority and completion interfaces for
  the architecture-first redesign; interface skeletons do not grant runtime
  authority or functional completion.
- [Immutable genesis trust](genesis-trust.md)
  ([DR-0182](decisions/0182-immutable-verified-genesis-root.md)):
  one privately constructed original trust root and root-derived core/SDK/
  operator composition, separate from installation and current serving powers.
- [Committee record validation](committee-record-validation.md)
  ([DR-0184](decisions/0184-one-fastvote-committee-record-validator.md)):
  one typed structural invariant across core and operator consumers, distinct
  from genesis capacity, historical authentication and live serving authority.
- [Immutable reconstruction configuration](reconstruction-policy-binding.md)
  ([DR-0185](decisions/0185-one-reconstruction-policy-binding.md)):
  one private root/policy/domain and signed-anchor relation used by overlay and
  control collection; independent history, cut and destination evidence remain.
- [Generic contract architecture](generic-contracts.md): common execution and
  authority, type/instance/object separation, upgrades, migration and durable
  verification obligations.
- [Writer-free operation preparation](operation-preparation.md)
  ([DR-0181](decisions/0181-writer-free-operation-preparation.md)):
  business evaluation, physical observations and actual commit are separate
  contracts; logical dependency selection remains owner-specific.
- [Test observation contracts](test-observation-contracts.md)
  ([DR-0183](decisions/0183-test-observation-ownership.md)):
  private reader/counter/capture mechanics, complete direct/prepared persisted
  equivalence, and distinct replay and cut/import comparison responsibilities.
- [Smart contracts](../smartcontract/README.md): publication/call lifecycle and
  Standard Asset/fee semantics.
- [Durable local code publication](decisions/0121-durable-local-code-publication.md):
  authenticated immutable code storage, exact dependency provenance, shared
  nonce/receipt atomicity, and opt-in native HTTP/CLI publication.
- [Local instance execution](decisions/0122-local-instance-execution.md): typed
  host authority, immutable instances, bounded dependency libraries, and atomic
  local execution/replay; distinct from public-network admission.
- [Unified contract calls](decisions/0123-unified-contract-calls.md): one signed
  target/delegated-handle model, scope validation and atomic outcome for every call.
- [FastVote HTTP network](fastvote-network.md): the certified-only,
  opt-in HTTP surface for DR-0130/DR-0129's fast-path prepare/apply and
  quorum certification, its trust/pinning model, and known Phase 1 limits.
- [Offline signed fee claims](decisions/0149-offline-signed-fee-claims.md):
  generic claim preparation and explicitly stopped/fenced single-namespace
  operator execution; distinct from online shared-escrow ordering.
- [Certified-call catch-up](decisions/0150-certified-call-catch-up.md):
  signerless recovery of declared, same-epoch certified calls on a replica
  that missed prepare, without claiming complete state handoff or activation.
- [Integrated network delivery and lightweight stores](decisions/0151-integrated-network-delivery-and-lightweight-stores.md):
  four usable functional outcomes, capability-based persistence profiles,
  single-domain atomicity and the decision to implement the generic certified
  contract lifecycle before the Cloudflare DO profile.
- [Decision records](decisions/README.md): accepted and compatibility-relevant
  decisions grouped into bounded ranges.
- [Embedded DO contract hosting](decisions/0152-durable-object-contract-host.md):
  real Rust/Wasmi execution, shared synchronous SQL validation, confirmed-output
  and single-domain authority boundaries for the experimental lightweight host.
- [Ordered network economics](ordered-economics.md) ([DR-0153](decisions/0153-ordered-network-economics.md)):
  shared HotStuff ordering distinct from owned FastVote, durable reservations,
  atomic economic/order effects and declared signerless recovery.
- [Complete epoch handoff](epoch-handoff.md) ([DR-0154](decisions/0154-complete-epoch-handoff.md)):
  publication-before-apply, quorum-complete frozen frontiers, ordered epoch
  control, portable logical commitments and verified new-validator readiness.
- [Logical execution generation admission](logical-execution-generation.md)
  (DR-0154 slice): the checked causal `ExecutionGeneration` operand, signed
  genesis commitment-profile binding, and per-subject provenance admission
  wired through every live application path; explicit As-Is/To-Be boundary
  against the rest of DR-0154's design.
- [Publication-before-apply availability](publication-availability.md)
  (DR-0154 capability): exact prepared artifacts, execution-free durable
  full-certificate retention, quorum ACKs and proof-gated Logical apply;
  bounded native HTTP, Rust SDK and saved CLI replay, without epoch handoff.
- [Portable storage reconstruction reads](portable-reconstruction.md)
  ([DR-0166](decisions/0166-portable-candidate-snapshot.md)): bounded
  independent durable/blob/outbox reads and an optional backend-enforced
  snapshot-continuity contract for one quiet source; source-local storage
  metadata only, with no cut/import/readiness/Seal/activation claim.
- [Ordered Freeze and immutable frontier extraction](frozen-frontier.md)
  ([DR-0167](decisions/0167-frozen-frontier-extraction-boundary.md)):
  the fresh signed-profile boundary for the next core/HTTP/SDK/CLI capability;
  no local unfreeze, drain authority or new-epoch activation is implied.
- [Quorum-retained DrainSet and member drain](quorum-drain.md)
  ([DR-0168](decisions/0168-quorum-retained-drainset-and-member-drain.md)):
  complete selected frontier union, pre-vote full proof possession, imported
  proof relay and explicit committed-member application; no cut or activation.
- [Authenticated ordered-history export](ordered-history.md)
  ([DR-0169](decisions/0169-authenticated-ordered-history-export.md)):
  full per-height commit witnesses, contiguous genesis-to-target verification
  and bounded saved export; source completion companions are not an
  independently reconstructed business cut or import authority.
- [Causal business reconstruction and semantic audit](business-reconstruction.md)
  ([DR-0170](decisions/0170-causal-business-reconstruction.md)):
  signed causal admission, disjoint external request lanes, private verified
  execution and closed real-store comparison; no persistent import or activation.
- [Frozen member business reconstruction](decisions/0174-frozen-member-business-reconstruction.md):
  independently replayed committed Freeze/DrainSet and narrow member execution
  for a completed source without aggregate availability; not complete cut/import.
- [First-epoch pre-Seal business cut](first-epoch-business-cut.md)
  ([DR-0175](decisions/0175-first-epoch-preseal-business-cut.md)):
  private complete-drain derivation, separate semantic/package identity and
  bounded independently reverified saved export; not import, Seal or activation.
- [Verified inactive business import](verified-inactive-import.md)
  ([DR-0176](decisions/0176-verified-inactive-business-import.md)):
  private raw-plan derivation, permanent import origin, atomic bounded storage
  and core/live-response guards; no readiness, Seal or activation authority.
- [Conditional readiness and ordered Seal](conditional-readiness-seal.md)
  ([DR-0178](decisions/0178-conditional-readiness-wire-and-retention.md)):
  private fresh staging verification, actual-key-bound votes, weighted public
  certificates and protected per-identity retention; no serving authority.
  Seal traversal follows the separate DR-0187 contract below; successor
  activation requires its own serving-authority contract.
- [Functional handoff closure](functional-handoff-closure.md)
  ([DR-0186](decisions/0186-functional-handoff-closure.md), Proposed):
  staged namespace/crash ordering, retained Seal companions, complete suffix
  verification and snapshot-covered serving activation; not code authority.
- [First-epoch ordered Seal](ordered-seal.md)
  ([DR-0187](decisions/0187-first-epoch-ordered-seal.md)):
  accepted hard-stop authority, private exact acceptance terminal and permanent
  token-checked outgoing barrier contract; not successor activation or serving.
- [First successor serving](first-successor-serving.md)
  ([DR-0189](decisions/0189-first-successor-serving.md)):
  source-free Seal authority, target-local atomic activation and separately
  scoped successor signing/admission, with permanent import origin retained.
  Design acceptance does not create a serving capability.
- [Initial validator bond registration](initial-validator-bond.md)
  ([DR-0179](decisions/0179-initial-validator-bond-registration.md)):
  self-authenticated first collateral through generic custody and ordered
  execution; no fabricated predecessor, membership or activation authority.
- [Repository validation](repository-validation.md)
  ([DR-0172](decisions/0172-storage-neutral-required-validation.md)):
  four required storage-neutral lanes and separately selected complete PG
  acceptance, each with a success-only result; no mandatory database product.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references:
[persistence](../operations/persistence.md) and
[PostgreSQL](../operations/postgres.md).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.
