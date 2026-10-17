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
- [Host compositions and capabilities](compositions-and-capabilities.md):
  actual router/executable/store/signer boundaries, closed versus accepted
  surfaces, and the distinction between component and provider qualification.
- [First native profile and protected signing](decisions/0208-native-sqlite-first-and-protected-signing.md):
  Native plus SQLite first, DO following; a separately reviewed protected
  signer replaces Ledger-specific prerequisites, not plaintext development keys.
- [Native SQLite connection and attachment ownership](decisions/0210-native-sqlite-connection-ownership.md):
  one native settings owner, lock-safe identity checks and explicit operator
  commit ambiguity; shared SQL decisions and live protocol authority stay separate.
- [Complete-owner-loss local SQLite writer failover control](decisions/0260-complete-owner-loss-local-writer-failover.md):
  separate actual sole-writer SIGKILL/reap and fresh generation business, with
  complete SQL/portable/blob reconciliation; host/power/media/fsync faults
  retain separate owning boundaries.
- [Native SQLite virtual power and block-error profile](native-sqlite-virtual-fault-profile.md)
  ([DR-0262](decisions/0262-native-sqlite-virtual-power-and-block-errors.md)):
  actual guest kernel/cache loss and typed block EIO under source COMMIT,
  independent cold full-image reconciliation and fresh fenced work.
- [Owned local TLS stop and explicit rotation](decisions/0216-local-tls-stop-restart-rotation.md):
  retained listener and trust boundaries, actual served-leaf observation and
  orderly compiled-host restart; separate from production PKI and custody.
- [Direct Native TLS connection ownership](decisions/0219-native-direct-tls-connection-ownership.md):
  optional immutable host DER/PKCS8 inputs, one admitted upgrade/HTTP lifecycle,
  bounded encrypted output and explicit stopped rotation; transport identity
  never replaces protocol authority or production PKI qualification.
- [Native stop and operational observations](native-operations.md)
  ([DR-0222](decisions/0222-native-stop-and-operational-observations.md)):
  explicit SIGINT/SIGTERM ownership, actual admitted-work drain and bounded
  secret-free counters; no protocol, public-readiness or deployment authority.
  [DR-0247](decisions/0247-native-stop-before-storage-continuation.md) extends
  cooperative checks to queued scheduler recovery and ordered storage context.
  [DR-0250](decisions/0250-successor-operation-context-stop-check.md) rechecks
  the same successor executor before fresh authority and storage resolution.
  [DR-0251](decisions/0251-successor-historical-read-stop-check.md) rechecks
  the separate signerless successor-history read boundary's own executor
  before its policy/storage resolution.
- [Native source-host SIGTERM wiring oracle](native-source-host-sigterm-wiring-oracle.md)
  ([DR-0254](decisions/0254-native-source-host-sigterm-wiring-oracle.md)):
  a real compiled `sqlite_source_host` process and a real SIGTERM prove the
  production constructor wires that signal to the exact executor the
  ordered-economics `propose` route's own cancellation check honors, through
  a deterministic listener-drop barrier; wiring only, not the late
  pre-storage window isolation DR-0247 already covers separately.
  [DR-0256](decisions/0256-native-frontier-sigterm-wiring-oracle.md) extends
  the same barrier to the certified FastVote router's own, separately wired
  frontier-maintenance `advance` route
  ([native frontier-maintenance SIGTERM wiring oracle](native-frontier-sigterm-wiring-oracle.md)).
- [Independent import history floor](decisions/0248-import-ordered-history-freshness-floor.md):
  retained same-epoch ancestor pins refuse older or conflicting ordered history
  before opening or creating destination databases; no checkpoint/state-root or activation authority.
- [Independent import closure-identity pins](decisions/0252-import-closure-identity-pins.md):
  retained exact cut/package/plan digest pins refuse a differing independently
  reverified closure before opening or creating destination databases; no
  checkpoint/state-root or activation authority.
- [Encrypted local checkpoint continuation](local-checkpoint-backup.md)
  ([DR-0263](decisions/0263-encrypted-local-checkpoint-continuation.md)):
  complete same-layout SQLite snapshots, existing independent currentness,
  maintained age transport and fresh-fence continuation; v1 proof archives
  and activated protocol migration retain their original owners.
- [Stopped Native storage-profile software upgrade](decisions/0265-stopped-native-storage-profile-upgrade.md):
  pinned prior RELEASE hosts, explicit one-way independent-anchor enrollment,
  incompatible old-writer refusal, historical receipt/body preservation and
  fresh fenced paid business; structural version5 and protocol remain fixed.
- [Immutable operation signing preparation](signing-preparation.md): one
  mechanical frame/identity owner, operation-specific immutable trust inputs,
  actual SDK/CLI consumers and the separate custody/content-review boundary.
- [Bounded publication metadata review](publication-review.md)
  ([DR-0237](decisions/0237-bounded-publication-review-presentation.md)):
  exact immutable artifact/frame correspondence, bounded terminal-safe output
  and diagnostic component hashes, without provenance or approval authority.
- [Saved successor fee-claim review](fee-claim-review.md)
  ([DR-0245](decisions/0245-saved-successor-fee-claim-review.md)):
  seed-free canonical exports, bounded exact-content inspection and offline
  development signing under the independently verified historical committee.
- [Publication-only local OS custody](local-publication-custody.md)
  ([DR-0238](decisions/0238-publication-only-local-os-custody.md)):
  separate UID/key permissions, independently pinned preimages, exact approval,
  authenticated local IPC and refusal/restart controls.
- [Original ordered protocol custody](local-protocol-custody.md)
  ([DR-0264](decisions/0264-original-ordered-protocol-custody-worker.md)):
  distinct-UID authority-owning worker and ordered-only HTTP frontend; existing
  protocol owners/bytes retained, with no per-request raw signature endpoint.
- [Publication custody lifecycle](publication-custody-lifecycle.md)
  ([DR-0244](decisions/0244-publication-approval-revocation-and-key-lifecycle.md)):
  durable request cancellation and stopped disposable-key recovery/rotation.
- [Genesis Standard Asset transfer custody](standard-asset-transfer-custody.md)
  ([DR-0246](decisions/0246-genesis-standard-asset-transfer-custody.md)):
  independent object preimages and known-code whole-coin review, separate
  transfer-only signer and the ordinary paid CLI consumer.
- [Genesis Standard Asset split/merge custody](standard-asset-split-merge-custody.md)
  ([DR-0249](decisions/0249-genesis-standard-asset-split-merge-custody.md)):
  shares the transfer family's genesis/code/instance/policy pin, adds a
  separate kind-3 split/merge signer and overflow-checked review, and
  connects the ordinary paid `split`/`merge` CLI consumer.
- [Genesis Standard Asset mint/burn custody](standard-asset-mint-burn-custody.md)
  ([DR-0253](decisions/0253-genesis-standard-asset-mint-burn-custody.md)):
  shares the transfer/split/merge families' genesis/code/instance/policy
  pin, adds a separate kind-4 mint/burn signer with an independently
  rebuilt checked-supply review, and connects the ordinary paid
  `mint`/`burn` CLI consumer.
- [Standard Asset create-asset custody](standard-asset-create-asset-custody.md)
  ([DR-0255](decisions/0255-standard-asset-create-asset-custody.md)): shares
  the same `PinnedAssetTrust` genesis/code/policy pin via a new
  `AssetCreateTrust`, but — unlike every other family — independently
  derives a *fresh* application `InstanceTarget` for a separate kind-5
  signer, and connects the ordinary paid `create-asset` CLI consumer.
- [Optional mint/burn application asset pin](decisions/0258-mint-burn-application-asset-pin.md)
  (DR-0258; see also
  [mint/burn custody](standard-asset-mint-burn-custody.md#optional-application-asset-pin-dr-0258)):
  one small, independently local, all-or-none non-genesis asset/instance pin
  introduced for mint/burn to target a `create-asset`-created asset; no
  new wire kind/version or change to genesis fee authority. DR-0261 below
  extends that same pin to transfer/split/merge.
- [Own-created Standard Asset Coin custody](standard-asset-application-coin-custody.md)
  ([DR-0261](decisions/0261-created-standard-asset-coin-custody.md)):
  extends the same immutable local pin to transfer and split/merge, keeping
  genesis fee typing, whole-frame approval and no-pin bytes unchanged.
- [Portable certified relay contract](decisions/0204-portable-certified-relay.md):
  an explicitly configured closed HTTPS transport, separate from default
  event-only relays, embedded DO policy and core authority.
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
- [Bounded compiled-host startup line](decisions/0229-bounded-compiled-host-startup-line.md):
  fixture-derived byte allowance and finite first-line probing in shared test
  supervision; source contracts, not runtime or all-path cleanup qualification.
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
- [Encrypted saved-business-closure transport](encrypted-recovery-closure.md)
  ([DR-0221](decisions/0221-encrypted-recovery-closure.md), accepted design):
  disposable local X25519/age transport for original and full successor saved
  roles, opt-in bounded reads and independent inactive verification; source
  candidate, not execution, real custody or off-host recovery qualification.
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
- [Recurring successor serving](recurring-successor-serving.md)
  ([DR-0191](decisions/0191-recurring-successor-serving.md)):
  one verified link chain, private base replay, scope-retaining audit and
  successor Seal retirement; the design itself creates no serving capability.
- [Original SQLite source hosting](decisions/0192-verified-sqlite-source-host.md):
  existing Ordinary/Unsealed namespace, one fresh writer fence, locally pinned
  original-root composition and verified ordered state without implicit repair.
- [Local SQLite validator startup](decisions/0195-local-sqlite-validator-startup.md):
  separate fresh signed-manifest preparation, snapshot-bound advisory
  preflight and independently reverified serving; no public activation authority.
- [Offline Standard Asset genesis authoring](decisions/0196-standard-asset-genesis-authoring.md):
  explicitly configured public-contract preset, protected expected-authority
  signing and defining-installer validation, without native balances or custody
  approval.
- [Offline original-genesis inspection](decisions/0197-offline-original-genesis-inspection.md):
  independently pinned, secret-free diagnostics after the defining generic
  installers validate in isolated memory; no serving or ceremony authority.
- [Initial validator bond registration](initial-validator-bond.md)
  ([DR-0179](decisions/0179-initial-validator-bond-registration.md)):
  self-authenticated first collateral through generic custody and ordered
  execution; no fabricated predecessor, membership or activation authority.
- [Repository validation](repository-validation.md)
  ([DR-0172](decisions/0172-storage-neutral-required-validation.md)):
  seven required storage-neutral owners and separately selected complete PG
  acceptance, each with a success-only result; no mandatory database product.
- [Native release handoff: artifact-to-capability/runbook bindings](native-release-handoff.md)
  ([DR-0241](decisions/0241-native-release-handoff-bindings.md)): the thirteen
  DR-0213 evidence artifacts bound to their source owner, actual modes,
  accepted capability, and existing runbook; documentation only, no R4/M7
  completion claim.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references:
[persistence](../operations/persistence.md) and
[PostgreSQL](../operations/postgres.md).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.

- [Independent local checkpoint anchor](local-checkpoint-anchor.md): opt-in local storage acknowledgement, complete typed state/body roots, crash reconciliation and clone exclusion; [DR-0259](decisions/0259-independent-local-checkpoint-anchor.md).
