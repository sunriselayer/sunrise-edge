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
- [Generic contract architecture](generic-contracts.md): common execution and
  authority, type/instance/object separation, upgrades, migration and durable
  verification obligations.
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
- [Complete epoch handoff](epoch-handoff.md) ([DR-0154](decisions/0154-complete-epoch-handoff.md),
  [DR-0155](decisions/0155-epoch-end-freeze-warrant.md),
  [DR-0156](decisions/0156-frozen-frontier-possession.md),
  [DR-0157](decisions/0157-frozen-frontier-readiness.md),
  [DR-0158](decisions/0158-bounded-drain-network-driver.md),
  [DR-0159](decisions/0159-ordered-drainset.md),
  [DR-0160](decisions/0160-certified-drain-application.md)):
  publication-before-apply, quorum-complete frozen frontiers, ordered epoch
  control, portable logical commitments and verified new-validator readiness.
- [Portable reconstruction storage contract](portable-reconstruction.md):
  body-free key/metadata enumeration, bounded payload ranges and the separate
  protocol obligations for cut authentication and completeness;
  [DR-0166](decisions/0166-portable-candidate-snapshot.md) defines the stronger
  backend-enforced snapshot boundary for candidate enumeration, not cut authority.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references:
[persistence](../operations/persistence.md) and
[PostgreSQL](../operations/postgres.md).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.
