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
- [Decision records](decisions/README.md): accepted and compatibility-relevant
  decisions grouped into bounded ranges.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references:
[persistence](../operations/persistence.md) and
[PostgreSQL](../operations/postgres.md).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.
