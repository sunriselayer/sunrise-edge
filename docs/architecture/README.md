# Architecture

The accepted generic-contract To-Be is maintained in
[`../design.md`](../design.md), with dated rationale and As-Is gaps in the
[meeting record](../meeting-notes/2026-09-07-generic-contract-design.md).
Read that target before extending trusted preinstalled execution paths.

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
- [Durable local code publication](decisions/0121-durable-local-code-publication.md):
  authenticated immutable code storage, exact dependency provenance, shared
  nonce/receipt atomicity, and opt-in native HTTP/CLI publication.
- [Local instance execution](decisions/0122-local-instance-execution.md): typed
  host authority, immutable instances, bounded dependency libraries, and atomic
  local execution/replay; distinct from cross-instance or network admission.
- [Decision records](decisions/README.md): accepted and compatibility-relevant
  decisions grouped into bounded ranges.

Production-oriented persistence requirements and the PostgreSQL mapping are
separate operational references:
[persistence](../operations/persistence.md) and
[PostgreSQL](../operations/postgres.md).
Current work queues, gate summaries, and roadmap sequencing belong only in
[`TODO.md`](../../TODO.md). Architecture documents may describe implemented
behavior and preserve historical evidence inside accepted decision records.
