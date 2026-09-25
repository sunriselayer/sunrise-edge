# DR-0143: PostgreSQL first-network escrow operations

## Status

Accepted, 2026-09-25. Implementation and validation status belong in
`TODO.md`; this decision does not certify a network launch.

## Context

DR-0142's executable checks a stopped local SQLite namespace. The first
multi-validator network instead intends to persist each validator's
structured state in PostgreSQL. `PostgresDurableStore` already implements
the same bounded key scanner and writer-generation checks used by the
read-only fee-escrow verifier, but a scanner alone is not an operator
workflow. Immutable object versions may also refer to external blob bytes;
the current local SQLite blob file is not a PostgreSQL deployment's durable
blob composition.

## Decision

Use PostgreSQL as the initial multi-validator structured persistence profile.
Its object blobs must be durable and bound to the same configured
chain/validator/domain namespace. Blob insertion remains content-addressed,
insert-if-absent, byte-identical idempotent and conflict-rejecting; reads
still verify each blob against its authenticated object digest and provenance.
The blob interface has no operation context or writer generation, so it may
not authorize state transitions or claim to fence a live writer. The
structured store remains the sole authority for object heads, versions,
settlements, receipts and the writer fence.
Publication must durably commit the blob before a structured object version
can reference it. The selected PostgreSQL durability policy must acknowledge
that ordering (including `synchronous_commit` and underlying storage or
replication settings); a failed later structured commit may leave an orphan
blob, but the reverse order would create an unreadable authoritative object.

The PostgreSQL inventory command must be operator-only and require an
independently trusted chain/validator/domain, protocol version and complete
hash-suite schedule, a certificate-validating TLS connection, and explicit
confirmation that the validator has stopped. It must inspect an existing
schema and namespace without bootstrapping either, atomically advance that
namespace's writer fence before scanning, use the new generation for every
page, then recheck the generation and deadline before printing any complete
result. A stopped process must restart under a newer generation afterward.
The command may not treat a partial page count, a missing blob, or a
zero-row result as a proof of a complete certified fee history.

Before calling this a network-start gate, test the actual command against a
nonempty quorum-certified escrow fixture on real PostgreSQL, including
blob-backed object reads, close/reopen, multiple pages, and a stale-writer
or concurrent-fence negative. Load/soak, capacity, recovery-time and the
independent Phase 3 review remain separate evidence requirements.

## Limits

- Advancing a writer fence is not a distributed stop-the-world mechanism.
  The operator must stop the validator and control direct database access;
  a writer bypassing the supported boot path could adopt the new generation.
- Blob put/get has no delete or garbage collection. A successful sweep does
  not prove absence of deleted historical rows, a whole-store rollback, or
  retention capacity; those claims need independent evidence and anchoring.
- This choice does not add a public event ingress, activate a protocol
  version, change canonical bytes, or declare FastVote, testnet, production
  or mainnet ready.
