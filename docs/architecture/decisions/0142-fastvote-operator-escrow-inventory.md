# DR-0142: Operator-driven FastVote escrow inventory

## Status

Accepted, 2026-09-25. Implementation and remaining network certification
are tracked in `TODO.md`.

## Context

DR-0140/0141 supply bounded per-page verification and certified SQLite
fixtures, but the complete loop was test-only. Pages are independent SQLite
read transactions; a cursor alone cannot prove complete coverage while
settlement keys can be inserted behind it.

## Decision

Expose a node-core all-page driver that returns aggregate counts only after
the terminal page. The operator executable must open existing structured and
blob files without bootstrapping either, require the exact chain/validator/
domain namespace and a locally supplied trusted protocol-version/hash-suite
schedule, and require an explicit stopped-node acknowledgement. It atomically
claims the next persisted SQLite writer generation before the first page.
Every page uses that generation; a later boot advances the fence and causes
subsequent reads to fail. It re-reads the generation after the terminal page
and withholds the result if the fence changed or the operation deadline
expired. A failed or interrupted run is never reported as complete. The
fence claim is the one durable write; the verifier itself only reads.

This is a deliberately disruptive maintenance operation. Old writers are
fenced permanently and must restart. The operator must stop the node before
running it. A writer that bypasses the supported boot/fence protocol and
directly uses the newly claimed generation is outside this guarantee. Blob
content is insert-if-absent and not writer-fenced; the proof consumes only
blobs referenced by authenticated structured records.

## Limits

- This proves present chain-scoped settlement keys in one namespace at the
  claimed generation. It does not prove absence of deleted history or a
  whole-store rollback; an external anchor is still needed for that claim.
- The current executable targets the local SQLite profile only. An intended
  PostgreSQL network needs its own quiescence/fencing operator path before
  this is a network-start gate. The command is not an online HTTP endpoint.
- Historical protocol versions need an explicitly trusted resolver history;
  the current command passes none and fails closed on unsupported history.
  The future version-activation gate remains separate.
- Neither a successful sweep nor its counts certify claim throughput,
  retained-byte cost, recovery-time SLO, or production readiness.
- No canonical transaction, certificate, claim, object, receipt or nonce
  bytes change.
