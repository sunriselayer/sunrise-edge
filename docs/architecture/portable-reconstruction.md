# Portable storage reconstruction reads

Status: accepted implementation, storage layer only
([DR-0166](decisions/0166-portable-candidate-snapshot.md)). This document
describes bounded independent durable/blob/outbox reads and an optional
backend-enforced snapshot-continuity contract built on top of them. It makes
no claim about authenticated cut/import readiness, activation, Seal, or
network completeness; see "Non-goals" below and `TODO.md` for what remains
open in Delivery 3.

## Two layers

**`DurablePortableRepository`** (unconditional, every structured backend)
gives bounded, individually fenced reads: a forward-only keyset page over
one closed collection, a body-free descriptor for one key, and an exact
byte-range chunk of one record's payload. Each call independently validates
domain/schema/writer/deadline authority; there is no relationship enforced
between two separate calls.

**`DurablePortableSnapshotRepository`** (optional, implemented by memory,
SQL-durable and PostgreSQL) adds a local `PortableSnapshotToken` that a
caller obtains once and then presents to every subsequent guarded read
(`*_at` methods) so the backend can tell it whether the source has mutated
since the token was issued. A backend that cannot guarantee every covered
write advances the token's sequence — including any legacy write path
touching the same rows — must not implement this trait; reads then remain
individually fenced only, with no cross-read continuity claim.

## Source-local metadata versus signed/canonical authority

Everything in this document is source-local storage metadata: a namespace
identity, a writer-fence generation, a mutation-sequence counter, and a
per-bootstrap instance identifier, all compared inside one backend's own
read snapshot. None of it is a state root, a signature, a quorum
certificate, or any other signed/canonical protocol fact. A caller must not
treat a successful guarded read, or a fully replayed enumeration, as
authority to import, activate, or serve the observed state; that authority
comes only from separately verifying canonical `Transaction`/`Object`/
receipt bytes and, where applicable, a signed cut decision. This decision
changes no canonical `Transaction`, `Object`, or receipt encoding.

## Closed bounds and exact framing

Every page is capped at `MAX_PORTABLE_PAGE_KEYS` keys; every descriptor at
`MAX_PORTABLE_DESCRIPTOR_BYTES`; every chunk request at
`MAX_PORTABLE_CHUNK_BYTES`. All lengths, offsets and running totals use
checked arithmetic and fail closed on overflow rather than wrapping. A
chunk request's range is resolved once from the descriptor it was
constructed against, so a caller cannot request a range inconsistent with
the descriptor it already has.

## Four collections, exact keys

`DurableCollection` is closed to exactly four members: `State`, `Receipts`,
`ObjectHeads`, `ObjectVersions`. Each has an exact natural key
(`DurableRecordKey`) with unsigned numeric ordering for object versions.
Within these runtime crates, structured state keys are opaque bounded
bytes; there is no reserved-family classifier here deciding which keys
belong to the enumeration, unlike higher layers such as `node-core`, which
is out of this contract's scope. A page's continuation cursor is a
caller-supplied lower bound: the backend validates it against the
collection it was issued for and rejects one that is not strictly ordered
relative to the page it appends to, but this is bounds validation, not a
cryptographic completeness or forgery-detection guarantee — an arbitrary
cursor value that happens to fall in-range is not detected, the backend
simply resumes the scan from wherever it points.

## Absence, empty, and tombstone are three distinct outcomes

A missing key (`read_portable_descriptor` returning `None`) is distinct
from a present record with a zero-length payload (`Some(0)` in
`DurableRecordDescriptor::payload_length`), which is in turn distinct from
a tombstoned object head or a state deletion marker (represented in the
record's own metadata, not by absence). A caller must not collapse any two
of these into the same case.

## Snapshot tokens and whole mutation coverage

A `PortableSnapshotToken` binds an exact local namespace/domain identity, a
writer-fence generation and a checked monotonic mutation sequence. Every
write to any of the four covered collections, and to outbox
claim/acknowledgement, advances the sequence atomically with the write; a
rolled-back write does not advance it. A guarded read compares the token's
fields against the exact row read inside the same backend read transaction
that serves the data — never a separate before/after advisory check — and
returns `PortableSnapshotError::Changed` on any mismatch. Coverage is
whole-namespace, not per-key: there is no way for a token to remain valid
for some keys while invalidated for others. A stale/changed token is a
refusal to serve a possibly-inconsistent read, not evidence that the
underlying data is absent, corrupt, or has taken any particular new value.

## Physical source identity and restore refencing

The token binds a backend-local source identity, observed under the same lock
or transaction as the writer fence and mutation sequence. SQL backends persist
that identity alongside their logical namespace/domain. The mechanism differs:
PostgreSQL
generates a UUIDv4 (`gen_random_uuid()`) once at bootstrap; the shared
SQL-durable schema (SQLite/DO) generates 16 raw random bytes
(`randomblob(16)`, not UUID-formatted) once at bootstrap; the in-memory
store allocates a process-local monotonic counter value, unique across fresh
stores within one process; clones share the same store identity. It is not
persisted. This
distinguishes two *independently bootstrapped* namespace rows that would
otherwise share the same chain/validator/domain tuple.

It does **not**, by itself, distinguish a byte-identical restored or
copied backup from its source: a `pg_dump`/restore or file-level copy
carries the source's identity bytes over unchanged, so the copy is
indistinguishable from the source by identity alone, and a token issued
against the original can remain structurally valid against the copy for as
long as the copy's writer fence and commit sequence still happen to match.
This identity is a local fence only: it is never compared across replicas
and carries no protocol meaning. Restoring or promoting a copied namespace
still REQUIRES its own explicit operator writer-refencing step — see the
operator-only `advance_writer_fence` seam exercised by
`crates/runtime-postgres/tests/postgres_backup_restore.rs`, a separate
mechanism from this token — regardless of whether a stale token happens to
still validate against the copy.

## Quiet-source requirement and exact no-write replay stability

Completing a full multi-collection enumeration under one token requires
that the source receive no covered write for the duration of that
enumeration; any covered write during enumeration invalidates the token,
by design, as a conservative refusal rather than a best-effort merge. This
is a safety property, not a liveness guarantee — a continuously written
source may never complete an enumeration this way. Conversely, an exact
no-write retry (re-reading an unchanged descriptor, or replaying an
outbox claim/acknowledgement that was already applied under the same lease)
must never advance the sequence and must never invalidate an outstanding
token.

## Pending and nonempty outbox exclusion

`check_portable_outbox_empty_at` fails with
`PortableSnapshotError::NonemptyOutbox` under three conditions: a nonempty
historical batch blocks even once every one of its messages has been fully
acknowledged, because the signal the backend checks is the batch/message
rows (or, equivalently, an advanced delivery cursor) rather than current
lease state; an uncompleted delivery cursor blocks even when its own batch
was created explicitly empty; and only a batch created explicitly empty
whose delivery record is marked completed with an unmoved cursor passes.
Because the blocking signal is this persisted historical state rather than
pending work, it is **not** cleared by quiescing writes alone once any
message has ever been processed for that namespace/domain — this document
does not advise deleting outbox history rows to force a pass, and this
initial contract does not attempt to reconstruct in-flight or historical
outbox content. Memory and SQLite additionally retain a separate legacy
generic `outbox/` state-key-prefix presence check
(`LegacyOutboxInventory`/`inspect_legacy_outbox_prefix`,
`crates/runtime/src/outbox_guard.rs`) used by the broader DR-0154 exclusion
design; it is a distinct code path over the plain `StateStore` and is
**not** invoked by `check_portable_outbox_empty_at`, so a caller relying
only on this token gets no legacy-prefix coverage.

## Blob ranges give no content-closure guarantee

`PortableBlobRepository` gives bounded, exact byte-range reads over one
content-addressed blob, confirming the stored byte length still matches an
expected descriptor inside the same read that extracts each range, and
returning `Corrupt` rather than silently returning fewer bytes if the
digest-keyed row has changed or disappeared. It takes no namespace or
writer-fence argument, so it cannot fence a live blob writer and gives no
claim about which structured store, if any, currently references the blob.
A caller MUST hash the fully reconstructed bytes against the digest it
already trusts before treating them as authentic; this document gives no
guarantee that all referenced blob content is present, complete, or
reachable.

## Non-goals

This decision and its implementation make none of the following claims:
cut authority, import authority, next-set readiness, Seal, activation, or
any statement about overall network/replica completeness. A locally
observed token or a fully replayed enumeration is not a substitute for a
signed cut decision, causal fastpath/economics replay, artifact/dependency
closure, or logical state-root normalization. Those remain open Delivery 3
and later-phase work; see `TODO.md`.
