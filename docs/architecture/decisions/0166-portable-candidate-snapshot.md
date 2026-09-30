# DR-0166: Backend-enforced portable snapshot continuity

Date: 2026-09-30

Status: Accepted; implemented in memory, SQL-durable (SQLite/DO) and
PostgreSQL. Scope is storage-layer read continuity only; see
[portable reconstruction](../portable-reconstruction.md) for the full
contract and non-goals, and `TODO.md` for outstanding verification.

## Context

The bounded portable keyset/descriptor/chunk reads
(`DurablePortableRepository`) fence each individual read against its own
row, but give no way to tell whether a sequence of reads observed one
consistent source or a source that mutated mid-enumeration. Reconstructing
a large namespace requires many separate reads across four collections
(state, receipts, object heads, object versions) plus out-of-band blob
ranges; without a shared continuity check, a caller cannot distinguish a
quiet source from one that changed between reads.

## Decision

Add an optional, stronger `DurablePortableSnapshotRepository` contract on
top of the existing bounded reads. A backend that implements it issues a
local `PortableSnapshotToken` binding the exact namespace/domain, the
writer-fence generation, and a checked monotonic mutation sequence. Every
write to the covered structured collections and to outbox
claim/acknowledgement must advance that sequence in the same transaction as
the write; a backend that cannot guarantee this for all its write paths
(including any remaining legacy access to the same rows) must not implement
the trait. Guarded page, descriptor, chunk and outbox-emptiness reads
compare the token against the exact row read inside their own backend read
snapshot — never a separate before/after advisory query.

PostgreSQL reuses its existing `storage_metadata.commit_sequence` column
rather than introducing a second protocol counter, and extends its coverage
to the outbox claim/acknowledgement write paths that previously did not
advance it. Memory and the shared SQL-durable schema use the same checked
contract. A rolled-back write must not advance the sequence. The token also
binds a per-backend physical source identity, read inside the same guarded
transaction as the writer fence and commit sequence, so that two
independently bootstrapped namespace rows that otherwise share the same
chain/validator/domain tuple do not validate against the same token. This
identity is generated once at bootstrap and differs by backend (PostgreSQL:
a UUIDv4 from `gen_random_uuid()`; shared SQL-durable/SQLite: 16 raw random
bytes from `randomblob(16)`, not UUID-formatted; memory: a process-local
monotonic allocator, unique across fresh stores with clones sharing the same
identity, never persisted). It does not by itself distinguish a
byte-identical restored/copied backup from its source; see "Physical
source identity is local, not authoritative" below.

### Four closed collections, exact keys, absence/tombstone

The reads this contract guards cover exactly `DurableCollection::State`,
`Receipts`, `ObjectHeads` and `ObjectVersions`. Each collection has an exact
natural key and a canonically sorted forward-only keyset page (no full
values in a page). Within these runtime crates, structured state keys are
opaque bounded bytes: there is no reserved-family classifier here deciding
which state keys are protocol facts versus replica-local metadata; that
classification, where it exists, belongs to `node-core`, outside this
contract's scope. A present record with an
empty payload (for example a zero-length state value) is distinct from an
absent key, which is in turn distinct from a tombstoned object head or
state deletion marker; the descriptor/metadata types preserve this
three-way distinction rather than collapsing "no bytes" into one case.

### Closed bounds

Every page, descriptor and chunk is bounded (`MAX_PORTABLE_PAGE_KEYS`,
`MAX_PORTABLE_DESCRIPTOR_BYTES`, `MAX_PORTABLE_CHUNK_BYTES`) and every
length/offset/count uses checked arithmetic. A descriptor read and its
payload chunk reads are two separate fenced operations; a chunk read
re-compares the exact expected descriptor inside its own read before
extracting bytes, and returns `Changed`/`Corrupt` rather than stitching
bytes from two different row revisions when it disagrees. A page's
continuation cursor (`after`) is a caller-supplied lower bound: the backend
validates it against the collection it was issued for and rejects one that
is not strictly ordered relative to the page it appends to, but this is
bounds validation, not a cryptographic completeness proof. An arbitrary
cursor value that happens to fall in-range is not detected as forged; the
backend simply resumes the scan from wherever it points. Enumeration
completeness is established by walking every page under one unchanged
`PortableSnapshotToken`, not by any property of an individual cursor.

### Whole mutation coverage, not a partial cache view

This contract does not treat the covered namespace/domain as a
point-in-time cache with independently refreshable pieces. The mutation
sequence advances on every covered write, so a token obtained before any
concurrent write remains valid only as long as no covered write has
happened since; there is no notion of "still valid for this key, stale for
that key." Immutable content-addressed blob bytes are outside the
structured token: `PortableBlobRepository` gives bounded, exact byte-range
reads over one digest-keyed blob, confirming the stored length matches the
expected descriptor inside the same read that extracts the range, but it
takes no namespace or writer-fence argument and proves nothing about the
structured store's own cut authority. A caller must independently check
reconstructed blob content against the digest it already trusts before
treating it as authentic; this contract gives no blob-content closure
guarantee.

### Quiet-source requirement and no-write replay stability

Because the sequence advances on *every* covered write, completing a full,
multi-page enumeration across four collections requires a source that does
not receive a covered write during that enumeration. This is a
deliberately conservative refusal-safe design, not a liveness guarantee: a
continuously written source may never complete an enumeration under this
contract. Exact no-write retries (for example, replaying an already-applied
outbox claim against the same lease, or re-reading a descriptor that has
not changed) must never advance the sequence and must never invalidate an
outstanding token; only a genuine new write does. A pending outbox message,
or any nonempty outbox state, excludes a namespace/domain from a complete
enumeration (`check_portable_outbox_empty_at` returns
`PortableSnapshotError::NonemptyOutbox`). Precisely: a nonempty batch blocks
even once every one of its messages has been fully acknowledged, because
the backend's signal is the batch/message rows or an advanced delivery
cursor, not current lease state; an uncompleted delivery cursor blocks even
when its own batch was created explicitly empty; only a batch created
explicitly empty whose delivery record is marked completed with an
unmoved cursor passes. Because the blocking signal is this persisted
historical state, not pending work, it cannot be cleared by quiescing
writes alone once any message has ever been processed — this document does
not advise deleting outbox history rows to force a pass, and this initial
contract does not attempt to reconstruct in-flight or historical outbox
content. Memory and SQLite additionally retain a separate legacy generic
`outbox/` state-key-prefix presence check (`LegacyOutboxInventory`,
`crates/runtime/src/outbox_guard.rs`) used by the broader DR-0154 exclusion
design; that check is a distinct code path over the plain `StateStore` and
is not invoked by `check_portable_outbox_empty_at`, so a caller relying
only on this token gets no legacy-prefix coverage.

### Physical source identity is local, not authoritative

The token's namespace bytes are a local, backend-enforced identity fence —
chain/validator/domain plus the per-backend bootstrap identity described
above — used only to distinguish two *independently bootstrapped* namespace
rows that share the same chain/validator/domain tuple. They are never
compared across replicas, never included in a semantic/protocol
commitment, and never treated as a state root or as signed/canonical
authority over the business state the source holds.

This identity does **not**, by itself, detect a byte-identical
restored/copied backup: a `pg_dump`/restore or file-level copy carries the
source's `source_instance_id` bytes over unchanged, so a copy is
indistinguishable from its source by identity alone, and a token issued
against the original can remain structurally valid against the copy for as
long as the copy's writer fence and commit sequence happen to still match
what the token expects. Detecting and rejecting a stale writer after a
restore/failover is the job of the existing, separate operator-only
writer-fence-advance procedure
(`advance_writer_fence`, exercised by
`crates/runtime-postgres/tests/postgres_backup_restore.rs`), not this
token: an operator restore or failover MUST perform that writer-refencing
step; skipping it because the snapshot token "still validates" is
incorrect and unsafe. This decision makes no claim about cut/import
readiness, activation, Seal, or network completeness: it is bounded,
independent durable/blob/outbox read continuity for one quiet local source,
nothing more.

### Schema bootstrap shape: accepted pre-release decision

Following the existing accepted precedent of redefining an unreleased
schema generation in place rather than shipping a migration
(`docs/architecture/decisions/0058-0075-postgres-conformance.md`, DR-0068),
this decision is implemented as a bootstrap-shape change to each backend's
still-unreleased schema, not a migration:

- the shared SQL-durable schema identity is redefined in place from `v1` to
  `v2` to add the checked `mutation_sequence` column, and `v2` is further
  redefined in place (still without advancing its identity) to add
  `source_instance_id`;
- the PostgreSQL schema identity is redefined in place to `v3` (already
  used for the namespace-bound blob table added under DR-0143) to add
  `source_instance_id` to `storage_metadata`.

Per explicit user instruction, this PR does not design pre-release backward
compatibility for either shape. An existing database whose schema is
missing the new column fails closed (`SchemaMismatch`/equivalent) on the
next bootstrap or inspection; no migration, backfill, or silent rewrite is
shipped or planned for these unreleased shapes.

## Consequences

This is local storage-read consistency evidence for one quiet source, not
authenticated history completeness, transport verification, or activation
authority. It does not, by itself, prove that a source's business state is
legitimate, that its dependencies are complete, or that any other replica
shares the same semantic state. Required negative evidence (implemented in
`crates/runtime/src/portable/conformance.rs` and exercised per backend)
includes: a legacy or covered mutation invalidating an outstanding token; a
mid-page/mid-chunk row change; a changed writer fence, namespace, or
domain; an unsupported/missing-column schema; a duplicate, reordered or
out-of-collection continuation cursor rejected by bounds validation (not a
forgery-detection guarantee); tombstone versus absence; a large
legal payload continuation across chunk boundaries; and exact no-write
replay stability (no spurious sequence advance or token invalidation).

Remaining work belongs to Delivery 3 and later phases, not this decision:
causal fastpath/economics replay, artifact/dependency closure, logical
state-root normalization, a signed cut decision, next-set readiness, Seal,
activation, fresh-genesis gating, and independent PostgreSQL network E2E.
