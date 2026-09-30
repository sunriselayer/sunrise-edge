# Portable reconstruction storage contract

This is the storage boundary for [complete epoch handoff](epoch-handoff.md).
The individual-read contract is not a multi-page snapshot. The optional stronger
contract below pins a local observation, not a cut certificate or import authorization.
Implementation and validation status belong in [`TODO.md`](../../TODO.md).

## Consistent candidate enumeration

[DR-0166](decisions/0166-portable-candidate-snapshot.md) adds the optional
`DurablePortableSnapshotRepository` contract on top of the individual reads.
A token binds the exact local namespace/domain, writer generation and checked
mutation sequence. Every guarded read checks that binding inside the same
transaction/lock that supplies the page, descriptor or chunk. A separate
before/after query is not an implementation of this contract.

Every write to the covered structured rows participates, including receipt-
only/object-only commits, outbox claims, expired-attempt reconciliation and
acknowledgements. Refused/rolled-back transactions cannot advance the sequence;
an existing expiry path that actually changes lease rows must advance it even
when that path refuses reuse of the expired lease. Exact no-write replay need
not advance it. A schema or legacy writer that cannot supply these guarantees
must refuse snapshot support rather than silently returning a weaker token.

PostgreSQL reuses its namespace `commit_sequence`. Shared SQL persists the
counter and a random 16-byte source-instance ID in metadata. PostgreSQL uses
a per-bootstrap 16-byte UUIDv4 source-instance ID. Both read it in the same transaction
as the fence/counter and data; neither silently upgrades an old metadata shape.
No PostgreSQL monitoring or cluster-admin privilege is needed for these reads.
Copies/restores require separate operator writer-refencing: a copied source ID
is not fresh identity. The memory fixture binds tokens to a unique store
instance, with per-domain sequences; clones share its identity and lock.
Physical tokens are local continuity fences, not signed execution generations
or semantic root inputs. Immutable blobs remain outside this structured token.

The conservative profile invalidates continuation on any covered local/control
write too. It therefore needs a quiet source to complete; this is not a claim
that the business-free barrier makes all storage immutable. Progress must be
CAS-fenced in a separate namespace/domain so it does not invalidate itself.
That progress transaction cannot atomically assert another domain's U14 read
set. A candidate attached to a locally certified terminal remains only an
enumerative/transport observation; Seal must independently rederive and bind
the authenticated cut. No progress marker grants readiness or serving.

## Keys, metadata and payloads

`runtime::portable::DurablePortableRepository` separates indexed key
enumeration, body-free metadata and bounded payload reads. A page never embeds
the complete value of its first row as an exception to the byte bound.

| Collection | Natural ordered key | Body-free descriptor | Separate payload |
| --- | --- | --- | --- |
| State | Exact byte key | Revision and value length, or a retained deletion tag | Value bytes, including an empty value |
| Receipts | Original request ID | Event digest and exact receipt length | Original canonical response bytes |
| Object heads | Object ID | Current or tombstoned head, retained version/ABA revision, digest and owner/routing projections | None |
| Immutable versions | Object ID, unsigned numeric version | Digest, schema, original chain/protocol provenance, creation checkpoint and payload kind | Canonical object bytes, or a content-addressed blob reference |

Local storage revisions and creation checkpoints remain audit/CAS inputs. The
protocol classifier must not reinterpret them as authenticated execution
generations or insert them into the new logical commitment.

Pages fetch at most 128 keys plus one lookahead key. Their cursor is the last
exposed key, exclusively, not the lookahead. Empty final pages are valid. The
backend must order and compare the original key, including full unsigned
object versions, rather than a display-text cast. Unknown persisted record
families, malformed keys, duplicates and reordered candidates refuse the page.
Do not filter an unknown PostgreSQL record-kind family out of the enumeration.

State keys use the existing runtime key bound. Key/metadata projections must
be bounded before copying out of SQL, including corrupt stored rows. A
maximum-plus-one projection may detect an oversized key but must never return
it as a truncated apparent valid key. Descriptors have a conservative 16KiB
body-free bound; provenance chain IDs follow the existing 128-byte execution
and PostgreSQL namespace boundary.

Payload requests carry an exact validated descriptor, offset and non-zero
chunk budget, capped at 1MiB. The descriptor is re-read and compared in the
**same read snapshot** as the selected byte range. A changed or missing row
returns `Changed`, not stitched bytes or a newly invented absence. An unchanged
row must return the exact requested range; truncated success is invalid.
Empty values produce one terminal empty chunk only after their `Some(0)`
descriptor is confirmed. Tombstones have no payload and remain distinct from
never-created keys. Legal large rows use continuation rather than a whole-row
page exception or an arbitrary total-history ceiling.

Every method enforces the configured namespace/domain, supported schema,
writer generation and absolute deadline. SQL implementations check the
deadline again before returning. Each method is a separate read: the caller
must discard unfinished content after `Changed` and cannot assume that an
earlier descriptor pins later pages or writer authority.

## Candidate driver and transport

`node_core::portable_candidate` connects that optional source contract to the
already verified candidate-free ordered terminal. It captures the source token
before deriving the terminal, then checks the outbox under that token after
derivation. Progress writes belong to a different namespace and domain.

The fixed collection order is State, Receipts, ObjectHeads, ObjectVersions.
Rows carry exact natural keys and consecutive chunks of at most 1 MiB. Empty
values emit an empty final chunk; tombstones, heads and blob references have
no body. Each collection has an explicit end item and exact emitted row count.
There is no arbitrary total-history cap. At most 128 physical keys are scanned
per step; an all-excluded page persists a skip cursor and returns `Continue`,
which is retried with the same next-item index.

| Canonical frame (v1) | Responsibility |
| --- | --- |
| `0x6490` identity | Complete DrainUnionIdentity, certified terminal height/digest and exact committed-proof digest |
| `0x6491` descriptor | Closed semantic metadata, excluding physical CAS revisions and object creation checkpoints |
| `0x6492` item | Identity digest, collection, row index, row/key/descriptor/chunk or collection-end count |
| `0x6493` manifest | Identity, four row counts and terminal running commitment |
| `0x6494` local progress | Source token, cursor, counts, running commitment and last exact item, outside portable roots |
| `0x6495` hash step | Identity digest, cumulative item count, previous digest and exact encoded item |

Identity and hash steps use the existing epoch-resolved `ExecutionEffects`
framing. The initial accumulator is the identity digest. Each committed item
folds the corresponding `0x6495` frame; the final manifest pins the result.
The independent `scripts/portable-candidate-vectors.mjs` fixes all six frame
encodings against Rust vectors without invoking a Rust encoder.

Progress is CAS/writer-fenced. Only the immediately previous item index can
replay its saved exact item without source I/O or a new write. A changed source
refuses new items; previously emitted bytes remain a historical observation.
Unknown commit confirmation returns `Indeterminate`, not presumed success or
an automatic retry. Impossible persisted cursor combinations fail closed.

If a source changes, the existing progress row cannot restart under that same
identity and token: `begin` refuses with `Conflict`. Preserve or abandon those
old candidate bytes as a historical observation, and use a freshly bootstrapped
separate progress store for a new attempt after verifying the current terminal.
There is no automatic retirement/cleanup API. Never reset source counters,
delete source history or reinterpret the stale candidate as a usable cut to
force continuation.

The closed classifier retains original receipts, candidates, committed proofs,
publication artifacts, economic history and logical provenance. It excludes
only named local reservation, anti-equivocation, engine and progress families.
Unknown reserved families and even tombstoned legacy outbox keys are refused.
Descriptor normalization does not normalize every legacy signed body; a
candidate commitment can vary with checkpoint operands or valid QC subsets.

The incremental receiver takes an **externally pinned** manifest, never the
sender's unverified claim of its own root. It validates identity, exact key
order, collection and descriptor kind, row/chunk continuity, terminal markers,
counts and the final hash. A rejected item cannot advance receiver state.
This is transport verification, not an importer or complete replay. Blob
references still require separate content and dependency closure. No method
creates readiness, serving authority, Seal or activation.

## Protocol responsibilities

The handoff protocol freezes the source and uses a closed key/schema
classifier to distinguish business facts, required authority history and
replica-local metadata. Storage enumeration alone cannot prove that every
required table or artifact was included. The four collections above do not
replace the complete protocol dependency manifest.

Bind descriptors and chunks to the committed frontier/cut, authenticated
ordered ranges, counts and content linkage. Verify complete reconstructed
canonical bytes against the expected digest, object ID/version, schema,
owner/authority and historical provenance before admitting them. Blob
references are not blob availability: retrieve, retain and verify the actual
referenced content through a bounded content-transfer path.

Persist continuation work under CAS fences and bound pages/bytes per event.
Verify every range and dependency to completion before readiness or a
DrainSet vote. Never turn a transient partial download into business-state
application, next-set eligibility or a claim that the cut is complete.

Store tests exercise byte/metadata preservation, empty/deleted distinctions,
pagination, legal large values, revision changes and authority refusals.
File close/reopen and fresh PostgreSQL connections prove persistence behavior
only; they do not prove authenticated state handoff, independent operational
control, network activation or production readiness.

## Referenced blob content

`runtime::portable::PortableBlobRepository` reads a present blob's exact
stored length separately from ranges of at most 1 MiB, including the first
range. It distinguishes a missing digest from a present empty blob and
refuses a later missing row or length mismatch instead of stitching ranges.
Memory, the separate SQLite blob file and namespace-bound PostgreSQL blob
storage implement this read contract. The current blob stores define no
delete or garbage collection; introducing reclamation must revisit the
range-read mismatch outcome.

These reads are content retrieval, not content authentication or cut
authority. The importer must verify the complete reconstructed bytes with
the committed digest and its purpose/context, then verify the referenced
object or publication provenance. The range-read trait itself carries no
writer fence; PostgreSQL binds its namespace at construction, while SQLite
and memory blob stores are separate from the structured-store namespace.
The protocol must independently fence and verify the structured cut. The
1 MiB bound is a process-side result bound; database-side work per range has
not been measured.
