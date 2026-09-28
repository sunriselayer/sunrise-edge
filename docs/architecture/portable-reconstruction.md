# Portable reconstruction storage contract

This is the storage boundary for [complete epoch handoff](epoch-handoff.md).
It is not a cut certificate, an import authorization or a multi-page snapshot.
Implementation and validation status belong in [`TODO.md`](../../TODO.md).

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
