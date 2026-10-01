# DR-0175: Derive and export a first-epoch pre-Seal business cut

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted implementation boundary for DR-0154/DR-0173 after independent
design review. Current work and gate results belong only
in [TODO.md](../../../TODO.md).

## Decision boundary

The first capability derives an immutable candidate cut from an independently
reconstructed, completely drained first outgoing CausalAdmission epoch. It
exports bounded records and proof material and independently verifies saved
exports. It does not persist business state into an incoming validator or
grant readiness, Seal, transition voting, active serving or activation.

Require exact locally pinned signed genesis, outgoing context, committee,
atomicity domain and contiguous authenticated ordered history. The predecessor
anchor is explicitly that genesis, not an unverified caller-provided prior cut.
Reject advanced epochs and unsupported profiles. A later epoch requires its
own verified predecessor and activation chain; this version does not claim it.

## Private derivation, not a snapshot assertion

Complete normal and frozen-member reconstruction through the owning handlers
as specified by DR-0170 and DR-0174. Supplied application flags, results and
receipts remain comparison targets. Construct the cut from private expected
state only, after successful replay; a public report flag cannot construct a
verified capability. A real-source export additionally requires complete
field-aware equality under one backend-enforced snapshot token and a final
token check. Do not change the existing audit's comparison contract.

Independently reconstruct and verify committed Freeze, the exact committed
DrainSet selection and every complete selected signer stream and publication
closure. Deduplicate identical member identities and refuse contradictions.
Every selected union member must have an independently executed complete
original outcome. Every applied owned original must belong to that committed
union. An uncommitted candidate, partial prepare, possession/ready flag,
aggregate count or empty history tip is not a complete drain.

Bind the applied ordered prefix to its exact verified fixed target. Require a
verified candidate-free terminal three-chain for this export. That terminal
proof does not establish the complete live high/locked suffix predicate needed
by Seal. The cut is a candidate, not a Seal-ready permit or proof of latest
network state. Further justified progress may require a corrected candidate
before Seal; no first-writer-wins target is installed by export.

## Business facts and companion authority

Reuse the existing field-aware semantic projection. Partition exactly validated
records through their owning schemas, never by dropping a familiar namespace
prefix. Keep State, original business Receipts, ObjectHeads and immutable
ObjectVersions/deletions, including authenticated provenance, logical
generations, nonces, code/instances, economic history and custody.

The closed business partition keeps ordinary application state, authenticated
code/instance/object authority, nonces, economic state and non-control logical
provenance; original Owned and Ordered business receipts; and all object heads
and versions. The companion partition contains exact reconstructed ordered
candidate/header/outcome/archive/applied-height rows, current Freeze/DrainSet
rows and their subject-specific provenance, and their exact original command
receipts. Those command receipts are original outcomes, not synthetic receipts:
they remain independently verified, never dropped from audit equality.
Other exact recognized local rows retain the existing audit exclusions. Unknown
keys or schemas do not acquire companion placement by prefix.

Keep all required original candidates, full proofs, ordered outcomes and control
records as verifiable companion material. Economic original receipts remain
business facts. Fast/availability
certificate comparison bytes are not restorable rows: retain the verifying
original proof carriers separately and commit their common verified producer
identity, not an arbitrarily chosen certificate signer subset.

Exclude local CAS revisions, writer tokens, physical creation coordinates,
signing/reservation state and progress only under existing exact owner checks.
Normalize the initial genesis marker/epoch coordinate only through the existing
pin-verified schema rule. Do not normalize later signed/hash-linked checkpoints,
erase tombstones or discard provenance. Large legal bodies stay separate from
their small descriptors.

The execution-generation floor is the maximum of the verified genesis floor,
the logical generation of every independently applied Owned witness, and every
independently produced logical provenance generation, including deleted
subjects and verified control/history provenance moved into companions.
Unapplied local prepares, unselected retention and a source-advertised maximum
do not contribute authority. This maximum is not its later checked successor,
nor a backend sequence or physical checkpoint. Later admission must compute
its checked successor with authenticated prerequisites; export grants no such
mutation authority.

The cut identity binds genesis predecessor, outgoing context/set/domain,
committed DrainSet, applied prefix, exact four collection counts/roots,
execution-generation floor and semantic artifact closure. Use the committed
HashSuite and canonical NodeEvent-purpose frames, no new cryptographic primitive.
The current/future Seal, readiness and activation are not in their own cut.
No self-referential digest field is added to a committed collection.

## Transfer, resumption and verification

Separate semantic cut identity from exact proof-package integrity. A streamed
exact proof-package manifest binds the semantic cut and the descriptor/count/
digest of each immutable proof component, with its own terminal accumulator.
Saved continuation pins both identities; the manifest's own final frame is not
an entry in its accumulator. Collection/artifact root seeds bind explicit
context/genesis/domain and collection kind, never the final cut digest.
Different
valid Fast/availability signer subsets must not perturb normalized business
roots, but each actual saved proof is verified and its exact bytes retained.
Neither descriptor integrity nor a supplied cut root authenticates business
execution; saved verification repeats the pinned original reconstruction and
compares the independently derived cut and complete export stream.

Use explicit canonical keys and collection order. Pages bind cut identity,
collection, preceding accumulator, ordered key range, count and terminal status.
Chunks bind the cut, exact descriptor, offset and total length. Reject omitted,
extra, foreign, duplicated, reordered or substituted records, incomplete final
collections and tombstone-as-absence. Bound entries/bytes per page, bytes per
chunk and new saved work per invocation, not total legal history size. A
descriptor is at most 16 KiB; a page has at most 128 descriptors and 4 MiB;
one payload chunk is at most 1 MiB. The operator accepts one through 4,096 new
saved chunks/components per invocation and revalidates existing material.
Original record/component bodies retain their owning legal bounds. A
candidate-free terminal three-chain means the independently authenticated
target proposal, its child and its grandchild each have no candidate digest,
all bound to the exact fixed history identity. It is not a leader boolean or
a full live high/locked suffix assertion.

Saved components are immutable, synced and reverified on resume. Progress is
not authority and cannot authorize import or signing. Pin the exact source
token separately for source continuation; local tokens never enter cross-
replica semantic roots. A changed source refuses that observation instead of
repairing or silently widening it. Preserve read-only source bytes and fences.

Before code allocates wire frames, sweep the current canonical namespace.
Draft PR #235's portable-candidate IDs collide with merged ordered-history
frames and must not be reused. Add stable independent vectors and adversarial
decoder/transfer tests alongside the callable feature.

## Acceptance and non-goals

Use real frozen/drained generic paid contracts, assets, charged traps and
economic originals, including a member with no aggregate availability proof.
Compare all four semantic collections, exact original receipts and artifact
closure. Exercise incomplete drain, wrong controls/profile/prefix, missing or
contradictory material, normalized proof variants, physical-counter differences,
chunk/page corruption, interruption/resumption and real source restart/fencing.

Keep PostgreSQL optional. Reuse runtime-neutral capture and verification;
provider-specific source open/inspection is composition, not cut authority.
Local SQLite evidence does not certify a deployed provider. No incoming-state
installation, destructive reset, foreign writer copy, force/unfreeze path,
new consensus chain, production/mainnet activation or independent security
audit is introduced.
