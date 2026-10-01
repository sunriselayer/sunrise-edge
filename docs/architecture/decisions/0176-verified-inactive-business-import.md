# DR-0176: Persist verified business state into an import-only namespace

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted implementation boundary following independent technical design
review of DR-0154/DR-0173/DR-0175. Work and validation status belong only in
[TODO.md](../../../TODO.md).

## Boundary

Derive a private raw installation plan from the first-epoch verified cut and
persist it into a genuinely fresh, permanently import-only namespace. The only
states introduced are FreshImport, Importing and CompleteInactive. None permits
new business admission, protocol signing, readiness, Seal, activation or active
serving. There is no transition back to an ordinary namespace in this slice.
`Ordinary` means an explicitly verified storage origin, not an activation permit.

Keep cut, exact package, local destination and import-plan identities distinct.
A source token or source writer generation is never destination authority.
Correction uses another fresh inactive namespace, not an active/history reset.

## Non-removable origin and common-store lifecycle

Add a required lifecycle read to the common durable state-store contract, with
no default Ordinary/Active implementation. Every concrete store and forwarding
view explicitly implements it. A read-only captured source view cannot invent
live admission authority. Validate domain, writer fence and operation deadline
when returning the lifecycle; malformed or missing required metadata refuses.

Persist an immutable namespace origin and bounded import binding in the shared
SQL metadata, outside generic State writes. Binding commits the locally pinned
genesis/context/domain, semantic cut, exact package, private raw-plan identity,
counts and authenticated generation floor. Mutable progress cannot erase that
origin: deleting a phase/progress/completion record is corruption, not Ordinary.
Import progress stores the next ordinal, last batch identity and accumulator;
completion remains bound to the same immutable identity.

Dedicated create/open-existing import composition is separate from ordinary
store bootstrap. Creation atomically verifies a genuinely fresh namespace and
allocates its own writer fence/source-instance binding. It refuses a populated,
tombstoned, previously ordinary, differently bound or already claimed target.
Normal store open, live composition and ordinary genesis bootstrap refuse every
import-origin phase. Generic commits recheck lifecycle in their transaction so
a prior successful admission read cannot race an incompatible namespace.

Use a new shared schema identity and native SQLite schema version with mandatory
origin/binding fields. Unreleased old initialized files are explicitly unsupported
by this slice; do not automatically migrate, reset or repair them. A needed
preservation/migration workflow requires its own scoped decision. PostgreSQL
remains a verified Ordinary-only implementation with no import bootstrap in this
slice. Shared SQL enforcement is not a claim that a DO host exposes import or
that any provider deployment is certified.

## Private rederivation, not restoration of comparison subjects

An opaque `VerifiedImportPlan` has no constructor from decoded rows, a supplied
completion flag, claimed cut roots or a public equality report. Construct it
while independently reconstructed raw facts remain available, under the original
local genesis/hash/context/committee/domain/history pins. Preserve the opaque
verified cut boundary and reverify its exact original proof package.

Do not decode or restore `SemanticRecord` comparison bytes as original rows.
Logical provenance/profile and certificate comparison normalization is for
cross-replica equality, not an installation codec. Read owner-validated original
private rows. Restore actual independently verified full Fast/availability
carriers through their owning encoders, not a normalized producer subject or
invented availability certificate.

Keep exact original business/control receipts, nonces, economics, code/instances,
immutable object versions/deletions, object heads, authenticated provenance and
required historical ordering/control material. Exclude signing identities,
votes/ACKs, reservations, local progress and live consensus safety state only by
exact validated owners. Do not create a fake live ordering tip for an inactive
namespace. Allocate fresh physical State/head revisions and local installation
coordinates; preserve authenticated logical generations, immutable versions and
signed/hash-linked checkpoint operands. No Standard Asset exception is allowed.

The plan commits its closed raw row/blob inventory using the committed HashSuite
and NodeEvent-purpose frames. Large legal bodies use individually bounded fixed
digest ranges, never one whole-history or oversized body-containing superframe.
Generation floor remains authenticated business history, not a local sequence;
this slice never enables fresh admission from its unchecked successor.

## Separate atomic installation seam

Introduce a typed `InactiveImportRepository`, not a maintenance flag on ordinary
transactions or live handlers. Keep ordinary receipt cardinality, object
transition validation and execution authority unchanged. Its storage-only batch
contract is not proof of cryptographic business validity; core owns verification
and private plan construction.

Closed row kinds are retained State value/tombstone, exact typed original
receipt, immutable object-version record and live/tombstoned head without a
caller-supplied physical revision. Install verified immutable blobs before
references, versions before heads, and original receipts after their material.
At most 128 rows and 64 MiB represented bytes enter one batch, preserving each
owning legal bound, including a legal 32 MiB body. Bound new batches per call,
not total legal history or reverification cost.

Every batch atomically checks exact binding, current fence/deadline and expected
progress, installs absent rows or verifies identical retry rows, and advances
progress with the same commit. Conflict does not overwrite. Indeterminate
commit requires fresh fenced reconciliation of exact batch identity/contents;
no cursor advance based on an uncertain acknowledgement or blind retry success.

Before CompleteInactive, core completely enumerates all destination rows and
referenced immutable bodies and compares them against its private raw plan.
Finish atomically fences that verified destination snapshot and the complete
progress. Do not weaken the existing live-source audit comparison or trust a
progress/completion marker as a substitute for independent verification.

## Core guard and replay

Refuse import-origin authority before execution, reservation or signature
exposure, including cached protocol votes/ACKs. Cover Fast prepare/retain/apply,
frontier/drain retention and signer streams, epoch voting, ordered proposal/tick,
signerless ordered recovery, ordinary genesis initialization and activation.
Store-level commit refusal is the atomic backstop, not the only signature guard.

Preserve receipt-first exact original business replay under the current local
writer fence: it returns original responses without execution or outbox work.
That exemption is not cached protocol signing or AV ACK replay. Fresh business
paths check lifecycle after exact receipt reconciliation and before owning
execution. Do not put a blanket guard on shared read-only historical inspection
helpers merely because live handlers also call them.

## Acceptance

Use a genuine complete cut and real file-backed SQLite destination with its own
fence. Interrupt between bounded batches, close/reopen, resume and compare every
original receipt, version/deletion, provenance/floor and blob. Exact replay must
execute nothing. Advance the destination fence through another handle and prove
stale batch, completion and replay refuse without execution or signatures.

Exercise missing/surplus/duplicate/foreign/corrupt material, wrong package/pins,
inconsistent progress/floor, deleted mutable markers, normal-open refusal,
ambiguous commits, fresh physical revisions and concurrent ordinary admission.
Signer/ACK counters must stay zero in every import-origin phase. Relevant PG
adapter changes require separately selected PG evidence; SQLite is not PG
acceptance. No production/mainnet profile, provider certification, destructive
reset, force-unfreeze or independent security-audit claim is introduced.
