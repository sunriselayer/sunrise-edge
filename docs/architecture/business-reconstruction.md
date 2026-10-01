# Causal business reconstruction and semantic audit

[DR-0170](decisions/0170-causal-business-reconstruction.md) specifies the
accepted boundary. Implementation progress and gate results belong in
[TODO.md](../../TODO.md), not this contract or the repository README.

## Authority

Ordering QCs prove original candidate identity and ancestry, not execution
companions. Business reconstruction requires the fresh signed causal-admission
profile, a locally pinned genesis commitment and committee, complete verified
owned material, and contiguous authenticated original ordered events.

The profile keeps v2 logical witnesses but separates external original IDs:
high bit 0 is Owned, high bit 1 is Ordered. Internal synthetic receipts remain
excluded. All original producer, retention, apply, recovery and observer paths
enforce the appropriate lane before fresh work. Embedded economic legs use
the Ordered original identity, not standalone owned classification.
Genesis/profile verification produces a private trusted capability; raw enum
tags, client flags, decoded certificates and source rows do not.

Fresh causal genesis fixes the initial hash-linked bond checkpoint at 0, so
the same signed manifest seeds the same business bytes at different local
installation coordinates. Marker/initial epoch/physical creation coordinates
remain local. Never normalize a bond or transition checkpoint to repair a
source mismatch: it participates in subsequent signed row digests.

Ordered signing additionally proves the exact committed first nonce and full
reserved address-owned inputs in the same fenced commit as its vote. Missing
prerequisites cause recovery stops. Justified predecessor progress is processed
before successor admission. Settlement/bond generations and protocol custody
stay governed by shared order, preserving competing-candidate concurrency.

Configuration and lifecycle CAS assertions share the runtime's 4,096 atomic
read slots with application keys. The generic historical durable handler now
allows at most 4,092 application keys; authenticated nonce and lock assertions
consume additional slots. A structurally valid `NodeStateAccessPlan` is not an
executable-capacity promise. Oversized plans refuse before application reads
or execution. This deliberate operational change does not alter historical
canonical encodings; see the capacity tradeoff in DR-0170.

## Reconstruction

The private overlay has no real-source write handle, signer or import permit.
It starts from verified genesis and uses the same deterministic execution as
normal owned/ordered application. A strict typed owned-witness decoder returns
untrusted operands only; crypto/context/closure verification and independent
execution must establish their authority before use.

An exact subject/observation producer index resolves dependencies, including
nonce and address-owned prerequisites required at ordered admission even for
later no-effect refusals. It distinguishes pristine absence from deletion and
checked logical generations from local CAS revisions. Duplicate certificate
subsets cannot double-apply a producer. Contradictory producers, missing
material, impossible dependency cycles and unrecognized schemas stop.

Accepted DrainSet controls additionally need the exact selected signed frontier
entry streams and their complete retained publication closure. These are
untrusted proof inputs bound to the original candidate, not copied source
ready/progress rows. Reverify each stream from its seed to the signed terminal
count/digest and privately run ordinary page ingestion, retention import,
confirmation and bounded union derivation before the owning control handler.
NoFreeze, AlreadyDrained and other pre-readiness refusals retain their normal
precedence. Proof retention does not authorize an owned application.

Keep original ordered events in certified order and process owned producers
only where their verified dependencies permit. Request-ID sorting and an
all-owned-first replay are invalid. Recommits retain the first occurrence and
exact original receipt/outcome; they do not repeat business effects.

Compare independently produced complete result/effects and receipt bytes
against source companions. A canonical, internally consistent source result
can still fail business verification. A refusal cannot be synthesized from
missing code, bodies, authority, nonce or evidence.

## Real-store comparison

Enumerate all four closed portable collections under one backend-enforced
snapshot token: State, Receipts, ObjectHeads and ObjectVersions. Resolve and
hash the full referenced blob closure with bounded reads. Unreferenced blob
garbage is not an authenticated business fact; physical blob-set equivalence
requires a separate enumeration/continuity contract.

Project each fact using its owning schema:

- Exact application bytes and verified logical observations/generations.
- Immutable code/ABI/dependencies, instances and object authorities.
- Object identity, version, digest, payload, owner/routing and deletion history.
- Sender nonce and exact original receipt identity/bytes.
- Verified escrow/shares/claims, bonds/transitions, evidence and consumption.
- Verified original ordered identity, closure and DrainSet control.

Preserve checkpoint fields that belong to signed candidates or hash-linked
business records. Exclude physical revisions, writer fences and unsigned
object creation coordinates only through explicit field-aware projections.
Genesis installation and its initial epoch activation normalize their unsigned
local installation coordinates only after the exact manifest/committee pin
matches. Post-genesis transition checkpoints are never normalized this way.
Normalize equivalent proof subsets only after independently verifying their
same producer identity; do not discard economically deciding fields.

Exactly recognized local reservation/signing/progress records confer no
business authority. Unknown reserved keys/versions fail closed, including
malformed keys hidden beneath a familiar prefix. Any unexplained business row,
receipt, head/version, tombstone or referenced artifact defeats equality.

The source remains unchanged. A changed token, stale writer, incomplete page,
corrupt chunk, missing closure or different fixed target refuses comparison;
none is permission to seal or repair the source.

## Product and scope

Saved material and CLI resumption pin local genesis/profile/domain and fixed
history identity, use bounded immutable components, and reverify the saved
prefix. Reports distinguish verified material, snapshot continuity and semantic
equality. They do not label a fixed target the latest network state.

This is an audit/reconstruction boundary, not persistent cut/import, incoming
validator installation, readiness, Seal or activation. Legacy profiles keep
their original interpretations and receive no fabricated causal guarantee.
Ledger, UI, load targets and other deferred gates remain independent.

See the [read-only PostgreSQL operator guide](../guides/business-audit.md) for
fixed-observation collection, immutable resumption and refusal behavior.
