# DR-0170: Causal business reconstruction and semantic audit

Date: 2026-10-01 (Asia/Singapore)

Status: accepted design; implementation and release evidence belong in TODO.md.

## Context

DR-0169 authenticates original candidates and their shared ordering. Its QCs
do not sign the source's outcome, receipt or business state. An exporter can
provide mutually consistent companions without independently proving execution.
DR-0154 therefore still requires causal reconstruction from verified genesis.

The genuine production-path regression
`identical_logical_owned_material_and_ordered_proof_do_not_pin_original_nonce_refusal`
demonstrates two legitimate histories with identical signed v3 genesis,
complete owned v2 publications, availability certificates and ordered
proposals/QCs. A nonce-1 FeeClaim committed before an independent nonce-0
owned application originally refuses; the same candidate committed afterward
succeeds. Both ordering exports verify. This is an ambiguity between two
histories, not evidence of same-run signature equivocation.

A separate source trace identifies an original-request collision: zero-leg
Unbond, ZeroShare, Evidence and control operations need no owned input/nonce
reservation. An unrelated owned operation can use the same external request
ID. Distinct admission records allow both certificates; the shared original
receipt key prevents a second local application but cannot reconcile the two
possible first applications. A receipt-absence read alone does not prevent
later occupancy. This trace is not described as an executed regression.

The user requested a larger usable feature, including independent business
reconstruction, real-store comparison and CLI acceptance rather than another
transport-only prerequisite. Independent design review approved the closed
profile below after rejecting underspecified generalized read reservations
and an extra execution-result consensus round.

## Decision

### Signed causal admission profile

Introduce `CommitmentProfile::CausalAdmission`, canonical profile tag 3,
authorized only by fresh signed genesis v4 and `genesis-manifest-v4`.
It preserves logical generation derivation and witness v2. The signed
positive minimum Freeze height remains mandatory. Existing manifest profiles,
transactions, candidates, certificates, witnesses and receipts retain their
exact historical layouts and interpretations; no missing history is backfilled.

Under this profile, the high bit of an external 32-byte original request ID
names its certified lane: 0 for owned paid Publish/Instantiate/Call, 1 for
ordered operations. Existing internal synthetic-ID exclusions still apply.
All six current ordered kinds enforce Ordered; standalone paid authentication,
prepare, retention, apply, recovery and drain verification enforce Owned.
Embedded ordered execution legs keep their original Ordered ID and private
ordered authority; they are not standalone owned paid requests.

The caller cannot choose the rule with a boolean. Pure verification receives
a privately constructed profile from verified, locally pinned genesis.
Mutating admission fences the installed binding; reopen verifies the exact
manifest/profile association. Missing, replaced or downgraded bindings stop.
Wrong-lane fresh input fails before signature, reservation or metadata.
Authenticated bootstrap is an internal genesis operation, not a public bypass.
Alternate direct business writers refuse fresh causal-profile work unless
entered through the appropriate genuine private certified capability.
Exact completed replay remains receipt-first and preserves the original bytes.

Fresh causal genesis derives initial business state independently of the
caller's unsigned local installation coordinate. In particular, every initial
bond's hash-linked `committed_at_checkpoint` is the deterministic genesis
coordinate 0. Its later transition checkpoints remain exact signed/hash-linked
business facts. Only installation marker, initial epoch activation and physical
object-version creation coordinates may use the caller's local checkpoint.
Otherwise the same signed genesis would seed different bond digests, and a
later signed Replace could not be independently reconstructed. Historical
profiles retain their existing interpretation; an earlier development causal
namespace using a different initial business coordinate is not silently
normalized, overwritten or accepted as a valid reconstruction source.

The semantic projection also accounts for an initial logical provenance row
whose subject is exactly the genesis install marker (or initial epoch row, if
the owning genesis schema produces such a subject). First require the exact
genesis-floor generation, observed genesis epoch, canonical subject/key and
`StatePresent` digest independently recomputed from that snapshot's actual
owning row. Validate the row's full genesis/committee binding, then project
only the digest of its explicitly normalized local installation coordinate.
Preserve subject, generation and epoch. This is not a provenance-prefix
exclusion or permission to normalize a post-genesis observation, signed
witness, bond, transition or candidate digest. Malformed, foreign, tombstoned
or mismatched source provenance must still refuse; source bytes are not
changed or used to seed private execution.

### Ordered admission and interleaving

Before exposing an ordered signature, validate the exact committed first
sender nonce, checked consecutive range, and each reserved address-owned
source's full reference, body, owner and authority. Fence these observations
atomically with the existing precise FastVote reservations and signing state.
Missing/future inputs stop for authenticated recovery, not an invented refusal.

Process a justification's newly committed predecessor progress before fresh
admission, using bounded signerless steps. Otherwise a valid successor can be
blocked by the prerequisite that its own justification commits. Maintain the
at-most-one-business-operation-per-durable-invocation rule and never expose
signatures/results after rejected or indeterminate persistence.

The existing structured commit contract requires a receipt to atomically
assert object heads. Head-reading proposal/vote admission therefore uses an
internal bookkeeping receipt, with no business/object mutations or outbox.
Use the already reserved synthetic namespace and existing receipt/dedup
layouts, but a distinct `se-ordered-admission-receipt-v1` hash preimage binding
epoch, original request, candidate, stage and view under the trusted chain/
protocol hash context. Do not reuse the owned prepare's identity. Exact stage
replay reconciles its retained signing identity without another write.
Bookkeeping is not original completion. Empty infrastructure steps need no
synthetic receipt when there are no object-head assertions. A business
predecessor receipt and a fresh admission receipt are never merged by dropping
one; bounded predecessor processing finishes before the new signing step.

Do not reserve protocol custody, settlement/bond generations or a global
business sequence. The authenticated ordered prefix determines competing
claims and genuine stale refusals. Initial escrow/settlement and immutable
executable prerequisites come from authenticated owned producers. Evidence,
bond transitions, closure and DrainSet have their existing closed derivations.
The rule covers the current six operations, not arbitrary future shared code.

### Private reconstruction and closed comparison

Initialize a private overlay from locally verified signed genesis. Authenticate
each complete owned publication and its required artifact closure, verify
original ordered events, and independently execute existing deterministic
handlers in causal order. Source effects/outcomes/receipts are comparison
targets, never executable authority.

Resolve exact subject, semantic observation/version and authenticated producer
identity. Generation alone is not unique. Account for ordered admission
dependencies even when execution subsequently early-refuses. Never sort
request IDs or apply every owned producer before all ordered operations.
Reject contradictions, missing producers, cycles, deletion-to-absence
substitution and unsupported business schemas. Recompute checked generations.
Use heap-backed cycle-detecting dependency traversal: per-witness bounds do
not justify native recursion or an arbitrary total-history depth ceiling.
Equivalent valid quorum subsets identify one producer; fee shares derive from
the full authenticated committee, not the proof's selected signers.
Normal and DrainSet retention are independently verified carriers of that same
producer. Account for their exact keys and full artifact closure, including
retained but unapplied material; never blanket-ignore a publication prefix.
Application and availability certificate carriers may have different valid
signer subsets, but must authenticate the same execution/publication identity.

DrainSet reconstruction also receives explicit untrusted control-proof material,
bound to each authenticated original candidate digest and its exact selected
signed frontier votes. Reconstruct every selected entry stream from its seed
and require its signed terminal count and digest; source running digests,
progress, possession and ready flags are never replay authority. In the private
overlay, use the existing verified page ingestion, full-publication import,
entry confirmation and bounded union handlers to derive readiness, then run
the unchanged owning ordered handler and compare its original result/receipt.
Retention of unapplied material is not business application. Deterministic
pre-readiness refusals keep their owning preflight precedence. Missing or
contradictory required proof closure stops; an ordering QC cannot replace it.
Saved control pages share the fixed genesis/history/source-token binding and
immutable bounded-file/resumption contract with owned publication material.
Collect complete independently verified optional streams for authenticated
original controls regardless of the unsigned source Accepted/Refused status.
Private state decides whether missing closure must stop; a source refusal
cannot remove that dependency. Derive the actual selected union, not a claimed
union copied from the candidate. The owning handler must still independently
refuse a wrong claimed union and reproduce its exact original companions.
Honest pre-readiness refusals need no invented successful-control closure.

An actual accepted Freeze is also the last normal-admission replay barrier.
Preserve all preceding certified ordered events and their exact prerequisite
closures first. Before closing private admission, independently query the
owning completed-first admission and full Freeze preflight at the certified
block height: live authority, open admission and the normal warrant must all
hold. Only then resolve the still-applied Owned comparison targets through
their authenticated witness dependencies and ordinary paid recovery. This is
not an all-Owned-first ordering, request-ID sort or source-result scheduling
oracle. Refused, foreign, ineligible and completed/recommitted Freeze candidates
do not flush that remainder. A missing or contradictory prerequisite still
stops; retained but unapplied publications remain unexecuted. The same
ordinary handler subsequently closes admission and must reproduce the exact
source companions. No live closure fence is weakened for audit replay.

The initial audit supported applied Owned targets with a verified aggregate
availability certificate and the complete normal completion tuple. Existing
`apply_drain_member` can legitimately apply a committed member after Freeze
without that aggregate certificate; this is not made impossible by the audit
profile. The original boundary refused such a source rather than interpreting
it as unapplied or fabricating a certificate.
[DR-0174](0174-frozen-member-business-reconstruction.md) extends reconstruction
through that existing narrow member authority after independently replayed
committed controls and verified local union possession. This extension does
not assert complete drain, cut, import or activation.

Compare the complete semantic projection of state, original receipts, object
heads/versions/deletions and referenced blobs, including code/ABI/dependency/
instance/authority closure, nonces, escrow/claims, bonds/transitions, evidence/
consumption and epoch control. Project by owning schema. Preserve candidate-
bound checkpoints and fields inside signed/hash-linked rows. Exclude physical
CAS revisions, writer fences and unsigned creation coordinates only where
the signed logical profile explicitly makes them local. Known local signing
and reservation records are not transferred as business facts, but unknown
reserved records never inherit an exclusion just by prefix.

Use one backend-enforced portable snapshot token for real-store comparison.
Bound each descriptor/chunk/operation and saved step without an invented total
history ceiling. Every resumed file is immutable and reverified against its
locally pinned identity. Missing material, changed snapshots and incomplete
enumeration fail closed. Audit does not mutate the real source.

## Alternatives and tradeoffs

An additional result quorum can split across honest owned progress and wedge
immutable votes. A generalized execution envelope requires complete read/
absence fencing and safe abandoned-proposal supersession. Neither was proven
necessary for the closed current operation set.

A universal request-binding reservation avoids a lane bit, but needs partial-
admission arbitration and recovery rules. Disjoint lanes spend one ID bit and
require profile-aware clients, without adding that mutable locking protocol.
The namespace is protocol-wide, not a Standard Asset privilege.

Authenticated configuration reads consume real slots in the unchanged 4,096
atomic-read bound. This intentionally reduces the maximum application plan
for the historical generic durable handler from 4,096 to 4,092 keys: four
slots fence epoch, profile, manifest and its marker. An authenticated sender
nonce consumes another slot, and other lifecycle assertions can reduce the
remaining capacity further. `NodeStateAccessPlan::new` validates structural
plan size only; handler admission must also fit these protocol assertions.
This is an operational capacity change, including for historical profiles,
not a change to historical canonical bytes. The unreleased protocol does not
preserve the old maximum by skipping authentication or increasing the runtime
bound. Oversized plans fail before application reads, execution or commit.

## Boundaries and acceptance

The audit proves equality to supplied authenticated fixed material and one
source-local consistent snapshot. It does not prove network freshness, a
complete cut, persistent import, incoming-validator inactivity, readiness,
Seal, epoch activation or Delivery 3 completion. Legacy archives remain useful
ordering proofs but do not acquire the new reconstruction guarantee.

Integrated acceptance covers all lane entrypoints and synthetic exclusions;
genuine future-nonce recovery and justified-prefix successor admission;
contract lifecycle, charged traps, zero charge and replay; positive/zero-share
and competing claims; reachable bond/evidence/slash operations; Freeze/DrainSet
and inherited refusals; field-aware corruption and missing/cyclic material;
real PostgreSQL close/reopen and read-only comparisons; compiled CLI saved
material interruption/resumption. Final release additionally requires the full
repository gate, independent explicit exact-head approval and required CI.

No general reservation cancellation, force unlock, rollback of minority
applications or historical state overwrite is introduced. Unresolved partial
locks remain declared stops unless an existing narrowly authenticated drain
operation resolves precisely that conflict.

See [business reconstruction](../business-reconstruction.md),
[ordering history](../ordered-history.md) and
[complete handoff](0154-complete-epoch-handoff.md).
