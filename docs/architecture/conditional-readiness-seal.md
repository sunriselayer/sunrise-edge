# Conditional readiness and ordered Seal

The readiness-only contract in
[DR-0178](decisions/0178-conditional-readiness-wire-and-retention.md) refines
[DR-0154](decisions/0154-complete-epoch-handoff.md) and the earlier
[DR-0177 proposal](decisions/0177-conditional-readiness-and-ordered-seal.md).
Readiness is a nonexclusive assertion, not Seal, membership activation or
serving authority. The separate Seal design remains unresolved. Work and
validation status belong only in [TODO.md](../../TODO.md).

## Finite source of readiness

Use the first-outgoing-epoch CausalAdmission [pre-Seal cut](first-epoch-business-cut.md)
and [inactive import](verified-inactive-import.md). Incoming E and retained
A/B/C each need their own separate CompleteInactive staging namespace, fresh
full verification and actual registered signing key. A namespace selector is
not membership or key ownership. Duplicate state, immutable bodies and replay
work for retained members are an explicit cost, not a new Ordinary-signer bypass.
Incoming E's first liability must come from the genuine
[initial registration](initial-validator-bond.md), not a seeded bond or
fabricated Exited predecessor.

FreshImport and Importing cannot sign readiness. CompleteInactive remains
unable to admit fresh business, expose ordinary or cached live signatures,
advance the live ordered engine, bootstrap an ordinary host or activate.
Current Ordinary guards and receipt-first original business replay remain
unchanged. Only a separately reviewed activation may introduce serving authority.

## Private verification and signer contract

Before either new signing or retained replay, one closed core operation must:

1. Independently reconstruct the exact saved cut/raw plan under local genesis,
   chain/protocol, outgoing committee, domain, history and hash-suite pins.
   Verify actual original carriers, all installed rows and referenced bodies;
   normalized comparison subjects and completion flags are not constructors.
2. Require exact CompleteInactive origin, immutable binding and completed
   progress, then verify the destination under a current local snapshot token.
   Read the exact bounded retained slot. Present records undergo strict
   linkage/signature verification; retries perform the same target verification
   and return those original bytes without re-signing. Absence is only absence
   of a cached record, never proof that the key has never signed.
3. Derive successor eligibility from those same reconstructed post-drain facts.
   Require checked adjacent epoch, 1..256 members, unique registered IDs and
   keys, the existing Ed25519-only activation scheme, positive weights and
   checked total power. Require canonical 32-byte public keys and 64-byte
   signatures under the locally pinned verification profile. All successor
   keys require canonical, nonidentity prime-order Ed25519 admission; historical
   ZIP-215 signature verification is not changed. Reuse
   structural activation-set checks and the existing committed bond/resource
   predicate: Active bonds, valid lifecycle/slashability, matching registered
   key/scheme and enabled resource/minimum/exposure policy. Bond amount does
   not select power; Freeze's advisory set is not irrevocable membership.
4. Match the actual signer identity, scheme and public key to that registered
   entry **before signing**. Current ConsensusSigner has no public-key accessor:
   `ReadinessSigningKey` owns its real software key and derives that key's
   public bytes. It does not implement ConsensusSigner or expand ordinary/live
   signer authority. Its signature counter is diagnostics, not authorization.
5. Verify the new or retained signature against the registered key and exact framed
   readiness message before protected retention. Expose it only after exact
   landed retention is observed through confirmed atomic retention or fresh
   fenced reconciliation.

The private capability must not have a constructor from decoded rows, supplied
reports, a namespace label or a public maintenance Boolean. Structural reuse
does not call the unsupported Logical activation writer or install policies.

## Semantic subject and local record

The semantic readiness subject binds pinned genesis, chain/protocol, outgoing
epoch/set, logical domain, exact semantic cut and checked adjacent-epoch
successor-set identity. Its canonical set digest binds the separately supplied
bounded full set at the incoming epoch. Bind every entry and hash purpose of
the separately trusted local schedule, including future entries. The genesis
manifest does not authenticate that schedule. Hash its existing canonical
0xC003 frame in NodeEvent at the outgoing epoch and recompute the commitment
against local configuration before accepting a vote or certificate. Sign with
a **distinct readiness purpose at the outgoing
epoch**, never an ordinary vote, availability ACK or transition-vote purpose.
The closed signed payload also binds the registered signer ID and scheme;
certificate assembly cannot relabel a signature as another member or purpose.
The closed public frames are 0xD040 subject, 0xD041 payload, 0xD042 vote and
0xD043 certificate. The 0x2001 signing frame carries the exact payload under
`conditional-readiness-v1`, not a lifted ordinary vote or bare digest.
These public values remain assertions. A correctly signed supplied set alone
does not construct verified eligibility, completeness, Seal or activation.

Exclude exact proof-package/raw-plan variants, local coordinates/revisions,
snapshot tokens, writer generations and future Seal identity. Equivalent valid
full-proof subsets must share one semantic cut/set subject. Local retention
instead binds the exact package/plan, immutable destination binding, completed
progress and the retained record's creation observation. Equivalent packages may use different
fresh local bindings; they cannot rebind an existing target.

Readiness is nonexclusive before Seal: a corrected eligible set for the same
cut has another identity and does not replace earlier signatures. There is no
epoch singleton or global candidate cap. A different business/control cut
requires an independently verified saved cut and fresh immutable import binding,
never mutation, reset or deletion of the prior origin.

## Bounded protected per-identity retention

Retain one bounded closed record keyed by the full semantic identity and signer.
Mandatory namespace lifecycle, immutable binding, completed progress and exact
store/schema validation remain authoritative. Missing or corrupt target metadata
never becomes a fresh target, readiness capability or ordinary-host fallback.
Exact local records use 0x64D0 slot, 0x64D1 record and 0x64D2 creation observation.
The owning `durable_conditional_readiness` table is outside business inventory;
its schema and bounded exact lookup are still mandatory. The shared metadata
identity is v4, the native SQLite durable schema is v3 and the aligned ordinary
PostgreSQL identity is v5. Older initialized targets are unsupported, never
automatically migrated, recreated or repaired. PG import/readiness is not
introduced by an ordinary schema identity update.

Present records must match the local import identity and exact semantic subject,
registered signer and verified signature. Malformed/conflicting records and any
known tombstone refuse; do not overwrite or repair. This capability introduces
no reset/delete/pruning or tombstone-management operation.

A closed storage-only retention transaction atomically validates CompleteInactive,
exact binding/completed progress, the **fresh verified target token**, current
domain/fence/deadline and exact retained-slot observation. It inserts one bounded
signed record into an absent slot or compares the original retained record.
Concurrent changes require fresh verification/reconciliation, not overwrite. Protected
writes advance the covered local snapshot sequence. Readiness metadata stays
outside business roots and installed raw inventory through its exact owning
schema, never a blanket prefix exclusion or ordinary transaction bypass.

No mandatory whole-ledger/head/index walk or global sign-once invariant is
needed for this nonexclusive readiness assertion. Deterministic Ed25519 over
the same framed subject produces the same public vote; another fresh imported
namespace is already permitted to produce it. Certificates count the registered
signer once. Repeating a valid assertion neither adds power nor selects a unique
pre-Seal target. A global audit/no-resign history would be a separate requirement.

This reasoning does not apply to unique ordered votes or post-Seal transition
targets: losing their signing history may permit contradictory authority and
their existing protections stay unchanged. Ordinary CAS/fencing also does not
detect a mutually consistent whole-database rollback without an independent
anchor; no external hardware/anchoring guarantee is introduced here.

## Retry, restart and uncertainty

The record's creation observation is immutable while that record is present,
not the token a later retry must reuse. A retry freshly verifies the entire import,
obtains a current token and atomically validates it. It then returns the same
retained signature without re-signing, preserving the original observation.
Never require equality between old observation and current token, and never
ignore a stale current token because an entry appears identical.

An absent cached record may permit new signing only after all fresh target,
eligibility and actual-key checks succeed. It does not prove virgin key history.
Recreation must not claim preservation of an unknown historical first observation;
it records this retention's observation. Normal present-record replay stays exact
and non-signing. Known tombstones or conflicting present records still refuse.

An ambiguous retention acknowledgement exposes no newly computed signature.
Fresh fenced reconciliation must observe the exact durable identity and retained
record/signature before returning it. Absence or rejection alone never justifies
exposing an unretained signature. Conflicts never overwrite or repair.

## Closed bounds and explicit costs

| Public component or new work | Maximum |
| --- | --- |
| Canonical successor set | 64 KiB, 1..256 members |
| Semantic subject | 16 KiB |
| Readiness vote | 4 KiB |
| Certificate | 1 MiB, at most 256 distinct votes |
| New signing/retention per call | At most one new signature and one 16 KiB record |
| Retained slot read/CAS | One exact record, at most 16 KiB including framing |

Validate byte/count bounds before allocation and framing. Votes/certificates
bind the semantic subject/set identity; exact layouts and preimages are owned
by DR-0178 and checked against independent Node/OpenSSL vectors. Quorum uses distinct registered next-set
signers and the existing strictly greater-than-two-thirds checked power rule,
not member count or the outgoing committee's threshold.

Legal total history and number of candidates remain unbounded. Public inputs
use bounded references/components, not a whole-history or arbitrary candidate
vector. Retention uses exact identity lookup, not a scan over all prior candidates.
Existing saved-cut/import readers retain their bounded page/chunk contracts.
Full private reconstruction and destination comparison retain explicit linear
cost; this is not a constant-memory, constant-time or bounded-total-history claim.

## Subsequent Seal boundary, still unresolved

Fix the exact pre-Seal business-prefix anchor. This first boundary admits only
fully proof-checked post-anchor empty progress with unchanged business roots
and generation floor. Different business/control material requires another
verified cut/binding. The cut's fixed terminal three-chain does **not** prove
the live high/locked suffix; equal applied/committed heights do not prove it either.
Checking outgoing empty progress grants no live-progress rights to inactive staging.

Before Seal implementation, specify complete phase-aware high/locked and
justification traversal, inherited candidate authentication, bounded continuation
and exact Seal candidate/proof-companion ownership. Process justified committed
progress and fence all relevant observations. Resolve inherited business-bearing
suffixes through normal recovery, without erasing locks/QCs or original outcomes.

Seal must use the existing ordered engine and narrowly warranted post-DrainSet
control admission; current broad refusal is not weakened by readiness. Competing
uncommitted Seal proposals do not create a singleton target lock. Only normal
committed acceptance fixes the immutable target. Seal's own proof/receipt stays
outside its pre-Seal cut, avoiding circular roots. Seal, transition voting,
activation and policy/provenance/serving rollover are subsequent features, not
readiness-only acceptance requirements.

## Owners and required readiness evidence

Reuse [private import reconstruction](../../crates/node-core/src/business_reconstruction/inactive_import.rs),
[epoch eligibility](../../crates/node-core/src/epoch_transition.rs),
[validator-set rules](../../crates/validator-set/src/lib.rs) and
[signature framing](../../crates/crypto/src/lib.rs). Runtime memory/shared SQL
and dedicated SQLite import composition own protected retention, not protocol
validity. Operator local pins, genuine key binding and held artifact outputs
own a callable local workflow; a host/router cannot manufacture completeness.
Do not add a duplicate generic readiness framework.

Required acceptance evidence includes:

- Genuine complete history with more than 128 rows; real SQLite staging for
  A/B/C/E, actual initial E registration and independently registered keys. Compare
  every original receipt/body/provenance/floor, including close/reopen and
  partial-import refusal, without seeded eligibility or noncryptographic signers.
- Equivalent proof variants yielding the same semantic subject; corrected sets
  retaining multiple identities; adjacent-epoch overflow, duplicate IDs/keys,
  zero/overflow weights, ineligible bond/resource, wrong key/scheme and foreign
  pins producing no signature. Verify actual signatures and weighted quorum.
- Missing/corrupt mandatory target metadata, wrong/conflicting present records,
  known tombstones and stale verification token/fence refusal. Absent-cache
  recreation must fully reverify and preserve identical public vote bytes without
  claiming old local observations. Duplicate votes never add quorum power.
- Real SQLite restart/exact retry with no re-signing, both ambiguous-retention
  directions and fresh reconciliation. Ordinary/live signer counters stay zero;
  only privately authorized readiness signs, and original business replay stays exact.

The closed wire/storage frames, fresh-token CAS and actual-key owner have a
separate accepted design boundary. Callable local composition is documented
in the [readiness guide](../guides/conditional-readiness.md). Future Seal
traversal/companion review remains separate and unresolved.

PostgreSQL is optional; relevant changes/claims need selected actual acceptance.
SQLite readiness implies no PG import, DO deployment or provider certification.
This capability completes no activation, Delivery 3, live startup, security audit,
production/mainnet release or deferred product/production gate.
