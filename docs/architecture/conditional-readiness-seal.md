# Conditional readiness and ordered Seal

Proposed refinement of [DR-0154](decisions/0154-complete-epoch-handoff.md),
recorded in [DR-0177](decisions/0177-conditional-readiness-and-ordered-seal.md).
The first implementation candidate is **readiness only**. This document is not
accepted code authority, a wire/key allocation, a migration or completion
claim. Work and validation status belong only in [TODO.md](../../TODO.md).

## Finite source of readiness

Use the first-outgoing-epoch CausalAdmission [pre-Seal cut](first-epoch-business-cut.md)
and [inactive import](verified-inactive-import.md). Incoming E and retained
A/B/C each need their own separate CompleteInactive staging namespace, fresh
full verification and actual registered signing key. A namespace selector is
not membership or key ownership. Duplicate state, immutable bodies and replay
work for retained members are an explicit cost, not a new Ordinary-signer bypass.

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
   Completely verify the protected ledger and indexes before any new signing.
   Retained retries perform the same verification and return the original
   without re-signing.
3. Derive successor eligibility from those same reconstructed post-drain facts.
   Require checked adjacent epoch, 1..256 members, unique registered IDs and
   keys, the existing Ed25519-only activation scheme, positive weights and
   checked total power. Require canonical 32-byte public keys and 64-byte
   signatures under the locally pinned verification profile. Reuse
   structural activation-set checks and the existing committed bond/resource
   predicate: Active bonds, valid lifecycle/slashability, matching registered
   key/scheme and enabled resource/minimum/exposure policy. Bond amount does
   not select power; Freeze's advisory set is not irrevocable membership.
4. Match the actual signer identity, scheme and public key to that registered
   entry **before signing**. Current ConsensusSigner has no public-key accessor:
   review a narrow owning key-bound adapter, not caller-asserted key metadata
   or a blanket expansion of ordinary/live signer authority.
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
bounded full set. Sign with a **distinct readiness purpose at the outgoing
epoch**, never an ordinary vote, availability ACK or transition-vote purpose.
The closed signed payload also binds the registered signer ID and scheme;
certificate assembly cannot relabel a signature as another member or purpose.

Exclude exact proof-package/raw-plan variants, local coordinates/revisions,
snapshot tokens, writer generations and future Seal identity. Equivalent valid
full-proof subsets must share one semantic cut/set subject. Local retention
instead binds the exact package/plan, immutable destination binding, completed
progress and first-retention observation. Equivalent packages may use different
fresh local bindings; they cannot rebind an existing target.

Readiness is nonexclusive before Seal: a corrected eligible set for the same
cut has another identity and does not replace earlier signatures. There is no
epoch singleton or global candidate cap. A different business/control cut
requires an independently verified saved cut and fresh immutable import binding,
never mutation, reset or deletion of the prior origin.

## Mandatory protected append-only ledger

A readiness-capable import target must atomically initialize its mandatory
protected ledger anchor with the **fresh namespace initialization**, before any
readiness operation. Earlier initialized targets without it are unsupported
for readiness: refuse and freshly reimport into another staging target. Never
lazily initialize, automatically upgrade, repair or infer a virgin ledger from
absent records. This proposal allocates no schema version or capability registry.

The protected anchor/head and entries bind the destination-local identity,
checked contiguous ordinal/count and hash chain. Keep an immutable
identity-plus-signer index with exact ledger correspondence. Any deleted or
tombstoned index is invalid, not unused identity. No separate deletion,
tombstone-management or pruning API is needed for this append-only capability.
Verify complete continuity from the initialized anchor to the observed head,
with exact index/entry correspondence. Missing anchor/head/entry/index, ordinal
gaps, conflicting bytes, invalid links or malformed metadata refuse before
signing. No reset/delete/pruning operation is introduced.

A closed storage-only retention transaction atomically validates CompleteInactive,
exact binding/completed progress, the **fresh verified target token**, current
domain/fence/deadline and expected ledger head/count/root with the verified
index-inventory observation. These ledger observations join retention CAS
alongside the fresh destination observation. It appends one bounded signed
record and index/head changes, or compares an exact retained record. Protected
writes advance the covered local snapshot sequence. Readiness metadata stays
outside business roots and installed raw inventory through its exact owning
schema, never a blanket prefix exclusion or ordinary transaction bypass.

Ordinary CAS/fencing detects stale writers and malformed/deleted protected
records, not a mutually consistent rollback of the entire database. Detecting
that rollback needs an independent anchor and is not guaranteed here; this
proposal adds no external hardware or anchoring service.

## Retry, restart and uncertainty

The first-retention observation is immutable record evidence, not the token a
later retry must reuse. A retry freshly verifies the entire import and ledger,
obtains a current token and atomically validates it. It then returns the same
retained signature without re-signing, preserving the original observation.
Never require equality between old observation and current token, and never
ignore a stale current token because an entry appears identical.

An ambiguous retention acknowledgement exposes no newly computed signature.
Fresh fenced reconciliation must prove the exact durable identity, original
record/signature and consistent ledger before returning it. A genuinely absent
entry may authorize new signing only after complete anchored-ledger verification;
a missing record alone proves nothing. Conflicts never overwrite or repair.

## Proposed bounds and explicit costs

| Public component or new work | Proposed maximum |
| --- | --- |
| Canonical successor set | 64 KiB, 1..256 members |
| Semantic subject | 16 KiB |
| Readiness vote | 4 KiB |
| Certificate | 1 MiB, at most 256 distinct votes |
| New signing/retention per call | At most one new signature and one 16 KiB record |
| Protected ledger page | At most 64 entries and 1 MiB |

Validate byte/count bounds before allocation and framing. Votes/certificates
bind the semantic subject/set identity; exact closed layouts and signature
preimages remain pre-code review gates. Quorum uses distinct registered next-set
signers and the existing strictly greater-than-two-thirds checked power rule,
not member count or the outgoing committee's threshold.

Legal total history and number of candidates remain unbounded. Public inputs
use bounded references/components, not a whole-history or arbitrary candidate
vector. Ledger pages/continuations bind namespace, exact import/readiness identity,
signer, observed ledger head and current snapshot/fence. Head changes or missing,
gapped or orphan index material invalidate continuation: never silently adopt a
suffix or infer virgin signing authority. A partial walk never authorizes signing.
Full private reconstruction and a complete ledger walk have explicit linear
cost; this is not a constant-memory,
constant-time or bounded-total-history claim.

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

Required future evidence includes:

- Genuine complete history with more than 128 rows; real SQLite staging for
  A/B/C/E, actual Deposit E facts and independently registered keys. Compare
  every original receipt/body/provenance/floor, including close/reopen and
  partial-import refusal, without seeded eligibility or noncryptographic signers.
- Equivalent proof variants yielding the same semantic subject; corrected sets
  retaining multiple identities; adjacent-epoch overflow, duplicate IDs/keys,
  zero/overflow weights, ineligible bond/resource, wrong key/scheme and foreign
  pins producing no signature. Verify actual signatures and weighted quorum.
- Missing/deleted ledger anchor/head/entry/index, orphan indexes, tombstones, gaps/corrupt links,
  foreign/reordered continuations and stale verification token/fence refusal.
  Exercise multiple ledger pages and initialized old-target refusal without repair.
- Real SQLite restart/exact retry with no re-signing, both ambiguous-retention
  directions and fresh reconciliation. Ordinary/live signer counters stay zero;
  only privately authorized readiness signs, and original business replay stays exact.

Before code, review closed frames/preimages, exact fresh anchor/entry/index and
first-observation schema, token/ledger traversal semantics and key-bound signer
adapter; perform the canonical namespace sweep and independent vectors then.
Future Seal traversal/companion review remains separate and unresolved.

PostgreSQL is optional; relevant changes/claims need selected actual acceptance.
SQLite readiness implies no PG import, DO deployment or provider certification.
This proposal completes no activation, Delivery 3, live startup, security audit,
production/mainnet release or deferred product/production gate.
