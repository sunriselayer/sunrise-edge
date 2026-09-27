# Complete epoch handoff

This is the handoff-capable **To-Be**, governed by
[DR-0154](decisions/0154-complete-epoch-handoff.md). It is not a description of
the existing fixed-epoch implementation. Implementation and validation status
belong only in [`TODO.md`](../../TODO.md).

## Guarantees and fault model

Preserve every authenticated atomic application, even if only one replica
applied it and that replica is now unavailable. Do not roll back its objects,
receipt, nonce or fee settlement. A caller-supplied transaction list, valid
individual records or a majority's current state do not establish completeness.

For outgoing voting power `T`, use the existing strict greater-than-two-thirds
quorum `q = T - floor((T - 1) / 3)`. Byzantine power must be strictly below
`T / 3`; Byzantine signers need not obey our locks or use our software. Safety
holds under delayed, duplicate and reordered delivery. Progress requires an
eventually responsive honest outgoing quorum, the required next-set quorum,
and delivery of bounded continuation events. No daemon, persistent socket,
timeout unlock or cloud provider is an authority.

Two quorums intersect in power at least `2q - T > T / 3`, hence in honest
power. This proves an honest intersection, **not** that missing payloads or an
aggregated certificate can be recovered from partial votes.

## Why the existing apply rule must change

Consider equal-power A/B/C/D, Byzantine C and absent D. A and C sign X; B and
C sign conflicting Y. In one world D signs X and applies its certificate; in
another D signs Y and applies it. A/B/C observe the same partial votes. C can
sign both outside the honest implementation. Although two conflicting full
certificates cannot coexist in one valid history, the survivors cannot tell
which hidden certificate exists.

Today's prepared record retains votes and hashes, not the original signed
intent. A prepared quorum therefore supplies neither the missing full
certificate nor its payload. Even retaining the original intent at prepare
would not resolve the indistinguishable hidden-certificate case.

The handoff-capable profile requires a separate durable **publication before
application**. This adds one execution-free quorum round; it does not globally
order ordinary owned-object calls or introduce a quorum-of-applied-effects
finality rule.

| Evidence | Meaning in this profile |
| --- | --- |
| `FastCertificate` | Existing outgoing-set authorization for the exact signed intent and execution commitment; alone it cannot admit a new application |
| Availability certificate | A quorum retained the full verifying certificate, original signed intent and required replay artifacts before acknowledging them |
| Ordered drain/seal proof | The outgoing shared engine chose the complete closed frontier and final handoff state; not a caller's assertion of completeness |

### Execution-free publication

After FastVote aggregation, `retain` verifies the original authorization,
context, logical atomicity domain, full FastCertificate and replay-artifact
binding. It retains the exact signed intent, a valid full certificate, the
authenticated execution checkpoint operand, logical commitment witness and
content-addressed artifact/dependency references. All referenced bytes must
actually be available and verified before an ACK is exposed; a hash alone is
not retention. Existing code/ABI/object provenance remains mandatory.

Retention does not execute WASM again, move objects or custody, charge fees,
advance the sender nonce, release locks or create an original user receipt.
An honest retainer may hold a conflicting **partial** local prepare: verifying
and storing a full certificate is not permission to overwrite that lock.

Persist the publication record and exact ACK identity atomically under writer,
epoch and admission-state CAS fences. Only a confirmed commit or exact
reconciliation may expose the retained ACK. A failed or ambiguous write cannot
expose a fresh signature. Aggregate distinct registered signers of power at
least `q` over the same publication identity into an availability certificate.
Signatures bind chain/protocol/epoch, domain, original request and intent,
execution commitment and artifact identity under an explicit canonical domain.

`apply` and signerless recovery require the availability certificate in the
open epoch. Application remains one atomic commit of original effects, exact
receipt, nonce, settlement and precise bookkeeping. Charged traps follow the
same rule. Retained original completion replay precedes fresh epoch, policy,
module, object and reservation work and never reapplies effects or fees.

Equivalent valid FastCertificate signer subsets denote one operation, not two
effects. Retain the actual proof bytes for audit, but compare the verified
intent/commitment identity for logical-state equality. Alternate proof subsets
cannot manufacture a second charge or rewrite a retained receipt.

## One ordered epoch-control chain

Extend the existing shared HotStuff operation family with closed epoch-control
commands. Do not create a parallel first-writer-wins epoch voting chain.
Commands occupy the existing operation-bearing slots and use the same normal
leader, view, lock, QC and three-chain commit rules. Ticks affect liveness only.

```text
Open -> Freeze committed -> Frontier fixed -> Drain completed -> Seal committed
                                                                  |
                                               local verified readiness
                                                                  |
                                                    Activate next epoch
```

### 1. Freeze and fix authenticated frontiers

Only a committed outgoing-set `Freeze` changes admission. Bind its identity to
the chain/protocol/epoch/domain, ordered block and proposed eligible next set.
A proposal or operator request alone cannot freeze a replica. Check next-set
eligibility through the existing bond, key, policy and power rules; bond value
must not become voting power.

At each replica, commit the closed-admission marker with processing this
ordered prefix. Stop new prepares, new retention ACKs, direct local/paid
mutations and construction of fresh economic candidates. Publication commits
racing this boundary must assert the admission-marker revision: either their
full artifacts enter the frozen log before their ACK is exposed, or they fail
without exposing a signature.

Still allow historical reads, exact completed replay, safe shared-engine
progress and catch-up. Ordinary fresh apply stops; certificate-backed missing
applications resume through the selected drain authority, not a blanket
mutation bypass.

Derive a signed frontier from **all full certificates retained locally before
closure**, including records whose availability ACKs were never aggregated or
whose operation was never applied locally. Include the necessary ordered
prefix/proof artifacts. Persist the immutable frontier descriptor before
signing it. Enumerate it incrementally while publication stays closed.

An untrusted coordinator proposes at least `q` power of verified frontier
descriptors and all their pages. Select only complete, retrievable frontiers;
unavailable or forged pages cannot count toward that quorum. Construct the
union of full-certificate operation identities and authenticated dependency
closure. Every verifier reconstructs this union, not just its digest/count.
Choose exactly one `DrainSet` by a normal outgoing ordered commit.

If any operation applied, an availability quorum retained its **full** proof
and payload before application. That quorum intersects the selected frozen
frontier quorum in an honest retainer, whose fixed log includes it. Thus the
union contains every applied operation, even if its only applying replica is
absent or the ACKs were aggregated only after freeze. A retainer need not hold
the aggregated availability certificate for this proof to work.

No new availability quorum for an operation absent from this union can form:
an honest intersection member is closed to new ACKs and its previous ACKs are
already covered. This is why leaving `retain` open while draining is forbidden.

### 2. Drain without speculative execution or rollback

The committed `DrainSet` authorizes completing its verifying full-certificate
operations while their original epoch is still current, including full
certificates for which no aggregated availability certificate was supplied.
Do not drain transactions supported only by partial prepare votes.

Apply in verified causal order: code/dependency publication, instance creation,
input versions and sender nonces precede dependent operations. Missing,
contradictory or unauthenticated prerequisites stop progress; no opaque DB copy
or supplied witness alone overrides current heads or origin authority.

A survivor may have a partial prepare Y conflicting with a full certificate X
in the drain. Two conflicting full certificates cannot exist: their prepare
quorums share an honest voter that cannot reserve the same version/nonce for
both. Therefore a narrowly scoped drain application may resolve Y only after
verifying the committed DrainSet, X's full certificate, the actual conflict
and exact observed local Y reservation rows. Resolve only conflicting
reservations needed by X; other old Y reservations can become stale at
activation. This authority is confined to the
frozen epoch/cut. Keep an internal resolution audit and use CAS; never release
an unrelated lock, overwrite a newer object head, rewind a nonce or delete an
original receipt. Fold required reservation resolution into the same atomic
application as X's effects/receipt/nonce/settlement.

Uncertified prepares need not all disappear before handoff. Preserve their
scoped local audit and make their old-epoch reservations inactive at activation.
They had no effects; there is no fee refund or synthetic successful application.
Do not create a global original-user refusal receipt merely from one
validator's alleged pending request: a Byzantine claim must not reserve an
arbitrary request ID. A boundary refusal may be reported without pretending
that an unauthenticated claim was an executed user transaction.

### 3. Preserve shared-engine safety before sealing

Do not reset old high/locked QCs or assume every uncommitted branch is dead.
Process the existing committed prefix and inherited justified proposals using
normal HotStuff ancestry, view and lock rules. Before exposing a new vote,
account for any Freeze committed by processing the proposal's justification;
admission must use the resulting control state, not a stale pre-event snapshot.

An inherited economic candidate that commits after Freeze receives a
deterministic, authenticated no-effect closed-epoch refusal, its original
retained outcome and exact reservation cleanup. It does not mutate economic
state or advance its sender nonce. A storage failure, missing artifact,
tombstone corruption or indeterminate commit is not such a refusal: stop and
recover. A branch that never commits has no global original outcome; its local
reservations become stale only through the authorized epoch boundary.

Advance with empty/control proposals until all ordered business outcomes in
the prefix are applied and the seal's continuing high/locked suffix is
business-free. Any business-bearing justification must be resolved first,
not hidden behind a claimed equal applied/committed height. Do not reject the
consensus messages needed to reach this barrier. After Seal, only empty
progress and the retained activation decision can progress the old engine;
no new user outcome may appear behind the sealed state. Treat the seal suffix
as a protocol predicate over complete verified block headers/justifications,
not a leader's Boolean claim. Include imported inherited candidates and their
authentication in the applied prefix before deriving the state to seal.

### 4. Seal, verify readiness and activate

Each outgoing voter independently derives the normalized final logical state,
original receipt history and complete artifact manifest after drain. `Seal`
commits their identity and exact eligible next set through the same old engine.
Voting requires the committed business prefix applied, drain complete, no
unresolved authenticated facts and equality with the locally derived cut.
Signature-subset differences and local database counters are not disagreement
about business state.

The cut commits the **pre-Seal business snapshot** and verified replay prefix,
not a row that contains its own cut digest. Bind genesis/predecessor cut,
outgoing context/set/domain, committed DrainSet, applied business-prefix anchor,
normalized business-state/receipt roots and the artifact manifest. The current
Seal, its proof, control-phase bookkeeping, its internal command receipts and
the later activation/readiness proofs are companion authority artifacts outside
that snapshot/manifest. Previous epochs' authority history stays bound through
the predecessor anchor. This avoids a self-referential root and distinguishes
business-state equality from changing consensus/control metadata.

A new host imports using **its own** writer fence into an ineligible namespace.
It independently verifies genesis, full history, artifact closure and sealed
logical state. A remote readiness signature never substitutes for that local
verification. Serve/sign as the new active validator only after a durable
verified-cut marker and activation. Require a next-set quorum's readiness for
this exact cut/context/set before outgoing activation votes are exposed.

Cast an epoch-transition vote only for the committed Seal. Persist its exact
signed identity before exposure, retain it on retry, and refuse another target.
Before Seal, proposal changes use ordinary HotStuff views; they cannot wedge
an epoch-wide first-writer-wins transition-vote row. Bind activation to the
outgoing authority, Seal/DrainSet proofs, cut and next set; rederive/verify
locally and install new policies/epoch atomically with fences.

In this initial profile a committed Freeze is a commitment to finish that
epoch. There is **no local unfreeze or cancellation transition**. Resume through
normal quorum/view progress; only verified activation reopens fresh admission.
An uncommitted proposal may be abandoned without changing admission. Loss of
the required outgoing or next-set quorum safely stops progress; it is not
permission for a force flag. A separate future cancellation protocol would
need an ordered authority and its own proof and is not an implementation
prerequisite disguised as an operator escape hatch.

## Portable commitment and cut schema

Current `fast_path/commitment.rs` v1 includes some generic state/nonce revisions,
object-head revisions and creation-checkpoint fields. Merely dropping local
fields from the transfer root does not make its signed witness replayable.
The new profile needs a logical staged-commit encoding: bind exact original
signed intent and result, read keys with authenticated content observations,
pristine-versus-deleted tags, semantic generations, ObjectRefs, mutations,
authorities, nonce value/precondition and the authenticated execution operand.
Keep node-local `StateRevision`, head revision and writer generation solely in
the local commit read set. **Do not remove read authority along with counters.**
Historical v1 witnesses remain verifiable as their original bytes.

Define explicit runtime-neutral bounded repositories; the current key scanner
does not enumerate the separate SQL receipt, object-head or object-version
tables. Each collection has canonical keys, exact semantic projections and
complete range boundaries:

- Code/ABI/blob content and authenticated publication/dependency provenance.
- Instance and created-object authority, defining-code policy and type/schema.
- Immutable object versions and current/deleted heads, including logical
  versions, digests, provenance, body and logical owner/routing projections.
- Original request receipts, dedup identities, nonces and relevant state
  values/deletion tags; no transplant of synthetic admission receipts.
- Escrows, entitlement/claim/settlement history, bonds/custody, evidence,
  eligibility and historical policy/epoch transitions.
- Full-certificate publication artifacts, ordered committed business outcomes
  and the dependency/authority proofs required to replay them.

Use a closed key/schema classifier: unknown protocol rows cannot be silently
skipped. Local prepare/vote/lock identity, writer/schema tokens, delivery cursors
and import/hash progress are local metadata, not global business facts. Retain
necessary historical proofs separately; normalized roots may ignore equivalent
signature subsets but must not ignore signed execution operands, tombstones,
nonce/claim generations or history that affects future authority.

Use the committed protocol HashSuite and canonical framing, not a new
cryptographic primitive. Pages bind collection, frozen frontier/cut identity,
ordered key ranges, counts and authenticated content linkage. Reject omission,
addition, duplicate/reordered entries, foreign pages and tombstone-as-absence.
Bound bytes/entries per page and pages/work per invocation; persist a CAS-fenced
cursor/running digest for continuation. Large **legal** records must transfer
as bounded authenticated chunks rather than become impossible to export.
There is no arbitrary whole-history/cut-size ceiling. New exact frame/key IDs
and constants require the repository namespace sweep and stable/adversarial
vectors before implementation; no IDs are allocated by this design document.
Derivation/drain staging must also obey the runtime's existing transaction
read/write/byte bounds, including extra cut-fence and conflict-resolution reads;
never turn an over-limit step into partial business application.

## Recovery and serving authority

Separate immutable signed-genesis trust at epoch g from verified live serving
context at c. Replay authenticated operations and controls **within each
epoch**, then its activation, then the next epoch. Installing all transitions
before replaying old operations violates existing epoch fences. Exact original
completed replay is separate and remains read-only across epochs.

Retain old ordered history; scope new live engine/leader/vote/high-QC keys by
epoch and derive the new anchor from the verified predecessor cut and next set.
Do not overwrite old safety state or treat a tombstone as never-created.
Derive current fee/execution/publication policies from committed authority.
Economics authority defined by historical code is not blindly rewritten to c.
Keep TLS endpoint checks and locally pinned protocol-context validation distinct
before signing. Transport callers, relays and supplied live-epoch hints remain
untrusted. A retired key verifies history but authorizes no fresh work.

This is a fresh handoff-capable genesis/profile, not an optional request flag.
A bare legacy certificate cannot reach a mutation fallback. Existing stores
with pre-rule applications lack the required availability guarantee: refuse
their unsupported handoff rather than silently migrate, discard facts, reset
databases or certify absence. No destructive migration is authorized. Preserve
historical read verification and original completed bytes without keeping an
unsafe active legacy path.

## Integrated verification obligations

Use old A/B/C/D and a genuinely fresh E namespace. Generate real paid generic
Publish/Instantiate/Call, Standard Asset operations, charged traps, fee claims
and original receipts. Actually Deposit E, Unbond D, replace D while absent,
verify/import the complete cut, execute contracts/claims under A/B/C/E and
advance to D's recorded unlock epoch before genuine Withdraw. No fixture-only
Exited/Unbonding state or Standard Asset-specific admission backdoor.

Test Byzantine dual partial votes; privately aggregated availability ACKs;
application only on absent D; pre-freeze ACK aggregated afterward; the
retain/freeze CAS race; full-certificate drain against a conflicting partial
local lock; uncertified claims that must not occupy global receipt IDs;
inherited high/locked business branches; different physical revisions with
identical logical state; all cut/page/history negatives; real stale writers;
process restart at every boundary; exact successful/trapped/completed replay;
early/still-member withdrawal refusal and retired-signer rejection.

The whole core/HTTP/SDK/CLI/multi-validator feature, full repository gate and
independent exact-head review are one delivery. Independent operational control,
release security audits and live startup are separate from namespace-only E2E.
No public deployment, real custody, HA/load/provider certification or production
readiness is implied.
