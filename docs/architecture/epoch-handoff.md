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

For each outgoing/next committee's voting power `T`, use the existing strict greater-than-two-thirds
quorum `q = T - floor((T - 1) / 3)`. Byzantine power must be strictly below
`T / 3`; Byzantine signers need not obey our locks or use our software. Safety
holds under delayed, duplicate and reordered delivery. Progress requires an
eventually responsive honest outgoing quorum, the required next-set quorum,
and delivery of bounded continuation events. Historical authorizing signatures
must remain unforgeable, including retired-key handling; genesis verification
alone is not proof of a peer's claimed latest epoch. No daemon, persistent socket,
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

The publication input is a versioned, canonical bundle, not a certificate
plus a caller-chosen list of hashes. It contains the original signed intent,
one verifying full certificate, the exact logical commitment witness, and a
closed manifest of the bytes needed to replay that witness. The retainer
strictly decodes every witness field and derives the required artifact set
from its signed read, object and mutation operands and the transitive
code/ABI/dependency closure. It verifies the content of every present state
value, immutable object version, code/ABI record and referenced blob against
the witness hashes and committed hash suite. A missing dependency,
unknown artifact kind, contradictory version, duplicate key, unverified blob
or claimed tombstone presented as absence refuses the ACK. Manifest entries
are canonically ordered by kind and identity and include content digest and
length; the availability identity signs the manifest digest. Transfer and
verification are bounded and resumable, but an ACK is exposed only after the
complete closure has been durably retained and rechecked.

The full FastCertificate's quorum attests to the exact logical witness hash;
it does not turn a retainer's own prepared lock or its local physical
provenance rows into a portable proof. The retainer verifies the witness and
bundle without re-running admission against local heads or locks, which may
legitimately contain a conflicting partial prepare. The independently
reconstructed cut later replays the authenticated history and checks the
semantic provenance chain before the next set becomes eligible. Neither a
bare certificate nor an unauthenticated local provenance row can substitute
for this two-stage verification.

Persist the publication record and exact ACK identity atomically under writer,
epoch and admission-state CAS fences. Only a confirmed commit or exact
reconciliation may expose the retained ACK. A failed or ambiguous write cannot
expose a fresh signature. Aggregate distinct registered signers of power at
least `q` over the same publication identity into an availability certificate.
Signatures bind chain/protocol/epoch, domain, original request and intent,
execution commitment and semantic replay-artifact identity under an explicit
canonical domain. This identity excludes FastCertificate signer-subset bytes:
verify and retain at least one full proof, retain its exact audit bytes, and
return the same ACK for an equivalent valid proof. Do not fragment availability
votes or permit unbounded proof-variant storage for the same operation.
Before returning a retained ACK on retry, verify the saved context, request
identity, original intent, witness, manifest and first full certificate, and
re-read every retained artifact's exact bytes. A matching newly supplied proof
cannot excuse a missing or corrupt retained dependency.

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
Open -> Freeze -> Fixed frontiers -> Quorum-retained DrainSet -> Drain
                                                                  |
                                Verified cut + conditional next-set readiness
                                                                  |
                                      Seal -> Transition certificate -> Activate
```

### 1. Freeze and fix authenticated frontiers

Only a committed outgoing-set `Freeze` changes admission. Bind its identity to
the chain/protocol/epoch/domain and ordered block. A proposed next set is
advisory: Freeze does not irrevocably commit membership before readiness.
A proposal or operator request alone cannot freeze a replica. Check next-set
eligibility through the existing bond, key, policy and power rules; bond value
must not become voting power.

HotStuff orders an authorized control decision; it does not make an arbitrary
caller-supplied Freeze candidate warranted. Before voting, each honest replica
must verify the same deterministic epoch-end warrant and the legal eligibility
of the candidate's canonical, advisory next set, including the same set if it
passes the ordinary checks. The handoff-capable signed genesis manifest binds a
positive minimum ordered-block height for Freeze proposals. Validators compare
that committed rule with the proposal's actual height; a local clock, timeout
tick, caller-supplied threshold or HTTP request is never the warrant. They
validate the next-epoch chain/protocol binding, set structure and voting power,
then each member's committed Active bond, registered key and current economics
policy before exposing a proposal or vote. At execution of the committed
ordered block they check the actual height and eligibility again, since the
intervening prefix may have changed them. A healthy ineligible set is a
retained refusal with no closure; a missing or corrupt prerequisite stops
application. See [DR-0155](decisions/0155-epoch-end-freeze-warrant.md).

At each replica, commit the closed-admission marker with processing this
ordered prefix. Stop new prepares, new retention ACKs, direct local/paid
mutations and construction of fresh economic candidates. Publication commits
racing this boundary must assert the admission-marker revision: either their
full artifacts enter the frozen log before their ACK is exposed, or they fail
without exposing a signature.

The Freeze marker is a local CAS precondition for each replica's admission;
it is not a signed business read in the FastVote execution commitment. Thus a
certificate does not by itself attest that admission was open at every later
replica. Fresh publication ACKs assert the marker revision in their atomic
commit, and exact earlier ACK replay does not create a new signature.

Still allow historical reads, exact completed replay, safe shared-engine
progress and catch-up. Ordinary fresh apply stops; certificate-backed missing
applications resume through the selected drain authority, not a blanket
mutation bypass.

Derive a signed frontier from **all full certificates retained locally before
closure**, including records whose availability ACKs were never aggregated or
whose operation was never applied locally. Include the necessary ordered
prefix/proof artifacts. Atomically persist the final descriptor with its
signature before exposing the vote. Enumerate it incrementally while
publication stays closed.

The local frontier identity binds the chain, protocol, outgoing epoch, logical
domain, committed Freeze request and height, entry count, and ordered digest.
The accumulator seeds from that context and folds each retained availability
identity in ascending request-ID order. A replica re-verifies each retained
full certificate, signed intent, ACK and required artifact's actual bytes
before moving a CAS-fenced cursor. Its final descriptor and vote commit in one
row; an exact retry returns those bytes without signing again. The canonical
identity, vote and accumulator frames are `0xD036`-`0xD038/v1` with a distinct
`epoch-frozen-frontier-v1` signing domain. A bounded canonical `0xD039/v1`
page carries an exclusive request-ID cursor, up to 128 ascending availability
identities and an explicit terminal flag. The `0xE107` request and `0xE108`
response envelopes transport an exact epoch/cursor/limit and the final signed
vote plus page; the envelope itself is not authority. A remote verifier starts
from the voted Freeze context, authenticates the registered signer, folds
every consecutive page, and accepts the terminal page only when its count and
digest equal the signed final descriptor. A missing, repeated, reordered,
foreign or prematurely terminal page fails closed. An identity-only page never
proves possession of its full certificate, original intent or artifact bytes;
the verifier must fetch, independently verify and durably retain those before
counting the signer toward DrainSet. A local cursor or signed descriptor alone
is not a closed-range proof to another validator. DrainSet voters must verify
all pages and their completeness independently before counting that signer.
The certified-only `/v1/fastvote/frontier/advance` route performs one
CAS-fenced local step and returns no vote until the final row is committed;
`/v1/fastvote/frontier/page` reads only from that finalized row, re-verifying
each selected retained publication and its exact artifact bytes. The Rust
client checks the returned signature against its locally pinned outgoing set
and configured endpoint identity. A caller must still compare the vote with
the expected committed Freeze, keep it identical across all pages, and
complete the terminal digest check; HTTP success alone never establishes a
complete frontier or durable possession of its artifacts.
The final frontier row contains one validator's own signature and is local
signing state, not transferable authenticated business history. A future cut
may carry the outgoing signer vote as an independently keyed and verified
attestation, but must never copy that local row into another validator's
identically named state key. The advance route is an intentional certified-host
exception to user transaction authentication: it mutates only local cursor
and final rows after the committed Freeze and deterministic local verification.
It must not be exposed as a complete handoff or public signing service.
Publication records, local ACKs and artifact rows are now keyed by chain,
epoch and request ID. A later epoch scans only its own immutable publication
family without deleting older authenticated history or treating an earlier
epoch's proof as a current candidate. This key property alone does not enable
activation. The active-epoch serving contract requires a lagging validator to
finish before activation or use a separately designed, authenticated
historical serving path. The historical path must pin the old committee and
complete proof history independently; an untrusted epoch field cannot select
it.
The active-epoch retained-publication source accepts only a signed-frontier
request ID and the locally pinned current epoch. Its store must carry the
installed logical commitment profile, current outgoing set, complete retained
publication and artifacts, and its own valid ACK. It is a read-only proof
source even when the validator never prepared the operation. The requester
independently verifies the complete bundle against its locally pinned
committee and exact signed-frontier identity. A historical profile, missing
or tombstoned ACK, or server-supplied identity cannot authorize the source.
It does not by itself prove complete frontier pages, DrainSet readiness, or
historical serving after activation.
Before deploying the page route on an untrusted network, bound its per-request
verification work by cumulative artifact bytes or require peer/operator
authentication: a valid request can currently make the server re-verify the
cursor plus up to 128 full publications. Executor concurrency alone does not
bound that repeated CPU and storage-read cost.

An untrusted coordinator proposes at least `q` power of verified frontier
descriptors and all their pages. Select only complete, retrievable frontiers;
unavailable or forged pages cannot count toward that quorum. Construct the
union of full-certificate operation identities and authenticated dependency
closure. Every verifier reconstructs this union, not just its digest/count.
The selected descriptors must carry ascending, unique registered validator
IDs, valid outgoing signatures and one exact locally committed Freeze identity;
duplicate or mixed-Freeze power never counts. Each importer stores a verified
full bundle and its exact artifacts in a separate post-Freeze drain namespace,
with an atomic local possession marker. It does not call availability
retention, create an ACK, or extend its own immutable `publication/` frontier.
The imported proof and artifacts are authenticated cut history; the possession
marker is local progress only. A marker counts toward a selected frontier
only after that signer's consecutive pages reach their authenticated terminal
count and digest. A new source may relay an imported proof only after
independently rechecking its saved bytes. See
[DR-0156](decisions/0156-frozen-frontier-possession.md).

The importer's bounded per-signer progress must authenticate every consecutive
page through the signer's terminal count and digest, then confirm each entry
against a fully re-verified local proof. Only confirmed entries of the
selected weighted quorum are folded into a deterministic union, one bounded
step at a time. The separate proof store is not the union's member list; a
local ready marker is written only after the whole union is reconstructed.
The later DrainSet vote reads that marker under CAS. See
[DR-0157](decisions/0157-frozen-frontier-readiness.md).

Choose exactly one `DrainSet` by a normal outgoing ordered commit. Before
exposing a vote for it, each voting replica must durably retain and verify
**every union member's full certificate, original signed intent and replay
artifacts**, including its dependency closure, in its own store. Reconstruction
means identities plus dependency closure; a descriptor, an earlier holder's
ACK or a transient download is not possession. Commit this local readiness
atomically before vote exposure. Thus the committed obligation is backed by
`q` power of durable artifact retention even for a full certificate that
previously existed on only one withholding/failing replica. With the assumed
eventually responsive quorum, an honest intersection holder can supply it.
The exact ordered-vote/CAS binding and initial roster bound are fixed in
[DR-0159](decisions/0159-ordered-drainset.md).

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
The separate certified drain-application and exact lock-resolution rule is
fixed in [DR-0160](decisions/0160-certified-drain-application.md).

### 3. Preserve shared-engine safety before sealing

Do not reset old high/locked QCs or assume every uncommitted branch is dead.
Process the existing committed prefix and inherited justified proposals using
normal HotStuff ancestry, view and lock rules. Before exposing a new vote,
account for any Freeze committed by processing the proposal's justification;
admission must use the resulting control state, not a stale pre-event snapshot.
After processing committed Freeze, an honest replica emits no fresh vote for
a proposal whose **own payload** carries business. Empty/control proposals
extending a business-bearing inherited justification remain votable and are
how that suffix reaches its closed-epoch refusal. Retained pre-freeze votes/QCs may still be replayed
and inherited justifications processed; this rule does not erase them. No fresh
business QC can form, so honest empty/control views can drain the finite
inherited suffix and reach the business-free seal barrier.

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
original receipt history and complete artifact manifest after drain. Choose a
currently eligible next set, evaluated at the same post-drain frozen state,
through the existing policy, bond, key and power
rules; it may differ from Freeze's advisory proposal. The implementation must
not assume that a dead proposal defines the only next-set choice.

A new host imports using **its own** writer fence into an ineligible namespace.
It independently verifies genesis, full history, artifact closure and this
pre-Seal business cut. Only after durable local verification may it sign
conditional readiness for the exact cut/context/proposed set. Collect a
next-set quorum's readiness **before committing Seal**; otherwise choose a
different legally eligible ready set while the epoch remains frozen. Readiness
binds the pre-Seal cut identity, not a future Seal block digest, and does not
authorize active serving or consensus votes. Conditional readiness is
non-exclusive across cut/set candidates: exact retries return the retained
signature, and a corrected candidate may obtain a new readiness signature.
Only the post-Seal epoch-transition vote has the unique-target constraint.
An incomplete or rejected import can continue from verified content, or its
still-ineligible, unverified staging namespace can be quarantined and another
fresh staging namespace prepared. Do not delete/reset an existing active or
historically verified store, roll back authenticated applications, or copy a
foreign writer token. This is not a legacy migration escape hatch.

`Seal` commits the cut, the exact ready eligible set and verifying readiness
evidence through the same old engine. After that decision its target cannot
change. Loss of that next quorum is a fault-model availability stop, not an
excuse to sign another epoch-transition target.
Voting requires the committed business prefix applied, drain complete, no
unresolved authenticated facts and equality with the locally derived cut.
Signature-subset differences and local database counters are not disagreement
about business state.

The cut commits the **pre-Seal business snapshot** and verified replay prefix,
not a row that contains its own cut digest. Bind genesis/predecessor cut,
outgoing context/set/domain, committed DrainSet, applied business-prefix anchor,
normalized business-state/receipt roots, an explicit authenticated
`execution_generation_floor` derived from verified history, and the artifact
manifest. The current
Seal, its proof, control-phase bookkeeping, its internal command receipts and
the later activation/readiness proofs are companion authority artifacts outside
that snapshot/manifest. Previous epochs' authority history stays bound through
the predecessor anchor. This avoids a self-referential root and distinguishes
business-state equality from changing consensus/control metadata.

A remote readiness signature never substitutes for local cut verification.
Serve/sign as the new active validator only after a durable verified-cut marker,
the same committed Seal and activation. Conditional readiness is not active
validator eligibility.

Cast an epoch-transition vote only for the committed Seal. Persist its exact
signed identity before exposure, retain it on retry, and refuse another target.
Before Seal, proposal changes use ordinary HotStuff views; they cannot wedge
an epoch-wide first-writer-wins transition-vote row. Bind activation to the
outgoing authority, Seal/DrainSet proofs, cut and next set; rederive/verify
locally and install new policies/epoch atomically with fences.
Version the activation-set signed preimage to carry these bindings: this is a
semantic change to the existing `0x6428` frame, not merely a new key constant.
Historical activation preimages retain their own verification rules.

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
authorities, nonce value/precondition and an authenticated **semantic execution
generation**. Define that generation deterministically as one plus the maximum
of the predecessor cut's generation floor and authenticated input/prerequisite
generations, using checked arithmetic. Overflow is a typed refusal before any
reservation/mutation or exposed signature; never saturate or wrap. Genesis supplies the initial floor.
The next cut derives its floor from verified history. This is a causal operand,
not a globally incremented counter or proof of checkpoint publication; separate
owned transactions can share a generation and need no global ordering.

Persist that generation in versioned protocol provenance/authority metadata
and the logical witness. Admission's non-regression checks compare these
authenticated semantic generations, not a backend's creation timestamps. All
replicas derive the same operand from the same logical prerequisites and reuse
the exact certified operand at apply/recovery. It must not be chosen separately
from each host's trusted physical checkpoint counter.

Node-local `StateRevision`, head/nonce revision, writer generation and physical
creation/admission/commit checkpoint counters stay solely in local persistence
and commit-fencing inputs. They do not enter the signed preimage, protocol read
observations or new-profile admission monotonicity. A differently initialized
physical checkpoint source cannot make E alone reject a Write or change its
commitment. **Do not remove semantic read/provenance authority along with local
counters.** Historical v1 witnesses retain their original signed checkpoint
operands and bytes for read-only verification; do not reinterpret those legacy
fields as new semantic generation metadata.

Define explicit runtime-neutral bounded repositories; the current key scanner
does not enumerate the separate SQL receipt, object-head or object-version
tables. The [portable reconstruction storage contract](portable-reconstruction.md)
separates indexed keys, body-free descriptors and bounded payload ranges;
it provides no authenticated cut or cross-page snapshot by itself.
Each collection has canonical keys, exact semantic projections and
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

The existing `fastpath/` namespace is not one homogeneous cache. Only
`prepared/`, `lock/` and `nonce-lock/` are replica-local reservations.
`certificate/`, `commitment-witness/`, `settlement/`, `fee-claim/`, `bond/`,
`bond-transition/`, `evidence-consumed/`, `equivocation/`, `validators/`,
`economics-policy/`, `transition/` and `epoch/` carry authenticated business
or control history. The generic logical-generation provenance does not assign
these separately verified records a second generation. The cut must instead
enumerate, classify, retain and independently replay/verify every required
history family, and derive its generation floor from the verified history. An
unknown family under the reserved prefix is a cut refusal, not an implicit
local-data exclusion.

Likewise, `ordered-economics/header/` is an immutable **request-id binding**,
not a consensus block header. `outcome/` retains business results, while
`candidate/` retains the candidate body; none of these rows alone proves that
the shared engine committed a block. The signed proposal/QC chain for every
committed height must be retained separately as `committed-proof/` history
before the engine prunes its short-lived cache. A cut must verify that history
against the configured outgoing validator set, contiguous genesis ancestry,
the original candidate bytes, request headers, outcomes and receipts, plus a
separately authenticated terminal anchor. `state/` and `applied-height/` are
local engine/progress rows, not substitutes for that proof. The inherited
high/locked suffix also needs a direct certified empty control anchor.
Unknown ordered families fail closed.

Use a closed key/schema classifier: unknown protocol rows cannot be silently
skipped. Local prepare/vote/lock identity, writer/schema tokens, delivery cursors
and import/hash progress are local metadata, not global business facts. Retain
necessary historical proofs separately; normalized roots may ignore equivalent
signature subsets but must not ignore signed execution operands, tombstones,
nonce/claim generations or history that affects future authority.

The initial handoff profile names outbox batches, messages, delivery and
attempt rows as excluded families in each supported schema, including the
legacy `outbox/` state-key prefix. Exclusion is conditional: verify that no
nonempty or pending outbound obligation exists before freezing the cut or
admitting an import; otherwise refuse the handoff. The currently certified,
paid and ordered application paths emit no outbound messages. Never import
replica-local leases or delivery attempts. If a future contract runtime emits
messages, define cross-epoch delivery and prove deterministic reconstruction
before enabling handoff for it; an old-epoch message rejected at new-epoch
ingress must not be silently discarded. Empty-batch representations in SQL
profiles must be normalized explicitly rather than equated by row shape.

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
DrainSet pre-vote bulk retention uses this same bounded chunk/cursor contract.
Key retained progress by verified operation/artifact identity, not by a leader's
proposal, so view changes reuse completed downloads rather than restart them.
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

Post-Freeze signer-page, proof-import, member-confirm and union-advance HTTP
routes are internal validator/operator ingress, not public authorization.
Canonical body limits and the native blocking executor bound one invocation's
bytes and concurrency, but do not authenticate a caller or stop repeated
expensive proof verification. A deployment reachable from an untrusted network
must add authenticated peer/operator ingress and per-peer work/rate budgets
before exposing these routes. A certified-only router excludes direct legacy
mutations; it is not itself a peer-authentication mechanism.

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
inherited high/locked business branches; a sole full-certificate holder failing
after DrainSet commit; fragmented certificate-proof subsets that must share
one availability identity; a dead advisory next set replaced before Seal;
conditional readiness corrected without resetting an active store;
empty/control votes extending a business-bearing inherited justification;
different physical revisions and checkpoint sources with
identical logical state; all cut/page/history negatives; real stale writers;
process restart at every boundary; exact successful/trapped/completed replay;
early/still-member withdrawal refusal and retired-signer rejection.

The whole core/HTTP/SDK/CLI/multi-validator feature, full repository gate and
independent exact-head review are one delivery. Independent operational control,
release security audits and live startup are separate from namespace-only E2E.
No public deployment, real custody, HA/load/provider certification or production
readiness is implied.
