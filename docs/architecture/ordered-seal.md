# First-epoch ordered Seal

This is the accepted closed design contract of
[DR-0187](decisions/0187-first-epoch-ordered-seal.md).
It replaces only the Seal alternatives of
[functional handoff closure](functional-handoff-closure.md); post-Seal
transition, successor serving and recurring epochs remain separate contracts.
Its hard-stop also rules out the older proposal's post-Seal outgoing
transition-vote sketches. Separate successor design must not assume an
exception permitting a new outgoing live signature.
Current status belongs only in [TODO.md](../../TODO.md).

## Authority and finite composition

Seal is a new unsigned `OrderedOperationKind::Seal`, tag 8, admitted only in
the signed-genesis causal Logical profile with a warranted Freeze schedule,
the original outgoing epoch, committed DrainSet and independently complete
post-drain cut. Its authorization is ordinary outgoing ordered consensus over
verified material, not a direct operator mutation. Existing ordinary HTTP
proposal/vote/certificate/observer routes carry the same candidate. SDK reuses
the owning core codecs; the CLI stages the certificate and constructs the
candidate under explicit local pins.

The callable native path supplies the real reconstruction port and the same
owning SQLite store's Seal capability. The operator's `sqlite_source_host`
composes those existing dispatchers over independently pinned original trust
and existing Ordinary, Unsealed files. It claims one writer generation with
explicit offline coordination, checks the committed marker, fee policy,
committee and local key under that generation, and refuses non-loopback
listeners. It never installs, resets, imports or activates a namespace.
The [composition contract](decisions/0192-verified-sqlite-source-host.md) keeps
query projection separate from signing authority and transport lifetime
separate from protocol correctness. `ordered_seal` remains unsigned preparation.
The PostgreSQL host supplies `seal: None`; receiving a candidate does not enable
it. Exact process/test and release evidence remain only in TODO.

The exact `ReadinessSubject` names the separate complete local hash-suite
schedule, adjacent successor set and semantic cut. Verify all successor keys,
weights, registered eligibility and weighted quorum with the existing owners.
Readiness is not serving permission. Genesis does not authenticate future
schedule extensions. Derive eligibility from the same independently reconstructed
post-drain state, not the certificate's supplied set alone.

The candidate contains bounded references, not a saved-cut superframe. Actual
local reconstruction uses immutable original trust, the complete authenticated
ordered history, actual code/body carriers and the same reconstruction engine
and semantic projection as ordinary cut derivation. No caller-supplied equality
report or decoded row constructs the private verifier result.

## Closed public frames and identities

A workspace sweep on the design base found no allocation of 0xD050..0xD053,
0x64D3..0x64D4 or `durable_outgoing_barrier`. DR-0187 accepts these allocations;
existing canonical namespaces/vectors
are untouched. All frames below use encoding version 1, closed fields, exact
decode/re-encode and checked lengths before copies.

| Frame | Fields in canonical order |
| --- | --- |
| 0xD050 SealIntent | 1 readiness subject frame, 2 exact BusinessCutIdentity frame, 3 predecessor tag u16, 4 predecessor Digest32, 5 exact certificate Digest32, 6 certificate length u32 |
| 0xD051 target preimage | 1 subject identity Digest32, 2 predecessor tag u16, 3 predecessor Digest32 |
| 0xD052 request preimage | 1 target Digest32, 2 exact certificate Digest32 |
| 0xD053 accepted SealOutcome | 1 target Digest32, 2 original request bytes, 3 Seal block height u64, 4 exact Seal block Digest32 |

Only predecessor tag 1, original genesis, is supported. Its digest equals the
subject and locally pinned original genesis. Unknown tags stop; no legacy
transition certificate is a fallback. Target and request preimages use NodeEvent
at outgoing epoch: take the resulting 32 request bytes, then set exactly
`request_id[0] |= 0x80`. Pure authentication recomputes that derivation.
`created_checkpoint` is exactly field 2's
`BusinessCutIdentity.ordered_history.through_height`; pure authentication
rejects every other value. Changing the verifying certificate variant yields a
different request/candidate, not a conflicting overwrite of one header.

Limits: chain 128 bytes; each subject and cut identity 16 KiB; SealIntent 40 KiB;
certificate 1 MiB and at most 256 successor votes; accepted outcome 1 KiB.
The actual certificate reference uses Certificate at outgoing epoch. Verify
its exact length, digest, canonical frame, subject and every signature/quorum
against local configuration. The 512 KiB ordinary candidate bound is unchanged.
Equivalent genuine certificate variants share target identity but not exact
candidate bytes. No package digest, local token/fence or high/locked observation
is a semantic target field.

Stage the immutable certificate through its existing blob owner before vote
retention. The candidate record retained in the same real signing CAS is its
exact reference. Every new signature re-reads and verifies the bounded immutable
certificate; a hash without material is not availability or authority.
Unreachable immutable content after a failed CAS is not authority.

## Selected-branch verification and justified progress

Authenticate and link the candidate/proposal before any prefix mutation. Apply
the supplied justified certificate with the existing signerless engine and
actually complete any resulting prefix. Reload state before evaluating new or
retained live signatures. A leader similarly processes its current high QC
before proposing. A dropped capacity probe is neither commit nor permission.
An indeterminate prefix write exposes no messages.

The proposal's selected justification path must be complete through the exact
locally committed boundary. At the boundary, compare the proposal digest with
the independently verified per-height committed proof, not height alone.
Every post-anchor committed height is empty. Before fresh Seal signing the
unmodified source-cut producer has an empty terminal three-chain. Compare its
entire BusinessCutIdentity to the intent after replacing only ordered_history;
all business/artifact roots, floor and exact Freeze/Drain identities must match.
Require its current token during actual signing retention.

Normal proposal context, membership, leadership, view, lock and 64-step
vote-readiness rules remain in force. Missing ancestors/candidates or a bound
exhaustion require signerless catch-up. Do not reset locks or require an unrelated
legally superseded branch to be business-free. The consensus cache retains
uncommitted heights; the already existing immutable per-height archive verifies
the committed boundary. This feature creates no second consensus archive.

Competing proposals are nonexclusive until committed acceptance. No protected
target slot is set by admission. Once one Seal is accepted, every outgoing live
signature is forbidden, including empty proposals, cached leader/vote replay,
FastVote prepare and cached ACK. This includes actual frozen-frontier signing
and retained cursor/final replay, and legacy `propose_and_vote` and `activate`:
all use the fresh live-ordinary guard before signature exposure or activation.
The ordered leader's exact retained-return path is guarded too. Relaying an
already formed QC, including the QC committing Seal, is not creation of this
validator's own signature and remains legal. Under existing consensus safety assumptions
and real justify-first completion, no later competing Seal can commit. A claimed
post-Seal new commit stops; it never fabricates a refusal or original receipt.

## Private acceptance-only business closure

At acceptance the source's prior applied/committed tip must be exactly h-1.
If it lags, apply the authenticated h+1 certificate first through existing
declared recovery. The output being accepted provides the exact authenticated
Seal block h and its normal commit proof. Earlier post-anchor heights contain
no candidate. The private acceptance terminal verifies the prior tip's exact
proof: committed h-1 empty, child h is exactly that Seal digest/single candidate,
grandchild h+1 empty. Verify signatures, QCs, direct links and profile shape with
the existing consensus verifier, not a structural header comparison alone.

`verify_live_seal_closure` is private read-only preparation, not a new public
cut/import producer. It reuses one token-covered source capture, independent
original execution, complete source comparison, selected drain/body closure,
generation floor and all four business/artifact root derivations. It substitutes
only the exact terminal rule above. Compare every identity field except the
already independently verified empty-prefix history extension. Return the
capture's unchanged token, not a newer replacement observation.

Ordinary source export, saved cut, import and readiness keep their original
empty-three-chain check. A future authenticated predecessor needs another
reviewed producer; this first-epoch verifier cannot repin to a peer's epoch.
Seal's own proof, result and receipt are added only after verification, outside
its pre-Seal cut, avoiding a circular commitment.

## Mandatory barrier, independent of permanent origin

Initialize a protected outgoing barrier in every fresh namespace transaction,
including ordinary creation and inactive import. Origin remains Ordinary or
permanent import with its exact binding/progress. Missing or corrupt mandatory
barrier metadata fails closed. Unsealed means only no committed outgoing Seal,
never current membership or serving permission. Sealed never becomes Unsealed.

| Protected frame | Fields in canonical order |
| --- | --- |
| 0x64D3 barrier | 1 phase u16, 2 bounded exact sealed record or empty bytes |
| 0x64D4 sealed record | 1 outgoing epoch u64, 2 original Seal request bytes, 3 height u64, 4 block Digest32, 5 target Digest32, 6 transition-history state u16 |

Phase 1 = Unsealed requires empty field 2. Phase 2 = Sealed requires one exact
0x64D4 record. The sealed record is at most 1 KiB; phase/history tags are closed.
Acceptance initializes transition-history state 1 = Virgin in the same
transaction. This is positive history bound to committed Seal, not inference
from an absent cache. No signing/activation/reset/delete API is introduced.
The protected barrier/table is outside business inventory through its exact
schema owner. Memory initializes it explicitly; Seal requires one explicitly
bound domain. SQL requires exactly one `durable_outgoing_barrier` row with
`id = 1` and bounded exact bytes. Namespace verification requires that row.

Bump shared SQL identity v4 to v5 and native SQLite file version 3 to 4; align
ordinary PostgreSQL identity v5 to v6 and its schema generation. Unsupported
older initialized files fail; no automatic migration, reset or repair.
Ordinary namespace bootstrap and live host startup report Sealed and refuse
serving. `install_ordered_genesis`'s existing-state early return is not a serving
signal and cannot reopen a barrier. Provide a separately named read-only
historical open for cut/query/export. It grants no live composition or write
exemption; existing handles still face the same atomic backstops.

Add required barrier observation to the base durable and structured read-only
ports, with no ordinary/unsealed default. A fresh core live-ordinary guard checks
both original origin and this barrier before exposure. Both actual ordinary
commit ports independently reject Sealed under the same lock/transaction,
including previously opened handles. Original receipt reconciliation and
historical queries remain before or separate from that live guard.

## Narrow consumed completion, not a universal transaction framework

The optional `OutgoingSealRepository` has required methods for token-checked
signing retention and original Seal completion. Native SQLite and explicitly
bound memory expose it through their actual owning store; PG/DO/other facades
have no default Seal capability. An optional getter defaults to unsupported,
never success; it refers to the same store, not a caller-supplied foreign writer.
Generic ordered routes reject a Seal without this capability before signing.
If any certificate, vote aggregation, observed proposal or proposal-prefix
output would commit Seal on a store lacking it, Stop without advancing the
applied prefix. Never skip it, invent a refusal or fall back to ordinary commit.

Signing retention takes one AtomicStateTransaction and the freshly verified
token. Completion takes one structured original invocation, that token and the
exact sealed record. Under one lock/transaction, check namespace/domain,
fence/deadline, permanent Ordinary origin, barrier Unsealed, exact token sequence,
empty-only outbox, all state observations and receipt uniqueness. Completion
permits no object changes or nonempty outbox and requires receipt identity equal
to the record. Commit assembled consensus/proof/applied-prefix/outcome state,
original receipt, barrier and checked sequence advance together. A retention
never sets the barrier. No key-prefix or maintenance exemption exists.

Storage validates local continuity and closed sections, not protocol authority;
private core preparation owns full proofs and deciding observations. A token
check outside completion or exact-key CAS alone cannot exclude phantom inventory.
An indeterminate completion exposes nothing. Fresh fenced reconciliation must
observe the exact original outcome/barrier/receipt before returning it; retained
exact original replay writes nothing and does not reapply fees or change a fence.

## Delivery, errors and acceptance

The existing EmptyOnlyV1 cut excludes every nonempty outbox batch, even if
fully acknowledged. Recheck this predicate inside acceptance. After Seal,
ordinary writers cannot enqueue; existing zero-message completed rows stay
historical. Indexed claim/ACK remains a separate bounded transport-only owner,
not a business permission. A supposedly claimable nonempty row in Sealed state
is invalid persisted state, not permission to dispatch it. No fresh signed work
or business effect is created by delivery. Lease/ACK writes before Seal advance
the covered sequence and invalidate a stale verification token.

Preserve the existing pure-authentication/refusal distinction. Missing mandatory
material, invalid carriers, incomplete drain, mismatched roots/configuration,
nonempty suffix and changed token are Stops, not new healthy-state refusal tags.
Existing malformed candidate authentication retains its established handling.
Never advance the applied prefix on a local prerequisite failure.

Tests must exercise real multi-validator quorum and independent cut/readiness,
all exact fields/vectors, certificate variants, inherited competing proposals,
legal superseded locks and committed-boundary forks, offline catch-up, SQLite
close/reopen/refencing, landed/unlanded reply loss, inventory/token/fence races,
both ordinary ports and cached signature guards, protected metadata corruption,
original receipts/queries and unchanged older vectors. Include one guard test
per actual signing site above and a request vector whose first digest byte
already has the high bit set. The callable command
stages bounded companions and uses ordinary ordered transport; it cannot call
the raw storage seam to force selection. Required DB-free validation and the
complete selected PG suite for the actual schema change remain mandatory.

This contract grants no target serving, post-Seal transition signature,
recurring epoch, DO/PG Seal production, independent audit or startup approval.
Ordinary CAS is not consistent whole-database rollback protection.

The proposed [recurring successor serving](recurring-successor-serving.md)
contract ([DR-0191](decisions/0191-recurring-successor-serving.md)) extends
this hard-stop to every successor namespace. It adds SealIntent predecessor
tag 2 with new vectors, keeping tag-1 bytes unchanged. It also adds
successor-scoped Seal retirement ports that recheck the same token, outbox,
receipt and barrier rules. `OutgoingSealRepository` stays Ordinary-only.
