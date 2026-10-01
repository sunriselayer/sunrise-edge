# DR-0169: Authenticated ordered-history archive and export

Date: 2026-10-01

Status: Accepted implementation boundary. Work and validation status belong
only in [`TODO.md`](../../../TODO.md).

## Context

[DR-0154](0154-complete-epoch-handoff.md) requires a joining validator to
derive the business cut from authenticated history, not trust a SQL snapshot,
a supplied transaction list or a quorum of current database values.
[DR-0168](0168-quorum-retained-drainset-and-member-drain.md) completes the
quorum-retained frontier union and explicit certified-member application, but
does not provide that reconstruction.

The shared engine currently reports committed block identities and subsequently
prunes live proposals/certificates. It retains ordered candidates, outcomes and
original receipts, but not a self-contained commit proof for every height.
Consequently a fresh verifier cannot establish the full committed prefix after
pruning. The next functional capability must close this gap before state
import, rather than disguise transport-digest equality as cut verification.

## Decision

### Capture before pruning; commit atomically

Emit a self-contained three-chain proof for every newly committed height,
including empty blocks, controls, ordinary economics and recommitted completed
candidates. Capture each height's actual committed proposal, direct child,
direct grandchild and grandchild certificate before pruning. The newest QC
which triggered a multi-height commit is not automatically each ancestor's
own three-chain witness.

Archive each exact proof under chain, epoch and height in the same bounded CAS
as consensus/applied progress, the original ordered outcome/receipt and any
application effects. A failed or ambiguous application cannot leave an advanced
prefix without its archive. Tombstones, conflicting archives and unavailable
required witnesses fail closed. Exact replay preserves existing bytes and
revisions. Do not manufacture missing older proofs from progress counters or
silently backfill an already-pruned legacy store.

For a legal delayed observer event which commits one economic candidate and
later empty heights together, apply that candidate once and mark the entire
verified empty-followed prefix applied in the same commit. The prior
finalizer advanced only to the candidate's height, leaving a processed empty
suffix falsely unapplied and blocking following readiness. Exact retained
candidate replay follows the same progress rule without changing its original
outcome height, receipt or effects. Multiple economic operations, an already
unapplied prefix, handler stop or persistence failure are not permission to
advance this marker. This corrects local applied progress, not consensus order,
scheduling, signed bytes or execution outcomes.

### Authenticate order; distinguish completion companions

A verifier starts from the locally trusted signed-v3 genesis, its outgoing
committee, protocol context, consensus anchor and LogicalGenerationV2 profile.
It verifies every proposal signature and QC, the exact three-chain, the closed
ordered scheduling shape, every contiguous height and direct parent linkage.
Candidate-bearing blocks must carry the exact authenticated candidate bytes
whose digest the block names. A recommitted candidate binds to its original
committed-height proof rather than pretending to have executed again.
Track compact first-seen request/candidate, origin and canonical companion
fingerprints across the verified stream. A source cannot rewrite a later
recommit's first height or replace both matching companions. This index grows
with distinct original ordered requests, but does not retain full historical
components or impose a whole-history byte ceiling.

Export the complete retained `OrderedOutcome` and original receipt as source
completion companions. Check canonical encoding, request/event identities,
candidate kind/context, exact response bytes and original-height linkage.
Keep deterministic refusal companions as well as accepted ones. **Consensus
votes certify ordered candidate identity, not the companion's result bytes.**
Matching an outcome to a receipt is consistency evidence, not independent
re-execution of economic effects. Two mutually consistent forged companions
are not an authenticated business result. This capability must not expose a
verified-execution, verified-cut or import-eligibility marker.

### Fixed target and bounded transfer

Pin one target height/digest and walk from genesis to that exact target. A
source's advertised tip is untrusted until its proof and the contiguous prefix
verify. An old valid target is not proof of the latest network state. An empty
terminal three-chain alone does not prove complete drain, absence of later
history, Seal or readiness. No new signing or local irreversible barrier is
introduced to export history.

Use closed typed component descriptors and bounded chunks rather than one
frame containing all proof/candidate/outcome/receipt components. Respect the
existing legal per-component canonical bounds, descriptor bounds and at most
1 MiB per chunk. Descriptor digest/length checks prevent stitching changed
components; signature and linkage verification remain mandatory after complete
assembly. Bound work per invocation, not total history size. Unknown component
kinds, foreign context, gaps, duplicates, reordering, missing/tombstoned rows,
changed chunks and contradictory original-height links refuse.

### Connected product surface

Provide read-only core source APIs, opt-in authenticated native HTTP routes,
locally pinned Rust SDK verification and a separately compiled CLI export
command. The CLI synchronizes immutable saved files, re-verifies them on
restart, refuses replacement of changed bytes and writes completion only after
the full genesis-to-target stream verifies. An interrupted export may resume
without a new signature or business mutation. Transport locators and TLS
validation remain separate from locally configured protocol/genesis trust.

## Acceptance and remaining authority

Use actual PostgreSQL validator processes and the compiled CLI over real
ordered economics, Freeze/DrainSet and empty progress. Exercise pruning,
multi-height/fork progress, recommitted outcomes, bounded/chunked export,
process restart, immutable saved-file resume and same-replica full-row/revision
comparison for read-only assertions. Add independent stable vectors and
adversarial signature/quorum/ancestry/context/component/companion tests.
The complete repository gate, fresh explicit exact-head independent review
and required CI remain merge gates.

This is an authenticated **ordering-history** capability, not authenticated
business-state export/import. The next cut implementation still needs the
closed semantic projection registry, actual causal interleaving of owned and
ordered applications from verified genesis, full result/effects comparison,
authenticated artifact closure and generation floor, and a core/store inactive
guard for a genuinely new incoming validator. Retain the initial EmptyOnlyV1
outbox exclusion rather than deleting delivery history to force a pass.
Conditional readiness, Seal, activation, predecessor-epoch reconstruction and
complete Delivery 3 remain separate required work. No public deployment, real
custody, production or independent-operational-control claim is implied.
