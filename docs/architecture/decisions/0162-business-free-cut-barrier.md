# DR-0162: business-free cut barrier before portable enumeration

Date: 2026-09-30

## Status

Accepted implementation direction. Implementation and test status remain in
[`TODO.md`](../../../TODO.md). This decision refines the pre-Seal barrier in
[complete epoch handoff](../epoch-handoff.md); it does not claim a portable
cut, conditional readiness, Seal, activation or an operational epoch change.

## Problem

Committed Freeze closes fresh admission but does not make the state immutable.
The inherited justified HotStuff suffix can still commit a business candidate
after Freeze. Its required closed-epoch refusal writes an original receipt,
retained outcome and applied-prefix marker even though it moves no economic
value. A committed DrainSet and a local drain-completion marker do not prove
that suffix has ended. Re-reading only those immutable marker revisions around
a paginated state scan cannot detect an intervening receipt or outcome write.

## Decision

1. Before exposing a vote for a proposal whose own payload carries business,
   account for a Freeze that its justification would newly commit. Persist the
   authenticated observation of that Freeze without exposing a business vote.
   After an accepted committed `DrainSet`, close fresh votes and proposals for
   **all** candidate kinds, including control, as specified in
   [DR-0163](0163-committed-drain-set-closes-candidate-voting.md). Its
   same-event preview likewise abstains when a justification newly commits
   `DrainSet`. Empty consensus progress remains votable.
   Before barrier installation, declared signerless recovery still accepts
   historical proposal bytes and processes inherited justifications through
   ordinary HotStuff rules. After installation, a newly arriving candidate
   body stops locally; the network-level exhaustion proof remains separate.
2. A local business-free predicate requires the applied committed prefix to
   equal the committed height, verifies local DrainSet completion, and walks
   the complete authenticated high-QC and locked-QC ancestor suffixes above
   that prefix. Every referenced candidate must have present, canonical,
   digest-matching bytes. No candidate, including `Freeze` or `DrainSet`, may
   remain above the applied prefix: control commits also write receipts and
   outcomes. Missing ancestry, candidate content or a walk bound is a
   stop, never an inferred empty suffix. Fold every relevant row revision into
   the same CAS read set used to install the barrier.
3. Install one immutable replica-local barrier row only after those checks.
   Its canonical local marker uses type `0x6463/v1` and stores the exact chain,
   epoch and completed drain-union identity. It is classified local progress,
   not a transferable history claim.
   From then on, fresh ordered candidate placement (including header and
   candidate history), a newly committed ordered candidate block, fresh
   post-Freeze drain-publication/artifact retention, and a fresh certified
   drain application must assert the row's virgin absence in their
   own atomic commit. A concurrent barrier installation makes the writer lose
   by CAS. A present or tombstoned barrier makes the writer stop before any
   new header, publication, receipt, outcome, nonce or object mutation. Exact
   already-committed drain replay remains receipt-first and writes nothing;
   exact retained publication replay may only rebuild replica-local progress.
   A newly committing ordered re-placement of an already-completed candidate
   can still stop at this fence: ordered completion replay is not an exception
   to a new committed block after the cut. An unchanged certificate event
   with no newly committed candidate remains a no-op.
   Empty consensus progress remains possible. A future `Seal` needs a narrow
   reviewed exception to fresh candidate placement, not an exception for
   already-inherited control candidates. Ordinary fast-path writes are
   independently closed by the committed Freeze fence. Direct evidence
   submission must also fence the current serving epoch while Freeze is
   active; exact retained evidence replay remains legal. Evidence about an
   old offense may still be newly submitted after activation, so the future
   historical cut cannot naively rescan all evidence keys by offense epoch.
   The installer is an internal local step at present. Any future exposed
   request surface must require operator authority: installing this marker
   permanently stops fresh candidate progress on that replica until a
   separately verified Seal/activation path exists. In particular, a local
   barrier before the DR-0163 network-wide candidate-vote closure can strand
   one replica while an honest quorum commits another control candidate; the
   barrier row alone is not an activation-safe protocol decision.

The barrier is **local cut-stability evidence**, not portable authority and
not an alternative to an authenticated history replay on a joining validator.
The portable cut must independently verify receipts, candidate/QC history,
certificates and artifacts, normalize replica-local representation, and use a
bounded manifest. It cannot import another replica's barrier marker.

The barrier also is not a leader-supplied Boolean. If a previously unknown
authenticated business branch somehow appears after installation, stop rather
than silently creating a late refusal under an already-derived cut. The
business-free high/locked suffix and no-new-business-vote rule are local
checks, not proof that every earlier certified branch is globally known.
How an unseen pre-Freeze branch is exhausted before Seal remains a separate
network-level proof obligation; the writer fence only prevents local silent
mutation if one arrives. Seal and its own control
receipt, if any, require an explicit, separately reviewed exception to the
post-barrier ordered economic-block fence so the pre-Seal business snapshot
does not include a self-referential Seal result.

## Verification and limitations

Use a genuine four-validator Freeze chain with one replica missing the QC
that commits Freeze; its next business-bearing proposal must cause the
justification to commit Freeze but produce no vote. Verify that an inherited
business suffix prevents barrier installation until its authenticated
no-effect refusal is durably applied, and that a healthy candidate-free suffix
allows installation only after real drain completion. Race the barrier commit
against both ordered refusal and drain application and assert one side loses
without partial receipt/object/nonce changes. After installation, empty
progress and exact replay remain legal; new business writes do not.

This work does not provide a cross-page database snapshot by itself. Before
portable enumeration relies on the barrier, every other cut-classified writer
and the outbox obligation guard must be audited and fenced, and source and
importer verification must remain distinct. The evidence-recording epoch and
its authenticated ordering relative to the cut also remain to be specified.
