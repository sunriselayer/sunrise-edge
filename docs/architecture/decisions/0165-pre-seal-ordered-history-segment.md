# DR-0165: certified empty terminal witness before the portable cut

Date: 2026-09-30

## Status

Accepted direction for the next Delivery 3 implementation slice. The
implementation status and remaining acceptance gates belong in
[`TODO.md`](../../../TODO.md). This segment is not a portable business-state
cut, a Seal decision, a readiness signature or activation authority.

## Context

DR-0164 retains a signed three-chain proof for each committed height and
permits bounded independent verification from genesis. It deliberately does
not authenticate a replica's claimed terminal height. The local business-free
barrier proves a receipt-backed DrainSet and candidate-free high/locked suffix
at its own installation, but its marker is neither signed nor transferable.
The existing key scanner supplies bounded pages, not a cross-page snapshot.

## Decision

1. Derive a candidate-free terminal witness from an already committed block
   strictly after the committed DrainSet height. Re-verify that block's
   archived three-chain proof against the pinned outgoing validator set and
   require the committed proposal and its direct child and grandchild to be
   candidate-free. Do not invent a new finality signature or accept a local
   committed-height counter as the proof.
2. A local derivation must re-verify the serving epoch, receipt-backed drain
   completion, exact retained business-free barrier, fully applied committed
   prefix and high/locked suffix. Fold every observed row revision, including
   the terminal proof, into a caller-owned CAS read set. A read-only result
   cannot on its own authorize a cut; a later signing/commit operation must
   atomically assert those reads.
3. A future importer must independently verify the contiguous committed
   history from genesis to the exact derived terminal digest and close each
   candidate-bearing height against its original candidate, request binding,
   outcome and receipt. A barrier marker or source-local progress row has no
   remote authority. Missing, tombstoned, noncanonical, foreign, divergent or
   skipped material is a refusal.
4. Keep the ordered-history segment distinct from the complete portable cut.
   Business-state and artifact collection completeness, a normalized root,
   authenticated cross-page continuation, conditional next-set readiness,
   Seal and activation remain separate acceptance gates. No imported segment
   may become servable merely because its terminal witness verifies.

## Consequences

The witness can reuse the existing canonical signed proposal and quorum
certificate bytes, so this decision allocates no new frame ID. Honest
replicas may retain different valid vote subsets for the same committed
proposal; compare the verified terminal height and digest, not proof bytes.
The witness may be chosen at different empty heights before Seal. Only a
later ordered Seal decision can fix one exact cut and next set. Large legal
histories must be verified in bounded pages without treating an intermediate
cursor as an externally signed terminal claim.
