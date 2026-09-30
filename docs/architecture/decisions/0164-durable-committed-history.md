# DR-0164: durable signed committed history before epoch cut

Date: 2026-09-30

## Status

Accepted design direction for the committed-consensus-history slice of Delivery 3.
Implementation evidence and remaining work belong in [`TODO.md`](../../../TODO.md).
This decision does not authorize a portable cut, Seal, readiness or activation.

## Problem

The shared consensus engine prunes old proposals and quorum certificates after
each transition. The durable ordered outcome identifies a committing block but
is not its independently verifiable commit proof. A new validator cannot treat
the exporting replica's current committed height, applied-height marker or
local business-free barrier as proof of a complete signed prefix.

## Decision

1. For every newly committed height, including empty windows, retain a
   canonical proof containing the committed proposal, its direct child and
   grandchild proposals, and a quorum certificate for the grandchild. Capture
   it from the authenticated engine state **before pruning**. The original
   signed proposal and vote bytes remain intact; do not synthesize a new
   finality signature over a derived header.
2. Write the immutable proof row in the same fenced, atomic transaction as
   the new consensus state, applied-height marker, candidate outcome and
   original business receipt when present. An encoding failure, missing
   ancestry, pre-existing height, tombstone or CAS race stops the entire
   transition. Exact replay creates no second proof or revision change.
3. An independent importer starts from the configured genesis authority and
   verifies that epoch's validator set, proposer signatures, QC vote signatures and
   quorum, every digest and direct parent link, three consecutive heights
   with increasing (not necessarily consecutive) views, and each committed
   height's link to the preceding verified
   height. A declared tip must be externally authenticated by the later cut
   protocol. A gap, duplicate, branch divergent from the already verified
   prefix, forged proof or wrong declared tip is a refusal, not a request to
   trust the source's local state. A fully alternative signed three-chain
   cannot be disproved from one branch's bytes alone; uniqueness still rests
   on the consensus fault and locking assumptions.
4. Proof-history verification is necessary but insufficient. The portable
   cut must separately enumerate and authenticate candidate bytes, original
   outcomes and receipts, business state, full-certificate artifacts and the
   post-DrainSet empty control anchor. The normalized cut excludes physical
   revision/writer counters but cannot omit causal history. No current local
   marker gains remote authority from this proof archive alone.

## Safety and operational notes

The proof key includes chain, epoch and committed height. Height continuity
is checked against the preceding verified digest, not merely a claimed height
counter. The proof's proposal and vote signatures themselves also bind chain,
protocol version and epoch; the key is not the sole replay boundary. A
per-height proof may duplicate a short signed suffix; this bounded
redundancy is preferable to importing a mutable, prunable cache or requiring
the next host to infer an absent certificate. Export and verification are
bounded and resumable by height; the later cut binds their final tip and
manifest. Equivalent quorum certificates can contain different valid vote
subsets, so byte equality of proof rows across honest replicas is not a cut
equality rule; each proof must verify and normalized history must identify
the same committed proposal/height chain. Fresh-genesis enforcement is
required for stores that predate this archive, since reconstructing a pruned
signed history from an outcome row is not possible.
