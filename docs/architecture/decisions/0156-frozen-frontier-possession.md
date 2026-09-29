# DR-0156: Keep post-Freeze drain possession separate from availability retention

## Status

Accepted design direction, 2026-09-29. This refines the frontier and DrainSet
obligations in [DR-0154](0154-complete-epoch-handoff.md). Implementation and
validation progress belongs in [`TODO.md`](../../../TODO.md), not in this ADR.

## Context

A signed frozen frontier is a closed record of the full publications a
validator retained before committed Freeze. Other validators must obtain the
complete certificate, original signed intent and replay artifacts for every
operation in a selected frontier union before voting for DrainSet. Reusing
ordinary availability retention for this transfer would be wrong: that path
creates a fresh ACK and inserts a `publication/` row after closure. It would
either violate Freeze or make the importing validator's already signed local
frontier incomplete.

An identity-only page or a marker saying that a download finished is also
insufficient. The local store must contain independently verified exact bytes
under the current outgoing epoch's writer and validator-set fences. A
previous holder's ACK never becomes the importing validator's ACK.

## Decision

The locally committed Freeze, logical commitment profile, active outgoing
epoch and installed validator set are prerequisites for every post-Freeze
import. The importer independently verifies the canonical full bundle, quorum
FastCertificate, authenticated signed-intent/request binding, logical witness,
exact required artifact manifest and each artifact's content bytes. It
compares the resulting availability identity with the identity obtained from
a selected signed frontier page. An untrusted request cannot select another
epoch, domain, hash history or validator set.

One bounded atomic CAS commit places the first accepted proof in separate
`fastpath/drain-publication/` and `fastpath/drain-publication-artifact/` families
and its identity in a local `ordered-economics/drain-possession/` marker. The
two proof families are authenticated history for the later cut. The marker is
local progress and is never imported as business history. The original
`fastpath/publication/` and `fastpath/availability-ack/` families remain
unchanged. No signature, ACK, application effect, fee, nonce or receipt is
created. Exact retries reverify the saved proof and all artifacts; an
indeterminate commit returns ambiguity rather than claiming possession.

Selected frontier votes must bind the same locally committed Freeze and form
a weighted outgoing quorum with ascending unique validator IDs. This vote
check is only the start of selection. Each selected signer's pages must be
consecutive and terminal-verified, and each listed identity must have a
verified local possession marker and proof, before that signer is complete.
Only after the selected quorum is complete and the deterministic union is
reconstructed may a local DrainSet-ready marker be committed. A DrainSet vote
must read that marker under CAS; no caller-provided Boolean is authority.

## Consequences

The separated namespace preserves every validator's immutable pre-Freeze
frontier while allowing repair of missing full proofs after Freeze. It costs
additional durable bytes, including duplicates of proofs a validator already
holds; deduplicating those later must preserve independent full-byte
verification and the original frontier's identity. Serving imported proofs
to further peers requires an independently verified read path. Until that
relay path, terminal page completion, union reconstruction and ordered
DrainSet vote fence exist, this decision does not establish a usable handoff
or permit network activation.
