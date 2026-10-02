# DR-0184: One FastVote committee record validator

Date: 2026-10-02 (Asia/Singapore)

Status: Accepted bounded design under DR-0180. Fresh independent implementation
review and actual acceptance remain required; no new serving authority.

## Context

Core already centralizes live and historical byte-row conversion in
`fast_path::decode_validator_set_row`. There is no justification for another
live resolver framework inside core. Across the crate boundary, operator
startup and CLI duplicate conversion because that defining helper is private.
Startup omits the Ed25519-only rule which core admission and the CLI enforce.
Original genesis conversion shares these structural rules but has a distinct
local authority and capacity/error-order contract.
Its installed transition-chain verifier separately repeats member conversion
for the historical outgoing rows and the final live row. Those consumers keep
their digest-chain, certificate, activation and singleton authority checks;
sharing structure must not replace any of that evidence.

## Decision

Adopt [committee record validation](../committee-record-validation.md). Expose
one pure typed record-to-committee validator; keep bounded byte decoding and
actual live/historical authority with their existing owners. Delete duplicate
operator conversion, and reuse structural validation from genesis without
moving its capacity checks or broadening historical limits. Map typed failures
to owning diagnostics rather than inspect error strings.
Migrate both installed-chain conversions too, preserving their existing exact
tampered-record labels and bounded decode/error order. If a row reaches this
conversion, non-Ed25519 members stop at the shared supported-structure boundary.
An earlier signed activation/digest check may already reject a tampered row;
tests must preserve that genuine first failure, not fabricate a certificate or
reader race to reach a later branch. No new signature implementation is added.
Freeze's advisory record and activation's canonically ordered next record use
the same conversion after their owning capacity/context/order guards, retaining
their exact diagnostics and commitments. Raw conditional-readiness successor
validation remains with its different consensus/key-bound/error-order owner;
this is not a universal committee authority abstraction.

Do not equate record structure, a locally authenticated original genesis or
current serving authority. No universal authority context, runtime trait,
wire tag, signature scheme implementation or successor producer is added.

## Consequences and acceptance

The same structural invariant applies at each actual consumer; a future change
cannot leave startup silently enforcing a different member policy. The earlier
startup refusal is intentional fail-fast configuration behavior, not a claim
that core signature verification was bypassed.

Preserve canonical committee/record digests, genesis v1-v4 baselines, core
error-order and original receipt-first reconciliation. Exercise a genuine
matching-digest unsupported startup row as a negative, complete required
storage-neutral acceptance, affected operator PostgreSQL workflows and fresh
exact-head review before normal merge. This does not complete Delivery 3.
