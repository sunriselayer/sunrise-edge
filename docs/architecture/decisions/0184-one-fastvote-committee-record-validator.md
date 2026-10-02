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

## Decision

Adopt [committee record validation](../committee-record-validation.md). Expose
one pure typed record-to-committee validator; keep bounded byte decoding and
actual live/historical authority with their existing owners. Delete duplicate
operator conversion, and reuse structural validation from genesis without
moving its capacity checks or broadening historical limits. Map typed failures
to owning diagnostics rather than inspect error strings.

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
