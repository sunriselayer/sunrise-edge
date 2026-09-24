# DR-0139: FastVote fee-claim history verification

## Status

Accepted, 2026-09-24. The commitment witness and explicit per-escrow,
escrow-side verifier are implemented with focused tests. Split payout-object
verification, an all-escrow restart inventory, and network capacity evidence
remain open. This decision does not close FastVote Phase 3 or establish
network readiness.

## Context

Certificate apply writes one mutable fee-settlement row. Each later claim
overwrites that row and retains its exact signed envelope under a
generation-scoped key. The envelope signs the previous and resulting row
digests, but a SQLite close/reopen followed by exact replay checks only the
latest state and receipt. It does not independently establish how that state
was reached.

Before this decision, the FastCertificate authenticated a staged-commit
digest but its preimage was not retained. Thus the initial fee amount and
escrow ObjectRef could not be re-derived from the certificate after restart.
An unclaimed escrow has no claimant-signed previous-row digest either. A
verifier that merely trusts the installed row as its first link would
overstate its guarantee.

## Decision

Certificate apply will atomically retain the exact already-defined staged
commitment envelope under a request-scoped reserved key, with an initial
revision assertion. Its hash must equal both the locally prepared commitment
and the quorum-verified certificate's effects hash. This does not change the
existing transaction, certificate, object, receipt, settlement, or claim
wire formats. On verification, the retained envelope is canonical-decoded,
hashed under the certificate context, and its paid result supplies the
initial fee output and charged amount. The certificate-epoch validator set
supplies the initial sorted shares; the pinned fee policy supplies the
resource identity. The initial escrow object version is checked against
that certified ObjectRef.

A bounded per-escrow verifier then walks immutable signed claim envelopes in
generation order. It must recheck historical validator signatures, exact
identity and context, the operation implied by the prior share state, both
row digests recomputed from exact reconstructed bytes, and the final row's
byte equality with the installed singleton. Each positive claim must also
re-authenticate its embedded leg against the historical committed execution
policy and exact economics-pinned target, then check the previous and
resulting immutable escrow object versions under
their respective hash epochs, owner transitions, type/schema continuity,
and nominal-value conservation through the signed executable ABI. Zero-share
claims must not imply an object transition. A missing, reordered, forged,
orphaned, or coordinated rewritten row/envelope chain fails closed.

This API verifies one explicit escrow request id. It is not a startup-wide
inventory: the post-genesis escrow IDs are not in the genesis manifest, and
the structured durable-store interface has no typed escrow enumeration.
The current claim envelope also does not retain the split payout ObjectRef.
Escrow-side value conservation alone does not independently authenticate
the payout object. Those two gaps must remain explicit in Phase 3 TODO until
there is a bounded inventory and a complete payout transition proof. A
whole-store rollback still requires a separately anchored checkpoint or
state root; a local database alone cannot detect its own complete rollback.

The implementation verifies an explicit charged escrow's certified initial
row after a real file-backed SQLite close/reopen, plus independent positive
split/final chain fixtures and tamper cases. The local capacity regression of
DR-0138 uses directly set-up zero-share rows, not certified apply. Neither
test family alone proves the still-open end-to-end all-escrow/payout gate.

## Evidence required before Phase 3 closes

- Real file-backed SQLite close/reopen verification of a certified initial
  escrow followed by zero, split, and final claims, including historical
  validator-set and hash-suite changes where protocol rules permit them.
- Direct tamper tests for the certificate, commitment preimage, initial row,
  signed envelope, intermediate row, escrow object version/body, split payout,
  and installed tail; positive and unclaimed escrows both need coverage.
- A bounded way to discover all escrows at restart, or an explicitly reviewed
  equivalent operational verification gate. Per-request verification alone
  cannot support a claim that every retained escrow was checked.
- The independent capacity/load/soak evidence of DR-0138 and the Phase 3
  review gate. Neither an added verifier nor deterministic byte counts imply
  network capacity.
