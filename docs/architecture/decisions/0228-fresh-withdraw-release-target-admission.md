# DR-0228: Fresh registered withdrawal release-target admission

Date: 2026-10-11, Asia/Singapore

Status: Bounded source implementation decision; verified remediation and
integration acceptance remain open. This record supplies no rollout authority.

## Context

A registered owner can sign a structurally valid Withdraw intent whose local
leg cannot release the committed collateral. An exact custody reference alone
is insufficient: a different valid contract entrypoint can still reach ordered
certification before the release owner refuses it at completion. A fresh gate
must check the installed release target, not reinterpret such a committed
failure as an economic rejection or repair already-certified history.

## Decision

Use the existing shared fresh causal signing boundary for both leader proposal
and voter admission, after retained replay and justified-prefix completion.
Require the actual live epoch and chain-anchored committee to equal the pinned
trusted authority, and load the registered owner's committed bond row.

Preserve the owning refusal order: jail, a stale signed predecessor/resource,
early unlock, current membership and other ineligible states retain their
existing typed outcome. Only a healthy Unbonding row at or after unlock, outside
the actual current committee and with the exact predecessor, reaches the new
release-target comparison.

The authenticated embedded leg must have exactly one Write access entry whose
whole typed ObjectRef equals the committed custody reference. Do not recompute
its historical digest under the current hash suite. Load the installed economics
policy at the committed bond's own context and select its exact resource. Require
the current call context, code, instance and transfer entrypoint to match the
owning release tuple. Do not require that historical resource to remain
bond-enabled, substitute the latest policy, or grant custody from this check.

All deciding state reads use the existing observed reader and join its admission
CAS. A conflicting repeated observation remains sticky and outranks a later
semantic error. A race after private signing can reject the durable commit
without exposing a proposal/vote; this is not a zero-private-signature claim.

## Compatibility and limits

The gate changes only fresh causal Withdraw signing. It changes no canonical
bytes, signature frames, public API, persisted layout or dependency. Historical
admission, retained/completed replay and signerless reconciliation keep their
existing behavior. Justified-prefix completion can legitimately write before
the fresh gate; refusal is not a whole-call no-write guarantee.

This check does not reserve the object, execute WASM, validate all release
effects/recipient constraints or issue a custody capability. The owning generic
leg admission, release capability, business evaluation and one atomic completion
still enforce those responsibilities. Lost committed prerequisites still stop
completion; no downgrade, rollback or certified-history repair is introduced.

The source fixture retains genuine original-root and seven successor handoffs,
the registered nonmember's configured unlock, both leader/voter paths and the
ordinary accepted withdrawals. It adds full-reference and re-signed wrong-target
refusals, exact deciding-read CAS races and sticky-read checks. Snapshots, signer
calls, mutation forwarding and custody reads are distinct oracles.

The single independent candidate review rejected the original reference-only
gate. Its concrete entrypoint route was parent-confirmed and the candidate was
revised. No independent approval of the revised source, compiler/test result,
physical durability proof or completed security finding is claimed. Written
controls and read-only diff checks are not execution. Current verification and
remaining release gates are tracked only in [TODO.md](../../../TODO.md).
