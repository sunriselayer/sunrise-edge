# DR-0283: Live genesis foreign split with the recovered same-A key

Date: 2026-10-30 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

The independent `genesis-split-handoff` fixture already runs a foreign split
from disposable A to B, then B's whole-Coin return to A. Its original 21
predicates, exact approvals, signed frames, separate fee/nonce transitions,
paid results, receipts, replays, wrong-owner refusals and revoked restarts
remain the contract. The profile previously selected both original seed
paths. Its fresh setup has no prior signer or recovered A file.

## Decision

After the original A/B keygen/config setup and before the foreign phase,
reuse the unchanged early-recovery helper once. Its separate empty-registry
guard must pass; do not weaken the existing nonempty stopped-signer guard.
Use the default A `custody.seed.backup` and `custody.seed.restored` paths
under `/work/custody-keys`, initially absent. The existing private UID-copy
primitive backs up and restores only A, with its original 256-byte per-copy
limit and actual child waits. Require original/backup/restored regular,
single-link, custody-owned mode-0600 files and distinct device/inodes.

Select recovered same-A for the existing live foreign split and revoked
restart. Retain original B for its existing return and revoked restart.
Record actual retained `Popen` argv paths for both identities and both
lifetimes. Python checks every selection; Node independently requires the
exact ordered pair `[A restored, B original]` for live and restarted signers.

Keep new preparation and selection evidence in a separate top-level
`genesis_split_key_recovery` object. It retains the helper's three additive
predicates, exact paths, two waited private-copy children and generated-byte
accounting, plus observed per-file sizes and both selected-path arrays. The
two files are each at most 256 bytes, together at most 512 bytes; the existing
65-byte key format adds 130 logical bytes. Bound this new JSON evidence to
2KiB. Add no CLI, PTY, approval, signer or business call.

Preserve the original 21 predicates and old phase summary unchanged:
19 exec, two PTY, four signers, one host, zero private-copy children,
32 evidence leaves, 2MiB generated content, 48KiB capture and 4KiB summary.
Original setup retains two keygens and four waited isolation children.
The new pair is accounted outside both old groups. Preserve all four whole
profile selectors and every existing operation, approval, frame, signature,
nonce, fee, owner, result, receipt, replay, refusal, counter and resource,
capture, transport and time limit. Preserve both identities' live
`3/3/2/1` and restarted `1/1/0/1` counters.

## Limits

This is a same-A consumer connection within existing trust contracts.
It establishes no positive identity rotation, application/fee authority
migration, real-key ceremony, independent security clearance, parent-M2
completion or public readiness. Source checks do not establish actual
distinct-UID execution or runtime resource headroom. Qualification remains
source-specific in TODO.md.
