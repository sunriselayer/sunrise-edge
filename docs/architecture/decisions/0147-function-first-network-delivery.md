# DR-0147: Function-first network delivery sequencing

## Status

Accepted, 2026-09-26.

## Context

The Phase 3 checklist mixed two different kinds of remaining work under one
gate: the Phase 3 economics/security core (custody, bonds, forfeiture, signed
fee claims and payout verification — implemented — plus the still-open Phase
3 security/tech-lead review gate) and representative sustained
load/soak/capacity certification with adopted throughput/recovery targets.
Separately, exposing FastVote as a usable network — authenticated external
validator ingress, a CLI end-to-end quorum submission path, and operator/
network surfaces for the bond/epoch/equivocation/reward/claim lifecycle — is
its own follow-on delivery with its own design/authentication/audit gate, but
recent wording had started folding it into Phase 3 completion itself.
DR-0145/0146 produced real, bounded PostgreSQL measurements (concurrent
claim/reopen regressions and a finite certified workload/recovery harness)
but explicitly declined to adopt an initial-network workload or recovery
budget. That target is still undecided: no peak TPS, concurrent-user count,
or recovery-time budget has been chosen.

## Decision

Prioritize functional work over load testing. Representative sustained
load/soak/capacity certification and adopting throughput/recovery SLOs
become **post-launch hardening**: they follow initial network startup
rather than gating it. They are not prerequisites for Phase 3 completion or
for the network functional delivery below.

Phase 3 completion still requires, unchanged: the completed custody/bond/
forfeiture/signed-claim/payout economics core, and the existing Phase 3
security and tech-lead review gate. It does not require external validator
ingress.

Once Phase 3 closes, exposing FastVote as a usable network is the next
integrated **network functional delivery**, additionally requiring:

- authenticated, request/event-driven external validator access for
  FastVote prepare/certificate/apply, plus a CLI end-to-end quorum
  submission path;
- exposing the already-implemented bond/epoch/equivocation/reward/claim
  lifecycle through explicit authenticated operator/network surfaces where
  needed;
- bounded independent-validator functional start/restart/replay/
  authorization evidence and a documented deployment/configuration
  walkthrough;
- a focused security review before exposing this ingress, plus its own
  separate design/authentication/audit gate, distinct from the Phase 3
  review gate above.

No peak TPS, concurrent-user count, or recovery-time budget is adopted by
this decision; those targets remain undecided and are revisited after the
network is actually running.

## Limits

This decision does not waive correctness, atomicity or replay guarantees;
persistence, fencing or restart-recovery evidence; basic failure/error
handling checks; authenticated/authorized ingress; independent validator
authority; the existing security and tech-lead review gates; or any
production/mainnet criterion. It does not remove validator-set changes,
slashing or rewards from FastVote Phase 3 completion. It does not mark
FastVote, Phase 3 or the network ready — the focused security/tech-lead gate
remains open. The bounded PostgreSQL measurement instrument (DR-0146) remains
implemented as fixture-level evidence; it is not the next development focus
and does not constitute certification. This decision authorizes no new
public route, no daemon, no Standard Asset core privilege and no blanket
launch authorization.
