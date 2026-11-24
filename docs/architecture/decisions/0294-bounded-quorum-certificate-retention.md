# DR-0294: Bounded quorum-certificate retention

Date: 2026-11-16 (Asia/Singapore)

Status: Proposed defensive cache policy; final security review pending.

## Context

DR-0293 bounds speculative proposal bodies. Authenticated certificates remained
subject only to a committed-height retention window. Repeated certified views
at one uncommitted height can therefore fill the persisted certificate count
or encoded-state byte limit, even when speculative proposal bodies are bounded.
The existing limits correctly fail closed, but then an authorized transition
cannot persist progress.

## Decision

Keep certificate verification and far-ahead catch-up unchanged. In the shared
`prune_state` transition, protect the high and locked certificates, an existing
certificate for the local last vote, and certificates on the available safety
ancestry. Admit other certificates as speculative state in descending view
order, with the canonical minimum digest per view, a finite count, and the
remaining encoded-state byte budget. Charge a known matching proposal body
and its available ancestry with the certificate when admitting it; skip an
optional certificate when that full cost does not fit. Preserve the
proof-before-prune order. Reattach a certificate to a speculative body only
when its available ancestry remains retained.

This is a retention policy. It does not change the v1 `0xD010`–`0xD016`
layout, type IDs, stable encoding vectors, signatures, quorum checks, or
persisted-state decoder. An old saturated v1 snapshot remains readable and
round-trips unchanged; its first authorized transition applies the new bound.
Protected material that alone exceeds the existing limits still fails closed.

## Consequences

A certificate outside the bounded cache can be delivered again. A proposal
arriving after its certificate was evicted does not recover that certificate
from partial votes; certified progress needs certificate redelivery. Existing
ordered replay sends the proposal and certificate for each round and retains
its separate certified-body reobservation. Cache contents after a transition
may differ from an earlier v1 implementation, while wire bytes and historical
decoding remain compatible. D02 and M1 still require final-source independent
security review and the repository gates.
