# DR-0192: Verified original SQLite Seal host composition

Date: 2026-10-04 (Asia/Singapore)

Status: Accepted composition following the independently reviewed and merged
Delivery 3 implementation. This records the composition boundary, not release
or security-audit readiness. Current evidence and remaining work belong in
[TODO.md](../../../TODO.md).

## Context

[DR-0187](0187-first-epoch-ordered-seal.md) defines the actual outgoing Seal,
but a library router in a test is not a shipped serving host. The optional
PostgreSQL host deliberately supplies no Seal reconstruction capability.
Operators need a storage-neutral local composition that can use each outgoing
validator's existing SQLite namespace without introducing another protocol
engine or making a long-lived process a consensus assumption.

Host query configuration also must represent its independently pinned complete
hash schedule. A startup suite choice is insufficient: each query must resolve
the authoritative committed epoch or fresh successor warrant and emit a
consistent suite ID and canonical configuration. That read-only projection is
not authorization for signing or for accepting a remote protocol context.

## Decision

1. Add a thin `sqlite_source_host` executable around an operator-owned original
   host composition. Require independently pinned genesis, chain, protocol,
   outgoing epoch, domain, complete hash schedule and each local signer's key.
   Require the causal genesis profile and exact committed original committee,
   marker and paid fee policy. Never install genesis, import, activate, reset,
   repair a namespace or infer trusted pins from its database.
2. Open only existing Ordinary, Unsealed SQLite state and blob files. Refuse
   unknown arguments and non-loopback listeners. Explicit offline fence-advance
   confirmation is operational coordination, not cryptographic authority.
   Claim one fresh writer generation and make deciding durable reads under that
   generation before exposing a listener; never reclaim a fence during a request.
   Re-verify existing ordered consensus state read-only; a missing or deleted
   row is refusal, never a reason to initialize it inside the serving host.
3. Compose the existing certified FastVote and ordered economics dispatchers,
   paid engine, immutable verified root and the same store's existing Seal port.
   `OrderedSealHostComposition` supplies reconstruction; no raw operator Seal
   completion or alternate acceptance rule is added. Keep original read-only
   reconciliation distinct from fresh signing and mutation. A sealed namespace
   remains permanently retired and a new ordinary serving open refuses it.
4. Place genuinely identical local signer, attempt-identity and original-root
   startup invariants under one operator owner. Preserve different successor
   warrant and PostgreSQL startup/fence semantics rather than merging their
   authority or treating an original committee check as successor membership.
5. Build query configuration from the actual trusted resolver. The shared HTTP
   projection checks complete schedule and protocol agreement, selects the suite
   at the current authoritative epoch for each query, and refuses disagreement
   without repairing it. Existing schemas, vectors and independently expected
   client context checks are unchanged.

## Acceptance boundary

Require real independently owned SQLite source-host processes and genuine
signed quorum/Seal execution, startup refusal and fence/replay checks, alongside
the existing isolated completion-fault tests. Do not relabel same-committee
evidence as A/B/C/D -> A/B/C/E or as recurring epoch proof. Host process lifetime
is only a native transport convenience. No public-network, PostgreSQL Seal,
Durable Objects, production or audit readiness follows from this composition.

PostgreSQL remains optional. Its touched host composition/dependencies require
the selected complete PostgreSQL acceptance profile; the ordinary repository
gate remains storage-neutral.
