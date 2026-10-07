# DR-0208: Native SQLite first and provider-independent protected signing

Date: 2026-10-07 (Asia/Singapore)

Status: Accepted human scope decision. The human selected Native plus SQLite
first, Cloudflare DO later, and removed Ledger as a mandatory mainnet
prerequisite. This accepts neither a replacement signer nor production
readiness or deployment.

## Context

[DR-0200](0200-maintainability-and-mainnet-roadmap.md) retained the historical
complete S4 Ledger prerequisite pending a human decision. That decision is now
explicit. PostgreSQL remains optional under DR-0151/0172; local SQLite acceptance
does not become production qualification by renaming it.

## Decision

Qualify the native host with an independent local SQLite state/blob pair per
validator first. Preserve one atomicity-domain contract for objects, state,
nonce, receipt and outbox. Immutable blob storage remains a distinct resource;
do not claim cross-file transactions. Native filesystem, synchronous I/O,
ownership, fencing, crash/ambiguity, backup/restore and ingress need their own
attributable evidence. PostgreSQL and DO are neither substitutes for that
evidence nor initial-profile prerequisites. Other providers need separate
qualification before being advertised as supported production profiles;
retain their existing adapter checks and historical criteria.

Replace the mainnet dependency on the Ledger-specific S4a–S4d product with a
separately designed, independently reviewed protected-signing gate. Retain key
protection, authority separation, exact signing-content verification,
refusal/failure, recovery, rotation and revocation. Historical Ledger
physical/HIL/UI/reproducibility requirements remain binding for a future
advertised Ledger product, not a non-Ledger release. Neither `LocalSigner` nor
a plaintext validator seed file qualifies merely because hardware is optional.

Distinguish automatic validator protocol signatures from human asset/governance
approval. The former require locally pinned identity, allowed signature domains
and verified live authority, not human confirmation for every consensus vote.
The latter require exact intent review before the same retained bytes are signed
and independent returned-signature verification. A backend and a clear-signing
policy are separate responsibilities; arbitrary transport-supplied bytes do not
grant signing authority.

Reuse existing cryptographic domains, runtime signer ports, prepared-value
finalization and device-independent signing-view where they actually apply.
Define the replacement backend and concrete consumers in a separate reviewed
design before implementation. Do not introduce another signature format, blind
fallback, generic `trusted=true` flag, asset-only node-core privilege or unused
framework. Local mocks prove composition/refusal, not production custody.

## Release and authority boundary

This supersedes only the pending profile choice and Ledger-specific mainnet
dependency in DR-0200 and the live M2 gate. Other M1–M8, protocol-activation,
economic/security, capacity, actual-fault, off-host-restore and public-operation
criteria remain. Preserve the original text and this explicit amendment for
the final gate review. Neither this decision nor an automated work window
authorizes public testnet/mainnet activation.

Development remains local: loopback, disposable keys and local SQLite. No live
Cloudflare writes, public listeners, cloud resources, deployments, billing
changes or live PostgreSQL service are authorized. Real custody, independent
operators, genesis/economics and external qualification need actual decisions
and evidence, not fixture values. Continue independent safe work while those
prerequisites are obtained.

Progress and remaining work belong only in [TODO.md](../../../TODO.md).
