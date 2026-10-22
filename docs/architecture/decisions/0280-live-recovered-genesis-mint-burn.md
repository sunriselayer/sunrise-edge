# DR-0280: Live genesis mint/burn with the recovered same-identity key

Date: 2026-10-22 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

The genesis mint/burn fixture already performs the ordinary paid mint and
whole-Coin burn, stops its signer, restarts it to check revoked requests, and
then tests same-key historical signing recovery. Its ordinary live operations
previously used the original genesis key path. The historical recovery
signatures remain stale controls and are not submitted.

## Decision

Select the already stopped, distinct, custody-owned mode-0600
`custody.seed.restored` path produced by the existing publication recovery for
the existing genesis mint/burn live signer and its revoked restart. Require all
prior signers to be stopped before this family starts, verify the restored file
is distinct from the original key inode, and attribute both signer invocations
to that exact path.

Retain the current mint/burn requests, approvals, business submissions,
verification, request counters, revocations, restart refusals, and later
historical recovery controls. Add no operation, key, identity, child, profile,
path, allocation, authority, or selector. Do not submit the historical 9e/9f
frames or treat them as current.

## Limits

This fixture slice does not establish key rotation, ownership migration,
automatic signing, real-key ceremony, complete M2 acceptance, or public
readiness. Source checks do not establish actual fixture execution.
