# DR-0278: Live genesis split/merge with the recovered same-identity key

Date: 2026-10-22 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

The existing genesis split/merge fixture performs a live self-split and merge,
then separately checks same-key historical signing recovery. The live consumer
previously loaded the original genesis key path, so the historical recovery
control did not show the recovered key serving a live operation.

## Decision

Use the existing `custody.seed.restored` file from the earlier stopped-key
recovery in the existing genesis split/merge fixture. Before this consumer
starts, require every previously owned custody signer to have completed its
existing `communicate()` wait, exited, and removed its socket. Check that the
restored key is a distinct custody-owned mode-0600 regular file. Require both
the live split/merge signer and the existing revoked-restart signer to use that
exact restored path, retaining the existing approvals, genesis trust, request
frames, live split/merge operations, revocation and refusal controls.

Keep the later split/merge historical signing-only recovery in place. It
continues to use retained original preimages and its own backup/restore paths;
it remains separate evidence. Add no submissions, keys, copies, operations,
authority, selectors, profiles, children, files, or allocation. Existing
fixture time, output, container and resource bounds remain fixed.

## Limits

This selected development fixture does not establish key rotation, ownership
migration, other asset-family lifecycle coverage, real-key ceremony, complete
M2 acceptance, or public readiness. Source checks do not establish actual
fixture execution.
