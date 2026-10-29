# DR-0276: Live genesis transfer with the recovered same-identity key

Date: 2026-10-21 (Asia/Singapore)

Status: Accepted source contract. Actual qualification belongs in TODO.md.

## Context

The existing transfer recovery control signs retained historical preimages
without submitting them again. The separate two-owner genesis Coin handoff
executes fresh A -> B -> A transfers, but previously loaded A's original key
path. These controls establish different facts; historical signature equality
alone does not establish a fresh successful business operation after recovery.

## Decision

Pass `main()`'s already recovered `custody.seed.restored` path into the existing
genesis Coin handoff. Both A's live `serve-transfer` and its restarted refusal
load that path. B continues to load its existing `custody2.seed`. Require the
recovered path to be the existing expected path, different from the original
path, and a distinct custody-owned mode-0600 regular file. The server's existing
key/config check and independently finalized signatures retain A's public key.
The controller never reads key bytes and adds no key or private-copy operation.

A small ledger retains the actual owned signer `Popen` instances, their actual
key-file arguments and socket paths. Only the existing `communicate()` calls
mark completion, including expected startup refusals whose nonzero exits stay
expected. Before the original recovery copy and before the live handoff, require
all prior signer communications to have completed, their processes reaped and
their sockets absent. Keep the existing explicit A stop/wait barrier before B.
The ledger adds no process discovery or termination mechanism and does not
reconstruct historical pipe or execution evidence.

The handoff receipt records the actual live and restart key arguments. Its
existing Node validator requires the recovered A path and unchanged B path,
the distinct recovered-file check and the prior-signer stop barrier. Preserve
all prior controls, complete operation review, offline/actual signed-byte
equality, both real submissions, current versions/owners, separate fees/nonces,
canonical results/receipts and all saved replays. No child, generated file,
request, key copy, selector, profile, deadline or output allowance is added.

Explanatory Python comments for the logical instance seed, application mint/burn
and create-asset phases live outside the embedded program in JavaScript comments.
This keeps the raw program within its unchanged 262144-byte transport limit;
the Python AST, protocol frames, assertions, selectors and all runtime budgets
remain unchanged. Source checks alone do not qualify an actual fixture run.

## Compatibility and limits

This remains the accepted trusted-local-OS, separate-process/UID development
fixture. No protocol Rust, canonical bytes, authority, genesis/code/policy pin,
key identity, rotation or ownership rule changes. Historical signing-only
recovery remains separately labeled. Original and recovered key paths coexist
under the trusted administrator; the proof is stopped invocation and actual
key-path attribution, not deletion or global prevention of old-key reuse.

Only actual source-bound execution may qualify this selected live same-key
transfer recovery. Syntax/source checks do not establish runtime success,
other-family lifecycle coverage, new-identity rotation, off-host recovery,
real-key ceremony, parent M2 completion or public readiness.
