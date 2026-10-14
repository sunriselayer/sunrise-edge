# DR-0244: Publication approval revocation and stopped key lifecycle

Date: 2026-10-15, Asia/Tokyo

Status: Accepted for the development-only Linux OS custody profile.

## Context

[DR-0238](0238-publication-only-local-os-custody.md) retains exact publication
approvals across process restart. Expiry alone cannot cancel a still-valid
approval. Replacing or recovering a key file while a signer runs also leaves
the old key in that process's memory. The selected local OS/UID protection
boundary remains unchanged.

## Decision

`custody revoke --approvals-dir DIR --request-id ID` publishes an immutable,
administrator-owned `ID.revoked` file in the existing private approval store.
Its adapter-local bytes are version 1 followed by the exact 32-byte request ID.
The existing synchronized, non-replacing private-file publication primitive
provides complete bytes, exclusive creation and directory synchronization.
An identical record permits an idempotent retry that synchronizes the directory
again before success; malformed, inaccessible,
unknown-version, wrong-owner/mode and symlink records fail closed. No delete,
expiry, overwrite or unrevocation command is introduced. Cancellation reduces
authority, so the explicit command does not require interactive approval.

`custody approve` refuses a revoked ID before showing a confirmation and at
the approval write boundary. `serve` checks revocation from disk immediately
before each signature, returning the existing `NoApproval` refusal. It never
writes either approvals or revocations. Canonical publication bytes, signature
payloads, protocol type IDs and the existing custody request/response codec
remain unchanged. An old approval file cannot override a retained revocation.
New intent requires a new request ID and an independent exact approval.

A concurrent cancellation cannot retract an already produced signature or
preempt an in-flight request after its last revocation check. For a complete
local signing fence, the administrator must stop and wait for every signer
using the key/store, cancel the ID, then start a new bounded signer. Account
nonce reconciliation remains necessary for signatures already delivered.

Key recovery and rotation use that same stopped boundary and existing keygen,
config/public-key pinning and startup validation. Recovery preserves the exact
config and all current revocations; restoring a stale entire store is forbidden.
Rotation creates a new key at a new path and a separately pinned config, changes
the client public-key pin, and independently prepares/approves new-publisher
artifacts. It neither migrates an on-chain account nor revokes old signatures.
No hot reload, generic signing route, seed export command or new cryptography
is added.

## Validation and limits

Owning tests cover immutable retry, exact record bytes, corrupt/unsupported
records, symlinks/modes, signature refusal, restored old approvals and failed
reapproval. The retained Docker UID/PTY fixture adds cancellation/restart,
private disposable key recovery and stopped rotation controls without replacing
its earlier peer, approval, expiry and restart controls.

The lifecycle runbook is [publication custody lifecycle](../publication-custody-lifecycle.md).
This remains publication-only local OS protection: other interactive and
automatic protocol signing families, encrypted/off-host custody, compromised
root resistance, real ceremonies, administrator/recovery roles and production
qualification remain outside this slice. Whole-store rollback resistance is
not claimed; a trusted administrator must retain current revocations.
