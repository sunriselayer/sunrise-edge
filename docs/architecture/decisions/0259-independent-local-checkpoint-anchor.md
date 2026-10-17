# DR-0259: Independent local acknowledgement anchor

Date: 2026-10-17 (Asia/Singapore)

Status: Selected local implementation contract. Execution and release status
remain in TODO; this record does not close all M4 requirements.

## Context and decision

Closure-identity pins and ordered-history floors verify selected saved material,
but cannot detect a mutually consistent rollback of the latest owned state in
one epoch. A readiness nonce would change protocol bytes and still travel with
a cloned namespace. Retain every existing canonical frame and introduce an
explicit native deployment/storage profile instead.

The trusted local OS retains a separate, non-restored anchor database with one
lifetime namespace lease on a separate inode. All native SQL transactions check
its complete typed 12-table state root and immutable body manifest. A durable
Pending intent precedes source COMMIT; exact committed-state inspection and
anchor finalization precede acknowledgement. Pending with old state refuses
without auto-clear. Pending with exact new state can finish that same intent.
Missing, replaced, cloned, corrupt or unreachable anchor authority never falls
back to baseline or self-enrolls.

One-time enrollment requires stopped legacy writers/signers and explicit
independently retained initial state/body roots. The distinct local schema
identity makes baseline engines, including already opened handles, reject their
next operation. Row layouts, old history decoding, canonical protocol values and
baseline PG/DO session behavior remain unchanged. An exact current state clone
can take over only after the old lease closes; stale copies and in-place rollback
refuse. Copying the independent authority itself is not supported recovery.

Use the responsibility-owned [local checkpoint anchor contract](../local-checkpoint-anchor.md)
for exact ownership, roots, bounds, crash states, profile transition, command and
entry-path requirements. No new service, privileged host configuration, crypto
primitive or protocol identifier is introduced.

## Limits and acceptance

The initial stopped-writer assertion does not retrospectively prove freshness or
revoke an old in-memory signer. Full media snapshots that also roll back the
independent authority cannot be detected locally. This scope does not create
quorum checkpoint authority or replace proof reconstruction, protected key
custody, encrypted whole-crash-state/off-host restore, protocol-upgrade activation
or actual M3 host/power/storage fault qualification.

Require executable baseline-handle exclusion, concurrent-current-clone refusal,
exact-current recovery after stop, same-epoch in-place rollback refusal, both
sides of source COMMIT, immutable-body retention, fixed-field and quota refusals,
and external SQLite main/WAL lock exclusion after a failed second open. Keep all
existing import/readiness/Seal/activation guards and the original recurring
8-link/e8-withdrawal/35-role owners. Compilation is not execution. Complete
source review, owning execution, full required validation and exact-source
hosted CI remain separate gates; old-source successes cannot qualify this slice.
