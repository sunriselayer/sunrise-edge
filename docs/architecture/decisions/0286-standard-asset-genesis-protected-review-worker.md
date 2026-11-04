# DR-0286: Offline Standard Asset genesis protected review worker

Date: 2026-11-04, Asia/Singapore

Status: The human selected the trusted local OS with a separate process and
UID for the offline genesis author on 2026-11-04. This record describes the
development implementation and its required evidence. It does not assign real
approvers, recovery holders, host users or keys, approve economic values, or
qualify a launch.

## Actual signing owner

The existing `standard-asset-genesis author` composes the public Standard
Asset package and an ordinary `GenesisManifest`. It signs the publication
submission, Instantiate initialization and outer manifest with the same
independently expected genesis-authority key. The first two exact frames are
independent of their signatures. The outer frame includes both signatures,
so a reviewer cannot approve its exact bytes before those two key uses.
The generic `VerifiedGenesisRoot` and original in-memory installer remain the
authority for all signed output; this record creates no new genesis encoding,
canonical frame, key family, or installer.

## Selected local composition

The genesis-only `protected-worker nested` command reads a worker-owned private
config (one existing `--flag=value` author argument per line) and bounded
validator/allocation tables. It prepares the complete manifest with zero
signature fields and exact publication and initialization frames through the
same builder as the ordinary author. Its Unix socket is owned by the worker
UID, and the connection's peer credential must match the separately configured
reviewer UID. The worker and reviewer UIDs must differ. The reviewer frontend
receives a bounded canonical candidate and exact frames, recomputes the frames
from the candidate and configured hash schedule, renders the complete candidate
using the existing inspection fields, and requires an exact typed approval
digest. The worker persists the approval under a private create-new state file
with a one-hour maximum expiry and the exact reviewer UID. No key is opened in
this phase. A connected reviewer has a finite fifteen-minute window to inspect
and respond. The displayed hash schedule is part of the approval digest.
Protected key, table and output paths are absolute; output cannot alias the
local socket or revocation tombstone.

After that worker has stopped, `protected-worker manifest` reads the same
worker-owned config and approval. It recomputes the complete unsigned draft;
a changed config, code, table, policy, committee, authority, request identity,
reviewer UID, or economics changes the pinned digest and refuses. The bounded
tables are read once into a single typed snapshot used for both the draft
comparison and candidate composition. Only then does it open
the worker-owned key and compare its real public key to the independently
configured genesis authority. It signs the two previously reviewed nested
frames, presents the signed candidate and exact outer frame to the same
authenticated reviewer UID, and requires a second exact typed approval. It
rechecks expiry and revocation before the outer signature. The final manifest
must pass `VerifiedGenesisRoot`, the original in-memory installer and the
existing fresh-output publisher. The frontend's `approval_sent` message is not
a claim that the worker published a manifest.

`protected-worker revoke` records a worker-owned create-new tombstone after an
authenticated reviewer request. It is effective for later manifest phases.
Expiry or a tombstone refuses signing after restart. An absent/corrupt state,
unexpected peer UID, wrong key, changed candidate, disconnect, timeout, or
existing output refuses with no alternate key or ordinary-author fallback.
The finite one-connection worker uses the shared operator path/socket admission
and the existing Native HTTP bounded IPC and peer-credential primitives. It
accepts no arbitrary frame-signing request. Actual code approval provenance
and authorized semantic values remain separate product choices; a digest and
local display cannot establish those decisions by themselves.

## Verification and limits

Extend the existing Standard Asset genesis test owner with a disposable
distinct-UID process path that produces a real signed manifest and installs it
for the original four independent validator pairs. Check ordinary-author byte
equivalence, wrong UID and key, changed code/policy/committee/economics,
expiry/revocation, restart, disconnected review and existing-output refusal.
This selected boundary trusts local OS/root and worker process integrity. It
does not claim resistance to a compromised OS, rollback of all worker-owned
approval state, production key recovery, reviewer identity enrollment,
semantic code-safety approval or network activation.
