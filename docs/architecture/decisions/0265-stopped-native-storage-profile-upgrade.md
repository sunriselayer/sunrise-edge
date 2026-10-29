# DR-0265: Stopped Native storage-profile software upgrade

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for the selected local upgrade fixture.

## Decision

Exercise the supported software/storage transition with an actual retained prior
release and current independently anchored hosts. Existing explicit stopped-owner
enrollment changes `sunrise-edge/sqlite/structured/schema/v6` into
`sunrise-edge/sqlite/structured/schema/v6/independent-anchor/v1`.
SQLite `PRAGMA user_version` remains5. This is one-way authority-profile enrollment
and software upgrade, without structural schema rewrite or protocol activation.

Keep all fifteen existing local-TLS selectors and assertions. A separate ignored
Linux selector requires an absolute `SUNRISE_EDGE_PREVIOUS_SQLITE_SOURCE_HOST`.
Missing or differing input fails; never substitute the current host, download a
binary or change the process-global environment. Prior source:
`9de634a7bdcd38b0b2f78c6dcab695eaf8f80853`; retained RELEASE host:
20,055,432 bytes, SHA-256
`00fdc14a864249d798460562cfa10dbd3e2e8e50da91dcc85ab691001bc7ae24`.
Original reproducible A/B manifest SHA-256:
`b7024bf9010014ad430216bfb393626f46d6de3cd22c4c0cbc4486600b18aba4`.
Its `fixturePassed=false` remains artifact-provenance-only evidence. The new
fixture requires its own execution. The old ELF has release opt3, debug assertions
and overflow checks disabled; current driver/oracle/host profiles are separately
recorded by their owning build.

Use a private0700 task directory and a separate-inode0555 executable copy of the
regular current-UID single-link0755 retained ELF. Never chmod/hardlink the original.
Admit its exact length before a bounded read plus one overflow probe. Recheck
original/copy identity, mode, length, mtime/ctime and complete hash around every
prior child dispatch. Fixed fixture inputs are at most19 files of1MiB each.

## Actual upgrade and refusal oracle

1. Prepare the original signed genesis. Add one unrelated70KiB canonical historical
   object through actual `put_blob` and typed invocation commit. Independently fixed
   identity/owner/data, context-derived digest, head/version and canonical receipt
   are separate from signed paid Coin traffic. Prove the referenced body in complete
   portable captures and its reference through actual old/current TLS queries.
   No ad-hoc SQL write, fake quorum or recovered-output-derived expectation.
2. Start four actual prior hosts at fence2 using valid original argv and unchanged
   protocol/namespace/genesis/TLS/signing pins. Run existing paid CLI/quorum,
   receipt/object-history and full closed12 structured/2 blob table/4 portable
   collection oracles with a positive referenced body.
3. Orderly SIGTERM and actually wait/reap each owned prior host. Require successful
   termination records and no parent SQLite owners. Current compiled inspect,
   enroll and checkpoint commands use independently retained exact roots and four
   separate sibling authorities outside the source tree. Every source/blob cell
   remains equal except the explicit metadata schema identity. Structural version5,
   source identity, mutation sequence, fence2, receipts and bodies remain fixed.
4. Attempt each actual old host with the same valid old argv, no anchor flag and
   available original endpoint. Require exit1, exact unsupported-schema diagnostic,
   empty stdout, available endpoint and no fence advance. Complete logical
   observations before physical fingerprinting; an actual current checkpoint owner
   then closes observer-created source sidecars without advancing acknowledgement.
   Compare all stopped main/optional WAL/SHM/journal presence and bytes plus empty
   leases immediately after every refusal, before any new SQL observer. Admit the
   whole stopped image within16MiB before copying; never unlink a sidecar to fit
   the oracle. After all four physical comparisons, independently compare all rows
   and authority manifests again.
5. Resume four actual current anchored hosts at fence3 and identical endpoints.
   Prove a complete fence-only image delta, historical paid receipt/object bytes,
   old saved replay without state/acknowledgement mutation, then fresh funded paid
   CLI/quorum work and exact receipt replay. Preserve positive historical bodies,
   fixed inputs and complete images through ordinary tail stop. Existing finite
   per-process/startup/capture and CLI deadlines apply, without a promise to bound
   kernel syscalls or global host cleanup.

## Compatibility boundary

Rollback policy is incompatible old-writer refusal and safe stop followed by
current-profile continuation. Never downgrade metadata, reset anchor/fence,
reinstall genesis, invent protocolV2 or allow a stale snapshot. Existing history
readers remain valid; unsupported cross-version execution refuses until an explicit
migration is defined. Original M4 migration/upgrade and rollback-or-stop criteria
are exercised against this supported profile; activating an unsupported future
protocol version is not required. Execution/completion status belongs in TODO.

This fixture grants no quorum checkpoint authority, cross-file atomicity, physical
power/media guarantee, off-host retention, real key ceremony, independent security
audit or blanket M4/release qualification.
