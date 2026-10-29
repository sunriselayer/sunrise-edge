# DR-0273: Original ordered stopped same-identity key recovery

Date: 2026-10-19, Asia/Singapore

Status: Accepted bounded fixture design. Execution qualification belongs only
in TODO. This does not establish all-M2 or production key-management readiness.

## Decision

Extend the existing [DR-0264](0264-original-ordered-protocol-custody-worker.md)
four-validator disposable fixture to verify stopped same-identity recovery at
new private key paths. A restart that reopens the original key path does not
exercise this recovery procedure.

Keep all original worker/frontend separation, peer authentication, refused
operations, stored proposal/vote identity, complete-row oracle, direct TLS,
resource bounds and release inventory. No Rust or protocol behavior changes.

After the first proposal and four saved votes, stop every original signing
worker. Require its exact drain summary, actual exit 0, wait/reap, both pipe EOFs
and absent socket before any seed backup/restore. Keep frontends alive and
require the existing unavailable response and unchanged row images. Checkpoint
only through the existing released-lease owner.

One helper runs as worker 12001 with no supplementary groups and CapEff 0 under
the existing checked role wrapper. It handles all four exact 32-byte disposable
seeds in sequence. For each worker it creates a 0700 backup directory and a 0600
create-new backup, verifies exact seed equality, unlinks the original key and
requires ENOENT. It then reads the backup into a 0600 create-new restored key
inside a separate new 0700 directory and verifies exact seed equality again.
Private file checks require worker ownership, regular single-link files and
distinct backup/restored inodes. Seeds and their hashes never enter logs or
public artifacts. Every writable path remains within the same owned tmpfs.

Leave original worker configs and all frontend configs unchanged. Create a
separate private recovery config whose bytes differ only in the one
`signing-key-file` value. Pin the same public validator identities, genesis
manifests/digest, protocol context and retained source/body/anchor paths. The
helper never opens or copies those stores. Require the original SQL oracle's
complete unchanged row images after the key procedure and before resumption.

Frontend 12002 and unprivileged operator/intruder 12003 must each receive EACCES
when opening every restored keyfile and backup, as well as the private configs
and stores covered by the original refusal control. Root and the worker's
existing trusted code remain in the trusted local OS boundary.

Resume all four workers with the new recovery configs and original paths
unavailable. Preserve the exact fence 3 claim, same-vote byte equality and
unchanged confirmed row images. Apply the saved QC, run the existing fresh
empty ordered round at height 2 and signerlessly replay the two-round prefix.
The fresh round exercises new protocol signing under the same identities;
it does not assert paid business execution. Retain final drain/wait/EOF and
socket/old-key-path absence checks for every worker.

The added helper and two read-refusal children fit the existing 160 child-record
limit and use the existing shared 175s positive-work deadline. The helper has
a 5s individual cap. Outer 280s, inner 230s, output/frame/allocation/pids/cgroup,
owned-PID cleanup and exact Docker resource-release bounds remain unchanged.
The Node owner validates the recovery receipt and its ordering before requiring
the original runtime results. Failure is preserved and cannot become success
through cleanup.

The exact source HEAD/tree and source inventory hashes in the actual compiled
build receipt stay mandatory. This decision introduces no provenance bridge,
cached-input exception or ancestor-source substitution.

## Scope

This is same-host recovery of disposable fixture seeds, with both backups and
restored keys destroyed by the existing tmpfs lifecycle. It adds no encryption,
real-key ceremony, host users/policy, database or anchor copy/rollback,
new-identity rotation, successor/FastVote/DrainSet authority, VM/ZeroShare
profile, security audit, off-host restore or public deployment claim. Owning
runtime verification and broader repository gates remain separate evidence.
