# DR-0274: Certified stopped same-identity key recovery

Date: 2026-10-19, Asia/Singapore

Status: Implementation design. Owning execution qualification belongs in TODO.

Extend the existing DR-0268/DR-0271 disposable certified multi-UID fixture at its
first worker downtime, before fence3. Preserve all original39 controls,27 probe
phases,32 row-oracle exchanges and their original request/resource/deadline and
complete-output caps. Two closed helpers add two controls and bring the expected
role-child count from147 to149, within the existing160-child cap.

All four original certified workers must first drain, exit0, reach both physical
stdout/stderr EOFs and be waited. Require their original PIDs and sockets absent
before any key-copy helper starts; the worker-UID helper independently checks
those absences before opening a seed. With CapEff0 and no supplementary groups,
only this helper reads each existing32-byte seed, writes a0600 backup and a
different0600 restored file inside a new worker-owned0700 directory, compares
the copied bytes internally and removes the original `validator.key` path.
Use exclusive no-follow file creation, exact owner/group/mode/single-link checks
and bounded complete reads/writes. No seed or seed digest is returned to the
controller or frontend.

Create new worker-owned0600 certified and original ordered configuration files.
Their bytes must differ from their existing role-owned originals only in the
`signing-key-file` line, which selects the restored path. Keep the same public
validator identities, genesis pins and exact retained source/body/independent
anchor paths. Each later worker generation must recheck original-key absence,
private metadata and the exact config substitution before startup; recheck them
after final shutdown. A separate capability-free frontend/operator-UID helper,
including its original supplementary socket group, must receive EACCES opening
all four restored seeds and backups.

Continue the unchanged real protocol sequence with these restored paths at
fences3,4,5,6. Existing A saved vote/ACK byte equality, fresh paid B, original
ordered three-chain Freeze, actual frozen-frontier signatures, complete page
verification and fence6 retained replay retain their original core/SDK checks.
The existing whole source/body/anchor image equality check spans downtime and
key recovery. No state or anchor image is copied, replaced or rolled back.

Record the actual recovery/refusal helper PIDs, UID/capability markers, waits,
EOFs and all five worker generations with their selected config/key paths. The
Node owner requires the corresponding receipts without relaxing the existing
exact build-receipt HEAD/tree/sourceFiles guard. Changed controller source needs
fresh matching compiler provenance or a separately admitted exact non-Rust
bridge; old compiler receipts are never relabeled as new-source builds.

This selects same-identity recovery for known disposable keys under a trusted
local OS. It adds no production recovery command, new identity, key/membership
rotation, successor or positive DrainSet/member application. It makes no
database/anchor rollback, off-host backup, guest-VM, compromised-worker/root,
real-key ceremony, public-service, independent-audit or whole-M2 claim. Stopped
security-audit and ZeroShare tasks remain outside this slice. Source/syntax
qualification is separate from the actual owning runtime and final repository
required/hosted/release gates.
