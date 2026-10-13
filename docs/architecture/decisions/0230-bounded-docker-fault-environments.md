# DR-0230: bounded Docker fault environments

Date: 2026-10-12. Time zone: Asia/Tokyo.

Status: Selected local environment design. Implemented-source review and actual
execution are separate obligations, not satisfied by this decision.

## Context and scope

[DR-0208](0208-native-sqlite-first-and-protected-signing.md) records the human's
permission for disposable Docker PostgreSQL and isolated full-filesystem/
forced-stop experiments. The PC previously exhausted storage; filling its
filesystem, changing host swap/security/resource settings, privileged devices,
foreign workloads and production data are not part of these experiments.

## Decision

Use only explicitly pinned, already-cached images and `--pull=never`. Give every
container and local-driver volume a fresh owner label and unpredictable name.
No host/source/cache/Docker-socket binds, image acquisition or build fallback.
Require effective configuration, kernel/filesystem observations and complete
subprocess termination; requested flags alone are not capability evidence.

The general capability probe uses a fresh 8MiB local-driver tmpfs with literal
`noswap`, 64MiB container memory and zero allowed swap. Actual bounded writes
must produce errno28; then only the identity-held filler is removed. The managed
volume route is explicit, not a fallback that weakens the mount options.

The PostgreSQL ENV probe uses one fresh 512MiB tmpfs with literal `noswap` and
16,384 inodes. A finite, read-only Python keeper preserves its mount while the
database process is killed. A short initializer creates only `socket/` and
`tmp/`. PostgreSQL18 keeps its default `18/docker` data subtree and mounts only
the socket subtree at its default socket path; all mounts use no-copy.

All containers have read-only roots, private IPC without the dedicated
`/dev/shm` mount, network none, dropped capabilities, no-new-privileges, explicit
seccomp, no restart and no logs. Keeper/initializer are each limited to 64MiB,
0.25 CPU and 32 PIDs; the primary to 512MiB, one CPU and 128 PIDs. Equal Docker
memory/memory-swap values and effective cgroup checks prohibit container swap.
These are per-container limits, not an aggregate host-memory reservation.
Docker-managed system mounts still exist: this is not a sole-writable-system-
allocation guarantee. The tmpfs capacity, not the WAL soft threshold, is the
hard data-storage ceiling.

Set each selected PostgreSQL setting separately both during `initdb` and final
startup. Main shared memory uses anonymous mmap; dynamic mmap files stay inside
the bounded PGDATA. No host transparent-huge-page change or sync disabling.
Before baseline SQL or SIGKILL, independently require PID1 to be the exact final
PostgreSQL executable/argument vector. The entrypoint's temporary bootstrap
server is not final readiness.

Use a fixed singleton SQL fixture, complete literal comparison, cluster identity,
effective settings and integer postmaster-start time. Kill and restart the same
exact primary container; require a later start time, retained cluster/fixture
and uninterrupted keeper identity. Do not retry an ambiguous fixture write.

The PG experiment has one 90-second deadline, 30 seconds reserved for cleanup,
and 64KiB aggregate captured evidence including a cleanup reserve. The general
probe retains its separate 45-second/64KiB limits. Overflow, missing EOF,
unreaped clients, OOM, changed identity and unresolved release fail. Remove only
verified owned primary/initializer containers before keeper, then the exact
volume, without force/prune. Report residue rather than silently widening bounds.

## Acceptance boundary

These probes establish only their observed Docker ENV capabilities. They do not
run the Rust SQLite/PostgreSQL suite, the existing fresh-client PG crash guard,
host-URL checks or complete repository validation. They neither reconstruct
missing dependencies/private inputs nor grant ONE/runtime authority.
Tmpfs process-retention evidence is not physical-disk, power-loss, custody,
release or mainnet readiness. Existing source/code/PG/fault/independent-review
completion gates remain in [TODO.md](../../../TODO.md), with launch choices
kept separate.

## 2026-10-12: observed environment-only results

The [general probe](../../../scripts/check-docker-fault-environment.mjs), selected
explicitly with `--managed-volume`, observed positive bounded writes ending in
errno28 inside its 8MiB noswap allocation, removed its filler and released its
owned container/volume. This did not execute the Rust SQLite fault controls.

The [PostgreSQL probe](../../../scripts/check-docker-postgres-environment.mjs)
at source SHA-256 `b751fb1eefe192c745c0169f14ba08d7b92cdc8dfd26bd5794790e198bc24d35`
completed with direct exit0. It observed SIGKILL exit137 and a later postmaster
start in the same exact container, the same cluster identity and complete literal
singleton fixture, and unchanged keeper identity. Effective storage was 512MiB
noswap with 16,384 inodes; the primary had 512MiB memory and zero allowed swap.
Its 29,917 captured bytes plus the complete 799-byte final line total 30,716 bytes
under the unchanged 64KiB bound. Root independently observed the exact owner and
the whole PG ENV label namespace empty after release; neither container nor
volume residue remained. No full raw Docker transcript was exported or reviewed
independently; terminal source guards and the observed final result are distinct.

The fixed SQL selector reads mountinfo once with an overflow byte, checks complete
input framing and retains every complete row for both selected mounts and
`/dev/shm`, including duplicates. Versioned byte/count/ordinal framing and the
original attachment/flag/inode checks remain. Unselected mount bodies are not
retained. Oversize or malformed input, duplicate/missing mounts, unexpected shm,
wrong attachment and malformed subset are reviewed source refusal expectations,
not separately executed adversarial controls.

Earlier probe failures remain failures, not historical passes. These observations
do not run the product's PG/SQLite suites or establish physical-disk/power-loss,
custody, full-profile, M3/TODO20 or release qualification. Do not rerun a consumed
successful probe as a substitute for the remaining product-owned verification.

## 2026-10-13: product-owned blob-publication fault boundary

The original four SQLite fault controls prepublish both known blobs and fault
the structured commit. A fifth control instead starts with only the unrelated
blob and invokes the ordinary public `put_blob` once while the same bounded
Docker filesystem has observed errno28. Its target remains absent; the full
physical blob tables and all twelve structured tables/four portable collections
must remain equal before release, after release and after existing-only reopen.
Both public blob owners verify complete descriptor/chunk/hash/codec closure.

An added SQLite-owned maintenance connection checkpoints the actual blob WAL
to the full `(0,0,0)` result and verifies zero WAL length/blocks before filling.
A DISTINCT absent digest then probes a raw INSERT on that same blob database,
requiring actual `SQLITE_FULL` and checked rollback/autocommit. This is not the
hidden raw cause or statement of the public `put_blob` error. The held filler
observes errno28 again after each operation: restored exhaustion is not a claim
of uninterrupted fullness inside SQLite. Sidecar observers and maintenance
owners close before original blob owners' last-close; main inodes remain bound.

One authorized successful blob retry after release may add exactly the target
body. Duplicate publication is idempotent and every structured field must stay
unchanged. No structured commit, fresh production hook or dependency is added.
The original four case bodies remain; their stronger shared blob observer also
needs fresh execution. The exact new executable must be rebuilt and rebound
before the five-case runner is used. Source/format review alone is not execution,
cross-file atomicity, power/fsync/storage-media, custody or complete M3 acceptance.
