# M2 N1/N2 current-source UID evidence (2026-11-12)

The frozen test source is commit `6801bca323bdd2a986d76ad5152b5ab1c6c389a9`,
tree `d9b20c67b62439c4f79568dc7f6b4e3478d619d0`. It adds the two
tracking checkboxes to `TODO.md` without changing runtime code. The tested
operator binaries, CLI and `conditional_readiness_sqlite` harness came from
offline, locked Cargo JSON builds on this clean commit. The existing
`scripts/check-docker-readiness-fixture-1103.mjs` controller checked their
exact executable paths and hashes, the pinned Docker image, and the source
commit before execution. Node 24.19.0 ran the controller.

## N1 readiness: passed

The `readiness` profile ran the existing ignored owner
`compiled_conditional_readiness_real_retention_restart_and_distinct_certificate`
with the opt-in worker/frontend distinct-UID fixture. Limits were 900 seconds,
4096 MiB tmpfs, 6144 MiB memory, two CPUs and 128 PIDs; the container had no
network and no added host users. The [raw receipt](raw/readiness-6801bca.json)
records exit code 0, no signal or abort, one passed test, and owned-container
cleanup as `already-removed`. [stdout](raw/readiness-6801bca.stdout) and
[stderr](raw/readiness-6801bca.stderr) are preserved unchanged. No labelled
fixture container remained after the run.

## N2 successor: pending

The separate `recurring` profile started from the same frozen commit with the
original seven-epoch/e8 owner. Its result and resource release must be checked
before the N2 tracking box can be marked complete.

These are component-specific UID results. They do not close parent M2, change
the original release gate, or qualify a later source tree by inheritance.
