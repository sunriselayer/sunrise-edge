# M2 N1/N2 current-source UID evidence (2026-11-12)

The N1 frozen test source is commit `6801bca323bdd2a986d76ad5152b5ab1c6c389a9`,
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

## N2 successor: passed (2026-11-13)

The completed N2 source is commit `abccadfd9bd1ffa960a60ca7efc9dbc315e3d1ae`,
tree `5f874da90dcdba4e98dd7db5de6a96004ab58789`. The existing `recurring`
profile selected the original ignored owner
`compiled_registered_replacement_and_recurring_successor_hosts` with
`SUNRISE_SUCCESSOR_MULTIUID_FIXTURE=1`. Exact discovery found one test.

The offline, locked operator/CLI/harness builds used Rust 1.97.1 and the
unchanged default optimization level 1, debug assertions and overflow checks.
Node 24.19.0 ran the unchanged controller with its existing finite profile:
6144 MiB tmpfs, 8192 MiB memory, two CPUs, 128 PIDs and a 21600-second outer
limit. The Docker image digest remained pinned. Source and protocol/runtime
code, selectors, epochs, refusal/recovery assertions and recovery quotas were
unchanged. Missing locked registry inputs were fetched with `cargo fetch --locked`
after the first offline build refused a missing cached `sha3` package; that
initial build is not counted as successful.

Execution ran from **2026-11-13 15:38:25.709 to 19:03:01.039 Asia/Singapore**.
The [raw receipt](raw/recurring-abccadfd.json),
[stdout](raw/recurring-abccadfd.stdout.gz) and
[stderr](raw/recurring-abccadfd.stderr) record controller/runtime exit 0,
no signal or abort, **1 passed / 0 failed / 0 ignored / 21 filtered** in
12275.05 seconds. Stdout archives use lossless gzip to preserve the original
terminal whitespace; their uncompressed sizes and SHA-256 values are recorded
in the verification JSON. The logs retain `successor_protected=distinct-uid`, all seven
recurring epochs and activation into e8, both original 1832-byte withdrawal
candidates with committed acknowledgements, and successful terminal recovery.
The passed owner retains its eight-link/35-role cold saved-closure assertions.

The [post-run verification](raw/recurring-abccadfd-verification.json) records
the exact build/controller argv, environment, compiler/Node versions and
cleanup observations. All eleven selected executable hashes were unchanged
before cache removal. The controller recorded `cleanup: already-removed`;
a fresh Docker query found zero labelled fixture containers and exact
inspection found this run's name and ID absent. The transient user unit was
absent/inactive with MainPID 0, no matching host fixture process remained, and
the dedicated target was removed. Temporary fixture data and disposable users
were container-local. Small private build receipts and run metadata remain at
`/home/yu/Desktop/SunriseEdge/validation-tmp/m2-n2-1113/`.

The previous same-source 4096 MiB tmpfs / 6144 MiB memory attempt remains a
failure: [receipt](raw/recurring-abccadfd-failed.json),
[stdout](raw/recurring-abccadfd-failed.stdout.gz) and
[stderr](raw/recurring-abccadfd-failed.stderr) preserve exit 101 and
`open-saved: recovery quota refused` after the seven-epoch/e8 work. The failed
run did not record physical free space, so this success does not establish
its unique quota-refusal cause. The 1 GiB output-headroom guard and all SDK
quotas remain intact. Earlier interrupted/preflight attempts remain in the
private `m2-current-source-uid-1112` evidence directory described in PR #368;
none is reclassified as a pass.

These are component-specific UID results. They do not close parent M2, change
the original release gate, or qualify a later source tree by inheritance.
The local complete profile and final security/release review were not run for
this component check. Subsequent documentation-head CI is separate evidence.
