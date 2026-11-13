# M2 original bond: real SQLite host and protected signing

2026-11-12 (Asia/Singapore). The first focused owner ran on commit
`b2087f0d679160346e302791fcbf15dee1c9a2c0`, tree
`36786d2e238078943fe938ea3939d26fd58bfc64`. The corrected owner ran on
`3b05f2d2d589fe2d6c9e7142ead2347b20e390b9`, tree
`61997755894c0a43e234dabd43033d9d971be0eb`. Its runtime/test/script paths
were cherry-picked unchanged into the current PR branch. This record qualifies
only the bounded original-genesis bond component, not M2 release acceptance.

The existing standalone `bond_registration` owner now starts `sqlite_genesis`
and `sqlite_source_host` with the same original-genesis manifest and Coin used
for the protected inner transfer and outer validator registration. It checks
the two distinct content approvers and key workers, exact signed bytes, and
rejection of an old writer fence after the host stops and restarts. The
node-core ordered handoff uses a Coin created by a later paid split; its
currentness response remains the existing fixed fixture, with its protected
approval, byte, and refusal checks retained. No real-host result is claimed
for that post-genesis Coin. CI pins the two additional operator binaries by
path and SHA-256 without relaxing the original selectors.

## Executed checks

- Built `sunrise-edge-cli` with all features, the `sqlite_genesis` and
  `sqlite_source_host` operator binaries, and the `bond_registration` harness
  in a dedicated Cargo target. All builds exited 0. The selected eight
  executable paths and hashes are in [pins-v2](raw/pins-v2).
- The first focused test failed before binding the real host socket because
  its 0600 config file was under the shared 0750 socket directory. The config
  was moved to a nested host-owned 0700 directory. The [failed stdout](raw/bond-test.stdout)
  and [stderr](raw/bond-test.stderr) remain visible.
- On committed source `b2087f0d`, the owning
  `protected_original_bond_uses_two_distinct_approvers_and_workers` test
  exited 0: **1 passed, 0 failed, 15 filtered**, in 11.13 seconds. The
  [stdout](raw/bond-test-committed.stdout) and [stderr](raw/bond-test-committed.stderr)
  are preserved verbatim.
- Node 24.19.0 `scripts/test-ci-gates.mjs` exited 0; its
  [output](raw/ci-gates-test.stdout) confirms the seven required lanes and
  preserved recurring selectors.
- The first run's test-owned fixture and dedicated Cargo target were removed after the
  process check found no owned test processes. The small raw receipts remain.

## CI failure and focused correction

At PR head `08e5a10c`, the [rust-tests job](https://github.com/sunriselayer/sunrise-edge/actions/runs/43132587963/job/130900262414)
failed in the unchanged node-core registration selector: the real host's
development genesis key did not match that fixture's registered validator.
The full job log was saved privately at
`/home/yu/Desktop/SunriseEdge/validation-tmp/pr368-ci-failure-1112/rust-tests-08e5.log`
(SHA-256 `8b0a33652290cc28781661167096db874389bb28c33a7f33f5555778d25938b4`).
The subsequent local attempts also exposed that the node-core paid-split Coin
is absent from a genesis-only SQLite store. Their [first](raw/node-core-handoff.stdout)
and [second](raw/node-core-handoff-v2.stdout) stdout and matching stderr files
remain raw failures.

The final test fixture selects the registered validator by its seed-derived ID
and uses the real source host only for the standalone genesis Coin. On exact
`3b05f2d2` source, the [standalone owner](raw/cli-owner-v3.stdout) and the
[node-core handoff](raw/node-core-handoff-v3.stdout) each exited 0 with
**1 passed, 0 failed**. Their stderr and exit-code files, and the
[eight artifact pins](raw/pins-v3), are preserved beside those outputs. These
focused successes do not turn the failed CI run into a pass; the next exact
PR-head CI is required before merging.

The final focused commands, run from the isolated `3b05f2d2` worktree, were:

```sh
bash -c 'set -a; . /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/pins-v3; set +a; exec timeout -k 30s 600s "$SUNRISE_BOND_ORDERED_HARNESS" --exact protected_original_bond_uses_two_distinct_approvers_and_workers --nocapture' > /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/cli-owner-v3.stdout 2> /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/cli-owner-v3.stderr
bash -c 'set -a; . /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/pins-v3; set +a; export CARGO_TARGET_DIR=/home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/target CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0; exec timeout -k 30s 900s cargo test -p node-core --lib --all-features ordered_economics::tests::causal_placement::registration::initial_registration_distinct_source_and_validator_keys_order_effects -- --exact --nocapture' > /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/node-core-handoff-v3.stdout 2> /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-handoff-fixture-1112/node-core-handoff-v3.stderr
```

Both shell exit codes were observed as 0. The earlier failed temporary
fixtures were copied to a private `failed-handoff-raw` directory with matching
hashes, then removed. The successful fixture self-cleaned, and the process
check found no owned host, CLI, harness, or target process. The v3 dedicated
target (~4 GiB) is retained until the PR CI result is known; it is not a test
success predicate.

The PR's exact-head hosted CI and local complete profile were not part of this
focused run. Actual authority/key enrollment, successor live-epoch collateral,
and parent M2/M7 release qualification remain open.

The successful command, from the isolated bond worktree, was:

```sh
bash -c 'set -a; . /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-realhost-1112-focused/pins-v2; set +a; exec timeout -k 30s 600s "$SUNRISE_BOND_ORDERED_HARNESS" --exact protected_original_bond_uses_two_distinct_approvers_and_workers --nocapture' > /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-realhost-1112-focused/bond-test-committed.stdout 2> /home/yu/Desktop/SunriseEdge/validation-tmp/m2-bond-realhost-1112-focused/bond-test-committed.stderr
```

The CLI/operator binaries and rebuilt harness were produced before the
`b2087f0d` commit; no source edits occurred between the harness build and that
commit. The test was rerun after the commit using those pinned bytes. No
post-commit rebuild is claimed. The fixture deletion, absence of matching
processes and temporary directories, and removal of the dedicated target were
observed after the test; the build JSON and cleanup details remain in the
private external evidence directory named above.
