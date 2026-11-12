# M2 original bond: real SQLite host and protected signing

2026-11-12 (Asia/Singapore). The focused owner ran on commit
`b2087f0d679160346e302791fcbf15dee1c9a2c0`, tree
`36786d2e238078943fe938ea3939d26fd58bfc64`. Its runtime/test/script paths
were cherry-picked unchanged into the current PR branch. This record qualifies
only the bounded original-genesis bond component, not M2 release acceptance.

The existing `bond_registration` owner now starts `sqlite_genesis` and
`sqlite_source_host` with the same manifest and Coin used for the protected
inner transfer and outer validator registration. It checks the two distinct
content approvers and key workers, exact signed bytes, and rejection of an old
writer fence after the host stops and restarts. The fixed-response owner remains
for transport-negative cases. CI pins the two additional operator binaries by
path and SHA-256 without relaxing the original selector.

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
- The test-owned fixture and dedicated Cargo target were removed after the
  process check found no owned test processes. The small raw receipts remain.

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
