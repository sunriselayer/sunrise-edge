# Offline Standard Asset genesis protected author validation

Date: 2026-11-04, Asia/Singapore. This is development evidence for the
genesis-only two-stage review and distinct-UID worker in [DR-0286](../../../architecture/decisions/0286-standard-asset-genesis-protected-review-worker.md).
It is not production custody or release acceptance.

## Source and build

- Base HEAD: `049dcd590de27dcb3020ba109ddfca1555af0f01` on the isolated
  `codex/m2-genesis-author-worker-1104` branch. The frozen nine-file code,
  test and architecture diff had combined SHA-256
  `aea8c06ec5a15cfaef238ca6935c1e5848a12b2c08b3aec86552beacccad783c`
  (SHA-256 of ordered `sha256sum` lines). The test controller checked the
  same source hash and exact nine-entry `git status --porcelain -z` before and
  after both test processes.
- `cargo fmt --all --check` and `git diff --check` passed. The initial targeted
  binary `cargo check` passed before the final test/display edits; its scope is
  identified in
  `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-genesis-check-1104-1-receipt.md`.
- Final-source `cargo +1.97.1 test --locked --offline -p sunrise-edge-operator
  --test standard_asset_genesis --no-run` passed in a detached, finite user
  service. The exact command, invocation ID, terminal exit, log hash, test ELF
  hash and cgroup release are in
  `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-genesis-test-build-1104-1-receipt.md`.
  It used a dedicated Cargo home and target, one build job, 4GiB memory cap,
  no swap and 200% CPU cap. Target size was 10,612,831,059 bytes at terminal,
  below the 20GiB guard.

## Actual process tests

The pinned controller
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/run-m2-genesis-tests-1104-v2.py`
(SHA-256 `cae255990779f925965b5e5c8bcf78f40d5933b4c2fe2f997041ce4dd82d140f`)
ran once against the same compiled test ELF. Its raw terminal record is
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-genesis-tests-1104-v2/terminal.json`
(SHA-256 `03be49a465640ef56848a7400b37123cf9ab8f29c2afbbc6026539671aa92e3c`).
The private controller log has SHA-256
`3e6d9c99bd3a11b667583e0fc13b58fe990f57ede26183c95513cd1161fc68a0`.

- The ordinary existing owner: 7 passed, 0 failed, 1 ignored. Raw stdout
  SHA-256 `bca4ab7c3c0be44cb292cef7f4710d124a2fc64fb390268cc7018cd6c5735da8`.
- The exact ignored protected selector
  `protected_author_reviews_three_exact_frames_and_installs_four_validator_pairs`:
  1 passed, 0 failed. Raw stdout SHA-256
  `6cea1a2a167c5e3c46cb5ffafbf74cdf314c7afa707b0a3fbef88c7b78095191`.
  It used disposable worker UID 10001 and reviewer UID 10002, checked the
  socket owner/mode and reviewer key inaccessibility, wrong peer/key and
  changed reviewer UID, changed origin/committee/allocation, expired and
  revoked approval, restart, exact ordinary-author byte equivalence, and a
  real signed manifest installed and preflighted for all four independent
  original validator pairs.

Both Docker runs had exit 0, actual stdout/stderr EOF, completed wait/reap,
captured owned container IDs and live PID/cgroup identities, and confirmed
container/PID/cgroup release. The source and four compiled ELF hashes were
unchanged afterward. The pinned local Python image ran with no network,
read-only source and compiled-binary mounts, a fresh writable `/tmp`, two CPUs,
4GiB memory and no swap. The controller unit was collected with main PID 0 and
its cgroup released. No failure was retried.

## Remaining qualification

The repository-wide literal `npm ci` and complete required check, hosted CI,
real approver and recovery-holder assignment, approved code/economic policy
provenance, real key ceremony and production host-user configuration are not
established by this component test. This record does not close parent M2 or
grant network activation.
