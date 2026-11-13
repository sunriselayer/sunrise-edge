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

## Disconnected-review follow-up

After PR #348 merged, commit `823671df` added disconnected-review refusals
to the same ignored protected selector. Closing reviewer stdin after the
nested preview must leave no retained approval or manifest. Closing stdin
after the outer manifest preview must leave the existing nested approval
unchanged and publish no manifest. The original positive review and four
validator installations remain in the selector. This follow-up initially had
Rust 1.97.1 format-check coverage only. Its current-source real-UID runtime
result is recorded below; complete required and hosted qualification remain
separate.
The 2026-11-04 results above apply only to their earlier source.

## Current-source follow-up (2026-11-13)

The selected clean source was commit
`894e58817945b602fea97073bcee0c7f640c2955`, tree
`72b23957fd8fcfaf19bcd288600be039384e024e`. The original ordered nine-file
source digest was recomputed as
`238153dde1deddd4382a02e82c83629651584ef5f9e8df342cbbeed399da3565`.
HEAD, tree, the nine-file digest and clean worktree status were unchanged
before and after both processes. This result supplies the disconnected-review
runtime delta for this source only.

The [build request](raw/current-894e5881/build-request.json) records the exact
Rust 1.97.1 offline/locked Cargo argv and environment, one build job, dedicated
target, 4GiB/no-swap/200%-CPU build service and finite 1800-second limit.
[Execution bindings](raw/current-894e5881/controller-bindings.json) retain the
Cargo receipt hash, exact four executable paths/hashes and default optimization
level 1 with debug assertions and overflow checks, plus the canonical four-file
dynamic-library/interpreter closure and guest mount targets.

The preserved original controller above was rebound only to the selected
source and artifacts, current library paths, fresh owned names/output,
clean HEAD/tree checks and the explicit `unix:///var/run/docker.sock`
endpoint. The [exact adaptation](raw/current-894e5881/controller-adaptation.diff.gz)
is retained. Its private path is
`/home/yu/Desktop/SunriseEdge/validation-tmp/m2-genesis-disconnect-1113/controller-current.py`,
SHA-256 `eda519f9cd4a9ccbea77e8aec0047dfb6e9581e7c16f56c89e290d03121d1f46`.
Original selectors, source/test assertions and controller capture/cleanup
semantics were retained. The controller and original 2026-11-04 evidence
remain separate immutable inputs; no controller helper was added to product code.

The [raw terminal record](raw/current-894e5881/terminal.json) contains both
complete Docker argv lists, all source/artifact pins, actual exits, raw stream
sizes/hashes, EOF, waits and resource identities. It reports:

- Ordinary owner: **7 passed / 0 failed / 1 ignored**, exit 0;
  [stdout](raw/current-894e5881/sunrise-m2-genesis-1113-v1-ordinary.stdout.gz),
  [stderr](raw/current-894e5881/sunrise-m2-genesis-1113-v1-ordinary.stderr).
- Protected exact ignored owner: **1 passed / 0 failed / 0 ignored**, exit 0,
  with `genesis_protected_review_disconnects=both_refused`;
  [stdout](raw/current-894e5881/sunrise-m2-genesis-1113-v1-protected.stdout.gz),
  [stderr](raw/current-894e5881/sunrise-m2-genesis-1113-v1-protected.stderr).

Stdout and the adaptation diff use lossless gzip to preserve original terminal
whitespace and diff context lines. Decompression was checked against stdout's
uncompressed byte counts/hashes in the terminal record and the diff hash in
the bindings JSON. Stderr and the linked JSON inputs are copied byte-for-byte.
Controller terminal exit was 0 in 2.798658417 seconds; both
runs have complete stdout/stderr EOF, `waitReaped: true`, `released: true`,
no timeout and no stream-cap refusal. The original positive two-stage review,
ordinary-author byte equality and four independent validator-pair installations
remain assertions of the same protected owner.

Both containers used the same pinned image digest as above, two CPUs,
4GiB memory with no swap, PIDs256, 2GiB executable `/tmp`, no network,
read-only source/binary/library mounts and no-new-privileges. The original
1200-second per-process, 2700-second total, 32MiB-per-stream and source/target
space bounds were unchanged. Worker UID10001 and reviewer UID10002 remained
disposable container-local identities; no real keys or host users were enrolled.

[Parent verification](raw/current-894e5881/verification.json) records unchanged
four-ELF/four-library hashes, matching raw hashes and the current-source checks.
A fresh Docker query found no containers bearing this run's ownership label.
Both build/runtime units were absent/inactive with MainPID0, and the dedicated
target was removed. Exact container IDs, PID-start/cgroup identities and release
results remain in the terminal record. Small private build/runtime metadata are
retained under `/home/yu/Desktop/SunriseEdge/validation-tmp/m2-genesis-disconnect-1113/`.

## Remaining qualification

The repository-wide literal `npm ci` and complete required check, hosted CI,
real approver and recovery-holder assignment, approved code/economic policy
provenance, real key ceremony and production host-user configuration are not
established by this component test. This record does not close parent M2 or
grant network activation.
Results do not qualify a later documentation head or a different release
source by inheritance.
