# M7 known release execution issues (2026-11-08)

This is a bounded, partial non-security reconciliation of already executed Native
release and required-gate records. It is not the independent final source,
security, or release review. [M7 in TODO](../../../../TODO.md#m7-再現可能なsupported-runtime-releaseを作る)
owns the current status; the [original M7 criteria](../../history/todo-before-reconstruction-2026-10-13.md)
and [release handoff boundary](../../../architecture/native-release-handoff.md)
remain unchanged. No command or fixture was run for this record.

## Historical failures and partial results

| Source/profile | Observation | Disposition |
| --- | --- | --- |
| `a6ae6229` post-#349 Native RELEASE preparation | First driver-build owner returned `passed=false`; the first `--list` owner also returned `passed=false`. Initial runtime-check raised `TypeError`; initial runtime-probe failed because its private `probe-tmp` was missing. | Keep each failed outer receipt and its monitoring gap as failed. Later successful stages below qualify their own executions on the same source; they do not change these verdicts. [TODO](../../../../TODO.md) records the receipt hashes and exact gaps. |
| `81bde20fc42acbbf7084c1d2eaf715fbe0a14cda` / local required | `npm ci` exited 0, but `./scripts/check-all.sh` exited 101 after the seven-epoch e8 `pack-saved` reached `recovery_budget_refusal=observations`, including the shallow `/tmp` retry. | Local full required **failed on this exact head**. The final controller receipt is SHA-256 `949c7cce3adb2ca8127b34562c28eba06a7c0144d3c9676e6252a04908a6c610`. CI on this head and RELEASE runtime on earlier `a6ae6229` do not replace the failed local gate. |
| Earlier M7 sources and attempts | E20 lacked a confirmed local terminal result; E47/E57/E61/E65 and the later interrupted or guard-rejected attempts remain as recorded in [TODO](../../../../TODO.md). | Preserve their original source, profile, and outcome. Later source success is not an exact-source retry result for any of them. |

## Later successful executions, with their own source pins

| Source/profile | Verified result | Limit |
| --- | --- | --- |
| `a6ae6229` / post-#349 Native RELEASE | The revised driver-list, runtime-check, and runtime-probe owners passed on their separate invocations. The original 12 runtime cases then exited 0 (105 passed, 0 failed, 4 ignored), with EOF/wait/reap and owned resource release. Runtime outer receipt SHA-256: `0397cddf1962d9b196bbe0dd9b9ef5bc1119c76c43f3054f690463cc389e8b80`. | Qualifies those exact saved RELEASE artifacts and original selectors on `a6ae6229` only. The earlier failed outer receipts remain failed. |
| `9981690a414ea0b6cc083c84e778d802ae04fae9` / local required | In the guarded direct-`/tmp` invocation, literal `npm ci --prefix adapters/cloudflare-workers` and `./scripts/check-all.sh` both exited and waited 0. Both raw streams reached EOF without truncation; the seven-epoch e8 `pack-saved` succeeded. Source/tree stayed clean and owned PIDs/cgroup were released. Controller receipt SHA-256: `3c27709c39a0f2897da25332ed1af0cbc3b4ed46616037fd8f37c6e9e20a13e1`. All eight hosted checks succeeded on this head. | This qualifies the `9981690a` local/CI run, not the failed `81bde20f` local run. PR [#350](https://github.com/sunriselayer/sunrise-edge/pull/350) merged as `7b8e777725a33e6966a8940219cfe3eceb0258ed` with the same tree `d26359fc05e7a5e9438433057a1b6ae41bde0549`. |

The local receipts and raw streams above are retained below
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/` in
`post349-original12-outer-*-a6ae6229-1107/`,
`pr350-shallowtmp-retry-inert-1107/runs/`, and
`pr350-direct-tmp-retry-inert-1108/runs/`. Their hashes identify the exact
terminal records; this summary does not promote a liveness observation, a
partial step, or a different source to success.

## 2026-11-11 exact-source follow-up

Combined dependency PR [#364](https://github.com/sunriselayer/sunrise-edge/pull/364)
merged as `2415dbec19c5cb10885820e7daa626cd4b24dec1` with tree
`2a0a2f091cc6baa692417bb9c32840f692a42b4f`. Its exact PR head has
successful literal `npm ci --prefix adapters/cloudflare-workers` and complete
local required checks, all eight ordinary CI
checks, and the five PostgreSQL lanes plus aggregate. On the merged head/tree,
the second fresh Native13 A/B attempt built all 13 targets twice and found all
13 pairs byte-equal. The first Native attempt failed before build A and remains
failed.

The first original12 driver-build owner failed its post-build hard-link-count
assumption, despite both Cargo invocations exiting 0. Its result remains
failed. A separately reviewed v2 post-build validator qualified the 13 debug
hosts and ten test drivers; all 22 original inventory invocations then passed.
Bounded check and probe stages passed before the original ten whole and two
exact ignored RELEASE selections ran. All 12 selections exited 0 with actual
EOF/wait (105 passed, 0 failed, 4 ignored). The executed selector covered seven
recurring epoch start/end pairs, terminal epoch 8, two distinct 1,832-byte
withdrawal candidates and both committed acknowledgments. It asserts eight
links; its recovery helper checks `3 + 4 × 8 = 35` roles. These two counts are
test assertions, not separately printed raw counts. Source and all 36 bound
RELEASE/debug/test ELF hashes matched before and after; owned temporary data,
known PIDs and the service cgroup were released. The independent non-security
review found no additional source/runtime defect on this exact tree. The
bounded root receipt is SHA-256
`6f8fd2ace5740d9c0cc5ec941112294f7e28783fa09ee7958b555b0eee344bef`
at `/home/yu/Desktop/SunriseEdge/validation-tmp/m7-issue-disposition-prep-1111/h-root-verification.json`;
the inner/outer runtime receipts are SHA-256 `2146fe4c902fc6b0a59affd4f898b0ace86aef353e85be0a7d807c88484e4375`
and `2c8d558d8919d0833c682c531cd3b768eb124259ca7b53ea2be8864e458aec66`.
The ignored real-UID protected-author fixture was not qualified by this run.

The CLI capability row in the release handoff was stale on `2415dbec` and is
corrected in the later documentation tree. The Native/RELEASE result above
belongs only to `2415dbec`/`2a0a2f09`; it does not qualify that later tree.
The independent security review remains stopped, so M7 remains unchecked and
this record authorizes no release.

## Still unresolved

The independent final security/release approval remains open. M2
protected-signing coverage, M3 selected-profile fault coverage, and the
human-selected public operation conditions remain separate TODO rows. This
reconciliation closes no M7 checkbox and authorizes no deployment or release.
