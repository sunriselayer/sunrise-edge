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

## Still unresolved

The independent final source/security/release review and complete final issue
disposition remain open. M2 protected-signing coverage, M3 selected-profile
fault coverage, and the human-selected public operation conditions remain
separate TODO rows. This reconciliation closes no M7 checkbox and authorizes
no deployment or release.
