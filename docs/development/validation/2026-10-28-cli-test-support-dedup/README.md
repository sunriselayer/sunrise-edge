# CLI・SDK・operator test-support共通化の検証

Source `5ac947f3856d3abbfb39abbdcf3e713d328cb7b4` / tree
`10b53dc5c42b88086c56af24ef6403bcd846c827`。
BaseはPR #335 merge `55a787d8`。
[PR #336](https://github.com/sunriselayer/sunrise-edge/pull/336) はReady for review。

CLIの1回openとbounded read、SDKのtyped32 query hex、operatorのtest hex5コピー、
startup-refusalの既存ChildGuard再利用を実装し、commit/pushした。
caller別error型/文言、元cap算術と入力symlink扱い、context/404/selector検査、
spawn/pipes/20秒/10ms/final waitは保持した。新しいdependencyやpublic SDK APIはない。

通常の静的correctness reviewはblocking findingなし。
変更file内の既存74 test-function bodiesと436 assertion/matches occurrencesはbyte-identicalで、
CLI4 /SDK2の互換性controlsを追加した。guard定義と元Drop bodyもbyte-identical。

Focused checksは全6 commandが自然exit0。Rust12 summariesは315 passed /0 failed /2 ignored。
合計はhelper実行を含み、distinct test数ではない。元のignoredは未実行として残す。
rootが全12 raw streamsのbytes/hash、実両EOF/wait、既知command PID/process groups不在と
source diff/new filesのbefore/after一致を照合した。Rust1.97.1 fmt/diff checkも成功。

同sourceのliteral `npm ci --prefix adapters/cloudflare-workers` と完全 `./scripts/check-all.sh` は
2026-10-28 09:01:16 UTC (17:01:16 SGT) に開始した。全8 CI run40660945044も実行中。
完了は両方の実終端と終了後照合を待つ。4件全体はまだ完了扱いにしない。
PG実装・依存の変更とPG deploymentの主張は含まず、別PG profileを今回の実行に含めない。

既存checkout/target/cache、Node24.19.0、Rust1.97.1、Deno2.9.4、cfとretained wrappersを再利用した。
新しいworktree/cache/tool binary、直接Wrangler、automationは作成・実行していない。
full ownerは28200秒work +300秒cleanup、service上限を含め28800秒以内。
原requiredのselectors、timeouts、7epochs、e8 terminal unlockを変更していない。

元の85 checkbox /71完了 /14未完了とD02/M1/M2/M3/M7の親5件は保持する。
停止済み監査、ZeroShare、torn-WAL/mechanism2、独立anchor guestには着手しない。

## 保存先

Raw evidence root: `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`。

| 記録 | SHA256 |
| --- | --- |
| `maintenance-four-1028-root-targeted-qualified.json` | `16c71238819b0da1d2c86156d639061ca115c71e6f6ddbb77aa7cfa544be6ed3` |
| `maintenance-four-1028-static-review.json` | `ebb390894e484c4963d3712bafa3b554af761d96990d2bf5e6fd74b0beb26ff0` |
| `maintenance-four-1028-freeze-receipt.json` | `41dc88d8db41ead1a5181767ccda794ec0366dc2defb3e04c5835b59929d3c55` |
| `maintenance-four-1028-launch.json` | `993e99e19aef71a639277c805f74a239e81c4907543babb70128d4a2ab0954b4` |
