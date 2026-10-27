# Operator helperとSQLite inventoryの通常保守

Date: 2026-10-27 (Asia/Singapore)

Source: `a3fa4576f18f81b6d81e4dd7ebb5dd3f18c3b680`  
Tree: `99fb314dd9aaac5e38e11802136afbb305dfcc84`  
Base: `8da1d620cba7428672df086318b2df2d3cec5976`  
[Draft PR #333](https://github.com/sunriselayer/sunrise-edge/pull/333)

## 変更範囲

- FastVote PGのscalar、decimal hash-suite、schedule parserをoperator commonへ移した。
  literal-ID grammarは独立したまま、数値表記、診断と最初のerror、schedule順序と上限を保持した。
- 小文字hex表示の7実装を共通helperへまとめた。既存の独立した期待値は保持した。
- SQLite inventory fixtureがexporterのexact selectorとdiscovery/executionを所有する。
  CI dispatcherも同fixtureを呼び、二重のselector管理を解消した。
  standalone/CIの両入口で列挙0件、重複、列挙失敗、export失敗とcleanupを検証する。

実装commitは `3a2e3aa4` と `a3fa4576`。依存、Cargo profile、protocol、custody、
元のgate membership、selector、timeout、fault/workloadは変更していない。

## 検証

追加Rust互換性テストは8 passed / 0 failed / 0 ignored。
Node 24.19.0の `scripts/test-ci-gates.mjs` 全体、rustfmt、bash syntax、diff checkは成功。
通常の限定correctness reviewではblocking regressionを確認しなかった。

同sourceのliteral `npm ci --prefix adapters/cloudflare-workers` はactual exit 0。
`./scripts/check-all.sh`、既存の完全5-group PostgreSQL `profile`、
[全8 CI](https://github.com/sunriselayer/sunrise-edge/actions/runs/40447306260) は
実終端と終了後照合を待つ。部分結果を全体の成功へ加算しない。

local実行は既存source、target、cache、node_modulesを再利用し、専用の有限serviceで
単一ownerが順番に実行する。Node 24.19.0、Rust 1.97.1、Deno 2.9.4、
cf 1.0.0-beta.13を固定し、直接Wranglerを呼ばない。
worktree、compiler cache、tool binaryのコピーやglobal default変更は行っていない。

## 実行前の停止と保存

最初のCF wrapper preflightは、旧manifestのfilesystem device 43と実配置52の不一致で停止した。
製品検証の開始前であり、製品テスト失敗や成功へは数えない。
全2,347 body hashesと2,725 layout rowsを照合し、device以外のmetadata、link target、
resolved pathが一致した。system toolのdevice 37は変わっていない。

初回readerが全toolのdevice変更を要求した停止も含め、旧manifest、wrapper、失敗rawを保存した。
現在の配置に対応するmanifestへ固定し直し、wrapperのguard本体を保持した。
deviceが変化した原因はこの照合では確定していない。

ローカル証跡root:
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`

| 証跡 | SHA-256 |
| --- | --- |
| `maintenance-dedup-1027-source-index.json` | `4f726376a102fb0500ac3e01d2670aa9aef351ced5eaaa47718699caa1807e1c` |
| `maintenance-dedup-1027-owner.py` | `d9ed76c9e06f3d6a9fbb71342ae1cbc11bdf451fe348199fe59f22bc00dc6149` |
| `maintenance-dedup-1027-config.json` | `312e3090e6a778f3a238162c0cf75b103a80fa5114bf7e9e22acd1cc6e66be97` |
| `maintenance-dedup-1027-cf-closure-device52.json` | `8ceee07cbd07993a808edba96aba91d6974f1f1d8b9e823f27c19c886b86bd6c` |

## 元のTODOとの関係

今回の3件は通常保守であり、D02/M1/M2/M3/M7の親5件は未完了のまま。
停止済みの独立監査、ZeroShare、M3 torn-WAL/mechanism2、独立anchor VM boot修正は再開していない。
この保守変更について新しいNative/M7 RELEASE認定は主張しない。
main merge、deploy、実鍵、host user、security policy変更、定期タスク再作成は行っていない。
