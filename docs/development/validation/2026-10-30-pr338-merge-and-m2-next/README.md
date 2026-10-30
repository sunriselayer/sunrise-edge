# PR #338 mergeと次のM2候補

2026-10-30 (Asia/Singapore) の通常merge・既存実装対応の確認。
ユーザーはPR #338のmergeと、安全判定で停止した対象以外の次候補の提示を依頼した。
新規の製品実装・fixture実行・security監査は行っていない。

## Merge

[PR #338](https://github.com/sunriselayer/sunrise-edge/pull/338) はhead `76345c53` /base `5626863a`。
直前のReady /mergeState CLEAN /全9 checks successと、完全paginationの
reviews /issue comments /inline comments各0を確認し、expected-head guard付き通常mergeした。
通常gh認証を使い、PR作成専用PATは読んでいない。既知のconnector書込権限不足への再試行もしない。

実merge `9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09`、2026-10-30 10:44:20 SGT。
公式Git metadataとlocal Gitでtree `12e140c6b6e2a41c83149c64685fddc5192e7608`、ordered parents
`[5626863a563216af5c4bb78b4122bd7861498f09, 76345c539ea333b79bbd2ca4c2e54eb945ca00d9]` を照合した。
local mainはcleanを確認してfast-forwardした。製品sourceは前回検証済みtreeと一致する。
[元の実装・完全required・全8 CI記録](../2026-10-30-initial-recovered-application-key/README.md) を参照する。
mainの自動CIは別runであり、前回runへ付け替えたり結果を先取りしたりしない。

## 次に着手できる限定候補

1. **Foreign splitの同一A鍵復旧consumer**。
   [既存profile main](https://github.com/sunriselayer/sunrise-edge/blob/9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09/scripts/check-docker-custody-fixture-1013.mjs#L4528) は
   fresh A/Bを作って直ちにhandoffへ入り、[keys](https://github.com/sunriselayer/sunrise-edge/blob/9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09/scripts/check-docker-custody-fixture-1013.mjs#L4165) は両方元path。
   同じserving helperがAのlive splitと取消後restartへ渡す。既存UID copy helperでsigner前に
   同一A鍵を復旧し、そのpathをこの2consumerへ接続するのが具体的な次slice。
   [既存contract](https://github.com/sunriselayer/sunrise-edge/blob/9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09/docs/architecture/standard-asset-split-merge-custody.md#L159) の
   Bへの5M split・同一Coin返送、元21 predicates、全approval/frame/nonce/fee/receipt/replay/取消、
   元counter/上限は維持する。追加copy/process/file/capture余裕は、後の所有実行で検証が必要。
   これは既存recovery条件に沿うconsumer拡張候補であり、M2へ新しい必須完了条件を加えない。
   今回は未実装・未実行であり、将来の実行を安全判定済みと扱わない。
2. **署名入口とprotected backendの有限な対応表**。
   [prepared owners](https://github.com/sunriselayer/sunrise-edge/blob/9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09/docs/architecture/signing-preparation.md#L24) の
   6groupを、実consumer・受入済みbackend・lifecycle証跡へ対応付ける。
   generic local executionは `local_execution.rs:135`、generic paidは `paid_execution.rs:173` でcustodyを拒否し、
   bond登録は `bond_registration.rs:50` のdevelopment seed入口を持つ。
   prepare/finalize実装とprotected family受入を混同せず、未接続・明示拒否・契約未確定を記録する。

publication-genesisのwhole-Coin A→B→Aは既に復旧A鍵を使うため、A接続を残件に戻さない。
同profileのBは元鍵、foreign split専用profileはA/Bとも元鍵である。
self split/merge、初回create/mint-burnと後続6-stageの復旧成功も、それぞれの既存範囲として保持する。

FinalTransferはpositive Split backendの対象外。governanceには具体的なprotected consumer契約がなく、
application creator移行は現行 `creator == publisher` 条件を変える。
これらは単純なpath置換として開始せず、既存の未確定契約と区別して設計する候補。
実鍵/役割/ceremonyはD04/D06/D07、Ledgerはdeferredのまま。
停止済み独立監査・ZeroShare fixture/WIP・torn-WAL/mechanism2・独立anchor guestへは触れていない。

## 保存と今回の検証

rawは `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-next-1030-merge338-*`。
`preflight.json` は最新head/checksと完全review pagination、`command.json` は実mergeのactual0/EOF/wait、
`post-pr.json` と `official-git-commit.json`、`receipt.json` はmerged時刻/tree/ordered parentsとlocal main照合。
前回CI root資格 `69b8248105c65bbf22e129c845350721b7d5017c059e173c5de31dfe9bcf157a` と
完全required root資格 `2c719a5237f40697a35baf32b62d6caa64ca5cede26c1754cff4f7649f892749` は不変。
今回の文書更新はdiff・参照path/line・checkbox数を確認し、製品テスト・CI再実行は追加していない。
元85 checkbox /71完了 /14未完了と親5件は維持する。
