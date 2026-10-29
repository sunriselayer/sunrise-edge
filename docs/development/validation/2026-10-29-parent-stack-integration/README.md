# 親PR stackのmain統合とM2残件の対応付け

2026-10-29 (Asia/Singapore) の通常統合作業。ユーザーは親PR群をmergeで整理し、
M2の既存未達をfamily別に具体化することを承認した。

## Source統合

対象は#301-#332の32 source PR。元mainは
`ffcf57674c1d500a143c50ebb8b6f195fbcb5852`、先端は
`34da6a5566c0702dfdd009497557dcca2fe1f404`。
mainと全32 recorded headsが先端の祖先であることをlocal Gitで確認した。
先端の全tree `10b53dc5c42b88086c56af24ef6403bcd846c827` は、完全requiredと
全8 hosted CIを終えたsource `5ac947f3856d3abbfb39abbdcf3e713d328cb7b4` と一致する。

#332をmainへretargetし、全体の変更と既存検証を記載してReadyにした。
通常mergeの実結果は `b191bbe6a12f36c2677a9383451bd8c6af830a0e`、
2026-10-29 09:13:18 UTC (17:13:18 SGT) 。treeは上記と同じ、ordered parentsは
`[ffcf57674c1d500a143c50ebb8b6f195fbcb5852, 34da6a5566c0702dfdd009497557dcca2fe1f404]`。
公式Git metadataと取得したGit objectを別々に照合し、全32元headsがmainへ残ることを確認した。
履歴のsquash/rebase/force push、明示的なbranch削除、新しいworktree/cache/toolの導入はない。
repositoryの既存`delete_branch_on_merge=true`設定は保持しており、GitHubによる自動削除は別途発生する。
古い独立PR #235/#298とDependabot提案は対象外。

## PR記録の整理結果

対象32件のopenは0、repository全体のopenは45→13。
最終状態は31 Merged /1 Closed。#301-#319と#332のmerge状態を確認し、
#321-#331は元headがmainの祖先であることを確認したうえで元の親系列へ通常mergeした。
各補助mergeのtreeはその元headと一致し、mainのsource統合pinは `b191bbe6` のまま保持した。
この履歴整理を、過去の限定sourceでの失敗やpartialの合格への変更には使わない。

#320はmain統合時にClosedとなった。元base branchは既存の自動削除設定により不在で、
reopenもAPIに拒否されたため、統合済みClosedのまま保持する。元head `7658629a` はmainへ残る。
このPRをMergedと偽って数えたり、消えたbaseを新規作成して履歴を書き換えたりしない。

補助制御の旧記録には、#320 reopen拒否、新しいmerge baseのlocal object未取得、
一時candidateの古いparents、自動base retargetの読取時差による停止を保持した。
それぞれの停止までに完了したmergeと以降の未実行を分けて保存し、元rawを上書きしない。
最後は既知の親branchへ明示retargetし、actual base treeが元の直前headと一致し、
実merge treeが今回の元headと一致することを各回照合して完了した。製品runtime再実行は0。

これはsource統合であり、元の親5件、選択profileのRELEASE、独立監査や公開判断の完了ではない。
成功の根拠は上記の同一treeでの既存完全required/CIであり、追加のcurrent-head/main CIを
成功済みへ付け替えない。新しいCIは別runとして残り、終端成功はこの記録には含めない。

初回preflightはgh GraphQLの`mergeCommit`をopen PRの一時merge候補と誤認して停止した。
変更は発生していない。元の記録を保持し、RESTの`merge_commit_sha`で一時候補を確認してから
実mergeした。製品検証やCIの再試行・判定変更ではない。
GitHub connectorのwriteは403で変更なし。edit/mergeは通常gh認証、readはconnectorとghを使用し、
PR作成専用PATは読み取っていない。新しいPRやautomationも作成していない。

## 既存reviewのdisposition

32 PRのreview/threadを読み取り、未解決2件をrootとread-only担当が現行sourceへ対応付けた。

| 対象 | 現行sourceで確認した契約 |
| --- | --- |
| #320 clean exitをfailureにする指摘 | `ordered_custody.rs:399-426` と `certified_custody.rs:590-600` はlimit到達後にadmissionを閉じてshutdownをawaitする。frontendも `native-http/src/lib.rs:1444-1464,1516-1523` のshutdownからdrainして戻る。`protocol_custody/linux.rs:412-423` はshutdown完了前に結果を送るため、指摘のclean-return経路とは一致しない |
| #321 204で署名検証を省略する指摘 | `certified-route-contract.tsv:10,13` が元からresult-or-empty。`fastvote.rs:243-263` と `fastvote/drain.rs:744-764` は途中進捗を204、最終vote/identityを200で返す。`certified_custody/verification.rs:129-139,245-289` はempty204を制限し200 artifactを検証する。既存TSV対応・改変artifact拒否テストとも一致する |

両threadをresolveした。新しいコード修正・runtime実行・security finding探索や
独立M1/D02監査は行っていない。元の指摘と履歴は保持する。

## M2 family別対応

実際の進捗と次の作業は唯一の作業表[TODO](../../../../TODO.md) のM2直下に置いた。
publication/genesis kinds2/3/4の選択済み子条件、historical signing-onlyのcreate/application復旧、
positive Split、automatic ordered/certified、unsupported/停止中のfee claimsを分けた。
準備APIの存在をprotected backendの受入済みfamily一覧へ読み替えていない。

次の既存scope内の候補は、`phase_own_asset_mint_burn` が既に生成する
`own-recovered.seed.restored` を、後続 `phase_own_asset_coin_operations` の
既存6 stages (kinds2/3/4) と取消後restartへ渡すこと。
sourceの順序と元鍵を使う `serve_command` をrootも確認し、read-only担当の再照合もblocking指摘なし。
初回create/application mint-burnより前に復旧があるとは仮定せず、新しいoperation/identity/
authority/profileを追加する条件にはしない。今回は具体化だけで、実装・実行成功には数えない。

同一鍵復旧と正のrotation、application creator/TreasuryCapとgenesis ownership、
実役割/実鍵/ceremony/実topologyを分ける。Proposed DR-0214は変更せず、親M2の未達全体を残す。
停止済み監査・ZeroShare fixture・torn-WAL/mechanism2・独立anchor guestは再開していない。

## Raw保存先

`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`:

- `parent-stack-1029-initial-pr-inventory.json` と `parent-stack-1029-initial-reviews.json`
- `parent-stack-1029-ancestry-qualified.json` (SHA256 `d2ab2b54fd2f0cb5c4b4f68702b434a45cdf949baa598c47bb6511e7805c2c7a`)
- `parent-stack-1029-review-disposition.json` と `parent-stack-1029-retarget332.json`
- `parent-stack-1029-merge332.json` (初回preflight停止) と `parent-stack-1029-merge332-v2.json` (実merge)
- `parent-stack-1029-main-ancestry-qualified.json` (SHA256 `2bf146cc71749122676386a93333b45a8a7788ebeda5ab268f24cc8b040fb3a0`)
- `parent-stack-1029-ancestor-pr-merges*.json` (既にmainへ含まれる親PRのmerge記録整理と停止記録)

文書同期では作業表と既存のvalidation記録だけをmainへ移す。古いrecords branchの
runtime/source/architectureをまとめてmergeせず、記録を現在の実装へ付け替えない。
