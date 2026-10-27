# Operator・PG test setup・SDK deadlineの共通化

Date: 2026-10-27 (Asia/Singapore)

Source: `e7bdf83fa184f5eecadcb524dd3d7ba87166986d`  
Tree: `c28d0437ca545b642b00d20fd137c0c4585cb314`  
Base: `bfbca5fcdf6144241a4e7db8b8095375e1c92f7d`  
[PR #334](https://github.com/sunriselayer/sunrise-edge/pull/334)

## 変更

- Genesis inspector/authorのstrict canonical decimal処理をoperator commonへ移し、inventory argvのhex decoderも既存helperを使う。
- PG E2Eのcompiled CLI locator、temporary file、backend解決、proxy DSNに既存test supportを使う。
- successorの2 test targetsのTempDirをstd-only helperへまとめた。元prefix、tag、PID、各targetのcounterとinterleaving、best-effort cleanupを保つ。
- SDKのoptional deadline guardをcrate-private helperへまとめた。send前後10か所の呼出し位置、None/future/expiredの扱いとerrorは保つ。

canonical grammarとFastVoteの緩いdecimal grammarは分け、fixture固有assertionと独立oracleを保持する。
既存test case/assertionの削除は0。7つの互換性test functionsを追加した。
CLI locatorのmissing-CLI diagnosticとEXE_SUFFIX対応だけは既存共有ownerへ統一した。
SQLite startup collectorはtiming/drain条件が異なるため今回の4件に含めない。

## 検証状況

rustfmt、diff checkと通常の差分correctness reviewは成功。
focused15件 (common11、inventory argv1、SDK deadline3) はpassed、failed/ignoredは0。
独立した時計やsleepを導入せず、SDK transport call数とadmissionのerrorを検証する。

同sourceのlocal完全検証は09:44:52 UTC開始、13:10:58 UTC自然終了。
literal `npm ci --prefix adapters/cloudflare-workers`、`./scripts/check-all.sh`、
`bash scripts/run-postgres-docker-tests.sh profile` はすべてactual exit0。
所要時間は順に2.890秒、11,214.937秒、1,142.345秒だった。

requiredはRust147 summariesで4,415 passed /0 failed /43 ignored、
Cloudflareは13 +28 +10 +15の全66件成功。
元の7 epochsとepoch8 terminal unlockを保持し、長時間scenarioも9,296.14秒で成功した。
PGは元5 groupsすべてを実行し、Rust83 summariesは1,497 passed /0 failed /20 ignored。
crash、disk-full、WAL-full、connection exhaustion、backup/restore、PgBouncerの元required flagsを保持する。
対応する実targetとprofileの完了を確認した。quiet exact testsのselector帰属は固定source registryと実行順で照合し、rawにselector名が印字されたとは主張しない。
これらは別exact/helper実行を含むsummary合計で、distinct test数ではない。元ignoredは実行済みにしない。

rootは全43 commands /86 streamsの実exit・両EOF・wait/reap・bytes/hash、全1,226 source inputs、
23 runtime tool roles、CF2,347 tool roles /2,725 layout rowsを終了後にも照合した。
ownerと全command PID、監視で観測した169 process identitiesとcaptured cgroupは残っていない。
自然成功の保存・照合後に、空の完了unitだけを停止した。
今回のPG owner `9d0a57a7744f1ca3d21ef33465ef2b8f` のlabelと記録された5資源名は残っていない。
無関係なDocker資源は一致条件にせず、削除やpruneも行っていない。
passing suite内のworkerd診断とmissing live secret warningはrawに保存し、production設定の準備完了は主張しない。

[全8 CI run40482348781](https://github.com/sunriselayer/sunrise-edge/actions/runs/40482348781) は
attempt1のまま14:37:10 UTCに全job自然success。
rootは封印済み386 filesと全8 raw logsの1,237,025 bytesを再hashし、各実checkout
`70e9807b697a9d59a23d5947740fde57fdb89aef`、tree `c28d0437`、
parents `[bfbca5fc, e7bdf83f]` を実logと公式GitHub commit metadataで照合した。
CIもRust147 summariesは4,415/0/43、CF全66件成功。
rawは最初の1回の取得で完了し、全8 childの実exit0・両EOF・full capture・waitと
collector/記録済みPIDの不在を照合した。CIの再実行・cancelは0。

全9 check-runsは成功し、Cursor Bugbotもreview完了・issueなしと記録している。
その時点のreviews /issue comments /inline commentsとBugbot annotationsは0。
各CI jobにはUbuntu runner image移行のnoticeが1つずつあり、計8 notice /0 warning /0 failureを別途取得して確認した。
legacy combined-statusはcontexts0のpendingを返すが、9 check-runsの実successとは分けて記録した。
これは通常の保守差分についての結果で、独立したsecurity/release auditを意味しない。

ローカル証跡root:
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`

実行前に1,226 tracked inputsとruntimeを固定し、既存checkout/target/cache/node_modulesを再利用した。
Node24.19.0、Rust1.97.1、Deno2.9.4、cf1.0.0-beta.13を使い、直接Wranglerは呼ばない。
実行は有限時間の単一ownerが逐次担当し、同じsource/cache/targetの重複writerは作らない。

## 元のTODO

通常保守4件は実装・互換性controls・同source完全required/PG/全8 CIと終了後照合がそろったため完了。
実装はcommit/push済み。全9 check-runsのsuccessと同一headを再確認し、
15:29:39 UTCにPR #334をReady for reviewへ切り替えた。
元の85 checkbox中71完了/14未完了とD02/M1/M2/M3/M7の親条件は変更しない。
停止済み監査、ZeroShare、torn-WAL/mechanism2、独立anchor guestは再開していない。
新しいNative/M7 RELEASE認定、main merge、deploy、実鍵・host user・security policyの変更は行わない。

## 証跡

| ローカル証跡 | SHA-256 |
| --- | --- |
| `maintenance-followup-1027-source-index.json` | `8a3ccd1ea88042f643b16958b6f857f4a658cd037cd39ce34fb2d57aa9bb1886` |
| `maintenance-followup-1027-root-local-qualified.json` | `14950e6f90cc6fe61f8b4230618aba8df0d7590278418dbf9616df6439a6495d` |
| `maintenance-followup-1027-root-postclose-qualified.json` | `acb1b4de4eb7a05d6f06a4060465fba425de40f3a4ed008607645051dbf81979` |
| `maintenance-followup-1027-supervision-closure.json` | `8ba704d4903c5fcaf0370645813f2fead7f22b95be1c24d401cce0c648b60255` |
| `maintenance-followup-1027-root-ci-qualified.json` | `2c6d2c7cf4a51d889a6bdc238037dfde8dbcbd8df5ad56b4275621a02d7e8e05` |
| `maintenance-followup-1027-ci-run-40482348781-20261027T094001Z/file-index.json` | `b203f060f1fd6a30ffcf2f23b1a4a4cb6202718ec16b880c5a713cdd21461adf` |
| `maintenance-followup-1027-root-annotations-qualified.json` | `c66d0003441abb0b3555a36ff17ee532b38e10da6577e6c1c3e76f3ba08bebb7` |
