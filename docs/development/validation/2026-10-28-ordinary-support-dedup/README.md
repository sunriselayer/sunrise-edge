# Operator接続・SDK表示・テスト補助の共通化

Date: 2026-10-28 (Asia/Singapore)

Source: `b436b931e711eb090f4b02db4e451016c96f799a`

Tree: `b341d6c921925207882facb85333fff93976d8a6`

Base: `3814b3ea2654c0361db9dd7292cd0e5b95da8797`

[PR #335](https://github.com/sunriselayer/sunrise-edge/pull/335)

## 実装

1. PG inventoryは既存commonのTLS接続/pool ownerを使う。上限4、10/30/300秒、DSN/certificate診断、TCP/TLS条件とnamespace/blob/fenceの順序は保持した。
2. SDKのfee-claim/publication reviewはprivateな表示文字列grammarを共有する。byte長優先、printable ASCII、コピー前の拒否、各public error型とfield名を保持した。
3. SDK integration testsは同じrequest記録付きFIFO transportを共有する。request clone後のresponse消費、exhaustionのpanicと各testの独立payload/context/signing期待値を保持した。
4. import/recurrence testsは再帰archive snapshotを共有する。relative PathBuf key、directory=None、全file bytes、symlink/nonregular拒否と各callerのbefore/after比較を保持した。
5. 4つのprocess-test callersは捕捉済みOutputの成功検査だけを共有する。status優先の両stream診断とstrict UTF-8を保持し、spawn/wait/pipe/deadlineは移さない。
6. CI契約テストの同一assertion loopsを1つにし、元PG→recurringの順序と独立したcase inventories、各assertionを保持した。

既存49 test-function bodiesは差分reviewでbyte一致を確認し、case/assertion削除は0。
operator2 /SDK4の互換性controlsを追加した。SDK renderer全体、別deadline計算、
独立wire vectors、SQLite startup child/output collectorsは統合していない。

## 検証

rustfmt/diff checkと通常の差分correctness reviewは成功。
修正後focused Rustは57 passed /0 failed /0 ignored、Node24.19.0の完全CI契約スクリプトもactual exit0。
10 streamsのhash/bytes、実両EOF/wait、全command PID/process group不在と変更中source snapshotの一致を照合した。

同sourceのlocal完全検証は01:28:55 UTC (09:28:55 SGT) 開始、04:46:51 UTC (12:46:51 SGT) 自然終了。
literal `npm ci --prefix adapters/cloudflare-workers`、`./scripts/check-all.sh`、
`bash scripts/run-postgres-docker-tests.sh profile` はすべてactual exit0。
所要時間は順に1.607秒、10,775.073秒、1,096.154秒だった。

requiredはRust147 summariesで4,421 passed /0 failed /43 ignored、
Cloudflareは13 +28 +10 +15の全66件成功。元7 epochsとepoch8 terminal unlockを保持し、
長時間scenarioも9,026.99秒で成功した。PGは元5 groupsすべてを実行し、
Rust83 summariesは1,499 passed /0 failed /20 ignored。
crash、disk-full、WAL-full、connection exhaustion、backup/restore、PgBouncerの元required flagsを保持し、
対応する実targetとprofileの完了を確認した。quiet exact testsの帰属は固定source registryと実行順で照合し、
rawにselector名が印字されたとは主張しない。summary合計には別exact/helper実行を含み、distinct件数ではない。
既存ignoredは未実行として保持する。

rootは全43 commands /86 streamsの実exit・両EOF・wait/reap・bytes/hash、全1,230 source inputs、
23 runtime tool roles、CF2,347 tool roles /2,725 layout rowsを終了後にも照合した。
ownerと全command PID、監視で観測した207 PID/start identitiesとcaptured cgroupは残っていない。
自然成功の保存・照合後に空の完了unitだけを停止し、今回PG owner labelと記録された5資源名の不在を確認した。
無関係なDocker状態の一致を条件にせず、削除やpruneも行っていない。
passing suite内のworkerd診断とmissing live secret warningはrawに保存し、production設定の準備完了は主張しない。

[全8 CI run40615244027](https://github.com/sunriselayer/sunrise-edge/actions/runs/40615244027) は
attempt1のまま06:13:07 UTC (14:13:07 SGT) に全job自然success。
rootは封印済み628 filesと全8 raw logsの1,237,081 bytesを再hashし、実checkout
`e425d8eb416a601a5a59d16f091428a2cd1f1598`、tree `b341d6c9`、
parents `[3814b3ea, b436b931]` を各実logと公式GitHub commit metadataで照合した。
CIもRust147 summariesは4,421/0/43、CF全66件成功。
rawは最初の1回の取得で完了し、全8 childの実exit0・両EOF・wait・full captureと
collector/全記録済み193 PIDの不在、sealerの実exit0を照合した。

全9 check-runsはsuccessで、Cursor Bugbotもreview完了・issueなし・annotations0。
その時点のreviews /issue comments /inline commentsは0。
CI各jobには同じUbuntu runner image移行noticeが1つずつあり、8 notice /0 warning /0 failureを
実annotation bodyまで取得して確認した。legacy combined-statusのcontexts0/pendingとは分けて記録する。
source headを再確認し、06:21:14 UTC (14:21:14 SGT) にPR #335をReady for reviewへ切り替えた。
ユーザー承認により08:28:01 UTC (16:28:01 SGT) にPR #335を既存base
`codex/live-genesis-mint-burn-1022` へmergeした。merge `55a787d8` は同tree `b341d6c9`、
parents `[3814b3ea, b436b931]`。直前にも全9 checks成功、review/comments0、headとbaseを確認した。
GitHub連携のmergeは権限不足403で変更されず、既存の通常認証と同一head指定で完了した。
マージ後の公式commit metadataとremote baseが同じmergeを指すことも照合した。

## 保存した初回停止

SDKのinert patchは新規file2件のGit header不足により適用前checkが停止した。
原patch/manifestを保持し、headerだけを補正した。適用後の全7file body hashesは準備済み結果と一致した。

初回focused runはinventory actual0後、新規archive controlがUnix socketのSUN_LENで失敗した。
同じ長いTMPDIRを維持し、Linuxではopen済みの自己所有fixture directoryを短いfd path経由で
bindするよう修正した。snapshot対象は元directoryで、Unix bytes/directory/symlink検査も保持する。
元失敗rawと実exit/両EOF/wait/PID解放を保存し、修正後は全focused stepsが成功した。
共有helperや元のprotocol/workload/selectorを弱めていない。

remote metadata-observerの初回wrapperは終端前にexit143となった。
元のstart identity/process groupとstream EOF/waitは未記録で、その部分を推測で補わない。
既知observer PIDと134 metadata-child PIDの不在を確認し、短い有限pollへ切り替えた。
同じhead/run/attempt1の継続を確認し、実CIのrerun/cancelとrawの重複取得は行っていない。
終端rawは後続の完全取得で実exit/両EOF/waitを確認した。
追加metadata readerがshort-poll receiptに冗長な `complete` keyを仮定した停止も保存し、
実exit/EOF/wait/full_capture/bytes/hashの既存schemaに従って19 terminal queriesを照合した。
これはreaderの補正で、製品検証を再実行した結果ではない。

## 証跡と範囲

ローカル証跡root:
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`

既存source/target/cache/node_modulesとNode24.19.0、Rust1.97.1、Deno2.9.4、cf1.0.0-beta.13を使う。
新しいworktree/cache/tool binaryは複製せず、直接Wranglerを呼ばない。
1,230 tracked inputsとruntime/tool inputsを固定し、同じsource/cache/targetに別ownerを重ねない。

今回の通常保守6件は実装・互換性controls・同source完全required/PG/全8 CIと終了後照合がそろったため完了。
実装はcommit/push済みで、PR #335は既存の作業baseへmerge済み。
元85 checkbox /71完了 /14未完了とD02/M1/M2/M3/M7の親5件は変更しない。
停止済み独立監査・ZeroShare WIP・torn-WAL/mechanism2・独立anchor guestを再開しない。
新しいNative/M7 RELEASE認定やmain merge、deploy、実鍵・host user・security policy変更は含めない。

## 保存証跡

| ローカル証跡 | SHA-256 |
| --- | --- |
| `maintenance-six-1028-source-index.json` | `ec75bcc26f8c1b56f0de41064857862b35630ed7bf78f2e3c2ff0b91a86969b6` |
| `maintenance-six-1028-root-targeted-qualified.json` | `f524916df1ebbd40745febe074a5e7191461829f62f774cfeee93d973329df18` |
| `maintenance-six-1028-targeted-v1-qualified-failure.json` | `75b60de48742bfd25f3ab2eb757e73f3539ccb89f5738959f5d0e5c7bc04e74b` |
| `maintenance-six-1028-root-local-qualified.json` | `55ce335cf9cf2425e0234ec102f7d695a6a8ce54b655686ea1424fffdee0707e` |
| `maintenance-six-1028-root-postclose-qualified.json` | `968f5e35f9733150405bd6cdce9250b4137843c1505e39d143576ea418a6e2ed` |
| `maintenance-six-1028-supervision-closure.json` | `e345c1047d0f1f1af14b98d706c43cc6a91f1be7dbe6c9cdc111729138bf5151` |
| `maintenance-six-1028-root-ci-qualified.json` | `3b794aac37861a459f3bf2bb6a66837e9b11f0a14e6172fbac98be0c2f98b420` |
| `maintenance-six-1028-ci-run-40615244027-20261028T013045Z/file-index.json` | `6f8c2a2bdcc2abb290f344802a7319f8e41e67117734e5a9e1f8ea93ca045816` |
| `maintenance-six-1028-ci-run-40615244027-20261028T013045Z-seal-outcome-20261028T061539Z.json` | `f27e93455ed005b690c78dee49227bb0c27bb9f710ae9388712815f132fc7173` |
| `maintenance-six-1028-pr-ready.json` | `4417dcac9cc621e746b05021afef8171eb648525d51c2f913d03c16ff7e0fa71` |
| `maintenance-six-1028-merge335-receipt.json` | `9af18fc6f5f971b36771769c52545faf5dd46465dd0bb4bbfedcd16e5023ecea` |
