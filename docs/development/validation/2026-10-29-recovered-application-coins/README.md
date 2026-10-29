# 復旧したapplication鍵による既存Coin操作

2026-10-29 (Asia/Singapore) 。Source `ef0cea4e33e942f22aa40379e6d426579f846109`、
tree `38621a364d01e691c9496f2b6756d87de9827818`、base `27650eea85818433d1cd0043cb764243d4b96ebf`。
[PR #337](https://github.com/sunriselayer/sunrise-edge/pull/337) はmain向けのReady PR。

## 実装

既存 `phase_own_asset_mint_burn` が生成する `own-recovered.seed.restored` を、
後続 `phase_own_asset_coin_operations` のmint-one・split・merge・burn・mint-two・transferへ渡した。
5 live groupsとその5 revoked restartsの実child argvを記録して照合する。
以前のsigner終了を先に確認し、復旧先はcustody UIDのregular mode-0600 fileであり、
元鍵とpath/dev+inodeが異なることを確認した。Node側も全10選択を独立に検査する。

既存47 setup predicatesのpath、historical signing-only recovery、6段階の独立oracle、
実送信・approval/frame/receipt/replay、nonce/supply/counter、元resource/PTY/output/timeout上限は維持した。
追加2 flagsは既存47と別に数える。naiveなrecursive true合計61を新規61テストとは扱わない。
protocol/Rust実装、operation、identity、authority、profile、鍵copyや子process数は増やしていない。
設計契約は[DR-0281](https://github.com/sunriselayer/sunrise-edge/blob/ef0cea4e33e942f22aa40379e6d426579f846109/docs/architecture/decisions/0281-live-recovered-application-coins.md) に記録した。

## 実component検証

Node24.19.0 syntax、embedded Python3.14 AST/compile、変更対象function以外のAST一致、
Git diff checkに成功した。raw Python248,512/262,144 bytes、bootstrap55,725/65,536 bytes。

最初のcomponent controllerはmetadata専用systemctl subprocessにuser-bus環境がなく、
製品dispatch前にactual exit1となった。元raw/失敗を保持した。
同subprocessだけに既存user-bus環境を渡すcontroller修正後、製品環境を変えず4 profileが自然成功した。

| 完全profile | 元のpredicate groups | 追加group | 保存evidence bytes |
| --- | --- | --- | --- |
| publication-genesis | legacyCore70 | 既存のgenesis controlsを保持 | 16,373 |
| genesis-split-handoff | legacyGenesisHandoff21 | 既存のgenesis controlsを保持 | 8,821 |
| application-transfer-recovery | legacyApplicationSetup47 / historicalTransfer9 | newRecoveredApplication2 | 17,930 |
| application-split-merge-recovery | legacyApplicationSetup47 / historicalSplitMerge9 | newRecoveredApplication2 | 18,720 |

両application profilesで全6 stages、5 live groupsと5 restart groupsを確認した。
署名要求数n=[1,2,1,1,1]に対し、live countersは[3n,3n,2n,n]、restartは[n,n,0,n]。
最終supply5,000,000 /cap version6 /next nonce9を保持する。
Cargo JSONの完全package/manifest/src/profileから選択したCLI/libtestを使用し、
両方の `fresh:true` はキャッシュ再利用として保存した。fresh rebuildとは主張しない。
ELF/loader/librariesとtracked source1,243 filesのhash/metadataを照合した。
67 commands /134 streamsの実exit0・両EOF・wait/reap・既知PID不在、自然unit successとcgroup消失をroot照合した。
fixture controller自身のowner labels・container/PID停止・container/tmpfs volume削除の検査を根拠とし、
独立したcontainer ID別再queryを実施したとは扱わない。成功保存後、空の完了unitを停止した。

## 完全requiredとCI

同sourceでliteral `npm ci --prefix adapters/cloudflare-workers` と `./scripts/check-all.sh` を
10:48:22 UTCから13:29:06 UTCまで実行し、両方actual0で自然終了した。
Rust147 summariesは4,427 passed /0 failed /43 ignored、CFは13+28+10+15=66 passed。
Rust値はinvocation合計であり、ignored entriesを成功やglobally distinct未実行case数へ加えない。
元7epochsの各1832-byte候補2件、computed epoch8の候補2件とterminal-unlock end rawを保持した。
rootが全42 commands /84 streams /962,811 captured bytes、source1,243 inputs、runtime23と
CF2,347 roles/layout2,725行を照合し、実EOF/wait/reapと既知PID/cgroup解放を確認した。
root reader自身もactual0/両EOF/waitで完了し、成功保存後に空の完了unitを停止した。
metadata supervisorは159 inner probesの実EOF/waitと全既知identityの解放を保存した。
外側tool APIに個別EOF/wait flagsがない事実はnullのまま保持し、product captureの証拠と分けた。
別PG profileやRELEASE runtimeは今回の受入対象に含めない。

[全8 CI run40860404544](https://github.com/sunriselayer/sunrise-edge/actions/runs/40860404544) は
attempt1のまま15:43:07 UTCに全job成功。Bugbotを含む全9 checksはsuccess、PRはReady/head ef0/base27650。
各実checkout `f9cd48dd7c5a3eeaefbcbd52ac31585074539380` はtree `38621a364d01e691c9496f2b6756d87de9827818`、
ordered parents `[27650eea85818433d1cd0043cb764243d4b96ebf, ef0cea4e33e942f22aa40379e6d426579f846109]`。
全8のraw git-log行と公式Git metadataを別々に照合した。

Raw8件を一度だけ取得し、1,238,733 bytes。148 command receiptsと39 wrapper capturesの
actual0/両EOF/wait/full capture、sealed687 filesのbytes/SHA、既知229 writer PIDs不在をroot照合した。
116 short/discovery receiptsには `complete` fieldがなく、既存schemaの実exit/EOF/waitで確認した。
全command bytes3,502,007はraw+metadata合計でも8MiB以内。元mechanismのraw8MiB/metadata32MiBと
取得開始からsealer reap/rehashまでの300秒上限を維持し、実時間10.319199秒だった。

8 Actions checksのadvertised1/fetched1はUbuntu26 runner-label移行notice各1、warning/failure0。
Bugbotはadvertised0/fetched0で、元mechanismはannotation endpointを取得していない。
この未取得を独立したempty page取得へ読み替えず、full check metadataを保持した。
Reviews/issue comments/inline commentsは別のpaginated rawでも全0。
Legacy combined statusはpending、legacy statusesは空であり、実9 check-runsのsuccessと分けて保存した。

終了後のreaderはreceipt filename globとURL query suffixの仮定で停止した記録を保持した。
読取schemaを修正して同じ閉じたrawを照合し、製品/CI rerun・raw再取得・cancelは行っていない。

## 残る範囲

初回create-assetと初回application mint/burnはこの復旧鍵生成より前に実行されるため、
今回のlive consumer接続による完了には含めない。同一鍵復旧から正のidentity/ownership rotation、
creator/TreasuryCap移行、実鍵ceremony、全accepted family対応や親M2完了を推定しない。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を保持する。
停止済み監査・ZeroShare fixture・torn-WAL/mechanism2・独立anchor guestには着手していない。
別PG profile、RELEASE runtime、provider deployment/public readinessの新しい受入結果は主張しない。

## Rawの保存先

`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013` の
`application-recovered-live-1029-*`。既存source/target/cache/toolsを再利用した。

- `static.json`: static checksとtransport予算。
- `component-v1-closed-failure.json`: product未dispatchのmetadata admission失敗。
- `component-v2-run-v1/result.json`: 全4 profileの自然成功。
- `component-root-qualified.json`: SHA256 `9339495b90e84c0a027f5c7da5958046232ffeb0727133230bd7ebdbdca50563`。
- `component-empty-unit-stopped.json`: 成功保存後の空unit停止。
- `launch.json` / `full-admission.json`: 完全requiredの有限実行・source/runtime/bridge pins。

- `root-postclose-qualified.json`: SHA256 `e3d387e6cde27d91e36ea75f6b044187ce3953eeb4254def2acf468bfbc83044`。
- `full-terminal-raw-lines.json`: 元7epochsとcomputed e8の候補/terminal-unlock行。
- `ci-root-qualified.json`: SHA256 `c60519dbe2b30779b17b1d808ce627123d743b8b5c8a78dff10e9acd3ac0f9e4`。
- `ci-run-40860404544-20261029T105136Z/file-index.json`: SHA256 `b88ee40140a346b7a4bcbc4a5291583334555ba9224c6d65278ec95b76501118`。
- sibling `writer-release-proof.json`: SHA256 `6933681524e1d00fa6d1216fcd8c2bd478a3d9ece9592d1a73d438c9e814b127`。
