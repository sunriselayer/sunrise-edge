# PR #340の環境固定情報修復と検証

2026-11-01 (Asia/Singapore)。ユーザーは環境固定情報の不一致修復、完全required、CI結果確認、
変更のcommit/pushと、問題がなければPR #340のmergeを指示した。
この記録の段階では環境の再照合とCI確認が完了し、local完全requiredは実行中。mergeは未実施。

## 対象sourceと環境修復

sourceは `2e2c10fe0c360f99400be79ee50cad18f5e2336f`、tree `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e`。
base/mainは `8a5cc30a1d4a6166c6a69e720713252112817833`。前回の文書3件からruntime/test/selectorは変更していない。
以前の失敗、旧wrappers/core/CF manifestを上書きせず、`m2-signing-env-1101-*` に新しい入力を作成した。

- 7 directoriesはdevice52→53のみ変更。inode/UID/mode0700/type/正規pathは一致する。
- CFの全2725 layout entriesと2347 tool rolesを再照合し、private regular files2335件を再hashした。
  layoutの2725 device fields、toolの4682 device fieldsだけが52→53。既存device37の12 fieldsは維持。
  他のcontent hash/size/inode/UID/GID/mode/timestamps/links/entry集合は一致した。
- metadataのsourceRoot/state/provenanceは、旧source説明から現在sourceへの明示的な新admissionとして記録した。
  current Btrfs UUID `673f9922-f421-44c7-87d5-3e121f1b29d7`、/home subvolume257をread-onlyで観測。
  過去UUIDの記録がないため、device番号やinode一致だけで過去filesystem全体の同一性を推定しない。
- runtime17 rolesのresolved path/body hash、source全1246 filesのbody/metadata/clean HEADを実照合した。
  Node24.19.0/Rust1.97.1/Deno2.9.4/wasm-bindgen0.2.127を既存実体から確認。新規runtime/cacheは導入していない。
- cargo/cf wrapperの変更は固定core/manifestのpathとhashのみ。他4 wrappersはbyte-identical。
  directory/device/content比較、exact311 registry archives、private CF隔離とversion/types allowlistは維持した。
  outer driverは6 metadata filesと実runtime identity/source indexを前後に照合する。

rootもCF全layout/tools/body、runtime17/source1246とparent hashesを独立に実照合した。
通常のcontrol対応確認で、準備driverのper-file capが512MiBへ広がっていた点を検出し、
実行前に元256MiBへ戻した別driver-v2を作成した。準備版は上書きせず保存し、実行には使用していない。
初回のcf version probeはrootがrepository rootで呼び出したため既存cwd guardが拒否した。
guardを変更せず、正しいadapter cwdでの別probeが成功。cargo version probeも成功した。

root admission SHA256 `2c66102734e229f604df5dbbc7d85bd7c91a68323c18649ce254fc43ceaa81c0`。
bundle-v2 SHA256 `3dc6f0dd51402ca8f34a497046fbf1bbc88570a91d7d02af70017d1e12711788`。
実driver SHA256 `d7f89448899d5544fd0c3240d72be18f9fe066da4d4f95b24e1e439ba98b4c54`。

## Hosted CI確認済み

[run41163320441 /attempt1](https://github.com/sunriselayer/sunrise-edge/actions/runs/41163320441) の全8 jobsがsuccess。
exact headのCursor Bugbot `124425454109` もsuccess・no issues foundで、全9 checksが成功した。
全8 raw logsはcheckout `c3407a611c892d4b4a1b89b29e287eaf98c2b452` を示し、公式fetch/local Gitから
tree `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e`、ordered parents `[8a5cc30a,2e2c10fe]` を照合した。

全8 rawは1238688 bytes、147 Rust result summariesは4427 passed /0 failed /43 ignoredの実行集計。
これはglobally unique test数ではない。CF4 suitesは13+28+10+15=66 passed。
元7epochs/e8で各2件の1832-byte withdrawal候補とsuccessor-activation/terminal-unlockのendを原rawで確認した。
8 annotationsは全てUbuntu runner移行のnoticeで、warning/error0。Bugbot0 annotations。
reviews/issue comments/inline comments/review threadsは完全inventoryで各0。

通常gh認証で取得し、PR作成専用PATは使用していない。lint logの初回はghがescape出力を拒否したため、
0-byte stdout/99-byte stderr/actual1を保存し、rawを端末に表示せずfileへ保存する明示flag付きで別取得した。
残り7 rawは各1回。local argument-size失敗も保存した。CIのrerun/cancelは行っていない。
20 command receiptsのactual exit/両EOF/wait、全58 indexed files+hash manifest、既知20 PIDs不在をrootが再照合した。
CI root資格SHA256 `41cf175c2bcd5233a0af0a1591d31d9ddea63fe05f042524c23d6deae226d73e`。

## Local完全required

専有source/target/cacheに別producerがいないことを確認し、2026-11-01T02:21:48.751022Zに
`m2-signing-env-1101-required-v1.service` を開始した。実owner PID258735/start8754980、
InvocationID `0ef5d24a892b459399852490278da42d`。実cgroupの12GiB/no swap/CPU400%/Tasks512をdriverが検査する。
literal `npm ci --prefix adapters/cloudflare-workers` と `./scripts/check-all.sh` をserialで実行する。
npm300秒/required26000秒、全体28200秒内のcleanup300秒、stream64MiB/total256MiB、
元dev/test opt2・assertions/overflow checksを維持する。PostgreSQL full profileや停止済み作業は選んでいない。

現在は実行中。終端raw・実EOF/wait/reap・source/tool前後一致と所有PID/cgroup解放を確認してから結果を追記する。
この時点でlocal完全required成功やPR mergeを主張しない。

## 記録したcontrol source

`control-sources.json` は、実際に使うdriver-v2と生成controlのexact bytes/hash、旧親入力と新bundleを記録する。
同folderのPythonファイルはlocal検証controlの写しであり、protocolやproduction runtimeの変更ではない。
大きなsource/CF入力manifest、raw logsと失敗は、元の
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/` に保持する。
停止済み独立監査・ZeroShare WIP/fixture・torn-WAL/mechanism2・独立anchor guest、実鍵・host user・security policyは変更しない。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を維持する。
