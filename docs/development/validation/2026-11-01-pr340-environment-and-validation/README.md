# PR #340の環境固定情報修復と検証

2026-11-01 (Asia/Singapore)。ユーザーは環境固定情報の不一致修復、完全required、CI結果確認、
変更のcommit/pushと、問題がなければPR #340のmergeを指示した。
環境の再照合、local完全requiredとCI確認を完了し、PR #340をmergeした。

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

実ownerの開始は2026-11-01T02:21:48.824472Z、自然終了は05:10:54.860441Z。
10146.049秒でliteral npm ciと完全requiredが成功した。
10 commands/20 streams・961576 captured bytesの全actual0/両EOF/fullCapture/wait/reapとlength/hashを確認した。
147 Rust result summariesは4427 passed /0 failed /43 ignoredの実行集計、CF4 suitesは13+28+10+15=66 passed。
原selector/timeout/7epochsとe8、withdrawal候補の検査を保持し、Deno/Vercel/Supabase/AWSも元requiredのまま完走した。
invocation集計をdistinct test数や追加RELEASE認定へ読み替えない。local timing表示がない部分はCIの原raw証拠と区別した。

source全1246 filesの前後metadata/body/clean HEAD、6入力metadata files、17 runtime full identities、
6 wrappersは一致した。独立した終端readerも現在sourceとCF全2347 tool roles/2725 layout/2335 private bodiesを再照合した。
source snapshot SHA256 `09e72bc59b16129c01430d4b56f52822abf26b2e8c8e4495ef81a7467a759988`。
root資格SHA256 `5330cd4f84c6fec2930e3649b343af6594a5250122acdc0e160519f622caa84e`。

最初の終端readerはsystemdのControlGroup propertyが終了後も残ると仮定して停止した。
実際はInvocationID/ExecMainPIDが一致し、自然終了0を保持したままControlGroupだけが空になり、
元のsaved cgroup pathも既に消失していた。失敗とreader-v1を保存し、v2は同じidentityを維持して
「propertyが空ならsaved groupの実不在」を要求する形へ訂正した。製品・CIのrerunはしていない。
reader-v2はactual0で1.897秒、監視observerもactual0/EOFで終了した。
既知109 sampled PID/start identities、10 command PIDs、owner258735とobserver275554の解放、
saved cgroup不在を確認した。自然成功の保存後、完了した自己所有unitだけをstopして後片付けした。
partial/cancelled/強制終了を成功に数えていない。

## PR #340 merge

local完全requiredのroot資格とcontrol sourceをcommit/pushした `3535fef2` の後、
exact head `2e2c10fe` の全9 current checks success、Ready/mergeable、reviews/threads各0を再確認した。
通常gh認証でhead一致条件付きmergeを実行し、2026-11-01T05:17:09Z (13:17:09 SGT) に
`8afaf3566294fe3d6e2096ac4107d2270439b7a8` でmergeされたことを公式PR metadataから確認した。
作成専用PAT、force pushやchecksの省略は使用していない。

mainのtreeは検証済みsourceと同じ `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e`、
ordered parentsは `[8a5cc30a,2e2c10fe]`。local mainもfast-forwardしてclean/upstream一致を確認した。
merge後に自動起動するmain CIは別runであり、この記録で成功済みとはしていない。
今回の完了は環境修復・選択sourceの完全required/PR CI確認とmergeで、M2/親5件全体の完了ではない。

## 記録したcontrol source

`control-sources.json` は、実際に使うdriver-v2と生成controlのexact bytes/hash、旧親入力と新bundleを記録する。
同folderのPythonファイルはlocal検証controlの写しであり、protocolやproduction runtimeの変更ではない。
大きなsource/CF入力manifest、raw logsと失敗は、元の
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/` に保持する。
停止済み独立監査・ZeroShare WIP/fixture・torn-WAL/mechanism2・独立anchor guest、実鍵・host user・security policyは変更しない。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を維持する。
