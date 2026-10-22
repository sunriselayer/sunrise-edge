# 復旧鍵によるgenesis mint/burnの検証

Date: 2026-10-22 (Asia/Singapore)

Source: `8da1d620cba7428672df086318b2df2d3cec5976`
Tree: `b60b28e8231895d6c62cbaa62f0c6faf0cd20622`
[Draft PR #332](https://github.com/sunriselayer/sunrise-edge/pull/332)

既存publication recoveryで停止後に復旧した同一A鍵を、既存のgenesis mint、whole-Coin
burn、取消後restartへ接続した。新しい操作・identity・authority・profileは追加していない。
historical 9e/9fの署名専用復旧と元の操作・拒否・上限を保持する。

## 限定componentの実結果

2026-10-22 12:26:58 UTCに開始し、12:27:58 UTCに自然終了した。
fmt/Clippy、元5 build/no-run、実Docker Linux UID/PTY fixture、元4 local TLS selectors、
remote TLS全15件の計13コマンドはすべてactual exit 0。

実fixtureでは、live/restart両signerの選択pathが
`/work/custody-keys/custody.seed.restored` であることを確認した。
mint/burnの6 accepted / 6 handled / 4 signed / 2 refused、取消後restartの2/2/0/2、
historical 9e/9fの2/2/2/0、6/6/2/4、4/4/0/4をそれぞれ保持する。
split/merge、Coin往復、historical body付きACK喪失後のgeneration 2→3正常再起動・
同一再送も既存判定どおり成功した。

rootは全26 command streams、各EOF/wait/reap、8 ELF rolesと今回のCargo JSON producer行、
全1224 tracked filesのmetadata/SHAとHEAD/tree/clean setを照合した。
実Cargo `fresh` flagは変更せず記録しており、全ELFの新規コンパイルを主張しない。
追加の終了後照合で67 strict tool roles、3 own aliases、311 registry archivesのidentityを確認し、
archivesはownerのbefore/after inventoriesとも一致した。private CFの全body照合は完全gate側の範囲。

owner PID 1330082とlauncher PID 1330081の不在、captured cgroupの消失、
実Invocation `6268492b755a4b48976b03579b802438` の自然Status 0を確認した。
rootは終了証跡を保存した後、空であることを確認したこのunitだけを停止した。

ローカル証跡rootは `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`。

| 証跡 | SHA-256 |
| --- | --- |
| `genesis-mint-burn-component-1022-root-qualified.json` | `c8ac8317f068001bee90c2f039beb9ebc984b50736324340c7cf56632ba8a152` |
| `genesis-mint-burn-component-1022-root-input-recheck.json` | `6331b2b319a4895a56c5fb23235201f5f18ce288448193414ce13d223ed6cfd9` |
| `genesis-mint-burn-component-1022-closed-proof.json` | `3c175a4788d12a4f00c5eff6c6514a59600c0bc866d30e536a9c5c6988deeeb1` |

## 同sourceの完全required

12:38:31 UTC開始、15:28:00 UTC自然終了。literal
`npm ci --prefix adapters/cloudflare-workers` と `./scripts/check-all.sh` は
それぞれactual exit 0/実両EOF/wait/reapで、1.685秒・10,157.567秒だった。
Rust147 success summariesは4,400 passed/0 failed/43 ignored、CFは13/28/10/15の66件。

rootは全9 raw streams、全1224 sourceのfull9/SHA/HEAD/tree/clean/set、2396 tool/seed
hashes、67 strict roles/3 aliases、CF2347 roles/layout2725、311 archives、5 wrappers、
7 directories、保存したbefore/afterと現在のcache/target inventoriesを照合した。
target/cacheはreuseであり、freshと呼ばない。
自然Invocation `877f292d833045e4869b11d55b310819` のStatus0、owner1360561と
check-all1360606・npm1360586の不在、captured cgroupの消失を確認した。
MemoryPeakは3,844,284,416 bytes、MemorySwapPeakは0。終了証跡を保存した後、
rootは空の完了unitだけを停止した。

| 証跡 | SHA-256 |
| --- | --- |
| `genesis-mint-burn-full-required-1022-root-qualified.json` | `c578c9e265c5e380b2d2b08a505322f8749378dfd6f9c3cebe923c7c66d9bc6b` |
| `genesis-mint-burn-full-required-1022-closed-proof.json` | `963f6e55dfd6fd43d81251789a4435b18a2c8850897d9139006490d4ddee5df6` |
| `genesis-mint-burn-full-required-1022-supervisor-termination-proof.json` | `0dcaa7b1e2430886290506093e95bdc86fccea43ca83d9e5f97bfa87756079dc` |
| `genesis-mint-burn-full-required-1022-root-empty-unit-stop.json` | `1d069f30f5d717074ff37c2ba3a83cce2a595c9639e1729e7afaa860aa51f551` |

## 同sourceの残るgate

[CI run 39775926228](https://github.com/sunriselayer/sunrise-edge/actions/runs/39775926228) は
17:14:36 UTCにattempt1の全8 jobsが自然successとなった。rootが8 raw logs計1,564,992Bと
各実checkout58f7cef8/treeb60b28e8/parents[b389,8da]を照合した。
Rust147 summariesは4,400/0/43、CF13/28/10/15=66。元7epochs/e8、同IDの1832B候補2件と
round3 committed ACK、8link history testの実成功を確認した。
35roleのsource補足は別照合として残す。root proof
`ci332-mint-burn-1022-root-qualified.json` のSHA-256は
`7a0ec1755309011558a39abba89d6bc9783ee25508eaff506b9b57fc0ce4ee14`。

ログ回収の初回はsystemd scope/wait flagsの不整合、2回目はservice PATHのgh不足で停止した。
両失敗は元pathに保持し、未知のcgroupを消失確認済みとは扱わない。修正した3回目の
collectionはactual0・実両EOF/wait/reap。既知PID1666753/1666754/1666756/1666757/1666758と
観測したservice cgroupの不在を確認した。元CI jobsの再実行は0。

fresh 13-target RELEASE A/Bは16:19:17 UTCに開始し、726.639秒で自然終了した。
rootが13組の全byte/mode/owner一致、保存26 ELFのfull9/hash・別inode・nlink1・0755/UID1000、
実Cargo JSON、C全1224 files/Git blobs、23 tools、311 archive/manifest/marker inputsを照合した。
Nativeが選択した231依存の10,017 files/122,049,003 bytesは、archive payloadとの一致も確認した。
この選択範囲を、未選択依存のexpanded code全体へ拡張しない。
実両EOF/wait/reap、owner1607616/launcher1607614と既知PID不在、captured cgroup消失、
4 compiler/temp directoriesとsource leaseの解放まで確認した。

最初の終了後readerは、固定済みconfigured tool alias `/usr/bin/cc` を通常証跡用の
no-follow readerへ渡して停止した。この失敗を保持し、明示されたtool rolesだけについて、
configured metadata/link target/resolved path/実体metadata/hashを照合して読むよう修正した。
証跡/sourceのno-follow guardと元の全判定は保持する。修正readerのactual0を確認し、
ビルドは再実行していない。

| 証跡 | SHA-256 |
| --- | --- |
| `mint-burn-native13-ab-1022-root-postclose-v2-qualified-fetch-reader2-qualified.json` | `c27ecbe5c223c3d0a4857b36efbfcd681d87a1369703faca813f7d074fa1ca14` |
| `mint-burn-native13-ab-1022-lean-c-v1-ab-parent-qualified.json` | `9da5ae4d696f8ed39ccc38e65600689e3adf9eb3e55ccc0255037228ec262e14` |
| `mint-burn-native13-ab-1022-lean-c-v1-ab-parent-consumer-view-qualified.json` | `f13edfd88520628db5cf433981fefdd7e3b113d62c3b6a311a37f266d8cfe691` |

対応するCLI fixtureは後述のE219で成功。元12 RELEASE runtimeは未実行。
元のclean source/no-target/no-extra guardを守り、既存のS target/node_modulesを移動しないため、
完全gate終了後に同8daの専用checkout Cを1個作成した。
追跡sourceのlogical bytesは26,617,053で、cache/target/node_modulesをコピーしていない。
Cの全1224 files/Git blobs/full9を新規観測した。

その後の入力censusは、固定済みarchiveに対応する
`fiat-crypto-0.2.9` のprivate expanded source pointerがないためactual1で停止した。
helper PID1554858はwait/reap後に不在、両stream実EOF。失敗のterminal
`mint-burn-native13-ab-1022-root-stage-v1-census-external-terminal.json`
SHA-256は`6b0b2b8d41a0f6f0a8ef37da9bd10475c5f3b9c1f8d08f4a56826f327fa73095`。
この準備失敗は保持し、完全gateの製品結果やRELEASE成功へ付け替えない。
不足は26依存の未展開sourceだった。既存の固定済みarchiveだけを使い、ネットワークを
無効にした元の `cargo fetch --locked --offline` を1回実行し、actual0で終了した。
26 source directoriesの展開と元285 directoriesのidentity不変、全311 archivesの固定hash、
実両EOF/wait/reap・既知PID/cgroup解放をrootで照合した。
archiveの取得・コピーは0。展開されたregular filesのlogical bytesは114,639,116で、
sampling上のgrowth0を展開量0とは解釈しない。展開した全code bytesの検証完了も主張しない。

その終了後、元helper・同じplan-root・同じ上限で、別raw名のcensus attempt2を1回実行した。
actual0/実両EOF/wait/reap、PID1605983不在を確認した。rootが全311 archivesと
Cargo.toml/marker/source directory metadata、23 tool roles、Cの全1224 files/Git blobs/full9を
再照合した。初回actual1の失敗とrawは保持する。これはRELEASE入力準備の回復であり、
A/B生成物やRELEASE runtimeの成功ではない。

| 証跡 | SHA-256 |
| --- | --- |
| `mint-burn-native13-ab-1022-offline-readiness-attempt2-root-qualified.json` | `6ce16d1ec8ee3b1174201b5b61a8dd224a1fa9c095da615706aa8228c49a5418` |
| `mint-burn-native13-ab-1022-root-stage-v1-census-attempt2-external-terminal.json` | `8664a39b01d90a7f777902234a73577fbc755f4f69c28db0eb69e9dcfc181864` |
| `mint-burn-native13-ab-1022-root-stage-v1-root-input-review.json` | `2c56d2ff6c02462b488eceeceb84c0c214dcfa7a570aae8a9cae06296120bf04` |

A/Bは元8GiB/swap0/CPU4/tasks512・7200秒の上限、13 targets・2 fresh compiler lanesを維持した。
Invocationは `1d02e0c3983e4c51b79f01e0a43b84d2`。実行中はC/cache/tools/targetを専有し、
終了・PID/cgroup解放後にrootの終了後照合を行った。

元12ケース用driver準備の初回は、監視captureに旧owner名のexpressionが残っていたため、
開始直後に当該unitだけを停止した。Invocation `37a9f4c6c5054dacb3b384a1e9f06d1e`、
owner1643571と既知child/launcherの不在・captured cgroup消失を確認した。
launcher exit0とは別に、実mainはSIGTERM15、最初のCargo commandのexitはnullであり、
コンパイル成功に数えない。部分target/raw/元controlsを保存して、別attemptの修正を準備する。
終了記録 `mint-burn-original12-1022-lean-c-v2-driver-attempt1-root-closed-failed.json` の
SHA-256は `f0291de81dcdca07431e39897ecd26210789de9e5036845ae5d9ae7d2c01389b`。

監視pathを修正したattempt2は別unit・別target・別rawで実行し、798.119秒で自然終了した。
元の2 Cargo commandsはmerged stdout/stderrの実EOF/waitを伴ってactual0。
外側captureもactual0/実両EOF/wait/reap。Invocation
`733a0d87f16b458680abd8bfd4d65f3e`、owner1648518/launcher1648516と既知PID、
captured cgroupの不在を確認した。
rootは13 debug binaries・10 integration driversの実体hash/metadataと今回のCargo JSON、
genuine Cのpackage/manifest/srcPath、元dev/test opt2・assertions/overflow profile、
C全1224 source inputs、23 configured/resolved toolsと4 own wrapper hashesを照合した。
これはコンパイル結果だけであり、テスト一覧の観測・元12ケースの実runtimeは別に残る。

| 証跡 | SHA-256 |
| --- | --- |
| `mint-burn-original12-1022-lean-c-v2-driver-attempt2-closed-proof.json` | `1d8f5d21899d6253aae350d86632a94fdb0f52dcccf0b75ff567bd7074263ce7` |
| `mint-burn-original12-1022-lean-c-v2-driver-attempt2-postclose-qualified-v4.json` | `8a429482e37a911feea28907291fd13c7d710d9ed066a7ae080cdce901dffdc8` |

元10 driversの一覧は通常/ignored各1回、全20 commandsがactual0・実両EOF/wait/reapで終了した。
rootは全40 raw hash・元argv・名前を照合し、通常99件とignored3件を確認した。
元のexact ignored2 selectorsはconditional_readiness_sqliteにあり、通常99+指定2=101となる。
local_tls_startupは18/1。一覧はテスト本体を実行せず、成功件数には加算しない。
10 ELFの現在hash/full9がbefore/afterと一致し、owner1663357/launcher1663355と
全20 child PID・captured cgroupの不在まで確認した。初回root readerのmode比較は、
raw st_modeと保存されたpermission bitsを混同して停止した。元reader/失敗記録を保持し、
permission bitsへ修正して照合した。list commandの再実行は0。
root proof `mint-burn-original12-1022-driver-count-inventory-v1-root-qualified.json` の
SHA-256は `21fa93bbc0e48f4e2dfb6cc48a7a00094c9518892e919d53f0066b857f24e4b3`。

新しいcompiler/driver outputsは元の専有external directoriesに生成し、source checkoutは
全runtime・終了後照合・PID/cgroup/lease解放の後にcleanを確認して削除する。
限定componentと完全gateだけで新mint/burn子条件・親M2/M3/M7を完了にしない。
停止済み監査・ZeroShare WIP・partial persistent-write/anchor guest対象は再実行していない。

## RELEASE publication fixtureと元protocol補足

同8daのNative13 A/B lane A CLIと、genuine Sの同sourceから生成したretained libtest harnessを
使用した。C/S全1224 Git blobs・body SHA・full9、空のsource差分、実Cargo JSONのS manifest/srcPath、
retained119efのhash・別inodeを確認した。Sの生成元をCへ読み替えていない。

fresh2 ELF/LDD inventoryは0.601秒でactual0・実両EOF/wait/reap。元1GiB/swap0/CPU1/tasks128の
owner cgroup limitsと既知PID1668080/1668082/1668095/1668100の不在、capturedCG消失を確認した。
1秒pollより短く、外側live InvocationID/ExecStartは未観測と明記する。通常の子process argv、
固定owner、実raw/終端と現在のsource/binaries/libraries/toolsを照合した。
root inventory proofは `mint-burn-publication-genesis-release-1022-lean-c-v2-inventory-parent-qualified-1022.json`
SHA-256 `d9dfe9e61acb233c8ccab8da5a1d755727588e2bfd9abf8237de3496dbc1669e`。
準備時のJSONLを単一JSONとして読む失敗は保持し、明示JSON inputsだけをparseするreaderへ修正した。

元publication-genesis profileの1回実行は5.632秒、actual0・実両EOF/wait/reapで自然終了した。
73 recursiveTrue pathsは元source期待pathと完全一致。mint_burn.live_key_path/restart_key_pathは
復旧pathで、live6/6/4/2とrevoked restart2/2/0/2、9e/9f signing-only controlsも維持した。
出力190,217Bは元262,144B上限内。保存live ExecStartは実v3 ownerとprofileに一致し、
Invocation `af003ec8d3384c90aefd006b2abcccce`、owner1669845/launcher1669843とcapturedCGの不在を確認した。
container_removed=trueは元Node fixture所有のcleanup postconditionであり、追加Docker queryの実施とはしない。
executor proof `mint-burn-publication-genesis-release-1022-lean-c-v2-publication-executor-actual-qualified-1022.json`
SHA-256 `bde4f5cb5102fa1e4f7a8494aff70bc514c827b4b3b2370f67c0192619c6ce2e`。

local完全required/全8 CIのrawは元7epochs/e8の1832B withdrawal2件、全epoch同IDとround3 committed ACKを
保持した。元12 product filesはc535から8daまで不変。成功した8link driverの元sourceが
3+4*8=35rolesをassertすることを照合し、stdout path数からrole数を推測していない。
補足proof `genesis-mint-burn-1022-original-required-protocol-qualified.json` のSHA-256は
`4a3ddf6b10626dde55e1e017fa6d17d4c61cb01e06f52c6747f2d9ba787adec9`。
最初の補足readerのstate label schema相違は保持し、固定済み実FULL proofの_8DA1へ修正した。
製品runは再実行していない。元12 RELEASE runtimeが残るため、mint/burn子条件はまだ閉じない。
