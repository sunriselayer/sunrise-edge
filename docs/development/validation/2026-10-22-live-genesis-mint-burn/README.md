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

[CI run 39775926228](https://github.com/sunriselayer/sunrise-edge/actions/runs/39775926228) は終端待ち。
元7epochs/e8・8links/35roleのsource補足も、同CI終端後の別照合として残す。

fresh 13-target RELEASE A/Bは16:19:17 UTCに開始した。対応するCLI fixtureと
元12 RELEASE runtimeは未実行。A/Bは実終了・生成物照合待ちであり、成功には数えない。
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

A/Bは元8GiB/swap0/CPU4/tasks512・7200秒の上限、13 targets・2 fresh compiler lanesを維持する。
Invocationは `1d02e0c3983e4c51b79f01e0a43b84d2`、開始時owner PID1607616。
このproducerがC/cache/tools/targetを専有し、終了・PID/cgroup解放まで他writerやbody readerを作らない。

新しいcompiler/driver outputsは元の専有external directoriesに生成し、source checkoutは
全runtime・終了後照合・PID/cgroup/lease解放の後にcleanを確認して削除する。
限定componentと完全gateだけで新mint/burn子条件・親M2/M3/M7を完了にしない。
停止済み監査・ZeroShare WIP・partial persistent-write/anchor guest対象は再実行していない。
