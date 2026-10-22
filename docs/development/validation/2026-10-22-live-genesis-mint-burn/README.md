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

## 同sourceの残るgate

`genesis-mint-burn-full-required-1022` は12:38:31 UTC開始。
literal `npm ci --prefix adapters/cloudflare-workers` と `./scripts/check-all.sh` を、
元の26000秒work +300秒cleanup・12GiB/swap0/CPU4/PIDs512で単独実行する。
現時点ではnpm ci成功、check-allは実行中であり、完全gateの合格は未確定。
[CI run 39775926228](https://github.com/sunriselayer/sunrise-edge/actions/runs/39775926228) も終端待ち。

fresh 13-target RELEASE A/B、対応するCLI fixtureと元12 RELEASE runtimeも未実行。
元のclean source/no-target/no-extra guardを守り、既存のS target/node_modulesを移動しないため、
完全gate終了後に同じcommitの小さな専用checkoutを1個だけ作成する。
追跡sourceのlogical bytesは26,617,053であり、cache/target/node_modulesはコピーしない。
新しいcompiler/driver outputsは元の専有external directoriesに生成し、source checkoutは
全runtime・終了後照合・PID/cgroup/lease解放の後にcleanを確認して削除する。

限定componentの成功だけで新mint/burn子条件・親M2/M3/M7を完了にしない。
停止済み監査・ZeroShare WIP・partial persistent-write/anchor guest対象は再実行していない。
