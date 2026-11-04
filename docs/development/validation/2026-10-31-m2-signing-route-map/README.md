# M2署名経路と既存テストの対応確認

2026-10-31 (Asia/Singapore)。安全判定で停止した対象を除き、M2の実署名経路と
既存テストを対応付け、実装・検証の不足を整理してcommit/pushする依頼への記録。
security auditや新しいbackendの設計・実装ではない。

## Sourceと変更

main `8a5cc30a1d4a6166c6a69e720713252112817833` を取得・照合し、既存checkoutを使い、
`codex/m2-signing-route-test-map-1031` を作成した。他のactive agent/producerがいないことを確認した。
source commit `2e2c10fe0c360f99400be79ee50cad18f5e2336f`、tree `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e`。
[PR #340](https://github.com/sunriselayer/sunrise-edge/pull/340) はmain向けReadyで作成・push済み。

変更は次のarchitecture文書3件、173 additions /7 deletionsだけ。
runtime・test・selector・依存・authorityやcanonical bytesに変更はない。

- `docs/architecture/signing-route-test-map.md`: 6 logical entries /7 prepared types、
  actual CLI、selected client backend、automatic authority、readiness/genesis、exact test ownerと証拠の限界。
- `docs/architecture/signing-preparation.md`: generic local/paidのcustody拒否と専用routeを区別し、
  古いtransfer-only説明を後続DR-0249/0253/0255/0258/0261/0269とprotocol workersへ対応させた。
- `docs/architecture/README.md`: 対応表への導線。

既存判断の対応整理なので新しいADRや必須gateは追加せず、live statusはcanonical TODOだけに記録する。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を維持した。

## 対応確認と文書検証

2担当へ独立したread-onlyのSDK/CLI/testとselected lifecycleの対応確認を英語で分担した。
rootがコードと既存記録を照合し、文書作成後にも両担当で通常の文書correctness確認を行った。
publication-genesisのcore70と両application profileのsetup47の所属、foreign split probeのfile、
certified test moduleへの参照を修正した。停止済み監査の再試行やsecurity assessmentではない。

ローカルMarkdownリンク250件のdestinationと、記載した関数74個の存在をtracked Rust 775 filesで確認。
ASCII括弧、`git diff --check`、staged diff checkも成功。初回の補助checkerはoutput tag/module名を
関数とみなしたため、その2 tokensを区別して修正した。製品の失敗とは扱わない。
対応表のSHA256は `7fae61f9c331790117e28a196c1ce333c05aaa2f8ca9f1744cfd852cfcc39291`。
これらはsource対応の検証であり、記載したRustテスト74個を今回実行したという意味ではない。

実行済みfamily証拠は、既存canonical commit `395dbb1d` のE-recordと3件の復旧consumer記録へ
source/profile付きでリンクした。祖先sourceの成功を新しい文書commitのruntime成功にはしていない。

## 完全requiredの実試行と環境停止

AGENTS.mdの要求に従い、新しい専用runでliteral
`npm ci --prefix adapters/cloudflare-workers`、続いて `./scripts/check-all.sh` を実行した。
既存Node24.19.0、tools/target/cacheと変更していないretained wrappersを使用し、直接Wranglerは呼んでいない。
source/target/cacheの別producer不在を確認してから、専用user unit内で実行した。
12GiB/no-swap/CPU400%/Tasks512、npm300秒/required26000秒、全体28200秒内のcleanup300秒、
各stream64MiB/合計256MiBの有限上限を実cgroupから確認した。追加runtime/cacheのinstallは行っていない。

実行時間は2026-10-31T03:15:16.777171Z–03:15:56.149886Z、39.384秒。
`npm ci` はactual0/両EOF/wait、requiredはactual1/両EOF/waitで終了した。
gate contract、native-evidenceの151 mock controls、PG cleanupの43 mock controlsの後、
Cargo wrapperの `private directory identity differs: target` でRust検証前に停止した。
Rust tests、recurrence、Cloudflare等のlocal完全required成功は主張しない。
151 controlsはZERO native builds、43 controlsはreal Docker operationなしと原出力にも明示されている。

停止後のread-only照合では、旧wrapper coreの全7 directory pinsのdeviceが52、現在値が53で、
inode/UID/mode0700/type/canonical pathは一致した。target inodeは47881681。
host bootは2026-10-31T02:02:38Zで、再起動/remount後のdevice番号変更と整合するが、
この推測だけでfilesystem/cache内容の連続性を受入済みにはしない。
cf wrapperのdevice52 closureにも別のmetadata pinsがあるため、device検査を一括無効にする修正は行わない。
修復する場合は旧証拠を保持した新しいtask-owned admissionとして扱う。

rootは10 commands/20 streams、256704 captured bytesの全length/hash/EOF/waitを確認。
tracked source全1246 filesの前後snapshotはbyte-identicalでclean。
source snapshot SHA256 `25d7ab59b349e0fd493a15e281b9637d46025744abc9bc47e5cd63fd7131ab59`。
owner PID59969と既知10 command PIDs、専用cgroupの不在を確認し、failed unitの状態を解除した。
生きたlocal validation processは残していない。失敗を消したり、旧pinを現在値へ黙って変更して再実行していない。

原証跡は `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/` の
`m2-signing-map-1031-launch.json`、`m2-signing-map-1031-run-v1/`、
`m2-signing-map-1031-run-v1-verified.json`、専用service stdout/stderr。
result SHA256 `441fe611142b023dca90b8146cfce1f2fd52e07606a585622c8646580067cb4a`。

Hosted [run41163320441](https://github.com/sunriselayer/sunrise-edge/actions/runs/41163320441) は別の実行。
記録時点でlint/readiness-sqlite/portable-toolsはsuccess、他4 lanesはin progress、
aggregate checkはまだ生成前。全8CIの成功とは扱わず、結果を先取りしない。

## 不足の結論

今回の範囲で新たなselected consumerの配線バグは特定していない。
直近の同一鍵recovery接続を未達へ戻さず、共通prepare/finalizeやfakeの存在をprotected対応とも数えない。
具体的な残件はcanonical TODOの対応表に記録した。
対象family/consumer契約の確定、選択した場合の未接続backend、必要とする新identityへの正の権限移行、
最終範囲と実検証の帰属はそれぞれ別の判断・作業である。
ローカル完全requiredは上記環境停止のため未達、hosted CIは記録時点では未完了。

ZeroShare WIP/fixture、停止済み独立監査、torn-WAL/mechanism2、独立anchor guestは再開していない。
実鍵・user/security policy変更、deploy、main merge、新しいautomationは行っていない。
