# Sunrise Edge: 実装・検証・公開準備

更新: 2026-10-27 (Asia/Singapore)。これは唯一の現行作業表です。
設計は[architecture](docs/architecture/README.md)、実装場所は
[code map](docs/development/code-map.md)、整理の決定は
[DR-0236](docs/architecture/decisions/0236-separated-code-verification-and-launch-tracking.md)に置きます。

## この表の読み方と件数

旧20項目は「R1-R4の4件 + Delivery 4の8件 + M1-M8の8件」です。
20個の未実装機能という意味ではありません。元のIDを維持し、
Delivery 4の8件には順番どおりD01-D08を付けました。

- コード・検証対象: **14件** (R1-R4、D01-D03・D05、M1-M5・M7)。
- 公開準備対象: **6件** (D04・D06-D08、M6・M8)。実装キューとは別です。
- 再開後: **旧20件のうち9件完了、11件未完了、既存の完了履歴は9件**。
  再分類・延期・重複する検証の共用を、機能の完了件数には数えません。
- R1・R2・R3・D01は、保存ソース・欠落資料・実際のCI tested treeと
  完了したrecipeの最終照合および独立source reviewを終えました。
  R1/R2/R3/D01の完了は `c69fa2f0` の各行の技術範囲です。D03は現在の50a4の
  locked advisory reviewと修正版実体・互換性の確認を終えました。各sourceの技術範囲と
  main統合・独立security監査・公開認定は区別します。
- R4は `537c8777` のE17/E18/E19で13-targetの技術handoffを完了しました。
  旧local完全gateの終端未確認E20は保持し、新しいM2 sourceの完全gateはE22で成功。
  M2/M3/M7・公開条件は未完了のまま保持します。M4の選択済み技術範囲はE152で完了。
- D05/M5の選択済みNative/closed relayの技術範囲はE71/E73で完了。
  選択した8件 (D02/D05/M1/M2/M3/M4/M5/M7) は3件完了・5件未完了です。
  残るコード・検証の親項目はD02/M1/M2/M3/M7の5件です。
  M4はexact `5f6b1819` の選択済みNative+SQLite/trusted-local-OS範囲をE152で完了しました。
  元M5の実PKI・capacity・alerts・運用の公開条件はD04/D07/M8に残ります。
  継続中の統合変更は[Draft PR #320](https://github.com/sunriselayer/sunrise-edge/pull/320)。
  このDraftの存在を完全required/CI・Nativeまたは親項目の完了には数えません。
  positive Splitとcertified FastVoteの追加実装は、別の統合branch
  `codex/positive-certified-integration-1017` の `3b4aa7ff` に通常mergeしました。
  追加UID fixtureはE128/E129で選択範囲の実行・照合が完了しました。
  7658の完全required・全8 CI・原12 RELEASE runtimeはE131/E132で終端成功を確認。
  その後の `e6f1dfe3` は13-target A/Bと23バイナリのbuildが成功しましたが、完全requiredは
  checkpoint authority再openの1件で失敗しました (E133)。この失敗を成功へ上書きしません。
  後続`5f6b1819`はcheckpoint test-only隔離の対象prefix、13-target A/B・23 driver/H6 producer、
  scoped TLS15 +実old upgrade1・同source RELEASE CLIまでactual qualificationを完了しました
  (E136-E139)。T/Gの旧e6f1に対する3/4-file bridge付き実行と、C/MBの5f6bに対する
  3/4-file bridge付き同一鍵historical recoveryも確認しました (E140/E141)。
  同一鍵復旧の追加source `ad3ce3a0` / tree`d3fdc54a` は[Draft PR #323](https://github.com/sunriselayer/sunrise-edge/pull/323)。
  W5f6bのliteral npm ci +完全requiredは全commands actual0で完走しました (E150)。
  同5f原12 RELEASE runtimeも全12 cases・98 passed/0 failed/3 ignoredで完走しました (E151)。
  MBのliteral npm ciは成功。旧ad3の完全requiredは、後段の直接Wrangler呼出しを避けるため中断しました (E157)。
  移行済みe4fbのcf版完全requiredはE162、50fbはE167で成功。旧ad3の途中結果は全体成功へ加算しません。
  [Draft PR #321](https://github.com/sunriselayer/sunrise-edge/pull/321) の全8 CIはE142で成功を照合。
  [Draft PR #322](https://github.com/sunriselayer/sunrise-edge/pull/322) は全8 CI成功を実ログ/checkoutで照合 (E152)。
  #323は全8 CI成功をraw/checkoutまで照合しました (E160)。旧local中断E157は保持。
  #324も全8 CI成功をraw/checkoutまで照合しました (E161)。
  #325も全8 CI成功をraw/checkoutまで照合しました (E168)。
  正のgenesis Coin A→B→A移行は `fe542b82` に追加し、strictと新H7 producerは成功。
  新13-target A/Bは両laneの全13 ELFのbyte一致・source/provenance照合まで完了しました (E145)。
  追加fixtureの2回の実失敗を保持し、private exportのumaskとtransient予約のAbsent oracleを修正。
  `f6b5ffab`の新H8・fresh lddの後、実fixture全117 flagsが成功しました (E146/E149)。
  Cloudflare CLIへの5-profile統一は実npm ci・typegen・10拒否controlsに加え、修正後の
  型照合・TS・lint・全4 Vitest計66 testsまで成功しました (E147/E148)。
  新source `e4fb6e55` は[Draft PR #324](https://github.com/sunriselayer/sunrise-edge/pull/324)。
  同headのliteral npm ci・local完全required・全8 hosted CIは終端まで成功を照合しました (E161/E162)。
  この文書更新は別worktreeで行い、実行中のsource/HEAD/TODOは変更していません。
  E133の自然失敗原因は未確定で、旧失敗と当時source-onlyだったE134/E135を保持します。
  祖先の成功を新source全体の合格へ付け替えず、全M2/M7は未完了です。
  追加の公開advisory照会でRustls 0.23.45に4件を検出し、別branchで0.23.46へ更新しました (E153)。
  更新後311 locked versionsのOSV応答は該当0件。修正版の[Draft PR #325](https://github.com/sunriselayer/sunrise-edge/pull/325)
  exact `50fbf22d` は完全5-group PG/集約check・fresh13-target A/B・current CLI全117・
  fresh23/full49 compile-only・TLS/実prior upgradeをE154-E156/E158で完了しました。
  原12 RELEASE runtimeも全12 cases・98 passed/0 failed/3 ignoredで終端成功を照合しました (E164)。
  追加2 harnessの7 compile/syntax/lint gatesはE163、ordered/certified別UID・TLSはE166で成功。
  同sourceのliteral npm ci +完全requiredはE167、全8 ordinary CIはE168で実終端まで
  照合し、Rustls更新のsource qualificationを完了しました。旧sourceの合格を借用しません。
  `50fbf22d` の既存ENOSPC全5 casesも新しい所有実行で成功しました (E169)。
  他者へのgenesis部分分割と受取Coin返送のsource `c6807388` は、元117と追加21を
  同じ上限の独立profileへ分離し、両方の実owningに成功しました (E174)。
  fresh H10の実build元は8a90のまま、MJS/guideの2-file bridgeで対応付けています。
  旧combined失敗E172/E173は保持。同headのliteral npm ci +完全requiredはE183、
  全8 hosted CIの実ログ・checkout tree/parents照合はE184で成功しました。
  [Draft PR #326](https://github.com/sunriselayer/sunrise-edge/pull/326)。全M2/M3/M7の完了には数えません。
  application Coin kind2の同一鍵historical recoveryは `7663e0ab` で実owning成功 (E177)。
  [Draft PR #327](https://github.com/sunriselayer/sunrise-edge/pull/327)。初回の表示照合失敗E176は保持し、
  同sourceのlocal完全requiredはE185、全8 hosted CIはE186で成功。別source `d0128975` は、全完了PTYの集計と
  明示core/application分離で元117の全判定を別実行のまま保持して実owning成功 (E179)。
  後続 `f51bee72` はapplication kind3のsplit/merge同一鍵historical復旧も追加し、
  fresh inventory・core70・split21・application kind2/3各57を別実行で成功しました (E180)。
  [Draft PR #328](https://github.com/sunriselayer/sunrise-edge/pull/328) に保全。D全体gateはE188で失敗、全8 hosted CIはE189で成功しました。
  同f51の新fresh13-target A/Bは、全26 ELFの13組完全byte一致・実producer/source/tool/
  dependency照合と終了回収まで成功しました (E181)。今回生成した同source CLIでもfresh inventory・
  core70・split21・application kind2/3各57の実owningと全raw/終了回収を照合しました (E182)。
  同f51の元12 RELEASE runtimeも98 passed/0 failed/3 ignoredで完走し、fresh23/current49・
  全raw/実終了・後片付けをrootで照合しました (E187)。E188の旧D完全required失敗は保持します。
  手動作業で検証CLIを専用コピーへ分離し、元5-profile型生成をE190で完了しました。
  同f51の新規source/cache/targetでliteral npm ci +完全requiredが全actual0で完走し、
  Rust4,397 passed/0 failed/43 ignored・CF66件と元7epochs/e8をrootで照合しました (E191)。
  local完全required・全8CI・元12RELEASE・13-target A/Bが同じf51でそろいました。
  残る独立監査・signing family/lifecycle・SQLite faultの未達を解消したとは扱いません。

2026-10-22追記: 復旧済み同一鍵のgenesis split/mergeと、参照body付きACK喪失後の
正常再起動・同一要求再送の2子条件を、同じb389 sourceのE206/E208/E209で完了しました。
同日の次作業として、元M2 recovery条件からgenesis mint/burnのlive復旧鍵consumerを
1子項目へ細分化しました。現行チェックボックスは **85個中70個完了・15個未完了**。
残る15個はコード・検証の親5件、停止中の子3件、検証中のmint/burn子1件、公開準備の親6件です。
旧20親項目の9完了/11未完了は変わりません。

チェックは各行に明記した「対象」の完了を示します。実装があること、
単体テストが通ること、公開できることは別です。混在していたM2/M4/M5の
実鍵・オフホスト運用・本番PKI等はD04/D06/D07/M8の公開条件へ対応付けます。
コード側が完了しても、対応する公開条件が未完了なら元の総合readinessは未完了です。
実鍵運用・実genesis・公開判断を、パラメーター化したコードの実装待ちにしません。

[移行前全文と全ての原条件](docs/development/history/todo-before-reconstruction-2026-10-13.md)
および[元ロードマップ](docs/development/history/roadmap-through-2026-10-06.md)は保存済みです。
以下の短い記述は索引であり、原条件・失敗履歴を削除するものではありません。

## ソースと作業環境の保存状況

| 対象 | 現在確認できた事実 | 扱い |
| --- | --- | --- |
| main | `ffcf5767`。PR #299の正常merge。作業ツリーはclean | 既存の統合済みbaseline |
| 復元修正 | `c69fa2f0` / `codex/fresh-slash-evidence-1011` はGitに残存。PR #301の対象 | mainへ統合済みとは扱わない |
| Blob強制停止テスト | `f093fb6c` / `codex/blob-crash-1013` はGitに残存 | c69の総合テストに含めない |
| 署名試作 | `codex/publication-review-1013` のHEADはc69。試作は未コミットだった | 現在の回収可否は不明。実装済みとは扱わない |
| 旧作業コピー・専用キャッシュ・raw検証資料 | 人がキャッシュを手動削除したと以前のチャットで確認。旧パスは不在 | 未コミット署名試作・ローカルrawは未回収。Git登録はファイル残存の証明ではない |

2026-10-13の再開時に以前のチャットを照合し、人がキャッシュを削除したと確認しました。
再構成時は原因不明でしたが、現在の消失原因は手動削除です。
コミット済みソースは残存し、今回の統合先はキャッシュ外の
`/home/yu/src/github.com/sunriselayer/sunrise-edge-todo-completion-1013`、
ブランチ `codex/todo-completion-1013`、起点は指定された `f655bd40` です。
未コミット署名試作と削除されたローカルraw資料は未回収です。
旧検証用home/targetのidentityを復元したとは扱いません。
保存済み `f093fb6c` は `3a5c8249` としてこのブランチへ統合済みで、mainは未変更です。

実装のDraftは[PR #302](https://github.com/sunriselayer/sunrise-edge/pull/302)、
M7の限定修正はその上の[PR #303](https://github.com/sunriselayer/sunrise-edge/pull/303)、
Node 24対応・復旧reproducer修正・R4 handoffは
[PR #304](https://github.com/sunriselayer/sunrise-edge/pull/304)です。
R4の実装qualification対象は `537c8777870f7b304f5373afde4dd2cb147c420d`、
tree `f079832474ccd1ad4fe7ad4f29743dae24b843c7`。専用作業コピーは
`/home/yu/src/github.com/sunriselayer/sunrise-edge-release-handoff-1014` です。
source qualificationは同一treeのhosted E17、Native A/BはE18、実RELEASEの
手順検証はE19に記録します。local完全gateの終端は未確認としてE20へ残します。
R4の後続状態文書だけの更新も、この13-target qualificationの対象pinを537cに保持します。

publication承認取消・鍵復旧/交換は、その上の[PR #305](https://github.com/sunriselayer/sunrise-edge/pull/305)。
publicationのM2実装sourceは `1b796c3c1d516837797d840ff663c5d0c40fb363`、
tree `ecfebae57054b524d2a8a7af5c34c9110663ae0d`。作業コピーは
`/home/yu/src/github.com/sunriselayer/sunrise-edge-custody-lifecycle-1015` です。
対象別のcustody検証はE21、local完全gateと同一treeのhosted CIはE22。
このsourceを537cのNative A/B・実RELEASE artifactとして扱いません。
fee-claimの非承認表示・保存内容の開発用署名は、その上の
[PR #306](https://github.com/sunriselayer/sunrise-edge/pull/306)。対象は
`cf2dd35fb488377e0d8584fc19144f44e48707ad` / tree
`01bcfe95ec91b882ebf6bd8424c733514afa924f`、作業コピーは
`/home/yu/src/github.com/sunriselayer/sunrise-edge-fee-claim-review-1015`。
限定検証はE23、local完全gateと同一treeのhosted CIはE24で成功しました。
後続の状態文書だけの更新も、実装qualificationの対象pinをcf2dに保持します。
このsourceの新しい13-target Native A/B・実RELEASE認定は行っていません。
CODE/VERIFY 8件の継続作業は[PR #307](https://github.com/sunriselayer/sunrise-edge/pull/307)
の `426e8359` / tree `b7fa71cd` に、genesis Standard Asset transfer専用custody・
待機中workの取消・旧host生存中のfence拒否を固定しました。component controlsと
Native A/B・RELEASE CLIはE25-E27で成功。同一treeのhosted CIはE36で全8 jobsが成功。
ローカル完全requiredもE38で終端成功を確認しました。
後続の[PR #308](https://github.com/sunriselayer/sunrise-edge/pull/308) は
`b568037f` / tree `2a691d63`。recovery/ordered contextの追加停止確認と、importの
独立history floorを実装し、対象Native HTTP 206件、parse/comparison 12件、
compiled import全10件、手動構成SQLite/HTTP全3件・Clippyが成功しました。
これは本番host constructor/signalの配線証明ではありません。完全required/CIはE42/E39で成功しました。
同sourceのNative A/Bと、RELEASE childでのimport全10件はE28/E29。
正常停止TLS交代後の新規取引はE30 / `4312d547`、後継live/historyの停止確認は
E31 / `e60337b3` とE32 / `92fd5c93` に固定し、それぞれDraft PR #309-#311で確認できます。
分割・結合custodyの最初のcomponent sourceはE33 / `bcb9a1c9`。
これらを `codex/coin-ops-custody-1016` へ通常mergeした統合sourceは
[PR #312](https://github.com/sunriselayer/sunrise-edge/pull/312) の `7c5778b0` / tree `710b4c3d`。
対象9 commandsと実Dockerを再検証し、Native A/BをE34、実RELEASE CLIをE35で確認しました。
同sourceのhosted CIはE46で成功し、元10 whole + 2 exact ignoredのR4 RELEASE runtimeは
最後のcaseで共有時間上限に達して失敗しました (E47)。全R4成功には数えません。
E28/E29のsourceに後続差分を含めたことにはしません。
復元の追加拒否と後継floorの統合code sourceは `53e324c1` / tree `499ef2e8`、
`codex/successor-floor-1016`。E37の対象検証は成功し、後継floorのlong case・
当時未終端だった後継floorのlong case/CIはE53、277fの完全requiredはE63で成功。
原12 Native runtimeはE57の失敗として保持します。後続4 sourcesの完全required/CIは
E68-E71、b4のtest-only CIはE72、D05/M5の技術最終照合はE73へ記録しました。
M2/M3/M7全体・独立監査・公開条件は未完了です。M4の選択済み技術範囲はE152を参照します。
9de6の原12 RELEASE runtimeはE92で全actual0/実EOF/waitを確認しました。
7658の別の原12 RELEASE runtimeと完全required/CIはE131/E132で終端成功を確認しました。
元12ケース・共有18,000秒・CPU4/16GiB/swap0を維持しています。
後続e6f1の完全required失敗E133は保持します。5f6bの対象prefix/Native build/TLS/CLIはE136-E139、
追加recoveryの範囲はE140/E141。旧MB完全requiredはE157のpolicy中断として保持。旧MB CIと移行済み最終source完全required/原12の終端照合は未完了です。
初回DockerのSQLite祖先directory読取EACCES、manual fixtureのsetup counter誤り、
import testのsource retirement不足と各修正前失敗も保持します。
50a4 / tree eff704ddのE14-E16と旧作業コピーは過去の対象として保持します。

再構成時の確認ではGitの作業コピー登録が存在する一方、そのパスがENOENTでした。
当時は原因未確定でしたが、その後のチャット照合で手動削除を確認しました。今回の文書編集は
キャッシュ外の専用作業コピーで行い、main・履歴・既存ブランチを変更しません。

復帰作業は次の2件です。製品機能の完了数には含めません。

1. コミット済みソースを保全し、未コミット署名作業・検証資料の退避先を確認する。
   回収不能なら、既に取得済みであるかのように扱わず、欠落範囲を明示する。
2. ローカル実行環境を再成立させる。失われた専用home/targetのidentityや古い実行入力を
   新しいものへ黙って置換しない。既存の取得・検証・資源上限を維持して別途扱う。

## 確認済みの結果と未達部分

E1-E4は以前実際に読んだ記録です。失われたrawを回収したとは扱いません。
E5以降の新しいrawは専用validationディレクトリに保存しています。各source/profileの
範囲を区別し、祖先の成功を新しいソースの全体合格へ転用しません。

| 証拠 | 以前確認した結果 | 未達・限界 |
| --- | --- | --- |
| E1: c69 required | `validation-90e28db0e9a6421594d8e2451d9ddefc`。exit 0、13,135.63秒。元の8リンク・e8 withdrawals・35暗号化rolesを維持したsource-unavailable復元を含む | main未統合。raw所在不明。オフホスト鍵運用・power/cross-file atomicityの証明ではない |
| E2: selected PG | `validation-9999f12b88c94f6987e84dcbe6d409cf`。5グループを実行しexit 0、766.16秒。前後のソース対応も確認済み | 別ソース・新しい依存には転用しない。PG-every-PRには戻さない |
| E3: Blob owner-loss | `validation-0fed3d1a6460413294be623cb89e7fb1`。Dockerの1ケース合格、512MiB/no additional swap、64MiB noswap、所有資源cleanup確認 | AfterCommitの全fixture所有者SIGKILL。interrupted COMMIT/power/fsyncの証明ではない |
| E4: 署名試作 | `validation-892dea33e428435cbd7a586326984566`。SDK 8ケース合格後、operatorコンパイルがENOSPCで停止 | operator・CLI・5ケースDockerの一連実行は未完了。試作ソース回収可否も不明 |
| E5: c69 CI | [run `38339555677`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38339555677)、対象 `c69fa2f042c498c38440f0b100f0146f093d11a7`。7 unconditional owners + success-only checkの全terminal success | main未統合。f093や今回の新しい署名consumerの検証結果ではない |
| E6: c69 final照合 | 独立Opus source reviewでR1/R2/R3/D01の各技術範囲を確認。rootが完全hostedログとGitHub commit APIを別に照合 | CI checkout `e63abd5e099361e8d1b3d886c1987008f7cb5bd3` のtreeはc69と同じ `10cfe7dd8b7802557288b00146572109ad7dab0b`。parentsはffcf/c69。欠落したローカルrawを復元したとは扱わない |
| E7: 新しいSQLite owning | f093統合後のblob outer controlが成功。helperのinert通常呼び出しを含む2 passed/0 failed。続くSQLite libは98 passed/0 failed/5 ignored | Rust 1.97.1、locked/offline、共有cacheはread-only namespace、新規target。4GiB/no swap/1 CPU/128 PIDs。host/power/media/fsync・Docker ENOSPCの新規合格ではない |
| E8: 新しいSQLite ENOSPC | 既存5 ignored controlsを各1回のfresh Docker allocationで実行し、5 passed/0 failed。outer service exit 0、21.45秒、各回のexact owner container/volume releaseを確認 | E7の同じSQLite test executable (SHA-256 `e4f75d8f315fda4f40082600c928df59f510442f22d9043a8198a38704b9edda`) を使用。SQLite crateに3a5c8249→d5395ba6の変更なし。512MiB/no additional swap、64MiB noswap、64 PIDs、1 CPU、network none。全体required、power/host/media/fsyncの証明ではない |
| E9: publication-only local OS custody | 独立source reviewで指摘を処理し `64a42475` を承認。親がcompiled CLI lib 274 passed/0 failed/1 ignored、preview/export 8 passed/0 failedと実Docker/UID/PTY fixtureを別に実行。UID分離・private key/approval拒否・正当な署名・各拒否・再起動同一signatureを確認 | CLI/libは54869f26、fixtureは46aad542、exportは49ab0964の対象範囲。実UID 12001/12002/12003、512MiB/no additional swap/64 PIDs/1 CPU、64MiB noswap volume、network noneをkernelで確認。署名1・拒否4、restart署名1、exact owner container/volume release。scripted PTYであり実ceremony・実publication submit・全M2の合格ではない |

E9の新しい試験では、既存Ledgerエラー文言の変更、empty ABI/invalid WASM、
preimage権限・Docker metadata表記・`--tmpfs` のnoswap非対応を実際の失敗で確認して
修正しました。元のWASM/ABI/UID/fault checksは弱めていません。
managed volumeは既存ENOSPCと同じ方式を使い、合格ログ `custody-os7.log` と
失敗ログを専用validationディレクトリに保存しています。clippyの指摘もlint overrideを
使わず修正し、全target/all-feature Clippyも成功しました。5672の再実行はE13、
その全体requiredはE11、現在50a4の全体requiredはE14に記録します。

M7の固定Node 22.20.0は未導入だったため、人が別の限定取得を承認しました。
公式archiveのSHA-256と30,737,976 bytesを照合し、生成153,921,504 bytes /
gross I/O 184,659,480 bytes / 3 artifact files / 6.38秒で取得が完了しました。
network/archive 32MiB、Node本体128MiB、生成192MiB、gross I/O 512MiB、
300秒と5GiB観測の新しい上限内です。Node file hash/0755/current UIDと
実際の `v22.20.0` を確認し、共有cache・既存Nodeは変更していません。
取得単体は13-target A/Bの証明ではありません。311 locked registry packagesの
archive/展開sourceを検証し、共有cacheへの書き込みを許さない入力viewを別途準備しました。
欠けていた2 packageのsourceは正式archiveから専用ディレクトリだけへ展開しました。
専用clean checkoutと直接の固定toolchainによる実A/Bは5672のE12と50a4のE15です。

`d5395ba6` の新しい5-group PG実行は最後のfixture exportで失敗しました。
task-local Cargo wrapperが `SUNRISE_EDGE_ESCROW_FIXTURE_DIR` を継承しなかったことを
実際のpanicとdriver照合で確認しました。rawログを保存し、成功とは扱いません。
owning live testsとlifecycle/drain-history/business-auditの部分成功は全体合格へ転用しません。
生成owner `c05374cd203b1e743d19b7f69aeb6a2a` のcontainer/volume残存がないことを確認しました。
compiler serviceの4GiB上限はreclaimを観測して6GiBへ変更しましたが、Dockerの
512MiB/no additional swap上限は維持しました。wrapperには閉じたfixture変数と
task-owned temporary outputだけを追加し、SQLiteのexport→compiled inventoryの
同じscriptがexit 0で完了しました。その後14fb7410で全5グループを最初から再実行し、
exit 0を確認しました (E10)。5672全体のPG acceptanceへは転用しません。

E5/E6の実recipeは、core recurrence 1 passed/0 failed、readiness SQLite
1 passed/0 failed、compiled recurring SQLite 1 passed/0 failed (21,192.42秒) です。
exact selectorは閉じたregistry/recipeで一つのtestへ結び付き、quiet出力のdotだけでなく
本物のe8 terminal-unlock、saved-closure pack/openと既存8-link/35-role assertionsの
sourceも照合しました。通常rust-testsに含まれるauthor/inspection/four-store/TLS/CLI/
bad-pin/refusal/restartケースの実test成功も確認済みです。

今回の新しい専用キャッシュはキャッシュ外の
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013` に分離します。
保持されている共有キャッシュの非秘密metadata・lock checksum照合で、46パッケージに
archiveまたは展開済みmanifestの不足を確認しました。ネットワーク禁止の新しい限定ビルドは
`age` のindex不足でexit 101、compiler前に停止しました。失敗を成功扱いしません。
復元は別途source reviewした取得処理で行い、lockと共有cacheを変更せず、以前の
32MiB network / 16MiB per file / 700 files / 128MiB生成 / 512MiB gross I/O /
256KiB evidence / 300秒と5GiB観測監視の上限を維持します。
既存展開sourceへの明示参照は新しいofflineビルドの入力であり、古い専用cacheの復元や
M7のfresh A/B・provenance合格を意味しません。
取得はexit 0、network 5,991,554 bytes / gross I/O 116,957,679 bytes /
生成25,915,058 bytes / 599 files / 3.61秒でした。観測した最小空きは
266,264,657,920 bytes、最大観測間隔0.116秒。全checksumをlockと照合し、
所有serviceは終了・回収済みです。コンパイラ入力はbwrapで共有cacheをread-onlyにし、
不足archiveもread-onlyで同じoffline入力viewへ結び付けています。

以前のopaque Quota失敗の唯一の原因は未確定です。有限の観測予算修正・
再現コントロールとE1の成功は、失敗履歴を書き換えません。
Btrfsの管理領域逼迫を以前観測しましたが、後の容量状態は改善しています。
現在の所在不明と容量変化の原因を、この情報だけで断定しません。

| 新しい証拠 | 対象と結果 | 限界 |
| --- | --- | --- |
| E10: complete PG profile | `14fb7410`、pg-storage/lifecycle/drain-history/business-audit/recovery-economics全5グループ、exit 0、2,492.184秒。80 pass summaries。exact ownerのcontainer/volume残存なし | shared依存更新を含むこのsourceのlocal profile。繰り返しowning実行を合算した1,434 passedはunique test数ではない。5672・実provider・物理faultの証明ではない |
| E11: complete required | `14fb7410` のliteral npm-ci +完全check-allはexit 0、13,584.298秒。続く `56727192` の同じ全体gateもexit 0、14,318.546秒。core 535.70秒/readiness 29.35秒/recurring 11,423.56秒、元8リンク/e8 withdrawals/35 rolesのpack/open/source-free restore成功 | 古い成功を最新sourceへ転用しない。038bの途中実行は候補変更で停止し、成功に数えない。5672はliteral npm-ciから再実行。local requiredはPG/実provider/監査/公開認定ではない |
| E12: actual Native A/B | `56727192` / tree `15c2c0dd`、Node 22.20.0 / Rust 1.97.1 / Linux x86_64 GNU。fresh build 2回、13ターゲット全byte/mode/owner比較成功、exit 0、739.627秒。保存した26 ELF64のSHA-256を親でも照合。4一時ディレクトリとsource leaseを解放 | `native-local`、fixtureではない。同一ホストのtrusted OS範囲。cross-machine/hermetic/upstream authenticity・他provider・全M7/release認定ではない |
| E13: 5672 custody | `56727192`、CLI lib 281 passed/0 failed/1 ignored。fresh compiled CLIを使う実Docker/UID/PTY fixtureもexit 0、3.441秒。UID分離・秘密file拒否・署名1/拒否4・restart同一signature・exact owner releaseを確認 | E9と同じpublication-only/scripted PTY範囲。実ceremony・実publication submit・他family・復旧/rotation/revocationの完了ではない |
| E14: 50a4 complete required | `50a464c8` / tree `eff704dd`、literal npm-ci +完全check-allがexit 0、12,915.092秒、outer EOF/exit 0。core 452.93秒/readiness 23.67秒/recurring 9,709.47秒。元8リンク/e8 withdrawals/35 rolesのpack/open/source-free restoreと後続adapter checksを完走 | CI dev/test opt2、curve opt3、debug assertions/overflow checks有効、debug-info 0。case/待機時間削減なし。local requiredはPG/実provider/独立監査/公開認定ではない |
| E15: actual Native release A/B | `50a464c8` / tree `eff704dd`、固定release recipe。2 fresh builds/13ターゲット全byte/mode/owner比較成功、exit 0、709.267秒。26 ELF64のhashを親でも照合し、4専有directoryとsource leaseを解放 | Node 22.20.0 / Rust 1.97.1 / Linux x86_64 GNUの同一ホストtrusted OS範囲。CI dev/test opt2はこのrelease recipeに使っていない。fixture/cross-machine/hermetic/全M7/release認定ではない |
| E16: 50a4 locked advisory review | `50a464c8`、npm audit 0件、Cargo.lock全311 registry versionsのOSV query 0 matches。旧f655 npm lockの7 high entriesと旧Rustls 0.23.43の既知advisoryを同じ手法で検出。変更npm lock全69 entriesのdeclared licenseに変更なし。実loaded sharp 0.35.5 / libvips 8.18.7 / librsvg 2.63.2も確認 | point-in-time public advisory metadataと実体/宣言metadataの確認。独立security監査・legal clearance・低いMSRVのbuild matrix・実provider/公開認定ではない |


| E17: Node24 hosted source qualification | `537c8777` / tree `f0798324`。run `38528903004` attempt 1、7 required owners + checkの全8 jobs SUCCESS。全8 checkout `37e23bf9` の同一treeを実ログ/Git commitで照合。Node設定5 lanesは実v24.19.0。core/readiness/recurringは952.18/52.36/11,381.89秒で各1 passed/0 failed | sourceのrequired CI qualification。local完全commandの終端、PG、実provider、独立security監査、公開認定へ転用しない |
| E18: Node24 actual Native release A/B | `537c8777` / tree `f0798324`、Node 24.19.0 / Rust 1.97.1 / Linux x86_64 GNU。2 fresh builds、13ターゲット全byte/mode/owner比較成功、exit 0/outer EOF、861.388秒。26 ELF64/324,416,048 bytesを親でもhash照合。UMask0077の実mode0700を保持し、4専有directoryとsource leaseを解放 | 固定RELEASE recipe、same-host trusted OS範囲。modeを正規化していない。fixture/cross-machine/hermetic/upstream authenticity・全M7/release認定ではない |
| E19: R4 actual RELEASE runtime | `537c8777`、E18の13 readonly RELEASE child bindingsとdev/test opt2 oracleを分離。10 whole driversの報告pass合計84 + 2 exact ignored各1 passed、全12 actual exit 0/EOF。元8リンク/e8 withdrawals/35 roles、restart/refusal/delay、pack/open/source-free restoreを完走。実helper waitでexit 0、10,545.017秒。10 drivers/13 host debug/13 RELEASEの前後hash一致、1,451,827,200 bytes peak/swap 0、private run TMP・mount/PID/networkを解放 | local/dev-signerのR4技術範囲。全M2/M3/M4/M7、PG、実provider、独立監査、public/production readinessではない。in-process oracleはRELEASEへ差し替えていない |
| E20: Node24 local full terminal unconfirmed | `537c8777`のliteral npm-ci +完全check-all rawに143 Rust pass summaries/0 failed、core/readiness/recurring 564.11/27.60/11,119.93秒、66 workerd testsと全4 portable adaptersの成功を記録。wait clientのactual outer exit 143/EOF | main process terminalと全体command成功は未確認。回収済みunitのinactive/success/status0既定値を成功証拠にしない。terminalExit/allRequiredStepsExecutedはnullで保持し、local exit 0と呼ばない |
| E21: publication cancellation/recovery/rotation | `bc4d1a25` / tree `fc2fab91`、CLI build・custody 71 passed/0 failed/1 ignored・実Docker/UID/PTYが全actual exit 0/EOF。取消は同一serveとrestart・古いapproval復元後に拒否。停止後の同一鍵復旧は同一signature、新鍵/設定の両方向取り違えは拒否、新identityは独立approval必須。6 lifecycle summariesと元のUID/refusal/restart controlsを維持 | publication-only local trusted OS、scripted PTY。全store rollback耐性・既発行signature取消・on-chain account移行・他family/実鍵/実ceremonyは含まない。後続1b79の差分はテストのrustfmtだけ |
| E22: M2 complete required + hosted CI | `1b796c3c` / tree `ecfebae5`、literal npm-ci +完全check-allがactual exit 0/EOF、13,040.839秒。143 Rust success summaries/報告pass合計4,150/0 failed、core/readiness/recurringは505.25/26.47/10,730.31秒。元8リンク/e8 withdrawals/35 rolesのsource-free復元と全adapterを完走。[run `38607184408`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38607184408) attempt 1の7 owners + checkが全SUCCESS、全8 checkout `bbd4c95e` のtree一致を照合 | Node 24.19.0 / Rust 1.97.1、CI dev/test opt2・curve opt3、debug assertions/overflow checks有効、case/待機削減なし。local sourceは実行前後clean同一pin。PG/新13-target release A/B/独立security監査/実provider/公開認定ではない。旧E20はnullのまま |
| E23: saved fee-claim review components | `cf2dd35f` / tree `01bcfe95`、SDK fee-claim 23 passed、CLI fee-claim 4 passed、custody 73 passed/1 ignored、CLI buildと実Docker/UID/PTYが全actual exit 0/EOF、55.737秒。元のpublication controlsと6 lifecycle summariesを保持。独立correctness reviewと指摘処理済み | 非承認の内容表示・development signing。SDKのfocused renderer testsだけをhistorical committeeの認証証明にしない。private exportのparent判定はwriterと共通。初回の実行file mode0700によるDocker失敗を保持し、child umask0022で新しく生成した実mode0755を使用。chmod正規化なし |
| E24: fee-claim complete local required | `cf2dd35f` / tree `01bcfe95`、literal npm-ci +完全check-allがactual exit 0/EOF、14,049.412秒。143 Rust success summaries/報告pass合計4,166/0 failed、core/readiness/recurringは495.01/26.99/11,124.30秒。元8リンク/e8 withdrawals/35 rolesのsource-free復元と全adapterを完走。実Split/ZeroShareでseed-free保存→offline review/sign、legacy候補の全byte一致・別鍵/受取人/証明epoch/上書き拒否を実行 | local前後clean同一source、Node24.19.0/Rust1.97.1、dev/test opt2・curve opt3・debug assertions/overflow有効、case/待機削減なし。[hosted run `38674732337`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38674732337) attempt 1は7 required owners + checkの全8 jobs SUCCESS。全8 actual checkout `29f91118` / tree `01bcfe95` が対象sourceと一致。FinalTransferはfocused structural renderer coverage。PG/新13-target Native A/B・RELEASE/実provider/独立security監査/公開認定ではない |
| E25: transfer・queued stop・overlapping TLS components | `426e8359` / tree `b7fa71cd`。custody 78 passed/2 ignored、Standard Asset 17 passed、Native operations 7 passed、全12 actual TLS controls、CLI build、対象3 crate Clippy、実Docker/UID/PTYを含む全7 commandsがactual exit 0/EOF、255.769秒。元publicationと6 lifecycle、whole-coin transferの実SQLite/WASM実行・offline/CLI署名byte一致・receipt replay・取消を確認。前後source clean/input binary不変 | component qualification。原2 ignoredのfixtureはDocker ownerが別途実行。全M2/M3/D05/M5・独立監査・実provider/公開認定ではない。同sourceの完全requiredとhosted CIはE38/E36で終端成功 |
| E26: 426e actual Native release A/B | `426e8359` / tree `b7fa71cd`、固定Node24.19.0/Rust1.97.1/Linux GNU recipe。2 fresh builds・13ターゲット全byte/mode/owner比較成功、actual exit 0/EOF、858.399秒。保存26 ELFを親でも照合。生成umask0022の実mode0755を維持し、chmod正規化なし。4専有作業dirとsource leaseを解放 | same-host trusted OS。fixture/cross-machine/hermetic/upstream authenticity・全13 RELEASE runtime・全M7・公開認定ではない。後続sourceへ借用しない |
| E27: 426e RELEASE CLI custody | E26保存の実RELEASE CLIをE25と同sourceのdev/test harnessへ渡し、元publication・6 lifecycle・実transfer/取消/再起動拒否をactual exit 0/EOF、3.670秒で確認。CLIとharnessの前後hash一致 | RELEASEなのはCLI child。SQLite/WASM hostはdev/test harness内で動き、全13 RELEASE runtime qualificationとは区別する |
| E28: b568 actual Native release A/B | `b568037f` / tree `2a691d63`、固定Node24.19.0/Rust1.97.1/Linux GNU recipe。2 fresh builds・13ターゲット全byte/mode/owner比較成功、actual exit 0/EOF、931.235秒。親が保存26 ELFを照合。生成umask0022の実mode0755を維持し、4専有dirとsource leaseを解放 | same-host trusted OS。新しいfloor/stop sourceの実build証拠。cross-machine/hermetic・全13 runtime・独立監査・全M7/公開認定ではない |
| E29: b568 RELEASE import component | E28の13 readonly RELEASE child bindingsの隔離環境で、`business_import_sqlite` whole driver全10件/0 failed/0 ignored、actual exit 0/EOF、6.053秒。genesis import/create/resumeと追加history floor、既存借用controlsを保持。driver・13 debug・13 RELEASEの計27 binary hashとraw logを親でも再照合。PID/network namespaceの分離、owned pids 2→2、private TMP除去を確認 | child binariesだけがRELEASE、driver/in-process oracleはdev/test opt2。原12 drivers・2 long ignoredのR4 runtime全体、successor floorの個別end-to-end、全M4/M7/公開認定ではない |
| E30: fresh business after authorized stopped TLS rotation | b568上のこの差分。元の全assertion/helper/待機/資金を削らず、正常停止後に最終generation4で新規有料送金を実CLIから確定。全4 replicasの独立intent/両quorum・exact mutation/version/body・新旧receipt・nonce・exact再送/full snapshotを確認。元12 TLS cases、formatとoperator全target Clippyの全3 commandsがactual exit 0/EOF、40.845秒。独立correctness review指摘を処理し再承認 | selected stopped same-file handoffのcomponent。先のoverlap拒否fixtureとは別。live handoff/cross-host/物理fault・全M3/公開認定ではない。同sourceのhosted CIとlocal完全requiredはE39/E45で成功 |
| E31: successor late-stop boundary | 4312上のこの差分。同じexecutorのstopをidentity/clock/deadline後・fresh authority解決前に再確認。Native HTTP全213件とformat/operator全target Clippyが全actual exit 0/EOF。guardを外すと対象2件が409対503でactual101になり、exact bytes復元後は2件actual0/EOF。E30統合後も全12 TLS casesとClippy/formatの全3 commandsがactual0/EOF、374.159秒。独立correctness review承認 | 手動構成のactual router component + compiled TLS controls。実signal/factoryの当該guardだけの配線分離oracle・全D05/M5の完了ではない。実行済みstorageのabort/rollbackやprotocol変更は追加せず、同source完全required/CIはE51/E46で成功 |
| E32: historical successor late-stop boundary | e603上のこの差分。signerless履歴hostの別read ownerでも、identity/clock/deadline後・fresh policy解決前に同じexecutorのstopを再確認。Native HTTP全218件、format、native-http/operator全target Clippyの全3 commandsがactual0/EOF、366.549秒。guard除去時は対象1件がactual101、exact bytes復元後は1件actual0/EOF。独立correctness review承認 | 手動構成actual routerのsummary controlと、同じreadを使う3 history routesのsource対応。compiled signal配線単独の検証・物理fault・全D05/M5の完了ではない。同sourceのhosted CIとlocal完全requiredはE39/E55で成功 |
| E33: genesis Standard Asset split/merge custody component | `bcb9a1c9` / tree `4619ceab`。共通の独立genesis/code/instance/policy pinを保ち、専用kind3で分割・結合の完全preimage/内容表示/正確な期限・frame approvalと実CLIを接続。custody 98 passed/3 ignored、Standard Asset 18 passed、CLI build・Clippy・fmt/構文・compiler artifact記録の全7 commandsがactual0/EOF、92.870秒。実Docker/UID/PTYは元publication・6 lifecycle・送金と追加分割→結合を全actual0/EOF、4.687秒。両独立correctness review指摘を処理し再承認 | 3 ignored entriesは同じharnessのDocker ownerが別途実行。5Mへ分割・10Mへ結合、送信元/新coinのcanonical effectとquery、nonce2、非空の一致receipt、exact replay、取消後/restart拒否・入出力binary不変と所有資源解放を確認。trusted OS/local genesis profileのみ。自動署名/TreasuryCap/他family・epoch/全M2・完全required/CI・RELEASE認定ではない。E30-E32統合後のsourceは新しく完全検証する |
| E34: combined 7c57 actual Native release A/B | `7c5778b0` / tree `710b4c3d`。M2 custodyと全late-stop/TLSを統合し、対象9 commandsが全actual0/EOF、712.548秒。固定Node24.19.0/Rust1.97.1の2 fresh buildsで13ターゲット全byte/mode/owner一致、actual0/EOF、1,128.808秒。保存26 ELFを親で再hash照合、実mode0755を正規化せず保持。4専有dir・source lease解放 | same-host trusted OSのRELEASE build証拠。cross-machine/hermetic・独立監査・全M7/公開認定ではない。原12 RELEASE runtimeはE47の時間上限失敗、ローカル完全requiredは終端待ち、同source CIはE46で成功 |
| E35: combined 7c57 actual RELEASE CLI custody | E34保存の実RELEASE CLI + 同sourceで保存したdev/test opt2 harnessで、元publication・6 lifecycle・transfer・自分宛てsplit/mergeを実UID/PTYで全actual0/EOF、4.392秒。全byte署名一致、非空receipt・replay・nonce・取消/restartを検証。sourceと両ELFの前後hash/metadata一致、owned container/volume解放 | RELEASEなのはCLI child。SQLite/WASM oracleはdev/test。他者宛てはprepare/approval controlsのみで、この実CLI round tripには含めない。全M2・全13 runtime・公開認定ではない |
| E36: 426e hosted complete CI | [run `38839795270`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38839795270) の7 owners + aggregate checkが全8 jobs terminal SUCCESS。全8 actual checkoutは `47636cf615a8ebfc73bde33f8149dae71c1e4e53`、tree `b7fa71cd083b8f257708b3f43378a310ff785267` は `426e8359` と一致。親 `f21477d9` + `426e8359`、各raw log hashとcommit metadataも照合 | Node24.19.0固定、元long cases/待機を保持したsource qualification。ローカル完全requiredの終端、後続b568/4312/e603/92fd/7c57のCI、独立security監査・公開認定へ転用しない |
| E37: import closure pins and successor floor source | `53e324c1` / tree `499ef2e8`。独立に保持したcut/package/planの3 digestを全て指定または全て省略し、既存の完全証明再検証後・destination create/open前で追加拒否。新6件を含むoperator lib全150件、compiled import driver全11件、fmt、operator全target/all-feature Clippy、元conditional driverの実ELF生成を含む全5 commandsがactual0/EOF、359.714秒。guard除去時の新1件は意図したmismatch assertionでactual101、exact bytes復元後はactual0/EOF。負対照controllerは637.965秒で完了し、元コード・raw hashを親でも照合。両変更の独立correctness review承認 | 新しい後継floor controlは元recurringケースのfirst successor linkへ追加し、Freeze/DrainSet/empty-three-chain済みの既存history/cutを使用。元8リンク/e8 withdrawals/35 roles/待機を保持。ただしこのsourceでは当該long caseをまだ実行しておらず、compileだけの成功をend-to-end合格にしない。新Native A/BはE40で成功。全M4/M7、原12 runtime・完全required/CI、checkpoint/state-root・whole-store rollback・公開認定は未完了 |
| E38: 426e complete required and hosted CI | `426e8359` / tree `b7fa71cd`。literal npm-ci +完全check-allがactual0/EOF、16,941.054秒。元8リンク/e8 withdrawals/35-role source-free復元と全adapterを維持。Rust success summaries143・報告pass合計4,176・failed0。前後HEAD/clean state、Node24と全wrapper hash・raw hashを親で照合。同treeのhosted CI全8 jobs SUCCESSはE36 | 426eのsource qualification。新source b568/7c57/277f、全M2/M3/M4/M5/M7・独立security監査・公開認定へ流用しない。426eの既存transfer component owning/full/RELEASE CLIを確認した結果であり、後続common trustの統合はE34/E35の限定証拠と最終source gateを分ける |
| E39: b568/4312/92fd hosted complete CI | [run `38845223600`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38845223600) と [run `38850438856`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38850438856)  と [run `38854487300`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38854487300) の各7 owners + aggregate checkが全8 jobs terminal SUCCESS。全raw logのactual checkoutは各 `7b207947` / `fa755c46` / `59e57f13`、tree `2a691d63` / `3c0960d6` / `37346f60` が対象head `b568037f` / `4312d547` / `92fd5c93` と一致。両merge parents・各raw hash・GitHub commit metadataを照合 | この3 sourceのhosted qualification。b568/4312のlocal完全requiredはE42/E45で成功し、92fdは実行中。後続sourceの結果、全M3/M4/M5/M7・独立監査・公開認定に転用しない |
| E40: 277f actual Native release A/B | `277fd2c5` / tree `39d05ad1`、固定Node24.19.0/Rust1.97.1/Linux GNU recipeの2 fresh builds・13ターゲット全byte/mode/owner一致、actual0/EOF、1,407.987秒。保存26 ELFを親で再照合。別targetの13 debug + 10 driverコンパイルもactual0/EOF、1,591.155秒、23 ELFとCargo JSONを照合。4専有dir・source lease解放、実mode0755を正規化せず保持 | same-host trusted OSのRELEASE build証拠。新floorを含む原12 runtimeとローカル完全requiredは実行中。CIとfloor個別long caseはE53で成功し、コンパイルだけをend-to-end成功と呼ばない。全M4/M7・cross-machine/hermetic・独立監査・公開認定ではない |
| E41: genesis Standard Asset mint/burn custody component | `32cf6f04` / tree `fbf1a5e1`。専用kind4のmint/burnで独立genesis/code/instance/policy pin・canonical cap/coin preimage・checked供給量・exact frame/単一期限の承認と実CLIを接続。custody 128 passed/4 ignored、Standard Asset 18 passed、CLI build・Clippy・fmt/Node構文・Cargo JSONの全7 commandsがactual0/EOF、138.504秒。実Docker/UID/PTYは元publication・6 lifecycle・transfer・split/mergeと新mint→burnを全actual0/EOF、5.314秒。両独立correctness reviewの指摘を処理・再承認。親が後続のtest-only Debug型制約/単一要素loopを修正し、初回失敗2件の記録も保持 | 同じpublisherへ5Mをmintし、作ったCoin全体をburn。live SQLite/WASMでcap供給量S→S+5M→S・version・消費Coin tombstone・nonce2、署名全byte一致、非空Accepted dedup payloadと保存結果の一致、captured request再送、取消後とrestart後の拒否を検証。source/wrapper/実ELF前後不変、owned container/volume解放、実mode0755のCLI/harnessを別inodeへ保持。trusted OS/local genesisのみ。新familyの鍵復旧/交換・自動protocol署名・create-asset・他family/epoch・全M2・完全required/CI/RELEASE・独立監査/公開認定ではない |
| E42: b568 complete required and hosted CI | `b568037f` / tree `2a691d63`。literal npm-ci +完全check-allがactual0/EOF、19,899.251秒。元8リンク/e8 withdrawals/35-role source-free復元と全adapterを維持。Rust success summaries144・報告pass合計4,196・failed0。前後HEAD/clean state、Node24と全wrapper/raw hashを親で再照合。同treeのhosted CI全8 jobs SUCCESSはE39、全8 raw logも再hash確認 | b568のsource qualificationのみ。新F sourceのsuccessor floor oracle、10a4のmint/burn、原12 RELEASE runtime、全M2/M3/M4/M5/M7・独立監査/実provider/公開認定は別条件として保持する |
| E43: 10a4 actual Native A/B and RELEASE CLI custody | `10a47db1` / tree `ede55f33`。固定Node24.19.0/Rust1.97.1の13ターゲット・2 fresh buildsが全byte/mode/owner一致、actual0/EOF、1,529.682秒。親が保存26 ELFを再hash/byte比較し、4専有dir・source leaseを解放。13 debug + 10 driverの別targetコンパイルもactual0/EOF、1,709.378秒、23 ELFとCargo JSONを再照合。同sourceの実RELEASE CLIで元publication・6 lifecycle・transfer・split/mergeとmint→burnの別UID/PTYを全actual0/EOF、5.655秒。source/ELF前後不変、所有container/volume解放 | RELEASEなのはCLI child。SQLite/WASM oracleは保持した32cfのdev/test opt2 harnessで、10a4との差分はTODOだけ、他の全code bytes一致を検証。原12 RELEASE runtimeはcheck/probeを通して実行中、同sourceの完全required/CIも未終端。全M2/M4/M7・cross-machine/hermetic・独立監査/実provider/公開認定ではない |
| E44: compiled SQLite ordered-router SIGTERM wiring | `3b51aa67`。元4件を残したcompiled process全5件/0 failed/0 ignored、fmt、operator全target/all-feature Clippy、実Cargo JSON artifactの全4 commandsがactual0/EOF、188.498秒。実leader/genesis/policyのowned hostへSIGTERMを送り、Expect/100-continue + idle EOF/接続拒否のbarrier後に本文を渡して保存record/blob不変・正確な取消応答と通常summaryを確認。fresh正対照では実LeaderProposalRecordをHTTP proposal/再計算digestと照合 | source-only独立correctness reviewのB1実DBパスとwant-channel証明を修正、test source承認。N1 pre-runclose除去は実書込みによる不変assertionでactual101/EOF、N2 cancellation Noneはrecord/blob不変後に別admission拒否bodyでactual101/EOF。固定した元test ELFで実行し、同じchild build recipeでexact bytes復元後はactual0/EOF。controller全469.101秒、元source全hash/clean・全raw hash・wrapper/保持ELFを親で再照合、owned peers0/専用TMP除去。N2のdynamic metrics観測とは呼ばない。Docs証拠参照も修正し別承認。ordered host wiring限定、実binary内late window・他family/TLS・全D05/M5/完全required/CI/RELEASE/独立監査/公開認定ではない |
| E45: 4312 complete required and hosted CI | `4312d547` / tree `3c0960d6`。literal npm-ci +完全check-allがactual0/EOF、23,545.999秒。Rust success summaries144・報告pass合計4,196・ignored31・failed0。前後source/tree/clean、Node24・全wrapper・raw logとE39全8 CI raw logのhashを親で再照合 | 同sourceのstorage-neutral qualification。PG・後続source・全M3/M4/M5/M7・独立監査・公開認定へ転用しない |
| E46: e603/7c57 hosted complete CI | [run `38852510726`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38852510726) / [run `38856074268`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38856074268)、各attempt1の全8 jobs terminal SUCCESS。全raw logのactual checkout `c4b9bc5e` / `8ca49bca`、tree `3c8b49ec` / `710b4c3d` は対象head `e60337b3` / `7c5778b0` と一致。両merge parentsと全raw hashを親で照合 | この2 sourceのhosted qualificationのみ。local完全requiredは終端待ち。E47のR4 runtime失敗、全milestone・独立監査・公開条件を成功へ置き換えない |
| E47: 7c57 R4 runtime deadline failure | 原10 whole +2 exact ignoredを同一範囲で実行し、最初の11 casesはactual0/EOF。最後のrecurring successor caseはe8 closure出力後に共有18,000秒の上限へ到達し、controller terminalExit1、18,002.485秒。失敗receipt/rawと専有TMPを保持。sourceは前後clean同一pin、systemd unit終了済み | 原12ケース全体の成功ではない。自動再実行・case/待機削減・上限変更はしていない。進行中の後続sourceの試験結果とも区別する |
| E48: f973 actual Native A/B and RELEASE CLI custody | `f973c02d` / tree `63877d27`。固定Node24.19.0/Rust1.97.1の13-target・2 fresh buildsが全byte/mode/owner一致、actual0/EOF、1,606.111秒。保存26 ELFを親で再hash/byte比較し、4専有dir・leaseを解放。別targetの13 debug +10 driverコンパイルもactual0/EOF、1,782.877秒、23 ELF/Cargo JSONを再照合。実RELEASE CLIで元publication・6 lifecycle・transfer・split/merge・mint/burnの全UID/PTYをactual0/EOF、9.104秒 | RELEASEなのはCLI child。SQLite/WASM oracleは保持した32cf dev/test opt2 harnessで、全CLI bytesとharness sourceの一致を確認。source/両ELF不変、owned container/volume解放。原12 runtimeはcheck0/probe0後に実行中、source全体required/CIは未終端。same-host trusted OSの範囲で、全D05/M2/M5/M7・独立監査・公開認定ではない |
| E49: Standard Asset create-asset custody component | `899539bc` / tree `ab5b7850`。専用kind5のprepare/approve/sign/serve-createを実CLIへ接続。署名側が固定したsender/context/codeと公開seedからnew instanceを独立導出し、genesis fee sourceと別に承認する。custody 145 passed/5 ignored、Standard Asset 18 passed、CLI build・Clippy・fmt/Node構文・Cargo JSONの全7 commandsがactual0/EOF、98.762秒。元publication・6 lifecycle・transfer・split/merge・mint/burnに追加した実Docker/別UID/PTYも全actual0/EOF、7.559秒 | 実WASM/SQLiteでnew InstanceRecord、型IDを独立導出したDefinition + TreasuryCapの2 object・初期供給量0、genesis app coin不変、nonce1、非空Accepted dedupと保存結果、exact replay、offline/実CLI全署名byte一致、取消後/restart拒否を確認。core/docsとfixtureの独立correctness reviewを修正・再承認。親がsource/wrapper/両ELF/rawを再照合し、実mode0755入力を別inodeに保持。seed再利用の事前不在証明・作成IDの事前予測はなく、再利用時にもreview済みfeeが課金され得る。他familyはgenesis-onlyのまま。新familyの鍵復旧/交換・fee-claim/governance/自動署名・全M2・完全required/CI/Native release・独立監査/公開認定は未完了 |
| E50: compiled frontier-maintenance SIGTERM wiring | `f209b6d1` / tree `9c95af1b`。元5件を保持した実process全6件/0 failed/0 ignored、fmt・operator全target/all-feature Clippy・Cargo JSONの全4 commandsがactual0/EOF、984.775秒。chunkedの空bodyの終端だけを保持し、実SIGTERMとlistener停止確認後の取消、停止前なら独立validator3のcursor/entry 2 recordが実保存される正対照を確認 | 固定baseline oracleでN1 pre-run close除去は実書込みによる不変assert失敗、N2 components取消参照除去はrecord/blob不変後の別拒否bodyで各actual101/EOF。exact復元・同じchild build recipeの正常成功を含む全7 stagesをactual0/EOFで完了、418.458秒。全source/wrapper/raw/保持ELFを親で再照合、owned peers0/TMP除去。N2 metric観測とは呼ばない。Rust独立review承認、Docs v2指摘修正を承認後に適用したcommitは`8df6d7ff`。frontier保守の配線componentであり、paid prepare/apply・実binary late window・全D05/M5・最終source全体gate/CI/RELEASE・独立監査/公開認定ではない |
| E51: e603 complete required and hosted CI | `e60337b3` / tree `3c8b49ec`。literal npm-ci +完全check-allがactual0/EOF、24,587.277秒。Rust success summaries144・報告pass合計4,203・ignored31・failed0。前後source/tree/clean、Node24・全wrapper/rawとE46全8 CI raw hashを親で再照合 | このsourceのstorage-neutral qualification。後続history guard/source union、PG、実provider・全D05/M5/M7・独立監査/公開認定に転用しない |
| E52: 5c4d actual Native A/B and RELEASE CLI custody | `5c4d0cc5` / tree `c32ed10e`。13-target・2 fresh buildsが全byte/mode/owner一致、actual0/EOF、1,680.730秒。保存26 ELFを親で再hash/byte比較し4専有dir・leaseを解放。13 debug +10 driverの別target buildもactual0/EOF、1,864.138秒、23 ELF/Cargo JSONを再照合。実RELEASE CLIで元publication・6 lifecycle・transfer・split/merge・mint/burn・create-assetの全UID/PTYがactual0/EOF、5.579秒 | Node24.19.0/Rust1.97.1、same-host trusted OS、実mode0755を正規化せず保持。SQLite/WASM oracleは8995 dev/test opt2 harnessで、code差分はTODOだけと照合。source/両ELF不変・owned container/volume解放。原12 runtimeはcheck0/probe0までで未起動、同source完全gate/CIは実行中。新f209 frontierケースのrelease資格や全M2/M5/M7・独立監査/公開認定ではない |
| E53: 277f hosted CI and successor history-floor long case | [run `38864944974`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38864944974) attempt1の全8 jobs terminal SUCCESS。全raw checkout`28f4fe93` / tree`39d05ad1`がhead`277fd2c5`と一致し、両parents/raw hashを親で照合。元selector`compiled_registered_replacement_and_recurring_successor_hosts`は1 passed/0 failed/0 ignored、17,978.47秒。code53e3との差分はTODOだけ | 元8 links/e8/35-role controlsを保持するsourceのactual CI long case。最初のlinkで既存sealed/drained history/cutへ追加したgenuine successor floor拒否/受理/resumeをsource対応とともに確認。published checkpoint/state-root・latest owned rollback・旧writer除外は追加しない。原12 Native runtime・ローカル完全requiredと全M4/M7・独立監査/公開認定は別条件 |
| E54: ZeroShare WIP provider stop | 別branch`codex/zero-share-custody-1016` / local`5bcef7a2`へkind6と既存fee-claim-sign接続の未検証コードを保全。Claudeのcore authorはsourceのみ完了したが、fixture authorは2026-10-16にproviderのcyber保護判定で停止した | コンパイル・実fixture・全体gate/CI未確認、未push/未merge。このfixtureの再試行・言い換え・他モデル/手動実装による迂回を行わない。componentやM2の完了には数えない |
| E55: 92fd complete required and hosted CI | `92fd5c93` / tree `37346f60`。literal npm-ci +完全check-allがactual0/EOF、26,045.599秒。Rust success summaries144・報告pass合計4,208・ignored31・failed0。同treeの全8 CI jobsもSUCCESS、親が前後source/tree/clean・Node24・全wrapper/raw・全8 CI raw hashを再照合 | signerless history stopを含むこのsourceのstorage-neutral qualification。後続source・PG・全D05/M5/M7・独立監査/公開認定へ借用しない |
| E56: 7c57 complete required and hosted CI | `7c5778b0` / tree `710b4c3d`。literal npm-ci +完全check-allがactual0/EOF、25,726.089秒。Rust success summaries144・報告pass合計4,229・ignored32・failed0。同treeの全8 CI jobsもSUCCESS、親が前後source/tree/clean・Node24・全wrapper/raw・全8 CI raw hashを再照合 | split/merge custodyを含むこのsourceのstorage-neutral qualification。E47の原12 R4 runtime時間上限失敗は保持し、全M2/M5/M7・独立監査/公開認定に数えない |
| E57: 277f original R4 runtime timeout | `277fd2c5`。原10 whole +2 exact ignoredの12ケース中、11ケースはactual0/EOF、最後の元recurring successor selectorが共有18,000秒の上限で停止。controllerはactual1/EOF、18,002.967秒。親がhelper・終端/inner receipt・両raw hash、unit停止を確認 | 失敗のまま保持。最後のattemptはEOF/wait未完、killとterminationは確認。専有TMPをforensicsとして残し、自動再実行・上限変更なし。E53のCI long case成功とは分け、原12 Native runtime・全M4/M7の合格に数えない |
| E58: c04e actual Native A/B and RELEASE CLI | `c04e5a38` / tree `ea3cf658`。13-target・2 fresh buildsは全byte/mode/owner一致、actual0/EOF、1,516.457秒。別targetの13 debug +10 driver buildもactual0/EOF、1,666.261秒。親が26+23 ELF・Cargo JSON/source/profile/raw・4専有dir/lease解放を照合。実RELEASE CLIの元5 families/6 lifecycle UID/PTYもactual0/EOF、5.863秒 | Node24/Rust1.97.1・same-host trusted OS。CLI oracleはcompiled inputs同一の8995 dev/test2保持harnessで、新frontier operator integration testのRELEASE oracleには数えない。原12 runtimeはcheck/probe成功までで未起動。新しい0258 application-pin実装、全M2/M5/M7・独立監査/公開認定は含めない |
| E59: f973 hosted CI | [run `38886425920`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38886425920) attempt1の全7 owners + checkがSUCCESS。全8 raw checkout`b77346ba` / tree`63877d27`がhead`f973c02d`と同じtreeで、両merge parents・local clean pin/tree・全raw hashを親で再照合 | ordered SIGTERM wiring sourceのexact CI qualification。local完全required・原12 RELEASE runtimeと後続source、全D05/M5/M7・独立監査/公開認定は別条件 |
| E60: 10a4 hosted CI | [run `38876217021`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38876217021) attempt1の全7 owners + checkがSUCCESS。全8 raw checkout`efd6a15c` / tree`ede55f33`がhead`10a47db1`と同じtreeで、両merge parents・local clean pin/tree・全raw hashを親で再照合 | genesis mint/burn sourceのexact CI qualification。後続のapplication pin source、local完全requiredと原12 RELEASE runtime、全M2/M7・独立監査/公開認定は別条件 |
| E61: 10a4 original R4 runtime timeout | 原12ケース中11ケースはactual0/EOF。最後の元recurring successor selectorが共有18,000秒の上限で停止し、controller actual1/EOF、18,002.073秒。親がhelper・終端/inner receipt・両raw hashとunit停止を照合 | 最後のattemptはEOF/wait未完、killとterminationを確認。専有TMPをforensicsとして残し、再実行・上限変更なし。E60のCI成功と分け、原12 runtime・全M7の合格に数えない |
| E62: own-created application mint/burn custody | `4d2c97e0` / tree`59019e02`。custody163 passed/5 ignored、Standard Asset19 passed、fmt/Node/CLI build/全target全feature Clippy/Cargo JSONの全7 commandsがactual0/EOF、9.986秒。実Docker/別UID/PTYの通常実行はactual0/EOF、5.369秒。作成assetで供給量0→5M→0、cap version1→2→3、新Coin1→tombstone、nonce1→2→3、非空Accepted/full result、offline/実CLIの全署名byte一致を確認 | 元5 families/6 lifecycle・取消/restartを保持。新profileの6/6/4/2、restart2/2/0/2、exact replayのDefinition/genesis spend/fee・全effect IDs・nonce3/2 receipts/InstanceRecord不変を確認。全store/all tables/cross-file snapshotとは呼ばない。source/raw/両ELFを親で照合し、container/volume残存なし。cap追加なし、60/230/280/30秒を維持。pure/fixture指摘修正を独立承認。最終source完全required/CI/新Native release、他creator・全M2/M7・独立監査/公開認定は未完了 |
| E63: 277f complete required and hosted CI | `277fd2c5` / tree`39d05ad1`。literal npm-ci +完全check-allがactual0/EOF、26,575.667秒。Rust success summaries144・報告pass合計4,236・ignored32・failed0。E53全8 CI raw、前後source/tree/clean・Node24・全wrapper/rawを親で再照合 | closure pins/history floor sourceのstorage-neutral qualification。E57の原12 RELEASE runtime失敗は保持し、published checkpoint/state-root・latest owned rollback・PG・全M4/M7・独立監査/公開認定や後続sourceへ転用しない |
| E64: 9de6 actual Native A/B and RELEASE CLI | `9de634a7` / tree`229b397f`。13-targetの2 fresh buildsがactual0/EOF、1,399.459秒、全13組のbyte/mode/owner一致。別targetの13 debug +10 driver compileもactual0/EOF、1,562.884秒。26+23 ELF・Cargo JSON/source/profile/raw・4専有dir/lease解放を独立照合。実RELEASE CLIの元5 families/6 publication lifecycleとown-created Asset mint/burnもactual0/EOF、5.620秒 | Node24/Rust1.97.1・same-host trusted OS。oracleはcode `4d2c97e0` の保持済みdev/test2 CLI harnessで、全code/Node入力同一・3 doc/TODOだけの差分を確認。全tracked files/両ELF/rawとcontainer/volume解放を再照合。原12 runtimeはcheck/private13ROmapping probe成功まで、実12ケース未実行。重い並行検証の終端後に進める。完全required/CI・新しい鍵復旧テスト・全M2/M7・独立監査/公開認定は含めない |
| E65: f973 original R4 runtime timeout | 原12ケース中11ケースはactual0/EOF。最後の元recurring successor selectorが共有18,000秒の上限で停止し、controller actual1/EOF、18,002.004秒。helper・終端/inner receipt・両raw hash・clean sourceとunit停止を親で照合 | 最後のattemptはEOF/wait未完、killとterminationを確認。専有TMPをforensicsとして保持し、再実行・上限変更なし。E59のCI成功と分け、原12 Native runtime・全D05/M5/M7の合格に数えない。新source 9de6の実runtimeは、現在実行中の完全required controllersの終端後に進める |
| E66: 10a4 complete required and hosted CI | `10a47db1` / tree`ede55f33`。literal npm-ci +完全check-allがactual0/EOF、26,021.786秒。Rust success summaries144・報告pass合計4,266・ignored33・failed0。E60全8 CI raw、前後source/tree/clean・Node24・全wrapper/rawを親で再照合 | genesis mint/burn sourceのstorage-neutral qualification。E61の原12 RELEASE runtime失敗を保持し、後続application-pin/鍵復旧source・PG・全M2/M7・独立監査/公開認定へ借用しない |
| E67: stopped asset key recovery and rotation refusal | test source `be3b4896` / tree`e8878c44`、A/B生成`9de634a7`実RELEASE CLI + compiled inputs同一の`4d2c97e0`保持oracleでactual0/EOF、5.558秒。元5 families/6 publication lifecycleを保持し、own-created mint/burnの全signer停止→同じ新規requestの元鍵reference→鍵復旧→完全署名byte一致を確認。復旧前からの取消と新規取消を保持し、restart後も両方拒否。reference1/1/1/0、復旧3/3/1/2、restart2/2/0/2を内外で検証。5 profilesのnew publisherで旧owner/creatorを拒否、出力なしも確認 | source/両ELFのhash/mode/owner/identity不変、container/volume解放、生成880,006 bytes。initial argv E2BIG失敗を保持し、同一136,386-byte programを31,025-byte bootstrapへ圧縮、長さ/digest検証後に実行。復元一致・digest/trailing-data拒否と独立reviewを確認。元のresource/deadline/UID/capability/全assertionは維持。新test-only sourceの13-target/完全required/CI、正の所有権移行・他profileの鍵復旧・automatic signing・全M2/M7・独立監査/公開認定は含めない |
| E68: f973 complete required and hosted CI | `f973c02d` / tree`63877d27`。literal npm-ci +完全check-allがactual0/EOF、24,322.791秒。Rust success summaries144・報告pass合計4,267・ignored33・failed0。[run `38886425920`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38886425920) attempt1の全7 owners + checkもSUCCESS。前後source/tree/clean・Node24本体・全wrapper/raw・全8 CI raw/checkout/tree/parentsを親で再照合 | ordered SIGTERM sourceのexact storage-neutral qualification。原12 RELEASE runtime・後続source資格・全M2/M7・PG・独立監査/公開認定とは分ける |
| E69: 5c4d complete required and hosted CI | `5c4d0cc5` / tree`c32ed10e`。literal npm-ci +完全check-allがactual0/EOF、22,952.088秒。Rust success summaries144・報告pass合計4,284・ignored34・failed0。[run `38893147242`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38893147242) attempt1の全7 owners + checkもSUCCESS。前後source/tree/clean・Node24本体・全wrapper/raw・全8 CI raw/checkout/tree/parentsを親で再照合 | create-asset custody sourceのexact storage-neutral qualification。原12 RELEASE runtime・後続source資格・全M2/M7・PG・独立監査/公開認定とは分ける |
| E70: c04e complete required and hosted CI | `c04e5a38` / tree`ea3cf658`。literal npm-ci +完全check-allがactual0/EOF、20,908.092秒。Rust success summaries144・報告pass合計4,285・ignored34・failed0。[run `38901912984`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38901912984) attempt1の全7 owners + checkもSUCCESS。前後source/tree/clean・Node24本体・全wrapper/raw・全8 CI raw/checkout/tree/parentsを親で再照合 | frontier SIGTERM sourceのexact storage-neutral qualification。原12 RELEASE runtime・後続source資格・全M2/M7・PG・独立監査/公開認定とは分ける |
| E71: 9de6 complete required and hosted CI | `9de634a7` / tree`229b397f`。literal npm-ci +完全check-allがactual0/EOF、17,587.750秒。Rust success summaries144・報告pass合計4,304・ignored34・failed0。[run `38922549356`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38922549356) attempt1の全7 owners + checkもSUCCESS。前後source/tree/clean・Node24本体・全wrapper/raw・全8 CI raw/checkout/tree/parentsを親で再照合 | own-created Asset mint/burn custody sourceのexact storage-neutral qualification。原12 RELEASE runtime・後続source資格・全M2/M7・PG・独立監査/公開認定とは分ける |
| E72: b4 test-only hosted CI | `b4d20a4a` / tree`1e934d3a`。[run `38930807287`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38930807287) attempt1の全7 owners + checkがSUCCESS。全8 raw checkout`b2dd371d`のtree一致・merge parents・clean local sourceと全raw hashを親で再照合 | E67の鍵復旧test-only headのexact CI。literal local完全required/このheadの13-targetは未実行。E71のsourceとして付け替えない |
| E73: D05/M5 technical final coverage | E71の完全required/全8 CI成功と独立functional reviewで下の共通case表を最終照合。c04e→b4のoperator/native-http/shared relay・gate dispatcher/workflowはbyte同一。9de6→b4の差分はTODO/guideと別実行のDocker custody fixtureのみで、通常required/CIの入力は不変。E67/E72は別sourceの限定資格として保持 | 選択済みloopback Native + closed certified relayの技術範囲を完了。元M5総合readiness・原12 RELEASE runtime/M7・独立security監査・実provider/公開認定ではない。実PKI/capacity/alerts/spend/topology/rehearsalはD04/D07/M8 |
| E74: combined application Coin / complete-owner-loss / anchored TLS | `d4dd0109` / tree`aaff6747`。全9 owning commandsがactual0/EOF/wait、675.094秒。custody174 passed/6 ignored、Standard Asset19 passed、実compiled local TLS全14 passed。全4 sole-owner SIGKILL/reap後のwriter交代と、新しい独立anchor付きの同復旧controlも成功。fmt/Node syntax・全target全feature strict Clippyも成功 | 親が1157 tracked files・固定Node24/全wrapper/raw hash・前後clean sourceを照合。component gateでありliteral完全required/CI・13-target Native・全M2/M3/M4/M7ではない。旧retained-handle controlと元13 TLS selectorsは保持 |
| E75: own-created application Coin actual custody | 同じ`d4dd0109`の実CLI/新ignored oracleを通常dev/test opt2で生成し、実mode0755を保持した別inodeへ保存。Docker/別UID/PTYがactual0/EOF/wait、6.564秒。mint→split→merge→whole burn→mint→他者へのwhole transfer、全6段階の保存済み再送と供給量5M→0→5M、最終nonce9/cap6を検証 | 元5 families/6 lifecycleとE67を保持。新5 groupsの取消/restart・正確な件数・offline byte一致を確認。親が全source/両ELF/raw hashと専有container/volume消滅を照合。RELEASE・全storeの等値性・他profileの鍵復旧/交換・automatic signing・全M2は主張しない |
| E76: independent local checkpoint anchor | `7d5d91dd` / tree`64a3079a`でruntime-sqlite111 passed/5 original ignored、新anchor13 controls、strict全target全feature Clippyがactual0/EOF/wait。別`.lease` inodeでの排他、12 SQL tablesと閉じたbody manifest、COMMIT前Pending/後の照合、stale clone拒否と現行cloneのfresh fencingを検証 | 初回compile失敗とClippy失敗を保存。24入力を親で再hashし、統合d4ddとの差分は設計index/ADRの2文書だけ。実compiled anchor inspect/enroll/checkpointと4-host TLS復旧はE74で追加実行。local ACKの独立anchorでありquorum checkpoint・完全暗号化backup・upgrade・全M4ではない |
| E77: ordinary-v5 actual guest faults, first failed attempt | `6c4ea77b`のfmt・pure parser・SQLite lib112 passed/6 ignored・strict Clippy・Cargo JSONが全actual0/EOF/wait、94.423秒。保持ELFで実VMを起動し、caller ACK後とSQLite COMMIT後/caller ACK前の2電源断・cold復旧は全12+2 tables/4 collections/2 bodies/fresh fence/new work/replayを完了。続くwrite-only仮想block EIOは実COMMITから1034 (FSYNC) として返り、778だけを期待したfixtureがactual1/EOF、6.394秒で失敗 | 失敗原本`qg1017a`の全images/rawとouter wait1を保持。kernel WRITE EIO・実QMP device eventを照合。writeのcold復旧とflush-only caseは未実行。全child wait/EOF/reap・socket消滅を確認。writeback時の分類を修正して別sourceで再検証する。ordinary v5のみであり、anchor v6・物理hardware・全M3の資格にはしない |
| E78: encrypted checkpoint first owning failure | 統合`c68e34ed` / tree`34c0b1d4`。fmtはactual0、SQLite libはactual101/EOF/wait、115 passed/2 failed/6 ignored、全体55.014秒。positive fixtureがreadonly blob ownerへputした誤りと、閉じたWAL snapshotのreadonly照合後にsidecarsが残る問題を検出 | operator age controls・Clippy等の後続3 commandsは未実行。raw/終端/sourceを失敗のまま保持。strict sidecar refusalを維持して修正中であり、完全backup/restore・このsourceの全体gate成功とは数えない |
| E79: ordinary SQLite actual virtual faults | `62432e47` / tree`1d823321`の保持ELFで全4 cases・8 bootsがactual0/EOF、10.477秒。ACK後/COMMIT後ACK前はcold full write setがall、write-only/flush-only EIOはnone。全caseで12+2 tables/4 portable collections/2 positive bodies・receipt先行照合・fresh fence・新規state/receipt/outbox・exact replayが成功。両EIOの実COMMIT codeは1034、独立flush-only caseが正確なFSYNC条件を満たした | `ordinary`は既存schema/v6・PRAGMA user_version5で、独立anchorは使わない。各実rule/QMP graph/device event/kernel EIOと全15 child wait/EOF/reap・socket/cgroup消滅、全入力/失敗原本hashを親で照合。build2のcontroller1は生成dirのuntracked判定失敗として保持し、5 commandsの実0と別inode ELFを別途資格照合した。物理hardware・anchor付きprofile・最終source全体gate・全M3ではない |
| E80: checkpoint corrected native/age and first compiled fixture failure | `22250784` / tree`4ba328e4`のowningはactual101/EOF/wait、383.828秒。修正後SQLite lib119 passed/6 ignored、実ageの5 controlsと元14 compiled TLSは全成功。新15thはcompiled packがexit0の後、fixtureが別command用の`complete=true`表示を要求して失敗 | raw/終端と全sourceを保存し、厳格な実診断照合を持つfixtureへ修正する。新15th・後続Clippy/全体gateの成功とは数えない。既存Native/age結果とcompiled pack/open全体資格を区別する |
| E81: checkpoint compiled inventory failure | `98e45e05` / tree`76ad2e8b`の新15thはactual101/EOF/wait、owning全体23.192秒。復元後の通常SQLite検査の後、closed inventoryが期待4 leafに対して6 leafとなり失敗 | rawには余分なleaf名がない。sourceの呼出順から通常readonly WAL検査の副作用と診断し、archiveの厳格な一覧検査を最初の通常open前へ移した。元raw/終端は保持。4台continuation・fresh business・後続Clippyの成功とは数えない |
| E82: original ordered custody functional component | `976deed4` / tree`5f81352e`で全7 commandsがactual0/EOF/wait、696.548秒。新IPC/署名応答9、元routerとの応答比較4、role/private config3、既存DR-0215 local-signature16 controlsが全成功。fmtと全target全feature strict Clippyも成功 | 独立source reviewの3指摘を修正し、統合code/testは承認candidateとbyte一致。親が1172 tracked inputs・Node24・wrapper/controller/raw・clean sourceを再照合。別UIDの実4-worker/frontend・完全required/CI・Native・全M2・security監査は未完了 |
| E83: compiled complete checkpoint and prior-release upgrade | `07ebbc5a` / tree`c66689d9`のdefault TLS15 passed/1 ignoredがactual0/EOF、42.422秒。4台の実pack/open・旧source不在・独立authority一致・fresh fence/有料取引が成功。明示的な旧9de6 RELEASEを使う追加upgradeもactual0/EOF、5.490秒で全旧4台の取引→停止→schema identityだけの移行→旧版拒否/停止bytes不変→新fence3/新規取引/再送に成功 | owning全体はClippyのテスト内空文字比較1箇所でactual1/EOF、238.042秒の失敗として保持し、成功prefixを別途資格照合。等価な`is_empty`への変更だけの`fee693ff` / tree`4ac28a26`でfmt/全target全feature strict Clippy/diffはactual0/EOF、5.580秒。1174 tracked inputs・実driver/旧ELF/rawを親で再hash。全体required/CI・Native・全M4は未完了 |
| E84: original ordered multi-UID build/inventory and first setup failure | `44077af2` / tree`7e67ceeb`で4 bins + ignored fixture harnessの実CargoJSON build、fmt、Node/Python構文、strict Clippyの全6 commandsがactual0/両EOF/wait、owning15.83秒。5 ELFは通常0755のまま別inodeへ保持。read-only inventoryもactual0、0.59秒で12 source/5 ELF/4 loader-librariesを照合 | 最初のbuildのunused shared test helper失敗を保存し、単一関数だけに理由付きlint属性を追加。実UID fixture初回はdirectory chmodのEPERMでactual1/両EOF/wait、1.17秒、role child開始0。専有container/volume解放と不在を再確認。権限設定を所有権移譲前へ移す限定修正を統合し、修正後の実UID owningは未実行。build成功をM2/runtime成功に数えない |
| E85: partial-write mechanism refusal and stopped assessment | 別の小さいQEMU mechanismは実`max-transfer512`の制約拒否でactual1、0.285秒。子processのEOF/wait/reap/socket不在、実disk全old bytesと失敗rawを保存 | mixed bytes・SQLite/WAL・M3成功には数えない。続く実WAL source assessmentはprovider safetyで停止し、再試行・別agentへの迂回を行わない。supporting mechanism2の準備sourceも未実行で保全。独立anchorの9 casesと、この停止taskは別に扱う |
| E86: anchored SQLite library and failed first guest boot | `80c028a9` / tree`11e9044c`でSQLite lib全120 passed/7 ignored、3 packagesの全target全feature strict Clippy、fmt/diffの全5 commandsがactual0/両EOF/wait、19.84秒。前のbuild ownerは実CargoJSON package IDの照合誤りで失敗したまま保持し、正しいIDだけで別attemptを実行 | 1180 tracked inputs・18 VM inputs・通常0755の保持ELFを親で再hash。初回guestはinit exit76でactual1、2.07秒、product control成功0。全6 childrenのEOF/wait/reap・socket不在・raw/imagesを保持。続くboot修正taskもprovider safetyで停止したため、再試行・迂回せず未達を保持。library成功を9 boundariesの実guest成功へ読み替えない |
| E87: original ordered multi-UID second setup failure | `80c028a9`の新build/inventoryはactual0。実UID owningは準備probe成功後、実authorの親directory読み取りでEACCESとなりactual1/両EOF/wait、1.54秒。全15 Docker clientsのwait/EOF/PID不在と専有container/volume解放・不在を親で再確認 | `6e84e3a1`でroot-owned public routing ancestorsだけを0755へ合わせた。private leaves0700・private files0600・caps・拒否controlsを維持。修正後の実4-worker/4-frontend owningは未実行で、M2/runtime成功には数えない |
| E88: read-only anchor inspection and actual five ENOSPC controls | `4db1229f` / tree`c09cd519`。自動修正の後にも残ったwritable historical preflightを除き、同じreadonly snapshotで既存header/WAL/shared namespace検証とroot走査を実行。writer保持中・12拒否入力・authority非更新の3新規controlsを含むSQLite全123 passed/7 ignoredとstrict Clippy/fmt/diffが全actual0/両EOF/wait、64.387秒。元5 ENOSPC selectorsもactual0、26.992秒 | 全1180 tracked inputs・実CargoJSON/保持ELF・全framed rawを親で照合。ENOSPCの全86 clientsと専有5 container/volumeの解放・不在を再確認。既存historical/writable factoryと全5 fault controlsを保持。普通のcorrectness reviewは最終security監査ではなく、VM・全M3・最終完全gateの成功にも数えない |
| E89: original ordered fixture bounded output failure | `4db1229f`で4 bins + fixture harness、構文、strict Clippyの全6 commandsがactual0/両EOF/wait、195.059秒。通常0755の5 ELFとread-only inventoryも再照合。実UID attemptは64KiB内の出力配分を超え、actual1/両EOF/wait、13.937秒 | inner start clientはSIGKILL、観測stdout58102 bytesの完全rawを保持できなかったためproduct成功0として扱う。outer Node rawは完全。全15 clientsのwait/EOF/PID不在と専有container/volume解放・不在を確認。上限・oracle・拒否controlsを維持して完全ログのtransportを修正し、別attemptで検証する |
| E90: lossless complete-output transport source | `1973380a`で全child stdout/stderrを含む既存JSONをzlib/base64で転送し、正確なwireと復号resultを両方保持する。Node24の実16 controlsでPython相互運用、decoded512KiB境界、破損/末尾/連結stream・length/hash/base64/UTF8/JSON拒否が成功 | 64KiB wire/metadata・16KiB cleanup reserve、inner256KiB/stream64KiB、既存期限/caps/oracle/拒否controlsは維持。decoded allocation512KiBを明示し、outer最大serialization1,442,020 bytesが既存4MiB未満であることを確認。親が全既存Python owner/control AST・raw codec結果を照合。synthetic codec成功であり、修正後の実UID owningは未実行 |
| E91: original ordered actual multi-UID custody | `226c861a` / tree`f4513fbd`。全6 build/構文/strict Clippy commandsとread-only inventoryがactual0。実4-worker/4-frontend TLS fixtureもactual0/両EOF/wait、13.728秒。全76 role childrenと17 Docker clientsを回収し、署名・保存済み再送・停止中503・再起動fence3・QC・新規height2・不正UID/authority/入力の拒否が成功 | 親が1180 source/21 inputs・通常0755の5 ELF/4 librariesを再照合。完全child raw45653 bytes、wire7442 bytesと復号JSON58103 bytesの正確な対応を独立確認。専有container/volume解放・不在を確認し、全旧失敗を保持。original orderedのlocal OS custody componentのみで、後継epoch・他family・全M2・最終完全gate/CI/Native・独立監査/公開認定ではない |
| E92: 9de6 original R4 RELEASE runtime | `9de634a7` / tree`229b397f`。元10 wholeの89 passedと元2 exact ignoredの各1 passed、計12 commandsが全actual0/結合stream実EOF/wait、11,358.636秒。元8-link/e8 withdrawals/35 roles・7-epoch delay・全restart/refusalを保持し、最後のrecurringも11,292.938秒で成功。outer実exit0/waitとunit terminal successを確認 | 1146 source・Node24/両controller・15 provenance/raw・49保持ELF/13 byte pairsを独立に再hashし、親も再照合。private TMP/lease・全記録PID・cgroup不在、peak1,316,077,568 bytes/swapPeak0。RELEASEは13 child bindings、driver/oracleはdev/test2。outer EOF flagはwait由来で、歴史的driver timestamp/OOM counters等の未保存限界をreceiptへ保持。旧7c57/277f/10a4/f973失敗は変更しない。9de6限定であり7658以降・全M7・独立監査/実provider/公開認定へ転用しない |
| E93: final7658 Native release A/B | `7658629a` / tree`7ab61388`。固定Node24.19.0/Rust1.97.1の13-target fresh A/Bがactual0/結合stream実EOF/wait、884.992秒。全13組のbyte/mode/owner一致、通常0755の26 ELFを別inode・single linkで保持し、4専有directoryとsource leaseを解放 | 独立照合に加え親が1180 sourceのmetadata/hash/Git blobs、全26 ELF/13全byte pairs、311 locked archives、10 tools/10 controllers/9 raw・metadataを再照合。host UID0と隔離view UID65534の違いを記録。同一host/trusted OSの再現性であり、driver compile・実RELEASE runtime・最終完全required/CI・cross-machine/hermetic・全M4/M7・独立監査/公開認定ではない |
| E94: final7658 Native drivers and scoped M4 RELEASE | `7658629a` / tree`7ab61388`。13 debug binsと10元driversの実2 commandsがactual0、外部の両実EOF/wait、1,051.550秒。default TLSは15 passed/1 ignored、明示的な旧9de6 RELEASEからのupgradeは1 passed/0 failed、計47.911秒でactual0/実EOF/wait | 23実Cargo attribution/profile・1180 sourceと全49保持ELFを独立照合し、親も再hash。旧ELFのidentity、13 RELEASEのread-only置換、全PID/private TMP回収を確認。driver/oracleはdev/test2で、13 subprocessesがRELEASE。M4普通source reviewに新しい具体的指摘なし。最終完全required/同head CIと全M4・原12総合M7は未完了 |
| E95: final7658 complete RELEASE CLI and original ordered custody | `7658629a`で新しく実compile/normal reflink保持したCLI lib harnessと13AのRELEASE CLIを明示。元5 families・publication6 lifecycles・E67停止後復旧・作成application Coin6操作がactual0/結合stream実EOF/wait、6.500秒。outerはactual0/両実EOF/wait、6.901秒 | 全1180 sourceと両ELF不変、全positive flags・28 service summariesと独立nonce9/cap6/supply5Mを親で再照合。完全final fixture JSONを保持し、専有container解放とNode finallyを確認。各child/signatureの独立ledgerとは呼ばない。別のoriginal ordered RELEASE4-worker/4-frontend TLSもactual0/両実EOF/wait、inner14.049秒/outer14.118秒。全76 role children/17 Docker clients、完全raw45653 bytesとwire7438/decoded58103 bytes、fence3/QC3/新規height2と専有資源不在を親で照合。最終完全required/CI、原12総合・新しいpositive fee-claim backend・全M2/M7は未完了 |
| E96: genuine positive Split immutable policy | 別branch `348b5c6c` / tree`c2f52685`。全6 component commandsがactual0/両実EOF/wait、923.669秒。全CLI401 passed/0 failed/6 ignoredと新4 policy controls、元genuine helper compile・strict3crate Clippy/fmt/diffが成功。明示的なCLI追加producerと元のfirst-successor ignored selectorもactual0、1 passed/0 failed/0 ignored・policy marker1、計75.461秒 | 全1184 source・17 tools・10実ELFと完全raw162 frames/11 operationsを親で再照合。実genuine authorityと既存signature/candidate byte一致の限定資格。現在の7658 branchへ未統合で、新Q custody backend・別UID/PTY lifecycle・nonce/escrow現在性・元long recurrence・最終完全gate/CI/全M2は未完了 |
| E97: certified FastVote candidate failures retained | 別branchのcandidate1は7 compile errorsで失敗。source修正 `9ae82497` のattempt2では実native lib compileはactual0だが、検証controllerのCargo package ID誤認で失敗。型・manifest/source/profileの条件を保持して修正したattempt3はwhole native243 passed/1 failed/0 ignored | 新13 controls・旧9 IPC/4 HTTP controlsは実成功したが、元LGv2 genuine fixtureをcausal専用frontendへ接続する追加assertionが拒否され、後続gatesは未実行。全raw/EOF/wait/source/ELF/cleanupと旧失敗を保存。production profile guardを弱めず、元LGv2全assertionsを保持したcausal siblingを `5dc53a5c` に追加。attempt4ではnative whole245 passed/0 failed/0 ignoredと元LGv2/causalの両genuineが成功したが、operator起動callのerror型変換漏れE0277でcompile失敗。後続gatesは未実行。全失敗を保持し1行修正48dbを固定、修正後owningはE100で成功。実別UID・現在branchへの統合・完全gate/CI・全M2は未完了 |
| E98: positive Split protected-backend ordinary component | 別branch `c7e617e3` / tree`31352862`。全6 commands/16 operationsがactual0/両実EOF/wait、918.721秒。whole CLI406 passed/0 failed/6 ignored、新4 policy/5 closed phase codec・approval controls、元genuine consumer helper compile、strict3crate Clippy/fmt/diffが成功 | 親が全raw1569 frames/548 CargoJSON、20実ELF、1190 source・17 toolsを再照合。peak1,758,355,456 bytes/swap0/OOM0、全記録PID/cgroup・専有short TMPの回収を確認。現在の7658 branchへ未統合。production CLI binはまだ未linkで、genuine first-successorの実CLI prepareと実別UID/PTYのLeg/Claim署名・取消/復旧/再起動、最終完全gate/CI/全M2は未完了 |
| E99: genuine positive Split production preparation consumers | 別branch `c7e617e3` / tree`31352862`。E98の全6 commands/406 passedを保持し、実際の不足CLI binを追加compileしてから元のfirst-successor ignored selectorを実行。全2 commands/11 operationsがactual0/両実EOF/wait、70.589秒。元selectorは1 passed/0 failed/0 ignored、policy marker1と無条件のproduction CLI prepare assertionsが成功 | 親が完全raw109 framesとE98の1569 frames、1190 source・17 tools・10実ELF、outer70.682秒/両実EOF/waitとshort TMP回収を再照合。実genuine後継authority・保存host request/intent・両phase prepare bytes/破損拒否の資格。追加prepare entrypointsは同一process内であり、protected key/service・別UID/PTY・全M2/M7の資格ではない。7658へ未統合。追加UID fixture3b8eは証跡copy順と異常終了時signalの2件を普通reviewで指摘し、未実行のまま修正中 |
| E100: certified FastVote protected backend ordinary component | 別branch `48db5e86` / tree`0b2945db`。全7 commands/18 operationsがactual0/両実EOF/wait、210.375秒。全native245 passed/0 failed/0 ignoredと元LGv2/causalの両genuine、全operator159 passed/0 failed/0 ignored、strict native/operator/client Clippy・fmt/diffが成功 | 親が完全raw1085 frames、1185 source・17 tools・実CargoJSON/profileと5異なるELF identitiesを再照合。qualified target4の明示reuseでありfresh buildとは呼ばず、旧native原本/保持物は不変。peak884,031,488 bytes/swap0/全memory events0、全記録PIDとshort TMP回収。旧4失敗を保持。現在の7658 branchへ未統合。追加F7797の実別UID/TLS/保存済み再送・最終完全required/CI/Native・全M2/M7は未完了 |
| E101: certified FastVote UID fixture compile failure | 別branch `77978850` / tree`391d0362`。four-bin compileはactual0/429.609秒。続く追加ignored harness compileはactual101で停止し、outeractual1/両実EOF/wait、463.679秒。後続syntax/fmt/strict Clippy、inventory・Docker/runtimeは未実行 | 独立に1190 source・17 tools・完全raw838 frames/7 operationsと四つの実CargoJSON bin identities、失敗TMP/target、全PID/cgroupとouter終端を照合。保持ELF directory・build receipt・harness ELFは未生成。ObjectEffectのimport先とDrainSignerProgressRequest.signer参照の2件だけを `b8edcabb` で修正し、全assertions/oraclesを維持。修正後producer2・実別UID/TLS・統合/全体qualificationは未完了。旧失敗rawを成功へ置換しない |
| E102: positive Split UID component strict-lint failure | 別branch `1ed3e8f`。CLI全406 passed/0 failed/7 ignoredと追加genuine/exporter helper compileはactual0。続くstrict Clippyは未使用ExternalSigner importのためactual101。outeractual1/両実EOF/wait、943.091秒 | 全1195 source・17 tools・20実ELF、完全raw1561 frames/10 operations、全PID/cgroup回収を独立照合。failed TMP/targetと旧rawを保持。fmt/diff・実別UID/PTY・genuine inline submissionは未実行。`a41bd6c5`でimportのみ修正し、同じ全gatesの再検証を準備。全M2/M7の成功には数えない |
| E103: certified FastVote UID fixture version-binding compile failure | 別branch `b8edcabb`。four-bin compileはactual0、追加harnessはobject.versionのu64をrusqliteへ直接渡す型誤りE0277でactual101。outeractual1/両実EOF/wait、1.933秒 | 全1190 source・17 tools・完全raw389 frames/7 operationsと既存四つの実bin不変を独立照合。追加harness/保持5ELF receipt・後続gates・inventory/runtimeは未生成または未実行。`71d79292`で実ownerの8-byte big-endian BLOB表現へ検証queryだけを合わせ、元canonical bytes assertionを維持。修正後producerは未実行。旧失敗とTMP/targetを保持し、成功へ置換しない |
| E104: positive Split UID component strict gates | 別branch `a41bd6c5` / tree`656f11f9`。同じ全6 commandsがactual0/両実EOF/wait、inner81.108秒/outer81.181秒。CLI全406 passed/0 failed/7 ignored、新4 policy/5 custody controls、genuine helper compile・strict3crate Clippy・fmt/diffが成功 | 親が1195 source/Git blobs・17 tools、完全raw878 frames/16 operations/548 CargoJSONと現19 target ELF+新保持CLI libを再照合。旧target18 identitiesは不変、CLI libだけ正当なactual再compileとして明示し、旧保持物と全失敗証拠を保存。全PID/cgroup・TMP回収。追加UID probeはcompileのみで、実genuine/UID/PTY/全M2/M7は未達 |
| E105: certified FastVote actual five-ELF producer | 別branch `71d79292` / tree`6fe0772b`。全6 build/構文/fmt/strict Clippy commandsがactual0/両実EOF/wait、inner218.836秒/outer218.924秒。実CargoJSONから4 binsと追加harnessを通常0755・single link・別inodeの5保持ELFへ固定 | 親が1190 source/Git blobs・17 tools、完全raw770 frames/21 operations/728 CargoJSON、全5 source/保持物・既存4 binsの全前後identityを再照合。target1の明示reuseでfresh buildとは呼ばない。全PID/cgroup・TMP3回収、過去2失敗は保持。追加harnessは未実行で、inventory・実別UID/TLS/全M2/M7の成功には数えない |
| E106: certified FastVote read-only inventory | `71d79292`の固定5保持ELF、22 fixture sourcesと4実loader/librariesをNode24で照合。actual0/両実EOF/wait、inner0.694秒/outer0.770秒。完全stdout JSONが保存inventoryと一致し、Docker clients0・資源作成0を確認 | 親が1190 source/Git blobs・tools・全5 ELF/4 librariesのmetadata/hashと完全rawを再照合。外部samplerより先に完了したためexternal InvocationIDは未観測のまま保持し、innerの実cgroup limitsを照合。inventoryの未使用UUIDを後続runtimeのowner pinへ転用しない。実UID/TLSは別attempt |
| E107: positive Split genuine public-export failure | `a41bd6c5`で実CLI producerはactual0、続く元first-successor selectorはmanifest-historyのnested directoryを平坦archive APIで読むためactual101。outeractual1/両実EOF/wait、64.096秒 | 独立に1195 source/Git blobs・19 own/17 component tools、全11 runtime bindingsと4 libraries、完全raw141 frames/9 operations・全PID/cgroup回収を確認。完全な公開資料は未生成で、144 source filesの部分copyとindexを含む145 filesだけを保持。元fixtureはunwind時にRAII削除されており、元history treeを保持したとは呼ばない。Node/UID phases成功0。既存nested-history owner契約へexporterと読み手を合わせ、元拒否条件・完全authority検証を維持して再検証する |
| E108: certified FastVote strict phase-marker failure | `71d79292`の初回実UID attemptはactual1/両実EOF/wait、inner1.264秒/outer1.329秒。UID12001/gid12001/caps0のprepare-inputs probe自体は1 passed/0 failed/0 ignored・endpoint counts全0で成功したが、libtestの行prefixにより厳密な行頭marker検査が拒否 | 全1190 source/Git blobs・22 fixture sources・5 ELF/4 libraries、完全Node JSON・636-byte wire/583-byte復号とsole child全264 UTF8 bytes、全15 fixture clientsの終端・専有資源解放を独立照合。親の追加2 read-only queriesでも対象container/volume不在を確認。worker/署名段階は未到達。`5be398ec`でRust markerの先頭改行だけを修正し、strict parser/全件数・拒否条件は維持。修正後producerはE109で成功、runtimeは未実行 |
| E109: certified FastVote marker correction strict producer | 別branch `5be398ec` / tree`b6aad460`。全6 commandsがactual0/両実EOF/wait、inner23.459秒/outer23.543秒。新markerを含む追加harnessと4 binsの通常0755・single link・別inodeの5保持ELFを固定 | 親と独立reviewが1190 source/Git blobs・17 tools、完全raw694 frames/21 operations、全5 source/保持ELFと旧4 compiler bins・旧5保持ELFの不変、全PID/cgroup・TMP4回収を確認。strict parserと全元assertionを維持。component buildのみで、修正後の実別UID/TLS runtime・全M2/M7は未完了 |
| E110: positive Split nested-history correction and four regressions | 別branch `fff121c2` / tree`a9c1aca8`。全7 commandsがactual0/両実EOF/wait、inner109.913秒/outer110.001秒。全CLI406 passed/0 failed/7 ignored、history exportの4 named regressionsは4 passed/0 failed/0 ignored、strict Clippy/fmt/diffも成功 | 親が1195 source/Git blobs・17 tools、完全raw842 frames/17 operationsと現20 target+新保持ELFを再照合。flat cut契約を維持し、履歴だけ既存bounded recursive APIへ接続。structural transport closureであり、descriptor由来のsemantic exact inventoryとは呼ばない。旧保持2件・失敗319 files/10 dirsは保存、全PID/cgroup/TMP回収。修正後genuine/UID/PTYは未実行 |
| E111: certified FastVote actual context mismatch | `5be398ec`の修正後実UID attemptはactual1/両実EOF/wait、outer11.098秒。4 worker/4 frontendと準備・権限/UID/期限/profile/TLS拒否controlsの後、a-prepareのSDK照合が認証profile expected1/actual2を拒否。Aの有料prepareと後段成功は0 | 独立に1190 source/Git・22 fixture sources・全5 ELF/4 libraries、全15 Docker clients/55 role childrenのwait/EOF、wire6898 bytes→完全復号50420 bytesを照合。全childにU+FFFDなし、再構成UTF8の41901 bytesがcounterと一致。専有資源解放を確認し、親の追加2 read-only queriesも0/空。oracleのEOF assertionは失敗abort後の二次的観測として保持。`d58c874a`で既存canonical認証profileから3つの期待IDを取得し、exact context verification/全39 guardsを維持。修正後producerはE113で成功、runtimeは未実行 |
| E112: positive Split wrapper temporary-pin failure | `fff121c2`の次attemptはactual1/両実EOF/wait、outer0.847秒。mandatory CLI producerの前段guardが、新TMP pathに残った旧TMP_INODEを拒否。全6 operations/12 raw framesを保持 | Node24 --versionは0だが、CargoJSON/CLI producer合格・ldd・元genuine selector・selected Node/UID/Dockerは全て未到達。独立に1195 source/Git・19 own/17 component tools・現21 ELF・10 bindings/旧CLI・失敗319 files/10 dirs/旧保持2件の不変と全8 saved PIDs/cgroup不在を確認。TMP2は空のまま保存。wrapperのTMP_DEVICE/TMP_INODE、owner tuple、実filesystem identityを明示的に一致させる新attemptを準備し、失敗を上書きしない |
| E113: certified exact-auth-profile strict producer | 別branch `d58c874a` / tree`d311bad0`。全6 commandsがactual0/両実EOF/wait、inner21.742秒/outer21.823秒。既存canonical profile2/scheme1/address binding2からexpected contextを構築する修正を含む全5 source/保持ELFを固定 | 親と独立reviewが1190 source/Git blobs・17 tools・9入力、完全raw623 frames/21 operations、旧4 compiler binsと旧5保持ELFの不変、全PID/cgroup・TMP5回収を確認。コンパイルとstrict gatesのみで、修正後の実UID/TLS lifecycle・全M2/M7と統合source全体の合格は未達 |
| E114: positive Split actual no-approval boundary and failure cleanup | `fff121c2`の次attemptは実CLI producer/lddが0、元genuine selectorがfirst-successorでactual101。outeractual1/両実EOF/wait、33.370秒。公開archive234 filesの生成後、別UIDの承認なしLeg署名は正しくexit1/出力なし/public no_approvalを返したが、fixtureがRust enum表記NoApprovalを期待して拒否 | 完全outer raw142 frames/9 operations、inner135 frames/36 operations、21 host operationsと全32 saved host PIDs/cgroup・専有container/volume不在を照合。公開archiveとNode試験資料を保持し、1195 source/Git・全入力/345過去失敗files等の不変を確認。強制停止後に残るsocketによりstrict file-only volume accountingも二次的に失敗。PTY承認/署名/元protected submit成功は0。実public statusのexact照合と、serviceの実wait/PID不在後に記録済みexact socketだけを処理する修正を進め、strict file-only accounting/元97 operations・各capsを維持する |
| E115: certified FastVote drain page boundary | `d58c874a`の実UID attemptはAのprepare/retention/replay・有料apply/replay、B新規apply、C保存、元ordered Freeze、frontier初回/再送を通過後、drain-firstでpage.terminalのfixture assertionが失敗。actual1/両実EOF/wait、outer24.301秒 | 完全復号73138 bytes、全125 role recordsのwait/EOF・U+FFFDなし/再構成UTF8 54106 bytes一致、全15 Docker clientsと専有資源解放・1190 source/全入力を照合。親の追加2 read-only不在queriesも0/空。満杯ページはnonterminalとする既存仕様に対し、3 entriesの要求limit3をterminalと誤認。`94eee3b3`で要求limitだけ4へ変更し、実entry数3/terminal/全署名・stage/import/confirm検証と既存limit1の全stream検証を維持。後段drain/union/最終lifecycle合格は未達で、oracle EOFはabort時の二次観測として保存 |
| E116: positive Split complete-evidence budget amendment | 元97 operationsの実normal prefixと残り固定command/resultだけでframed rawの下限322101 bytesとなり、旧262144-byte上限で完了不能と確認。`f14473ed`のexact no_approval/socket後処理に続き、`a4f6c1a8`でraw allowanceだけ655360 bytesへ変更し、ADR-0270へ2026-10-17の修正理由と有限capture条件を記録 | 全97操作・完全pipe/PTY/command/result bytesを維持。per-stream64KiB/meta256KiB/candidate64KiB・mounted-copy1MiB、512MiB/no swap/64MiB volume・各時間/UID/authority/拒否条件は保持。raw640KiB+meta256KiB+candidate64KiBと通常tar overheadは既存1MiB以内。任意fragmentationの完了保証ではなく、実captureが全量収まった場合だけ成功。旧profile/全失敗証拠/inert component5は保存。新component6/runtimeは未実行 |
| E117: certified drain-boundary strict producer | 別branch `94eee3b3` / tree`b6aecc27`。要求page limitだけを4へ直した全6 commandsがactual0/両実EOF/wait、inner20.611秒/outer20.680秒。実CargoJSONから新harnessを含む5保持ELFを固定 | 親と独立reviewが1190 source/Git blobs・17 tools・9入力、完全raw744 frames/21 operations、旧4 compiler bins・旧5保持ELFの不変、全PID/cgroup・TMP6回収を確認。component buildのみで、修正後の実UID/TLS後段drain/union/最終lifecycle・全M2/M7の合格は未達 |
| E118: positive Split 640KiB-profile component gates | 別branch `a4f6c1a8` / tree`65090b4b`。同じ全7 commandsがactual0/両実EOF/wait、inner9.875秒/outer9.961秒。CLI全406 passed/0 failed/7 ignoredと元9 policy/custody controls、追加exporter4 passed/0 failed/0 ignored、strict3crate Clippy・fmt/diffが成功 | 親と独立reviewが1195 source/Git blobs・17 tools・311 archives、完全raw807 frames/17 operationsと実CargoJSON/profile、20 target ELF・新保持CLI lib、旧保持物3個と973 failure files/141 directoriesの保持、全PID/cgroup・TMP6回収を確認。元targetを明示reuseし再compileなし。modified Node/Python fixtureはこのcomponentで未実行で、実97操作のUID/PTY/genuine submission・全M2/M7の成功には数えない |
| E119: certified drain member possession boundary | `94eee3b3`の実UID attemptはterminal page取得とstagingまで成功後、最初のA member confirmで409 drain-proof-not-retainedとなりactual1。inner24.414秒/outer24.474秒、両実EOF/wait | 完全復号73220 bytes、全125 role recordsのwait/EOF・U+FFFDなし/再構成UTF8 54187 bytes一致、15 Docker clientsの終了と専有資源解放・1190 source/全入力を独立照合。通常publication/ACKと別のdrain proof保持が必要と確認し、`812458ba`で全3 staged entriesのgenuine proofを既存ownerでimportしてからconfirmするfixtureへ修正。Cの事前409・全署名/identity/union/oracleと上限を維持し、追加HTTP4回・child追加なし。修正後のC import/union/pre-DrainSet/最終lifecycleは未検証。oracle EOFはabort時の二次観測であり、全元assertionと失敗資料を保持。Docker client全streamの別raw保存はなく、metadata照合とstart wireの完全照合を区別する |
| E120: positive Split complete-metadata budget failure | `a4f6c1a8`の実CLI producer/lddは0、元selectorはfirst-successorで101。outer43.489秒/両実EOF/wait。mounted readyが出ず、実103-byte errorはcomplete evidence metadata exceeds256KiB | 完全outer raw142 frames/9 operations・18 host operations、1195 source/Git・19 own/17 component tools・21 ELF/11 bindings/4 libraries、旧973 files/141 dirs/保持3個、全29 saved PIDs/cgroup・専有資源解放を独立照合。公開233 leaves+index、291 source/292保持filesを保存。inner raw/meta/tar/candidateが保存されなかったため、97操作/PTY/署名/socket/serviceの成功には数えない |
| E121: certified all-staged-proof strict producer | 別branch `812458ba`。全6 commandsがactual0/両実EOF/wait、inner22.747秒/outer22.852秒。完全raw903023 bytes/704 frames/21 operations、新harnessを含む5実CargoJSON保持ELFを固定 | 親と独立reviewが1190 source/Git blobs・17 tools・9入力、旧4 compiler bins/旧5保持ELFの不変、全PID/cgroup・TMP7回収を確認。component gatesのみで、修正後の実UID drain/union/最終lifecycleは未検証 |
| E122: positive Split complete-metadata finite envelope | 元97操作/8approval/9socket schemaのmetadata下限320224 bytes・保守上限323624 bytesを照合。`207ea842`でmetadata524288 bytesとmounted tar1310720 bytesへ限定変更し、全フィールドとraw655360/candidate65536 bytesを保持 | payload合計1245184 bytesと通常tar overheadは新有限上限以内。任意PAX/framingの成功保証ではなく実全量captureが必要。今後のownerで例外にする保持fileは正確なinside.tar/host-11.stdoutの2個のみで、他は1MiB・総量24MiB/counts・10GiB growth・元97/22操作・全権限/拒否/時間/資源条件を維持。旧失敗profileは保持し、新component/runtimeは未実行 |
| E123: bounded canonical frame mutation campaign source | 統合branchの`0b26e721`に非ignored testと手順書を追加。依存/manifest/production/既存recipesを変えず、4固定seeds、独立wire256 frames・4096 mutations・12固定拒否controlsを1024-byte/8-field内で検証するソースを普通review | 独立format oracleの受理/type/version/全fieldsとproduction再encodeのbyte一致、過大field countの明示拒否を確認する。このsource行の時点ではコンパイル/実行は未達。実結果はE126へ追記し、exhaustive/coverage-guided fuzz・独立security監査・全M7の成功には数えない |
| E124: certified post-Freeze exact refusal boundary | `812458ba`の実UID attemptはdrain proof import・union・DrainSet未確定時の実行拒否まで成功後、新prepareの期待400/実500でactual1。outer29.383秒/両実EOF/wait | 全127 roles・完全復号74020 bytes、再構成UTF8 54657 bytes/U+FFFDなし、15 clientsの終了と専有資源不在を照合。既存PersistenceInvariantの500 invalid-node-outputを保存し、`5d8d7f46`でfresh intentの事前認証とexact status/bodyだけを合わせた。ACK byte再送と完全image不変を保持し、任意500を合格にしない。旧失敗を保存し、修正後runtimeは未検証 |
| E125: positive Split metadata-profile strict component | `207ea842`の全7 commandsがactual0/両実EOF/wait、inner9.794秒/outer9.872秒。CLI406 passed/0 failed/7 ignored・元9 policy/custody controls・exporter4 passed/0 failed/0 ignored、strict Clippy/fmt/diffが成功 | 完全raw741 frames/754255 bytes/17 operations、1195 source/Git・17 tools・311 archives・20 target ELF/新保持CLI lib、旧1581 failure files/270 directories/保持4個と全PID/cgroup/TMP7回収を照合。component成功を後続genuineまたは統合head全体の資格にはしない |
| E126: bounded canonical mutation actual campaign | 統合head `ab8ff2da` / tree`2b3c93f2`で4固定seeds・256 originals/4096 mutations/12固定controlsの4364 decoder inputsを検査する非ignored testが1 passed/0 failed/0 ignored。crate全target/all-feature strict Clippyと追加test rustfmtもactual0 | 完全raw33 frames/11 operations、1207 source/Git・15 tools・311 checksum-pinned archives、実Cargo Running由来ELFと全PID/cgroup/TMPを親と独立reviewで照合。inner2.763秒/outer2.830秒。有限の固定入力campaignで、unique inputs/各case transcript・coverage-guided/exhaustive fuzz・security監査・全M7の成功とは呼ばない |
| E127: certified exact-refusal strict producer | `5d8d7f46`の全6 commandsがactual0/両実EOF/wait、inner21.244秒/outer21.334秒。完全raw725 frames/904514 bytes/21 operations、新harnessを含む5実CargoJSON保持ELFを固定 | 1190 source/Git・17 tools・9入力、旧4 compiler bins/旧5保持ELF不変と全PID/cgroup/TMP8回収を親と独立reviewで照合。component成功のみで、修正後の実別UID/TLS後段lifecycleは別attemptで検証する |
| E128: genuine positive Split actual distinct-UID protected submission | `207ea842`で元first-successor selectorが1 passed/0 failed/0 ignored、actual0/両実EOF/wait、inner49.791秒/outer49.870秒。別UIDのLeg/Claim承認・署名・取消・鍵復旧・再起動・expiryと実protected Aの元ordered提出が成功 | 完全outer152 frames/13 operations、inner351 frames/97 operations、22 host operations、8 successful PTY/2拒否、8canonical approvalsと9exact normal socket wait/不在/FD閉鎖を照合。raw456372/meta320761/tar783360 bytesを全量保持。1195 source/Git・全tools/runtime bindings、旧1581 failure files/270 dirs/保持4個と309保持files/64 dirs、全37 saved host PIDs/cgroup/TMP回収を確認。既知fixture鍵の選択範囲であり、本番鍵秘匿・全M2/M7・統合head全体の資格ではない |
| E129: certified FastVote actual distinct-UID/TLS lifecycle | `5d8d7f46`の実4-worker/4-keyless-TLS fixtureがactual0/両実EOF/wait、outer30.526秒。全39 required controls・147 roles・27 probes・32 read-only SQL oracle exchangesが成功。4つの明示startup拒否だけexit1 | 完全wire10430 bytes/復号84355 bytesを厳密照合し、全childにU+FFFDなし・再構成UTF8 59099 bytes一致。全17 Docker clientsが0で終了し、専有資源は明確に削除。全1190 source/Git・5 ELF/4 libraries・toolsと旧失敗を保存。3署名family、A/B実apply/保存済み再送、C pre-import409/no-DrainSet409・nonce2/C未適用、元ordered Freeze、frontier/union3とfence6再開後の全source/body/anchor imageを検証。親の追加2不在queriesも0/空。全M2/M7・統合head全体の資格にはしない |
| E130: final7658 literal complete required | `7658629a` / tree`7ab61388`でliteral npm ci --prefix adapters/cloudflare-workers と ./scripts/check-all.sh がともにactual0/merged pipe実EOF/wait。inner合計15878.474秒、完全log706439 bytes。Rust145 summariesの合計4366 passed/0 failed/39 ignored、元3 extended lanesと各provider checksが成功 | 1180 source/Git・50 tools/aliases・311 locked archive checksumsと元8links/e8terminal withdrawals/35roles/delay7 assertionsを照合。unit invocation一致/最終journal/owner MainPID0/ExecMain0、cgroupと既知owner/Cargo/fixture PIDs不在を確認。detached dispatchのためlong outer capture/両外部EOF/reapを主張しない。既存TMP/cacheは保持。7658の選択required資格であり、新統合head・原12 RELEASE runtime・hosted CI・全M7/監査/公開の資格ではない |
| E131: 7658 original12 RELEASE runtime terminal | `7658629a` / tree`7ab61388`の元10 whole + 2 exact ignoredが全actual0、94 passed/0 failed/3 ignored。actual outer0/両実EOF/wait、12,119.104秒。親receipt`r4-runtime-promoted-parent-qualified-1017.json` (`87873e92`) と独立照合が完了 | strict24 events/12完全本文・49 ELF・1180 source/Git・tools/13 byte pairsを照合。既知535 PIDs・4 TMP・cgroup・leaseの消失を確認。e6f1や後続source、全M2/M3/M4/M7の成功へ転用しない |
| E132: 7658 full required and exact-tree all8 hosted CI | 同じ7658のliteral npm ci/check-allはactual0、15,878.474秒。run`39000226577`の全8 jobsがsuccess、全8 checkoutのtree`7ab61388`とparents befca7e9/7658629aを照合。親required receipt`d1d2e963` / CI receipt`cba68bb3` | 完全required/CI rawと独立照合を保存。145 Rust summaries/4366 passed/0 failed/39 ignored。localはdetached ownerでありouter両EOFを新たに主張しない。原条件対応と後続sourceの失敗は別に保持 |
| E133: e6f1 integration full-required failure and Native build | `e6f1dfe3` / tree`71a2a77e`。literal npm ciは0、check-allはactual101、2443.274秒。runtime-sqliteの`checkpoint_snapshot_restores_source_free_complete_rows_bodies_fence_and_receipt_replay`でConfiguredCheckpointAuthority再openがIndependentAnchorError。全体停止時点で2800 passed/1 failed/14 ignored | 元raw/ELF/target/private cacheと失敗receipt`ebc86b9b`を保存。別のfresh13 A/Bは全byte/mode/owner一致、親`385602e3`・独立`8abe9fcc`で照合済み。23 debug/driver buildは2 commandsがactual0、outer954.573秒/両実EOF/wait。実runtime/CLI・新source全体の合格には数えない。e6f1 hosted CIは継続中 |
| E134: ordinary checkpoint diagnosis and test-only isolation | 旧診断1はsubordinate終了の判定誤りで失敗、親`120c766b`。修正診断2は1回だけ22 passed/0 failed/0 ignoredで対象testも正常、2回目はGDBのsubordinate待機中に240秒上限へ達して失敗。独立receipt`2aa57eb4` | 全raw、旧57 files/14 dirs、新OUT/TMPを保持。診断2の4 pidfd cleanup entries/100既知PIDs・LWPs消失を照合。元の自然失敗原因は未確定。対象1件を同名exact childで実行し全assertionを保持する19行のtest-only隔離を準備、実行は未完了。production lease・global parallelism・元selectorは変更しない |
| E135: transfer and genesis Split/Merge recovered-key fixture source | 転送`fb00a82a`とその子`285df467`の分割/結合を別作業コピーに保存。実署名前後の同一request byte比較、元と新しい取消・再起動拒否を追加。285dは1207 source/Git・既存45 defs・元phaseの保持を親`6f619c2c`/独立`a629c416`で確認 | source-only。実CLI/Docker/鍵操作・本体再compile・各fixtureの実行成功はまだない。新署名は提出せず、元preimageを使う独立signing-only要求であり新business chain/currentness/nonceを主張しない。resource capsを維持し、fb00実行成功後に285dを別に実行する。全M2や新source gateは未完了 |
| E136: W checkpoint isolation targeted prefix | `5f6b1819` / tree`468c7be5`。同名exact checkpoint testは1 passed/0 failed/0 ignored、続くall-feature ordinary runtime-sqlite libは123 passed/0 failed/7 ignored。両command actual0/結合stream実EOF/wait、親`checkpoint-isolation-required-final-targeted-prefix-parent-qualified-1017.json` (`7c7b8f1e`) | E134の19行test-only隔離を実行した後続証拠。元assertion・production lease・global parallelism・全selectorを保持。自然失敗の原因を確定した証拠ではなく、E133のactual101とE134の診断失敗を保持。対象prefixだけで完全required成功・owner全体cleanupを主張しない |
| E137: final5f Native13 fresh A/B | `5f6b1819` / tree`468c7be5`の13-targetを2回fresh buildし、13組全byte/mode/owner一致、26 ELFとsource1207を照合。actual0/outer両実EOF/wait/reap、887.840秒。親`integration-native-promoted5-ab-parent-qualified-1017.json` (`7ba6f2a8`) | 311 locked archivesと231展開treeの実入力も独立照合。Node24/Rust1.97.1、元7200秒/16GiB/swap0/CPU4と13 targetsを維持。build/provenanceだけでruntime・MB source全体・全M7の合格へ転用しない |
| E138: final5f driver23 and H6 harness producer | 同5fの13 host-debug +10 driverを2 commandsでactual compile、23 CargoJSON/全49 ELFを照合、outer0/両実EOF/wait、1016.340秒。別の同source H6 CLI lib harness producerもactual0/両実EOF/wait、307.592秒。親driver`217420da` / H6`bbfcd03a` | `integration-native-promoted5-drivers-parent-qualified-1017.json` / `integration-native-cli-harness6-parent-qualified-1017.json`。H6は実CargoJSON・normal0755/単一link/別inode保持を確認し、旧H5と同byteでも資格を借用しない。compile-onlyでありtest実行・原12 runtime・全M4/M7ではない |
| E139: final5f scoped TLS and actual RELEASE CLI | 同5fのdefault local TLSは15 passed/0 failed/1 ignored、明示した実old9de6 hostからのupgrade exact1は1 passed/0 failed/0 ignored。actual0/outer両実EOF/wait、45.587秒、親`integration-native-later5-tls-upgrade-parent-qualified-1017.json` (`057917f8`)。同source RELEASE CLI +実H6では元5 families/6 publication lifecycles/E67/Coin6操作/T/Gと85 flagsがactual0、outer7.133秒、親`checkpoint-isolation-release-cli-final1-parent-qualified-1017.json` (`02c69559`) | W CLIのtest/docs bridgeは空。1207 source/49 ELF/20 tools/10 provenanceと専有資源回収を照合。内側merged EOFと外側2 physical EOFを区別。原12 RELEASE・完全required/CI・全M4/M7の終端成功はまだ加算しない |
| E140: actual transfer and genesis Split/Merge stopped-key recovery | T`fb00a82a`はactual0/outer両実EOF/wait、7.339秒、親`transfer-recovery-fixture-runtime5-parent-qualified-1017.json` (`41eefae9`)。G`285df467`もactual0/両実EOF/wait、7.203秒、親`genesis-split-merge-recovery-fixture-runtime1-parent-qualified-1017.json` (`50a1fe33`)。同じ新frameの元鍵referenceと復旧署名全byte一致、旧/新取消・restart拒否・socket不在を検証 | 実ELFは旧e6f1。T/Gへはtest/docsだけの厳密3/4-file bridge、他1204/1203 blobs不変。E135はsource-onlyだった保存時点の履歴として保持し、今回の実行と分ける。Tはreference1/1/1/0・復旧3/3/1/2・restart2/2/0/2、Gは2/2/2/0・6/6/2/4・4/4/0/4。新business提出/currentness/nonce進行/所有権移行は含めない |
| E141: actual create and genesis mint/burn stopped-key recovery | C`d4413457`のfresh9dはactual0/outer両実EOF/wait、7.750秒、親`create-recovery-fixture-runtime1-parent-qualified-1017.json` (`35d7410c`)。MB`ad3ce3a0`のfresh9e/9fもactual0/両実EOF/wait、8.209秒、親`genesis-mint-burn-recovery-fixture-runtime1-parent-qualified-1017.json` (`808eaea3`)。同frame元鍵reference→停止/wait/PID/socket不在→同じ鍵のUID private-copy→署名一致・旧新取消/restart拒否を検証し、元C/T/G/E67/Coinを保持 | 実ELFは5f6b AB5/H6。C/MBはtest/docs厳密3/4-file bridge、他1204/1203 blobs不変。Cは15 normalchildren/8 files/4 absent refusals、MBは25/14/8と32KiB生成/48KiB出力/4KiB summary subcap内。全体の時間/資源/UID/出力上限は維持。元preimageを使うhistorical sign-onlyで、新9d Instantiateや9e/9f mint/burnのbusiness提出・live currentness・ownership migration・全M2は主張しない |


| E142: e6f1 hosted CI all8 terminal success | [run39017280255](https://github.com/sunriselayer/sunrise-edge/actions/runs/39017280255) はattempt1・全7 ownersと集約checkが成功。8 raw logsを再hashし、全checkout `f4348a03` / tree`71a2a77e`、parents `7658629a` / `e6f1dfe3`を実commit API・local Gitと照合。親`ci-run-39017280255-qualified-1016.json`、root照合`4a9554fe` | e6f1 hosted CIだけの成功。E133のlocal完全required失敗を保持し、後続5f/MB/J sourceや全M2/M4/M7の合格へ転用しない |
| E143: same-source genesis Coin identity handoff preparation | `fe542b82` / tree`da56660e`。既存A/Bの同じgenesis Coinをv1/A→v2/B→v3/Aへ有料移行するfixtureを追加。strict3 commandsがactual0、親`eafaa585`。新H7のactual CargoJSONから別inodeに保持したCLI lib ELFは`e329a804`、親`55846272`。private cacheで全311 archive/manifest/markerのfresh censusを照合し、新13 A/Bを実行中 | Bは別prefunded fee Coinを使用し、新しい鍵・key copyは追加しない。現時点で追加fixture117 flagsの実runtime成功はない。compiler/provenanceを所有権移行の実行成功や全M2完了に数えず、A/B後に新ldd inventoryと実Dockerを実行する |
| E144: Cloudflare CLI five-profile migration source | `codex/cloudflare-cli-migration-1017` のfe54上に5つのplain-object config leaves、共有profiles、既存Env名を維持するtype renderer、VitestのnewConfigとexact外部`cf@1.0.0-beta.13`を反映。Node24 syntax/git diff checkは成功。直接のWrangler commandsとdirect dependencyを除去 | 実cf typegen/positive・stale fingerprint no-overwrite/TypeScript/lint/4 Vitest/npm ci・完全requiredは未実行。既存plugin内部のtransitive Wrangler SDKは保持。source反映をprovider deploymentや実migration・公開認定に数えない |
| E145: fresh fe54 Native13 A/B and H7 qualification | J`fe542b82`の新13-target A/Bはactual0、両lane全13 ELFをbyte照合し、root/独立peerがsource1207・tool21・CargoJSON・311 archive/metadataと選択231 expanded bodiesを照合。親`genesis-coin-identity-handoff-native6-private1-1017-ab-parent-qualified.json` (`ab142f8d`)。H7は新test ELF`e329a804`を別inodeへ保持、親`55846272`。新2-ldd inventoryも親`e4b77cec`で照合 | compiler/lddだけの成功。追加fixture runtime・117 flags・所有権移行・全M2/M7の成功へ転用しない。新H8は修正済みRust oracleを含む別sourceから作る |
| E146: actual handoff failures and two test fixes | runtime1はactual1、raw`a59296f1`・terminal`e08a23fa`。fixtureのumask0でCLI exportがprivate0600 guardに拒否され、実CLI呼出中だけumask077へ限定。runtime2はactual1、raw`cd5b36d6`・terminal`51c35903`。同transaction内生成・消費のfee予約はrunnerが永続effectへ出さずqueryはAbsentのため、effect_ids不在とexact Absentを要求するoracleへ修正。両修正をCF branchに反映、Node syntax/rustfmt/diff check0 | productionのexport policy・runner・queryを変更せず、既存CoinのTombstoned検証とgas/fee/refund/receipt/replay checksは保持。runtime2は旧H7での自然失敗。修正を含む新H8と実全117 flagsは未実行で、失敗を成功へ書き換えない |
| E147: actual cf migration prefix, prerequisites and SQL startup fix | CF2でliteral offline npm ci、実`cf workers types`全5 profile、positive check、stale/入力/CLI version全10拒否controlsとno-overwrite確認が成功。CF3で通常Rust/WASM+contract fixture producer、TS7/typecheck・lint・ingress/certified Vitestがactual0 | CF1のnpm config double-load失敗とCF2の生成WASM未準備失敗を保持。CF3はSQL self DOが旧published worker名を参照してstartupでactual1、SQL test0・contract未実行。schema必須workerは保持し、SQL/contract Vitestだけlocal class/useSQLite designatorへ上書きする修正を反映。実修正後全4 Vitest・全required/CIは未達。direct Wrangler commands/dependencyは廃止し、plugin内transitive SDKは保持。deployment/公開認定は主張しない |
| E148: current cf migration all four Vitest groups | `f6b5ffab` / tree`c920900e`でactual CF4の13 operationsが全0、76 raw frames・全26 streamsのhash/実EOF/waitを照合。型照合・TS7・lintに加えingress13/certified28/SQL10/contract15の計66 tests成功。source1215全Ns、元package bodies、生成WASM/fixture5入力不変と既知15 PIDs/cgroup不在を確認。root・独立peer親`cloudflare-cli-migration-validation4-parent-qualified-1017.json` (`0a52e00f`) | E144/E147は当時の未実行/自然失敗履歴として保持。直接Wrangler呼出しを廃止した実cf型生成/Node検証の技術範囲だけ。新source完全required/全8 hosted CI、provider deployment、全M2/M7は未完了 |
| E149: actual two-owner genesis Coin handoff | `f6b5ffab`の新H8はactual CargoJSONからtest ELF`8eeecd95`を別inodeへ正常保持し、root・独立peerがproducerを照合。親`401d40ca`。fresh 2 lddの後、実fixture runtime3はactual0/両outer実EOF/wait/8.730秒、raw`4c00a43d`の全117 expected flagsが一致。既存の同CoinをA→B version2/nonce1,0/replay1→A version3/nonce1,1/replay2へ実有料移行。親`cloudflare-cli-migration-fixture-runtime3-parent-qualified-1017.json` | root実照合とinert adapter作者の別照合を区別し、外部独立auditとは呼ばない。actual RELEASE CLIはfe54 Native6のままで、28-file差分・cfg(test)除外・804 build inputsの厳密対応を使用。H8/driverだけf6b5。26 normalchildren/2 PTY/30 leaves/6 absent refusals・生成71833B/出力28712Bは元上限内、private key copy追加0。前2失敗は保持。genesis Coinの選択範囲であり、creator/TreasuryCap・他asset/fee/account/governance移行・全M2/M7/公開条件を閉じない |
| E150: final5f complete required success | `5f6b1819` / tree`468c7be5`、exact checkpoint/SQLite lib/literal npm ci/完全check-allの全4 commandsがactual0・各merged EOF/wait、17,307.340秒。全149 Rust summariesは4,521 passed/0 failed/48 ignored、required部分147は4,397/0/41。元8リンク・e8の2 withdrawals・delay7・35 rolesと全adapterを維持。root・独立peer親`checkpoint-isolation-required-final-parent-qualified-1017.json` (`d3bd1bef`) | E133の自然失敗を保持。source1207・49tools・5proofs・7dir tuplesを照合。detached ownerのouter物理EOFは主張せず、自然終了/owner・全既知PID/cgroup不在後に所有unitだけを整理。M4はPR #322全8 CIの終端照合待ち。別source/PG/公開認定へ借用しない |
| E151: final5f original12 RELEASE runtime | 同`5f6b1819`の原10 whole +2 exact ignored selectors全12 casesがactual0/実pipe EOF/wait。24 events/12 full summariesは98 passed/0 failed/3 ignored、outer両実EOF/wait/reap0、12,920.211秒。全49 ELF・20tools/aliases・10producer refs・source1207と各caseの13 RELEASE read-only bindingsを照合。root・独立peer親`integration-native-promoted5-runtime-parent-qualified-1017.json` (`528d4842`) | 原7 epochs/e8 unlock・freeze-drain・2 withdrawals・35 rolesのsaved closureを維持。観測430 live kernel rowsで元16GiB/swap0/CPU4/tasks512/18600秒/stop45秒、既知550 PID・cgroup・2TMP不在を照合。launcherのfile redirection EOF flagと実12 pipe/outer2 EOFを区別。別source/全M7/公開認定へ借用しない |
| E152: final5f hosted all8 and M4 technical completion | [run39024805837](https://github.com/sunriselayer/sunrise-edge/actions/runs/39024805837) attempt1の7 owners +集約checkが全SUCCESS。全8 raw logs計1,558,963 bytesを再hashし、actual checkout`a7f33f4d` / tree`468c7be5`・parents`e6f1dfe3`,`5f6b1819`と全7 needs successを照合。147 Rust summariesは4,397 passed/0 failed/41 ignored、元8リンク/e8の2 withdrawals/delay7/35 rolesを保持。root`7d6f3901`・独立`97b2ba53` | E137/E139/E150と69-path原条件対応/独立ordinary reviewを合わせ、選択済みNative+SQLite/trusted-local-OSのM4 CODE/VERIFYを完了。receipt`888abf02`。E133の自然失敗を保持。別source・独立security監査・実オフホスト運用・全M7/公開認定は未完了 |
| E153: new public Rustls advisories and exact dependency update | e4fbの311 locked registry versionsに対するfresh OSVでRustls 0.23.45のRUSTSEC-2026-0346/0347/0348/0349を検出。公式4詳細と[0.23.46 release](https://github.com/rustls/rustls/releases/tag/v/0.23.46)を確認し、別branch`codex/rustls-advisory-update-1017`でCargo.toml/lockをexact0.23.46へ変更。公式archive checksum`48e13bd8`一致、normalized manifest全体はversion以外同一、他310 locked packages/全dependency edges/features/MSRV不変。更新後exact311 OSVは該当0件、root親`rustls-02346-source-and-public-metadata-root-qualified-1017.json` (`5ad360f7`) | point-in-time公開metadataとsource/integrity確認。npm registry bulkはraw該当0件で、npm audit CLI/metavulnerability判定とは呼ばない。API到達性/独立security監査・実build/TLS/完全required/CI/新Nativeは未認定。runtime-postgresの依存でもあるため、新sourceの元5-group完全PGと集約checkが必要。旧sourceの成功を修正版へ転用しない |
| E154: Rustls 0.23.46 complete hosted PostgreSQL qualification | `50fbf22d` / tree`ccae85a6`の[run39047321893](https://github.com/sunriselayer/sunrise-edge/actions/runs/39047321893) attempt1は元5 ownersとsuccess-only集約が全SUCCESS。全6 actual checkoutが同head/tree/parent`58a552e7`で一致し、全raw 765,484 bytesをroot・独立peerが照合。83 Rust summariesは1,482 passed/0 failed/20 ignored。14 protocol selectorsと4 auxiliaryの計18 exact実行が全1/0/0、元6 storage fault testsは各REQUIRED=1と固定PG/PgBouncer imageで成功。親`pg-run-39047321893-parent-qualified-1017.json` (`972ade9b`) | quiet実行のselectorは同checkoutのclosed registry・exact discovery/execution契約へ対応し、全nameがrawに表示されたとは扱わない。20 ignoredはwhole storage laneの値であり、別ownerが18 exact runsを実行。依存変更に必要な完全PGの資格だけ。新source完全required/全8 ordinary CI/Native/TLS/独立security監査・全M7/公開認定は未完了 |
| E155: Rustls 0.23.46 fresh Native13 A/B | `50fbf22d` / tree`ccae85a6`の13 targetsを2回fresh buildし、全13組のbyte/mode/ownerが一致。actual0/outer両実EOF/wait/reap、1,024.127秒。保存26 ELFは元の0755・単一link・別inodeのまま照合。source1215全Ns/Git・311 locked archive/metadataと選択231 expanded packagesの10,017 files/122,049,003 bytesを照合。親`rustls-native7-1017-ab-parent-precision2-qualified.json` (`25fc610b`、観測数補正`102a7fb3`) | authorの終端照合後、rootが同じreview済み有限readonly verifierを別実行し、全source/artifact/closure/reference観測を再照合。独立source/security auditとは呼ばない。保存70 samples中の69 live kernel rowsは元16GiB/swap0/CPU4/tasks512とOOM0、既知PID/cgroup・4 compiler/TMP・source lease不在を確認。rootのcache読取leaseも明示解放済み。current TLS/CLI/原12 runtime・完全required/全8 ordinary CI・全M7/公開認定は未完了 |
| E156: current Rustls RELEASE CLI and fresh H9 whole117 | 同`50fbf22d`の新H9はactual CargoJSONからCLI libtest ELF`52eb6386`を正常0755/単一link/別inodeへ保持し、compile+cpはactual0/両outer実EOF/wait、391.000秒。親`307f175b`。fresh 2 ldd後、新Native7 RELEASE CLI`f2cf9e8d`とのwhole fixtureはactual0/両outer実EOF/wait、9.336秒。raw18,288 bytesの全117 flagsが一致。元5 families/6 publication lifecycles/E67/Coin6/T/G/C/MBと実有料A→B version2/nonce1,0/replay1→A version3/nonce1,1/replay2・取消/restart拒否を確認。root・独立peer・author親`rustls-native7-fixture-runtime1-parent-precision2-qualified-1018.json` (`4146573f`、旧親`8a4f6ea1`を保持) | CLI/H9/driverは全て同50fb/tree・source1215の厳密一致で、旧artifactやsource bridgeを使わない。117の旧rawはpath集合の比較だけで、旧成功値/object IDを借用しない。19exec/2PTY/4serve/1host・30files/出力28,712 bytesは元上限内。1GiB/swap0/CPU1/tasks128の保存live unit properties・既知owner/external PID/cgroup不在を照合。未保存のruntime kernel samplesは主張しない。破棄済み個別stream/鍵/DBの再構成は主張せず、businessはcompiled oracleと完全aggregate rawへ対応。current TLS/原12 runtime・完全required/全8 ordinary CI・全M2/M7/公開認定は未完了 |
| E157: historical MB gate interrupted for Cloudflare CLI policy | 旧`ad3ce3a0`の保存済みpackage typecheckに直接`wrangler types`が残り、完全requiredの後段で実行されるため、root所有のunit/invocation`1e4129c4`・MainPID2223187を照合して停止。停止commandはactual0/両EOF/wait、owner PID/cgroup不在。結果`genesis-mint-burn-required-cf-policy-stop-result-1018.json` (`06c72cd1`)。literal npm ci成功とepoch8 freeze-drain endまでの部分ログ・source/cache/target/TMPを保持 | userの今後cf/cloudflareへ統一する指示に対応する制御中断。complete check-allの終端は未取得でnullのまま保持し、product failureや全体passへ変更しない。旧owner/sourceを改変・再起動せず、現行e4fb/50fbのcf版完全requiredを継続。ad3 hosted CI終端・現行source資格と分け、全M2/M7の完了へ加算しない |
| E158: current fresh23/full49 and RELEASE TLS/prior upgrade | 同`50fbf22d`の原2 compile-only commandsがactual0/両outer実EOF/wait、1,148.580秒。全13 debug bins/10 driversはfresh CargoJSON・package/source/profile/featuresを照合し、26 RELEASEと合わせ49個の異なるELF inode/706,709,848 bytesを照合。source1215・Rustls0.23.46を確認し、root・独立peer・author親`rustls-native7-1017-driver-parent-qualified-1018.json` (`b7e96dfd`)。同helperのdefault TLS15/0/1と実old9de6 hostのexact upgrade1/0/0はactual0/両outer実EOF/wait、50.466秒。親`rustls-native7-1017-tls-upgrade-parent-qualified-1018.json` (`a4f62568`) | compile-onlyをtest passへ加算しない。元debug13のnlink2/test10のnlink1・0755を正規化せず保持。driver保存78 samples/77 liveは16GiB/swap0/CPU4/tasks512/7200秒/stop5/OOM0。TLSはfull49 guardと36 actual runtime mappingsを保持し、6GiB/swap0/CPU1/tasks128・旧host20,055,432 bytes不変・既知PID/cgroup/TLS専用TMP不在を照合。原12全体/完全required/全8 ordinary CI・全M2/M7/公開認定は未完了 |
| E159: current original12 actual dispatch | 同`50fbf22d`でcheck0/1.706秒、probe0/1.673秒の実EOF/wait後、原10 whole+2 exactを新sourceの実13 RELEASE read-only bindingsで開始。admission`rustls-native7-1017-original12-dispatch-admission-1018.json` (`08186b68`)。unit/invocation`531edd83`、元16GiB/swap0/CPU4/tasks512・work18000/unit18600秒/stop45/8MiB rawを実観測。Native agentの保存prefixでは11 casesが終了し、最後のrecurringを実行中 | actual dispatchだけで全12成功/98 passedを主張しない。元8links/e8の2 ACK withdrawals/35roles/delay7・全selectorを保持。31 file-module closureに直接Wrangler/npm/npxはなく、legacy adapter phaseは実行しない。private Cargo cacheは閉鎖済み。終端/reap/全24 events/各case body・source/artifact/TMP回収の照合は未完了 |
| E160: historical MB/ad3 complete hosted CI | `ad3ce3a0`の[run39031278823](https://github.com/sunriselayer/sunrise-edge/actions/runs/39031278823) attempt1は元7 ownersとsuccess-only check全8がSUCCESS。8 raw 1,558,299 bytesとactual merge`44453eb8` / tree`d3fdc54a` / parents`[5f6b,ad3c]`をroot・独立peerが照合。147 Rust summariesは4,397 passed/0 failed/41 ignored。元7 epoch spans・epoch8 freeze-drain/unlock・saved closure、2 unique 1,832-byte withdrawal候補と各rounds3 ACK manifest stemの一致を実rawで確認。親`ci-run-39031278823-parent-qualified-1018.json` (`7d3c974f`) | 5fからの差分はfixture MJSと設計3 filesだけで、元selectors/8links/delay7/35rolesのsource contractは不変。collectorはactual0/両実EOF/wait/reap。旧ad3 hosted CIの資格だけで、直接Wranglerを含む旧sourceのcf-only適合や中断済みlocal完全required E157の成功にはしない。e4fb/50fbの完全source資格・Native・独立security監査・全M2/M7/公開認定へ転用しない |

| E161: current Cloudflare CLI migration hosted all8 | `e4fb6e55`の[run39044872288](https://github.com/sunriselayer/sunrise-edge/actions/runs/39044872288) attempt1は元7 ownersとsuccess-only check全8がSUCCESS。8 raw 1,557,386 bytesとactual merge`18c6f005` / tree`bb7cad0c` / parents`[ad3c,e4fb]`をroot・独立peerが照合。147 Rust summariesは4,397 passed/0 failed/42 ignored。実cf `1.0.0-beta.13`の型照合・TS7とVitest全4 groups計66 testsも成功。親`ci-run-39044872288-parent-qualified-1018.json` (`9b49ccb8`) | 元7 epoch spans・epoch8 freeze-drain/unlock・saved closure、2 unique 1,832-byte候補と各rounds3 ACK manifest stemを実rawで照合。元selectors/8links/delay7/35rolesのsource contractを保持。collectorはactual0/両実EOF/wait/reap。直接CLIはcfへ統一し、SDK内部のtransitive Wranglerと区別する。local完全requiredは実行中で、50fb・全M2/M7・独立security監査・provider deployment/公開認定へ転用しない |
| E162: current Cloudflare CLI migration local complete required | exact `e4fb6e55` / tree`bb7cad0c`のliteral npm ci +完全check-allが両actual0・各merged実EOF/waitで自然終了、17,653.508秒。147 Rust summariesは4,397 passed/0 failed/42 ignored、cf全4 Vitest計66 tests。rootと独立peerが全747,390-byte raw、1215 source Ns/Git・360 tools・3 seed proofs・7 directory tuplesを照合。親`cloudflare-cli-migration-required-final-parent-qualified-1018.json` (`a78654d3`) | 実rawで7 epoch spans/e8 freeze-drain・unlockと2 unique 1,832-byte候補/各rounds3 ACK manifest stemを照合。cold-open・8links/delay7/35rolesは元の成功source predicateへ対応し、削除artifactを再構成しない。全8 hosted CIのE161と合わせ、このCLI移行確認だけ完了。保存293 observationsのkernel limitsと同invocation自然終了/MainPID・CG不在を確認。未保存のOOM counters/全child census/detached outer EOFは主張しない。最初のreader marker仮定失敗・旧E157中断を保持し、50fb・全M2/M7・独立source/security監査・provider/deployment/公開認定へ転用しない |
| E163: current ordered/certified fresh two-harness compile qualification | exact `50fbf22d`で2つの元libtest harnessをfresh CargoJSONから保持し、元のcompile-only2件・fmt・Node syntax2件・Python AST-only・strict3-crate Clippyの7 gatesが全actual0。19 operations/1,278 frames/1,038,961-byte rawと各EOF/wait、691.391秒。author・root・独立peer親`rustls-native7-ordered-certified-harnesses1-parent-qualified-1018.json` (`e606e367`) | source1215・17 tools/19 aliases、normal0755/単一link/別inodeの2 ELF、既存Native actual51-argument commandと4 RELEASE rolesを照合。既存Native1+新7の構成であり、新しい4-bin buildとは呼ばない。現在lockの311 archives/43,045,697 bytesを照合。private namespaceは312で、未使用旧Rustls0.23.45は元copy metadataとの対応だけ。最初のreader namespace仮定失敗を両方保持し、productは再実行しない。6GiB/swap0/CPU1/tasks512・保存final OOM0/既知PID/CG/TMP不在。compile-onlyであり別UID/TLS fixture・全M2/M7の成功にはしない |
| E164: current original12 actual RELEASE runtime | exact `50fbf22d` / tree`ccae85a6`の元10 whole+2 exact casesが全actual0/EOF/wait、98 passed/0 failed/3 ignored。actual outer0/両physical EOF/wait/reap、12,785.019秒。全24 events/12完全body・265,690-byte rawと各caseの13 RELEASE read-only bindingsをauthor・root・独立peerが照合。親`rustls-native7-1017-original12-parent-qualified-1018.json` (`d5c59b01`) | 元7 epoch spans/e8 freeze-drain・unlock・saved closureと2 unique 1,832-byte候補/同じ2 rounds3 committed-ACK manifest stemを実rawで照合。source1215全Ns/Git、49 ELF/20 tools/10 provenance、保存427 rows中426 liveの16GiB/swap0/CPU4/tasks512、保存既知565 PID numbers・CG・2 TMP不在を確認。8links/delay7/35roles・cold-open/source-free restoreは元の成功source predicateへ対応し、削除artifactを再構成しない。launcherのfile-redirection EOF flagとactual outer物理EOFを区別する。同source完全required/全8 ordinary CI・全M2/M7・独立source/security監査・公開認定は未完了 |
| E165: ordered current50fb runtime1 prelaunch path refusal | 新runtime1 ownerはproof SHAを新しいruntime1証拠へ固定したが、rootのpromotionがCOMPOSITION_PROOFの旧unversioned pathnameを残したため、最初のordered起動はFileNotFoundErrorで拒否。actual outer1/両EOF/wait/reap、0.210秒。Node argv/PID設定前で、inner stream filesは未作成。certified1は未実行。保存`rustls-uid-ordered-current50fb-runtime1-actual-failure-qualified-1018.json` (`018fe3d9`) | product成功/失敗のテスト結果ではなく起動前のmetadata誤り。既知owner/external PID・CG不在を確認。最初のreadonly checkerによる未作成stream仮定の失敗も保持。rootの旧READY判定`47100a1d`とpeerの実行可能性判定`d519b784`はscope correctionで撤回し、元artifact/出力を上書きしない。runtime2では新grant/proof/出力名を使い、全16 configured Path+SHAと親の一致をroot・別peerが実ファイルで照合。aliasやproduct oracle/capの変更は行わない |
| E166: current ordered/certified separate-UID TLS components | exact `50fbf22d`の新2 harnessと既存同source Native4 RELEASE rolesを実使用。各fresh5 ELF/4 loader-libs計4,825,056 bytesのinventoryは両actual0で照合。runtime2はordered→clean回収後certifiedの順で各1回、actual0/両outer・Node EOF/wait/reap、13.907/30.553秒。orderedは18 controls/76 roles・fence3/new height2、certifiedは39 controls/147 roles/27 probes/32 oracle exchanges・fence6/two paid/nonce2/frontier・union3を確認。親`rustls-uid-current50fb-runtimes2-parent-qualified-1018.json` (`00ada6e7`) | author・root・独立peerが元UID/TLS/署名/拒否/保存済み再送/停止・restart/SQL oracleを現在入力へ対応付ける。strict base64/zlib EOF・trailingなし・decoded SHA/JSON一致と全recorded stdout/stderrのUTF8 byte和45,653/59,099・置換文字なしを照合。各17 Docker clientsと全role waits、exact ownerのcontainer/volume回収statement・既知host PID/CG不在を確認。個別Docker raw/ldd ledger・fresh Docker query/未保存OOMは主張しない。certifiedのpositive drain member application=falseは元の範囲。E165とreader regex仮定失敗を保持し、ZeroShare・全M2/M7・独立source/security監査・公開認定へ転用しない |
| E167: current Rustls complete local required and predicate correspondence | exact `50fbf22d` / tree`ccae85a6`のliteral npm ci +完全check-allが各actual0/merged実EOF/waitで自然終了、17,674.091秒。147 Rust summariesは4,397 passed/0 failed/42 ignored、cf全4 Vitest計66 tests。root・独立peerが全747,165-byte raw、source1215全Ns/Git・360 tool hash refs/alias metadata・5 seed proof JSON・7 directory tuplesを照合。親`rustls-advisory-required-final-parent-qualified-1018.json` (`d17f344a`) | 実7 epoch spans/e8 freeze-drain・unlock・pack-saved timingと2 unique1,832-byte候補/同じ2rounds3 ACK stemsを照合。保存6 cycles293 observations/292 direct kernel rowsは16GiB/swap0/CPU4/tasks512。既知MainPID/CG不在と同invocationの自然終了後、rootは当該unitだけを停止し、cache/target/TMP/logを保持。cold-open/8links/delay7/35rolesは成功source predicateに対応し、未保存OOM/全child census/detached outer EOFは主張しない。7つの元nonignored vector/finite-frame-campaign testsの各1回success実行、21 vectors/Native-WASM parityの元recipeとsource対応をordinary peerが照合 (`c2620ac0` / `2d97366a`)。全8 ordinary CI・全M2/M7・独立source/security監査・公開認定は未完了 |
| E168: current Rustls all8 CI and source qualification | exact `50fbf22d`の[PR #325全8 CI](https://github.com/sunriselayer/sunrise-edge/actions/runs/39047302352)がactual success。tested merge`f47bc421` / tree`ccae85a6` / parents e4fb+50fb / attempt1。root・独立peerが全8 raw計1,557,534 bytesとcheckoutを照合し、147 Rust summariesは4,397 passed/0 failed/42 ignored、cf全66 tests、実Node24.19.0の5 lanesを確認。CI親`ci-run-39047302352-parent-qualified-1018.json` (`08b77327`) | 元7 epoch spans/e8 freeze・unlock/saved closure、2 unique1,832-byte candidatesと同じ2 rounds3 committed ACK stems、実finite-frame-campaign名の各1回successを確認。E153-E156/E158/E163/E164/E166/E167と当該CIを同sourceへ対応し、17 closed refsの親`rustls-02346-current-source-qualification-parent-1018.json` (`b25d7188`)でRustls更新のsource/component資格を完了。collectorはactual0/両実EOF/wait/reap。親の旧schema参照失敗を保持し、実field名だけに直したreaderで照合した。全M2/M3/M7・独立source/security/release監査・issue disposition・公開認定は完了扱いにしない |
| E169: current50fb existing ENOSPC five cases | exact `50fbf22d` / tree`ccae85a6`の既存5 selectorsを各1回、固定image・各512MiB/swap0/CPU1/pids64で実行し、全5 passed/0 failed/0 ignored。outer actual0/両実EOF/wait/reap、23.110秒。rootは全57,487-byte framed raw、86 commands/172 streamsのlength/hash、5 test summaries・actual container stateと所有cleanup statementsを照合。root receipt`sqlite-current50fb-enospc5-root-actual-qualified-1018.json` (`7d001b71`) | 50fbの完全requiredで実使用したELFを、終了後の限定grantで新規retained pathへ保存した。今回観測したSHA/metadataを固定し、過去のper-ELF digest/CargoJSON・fresh buildを主張しない。1215 source body hashes、実tool/loader/libs/ELFと前後alias、既知86 client PID・owner CG不在を照合。元のreal SQLITE_FULL・predispatch/literal COMMIT ambiguity・全12 SQL/4 portable/positive blob・receipt-first/retry/replay条件を維持。E85/E86の停止済みtask、torn-write/独立anchor guest・全M3・全releaseの合格へ転用しない |
| E170: H10 root promotion prelaunch path refusal | rootの最初のpromotionは新owner/viewのSHAとabsolute argvを更新したが、captureのB-relative OWNER/WRAPPER pathが旧concrete名のままだった。actual capture1は`actual promoted owner/wrapper changed`でchild/output/compile前に拒否、exit1。correction receipt`genesis-split-handoff-h10-prelaunch-relative-alias-failure-and-correction-1018.json` (`1bdf0b1f`) | 旧ready判定`b5ed9c07`を実行可能admissionとして撤回。candidate2は未実行で保持し、rootは残っていたlive ExecStart照合の旧relative名もdispatch前に修正。capture3は全24 actual Path+SHA・exact argv/live比較をrootと別peerが再照合 (`1bd28f24` / `571bd91b`)。cap/oracleを変えず、productの失敗/成功件数へ加算しない |
| E171: fresh current8a90 H10 compile and normal retention | exact `8a90ea52` / tree`79834fbf`のCLI lib all-feature no-runとactual CargoJSON由来の保持copyが両actual0/merged EOF/wait。outer actual0/両physical EOF/wait/reap、296.910秒。171 CargoJSON recordsと唯一のfresh=false/opt2/assertions+overflow enabled libtest、30,252,104-byte ELFの0755/UID1000/nlink1・全byte hash一致/別inodeをrootと独立peerが照合。親`genesis-split-handoff-h10-parent-qualified-1018.json` (`5d17bc33`) | source1215全Ns/hash/Git・17 alias-aware tools、保存21 samples/20 live kernel rowsの6GiB/swap0/CPU2/tasks512、既知47 PID・特定CG不在とhost recipe TMP空を照合。root E170とpeer readerの最初のsymlink仮定失敗を保持。旧H9/Native cacheのleaseや結果を移さず、新しいpublic seed/専用cache/targetからbuild。test/全138 owning・完全required/CI・production CLI新build・全M2/M7の合格は主張しない |
| E172: current8a90 whole138 fixture actual failure | actual H10とfresh2-ELF lddを固定して全138用driverを1回実行したが、Node actual1/merged EOF/wait、outer actual1/両physical EOF/wait/reap、7.899秒。保存117-byte rawは`captured command/PTY output exceeds the fixture's bounded allocation`。root/peer failure receipts`genesis-split-handoff-fixture-runtime1-root-actual-failure-qualified-1018.json` (`10a15c97`) / `genesis-split-handoff-fixture-runtime1-independent-failure-and-diagnostic-review-1018.json` (`4d62bff8`) | source1215・2ELF/4libs/driver/aliasesの保存前後一致と既知owner/external PID・saved CG不在を照合。run_execはrc判定より先に累積262144-byte capを検査するため、元command・通常の累積量か大きなpanic出力かは元rawから確定できない。phase48KiB/全体262144やselectors/timeoutsを増減せず、失敗時だけpublic新probeのbounded diagnosticsを追加する。旧117・新21の部分成功や全M2の合格へ加算せず、当該完全requiredも未起動で保持する |
| E173: current8258 bounded diagnostic actual failure and cause | `8258619c` / tree`8ed58c89`の限定diagnosticsを1回実行し、Node/outerはactual1・実EOF/wait/reap。297-byte rawは正常終了rc0の`prepare-transfer`出力5,752B/stderr0で累積257,798→263,550B、元262,144Bを1,406B超えたことを示した。author/root receipts`genesis-split-handoff-fixture-runtime2-author-actual-failure-qualified-1018.json` (`58271e77`) / `genesis-split-handoff-fixture-runtime2-root-actual-failure-qualified-1018.json` (`5669b47d`) | source1215・2ELF/4libs/driver/aliasesの保存前後一致、両outer streamsと既知PID/CG解放を照合。phaseは記録されておらず推測しない。残り出力があるため1,406B削減で足りるとは主張せず、全138/元117/追加21の成功も加算しない。capを上げたり途中resetせず、元117と新21を独立profileへ分離する通常のtest-layout修正を進める。E172の失敗を保持し、全M2/M7は未完了 |
| E174: currentc680 separate default117 and foreign-split21 actual success | exact `c6807388` / tree`a6239a24`。fresh2-ELF lddの後、元default117はactual0/両outer実EOF/wait/reap・7.591秒、独立`--profile genesis-split-handoff`の21 feature flagsもactual0/同closure・1.807秒。source・全判定の別review`a8f8a4bd`、executor aggregate`genesis-split-handoff-profiles1-executor-aggregate-qualified-1018.json` (`8db7135a`) とroot実照合`genesis-split-handoff-profiles1-root-actual-qualified-1018.json` (`b350a125`) | 元117 flow/host判定は50fbとbyte一致、新21 phase/判定は8258から保持。Aの10MをA残5M/S v2とB受取5M/C v1へ分割し、同CをA/C v2へ返送。別fee・nonce1,0→1,1・全保存再送・実PTY内容一致・誤owner拒否・A停止後B開始・取消/restart拒否を確認。新phaseは73,078B/32 leaves、出力29,412/49,152B・26 children、setup6 children。両1215 source/body/Ns・2ELF/4libs/aliases保存前後、host PID/CGとcontainer/volume cleanup判定を照合。H10実build元8a90とはMJS/guide2-file、production CLI実50fbとは3-file bridge。138は別実行の判定和で、single whole138合格ではない。全M2/M7・実鍵/公開・未実施の個別Docker raw ledgerの証明に拡張しない。完全required/CIは当該c680で実行中 |
| E175: inherited application-flow PTY counter observation | exact `c6807388`の静的call graphで、既存`phase_create_asset`からの10 successful PTY (create1・ownMB3・ownCoin6) がhelperの返す長さを累積counterへ加算しないことを確認。helperは各PTYの16,384B capとwaitを持つ。source-only observation`m2-c680-inherited-discarded-pty-accounting-observation-1018.json` (`e93a73a9`) | 実際の全PTY合計が262,144Bを超えたとは主張せず、旧rawから未保存の端末出力も再構成しない。E174の新foreign-split phaseは明示的にPTYを加算し、実29,412/49,152Bと全21判定の成功を保持する。元default117のsemantic判定成功と、全PTYを含むglobal集計の完全性は区別する。追加application historical recovery profileは既存明示加算を二重計上せず、再利用するcreate/ownMB/ownCoinの端末表示も集計する。defaultの既存集計漏れは未解消で、全M2の残件へ保持する |
| E176: application kind2 recovery first actual review refusal | `c91b7a49` / tree`75e8ea3b`のfresh inventory、元default117、split21は別々にactual0/実EOF/wait/reap。新`application-transfer-recovery`はactual1・3.289秒・両outer EOF/wait/reapで新復旧の署名前に拒否。全116B rawと失敗をauthor `application-coin-recovery-transfer-runtime1-executor-actual-failure-qualified-1018.json` (`57afe8e3`) / root `application-coin-recovery-transfer-runtime1-root-actual-failure-qualified-1018.json` (`30516ec4`) に固定 | 1215 sourceとELF/libs/driver/aliasesの保存前後一致、既知PID/CG不在、C target未生成を照合。期待genesis digestはraw hex、実rendererは`sha2-256:<hex>`で、型の表示形式との不一致をsourceから確認。完全digest比較を保持したまま期待形式を修正する。新PTY・参照signer・鍵copy・復旧署名の成功や38判定の完了へ加算せず、旧2profile成功も新復旧の成功へ転用しない。完全requiredは未起動、全M2/M7未完了 |
| E177: corrected application kind2 historical recovery actual success | exact `7663e0ab` / tree`9d3e849a`。canonical digest表示の1-line修正後、fresh inventoryと元default117・split21・新application-transfer-recovery38 selectedは4つの別owningでactual0/実EOF/wait/reap。新復旧は3.291秒・完全raw10,979B。root source `41ae63c8`、root inventory `6aebd888`、root actual `application-coin-recovery-profiles2-root-actual-qualified-1018.json` (`c84b32e8`)、controller authorの別data照合 `c2be1e1c` | 同一publisherが作成したapplication Coinのretained nonce8/a5取消状態から、新a6の完全review・PTY内容一致・同frame署名一致、original reference停止/wait後の2UID key copy、旧/新取消とrestart拒否を確認。署名のみで再提出・live currentness/鍵交換ではない。reference1/1/1/0→復旧3/3/1/2→restart2/2/0/2、追加9exec+1PTY+2copy+3serve、8files/6,443B・phase13,982/16,384B。strict setupを含む全出力181,755/262,144B、isolation2read/2write拒否・4wait。1215 source/2ELF/4libs/aliases前後一致、既知PID/CGとcleanup判定を照合。実H10元8a90とはMJS/2guideの3-file、実production CLI元50fbとは4-file bridge。117/21/38は別実行で、単一176合格ではない。E176失敗を保持し、kind3・default既存PTY集計・全M2/M3/M7と新source完全required/CIは未完了 |
| E178: exact-once PTY accounting exposes strict default cap failure | 別Dのlocal `264d3135` / tree`bd77e3c8`で共通helperへ完了PTYの加算を集約し、11 caller accounting sitesを除去。20 call-siteの引数/順序・全操作・phase-local checksとhost Node bytesを保持し、rootが1215 body/Ns・限定正規化後の全embedded AST一致を確認 (`67ba0860`)。fresh2-ELF inventoryはactual0、strict defaultは1回だけactual1/両outer実EOF/wait/reap・6.904秒。author/root failure `9588e08d` / `custody-output-accounting-default117-runtime1-root-actual-failure-qualified-1018.json` (`0c182b73`) | 完全227B rawは実累積267,120 > 元262,144Bを示す。保存されたcleanup commandはrc0・追加stdout/stderr0でbefore=after267,120のため、最初に超過したphase/PTY量は確定しない。過去の破棄された端末出力も再構成せず、117成功・他2profile成功へ加算しない。保存source/ELF/libs/aliases前後一致、既知PID/CG不在・D target未生成を照合して全owningを閉じ、split/applicationは未起動。E175のapplication10に加え、他9成功PTY返却も旧defaultで未加算だった。cap増加/reset/項目削除をせず、core70と元application47を別allocationへ分け、既存application profileで元47の詳細host検証も共用する修正へ進む。no-arg shape変更はcoreと明示し、旧default117とは呼ばない。D完全gateは未起動、全M2/M7未完了 |
| E179: metered original117 coverage across explicit separate profiles | exact `d0128975` / tree`854fecbd`。fresh2-ELF inventoryと明示`publication-genesis`、`genesis-split-handoff`、`application-transfer-recovery`は全4 owningがactual0/両outer実EOF/wait/reap。core70は5.980秒・加算190,217/262,144B、split21は1.883秒・23 recursive true、application57は3.528秒・加算181,755/262,144Bと59 recursive true。author aggregate`176129e1`、root source`35686649`、root inventory`4234d859`、root fullraw/actual`custody-output-accounting-profiles2-root-actual-qualified-1018.json` (`48bf44a3`) | rootが全rawから抽出したcore70とapplication setup47の重複なしpath/value mapは、旧c680元117と完全一致。元47の9,798-byte詳細host検証を共用し、全6段階/5group/counters/recovery attachmentsを保持。appは元47+newT9+strict1=57 selected、common2込み59。共通helperが完了PTYを1回加算しcaller重複を除去。各allocationの上限を保持し、単一117実行・過去の破棄出力再構成とは呼ばない。旧default/no-argはcoreと明示してalias化、3manual guidesも必須pairとsplit別実行へ移行。1215 source/ELF/libs/aliases保存前後一致・既知PID/CG不在とcleanup判定、復旧署名/取消/restartを照合。実H10元8a90とは4-file、実production CLI元50fbとは5-file bridge。E178失敗を保持、controller ancillary38→57 prose訂正は別`b4990a5c`で保存。d012はbranchへ保全し、D完全required/CI・最終source release・全M2/M7は未完了 |
| E180: application kind3 split/merge historical recovery actual success | exact `f51bee72` / tree`925361b2`。fresh2-ELF inventoryとcore70・split21・application kind2/3各57 selectedの全5 owningがactual0/実EOF/wait/reap。新kind3は3.830秒・完全raw11,756B、57 selected/59 recursive true。author aggregate`909c3be1`、root source`2b7b8532`、root inventory`5f90a5ba`、root fullraw/actual`custody-output-accounting-profiles3-root-actual-qualified-1018.json` (`7758b266`) | retained nonce4/5・旧a1/a2から新a7/a8の完全prepare/PTY review・同frame署名一致を確認。original reference停止/wait/socket不在の後だけ別UIDで同じ鍵を保管/復元し、旧/新取消とrestart拒否、preimages不変を実証。reference2/2/2/0→復旧6/6/2/4→restart4/4/0/4、phase18exec+2PTY+2copy+3serve、14files/13,717B・8 absent outputs・phase28,710/49,152B、全加算196,483/262,144B。setup isolationは3read/3write拒否・6waitだが、同じ復元鍵pathを2承認で検査したもので3種類の鍵ではない。rootは全rawと保存source1215/ELFs/libs/aliases/driver前後・両outer streams・既知PID/CG不在を照合。core70とkind2/3それぞれの元application47は旧117全mapに一致し、split21も保持。実H10元8a90/CLI元50fbとは4/5-file bridgeでありf51新ELF buildではない。historical署名のみで再提出・currentness・正の権限移行ではない。旧E176/E178失敗、全M2/M3/M7とD完全required/CI未完了を保持 |
| E181: exact f51 fresh13-target A/B actual success | exact `f51bee72` / tree`925361b2`。新Native8の両laneは各13 fresh CargoJSON bins・release opt3/debug0、全26 retained ELFの13組完全byte一致。777.183秒でactual0/実両EOF/wait/reap、unit/既知PID/CG・source lease・4 compiler/temp treesを回収。author`4784ecfc`、root全26ELF/全build raw`24ce242d`、root sampled caps`d3283f49`、統合`custody-f51-native8-1018-ab-parent-qualified.json` (`881da71e`) | rootは336,973,280Bの全retained bytes・0755/UID1000/singlelink/別inode・source1215 manifest map・CargoJSON profileを独立照合。authorは現source1215/Git・22 tools・311 archives/metadata・選択231 packages/10,017 files/122,049,003Bを照合。53保存sample中52 live、peak1,737,285,632B、8GiB/swap0/CPU4/Tasks512とmax/oom/kill0を確認。reader初回のTAR集計不一致を保持し、99 GNU-L headers/10,525Bを厳密計上するreaderだけ修正、product再実行なし。`fixturePassed=false`、custody runtime/D完全required/CI・原12 RELEASE runtime・全M7や独立security/release監査は未完了。ancestor成功の借用なし |
| E182: current f51 Native8 RELEASE CLI custody actual success | E181のactual `f51bee72` Native8 CLIを直接使用。fresh2-ELF ldd inventoryは0.561秒、独立core70/split21/kind2 recovery57/kind3 recovery57は5.814/1.643/3.254/3.245秒で全5 owning actual0/実両EOF/wait/reap、既知host PID/CG不在。author aggregate`9f2030f0`、root inventory`cdd7f452`、root全raw/actual`custody-f51-native8-profiles1-root-actual-qualified-1018.json` (`89a57aa2`)、統合parent`1c09b2b2` | 全rawから70/23/59/59 recursive trueと各selected70/21/57/57、元core70+各application47の完全117 path/value map、split全mapを再抽出。kind3は完全review/同frame署名・旧新取消/restart、14files/13,717B・phase28,710B・18exec+2PTY+2copy+3serveとreference/recovered/restart countersを保持。source1215/2ELF/libs/aliases/driver保存前後一致、current CLIの全1215 compiled sourceは同f51で例外なし。H10だけは実8a90と4-file nonRust bridge。core/T/Gの全加算190,217/181,755/196,483 < 元262,144B。splitの保存値はphase29,412Bだけでglobal合計値は作らず、元のglobal/phase capを実source内で保持。container_removedはNode cleanupの実判定で、未保存の個別Docker-role PID/rawを追加主張しない。同一鍵historical signingのみ、再提出/currentness/正の権限移行・D完全required/CI・原12 RELEASE runtime・全M2/M3/M7は未完了。旧失敗とreader-only split形式訂正を保持、product再試行なし |
| E183: exact c680 local complete required actual success | exact `c6807388` / tree`a6239a24`。literal npm ci + `./scripts/check-all.sh`の2 commandsが全actual0/merged EOF/wait、outer13,712.935秒で実両EOF/wait/reap。Rust147 summaries・4,397 passed/0 failed/43 ignored、CF13+28+10+15=66。author`47fb44ce`、実tool reap`d24610db`/chunk`3d9617`、root全raw/inputs`w-c-required-W-root-postclosed-qualified-1018.json` (`23fa1ff7`)、統合`c1276ddb` | rootは全746,949B rawを再parseし、元7 epochsとepoch8 freeze/unlock・実1832-byte候補2件/対応3-round committed ACK、current1215 source/Git/Ns・360 tools・317 CF aliases・5 wrappers・実2 seedproof JSON・7 directory tuplesを独立照合。実oneshot有限TimeoutStart20,000sでありRuntimeMax infinityを時間上限と呼ばない。両outer physical streamsとmerged inner pipeを区別し、既知Main3214325/external3214323・保存した非空CG不在まで確認。current ignored43を旧50fbの42から借用せず、原8links/7delays/35roles等はexact成功recipeのsource-owned oraclesへ帰属。privatecache/target bodyは読まず変更・削除なし。c680の既存PTY集計漏れ、後続f51のD全体gate/CI、CI326の別資格照合、原12 RELEASE runtime・独立監査・全M2/M3/M7は未達のまま保持 |
| E184: exact c680 all8 hosted CI actual success | [run `39109200775`](https://github.com/sunriselayer/sunrise-edge/actions/runs/39109200775) attempt1の元7 owners + check全8がterminal SUCCESS。全8 rawの実checkout `a9f59728` はtree`a6239a24`でexact head`c6807388`と一致、parentsは`50fbf22d`/`c6807388`。全1,558,242B raw・8 job IDs・run/commit JSONをrootで照合し、Rust147 summaries・4,397 passed/0 failed/43 ignored、CF13+28+10+15=66を再抽出。author`b290ace7`、root`hosted-ci-pr326-current-c680-root-actual-qualified-1018.json` (`5533ea7e`)、E183 localとの統合`1ae1646d` | 既存collectorだけを1回実行しactual0・実両EOF/wait/reap・既知PID不在を確認。Actionsのsynthetic PR mergeは観測したCI checkoutであり、本作業でmainをmergeしたものではない。初回readerのliteral ANSI形式照合失敗を保持し、parse用copyだけ正規化、raw変更・collector/product再実行なし。c680の既存PTY集計漏れと旧combined失敗、後続f51のD全体gate/CI・原12新source RELEASE runtime・独立security/release監査・全M2/M3/M7は未完了のまま保持 |
| E185: exact7663 local complete required actual success | exact `7663e0ab` / tree`9d3e849a`。literal npm ci + `./scripts/check-all.sh`の2 commandsが全actual0/merged EOF/wait、outer13,341.298秒で実両EOF/wait/reap。Rust147 summaries・4,397 passed/0 failed/43 ignored、CF13+28+10+15=66。author`703201e3`、root全raw/inputs`w-c-required-C-root-postclosed-qualified-1018.json` (`23b90e6c`)、統合`ee19f553` | rootは全747,778B raw、元7 epochsとepoch8 freeze/unlock・実1832-byte候補2件/対応3-round committed ACK、current1215 source/Git/Ns・360 tools・317 CF aliases・実4 seedproof JSON・7 directory tuplesを照合。actual session99398/chunk`f7e922`のreap証跡は、後から作ったauthor転記`2ee19d3a`と区別。既知Main3286218/external3286216・非空CG不在、実oneshot有限TimeoutStart19,000sを確認。未保存の最終kernel/OOM値やprivatecache/target bodyは主張しない。root readerはactual0で1回終了し全read phaseを閉じた。CI327・既存default PTY集計漏れ・後続f51のD全体gate/CI・原12新source RELEASE runtime・独立監査・全M2/M3/M7は未完了、先のE176等失敗は保持 |
| E186: exact7663 all8 hosted CI actual success | [run `39112865778`](https://github.com/sunriselayer/sunrise-edge/actions/runs/39112865778) attempt1の元7 owners + check全8がterminal SUCCESS。全8 rawの実checkout `e4d02ccc` はtree`9d3e849a`でexact head`7663e0ab`と一致、parentsは`c6807388`/`7663e0ab`。rootが全1,558,233B raw・8 job IDs・run/commit metadataを照合し、Rust147 summaries・4,397 passed/0 failed/43 ignored、CF13+28+10+15=66を再抽出。author`305b8eab`、root`hosted-ci-pr327-current-7663-root-actual-qualified-1018.json` (`cba6b9c2`)、E185 localとの統合`f15ae563` | 既存hash固定collectorを1回だけ実行、session4813/chunk`950553` actual0/reapをauthorの後日転記と区別して帰属。14:02:50の全8終端status queryは実両EOF/wait・既知PID不在。全CIは自然終了しcancel/retryなし、全local owning/read phaseも終了。Actions synthetic checkoutは観測したCI証拠でmain mergeではない。readerのschema/ANSI拒否を保持しraw変更・provider/collector/product再実行なし。既存default PTY集計漏れと旧失敗、後続f51のD全体gate/CI・原12 RELEASE runtime・独立監査・全M2/M3/M7は未完了 |
| E187: finalf51 fresh23/current49 + original12 RELEASE runtime | exact`f51bee72`/tree`925361b2`。元2 compiler commandsでfresh13debug+10testdrivers、既存E181のreadonly13RELEASE A/Bと合わせ49ELFを保持。元10whole+2exactの全12 actual0/実EOF/wait、98 passed/0 failed/3 ignored、outer9,509.763秒。rootが全24events/12summaries・270,697B raw(`94b7da97`)・全13 RELEASE ro-bind・元7epochs/e8 freeze+unlock・異なる1832B候補2件と同じ2件のrounds3 committedACK・saved closureを照合。current1215 source/Git・49ELF/13A/B・20tool aliases・10proofsの953,075,614Bを実照合。author`5bb6ae7d`、root`156a37ad`、統合`todo-e187-native8-original12-current-f51-parent-qualified-1018.json` (`bad7fb79`) | 元selector/18,000秒work/18,600秒unit/6GiB/swap0/CPU4/512PIDsを維持。driver55samples/54live、runtime318/317live、保存済み538PIDと2owned cgroup不在・runtime/probe TMP削除を確認。owning4902/chunk`5c9da4` actual0/reap、root reader66423/chunk`2918b7` actual0/reap/1.383秒/実両EOF/wait。root reader2のsnapshot分類失敗を保存しreader3だけ修正、product/source/raw再実行・変更なし。private311archive検証はauthor帰属でroot読取なし。削除済みrole個別記録は再構成せず、8links/7delays/35rolesは成功した元source assertionsへ帰属。source/cache/target/ELFを保全して全read phase終了。D完全required/全8CI・全M2/M3/M7・独立最終review/公開認定は未完了 |
| E188: finalf51 local complete-required actual failure | exact`f51bee72`/tree`925361b2`。literal npm ciはactual0/merged EOF/wait、完全check-allはactual1/merged EOF/waitで停止。outer13,046.442秒、owning48530/chunk`99a997` actual1/reap、実外側両EOF/wait、captureerror null。rootが全721,674B raw(`0e4633d6`)・inner/outer/full streamsを照合。成功prefixは147 Rust summaries/4,397 passed/0 failed/43 ignored、元7epochs/e8 freeze+unlock・2件1832Bと同じ2件の3round committedACK、adapter WASM release buildまで。CF型生成の前提`cf --version`がexternal317 integrity guardで拒否され、TypeScript/lint/Vitest未到達。author`301a32ee`、実reap witness`17bc2b94`、root`todo-e188-f51-full-required-root-actual-failure-qualified-1018.json` (`b74c6b32`) | 保存prelaunch317とpostclosed snapshot`0237063e`の77 rolesはctimeNsのみ変更、全317 body SHA・他metadata・alias先は一致。変更時刻16:26:54-16:40:40 UTC、原因/実行主体は不明で推測しない。source1215/tool360/4copyproof/7directory tuplesの現在照合はauthor帰属、rootは保存raw/records/317deltaと既知3564438/3564435・savedCG不在を独立確認。12GiB/0swap/CPU4/512PIDs/oneshot finite26,000秒を維持、privatecache/target body不変や未保存最終OOM値は主張しない。source/cache/target/失敗を保全して全read phase終了。PASS専用readersは実行せずguard緩和/環境変更/再実行なし。残り枠に元の完全上限と回収余裕が収まらず新規full runを開始しない。完全required・全M2/M3/M7未完了、CIは別の実終端待ち |
| E189: finalf51 all8 hosted CI actual success | [run `39138896024`](https://github.com/sunriselayer/sunrise-edge/actions/runs/39138896024) attempt1の元7 owners + check全8が自然終了SUCCESS。全8 rawのactual checkout`ef504719ee3dee239a635260a383ba9ec51de7cf`、tree`925361b2`はexactf51と一致、parentsは`7663e0ab`/`f51bee72`。rootが全1,557,774B raw/hashes・8 job IDs・actual checkout/Gitdata・aggregate7needsを独立照合。Rust147 summaries/4,397 passed/0 failed/43 ignored、CF13+28+10+15=66、元7epoch ends/e8 freeze+unlock・2件1832Bと同じ2件の3round committedACKを再抽出。author`4d0d41f1`、root`a6649f65`、統合`todo-e189-ci328-current-f51-parent-qualified-1018.json` (`dc619470`) | hash固定collector`99b21e94`を1回のみ実行、owning79379/chunk`13d1ed` actual0/reap。root saved-data readerはchunk`99f02d` actual0/0.058秒/実両EOF/wait・既知PID不在。全CI自然終了しcancel/retryなし、author/root read phases終了。rawは変更せずANSI除去はparse copyだけ。collectorの未保存PID/個別physical pipe ledgerや削除済みrole記録を再構成しない。synthetic checkoutはCI証拠でmain mergeではない。E188のlocal完全required失敗は保持し、hosted成功をlocal合格や全M2/M3/M7・独立最終review/公開認定へ転用しない |
| E190: finalf51 isolated CLI environment and original five-profile types | exact`f51bee72`/tree`925361b2`の新しい専用worktree。元317 roleのbody SHAを保持し、34 packages/2,335 files/486,818,934Bを別inodeへコピー、全2725 layoutと2347 tool rolesの厳密なmetadata/body guardを維持した。元の`node scripts/cloudflare-types.mjs --check`が5 profilesを全て通り、actual0/7.467秒/両EOF/wait/reap、owning29056/chunk`6f7e41`。root統合`todo-e190-manual-isolated-cf-types-root-qualified-1019.json` (`282f0048`) | プロセス内で共有pnpmを隠し、private CLIと依存先を実行。Node24.19.0、元selector/timeout/assertionは維持。公開依存1216件の別inodeコピーも元body SHA一致。旧metadata差分によるコピー失敗とE188を保全し、新しい実行開始時のmetadataを記録後は変更を許容しない。これは環境と型生成だけの資格。別の完全required初回は記録プロセス143を受け自己所有runを停止しpartialとして保全。型生成資格は維持し、全M2/M3/M7・独立監査の完了にはしない |
| E191: finalf51 isolated local complete-required actual success | exact`f51bee72`/tree`925361b2`のfresh source/cache/targetで元literal npm ci +完全check-allが両actual0/各merged EOF/wait。outer12,954.791秒、実両EOF/wait/reap。rootが全747,003B raw(`c9b66202`)を再parseし、Rust147 summaries/4,397 passed/0 failed/43 ignored、CF13+28+10+15=66、元7epochs/e8 freeze+unlock・2件1832Bと同じ2件のround3 committedACKを照合。root reader16802/chunk`2f3e3e` actual0、proof`43ea7a36`、統合`todo-e191-manual-full-required-f51-parent-qualified-1019.json` (`6d6ae001`) | current1215 source全Ns/SHA/Git、2390 runtime body hashes、CF2725 layout/2347 full roles、5 seedproof JSON/7 directory tuplesを照合。guard・元selector/timeout/12GiB/swap0/CPU4/512PIDsを維持し、Node24.19.0とprivate cfを使用。記録serviceは同Invocationの自然終了Code1=CLD_EXITED/Status0を実確認し、その後rootが自己所有の残存unitだけ停止。既知3PID・両CG不在。root組立ての参照ミス1件を保存しJSON記録だけ修正、product/test再実行なし。E188と初回manual recorder143 partialは保全。private cache/target body読取・未保存最終OOM値・削除済みchild ledgerを主張しない。author/observer/root read phaseは終了。local gateだけの完了で、親5項目・独立監査・公開認定は未達 |
| E192: M2/M3 current-source public dependency preparation | 新規c1検証用にCargo599件/64,562,928Bとnpm617件/252,200,540Bを別inodeの専用v2 cacheへコピー。元body SHAを保持し、actual0/実両EOF/wait/reap・既知PID/PG/cgroup不在を確認。copy閉鎖proof `m2-m3-independent-public-seeds-v2-1019-closed-proof.json` (`2b4ce1d5`) | 初回は祖先FDの同時保持でmetadata段階の上限に達し、選択本文0件のまま失敗した記録を保全。既存上限を変えず、単一fileずつ祖先FDを閉じる処理へ修正した別実行。依存準備だけでcomponent・親項目の完了ではない |
| E193: currentc1 targeted controls and actual TLS ACK loss | exact `c1d22757`/tree `6328224f`。fmt・strict operator/CLI全target/all-feature Clippy・実bins/選択3test no-run・M2両inventory/Docker・新旧TLSの10 commandsが全actual0/実両EOF/wait/reap。新TLS4.975秒、元TLS19.454秒。rootが全raw・current1218 source/70 tools/保存7 ELFを独立hashし、knownPID/cgroupと両container/volume不在、同unit自然Code1/Status0を確認後に空unitを停止。root proof `m2-m3-independent-component-1019-parent-closed-proof.json` (`a465a55c`) | M2の両runtime自体はoriginal ordered79 roles・certified149 rolesで成功したが、4 operator ELFのreceiptが実際の最後のproducer1を0と記載したため、strict M2資格は未達。元receipt/rawを保全し、別の正しいreceiptによる再検証はE194で成功。M3はactual harness1/test・CLI0/devを照合。参照blob closureは空/positive_blob_fault=false。初回launcher observer timeoutとrootのsymlink照合ミスも保全し、後者は検証記録だけ修正。完全required/同sourceCI・全M2/M3は未達 |
| E194: currentc1 corrected-producer M2 recovery components | 元receipt/rawを変更せず、4 operator rolesの実際の最後のproducerをcommand1/devへ訂正した別receiptで、元Node controllersを再実行。ordered inventory/Dockerとcertified inventory/Docker全4 actual0/実両EOF/wait/reap。ordered79/certified149 role children、全17+17 Docker client EOF/wait/closeを保持。rootがcurrent1218 source/70tools・全raw・両receiptの差分とactual CargoJSON/current emitted ELF/保存5role bytesを照合。`m2-m3-independent-receipt-corrected-1019-parent-qualified.json` (`b51012ae`) | 訂正は実際の生成記録への対応付けだけで、source/test/ELF/cache/target変更や再buildなし。元の誤帰属E193を保全。実unit自然Code1/Status0・knownPID/cgroupと2container/2volume不在をroot確認後、自己所有の空unitだけ停止。orderedはfresh empty height2、certifiedはfresh paid B/fence6まで。全M2・正の鍵交換/off-host/公開、c1の完全required/CIは含めない |
| E195: currentc1 full-runner preflight actual failure | literal npm ci/check-all開始前に、検証ownerが新producerのmetadata-array+SHAを旧flat形式と直接比較して拒否し、steps=[]/両command未実行のまま自然exit1。first-fileのSHA/all9 fullNsは一致。rootは全1218 sourceのSHA/all9 fullNs不変・全raw・自然Code1/Status1・既知PID/start cgroup不在を再確認し、同じ自己所有の空failedunitだけ停止/reset。`m2-m3-independent-full-required-1019-parent-failure-closed.json` (`d47152d2`) | product/test失敗や内容変更とは区別し、この実行を完全required成功へ数えない。元index/ソース/失敗を保全。通常のread-only helper形式確認ではsource比較と終端ControlGroup空文字の2点だけを検出、runtime70/archive311/CF2347/layout2725の形式は一致。全10 source値と既存guardを保持する別v2 helperへ訂正し、再baseline/guard緩和は行わない。この実行では全体gateと同sourceCIの終端は未完了 |
| E196: currentc1 complete-required actual SUN_LEN failure | 別v2はstrict source1218/runtime/CF2347/layout2725/archive311照合とliteral npm ci actual0を通過。完全check-allはactual101/1,748.277秒・実両EOF/wait/reapで自然失敗。全workspace test compileは25m10s、partial35 summaries/1,087 passed/11 failed/0 ignored。native-httpの11件が全て`path must be shorter than SUN_LEN`。rootが全raw/前後snapshot、source/tool/archive verifierをread-only再実行し、自然Code1/Status1・knownPID/startCG不在を照合後、同じ空failedunitだけ停止/reset。`m2-m3-independent-full-required-v2-1019-parent-failure-closed.json` (`3f665226`) | 元の成功済みE191 Cargo wrapperとの差分はchild TMPDIRに90Bの長いpathを追加した1行。新v3 helperではその追加だけを除き、元のprivate /tmp tmpfsと明示environmentを復元して対象native-http全libから確認する。source/test/selector/timeout/期待hash/metadataは変更しない。全v2失敗・未到達の元recurring/e8/provider群とrootの記録組立てミスを保全。完全requiredと親項目は未完了 |
| E197: currentc1 private-temp native-http whole-library probe | Cargo childの追加TMPDIRだけを除いた別v3 helperで、元のprivate /tmp tmpfsを使う全lib `cargo test -p native-http --all-features --lib` がactual0/245 passed/0 failed/0 ignored。実両EOF/wait/reap・元source/tool/archive/wrapper postguard不変、knownPID/startCG不在。rootは公開raw/snapshot hash・同Invocationの自然Code1/Status0を独立確認後、自己所有の空probe unitだけ停止。`m2-m3-independent-full-required-v3-1019-probe-parent-published-qualified.json` (`626bef5a`) | 元E196の11 SUN_LEN failuresを含む全245件を保持。限定probeであり完全required成功ではない。rootは次のfull owner専有中にsource/cache/target/ELF/tool/privateCFを読んでいない。probe実終端後、別unitで元2 commandsだけの完全requiredを開始し、strict preflightとliteral npm ci actual0の後にcheck-allを開始した。後続の完全終端はE199で成功。過去失敗と完了条件を保持 |
| E198: currentc1 PR329 all8 hosted CI | run `39211600220` attempt1の元7 owners+aggregate全8が自然SUCCESS。rootが全8 raw/1,559,211B・actual checkout `3b971e65`・tree `6328224f`・ordered parents[f51,c1]とaggregate needsを照合。Rust147 summaries/4,398 passed/0 failed/43 ignored、新M3 nonignored selector actual ok、CF13/28/10/15=66、元7 epoch END/e8 freeze/unlock/実1832B候補2件と同ID round3 committed ACKをcurrent rawから再導出。`ci329-current-c1-1019-root-qualified.json` (`2469d499`) | collectorは1回actual0/7.429秒・別々の実pipe EOF/明示wait/reap・全FD/file閉鎖・PID/PG不在。normal GH認証のみ。全CI owner/query/read phaseは終了し、旧raw/count/candidate IDを借用しない。CI成功をlocal完全requiredの代わりやrelease/独立監査・全M2/M3/M7へ転用しない |
| E199: currentc1 literal npm ci and complete required | 同c1/tree6328で元の `npm ci --prefix adapters/cloudflare-workers` と `./scripts/check-all.sh` がactual0/実両EOF/wait/reap、10,533.522秒。Rust147 summaries/4,398 passed/0 failed/43 ignored・CF13/28/10/15=66、新M3 actual ok、元7 epoch END/e8 freeze/unlockとcurrent1832B候補2件/同ID round3 ACKをrootがrawから再導出。source1218全SHA/all9 fullNs・tracked集合/HEAD/tree/clean、runtime70/CF2347/layout2725/archive311/wrappersとcurrent全331 executableELF/全cache-target snapshotを閉鎖後read-only再照合。`m2-m3-independent-full-required-v3-1019-parent-qualified.json` (`fe7a44a1`) | known owner/command/fixture PIDsとcapturedCG不在、同Invocation自然Code1/Status0を独立確認後、自己所有の空successunitだけ停止。元のcurrent target/newv2 cacheのreuseでありfreshとは呼ばない。probe E197と失敗E195/E196は別記録のまま保全。Node24.19.0/cf/cloudflare、全元条件を維持。ここで3子タスクの実装・個別runtime・完全required・同sourceCIがそろう。親M2/M3/M7・独立監査/release全体の合格へ拡張しない |

| E200: 1021の専用依存・current-device準備 | 公開Cargo599/npm617件・316,763,468Bを専用cacheへ新inodeでコピーし、元SHA/bytes・前後source・readbackを照合。既存CF/runtimeの2,404 bodies・全metadata/linkを確認し、別の新manifestでは元のdevice52だけを53へ結び直した。rootがCF7,407/runtime21の差分だけで他属性不変と証跡hashを再照合。`m2-m3-followup-1021-root-preparation-qualified.json` (`85957e36`) | 余分なnlink1仮定と誤った差分集計数による準備V1/V2のactual1を保全。V3はactual0/実両EOF/wait/reap・既知PID/PG不在。旧manifest/cache/ソースを変更せず、製品runtimeや親M2/M3の成功には数えない。新source2ffの個別検証は別ownerの有限unitで実行中 |

| E201: 1021 targeted runnerの出力属性判定失敗 | 同2ff/tree5993でfmt/strict operator-CLI Clippy/JSON buildはactual0・実両EOF/wait/reap。Cargoの18実出力はmode0755/uid1000/nlink2で、helperの追加nlink1仮定が拒否した。rootが全18実SHA/full9・全3command raw・同Invocation自然Status1・PID/CG不在を照合し、自己所有の空failedunitだけ停止。`m2-m3-followup-component-1021-root-failure-closed.json` (`8f776748`) | no-runとM2/M3 runtimeは未実行。全体失敗を保全し、空のretained-role postguardを成功証拠には使わない。source/tool/seed/archive postguardは不変。別v2で同sourceの生成物を保全・明示再利用し、元の3 actual0 producer証跡と残る8実commandを区別して結び付ける。元の検証条件・上限は変えない |

| E202: 1021 fixtureの元transport上限拒否 | v2のCLI/operator/client全3 no-runはactual0。8役は実際の最終fresh:false producerへ結び付き、source/tool/全役の実SHA/full9不変を確認。M2 controllerはembedded program263,004Bが元上限262,144Bを超えているためactual1。tmpfs volumeだけ作成後にfinally cleanupし、コンテナとruntimeは未実行。`m2-m3-followup-component-v2-1021-root-failure-closed.json` (`21f7fda9`) | 実両EOF/wait/reap・同Invocation自然Status1・PID/CG不在をroot照合し、自己所有の空failedunitだけ停止。V1/V2の失敗と実生成物は保全。上限を増やさず、Python ASTを変えないcomment整理だけでサイズを直してから別の実行で検証する。後続TLS/完全requiredや親全体へ転用しない |

| E203: c535の復旧鍵送金・historical body ACK喪失の実runtime | 同c535/treec439で元publication-genesis actual0、復旧済みA鍵のlive/restart実argv・A→B→A送信/各fee/nonce/owner/receipt/replayが成功。historical/empty/original TLSは各1 passed、remote TLS全15 passed。rootが全10実rawのSHA・EOF/wait/reap、source1221 full9/SHA・strict70/archive311/実生成物と別copy全8役・元producer/rawを再照合。同Invocation自然Status0・PID/CG不在後に自己所有の空unitだけ停止。`m2-m3-followup-component-v3-1021-root-qualified.json` (`6c347a5a`) | 元262144Bを上げず、Python AST同一のcomment移動でprogramを260747Bへ修正。Rust等1219 filesは同一で、6 actual0 compile commandの2ff生成履歴を保持する限定input bridge。5 runtimeはc535で新たに実行し、V1/V2 whole failureは保全。historical markerは保存済みstderrから照合し、rootの初回stdout-only判定ミスも保存。完全required/同sourceCIと親M2/M3は未完了 |
| E204: final c535 literal npm ci + complete required | c535/treec439で元2 commandsがactual0/実両EOF/wait/reap。check-all 12,228.090秒、Rust147 summaries/4,399 passed/0 failed/43 ignored、CF13/28/10/15=66。rootがsource1221全full9/SHA・HEAD/tree/clean/set、strict70/CF2347/layout2725/archive311/wrappersとcurrent330 executable ELF・cache/target全snapshotを再照合。`m2-m3-followup-final-full-required-1021-root-qualified.json` (`fe1db840`) と同root-raw-qualified (`848d42cf`) | 原7 epoch END・e8 freeze/unlock・実1832B候補2件/同ID round3 ACK・8links、元35-role assertionを保つ。実timingはstderr、候補/ACKはstdoutから再導出。natural同Invocation Code1/Status0と全既知PID/capturedCG不在後、自己所有の空unitだけ停止。current target/cache再利用でありfreshとは呼ばない。限定2子条件のsource gate。親M2/M3・release/独立監査は未完了 |
| E205: final c535 PR330 all8 hosted CI | [run39553580566](https://github.com/sunriselayer/sunrise-edge/actions/runs/39553580566) attempt1の元7 owners+aggregate全8が自然SUCCESS。actual checkout a84db307/treec439/ordered parents[c1,c535]、全8 raw 1,539,887B/SHA、Rust147 summaries/4,399 passed/0 failed/43 ignored、CF66、新旧TLS selector成功と元7epochs/e8候補2件/round3 ACKをroot照合。`ci330-final-1021-root-qualified.json` (`c712f86e`) | 旧2ff cancelledとcapacity停止、09:36のwatch終了code2/回収期限超過を保持。CIは11:17:56 UTCに自然完了し、再開後にread-onlyで初回raw回収。collector actual0/実EOF/wait/reapだがrecorderは同unit残存PID検出でStatus1。このwhole failureを成功扱いせず保存し、同Invocationの終了・当該PID/CG不在を別途照合した完了CI/rawの証拠。自己所有の空failedunitだけ停止。parserの診断stream/role集合の誤仮定も保存し、source/元assertion変更や再実行なし |

| E206: b389の復旧鍵split/merge・参照body付きACK喪失後の正常再起動 | b389/tree dfdc63d5の元publication-genesisと4 TLS selector・remote TLS全15がactual0。元split/mergeの復旧済みA鍵pathとlive/revoked restart実argv検査、歴史preimage復旧、全判定を保持。新M3はhistorical_nonempty/2→3 orderly restartを実stderr、1 passedを実stdoutで照合。rootが全13 commands/26 streamsのSHA・実EOF/wait/reap・既知PID/CG不在、source1223 full9/SHAとcurrent Cargo JSON/raw/原本・別copy全8役を再照合。`m2-m3-next-component-v4-1022-root-qualified.json` (`155bc428`) | current invocationのCargo fresh:trueをそのまま保持し、新規compileとは呼ばない。元raw 262144B/bootstrap 65536Bを維持し、コメント移動だけで両上限内。旧V1-V3/CI失敗は保存。元empty/same-generation/original TLS controlsも成功。positive_blob_fault/paid-produced blob publicationはfalse。完全required/全8 CIと親M2/M3は未完了 |
| E207: b389の完全required本体成功・環境固定postcheck失敗 | literal npm ci と ./scripts/check-all.sh はともにactual0/実両EOF/wait/reap。check-all 12,539.812秒、Rust147 summaries/4,400 passed/0 failed/43 ignored・CF13/28/10/15=66、新M3 selectorもok。source1223の全SHA/metadata・clean/HEAD/treeと全9 raw hashを閉鎖後に照合。read-only raw/source evidence `04c18cf7`、terminal `39bcc74d`、root tool-drift diagnosis `5c176e28` | ownerは終了時の固定tool照合でFileNotFoundErrorとなり、whole gateはFAILEDのまま保全。開始時Deno2.9.5/Python3.14.7のCellar実体が消失し、終了後aliasはDeno2.9.8/Python3.15.0へ変更。変更原因や実行中の全tool identity不変は未証明。固定guardを免除せず、ツールの復元・置換・再導入は行わない。close proofはCLOSED_FAILED、全既知PID/capturedCG不在・source/resource phase解放済み。全8 CIと新2子条件の最終資格は未完了 |
| E208: final b389 PR331 all8 hosted CI | [run39712537120](https://github.com/sunriselayer/sunrise-edge/actions/runs/39712537120) attempt1の全7 owners+aggregateが自然SUCCESS。actual checkout ec5ed35e/tree dfdc63d5/ordered parents[c535,b389]、全8 raw 1,564,511B/SHA、Rust147 summaries/4,400 passed/0 failed/43 ignored、CF13/28/10/15=66、新M3 selector okと元7epoch END/e8の1832B候補2件・同ID round3 committed ACKをroot照合。`ci331-final-v4-1022-root-qualified.json` (`e6300a0b`) | 元collectorを単発・独立有限scopeで実行し、actual0/実両EOF/wait/reap・collector/owner PID/capturedCG不在を確認。8link history testもactual ok。source phase解放後に元12 sourceのc535→b389不変・8links/35role assertionsを補足照合 (`c04ddbe3`)。stdoutのpath数から推定しない。旧observer143と2回の旧閉鎖記録は保持。新2子条件はE206/E208/E209の同source照合で完了し、親M2/M3は未完了 |
| E209: final b389の新固定profileでのliteral npm ci + complete required | Deno2.9.4の公式SHA固定task-local binaryと既存system Python3.14.8へ4 tool rolesを一対一bindingし、元guardを維持。両commands actual0/実両EOF/wait/reap、npm ci 1.698秒・check-all 10,227.685秒。Rust147 summaries/4,400 passed/0 failed/43 ignored・CF13/28/10/15=66。終了後にsource1223全full9/SHA・HEAD/tree/clean/set、2396 tool/seed hashes・67 strict/3 aliases・CF2347/layout2725、311 archives・5 wrappers・7 directoriesとcache/target/312実ELFをroot再照合。`m2-m3-stable-full-required-1022-root-qualified.json` (`7964867a`) | 元7 epoch END/e8の1832B候補2件・同ID round3 committed ACKと、元8links/35role assertionsをlocal/CIで照合 (`m2-m3-next-1022-original-required-protocol-qualified.json`, `c04ddbe3`)。自然同Invocation Status0・全既知PID/capturedCG不在・source/resource phase解放を確認。target/cacheは明示reuseでfreshとは呼ばない。E207の旧whole FAILEDと準備V1/readerの書式誤仮定は保存し、product再実行や元判定の変更へ混同しない。E206/E208と合わせ今回の2子条件だけを完了。親M2/M3・release/独立監査・公開判断は未完了 |
| E210: ordinary M3 coverageのsource/既存結果対応 | b389の全12 SQL tables・2 blob tables・4 portable kinds・70KiB historical body・reopen/fencing/ACK loss/replayを[固定記録](docs/development/validation/2026-10-22-m3-ordinary-coverage/README.md)へ対応付けた。rootが5 product file blobsと8daでの同一bytes、12 table名とE209実stdoutの5 named SQLite controlsのactual okを再照合。`m3-ordinary-coverage-map-1022-root-qualified.json` (`85574b21`) | 新しいruntime実行0。全table非空やphysical fault、positive_blob_fault/paid-produced publication、全M3の証明ではない。停止中のpartial write/anchor guest等は除外・未達のまま。追加の通常assertion不足は特定せず、対応表のみを理由とする再実行はしない |
| E211: live recovered-key genesis mint/burn source | `8da1d620` / tree `b60b28e8` の4 modified/1 added files。既存restored same-A keyを元live mint/burn・revoked restartへ接続し、path attributionを追加。Node24.19.0 parser/embedded Python AST/diff-check成功、raw247194/262144B・bootstrap55325/65536B、transport関数はb389とbyte同一。通常の狭いcorrectness checkも具体的regressionなし。DR-0280へ元契約の細分化を記録 | source-only。元6/6/4/2とrestart2/2/0/2・historical9e/9f・selectors・上限・authority/profileを保持。実UID/PTY・同source完全required/CI/releaseは未完了で、b389のE206/E208/E209を新source成功へ借用しない |
| E212: restored-key live mint/burnの実component | 同8daで元13 commands全actual0。実Docker Linux UID/PTYのlive/restart両signerがrestored pathを使用し、mint/burn6/6/4/2・取消restart2/2/0/2とhistorical9e/9fを保持。全26 streams/実EOF/wait/reap、今回のCargo JSONに結合した8 ELF roles、全1224 source inputs、終了後67 strict roles/3 aliases/311 archivesをrootで照合。自己所有PID/capturedCG解放と自然Status0を確認。[固定記録](docs/development/validation/2026-10-22-live-genesis-mint-burn/README.md)、root proof `c8ac8317` / input recheck `6331b2b3` | 限定実runtimeのみ。同8daの完全requiredは後続E213で成功。CI全8・RELEASEは未完了。子1件・親5件は未完了のまま。旧source gate/停止対象へ拡張しない |
| E213: restored-key mint/burn sourceの完全required | 同8da/tree b60bのliteral npm ciと完全check-allは両actual0/実両EOF/wait/reap。npm 1.685秒・check-all 10,157.567秒、Rust147 summaries/4,400 passed/0 failed/43 ignored・CF13/28/10/15=66。rootが全9 raw、全1224 source full9/SHA/HEAD/tree/clean/set、2396 tool/seed hashes・67 strict/3 aliases・CF2347/layout2725、311 archives・5 wrappers・7 directoriesとsaved/current inventoriesを再照合。root proof `c578c9e2` | 自然同Invocation `877f292d` Status0、MainPID0、既知PID/capturedCG不在とsource/resource phase解放を確認し、証跡保存後に空unitだけ停止。target/cacheはreuse。元protocol source補足と全8CIは別gateで未完了。RELEASE準備の初回census actual1/raw/EOF/waitは保持し、後続E214と区別する。同source RELEASE・子条件・親5件を未完了のまま保持 |
| E214: current RELEASE入力の通常offline準備とcensus | 初回censusの未展開26 sourceを、既存固定archiveのみの元 `cargo fetch --locked --offline` 1回で展開しactual0。root proof `6ce16d1e`。別rawの元census attempt2もactual0/実両EOF/wait/reap/PID不在。rootが全311 archives/Cargo.toml/markers/source metadata、23 tools、Cの1224 files/Git blobs/full9を再照合し、input review `2c56d2ff` | 新archive取得/コピー0、元285 source dirs不変。26展開分regular logical bytes114,639,116。expanded code全byte inventoryは未完了。元13-target A/Bを16:19:17 UTCに開始、実結果は後続E215。入力準備だけをA/B・runtime成功へ加算せず、初回失敗・元selector/上限・source/cache専有を保持 |
| E215: exact8da Cのfresh Native13 A/B | 元13 targets・2 fresh lanesがactual0/実両EOF/wait/reap、726.639秒。rootが全13組byte/mode/owner一致・保存26 ELF/full9/別inode/nlink1/0755/UID1000、実Cargo JSON・C1224 files/Git blobs・23 tools・311 archive/metadataを照合。選択231依存の10,017 files/122,049,003 bytesもarchive payloadへ対応。root proof `c27ecbe5`、consumer view `f13edfd8` | 同Invocation `1d02e0c3` の既知PID/capturedCG不在、4専有dirとsource lease解放。初回readerのconfigured tool alias処理不備を保持し、元guard付きのreader修正だけを実行、build再実行0。全M7・未選択expanded code・元12 runtime・CLI fixture成功へ拡張しない。driver初回はstale監視pathにより自己停止し、実main SIGTERM15/Cargo exit null/部分targetを保持、終了proof `f0291de8`。子条件・親5件は未完了 |
| E216: current Cの元12ケース用driver compile | 初回自己停止を保持した別attempt2が自然actual0/外側実両EOF/wait/reap、798.119秒。元2 Cargo commandsもmerged stdout/stderrの実EOF/wait・actual0。13 debug bins/10 integration driversを今回のCargo JSON/genuine C package/manifest/srcPath/元dev-test opt2 profileへ対応付け、実体hash/metadata、C1224 source inputs、23 configured/resolved toolsと4 own wrapper hashesをrootで照合。proof `8a429482` | Invocation `733a0d87`、owner1648518/launcher1648516と既知PID/capturedCG不在、終了proof `1d8f5d21`。元のselector・上限は維持。テスト本体実行0、一覧観測と元12 runtime/CLI fixtureは後続。最初の失敗・部分target・binding/reader準備の失敗記録を保持し、子条件・親5件へ加算しない |
| E217: current driverの実テスト一覧 | 元10 driversの通常/ignored一覧20 commandsが全actual0・実両EOF/wait/reap。rootで全40 raw hash/argv/nameを照合し、通常99・ignored3、元のexact ignored2件はconditional_readiness_sqliteに存在すると確認。local_tlsは18/1。通常99+指定2=101。proof `21fa93bb` | 10 ELFの現在hash/full9がbefore/afterと一致。owner1663357/launcher1663355と全20 child PID/capturedCG不在。一覧だけでテスト本体成功には数えない。初回root readerのmode schema比較ミスを保持し、permission bitsへ修正して照合。list再実行0 |
| E218: mint/burn同sourceの全8 CI | run39775926228 attempt1が自然全8 success。checkout58f7cef8/treeb60b28e8/parents[b389,8da]と8 raw logs計1,564,992Bをroot照合。Rust147 summaries=4,400/0/43、CF13/28/10/15=66。元7epochs/e8・同IDの1832B候補2件/round3 committed ACKと8link test成功も照合。proof `7a0ec175` | ログ回収のscope/wait不整合とPATH不足の2失敗を保持。3回目collectionはactual0・実両EOF/wait/reap、全既知PID/capturedCG不在。CI job再実行0。35roleのsource補足とRELEASE runtime/CLI fixtureは別に残り、子条件・親5件へ加算しない |
| E219: current RELEASE CLIのpublication-genesis | 新しい8daのNative13 RELEASE CLIと同source/S由来のretained harnessを使用。fresh2 ELF/library inventoryはactual0・root `d9dfe9e6`。元profileを1回実行しactual0/外側実両EOF/wait/reap、5.632秒。73 recursiveTrue pathsが元sourceの全期待pathと一致し、復旧key live/restart・6/6/4/2と2/2/0/2・9e/9f signing-only controlsを保持。executor proof `bde4f5cb` | Invocation `af003ec8`、保存live ExecStartは実v3 ownerと一致。owner1669845/launcher1669843・capturedCG不在、Node所有container_removed=true。C/S1224 files/Git/full9のempty-diff bridgeとgenuine S Cargo provenanceを保持。元12 runtimeと親M2/M7は別条件 |
| E220: local/CIの元protocol assertions | E213のlocal完全requiredとE218の全8 CIの実rawを照合し、元7epochs/e8の1832B候補2件・同ID/round3 committed ACKを確認。元12 product filesはc535から8daまで不変で、成功した8link driverのsourceが3+4*8=35rolesをassertすることを確認。root `4a3ddf6b` | stdoutのpath数からrole数を推測しない。旧readerのFULL state label schema相違を保持し、固定済み実proofの_8DA1へ修正。製品run再実行0。物理fault・独立監査・RELEASE全体・親5件の完了を主張しない |
| E221: 元12 RELEASEのcheck/probe | 同8da/current49 ELF・C1224 source・23 toolsの固定snapshotを使い、check1.425秒/probe1.310秒がactual0・実両EOF/wait/reap。rootが閉じたraw/hashと13 RELEASE replacements・13 debug/10 drivers、probe内のPID/net namespace分離とloopbackを照合。proof `c5b6d2c6` | 各preflightのknownPID/capturedCG不在。元selector/timeout/capsは維持。開始前のbinder count-assertion選択とunit名重複の不具合は保存し、controlsだけ修正。runtime-attempt3はcontrol revision名で、製品runの3回目ではない。元12本体は当時17:40:29 UTCから実行中だった。後続E222で本体を別途照合。CI/Native成功を本体成功へ転用しない |
| E222: current8daの元12 RELEASE runtime | 17:40:29→20:17:38 UTCに本体が自然終了。元10 whole/2 exactの全12 commandがactual0/merged EOF/wait、通常99+元exact2=101 passed/0 failed、whole側ignored3。実13 RELEASE replacements・13 debug/10 driversを保持。全7epochs/e8・同IDの1832B候補2件/round3 committed ACK、元8link/35role source assertionsを照合。root終了後reader actual0/proof `4169685e` | 外側session51431の143、wrapper個別exit/owning terminal未観測、attachment前の外側stream欠落、captureのCOUNT順序/type誤りを保全。元helperの順序/tupleをread-only reader内だけで復元し、元全predicateを再照合。product再実行0。全C1224/Git/full9・49ELF・23tools、全既知PID/capturedCG・drain・privateTMPの解放まで確認。このmint/burn子条件だけを完了し、親5件へ転用しない |

E136-E141は後続の限定実行です。E133-E135の保存済み行は当時の失敗/source-only状態のまま残します。
E140/E141のUID/PTY/同frame署名・保持preimage・refusalは、固定sourceで成功したaggregate JSONと
全体rawへ結び付きます。削除済み個別seed/approval/signatureや未保存の各child/PTY/client streamを
再open・独立再構成したとは扱いません。親receipt・raw・厳密source bridgeのfull hashは
validationの`todo-post-e135-through-e141-mb-ad3c-proposal-1017.json`に固定します。










新しいrawの保存先は `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013`。
E74は `technical-six-owning-1017-terminal.json` / `.log` と親の
`technical-six-owning-parent-qualified-1017.json`。raw SHA-256は
`498730b69ea721f978e8597fb8f14b90675a6451505db4b2b8b15d7560f29be5`。
E75は `d4dd-coin-custody-fixture-1017-terminal.json` / `.log` と
`d4dd-coin-custody-fixture-parent-qualified-1017.json`、raw SHA-256は
`cff27046aa8aac4798ba7c0eea5b1813179d81adb23cb05557452db6dc8ef849`。
E76は `checkpoint-anchor-component-qualified-1017.json` /
`checkpoint-anchor-parent-qualified-1017.json` と
`checkpoint-anchor-d4dd-code-correspondence-1017.json`、成功raw SHA-256は
`d66d292bc7ad6a745f945cf63ab2750b63cd93cab862bfd5b37c93d5a953cd86`。
E77は `m3-qemu-product-build-1017-terminal.json` / `.raw` と
`m3-qemu-product-vm-attempt1-qualified-failure-1017.json` / `qg1017a/terminal.json`。
VM raw SHA-256は `29e90314983a21418f6b80047d0434d635e7345eb29c77477f3c975391c08157`。
E78は `checkpoint-v2-owning-1017-terminal.json` / `.log` と
`checkpoint-v2-owning-failure-qualified-1017.json`、raw SHA-256は
`98b3f98cf32b54a8307799f831edc188d33b1ea1f1b89d03110ce7de2b758164`。
E79は `m3-qemu-product-build2-parent-qualified-1017.json` /
`m3-qemu-product-vm-attempt2-qualified-1017.json` /
`m3-qemu-product-vm2-parent-qualified-1017.json` と `qg1017b/terminal.json`。
VM raw SHA-256は `cb32205d920fa6d727740bc2862857f31950a2b1b5ada6d7899626d772b08c68`。
E80は `checkpoint-v2-owning2-1017-terminal.json` / `.log` と
`checkpoint-v2-owning2-failure-qualified-1017.json`、raw SHA-256は
`e9cbf7fbfaa6f440214a81295543654a5589a0e7a3ed79b6ceb93d71ec36a5bb`。
E81は `checkpoint-v2-owning3-1017-terminal.json` / `.log` と
`checkpoint-v2-owning3-failure-qualified-1017.json`、raw SHA-256は
`5ff30e574b182b15b072131dfaf694df3cacbbac46b711273f6dca8998eecf71`。
E82は `ordered-worker-component-owning1-1017-terminal.json` / `.log` と
`ordered-worker-component-owning1-parent-qualified-1017.json`、raw SHA-256は
`f9f3ac5fb51d29491de2589eb9b44a0142cc19c17751745e0861c30b7233ef45`。
E83は `checkpoint-upgrade-owning4-1017-terminal.json` / `.log` と
`checkpoint-upgrade-owning4-parent-prefix-qualified-1017.json`、raw SHA-256は
`8c6239d44ab9223dae29338dab0629e062c4baff96c23224cd70c0560a2546b8`。
Clippy修正後は `checkpoint-upgrade-lint5-parent-qualified-1017.json` と
`checkpoint-upgrade-lint5-1017-terminal.json` / `.log`、raw SHA-256は
`2ff7660d6181f881204905cc2e30da0703f09052962b74c38e62ce6a99f28a26`。
E86は `m3-anchored-library-build2-parent-qualified-failure-1017.json` /
`m3-anchored-library-build3-parent-qualified-1017.json` /
`m3-anchored-vm1-parent-qualified-failure-1017.json` と `qga1017a/terminal.json`。
guest raw SHA-256は `e33c54ab54e106080bb810b729fbefe56607ac10611cc4778621429b7318b998`。
停止は `m3-anchored-boot-provider-stop-1017.json` に保持する。
E87は `m2-ordered-fixture-build3-parent-qualified-1017.json` /
`m2-ordered-fixture-inventory3-parent-qualified-1017.json` /
`m2-ordered-fixture-runtime3-parent-qualified-failure-1017.json` と
`m2-ordered-fixture-runtime3-1017-terminal.json` / `-complete.json`。
E88は `sqlite-library-inspection-build4-parent-qualified-1017.json` /
`sqlite-final-five-inspection4-parent-qualified-1017.json` と
`sqlite-library-inspection-build4-1017-terminal.json` / `.raw`、
`enospc-final-inspection4/terminal.json` / `raw.log`。
library raw SHA-256は `891ad3015b03388da289df829520c1e710c27f1558f92e7cd7c74bf421f9839b`、
ENOSPC raw SHA-256は `1a161db14ebac9262cb9778dc8f55b58439099f9ba664eec61e8e7e730c40d4b`。
E89は `m2-ordered-fixture-build4-final-parent-qualified-1017.json` /
`m2-ordered-fixture-inventory4-final-parent-qualified-1017.json` /
`m2-ordered-fixture-runtime4-final-parent-qualified-failure-1017.json`。
E90は `m2-original-ordered-fixture-complete-output-transport-source-1017.json` /
`m2-ordered-output-transport-1017-pure-check.json` /
`m2-ordered-output-transport-parent-source-review-1017.json`。
E91は `m2-ordered-fixture-build5-parent-qualified-1017.json` /
`m2-ordered-fixture-inventory5-parent-qualified-1017.json` /
`m2-ordered-fixture-runtime5-parent-qualified-1017.json` と
`m2-ordered-fixture-runtime5-1017-terminal.json` / `-complete.json`。
完全runtime JSONのSHA-256は
`256294416e9bb1ad48a194f56c8dcc36123c6005e9f884f19c09a181e7b25f79`。
E92は `r4-runtime-9de6-1016-terminal.json` / `-receipt.json` と
`r4-runtime-9de6-independent-qualified-1017.json` /
`r4-runtime-9de6-parent-qualified-1017.json`。実rawは
`r4-runtime-9de6-1016.log`、SHA-256は
`6e9b3ed1b9367c9f1586fc61a484e880c494329956b021e61983dcaed9c4dae4`。
E93は `final-native-promoted-1017-terminal.json` とactual Native manifest、
`native-final-7658-ab-independent-qualified-1017.json` /
`native-final-7658-ab-parent-qualified-1017.json`。manifest SHA-256は
`acde37f611642b76001e5342c6fb28e11edad9fdb73189c4ab2c8b198c0bae57`。
E94は `native-final-7658-drivers-parent-qualified-1017.json` と
`m4-release-promoted-parent-qualified-1017.json`、普通source reviewは
`m4-final-7658-ordinary-source-evidence-review-1017.json`。
E95は `native-final-7658-cli-harness-parent-qualified-1017.json` と
`native-final-7658-release-cli-runtime-parent-qualified-1017.json`。
E96は `positive-fee-claim-policy-build2-parent-qualified-1017.json` と
`positive-fee-claim-policy-genuine1-parent-qualified-1017.json`。
E97の失敗は `certified-fastvote-component1-independent-qualified-failure-1017.json`、
`certified-fastvote-component2-independent-qualified-failure-1017.json`、
`certified-fastvote-component3-independent-qualified-failure-1017.json` と各actual raw/terminal。
E95のoriginal ordered RELEASEは `m2-ordered-release-7658-runtime-parent-qualified-1017.json`。
E98は `positive-fee-claim-custody-build1-independent-qualified-1017.json` /
`positive-fee-claim-custody-build1-parent-qualified-1017.json` とactual raw/terminal。
E99は `positive-fee-claim-custody-genuine1-parent-qualified-1017.json` とactual raw/terminal。
E97 attempt4は `certified-fastvote-component4-independent-qualified-failure-1017.json`。
追加UID sourceの指摘は `positive-fee-split-uid-3b8e-ordinary-review2-1017.json` /
`positive-fee-split-uid-3b8e-parent-partial-source-review-1017.json` に保存。
E100は `certified-fastvote-component5-parent-qualified-1017.json` とactual raw/terminal。
E101は `m2-certified-fastvote-fixture-build1-independent-qualified-failure-1017.json` とactual raw/terminal。
E102は `positive-fee-split-uid-build2-independent-failure-qualified-1017.json` とactual raw/terminal。
E103は `m2-certified-fastvote-fixture-build2-independent-qualified-failure-1017.json` とactual raw/terminal。
E104は `positive-fee-split-uid-build3-parent-qualified-1017.json` とactual raw/terminal。
E105は `m2-certified-fastvote-fixture-build3-parent-qualified-1017.json` とactual raw/terminal。
E106は `m2-certified-fastvote-fixture-inventory2-parent-qualified-1017.json` とactual complete inventory/terminal。
E107は `positive-fee-split-uid-genuine1-independent-failure-qualified-1017.json` とactual raw/terminal/partial public evidence。
E108は `m2-certified-fastvote-fixture-runtime2-independent-qualified-failure-1017.json` とactual complete/raw/terminal、
追加不在確認は `m2-certified-fastvote-fixture-runtime2-root-owned-absence-1017.json`。
E109は `m2-certified-fastvote-fixture-build4-parent-qualified-1017.json` とactual raw/terminal。
E110は `positive-fee-split-uid-build4-parent-qualified-1017.json` とactual raw/terminal。
E111は `m2-certified-fastvote-fixture-runtime3-independent-qualified-failure-1017.json` とactual complete/raw/terminal、
追加不在確認は `m2-certified-fastvote-fixture-runtime3-root-owned-absence-1017.json`。
E112は `positive-fee-split-uid-genuine2-independent-failure-qualified-1017.json` とactual raw/terminal。
E113は `m2-certified-fastvote-fixture-build5-parent-qualified-1017.json` とactual raw/terminal。
E114は `positive-fee-split-uid-genuine3-independent-failure-qualified-1017.json` とactual raw/terminal/retained public evidence。
E115は `m2-certified-fastvote-fixture-runtime4-independent-qualified-failure-1017.json` とactual complete/raw/terminal、
追加不在確認は `m2-certified-fastvote-fixture-runtime4-root-owned-absence-1017.json`。
E116は `positive-fee-split-fixed97-raw-budget-1017.json` / append-only addendum、
`positive-fee-split-uid-a4f6-source-inputs-1017.json` とADR-0270。
E117は `m2-certified-fastvote-fixture-build6-parent-qualified-1017.json` とactual raw/terminal。
E118は `positive-fee-split-uid-build6-parent-qualified-1017.json` とactual raw/terminal。
E119は `m2-certified-fastvote-fixture-runtime5-independent-qualified-failure-1017.json` とactual complete/raw/terminal。
E120は `positive-fee-split-uid-genuine4-independent-failure-qualified-1017.json` とactual raw/terminal/retained public evidence。
E121は `m2-certified-fastvote-fixture-build7-parent-qualified-1017.json` とactual raw/terminal。
E122は `positive-fee-split-fixed97-metadata-budget-1017.json` とADR-0270/207e source。
E123は `m7-canonical-frame-mutation-0b26-source-candidate-1017.json` と追加test/手順書。
E124は `m2-certified-fastvote-fixture-runtime6-independent-qualified-failure-1017.json` と追加不在確認/ADR-0271。
E125は `positive-fee-split-uid-build7-parent-qualified-1017.json` とactual raw/terminal。
E126は `m7-canonical-mutation-build1-parent-qualified-1017.json` / independent qualificationとactual raw/ELF/terminal。
E127は `m2-certified-fastvote-fixture-build8-parent-qualified-1017.json` とactual raw/receipt/terminal。
E128は `positive-fee-split-uid-genuine5-parent-qualified-1017.json` / actual-runtime qualificationとcomplete retained public evidence。
E129は `m2-certified-fastvote-fixture-runtime7-parent-qualified-1017.json` / independent qualificationとactual complete/raw/decoded success。
E130は `technical-six-required-final-parent-qualified-1017.json` / independent qualificationとactual merged log/terminal/journal。
これらは各componentの資格であり、この後の統合headの完全gateへ付け替えません。

E10は `pg-profile2.log` / `pg-profile2-receipt.json`、E11は
`required-current3.log` / `required-14fb-receipt.json` と
`required-current5.log` / `required-5672-receipt.json`、
E12は `native-ab4.log` / `native-5672-receipt.json` と
`native-output-parent-1013/native-56727192-1013/manifest.json`、
E13は `custody-os-current.log` です。E12 manifest SHA-256は
`7349da32802348e5ca5f9298c09330fc0c3385c898fe8165d2edfaa496aade80`。

E14は `required-ci2-50a4.log` / `required-ci2-50a4-receipt.json`、
raw SHA-256 `0f892b3b76b878c79eaf94ec6a34ce21f518aa23a2f8a01d9015d71d3997018d`。
E15は `native-ab5.log` / `native-50a4-receipt.json` と
`native-output-parent-1013/native-50a464c8-1014/manifest.json`、manifest SHA-256
`30de43ec73634640db924864ba01beb56e7ea51eb3f70dcb4d73bf8f529702e8`。
E16は `npm-audit-50a4-receipt.json` / `cargo-osv-50a4-receipt.json`、
`npm-audit-old-f655-control-receipt.json` / `cargo-osv-old-rustls-control.json`、
`npm-lock-metadata-delta-50a4.json` / `sharp-runtime-50a4.json` です。
14fb/5672/50a4の両lock hashは同じですが、入力対応だけで別sourceのPG/custody結果を
新しい全体合格へ転用しません。


E17は `hosted-node24-537c.log` / `hosted-node24-537c-receipt.json` と
`hosted-node24-537c-run-metadata.json` / `hosted-node24-537c-checkout-commit.json`。
E18は `native-node24-ab2-537c-1014.log` / `native-node24-537c-receipt.json` と
`native-output-parent-1013/native-537c8777-node24-2-1014/manifest.json`、manifest SHA-256
`073ae468a1568798bbee7d9566a332b5c2c7266350072b6c7642a86a2e0bfab7`。
E19は `r4-runtime-node24-537c.log` / `r4-runtime-node24-537c-receipt.json` /
`r4-runtime-node24-537c-terminal.json` / `r4-runtime-node24-537c-collected.json`。
raw SHA-256 `dcdaaddd446c88f0794a47d5c6c597287c7f6b5ffa9e34bcf165ad073b47e1fc`。
E20は `node24-required-r4-2-1014.log` / `node24-required-537c-receipt.json`。
独立Opusのsource/profile admission reviewと親の実raw/前後hash/cleanup照合を終えました。
E17によるsource qualificationとE20のlocal終端未確認を区別します。
旧50a4のrelease実行停止raw・Btrfsの失敗root・probe資料も保持しています。

E21は `m2-lifecycle-pinned-bc4d-1015-terminal.json` / `-receipt.json` /
`m2-lifecycle-pinned-bc4d-1015.log`。取消記録の並行再試行が成功した後に先行処理が
sync失敗しても記録を消さない修正を含み、独立correctness review済みです。
旧動作へ一時的に戻す隔離negative controlはactual exit 101/1 failedとなり、元のbytesへ
戻した正常sourceで71件と実UID/PTYを再確認しました。rawは
`m2-mutant-overlap-bc4d-1015-receipt.json` / `.log` として保持します。
E22は `m2-lifecycle-required-1b79-1015-terminal.json` / `.log`、raw 650,200 bytes、
SHA-256 `ea6707a917753844f46b98e8624f6a057bd330c4fc3ba8cdd7d3c008c2aa037d`。
所有controllerが各processの実wait/EOFと前後sourceを記録し、npm-ciは1.844秒、
check-allは13,038.980秒で全required stepsを完了。unit invocationは
`dcf846e3b63841cdba7d9c17bdd0d880`、観測peak 3,226,845,184 bytes、swap 0。
hostedは `hosted-m2-1b79-1015-receipt.json` / `.log` とrun metadata/checkout commit。
raw 1,428,951 bytes、SHA-256
`d1e1b1f153127b823e0246b64fbbd276c49cf7120a1fd12d8260cf88e5928b51`。
先行8910のlocal完全gateはsource更新で停止しterminal nullのまま、bc4dの完全gateは
rustfmtでactual exit 1/EOFとなった失敗を保持。旧CIのcancelも成功へ転用しません。

E23は `fee-claim-targeted-cf2d-1015-terminal.json` / `.log` / `-inputs.json`。
raw 12,030 bytes、SHA-256
`cb2747dca1a0d5f769a612ff74848a3e486e0e8e80f44d9c5827df15f309621d`。
E24は `fee-claim-required-cf2d-1015-terminal.json` / `.log` / `-collected.json`、
raw 673,218 bytes、SHA-256
`baa202fce34921828e7cc21240c3d086f6508aefadbd5c09b9501b58e9fcbedb`。
npm-ciは1.828秒、完全check-allは14,047.564秒。所有controllerが全stepsの実wait/EOFと
前後source/cleanを保存し、unit invocation `c842ef8b5d344cd29ec6efbad134386f` の
観測peak 3,789,402,112 bytes / swap 0を別記録した。既存nvmのversion/defaultは維持。
9178の初回Dockerは分離UIDが生成物mode0700を読めずactual exit 1、診断はloaderの
Permission denied/127。元実行fileのbytes/modeと失敗rawを保存し、成功へ書き換えない。
1feの限定検証成功はそのsourceだけの履歴。1feの完全gateはcf2dのparent判定修正で停止し
terminal nullのまま保持、旧CI `38673793393` のcancelも全体成功に数えません。
hosted rawは `hosted-fee-claim-cf2d-1015.log` / `-receipt.json`、run metadata/jobsと
checkout commitを別保存。raw 1,481,063 bytes、SHA-256
`d5d081f096a7e59eeb893b5e863d29d82d5f00be7929a6736facc630ccf56716`。
CI merge checkout `29f91118a5d7b5f8954e16d999a93836d7d8a242` のparentsはa089/cf2d、
treeはcf2dと同じ `01bcfe95ec91b882ebf6bd8424c733514afa924f` と実ログ/Git APIで照合済み。

実M7の初回は、正式なcookie-factory 0.3.3 archiveに同梱されない未選択exampleを
held inputにしてビルド前に停止しました。欠損cacheとは扱わず、library/proc-macro/
build scriptは必須のまま、未選択registry targetをartifact/diagnosticに認めない
限定修正を行いました。[DR-0239](docs/architecture/decisions/0239-registry-dependency-target-kind-scope.md)、
151 fixture controlsと独立correctness reviewを経てE12を実行しました。
先行PRの自動修正 `9ff2a489` / `6c3f4ddc` による非上書き書き込み・socket cleanup・
rollback後directory syncも独立correctness reviewとE13の回帰controlsで確認しました。
これらのcorrectness reviewはM1/D02の独立security監査の代替ではありません。

5672の[hosted CI run `38410087138`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38410087138)
は6/7 ownersがsuccess、recurring-sqliteが360分の枠でCANCELLED、success-only checkはFAILUREです。
checkout `6eaf4cf84f4055fba71f2760bc04a58ba9f69f7a` のtreeは5672と同じ15c2。
local E11をhosted terminal successとして扱いません。timeoutの実ログを照合し、
元8リンク/e8 withdrawals/35 roles・拒否controls・待機時間を維持して実行条件を修正しました。
旧pending状態の間はCIをcancelしないため状態更新commitをローカルに保持しました。
そのterminal後に[DR-0240](docs/architecture/decisions/0240-recurring-ci-compilation-profile.md)
のcompilation profileを適用し、通常dev/test level 1とcurve level 3、安全checkを保持した
まま、hosted recurring-sqliteだけlevel 2を選択しました。元の全case/selector/restart/
refusal/待機時間/360分枠・全7 ownersとsuccess-only checkは維持しています。
独立Opus correctness review、CI mutation contract、実compiler flagsと補助arithmetic
controlも確認済みです。新しい[hosted run `38481465847`](https://github.com/sunriselayer/sunrise-edge/actions/runs/38481465847)
は全7 unconditional owners + success-only checkがSUCCESS。
recurring owningは14,824.48秒、job全体15,094秒。checkout `678509cb5b43b41154221c06b048a5fae17b7f85`
のtreeは50a4と同じ `eff704ddad3be9e7730c53776fe5d8c019d7ea4f` です。全8 checkoutの実ログを照合し、
`hosted-ci2-50a4.log` / `hosted-50a4-receipt.json`を保存しました。raw SHA-256は
`9642d8707876f5e40888ccd9302887fb5f121313f024d7b9b1798123eca32862`。

E25は `technical-eight-targeted-1016-terminal.json` / `.log`、raw SHA-256
`94653591bfa8364856ab3a48d1ba3c0b359da9b189bc67e6dbb0b725a3ffbfa5`。
E26は `native-426e-1016-terminal.json` と
`native-output-parent-1013/native-426e8359-1016/manifest.json`、manifest SHA-256
`8b2d40f8d047ce2fe16a6cc45568226f8a232205e73c1657539a430360f751ed`。
E27は `release-cli-custody-426e-1016-terminal.json` / `.log`、raw SHA-256
`3f66c384240ed43c97c5aabd98561431b19de88af498e2f0571429afdcf1e10c`。
いずれも426eに固定した範囲。新しいfloor/stop sourceの完全gateへは借用しません。
E28は `native-b568-1016-terminal.json` と
`native-output-parent-1013/native-b568037f-1016/manifest.json`、manifest SHA-256
`3c97a9a33782f7f650e0addd3e9449ae684bc91a0205b0bd4304a10f9742a5af`。
E29は `native-b568-release-import-1016-terminal.json` と
`run-native-b568-release-import-view-1016-receipt.json`、complete driver rawは
`run-native-b568-release-import-view-1016.log`、SHA-256
`1667abb0524741c98c169f93ec05f927de234a374ff62112e2a3434f449393aa`。
最終helperは独立correctness reviewの指摘処理後、同一SHAでcheck/probe/runtimeを実行しました。
各rawは上記sourceだけの証拠であり、後続変更や長時間完全gateの成功へ置き換えません。
E30は `stopped-fresh-targeted2-1016-terminal.json` / `.log`、raw SHA-256
`1ae264a72c9db004fc1e3c0e6bc91678725aa9dc3fc25f4d9a860eac72bc8479`。同receiptのsourceBefore/Afterで
実test/doc bytesの同一性を照合しました。初回の12 cases成功も保持し、fee sourceの
説明訂正とreceipt/effect oracle追加後の再実行を最終component証拠に使います。



E31は `successor-stop-targeted-1016-terminal.json` / `.log`、raw SHA-256
`95cd4d9b5552851ffef5530fe166f9cefd44e21f209a299df566787ac304ff3d`。
負対照は `successor-stop-negative-1016-terminal.json` / `.log`、raw SHA-256
`fef766daeefac7f2cf6c530bef2d2ce7964ef4aeaeec89812192651603393fac`。controller exit 0は期待した失敗の検出と復元成功を表し、
guard欠落時のtest exit 101をtest成功へ読み替えません。
統合後は `successor-stop-merged-targeted-1016-terminal.json` / `.log`、raw SHA-256
`f681007eaeae58f61165e0c7d391a405f15e6359e42ffc36bec19304de804ecd`。新guard/testの2 Rust filesは最初の213件実行時ともbyte一致し、
統合後のsourceBefore/Afterも一致します。既存の別sourceへ成功を借用しません。

E32は `history-stop-targeted-1016-terminal.json` / `.log`、raw SHA-256
`e7e2f1d38e0a4930c13e275531d81249ba62470bc250b795bcf12486fc003c8d`。負対照は
`history-stop-negative-1016-terminal.json` / `.log`、raw SHA-256
`c603dac0ffa1f3b5a9ec5b7047f7e3b31adecc2a8ec545f573416b8c74abcd5d`。負対照actual101と復元後actual0を分けて保存し、
2 Rust filesのbyte復元・最初の全218件との一致を親でも照合しました。

E33は `coin-ops-core-targeted4-1016-terminal.json` / `.log`、raw SHA-256
`eb8d73a64f26e522c4fe5cfd0be6ed07166ca38396d7ff72bc10e4586d90de16`。実UID/PTYは
`coin-ops-docker-1016-terminal.json` / `.log`、raw SHA-256
`f4cacba2d8736c0437d00226d03e99913070db1f023362cb5a8338dbd9f83920`。compilerの実package ID/src path/test executableは
`coin-ops-compiler-artifact-observation-1016.json`。親もsourceBefore/Afterと
両入力ELFのhash/mode/owner/identity不変を照合しました。Node/Python構文、private
preimageの上書き衝突、Rust型/lifetimeと承認期限の初期指摘・失敗は保持し、修正後の
実行だけを成功に数えます。outer280秒/inner230秒・出力・コンテナ上限は維持しました。


## 作業終了時の環境整理

これは製品の旧20項目とは別の作業TODOです。

- [x] **専用Node 22を終了後に削除する**: 50a4のlocal requiredとhosted CI終端成功後、
  所有service終了と実行/保持中のruntimeがないことを確認し、今回取得した
  `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/node-22.20.0-1013`
  のNode本体とarchiveだけを削除した (計153,921,504 bytes)。取得記録はvalidation直下の
  `node22-acquisition-receipt-preserved-1014.json`、削除記録は
  `node-cleanup-1014-receipt.json`。rawログ・manifest・元の`receipt.json`を保持した。
  既存nvm/system Nodeのidentityとdefaultを前後で照合した。
- [x] **今後のローカルNode管理をnvmに統一する**: 既存nvmと選択profileの固定versionを
  使う運用ルールをAGENTS.mdへ記録した。global defaultを維持し、選択profileの固定versionを
  別versionで代用しない。今回の専用Cargo/check-all wrapper 5件は元file/hashを保存して
  退役させた。次回はnvmの固定runtimeを明示して新しいsource/profile用に準備する。
- [x] **Node 24で現行の検証profileを揃える**: CI、SDK relay、Native evidenceを
  既存nvmの24.19.0へ統一し、DR-0243と`.nvmrc`へ固定した。SDK 11 targets/294 tests、
  CI契約、Native 151 fixture、Cloudflare type/lint/workerd 66 testsが成功。
  同一treeの全7 required owners + checkはE17、actual Native A/BはE18、
  実RELEASEのR4はE19で成功した。過去22.20.0の証拠を保持し、nvmへの22.20.0
  再取得案は未実行のまま取り下げた。既存24.19.0/22.23.2とglobal defaultは維持した。
  E20のlocal完全command終端未確認は旧履歴として残し、新しい完全実行はE22へ記録した。
- [x] **local完全gateの終端記録を確定する**: 新しいM2 source `1b796c3c` でliteral
  npm-ci +完全check-allのactual exit 0/EOF・全steps完了・前後cleanを所有controllerが
  保存した (E22)。最後の無出力stepを含む全commandの終端が対象。
  E20の旧実行はouter143/terminal nullのまま保持し、成功へ書き換えない。
- [x] **Cloudflare CLIへの残る移行を確認する**: 直接の操作・型生成を`cf` / `cloudflare`へ統一。
  5 profilesの実typegen・10拒否controlsと全4 Vitest計66 testsはE147/E148で成功。
  既存Vitest plugin内部のtransitive Wrangler SDKは保持する。exact e4fbの完全requiredと
  全8 CIをE161/E162で照合し、この移行確認を完了した。後続Rustls更新sourceの資格は別途照合する。

## コード・検証: 14件

共通の検証は後述Gを一度記録し、同一ソース・同一範囲なら複数項目から参照します。
単なる整理のために新しいframework、SDK foundations crate、重いCI laneを追加しません。

- [x] **R1: データ・codec・error・boundsの定義元を一本化する**
  - 対象: 実装 + 検証。実際のcore/wire/SDK/host呼び出しを移行し、コピーした規則を除去する。
    既存bytes・error優先順位・権限境界を保つ。全SDK依存の解消を新条件にはしない。
  - 状態: c69の移行をE5/E6で確定。receipt binding、E009署名codec、validator/
    consensus/frontier boundsのownerとactual callers、既存bytes/error orderを確認。
    evaluator自身の確定出力比較はquery bindingとは異なる規則なので無理に統一しない。

- [x] **R2: admission・evaluation・commit・reconciliationの責務を揃える**
  - 対象: 実装 + 検証。判断を一つのownerへ置き、actual CAS/Conflict/Rejected/Indeterminate、
    receipt-first replay、正当なprefix進行とmemory reconstructionを維持する。
  - 状態: c69の実装をE5/E6で確定。transaction parts・ordinary write lifecycleの
    shared owners、Memory/SQL callersとreceipt-first/CAS/Indeterminateの保持を確認。
    PostgreSQL固有規則と各evaluatorの結果照合はそれぞれのownerに残す。

- [x] **R3: テストとCIの責任範囲を明確にする**
  - 対象: 実装 + 検証。fixtureは入力、独立oracleは期待値を所有する。重複削減は
    exact-input coverageと実測がある場合だけ。元のrecurrence・delay・restart・faultを保持する。
  - 状態: c69のregistry・capture・controlsをE5/E6で確定。7 ownersはrequired actionの
    全範囲を保持し、3つのlong controlsを各1回実行。8リンク/e8 withdrawals/35 rolesの
    元の負荷・restart/refusal assertionsは削減していない。

- [x] **R4: source/build/configurationと実行可能な手順を結び付ける**
  - 対象: 実装 + 検証。公開するfamily・signer/store capabilityと
    startup/stop/restart/recovery手順を同じrelease artifactへ結び付ける。
  - 状態: DR-0241とNative handoff設計で13 targetsの実mode・family・signer/store・
    既存手順を対応付けた。537cのE17 source qualification、E18実A/BとE19実RELEASE
    runtimeを照合し、起動/TLS/compiled CLI/stop/restart/fence/refusal/recoveryを確認した。
    元8リンク/e8 withdrawals/35 rolesを維持し、全12 runsがactual exit 0/EOF。
    13 RELEASE/13 host debug/10 driversの前後hash一致と所有資源releaseを確認した。
    旧Btrfs失敗raw/rootを保持し、DR-0242のfresh-open修正と同一case/拒否/回帰を検証した。
    E20のlocal終端未確認は残し、R4の根拠へlocal exit 0を捏造しない。
  - 限界: same-host local/dev-signerの技術handoff。実配置・public/production PKI・
    全M2/M3/M7・独立監査・公開判断は対応する未完了行に保持する。M4はE152の範囲で完了。
  - 次: D04/D07/D08の実際の配置・操作・公開判断へ、この固定artifact/手順を引き継ぐ。

- [x] **D01: Native起動・操作の技術統合を確定する**
  - 対象: 検証。author → 独立inspection → 4つの独立store → authenticated TLS →
    compiled CLI → restart・exact replay・refusalを実行する。
  - 状態: c69のE5/E6と実際のcompiled local TLS startup/recurrenceで技術統合を確定。
    公開テストネット稼働・実validator独立運用の宣言ではない。

- [ ] **D02: 最終機能・権限範囲を独立監査する**
  - 対象: 検証。economics/FastVote、generic contracts、ingress、lifecycleを対象にし、
    指摘を修正して独立に再検証する。tech-lead approvalと監査は別。
  - 状態: 最終範囲の監査は未完了。
  - 次: M1と同一head/scopeの監査を共用する。先の狭い監査を全体監査へ拡大解釈しない。

- [x] **D03: locked Rust・npm・build toolingのadvisoryを処理する**
  - 対象: 実装 + 検証。実際の使用・露出・修正版の互換性を確認し、対応または
    残余リスクを記録する。MSRV/licenseも保持する。7 high entriesは7独立advisoriesとは限らない。
  - 状態: 元Delivery 4 #3のlocked advisory review・実際の使用/修正版実体・互換性の
    確認は50a4で完了。E14/E15/E16と全7 owners + checkのterminal successを照合した。
    再開時のf655 lockのnpm auditは7 high entries。別候補 `05ddad13` ではVitest plugin 1.4.0 /
    Wrangler 4.149.0 / peerと一致するworkers-types 5.20261006.1、および互換範囲の
    brace-expansion/source-map-jsを固定し、npm auditは0件。literal npm-ciとCloudflare
    owning gate (13 + 28 + 10 + 15 workerd tests、型/lint/WASM/native oracle) が成功し、
    `70d0109a` / `5ceb4d22` として今回のブランチへ統合済み。
    初回peer不一致・生成型hash不一致の失敗は保存し、force/legacy-peer-depsや
    型check省略は使っていない。生成宣言は実際の新Wranglerで更新した。
    Rustlsは既存PR #298と同じ0.23.45の限定pinを `5df02926` に適用。
    [maintainer advisory](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc)
    とchecksumを照合済み。shared依存を含む14fbのcomplete PGはE10、requiredはE11。
    5672/50a4にも同じlockを保持し、50a4を対象にしたfresh point-in-time npm auditは0件、
    Cargo.lockの全311 registry versionsをOSVで照会し
    0 matchesを確認。同じ手法の旧npm lock正対照は7 high、旧Rustls 0.23.43は既知advisoryを
    検出した。対象npm packageはadapterのdev/tooling依存で、Worker/shared/build scriptの
    18 text filesに対象moduleの直接literal importはなかった。この限定確認を全露出の
    不在証明にはしない。RustlsはNative/SDK/PG TLSで使用する依存として修正版へ固定した。
    変更npm lock全69 entriesで既存declared licenseに変更なし、新規package追加なし。
    実loaded sharp 0.35.5 / libvips 8.18.7 / librsvg 2.63.2も修正版実体と照合した。
    advisory metadataの照会でありcode監査ではない。dependency metadataも実fileで照合した。Rustlsの
    declared MSRV 1.71 / license Apache-2.0 OR ISC OR MITは0.23.43→0.23.45で同じ。
    workspaceにrust-version指定はなく、検証は固定1.97.1 / Node 22.20.0で実行した。
    declared MSRVとtested toolchainは別の事実であり、低いMSRVのbuild matrixや独立legal
    clearanceを実施したとは扱わない。原条件にないmatrixを新しい完了gateにはしない。
    forced bulk updateを使わず、独立correctness reviewの条件だったlocal required/hosted
    終端成功も確認した。
  - 範囲: 今回のlocked入力と照会時点のadvisory review。独立security監査はD02/M1、
    公開前の実露出/選択profileと新しいadvisoryの確認はD04/M8に残る。

- [x] **D05: exposed ingress/operationsのコードを検証する**
  - 対象: 実装 + 検証。全accepted familyのauth/TLS・rotation、request/retry/work bounds、
    liveness、secret-free logs/alerts・spend controlsを確認し、未対応familyは閉じる。
  - 状態: E71/E73で選択済みloopback Native + closed certified relayの技術範囲を完了。
    accepted familyと閉じるfamily、auth/TLS・rotation、bounds/liveness/observations/spendの
    共通case表をM5下へ対応付け、実装・実fixture・完全required/CIを照合した。
  - 範囲: 受入pinは `9de634a7`。b4まで対象コード/gate入力は不変。E72はb4のCIであり、
    b4のlocal完全requiredへ付け替えない。本番PKI・SLO・topologyの適用はD04/D07に残る。

- [ ] **M1: 固定したreleaseの独立security/release reviewを終える**
  - 対象: 検証。code/deployment仕様、contracts、economics、handoff/activation、
    ingress、storage、signingの最終範囲と指摘・修正・残余リスクを固定する。
  - 状態: 先の狭いscanは最終c69・署名試作を監査した結果ではない。
  - 次: D02/R4と範囲を揃える。provider-stoppedの過去タスクは再試行・迂回しない。
    SECURITY policyの未承認変更も行わない。実配置の確認はD04/D07/M8に残す。

- [ ] **M2: protected signerと操作内容レビューを実装・検証する**
  - 対象: 実装 + 検証。protected key backend、operator/authority分離、
    exact operation-specific content、refusal/failure、recovery/rotation/revocation。
    automatic protocol signingと人のasset/governance approvalは区別する。
  - 現状: publicationとStandard Asset各family、positive Split、original ordered、
    certified FastVoteの選択済みcomponentは下記の個別証拠へ対応する。
    `50fbf22d` のStandard Asset/publication fixture全117はE156で成功。
    同sourceのoriginal ordered/certified別UID・TLS fixtureもE166で成功。
    f51はE182の4 RELEASE CLI profiles、E187の元12 runtime、E189の全8CI、
    E191のlocal完全requiredまで成功。現行8daはE213の完全required・E218の全8CI、
    E215のNative13 A/B・E219のpublication-genesis RELEASE・E222の元12 runtimeで照合した。
    ZeroShare専用WIPは未統合・未検証で、
    各familyの残るlifecycle/全体対応をそろえるまでM2全体は未完了。
    実鍵ceremonyの公開条件と区別する。
  - 初期履歴: publication-only Linux試作の回収可否が不明。E4はSDK部分だけの成功。
    新しい[publication metadata preview](docs/architecture/publication-review.md) と
    CLI `contract preview` は実装し、独立指摘を処理してsource approval済み。
    SDKの8 owning controls、compiled CLIの7 controlsが成功。診断hashとartifact
    identityを区別し、実approvalやprotected key backendの合格には数えない。
    人は再開中に「ローカルOSを信頼し、鍵を別プロセス・別権限で保護」を選択済み。
    publication専用の[local OS custody](docs/architecture/local-publication-custody.md) は
    今回のブランチへ統合し、独立reviewとE9の実UID/PTY/refusal/restartを確認済み。
    `preview --artifact-out` が独立した承認preimageの作成を支える。
    publication-onlyの[取消・鍵復旧/交換](docs/architecture/publication-custody-lifecycle.md) を
    E21で検証し、M2 sourceの完全required/CIはE22で成功。real keys・host users/servicesは
    作成していない。他family/automatic protocol signingと各lifecycleは未完了。
  - [x] publication承認取消: 同一serve/restart/古いapproval復元後の拒否と並行sync失敗を検証。
  - [x] publication鍵復旧: serve停止後に同一鍵を新pathへ復旧し、取消を保持して署名一致を検証。
  - [x] publication鍵交換: 新鍵/設定/独立approvalと旧新の取り違え拒否を検証。
  - [x] [fee-claimの非承認表示・保存内容の開発用署名](docs/architecture/fee-claim-review.md):
    seed-free canonical exportとoffline review/signをE23/E24で検証し、local完全gate・同一treeの
    hosted CIを完了。実Split/ZeroShareの候補byte一致とCLI拒否、FinalTransferのstructural
    rendererを確認。protected fee-claim approval/backend・操作意味の承認は未完了。
  - [ ] ZeroShare専用custody WIP: E54の別branch/local commitに未検証コードを保全。
    fixture作成がprovider-stoppedのため再試行・迂回しない。現在のbranchへは統合せず、
    compile/owning/full/CIの完了や実装済みcomponentに数えない。
  - [x] [genesis Standard Asset transferの専用custody component](docs/architecture/standard-asset-transfer-custody.md):
    独立genesis/code/instance/policy pin、完全object preimageからの金額/参照検証、
    exact approval・別UID署名・既存transfer CLIを接続。426eのE25-E27とE38/E36で
    owning・RELEASE CLI・完全required/同tree CIを確認。後続common trust統合は
    E34/E35の対象証拠として分け、最終source gate/全M2は未完了に保つ。
    他operation/epoch/自動署名の合格へ転用しない。
  - [x] [genesis Standard Asset split/mergeの専用custody component](docs/architecture/standard-asset-split-merge-custody.md):
    E33の実CLI/別UID/PTYで自分宛ての分割→結合、完全内容とframe、金額・消費入力・実receipt/replay・
    取消と再起動を検証。他者宛てはprepare/approval controls、overflowは純粋なpreparationで確認。
    splitは他者への部分送金も許すが、この実CLI round tripの相手は自分だけ。
    publication kind1/transfer kind2は閉じたまま維持し、mint/burn/create-assetは対象外。
    各family全lifecycle・自動署名・最終sourceの完全gate/CIは引き続き未完了。
  - [x] [genesis Standard Asset mint/burnの専用custody component](docs/architecture/standard-asset-mint-burn-custody.md):
    E41でTreasuryCap ownerのmint→whole-Coin burnと完全内容/期限/frame承認、実CLI/別UID/PTY・
    非空dedup応答・再送・取消/restart拒否を確認。供給量は参照preimage版から独立検証し、
    live currentnessは実行で確認する。新familyの鍵復旧/交換・自動署名・create-asset・
    全M2と最終sourceの完全gate/CI/Native releaseは未完了。
  - [x] [Standard Asset create-assetの専用custody component](docs/architecture/standard-asset-create-asset-custody.md):
    E49で別UIDの操作内容承認・署名・実CLI送信とnew instance、独立型IDのDefinition/TreasuryCap・
    供給量0・非空receipt/再送・取消/restart拒否を確認。承認後のseed/nonce/max_fee変更を拒否する。
    feeはgenesis context、applicationは独立導出したnew instanceであり、seedの事前freshnessや
    作成IDの事前予測は主張しない。作成assetのmint/burnはE62、transfer/split/mergeはE75で確認。
    新familyの残る鍵復旧/交換・
    最終source完全gate/CI/Native releaseと全M2は未完了。
  - [x] [mint/burnの任意application asset pin](docs/architecture/decisions/0258-mint-burn-application-asset-pin.md):
    E62でgenesis feeと独立local application pinを分け、作成assetの実mint/burnを確認。
    型・context/code/creator・alias・異なるinstance/旧genesis承認の流用拒否、
    全163 custody unit/19 Standard Asset testsと実UID/PTY/CLI・再送・取消/restartを検証。
    公開instance参照のprivate設定への移行はfile ownerが行い、後処理のsignalも同じUIDで送る。
    Node/Rust sourceと入力ELF不変・専有container/volume解放を親で再照合した。
    同じtrusted OSのown-created profileで、現在性やassetとinstanceの起源をfetch証明しない。
    9de6の13-target Native A/Bと実RELEASE CLIはE64で成功。
    同profileの停止後鍵復旧はE67で確認。
    作成assetのtransfer/split/mergeはE74/E75で追加検証。他profileの鍵復旧・所有権移行を含む鍵交換、automatic protocol signingと
    最終source完全required/CI・原12 RELEASE runtime・全M2は未完了。
  - [x] [own-created mint/burnの停止後鍵復旧と5 profilesの鍵交換時拒否](docs/architecture/publication-custody-lifecycle.md#asset-family-fixture-coverage):
    E67で元鍵のsignerを停止してから復旧し、同じ新規承認frameでのreference署名一致、
    復旧前の取消・新規取消・restart後の両拒否を実CLI/別UID/PTYで検証。
    新publisherで旧Coin/Cap/fee/creatorを拒否し、出力が作られないことも確認。
    元5 families/6 lifecycleと全件数を維持。正の所有権移行、他profileのlive鍵復旧/交換、
    automatic protocol signingと全M2・最終source全体gateは未完了。
  - [x] [genesis transferの停止後同一鍵historical復旧](docs/architecture/publication-custody-lifecycle.md#asset-family-fixture-coverage):
    E140のT実行でfresh77の元鍵referenceと復旧署名一致、旧75/新77取消・restart拒否を確認。
    E139の同source W RELEASE CLIでも保持した。追加のtransfer提出/currentnessは主張しない。
  - [x] [genesis split/mergeの停止後同一鍵historical復旧](docs/architecture/publication-custody-lifecycle.md#asset-family-fixture-coverage):
    E140のG実行とE139でfresh9b/9cのsame-frame署名一致・旧91/92と新要求の取消/restart拒否を確認。
    merge preimageは元91後の保持物。新9b/9cのbusiness提出・live所有権移行は含めない。
  - [x] [create-assetの停止後同一鍵historical復旧](docs/architecture/standard-asset-create-asset-custody.md):
    E141でfresh9dの元鍵referenceを実停止/wait/PID/socket不在にしてから既存UID-copyで復旧。
    同frame署名一致と旧95/新9d取消・restart拒否、元T/G/E67/Coinを保持。新Instantiateは提出しない。
  - [x] [genesis mint/burnの停止後同一鍵historical復旧](docs/architecture/standard-asset-mint-burn-custody.md):
    E141でfresh9e/9fのsame-frame元鍵/復旧署名と旧93/94・新9e/9f取消/restart拒否を確認。
    burn入力は元93後の保持preimage。25 normalchildren/14 files/8 absent refusalsを元cap内で照合。
    E41/E49等の未達記述は当時の履歴であり、今回閉じた範囲は同一鍵historical signing-onlyだけ。
    鍵交換時の正の所有権移行、live currentness、automatic signing、実鍵ceremony・全M2は未完了。
  - [x] [genesis Coinの別identity間live所有権移行](docs/architecture/standard-asset-transfer-custody.md#two-owner-genesis-coin-identity-handoff-control):
    E149で同じlive SQLite/WASM store上の同Coinを既存A→B→Aへ実CLIで移行。
    fee Coinは別prefunded入力、version2/3・nonce1,0→1,1・paid effects/receiptと全保存済み再送を確認。
    両UID/PTY承認、Bの所有前/Aの譲渡後拒否、A停止/wait後のB開始、両取消/restart拒否も成功。
    新key/copyは追加せず、application creatorは不変。他familyや全M2は未完了。
  - [x] [genesis Coinの他者宛て部分分割と受取Coin返送 component](docs/architecture/standard-asset-split-merge-custody.md):
    E174でAの10MをA残5MとB受取5Mへ分割し、同じ受取CoinをBからAへ返送。
    別UID/PTYの完全内容承認・exact frame・paid effects/nonce/receipt・全保存再送、誤owner拒否、
    A停止後B開始・両取消/restart拒否を確認。元117と新21は同じ制限の別実行で成功した。
    全M2、application creator/TreasuryCap・account/fee所有権の移行、実鍵ceremonyは含めない。
    同c680の完全requiredはE183、全8 hosted CIの実ログ・checkout照合はE184で成功。先のcombined上限失敗E172/E173と既存PTY集計漏れは保持する。
  - [x] [own-created application Coinのtransfer/split/merge custody](docs/architecture/standard-asset-application-coin-custody.md):
    E74/E75で独立application pinとgenesis feeを分け、実別UID/PTYの6操作と正確な
    type/owner/version/amount/receipt/nonce・全保存済み再送・取消/restartを検証。
    自己宛whole transferの拒否は保持し、最後の送金先は別のdisposable recipient。
    内容承認・署名・実CLIで同じframeを使う。全M2と最終source全体gateは未完了。
  - [x] [own-created application Coin kind2の同一鍵historical recovery component](docs/architecture/standard-asset-application-coin-custody.md):
    E177で停止/wait後に別UIDで保管・復元し、同じframeの署名一致、旧/新取消の維持とrestart拒否、
    完全PTY review・retained preimages不変・新復元鍵のoperator読取拒否を実証。strict setupの
    10 PTYと既存create復旧/新transferの端末表示を二重計上せず全出力上限へ加算した。
    kind3は別E180、default既存集計は別E179で確認。currentness・鍵交換・全M2は含めない。
    exact7663のliteral npm ci +完全requiredはE185、全8 hosted CI照合はE186で成功。後続f51へ転用しない。
  - [x] [own-created application Coin kind3のsplit/merge同一鍵historical recovery component](docs/architecture/standard-asset-application-coin-custody.md):
    E180のf51でretained nonce4/5を使い、新a7/a8承認の完全review・同frame署名一致、
    reference停止/wait後の別UID鍵復元、旧a1/a2と新承認の取消維持/restart拒否を実証。
    fresh inventoryと独立core/split/kind2/kind3 profileも成功し、元117判定を保持。
    再提出・live currentness・正の権限移行・全M2とD完全required/CIは含めない。
  - [x] [完了PTY出力の一元集計と独立profile component](docs/architecture/standard-asset-application-coin-custody.md):
    E179のd012で共有helperの加算を1回に統一し、明示core70/application setup47の別実行で
    旧117の全path/value mapを保持。split21も別実行で成功し、各出力capを満たした。
    旧一括の実上限失敗E178を保存し、manual/no-arg shapeをcoreへ明示的に移行した。
    完全required/CI・最終source・全M2/M7の完了や旧discarded bytes再構成には拡張しない。
  - [x] [original ordered protocolの別process/UID worker](docs/architecture/local-protocol-custody.md):
    元のverified startup・ordered router・confirmed retentionをworkerだけが所有し、
    frontendは鍵/DB/fenceを持たない。E82のfunctional controlsと独立source reviewは成功。
    別UID・TLS・停止/restart/replay fixtureを実装。E84で5 ELFのbuild/strict Clippyと
    全入力inventoryは成功したが、初回runtimeは準備時のEPERMで失敗。所有権移譲前に
    権限を設定し、E87の次attemptで準備probeは成功したが実authorのEACCESで失敗。
    public routing ancestorsだけを0755へ合わせ、private leaves/拒否controlsは保持。
    E89の次attemptはログ配分超過で失敗し、完全inner rawがないためproduct成功0。
    E90で上限・oracle・拒否controlsを維持した完全ログtransportを実装し、
    実Node24の16 codec controlsを確認。E91で修正後の実4-worker/4-frontend TLS owningが
    actual0/両EOF/wait。全76 role childrenを回収し、署名・不正UID拒否・停止中503・
    再起動fence3/保存済み再送・QC・新規height2を検証。完全rawと専有資源の不在を照合。
    後継epoch・FastVote/readiness・他signing family・全M2へ転用しない。
  - [x] [positive Standard Asset fee-claim Splitの操作内容policyとprepare consumers](docs/architecture/positive-fee-claim-split-policy.md):
    E96/E99で実genuine後継authority・保存host request/intentと、元oracleとの署名対象byte一致を確認。
    E104で追加UID fixtureを含む現componentのCLI406件とstrict gatesが成功。
    immutableな意味の確認であり、現在のescrow残高・nonce・entitlementの保証にはしない。
  - [x] [certified FastVote protected workerの通常component](docs/architecture/certified-fastvote-protocol-custody.md):
    E100のnative245件/operator159件とstrict gatesを確認。鍵・DB・独立anchor/fenceはworkerだけが持ち、
    frontendはclosed contractと既存coreのauthority/confirmed retentionを保持する。
  - [x] [genuine positive Splitの別UID・PTY lifecycle](docs/architecture/positive-fee-split-uid-fixture.md):
    E125の全CLI406件・export回帰4件/strict gatesの後、E128で元genuine selector内の
    Leg/Claim両phase承認・署名・取消・鍵復旧・再起動・expiryと実protected candidate提出が成功。
    全97/22操作・9socket controls・完全証拠と回収を照合。既知fixture鍵の選択範囲であり、
    本番鍵秘匿・最終統合head全体gate・全M2の完了にはしない。旧4失敗は保持する。
  - [x] [certified FastVoteの実別UID・TLS lifecycle](docs/architecture/local-certified-protocol-custody-fixture.md):
    E127のstrict producer後、E129で実署名・保存済み再送・停止中拒否・fence6 restart・
    frontier/progress/union3と全source/body/anchor imageのread-only SQL oracleが成功。
    全39 controls・147 roles・27 probes・32 oracle exchangesと完全証拠/回収を照合。
    E108/E111/E115/E119/E124の失敗は保持し、最終統合head全体gate・全M2とは分ける。
  - [x] original ordered workerの停止後同一identity鍵復旧:
    既存M2のrecovery条件を細分化する。全4 worker停止/wait後にworker UIDだけで
    別のprivate pathへ既知fixture鍵を復旧し、元pathを使えない状態にする。
    source/body/独立anchorを保持し、保存vote一致と元のfresh empty height2 roundを確認する。
    正の鍵交換・有料business・off-host復元・全M2の証拠にはしない。実runtimeはE194で成功。
    同sourceCIはE198、c1の完全requiredはE199で成功。全M2は未完了。
  - [x] certified FastVote workerの停止後同一identity鍵復旧:
    同じ既存recovery条件。復旧pathをcertified/後段ordered両worker configへ接続し、
    元のvote/ACK再送、fresh paid B、frontier署名、fence6 retentionを維持する。
    operatorからの新key読取拒否と旧path不使用もE194で成功。同sourceCIはE198、c1の完全requiredはE199で成功。全M2は未完了。
  - [x] 復旧した同一鍵によるgenesis Coinのlive送金:
    元M2のrecovery条件を細分化。既存の停止後復旧pathをgenesis A→B→AのA signerと
    取消後restartへ渡し、完全review/frame・実送信・各時点のowner/fee/nonce/receiptを確認する。
    旧historical signing-only controlと全既存上限/判定を保持し、鍵交換や全M2へ拡張しない。
    E203でc535の実runtime成功。最終local完全requiredはE204、同sourceCIはE205で終端照合済み。
  - [x] 復旧した同一鍵によるgenesis split/mergeのlive操作:
    元M2のrecovery条件の続き。既存の同一A鍵を別pathへ復旧してから、既存self split/mergeと
    取消後restartに接続する。歴史preimageのsigning-only復旧と元の全操作/判定/上限を保持する。
    新identity・authority・profileを追加せず、実runtimeと最終source完全required/CIで確認する。
    E206の実runtime、E208の全8 CI、E209の新固定profileでのlocal完全requiredを同b389で照合済み。
    E207の固定tool postcheck失敗は保全。元の全条件を維持し、この子条件だけを完了する。
  - [x] 復旧した同一鍵によるgenesis mint/burnのlive操作:
    元M2のfamily別recovery条件の続き。既存publication recoveryで停止後に復旧した同一A鍵を、
    既存のlive mint・whole-Coin burnと取消後restartへ接続する。9e/9fのhistorical signing-only
    controlsと元の全操作/判定/上限を保持し、新operation・identity・authority・profileを追加しない。
    source `8da1d620` / tree `b60b28e8` をcommit/push済み。E211のsyntax/AST/transport照合は成功、
    実UID/PTY fixtureはE212、同source完全requiredはE213、全8 CIはE218でroot照合済み。
    E215のNative13 A/B、E219のRELEASE publication fixture、E220の元protocol補足も成功。
    元12 RELEASE runtimeはE221のcheck/probe後、E222で全12ケース・101 passed/0 failedを照合した。
    記録側の143と集計順序誤り・未観測区間を保存し、この子条件だけを閉じる。親M2は未完了。
  - 検証の残件: E175/E178の旧default集計漏れは、d012の完了PTY共有加算と
    明示core/application別allocationで修正し、E179で元117の全path/value mapと上限を実証。
    旧一括267,120Bの失敗を保持し、未保存の過去出力や単一117成功へは拡張しない。
    kind2同一鍵復旧はE177/E179、kind3のsplit/merge復旧はE180で実証済み。
    E182では同f51の新Native8 RELEASE CLIを使い、fresh inventoryと4独立profileを再確認。
    production CLIの旧50fb source例外は使わず、H10の4-file nonRust bridgeだけを保持した。
    異なる受取人のapplication往復は現契約のcreator==publisher制約を変える別設計となる。
    現行f51の完全required/CI・releaseはE191/E189/E181/E182/E187で成功。
    各familyの残件は解消しておらず、全M2は未完了。
  - 次: 各familyの残るlifecycleとaccepted signing family全体の対応を埋める。
    既存のpositive Split/original ordered/certified FastVote componentと未統合ZeroShareを
    区別し、provider-stoppedのWIPを再試行・迂回しない。automatic protocol signingは
    固有のauthority条件を保持する。
    全accepted signing familyの範囲を明示し、publicationのみで全体を閉じない。
    実鍵・実administrator/recovery役割とceremonyはD04/D06/D07へ残す。Ledgerは別途deferred。

- [ ] **M3: selected SQLite profileのdurabilityを検証する**
  - 対象: 検証。atomic object/state/nonce/receipt/outbox、indexed delivery、
    full-read revision/ABA、reopen・fencing・ambiguity reconciliationと実際のfault boundaries。
  - 状態: c69のENOSPC/blob controlsとE3は以前の合格。f093は今回の作業ブランチへ
    `3a5c8249` として統合済み。新しいowningとSQLite libはE7で成功。
    ignoredの5 ENOSPC controlsはE8で新しく成功。combined requiredの状態はE14。
    host/power/media/fsync・実writer failover/TLS rotationの条件は未完了。
    追加の同一file上の旧host生存中・新generation起動controlsはcomponentで成功。
    旧read/CASの具体的WriterFenced、旧HTTPの汎用503、新hostの保存済み再送と返金coinの
    新規送金・両quorum・全business snapshot不変を確認。offline確認flagを意図的に
    重ねる拒否境界の検証で、正規live handoff手順・別host復元・物理faultの合格にはしない。
    現行f51の完全required/CIはE191/E189で成功。個別fault profileの未達条件とは分ける。
  - [x] exact50fbの既存ENOSPC 5 cases: E169で新規所有実行・全5 actual successを確認。
    元の12 SQL/4 portable/positive blob・receipt-first/不確定COMMITを省略していない。
    他selected-profile faultや後続sourceの全体資格はこのチェックへ含めない。
  - [x] 正常停止・TLS trust交代後の新規business: E30の実CLI/4 replicasで確認。
    保存済み再送に加え、新規nonce/返金Coinを使った取引の確定と新旧receipt保存を検証。
    同sourceの完全gate/CIはE45/E39で成功。残るM3条件は未完了として保持する。
  - [x] 実TLSのdurable apply後ACK喪失と同一要求の再送:
    元M3のTLS failure条件を細分化する。全4実Native hostの正常な保存/応答を受けた後、
    TLS clientへ応答bodyを渡す前にtest-private relayだけで切断する。
    実CLIの未確認失敗、全replicaの対象receipt、保存intent/certificatesを確認し、
    同じ要求の再送で12 SQL/2 blob tables・4 portable collections・nonce/paid effectsが
    二重更新されないことをE193で検証した。同sourceCIはE198、c1の完全requiredはE199で成功。
    参照blob closureは空でpositive_blob_fault=false。VM/partial WAL障害・全M3の証拠へ拡張しない。
  - [x] 参照付きhistorical bodyを含むTLS ACK喪失と同一再送:
    元M3のpositive blob/oracle条件を細分化。既存DR-0265の独立に固定した70KiB historical
    objectをtyped Create/receiptと共に準備し、4 replicasの完全SQL/portable/bodyと実TLS queryを確認する。
    空closureの元caseを保持。paid-produced blob publicationやpositive_blob_faultの合格にはしない。
    E203でc535の新旧実runtime成功。最終local完全requiredはE204、同sourceCIはE205で終端照合済み。
  - [x] 参照body付きACK喪失後の正常再起動と同一要求の再送:
    元M3のreopen・ambiguity reconciliation条件の続き。全4 replicaのdurable receipt確認後に
    hostを正常停止/waitし、同じstore・既存の次generation・同じTLS入力で再起動する。
    保存artifact/receipt・historical70KiB bodyと完全business oracleを再送前後で確認し、
    既存の空closure/同generation caseを保持する。physical/partial-write faultには数えない。
    E206の実runtime、E208の全8 CI、E209の新固定profileでのlocal完全requiredを同b389で照合済み。
    E207の固定tool postcheck失敗は保全。元の全条件を維持し、この子条件だけを完了する。
  - [x] [全connection喪失後の正規local writer交代](docs/architecture/decisions/0260-complete-owner-loss-local-writer-failover.md):
    retained-handleの元SIGKILL controlを保持し、全4 sole-ownerをSIGKILL/reapしてから
    次generationを起動する別controlを追加。全12 SQL tables・2 blob tablesと4 portable
    collections/参照bodyの保存済み再送不変、新規有料取引/両quorum/nonce/receiptを検証する。
    E74の実compiled TLSで成功。独立anchorを使用する追加variantも成功。
    このsourceの最終完全gate/CIは未完了。
    host/power/media/fsync・別host/実topology failoverの証拠へ読み替えない。
  - [x] [ordinary SQLiteの仮想power/block-I/O fault component](docs/architecture/native-sqlite-virtual-fault-profile.md):
    E77の失敗を保持し、E79で実guest電源断2種・write-only EIO・flush-only EIOと
    全cold復旧を検証。既存schema/v6・user_version5の通常profileだけを対象とする。
    独立anchor付きprofile、物理hardwareや最終headの全体qualificationへ借用しない。
  - [ ] [独立anchor付きprofileの実guest fault boundaries](docs/architecture/decisions/0266-independent-anchor-virtual-fault-profile.md):
    ACK後・Pending後/source COMMIT前・source COMMIT後/finalize前のguest電源断と、
    source/prepare/finalize各COMMITの実write/flush EIOの計9境界を実装し、source review済み。
    Pendingと旧sourceの不一致は既存契約どおり安全停止し、完全new sourceとPendingが
    一致する場合だけ既存factoryで照合・確定してfresh fence/new workへ進む。
    通常profileのE79を流用せず、全12+2+authority tablesとpositive bodiesを検証する。
    E86でSQLite library全120件・strict Clippyは成功したが、実guestは初期化時に失敗し、
    product control成功0。boot修正taskもprovider safetyで停止したため再試行・迂回しない。
    source/raw/imagesを保持し、9 boundariesの実guest owningは未達として残す。
  - [ ] selected virtual deviceのpartial persistent write:
    元のgeneric torn-write条件を保持。実WAL extent・対象sector・混在した保存bytesと
    cold receipt-first none/allを対応付ける。単なるEIOやtransfer上限だけで完了にしない。
    追加source assessmentは2026-10-17にprovider safetyで停止。再試行・迂回せず、
    supporting mechanism2の準備sourceも未実行で保持する。
    exact50fbのENOSPCはE169、通常conformance/TLS/完全required/CIはE156/E164/E167/E168で
    照合済み。停止済みの当該partial persistent write条件と全M3は未完了。
  - E210の[通常SQLite coverage記録](docs/development/validation/2026-10-22-m3-ordinary-coverage/README.md)で、
    全12 SQL tables・2 blob tables・4 portable collections・positive historical bodyと通常reopen/fencingを
    b389のsource/実結果へ対応付けた。表の非空やphysical faultを主張せず、追加の通常assertion不足は
    特定されていない。この対応表だけを理由とするruntime再実行や親M3の完了は行わない。
  - 次: 統合したf093の新しいowning結果と、残るselected-profile coverageを対応表で埋める。
    trait reply-loss、process SIGKILL、power/host/media/fsync faultは別証拠。
    全12 SQL tables・4 portable collections・positive blob/oracleを省略しない。
    selected-profileのhost/power/storage faults、ENOSPC/resource exhaustion、
    real writer failover、TLS failure/rotationは、このCODE/VERIFY行の完了条件に残す。
    D07の実topology運用rehearsalは代替・延期理由にならない。一つの合格で全M3を閉じない。

- [x] **M4: checkpoint・暗号化バックアップ・復元コードを検証する**
  - 対象: 実装 + 検証。checkpoint/state-root・immutable body manifests、
    完全history/receipt/blob restore、fresh fencing、migration/upgrade・safe rollback/stop。
  - 状態: `5f6b1819` / tree`468c7be5` の選択済みNative+SQLite/trusted-local-OS
    コード・検証範囲を完了。独立current anchorと暗号化complete-store continuation、
    history/receipt/blob・fresh fence・実prior release upgrade/旧版停止/新規有料取引を確認。
    最終sourceのfresh13-target A/BはE137、M4対象RELEASE TLS/upgradeとCLIはE139、
    literal npm ci +完全requiredはE150、同treeの全8 hosted CIはE152で成功した。
    原条件の69-path source対応と通常の独立correctness reviewを照合し、
    完了receipt`m4-final-5f6b-selected-code-verify-completion-1017.json` (`888abf02`)に記録。
    E133の自然失敗・原因未確定と当時source-onlyのE134/E135は履歴として保持する。
    元8リンク/e8の2 withdrawals/delay7/35 rolesは完全required/CIの両方で維持した。
    原12 RELEASE runtimeの総合qualificationはM7の別gateで、E151にも成功を記録。
    後続Rustls更新の新source完全gate/PG・全M7・独立security監査・実オフホスト運用と
    実鍵retention/DR・公開判断をこのチェックで完了にはしない。
  - [x] [独立に保持したordered history floor component](docs/architecture/decisions/0248-import-ordered-history-freshness-floor.md):
    実import create/resumeへの追加拒否を実装。parse/comparison 12件・元9件を保持したcompiled import全10件・Clippy・
    独立component reviewは成功。E29で同sourceのRELEASE child import全10件も成功。
    E53の同tree CIと元long caseでgenuine successorの拒否/受理/resumeも確認した。
    同sourceのローカル完全gateはE63で成功。原12 Native runtimeはE57の時間上限失敗。
    同一epoch内の履歴位置だけを拘束し、published checkpoint/state-root・owned fast-pathの
    whole-store rollback検出・旧writer除外の未達条件は維持する。
  - [x] [独立closure identityの追加拒否component](docs/architecture/decisions/0252-import-closure-identity-pins.md):
    E37で既存のcut/package/plan digest pinを実import create/resumeへ接続し、正しい復元、
    3種の単一digest不一致、partial/malformed parse、resume時のDB bytes・binding/token不変を検証。
    guard欠落の負対照も検出した。信頼するローカル入力によるexact closureの追加拒否であり、
    公開checkpoint/state-root・latest-state・全owned fast-path rollbackやactivation権限は追加しない。
    同sourceのCIとローカル完全requiredはE53/E63で成功し、原12 Native runtimeはE57の失敗として保持する。
  - 後継epochのhistory floorはE37で実genuine successor importの既存loopへ追加し、
    元long caseを変えずにE53のactual CI終端成功を確認した。
  - [x] [trusted local OSの独立checkpoint anchor component](docs/architecture/local-checkpoint-anchor.md):
    E76で独立authorityのPending/acknowledged根と閉じたimmutable body manifest、
    stale rollback拒否・lease・current clone交代を検証。E74ではcompiled hostで明示的に
    inspect/enroll/checkpointし、4-host TLSの全owner喪失後にも有料取引を継続した。
    旧保存済み再送ではauthority不変、新規取引ではACK更新を確認。
    complete encrypted backup/restoreと実prior release upgrade/safe stopはE83で検証。
    最終5f sourceの全体qualificationは親M4のE137/E139/E150/E152を参照する。
  - [x] [独立current anchorと照合する暗号化full-store continuation](docs/architecture/local-checkpoint-backup.md):
    v1のproof archiveを保持したままlocal v2形式を実装し、独立source reviewを完了。
    初回owningはE78の2 failures。readonly snapshot副作用とfixture ownerを修正し、
    E80のNative119/age5は成功。E81のfixture検査順を修正し、E83の実4 pack/open・
    旧source不在・4-host fresh fence/新規有料businessと再送まで成功。
    protocol-version activation/migrationと実off-host運用の合格には転用しない。
  - [x] [実prior RELEASEから独立anchor profileへのsoftware/storage upgrade](docs/architecture/decisions/0265-stopped-native-storage-profile-upgrade.md):
    既存15 TLS selectorsを保持し、明示的な9de6 RELEASE ELFを要求するignored16件目を追加。
    実旧4-host paid/quorum/historyとpositive blobを基準に、停止・root-pinned enrollment、
    schema identityだけの変更とuser_version5維持、旧binaryのschema拒否・全停止bytes不変、
    現行fence3・保存済み再送・新しい有料取引とtail stopをE83で検証。
    旧manifestの`fixturePassed=false`は旧ELFのprovenanceだけに使用し、この実行とは分ける。
  - 維持する境界: source/artifact対応と独立current anchorに照合する復元・upgradeを保持する。
    別namespaceを区別するnonceだけではbyte cloneやepoch内の古いowned状態を検出できない。
    このため独立した最新性anchorを使用する。M7の残るrelease qualificationは別行で継続する。
    元の8リンク・e8 withdrawals・35 rolesと全拒否controlsを維持する。
    age等のshared PG feature edgeはE10の14fb全5グループで再検証済み。
    実オフホスト保管・実鍵retention・DR運用はD04/D06/D07へ残す。
    exact restoreをblanket raw-state equalityやcross-file atomicityとは呼ばない。

- [x] **M5: Native ingress/operationsの未達コード・検証を埋める**
  - 対象: 実装 + 検証。D05に加え、backpressure/request/work/capacity policy、
    monitoring/incident/validator運用を再現可能なコード・手順へ結び付ける。
  - 状態: E71/E73で選択済みlocal Native/closed relayの実装・検証を完了。
    元M5の実運用readinessはD04/D07/M8の公開条件が残る。
    追加のstop cancellationは共有admitted/structured-event/query dispatcherのjob開始前とSQLite hostの既存
    pre-storage checksを接続。待機中workの拒否・既実行workの完走・drain/拒否優先順位を
    component検証とE44/E50の実factory/SIGTERM oracle、E71の完全gateを対応付けた。
    admitted counterには待機後の取消も含み、業務実行件数とは解釈しない。
  - [x] [scheduler recoveryとordered contextの停止確認 component](docs/architecture/decisions/0247-native-stop-before-storage-continuation.md):
    既存型のAdmissionClosedとstorage直前のcooperative checkを追加。actual recovery APIの欠落guard
    negative controlとNative HTTP 206件/Clippy・独立component reviewは成功。
    手動構成の実SQLite/HTTP ownerも全3件成功。同sourceの完全gate/CIはE42/E39で成功し、
    このfixtureを本番host constructor/signalの配線証明に数えない。
  - [x] [後継hostの権限解決直前の停止確認](docs/architecture/decisions/0250-successor-operation-context-stop-check.md):
    E31で既存executorから直接再確認し、read/mutation・旧error優先順位・欠落guardの負対照を検証。
    初期admission確認だけでは観測できない遅いstopを拒否。全体qualificationはE71/E73で別に照合した。
  - [x] [signerless履歴hostのpolicy解決前の停止確認](docs/architecture/decisions/0251-successor-historical-read-stop-check.md):
    E32で別compositionのread ownerも検証。停止hookはadmission後に入り、未開始policyを0回、
    open対照では1回呼ぶことと、error優先順位・欠落guardの負対照を確認した。
  - [x] [compiled SQLite ordered-routerの実SIGTERM配線 component](docs/architecture/decisions/0254-native-source-host-sigterm-wiring-oracle.md):
    E44でin-flight HTTPの本文を停止後に渡す拒否とfresh提案の実保存を確認。close除去/N2注入除去の
    実負対照・exact復元後の正常成功を検証。ordered routerだけのfactory/signal配線であり、
    実binary内のlate windowやFastVote/successor/historical/TLS・全D05/M5の完了ではない。
  - [x] [compiled frontier-maintenanceの実SIGTERM配線 component](docs/architecture/decisions/0256-native-frontier-sigterm-wiring-oracle.md):
    E50で空のchunked body、実停止後の取消と停止前のcursor/entry 2 record保存、
    pre-close/別composition取消参照の負対照・exact復元後の正常成功を確認。
    同一executorのstop stateへの別参照を検証し、paid prepare/apply・実binary late window・
    全D05/M5や最終source全体gate/CI/RELEASEへ拡張しない。
  - 範囲: 下の共通case表と `9de634a7` の完全required/全8 CIを受入対象とする。
    実workload/SLOに対するcapacity、actual production PKI、alerts/response・spend適用は
    D04/D07/M8で決め、適用後に検証する。原12 RELEASE runtimeはM7の別gate。

### D05/M5の共通case表

| 技術条件 | 実装と実行されたcontrol | 資格・残る境界 |
| --- | --- | --- |
| 全accepted familyの列挙・authorization | shared `certified-route-contract.tsv` とNative contract oracle、signed intent/certificate/policy、successor live warrant。historyはsignerlessの3 read routes | E71/E73。closed relayはNodeEvent/ordered/Seal/fee-claim/historyとunknown method/selector/queryを拒否。query/livenessに新JWT要件は加えない |
| TLS/拒否・停止後trust rotation | `local_tls_startup` の実4 host・SDK/CLI・bad pin・stop/rotation後の新規paid transferとreplay。successor/historyは既存recurring support | E30/E71。disposable local trustであり本番PKI/compromise revocationではない |
| request/retry/work/backpressure | Native policyのzero/oversized/incoherent拒否、slow header/body/handshake/output/peer切断、structured work overload、collector/output上限 | E71。1つのconnection/work owner、relay自動retryなし。transport lossはoutcome-unknownでreceipt照合。fixture値をproduction capacityにしない |
| stop/queue取消・started work drain・本番factory配線 | queued/in-flight executor、ordered/successor/historyのlate component controls、compiled ordered/frontierの実SIGTERMとpositive writes・欠落guard負対照 | E31/E32/E44/E50/E71。共通executorを所有する別参照を照合。binaryのlate window自体はcomponentで分担し、forced killをclean drainとしない |
| liveness・secret-free observations/collector | protocol stateを触らないliveness、固定15 numeric counters、bounded schema、actual foreground collector/SIGUSR1・実host継続 | E71。caller IDs/raw errors/秘密labelsを記録しない。実alert thresholds/routing/on-callはD04/D07 |
| spend・再現可能な操作/incident手順 | signed max_fee/gas、max_fee不足拒否、bounded host work、既存Native/fastvote/ordered/business-cut/release guidesのstop/restart/refusal/reconciliation | E71/E73。実billing cap・abuse/SLO設定・mainnet代表負荷/soak・topology/rehearsalはD04/D07/M8 |

M5の元のproduction条件は保存した原文と公開準備の対応表へ残す。この表の技術完了を
実運用・独立security監査・他provider・全M7完了へ拡張しない。

- [ ] **M7: 再現可能なsupported-runtime releaseを作る**
  - 対象: 実装 + 検証。source/compiler/deps/build provenance、2回のfresh 13-target
    Nativeビルドと全byte比較、canonical/digest/effects/consensus/proof parity、
    conformance/property/fuzz/adversarial/long-run・upgrade/restore・advisory qualification。
  - 状態: 古い11-target A/Bは既存baseline。50a4のE14/E15を保持し、537cのsource CIはE17、13-target実A/BはE18、実RELEASE runtimeはE19で成功。
    E20の旧local完全gate終端は未確認。後続M2 sourceの完全required/CIはE22/E24で成功したが、
    E18/E19のNative artifact/source pinとは異なる。426eの新A/BとRELEASE CLIはE26/E27で
    確認。後続b568の13-target A/Bと限定RELEASE importはE28/E29で成功したが、
    原12 driversの全RELEASE runtimeと完全source qualificationは未完了。
    統合7c57の13-target A/Bと実RELEASE CLIはE34/E35で成功し、元12ケースのruntimeはE47の時間上限失敗として保持。
    復元の後続source 277fはE53のCIを完了したが、原12 Native runtimeはE57で失敗。
    ローカル完全gateもE63で成功したが、原12 Native runtimeのE57失敗を保持する。
    10a4/E61・f973/E65の原12 runtime失敗も保持する。9de6はE64の13-target A/B・
    E71の完全required/CIに加え、E92で原12 RELEASE runtimeの全actual0/実EOF/waitを完了した。
    後続5f6bのfresh13-target A/BはE137、原12 RELEASE runtime全12 casesはE151で成功。
    9de6/5f6bの資格を別sourceへ借用しない。現行`50fbf22d`のE154-E156/E158・E164・
    E166-E168は同source/treeへ対応付けた。実旧9de6 upgradeと元12 casesのcold-open/
    source-free restore、元vectors・Native/WASM/workerd parity、既存の有限frame campaignは
    各成功predicateの範囲で確認済み。元の独立した最終source/security/release reviewと
    issue dispositionは未完了で、全M7は未完了。
  - [x] Rustls 0.23.46更新のsource qualification: E153の公開advisory metadataと
    exact dependency更新に対し、同`50fbf22d`の元5-group完全PG/集約checkはE154、
    fresh13-target A/BはE155、同source RELEASE CLI117はE156、fresh23/full49と
    default TLS15/実旧9de6 upgrade1はE158で成功。元12 runtimeはE164、既存ordered/
    certified別UID/TLS componentsはE166、literal npm ci +完全requiredはE167、
    全8 ordinary CIはE168で実終端まで照合した。当該更新のsource/component資格であり、
    独立最終source/security/release review・全M2/M3/M7・provider deployment・公開認定を
    完了したとは扱わない。
  - 新f51の13-target build component: E181でfresh A/B全13組の完全byte一致と
    actual source/tool/dependency・終了回収を照合。これは今回のNative buildだけの資格で、
    新CLI custodyの4独立runtimeはE182、元12 RELEASE runtimeはE187で成功。E187は
    fresh23/current49・全24events/98-0-3・元7epochs/e8の2件1832Bと同じ2件のACK・
    実EOF/wait/reap/資源解放までrootで照合した。全8 hosted CIはE189で成功。
    local完全requiredもE191で成功し、同f51のbuild/RELEASE/CI/local資格はそろった。
    独立最終reviewとissue dispositionが残り、全M7は未完了。
    D完全requiredはE188のcf317 ctime差分guard拒否でactual1となり、
    CF検証未到達。成功したRust prefixやE187を全体合格へ転用せず、先の失敗も保持する。
    E190で共有CLIから独立した検証環境と元5-profile型生成を完了した。
    同じf51の新しい専用source/cache/targetでの初回完全requiredは、記録プロセスの
    予期しない終了143を受け、rootが確認済みの自己所有runだけを停止した。
    npm ciはactual0、完全check-allはcompile途中のpartial。PID/cgroup解放を確認し、
    rawとcache/targetを保全した。別の新規source/cache/targetと有限の単発記録serviceで
    元の完全requiredを完走し、E191で全actual0・全raw/source/tool・実終了回収を照合した。
    Rust147 summaries/4,397 passed/0 failed/43 ignored・CF66、元7epochs/e8条件を保持。
    記録serviceの同Invocation自然終了と自己所有unit停止後のPID/cgroup不在も確認し、
    local完全gateは完了。E188/初回143の失敗・partialと未保存証拠の限界は保持する。
  - 現行8daの資格: E213のliteral npm ci +完全required、E218の全8 CI、E215のfresh
    Native13 A/B全byte/mode/owner一致、E216/E217のfresh23/current49と元一覧、
    E219のRELEASE publication-genesis 73 predicates、E222の元12 runtime101/0/3を
    同じsource/treeでroot照合した。外側143・集計失敗と未観測区間は保全し、
    製品本体の自然0/全raw/EOF/wait・inputs・全既知PID/cgroup解放を別途確認した。
    独立最終source/security/release reviewとissue dispositionは残り、全M7は未完了。
  - 次: 元の独立した最終source/release reviewとissue dispositionを現行source/tool/profile・
    上記実結果に対応付ける。独立security監査など元のrelease条件、D02/M1・M2/M3・
    公開準備行の責務は未達のまま保持する。現行8daのbuild/upgrade/restore/parity/
    元selectorの成功を、別の未指定campaign待ちとはしない。新sourceにはそのsourceの
    13-target A/B・実RELEASE bindingsを使い、ancestor結果を借用しない。
    広告する他providerに限り元のPhase16/17実provider基準を適用する。
    ローカルworkerd/adapter合格は実provider認定ではない。

## 公開準備: 6件

これらは実値・実役割・実環境・公開権限の完了を記録する行です。
公開まで延期していることは完了ではなく、コードを実装できない理由でもありません。

- [ ] **D04: 実validator・custody/admin役割とrelease profileを選ぶ**
  - 対象: 公開。独立operators、real genesis/chain pins、economics、
    supported routesとexact release artifactを固定する。
  - 状態: Native+SQLite firstは選択済み。実運用の選択は公開時に延期。
  - CODE/VERIFY参照: R4/M2/M4/M5/M6/M7。fixture値から本番値を決めない。

- [ ] **D06: 実genesis・鍵/config ceremonyを確認する**
  - 対象: 公開。実genesisを独立検証し、key/config ceremonyと独立installationをrehearsalする。
  - 状態: パラメーター化したauthor/inspector/installコードは存在し、ローカル検証歴あり。
    実値・実鍵ceremonyは公開時に延期。コード未実装とは扱わない。
  - CODE/VERIFY参照: M2/M6/G。dev keysやshared test DBを運用独立性とは呼ばない。

- [ ] **D07: 実topology上の運用rehearsalを行う**
  - 対象: 公開。outside-client、fees/claims、bonds/slash、membership/epochs、
    stopped catch-up、safe stop/restart/recoveryをexact receipt/canonical-stateで確認する。
  - 状態: 実運用topologyは未選択。local Docker/loopbackの合格とは別。
  - CODE/VERIFY参照: D01/D05/M2/M3/M4/M5/M7。物理fault/オフホストbackup・
    実PKI/SLO/alerts/retention等の元の運用基準を省略せず、選択profileに結び付ける。
    M3のselected-profile fault qualificationはCODE/VERIFYで先に満たす。
    この行は、その検証を置き換えるのでなく実運用topologyで追加のrehearsalを行う。

- [ ] **D08: launch・rollback・stop手順を承認する**
  - 対象: 公開。resources作成・public traffic受理前に人の承認を得る。
  - 状態: 未承認。実装継続やこの表の再構成は公開許可ではない。
  - CODE/VERIFY参照: R4/M4/M5/M7。実値と実操作手順を固定した後に確認する。

- [ ] **M6: 本番economics/genesis値を承認する**
  - 対象: 公開。sets/roles/powers、bond/fee assets/schedules、treasury/supply/
    distribution、security/unbonding/governance parameters・ceremonyとsupply invariants。
  - 状態: code側のparameterized author/inspector/install・checked-supplyは存在する。
    実値・役割・ceremonyは人が公開時に決める。
  - CODE/VERIFY参照: D06/M1/G。bondからvoting powerを推定したり、完了のために値を作らない。

- [ ] **M8: 公開運用の最終go/no-goを行う**
  - 対象: 公開。Delivery 4・actual public operation/recovery、experimental/
    unsupported/mock/deferred範囲を元の条件で確認し、人が最終判断する。
  - 状態: 未着手。mainnet genesis・公開は人の明示承認が必要。
  - CODE/VERIFY参照: 全コード・検証行とD04/D06/D07/D08/M6。
    コード完了・testnet公開・mainnet公開を同じチェックにしない。

## 元20項目の対応と公開readiness

下表は原条件を失わないための対応表です。原条件の全文は移行前資料にあります。
混在行のコード対象を完了しても、その公開依存が未完なら旧総合readinessは未完です。

| 旧項目 | 現在のコード・検証行 | 実環境・公開側の依存 |
| --- | --- | --- |
| R1 | R1 | なし |
| R2 | R2 | なし |
| R3 | R3 | なし |
| R4 | R4/M7 | D04/D08 |
| Delivery 4 #1 | D01 | D04/D06/D07/M8 (公開する場合) |
| Delivery 4 #2 | D02/M1 | D04/D07/M8 (実配置の最終監査) |
| Delivery 4 #3 | D03/M7 | D04/M8 (露出判断) |
| Delivery 4 #4 | R4/M7 (選択可能なartifact) | D04 |
| Delivery 4 #5 | D05/M5 | D04/D07/M8 |
| Delivery 4 #6 | M6の既存parameterized code + G | D06/M6 |
| Delivery 4 #7 | D01/M3/M4/M5 (ローカル実行可能な部分) | D07 |
| Delivery 4 #8 | R4/M4/M5/M7 (手順のコード/検証) | D08 |
| M1 | M1/D02/R4 | D04/D07/M8 |
| M2 | M2 | D04/D06/D07 |
| M3 | M3 | D07/M8 |
| M4 | M4/M7 | D04/D06/D07 |
| M5 | M5/D05 | D04/D07/M8 |
| M6 | parameterized code + G/M1 | M6/D04/D06 |
| M7 | M7/R4/D03 | D04/D07/M8 (実provider/profile適用) |
| M8 | 全コード・検証行 | M8/D04/D06/D07/D08/M6 |

元のS4は[DR-0208](docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md)
の明示変更でLedger必須ではなくprotected signingへ対応します。S5/Phase 15、
Security Invariants/Coding Requirements/Required Integration Tests、selected-profile
durability・disaster recovery、advertised-provider Phase 16/17の基準は残ります。
Native+SQLite firstは他providerの認定ではありません。protocol-v3のatomic composition、
全accepted familyのauth、protected signingと独立security/release条件はpublic testnetにも
適用され、この整理だけでlive activationは許可されません。

## G: 一つの共通acceptanceと証拠記録

同じhead/profile/scopeの結果を参照で共用します。別ソース・祖先・部分結果の転用、
未実行/skip/cancelを成功扱い、selector削減、delay短縮やfault除外はしません。

1. 実際のsource/tree、lock/tool inputs、profile、実行範囲・独立reviewを固定する。
   refactorはowner・migrated callers・removed duplicateとbytes/error/authority保持を示す。
2. proportionalなowning/vector/adversarial/store/HTTP/CLI/fault controlsを実行する。
3. literal `npm ci --prefix adapters/cloudflare-workers` と完全な
   `./scripts/check-all.sh`。全7 unconditional ownersとsuccess-only `check` を残す。
4. PG実装/依存変更またはPG claimにはselected-sourceの5-group complete PG/full profile。
   Docker-only live prerequisitesを必須とし、E2を別headへ借用しない。
5. M7/R4では現在の13 Native targetsのfresh A/Bと完全比較・provenance。
   これは全てのR1/R2/R3/D01完了に新しく足す前提ではない。
6. exact-source CI terminal、独立最終review・指摘処理、実際のraw exit/EOF・所有資源releaseを
   記録する。startup 0、check件数、hash/countだけはsemantic/runtime合格ではない。
   失われたrawを現在存在するものとしてリンクせず、回収可否と証拠の限界を明記する。
7. 正常なmergeは該当する元の条件を満たした後だけ。squash/rebase/forceや
   未認定release/main mergeを行わない。公開許可はD08/M8の別判断。

[Validation profiles](docs/architecture/repository-validation.md)と
[元production gate](docs/development/history/roadmap-through-2026-10-06.md#cli-first-node-production-gate)
が原条件を所有します。原条件の詳細はarchitecture/historyへ辿り、live状態はここだけに書きます。

## 次の実行順

1. 所在・欠落範囲の照合、新しいbounded依存cache、E5/E6とR1/R2/R3/D01の
   最終照合は完了。削除されたローカルraw/署名試作は未回収として保持する。
2. M2のpreview/exportとpublication-only local OS custodyは実装・独立correctness
   review・実UID/PTY/refusal/restartに加え、publicationの取消・鍵復旧/交換をE21/E22で検証済み。
   fee-claimの非承認表示・保存内容のdevelopment signingはE23/E24のlocal完全gateとhosted CIまで成功。
   残るprotected backend/操作意味の承認、他family/automatic signingと各lifecycleを進める。
   D03の元scopeはE14/E15/E16・hosted終端成功で完了。公開前の露出/新advisory確認はD04/M8へ対応する。
3. M3のf093統合と新しいowningはE7、既存5 ENOSPC controlsはE8で成功。
   残るselected-profile fault/combined条件を進める。
   M4で既に成功した暗号化復元を未実装として作り直さない。
4. R4とNode24 profileはE17/E18/E19で技術範囲を完了。E20の旧local終端未確認と
   未達qualificationを保持。後続M2 sourceの所有controllerによる完全gate成功はE22/E24へ記録済み。
   D02/M1のprovider-stopped taskは再試行・迂回せず、未達として保持する。
   D05/M5はE71/E73と同一case表で選択済み技術範囲を完了。公開運用はD04/D07/M8に残す。
5. コード・検証が揃ってから人の公開準備へ引き渡す。新たな許可/実値が必要な
   公開側の仕事を勝手に実行せず、具体的な不足を説明する。

## 既存の完了履歴: 9件

以下は元の完了履歴を保持したもので、新しいコード・公開readinessへの転用ではありません。

- [x] CLI Developer MVP: local Rust queries, generic paid Publish/Instantiate/Call
  and ordinary Standard Asset create/transfer/split/merge/mint/burn. Standard
  Asset has no node-core admission or balance privilege.
- [x] Delivery 1: certified network contract lifecycle, replay and declared
  catch-up (PR #228), not complete state handoff.
- [x] Delivery 2: shared ordered claims, bonds, evidence/slashing and reactivation
  (PR #232). Membership, ownership, bond and voting power remain distinct.
- [x] Delivery 3: recurring original-root membership/recovery through actual
  configured e8 withdrawal unlock, changed five-member committees, restart,
  fencing and replay (PR #269/#270, normal merge `952c77f`). This is functional
  local acceptance, not an independent audit or public/mainnet qualification.
- [x] Semantic foundations: writer-free business preparation, domain-bound
  observations/assembly, immutable `VerifiedGenesisRoot`, one committee record
  validator and reconstruction-policy owner, and shared SQLite/DO SQL decisions.
- [x] Local SQLite preflight, offline Standard Asset genesis, exact publication
  reference checks and real four-validator SQLite/TLS/compiled-CLI startup
  (PR #271–#276). Development composition is not operational custody.
- [x] Native/SDK/certified-relay integration (PR #285): exact `fb3e6884` received
  complete independent Codex fallback source approval, literal npm-ci plus
  `./scripts/check-all.sh` PASS, all seven required hosted owners plus `check`,
  and normal merge `4d919b0d` at 07:28 UTC. Merge tree equals the approved head;
  local main equaled origin/main and was clean. PR #281–#284 are merged ancestors.
- [x] Native SQLite integration (PR #293): normal merge `364e2ec8`, tree
  `00e1d340`, equals independently reviewed frozen `3ec8d7bd`. Literal npm-ci
  and full required `./scripts/check-all.sh` both exited 0 on that exact source;
  fresh eleven-target native A/B byte equality was independently verified.
  All seven hosted required owners plus success-only `check` succeeded in
  run `37610011266`. Components #286–#292/#294/#295 are merged. This local
  profile acceptance is not a security audit or completion of M1–M8.

Validator-set changes, slashing and reward/claim distribution remain FastVote
completion requirements. Functional acceptance does not close their economic
and security release gates.

- [x] **R0 — one truthful plan:** one live queue, preserved original requirements
  and attributable history, architecture/code-map/ADR ownership, working links
  and independent review. The complete 662eda8f review verified the exact
  558-line archived body and every original criterion mapping; links passed.
  Implementation/release acceptance remains separate. Keep this queue
  synchronized with actual integration.

## 作業権限と延期項目

- 普通の非破壊的実装、公式locked入力の準備・ローカル検証、Docker-only local PGと
  bounded Docker disk-full/forced-stopは既存の許可範囲。各取得/検証/資源上限は維持する。
  壊れた古いpacket、消費済みONE/helpers、provider-stopped taskを再試行・迂回しない。
- R0の再構成時はdocumentationだけだった。現在の続行は指定f655bd40を起点とする
  通常実装・限定依存更新・local検証の範囲。実host設定・公開資源・実資格情報は変更しない。
  CI定期タスクも復活させない。
- SSH/normal merge。Senna PATは指定organizationのPR作成だけで、read/review/mergeには使わない。
  全作成PRはchatへattachする。既存main/branches/stashesと無関係な変更は保持する。
- TypeScript client、explorer/wallet、Ledger、Unique Asset、multisig、contract upgrade/
  irreversible relinquishment/atomic migration、ZK、cross-domain atomicity、追加provider/HA/scaleは
  元の条件付きdeferredのまま。未実装のものを広告しない。認定条件を黙って取り消さない。

## 2026-10-18の8時間枠終了記録

人の承認期限は23:20:19 JSTのまま延長しない。保存済みの全local実行とCI326/327は
自然終了・回収と照合を完了した。今回の新規13-target A/Bとcurrent RELEASE CLIの
4 custody profilesはE181/E182、c680/7663の完全local requiredと全8 CIはE183-E186へ記録した。
全77 checkboxes、旧20項目は9件完了・11件未完了、選択8件は3件完了・5件未完了を維持する。

残る5件の理由は次の通り。既存の完了条件を増やさず、狭いcomponent成功で親を閉じない。

- D02: 最終の機能・権限範囲を対象にした独立監査が未完了。provider-stoppedの監査は再試行しない。
- M1: 固定した最終release全体の独立security/release reviewとissue dispositionが未完了。
- M2: 未統合・未検証ZeroShare、各signing familyの残るlifecycle/全体対応、最終f51 sourceの完全required/CIが未完了。
- M3: selected SQLiteの残るfault boundariesと独立anchor firstbootの検証が未完了。既存ENOSPC5成功とは分ける。
- M7: 最終f51 sourceの完全required/CI・原12 RELEASE runtimeと独立最終source/release reviewが未完了。E181/E182はbuild/限定runtimeの資格に留める。

独立監査・ZeroShare fixture・M3 torn-WAL assessment/mechanism2・独立anchor VM boot修正は、
providerがpossible cybersecurity riskとして拒否したため停止したまま保持した。別担当への
付け替え・言い換え・再試行はしていない。残る新規long runは元の有限上限では期限内に
収まらず開始しない。新たなtrust契約も選択しない。これ以上実行できる許可済み作業が
ないため、証跡・失敗・source/cache/targetを保持して同じheartbeatを停止する。

## 2026-10-18の第2の8時間枠

人が新たにCodexサブエージェントでの8時間の作業を指示した。前の終了記録を保持し、
第2枠は2026-10-18 14:58:06 UTCから22:58:06 UTCまでに限定する。
シンガポール時間では10月18日22:58:06から10月19日06:58:06まで。自動延長しない。

- 最終f51 sourceのliteral npm ci +完全requiredはE188の失敗として終了記録済み。npm ci actual0、check-all actual1/実EOF/wait/reap、outer13,046.442秒。cf317の77 ctimeNs差分をguardが拒否し、全body SHAは一致したがCF typegen/lint/Vitestは未到達。guard緩和・環境変更・再実行はせず、source/cache/target/失敗を保全した。元のfull上限が残り時間に収まらないため、この枠で新規full runは開始しない。別実行の全8 hosted CIはE189で成功し、local失敗と分けて保持する。
- 元12 RELEASE runtimeはE187で終了照合済み。fresh23 driver buildはactual0/実両EOF/wait/reap、809.210秒、元12実行は15:35:55 UTC開始から9,509.763秒でactual0/98 passed/0 failed/3 ignored。rootがcurrent49/source/tool/CargoJSON・全raw/元recurrence・実EOF/wait/reapと資源解放まで照合した。E181の実13 RELEASE artifactsを使い、成功済みA/B・custody4 profilesを重複実行していない。source/cache/target/ELFは保全し、この実行と読取phaseは終了。
- 既存f51差分の[Draft PR #328](https://github.com/sunriselayer/sunrise-edge/pull/328)を保全し、[CI run39138896024](https://github.com/sunriselayer/sunrise-edge/actions/runs/39138896024) attempt1の全8自然終了SUCCESSと全raw/actualcheckout/tree/parentsをE189でroot照合した。先のc680/7663やhosted成功をlocal完全gateへ借用しない。
- 3担当はいずれもCodexサブエージェント。rootだけがTODOを更新し、完了数は77 checkboxes/旧9完了11未完了/選択3完了5未完了のまま開始する。

保存記録から、ZeroShareの停止はClaude Sonnetのreal-time cyber safeguards、
M3 anchor firstbootの停止はCodex担当へのpossible cybersecurity risk判定と確認した。
単なるClaude起動障害ではないため、既存4系統の拒否対象はモデル変更・言い換え・
別担当への付け替えで再試行しない。許可された別の未実行検証を進める。
実行予定・所有権・証跡はvalidationの`eight-hour-window-1018-second-plan.json`へ保存する。

## 第2枠の終了記録

E187の最終f51元12 RELEASE runtimeとE189の全8 hosted CIは、実終端・全rawと
対象sourceの照合まで完了した。E188のlocal完全required失敗は失敗のまま保持する。
全自己所有local実行・CI・collectorは自然終了して回収済みで、author/root read phaseも
終了した。source/cache/target/ELF・過去失敗・証跡を保全し、main merge・deployはしていない。

残る親5項目は未完了のまま。新しい完了条件を作らず、既存の不足を記録する。

- D02: 最終機能・権限範囲の独立監査が未完了。既存provider-stopped scopeを再試行しない。
- M1: 最終release全体の独立security/release reviewとissue dispositionが未完了。
- M2: ZeroShare未統合・未検証と残るsigning family/lifecycle・全体対応、local完全requiredが未達。
- M3: selected SQLiteの残るfault boundariesと独立anchor firstbootの検証が未完了。
- M7: build/元12 RELEASE/全8CIは成功したが、local完全requiredと独立最終source/release reviewが未達。

元のfull実行上限と回収余裕は残り時間に収まらず、新規実行は開始しない。停止済みの
監査・ZeroShare・torn-WAL/mechanism2・anchor VM bootを付け替えで再開せず、guard緩和・
環境変更・新trust契約の選択も行わない。これ以上実行できる許可済み作業がなくなったため、
未完了理由と実績を保存して同じheartbeatを停止する。期限22:58:06 UTCの延長や次枠作成はしない。
77 checkboxes、旧20項目は9完了/11未完了、選択8件は3完了/5未完了を維持する。

## 2026-10-19の手動作業: 独立して進める既存gate

新しい手動指示で、既存のlocal完全requiredを次の作業に分けた。元の完了条件は増減しない。

- 完了: Cargo599件/npm617件の公開依存を専用cacheへ別inodeでコピーし、元の内容hashを照合。
- 完了: CLIと34依存packagesを専用コピーへ切り替え、厳密なguardを維持したまま元5-profile型生成がactual0。E190を参照。
- 完了: literal npm ci +完全requiredの実終端確認。E191で両actual0、Rust4,397 passed/0 failed/43 ignored・CF66、元7epochs/e8、全raw/source/toolと実EOF/wait/reap・PID/cgroup解放をrootで照合。初回recorder143のpartialは保全し、記録処理を有限の単発serviceへ分離した実行の自然成功と区別した。

同じf51の13-target A/B・元12 RELEASE runtime・全8 hosted CI・local完全requiredは完了した。
残る親項目の不足は次のとおり。

- D02/M1: 独立した最終機能・権限/security/release reviewとissue disposition。
- M2: ZeroShare未統合・未検証と、残るsigning family/lifecycle・全体対応。
- M3: 未達のselected SQLite fault boundaries、独立anchor guestとpartial persistent write。
- M7: 独立した最終source/security/release reviewとissue disposition。

停止済みの独立監査・ZeroShare fixture・torn-WAL・anchor VM修正は再開しない。
削除済みの`sunrise-edge-5-8`は再作成せず、以前の時間枠も閉じたまま保持する。
親D02/M1/M2/M3/M7は未完了。上記の限定実績を親全体へ転用しない。


## 2026-10-19の独立したM2/M3残件の細分化

既存のM2 recovery/M3 TLS failure条件から、停止対象と独立した上記3子タスクを完了した。
original ordered鍵復旧、certified鍵復旧、durable apply後のTLS ACK喪失を別worktreeの
Codexサブエージェントへ分担し、rootが統合・実行所有・結果照合・TODO更新を行った。
通常の変更箇所の確認後、`c1d2275752266cb3eb44cbe271529deca0bd22ea`
(tree `6328224f0e5167c248dea6181289ba78258108a0`) に統合した。
[Draft PR #329](https://github.com/sunriselayer/sunrise-edge/pull/329) に保全している。

- E193/E194: 実targeted runtime。ordered79/certified149 role children、新旧TLSのactual成功、元receiptの誤帰属と訂正後の実再検証、完全raw/EOF/wait/reap/自己所有資源の回収を照合。
- E195/E196/E197: runner形式不一致と長いchild TMPDIRによるSUN_LEN失敗を保全。元の比較属性・期待hash・guardを保持し、元のprivate /tmp設定へ戻した全245 native-http probeが成功。
- E198: [同sourceCI](https://github.com/sunriselayer/sunrise-edge/actions/runs/39211600220) 全8の自然SUCCESS、全raw/actual checkout/tree/parents・collector実EOF/wait/reap/資源解放をroot照合。
- E199: literal npm ci +完全requiredがactual0。Rust4,398 passed/0 failed/43 ignored・CF66、元7epochs/e8の1832B候補2件と同ID round3 ACK、source/tool/全331 currentELF・cache/target snapshotをroot照合し、同じ自己所有の空unitだけ停止。

全owner/query/read phaseは終了し、source/cache/target/ELF・元の失敗と証跡を保持する。
元の制約や完了条件は減らさない。チェックは既存77から80へ細分化し、今回の3子タスクは完了。
親20件の9完了/11未完了、選択8件の3完了/5未完了は不変。限定した実績を親全体へ転用しない。

残るM2はZeroShareと未達signing family/lifecycle全体、M3はselected SQLiteの未達physical fault/
partial persistent write/独立anchor guest。残件表の通常の対応付けでも、今回の3件以外に
新しいauthority/profile判断なしで着手できる別の具体的な小タスクは確認できなかった。
停止済みの独立監査・ZeroShare・torn-WAL/mechanism2・anchor VM修正は再試行していない。
main merge/deploy・実鍵/host user/security policy変更は行わず、削除済み定期タスクも再作成しない。

## 2026-10-21のM2/M3既存条件の続行

前回完了した3子タスク、c1/tree6328とPR #329は保全する。実装sourceを通常の範囲で
確認し、上記2条件を別worktreeのCodex担当へ分担した。M2は既存の復旧済み同一A鍵を
既存live手順に渡す検証、M3は既存の参照付きhistorical bodyをTLS応答喪失/再送の状態保持へ
組み合わせる検証であり、元の親条件を増減しない。実装・実runtime・source全体gateの
終端がそろうまで完了にしない。rootだけがTODOを更新する。

停止済みの独立監査・ZeroShare・torn-WAL/mechanism2・独立anchor VM boot修正は再開しない。
M3のprior-release upgrade helperも変更せず、旧ELF/VMの再実行をこの作業へ持ち込まない。
Node24.19.0/cfを使用し、各実行は有限時間・単一ownerで管理する。定期タスクは作らない。

最終source `c535c78f` / tree `c43985ca` の5 runtimeはE203で全成功。
[Draft PR #330](https://github.com/sunriselayer/sunrise-edge/pull/330) に統合し、
2026-10-21 06:33:52 UTC開始のliteral npm ci +完全requiredはE204で終端成功。
元のcase/待機/上限を保持し、current target/cache再利用を明示した。
同source CI [run 39553580566](https://github.com/sunriselayer/sunrise-edge/actions/runs/39553580566) はE205で全8自然SUCCESSを照合した。
今回の子2件は実装・実runtime・最終source完全required/CIがそろったため完了。
全82 checkboxesは68完了/14未完了、旧20親は9完了/11未完了、選択8親は3完了/5未完了。
M2の未達signing family/lifecycleとZeroShare、M3の未達physical/partial-write/独立anchor条件は残す。
親M2/M3と他の親5項目を完了へ付け替えず、停止対象は再開しなかった。
全既知自己所有プロセス/PID/cgroupは閉鎖済み。定期タスク・新たな8時間枠は作成していない。

## 2026-10-22のM2/M3既存条件の続行

最終c535/PR330とE203-E205を保持し、上記の復旧鍵genesis split/mergeと
参照body付きACK喪失後の正常再起動を次の2子条件として実装する。
既存checkoutを `codex/m2-m3-next-1022` で使い、worktreeやcacheの複製を増やさない。
単一source writerが順番に実装し、rootだけがこのTODOを更新する。
source変更は各段階でcommitし、review後にpushする。実装/実runtime/最終source gateが
そろうまで新2件は未完了に保ち、停止済み4対象は再開しない。

古いworktree98個は復元用ref/ローカル状態archiveを保存して削除済み。
そこに残っていた11件のsource変更も `codex/archive-1022/*` へcommit/pushし、
remote SHAを照合した。保存用WIPを実装の統合/検証成功として扱わない。

新2件の実装は `8aacb46d` / `194c7854`、設計書indexは `4d05afd1` にcommitし、
`codex/m2-m3-next-1022` のremote HEAD一致を照合した。
[Draft PR #331](https://github.com/sunriselayer/sunrise-edge/pull/331) はPR330上へ積み、
通常の差分review・Node24構文・rustfmt・diff checkは成功した。
[CI run 39706512959](https://github.com/sunriselayer/sunrise-edge/actions/runs/39706512959)
と同sourceの実runtime/完全requiredは検証中であり、新2件はまだ完了にしない。

追加確認で、新M3 selectorがcontext照会後にrequests=0を要求する検査順序の誤りを発見した。
旧CIのrust-tests rawも該当箇所の2対0だけの失敗を示した。失敗rawと旧run全体cancelledを
保全し、成功へ転用しない。照会前へ元の3検査を移した `503ca159` / tree `1fd4ec81`
をcommit/pushし、remote HEAD一致を照合した。
修正sourceの[run 39707845153](https://github.com/sunriselayer/sunrise-edge/actions/runs/39707845153)
が自動開始した。検証中のため新2件は引き続き未完了。

2度目のCIは、通常の再起動relayへACK喪失専用getterを呼んだ箇所で失敗した。
旧getterの明示arming条件は保ち、test-onlyのarming状態照会を使う `ef92e9df`
/ tree `a17889f7` をcommit/pushした。旧runはcancelledを保全し、
[run 39710233943](https://github.com/sunriselayer/sunrise-edge/actions/runs/39710233943) が検証中。
local旧runnerの設定不足による実テスト前停止と、V2のfmt/clippy成功・CLI build中断も
別証跡へ保全した。中断や部分成功を新sourceの完了へ転用せず、既存target/cacheを保持する。

local V3は同ef92のfmt/clippyと全5 buildがactual 0、EOF/wait/reapを確認した。
続くpublication-genesisは圧縮bootstrapの64KiB引数上限でactual 1となり、runtime成功へは
数えない。decompressed Pythonは261654Bで元262144B以内だったが、別の圧縮transport上限に
達した。失敗rawとPID/cgroup解放を保全し、実行内容/判定/両上限を保ったコメント配置修正を行う。
CIのrust-tests成功は確認したが、追加2件の最終source全体資格は引き続き未完了。

`b3898434` / tree `dfdc63d5` は説明コメントだけをembedded Pythonの外へ移し、commit/push済み。
rootがPython AST/token列の一致とbootstrap/driver部分の不変を別途確認した。
Node24.19.0の実圧縮ではraw 246128/262144B、bootstrap 54837/65536Bで両上限内。
ef92のCIはhead更新で自動cancelledとなったため、6 job成功を最終source全体へ転用しない。
新sourceの実runtime/完全required/全8 CIは引き続き検証対象とする。

b389の新旧runtime全6件とfmt/clippy/5 buildの計13 commandsはE206で実成功し、
rootがsource/生成物/実rawとPID/cgroup解放を照合した。元の判定/selector/上限は保持する。
同sourceのliteral `npm ci --prefix adapters/cloudflare-workers` + `./scripts/check-all.sh` は
2026-10-22 02:53:41 UTCに単一ownerで開始した。既存target/cacheを再利用し、
26000秒work +300秒cleanupの有限枠で管理する。最終sourceの
[run39712537120](https://github.com/sunriselayer/sunrise-edge/actions/runs/39712537120)
も進行中。両gateの終端前は新2子条件を完了にしない。

02:53:41 UTC開始のlocal完全requiredは、両command本体がactual0/実両EOF/wait/reapで終了した。
Rust4,400件・CF66件が成功した一方、終了時の環境固定照合はDeno/Pythonの旧実体不在で
失敗した。現在のaliasは開始時と異なり、この作業によるtool変更や再導入は行っていない。
E207に本体成功とowner全体失敗を分けて保存し、元guardを免除せず新2件は未完了に保つ。
全既知local producer PID/cgroupは閉鎖済み。CI run39712537120の残るrecurring-sqliteと
aggregateの終端は未確認であり、6 job成功を全8成功へ読み替えない。
CIの最終metadata確認は2026-10-22 06:36:51 UTC。上記6件成功・recurring-sqlite実行中で、
read-only確認担当は両GH commandのactual0/EOF/wait/reap・PID不在を保存して終了した。
local常駐observerは残さず、既存CIの360分timeoutや元の09:30 UTC上限は延長しない。
CIのcancel/rerunや新automationは行っていない。

環境固定の修正は製品source b389を変えず、別のlocal検証profileとして準備する。
README/CIと同じ公式Deno2.9.4をSHA固定で専用pathへ展開し、Homebrew依存のないsystem
library closureを確認。Pythonは既存system3.14.8へ明示bindingする。旧4tool rolesだけを
一対一で置換し、元2390 tools/67 strict/3 aliases・CF2347/layout2725・311 archives・
source1223のfull9/SHAと元2 commands/全selector/資源上限を維持する。
新profileのpreflightはactual0。既存Python pathのrole重複を拒否した準備V1は実製品実行前の
失敗として保全し、固有aliasを用いた準備V2は成功した。ツール取得/入力bindingの手順は
[作業専用runtimeの手順](docs/development/validation/2026-10-22-runtime-repair/README.md)へ保存。
全体gateは別の単一ownerで再実行し、前回FAILEDを成功へ変更しない。
新profile `m2-m3-stable-full-required-1022` は2026-10-22 07:24:02 UTCに開始。
同b389 source/既存target-cacheを単一ownerで使用し、26000秒work +300秒cleanup、
12GiB/swap0/CPU4の元上限を維持する。終了後に固定入力を再照合するまで新2件は保留。

同b389のCIは2026-10-22 07:46:43 UTCに全8自然SUCCESSで完了し、E208でrootが
全raw/実checkout/tree/parentsと元protocol markersを照合した。collectorとmetadata確認の
自己所有PID/cgroupは閉鎖済み。CIの再実行・cancelは行っていない。新固定profileのlocal
全必須チェックだけが残っていたため、source/cache/target/toolsの専有と元の検証条件を維持した。

新固定profileは2026-10-22 10:14:43 UTCに自然Status0で終了した。両commandの実EOF/wait/reap、
終了時の全source/tool/archive/wrapper identity、全既知PID/capturedCG不在をE209で照合した。
rootの元protocol補足はlocal/CIの7epochs/e8候補2件/1832B/同ID round3 ACKと、変更されていない
元12 sourceの8links/35role assertionsを照合。最初のreaderはquiet出力をnamed-resultと誤仮定して
停止したため、その失敗を保存し、元のquiet owning summaryに対応したreaderだけを修正した。
製品source/selector/上限や検証結果は変更せず、製品の再実行も行っていない。
E206/E208/E209が同b389でそろったため、今回のM2/M3各1子条件を完了とする。
残件は14チェック (コード・検証の親D02/M1/M2/M3/M7、停止中の子3件、公開準備の親6件)。

2026-10-22の次作業: Cloudflareのsecurity-audit skillをuser領域へ導入し、upstream
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` の全20 files/Git blobs一致を確認した。
これはtool導入であり監査結果ではない。D02/M1の停止済み独立監査を別skill/modelへ
付け替えて再試行せず、他の停止対象も保持する。新automationやcacheコピーは作らない。
作業worktreeを増やさない当初の方針は、RELEASEのclean source guardと既存target保全のため、
同8daの追跡source 26,617,053 logical bytesだけの専用checkout 1個に限り変更する。
既存source/cache/target/node_modulesのコピーは行わず、全検証終了・終了後照合と資源解放の後、
clean状態で当該checkoutだけを削除する。
M2は8daの実fixture/完全required/CI、M3はE210のcoverage対応、M7はM2変更確定後の
同source 13-target A/B・元12 RELEASE runtime admissionを進める。rootだけがこの表を更新する。
E212の限定runtimeに続き、E213で同8daの完全requiredも自然終了・root照合まで成功した。
同source CIは終端待ち。RELEASE用のlean checkoutは作成済みだが、入力censusは未展開
locked source pointerを検出して停止したため、失敗を保持して配置だけを確認中。
85チェック中70完了/15未完了、選択した親5件は未完了のまま保持する。


## 2026-10-27の通常保守: CLI helperとCI selector

親5件と別枠の保守改善として、既存source `8da1d620` を起点に以下3件を実装した。
新しいprotocol・authority・親項目の完了条件は追加しない。

- FastVote PGのscalar/decimal-suite/schedule parserを既存operator commonへ移した。
  literal-ID grammarは別に保持し、受理する数値表記・error順序/文言・schedule順序を変えない。
- operatorの小文字hex表示7実装を同commonのhelperへ移し、既存の独立期待値を残した。
- SQLite inventory自身がexporter selectorとexact discovery/executionを所有する。
  standalone/CI両入口から同じhelperを使い、列挙0件/重複/失敗・export失敗時の停止とcleanupを保つ。

実装は `3a2e3aa4` / `a3fa4576` (tree `99fb314d`) にcommit/push済み。
[PR #333](https://github.com/sunriselayer/sunrise-edge/pull/333) は#332上へ積み、
ユーザー承認により09:12:32 UTCに既存base `codex/live-genesis-mint-burn-1022` へmergeした。
Merge `bfbca5fc` のtreeは同 `99fb314d`、parentsは `[8da1d620, a3fa4576]`。
mainへの統合やbranch削除は行っていない。
追加Rust互換性8件、Nodeの全CI契約、fmt/bash syntax/diff checkは成功。
通常の狭いcorrectness reviewで具体的なblocking regressionは見つからなかった。
同sourceのliteral npm ci・完全required・完全5-group PG profileは07:36:13 UTCに自然成功。
rootが全86 streams/実EOF/wait/reap、1,225 source inputs、23 runtime/CF2,347 tool rolesと
layout2,725行、既知PID/cgroupと今回PG資源の解放を終了後に照合した。
requiredはRust4,408 passed/0 failed/43 ignoredとCF66成功、PGは1,493/0/20。
summary合計には別exact/helper実行を含み、元のignoredは実行済みにしない。
[検証記録](docs/development/validation/2026-10-27-operator-helper-ci-dedup/README.md) に
実行前CF停止と終了後reader停止も保存した。
[CI run40447306260](https://github.com/sunriselayer/sunrise-edge/actions/runs/40447306260) は
attempt1の全8 jobsが08:59:30 UTCに自然success。rootが全8 raw logs、実checkout
`f5ac2374`、tree `99fb314d`、parents `[8da1d620, a3fa4576]`、全483証跡filesを照合した。
CI取得のescape guard停止とPID未記録の初期2 attemptsは保持し、最後の完全取得の
実両EOF/waitと既知collector/child PID不在を確認した。CI本体の再実行は0。
今回の通常保守3件は同sourceの実装・完全required/PG/CIがそろったため完了。
元のチェックボックスは85個中71完了/14未完了で変えず、新しい親完了条件も追加しない。
残るD02/M1/M2/M3/M7の親5件は引き続き未完了。停止対象の監査等は再開していない。

## 2026-10-27の追加通常保守4件

4件の実装を `e7bdf83f` (tree `c28d0437`) にcommit/pushし、
[Draft PR #334](https://github.com/sunriselayer/sunrise-edge/pull/334) を作成した。
canonical/hexの互換性4件とSDK deadline3件を追加し、既存case/assertionは削除していない。
SDKのsend前後10か所の検査位置とTempDirの元counter共有・interleavingを保持した。
共有CLI locatorへの移行に伴い、missing-CLI diagnosticとEXE_SUFFIXは既存共有ownerの動作へ統一した。
fmt/diff check、focused15件 (common11・inventory argv1・SDK3) と通常の差分correctness reviewは成功。
09:44:52 UTCに開始した単一ownerは13:10:58 UTCに自然成功。
literal npm ci・完全required・完全5-group PG profileはすべて実exit0。
requiredはRust4,415/0/43とCF全66件成功、PGは1,497/0/20で、元ignoredは未実行として残す。
rootは全86 streams、source1,226 inputs、23 runtime/CF2,347 tool rolesとlayout2,725行を終了後にも照合し、
既知PID/cgroupと今回PG資源の解放を確認後、空の完了unitだけを停止した。
[検証記録](docs/development/validation/2026-10-27-operator-test-sdk-dedup/README.md) に実績と証跡を保存した。
[全8 CI run40482348781](https://github.com/sunriselayer/sunrise-edge/actions/runs/40482348781) は
attempt1のまま14:37:10 UTCに全job自然success。rootは386 filesと全8 raw logsを再hashし、
実checkout `70e9807b`、tree `c28d0437`、parents `[bfbca5fc, e7bdf83f]` を照合した。
全8 childの実exit0・両EOF・waitとcollector/既知PID不在を確認した。Bugbotを含む全9 check-runsもsuccessで、
その時点のreview/commentsとBugbot annotationsは0。CI各jobのannotation計8件は同じrunner image移行noticeで、
warning/failureは0。今回の通常保守4件は完了。全9 check-runsのsuccessと同一headを再確認し、
15:29:39 UTCにPR #334をReady for reviewへ切り替えた。
ユーザー承認により2026-10-28 04:18:25 SGT (2026-10-27 20:18:25 UTC) に
既存base `codex/live-genesis-mint-burn-1022` へmergeした。merge `3814b3ea` は
同tree `c28d0437`、parents `[bfbca5fc, e7bdf83f]`。全9チェック成功と同一headを再確認した。
元の85 checkbox /71完了 /14未完了と親5件は変わらない。

PR #333のsource `a3fa4576` / tree `99fb314d` を実装側とテスト側に分担してread-only確認した。
rootも下記の候補を実sourceで照合した。merge `bfbca5fc` は同じtreeである。
ユーザーの「全部やろ」により、以下4候補すべてを実装・検証して完了した。
既存checkoutを `codex/operator-test-sdk-dedup-1027` / `bfbca5fc` から再利用し、
source/cache/targetを複製しない。operatorを単一writerへ分担し、SDK変更は別担当のinert patchを
rootがwriter解放後に適用する。rootだけがTODOを更新する。
実装、互換性controls、同source完全required・完全5-group PG・全8 CIの実終端と証跡照合がそろった。
元の親条件やcheckbox数は増減しない。

1. CLI helper (完了) 。genesis inspector/authorのcanonical decimal /number /positiveを既存commonへ移し、
   inventory argvの32-byte hex decoderも既存helperへ統一した。緩いFastVote grammarとは分け、
   入力表記・error順序/文言・flag消費を互換性controlsで確認した。
2. PG test supportの再利用 (完了) 。catch-upのcompiled CLI locatorとinventoryのTempFileGuard、
   backend解決、proxy DSNを既存ownerへ移した。env名とfixture固有の独立assertionsは保持した。
   missing-CLI diagnosticとEXE_SUFFIX対応は既存共有locatorへ統一した。
3. std-only TempDir (完了) 。successor artifact/refusalの2 targetsで共通helperを使う。
   元prefix、tag、PID、各targetのcounterとinterleaving、createとbest-effort Dropを保持した。
   timestamp命名や厳格cleanupを要求する別fixtureは統合しない。
4. SDK deadline guard (完了) 。crate-private helperへまとめ、send前後10か所の位置と同じerrorを保持した。
   pollingと残時間計算を変更せず、None/future/expiredとtransport call数をsleepなしで検証した。

テストのcase削除を正当化する重複は今回確認していない。共通化は準備・後片付けを中心とし、
各command/transport/storage境界のassertion、独立oracleと元scenario matrixを維持する。
SQLite startupのchild/output collectorにも類似処理があるが、poll間隔、同時drain、
pipe完了期限が異なるため、単純な置換候補には含めない。今回そこへ実装・実行は行っていない。
停止済み監査・ZeroShare・torn-WAL/mechanism2・独立anchor guestを再開する提案ではない。

## 2026-10-28の追加共通化候補

PR #334のmerge `3814b3ea` と同tree `c28d0437` のsource `e7bdf83f` を
2担当へread-only分担し、rootが全候補を実sourceで照合した。以下は未実装の候補で、完了扱いにしない。
新しいworktree/cacheは作らず、製品コードやテストケースの変更・実行も行っていない。

1. PG接続処理を既存ownerへ寄せる。
   `apps/operator/src/bin/fee_escrow_inventory_pg.rs:149` / `:161` と
   `apps/operator/src/common.rs:531` / `:539` は同じTCP/TLS検査と接続pool構築を持つ。
   inventoryも `common::connect_pool` を使い、pool上限4、10/30/300秒の設定、DSN/certificate診断、
   既存TLS必須条件とnamespace/blob/fenceの評価順序を保持する。元のinventory controlsは残す。
2. SDKの表示フィールド検査を共通化する。
   `clients/rust/src/fee_claim_review.rs:163` と `clients/rust/src/publication_review.rs:204` の
   `display_safe` はerror型以外同じ。private helperから各既存errorへ写像し、
   byte長優先、ASCII `0x20..=0x7E`、field名とコピー前の拒否を保持する。
   両consumerの独立controlsとpublication reviewのintegration controlsは残す。
3. SDKテストのFIFO transportを共有する。
   `clients/rust/tests/paid_execution.rs:194` と `clients/rust/tests/publication.rs:271` の
   request記録付きFakeTransportは同一。test-only supportへ移し、request clone後のFIFO消費、
   exhaustion時のpanicを保持する。response/context/signing/expected payloadは各test側に残す。
4. テストのread-only archive snapshotを共有する。
   `apps/operator/tests/business_import_sqlite.rs:248` と
   `apps/operator/tests/support/recurring_host_acceptance.rs:2227` は同じ再帰snapshot。
   relative PathBuf key、directory=None、完全なfile bytes、symlink/nonregular拒否を保持し、
   before/afterの比較assertionとfloorのcase matrixは各callerに残す。flat inventoryとは統合しない。
5. 捕捉済みprocess outputの成功検査を共有する。
   `apps/operator/tests/business_cut_sqlite.rs:77`、`business_import_sqlite.rs:198`、
   `conditional_readiness_sqlite.rs:63`、`support/successor_host_acceptance.rs:227` は同一。
   status検査と両diagnostic streamの表示後、stdoutをstrict UTF-8で返す小さなhelperにできる。
   spawn/wait、pipe収集、deadline、出力固有assertionはこのhelperに移さない。
6. CI契約テスト内の重複assertion手順を共有する。
   `scripts/test-ci-gates.mjs:674` と `:685` の2 loopsは同じ検査を繰り返している。
   discovery/executionの2回、list/exact、package/target、nocaptureの検査を同じtest helperへ寄せられる。
   PG/recurringの独立したcase inventory、元selector/順序/件数と全assertionは保持する。

小さく始める候補は1/3/5/6。2は公開errorの写像、4は再帰snapshotの観測意味を確認して進める。
SDK rendererのbyte予算計算にも類似はあるが、16,384/65,536の上限、field数優先の違いと
hex割当て前検査があるため、renderer全体の機械的な統合は候補に含めない。
FastVote/ordered-economics deadline計算はclock sampling・cap・overflow errorが異なる。
独立wire vector、独立expected values、SQLite startup child/output collectorも一括統合しない。
同じ境界を検証する重複test functionの削除候補は今回確認できていない。
元の85 checkbox /71完了 /14未完了とD02/M1/M2/M3/M7の親5件は変わらず、停止対象は再開しない。
