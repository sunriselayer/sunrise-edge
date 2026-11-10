# Sunrise Edge: 実装・検証・公開準備

更新: 2026-11-10 (Asia/Singapore)。これは唯一の現行作業表です。
現行チェックは **85件中71件完了・14件未完了**。残るコード・検証の親は
**D02/M1/M2/M3/M7**、停止中の子3件と公開準備の親6件も未完了です。
以下の行を現行状態とし、祖先sourceの成功や部分実行を親の完了へ転用しません。

設計は[architecture](docs/architecture/README.md)、実装場所は
[code map](docs/development/code-map.md)、整理の決定は
[DR-0236](docs/architecture/decisions/0236-separated-code-verification-and-launch-tracking.md)です。
E1-E222の原記録と日付別の実行・失敗履歴は
[保存済み実行証跡](docs/development/history/todo-evidence-through-2026-11-03.md)
へ移しました。原条件は[移行前TODO](docs/development/history/todo-before-reconstruction-2026-10-13.md)
と[元ロードマップ](docs/development/history/roadmap-through-2026-10-06.md)に保存しています。
証跡は必要なE番号・原条件だけを辿ってください。

2026-11-05に[PR #345](https://github.com/sunriselayer/sunrise-edge/pull/345)
をmergeした。readiness/successorの選択済み別UID境界を実装し、N1の元ownerを実UID fixtureで検証。
N2の元7 epoch/e8 selectorはexact `049dcd59`で実UID正例を含め終端成功した。
外部検証記録: `n2-049d-retry1-terminal-1104/root-verification.md`。
同sourceのNative13 A/Bと原12 RELEASE runtimeは成功し、後者は104 passed / 0 failed / 3 ignored。
literal npm ciと完全required、全8 CIも終端成功した。外部の完全required終端記録は
`m2-required-049dcd59-1105-v11-b4c9a60d27f5-terminal-success-handoff.md`。
全M2/M7の最終独立review・issue dispositionは残る。
[PR #346](https://github.com/sunriselayer/sunrise-edge/pull/346) も2026-11-05にmergeした。offline genesis
authorの[DR-0286](docs/architecture/decisions/0286-standard-asset-genesis-protected-review-worker.md)
境界を実装し、既存author 7件と別UID ignored 1件を限定検証した。
[検証記録](docs/development/validation/2026-11-04-m2-genesis-protected/README.md) は
実承認役割・鍵・ceremonyやrelease資格を確定しない。同source CIは全8件成功。
exact `25a86df1` のreadiness同一鍵別path復元は別UID ignored fixtureを終端成功で確認した。
外部検証記録: `n4-readiness-25a-1104-owned-v2/terminal-v2.json`。
exact `25a86df1`のliteral npm ciと完全requiredは全20実行記録がexit 0・EOF/waitで
終端成功し、source不変とPID/cgroup解放を確認した。外部終端記録:
`m2-required-25a86df1-1105-v8-a16b5e9d-terminal-success-handoff.md`。
これは同sourceの資格であり、RELEASE資格と親M2/M7の完了ではない。
親M2/M7は未完了。
[PR #347](https://github.com/sunriselayer/sunrise-edge/pull/347) は2026-11-06にmergeした。
文書とAGENTSだけのexact `38575295`で全8 CI、literal npm ciと完全requiredが
終端成功した。元7 epoch/e8 selectorを含む20 command/40 streamのexit 0・EOF/wait、
source不変、PID/cgroup解放を別途照合した。merge commitは `add45bb62`。
これは文書統合sourceの資格であり、親M2/M7の未達を解消しない。
[PR #348](https://github.com/sunriselayer/sunrise-edge/pull/348) は2026-11-07
(Asia/Singapore) にmergeした。exact `d3c57cbc`のliteral npm ci・完全required、
全8 hosted CI、元7 epoch/e8の実UID N2誤鍵拒否fixtureを終端成功で照合した。
fixtureは誤鍵拒否2件・別UID起動2件・e8の1832-byte候補とACK各2件、
EOF/wait/reap・既知PID/cgroup/Docker解放を確認。先のstaging失敗2件は別に保全した。
merge commitは `8fc79746`、treeは検証済みheadと同一。M3の新selectorも
同headの完全requiredとCIで成功した。これは選択済みcomponentの資格であり、
親M2/M3/M7、停止中fault、最終独立security/release reviewは未完了。
[PR #352](https://github.com/sunriselayer/sunrise-edge/pull/352) は2026-11-08にmergeした。
original bondのseed-free構造プレビューをexact `0907bb22`で確認し、同sourceの
literal npm ci・完全requiredはV5でexit 0/実EOF/wait、全8 CIも成功した。
外部終端記録の移動先は `sunrise-edge-validation-1013/home-temp-relocations-1108.json` に記録。
初回CIのDeno取得504と先行V4のdisk-floor失敗は別に保全する。
内容承認・実登録・保護署名の証拠ではなく、
親M2/M7と停止中の子条件は未完了のまま保持する。
[PR #353](https://github.com/sunriselayer/sunrise-edge/pull/353) は2026-11-09
(Asia/Singapore) にmergeした。successor bondのseed-free構造プレビューを
exact `6fec1e5d`で確認し、literal npm ci・完全required、元7 epoch/e8 selector、
全8 CIが終端成功した。e8の1832-byte候補とcommitted ACKは各2件。
merge commitは `cfe02169`、treeは検証済みheadと同一。これは内容承認・実登録・
protected governance署名や親M2/M7の完了ではない。
[PR #355](https://github.com/sunriselayer/sunrise-edge/pull/355) は2026-11-09に
mergeした。文書・TODOのexact `6209977b`でliteral npm ci・完全requiredと
全8 CI・Bugbotが終端成功し、元7 epoch/e8 selectorの候補2件とACK、
raw/EOF/wait/reap・source不変・PID/cgroup解放を照合した。merge commitは
`d044d436`。これは文書sourceの資格であり、親M2/M3/M7を完了しない。
[PR #356](https://github.com/sunriselayer/sunrise-edge/pull/356) は2026-11-10
(Asia/Singapore) にmergeした。incoming successor E5を保護するe1の実UID
fixtureをexact `3d5687d4`で終端成功し、元7 epoch/e8 selector、候補1832 bytesと
committed ACK各2件、literal npm ci・完全required、全8 CIを同headで確認した。
初回fixtureのEACCES失敗は保全し、成功したr2のraw/EOF/wait/reap・Docker/
PID/cgroup・target解放を独立照合した。merge commitは `4c7ed157`。
これは後段e1のincoming鍵に限る資格であり、setup・後続epochs・全M2/M7や
独立最終reviewを完了しない。
[PR #357](https://github.com/sunriselayer/sunrise-edge/pull/357) は2026-11-10
(Asia/Singapore) にmergeした。選択済みoriginal genesis Standard Asset Coin rev1
全量transferの内側プレビューをexact `d3521522`で確認し、literal npm ciと
完全requiredのR2はexit 0・raw/EOF/wait/reap、source不変・PID/cgroup/target解放まで
独立照合した。元7 epoch/e8 selector、1832-byte候補とcommitted ACK各2件を維持し、
全8 CIも同headで成功した。R1のanchor失敗は別に保全した。merge commitは
`13ae8b30`。これは内側のseed-free構造プレビューの資格であり、保護署名・
実登録・親M2/M7の完了ではない。

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
    E191のlocal完全requiredまで成功。8da sourceではE213の完全required・E218の全8CI、
    E215のNative13 A/B・E219のpublication-genesis RELEASE・E222の元12 runtimeで照合した。
    ZeroShare専用WIPは未統合・未検証で、
    各familyの残るlifecycle/全体対応をそろえるまでM2全体は未完了。
    初期profileの既存要件照合と、停止対象を除く具体的な次作業は
    [M2初期リリース対象の照合](#m2初期リリース対象の照合-2026-11-03) にまとめる。
    実鍵ceremonyの公開条件と区別する。
    2026-11-04にoffline genesis authorへ別process/UID境界を選択し、既存author/buildと
    installerを使うgenesis専用二段階review workerを実装した。独立source指摘3件を修正し、
    既存author非ignored 7件と別UID ignored 1件 (4 validator installを含む) は限定環境で成功。
    [N3限定検証](docs/development/validation/2026-11-04-m2-genesis-protected/README.md)
    は最終source全体gateや実承認者・鍵の証拠ではなく、親M2は未完了。
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

### M2のfamily別対応と残件 (2026-10-30)

main統合時のsource `34da6a55` / tree `10b53dc5` を、上の実績と各familyの既存契約へ対応付けた。
このtreeの完全required/全8 CIは `5ac947f3` の記録を参照する。
後続source `ef0cea4e` のapplication Coin復旧鍵consumerは2026-10-29の検証記録、
`76345c53` の初回create/mint-burn consumerは2026-10-30の検証記録を参照する。
以下の「完了」は各行に示す選択済み子条件の範囲であり、親M2の完了や最新sourceのRELEASE認定ではない。
新しいoperation・identity・authorityやtrust条件を追加する表ではない。

| Family | 実装・実検証で確認済みの範囲 | 残件・境界 |
| --- | --- | --- |
| Publication / kind1 | E9/E21/E22の別UID承認・取消・同一鍵復旧・独立した新鍵/config/approvalの検証 | 選択済みlocal componentは完了。署名済み要求の取消、account移行や実ceremonyとは別 |
| Genesis whole-Coin transfer / kind2 | E149のA→B→A ownership、E203-E205の復旧同一A鍵によるlive操作と取消後restart | 選択済み子条件は完了。wallet/account/fee全体の正の鍵交換とは別 |
| Genesis split/merge / kind3 | E174のforeign split/返送、E206/E208/E209の復旧同一A鍵によるself操作とrestart。77f6の4完全profiles・完全required・全8 CIで、独立foreign-split profileの復旧同一A鍵によるlive splitとrestart、元Bの返送を確認 | 選択済みconsumer接続は完了。B鍵復旧、正のidentity rotationやwallet/account/fee全体の移行は含めない |
| Genesis mint/burn / kind4 | E212/E213/E218/E219/E222の復旧同一A鍵によるlive mint/burn・restartと元runtime | 選択済み子条件は完了。古いE41/E141のlive未接続やgate待ちを現在の残件に戻さない |
| Create-asset / kind5 | E49の実create/receipt/replay/取消とE141の歴史frame署名復旧を保持。7634の4完全profiles・完全required・全8 CIで、early同一復旧鍵による初回live createと取消後restartを確認 | 選択済みconsumer接続は完了。新identityへの正のrotation、creator/TreasuryCap移行や実ceremonyは含めない |
| Own-created application mint/burn | E62の実supply遷移とE67のhistorical burn復旧・取消/restartを保持。7634で初回create前にearly復旧pairを作り、初回live mint/burnと取消後restartを接続し、4完全profiles・完全required・全8 CIで確認 | 選択済みconsumer接続は完了。historical停止後copyと後続6-stage用のlater復旧鍵を維持し、全M2や正のidentity/ownership rotationは含めない |
| Application Coinの既存6 stages / kinds2/3/4 | E74/E75の有料操作とhistorical復旧を保持。ef0の4完全profiles・local完全required・全8 CIで、既存復旧鍵による6 live操作と5 groupsの取消後restartを確認 | 選択済みconsumer接続は完了。初回create/初回application mint-burn、正のidentity rotationや全M2はこの範囲に含めない |
| Positive fee-claim strict partial Split | E128の実protected候補送信、Leg/Claim別承認、永久取消、復旧/restart/expiry/rotation mismatch | 選択済みcomponentの範囲。live escrow/nonce/entitlementや新しいhistorical identityへの正のrotationはこの結果へ含めない |
| ZeroShare / FinalTransfer fee claims | E23/E24のsaved review・開発用署名とFinalTransfer structural表示 | ZeroShare WIPは未統合・未検証・停止中。FinalTransferは既存positive Split serverの対象外で、具体的なprotected backend契約は未確定 |
| Automatic original ordered proposal/vote | E91のworker/frontend分離とTLS/UID、E194/E198/E199の同一identity復旧とgate | 選択済みoriginal epochの同一host復旧。新identity/membership、後継epochやoff-host復旧は別条件 |
| Automatic certified FastVote/availability ACK/original frontier vote | E129の21-route UID/TLS、E194の復旧path・vote/ACK一致とfresh paid business | 選択済み同一identity復旧。人のasset承認とは別のlive authority条件を保持し、正のidentity/membership rotationや本番復旧操作を含めない |

[ef0のfixture](https://github.com/sunriselayer/sunrise-edge/blob/ef0cea4e33e942f22aa40379e6d426579f846109/scripts/check-docker-custody-fixture-1013.mjs) で、
`phase_own_asset_mint_burn` が生成する `own-recovered.seed.restored` を、後続の
`phase_own_asset_coin_operations` の既存6 stagesと全5 groupsの取消後restartへ接続した。
元47 setup predicates、historical signing-only controls、operation/approval/frame/receipt/
nonce/counterと元profile別上限を保持し、追加2 flagsは別に照合した。
[実検証記録](docs/development/validation/2026-10-29-recovered-application-coins/README.md) の
4完全profiles・同sourceの完全required・全8 CIでこのconsumerを完了した。
[初回consumerの検証記録](docs/development/validation/2026-10-30-initial-recovered-application-key/README.md) では、
初回create前に既存helperで2files/2copychildrenのearly復旧pairを作り、初回create・mint/burnと
両取消後restartの4実child argvを同じ復旧pathへ接続した。原47・prior2・historical9を保持し、
新initial3 predicatesは別に検査した。実4完全profiles・同source完全required・全8 CIが成功したため、
この初回consumerの接続は完了。残る全accepted family対応・正のidentity/ownership rotationや実ceremonyへは拡張しない。

[prepared signing owners](docs/architecture/signing-preparation.md) のtransaction/local/general/paid/bond等は、
prepare/finalizeの共通化や開発用LocalSignerだけでprotected backendの受入済みfamilyにはならない。
全accepted familyの有限な一覧とprotected governance consumerの具体契約は、参照した既存M2資料では
まだ確定できない。ProposedのDR-0214をAcceptedへ読み替えず、不明な全体対応を完了にしない。
同一鍵復旧・鍵違い拒否・正のownership/identity rotationは別々に扱い、application creator/
TreasuryCap・account/feeの移行をgenesis Coin handoffから推定しない。
実役割/実鍵/ceremony/実topologyはD04/D06/D07、Ledgerは既存deferredのまま保持する。

### M2初期リリース対象の照合 (2026-11-03)

照合したmainは `8afaf3566294fe3d6e2096ac4107d2270439b7a8`、tree `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e`。
現行statusの照合元は `c12bc7d176a65efeabcec414e918b7f6a17b72b2`。
以下の表とN1〜N5の「着手可」はこの日付のsourceに対する照合記録であり、
2026-11-04の選択・開発差分より前の状態を示す。現在の実行順は下の
[次の実行順](#次の実行順) と冒頭の未統合差分を参照する。
以下は既存決定から確定できる技術範囲と不足であり、公開release profileの承認や
ProposedのDR-0214の受入ではない。初期ネットワークを狭く呼び替えて、既存の
protocol-v3 activation・membership/epoch・protected signing条件を免除しない。

#### 元要件と初期profileの境界

| 既存要件の根拠 | 今回の照合結果 | 残す責務 |
| --- | --- | --- |
| [DR-0208](docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md) | Native+SQLite first、DO後続、Ledger製品の必須化を解除。ローカルOSを信頼する個別componentは後続ADRで実装済み | key保護・役割分離・操作内容確認・失敗拒否・復旧/交換/取消は引き続きM2。plaintext seedやLocalSignerだけで代替しない |
| [DR-0211のautomatic/readiness要件](docs/architecture/decisions/0211-external-signing-preparation.md#content-review-and-automatic-signing) | automatic signingとreadinessは別owner。後者は当時未選択だったが、後にDR-0284で境界を選択し開発workerを実装した | readiness保護を任意の追加機能として消さない。actual key/eligible identity・retained slotと独立した署名検証を維持する。各voteに人の承認を加えない |
| [DR-0264](docs/architecture/decisions/0264-original-ordered-protocol-custody-worker.md)、[DR-0268](docs/architecture/decisions/0268-certified-fastvote-protocol-custody-worker.md) | protected automatic workerはoriginal orderedとcurrent certifiedの閉じた範囲。この時点のsuccessorは選択範囲外。後にDR-0285で別境界を選択した | recurring/successorの機能的合格をprotected successor signerの合格にしない。初期profileで実際に使うsuccessorのauthority/host境界を定義する |
| [DR-0214](docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)、[既存署名経路表](https://github.com/sunriselayer/sunrise-edge/blob/8afaf3566294fe3d6e2096ac4107d2270439b7a8/docs/architecture/signing-route-test-map.md) | 署名準備型、認識済み操作、保護backendは別。genesis作成は実consumerだが、汎用admin signerは存在を仮定できない | 実consumerごとのauthority・承認内容・backendを確定する。単にprepared型があるという理由で全familyを必須化せず、現在の拒否も外さない |
| [DR-0236](docs/architecture/decisions/0236-separated-code-verification-and-launch-tracking.md)、[DR-0208のlaunch分離](docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md#2026-10-11-bounded-docker-and-launch-scope-amendment) | disposable鍵・値でのparameterized実装/検証は進められる | 実operators/key/recovery roles、genesis/economics、実ceremony・topologyはD04/D06/D07/M6/M8。fixture値で本番を決めない |
| [元activation条件](docs/development/history/roadmap-through-2026-10-06.md#fastvote-certified-execution-gate)、G | 既存の全accepted familyの認証/認可と元release条件を保持 | 狭いcomponent合格や今回の文書照合でM2/公開readinessを完了にしない。停止済み監査の再試行もこの作業に含めない |

#### 初期候補へ対応付ける実consumer

| 区分 | 実consumerと既存の範囲 | 初期profileでの扱い |
| --- | --- | --- |
| 選択済みinteractive component | publication、genesis transfer/split/merge/mint/burn、create、自己作成applicationのmint/burn/Coin操作、positive strict partial SplitのLeg/Claim | 上のfamily表の完了範囲を保持。同一鍵復旧・取消後restartの追加接続漏れは今回も特定していない。SDK fake、実UID、RELEASEの証拠は分ける |
| 選択済みautomatic component | original ordered proposal/voteとcertified FastVote/availability ACK/original frontier voteのworker/frontend | 元ADRの閉じた経路と同一identity復旧まで。successor/readiness、新membership・off-host復旧まで対応済みとはしない |
| 選択済み境界の全体資格が残るprotocol owner | `conditional_readiness::ReadinessSigningKey` / operator readiness、`successor-host`の実署名consumer | DR-0284/0285で選択した開発workerを元ownerへ照合する。N2元recurring ownerはexact `049dcd59`の実UID正例を含め成功。後続sourceの全体資格は未達。coreの既存authority/retentionや原profileを縮めない |
| 保護署名の対象選択が残るinteractive/author owner | generic local/general・paid、bond registration、FinalTransfer fee claim、offline genesis author | generic/paidはcustody拒否、bond/claimはdevelopment署名で未選択。offline genesisだけDR-0286の別UID workerを開発実装・限定検証した。実承認役割/鍵、全体資格は未達。未選択経路を自動接続しない |
| 引き続き対象外 | Ledger製品、追加provider/HA、新たな汎用admin signer、未選択の広いasset/account移行 | 元のdeferred/未選択を保持。新backendや新しい公開操作をこの照合から承認しない |

#### 停止対象を除く有限な次作業

M2-N1〜N5は既存M2の不足を分ける作業IDであり、新しい親gateやcheckboxではない。
以下の表は2026-11-03の元照合条件を保存する。後日の選択と限定実装・実検証は
冒頭と下の現行差分に記す。publication向け判断から他roleへ暗黙に拡張しない。

| ID / 現在の状態 | 必要な実装・設計作業 | 完了とするための検証・成果物 | 依存/着手条件 |
| --- | --- | --- | --- |
| M2-N1 / 設計から着手可 | readinessのparameterized protected-provider契約を、既存のeligible key・complete inactive target・retained slot ownerへ対応付ける。実hostの鍵load/署名/retained returnを列挙し、providerとhostの責任、停止/拒否/復旧を定義する | architectureと日付付きADRに具体consumer・expected key/domain・既存retentionとの境界を記録。選択後に実hostを接続し、既存readinessのexact owner内で正常署名、wrong-key/拒否、再起動/retained reconciliationを検証する。prepared/fakeだけの成功で閉じない | DR-0211の残件。設計整理は実鍵/実operator待ちにしない。backend接続はそのroleの具体契約確定後 |
| M2-N2 / 設計から着手可 | successorの自動署名consumerと、original workerだけでは満たせない初期profileの差を列挙する。fresh serving warrant・committee/key一致・writer fence・confirmed retentionを元ownerに残す具体契約を定義する | accepted profileの実host/署名domain/authorityを有限に記載し、選択後のhost接続と元recurring ownerによる実検証を行う。通常hostの平文seedや原epoch worker成功をsuccessor保護の証拠にしない | M2-N1と独立して設計可能。新しいIPC/raw-frame署名契約を先に実装しない。元のmembership/epoch条件を削減しない |
| M2-N3 / 要件・対象選択の整理から着手可 | generic local/paid、bond registration、FinalTransfer、offline genesis authorを、初期profileで必要な具体操作へ照合する。各行を対象/非公開・未対応/後続へ根拠付きで分類し、genesis/adminは実在するconsumerだけを扱う | 対象に選ぶ行にはauthority、認識済みcode/semantics、完全review内容、backend契約を記録。確定した行に限り既存prepared ownerまたはgenesis author/build ownerを使って具体consumer/backendを接続し、exact-byte/返却署名検証・誤入力/未知操作拒否・実consumerの操作結果を元test ownerで確認する | 型が存在するだけでは実装必須にしない。対象外指定で元accepted機能/activation条件を免除しない。安全判定で停止したZeroShareはこの分類・実装候補から除外 |
| M2-N4 / 対象別仕様の整理から着手可 | N1〜N3と選択済みfamilyごとに、同一鍵復旧・provider停止/取消・新identityへの交換で必要な動作を区別する。既存authorized operation/epochで可能なcutoverと履歴保持、未対応を明示する | 必要と決めた移行だけ、既存authorityの正の移行と旧権限の扱いを実ledger/receiptで検証する。同一鍵署名一致・wrong-key拒否を正の移行に数えない。新address alias、creator pin緩和、historical claimant書換えを解決策にしない | 残るrotation/revocation要件の具体化。B鍵復旧、全account/fee/TreasuryCap移行、off-host復旧を自動で新必須gateにしない。完了済みconsumerを再実装しない |
| M2-N5 / 対象source確定後 | 確定した対象と必要なN1〜N4変更を、既存実test owner・source/tree・profile別の証拠へ対応付け、欠ける検証だけを実行計画へ落とす | 既存4完全custody profiles、positive Split、ordered/certified UID、readiness/recurringの該当ownerを選び、実行した範囲のraw/actual exit/EOF/wait/reap/資源解放を照合する。runtime変更後はGのliteral npm ci+完全required・exact-source CIと必要なrelease資格を満たす | 今回のTODO変更や既存証拠の整理だけを理由に製品gateを再実行しない。元selector/timeout/7epochs/e8のwithdrawal候補2件/8links/35rolesを保持。RELEASE/原13-target A/B等は元の適用条件でM7と共用 |

### M2-N3/N4の現行区分 (2026-11-04)

| N3の実経路 | 現行区分と残件 |
| --- | --- |
| generic local/general・paid | 既存CLIはcustodyをI/O前に拒否する。認識済み操作・権限・review内容が選ばれるまで別backendを接続しない |
| bond registration | [DR-0287](docs/architecture/decisions/0287-bond-registration-structural-preview.md) のoriginalと[DR-0288](docs/architecture/decisions/0288-successor-bond-registration-structural-preview.md) のsuccessor seed-free構造プレビューはPR #352/#353の完全required・全8 CIで成功。#353は元7 epoch/e8 selectorでも成功。[DR-0289](docs/architecture/decisions/0289-bond-outer-key-custody-and-split-approval.md) で外側の新validator鍵の別process/UID保護と、担保移動・登録の承認者分離を選択。[DR-0291](docs/architecture/decisions/0291-original-bond-inner-standard-asset-profile.md) でoriginal genesisのmanifest固定Standard Asset Coin rev1 `transfer`、全Coinの導出済みBondCollateral deposit tokenへの移動と、内側source-owner鍵の別process/UID保護を初期対象に選択。`6095e6d2`でmanifest/code/effects照合、段階別UID承認とexact frame結合、別UID鍵worker・brokerのdevelopment実装をコミット・pushし、独立静的レビュー2件はPASS。`7a6fb1a2`の既存bond CLI ownerで保護inner実出力からouter承認・署名への結合を検証し、16/16成功（外部記録`bond-protected-link-1110/exact-head-bond-registration.receipt.json`、raw log SHA256 `45a735e5`）。PR #358のexact `ff003d92`では同ownerの保護結合を維持し、literal npm ciと完全required R3をexit 0・実EOF/wait/reap・source不変・unit/PID/cgroup/target/一時領域解放まで独立照合した。元7 epoch/e8と異なる1832-byte候補・committed ACK各2件も確認した。R1/R2失敗は別に保全し、全8 hosted CIも同headで成功。PR #358はmerge commit `75521d62`でmainへ統合した。source現行性の運用証明、実承認者・鍵のenrollment、release資格は未達。successorのlive-epoch担保移動はこの限定profileに含めない。development構造claimは`executed=false` |
| FinalTransfer fee claim | development署名の経路でありpositive Split custodyに含めない。具体authorityとreview契約は未選択 |
| offline genesis author | [DR-0286](docs/architecture/decisions/0286-standard-asset-genesis-protected-review-worker.md) の二段階workerを実装・限定別UID検証済み。実承認者/鍵/economics/ceremony、全体gateは未達 |

original bondの既存node-core ordered登録ownerでは、`184ef2a3`で内側
source-owner鍵と外側validator鍵を分離した正例を追加し、既存commit・全replicaの
担保object/nonce/登録chain/receipt照合を再利用した。新旧の限定テストは各1件成功。
これは同ownerのlocal test signerによる実ordered効果の証拠。PR #359のexact
`eb88a848`ではこの限定正例と既存正例を各1件成功で確認した。同headの全8 CIと
literal npm ci・完全required R1はexit 0、実EOF/wait/reap・source不変・unit/PID/cgroup/
target/一時領域解放まで独立照合し、元7 epoch/e8・異なる1832-byte候補と
committed ACK各2件を保持した。PR #359はmerge commit `d4264777`でmainへ統合した。
後続[PR #360](https://github.com/sunriselayer/sunrise-edge/pull/360)の`b90d855a`ではnode-core fixtureの正規genesis/current Coinを保護CLIへ渡し、
実inner/outer workerの出力bytesを元ordered ownerへ戻すテスト専用結合を実装した。
独立静的reviewはPASS。限定R5は結合1/1、通常CLI 1/1、pinなしbaseline 1/1が成功し、
不完全pinは期待どおり拒否された。失敗したR1/R2と修正前R3/R4の証跡は別に保全する。
外部終端記録は`m2-bond-handoff-focused-1110/ordered-handoff-final-focused-terminal-audit.json`。
最終source `8827a7b7` / tree `643c42ec` のliteral npm ci・完全required R2は
exit 0、実EOF/wait/reap・source/tool不変・unit/PID/cgroup/一時領域解放まで独立照合した。
元recurring selector各1/1、7 epochとe8の異なる1832-byte候補2件・committed ACK各2件も確認した
（外部記録`bond-handoff-final-8827a7b7-1110/required-inert-r2/required-bond-handoff-r2-unit/unit-terminal.json`）。
同headの全8 hosted CIも成功し、PR #360はmerge commit `a023cb94`でmainへ統合した。
この証拠はテスト専用結合のsource資格であり、運用上の署名前source現行性、
実承認者・鍵のenrollment、親M2/M7・release資格は引き続き未達。

original bondの初期releaseでは、人が[DR-0292](docs/architecture/decisions/0292-original-bond-trusted-local-currentness.md) の
指定ローカルserving nodeを信頼境界に選択した。chain-state proofとは呼ばない。
`cbcd82ad`で同一store・fenceからの局所観測に使う読み取り専用primitiveを追加し、
公開constructorを閉じた。隔離環境の限定3テストはCurrentInlineの一致・拒否、
実SQLiteのgenesis Coin、誤validator・古いfence、token中の書込み/変更を確認した
（外部記録`m2-currentness-1110/opaque-fix-49cc/result.txt`）。`746c0734`では
元ホストのfence取得後、同一storeを使うopt-in認証付きUnix照会口へ接続した。
隔離環境の限定5テストはpeer UIDの本文前拒否、Coin/tip観測、古いfence、
同じsocket pathでのrestart、設定・確認フラグの拒否を確認した
（外部記録`m2-currentness-1110/listener-d4db/result.txt`）。
`e6ba7490`ではlistenerの期限・接続上限後にbond照会だけを閉じ、通常HTTPを
継続するよう修正した。隔離Dockerの元compiled host UID12001と許可client UID12002、
同groupの拒否UID12003で元ignored selector 1/1が成功。実Coin/token/tip、
proof=false、期限・上限後のsocket削除とHTTP 200、fence更新後restart、
実EOF/wait/reap・container解放を確認した
（外部記録`m2-currentness-1110/multiuid-a0aa/result.txt`）。
`fccd23a9`では局所観測の要求・応答codecを`node-wire`へ一元化し、既存listenerを
同じcodecへ移した。変更前の154-byte要求・405-byte応答と独立照合した固定vector、
不正frame拒否の限定3件、operator listenerの限定1件が隔離環境で成功し、
独立静的reviewもPASS（外部記録`m2-currentness-1110/codec-7b02c7d2/result.txt`）。
復号した観測値は未認証の局所locatorであり、chain proofや現在性承認ではない。
`50338c2a`ではCLIの私有optional node設定をcomplete-or-refuseで追加し、
socket・server UID・元validator・正確なstore namespaceとverified genesis由来の
chain/domain/committee/anchorを照合する単一clientを実装した。peer UIDの送信前確認、
有限時間のframe/EOF、先行観測の全token/tip一致と拒否を限定7テストで確認した
（外部記録`m2-currentness-1110/client-46256109/terminal-release.txt`）。
このclientはPR #361時点では呼び出されず、単独で現在性を保証しない。
後続[PR #362](https://github.com/sunriselayer/sunrise-edge/pull/362)ではrequest v2へ正規locatorを結び、
CLI両承認者の確認前後、brokerの承認記録・challenge・署名返却前と鍵workerの署名前に
独立再照会を接続した。期限は再照会後に確認し、v1のpinなし経路とsignable frameを維持する。
既存bond multi-UID ownerにsynthetic nodeの通し経路、直接broker/worker拒否、
変更fence拒否を追加し、別UIDが実行する同じtest harnessを検証付きで一時領域へコピーする。
独立静的reviewは順序修正とcopyまでPASS。実行テスト・完全required・同head CI、
実hostと保護署名を結ぶ検証、実承認者・鍵のenrollment、release資格は未達。
synthetic nodeをchain proofや実hostの現在性証拠にせず、親M2は未完了のまま。

FinalTransferの既存codec・prepared consumer・review表示・development signer・
positive Splitとの権限分離を[署名経路マップ](docs/architecture/signing-route-test-map.md#finaltransfer-within-the-prepared-fee-claim-owner)へ対応付けた。
これは静的な所在確認であり、未選択のauthority・leg semantics・承認内容・backend、
実consumerの保護署名と検証は未達のまま保持する。

N4では、同一identityの鍵復旧、provider停止/取消後restart、新identityへの正の移行を
分ける。N1 readinessの元ownerは別UID・retained voteを確認した。N2の元recurring
7 epoch/e8 ownerと実UID正例はexact `049dcd59`で成功した。N4の同一鍵別path復元も
exact `25a86df1`の別UID ignored fixtureで成功した。いずれも限定sourceの証拠であり、
同一鍵署名一致やwrong-key拒否は新identity移行の
成功ではない。別公開鍵は別addressであり、既存の認可操作・epochと履歴検証だけを対象別に
照合する。新address alias、creator pin緩和、historical claimant書換え、包括的な
B鍵/account/TreasuryCap/off-host移行を新gateに追加しない。

N1/N2の実workflow ownerは既存の
[`conditional_readiness_sqlite.rs`](apps/operator/tests/conditional_readiness_sqlite.rs) 内の
`compiled_conditional_readiness_real_retention_restart_and_distinct_certificate` と
`compiled_registered_replacement_and_recurring_successor_hosts`。新しい短縮版を複製せず、
保護境界の追加分だけを元ownerへ対応付ける。positive Splitのlive escrow/nonce/entitlementは
元store-backed preparationとordered executionの責務であり、custodyへ重複実装しない。

N1の現行consumer・core保持境界と別UID worker案は[DR-0284](docs/architecture/decisions/0284-conditional-readiness-protected-worker-proposal.md) に整理した。
N2の実successor hostと別UID worker/frontend案は[DR-0285](docs/architecture/decisions/0285-successor-protected-host-proposal.md) に整理した。
2026-11-03に人が両roleへtrusted local OS・別process/UID境界を選択した。
N1は元readiness ownerの実UID 10001/10002、wrong-key、lost-response、retained restartを
[限定検証](docs/development/validation/2026-11-03-m2-readiness-worker/README.md)で確認した。
N2のworker/frontend開発実装だけを元recurring acceptanceに数えない。元selector
`compiled_registered_replacement_and_recurring_successor_hosts`はexact `049dcd59`で
1件成功、7 epoch ends、実別UID marker 2件、e8 terminal unlockと1832-byte候補2件を
外部検証記録 `n2-049d-retry1-terminal-1104/root-verification.md` で終端照合した。
N4同一鍵別pathの別UID fixtureはexact `25a86df1`で成功。exact `049dcd59`の
literal npm ci・完全required・全8 CI・Native13 A/B・原12 RELEASE runtimeは成功した。
exact `25a86df1`の全8 CI・literal npm ci・完全requiredも終端成功し、
元の7 epoch selectorを保持した。適用される後続sourceのRELEASE資格は未確認。
2026-11-06にN2の既存recurring ownerへ、保護workerの誤鍵起動拒否を追加した。
別鍵は実member key mismatchで拒否し、fenceの既存進行だけを許して
他のmetadata・receipt・blob行と署名routeを不変とする検証である。
元targetと統合後のtest targetのビルド・Clippy・fmtは成功した。
記録訂正前のexact `17946e42`でliteral npm ci・完全requiredはexit 0、実EOF/wait、
process group解放、source不変で終端し、通常分岐の元7 epoch/e8も成功。
ただし通常gateは`SUNRISE_SUCCESSOR_MULTIUID_FIXTURE`を設定せず、
追加したwrong-key別UID分岐は実行されていない。markerもrawにない。
同sourceのCIは記録訂正pushでcancelされたため成功に数えない。
最終exact `d3c57cbc`ではliteral npm ci・完全requiredと全8 CIが終端成功し、
通常分岐の元7 epoch/e8を保持した。別の実UID fixtureで同じ元selectorを
13,408.18秒実行し、誤鍵拒否2件・別UID 2件・epoch 1〜7終了・e8 unlock・
1832-byte候補とACK各2件・1 passed/0 failedをrawで確認。実EOF/wait/reap、
既知PID/cgroup/Docker解放、source/tool不変も独立照合した。
先のpartialとstaging失敗2件は別に保全し、成功へ合算しない。
[限定記録](docs/development/validation/2026-11-06-m2-n2-protected-wrong-key/README.md) を参照する。
後続`823671df`は既存offline genesis author ownerに二つの承認切断拒否を追加した。
PR #349のexact `c58c5444`で全8 CIとliteral npm ci・完全requiredが終端成功し、
元recurring selectorも1 passed/0 failed・約10,759秒で完走した。
初回完全gateはservice PATHに`cf`がなく最終型検証でexit 1、初回genesis fixtureは
compile serviceの作業ディレクトリ不足でexit 1となった。両失敗のrawとreceiptを保全した。
修正した専用環境での完全gateはexit 0・実EOF/wait/reap・PID/cgroup解放・source/CLI不変を
独立照合した。同じ`c58c5444`の別UID genesis V2 fixtureは既存7通常テストと
元ignored selector 1件が成功した。二つの切断拒否と4 validator installを
元testのassertionで確認し、単一の`both_refused` markerをrawで確認した。
raw/ELF hash、container/unit/PID解放も独立照合済み。
merge commit `a6ae6229`は同tree。これはN3の限定consumer資格であり、
未選択のgeneric/paid、bond、FinalTransfer、親M2を完了とはしない。
元original/certified
workerの証拠をsuccessorへ流用せず、N1/N2と親M2は未完了とする。

次は後続sourceの全体資格とN3の残る未選択対象を照合する。
この時点で未選択の新backend配線や新しい移行を実装しない。N1〜N5の成果を
既存M2の該当条件へ戻して記録し、親M2や元の独立security/release条件の代わりにしない。
停止済みD02/M1独立監査、ZeroShare WIP/fixture、M3 torn-WAL assessment/mechanism2、
独立anchor VM boot修正はこの実行キューに入れず、未完了・停止の記録だけを保持する。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を維持する。
今回の文書照合と静的検証は[記録](docs/development/validation/2026-11-03-m2-initial-scope/README.md) を参照する。

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
    E74時点のsourceの最終完全gate/CIは未完了だった。後続sourceの結果は下に記録する。
    host/power/media/fsync・別host/実topology failoverの証拠へ読み替えない。
    2026-11-06に既存の実TLS owner-loss helperへ、70KiBの参照付きhistorical bodyを
    保持する別selectorを追加。全4hostのSIGKILL/reap、次generation、保存済み再送、
    新規有料取引と最終停止までのbody・portable collectionsを照合した。
    新selectorと既存関連4件の限定実行は成功し、[記録](docs/development/validation/2026-11-06-m3-positive-owner-loss/README.md) を保存。
    記録訂正前のexact `17946e42`の完全requiredで新selectorも成功した。
    最終exact `d3c57cbc`の完全requiredと全8 CIでも同selectorが成功。
    別host/物理faultは未達で、M3親は未完了。
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
  - f093の新owning/SQLite libはE7、元5 ENOSPCはE8に記録済み。
    E210が通常coverageを対応付け済みであり、同じassertionを増やさない。
    selected-profileの物理host/power/media/fsync、別host writer failoverは未検証。
    E8/E169のENOSPC、E30/E193/E203/E206のTLS、E74の同host SIGKILL、E79の通常VMを
    他のresource exhaustion・fault条件へ転用しない。上記の停止中2子条件とD07の
    実topology rehearsalは別に保持し、親M3は未完了。

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
  - 8da sourceの歴史資格: E213のliteral npm ci +完全required、E218の全8 CI、E215のfresh
    Native13 A/B全byte/mode/owner一致、E216/E217のfresh23/current49と元一覧、
    E219のRELEASE publication-genesis 73 predicates、E222の元12 runtime101/0/3を
    同じsource/treeでroot照合した。外側143・集計失敗と未観測区間は保全し、
    製品本体の自然0/全raw/EOF/wait・inputs・全既知PID/cgroup解放を別途確認した。
    独立最終source/security/release reviewとissue dispositionは残り、全M7は未完了。
  - PR #348 exact `d3c57cbc`ではliteral npm ci・完全required、全8 CIと
    N2実UID元selectorを終端成功で照合した。merge commit `8fc79746`は同tree。
    PR #349 exact `c58c5444`では全8 CI、literal npm ci・完全requiredと
    genesis別UID限定fixtureを終端成功で照合した。最初の`cf` PATH不足と
    fixture作業ディレクトリ不足によるexit 1も別に保全。merge commit `a6ae6229`は
    exact `c58c5444`と同tree。merge後HEAD `a6ae6229`ではfresh Native13 A/Bの
    元13ターゲットを2回ビルドし、26 ELFを再hash、13組の全byte・mode一致を独立照合した。
    exit 0・実EOF/wait/reap・PID/cgroup解放も確認済み。この時点では元12 RELEASE runtime、
    独立最終source/security/release reviewとissue dispositionが未達だった。
    同HEADの元12用に別RELEASE source・専用Cargo cacheを固定し、Native13証跡と
    #348→#349の変更5 pathを照合した。独立review後に13 host/10 driver/2 exact ignoredの
    実行しない候補を生成した。候補manifest SHA-256は
    `24d86bf26d33c1e5a7c1ca50ea25a855c0d8040ceed1bcefdfd7b8c1b91ee279`。driver build・
    実測`--list`・12 runtimeは未実行で、候補の`PENDING`安全弁を保持する。
    続く専用driver buildでは13 debug host・10 test driverのcompileと全23 ELF再hashが
    成功したが、外側ownerはunit解放判定で`passed=false`を記録した。失敗記録を保持し、
    full-window監視の592サンプルと実資源解放を独立照合した。別の限定validatorは同じHEADの
    13 host・10 driverの23 ELF、1,310 source file、311 private archiveを再hashし、
    元の単一Description不一致以外のpredicateを満たすことを終端exit 0で確認した。
    限定compile資格のreceipt SHA-256は
    `e4d689d0d62c12c41c5f3cb59801aea984b3de2783e5e28f64d64b787734d410`。
    元の外側`passed=false`を成功に書き換えない。初回実測`--list`は22回すべて
    exit 0で候補一覧を生成したが、外側ownerは245msの短いunit実行を捕捉できず、
    admission SHAの取り違えもあり`passed=false`で終了した。失敗receipt
    `aa9cf2b779bb820379de26cad8b22612b8cac8031ffa7f2b119f7b0f94307796`を
    保全した。残余監視は135サンプル・停止時刻後の最終観測・実unit/cgroup不在を
    独立照合し、monitor receipt SHA-256
    `99912018576e6c36864a59cf6e2a70deb6e5317fcc5e18724101a4d841287f02`を記録。
    監視成功を元ownerの合格に転用しない。別outputの修正版は実行中unitの再観測を
    gateにして元10 driverのall/ignoredと2 exact ignoredの計22一覧を取得した。
    外側`passed=true`、22 exit 0/wait、実EOF/reap、unit/cgroup解放とsource不変を
    独立照合した。outer receipt SHA-256は
    `5165dcbc1e5b00a04736625c156697abac0f857d562a9656f860fe76c1fdb1c0`。
    一覧候補は確定した。次の`runtime-check`は新しいguard関数への引数を内部呼出しで
    渡していないためTypeErrorでexit 1となり、outer receipt
    `010c641c62b169fd15bcf89eff394d79ce12b21c28d8d2a85533b945fb18735c`を
    保全した。既知wrapper/worker PIDとcgroup不在を確認し、該当unitだけを`reset-failed`して
    前後の状態を保存した。監視は停止時刻後まで102サンプル全件でunit/cgroup不在を照合し、
    receipt SHA-256 `569181ef18a9807e4a01b1c7f7bc2daee70d51d724cb1ea4b9f9abdc8892ca2f`。
    owner終了から監視開始までの302.396秒は未観測として保持し、失敗checkを合格にしない。
    修正版の独立審査後、別outputの`runtime-check`を実行し、13 RELEASE host・
    13 debug host・10 driverの実hash、outer/child exit 0、EOF/wait/reap、
    bounded unitとPID/cgroup解放を独立照合した。outer receipt SHA-256は
    `62339e06620af0b917811af2f055278d42d5abd5b744efcc83db794c06e2693b`。
    初回`runtime-probe`はcallerが事前作成するprivate `probe-tmp`欠落でexit 1となり、
    失敗outer receipt
    `7338166742581de40551f10590ee24160d942d3491ff947da64540466770ba2c`を
    保全した。失敗unitの期限後まで162サンプル・全観測0エラー・既知PID/cgroup不在を
    監視し、terminal receipt SHA-256
    `30755462562245b93752e0eb9fa1e8a37eb5e47e6d092d67e98112d1b0c4a675`を得た。
    owner終了から監視開始までの189.054秒は未観測として保持し、失敗probeを合格にしない。
    必要な空のprivate `probe-tmp`を用意し、別admission/別outputで再検証した。
    新probeは13 RELEASE artifactの隔離view hash、loopback、独立PID/net名前空間を
    確認し、outer/child exit 0・実EOF/wait/reap・unit/cgroup/PID解放を独立照合した。
    probe外側receipt SHA-256は
    `51e09bf1e3548dd895fe98f4bc466ec894bbebe14a9e29dd578cbba305d13ed8`。
    続く同HEADの元12 RELEASE runtimeは10 wholeと2 exact ignored selectorを単発で実行し、
    12/12 exit 0・実EOF/wait/reap、105 passed・0 failed・4 ignoredを独立照合した。
    7 epochの全start/end、e8 terminal unlock、別々の1832-byte withdrawal候補2件と
    各committed ACK、13 RELEASE/13 debug host/10 driverの実hash、source不変、
    1,775 live unit samplesと全既知PID/cgroup/TMP解放まで確認した。外側receipt SHA-256は
    `0397cddf1962d9b196bbe0dd9b9ef5bc1119c76c43f3054f690463cc389e8b80`、
    内部receipt SHA-256は
    `2d8d184b3157bce45f0fb6828dfd0333c4123ce3fe54cecc9eb07858d7892b77`。
    e8の8 linksは実行したexact selectorの既存assertionに含まれる。35 rolesは別の
    `business_recovery` unit testのassertionで、この元12 runtime rawからの独立観測とはしない。
    独立最終source/security/release reviewとissue dispositionは未達で、親M7は未完了。
    PR #350の`81bde20f`では全8 hosted CIが成功したが、同HEADのlocal完全requiredは
    literal npm ciがexit 0、`./scripts/check-all.sh`がexit 101。実`/tmp`を使った
    再実行でも7 epoch後のe8 `pack-saved`で`recovery_budget_refusal=observations`となった。
    最終receipt SHA-256は`949c7cce3adb2ca8127b34562c28eba06a7c0144d3c9676e6252a04908a6c610`。
    rawのEOF・wait/reap・PID/cgroup解放とsource不変を確認済み。CIや祖先sourceの成功を
    このlocal失敗の代わりにしない。その後の`9981690a`では隔離したdirect `/tmp`を使い、
    同HEADのliteral npm ci・完全requiredをともにexit 0、rawのEOF・wait/reap、
    全既知PID/cgroup解放まで照合した。7 epoch後のe8 `pack-saved`もsuccess=true。
    終端receipt SHA-256は`3c27709c39a0f2897da25332ed1af0cbc3b4ed46616037fd8f37c6e9e20a13e1`。
    同HEADの全8 CIも成功し、PR #350の通常merge `7b8e7777`は検証済みtreeと一致。
    先の失敗は保全し、独立最終reviewとissue dispositionを残して親M7は未完了。
  - 次: 既知の実行失敗と後続成功は[部分整理](docs/development/validation/2026-11-08-m7-release-issue-disposition/README.md)した。
    元の独立した最終source/release reviewと完全なissue dispositionを現行source/tool/profile・
    上記実結果に対応付ける。独立security監査など元のrelease条件、D02/M1・M2/M3・
    公開準備行の責務は未達のまま保持する。8da sourceのbuild/upgrade/restore/parity/
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
   選択済みasset/automatic componentと直近の復旧consumer接続は上のfamily表へ対応済み。
   readiness/successorの別UID境界はPR #345でmerge済み。
   PR #346もmerge済み。N1元ownerの実UID fixtureとoffline genesis限定fixtureは個別に成功した。
   N2元recurring ownerはexact `049dcd59`で実UID・7 epoch/e8と終端資源解放まで成功。
   readiness同一鍵別pathのN4別UID fixtureはexact `25a86df1`で成功した。
   exact `049dcd59`ではNative13 A/B、原12 RELEASE runtime、literal npm ciと完全required、
   全8 CIまで成功。exact `25a86df1`の全8 CIとliteral npm ci・完全requiredも
   exit 0・EOF/wait・資源解放まで終端確認した。次は同sourceの適用される
   RELEASE条件と親の残件を照合する。文書統合PR #347自身の全体gateは冒頭に記録済み。
   PR #349の限定genesis別UID fixtureと同source完全required・CIは上記の通り成功した。
   merge commit `a6ae6229`起点のfresh Native13 A/Bと元12 RELEASE runtimeは
   上記M7の範囲で終端成功した。途中のowner判定・probe失敗はM7に保全済み。
   PR #350ではlocal完全requiredと全8 CIを同sourceで照合してmergeした。
   次は親M2/M7の未達条件を個別に照合し、独立最終reviewと公開準備を完了扱いしない。
   [M2-N1〜N5の元照合](#m2初期リリース対象の照合-2026-11-03) を参照し、
   残る未選択consumerの必要性、対象別lifecycleと不足検証を具体化する。
   停止対象を再開せず、全prepared型や全identity移行を新たな必須条件にしない。
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
