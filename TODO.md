# Sunrise Edge: 実装・検証・公開準備

更新: 2026-10-13 (JST)。これは唯一の現行作業表です。
設計は[architecture](docs/architecture/README.md)、実装場所は
[code map](docs/development/code-map.md)、整理の決定は
[DR-0236](docs/architecture/decisions/0236-separated-code-verification-and-launch-tracking.md)に置きます。

## この表の読み方と件数

旧20項目は「R1-R4の4件 + Delivery 4の8件 + M1-M8の8件」です。
20個の未実装機能という意味ではありません。元のIDを維持し、
Delivery 4の8件には順番どおりD01-D08を付けました。

- コード・検証対象: **14件** (R1-R4、D01-D03・D05、M1-M5・M7)。
- 公開準備対象: **6件** (D04・D06-D08、M6・M8)。実装キューとは別です。
- 再構成時点: **旧20件の完了確定は0件、既存の完了履歴は9件**。
  再分類・延期・重複する検証の共用を、機能の完了件数には数えません。
- R1・R2・R3・D01は完了候補です。過去に確認したローカル結果に加え、
  対象ソースのCI完了と最終照合を確認してからチェックします。
  作業フォルダ・検証資料の所在確認も未解決なので、自動で4件完了とはしません。

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
| 旧作業コピー・専用キャッシュ・raw検証資料 | `/home/yu/.cache/sunrise-edge-worktrees` と `sunrise-edge-continuation-1007-QxQ44s` は所在不明 | 原因不明。Git登録が残っていてもファイルの存在を意味しない |

直前の確認ではGitの作業コピー登録が存在する一方、そのパスがENOENTでした。
削除・移動・クラッシュのどれが原因かは未確定です。今回の文書編集は
キャッシュ外の専用作業コピーで行い、main・履歴・既存ブランチを変更しません。

復帰作業は次の2件です。製品機能の完了数には含めません。

1. コミット済みソースを保全し、未コミット署名作業・検証資料の退避先を確認する。
   回収不能なら、既に取得済みであるかのように扱わず、欠落範囲を明示する。
2. ローカル実行環境を再成立させる。失われた専用home/targetのidentityや古い実行入力を
   新しいものへ黙って置換しない。既存の取得・検証・資源上限を維持して別途扱う。

## 確認済みの結果と未達部分

これは以前実際に読んで確認した結果の記録です。rawファイルが現在手元にある、
新しいソースにも同じ結果が使える、という意味ではありません。

| 証拠 | 以前確認した結果 | 未達・限界 |
| --- | --- | --- |
| E1: c69 required | `validation-90e28db0e9a6421594d8e2451d9ddefc`。exit 0、13,135.63秒。元の8リンク・e8 withdrawals・35暗号化rolesを維持したsource-unavailable復元を含む | main未統合。raw所在不明。オフホスト鍵運用・power/cross-file atomicityの証明ではない |
| E2: selected PG | `validation-9999f12b88c94f6987e84dcbe6d409cf`。5グループを実行しexit 0、766.16秒。前後のソース対応も確認済み | 別ソース・新しい依存には転用しない。PG-every-PRには戻さない |
| E3: Blob owner-loss | `validation-0fed3d1a6460413294be623cb89e7fb1`。Dockerの1ケース合格、512MiB/no additional swap、64MiB noswap、所有資源cleanup確認 | AfterCommitの全fixture所有者SIGKILL。interrupted COMMIT/power/fsyncの証明ではない |
| E4: 署名試作 | `validation-892dea33e428435cbd7a586326984566`。SDK 8ケース合格後、operatorコンパイルがENOSPCで停止 | operator・CLI・5ケースDockerの一連実行は未完了。試作ソース回収可否も不明 |
| E5: c69 CI | run `38339555677`。2026-10-13 16:54 JST確認: 6 owners成功、recurring-sqlite実行中 | 7 owners + success-only checkの最終成功は未確認。再実行・中断はしていない |

以前のopaque Quota失敗の唯一の原因は未確定です。有限の観測予算修正・
再現コントロールとE1の成功は、失敗履歴を書き換えません。
Btrfsの管理領域逼迫を以前観測しましたが、後の容量状態は改善しています。
現在の所在不明と容量変化の原因を、この情報だけで断定しません。

## コード・検証: 14件

共通の検証は後述Gを一度記録し、同一ソース・同一範囲なら複数項目から参照します。
単なる整理のために新しいframework、SDK foundations crate、重いCI laneを追加しません。

- [ ] **R1: データ・codec・error・boundsの定義元を一本化する**
  - 対象: 実装 + 検証。実際のcore/wire/SDK/host呼び出しを移行し、コピーした規則を除去する。
    既存bytes・error優先順位・権限境界を保つ。全SDK依存の解消を新条件にはしない。
  - 状態: c69の移行・ローカル検証は確認済み。完了候補。
  - 次: 保存ソース・証拠を照合し、E5と最終独立確認でこの範囲を確定する。

- [ ] **R2: admission・evaluation・commit・reconciliationの責務を揃える**
  - 対象: 実装 + 検証。判断を一つのownerへ置き、actual CAS/Conflict/Rejected/Indeterminate、
    receipt-first replay、正当なprefix進行とmemory reconstructionを維持する。
  - 状態: c69の実装・ローカル検証は確認済み。完了候補。
  - 次: R1と同じ共通結果を参照して最終照合する。無関係なfacade分割は要求しない。

- [ ] **R3: テストとCIの責任範囲を明確にする**
  - 対象: 実装 + 検証。fixtureは入力、独立oracleは期待値を所有する。重複削減は
    exact-input coverageと実測がある場合だけ。元のrecurrence・delay・restart・faultを保持する。
  - 状態: registry・capture・controlsのc69ローカル検証は確認済み。完了候補。
  - 次: E5と実際のrecipe/selector/結果を照合する。件数やstartupだけで合格にしない。

- [ ] **R4: source/build/configurationと実行可能な手順を結び付ける**
  - 対象: 実装 + 検証。公開するfamily・signer/store capabilityと
    startup/stop/restart/recovery手順を同じrelease artifactへ結び付ける。
  - 状態: 既存manifest/fixtureはある。現在版13-target A/Bと最終handoffは未完了。
  - 次: M7の同一証拠を使い、実際の配置選択はD04/D07へ引き継ぐ。

- [ ] **D01: Native起動・操作の技術統合を確定する**
  - 対象: 検証。author → 独立inspection → 4つの独立store → authenticated TLS →
    compiled CLI → restart・exact replay・refusalを実行する。
  - 状態: E1のローカル条件を満たした完了候補。公開テストネット稼働の宣言ではない。
  - 次: c69のE5・最終照合を完了する。D04/D06の実値選択をローカルコード検証へ持ち込まない。

- [ ] **D02: 最終機能・権限範囲を独立監査する**
  - 対象: 検証。economics/FastVote、generic contracts、ingress、lifecycleを対象にし、
    指摘を修正して独立に再検証する。tech-lead approvalと監査は別。
  - 状態: 最終範囲の監査は未完了。
  - 次: M1と同一head/scopeの監査を共用する。先の狭い監査を全体監査へ拡大解釈しない。

- [ ] **D03: locked Rust・npm・build toolingのadvisoryを処理する**
  - 対象: 実装 + 検証。実際の使用・露出・修正版の互換性を確認し、対応または
    残余リスクを記録する。MSRV/licenseも保持する。7 high entriesは7独立advisoriesとは限らない。
  - 状態: tooling/Rustlsの対応・最終clearanceは未完了。
  - 次: bundled copyも含めて修正版の実体を確認する。forced bulk updateやPATによるreadはしない。

- [ ] **D05: exposed ingress/operationsのコードを検証する**
  - 対象: 実装 + 検証。全accepted familyのauth/TLS・rotation、request/retry/work bounds、
    liveness、secret-free logs/alerts・spend controlsを確認し、未対応familyは閉じる。
  - 状態: ローカルTLS/stop/observationsの証拠はある。全体qualificationは未完了。
  - 次: M5と同じ検証を共用する。本番PKI・SLO・topologyの適用はD04/D07で扱う。

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
  - 状態: publication-only Linux試作の回収可否が不明。E4はSDK部分だけの成功。
  - 次: 所在確認後、未達のbackend/consumerとoperator・CLI・実UID/PTY/Dockerの
    controlsを進める。全accepted signing familyの範囲を明示し、publicationのみで全体を閉じない。
    実鍵・実administrator/recovery役割とceremonyはD04/D06/D07へ残す。Ledgerは別途deferred。

- [ ] **M3: selected SQLite profileのdurabilityを検証する**
  - 対象: 検証。atomic object/state/nonce/receipt/outbox、indexed delivery、
    full-read revision/ABA、reopen・fencing・ambiguity reconciliationと実際のfault boundaries。
  - 状態: c69のENOSPC/blob controlsとE3が合格。f093は未統合。
  - 次: f093をreview済み範囲で統合し、残るselected-profile coverageを対応表で埋める。
    trait reply-loss、process SIGKILL、power/host/media/fsync faultは別証拠。
    全12 SQL tables・4 portable collections・positive blob/oracleを省略しない。
    selected-profileのhost/power/storage faults、ENOSPC/resource exhaustion、
    real writer failover、TLS failure/rotationは、このCODE/VERIFY行の完了条件に残す。
    D07の実topology運用rehearsalは代替・延期理由にならない。一つの合格で全M3を閉じない。

- [ ] **M4: checkpoint・暗号化バックアップ・復元コードを検証する**
  - 対象: 実装 + 検証。checkpoint/state-root・immutable body manifests、
    完全history/receipt/blob restore、fresh fencing、migration/upgrade・safe rollback/stop。
  - 状態: E1の35-role source-free restoreは合格。全M4/releaseは未完了。
  - 次: source/artifact対応、M7、残るmanifest/upgrade/fencing範囲を照合する。
    元の8リンク・e8 withdrawals・35 rolesと全拒否controlsを維持する。
    ageのshared PG feature edgeにはE2の対象ソース照合が必要。
    実オフホスト保管・実鍵retention・DR運用はD04/D06/D07へ残す。
    exact restoreをblanket raw-state equalityやcross-file atomicityとは呼ばない。

- [ ] **M5: Native ingress/operationsの未達コード・検証を埋める**
  - 対象: 実装 + 検証。D05に加え、backpressure/request/work/capacity policy、
    monitoring/incident/validator運用を再現可能なコード・手順へ結び付ける。
  - 状態: local TLS/stop/collectorは実装・部分検証済み。public operationsは未認定。
  - 次: D05と一本のcase/coverage表を使う。実workload/SLOに対するcapacity、
    actual production PKI、alerts/response・spend適用はD04/D07で決め、適用後に検証する。

- [ ] **M7: 再現可能なsupported-runtime releaseを作る**
  - 対象: 実装 + 検証。source/compiler/deps/build provenance、2回のfresh 13-target
    Nativeビルドと全byte比較、canonical/digest/effects/consensus/proof parity、
    conformance/property/fuzz/adversarial/long-run・upgrade/restore・advisory qualification。
  - 状態: 古い11-target A/Bは既存baseline。現在版13-target A/Bは未実行。
  - 次: M2/M3等の対象ソースを固定後に実行し、R4/D03/Gへ同一証拠を渡す。
    過去の11/12-target成功やcheap fixtureを13-target成功にはしない。
    広告する他providerにはPhase 16/17の実provider基準を残す。ローカルadapterの合格で閉じない。

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

1. 所在不明の作業・検証資料を照合し、今回の再構成を独立確認する。
   この段階ではcompiler/helper、依存再取得、故障試験を起動しない。
2. E5のterminalが出たらR1/R2/R3/D01を対象ソースと最終照合し、
   条件を満たした分だけチェックする。公開準備が未着手でもコード作業は進める。
3. M2の欠落/未検証範囲とM3のf093統合を進める。
   M4で既に成功した暗号化復元を未実装として作り直さない。
4. sourceを固定しM7と必要なGを実行、D02/D03/M1の未達を処理する。
   D05/M5は同一の実case表で進める。
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
- 本再構成はdocumentationだけ。製品コード・依存・lock・compiler/formatter・
  target・host設定、公開資源、資格情報を変更しない。CI定期タスクも復活させない。
- SSH/normal merge。Senna PATは指定organizationのPR作成だけで、read/review/mergeには使わない。
  全作成PRはchatへattachする。既存main/branches/stashesと無関係な変更は保持する。
- TypeScript client、explorer/wallet、Ledger、Unique Asset、multisig、contract upgrade/
  irreversible relinquishment/atomic migration、ZK、cross-domain atomicity、追加provider/HA/scaleは
  元の条件付きdeferredのまま。未実装のものを広告しない。認定条件を黙って取り消さない。
