# Sunrise Edge: 現在のTODO

更新: 2026-11-25 (Asia/Singapore)。元85チェックのうち74件は完了、元の未完了は下の11件（親11件）。下位チェックは実用上の進捗を示し、元85件には加えない。`[x]`は記載した範囲で確認済み、親の完了は元の条件で判定する。完了経緯、旧sourceごとの成功・失敗、元の対応表は[固定commitの旧TODO][historical-todo]に保存した。ここには現在必要な条件だけを置く。設計は[architecture](docs/architecture/README.md)、実行方法は[validation profiles](docs/architecture/repository-validation.md)、元のbinding条件は[preserved roadmap](docs/development/history/roadmap-through-2026-10-06.md)が所有する。文書整理だけで実装・検証・公開を完了とはしない。

## 公開ベータ: 実資産・全機能

実資産を扱い、現行repoの実装済み機能と公開経路を全て対象とする公開ベータを進める。Standard Assetだけ、FastVoteだけ、`/v1/events`を除く、generic paidを除くといった機能制限は置かない。ベータという名称を状態のリセット・巻き戻しや実資産保護の省略理由にしない。未実装・未検証の機能は完了扱いにせず、下のTODOと公開前の作業に残す。現行の[security policy](SECURITY.md)は実資産custodyとcertified surfaceの公開をまだ認めておらず、証拠を揃えて公開前に改訂する。

- [x] 公開ベータの目標を実資産・全機能に訂正した（2026-11-25）。既存の各host/adapterは異なる経路を提供し、一つのcertified relayだけでは全機能を公開できないことを確認した。これは公開資格の達成ではない。
- [ ] 全ての実装済み機能・入口・host・backendと未実装/未検証の機能を対応付け、提供を完了する。受け付ける取引、FastVote管理・drain、generic paid、direct/ordered、handoff/successor、参照などを勝手に除外しない。
  - [x] 現行sourceの実装済み主要経路とhostを[構成一覧](docs/architecture/compositions-and-capabilities.md#concrete-composition-owners)・実sourceで照合した。event/directはdevnet実行のみ、certified/orderedはoriginal host、successor/handoffはsuccessor host、Cloudflare内蔵validatorは一部経路という境界を確認。全機能を公開するhost/入口と未実装機能の完了は残る。
  - [x] causal preinstalled `SubmitTransaction`の最初の候補判定を実装した。profile-2署名が外側のrequest IDを覆うこと、signed genesisのchain/version・Owned lane・空でないobject manifestを確認する純粋な判定に限定する。証明書、状態更新、公開hostとhandoff対応は未実装であり、このチェックを公開資格に転用しない。
  - [x] preinstalled `SubmitTransaction`の既存direct遷移から、正確なinvocation・result・blob公開予定・logical derivationを返す内部ステージング境界を抽出した。preinstalledのstage後もobject head/nonce/receiptは未更新で、続く既存direct実行は同じresultを返す。共通staging関数の大きなobject出力もblob公開・commitがstage中は0回で、direct実行時に各1回となることをowning testsで確認した。causal用のinstalled-profile gate、証明書・durable prepare/apply・公開hostは未実装で、このチェックを公開資格に転用しない。
- [ ] 全対象操作の保護鍵・正確な内容確認・実承認者・復旧/取消と、実chain/genesis・validator/運営担当・asset/economics・artifactを固定して通す。M2/D04/D06/M6の結果を共用する。
- [ ] 全公開入口を実配置で構成し、TLS、upstream認証、要求量・同時実行の上限、停止手段を確認する。到達する全経路を独立にsecurity reviewし、非公開指摘を修正・再確認する。D02/M1と結果を共用する。
- [ ] 使用する全store/hostで実host/media/fsync、停止・同じ状態からの再開、exact replay、別hostのbackup復旧・writer failover/fenceを確認する。資産状態を巻き戻さない。M3/D07と結果を共用する。
- [ ] 最終sourceのowning checks、全7 CI lane・集約`check`、対象runtimeのRELEASE artifactと実行結果を揃え、外部clientから全公開機能・故障/再開を確認する。M7/D07と結果を共用する。
- [ ] 実endpoint・asset、監視・停止・復旧手順、残余リスクを記録し、実資産を受ける前に[security policy](SECURITY.md)を実態に合わせて改訂して人が公開ベータのgo/no-goを決める。D08/M8と結果を共用する。

## コード・検証: 親5件

- [ ] **D02: 最終機能・権限範囲を独立監査する**
  - economics/FastVote、generic contracts、ingress、lifecycleの最終範囲を同一sourceで監査し、指摘修正と独立再検証を終える。tech-lead approvalや過去の狭いscanは代替しない。
  - M1と監査対象・証拠を共用できる。旧private sourceの独立scanは1,369ファイル中53ファイルの部分進捗にとどまり、完走結果はない。現行mainの最終監査には転用しない。
  - [ ] 最終sourceの上記4領域を独立監査で通す。
    - [x] 料金計算・予約の限定component: `2214eb9f649eb0688b41c5299a499c62d79fcb87`の`crates/fees` 3ファイルを独立に静的reviewし、Codex Security scan `f3ca21da-bc5f-4ef2-9452-29ff1a0f36c8`は報告対象0件。owning test 35件とClippyが成功した。FastVoteを含む残りの領域と最終source全体の資格には転用しない。
    - [x] 債券primitiveの限定component: `1788b948606f11f17321d3c1979ae149200137a1`の`crates/bonds` 2ファイルを独立に静的reviewし、Codex Security scan `e8857ec6-1339-4572-b68c-c8bdc51f63e9`は報告対象0件。owning test 16件とClippyが成功した。現行の非test利用がないadmission/evidence APIを有効化する際のcaller監査、FastVote連携、最終source全体の資格には転用しない。
    - [x] validator-setの限定component: `78187e757a19f707bb6c469e38b60f5ea8a8cc44`の`crates/validator-set` 2ファイルを独立に静的reviewし、Codex Security scan `d4bcd8ba-dfc3-489b-8168-dccab344973e`は報告対象0件。owning test 12件とClippyが成功した。暗号鍵・署名の実承認とFastVote統合、最終source全体の資格には転用しない。
    - [x] system-modulesの限定component: `985791375f54a912043089dbd4c4403c96360502`の`crates/system-modules` 2ファイルを独立に静的reviewし、Codex Security scan `45c88144-6ab7-4e84-9817-00ceaa0e4beb`は報告対象0件。owning test 8件とClippyが成功した。実行側の呼出元は到達性・制御の確認に限り、generic contracts全体と最終source全体の資格には転用しない。
    - [x] hash-suite scheduleとupgrade型の限定component: 同sourceの`crates/protocol-upgrades` 2ファイルを独立に静的reviewし、Codex Security scan `2dea698e-d2a1-40c2-a4a9-2cf6bd82caab`は報告対象0件。owning test 7件とClippyが成功した。現行のschedule利用を確認した一方、外部`ApplyProtocolUpgrade`は拒否され、実upgrade・migrationの起動資格と最終source全体の監査は残る。
  - [ ] 指摘を修正し、独立に再確認する。

- [ ] **M1: 固定releaseの独立security/release reviewを終える**
  - code/deployment仕様、contracts、economics、handoff/activation、ingress、storage、signingを固定し、指摘・修正・残余リスクを独立に確認する。D02と同じ範囲の結果は共用する。
  - 最終reviewは未完了。停止済み監査を旧scanや非security reviewで置き換えない。実配置の承認はD04/D07/M8に残る。
  - [ ] release候補のcode/deployment・security範囲を独立reviewで通す。
  - [ ] 指摘・残余リスクとissue dispositionを確定する。

- [ ] **M2: protected signerと操作内容レビューを実装・検証する**
  - 必須範囲: 保護された鍵backend、operator/authority分離、操作ごとの正確な内容確認、拒否・故障、必要な復旧・交換・取消。自動protocol署名と人のasset/governance承認を分ける。
  - 過去の初期release対象の選択（2026-11-13）: 当時は既存の選択済みfamilyに限定した。generic local/general・paidとFinalTransferは未完了であり、2026-11-25の全機能公開ベータの対象からは除外しない。
  - 2026-11-25の実資産・全機能公開ベータは、上の2026-11-13の限定選択を引き継がない。generic local/general・paidとFinalTransferを勝手に除外せず、未実装・未検証の対象として追う。既存のStandard Asset保護署名とFastVote送信の同一実行も未検証。
  - 完了済みの小項目は下のチェックで保持する。各結果のsource/profileと限界は[旧TODO][historical-todo]と[signing contracts](docs/architecture/signing-preparation.md)を参照する。個別合格を全familyの資格に転用しない。
  - 残件: original bondの局所観測と承認・署名前の反復照会はPR #362で実装済み、実hostと保護署名の限定結合も下の小項目で検証済み。選択済みfamilyのlifecycleと元ownerの対応付けは[照合表](docs/architecture/signing-preparation.md#selected-family-lifecycle-correspondence)で整理済み。同一sourceの実UID/RELEASE全体資格、実承認者/鍵enrollmentとM2親の受入は未達。対象外の全prepared型や全identity移行を新しい必須条件にしない。
  - [x] 2026-11-13の旧対象についてlifecycleと検証ownerを[対応付けた](docs/architecture/signing-preparation.md#selected-family-lifecycle-correspondence)。全機能ベータの資格には転用しない。
  - [x] 下のZeroShare componentのコードを[PR #381](https://github.com/sunriselayer/sunrise-edge/pull/381)でmainへ統合し、限定資格を下のCI結果で確認した。
  - [ ] 選択済みfamilyを実UID/RELEASEと実承認者・保護鍵で通し、最終reviewを終える。
  - [ ] 実資産ベータの全対象操作を保護署名し、実承認者・実鍵・復旧/取消まで同一profileで通す。既存のStandard AssetとFastVoteの結合も含む。
  - [x] **publicationの保護承認と取消・同一鍵復旧・交換component**: [専用custody](docs/architecture/local-publication-custody.md)と[lifecycle](docs/architecture/publication-custody-lifecycle.md)の既存実UID/PTY/拒否・restart結果に限定する。
  - [x] **genesis Standard Assetのtransfer・split/merge・mint/burn・create component**: [transfer](docs/architecture/standard-asset-transfer-custody.md)、[split/merge](docs/architecture/standard-asset-split-merge-custody.md)、[mint/burn](docs/architecture/standard-asset-mint-burn-custody.md)、[create](docs/architecture/standard-asset-create-asset-custody.md)の実CLI・別UID結果と、旧TODOに記録した限定復旧・live Coin handoffを含む。
  - [x] **own-created application asset/Coinの操作と限定復旧component**: [application asset pin](docs/architecture/decisions/0258-mint-burn-application-asset-pin.md)のmint/burnと[Coin custody](docs/architecture/standard-asset-application-coin-custody.md)のCoin操作・kind2/3 historical recoveryを既存profileで検証済み。
  - [x] **fee-claimの非承認preview/export component**: [開発用署名](docs/architecture/fee-claim-review.md)の構造表示と保存内容に限定し、protected fee-claim承認の完了とはしない。
  - [x] **positive fee-claim SplitのLeg/Claim component**: [操作内容policy](docs/architecture/positive-fee-claim-split-policy.md)と[別UID/PTY lifecycle](docs/architecture/positive-fee-split-uid-fixture.md)の既存結果に限定する。
  - [x] **original ordered protocol worker component**: [別UID/TLS worker](docs/architecture/local-protocol-custody.md)と停止後同一identity復旧を既存ownerで検証済み。
  - [x] **certified FastVote protected worker component**: [別UID/TLS lifecycle](docs/architecture/local-certified-protocol-custody-fixture.md)と停止後同一identity復旧を既存ownerで検証済み。
  - [x] **offline genesis authorの二段階保護review component**: [限定別UID検証](docs/development/validation/2026-11-04-m2-genesis-protected/README.md#current-source-follow-up-2026-11-13)で`894e5881`の既存ownerが1 passed/0 failed、nested/outerのreview切断拒否と4組のvalidator pairへのinstallを確認。実承認者・実鍵ceremonyとM2全体資格は未達。
  - [x] **original bondの限定保護inner/outer結合component**: [固定manifest/profile](docs/architecture/decisions/0291-original-bond-inner-standard-asset-profile.md)と[PR #358](https://github.com/sunriselayer/sunrise-edge/pull/358)の既存CLI owner結果に限る。実SQLite host接続は下の別小項目で扱う。
  - [x] **N1 readiness: 現行sourceの別UID実行結果**: commit `6801bca3`で既存readiness ownerの別UID worker/frontend profileが1 passed/0 failed。raw結果・実行元tree・資源解放は[検証記録](docs/development/validation/2026-11-12-m2-current-source-uid/README.md)に固定。後続の文書commitやM2親の資格へ転用しない。
  - [x] **N2 successor: 現行sourceの別UID実行結果**: commit `abccadfd`の既存recurring ownerが、元の7 epochs/e8・2件の1832-byte候補/committed ACKを保持して1 passed/0 failed。別UID、raw結果、11 artifact不変と資源解放は[検証記録](docs/development/validation/2026-11-12-m2-current-source-uid/README.md#n2-successor-passed-2026-11-13)に固定。後続sourceやM2/M7親の資格へ転用しない。
  - [x] **original bond: 実SQLite hostと保護署名の結合検証**: `b2087f0d`から修正した`3b05f2d2`の既存ownerで、同一genesis/Coinの実host観測から別承認・署名へ接続し、停止後の古いfenceを拒否。standaloneとnode-core handoffは各1 passed/0 failed。後者のpost-genesis Coin currentnessは既存固定応答のまま。失敗・成功rawと範囲は[限定検証記録](docs/development/validation/2026-11-12-m2-bond-realhost/README.md)。最終PR headの全体gateや実鍵資格へ転用しない。
  - [x] **ZeroShare専用custody component**: [PR #381](https://github.com/sunriselayer/sunrise-edge/pull/381)の実装はCI終端前にmainへ統合されたが、後に同じPR headの全8チェックが成功した。実承認者・実鍵とM2全体資格は親で追う。
    - [x] 専用kind 7と操作内容guardをPR head `238884fd`に実装した。
    - [x] 同headのCLI owning 27件、実Seal sourceを使う別UID/PTY・拒否・restartの限定Docker fixture 1件と独立静的reviewを通した。
    - [x] PR #381を通常merge `969a81db`でmainへ統合した。
    - [x] PR head `238884fd`の[CI run 43819333018](https://github.com/sunriselayer/sunrise-edge/actions/runs/43819333018)で7レーンと集約`check`が成功した（`recurring-sqlite` 5h13m40s、最終`check` 12s）。
  - 現行のN1〜N5区分は[下の表](#m2初期リリース対象の照合-2026-11-03)にまとめる。

- [ ] **M3: selected SQLite profileのdurabilityを検証する**
  - 対象: atomic object/state/nonce/receipt/outbox、indexed delivery、full-read revision/ABA、reopen/fence/ambiguous acknowledgementと実fault boundaries。通常SQLite/ENOSPC、TLS ACK喪失・再送/再起動、同host owner-loss、通常VM power/EIOの個別合格は[旧TODO][historical-todo]と[coverage記録](docs/development/validation/2026-10-22-m3-ordinary-coverage/README.md)に保存した。
  - 未達: selected-profileの物理host/power/media/fsyncと別host writer failover。通常profileやloopback/TLSの結果を転用しない。実topologyの追加rehearsalはD07。
  - [x] 通常SQLite/ENOSPC・TLS ACK・同host owner-loss・通常VM power/EIOの個別結果を[旧sourceで確認した](docs/development/validation/2026-10-22-m3-ordinary-coverage/README.md)。
  - [ ] selected-profileの物理host/power/media/fsyncと別host writer failoverを通す。
  - [x] **独立anchor付きprofileの実guest fault boundaries**: [DR-0266](docs/architecture/decisions/0266-independent-anchor-virtual-fault-profile.md)の元9境界を、現行のQEMU 11.1.3/Arch 7.2.15を固定した[ローカル仮想owner](docs/development/validation/2026-11-16-m3-anchored-qemu11/README.md)で通した。記録前の固定source `ef6e066d`の実guest電源断・write/flush EIO、cold完全new/旧source safe stop、全12+2+authority tablesとpositive bodies、別の独立reviewを確認。旧QEMU 10.2.2試行の失敗は保持し、物理hostやpartial WALへ転用しない。
    - [x] [PR #382](https://github.com/sunriselayer/sunrise-edge/pull/382)で20-byte以下のserialと現行QEMUのread-only 2-disk bootを確認した。これ単独はproduct fault合格ではない。
    - [x] 選択したguestで元9境界の電源断・write/flush EIOと各cold oracleを通し、全18 QEMU socket・39子プロセス・cgroupを解放した。
  - [x] **selected virtual deviceのpartial persistent write**: [実WAL fault記録](docs/development/validation/2026-11-17-m3-wal-partial/README.md)の固定test source `cc599a04`で、実WAL extent/sector、前半4 KiBの新byteと後半56 byteの旧byte、元authorityでのcold receipt-first `none`と完全な状態照合を確認。以前停止したassessment/mechanism2はこの結果に転用していない。物理hostやM3親は未達。
    - [x] 実WALのpartial writeを再現する。
    - [x] cold restartでreceipt-first none/all判定の`none`を確認する。

### M7: 再現可能なsupported-runtime releaseを作る

- [ ] **M7: 再現可能なsupported-runtime releaseを作る**
  - 対象: source/compiler/deps/build provenance、fresh 13-target Native A/B全byte比較、canonical/digest/effects/consensus/proof parity、conformance/property/fuzz/adversarial/long-run・upgrade/restore・advisory qualification、独立最終source/security/release reviewとissue disposition。
  - `2415dbec`/tree `2a0a2f09`では#364のliteral npm ci・完全required、全8 CI/PG、13-target A/B、元12 RELEASE runtime 105 passed/0 failed/4 ignored、元7 epochs/e8と2件の1832-byte候補/committed ACK、source/36 ELF不変と資源解放を照合した。[exact-source issue記録](docs/development/validation/2026-11-08-m7-release-issue-disposition/README.md#2026-11-11-exact-source-follow-up)を参照。旧失敗は消さない。独立非security reviewは完了したが、独立security/final release reviewとissue dispositionは未完了。実UID ignored fixtureはこの実行の資格外。
  - 文書PR #365はCI終端前にマージされたが、その後head `e1bc3809`/同一tree `71acddf4`の全7 laneと集約`check`が[成功](https://github.com/sunriselayer/sunrise-edge/actions/runs/43035754943)した。#366/#367も各headの全8 CI成功後にマージした。これらを別sourceの技術資格や独立security/final reviewに転用せず、公開条件とM2/M3/D02/M1を完了扱いしない。広告する他providerには元の実provider基準を適用する。
  - [x] `2415dbec`の13-target A/B・RELEASE・完全gateを旧sourceの基準結果として[保存した](docs/development/validation/2026-11-08-m7-release-issue-disposition/README.md#2026-11-11-exact-source-follow-up)。
  - [ ] 最終sourceで再現可能なbuild・実行結果を揃える。
  - [ ] 独立security/release reviewとissue dispositionを終える。

### 非公開監査repoの後片付け

- [x] 今回の非公開指摘3件の修正を[公開mainのcommit `6aedd259`](https://github.com/sunriselayer/sunrise-edge/commit/6aedd259dad94654b659d21b6201df865754b1b1)へ統合し、重複した非公開PRを閉じた。D02/M1の最終独立reviewは別に残る。
- [ ] 3件のDraft Security Advisoryの対応と必要な非公開証跡の保存を終えたら、一時監査用の非公開repoを廃止する。D02/M1のrelease reviewとは別の後片付けであり、元85件の親条件には加えない。

### M2初期リリース対象の照合 (2026-11-03)

これは[元のN1〜N5照合とfamily表][historical-m2]への固定リンクである。現行区分は次の通り。

| 区分 | 現在必要な残件 |
| --- | --- |
| N1 readiness / N2 successor | 選択した別UID worker/frontendと旧sourceの元owner実UID検証は存在する。現行sourceでの対応結果は上のN1/N2補助チェックで個別に追う。元のeligible key、retained slot、fresh serving warrant、committee/fenceを省略しない。 |
| N3 対象consumer | 2026-11-13の旧選択は既存family限定だった。2026-11-25の実資産・全機能公開ベータではgeneric local/general・paidとFinalTransferも除外せず、実装・保護署名・検証の未完了として追う。旧original genesis限定profileの結果をsuccessor live-epoch担保移動の資格に転用しない。 |
| N4 lifecycle | `8bb97ddf`の選択済みfamilyについて実装と元ownerの[対応付け](docs/architecture/signing-preparation.md#selected-family-lifecycle-correspondence)を完了。今回の照合では、採用済み契約に対する追加の未対応遷移は特定されなかった。同一鍵の再読込、別identityの署名、実object/membership移行を区別し、genesis/bondの限定restartを本番backup復旧へ広げない。過去の実行結果は各source/profileのまま保持し、N5の新たな実UID/RELEASE合格とはしない。 |
| N5 全体資格 | 選択済みconsumerのrequired・実UID/PTY・Native13 A/B・保存RELEASE runtime・独立最終reviewを[既存ownerへ対応付け済み](docs/architecture/signing-preparation.md#qualification-owner-correspondence)。全体資格は未達であり、G6の独立最終review/issue dispositionをCI・技術review・部分再実行で代替しない。停止条件が残る間は全体資格を閉じるためだけの一括再検証を増やさない。元のselector、7 epochs/e8、候補2件、8 links、35 rolesを維持する。 |

## 公開準備: 6件

これらは実役割・実値・実環境・公開権限の条件であり、fixture値やlocal Docker/loopbackの合格とは分ける。

作業順（2026-11-25）: 上の実資産・全機能公開ベータを進める。D04/D06/D07/D08/M6/M8の実担当・値・復旧・承認をベータでも通し、元の完全release条件は保持する。未確定の実運用情報を既存資料の提出待ちにはしない。

- [ ] **D04: 実validator・custody/admin役割とrelease profileを選ぶ**: 独立operators、real genesis/chain pins、economics、supported routes、exact release artifactを固定する。Native+SQLite firstの技術選択だけでは足りない。
  - [ ] operatorsとcustody/admin担当を決める。
  - [ ] genesis/chain・economics・routes・artifactをひとつのrelease profileに固定する。
- [ ] **D06: 実genesis・鍵/config ceremonyを確認する**: 実genesisを独立検証し、実鍵・設定・独立installationをrehearsalする。parameterized author/inspector/installの既存コードを実ceremonyの結果と混同しない。
  - [ ] 実genesisを独立検証する。
  - [ ] 実鍵・config・独立installationのceremonyを通す。
- [ ] **D07: 実topology上の運用rehearsalを行う**: outside-client、fees/claims、bonds/slash、membership/epochs、stopped catch-up、safe stop/restart/recoveryを実receipt/canonical stateで確認する。選択profileの物理fault・off-host backup、PKI/SLO/alerts/retentionを省かない。
  - [ ] 実topologyでclient・economic・membership/epoch操作を通す。
  - [ ] stop/restart/recovery・物理fault・backupと運用監視を通す。
- [ ] **D08: launch・rollback・stop手順を承認する**: 実値・実操作手順を固定し、resources作成・public traffic受理前に人が承認する。
  - [ ] 実値を入れたlaunch・rollback・stop手順を揃える。
  - [ ] 公開操作前の人の承認を得る。
- [ ] **M6: 本番economics/genesis値を承認する**: sets/roles/powers、bond/fee assets/schedules、treasury/supply/distribution、security/unbonding/governance parameters、ceremonyとsupply invariantsを決める。bond額からvoting powerを推定しない。
  - [ ] 本番のsets/roles/powers・assets/schedules・treasury/supply・governance値を決める。
  - [ ] ceremonyとsupply invariantsを確認して承認する。
- [ ] **M8: 公開運用の最終go/no-goを行う**: 全コード・検証行とD04/D06/D07/D08/M6、実public operation/recovery、experimental/unsupported/mock/deferred範囲を元条件で確認し、人が最終判断する。コード完了、testnet公開、mainnet公開は別。
  - [ ] 全条件と公開する範囲を照合する。
  - [ ] 人がtestnet/mainnetのgo/no-goを決める。

## G: 共通acceptanceと証拠記録

下位チェックと選択済みfamilyの限定componentは、owning test・主要な故障時挙動・必要な実UID fixture・独立reviewで実用性を確認した時点で閉じる。各componentに完全local gateを繰り返さない。親とreleaseの受入には以下の共通条件を適用する。

同じhead/profile/scopeの結果を参照で共用します。別ソース・祖先・部分結果の転用、
未実行/skip/cancelを成功扱い、selector削減、delay短縮やfault除外はしません。

1. 実際のsource/tree、lock/tool inputs、profile、実行範囲・独立reviewを固定する。
   refactorはowner・migrated callers・removed duplicateとbytes/error/authority保持を示す。
2. proportionalなowning/vector/adversarial/store/HTTP/CLI/fault controlsを実行する。
3. 通常PRは全7 unconditional ownersとsuccess-only `check` を通す。親やreleaseの受入で完全local profileを要求する場合は、最終sourceでliteral `npm ci --prefix adapters/cloudflare-workers` と完全な `./scripts/check-all.sh` を実行する。
4. PG実装/依存変更またはPG claimにはselected-sourceの5-group complete PG/full profile。
   Docker-only live prerequisitesを必須とし、E2を別headへ借用しない。
5. M7/R4では現在の13 Native targetsのfresh A/Bと完全比較・provenance。
   これは全てのR1/R2/R3/D01完了に新しく足す前提ではない。
6. exact-source CI terminal、独立最終review・指摘処理、実際のraw exit/EOF・所有資源releaseを
   記録する。startup 0、check件数、hash/countだけはsemantic/runtime合格ではない。
   失われたrawを現在存在するものとしてリンクせず、回収可否と証拠の限界を明記する。
7. 正常なmergeは該当する元の条件を満たした後だけ。squash/rebase/forceや
   未認定release/main mergeを行わない。実資産・全機能の公開ベータは上記の全範囲と
   D08/M8の実操作承認を通して判断し、完全releaseの親資格と区別する。

[Validation profiles](docs/architecture/repository-validation.md)と
[元production gate](docs/development/history/roadmap-through-2026-10-06.md#cli-first-node-production-gate)
が原条件を所有します。原条件の詳細はarchitecture/historyへ辿り、live状態はここだけに書きます。

## 作業境界

利用者は2026-11-16に停止済み監査・障害検証の再試行を指示した。ZeroShareの限定fixtureはPR #381、独立anchor VMのserial診断はPR #382、現行pinの元9境界と別実行のpartial-WALは上の検証記録で進んだ。D02/M1独立監査と旧M3 torn-WAL assessment/mechanism2は未完走であり、部分結果を合格に転用しない。実鍵・host user・security policy・deploy・公開設定はこのTODO整理では変更しない。TypeScript client、explorer/wallet、Ledger、Unique Asset、multisig、contract upgrade/irreversible relinquishment/atomic migration、ZK、cross-domain atomicity、追加provider/HA/scaleなど未実装・未検証の機能を完了済みと広告しない。全機能の対象から勝手に外さず、必要な実装と元の条件を追う。

[historical-todo]: https://github.com/sunriselayer/sunrise-edge/blob/eb79768ba9806220576f3abe4e344b75b19390fe/TODO.md
[historical-m2]: https://github.com/sunriselayer/sunrise-edge/blob/eb79768ba9806220576f3abe4e344b75b19390fe/TODO.md#m2初期リリース対象の照合-2026-11-03
