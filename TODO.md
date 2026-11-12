# Sunrise Edge: 現在のTODO

更新: 2026-11-12 (Asia/Singapore)。元85チェックのうち71件は完了、元の未完了は下の14件（親11件、子3件）。M2の既存N1/N2未達を追う補助チェック2件は元85件に加えない。完了経緯、旧sourceごとの成功・失敗、元の対応表は[固定commitの旧TODO][historical-todo]に保存した。ここには現在必要な条件だけを置く。設計は[architecture](docs/architecture/README.md)、実行方法は[validation profiles](docs/architecture/repository-validation.md)、元のbinding条件は[preserved roadmap](docs/development/history/roadmap-through-2026-10-06.md)が所有する。文書整理だけで実装・検証・公開を完了とはしない。

## コード・検証: 親5件、子3件

- [ ] **D02: 最終機能・権限範囲を独立監査する**
  - economics/FastVote、generic contracts、ingress、lifecycleの最終範囲を同一sourceで監査し、指摘修正と独立再検証を終える。tech-lead approvalや過去の狭いscanは代替しない。
  - M1と監査対象・証拠を共用できる。従来の独立監査実行は提供側の安全判定で停止したままで、再試行・迂回しない。

- [ ] **M1: 固定releaseの独立security/release reviewを終える**
  - code/deployment仕様、contracts、economics、handoff/activation、ingress、storage、signingを固定し、指摘・修正・残余リスクを独立に確認する。D02と同じ範囲の結果は共用する。
  - 最終reviewは未完了。停止済み監査を旧scanや非security reviewで置き換えない。実配置の承認はD04/D07/M8に残る。

- [ ] **M2: protected signerと操作内容レビューを実装・検証する**
  - 必須範囲: 保護された鍵backend、operator/authority分離、操作ごとの正確な内容確認、拒否・故障、必要な復旧・交換・取消。自動protocol署名と人のasset/governance承認を分ける。
  - publication、選択済みStandard Asset各family/positive Split、original ordered/certified FastVote、readiness/successor、offline genesis author、original bondの限定componentは実装・個別検証済み。各結果のsource/profileと限界は[旧TODO][historical-todo]と[signing contracts](docs/architecture/signing-preparation.md)を参照する。個別合格を全familyの資格に転用しない。
  - 残件: generic local/general・paidとFinalTransferの対象/authority/content/backendは未選択。original bondの局所観測と承認・署名前の反復照会はPR #362で実装済みだが、実hostと保護署名を結ぶ検証、実承認者/鍵enrollment、release資格が未達。選択済みfamilyの残るlifecycleと、確定対象に対する同一sourceの全体検証を照合する。未選択の全prepared型や全identity移行を新しい必須条件にしない。
  - [x] **N1 readiness: 現行sourceの別UID実行結果**: commit `6801bca3`で既存readiness ownerの別UID worker/frontend profileが1 passed/0 failed。raw結果・実行元tree・資源解放は[検証記録](docs/development/validation/2026-11-12-m2-current-source-uid/README.md)に固定。後続の文書commitやM2親の資格へ転用しない。
  - [ ] **N2 successor: 現行sourceの別UID実行結果**: 既存recurring ownerの別UID profileを元の7 epochs/e8のまま同一sourceで実行し、raw結果と資源解放を記録する。
  - [ ] **ZeroShare専用custody WIP**: 別branchの未検証コードは未統合。fixture作成は提供側の安全判定で停止しており、再試行・迂回しない。実装済み・検証済みとは数えない。
  - 現行のN1〜N5区分は[下の表](#m2初期リリース対象の照合-2026-11-03)にまとめる。

- [ ] **M3: selected SQLite profileのdurabilityを検証する**
  - 対象: atomic object/state/nonce/receipt/outbox、indexed delivery、full-read revision/ABA、reopen/fence/ambiguous acknowledgementと実fault boundaries。通常SQLite/ENOSPC、TLS ACK喪失・再送/再起動、同host owner-loss、通常VM power/EIOの個別合格は[旧TODO][historical-todo]と[coverage記録](docs/development/validation/2026-10-22-m3-ordinary-coverage/README.md)に保存した。
  - 未達: selected-profileの物理host/power/media/fsync、別host writer failoverと下の2つの独立fault条件。通常profileやloopback/TLSの結果を転用しない。実topologyの追加rehearsalはD07。
  - [ ] **独立anchor付きprofileの実guest fault boundaries**: Pending後/source COMMIT前、source COMMIT後/finalize前など元9境界で実guest電源断・write/flush EIO、完全new/旧source safe stop、全12+2+authority tablesとpositive bodiesを確認する。[DR-0266](docs/architecture/decisions/0266-independent-anchor-virtual-fault-profile.md)のsourceと失敗証跡は保持。実guest boot修正は提供側の安全判定で停止し、product control成功0。再試行・迂回しない。
  - [ ] **selected virtual deviceのpartial persistent write**: 実WAL extent/sector、混在した永続bytesとcold receipt-first none/allを対応付ける。単なるEIO/転送上限では完了しない。assessmentとsupporting mechanism2は提供側の安全判定で停止し、再試行・迂回しない。

### M7: 再現可能なsupported-runtime releaseを作る

- [ ] **M7: 再現可能なsupported-runtime releaseを作る**
  - 対象: source/compiler/deps/build provenance、fresh 13-target Native A/B全byte比較、canonical/digest/effects/consensus/proof parity、conformance/property/fuzz/adversarial/long-run・upgrade/restore・advisory qualification、独立最終source/security/release reviewとissue disposition。
  - `2415dbec`/tree `2a0a2f09`では#364のliteral npm ci・完全required、全8 CI/PG、13-target A/B、元12 RELEASE runtime 105 passed/0 failed/4 ignored、元7 epochs/e8と2件の1832-byte候補/committed ACK、source/36 ELF不変と資源解放を照合した。[exact-source issue記録](docs/development/validation/2026-11-08-m7-release-issue-disposition/README.md#2026-11-11-exact-source-follow-up)を参照。旧失敗は消さない。独立非security reviewは完了したが、独立security/final release reviewとissue dispositionは未完了。実UID ignored fixtureはこの実行の資格外。
  - 文書PR #365はCI終端前にマージされたが、その後head `e1bc3809`/同一tree `71acddf4`の全7 laneと集約`check`が[成功](https://github.com/sunriselayer/sunrise-edge/actions/runs/43035754943)した。#366/#367も各headの全8 CI成功後にマージした。これらを別sourceの技術資格や独立security/final reviewに転用せず、公開条件とM2/M3/D02/M1を完了扱いしない。広告する他providerには元の実provider基準を適用する。

### M2初期リリース対象の照合 (2026-11-03)

これは[元のN1〜N5照合とfamily表][historical-m2]への固定リンクである。現行区分は次の通り。

| 区分 | 現在必要な残件 |
| --- | --- |
| N1 readiness / N2 successor | 選択した別UID worker/frontendと旧sourceの元owner実UID検証は存在する。現行sourceでの対応結果は上のN1/N2補助チェックで個別に追う。元のeligible key、retained slot、fresh serving warrant、committee/fenceを省略しない。 |
| N3 対象consumer | offline genesisとoriginal bondの限定経路は実装済み。generic local/general・paid、FinalTransferは対象と承認契約の選択待ち。successor live-epoch担保移動はoriginal genesis限定profileの資格に含めない。 |
| N4 lifecycle | 同一鍵復旧・取消・交換の既存結果をfamilyごとに使い、必要な未対応移行だけを特定する。新address aliasやhistorical claimant書換えを暗黙に採用しない。 |
| N5 全体資格 | 確定したconsumer/変更を既存の元test owner、実UID/RELEASE、同一sourceのGへ対応付ける。既存selector、7 epochs/e8、候補2件、8 links、35 rolesを縮めない。 |

## 公開準備: 6件

これらは実役割・実値・実環境・公開権限の条件であり、fixture値やlocal Docker/loopbackの合格とは分ける。

- [ ] **D04: 実validator・custody/admin役割とrelease profileを選ぶ**: 独立operators、real genesis/chain pins、economics、supported routes、exact release artifactを固定する。Native+SQLite firstの技術選択だけでは足りない。
- [ ] **D06: 実genesis・鍵/config ceremonyを確認する**: 実genesisを独立検証し、実鍵・設定・独立installationをrehearsalする。parameterized author/inspector/installの既存コードを実ceremonyの結果と混同しない。
- [ ] **D07: 実topology上の運用rehearsalを行う**: outside-client、fees/claims、bonds/slash、membership/epochs、stopped catch-up、safe stop/restart/recoveryを実receipt/canonical stateで確認する。選択profileの物理fault・off-host backup、PKI/SLO/alerts/retentionを省かない。
- [ ] **D08: launch・rollback・stop手順を承認する**: 実値・実操作手順を固定し、resources作成・public traffic受理前に人が承認する。
- [ ] **M6: 本番economics/genesis値を承認する**: sets/roles/powers、bond/fee assets/schedules、treasury/supply/distribution、security/unbonding/governance parameters、ceremonyとsupply invariantsを決める。bond額からvoting powerを推定しない。
- [ ] **M8: 公開運用の最終go/no-goを行う**: 全コード・検証行とD04/D06/D07/D08/M6、実public operation/recovery、experimental/unsupported/mock/deferred範囲を元条件で確認し、人が最終判断する。コード完了、testnet公開、mainnet公開は別。

## G: 共通acceptanceと証拠記録

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

## 作業境界

停止済みD02/M1監査、ZeroShare fixture、M3 torn-WAL assessment/mechanism2、独立anchor VM boot修正は再試行・言い換え・別担当への付け替えをしない。実鍵・host user・security policy・deploy・公開設定はこのTODO整理では変更しない。未選択のTypeScript client、explorer/wallet、Ledger、Unique Asset、multisig、contract upgrade/irreversible relinquishment/atomic migration、ZK、cross-domain atomicity、追加provider/HA/scaleは広告しない。必要になった時は元の条件を参照する。

[historical-todo]: https://github.com/sunriselayer/sunrise-edge/blob/eb79768ba9806220576f3abe4e344b75b19390fe/TODO.md
[historical-m2]: https://github.com/sunriselayer/sunrise-edge/blob/eb79768ba9806220576f3abe4e344b75b19390fe/TODO.md#m2初期リリース対象の照合-2026-11-03
