# PR #339 mergeと次のM2候補

2026-10-30 (Asia/Singapore)。ユーザーの指示でPR #339をmergeし、停止対象以外の次候補を既存の契約とcodeから確認した。

## Mergeの照合

[PR #339](https://github.com/sunriselayer/sunrise-edge/pull/339) は2026-10-30 18:44:36 SGTにmerge済み。
merge commit `8a5cc30a1d4a6166c6a69e720713252112817833`、tree `a036f4ed11633b8ac3f59c29f417afc4c307a92f`。
順序付きparentsは `[9d22920ad08c9f9b05aedd9e6dfcf8730bb9ec09,77f6e576986b579ba6962f882c47a7c9829c9731]`。
local mainはfast-forward済み・clean。実装のtreeは[前回の全4profiles/完全required/全8CIの記録](../2026-10-30-recovered-genesis-foreign-split/README.md)と一致する。

merge直前にexact-headの8 CI jobs + Bugbotの全9 SUCCESS、review/inline threads各0を再確認した。
GitHub連携は権限403で変更できず、通常gh認証のhead一致条件付きmergeがactual0/両EOF/waitで完了した。
PR作成専用PATは使っていない。新しいmainの自動CIは別実行であり、その成功や新mainのRELEASE再buildは主張しない。

## 次に進める一つの範囲

既存の署名準備owner → 実CLI consumer → 受入済みprotected backend → lifecycle/実検証の対応表を、
architecture文書とcode参照付きで確定する。これは既存TODOが既に挙げる通常候補で、新しいM2必須gateの追加ではない。
ここで確認したcode対応は次の通り。これは候補選定の静的確認であり、新たなruntime検証ではない。

| 署名準備の分類 | 実装の対応と区別 |
| --- | --- |
| PreparedTransaction | [歴史的Ledger finalizer](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/signer.rs#L310-L333) は現在のproduction CLI callerを持たず、専用testを保持する。Ledger製品をM2の必須条件へ戻さない |
| PreparedLocalExecution | [generic local/general](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/local_execution.rs#L123-L140) はcustodyを明示拒否する。positive fee Splitの認識済みLegは別の有限consumerで、generic対応と数えない |
| PreparedPaidExecution | [generic paid](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/paid_execution.rs#L166-L185) はcustodyを拒否する。[Standard Asset](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/standard_asset.rs#L75-L130) はtransfer/split/merge/mint/burn/createの専用protected dispatchを持つ |
| PreparedPublication | [実publish consumer](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/publication.rs#L241-L263) は署名を受け取りprepared valueでfinalizeする。DR-0238の選択済みlocal OS componentと対応付ける |
| Original/successor bond preparation | [CLI registration](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/bond_registration.rs#L123-L155) はdevelopment seed/LocalSignerを使用する。準備と構造検証を、未選択protected governance backendの受入へ読み替えない |
| PreparedFeeClaim | [generic review/dev signing](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/apps/cli/src/commands/fee_claim_review.rs#L199-L228) と、DR-0269のpositive strict partial Split専用protected consumerを分ける。FinalTransferはそのbackendの対象外 |

original ordered/certified FastVote等のautomatic signingは、SDK prepared ownerへ混ぜず別のauthority ownerとして対応付ける。
各selected routeについて、historical signing-only・live recovered-key操作・取消/restart・正のidentity/ownership変更を
混同せず、既に存在する実検証の参照を付ける。完了済みconsumerを未達へ戻したり、似たfixtureを増やすことを目的にしない。

## 先に新しい署名接続を決めない理由

[signing preparation](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/docs/architecture/signing-preparation.md#L24-L54) の共有prepare/finalizeやLocalSignerは鍵保護の証明ではない。
canonical TODOのfamily表は、全accepted familyの有限な一覧とprotected governanceの具体契約を未確定としている。
[DR-0208](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/docs/architecture/decisions/0208-native-sqlite-first-and-protected-signing.md#L29-L50) は具体consumer/backend設計を実装に先行させる。
[DR-0214](https://github.com/sunriselayer/sunrise-edge/blob/8a5cc30a1d4a6166c6a69e720713252112817833/docs/architecture/decisions/0214-protected-custody-and-review-boundary.md#L5-L9) はProposedのまま。
したがってgeneric paid/local/bondやFinalTransferを、既存consumerへの単純なpath接続とみなして実装しない。
B鍵復旧等が前回の完了範囲外だったことだけで、新しい必須TODOにはしない。

今回行ったのはmergeと候補のcode照合まで。architecture対応表の反映と既存testへの完全な対応付けは次の作業。
ZeroShare fixture/WIP、停止済み独立監査、torn-WAL/mechanism2、独立anchor guestは再開していない。
元85 checkbox /71完了 /14未完了と親D02/M1/M2/M3/M7を維持する。

原証跡: `/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/pr339-merge-and-m2-next-1030-merge.json` と `pr339-merge-and-m2-next-1030-verified.json`。
