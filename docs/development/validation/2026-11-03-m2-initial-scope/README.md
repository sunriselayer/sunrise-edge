# M2初期リリース対象の既存要件照合

2026-11-03 (Asia/Singapore)。ユーザーは初期対象を既存要件と照合し、停止対象を除く
必要な実装・検証をTODOへ具体化してcommit/pushするよう依頼した。
この記録は通常の要件・証拠の対応確認であり、security auditや新backendの設計・実装ではない。
現在の対象と実行順は[canonical TODO](../../../../TODO.md#m2初期リリース対象の照合-2026-11-03) が所有する。

## 照合元と成果物

main `8afaf3566294fe3d6e2096ac4107d2270439b7a8`、tree `d392a0da9c8805a8bcc8bf84acd674eb3a42f54e` と、
status branchのbase `c12bc7d176a65efeabcec414e918b7f6a17b72b2` を照合した。
SSHのremote ref確認も両commitと一致した。open PR一覧に今回のmainより新しいM2実装stackはなかった。
保留中の依存更新・旧WIPには変更を加えていない。

変更はcanonical TODO、本文書と[静的検証記録](verification.json) だけ。
TODOへ元要件の根拠、選択済みcomponent、未選択の保護境界、M2-N1〜N5の作業/成果物/依存を記載した。
既存のaccepted decisionを変更する作業ではないため、新ADRや新release profileは作成していない。
初期profileの承認、ProposedのDR-0214の受入、元条件の免除は行っていない。

## 対応確認

要件と既存証拠を2担当のread-only Codex subagentsへ英語で分担し、rootが原資料と照合した。
両担当とも新しいselected recovery consumerの配線漏れは特定しなかった。
accepted DR-0211がreadinessのprotected provider/host接続をM2へ残していること、
DR-0264/0268のautomatic custodyがsuccessorを含まないことを区別してTODOへ反映した。
全prepared型の保護対応や全identity移行を新しい必須条件として追加していない。

作成後の通常の文書対応確認では、genesis authorをprepared型だけで説明していた表現と、
e8 withdrawal候補数の曖昧な表現を修正した。前者は既存author/build ownerを明記し、
後者は元のwithdrawal候補2件とした。別担当の追確認はmodel capacity errorで結果がなく、
再試行・別モデルへの付け替えは行っていない。rootが既存証拠と変更全体を確認した。
これは独立security/release reviewやその代替ではない。

## 文書の検証範囲

[DR-0236のDocumentation acceptance](../../../architecture/decisions/0236-separated-code-verification-and-launch-tracking.md#documentation-acceptance)
に従い、対象は文書の静的検証とした。変更内のlocal/pinned-main参照、section anchors、
根拠資料のtracked bytes/hash、元checkbox列と20親ID、ASCII括弧、diffの空白を確認した。
各元資料のcommit/path/SHA256と確認結果は `verification.json` に記録する。

Rust/Node/runtime、test selector/timeout/budget、workflow、lockfileや信頼境界は変更していない。
今回はliteral npm ci、完全required、Docker、RELEASE、CIを実行しておらず、
新しい製品qualificationとして記録しない。PR #340の以前の完全検証とmergeは
[2026-11-01の別記録](../2026-11-01-pr340-environment-and-validation/README.md) のsource/profileへ帰属する。
文書照合の合格をM2や他の親milestoneの完了へ転用しない。

## 除外と保持

停止済みD02/M1独立監査、ZeroShare WIP/fixture、M3 torn-WAL assessment/mechanism2、
独立anchor VM boot修正は作業分担・実装・再試行の対象にしていない。
その未完了記録、旧失敗・証拠と完了済みの選択範囲を保持した。
実鍵・host users/security policy、公開設定、deploy、main mergeやautomationの作成は行っていない。
PATは使用せず、status branchを通常のSSH pushで更新する。
