# DR-0111: Generic contract authority and revision model

Accepted: 2026-09-07 (Asia/Singapore).

The accepted target contract is maintained in
[`docs/design.md`](../../design.md). The dated rationale, primary sources, and
As-Is/To-Be gap at the decision point are preserved in the
[2026-09-07 meeting record](../../meeting-notes/2026-09-07-generic-contract-design.md).

This decision requires Standard Asset and user contracts to share public
execution and authority facilities, immutable code revisions, authenticated
type provenance, isolated instances/objects, and explicit upgrade/migration
authority. Remove superseded unreleased privileged paths during replacement.
The target is not a claim of implemented behavior; status and completion
criteria remain in [`TODO.md`](../../../TODO.md).
