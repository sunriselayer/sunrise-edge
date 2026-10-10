# DR-0200: Semantic maintainability and one mainnet roadmap

Date: 2026-10-06 (Asia/Singapore)

Status: Human-requested planning direction. Detailed interface changes require
independent design review before implementation; this record approves no new
protocol authority, deployment or release-readiness claim.

## Context

The user requests a saved refactoring plan covering fundamental design,
maintainability, redundancy and over-engineering, a consolidated mainnet TODO,
and ten hours of continued implementation. File splitting alone is insufficient.
The existing roadmap mixes a live queue, repeated design brief and thousands
of lines of historical attempts. Existing architecture contracts already define
most responsibilities; another generic framework or parallel roadmap would make
that problem worse.

## Decision

Keep one live queue in root TODO.md, one responsibility-oriented structural
plan in implementation-structure.md, actual locations in development/code-map.md,
and dated rationale here. Preserve the old roadmap and original criteria under
development/history, clearly marked historical, with repository links rebased.
Do not erase failed/interrupted evidence or reinterpret old pending statuses.
The human's requested documentation/plan consolidation also covers aligning
the contributor orientation in AGENTS.md with these owners. This changes no
authority, security, validation or original release requirement.

Use R0–R4 work packages: plan/gate reconciliation; public contract/dependency
ownership; core/runtime semantic responsibilities; attributable tests and
nonredundant CI; audit/startup integration seams. They are outcomes rather than
mandatory helper-sized PRs. The ten-hour queue is in TODO, not this record.

A substantive refactor has one defining invariant, actual migrated callers and
a removed old mechanism. A mechanical move may support that work but cannot
stand in for it. Shared canonical bounds/codec contracts belong to their defining
owner; transport framing overhead and local deployment budgets stay separate.
Move no execution, store or lifecycle authority into a new foundational crate
just to make an SDK dependency graph look smaller.

Consolidate mainnet work into independent release audits, protected signing,
selected-profile durability, checkpoint/backup/restore, ingress/operations,
economic/genesis approval, reproducible supported-runtime release and public
testnet/final approval. These are mappings of existing S4/S5, Phase 15–17 and
cross-phase criteria, not permission to delete or soften them.

PostgreSQL remains optional under DR-0151/0172; its actual suite is retained for
selected PG changes/claims. Lightweight profiles need their own real capability
evidence, not a renamed PG pass. Development remains local SQLite/loopback.

The later Ledger deferral permits non-Ledger software work but does not itself
close the original complete S4/mainnet constraint. Keep that gate and the
all-provider release-scope question open until an explicit human-reviewed
decision changes them. Do not invent a production signer, economic configuration,
SLO or launch profile merely to finish an automated window.

## Acceptance and non-goals

Preserve original gate text/evidence in the archive; check rebased links and
all live requirements against it. Status is updated only in TODO. Retain all
required real functional tests, independent oracles, protocol vectors, actual
store faults and optional selected-PG coverage. No path-filter skip, simulated
success, changed unlock delay or erased history is a CI optimization.

Every implementation slice needs proportional targeted checks, complete required
acceptance, independent exact-head source approval and required CI before a
normal merge. Approval is not a security audit or operational qualification.

The budget authorizes continued local implementation, not cloud resources,
production D1/Worker traffic, paid-plan changes, live provider activation or
public/mainnet launch. Stop starting new slices at the window deadline; retain
real head/review/test state and any unfinished requirements.

## 2026-10-10 R1 submission-signature codec ownership

The existing E009/version1 raw signature-envelope codec and the unchanged
transaction-v1/submit-transaction-v1 message families belong to execution.
The SDK uses that owner directly. Core retains its public typed RequestId
wrapper and reexports, preserving existing API paths and authentication order.
Its old defining constants and local envelope construction are removed.

The raw owner encodes exactly 32 identity bytes and the supplied payload,
including zero identity or an empty payload. It validates no request authority,
transaction, signature or durable outcome. Field copies precede the existing
32 MiB canonical finish bound; this is not preallocation admission. Core's
nonzero RequestId and separate 1 MiB authentication bound remain unchanged.
SDK canonical-envelope failure still maps to the existing NodeCore error;
unsupported-scheme and transaction-encoding errors retain their priority.

Seven added source controls use independent complete E009 literals, complete
prepared/signed bytes, exact/+1 frame-size refusal, typed-zero refusal and
caller-error priority. The large SDK operand is an encoder-only negative,
not an admissible transaction. Approximately 96 MiB of major live byte buffers
is source reasoning, not a measured heap/concurrency ceiling or resource grant.

UNFORMATTED, UNCOMPILED and UNEXECUTED. This ownership slice changes no Cargo
edge, protocol bytes, crypto, custody or durable admission and does not close
R1/M2 or qualify release. Actual validation and all existing gates remain.
