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

## 2026-10-11 R1 generic validator-count bound ownership

Date: 2026-10-11 (Asia/Tokyo).

The existing generic 10,000-member ceiling has one defining owner,
`validator_set::MAX_VALIDATORS`, exposed additively from the validator-set
crate. Core's fee-share and validator-entry record codecs consume that owner
at their four existing encode/decode bound operands. The two private copies
are removed without changing wire bytes, record APIs, errors or check order.
Encoders still validate/build their items before the list-bound check;
decoders still reject excessive counts before looking up missing list items.

The distinct `MAX_FASTPATH_ACTIVE_VALIDATORS = 256` live economics admission
limit remains unchanged. The generic record ceiling preserves historical
readability; exposing it grants no membership, key, quorum, custody or durable
authority and does not widen live admission.

Eight appended source controls use independent literal 10,000/10,001
boundaries for generic construction/codec and both core record codecs.
The generic decoder control retains caller-limit clamping and a narrower
caller cap. Count-only malformed frames retain refusal priority over missing
members/items. Structural fixtures use ordered u32-derived IDs, unique opaque
keys and power one, not verified signing keys. Charged settlements have
strictly ordered shares, a conserved positive total, generation one and no
claims, so their excessive-count refusal is not an earlier invariant failure.
Existing complete vectors and committee controls are left unchanged.

UNFORMATTED, UNCOMPILED and UNEXECUTED. This source implementation removes
duplicate bound definitions, not a Cargo edge or all SDK/core coupling. No
build benefit, execution result or custody qualification is measured. R1
remains open; targeted/full validation, independent implementation review and
required CI gates remain unmet by this slice alone.

## 2026-10-11 R1 consensus decoder-byte bound ownership

Date: 2026-10-11 (Asia/Tokyo).

The existing strict decoder admission caps have one defining consensus owner:
`MAX_ENCODED_CERTIFICATE_BYTES = 8_388_608` and
`MAX_ENCODED_PROPOSAL_BYTES = 10_485_760`. Both are additively reexported from
the crate root; the durable module remains private. Node-wire consumes these
owners instead of two copied numerical operands. Candidate/framing overhead
and status derivation remain unchanged and transport-owned: certificate
8_388_608, ordered proposal 11_018_240 and status 8_388_864 bytes.

The existing `actual > max` checks still precede canonical parsing. Values,
canonical bytes, codec function bodies, error kinds/fields/text/priority,
signatures and context/admission checks remain unchanged. These are decoder
admission caps, not universal encoder limits, admissible capacity, committee
or custody authority. No manifest or Cargo edge changes.

Five appended consensus controls independently pin the two public literals
and malformed zero frames at each literal cap and cap+1. At-cap inputs reach
canonical refusal; cap+1 inputs assert the complete existing typed oversize
refusal. One appended wire control separately pins all three literal totals
and their owner/overhead relationships. Existing vectors and controls remain.

Independent design and implemented-source reviews approved only this exact
four-Rust-path slice. All six controls remain UNFORMATTED, UNCOMPILED and
UNEXECUTED, outside the original 41 selectors. This removes copied bounds,
not all SDK/core coupling. No build benefit, runtime, valid-capacity, custody
or release qualification is established. R1 remains open; all required
targeted/full and CI validation remains separate.
