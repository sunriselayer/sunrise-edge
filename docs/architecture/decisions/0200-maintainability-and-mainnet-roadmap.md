# DR-0200: Semantic maintainability and one mainnet roadmap

Date: 2026-10-06 (Asia/Singapore)

Status: Human-requested planning direction. Detailed interface changes require
independent design review before implementation; this record approves no new
protocol authority, deployment or release-readiness claim.

## Context

The user requested a structural refactoring plan, one mainnet TODO and ten
hours of implementation. The old roadmap mixed live work, design and historical
attempts; existing architecture contracts already define most responsibilities.

## Decision

Keep the live queue in root TODO.md, structural plan in
implementation-structure.md, code locations in development/code-map.md and
dated rationale here. Preserve the original roadmap, criteria and failed or
interrupted evidence under development/history with rebased links; do not
reinterpret old pending statuses. Align AGENTS.md with these owners without
changing authority, security, validation or release requirements.

R0–R4 cover plan/gate reconciliation, contract/dependency ownership,
core/runtime responsibilities, attributable tests and CI, and audit/startup
seams. They describe outcomes, not mandatory PR size; the timed queue is in TODO.

A substantive refactor needs one invariant owner, migrated callers and removal
of the old mechanism. A mechanical move alone does not suffice. Canonical
bounds/codecs belong to their owner; transport overhead and deployment budgets
stay separate. Do not move execution, store or lifecycle authority into a
foundation crate merely to shrink the SDK dependency graph.

Group mainnet work under independent audits, protected signing, selected-profile
durability, checkpoint/backup/restore, ingress/operations, economic/genesis
approval, reproducible supported-runtime release and public testnet/final
approval. These map existing S4/S5, Phase 15–17 and cross-phase criteria;
none is waived.

PostgreSQL remains optional under DR-0151/0172, with its real suite required for
selected PG changes/claims. Other profiles need their own capability evidence.
Development remains local SQLite/loopback.

Ledger deferral permits non-Ledger work but does not close the original S4/mainnet
gate or all-provider release-scope question; those require a human-reviewed
decision. Do not invent production signing, economics, SLOs or a launch profile.

## Acceptance and non-goals

Preserve archived gate text/evidence and verify rebased links and live
requirements against it; update status only in TODO. Retain required real
functional tests, independent oracles, vectors, store faults and selected-PG
coverage. Path-filter skips, simulated success, changed unlock delays and
erased history are not CI optimizations.

Every implementation slice needs proportional checks, complete required
acceptance, independent exact-head source approval and required CI before a
normal merge. Approval is not a security audit or operational qualification.

The budget authorized local implementation only: no cloud resources,
production D1/Worker traffic, paid plans, live providers or launch. At the
deadline, stop new slices and retain exact head/review/test state and unmet gates.

## 2026-10-10 R1 submission-signature codec ownership

Execution owns the existing E009/version1 raw signature-envelope codec and
unchanged transaction-v1/submit-transaction-v1 messages; SDK uses it directly.
Core retains the public typed RequestId wrapper/reexports and existing API and
authentication order, while its duplicate constants/envelope builder are removed.

The raw owner encodes 32 identity bytes and the supplied payload, including
zero/empty values, without validating authority, transaction, signature or
durable outcome. Field copies precede the existing 32 MiB finish bound, not
preallocation admission. Core's nonzero RequestId and 1 MiB authentication
bound, SDK NodeCore mapping and unsupported-scheme/transaction-error priority
remain unchanged.

Seven source controls cover independent E009 literals, complete prepared/signed
bytes, exact/+1 frame-size and typed-zero refusal, and caller-error priority.
The large SDK operand is encoder-only; approximately 96 MiB of major live
buffers is source reasoning, not measured heap/concurrency or a resource grant.

At authorship: UNFORMATTED, UNCOMPILED, UNEXECUTED. No Cargo edge, protocol
bytes, crypto, custody or durable admission changed; R1/M2 and release gates
remained open pending actual validation.

## 2026-10-11 R1 generic validator-count bound ownership

Date: 2026-10-11 (Asia/Tokyo).

`validator_set::MAX_VALIDATORS` is the additive defining owner of the generic
10,000-member ceiling. Core fee-share and validator-entry codecs use it at
their four existing encode/decode bounds; two private copies are removed.
Wire bytes, APIs, errors and order remain: encoders build/validate items before
the count check; decoders reject excess counts before missing-item lookup.

The distinct live `MAX_FASTPATH_ACTIVE_VALIDATORS = 256` admission cap remains.
The generic record cap preserves historical reads and grants no membership,
key, quorum, custody, durable authority or wider live admission.

Eight source controls pin independent 10,000/10,001 boundaries for generic
construction/codec and both core codecs, including caller-limit clamping and
a narrower cap. Malformed count refusal precedes missing-item refusal.
Fixtures use ordered u32 IDs, unique opaque keys and power one, not verified
signers; charged settlements use ordered shares, conserved positive total,
generation one and no claims so the count is the first failure. Existing
vectors and committee controls remain.

At authorship: UNFORMATTED, UNCOMPILED, UNEXECUTED. This removes duplicate
bounds, not a Cargo edge or all SDK/core coupling. It established no measured
build, runtime or custody result; R1 still required targeted/full validation,
independent review and CI.

## 2026-10-11 R1 consensus decoder-byte bound ownership

Date: 2026-10-11 (Asia/Tokyo).

Consensus owns the strict decoder caps
`MAX_ENCODED_CERTIFICATE_BYTES = 8_388_608` and
`MAX_ENCODED_PROPOSAL_BYTES = 10_485_760`, additively reexported from the
crate root while durable stays private. Node-wire replaces two numeric copies
with these owners. Transport still owns certificate 8_388_608, ordered proposal
11_018_240 and status 8_388_864 byte totals, including framing/derivation.

`actual > max` still precedes canonical parsing. Values, bytes, codec bodies,
errors and priority, signatures, context/admission checks, manifests and Cargo
edges remain unchanged. These decoder caps grant no universal encoder capacity,
committee or custody authority.

Five consensus controls pin both literals and malformed zero frames at cap and
cap+1: canonical refusal at cap, existing typed oversize refusal above it.
One wire control pins all three totals and owner/overhead relations; existing
vectors and controls remain.

Independent design/source reviews approved this four-Rust-path slice only.
At authorship its six controls were UNFORMATTED, UNCOMPILED, UNEXECUTED and
outside the original 41 selectors. Removing copied bounds did not resolve all
SDK/core coupling or qualify build benefit, runtime, valid capacity, custody,
release or R1; targeted/full and CI remained separate.

## 2026-10-11 R1 frozen-frontier bound ownership

Date: 2026-10-11 (Asia/Tokyo).

The frontier codec publicly owns its 8,192-byte vote cap through the distinct
`MAX_FROZEN_FRONTIER_VOTE_BYTES` alias, not the equal availability-vote cap.
Wire uses it with existing 524,288-byte page and 128-entry owners, preserving
public names/types. A private const assertion precedes the u16 entry-limit
cast; compiler qualification was pending. Transport still owns the 128-byte
request, 64-byte response allowance and derived 532,544-byte response cap.
No Cargo edge changes.

The vote encoder checks after frame construction; the strict decoder checks
before parsing. Codec bodies, values, signatures, error variant/text/priority
and caller authority checks remain unchanged. The cap grants no authentication,
quorum, persistence or custody authority.

Four consensus and five wire controls pin literal caps, at-cap canonical versus
cap+1 bound refusal, page count and wire refusal order. The 128-entry page
round-trips; the 129-entry frame has 129 valid nested identities in fields
4–132, 132 complete fields and literal length 41,441, avoiding a missing-body
shortcut. Request controls pin limit-only 129 refusal and limit-before-zero-
cursor priority after framing checks. Opaque vote/page parts round-trip only
as an envelope; framed component+1 cases stay below the outer allowance and
retain vote-before-page refusal. Malformed-at-cap is not valid capacity proof.

Independent design/corrected-source reviews approved this five-Rust-path slice;
the original review BLOCK remains historical. The persistence disclaimer and
isolated 129/None encode/decode controls resolved its two conformance gaps.
Existing functions, controls and vectors remain. At authorship nine new
controls were UNFORMATTED, UNCOMPILED, UNEXECUTED and outside the original 41.
No runtime, signed capacity, quorum, retention, physical durability or custody
was qualified; R1 and twenty completion groups retained targeted/full,
independent exact-head and CI/release gates.

## 2026-10-11 human amendment: code completion versus network launch

Date: 2026-10-11 (Asia/Tokyo).

The human authorized local Docker PostgreSQL and bounded isolated Docker
disk-full/forced-stop experiments, excluding host disk filling, global
swap/settings, foreign workloads, cloud/public activation and real keys.
The old environment refusal remains historical; permission proves no result.

Keep SOURCE, VERIFY and LAUNCH distinct: source alone is not verified CODE.
Cryptographic, atomicity, recovery/fault, advisory, independent review and
exact-head required/selected-profile/CI gates remain code obligations.
Actual keys, backup/operator ceremonies, production topology/workload,
genesis/economics and activation are human-owned launch choices. Disposable
values may verify parameterized code without choosing production values;
protected signing/content, genesis/supply and recovery code remain required.

This closes no checkbox. The twenty readiness groups retain their mappings;
only launch-only actions leave code completion. A separately provider-stopped
dependency workflow remains stopped: Docker permission is neither runtime
admission nor retry/reroute permission. Progress belongs in TODO.

## 2026-10-12 R1 retained-receipt reconciliation binding

Durable reconciliation now calls pure `NodeDedupRecord::decode_bound` rather
than duplicating nested identity/digest and canonical re-encoding checks.
Lookup identity and outer event-digest/RequestIdReuse checks still precede it;
decode/projection/encoding error mappings and order, responses, and replay's
absence of outbound work, state/object reads or commit remain unchanged.

Four controls supplement genuine idempotent/paid/claim/bond replay tests:
absence/exact output, joint-invalid outer identity/reuse, nested identity/
digest substitution and malformed canonical bytes. Source review and actual
targeted/full acceptance remained separate; this alone qualified no custody,
inclusion, release or whole R1 completion.
