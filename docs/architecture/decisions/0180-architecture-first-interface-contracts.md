# DR-0180: Architecture-first interfaces and owning implementations

Date: 2026-10-02 (Asia/Singapore)

Status: User-requested planning direction. Detailed interface proposals require
independent review before their owning implementation. No new protocol,
signing or activation authority is introduced by this record.

## Context

DR-0173 integrated refactoring with functional delivery and discouraged a
repository-wide rewrite as a prerequisite. The user now explicitly requests
a broader architecture-first pass: fundamentally review the design, establish
coherent code interfaces for the whole system and remaining functions, then
fill their implementations. Tests and CI must follow the same model. The work
window is approximately eight hours, not an assertion that complete handoff
or production readiness can be achieved in that time.

This is not a request to split long files. The relevant design questions are
which owner makes a decision, what a type proves, which observations remain
valid at commit, whether two paths implement the same invariant, and how
the remaining functions compose without protocol-specific backdoors.

## Decision

The [architecture contracts](../architecture-contracts.md) define the target
responsibility/dependency model. Start with its global map and defining
interfaces, then integrate independently useful owning implementations and
their actual callers. Keep one live implementation/refactoring queue in
[TODO.md](../../../TODO.md). The code map describes actual owners; README does
not become a changing progress report.

This supersedes DR-0173's narrow sequencing preference for this explicit work
window, not its safety, store-neutrality, validation or release boundaries.
Broad crate churn and universal handler/store frameworks still need a real
consumer and a demonstrated invariant; they are not aesthetic prerequisites.

Separate immutable genesis trust, verified current serving authority,
historical verification and physical operation context. Keep common atomic
transaction assembly distinct from business admission. Keep original receipt
replay distinct from cached live-authority exposure. Preserve one owning
execution and consensus mechanism rather than creating alternate engines.

The user accepts unfinished code interfaces. Isolate such skeletons from
advertised runtime compositions; prefer an explicit unsupported result to a
reachable panic. A missing body or public certificate cannot manufacture a
verified capability. Do not replace working features with placeholders.

Implement semantic redesign and removal of duplication where the interface
has a real caller. Review authority changes as authority changes, not as
mechanical moves. Historical receipts, proof verification, exact canonical
bytes and safety state are not discarded for naming or unreleased API
cleanliness. Changes to protocol formats require their own explicit contract.

## Acceptance and exclusions

Every accepted slice identifies the invariant it centralizes, migrated
callers, removed duplicate mechanism, tests and unresolved feature bodies.
Preserve real positive/negative, restart/fencing/atomicity and independent
vector coverage. Keep four unconditional DB-free lanes and explicit selected
PG acceptance; PostgreSQL does not become mandatory.

Use independent exact-head review, the complete required local gate and
required CI before normal merge. A passing skeleton is not functional
completion; tech-lead review is not the independent security audit. No live
deployment, timeout unlock, maintenance bypass, Standard Asset privilege,
new readiness/Seal/serving authority or production certification is approved
by this plan.
