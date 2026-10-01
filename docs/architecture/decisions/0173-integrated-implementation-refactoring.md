# DR-0173: Integrate functional delivery and implementation refactoring

Date: 2026-10-01 (Asia/Singapore)

Status: Accepted planning direction. No runtime, canonical bytes, authorization
or activation policy changes are introduced. Current implementation status and
the only live queue remain in [TODO.md](../../../TODO.md).

## Context

The user requested an overall implementation-refactoring plan integrated with
the remaining feature plan, after making PostgreSQL acceptance optional in
DR-0172. File-level cleanup alone would obscure the outstanding functional
critical path; treating every recorded production criterion as an initial-
network prerequisite would again delay usable features.

Read-only code and roadmap reconnaissance at main `a969ed4` found mixed
responsibilities in core/runtime facades, ordered orchestration, source
reconstruction, SQL internals and host/artifact plumbing. Large files also
contain already-extracted or inline test suites, so file length is not a useful
standalone priority measure. The current wire and Rust SDK dependency on
node-core is real and must not be described as an already-minimal protocol SDK.

The active baseline includes certified generic contracts and fixed-epoch
ordered economics. Complete epoch handoff is still open: the DR-0170 audit
does not reconstruct legitimate frozen member application without aggregate
availability evidence, and audit comparison is not complete cut derivation,
persistent import or serving authority. Old chronological TODO prose also
continued to describe completed functions as open or PG as mandatory.

## Decision

### One live plan, separate stable responsibilities

Integrate feature dependencies, needed refactors, parallel cleanup, deferred
work and acceptance in TODO's current roadmap. Detailed lower gates retain
their invariants and dated implementation evidence, not a competing execution
order. Keep the As-Is navigation in
[code-map.md](../../development/code-map.md) and stable target ownership in
[implementation-structure.md](../implementation-structure.md). README receives
no current-status section. Architecture and this dated ADR do not duplicate
changing checkboxes or PR progress.

### Functional outcomes lead

Complete the authenticated drained business cut, then guarded persistent
import, readiness/Seal/activation and usable membership/recovery. Integrate
only the reconstruction/drain, runtime/store, ordered authority and serving-
context separations needed by each capability. A stage can span coherent
callable feature PRs; it is not one mandatory whole-Delivery PR and not a
sequence of codec-only PRs.

Optional facade, artifact/configuration and test organization may proceed in
parallel when ownership is disjoint. They must not block the critical path
merely because a file exceeds an arbitrary length. Mechanical moves have
separate reviewable commits; new authority semantics belong to their feature.
Keep existing crates and public reexports by default. Broad crate/SDK decoupling
waits for stable serving-epoch semantics and an actual consumer.

### Preserve safety and store neutrality

Preserve exact canonical bytes/IDs/domains, deterministic effects, receipt-first
replay, historical verification, ownership/custody, bounded work and atomic
state/object/nonce/receipt/publication/settlement composition. No private asset
path, blanket metadata-prefix exclusion, fabricated availability proof,
destructive history reset or force activation is authorized by reorganization.
Memory stores remain a production reconstruction dependency. Shared SQL rules
already used by SQLite/DO stay shared; PostgreSQL-specific behavior does not
need to be forced into that interface.

DR-0151's one-validator transactional domain and optional deployment products
remain unchanged. D1 is a candidate requiring an actual adapter and conformance,
not an implementation or mandatory detour. DR-0172's four unconditional DB-free
lanes remain the required gate; relevant PG changes and claims need fresh
selected-source complete PG evidence. Generic changes retain proportionate
real integration checks. Neither refactoring nor passing another backend
certifies a provider.

### Release scope is explicit

Validator-set changes, slashing and reward/claim distribution remain FastVote
completion criteria. Prepare independent economics/ingress audit and executable
auth/TLS/startup/recovery work alongside functions; close those gates and the
selected activation profile before live exposure. Namespace E2E, tech-lead
review and docs are not a security audit or deployment approval.

An initial bounded non-production network requires its own reviewed activation
profile. This planning decision does not introduce it, waive S4/S5 or weaken
the existing protocol-v3/production/mainnet activation constraints. Ledger,
UI/TypeScript, Unique Asset, multisig, upgrades, sustained load/SLO adoption and
HA/full provider production gates stay separately deferred rather than
silently completed or restored as current functional prerequisites.

## Consequences

The next change has a concrete functional consumer and a finite structural
scope; there is no open-ended cleanup phase before it. Readers have one live
queue, one current code-navigation map and stable ownership contracts. The
plan distinguishes a merged prerequisite, complete membership functionality,
an audited initial-network profile and full production readiness.

No production implementation is moved by this documentation change. Future
refactors must demonstrate preserved behavior rather than claim performance,
compile-time or readiness improvements from file splitting alone.
