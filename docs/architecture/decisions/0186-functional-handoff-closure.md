# DR-0186: Functional Seal and authenticated serving closure

Date: 2026-10-02 (Asia/Singapore)

Status: **Proposed** for independent design review. No implementation approval,
wire/key allocation, migration, serving activation or deployment is authorized.
Current work and evidence remain only in [TODO.md](../../../TODO.md).

## Context

[DR-0180](0180-architecture-first-interface-contracts.md) asks for responsibility
and authority redesign, not file splitting or unused frameworks. The existing
handoff contracts distinguish completed import, conditional readiness, committed
Seal, post-Seal transition authority, serving and recurring reconstruction.
[DR-0177](0177-conditional-readiness-and-ordered-seal.md) leaves live suffix and
Seal companions unresolved. [DR-0178](0178-conditional-readiness-wire-and-retention.md)
already chooses separate verified staging for retained and incoming validators.

Source inspection establishes real missing seams: fixed terminal cut proofs
are not complete high/locked traversal; cache pruning does not promise that
closure; readiness can exceed the ordered intent bound; exact-key CAS does not
check a whole snapshot sequence; raw legacy transition signing is not protected
retention; successor serving/epoch keys cannot come from genesis-only policy.
Supported profiles currently refuse these unfinished authority paths. This
record alleges no existing exploit and supplies no substitute permission.

## Proposed decision

Use [functional-handoff-closure.md](../functional-handoff-closure.md) as the
concrete proposed functional contract, with primary-source links. Its choices:

1. Reuse separate verified staging for A/B/C/E. Confirm outgoing closure before
   target-local activation, preserving both namespaces and permanent import
   origin. Cross-namespace retirement need not be atomic only if fresh core
   completions/exposures and backend ordinary writers enforce committed closure.
2. Separate semantic target from bounded retained transport companions. Verify
   real cut/readiness/suffix material before voting; retain references with the
   actual event. Keep current Seal proof/receipt outside its own pre-Seal roots.
3. Verify phase-aware high/locked/proposed-QC ancestry to the exact selected
   anchor, with bounded continuations and evidence retained before pruning.
   Recover inherited business normally; never reset locks or infer missing data.
4. Check the token-covered local mutation sequence inside Seal/activation
   completion, alongside deciding observations and the actual assembled result.
   Add only consumed completion seams, not a generic maintenance override.
5. Retain one unique outgoing signer/epoch-transition slot after committed Seal.
   Positively initialized virgin protected history, not absent cache alone,
   permits initial signing. Exact retry does not sign; conflicting/tombstoned
   history refuses. Ambiguity
   exposes no authority until fresh reconciliation observes exact landed bytes.
6. Review distinct purpose/versioned schemas and successor epoch-key families;
   retain original signed preimages and verification. Bind verified predecessor,
   Seal/cut/set and the independently trusted complete schedule. Genesis does
   not authenticate arbitrary future local schedule extensions.
7. Atomically install proof-backed successor policies/provenance/safety/serving
   under its own fence, then reconstruct recurring epochs from that predecessor.
   Neither a namespace selector, stored active flag nor public certificate is
   a serving producer. Historical withdrawal ownership is not current membership.

## Not yet decided

Exact competing Seal no-effect outcomes, phase/error tags, traversal rules and
limits, companion retention/manifest shape, activation/provenance preimages,
token-covered completion interfaces, protected virgin-slot initialization and
canonical/storage allocations require independent pre-code review.
The closure/no-cross-namespace-atomicity argument
must be checked against every actual fresh completion and exposure path.
Do not preselect numeric IDs or treat proposed function names as callable APIs.

## Consequences and acceptance

Implement coherent Seal, protected transition/activation and recurring lifecycle
features with actual engine/store/operator/client consumers. No universal context,
second consensus engine, unused sealed ports or source moves are prerequisites.
Preserve original canonical evidence, real outcomes and fences; no source lock
copy, forced epoch, timeout unfreeze, destructive reset or automatic repair.

Require real-SQLite proof/atomicity/crash/replay negatives and genuine recurring
replacement through the real withdrawal unlock epoch, independent vectors,
exact-head review and unchanged complete gates. PG remains optional with actual
selected acceptance for relevant changes/claims. Ordinary CAS promises no
whole-database rollback detection. This Proposed record completes no Delivery 3,
independent security audit, startup, provider or production qualification.
