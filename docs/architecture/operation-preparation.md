# Writer-free operation preparation

This refines the [architecture contracts](architecture-contracts.md) for
business evaluation and atomic completion. [DR-0181](decisions/0181-writer-free-operation-preparation.md)
records the design decision; implementation and review status belong only
in [TODO.md](../../TODO.md).

## Responsibility and data flow

```text
authenticated original + exact admission + read-only dependencies
                             |
                     owning preparation
                             |
              proposed effects + original receipt + output
                             |
              direct commit OR ordered composition
                             |
              actual confirmed/rejected/indeterminate store result
```

Preparation may execute the deterministic contract engine, but never reports
a successful durable write. It cannot acquire a writer, expose a consensus
signature, advance a nonce, retain an original receipt or publish business
effects. A prepared transaction is a proposal, not an authenticated operation
capability. The operation's owning verifier still controls admission.

Direct handlers and ordered live/recovery/private reconstruction use the same
owning preparation. Direct wrappers invoke actual persistence with the
owner's existing reconciliation policy. Ordered completion joins protocol
progress and deciding observations with the original transaction and invokes
one actual commit. There is no capture store, intercepted commit, synthetic
`Committed` acknowledgement or second business evaluator.

## Read contracts

`VersionedStateReader` remains the lowest exact-value/revision port. A minimal
`StructuredStateReader` extends it with mandatory lifecycle, object-head,
immutable object-version and original-receipt reads. Distinct `read_*` methods
avoid ambiguity with the existing durable store interface. Existing structured
stores forward into the lower read contract; no reverse implementation can
promote a reader into a writer. No default fabricates lifecycle or an absent
receipt.

The ports grant neither a stable snapshot nor live protocol authority. They
forward the same local domain, deadline, writer-fence and schema checks. Narrow
only actually read-only helper chains; a real commit wrapper continues to
require a writable store. Pure helper conversion does not weaken its owning
signature, provenance, history or resource validation.

A private `ObservedBusinessReadView` has two consumers: ordered original
evaluation and fresh signing preflight. It implements only read ports and
records the bounded physical state observations in one logical domain.
Conflicting revisions poison the attempt. Its consuming finish checks poison
before propagating a handler refusal or stop, so no decision can be retained
from inconsistent reads. A genuine read failure remains a read failure; an
observation invariant never becomes fictitious backend commit ambiguity.

Object-head/version observations remain with the existing owning transaction
and admission checks. Do not turn this view into a second universal snapshot
or provider API. Read-only verification which needs one state value does not
acquire the larger structured interface merely for uniformity.

## Logical dependencies are not the physical read closure

Each business owner derives its logical generation/provenance from its exact
existing business dependency map. Configuration observations join only after
that derivation. The observed view's broader closure joins final CAS assembly;
it never becomes a signed logical dependency map. Direct handlers retain their
existing transaction read sets.

These separate maps express different meanings. Collapsing them would change
authenticated generations and row/object bytes, even if every physical read
looked consistent. Share observation consistency and bounded assembly, not
the choice of signed operands.

## Preparation owners

| Owner | Prepared result | Responsibility retained by the owner |
| --- | --- | --- |
| Fee claim | Original invocation or exact retained replay | Historical entitlement/signature, generic custody execution, payout conservation, settlement/claim provenance and nonce |
| Bond lifecycle and initial registration | Original invocation or exact retained replay | Exact transitions, custody, pristine initial slot, resulting-row signature commitment, generation and anchor |
| Slash | Shared bond-transition invocation or exact retained replay | Historical evidence, liability window, evidence-consumption marker and forfeiture |
| Equivocation evidence | Existing exact evidence or new bounded metadata proposal | Normalized immutable identity, all three evidence families and direct same-key-race reconciliation |
| Freeze | Bounded control-state proposal and output | Exact closure mutation; fresh signing eligibility remains preflight-owned |
| DrainSet | Bounded control-state proposal and output | Independently verified Freeze/readiness and exact selected union; never member application |

Invocation-bearing owners return distinct retained and prepared results.
Prepared owns the existing bounded `DurableInvocationTransaction` and exact
output. Receipt/output consistency is checked before commit. This common
description is not a generic business handler registry or a permission to
omit receipts. An unexpected retained replay inside an independently admitted
fresh ordered attempt stops; normal original replay remains receipt-first.

Evidence keeps its own result because it does not have an invocation receipt
or nonce. The direct committer preserves the existing exact same-key-conflict
reread and returns `AlreadyRecorded` only from actual matching retained data.
Ordered composition preserves the no-effect existing-evidence outcome while
atomically retaining its own original receipt and progress. Do not flatten
these cases into generic commit success.

## Confirmation and error ownership

- Direct invocation wrappers retain `durable_reconciliation::committed_output`
  and their existing exact request/event identity checks.
- The ordered owner retains reservation release, archive/outcome/applied-prefix
  and consensus-state updates in the same original completion. A stop releases
  nothing and exposes no output.
- Rejection, read failure and indeterminate writes remain distinct. Only an
  actual confirmed commit or the existing exact retained reconciliation can
  expose a completion. No successful preparation manufactures confirmation.
- Immutable code/object body reads do not become blob writes. Audit the
  reachable engine and artifact paths; acceptance must prove preparation has
  no state, receipt or blob publication side effects.
- Object mutations, original receipts, outbox sections and logical bytes remain
  unchanged. No new committee, readiness, Seal, activation or provider authority
  is introduced.

## Migration and acceptance

Migrate every ordered arm and both observation-view consumers in one coherent
slice. Preserve public direct-handler signatures as preparation/actual-commit
wrappers. Remove the superseded `StagingStore`, interception slots, synthetic
outcomes and interception-only tests once all consumers use writer-free
preparation. Do not leave two permanent frameworks or claim migration from
new type declarations alone.

Required evidence includes reader negative-capability compilation tests;
genuine preparation with no effects; direct and ordered positive/refusal,
same-key evidence race, deciding-row CAS interference and ambiguity controls;
real SQLite close/reopen/exact replay/fencing; and direct/ordered/private
reconstruction generation and byte comparisons. Existing independent vectors
and all acceptance assertions remain. The full local gate, independent exact
head review and CI still apply; PostgreSQL acceptance remains explicitly
selected, not mandatory for every operation.
