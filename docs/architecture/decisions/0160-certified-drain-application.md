# DR-0160: Apply only committed DrainSet members through a separate certified path

Date: 2026-09-30

## Decision

A post-Freeze full FastCertificate without an aggregated availability
certificate may be applied only through a separate drain entry point. Ordinary
`apply`, published apply and recovery keep their existing admission and
publication-certificate gates. The drain entry point accepts a request ID,
not caller-supplied signed intent, certificate, lock list or publication
authority. It loads the original signed bytes and full certificate from its
own retained proof.

Before fresh effects, the replica independently verifies a committed ordered
DrainSet record for the current outgoing epoch, that record's exact selected
signed frontier quorum, its own CAS-fenced ready marker for the same union,
membership in a selected signer's confirmed entry set, and the member's
durably retained full certificate, signed intent, witness and replay-artifact
closure. It then re-executes against its actual predecessor state and requires
the exact full-certificate commitment and locked-object digest. A ready marker
alone, an unverified member row, or a supplied certificate alone is never
authority. All observed authority rows enter the effects transaction's CAS
read set. Missing, corrupt or inconsistent prerequisites stop without effects.

The normal current-epoch mutation fence remains closed after Freeze. Only
this proven drain path can enter the shared paid-admission pipeline in its
distinct `DrainApply` mode; an unconstructible-outside-the-drain-module permit
prevents other callers from choosing that mode. It still CAS-fences the
current outgoing epoch, but the already committed Freeze is not reinterpreted
as a ban on completing the DrainSet's certified obligations. The signed
logical commitment excludes physical creation-checkpoint counters.

A local partial prepare Y may hold an object or sender/epoch nonce lock that
the certified member X needs. Drain resolution reads the exact lock row and
Y's prepared row, validates the same object reference and epoch or sender,
epoch and nonce, and refuses a missing/mismatched prepared row or an existing
local Y certificate/receipt. Only locks actually encountered in X's own
admitted input set can be deleted. X's own local prepare locks are deleted
without being misreported as displaced Y locks. Lock deletes, X's effects,
nonce, settlement, witness, original receipt and an immutable per-displaced-
lock `0x6450/v1` local audit row commit atomically under one CAS. Unrelated
locks, Y's original prepared record and any original outcome remain intact.
The audit is replica-local reservation history, not a portable business fact.

Authenticate the locally retained signed bytes and require their request ID
to equal the requested member before receipt reconciliation. Exact completed
replay returns the retained original result before re-checking the old live
epoch or local ready marker; it cannot reapply fees or effects. Fresh work
still requires every DrainSet and current-epoch precondition.

The committed DrainSet record is authenticated outcome history. A future
portable cut must carry and verify its ordered proof and reconstruct the
full signed frontier membership rather than importing replica-local ready,
signer-entry or conflict-audit rows as authority. This core rule does not
itself supply a network operator route, a complete causal scheduler,
post-DrainSet business-free Seal, cut, next-set readiness or activation.

## Required verification

Exercise a genuine nonempty selected union and full certificate without an
availability certificate; conflicting Y partial locks, X's own locks and no
lock; absent/mismatched members, Freeze and readiness; mismatched object,
epoch, sender and nonce; missing Y prepared provenance; unrelated locks;
exact same-boot and post-restart replay; CAS races and writer fencing. A
separate multi-validator network and PostgreSQL run must cover the complete
Freeze through activation sequence before live exposure.
