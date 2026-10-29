# DR-0227: Fresh causal ordered slash evidence admission

Date: 2026-10-11, Asia/Singapore

Status: Accepted bounded source implementation direction. Runtime validation,
different implemented-source review and integration acceptance remain separate.
This decision does not qualify deployment, custody or production activation.

## Decision

New causal `BondSlash` proposal and vote admission must already possess the
committed authority referenced by the unsigned slash envelope. The submitter's
local-execution signature spends only its own nonce; it cannot prove evidence
existence or permission to forfeit the target bond. A fresh candidate naming
nonexistent evidence must not acquire an honest quorum and permanently obstruct
the economic prefix when execution later requires that missing prerequisite.

Use the existing shared fresh signing boundary after completed/retained replay
and justified-prefix completion. Privately read the exact durable evidence row
from the pinned chain and claimed current-epoch target/digest selector. Strictly
decode the record and family; check chain, epoch and target identity, recompute
and compare the full self-describing normalized digest, and independently hash
both ObjectConflict preimages to their own signed locked-object digests. The
decoded evidence protocol must explicitly equal the pinned protocol in this
new preflight only, even when foreign-protocol statements have valid signatures.

Load the actual chain-anchored committee with the existing fenced historical
loader and require exact equality with the pinned committee. Membership alone
or the caller's supplied key is insufficient. Re-verify both signed statements
for FastVote, ObjectConflict and EpochTransition using the same pure proof
helpers as slash execution. Extract only those pure checks: do not run economic
preparation, issue custody authority or duplicate the business evaluator.

Every deciding epoch, evidence and committee observation joins the existing
`ObservedBusinessReadView` and the admission CAS with the exact new leader or
vote identity. Conflicting repeated reads poison the scope and outrank a later
preflight error. A race after private signing rejects the actual commit and
exposes no signature; this is not a zero-private-signature guarantee.

## Chronology and compatibility

The producer's actual ordered Evidence three-chain commit supplies the row.
A retained candidate/header, pending QC or local checkpoint number does not
prove that its business effect committed. The existing justified-prefix path
may legitimately complete that producer before deciding the new slash; such
prior completion is distinct from a fresh slash admission write.

The extra requirement rejects only newly signed causal `BondSlash` admission,
including a currently refusable slash whose absent proof could otherwise become
relevant in a later generation. It changes no wire bytes, hash domains,
dependencies, persisted layouts or capability policy. Historical noncausal
signing, reconciliation-only admission, exact retained proposal/vote replay and
completed replay keep their existing behavior. The shared historical slash
helper gains no new protocol-equality restriction, and retains the original
identity, preimage, committee-read and proof-error order.

Execution must still stop on genuinely lost committed evidence. Do not convert
that stop to a semantic rejection, advance an unknown prefix, erase reservations
or invalidate an authentic retained artifact. The fresh gate cannot retroactively
remove a quorum-certified invalid ancestor or its consensus lock. Recovery of
existing poisoned history, production rollout and any protocol-upgrade activation
plan remain separate decisions; this record supplies none of those authorities.

## Focused source controls and assurance limits

The associated causal tests use the signed CausalAdmission genesis fixture,
real consensus signers, independently stored replicas and actual ordered
Evidence producers for all three families. Negative fixtures include absence,
malformed proofs, both ObjectConflict preimage bindings, full typed selectors,
actual committee corruption and correctly signed foreign-protocol evidence.
Fresh rejection checks zero actual signer calls and zero forwarded fresh commit
calls against complete persisted snapshots. Other controls distinguish legitimate
justified-prefix completion, retained/completed replay, signerless recovery,
lost committed evidence apply stops, deciding-row CAS races and sticky read
conflicts. Corrupt-row fixtures are negative-only, never positive authority.

This source-only slice does not claim compilation, formatting, test execution,
runtime durability qualification, full repository validation or a passed security
release gate. The current task forbids those invocations; written controls and
read-only diff checks are not their successful execution.
