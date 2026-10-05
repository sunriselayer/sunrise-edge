# DR-0194: Recurring handoff acceptance by owning boundary

Date: 2026-10-05 (Asia/Singapore)

Status: Accepted clarification of the recurring successor contract's acceptance
ownership under DR-0191. No protocol, authority, storage, genesis or delay is
changed. An impossible fixture premise is corrected explicitly below, not
counted as a passed scenario.

## Context

The recurring successor contract's Section 12 combines a real recurring
compiled-process scenario with fault and fencing requirements. Those
requirements span different owners:
network/process composition, successor engine/activation composition, and
typed store ports. Calling all of them process coverage would be inaccurate;
adding production fault hooks solely for the test would violate the accepted
no-new-machinery boundary.

The retained original/import/readiness and raw successor-store controls already
prove their epoch-bearing contracts. They do not substitute for missing actual
successor engine or chain-activation composition. Nor does one library result
prove the compiled changed-committee workflow completed.

## Decision

Retain every behavior requirement and verify it at its actual owner, in the
same mandatory repository acceptance profile:

| Owner | Required proof |
| --- | --- |
| Recurring core fixture | Original-root e0..e8, real delay7, legitimate historical exits and withdrawals, exact replay, every-epoch reopen/refence, stale held-warrant zero-signature refusal, and verified later-link evidence |
| Successor engine and SQLite test adapter | Consumed retention/completion reply loss, byte-identical retained-proposal reconciliation without another signature, and genuine protected live-write versus completion-token rejection before fresh retry |
| Genuine e2 chain activation and SQLite test adapter | Consumed committed-reply reconciliation, undispatched ambiguity leaving the slot inactive, and a real competing activation on a second local handle; captures compare against the actual post-race state |
| Compiled recurring process | Changed committees including F-required quorums; real CLI paid contracts/claims/bonds and owner-only exit operations; historical material and artifact refusal; authentic former-domain envelopes on every current host; one actual e2 host restart, missed-prefix catch-up and subsequent real Freeze/frontier/Seal participation; exact receipts and writer generations |
| Existing import/readiness and raw store-port fixtures | Import inventory/fence races, readiness reply loss and independent activation/Seal token, assertion, indeterminate-result and CAS contracts; these remain mandatory, not newly replaced by the process scenario |

The one recurring process scenario owns observable shipped behavior. Consumed
typed-port faults are separately exercised through the actual successor engine
or activation caller with real chain evidence. This partition is not permission
to omit a required fault, replace it with malformed authentication, repeat only
the original-epoch engine, or infer a library signer counter from a process.
No production fault endpoint or unchecked result hook is added.

### Actual imported publication families

The verified genesis-to-successor import does not contain historical ordinary
`publication/` rows. Normal retention writes that source-local carrier and ACK;
private owned replay uses `apply_internal` without normal retention. Private
DrainSet reconstruction imports the authenticated epoch-scoped
`drain-publication/` family, and `private_import_snapshot` exports independently
reconstructed rows, not source-local retention aliases. This is the existing
ownership contract, not a missing business replay effect.

A proposed genuine fixture requiring ordinary historical publication rows
therefore failed before exercising the frontier. Adding more origin transactions
cannot create those rows through the accepted importer. Do not synthesize them,
copy raw source rows into a verified import, add a restoration capability, or
claim that impossible historical-prefix traversal passed.

The actual integration proof asserts the empty imported ordinary prefix, then
retains two genuine current publications and verifies bounded monotonic progress,
behind-tail current carrier/index refusal, exact full/empty-terminal pages,
complete independent cut replay, and reopen/refencing. Separately, a fresh whole
source cut rejects corruption, tombstones and actual physical absence of genuine
historical drain carriers, with full after-injection captures and positive
restores. Their request IDs may sort before current IDs, but their rows are
outside the frontier's scanned prefix; they are not physically traversed prior
frontier carriers. Existing generic physical-merge algorithm tests retain the
large-prior-corpus budget, monotonic resumption and missing/altered/tombstoned
merge coverage, clearly identified as algorithm tests rather than genuine
authenticated import history. A future producer of ordinary prior-prefix rows
would need its own authenticated integration proof before claiming that flow.

Faults need not repeat in every epoch. Use a genuine successor e1/e2 checkpoint
and the existing real repeated flow where the boundary is epoch-generic. Record
the exact owning selectors and completed results in TODO and validation evidence;
an unconsumed injected plan, zero-match run, interrupted log, build-only success
or review startup is not acceptance.

## Consequences

Delivery 3 still requires complete final-source required checks, the retained
selected PostgreSQL profile for shared-store changes, independent exact-head
approval and successful unconditional CI before normal merges. PostgreSQL is
not made mandatory. DO/D1 activation, independent audit and real first-network
startup remain separate work; this partition certifies none of them.

## References

- [Recurring successor serving](../recurring-successor-serving.md)
- [DR-0191](0191-recurring-successor-serving.md)
- [DR-0193](0193-required-recurring-acceptance.md)
