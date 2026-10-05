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

### Real rejoin signing is not minimal-certificate membership

Ordered consensus verifies all supplied votes, then canonical-sorts validators
and retains only the minimal quorum. An all-four endpoint submission therefore
does not guarantee that a particular fourth signer appears in its three-vote
certificate. Do not change production quorum selection, manufacture a vote,
or remove the positive rejoin proof to satisfy that false premise.

The compiled caller can prove actual participation using the CLI's saved
per-endpoint vote acknowledgements and chronological proposal/certificate
artifacts. Verify the actual returned vote's current pinned committee/key,
endpoint and validator attribution, signature and exact proposal context,
digest, view and height. The saved acknowledgement is the canonical re-encoding
of a decoded HTTP response, not a byte-level transport capture; the actual vote
signature supplies authenticity. Bind the Freeze or Seal candidate and both certified
descendants; reconstruct the exact deterministic minimal certificate from the
recorded valid votes. Keep every host's actual completion acknowledgement and
byte-equal receipts, rather than replacing all-host delivery with a forced
subset. A saved high-QC status or fixture-signed replacement is not this proof.
The restart itself and the declared signerless missed-prefix recovery remain
separate actual process requirements before fresh signing resumes.

### A sealed host is material, not live authority

Committing Seal retires the outgoing namespace. Its live HTTP status and
outcome routes correctly return `409 successor-authority-refused`, just like
fresh signing/control routes; being read-only does not make a route exempt
from the live serving gate. Do not widen those routes to make an acceptance
assertion succeed.

After actual e2 Seal completion, compare each endpoint's final acknowledged
outcome with its own actually served database through the existing bounded
`query_ordered_outcome` reader, which cross-checks the retained outcome against
its immutable header and receipt. Read and independently re-verify that
database's current scoped consensus state through `query_status` and compare
its high QC with the final actual submission certificate. Neither material
reader grants a live warrant, advances a fence, signs or writes. Keep the
canonical receipt equality and actual sealed live-route refusals. Freeze
remains unsealed and retains its positive live HTTP status/outcome checks.
Saved acknowledgements alone are not durable read-back evidence, and the
untouched original fixture is not the served successor database.

### Independent process stages may run concurrently

Within one receipt check, query the existing four/five endpoints concurrently
using copied endpoint/validator/process/generation identifiers, never the
live child/store owners. After one common business cut is complete, each
independent target may run its existing create-then-readiness sequence with
distinct databases and outputs. After Seal, historical teardown and verified
next workflow construction, each target may run activate-then-exact-repeat.
Keep the existing 600-second child bounds and kill/reap guards. Join every
worker before propagating failures or checking results in original host order.
Directories, 0600 keys, pins, quorum selection and certificate assembly remain
under the parent owner.

Do not parallelize drain preparation: its targets also serve one another's
retained publication reads. Seal preparation, common source-cut writing,
consensus/Tick/replay rounds and fault-injection/capture windows also retain
their original sequential ownership. Concurrent scheduling is not reduced
coverage, changed network input, a shorter unbonding delay or acceptance proof.

### Safe development/test runtime compilation

Repeated bounded replay is also a development/test runtime cost. Use dev
opt-level 1 with explicit debug assertions and overflow checks enabled; Cargo's
test profile inherits these settings. Retain the curve package's opt-level 3
override and the verifier package's explicit safety settings, whose opt-level 1
matches the workspace default. Release and build-override profiles are unchanged.
This changes compilation, not proof ownership, canonical inputs or capabilities.

A paired read-only saved-cut measurement is evidence about that workload only,
not compilation time, whole-case completion, CI duration or network throughput.
The new committed configuration still needs every actual required owner and
selected original PostgreSQL group. Keep original-root e0..e8, the installed
seven-epoch delay, F-required quorums, historical/tamper/restart/replay/fault
controls, the existing 360-minute CI budget and 600-second child bounds. Do not
replace repeated verification with a trusted cache/checkpoint or count a retired
old-profile run as a pass under the new configuration.

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
- [Cargo profile inheritance and overrides](https://doc.rust-lang.org/cargo/reference/profiles.html)
