# DR-0159: Bind an ordered DrainSet vote to durable local possession

Date: 2026-09-30

## Decision

The first handoff-capable profile uses the existing outgoing HotStuff chain for
one `DrainSet` control candidate. It does not create a parallel voting chain
or treat a local `DrainSet-ready` response as a global decision. The candidate
contains the exact ascending, unique signed frozen-frontier selection and its
reconstructed `DrainUnionIdentity`, bound to the committed Freeze, outgoing
context and its own request ID. The ordinary ordered candidate kind receives
wire tag 6. Its canonical intent and retained decision record use the
repository-swept free type IDs `0x645E/v1` and `0x645F/v1`; `0x6460` already
belongs to the ordered HTTP envelope. Later cut, readiness and Seal frames
must receive separate swept IDs.

The handoff-capable signed-genesis profile admits at most 256 active
validators, matching the existing FastVote economics admission ceiling. The
selected frontier roster cannot exceed that committed outgoing set, so its
canonical votes fit the existing 512 KiB ordered candidate intent ceiling.
Historical signed-genesis profiles retain their existing interpretation; a
larger set cannot silently opt into this handoff profile. This bounded first
network is preferable to introducing an unbounded external roster reference
whose availability and equivocation rules would be another prerequisite.

Before exposing a leader proposal or validator vote for `DrainSet`, the
signer verifies the selected outgoing quorum and its exact locally committed
union-ready marker. `verify_drain_ready_into` folds the Freeze, epoch, set
and marker revisions into the *same atomic commit* as the signed proposal or
vote identity. A standalone read followed by a signature would be a
time-of-check/time-of-use gap. Each voter has durably retained and verified
every selected union member's full proof and artifact closure before its vote
is exposed. A signer with missing local readiness stops and may resume after
import; it does not manufacture a deterministic refusal for a local storage
lag. Tombstones, mismatched selection and corrupt prerequisites fail closed.

Post-Freeze proposal and vote admission uses a positive control-kind allowlist
for `Freeze` and `DrainSet`; all business kinds remain closed. A future
control kind is not implicitly allowed. Committed execution repeats the
readiness check through the ordered staging store, making the observed
revisions assertions in the one commit that installs an immutable,
one-per-epoch `DrainSet` record and retained ordered outcome. A different
later candidate cannot replace that record. Exact replay returns retained
bytes and does not rewrite it. No object, sender nonce, fee, original user
receipt or ordinary mutation fence is changed by this control decision.

The committed record authorizes *future narrowly scoped drain application*;
it does not itself apply a certificate, prove a portable cut, seal an epoch or
activate the next set. Ordinary post-Freeze application and local/paid
mutations remain blocked. The new drain executor must separately verify
record membership, complete certificate and causal prerequisites, and resolve
only directly conflicting local reservations under its own atomic CAS.

## Verification and remaining obligations

Test a genuine ordered Freeze followed by a selected quorum whose complete
publication union has been imported by voting replicas. Verify that
leader/voter signatures cannot escape before the local ready marker is
committed; a changed marker or Freeze revision loses the CAS race. Wrong,
forged, underpowered or mixed-Freeze votes, a different selection, tombstones,
no Freeze and stale epoch must not install the record. An unready replica must
stop, import the missing proof and resume without a divergent refusal. A
second selection cannot rewrite the first committed decision; exact replay
returns the original outcome. Business candidates stay closed after Freeze.
Pin canonical intent/record bytes and reject unknown operation tags.

This decision leaves verified causal drain application, a closed and complete
portable business cut, conditional next-set readiness, a business-free Seal
barrier, activation and independent PostgreSQL multi-validator E2E open.
Implementation and validation status belong in `TODO.md`, not this ADR.
