# DR-0215: Ordered local signature verification

Date: 2026-10-07, Asia/Singapore

Status: Accepted bounded design after complete independent Codex fallback
review of `c5a1442be6251b1491f75442898f4657cf4485b0caee5c94f582617a48c3a46a`.
This accepts the contract, not implementation. It selects no custody backend,
provider, trusted review surface or release qualification.

## Context and inspected As-Is

[DR-0208](0208-native-sqlite-first-and-protected-signing.md) selects Native plus
SQLite first; [DR-0214](0214-protected-custody-and-review-boundary.md) requires
independent checks of automatic returned signatures without replacing their
actual authority owners. [DR-0211](0211-external-signing-preparation.md) concerns
SDK preparation, not the automatic validator path. This proposal is a bounded
handler-correctness check before custody selection, not protected custody itself.

Source inspection used `dba52dddd3f620357cffdbc055861c0bbee6d9e9`:

- [`ChainedHotStuff`](../../../crates/consensus/src/lib.rs) checks declared
  validator/scheme and bounds signatures to nonempty, at most 4096 bytes in
  `propose` and fresh proposal voting; it does not require exactly 64 bytes or
  authenticate the freshly returned signature. `verify_vote` and
  `verify_proposal` already reconstruct the existing exact frame and verify with
  the engine's registered public key and explicit context/scheme checks.
- [`ordered_economics::engine`](../../../crates/node-core/src/ordered_economics/engine.rs)
  authenticates incoming proposals and preserves admission, locks and live
  gates. `process_proposal_gated` extracts a fresh vote from actual `on_event`
  output, then passes it to `prepare_event`/`finalize_event` without verifying it.
  Completion can retain that vote, its watermark and next consensus state.
  Retained votes already verify on the earlier exact-return path, but its local
  identity comparison rereads `signer.validator_id()` after gate admission.
  The final post-completion re-emission is a distinct store reread and currently
  inserts a retained vote without either local-identity or crypto verification;
  the earlier exact-return branch would already have returned.
- Causal fresh leader proposals verify before retention. Their retained path in
  [`identity`](../../../crates/node-core/src/ordered_economics/identity.rs) also
  verifies the signature, unsigned correspondence and retained digest. The
  noncausal `propose_gated` branch instead retains a fresh signature without
  verification; its exact-return path checks record bindings but neither the
  retained signature nor a recomputed retained proposal digest. Noncausal identity
  reconciliation also rereads signer identity after signing. Causal preview and
  actual proposals use later signer getters; existing correspondence and crypto
  do not bind them to the earlier gate's validator. `ConsensusSigner` promises
  no stable identity across calls; a valid committee signature alone is not this
  invocation's admitted local identity.
- Both original [`native ordered routes`](../../../crates/native-http/src/ordered_economics.rs)
  and [`successor routes`](../../../crates/native-http/src/successor.rs) reach
  these same gated owners. The original router is policy-parametric and the
  optional PG host still composes it; legacy noncausal proposal return is not an
  unused API. The selected [`SQLite source host`](../../../apps/operator/src/sqlite_source_host.rs)
  requires causal admission and retains its startup public-key check. Current
  [`FileEd25519Signer`](../../../apps/operator/src/host_runtime.rs) owns a raw
  software key; the trait declaration alone cannot detect a wrong signing key.

FastVote, availability ACK and frontier owners already verify fresh signatures
before retention. Do not add equivalent wrappers there. The legacy
[`epoch-transition vote helper`](../../../crates/node-core/src/epoch_transition.rs)
is not called by the inspected host routes and refuses Logical/successor live
use; it remains outside this slice and gains no new live authority.

## Proposed contract and minimal placement

### One invocation-local identity

At each existing `gate.require_local_signer` position in noncausal
`propose_gated`, causal `propose_causal` and `process_proposal_gated`, capture the
argument once and use that same value for this invocation's local bindings:

```rust
let local_validator: ValidatorId = signer.validator_id();
gate.require_local_signer(store, local_validator)?;
```

Do not move the gate/query across existing admission or justified-prefix steps,
invent an `env.validator` field, or query a scheme early. Engine internals may
still read signer metadata; returned local identities must match the capture
before crypto or exposure. The existing engine verifier then binds the
registered scheme/key and exact frame for that fixed identity. An identity
mismatch is an existing `stop`-family prerequisite failure, not new authority,
a business refusal or a provider-history authentication protocol.

### Actual ordered votes

In `process_proposal_gated`, immediately after extracting `produced` from the
actual engine output, require `vote.validator == local_validator`, then verify
the vote, when present, through existing `engine.verify_vote` and
`Ed25519ConsensusVerifier` configured explicitly with
`UnsupportedSignatureSchemeResponse::InvalidSignature`. Reuse
`consensus_to_node` for failures. The current engine produces at most one such
vote; absence skips this pre-completion check and adds no signer call.

The check must precede both ordinary completion and Seal-retention completion.
An invalid result yields no successful signed output and no completion of that
fresh vote, watermark, consensus state, candidate/reservation or business rows.
Replace the earlier retained-vote comparison's repeated signer getter with the
capture; keep its existing crypto verification once and all live/commit
backstops. The final no-vote-output branch performs a new
`reconcile_local_vote` read after completion. For an Exact vote from that read,
preserve the existing `gate.require_live`, then require
`vote.validator == local_validator` and call the same existing `engine.verify_vote`
with the explicit verifier/error mapping before inserting it into the response.
This verifies a distinct read, not a second pass on the earlier Exact branch
or the fresh-output branch, neither of which reaches this re-emission check.

A refusal at this final read prevents an unverified signed response; it does
not undo or classify as failed any legitimate completion or justified prefix
already confirmed. Compare these state/read boundaries separately from failure
of the pre-completion fresh-vote check. Add no repair write or new commit here.

Do not put this check inside the generic completion helper or consensus signer
port. `CapacityProbeSigner` intentionally produces same-sized noncryptographic
bytes; causal preflight constructs and drops `prepare_event` output with them.
The probe is neither signature validity, authority nor permission to confirm.
Crypto-check only real produced or reread retained signatures; preserve the
nonauthoritative probes and bounded preflight before key use.

### Exposed noncausal leader parity

Include both outgoing noncausal proposal branches in the same ordered owner:

1. Preserve existing authentication, live/local-signer gates, state/policy reads,
   admission, engine signing, digest derivation and identity reconciliation order.
   Pass `local_validator` to `reconcile_leader_proposal`, not a signer getter
   reread after signing. For `RetainedIdentity::Absent`, require
   `proposal.leader == local_validator`, then call existing
   `engine.verify_proposal` with the same explicit verifier/error mapping before
   constructing or committing the new leader record and admitted writes.
2. For `RetainedIdentity::Exact`, require
   `retained_proposal.leader == local_validator` before independently verifying
   it with that engine/verifier. Recompute its `proposal_digest` and require equality
   with the requested digest already checked by reconciliation. A mismatch is
   an existing `stop`-family prerequisite failure, not a healthy business refusal.
   Return only the unchanged verified retained bytes; do not rewrite the row.

This preserves the historical sign-before-reconciliation order. Legacy exact
replay/conflict can already call the signer; this proposal does not claim zero
key use for them or move them to a new unsigned-preparation protocol. Any stronger legacy
pre-key-use/history contract needs separately reviewed work before provider wiring.

### Bind existing causal proposal checks, without duplicate crypto

Use the same causal gate capture to require `preview.leader == local_validator`
before `reconcile_unsigned_leader_proposal`. Its existing unsigned comparison
therefore binds a retained proposal to that validator before its existing
signature/digest verification. In the existing actual fresh proposal/preview
correspondence guard, require `proposal.leader == local_validator` too. Keep all
other correspondence fields, exact 64-byte capacity-preview parity and the
already existing single crypto check. Add no second verifier, signer call or
general prepared-signing framework. Both causal fresh and retained return must
use the admitted identity, not later mutable signer declarations.

## Refusal order, completion and retention boundaries

Preserve incoming authentication, candidate/header conflict, prefix/readiness,
membership/scheme, lock safety, capacity and serving/fencing refusal order.
The pre-completion fresh-vote check follows actual signing and precedes only
its completion; the distinct retained reread is checked after completion.
Signer errors and empty or over-4096-byte signatures already stop earlier through
the opaque `consensus_to_node` mapping. Fresh vote/noncausal proposal signatures
of 63 or 65 bytes pass that generic bound and must fail at the new crypto check;
causal fresh leaders already fail their exact 64-byte capacity-preview parity.
Add no provider diagnostic, fallback key, business-refusal tag or successful
result on either local-binding or signature failure.

[Ordered Seal](../ordered-seal.md) permits authenticated justified-prefix
progress before fresh signing. A later signing failure cannot roll back that
confirmed progress. Distinguish it from the rejected fresh completion in tests;
do not assert that the entire invocation performed no earlier legitimate commit.
Confirmed-commit exposure and exact fresh reconciliation after uncertain storage
remain unchanged. Verification supplies no independent external signing history
and does not prevent a signer from observing a frame before a losing commit.

Pruning inspection found `ChainedHotStuff::prune_state` pruning consensus caches,
not deleting durable per-view leader/vote rows or the watermark. The identity
owner retains them separately; [`audit_projection`](../../../crates/node-core/src/ordered_economics/audit_projection.rs)
explicitly verifies old votes after their proposals leave the cache. Private
import omits local signing rows from a distinct reconstructed target, not by
pruning a live source. Successor activation separately requires virgin singleton
roots. `reconcile_local_vote` currently treats absent watermark/vote values as
zero/absence without distinguishing noninitial revisions; causal leader
reconciliation does reject a tombstone. This observation is not proof of ordinary
equivocation or consistent rollback detection. Do not change tombstone refusal,
pruning, key layouts or retention policy in this signature-only slice. Any later
change must separately specify intentional retirement versus corrupt deletion
and preserve the retained watermark's refusal of lower-view fresh work.

## Independent acceptance controls

Extend actual ordered-owner tests using committed real Ed25519 committees:

- Fresh vote and noncausal fresh proposal: valid positive control, wrong-key and
  wrong-frame signatures, invalid 64-byte bytes, 63/65-byte results and a signer
  error containing a diagnostic marker. Verify opaque errors and no successful
  output, with exact affected rows/revisions unchanged for the fresh completion.
  Distinguish empty/over-4096 old-bound refusal from 63/65 new-crypto refusal and
  existing causal leader exact-64 refusal.
- Identity drift: use real independently registered keys for two committee
  members and a signer whose gate identity differs from later declarations.
  For fresh votes and noncausal proposal return, independently prove the other
  member's actual message passes the engine's committee verification, yet the
  owning invocation refuses its local binding. Include fresh/retained cases and
  stable-identity positives. Separately cover causal preview/fresh/retained
  binding placements under existing leadership/correspondence rules. Do not make
  a wrong-key crypto failure stand in for the independent local-binding negative.
- Keep declared unknown-validator/scheme mismatch and existing pre-sign refusals
  as separate zero-call controls where the actual ordering provides that promise.
  Test causal capacity probes remain unsigned/unconfirmed and reach real signing
  only after the existing bounded construction succeeds.
- Noncausal retained proposal: unchanged valid replay, invalid retained signature,
  and a correctly signed different retained proposal with inconsistent recorded
  digest. Refuse corruption without repairing, rewriting or re-exposing it;
  retain the historical signer-call ordering rather than asserting zero calls.
- Final retained-vote reread: use a genuine already-certified empty proposal
  for which the existing engine emits no fresh vote. Select a narrowly bounded
  read/insertion fault fixture over the existing retained-row/store port after
  inspecting the actual setup: the earlier lookup must not return Exact, and
  the distinct final reread must supply the canonical retained record. Exercise
  the actual handler through its unchanged/confirmed completion, preserving real
  write-CAS checks; require no row deletion, tombstone-policy change, new provider
  or live authority. Check a valid local vote returns, an invalid retained
  signature refuses, and an independently committee-valid other-member vote
  fails local binding. Assert no new signer call, repair or unverified signed
  response; already-confirmed rows/progress remain. Label this a fault-path
  control, not healthy-concurrency or provider qualification.
- Compare valid encoded messages with original engine/frame/encoding controls,
  not only the newly added check. Preserve exact vote/leader replay, durable
  watermark/locks, existing causal leader verification and original/successor
  Seal/fencing guards. Reuse the independent wrong-key pattern in
  [`FastVote tests`](../../../crates/node-core/src/fast_path/tests.rs) and the
  [`consensus verifier matrix`](../../../crates/consensus/src/verifier_tests.rs).
- Compare new vote/highwater/consensus completion, reservation, receipt and outbox
  observations explicitly. Include a genuine earlier justified-prefix commit
  followed by signing failure: prefix state/effects remain, but no failed fresh
  vote completion or signed response follows. Preserve rejected/indeterminate
  commit controls and exact retained retry; a fake proves no actual provider.

No crypto, canonical/schema/domain change, runtime `Signer`, broker, SDK
`PreparedSigningFrame` duplication or authority waiver is proposed. Protected
keys, semantic/human review, provider failure topology, recovery/rotation/
revocation and mutually consistent rollback protection remain separate choices
and qualification. No M2/release or public-network gate closes here. Implementation,
independent exact-source review and required validation remain subsequent work;
current status belongs only in [TODO.md](../../../TODO.md).
