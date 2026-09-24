# DR-0130: owned-object certified execution (FastVote phase 1)

## Status

Accepted and implemented locally, 2026-09-22. `node-core` now implements the
Phase 1 prepare/apply state machine, signed-genesis validator-set binding,
durable object/nonce locks, complete staged-commit commitment, byte-stable
vote replay, and atomic certificate publication. The implementation is
compiled, tested against independent file-backed validator stores, and
independently vector-checked. It adds no HTTP/CLI or other externally
reachable FastVote ingress, and it does not implement Phase 2 validator
lifecycle/recovery or Phase 3 slashing/reward distribution.

## Context

[DR-0129](0129-fastvote-fastcertificate-fast-path.md) ("phase 0") implemented
only the owned-object fast path's canonical `FastVote`/`FastCertificate`
types, wire codec, and a stateless `FastPathCertifier` signature/quorum
aggregation library in `crates/consensus`. It deliberately stopped short of
any `node-core` dependency, persistent lock, effects application, certificate
publication, or ingress, and named the next slice as a separate decision
because "authenticated execution, object authority, fees, crash recovery, and
idempotent publication cannot be bypassed by an intermediate API."

FastVote/multi-validator integration is item 5 of `TODO.md`'s delivery
roadmap and is delivered across four phases, tracked there and in
`docs/architecture/core-protocol.md` section 11:

* **Phase 0 (DR-0129, done).** Canonical types, wire codec, and
  signature/quorum aggregation library only.
* **Phase 1 (this DR, implemented locally).** One coherent
  certified-execution slice:
  signed paid intent authentication, exact replay reconciliation,
  nonce/policy/object/ABI validation, deterministic paid execution, a
  canonical commitment over the complete staged commit, durable exclusive
  sender-authorized owned-object version locks, byte-stable `FastVote`,
  quorum certificate verification, and atomic certificate apply.
* **Phase 2 (not yet designed).** Validator lifecycle: epoch/validator-set
  transitions, retired/wrong-epoch rejection, relay/event-family
  authorization, explicit equivocation evidence, multi-validator
  fault/restart tests.
* **Phase 3 (subsequently designed in DR-0137).** Economics/security completion:
  bond-linked slashing execution and deterministic transaction-fee escrow
  distribution to the committed active validator set, including a canonical
  rounding-remainder rule and vectors. DR-0137 corrects this decision's earlier
  signer-subset proposal because valid certificates can carry different quorums.

**FastVote is complete only after Phase 3.** A testnet may launch on top of
Phase 1 — a static signed genesis validator set with a frozen epoch is
sufficient for a permissioned testnet — but that launch is a deployment
decision, not a claim that FastVote itself is finished. Validator-set
changes, slashing, and fee/reward distribution are FastVote completion
criteria in this plan, not vague "production" deferrals to be named later.

This phase remains scoped to the owned-object fast path. `ChainedHotStuff`,
shared-object consensus, and validator-set-change events
(`ApplyValidatorSetChange`) are unchanged and out of scope here, exactly as
in DR-0129. Standard Asset remains ordinary paid contract state: this DR adds
no node-core special balance authority, and the existing paid-fee mechanism
(DR-0126/DR-0127) is reused, not replaced (see "Fee escrow boundary" below).

## Decision

Phase 1 delivers certified execution as one coherent slice, not a sequence of
standalone type/codec/validation PRs (per this repository's working rule).
The slice covers, in order:

1. **Signed paid intent authentication.** Reuse the existing authenticated
   paid-intent authentication boundary
   (`execution::paid_execution::authenticate_paid_intent`, DR-0124) rather than defining a new
   signature family for the intent itself. Both the prepare step and the
   apply step start from the same canonical signed intent bytes; neither
   accepts a caller-supplied transaction hash or execution-effects hash as an
   input to signing or verification. Apply always re-derives or loads the
   locally prepared commitment (see item 5) and compares it against the
   certificate's header — it never signs or trusts a hash handed to it over
   the wire.
2. **Exact replay reconciliation.** Before any nonce, lock, or execution work,
   reconcile the request against persisted prepared/certificate/receipt state
   for the same signed intent, following this workspace's existing
   receipt-before-nonce reconciliation convention. A replayed prepare or
   apply returns the original recorded outcome and performs no additional
   locking, execution, or mutation.
3. **Nonce/policy/object/ABI validation.** Reuse the existing sender-nonce,
   preinstalled/typed-ABI, and `AccessManifest` validation layers used by the
   ordinary paid path; the fast path does not get a parallel, looser
   validation surface.
4. **Deterministic paid execution.** Reuse the existing deterministic paid
   execution engine and fee composition (DR-0087, DR-0126/DR-0127) to produce
   canonical `ExecutionEffects`. No new execution semantics are introduced by
   this DR.
5. **Canonical commitment over the complete staged commit.** The value a
   validator signs a `FastVote` for is not the bare `ExecutionEffects` hash.
   It is a canonical commitment over the complete staged commit: the
   execution effects, the post-execution nonce, the receipt outcome, the
   charged amount/fee output that form the pre-certificate settlement base,
   and the exact `(ObjectId, version, digest)` of every
   object the intent locks. This closes the gap where a vote could attest to
   "this execution" while a different nonce, fee, or lock state was actually
   staged. This DR fixes the *property* the commitment must have; the exact
   canonical frame, hash purpose, and whether it reuses or extends DR-0129's
   `FastVote.execution_effects_hash` field is an implementation detail of the
   implementation and requires its own stable-vector and dual Rust/JS
   reconstruction evidence before being claimed done (see "Test evidence
   required"). The certificate's signer list is necessarily derived from the
   verified certificate at apply time and is not part of the value validators
   sign before that certificate exists.
6. **Durable exclusive sender-authorized owned-object version and nonce locks.** Before
   a `FastVote` is signed, every object the intent declares `Write`/`Consume`
   must be durably locked, exclusively, at the exact version the intent read,
   and only on behalf of the intent's authenticated sender/owner. The lock
   must survive process restart. A conflicting intent for the same
   `(ObjectId, version)` is rejected before execution while the lock is held.
   Prepare also asserts the sender's exact current nonce and installs one
   exclusive sender/epoch nonce lock for the prepared request. It does **not**
   advance the sender nonce. The ordinary direct paid path must reject while
   that nonce lock exists; certificate apply advances the nonce and deletes
   the nonce lock in the same final commit as the effects and receipt. This
   avoids permanently consuming a nonce merely because quorum never forms.
7. **Byte-stable `FastVote`.** Re-preparing an already-prepared intent (same
   signed bytes, already locked) returns the identical, previously signed
   `FastVote` bytes rather than signing a new one. This is required for
   deterministic certificate formation under replay and for an untrusted
   relay to collect votes idempotently, and follows directly from DR-0129's
   own certificate-formation determinism requirement.
8. **Quorum certificate verification.** Apply uses DR-0129's
   `FastPathCertifier::verify_certificate` against the phase's static signed
   genesis validator set for the frozen current epoch. There is no
   validator-set rotation in Phase 1 (Phase 2).
9. **Atomic certificate apply.** Once a certificate verifies against the
   locally recomputed staged-commit commitment, apply is one atomic, fenced
   durable invocation that commits together: the application/fee-escrow
   mutations, the nonce advance, the receipt, the certificate publication
   record, the settlement metadata, and every object/nonce lock release. Any failure
   leaves none of these committed, matching this repository's existing
   nonce+effects+receipt+outbox atomicity convention. A certificate that does
   not match the locally recomputed commitment is rejected without applying
   and without releasing the lock.

**Validator set and epoch.** The validator set used to build the
`FastPathCertifier` is the static signed genesis validator set for one frozen
epoch, matching DR-0129's `# 30` genesis permissioned model. Rotation,
bonding, and slashing are unchanged and out of scope (Phase 2/3).

**Lock lifetime.** Locks acquired in step 6 are permanent until apply: Phase 1
defines no timeout, `Tick`, or other clock-based unlock path after a vote is
cast. An intent whose certificate never forms leaves its objects locked
indefinitely under this phase. Recovering from that state without permitting
two conflicting certificates for the same object version is explicitly
deferred to Phase 2 (see "Consequences / Deferred").

**Fee escrow boundary.** The existing paid-execution fee recipient (the
single governance-pinned recipient used by DR-0126/DR-0127) becomes the
protocol escrow for certified execution's fee settlement at this phase
boundary. Certificate apply debits the fee into that same existing recipient;
it does not introduce a new balance authority. Distributing fee revenue to
the individual validators in the committed active set is explicitly
Phase 3 work (deterministic distribution with a canonical rounding-remainder
rule and vectors) and is not implemented by this DR — escrowed funds are not
distributed by Phase 1.

## Phase completion criteria

Phase 1 is complete only when all of the following hold, evidenced the same
way as prior decision records in this index (stable vectors, adversarial
tests, complete repository gate, fresh tech-lead and security review):

1. An authenticated signer can submit a signed paid intent that a validator
   independently prepares: authenticates it, reconciles exact replay,
   validates nonce/policy/object/ABI, executes deterministically, computes
   the staged-commit commitment, durably locks every declared `Write`/
   `Consume` object exclusively at its read version, and signs a byte-stable
   `FastVote` over that commitment.
2. A quorum of independently obtained `FastVote`s for the same commitment
   forms a `FastCertificate` (DR-0129 `FastPathCertifier`), independent of
   arrival order.
3. Presenting a verified certificate to apply atomically commits application
   effects, fee-escrow debit, nonce advance, receipt, certificate
   publication, settlement metadata, and lock release, or none of them.
4. A certificate whose header does not match the locally recomputed
   staged-commit commitment is rejected without mutating state, fee, nonce,
   or lock.
5. Exact replay of prepare and of apply, at any point after a restart,
   returns the original recorded outcome without re-locking, re-executing,
   re-debiting, or re-publishing.
6. A second intent addressed to a locked `(ObjectId, version)` is rejected
   before execution while the lock is held.
7. No new externally reachable event family is live (see "Ingress/activation
   boundary").
8. Stable Rust hex vectors for every new canonical frame, independently
   reconstructed byte-for-byte in JavaScript (this workspace's dual
   Rust/JS-vector convention), a real multi-validator SQLite restart/replay
   E2E, the complete repository gate, a focused security review, and a fresh
   tech-lead review of the integrated diff all pass.

The local Phase 1 boundary satisfies these criteria with the evidence recorded
below. This does not authorize testnet or production activation: external
ingress and the independent activation gates remain separate requirements.

## Safety invariants

- A `FastVote` is returned or published only after full intent
  authentication, deterministic execution, and an atomic durable commit of
  the vote with every required lock. The deterministic signature may be
  computed while assembling that CAS transaction, but a losing/conflicting
  transaction never persists or exposes it.
- Neither prepare nor apply accepts a caller-supplied transaction hash or
  execution-effects hash as a value to sign or to trust; both are always
  locally recomputed from canonical intent bytes and locally staged state.
- Locks are exclusive per `(ObjectId, version)` and are held until either (a)
  an atomic certificate apply releases them, or (b) a Phase 2
  validator-set-authorized recovery procedure releases them (not defined by
  this DR). There is no other release path in Phase 1.
- Certificate apply is fail-closed on commitment mismatch: it neither applies
  nor releases the lock, since a mismatched certificate is not proof that the
  correct commitment is unreachable.
- Certificate apply reuses the existing atomic durable-commit convention
  (fenced invocation, no partial commit); it does not introduce a second,
  weaker atomicity boundary for the fast path.
- Fee debits under certified execution use the same ordinary asset-account
  state and existing pinned recipient as the rest of paid execution; this DR
  adds no new balance authority (see `SECURITY.md`'s existing fee invariant).
- Object access and effects remain within the signed intent's manifest, same
  as the ordinary paid path; the fast path is a different commit/lock
  mechanism, not a different authorization surface.

## Durable state machine

The implementation assigns these canonical frame IDs, all at version 1:

| Type ID | Record |
| --- | --- |
| `0x641B` | exact object lock |
| `0x641C` | prepared intent/vote |
| `0x641D` | applied certificate |
| `0x641E` | authoritative fee-escrow settlement row (extended in place by DR-0137) |
| `0x641F` | signed-genesis validator set |
| `0x6420` | prepared object-reference list |
| `0x6421` | retired by DR-0137 (former settlement signer-ID list) |
| `0x6422` | validator-entry list |
| `0x6423` | validator entry |
| `0x6424` | staged-commit commitment envelope |
| `0x6425` | sender/epoch nonce lock |
| `0x6435` | DR-0137 fee-share entry |
| `0x6436` | DR-0137 bounded fee-share list |

Their literal Rust bytes and the independently reconstructed JavaScript bytes
are pinned by `crates/node-core/src/fast_path/tests.rs` and
`scripts/fast-path-vectors.mjs`.

Records live under a reserved fast-path namespace, parallel to this
workspace's existing chain/protocol-version-scoped object, nonce, and outbox
namespaces (see `docs/operations/persistence.md`):

- **Prepared intent/vote record.** Keyed by chain and the original signed
  request ID. Holds the trusted context, signed-intent digest, staged-commit
  commitment, exact locally cast vote bytes, exact locked object references,
  and pending nonce. Apply receives and re-authenticates the canonical signed
  intent bytes and re-executes the shared admission pipeline; the record does
  not preserve a second copy of those potentially large bytes or of the
  staged effects.
- **Object lock record.** Keyed by `(chain, ObjectId)` and containing the
  exact `(ObjectId, version, digest)` plus owning request ID. This is stronger
  than a key scoped only to one version: no later version of the same object
  can bypass a pending lock. Its presence is what a conflicting intent's
  validation checks before execution.
- **Sender nonce lock record.** Keyed by `(sender, epoch)`. Carries the exact
  nonce asserted at prepare and points back to the prepared intent. It blocks
  both another fast-path prepare and the ordinary direct paid path from
  consuming the same nonce; it is deleted only by the final apply that
  atomically advances the ordinary sender-nonce record.
- **FastVote bytes.** Embedded in the prepared record so the object/nonce
  locks and the exact vote become durable in one CAS commit; re-preparation
  returns those byte-identical bytes instead of re-signing.
- **FastCertificate record.** The verified, applied certificate for a
  commitment. Phase 1 has no separately committed "verified but unapplied"
  state.
- **Settlement metadata record.** The fee output, actual charged amount, and
  canonical active-validator IDs attributed to this certified execution.
  Recording the inputs for later distribution is not distribution itself;
  balance mutations and the deterministic rounding/remainder rule remain
  Phase 3.
- **Receipt.** The ordinary receipt record, reused as-is, now attributable to
  a certificate apply rather than direct execution.

The prepared-intent, FastVote, object-lock, and nonce-lock records commit
together at prepare time without applying effects or advancing the nonce.
The application/fee mutations, ordinary receipt, FastCertificate and
settlement records, nonce advance, and deletion of all those locks commit
together in the atomic certificate apply described in "Decision" item 9.

## Ingress/activation boundary

Phase 1 does not activate any new externally reachable event family. It does
not change the fact recorded in `SECURITY.md` that the implemented native
external mutation surface accepts only authenticated `SubmitTransaction`
events, and it does not change the existing hard activation constraint
already recorded in `TODO.md` and `docs/architecture/core-protocol.md`
section 8: protocol version 3 must not go live on any chain until
shared-object ordering, `FastVote`/`FastCertificate`, certificate
publication, and every externally accepted event family's
authenticated/authorized ingress are implemented and atomically composed,
and the CLI-First Node Production Gate's S4/S5 and independent
security/release gates are separately complete.

An implementation of this DR may add a local/devnet-only, explicitly opt-in
path for testing (mirroring how DR-0121/DR-0122/DR-0123 gated local contract
publication before any public activation), but it must not accept
unauthenticated or unauthorized external submissions, and it does not by
itself satisfy the hard activation constraint above. Any HTTP/CLI surface for
submitting votes or certificates externally requires its own
authenticated/authorized ingress design and its own decision record, same as
any other non-`SubmitTransaction` event family.

## Verification evidence

The 2026-09-22 implementation records the following evidence in the same
form used by DR-0121-DR-0129:

- Real Ed25519 sign/verify across at least four independently invoked
  validators forming one real quorum `FastCertificate` deterministically,
  independent of vote/apply arrival order.
- Exact replay reconciliation at prepare and at apply, including after a real
  process restart with file-backed SQLite (this workspace's restart/replay
  convention), proving no re-lock, re-execution, re-debit, or
  re-publication.
- Conflicting-intent rejection: a second intent addressed to an already
  locked `(ObjectId, version)` is rejected before execution, with object,
  fee, nonce, and receipt state unchanged.
- Certificate/commitment mismatch rejection: an invalid or wrong-commitment
  certificate is rejected without mutating application state, fee, nonce, or
  releasing the lock.
- Atomicity fault injection on certificate apply (matching this workspace's
  existing PostgreSQL/SQLite fault-injection conventions) proving effects,
  fee-escrow debit, nonce, receipt, certificate record, settlement metadata,
  and lock release commit or fail together, with no partial commit.
- Stable Rust hex vectors for every new canonical frame this phase
  introduces, each independently reconstructed byte-for-byte by a
  `scripts/*-vectors.mjs` script with no Rust encoder invoked, following
  `scripts/fast-vote-vectors.mjs`'s existing convention.
- `crates/node-core/src/fast_path/tests.rs` contains 25 passing tests,
  including four independent file-backed SQLite validator stores, real
  three-of-four certificate formation, close/reopen prepare/apply replay,
  direct-path exclusion, conflicting-intent rejection, wrong-commitment
  rejection, writer-generation fencing, and indeterminate-commit
  reconciliation. `crates/node-core/src/genesis/tests.rs` contains 10 passing
  signed-genesis tests.
- `scripts/fast-path-vectors.mjs` independently reconstructs every new
  canonical frame and the staged-commit digest without invoking a Rust
  encoder; it is wired into `scripts/check-all.sh`.
- `cargo fmt --all`, the workspace tests and Clippy checks, and the complete
  `./scripts/check-all.sh` gate are required on the final integrated diff.
  A focused security review and fresh tech-lead approval remain mandatory
  pre-merge gates; a later code change invalidates those review results.

## Consequences / Deferred

- FastVote is not complete after Phase 1. A testnet may launch on the static
  genesis validator set Phase 1 defines, but that is a deployment decision
  separate from FastVote completion, which requires Phase 3.
- Phase 1 alone does not change any fact in `SECURITY.md` about the current
  external ingress surface; its own ingress, if any, stays local/opt-in only
  until a dedicated authenticated ingress decision activates it.
- Lock recovery — releasing a permanently held lock whose certificate never
  formed — is explicitly out of scope for Phase 1. Phase 2's validator
  lifecycle design must guarantee that any recovery procedure it introduces
  can never permit two conflicting certificates to apply for the same object
  version.
- Validator-set changes, epoch/view rotation, equivocation evidence, and
  multi-validator fault/restart tests beyond what Phase 1's own test
  evidence requires remain Phase 2, undesigned by this DR.
- Bond-linked slashing and fee/reward distribution to the committed active
  validator set remain Phase 3, later designed by DR-0137. Phase 1's "protocol
  escrow" fee boundary is explicitly not a distribution mechanism.
- This DR does not modify DR-0129's `crates/consensus` types, wire IDs, or
  signature domain. Any new canonical frame this phase needs (in particular
  the staged-commit commitment) is scoped by property here and left to the
  implementation PR to define, vector, and review.
- `ChainedHotStuff`, shared-object consensus, and Standard Asset's status as
  ordinary paid contract state are unchanged by this DR.
- **[DR-0133](0133-fastvote-equivocation-evidence.md) (2026-09-22, design
  only, not implemented) extends `FastVote`'s canonical v1 payload in place**
  with a `locked_objects_digest` field hashed from this DR's own
  `PaidAdmissionOutput::locked_objects`, threaded through the `cast_vote`
  call site this DR introduced (`fast_path.rs`'s `certifier.cast_vote(event_digest,
  commitment, signer)`, which gains a third argument). This is an in-place
  wire revision, not a new field this DR itself defines; no v2 or
  compatibility decoder exists in this unreleased repository.
