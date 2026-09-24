# DR-0137: FastVote release authority and economics state machine

## Status

Accepted, 2026-09-23. Implementation unit 1 (resource-generic policy, signed
economics/lifecycle codecs and genesis persistence/restart verification) is
implemented and locally validated. Unit 2 is now implemented and locally
validated: the invocation-local protocol-custody execution capability; a
generic, contract-agnostic whole-object custody-effect validator
(`bond_lifecycle::effects`) that independently rejects any leg reporting a
created object regardless of engine output; the closed
`BondLifecycleIntent 0x642F/v1` envelope (signed as `0x6430/v1`), which pins
the exact `BondResourceId`, expected pre-transition generation, expected
previous-row digest and expected next-row digest the validator committed to
ahead of execution, verified against the committed bond row's own
authorization key both at submission (against the row actually read) and at
commit (against the deterministically built resulting row, byte-exact,
before any state is written) -- making the transition chain
cryptographically non-forgeable rather than merely digest-summarized; a
receipt/dedup digest kept distinct from the signing digest, hashing the
exact signed envelope bytes so a resubmission under a different signature
over an identical intent conflicts instead of replaying; the complete closed
Deposit/Replace/Unbond/Withdraw state machine (Withdraw authorized by the
committed validator plus an exact release-submitter signature, not any
source/deposit authority; Unbond/Withdraw preserving the current row's
`required_minimum` exactly so a later policy minimum raise cannot strand an
already-eligible exit; Unbond independently validating a canonical
prime-order Ed25519 recipient address; every leg's own `request_id` pinned
to the outer intent's), each committing through one atomic
`DurableInvocationTransaction`; a canonical, safe
`FastPathBondRecord::live_collateral()` accessor that returns `None` once
`Exited`/`Jailed` -- a discipline the type invites for any code that sums or
reports bonded stake, not one Rust's field visibility mechanically enforces,
since `custody_object`/`amount` remain public fields a caller can still read
directly; the permanent `FastPathBondTransitionRecord 0x6431/v1` audit
chain, now retaining the exact signed envelope and exact resulting row
bytes (not a digest/signature summary) for independent re-verification, and
now also cross-checking its own redundant `committed_at_checkpoint` copy
against the decoded resulting row's; and genesis restart re-verification
that walks that chain (`genesis::verify_fastpath_bond_chain`), independently
re-decoding and re-verifying every stored envelope's signature and every
stored row's identity/closed-transition from first principles, so a
post-genesis transition no longer makes restart fail closed on the
now-expected byte difference, while a deleted transition, swapped
generation, lifted signature, tampered envelope, tampered stored row, a
tampered `committed_at_checkpoint` summary, or a coordinated rewrite of a
transition and the final row together all still fail restart -- while the
advanced singleton itself, or the transition chain leading to it, remains
present under this store; a full durable-store rollback to exactly the
genesis snapshot is, by construction, indistinguishable from a legitimate
fresh install unless a separately anchored checkpoint/state-root publication
detects it, which remains out of this decision's scope. Partial
(non-whole-object) release remains deferred to unit 4's fee-claims work,
unchanged from unit 1. Unit 4's certification half is now implemented and
locally validated: FastPath prepare/apply install a settle-phase-only creation
capability that promotes only the ABI-returned fee result slot to exactly one
request-scoped `FeeEscrow` owner before the effects commitment is computed;
ordinary paid/application execution receives no such authority; apply derives
ascending unique signer entitlements by the quotient/remainder rule and stores
them with the exact escrow object, resource, creation epoch, total and initial
generation in the same atomic certificate commit. The mutable claim state
machine, claim races/restart evidence and Phase 3 review gate remain
incomplete. Deposit and Replace now each have dedicated
real-WASM success-path integration tests (Replace proving same-sender
consecutive nonces, both owner transitions, and one atomic commit) alongside
Withdraw's real-WASM, real-storage end-to-end coverage including genesis
restart chain-walk re-verification; a real file-backed SQLite test spans
Deposit, Unbond and Withdraw across three independent close/reopen cycles
plus writer-fence rejection and two competing writer attempts proving
exactly one commit with no partial state. Units 3 and 4 and the Phase 3
review gate remain incomplete.

## Context

DR-0135 makes protocol custody non-signable. DR-0136 observes one positive,
typed genesis bond per validator without a runtime `node-core` import of
Standard Asset or a private asset-body decoder. Neither decision grants an
authority that can mutate custody. Standard Asset remains a dev-dependency for
fixtures, and the existing generic fee layer still carries `fees::AssetId`,
therefore retaining a transitive `fees -> standard-assets` dependency.
Removing that separate generic fee identifier dependency is not part of
implementation unit 1.

Phase 3 still needs four related value-moving operations:

1. bond deposit, replacement, unbond and withdrawal;
2. evidence-driven forfeiture, jail and reactivation;
3. conversion of certified fee outputs into escrow; and
4. deterministic signer entitlements and claims.

These operations cannot use ordinary sender ownership, a node-local policy, or
direct object-body rewriting. They must be authorized by committed protocol
state and must execute the object's defining public contract.

## Decision

### One closed release-authority boundary

`node-core` exposes these operations only as in-process APIs. This decision
adds no HTTP route, CLI command or `NodeEventKind`. Each API authenticates its
complete canonical intent or cryptographic evidence before trusted storage
work, reconciles exact replay, and then performs one CAS-fenced durable commit.

The boundary may execute a policy-pinned public-contract entrypoint, but it
does not gain a generic ability to write object bodies. Contract effects are
accepted only when their exact type, authority, ownership and value
postconditions match the requested protocol transition.

### Signed economics policy

Genesis commits a bounded `FastPathEconomicsPolicy` inside the signed
`GenesisManifest`. It is persisted and restart-verified with the manifest and
is not read from node-local `ProtocolConfig`.

Each ordered resource entry commits:

- a non-zero opaque resource domain and 32-byte value;
- the exact publication context, instance target, code reference and complete
  nominal type;
- the non-zero object schema;
- exact public `split` and `transfer` entrypoint names;
- whether the resource may be used for bonds and/or certified fee escrow;
- when bond-enabled, a positive minimum and positive unbonding delay.

Entries are strictly ordered and unique by resource identity. The complete
nominal type must contain that same opaque resource as its sole type argument.
Genesis verifies the referenced code, instance, ABI, schema and entrypoints.
No package id, Standard Asset constructor, native coin body or local alias is
recognized by node core.

This repository is unreleased. `GenesisManifest` remains its clean v1 format
and is changed in place to carry the policy; no compatibility decoder or
parallel v2 format is retained.

### Generic custody execution

Execution receives an authenticated, policy-pinned operation and the exact
current object/authority. It invokes the defining contract through the normal
typed WASM path. Node core then validates the returned effects generically:

- every input and output keeps the exact defining code, instance, complete
  nominal type and schema;
- values are observed only through the signed ABI and canonical `CallValue`;
- partial release conserves `old = retained + released`;
- full release conserves the complete old value;
- the retained object stays in the exact required protocol-custody scope;
- the released object has the exact signed recipient;
- no undeclared creation, deletion, event or state mutation is admitted; and
- the complete contract/object/state effects and protocol records commit in
  one durable invocation transaction.

The host cannot manufacture the released body. A resource whose public
contract does not expose the committed ABI-compatible operations cannot be a
bond or fee resource.

The implementation-unit-2 prerequisite uses no generic `Owner` ABI and does
not add an owner-constructor profile. A protocol operation constructs one
private capability bound to the current context, authenticated sender, exact
signed execution event digest, instance/code/type/schema/entrypoint, one exact
object and one closed direction. For deposit it maps a derived, non-address 32-byte operand to one
exact `ProtocolCustodyScope`; for release it admits one exact custody-owned
`Write` input and maps only the exact recipient address. The mapping lives for
one invocation, cannot be persisted, cannot authorize `Consume`, and is never
available to `create_object`. All ordinary and paid execution paths pass no
capability.

The deposit operand is derived from canonical preimage `0x642E/v1` and the
existing `HashPurpose::Object` domain at the invocation epoch. Its fields are:

1. the exact chain id;
2. canonical `ProtocolCustodyScope 0x4007/v1` bytes;
3. canonical source `ObjectId 0x4001/v1` bytes; and
4. a canonical little-endian `u32` rejection-sampling counter.

Counters 0 through 63 are tried in ascending order and the first digest that is not
a canonical prime-order Ed25519 address is selected. Address-shaped digests are
skipped rather than making that source permanently unusable. Exhausting all 64
attempts fails closed; it is bounded and negligible under the committed hash
suite assumptions. The counter-zero preimage has matching Rust and independent
JavaScript vectors. `0x642E` was the next clean unallocated execution/FastVote
frame id in this unreleased repository; `0x642F` remains unallocated and has no
implied compatibility meaning.

`ProtocolCustodyScope.resource` remains the 32-byte value component of the
resource identity and its existing owner bytes do not change. The opaque domain
is still bound: the private capability pins the complete `ScopedTypeTag`
(including opaque domain and value), defining code, instance and schema, while
the scope value must equal that tag's sole opaque value. A different opaque
domain is therefore a different exact target and cannot bind the admitted
object. The scope alone is not claimed to encode the complete typed resource
policy.

This foundation only allows the defining contract to produce provisional
effects. It neither authorizes a lifecycle operation nor commits storage.
Node core must still construct the capability from committed economics policy,
validate the complete effect postconditions above and atomically fence the
object and lifecycle rows before any post-genesis custody transition is real.

### Bond lifecycle

`FastPathBondRecord` is the single authoritative per-validator lifecycle row.
Every generation records the epoch in which that lifecycle transition was
committed (`lifecycle_epoch`) -- pure transition time, never overloaded to
carry liability or object-mint provenance. An `Unbonding` generation must
name an unlock epoch strictly after that lifecycle epoch, rather than after
the defining publication epoch. Two further epochs are tracked separately,
each answering a distinct question `lifecycle_epoch` cannot: `custody_object_epoch`
names the exact epoch the live `custody_object`'s own digest was actually
computed at -- every operation that mints a fresh object ref (genesis,
`Deposit`, `Reactivate`, `Replace`, `Withdraw`, `Slash`) sets it to that
transition's own committing epoch, while `Unbond` (which executes no leg and
never touches the custody object) carries it forward unchanged even as
`lifecycle_epoch` itself advances -- restart must hash a retained previous
object body at exactly this recorded epoch, never at `lifecycle_epoch`, or a
hash-suite rotation that occurred while a bond sat `Unbonding` silently
miscomputes the digest; `slashable_from_epoch` is the liability floor
(below). Before release it is extended in place, without a compatibility
version, with a positive generation, the policy minimum captured for the
transition, and one state:

- `Active`;
- `Unbonding { unlock_epoch, recipient }`;
- `Jailed { evidence_digest }`; or
- `Exited`.

Whole-object deposit or replacement is the first supported profile. Arbitrary
partial top-up is deferred because it is not required for FastVote safety.
Replacement requires source-owner authorization, validator authorization, the
same policy-pinned resource/type/instance, a newer generation and an amount at
least the previous live bond amount (and therefore also at least the committed
minimum), while still respecting the committed maximum exposure. Replacement
releases the complete prior object, so allowing a smaller replacement would
bypass the Unbond/Withdraw delay and reduce collateral still exposed to old
evidence. Amount reduction therefore goes only through Unbond/Withdraw.

Unbond records `current_epoch + unbonding_epochs` and the signed recipient.
The bond remains slashable for as long as the collateral remains custody-owned,
including after the unlock epoch and until withdrawal actually commits.
Withdrawal requires the delay to have elapsed, the validator to be absent from
the committed live set, the exact bond generation/object to remain unchanged,
and no jail or forfeiture record. Slash-versus-withdraw is resolved by the
shared bond-row and object-head compare-and-swap fences, so exactly one may
commit.

Every embedded leg's own `request_id` is required to equal the outer
`BondLifecycleIntent::request_id` exactly, and both share the ordinary
`DurableRequestId` dedup namespace with every other externally reachable
request. This closes ordinary-path/outer-path replay, but it also means a
leg cannot be pre-submitted or resubmitted on its own once its request id has
been consumed: whichever path (the bare leg through ordinary local execution,
or the leg embedded in a `bond_lifecycle` envelope) commits or is rejected
first for that request id fails-closed conflicts the other. An operator who
separately pre-submits or replays a leg's own bytes before submitting the
full `bond_lifecycle` envelope therefore burns that request id and must sign
a fresh envelope (a new outer and leg request id) rather than resubmit the
same one; this is deliberate fail-closed behavior, not a defect.

### Evidence consumption and jailing

All three DR-0133 evidence families are eligible only after their existing
canonical verification against the chain-anchored historical validator set.
One evidence digest may be consumed once.

Slashing gates on `slashable_from_epoch`, never on `lifecycle_epoch`:
`evidence_epoch >= bond.slashable_from_epoch` is required, but `evidence_epoch`
is never compared against `lifecycle_epoch`. `slashable_from_epoch` is the
earliest evidence epoch a generation's live collateral is liable for. Fresh
collateral (`Deposit` from `Exited`, `Reactivate` from `Jailed`) sets it to
the committing epoch plus one -- it can only ever join the *next* validator
set and must never be liable for evidence at or before the epoch it was
posted; every other operation, including `Unbond` and `Replace`, preserves it
unchanged from the previous generation; the one genesis generation is liable
from the genesis epoch itself. `Unbond` and `Replace` both stamp
`lifecycle_epoch` to their own committing epoch while carrying forward the
same (or, for `Replace`, freshly re-posted but liability-equivalent) live
collateral a validator was already liable for; gating on `lifecycle_epoch`
instead would let a validator launder away old equivocation evidence for free
merely by unbonding or replacing after misbehaving but before evidence lands.
`Withdraw` and `Slash` also preserve `slashable_from_epoch` unchanged, purely
as historical audit data once the row is no longer live.

The initial slash rule is full forfeiture. One atomic commit consumes the
evidence, moves the complete bond into `ForfeitedCollateral`, advances the
bond generation and records `Jailed`. Percentages, discretionary penalties
and forfeited-value disposal are outside FastVote's first complete profile.

Jailing never changes current-epoch certificate verification. It disables
local signing and prevents the validator from entering a later certified set.
Reactivation requires a newly authorized policy-compliant bond and affects
only a future epoch transition.

Every proposed next-set validator must have an `Active`, custody-owned bond
whose authorization key matches the proposed validator key and whose amount
satisfies the current committed economics policy. `Unbonding`, `Jailed`,
`Exited`, absent, disabled, under-bonded and over-exposed records fail closed.
Genesis therefore requires exactly one policy-compliant bond per genesis
validator; this invariant is established at install instead of being
discovered only at the first epoch transition.

This eligibility gate is checked in exactly one place: before a validator
casts its own epoch-transition vote. It is never re-checked when a
certificate is later applied. Certificate application is a pure function of
an already-quorum-certified transition: whether a slash happens to commit
before or after a certificate is formed or activated must never change
whether that certificate applies. A slash that lands between certificate
formation and activation therefore has no effect on that transition -- the
now-jailed validator's bond simply fails the gate the *next* time a set is
proposed. Coupling activation to live bond eligibility (for example by
folding bond/policy revisions into activation's own compare-and-swap read
set) would let a race between a slash and an activation determine whether an
already-certified transition commits, which is exactly the divergence this
ordering rule forecloses.

Under the full-forfeiture profile, a second evidence item for the same
misconduct epoch cannot take a later reactivation bond: the first item removes
the only live collateral, and a reactivated generation's `slashable_from_epoch`
is set to strictly after the reactivation's own committing epoch, which is
itself strictly after the old evidence's epoch -- not because
`lifecycle_epoch` merely advanced (an advancing `lifecycle_epoch` alone never
gates a slash; see above). This is deliberate; partial or cumulative
penalties require a later policy.

### Certified fee escrow and claims

The paid-execution fee output is promoted to `FeeEscrow` before the prepared
effects commitment is computed. This is not a node-core body/owner rewrite: a
settle-phase-only execution capability binds the policy-pinned fee recipient,
exact type/schema/instance/code/entrypoint and exact request-scoped custody
owner, then promotes only the fee slot returned by the pinned settlement ABI.
The refund slot remains address-owned even when both recipients are the same.
A certificate therefore covers the exact custody object later applied. Apply
derives one bounded escrow row from the verified certificate and settlement
data in the same commit.

Signer ids are sorted and must be unique. For total `T` and signer count `N`,
each signer receives `T / N`; the first `T % N` ids in ascending byte order
receive one additional unit. The shares must sum exactly to `T`.

One escrow row carries all bounded shares and their claimed state to avoid a
state write per signer. A claim is signed by the historical validator key and
binds the certificate epoch, escrow id, generation, exact share and recipient.
For a charged row, `generation == claimed_share_count + 1`; this makes every
claimed-bit transition part of the same monotonic CAS fence.
Partial positive claims use the policy-pinned `split`; the final positive
claim uses `transfer`. A zero share is finalized without an object mutation.

### Implementation order

1. make bond policy resource-generic; add strict economics policy and lifecycle
   codecs, keys, genesis commitment and restart verification;
2. add the invocation-local contract execution capability, then implement
   generic custody-effect validation plus deposit/replacement, unbond and
   withdrawal;
3. consume equivocation evidence atomically with full forfeiture, jail,
   reactivation and next-set eligibility checks; and
4. commit fee escrow before certification, derive deterministic entitlements,
   implement claims and close the Phase 3 review gate.

## Invariants

1. Node core runtime code has no Standard Asset import, constructor id,
   private body codec or asset-specific economics branch. Standard Asset test
   fixtures remain dev-dependencies, and the generic fee layer's existing
   transitive `AssetId` dependency is not an economics authority.
2. Every release is authorized by signed bytes or verified evidence and a
   committed economics policy.
3. Replay reconciliation precedes policy/object/ABI work after authentication.
4. Custody value moves only through the defining public contract.
5. Policy, bond, evidence, escrow and object revisions are fenced in the same
   atomic commit that changes value.
6. A validator cannot withdraw value that remains slashable.
7. Local jail arrival cannot invalidate a certificate other nodes accept.
8. Shares are deterministic, order-independent and exactly conserve value.
9. Existing `FastVote` and `FastCertificate` canonical bytes do not change.

## Required evidence

- stable Rust and independent JavaScript vectors for every new policy,
  lifecycle, escrow, claim and intent frame;
- malicious-contract rejection for wrong value, type, instance, schema,
  authority, owner, recipient, creation count or conservation;
- exact/conflicting replay, restart, tombstone, CAS race and indeterminate
  commit tests in memory and real file-backed SQLite;
- withdraw-versus-slash, replacement-versus-slash and duplicate-claim races;
- one-time full forfeiture for each DR-0133 evidence family;
- real, multi-epoch evidence-versus-later-transition coverage: evidence
  recorded at epoch `E`, a real epoch bump to `E + 1`, then a real `Unbond`
  (respectively `Replace`) committing at `E + 1`, then a real evidence-driven
  slash using the old evidence that still succeeds and restart-verifies,
  proving the `slashable_from_epoch` gate -- not `lifecycle_epoch` -- is what
  actually decides eligibility; plus a hash-suite-rotation variant proving
  restart hashes a bond's previous custody object at its own recorded
  `custody_object_epoch`, never at the transitioning epoch;
- a focused negative test proving a freshly deposited/reactivated bond's
  `slashable_from_epoch == committing epoch + 1` floor rejects real evidence
  dated at or before the deposit/reactivation itself;
- next-set rejection for unbonding, jailed, exited or under-bonded validators;
- signer-order-invariant rounding vectors including `T < N`, exact division,
  remainder ordering and `u64::MAX`; and
- a dependency/source guard proving economics runtime code has no Standard
  Asset import, Standard Asset special case or direct asset-body rewrite;
  dev fixtures remain permitted, while eliminating the generic fee layer's
  transitive `AssetId` dependency remains separate follow-up work.

## Consequences

The protocol gains one auditable authority boundary instead of separate
exceptions for bonds, slashing and fees. The first complete profile is
deliberately strict: whole-object replacement, full forfeiture and explicit
claims. More flexible economics can be introduced later through a new signed
policy, not by widening node-core asset knowledge.

FastVote remains incomplete until all four implementation units and their
independent security and tech-lead reviews pass.
