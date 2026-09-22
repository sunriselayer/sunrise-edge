# DR-0137: FastVote release authority and economics state machine

## Status

Accepted, 2026-09-23. Implementation unit 1 (resource-generic policy, signed
economics/lifecycle codecs and genesis persistence/restart verification) is
implemented and locally validated. Units 2 through 4 and the Phase 3 review
gate remain incomplete.

## Context

DR-0135 makes protocol custody non-signable. DR-0136 observes one positive,
typed genesis bond per validator without importing Standard Asset into node
core. Neither decision grants an authority that can mutate custody.

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

### Bond lifecycle

`FastPathBondRecord` is the single authoritative per-validator lifecycle row.
Before release it is extended in place, without a compatibility version, with
a positive generation, the policy minimum captured for the transition, and
one state:

- `Active`;
- `Unbonding { unlock_epoch, recipient }`;
- `Jailed { evidence_digest }`; or
- `Exited`.

Whole-object deposit or replacement is the first supported profile. Arbitrary
partial top-up is deferred because it is not required for FastVote safety.
Replacement requires source-owner authorization, validator authorization, the
same policy-pinned resource/type/instance, a newer generation and an amount at
least the committed minimum.

Unbond records `current_epoch + unbonding_epochs` and the signed recipient.
The bond remains slashable before the unlock epoch. Withdrawal requires the
delay to have elapsed, the validator to be absent from the committed live set,
the exact bond generation/object to remain unchanged, and no jail or
forfeiture record.

### Evidence consumption and jailing

All three DR-0133 evidence families are eligible only after their existing
canonical verification against the chain-anchored historical validator set.
One evidence digest may be consumed once.

The initial slash rule is full forfeiture. One atomic commit consumes the
evidence, moves the complete bond into `ForfeitedCollateral`, advances the
bond generation and records `Jailed`. Percentages, discretionary penalties
and forfeited-value disposal are outside FastVote's first complete profile.

Jailing never changes current-epoch certificate verification. It disables
local signing and prevents the validator from entering a later certified set.
Reactivation requires a newly authorized policy-compliant bond and affects
only a future epoch transition.

### Certified fee escrow and claims

The paid-execution fee output is converted to `FeeEscrow` before the prepared
effects commitment is computed. A certificate therefore covers the exact
custody object later applied. Apply derives one bounded escrow row from the
verified certificate and settlement data in the same commit.

Signer ids are sorted and must be unique. For total `T` and signer count `N`,
each signer receives `T / N`; the first `T % N` ids in ascending byte order
receive one additional unit. The shares must sum exactly to `T`.

One escrow row carries all bounded shares and their claimed state to avoid a
state write per signer. A claim is signed by the historical validator key and
binds the certificate epoch, escrow id, generation, exact share and recipient.
Partial positive claims use the policy-pinned `split`; the final positive
claim uses `transfer`. A zero share is finalized without an object mutation.

### Implementation order

1. make bond policy resource-generic; add strict economics policy and lifecycle
   codecs, keys, genesis commitment and restart verification;
2. implement generic custody-effect validation plus deposit/replacement,
   unbond and withdrawal;
3. consume equivocation evidence atomically with full forfeiture, jail,
   reactivation and next-set eligibility checks; and
4. commit fee escrow before certification, derive deterministic entitlements,
   implement claims and close the Phase 3 review gate.

## Invariants

1. Node core has no Standard Asset dependency, constructor id or body codec.
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
- next-set rejection for unbonding, jailed, exited or under-bonded validators;
- signer-order-invariant rounding vectors including `T < N`, exact division,
  remainder ordering and `u64::MAX`; and
- a dependency/source guard proving economics code has no Standard Asset
  special case or direct asset-body rewrite.

## Consequences

The protocol gains one auditable authority boundary instead of separate
exceptions for bonds, slashing and fees. The first complete profile is
deliberately strict: whole-object replacement, full forfeiture and explicit
claims. More flexible economics can be introduced later through a new signed
policy, not by widening node-core asset knowledge.

FastVote remains incomplete until all four implementation units and their
independent security and tech-lead reviews pass.
