# DR-0135: protocol custody owner (FastVote phase 3 prerequisite)

## Status

Accepted and implemented, 2026-09-22. This decision defines and implements
the first prerequisite slice for FastVote phase 3. It does not implement
slashing, unbonding, fee distribution, or payout, and it does not close phase
3.

DR-0137 partially supersedes only this decision's temporary creation and
mutation closure: its implementation-unit-2 execution prerequisite now admits
one exact protocol-constructed, invocation-local capability through the normal
typed-WASM path. Ordinary sender-authorized, paid and contract-creation paths
remain closed, and no bond lifecycle operation or durable custody mutation is
complete yet.

Phase 2 is already implemented on `main` by DR-0134's companion code and
review gate. Phase 3 remains required before FastVote is complete.

## Context

Phase 3 must eventually do two value-moving jobs:

1. hold validator collateral so proven equivocation can forfeit value after
   the offense, rather than merely record an operator-declared number; and
2. hold a certified transaction's fee until the final certificate signer set
   is known, then release deterministic shares.

An address-owned object cannot provide that boundary. Any address has a
signature-shaped authorization path, so an address-based "escrow" either has
a private key that can bypass protocol rules or depends on an unsafe
assumption that no valid signature can exist. `Shared`, `Immutable`, and
`System` ownership also do not identify a bounded economic custody scope.

The current `objects::Owner` encoding is a closed tagged union. Existing tags
1 through 4 are `Address`, `Shared`, `Immutable`, and `System`; tag 5 is free.
Adding a new tag leaves every existing owner and object byte-for-byte
unchanged while Rust's exhaustive matches force every authorization boundary
to classify the new owner explicitly.

The ownership layer must remain independent of Standard Asset, bonds, and
fees. `objects` is below those crates in the dependency graph and must not
learn an `AssetId`, a balance layout, or a slashing policy.

## Decision

### Canonical custody owner

Add `Owner::ProtocolCustody(ProtocolCustodyScope)` as owner tag 5.
`ProtocolCustodyScope` is a bounded canonical ownership namespace containing:

- a closed `ProtocolCustodyPurpose` tag;
- the exact `ChainId`;
- a 32-byte subject identifier; and
- a 32-byte resource identifier.

This slice admits only `BondCollateral` as a purpose. For that purpose a
higher layer interprets `subject` as a `ValidatorId` and `resource` as an
`AssetId`. Those meanings are not imported into `objects`; later purposes,
including fee escrow, must receive their own explicit enum variant and
validation decision rather than overloading `BondCollateral`.

The scope uses a new canonical frame `0x4007/v1`. The existing owner frame
`0x4003/v1` keeps field 1 as the tag, keeps field 2 exclusively for an
encoded `Address`, and uses field 3 exclusively for the encoded custody
scope. Decoding requires the exact field set for the selected tag and a
structurally canonical byte representation: ordered unique fields, exact
field widths, and no trailing bytes.

### Authority boundary

Protocol custody is not an address and has no signing key. Ordinary
sender-authorized execution must never treat it as sender ownership.

Every existing owner match in execution, node-core, durable projections, and
tests is made exhaustive for the new variant. Unless this decision explicitly
allows an operation, `ProtocolCustody` follows the fail-closed branch used by
unsupported non-address owners. In this slice it cannot:

- authenticate a sender;
- be supplied as a sender-authorized `Write` or `Consume` input;
- be used as a paid fee source;
- change owner through the ordinary transferable-object path (DR-0137's
  separate pinned capability is not an ordinary path);
- be acquired as a FastVote sender-owned lock; or
- be created by an ordinary contract result.

Read access is not opened by this slice. A later economics operation must
define its own proof, exact object set, and mutation boundary rather than
reusing an ordinary sender path.

### Creation boundary

The only creation path in this slice is the existing signed genesis manifest.
`GenesisObjectEntry` already commits the complete canonical `Object` and its
immutable `ObjectAuthority`; no manifest field or signature domain is added.
Genesis may install a `ProtocolCustody` object only when:

- the scope chain equals the manifest chain;
- the purpose is one of the closed purposes supported by this release; and
- the object's existing authority, nominal body, type fingerprint, version,
  and signed-manifest checks all pass unchanged.

Genesis does not interpret the resource bytes as a Standard Asset, decode an
amount, create a bond record, or enforce a minimum bond. A custody-owned
object is therefore only safely immobilized value/state at this boundary; it
is not yet a recognized bond.

No post-genesis deposit, release, withdrawal, forfeiture, transfer, or payout
path is added. Absence of a release path is intentional and fail closed.

### External boundary

This slice adds no `NodeEventKind`, HTTP route, CLI command, client method,
relay, watcher, or signature domain. DR-0134's seven-operation Phase 2 matrix
and closed public FastVote ingress remain unchanged.

## Invariants

1. Every pre-DR-0135 `Address`, `Shared`, `Immutable`, and `System` owner
   encoding is byte-for-byte unchanged.
2. A custody scope is canonical, chain-bound, closed-purpose, and cannot be
   confused with an address.
3. No ordinary sender signature authorizes a custody-owned object.
4. No ordinary execution, paid execution, owner-transition, or FastVote lock
   path writes or consumes a custody-owned object.
5. Only a valid signed genesis manifest can introduce custody ownership under
   this decision alone; DR-0137 separately defines the exact contract-produced
   capability required for a post-genesis transition.
6. Genesis custody installation does not claim that the object is collateral,
   does not inspect an asset balance, and grants no future release authority.
7. No native code gains authority to decode or write a Standard Asset balance.
8. No existing consensus, transaction, certificate, or FastVote canonical
   bytes change.

## Required evidence

- stable Rust vectors for `0x4007/v1` and owner tag 5;
- regression literals proving the four existing owner encodings are unchanged;
- strict decode rejection for unknown purpose, wrong owner field selection,
  malformed identifiers, wrong frame type/version, extra fields, and trailing
  bytes;
- signed genesis install plus close/reopen `VerifiedExisting` for one custody
  object, and rejection of a scope bound to another chain;
- adversarial rejection of a custody object as an authenticated object input,
  ordinary owner transition, paid fee source, local execution mutation,
  preinstalled-WASM mutation, and FastVote lock target;
- unchanged FastVote/FastCertificate vectors and the complete repository gate;
- fresh security and tech-lead review of the integrated diff.

## Consequences and next slices

This decision creates the non-signable ownership primitive needed by both
halves of Phase 3 without embedding asset-specific logic in `objects`.

It deliberately leaves Phase 3 open. DR-0136 now adds typed, read-only value
observation through committed executable ABI metadata and binds a genesis
custody object to an asset-aware bond record. The next decision must define
the closed protocol-authorized release operations together:
deposit, unbond/withdraw, evidence-driven forfeiture, fee-escrow conversion,
signer entitlement, and payout. These operations must execute amount changes
through the defining public contract; node-core must never write asset bodies
directly.

Until that release-authority slice lands, custody objects installed by genesis
remain immobile. DR-0136 records their validated bond value, but must not be
presented as working slashing, unbonding, payout, or distributed-fee
machinery. Testnet or production activation remains a separate decision under
the existing hard activation constraints.

DR-0137's first execution prerequisite has since landed locally: a private,
non-address transfer operand is derived for one exact source and custody scope,
and the host resolves it only inside one exact policy-pinned invocation. The
inverse release capability accepts only the exact custody input and exact
recipient. These effects remain provisional; node-core lifecycle admission,
postcondition validation and atomic durable commit are still required before
custody is actually movable.
