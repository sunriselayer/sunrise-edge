# DR-0136: typed FastVote bond commitment

## Status

Accepted and implemented, 2026-09-22. This decision defines FastVote
phase 3 slice 1. It follows DR-0135's non-signable protocol-custody owner and
does not yet authorize any custody mutation or close phase 3.

## Context

DR-0135 can immobilize an object under
`Owner::ProtocolCustody(BondCollateral)`, but that owner alone proves only a
chain-bound custody namespace. It does not prove that:

- the `subject` names a validator in the committed genesis validator set;
- the `resource` matches the nominal asset carried by the object;
- the object body represents a positive amount under its defining public
  contract's signed ABI; or
- a durable record binds the validator, resource, exact object version and
  observed amount for later protocol-authorized lifecycle operations.

Node core must not close those gaps by importing Standard Asset, recognizing
one package identifier, or decoding a `Coin<A>` body with a privileged native
codec. Public contracts already commit their constructor body layouts and
nominal types in `ExecutableAbi`. The correct boundary is a generic value
observation over that authenticated metadata.

Fee distribution is related but not identical. This slice's settlement record
was metadata-only. DR-0137 supersedes the historical certificate-signer payout
proposal: certified apply now commits the exact escrow output, charged amount,
and deterministic committed active-validator shares. Custody creation and
share release belong with the closed release-authority design, not this
read-only observation slice.

## Decision

### Generic signed-ABI value observation

`execution::publication` exposes one generic helper that:

1. validates the supplied complete `ScopedTypeTag` against a
   `VerifiedPublicationInterface`;
2. resolves the exact constructor schema and signed body `ValueLayout` from
   the authenticated executable ABI;
3. decodes the body through `abi::call_values::decode_call_value`; and
4. returns the resulting `CallValue` without granting execution, storage,
   ownership or mutation authority.

The existing `validate_nominal_body` uses the same helper and discards the
value. The helper contains no Standard Asset identifier, constructor number,
asset domain, or private body decoder.

For a bond, node core admits only the closed initial value profile needed by
the current public asset contract: the observed top-level value must be a
strictly positive `CallValue::U64`. This is protocol policy over a generic ABI
value, not knowledge of Standard Asset's wire encoding. A tuple, byte string,
zero, malformed value, unknown constructor, wrong schema, or unverified ABI
fails closed.

### Resource and validator binding

Every genesis object owned by
`ProtocolCustody(BondCollateral)` must satisfy all of the following:

- the scope chain equals the manifest chain, as required by DR-0135;
- `scope.subject` is exactly one `ValidatorId` in the manifest's committed
  validator set;
- its immutable `ObjectAuthority` is valid under the authenticated genesis
  publication and instance;
- its complete nominal type has exactly one opaque type argument;
- that opaque argument's 32-byte value equals `scope.resource`; and
- generic signed-ABI observation returns a positive `u64` amount.

The opaque argument's non-zero domain is retained in the bond record. Node
core does not name the domain or interpret the 32-byte value as a particular
application type. The exact defining code, instance and complete nominal type
remain bound by the persisted `ObjectAuthority`.

Every genesis validator has exactly one genesis bond record. A validator with
no matching custody object fails genesis installation rather than entering a
set without slashable collateral. Multiple custody objects for the same
validator fail closed instead of being summed implicitly. A future explicit
lifecycle operation may replace the record atomically, but there is no hidden
aggregation rule.

### Durable record

Add `FastPathBondRecord` as canonical frame `0x642A/v1`, keyed by
`fastpath_bond_record_key(chain, validator_id)` under the reserved FastVote
state namespace. It contains:

1. the genesis `PublicationContext`;
2. the exact `ValidatorId`;
3. the non-zero opaque resource domain;
4. the 32-byte resource identifier;
5. the exact custody `ObjectRef`;
6. the exact encoded `ObjectAuthority`;
7. the observed positive amount; and
8. the checkpoint at which the bond was committed.

The full authority is retained rather than restating selected package or
instance fields. Its existing strict codec binds object identity, original
instance target, defining code and complete nominal type without inventing a
second type system.

### Genesis atomicity and replay

Bond records are derived from fields already signed by the genesis manifest;
no new manifest field or signature domain is added. Fresh installation writes
every derived bond record in the same writer-fenced commit as the manifest,
validator set, epoch record, objects, authorities and closed marker.

Before that commit, every bond key must be absent at initial revision. A
duplicate derived key, live row, tombstone or partial prior state fails
closed. The marker is never written without every bond record.

On `VerifiedExisting`, installation re-derives the records from the supplied
signed manifest and authenticated ABI, then requires exact persisted bytes.
A missing or changed expected bond record is not repaired; restart
verification fails closed. Object and authority verification remains
independent, so a matching bond row cannot conceal object-state corruption.

### External and mutation boundary

This slice adds no `NodeEventKind`, HTTP route, CLI command, client method,
signature domain, vote field, certificate field or public mutation API. It
does not let ordinary execution read or mutate protocol custody.

The following remain closed for one later, integrated release-authority
decision:

- post-genesis deposit or bond replacement;
- unbond scheduling, withdrawal and validator exit;
- evidence-driven forfeiture, jailing and reactivation;
- fee-output conversion to protocol custody;
- committed active-validator entitlement calculation (DR-0137 supersedes the
  historical certificate-signer proposal);
- deterministic rounding/remainder assignment; and
- payout through the defining public contract.

Those operations must call the defining public contract and validate its
effects under authenticated ABI/instance authority. Node core must never
write an asset body directly.

## Invariants

1. Node core runtime code contains no Standard Asset import, constructor
   special case or private coin decoder. Standard Asset test fixtures remain
   dev-dependencies, and the generic fee layer's existing transitive
   `fees::AssetId` dependency is outside this genesis-bond boundary.
2. Bond amount observation is derived only from authenticated executable ABI
   metadata and generic canonical `CallValue` decoding.
3. Every bond record binds one committed validator, one resource, one exact
   custody object version and its complete immutable object authority.
4. The custody resource equals the sole opaque nominal type argument; an
   arbitrary `u64` object with another type cannot be substituted.
5. Bond creation and the genesis marker commit together or not at all.
6. Exact restart replay neither recreates nor mutates a bond; missing or
   changed durable bytes fail closed.
7. No custody release, slash, payout or externally reachable surface is
   introduced.
8. Existing transaction, object, vote, certificate, receipt and genesis
   manifest canonical bytes remain unchanged.

## Subsequent decision

[DR-0137](0137-fastvote-release-authority.md) intentionally supersedes the
last byte-stability statement for the unreleased `GenesisManifest` and
`FastPathBondRecord`. It keeps both as clean v1 formats while adding the signed
economics policy to `0x6416/v1` and generation/minimum/lifecycle state to
`0x642A/v1`; it retains unchanged transaction, object, vote, certificate and
receipt bytes and adds no compatibility decoder.

## Required evidence

- generic value-observation tests for a positive scalar, zero, wrong shape,
  wrong schema/type and malformed bytes;
- stable and adversarial `0x642A/v1` codec tests;
- genesis rejection for an unknown validator, resource/type mismatch,
  duplicate validator bond, zero value and non-scalar value;
- one real file-backed SQLite fresh install, close/reopen
  `VerifiedExisting`, exact record readback and tamper/missing-record
  rejection;
- proof that address-owned genesis objects create no bond row and ordinary
  custody mutation paths remain closed;
- unchanged FastVote/FastCertificate vectors and complete repository gate;
  and
- fresh security and tech-lead review of the integrated diff.

## Consequences

Phase 3 now has an asset-generic, auditable source of bonded value without a
native token or a Standard Asset exception. Slice 2 can use the exact bond
record as its CAS-fenced starting state and can require public-contract
effects to produce the next exact record.

FastVote remains incomplete. This record is an observed genesis commitment,
not proof that slashing, unbonding, fee distribution or payout exists.
