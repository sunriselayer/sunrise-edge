# Architecture decision DR-0106

Finish Slice A of the Standard Asset v1 whole-object transfer capability begun
by [DR-0105](0105-typed-asset-abi-foundation.md): persist DR-0105's typed-ABI
policy components as canonical wire bytes, let `node-core` commit them inside
a `PreinstalledModuleSemanticsEnvelope`, and wire `node-core`'s
`PreinstalledWasmMachine` to verify a typed entrypoint's inputs and
independently synthesize a narrow, sender-authorized owner-only mutation
before and after a preinstalled-module call. This slice commits, verifies,
and translates the capability correctly end-to-end, but activates no
preinstalled-module catalog entry: no current catalog commits either new
policy, so every code path this decision adds remains unreachable in
production until a later slice activates it. `Create`, devnet fixture
replacement, `StandardAssetTransferArgs`, `protocol-config`/devnet protocol
version 4 activation, CLI/signing-view wiring, split/merge/mint, fee
aggregation, and public-testnet readiness are all explicitly deferred to
later slices.

- **DR-0106: `abi` gains canonical wire codecs for its DR-0105 in-memory-only
  policy components, without turning `ConstructorRegistry` into a wire
  type.** `ProjectionStep` (`0x5103`), `ConstructorDeclaration` (`0x5104`),
  `ParamDeclaration` (`0x5105`), and `EntrypointSignature` (`0x5106`) each
  gain an `encode_*`/`decode_*` pair, all in the `0x51xx` band re-audited
  unused above `0x5102` before this allocation. `ConstructorRegistry` itself
  stays exactly the in-memory, `BTreeMap`-backed index DR-0105 defined: a
  caller decodes a `Vec<ConstructorDeclaration>` one item at a time and
  registers each into a fresh registry, so `ConstructorRegistry::register`'s
  existing duplicate-id, duplicate-`body_type_id`, and bound checks apply for
  free without `abi` inventing a second registry wire format.
  `decode_constructor_declaration` builds a real `ConstructorDeclaration` and
  calls its existing private `validate()`, so every structural rule
  `ConstructorRegistry::register` already enforces (arity/projection shape,
  first-step self-agreement, zero body/projection ids, the reserved zero
  `ConstructorId`) is rejected at decode time too, not only at registration.
  Every new decoder additionally rejects an unknown discriminant/arity tag,
  an out-of-bound count, and an unexpected/missing/trailing field, matching
  this crate's existing canonical-decoding conventions.

- **DR-0106: `node-core` commits two new bounded, independent policy
  collections inside `PreinstalledModuleSemanticsEnvelope`.**
  `PreinstalledTypedEntrypointPolicy` binds one exact entrypoint to a bounded
  constructor-id-sorted list of `ConstructorDeclaration`s (≤
  `MAX_PREINSTALLED_TYPED_ENTRYPOINT_CONSTRUCTORS = 32`, restating
  `abi::MAX_CONSTRUCTORS` as a dependency-safe identical bound) and one
  `EntrypointSignature`; construction rejects any
  `ConstructorRegistry::register` failure and a signature parameter naming a
  constructor absent from the resulting registry, so a committed policy can
  never reference an unknown constructor. Sorting makes semantically identical
  registries produce identical semantics hashes regardless of governance input
  order. `PreinstalledOwnerTransitionPolicy`
  binds one exact entrypoint, one `transferred_access_index`, and the exact
  canonical type id/encoding version/field id node-core projects the
  recipient `Address` from inside the transaction's own signed `args`.
  Unlike `PreinstalledObjectAccessPolicy`, index `0` is not reserved here:
  node-core's default sender-owned loading rule already applies to every
  declared access including index `0`, and this capability only relaxes the
  post-execution mutation's owner-preservation check, never the loading rule.
  Both collections are bounded (≤ `MAX_PREINSTALLED_TYPED_ENTRYPOINT_POLICIES`
  / `MAX_PREINSTALLED_OWNER_TRANSITION_POLICIES = 8` each), reject a
  duplicate declared entrypoint, and — for owner-transition policies — reject
  an entrypoint with no matching typed-entrypoint policy, a
  `transferred_access_index` at or beyond that signature's parameter count, an
  index whose typed parameter is not `AccessMode::Write`, and an index that
  collides with a `PreinstalledObjectAccessPolicy`'s `access_index` for the
  same entrypoint — the two relaxations are deliberately kept mutually
  exclusive so a single access index is never simultaneously a cross-owner
  destination exception and an owner-transition grant.

  `encode_preinstalled_semantics_envelope` emits both new collections' count
  and item fields only when non-empty, at high, deliberately non-adjacent
  field ids (`100`/`101+` and `200`/`201+`) well clear of
  `object_access_policies`' numbering, so every historical envelope (both
  collections empty, as every current catalog commits) encodes exactly the
  same bytes it always did. A stable literal vector pins this for a populated
  envelope containing one policy of each new kind, alongside the historical
  empty-policy envelope vector, proven byte-identical.

- **DR-0106: `PreinstalledWasmMachine::transition` verifies a typed
  entrypoint's inputs and gates a low protocol version, both strictly before
  the WASM engine ever runs.** If a `PreinstalledTypedEntrypointPolicy`
  matches the invoked entrypoint, every engine-visible input — the same
  access-checked `state.resolved_objects()` set `load_and_authorize_objects`
  already produced, in exact signed manifest order — is passed to
  `abi::verify_entrypoint_inputs` against the policy's rebuilt
  `ConstructorRegistry` and signature, using the authenticated event epoch
  (never request-supplied). Independently, if a
  `PreinstalledOwnerTransitionPolicy` matches the invoked entrypoint and
  `Transaction.protocol_version < MIN_OWNER_TRANSITION_PROTOCOL_VERSION`
  (`4`), the call is rejected outright with
  `NodeCoreError::OwnerTransitionProtocolVersionTooLow` before the engine
  runs. This corrects an earlier draft of this slice, which treated a
  too-low protocol version as though the policy were simply absent and let
  the call fail later, if at all, with a generic
  `NodeCoreError::ObjectEffectMismatch` once the module's own no-op left the
  committed access index without a matching effect — an easily
  misdiagnosed, non-obvious failure mode for what is actually a version
  gate. `synthesize_owner_transition` independently rechecks the same gate
  defensively (returning the identical `Err`) rather than assuming the
  caller already enforced it.

- **DR-0106: node-core independently synthesizes and verifies the
  owner-only mutation an owner-transition policy authorizes; it never trusts
  the preinstalled module's own returned effects to declare the new
  owner.** After a successful call, `synthesize_owner_transition` resolves
  the policy's committed `transferred_access_index` against the engine-visible
  inputs and requires: that access was resolved with `AccessMode::Write`
  (`NodeCoreError::OwnerTransitionModeMismatch`) and is owned by the
  authenticated sender (`NodeCoreError::OwnerTransitionSenderMismatch`); the
  module's own returned effects name no effect at all for that object
  (`NodeCoreError::OwnerTransitionObjectEffectForbidden`) — the module is a
  no-op for this object by construction; and neither a declared
  `fee_payment.fee_object` nor the trusted composition treasury aliases it
  (`NodeCoreError::OwnerTransitionFeeObjectAlias`). The recipient is
  projected from the exact canonical transaction `args` via the policy's
  committed type id/version/field
  (`PreinstalledOwnerTransitionPolicy::project_recipient`), requiring the
  args frame to contain nothing else. The synthesized `ObjectEffect::Mutated`
  keeps `id`, `data`, `type_hash`, and `schema_version` unchanged and
  advances `version` by exactly one; only `owner` changes, to
  `Owner::Address(recipient)`.

  This synthesized effect is folded into the *same* canonical
  `ExecutionEffects` node-core encodes into the accepted response and commits
  as the durable mutation: an earlier draft of this slice canonically encoded
  the module's raw, pre-synthesis effects into the receipt before computing
  the synthesis and appending it only to the *committed* mutation set,
  so the receipt a caller observed disagreed with what was actually
  committed. This is fixed by moving the encode to after synthesis, for the
  success path only; fee payer/treasury mutations remain charged and
  committed separately (never folded into this struct), preserving existing
  fee semantics of excluding them from the canonical application effects. A
  trap path is unaffected: it never calls `synthesize_owner_transition`, so
  it can never introduce this disagreement.

  `translate_authenticated_object_effects_with_owner_transition` is an
  independent translation-boundary re-check, not a rubber stamp for whatever
  the caller's own synthesis already decided: `ObjectEffectMatching::ExactWithOwnerTransition`
  now carries the exact expected recipient `Address` (not only the
  `ObjectId`), and for that one object's declared `Write` effect,
  `translate_update_impl` independently requires the new owner to be
  *exactly* `Owner::Address(recipient)` (never merely some `Owner::Address`)
  and the new object's `data` to stay byte-identical to the verified input's
  own body — a whole-object transfer changes ownership only. Every other
  identity/previous-version/`+1`-version/`type_hash`/`schema_version`/
  checkpoint/mutable-`Owner::Address`-kind check, and every other declared
  access in the same call (including every other object, and the entire
  fee-only path), is unmodified and exactly as strict as before this
  decision. `validate_output_owner_addresses` still uniformly revalidates the
  synthesized effect's admissibility under the authenticating profile after
  `transition` returns, exactly like every module-produced effect.

- **Deferred.** No current preinstalled-module catalog commits a
  `PreinstalledTypedEntrypointPolicy` or `PreinstalledOwnerTransitionPolicy`,
  so every path this decision adds remains unreachable end-to-end in
  production. `Create`, a Standard Asset v1 preinstalled module, the devnet
  fixture replacement this activation implies, `StandardAssetTransferArgs`
  (the concrete typed `args` shape a whole-coin-transfer entrypoint would
  use), `protocol-config`/devnet protocol version 4 activation, CLI and
  `signing-view` wiring, split/merge/mint, fee aggregation for this
  entrypoint family, and public-testnet readiness are all out of scope for
  this slice and tracked by the Asset Standards Gate's remaining completion
  criteria (`TODO.md`).
