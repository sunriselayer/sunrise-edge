# Architecture decision DR-0105

Add the smallest coherent typed ABI foundation so `AssetId` is a nominal ABI
type argument for `StandardAssetDefinitionV1`, `StandardAssetCoinV1`, and
`StandardAssetMintCapabilityV1`. This slice is inert: it activates no module,
`Create`, owner change, transfer, merge, mint, fee integration, node-core
wiring, or network behavior, and Standard Asset v1 remains unavailable.

- **DR-0105: nominal object-type identity is a distinct, protocol-version-
  invariant hash frame.** `HashDomain::ObjectType = 0x000F` and the
  corresponding `HashPurpose::ObjectType` are allocated at the next audited
  free `HashDomain` value; `HashSuite::algorithm_for` selects the active
  suite's `config_hash` algorithm for this purpose, the same algorithm
  already used for `HashPurpose::SystemModuleManifest` and
  `HashPurpose::AssetId`, so no caller may select a derivation algorithm.

  `hashing::frame_type_identity_input` is a distinct canonical frame from the
  general-purpose `frame_hash_input`, not a specialization of it: it binds
  the algorithm, the `ObjectType` domain and domain version, and the chain
  id, but deliberately excludes `protocol_version` and never carries an
  object's `schema_version`. An object's nominal type identity therefore
  survives both a protocol upgrade and a schema migration, unlike `AssetId`,
  which intentionally binds `protocol_version` because it identifies one
  specific asset creation event rather than a type.

  `hashing::verify_type_identity_digest` verifies using the digest's own
  recorded algorithm, and fails closed unless that algorithm is both
  implemented and was selected for `HashPurpose::ObjectType` by some
  schedule entry active at or before the caller-supplied epoch in the
  resolver's own trusted history (`HashSuiteResolver::is_algorithm_trusted_for_purpose`).
  This is strictly stronger than the existing `verify_digest`, which trusts
  any digest-recorded algorithm unconditionally: type identity additionally
  refuses a digest minted under an algorithm the schedule has not yet (or
  never) activated for this purpose, even when that algorithm is otherwise
  fully implemented. Both checks are additive: they do not relax or bypass
  any existing hashing validation.

- **DR-0105: `abi` gains a bounded, dependency-light typed-ABI foundation,
  kept separate from `AccessManifest`.** `AccessManifest` continues to answer
  only which exact objects and access modes a transaction declares; the new
  types answer what constructor, type argument, and schema version each
  already-resolved object must have before execution. `abi` remains
  independent of `standard-assets`, `execution`, `node-core`, runtimes, and
  adapters, so this foundation cannot acquire an execution-engine or storage
  dependency; it gained only a new dependency on the already dependency-light
  `hashing` crate.

  New canonical wire type IDs are allocated in the audited-unused `0x51xx`
  band, distinct from the existing `0x50xx` `AccessEntry`/`AccessManifest`
  IDs: `TypeArg` is `0x5101`, `TypeTag` is `0x5102`. `TypeArg` is bounded to
  exactly one structural kind — a 32-byte Standard Asset v1 `AssetId`-shaped
  value — and `abi` represents it as a raw `[u8; 32]` rather than importing
  `standard_assets::AssetId`, preserving the dependency direction
  (`standard-assets` depends on `abi`, not the reverse). `ConstructorDeclaration`,
  `ConstructorRegistry`, `EntrypointSignature`, and `ParamDeclaration` are
  deterministic in-memory protocol configuration, not wire-transmitted
  frames, so they own no canonical type ID.

  A `ConstructorDeclaration` binds one `abi::ConstructorId` (`abi`'s own
  namespace) to exactly one canonical object-body wire type id
  (`body_type_id`, owned by the defining crate's own canonical-encoding
  namespace, required non-zero) and declares a fixed-depth canonical body
  projection (bounded by `MAX_PROJECTION_DEPTH = 4`, each step's type id and
  field id required non-zero) used to extract the constructor's type
  argument directly from an object's raw body bytes. Validation additionally
  requires a variable-arity constructor's *first* projection step to exactly
  match its own `body_type_id`/`body_version`, since that step always
  decodes the object's outer body; only the projection's *last* step is
  additionally required to contain nothing but its declared terminal field,
  because earlier steps — including the outer body itself — may legitimately
  carry other value fields (an amount, creation metadata, and so on) that
  the projection does not otherwise inspect. A fixed-arity constructor still
  decodes its body and requires it to match the declared `body_type_id`/
  `body_version` exactly, even though it extracts no type argument, so an
  arbitrary or wrongly-typed body cannot be silently accepted.
  `ConstructorRegistry` is a deterministic, `BTreeMap`-backed registry
  (bounded by `MAX_CONSTRUCTORS = 32`) that rejects a duplicate
  `ConstructorId` and, more importantly, rejects binding two different
  constructors to the same `body_type_id` — the exact ambiguity a mirrored
  constructor/body numeric value could otherwise create. Iteration order is
  always sorted `ConstructorId` order, independent of registration order.

  `EntrypointSignature` (bounded by `MAX_PARAMS = 8`) declares an ordered
  list of `ParamDeclaration`s, each an exact `AccessMode`, constructor, and
  schema version. `MAX_ENTRYPOINT_BYTES = 256` restates
  `execution::MAX_TRANSACTION_ENTRYPOINT_BYTES` as a dependency-safe
  identical bound, since `abi` must not depend on `execution`; changing one
  without the other is a compatibility break requiring its own review. This
  is the protocol-level transaction entrypoint bound, deliberately distinct
  from `signing-view`'s narrower, optional `DeviceSigningProfile::V1.max_entrypoint_bytes()`
  (64), which exists only to keep one signed field within a hardware
  clear-signing display line and is not itself a protocol invariant.

  `verify_entrypoint_inputs` performs single-pass pre-execution verification:
  for each declared parameter, in order, it checks the resolved input's
  access mode, looks up and cross-checks the constructor's registry schema
  version against the resolved object's own `schema_version`, projects the
  object's body to a type argument, and verifies the resulting `TypeTag`
  against the object's stored `type_hash` via `abi::verify_type_id`
  (`hashing::verify_type_identity_digest`), rejecting a mismatch (a
  body/header disagreement). Verification always uses the stored digest's
  own recorded algorithm rather than deriving a fresh digest under whichever
  algorithm happens to be active at the verifying epoch: an object's
  `type_hash` is an algorithm-tagged *commitment* to its `TypeTag`, not the
  sole logical type identity, so an object committed under an algorithm
  trusted at an earlier epoch correctly remains valid after a later
  hash-suite rotation, and the corresponding error reports the projected
  `TypeTag` rather than a recomputed digest that would misleadingly imply
  the wrong algorithm was expected. Every `TypeArity::Variable` parameter in
  one signature shares this foundation's single type variable: the first
  resolved type argument is bound, and every subsequent variable-arity
  parameter must resolve to the same *projected* type-argument value —
  never a raw `type_hash` comparison — or verification fails closed. `abi`
  does not resolve objects itself; the caller supplies already
  access-checked `(AccessMode, &Object)` pairs derived from a transaction's
  own `AccessManifest`, so this is not a second access-control mechanism.

  **`type_hash` is a commitment, not the logical identity.** Because
  `HashPurpose::ObjectType` excludes `protocol_version` but still binds the
  active algorithm, two objects that share the exact same logical `TypeTag`
  (constructor and `AssetId`) can carry different `type_hash` bytes if one
  was committed before a hash-suite rotation and the other after. Nominal
  type equality must always be established by verifying each `type_hash`
  against its own claimed `TypeTag` (`verify_type_id`) and then comparing
  the verified `TypeTag`/`AssetId` values, never by comparing two
  `type_hash` values for raw byte equality. Every current and future typed
  policy in this foundation (including cross-parameter type-variable
  unification) follows this rule.

- **DR-0105: `standard-assets` exposes the concrete Standard Asset v1
  typed-ABI bindings.** `STANDARD_ASSET_SCHEMA_VERSION_V1 = 1` is the schema
  version validators compare against `objects::Object::schema_version` and
  `abi::ParamDeclaration::schema_version`. `STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR`,
  `STANDARD_ASSET_COIN_V1_CONSTRUCTOR`, and
  `STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR` deliberately mirror the
  already allocated body type IDs `0x7101`–`0x7103`. This mirroring is safe
  specifically because `abi::ConstructorId` and this crate's canonical wire
  type ids are distinct Rust types in distinct namespaces, and
  `constructor_registry` binds each constructor to its own `body_type_id`
  through `abi::ConstructorRegistry::register`, which fails closed on any
  collision. `constructor_registry` registers all three constructors with
  the same fixed-depth projection — canonical field 1 of the body (the
  nested encoded `AssetId`), then canonical field 1 of that `AssetId` frame
  (the raw 32 bytes) — because every one of the three existing bodies places
  `asset_id` in field 1. `definition_type_tag`, `coin_type_tag`, and
  `mint_capability_type_tag` build the canonical `TypeTag` for a given
  `AssetId`, and `derive_definition_type_id`/`derive_coin_type_id`/
  `derive_mint_capability_type_id` wrap `abi::derive_type_id` for each.

  Stable vectors and adversarial tests pin: the new hash frame and domain
  bytes; protocol-version invariance of the derived type-identity digest
  (contrasted with `AssetId`, which is protocol-version-bound); chain,
  constructor, and `AssetId` separation; hash-suite rotation continuing to
  verify an old type-identity digest, including an end-to-end
  `verify_entrypoint_inputs` regression where a `Coin<A>` object committed
  under SHA2-256 before a rotation and another committed under SHA3-256
  after both still verify at a later epoch and bind the exact same logical
  `AssetId`; fail-closed rejection of an unimplemented algorithm and of an
  otherwise-implemented algorithm used before its schedule activation
  epoch; registry ordering, duplicate, and bound rejection; rejection of a
  zero `body_type_id`, a zero projection type id, a zero projection field
  id, and a variable-arity constructor whose first projection step
  disagrees with its own `body_type_id`/`body_version`; a fixed-arity
  constructor still rejecting an arbitrary or wrongly-typed body even
  though it extracts no type argument; a projection's terminal inner frame
  rejecting an unknown extra field while the outer body's own legitimate
  extra fields (e.g. a coin's `amount`) remain accepted; entrypoint
  signature shape/mode/schema/arity rejection; body-header/type-hash
  agreement (a `Coin<A>` object whose stored `type_hash` disagrees with its
  own projected body is rejected); a shared mint entrypoint accepting
  `MintCap<A>`/`Coin<A>` and rejecting `MintCap<B>`/`Coin<A>`; and that
  mutating a coin's amount preserves its nominal type identity while
  mutating its `AssetId` breaks it.

  This slice remains inert: no preinstalled Standard Asset module,
  `Create`, owner change, transfer, merge, mint, or fee integration exists
  yet, and none of `execution`, `node-core`, a runtime, or an adapter wires
  this typed-ABI foundation into a live path. Standard Asset v1 remains
  unavailable; the Asset Standards Gate's remaining completion criteria are
  unaffected by this decision.
