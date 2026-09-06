# Architecture decision DR-0107

Activate DR-0106's typed-entrypoint and owner-transition machinery end to
end, for the first time in production code: replace the local devnet's
protocol-3 `sunrise.devnet.asset_account.v1` fixture with a protocol-4
Standard Asset v1 whole-object `Coin<A>` transfer, committing a real
`PreinstalledTypedEntrypointPolicy` and `PreinstalledOwnerTransitionPolicy`
for the first time in any catalog. This is the first end-to-end reachable
owner change in the codebase. `Create`/mint, partial transfer/split/merge,
discovery, Unique Asset v1, multisig, Ledger device-profile updates,
TypeScript/UI, production fee aggregation, and public-testnet/mainnet
readiness remain explicitly deferred.

- **DR-0107: `standard-assets` gains `StandardAssetTransferArgsV1` (`0x7104`)
  and a reusable coin constructor declaration.** The sole field is a 32-byte
  `recipient: Address` (canonical field id `1`); the strict decoder rejects
  wrong type/version, missing/unknown/extra fields, wrong length, and
  trailing bytes, exactly like every other body in this crate. There is no
  amount, asset, or source field: a whole-object transfer entrypoint
  identifies its coin and asset entirely through the signed transaction's
  typed access manifest, never through these arguments.
  `coin_constructor_declaration()` factors the exact `ConstructorDeclaration`
  `constructor_registry()` already builds for `StandardAssetCoinV1` into a
  public function, so the committed devnet policy and the registry share one
  source of truth instead of two independently maintained declarations that
  could silently drift apart.

- **DR-0107: the devnet's `AssetId` is derived, not a hardcoded literal.**
  `apps/devnet/src/genesis.rs::build_devnet_protocol_context` now builds the
  `HashSuiteResolver` from the protocol config's own chain/version/schedule
  *before* populating `fee_assets`, then derives the one devnet
  `AssetId` via `standard_assets::derive_asset_id` from a fixed development
  creation authority and a fixed nonzero `AssetCreationSeed`
  (`apps/devnet/src/standard_asset.rs`), then registers that derived id as
  the sole enabled fee asset. Consequently `--chain-id`, `--epoch`, and the
  committed protocol version all change the derived `AssetId` — this is a
  deliberate, documented consequence of correct domain separation, not a
  defect. Because the seed's own object-id descriptor hash
  (`resolver.hash_for_purpose(..., HashPurpose::Object, ...)`) also mixes in
  `protocol_version`, a stale protocol-3 data directory can never derive the
  same object ids or `AssetId` a protocol-4 boot expects. Left unchecked that
  would let a reused v3 data directory silently seed a *disjoint* v4 object
  set into the same SQLite file rather than failing; `apps/devnet/src/seed.rs`
  therefore also persists a small protocol-version-independent marker object
  (fixed `ObjectId`, deliberately never derived through
  `hash_for_purpose`) recording the protocol version and epoch a data directory
  was created under. Because protocol 3 predates the marker itself, startup first
  uses SQLite's operator-only `object_store_is_empty` snapshot: an absent
  marker is created only for an empty object store, while any unmarked
  non-empty store fails with `UnmarkedExistingObjectState`. Once present,
  every later boot fails closed with a typed `ProtocolVersionMismatch` or
  `EpochMismatch` before seeding any coin if either configured replay boundary
  disagrees with it. This prevents an epoch-only change from silently deriving
  and seeding a disjoint `AssetId` and object set alongside the old state.

- **DR-0107: one preinstalled Standard Asset v1 whole-coin transfer module
  replaces the deleted `sunrise.devnet.asset_account.v1` fixture outright.**
  `apps/devnet/src/asset_account.rs` and `modules/asset_account.{wat,wasm}`
  are deleted, along with their `0xF001`-`0xF003` and `0xF010`/`0xF011`
  devnet-local wire types (Sunrise Edge has not released, so this is a
  replacement, never a migration or dual-support facade). The new module
  (`apps/devnet/src/standard_asset.rs`, `modules/standard_asset_transfer.{wat,wasm}`)
  commits one `PreinstalledTypedEntrypointPolicy` for its `transfer`
  entrypoint: an `EntrypointSignature` of exactly two `ParamDeclaration`s,
  both `AccessMode::Write`, both `STANDARD_ASSET_COIN_V1_CONSTRUCTOR` at
  `STANDARD_ASSET_SCHEMA_VERSION_V1` — index 0 the transferred coin, index 1
  a distinct fee-payer coin, unified by `abi`'s one shared type variable per
  signature so both must carry the *same* `AssetId` (this also forces the fee
  asset to equal the transferred asset for this entrypoint; a
  fee-in-a-different-asset shape is not expressible here and is a deliberate,
  documented limitation, not an oversight). It commits one
  `PreinstalledOwnerTransitionPolicy::new("transfer", 0, 0x7104, 1, 1)`:
  `transferred_access_index = 0` is the transferred coin; the recipient
  projects from `StandardAssetTransferArgsV1`'s exact type id/encoding
  version/field id. `object_access_policies` stays empty — there is no
  cross-owner object access policy; both engine-visible params are
  ordinary sender-owned `Write`s, and only the owner-transition policy
  relaxes the post-execution owner-preservation check, only for index 0.

  The committed WASM is honestly non-vacuous but still trivial: it asserts
  `get_object_count() == 2` and `get_args_len() == 48` (the exact
  `StandardAssetTransferArgsV1` frame length) and then returns, performing no
  state transition and calling neither `read_object_data` nor
  `write_object_data`. The owner-only mutation of index 0 is synthesized and
  independently re-verified by node-core's committed owner-transition policy,
  never by this module; the fee debit/credit is composed entirely by trusted
  node fee composition. This is the cheapest honestly-non-empty version of
  DR-0106 F8's finding: a literally empty entrypoint would commit
  `canonical_code_hash` to nothing and make a future accidental drift in
  engine-visible object count or args shape undetectable, while a
  non-trivial application semantics would falsely suggest the module itself
  does more than validate a fixed shape.

  Devnet protocol version bumps 3 → 4
  (`crates/node-core::MIN_OWNER_TRANSITION_PROTOCOL_VERSION`, unchanged,
  already committed by DR-0106) to make the committed owner-transition policy
  reachable at all.

- **DR-0107: `StandardAssetCoinFeeComposer` replaces `AssetAccountFeeComposer`.**
  Both bodies decode as `StandardAssetCoinV1`; both must carry the request's
  exact `asset_id`; the payer amount is checked-subtracted and, critically,
  a resulting `remaining == 0` is rejected *before* ever calling
  `StandardAssetCoinV1::new` (which categorically rejects a zero amount) —
  `FeeCompositionError::InsufficientBalance`, not a confusing generic
  encoding failure or, worse, a silently-produced unencodable coin. This is
  forced by the interaction DR-0106 predicted (F3): a fee coin's amount
  becomes permanently unusable as a fee payer once it falls to exactly the
  currently settled fee, so devnet seeds every fee coin generously (see
  `docs/guides/devnet.md`). The treasury amount is checked-added, then both
  output bodies are decoded back and re-checked (asset id unchanged, both
  amounts non-zero) before ever returning them to node-core — the treasury is
  excluded from `resolved_objects()` and therefore never reaches
  `abi::verify_entrypoint_inputs`, so this composer's own `asset_id` check,
  plus boot-time seeding's `abi::verify_type_id` check (below), are the only
  runtime controls over its nominal type. The devnet's committed
  `DEVNET_BASE_FEE = 1` stays non-zero: this is load-bearing, not incidental
  — a worst-case-free call's fee-payer `Write` access has no possible effect
  producer if the settled fee could ever be exactly zero, which would fail
  with a generic `ObjectEffectMismatch` rather than a clear error. A test
  (`genesis::tests::devnet_gas_schedule_base_fee_is_nonzero`) pins this.

- **DR-0107: devnet seeding is heterogeneous, and its supply/uniqueness
  invariant is redefined over seed identities, not current owners.** Per
  configured `--dev-owner`, `apps/devnet/src/seed.rs::seed_dev_owner_coins`
  seeds one transferable coin and one distinct fee coin, both initially
  owned by that dev owner; `seed_treasury_coin` seeds one ordinary treasury
  coin for the separate `--fee-treasury-owner` (necessarily non-zero, unlike
  the deleted `AssetAccount`'s zero-balance destination, since
  `StandardAssetCoinV1` forbids a zero amount). `verify_seeded_asset_supply`'s
  expected total is now a fixed function of the configured dev-owner count
  and the fixed treasury seed amount, never of current balances, and its
  uniqueness set is over **seed** owners and object ids — never current
  owners, since a transferable coin may legitimately end up owned by an
  address outside the configured set after a real transfer.

  Restart verification (`verify_current_coin`) relaxes both of a dev
  owner's seeded coins **identically**: each's head `owner_projection` and
  decoded `object.owner` may be any `Owner::Address` passing
  `validate_ed25519_owner_address(..., CanonicalPrimeOrder)` — the same gate
  seeding already applies at creation time and the same admissibility
  commit-time enforces — and each's amount may differ from its seed amount,
  so long as it still decodes as a canonical, nonzero `StandardAssetCoinV1`
  for the exact seeded asset id. This is a deliberate correction from an
  earlier draft that froze the transferable-coin slot to ownership-only
  movement and the fee-coin slot to amount-only movement: the two coins are
  protocol-indistinguishable at seed time (same type, schema, asset,
  owner), so a real devnet run may use *either* as the whole-coin transfer
  source and the *other* as the fee payer, and restart verification must
  accept that swapped arrangement exactly as readily as the un-swapped one.
  Only the treasury coin keeps its exact expected owner across every
  restart; its amount may still have changed. All three coin kinds' nominal
  type is verified through `abi::verify_type_id` /
  `standard_assets::derive_coin_type_id`, never raw `Digest32` equality
  (DR-0105's "`type_hash` is a commitment, not the logical identity" applies
  directly to the hidden treasury, which is never checked by
  `abi::verify_entrypoint_inputs` at transaction time).

- **DR-0107: `apps/cli`'s `transfer` surface is rebuilt around coins, not
  accounts.** `--source-coin`, `--recipient`, `--fee-coin`, `--fee-asset-id`,
  `--max-fee`, `--fee-treasury-object` replace `--source-object`,
  `--destination-object`, `--destination-owner`, `--amount`: there is no
  amount or destination-account concept in a whole-object transfer. Before
  signing, the client independently queries and decodes both coins as
  `StandardAssetCoinV1`, requires both to be owned by the signer, requires
  them to share one `AssetId`, requires `--fee-asset-id` to equal that
  shared id, and requires the two coin ids to be distinct — defense in
  depth alongside the server's committed typed-entrypoint policy, never a
  substitute for it. Ledger rejection (a typed `CliError` before any
  `connect()`) and hardware-signing device profile/APDU behavior are
  unchanged; no new Ledger clear-signing policy is added for this
  entrypoint in this slice (Ledger updates remain deferred).

- **DR-0107: `signing-view`'s devnet policy constant is renamed and
  documented as historical.** `DEVNET_ASSET_TRANSFER_POLICY` (pinned to the
  deleted protocol-3 module/args/`AssetId`) is renamed
  `HISTORICAL_ASSET_ACCOUNT_TRANSFER_POLICY_V3` and its doc comment states
  plainly that no live devnet build matches it; it is kept only so
  `clients/rust::transaction`'s historical vector test keeps exercising
  `ClearSigningPolicy::recognize` against a fixed, non-trivial byte shape.
  Signing-view's behavior, device profile, view algorithm, and Ledger APDU
  contract are otherwise unchanged.

## Deferred

`Create`/mint, partial transfer/split/merge, discovery/query beyond the
existing bounded object query, Unique Asset v1, multisig, a new Ledger
clear-signing policy for this entrypoint, TypeScript/UI, production fee
aggregation (the treasury remains one hot, non-certificate-distributed
ordinary coin — an explicit, documented non-production devnet limitation),
and public-testnet/mainnet readiness are all out of scope for this slice.

VERDICT: APPROVE DESIGN
