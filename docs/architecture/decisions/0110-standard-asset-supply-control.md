# Architecture decision DR-0110

Replace the local devnet's active reusable, unbounded mint authority with an
owner-held, supply-accounted `StandardAssetTreasuryCapV1`. Protocol version 6
activates canonical `sunrise.standard_asset.v1` at module version 1 with
bounded mint and whole-coin burn. Earlier unreleased development fixtures are
isolated under distinct disabled module identifiers rather than consuming
versions in the canonical module namespace; their frozen
`StandardAssetMintCapabilityV1` bytes remain available for regression tests.

- **Supply authority is ordinary typed object state.** `TreasuryCap<A>` is a
  `Write` object containing exact `asset_id`, current `total_supply`, and fixed
  nonzero `max_supply`. Its canonical type id is `0x7107`; the historical
  `MintCapability<A>` at `0x7103` is unchanged. The cap is address-owned by the
  first configured development owner, is neither native balance state nor a
  node-core privilege, and has no path that raises `max_supply` or changes its
  owner.
- **Mint and burn account supply atomically.** `mint` takes `Write
  TreasuryCap<A>` at signed index 0 and a distinct sender-owned fee `Write
  Coin<A>` at index 1. It checked-adds the nonzero requested amount, rejects
  overflow or `total_supply > max_supply`, mutates the cap, and creates exactly
  one recipient `Coin<A>`. `burn` takes `Write TreasuryCap<A>` index 0,
  sender-owned `Consume Coin<A>` index 1, and distinct fee `Write Coin<A>`
  index 2. It has empty arguments, checked-subtracts the entire consumed coin,
  mutates the cap, and creates nothing. The committed typed signatures unify
  every visible input to the same asset identity. The trusted fee treasury is
  still a final hidden `Write` and fees remain ordinary `Coin<A>` state.
- **Node-core remains asset-generic.** The active catalog commits the new
  treasury-cap constructor, exact typed entrypoint signatures, and the existing
  exact-one mint creation policy. WASM owns checked balance and supply
  arithmetic. Node-core verifies the committed input order, modes,
  type/schema/ownership, created-object id/owner/type/body projection, exact
  absent pre-read, fee composition, and atomic durable effects without decoding
  Standard Asset balances.
- **Genesis and restart preserve history.** The cap starts with the checked sum
  of all configured dev-owner seed coins and the ordinary fee-treasury seed
  coin; its devnet `max_supply` is a fixed explicit bound. Restart verifies the
  immutable definition, the cap's exact version-one seed record and receipt,
  and the cap's current canonical head at any legitimately advanced version.
  Split, merge, or burn may tombstone an originally seeded coin; startup
  verifies its retained immutable history and never recreates it.
- **The CLI fails before signing.** `mint` and `burn` require a local software
  signer, locally expected protocol context, current nonce, exact current
  object references, strict treasury-cap/coin bodies, one shared asset id, and
  pairwise-distinct cap/application-coin/fee-coin/fee-treasury ids. Their signed
  access manifests use the exact committed orders above. Ledger selection
  remains closed until an exact clear-signing policy exists.
- **Replay and persistence semantics are unchanged.** Exact replay is
  reconciled before module/policy resolution and object I/O. Successful mint or
  burn commits application effects, fee payer/treasury updates, nonce, receipt,
  and outbox once. Same-boot and post-restart replay must not reapply supply,
  coin, or fee changes; request-id reuse with different signed bytes must leave
  every object, both receipts, and nonce unchanged.

This decision does not add arbitrary asset creation, metadata authenticity,
authority transfer/freeze/close, coin discovery/selection, partial burn,
Unique Asset v1, multisig, Ledger clear signing, FastVote, production fee
aggregation, or public-testnet/mainnet readiness. Arbitrary asset creation is a
separate atomic multi-create decision so its authenticated authority and
protocol context are not smuggled into node-core.
