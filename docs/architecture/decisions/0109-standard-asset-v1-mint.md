# Architecture decision DR-0109

Activate a bounded Standard Asset v1 mint path for the one already-derived
local-devnet asset. This is an additive module-version change within protocol
v5: historical module versions 1 and 2 remain byte-for-byte catalog entries,
while module version 3 adds `mint`. It does not add arbitrary asset creation,
an asset registry, supply accounting, burn, metadata, or public-testnet
readiness.

- **Authority is an owned typed object.** Startup atomically seeds the fixed
  devnet asset's immutable `StandardAssetDefinitionV1` and one
  `StandardAssetMintCapabilityV1` owned by the first configured development
  owner. Restart accepts only the exact immutable version-one definition and
  exact version-one capability, including canonical bodies, nominal type ids,
  owners, provenance, history, and seed receipt. A half-present pair or any
  mismatch fails closed. The capability is read, not consumed, so this slice
  deliberately grants repeatable issuance for the development fixture; it is
  not a bounded-supply or revocable production policy.
- **The module owns asset semantics.** The `mint` typed signature is exactly
  `Read MintCapability<A>` at signed index 0 followed by sender-owned
  `Write Coin<A>` fee input at index 1. The shared type variable requires both
  inputs to name the same `AssetId`; the trusted fee-treasury `Write` remains
  final and hidden from WASM. Canonical `StandardAssetMintArgsV1` (`0x7106`)
  contains only a nonzero `u64` amount and recipient address. The committed
  WASM copies the already-verified capability's `AssetId`, constructs one
  `StandardAssetCoinV1`, and takes its nominal type/schema from the verified
  fee coin. Node-core remains asset-generic and does not decode balances or
  capability bodies.
- **Creation remains exact and independently verified.** A dedicated
  `PreinstalledObjectCreationPolicy` permits exactly one created object at
  ordinal zero for this exact module/version/entrypoint. It projects the
  recipient from field 2 of the exact `0x7106` argument frame and copies the
  nominal type/schema from signed input 1. Node-core independently derives the
  object id from the signed transaction hash, verifies owner/type/schema/body
  projection, and requires an exact `Absent` head. Current or tombstoned
  collisions, missing/extra/duplicate creates, malformed arguments, wrong
  access order/mode/owner/type/schema, mismatched assets, and generic Create
  remain fail closed.
- **The CLI verifies before signing.** `sunrise-edge-cli mint` supports the
  local development signer only. It verifies the locally expected protocol
  context, current nonce, sender ownership and strict body of the capability
  and fee coin, their shared `AssetId`, the explicit fee asset, distinct
  capability/fee/treasury ids, and the current treasury reference before it
  signs. Ledger selection fails locally before device or network access until
  an exact clear-signing policy exists.
- **Atomicity and replay are unchanged.** One successful invocation atomically
  commits the created coin, fee payer/treasury changes, nonce, receipt, and
  outbox. Exact replay reconciliation happens before policy resolution and
  object I/O, so same-boot and post-restart replay cannot mint or charge twice.
  Request-id reuse with different signed bytes leaves definition, capability,
  created coin, fee coin, treasury, receipt, and nonce unchanged.

Arbitrary authenticated asset definition/capability creation is a separate
future decision. It needs an exact multi-create policy and a trusted execution
surface for chain, protocol, epoch, authenticated authority, and hash-suite
selection; hard-coding that derivation in node-core would violate the module
boundary. Burn, supply policy/accounting, capability rotation/revocation,
metadata authenticity, discovery/selection, Unique Asset v1, multisig,
Ledger clear signing, production fee aggregation, and public-testnet/mainnet
release gates also remain deferred.
